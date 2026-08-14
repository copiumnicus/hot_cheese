//! The one session both front ends run: the loopback listener, the adapter sockets, the single
//! approver fed over an mpsc channel, the background tasks, and the store claim.
//!
//! The renderer is injected, so `hot_cheese` and `hot_cheese serve` differ in how they ask the
//! human and in which TCP port they ask the kernel for — and in nothing else. The thread that
//! owns a [`Runtime`] is the only thread that ever calls [`Approver::approve`], which is what
//! keeps the `!Send` [`hc_core::mac::local_auth::LaContext`] on one thread by construction.
use crate::approval::Approver;
use crate::bundle_poll::{BundlePoll, PollThread};
use crate::git_store::GitStore;
use crate::renderer::Renderer;
use crate::{
    bundle_poll, exposure, flock, git_store, live, socket, HotApi, Listener, OpErr, Peer,
    PrivilegedOp, PENDING_OPS,
};
use err_mac::create_err_with_impls;
use hc_core::config::Config;
use hc_core::mac::BackendImpl;
use hc_sign::SignErr;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};

/// How long the tokio runtime is given to finish in-flight connections at exit.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Port the terminal renderer asks the kernel for: any free one. `config.port` is the `serve`
/// daemon's contract with its clients; the console's listener is reached only through tunnels
/// the console opens itself, and it hands `ssh` the real port at that moment, so no peer ever
/// needs to predict it. A fixed port is the entire mechanism of the silent re-attach: an
/// `ssh -R 7777:localhost:5555` that outlived its session serves every request to a remote the
/// next session cannot see, because that tunnel is not in its [`exposure::TunnelManager`].
const EPHEMERAL: u16 = 0;

create_err_with_impls!(
    #[derive(Debug)]
    pub RuntimeErr,
    NotServing,
    StdIo(std::io::Error),
    Serve(crate::ServeErr),
    Manifest(hc_sign::manifest::ManifestErr),
    Socket(socket::SocketErr),
    Tunnel(exposure::TunnelErr),
    Flock(flock::FlockErr),
    Git(git_store::GitErr)
    ;
    StrandedTunnels { port: u16, found: Vec<exposure::StrandedTunnel> }
);

/// Which TCP port the loopback listener asks for. The terminal renderer keeps the kernel-chosen
/// one so a stranded reverse tunnel points at nothing; the headless renderer takes the
/// documented one so services can reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindPort {
    /// Whatever the kernel gives, read back with `local_addr()` after the bind.
    Ephemeral,
    /// `config.port()`, the `serve` daemon's contract with its clients.
    Configured,
}

/// Which KEK unlocked this session, and therefore whether keys may leave the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockGate {
    /// Secure Enclave: a live Touch ID gates every single request.
    Biometric,
    /// Recovery passphrase: one startup prompt would answer every later request.
    Passphrase,
}

/// The in-process daemon, which exists only when a live biometric gates every request.
pub enum Serving {
    Live {
        /// Loopback address the listener actually bound.
        addr: SocketAddr,
        /// Requests waiting for approval on the main thread.
        ops: mpsc::Receiver<PrivilegedOp>,
        /// Flips the accept loops off.
        shutdown: watch::Sender<bool>,
    },
    /// Nothing listens — a passphrase session, or the listener exited — and no tunnel may open.
    Refused,
}

impl fmt::Display for Serving {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Serving::Live { addr, .. } => write!(f, "https://{addr}"),
            Serving::Refused => f.write_str("refused"),
        }
    }
}

/// A signal that ends the session. The process leaves with the shell's `128 + signal`.
#[derive(Clone, Copy, Debug)]
pub enum ExitSignal {
    Interrupt,
    Terminate,
    Hangup,
}

impl ExitSignal {
    pub fn code(self) -> i32 {
        match self {
            ExitSignal::Interrupt => 130,
            ExitSignal::Terminate => 143,
            ExitSignal::Hangup => 129,
        }
    }
}

/// How one serviced request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    Denied,
    Failed,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Outcome::Approved => "approved",
            Outcome::Denied => "denied",
            Outcome::Failed => "failed",
        })
    }
}

/// Run one queued request on the thread that owns the runtime and answer its reply channel
/// exactly once. Both renderers' loops come through here, so a caller is never left hanging.
pub fn service_one(api: &HotApi, approver: &Approver, op: PrivilegedOp) -> Outcome {
    let PrivilegedOp { ctx, body, reply } = op;
    let result = crate::execute(api, approver, &ctx, &body);
    let outcome = match &result {
        Ok(_) => Outcome::Approved,
        Err(OpErr::Denied | OpErr::Sign(SignErr::ApprovalDenied)) => Outcome::Denied,
        Err(e) => {
            tracing::error!(error = ?e, key = %ctx.key, "operation failed");
            Outcome::Failed
        }
    };
    if reply.send(result).is_err() {
        tracing::warn!(key = %ctx.key, "caller disconnected before its answer");
    }
    outcome
}

/// One session's listeners, approver and claim. Deliberately without a `Drop` impl, so
/// [`Runtime::stop`] can move the tokio runtime out; the sockets and the claim carry their own.
pub struct Runtime {
    /// Store, port, pinned grant key, remotes and adapter pins, shared with the listeners.
    pub config: Arc<Config>,
    /// The privileged API. Every call on it runs on the thread that owns this Runtime.
    pub api: HotApi,
    /// Which KEK unlocked this session.
    pub gate: UnlockGate,
    /// Takes the human decision and mints the one biometric a sign reuses.
    pub approver: Approver,
    /// Where the listener bound, and the queue of requests waiting for this thread.
    pub serving: Serving,
    /// Reverse ssh tunnels opened from this process; consulted for request provenance.
    pub tunnels: Arc<exposure::TunnelManager>,
    /// Runs the accept loops, the connection tasks and the read-test client.
    pub tokio: tokio::runtime::Runtime,
    /// The store as a git repository: the chokepoint every mutation commits through, the claim
    /// held for the whole session, and the state the status panel reads.
    pub git: Arc<GitStore>,
    /// Pulls every enrolled peer's bundles on a timer, pushes back only what this device wrote,
    /// and publishes what arrived. Poked by the write verbs.
    pub bundles: Arc<BundlePoll>,
    /// What a renderer draws its live status from: the handles above, plus the queue gauge.
    pub live: live::Live,
    /// The poller's own thread, joined with a deadline at [`Runtime::stop`].
    poller: PollThread,
    /// Unlinked when this drops or when a signal is caught.
    _sockets: socket::AdapterSockets,
}

impl Runtime {
    /// `store` is taken by the caller, above the first store mutation, and handed in. Nothing in
    /// this process may take it a second time.
    ///
    /// A passphrase session binds nothing at all — no TCP listener and no adapter socket —
    /// because a session that can never answer a request must not accept one either.
    pub fn start(
        config: Config,
        backend: Box<dyn BackendImpl>,
        gate: UnlockGate,
        renderer: Arc<dyn Renderer>,
        bind: BindPort,
        store: flock::Claim,
    ) -> Result<Self, RuntimeErr> {
        let config = Arc::new(config);
        let tokio = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let tunnels = Arc::new(exposure::TunnelManager::new());

        let (git, wake) = GitStore::session(config.clone(), store)?;
        let git = Arc::new(git);
        git.open()?;

        let pending = Arc::new(live::Pending::default());
        let mut sockets;
        let serving;
        match gate {
            UnlockGate::Passphrase => {
                sockets = socket::AdapterSockets::bind(Vec::new())?;
                serving = Serving::Refused;
            }
            UnlockGate::Biometric => {
                let adapters = hc_sign::manifest::load_all(&config)?;
                let count = adapters.len();
                let tls = crate::tls_from_home()?;
                let wanted = SocketAddr::new(
                    Ipv4Addr::LOCALHOST.into(),
                    match bind {
                        BindPort::Ephemeral => EPHEMERAL,
                        BindPort::Configured => config.port(),
                    },
                );
                let listener = tokio.block_on(TcpListener::bind(wanted))?;
                let addr = listener.local_addr()?;
                let found = exposure::scan_stranded(addr.port())?;
                if !found.is_empty() {
                    return Err(RuntimeErr::StrandedTunnels {
                        port: addr.port(),
                        found,
                    });
                }
                let (tx, ops) = mpsc::channel(PENDING_OPS);
                let (shutdown, rx) = watch::channel(false);
                sockets = socket::AdapterSockets::bind(adapters)?;
                for (adapter, bound) in sockets.bound.drain(..) {
                    let git = git.clone();
                    let tx = tx.clone();
                    let queued = pending.clone();
                    let rx = rx.clone();
                    tokio.spawn(async move {
                        let id = adapter.manifest.id.clone();
                        let listener = Listener::Unix(bound);
                        if let Err(e) =
                            crate::serve_loop(listener, Peer::Adapter(adapter), git, tx, queued, rx)
                                .await
                        {
                            tracing::error!(adapter = %id, error = ?e, "adapter listener exited");
                        }
                    });
                }
                let served = git.clone();
                let queued = pending.clone();
                tokio.spawn(async move {
                    let listener = Listener::Tcp(listener, tls);
                    if let Err(e) =
                        crate::serve_loop(listener, Peer::Loopback, served, tx, queued, rx).await
                    {
                        tracing::error!(error = ?e, "loopback listener exited");
                    }
                });
                tracing::info!(%addr, adapters = count, "hot_cheese serving over https");
                serving = Serving::Live {
                    addr,
                    ops,
                    shutdown,
                };
            }
        }

        let paths = sockets.paths.clone();
        let caught_tunnels = tunnels.clone();
        let caught_renderer = renderer.clone();
        let (mut interrupt, mut terminate, mut hangup) = {
            let _entered = tokio.enter();
            (
                signal(SignalKind::interrupt())?,
                signal(SignalKind::terminate())?,
                signal(SignalKind::hangup())?,
            )
        };
        tokio.spawn(async move {
            let caught = tokio::select! {
                _ = interrupt.recv() => ExitSignal::Interrupt,
                _ = terminate.recv() => ExitSignal::Terminate,
                _ = hangup.recv() => ExitSignal::Hangup,
            };
            tracing::warn!(signal = ?caught, "closing every tunnel, unlinking every socket, and leaving");
            caught_tunnels.close_all();
            caught_renderer.restore();
            paths.unlink();
            std::process::exit(caught.code());
        });

        tokio.spawn(git_store::background(git.clone(), wake));
        let (bundles, poller) = bundle_poll::start(config.bundle_watch_secs())?;

        Ok(Runtime {
            api: HotApi::new(backend, config.clone()),
            gate,
            approver: Approver::new(gate, renderer),
            serving,
            tunnels,
            tokio,
            live: live::Live {
                config: config.clone(),
                gate,
                git: git.clone(),
                bundles: bundles.clone(),
                pending,
            },
            config,
            git,
            bundles,
            poller,
            _sockets: sockets,
        })
    }

    /// Answer every queued request on this thread until every sender is gone. The headless
    /// renderer's whole main-thread program.
    pub fn approve_forever(&mut self) -> Result<(), RuntimeErr> {
        let Runtime {
            api,
            approver,
            serving,
            tunnels,
            ..
        } = self;
        let Serving::Live { ops, .. } = serving else {
            return Err(RuntimeErr::NotServing);
        };
        while let Some(mut op) = ops.blocking_recv() {
            op.ctx.peer = op.ctx.peer.with_tunnels(tunnels.list().len());
            service_one(api, approver, op);
        }
        Ok(())
    }

    /// Stop the accept loops and the poller, close the tunnels, give the terminal back, and let
    /// the tokio runtime finish what is in flight. The sockets and the claim drop with the struct.
    pub fn stop(self) {
        if let Serving::Live { shutdown, .. } = &self.serving {
            let _ = shutdown.send(true);
        }
        self.bundles.close();
        self.tunnels.close_all();
        self.approver.renderer().restore();
        self.tokio.shutdown_timeout(SHUTDOWN_GRACE);
        self.poller.join(SHUTDOWN_GRACE);
    }
}
