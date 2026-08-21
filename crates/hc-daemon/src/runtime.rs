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
use crate::renderer::{peer_may_log, Decision, Renderer};
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

/// Deny every request still queued, without a prompt, and report how many. Reached only when the
/// operator escaped a prompt and thereby asked for it: each of these callers gets
/// [`OpErr::Denied`] rather than silence.
fn refuse_queued(ops: &mut mpsc::Receiver<PrivilegedOp>) -> usize {
    let mut refused = 0;
    while let Ok(op) = ops.try_recv() {
        let _ = op.reply.send(Err(OpErr::Denied));
        refused += 1;
    }
    if refused > 0 {
        tracing::warn!(refused, "denied queued requests without prompting");
    }
    refused
}

/// Put `woke` and everything queued behind it in front of the operator, one at a time and in
/// arrival order, and report how many they were shown.
///
/// A queued op on a serving daemon is a live client waiting for an answer, so this loop sweeps
/// none of them: the interactive console caps a drain because its operator is working through a
/// backlog, but here a cap would deny a service that just asked for four keys at once, and —
/// since nothing on the loopback listener distinguishes that service from a flood — it would hand
/// an attacker the power to have everybody refused. The unprompted refusal this loop can reach is
/// the operator escaping a prompt, which is them asking for it, and it is read off the op that
/// was just refused, so a request the approver never saw can never inherit an older answer.
///
/// Every receive on `ops` releases one place in the approval line, and places are handed out in
/// arrival order, so a caller that has been waiting is admitted here before any request submitted
/// after it. That is the whole of what keeps a continuous submitter off the operator's screen.
fn answer_queued(
    api: &HotApi,
    approver: &Approver,
    tunnels: &exposure::TunnelManager,
    ops: &mut mpsc::Receiver<PrivilegedOp>,
    woke: PrivilegedOp,
) -> usize {
    let mut op = woke;
    let mut answered = 0;
    loop {
        op.ctx.peer = op.ctx.peer.with_tunnels(tunnels.list().len());
        let outcome = service_one(api, approver, op);
        answered += 1;
        if outcome == Outcome::Denied
            && matches!(approver.decision(), Decision::Cancel | Decision::Interrupt)
        {
            refuse_queued(ops);
            return answered;
        }
        match ops.try_recv() {
            Ok(next) => op = next,
            Err(_) => return answered,
        }
    }
}

/// Run one queued request on the thread that owns the runtime and answer its reply channel
/// exactly once. Both renderers' loops come through here, so a caller is never left hanging.
///
/// A closed reply channel is a caller that stopped waiting, and it is checked BEFORE the request
/// reaches the operator: the whole authorization mechanism is a human answering a prompt, so a
/// request nobody would receive the answer to must never spend one. What makes that check real is
/// that the connection ends when the caller does, which is why half-closed connections are refused
/// where the daemon serves them.
///
/// Every line here is one an unauthenticated peer can produce at will — by disconnecting, or by
/// sending a body that fails — so every one of them is gated on [`peer_may_log`] whatever its
/// level. A peer that can write to the screen a prompt is on can scroll the request away.
pub fn service_one(api: &HotApi, approver: &Approver, op: PrivilegedOp) -> Outcome {
    let PrivilegedOp {
        ctx,
        body,
        reply,
        outstanding: _outstanding,
    } = op;
    if reply.is_closed() {
        if peer_may_log("caller_gone") {
            tracing::debug!(key = %ctx.key, "skipping an operation whose caller disconnected");
        }
        return Outcome::Failed;
    }
    let result = crate::execute(api, approver, &ctx, &body);
    let outcome = match &result {
        Ok(_) => Outcome::Approved,
        Err(OpErr::Denied | OpErr::Sign(SignErr::ApprovalDenied)) => Outcome::Denied,
        Err(e) => {
            if peer_may_log("operation_failed") {
                tracing::error!(error = ?e, key = %ctx.key, "operation failed");
            }
            Outcome::Failed
        }
    };
    if reply.send(result).is_err() && peer_may_log("answer_undelivered") {
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
                let paths = crate::GrantPaths::of(&config);
                let prompt = config.approval_timeout();
                sockets = socket::AdapterSockets::bind(adapters)?;
                for (adapter, bound) in sockets.bound.drain(..) {
                    let tx = tx.clone();
                    let queued = pending.clone();
                    let rx = rx.clone();
                    let paths = paths.clone();
                    tokio.spawn(async move {
                        let id = adapter.manifest.id.clone();
                        let listener = Listener::Unix(bound);
                        let peer = Peer::Adapter {
                            manifest: adapter,
                            cred: None,
                        };
                        if let Err(e) =
                            crate::serve_loop(listener, peer, paths, tx, queued, rx, prompt).await
                        {
                            tracing::error!(adapter = %id, error = ?e, "adapter listener exited");
                        }
                    });
                }
                let queued = pending.clone();
                tokio.spawn(async move {
                    let listener = Listener::Tcp(listener, tls);
                    if let Err(e) =
                        crate::serve_loop(listener, Peer::Loopback, paths, tx, queued, rx, prompt)
                            .await
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
            api: HotApi::runtime(backend, config.clone(), git.clone()),
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
    /// renderer's whole main-thread program. Every op leaves here answered: through the operator,
    /// or with [`OpErr::Denied`] because the operator escaped a prompt.
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
        loop {
            let Some(op) = ops.blocking_recv() else {
                return Ok(());
            };
            answer_queued(api, approver, tunnels, ops, op);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::renderer::Decision;
    use crate::{live, OpContext, Operation, Peer, PENDING_OPS};
    use hc_core::crypto::envelope::Dek;
    use hc_core::mac::local_auth::LaContext;
    use hc_core::unlock::UnlockErr;
    use hyper::body::Bytes;
    use parking_lot::Mutex;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::oneshot;

    struct NeverUnlocks {
        store: String,
    }

    impl hc_core::mac::BackendImpl for NeverUnlocks {
        fn unlock_dek(&self, _reason: &str, _auth: Option<&LaContext>) -> Result<Dek, UnlockErr> {
            Err(UnlockErr::NoMatchingEnrollment)
        }
        fn store(&self) -> &str {
            &self.store
        }
    }

    /// Counts every prompt it was shown and answers the first one differently from the rest.
    struct Answers {
        first: Decision,
        rest: Decision,
        asked: Mutex<usize>,
    }

    impl Renderer for Answers {
        fn ask(&self, _seq: u64, _ctx: &OpContext, _summary: &str) -> Decision {
            let mut asked = self.asked.lock();
            *asked += 1;
            match *asked {
                1 => self.first,
                _ => self.rest,
            }
        }
        fn restore(&self) {}
    }

    /// A serving daemon's queue holds live clients: a service fetching four keys at once on
    /// restart must have every one of them put in front of the operator, and the only request
    /// denied without a prompt is one queued behind a prompt the operator escaped.
    #[test]
    fn every_queued_client_reaches_the_operator_unless_the_operator_escapes() {
        for (first, prompts) in [(Decision::Deny, PENDING_OPS), (Decision::Cancel, 1)] {
            let dir = std::env::temp_dir()
                .join(format!("hot_cheese_burst_{}_{first:?}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("make the store");
            let store = dir.to_string_lossy().to_string();
            let api = HotApi::new(
                Box::new(NeverUnlocks {
                    store: store.clone(),
                }),
                Config::for_test(&store),
            );
            let renderer = Arc::new(Answers {
                first,
                rest: Decision::Deny,
                asked: Mutex::new(0),
            });
            let approver = Approver::new(UnlockGate::Biometric, renderer.clone());
            let pending = Arc::new(live::Pending::default());
            let (tx, mut ops) = mpsc::channel(PENDING_OPS);
            let mut answers = Vec::new();
            for n in 0..PENDING_OPS {
                let (reply, answer) = oneshot::channel();
                tx.try_send(PrivilegedOp {
                    ctx: OpContext {
                        key: format!("BURST_{n}"),
                        op: Operation::EvmGenerate,
                        peer: Peer::Loopback,
                    },
                    body: Bytes::new(),
                    reply,
                    outstanding: live::Outstanding::new(pending.clone()),
                })
                .expect("the queue holds PENDING_OPS");
                answers.push(answer);
            }

            let woke = ops.blocking_recv().expect("the queue is full");
            let answered = answer_queued(
                &api,
                &approver,
                &exposure::TunnelManager::new(),
                &mut ops,
                woke,
            );

            assert_eq!(answered, prompts);
            assert_eq!(*renderer.asked.lock(), prompts);
            for mut answer in answers {
                assert!(
                    matches!(
                        answer.try_recv(),
                        Ok(Err(OpErr::Denied | OpErr::Sign(SignErr::ApprovalDenied)))
                    ),
                    "every queued caller must leave with a typed answer"
                );
            }
            assert!(matches!(ops.try_recv(), Err(TryRecvError::Empty)));
            assert_eq!(pending.get(), 0);
            std::fs::remove_dir_all(&dir).expect("clean the store");
        }
    }
}
