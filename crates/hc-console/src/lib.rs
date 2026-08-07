//! The interactive console: `hot_cheese` with no subcommand.
//!
//! The main OS thread owns the terminal, the tunnels, and EVERY privileged operation —
//! [`hc_core::mac::local_auth::LaContext`] wraps a raw ObjC pointer and is `!Send`, so Touch ID,
//! the Secure-Enclave ECDH and the plaintext DEK can only ever live here. A tokio runtime runs
//! the HTTPS accept loop, the per-connection tasks and the read-test client; those workers
//! shuttle ciphertext across [`hc_daemon::PrivilegedOp`] and never unlock anything.
//!
//! Exposure lasts exactly as long as the session. Every ending the process can act on — a
//! normal return, an error, a panic unwind, SIGINT, SIGTERM, SIGHUP — runs [`teardown`], and
//! the listener takes a kernel-chosen port so the one ending it cannot act on, `SIGKILL`,
//! leaves its `ssh` children pointed at a port the next session will not be holding.
pub mod approval;
pub(crate) mod bundles;
pub mod exposure;
pub mod menu;
pub mod readtest;
pub mod status;

use alloy_primitives::Address;
use err_mac::create_err_with_impls;
use exposure::TunnelManager;
use hashbrown::HashMap;
use hc_core::config::{home_dir, Config};
use hc_core::mac::BackendImpl;
use hc_daemon::{Approval, HotApi, PrivilegedOp, PENDING_OPS};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::runtime::{Handle, Runtime};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};

/// How long the runtime is given to finish in-flight connections at exit.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Port the console asks the kernel for: any free one. `config.port` is the `serve` daemon's
/// contract with its clients; the console's listener is reached only through tunnels the
/// console opens itself, and it hands `ssh` the real port at that moment, so no peer ever
/// needs to predict it. A fixed port is the entire mechanism of the silent re-attach: an
/// `ssh -R 7777:localhost:5555` that outlived its session serves every request to a remote
/// the next session cannot see, because that tunnel is not in its [`TunnelManager`].
const EPHEMERAL: u16 = 0;

create_err_with_impls!(
    #[derive(Debug)]
    pub ConsoleErr,
    Serve(hc_daemon::ServeErr),
    Status(status::StatusErr),
    Menu(menu::MenuErr),
    Tunnel(exposure::TunnelErr),
    StdIo(std::io::Error)
    ;
    StrandedTunnels { port: u16, found: Vec<exposure::StrandedTunnel> }
);

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
        /// Flips the accept loop off.
        shutdown: watch::Sender<bool>,
    },
    /// Nothing listens — a passphrase session, or the listener exited — and no tunnel may open.
    Refused,
}

/// Everything the menu operates on. Lives on the main OS thread and never leaves it.
pub struct Console {
    /// Store, port, pinned grant key and backup remotes, shared with the API and listener.
    pub config: Arc<Config>,
    /// The privileged API; every call on it runs on this thread.
    pub api: HotApi,
    /// Which KEK unlocked this session.
    pub gate: UnlockGate,
    /// The in-process daemon, when this session is allowed one.
    pub serving: Serving,
    /// Reverse SSH tunnels this console opened, shared with the signal teardown.
    pub tunnels: Arc<TunnelManager>,
    /// Runs the accept loop, the connection tasks and the read test.
    pub runtime: Handle,
    /// Recent log lines for the status view.
    pub log: Arc<status::LogRing>,
    /// Signer addresses this session produced, and the local keystore each came from. A
    /// keystore's address costs a decrypt and therefore a biometric, so the bundle list names
    /// the operator's own signatures only where signing already paid for the answer.
    pub signers: HashMap<Address, String>,
}

/// End the session's exposure: every `ssh` child dies and the terminal goes back to the
/// shell. Idempotent, because several endings can reach it at once.
fn teardown(tunnels: &TunnelManager) {
    tunnels.close_all();
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(std::io::stderr(), crossterm::cursor::Show);
}

/// Runs [`teardown`] on drop, so an error return or a panic unwind cannot skip it.
struct ExitGuard {
    tunnels: Arc<TunnelManager>,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        teardown(&self.tunnels);
    }
}

/// A signal that ends the session. The process leaves with the shell's `128 + signal`.
#[derive(Clone, Copy, Debug)]
enum ExitSignal {
    Interrupt,
    Terminate,
    Hangup,
}

impl ExitSignal {
    fn code(self) -> i32 {
        match self {
            ExitSignal::Interrupt => 130,
            ExitSignal::Terminate => 143,
            ExitSignal::Hangup => 129,
        }
    }
}

/// Give SIGINT, SIGTERM and SIGHUP the same teardown as a normal exit before the process
/// leaves: a window closing, a `kill`, or a logout must not leave an `ssh -R` alive with a
/// terminal in raw mode behind it. SIGINT is caught too because crossterm's raw mode clears
/// `ISIG`, so the console's own ctrl-c is a keypress and never a signal — a SIGINT here is
/// always someone else's `kill`. SIGKILL cannot be caught by anything, so [`EPHEMERAL`] and
/// [`exposure::scan_stranded`] are what cover it.
fn install_signal_teardown(
    runtime: &Runtime,
    tunnels: Arc<TunnelManager>,
) -> Result<(), ConsoleErr> {
    let _entered = runtime.enter();
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    runtime.spawn(async move {
        let caught = tokio::select! {
            _ = interrupt.recv() => ExitSignal::Interrupt,
            _ = terminate.recv() => ExitSignal::Terminate,
            _ = hangup.recv() => ExitSignal::Hangup,
        };
        tracing::warn!(signal = ?caught, "closing every tunnel and leaving");
        teardown(&tunnels);
        std::process::exit(caught.code());
    });
    Ok(())
}

/// Take over the terminal: redirect logs, start the loopback daemon when the session is
/// biometrically gated, run the menu, then tear both down. The subscriber the session
/// installs owns the global default, so a failure would otherwise reach only the log file:
/// the operator gets it on the terminal here.
pub fn run_console(
    config: Config,
    backend: Box<dyn BackendImpl>,
    gate: UnlockGate,
) -> Result<(), ConsoleErr> {
    let result = session(config, backend, gate);
    if let Err(e) = &result {
        let _ = writeln!(std::io::stderr(), "hot_cheese console failed: {e}");
    }
    result
}

fn session(
    config: Config,
    backend: Box<dyn BackendImpl>,
    gate: UnlockGate,
) -> Result<(), ConsoleErr> {
    let config = Arc::new(config);
    let log = status::install_subscriber(&home_dir(), hc_core::config::env_log_level())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let tunnels = Arc::new(TunnelManager::new());
    install_signal_teardown(&runtime, tunnels.clone())?;

    let serving = match gate {
        UnlockGate::Passphrase => Serving::Refused,
        UnlockGate::Biometric => {
            let tls = hc_daemon::tls_from_home()?;
            let wanted = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), EPHEMERAL);
            let listener = runtime.block_on(TcpListener::bind(wanted))?;
            let addr = listener.local_addr()?;
            let found = exposure::scan_stranded(addr.port())?;
            if !found.is_empty() {
                return Err(ConsoleErr::StrandedTunnels {
                    port: addr.port(),
                    found,
                });
            }
            let (tx, ops) = mpsc::channel(PENDING_OPS);
            let (shutdown, rx) = watch::channel(false);
            let served_config = config.clone();
            runtime.spawn(async move {
                let approval = Approval::Console(tx);
                let listener = hc_daemon::Listener::Tcp(listener, tls);
                if let Err(e) = hc_daemon::serve_loop(
                    listener,
                    hc_daemon::Peer::Loopback,
                    served_config,
                    approval,
                    rx,
                )
                .await
                {
                    tracing::error!(error = ?e, "console listener exited");
                }
            });
            tracing::info!(%addr, "console serving over https");
            Serving::Live {
                addr,
                ops,
                shutdown,
            }
        }
    };

    let previous_hook = std::panic::take_hook();
    let panicking = tunnels.clone();
    std::panic::set_hook(Box::new(move |info| {
        teardown(&panicking);
        previous_hook(info);
    }));
    let exit = ExitGuard {
        tunnels: tunnels.clone(),
    };

    let mut console = Console {
        api: HotApi::new(backend, config.clone()),
        config,
        gate,
        serving,
        tunnels,
        runtime: runtime.handle().clone(),
        log,
        signers: HashMap::new(),
    };
    let result = menu::run(&mut console);

    if let Serving::Live { shutdown, .. } = &console.serving {
        let _ = shutdown.send(true);
    }
    drop(console);
    drop(exit);
    runtime.shutdown_timeout(SHUTDOWN_GRACE);
    Ok(result?)
}
