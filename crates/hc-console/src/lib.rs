//! The interactive console: `hot_cheese` with no subcommand.
//!
//! The main OS thread owns the terminal, the tunnels, and EVERY privileged operation —
//! [`hc_core::mac::local_auth::LaContext`] wraps a raw ObjC pointer and is `!Send`, so Touch ID,
//! the Secure-Enclave ECDH and the plaintext DEK can only ever live here. The tokio runtime
//! inside [`hc_daemon::runtime::Runtime`] runs the accept loops, the per-connection tasks and
//! the read-test client; those workers shuttle ciphertext across [`hc_daemon::PrivilegedOp`] and
//! never unlock anything.
//!
//! Exposure lasts exactly as long as the session. Every ending the process can act on — a normal
//! return, an error, a panic unwind, SIGINT, SIGTERM, SIGHUP — closes every tunnel and gives the
//! terminal back. At startup, the runtime refuses any reverse tunnel left pointing at the
//! configured port by an ending it cannot act on, `SIGKILL`.
pub mod approval;
pub(crate) mod bundles;
pub mod menu;
pub(crate) mod pick;
pub mod readtest;
pub mod renderer;
pub mod status;

use alloy_primitives::Address;
use crossterm::event::{Event, KeyCode, KeyModifiers};
use err_mac::create_err_with_impls;
use hashbrown::HashMap;
use hc_core::config::{home_dir, Config};
use hc_core::mac::BackendImpl;
use hc_daemon::exposure::TunnelManager;
use hc_daemon::flock;
use hc_daemon::renderer::Renderer;
use hc_daemon::runtime::{Runtime, UnlockGate};
use renderer::Terminal;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

/// How long a live screen waits on the keyboard before looking at its own work again.
pub(crate) const TICK: Duration = Duration::from_millis(120);

create_err_with_impls!(
    #[derive(Debug)]
    pub ConsoleErr,
    Runtime(hc_daemon::runtime::RuntimeErr),
    Status(status::StatusErr),
    Menu(menu::MenuErr)
    ;
);

/// What a keypress on a live screen means. `Other` carries a screen's own keys, which only the
/// screen that binds them knows the meaning of.
pub(crate) enum Key {
    Quit,
    Leave,
    Redraw,
    Other(char),
    Ignore,
}

/// Wait one [`TICK`] for the keyboard and classify what arrived.
pub(crate) fn tick() -> Result<Key, std::io::Error> {
    if !crossterm::event::poll(TICK)? {
        return Ok(Key::Ignore);
    }
    match crossterm::event::read()? {
        Event::Key(key) => match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Ok(Key::Quit),
            KeyCode::Char('q') | KeyCode::Esc => Ok(Key::Leave),
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                Ok(Key::Other(c))
            }
            _ => Ok(Key::Ignore),
        },
        Event::Resize(_, _) => Ok(Key::Redraw),
        _ => Ok(Key::Ignore),
    }
}

/// Everything the menu operates on. Lives on the main OS thread and never leaves it.
pub struct Console {
    /// The one runtime: listener, adapter sockets, approver, tunnels, store claim.
    pub rt: Runtime,
    /// Recent log lines for the status view.
    pub log: Arc<status::LogRing>,
    /// Signer addresses this session produced, and the local keystore each came from. A
    /// keystore's address costs a decrypt and therefore a biometric, so the bundle list names
    /// the operator's own signatures only where signing already paid for the answer.
    pub signers: HashMap<Address, String>,
}

/// Closes every tunnel and gives the terminal back on drop, so an error return or a panic
/// unwind cannot skip it. The signal task holds an [`Arc`] clone of the manager forever, so
/// `Drop for TunnelManager` never fires and this is what closes them.
struct ExitGuard {
    tunnels: Arc<TunnelManager>,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.tunnels.close_all();
        Terminal.restore();
    }
}

/// Take over the terminal: redirect logs, start the one runtime, run the menu, then stop it.
/// The subscriber installed below owns the global default, so a failure would otherwise reach
/// only the log file: the operator gets it on the terminal here.
pub fn run(
    config: Config,
    backend: Box<dyn BackendImpl>,
    gate: UnlockGate,
    store: flock::Claim,
) -> Result<(), ConsoleErr> {
    let result = session(config, backend, gate, store);
    if let Err(e) = &result {
        let _ = writeln!(std::io::stderr(), "hot_cheese console failed: {e}");
    }
    result
}

fn session(
    config: Config,
    backend: Box<dyn BackendImpl>,
    gate: UnlockGate,
    store: flock::Claim,
) -> Result<(), ConsoleErr> {
    let log = status::install_subscriber(&home_dir(), hc_core::config::env_log_level())?;
    let rt = Runtime::start(config, backend, gate, Arc::new(Terminal), store)?;

    let previous_hook = std::panic::take_hook();
    let panicking = rt.tunnels.clone();
    std::panic::set_hook(Box::new(move |info| {
        panicking.close_all();
        Terminal.restore();
        previous_hook(info);
    }));
    let exit = ExitGuard {
        tunnels: rt.tunnels.clone(),
    };

    let mut console = Console {
        rt,
        log,
        signers: HashMap::new(),
    };
    let result = menu::run(&mut console);
    drop(exit);
    console.rt.stop();
    Ok(result?)
}
