//! The arrow-key menu tree: one `inquire::Select` per screen, redrawn rather than streamed.
use super::approval::{self, ApprovalErr, ConsoleApprover, Drained};
use super::exposure::{TunnelId, TunnelSpec};
use super::{readtest, status, Console, Serving, UnlockGate};
use crate::backup;
use crate::crypto::envelope::{encrypt_file, Dek};
use crate::keyring::{EnrollParams, Keyring};
use crate::mac::secure_enclave::{ensure_se_key, SE_KEY_LABEL};
use crate::mac::MacBackend;
use crate::server::{is_valid_string_name, resolve_path, OpContext, Operation, Peer};
use crate::sign::intent::Intent;
use crate::unlock::{PassphraseUnlocker, SecureEnclaveUnlocker, Unlocker};
use crossterm::cursor::MoveTo;
use crossterm::terminal::{Clear, ClearType};
use err_mac::create_err_with_impls;
use inquire::{Confirm, CustomType, InquireError, Password, PasswordDisplayMode, Select, Text};
use std::fmt;
use std::io::Write;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// How often the main thread services queued requests while a read test is in flight.
const DRAIN_POLL: Duration = Duration::from_millis(25);

/// How long a read test may stay idle — nothing approved, nothing returned — before it is
/// abandoned. Time the operator spends at an approval prompt is not idle and does not count.
const READ_TEST_TIMEOUT: Duration = Duration::from_secs(60);

create_err_with_impls!(
    #[derive(Debug)]
    pub MenuErr,
    NotServing,
    NoKeystores,
    NoTunnels,
    NoBackupRemote,
    BadHexSecret,
    ReadTestTimedOut,
    Inquire(inquire::InquireError),
    Tunnel(super::exposure::TunnelErr),
    Approval(super::approval::ApprovalErr),
    ReadTest(super::readtest::ReadTestErr),
    ApiBackend(crate::server::ApiBackendErr),
    Sign(crate::sign::SignErr),
    Unlock(crate::unlock::UnlockErr),
    Keyring(crate::keyring::KeyringErr),
    Backup(crate::backup::BackupErr),
    Config(crate::config::ConfigErr),
    Envelope(crate::crypto::envelope::EnvErr),
    Se(crate::mac::secure_enclave::SeErr),
    Base58(bs58::decode::Error),
    Serde(serde_json::Error),
    Join(tokio::task::JoinError),
    StdIo(std::io::Error)
    ;
    InvalidKeyName { name: String },
    KeyExists { name: String }
);

/// Which screen the console is showing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuState {
    Root,
    Keys,
    Sign,
    Exposure,
    Backup,
    Enroll,
    Status,
    ServeAndApprove,
    Quit,
}

/// What the operator picked on the current screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuChoice {
    Keys,
    Sign,
    Exposure,
    Backup,
    Enroll,
    Status,
    ServeAndApprove,
    Back,
    Quit,
}

impl fmt::Display for MenuChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            MenuChoice::Keys => "Keys",
            MenuChoice::Sign => "Sign",
            MenuChoice::Exposure => "Exposure",
            MenuChoice::Backup => "Backup",
            MenuChoice::Enroll => "Enroll",
            MenuChoice::Status => "Status",
            MenuChoice::ServeAndApprove => "Serve and approve",
            MenuChoice::Back => "Back",
            MenuChoice::Quit => "Quit",
        };
        f.write_str(label)
    }
}

/// Where a choice lands. Backing out of the root screen leaves the console.
pub fn next(state: MenuState, choice: MenuChoice) -> MenuState {
    match (state, choice) {
        (_, MenuChoice::Quit) => MenuState::Quit,
        (MenuState::Root, MenuChoice::Back) => MenuState::Quit,
        (_, MenuChoice::Back) => MenuState::Root,
        (_, MenuChoice::Keys) => MenuState::Keys,
        (_, MenuChoice::Sign) => MenuState::Sign,
        (_, MenuChoice::Exposure) => MenuState::Exposure,
        (_, MenuChoice::Backup) => MenuState::Backup,
        (_, MenuChoice::Enroll) => MenuState::Enroll,
        (_, MenuChoice::Status) => MenuState::Status,
        (_, MenuChoice::ServeAndApprove) => MenuState::ServeAndApprove,
    }
}

macro_rules! menu_enum {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum $name {
            $($variant,)+
        }
        impl $name {
            const ALL: &[Self] = &[$(Self::$variant,)+];
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self {
                    $(Self::$variant => $label,)+
                })
            }
        }
    };
}

menu_enum!(KeyAction {
    List => "List keystores and enrollments",
    Generate => "Generate a new key",
    Address => "Show a public address",
    Add => "Import an existing secret",
    Back => "Back",
});

menu_enum!(ExposureAction {
    Open => "Open a reverse ssh tunnel",
    List => "List open tunnels",
    Close => "Close a tunnel",
    ReadTest => "Read test over the pinned TLS route",
    Back => "Back",
});

menu_enum!(BackupAction {
    Push => "Push the store to every remote",
    Pull => "Pull the store from the first remote",
    Back => "Back",
});

menu_enum!(EnrollAction {
    Se => "Secure Enclave (Touch ID)",
    Passphrase => "Recovery passphrase",
    Back => "Back",
});

menu_enum!(StatusAction {
    Refresh => "Refresh",
    Back => "Back",
});

menu_enum!(Chain {
    Evm => "EVM",
    Solana => "Solana",
});

menu_enum!(SecretKind {
    Ethereum => "Ethereum private key (hex)",
    Solana => "Solana keypair (base58)",
    Bytes => "Raw UTF-8 bytes",
});

/// What a prompt produced: a value, or the two keys that mean navigation.
enum Nav<T> {
    Chose(T),
    Back,
    Quit,
}

/// Esc backs out one level and Ctrl-C quits, so neither ever becomes an error.
fn nav<T>(answer: Result<T, InquireError>) -> Result<Nav<T>, MenuErr> {
    match answer {
        Ok(v) => Ok(Nav::Chose(v)),
        Err(InquireError::OperationCanceled) => Ok(Nav::Back),
        Err(InquireError::OperationInterrupted) => Ok(Nav::Quit),
        Err(e) => Err(e.into()),
    }
}

/// One screen's outcome: where to go, and what the next frame shows.
struct Step {
    /// Where the operator wants to go from here.
    choice: MenuChoice,
    /// Result text rendered at the top of the next frame.
    notice: String,
}

macro_rules! ask {
    ($answer:expr) => {
        match $answer? {
            Nav::Chose(v) => v,
            Nav::Back => {
                return Ok(Step {
                    choice: MenuChoice::Back,
                    notice: String::new(),
                })
            }
            Nav::Quit => {
                return Ok(Step {
                    choice: MenuChoice::Quit,
                    notice: String::new(),
                })
            }
        }
    };
}

/// Draw screens and run the operator's choices until they quit. A screen that fails without
/// having asked anything must not be re-entered on the next pass: the two screens that need a
/// live listener fall back to the root, and a terminal that cannot prompt at all ends the run.
pub fn run(console: &mut Console) -> Result<(), MenuErr> {
    let approver = ConsoleApprover::new(console.gate);
    let mut state = MenuState::Root;
    let mut notice = String::new();
    loop {
        match service_pending(console, &approver) {
            Ok(drained) => {
                if drained.answered > 0 || drained.refused > 0 {
                    notice = format!(
                        "answered {} request(s), denied {} unprompted",
                        drained.answered, drained.refused
                    );
                }
                if drained.quit {
                    state = MenuState::Quit;
                }
            }
            Err(MenuErr::Approval(ApprovalErr::ListenerGone)) => {
                console.serving = Serving::Refused;
                notice = "the https listener exited: nothing is served any more".to_string();
            }
            Err(e) => notice = format!("error: {e}"),
        }
        if state == MenuState::Quit {
            return Ok(());
        }
        draw(console, &notice)?;
        let step = match screen(console, &approver, state) {
            Ok(step) => step,
            Err(MenuErr::Inquire(InquireError::OperationCanceled)) => Step {
                choice: MenuChoice::Back,
                notice: String::new(),
            },
            Err(MenuErr::Inquire(InquireError::OperationInterrupted)) => Step {
                choice: MenuChoice::Quit,
                notice: String::new(),
            },
            Err(MenuErr::Inquire(e @ (InquireError::NotTTY | InquireError::IO(_)))) => {
                return Err(MenuErr::Inquire(e))
            }
            Err(e) => {
                notice = format!("error: {e}");
                if matches!(state, MenuState::Exposure | MenuState::ServeAndApprove) {
                    state = MenuState::Root;
                }
                continue;
            }
        };
        notice = step.notice;
        let target = next(state, step.choice);
        let refused = matches!(target, MenuState::Exposure | MenuState::ServeAndApprove)
            && matches!(console.serving, Serving::Refused);
        if refused {
            notice = format!("error: {}", MenuErr::NotServing);
        }
        state = if refused { state } else { target };
    }
}

/// Run the requests that queued while the operator was elsewhere in the tree.
fn service_pending(console: &mut Console, approver: &ConsoleApprover) -> Result<Drained, MenuErr> {
    let Console {
        api,
        serving,
        tunnels,
        ..
    } = console;
    let Serving::Live { ops, .. } = serving else {
        return Ok(Drained::default());
    };
    Ok(approval::drain(api, approver, ops, tunnels)?)
}

/// The read test's own request may still be queued when it is abandoned, and its caller is
/// then gone: deny it rather than prompting the operator for an answer nobody will read.
fn refuse_pending(console: &mut Console) {
    let Serving::Live { ops, .. } = &mut console.serving else {
        return;
    };
    approval::refuse_queued(ops);
}

/// Replace the screen with the session header and the last outcome.
fn draw(console: &Console, notice: &str) -> Result<(), MenuErr> {
    let mut out = std::io::stderr();
    crossterm::execute!(out, Clear(ClearType::All), MoveTo(0, 0))?;
    writeln!(out, "hot_cheese")?;
    match console.gate {
        UnlockGate::Biometric => {
            writeln!(out, "unlock:  Secure Enclave, Touch ID gates every request")?
        }
        UnlockGate::Passphrase => writeln!(
            out,
            "unlock:  recovery passphrase, no per-request biometric: nothing is served, \
             tunnels and read tests are refused"
        )?,
    }
    match &console.serving {
        Serving::Live { addr, .. } => writeln!(out, "serving: https://{addr}")?,
        Serving::Refused => writeln!(out, "serving: refused")?,
    }
    writeln!(out, "store:   {}", console.config.store_path().display())?;
    if !notice.is_empty() {
        writeln!(out, "\n{notice}")?;
    }
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn screen(
    console: &mut Console,
    approver: &ConsoleApprover,
    state: MenuState,
) -> Result<Step, MenuErr> {
    match state {
        MenuState::Root => root_screen(),
        MenuState::Keys => keys_screen(console),
        MenuState::Sign => sign_screen(console, approver),
        MenuState::Exposure => exposure_screen(console, approver),
        MenuState::Backup => backup_screen(console),
        MenuState::Enroll => enroll_screen(console),
        MenuState::Status => status_screen(console),
        MenuState::ServeAndApprove => serve_screen(console, approver),
        MenuState::Quit => Ok(Step {
            choice: MenuChoice::Quit,
            notice: String::new(),
        }),
    }
}

fn root_screen() -> Result<Step, MenuErr> {
    let options = vec![
        MenuChoice::Keys,
        MenuChoice::Sign,
        MenuChoice::Exposure,
        MenuChoice::Backup,
        MenuChoice::Enroll,
        MenuChoice::Status,
        MenuChoice::ServeAndApprove,
        MenuChoice::Quit,
    ];
    let choice = ask!(nav(Select::new("hot_cheese", options)
        .with_help_message("arrows move, enter selects, esc quits, ctrl-c quits")
        .without_filtering()
        .prompt()));
    Ok(Step {
        choice,
        notice: String::new(),
    })
}

fn keys_screen(console: &Console) -> Result<Step, MenuErr> {
    let action = ask!(nav(Select::new("Keys", KeyAction::ALL.to_vec())
        .with_help_message("esc goes back")
        .without_filtering()
        .prompt()));
    match action {
        KeyAction::Back => Ok(Step {
            choice: MenuChoice::Back,
            notice: String::new(),
        }),
        KeyAction::List => Ok(Step {
            choice: MenuChoice::Keys,
            notice: list_notice(console)?,
        }),
        KeyAction::Generate => generate(console),
        KeyAction::Address => address(console),
        KeyAction::Add => add(console),
    }
}

fn generate(console: &Console) -> Result<Step, MenuErr> {
    let chain = ask!(nav(Select::new("Chain", Chain::ALL.to_vec())
        .without_filtering()
        .prompt()));
    let name = ask!(nav(Text::new("New key name (a-z A-Z 0-9 _)").prompt()));
    let name = name.trim().to_string();
    if name.is_empty() || !is_valid_string_name(&name) {
        return Err(MenuErr::InvalidKeyName { name });
    }
    if console.config.store_path().join(&name).exists() {
        return Err(MenuErr::KeyExists { name });
    }
    let ctx = OpContext {
        key: name.clone(),
        op: match chain {
            Chain::Evm => Operation::EvmGenerate,
            Chain::Solana => Operation::SolanaGenerate,
        },
        peer: Peer::Cli,
    };
    match chain {
        Chain::Evm => console.api.generate(&ctx)?,
        Chain::Solana => console.api.generate_solana(&ctx)?,
    }
    backup::push_all(&console.config)?;
    Ok(Step {
        choice: MenuChoice::Keys,
        notice: format!("generated {chain} key \"{name}\""),
    })
}

fn address(console: &Console) -> Result<Step, MenuErr> {
    let chain = ask!(nav(Select::new("Chain", Chain::ALL.to_vec())
        .without_filtering()
        .prompt()));
    let name = ask!(nav(Select::new("Key", keystore_names(console)?).prompt()));
    let ctx = OpContext {
        key: name.clone(),
        op: match chain {
            Chain::Evm => Operation::EvmAddress,
            Chain::Solana => Operation::SolanaAddress,
        },
        peer: Peer::Cli,
    };
    let addr = match chain {
        Chain::Evm => console.api.address(&ctx)?,
        Chain::Solana => console.api.address_solana(&ctx)?,
    };
    Ok(Step {
        choice: MenuChoice::Keys,
        notice: format!("{name} {chain} address: {addr}"),
    })
}

fn add(console: &Console) -> Result<Step, MenuErr> {
    let name = ask!(nav(Text::new("Key name (a-z A-Z 0-9 _)").prompt()));
    let name = name.trim().to_string();
    if name.is_empty() || !is_valid_string_name(&name) {
        return Err(MenuErr::InvalidKeyName { name });
    }
    let store = console.config.store_path();
    if store.join(&name).exists() {
        return Err(MenuErr::KeyExists { name });
    }
    let kind = ask!(nav(Select::new(
        "Secret encoding",
        SecretKind::ALL.to_vec()
    )
    .without_filtering()
    .prompt()));
    let entered = Zeroizing::new(ask!(nav(Password::new("Secret")
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt())));
    let secret = Zeroizing::new(decode_secret(kind, entered.trim())?);
    let keyring = keyring_of(console)?;
    let dek = ask!(dek_for(
        console,
        &keyring,
        &format!("Unlock \"{name}\" to import a key")
    ));
    encrypt_file(&store, &name, &dek, &secret)?;
    backup::push_all(&console.config)?;
    Ok(Step {
        choice: MenuChoice::Keys,
        notice: format!("imported \"{name}\" as {kind}"),
    })
}

fn decode_secret(kind: SecretKind, entered: &str) -> Result<Vec<u8>, MenuErr> {
    match kind {
        SecretKind::Ethereum => df_share::from_hex_str(entered).ok_or(MenuErr::BadHexSecret),
        SecretKind::Solana => Ok(bs58::decode(entered).into_vec()?),
        SecretKind::Bytes => Ok(entered.as_bytes().to_vec()),
    }
}

fn sign_screen(console: &Console, approver: &ConsoleApprover) -> Result<Step, MenuErr> {
    let path = ask!(nav(Text::new("JSON intent file").prompt()));
    let body = std::fs::read(resolve_path(path.trim()))?;
    let Intent::SafeTx(intent) = serde_json::from_slice(&body)?;
    let ctx = OpContext {
        key: intent.key,
        op: Operation::Sign,
        peer: Peer::Cli,
    };
    let signed = console.api.sign_intent(&ctx, &body, approver)?;
    Ok(Step {
        choice: MenuChoice::Back,
        notice: String::from_utf8_lossy(&signed).into_owned(),
    })
}

fn exposure_screen(console: &mut Console, approver: &ConsoleApprover) -> Result<Step, MenuErr> {
    let addr = match &console.serving {
        Serving::Live { addr, .. } => *addr,
        Serving::Refused => return Err(MenuErr::NotServing),
    };
    let action = ask!(nav(Select::new("Exposure", ExposureAction::ALL.to_vec())
        .with_help_message("esc goes back")
        .without_filtering()
        .prompt()));
    let notice = match action {
        ExposureAction::Back => {
            return Ok(Step {
                choice: MenuChoice::Back,
                notice: String::new(),
            })
        }
        ExposureAction::ReadTest => return read_test(console, approver, addr),
        ExposureAction::Open => {
            let target = ask!(nav(Text::new("SSH target (user@host)").prompt()));
            let remote_port = ask!(nav(CustomType::<u16>::new("Remote port").prompt()));
            let spec = TunnelSpec {
                target: target.trim().to_string(),
                remote_port,
                local_port: addr.port(),
            };
            let id = console.tunnels.open(spec.clone())?;
            format!("opened {}", tunnel_label(id, &spec))
        }
        ExposureAction::List => {
            let open = console.tunnels.list();
            if open.is_empty() {
                "no tunnels open".to_string()
            } else {
                let mut lines = Vec::new();
                for (id, spec) in open {
                    lines.push(tunnel_label(id, &spec));
                }
                lines.join("\n")
            }
        }
        ExposureAction::Close => {
            let open = console.tunnels.list();
            if open.is_empty() {
                return Err(MenuErr::NoTunnels);
            }
            let mut options = Vec::new();
            for (id, spec) in open {
                options.push(TunnelChoice {
                    id,
                    label: tunnel_label(id, &spec),
                });
            }
            let chosen = ask!(nav(Select::new("Close tunnel", options)
                .without_filtering()
                .prompt()));
            console.tunnels.close(chosen.id)?;
            format!("closed {}", chosen.label)
        }
    };
    Ok(Step {
        choice: MenuChoice::Exposure,
        notice,
    })
}

/// One open tunnel as a selectable line.
struct TunnelChoice {
    /// Handle the console closes.
    id: TunnelId,
    /// Rendered line shown in the menu.
    label: String,
}

impl fmt::Display for TunnelChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label)
    }
}

fn tunnel_label(id: TunnelId, spec: &TunnelSpec) -> String {
    format!(
        "tunnel {} {} remote localhost:{} -> 127.0.0.1:{}",
        id.0, spec.target, spec.remote_port, spec.local_port
    )
}

/// The read test blocks on an approval only this thread can grant, so it runs as a task
/// while the main thread keeps servicing the very request it made. The timeout measures idle
/// time only: a request answered at the prompt restarts the clock, so a key that really was
/// released is never reported as a timeout.
fn read_test(
    console: &mut Console,
    approver: &ConsoleApprover,
    addr: SocketAddr,
) -> Result<Step, MenuErr> {
    let key = ask!(nav(Select::new(
        "Key to read-test",
        keystore_names(console)?
    )
    .prompt()));
    let handle = readtest::spawn(&console.runtime, addr, key);
    let mut idle = Instant::now();
    loop {
        let drained = match service_pending(console, approver) {
            Ok(drained) => drained,
            Err(e) => {
                handle.abort();
                refuse_pending(console);
                return Err(e);
            }
        };
        if handle.is_finished() {
            break;
        }
        if drained.quit {
            handle.abort();
            refuse_pending(console);
            return Ok(Step {
                choice: MenuChoice::Quit,
                notice: String::new(),
            });
        }
        if drained.answered > 0 || drained.refused > 0 {
            idle = Instant::now();
        }
        if idle.elapsed() >= READ_TEST_TIMEOUT {
            handle.abort();
            refuse_pending(console);
            return Err(MenuErr::ReadTestTimedOut);
        }
        std::thread::sleep(DRAIN_POLL);
    }
    let proof = console.runtime.block_on(handle)??;
    let mut lines = vec![
        format!("read \"{}\" over https://{}", proof.key, addr),
        format!("secret bytes: {}", proof.secret_len),
        format!("salted digest: {}", proof.digest),
    ];
    if let Some(evm) = proof.evm_address {
        lines.push(format!("evm address: {evm}"));
    }
    Ok(Step {
        choice: MenuChoice::Exposure,
        notice: lines.join("\n"),
    })
}

fn backup_screen(console: &Console) -> Result<Step, MenuErr> {
    let action = ask!(nav(Select::new("Backup", BackupAction::ALL.to_vec())
        .with_help_message("esc goes back")
        .without_filtering()
        .prompt()));
    let notice = match action {
        BackupAction::Back => {
            return Ok(Step {
                choice: MenuChoice::Back,
                notice: String::new(),
            })
        }
        BackupAction::Push => {
            if console.config.backup_remotes.is_empty() {
                return Err(MenuErr::NoBackupRemote);
            }
            backup::push_all(&console.config)?;
            format!(
                "pushed the store to {} remote(s)",
                console.config.backup_remotes.len()
            )
        }
        BackupAction::Pull => {
            let Some(remote) = console.config.backup_remotes.first() else {
                return Err(MenuErr::NoBackupRemote);
            };
            let confirmed = ask!(nav(Confirm::new(
                "Pull replaces the local store with the remote copy. Continue?"
            )
            .with_default(false)
            .prompt()));
            if !confirmed {
                return Ok(Step {
                    choice: MenuChoice::Backup,
                    notice: "pull declined".to_string(),
                });
            }
            backup::pull(&console.config, remote)?;
            format!("pulled the store from {}", remote.host)
        }
    };
    Ok(Step {
        choice: MenuChoice::Backup,
        notice,
    })
}

fn enroll_screen(console: &Console) -> Result<Step, MenuErr> {
    let action = ask!(nav(Select::new("Enroll", EnrollAction::ALL.to_vec())
        .with_help_message("esc goes back")
        .without_filtering()
        .prompt()));
    let (kind, default_label, unlocker): (&str, &str, Box<dyn Unlocker>) = match action {
        EnrollAction::Back => {
            return Ok(Step {
                choice: MenuChoice::Back,
                notice: String::new(),
            })
        }
        EnrollAction::Se => {
            ensure_se_key(SE_KEY_LABEL)?;
            (
                "secure enclave",
                "secure-enclave",
                Box::new(SecureEnclaveUnlocker::new(SE_KEY_LABEL)),
            )
        }
        EnrollAction::Passphrase => {
            let new = ask!(nav(Password::new("New recovery passphrase")
                .with_display_mode(PasswordDisplayMode::Masked)
                .with_custom_confirmation_message("Confirm the new recovery passphrase")
                .prompt()));
            (
                "recovery passphrase",
                "recovery",
                Box::new(PassphraseUnlocker::new(new)),
            )
        }
    };
    let label = ask!(nav(Text::new("Enrollment label")
        .with_default(default_label)
        .prompt()));
    let mut keyring = keyring_of(console)?;
    let dek = ask!(dek_for(
        console,
        &keyring,
        "Enroll a new hot_cheese unlock method"
    ));
    let enrollment = unlocker.enroll(label.trim(), &dek)?;
    let id = enrollment.id.clone();
    keyring.add(enrollment);
    keyring.save(&MacBackend::keyring_path(&console.config.store))?;
    Ok(Step {
        choice: MenuChoice::Enroll,
        notice: format!("enrolled {kind} as {id}"),
    })
}

fn status_screen(console: &Console) -> Result<Step, MenuErr> {
    let mut out = std::io::stderr();
    writeln!(out, "{}\n", status::view(console))?;
    out.flush()?;
    let action = ask!(nav(Select::new("Status", StatusAction::ALL.to_vec())
        .with_help_message("esc goes back")
        .without_filtering()
        .prompt()));
    match action {
        StatusAction::Refresh => Ok(Step {
            choice: MenuChoice::Status,
            notice: String::new(),
        }),
        StatusAction::Back => Ok(Step {
            choice: MenuChoice::Back,
            notice: String::new(),
        }),
    }
}

fn serve_screen(console: &mut Console, approver: &ConsoleApprover) -> Result<Step, MenuErr> {
    let Console {
        api,
        serving,
        tunnels,
        ..
    } = console;
    let Serving::Live { addr, ops, .. } = serving else {
        return Err(MenuErr::NotServing);
    };
    let addr = *addr;
    let mut out = std::io::stderr();
    writeln!(
        out,
        "approving every incoming request here; esc stops serving, ctrl-c quits\n"
    )?;
    out.flush()?;
    match approval::serve_and_approve(api, approver, ops, addr, tunnels) {
        Ok(()) | Err(ApprovalErr::Inquire(InquireError::OperationCanceled)) => Ok(Step {
            choice: MenuChoice::Back,
            notice: "stopped serving".to_string(),
        }),
        Err(
            ApprovalErr::ShutdownRequested
            | ApprovalErr::Inquire(InquireError::OperationInterrupted),
        ) => Ok(Step {
            choice: MenuChoice::Quit,
            notice: String::new(),
        }),
        Err(ApprovalErr::ListenerGone) => {
            console.serving = Serving::Refused;
            Ok(Step {
                choice: MenuChoice::Back,
                notice: "the https listener exited: nothing is served any more".to_string(),
            })
        }
        Err(e) => Err(e.into()),
    }
}

fn keyring_of(console: &Console) -> Result<Keyring, MenuErr> {
    Ok(Keyring::load(&MacBackend::keyring_path(
        &console.config.store,
    ))?)
}

/// Unwrap the DEK through the same KEK that opened this session.
fn dek_for(console: &Console, keyring: &Keyring, reason: &str) -> Result<Nav<Dek>, MenuErr> {
    let unlocker: Box<dyn Unlocker> = match console.gate {
        UnlockGate::Biometric => Box::new(SecureEnclaveUnlocker::new(SE_KEY_LABEL)),
        UnlockGate::Passphrase => {
            let entered = match nav(Password::new("Recovery passphrase")
                .with_display_mode(PasswordDisplayMode::Masked)
                .without_confirmation()
                .prompt())?
            {
                Nav::Chose(p) => p,
                Nav::Back => return Ok(Nav::Back),
                Nav::Quit => return Ok(Nav::Quit),
            };
            Box::new(PassphraseUnlocker::new(entered))
        }
    };
    Ok(Nav::Chose(unlocker.unlock(reason, keyring, None)?))
}

/// Every keystore in the store dir, sorted, excluding the keyring envelope itself.
fn keystore_names(console: &Console) -> Result<Vec<String>, MenuErr> {
    let keyring = MacBackend::keyring_path(&console.config.store);
    let mut names = Vec::new();
    for entry in std::fs::read_dir(console.config.store_path())? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path() == keyring {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_valid_string_name(&name) {
            names.push(name);
        }
    }
    if names.is_empty() {
        return Err(MenuErr::NoKeystores);
    }
    names.sort();
    Ok(names)
}

fn list_notice(console: &Console) -> Result<String, MenuErr> {
    let keyring = keyring_of(console)?;
    let mut lines = Vec::new();
    match keystore_names(console) {
        Ok(names) => {
            for name in names {
                lines.push(format!("keystore {name}"));
            }
        }
        Err(MenuErr::NoKeystores) => lines.push("no keystores".to_string()),
        Err(e) => return Err(e),
    }
    for enrollment in &keyring.enrollments {
        let kind = match enrollment.params {
            EnrollParams::SecureEnclave { .. } => "secure_enclave",
            EnrollParams::Passphrase { .. } => "passphrase",
        };
        lines.push(format!(
            "enrollment {} {} \"{}\"",
            enrollment.id, kind, enrollment.label
        ));
    }
    if !keyring.has_passphrase() {
        lines.push(
            "no recovery passphrase enrolled: losing the Secure Enclave key loses the store"
                .to_string(),
        );
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every section is reachable from the root, re-picking a section stays put so the
    /// drain runs between screens, Back climbs exactly one level, and both Quit anywhere
    /// and Back at the root terminate the loop.
    #[test]
    fn transitions_enter_and_leave_submenus() {
        for (choice, state) in [
            (MenuChoice::Keys, MenuState::Keys),
            (MenuChoice::Sign, MenuState::Sign),
            (MenuChoice::Exposure, MenuState::Exposure),
            (MenuChoice::Backup, MenuState::Backup),
            (MenuChoice::Enroll, MenuState::Enroll),
            (MenuChoice::Status, MenuState::Status),
            (MenuChoice::ServeAndApprove, MenuState::ServeAndApprove),
        ] {
            assert_eq!(next(MenuState::Root, choice), state);
            assert_eq!(next(state, choice), state);
            assert_eq!(next(state, MenuChoice::Back), MenuState::Root);
            assert_eq!(next(state, MenuChoice::Quit), MenuState::Quit);
        }
        assert_eq!(next(MenuState::Root, MenuChoice::Back), MenuState::Quit);
        assert_eq!(next(MenuState::Root, MenuChoice::Quit), MenuState::Quit);
    }
}
