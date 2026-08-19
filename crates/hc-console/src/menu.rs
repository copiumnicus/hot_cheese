//! The arrow-key menu tree: one [`super::pick::pick`] list per screen, redrawn rather than
//! streamed. The prompts that are not a list — a line of text, a number, a masked secret, a
//! yes/no — stay on inquire, so [`nav`] and [`MenuErr::Inquire`] stay with them.
use super::approval::{self, ApprovalErr, Drained};
use super::pick::{pick, Filter, Pick};
use super::{bundles, readtest, status, Console};
use crossterm::cursor::MoveTo;
use crossterm::terminal::{Clear, ClearType};
use err_mac::create_err_with_impls;
use hc_core::crypto::envelope::{
    encrypt_file_new, read_keystore, Dek, EnvErr, KeyUse, MAX_SECRET_BYTES,
};
use hc_core::is_valid_key_name;
use hc_core::keyring::{EnrollParams, Keyring};
use hc_core::mac::secure_enclave::{ensure_se_key, SE_KEY_LABEL};
use hc_core::mac::MacBackend;
use hc_core::unlock::{PassphraseUnlocker, SecureEnclaveUnlocker, UnlockErr, Unlocker};
use hc_daemon::exposure::{TunnelId, TunnelSpec};
use hc_daemon::git_store;
use hc_daemon::live::Live;
use hc_daemon::runtime::{Runtime, Serving, UnlockGate};
use hc_daemon::{OpContext, Operation};
use hc_sign::grant::now_secs;
use inquire::{Confirm, CustomType, InquireError, Password, PasswordDisplayMode, Text};
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

/// The question every creation screen asks, spelling out that one answer is permanent.
const USE_PROMPT: &str = "Use (sign_only can never be exported, and never loosened)";

/// Store file names one pull question lists before it counts the rest.
const PULL_FILES_SHOWN: usize = 8;

create_err_with_impls!(
    #[derive(Debug)]
    pub MenuErr,
    NotServing,
    NoKeystores,
    NoTunnels,
    NoDiscoveredPeers,
    NoEnrolledPeers,
    BadHexSecret,
    ReadTestTimedOut,
    Inquire(inquire::InquireError),
    Tunnel(hc_daemon::exposure::TunnelErr),
    Approval(super::approval::ApprovalErr),
    ReadTest(super::readtest::ReadTestErr),
    ApiBackend(hc_daemon::ApiBackendErr),
    Bundle(hc_bundle::BundleErr),
    BundlePoll(hc_bundle::poll::PollErr),
    BundleSync(hc_bundle::sync::SyncErr),
    Render(hc_daemon::qr_term::RenderErr),
    Grant(hc_sign::grant::GrantErr),
    Sign(hc_sign::SignErr),
    Unlock(hc_core::unlock::UnlockErr),
    Keyring(hc_core::keyring::KeyringErr),
    Git(hc_daemon::git_store::GitErr),
    Config(hc_core::config::ConfigErr),
    Envelope(hc_core::crypto::envelope::EnvErr),
    Se(hc_core::mac::secure_enclave::SeErr),
    Base58(bs58::decode::Error),
    Serde(serde_json::Error),
    Join(tokio::task::JoinError),
    StdIo(std::io::Error)
    ;
    InvalidKeyName { name: String },
    KeyExists { name: String },
    SecretInputTooLarge { size: usize, max: usize },
    NotBundleable { kind: hc_sign::grant::IntentKind },
    NotATerminal { source: std::io::Error }
);

/// Hex is the widest supported textual encoding; this also bounds base58 decoding work.
const MAX_ENCODED_SECRET_BYTES: usize = MAX_SECRET_BYTES * 2 + 2;

fn path_is_occupied(path: &std::path::Path) -> Result<bool, std::io::Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Which screen the console is showing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuState {
    Root,
    Keys,
    Bundles,
    BundlePeers,
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
    Bundles,
    BundlePeers,
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
            MenuChoice::Bundles => "Bundles",
            MenuChoice::BundlePeers => "Peers",
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

impl Pick for MenuChoice {
    fn describe(&self) -> &str {
        match self {
            MenuChoice::Keys => {
                "List, generate, import and address the keystores in the store dir. Only the \
                 address and import verbs unlock anything."
            }
            MenuChoice::Bundles => {
                "Collect several owners' signatures for one Safe transaction across machines: \
                 sign, import, export, watch, and sync over the tailnet."
            }
            MenuChoice::BundlePeers => {
                "The machines this one exchanges bundles with. Enrolling or dropping one \
                 rewrites the config; no key is touched."
            }
            MenuChoice::Exposure => {
                "Reverse ssh tunnels that publish this session's loopback listener, and the read \
                 test over the pinned TLS route. Every tunnel dies with the session."
            }
            MenuChoice::Backup => {
                "Push the store's commits to the configured remotes, fetch theirs, and read how \
                 the two stand. Ciphertext only: nothing is decrypted here."
            }
            MenuChoice::Enroll => {
                "Add another way to unwrap the DEK — a Secure Enclave key, or a recovery \
                 passphrase. It unlocks once, with the method that opened this session."
            }
            MenuChoice::Status => {
                "A panel that keeps itself up to date: where the daemon listens, how the store \
                 stands against every remote, what the bundle poller last did, and the log tail. \
                 [p] asks for a fetch, [r] re-reads the store, [q] leaves."
            }
            MenuChoice::ServeAndApprove => {
                "Waits on the incoming requests and puts each one in front of you as it lands, \
                 with its own approval prompt. q or esc stops serving."
            }
            MenuChoice::Back => "Leave this screen for the one above it.",
            MenuChoice::Quit => {
                "Close every ssh tunnel this session opened, stop the listener, and leave the \
                 console."
            }
        }
    }
}

impl Pick for KeyUse {
    fn describe(&self) -> &str {
        match self {
            KeyUse::SignOnly => {
                "The key signs inside the daemon and no path can export it: /read refuses it \
                 forever, and the choice can never be loosened."
            }
            KeyUse::Shareable => {
                "The key may be handed to a client over /read, which is the only way it ever \
                 leaves this machine."
            }
        }
    }
}

/// Where a choice lands. Back climbs exactly one level, so the one screen that sits under
/// another — the bundle peers — returns to its parent rather than to the root, and backing out
/// of the root screen leaves the console.
pub fn next(state: MenuState, choice: MenuChoice) -> MenuState {
    match (state, choice) {
        (_, MenuChoice::Quit) => MenuState::Quit,
        (MenuState::Root, MenuChoice::Back) => MenuState::Quit,
        (MenuState::BundlePeers, MenuChoice::Back) => MenuState::Bundles,
        (_, MenuChoice::Back) => MenuState::Root,
        (_, MenuChoice::Keys) => MenuState::Keys,
        (_, MenuChoice::Bundles) => MenuState::Bundles,
        (_, MenuChoice::BundlePeers) => MenuState::BundlePeers,
        (_, MenuChoice::Exposure) => MenuState::Exposure,
        (_, MenuChoice::Backup) => MenuState::Backup,
        (_, MenuChoice::Enroll) => MenuState::Enroll,
        (_, MenuChoice::Status) => MenuState::Status,
        (_, MenuChoice::ServeAndApprove) => MenuState::ServeAndApprove,
    }
}

/// Whether a session that is not serving may enter `target`. The two screens that open a tunnel
/// or read a key off-process are the ones a refused session must not reach.
pub(crate) fn allowed(target: MenuState, serving: &Serving) -> bool {
    !matches!(target, MenuState::Exposure | MenuState::ServeAndApprove)
        || !matches!(serving, Serving::Refused)
}

/// One screen's choices: each variant carries the line the list shows and the sentence → opens
/// under it, so a new variant without a description does not compile.
macro_rules! menu_enum {
    ($name:ident { $($variant:ident => $label:literal, $describe:literal),+ $(,)? }) => {
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
        impl $crate::pick::Pick for $name {
            fn describe(&self) -> &str {
                match self {
                    $(Self::$variant => $describe,)+
                }
            }
        }
    };
}
pub(crate) use menu_enum;

menu_enum!(KeyAction {
    List => "List keystores and enrollments",
        "Reads the store dir and the keyring header: every keystore with its use, and every \
         enrolled unlock method. Decrypts nothing and prompts for nothing.",
    Generate => "Generate a new key",
        "Mints a key, seals it under the DEK — one unlock of the store — and commits the store, \
         which the session then pushes to every backup remote. The use you pick is permanent.",
    Address => "Show a public address",
        "Decrypts one keystore to derive its public address: an unlock of the store, and a Touch \
         ID where that is the gate, even though nothing leaves this machine.",
    Add => "Import an existing secret",
        "Takes a secret at a masked prompt, seals it under the DEK, and commits the store, which \
         the session then pushes to every backup remote. The use you pick is permanent.",
    Back => "Back",
        "Leave this screen for the one above it.",
});

menu_enum!(ExposureAction {
    Open => "Open a reverse ssh tunnel",
        "Runs ssh -R to the host you name, so a remote port reaches this session's https \
         listener. The tunnel dies with the session.",
    List => "List open tunnels",
        "Prints the tunnels this session opened with their remote and local ports. Touches \
         nothing.",
    Close => "Close a tunnel",
        "Kills one tunnel's ssh child, and the remote port stops answering at once.",
    ReadTest => "Read test over the pinned TLS route",
        "Fetches one key the way a remote client would, over the pinned TLS route, to prove the \
         whole path works. It approves a request and releases that key.",
    Back => "Back",
        "Leave this screen for the one above it.",
});

menu_enum!(BackupAction {
    Status => "Show the store and its remotes",
        "Prints this install's vault, its local commit, and how each remote stood at the last \
         fetch. Touches no network and writes nothing.",
    Push => "Push the store to every remote",
        "Pushes this install's commits to every configured remote, ciphertext as it sits on \
         disk. A remote that does not answer is a warning; all of them failing is an error.",
    Fetch => "Fetch and inspect",
        "Fetches and validates every remote without changing the active store. Remote commits \
         become active only through an explicit forced pull.",
    Pull => "Forced pull from the first remote (DESTRUCTIVE)",
        "Explicitly trusts the first remote and replaces this machine's history, changing or \
         deleting the local files it names before asking.",
    Back => "Back",
        "Leave this screen for the one above it.",
});

menu_enum!(EnrollAction {
    Se => "Secure Enclave (Touch ID)",
        "Wraps the DEK under a Secure Enclave key that never leaves this Mac, so Touch ID opens \
         the store. Unlocks once with the method that opened this session.",
    Passphrase => "Recovery passphrase",
        "Wraps the DEK under a passphrase you type twice. It is the only way back into the \
         store if the Secure Enclave key is ever lost.",
    Back => "Back",
        "Leave this screen for the one above it.",
});

menu_enum!(Chain {
    Evm => "EVM",
        "A secp256k1 key and its 0x address: Ethereum and every chain that copies it.",
    Solana => "Solana",
        "An ed25519 keypair and its base58 address.",
});

menu_enum!(SecretKind {
    Ethereum => "Ethereum private key (hex)",
        "A secp256k1 private key as hex, with or without the 0x.",
    Solana => "Solana keypair (base58)",
        "A Solana keypair in base58, the form solana-keygen writes.",
    Bytes => "Raw UTF-8 bytes",
        "What you type, stored as its own bytes: for a secret that is not a chain key.",
});

/// What a prompt produced: a value, or the two keys that mean navigation.
pub(crate) enum Nav<T> {
    Chose(T),
    Back,
    Quit,
}

/// Esc backs out one level and Ctrl-C quits, so neither ever becomes an error.
pub(crate) fn nav<T>(answer: Result<T, InquireError>) -> Result<Nav<T>, MenuErr> {
    match answer {
        Ok(v) => Ok(Nav::Chose(v)),
        Err(InquireError::OperationCanceled) => Ok(Nav::Back),
        Err(InquireError::OperationInterrupted) => Ok(Nav::Quit),
        Err(e) => Err(e.into()),
    }
}

/// One screen's outcome: where to go, and what the next frame shows.
pub(crate) struct Step {
    /// Where the operator wants to go from here.
    pub(crate) choice: MenuChoice,
    /// Result text rendered at the top of the next frame.
    pub(crate) notice: String,
}

/// Take a prompt's answer, or leave the screen the way Esc and Ctrl-C mean. The one-argument
/// form backs out to the parent screen; a nested prompt names the screen it belongs to, so Esc
/// still climbs exactly one level from inside a section.
macro_rules! ask {
    ($answer:expr) => {
        ask!($answer, MenuChoice::Back)
    };
    ($answer:expr, $back:expr) => {
        match $answer? {
            Nav::Chose(v) => v,
            Nav::Back => {
                return Ok(Step {
                    choice: $back,
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
pub(crate) use ask;

/// Draw screens and run the operator's choices until they quit. A screen that fails without
/// having asked anything must not be re-entered on the next pass: the two screens that need a
/// live listener fall back to the root, and a terminal that cannot prompt at all ends the run.
pub fn run(console: &mut Console) -> Result<(), MenuErr> {
    let mut state = MenuState::Root;
    let mut notice = String::new();
    loop {
        match service_pending(console) {
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
                console.rt.serving = Serving::Refused;
                notice = "the https listener exited: nothing is served any more".to_string();
            }
            Err(e @ MenuErr::Approval(ApprovalErr::NoApprovalTerminal)) => return Err(e),
            Err(e) => notice = format!("error: {e}"),
        }
        if state == MenuState::Quit {
            return Ok(());
        }
        draw(console, &notice)?;
        let step = match screen(console, state) {
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
            Err(
                e @ (MenuErr::NotATerminal { .. }
                | MenuErr::Approval(ApprovalErr::NoApprovalTerminal)),
            ) => return Err(e),
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
        let refused = !allowed(target, &console.rt.serving);
        if refused {
            notice = format!("error: {}", MenuErr::NotServing);
        }
        state = if refused { state } else { target };
    }
}

/// Run the requests that queued while the operator was elsewhere in the tree.
pub(crate) fn service_pending(console: &mut Console) -> Result<Drained, MenuErr> {
    let Runtime {
        api,
        approver,
        serving,
        tunnels,
        ..
    } = &mut console.rt;
    let Serving::Live { ops, .. } = serving else {
        return Ok(Drained::default());
    };
    Ok(approval::drain(api, approver, ops, tunnels)?)
}

/// The read test's own request may still be queued when it is abandoned, and its caller is
/// then gone: deny it rather than prompting the operator for an answer nobody will read.
fn refuse_pending(console: &mut Console) {
    let Serving::Live { ops, .. } = &mut console.rt.serving else {
        return;
    };
    approval::refuse_queued(ops);
}

/// Replace the screen with the session header and the last outcome.
fn draw(console: &Console, notice: &str) -> Result<(), MenuErr> {
    let mut out = std::io::stderr();
    crossterm::execute!(out, Clear(ClearType::All), MoveTo(0, 0))?;
    writeln!(out, "hot_cheese")?;
    match console.rt.gate {
        UnlockGate::Biometric => {
            writeln!(out, "unlock:  Secure Enclave, Touch ID gates every request")?
        }
        UnlockGate::Passphrase => writeln!(
            out,
            "unlock:  recovery passphrase, no per-request biometric: nothing is served, \
             tunnels and read tests are refused"
        )?,
    }
    writeln!(out, "serving: {}", console.rt.serving)?;
    writeln!(out, "store:   {}", console.rt.config.store_path().display())?;
    if !notice.is_empty() {
        writeln!(out, "\n{notice}")?;
    }
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn screen(console: &mut Console, state: MenuState) -> Result<Step, MenuErr> {
    match state {
        MenuState::Root => root_screen(&console.rt.live),
        MenuState::Keys => keys_screen(console),
        MenuState::Bundles => bundles::screen(console),
        MenuState::BundlePeers => bundles::peers_screen(console),
        MenuState::Exposure => exposure_screen(console),
        MenuState::Backup => backup_screen(console),
        MenuState::Enroll => enroll_screen(console),
        MenuState::Status => status::panel(console),
        MenuState::ServeAndApprove => serve_screen(console),
        MenuState::Quit => Ok(Step {
            choice: MenuChoice::Quit,
            notice: String::new(),
        }),
    }
}

fn root_screen(live: &Live) -> Result<Step, MenuErr> {
    let options = vec![
        MenuChoice::Keys,
        MenuChoice::Bundles,
        MenuChoice::Exposure,
        MenuChoice::Backup,
        MenuChoice::Enroll,
        MenuChoice::Status,
        MenuChoice::ServeAndApprove,
        MenuChoice::Quit,
    ];
    let choice = ask!(pick(live, "hot_cheese", options, Filter::Off));
    Ok(Step {
        choice,
        notice: String::new(),
    })
}

fn keys_screen(console: &Console) -> Result<Step, MenuErr> {
    let action = ask!(pick(
        &console.rt.live,
        "Keys",
        KeyAction::ALL.to_vec(),
        Filter::Off
    ));
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
    let chain = ask!(pick(
        &console.rt.live,
        "Chain",
        Chain::ALL.to_vec(),
        Filter::Off
    ));
    let name = ask!(nav(Text::new("New key name (a-z A-Z 0-9 _)").prompt()));
    let name = name.trim().to_string();
    if name.is_empty() || !is_valid_key_name(&name) {
        return Err(MenuErr::InvalidKeyName { name });
    }
    if path_is_occupied(&console.rt.config.store_path().join(&name))? {
        return Err(MenuErr::KeyExists { name });
    }
    let key_use = ask!(pick(
        &console.rt.live,
        USE_PROMPT,
        KeyUse::ALL.to_vec(),
        Filter::Off
    ));
    let mutation = console.rt.git.mutation();
    if path_is_occupied(&console.rt.config.store_path().join(&name))? {
        return Err(MenuErr::KeyExists { name });
    }
    let ctx = OpContext::local(
        name.clone(),
        match chain {
            Chain::Evm => Operation::EvmGenerate,
            Chain::Solana => Operation::SolanaGenerate,
        },
    );
    match chain {
        Chain::Evm => console.rt.api.generate(&ctx, key_use)?,
        Chain::Solana => console.rt.api.generate_solana(&ctx, key_use)?,
    }
    mutation.commit()?;
    Ok(Step {
        choice: MenuChoice::Keys,
        notice: format!("generated {chain} key \"{name}\" ({key_use})"),
    })
}

fn address(console: &Console) -> Result<Step, MenuErr> {
    let chain = ask!(pick(
        &console.rt.live,
        "Chain",
        Chain::ALL.to_vec(),
        Filter::Off
    ));
    let name = ask!(pick(
        &console.rt.live,
        "Key",
        keystore_names(console)?,
        Filter::On
    ));
    let ctx = OpContext::local(
        name.clone(),
        match chain {
            Chain::Evm => Operation::EvmAddress,
            Chain::Solana => Operation::SolanaAddress,
        },
    );
    let _stable_store = console.rt.git.mutation();
    let addr = match chain {
        Chain::Evm => console.rt.api.address(&ctx)?,
        Chain::Solana => console.rt.api.address_solana(&ctx)?,
    };
    Ok(Step {
        choice: MenuChoice::Keys,
        notice: format!("{name} {chain} address: {addr}"),
    })
}

fn add(console: &Console) -> Result<Step, MenuErr> {
    let name = ask!(nav(Text::new("Key name (a-z A-Z 0-9 _)").prompt()));
    let name = name.trim().to_string();
    if name.is_empty() || !is_valid_key_name(&name) {
        return Err(MenuErr::InvalidKeyName { name });
    }
    let store = console.rt.config.store_path();
    if path_is_occupied(&store.join(&name))? {
        return Err(MenuErr::KeyExists { name });
    }
    let kind = ask!(pick(
        &console.rt.live,
        "Secret encoding",
        SecretKind::ALL.to_vec(),
        Filter::Off
    ));
    let key_use = ask!(pick(
        &console.rt.live,
        USE_PROMPT,
        KeyUse::ALL.to_vec(),
        Filter::Off
    ));
    let entered = Zeroizing::new(ask!(nav(Password::new("Secret")
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt())));
    let secret = Zeroizing::new(decode_secret(kind, entered.trim())?);
    let mutation = console.rt.git.mutation();
    if path_is_occupied(&store.join(&name))? {
        return Err(MenuErr::KeyExists { name });
    }
    let keyring = keyring_of(console)?;
    let dek = ask!(dek_for(
        console,
        &keyring,
        &format!("Unlock \"{name}\" to import a key")
    ));
    match encrypt_file_new(&store, &name, &dek, key_use, &secret) {
        Err(EnvErr::StdIo(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(MenuErr::KeyExists { name })
        }
        Err(error) => return Err(error.into()),
        Ok(()) => {}
    }
    mutation.commit()?;
    Ok(Step {
        choice: MenuChoice::Keys,
        notice: format!("imported \"{name}\" as {kind} ({key_use})"),
    })
}

fn decode_secret(kind: SecretKind, entered: &str) -> Result<Vec<u8>, MenuErr> {
    if entered.len() > MAX_ENCODED_SECRET_BYTES {
        return Err(MenuErr::SecretInputTooLarge {
            size: entered.len(),
            max: MAX_ENCODED_SECRET_BYTES,
        });
    }
    let decoded = match kind {
        SecretKind::Ethereum => hex::decode(
            entered
                .strip_prefix("0x")
                .or_else(|| entered.strip_prefix("0X"))
                .unwrap_or(entered),
        )
        .map_err(|_| MenuErr::BadHexSecret),
        SecretKind::Solana => Ok(bs58::decode(entered).into_vec()?),
        SecretKind::Bytes => Ok(entered.as_bytes().to_vec()),
    }?;
    if decoded.len() > MAX_SECRET_BYTES {
        return Err(EnvErr::PlaintextTooLarge {
            size: decoded.len(),
            max: MAX_SECRET_BYTES,
        }
        .into());
    }
    Ok(decoded)
}

fn exposure_screen(console: &mut Console) -> Result<Step, MenuErr> {
    let addr = match &console.rt.serving {
        Serving::Live { addr, .. } => *addr,
        Serving::Refused => return Err(MenuErr::NotServing),
    };
    let action = ask!(pick(
        &console.rt.live,
        "Exposure",
        ExposureAction::ALL.to_vec(),
        Filter::Off
    ));
    let notice = match action {
        ExposureAction::Back => {
            return Ok(Step {
                choice: MenuChoice::Back,
                notice: String::new(),
            })
        }
        ExposureAction::ReadTest => return read_test(console, addr),
        ExposureAction::Open => {
            let target = ask!(nav(Text::new("SSH target (user@host)").prompt()));
            let remote_port = ask!(nav(CustomType::<u16>::new("Remote port").prompt()));
            let spec = TunnelSpec {
                target: target.trim().to_string(),
                remote_port,
                local_port: addr.port(),
            };
            let id = console.rt.tunnels.open(spec.clone())?;
            format!("opened {}", tunnel_label(id, &spec))
        }
        ExposureAction::List => {
            let open = console.rt.tunnels.list();
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
            let open = console.rt.tunnels.list();
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
            let chosen = ask!(pick(&console.rt.live, "Close tunnel", options, Filter::Off));
            console.rt.tunnels.close(chosen.id)?;
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

impl Pick for TunnelChoice {
    fn describe(&self) -> &str {
        ""
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
fn read_test(console: &mut Console, addr: SocketAddr) -> Result<Step, MenuErr> {
    let key = ask!(pick(
        &console.rt.live,
        "Key to read-test",
        keystore_names(console)?,
        Filter::On
    ));
    let handle = readtest::spawn(console.rt.tokio.handle(), addr, key);
    let mut idle = Instant::now();
    loop {
        let drained = match service_pending(console) {
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
    let proof = console.rt.tokio.block_on(handle)??;
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
    let action = ask!(pick(
        &console.rt.live,
        "Backup",
        BackupAction::ALL.to_vec(),
        Filter::Off
    ));
    let notice = match action {
        BackupAction::Back => {
            return Ok(Step {
                choice: MenuChoice::Back,
                notice: String::new(),
            })
        }
        BackupAction::Status => backup_notice(&console.rt.git.status().snapshot()),
        BackupAction::Push => {
            console.rt.git.push_every(&console.rt.config)?;
            format!(
                "pushed the store to {} remote(s)",
                console.rt.config.backup_remotes.len()
            )
        }
        BackupAction::Fetch => {
            console.rt.git.fetch_every(&console.rt.config)?;
            backup_notice(&console.rt.git.status().snapshot())
        }
        BackupAction::Pull => {
            let Some(remote) = console.rt.config.backup_remotes.first() else {
                return Err(git_store::GitErr::NoBackupRemote.into());
            };
            let vault = git_store::pull_vault(&console.rt.config, remote, None)?;
            let mut doomed = console.rt.git.pull_preview(remote, &vault)?;
            let mut out = std::io::stderr();
            writeln!(out, "{}\n", pull_report(&doomed, now_secs()?))?;
            out.flush()?;
            let confirmed = ask!(nav(Confirm::new(&doomed_prompt(&doomed))
                .with_default(false)
                .prompt()));
            if !confirmed {
                return Ok(Step {
                    choice: MenuChoice::Backup,
                    notice: "pull declined".to_string(),
                });
            }
            if let Some(rewind) = doomed.rewind {
                let question =
                    rewind_prompt(rewind, doomed.local_only, &doomed.changed, &doomed.removed);
                let accepted = ask!(nav(Confirm::new(&question).with_default(false).prompt()));
                if !accepted {
                    return Ok(Step {
                        choice: MenuChoice::Backup,
                        notice: "rollback declined; the store is unchanged".to_string(),
                    });
                }
                doomed.accept_rewind();
            }
            console.rt.git.pull_apply(&doomed)?;
            format!("pulled vault {vault} from {}", remote.host)
        }
    };
    Ok(Step {
        choice: MenuChoice::Backup,
        notice,
    })
}

/// At most [`PULL_FILES_SHOWN`] names, then a count of the rest, so a large diff cannot bury the
/// question underneath it.
fn names(files: &[String]) -> String {
    let mut shown = Vec::new();
    for name in files.iter().take(PULL_FILES_SHOWN) {
        shown.push(name.as_str());
    }
    match files.len().saturating_sub(PULL_FILES_SHOWN) {
        0 => shown.join(", "),
        rest => format!("{}, … and {rest} more", shown.join(", ")),
    }
}

/// One line per class of store file the incoming tip touches, absent where that class is empty.
fn touched(mark: &str, label: &str, files: &[String]) -> Option<String> {
    match files.is_empty() {
        true => None,
        false => Some(format!(
            "  {mark} {label} {}: {}",
            files.len(),
            names(files)
        )),
    }
}

/// What the incoming tip is, against what this machine holds. Ancestry proves neither authorship
/// nor freshness, so both sides are counted and the remote's stamp is labelled as its own claim
/// rather than as truth.
fn pull_report(doomed: &git_store::Doomed, now: u64) -> String {
    let mut lines = vec![
        format!("incoming {} — {}", doomed.remote_head, doomed.relation),
        format!(
            "  local  {} commit(s) the incoming tip does not have{}",
            doomed.local_only,
            match doomed.local_at {
                Some(at) => format!(", HEAD committed {} ago", status::age(at, now)),
                None => ", no local commit yet".to_string(),
            }
        ),
        format!(
            "  remote {} commit(s) this machine does not have, stamped {} ago by the remote's \
             own clock",
            doomed.remote_only,
            status::age(doomed.remote_at, now)
        ),
    ];
    if let Some(line) = touched("+", "adds", &doomed.added) {
        lines.push(line);
    }
    if let Some(line) = touched("~", "replaces", &doomed.changed) {
        lines.push(line);
    }
    if let Some(line) = touched("!!", "REMOVES", &doomed.removed) {
        lines.push(line);
    }
    lines.join("\n")
}

/// The second question a rollback costs, naming the specific loss. A backup host chooses the
/// history it serves, so accepting a fast-forward is not accepting this.
fn rewind_prompt(
    rewind: git_store::Rewind,
    local_only: u64,
    changed: &[String],
    removed: &[String],
) -> String {
    let danger = match rewind {
        git_store::Rewind::Backwards => format!(
            "ROLLBACK: the incoming tip is older history this machine already moved past, and \
             applying it discards {local_only} local commit(s)"
        ),
        git_store::Rewind::Fork => format!(
            "FORK: the incoming tip does not contain {local_only} commit(s) made on this machine, \
             and applying it discards them"
        ),
        git_store::Rewind::Deletes => format!(
            "DELETES {} store file(s) — {}",
            removed.len(),
            names(removed)
        ),
        git_store::Rewind::Contents => format!(
            "OLDER CONTENT: nothing is deleted and no local commit is discarded — the incoming tip \
             REPLACES {} security-relevant file(s) with older content — {}",
            changed.len(),
            names(changed)
        ),
    };
    format!(
        "{danger}. Ancestry proves neither who wrote this history nor that it is current, so a \
         hostile backup host can serve exactly it: this can revive a retired keystore, restore an \
         older keyring.json, or reinstate a looser policy. Accept this rollback?"
    )
}

/// A forced pull is the one action here that can replace key material and policy, so the
/// question names every tracked file it changes and every untracked file it deletes.
fn doomed_prompt(doomed: &git_store::Doomed) -> String {
    let mut affected = doomed.tracked.clone();
    affected.extend_from_slice(&doomed.untracked);
    match affected.is_empty() {
        true => "Pull explicitly trusts the remote and replaces this machine's history. \
                 The working tree is already identical. Continue?"
            .to_string(),
        false => format!(
            "Pull explicitly trusts the remote and changes or deletes {} local file(s) — {}. \
             Continue?",
            affected.len(),
            names(&affected)
        ),
    }
}

/// One line per remote: how it stood at the last fetch, and why it last failed.
fn backup_notice(state: &git_store::GitState) -> String {
    let mut lines = vec![format!(
        "vault {} at {}{}",
        match &state.vault {
            Some(v) => v.to_string(),
            None => "none".to_string(),
        },
        match &state.head {
            Some(head) => head.to_string(),
            None => "no commit yet".to_string(),
        },
        match state.fetching {
            true => "  (fetching)",
            false => "",
        }
    )];
    if state.remotes.is_empty() {
        lines.push("no backup remotes configured".to_string());
    }
    for remote in &state.remotes {
        lines.push(format!(
            "{} {} {}",
            remote.host, remote.folder, remote.relation
        ));
        if let Some(failure) = &remote.last_failure {
            lines.push(format!(
                "  last failure {:?}: {} {}",
                failure.op, failure.cause, failure.stderr
            ));
        }
    }
    lines.join("\n")
}

fn enroll_screen(console: &Console) -> Result<Step, MenuErr> {
    let action = ask!(pick(
        &console.rt.live,
        "Enroll",
        EnrollAction::ALL.to_vec(),
        Filter::Off
    ));
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
        EnrollAction::Passphrase => (
            "recovery passphrase",
            "recovery",
            Box::new(PassphraseUnlocker::from_secret(ask!(new_passphrase()))),
        ),
    };
    let label = ask!(nav(Text::new("Enrollment label")
        .with_default(default_label)
        .prompt()));
    let mutation = console.rt.git.mutation();
    let mut keyring = keyring_of(console)?;
    let dek = ask!(dek_for(
        console,
        &keyring,
        "Enroll a new hot_cheese unlock method"
    ));
    let enrollment = unlocker.enroll(label.trim(), &dek)?;
    let id = enrollment.id.clone();
    let mut change = String::new();
    if let EnrollParams::SecureEnclave { se_pub, .. } = &enrollment.params {
        let mut adopted = false;
        for enrolled in &keyring.enrollments {
            if let EnrollParams::SecureEnclave {
                se_pub: recorded, ..
            } = &enrolled.params
            {
                adopted |= recorded == se_pub;
            }
        }
        let se_key = se_fingerprint(se_pub);
        change = match adopted {
            true => format!(
                "\nADOPTED the Secure Enclave key se_key {se_key} already on this disk; stop \
                 unless this is the fingerprint you enrolled"
            ),
            false => format!(
                "\nMINTED a new Secure Enclave key se_key {se_key}: the set of enclave keys this \
                 store trusts CHANGED"
            ),
        };
    }
    keyring.add(enrollment);
    keyring.save(&MacBackend::keyring_path(&console.rt.config.store))?;
    mutation.commit()?;
    Ok(Step {
        choice: MenuChoice::Enroll,
        notice: format!("enrolled {kind} as {id}{change}"),
    })
}

fn serve_screen(console: &mut Console) -> Result<Step, MenuErr> {
    let label = console.rt.serving.to_string();
    let Runtime {
        api,
        approver,
        serving,
        tunnels,
        live,
        ..
    } = &mut console.rt;
    let Serving::Live { ops, .. } = serving else {
        return Err(MenuErr::NotServing);
    };
    let mut out = std::io::stderr();
    writeln!(
        out,
        "approving every incoming request here; esc stops serving, ctrl-c quits\n"
    )?;
    out.flush()?;
    match approval::serve_and_approve(api, approver, ops, &label, tunnels, live) {
        Ok(()) => Ok(Step {
            choice: MenuChoice::Back,
            notice: "stopped serving".to_string(),
        }),
        Err(ApprovalErr::ShutdownRequested) => Ok(Step {
            choice: MenuChoice::Quit,
            notice: String::new(),
        }),
        Err(ApprovalErr::ListenerGone) => {
            console.rt.serving = Serving::Refused;
            Ok(Step {
                choice: MenuChoice::Back,
                notice: "the https listener exited: nothing is served any more".to_string(),
            })
        }
        Err(
            e @ (ApprovalErr::NoApprovalTerminal | ApprovalErr::StdIo(_) | ApprovalErr::Grant(_)),
        ) => Err(e.into()),
    }
}

/// The rule an enrollment applies, run here against a throwaway DEK so the prompt and the
/// enrollment can never disagree about what a new recovery passphrase is.
fn check_new_passphrase(entered: &Zeroizing<String>) -> Result<(), UnlockErr> {
    PassphraseUnlocker::from_secret(entered.clone()).enroll("preflight", &Dek::random())?;
    Ok(())
}

/// Prompt twice, and refuse here what the enrollment would refuse later — before [`dek_for`]
/// spends a Touch ID on a passphrase that was never going to be accepted. A refusal costs a
/// re-prompt, not the screen.
fn new_passphrase() -> Result<Nav<Zeroizing<String>>, MenuErr> {
    let mut out = std::io::stderr();
    loop {
        let entered = Zeroizing::new(
            match nav(Password::new("New recovery passphrase")
                .with_display_mode(PasswordDisplayMode::Masked)
                .with_custom_confirmation_message("Confirm the new recovery passphrase")
                .prompt())?
            {
                Nav::Chose(entered) => entered,
                Nav::Back => return Ok(Nav::Back),
                Nav::Quit => return Ok(Nav::Quit),
            },
        );
        match check_new_passphrase(&entered) {
            Ok(()) => return Ok(Nav::Chose(entered)),
            Err(error) => {
                writeln!(out, "passphrase refused: {error}; enter a different one")?;
                out.flush()?;
            }
        }
    }
}

fn keyring_of(console: &Console) -> Result<Keyring, MenuErr> {
    Ok(Keyring::load(&MacBackend::keyring_path(
        &console.rt.config.store,
    ))?)
}

/// Unwrap the DEK through the same KEK that opened this session.
fn dek_for(console: &Console, keyring: &Keyring, reason: &str) -> Result<Nav<Dek>, MenuErr> {
    let unlocker: Box<dyn Unlocker> = match console.rt.gate {
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
pub(crate) fn keystore_names(console: &Console) -> Result<Vec<String>, MenuErr> {
    let keyring = MacBackend::keyring_path(&console.rt.config.store);
    let mut names = Vec::new();
    for (at, entry) in std::fs::read_dir(console.rt.config.store_path())?.enumerate() {
        if at >= hc_core::MAX_STORE_ENUM_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "store directory has too many entries",
            )
            .into());
        }
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path() == keyring {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_valid_key_name(&name) {
            names.push(name);
        }
    }
    if names.is_empty() {
        return Err(MenuErr::NoKeystores);
    }
    names.sort();
    Ok(names)
}

/// The 16 lowercase hex characters of SHA-256 over a SEC1 enclave public key, the form the
/// bootstrap ritual and the `/read` prompt already name an enclave key by.
pub fn se_fingerprint(public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(public_key)[..8])
}

fn list_notice(console: &Console) -> Result<String, MenuErr> {
    let keyring = keyring_of(console)?;
    let store = console.rt.config.store_path();
    let mut lines = Vec::new();
    match keystore_names(console) {
        Ok(names) => {
            for name in names {
                let key_use = read_keystore(&store.join(&name))?.use_label();
                lines.push(format!("keystore {name} {key_use}"));
            }
        }
        Err(MenuErr::NoKeystores) => lines.push("no keystores".to_string()),
        Err(e) => return Err(e),
    }
    for enrollment in &keyring.enrollments {
        match &enrollment.params {
            EnrollParams::SecureEnclave { se_pub, .. } => lines.push(format!(
                "enrollment {} secure_enclave \"{}\" se_key {}",
                enrollment.id,
                enrollment.label,
                se_fingerprint(se_pub)
            )),
            EnrollParams::Passphrase { .. } => lines.push(format!(
                "enrollment {} passphrase \"{}\"",
                enrollment.id, enrollment.label
            )),
        }
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

    /// Every screen the menu can be on, so one added later is considered by the gate test.
    const EVERY_STATE: [MenuState; 10] = [
        MenuState::Root,
        MenuState::Keys,
        MenuState::Bundles,
        MenuState::BundlePeers,
        MenuState::Exposure,
        MenuState::Backup,
        MenuState::Enroll,
        MenuState::Status,
        MenuState::ServeAndApprove,
        MenuState::Quit,
    ];

    #[test]
    fn secret_decoding_is_bounded_before_unlock() {
        assert!(matches!(
            decode_secret(SecretKind::Bytes, &"x".repeat(MAX_SECRET_BYTES + 1)),
            Err(MenuErr::Envelope(EnvErr::PlaintextTooLarge { .. }))
        ));
        assert!(matches!(
            decode_secret(
                SecretKind::Solana,
                &"1".repeat(MAX_ENCODED_SECRET_BYTES + 1)
            ),
            Err(MenuErr::SecretInputTooLarge { .. })
        ));
    }

    /// The second confirmation is the operator's last chance to notice they are being rolled back,
    /// so each ground has to say what is actually happening. A hostile child that reverts blob
    /// contents deletes nothing and discards no commit, and sharing the `Backwards` arm made the
    /// question claim both — "discards 0 local commit(s)" over the one danger that was real.
    #[test]
    fn each_rollback_ground_names_the_loss_it_is() {
        let changed = vec!["TREASURY".to_string(), "keyring.json".to_string()];
        let removed = vec!["OPS".to_string()];
        let backwards = rewind_prompt(git_store::Rewind::Backwards, 3, &changed, &[]);
        let fork = rewind_prompt(git_store::Rewind::Fork, 3, &changed, &[]);
        let deletes = rewind_prompt(git_store::Rewind::Deletes, 0, &changed, &removed);
        let contents = rewind_prompt(git_store::Rewind::Contents, 0, &changed, &[]);

        assert!(backwards.contains("discards 3 local commit(s)"));
        assert!(fork.contains("does not contain 3 commit(s)"));
        assert!(deletes.contains("DELETES 1 store file(s)") && deletes.contains("OPS"));
        assert!(contents.contains("REPLACES 2 security-relevant file(s) with older content"));
        assert!(contents.contains("TREASURY, keyring.json"));
        assert!(contents.contains("revive a retired keystore"));
        assert!(
            !contents.contains("discards 0 local commit(s)"),
            "the shared variant reported the harmless fact as the danger: {contents}"
        );
        for other in [&backwards, &fork, &deletes] {
            assert_ne!(other, &contents);
        }
    }

    /// The strength rule has to refuse at the prompt, where a re-prompt is free — not after
    /// `dek_for` has already spent a Touch ID on a passphrase the enrollment was always going to
    /// reject.
    #[test]
    fn a_weak_passphrase_is_refused_before_anything_is_unlocked() {
        assert!(matches!(
            check_new_passphrase(&Zeroizing::new("x".repeat(64))),
            Err(UnlockErr::PassphraseTooSimple { .. })
        ));
        assert!(matches!(
            check_new_passphrase(&Zeroizing::new("too short".to_string())),
            Err(UnlockErr::PassphraseTooShort { .. })
        ));
        check_new_passphrase(&Zeroizing::new("correct horse battery staple".to_string()))
            .expect("what the enrollment accepts must pass the prompt");
    }

    /// A session that cannot serve must not reach the two screens that publish this machine or
    /// read a key off-process: a passphrase session has no per-request biometric to gate a
    /// release with, so an `ssh -R` from it would expose a key API nothing can guard. Getting
    /// the set wrong is invisible until it matters, and no test reached this guard before.
    #[test]
    fn a_refused_session_may_not_reach_the_screens_that_expose_keys() {
        let (_tx, ops) = tokio::sync::mpsc::channel(1);
        let (shutdown, _rx) = tokio::sync::watch::channel(false);
        let live = Serving::Live {
            addr: "127.0.0.1:1".parse().expect("a loopback address"),
            ops,
            shutdown,
        };
        for state in EVERY_STATE {
            assert!(
                allowed(state, &live),
                "{state:?} must be reachable while serving"
            );
            assert_eq!(
                allowed(state, &Serving::Refused),
                !matches!(state, MenuState::Exposure | MenuState::ServeAndApprove),
                "{state:?} is gated wrongly for a refused session"
            );
        }
    }

    /// Every section is reachable from the root, re-picking a section stays put so the
    /// drain runs between screens, Back climbs exactly one level, and both Quit anywhere
    /// and Back at the root terminate the loop.
    #[test]
    fn transitions_enter_and_leave_submenus() {
        for (choice, state) in [
            (MenuChoice::Keys, MenuState::Keys),
            (MenuChoice::Bundles, MenuState::Bundles),
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

    /// The peers screen is the one screen that sits under another, so Back there must climb to
    /// the bundle list and not to the root: an operator who enrolled a peer is put back where
    /// the bundles are. Entering it from anywhere still lands on it, re-picking either screen
    /// stays put so the drain runs between them, and Quit leaves from inside both.
    #[test]
    fn transitions_nest_the_peers_screen_under_the_bundle_list() {
        assert_eq!(
            next(MenuState::Bundles, MenuChoice::BundlePeers),
            MenuState::BundlePeers
        );
        assert_eq!(
            next(MenuState::Root, MenuChoice::BundlePeers),
            MenuState::BundlePeers
        );
        assert_eq!(
            next(MenuState::BundlePeers, MenuChoice::BundlePeers),
            MenuState::BundlePeers
        );
        assert_eq!(
            next(MenuState::BundlePeers, MenuChoice::Back),
            MenuState::Bundles
        );
        assert_eq!(
            next(MenuState::BundlePeers, MenuChoice::Bundles),
            MenuState::Bundles
        );
        for state in [MenuState::Bundles, MenuState::BundlePeers] {
            assert_eq!(next(state, MenuChoice::Quit), MenuState::Quit);
        }
    }
}
