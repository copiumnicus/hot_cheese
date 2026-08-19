//! Command-line interface (clap).
//!
//! Replaces the old `cargo run --example ...` + manual Keychain Access workflow with
//! first-class subcommands: init, enroll, add, generate, address, list, serve,
//! backup, migrate, bootstrap-from, bootstrap-serve.
//!
//! The DEK is never cached: every command that needs it builds an [`Unlocker`]
//! (Secure Enclave in production, recovery passphrase as the survivable backstop)
//! and unwraps the DEK for that single operation.
//!
//! The interactive console is the `console` feature, on by default; `--no-default-features`
//! builds the same binary without it (and so without inquire/crossterm), subcommands only.
mod bootstrap;
mod bundle;
mod migrate;

use clap::builder::TypedValueParser;
use clap::{Parser, Subcommand};
use err_mac::create_err_with_impls;
use hc_core::config::{
    adapter_socket, adapters_dir, cert_paths, config_path, env_log_level, home_dir, BackupRemote,
    Config,
};
use hc_core::crypto::envelope::{
    atomic_write, encrypt_file_new, enforce_store_modes, parse_keystore, read_keystore,
    seal_keystore, write_private_file, Dek, EnvErr, KeyUse, KeystoreFile, MAX_SECRET_BYTES,
};
use hc_core::is_valid_key_name;
use hc_core::keyring::{EnrollParams, Enrollment, Keyring, VaultId};
use hc_core::mac::secure_enclave;
use hc_core::mac::{authorize_with_touch_id, get_password_from_keychain, BackendImpl, MacBackend};
use hc_core::unlock::{PassphraseUnlocker, SecureEnclaveUnlocker, UnlockErr, Unlocker};
use hc_daemon::approval::Approver;
use hc_daemon::git_store::{self, GitStore};
use hc_daemon::renderer::Headless;
use hc_daemon::runtime::UnlockGate;
use hc_daemon::{flock, HotApi, OpContext, Operation};
use std::io::IsTerminal;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// What [`CliErr::Console`] carries in a build without the console: only its absence.
#[cfg(not(feature = "console"))]
#[derive(Debug)]
pub struct ConsoleNotBuilt;

#[cfg(feature = "console")]
type ConsoleErr = hc_console::ConsoleErr;
#[cfg(not(feature = "console"))]
type ConsoleErr = ConsoleNotBuilt;

/// Shared Secure Enclave key label. Every machine stores its device-bound SE key
/// under this label, so the SE unlocker always knows where to look.
const SE_LABEL: &str = hc_core::mac::secure_enclave::SE_KEY_LABEL;

/// Shared Secure Enclave grant-key label: the signing key whose public half `config.toml` pins.
const GRANT_LABEL: &str = hc_core::mac::secure_enclave::SE_GRANT_KEY_LABEL;

// Defaults baked into a fresh `config.toml` on `init`.
const DEFAULT_SERVICE: &str = "com.cc.hot_cheese";
const DEFAULT_ACCOUNT: &str = "hot_cheese_master";
const MAX_PEM_BYTES: u64 = 1024 * 1024;

// Variants in source order: AlreadyInitialized (`init` without `--force`), CertKeyPairRequired (one of
// --import-cert/--import-key supplied), PullNeedsForce (`backup pull` without --force, after
// naming everything the pull would destroy), ServeRefusesPassphraseUnlock (`serve --unlock
// passphrase` would cache the passphrase for the daemon's lifetime and drop the per-request
// biometric), SealNeedsTarget (`seal` with neither a name nor --all), then `#[from]` wrappers
// for each module error this CLI touches, then ExistingStore (`init` found key material),
// NotInitialized (no config.toml, so there is nothing for the console to open),
// SealCannotLoosen (sealing is one-way), SealVerifyMismatch (the re-sealed file did not re-open
// to the same bytes; nothing written) and GrantKeyPinMismatch (`serve` found a grant key that
// is not the one config.toml pins).
// GrantKeyMissingRunEnrollGrant is `serve` without an enrolled grant key, which every
// signature needs: nothing is pinned in config.toml, or the enclave blob is gone.
// ConfirmationNeedsTerminal is an irreversible verb (`init --force`, a rewinding `backup pull`,
// `accept-deletions`) with no terminal to type its phrase on, ConfirmationRefused is the same
// guard when what came back was not the phrase, and NoDeletionsToAccept is `accept-deletions`
// on a store that has lost nothing.
create_err_with_impls!(
    #[derive(Debug)]
    pub CliErr,
    AlreadyInitialized,
    CertKeyPairRequired,
    PullNeedsForce,
    ServeRefusesPassphraseUnlock,
    SealNeedsTarget,
    TouchIdDenied,
    GrantKeyMissingRunEnrollGrant,
    StoreMissingRunBackupPull,
    Config(hc_core::config::ConfigErr),
    Keyring(hc_core::keyring::KeyringErr),
    Passphrase(PassphraseErr),
    Unlock(hc_core::unlock::UnlockErr),
    Envelope(hc_core::crypto::envelope::EnvErr),
    ApiBackend(hc_daemon::ApiBackendErr),
    Git(hc_daemon::git_store::GitErr),
    Migrate(migrate::MigrateErr),
    Bootstrap(bootstrap::BootstrapErr),
    Bundle(hc_bundle::BundleErr),
    BundleSync(hc_bundle::sync::SyncErr),
    Render(hc_daemon::qr_term::RenderErr),
    GetPassword(hc_core::mac::GetPasswordErr),
    Se(hc_core::mac::secure_enclave::SeErr),
    Sign(hc_sign::SignErr),
    Grant(hc_sign::grant::GrantErr),
    Serde(serde_json::Error),
    Runtime(hc_daemon::runtime::RuntimeErr),
    Tls(hc_daemon::ServeErr),
    Flock(hc_daemon::flock::FlockErr),
    Console(ConsoleErr),
    Rcgen(rcgen::Error),
    StdIo(std::io::Error)
    ;
    ExistingStore { store: PathBuf, keyring: bool, keystores: usize },
    NotInitialized { config: PathBuf },
    SealCannotLoosen { name: String, from: KeyUse, to: KeyUse },
    SealVerifyMismatch { name: String },
    NotBundleable { kind: hc_sign::grant::IntentKind },
    SecretInputTooLarge { size: usize, max: usize },
    GrantKeyPinMismatch { pinned: String, found: String },
    ConfirmationNeedsTerminal { required: &'static str, flag: &'static str },
    ConfirmationRefused { typed: String, required: &'static str },
    NoDeletionsToAccept { store: PathBuf }
);

// Mismatch is the confirmation entry differing from the first, Empty a passphrase read from an
// empty stdin, Unlock the enrollment rule refusing the entry at the prompt. No variant ever
// carries the entered secret.
create_err_with_impls!(
    #[derive(Debug)]
    pub PassphraseErr,
    Mismatch,
    Empty,
    Unlock(UnlockErr),
    Utf8(std::str::Utf8Error),
    StdIo(std::io::Error)
    ;
);

/// Hex is the widest supported textual encoding; this also bounds base58 decoding work.
const MAX_ENCODED_SECRET_BYTES: usize = MAX_SECRET_BYTES * 2 + 2;

#[derive(Parser, Debug)]
#[command(
    name = "hot_cheese",
    about = "macOS key daemon: envelope-encrypted EVM/Solana keystores unlocked per request via Secure Enclave (Touch ID) or a recovery passphrase.",
    version
)]
struct Cli {
    /// Omit every subcommand to open the interactive console.
    #[command(subcommand)]
    command: Option<Commands>,
    /// Which enrolled KEK unwraps the DEK; defaults to the Secure Enclave when one is enrolled.
    #[arg(long, global = true, value_name = "METHOD")]
    unlock: Option<UnlockMethod>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize the home dir + store, generate (or import) the TLS cert, mint the
    /// DEK, and require a recovery passphrase. Prints the cert fingerprint for pinning.
    Init {
        /// Import this PEM cert instead of generating a self-signed one (requires --import-key).
        #[arg(long, value_name = "PEM")]
        import_cert: Option<PathBuf>,
        /// Import this PEM private key (requires --import-cert).
        #[arg(long, value_name = "PEM")]
        import_key: Option<PathBuf>,
        /// Overwrite an existing config/store.
        #[arg(long)]
        force: bool,
        /// Confirm a forced overwrite without a terminal, by repeating the phrase it asks for.
        #[arg(long, value_name = "PHRASE", requires = "force")]
        confirm_destroy: Option<String>,
    },
    /// Add another way to unlock the same DEK (Secure Enclave or recovery passphrase).
    #[command(subcommand)]
    Enroll(EnrollCmd),
    /// Import an existing secret key under `name`.
    Add {
        /// Keystore name (a-z, A-Z, 0-9, _).
        name: String,
        /// How to decode the secret read from the prompt.
        kind: SecretKind,
        /// Whether the key may ever leave the daemon. sign-only is permanent.
        #[arg(long = "use", value_name = "USE", default_value = "sign-only", value_parser = key_use_parser())]
        key_use: KeyUse,
    },
    /// Generate a fresh key under `name`.
    Generate {
        /// Chain the key is for.
        chain: Chain,
        /// Keystore name (a-z, A-Z, 0-9, _).
        name: String,
        /// Whether the key may ever leave the daemon. sign-only is permanent.
        #[arg(long = "use", value_name = "USE", default_value = "sign-only", value_parser = key_use_parser())]
        key_use: KeyUse,
    },
    /// Print the public address of a stored key.
    Address {
        /// Chain to derive the address for.
        chain: Chain,
        /// Keystore name.
        name: String,
    },
    /// Collect owner signatures for one Safe transaction across several devices.
    Bundle {
        #[command(subcommand)]
        cmd: bundle::BundleCmd,
        /// Do not exchange anything with the enrolled tailnet peers for this command.
        #[arg(long, global = true)]
        no_sync: bool,
    },
    /// List stored keystores and keyring enrollments.
    List,
    /// Show every trusted signing adapter, its pin, its socket and its policy verdict.
    Adapters,
    /// Bind an existing keystore to a use it can never be loosened from.
    Seal {
        /// Keystore to seal; omit it and pass --all to seal the whole store.
        name: Option<String>,
        /// Seal every keystore in the store.
        #[arg(long, conflicts_with = "name")]
        all: bool,
        /// Use to seal under. sign-only is a one-way door: it can never be loosened.
        #[arg(long = "use", value_name = "USE", default_value = "sign-only", value_parser = key_use_parser())]
        key_use: KeyUse,
    },
    /// Run the HTTPS daemon. A missing store must be restored explicitly first.
    Serve,
    /// Push or pull the encrypted store to/from configured backup remotes.
    #[command(subcommand)]
    Backup(BackupCmd),
    /// Record store files or enrollments that are already gone, which every other command
    /// refuses to commit. Names each one, then requires the phrase it asks for.
    AcceptDeletions {
        /// Confirm without a terminal, by repeating the phrase it asks for.
        #[arg(long, value_name = "PHRASE")]
        confirm_deletion: Option<String>,
    },
    /// Migrate legacy Keychain-master keystores into the new envelope format.
    Migrate {
        /// Directory holding the legacy keystores.
        #[arg(long, value_name = "DIR")]
        old_store: PathBuf,
        /// This initialized installation's configured store (normally ~/.config/hot_cheese/store).
        #[arg(long, value_name = "DIR")]
        new_store: PathBuf,
        /// Migrate this key as shareable (repeatable). Everything unnamed becomes sign-only
        /// permanently, so name every key your services fetch over /read.
        #[arg(long, value_name = "NAME")]
        shareable: Vec<String>,
    },
    /// Bootstrap this machine's DEK + store from an authority machine over SSH.
    BootstrapFrom {
        /// SSH target, e.g. user@host.
        target: String,
        /// Also enroll a recovery passphrase here, read from a masked prompt or, with no
        /// terminal, from stdin.
        #[arg(long)]
        recovery_passphrase: bool,
    },
    /// Authority side of the SSH bootstrap (invoked remotely over SSH).
    #[command(hide = true)]
    BootstrapServe,
    /// Validate the Secure Enclave path on real SE hardware (prompts Touch ID).
    #[command(hide = true)]
    SeSelftest,
}

#[derive(Subcommand, Debug)]
enum EnrollCmd {
    /// Enroll this machine's Secure Enclave key (Touch ID).
    Se {
        /// Human-readable label for the enrollment record.
        #[arg(long, default_value = "secure-enclave")]
        label: String,
    },
    /// Enroll an additional recovery passphrase.
    Passphrase {
        /// Human-readable label for the enrollment record.
        #[arg(long, default_value = "recovery")]
        label: String,
    },
    /// Create this machine's Secure Enclave grant-signing key and pin it in `config.toml`.
    Grant,
}

#[derive(Subcommand, Debug)]
enum BackupCmd {
    /// Print what this install knows about its store and its remotes. No network, no write.
    Status,
    /// Push the store to every configured remote, under this install's vault id.
    Push,
    /// Fetch and inspect configured remotes without changing the active store.
    Fetch,
    /// Discard local history for the first remote's copy. Names what it destroys, and does
    /// nothing without --force.
    Pull {
        /// Vault to pull (`v_<hex>`); defaults to this install's own vault id.
        #[arg(long, value_name = "ID")]
        vault: Option<VaultId>,
        /// Actually discard local history. Without it the destruction is only listed.
        #[arg(long)]
        force: bool,
        /// Accept a pull that rewinds, forks, deletes store files or replaces them with older
        /// content, by repeating the phrase it asks for.
        #[arg(long, value_name = "PHRASE", requires = "force")]
        confirm_rewind: Option<String>,
    },
    /// List the vaults sharing the first configured remote's folder.
    List,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum SecretKind {
    /// Hex private key (with or without a 0x prefix).
    Ethereum,
    /// base58-encoded keypair bytes.
    Solana,
    /// Raw UTF-8 bytes.
    Bytes,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Chain {
    Evm,
    Solana,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum UnlockMethod {
    /// This machine's Secure Enclave key (Touch ID per request).
    Se,
    /// A recovery passphrase — the escape hatch when the Secure Enclave key is gone.
    Passphrase,
}

/// `--use` accepts exactly the two spellings, and only those, so `KeyUse` itself stays
/// free of clap and the key core never links a CLI parser.
fn key_use_parser() -> impl TypedValueParser<Value = KeyUse> {
    fn chosen(value: String) -> KeyUse {
        match value.as_str() {
            "shareable" => KeyUse::Shareable,
            _ => KeyUse::SignOnly,
        }
    }
    clap::builder::PossibleValuesParser::new(["shareable", "sign-only"]).map(chosen)
}

/// Parse args and dispatch; returns a process exit code.
pub fn run() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap already formats help/usage/version nicely; let it print and pick the code.
            return if e.exit_code() == 0 {
                e.print().ok();
                ExitCode::SUCCESS
            } else {
                e.print().ok();
                ExitCode::FAILURE
            };
        }
    };

    // The console redirects tracing into its own ring buffer + log file, so the stdout
    // subscriber must never be installed underneath it.
    let result = match cli.command {
        Some(command) => {
            if command_owns_stdout(&command) {
                init_stderr_tracing();
            } else {
                init_stdout_tracing();
            }
            dispatch(command, cli.unlock)
        }
        None => cmd_console(cli.unlock),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            init_stdout_tracing();
            tracing::error!(error = %e, "command failed");
            ExitCode::FAILURE
        }
    }
}

/// Log to stdout unless a subscriber (the console's) already owns the global default.
fn init_stdout_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(env_log_level())
        .try_init();
}

/// Hidden machine protocols must keep stdout byte-exact. In particular, a tracing line inserted
/// between bootstrap frames is indistinguishable from a hostile length prefix to the peer.
fn command_owns_stdout(command: &Commands) -> bool {
    matches!(command, Commands::BootstrapServe)
}

fn init_stderr_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(env_log_level())
        .with_writer(std::io::stderr)
        .try_init();
}

fn dispatch(command: Commands, unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    match command {
        Commands::Init {
            import_cert,
            import_key,
            force,
            confirm_destroy,
        } => cmd_init(import_cert, import_key, force, confirm_destroy),
        Commands::Enroll(cmd) => cmd_enroll(cmd, unlock),
        Commands::Add {
            name,
            kind,
            key_use,
        } => cmd_add(&name, kind, key_use, unlock),
        Commands::Generate {
            chain,
            name,
            key_use,
        } => cmd_generate(chain, &name, key_use, unlock),
        Commands::Address { chain, name } => cmd_address(chain, &name, unlock),
        Commands::Bundle { cmd, no_sync } => bundle::run(cmd, no_sync, unlock),
        Commands::List => cmd_list(),
        Commands::Adapters => cmd_adapters(),
        Commands::Seal { name, all, key_use } => cmd_seal(name, all, key_use, unlock),
        Commands::Serve => cmd_serve(unlock),
        Commands::Backup(cmd) => cmd_backup(cmd),
        Commands::AcceptDeletions { confirm_deletion } => cmd_accept_deletions(confirm_deletion),
        Commands::Migrate {
            old_store,
            new_store,
            shareable,
        } => cmd_migrate(&old_store, &new_store, shareable, unlock),
        Commands::BootstrapFrom {
            target,
            recovery_passphrase,
        } => {
            let _store = flock::store_claim()?;
            Ok(bootstrap::bootstrap_from(&target, recovery_passphrase)?)
        }
        Commands::BootstrapServe => {
            let _store = flock::store_claim()?;
            Ok(bootstrap::bootstrap_serve()?)
        }
        Commands::SeSelftest => cmd_se_selftest(),
    }
}

/// Open the interactive console. A passphrase session may manage keys locally but may never
/// expose them: without a live per-request biometric there is nothing to gate a release, so
/// the console starts no listener and refuses every tunnel.
#[cfg(feature = "console")]
fn cmd_console(unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    if !config_path().exists() {
        return Err(CliErr::NotInitialized {
            config: config_path(),
        });
    }
    let store = flock::store_claim()?;
    let config = Config::load()?;
    let (backend, gate) = backend_for(&config, unlock)?;
    Ok(hc_console::run(config, Box::new(backend), gate, store)?)
}

/// Without the console feature there is no interactive session to open, so a bare
/// `hot_cheese` fails closed and the operator uses a subcommand.
#[cfg(not(feature = "console"))]
fn cmd_console(_unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    Err(CliErr::Console(ConsoleNotBuilt))
}

/// Validate the Secure Enclave path end-to-end on real SE hardware (prompts Touch ID).
/// Uses a throwaway key label so the real unlock key is never touched.
fn cmd_se_selftest() -> Result<(), CliErr> {
    const SELFTEST_LABEL: &str = "hotcheese.se.selftest";
    secure_enclave::selftest(SELFTEST_LABEL)?;
    tracing::info!(
        "Secure Enclave self-test PASSED — Touch ID gating, ECDH determinism, SE/host ECDH \
         equivalence, and one biometric covering both an enclave ECDH and a verifying enclave \
         grant signature all hold; the SE unlock path is ready (`hot_cheese enroll se`)."
    );
    Ok(())
}

/// Build the [`Unlocker`] the operator asked for with `--unlock`. Unspecified keeps the
/// default: the Secure Enclave key when any SE enrollment exists, else a passphrase prompt.
/// `--unlock passphrase` is the escape hatch when this machine's SE key is lost or
/// invalidated — the same DEK is still wrapped under the recovery enrollment.
fn make_unlocker(
    keyring: &Keyring,
    method: Option<UnlockMethod>,
) -> Result<Box<dyn Unlocker>, CliErr> {
    match resolve_unlock_method(keyring, method) {
        UnlockMethod::Se => Ok(Box::new(SecureEnclaveUnlocker::new(SE_LABEL))),
        UnlockMethod::Passphrase => {
            let pass = prompt_passphrase("Recovery passphrase: ")?;
            Ok(Box::new(PassphraseUnlocker::from_secret(pass)))
        }
    }
}

/// The KEK an unspecified `--unlock` lands on: the Secure Enclave whenever one is enrolled.
fn resolve_unlock_method(keyring: &Keyring, method: Option<UnlockMethod>) -> UnlockMethod {
    if let Some(m) = method {
        return m;
    }
    let has_se = keyring
        .enrollments
        .iter()
        .any(|e| matches!(e.params, EnrollParams::SecureEnclave { .. }));
    if has_se {
        UnlockMethod::Se
    } else {
        UnlockMethod::Passphrase
    }
}

/// Prompt once for a passphrase.
fn prompt_passphrase(prompt: &str) -> Result<Zeroizing<String>, PassphraseErr> {
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

/// The rule an enrollment applies, run here against a throwaway DEK so the prompt and the
/// enrollment can never disagree about what a new recovery passphrase is.
pub(crate) fn check_new_passphrase(entered: &Zeroizing<String>) -> Result<(), UnlockErr> {
    PassphraseUnlocker::from_secret(entered.clone()).enroll("preflight", &Dek::random())?;
    Ok(())
}

/// Prompt twice, confirm the two entries match, and refuse here what the enrollment would refuse
/// later — before any caller writes a file, opens an SSH pipe or spends a Touch ID. A terminal
/// asks again; anything else takes the refusal as the command's answer.
pub(crate) fn prompt_new_passphrase() -> Result<Zeroizing<String>, PassphraseErr> {
    loop {
        let first = prompt_passphrase("New passphrase: ")?;
        if first.is_empty() {
            return Err(PassphraseErr::Empty);
        }
        if let Err(error) = check_new_passphrase(&first) {
            if !std::io::stdin().is_terminal() {
                return Err(error.into());
            }
            tracing::warn!(%error, "passphrase refused; enter a different one");
            continue;
        }
        let second = prompt_passphrase("Confirm passphrase: ")?;
        if bool::from(first.as_bytes().ct_eq(second.as_bytes())) {
            return Ok(first);
        }
        if !std::io::stdin().is_terminal() {
            return Err(PassphraseErr::Mismatch);
        }
        tracing::warn!("the two entries differ; enter the new passphrase again");
    }
}

/// Load `config.toml`, then load `<store>/keyring.json`.
fn load_config_and_keyring() -> Result<(Config, Keyring), CliErr> {
    let config = Config::load()?;
    let keyring = Keyring::load(&keyring_file(&config))?;
    Ok((config, keyring))
}

/// `<store>/keyring.json`.
fn keyring_file(config: &Config) -> PathBuf {
    config.store_path().join("keyring.json")
}

/// Existence check for overwrite guards. Unlike `Path::exists`, a dangling symlink is occupied,
/// and metadata errors other than absence are not silently reclassified as a free pathname.
fn path_is_occupied(path: &Path) -> Result<bool, std::io::Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Load the keyring once, resolve which KEK this invocation runs under, build the unlocker and
/// open the Mac backend. The gate travels with the backend because everything that raises an
/// approval prompt needs to know whether a per-request biometric exists to reuse.
fn backend_for(
    config: &Config,
    method: Option<UnlockMethod>,
) -> Result<(MacBackend, UnlockGate), CliErr> {
    let keyring = Keyring::load(&keyring_file(config))?;
    let gate = match resolve_unlock_method(&keyring, method) {
        UnlockMethod::Se => UnlockGate::Biometric,
        UnlockMethod::Passphrase => UnlockGate::Passphrase,
    };
    let unlocker = make_unlocker(&keyring, method)?;
    Ok((MacBackend::new(&config.store, unlocker)?, gate))
}

/// Everything an `init` guard has to weigh before a fresh DEK replaces the old one.
struct StoreContents {
    /// Keystore names the new DEK would leave permanently undecryptable.
    keystores: Vec<String>,
    /// Enrollments the new keyring would discard.
    enrollments: Vec<Enrollment>,
    /// Whether `keyring.json` occupies the store at all, readable or not.
    keyring: bool,
    /// Every directory entry in the store, keystore or not.
    entries: usize,
}

impl StoreContents {
    fn read(store: &Path) -> Result<Self, CliErr> {
        let mut keystores = Vec::new();
        let mut entries = 0usize;
        match std::fs::read_dir(store) {
            Ok(dir) => {
                for (at, entry) in dir.enumerate() {
                    if at >= hc_core::MAX_STORE_ENUM_ENTRIES {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "pre-existing store has too many entries",
                        )
                        .into());
                    }
                    let entry = entry?;
                    entries += 1;
                    if !entry.file_type()?.is_file() {
                        continue;
                    }
                    if let Some(name) = entry.file_name().to_str() {
                        if is_valid_key_name(name) {
                            keystores.push(name.to_string());
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        keystores.sort();

        let keyring_path = store.join(hc_core::keyring::KEYRING_FILE);
        let keyring = path_is_occupied(&keyring_path)?;
        let mut enrollments = Vec::new();
        if keyring {
            match Keyring::load(&keyring_path) {
                Ok(loaded) => enrollments = loaded.enrollments,
                Err(error) => {
                    tracing::warn!(%error, "the keyring is unreadable; it will be replaced unlisted")
                }
            }
        }
        Ok(Self {
            keystores,
            enrollments,
            keyring,
            entries,
        })
    }

    fn is_empty(&self) -> bool {
        !self.keyring && self.entries == 0
    }
}

const FORCED_INIT_PHRASE: &str = git_store::Destruction::Replacement.phrase();
const FORCED_INIT_FLAG: &str = "--confirm-destroy";
const PULL_REWIND_PHRASE: &str = "roll this store back";
const PULL_REWIND_FLAG: &str = "--confirm-rewind";
const ACCEPT_DELETION_PHRASE: &str = git_store::Destruction::Deletion.phrase();
const ACCEPT_DELETION_FLAG: &str = "--confirm-deletion";

/// The one way an irreversible verb takes consent: the exact phrase, typed on a terminal, or
/// carried by `flag` where there is no terminal to type it on. Anything else refuses, so a
/// habitual `-y` and an unattended run both fail closed. The accepted bytes come back, because a
/// capability that a confirmed destruction mints must be minted from them and not from a constant.
fn require_typed_confirmation(
    required: &'static str,
    flag: &'static str,
    confirm: Option<&str>,
) -> Result<String, CliErr> {
    let typed = match confirm {
        Some(phrase) => phrase.to_string(),
        None => {
            if !std::io::stdin().is_terminal() {
                return Err(CliErr::ConfirmationNeedsTerminal { required, flag });
            }
            tracing::warn!(phrase = %required, "type this phrase to proceed, or Ctrl-C to abort");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line
        }
    };
    if typed.trim() != required {
        return Err(CliErr::ConfirmationRefused {
            typed: hc_core::safe_diagnostic_text(typed.trim()),
            required,
        });
    }
    Ok(typed)
}

/// `--force` mints a new DEK, so every keystore wrapped under the old one becomes permanently
/// undecryptable. Name each casualty first, then require the phrase back before any of it happens.
///
/// The phrase is what mints the capability the replacing commit is recorded under; a store with
/// nothing to destroy has no replacement to confirm and gets none.
fn confirm_forced_init(
    store: &Path,
    existing: &StoreContents,
    confirm: Option<&str>,
) -> Result<Option<git_store::Consent>, CliErr> {
    if existing.is_empty() {
        return Ok(None);
    }
    tracing::warn!(
        store = %store.display(),
        keystores = existing.keystores.len(),
        enrollments = existing.enrollments.len(),
        entries = existing.entries,
        "`init --force` mints a NEW DEK; everything below stays encrypted under the OLD one and becomes permanently undecryptable"
    );
    for name in &existing.keystores {
        tracing::warn!(key = %name, "  keystore orphaned by the new DEK");
    }
    for enrollment in &existing.enrollments {
        tracing::warn!(id = %enrollment.id, label = %enrollment.label, "  enrollment discarded with the old keyring");
    }
    let typed = require_typed_confirmation(FORCED_INIT_PHRASE, FORCED_INIT_FLAG, confirm)?;
    Ok(Some(git_store::Consent::confirmed(
        git_store::Destruction::Replacement,
        &typed,
    )?))
}

/// Record store state that is already gone. A routine mutation refuses to, because the backup
/// exists to survive exactly that loss and a deletion replicates as a clean fast-forward — but
/// the refusal is permanent and `open` is a commit, so without this the first store file to
/// vanish takes `serve`, `generate` and the forced-pull recovery down with it for good.
///
/// Runs without [`claimed_store`]: opening the store is the operation that is already failing.
fn cmd_accept_deletions(confirm: Option<String>) -> Result<(), CliErr> {
    let config = Arc::new(Config::load()?);
    let git = GitStore::cli(config.clone(), flock::store_claim()?)?;
    let missing = git.missing()?;
    if missing.is_empty() {
        return Err(CliErr::NoDeletionsToAccept {
            store: config.store_path(),
        });
    }
    tracing::warn!(
        store = %config.store_path().display(),
        files = missing.paths.len(),
        enrollments = missing.ids.len(),
        "these are ALREADY GONE from this store; recording their loss replicates it to every backup, and a backup cannot restore what it no longer holds"
    );
    for path in &missing.paths {
        tracing::warn!(file = %path, "  GONE: a store file the last commit still has");
    }
    for id in &missing.ids {
        tracing::warn!(enrollment = %id, "  GONE: an unlock path the committed keyring still wraps");
    }
    let typed = require_typed_confirmation(
        ACCEPT_DELETION_PHRASE,
        ACCEPT_DELETION_FLAG,
        confirm.as_deref(),
    )?;
    git.mutation().commit_loss(
        git_store::Consent::confirmed(git_store::Destruction::Deletion, &typed)?,
        &missing,
    )?;
    tracing::info!(
        files = missing.paths.len(),
        enrollments = missing.ids.len(),
        "recorded the loss; the store commits again"
    );
    Ok(())
}

fn cmd_init(
    import_cert: Option<PathBuf>,
    import_key: Option<PathBuf>,
    force: bool,
    confirm_destroy: Option<String>,
) -> Result<(), CliErr> {
    // Home dir holds config.toml + the TLS cert/key; the store lives under it so
    // $HOT_CHEESE_HOME fully isolates an install (the demo's /tmp home stays self-contained).
    let home = home_dir();
    let store = home.join("store");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&home)?;
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
    // First-run initialization mutates the same store and home material as every later command.
    // Take the claim before inspecting either so two initializers cannot both mint a DEK and
    // race to replace one another's keyring/config.
    let _store = flock::store_claim()?;

    // A fresh DEK orphans every keystore already wrapped under the old one, so refuse when
    // ANY prior install is visible — config.toml, a keyring, or keystore files.
    let existing = StoreContents::read(&store)?;
    let consent = if force {
        confirm_forced_init(&store, &existing, confirm_destroy.as_deref())?
    } else {
        let (existing_cert, existing_key) = cert_paths();
        if path_is_occupied(&config_path())?
            || path_is_occupied(&existing_cert)?
            || path_is_occupied(&existing_key)?
        {
            return Err(CliErr::AlreadyInitialized);
        }
        if !existing.is_empty() {
            return Err(CliErr::ExistingStore {
                keyring: existing.keyring,
                keystores: existing.keystores.len(),
                store,
            });
        }
        None
    };

    let config = Config {
        service: DEFAULT_SERVICE.to_string(),
        account: DEFAULT_ACCOUNT.to_string(),
        store: store.to_string_lossy().into_owned(),
        port: None,
        grant_public_key: None,
        bundle_watch_secs: None,
        backup_fetch_secs: None,
        mcp: None,
        backup_remotes: Vec::new(),
        adapters: Vec::new(),
        bundle_peers: Vec::new(),
        token: Vec::new(),
        label: Vec::new(),
    };
    config.validate()?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&store)?;
    enforce_store_modes(&store)?;

    // TLS cert: import the supplied pair, or mint a self-signed localhost cert.
    let tls = match (import_cert, import_key) {
        (Some(c), Some(k)) => {
            let cert_pem = hc_core::read_regular_file_bounded(&c, MAX_PEM_BYTES)?;
            let key_pem = Zeroizing::new(hc_core::read_regular_file_bounded(&k, MAX_PEM_BYTES)?);
            let cert_der = hc_daemon::validate_tls_pair(&cert_pem, &key_pem)?;
            TlsMaterial {
                cert_pem,
                key_pem,
                cert_der,
            }
        }
        (None, None) => generate_localhost_cert()?,
        // Importing requires both halves.
        _ => return Err(CliErr::CertKeyPairRequired),
    };

    // Mint the DEK and require a recovery passphrase as the first (and survivable) enrollment.
    let dek = Dek::random();
    tracing::info!("A recovery passphrase is required: it is the only cross-machine restore path.");
    let pass = prompt_new_passphrase()?;
    let enrollment = PassphraseUnlocker::from_secret(pass).enroll("recovery", &dek)?;

    // The cert is public; the private key is written 0600 on both paths (std::fs::copy would
    // carry the source's mode over instead).
    let (cert_path, key_path) = cert_paths();
    atomic_write(&cert_path, &tls.cert_pem)?;
    write_private_file(&key_path, &tls.key_pem)?;

    let mut keyring = Keyring::new();
    // A fresh DEK is a fresh vault: it gets its own remote subtree so this install can share
    // a backup folder with other installs instead of overwriting one of them.
    let vault = VaultId::random();
    keyring.vault_id = Some(vault.clone());
    keyring.add(enrollment);
    keyring.save(&keyring_file(&config))?;

    // Persist config last, once the store + keyring are in place.
    config.save()?;

    git_store::ensure_repo(&store, consent)?;

    let fingerprint = sha256_hex(&tls.cert_der);
    tracing::info!(home = %home.display(), store = %store.display(), %vault, "initialized hot_cheese");
    tracing::info!(cert = %cert_path.display(), "TLS certificate written");
    tracing::info!(sha256 = %fingerprint, "certificate fingerprint (pin this on the client)");
    Ok(())
}

/// What an enrollment did to the set of Secure Enclave keys `keyring.json` records.
enum EnclaveKeyChange {
    /// A key this store had never recorded, so the set of keys it trusts grew by one.
    Minted { se_key: String },
    /// The key already at this machine's enclave key path, and already recorded here.
    Adopted { se_key: String },
    /// A passphrase enrollment, which records no enclave key at all.
    Untouched,
}

fn cmd_enroll(cmd: EnrollCmd, unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    let config = Arc::new(Config::load()?);
    let git = claimed_store(&config)?;
    let mut keyring = Keyring::load(&keyring_file(&config))?;

    let enrollment = match cmd {
        EnrollCmd::Se { label } => {
            let dek = enroll_dek(&keyring, unlock)?;
            if let Err(e) = secure_enclave::ensure_se_key(SE_LABEL) {
                tracing::warn!(
                    "Could not create this machine's Secure Enclave key. Confirm the Mac has a \
                     Secure Enclave with an enrolled fingerprint and that you are in your GUI \
                     login session with the screen unlocked (Touch ID cannot prompt over \
                     ssh/sudo). Use a recovery passphrase in the meantime."
                );
                return Err(e.into());
            }
            SecureEnclaveUnlocker::new(SE_LABEL).enroll(&label, &dek)?
        }
        EnrollCmd::Passphrase { label } => {
            let pass = prompt_new_passphrase()?;
            let dek = enroll_dek(&keyring, unlock)?;
            PassphraseUnlocker::from_secret(pass).enroll(&label, &dek)?
        }
        EnrollCmd::Grant => {
            secure_enclave::ensure_grant_key(GRANT_LABEL)?;
            let public_key = secure_enclave::grant_public_key(GRANT_LABEL)?;
            let pinned = hex::encode(&public_key);
            let adopted = config.grant_public_key.as_deref() == Some(pinned.as_str());
            Config::update(|pinning| {
                pinning.grant_public_key = Some(pinned.clone());
                Ok::<(), CliErr>(())
            })?;
            let grant_key = se_fingerprint(&public_key);
            if adopted {
                tracing::warn!(%grant_key, "ADOPTED the Secure Enclave grant key already on this disk; stop unless this is the fingerprint you enrolled");
            } else {
                tracing::warn!(%grant_key, "MINTED a new Secure Enclave grant key: the key config.toml pins CHANGED");
            }
            tracing::info!(grant_public_key = %pinned, "pinned the Secure Enclave grant key in config.toml");
            return Ok(());
        }
    };

    let id = enrollment.id.clone();
    let change = match &enrollment.params {
        EnrollParams::SecureEnclave { se_pub, .. } => {
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
            match adopted {
                true => EnclaveKeyChange::Adopted { se_key },
                false => EnclaveKeyChange::Minted { se_key },
            }
        }
        EnrollParams::Passphrase { .. } => EnclaveKeyChange::Untouched,
    };
    keyring.add(enrollment);
    keyring.save(&keyring_file(&config))?;
    tracing::info!(enrollment = %id, "added enrollment");
    match change {
        EnclaveKeyChange::Minted { se_key } => tracing::warn!(
            %se_key,
            "MINTED a new Secure Enclave key: the set of enclave keys this store trusts CHANGED"
        ),
        EnclaveKeyChange::Adopted { se_key } => tracing::warn!(
            %se_key,
            "ADOPTED the Secure Enclave key already on this disk; stop unless this is the fingerprint you enrolled"
        ),
        EnclaveKeyChange::Untouched => {}
    }
    git.after_mutation()?;
    Ok(())
}

/// Unwrap the DEK a new enrollment re-wraps, via whatever enrollment already works.
fn enroll_dek(keyring: &Keyring, unlock: Option<UnlockMethod>) -> Result<Dek, CliErr> {
    let unlocker = make_unlocker(keyring, unlock)?;
    Ok(unlocker.unlock("Enroll a new hot_cheese unlock method", keyring, None)?)
}

fn cmd_add(
    name: &str,
    kind: SecretKind,
    key_use: KeyUse,
    unlock: Option<UnlockMethod>,
) -> Result<(), CliErr> {
    let config = Arc::new(Config::load()?);
    let git = claimed_store(&config)?;
    if !is_valid_key_name(name) {
        tracing::error!(%name, "invalid key name: only a-z, A-Z, 0-9, _ are allowed");
        return Err(CliErr::ApiBackend(hc_daemon::ApiBackendErr::InvalidName));
    }
    let store = config.store_path();
    if path_is_occupied(&store.join(name))? {
        tracing::error!(%name, "key already exists");
        return Err(CliErr::ApiBackend(hc_daemon::ApiBackendErr::KeyExists));
    }

    let secret = read_secret(kind)?;

    let (backend, _) = backend_for(&config, unlock)?;
    let dek = backend.unlock_dek(&format!("Unlock \"{}\" for import key", name), None)?;
    match encrypt_file_new(&backend.store_path(), name, &dek, key_use, &secret) {
        Err(EnvErr::StdIo(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(CliErr::ApiBackend(hc_daemon::ApiBackendErr::KeyExists))
        }
        Err(error) => return Err(error.into()),
        Ok(()) => {}
    }
    tracing::info!(%name, %key_use, "imported key");

    git.after_mutation()?;
    Ok(())
}

fn cmd_generate(
    chain: Chain,
    name: &str,
    key_use: KeyUse,
    unlock: Option<UnlockMethod>,
) -> Result<(), CliErr> {
    let config = Arc::new(Config::load()?);
    let git = claimed_store(&config)?;
    let (backend, _) = backend_for(&config, unlock)?;
    let api = HotApi::new(Box::new(backend), config.clone());
    match chain {
        Chain::Evm => api.generate(
            &OpContext::local(name.to_string(), Operation::EvmGenerate),
            key_use,
        )?,
        Chain::Solana => api.generate_solana(
            &OpContext::local(name.to_string(), Operation::SolanaGenerate),
            key_use,
        )?,
    }
    tracing::info!(%name, ?chain, %key_use, "generated key");
    git.after_mutation()?;
    Ok(())
}

fn cmd_address(chain: Chain, name: &str, unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    let _store = flock::store_claim()?;
    let config = Arc::new(Config::load()?);
    let (backend, _) = backend_for(&config, unlock)?;
    let api = HotApi::new(Box::new(backend), config);
    let addr = match chain {
        Chain::Evm => api.address(&OpContext::local(name.to_string(), Operation::EvmAddress))?,
        Chain::Solana => api.address_solana(&OpContext::local(
            name.to_string(),
            Operation::SolanaAddress,
        ))?,
    };
    tracing::info!(%name, %addr, "address");
    Ok(())
}

/// A JSON body from `--file` or stdin. Every verb that ingests one takes it the same way.
fn read_input(file: Option<&Path>) -> Result<Vec<u8>, std::io::Error> {
    const MAX_CLI_INPUT_BYTES: u64 = hc_sign::qr::MAX_BODY_BYTES as u64;
    let Some(path) = file else {
        return hc_core::read_bounded(std::io::stdin().lock(), MAX_CLI_INPUT_BYTES);
    };
    hc_core::read_regular_file_bounded(path, MAX_CLI_INPUT_BYTES)
}

/// THE local signing path. Policy, the manifest-free CLI provenance, the pinned grant key, the
/// single biometric and the zeroizing decrypt all live behind [`HotApi::sign_typed`], so
/// `bundle sign` cannot grow a second route to a key.
fn sign_intent_locally(
    intent: hc_sign::intent::SafeTxIntent,
    unlock: Option<UnlockMethod>,
) -> Result<hc_sign::SignResponse, CliErr> {
    let _store = flock::store_claim()?;
    let config = Arc::new(Config::load()?);
    let (backend, gate) = backend_for(&config, unlock)?;
    let api = HotApi::new(Box::new(backend), config);
    let approver = Approver::new(gate, Arc::new(Headless::detect()));
    let ctx = OpContext::local(intent.key.clone(), Operation::Sign);
    Ok(api.sign_typed(&ctx, intent, &approver)?)
}

fn cmd_list() -> Result<(), CliErr> {
    let (config, keyring) = load_config_and_keyring()?;
    let store = config.store_path();

    tracing::info!(store = %store.display(), "keystores");
    for name in keystore_names(&store)? {
        let key_use = read_keystore(&store.join(&name))?.use_label();
        tracing::info!(key = %name, key_use, "  keystore");
    }

    tracing::info!(count = keyring.enrollments.len(), "enrollments");
    for e in &keyring.enrollments {
        match &e.params {
            EnrollParams::SecureEnclave { se_pub, .. } => tracing::info!(
                id = %e.id,
                kind = "secure_enclave",
                label = %e.label,
                se_key = %se_fingerprint(se_pub),
                created_at = e.created_at,
                "  enrollment"
            ),
            EnrollParams::Passphrase { .. } => tracing::info!(
                id = %e.id,
                kind = "passphrase",
                label = %e.label,
                created_at = e.created_at,
                "  enrollment"
            ),
        }
    }
    if !keyring.has_passphrase() {
        tracing::warn!(
            "no recovery passphrase enrolled — if the Secure Enclave key is lost the store \
             becomes unrecoverable; run `hot_cheese enroll passphrase`"
        );
    }
    Ok(())
}

/// Show what `serve` would do with each `[[adapters]]` entry: where its manifest is, whether
/// the bytes still hash to the pin, which socket carries its provenance, and whether every
/// grant narrows the key's policy. Prompts nothing, unlocks nothing, binds nothing.
fn cmd_adapters() -> Result<(), CliErr> {
    let config = Config::load()?;
    let store = config.store_path();
    tracing::info!(
        count = config.adapters.len(),
        dir = %adapters_dir().display(),
        "adapters"
    );
    for pin in &config.adapters {
        let socket = adapter_socket(&pin.id);
        let loaded = match hc_sign::manifest::load_pinned(pin) {
            Ok(loaded) => loaded,
            Err(e) => {
                tracing::warn!(
                    id = %pin.id,
                    manifest = %pin.manifest_path().display(),
                    pinned = %pin.sha256,
                    socket = %socket.display(),
                    error = ?e,
                    verdict = "REFUSED: serve will not start",
                    "  adapter"
                );
                continue;
            }
        };
        match loaded.check(&store) {
            Ok(()) => tracing::info!(
                id = %pin.id,
                manifest = %loaded.path.display(),
                pinned = %pin.sha256,
                computed = %hex::encode(loaded.digest),
                socket = %socket.display(),
                grants = loaded.manifest.grants.len(),
                verdict = "ok: every grant narrows its key's policy",
                "  adapter"
            ),
            Err(e) => tracing::warn!(
                id = %pin.id,
                manifest = %loaded.path.display(),
                pinned = %pin.sha256,
                computed = %hex::encode(loaded.digest),
                socket = %socket.display(),
                grants = loaded.manifest.grants.len(),
                error = ?e,
                verdict = "REFUSED: serve will not start",
                "  adapter"
            ),
        }
    }
    Ok(())
}

/// Every keystore in `store`: a regular file whose name is a valid key name, sorted. The
/// keyring and any `.hctmp` write are excluded by the name rule, which rejects `.`.
fn keystore_names(store: &Path) -> Result<Vec<String>, CliErr> {
    let mut names = Vec::new();
    for (at, entry) in std::fs::read_dir(store)?.enumerate() {
        if at >= hc_core::MAX_STORE_ENUM_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "store directory has too many entries",
            )
            .into());
        }
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_valid_key_name(&name) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Re-seal keystores under `key_use`, tightening only. The whole batch is decided from the
/// cleartext headers first, so the DEK is unlocked ONCE and only if there is work; each file
/// is re-opened from its new bytes and compared before it replaces the old one.
fn cmd_seal(
    name: Option<String>,
    all: bool,
    key_use: KeyUse,
    unlock: Option<UnlockMethod>,
) -> Result<(), CliErr> {
    let config = Arc::new(Config::load()?);
    let git = claimed_store(&config)?;
    let store = config.store_path();
    if name.as_deref().is_some_and(|name| !is_valid_key_name(name)) {
        return Err(hc_daemon::ApiBackendErr::InvalidName.into());
    }
    let names = match (all, name) {
        (true, _) => keystore_names(&store)?,
        (false, Some(name)) => vec![name],
        (false, None) => return Err(CliErr::SealNeedsTarget),
    };

    let mut pending = Vec::new();
    for name in names {
        let file = read_keystore(&store.join(&name))?;
        if let KeystoreFile::Sealed(sealed) = &file {
            // A sweep never re-decides a use someone already chose; tightening one takes
            // naming it, because it cannot be undone.
            if all || sealed.key_use == key_use {
                continue;
            }
            if sealed.key_use == KeyUse::SignOnly {
                return Err(CliErr::SealCannotLoosen {
                    name,
                    from: sealed.key_use,
                    to: key_use,
                });
            }
        }
        pending.push((name, file));
    }
    if pending.is_empty() {
        tracing::info!(%key_use, "nothing to seal");
        return Ok(());
    }

    let (backend, _) = backend_for(&config, unlock)?;
    let dek = backend.unlock_dek(
        &format!(
            "Unlock the hot_cheese DEK to seal {} keystore(s)",
            pending.len()
        ),
        None,
    )?;
    for (name, file) in pending {
        let plaintext = file.open(&name, &dek)?;
        let bytes = seal_keystore(&name, &dek, key_use, &plaintext)?;
        let verify = parse_keystore(&bytes)?.open(&name, &dek)?;
        if verify.as_slice() != plaintext.as_slice() {
            return Err(CliErr::SealVerifyMismatch { name });
        }
        atomic_write(&store.join(&name), &bytes)?;
        tracing::info!(%name, %key_use, "sealed");
    }

    git.after_mutation()?;
    Ok(())
}

fn cmd_serve(unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    // The daemon holds its unlocker for the whole process lifetime, so a passphrase unlocker
    // would answer every later request from one startup prompt — no per-request human. The
    // biometric gate is the point of the daemon; recover an SE key with the management
    // commands (`--unlock passphrase enroll se`) instead of downgrading `serve`.
    if unlock == Some(UnlockMethod::Passphrase) {
        return Err(CliErr::ServeRefusesPassphraseUnlock);
    }
    let store = flock::store_claim()?;
    let config = Config::load()?;

    let Some(pinned) = &config.grant_public_key else {
        return Err(CliErr::GrantKeyMissingRunEnrollGrant);
    };
    let found = match secure_enclave::grant_public_key(GRANT_LABEL) {
        Ok(pk) => hex::encode(pk),
        Err(secure_enclave::SeErr::KeyNotFound) => {
            return Err(CliErr::GrantKeyMissingRunEnrollGrant)
        }
        Err(e) => return Err(e.into()),
    };
    if &found != pinned {
        return Err(CliErr::GrantKeyPinMismatch {
            pinned: pinned.clone(),
            found,
        });
    }

    if git_store::local_vault(&config.store_path())? == git_store::LocalVault::Absent {
        return Err(CliErr::StoreMissingRunBackupPull);
    }

    let (backend, _) = backend_for(&config, unlock)?;
    Ok(hc_daemon::serve(config, Box::new(backend), store)?)
}

/// The one remote every reading verb uses. Push is the only verb that fans out.
fn first_remote(config: &Config) -> Result<&BackupRemote, CliErr> {
    Ok(config
        .backup_remotes
        .first()
        .ok_or(git_store::GitErr::NoBackupRemote)?)
}

/// Open the store's repository for a subcommand that is about to write to it. `status` and
/// `list` deliberately do not come through here: neither writes, and an operator must be able
/// to ask "is my backup healthy?" while a console holds the claim.
fn claimed_store(config: &Arc<Config>) -> Result<GitStore, CliErr> {
    let git = GitStore::cli(config.clone(), flock::store_claim()?)?;
    git.open()?;
    Ok(git)
}

fn cmd_backup(cmd: BackupCmd) -> Result<(), CliErr> {
    let config = Arc::new(Config::load()?);
    match cmd {
        BackupCmd::Status => {
            let state = git_store::GitState::local(&config)?;
            tracing::info!(
                vault = ?state.vault,
                head = ?state.head,
                remotes = state.remotes.len(),
                "backup status"
            );
            for remote in &state.remotes {
                tracing::info!(host = %remote.host, folder = %remote.folder, relation = %remote.relation, "  remote");
            }
        }
        BackupCmd::Push => {
            let git = claimed_store(&config)?;
            git.push_every(&config)?;
            tracing::info!(remotes = config.backup_remotes.len(), "pushed the store");
        }
        BackupCmd::Fetch => {
            let git = claimed_store(&config)?;
            git.fetch_every(&config)?;
            let state = git.status().snapshot();
            for remote in &state.remotes {
                tracing::info!(host = %remote.host, relation = %remote.relation, remote_head = ?remote.remote_head, "  remote");
            }
            if let Some((host, local, remote)) = diverged(&state) {
                return Err(git_store::GitErr::Diverged {
                    host,
                    local,
                    remote,
                }
                .into());
            }
        }
        BackupCmd::Pull {
            vault,
            force,
            confirm_rewind,
        } => {
            let git = claimed_store(&config)?;
            let remote = first_remote(&config)?;
            let vault = git_store::pull_vault(&config, remote, vault)?;
            let mut doomed = git.pull_preview(remote, &vault)?;
            tracing::warn!(
                host = %remote.host,
                %vault,
                relation = %doomed.relation,
                local_only_commits = doomed.local_only,
                remote_only_commits = doomed.remote_only,
                local_committed_at = ?doomed.local_at,
                remote_committed_at = doomed.remote_at,
                added = doomed.added.len(),
                changed = doomed.changed.len(),
                removed = doomed.removed.len(),
                "a forced pull REPLACES the active store with an explicitly trusted remote copy"
            );
            for name in &doomed.added {
                tracing::info!(file = %name, "  ADDED by the pull");
            }
            for name in &doomed.changed {
                tracing::warn!(file = %name, "  REPLACED by the pull");
            }
            for name in &doomed.removed {
                tracing::warn!(file = %name, "  DELETED by the pull");
            }
            for id in &doomed.lost_enrollments {
                tracing::warn!(enrollment = %id, "  UNLOCK PATH LOST: the incoming keyring keeps none of this machine's enrollments");
            }
            for name in &doomed.tracked {
                tracing::warn!(file = %name, "  local edit discarded by the reset");
            }
            for name in &doomed.untracked {
                tracing::warn!(file = %name, "  untracked file deleted by the clean");
            }
            if !force {
                return Err(CliErr::PullNeedsForce);
            }
            if let Some(rewind) = doomed.rewind {
                let ground = match rewind {
                    git_store::Rewind::Backwards => {
                        "OLDER HISTORY: the incoming tip is a commit this machine already moved past"
                    }
                    git_store::Rewind::Fork => {
                        "FORK: the incoming tip does not contain this machine's commits and discards them"
                    }
                    git_store::Rewind::Deletes => {
                        "DELETION: the incoming tip drops store files this machine's commit has"
                    }
                    git_store::Rewind::Contents => {
                        "OLDER CONTENT: nothing is deleted and no local commit is discarded, and the security-relevant files listed as REPLACED above take older content — which can revive a retired keystore, restore an older keyring.json, or reinstate a looser policy"
                    }
                };
                tracing::warn!(
                    ground,
                    ?rewind,
                    local_only_commits = doomed.local_only,
                    replaced = doomed.changed.len(),
                    removed = doomed.removed.len(),
                    lost_enrollments = doomed.lost_enrollments.len(),
                    local_committed_at = ?doomed.local_at,
                    remote_committed_at = doomed.remote_at,
                    "THIS PULL PUTS BACK STATE THIS MACHINE MOVED PAST: every file listed as REPLACED or DELETED above takes the content a remote host chose"
                );
                require_typed_confirmation(
                    PULL_REWIND_PHRASE,
                    PULL_REWIND_FLAG,
                    confirm_rewind.as_deref(),
                )?;
                doomed.accept_rewind();
            }
            git.pull_apply(&doomed)?;
            tracing::info!(host = %remote.host, %vault, head = %doomed.remote_head, "pulled the store from the remote");
        }
        BackupCmd::List => {
            let remote = first_remote(&config)?;
            let mine = git_store::local_vault(&config.store_path())?;
            let found = git_store::list_vaults(remote)?;
            tracing::info!(host = %remote.host, folder = %remote.folder, count = found.git.len(), "vaults on remote");
            for v in &found.git {
                tracing::info!(vault = %v, this_install = mine.id() == Some(v), "  vault");
            }
            for v in &found.legacy {
                tracing::warn!(vault = %v, "  pre-git backup directory, no longer written to");
            }
        }
    }
    Ok(())
}

/// The first remote a fetch found a fork against, if any. A fork is a state the status carries,
/// so only the operator-driven verbs turn it into a failure.
fn diverged(
    state: &git_store::GitState,
) -> Option<(String, git_store::CommitId, git_store::CommitId)> {
    let local = state.head?;
    for remote in &state.remotes {
        if remote.relation == git_store::Relation::Diverged {
            return Some((remote.host.clone(), local, remote.remote_head?));
        }
    }
    None
}

fn cmd_migrate(
    old_store: &Path,
    new_store: &Path,
    shareable: Vec<String>,
    unlock: Option<UnlockMethod>,
) -> Result<(), CliErr> {
    // Migration changes the initialized keyring's store. Take that installation's claim before
    // loading either file, then require the requested destination to be the same directory; an
    // arbitrary --new-store would not be protected by this lock and would be backed up wrongly.
    let claim = flock::store_claim()?;
    let (config, keyring) = load_config_and_keyring()?;
    let configured_store = config.store_path();
    let expected = std::fs::canonicalize(&configured_store)?;
    let found = std::fs::canonicalize(new_store)?;
    if expected != found {
        return Err(migrate::MigrateErr::WrongNewStore {
            expected: configured_store,
            found: new_store.to_path_buf(),
        }
        .into());
    }
    let config = Arc::new(config);
    let git = GitStore::cli(config.clone(), claim)?;
    let shareable: hashbrown::HashSet<String> = shareable.into_iter().collect();

    // Reject public mistakes and unsafe filesystem state before either Touch ID authorization.
    // `migrate::run` repeats this preflight once the secrets are available.
    migrate::preflight(old_store, new_store, &shareable)?;

    // The legacy master lives in the login Keychain behind Touch ID.
    if !authorize_with_touch_id("read the legacy hot_cheese Keychain master for migrate") {
        tracing::error!("Touch ID authorization was denied; migration aborted");
        return Err(CliErr::TouchIdDenied);
    }
    // Zeroizing so the legacy master is wiped on every exit path, including early `?` returns.
    let old_master = get_password_from_keychain(&config.service, &config.account)?;

    // Unlock the new DEK that the migrated keys will be re-encrypted under.
    let unlocker = make_unlocker(&keyring, unlock)?;
    let dek = unlocker.unlock("Unlock the hot_cheese DEK for migrate", &keyring, None)?;

    let migrated = migrate::run(old_store, &old_master, new_store, &dek, &shareable)?;

    tracing::info!(count = migrated.len(), "migration complete");
    for k in &migrated {
        tracing::info!(name = %k.name, identity = %k.identity, key_use = %k.key_use, "  migrated");
    }
    git.after_mutation()?;
    Ok(())
}

/// Read a secret from a hidden prompt and decode it per `kind`. Every buffer holding the
/// plaintext is wiped when it drops, including on the error paths.
fn read_secret(kind: SecretKind) -> Result<Zeroizing<Vec<u8>>, CliErr> {
    let prompt = match kind {
        SecretKind::Ethereum => "Private key (hex, 0x optional): ",
        SecretKind::Solana => "Keypair (base58): ",
        SecretKind::Bytes => "Secret (raw UTF-8): ",
    };
    let entered = Zeroizing::new(rpassword::prompt_password(prompt)?);
    decode_secret(kind, &entered)
}

/// Pure decoding of an entered secret string into raw bytes, mirroring the legacy
/// `add_existing` example: ethereum=hex(0x optional), solana=base58, bytes=UTF-8.
fn decode_secret(kind: SecretKind, entered: &str) -> Result<Zeroizing<Vec<u8>>, CliErr> {
    if entered.len() > MAX_ENCODED_SECRET_BYTES {
        return Err(CliErr::SecretInputTooLarge {
            size: entered.len(),
            max: MAX_ENCODED_SECRET_BYTES,
        });
    }
    let decoded = Zeroizing::new(match kind {
        SecretKind::Ethereum => hex::decode(
            entered
                .trim()
                .strip_prefix("0x")
                .or_else(|| entered.trim().strip_prefix("0X"))
                .unwrap_or(entered.trim()),
        )
        .map_err(|_| {
            CliErr::StdIo(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid hex",
            ))
        }),
        SecretKind::Solana => bs58::decode(entered.trim()).into_vec().map_err(|_| {
            CliErr::StdIo(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid base58",
            ))
        }),
        SecretKind::Bytes => Ok(entered.as_bytes().to_vec()),
    }?);
    if decoded.len() > MAX_SECRET_BYTES {
        return Err(EnvErr::PlaintextTooLarge {
            size: decoded.len(),
            max: MAX_SECRET_BYTES,
        }
        .into());
    }
    Ok(decoded)
}

/// The TLS pair `init` installs once the recovery passphrase is accepted.
struct TlsMaterial {
    /// Certificate PEM, public.
    cert_pem: Vec<u8>,
    /// Private key PEM, written 0600.
    key_pem: Zeroizing<Vec<u8>>,
    /// Certificate DER, whose SHA-256 is the fingerprint clients pin.
    cert_der: Vec<u8>,
}

/// Generate a self-signed localhost cert (CN=localhost, SAN DNS:localhost + IP:127.0.0.1,
/// EKU serverAuth).
fn generate_localhost_cert() -> Result<TlsMaterial, CliErr> {
    use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};

    let key_pair = KeyPair::generate()?;
    // `new` maps each string to a SAN: parseable IPs become IpAddress SANs, the rest
    // become DnsName SANs — so this yields DNS:localhost + IP:127.0.0.1.
    let mut params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let cert = params.self_signed(&key_pair)?;
    Ok(TlsMaterial {
        cert_pem: cert.pem().into_bytes(),
        key_pem: Zeroizing::new(key_pair.serialize_pem().into_bytes()),
        cert_der: cert.der().as_ref().to_vec(),
    })
}

/// The 16 lowercase hex characters of SHA-256 over a SEC1 enclave public key, the form the
/// bootstrap ritual and the `/read` prompt already name an enclave key by.
fn se_fingerprint(public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(public_key)[..8])
}

/// Lowercase hex of SHA-256 over `bytes` (cert DER → pinning fingerprint).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_add_with_kind() {
        let cli = Cli::try_parse_from(["hot_cheese", "add", "MY_KEY", "ethereum"])
            .expect("add should parse");
        match cli.command {
            Some(Commands::Add {
                name,
                kind,
                key_use,
            }) => {
                assert_eq!(name, "MY_KEY");
                assert_eq!(kind, SecretKind::Ethereum);
                assert_eq!(key_use, KeyUse::SignOnly);
            }
            other => panic!("expected Add, got {:?}", other),
        }
    }

    #[test]
    fn parses_generate_chain_then_name() {
        let cli = Cli::try_parse_from(["hot_cheese", "generate", "solana", "trader"])
            .expect("generate should parse");
        match cli.command {
            Some(Commands::Generate {
                chain,
                name,
                key_use,
            }) => {
                assert_eq!(chain, Chain::Solana);
                assert_eq!(name, "trader");
                assert_eq!(key_use, KeyUse::SignOnly);
            }
            other => panic!("expected Generate, got {:?}", other),
        }
    }

    /// A key that may leave the daemon has to be asked for by name, everywhere: the default is
    /// the tight one on every creation surface, `--use` spells the loose one out, and `seal`
    /// takes either one target or the whole store but never both.
    #[test]
    fn shareable_is_never_the_default_and_must_be_spelled_out() {
        let cli = Cli::try_parse_from(["hot_cheese", "generate", "evm", "T", "--use", "shareable"])
            .expect("generate --use parses");
        assert!(
            matches!(cli.command, Some(Commands::Generate { key_use, .. }) if key_use == KeyUse::Shareable)
        );

        let cli = Cli::try_parse_from(["hot_cheese", "add", "T", "bytes", "--use", "shareable"])
            .expect("add --use parses");
        assert!(
            matches!(cli.command, Some(Commands::Add { key_use, .. }) if key_use == KeyUse::Shareable)
        );

        let cli = Cli::try_parse_from(["hot_cheese", "seal", "--all"]).expect("seal --all parses");
        assert!(
            matches!(cli.command, Some(Commands::Seal { name, all, key_use }) if name.is_none() && all && key_use == KeyUse::SignOnly)
        );

        assert!(Cli::try_parse_from(["hot_cheese", "seal", "T", "--all"]).is_err());
        assert!(
            Cli::try_parse_from(["hot_cheese", "generate", "evm", "T", "--use", "any"]).is_err()
        );

        let cli = Cli::try_parse_from([
            "hot_cheese",
            "migrate",
            "--old-store",
            "/o",
            "--new-store",
            "/n",
            "--shareable",
            "A",
            "--shareable",
            "B",
        ])
        .expect("repeatable --shareable parses");
        assert!(
            matches!(cli.command, Some(Commands::Migrate { shareable, .. }) if shareable == ["A", "B"])
        );
    }

    /// Disaster recovery types the vault id in by hand, so the value parser has to turn
    /// `v_<hex>` into a real [`VaultId`] and reject anything that is not one; omitting
    /// `--vault` must stay `None` so the pull falls back to this install's own id. A bare
    /// `pull` must also stay un-forced and carry no rollback consent, because the forced one
    /// deletes keystores and the rewinding one replays history a remote host chose.
    #[test]
    fn backup_pull_takes_a_typed_vault_id() {
        let cli = Cli::try_parse_from([
            "hot_cheese",
            "backup",
            "pull",
            "--vault",
            "v_0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "--force",
        ])
        .expect("backup pull --vault parses");
        let expected: VaultId = "v_0f1e2d3c4b5a69788796a5b4c3d2e1f0"
            .parse()
            .expect("fixture id parses");
        assert!(
            matches!(cli.command, Some(Commands::Backup(BackupCmd::Pull { vault, force, confirm_rewind })) if vault == Some(expected) && force && confirm_rewind.is_none())
        );

        let cli = Cli::try_parse_from(["hot_cheese", "backup", "pull"]).expect("bare pull parses");
        assert!(matches!(
            cli.command,
            Some(Commands::Backup(BackupCmd::Pull {
                vault: None,
                force: false,
                confirm_rewind: None
            }))
        ));

        assert!(
            Cli::try_parse_from(["hot_cheese", "backup", "pull", "--vault", "nonsense"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "hot_cheese",
                "backup",
                "pull",
                "--confirm-rewind",
                PULL_REWIND_PHRASE
            ])
            .is_err(),
            "rollback consent is meaningless without --force"
        );
    }

    /// Sync is woven into the bundle verbs rather than being a verb, so its off switch has to
    /// be accepted where an operator will actually type it — after the verb, after that verb's
    /// own arguments, and inside the nested `peer` tree — and must stay off by default so a
    /// plain `bundle status` really does reach the peers.
    #[test]
    fn no_sync_reaches_every_bundle_verb_and_nothing_else() {
        let cli = Cli::try_parse_from(["hot_cheese", "bundle", "list"]).expect("bundle list");
        assert!(matches!(
            cli.command,
            Some(Commands::Bundle { no_sync: false, .. })
        ));

        let cli = Cli::try_parse_from([
            "hot_cheese",
            "bundle",
            "status",
            "0x44ae0d1d0b9bbbf2cbb0ff9dd7a0b0b8b6d5c4a3e2f1908172635445362718b5",
            "--no-sync",
        ])
        .expect("--no-sync after the hash parses");
        assert!(matches!(
            cli.command,
            Some(Commands::Bundle { no_sync: true, .. })
        ));

        let cli = Cli::try_parse_from(["hot_cheese", "bundle", "peer", "add", "macbook"])
            .expect("the nested peer tree parses");
        assert!(matches!(
            cli.command,
            Some(Commands::Bundle { no_sync: false, .. })
        ));

        assert!(
            Cli::try_parse_from(["hot_cheese", "list", "--no-sync"]).is_err(),
            "it belongs to bundle alone, not to every command"
        );
    }

    #[test]
    fn parses_enroll_se_with_label() {
        let cli = Cli::try_parse_from(["hot_cheese", "enroll", "se", "--label", "macbook"])
            .expect("enroll se should parse");
        match cli.command {
            Some(Commands::Enroll(EnrollCmd::Se { label })) => assert_eq!(label, "macbook"),
            other => panic!("expected Enroll Se, got {:?}", other),
        }
    }

    #[test]
    fn bootstrap_serve_is_hidden_but_parses() {
        let cli = Cli::try_parse_from(["hot_cheese", "bootstrap-serve"])
            .expect("bootstrap-serve should parse");
        assert!(cli.command.as_ref().is_some_and(command_owns_stdout));
        assert!(matches!(cli.command, Some(Commands::BootstrapServe)));
    }

    #[test]
    fn invalid_chain_is_rejected() {
        assert!(Cli::try_parse_from(["hot_cheese", "generate", "dogecoin", "x"]).is_err());
    }

    /// The SE-loss escape hatch: `--unlock` is declared once on the root but must reach every
    /// unlocking subcommand (including the nested `enroll se`), be accepted AFTER the
    /// subcommand's own arguments, and stay `None` when absent so the default (Secure Enclave
    /// when enrolled) is untouched.
    #[test]
    fn unlock_is_global_and_defaults_to_none() {
        let cli = Cli::try_parse_from(["hot_cheese", "address", "evm", "DRYRUN_EVM"])
            .expect("address parses");
        assert_eq!(cli.unlock, None);

        let cli = Cli::try_parse_from([
            "hot_cheese",
            "address",
            "evm",
            "DRYRUN_EVM",
            "--unlock",
            "passphrase",
        ])
        .expect("trailing --unlock parses");
        assert_eq!(cli.unlock, Some(UnlockMethod::Passphrase));

        let cli = Cli::try_parse_from(["hot_cheese", "--unlock", "se", "list"])
            .expect("leading --unlock parses");
        assert_eq!(cli.unlock, Some(UnlockMethod::Se));

        let cli = Cli::try_parse_from(["hot_cheese", "enroll", "se", "--unlock", "passphrase"])
            .expect("nested subcommand inherits --unlock");
        assert_eq!(cli.unlock, Some(UnlockMethod::Passphrase));

        assert!(Cli::try_parse_from(["hot_cheese", "list", "--unlock", "yubikey"]).is_err());
    }

    #[test]
    fn ethereum_decodes_with_and_without_0x() {
        let with = decode_secret(SecretKind::Ethereum, "0xdeadbeef").expect("0x hex decodes");
        let without = decode_secret(SecretKind::Ethereum, "deadbeef").expect("bare hex decodes");
        assert_eq!(with.as_slice(), &[0xde, 0xad, 0xbe, 0xef][..]);
        assert_eq!(with.as_slice(), without.as_slice());
    }

    #[test]
    fn ethereum_rejects_odd_length_hex() {
        assert!(decode_secret(SecretKind::Ethereum, "abc").is_err());
    }

    #[test]
    fn solana_decodes_base58_roundtrip() {
        let raw = vec![1u8, 2, 3, 4, 5, 255, 0, 127];
        let encoded = bs58::encode(&raw).into_string();
        let decoded = decode_secret(SecretKind::Solana, &encoded).expect("base58 decodes");
        assert_eq!(decoded.as_slice(), raw.as_slice());
    }

    #[test]
    fn bytes_passes_through_utf8() {
        let decoded = decode_secret(SecretKind::Bytes, "hello world").expect("utf8 passes through");
        assert_eq!(decoded.as_slice(), &b"hello world"[..]);
    }

    #[test]
    fn secret_decoding_is_bounded_before_unlock() {
        assert!(matches!(
            decode_secret(SecretKind::Bytes, &"x".repeat(MAX_SECRET_BYTES + 1)),
            Err(CliErr::Envelope(EnvErr::PlaintextTooLarge { .. }))
        ));
        assert!(matches!(
            decode_secret(
                SecretKind::Solana,
                &"1".repeat(MAX_ENCODED_SECRET_BYTES + 1)
            ),
            Err(CliErr::SecretInputTooLarge { .. })
        ));
    }

    #[test]
    fn imported_tls_material_must_parse_and_match_before_installation() {
        let mine = generate_localhost_cert().expect("generate first pair");
        let other = generate_localhost_cert().expect("generate second pair");
        assert_eq!(
            hc_daemon::validate_tls_pair(&mine.cert_pem, &mine.key_pem)
                .expect("matching pair validates"),
            mine.cert_der
        );
        assert!(hc_daemon::validate_tls_pair(&mine.cert_pem, &other.key_pem).is_err());
        assert!(hc_daemon::validate_tls_pair(b"not pem", &mine.key_pem).is_err());
    }

    /// `init --force` mints a new DEK, so before anything happens it has to name every keystore
    /// it strands and every enrollment it drops, and refuse until the phrase comes back exactly.
    #[test]
    fn forced_init_names_what_it_destroys_and_refuses_without_the_phrase() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_forced_init_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = dir.join("store");
        std::fs::create_dir_all(&store).expect("fixture store");

        let empty = StoreContents::read(&store).expect("an empty store reads");
        assert!(empty.is_empty());
        assert!(confirm_forced_init(&store, &empty, None)
            .expect("an empty store needs no confirmation")
            .is_none());

        std::fs::write(store.join("SOLANA_MAIN"), b"ciphertext").expect("fixture keystore");
        std::fs::write(store.join("EVM_HOT"), b"ciphertext").expect("fixture keystore");
        let dek = Dek::random();
        let mut keyring = Keyring::new();
        keyring.add(
            PassphraseUnlocker::new("correct horse battery staple".to_string())
                .enroll("recovery", &dek)
                .expect("fixture enrollment"),
        );
        keyring
            .save(&store.join(hc_core::keyring::KEYRING_FILE))
            .expect("fixture keyring");

        let existing = StoreContents::read(&store).expect("the store reads");
        assert!(!existing.is_empty());
        assert!(existing.keyring);
        assert_eq!(existing.keystores, ["EVM_HOT", "SOLANA_MAIN"]);
        assert_eq!(existing.enrollments.len(), 1);
        assert_eq!(existing.enrollments[0].label, "recovery");

        assert!(matches!(
            confirm_forced_init(&store, &existing, Some("y")),
            Err(CliErr::ConfirmationRefused { .. })
        ));
        assert!(
            confirm_forced_init(&store, &existing, Some(FORCED_INIT_PHRASE))
                .expect("the exact phrase proceeds")
                .is_some(),
            "the phrase is what mints the capability the replacing commit needs"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Both surfaces that name an enclave key must render one key as the same 16 characters, or
    /// the fingerprint an operator wrote down at `enroll` cannot be compared with the one `list`
    /// and the console print, and the comparison this control exists for is worthless.
    #[cfg(feature = "console")]
    #[test]
    fn the_cli_and_the_console_name_an_enclave_key_identically() {
        let mut key = [4u8; 65];
        key[1] = 9;
        let printed = se_fingerprint(&key);
        assert_eq!(printed.len(), 16);
        assert_eq!(printed, hc_console::menu::se_fingerprint(&key));
    }

    #[test]
    fn sha256_hex_is_64_hex_chars() {
        let fp = sha256_hex(b"abc");
        assert_eq!(fp.len(), 64);
        // SHA-256("abc") well-known vector.
        assert_eq!(
            fp,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
