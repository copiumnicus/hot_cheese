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
    adapter_socket, adapters_dir, cert_paths, config_path, env_log_level, home_dir, Config,
};
use hc_core::crypto::envelope::{
    atomic_write, encrypt_file, parse_keystore, read_keystore, seal_keystore, write_private_file,
    Dek, KeyUse, KeystoreFile,
};
use hc_core::is_valid_string_name;
use hc_core::keyring::{EnrollParams, Keyring, VaultId};
use hc_core::mac::secure_enclave;
use hc_core::mac::{authorize_with_touch_id, get_password_from_keychain, BackendImpl, MacBackend};
use hc_core::unlock::{PassphraseUnlocker, SecureEnclaveUnlocker, Unlocker};
use hc_daemon::{backup, run_server, HotApi, OpContext, Operation, Peer};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

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

// Variants in source order: PassphraseMismatch (prompt confirmation differed),
// AlreadyInitialized (`init` without `--force`), CertKeyPairRequired (one of
// --import-cert/--import-key supplied), NoBackupRemote (pull/push with none set),
// ServeRefusesPassphraseUnlock (`serve --unlock passphrase` would cache the passphrase for
// the daemon's lifetime and drop the per-request biometric), SealNeedsTarget (`seal` with
// neither a name nor --all), then `#[from]` wrappers for each module error this CLI touches,
// then ExistingStore (`init` found key material), NotInitialized (no config.toml, so there is
// nothing for the console to open), SealCannotLoosen (sealing is one-way),
// SealVerifyMismatch (the re-sealed file did not re-open to the same bytes; nothing written),
// VaultAlreadyAdopted (`backup adopt` on a keyring that already has a vault id) and
// GrantKeyPinMismatch (`serve` found a grant key that is not the one config.toml pins).
// GrantKeyMissingRunEnrollGrant is `serve` without an enrolled grant key, which every
// signature needs: nothing is pinned in config.toml, or the enclave blob is gone.
create_err_with_impls!(
    #[derive(Debug)]
    pub CliErr,
    PassphraseMismatch,
    AlreadyInitialized,
    CertKeyPairRequired,
    NoBackupRemote,
    ServeRefusesPassphraseUnlock,
    SealNeedsTarget,
    TouchIdDenied,
    GrantKeyMissingRunEnrollGrant,
    Config(hc_core::config::ConfigErr),
    Keyring(hc_core::keyring::KeyringErr),
    Unlock(hc_core::unlock::UnlockErr),
    Envelope(hc_core::crypto::envelope::EnvErr),
    ApiBackend(hc_daemon::ApiBackendErr),
    Backup(hc_daemon::backup::BackupErr),
    Migrate(migrate::MigrateErr),
    Bootstrap(bootstrap::BootstrapErr),
    Bundle(hc_daemon::bundle::BundleErr),
    BundleSync(hc_daemon::bundle::sync::SyncErr),
    Render(hc_daemon::qr_term::RenderErr),
    GetPassword(hc_core::mac::GetPasswordErr),
    Se(hc_core::mac::secure_enclave::SeErr),
    Sign(hc_sign::SignErr),
    Grant(hc_sign::grant::GrantErr),
    Serde(serde_json::Error),
    Serve(hc_daemon::ServeErr),
    Console(ConsoleErr),
    Rcgen(rcgen::Error),
    StdIo(std::io::Error)
    ;
    ExistingStore { store: PathBuf, keyring: bool, keystores: usize },
    NotInitialized { config: PathBuf },
    SealCannotLoosen { name: String, from: KeyUse, to: KeyUse },
    SealVerifyMismatch { name: String },
    VaultAlreadyAdopted { vault: VaultId },
    GrantKeyPinMismatch { pinned: String, found: String }
);

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
    /// Sign a Safe transaction from a JSON intent (policy-checked, single Touch ID).
    Sign {
        /// Read the JSON intent from this file instead of stdin.
        #[arg(long, value_name = "JSON")]
        file: Option<PathBuf>,
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
    /// Run the HTTPS daemon (auto-pulls the store from the first backup remote if absent).
    Serve,
    /// Push or pull the encrypted store to/from configured backup remotes.
    #[command(subcommand)]
    Backup(BackupCmd),
    /// Migrate legacy Keychain-master keystores into the new envelope format.
    Migrate {
        /// Directory holding the legacy keystores.
        #[arg(long, value_name = "DIR")]
        old_store: PathBuf,
        /// Destination store dir (must be empty).
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
    /// Push the store to every configured remote, under this install's vault id.
    Push,
    /// Pull one vault from the first configured remote into the local store.
    Pull {
        /// Vault to pull (`v_<hex>`); defaults to this install's own vault id.
        #[arg(long, value_name = "ID")]
        vault: Option<VaultId>,
    },
    /// List the vaults sharing the first configured remote's folder.
    List,
    /// Mint a vault id for a keyring written before vault ids existed.
    Adopt,
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
            init_stdout_tracing();
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

fn dispatch(command: Commands, unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    match command {
        Commands::Init {
            import_cert,
            import_key,
            force,
        } => cmd_init(import_cert, import_key, force),
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
        Commands::Sign { file } => cmd_sign(file, unlock),
        Commands::Bundle { cmd, no_sync } => bundle::run(cmd, no_sync, unlock),
        Commands::List => cmd_list(),
        Commands::Adapters => cmd_adapters(),
        Commands::Seal { name, all, key_use } => cmd_seal(name, all, key_use, unlock),
        Commands::Serve => cmd_serve(unlock),
        Commands::Backup(cmd) => cmd_backup(cmd),
        Commands::Migrate {
            old_store,
            new_store,
            shareable,
        } => cmd_migrate(&old_store, &new_store, shareable, unlock),
        Commands::BootstrapFrom { target } => Ok(bootstrap::bootstrap_from(&target)?),
        Commands::BootstrapServe => Ok(bootstrap::bootstrap_serve()?),
        Commands::SeSelftest => cmd_se_selftest(),
    }
}

/// Open the interactive console. A passphrase session may manage keys locally but may never
/// expose them: without a live per-request biometric there is nothing to gate a release, so
/// the console starts no listener and refuses every tunnel.
#[cfg(feature = "console")]
fn cmd_console(unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    use hc_console::UnlockGate;

    if !config_path().exists() {
        return Err(CliErr::NotInitialized {
            config: config_path(),
        });
    }
    let (config, keyring) = load_config_and_keyring()?;
    let gate = match resolve_unlock_method(&keyring, unlock) {
        UnlockMethod::Se => UnlockGate::Biometric,
        UnlockMethod::Passphrase => UnlockGate::Passphrase,
    };
    let backend = open_backend(&config, unlock)?;
    Ok(hc_console::run_console(config, Box::new(backend), gate)?)
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
            Ok(Box::new(PassphraseUnlocker::new(pass)))
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
fn prompt_passphrase(prompt: &str) -> Result<String, CliErr> {
    Ok(rpassword::prompt_password(prompt)?)
}

/// Prompt twice and confirm the two entries match.
fn prompt_new_passphrase() -> Result<String, CliErr> {
    let first = rpassword::prompt_password("New passphrase: ")?;
    let second = rpassword::prompt_password("Confirm passphrase: ")?;
    if first != second {
        return Err(CliErr::PassphraseMismatch);
    }
    Ok(first)
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

/// Load the keyring, choose the unlocker, and open the Mac backend for `config`.
fn open_backend(config: &Config, method: Option<UnlockMethod>) -> Result<MacBackend, CliErr> {
    let keyring = Keyring::load(&keyring_file(config))?;
    let unlocker = make_unlocker(&keyring, method)?;
    Ok(MacBackend::new(&config.store, unlocker)?)
}

fn cmd_init(
    import_cert: Option<PathBuf>,
    import_key: Option<PathBuf>,
    force: bool,
) -> Result<(), CliErr> {
    // Home dir holds config.toml + the TLS cert/key; the store lives under it so
    // $HOT_CHEESE_HOME fully isolates an install (the demo's /tmp home stays self-contained).
    let home = home_dir();
    let store = home.join("store");

    // A fresh DEK orphans every keystore already wrapped under the old one, so refuse when
    // ANY prior install is visible — config.toml, a keyring, or keystore files.
    if !force {
        if config_path().exists() {
            return Err(CliErr::AlreadyInitialized);
        }
        let keyring = store.join("keyring.json").exists();
        let mut keystores = 0usize;
        if let Ok(entries) = std::fs::read_dir(&store) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_file())
                    && entry.file_name().to_str().is_some_and(is_valid_string_name)
                {
                    keystores += 1;
                }
            }
        }
        if keyring || keystores > 0 {
            return Err(CliErr::ExistingStore {
                store,
                keyring,
                keystores,
            });
        }
    }

    std::fs::create_dir_all(&home)?;
    let config = Config {
        service: DEFAULT_SERVICE.to_string(),
        account: DEFAULT_ACCOUNT.to_string(),
        store: store.to_string_lossy().into_owned(),
        port: None,
        grant_public_key: None,
        bundle_watch_secs: None,
        backup_remotes: Vec::new(),
        adapters: Vec::new(),
        bundle_peers: Vec::new(),
    };
    std::fs::create_dir_all(&store)?;

    // TLS cert: import the supplied pair, or mint a self-signed localhost cert. The cert is
    // public; the private key is written 0600 on both paths (std::fs::copy would carry the
    // source's mode over instead).
    let (cert_path, key_path) = cert_paths();
    let cert_der = match (import_cert, import_key) {
        (Some(c), Some(k)) => {
            std::fs::copy(&c, &cert_path)?;
            let key_pem = Zeroizing::new(std::fs::read(&k)?);
            write_private_file(&key_path, &key_pem)?;
            der_from_cert_pem(&cert_path)?
        }
        (None, None) => {
            let (cert_pem, key_pem, der) = generate_localhost_cert()?;
            let key_pem = Zeroizing::new(key_pem);
            std::fs::write(&cert_path, cert_pem)?;
            write_private_file(&key_path, key_pem.as_bytes())?;
            der
        }
        // Importing requires both halves.
        _ => return Err(CliErr::CertKeyPairRequired),
    };

    // Mint the DEK and require a recovery passphrase as the first (and survivable) enrollment.
    let dek = Dek::random();
    tracing::info!("A recovery passphrase is required: it is the only cross-machine restore path.");
    let pass = prompt_new_passphrase()?;
    let enrollment = PassphraseUnlocker::new(pass).enroll("recovery", &dek)?;
    let mut keyring = Keyring::new();
    // A fresh DEK is a fresh vault: it gets its own remote subtree so this install can share
    // a backup folder with other installs instead of overwriting one of them.
    let vault = VaultId::random();
    keyring.vault_id = Some(vault.clone());
    keyring.add(enrollment);
    keyring.save(&keyring_file(&config))?;

    // Persist config last, once the store + keyring are in place.
    config.save()?;

    let fingerprint = sha256_hex(&cert_der);
    tracing::info!(home = %home.display(), store = %store.display(), %vault, "initialized hot_cheese");
    tracing::info!(cert = %cert_path.display(), "TLS certificate written");
    tracing::info!(sha256 = %fingerprint, "certificate fingerprint (pin this on the client)");
    Ok(())
}

fn cmd_enroll(cmd: EnrollCmd, unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    let (mut config, mut keyring) = load_config_and_keyring()?;

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
            let dek = enroll_dek(&keyring, unlock)?;
            let pass = prompt_new_passphrase()?;
            PassphraseUnlocker::new(pass).enroll(&label, &dek)?
        }
        EnrollCmd::Grant => {
            secure_enclave::ensure_grant_key(GRANT_LABEL)?;
            let pinned = hex::encode(secure_enclave::grant_public_key(GRANT_LABEL)?);
            config.grant_public_key = Some(pinned.clone());
            config.save()?;
            tracing::info!(grant_public_key = %pinned, "created the Secure Enclave grant key and pinned it in config.toml");
            return Ok(());
        }
    };

    let id = enrollment.id.clone();
    keyring.add(enrollment);
    keyring.save(&keyring_file(&config))?;
    tracing::info!(enrollment = %id, "added enrollment");
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
    let config = Config::load()?;
    if !is_valid_string_name(name) {
        tracing::error!(%name, "invalid key name: only a-z, A-Z, 0-9, _ are allowed");
        return Err(CliErr::ApiBackend(hc_daemon::ApiBackendErr::KeyExists));
    }
    let store = config.store_path();
    if store.join(name).exists() {
        tracing::error!(%name, "key already exists");
        return Err(CliErr::ApiBackend(hc_daemon::ApiBackendErr::KeyExists));
    }

    // Read + decode the secret, then zeroize the decoded bytes after encryption.
    let mut secret = read_secret(kind)?;

    let backend = open_backend(&config, unlock)?;
    let dek = backend.unlock_dek(&format!("Unlock \"{}\" for import key", name), None)?;
    let result = encrypt_file(&backend.store_path(), name, &dek, key_use, &secret);
    secret.zeroize();
    result?;
    tracing::info!(%name, %key_use, "imported key");

    best_effort_backup_push(&config);
    Ok(())
}

fn cmd_generate(
    chain: Chain,
    name: &str,
    key_use: KeyUse,
    unlock: Option<UnlockMethod>,
) -> Result<(), CliErr> {
    let config = Arc::new(Config::load()?);
    let backend = open_backend(&config, unlock)?;
    let api = HotApi::new(Box::new(backend), config.clone());
    match chain {
        Chain::Evm => api.generate(&cli_context(name, Operation::EvmGenerate), key_use)?,
        Chain::Solana => {
            api.generate_solana(&cli_context(name, Operation::SolanaGenerate), key_use)?
        }
    }
    tracing::info!(%name, ?chain, %key_use, "generated key");
    best_effort_backup_push(&config);
    Ok(())
}

fn cmd_address(chain: Chain, name: &str, unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    let config = Arc::new(Config::load()?);
    let backend = open_backend(&config, unlock)?;
    let api = HotApi::new(Box::new(backend), config);
    let addr = match chain {
        Chain::Evm => api.address(&cli_context(name, Operation::EvmAddress))?,
        Chain::Solana => api.address_solana(&cli_context(name, Operation::SolanaAddress))?,
    };
    tracing::info!(%name, %addr, "address");
    Ok(())
}

/// A JSON body from `--file` or stdin. Every verb that ingests one takes it the same way.
fn read_input(file: Option<&Path>) -> Result<Vec<u8>, std::io::Error> {
    let Some(path) = file else {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        return Ok(buf);
    };
    std::fs::read(path)
}

/// THE local signing path. Policy, the manifest-free CLI provenance, the pinned grant key, the
/// single biometric and the zeroizing decrypt all live behind [`HotApi::sign_intent`]; `sign`
/// and `bundle sign` differ only in where the intent came from and where the answer goes, so
/// neither one may grow a second route to a key.
fn sign_intent_locally(
    intent: &hc_sign::intent::SafeTxIntent,
    unlock: Option<UnlockMethod>,
) -> Result<hc_sign::SignResponse, CliErr> {
    let config = Arc::new(Config::load()?);
    let body = serde_json::to_vec(&hc_sign::intent::Intent::SafeTx(intent.clone()))?;
    let backend = open_backend(&config, unlock)?;
    let api = HotApi::new(Box::new(backend), config);
    let out = api.sign_intent(
        &cli_context(&intent.key, Operation::Sign),
        &body,
        &hc_daemon::approval::ServeApprover,
    )?;
    Ok(serde_json::from_slice(&out)?)
}

/// Read a JSON SafeTx intent (from `--file` or stdin), then run the policy-checked,
/// single-Touch-ID sign flow and print the JSON response.
fn cmd_sign(file: Option<PathBuf>, unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    let hc_sign::intent::Intent::SafeTx(intent) =
        serde_json::from_slice(&read_input(file.as_deref())?)?;
    let response = sign_intent_locally(&intent, unlock)?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
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
        let kind = match e.params {
            EnrollParams::SecureEnclave { .. } => "secure_enclave",
            EnrollParams::Passphrase { .. } => "passphrase",
        };
        tracing::info!(id = %e.id, kind, label = %e.label, created_at = e.created_at, "  enrollment");
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
    for entry in std::fs::read_dir(store)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_valid_string_name(&name) {
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
    let config = Config::load()?;
    let store = config.store_path();
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

    let backend = open_backend(&config, unlock)?;
    let dek = backend.unlock_dek(
        &format!(
            "Unlock the hot_cheese DEK to seal {} keystore(s)",
            pending.len()
        ),
        None,
    )?;
    for (name, file) in pending {
        let plaintext = Zeroizing::new(file.open(&name, &dek)?);
        let bytes = seal_keystore(&name, &dek, key_use, &plaintext)?;
        let verify = Zeroizing::new(parse_keystore(&bytes)?.open(&name, &dek)?);
        if verify.as_slice() != plaintext.as_slice() {
            return Err(CliErr::SealVerifyMismatch { name });
        }
        atomic_write(&store.join(&name), &bytes)?;
        tracing::info!(%name, %key_use, "sealed");
    }

    best_effort_backup_push(&config);
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

    // Bootstrap-from-backup: if the store is empty and a remote is configured, pull first. With
    // no local keyring there is no vault id to ask for, so `pull_vault` adopts the remote's only
    // vault and refuses to guess between several.
    if backup::store_absent(&config.store_path()) {
        if let Some(remote) = config.backup_remotes.first() {
            let vault = backup::pull_vault(&config, remote, None)?;
            tracing::info!(host = %remote.host, vault = ?vault, "store empty; pulling from backup remote");
            backup::pull(&config, remote, vault.as_ref())?;
        }
    }

    let backend = open_backend(&config, unlock)?;
    Ok(run_server(Box::new(backend), config)?)
}

fn cmd_backup(cmd: BackupCmd) -> Result<(), CliErr> {
    let config = Config::load()?;
    match cmd {
        BackupCmd::Push => {
            backup::push_all(&config)?;
            tracing::info!("pushed store to all remotes");
        }
        BackupCmd::Pull { vault } => {
            let remote = config
                .backup_remotes
                .first()
                .ok_or(CliErr::NoBackupRemote)?;
            let vault = backup::pull_vault(&config, remote, vault)?;
            backup::pull(&config, remote, vault.as_ref())?;
            tracing::info!(host = %remote.host, vault = ?vault, "pulled store from remote");
        }
        BackupCmd::List => {
            let remote = config
                .backup_remotes
                .first()
                .ok_or(CliErr::NoBackupRemote)?;
            let mine = backup::local_vault(&config.store_path())?;
            let vaults = backup::list_vaults(remote)?;
            tracing::info!(host = %remote.host, folder = %remote.folder, count = vaults.len(), "vaults on remote");
            for v in &vaults {
                tracing::info!(vault = %v, this_install = mine.id() == Some(v), "  vault");
            }
        }
        BackupCmd::Adopt => {
            let path = keyring_file(&config);
            let mut keyring = Keyring::load(&path)?;
            if let Some(vault) = keyring.vault_id {
                return Err(CliErr::VaultAlreadyAdopted { vault });
            }
            let vault = VaultId::random();
            keyring.vault_id = Some(vault.clone());
            keyring.save(&path)?;
            tracing::info!(%vault, "adopted vault id; backups now land under <folder>/<vault>");
        }
    }
    Ok(())
}

fn cmd_migrate(
    old_store: &Path,
    new_store: &Path,
    shareable: Vec<String>,
    unlock: Option<UnlockMethod>,
) -> Result<(), CliErr> {
    let (config, keyring) = load_config_and_keyring()?;

    // The legacy master lives in the login Keychain behind Touch ID.
    if !authorize_with_touch_id("read the legacy hot_cheese Keychain master for migrate") {
        tracing::error!("Touch ID authorization was denied; migration aborted");
        return Err(CliErr::TouchIdDenied);
    }
    // Zeroizing so the legacy master is wiped on every exit path, including early `?` returns.
    let old_master = Zeroizing::new(get_password_from_keychain(
        &config.service,
        &config.account,
    )?);

    // Unlock the new DEK that the migrated keys will be re-encrypted under.
    let unlocker = make_unlocker(&keyring, unlock)?;
    let dek = unlocker.unlock("Unlock the hot_cheese DEK for migrate", &keyring, None)?;

    let migrated = migrate::run(
        old_store,
        &old_master,
        new_store,
        &dek,
        &shareable.into_iter().collect(),
    )?;

    tracing::info!(count = migrated.len(), "migration complete");
    for k in &migrated {
        tracing::info!(name = %k.name, identity = %k.identity, key_use = %k.key_use, "  migrated");
    }
    best_effort_backup_push(&config);
    Ok(())
}

/// Name a locally-invoked operation for the biometric prompt.
fn cli_context(name: &str, op: Operation) -> OpContext {
    OpContext {
        key: name.to_string(),
        op,
        peer: Peer::Cli,
    }
}

/// Push to backups if any remote is configured, logging but not failing on error.
fn best_effort_backup_push(config: &Config) {
    if config.backup_remotes.is_empty() {
        return;
    }
    if let Err(e) = backup::push_all(config) {
        tracing::warn!(error = %e, "backup push failed (continuing)");
    }
}

/// Read a secret from a hidden prompt and decode it per `kind`. Output is the raw
/// secret bytes the caller must zeroize after use.
fn read_secret(kind: SecretKind) -> Result<Vec<u8>, CliErr> {
    let prompt = match kind {
        SecretKind::Ethereum => "Private key (hex, 0x optional): ",
        SecretKind::Solana => "Keypair (base58): ",
        SecretKind::Bytes => "Secret (raw UTF-8): ",
    };
    let mut entered = rpassword::prompt_password(prompt)?;
    let decoded = decode_secret(kind, &entered);
    entered.zeroize();
    decoded
}

/// Pure decoding of an entered secret string into raw bytes, mirroring the legacy
/// `add_existing` example: ethereum=hex(0x optional), solana=base58, bytes=UTF-8.
fn decode_secret(kind: SecretKind, entered: &str) -> Result<Vec<u8>, CliErr> {
    match kind {
        SecretKind::Ethereum => {
            // df_share::from_hex_str strips an optional 0x and returns None on bad hex.
            df_share::from_hex_str(entered.trim()).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex").into()
            })
        }
        SecretKind::Solana => bs58::decode(entered.trim()).into_vec().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid base58").into()
        }),
        SecretKind::Bytes => Ok(entered.as_bytes().to_vec()),
    }
}

/// Read a PEM cert file and return its first certificate's DER bytes (for fingerprinting).
fn der_from_cert_pem(path: &Path) -> Result<Vec<u8>, CliErr> {
    let pem = std::fs::read_to_string(path)?;
    for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
        if let Some(end) = block.find("-----END CERTIFICATE-----") {
            let b64: String = block[..end].split_whitespace().collect();
            if let Some(der) = b64_decode(&b64) {
                return Ok(der);
            }
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "no certificate in PEM").into())
}

/// Minimal standard-base64 decoder (no external dep) for extracting cert DER from PEM.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for &c in &bytes {
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// Generate a self-signed localhost cert (CN=localhost, SAN DNS:localhost + IP:127.0.0.1,
/// EKU serverAuth). Returns (cert PEM, key PEM, cert DER).
fn generate_localhost_cert() -> Result<(String, String, Vec<u8>), CliErr> {
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
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let der = cert.der().as_ref().to_vec();
    Ok((cert_pem, key_pem, der))
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
    /// `--vault` must stay `None` so the pull falls back to this install's own id.
    #[test]
    fn backup_pull_takes_a_typed_vault_id() {
        let cli = Cli::try_parse_from([
            "hot_cheese",
            "backup",
            "pull",
            "--vault",
            "v_0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        ])
        .expect("backup pull --vault parses");
        let expected: VaultId = "v_0f1e2d3c4b5a69788796a5b4c3d2e1f0"
            .parse()
            .expect("fixture id parses");
        assert!(
            matches!(cli.command, Some(Commands::Backup(BackupCmd::Pull { vault })) if vault == Some(expected))
        );

        let cli = Cli::try_parse_from(["hot_cheese", "backup", "pull"]).expect("bare pull parses");
        assert!(matches!(
            cli.command,
            Some(Commands::Backup(BackupCmd::Pull { vault: None }))
        ));

        assert!(
            Cli::try_parse_from(["hot_cheese", "backup", "pull", "--vault", "nonsense"]).is_err()
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

        let cli = Cli::try_parse_from(["hot_cheese", "--unlock", "se", "sign"])
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
        assert_eq!(with, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(with, without);
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
        assert_eq!(decoded, raw);
    }

    #[test]
    fn bytes_passes_through_utf8() {
        let decoded = decode_secret(SecretKind::Bytes, "hello world").expect("utf8 passes through");
        assert_eq!(decoded, b"hello world".to_vec());
    }

    #[test]
    fn base64_decoder_matches_known_vector() {
        // "Man" -> "TWFu", "hot_cheese" -> base64 below.
        assert_eq!(b64_decode("TWFu"), Some(b"Man".to_vec()));
        assert_eq!(b64_decode("aG90X2NoZWVzZQ=="), Some(b"hot_cheese".to_vec()));
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
