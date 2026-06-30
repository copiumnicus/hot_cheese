//! Command-line interface (clap).
//!
//! Replaces the old `cargo run --example ...` + manual Keychain Access workflow with
//! first-class subcommands: init, enroll, add, generate, address, list, serve,
//! backup, migrate, bootstrap-from, bootstrap-serve.
//!
//! The DEK is never cached: every command that needs it builds an [`Unlocker`]
//! (Secure Enclave in production, recovery passphrase as the survivable backstop)
//! and unwraps the DEK for that single operation.
use crate::config::{cert_paths, config_path, home_dir, Config};
use crate::crypto::envelope::{encrypt_file, Dek};
use crate::keyring::{EnrollParams, Keyring};
use crate::mac::secure_enclave;
use crate::mac::{authorize_with_touch_id, get_password_from_keychain, MacBackend};
use crate::server::{is_valid_string_name, run_server, BackendImpl, HotApi};
use crate::unlock::{PassphraseUnlocker, SecureEnclaveUnlocker, Unlocker};
use crate::{backup, bootstrap, migrate};
use clap::{Parser, Subcommand};
use err_mac::create_err_with_impls;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::{Zeroize, Zeroizing};

/// Shared Secure Enclave key label. Every machine stores its device-bound SE key
/// under this label, so the SE unlocker always knows where to look.
const SE_LABEL: &str = crate::mac::secure_enclave::SE_KEY_LABEL;

// Defaults baked into a fresh `config.json` on `init`.
const DEFAULT_SERVICE: &str = "com.cc.hot_cheese";
const DEFAULT_ACCOUNT: &str = "hot_cheese_master";
const DEFAULT_STORE: &str = "~/.config/hot_cheese/store";

// Variants in source order: PassphraseMismatch (prompt confirmation differed),
// AlreadyInitialized (`init` without `--force`), CertKeyPairRequired (one of
// --import-cert/--import-key supplied), NoBackupRemote (pull/push with none set),
// then `#[from]` wrappers for each module error this CLI touches.
create_err_with_impls!(
    #[derive(Debug)]
    pub CliErr,
    PassphraseMismatch,
    AlreadyInitialized,
    CertKeyPairRequired,
    NoBackupRemote,
    TouchIdDenied,
    Config(crate::config::ConfigErr),
    Keyring(crate::keyring::KeyringErr),
    Unlock(crate::unlock::UnlockErr),
    Envelope(crate::crypto::envelope::EnvErr),
    ApiBackend(crate::server::ApiBackendErr),
    Backup(crate::backup::BackupErr),
    Migrate(crate::migrate::MigrateErr),
    Bootstrap(crate::bootstrap::BootstrapErr),
    GetPassword(crate::mac::GetPasswordErr),
    Se(crate::mac::secure_enclave::SeErr),
    Rcgen(rcgen::Error),
    StdIo(std::io::Error)
    ;
);

#[derive(Parser, Debug)]
#[command(
    name = "hot_cheese",
    about = "macOS key daemon: envelope-encrypted EVM/Solana keystores unlocked per request via Secure Enclave (Touch ID) or a recovery passphrase.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
    },
    /// Generate a fresh key under `name`.
    Generate {
        /// Chain the key is for.
        chain: Chain,
        /// Keystore name (a-z, A-Z, 0-9, _).
        name: String,
    },
    /// Print the public address of a stored key.
    Address {
        /// Chain to derive the address for.
        chain: Chain,
        /// Keystore name.
        name: String,
    },
    /// List stored keystores and keyring enrollments.
    List,
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
    },
    /// Bootstrap this machine's DEK + store from an authority machine over SSH.
    BootstrapFrom {
        /// SSH target, e.g. user@host.
        target: String,
    },
    /// Authority side of the SSH bootstrap (invoked remotely over SSH).
    #[command(hide = true)]
    BootstrapServe,
    /// Validate the Secure Enclave path on a code-signed binary (prompts Touch ID).
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
}

#[derive(Subcommand, Debug)]
enum BackupCmd {
    /// Push the store to every configured remote.
    Push,
    /// Pull the store from the first configured remote.
    Pull,
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

/// Parse args and dispatch; returns a process exit code.
pub fn run() -> ExitCode {
    // Default to INFO; let RUST_LOG override the max level (the `env-filter`
    // subscriber feature isn't enabled, so map the level by hand).
    tracing_subscriber::fmt()
        .with_max_level(env_log_level())
        .init();

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

    match dispatch(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "command failed");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Commands) -> Result<(), CliErr> {
    match command {
        Commands::Init {
            import_cert,
            import_key,
            force,
        } => cmd_init(import_cert, import_key, force),
        Commands::Enroll(cmd) => cmd_enroll(cmd),
        Commands::Add { name, kind } => cmd_add(&name, kind),
        Commands::Generate { chain, name } => cmd_generate(chain, &name),
        Commands::Address { chain, name } => cmd_address(chain, &name),
        Commands::List => cmd_list(),
        Commands::Serve => cmd_serve(),
        Commands::Backup(cmd) => cmd_backup(cmd),
        Commands::Migrate {
            old_store,
            new_store,
        } => cmd_migrate(&old_store, &new_store),
        Commands::BootstrapFrom { target } => Ok(bootstrap::bootstrap_from(&target)?),
        Commands::BootstrapServe => Ok(bootstrap::bootstrap_serve()?),
        Commands::SeSelftest => cmd_se_selftest(),
    }
}

/// Validate the Secure Enclave path end-to-end on a code-signed binary (prompts Touch ID).
/// Uses a throwaway key label so the real unlock key is never touched.
fn cmd_se_selftest() -> Result<(), CliErr> {
    const SELFTEST_LABEL: &str = "hotcheese.se.selftest";
    secure_enclave::selftest(SELFTEST_LABEL)?;
    tracing::info!(
        "Secure Enclave self-test PASSED — Touch ID gating, ECDH determinism, and SE/host \
         ECDH equivalence all hold; the SE unlock path is ready (`hot_cheese enroll se`)."
    );
    Ok(())
}

/// Build the right [`Unlocker`] for this keyring: prefer the Secure Enclave key if any
/// SE enrollment exists, otherwise fall back to a recovery passphrase prompt.
fn make_unlocker(keyring: &Keyring) -> Result<Box<dyn Unlocker>, CliErr> {
    let has_se = keyring
        .enrollments
        .iter()
        .any(|e| matches!(e.params, EnrollParams::SecureEnclave { .. }));
    if has_se {
        Ok(Box::new(SecureEnclaveUnlocker::new(SE_LABEL)))
    } else {
        let pass = prompt_passphrase("Recovery passphrase: ")?;
        Ok(Box::new(PassphraseUnlocker::new(pass)))
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

/// Load `config.json`, then load `<store>/keyring.json`.
fn load_config_and_keyring() -> Result<(Config, Keyring), CliErr> {
    let config = Config::load()?;
    let keyring = Keyring::load(&keyring_file(&config))?;
    Ok((config, keyring))
}

/// `<store>/keyring.json`.
fn keyring_file(config: &Config) -> PathBuf {
    config.store_path().join("keyring.json")
}

fn cmd_init(
    import_cert: Option<PathBuf>,
    import_key: Option<PathBuf>,
    force: bool,
) -> Result<(), CliErr> {
    if config_path().exists() && !force {
        return Err(CliErr::AlreadyInitialized);
    }

    // Home dir holds config.json + the TLS cert/key.
    let home = home_dir();
    std::fs::create_dir_all(&home)?;

    // Materialize the default config so we know where the store lives.
    let config = Config {
        service: DEFAULT_SERVICE.to_string(),
        account: DEFAULT_ACCOUNT.to_string(),
        store: DEFAULT_STORE.to_string(),
        port: None,
        backup_remotes: Vec::new(),
    };
    let store = config.store_path();
    std::fs::create_dir_all(&store)?;

    // TLS cert: import the supplied pair, or mint a self-signed localhost cert.
    let (cert_path, key_path) = cert_paths();
    let cert_der = match (import_cert, import_key) {
        (Some(c), Some(k)) => {
            std::fs::copy(&c, &cert_path)?;
            std::fs::copy(&k, &key_path)?;
            der_from_cert_pem(&cert_path)?
        }
        (None, None) => {
            let (cert_pem, key_pem, der) = generate_localhost_cert()?;
            std::fs::write(&cert_path, cert_pem)?;
            std::fs::write(&key_path, key_pem)?;
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
    keyring.add(enrollment);
    keyring.save(&keyring_file(&config))?;

    // Persist config last, once the store + keyring are in place.
    config.save()?;

    let fingerprint = sha256_hex(&cert_der);
    tracing::info!(home = %home.display(), store = %store.display(), "initialized hot_cheese");
    tracing::info!(cert = %cert_path.display(), "TLS certificate written");
    tracing::info!(sha256 = %fingerprint, "certificate fingerprint (pin this on the client)");
    Ok(())
}

fn cmd_enroll(cmd: EnrollCmd) -> Result<(), CliErr> {
    let (config, mut keyring) = load_config_and_keyring()?;
    // Obtain the existing DEK via whatever enrollment already works.
    let unlocker = make_unlocker(&keyring)?;
    let dek = unlocker.unlock("enroll a new unlock method", &keyring)?;

    let enrollment = match cmd {
        EnrollCmd::Se { label } => {
            if let Err(e) = secure_enclave::ensure_se_key(SE_LABEL) {
                tracing::warn!(
                    "Secure Enclave is unavailable (this binary may be unsigned). \
                     SE enrollment needs a code-signed build with SE entitlements. \
                     Use a recovery passphrase in the meantime."
                );
                return Err(e.into());
            }
            match SecureEnclaveUnlocker::new(SE_LABEL).enroll(&label, &dek) {
                Ok(e) => e,
                Err(crate::unlock::UnlockErr::Unsupported) => {
                    tracing::warn!(
                        "Secure Enclave enrollment is unsupported on this binary \
                         (unsigned build). Re-run on a code-signed binary, or enroll a passphrase."
                    );
                    return Err(crate::unlock::UnlockErr::Unsupported.into());
                }
                Err(e) => return Err(e.into()),
            }
        }
        EnrollCmd::Passphrase { label } => {
            let pass = prompt_new_passphrase()?;
            PassphraseUnlocker::new(pass).enroll(&label, &dek)?
        }
    };

    let id = enrollment.id.clone();
    keyring.add(enrollment);
    keyring.save(&keyring_file(&config))?;
    tracing::info!(enrollment = %id, "added enrollment");
    Ok(())
}

fn cmd_add(name: &str, kind: SecretKind) -> Result<(), CliErr> {
    let config = Config::load()?;
    if !is_valid_string_name(name) {
        tracing::error!(%name, "invalid key name: only a-z, A-Z, 0-9, _ are allowed");
        return Err(CliErr::ApiBackend(crate::server::ApiBackendErr::KeyExists));
    }
    let store = config.store_path();
    if store.join(name).exists() {
        tracing::error!(%name, "key already exists");
        return Err(CliErr::ApiBackend(crate::server::ApiBackendErr::KeyExists));
    }

    // Read + decode the secret, then zeroize the decoded bytes after encryption.
    let mut secret = read_secret(kind)?;

    let keyring = Keyring::load(&keyring_file(&config))?;
    let unlocker = make_unlocker(&keyring)?;
    let backend = MacBackend::new(&config.store, unlocker)?;
    let dek = backend.unlock_dek("import key")?;
    let result = encrypt_file(&backend.store_path(), name, &dek, &secret);
    secret.zeroize();
    result?;
    tracing::info!(%name, "imported key");

    best_effort_backup_push(&config);
    Ok(())
}

fn cmd_generate(chain: Chain, name: &str) -> Result<(), CliErr> {
    let (config, keyring) = load_config_and_keyring()?;
    let unlocker = make_unlocker(&keyring)?;
    let backend = MacBackend::new(&config.store, unlocker)?;
    let api = HotApi::new(Box::new(backend));
    match chain {
        Chain::Evm => api.generate(name)?,
        Chain::Solana => api.generate_solana(name)?,
    }
    tracing::info!(%name, ?chain, "generated key");
    best_effort_backup_push(&config);
    Ok(())
}

fn cmd_address(chain: Chain, name: &str) -> Result<(), CliErr> {
    let (config, keyring) = load_config_and_keyring()?;
    let unlocker = make_unlocker(&keyring)?;
    let backend = MacBackend::new(&config.store, unlocker)?;
    let api = HotApi::new(Box::new(backend));
    let addr = match chain {
        Chain::Evm => api.address(name)?,
        Chain::Solana => api.address_solana(name)?,
    };
    tracing::info!(%name, %addr, "address");
    Ok(())
}

fn cmd_list() -> Result<(), CliErr> {
    let (config, keyring) = load_config_and_keyring()?;
    let store = config.store_path();

    tracing::info!(store = %store.display(), "keystores");
    if let Ok(entries) = std::fs::read_dir(&store) {
        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            // Skip the keyring envelope itself; only list actual keystores.
            if name == "keyring.json" {
                continue;
            }
            if entry.file_type()?.is_file() {
                tracing::info!(key = %name, "  keystore");
            }
        }
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

fn cmd_serve() -> Result<(), CliErr> {
    let config = Config::load()?;

    // Bootstrap-from-backup: if the store is empty and a remote is configured, pull first.
    if backup::store_absent(&config.store_path()) {
        if let Some(remote) = config.backup_remotes.first() {
            tracing::info!(host = %remote.host, "store empty; pulling from backup remote");
            backup::pull(&config, remote)?;
        }
    }

    let keyring = Keyring::load(&keyring_file(&config))?;
    let unlocker = make_unlocker(&keyring)?;
    let backend = MacBackend::new(&config.store, unlocker)?;
    if let Err(e) = run_server(Box::new(backend), config) {
        // run_server returns a boxed dyn Error; surface it without losing the message.
        tracing::error!(error = %e, "server exited with error");
        return Err(CliErr::StdIo(std::io::Error::other(e.to_string())));
    }
    Ok(())
}

fn cmd_backup(cmd: BackupCmd) -> Result<(), CliErr> {
    let config = Config::load()?;
    match cmd {
        BackupCmd::Push => {
            backup::push_all(&config)?;
            tracing::info!("pushed store to all remotes");
        }
        BackupCmd::Pull => {
            let remote = config
                .backup_remotes
                .first()
                .ok_or(CliErr::NoBackupRemote)?;
            backup::pull(&config, remote)?;
            tracing::info!(host = %remote.host, "pulled store from remote");
        }
    }
    Ok(())
}

fn cmd_migrate(old_store: &Path, new_store: &Path) -> Result<(), CliErr> {
    let (config, keyring) = load_config_and_keyring()?;

    // The legacy master lives in the login Keychain behind Touch ID.
    if !authorize_with_touch_id("migrate keys") {
        tracing::error!("Touch ID authorization was denied; migration aborted");
        return Err(CliErr::TouchIdDenied);
    }
    // Zeroizing so the legacy master is wiped on every exit path, including early `?` returns.
    let old_master = Zeroizing::new(get_password_from_keychain(
        &config.service,
        &config.account,
    )?);

    // Unlock the new DEK that the migrated keys will be re-encrypted under.
    let unlocker = make_unlocker(&keyring)?;
    let dek = unlocker.unlock("migrate keys", &keyring)?;

    let migrated = migrate::run(old_store, &old_master, new_store, &dek)?;

    tracing::info!(count = migrated.len(), "migration complete");
    for k in &migrated {
        tracing::info!(name = %k.name, identity = %k.identity, "  migrated");
    }
    best_effort_backup_push(&config);
    Ok(())
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

/// Max tracing level from `RUST_LOG` (case-insensitive level word), defaulting to INFO.
fn env_log_level() -> tracing::Level {
    match std::env::var("RUST_LOG").ok().as_deref() {
        Some(v) if v.eq_ignore_ascii_case("trace") => tracing::Level::TRACE,
        Some(v) if v.eq_ignore_ascii_case("debug") => tracing::Level::DEBUG,
        Some(v) if v.eq_ignore_ascii_case("warn") => tracing::Level::WARN,
        Some(v) if v.eq_ignore_ascii_case("error") => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    }
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
            Commands::Add { name, kind } => {
                assert_eq!(name, "MY_KEY");
                assert_eq!(kind, SecretKind::Ethereum);
            }
            other => panic!("expected Add, got {:?}", other),
        }
    }

    #[test]
    fn parses_generate_chain_then_name() {
        let cli = Cli::try_parse_from(["hot_cheese", "generate", "solana", "trader"])
            .expect("generate should parse");
        match cli.command {
            Commands::Generate { chain, name } => {
                assert_eq!(chain, Chain::Solana);
                assert_eq!(name, "trader");
            }
            other => panic!("expected Generate, got {:?}", other),
        }
    }

    #[test]
    fn parses_enroll_se_with_label() {
        let cli = Cli::try_parse_from(["hot_cheese", "enroll", "se", "--label", "macbook"])
            .expect("enroll se should parse");
        match cli.command {
            Commands::Enroll(EnrollCmd::Se { label }) => assert_eq!(label, "macbook"),
            other => panic!("expected Enroll Se, got {:?}", other),
        }
    }

    #[test]
    fn bootstrap_serve_is_hidden_but_parses() {
        let cli = Cli::try_parse_from(["hot_cheese", "bootstrap-serve"])
            .expect("bootstrap-serve should parse");
        assert!(matches!(cli.command, Commands::BootstrapServe));
    }

    #[test]
    fn invalid_chain_is_rejected() {
        assert!(Cli::try_parse_from(["hot_cheese", "generate", "dogecoin", "x"]).is_err());
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
