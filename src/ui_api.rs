//! Facade over the core for GUI front-ends (the Tauri menu-bar app).
//!
//! These functions return serde-friendly values and never prompt or print, so a GUI can
//! drive the same operations the CLI exposes. Secrets (passphrases) are passed in by the
//! caller — the GUI collects them via dialogs — rather than read from a TTY. Operations
//! that need the DEK build an [`Unlocker`] the same way the CLI does: prefer the Secure
//! Enclave if enrolled (Touch ID), else a supplied recovery passphrase.
use crate::backup;
use crate::config::{Config, ConfigErr};
use crate::crypto::envelope::EnvErr;
use crate::keyring::{EnrollParams, Keyring, KeyringErr};
use crate::mac::secure_enclave;
use crate::mac::MacBackend;
use crate::server::{is_valid_string_name, ApiBackendErr, HotApi};
use crate::unlock::{PassphraseUnlocker, SecureEnclaveUnlocker, UnlockErr, Unlocker};
use err_mac::create_err_with_impls;
use serde::Serialize;
use std::path::{Path, PathBuf};

create_err_with_impls!(
    #[derive(Debug)]
    pub UiErr,
    NotInitialized,
    PassphraseRequired,
    BadChain,
    Config(ConfigErr),
    Keyring(KeyringErr),
    Unlock(UnlockErr),
    ApiBackend(ApiBackendErr),
    Backup(backup::BackupErr),
    Se(secure_enclave::SeErr),
    Envelope(EnvErr)
    ;
);

#[derive(Serialize)]
pub struct EnrollmentInfo {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub created_at: u64,
}

/// Snapshot of the install for the dashboard.
#[derive(Serialize)]
pub struct Status {
    pub initialized: bool,
    pub store_path: String,
    pub key_count: usize,
    pub keys: Vec<String>,
    pub enrollments: Vec<EnrollmentInfo>,
    pub has_passphrase: bool,
    pub has_secure_enclave: bool,
    /// True when the INSECURE software-enclave demo backend is active.
    pub demo_software_enclave: bool,
    pub backup_remotes: usize,
}

fn keyring_path(cfg: &Config) -> PathBuf {
    MacBackend::keyring_path(&cfg.store)
}

fn list_key_files(store: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(store) {
        for entry in entries.flatten() {
            let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
            if !is_file {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                if name != "keyring.json" && is_valid_string_name(name) {
                    out.push(name.to_string());
                }
            }
        }
    }
    out.sort();
    out
}

/// Build an unlocker: prefer the Secure Enclave if any SE enrollment exists (Touch ID),
/// otherwise a recovery passphrase, which the caller must supply.
fn make_unlocker(keyring: &Keyring, passphrase: Option<String>) -> Result<Box<dyn Unlocker>, UiErr> {
    let has_se = keyring
        .enrollments
        .iter()
        .any(|e| matches!(e.params, EnrollParams::SecureEnclave { .. }));
    if has_se {
        Ok(Box::new(SecureEnclaveUnlocker::new(
            secure_enclave::SE_KEY_LABEL,
        )))
    } else if let Some(p) = passphrase {
        Ok(Box::new(PassphraseUnlocker::new(p)))
    } else {
        Err(UiErr::PassphraseRequired)
    }
}

fn load_cfg_keyring() -> Result<(Config, Keyring), UiErr> {
    let cfg = Config::load().map_err(|_| UiErr::NotInitialized)?;
    let kr = Keyring::load(&keyring_path(&cfg))?;
    Ok((cfg, kr))
}

fn maybe_backup(cfg: &Config) {
    if !cfg.backup_remotes.is_empty() {
        if let Err(e) = backup::push_all(cfg) {
            tracing::warn!(error = %e, "backup push after mutation failed");
        }
    }
}

/// Current state for the dashboard. Never errors — an uninitialized install reports
/// `initialized: false` so the GUI can guide the user to `hot_cheese init`.
pub fn status() -> Status {
    let demo = secure_enclave::software_enclave_enabled();
    let cfg = match Config::load() {
        Ok(c) => c,
        Err(_) => {
            return Status {
                initialized: false,
                store_path: String::new(),
                key_count: 0,
                keys: Vec::new(),
                enrollments: Vec::new(),
                has_passphrase: false,
                has_secure_enclave: false,
                demo_software_enclave: demo,
                backup_remotes: 0,
            }
        }
    };
    let store = cfg.store_path();
    let keys = list_key_files(&store);
    let mut enrollments = Vec::new();
    let mut has_passphrase = false;
    let mut has_secure_enclave = false;
    if let Ok(kr) = Keyring::load(&keyring_path(&cfg)) {
        for e in &kr.enrollments {
            let kind = match e.params {
                EnrollParams::SecureEnclave { .. } => {
                    has_secure_enclave = true;
                    "secure_enclave"
                }
                EnrollParams::Passphrase { .. } => {
                    has_passphrase = true;
                    "passphrase"
                }
            };
            enrollments.push(EnrollmentInfo {
                id: e.id.clone(),
                kind: kind.to_string(),
                label: e.label.clone(),
                created_at: e.created_at,
            });
        }
    }
    Status {
        initialized: true,
        store_path: store.display().to_string(),
        key_count: keys.len(),
        keys,
        enrollments,
        has_passphrase,
        has_secure_enclave,
        demo_software_enclave: demo,
        backup_remotes: cfg.backup_remotes.len(),
    }
}

pub fn list_keys() -> Result<Vec<String>, UiErr> {
    let cfg = Config::load().map_err(|_| UiErr::NotInitialized)?;
    Ok(list_key_files(&cfg.store_path()))
}

/// Generate a fresh key (`chain` = "evm" | "solana"). Triggers an unlock (Touch ID on the
/// Secure Enclave path) and a best-effort backup push.
pub fn generate(chain: &str, name: &str, passphrase: Option<String>) -> Result<(), UiErr> {
    let (cfg, kr) = load_cfg_keyring()?;
    let backend = MacBackend::new(&cfg.store, make_unlocker(&kr, passphrase)?)?;
    let api = HotApi::new(Box::new(backend));
    match chain {
        "evm" => api.generate(name)?,
        "solana" => api.generate_solana(name)?,
        _ => return Err(UiErr::BadChain),
    }
    maybe_backup(&cfg);
    Ok(())
}

/// Derive the public address of a stored key. Triggers an unlock (Touch ID on the SE path).
pub fn address(chain: &str, name: &str, passphrase: Option<String>) -> Result<String, UiErr> {
    let (cfg, kr) = load_cfg_keyring()?;
    let backend = MacBackend::new(&cfg.store, make_unlocker(&kr, passphrase)?)?;
    let api = HotApi::new(Box::new(backend));
    let addr = match chain {
        "evm" => api.address(name)?,
        "solana" => api.address_solana(name)?,
        _ => return Err(UiErr::BadChain),
    };
    Ok(addr)
}

/// Add a recovery passphrase enrollment (unlocks the DEK via an existing method first).
pub fn enroll_passphrase(
    new_passphrase: String,
    existing_passphrase: Option<String>,
) -> Result<(), UiErr> {
    let (cfg, mut kr) = load_cfg_keyring()?;
    let dek = make_unlocker(&kr, existing_passphrase)?.unlock("enroll passphrase", &kr)?;
    kr.add(PassphraseUnlocker::new(new_passphrase).enroll("recovery", &dek)?);
    kr.save(&keyring_path(&cfg))?;
    Ok(())
}

/// Enroll this machine's Secure Enclave key (unlocks the DEK via an existing method first).
pub fn enroll_secure_enclave(existing_passphrase: Option<String>) -> Result<(), UiErr> {
    let (cfg, mut kr) = load_cfg_keyring()?;
    secure_enclave::ensure_se_key(secure_enclave::SE_KEY_LABEL)?;
    let dek = make_unlocker(&kr, existing_passphrase)?.unlock("enroll secure enclave", &kr)?;
    kr.add(SecureEnclaveUnlocker::new(secure_enclave::SE_KEY_LABEL).enroll("secure-enclave", &dek)?);
    kr.save(&keyring_path(&cfg))?;
    Ok(())
}

pub fn backup_push() -> Result<(), UiErr> {
    let cfg = Config::load().map_err(|_| UiErr::NotInitialized)?;
    backup::push_all(&cfg)?;
    Ok(())
}

pub fn backup_pull() -> Result<(), UiErr> {
    let cfg = Config::load().map_err(|_| UiErr::NotInitialized)?;
    match cfg.backup_remotes.first() {
        Some(r) => {
            backup::pull(&cfg, r)?;
            Ok(())
        }
        None => Err(UiErr::Backup(backup::BackupErr::NoRemotes)),
    }
}
