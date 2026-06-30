//! Runtime configuration + on-disk locations.
//!
//! Replaces the old compile-time `include_bytes!("conf/cheese_config.json")` so the
//! store path, port, certs, and backup remotes can change without a rebuild.
use crate::server::resolve_path;
use err_mac::create_err_with_impls;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Legacy Keychain service name (used only by `migrate` to read the old master).
    pub service: String,
    /// Legacy Keychain account name (migration only).
    pub account: String,
    /// Directory holding the encrypted keystores + `keyring.json`.
    pub store: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub backup_remotes: Vec<BackupRemote>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupRemote {
    /// SSH target, e.g. "user@1.2.3.4".
    pub host: String,
    /// Remote folder under the home dir, e.g. "hot_cheese_store".
    pub folder: String,
}

create_err_with_impls!(
    #[derive(Debug)]
    pub ConfigErr,
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error),
    Envelope(crate::crypto::envelope::EnvErr)
    ;
);

/// `$HOT_CHEESE_HOME`, else `~/.config/hot_cheese`.
pub fn home_dir() -> PathBuf {
    if let Ok(h) = std::env::var("HOT_CHEESE_HOME") {
        return PathBuf::from(h);
    }
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h).join(".config").join("hot_cheese");
    }
    PathBuf::from(".hot_cheese")
}

pub fn config_path() -> PathBuf {
    home_dir().join("config.json")
}

/// (cert.pem, key.pem) under the home dir.
pub fn cert_paths() -> (PathBuf, PathBuf) {
    let h = home_dir();
    (h.join("ssl-cert.pem"), h.join("ssl-key.pem"))
}

impl Config {
    pub fn store_path(&self) -> PathBuf {
        resolve_path(&self.store)
    }
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(5555)
    }
    pub fn load() -> Result<Self, ConfigErr> {
        let bytes = std::fs::read(config_path())?;
        Ok(serde_json::from_slice(&bytes)?)
    }
    pub fn save(&self) -> Result<(), ConfigErr> {
        let json = serde_json::to_vec_pretty(self)?;
        let p = config_path();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::crypto::envelope::atomic_write(&p, &json)?;
        Ok(())
    }
}
