//! Runtime configuration + on-disk locations.
//!
//! Replaces the old compile-time `include_bytes!("conf/cheese_config.json")` so the
//! store path, port, certs, and backup remotes can change without a rebuild.
use crate::resolve_path;
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
    /// Uncompressed SEC1 hex (65 bytes) of the Secure Enclave grant key `serve` must find.
    #[serde(default)]
    pub grant_public_key: Option<String>,
    /// Seconds `bundle watch` waits between polls.
    #[serde(default)]
    pub bundle_watch_secs: Option<u64>,
    #[serde(default)]
    pub backup_remotes: Vec<BackupRemote>,
    /// Out-of-process signing adapters this machine trusts.
    #[serde(default)]
    pub adapters: Vec<AdapterPin>,
    /// Tailnet machines this install syncs `bundles/` with.
    #[serde(default)]
    pub bundle_peers: Vec<BundlePeer>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupRemote {
    /// SSH target, e.g. "user@1.2.3.4".
    pub host: String,
    /// Remote folder under the home dir, e.g. "hot_cheese_store".
    pub folder: String,
}

/// Where a peer keeps its bundles when `config.toml` does not say otherwise.
const DEFAULT_PEER_BUNDLES_DIR: &str = ".config/hot_cheese/bundles";

/// One tailnet machine this install exchanges Safe bundles with over rsync-on-ssh.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BundlePeer {
    /// SSH target: the peer's MagicDNS name, optionally `user@`-prefixed.
    pub host: String,
    /// The peer's bundles dir; a relative path resolves against its home dir.
    #[serde(default)]
    pub dir: Option<String>,
}

impl BundlePeer {
    pub fn dir(&self) -> &str {
        self.dir.as_deref().unwrap_or(DEFAULT_PEER_BUNDLES_DIR)
    }
    /// The ssh target without any `user@` prefix, which is what the tailnet knows it as.
    pub fn name(&self) -> &str {
        match self.host.split_once('@') {
            Some((_, host)) => host,
            None => &self.host,
        }
    }
}

/// One trusted adapter: which manifest, and the exact bytes that manifest must be.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdapterPin {
    /// Adapter id: names its manifest, its socket, and the provenance on the approval prompt.
    pub id: String,
    /// Manifest path; a relative one resolves under the home dir.
    pub manifest: String,
    /// SHA-256 hex the manifest bytes must hash to before they are parsed.
    pub sha256: String,
}

impl AdapterPin {
    pub fn manifest_path(&self) -> PathBuf {
        let path = resolve_path(&self.manifest);
        if path.is_absolute() {
            return path;
        }
        home_dir().join(path)
    }
}

create_err_with_impls!(
    #[derive(Debug)]
    pub ConfigErr,
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error),
    Toml(toml::de::Error),
    TomlSer(toml::ser::Error),
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
    home_dir().join("config.toml")
}

/// `<home>/adapters`: adapter manifests and their sockets. Deliberately outside the store, so
/// adapter trust is per-machine and never travels with a backup or an SSH bootstrap.
pub fn adapters_dir() -> PathBuf {
    home_dir().join("adapters")
}

/// `<home>/adapters/<id>.sock`, the one socket that carries adapter `id`'s provenance.
pub fn adapter_socket(id: &str) -> PathBuf {
    adapters_dir().join(format!("{id}.sock"))
}

/// `<home>/bundles`: `safes.toml` and one directory per SafeTx being collected. Deliberately
/// outside the store, which backup replicates per vault: two machines hold deliberately
/// different signer keys, and a bundle — public fields plus signatures over a public digest —
/// must never ride the path that carries key material.
pub fn bundles_dir() -> PathBuf {
    home_dir().join("bundles")
}

/// `<home>/bundle-quarantine`: where a file a peer pushed goes when it fails verification.
/// Outside `bundles/` on purpose, so nothing quarantined is ever synced back out.
pub fn bundle_quarantine_dir() -> PathBuf {
    home_dir().join("bundle-quarantine")
}

/// (cert.pem, key.pem) under the home dir.
pub fn cert_paths() -> (PathBuf, PathBuf) {
    let h = home_dir();
    (h.join("ssl-cert.pem"), h.join("ssl-key.pem"))
}

/// Max tracing level from `RUST_LOG` (case-insensitive level word), defaulting to INFO.
pub fn env_log_level() -> tracing::Level {
    match std::env::var("RUST_LOG").ok().as_deref() {
        Some(v) if v.eq_ignore_ascii_case("trace") => tracing::Level::TRACE,
        Some(v) if v.eq_ignore_ascii_case("debug") => tracing::Level::DEBUG,
        Some(v) if v.eq_ignore_ascii_case("warn") => tracing::Level::WARN,
        Some(v) if v.eq_ignore_ascii_case("error") => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    }
}

impl Config {
    pub fn store_path(&self) -> PathBuf {
        resolve_path(&self.store)
    }
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(5555)
    }
    pub fn bundle_watch_secs(&self) -> u64 {
        self.bundle_watch_secs.unwrap_or(15)
    }
    pub fn load() -> Result<Self, ConfigErr> {
        let path = config_path();
        if !path.exists() {
            let legacy = home_dir().join("config.json");
            if legacy.exists() {
                let cfg: Config = serde_json::from_slice(&std::fs::read(&legacy)?)?;
                cfg.save()?;
                std::fs::remove_file(&legacy)?;
                return Ok(cfg);
            }
        }
        Ok(toml::from_str(&std::fs::read_to_string(&path)?)?)
    }
    /// A config for tests that build a `HotApi` directly: the store, plus the P-256 base
    /// point standing in for a pinned grant key so the sign path reaches its approver (no
    /// test owns an enclave, so none of them reaches the mint that key would answer).
    #[cfg(any(test, feature = "test-util"))]
    pub fn for_test(store: &str) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            service: String::new(),
            account: String::new(),
            store: store.to_string(),
            port: None,
            grant_public_key: Some(
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
                    .to_string(),
            ),
            bundle_watch_secs: None,
            backup_remotes: Vec::new(),
            adapters: Vec::new(),
            bundle_peers: Vec::new(),
        })
    }
    pub fn save(&self) -> Result<(), ConfigErr> {
        let text = toml::to_string_pretty(self)?;
        let p = config_path();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::crypto::envelope::atomic_write(&p, text.as_bytes())?;
        Ok(())
    }
}
