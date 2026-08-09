//! The key core: the DEK envelope, the keyring, the Secure Enclave / passphrase unlockers,
//! and the on-disk locations they use. Synchronous and runtime-free, so it builds for iOS.
pub mod config;
pub mod crypto;
pub mod keyring;
pub mod mac;
pub mod unlock;
pub mod wire;

use std::path::PathBuf;

/// Expand a leading `~/` against `$HOME`; every other path is taken verbatim.
pub fn resolve_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home_dir) = std::env::var("HOME") {
            return PathBuf::from(home_dir).join(path.trim_start_matches("~/"));
        }
    }
    PathBuf::from(path)
}

/// Whether `name` is a legal keystore name: a non-empty `[A-Za-z0-9_]` string, which is what
/// every route, AAD and store listing relies on.
pub fn is_valid_string_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}
