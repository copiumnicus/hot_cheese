use crate::crypto::envelope::Dek;
use crate::keyring::{Keyring, KeyringErr};
use crate::resolve_path;
use crate::unlock::{UnlockErr, Unlocker};
use std::fs::create_dir_all;
use std::path::PathBuf;

mod get_password;
pub mod local_auth;
pub mod secure_enclave;
mod touch_id;

use local_auth::LaContext;

// Exposed for the one-time migration path (reads the legacy Keychain master).
pub use get_password::{get_password_from_keychain, GetPasswordErr};
pub use touch_id::authorize_with_touch_id;

/// The backend supplies the Data Encryption Key (per request) and the store location.
/// Unlocking is where the Touch ID / Secure Enclave gate lives now — see `unlock_dek`.
pub trait BackendImpl: Send + Sync {
    /// Unwrap the DEK for a single operation. `reason` is surfaced to the user
    /// (e.g. the biometric prompt). A pre-evaluated `auth` context (when `Some`) is
    /// reused so the SE op doesn't prompt again. The returned DEK is zeroized when dropped.
    fn unlock_dek(&self, reason: &str, auth: Option<&LaContext>) -> Result<Dek, UnlockErr>;
    fn store(&self) -> &str;

    fn store_path(&self) -> PathBuf {
        let buf = resolve_path(self.store());
        if !buf.exists() {
            if let Err(e) = create_dir_all(buf.clone()) {
                tracing::error!(error = %e, "failed to create keys dir");
            }
        }
        buf
    }
}

/// The macOS backend: holds the loaded keyring and an [`Unlocker`] (Secure Enclave
/// in production, passphrase as the recovery backstop). The DEK is unwrapped
/// per request and never cached.
pub struct MacBackend {
    store: String,
    unlocker: Box<dyn Unlocker>,
    keyring: Keyring,
}

impl MacBackend {
    /// Bind an unlocker and load the keyring from `<store>/keyring.json`.
    pub fn new(store: &str, unlocker: Box<dyn Unlocker>) -> Result<Self, KeyringErr> {
        let keyring = Keyring::load(&Self::keyring_path(store))?;
        Ok(Self {
            store: store.into(),
            unlocker,
            keyring,
        })
    }

    pub fn keyring_path(store: &str) -> PathBuf {
        resolve_path(store).join("keyring.json")
    }
}

impl BackendImpl for MacBackend {
    fn unlock_dek(&self, reason: &str, auth: Option<&LaContext>) -> Result<Dek, UnlockErr> {
        self.unlocker.unlock(reason, &self.keyring, auth)
    }
    fn store(&self) -> &str {
        &self.store
    }
}
