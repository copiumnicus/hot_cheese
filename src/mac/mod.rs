use crate::crypto::envelope::Dek;
use crate::keyring::{Keyring, KeyringErr};
use crate::server::{resolve_path, ApiBackendErr, BackendImpl};
use crate::unlock::Unlocker;
use std::path::PathBuf;

mod get_password;
pub mod secure_enclave;
mod touch_id;

// Exposed for the one-time migration path (reads the legacy Keychain master).
pub use get_password::{get_password_from_keychain, GetPasswordErr};
pub use touch_id::authorize_with_touch_id;

/// The macOS backend: holds the loaded keyring and an [`Unlocker`] (Secure Enclave
/// in production, passphrase as the recovery/unsigned path). The DEK is unwrapped
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
    fn unlock_dek(&self, reason: &str) -> Result<Dek, ApiBackendErr> {
        Ok(self.unlocker.unlock(reason, &self.keyring)?)
    }
    fn store(&self) -> &str {
        &self.store
    }
    fn communicate_err(&self, e: String) {
        tracing::error!("{e}");
    }
}
