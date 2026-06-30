//! The `Unlocker` seam: obtain the DEK from an enrolled KEK source, per request.
//!
//! This replaces the old "Touch ID gate + Keychain master password" split. The
//! biometric is now cryptographically load-bearing: with the Secure Enclave
//! unlocker, no Touch ID means no ECDH means no KEK means no DEK.
use crate::crypto::envelope::Dek;
use crate::keyring::{Enrollment, Keyring};
use err_mac::create_err_with_impls;

pub mod pass;
pub mod se;

pub use pass::PassphraseUnlocker;
pub use se::SecureEnclaveUnlocker;

create_err_with_impls!(
    #[derive(Debug)]
    pub UnlockErr,
    NoMatchingEnrollment,
    WrongPassphrase,
    Unsupported,
    BadDekLen,
    Envelope(crate::crypto::envelope::EnvErr),
    Argon2(argon2::Error),
    Se(crate::mac::secure_enclave::SeErr)
    ;
);

/// A KEK source that can wrap (enroll) and unwrap (unlock) the DEK.
pub trait Unlocker: Send + Sync {
    /// Unwrap the DEK. For Secure Enclave this triggers Touch ID — the per-request gate.
    /// `reason` is surfaced to the user (e.g. in the biometric prompt).
    fn unlock(&self, reason: &str, keyring: &Keyring) -> Result<Dek, UnlockErr>;
    /// Wrap an existing DEK under this KEK, producing an enrollment record to add to the keyring.
    fn enroll(&self, label: &str, dek: &Dek) -> Result<Enrollment, UnlockErr>;
}
