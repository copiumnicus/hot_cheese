//! The `Unlocker` seam: obtain the DEK from an enrolled KEK source, per request.
//!
//! This replaces the old "Touch ID gate + Keychain master password" split. The
//! biometric is now cryptographically load-bearing: with the Secure Enclave
//! unlocker, no Touch ID means no ECDH means no KEK means no DEK.
//!
//! Every enrollment unwraps the SAME DEK, so a machine whose Secure Enclave key is gone
//! (blob deleted, or the `.biometryCurrentSet` ACL invalidated by a Touch ID re-enrollment)
//! is not bricked: [`UnlockErr::SeKeyUnavailableTryUnlockPassphrase`] tells the operator to
//! re-run the command with `--unlock passphrase`, which unwraps the DEK from the recovery
//! enrollment instead.
use crate::crypto::envelope::Dek;
use crate::keyring::{Enrollment, Keyring};
use crate::mac::local_auth::LaContext;
use err_mac::create_err_with_impls;

pub mod pass;
pub mod se;

pub use pass::PassphraseUnlocker;
pub use se::SecureEnclaveUnlocker;

create_err_with_impls!(
    #[derive(Debug)]
    pub UnlockErr,
    NoMatchingEnrollment,
    SeKeyUnavailableTryUnlockPassphrase,
    WrongPassphrase,
    BadDekLen,
    Envelope(crate::crypto::envelope::EnvErr),
    Argon2(argon2::Error),
    Se(crate::mac::secure_enclave::SeErr)
    ;
);

/// A KEK source that can wrap (enroll) and unwrap (unlock) the DEK.
pub trait Unlocker: Send + Sync {
    /// Unwrap the DEK. For Secure Enclave this triggers Touch ID — the per-request gate.
    /// `reason` is surfaced to the user (e.g. in the biometric prompt). A pre-evaluated
    /// `auth` context (when `Some`) is reused so the SE op doesn't prompt a second time.
    fn unlock(
        &self,
        reason: &str,
        keyring: &Keyring,
        auth: Option<&LaContext>,
    ) -> Result<Dek, UnlockErr>;
    /// Wrap an existing DEK under this KEK, producing an enrollment record to add to the keyring.
    fn enroll(&self, label: &str, dek: &Dek) -> Result<Enrollment, UnlockErr>;
}
