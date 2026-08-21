//! The `Unlocker` seam: obtain the DEK from an enrolled KEK source, per request.
//!
//! This replaces the old "Touch ID gate + Keychain master password" split. The
//! biometric is now cryptographically load-bearing: with the Secure Enclave
//! unlocker, no Touch ID means no ECDH means no KEK means no DEK.
//!
//! Every enrollment unwraps the SAME DEK, so no enclave failure can strand an operator whose
//! keys are fine: an absent key is [`UnlockErr::SeKeyUnavailableTryUnlockPassphrase`], an enclave
//! that refuses the key it has — an added or removed fingerprint invalidates
//! `.biometryCurrentSet`, and the blob stays put and stops working — is
//! [`UnlockErr::SeKeyUnusableTryUnlockPassphrase`], and every one of them says the same thing:
//! re-run with `--unlock passphrase` and the DEK comes out of the recovery enrollment.
//!
//! Naming that route everywhere is safe because it re-enrolls nothing. Re-enrolling is the
//! dangerous advice, since it is what would wrap this vault's DEK under a key it cannot prove is
//! its own, so [`UnlockErr::SeKeyPresentButUnprovenTryUnlockPassphraseDoNotReenroll`] carries the
//! passphrase route AND refuses to point at a re-enrollment.
use crate::crypto::envelope::Dek;
use crate::keyring::Keyring;
use crate::mac::local_auth::LaContext;
use err_mac::create_err_with_impls;

pub mod pass;
pub mod se;

pub use pass::PassphraseUnlocker;
pub use se::{enroll_secure_enclave, SecureEnclaveUnlocker};

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
    PassphraseTooShort { found: usize, min: usize },
    PassphraseTooLong { found: usize, max: usize },
    PassphraseTooSimple { distinct: usize, min: usize },
    SeKeyUnusableTryUnlockPassphrase { source: crate::mac::secure_enclave::SeErr },
    SeKeyPresentButUnprovenTryUnlockPassphraseDoNotReenroll {
        source: crate::mac::secure_enclave::SeErr
    }
);

/// A KEK source that unwraps (unlocks) the DEK. Wrapping is not part of this seam: the Secure
/// Enclave direction takes a [`crate::mac::secure_enclave::ProvenEnclaveKey`]
/// ([`enroll_secure_enclave`]) that no trait object can conjure, which is what keeps an
/// enrollment on the key this install proved rather than on whatever the blob path holds next.
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
}
