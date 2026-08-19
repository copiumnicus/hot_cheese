//! A pre-evaluated `LAContext` reused across the sign flow so it prompts exactly once.
//!
//! `evaluate_biometric` runs one biometric evaluation and retains the resulting context.
//! Handing that same context (its raw pointer) to the Swift Secure Enclave ECDH bridge lets
//! the enclave key operation reuse the biometric — no second prompt.
use crate::mac::secure_enclave::SeErr;
use std::ffi::CString;
use std::ffi::{c_char, c_void};
use std::ptr::NonNull;

/// `touchIDAuthenticationAllowableReuseDuration`: seconds during which a Touch ID match already
/// made on this Mac satisfies a further one. It is an OPT-IN to reuse — the platform default is
/// 0, no reuse — and it applies both to this context's own evaluation and to the enclave
/// operations it then authorises. One `/sign` spends it on two enclave operations (the grant
/// ECDSA signature and the KEK ECDH), which is what makes a payload cost exactly one Touch ID;
/// [`crate::mac::secure_enclave::selftest`] fails the whole self-test if that pair does not fit.
/// It is also the window in which an unrelated Touch ID (a device unlock, the previous request)
/// can stand in for this one, so it stays as short as that pair allows.
pub(crate) const TOUCH_ID_REUSE_SECS: f64 = 1.0;

/// A retained `LAContext` whose single biometric evaluation is reused for the SE key op.
pub struct LaContext {
    // `NonNull<c_void>` deliberately keeps this type !Send/!Sync: the request thread that
    // evaluated LocalAuthentication owns and consumes the context before dropping it.
    inner: NonNull<c_void>,
}

extern "C" {
    fn hc_la_evaluate(reason: *const c_char, reuse_seconds: f64) -> *mut c_void;
    fn hc_la_release(context: *mut c_void);
}

impl LaContext {
    /// Evaluate `deviceOwnerAuthenticationWithBiometrics` once and retain the context, so the
    /// enclave operations handed this context do not prompt again. Blocks on a Touch ID sheet
    /// unless a match made within the last [`TOUCH_ID_REUSE_SECS`] already satisfies the policy.
    pub fn evaluate_biometric(reason: &str) -> Result<Self, SeErr> {
        let reason = CString::new(reason).map_err(|_| SeErr::TouchIdDenied)?;
        // SAFETY: the pointer is a valid NUL-terminated string for the duration of the call. On
        // success Swift returns a +1 retained LAContext, balanced by this type's Drop.
        let inner = unsafe { hc_la_evaluate(reason.as_ptr(), TOUCH_ID_REUSE_SECS) };
        NonNull::new(inner)
            .map(|inner| Self { inner })
            .ok_or(SeErr::TouchIdDenied)
    }

    /// Borrow the retained `LAContext` as a raw pointer for the Swift Secure Enclave bridge.
    pub fn as_raw_ptr(&self) -> *mut std::ffi::c_void {
        self.inner.as_ptr()
    }
}

impl Drop for LaContext {
    fn drop(&mut self) {
        // SAFETY: `inner` is the unique +1 retain returned by `hc_la_evaluate`, and Drop runs
        // exactly once.
        unsafe { hc_la_release(self.inner.as_ptr()) }
    }
}
