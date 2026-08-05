//! A pre-evaluated `LAContext` reused across the sign flow so it prompts exactly once.
//!
//! `evaluate_biometric` runs one biometric evaluation and retains the resulting context.
//! Handing that same context (its raw pointer) to the Swift Secure Enclave ECDH bridge lets
//! the enclave key operation reuse the biometric — no second prompt.
use crate::mac::secure_enclave::SeErr;
use block::ConcreteBlock;
use dispatch::Semaphore;
use objc::rc::StrongPtr;
use objc::runtime::Object;
use objc::{class, msg_send, sel, sel_impl};
use std::ffi::CString;
use std::os::raw::c_long;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const TOUCH_ID_REUSE_SECS: f64 = 1.0;

/// A retained `LAContext` whose single biometric evaluation is reused for the SE key op.
pub struct LaContext {
    inner: StrongPtr,
}

impl LaContext {
    /// Evaluate `deviceOwnerAuthenticationWithBiometrics` once, blocking on the prompt.
    /// Retains the context for the brief [`TOUCH_ID_REUSE_SECS`] window so only the paired SE
    /// op reuses it — not an earlier device unlock or a prior sign.
    pub fn evaluate_biometric(reason: &str) -> Result<Self, SeErr> {
        let obj = unsafe {
            let obj: *mut Object = msg_send![class!(LAContext), alloc];
            let obj: *mut Object = msg_send![obj, init];
            StrongPtr::new(obj)
        };
        unsafe {
            let _: () =
                msg_send![*obj, setTouchIDAuthenticationAllowableReuseDuration: TOUCH_ID_REUSE_SECS];
        }
        let reason = CString::new(reason).map_err(|_| SeErr::TouchIdDenied)?;
        let localized_reason: *mut Object = unsafe {
            msg_send![class!(NSString), stringWithUTF8String: reason.as_ptr()]
        };

        let flag = Arc::new(AtomicBool::new(false));
        let flag_cb = Arc::clone(&flag);
        let sem = Semaphore::new(0);
        let sem_cb = sem.clone();
        let reply_block = ConcreteBlock::new(move |success: bool, _err: *mut Object| {
            flag_cb.store(success, Ordering::SeqCst);
            sem_cb.signal();
        });
        let reply_block = reply_block.copy();

        let policy: c_long = 1;
        unsafe {
            let _: () = msg_send![
                *obj,
                evaluatePolicy: policy
                localizedReason: localized_reason
                reply: &*reply_block
            ];
        }
        sem.wait();

        if flag.load(Ordering::SeqCst) {
            Ok(Self { inner: obj })
        } else {
            Err(SeErr::TouchIdDenied)
        }
    }

    /// Borrow the retained `LAContext` as a raw pointer for the Swift Secure Enclave bridge.
    pub fn as_raw_ptr(&self) -> *mut std::ffi::c_void {
        *self.inner as *mut std::ffi::c_void
    }
}
