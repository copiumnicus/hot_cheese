use err_mac::create_err_with_impls;
use std::{
    ffi::{c_char, c_int, c_void, CString, NulError},
    ptr,
};
use zeroize::Zeroizing;

#[repr(C)]
struct CFDictionary(c_void);

#[repr(C)]
struct CFString(c_void);

#[repr(C)]
struct CFTypeRef(c_void);

extern "C" {
    fn SecItemCopyMatching(query: *const CFDictionary, result: *mut *const CFTypeRef) -> c_int;
    fn CFDictionaryCreate(
        allocator: *const c_void,
        keys: *const *const c_void,
        values: *const *const c_void,
        num_values: usize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> *const CFDictionary;
    fn CFStringCreateWithCString(
        alloc: *const c_void,
        cstring: *const c_char,
        encoding: u32,
    ) -> *const CFString;
    fn CFDataGetLength(data: *const c_void) -> isize;
    fn CFDataGetBytes(data: *const c_void, range: CFRange, buffer: *mut c_void);
    fn CFGetTypeID(cf: *const c_void) -> usize;
    fn CFDataGetTypeID() -> usize;
    fn CFRelease(cf: *const c_void);
    static kSecClass: *const c_void;
    static kSecAttrService: *const c_void;
    static kSecAttrAccount: *const c_void;
    static kSecReturnData: *const c_void;
    static kSecClassGenericPassword: *const c_void;
    static kCFBooleanTrue: *const c_void;
}

#[repr(C)]
struct CFRange {
    location: isize,
    length: isize,
}
const K_CFSTRING_ENCODING_UTF8: u32 = 0x08000100;
/// A legacy master is 32 bytes; this merely leaves room for older encodings while preventing
/// an unexpected Core Foundation result from driving an unbounded allocation.
const MAX_KEYCHAIN_SECRET_BYTES: usize = 64 * 1024;

struct OwnedCf(*const c_void);

impl OwnedCf {
    fn new(ptr: *const c_void) -> Option<Self> {
        (!ptr.is_null()).then_some(Self(ptr))
    }

    fn as_ptr(&self) -> *const c_void {
        self.0
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        // SAFETY: every `OwnedCf` is created only from a Core Foundation create/copy call,
        // which transfers one retain that must be balanced exactly once.
        unsafe { CFRelease(self.0) }
    }
}

fn create_cf_string(string: &str) -> Result<OwnedCf, GetPasswordErr> {
    let cstr = CString::new(string)?;
    let string = unsafe {
        CFStringCreateWithCString(
            ptr::null(),
            cstr.as_ptr() as *const c_char,
            K_CFSTRING_ENCODING_UTF8,
        )
    };
    OwnedCf::new(string.cast()).ok_or(GetPasswordErr::FailCreateString)
}

struct Query {
    dictionary: OwnedCf,
    // The dictionary deliberately uses null callbacks, so it borrows rather than retains these
    // two dynamically created values. Keep them alive until the query has been submitted.
    _service: OwnedCf,
    _account: OwnedCf,
}

fn create_query(service: &str, account: &str) -> Result<Query, GetPasswordErr> {
    let service = create_cf_string(service)?;
    let account = create_cf_string(account)?;
    unsafe {
        // Use Core Foundation constants for keys
        let keys = [kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData];

        // Use valid values for the keys
        let values = [
            kSecClassGenericPassword,
            service.as_ptr(),
            account.as_ptr(),
            kCFBooleanTrue,
        ];

        // Create the query dictionary
        let dictionary = CFDictionaryCreate(
            ptr::null(),     // Allocator
            keys.as_ptr(),   // Keys
            values.as_ptr(), // Values
            keys.len(),      // Number of keys/values
            ptr::null(),     // Key callbacks
            ptr::null(),     // Value callbacks
        );

        let dictionary = OwnedCf::new(dictionary.cast()).ok_or(GetPasswordErr::FailCreateDict)?;
        Ok(Query {
            dictionary,
            _service: service,
            _account: account,
        })
    }
}

create_err_with_impls!(
    #[derive(Debug)]
    pub GetPasswordErr,
    NonzeroStatus(i32),
    NullRes,
    FailCreateDict,
    FailCreateString,
    WrongResultType,
    InvalidLength(isize),
    Nul(NulError)
    ;
    TooLarge { len: usize, max: usize },
);

pub fn get_password_from_keychain(
    service: &str,
    account: &str,
) -> Result<Zeroizing<Vec<u8>>, GetPasswordErr> {
    unsafe {
        let query = create_query(service, account)?;
        let mut result: *const CFTypeRef = std::ptr::null();
        let status = SecItemCopyMatching(
            query.dictionary.as_ptr().cast(),
            &mut result as *mut *const CFTypeRef,
        );
        if status != 0 {
            return Err(GetPasswordErr::NonzeroStatus(status));
        }
        let result = OwnedCf::new(result.cast()).ok_or(GetPasswordErr::NullRes)?;
        if CFGetTypeID(result.as_ptr()) != CFDataGetTypeID() {
            return Err(GetPasswordErr::WrongResultType);
        }
        let length = CFDataGetLength(result.as_ptr());
        if length < 0 {
            return Err(GetPasswordErr::InvalidLength(length));
        }
        let length = usize::try_from(length).map_err(|_| GetPasswordErr::InvalidLength(length))?;
        if length > MAX_KEYCHAIN_SECRET_BYTES {
            return Err(GetPasswordErr::TooLarge {
                len: length,
                max: MAX_KEYCHAIN_SECRET_BYTES,
            });
        }

        // Copy into memory whose owner is explicit and whose drop path wipes the secret. A CFData
        // returned by Security.framework is immutable; modifying its byte pointer is undefined.
        let mut buffer = Zeroizing::new(vec![0u8; length]);
        CFDataGetBytes(
            result.as_ptr(),
            CFRange {
                location: 0,
                length: length as isize,
            },
            buffer.as_mut_ptr() as *mut c_void,
        );
        Ok(buffer)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[ignore = "interactive: triggers a Keychain access prompt; run manually with `cargo test -- --ignored`"]
    fn test_get_password() -> Result<(), GetPasswordErr> {
        let service = "com.example.myapp";
        let account = "myusername";
        let v = get_password_from_keychain(service, account)?;
        assert!(!v.is_empty(), "the requested Keychain item has data");
        Ok(())
    }
}
