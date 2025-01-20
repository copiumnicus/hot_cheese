use err_mac::create_err_with_impls;
use std::{
    ffi::{c_char, c_int, c_void, CString, NulError},
    ptr,
};
use zeroize::Zeroize;

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
    fn CFDataGetLength(data: *const c_void) -> usize;
    fn CFDataGetBytes(data: *const c_void, range: CFRange, buffer: *mut c_void);
    fn CFDataGetBytePtr(theData: *const c_void) -> *mut u8;
    static kSecClass: *const c_void;
    static kSecAttrService: *const c_void;
    static kSecAttrAccount: *const c_void;
    static kSecReturnData: *const c_void;
    static kSecClassGenericPassword: *const c_void;
    static kCFBooleanTrue: *const c_void;
}

#[repr(C)]
struct CFRange {
    location: usize,
    length: usize,
}
const kCFStringEncodingUTF8: u32 = 0x08000100;

fn create_cf_string(string: &str) -> Result<*const CFString, GetPasswordErr> {
    let cstr = CString::new(string)?;
    unsafe {
        Ok(CFStringCreateWithCString(
            ptr::null(),
            cstr.as_ptr() as *const c_char,
            kCFStringEncodingUTF8,
        ))
    }
}

fn create_query(service: &str, account: &str) -> Result<*const CFDictionary, GetPasswordErr> {
    unsafe {
        // Use Core Foundation constants for keys
        let keys = [
            kSecClass as *const c_void,
            kSecAttrService as *const c_void,
            kSecAttrAccount as *const c_void,
            kSecReturnData as *const c_void,
        ];

        // Use valid values for the keys
        let values = [
            kSecClassGenericPassword as *const c_void, // Class: Generic Password
            create_cf_string(service)? as *const c_void, // Service string
            create_cf_string(account)? as *const c_void, // Account string
            kCFBooleanTrue as *const c_void,           // Return data as true
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

        if dictionary.is_null() {
            return Err(GetPasswordErr::FailCreateDict);
        }

        Ok(dictionary)
    }
}

create_err_with_impls!(
    #[derive(Debug)]
    pub GetPasswordErr,
    NonzeroStatus(i32),
    NullRes,
    FailCreateDict,
    Nul(NulError)
    ;
);

pub fn get_password_from_keychain(service: &str, account: &str) -> Result<Vec<u8>, GetPasswordErr> {
    unsafe {
        let query = create_query(service, account)?;
        let mut result: *const CFTypeRef = std::ptr::null();
        let status = SecItemCopyMatching(query, &mut result as *mut *const CFTypeRef);
        if status != 0 {
            return Err(GetPasswordErr::NonzeroStatus(status));
        }
        if result.is_null() {
            return Err(GetPasswordErr::NullRes);
        }
        let result_data = result as *const c_void;
        let length = CFDataGetLength(result_data);

        // COPY BYTES FOR US
        let mut buffer = vec![0u8; length];
        CFDataGetBytes(
            result_data,
            CFRange {
                location: 0,
                length,
            },
            buffer.as_mut_ptr() as *mut c_void,
        );

        // ZEROIZE CFDATA
        let byte_ptr = CFDataGetBytePtr(result_data);
        let bytes = std::slice::from_raw_parts_mut(byte_ptr, length);
        bytes.zeroize();

        Ok(buffer)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_password() -> Result<(), GetPasswordErr> {
        let service = "com.example.myapp";
        let account = "myusername";
        let v = get_password_from_keychain(service, account)?;
        println!("{:?}", df_share::to_hex_str(&v));
        Ok(())
    }
}
