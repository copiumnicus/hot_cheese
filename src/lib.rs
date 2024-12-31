mod crypto;
use std::{
    ffi::{c_void, CStr, CString, NulError},
    path::{Path, PathBuf},
    str::Utf8Error,
};

use crypto::{encrypt_key, random_pk, CryptoErr};
use err_mac::create_err_with_impls;
use rand::rngs::{OsRng, ThreadRng};

// this has to be in lib.rs, not main.rs otherwise linking fails
extern "C" {
    pub fn run_menu();
    fn get_password_from_keychain(service: *const i8, account: *const i8) -> *const i8;
    fn authenticate_with_touch_id(reason: *const i8) -> bool;
    fn show_toast_notification(title: *const i8, message: *const i8) -> bool;
    fn free(ptr: *mut std::ffi::c_void);
}
pub fn toast(title: impl ToString, message: impl ToString) {
    let title = CString::new(title.to_string()).expect("CString::new failed");
    let message = CString::new(message.to_string()).expect("CString::new failed");
    // ignore
    let _ = unsafe { show_toast_notification(title.as_ptr(), message.as_ptr()) };
}
/// returns true only if user is authed owner of device
fn touch_id_auth(reason: &str) -> Result<bool, UserErr> {
    let reason = CString::new(reason)?;
    Ok(unsafe { authenticate_with_touch_id(reason.as_ptr()) })
}

const STORE_PATH: &str = "~/Documents/SSTORE";
pub const BIND: &str = "127.0.0.1:5555";

create_err_with_impls!(
    #[derive(Debug)]
    pub UserErr,
    FailAuthorize,
    FailGetPassword,
    Utf(Utf8Error),
    Nul(NulError),
    KeyExists,
    Crypto(CryptoErr)
    ;
);

/// generates a new key of `name` if does not exist in store path
pub fn generate_key(name: &str) -> Result<(), UserErr> {
    let path = Path::new(&store()).join(name);
    if path.exists() {
        return Err(UserErr::KeyExists);
    }
    let mut rng = rand::rngs::OsRng::default();
    let mut pk = random_pk(&mut rng).to_bytes().to_vec();
    let mut password = aquire_encryption_key()?;
    encrypt_key(store(), &mut rng, &pk, &password, name)?;
    pk.fill(0);
    password.fill(0);
    Ok(())
}

fn aquire_encryption_key() -> Result<Vec<u8>, UserErr> {
    if !touch_id_auth("authorize access to vault")? {
        return Err(UserErr::FailAuthorize);
    }
    // Define the service and account
    let service = CString::new("com.example.myapp")?;
    let account = CString::new("myusername")?;

    // Call the Swift function
    let password_ptr = unsafe { get_password_from_keychain(service.as_ptr(), account.as_ptr()) };

    if !password_ptr.is_null() {
        // Convert the returned C string to a Rust string
        let password_vec = unsafe {
            let password_cstr = CStr::from_ptr(password_ptr);
            let password_bytes = password_cstr.to_bytes().to_vec();

            // Zero out the C string before freeing it
            std::ptr::write_bytes(password_ptr as *mut u8, 0, password_bytes.len());
            free(password_ptr as *mut c_void);

            password_bytes
        };
        return Ok(password_vec);
    }
    Err(UserErr::FailGetPassword)
}

fn store() -> PathBuf {
    resolve_path(STORE_PATH)
}
fn resolve_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home_dir) = std::env::var("HOME") {
            return PathBuf::from(home_dir).join(path.trim_start_matches("~/"));
        }
    }
    PathBuf::from(path) // Fallback: return the path as-is
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_generate() {
        let name = "test_key2";
        let path = Path::new(&store()).join(name);
        println!("path {:?}", path);
        if path.exists() {
            return;
        }
        std::fs::write(path, vec![]).unwrap();
        // let mut rng = rand::rngs::OsRng::default();
        // let pk = random_pk(&mut rng);
        // let password = vec![0, 0, 0];
        // encrypt_key(STORE_PATH, &mut rng, pk.to_bytes().to_vec(), password, name).unwrap();
    }
}
