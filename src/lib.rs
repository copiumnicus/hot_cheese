mod crypto;
// mod get_password;
// use get_password::{get_password_from_keychain, GetPasswordErr};
mod server;
pub use server::run_server;
use std::{
    ffi::{c_void, CStr, CString, NulError},
    io::Read,
    path::{Path, PathBuf},
    str::Utf8Error,
};

use crypto::{decrypt_key, encrypt_key, random_pk, to_str, CryptoErr};
use err_mac::create_err_with_impls;
use rand::rngs::{OsRng, ThreadRng};
use zeroize::Zeroize;

// // this has to be in lib.rs, not main.rs otherwise linking fails
// extern "C" {
//     pub fn run_menu();
//     fn authenticate_with_touch_id(reason: *const i8) -> bool;
//     fn show_toast_notification(title: *const i8, message: *const i8) -> bool;
// }
// pub fn toast(title: impl ToString, message: impl ToString) {
//     let title = CString::new(title.to_string()).expect("CString::new failed");
//     let message = CString::new(message.to_string()).expect("CString::new failed");
//     // ignore
//     let _ = unsafe { show_toast_notification(title.as_ptr(), message.as_ptr()) };
// }
// /// returns true only if user is authed owner of device
// fn touch_id_auth(reason: &str) -> Result<bool, UserErr> {
//     let reason = CString::new(reason)?;
//     Ok(unsafe { authenticate_with_touch_id(reason.as_ptr()) })
// }

// const STORE_PATH: &str = "~/Documents/SSTORE";
// pub const BIND: &str = "127.0.0.1:5555";

// create_err_with_impls!(
//     #[derive(Debug)]
//     pub UserErr,
//     Password(GetPasswordErr),
//     FailAuthorize,
//     Utf(Utf8Error),
//     Nul(NulError),
//     KeyExists,
//     KeyNotExists,
//     Crypto(CryptoErr),
//     ;
// );

// /// generates a new key of `name` if does not exist in store path
// pub fn generate_key(name: &str) -> Result<(), UserErr> {
//     let path = Path::new(&store()).join(name);
//     if path.exists() {
//         return Err(UserErr::KeyExists);
//     }
//     let mut rng = rand::rngs::OsRng::default();
//     let mut pk = random_pk(&mut rng).to_bytes().to_vec();
//     let mut password = aquire_encryption_key()?;
//     encrypt_key(store(), &mut rng, &pk, &password, name)?;
//     pk.zeroize();
//     password.zeroize();
//     Ok(())
// }

// pub struct ZeroizingVecReader {
//     data: Vec<u8>,
//     position: usize,
// }

// impl ZeroizingVecReader {
//     pub fn new(data: Vec<u8>) -> Self {
//         ZeroizingVecReader { data, position: 0 }
//     }
// }
// impl Read for ZeroizingVecReader {
//     /// Reads bytes from the internal buffer into the provided buffer and zeroizes the read bytes.
//     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//         if self.position >= self.data.len() {
//             return Ok(0); // EOF
//         }
//         let remaining = &mut self.data[self.position..];
//         let bytes_to_read = remaining.len().min(buf.len());
//         buf[..bytes_to_read].copy_from_slice(&remaining[..bytes_to_read]);

//         // Zeroize the read bytes
//         for byte in &mut remaining[..bytes_to_read] {
//             *byte = 0;
//         }

//         self.position += bytes_to_read;

//         Ok(bytes_to_read)
//     }
// }
// impl Drop for ZeroizingVecReader {
//     fn drop(&mut self) {
//         self.data.zeroize();
//     }
// }

// pub fn read_key(name: &str) -> Result<String, UserErr> {
//     let path = Path::new(&store()).join(name);
//     if !path.exists() {
//         return Err(UserErr::KeyNotExists);
//     }
//     let mut password = aquire_encryption_key()?;
//     let key = decrypt_key(path, &password)?;
//     password.zeroize();
//     Ok(to_str(key))
// }

// fn aquire_encryption_key() -> Result<Vec<u8>, UserErr> {
//     if !touch_id_auth("authorize access to vault")? {
//         return Err(UserErr::FailAuthorize);
//     }
//     let service = "com.example.myapp";
//     let account = "myusername";
//     Ok(get_password_from_keychain(service, account)?)
// }

// fn store() -> PathBuf {
//     resolve_path(STORE_PATH)
// }
// fn resolve_path(path: &str) -> PathBuf {
//     if path.starts_with("~/") {
//         if let Ok(home_dir) = std::env::var("HOME") {
//             return PathBuf::from(home_dir).join(path.trim_start_matches("~/"));
//         }
//     }
//     PathBuf::from(path) // Fallback: return the path as-is
// }

// #[cfg(test)]
// mod test {
//     use super::*;

//     #[test]
//     fn test_generate() {
//         let name = "test_key2";
//         let path = Path::new(&store()).join(name);
//         println!("path {:?}", path);
//         if path.exists() {
//             return;
//         }
//         std::fs::write(path, vec![]).unwrap();
//         // let mut rng = rand::rngs::OsRng::default();
//         // let pk = random_pk(&mut rng);
//         // let password = vec![0, 0, 0];
//         // encrypt_key(STORE_PATH, &mut rng, pk.to_bytes().to_vec(), password, name).unwrap();
//     }
// }
