mod crypto;
use std::ffi::CString;

// this has to be in lib.rs, not main.rs otherwise linking fails
extern "C" {
    pub fn run_menu();
    pub fn get_password_from_keychain(service: *const i8, account: *const i8) -> *const i8;
    fn authenticate_with_touch_id(reason: *const i8) -> bool;
    fn show_toast_notification(title: *const i8, message: *const i8) -> bool;
}
pub fn toast(title: &str, message: &str) {
    let title = CString::new(title).expect("CString::new failed");
    let message = CString::new(message).expect("CString::new failed");
    // ignore
    let _ = unsafe { show_toast_notification(title.as_ptr(), message.as_ptr()) };
}
/// returns true only if user is authed owner of device
pub fn touch_id_auth(reason: &str) -> bool {
    let reason = CString::new(reason).expect("CString::new failed");
    unsafe { authenticate_with_touch_id(reason.as_ptr()) }
}
