use std::ffi::CStr;
use std::ffi::CString;

extern "C" {
    fn authenticate_with_touch_id(reason: *const i8) -> bool;
    fn get_password_from_keychain(service: *const i8, account: *const i8) -> *const i8;
    fn show_toast_notification(title: *const i8, message: *const i8) -> bool;
}

fn main() {
    let title = CString::new("Hello from Rust").expect("CString::new failed");
    let message = CString::new("This is a toast notification!").expect("CString::new failed");
    let result = unsafe { show_toast_notification(title.as_ptr(), message.as_ptr()) };
    println!("show toast {}", result);

    if result {
        println!("Notification sent successfully!");
    } else {
        println!("Failed to send notification.");
    }
    // Custom reason string
    let reason = CString::new("authorize access to `CC_PROD_0`").expect("CString::new failed");

    // Call the Swift function
    println!("Starting authentication...");
    let result = unsafe { authenticate_with_touch_id(reason.as_ptr()) };

    // Check the result
    if result {
        println!("Authentication succeeded!");
    } else {
        println!("Authentication failed.");
        return;
    }
    // Define the service and account
    // security add-generic-password -a myusername -s com.example.myapp -w mypassword
    let service = CString::new("com.example.myapp").expect("CString::new failed");
    let account = CString::new("myusername").expect("CString::new failed");

    // Call the Swift function
    let password_ptr = unsafe { get_password_from_keychain(service.as_ptr(), account.as_ptr()) };

    if !password_ptr.is_null() {
        // Convert the returned C string to a Rust string
        let password = unsafe { CStr::from_ptr(password_ptr) }
            .to_str()
            .expect("Failed to convert CStr to &str");
        println!("Password: {}", password);

        // Free the returned string
        unsafe {
            libc::free(password_ptr as *mut libc::c_void);
        }
    } else {
        println!("Password not found or an error occurred.");
    }
}
