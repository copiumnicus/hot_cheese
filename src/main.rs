use std::ffi::CString;

extern "C" {
    fn authenticate_with_touch_id(reason: *const i8) -> bool;
}

fn main() {
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
    }
}
