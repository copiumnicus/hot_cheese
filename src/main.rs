use std::ffi::CStr;
use std::ffi::CString;
use std::net::SocketAddr;
use std::time::Duration;
use tiny_http::Method;
use tiny_http::StatusCode;
use tiny_http::{Response, Server};

extern "C" {
    fn run_menu();
    fn authenticate_with_touch_id(reason: *const i8) -> bool;
    fn get_password_from_keychain(service: *const i8, account: *const i8) -> *const i8;
    fn show_toast_notification(title: *const i8, message: *const i8) -> bool;
}

fn toast(title: &str, message: &str) {
    let title = CString::new(title).expect("CString::new failed");
    let message = CString::new(message).expect("CString::new failed");
    // ignore
    let _ = unsafe { show_toast_notification(title.as_ptr(), message.as_ptr()) };
}
/// returns true only if user is authed owner of device
fn touch_id_auth(reason: &str) -> bool {
    let reason = CString::new(reason).expect("CString::new failed");
    unsafe { authenticate_with_touch_id(reason.as_ptr()) }
}

const STORE_PATH: &str = "~/Documents/SSTORE";
const BIND: &str = "127.0.0.1:5555";

fn main() {
    let server = Server::https(
        BIND,
        tiny_http::SslConfig {
            certificate: include_bytes!("ssl-cert.pem").to_vec(),
            private_key: include_bytes!("ssl-key.pem").to_vec(),
        },
    )
    .unwrap();
    toast("Started server", format!("Bind on {}", BIND).as_str());

    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            assert!(request.secure());
            if !matches!(request.method(), Method::Get) {
                let _ = request.respond(Response::empty(StatusCode(400)));
                continue;
            }
            toast(
                "Request",
                format!(
                    "{} -> {} {}",
                    request
                        .remote_addr()
                        .map(|x| x.to_string())
                        .unwrap_or("undefined".into()),
                    request.method(),
                    request.url()
                )
                .as_str(),
            );
            let response = Response::from_string("hello world");
            request
                .respond(response)
                .unwrap_or(println!("Failed to respond to request"));
        }
    });

    std::thread::spawn(|| {
        if !touch_id_auth("authorize access to `CC_PROD_0`") {
            toast("Owner Auth", "Authorization failed");
            return;
        }
        // Define the service and account
        // security add-generic-password -a myusername -s com.example.myapp -w mypassword
        let service = CString::new("com.example.myapp").expect("CString::new failed");
        let account = CString::new("myusername").expect("CString::new failed");

        // Call the Swift function
        let password_ptr =
            unsafe { get_password_from_keychain(service.as_ptr(), account.as_ptr()) };

        if !password_ptr.is_null() {
            // Convert the returned C string to a Rust string
            let password = unsafe { CStr::from_ptr(password_ptr) }
                .to_str()
                .expect("Failed to convert CStr to &str");
            println!("Password: {}", password);
        } else {
            println!("Password not found or an error occurred.");
        }
    });
    // need on main thread
    unsafe { run_menu() };
}
