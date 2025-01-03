use std::time::SystemTime;

use cc_sstore::generate_key;
use cc_sstore::read_key;
use cc_sstore::run_menu;
use cc_sstore::run_server;
use cc_sstore::toast;
use cc_sstore::ZeroizingVecReader;
use cc_sstore::BIND;
use httpdate::HttpDate;
use tiny_http::Header;
use tiny_http::Method;
use tiny_http::StatusCode;
use tiny_http::{Response, Server};
use zeroize::Zeroize;

fn is_valid_string_name(name: &str) -> bool {
    // Check that all characters in the name are valid (a-z, A-Z, _)
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn handle_request(path: &str) -> Option<String> {
    if let Some(name) = path.strip_prefix("/generate/") {
        if is_valid_string_name(name) {
            match generate_key(name) {
                Ok(_) => {
                    toast("Generate", format!("Success generating: {}", name));
                    return Some(format!("Generated: {}", name));
                }
                Err(e) => {
                    toast("Generate error", format!("{:?}", e));
                }
            }
        }
    } else if let Some(name) = path.strip_prefix("/read/") {
        if is_valid_string_name(name) {
            match read_key(name) {
                Ok(key) => {
                    toast("Read", format!("Success read: {}", name));
                    return Some(key);
                }
                Err(e) => {
                    toast("Read error", format!("{:?}", e));
                }
            }
        }
    }

    None
}

fn main() {
    std::thread::spawn(move || {
        if let Err(_) = run_server() {
            std::process::exit(1);
        }
    });
    loop {}
    // let server = Server::https(
    //     BIND,
    //     tiny_http::SslConfig {
    //         certificate: include_bytes!("ssl-cert.pem").to_vec(),
    //         private_key: include_bytes!("ssl-key.pem").to_vec(),
    //     },
    // )
    // .unwrap();
    // toast("Started server", format!("Bind on {}", BIND).as_str());

    // std::thread::spawn(move || {
    //     for request in server.incoming_requests() {
    //         assert!(request.secure());
    //         if !matches!(request.method(), Method::Get) {
    //             let _ = request.respond(Response::empty(StatusCode(400)));
    //             continue;
    //         }
    //         toast(
    //             "Request",
    //             format!(
    //                 "{} -> {} {}",
    //                 request
    //                     .remote_addr()
    //                     .map(|x| x.to_string())
    //                     .unwrap_or("undefined".into()),
    //                 request.method(),
    //                 request.url()
    //             )
    //             .as_str(),
    //         );
    //         match handle_request(request.url()) {
    //             Some(r) => {
    //                 // let dl = r.len();
    //                 // let res = Response::new(
    //                 //     StatusCode(200),
    //                 //     vec![Header::from_bytes(
    //                 //         &b"Content-Type"[..],
    //                 //         &b"text/plain; charset=UTF-8"[..],
    //                 //     )
    //                 //     .unwrap()],
    //                 //     ZeroizingVecReader::new(r.into_bytes()),
    //                 //     Some(dl),
    //                 //     None,
    //                 // );
    //                 // mby can use this to prevent leaving sensitive info in memory
    //                 // request.into_writer()
    //                 let mut w = request.into_writer();
    //                 let mut res = vec![];
    //                 res.push("HTTP/1.1 200 OK");
    //                 res.push("Server: HotCheese (Rust)");
    //                 let d = format!("Date: {}", HttpDate::from(SystemTime::now()).to_string());
    //                 res.push(d.as_str());
    //                 res.push("Content-Type: text/plain; charset=UTF-8");
    //                 let cl = format!("Content-Length: {}", r.len());
    //                 res.push(cl.as_str());
    //                 res.push("");
    //                 res.push(r.as_str());
    //                 let res = res.join("\r\n");
    //                 let mut res_bytes = res.into_bytes();
    //                 let _ = w.write_all(&res_bytes);
    //                 let _ = w.flush();
    //                 res_bytes.zeroize();
    //             }
    //             None => {
    //                 let _ = request.respond(Response::empty(StatusCode(400)));
    //             }
    //         }
    //     }
    // });
    // need on main thread
    unsafe { run_menu() };
}
