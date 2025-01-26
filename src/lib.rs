pub use crypto::encrypt_key;
pub use mac::MacBackend;
pub use server::run_server;
pub use server::BackendImpl;

use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize)]
pub struct Config {
    pub service: String,
    pub account: String,
    pub store: String,
}

mod crypto;
mod mac;
mod server;
