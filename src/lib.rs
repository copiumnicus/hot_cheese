// Our error enums embed typed inner errors rather than boxing them (per CLAUDE.md:
// never box errors to shrink them), which trips clippy::result_large_err. We accept
// the larger Result size in exchange for preserving error type information.
#![allow(clippy::result_large_err)]

pub mod cli;
pub mod ui_api;

mod backup;
mod bootstrap;
mod config;
mod crypto;
mod keyring;
mod mac;
mod migrate;
mod server;
mod unlock;

pub use config::{BackupRemote, Config};
pub use crypto::encrypt_key;
pub use mac::MacBackend;
pub use server::{resolve_path, run_server, BackendImpl};
