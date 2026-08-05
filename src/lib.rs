// Our error enums embed typed inner errors rather than boxing them (per CLAUDE.md:
// never box errors to shrink them), which trips clippy::result_large_err. We accept
// the larger Result size in exchange for preserving error type information.
#![allow(clippy::result_large_err)]

pub mod cli;
pub mod console;
// `config` and `server` are public for the reference client in `examples/pin_cert.rs`: it
// resolves the pinned cert through the daemon's own home-dir logic and derives an EVM
// address with the daemon's own `sk_to_adr`, rather than duplicating either.
pub mod config;
pub mod server;
pub mod sign;

mod backup;
mod bootstrap;
mod crypto;
mod keyring;
mod mac;
mod migrate;
mod unlock;
