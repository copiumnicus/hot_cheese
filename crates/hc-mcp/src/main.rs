//! `hot_cheese_mcp`: one JSON-RPC message per line in on stdin, one per line out on stdout.
//!
//! stdout belongs to the protocol, so tracing is installed against stderr and this binary
//! writes nothing else to it. EOF on stdin ends the session immediately: the client closing the
//! pipe is the only shutdown signal a stdio server gets.
use hc_mcp::rpc::Server;
use std::io::{BufRead, Write};

fn main() -> std::io::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(hc_core::config::env_log_level())
        .try_init();

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut server = Server::default();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Some(response) = server.dispatch(&line) else {
            continue;
        };
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
    Ok(())
}
