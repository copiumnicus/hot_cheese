//! `hot_cheese_mcp`: one JSON-RPC message per line in on stdin, one per line out on stdout.
//!
//! stdout belongs to the protocol, so tracing is installed against stderr and this binary
//! writes nothing else to it. EOF on stdin ends the session immediately: the client closing the
//! pipe is the only shutdown signal a stdio server gets.
use hc_mcp::rpc::Server;
use std::io::{BufRead, Write};

const MAX_REQUEST_BYTES: usize = 64 * 1024;

enum InputLine {
    Eof,
    Line(Vec<u8>),
    TooLarge,
}

/// Read and drain exactly one newline-delimited request while retaining at most the cap. An
/// oversized request cannot leave its tail to be interpreted as a second JSON-RPC message.
fn read_line_bounded<R: BufRead>(reader: &mut R) -> std::io::Result<InputLine> {
    let mut line = Vec::new();
    let mut oversized = false;
    let mut saw_bytes = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if !saw_bytes {
                Ok(InputLine::Eof)
            } else if oversized {
                Ok(InputLine::TooLarge)
            } else {
                Ok(InputLine::Line(line))
            };
        }
        saw_bytes = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let used = newline.map_or(available.len(), |at| at + 1);
        let content = newline.map_or(&available[..used], |at| &available[..at]);
        if !oversized {
            let remaining = MAX_REQUEST_BYTES.saturating_sub(line.len());
            if content.len() > remaining {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(content);
            }
        }
        reader.consume(used);
        if newline.is_some() {
            return if oversized {
                Ok(InputLine::TooLarge)
            } else {
                Ok(InputLine::Line(line))
            };
        }
    }
}

fn main() -> std::io::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(hc_core::config::env_log_level())
        .try_init();

    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut stdout = std::io::stdout();
    let mut server = Server::default();
    loop {
        let bytes = match read_line_bounded(&mut stdin)? {
            InputLine::Eof => break,
            InputLine::TooLarge => {
                writeln!(
                    stdout,
                    "{}",
                    Server::parse_error(format!("request exceeds {MAX_REQUEST_BYTES} bytes"))
                )?;
                stdout.flush()?;
                continue;
            }
            InputLine::Line(bytes) => bytes,
        };
        let line = match std::str::from_utf8(&bytes) {
            Ok(line) => line,
            Err(error) => {
                writeln!(stdout, "{}", Server::parse_error(error.to_string()))?;
                stdout.flush()?;
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let Some(response) = server.dispatch(line) else {
            continue;
        };
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn oversized_line_is_drained_before_the_next_request() {
        let mut wire = vec![b'x'; MAX_REQUEST_BYTES + 1];
        wire.extend_from_slice(b"\n{}\n");
        let mut reader = BufReader::new(Cursor::new(wire));
        assert!(matches!(
            read_line_bounded(&mut reader).unwrap(),
            InputLine::TooLarge
        ));
        match read_line_bounded(&mut reader).unwrap() {
            InputLine::Line(line) => assert_eq!(line, b"{}"),
            _ => panic!("the next complete request was not preserved"),
        }
    }
}
