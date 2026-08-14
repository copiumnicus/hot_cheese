//! The terminal renderer: the operator's yes/no on the stream inquire prompts on, and the raw
//! mode and hidden cursor undone on every ending.
use crossterm::terminal::disable_raw_mode;
use crossterm::{cursor, execute};
use hc_daemon::renderer::{Decision, Renderer};
use hc_daemon::OpContext;
use std::io::{self, Write};

/// Asks in the console. The terminal must be in cooked mode, and the request and the question
/// about it go to the same stream, so a redirect cannot separate them.
pub struct Terminal;

impl Renderer for Terminal {
    fn ask(&self, seq: u64, ctx: &OpContext, summary: &str) -> Decision {
        let mut request = format!("\n=== hot_cheese request #{seq} ===\n");
        if !summary.is_empty() {
            request.push_str(summary);
            request.push('\n');
        }
        let mut out = io::stderr();
        if let Err(e) = out.write_all(request.as_bytes()).and_then(|()| out.flush()) {
            tracing::warn!(error = %e, key = %ctx.key, "could not show the request");
            return Decision::Cancel;
        }
        let message = format!("#{seq} {} - approve?", ctx.reason());
        match inquire::Confirm::new(&message).with_default(false).prompt() {
            Ok(true) => Decision::Approve,
            Ok(false) => Decision::Deny,
            Err(inquire::InquireError::OperationCanceled) => Decision::Cancel,
            Err(inquire::InquireError::OperationInterrupted) => Decision::Interrupt,
            Err(inquire::InquireError::NotTTY) => Decision::NoTerminal,
            Err(e) => {
                tracing::warn!(error = %e, key = %ctx.key, "approval prompt failed");
                Decision::Cancel
            }
        }
    }

    fn restore(&self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stderr(), cursor::Show);
    }
}
