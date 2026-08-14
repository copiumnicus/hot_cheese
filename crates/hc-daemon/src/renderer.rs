//! The half of the front end a privileged operation touches: asking the human, and giving the
//! terminal back on every ending.
use crate::OpContext;
use std::io::{IsTerminal, Write};

/// What the operator did at one approval prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Answered yes.
    Approve,
    /// Answered no.
    Deny,
    /// Esc, or a prompt that could not be shown.
    Cancel,
    /// Ctrl-C at the prompt.
    Interrupt,
    /// There is no terminal to ask anyone on.
    NoTerminal,
}

/// How one session asks the operator, and how it hands the terminal back.
pub trait Renderer: Send + Sync {
    /// Put one request in front of the operator and take their answer.
    fn ask(&self, seq: u64, ctx: &OpContext, summary: &str) -> Decision;
    /// Undo whatever this renderer did to the terminal. Idempotent.
    fn restore(&self);
}

/// Whether this process has a terminal to ask the operator on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tty {
    Interactive,
    Headless,
}

/// The daemon's renderer: a banner, the decoded summary and an explicit `y` on the terminal that
/// started it. With no terminal it refuses by type rather than denying, so the caller can tell
/// "nobody could be asked" from "somebody said no".
pub struct Headless {
    /// Whether stdin was a terminal when the runtime started.
    tty: Tty,
}

impl Headless {
    pub fn detect() -> Self {
        Self {
            tty: match std::io::stdin().is_terminal() {
                true => Tty::Interactive,
                false => Tty::Headless,
            },
        }
    }
}

impl Renderer for Headless {
    fn ask(&self, seq: u64, ctx: &OpContext, summary: &str) -> Decision {
        let Tty::Interactive = self.tty else {
            tracing::error!(seq, key = %ctx.key, op = ?ctx.op, "no terminal to approve on");
            return Decision::NoTerminal;
        };
        let text = format!(
            "\n=== hot_cheese {op:?} request #{seq} ===\n{reason}\n{summary}\n\
             Approve request #{seq}? [y/N] ",
            op = ctx.op,
            reason = ctx.reason()
        );
        let mut out = std::io::stdout().lock();
        if let Err(e) = out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
            tracing::error!(error = %e, seq, key = %ctx.key, "could not show the request");
            return Decision::Cancel;
        }
        drop(out);
        let mut line = String::new();
        if let Err(e) = std::io::stdin().read_line(&mut line) {
            tracing::error!(error = %e, seq, key = %ctx.key, "could not read the answer");
            return Decision::Cancel;
        }
        match line.trim().eq_ignore_ascii_case("y") {
            true => Decision::Approve,
            false => Decision::Deny,
        }
    }

    fn restore(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::Approver;
    use crate::runtime::UnlockGate;
    use crate::{Operation, Peer};
    use hc_sign::SignErr;
    use std::sync::Arc;

    /// A daemon with no terminal cannot ask anyone, and "nobody could be asked" must stay a
    /// distinct refusal all the way to the caller: degrading it into the denial a human types
    /// is exactly what would let an unattended daemon look like a refusing operator.
    #[test]
    fn no_terminal_is_a_typed_refusal_and_not_a_denial() {
        let ctx = OpContext {
            key: "TRADER".to_string(),
            op: Operation::Sign,
            peer: Peer::Loopback,
        };
        let headless = Headless { tty: Tty::Headless };
        assert_eq!(
            headless.ask(1, &ctx, "transfer(to=0x00, amount=1)"),
            Decision::NoTerminal
        );
        assert!(matches!(
            Approver::new(UnlockGate::Biometric, Arc::new(headless)).approve(&ctx, "summary"),
            Err(SignErr::NoApprovalTerminal)
        ));
    }
}
