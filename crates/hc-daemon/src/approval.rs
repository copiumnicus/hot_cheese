//! The daemon's approval prompt: one request on screen at a time, answered on a terminal.
use crate::{Approver, OpContext};
use hc_core::mac::local_auth::LaContext;
use hc_sign::SignErr;
use parking_lot::Mutex;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicU64, Ordering};

/// Held for a whole approval, so the answer belongs to the request printed above it.
static PROMPT: Mutex<()> = Mutex::new(());

/// Requests rendered this session, so no two prompts are byte-identical.
static SHOWN: AtomicU64 = AtomicU64::new(1);

/// Whether this process has a terminal to ask the operator on.
enum Console {
    Interactive,
    Headless,
}

impl Console {
    fn detect() -> Self {
        if std::io::stdin().is_terminal() {
            Self::Interactive
        } else {
            Self::Headless
        }
    }
}

/// Put one request in front of the operator and take their answer. Caller holds [`PROMPT`];
/// the banner, the summary and the question are a single write, so the answer read here can
/// only be the answer to the text this printed.
fn ask(console: Console, seq: u64, ctx: &OpContext, summary: &str) -> Result<(), SignErr> {
    let Console::Interactive = console else {
        tracing::error!(seq, key = %ctx.key, "no terminal to approve on");
        return Err(SignErr::NoApprovalTerminal);
    };
    let text = format!(
        "\n=== hot_cheese SIGN request #{seq} (policy: ALLOWED) ===\n{reason}\n{summary}\n\
         Approve request #{seq} and sign this transaction? [y/N] ",
        reason = ctx.reason()
    );
    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        tracing::error!(error = %e, seq, key = %ctx.key, "could not show the request");
        return Err(SignErr::ApprovalDenied);
    }
    drop(out);
    let mut line = String::new();
    if let Err(e) = std::io::stdin().read_line(&mut line) {
        tracing::error!(error = %e, seq, key = %ctx.key, "could not read the answer");
        return Err(SignErr::ApprovalDenied);
    }
    if !line.trim().eq_ignore_ascii_case("y") {
        return Err(SignErr::ApprovalDenied);
    }
    Ok(())
}

/// The daemon's approver: prints who asked and the decoded summary, requires an explicit `y`,
/// then evaluates the one biometric the Secure Enclave op reuses — whose sheet also names the
/// caller and the request number, so an adapter's request never reads as the operator's own.
/// Headless, non-`y` and an unshowable prompt all fail closed.
pub struct ServeApprover;

impl Approver for ServeApprover {
    fn approve(&self, ctx: &OpContext, summary: &str) -> Result<Option<LaContext>, SignErr> {
        let _one_at_a_time = PROMPT.lock();
        let seq = SHOWN.fetch_add(1, Ordering::Relaxed);
        ask(Console::detect(), seq, ctx, summary)?;
        let joined = summary.lines().take(3).collect::<Vec<_>>().join("\n");
        Ok(Some(LaContext::evaluate_biometric(&format!(
            "#{seq} {}\n{joined}",
            ctx.reason()
        ))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Operation, Peer};

    /// A daemon with no terminal cannot ask anyone, so the gate must refuse by type — it is the
    /// only thing between an accepted request and the biometric that signs it.
    #[test]
    fn headless_refuses_before_the_biometric() {
        let ctx = OpContext {
            key: "TRADER".to_string(),
            op: Operation::Sign,
            peer: Peer::Loopback,
        };
        assert!(matches!(
            ask(Console::Headless, 1, &ctx, "transfer(to=0x00, amount=1)"),
            Err(SignErr::NoApprovalTerminal)
        ));
    }
}
