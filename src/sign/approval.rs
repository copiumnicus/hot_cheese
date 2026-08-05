//! Show the decoded action, optionally confirm on a TTY, then take the single biometric.
use crate::mac::local_auth::LaContext;
use crate::server::{Approver, OpContext};
use crate::sign::SignErr;
use std::io::IsTerminal;

/// The daemon's approver: prints the decoded summary, requires an explicit `y` when stdin is
/// a TTY, then evaluates the one biometric the Secure Enclave op reuses. Headless or non-`y`
/// fails closed.
pub struct ServeApprover;

impl Approver for ServeApprover {
    fn approve(&self, ctx: &OpContext, summary: &str) -> Result<Option<LaContext>, SignErr> {
        println!("\n=== hot_cheese SIGN request (policy: ALLOWED) ===");
        println!("{summary}");
        if std::io::stdin().is_terminal() {
            println!("Approve and sign this transaction? [y/N]");
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err()
                || !line.trim().eq_ignore_ascii_case("y")
            {
                return Err(SignErr::ApprovalDenied);
            }
        }
        let joined = summary.lines().take(3).collect::<Vec<_>>().join("\n");
        let reason = if joined.is_empty() {
            ctx.reason()
        } else {
            joined
        };
        Ok(Some(LaContext::evaluate_biometric(&reason)?))
    }
}
