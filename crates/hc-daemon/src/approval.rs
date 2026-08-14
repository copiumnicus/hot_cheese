//! The one approver: every privileged operation goes past a human here, and a sign carries the
//! single biometric the Secure-Enclave op reuses away from it.
use crate::renderer::{Decision, Renderer};
use crate::runtime::UnlockGate;
use crate::{OpContext, Operation};
use hc_core::mac::local_auth::LaContext;
use hc_sign::SignErr;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Takes the human decision, then the one biometric a sign reuses. Only the thread that owns the
/// [`crate::runtime::Runtime`] ever calls this, which is what keeps the `!Send` [`LaContext`] on
/// one thread without anything having to say so.
pub struct Approver {
    /// Which KEK opened this session: a passphrase session has no per-request biometric.
    gate: UnlockGate,
    /// Prompts shown this session, so no two prompts are byte-identical.
    shown: AtomicU64,
    /// How the operator left the last prompt.
    decision: Mutex<Decision>,
    /// How this session asks, and how it gives the terminal back.
    renderer: Arc<dyn Renderer>,
}

impl Approver {
    pub fn new(gate: UnlockGate, renderer: Arc<dyn Renderer>) -> Self {
        Self {
            gate,
            shown: AtomicU64::new(1),
            decision: Mutex::new(Decision::Deny),
            renderer,
        }
    }

    /// How the operator left the last prompt, so a flood can be escaped between two of them.
    pub fn decision(&self) -> Decision {
        *self.decision.lock()
    }

    pub fn renderer(&self) -> &Arc<dyn Renderer> {
        &self.renderer
    }

    pub fn approve(&self, ctx: &OpContext, summary: &str) -> Result<Option<LaContext>, SignErr> {
        let seq = self.shown.fetch_add(1, Ordering::Relaxed);
        let decision = self.renderer.ask(seq, ctx, summary);
        *self.decision.lock() = decision;
        match decision {
            Decision::Approve => {}
            Decision::NoTerminal => return Err(SignErr::NoApprovalTerminal),
            Decision::Deny | Decision::Cancel | Decision::Interrupt => {
                return Err(SignErr::ApprovalDenied)
            }
        }
        if self.gate == UnlockGate::Passphrase || ctx.op != Operation::Sign {
            return Ok(None);
        }
        let head = summary.lines().take(3).collect::<Vec<_>>().join("\n");
        Ok(Some(LaContext::evaluate_biometric(&format!(
            "#{seq} {}\n{head}",
            ctx.reason()
        ))?))
    }
}
