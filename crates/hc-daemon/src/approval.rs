//! The one approver: every privileged operation goes past a human here, and a sign carries the
//! single biometric the Secure-Enclave op reuses away from it.
use crate::renderer::{Decision, Renderer};
use crate::runtime::UnlockGate;
use crate::{OpContext, Operation};
use hc_core::mac::local_auth::LaContext;
use hc_sign::adapter::Summary;
use hc_sign::SignErr;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Lines of the summary the Touch ID sheet carries, and the lines repeated directly above the
/// terminal's `[y/N]`. Both are size-limited surfaces the operator answers from, so both take
/// the WORST alarms the payload raised rather than whichever lines happen to come first; with
/// no alarms to carry, the sheet falls back to the top of the body.
///
/// It is a budget for the alarms the payload's authority does not depend on. The sheet is the
/// whole of what the biometric asks about — there is no body beneath it and nothing to scroll —
/// so [`Summary::head`] spends this on nothing until every alarm that changes who controls the
/// Safe is on it, however far past three lines that runs.
const SHEET_LINES: usize = 3;

/// Takes the human decision. A listening Secure-Enclave daemon uses Touch ID as that decision;
/// local signing may still take an explicit terminal answer first. Only the thread that owns the
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
    /// A serving Secure-Enclave session uses the biometric sheet itself as the answer. Local
    /// CLI signing keeps the explicit terminal confirmation it has historically used.
    direct_biometric: bool,
    biometric: fn(&str) -> Result<LaContext, SignErr>,
}

impl Approver {
    pub fn new(gate: UnlockGate, renderer: Arc<dyn Renderer>) -> Self {
        Self {
            gate,
            shown: AtomicU64::new(1),
            decision: Mutex::new(Decision::Deny),
            renderer,
            direct_biometric: false,
            biometric: |reason| Ok(LaContext::evaluate_biometric(reason)?),
        }
    }

    /// Build the approver used by a listening daemon. An arriving viable request immediately
    /// raises Touch ID; there is no separate terminal answer to discover first.
    pub fn direct(gate: UnlockGate, renderer: Arc<dyn Renderer>) -> Self {
        let mut approver = Self::new(gate, renderer);
        approver.direct_biometric = gate == UnlockGate::Biometric;
        approver
    }

    /// How the operator left the last prompt, so a flood can be escaped between two of them.
    pub fn decision(&self) -> Decision {
        *self.decision.lock()
    }

    pub fn renderer(&self) -> &Arc<dyn Renderer> {
        &self.renderer
    }

    /// Put one request in front of the operator. Every request that reaches this approver reaches
    /// them: nothing here refuses one on its own, and nothing here carries an answer forward. The
    /// operator's escape (`q`) denies the request they were asked about and everything already
    /// queued behind it, and buys no silence past that — on the loopback listener every client is
    /// the same unauthenticated caller, so "stop asking about this one" would be a promise to
    /// refuse the operator's own service without ever showing them a request.
    ///
    /// That is a claim about this approver and not about the daemon. Two refusals still happen
    /// with no prompt at all, both reachable by any loopback caller: a caller whose wait for a
    /// place in the approval line outlasted `LINE_WAIT`, and every op already queued when the
    /// operator escapes a prompt.
    pub fn approve(
        &self,
        ctx: &OpContext,
        summary: &Summary,
    ) -> Result<Option<LaContext>, SignErr> {
        let seq = self.shown.fetch_add(1, Ordering::Relaxed);
        let head = match summary.alarms().is_empty() {
            true => summary
                .body
                .lines()
                .take(SHEET_LINES)
                .collect::<Vec<_>>()
                .join("\n"),
            false => summary.head(SHEET_LINES),
        };
        if self.direct_biometric {
            let result = (self.biometric)(&format!("#{seq} {}\n{head}", ctx.reason()));
            *self.decision.lock() = match result {
                Ok(_) => Decision::Approve,
                Err(_) => Decision::Deny,
            };
            return result.map(Some);
        }
        let shown = match summary.alarms().is_empty() {
            true => summary.to_string(),
            false => format!("{summary}\n{}", summary.head(SHEET_LINES)),
        };
        let decision = self.renderer.ask(seq, ctx, &shown);
        *self.decision.lock() = decision;
        match decision {
            Decision::Approve => {}
            Decision::NoTerminal => return Err(SignErr::NoApprovalTerminal),
            Decision::Cancel => {
                tracing::warn!(
                    peer = %ctx.peer,
                    seq,
                    "the operator escaped the prompt: this request and the whole backlog are denied"
                );
                return Err(SignErr::ApprovalDenied);
            }
            Decision::Deny | Decision::Interrupt => return Err(SignErr::ApprovalDenied),
        }
        if self.gate == UnlockGate::Passphrase || ctx.op != Operation::Sign {
            return Ok(None);
        }
        Ok(Some(LaContext::evaluate_biometric(&format!(
            "#{seq} {}\n{head}",
            ctx.reason()
        ))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Peer;

    fn nothing_to_read() -> Summary {
        Summary {
            authority: Vec::new(),
            evictable: Vec::new(),
            body: String::new(),
        }
    }

    /// Counts every prompt it was shown, keeps the last one's text, and answers all of them the
    /// same way.
    struct Counting {
        answer: Decision,
        asked: Mutex<usize>,
        shown: Mutex<String>,
    }

    impl Renderer for Counting {
        fn ask(&self, _seq: u64, _ctx: &OpContext, summary: &str) -> Decision {
            *self.asked.lock() += 1;
            *self.shown.lock() = summary.to_string();
            self.answer
        }
        fn restore(&self) {}
    }

    fn counting(answer: Decision) -> (Arc<Counting>, Approver) {
        let counting = Arc::new(Counting {
            answer,
            asked: Mutex::new(0),
            shown: Mutex::new(String::new()),
        });
        let approver = Approver::new(UnlockGate::Biometric, counting.clone());
        (counting, approver)
    }

    fn remote(key: &str) -> OpContext {
        OpContext {
            key: key.to_string(),
            op: Operation::EvmAddress,
            peer: Peer::Loopback,
        }
    }

    fn biometric_denied(_: &str) -> Result<LaContext, SignErr> {
        Err(SignErr::ApprovalDenied)
    }

    #[test]
    fn daemon_biometric_is_the_decision_without_a_terminal_question() {
        let (counting, mut approver) = counting(Decision::Approve);
        approver.direct_biometric = true;
        approver.biometric = biometric_denied;

        assert!(matches!(
            approver.approve(&remote("TRADER"), &nothing_to_read()),
            Err(SignErr::ApprovalDenied)
        ));
        assert_eq!(*counting.asked.lock(), 0);
        assert_eq!(approver.decision(), Decision::Deny);
    }

    /// Nothing on the loopback listener tells the operator's own service from a flood, so a
    /// budget spent by either would refuse both. No sustained volume, and no number of denials,
    /// may cost a later request its prompt.
    #[test]
    fn no_volume_of_requests_can_take_a_later_one_off_the_screen() {
        let (counting, approver) = counting(Decision::Deny);
        for asked in 1..=512 {
            assert!(matches!(
                approver.approve(&remote("TRADER"), &nothing_to_read()),
                Err(SignErr::ApprovalDenied)
            ));
            assert_eq!(
                *counting.asked.lock(),
                asked,
                "request {asked} was refused without ever being shown"
            );
        }
    }

    /// The operator's escape denies the request it was typed at, and nothing after it. Loopback
    /// clients are one unauthenticated caller, so a forward-looking silence keyed on the caller
    /// would refuse the operator's own service for requests they were never shown — and the
    /// refusal it produced was a `403` no correct client retries, for a condition meant to lapse.
    #[test]
    fn escaping_a_prompt_buys_no_silence_from_the_next_request() {
        let (counting, approver) = counting(Decision::Cancel);
        for asked in 1..=64 {
            assert!(matches!(
                approver.approve(&remote("TRADER"), &nothing_to_read()),
                Err(SignErr::ApprovalDenied)
            ));
            assert_eq!(
                *counting.asked.lock(),
                asked,
                "request {asked} was refused without ever being shown"
            );
        }
        assert_eq!(
            approver.decision(),
            Decision::Cancel,
            "the escape must still be readable, so the queued backlog is drained once"
        );

        let tunnelled = OpContext {
            key: "TRADER".to_string(),
            op: Operation::EvmAddress,
            peer: Peer::Unattributed { tunnels: 2 },
        };
        assert!(matches!(
            approver.approve(&tunnelled, &nothing_to_read()),
            Err(SignErr::ApprovalDenied)
        ));
        let local = OpContext::local("TRADER".to_string(), Operation::EvmAddress);
        assert!(matches!(
            approver.approve(&local, &nothing_to_read()),
            Err(SignErr::ApprovalDenied)
        ));
        assert_eq!(
            *counting.asked.lock(),
            66,
            "no peer, tunnelled or not, may lose its prompt to an answer given at another one"
        );
    }

    /// [`SHEET_LINES`] is a budget for the alarms the Safe's authority does not turn on, and the
    /// block this hands the operator is the whole of what they answer from. A payload that only
    /// changes who controls the Safe must therefore reach that block whole — never the fallback
    /// to the top of the body, which is for a payload that raised nothing, and never three of
    /// six lines.
    #[test]
    fn the_prompt_carries_every_authority_alarm_past_the_sheet_budget() {
        let (counting, approver) = counting(Decision::Deny);
        let mut authority = Vec::new();
        for n in 1..=SHEET_LINES * 2 {
            authority.push(format!("\u{26a0} OWNER ROTATION [{n}]: swapOwner"));
        }
        let summary = Summary {
            authority,
            evictable: Vec::new(),
            body: "multiSend: 6 sub-calls".to_string(),
        };

        assert!(matches!(
            approver.approve(&remote("TRADER"), &summary),
            Err(SignErr::ApprovalDenied)
        ));
        let shown = counting.shown.lock().clone();
        for alarm in &summary.authority {
            assert!(shown.contains(alarm.as_str()), "{shown}");
        }
        assert!(
            shown.ends_with(&summary.head(SHEET_LINES)),
            "the block the operator answers from is the sheet, not the top of the body: {shown}"
        );
    }
}
