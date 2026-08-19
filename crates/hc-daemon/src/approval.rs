//! The one approver: every privileged operation goes past a human here, and a sign carries the
//! single biometric the Secure-Enclave op reuses away from it.
use crate::renderer::{Decision, Renderer};
use crate::runtime::UnlockGate;
use crate::{OpContext, Operation, Peer};
use hashbrown::HashMap;
use hc_core::mac::local_auth::LaContext;
use hc_sign::adapter::Summary;
use hc_sign::SignErr;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Lines of the summary the Touch ID sheet carries, and the lines repeated directly above the
/// terminal's `[y/N]`. Both are size-limited surfaces the operator answers from, so both take
/// the WORST alarms the payload raised rather than whichever lines happen to come first; with
/// no alarms to carry, the sheet falls back to the top of the body.
const SHEET_LINES: usize = 3;

/// How long the operator's explicit "stop asking about this caller" answer stays in force.
///
/// Nothing else suppresses a prompt. A budget the daemon spends on its own cannot tell an
/// attacker from the operator's own service — the two are byte-identical on an unauthenticated
/// loopback listener — so a rule that refuses past a budget is a lever the attacker aims at
/// everybody. Only the operator, at a prompt, may buy quiet, and it lapses by itself.
pub const QUIET_PERIOD: Duration = Duration::from_secs(30);

/// One caller's identity, as far as the listener can honestly tell callers apart.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Origin {
    /// Every client of the loopback listener: it authenticates nobody, so they are one caller.
    Loopback,
    /// One adapter socket, named by the manifest that socket was bound for.
    Adapter(String),
}

/// Which caller the operator would be silencing, or `None` for the operator's own keyboard,
/// which no listener can reach and which therefore is never silenced.
fn origin(peer: &Peer) -> Option<Origin> {
    match peer {
        Peer::Cli => None,
        Peer::Loopback | Peer::Unattributed { .. } => Some(Origin::Loopback),
        Peer::Adapter { manifest, .. } => Some(Origin::Adapter(manifest.manifest.id.clone())),
    }
}

/// How much quiet one silenced caller has left, forgetting it once the quiet has run out so a
/// single answer can never mute a caller for longer than the operator bought.
fn quiet_left(
    quiet: &mut HashMap<Origin, Instant>,
    origin: &Origin,
    now: Instant,
) -> Option<Duration> {
    let left = quiet.get(origin)?.saturating_duration_since(now);
    if left.is_zero() {
        quiet.remove(origin);
        return None;
    }
    Some(left)
}

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
    /// When each caller the operator silenced may be put in front of them again.
    quiet: Mutex<HashMap<Origin, Instant>>,
}

impl Approver {
    pub fn new(gate: UnlockGate, renderer: Arc<dyn Renderer>) -> Self {
        Self {
            gate,
            shown: AtomicU64::new(1),
            decision: Mutex::new(Decision::Deny),
            renderer,
            quiet: Mutex::new(HashMap::new()),
        }
    }

    /// How the operator left the last prompt, so a flood can be escaped between two of them.
    pub fn decision(&self) -> Decision {
        *self.decision.lock()
    }

    pub fn renderer(&self) -> &Arc<dyn Renderer> {
        &self.renderer
    }

    /// Put one request in front of the operator. The only request that does not reach them is one
    /// from a caller they themselves silenced within the last [`QUIET_PERIOD`]: every automatic
    /// refusal was removed, because on an unauthenticated listener the daemon cannot tell a flood
    /// from the operator's own service and would be refusing both.
    pub fn approve(
        &self,
        ctx: &OpContext,
        summary: &Summary,
    ) -> Result<Option<LaContext>, SignErr> {
        let origin = origin(&ctx.peer);
        if let Some(origin) = &origin {
            if let Some(left) = quiet_left(&mut self.quiet.lock(), origin, Instant::now()) {
                *self.decision.lock() = Decision::Deny;
                tracing::warn!(
                    peer = %ctx.peer,
                    op = ?ctx.op,
                    key = %ctx.key,
                    quiet_left_secs = left.as_secs(),
                    "refusing a request without a prompt: the operator silenced this caller"
                );
                return Err(SignErr::ApprovalDenied);
            }
        }
        let seq = self.shown.fetch_add(1, Ordering::Relaxed);
        let shown = match summary.alarms.is_empty() {
            true => summary.to_string(),
            false => format!("{summary}\n{}", summary.head(SHEET_LINES)),
        };
        let decision = self.renderer.ask(seq, ctx, &shown);
        *self.decision.lock() = decision;
        match decision {
            Decision::Approve => {}
            Decision::NoTerminal => return Err(SignErr::NoApprovalTerminal),
            Decision::Cancel => {
                if let Some(origin) = origin {
                    self.quiet
                        .lock()
                        .insert(origin, Instant::now() + QUIET_PERIOD);
                    tracing::warn!(
                        peer = %ctx.peer,
                        quiet_secs = QUIET_PERIOD.as_secs(),
                        "the operator asked not to be shown this caller's requests"
                    );
                }
                return Err(SignErr::ApprovalDenied);
            }
            Decision::Deny | Decision::Interrupt => return Err(SignErr::ApprovalDenied),
        }
        if self.gate == UnlockGate::Passphrase || ctx.op != Operation::Sign {
            return Ok(None);
        }
        let head = match summary.alarms.is_empty() {
            true => summary
                .body
                .lines()
                .take(SHEET_LINES)
                .collect::<Vec<_>>()
                .join("\n"),
            false => summary.head(SHEET_LINES),
        };
        Ok(Some(LaContext::evaluate_biometric(&format!(
            "#{seq} {}\n{head}",
            ctx.reason()
        ))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Quiet the operator bought must run out on its own and leave nothing behind, so no single
    /// answer can silence a caller for longer than the operator asked for.
    #[test]
    fn bought_quiet_lapses_by_itself() {
        let start = Instant::now();
        let mut quiet = HashMap::new();
        quiet.insert(Origin::Loopback, start + QUIET_PERIOD);

        assert_eq!(
            quiet_left(&mut quiet, &Origin::Loopback, start),
            Some(QUIET_PERIOD)
        );
        assert_eq!(
            quiet_left(&mut quiet, &Origin::Loopback, start + QUIET_PERIOD / 2),
            Some(QUIET_PERIOD / 2)
        );
        assert_eq!(
            quiet_left(&mut quiet, &Origin::Loopback, start + QUIET_PERIOD),
            None
        );
        assert!(
            quiet.is_empty(),
            "a lapsed quiet must be forgotten, not left to be re-read"
        );
        assert_eq!(
            quiet_left(&mut quiet, &Origin::Adapter("bot".to_string()), start),
            None,
            "silencing one caller may never silence another"
        );
    }

    fn nothing_to_read() -> Summary {
        Summary {
            alarms: Vec::new(),
            body: String::new(),
        }
    }

    /// Counts every prompt it was shown and answers all of them the same way.
    struct Counting {
        answer: Decision,
        asked: Mutex<usize>,
    }

    impl Renderer for Counting {
        fn ask(&self, _seq: u64, _ctx: &OpContext, _summary: &str) -> Decision {
            *self.asked.lock() += 1;
            self.answer
        }
        fn restore(&self) {}
    }

    fn counting(answer: Decision) -> (Arc<Counting>, Approver) {
        let counting = Arc::new(Counting {
            answer,
            asked: Mutex::new(0),
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

    /// The one prompt a request may not get is one from a caller the operator silenced at a
    /// prompt of their own. It silences that caller and nobody else: the operator's keyboard and
    /// every other socket keep their prompts.
    #[test]
    fn only_the_operator_can_buy_quiet_and_only_for_the_caller_they_answered() {
        let (counting, approver) = counting(Decision::Cancel);
        assert!(matches!(
            approver.approve(&remote("TRADER"), &nothing_to_read()),
            Err(SignErr::ApprovalDenied)
        ));
        assert_eq!(*counting.asked.lock(), 1);

        for _ in 0..64 {
            assert!(matches!(
                approver.approve(&remote("TRADER"), &nothing_to_read()),
                Err(SignErr::ApprovalDenied)
            ));
        }
        assert_eq!(
            *counting.asked.lock(),
            1,
            "the operator asked for quiet and must get it"
        );

        let local = OpContext::local("TRADER".to_string(), Operation::EvmAddress);
        for shown in 2..=17 {
            assert!(matches!(
                approver.approve(&local, &nothing_to_read()),
                Err(SignErr::ApprovalDenied)
            ));
            assert_eq!(*counting.asked.lock(), shown);
        }

        approver.quiet.lock().clear();
        assert!(matches!(
            approver.approve(&remote("TRADER"), &nothing_to_read()),
            Err(SignErr::ApprovalDenied)
        ));
        assert_eq!(
            *counting.asked.lock(),
            18,
            "once the quiet lapses the caller is heard again"
        );
    }

    /// A tunnelled loopback client and a plain one are the same unauthenticated transport, so
    /// they must share one budget rather than doubling it by opening a tunnel.
    #[test]
    fn tunnelled_loopback_shares_the_loopback_budget() {
        assert_eq!(
            origin(&Peer::Loopback),
            origin(&Peer::Unattributed { tunnels: 2 })
        );
        assert_eq!(origin(&Peer::Cli), None);
    }
}
