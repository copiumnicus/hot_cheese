//! The main thread's privileged-op loop. It owns Touch ID and the DEK, so every operation a
//! connection task forwarded is executed here and only here.
use super::exposure::TunnelManager;
use super::UnlockGate;
use crate::mac::local_auth::LaContext;
use crate::server::{self, Approver, HotApi, OpContext, OpErr, Operation, PrivilegedOp};
use crate::sign::SignErr;
use crossterm::event::{Event, KeyCode, KeyModifiers};
use crossterm::style::Print;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use crossterm::{cursor, execute};
use err_mac::create_err_with_impls;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

create_err_with_impls!(
    #[derive(Debug)]
    pub ApprovalErr,
    ListenerGone,
    ShutdownRequested,
    Inquire(inquire::InquireError),
    Sign(SignErr),
    StdIo(io::Error)
    ;
);

/// How long the serve screen waits on the keyboard before looking for a new request.
const TICK: Duration = Duration::from_millis(120);

/// Requests one drain pass may put in front of the operator. A freed queue slot refills at
/// once, so this — not the queue depth — is what keeps a flood from owning the terminal.
const PROMPTS_PER_DRAIN: usize = 2;

/// Hex characters of the body digest shown at the prompt.
const DIGEST_CHARS: usize = 16;

/// What the operator did at one approval prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Answered yes.
    Approve,
    /// Answered no.
    Deny,
    /// Esc, or a prompt that could not be shown: deny, and stop pulling requests.
    Cancel,
    /// Ctrl-C, which inquire consumes in raw mode: deny, and leave the console.
    Interrupt,
}

/// The approver the drain loop drives. It also reports how the operator left the last prompt,
/// so Esc and Ctrl-C escape a flood instead of handing over the next request.
pub trait DrainApprover: Approver {
    fn decision(&self) -> Decision;
}

/// Asks the operator in the console, then takes the single biometric the enclave op reuses —
/// only for a sign under the Secure Enclave gate, which is the one flow that reuses it.
pub struct ConsoleApprover {
    /// Which KEK opened this session: a passphrase session has no per-request biometric.
    gate: UnlockGate,
    /// Prompts shown this session, so no two prompts are byte-identical.
    shown: AtomicU64,
    /// How the operator left the last prompt.
    decision: Mutex<Decision>,
}

impl ConsoleApprover {
    pub fn new(gate: UnlockGate) -> Self {
        Self {
            gate,
            shown: AtomicU64::new(1),
            decision: Mutex::new(Decision::Deny),
        }
    }

    /// Show one request and take the operator's yes/no. The terminal must be in cooked mode,
    /// and everything is written to the stream inquire prompts on so a redirect cannot
    /// separate the decoded action from the question about it.
    fn ask(&self, ctx: &OpContext, summary: &str) -> Decision {
        let seq = self.shown.fetch_add(1, Ordering::Relaxed);
        let decision = match show(seq, summary) {
            Ok(()) => {
                let message = format!("#{seq} {} - approve?", ctx.reason());
                match inquire::Confirm::new(&message).with_default(false).prompt() {
                    Ok(true) => Decision::Approve,
                    Ok(false) => Decision::Deny,
                    Err(inquire::InquireError::OperationCanceled) => Decision::Cancel,
                    Err(inquire::InquireError::OperationInterrupted) => Decision::Interrupt,
                    Err(e) => {
                        tracing::warn!(error = %e, key = %ctx.key, "approval prompt failed");
                        Decision::Cancel
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, key = %ctx.key, "could not show the request");
                Decision::Cancel
            }
        };
        *self.decision.lock() = decision;
        decision
    }
}

impl Approver for ConsoleApprover {
    fn approve(&self, ctx: &OpContext, summary: &str) -> Result<Option<LaContext>, SignErr> {
        if self.ask(ctx, summary) != Decision::Approve {
            return Err(SignErr::ApprovalDenied);
        }
        if self.gate == UnlockGate::Passphrase || ctx.op != Operation::Sign {
            return Ok(None);
        }
        let head = summary.lines().next().unwrap_or_default();
        let reason = if head.is_empty() {
            ctx.reason()
        } else {
            format!("{}\n{head}", ctx.reason())
        };
        Ok(Some(LaContext::evaluate_biometric(&reason)?))
    }
}

impl DrainApprover for ConsoleApprover {
    fn decision(&self) -> Decision {
        *self.decision.lock()
    }
}

/// Write the request above the prompt, on the same stream inquire uses.
fn show(seq: u64, summary: &str) -> Result<(), io::Error> {
    let mut out = io::stderr();
    writeln!(out, "\n=== hot_cheese request #{seq} ===")?;
    if !summary.is_empty() {
        writeln!(out, "{summary}")?;
    }
    out.flush()
}

/// Names the exact bytes a body-carrying route was asked to act on, so two prompts from a
/// flood are never the same line twice.
fn body_digest(body: &[u8]) -> String {
    let full = hex::encode(Sha256::digest(body));
    full.chars().take(DIGEST_CHARS).collect()
}

/// How one serviced request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Approved,
    Denied,
    Failed,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Outcome::Approved => "approved",
            Outcome::Denied => "denied",
            Outcome::Failed => "failed",
        })
    }
}

/// Run one queued request on this thread and answer its reply channel exactly once.
fn service_one(api: &HotApi, approver: &dyn DrainApprover, op: PrivilegedOp) -> Outcome {
    let PrivilegedOp { ctx, body, reply } = op;
    let result = match ctx.op {
        Operation::Sign => server::execute(api, approver, &ctx, &body),
        _ => {
            let summary = if body.is_empty() {
                String::new()
            } else {
                format!("request body sha256 {}", body_digest(&body))
            };
            match approver.approve(&ctx, &summary) {
                Ok(_) => server::execute(api, approver, &ctx, &body),
                Err(e) => Err(OpErr::Sign(e)),
            }
        }
    };
    let outcome = match &result {
        Ok(_) => Outcome::Approved,
        Err(OpErr::Denied | OpErr::Sign(SignErr::ApprovalDenied)) => Outcome::Denied,
        Err(e) => {
            tracing::error!(error = ?e, key = %ctx.key, "operation failed");
            Outcome::Failed
        }
    };
    if reply.send(result).is_err() {
        tracing::warn!(key = %ctx.key, "caller disconnected before its answer");
    }
    outcome
}

/// Deny every request still queued, without a prompt. Nothing may be left hanging when a pass
/// ends, and a flood must never cost more than [`PROMPTS_PER_DRAIN`] approvals.
pub fn refuse_queued(ops: &mut mpsc::Receiver<PrivilegedOp>) -> usize {
    let mut refused = 0;
    while let Ok(op) = ops.try_recv() {
        let _ = op.reply.send(Err(OpErr::Denied));
        refused += 1;
    }
    if refused > 0 {
        tracing::warn!(refused, "denied queued requests without prompting");
    }
    refused
}

/// What one drain pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Drained {
    /// Requests the operator answered at a prompt.
    pub answered: usize,
    /// Requests denied without a prompt: the pass was full, or the operator escaped.
    pub refused: usize,
    /// Whether the operator asked to leave the console at a prompt.
    pub quit: bool,
}

/// Answer what is queued, at most [`PROMPTS_PER_DRAIN`] of it through the operator; whatever
/// is left over is denied unprompted so the terminal always comes back.
pub fn drain(
    api: &HotApi,
    approver: &dyn DrainApprover,
    ops: &mut mpsc::Receiver<PrivilegedOp>,
    tunnels: &TunnelManager,
) -> Result<Drained, ApprovalErr> {
    let mut drained = Drained::default();
    while drained.answered < PROMPTS_PER_DRAIN {
        let mut op = match ops.try_recv() {
            Ok(op) => op,
            Err(TryRecvError::Empty) => return Ok(drained),
            Err(TryRecvError::Disconnected) => return Err(ApprovalErr::ListenerGone),
        };
        op.ctx.peer = op.ctx.peer.with_tunnels(tunnels.list().len());
        let reason = op.ctx.reason();
        let outcome = service_one(api, approver, op);
        drained.answered += 1;
        tracing::info!(%outcome, %reason, "serviced a queued request");
        match approver.decision() {
            Decision::Cancel => break,
            Decision::Interrupt => {
                drained.quit = true;
                break;
            }
            Decision::Approve | Decision::Deny => {}
        }
    }
    drained.refused = refuse_queued(ops);
    Ok(drained)
}

/// Raw mode and the hidden cursor of the serve screen, restored on every exit path.
struct RawScreen;

impl Drop for RawScreen {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stderr(), cursor::Show);
    }
}

/// What the serve screen has done since it opened.
#[derive(Default)]
struct Tally {
    /// Requests executed after approval.
    approved: usize,
    /// Requests the operator refused.
    denied: usize,
    /// Requests that failed on their own.
    failed: usize,
    /// The last request serviced, already formatted.
    last: Option<String>,
}

fn draw(tally: &Tally, addr: SocketAddr, tunnels: usize) -> Result<(), io::Error> {
    let last = match &tally.last {
        Some(line) => line.as_str(),
        None => "none yet",
    };
    let panel = format!(
        "hot_cheese - serve and approve\r\n\r\n  \
         serving https://{addr}   tunnels open: {tunnels}\r\n  \
         approved {} | denied {} | failed {}\r\n  \
         last: {last}\r\n\r\n  \
         waiting for requests   [q] menu   [ctrl-c] shut down\r\n",
        tally.approved, tally.denied, tally.failed
    );
    execute!(
        io::stderr(),
        cursor::Hide,
        cursor::MoveTo(0, 0),
        Clear(ClearType::FromCursorDown),
        Print(panel)
    )
}

/// Stay on this thread approving incoming ops until the operator stops serving. Every
/// serviced request is followed by a keyboard poll, so `q` is reachable between any two
/// prompts, and escaping a prompt leaves the screen with the rest of the queue denied.
pub fn serve_and_approve(
    api: &HotApi,
    approver: &dyn DrainApprover,
    ops: &mut mpsc::Receiver<PrivilegedOp>,
    addr: SocketAddr,
    tunnels: &TunnelManager,
) -> Result<(), ApprovalErr> {
    enable_raw_mode()?;
    let _screen = RawScreen;
    let mut tally = Tally::default();
    let mut dirty = true;
    loop {
        match ops.try_recv() {
            Ok(mut op) => {
                op.ctx.peer = op.ctx.peer.with_tunnels(tunnels.list().len());
                let reason = op.ctx.reason();
                let cooked = disable_raw_mode();
                let outcome = service_one(api, approver, op);
                cooked?;
                enable_raw_mode()?;
                match outcome {
                    Outcome::Approved => tally.approved += 1,
                    Outcome::Denied => tally.denied += 1,
                    Outcome::Failed => tally.failed += 1,
                }
                tally.last = Some(format!("{outcome}: {reason}"));
                dirty = true;
                match approver.decision() {
                    Decision::Cancel => {
                        refuse_queued(ops);
                        return Ok(());
                    }
                    Decision::Interrupt => {
                        refuse_queued(ops);
                        return Err(ApprovalErr::ShutdownRequested);
                    }
                    Decision::Approve | Decision::Deny => {}
                }
            }
            Err(TryRecvError::Disconnected) => return Err(ApprovalErr::ListenerGone),
            Err(TryRecvError::Empty) => {}
        }
        if dirty {
            draw(&tally, addr, tunnels.list().len())?;
            dirty = false;
        }
        if !crossterm::event::poll(TICK)? {
            continue;
        }
        match crossterm::event::read()? {
            Event::Key(key) => match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Err(ApprovalErr::ShutdownRequested)
                }
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                _ => {}
            },
            Event::Resize(_, _) => dirty = true,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::envelope::Dek;
    use crate::server::{BackendImpl, Peer, PENDING_OPS};
    use crate::unlock::UnlockErr;
    use hyper::body::Bytes;
    use tokio::sync::oneshot;

    const POLICY: &str = concat!(
        "safe = \"0x1111111111111111111111111111111111111111\"\n",
        "chain_id = 1\n",
        "\n",
        "[[allow]]\n",
        "to = \"0x2222222222222222222222222222222222222222\"\n",
        "selectors = [\"0xa9059cbb\"]\n",
        "max_value = \"0\"\n",
        "operation = \"call\"\n",
    );

    const INTENT: &str = concat!(
        "{\"kind\":\"safe_tx\",\"key\":\"CONSOLE_DRAIN\",",
        "\"safe\":\"0x1111111111111111111111111111111111111111\",",
        "\"chain_id\":1,\"to\":\"0x2222222222222222222222222222222222222222\",",
        "\"value\":\"0\",\"data\":\"0xa9059cbb\",\"operation\":\"call\",\"nonce\":0}"
    );

    struct FakeBackend {
        store: String,
    }
    impl BackendImpl for FakeBackend {
        fn unlock_dek(&self, _reason: &str, _auth: Option<&LaContext>) -> Result<Dek, UnlockErr> {
            Ok(Dek::from_bytes([9u8; 32]))
        }
        fn store(&self) -> &str {
            &self.store
        }
    }

    /// Refuses every request the way the operator would have, without touching the terminal.
    struct Stub {
        decision: Decision,
    }
    impl Approver for Stub {
        fn approve(&self, _ctx: &OpContext, _summary: &str) -> Result<Option<LaContext>, SignErr> {
            Err(SignErr::ApprovalDenied)
        }
    }
    impl DrainApprover for Stub {
        fn decision(&self) -> Decision {
            self.decision
        }
    }

    /// A store, a full queue of sign requests, and the caller side of every one of them.
    struct Queued {
        api: HotApi,
        /// Held open so an emptied queue still reads as `Empty`, not `Disconnected`.
        _live: mpsc::Sender<PrivilegedOp>,
        ops: mpsc::Receiver<PrivilegedOp>,
        answers: Vec<oneshot::Receiver<Result<Vec<u8>, OpErr>>>,
    }

    fn queue(dir: &std::path::Path) -> Queued {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir.join("policies")).expect("make the store");
        std::fs::write(dir.join("policies").join("CONSOLE_DRAIN.toml"), POLICY)
            .expect("write the policy");
        let api = HotApi::new(Box::new(FakeBackend {
            store: dir.to_string_lossy().to_string(),
        }));
        let (tx, ops) = mpsc::channel(PENDING_OPS);
        let mut answers = Vec::new();
        for _ in 0..PENDING_OPS {
            let (reply, answer) = oneshot::channel();
            tx.try_send(PrivilegedOp {
                ctx: OpContext {
                    key: "CONSOLE_DRAIN".to_string(),
                    op: Operation::Sign,
                    peer: Peer::Loopback,
                },
                body: Bytes::from_static(INTENT.as_bytes()),
                reply,
            })
            .expect("the queue holds PENDING_OPS");
            answers.push(answer);
        }
        Queued {
            api,
            _live: tx,
            ops,
            answers,
        }
    }

    fn all_denied(answers: Vec<oneshot::Receiver<Result<Vec<u8>, OpErr>>>) {
        for mut answer in answers {
            let answered = answer.try_recv().expect("every op is answered");
            assert!(
                matches!(
                    answered,
                    Err(OpErr::Denied | OpErr::Sign(SignErr::ApprovalDenied))
                ),
                "every op must come back to its caller as a typed denial"
            );
        }
    }

    /// A flood must not own the terminal: one pass prompts for at most `PROMPTS_PER_DRAIN`
    /// requests, denies everything left queued without prompting, and leaves the queue empty
    /// so no HTTP caller hangs.
    #[test]
    fn a_drain_pass_bounds_prompts_and_denies_the_rest() {
        let dir = std::env::temp_dir().join("hot_cheese_console_drain_bound");
        let mut queued = queue(&dir);

        let drained = drain(
            &queued.api,
            &Stub {
                decision: Decision::Deny,
            },
            &mut queued.ops,
            &TunnelManager::new(),
        )
        .expect("a live queue drains");

        assert_eq!(
            drained,
            Drained {
                answered: PROMPTS_PER_DRAIN,
                refused: PENDING_OPS - PROMPTS_PER_DRAIN,
                quit: false
            }
        );
        all_denied(queued.answers);
        assert!(matches!(queued.ops.try_recv(), Err(TryRecvError::Empty)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Escaping a prompt must end the pass immediately and still fail closed: the request at
    /// the prompt and every one behind it are denied, and Ctrl-C additionally leaves.
    #[test]
    fn escaping_a_prompt_stops_the_pass_and_still_answers_everyone() {
        for (decision, quit) in [(Decision::Cancel, false), (Decision::Interrupt, true)] {
            let dir = std::env::temp_dir().join("hot_cheese_console_drain_escape");
            let mut queued = queue(&dir);

            let drained = drain(
                &queued.api,
                &Stub { decision },
                &mut queued.ops,
                &TunnelManager::new(),
            )
            .expect("a live queue drains");

            assert_eq!(
                drained,
                Drained {
                    answered: 1,
                    refused: PENDING_OPS - 1,
                    quit
                }
            );
            all_denied(queued.answers);
            assert!(matches!(queued.ops.try_recv(), Err(TryRecvError::Empty)));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
