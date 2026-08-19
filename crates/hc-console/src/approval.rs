//! The main thread's privileged-op loop. It owns Touch ID and the DEK, so every operation a
//! connection task forwarded is executed here and only here.
use super::renderer::Terminal;
use super::status::BandCache;
use super::Key;
use crossterm::style::Print;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use crossterm::{cursor, execute};
use err_mac::create_err_with_impls;
use hc_daemon::approval::Approver;
use hc_daemon::exposure::TunnelManager;
use hc_daemon::live::Live;
use hc_daemon::renderer::{Decision, Renderer};
use hc_daemon::runtime::{service_one, Outcome};
use hc_daemon::{HotApi, OpErr, PrivilegedOp};
use std::io;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

create_err_with_impls!(
    #[derive(Debug)]
    pub ApprovalErr,
    ListenerGone,
    ShutdownRequested,
    NoApprovalTerminal,
    Grant(hc_sign::grant::GrantErr),
    StdIo(io::Error)
    ;
);

/// Requests one drain pass may put in front of the operator. A freed queue slot refills at
/// once, so this — not the queue depth — is what keeps a flood from owning the terminal.
const PROMPTS_PER_DRAIN: usize = 2;

/// What the drain loops do after one prompt.
pub(crate) enum After {
    Continue,
    Stop,
    Leave,
    /// The prompt could not be shown at all, which is not an answer and not an ending the
    /// operator chose: it ends the session loudly, the way the menu ends on the same cause.
    Fail,
}

/// Written once so `NoTerminal` cannot be classified one way here and another way there.
pub(crate) fn after(decision: Decision) -> After {
    match decision {
        Decision::Approve | Decision::Deny => After::Continue,
        Decision::Cancel => After::Stop,
        Decision::NoTerminal => After::Fail,
        Decision::Interrupt => After::Leave,
    }
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
    approver: &Approver,
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
        match after(approver.decision()) {
            After::Stop => break,
            After::Leave => {
                drained.quit = true;
                break;
            }
            After::Fail => {
                refuse_queued(ops);
                return Err(ApprovalErr::NoApprovalTerminal);
            }
            After::Continue => {}
        }
    }
    drained.refused = refuse_queued(ops);
    Ok(drained)
}

/// Raw mode and the hidden cursor of a live screen, restored on every exit path.
pub(crate) struct RawScreen;

impl Drop for RawScreen {
    fn drop(&mut self) {
        Terminal.restore();
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

fn draw(tally: &Tally, serving: &str, tunnels: usize, band: &str) -> Result<(), io::Error> {
    let last = match &tally.last {
        Some(line) => line.as_str(),
        None => "none yet",
    };
    let panel = format!(
        "hot_cheese - serve and approve\r\n\r\n  \
         serving {serving}   tunnels open: {tunnels}\r\n  \
         {band}\r\n  \
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
///
/// The band ticks once per pass, whatever woke the pass, so a background task publishing while
/// nothing is arriving still repaints the frame.
pub fn serve_and_approve(
    api: &HotApi,
    approver: &Approver,
    ops: &mut mpsc::Receiver<PrivilegedOp>,
    serving: &str,
    tunnels: &TunnelManager,
    live: &Live,
) -> Result<(), ApprovalErr> {
    enable_raw_mode()?;
    let _screen = RawScreen;
    let mut tally = Tally::default();
    let mut band = BandCache::default();
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
                match after(approver.decision()) {
                    After::Stop => {
                        refuse_queued(ops);
                        return Ok(());
                    }
                    After::Leave => {
                        refuse_queued(ops);
                        return Err(ApprovalErr::ShutdownRequested);
                    }
                    After::Fail => {
                        refuse_queued(ops);
                        return Err(ApprovalErr::NoApprovalTerminal);
                    }
                    After::Continue => {}
                }
            }
            Err(TryRecvError::Disconnected) => return Err(ApprovalErr::ListenerGone),
            Err(TryRecvError::Empty) => {}
        }
        if band.tick(live)? {
            dirty = true;
        }
        if dirty {
            draw(&tally, serving, tunnels.list().len(), band.line())?;
            dirty = false;
        }
        match super::tick()? {
            Key::Quit => return Err(ApprovalErr::ShutdownRequested),
            Key::Leave => return Ok(()),
            Key::Redraw => dirty = true,
            Key::Other(_) | Key::Ignore => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::crypto::envelope::{encrypt_file, Dek, KeyUse};
    use hc_core::mac::local_auth::LaContext;
    use hc_core::mac::BackendImpl;
    use hc_core::unlock::UnlockErr;
    use hc_daemon::runtime::UnlockGate;
    use hc_daemon::{OpContext, Operation, Peer, PENDING_OPS};
    use hc_sign::SignErr;
    use hyper::body::Bytes;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    const POLICY: &str = concat!(
        "safe = \"0x1111111111111111111111111111111111111111\"\n",
        "chain_id = 1\n",
        "\n",
        "[[allow]]\n",
        "to = \"0x2222222222222222222222222222222222222222\"\n",
        "max_value = \"0\"\n",
        "operation = \"call\"\n",
        "\n",
        "  [[allow.call]]\n",
        "  signature = \"transfer(address,uint256)\"\n",
        "\n",
        "    [[allow.call.arg]]\n",
        "    at = 0\n",
        "    name = \"to\"\n",
        "    rule = \"unbounded\"\n",
        "\n",
        "    [[allow.call.arg]]\n",
        "    at = 1\n",
        "    name = \"amount\"\n",
        "    rule = \"unbounded\"\n",
    );

    const INTENT: &str = concat!(
        "{\"kind\":\"safe_tx\",\"key\":\"CONSOLE_DRAIN\",",
        "\"safe\":\"0x1111111111111111111111111111111111111111\",",
        "\"chain_id\":1,\"to\":\"0x2222222222222222222222222222222222222222\",",
        "\"value\":\"0\",\"data\":\"0xa9059cbb0000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000a\",\"operation\":\"call\",\"nonce\":0}"
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

    /// Answers every request the way the operator would have, without touching the terminal.
    struct Stub {
        decision: Decision,
    }
    impl Renderer for Stub {
        fn ask(&self, _seq: u64, _ctx: &OpContext, _summary: &str) -> Decision {
            self.decision
        }
        fn restore(&self) {}
    }

    fn stub(decision: Decision) -> Approver {
        Approver::new(UnlockGate::Biometric, Arc::new(Stub { decision }))
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
        encrypt_file(
            dir,
            "CONSOLE_DRAIN",
            &Dek::from_bytes([9u8; 32]),
            KeyUse::SignOnly,
            &[0x33u8; 32],
        )
        .expect("write the keystore");
        let store = dir.to_string_lossy().to_string();
        let api = HotApi::new(
            Box::new(FakeBackend {
                store: store.clone(),
            }),
            hc_core::config::Config::for_test(&store),
        );
        let (tx, ops) = mpsc::channel(PENDING_OPS);
        let mut answers = Vec::new();
        let pending = Arc::new(hc_daemon::live::Pending::default());
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
                outstanding: hc_daemon::live::Outstanding::new(pending.clone()),
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
            &stub(Decision::Deny),
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
                &stub(decision),
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
