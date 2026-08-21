//! The terminal renderer: the operator's yes/no on the stream inquire prompts on, and the raw
//! mode and hidden cursor undone on every ending.
//!
//! The daemon's headless prompt and this one gate the same privileged operations, so both are
//! built from the same three pieces of [`hc_daemon::renderer`]: the log gate an unanswered
//! request holds, the floor a keystroke has to clear before it counts as consent, and the rule
//! that makes a prompt which REPLACED an unanswered one answerable only by its own number.
use crossterm::terminal::disable_raw_mode;
use crossterm::{cursor, execute};
use hc_daemon::renderer::{interpret, Decision, OnScreen, Renderer, MIN_PROMPT_DISPLAY};
use hc_daemon::OpContext;
use parking_lot::Mutex;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Whether the prompt before this one ended without an answer the operator can be shown to have
/// given to it. One session owns one terminal, so the run belongs to the terminal and not to a
/// caller.
static STARTLED: AtomicBool = AtomicBool::new(false);

/// What one line meant for the request it was read against.
#[derive(Clone, Copy, Debug)]
struct Answer {
    /// What is to be done with the request.
    decision: Decision,
    /// Whether the line carried that request's own number.
    attributed: bool,
}

/// What one line submitted at a prompt produced.
#[derive(Clone, Copy, Debug)]
enum Taken {
    /// The line was read against the request on screen.
    Read(Answer),
    /// The line landed before the request could have been read, so it is not an answer to it.
    TooSoon,
}

/// One request in front of the operator: it holds the log gate for as long as that request is
/// unanswered, and reads a typed line the way the headless prompt reads one.
struct Prompt<'a> {
    /// The request the operator is being asked about.
    seq: u64,
    /// Whether this prompt replaced one that ended without an answer given to it.
    startled: bool,
    /// When the request reached the operator's screen.
    shown: Instant,
    /// The terminal's run of startled prompts, ended only by an attributable answer.
    run: &'a AtomicBool,
    /// Defers every peer-caused log line until the operator has the screen back.
    _on_screen: OnScreen,
}

impl<'a> Prompt<'a> {
    fn new(seq: u64, run: &'a AtomicBool) -> Self {
        Self {
            seq,
            startled: run.swap(true, Ordering::Relaxed),
            shown: Instant::now(),
            run,
            _on_screen: OnScreen::new(seq),
        }
    }

    /// The request as the operator reads it, above the line inquire draws.
    fn request(&self, summary: &str) -> String {
        let seq = self.seq;
        let legend = match self.startled {
            true => format!(
                "y{seq} = approve request #{seq}   q{seq} = deny it and everything already \
                 queued\nanything that does not carry #{seq} = deny\n"
            ),
            false => {
                "y = approve   q = deny this and everything already queued   anything else = \
                 deny\n"
                    .to_string()
            }
        };
        format!(
            "\n{startle}=== hot_cheese request #{seq} ===\n{body}{legend}",
            startle = match self.startled {
                true => "*** THE SCREEN CHANGED: the request you were reading ended WITHOUT your \
                         answer. This is a different request, and only an answer carrying its own \
                         number can approve it. ***\n",
                false => "",
            },
            body = match summary.is_empty() {
                true => String::new(),
                false => format!("{summary}\n"),
            }
        )
    }

    /// What an empty submission means, drawn by inquire beside the question.
    fn hint(&self) -> String {
        match self.startled {
            true => format!("y{}/N", self.seq),
            false => "y/N".to_string(),
        }
    }

    /// Read one submitted line against the request on screen. A line that lands before the
    /// request could have been read is refused rather than consumed, so the keys typed at the
    /// prompt before this one buy nothing here.
    fn take(&self, line: &str) -> Taken {
        if self.shown.elapsed() < MIN_PROMPT_DISPLAY {
            return Taken::TooSoon;
        }
        let (decision, attributed) = interpret(line, self.seq, self.startled);
        Taken::Read(Answer {
            decision,
            attributed,
        })
    }

    /// End this prompt. Only a line the operator can be shown to have composed for THIS request
    /// ends a startled run; every other ending, including one nobody answered, leaves the next
    /// prompt answerable by its own number alone.
    fn ended(&self, attributed: bool) {
        self.run
            .store(self.startled && !attributed, Ordering::Relaxed);
    }
}

/// Asks in the console. The terminal must be in cooked mode, and the request and the question
/// about it go to the same stream, so a redirect cannot separate them.
pub struct Terminal;

impl Renderer for Terminal {
    fn ask(&self, seq: u64, ctx: &OpContext, summary: &str) -> Decision {
        let mut prompt = Prompt::new(seq, &STARTLED);
        let mut out = io::stderr();
        let request = prompt.request(summary);
        if let Err(e) = out
            .write_all(request.as_bytes())
            .and_then(|()| out.flush())
        {
            tracing::warn!(error = %e, key = %ctx.key, "could not show the request");
            return Decision::Cancel;
        }
        prompt.shown = Instant::now();
        let hint = prompt.hint();
        let too_soon =
            format!("that answer landed before request #{seq} was readable and was not used");
        let recorded = Mutex::new(Answer {
            decision: Decision::Deny,
            attributed: false,
        });
        let read = |line: &str| -> Result<bool, ()> {
            match prompt.take(line) {
                Taken::TooSoon => Err(()),
                Taken::Read(answer) => {
                    *recorded.lock() = answer;
                    Ok(answer.decision == Decision::Approve)
                }
            }
        };
        let empty = |_: bool| hint.clone();
        let message = format!("#{seq} {} - approve?", ctx.reason());
        let answered = inquire::Confirm::new(&message)
            .with_default(false)
            .with_parser(&read)
            .with_default_value_formatter(&empty)
            .with_error_message(&too_soon)
            .prompt();
        let answer = *recorded.lock();
        match answered {
            Ok(_) => {
                prompt.ended(answer.attributed);
                if prompt.startled && !answer.attributed {
                    tracing::warn!(
                        seq,
                        key = %ctx.key,
                        "an answer that did not carry the request number denied it"
                    );
                }
                answer.decision
            }
            Err(inquire::InquireError::OperationCanceled) => {
                prompt.ended(false);
                Decision::Cancel
            }
            Err(inquire::InquireError::OperationInterrupted) => {
                prompt.ended(false);
                Decision::Interrupt
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use hc_daemon::renderer::{peer_may_log, SCREEN};
    use std::sync::Arc;
    use tracing_subscriber::fmt::MakeWriter;

    /// A kind no other test in this binary produces, so the count one prompt defers is this
    /// test's own however the rest of the suite is scheduled.
    const PROBE: &str = "console_prompt_probe";

    /// Peer-caused lines one prompt is made to hold back.
    const FLOOD: usize = 10_000;

    /// Everything one subscriber wrote, readable after it is gone.
    #[derive(Clone)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Move the prompt back past the display floor, so what a line means is decided by what it
    /// carries and never by how long the operator took to type it.
    fn readable(prompt: &mut Prompt) {
        prompt.shown = prompt
            .shown
            .checked_sub(MIN_PROMPT_DISPLAY * 8)
            .expect("the process is older than the display floor");
    }

    /// The console prompt is the same authorization mechanism as the headless one, so it must
    /// hold the same log gate: while it waits, a peer's lines are deferred under their kind
    /// rather than written, and the screen coming back reports what was held and how fast.
    #[test]
    fn peer_lines_are_deferred_while_a_console_prompt_waits_and_reported_on_release() {
        let _screen = SCREEN.lock();
        let run = AtomicBool::new(false);
        let written = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(Captured(written.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            assert!(peer_may_log(PROBE), "nothing is on screen yet");
            let prompt = Prompt::new(4, &run);
            for _ in 0..FLOOD {
                assert!(
                    !peer_may_log(PROBE),
                    "a peer wrote to the screen the request is on"
                );
            }
            drop(prompt);
            assert!(peer_may_log(PROBE), "the screen is the operator's again");
        });

        let seen = String::from_utf8_lossy(&written.lock()).into_owned();
        assert!(
            seen.contains(PROBE) && seen.contains(&format!("lines={FLOOD}")),
            "what the peer caused while the prompt waited must be reported: {seen:?}"
        );
    }

    /// A keystroke typed before the request could have been read is not consent: it is refused
    /// and the prompt stays up, and the same line clears once the request has been on screen.
    #[test]
    fn an_answer_landing_before_the_display_floor_is_not_taken_as_consent() {
        let _screen = SCREEN.lock();
        let run = AtomicBool::new(false);
        let prompt = Prompt::new(5, &run);
        assert!(
            matches!(prompt.take("y"), Taken::TooSoon),
            "an answer at a request that went up microseconds ago is not an informed one"
        );
        std::thread::sleep(MIN_PROMPT_DISPLAY);
        assert!(
            matches!(
                prompt.take("y"),
                Taken::Read(Answer {
                    decision: Decision::Approve,
                    ..
                })
            ),
            "the operator's own answer must still be taken"
        );
    }

    /// The whole run, not one line from it: a prompt nobody answered leaves the next one
    /// answerable by its own number alone, every line the operator could have composed for the
    /// request that expired denies it however long they took, only the line carrying this
    /// request's number approves it and ends the run, and the prompt after that takes a plain
    /// `y` again. The floor cannot establish any of this — it only moves the window.
    #[test]
    fn a_prompt_that_replaced_an_unanswered_one_is_answered_only_by_its_own_number() {
        let _screen = SCREEN.lock();
        let run = AtomicBool::new(false);

        let unanswered = Prompt::new(1, &run);
        assert!(!unanswered.startled, "the first prompt replaced nothing");
        drop(unanswered);

        let mut replaced = Prompt::new(2, &run);
        assert!(replaced.startled, "this prompt replaced an unanswered one");
        assert_eq!(replaced.hint(), "y2/N");
        assert!(replaced.request("").contains("THE SCREEN CHANGED"));
        readable(&mut replaced);
        for stale in ["y", "Y", " y ", "yes", "y1", "y22"] {
            assert!(
                matches!(
                    replaced.take(stale),
                    Taken::Read(Answer {
                        decision: Decision::Deny,
                        attributed: false
                    })
                ),
                "{stale:?} was composed for the request that expired and approved the one that \
                 replaced it"
            );
        }
        replaced.ended(false);
        assert!(
            run.load(Ordering::Relaxed),
            "an answer that carried no number must not end the startled run"
        );

        let mut still_startled = Prompt::new(3, &run);
        assert!(still_startled.startled);
        readable(&mut still_startled);
        let carried = still_startled.take("y3");
        assert!(
            matches!(
                carried,
                Taken::Read(Answer {
                    decision: Decision::Approve,
                    attributed: true
                })
            ),
            "the line carrying this request's own number must approve it: {carried:?}"
        );
        still_startled.ended(true);
        assert!(
            !run.load(Ordering::Relaxed),
            "an attributable answer must end the startled run"
        );

        let mut plain = Prompt::new(4, &run);
        assert!(!plain.startled, "the run ended, so this prompt is plain");
        assert_eq!(plain.hint(), "y/N");
        assert!(!plain.request("").contains("THE SCREEN CHANGED"));
        readable(&mut plain);
        assert!(
            matches!(
                plain.take("y"),
                Taken::Read(Answer {
                    decision: Decision::Approve,
                    attributed: false
                })
            ),
            "the ordinary case must stay a plain y"
        );
        plain.ended(false);
    }
}
