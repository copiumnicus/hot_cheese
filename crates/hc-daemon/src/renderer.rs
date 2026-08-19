//! The half of the front end a privileged operation touches: asking the human, keeping the
//! screen they answer from legible, and giving the terminal back on every ending.
use crate::approval::QUIET_PERIOD;
use crate::OpContext;
use std::io::{IsTerminal, Write};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_APPROVAL_ANSWER_BYTES: usize = 16;

/// How long one prompt waits for an answer before denying itself. The caller chooses when a
/// prompt appears, so an unanswered one may not hold the single approval thread open for it.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a prompt is on screen before a keystroke counts as an answer to it. The caller and
/// not the operator decides which request is on screen, so an answer arriving inside this window
/// is reported and asked again rather than used — and never dropped in silence.
const MIN_PROMPT_DISPLAY: Duration = Duration::from_millis(400);

/// Whether an approval prompt is on the operator's screen with no answer yet.
static PROMPT_ON_SCREEN: AtomicBool = AtomicBool::new(false);

/// Lines an unauthenticated peer caused that were held back while a prompt was on screen.
static HELD_BACK: AtomicU64 = AtomicU64::new(0);

/// Whether a line an unauthenticated peer caused may reach the operator's screen. The prompt IS
/// the authorization mechanism here, so a peer that can scroll it away is attacking the control
/// itself: while one waits the line is counted instead of written, and the count is reported in
/// one line once the screen is the operator's again.
pub fn peer_may_log() -> bool {
    if PROMPT_ON_SCREEN.load(Ordering::Relaxed) {
        HELD_BACK.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    true
}

/// Owns [`PROMPT_ON_SCREEN`] for exactly as long as one prompt is unanswered, on every exit.
struct OnScreen;

impl OnScreen {
    fn new() -> Self {
        PROMPT_ON_SCREEN.store(true, Ordering::Relaxed);
        Self
    }
}

impl Drop for OnScreen {
    fn drop(&mut self) {
        PROMPT_ON_SCREEN.store(false, Ordering::Relaxed);
        let held = HELD_BACK.swap(0, Ordering::Relaxed);
        if held > 0 {
            tracing::warn!(
                held,
                "peer-caused log lines were held back while the prompt waited"
            );
        }
    }
}

/// Throw away whatever the terminal has already queued for `fd`.
fn discard_typeahead(fd: RawFd) {
    // SAFETY: `tcflush` reads no caller memory and only discards this terminal's queued input.
    let _ = unsafe { libc::tcflush(fd, libc::TCIFLUSH) };
}

fn wait_readable(fd: RawFd, within: Duration) -> std::io::Result<bool> {
    let mut polled = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    let millis = i32::try_from(within.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: `polled` is one initialised `pollfd` and `poll` writes only its `revents`.
    let ready = unsafe { libc::poll(polled.as_mut_ptr(), 1, millis) };
    if ready >= 0 {
        return Ok(ready > 0);
    }
    let err = std::io::Error::last_os_error();
    match err.kind() == std::io::ErrorKind::Interrupted {
        true => Ok(false),
        false => Err(err),
    }
}

fn read_terminal(fd: RawFd, into: &mut [u8]) -> std::io::Result<usize> {
    loop {
        // SAFETY: `into` is exclusively borrowed and valid for `into.len()` bytes.
        let read = unsafe { libc::read(fd, into.as_mut_ptr().cast(), into.len()) };
        if read >= 0 {
            return Ok(read.unsigned_abs());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// What one attempt to take the operator's answer produced.
#[derive(Debug)]
enum Answer {
    /// One complete line, within the length cap.
    Line(Vec<u8>),
    /// A line longer than [`MAX_APPROVAL_ANSWER_BYTES`].
    Overlong,
    /// The wait ran out with no complete line.
    TimedOut,
    /// The terminal reached end of input.
    Closed,
}

/// Take one line from `fd`, waiting at most `timeout` for it. Whatever follows the newline in
/// the same read is dropped rather than buffered, so a second line typed ahead cannot become
/// the answer to a prompt the caller has not shown yet.
fn read_answer(fd: RawFd, timeout: Duration) -> std::io::Result<Answer> {
    let started = Instant::now();
    let mut answer = Vec::new();
    let mut overlong = false;
    let mut chunk = [0u8; 64];
    loop {
        let left = timeout.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Ok(Answer::TimedOut);
        }
        if !wait_readable(fd, left)? {
            continue;
        }
        let read = read_terminal(fd, &mut chunk)?;
        if read == 0 {
            return Ok(Answer::Closed);
        }
        let bytes = &chunk[..read];
        let line_end = bytes.iter().position(|byte| *byte == b'\n');
        let content = line_end.map_or(bytes, |at| &bytes[..at]);
        if !overlong {
            let room = MAX_APPROVAL_ANSWER_BYTES.saturating_sub(answer.len());
            if content.len() > room {
                overlong = true;
                answer.clear();
            } else {
                answer.extend_from_slice(content);
            }
        }
        if line_end.is_some() {
            return Ok(match overlong {
                true => Answer::Overlong,
                false => Answer::Line(answer),
            });
        }
    }
}

/// Absorb everything typed while a prompt was too fresh to have been read, and report whether
/// anything was. A complete line inside the window cannot be an informed answer to a prompt that
/// went up microseconds ago, and discarding it in silence leaves the operator's own keystroke on
/// screen next to a request that then waits out its whole timeout.
fn settle(fd: RawFd, window: Duration) -> std::io::Result<bool> {
    let started = Instant::now();
    let mut early = false;
    let mut chunk = [0u8; 64];
    loop {
        let left = window.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Ok(early);
        }
        if !wait_readable(fd, left)? {
            continue;
        }
        if read_terminal(fd, &mut chunk)? == 0 {
            return Ok(early);
        }
        early = true;
    }
}

/// What the operator did at one approval prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Answered yes.
    Approve,
    /// Answered no, or let the prompt expire.
    Deny,
    /// Escaped the prompt: deny this request and stop asking about this caller for a while.
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

fn show(text: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(text.as_bytes())?;
    out.flush()
}

impl Renderer for Headless {
    fn ask(&self, seq: u64, ctx: &OpContext, summary: &str) -> Decision {
        let Tty::Interactive = self.tty else {
            tracing::error!(seq, key = %ctx.key, op = ?ctx.op, "no terminal to approve on");
            return Decision::NoTerminal;
        };
        discard_typeahead(libc::STDIN_FILENO);
        let question = format!(
            "y = approve   q = deny and stop asking about this caller for {}s   anything else = deny\n\
             Approve request #{seq}? [y/N] ",
            QUIET_PERIOD.as_secs()
        );
        let _on_screen = OnScreen::new();
        if let Err(e) = show(&format!(
            "\n=== hot_cheese {op:?} request #{seq} ===\n{reason}\n{summary}\n{question}",
            op = ctx.op,
            reason = ctx.reason()
        )) {
            tracing::error!(error = %e, seq, key = %ctx.key, "could not show the request");
            return Decision::NoTerminal;
        }
        match settle(libc::STDIN_FILENO, MIN_PROMPT_DISPLAY) {
            Ok(true) => {
                if let Err(e) = show(&format!(
                    "\nthat answer landed before request #{seq} was readable and was not used.\n{question}"
                )) {
                    tracing::error!(error = %e, seq, key = %ctx.key, "could not show the request again");
                    return Decision::NoTerminal;
                }
            }
            Ok(false) => {}
            Err(e) => {
                tracing::error!(error = %e, seq, key = %ctx.key, "could not watch the terminal");
                return Decision::NoTerminal;
            }
        }
        match read_answer(libc::STDIN_FILENO, APPROVAL_TIMEOUT) {
            Ok(Answer::Line(line)) => match std::str::from_utf8(&line).map(str::trim) {
                Ok(answer) if answer.eq_ignore_ascii_case("y") => Decision::Approve,
                Ok(answer) if answer.eq_ignore_ascii_case("q") => Decision::Cancel,
                _ => Decision::Deny,
            },
            Ok(Answer::Overlong) => Decision::Deny,
            Ok(Answer::TimedOut) => {
                tracing::warn!(
                    seq,
                    key = %ctx.key,
                    op = ?ctx.op,
                    after_secs = APPROVAL_TIMEOUT.as_secs(),
                    "denying a request the operator never answered"
                );
                Decision::Deny
            }
            Ok(Answer::Closed) => {
                tracing::warn!(seq, key = %ctx.key, op = ?ctx.op, "the terminal closed at the prompt");
                Decision::Deny
            }
            Err(e) => {
                tracing::error!(error = %e, seq, key = %ctx.key, "could not read the answer");
                Decision::NoTerminal
            }
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
    use hc_sign::adapter::Summary;
    use hc_sign::SignErr;
    use std::sync::Arc;

    /// [`PROMPT_ON_SCREEN`] is one process-wide fact, so the two tests that assert on it may not
    /// run beside each other.
    static SCREEN: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

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
        let summary = Summary {
            alarms: Vec::new(),
            body: "transfer(to=0x00, amount=1)".to_string(),
        };
        assert!(matches!(
            Approver::new(UnlockGate::Biometric, Arc::new(headless)).approve(&ctx, &summary),
            Err(SignErr::NoApprovalTerminal)
        ));
    }

    /// The answer reader must end on its own deadline rather than on the caller's patience, must
    /// keep an over-long line from smuggling a `y` past the cap, and must drop what follows the
    /// newline so a second line typed ahead cannot answer the next prompt.
    #[test]
    fn an_unanswered_prompt_expires_and_typed_ahead_lines_never_carry_over() {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe` fills the two-element array with the pair it creates.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_fd, write_fd) = (fds[0], fds[1]);
        let write = |bytes: &[u8]| {
            // SAFETY: `bytes` is a live borrow of `bytes.len()` readable bytes.
            let written = unsafe { libc::write(write_fd, bytes.as_ptr().cast(), bytes.len()) };
            assert_eq!(written, bytes.len() as isize);
        };

        assert!(matches!(
            read_answer(read_fd, Duration::from_millis(30)),
            Ok(Answer::TimedOut)
        ));

        write(b"y\nY\n");
        match read_answer(read_fd, Duration::from_secs(1)) {
            Ok(Answer::Line(line)) => assert_eq!(line.as_slice(), b"y".as_slice()),
            other => panic!("a complete line must be read: {other:?}"),
        }
        assert!(
            matches!(
                read_answer(read_fd, Duration::from_millis(30)),
                Ok(Answer::TimedOut)
            ),
            "the line typed ahead must have been dropped with the first read"
        );

        write(b"yyyyyyyyyyyyyyyyyyyyyyyyyyy\n");
        assert!(matches!(
            read_answer(read_fd, Duration::from_secs(1)),
            Ok(Answer::Overlong)
        ));

        // SAFETY: `write_fd` is open and owned by this test.
        assert_eq!(unsafe { libc::close(write_fd) }, 0);
        assert!(matches!(
            read_answer(read_fd, Duration::from_secs(1)),
            Ok(Answer::Closed)
        ));
        // SAFETY: `read_fd` is open and owned by this test.
        assert_eq!(unsafe { libc::close(read_fd) }, 0);
    }

    /// An answer typed while the prompt was still being drawn must be reported, so the operator
    /// is asked again, and the line they type next must still be read at once — never discarded
    /// into a wait that runs the request's whole timeout out.
    #[test]
    fn an_answer_typed_inside_the_display_window_is_seen_and_re_asked() {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe` fills the two-element array with the pair it creates.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_fd, write_fd) = (fds[0], fds[1]);
        let write = |bytes: &[u8]| {
            // SAFETY: `bytes` is a live borrow of `bytes.len()` readable bytes.
            let written = unsafe { libc::write(write_fd, bytes.as_ptr().cast(), bytes.len()) };
            assert_eq!(written, bytes.len() as isize);
        };

        let quiet = Instant::now();
        assert!(
            !settle(read_fd, Duration::from_millis(120)).expect("an idle terminal settles"),
            "nothing typed means nothing to report"
        );
        assert!(quiet.elapsed() >= Duration::from_millis(120));

        write(b"y\n");
        assert!(
            settle(read_fd, Duration::from_millis(120)).expect("a hurried answer settles"),
            "an answer inside the window must be reported, not silently dropped"
        );

        let asked_again = Instant::now();
        write(b"y\n");
        match read_answer(read_fd, APPROVAL_TIMEOUT) {
            Ok(Answer::Line(line)) => assert_eq!(line.as_slice(), b"y".as_slice()),
            other => panic!("the answer after the window must be read: {other:?}"),
        }
        assert!(
            asked_again.elapsed() < Duration::from_secs(1),
            "the re-asked prompt must be answered at once, not after {APPROVAL_TIMEOUT:?}"
        );

        // SAFETY: both ends are open and owned by this test.
        assert_eq!(unsafe { libc::close(write_fd) }, 0);
        // SAFETY: both ends are open and owned by this test.
        assert_eq!(unsafe { libc::close(read_fd) }, 0);
    }

    /// The regression this exists for, on a real pty and through the real `ask`: an answer typed
    /// while the prompt was still being drawn used to be flushed away and then waited out for the
    /// whole approval timeout, so it must now cost one re-ask and be answered in milliseconds.
    #[test]
    fn a_hurried_answer_on_a_real_pty_costs_a_re_ask_and_not_the_timeout() {
        let _screen = SCREEN.lock();
        let mut master = 0 as libc::c_int;
        let mut slave = 0 as libc::c_int;
        // SAFETY: `openpty` writes only the two descriptors; the three null arguments ask it for
        // this platform's default terminal settings.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        // SAFETY: fd 0 is open and `dup` only copies it.
        let saved = unsafe { libc::dup(libc::STDIN_FILENO) };
        assert!(saved >= 0);
        // SAFETY: both descriptors are open and owned here.
        let onto = unsafe { libc::dup2(slave, libc::STDIN_FILENO) };
        assert_eq!(onto, libc::STDIN_FILENO);

        let (drawn, going_up) = std::sync::mpsc::channel();
        let operator = std::thread::spawn(move || {
            going_up.recv().expect("the prompt is going up");
            let write = |bytes: &[u8]| {
                // SAFETY: `bytes` is a live borrow of `bytes.len()` readable bytes.
                let written = unsafe { libc::write(master, bytes.as_ptr().cast(), bytes.len()) };
                assert_eq!(written, bytes.len() as isize);
            };
            std::thread::sleep(MIN_PROMPT_DISPLAY / 4);
            write(b"y\n");
            std::thread::sleep(MIN_PROMPT_DISPLAY);
            write(b"y\n");
        });

        let ctx = OpContext {
            key: "TRADER".to_string(),
            op: Operation::Sign,
            peer: Peer::Loopback,
        };
        drawn.send(()).expect("the operator is waiting");
        let started = Instant::now();
        let decision = Headless {
            tty: Tty::Interactive,
        }
        .ask(1, &ctx, "transfer(to=0x00, amount=1)");
        let took = started.elapsed();
        operator.join().expect("the operator answers and leaves");

        // SAFETY: `saved` is the descriptor `dup` handed back and fd 0 is open.
        let back = unsafe { libc::dup2(saved, libc::STDIN_FILENO) };
        assert_eq!(back, libc::STDIN_FILENO);
        for fd in [saved, slave, master] {
            // SAFETY: each of these is open and owned by this test.
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }

        println!("pty: decision={decision:?} after={took:?}");
        assert_eq!(
            decision,
            Decision::Approve,
            "the operator's answer must be the decision"
        );
        assert!(
            took >= MIN_PROMPT_DISPLAY,
            "the display window must still run: {took:?}"
        );
        assert!(
            took < APPROVAL_TIMEOUT / 10,
            "a hurried answer must not stall the approval thread: {took:?}"
        );
    }

    /// Connection-level noise is what an unauthenticated peer can produce at will, and the prompt
    /// is the whole authorization mechanism: while one waits, that noise is counted rather than
    /// written, and the screen is given back the moment the prompt is answered.
    #[test]
    fn peer_noise_is_held_back_only_while_a_prompt_waits() {
        let _screen = SCREEN.lock();
        assert!(peer_may_log());
        let on_screen = OnScreen::new();
        for _ in 0..10_000 {
            assert!(!peer_may_log());
        }
        assert_eq!(HELD_BACK.load(Ordering::Relaxed), 10_000);
        drop(on_screen);
        assert!(peer_may_log());
        assert_eq!(HELD_BACK.load(Ordering::Relaxed), 0);
    }
}
