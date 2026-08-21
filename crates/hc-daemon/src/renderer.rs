//! The half of the front end a privileged operation touches: asking the human, keeping the
//! screen they answer from legible, and giving the terminal back on every ending.
use crate::OpContext;
use hc_core::config::Config;
use parking_lot::Mutex;
use rand::Rng;
use std::io::IsTerminal;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_APPROVAL_ANSWER_BYTES: usize = 16;

/// The fraction of one prompt's wait it may additionally wait, drawn afresh for each. The caller
/// of the request on screen is told the instant that request is refused, so a fixed deadline
/// would hand it a clock on the moment the screen changes under the operator. It is a fraction
/// and not a constant so that shortening the wait shortens the window an attacker must resolve
/// by the same proportion it shortens the wait itself.
const APPROVAL_JITTER_DIVISOR: u32 = 3;

/// How long the terminal may accept no byte at all before the prompt is given up on. The deadline
/// is on progress and not on the whole write: a screen that keeps taking bytes is slow, and a slow
/// screen is still one the operator can read, while one that has stopped draining — a stalled ssh
/// session, Ctrl-S, a pipe nobody reads — would hold the single approval thread forever.
const SHOW_STALL: Duration = Duration::from_secs(2);

/// Bytes offered to the terminal between two writability checks. A pipe calls itself writable
/// only with `PIPE_BUF` bytes free and a terminal only above its low-water mark, both larger than
/// this, so a write this size cannot park on a terminal that has just said it has room.
const SHOW_CHUNK: usize = 256;

/// How long a prompt is on screen before a keystroke counts as an answer to it, which is what
/// absorbs the keys typed at the prompt before this one.
pub const MIN_PROMPT_DISPLAY: Duration = Duration::from_millis(400);

/// Whether an approval prompt is on the operator's screen with no answer yet.
static PROMPT_ON_SCREEN: AtomicBool = AtomicBool::new(false);

/// Kinds of suppressed peer line remembered while a prompt waits. The peer picks which kinds it
/// produces, so what is kept is bounded by this crate's own set of them and never by its volume.
const HELD_KINDS: usize = 24;

/// What an unauthenticated peer caused while a prompt waited, by kind and count.
static HELD_BACK: Mutex<Vec<(&'static str, u64)>> = Mutex::new(Vec::new());

/// Held-back lines whose kind did not fit in [`HELD_KINDS`].
static HELD_BACK_UNKINDED: AtomicU64 = AtomicU64::new(0);

/// Whether a line an unauthenticated peer caused may reach the operator's screen. The prompt IS
/// the authorization mechanism here, so a peer that can scroll it away is attacking the control
/// itself: while one waits the line is deferred under its `kind`, and every kind deferred, its
/// count, the window it covers and the rate it implies are reported once the screen is the
/// operator's again.
pub fn peer_may_log(kind: &'static str) -> bool {
    if !PROMPT_ON_SCREEN.load(Ordering::Relaxed) {
        return true;
    }
    let mut held = HELD_BACK.lock();
    for entry in held.iter_mut() {
        if entry.0 == kind {
            entry.1 = entry.1.saturating_add(1);
            return false;
        }
    }
    match held.len() < HELD_KINDS {
        true => held.push((kind, 1)),
        false => {
            HELD_BACK_UNKINDED.fetch_add(1, Ordering::Relaxed);
        }
    }
    false
}

/// The one process-wide screen, held by every test that drives [`PROMPT_ON_SCREEN`] so they
/// cannot interleave with each other or with the deferral one listener's tests measure. Both
/// approval surfaces put a prompt there, so the console's tests take this same lock.
#[cfg(any(test, feature = "test-util"))]
pub static SCREEN: Mutex<()> = Mutex::new(());

/// Owns [`PROMPT_ON_SCREEN`] for exactly as long as one request is unanswered, on every exit.
pub struct OnScreen {
    /// The request the operator is being asked about.
    seq: u64,
    /// When the screen became theirs.
    since: Instant,
}

impl OnScreen {
    pub fn new(seq: u64) -> Self {
        PROMPT_ON_SCREEN.store(true, Ordering::Relaxed);
        Self {
            seq,
            since: Instant::now(),
        }
    }
}

impl Drop for OnScreen {
    fn drop(&mut self) {
        PROMPT_ON_SCREEN.store(false, Ordering::Relaxed);
        let held: Vec<(&'static str, u64)> = HELD_BACK.lock().drain(..).collect();
        let unkinded = HELD_BACK_UNKINDED.swap(0, Ordering::Relaxed);
        let over_ms = self.since.elapsed().as_millis().max(1);
        for (kind, lines) in held {
            tracing::warn!(
                seq = self.seq,
                kind,
                lines,
                over_ms,
                per_sec = u128::from(lines) * 1000 / over_ms,
                "peer-caused log lines were held back while the prompt waited"
            );
        }
        if unkinded > 0 {
            tracing::warn!(
                seq = self.seq,
                unkinded,
                over_ms,
                "more kinds of peer-caused log line were held back than are remembered"
            );
        }
    }
}

/// Throw away whatever the terminal has already queued for `fd`.
fn discard_typeahead(fd: RawFd) {
    // SAFETY: `tcflush` reads no caller memory and only discards this terminal's queued input.
    let _ = unsafe { libc::tcflush(fd, libc::TCIFLUSH) };
}

fn wait_ready(fd: RawFd, events: libc::c_short, within: Duration) -> std::io::Result<bool> {
    let mut polled = [libc::pollfd {
        fd,
        events,
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

/// Put `text` in front of the operator, or give up with [`std::io::ErrorKind::TimedOut`] once the
/// terminal has taken no byte for [`SHOW_STALL`]. The deadline runs from the last byte accepted
/// rather than from the first, so a screen that is merely slow — a long summary over a congested
/// ssh link, a terminal under load — is written out however long it takes, and only one that has
/// stopped draining ends the prompt.
fn show(fd: RawFd, text: &str) -> std::io::Result<()> {
    let mut moved = Instant::now();
    let mut left = text.as_bytes();
    while !left.is_empty() {
        let within = SHOW_STALL.saturating_sub(moved.elapsed());
        if within.is_zero() {
            return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
        }
        if !wait_ready(fd, libc::POLLOUT, within)? {
            continue;
        }
        let take = left.len().min(SHOW_CHUNK);
        // SAFETY: `left` is a live borrow of at least `take` readable bytes.
        let written = unsafe { libc::write(fd, left.as_ptr().cast(), take) };
        if written < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if written > 0 {
            moved = Instant::now();
        }
        left = &left[written.unsigned_abs()..];
    }
    Ok(())
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
        if !wait_ready(fd, libc::POLLIN, left)? {
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
        if !wait_ready(fd, libc::POLLIN, left)? {
            continue;
        }
        if read_terminal(fd, &mut chunk)? == 0 {
            return Ok(early);
        }
        early = true;
    }
}

/// What one typed line means for the request on screen, and whether it proves the operator was
/// reading THAT request: a line carrying the request's own number cannot have been composed for
/// the request it replaced, because that one carried a different number and was numbered lower.
/// A time floor cannot establish this — an answer typed a minute late still lands on whatever is
/// on screen — so the number, and not the delay, is what a startled prompt is answerable by.
pub fn interpret(line: &str, seq: u64, startled: bool) -> (Decision, bool) {
    let answer = line.trim();
    let (verb, attributed) = match answer.strip_suffix(seq.to_string().as_str()) {
        Some(verb) if verb.len() < 2 => (verb, true),
        _ => (answer, false),
    };
    let decision = match verb {
        _ if verb.eq_ignore_ascii_case("q") => Decision::Cancel,
        _ if verb.eq_ignore_ascii_case("y") && (attributed || !startled) => Decision::Approve,
        _ => Decision::Deny,
    };
    (decision, attributed)
}

/// What the operator did at one approval prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Answered yes.
    Approve,
    /// Answered no, or let the prompt expire.
    Deny,
    /// Escaped the prompt: deny this request and everything already queued behind it.
    Cancel,
    /// Ctrl-C at the prompt.
    Interrupt,
    /// There is no terminal to ask anyone on, or none that will take the question.
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
    /// The terminal the operator's answer is taken from.
    asking: RawFd,
    /// The terminal the request is drawn on.
    screen: RawFd,
    /// How long one prompt waits for an answer before denying itself.
    wait: Duration,
    /// How much longer than `wait` a prompt may wait, drawn afresh for each one.
    jitter: Duration,
    /// Whether the prompt before this one ended without an answer the operator can be shown to
    /// have given to it.
    startled: AtomicBool,
}

impl Headless {
    /// The renderer with the prompt deadline this install's `config.toml` states.
    pub fn for_config(config: &Config) -> Self {
        Self::waiting(config.approval_timeout())
    }

    fn waiting(wait: Duration) -> Self {
        Self {
            tty: match std::io::stdin().is_terminal() {
                true => Tty::Interactive,
                false => Tty::Headless,
            },
            asking: libc::STDIN_FILENO,
            screen: libc::STDOUT_FILENO,
            wait,
            jitter: wait / APPROVAL_JITTER_DIVISOR,
            startled: AtomicBool::new(false),
        }
    }

    /// The deadline this prompt denies itself at. Drawn per prompt, so the caller that is told the
    /// instant its own request was refused learns nothing about when the screen next changes.
    fn deadline(&self) -> Duration {
        let spread = u64::try_from(self.jitter.as_millis()).unwrap_or(u64::MAX);
        match spread {
            0 => self.wait,
            _ => self.wait + Duration::from_millis(rand::rngs::OsRng.gen_range(0..spread)),
        }
    }
}

impl Renderer for Headless {
    fn ask(&self, seq: u64, ctx: &OpContext, summary: &str) -> Decision {
        let Tty::Interactive = self.tty else {
            tracing::error!(seq, key = %ctx.key, op = ?ctx.op, "no terminal to approve on");
            return Decision::NoTerminal;
        };
        let startled = self.startled.swap(true, Ordering::Relaxed);
        let _on_screen = OnScreen::new(seq);
        discard_typeahead(self.asking);
        let question = match startled {
            true => format!(
                "y{seq} = approve request #{seq}   q{seq} = deny it and everything already queued\
                 \nanything that does not carry #{seq} = deny\nApprove request #{seq}? [y{seq}/N] "
            ),
            false => format!(
                "y = approve   q = deny this and everything already queued   anything else = deny\n\
                 Approve request #{seq}? [y/N] "
            ),
        };
        if let Err(e) = show(
            self.screen,
            &format!(
                "\n{startle}=== hot_cheese {op:?} request #{seq} ===\n{reason}\n{summary}\n\
                 {question}",
                startle = match startled {
                    true =>
                        "*** THE SCREEN CHANGED: the request you were reading ended WITHOUT your \
                         answer. This is a different request, and only an answer carrying its own \
                         number can approve it. ***\n",
                    false => "",
                },
                op = ctx.op,
                reason = ctx.reason()
            ),
        ) {
            tracing::error!(error = %e, seq, key = %ctx.key, "could not show the request");
            return Decision::NoTerminal;
        }
        match settle(self.asking, MIN_PROMPT_DISPLAY) {
            Ok(true) => {
                if let Err(e) = show(self.screen, &format!(
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
        let deadline = self.deadline();
        match read_answer(self.asking, deadline) {
            Ok(Answer::Line(line)) => {
                let (decision, attributed) = match std::str::from_utf8(&line) {
                    Ok(answer) => interpret(answer, seq, startled),
                    Err(_) => (Decision::Deny, false),
                };
                self.startled
                    .store(startled && !attributed, Ordering::Relaxed);
                if startled && !attributed {
                    tracing::warn!(
                        seq,
                        key = %ctx.key,
                        "an answer that did not carry the request number denied it"
                    );
                }
                decision
            }
            Ok(Answer::Overlong) => {
                self.startled.store(startled, Ordering::Relaxed);
                Decision::Deny
            }
            Ok(Answer::TimedOut) => {
                tracing::warn!(
                    seq,
                    key = %ctx.key,
                    op = ?ctx.op,
                    after_secs = deadline.as_secs(),
                    "denying a request the operator never answered"
                );
                let _ = show(
                    self.screen,
                    &format!("\nrequest #{seq} expired with no answer and was DENIED.\n"),
                );
                discard_typeahead(self.asking);
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
    use std::os::unix::io::AsRawFd;
    use std::sync::Arc;

    /// The longest any test here waits on a terminal, so a wedged one fails instead of stalling.
    const TEST_WAIT: Duration = Duration::from_millis(1500);

    fn signing() -> OpContext {
        OpContext {
            key: "TRADER".to_string(),
            op: Operation::Sign,
            peer: Peer::Loopback,
        }
    }

    fn interactive(asking: RawFd, screen: RawFd) -> Headless {
        Headless {
            tty: Tty::Interactive,
            asking,
            screen,
            wait: TEST_WAIT,
            jitter: Duration::ZERO,
            startled: AtomicBool::new(false),
        }
    }

    /// One pty pair, and a `write` for the end the operator types on.
    fn openpty() -> (libc::c_int, libc::c_int) {
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
        (master, slave)
    }

    fn types(fd: RawFd, bytes: &[u8]) {
        // SAFETY: `bytes` is a live borrow of `bytes.len()` readable bytes.
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        assert_eq!(written, bytes.len() as isize);
    }

    fn close(fds: &[libc::c_int]) {
        for fd in fds.iter().copied() {
            // SAFETY: each of these is open and owned by the calling test.
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
    }

    /// The shortest wait `config.toml` may state must still be drawn afresh for every prompt: a
    /// spread that rounded to zero at the short end would leave the caller it refuses a fixed
    /// instant to read the redraw off, which is the whole reason the deadline is jittered.
    #[test]
    fn the_shortest_configured_wait_still_draws_a_fresh_deadline() {
        let shortest = Duration::from_secs(5);
        let renderer = Headless::waiting(shortest);
        let first = renderer.deadline();
        let mut drawn = vec![first];
        for _ in 0..64 {
            drawn.push(renderer.deadline());
        }
        assert!(
            drawn.iter().any(|deadline| *deadline != first),
            "every draw returned {first:?}, so a configured wait carries no jitter at all"
        );
        for deadline in drawn {
            assert!(
                deadline >= shortest && deadline < shortest + shortest / APPROVAL_JITTER_DIVISOR,
                "{deadline:?} is outside the spread the configured wait allows"
            );
        }
    }

    /// A daemon with no terminal cannot ask anyone, and "nobody could be asked" must stay a
    /// distinct refusal all the way to the caller: degrading it into the denial a human types
    /// is exactly what would let an unattended daemon look like a refusing operator.
    #[test]
    fn no_terminal_is_a_typed_refusal_and_not_a_denial() {
        let ctx = signing();
        let headless = Headless {
            tty: Tty::Headless,
            asking: libc::STDIN_FILENO,
            screen: libc::STDOUT_FILENO,
            wait: TEST_WAIT,
            jitter: Duration::ZERO,
            startled: AtomicBool::new(false),
        };
        assert_eq!(
            headless.ask(1, &ctx, "transfer(to=0x00, amount=1)"),
            Decision::NoTerminal
        );
        let summary = Summary {
            authority: Vec::new(),
            evictable: Vec::new(),
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

        assert!(matches!(
            read_answer(read_fd, Duration::from_millis(30)),
            Ok(Answer::TimedOut)
        ));

        types(write_fd, b"y\nY\n");
        match read_answer(read_fd, TEST_WAIT) {
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

        types(write_fd, b"yyyyyyyyyyyyyyyyyyyyyyyyyyy\n");
        assert!(matches!(
            read_answer(read_fd, TEST_WAIT),
            Ok(Answer::Overlong)
        ));

        // SAFETY: `write_fd` is open and owned by this test.
        assert_eq!(unsafe { libc::close(write_fd) }, 0);
        assert!(matches!(
            read_answer(read_fd, TEST_WAIT),
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

        let quiet = Instant::now();
        assert!(
            !settle(read_fd, Duration::from_millis(120)).expect("an idle terminal settles"),
            "nothing typed means nothing to report"
        );
        assert!(quiet.elapsed() >= Duration::from_millis(120));

        types(write_fd, b"y\n");
        assert!(
            settle(read_fd, Duration::from_millis(120)).expect("a hurried answer settles"),
            "an answer inside the window must be reported, not silently dropped"
        );

        let asked_again = Instant::now();
        types(write_fd, b"y\n");
        match read_answer(read_fd, TEST_WAIT) {
            Ok(Answer::Line(line)) => assert_eq!(line.as_slice(), b"y".as_slice()),
            other => panic!("the answer after the window must be read: {other:?}"),
        }
        assert!(
            asked_again.elapsed() < TEST_WAIT / 2,
            "the re-asked prompt must be answered at once, not waited out"
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
        let (master, slave) = openpty();
        let quiet = std::fs::File::create("/dev/null").expect("a screen nobody reads");

        let operator = std::thread::spawn(move || {
            std::thread::sleep(MIN_PROMPT_DISPLAY / 4);
            types(master, b"y\n");
            std::thread::sleep(MIN_PROMPT_DISPLAY);
            types(master, b"y\n");
        });
        let started = Instant::now();
        let decision =
            interactive(slave, quiet.as_raw_fd()).ask(1, &signing(), "transfer(to=0x00, amount=1)");
        let took = started.elapsed();
        operator.join().expect("the operator answers and leaves");
        // SAFETY: both descriptors are open and owned by this test.
        for fd in [slave, master] {
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }

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
            took < TEST_WAIT,
            "a hurried answer must not stall the approval thread: {took:?}"
        );
    }

    /// The whole class, not one delay from it: a prompt that replaced an unanswered one must be
    /// unapproveable by every line the operator could have composed for the request it replaced,
    /// at every delay, including delays far past any floor a timing rule could hold. Only a line
    /// carrying this request's own number approves it, and only such a line ends the startled run.
    #[test]
    fn no_answer_composed_for_an_earlier_request_can_approve_the_one_that_replaced_it() {
        let _screen = SCREEN.lock();
        let (master, slave) = openpty();
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe` fills the two-element array with the pair it creates.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (screen_read, screen_write) = (fds[0], fds[1]);
        let watching = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let mut chunk = [0u8; 512];
            while let Ok(read) = read_terminal(screen_read, &mut chunk) {
                if read == 0 {
                    return seen;
                }
                seen.extend_from_slice(&chunk[..read]);
            }
            seen
        });

        let ctx = signing();
        let headless = interactive(slave, screen_write);
        assert_eq!(
            headless.ask(1, &ctx, "the request the operator was still reading"),
            Decision::Deny,
            "an unanswered request must deny itself"
        );

        for (seq, stale) in [(2u64, "y"), (3, "Y"), (4, "y1"), (5, "yes")] {
            for over in [MIN_PROMPT_DISPLAY * 2, MIN_PROMPT_DISPLAY * 3] {
                let typed = format!("{stale}\n");
                let operator = std::thread::spawn(move || {
                    std::thread::sleep(over);
                    types(master, typed.as_bytes());
                });
                let started = Instant::now();
                let decision = headless.ask(seq, &ctx, "the request that took its place");
                let took = started.elapsed();
                operator.join().expect("the operator types and leaves");
                assert_eq!(
                    decision,
                    Decision::Deny,
                    "{stale:?} typed {over:?} after request #{seq} appeared approved it"
                );
                assert!(
                    took < TEST_WAIT,
                    "the stale line must be read and refused, not waited out: {took:?}"
                );
            }
        }

        let operator = std::thread::spawn(move || {
            std::thread::sleep(MIN_PROMPT_DISPLAY * 2);
            types(master, b"y6\n");
            std::thread::sleep(MIN_PROMPT_DISPLAY * 2);
            types(master, b"y\n");
        });
        assert_eq!(
            headless.ask(6, &ctx, "the request the operator actually read"),
            Decision::Approve,
            "the answer carrying this request's own number must still be taken"
        );
        assert_eq!(
            headless.ask(7, &ctx, "the request after the startled run ended"),
            Decision::Approve,
            "an answered prompt ends the startled run, so the next one takes a plain y"
        );
        operator.join().expect("the operator answers and leaves");
        close(&[slave, master, screen_write]);
        let seen =
            String::from_utf8_lossy(&watching.join().expect("the screen is readable")).into_owned();
        // SAFETY: `screen_read` is open and owned by this test.
        assert_eq!(unsafe { libc::close(screen_read) }, 0);

        assert!(
            seen.contains("expired with no answer"),
            "the request that ran out must say so on screen: {seen:?}"
        );
        assert!(
            seen.contains("THE SCREEN CHANGED"),
            "the prompt that replaced it must announce itself: {seen:?}"
        );
        assert!(
            seen.contains("[y6/N]"),
            "a startled prompt must show the answer that carries its own number: {seen:?}"
        );
    }

    /// A startled prompt is answerable only by a line carrying its own number, whatever the delay;
    /// a plain prompt still takes a plain `y`; and the escape works either way.
    #[test]
    fn only_a_line_carrying_the_request_number_answers_a_startled_prompt() {
        for (line, decision) in [
            ("y", Decision::Approve),
            (" Y ", Decision::Approve),
            ("y41", Decision::Approve),
            ("q", Decision::Cancel),
            ("n", Decision::Deny),
            ("y4", Decision::Deny),
            ("y411", Decision::Deny),
        ] {
            assert_eq!(interpret(line, 41, false).0, decision, "plain prompt: {line}");
        }
        for (line, decision, attributed) in [
            ("y", Decision::Deny, false),
            ("y4", Decision::Deny, false),
            ("y411", Decision::Deny, false),
            ("y41", Decision::Approve, true),
            ("Y41", Decision::Approve, true),
            ("q", Decision::Cancel, false),
            ("q41", Decision::Cancel, true),
            ("n41", Decision::Deny, true),
        ] {
            assert_eq!(
                interpret(line, 41, true),
                (decision, attributed),
                "startled prompt: {line}"
            );
        }
    }

    /// A terminal that will not take the prompt must cost that request a typed refusal and cost
    /// the daemon nothing: the write is the one blocking call on the approval thread that had no
    /// deadline, and a screen that stopped draining held it — and every later request — forever.
    #[test]
    fn a_terminal_that_will_not_take_the_prompt_refuses_instead_of_wedging_the_thread() {
        let _screen = SCREEN.lock();
        let (master, slave) = openpty();
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe` fills the two-element array with the pair it creates.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (stalled_read, stalled_write) = (fds[0], fds[1]);
        // SAFETY: `stalled_write` is open and owned by this test.
        let flags = unsafe { libc::fcntl(stalled_write, libc::F_GETFL) };
        assert!(flags >= 0);
        // SAFETY: `stalled_write` is open and owned by this test.
        assert_eq!(
            unsafe { libc::fcntl(stalled_write, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let stuffing = [b'.'; 4096];
        // SAFETY: `stuffing` is a live borrow of its own length in readable bytes.
        while unsafe { libc::write(stalled_write, stuffing.as_ptr().cast(), stuffing.len()) } > 0 {}
        // SAFETY: `stalled_write` is open and owned by this test.
        assert_eq!(
            unsafe { libc::fcntl(stalled_write, libc::F_SETFL, flags) },
            0
        );

        let (answered, refusal) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let decision =
                interactive(slave, stalled_write).ask(1, &signing(), "transfer(to=0x00, amount=1)");
            let _ = answered.send((decision, started.elapsed()));
        });
        let outcome = refusal.recv_timeout(SHOW_STALL * 3);

        // SAFETY: `stalled_read` is open and owned by this test.
        let read_flags = unsafe { libc::fcntl(stalled_read, libc::F_GETFL) };
        assert!(read_flags >= 0);
        // SAFETY: `stalled_read` is open and owned by this test.
        assert_eq!(
            unsafe { libc::fcntl(stalled_read, libc::F_SETFL, read_flags | libc::O_NONBLOCK) },
            0
        );
        let mut drain = [0u8; 4096];
        // SAFETY: `stalled_read` is open and `drain` is exclusively borrowed.
        while unsafe { libc::read(stalled_read, drain.as_mut_ptr().cast(), drain.len()) } > 0 {}
        close(&[master, slave, stalled_read, stalled_write]);

        let (decision, took) = outcome.expect("a stalled screen must not hold the approval thread");
        assert_eq!(
            decision,
            Decision::NoTerminal,
            "a request the operator cannot see must not be counted as answerable"
        );
        assert!(
            took < SHOW_STALL * 2,
            "the write must end on its own deadline: {took:?}"
        );
    }

    /// A screen that keeps taking bytes is one the operator can read, however long the whole
    /// prompt takes to land: the deadline is on a screen that has STOPPED draining, so a slow one
    /// — a congested link, a terminal under load — must never turn a request into `NoTerminal`.
    #[test]
    fn a_slow_screen_is_written_out_however_long_it_takes() {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe` fills the two-element array with the pair it creates.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (slow_read, slow_write) = (fds[0], fds[1]);
        // SAFETY: `slow_write` is open and owned by this test.
        let flags = unsafe { libc::fcntl(slow_write, libc::F_GETFL) };
        assert!(flags >= 0);
        // SAFETY: `slow_write` is open and owned by this test.
        assert_eq!(
            unsafe { libc::fcntl(slow_write, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let stuffing = [b'.'; 4096];
        // SAFETY: `stuffing` is a live borrow of its own length in readable bytes.
        while unsafe { libc::write(slow_write, stuffing.as_ptr().cast(), stuffing.len()) } > 0 {}
        // SAFETY: `slow_write` is open and owned by this test.
        assert_eq!(unsafe { libc::fcntl(slow_write, libc::F_SETFL, flags) }, 0);

        let steps = 3;
        let draining = std::thread::spawn(move || {
            let mut sipped = [0u8; SHOW_CHUNK * 8];
            for _ in 0..steps {
                std::thread::sleep(SHOW_STALL * 3 / 4);
                // SAFETY: `slow_read` is open and `sipped` is exclusively borrowed.
                if unsafe { libc::read(slow_read, sipped.as_mut_ptr().cast(), sipped.len()) } <= 0 {
                    return;
                }
            }
        });
        let prompt = "a".repeat(SHOW_CHUNK * 16);
        let started = Instant::now();
        let shown = show(slow_write, &prompt);
        let took = started.elapsed();
        draining.join().expect("the slow screen keeps draining");
        close(&[slow_read, slow_write]);

        assert!(shown.is_ok(), "a draining screen must be written out: {shown:?}");
        assert!(
            took > SHOW_STALL,
            "the point is a prompt that outlasts the stall deadline: {took:?}"
        );
    }

    /// Connection-level noise is what an unauthenticated peer can produce at will, and the prompt
    /// is the whole authorization mechanism: while one waits, that noise is deferred per kind
    /// rather than written, and the screen is given back the moment the prompt is answered.
    #[test]
    fn peer_noise_is_deferred_by_kind_only_while_a_prompt_waits() {
        let _screen = SCREEN.lock();
        assert!(peer_may_log("accepted"));
        let on_screen = OnScreen::new(7);
        for _ in 0..10_000 {
            assert!(!peer_may_log("accepted"));
            assert!(!peer_may_log("tls_failed"));
        }
        let held = HELD_BACK.lock().clone();
        for kind in ["accepted", "tls_failed"] {
            assert_eq!(
                held.iter().find(|entry| entry.0 == kind).map(|entry| entry.1),
                Some(10_000),
                "what a peer did while the prompt waited must survive as more than one number, \
                 by kind: {held:?}"
            );
        }
        drop(on_screen);
        assert!(peer_may_log("accepted"));
        assert!(HELD_BACK.lock().is_empty());
    }
}
