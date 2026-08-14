//! Log capture for the console, and the live status both the band and the Status panel render.
//!
//! Nothing here owns status: [`render_band`] is a pure function of the projection
//! [`hc_daemon::live::Live`] hands it, and the panel formats the same subsystems' own types. The
//! only thing this file keeps between frames is the text that is on screen, because the repaint
//! rule is "the rendered text changed", which is the one rule that neither misses an ageing
//! string nor repaints when nothing moved.
//!
//! Where it is NOT live, plainly: the band ticks inside [`super::pick::pick`], inside
//! [`super::approval::serve_and_approve`] and inside [`panel`], which is every screen that owns
//! a keyboard loop. It is absent from the header [`super::menu`] writes above the anchor, whose
//! outer loop blocks in `screen()` with no tick, and it is frozen for as long as an `inquire`
//! text, password, confirm or number prompt owns the terminal — those have no repaint hook. A
//! frozen band is stale, never wrong: it re-renders from the clock the moment the prompt returns.
use super::approval::RawScreen;
use super::menu::{MenuChoice, MenuErr, Step};
use super::pick::clip;
use super::{Console, Key};
use crossterm::cursor::{Hide, MoveTo};
use crossterm::execute;
use crossterm::style::Print;
use crossterm::terminal::{self, enable_raw_mode, Clear, ClearType};
use err_mac::create_err_with_impls;
use hc_core::config::home_dir;
use hc_core::is_valid_string_name;
use hc_core::keyring::{EnrollParams, Keyring};
use hc_core::mac::MacBackend;
use hc_daemon::git_store::{CommitId, Relation};
use hc_daemon::live::{BandSource, Live};
use hc_daemon::runtime::{Serving, UnlockGate};
use hc_sign::grant::{now_secs, GrantErr};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::util::SubscriberInitExt;

/// Log lines kept for the status view.
const RING_CAPACITY: usize = 200;

/// Log lines the status view shows, newest last.
const LOG_TAIL: usize = 12;

/// File under the home dir that every console log line is appended to.
const LOG_FILE: &str = "console.log";

/// Hex characters of a commit id the panel shows: enough to tell two apart on one line.
const SHORT_ID: usize = 8;

/// Seconds in the coarser units an age steps through.
const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

/// Under this many seconds an event reads as `now`, so a console whose newest event is a few
/// seconds old does not repaint every frame to redraw the same fact.
const JUST_NOW: u64 = 5;

/// What separates two chips on the band.
const CHIP: &str = " · ";

create_err_with_impls!(
    #[derive(Debug)]
    pub StatusErr,
    StdIo(io::Error),
    Init(tracing_subscriber::util::TryInitError)
    ;
);

/// The most recent log lines, newest last.
#[derive(Debug)]
pub struct LogRing {
    lines: Mutex<VecDeque<String>>,
}

impl LogRing {
    /// The last `n` lines, oldest first.
    pub fn recent(&self, n: usize) -> Vec<String> {
        let lines = self.lines.lock();
        let skip = lines.len().saturating_sub(n);
        lines.iter().skip(skip).cloned().collect()
    }

    fn push(&self, line: &str) {
        let mut lines = self.lines.lock();
        if lines.len() == RING_CAPACITY {
            lines.pop_front();
        }
        lines.push_back(line.to_string());
    }
}

/// Tees one formatted event into the ring buffer and the log file.
#[derive(Clone)]
pub struct TeeWriter {
    ring: Arc<LogRing>,
    file: Arc<Mutex<File>>,
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        for line in text.lines() {
            self.ring.push(line);
        }
        self.file.lock().write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.lock().flush()
    }
}

impl<'a> MakeWriter<'a> for TeeWriter {
    type Writer = TeeWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Redirect tracing away from the terminal for the rest of the process.
pub fn install_subscriber(home: &Path, level: tracing::Level) -> Result<Arc<LogRing>, StatusErr> {
    let ring = Arc::new(LogRing {
        lines: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
    });
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(home.join(LOG_FILE))?;
    let writer = TeeWriter {
        ring: ring.clone(),
        file: Arc::new(Mutex::new(file)),
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(false)
        .with_writer(writer)
        .finish()
        .try_init()?;
    Ok(ring)
}

/// How long ago a Unix-epoch stamp was. Both arguments are seconds; a clock that stepped back
/// past the stamp saturates to zero, which is the only truthful thing a RELATIVE age can say once
/// `now` sits behind the event — it can neither go negative nor render an absurd age.
pub(crate) fn age(then: u64, now: u64) -> String {
    let secs = now.saturating_sub(then);
    match secs {
        s if s < JUST_NOW => "now".to_string(),
        s if s < MINUTE => format!("{s}s"),
        s if s < HOUR => format!("{}m", s / MINUTE),
        s if s < DAY => format!("{}h", s / HOUR),
        s => format!("{}d", s / DAY),
    }
}

/// The `(n/m)` a chip carries only when the remotes disagree with each other.
fn tally(count: usize, of: usize) -> String {
    match count < of {
        true => format!(" ({count}/{of})"),
        false => String::new(),
    }
}

/// The one live line: one chip per configured subsystem, in a fixed order.
///
/// A chip's presence is decided by CONFIGURATION alone — never by a poll result — so the band
/// never shifts sideways under an operator who is reading it. Only a chip's text changes.
pub(crate) fn render_band(src: &BandSource) -> String {
    let mut chips = Vec::new();
    if src.remotes > 0 {
        chips.push(match (src.push_failed.at, src.pushed_at) {
            (Some(at), _) => format!(
                "push FAILED {}{}",
                age(at, src.now),
                tally(src.push_failed.count, src.remotes)
            ),
            (None, Some(at)) => format!("push {}", age(at, src.now)),
            (None, None) => "push never".to_string(),
        });
        let mut store = match src.store_failed.at {
            Some(at) => format!(
                "store FAILED {}{}",
                age(at, src.now),
                tally(src.store_failed.count, src.remotes)
            ),
            None => format!(
                "store {}{}{}",
                match src.relation {
                    Relation::Unknown => "unknown",
                    Relation::Absent => "new",
                    Relation::InSync => "ok",
                    Relation::LocalAhead => "ahead",
                    Relation::RemoteAhead => "BEHIND",
                    Relation::Diverged => "DIVERGED",
                },
                match src.relation_seen.at {
                    Some(at) => format!(" {}", age(at, src.now)),
                    None => String::new(),
                },
                tally(src.relation_seen.count, src.remotes)
            ),
        };
        if src.fetching {
            store.push_str(" …");
        }
        chips.push(store);
    }
    if src.peers > 0 {
        let mut bundles = match (src.poll_failed, src.polled_at) {
            (true, Some(at)) => format!("bundles FAILED {}", age(at, src.now)),
            (true, None) => "bundles FAILED".to_string(),
            (false, Some(at)) => format!("bundles {}", age(at, src.now)),
            (false, None) => "bundles never".to_string(),
        };
        if src.bundles > 0 {
            bundles.push_str(&format!(" met {}/{}", src.ready, src.bundles));
        }
        if src.quarantined > 0 {
            bundles.push_str(&format!(" !{}", src.quarantined));
        }
        chips.push(bundles);
        chips.push(format!("peers {}/{}", src.peers_ok, src.peers));
    }
    if src.gate == UnlockGate::Biometric {
        chips.push(format!("pending {}", src.pending));
    }
    chips.join(CHIP)
}

/// The band as it currently stands on screen.
///
/// The repaint rule is that the rendered TEXT differs from what was drawn. A generation counter
/// would miss ageing — nothing mutates for three minutes, but `push 2m` must become `push 3m` —
/// and a timer would repaint when nothing changed at all.
#[derive(Default)]
pub(crate) struct BandCache {
    line: String,
}

impl BandCache {
    /// Re-render the band and say whether the frame has to be drawn again.
    pub(crate) fn tick(&mut self, live: &Live) -> Result<bool, GrantErr> {
        let next = render_band(&live.band_source(now_secs()?));
        if next == self.line {
            return Ok(false);
        }
        self.line = next;
        Ok(true)
    }

    pub(crate) fn line(&self) -> &str {
        &self.line
    }
}

/// The filesystem facts the panel shows, read on entry and on `[r]` only.
///
/// The operator cannot add a keystore or an enrollment while sitting on this screen, so
/// re-reading them per frame would be eight directory scans and eight keyring parses a second for
/// an answer that cannot have changed. `[r]` exists for the case where another process changed
/// the store underneath.
struct Facts {
    /// Keystores in the store dir.
    keystores: usize,
    /// What the keyring says, or that it could not be read.
    enrollments: Enrollments,
}

/// What the keyring holds. A keyring that cannot be read must not close the screen an operator
/// opened BECAUSE something is wrong, so it is a view state here and not a `MenuErr`.
enum Enrollments {
    Counted {
        total: usize,
        se: usize,
        passphrase: usize,
    },
    Unreadable,
}

impl Facts {
    fn read(console: &Console) -> Self {
        let mut keystores = 0usize;
        if let Ok(entries) = std::fs::read_dir(console.rt.config.store_path()) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_file())
                    && entry.file_name().to_str().is_some_and(is_valid_string_name)
                {
                    keystores += 1;
                }
            }
        }
        let enrollments = match Keyring::load(&MacBackend::keyring_path(&console.rt.config.store)) {
            Ok(keyring) => {
                let mut se = 0usize;
                let mut passphrase = 0usize;
                for enrollment in &keyring.enrollments {
                    match enrollment.params {
                        EnrollParams::SecureEnclave { .. } => se += 1,
                        EnrollParams::Passphrase { .. } => passphrase += 1,
                    }
                }
                Enrollments::Counted {
                    total: keyring.enrollments.len(),
                    se,
                    passphrase,
                }
            }
            Err(e) => {
                tracing::warn!(error = ?e, "the status panel could not read the keyring");
                Enrollments::Unreadable
            }
        };
        Self {
            keystores,
            enrollments,
        }
    }
}

/// One labelled line of the panel. An empty label is the continuation of the line above it.
fn row(label: &str, value: &str) -> String {
    format!("  {label:<12} {value}")
}

/// Enough of a commit to tell two apart on one line.
fn short(id: &CommitId) -> String {
    id.to_string().chars().take(SHORT_ID).collect()
}

/// One frame of the panel, unclipped and unbounded, so the repaint test compares what the SCREEN
/// says rather than what any one subsystem thinks it published — a body-only change no chip
/// reflects still repaints, and nothing repaints when every line is byte-identical.
///
/// Per frame this takes each subsystem's lock once and clones the log tail. It touches no
/// filesystem: everything that costs a syscall lives in [`Facts`].
fn body(console: &Console, facts: &Facts, note: &str, now: u64) -> Vec<String> {
    let git = console.rt.git.status().snapshot();
    let serving = match &console.rt.serving {
        Serving::Refused => "refused, this session may not release keys off-process".to_string(),
        live => live.to_string(),
    };
    let mut out = vec![
        "hot_cheese - status".to_string(),
        String::new(),
        row("serving", &serving),
        row(
            "unlock",
            match console.rt.gate {
                UnlockGate::Biometric => "secure enclave, Touch ID gates every request",
                UnlockGate::Passphrase => "recovery passphrase, one prompt at startup",
            },
        ),
        row(
            "store",
            &format!(
                "{} ({} keystores)",
                console.rt.config.store_path().display(),
                facts.keystores
            ),
        ),
        row(
            "vault",
            &format!(
                "{} at {}",
                match &git.vault {
                    Some(vault) => vault.to_string(),
                    None => "none yet".to_string(),
                },
                match &git.head {
                    Some(head) => short(head),
                    None => "no commit yet".to_string(),
                }
            ),
        ),
        row(
            "enrollments",
            &match facts.enrollments {
                Enrollments::Unreadable => "the keyring could not be read".to_string(),
                Enrollments::Counted {
                    total,
                    se,
                    passphrase,
                } => format!(
                    "{total} ({se} secure enclave, {passphrase} passphrase){}",
                    match passphrase {
                        0 => "  [no recovery passphrase]",
                        _ => "",
                    }
                ),
            },
        ),
    ];

    out.push(row(
        "backup",
        &match git.remotes.len() {
            0 => "no remote is configured".to_string(),
            n => format!(
                "{n} remote(s){}",
                match git.fetching {
                    true => ", fetching…",
                    false => "",
                }
            ),
        },
    ));
    for remote in &git.remotes {
        out.push(row(
            "",
            &format!(
                "{}:{} {}, {}, {}",
                remote.host,
                remote.folder,
                remote.relation,
                match remote.last_fetch_ok_at {
                    Some(at) => format!("fetched {} ago", age(at, now)),
                    None => "never fetched".to_string(),
                },
                match remote.last_push_ok_at {
                    Some(at) => format!("pushed {} ago", age(at, now)),
                    None => "never pushed".to_string(),
                }
            ),
        ));
        if remote.relation == Relation::Diverged {
            out.push(row(
                "",
                &format!(
                    "DIVERGED: local {}, remote {}. Nothing was overwritten and [p] will not \
                     resolve this.",
                    match &git.head {
                        Some(head) => short(head),
                        None => "no commit".to_string(),
                    },
                    match &remote.remote_head {
                        Some(head) => short(head),
                        None => "unknown".to_string(),
                    }
                ),
            ));
        }
        if let Some(failure) = &remote.last_failure {
            out.push(row(
                "",
                &format!(
                    "{:?} FAILED {} ago: {} {}",
                    failure.op,
                    age(failure.at, now),
                    failure.cause,
                    failure.stderr.replace(['\n', '\r'], " ")
                ),
            ));
        }
    }

    let poll = console.rt.bundles.status();
    out.push(row(
        "bundles",
        &format!(
            "{}, {} held, {} with the threshold met, {} signature(s) in, {} quarantined",
            match poll.last_finished_at {
                Some(at) => format!("polled {} ago", age(at, now)),
                None => "never polled".to_string(),
            },
            poll.bundles,
            poll.ready,
            poll.arrived,
            poll.quarantined
        ),
    ));
    if let Some(failure) = &poll.failure {
        out.push(row("", &format!("the last poll failed: {failure}")));
    }
    let enrolled = console.rt.config.bundle_peers.len();
    let mut reached = 0usize;
    let mut quiet = Vec::new();
    for peer in &poll.peers {
        match (&peer.pull, peer.last_ok_at) {
            (Ok(()), Some(_)) => reached += 1,
            (Ok(()), None) => quiet.push(format!("{} has not been reached yet", peer.host)),
            (Err(e), _) => quiet.push(format!("{} silent: {e}", peer.host)),
        }
    }
    out.push(row("peers", &format!("{reached} of {enrolled} reached")));
    for line in quiet {
        out.push(row("", &line));
    }
    drop(poll);

    out.push(row(
        "pending",
        &format!(
            "{} request(s) waiting for approval",
            console.rt.live.pending.get()
        ),
    ));
    let tunnels = console.rt.tunnels.list();
    out.push(row(
        "tunnels",
        &match tunnels.len() {
            0 => "none".to_string(),
            n => format!("{n} open"),
        },
    ));
    for (id, spec) in &tunnels {
        out.push(row(
            "",
            &format!(
                "#{} {} remote localhost:{} -> local :{}",
                id.0, spec.target, spec.remote_port, spec.local_port
            ),
        ));
    }
    out.push(row("log", &home_dir().join(LOG_FILE).display().to_string()));

    out.push(String::new());
    let mut keys = String::new();
    if !console.rt.config.backup_remotes.is_empty() {
        keys.push_str("[p] fetch the store now   ");
    }
    keys.push_str("[r] re-read the store   [q] back   [ctrl-c] quit");
    out.push(format!("  {keys}"));
    if !note.is_empty() {
        out.push(format!("  {note}"));
    }

    out.push(String::new());
    let recent = console.log.recent(LOG_TAIL);
    out.push(row("recent log", &format!("{} lines", recent.len())));
    for line in recent {
        out.push(format!("    {line}"));
    }
    out
}

/// Replace the terminal with one frame, cut to what the terminal actually holds so the panel
/// never scrolls itself off the top.
fn draw(lines: &[String]) -> Result<(), MenuErr> {
    let (cols, rows) = terminal::size().map_err(|source| MenuErr::NotATerminal { source })?;
    let mut frame = Vec::new();
    for line in lines.iter().take(usize::from(rows)) {
        frame.push(clip(line, usize::from(cols)));
    }
    execute!(
        std::io::stderr(),
        Hide,
        MoveTo(0, 0),
        Clear(ClearType::FromCursorDown),
        Print(frame.join("\r\n"))
    )?;
    Ok(())
}

/// The Status screen: a panel that repaints itself, because the facts on it move without a
/// keypress. It is where an operator goes when something is wrong, so a broken keyring is a line
/// on it rather than the error that closes it.
///
/// It runs no `inquire` prompt and therefore needs no cooked-mode window: raw mode is entered
/// once and [`RawScreen`]'s `Drop` gives it back on every exit — `[q]`, ctrl-c, an early `?` on a
/// crossterm write, and a panic unwind.
///
/// `[p]` is a FETCH plus a fast-forward-only merge, asked of the store's own background task so
/// this thread never blocks on ssh. It is not the forced pull, which lives on the Backup screen
/// behind the confirmation that names the keystores it would destroy.
pub(crate) fn panel(console: &Console) -> Result<Step, MenuErr> {
    let mut facts = Facts::read(console);
    let mut note = "";
    let mut drawn: Vec<String> = Vec::new();
    let mut dirty = false;
    enable_raw_mode().map_err(|source| MenuErr::NotATerminal { source })?;
    let _screen = RawScreen;
    loop {
        let next = body(console, &facts, note, now_secs()?);
        if next != drawn {
            drawn = next;
            dirty = true;
        }
        if dirty {
            draw(&drawn)?;
            dirty = false;
        }
        match super::tick()? {
            Key::Quit => {
                return Ok(Step {
                    choice: MenuChoice::Quit,
                    notice: String::new(),
                })
            }
            Key::Leave => {
                return Ok(Step {
                    choice: MenuChoice::Back,
                    notice: String::new(),
                })
            }
            Key::Redraw => dirty = true,
            Key::Other('p') => {
                note = match console.rt.config.backup_remotes.is_empty() {
                    true => "no git remote is configured",
                    false => match console.rt.git.request_fetch() {
                        Ok(()) => "asked the store to fetch now",
                        Err(e) => {
                            tracing::warn!(error = %e, "the store's fetch task did not take the request");
                            "the store's background task is gone; nothing will fetch"
                        }
                    },
                }
            }
            Key::Other('r') => {
                facts = Facts::read(console);
                note = "";
            }
            Key::Other(_) | Key::Ignore => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_daemon::live::Tally;

    /// A store with two remotes, three peers and five bundles, all of it healthy.
    fn configured() -> BandSource {
        BandSource {
            now: 1_000_000,
            gate: UnlockGate::Biometric,
            remotes: 2,
            relation: Relation::InSync,
            relation_seen: Tally {
                count: 2,
                at: Some(999_988),
            },
            fetching: false,
            pushed_at: Some(999_820),
            push_failed: Tally::default(),
            store_failed: Tally::default(),
            peers: 3,
            peers_ok: 3,
            polled_at: Some(999_972),
            bundles: 5,
            ready: 2,
            quarantined: 0,
            poll_failed: false,
            pending: 0,
        }
    }

    /// The leading word of every chip, which is what an operator's eye tracks along the line.
    fn keys(line: &str) -> Vec<&str> {
        line.split(CHIP)
            .map(|chip| chip.split(' ').next().unwrap_or_default())
            .collect()
    }

    /// For one configuration every band — healthy, failed, never-run, mid-flight — must carry the
    /// same chips in the same order, or the line shifts sideways under an operator reading it.
    #[test]
    fn the_band_keeps_its_chips_in_place() {
        let healthy = render_band(&configured());
        assert_eq!(
            keys(&healthy),
            vec!["push", "store", "bundles", "peers", "pending"]
        );

        let mut broken = configured();
        broken.relation = Relation::Diverged;
        broken.push_failed = Tally {
            count: 1,
            at: Some(999_880),
        };
        broken.store_failed = Tally {
            count: 1,
            at: Some(999_880),
        };
        broken.peers_ok = 0;
        broken.quarantined = 1;
        broken.poll_failed = true;
        broken.pending = 4;

        let mut fresh = configured();
        fresh.relation = Relation::Unknown;
        fresh.relation_seen = Tally::default();
        fresh.pushed_at = None;
        fresh.polled_at = None;
        fresh.bundles = 0;
        fresh.ready = 0;
        fresh.peers_ok = 0;

        let mut flight = configured();
        flight.relation = Relation::RemoteAhead;
        flight.fetching = true;

        for other in [&broken, &fresh, &flight] {
            let line = render_band(other);
            assert_eq!(keys(&line), keys(&healthy), "{line}");
            assert_ne!(line, healthy, "{line}");
        }

        let mut bare = configured();
        bare.remotes = 0;
        bare.peers = 0;
        assert_eq!(
            render_band(&bare),
            "pending 0",
            "an unserved subsystem shows no chip"
        );
        bare.gate = UnlockGate::Passphrase;
        assert_eq!(
            render_band(&bare),
            "",
            "a session that serves nothing costs no row"
        );
    }

    /// The two age boundaries where the STRING changes, which is where a repaint is triggered,
    /// and the backwards clock, which must never render as negative or absurd.
    #[test]
    fn an_age_rolls_over_where_the_string_changes() {
        assert_eq!(age(0, 59), "59s");
        assert_eq!(age(0, 60), "1m");
        assert_eq!(age(0, 4), "now");
        assert_eq!(age(0, 5), "5s");
        assert_eq!(age(1_000, 500), "now", "a clock behind the event saturates");
    }

    /// The ring must stay bounded at its capacity while keeping the newest lines: it drops the
    /// oldest on overflow, and `recent` returns the tail window in oldest-first order.
    #[test]
    fn ring_evicts_oldest_and_keeps_newest() {
        let ring = LogRing {
            lines: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
        };
        let overflow = 50;
        for i in 0..RING_CAPACITY + overflow {
            ring.push(&format!("line {i}"));
        }

        let all = ring.recent(RING_CAPACITY * 2);
        assert_eq!(all.len(), RING_CAPACITY, "ring must stay bounded");
        assert_eq!(all[0], format!("line {overflow}"), "oldest must be evicted");
        assert_eq!(
            all[RING_CAPACITY - 1],
            format!("line {}", RING_CAPACITY + overflow - 1),
            "newest must survive"
        );

        assert_eq!(
            ring.recent(3),
            vec![
                format!("line {}", RING_CAPACITY + overflow - 3),
                format!("line {}", RING_CAPACITY + overflow - 2),
                format!("line {}", RING_CAPACITY + overflow - 1),
            ]
        );
    }
}
