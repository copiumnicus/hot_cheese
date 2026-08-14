//! The console's list: one row per option, the description of the highlighted row under it,
//! and the two keys that mean navigation rather than an answer.
//!
//! `inquire::Select` cannot carry a per-row description — it has no highlight hook, and → and ←
//! are bound to its filter cursor whether or not filtering is on — so the list is drawn here, on
//! the same crossterm the serve and watch screens already poll. The frame is anchored to the row
//! the screen's header left the cursor on and never writes above it. The keyboard is waited on
//! with a timeout, which is the seam a later drain of queued requests goes through.
use super::approval::RawScreen;
use super::menu::{MenuErr, Nav};
use super::status::BandCache;
use crossterm::cursor::{self, Hide, MoveTo};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::style::Print;
use crossterm::terminal::{self, enable_raw_mode, Clear, ClearType};
use hc_daemon::live::Live;
use std::fmt;
use std::io::Write;

/// Option rows one frame shows before the list scrolls, and the jump PageUp and PageDown make.
const MAX_PAGE: usize = 12;

/// Option rows the list keeps when the terminal is too short for everything else.
const MIN_PAGE: usize = 3;

/// Rows the title occupies.
const TITLE: usize = 1;

/// Rows the help line occupies when it fits.
const HELP: usize = 1;

/// Rows a usable frame needs. A header that ended closer than this to the bottom scrolls the
/// terminal until the widget has them.
const MIN_FRAME: usize = TITLE + MIN_PAGE + HELP;

/// Columns every row and the panel are indented by.
const INDENT: usize = 2;

/// A row of the console's list: what it says, and what → opens under it.
pub(crate) trait Pick: fmt::Display {
    /// What choosing this row does. Empty when the label is the whole story, which shows no
    /// panel and no hint.
    fn describe(&self) -> &str;
}

impl Pick for String {
    fn describe(&self) -> &str {
        ""
    }
}

/// Whether typing filters the list, mirroring inquire's `without_filtering`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Filter {
    On,
    Off,
}

/// One option as the frame shows it, rendered once so a keypress costs no formatting.
struct Row {
    /// The line the list prints.
    label: String,
    /// The sentence the panel prints.
    describe: String,
}

/// What the widget is showing right now.
struct State<'a> {
    /// Every option, in the order they were given.
    rows: &'a [Row],
    /// Rows the typed filter kept, as indexes into `rows`.
    matches: Vec<usize>,
    /// The highlighted row, as an index into `matches`.
    cursor: usize,
    /// Whether the description panel is open.
    expanded: bool,
    /// What the operator has typed, when the list filters.
    typed: String,
    /// Whether typing filters at all.
    filter: Filter,
    /// The live status line as it stands on screen.
    band: BandCache,
    /// Whether the frame has to be drawn again.
    dirty: bool,
}

/// What one keypress settled.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The row the operator took, as an index into the options.
    Chose(usize),
    Back,
    Quit,
}

impl<'a> State<'a> {
    fn new(rows: &'a [Row], filter: Filter) -> Self {
        Self {
            rows,
            matches: (0..rows.len()).collect(),
            cursor: 0,
            expanded: false,
            typed: String::new(),
            filter,
            band: BandCache::default(),
            dirty: true,
        }
    }

    /// Highlight a row, clamped to the list the way inquire clamps: the ends do not wrap.
    fn move_to(&mut self, cursor: usize) {
        self.cursor = cursor.min(self.matches.len().saturating_sub(1));
        self.dirty = true;
    }

    /// Keep the rows whose label holds what was typed, and start again at the top.
    fn rematch(&mut self) {
        let needle = self.typed.to_lowercase();
        self.matches.clear();
        for (i, row) in self.rows.iter().enumerate() {
            if row.label.to_lowercase().contains(&needle) {
                self.matches.push(i);
            }
        }
        self.cursor = 0;
        self.dirty = true;
    }

    fn highlighted(&self) -> Option<&Row> {
        self.matches
            .get(self.cursor)
            .and_then(|i| self.rows.get(*i))
    }

    fn describe(&self) -> &str {
        match self.highlighted() {
            Some(row) => row.describe.as_str(),
            None => "",
        }
    }
}

/// Esc backs out one level and Ctrl-C leaves the console — raw mode clears `ISIG`, so both are
/// keypresses here — and neither is ever an error. → opens the description and ← closes it.
fn step(state: &mut State, key: KeyEvent) -> Option<Outcome> {
    let last = state.matches.len().saturating_sub(1);
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Some(Outcome::Quit),
        KeyCode::Esc => Some(Outcome::Back),
        KeyCode::Enter => state.matches.get(state.cursor).map(|i| Outcome::Chose(*i)),
        KeyCode::Up => {
            state.move_to(state.cursor.saturating_sub(1));
            None
        }
        KeyCode::Down => {
            state.move_to(state.cursor + 1);
            None
        }
        KeyCode::PageUp => {
            state.move_to(state.cursor.saturating_sub(MAX_PAGE));
            None
        }
        KeyCode::PageDown => {
            state.move_to(state.cursor + MAX_PAGE);
            None
        }
        KeyCode::Home => {
            state.move_to(0);
            None
        }
        KeyCode::End => {
            state.move_to(last);
            None
        }
        KeyCode::Right => {
            state.expanded = true;
            state.dirty = true;
            None
        }
        KeyCode::Left => {
            state.expanded = false;
            state.dirty = true;
            None
        }
        KeyCode::Backspace if state.filter == Filter::On => {
            state.typed.pop();
            state.rematch();
            None
        }
        KeyCode::Char(c)
            if state.filter == Filter::On
                && !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            state.typed.push(c);
            state.rematch();
            None
        }
        _ => None,
    }
}

/// How one frame splits the rows it has. The list is served first, so a terminal too short for
/// everything drops the description, then the band, and then the help line, never the options.
#[derive(Debug, PartialEq, Eq)]
struct Budget {
    /// Rows the option list occupies, markers included.
    page: usize,
    /// Rows the live status line occupies: the one it asked for, or none.
    band: usize,
    /// Rows the description panel may use; under two it is left off this frame.
    room: usize,
    /// Whether the help line fits.
    help: bool,
}

/// `band` in is the row the status line wants; `band` out is what the frame may draw. It is paid
/// AFTER the help line: the help line is how the operator leaves the screen and the band is
/// decoration, so at [`MIN_FRAME`] the band is what goes. Payment order is priority; draw order
/// is layout, and the two are independent.
fn budget(rows: usize, start: usize, options: usize, band: usize, wanted: usize) -> Budget {
    let mut left = rows.saturating_sub(start).saturating_sub(TITLE);
    let page = options.min(MAX_PAGE).min(left);
    left -= page;
    let help = left >= HELP;
    if help {
        left -= HELP;
    }
    let band = band.min(left);
    left -= band;
    Budget {
        page,
        band,
        room: wanted.min(left),
        help,
    }
}

/// Which rows a page shows, and how many it left off in each direction. A marker costs a row of
/// the same page, so the block is exactly `page` rows tall wherever the cursor is and nothing
/// under the list moves as the operator walks it.
struct Window {
    /// First row on the frame, as an index into the matches.
    first: usize,
    /// Rows on the frame.
    shown: usize,
    /// Rows left off above, announced only when there is a row to announce them on.
    above: usize,
    /// Rows left off below.
    below: usize,
}

fn fit(count: usize, cursor: usize, shown: usize) -> Window {
    let first = cursor.saturating_sub(shown / 2).min(count - shown);
    Window {
        first,
        shown,
        above: first,
        below: count - first - shown,
    }
}

fn window(count: usize, cursor: usize, page: usize) -> Window {
    if count <= page || page < MIN_PAGE {
        let shown = page.min(count);
        return Window {
            above: 0,
            below: 0,
            ..fit(count, cursor, shown)
        };
    }
    let one = fit(count, cursor, page - 1);
    match one.above > 0 && one.below > 0 {
        true => fit(count, cursor, page - 2),
        false => one,
    }
}

/// Break `text` into lines of at most `width` characters, splitting a word wider than the line
/// rather than letting it run off the frame.
fn wrap(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut len = 0usize;
    for word in text.split_whitespace() {
        let word_len = word.chars().count();
        if len > 0 && len + 1 + word_len > width {
            lines.push(std::mem::take(&mut line));
            len = 0;
        }
        if word_len > width {
            for ch in word.chars() {
                if len == width {
                    lines.push(std::mem::take(&mut line));
                    len = 0;
                }
                line.push(ch);
                len += 1;
            }
            continue;
        }
        if len > 0 {
            line.push(' ');
            len += 1;
        }
        line.push_str(word);
        len += word_len;
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// Cut a line to `width` characters — never bytes, because the labels carry arrows and warning
/// marks that byte truncation would split — and mark the cut.
pub(crate) fn clip(line: &str, width: usize) -> String {
    if line.chars().count() <= width {
        return line.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut out: String = line.chars().take(width - 1).collect();
    out.push('…');
    out
}

fn help_line(state: &State) -> String {
    let mut line = String::from("↑↓ move");
    if !state.describe().is_empty() {
        line.push_str(match state.expanded {
            true => "   ← hide",
            false => "   → describe",
        });
    }
    line.push_str("   enter select   esc back   ctrl-c quit");
    if state.filter == Filter::On {
        line.push_str("   type filters");
    }
    line
}

/// One frame, as one string: the title, the list, the panel the description opens into, and the
/// help line. Nothing is drawn that the budget did not pay for, so the terminal never scrolls
/// and the anchor row stays where the header put it.
fn render(state: &State, title: &str, cols: usize, rows: usize, start: usize) -> String {
    let described = state.describe();
    let wrapped = match state.expanded && !described.is_empty() {
        true => wrap(described, cols.saturating_sub(INDENT)),
        false => Vec::new(),
    };
    let wanted = match wrapped.is_empty() {
        true => 0,
        false => wrapped.len() + 1,
    };
    let budget = budget(
        rows,
        start,
        state.matches.len().max(1),
        usize::from(!state.band.line().is_empty()),
        wanted,
    );

    let head = match state.typed.is_empty() {
        true => title.to_string(),
        false => format!("{title}  {}", state.typed),
    };
    let mut lines = vec![clip(&head, cols)];
    if budget.band > 0 {
        lines.push(clip(&format!("{:INDENT$}{}", "", state.band.line()), cols));
    }

    let win = window(state.matches.len(), state.cursor, budget.page);
    if win.above > 0 {
        lines.push(format!("{:INDENT$}↑ {} more", "", win.above));
    }
    if state.matches.is_empty() && budget.page > 0 {
        lines.push(format!("{:INDENT$}no match", ""));
    }
    let visible = state
        .matches
        .get(win.first..win.first + win.shown)
        .unwrap_or_default();
    for (slot, i) in visible.iter().enumerate() {
        let Some(row) = state.rows.get(*i) else {
            continue;
        };
        let prefix = match win.first + slot == state.cursor {
            true => "›",
            false => " ",
        };
        lines.push(clip(&format!("{prefix} {}", row.label), cols));
    }
    if win.below > 0 {
        lines.push(format!("{:INDENT$}↓ {} more", "", win.below));
    }

    if budget.room >= 2 {
        lines.push(String::new());
        let fits = budget.room - 1;
        let cut = wrapped.len() > fits;
        for (i, line) in wrapped.iter().take(fits).enumerate() {
            let tail = match cut && i + 1 == fits {
                true => "…",
                false => "",
            };
            lines.push(clip(&format!("{:INDENT$}{line}{tail}", ""), cols));
        }
    }
    if budget.help {
        lines.push(clip(&help_line(state), cols));
    }
    lines.join("\r\n")
}

/// The row the widget draws from: where the header left the cursor, after scrolling the
/// terminal when the header ended too close to the bottom for a usable frame. Every query here
/// talks to the tty, so a failure means there is no terminal to draw on at all.
fn anchor() -> Result<u16, MenuErr> {
    let (_, rows) = terminal::size().map_err(|source| MenuErr::NotATerminal { source })?;
    let (_, start) = cursor::position().map_err(|source| MenuErr::NotATerminal { source })?;
    let short = usize::from(rows.saturating_sub(start)) < MIN_FRAME;
    if !short || usize::from(rows) < MIN_FRAME {
        return Ok(start);
    }
    let mut out = std::io::stderr();
    write!(out, "{}", "\r\n".repeat(MIN_FRAME - 1))?;
    out.flush()?;
    Ok(rows - MIN_FRAME as u16)
}

fn draw(state: &State, title: &str, start: u16) -> Result<(), MenuErr> {
    let (cols, rows) = terminal::size().map_err(|source| MenuErr::NotATerminal { source })?;
    let start = start.min(rows.saturating_sub(1));
    let frame = render(
        state,
        title,
        usize::from(cols),
        usize::from(rows),
        usize::from(start),
    );
    execute!(
        std::io::stderr(),
        Hide,
        MoveTo(0, start),
        Clear(ClearType::FromCursorDown),
        Print(frame)
    )?;
    Ok(())
}

/// Put the list in front of the operator and hand back what they did with it. The frame is
/// erased on the way out so the prompts that still run on inquire start on a clean line, and
/// the header the screen wrote above the anchor is left alone.
///
/// The band is ticked at the TOP of the loop rather than in the poll-timeout branch: a held
/// arrow key wakes the loop through the key branch, and a tick that only ran on a timeout would
/// freeze the status for as long as the key is down.
pub(crate) fn pick<T: Pick>(
    live: &Live,
    title: &str,
    mut options: Vec<T>,
    filter: Filter,
) -> Result<Nav<T>, MenuErr> {
    let mut rows = Vec::with_capacity(options.len());
    for option in &options {
        rows.push(Row {
            label: option.to_string(),
            describe: option.describe().to_string(),
        });
    }
    let start = anchor()?;
    enable_raw_mode().map_err(|source| MenuErr::NotATerminal { source })?;
    let _screen = RawScreen;
    let mut state = State::new(&rows, filter);
    let outcome = loop {
        if state.band.tick(live)? {
            state.dirty = true;
        }
        if state.dirty {
            draw(&state, title, start)?;
            state.dirty = false;
        }
        if !crossterm::event::poll(super::TICK)? {
            continue;
        }
        match crossterm::event::read()? {
            Event::Key(key) => {
                if let Some(outcome) = step(&mut state, key) {
                    break outcome;
                }
            }
            Event::Resize(_, _) => state.dirty = true,
            _ => {}
        }
    };
    execute!(
        std::io::stderr(),
        MoveTo(0, start),
        Clear(ClearType::FromCursorDown)
    )?;
    match outcome {
        Outcome::Chose(i) => Ok(Nav::Chose(options.swap_remove(i))),
        Outcome::Back => Ok(Nav::Back),
        Outcome::Quit => Ok(Nav::Quit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<Row> {
        let mut rows = Vec::new();
        for label in ["alpha", "beta", "gamma"] {
            rows.push(Row {
                label: label.to_string(),
                describe: "what it does".to_string(),
            });
        }
        rows
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// A word wider than the line is split rather than left to run off the frame, a word that
    /// exactly fills the line takes it whole, and nothing to wrap — or nowhere to wrap it —
    /// produces no lines at all.
    #[test]
    fn wrapping_splits_only_what_cannot_fit() {
        assert_eq!(wrap("abcdefgh", 3), vec!["abc", "def", "gh"]);
        assert_eq!(wrap("abc", 3), vec!["abc"]);
        assert_eq!(wrap("abc def", 3), vec!["abc", "def"]);
        assert_eq!(wrap("abc de", 6), vec!["abc de"]);
        assert!(wrap("", 20).is_empty());
        assert!(wrap("anything at all", 0).is_empty());
    }

    /// The frame must never be taller than the rows between the anchor and the bottom, or the
    /// terminal scrolls and the anchor is a lie. Within that, the list is paid first: a short
    /// terminal keeps its rows and loses the description, then the band, and a tall one funds all
    /// of them. The sweep proves the sum for every geometry and both band heights, which is what
    /// catches a band that is measured but never subtracted; the fixed cases pin the order the
    /// sweep cannot see, because an inequality holds either way round.
    #[test]
    fn the_budget_pays_the_list_first_and_never_overdraws() {
        let tight = budget(6, 1, 9, 1, 6);
        assert_eq!(
            tight,
            Budget {
                page: MIN_PAGE + 1,
                band: 0,
                room: 0,
                help: false
            }
        );

        let tiny = budget(5, 1, 9, 1, 6);
        assert_eq!(tiny.page, MIN_PAGE, "the list keeps its rows");
        assert_eq!(tiny.room, 0, "the description is what goes");

        let roomy = budget(40, 8, 9, 1, 6);
        assert_eq!(
            roomy,
            Budget {
                page: 9,
                band: 1,
                room: 6,
                help: true
            }
        );

        assert_eq!(
            budget(MIN_FRAME, 0, MIN_PAGE, 1, 6),
            Budget {
                page: MIN_PAGE,
                band: 0,
                room: 0,
                help: true
            },
            "the minimum frame keeps the line that says how to leave and drops the band"
        );

        for rows in 0..30usize {
            for start in 0..rows {
                for options in [0usize, 1, 9, 200] {
                    for band in [0usize, 1] {
                        let b = budget(rows, start, options, band, 40);
                        let chrome = TITLE + b.band + usize::from(b.help);
                        assert!(
                            b.page + b.room + chrome <= rows - start,
                            "frame overdrew {rows}x{start} with {options} options \
                             and band {band}: {b:?}"
                        );
                        assert!(b.band <= band, "the frame drew a band nobody asked for");
                    }
                }
            }
        }
    }

    /// The two keys that mean navigation must never become an answer or an error, and the two
    /// arrows the description hangs on must set and clear it — the whole point of the widget.
    #[test]
    fn the_arrows_describe_and_esc_and_ctrl_c_navigate() {
        let rows = rows();
        let mut state = State::new(&rows, Filter::Off);

        assert_eq!(step(&mut state, press(KeyCode::Esc)), Some(Outcome::Back));
        assert_eq!(
            step(
                &mut state,
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
            ),
            Some(Outcome::Quit)
        );

        assert!(!state.expanded);
        assert_eq!(step(&mut state, press(KeyCode::Right)), None);
        assert!(state.expanded, "→ opens the description");
        assert_eq!(step(&mut state, press(KeyCode::Left)), None);
        assert!(!state.expanded, "← closes it again");

        assert_eq!(step(&mut state, press(KeyCode::Down)), None);
        assert_eq!(
            step(&mut state, press(KeyCode::Enter)),
            Some(Outcome::Chose(1)),
            "enter answers with the highlighted row"
        );
    }

    /// Typing is a filter only where the call site asked for one: with it off, a letter must not
    /// eat the list, and Ctrl-C stays navigation rather than a filtered "c".
    #[test]
    fn typing_filters_only_where_it_is_enabled() {
        let rows = rows();
        let mut state = State::new(&rows, Filter::Off);
        assert_eq!(step(&mut state, press(KeyCode::Char('b'))), None);
        assert_eq!(state.matches.len(), 3, "an unfiltered list never shrinks");

        let mut state = State::new(&rows, Filter::On);
        assert_eq!(step(&mut state, press(KeyCode::Char('B'))), None);
        assert_eq!(state.matches, vec![1], "the match ignores case");
        assert_eq!(
            step(
                &mut state,
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
            ),
            Some(Outcome::Quit)
        );
        assert_eq!(step(&mut state, press(KeyCode::Backspace)), None);
        assert_eq!(state.matches.len(), 3, "backspace gives the rows back");
    }
}
