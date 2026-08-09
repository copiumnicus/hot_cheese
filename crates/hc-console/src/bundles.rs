//! The Bundles section: several devices collecting owner signatures for one Safe transaction.
//!
//! Everything here drives [`hc_bundle`], which reads, merges, syncs and returns data.
//! The one verb that needs a signature does not sign: it asks the engine what to sign, hands
//! that to the console's OWN [`hc_daemon::HotApi::sign_intent`] — the same call the Sign screen
//! makes, with the same approver, the same policy check and the same single biometric — and
//! hands the answer back to the engine. There is no second route to a key in this file.
use super::approval::{ConsoleApprover, RawScreen};
use super::menu::{
    ask, keystore_names, menu_enum, nav, service_pending, MenuChoice, MenuErr, Nav, Step,
};
use super::pick::{pick, Filter, Pick};
use super::Console;
use alloy_primitives::{Address, B256};
use crossterm::cursor::{Hide, MoveTo};
use crossterm::event::{Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::style::Print;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use hashbrown::HashMap;
use hc_bundle::sync::{self, Report, SyncMode};
use hc_bundle::tailnet::{Backend, TailnetErr};
use hc_bundle::{Arrival, Loaded, Scope, Slot, Watch};
use hc_core::config::{home_dir, Config};
use hc_daemon::{OpContext, Operation, Peer};
use hc_sign::bundle::SafeTxBundle;
use hc_sign::intent::Intent;
use hc_sign::SignResponse;
use inquire::{Confirm, Text};
use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Bundles the landing screen puts in the list before it counts the rest.
const MAX_ROWS: usize = 100;

/// Hex characters of an address or a digest shown in a row.
const SHORT: usize = 8;

/// Lines one section of a rendered view shows before it counts the rest.
const MAX_LINES: usize = 8;

/// Milliseconds in an hour, the unit a bundle's age is read in.
const HOUR_MS: u64 = 3_600_000;

/// How long the watch screen waits on the keyboard between drains.
const TICK: Duration = Duration::from_millis(120);

/// Arrivals the watch screen keeps on the frame.
const MAX_ARRIVALS: usize = 8;

/// Files one directory contributes to a JSON picker.
const MAX_FILES: usize = 40;

menu_enum!(BundleAction {
    Sign => "Sign with a local key",
        "Asks the engine what this device has to sign and signs it through the console's own \
         path: the same policy check, the same approval prompt, the same single biometric.",
    Status => "Status: signatures, missing owners, rivals",
        "The merged bundle judged against safes.toml as it reads right now: who signed, which \
         owners are missing, and any rival on the same nonce. Reads only.",
    Qr => "Show the transaction as a QR",
        "Draws the transaction as QR parts for another device's camera, one part per keypress, \
         so a frame is never replaced before it is scanned.",
    Export => "Export the execTransaction call",
        "Prints the execTransaction call with every collected signature packed in owner order, \
         ready for whoever broadcasts it.",
    Import => "Import a signature from another device",
        "Takes one device's signature or a whole bundle, from a file or a paste. Every signature \
         is checked against the digest rebuilt from our own fields.",
    Watch => "Watch this bundle for arriving signatures",
        "Polls the peers until signatures land, and services queued requests while it waits so \
         nothing is stranded behind the wait. q leaves it.",
    Remove => "Remove this bundle from this machine",
        "Retires the bundle here after a confirmation, discarding the signatures it holds. A \
         peer that still has it pushes it back on the next sync.",
    Back => "Back",
        "Leave this bundle for the list of them.",
});

menu_enum!(PeerAction {
    Add => "Enroll a machine from the tailnet",
        "Picks a machine off the tailnet and enrolls it, so every later bundle write exchanges \
         with it.",
    Remove => "Stop syncing with a machine",
        "Drops one machine from the enrolled list. The bundles already on this disk stay.",
    Sync => "Exchange every bundle with the enrolled machines now",
        "Pulls and pushes every bundle once, now. A machine that does not answer is a line on \
         the frame, not a failure.",
    Refresh => "Refresh",
        "Reads the tailnet and the enrolled list again, and draws them.",
    Back => "Back",
        "Leave this screen for the bundle list.",
});

menu_enum!(QrStep {
    Next => "Next part",
        "Draw the next part. The far device rebuilds the digest from the parts and shows its own \
         summary of it.",
    Done => "Done",
        "Stop drawing parts and go back to the bundle.",
});

/// One line of the landing screen: a bundle to open, or one of the section's own verbs.
enum Landing {
    /// A pending bundle.
    Open {
        /// The digest its directory is named for.
        hash: B256,
        /// The row the menu shows.
        label: String,
    },
    New,
    Watch,
    Peers,
    Back,
}

impl fmt::Display for Landing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Landing::Open { label, .. } => f.write_str(label),
            Landing::New => f.write_str("New bundle from an intent file"),
            Landing::Watch => f.write_str("Watch every bundle for arriving signatures"),
            Landing::Peers => f.write_str("Peers"),
            Landing::Back => f.write_str("Back"),
        }
    }
}

impl Pick for Landing {
    fn describe(&self) -> &str {
        match self {
            Landing::Open { .. } => "",
            Landing::New => {
                "Reads a Safe transaction intent from a JSON file and starts a bundle for it, \
                 which the enrolled peers pick up on the next sync."
            }
            Landing::Watch => {
                "Polls every bundle until signatures land, servicing queued requests while it \
                 waits. q leaves it."
            }
            Landing::Peers => {
                "The machines this one exchanges bundles with, and the tailnet they are picked \
                 from."
            }
            Landing::Back => "Leave the bundles for the main menu.",
        }
    }
}

/// One tailnet machine the operator can enroll.
struct PeerChoice {
    /// What [`sync::peer_add`] is given: the MagicDNS name when the tailnet has one.
    name: String,
    /// The line the menu shows.
    label: String,
}

impl fmt::Display for PeerChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label)
    }
}

impl Pick for PeerChoice {
    fn describe(&self) -> &str {
        ""
    }
}

/// Where an imported JSON body comes from.
enum Source {
    File(PathBuf),
    Paste,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::File(path) => write!(f, "{}", path.display()),
            Source::Paste => f.write_str("Paste the JSON instead"),
        }
    }
}

impl Pick for Source {
    fn describe(&self) -> &str {
        match self {
            Source::File(_) => "",
            Source::Paste => {
                "Type or paste the JSON on one line, for a body that is not in a file here."
            }
        }
    }
}

fn short(bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    format!("0x{}", &hex[..SHORT.min(hex.len())])
}

/// Take at most [`MAX_LINES`] of a list onto a frame, then say how many were left off it.
fn capped(lines: &mut Vec<String>, rows: Vec<String>) {
    let extra = rows.len().saturating_sub(MAX_LINES);
    for row in rows.into_iter().take(MAX_LINES) {
        lines.push(row);
    }
    if extra > 0 {
        lines.push(format!("  … and {extra} more"));
    }
}

/// What one sync run did, as one line for the frame. An unreachable peer is a note and never an
/// error: the engine carries on past it, and the operator stays where they are.
fn sync_note(report: &Report) -> String {
    if report.peers.is_empty() {
        return String::new();
    }
    let failed = report.failed();
    let mut line = format!(
        "peers: {} of {} reached",
        report.peers.len() - failed,
        report.peers.len()
    );
    if failed > 0 {
        let mut hosts = Vec::new();
        for peer in &report.peers {
            if peer.result.is_err() {
                hosts.push(peer.host.as_str());
            }
        }
        line.push_str(&format!("; no answer from {}", hosts.join(", ")));
    }
    if !report.verdict.rejected.is_empty() {
        line.push_str(&format!(
            "; quarantined {} file(s) a peer pushed",
            report.verdict.rejected.len()
        ));
    }
    if !report.verdict.crowded.is_empty() {
        line.push_str(&format!(
            "; {} bundle(s) hold more files than the cap",
            report.verdict.crowded.len()
        ));
    }
    if report.verdict.capped {
        line.push_str("; too many files to validate in one pass");
    }
    line
}

/// One bundle as the list shows it: what it competes for, how far it has got, which of this
/// session's own keys are already in it, and — first on the line — whether another transaction
/// is contesting its nonce.
fn row(one: &Loaded, slot: &Slot, rival: bool, signers: &HashMap<Address, String>) -> String {
    let mut mine = Vec::new();
    for sig in &one.bundle.signatures {
        if let Some(name) = signers.get(&sig.signer) {
            mine.push(name.as_str());
        }
    }
    format!(
        "{:<6}{}/{} {:<4}{}  safe {}  chain {}  nonce {}  you: {}",
        if rival { "RIVAL" } else { "" },
        one.bundle.signatures.len(),
        one.bundle.threshold,
        if one.bundle.met() { "met" } else { "" },
        short(one.hash.as_slice()),
        short(slot.safe.as_slice()),
        slot.chain_id,
        slot.nonce,
        if mine.is_empty() {
            "none".to_string()
        } else {
            mine.join(", ")
        }
    )
}

/// The section's landing screen: every pending bundle, then the verbs that are not about one
/// bundle. The peers are pulled first rather than through `list`, so an unreachable machine is
/// a line on this frame instead of a silence.
pub(crate) fn screen(console: &mut Console, approver: &ConsoleApprover) -> Result<Step, MenuErr> {
    let mut header = vec![sync_note(&sync::pull(Scope::All))];
    let mut options = Vec::new();
    let mut pending = 0usize;
    match hc_bundle::list(SyncMode::Off) {
        Ok(grouped) => {
            for (slot, group) in &grouped {
                for one in group {
                    pending += 1;
                    if options.len() < MAX_ROWS {
                        options.push(Landing::Open {
                            hash: one.hash,
                            label: row(one, slot, group.len() > 1, &console.signers),
                        });
                    }
                }
            }
        }
        Err(e) => header.push(format!("the bundle tree could not be read: {e}")),
    }
    let listed = options.len();
    options.push(Landing::New);
    options.push(Landing::Watch);
    options.push(Landing::Peers);
    options.push(Landing::Back);

    let mut out = std::io::stderr();
    for line in &header {
        if !line.is_empty() {
            writeln!(out, "{line}")?;
        }
    }
    if pending > listed {
        writeln!(out, "{} more bundle(s) not listed", pending - listed)?;
    }
    writeln!(out)?;
    out.flush()?;

    let prompt = format!("Bundles ({pending} pending)");
    let chosen = ask!(pick(&prompt, options, Filter::On));
    match chosen {
        Landing::Back => Ok(Step {
            choice: MenuChoice::Back,
            notice: String::new(),
        }),
        Landing::Peers => Ok(Step {
            choice: MenuChoice::BundlePeers,
            notice: String::new(),
        }),
        Landing::New => new_bundle(),
        Landing::Watch => watch(console, approver, Scope::All),
        Landing::Open { hash, .. } => open(console, approver, hash),
    }
}

/// What one bundle can be asked to do. Esc here returns to the list, one level up.
fn open(console: &mut Console, approver: &ConsoleApprover, hash: B256) -> Result<Step, MenuErr> {
    let title = format!("Bundle {hash}");
    let action = ask!(
        pick(&title, BundleAction::ALL.to_vec(), Filter::Off),
        MenuChoice::Bundles
    );
    match action {
        BundleAction::Back => Ok(Step {
            choice: MenuChoice::Bundles,
            notice: String::new(),
        }),
        BundleAction::Sign => sign(console, approver, hash),
        BundleAction::Status => Ok(Step {
            choice: MenuChoice::Bundles,
            notice: status_view(hash)?,
        }),
        BundleAction::Qr => qr(hash),
        BundleAction::Export => Ok(Step {
            choice: MenuChoice::Bundles,
            notice: serde_json::to_string_pretty(&hc_bundle::export(SyncMode::On, hash)?)?,
        }),
        BundleAction::Import => import(hash),
        BundleAction::Watch => watch(console, approver, Scope::One(hash)),
        BundleAction::Remove => remove(hash),
    }
}

/// Ask the engine what this device has to sign, sign it through the console's existing path,
/// and hand the answer back. The keystore is picked from the store's own names, so no key name
/// is typed, and the address that comes back is remembered for the list's "you" column.
fn sign(console: &mut Console, approver: &ConsoleApprover, hash: B256) -> Result<Step, MenuErr> {
    let key = ask!(
        pick("Sign with", keystore_names(console)?, Filter::On),
        MenuChoice::Bundles
    );
    let intent = hc_bundle::intent_to_sign(SyncMode::On, hash, &key)?;
    let body = serde_json::to_vec(&Intent::SafeTx(intent))?;
    let ctx = OpContext {
        key: key.clone(),
        op: Operation::Sign,
        peer: Peer::Cli,
    };
    let signed = console.api.sign_intent(&ctx, &body, approver)?;
    let response: SignResponse = serde_json::from_slice(&signed)?;
    let signer = response.signer;
    let after = hc_bundle::collect(SyncMode::On, hash, response)?;
    let notice = format!(
        "signed as {signer} with \"{key}\": {}/{} collected{}",
        after.signatures.len(),
        after.threshold,
        if after.met() { ", threshold met" } else { "" }
    );
    console.signers.insert(signer, key);
    Ok(Step {
        choice: MenuChoice::Bundles,
        notice,
    })
}

/// The merged view of one bundle, judged against `safes.toml` as it reads right now.
fn status_view(hash: B256) -> Result<String, MenuErr> {
    let s = hc_bundle::status(SyncMode::On, hash)?;
    let intent = &s.bundle.intent;
    let mut lines = vec![
        format!("bundle {}", s.hash),
        format!(
            "safe {}  chain {}  nonce {}  age {}h",
            intent.safe,
            intent.chain_id,
            intent.nonce,
            s.age_ms / HOUR_MS
        ),
        format!(
            "to {}  value {}  data {} bytes  {:?}",
            intent.to,
            intent.value,
            intent.data.len(),
            intent.operation
        ),
        format!(
            "collected {}/{}{}  packed {} bytes",
            s.bundle.signatures.len(),
            s.bundle.threshold,
            if s.bundle.met() { "  met" } else { "" },
            s.bundle.packed().len()
        ),
    ];
    if s.safes_threshold != s.bundle.threshold {
        lines.push(format!(
            "THRESHOLD CHANGED: this bundle was built for {}, safes.toml states {}",
            s.bundle.threshold, s.safes_threshold
        ));
    }
    let mut rows = Vec::new();
    for sig in &s.bundle.signatures {
        rows.push(format!(
            "  signed  {}{}",
            sig.signer,
            match s.not_owners.contains(&sig.signer) {
                true => "  NOT AN OWNER in safes.toml: the assembled blob reverts",
                false => "",
            }
        ));
    }
    capped(&mut lines, rows);
    let mut rows = Vec::new();
    for owner in &s.missing {
        rows.push(format!("  missing {owner}"));
    }
    capped(&mut lines, rows);
    let mut rows = Vec::new();
    for rival in &s.rivals {
        rows.push(format!(
            "  RIVAL {rival}: same Safe, chain and nonce, a different transaction"
        ));
    }
    capped(&mut lines, rows);
    Ok(lines.join("\n"))
}

/// The transaction on screen for another device's camera. Each part waits for the operator,
/// because a frame that is replaced before it is scanned was never shown.
fn qr(hash: B256) -> Result<Step, MenuErr> {
    let set = hc_bundle::qr_frames(hash)?;
    let of = set.len();
    for (i, frame) in set.iter().enumerate() {
        let rendered = hc_daemon::qr_term::render(frame)?;
        let mut out = std::io::stderr();
        execute!(out, Clear(ClearType::All), MoveTo(0, 0))?;
        write!(out, "{rendered}")?;
        out.flush()?;
        let options = match i + 1 < of {
            true => QrStep::ALL.to_vec(),
            false => vec![QrStep::Done],
        };
        let step = ask!(
            pick(&format!("part {}/{of}", i + 1), options, Filter::Off),
            MenuChoice::Bundles
        );
        if step == QrStep::Done {
            break;
        }
    }
    Ok(Step {
        choice: MenuChoice::Bundles,
        notice: format!("showed {of} QR part(s)"),
    })
}

/// Take in what another device produced: one device's signature, or a whole bundle carrying
/// several. Both land through the engine, which checks every signature against the digest it
/// rebuilds from our own fields.
fn import(hash: B256) -> Result<Step, MenuErr> {
    let bytes = ask!(pick_json("Signature or bundle JSON"), MenuChoice::Bundles);
    if let Ok(response) = serde_json::from_slice::<SignResponse>(&bytes) {
        let signer = response.signer;
        let after = hc_bundle::collect(SyncMode::On, hash, response)?;
        return Ok(Step {
            choice: MenuChoice::Bundles,
            notice: format!(
                "took {signer}'s signature: {}/{} collected",
                after.signatures.len(),
                after.threshold
            ),
        });
    }
    let incoming: SafeTxBundle = serde_json::from_slice(&bytes)?;
    let merged = hc_bundle::merge(SyncMode::On, hash, incoming)?;
    let mut added = Vec::new();
    for signer in &merged.added {
        added.push(short(signer.as_slice()));
    }
    Ok(Step {
        choice: MenuChoice::Bundles,
        notice: format!(
            "merged {} new signature(s) [{}]: {}/{} collected",
            merged.added.len(),
            added.join(", "),
            merged.union.signatures.len(),
            merged.union.threshold
        ),
    })
}

fn new_bundle() -> Result<Step, MenuErr> {
    let bytes = ask!(
        pick_json("Intent JSON for the new bundle"),
        MenuChoice::Bundles
    );
    let Intent::SafeTx(intent) = serde_json::from_slice(&bytes)?;
    let hash = hc_bundle::new(SyncMode::On, intent)?;
    Ok(Step {
        choice: MenuChoice::Bundles,
        notice: format!("created bundle {hash}"),
    })
}

fn remove(hash: B256) -> Result<Step, MenuErr> {
    let confirmed = ask!(
        nav(Confirm::new(
            "Retire this bundle on THIS machine? A peer that still holds it will push it back."
        )
        .with_default(false)
        .prompt()),
        MenuChoice::Bundles
    );
    if !confirmed {
        return Ok(Step {
            choice: MenuChoice::Bundles,
            notice: "removal declined".to_string(),
        });
    }
    let held = hc_bundle::rm(hash)?;
    Ok(Step {
        choice: MenuChoice::Bundles,
        notice: format!(
            "retired {hash}, discarding {} signature(s)",
            held.signatures.len()
        ),
    })
}

/// Every `.json` file the operator could plausibly mean, so nobody types a path: the hot_cheese
/// home dir and the directory the console was started in.
fn json_files() -> Vec<PathBuf> {
    let mut dirs = vec![home_dir()];
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut found = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|e| e == "json") {
                found.push(path);
            }
        }
        found.sort();
        found.truncate(MAX_FILES);
        out.extend(found);
    }
    out.dedup();
    out
}

/// A JSON body from a file the operator picks, or from a paste. Both are bytes; nothing here
/// decides what they mean.
fn pick_json(prompt: &str) -> Result<Nav<Vec<u8>>, MenuErr> {
    let mut options = Vec::new();
    for path in json_files() {
        options.push(Source::File(path));
    }
    options.push(Source::Paste);
    let chosen = match pick(prompt, options, Filter::On)? {
        Nav::Chose(v) => v,
        Nav::Back => return Ok(Nav::Back),
        Nav::Quit => return Ok(Nav::Quit),
    };
    match chosen {
        Source::File(path) => Ok(Nav::Chose(std::fs::read(&path)?)),
        Source::Paste => match nav(Text::new("JSON")
            .with_help_message("one line; pick a file for anything pretty-printed")
            .prompt())?
        {
            Nav::Chose(text) => Ok(Nav::Chose(text.into_bytes())),
            Nav::Back => Ok(Nav::Back),
            Nav::Quit => Ok(Nav::Quit),
        },
    }
}

/// What the watch screen is showing right now.
struct WatchView {
    /// Bundles being watched.
    watching: usize,
    /// The last pull's peer note.
    peers: String,
    /// The most recent arrivals, newest last.
    arrivals: Vec<String>,
    /// Signatures that have arrived since this screen opened.
    seen: usize,
    /// Requests serviced at a prompt while watching.
    serviced: usize,
    /// Whether a pull is in flight right now.
    syncing: bool,
}

impl WatchView {
    fn push(&mut self, arrival: Arrival) {
        self.seen += 1;
        if self.arrivals.len() == MAX_ARRIVALS {
            self.arrivals.remove(0);
        }
        self.arrivals.push(format!(
            "{}  {}  {}/{}{}",
            short(arrival.hash.as_slice()),
            arrival.signer,
            arrival.have,
            arrival.threshold,
            if arrival.met { "  MET" } else { "" }
        ));
    }
}

fn draw_watch(view: &WatchView, interval: Duration) -> Result<(), MenuErr> {
    let mut panel = format!(
        "hot_cheese - watching for signatures\r\n\r\n  \
         watching {} bundle(s)   polling every {}s{}\r\n  \
         {}\r\n  \
         serviced {} request(s) while watching\r\n\r\n",
        view.watching,
        interval.as_secs(),
        if view.syncing { "   syncing…" } else { "" },
        match view.peers.is_empty() {
            true => "no bundle peers enrolled",
            false => view.peers.as_str(),
        },
        view.serviced
    );
    if view.arrivals.is_empty() {
        panel.push_str("  nothing has arrived yet\r\n");
    }
    if view.seen > view.arrivals.len() {
        panel.push_str(&format!(
            "  {} earlier arrival(s) not shown\r\n",
            view.seen - view.arrivals.len()
        ));
    }
    for line in &view.arrivals {
        panel.push_str(&format!("  {line}\r\n"));
    }
    panel.push_str("\r\n  [q] back to the bundles   [ctrl-c] quit\r\n");
    execute!(
        std::io::stderr(),
        Hide,
        MoveTo(0, 0),
        Clear(ClearType::FromCursorDown),
        Print(panel)
    )?;
    Ok(())
}

/// The screen the operator sits on while a co-signer signs. It has the serve screen's shape —
/// raw mode, one redraw in place per pass, `q` between any two of them — and it runs the
/// approval drain on every pass, so a request that queues while the operator waits is answered
/// here instead of being stranded behind the wait.
fn watch(console: &mut Console, approver: &ConsoleApprover, scope: Scope) -> Result<Step, MenuErr> {
    let interval = Duration::from_secs(console.config.bundle_watch_secs());
    let mut watch = Watch::start(scope)?;
    let mut view = WatchView {
        watching: watch.watching(),
        peers: String::new(),
        arrivals: Vec::new(),
        seen: 0,
        serviced: 0,
        syncing: false,
    };
    enable_raw_mode()?;
    let _screen = RawScreen;
    let mut due = Instant::now();
    let mut dirty = true;
    loop {
        if Instant::now() >= due {
            view.syncing = true;
            draw_watch(&view, interval)?;
            view.peers = sync_note(&sync::pull(scope));
            for arrival in watch.poll(SyncMode::Off)? {
                view.push(arrival);
            }
            view.watching = watch.watching();
            view.syncing = false;
            due = Instant::now() + interval;
            dirty = true;
        }
        let cooked = disable_raw_mode();
        let drained = service_pending(console, approver);
        cooked?;
        enable_raw_mode()?;
        let drained = drained?;
        if drained.quit {
            return Ok(Step {
                choice: MenuChoice::Quit,
                notice: String::new(),
            });
        }
        if drained.answered > 0 || drained.refused > 0 {
            view.serviced += drained.answered + drained.refused;
            dirty = true;
        }
        if dirty {
            draw_watch(&view, interval)?;
            dirty = false;
        }
        if !crossterm::event::poll(TICK)? {
            continue;
        }
        match crossterm::event::read()? {
            Event::Key(key) => match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(Step {
                        choice: MenuChoice::Quit,
                        notice: String::new(),
                    })
                }
                KeyCode::Char('q') | KeyCode::Esc => {
                    return Ok(Step {
                        choice: MenuChoice::Bundles,
                        notice: format!("stopped watching after {} arrival(s)", view.seen),
                    })
                }
                _ => {}
            },
            Event::Resize(_, _) => dirty = true,
            _ => {}
        }
    }
}

/// The tailnet as the peers screen shows it. A discovery that failed is a line naming the fix
/// rather than an empty list: "nobody is here" and "Tailscale is not running" have different
/// answers, and the engine already tells them apart.
fn peer_view() -> Vec<String> {
    let peers = match sync::peer_list() {
        Ok(peers) => peers,
        Err(sync::SyncErr::Tailnet(e)) => return vec![tailnet_line(&e)],
        Err(e) => return vec![format!("the tailnet could not be read: {e}")],
    };
    let mut lines = vec![format!("tailnet: {} machine(s)", peers.tailnet.len())];
    let mut rows = Vec::new();
    for view in &peers.tailnet {
        rows.push(format!(
            "  {:<18}{:<34}{:<9}{}",
            view.node.host_name,
            view.node
                .dns_name
                .as_deref()
                .unwrap_or("(no MagicDNS name)"),
            match view.node.online {
                true => "online",
                false => "offline",
            },
            match view.enrolled {
                true => "ENROLLED",
                false => "",
            }
        ));
    }
    capped(&mut lines, rows);
    for host in &peers.orphans {
        lines.push(format!(
            "  {host}: enrolled, but no tailnet machine answers to that name"
        ));
    }
    lines
}

/// What a discovery failure means, and what fixes it.
fn tailnet_line(e: &TailnetErr) -> String {
    match e {
        TailnetErr::BinaryNotFound { searched } => format!(
            "Tailscale is not installed: no `tailscale` binary in the {} place(s) searched",
            searched.len()
        ),
        TailnetErr::BackendNotRunning { state } => {
            let fix = match state {
                Backend::Running => "it answered for no tailnet",
                Backend::NeedsLogin => "it is logged out, so run `tailscale login`",
                Backend::NeedsMachineAuth => "this machine is not approved on the tailnet yet",
                Backend::Stopped => "it is stopped, so run `tailscale up`",
                Backend::Starting => "it is still starting, so try again in a moment",
                Backend::NoState => "tailscaled has not been started",
                Backend::Other => "it is in a state this build does not name",
            };
            format!("Tailscale is not running: {fix}")
        }
        e => format!("the tailnet could not be read: {e}"),
    }
}

/// The peers screen: who is on the tailnet, who this machine already syncs with, and the three
/// verbs that change either answer. Esc climbs back to the bundle list.
pub(crate) fn peers_screen() -> Result<Step, MenuErr> {
    let mut out = std::io::stderr();
    for line in peer_view() {
        writeln!(out, "{line}")?;
    }
    writeln!(out)?;
    out.flush()?;

    let action = ask!(pick("Peers", PeerAction::ALL.to_vec(), Filter::Off));
    let notice = match action {
        PeerAction::Back => {
            return Ok(Step {
                choice: MenuChoice::Back,
                notice: String::new(),
            })
        }
        PeerAction::Refresh => String::new(),
        PeerAction::Add => {
            let peers = match sync::peer_list() {
                Ok(peers) => peers,
                Err(sync::SyncErr::Tailnet(e)) => {
                    return Ok(Step {
                        choice: MenuChoice::BundlePeers,
                        notice: tailnet_line(&e),
                    })
                }
                Err(e) => return Err(e.into()),
            };
            let mut options = Vec::new();
            for view in peers.tailnet {
                if view.enrolled {
                    continue;
                }
                let name = view
                    .node
                    .dns_name
                    .clone()
                    .unwrap_or_else(|| view.node.host_name.clone());
                options.push(PeerChoice {
                    label: format!(
                        "{:<18}{:<34}{}",
                        view.node.host_name,
                        name,
                        match view.node.online {
                            true => "online",
                            false => "offline",
                        }
                    ),
                    name,
                });
            }
            if options.is_empty() {
                return Err(MenuErr::NoDiscoveredPeers);
            }
            let chosen = ask!(pick("Enroll", options, Filter::On), MenuChoice::BundlePeers);
            let peer = sync::peer_add(&chosen.name)?;
            format!(
                "enrolled {} ({}); every bundle write syncs with it from here",
                peer.host,
                peer.dir()
            )
        }
        PeerAction::Remove => {
            let mut options = Vec::new();
            for peer in Config::load()?.bundle_peers {
                options.push(peer.host);
            }
            if options.is_empty() {
                return Err(MenuErr::NoEnrolledPeers);
            }
            let chosen = ask!(
                pick("Stop syncing with", options, Filter::On),
                MenuChoice::BundlePeers
            );
            format!("dropped {}", sync::peer_rm(&chosen)?.host)
        }
        PeerAction::Sync => {
            let synced = sync::sync_now(Scope::All);
            let pulled = sync_note(&synced.pulled);
            let pushed = sync_note(&synced.pushed);
            match pulled.is_empty() && pushed.is_empty() {
                true => "no bundle peers enrolled".to_string(),
                false => format!("pulled — {pulled}\npushed — {pushed}"),
            }
        }
    };
    Ok(Step {
        choice: MenuChoice::BundlePeers,
        notice,
    })
}
