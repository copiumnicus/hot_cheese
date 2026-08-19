//! The Bundles section: several devices collecting owner signatures for one Safe transaction.
//!
//! Everything here drives [`hc_bundle`], which reads, merges, syncs and returns data.
//! The one verb that needs a signature does not sign: it asks the engine what to sign, hands
//! that to the console's OWN [`hc_daemon::HotApi::sign_typed`], with the same approver, the same
//! policy check and the same single biometric the loopback route pays, and hands the answer back
//! to the engine. There is no second route to a key in this file.
use super::menu::{ask, keystore_names, menu_enum, nav, MenuChoice, MenuErr, Nav, Step};
use super::pick::{pick, Filter, Pick};
use super::Console;
use alloy_primitives::{Address, B256};
use crossterm::cursor::MoveTo;
use crossterm::execute;
use crossterm::terminal::{Clear, ClearType};
use hashbrown::HashMap;
use hc_bundle::sync::{self, SyncMode};
use hc_bundle::tailnet::{Backend, TailnetErr};
use hc_bundle::{Loaded, Slot};
use hc_core::config::{home_dir, Config};
use hc_daemon::bundle_poll::Poke;
use hc_daemon::live::Live;
use hc_daemon::{OpContext, Operation};
use hc_sign::bundle::{Quorum, SafeTxBundle};
use hc_sign::grant::now_secs;
use hc_sign::intent::Intent;
use hc_sign::SignResponse;
use inquire::{Confirm, Text};
use std::fmt;
use std::io::Write;
use std::path::PathBuf;

/// Bundles the landing screen puts in the list before it counts the rest.
const MAX_ROWS: usize = 100;

/// Hex characters of an address or a digest shown in a row.
const SHORT: usize = 8;

/// Lines one section of a rendered view shows before it counts the rest.
const MAX_LINES: usize = 8;

/// Milliseconds in an hour, the unit a bundle's age is read in.
const HOUR_MS: u64 = 3_600_000;

/// Files one directory contributes to a JSON picker.
const MAX_FILES: usize = 40;
/// Directory entries inspected before the picker gives up looking for those files. The working
/// directory is not a trusted store and can contain arbitrarily much unrelated material.
const MAX_JSON_ENUM_ENTRIES: usize = hc_core::MAX_STORE_ENUM_ENTRIES;

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
    Peers,
    Back,
}

impl fmt::Display for Landing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Landing::Open { label, .. } => f.write_str(label),
            Landing::New => f.write_str("New bundle from an intent file"),
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
            Source::File(path) => {
                f.write_str(&hc_core::safe_diagnostic_text(&path.display().to_string()))
            }
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

/// Signatures held over what the LOCAL `safes.toml` requires, naming the peer file's figure only
/// where it disagrees, so a hostile peer's number is never shown as the requirement.
fn collected(quorum: &Quorum) -> String {
    match quorum.stated {
        None => format!("{}/{}", quorum.have, quorum.threshold),
        Some(stated) => format!(
            "{}/{} (file claims {stated})",
            quorum.have, quorum.threshold
        ),
    }
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
        "{:<6}{} {:<4}{}  safe {}  chain {}  nonce {}  you: {}",
        if rival { "RIVAL" } else { "" },
        collected(&one.quorum),
        if one.quorum.met { "met" } else { "" },
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
/// bundle. Nothing here syncs: the background poller does that on its own timer, and its last
/// tick is the first line on the frame.
pub(crate) fn screen(console: &mut Console) -> Result<Step, MenuErr> {
    let now = now_secs()?;
    let enrolled = console.rt.config.bundle_peers.len();
    let mut header = Vec::new();
    {
        let poll = console.rt.bundles.status();
        let mut reached = 0usize;
        for peer in &poll.peers {
            if peer.pull.is_ok() && peer.last_ok_at.is_some() {
                reached += 1;
            }
        }
        header.push(format!(
            "{} bundle(s), {} with the threshold met; peers {reached}/{enrolled} reached; \
             polled {}; {} signature(s) in, {} file(s) quarantined",
            poll.bundles,
            poll.ready,
            match poll.last_finished_at {
                Some(at) => format!("{}s ago", now.saturating_sub(at)),
                None => "not yet".to_string(),
            },
            poll.arrived,
            poll.quarantined,
        ));
        if let Some(failure) = &poll.failure {
            header.push(format!("the last bundle poll failed: {failure}"));
        }
    }
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
    let chosen = ask!(pick(&console.rt.live, &prompt, options, Filter::On));
    match chosen {
        Landing::Back => Ok(Step {
            choice: MenuChoice::Back,
            notice: String::new(),
        }),
        Landing::Peers => Ok(Step {
            choice: MenuChoice::BundlePeers,
            notice: String::new(),
        }),
        Landing::New => new_bundle(console),
        Landing::Open { hash, .. } => open(console, hash),
    }
}

/// What one bundle can be asked to do. Esc here returns to the list, one level up.
fn open(console: &mut Console, hash: B256) -> Result<Step, MenuErr> {
    let title = format!("Bundle {hash}");
    let action = ask!(
        pick(
            &console.rt.live,
            &title,
            BundleAction::ALL.to_vec(),
            Filter::Off
        ),
        MenuChoice::Bundles
    );
    match action {
        BundleAction::Back => Ok(Step {
            choice: MenuChoice::Bundles,
            notice: String::new(),
        }),
        BundleAction::Sign => sign(console, hash),
        BundleAction::Status => Ok(Step {
            choice: MenuChoice::Bundles,
            notice: status_view(hash)?,
        }),
        BundleAction::Qr => qr(&console.rt.live, hash),
        BundleAction::Export => {
            console.rt.bundles.poke(Poke::AwaitTick)?;
            Ok(Step {
                choice: MenuChoice::Bundles,
                notice: serde_json::to_string_pretty(&hc_bundle::export(SyncMode::Off, hash)?)?,
            })
        }
        BundleAction::Import => import(console, hash),
        BundleAction::Remove => remove(hash),
    }
}

/// Ask the engine what this device has to sign, sign it through the console's existing path,
/// and hand the answer back. The keystore is picked from the store's own names, so no key name
/// is typed, and the address that comes back is remembered for the list's "you" column.
fn sign(console: &mut Console, hash: B256) -> Result<Step, MenuErr> {
    let key = ask!(
        pick(
            &console.rt.live,
            "Sign with",
            keystore_names(console)?,
            Filter::On
        ),
        MenuChoice::Bundles
    );
    let intent = hc_bundle::intent_to_sign(SyncMode::Off, hash, &key)?;
    let ctx = OpContext::local(key.clone(), Operation::Sign);
    let _stable_store = console.rt.git.mutation();
    let response = console
        .rt
        .api
        .sign_typed(&ctx, intent, &console.rt.approver)?;
    let signer = response.signer;
    let after = hc_bundle::collect(SyncMode::Off, hash, response)?;
    console.rt.bundles.poke(Poke::Push { hash })?;
    let quorum = hc_bundle::quorum(&after)?;
    let notice = format!(
        "signed as {signer} with \"{key}\": {} collected{}",
        collected(&quorum),
        if quorum.met { ", threshold met" } else { "" }
    );
    console.signers.insert(signer, key);
    Ok(Step {
        choice: MenuChoice::Bundles,
        notice,
    })
}

/// The merged view of one bundle, judged against `safes.toml` as it reads right now.
fn status_view(hash: B256) -> Result<String, MenuErr> {
    let s = hc_bundle::status(SyncMode::Off, hash)?;
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
            "collected {}{}  packed {} bytes",
            collected(&s.quorum),
            if s.quorum.met { "  met" } else { "" },
            s.bundle.packed().len()
        ),
    ];
    if let Some(stated) = s.quorum.stated {
        lines.push(format!(
            "THRESHOLD DISAGREES: safes.toml requires {}, this bundle's file states {stated}",
            s.quorum.threshold
        ));
    }
    let mut rows = Vec::new();
    for sig in &s.bundle.signatures {
        rows.push(format!("  signed  {}", sig.signer));
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
fn qr(live: &Live, hash: B256) -> Result<Step, MenuErr> {
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
            pick(live, &format!("part {}/{of}", i + 1), options, Filter::Off),
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
fn import(console: &Console, hash: B256) -> Result<Step, MenuErr> {
    let bytes = ask!(
        pick_json(&console.rt.live, "Signature or bundle JSON"),
        MenuChoice::Bundles
    );
    if let Ok(response) = hc_core::wire::strict_json_from_slice::<SignResponse>(&bytes) {
        let signer = response.signer;
        let after = hc_bundle::collect(SyncMode::Off, hash, response)?;
        console.rt.bundles.poke(Poke::Push { hash })?;
        return Ok(Step {
            choice: MenuChoice::Bundles,
            notice: format!(
                "took {signer}'s signature: {} collected",
                collected(&hc_bundle::quorum(&after)?)
            ),
        });
    }
    let incoming: SafeTxBundle = hc_core::wire::strict_json_from_slice(&bytes)?;
    let merged = hc_bundle::merge(SyncMode::Off, hash, incoming)?;
    console.rt.bundles.poke(Poke::Push { hash })?;
    let mut added = Vec::new();
    for signer in &merged.added {
        added.push(short(signer.as_slice()));
    }
    Ok(Step {
        choice: MenuChoice::Bundles,
        notice: format!(
            "merged {} new signature(s) [{}]: {} collected",
            merged.added.len(),
            added.join(", "),
            collected(&merged.quorum)
        ),
    })
}

fn new_bundle(console: &Console) -> Result<Step, MenuErr> {
    let bytes = ask!(
        pick_json(&console.rt.live, "Intent JSON for the new bundle"),
        MenuChoice::Bundles
    );
    let intent = match hc_core::wire::strict_json_from_slice(&bytes)? {
        Intent::SafeTx(intent) => intent,
        Intent::TypedData(_) => {
            return Err(MenuErr::NotBundleable {
                kind: hc_sign::grant::IntentKind::TypedData,
            })
        }
    };
    let hash = hc_bundle::new(SyncMode::Off, intent)?;
    console.rt.bundles.poke(Poke::Push { hash })?;
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
fn json_files_in(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut found = Vec::new();
        for entry in entries.take(MAX_JSON_ENUM_ENTRIES).flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|kind| kind.is_file())
                && path.extension().is_some_and(|e| e == "json")
            {
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

fn json_files() -> Vec<PathBuf> {
    let mut dirs = vec![home_dir()];
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }
    json_files_in(dirs)
}

/// A JSON body from a file the operator picks, or from a paste. Both are bytes; nothing here
/// decides what they mean.
fn pick_json(live: &Live, prompt: &str) -> Result<Nav<Vec<u8>>, MenuErr> {
    let mut options = Vec::new();
    for path in json_files() {
        options.push(Source::File(path));
    }
    options.push(Source::Paste);
    let chosen = match pick(live, prompt, options, Filter::On)? {
        Nav::Chose(v) => v,
        Nav::Back => return Ok(Nav::Back),
        Nav::Quit => return Ok(Nav::Quit),
    };
    match chosen {
        Source::File(path) => Ok(Nav::Chose(hc_core::read_regular_file_bounded(
            &path,
            hc_bundle::ingest::MAX_FILE_BYTES,
        )?)),
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
pub(crate) fn peers_screen(console: &Console) -> Result<Step, MenuErr> {
    let mut out = std::io::stderr();
    for line in peer_view() {
        writeln!(out, "{line}")?;
    }
    writeln!(out)?;
    out.flush()?;

    let action = ask!(pick(
        &console.rt.live,
        "Peers",
        PeerAction::ALL.to_vec(),
        Filter::Off
    ));
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
            let chosen = ask!(
                pick(&console.rt.live, "Enroll", options, Filter::On),
                MenuChoice::BundlePeers
            );
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
                pick(&console.rt.live, "Stop syncing with", options, Filter::On),
                MenuChoice::BundlePeers
            );
            format!("dropped {}", sync::peer_rm(&chosen)?.host)
        }
        PeerAction::Sync => {
            console.rt.bundles.poke(Poke::AwaitTick)?;
            let poll = console.rt.bundles.status();
            let mut lines = Vec::new();
            for row in &poll.peers {
                lines.push(format!(
                    "  {:<34}{}{}",
                    row.host,
                    match &row.pull {
                        Ok(()) => format!("pulled {} signature(s)", row.arrivals),
                        Err(e) => format!("pull failed: {e}"),
                    },
                    match &row.push {
                        Ok(()) => String::new(),
                        Err(e) => format!("; push failed: {e}"),
                    }
                ));
            }
            match lines.is_empty() {
                true => "no bundle peers enrolled".to_string(),
                false => lines.join("\n"),
            }
        }
    };
    Ok(Step {
        choice: MenuChoice::BundlePeers,
        notice,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_picker_is_bounded_and_excludes_symlinks() {
        let dir = std::env::temp_dir().join(format!(
            "hot-cheese-json-picker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("make picker directory");
        for i in 0..(MAX_FILES + 8) {
            std::fs::write(dir.join(format!("{i:03}.json")), b"{}").expect("write fixture");
        }
        std::os::unix::fs::symlink(dir.join("000.json"), dir.join("linked.json"))
            .expect("make symlink fixture");

        let found = json_files_in(vec![dir.clone()]);
        assert_eq!(found.len(), MAX_FILES);
        assert!(!found.iter().any(|path| path.ends_with("linked.json")));

        std::fs::remove_dir_all(dir).expect("remove picker directory");
    }
}
