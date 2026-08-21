//! Moving bundles between the operator's own machines, automatically.
//!
//! One file per signer is what makes this safe. Each device only ever writes `0x<its
//! signer>.json`, so `rsync` WITHOUT `--delete` is already a correct union merge: pulling and
//! pushing in both directions converges with no last-writer-wins conflict to resolve. Transfers
//! also use `--ignore-existing`: a peer may add a name, but can never replace a seed or signer
//! file already held locally. A local cross-process lock guards validation and multi-step
//! mutations, and is never held across a transfer: an untrusted peer may stall for the whole
//! rsync timeout, and a claim held through that is one a `collect` behind a biometric cannot
//! take. That is exactly why the store may NOT travel this way — a keystore is per-vault
//! and two machines hold deliberately different DEKs — and why `[[bundle_peers]]` is a
//! separate config key from `[[backup_remotes]]`, pointed at a separate directory, with no
//! vault namespace anywhere near it.
//!
//! Transport is outbound-only: `rsync` over `ssh`, started by this process, finished before it
//! returns. Nothing listens, no port opens, the daemon is not involved, and there is no
//! long-running child to supervise or strand. Tailscale supplies reachability and a stable
//! name; it grants no authority, because there is nothing to grant authority TO.
//!
//! Every reachable peer is therefore an untrusted writer, and every pull is followed by
//! [`crate::ingest::Ingest::validate`] before anything reads what arrived.
use crate::ingest::{
    Delivered, Ingest, Truth, Verdict, MAX_BUNDLE_DIRS, MAX_FILES_PER_BUNDLE, MAX_FILE_BYTES,
    MAX_INGEST_FILES,
};
use crate::tailnet::{self, Node, TailnetErr};
use crate::{Scope, BUNDLE_SUFFIX, SEED_FILE};
use alloy_primitives::{Address, B256};
use err_mac::create_err_with_impls;
use hc_core::config::{bundles_dir, validate_ssh_target, BundlePeer, Config};
use rand::RngCore;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Seconds ssh waits for a peer before a sync gives up on it. Sync is woven into signing, so
/// an asleep laptop has to fail fast rather than hold the terminal.
const CONNECT_TIMEOUT_SECS: u64 = 5;
const ALIVE_INTERVAL_SECS: u64 = 5;
const ALIVE_COUNT_MAX: u64 = 2;
const RSYNC_TIMEOUT: Duration = Duration::from_secs(60);
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Lines a peer's listing may state. The remote truncates its own output, so a machine holding
/// more files than one pull asks about is still listed instead of failing the byte ceiling below
/// — which is what used to stop every pull from a peer whose tree had simply grown.
const MAX_REMOTE_LIST_LINES: usize = 20_000;
const MAX_REMOTE_LIST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PROBE_OUTPUT_BYTES: u64 = 256 * 1024;
/// Bundle directories one pull asks a peer for. Files this machine already holds are dropped from
/// the listing before this is counted, so a large LOCAL tree spends none of it, and a peer holding
/// more than this has the rest left for the next pull rather than the pull refusing everything.
const MAX_REMOTE_DIRS_PER_PULL: usize = MAX_BUNDLE_DIRS;
/// A hostile peer controls rsync's compact wire input. Keep expansion in the local parser below
/// a fixed physical-memory ceiling until every received bundle has passed semantic validation.
const MAX_RSYNC_PROCESS_MEMORY_BYTES: u64 = 256 * 1024 * 1024;

create_err_with_impls!(
    #[derive(Debug)]
    pub SyncErr,
    RsyncSignal,
    ValidationUnavailable,
    StdIo(std::io::Error),
    Config(hc_core::config::ConfigErr),
    Tailnet(TailnetErr),
    Ingest(crate::ingest::IngestErr),
    Lock(crate::lock::LockErr)
    ;
    RsyncFailed { code: i32 },
    PeerUnreachable { host: String },
    PeerHasNoBundlesDir { host: String, dir: String },
    PeerNotOnTailnet { name: String, known: Vec<String> },
    PeerAmbiguous { name: String, matches: Vec<String> },
    PeerHasNoMagicDnsName { name: String },
    PeerOffline { name: String },
    PeerAlreadyEnrolled { host: String },
    PeerNotEnrolled { name: String, enrolled: Vec<String> },
    RemoteListNotUtf8 { host: String },
    UnsafeLocalEntry { path: PathBuf }
);

/// Whether an operation syncs with the enrolled peers at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Pull before reading, push after writing.
    On,
    /// Touch no peer, which is what `--no-sync` asks for.
    Off,
}

/// What a peer offered that one pull did not ask for, because this machine's own ceilings ran
/// out. Reported rather than fatal: a peer holding more than one pull takes must never be able to
/// stop this machine from taking ANY of it, and a truncated pull the operator cannot see is its
/// own hazard.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Truncated {
    /// Bundle directories past [`MAX_REMOTE_DIRS_PER_PULL`] the listing left out.
    pub dirs: usize,
    /// Files past a directory's or the pull's own ceiling the listing left out.
    pub files: usize,
}

/// One peer's outcome in a sync run.
#[derive(Debug)]
pub struct PeerOutcome {
    /// The peer's ssh target.
    pub host: String,
    /// Whether rsync reached it.
    pub result: Result<(), SyncErr>,
    /// What its listing offered that this pull left for the next one.
    pub truncated: Truncated,
}

/// What one sync run did. Never an `Err`: an unreachable laptop must not break signing on the
/// desktop, so a failure is a row in here and a warning in the log, not a refusal.
#[derive(Debug, Default)]
pub struct Report {
    /// One entry per enrolled peer, in `config.toml` order.
    pub peers: Vec<PeerOutcome>,
    /// What the validator did to what a pull wrote; empty for a push.
    pub verdict: Verdict,
}

impl Report {
    /// Peers rsync could not finish with.
    pub fn failed(&self) -> usize {
        let mut n = 0;
        for peer in &self.peers {
            if peer.result.is_err() {
                n += 1;
            }
        }
        n
    }
}

fn absorb_verdict(total: &mut Verdict, mut next: Verdict) {
    total.rejected.append(&mut next.rejected);
    for hash in next.crowded {
        if !total.crowded.contains(&hash) {
            total.crowded.push(hash);
        }
    }
    total.dirs = next.dirs;
    for hash in next.refused_dirs {
        if !total.refused_dirs.contains(&hash) {
            total.refused_dirs.push(hash);
        }
    }
    for hash in next.retired {
        if !total.retired.contains(&hash) {
            total.retired.push(hash);
        }
    }
    for hash in next.skipped {
        if !total.skipped.contains(&hash) {
            total.skipped.push(hash);
        }
    }
    total.refused_files = total.refused_files.saturating_add(next.refused_files);
    total.judged = total.judged.saturating_add(next.judged);
    total.capped |= next.capped;
    total.changed |= next.changed;
}

/// Both directions of an explicit `bundle sync`.
#[derive(Debug)]
pub struct Synced {
    /// What came in, and what the validator made of it.
    pub pulled: Report,
    /// What went out.
    pub pushed: Report,
}

/// A tailnet node and whether this machine already syncs with it.
#[derive(Debug)]
pub struct PeerView {
    /// What the tailnet says about it.
    pub node: Node,
    /// Whether `config.toml` lists it in `[[bundle_peers]]`.
    pub enrolled: bool,
}

/// What `bundle peer list` shows.
#[derive(Debug)]
pub struct Peers {
    /// Every node on the tailnet, sorted, each marked with whether it is enrolled.
    pub tailnet: Vec<PeerView>,
    /// Enrolled hosts no tailnet node matches — a machine renamed, removed, or logged out.
    pub orphans: Vec<String>,
}

/// One trailing slash, whatever the input had, so rsync copies a directory's CONTENTS and no
/// path ever contains `//`.
fn dir_slash(path: &str) -> String {
    format!("{}/", path.trim_end_matches('/'))
}

/// The peer's bundles dir as its own shell sees it: home-relative unless it is absolute.
fn remote_root(peer: &BundlePeer) -> String {
    let dir = peer.dir().trim_end_matches('/');
    if dir.starts_with('/') {
        return dir.to_string();
    }
    format!("~/{dir}")
}

/// Every option this crate's ssh runs under, in the one-argument `-oKey=value` spelling both an
/// argv and rsync's whitespace-split `-e` string carry unchanged.
///
/// `-F /dev/null` is the load-bearing one: without it a same-uid process that can write
/// `~/.ssh/config` redirects a peer transfer through its own `ProxyCommand`, and a peer's identity
/// here is nothing but a MagicDNS name. `StrictHostKeyChecking` and `UserKnownHostsFile` are then
/// stated rather than defaulted, so a host key that CHANGES is refused while a first contact is
/// still able to enroll. `BatchMode=yes` is the other: sync runs inside `bundle sign`, and an ssh
/// that stopped to ask for a password would hold the terminal open behind a biometric.
fn ssh_options() -> Vec<String> {
    vec![
        "-T".to_string(),
        "-F".to_string(),
        "/dev/null".to_string(),
        "-oBatchMode=yes".to_string(),
        "-oConnectionAttempts=1".to_string(),
        "-oPermitLocalCommand=no".to_string(),
        "-oForkAfterAuthentication=no".to_string(),
        "-oControlMaster=no".to_string(),
        "-oControlPath=none".to_string(),
        "-oStrictHostKeyChecking=accept-new".to_string(),
        "-oUserKnownHostsFile=~/.ssh/known_hosts".to_string(),
        format!("-oConnectTimeout={CONNECT_TIMEOUT_SECS}"),
        format!("-oServerAliveInterval={ALIVE_INTERVAL_SECS}"),
        format!("-oServerAliveCountMax={ALIVE_COUNT_MAX}"),
    ]
}

/// `-e` transport: the same pinned ssh, as one string, because that is how rsync takes it.
fn ssh_transport() -> String {
    format!("/usr/bin/ssh {}", ssh_options().join(" "))
}

/// A child that inherits no environment. `SSH_AUTH_SOCK` is the one variable a working setup
/// genuinely needs — an agent-held key is the normal macOS case — and `HOME` is where ssh finds
/// the identity and the known-hosts file it was just told to use.
fn pinned_child(program: &str) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    for name in ["HOME", "SSH_AUTH_SOCK"] {
        if let Ok(value) = std::env::var(name) {
            command.env(name, value);
        }
    }
    command
}

/// The local side of one scope: the tree's contents for [`Scope::All`], the directory ITSELF —
/// no trailing slash — for one bundle.
fn local_side(local: &Path, scope: Scope) -> String {
    match scope {
        Scope::All => dir_slash(&local.display().to_string()),
        Scope::One(hash) => local.join(hash.to_string()).display().to_string(),
    }
}

/// The remote side of one scope, with the same trailing-slash rule. Naming the directory
/// rather than its contents is what makes a one-bundle pull create NOTHING when the peer does
/// not have that bundle, instead of leaving an empty directory the union would choke on.
fn remote_side(peer: &BundlePeer, scope: Scope) -> String {
    let root = dir_slash(&remote_root(peer));
    match scope {
        Scope::All => format!("{}:{root}", peer.host),
        Scope::One(hash) => format!("{}:{root}{hash}", peer.host),
    }
}

/// Flags every transfer carries in both directions. No `--delete`, ever: deletion is what
/// would turn a union merge into a race, and a peer that pulled before we pushed would take
/// our signatures away again. No overwrites either: every canonical file is immutable after its
/// create, and validation cannot restore a valid local signature after rsync replaced it.
fn canonical_filters() -> Vec<String> {
    let digest = format!("0x{}", "[0-9a-f]".repeat(64));
    let signer = format!("0x{}{}", "[0-9a-f]".repeat(40), BUNDLE_SUFFIX);
    vec![
        format!("--include=/{digest}/"),
        format!("--include=/{digest}/{SEED_FILE}"),
        format!("--include=/{digest}/{signer}"),
        "--exclude=*".to_string(),
    ]
}

fn flags() -> Vec<String> {
    let mut flags = vec![
        "-rz".to_string(),
        "--no-links".to_string(),
        "--no-devices".to_string(),
        "--no-specials".to_string(),
        "--ignore-existing".to_string(),
        "--no-owner".to_string(),
        "--no-group".to_string(),
        "--no-perms".to_string(),
        "--chmod=Du=rwx,Dgo=,Fu=rw,Fgo=".to_string(),
        "--prune-empty-dirs".to_string(),
        "-e".to_string(),
        ssh_transport(),
    ];
    flags.extend(canonical_filters());
    flags
}

/// `rsync -az … <local> <peer>:<root>/`.
fn rsync_push_args(local: &Path, peer: &BundlePeer, scope: Scope) -> Vec<String> {
    let mut args = flags();
    args.push(local_side(local, scope));
    args.push(remote_side(peer, Scope::All));
    args
}

/// `rsync -az … --max-size=… <peer>:<root>[/<hash>] <local>/`. The size cap is on the pull
/// only: a peer's bytes are capped before they are written, our own never need to be.
fn rsync_pull_args(local: &Path, peer: &BundlePeer, files_from: &Path) -> Vec<String> {
    let mut args = flags();
    args.push(format!("--max-size={MAX_FILE_BYTES}"));
    args.push(format!("--files-from={}", files_from.display()));
    args.push(remote_side(peer, Scope::All));
    args.push(local_side(local, Scope::All));
    args
}

/// A private, create-only `--files-from` input removed after the one transfer that uses it.
/// The names are public bundle coordinates, but create-only mode also prevents a local symlink
/// from turning this short-lived write into an overwrite elsewhere.
struct RemoteFileList {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl RemoteFileList {
    fn create(paths: &[String]) -> Result<Self, SyncErr> {
        let mut bytes = paths.join("\n").into_bytes();
        if !bytes.is_empty() {
            bytes.push(b'\n');
        }
        for _ in 0..8 {
            let mut random = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut random);
            let path = std::env::temp_dir().join(format!(
                ".hot-cheese-rsync-files-{}-{:032x}",
                std::process::id(),
                u128::from_be_bytes(random)
            ));
            match hc_core::crypto::envelope::write_private_file_new(&path, &bytes) {
                Ok(()) => {
                    let metadata = std::fs::symlink_metadata(&path)?;
                    return Ok(Self {
                        path,
                        dev: metadata.dev(),
                        ino: metadata.ino(),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not reserve a temporary rsync file list",
        )
        .into())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RemoteFileList {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_file()
                && metadata.dev() == self.dev
                && metadata.ino() == self.ino
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn canonical_remote_file(line: &str) -> Option<(B256, String)> {
    let path = line.strip_prefix("./")?;
    let mut components = path.split('/');
    let dir = components.next()?;
    let name = components.next()?;
    if components.next().is_some() {
        return None;
    }
    let hash = dir.parse::<B256>().ok()?;
    if dir != hash.to_string() {
        return None;
    }
    let canonical_name = name == SEED_FILE
        || name
            .strip_suffix(BUNDLE_SUFFIX)
            .and_then(|stem| stem.parse::<Address>().ok())
            .is_some_and(|address| name == format!("{address:#x}{BUNDLE_SUFFIX}"));
    canonical_name.then(|| (hash, path.to_string()))
}

/// Ask for names first, bound and canonicalise them locally, then let rsync fetch only that exact
/// list. A hostile peer therefore cannot make rsync materialise an unbounded tree before the
/// validator gets a turn, and a rename-to-symlink race is still stopped by `--no-links`.
fn remote_files(peer: &BundlePeer, scope: Scope) -> Result<Listing, SyncErr> {
    let mut command = pinned_child("/usr/bin/ssh");
    command
        .args(ssh_options())
        .arg(&peer.host)
        .arg("cd")
        .arg(remote_root(peer))
        .arg("&&")
        .arg("find")
        .arg(".")
        .arg("-type")
        .arg("f")
        .arg("-print")
        .arg("|")
        .arg("head")
        .arg("-n")
        .arg(MAX_REMOTE_LIST_LINES.to_string());
    let out = hc_core::output_bounded_timeout(
        &mut command,
        MAX_REMOTE_LIST_BYTES,
        MAX_PROBE_OUTPUT_BYTES,
        PROBE_TIMEOUT,
    )?;
    if !out.status.success() {
        tracing::warn!(host = %peer.host, stderr = %hc_core::safe_diagnostic(&out.stderr), "remote bundle listing failed");
        return match out.status.code() {
            Some(255) | None => Err(SyncErr::PeerUnreachable {
                host: peer.host.clone(),
            }),
            Some(_) => Err(SyncErr::PeerHasNoBundlesDir {
                host: peer.host.clone(),
                dir: peer.dir().to_string(),
            }),
        };
    }
    let text = std::str::from_utf8(&out.stdout).map_err(|_| SyncErr::RemoteListNotUtf8 {
        host: peer.host.clone(),
    })?;
    Ok(listing(&bundles_dir(), text, scope))
}

/// The exact paths one pull asks for, and what its ceilings left behind.
struct Listing {
    paths: Vec<String>,
    truncated: Truncated,
}

/// Bound what a peer's listing turns into WITHOUT discarding it. A name this machine already holds
/// as a regular file is dropped first: every canonical file is immutable after its create and the
/// transfer carries `--ignore-existing`, so asking for it again is work that changes nothing —
/// which is exactly why a tree that has simply grown locally can never spend a ceiling here.
fn listing(local: &Path, text: &str, scope: Scope) -> Listing {
    let mut by_dir: BTreeMap<B256, BTreeSet<String>> = BTreeMap::new();
    let mut overflow: BTreeSet<B256> = BTreeSet::new();
    let mut truncated = Truncated::default();
    let mut total = 0usize;
    for line in text.lines() {
        let Some((hash, path)) = canonical_remote_file(line) else {
            continue;
        };
        if matches!(scope, Scope::One(wanted) if wanted != hash) {
            continue;
        }
        if std::fs::symlink_metadata(local.join(&path))
            .is_ok_and(|metadata| metadata.file_type().is_file())
        {
            continue;
        }
        if !by_dir.contains_key(&hash) && by_dir.len() >= MAX_REMOTE_DIRS_PER_PULL {
            overflow.insert(hash);
            continue;
        }
        if total >= MAX_INGEST_FILES {
            truncated.files += 1;
            continue;
        }
        let files = by_dir.entry(hash).or_default();
        if files.contains(&path) {
            continue;
        }
        if files.len() >= MAX_FILES_PER_BUNDLE {
            truncated.files += 1;
            continue;
        }
        files.insert(path);
        total += 1;
    }
    truncated.dirs = overflow.len();
    Listing {
        paths: by_dir.into_values().flatten().collect(),
        truncated,
    }
}

/// Refuse receiver-side path aliases before rsync sees them. `--no-links` controls links sent by
/// the source; it does not make a pre-existing destination entry part of our create-only
/// protocol. In particular, rsync replaces a digest-directory symlink with a real directory even
/// under `--ignore-existing`. Only absent paths and real, owner-controlled bundle directories may
/// therefore participate in a pull.
fn local_pull_targets_are_safe(local: &Path, paths: &[String]) -> Result<(), SyncErr> {
    let mut checked_dirs = BTreeSet::new();
    for relative in paths {
        let Some((dir, file)) = relative.split_once('/') else {
            return Err(SyncErr::UnsafeLocalEntry {
                path: local.join(relative),
            });
        };
        let directory = local.join(dir);
        if checked_dirs.insert(directory.clone()) {
            match std::fs::symlink_metadata(&directory) {
                Ok(metadata) if metadata.file_type().is_dir() => {
                    crate::owned_directory_exists(&directory)?;
                }
                Ok(_) => return Err(SyncErr::UnsafeLocalEntry { path: directory }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }

        let destination = directory.join(file);
        match std::fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => return Err(SyncErr::UnsafeLocalEntry { path: destination }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn pull_one(local: &Path, peer: &BundlePeer, scope: Scope) -> Result<Truncated, SyncErr> {
    let listing = remote_files(peer, scope)?;
    if listing.truncated.dirs > 0 || listing.truncated.files > 0 {
        tracing::warn!(
            host = %peer.host,
            dirs = listing.truncated.dirs,
            files = listing.truncated.files,
            "a peer offers more than one pull asks for; the rest is left for the next pull"
        );
    }
    if listing.paths.is_empty() {
        return Ok(listing.truncated);
    }
    local_pull_targets_are_safe(local, &listing.paths)?;
    let files = RemoteFileList::create(&listing.paths)?;
    run_rsync(&rsync_pull_args(local, peer, files.path()))?;
    Ok(listing.truncated)
}

/// Run rsync with the given argv. Neither stream is inherited: a console owns the terminal and
/// library code may not draw into it, so rsync's diagnosis reaches the operator through the
/// log instead.
fn run_rsync(args: &[String]) -> Result<(), SyncErr> {
    const MAX_RSYNC_OUTPUT_BYTES: u64 = 1024 * 1024;
    let mut command = pinned_child("/usr/bin/rsync");
    command.args(args);
    // `--max-size` is negotiated with the remote rsync. `RLIMIT_FSIZE` is the independent local
    // backstop when that remote is malicious and lies about the size it is about to send.
    hc_core::limit_child_file_size(&mut command, MAX_FILE_BYTES)?;
    let out = hc_core::output_bounded_timeout_memory(
        &mut command,
        MAX_RSYNC_OUTPUT_BYTES,
        MAX_RSYNC_OUTPUT_BYTES,
        RSYNC_TIMEOUT,
        MAX_RSYNC_PROCESS_MEMORY_BYTES,
    )?;
    if out.status.success() {
        return Ok(());
    }
    tracing::warn!(stderr = %hc_core::safe_diagnostic(&out.stderr), "rsync failed");
    match out.status.code() {
        Some(code) => Err(SyncErr::RsyncFailed { code }),
        None => Err(SyncErr::RsyncSignal),
    }
}

/// Ask a peer whether its bundles dir exists. ssh reports the remote command's own status, and
/// reserves 255 for its own failures, so "I could not reach you" and "you have no bundles dir"
/// are different answers with different fixes.
fn probe(peer: &BundlePeer) -> Result<(), SyncErr> {
    let mut command = pinned_child("/usr/bin/ssh");
    command
        .args(ssh_options())
        .arg(&peer.host)
        .arg("test")
        .arg("-d")
        .arg(remote_root(peer));
    let out = hc_core::output_bounded_timeout(
        &mut command,
        MAX_PROBE_OUTPUT_BYTES,
        MAX_PROBE_OUTPUT_BYTES,
        PROBE_TIMEOUT,
    )?;
    if out.status.success() {
        return Ok(());
    }
    tracing::warn!(host = %peer.host, stderr = %hc_core::safe_diagnostic(&out.stderr), "ssh probe failed");
    match out.status.code() {
        Some(255) | None => Err(SyncErr::PeerUnreachable {
            host: peer.host.clone(),
        }),
        Some(_) => Err(SyncErr::PeerHasNoBundlesDir {
            host: peer.host.clone(),
            dir: peer.dir().to_string(),
        }),
    }
}

/// The enrolled peers, read fresh from `config.toml` on every run so a `peer add` in another
/// window — or in a console session that is still holding an older `Config` — takes effect at
/// the next sync rather than at the next restart.
fn enrolled() -> Vec<BundlePeer> {
    match Config::load() {
        Ok(config) => config.bundle_peers,
        Err(e) => {
            tracing::warn!(error = %e, "cannot read config.toml; bundle sync is off for this run");
            Vec::new()
        }
    }
}

/// Every peer marked unreachable by one local failure that has nothing to do with any of them.
/// The typed cause is logged here, because a `Report` is routinely dropped by a caller that only
/// wanted the signature written, and a transfer nobody attempted must not look like one that
/// succeeded.
fn unavailable(peers: Vec<BundlePeer>, error: impl std::fmt::Display) -> Report {
    tracing::warn!(%error, peers = peers.len(), "bundle sync is unavailable; no peer was reached");
    let mut report = Report::default();
    for peer in peers {
        report.peers.push(PeerOutcome {
            host: peer.host,
            result: Err(SyncErr::ValidationUnavailable),
            truncated: Truncated::default(),
        });
    }
    report
}

/// Push to every enrolled peer, continuing past whichever ones fail. No lock: a push only READS
/// this tree, every canonical file is immutable after its create, and holding a claim across a
/// minute of a stalling peer's network is what makes a local `collect` fail after a biometric.
fn each_peer(scope: Scope) -> Report {
    let local = bundles_dir();
    let mut report = Report::default();
    let peers = enrolled();
    if let Err(error) = crate::ensure_owned_directory(&local) {
        return unavailable(peers, error);
    }
    let total = peers.len();
    for peer in peers {
        let result = run_rsync(&rsync_push_args(&local, &peer, scope));
        if let Err(e) = &result {
            tracing::warn!(host = %peer.host, error = %e, "bundle push to peer failed; continuing");
        }
        report.peers.push(PeerOutcome {
            host: peer.host,
            result,
            truncated: Truncated::default(),
        });
    }
    let failed = report.failed();
    if failed > 0 {
        tracing::warn!(
            failed,
            total,
            "a bundle push did not reach every enrolled peer"
        );
    }
    report
}

/// One judging pass, holding the local claim for exactly as long as it takes. The claim is what
/// serialises validation against another process's write; it is emphatically NOT what makes a
/// transfer safe, since every canonical file is create-only in both directions.
fn locked_validate(
    ingest: &mut Ingest,
    scope: Scope,
    from: Delivered<'_>,
) -> Result<Verdict, SyncErr> {
    let _lock = crate::lock::Lock::take()?;
    let truth = match Truth::load() {
        Ok(truth) => truth,
        Err(error) => {
            tracing::warn!(%error, "cannot read this machine's own bundle facts; judging nothing");
            return Err(SyncErr::ValidationUnavailable);
        }
    };
    Ok(ingest.validate(scope, &truth, from)?)
}

/// Pull `scope` from every enrolled peer, then judge everything that landed. Best-effort in
/// both halves: an unreachable peer is a warning, and so is a validator that could not run.
///
/// The transfer itself runs OUTSIDE the local claim. A peer is untrusted and may stall for the
/// whole rsync timeout, and a claim held across that is a claim a `collect` cannot take — which
/// spends an operator's biometric on a signature the process then drops.
///
/// The [`Ingest`] is thrown away, so this is always a full pass — the right thing for a one-shot
/// CLI process, which has no earlier pass to be incremental against. A long-lived caller keeps
/// its own and gets the incremental one.
pub fn pull(scope: Scope) -> Report {
    let local = bundles_dir();
    let peers = enrolled();
    if let Err(e) = crate::ensure_owned_directory(&local) {
        tracing::warn!(dir = %local.display(), error = %e, "cannot create the bundles dir; skipping pull");
        return Report::default();
    }
    let mut report = Report::default();
    let mut ingest = match Ingest::new() {
        Ok(ingest) => ingest,
        Err(error) => return unavailable(peers, error),
    };
    match locked_validate(&mut ingest, Scope::All, Delivered::Locally) {
        Ok(verdict) => report.verdict = verdict,
        Err(error) => return unavailable(peers, error),
    }
    for peer in peers {
        let mut truncated = Truncated::default();
        let result = match pull_one(&local, &peer, scope) {
            Ok(left) => {
                truncated = left;
                Ok(())
            }
            Err(error) => {
                tracing::warn!(host = %peer.host, %error, "bundle pull from peer failed; validating any partial transfer");
                Err(error)
            }
        };
        match locked_validate(&mut ingest, scope, Delivered::By(&peer.host)) {
            Ok(verdict) => absorb_verdict(&mut report.verdict, verdict),
            Err(error) => {
                tracing::warn!(host = %peer.host, %error, "could not validate what the pull wrote")
            }
        }
        report.peers.push(PeerOutcome {
            host: peer.host,
            result,
            truncated,
        });
    }
    report
}

/// Push `scope` to every enrolled peer.
pub fn push(scope: Scope) -> Report {
    each_peer(scope)
}

/// Pull `scope` from ONE peer, without judging what landed. The caller that drives peers one at a
/// time owns its own [`Ingest`] and judges after each, which is what makes a quarantined file
/// attributable to the machine that sent it — and what makes
/// [`crate::ingest::MAX_DIRS_PER_PEER`] that peer's share.
pub(crate) fn pull_from(peer: &BundlePeer, scope: Scope) -> Result<Truncated, SyncErr> {
    let local = bundles_dir();
    crate::ensure_owned_directory(&local)?;
    pull_one(&local, peer, scope)
}

/// Push `scope` to ONE peer. Reads only, so it takes no local claim.
pub fn push_to(peer: &BundlePeer, scope: Scope) -> Result<(), SyncErr> {
    crate::ensure_owned_directory(&bundles_dir())?;
    run_rsync(&rsync_push_args(&bundles_dir(), peer, scope))
}

/// Both directions, for the explicit `bundle sync`. Pull first so what we send already
/// includes what they had.
pub fn sync_now(scope: Scope) -> Synced {
    Synced {
        pulled: pull(scope),
        pushed: push(scope),
    }
}

impl SyncMode {
    pub fn pull(self, scope: Scope) -> Report {
        match self {
            SyncMode::On => pull(scope),
            SyncMode::Off => Report::default(),
        }
    }
    pub fn push(self, scope: Scope) -> Report {
        match self {
            SyncMode::On => push(scope),
            SyncMode::Off => Report::default(),
        }
    }
}

/// The tailnet, marked up with what `config.toml` already syncs with.
pub fn peer_list() -> Result<Peers, SyncErr> {
    let enrolled = enrolled();
    let nodes = tailnet::peers()?;
    let mut tailnet = Vec::new();
    for node in nodes {
        let mut is_enrolled = false;
        for peer in &enrolled {
            if node.is(peer.name()) {
                is_enrolled = true;
            }
        }
        tailnet.push(PeerView {
            node,
            enrolled: is_enrolled,
        });
    }
    let mut orphans = Vec::new();
    for peer in &enrolled {
        let mut found = false;
        for view in &tailnet {
            if view.node.is(peer.name()) {
                found = true;
            }
        }
        if !found {
            orphans.push(peer.host.clone());
        }
    }
    Ok(Peers { tailnet, orphans })
}

/// Enroll a tailnet machine in `config.toml`, once, after proving it is really there.
///
/// `name` is whatever the operator calls it — hostname, short MagicDNS label, or the
/// fully-qualified name — optionally `user@`-prefixed when the account differs. What gets
/// stored is always the fully-qualified MagicDNS name, so nothing needs maintaining when the
/// tailnet re-addresses.
pub fn peer_add(name: &str) -> Result<BundlePeer, SyncErr> {
    // Refuse hostile/ambiguous user text before it is compared with external status names or
    // copied into an error. The stored FQDN is validated again after discovery.
    validate_ssh_target(name).map_err(hc_core::config::ConfigErr::from)?;
    let (user, wanted) = match name.split_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, name),
    };

    let nodes = tailnet::peers()?;
    let mut matched = Vec::new();
    for node in nodes.iter() {
        if node.is(wanted) {
            matched.push(node);
        }
    }
    let node = match matched.len() {
        1 => matched[0],
        0 => {
            let mut known = Vec::new();
            for node in &nodes {
                known.push(node.host_name.clone());
            }
            return Err(SyncErr::PeerNotOnTailnet {
                name: wanted.to_string(),
                known,
            });
        }
        _ => {
            let mut ambiguous = Vec::new();
            for node in matched {
                ambiguous.push(node.host_name.clone());
            }
            return Err(SyncErr::PeerAmbiguous {
                name: wanted.to_string(),
                matches: ambiguous,
            });
        }
    };
    let Some(dns) = node.dns_name.as_deref() else {
        return Err(SyncErr::PeerHasNoMagicDnsName {
            name: wanted.to_string(),
        });
    };
    if !node.online {
        return Err(SyncErr::PeerOffline {
            name: wanted.to_string(),
        });
    }

    let peer = BundlePeer {
        host: match user {
            Some(user) => format!("{user}@{dns}"),
            None => dns.to_string(),
        },
        dir: None,
    };
    validate_ssh_target(&peer.host).map_err(hc_core::config::ConfigErr::from)?;
    probe(&peer)?;

    Config::update(|config| {
        for held in &config.bundle_peers {
            if held.host == peer.host {
                return Err(SyncErr::PeerAlreadyEnrolled {
                    host: peer.host.clone(),
                });
            }
        }
        config.bundle_peers.push(peer.clone());
        Ok(peer)
    })
}

/// Stop syncing with a machine. Matches the stored ssh target, its host part, or its short
/// MagicDNS label, so the name that enrolled it also removes it.
pub fn peer_rm(name: &str) -> Result<BundlePeer, SyncErr> {
    Config::update(|config| {
        let mut found = None;
        for (i, peer) in config.bundle_peers.iter().enumerate() {
            let host = peer.name();
            let short = host.split('.').next().unwrap_or(host);
            if peer.host.eq_ignore_ascii_case(name)
                || host.eq_ignore_ascii_case(name)
                || short.eq_ignore_ascii_case(name)
            {
                found = Some(i);
                break;
            }
        }
        let Some(i) = found else {
            let mut hosts = Vec::new();
            for peer in &config.bundle_peers {
                hosts.push(peer.host.clone());
            }
            return Err(SyncErr::PeerNotEnrolled {
                name: name.to_string(),
                enrolled: hosts,
            });
        };
        Ok(config.bundle_peers.remove(i))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    fn peer() -> BundlePeer {
        BundlePeer {
            host: "macbook.tail1a2b.ts.net".to_string(),
            dir: None,
        }
    }

    fn hash() -> B256 {
        "0x44ae0d1d0b9bbbf2cbb0ff9dd7a0b0b8b6d5c4a3e2f1908172635445362718b5"
            .parse()
            .expect("fixed digest parses")
    }

    /// Both directions carry only canonical regular bundle files, normalise destination modes,
    /// refuse symlinks/devices, and never delete. Pulls add a byte cap and an exact local file
    /// list, so the remote does not choose how many names rsync materialises.
    #[test]
    fn whole_tree_argv_is_a_bounded_regular_file_union() {
        let local = Path::new("/home/me/.config/hot_cheese/bundles");
        let push = rsync_push_args(local, &peer(), Scope::All);
        let pull = rsync_pull_args(local, &peer(), Path::new("/tmp/exact-files"));

        for args in [&push, &pull] {
            assert!(args.contains(&"-rz".to_string()));
            assert!(args.contains(&"--no-links".to_string()));
            assert!(args.contains(&"--no-devices".to_string()));
            assert!(args.contains(&"--no-specials".to_string()));
            assert!(args.contains(&"--ignore-existing".to_string()));
            assert!(args.contains(&"--chmod=Du=rwx,Dgo=,Fu=rw,Fgo=".to_string()));
            assert!(args.contains(&"--exclude=*".to_string()));
            assert!(!args.iter().any(|arg| arg.contains("--delete")));
            assert!(!args.iter().any(|arg| arg == "-a" || arg == "-az"));
            assert!(!args.iter().any(|arg| arg.contains("safes.toml")));

            let at = args
                .iter()
                .position(|arg| arg == "-e")
                .expect("a transport");
            let transport = &args[at + 1];
            assert!(
                transport.contains("-F /dev/null"),
                "a user ssh config must not be able to inject a ProxyCommand"
            );
            assert!(transport.contains("-oStrictHostKeyChecking=accept-new"));
            assert!(transport.contains("-oUserKnownHostsFile="));
            assert!(transport.contains("-oBatchMode=yes"));
        }
        assert_eq!(
            &push[push.len() - 2..],
            [
                "/home/me/.config/hot_cheese/bundles/",
                "macbook.tail1a2b.ts.net:~/.config/hot_cheese/bundles/",
            ]
        );
        assert!(pull.contains(&"--max-size=65536".to_string()));
        assert!(pull.contains(&"--files-from=/tmp/exact-files".to_string()));
        assert_eq!(
            &pull[pull.len() - 2..],
            [
                "macbook.tail1a2b.ts.net:~/.config/hot_cheese/bundles/",
                "/home/me/.config/hot_cheese/bundles/",
            ]
        );
        assert!(
            !push.iter().any(|a| a.starts_with("--max-size")),
            "our own writes are not capped; a peer's are"
        );
    }

    /// A one-bundle push names the directory itself so the digest directory is recreated at the
    /// destination. Pull always names the root; its prevalidated `--files-from` list carries the
    /// requested scope instead, and an empty list runs no rsync at all.
    #[test]
    fn one_bundle_argv_names_the_directory_not_its_contents() {
        let local = Path::new("/home/me/.config/hot_cheese/bundles");
        let hash = hash();
        let push = rsync_push_args(local, &peer(), Scope::One(hash));
        let pull = rsync_pull_args(local, &peer(), Path::new("/tmp/one"));

        assert_eq!(
            push[push.len() - 2],
            format!("/home/me/.config/hot_cheese/bundles/{hash}"),
            "source is the directory itself"
        );
        assert!(!push[push.len() - 2].ends_with('/'));
        assert_eq!(
            push[push.len() - 1],
            "macbook.tail1a2b.ts.net:~/.config/hot_cheese/bundles/"
        );
        assert_eq!(
            pull[pull.len() - 2],
            "macbook.tail1a2b.ts.net:~/.config/hot_cheese/bundles/"
        );
        assert_eq!(pull[pull.len() - 1], "/home/me/.config/hot_cheese/bundles/");
    }

    /// A peer with more directories than one pull asks about used to abort the WHOLE listing, so
    /// that peer — hostile or simply busy — stopped every later transfer from itself for good. The
    /// ceiling must bound the WORK: the pull takes what it can, in digest order, and states what it
    /// left. Files this machine already holds are dropped before any ceiling is counted, so a tree
    /// that grew locally never spends the budget a genuinely new bundle needs.
    #[test]
    fn an_over_cap_listing_pulls_what_it_can_and_reports_the_rest() {
        let local = std::env::temp_dir().join(format!(
            "hot_cheese_listing_{}_{}",
            std::process::id(),
            hc_sign::grant::now_ms().unwrap_or_default()
        ));
        std::fs::create_dir_all(&local).expect("make a local bundle tree");

        let mut text = String::new();
        let mut offered = Vec::new();
        for at in 0..(MAX_REMOTE_DIRS_PER_PULL as u16 + 40) {
            let mut bytes = [0u8; 32];
            bytes[30..].copy_from_slice(&at.to_be_bytes());
            let hash = B256::from(bytes);
            offered.push(hash);
            text.push_str(&format!("./{hash}/{SEED_FILE}\n"));
        }
        let crowded = offered[0];
        for at in 0..(MAX_FILES_PER_BUNDLE + 19) {
            let mut bytes = [0u8; 20];
            bytes[18..].copy_from_slice(&(at as u16).to_be_bytes());
            let signer = Address::from(bytes);
            text.push_str(&format!("./{crowded}/{signer:#x}{BUNDLE_SUFFIX}\n"));
        }

        let listed = listing(&local, &text, Scope::All);
        assert_eq!(listed.truncated.dirs, 40);
        assert_eq!(listed.truncated.files, 20);
        assert!(!listed.paths.is_empty(), "an over-cap listing still pulls");
        let mut dirs = BTreeSet::new();
        for path in &listed.paths {
            dirs.insert(
                path.split('/')
                    .next()
                    .expect("a digest directory")
                    .to_string(),
            );
        }
        assert_eq!(dirs.len(), MAX_REMOTE_DIRS_PER_PULL);
        assert!(
            dirs.contains(&offered[MAX_REMOTE_DIRS_PER_PULL - 1].to_string()),
            "the digest-lowest directories are the ones taken"
        );

        for hash in &offered[..MAX_REMOTE_DIRS_PER_PULL] {
            let dir = local.join(hash.to_string());
            std::fs::create_dir_all(&dir).expect("hold this bundle locally");
            std::fs::write(dir.join(SEED_FILE), b"already ours").expect("hold its seed");
        }
        let settled = listing(&local, &text, Scope::All);
        assert_eq!(
            settled.truncated.dirs, 0,
            "a tree this machine already holds spends none of the pull's budget"
        );
        let mut fresh = BTreeSet::new();
        for path in &settled.paths {
            fresh.insert(
                path.split('/')
                    .next()
                    .expect("a digest directory")
                    .to_string(),
            );
        }
        for hash in &offered[MAX_REMOTE_DIRS_PER_PULL..] {
            assert!(
                fresh.contains(&hash.to_string()),
                "every directory the earlier pull left over is asked for now"
            );
        }

        std::fs::remove_dir_all(local).unwrap();
    }

    #[test]
    fn only_exact_canonical_remote_names_enter_a_file_list() {
        let hash = hash();
        let signer = "0x1111111111111111111111111111111111111111.json";
        assert_eq!(
            canonical_remote_file(&format!("./{hash}/{SEED_FILE}")),
            Some((hash, format!("{hash}/{SEED_FILE}")))
        );
        assert_eq!(
            canonical_remote_file(&format!("./{hash}/{signer}")),
            Some((hash, format!("{hash}/{signer}")))
        );
        for rejected in [
            format!("./{hash}/../safes.toml"),
            format!("./{hash}/junk.json"),
            format!("./{hash}/{signer}/nested"),
            format!("{hash}/{SEED_FILE}"),
            format!("./{}/{SEED_FILE}", hash.to_string().to_uppercase()),
        ] {
            assert_eq!(canonical_remote_file(&rejected), None, "{rejected}");
        }
    }

    #[test]
    fn a_receiver_side_symlink_cannot_be_replaced_by_a_peer_pull() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "hot_cheese_rsync_target_{}_{}",
            std::process::id(),
            hc_sign::grant::now_ms().unwrap_or_default()
        ));
        let local = root.join("bundles");
        let victim = root.join("victim");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::create_dir(&victim).unwrap();
        let digest = hash().to_string();
        symlink(&victim, local.join(&digest)).unwrap();

        let error = local_pull_targets_are_safe(&local, &[format!("{digest}/{SEED_FILE}")])
            .expect_err("a pull must stop before rsync can replace the symlink");
        assert!(matches!(error, SyncErr::UnsafeLocalEntry { .. }));
        assert!(std::fs::symlink_metadata(local.join(&digest))
            .unwrap()
            .file_type()
            .is_symlink());

        std::fs::remove_file(local.join(digest)).unwrap();
        std::fs::remove_dir(victim).unwrap();
        std::fs::remove_dir(local).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    /// A peer's dir is home-relative by default and absolute when it is spelled absolute, and
    /// a trailing slash the operator typed must not become `//`. The `user@` form belongs to
    /// the ssh target and must survive into the argv untouched.
    #[test]
    fn peer_dirs_are_home_relative_unless_they_are_not() {
        let absolute = BundlePeer {
            host: "ops@studio.tail1a2b.ts.net".to_string(),
            dir: Some("/Volumes/keys/bundles/".to_string()),
        };
        let args = rsync_push_args(Path::new("/b/"), &absolute, Scope::All);
        assert_eq!(args[args.len() - 2], "/b/");
        assert_eq!(
            args[args.len() - 1],
            "ops@studio.tail1a2b.ts.net:/Volumes/keys/bundles/"
        );

        let relative = BundlePeer {
            host: "studio".to_string(),
            dir: Some("elsewhere/bundles".to_string()),
        };
        let args = rsync_pull_args(Path::new("/b"), &relative, Path::new("/tmp/list"));
        assert_eq!(args[args.len() - 2], "studio:~/elsewhere/bundles/");
        assert_eq!(args[args.len() - 1], "/b/");
    }
}
