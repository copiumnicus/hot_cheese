//! Moving bundles between the operator's own machines, automatically.
//!
//! One file per signer is what makes this safe. Each device only ever writes `0x<its
//! signer>.json`, so `rsync` WITHOUT `--delete` is already a correct union merge: pulling and
//! pushing in both directions converges, there is no lock, no last-writer-wins and no conflict
//! to resolve. That is exactly why the store may NOT travel this way — a keystore is per-vault
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
use crate::ingest::{Ingest, Verdict, MAX_FILE_BYTES};
use crate::tailnet::{self, Node, TailnetErr};
use crate::Scope;
use err_mac::create_err_with_impls;
use hashbrown::HashSet;
use hc_core::config::{bundles_dir, BundlePeer, Config};
use std::path::Path;
use std::process::Command;

/// The one file in the tree that never crosses the wire. `safes.toml` states what a Safe IS —
/// its threshold and its owners — and a peer that could rewrite it could lower a threshold or
/// plant an owner, which is the only way bytes on this channel could ever matter.
const NEVER_SYNCED: &str = "safes.toml";

/// A half-finished `atomic_write`, which is nobody's business but the writer's.
const TEMP_FILES: &str = "*.hctmp";

/// Seconds ssh waits for a peer before a sync gives up on it. Sync is woven into signing, so
/// an asleep laptop has to fail fast rather than hold the terminal.
const CONNECT_TIMEOUT_SECS: u64 = 5;

create_err_with_impls!(
    #[derive(Debug)]
    pub SyncErr,
    RsyncSignal,
    StdIo(std::io::Error),
    Config(hc_core::config::ConfigErr),
    Tailnet(TailnetErr)
    ;
    RsyncFailed { code: i32 },
    PeerUnreachable { host: String },
    PeerHasNoBundlesDir { host: String, dir: String },
    PeerNotOnTailnet { name: String, known: Vec<String> },
    PeerAmbiguous { name: String, matches: Vec<String> },
    PeerHasNoMagicDnsName { name: String },
    PeerOffline { name: String },
    PeerAlreadyEnrolled { host: String },
    PeerNotEnrolled { name: String, enrolled: Vec<String> }
);

/// Whether an operation syncs with the enrolled peers at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Pull before reading, push after writing.
    On,
    /// Touch no peer, which is what `--no-sync` asks for.
    Off,
}

/// One peer's outcome in a sync run.
#[derive(Debug)]
pub struct PeerOutcome {
    /// The peer's ssh target.
    pub host: String,
    /// Whether rsync reached it.
    pub result: Result<(), SyncErr>,
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

/// `-e` transport. `BatchMode=yes` is the load-bearing one: sync runs inside `bundle sign`, and
/// an ssh that stopped to ask for a password would hold the terminal open behind a biometric.
fn ssh_transport() -> String {
    format!("ssh -o BatchMode=yes -o ConnectTimeout={CONNECT_TIMEOUT_SECS}")
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
/// our signatures away again.
fn flags() -> Vec<String> {
    vec![
        "-az".to_string(),
        format!("--exclude={NEVER_SYNCED}"),
        format!("--exclude={TEMP_FILES}"),
        "-e".to_string(),
        ssh_transport(),
    ]
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
fn rsync_pull_args(local: &Path, peer: &BundlePeer, scope: Scope) -> Vec<String> {
    let mut args = flags();
    args.push(format!("--max-size={MAX_FILE_BYTES}"));
    args.push(remote_side(peer, scope));
    args.push(local_side(local, Scope::All));
    args
}

/// Run rsync with the given argv. Neither stream is inherited: a console owns the terminal and
/// library code may not draw into it, so rsync's diagnosis reaches the operator through the
/// log instead.
fn run_rsync(args: &[String]) -> Result<(), SyncErr> {
    let out = Command::new("rsync").args(args).output()?;
    if out.status.success() {
        return Ok(());
    }
    tracing::warn!(stderr = %String::from_utf8_lossy(&out.stderr).trim(), "rsync failed");
    match out.status.code() {
        Some(code) => Err(SyncErr::RsyncFailed { code }),
        None => Err(SyncErr::RsyncSignal),
    }
}

/// Ask a peer whether its bundles dir exists. ssh reports the remote command's own status, and
/// reserves 255 for its own failures, so "I could not reach you" and "you have no bundles dir"
/// are different answers with different fixes.
fn probe(peer: &BundlePeer) -> Result<(), SyncErr> {
    let out = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg(format!("ConnectTimeout={CONNECT_TIMEOUT_SECS}"))
        .arg(&peer.host)
        .arg("test")
        .arg("-d")
        .arg(remote_root(peer))
        .output()?;
    if out.status.success() {
        return Ok(());
    }
    tracing::warn!(host = %peer.host, stderr = %String::from_utf8_lossy(&out.stderr).trim(), "ssh probe failed");
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

/// Run one direction against every enrolled peer, continuing past whichever ones fail.
fn each_peer(pull: bool, scope: Scope) -> Report {
    let local = bundles_dir();
    let mut report = Report::default();
    for peer in enrolled() {
        let args = match pull {
            true => rsync_pull_args(&local, &peer, scope),
            false => rsync_push_args(&local, &peer, scope),
        };
        let result = run_rsync(&args);
        if let Err(e) = &result {
            tracing::warn!(host = %peer.host, error = %e, pull, "bundle sync with peer failed; continuing");
        }
        report.peers.push(PeerOutcome {
            host: peer.host,
            result,
        });
    }
    report
}

/// Pull `scope` from every enrolled peer, then judge everything that landed. Best-effort in
/// both halves: an unreachable peer is a warning, and so is a validator that could not run.
///
/// The [`Ingest`] is thrown away, so this is always a full pass — the right thing for a one-shot
/// CLI process, which has no earlier pass to be incremental against. A long-lived caller keeps
/// its own and gets the incremental one.
pub fn pull(scope: Scope) -> Report {
    let local = bundles_dir();
    if let Err(e) = std::fs::create_dir_all(&local) {
        tracing::warn!(dir = %local.display(), error = %e, "cannot create the bundles dir; skipping pull");
        return Report::default();
    }
    let mut report = each_peer(true, scope);
    if report.peers.is_empty() {
        return report;
    }
    match Ingest::new().and_then(|mut ingest| ingest.validate(scope, &HashSet::new())) {
        Ok(verdict) => report.verdict = verdict,
        Err(e) => tracing::warn!(error = %e, "could not validate what the pull wrote"),
    }
    report
}

/// Push `scope` to every enrolled peer.
pub fn push(scope: Scope) -> Report {
    each_peer(false, scope)
}

/// Pull `scope` from ONE peer, without judging what landed. The caller that drives peers one at a
/// time owns its own [`Ingest`] and judges after each, which is what makes a quarantined file
/// attributable to the machine that sent it.
pub fn pull_from(peer: &BundlePeer, scope: Scope) -> Result<(), SyncErr> {
    let local = bundles_dir();
    std::fs::create_dir_all(&local)?;
    run_rsync(&rsync_pull_args(&local, peer, scope))
}

/// Push `scope` to ONE peer.
pub fn push_to(peer: &BundlePeer, scope: Scope) -> Result<(), SyncErr> {
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
    probe(&peer)?;

    let mut config = Config::load()?;
    for held in &config.bundle_peers {
        if held.host == peer.host {
            return Err(SyncErr::PeerAlreadyEnrolled {
                host: peer.host.clone(),
            });
        }
    }
    config.bundle_peers.push(peer.clone());
    config.save()?;
    Ok(peer)
}

/// Stop syncing with a machine. Matches the stored ssh target, its host part, or its short
/// MagicDNS label, so the name that enrolled it also removes it.
pub fn peer_rm(name: &str) -> Result<BundlePeer, SyncErr> {
    let mut config = Config::load()?;
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
    let removed = config.bundle_peers.remove(i);
    config.save()?;
    Ok(removed)
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

    /// The whole-tree form: contents to contents in both directions, `safes.toml` and
    /// half-written temp files left behind, a size cap on what a peer may write to us, and no
    /// `--delete` anywhere — deletion is what would turn a union merge into a race.
    #[test]
    fn whole_tree_argv_moves_contents_and_never_deletes() {
        let local = Path::new("/home/me/.config/hot_cheese/bundles");
        let push = rsync_push_args(local, &peer(), Scope::All);
        let pull = rsync_pull_args(local, &peer(), Scope::All);

        assert_eq!(
            push,
            vec![
                "-az".to_string(),
                "--exclude=safes.toml".to_string(),
                "--exclude=*.hctmp".to_string(),
                "-e".to_string(),
                "ssh -o BatchMode=yes -o ConnectTimeout=5".to_string(),
                "/home/me/.config/hot_cheese/bundles/".to_string(),
                "macbook.tail1a2b.ts.net:~/.config/hot_cheese/bundles/".to_string(),
            ]
        );
        assert_eq!(
            pull,
            vec![
                "-az".to_string(),
                "--exclude=safes.toml".to_string(),
                "--exclude=*.hctmp".to_string(),
                "-e".to_string(),
                "ssh -o BatchMode=yes -o ConnectTimeout=5".to_string(),
                "--max-size=65536".to_string(),
                "macbook.tail1a2b.ts.net:~/.config/hot_cheese/bundles/".to_string(),
                "/home/me/.config/hot_cheese/bundles/".to_string(),
            ]
        );

        for args in [&push, &pull] {
            for arg in args.iter() {
                assert!(!arg.contains("--delete"), "no argv may carry --delete");
            }
        }
        assert!(
            !push.iter().any(|a| a.starts_with("--max-size")),
            "our own writes are not capped; a peer's are"
        );
    }

    /// The one-bundle form names the DIRECTORY, never its contents: a source without a
    /// trailing slash makes rsync create `<dest>/<hash>`, so a pull for a bundle the peer does
    /// not have creates nothing at all instead of an empty directory the union would refuse.
    /// The destination stays the tree root in both directions.
    #[test]
    fn one_bundle_argv_names_the_directory_not_its_contents() {
        let local = Path::new("/home/me/.config/hot_cheese/bundles");
        let hash = hash();
        let push = rsync_push_args(local, &peer(), Scope::One(hash));
        let pull = rsync_pull_args(local, &peer(), Scope::One(hash));

        assert_eq!(
            push[5],
            format!("/home/me/.config/hot_cheese/bundles/{hash}"),
            "source is the directory itself"
        );
        assert!(!push[5].ends_with('/'));
        assert_eq!(
            push[6],
            "macbook.tail1a2b.ts.net:~/.config/hot_cheese/bundles/"
        );

        assert_eq!(
            pull[6],
            format!("macbook.tail1a2b.ts.net:~/.config/hot_cheese/bundles/{hash}")
        );
        assert!(!pull[6].ends_with('/'));
        assert_eq!(pull[7], "/home/me/.config/hot_cheese/bundles/");
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
        assert_eq!(args[5], "/b/");
        assert_eq!(args[6], "ops@studio.tail1a2b.ts.net:/Volumes/keys/bundles/");

        let relative = BundlePeer {
            host: "studio".to_string(),
            dir: Some("elsewhere/bundles".to_string()),
        };
        let args = rsync_pull_args(Path::new("/b"), &relative, Scope::All);
        assert_eq!(args[6], "studio:~/elsewhere/bundles/");
        assert_eq!(args[7], "/b/");
    }
}
