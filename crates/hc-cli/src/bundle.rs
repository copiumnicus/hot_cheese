//! `hot_cheese bundle`: argument parsing and rendering, and nothing else.
//!
//! The store, the union merge, the tailnet discovery and the rsync transport all live in
//! [`hc_bundle`], so the interactive console reaches exactly the same code through
//! exactly the same functions. What is left here is clap types, log lines, and the one place a
//! bundle needs a signature: this binary owns the unlock plumbing, so it asks the store what to
//! sign, signs it through [`crate::sign_intent_locally`], and hands the answer back.
use crate::{read_input, CliErr, UnlockMethod};
use alloy_primitives::B256;
use clap::{ArgGroup, Subcommand};
use hc_bundle::sync::{self, Report, SyncMode};
use hc_bundle::{Scope, Watch};
use hc_core::config::Config;
use hc_sign::intent::Intent;
use std::path::PathBuf;
use std::time::Duration;

/// Milliseconds in an hour, the unit a retirement decision is made in.
const HOUR_MS: u64 = 3_600_000;

/// Bundle verbs. Only `sign` prompts or unlocks; the rest read, merge, sync and print.
#[derive(Subcommand, Debug)]
pub enum BundleCmd {
    /// Start a bundle from a JSON intent; the threshold comes from `bundles/safes.toml`.
    New {
        /// Read the JSON intent from this file instead of stdin.
        #[arg(long, value_name = "JSON")]
        file: Option<PathBuf>,
    },
    /// Sign the bundle with a local key and file the signature under this device's signer.
    Sign {
        /// The bundle's `safeTxHash`.
        hash: B256,
        /// Local keystore to sign with; rebound in memory, outside the digest.
        #[arg(long, value_name = "NAME")]
        key: String,
    },
    /// Show the merged view: signatures, missing owners, rivals, packed length.
    Status {
        /// The bundle's `safeTxHash`.
        hash: B256,
    },
    /// List every bundle, grouped by the (Safe, chain, nonce) it competes for.
    List,
    /// Union an external bundle into the store.
    Merge {
        /// The bundle's `safeTxHash`.
        hash: B256,
        /// A bundle JSON file or a bundle directory; omit to read one from stdin.
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
    },
    /// Print the assembled `execTransaction` call and its packed signatures.
    Export {
        /// The bundle's `safeTxHash`.
        hash: B256,
    },
    /// Retire a bundle on this machine. Never synced: a pull would resurrect it.
    Rm {
        /// The bundle's `safeTxHash`.
        hash: B256,
    },
    /// Render the transaction as a QR for another device's camera.
    Qr {
        /// The bundle's `safeTxHash`.
        hash: B256,
    },
    /// Ingest another device's JSON sign response.
    #[command(group = ArgGroup::new("response").required(true).args(["file", "stdin"]))]
    AddSig {
        /// The bundle's `safeTxHash`.
        hash: B256,
        /// Read the JSON response from this file.
        #[arg(long, value_name = "JSON")]
        file: Option<PathBuf>,
        /// Read the JSON response from stdin.
        #[arg(long)]
        stdin: bool,
    },
    /// Exchange bundles with every enrolled peer, both directions, right now.
    Sync {
        /// Sync only this bundle; omit for the whole tree.
        hash: Option<B256>,
    },
    /// Poll the peers in the foreground and report signatures as they arrive. Ctrl-C ends it.
    Watch {
        /// Watch only this bundle, and stop once its threshold is met.
        hash: Option<B256>,
    },
    /// Discover, enroll and drop the tailnet machines this one syncs bundles with.
    #[command(subcommand)]
    Peer(PeerCmd),
}

#[derive(Subcommand, Debug)]
pub enum PeerCmd {
    /// Show every machine on the tailnet and which of them are enrolled.
    List,
    /// Enroll a tailnet machine after checking it is reachable and has a bundles dir.
    Add {
        /// Hostname, short MagicDNS label, or full MagicDNS name, optionally `user@`-prefixed.
        name: String,
    },
    /// Stop syncing with a machine.
    Rm {
        /// The name it was enrolled under.
        name: String,
    },
}

pub fn run(cmd: BundleCmd, no_sync: bool, unlock: Option<UnlockMethod>) -> Result<(), CliErr> {
    let mode = match no_sync {
        true => SyncMode::Off,
        false => SyncMode::On,
    };
    match cmd {
        BundleCmd::New { file } => {
            let Intent::SafeTx(intent) = serde_json::from_slice(&read_input(file.as_deref())?)?;
            hc_bundle::new(mode, intent)?;
            Ok(())
        }
        BundleCmd::Sign { hash, key } => {
            let intent = hc_bundle::intent_to_sign(mode, hash, &key)?;
            let response = crate::sign_intent_locally(&intent, unlock)?;
            hc_bundle::collect(mode, hash, response)?;
            Ok(())
        }
        BundleCmd::Status { hash } => status(mode, hash),
        BundleCmd::List => list(mode),
        BundleCmd::Merge { hash, file } => merge(mode, hash, file),
        BundleCmd::Export { hash } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&hc_bundle::export(mode, hash)?)?
            );
            Ok(())
        }
        BundleCmd::Rm { hash } => {
            hc_bundle::rm(hash)?;
            Ok(())
        }
        BundleCmd::Qr { hash } => qr(hash),
        BundleCmd::AddSig {
            hash,
            file,
            stdin: _,
        } => {
            let response = serde_json::from_slice(&read_input(file.as_deref())?)?;
            hc_bundle::collect(mode, hash, response)?;
            Ok(())
        }
        BundleCmd::Sync { hash } => {
            let synced = sync::sync_now(scope(hash));
            report("pulled", &synced.pulled);
            report("pushed", &synced.pushed);
            Ok(())
        }
        BundleCmd::Watch { hash } => watch(mode, hash),
        BundleCmd::Peer(cmd) => peer(cmd),
    }
}

fn scope(hash: Option<B256>) -> Scope {
    match hash {
        Some(hash) => Scope::One(hash),
        None => Scope::All,
    }
}

/// One sync run, peer by peer, plus whatever the untrusted-ingest validator had to move.
fn report(direction: &str, report: &Report) {
    tracing::info!(
        direction,
        peers = report.peers.len(),
        failed = report.failed(),
        quarantined = report.verdict.rejected.len(),
        "bundle sync"
    );
    for peer in &report.peers {
        match &peer.result {
            Ok(()) => tracing::info!(host = %peer.host, "  ok"),
            Err(e) => tracing::warn!(host = %peer.host, error = %e, "  FAILED"),
        }
    }
    for hash in &report.verdict.crowded {
        tracing::warn!(%hash, "  CROWDED: more files than the per-bundle cap; export will refuse a signer that is not an owner");
    }
    if report.verdict.capped {
        tracing::warn!(
            "  CAPPED: too many files to validate in one pass; the rest were not judged"
        );
    }
}

fn status(mode: SyncMode, hash: B256) -> Result<(), CliErr> {
    let s = hc_bundle::status(mode, hash)?;
    tracing::info!(
        %hash,
        have = s.bundle.signatures.len(),
        threshold = s.bundle.threshold,
        met = s.bundle.met(),
        packed_bytes = s.bundle.packed().len(),
        age_hours = s.age_ms / HOUR_MS,
        "bundle"
    );
    if s.safes_threshold != s.bundle.threshold {
        tracing::warn!(
            bundle = s.bundle.threshold,
            safes_toml = s.safes_threshold,
            "THRESHOLD CHANGED since this bundle was created"
        );
    }
    for sig in &s.bundle.signatures {
        tracing::info!(signer = %sig.signer, owner = !s.not_owners.contains(&sig.signer), "  signed");
    }
    for signer in &s.not_owners {
        tracing::warn!(%signer, "NOT AN OWNER in safes.toml — the assembled blob reverts");
    }
    for owner in &s.missing {
        tracing::info!(%owner, "  missing");
    }
    for rival in &s.rivals {
        tracing::warn!(%rival, "RIVAL: same Safe, chain and nonce, different transaction");
    }
    Ok(())
}

fn list(mode: SyncMode) -> Result<(), CliErr> {
    let grouped = hc_bundle::list(mode)?;
    let now = hc_sign::grant::now_ms()?;
    tracing::info!(dir = %hc_core::config::bundles_dir().display(), slots = grouped.len(), "bundles");
    for (slot, bundles) in &grouped {
        if bundles.len() > 1 {
            tracing::warn!(
                safe = %slot.safe,
                chain_id = %slot.chain_id,
                nonce = %slot.nonce,
                rivals = bundles.len(),
                "RIVAL: mutually exclusive transactions share one nonce"
            );
        } else {
            tracing::info!(safe = %slot.safe, chain_id = %slot.chain_id, nonce = %slot.nonce, "slot");
        }
        for one in bundles {
            tracing::info!(
                hash = %one.hash,
                have = one.bundle.signatures.len(),
                threshold = one.bundle.threshold,
                met = one.bundle.met(),
                age_hours = now.saturating_sub(one.bundle.created_at_ms) / HOUR_MS,
                "  bundle"
            );
        }
    }
    Ok(())
}

fn merge(mode: SyncMode, hash: B256, file: Option<PathBuf>) -> Result<(), CliErr> {
    let incoming = match file {
        Some(path) => hc_bundle::read_bundle(&path, hash)?,
        None => serde_json::from_slice(&read_input(None)?)?,
    };
    let merged = hc_bundle::merge(mode, hash, incoming)?;
    for signer in &merged.added {
        tracing::info!(%hash, %signer, "merged signature");
    }
    tracing::info!(
        %hash,
        have = merged.union.signatures.len(),
        threshold = merged.union.threshold,
        met = merged.union.met(),
        "merged"
    );
    Ok(())
}

fn qr(hash: B256) -> Result<(), CliErr> {
    let set = hc_bundle::qr_frames(hash)?;
    let of = set.len();
    for (i, frame) in set.iter().enumerate() {
        let rendered = hc_daemon::qr_term::render(frame)?;
        println!("part {}/{of}", i + 1);
        print!("{rendered}");
    }
    tracing::info!(%hash, parts = of, "scan every part; the set is verified against its own sha256");
    Ok(())
}

/// Poll in the FOREGROUND. Nothing is spawned, nothing is backgrounded, and Ctrl-C takes the
/// process and any rsync it is running down together, so no child is ever stranded.
fn watch(mode: SyncMode, hash: Option<B256>) -> Result<(), CliErr> {
    let scope = scope(hash);
    let interval = Duration::from_secs(Config::load()?.bundle_watch_secs());
    let mut watch = Watch::start(scope)?;
    tracing::info!(
        watching = watch.watching(),
        interval_secs = interval.as_secs(),
        "watching for signatures; Ctrl-C to stop"
    );
    loop {
        for arrival in watch.poll(mode)? {
            tracing::info!(
                hash = %arrival.hash,
                signer = %arrival.signer,
                have = arrival.have,
                threshold = arrival.threshold,
                met = arrival.met,
                "signature arrived"
            );
            if arrival.met && hash.is_some() {
                tracing::info!(hash = %arrival.hash, "threshold met");
                return Ok(());
            }
        }
        std::thread::sleep(interval);
    }
}

fn peer(cmd: PeerCmd) -> Result<(), CliErr> {
    match cmd {
        PeerCmd::List => {
            let peers = sync::peer_list()?;
            tracing::info!(count = peers.tailnet.len(), "tailnet");
            for view in &peers.tailnet {
                tracing::info!(
                    host = %view.node.host_name,
                    magic_dns = view.node.dns_name.as_deref().unwrap_or("(none)"),
                    online = view.node.online,
                    enrolled = view.enrolled,
                    "  peer"
                );
            }
            for host in &peers.orphans {
                tracing::warn!(%host, "ENROLLED but no tailnet machine answers to that name");
            }
        }
        PeerCmd::Add { name } => {
            let peer = sync::peer_add(&name)?;
            tracing::info!(host = %peer.host, dir = %peer.dir(), "enrolled bundle peer; sync is automatic from here");
        }
        PeerCmd::Rm { name } => {
            let peer = sync::peer_rm(&name)?;
            tracing::info!(host = %peer.host, "dropped bundle peer");
        }
    }
    Ok(())
}
