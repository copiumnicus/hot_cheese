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
use hc_bundle::Scope;
use hc_sign::bundle::Quorum;
use hc_sign::grant::IntentKind;
use hc_sign::intent::Intent;
use std::path::PathBuf;

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
            let intent = match hc_core::wire::strict_json_from_slice(&read_input(file.as_deref())?)?
            {
                Intent::SafeTx(intent) => intent,
                Intent::TypedData(_) => {
                    return Err(CliErr::NotBundleable {
                        kind: IntentKind::TypedData,
                    })
                }
            };
            hc_bundle::new(mode, intent)?;
            Ok(())
        }
        BundleCmd::Sign { hash, key } => {
            let intent = hc_bundle::intent_to_sign(mode, hash, &key)?;
            let response = crate::sign_intent_locally(intent, unlock)?;
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
            let response = hc_core::wire::strict_json_from_slice(&read_input(file.as_deref())?)?;
            hc_bundle::collect(mode, hash, response)?;
            Ok(())
        }
        BundleCmd::Sync { hash } => {
            let synced = sync::sync_now(scope(hash));
            report("pulled", &synced.pulled);
            report("pushed", &synced.pushed);
            Ok(())
        }
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
        judged = report.verdict.judged,
        bundles = report.verdict.dirs,
        "bundle sync"
    );
    for peer in &report.peers {
        match &peer.result {
            Ok(()) => tracing::info!(host = %peer.host, "  ok"),
            Err(e) => tracing::warn!(host = %peer.host, error = %e, "  FAILED"),
        }
    }
    for rejected in &report.verdict.rejected {
        tracing::warn!(file = %rejected.from.display(), reject = ?rejected.reject, disposal = ?rejected.disposal, "  REFUSED");
    }
    for hash in &report.verdict.crowded {
        tracing::warn!(%hash, "  CROWDED: more files than the per-bundle cap; the overflow was quarantined");
    }
    for hash in &report.verdict.refused_dirs {
        tracing::warn!(%hash, "  REFUSED: a bundle directory arrived past the cap and was removed");
    }
    if report.verdict.refused_files > 0 {
        tracing::warn!(
            files = report.verdict.refused_files,
            "  REFUSED: files past the per-bundle cap"
        );
    }
    if report.verdict.capped {
        tracing::warn!(
            "  CAPPED: too many files to judge in one pass; the rest are left to the next one"
        );
    }
}

/// The threshold the peer-written file claims, whenever it is not the one `safes.toml` states.
/// Quorum is counted from the local number alone; the claim is reported and never counted.
fn warn_stated_threshold(hash: B256, quorum: &Quorum) {
    let Some(stated) = quorum.stated else {
        return;
    };
    tracing::warn!(
        %hash,
        safes_toml = quorum.threshold,
        bundle_file = stated,
        "THRESHOLD MISMATCH: the bundle file states a threshold safes.toml does not"
    );
}

fn status(mode: SyncMode, hash: B256) -> Result<(), CliErr> {
    let s = hc_bundle::status(mode, hash)?;
    tracing::info!(
        %hash,
        have = s.quorum.have,
        threshold = s.quorum.threshold,
        met = s.quorum.met,
        packed_bytes = s.bundle.packed().len(),
        age_hours = s.age_ms / HOUR_MS,
        "bundle"
    );
    warn_stated_threshold(hash, &s.quorum);
    for sig in &s.bundle.signatures {
        tracing::info!(signer = %sig.signer, "  signed");
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
                have = one.quorum.have,
                threshold = one.quorum.threshold,
                met = one.quorum.met,
                age_hours = now.saturating_sub(one.bundle.created_at_ms) / HOUR_MS,
                "  bundle"
            );
            warn_stated_threshold(one.hash, &one.quorum);
        }
    }
    Ok(())
}

fn merge(mode: SyncMode, hash: B256, file: Option<PathBuf>) -> Result<(), CliErr> {
    let incoming = match file {
        Some(path) => hc_bundle::read_bundle(&path, hash)?,
        None => hc_core::wire::strict_json_from_slice(&read_input(None)?)?,
    };
    let merged = hc_bundle::merge(mode, hash, incoming)?;
    for signer in &merged.added {
        tracing::info!(%hash, %signer, "merged signature");
    }
    tracing::info!(
        %hash,
        have = merged.quorum.have,
        threshold = merged.quorum.threshold,
        met = merged.quorum.met,
        "merged"
    );
    warn_stated_threshold(hash, &merged.quorum);
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
