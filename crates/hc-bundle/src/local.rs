//! What THIS machine states about a bundle, kept where no peer can write it.
//!
//! Every fact here lives outside `bundles/`, so no rsync filter carries it and no pull can undo
//! it. There are four, and each answers a question a peer must not get to answer.
//!
//! A retirement says a bundle is done with: `rm` removes a directory, and without a tombstone the
//! next pull brings it straight back and it keeps holding its (safe, chain, nonce) slot forever.
//! A held approval says a device's biometric was already spent on a [`SignResponse`], so if the
//! local write cannot take it right now it is kept on disk and the next [`crate::collect`] takes
//! it — an approval is never discarded because a lock, a load or a write failed.
//!
//! The other two are what make "ours" a fact rather than a notification. A claim says this
//! machine created a bundle or spent a biometric on it, and a signer name says this machine wrote
//! a bundle file under it. Both are written by the code that does the writing, so every entry
//! point — CLI, console, MCP, daemon — records them by construction, and no cap, quota or expiry
//! can reach the operator's own work because one of them forgot to announce it.
use crate::ingest::{MAX_FILES_PER_BUNDLE, MAX_FILE_BYTES, PROPOSAL_TTL_MS};
use crate::{BundleErr, BUNDLE_SUFFIX};
use alloy_primitives::{Address, B256};
use hashbrown::HashSet;
use hc_core::config::home_dir;
use hc_core::crypto::envelope::{atomic_write_new, EnvErr};
use hc_sign::SignResponse;
use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Names one local fact directory may hold before reading it is refused. Every entry is an empty
/// file this machine wrote, so reaching this is not something a peer or a pass can drive.
const MAX_LOCAL_FACTS: usize = 4096;

/// How long a retirement nothing has had to enforce is kept. Enforcing one renews it, so this
/// expires only tombstones no peer has re-served the bundle for in a fortnight — after which the
/// bundle is an ordinary unsigned proposal again and expires on its own terms.
const RETIREMENT_TTL_MS: u64 = PROPOSAL_TTL_MS;

fn tombstones() -> PathBuf {
    home_dir().join("bundle-tombstones")
}

fn spool() -> PathBuf {
    home_dir().join("bundle-spool")
}

fn claims() -> PathBuf {
    home_dir().join("bundle-claims")
}

fn signer_names() -> PathBuf {
    home_dir().join("bundle-signers")
}

/// Every name one local fact directory holds. A read that cannot be completed is a refusal, never
/// a prefix: half of a fact set is not the fact set, and the caller is about to judge what may be
/// deleted by it.
fn facts(dir: &Path) -> Result<Vec<OsString>, BundleErr> {
    let mut out = Vec::new();
    if !crate::owned_directory_exists(dir)? {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        if out.len() >= MAX_LOCAL_FACTS {
            return Err(BundleErr::TooManyLocalFacts {
                dir: dir.to_path_buf(),
                max: MAX_LOCAL_FACTS,
            });
        }
        out.push(entry?.file_name());
    }
    Ok(out)
}

/// Write an empty fact, or leave the one already there.
fn state(dir: &Path, name: &str) -> Result<(), BundleErr> {
    crate::ensure_owned_directory(dir)?;
    match atomic_write_new(&dir.join(name), &[]) {
        Ok(()) => Ok(()),
        Err(EnvErr::StdIo(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn forget(path: &Path) -> Result<(), BundleErr> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Milliseconds since this kernel last changed the inode, which a peer does not choose.
fn local_age_ms(path: &Path, now_ms: u64) -> Result<u64, BundleErr> {
    let meta = std::fs::symlink_metadata(path)?;
    let stamped = meta
        .ctime()
        .saturating_mul(1000)
        .saturating_add(meta.ctime_nsec() / 1_000_000);
    let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
    Ok(u64::try_from(now.saturating_sub(stamped)).unwrap_or(0))
}

/// Every bundle this machine retired.
pub(crate) fn retired() -> Result<HashSet<B256>, BundleErr> {
    let mut out = HashSet::new();
    for name in facts(&tombstones())? {
        if let Some(hash) = crate::canonical_bundle_hash(&name) {
            out.insert(hash);
        }
    }
    Ok(out)
}

/// Every bundle this machine created, imported into, or spent a biometric on. Nothing automatic
/// removes a directory named here.
pub(crate) fn ours() -> Result<HashSet<B256>, BundleErr> {
    let mut out = HashSet::new();
    for name in facts(&claims())? {
        if let Some(hash) = crate::canonical_bundle_hash(&name) {
            out.insert(hash);
        }
    }
    Ok(out)
}

/// Every signer name this machine has itself written a bundle file under.
pub(crate) fn signers() -> Result<HashSet<Address>, BundleErr> {
    let mut out = HashSet::new();
    for name in facts(&signer_names())? {
        let Some(text) = name.to_str() else {
            continue;
        };
        let Ok(address) = text.parse::<Address>() else {
            continue;
        };
        if text == format!("{address:#x}") {
            out.insert(address);
        }
    }
    Ok(out)
}

/// State that this machine wrote a bundle file under this signer name, which is what keeps a
/// crowded directory's file cap from moving our own signature out before a peer's.
pub(crate) fn sign_as(signer: Address) -> Result<(), BundleErr> {
    state(&signer_names(), &format!("{signer:#x}"))
}

/// State that this bundle is this machine's own.
pub(crate) fn claim(hash: B256) -> Result<(), BundleErr> {
    state(&claims(), &hash.to_string())
}

/// State locally that this bundle is done with. Survives the next pull, which is the whole point:
/// a plain `rm` is undone by the transport, and no transfer here carries a deletion.
pub(crate) fn retire(hash: B256) -> Result<(), BundleErr> {
    if let Err(error) = reclaim(hc_sign::grant::now_ms()?) {
        tracing::warn!(%error, "cannot reclaim the local facts this machine is done with");
    }
    state(&tombstones(), &hash.to_string())?;
    forget(&claims().join(hash.to_string()))
}

/// Undo a retirement, because a local write into a bundle is this machine saying it is live and
/// its own again.
pub(crate) fn revive(hash: B256) -> Result<(), BundleErr> {
    forget(&tombstones().join(hash.to_string()))?;
    claim(hash)
}

/// Restamp a retirement a pass has just enforced, so a tombstone that is still doing work never
/// ages out from under a peer that keeps re-serving the bundle.
pub(crate) fn renew(hash: B256) -> Result<(), BundleErr> {
    let path = tombstones().join(hash.to_string());
    match std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Drop the facts that have nothing left to say: a retirement no bundle directory has needed for
/// [`RETIREMENT_TTL_MS`], and a claim whose bundle and whose held approvals are both gone. Both
/// sets are therefore bounded by what this machine is actually working on rather than by a ring
/// that silently drops the oldest thing the operator said.
pub(crate) fn reclaim(now_ms: u64) -> Result<(), BundleErr> {
    for name in facts(&claims())? {
        let Some(hash) = crate::canonical_bundle_hash(&name) else {
            continue;
        };
        if crate::owned_directory_exists(&crate::bundle_dir(hash))?
            || crate::owned_directory_exists(&spool().join(hash.to_string()))?
        {
            continue;
        }
        drop_fact(&claims().join(name));
    }
    for name in facts(&tombstones())? {
        let Some(hash) = crate::canonical_bundle_hash(&name) else {
            continue;
        };
        let path = tombstones().join(name);
        if crate::owned_directory_exists(&crate::bundle_dir(hash))?
            || local_age_ms(&path, now_ms)? <= RETIREMENT_TTL_MS
        {
            continue;
        }
        drop_fact(&path);
    }
    Ok(())
}

/// Drop one fact that has nothing left to say. One that will not go is reported and kept: it is
/// the next reclaim's problem, never this caller's.
fn drop_fact(path: &Path) {
    if let Err(error) = forget(path) {
        tracing::warn!(file = %path.display(), %error, "cannot reclaim a local fact");
    }
}

/// Make an approval durable, and the bundle this machine's own, before anything that can fail
/// runs. A second, different approval from the same signer is refused by
/// [`hc_sign::bundle::SafeTxBundle::add`] anyway, so the one already held stays.
pub(crate) fn hold(hash: B256, response: &SignResponse) -> Result<(), BundleErr> {
    if response.safe_tx_hash != hash {
        return Err(BundleErr::ForeignDigest {
            ours: hash,
            theirs: response.safe_tx_hash,
        });
    }
    let dir = spool().join(hash.to_string());
    crate::ensure_owned_directory(&spool())?;
    crate::ensure_owned_directory(&dir)?;
    claim(hash)?;
    let signer = response.signer;
    let bytes = serde_json::to_vec(response)?;
    match atomic_write_new(&dir.join(format!("{signer:#x}{BUNDLE_SUFFIX}")), &bytes) {
        Ok(()) => Ok(()),
        Err(EnvErr::StdIo(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Every approval held for `hash`, with the file each is held in. Bytes that are no longer an
/// approval are removed rather than returned: this machine wrote them, so they can only be
/// damage, and the check that says so is re-derived from the bytes themselves. Everything else —
/// a file that will not open, will not read, or will not unlink — is skipped and reported, because
/// one of them must never be able to fail every later collect for this bundle.
pub(crate) fn held(hash: B256) -> Result<Vec<(PathBuf, SignResponse)>, BundleErr> {
    let dir = spool().join(hash.to_string());
    let mut out = Vec::new();
    if !crate::owned_directory_exists(&dir)? {
        return Ok(out);
    }
    let mut paths = Vec::new();
    for name in facts(&dir)? {
        paths.push(dir.join(name));
    }
    paths.sort();
    paths.truncate(MAX_FILES_PER_BUNDLE);
    for path in paths {
        let bytes = match hc_core::read_regular_file_bounded(&path, MAX_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(file = %path.display(), %error, "skipping a held approval this machine cannot read");
                continue;
            }
        };
        let damaged = match hc_core::wire::strict_json_from_slice::<SignResponse>(&bytes) {
            Ok(response) if response.safe_tx_hash == hash => {
                out.push((path, response));
                continue;
            }
            Ok(_) => "a held approval names another transaction",
            Err(_) => "a held approval no longer parses",
        };
        tracing::warn!(file = %path.display(), damaged);
        if let Err(error) = release(&path) {
            tracing::warn!(file = %path.display(), %error, "cannot drop a damaged held approval");
        }
    }
    Ok(out)
}

pub(crate) fn release(path: &Path) -> Result<(), BundleErr> {
    forget(path)
}

/// Drop everything held for a bundle that is being retired, readable or not, so nothing a
/// filesystem can leave in the spool outlives the bundle it was held for.
pub(crate) fn discard(hash: B256) -> Result<(), BundleErr> {
    let dir = spool().join(hash.to_string());
    if !crate::owned_directory_exists(&dir)? {
        return Ok(());
    }
    for name in facts(&dir)? {
        let path = dir.join(name);
        if let Err(error) = release(&path) {
            tracing::warn!(file = %path.display(), %error, "cannot drop a held approval");
        }
    }
    match std::fs::remove_dir(&dir) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::NotFound
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}
