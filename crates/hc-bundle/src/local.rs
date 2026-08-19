//! What THIS machine states about a bundle, kept where no peer can write it.
//!
//! Both facts here live outside `bundles/`, so no rsync filter carries them and no pull can undo
//! them. A retirement is one: `rm` removes a directory, and without a tombstone the next pull
//! brings it straight back and it keeps holding its (safe, chain, nonce) slot forever. A held
//! approval is the other: a device's biometric was already spent on a [`SignResponse`], so if the
//! local write cannot take it right now it is kept on disk and the next [`crate::collect`] for
//! that bundle takes it — an approval is never discarded because a lock or a load failed.
use crate::ingest::{MAX_FILES_PER_BUNDLE, MAX_FILE_BYTES};
use crate::{BundleErr, BUNDLE_SUFFIX};
use alloy_primitives::B256;
use hashbrown::HashSet;
use hc_core::config::home_dir;
use hc_core::crypto::envelope::{atomic_write_new, EnvErr};
use hc_sign::SignResponse;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Retirements this machine keeps. A tombstone is a name and nothing else, and the oldest are
/// dropped to make room, so a long-running machine cannot grow this tree without bound.
const MAX_TOMBSTONES: usize = 256;

fn tombstones() -> PathBuf {
    home_dir().join("bundle-tombstones")
}

fn spool() -> PathBuf {
    home_dir().join("bundle-spool")
}

/// Every bundle this machine retired.
pub(crate) fn retired() -> Result<HashSet<B256>, BundleErr> {
    let dir = tombstones();
    let mut out = HashSet::new();
    if !crate::owned_directory_exists(&dir)? {
        return Ok(out);
    }
    for (at, entry) in std::fs::read_dir(&dir)?.enumerate() {
        if at >= MAX_TOMBSTONES {
            break;
        }
        let entry = entry?;
        if let Some(hash) = crate::canonical_bundle_hash(&entry.file_name()) {
            out.insert(hash);
        }
    }
    Ok(out)
}

/// State locally that this bundle is done with. Survives the next pull, which is the whole point:
/// a plain `rm` is undone by the transport, and no transfer here carries a deletion.
pub(crate) fn retire(hash: B256) -> Result<(), BundleErr> {
    let dir = tombstones();
    crate::ensure_owned_directory(&dir)?;
    let mut held = Vec::new();
    for (at, entry) in std::fs::read_dir(&dir)?.enumerate() {
        if at >= MAX_TOMBSTONES * 2 {
            break;
        }
        let entry = entry?;
        held.push((entry.metadata()?.ctime(), entry.path()));
    }
    held.sort();
    while held.len() >= MAX_TOMBSTONES {
        let (_, oldest) = held.remove(0);
        std::fs::remove_file(oldest)?;
    }
    match atomic_write_new(&dir.join(hash.to_string()), &[]) {
        Ok(()) => Ok(()),
        Err(EnvErr::StdIo(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Undo a retirement, because a local write into a bundle is this machine saying it is live again.
pub(crate) fn revive(hash: B256) -> Result<(), BundleErr> {
    match std::fs::remove_file(tombstones().join(hash.to_string())) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Make an approval durable before anything that can fail runs. A second, different approval from
/// the same signer is refused by [`hc_sign::bundle::SafeTxBundle::add`] anyway, so the one already
/// held stays.
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
    let signer = response.signer;
    let bytes = serde_json::to_vec(response)?;
    match atomic_write_new(&dir.join(format!("{signer:#x}{BUNDLE_SUFFIX}")), &bytes) {
        Ok(()) => Ok(()),
        Err(EnvErr::StdIo(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Every approval held for `hash`, with the file each is held in. Bytes that are no longer an
/// approval are removed rather than returned: this machine wrote them, so they can only be damage,
/// and one of them must not be able to fail every later collect.
pub(crate) fn held(hash: B256) -> Result<Vec<(PathBuf, SignResponse)>, BundleErr> {
    let dir = spool().join(hash.to_string());
    let mut out = Vec::new();
    if !crate::owned_directory_exists(&dir)? {
        return Ok(out);
    }
    let mut paths = Vec::new();
    for (at, entry) in std::fs::read_dir(&dir)?.enumerate() {
        if at >= MAX_FILES_PER_BUNDLE {
            break;
        }
        let entry = entry?;
        if entry.file_type()?.is_file() {
            paths.push(entry.path());
        }
    }
    paths.sort();
    for path in paths {
        let bytes = hc_core::read_regular_file_bounded(&path, MAX_FILE_BYTES)?;
        match hc_core::wire::strict_json_from_slice::<SignResponse>(&bytes) {
            Ok(response) if response.safe_tx_hash == hash => out.push((path, response)),
            Ok(_) => {
                tracing::warn!(file = %path.display(), "a held approval names another transaction");
                release(&path)?;
            }
            Err(error) => {
                tracing::warn!(file = %path.display(), %error, "a held approval no longer parses");
                release(&path)?;
            }
        }
    }
    Ok(out)
}

pub(crate) fn release(path: &Path) -> Result<(), BundleErr> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Drop every approval held for a bundle that is being retired.
pub(crate) fn discard(hash: B256) -> Result<(), BundleErr> {
    let dir = spool().join(hash.to_string());
    if !crate::owned_directory_exists(&dir)? {
        return Ok(());
    }
    for (path, _) in held(hash)? {
        release(&path)?;
    }
    match std::fs::remove_dir(&dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
