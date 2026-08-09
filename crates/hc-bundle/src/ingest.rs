//! What a peer put in our `bundles/` tree, judged before anything reads it.
//!
//! rsync is a write primitive: an enrolled peer, or anyone who has taken one, can drop
//! arbitrary bytes into a bundle directory. None of that can forge a signature — every
//! signature is checked against a digest we rebuild from the fields ourselves — but a single
//! unparseable or misfiled file makes [`crate::load_dir`] refuse the WHOLE directory, which
//! turns a write primitive into a denial of service against a transaction that is otherwise
//! fine. This module is what removes that: after every pull each file is judged on its own,
//! and anything that would poison the union is moved to `<home>/bundle-quarantine` before the
//! union is taken.
//!
//! A file is only ever moved when it is individually invalid, and no file this machine writes
//! can be: quarantine cannot eat your own signature, whatever a peer floods the directory
//! with. A flood is answered by [`Verdict::crowded`] — a count, not a deletion — because the
//! only thing a hostile peer buys with valid-but-unwanted signatures is disk and noise, and
//! `owners_ok` already refuses them at `export`.
use crate::{Scope, BUNDLE_SUFFIX, SEED_FILE};
use alloy_primitives::{Address, B256};
use err_mac::create_err_with_impls;
use hc_core::config::{bundle_quarantine_dir, bundles_dir};
use hc_sign::bundle::SafeTxBundle;
use std::path::{Path, PathBuf};

/// Largest file a pull may write, and the largest the validator will parse. A bundle is a
/// transaction's fields plus at most a handful of 65-byte signatures; 64 KiB is already
/// generous, and it is the same ceiling the daemon puts on a request body.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Files one bundle directory may hold before the validator says so. A Safe with a threshold
/// in the single digits needs one file per owner and the seed.
pub const MAX_FILES_PER_BUNDLE: usize = 64;

/// Files one validation pass inspects before it stops and says it stopped.
pub const MAX_INGEST_FILES: usize = 4096;

create_err_with_impls!(
    #[derive(Debug)]
    pub IngestErr,
    StdIo(std::io::Error)
    ;
);

/// Which rule a quarantined file broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Neither `unsigned.json` nor `0x<signer>.json`.
    Name,
    /// Bigger than [`MAX_FILE_BYTES`].
    Size,
    /// Not a bundle.
    Parse,
    /// Its fields hash to a digest other than the directory holding it.
    Digest,
    /// A signature does not recover to the address it claims, or contradicts one that does.
    Signature,
    /// A signature filed under a name that is not its signer's.
    Misfiled,
}

/// One file the validator moved out of the bundle tree.
#[derive(Debug, Clone)]
pub struct Rejected {
    /// Where it was.
    pub from: PathBuf,
    /// Where it is now.
    pub to: PathBuf,
    /// Which rule it broke.
    pub reject: Reject,
}

/// What one validation pass found.
#[derive(Debug, Default)]
pub struct Verdict {
    /// Files moved to the quarantine dir, with the rule each broke.
    pub rejected: Vec<Rejected>,
    /// Bundle directories holding more than [`MAX_FILES_PER_BUNDLE`] files.
    pub crowded: Vec<B256>,
    /// True when the pass hit [`MAX_INGEST_FILES`] and stopped early.
    pub capped: bool,
}

/// The bundle directories `scope` covers, in digest order. A directory whose name is not a
/// digest is not a bundle and is not judged: `load_all` already ignores it, so it cannot
/// poison anything, and moving a stray a human left there would be the tool losing their work.
fn dirs(scope: Scope) -> Result<Vec<(B256, PathBuf)>, IngestErr> {
    let root = bundles_dir();
    if let Scope::One(hash) = scope {
        let dir = root.join(hash.to_string());
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        return Ok(vec![(hash, dir)]);
    }
    let mut out = Vec::new();
    if !root.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Ok(hash) = entry.file_name().to_string_lossy().parse::<B256>() else {
            continue;
        };
        out.push((hash, entry.path()));
    }
    out.sort_by_key(|(hash, _)| *hash);
    Ok(out)
}

/// The address a file name binds its contents to: `None` for the seed, which carries no
/// signature at all, and a refusal for any other shape.
fn owner_of(name: &str) -> Result<Option<Address>, Reject> {
    if name == SEED_FILE {
        return Ok(None);
    }
    match name
        .strip_suffix(BUNDLE_SUFFIX)
        .and_then(|stem| stem.parse::<Address>().ok())
    {
        Some(address) => Ok(Some(address)),
        None => Err(Reject::Name),
    }
}

/// Judge one file. `Ok(None)` means the union may take it. Every check is one this machine's
/// own writes satisfy by construction, so a verdict is never a verdict on our own signature.
fn judge(path: &Path, name: &str, hash: B256) -> Result<Option<Reject>, IngestErr> {
    let owner = match owner_of(name) {
        Ok(owner) => owner,
        Err(reject) => return Ok(Some(reject)),
    };
    if std::fs::metadata(path)?.len() > MAX_FILE_BYTES {
        return Ok(Some(Reject::Size));
    }
    let Ok(bundle) = serde_json::from_slice::<SafeTxBundle>(&std::fs::read(path)?) else {
        return Ok(Some(Reject::Parse));
    };
    if bundle.digest() != hash {
        return Ok(Some(Reject::Digest));
    }
    for sig in &bundle.signatures {
        if owner != Some(sig.signer) {
            return Ok(Some(Reject::Misfiled));
        }
    }
    let mut recovered = SafeTxBundle {
        signatures: Vec::new(),
        ..bundle.clone()
    };
    for sig in bundle.signatures {
        if recovered.add(sig).is_err() {
            return Ok(Some(Reject::Signature));
        }
    }
    Ok(None)
}

/// Move a file out of the tree, under the digest of the directory it was poisoning.
fn quarantine(path: &Path, name: &str, hash: B256, reject: Reject) -> Result<Rejected, IngestErr> {
    let dir = bundle_quarantine_dir().join(hash.to_string());
    std::fs::create_dir_all(&dir)?;
    let to = dir.join(name);
    std::fs::rename(path, &to)?;
    Ok(Rejected {
        from: path.to_path_buf(),
        to,
        reject,
    })
}

/// Judge everything `scope` covers, quarantining what would poison a union. Sorted at every
/// level so two runs over the same tree do the same thing in the same order.
pub fn validate(scope: Scope) -> Result<Verdict, IngestErr> {
    let mut verdict = Verdict::default();
    let mut inspected = 0usize;
    for (hash, dir) in dirs(scope)? {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type()?.is_file() && name.ends_with(BUNDLE_SUFFIX) {
                names.push(name);
            }
        }
        names.sort();
        if names.len() > MAX_FILES_PER_BUNDLE {
            verdict.crowded.push(hash);
        }
        for name in names {
            if inspected >= MAX_INGEST_FILES {
                verdict.capped = true;
                return Ok(verdict);
            }
            inspected += 1;
            let path = dir.join(&name);
            if let Some(reject) = judge(&path, &name, hash)? {
                let rejected = quarantine(&path, &name, hash, reject)?;
                tracing::warn!(
                    file = %rejected.from.display(),
                    quarantined = %rejected.to.display(),
                    ?reject,
                    "an ingested bundle file failed verification"
                );
                verdict.rejected.push(rejected);
            }
        }
    }
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{bundle, intent, signed};
    use hc_sign::bundle::CollectedSignature;

    /// The four ways a peer can hand us bytes that break the union, and the one way they
    /// cannot: a file this machine would itself have written is always accepted. Corrupt
    /// bytes, a bundle for another transaction, a signature that recovers to nobody, and a
    /// real signature filed under someone else's name are each refused on their own terms.
    #[test]
    fn a_hostile_peer_cannot_get_a_file_past_the_validator() {
        let dir = std::env::temp_dir().join("hot_cheese_ingest_judge");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make the test dir");

        let held = bundle(intent(3));
        let hash = held.digest();
        let response = signed(0x11, &held);
        let signer = response.signer;
        let mut ours = held.clone();
        ours.add(CollectedSignature {
            signer,
            signature: response.signature,
        })
        .expect("our own signature");
        let good = format!("{signer:#x}{BUNDLE_SUFFIX}");

        let write = |name: &str, bytes: &[u8]| {
            let path = dir.join(name);
            std::fs::write(&path, bytes).expect("write the fixture");
            path
        };

        let path = write(&good, &serde_json::to_vec(&ours).expect("serialize"));
        assert_eq!(
            judge(&path, &good, hash).expect("judging reads the file"),
            None,
            "what this machine writes is what the validator accepts"
        );

        let path = write(SEED_FILE, &serde_json::to_vec(&held).expect("serialize"));
        assert_eq!(judge(&path, SEED_FILE, hash).expect("judged"), None);

        let path = write("junk.json", b"{ not json");
        assert_eq!(
            judge(&path, "junk.json", hash).expect("judged"),
            Some(Reject::Name),
            "a name outside the layout is refused before its bytes matter"
        );

        let path = write(&good, b"{ not a bundle");
        assert_eq!(
            judge(&path, &good, hash).expect("judged"),
            Some(Reject::Parse)
        );

        let elsewhere = bundle(intent(4));
        let path = write(&good, &serde_json::to_vec(&elsewhere).expect("serialize"));
        assert_eq!(
            judge(&path, &good, hash).expect("judged"),
            Some(Reject::Digest),
            "a bundle for another transaction does not belong to this directory"
        );

        let mut forged = ours.clone();
        forged.signatures[0].signature = vec![0x7u8; 65].into();
        let path = write(&good, &serde_json::to_vec(&forged).expect("serialize"));
        assert_eq!(
            judge(&path, &good, hash).expect("judged"),
            Some(Reject::Signature),
            "a signature that recovers to nobody is refused"
        );

        let stranger = format!("{:#x}{BUNDLE_SUFFIX}", Address::from([0x99u8; 20]));
        let path = write(&stranger, &serde_json::to_vec(&ours).expect("serialize"));
        assert_eq!(
            judge(&path, &stranger, hash).expect("judged"),
            Some(Reject::Misfiled),
            "one file per signer means the name binds the contents"
        );

        let path = write(SEED_FILE, &serde_json::to_vec(&ours).expect("serialize"));
        assert_eq!(
            judge(&path, SEED_FILE, hash).expect("judged"),
            Some(Reject::Misfiled),
            "the seed carries no signature, so a signature hidden in it is misfiled"
        );

        let path = write(&good, &vec![b'x'; MAX_FILE_BYTES as usize + 1]);
        assert_eq!(
            judge(&path, &good, hash).expect("judged"),
            Some(Reject::Size)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
