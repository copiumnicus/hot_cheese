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
//! A file judged invalid is one no local writer can produce, so quarantine cannot eat your own
//! signature. The ONE exception is [`MAX_FILES_PER_BUNDLE`]: past it the overflow is moved out
//! by name order, and a peer that floods a directory with names sorting below ours can push a
//! local signature no pass has judged yet into the quarantine tree. It is moved, never deleted,
//! precisely so the operator can put it back — and the alternative, leaving one directory's file
//! count unbounded under a poller that runs 2,880 times a day, is worse.
use crate::{Scope, BUNDLE_SUFFIX, SEED_FILE};
use alloy_primitives::{Address, B256};
use err_mac::create_err_with_impls;
use hashbrown::{HashMap, HashSet};
use hc_core::config::{bundle_quarantine_dir, bundles_dir};
use hc_sign::bundle::SafeTxBundle;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Largest file a pull may write, and the largest the validator will parse. A bundle is a
/// transaction's fields plus at most a handful of 65-byte signatures; 64 KiB is already
/// generous, and it is the same ceiling the daemon puts on a request body.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Files one bundle directory may hold. A Safe with a threshold in the single digits needs one
/// file per owner and the seed; the overflow is quarantined.
pub const MAX_FILES_PER_BUNDLE: usize = 64;

/// Files one validation pass JUDGES before it leaves the rest to the next one.
pub const MAX_INGEST_FILES: usize = 4096;

/// Bundle directories this machine will hold. Beyond it, a directory that ARRIVED is refused;
/// one that was already here is never touched. 64 × [`MAX_FILES_PER_BUNDLE`] is exactly
/// [`MAX_INGEST_FILES`], so a tree that has been under the cap from the start is covered by one
/// pass, and 64 is four times the review queue `mcp.max_pending` gives a human.
pub const MAX_BUNDLE_DIRS: usize = 64;

/// Files the quarantine tree holds before a rejected file is deleted instead of moved. 1024 ×
/// [`MAX_FILE_BYTES`] is a 64 MiB ceiling on what a flood can leave on this disk.
pub const MAX_QUARANTINE_FILES: usize = 1024;

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
    /// A per-signer file carrying more than the one signature its name binds it to.
    Stuffed,
}

/// Why a file is leaving the bundle tree, and therefore whether a full quarantine may delete it
/// rather than hold it.
enum Refusal {
    /// [`judge`] refused it by a rule no local writer can break.
    Judged(Reject),
    /// It pushed its directory past [`MAX_FILES_PER_BUNDLE`], which a local file can be caught by.
    Crowding,
}

/// What the validator did with a file it refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposal {
    /// Moved under `<home>/bundle-quarantine/<digest>/`.
    Quarantined { to: PathBuf },
    /// Deleted, because the quarantine tree is full and no local writer could have written it.
    Deleted,
    /// Left where it is: the quarantine tree is full and this refusal can touch a local file.
    Left,
}

/// One file the validator refused.
#[derive(Debug, Clone)]
pub struct Rejected {
    /// Where it was.
    pub from: PathBuf,
    /// What became of it.
    pub disposal: Disposal,
    /// Which rule it broke.
    pub reject: Reject,
}

/// What one validation pass found.
#[derive(Debug, Default)]
pub struct Verdict {
    /// Files the pass refused, with the rule each broke and what became of it.
    pub rejected: Vec<Rejected>,
    /// Bundle directories holding more than [`MAX_FILES_PER_BUNDLE`] files.
    pub crowded: Vec<B256>,
    /// Bundle directories this machine holds now, after any refusal below.
    pub dirs: usize,
    /// Bundle directories removed whole for arriving past [`MAX_BUNDLE_DIRS`].
    pub refused_dirs: Vec<B256>,
    /// Files quarantined for pushing a directory past [`MAX_FILES_PER_BUNDLE`].
    pub refused_files: usize,
    /// Files this pass judged: the ones whose local identity had moved since the last one.
    pub judged: usize,
    /// True when the pass spent [`MAX_INGEST_FILES`] and left the rest for the next one.
    pub capped: bool,
}

/// Identity of the exact bytes a pass judged. Every field is set by the local kernel on write,
/// so nothing a peer sends can forge a match: `mtime` is whatever the sender chose, and `-a`
/// preserves it, while `ctime` is when THIS kernel last changed the inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    /// Inode; rsync writes a temp file and renames, so a replacement is a new one.
    ino: u64,
    /// Inode change time, which a rename or a write always advances.
    ctime: i64,
    /// Its nanosecond part, which two writes in the same second still differ in.
    ctime_nsec: i64,
    /// Length, which catches an in-place rewrite that kept the inode.
    len: u64,
}

/// What a previous pass already judged, so the next pass ecrecovers only what changed.
///
/// In memory only, and deliberately: an index on disk would sit in the tree a peer writes to,
/// and a peer who could edit it could mark unjudged bytes as judged. The cost is a full pass
/// after every restart, which is exactly today's behaviour.
#[derive(Debug)]
pub struct Ingest {
    /// Identity of the last accepted bytes at each file name, per bundle directory. A directory
    /// with an entry here is one a previous pass accounted for, whatever it held.
    seen: HashMap<B256, HashMap<String, FileId>>,
    /// False until the first whole-tree pass has taken stock of what was already here.
    primed: bool,
    /// Files currently sitting in the quarantine tree.
    quarantined: usize,
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

/// Judge one file's bytes. `None` means the union may take it. Every check is one this machine's
/// own writes satisfy by construction, so a verdict is never a verdict on our own signature. The
/// io is the caller's, which is what lets a pass skip a file it has already judged.
fn judge(bytes: &[u8], name: &str, hash: B256) -> Option<Reject> {
    let owner = match owner_of(name) {
        Ok(owner) => owner,
        Err(reject) => return Some(reject),
    };
    let Ok(bundle) = serde_json::from_slice::<SafeTxBundle>(bytes) else {
        return Some(Reject::Parse);
    };
    if bundle.digest() != hash {
        return Some(Reject::Digest);
    }
    if bundle.signatures.len() > 1 {
        return Some(Reject::Stuffed);
    }
    for sig in &bundle.signatures {
        if owner != Some(sig.signer) {
            return Some(Reject::Misfiled);
        }
    }
    let mut recovered = SafeTxBundle {
        signatures: Vec::new(),
        ..bundle.clone()
    };
    for sig in bundle.signatures {
        if recovered.add(sig).is_err() {
            return Some(Reject::Signature);
        }
    }
    None
}

impl Ingest {
    /// Prime from the tree that is already here. Nothing has ARRIVED until a pass has taken
    /// stock, and the quarantine tree is counted once so [`MAX_QUARANTINE_FILES`] bounds the
    /// files it holds rather than the events that put them there — a peer whose file we quarantine
    /// every tick lands on the same `<digest>/<name>` every time and adds nothing.
    pub fn new() -> Result<Self, IngestErr> {
        let root = bundle_quarantine_dir();
        let mut quarantined = 0usize;
        if root.is_dir() {
            for entry in std::fs::read_dir(&root)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                for held in std::fs::read_dir(entry.path())? {
                    if held?.file_type()?.is_file() {
                        quarantined += 1;
                    }
                }
            }
        }
        Ok(Ingest {
            seen: HashMap::new(),
            primed: false,
            quarantined,
        })
    }

    /// Whether a directory is one a peer just created. A bundle this device wrote into is never
    /// one, which is what keeps [`MAX_BUNDLE_DIRS`] from deleting the operator's own new bundle,
    /// and before the priming pass nothing has arrived at all.
    fn arrived(&self, hash: B256, ours: &HashSet<B256>) -> bool {
        self.primed && !self.seen.contains_key(&hash) && !ours.contains(&hash)
    }

    /// Take a refused file out of the tree: to the quarantine dir, or deleted when that tree is
    /// full and no local writer could have produced the file, or left alone when one could.
    fn dispose(
        &mut self,
        from: &Path,
        name: &str,
        hash: B256,
        refusal: Refusal,
    ) -> Result<Disposal, IngestErr> {
        let dir = bundle_quarantine_dir().join(hash.to_string());
        let to = dir.join(name);
        let fresh = !to.exists();
        if fresh && self.quarantined >= MAX_QUARANTINE_FILES {
            if matches!(refusal, Refusal::Judged(reject) if reject != Reject::Stuffed) {
                std::fs::remove_file(from)?;
                return Ok(Disposal::Deleted);
            }
            return Ok(Disposal::Left);
        }
        std::fs::create_dir_all(&dir)?;
        std::fs::rename(from, &to)?;
        if fresh {
            self.quarantined += 1;
        }
        Ok(Disposal::Quarantined { to })
    }
}

impl Ingest {
    /// Judge everything `scope` covers, quarantining what would poison a union and reading
    /// nothing whose local identity has not moved since the last pass. `ours` is the set of
    /// bundles this device wrote into, which [`MAX_BUNDLE_DIRS`] never refuses. Sorted at every
    /// level so two runs over the same tree do the same thing in the same order.
    ///
    /// [`MAX_INGEST_FILES`] bounds the files one pass JUDGES, never the names it reaches: a
    /// budget spent on skips would be spent re-reaching the same sorted prefix every pass, and
    /// the suffix past it — which a peer aims at by choosing a low digest — would never be
    /// judged at all.
    pub fn validate(&mut self, scope: Scope, ours: &HashSet<B256>) -> Result<Verdict, IngestErr> {
        let entries = dirs(scope)?;
        let mut verdict = Verdict {
            dirs: entries.len(),
            ..Verdict::default()
        };
        let mut kept = 0usize;
        for (hash, _) in &entries {
            if !self.arrived(*hash, ours) {
                kept += 1;
            }
        }
        let mut pass: HashMap<B256, HashMap<String, FileId>> = HashMap::new();
        for (hash, dir) in entries {
            if self.arrived(hash, ours) {
                if kept >= MAX_BUNDLE_DIRS {
                    std::fs::remove_dir_all(&dir)?;
                    verdict.refused_dirs.push(hash);
                    verdict.dirs -= 1;
                    continue;
                }
                kept += 1;
            }
            let held = self.seen.remove(&hash).unwrap_or_default();
            let mut fresh = HashMap::new();
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
                names.sort_by_key(|name| match name.as_str() {
                    SEED_FILE => 0u8,
                    judged if held.contains_key(judged) => 1,
                    _ => 2,
                });
                for name in names.split_off(MAX_FILES_PER_BUNDLE) {
                    let from = dir.join(&name);
                    let disposal = self.dispose(&from, &name, hash, Refusal::Crowding)?;
                    tracing::debug!(file = %from.display(), ?disposal, "a bundle directory is over its file cap");
                    verdict.refused_files += 1;
                }
                names.sort();
            }
            for name in names {
                let from = dir.join(&name);
                let mut file = std::fs::File::open(&from)?;
                let meta = file.metadata()?;
                let id = FileId {
                    ino: meta.ino(),
                    ctime: meta.ctime(),
                    ctime_nsec: meta.ctime_nsec(),
                    len: meta.size(),
                };
                if held.get(&name) == Some(&id) {
                    fresh.insert(name, id);
                    continue;
                }
                if verdict.judged >= MAX_INGEST_FILES {
                    verdict.capped = true;
                    continue;
                }
                verdict.judged += 1;
                let reject = match id.len > MAX_FILE_BYTES {
                    true => Some(Reject::Size),
                    false => {
                        let mut bytes = Vec::with_capacity(id.len as usize);
                        file.read_to_end(&mut bytes)?;
                        judge(&bytes, &name, hash)
                    }
                };
                let Some(reject) = reject else {
                    fresh.insert(name, id);
                    continue;
                };
                let disposal = self.dispose(&from, &name, hash, Refusal::Judged(reject))?;
                tracing::debug!(
                    file = %from.display(),
                    ?disposal,
                    ?reject,
                    "an ingested bundle file failed verification"
                );
                verdict.rejected.push(Rejected {
                    from,
                    disposal,
                    reject,
                });
            }
            pass.insert(hash, fresh);
        }
        match scope {
            Scope::All => {
                self.seen = pass;
                self.primed = true;
            }
            Scope::One(_) => self.seen.extend(pass),
        }
        Ok(verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle_dir;
    use crate::tests::{bundle, intent, signed};
    use hc_sign::bundle::CollectedSignature;

    /// One test at a time owns `HOT_CHEESE_HOME`: it is process-wide, and `bundles_dir()` reads it
    /// on every call.
    static HOME: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// A throwaway home holding an empty bundle tree, pointed at by the environment.
    fn home(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("bundles")).expect("make the test home");
        std::env::set_var("HOT_CHEESE_HOME", &root);
        root
    }

    /// Every file under `root`, by path relative to it, so two trees compare byte for byte.
    fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(root) else {
            return out;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            match path.is_dir() {
                true => {
                    for (under, bytes) in tree(&path) {
                        out.push((format!("{name}/{under}"), bytes));
                    }
                }
                false => out.push((name, std::fs::read(&path).expect("read a tree file"))),
            }
        }
        out.sort();
        out
    }

    /// What one pass refused, named by paths relative to its own home so two homes compare.
    fn refusals(root: &Path, verdict: &Verdict) -> Vec<(String, Reject)> {
        let mut out = Vec::new();
        for rejected in &verdict.rejected {
            let under = rejected
                .from
                .strip_prefix(root)
                .expect("a refusal is under its own home");
            out.push((under.display().to_string(), rejected.reject));
        }
        out
    }

    /// One bundle directory holding its seed, written into both homes a test compares.
    fn seed_dir(roots: &[&PathBuf], nonce: u64) -> B256 {
        let seed = bundle(intent(nonce));
        let hash = seed.digest();
        let bytes = serde_json::to_vec(&seed).expect("serialize the seed");
        for root in roots {
            let dir = root.join("bundles").join(hash.to_string());
            std::fs::create_dir_all(&dir).expect("make a bundle dir");
            std::fs::write(dir.join(SEED_FILE), &bytes).expect("write the seed");
        }
        hash
    }

    /// The four ways a peer can hand us bytes that break the union, and the one way they
    /// cannot: a file this machine would itself have written is always accepted. Corrupt
    /// bytes, a bundle for another transaction, a signature that recovers to nobody, and a
    /// real signature filed under someone else's name are each refused on their own terms.
    #[test]
    fn a_hostile_peer_cannot_get_a_file_past_the_validator() {
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
        let bytes = |b: &SafeTxBundle| serde_json::to_vec(b).expect("serialize");

        assert_eq!(
            judge(&bytes(&ours), &good, hash),
            None,
            "what this machine writes is what the validator accepts"
        );
        assert_eq!(judge(&bytes(&held), SEED_FILE, hash), None);
        assert_eq!(
            judge(b"{ not json", "junk.json", hash),
            Some(Reject::Name),
            "a name outside the layout is refused before its bytes matter"
        );
        assert_eq!(judge(b"{ not a bundle", &good, hash), Some(Reject::Parse));
        assert_eq!(
            judge(&bytes(&bundle(intent(4))), &good, hash),
            Some(Reject::Digest),
            "a bundle for another transaction does not belong to this directory"
        );

        let mut forged = ours.clone();
        forged.signatures[0].signature = vec![0x7u8; 65].into();
        assert_eq!(
            judge(&bytes(&forged), &good, hash),
            Some(Reject::Signature),
            "a signature that recovers to nobody is refused"
        );

        let stranger = format!("{:#x}{BUNDLE_SUFFIX}", Address::from([0x99u8; 20]));
        assert_eq!(
            judge(&bytes(&ours), &stranger, hash),
            Some(Reject::Misfiled),
            "one file per signer means the name binds the contents"
        );
        assert_eq!(
            judge(&bytes(&ours), SEED_FILE, hash),
            Some(Reject::Misfiled),
            "the seed carries no signature, so a signature hidden in it is misfiled"
        );
    }

    /// A per-signer file can never cost more than one ecrecover. The refusal is not the point —
    /// that is one `if` — the ordering is: a second signature that recovers to nobody would come
    /// back `Signature` if the recovery loop had run at all.
    #[test]
    fn a_file_repeating_a_signature_is_refused_before_it_is_recovered() {
        let held = bundle(intent(3));
        let hash = held.digest();
        let response = signed(0x11, &held);
        let signer = response.signer;
        let name = format!("{signer:#x}{BUNDLE_SUFFIX}");
        let one = CollectedSignature {
            signer,
            signature: response.signature,
        };

        let mut stuffed = held.clone();
        stuffed.signatures = vec![one.clone(); 300];
        assert_eq!(
            judge(
                &serde_json::to_vec(&stuffed).expect("serialize"),
                &name,
                hash
            ),
            Some(Reject::Stuffed),
            "300 repeats of one valid signature is 300 recoveries no writer here can ask for"
        );

        stuffed.signatures = vec![
            one,
            CollectedSignature {
                signer,
                signature: vec![0x7u8; 65].into(),
            },
        ];
        assert_eq!(
            judge(
                &serde_json::to_vec(&stuffed).expect("serialize"),
                &name,
                hash
            ),
            Some(Reject::Stuffed)
        );
    }

    /// The whole correctness claim of the incremental pass: an `Ingest` that has judged a tree
    /// across several passes, with a mutation between each, ends exactly where a fresh one ends
    /// on the same final tree. The same-length rewrite is the case that fails if identity is
    /// keyed on the path or on the size, and the pass that spends `MAX_INGEST_FILES` is the case
    /// that fails if the budget is spent on skips instead of on work.
    #[test]
    fn incremental_and_full_validation_agree_on_the_same_tree() {
        let _env = HOME.lock();
        let a = home("hot_cheese_ingest_incremental_a");
        let b = std::env::temp_dir().join("hot_cheese_ingest_incremental_b");
        let _ = std::fs::remove_dir_all(&b);
        std::fs::create_dir_all(b.join("bundles")).expect("make the second home");
        let both = [&a, &b];

        let write = |rel: &str, bytes: &[u8]| {
            for root in both {
                std::fs::write(root.join("bundles").join(rel), bytes).expect("write a fixture");
            }
        };

        let mut dirs = Vec::new();
        for nonce in 0..66u64 {
            let seed = bundle(intent(nonce));
            let hash = seed_dir(&both, nonce);
            let bytes = serde_json::to_vec(&seed).expect("serialize");
            for filler in 0..62u8 {
                let name = Address::from([filler + 1; 20]);
                write(&format!("{hash}/{name:#x}{BUNDLE_SUFFIX}"), &bytes);
            }
            dirs.push((hash, seed));
        }

        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        let mut refused = Vec::new();
        let pass = |ingest: &mut Ingest, refused: &mut Vec<(String, Reject)>| {
            let verdict = ingest
                .validate(Scope::All, &HashSet::new())
                .expect("a pass over the test tree");
            refused.extend(refusals(&a, &verdict));
            verdict
        };

        assert!(
            pass(&mut ingest, &mut refused).capped,
            "66 × 63 files is past MAX_INGEST_FILES, so the priming pass leaves work behind"
        );
        assert!(
            !pass(&mut ingest, &mut refused).capped,
            "and the next pass finishes it, because a skip costs no budget"
        );

        let (hash, seed) = &dirs[0];
        let response = signed(0x11, seed);
        let signer = response.signer;
        let mut ours = SafeTxBundle {
            signatures: Vec::new(),
            ..seed.clone()
        };
        ours.add(CollectedSignature {
            signer,
            signature: response.signature,
        })
        .expect("our own signature over our own digest");
        write(
            &format!("{hash}/{signer:#x}{BUNDLE_SUFFIX}"),
            &serde_json::to_vec(&ours).expect("serialize"),
        );
        pass(&mut ingest, &mut refused);

        let corrupt = Address::from([1u8; 20]);
        write(
            &format!("{}/{corrupt:#x}{BUNDLE_SUFFIX}", dirs[1].0),
            b"{ not a bundle",
        );
        pass(&mut ingest, &mut refused);

        let stranger = Address::from([0x99u8; 20]);
        write(
            &format!("{}/{stranger:#x}{BUNDLE_SUFFIX}", dirs[2].0),
            &serde_json::to_vec(&ours).expect("serialize"),
        );
        pass(&mut ingest, &mut refused);

        let judged = a
            .join("bundles")
            .join(dirs[3].0.to_string())
            .join(format!("{corrupt:#x}{BUNDLE_SUFFIX}"));
        let same_length = vec![b'x'; std::fs::metadata(&judged).expect("stat it").len() as usize];
        write(
            &format!("{}/{corrupt:#x}{BUNDLE_SUFFIX}", dirs[3].0),
            &same_length,
        );
        pass(&mut ingest, &mut refused);

        for root in both {
            std::fs::remove_dir_all(root.join("bundles").join(dirs[4].0.to_string()))
                .expect("retire a bundle");
        }
        let settled = pass(&mut ingest, &mut refused);
        assert_eq!(
            settled.judged, 0,
            "a settled tree costs no recoveries at all"
        );
        assert_eq!(settled.dirs, 65);

        std::env::set_var("HOT_CHEESE_HOME", &b);
        let mut fresh = Ingest::new().expect("an empty quarantine tree");
        let mut full = Vec::new();
        loop {
            let verdict = fresh
                .validate(Scope::All, &HashSet::new())
                .expect("a full pass");
            full.extend(refusals(&b, &verdict));
            if !verdict.capped {
                break;
            }
        }

        refused.sort_by(|held, other| held.0.cmp(&other.0));
        full.sort_by(|held, other| held.0.cmp(&other.0));
        assert_eq!(refused, full, "the same files broke the same rules");
        assert_eq!(
            tree(&a.join("bundles")),
            tree(&b.join("bundles")),
            "several incremental passes leave the tree one full pass leaves"
        );
        assert_eq!(
            tree(&a.join("bundle-quarantine")),
            tree(&b.join("bundle-quarantine"))
        );
    }

    /// The priming asymmetry, which is the non-trivial half of the directory cap: getting it
    /// backwards deletes the operator's own bundles. A directory this device wrote into is never
    /// a peer's, whatever the cap says.
    #[test]
    fn only_a_directory_that_arrived_past_the_cap_is_refused() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_dir_cap");
        let held = [&root];
        for nonce in 0..(MAX_BUNDLE_DIRS as u64 + 1) {
            seed_dir(&held, nonce);
        }

        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        let verdict = ingest
            .validate(Scope::All, &HashSet::new())
            .expect("the priming pass");
        assert!(
            verdict.refused_dirs.is_empty(),
            "a tree already over the cap keeps every bundle the operator had"
        );
        assert_eq!(verdict.dirs, MAX_BUNDLE_DIRS + 1);

        let arrived = seed_dir(&held, 900);
        let verdict = ingest
            .validate(Scope::All, &HashSet::new())
            .expect("the pass that sees it arrive");
        assert_eq!(verdict.refused_dirs, vec![arrived]);
        assert!(!bundle_dir(arrived).exists());

        let mine = seed_dir(&held, 901);
        let verdict = ingest
            .validate(Scope::All, &HashSet::from_iter([mine]))
            .expect("the pass that sees our own");
        assert!(
            verdict.refused_dirs.is_empty(),
            "a bundle this device wrote into is never evicted by the cap"
        );
        assert!(bundle_dir(mine).is_dir());
    }

    /// Enforcing the per-bundle cap must not move a file this machine already had judged, which
    /// is as much of the "quarantine cannot eat your own signature" invariant as the cap leaves
    /// standing. The window it does NOT cover — a local write no pass has judged yet — is stated
    /// in this module's own doc and is not what this test claims.
    #[test]
    fn the_per_bundle_cap_keeps_the_seed_and_what_a_pass_already_judged() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_file_cap");
        let held = [&root];
        let seed = bundle(intent(7));
        let hash = seed_dir(&held, 7);
        let dir = bundle_dir(hash);
        let bytes = serde_json::to_vec(&seed).expect("serialize");

        let response = signed(0x11, &seed);
        let signer = response.signer;
        let mut ours = SafeTxBundle {
            signatures: Vec::new(),
            ..seed.clone()
        };
        ours.add(CollectedSignature {
            signer,
            signature: response.signature,
        })
        .expect("our own signature over our own digest");
        let mine = format!("{signer:#x}{BUNDLE_SUFFIX}");
        std::fs::write(
            dir.join(&mine),
            serde_json::to_vec(&ours).expect("serialize"),
        )
        .expect("write our own file");

        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        ingest
            .validate(Scope::All, &HashSet::new())
            .expect("the pass that puts our own file in seen");

        let flood = MAX_FILES_PER_BUNDLE + 8;
        for i in 0..flood {
            let name = format!("0x{:040x}{BUNDLE_SUFFIX}", i + 1);
            assert!(
                name < mine,
                "the flood must sort below our own file for this test to prove anything"
            );
            std::fs::write(dir.join(&name), &bytes).expect("write a peer's file");
        }

        let verdict = ingest
            .validate(Scope::All, &HashSet::new())
            .expect("the pass that enforces the cap");
        assert_eq!(verdict.crowded, vec![hash]);
        assert_eq!(verdict.refused_files, flood + 2 - MAX_FILES_PER_BUNDLE);
        assert!(dir.join(SEED_FILE).exists(), "the seed is kept first");
        assert!(
            dir.join(&mine).exists(),
            "then every file a pass has already judged"
        );
        assert_eq!(
            std::fs::read_dir(&dir).expect("read the dir").count(),
            MAX_FILES_PER_BUNDLE
        );
    }
}
