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
//! Nothing here DELETES a file this machine could have written. A refusal moves the file to the
//! quarantine tree, and only a file whose name is not one of this machine's own signer names is
//! ever dropped instead when that tree is full — so a signature the operator paid a biometric for
//! survives every ceiling in this module, including [`MAX_FILES_PER_BUNDLE`], where a peer that
//! floods a directory chooses which of ITS files leaves and never which of ours.
//!
//! Whose a directory is, is likewise read off the disk: [`Truth`] carries this machine's own
//! claims, so [`MAX_BUNDLE_DIRS`] and [`MAX_DIRS_PER_PEER`] bound peer-delivered directories and
//! nothing else, whichever entry point created the local one.
//!
//! Every ceiling here bounds WORK, never the pass itself. The quarantine tree is a ring that
//! [`Ingest::sweep`] reclaims from disk, so a peer that sends rubbish until the counter saturates
//! cannot make a crowded directory permanently unloadable; and [`MAX_DIRS_PER_PEER`] is the share
//! of the tree ONE peer holds at once, freed as its directories leave, rather than a per-pass
//! allowance it can spend again on the next tick.
use crate::{Scope, BUNDLE_SUFFIX, SEED_FILE};
use alloy_primitives::{Address, B256};
use err_mac::create_err_with_impls;
use hashbrown::{HashMap, HashSet};
use hc_core::config::{bundle_quarantine_dir, bundles_dir};
use hc_sign::bundle::SafeTxBundle;
use rand::RngCore;
use std::ffi::CString;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Largest file a pull may write, and the largest the validator will parse. A bundle is a
/// transaction's fields plus at most a handful of 65-byte signatures; 64 KiB is already
/// generous, and it is the same ceiling the daemon puts on a request body.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Files one bundle directory may hold: one seed plus every owner signature the bundle schema
/// accepts. The seed itself must not make a 64-owner Safe impossible to complete.
pub const MAX_FILES_PER_BUNDLE: usize = hc_sign::bundle::MAX_SIGNATURES + 1;

/// Files one validation pass JUDGES before it leaves the rest to the next one: a full admitted
/// tree, including every seed.
pub const MAX_INGEST_FILES: usize = 64 * MAX_FILES_PER_BUNDLE;

/// Bundle directories this machine will hold. Beyond it, a directory that ARRIVED is refused;
/// one that was already here is never touched. 64 × [`MAX_FILES_PER_BUNDLE`] is exactly
/// [`MAX_INGEST_FILES`], so a tree that has been under the cap from the start is covered by one
/// pass, and 64 is four times the review queue `mcp.max_pending` gives a human.
pub const MAX_BUNDLE_DIRS: usize = 64;

/// Directory slots ONE peer holds at once. A slot is spent when that peer's pull delivers a new
/// directory and freed when that directory leaves this machine, so it is a durable share of
/// [`MAX_BUNDLE_DIRS`] rather than an allowance a peer can spend again every pass: waiting for
/// more passes buys nothing. Everything past it is refused, which is also the only thing the
/// caller's flood backoff can see.
pub const MAX_DIRS_PER_PEER: usize = MAX_BUNDLE_DIRS / 4;

/// How long a bundle holding no signature keeps its (safe, chain, nonce) slot. A Safe executes
/// each nonce once, so a proposal nobody signed in a fortnight is holding a slot against every
/// later transaction for that nonce. It also bounds a directory whose signature files name a Safe
/// this machine cannot judge at all. Measured against the LOCAL clock: `created_at_ms` is
/// whatever a peer typed. A directory holding a signature for a Safe this machine DOES describe
/// never expires, and neither does one this machine claimed.
pub const PROPOSAL_TTL_MS: u64 = 14 * 24 * 60 * 60 * 1000;

/// How long a directory holding nothing but a seed for a Safe this `safes.toml` does not describe
/// keeps its slot. Nothing in it can become valid until the operator adds that Safe, and the peer
/// still has it: the pull after they do brings it straight back. It applies only to a machine
/// that describes some OTHER Safe, so a `safes.toml` that is simply absent expires nothing.
pub const UNKNOWN_SAFE_TTL_MS: u64 = 60 * 60 * 1000;

/// Files the quarantine tree holds before a rejected file is deleted instead of moved. 1024 ×
/// [`MAX_FILE_BYTES`] is a 64 MiB ceiling on what a flood can leave on this disk.
pub const MAX_QUARANTINE_FILES: usize = 1024;

/// How long a quarantined file is evidence before a sweep reclaims it.
pub const QUARANTINE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Files a sweep that has to make room leaves behind, so a flood pays one walk of the quarantine
/// tree per [`MAX_QUARANTINE_FILES`] − [`QUARANTINE_LOW_WATER`] refusals rather than one per
/// refusal.
const QUARANTINE_LOW_WATER: usize = MAX_QUARANTINE_FILES * 3 / 4;

/// How long a tree under its ceiling goes between sweeps, which is what bounds the life of a
/// quarantined file on a machine that is not being flooded.
const QUARANTINE_SWEEP_MS: u64 = 15 * 60 * 1000;

/// Directory entries a single filesystem enumeration may inspect. Valid peer traffic is capped
/// far below this before transfer; this larger ceiling preserves an operator's pre-existing tree
/// while preventing millions of irrelevant local names from pinning a validation pass.
pub(crate) const MAX_ENUMERATED_ENTRIES: usize = MAX_INGEST_FILES * 2;

create_err_with_impls!(
    #[derive(Debug)]
    pub IngestErr,
    StdIo(std::io::Error),
    Grant(hc_sign::grant::GrantErr)
    ;
    TooManyEntries { path: PathBuf, max: usize },
    NotOwnerControlled { path: PathBuf },
    NestedEntry { path: PathBuf },
    DirectoryChanged { path: PathBuf },
    NameHasNul { path: PathBuf },
    NoQuarantineName { path: PathBuf }
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
    /// Version or threshold outside the schema this build implements.
    Metadata,
}

/// Whether the file leaving the bundle tree is one this machine could have written, and therefore
/// what a full quarantine does about it: a local file evicts older evidence to make room, a
/// foreign one is simply dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// Written under a signer name this machine has never written a bundle file under.
    Foreign,
    /// This machine's own signer name, or a file the per-directory cap caught rather than a rule.
    Local,
}

/// What the validator did with a file it refused. Every refusal LEAVES the bundle directory:
/// leaving one behind is what made a crowded directory unloadable for as long as a peer kept the
/// quarantine tree full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposal {
    /// Moved under `<home>/bundle-quarantine/<digest>/`.
    Quarantined { to: PathBuf },
    /// Deleted, because the quarantine tree is full of evidence a sweep cannot yet reclaim and no
    /// local writer could have written this file.
    Deleted,
}

/// The LOCAL truth every directory in one pass is judged by, read as a unit so that no pass ever
/// runs on half of it.
pub struct Truth {
    /// The Safes this machine describes, which is who may sign and nothing a file says.
    safes: crate::Safes,
    /// Bundles this machine created, imported into or spent a biometric on; no cap, quota or
    /// expiry here ever removes one.
    ours: HashSet<B256>,
    /// Signer names this machine has itself written a bundle file under.
    signers: HashSet<Address>,
    /// Bundles this machine retired.
    retired: HashSet<B256>,
    /// The pass's own clock, read once, so every expiry in it measures from one instant.
    now_ms: u64,
}

impl Truth {
    /// Read every local fact one pass judges by. A failure is a refusal and never a default: a
    /// pass that ran without this would quarantine, refuse and expire against truth it does not
    /// have, and an empty `safes.toml` substituted for a broken one makes every fully-signed
    /// bundle on the disk look unknown, unsigned and expired.
    ///
    /// A `safes.toml` that is ABSENT is not a failure — it is a machine that describes no Safe —
    /// and [`Ingest::validate`] expires nothing on the unknown-Safe ground when there is no Safe
    /// to be unknown against.
    pub fn load() -> Result<Self, crate::BundleErr> {
        let safes = match crate::Safes::load() {
            Ok(safes) => safes,
            Err(crate::BundleErr::NoSafesFile { path }) => {
                tracing::debug!(path = %path.display(), "this machine describes no Safe");
                crate::Safes::default()
            }
            Err(error) => return Err(error),
        };
        Ok(Truth {
            safes,
            ours: crate::local::ours()?,
            signers: crate::local::signers()?,
            retired: crate::local::retired()?,
            now_ms: hc_sign::grant::now_ms()?,
        })
    }

    /// How this machine would refuse a file filed under `name`: a signer name it has written a
    /// bundle file under is its own work, whatever a later `safes.toml` says about that owner.
    fn refusal(&self, name: &str) -> Refusal {
        match owner_of(name) {
            Ok(Some(signer)) if self.signers.contains(&signer) => Refusal::Local,
            _ => Refusal::Foreign,
        }
    }
}

/// What judging one bundle directory left behind.
enum Judged {
    /// The files it holds now, by name.
    Held(HashMap<String, FileId>),
    /// The directory is gone: an arrival whose every file was refused, or a proposal past
    /// [`PROPOSAL_TTL_MS`].
    Reclaimed,
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
    /// Bundle directories removed whole for arriving past [`MAX_BUNDLE_DIRS`] or the delivering
    /// peer's [`MAX_DIRS_PER_PEER`].
    pub refused_dirs: Vec<B256>,
    /// Bundle directories removed because this machine retired them, or because a proposal
    /// outlived [`PROPOSAL_TTL_MS`] — [`UNKNOWN_SAFE_TTL_MS`] when it holds only a seed for a
    /// Safe this machine does not describe.
    pub retired: Vec<B256>,
    /// Bundle directories this pass could not judge and left for the next one; one broken
    /// directory costs itself and nothing else.
    pub skipped: Vec<B256>,
    /// Files quarantined for pushing a directory past [`MAX_FILES_PER_BUNDLE`].
    pub refused_files: usize,
    /// Files this pass judged: the ones whose local identity had moved since the last one.
    pub judged: usize,
    /// True when the pass spent [`MAX_INGEST_FILES`] and left the rest for the next one.
    pub capped: bool,
    /// The accepted tree changed, including a file or directory disappearing without any new
    /// bytes needing judgment. Long-lived callers use this to invalidate their merged view.
    pub changed: bool,
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

/// What a directory over its file cap keeps, worst last. This machine's own signer names rank
/// above anything a pass has merely judged, so a peer that floods a directory with names sorting
/// below ours cannot push a local signature no pass has seen yet out of it.
fn retention_priority<'a>(
    candidate: &'a str,
    held: &HashMap<String, FileId>,
    truth: &Truth,
) -> (u8, &'a str) {
    let rank = match candidate {
        SEED_FILE => 0,
        mine if truth.refusal(mine) == Refusal::Local => 1,
        judged if held.contains_key(judged) => 2,
        canonical if owner_of(canonical).is_ok() => 3,
        _ => 4,
    };
    (rank, candidate)
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
    /// The peer whose pull each directory first appeared in, which is what bounds that peer's
    /// share of [`MAX_BUNDLE_DIRS`] across every later pass.
    from: HashMap<B256, String>,
    /// False until the first whole-tree pass has taken stock of what was already here.
    primed: bool,
    /// Files the last sweep counted in the quarantine tree.
    quarantined: usize,
    /// Local clock at that sweep.
    swept_at_ms: u64,
}

/// Who a pass credits the directories that appeared since the last one to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered<'a> {
    /// A pull from this ssh target just ran, so a directory that is new is that peer's and spends
    /// its share of [`MAX_DIRS_PER_PEER`].
    By(&'a str),
    /// No transfer ran: priming, or a pass another local process's writes landed in.
    Locally,
}

/// The bundle directories `scope` covers, in digest order. A directory whose name is not a
/// digest is not a bundle and is not judged: `load_all` already ignores it, so it cannot
/// poison anything, and moving a stray a human left there would be the tool losing their work.
fn dirs(scope: Scope) -> Result<Vec<(B256, PathBuf)>, IngestErr> {
    let root = bundles_dir();
    if let Scope::One(hash) = scope {
        let dir = root.join(hash.to_string());
        if !crate::owned_directory_exists(&dir)? {
            return Ok(Vec::new());
        }
        return Ok(vec![(hash, dir)]);
    }
    let mut out = Vec::new();
    if !crate::owned_directory_exists(&root)? {
        return Ok(out);
    }
    for (at, entry) in std::fs::read_dir(&root)?.enumerate() {
        if at >= MAX_ENUMERATED_ENTRIES {
            return Err(IngestErr::TooManyEntries {
                path: root,
                max: MAX_ENUMERATED_ENTRIES,
            });
        }
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(hash) = crate::canonical_bundle_hash(&entry.file_name()) else {
            continue;
        };
        match crate::owned_directory_exists(&entry.path()) {
            Ok(true) => out.push((hash, entry.path())),
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!(%hash, %error, "skipping a bundle directory this pass cannot open")
            }
        }
    }
    out.sort_by_key(|(hash, _)| *hash);
    Ok(out)
}

/// Remove a bundle directory and every FLAT file in it — the canonical ones and the rsync temp
/// artefacts a force-killed transfer leaves behind, which are exactly what otherwise makes this
/// cleanup fail forever. The directory descriptor binds deletion to the inode we inspected.
///
/// Nothing nested is ever erased, or even opened: a directory, symlink or device under a bundle
/// pathname is not bundle state, and this refuses to remove the directory that holds it and names
/// it. The flat files still go, so the bundle stops being a bundle — a retirement that could
/// remove NOTHING because someone left a folder there is how a slot came to be held for ever with
/// no way for the operator to give it up.
pub(crate) fn remove_flat_directory(dir: &Path) -> Result<(), IngestErr> {
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)?;
    let identity = directory.metadata()?;
    // SAFETY: `geteuid` has no preconditions and changes no process state.
    let ours = unsafe { libc::geteuid() };
    if !identity.file_type().is_dir() || identity.uid() != ours {
        return Err(IngestErr::NotOwnerControlled {
            path: dir.to_path_buf(),
        });
    }

    let mut names = Vec::new();
    let mut nested = None;
    for (at, entry) in std::fs::read_dir(dir)?.enumerate() {
        if at >= MAX_ENUMERATED_ENTRIES {
            return Err(IngestErr::TooManyEntries {
                path: dir.to_path_buf(),
                max: MAX_ENUMERATED_ENTRIES,
            });
        }
        let entry = entry?;
        let name = entry.file_name();
        if !entry.file_type()?.is_file() {
            nested = Some(entry.path());
            continue;
        }
        names.push(name);
    }

    let current = std::fs::symlink_metadata(dir)?;
    if !current.file_type().is_dir()
        || current.dev() != identity.dev()
        || current.ino() != identity.ino()
    {
        return Err(IngestErr::DirectoryChanged {
            path: dir.to_path_buf(),
        });
    }

    for name in names {
        let Ok(name) = CString::new(name.as_bytes()) else {
            return Err(IngestErr::NameHasNul {
                path: dir.join(name),
            });
        };
        // SAFETY: the descriptor and NUL-terminated basename remain live, the validated name
        // has no slash, and flags=0 refuses to unlink a directory.
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    directory.sync_all()?;
    drop(directory);
    if let Some(path) = nested {
        return Err(IngestErr::NestedEntry { path });
    }

    let current = std::fs::symlink_metadata(dir)?;
    if !current.file_type().is_dir()
        || current.dev() != identity.dev()
        || current.ino() != identity.ino()
    {
        return Err(IngestErr::DirectoryChanged {
            path: dir.to_path_buf(),
        });
    }
    std::fs::remove_dir(dir)?;
    Ok(())
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
        Some(address) if name == format!("{address:#x}{BUNDLE_SUFFIX}") => Ok(Some(address)),
        None => Err(Reject::Name),
        Some(_) => Err(Reject::Name),
    }
}

/// What judging one file concluded.
#[derive(Debug, PartialEq, Eq)]
enum Ruling {
    /// The union may take it.
    Take,
    /// It breaks a rule no local writer can break.
    Refuse(Reject),
    /// This machine does not describe the Safe it names, so there is nothing to judge its
    /// signature against. Left exactly where it is: the operator who adds that Safe to
    /// `safes.toml` gets it judged at the next pass, and nothing here is destroyed meanwhile.
    Unknown,
}

/// Judge one file's bytes against LOCAL truth. Every check is one this machine's own writes
/// satisfy by construction, so a ruling is never a ruling on our own signature.
///
/// `threshold` and `created_at_ms` are NOT covered by `safeTxHash`, so a peer chooses both, and
/// neither is a reason to refuse a file: the local `safes.toml` states the threshold, and
/// [`crate::load_dir`] normalises what a file carries before it merges. Only the schema's own
/// bounds are checked here, because a value outside them is one `SafeTxBundle::validate` refuses
/// later. Who may sign is local truth too, and it comes from `safes.toml` and nowhere else.
fn judge(bytes: &[u8], name: &str, hash: B256, safes: &crate::Safes) -> Ruling {
    let owner = match owner_of(name) {
        Ok(owner) => owner,
        Err(reject) => return Ruling::Refuse(reject),
    };
    let Ok(bundle) = hc_core::wire::strict_json_from_slice::<SafeTxBundle>(bytes) else {
        return Ruling::Refuse(Reject::Parse);
    };
    if bundle.digest() != hash {
        return Ruling::Refuse(Reject::Digest);
    }
    if bundle.v != hc_sign::bundle::V
        || bundle.threshold == 0
        || usize::from(bundle.threshold) > hc_sign::bundle::MAX_SIGNATURES
    {
        return Ruling::Refuse(Reject::Metadata);
    }
    match owner {
        None if !bundle.signatures.is_empty() => return Ruling::Refuse(Reject::Misfiled),
        Some(_) if bundle.signatures.is_empty() => return Ruling::Refuse(Reject::Misfiled),
        Some(_) if bundle.signatures.len() > 1 => return Ruling::Refuse(Reject::Stuffed),
        _ => {}
    }
    for sig in &bundle.signatures {
        if owner != Some(sig.signer) {
            return Ruling::Refuse(Reject::Misfiled);
        }
    }
    let Ok(safe) = safes.find(bundle.intent.safe, bundle.intent.chain_id) else {
        return Ruling::Unknown;
    };
    // Keep this boundary aligned with `load_dir`: anything ingestion marks as seen must be a
    // bundle the loader will accept later. Besides recovering every signature against the Safe's
    // local owner list, `validate` checks canonical order and all coordination ceilings.
    if bundle.validate(&safe.owners).is_err() {
        return Ruling::Refuse(Reject::Signature);
    }
    Ruling::Take
}

/// Milliseconds since this machine's kernel stamped the directory's inode, which is when the
/// directory arrived HERE. A peer chooses `created_at_ms`; it does not choose this.
pub(crate) fn local_age_ms(dir: &Path, now_ms: u64) -> Result<u64, IngestErr> {
    let meta = std::fs::symlink_metadata(dir)?;
    let stamped = meta
        .ctime()
        .saturating_mul(1000)
        .saturating_add(meta.ctime_nsec() / 1_000_000);
    let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
    Ok(u64::try_from(now.saturating_sub(stamped)).unwrap_or(0))
}

impl Ingest {
    /// Prime from the tree that is already here. Nothing has ARRIVED until a pass has taken
    /// stock, and the quarantine tree is swept once so a restart also reclaims whatever the last
    /// run left past [`QUARANTINE_TTL_MS`] or beside a bundle directory that is gone.
    pub fn new() -> Result<Self, IngestErr> {
        let mut ingest = Ingest {
            seen: HashMap::new(),
            from: HashMap::new(),
            primed: false,
            quarantined: 0,
            swept_at_ms: 0,
        };
        ingest.sweep(hc_sign::grant::now_ms()?, false)?;
        Ok(ingest)
    }

    /// Reclaim the quarantine tree and recount it from what is on disk, which is what keeps
    /// [`MAX_QUARANTINE_FILES`] a ceiling rather than a latch: a counter that only ever grew is
    /// what let a peer send rubbish until a crowded directory could never be repaired again.
    /// Evidence past [`QUARANTINE_TTL_MS`], and evidence whose bundle directory is gone, is
    /// dropped; `room` then evicts oldest-first down to [`QUARANTINE_LOW_WATER`] so a refusal that
    /// can touch a local file always has somewhere to go. Age is the local kernel's `ctime`, which
    /// a peer does not choose.
    fn sweep(&mut self, now_ms: u64, room: bool) -> Result<(), IngestErr> {
        let root = bundle_quarantine_dir();
        self.swept_at_ms = now_ms;
        self.quarantined = 0;
        if let Err(error) = crate::local::reclaim(now_ms) {
            tracing::warn!(%error, "cannot reclaim the local facts this machine is done with");
        }
        if !crate::owned_directory_exists(&root)? {
            return Ok(());
        }
        crate::ensure_owned_directory(&root)?;
        let expired = i64::try_from(now_ms.saturating_sub(QUARANTINE_TTL_MS)).unwrap_or(i64::MAX);
        let mut held: Vec<(i64, PathBuf)> = Vec::new();
        let mut doomed: Vec<PathBuf> = Vec::new();
        let mut emptied: Vec<PathBuf> = Vec::new();
        let mut scanned = 0usize;
        for entry in std::fs::read_dir(&root)? {
            scanned += 1;
            if scanned > MAX_ENUMERATED_ENTRIES {
                return Err(IngestErr::TooManyEntries {
                    path: root,
                    max: MAX_ENUMERATED_ENTRIES,
                });
            }
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let orphan = match crate::canonical_bundle_hash(&entry.file_name()) {
                Some(hash) => !matches!(
                    crate::owned_directory_exists(&crate::bundle_dir(hash)),
                    Ok(true)
                ),
                None => true,
            };
            emptied.push(entry.path());
            for file in std::fs::read_dir(entry.path())? {
                scanned += 1;
                if scanned > MAX_ENUMERATED_ENTRIES {
                    return Err(IngestErr::TooManyEntries {
                        path: root,
                        max: MAX_ENUMERATED_ENTRIES,
                    });
                }
                let file = file?;
                if !file.file_type()?.is_file() {
                    continue;
                }
                let meta = file.metadata()?;
                let stamped = meta
                    .ctime()
                    .saturating_mul(1000)
                    .saturating_add(meta.ctime_nsec() / 1_000_000);
                match orphan || stamped < expired {
                    true => doomed.push(file.path()),
                    false => held.push((stamped, file.path())),
                }
            }
        }
        if room && held.len() > QUARANTINE_LOW_WATER {
            held.sort();
            let evict = held.len() - QUARANTINE_LOW_WATER;
            for (_, path) in held.drain(..evict) {
                doomed.push(path);
            }
        }
        let reclaimed = doomed.len();
        for path in doomed {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        for path in emptied {
            match std::fs::remove_dir(&path) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.quarantined = held.len();
        if reclaimed > 0 {
            tracing::info!(
                reclaimed,
                holding = self.quarantined,
                "reclaimed quarantined files"
            );
        }
        Ok(())
    }

    /// Whether a directory is one a peer just created. A bundle this machine claimed is never
    /// one, which is what keeps [`MAX_BUNDLE_DIRS`] and [`MAX_DIRS_PER_PEER`] from deleting the
    /// operator's own new bundle, and before the priming pass nothing has arrived at all.
    fn arrived(&self, hash: B256, truth: &Truth) -> bool {
        self.primed && !self.seen.contains_key(&hash) && !truth.ours.contains(&hash)
    }

    /// Take a refused file out of the tree: to the quarantine dir, or deleted when that tree is
    /// full of evidence no sweep can reclaim yet AND no writer here could have produced the file.
    /// A [`Refusal::Local`] file sweeps for room instead, because it is either this machine's own
    /// signature or a file whose absence is what puts its directory back under
    /// [`MAX_FILES_PER_BUNDLE`], and neither may be destroyed to make a ceiling hold.
    fn dispose(
        &mut self,
        from: &Path,
        name: &str,
        hash: B256,
        refusal: Refusal,
        now: u64,
    ) -> Result<Disposal, IngestErr> {
        let dir = bundle_quarantine_dir().join(hash.to_string());
        let full = self.quarantined >= MAX_QUARANTINE_FILES;
        if full || now.saturating_sub(self.swept_at_ms) >= QUARANTINE_SWEEP_MS {
            self.sweep(now, full && refusal == Refusal::Local)?;
        }
        if self.quarantined >= MAX_QUARANTINE_FILES {
            std::fs::remove_file(from)?;
            return Ok(Disposal::Deleted);
        }

        for private in [bundle_quarantine_dir(), dir.clone()] {
            crate::ensure_owned_directory(&private)?;
        }

        // Preserve an earlier rejection with the same name. `hard_link` is an atomic
        // create-if-absent on this same-home filesystem, unlike rename which overwrites.
        for attempt in 0..8 {
            let to = if attempt == 0 {
                dir.join(name)
            } else {
                let mut random = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut random);
                dir.join(format!("rejected-{:032x}", u128::from_be_bytes(random)))
            };
            match std::fs::hard_link(from, &to) {
                Ok(()) => {
                    self.quarantined += 1;
                    std::fs::remove_file(from)?;
                    return Ok(Disposal::Quarantined { to });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(IngestErr::NoQuarantineName { path: dir })
    }
}

impl Ingest {
    /// Judge everything `scope` covers against [`Truth`], quarantining what would poison a union
    /// and reading nothing whose local identity has not moved since the last pass. Sorted at
    /// every level so two runs over the same tree do the same thing in the same order.
    ///
    /// A directory this pass cannot judge is skipped, not fatal: one killed transfer must not
    /// deny service for every other bundle, and refusing every peer forever is what an aborted
    /// pass costs. There is no pass without truth: the caller loads it, and a load that failed
    /// never reaches here.
    ///
    /// [`MAX_INGEST_FILES`] bounds the files one pass JUDGES, never the names it reaches: a
    /// budget spent on skips would be spent re-reaching the same sorted prefix every pass, and
    /// the suffix past it — which a peer aims at by choosing a low digest — would never be
    /// judged at all.
    ///
    /// `from` names the peer whose pull this pass follows. What that peer already holds is
    /// counted before anything new is admitted, so its [`MAX_DIRS_PER_PEER`] share cannot be
    /// spent twice by waiting for the next pass.
    pub fn validate(
        &mut self,
        scope: Scope,
        truth: &Truth,
        from: Delivered<'_>,
    ) -> Result<Verdict, IngestErr> {
        let entries = dirs(scope)?;
        if scope == Scope::All {
            let mut present = HashSet::with_capacity(entries.len());
            for (hash, _) in &entries {
                present.insert(*hash);
            }
            self.from.retain(|hash, _| present.contains(hash));
        }
        let mut verdict = Verdict {
            dirs: entries.len(),
            ..Verdict::default()
        };
        let mut kept = 0usize;
        for (hash, _) in &entries {
            if !self.arrived(*hash, truth) {
                kept += 1;
            }
        }
        let mut spent = 0usize;
        if let Delivered::By(host) = from {
            for peer in self.from.values() {
                if peer == host {
                    spent += 1;
                }
            }
        }
        let mut pass: HashMap<B256, HashMap<String, FileId>> = HashMap::new();
        for (hash, dir) in entries {
            let arrived = self.arrived(hash, truth);
            if truth.retired.contains(&hash) && !truth.ours.contains(&hash) {
                match remove_flat_directory(&dir) {
                    Ok(()) => {
                        verdict.retired.push(hash);
                        verdict.dirs -= 1;
                        verdict.changed |= self.seen.remove(&hash).is_some();
                        if !arrived {
                            kept -= 1;
                        }
                        if let Err(error) = crate::local::renew(hash) {
                            tracing::warn!(%hash, %error, "cannot restamp a retirement this pass enforced");
                        }
                        tracing::info!(%hash, "removed a bundle this machine retired");
                    }
                    Err(error) => {
                        tracing::warn!(%hash, %error, "cannot remove a bundle this machine retired");
                        verdict.skipped.push(hash);
                    }
                }
                continue;
            }
            if arrived {
                if kept >= MAX_BUNDLE_DIRS || spent >= MAX_DIRS_PER_PEER {
                    match remove_flat_directory(&dir) {
                        Ok(()) => {
                            verdict.refused_dirs.push(hash);
                            verdict.dirs -= 1;
                        }
                        Err(error) => {
                            tracing::warn!(%hash, %error, "cannot remove an over-cap arrival");
                            verdict.skipped.push(hash);
                        }
                    }
                    continue;
                }
                if let Delivered::By(host) = from {
                    self.from.insert(hash, host.to_string());
                    spent += 1;
                }
                kept += 1;
            }
            match self.judge_dir(hash, &dir, arrived, truth, &mut verdict) {
                Ok(Judged::Held(fresh)) => {
                    pass.insert(hash, fresh);
                }
                Ok(Judged::Reclaimed) => {
                    verdict.dirs -= 1;
                    kept -= 1;
                }
                Err(error) => {
                    tracing::warn!(%hash, %error, "skipping a bundle directory this pass cannot judge");
                    verdict.skipped.push(hash);
                    verdict.changed = true;
                }
            }
        }
        match scope {
            Scope::All => {
                if !self.seen.is_empty() {
                    verdict.changed = true;
                }
                self.seen = pass;
                self.primed = true;
            }
            Scope::One(hash) => {
                if let Some(files) = pass.remove(&hash) {
                    self.seen.insert(hash, files);
                } else if self.seen.remove(&hash).is_some() {
                    verdict.changed = true;
                }
            }
        }
        Ok(verdict)
    }

    /// Judge one directory, taking every file it holds on its own terms. A name that came out of
    /// `read_dir` and will not open, stat or read is a transfer racing this pass, so it is left
    /// for the next one rather than judged on bytes this pass does not have, and it still counts
    /// as a signature the expiry below must not destroy. A proposal is only expired by a pass that
    /// had the budget to see every file it holds.
    ///
    /// An arrival whose every file was refused is reclaimed empty: the files leave for quarantine,
    /// and one invalid canonical file per fresh digest would otherwise let a peer hold every
    /// directory slot with shells. A concurrent local write makes that `remove_dir` fail with
    /// `DirectoryNotEmpty`, and the next pass accounts for the directory instead.
    fn judge_dir(
        &mut self,
        hash: B256,
        dir: &Path,
        arrived: bool,
        truth: &Truth,
        verdict: &mut Verdict,
    ) -> Result<Judged, IngestErr> {
        let held = self.seen.remove(&hash).unwrap_or_default();
        let mut fresh = HashMap::new();
        let mut names = Vec::with_capacity(MAX_FILES_PER_BUNDLE);
        let mut found = 0usize;
        for (at, entry) in std::fs::read_dir(dir)?.enumerate() {
            if at >= MAX_ENUMERATED_ENTRIES {
                return Err(IngestErr::TooManyEntries {
                    path: dir.to_path_buf(),
                    max: MAX_ENUMERATED_ENTRIES,
                });
            }
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // Judge every regular file, not only a name ending in `.json`. Besides making
            // `Reject::Name` effective for the complete directory, this collects rsync temp
            // files left by a force-killed transfer instead of letting repeated failures grow
            // an ignored, unbounded side tree.
            if entry.file_type()?.is_file() {
                found = found.saturating_add(1);
                if names.len() < MAX_FILES_PER_BUNDLE {
                    names.push(name);
                    continue;
                }
                if found == MAX_FILES_PER_BUNDLE + 1 {
                    verdict.crowded.push(hash);
                }
                let worst = names
                    .iter()
                    .enumerate()
                    .max_by(|(_, a), (_, b)| {
                        retention_priority(a, &held, truth)
                            .cmp(&retention_priority(b, &held, truth))
                    })
                    .map(|(at, _)| at)
                    .unwrap_or(0);
                let refused = if retention_priority(&name, &held, truth)
                    < retention_priority(&names[worst], &held, truth)
                {
                    std::mem::replace(&mut names[worst], name)
                } else {
                    name
                };
                let from = dir.join(&refused);
                let disposal = self.dispose(&from, &refused, hash, Refusal::Local, truth.now_ms)?;
                tracing::debug!(file = %from.display(), ?disposal, "a bundle directory is over its file cap");
                verdict.refused_files += 1;
            }
        }
        names.sort_by(|a, b| {
            let a_seed = a == SEED_FILE;
            let b_seed = b == SEED_FILE;
            b_seed.cmp(&a_seed).then_with(|| a.cmp(b))
        });
        let mut signed = false;
        let mut unknown = false;
        for name in names {
            let from = dir.join(&name);
            let bears_signature = matches!(owner_of(&name), Ok(Some(_)));
            let file = match hc_core::open_regular_file(&from) {
                Ok(file) => file,
                Err(error) => {
                    tracing::warn!(file = %from.display(), %error, "skipping a bundle file this pass cannot open");
                    signed |= bears_signature;
                    continue;
                }
            };
            let meta = match file.metadata() {
                Ok(meta) => meta,
                Err(error) => {
                    tracing::warn!(file = %from.display(), %error, "skipping a bundle file this pass cannot stat");
                    signed |= bears_signature;
                    continue;
                }
            };
            let id = FileId {
                ino: meta.ino(),
                ctime: meta.ctime(),
                ctime_nsec: meta.ctime_nsec(),
                len: meta.size(),
            };
            if held.get(&name) == Some(&id) {
                signed |= bears_signature;
                fresh.insert(name, id);
                continue;
            }
            if verdict.judged >= MAX_INGEST_FILES {
                verdict.capped = true;
                signed |= bears_signature;
                continue;
            }
            verdict.judged += 1;
            let ruling = match id.len > MAX_FILE_BYTES {
                true => Ruling::Refuse(Reject::Size),
                false => {
                    let mut bytes = Vec::with_capacity(id.len as usize);
                    if let Err(error) = file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes) {
                        tracing::warn!(file = %from.display(), %error, "skipping a bundle file this pass cannot read");
                        signed |= bears_signature;
                        continue;
                    }
                    if bytes.len() as u64 > MAX_FILE_BYTES {
                        Ruling::Refuse(Reject::Size)
                    } else {
                        judge(&bytes, &name, hash, &truth.safes)
                    }
                }
            };
            let reject = match ruling {
                Ruling::Take => {
                    signed |= bears_signature;
                    fresh.insert(name, id);
                    continue;
                }
                Ruling::Unknown => {
                    unknown = true;
                    signed |= bears_signature;
                    tracing::debug!(file = %from.display(), "this machine does not describe the Safe this bundle names");
                    continue;
                }
                Ruling::Refuse(reject) => reject,
            };
            let disposal = self.dispose(&from, &name, hash, truth.refusal(&name), truth.now_ms)?;
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
        if held != fresh {
            verdict.changed = true;
        }
        if arrived && fresh.is_empty() {
            match std::fs::remove_dir(dir) {
                Ok(()) => return Ok(Judged::Reclaimed),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Judged::Reclaimed)
                }
                Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                Err(error) => return Err(error.into()),
            }
        }
        let ttl = match (signed, unknown) {
            (true, false) => None,
            (false, true) if !truth.safes.safe.is_empty() => Some(UNKNOWN_SAFE_TTL_MS),
            _ => Some(PROPOSAL_TTL_MS),
        };
        let Some(ttl) = ttl else {
            return Ok(Judged::Held(fresh));
        };
        if !verdict.capped && !truth.ours.contains(&hash) && local_age_ms(dir, truth.now_ms)? > ttl
        {
            remove_flat_directory(dir)?;
            verdict.retired.push(hash);
            verdict.changed = true;
            tracing::warn!(%hash, unknown, signed, "removed a proposal whose slot expired");
            return Ok(Judged::Reclaimed);
        }
        Ok(Judged::Held(fresh))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle_dir;
    use crate::tests::{bundle, home, intent, signed, HOME};
    use hc_sign::bundle::CollectedSignature;

    /// Every fixture key these tests sign with, as the Safe's owner list.
    fn all_owners() -> Vec<u8> {
        (1..=64u8).collect()
    }

    /// The local truth of one pass, as [`judge`] takes it.
    fn safes(threshold: u8, seeds: impl IntoIterator<Item = u8>) -> crate::Safes {
        toml::from_str(&crate::tests::safes_toml(threshold, seeds)).expect("the fixture parses")
    }

    /// Every local fact of the home this test set up, as every entry point reads it.
    fn truth() -> Truth {
        Truth::load().expect("this test's own local truth")
    }

    fn now() -> u64 {
        hc_sign::grant::now_ms().expect("the local clock")
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

    /// The four ways a peer can hand us bytes that break the union, and the two ways they
    /// cannot: a file this machine would itself have written is always accepted, and coordination
    /// metadata a peer chose is never grounds for refusing a valid signature. Corrupt bytes, a
    /// bundle for another transaction, a signature that recovers to nobody, and a real signature
    /// filed under someone else's name are each refused on their own terms.
    #[test]
    fn a_hostile_peer_cannot_get_a_file_past_the_validator() {
        let local = safes(2, [0x11, 0x22]);
        let owners = crate::tests::owners_of([0x11, 0x22]);
        let held = bundle(intent(3));
        let hash = held.digest();
        let response = signed(0x11, &held);
        let signer = response.signer;
        let mut ours = held.clone();
        ours.add(
            CollectedSignature {
                signer,
                signature: response.signature,
            },
            &owners,
        )
        .expect("our own signature");
        let good = format!("{signer:#x}{BUNDLE_SUFFIX}");
        let bytes = |b: &SafeTxBundle| serde_json::to_vec(b).expect("serialize");

        assert_eq!(
            judge(&bytes(&ours), &good, hash, &local),
            Ruling::Take,
            "what this machine writes is what the validator accepts"
        );
        assert_eq!(judge(&bytes(&held), SEED_FILE, hash, &local), Ruling::Take);
        assert_eq!(
            judge(b"{ not json", "junk.json", hash, &local),
            Ruling::Refuse(Reject::Name),
            "a name outside the layout is refused before its bytes matter"
        );
        assert_eq!(
            judge(b"{ not a bundle", &good, hash, &local),
            Ruling::Refuse(Reject::Parse)
        );
        assert_eq!(
            judge(&bytes(&bundle(intent(4))), &good, hash, &local),
            Ruling::Refuse(Reject::Digest),
            "a bundle for another transaction does not belong to this directory"
        );

        let mut forged = ours.clone();
        forged.signatures[0].signature = vec![0x7u8; 65].into();
        assert_eq!(
            judge(&bytes(&forged), &good, hash, &local),
            Ruling::Refuse(Reject::Signature),
            "a signature that recovers to nobody is refused"
        );

        let stranger = format!("{:#x}{BUNDLE_SUFFIX}", Address::from([0x99u8; 20]));
        assert_eq!(
            judge(&bytes(&ours), &stranger, hash, &local),
            Ruling::Refuse(Reject::Misfiled),
            "one file per signer means the name binds the contents"
        );
        assert_eq!(
            judge(&bytes(&ours), SEED_FILE, hash, &local),
            Ruling::Refuse(Reject::Misfiled),
            "the seed carries no signature, so a signature hidden in it is misfiled"
        );

        let mut lowered = ours.clone();
        lowered.threshold = 1;
        lowered.created_at_ms = 1;
        assert_eq!(
            judge(&bytes(&lowered), &good, hash, &local),
            Ruling::Take,
            "coordination a peer chose cannot make a valid signature refusable"
        );

        let mut impossible = held.clone();
        impossible.threshold = u8::MAX;
        assert_eq!(
            judge(&bytes(&impossible), SEED_FILE, hash, &local),
            Ruling::Refuse(Reject::Metadata),
            "ingestion must not accept a bundle the loader rejects later"
        );

        let elsewhere = safes(2, [0x33]);
        assert_eq!(
            judge(&bytes(&ours), &good, hash, &elsewhere),
            Ruling::Refuse(Reject::Signature),
            "who may sign is the local owner list and nothing the file says"
        );
    }

    #[test]
    fn an_interrupted_rsync_temp_file_is_quarantined_instead_of_accumulating() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_rsync_temp", 2, [0x11, 0x22]);
        let hash = seed_dir(&[&root], 91);
        let temp = bundle_dir(hash).join(".unsigned.json.rsync-partial");
        std::fs::write(&temp, b"partial peer bytes").expect("leave an rsync temp file");

        let mut ingest = Ingest::new().expect("start validator");
        let verdict = ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("judge the bundle tree");

        assert!(verdict
            .rejected
            .iter()
            .any(|rejected| rejected.from == temp && rejected.reject == Reject::Name));
        assert!(
            !temp.exists(),
            "the ignored temp file cannot grow across pulls"
        );
        assert!(tree(&root.join("bundle-quarantine"))
            .iter()
            .any(|(_, bytes)| bytes == b"partial peer bytes"));

        std::fs::remove_dir_all(root).unwrap();
    }

    /// Quarantine is evidence, so rejecting the same peer-controlled name twice must preserve
    /// both byte strings. The second move gets a fresh create-only name instead of replacing the
    /// first refusal at its predictable destination.
    #[test]
    fn quarantine_name_collisions_preserve_both_rejections() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_quarantine_collision", 2, [0x11, 0x22]);
        let hash = B256::from([0x42; 32]);
        let source_dir = root.join("bundles").join(hash.to_string());
        std::fs::create_dir(&source_dir).expect("make the source directory");
        let source = source_dir.join("junk.json");
        std::fs::write(&source, b"second rejection").expect("write the new refusal");

        let quarantine = root.join("bundle-quarantine").join(hash.to_string());
        std::fs::create_dir_all(&quarantine).expect("make an existing quarantine directory");
        let earlier = quarantine.join("junk.json");
        std::fs::write(&earlier, b"first rejection").expect("write earlier evidence");

        let mut ingest = Ingest::new().expect("count the existing quarantine");
        let disposal = ingest
            .dispose(&source, "junk.json", hash, Refusal::Foreign, now())
            .expect("quarantine the colliding refusal");
        let Disposal::Quarantined { to } = disposal else {
            panic!("a non-full quarantine must retain the refusal");
        };

        assert_ne!(to, earlier);
        assert_eq!(std::fs::read(earlier).unwrap(), b"first rejection");
        assert_eq!(std::fs::read(to).unwrap(), b"second rejection");
        assert!(!source.exists());
    }

    /// A quarantine that is genuinely full drops a judged-invalid newcomer and keeps the evidence
    /// it already holds — but a refusal that can touch a LOCAL file must never be left in its
    /// bundle directory, because that directory then holds more than `load_dir` will read and
    /// nothing can load it again for as long as a peer keeps sending rubbish. The full tree makes
    /// room for that one instead, and the ring drops to its low-water mark, so the flood pays for
    /// one directory walk rather than one per refusal.
    #[test]
    fn a_full_quarantine_makes_room_rather_than_wedging_a_directory() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_full_quarantine", 2, [0x11, 0x22]);
        let hash = B256::from([0x43; 32]);
        let source_dir = root.join("bundles").join(hash.to_string());
        std::fs::create_dir(&source_dir).expect("make the source directory");
        for at in 0..MAX_QUARANTINE_FILES {
            let evidence = root
                .join("bundle-quarantine")
                .join(B256::from([0x43; 32]).to_string());
            std::fs::create_dir_all(&evidence).expect("make the quarantine directory");
            std::fs::write(evidence.join(format!("rejected-{at:04}")), b"old evidence")
                .expect("write earlier evidence");
        }

        let mut ingest = Ingest::new().expect("count a full quarantine tree");
        assert_eq!(ingest.quarantined, MAX_QUARANTINE_FILES);

        let stuffed = source_dir.join("stuffed.json");
        std::fs::write(&stuffed, b"peer bytes").expect("write judged-invalid bytes");
        assert_eq!(
            ingest
                .dispose(&stuffed, "stuffed.json", hash, Refusal::Foreign, now())
                .expect("dispose judged-invalid file"),
            Disposal::Deleted
        );
        assert!(!stuffed.exists());

        let crowded = source_dir.join("crowded.json");
        std::fs::write(&crowded, b"possibly local bytes").expect("write crowded bytes");
        let disposal = ingest
            .dispose(&crowded, "crowded.json", hash, Refusal::Local, now())
            .expect("make room for a refusal that can touch a local file");
        let Disposal::Quarantined { to } = disposal else {
            panic!("a full quarantine must evict rather than leave a crowded file behind");
        };
        assert_eq!(
            std::fs::read(to).expect("the evidence moved"),
            b"possibly local bytes"
        );
        assert!(
            !crowded.exists(),
            "the bundle directory is back under its cap"
        );
        assert_eq!(ingest.quarantined, QUARANTINE_LOW_WATER + 1);

        std::fs::remove_dir_all(root).unwrap();
    }

    /// The counter is not the truth; the disk is. A saturated `Ingest` that has lost track — the
    /// original wedge, where 1024 rejections latched the tree forever — must recover with no
    /// operator action, and a sweep must reclaim both what outlived its evidence value and what
    /// sits beside a bundle directory that is gone.
    #[test]
    fn a_saturated_quarantine_recovers_from_what_the_disk_actually_holds() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_quarantine_reclaim", 2, [0x11, 0x22]);
        let live = B256::from([0x61; 32]);
        let gone = B256::from([0x62; 32]);
        let source_dir = root.join("bundles").join(live.to_string());
        std::fs::create_dir(&source_dir).expect("make the live bundle directory");
        for (hash, name) in [(live, "kept.json"), (gone, "orphaned.json")] {
            let evidence = root.join("bundle-quarantine").join(hash.to_string());
            std::fs::create_dir_all(&evidence).expect("make a quarantine directory");
            std::fs::write(evidence.join(name), b"evidence").expect("write evidence");
        }

        let mut ingest = Ingest::new().expect("count the quarantine tree");
        assert_eq!(
            ingest.quarantined, 1,
            "evidence beside a bundle directory that is gone is reclaimed at startup"
        );
        assert!(!root
            .join("bundle-quarantine")
            .join(gone.to_string())
            .exists());

        ingest.quarantined = MAX_QUARANTINE_FILES;
        let refused = source_dir.join("refused.json");
        std::fs::write(&refused, b"peer bytes").expect("write a refused file");
        let disposal = ingest
            .dispose(&refused, "refused.json", live, Refusal::Foreign, now())
            .expect("dispose against a saturated counter");
        assert!(
            matches!(disposal, Disposal::Quarantined { .. }),
            "a counter that outran the disk must not keep refusing to store evidence"
        );
        assert_eq!(ingest.quarantined, 2);

        let now = hc_sign::grant::now_ms().expect("the local clock");
        ingest
            .sweep(now + QUARANTINE_TTL_MS + 1, false)
            .expect("sweep a tree whose evidence has outlived its value");
        assert_eq!(ingest.quarantined, 0);
        assert!(!root
            .join("bundle-quarantine")
            .join(live.to_string())
            .exists());

        std::fs::remove_dir_all(root).unwrap();
    }

    /// Coordination sits outside `safeTxHash`, so two devices that each created this bundle chose
    /// their own `threshold` and `created_at_ms`, and every signature file carries whichever one
    /// its device saw. Both signatures must still be taken — a signature that is valid for the
    /// digest cannot be quarantined over metadata a peer chose — and the union must still load.
    #[test]
    fn disagreeing_coordination_never_quarantines_a_valid_signature() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_coordination", 2, [0x11, 0x22]);
        let held = bundle(intent(13));
        let hash = held.digest();
        let dir = root.join("bundles").join(hash.to_string());
        std::fs::create_dir(&dir).expect("make the bundle directory");
        std::fs::write(
            dir.join(SEED_FILE),
            serde_json::to_vec(&held).expect("serialize the seed"),
        )
        .expect("write the seed");

        for (key, threshold, created_at_ms) in [(0x11, 1, 5), (0x22, 3, 9)] {
            let response = signed(key, &held);
            let signer = response.signer;
            let mut one = SafeTxBundle {
                threshold,
                created_at_ms,
                signatures: Vec::new(),
                ..held.clone()
            };
            one.add(
                CollectedSignature {
                    signer,
                    signature: response.signature,
                },
                &crate::tests::owners_of([0x11, 0x22]),
            )
            .expect("build an individually valid signer file");
            std::fs::write(
                dir.join(format!("{signer:#x}{BUNDLE_SUFFIX}")),
                serde_json::to_vec(&one).expect("serialize signer file"),
            )
            .expect("write signer file");
        }

        let mut ingest = Ingest::new().expect("start validator");
        let verdict = ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("validate the directory");
        assert!(
            verdict.rejected.is_empty(),
            "coordination a peer chose is not a refusal"
        );

        let union = crate::load_dir(&dir, hash).expect("the union still loads");
        assert_eq!(union.signatures.len(), 2);
        assert_eq!(
            union.threshold, 2,
            "the union normalises onto the reference file rather than refusing"
        );

        let settled = ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("the directory is settled");
        assert_eq!(settled.judged, 0);

        std::fs::remove_dir_all(root).unwrap();
    }

    /// A per-signer file can never cost more than one ecrecover. The refusal is not the point —
    /// that is one `if` — the ordering is: a second signature that recovers to nobody would come
    /// back `Signature` if the recovery loop had run at all.
    #[test]
    fn a_file_repeating_a_signature_is_refused_before_it_is_recovered() {
        let local = safes(2, [0x11, 0x22]);
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
                hash,
                &local
            ),
            Ruling::Refuse(Reject::Stuffed),
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
                hash,
                &local
            ),
            Ruling::Refuse(Reject::Stuffed)
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
        let a = home("hot_cheese_ingest_incremental_a", 2, all_owners());
        let b = std::env::temp_dir().join("hot_cheese_ingest_incremental_b");
        let _ = std::fs::remove_dir_all(&b);
        std::fs::create_dir_all(b.join("bundles")).expect("make the second home");
        crate::tests::write_safes(&b, 2, all_owners());
        let both = [&a, &b];

        let write = |rel: &str, bytes: &[u8]| {
            for root in both {
                std::fs::write(root.join("bundles").join(rel), bytes).expect("write a fixture");
            }
        };

        let mut dirs = Vec::new();
        for nonce in 0..67u64 {
            let seed = bundle(intent(nonce));
            let hash = seed_dir(&both, nonce);
            for filler in 0..62u8 {
                let response = signed(filler + 1, &seed);
                let signer = response.signer;
                let mut one = SafeTxBundle {
                    signatures: Vec::new(),
                    ..seed.clone()
                };
                one.add(
                    CollectedSignature {
                        signer,
                        signature: response.signature,
                    },
                    &crate::tests::owners_of(all_owners()),
                )
                .expect("a valid filler signature");
                write(
                    &format!("{hash}/{signer:#x}{BUNDLE_SUFFIX}"),
                    &serde_json::to_vec(&one).expect("serialize"),
                );
            }
            dirs.push((hash, seed));
        }

        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        let mut refused = Vec::new();
        let pass = |ingest: &mut Ingest, refused: &mut Vec<(String, Reject)>| {
            let verdict = ingest
                .validate(Scope::All, &truth(), Delivered::Locally)
                .expect("a pass over the test tree");
            refused.extend(refusals(&a, &verdict));
            verdict
        };

        assert!(
            pass(&mut ingest, &mut refused).capped,
            "67 × 63 files is past MAX_INGEST_FILES, so the priming pass leaves work behind"
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
        ours.add(
            CollectedSignature {
                signer,
                signature: response.signature,
            },
            &crate::tests::owners_of(all_owners()),
        )
        .expect("our own signature over our own digest");
        write(
            &format!("{hash}/{signer:#x}{BUNDLE_SUFFIX}"),
            &serde_json::to_vec(&ours).expect("serialize"),
        );
        pass(&mut ingest, &mut refused);

        let corrupt = signed(1, &dirs[3].1).signer;
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
        assert_eq!(settled.dirs, 66);

        std::env::set_var("HOT_CHEESE_HOME", &b);
        let mut fresh = Ingest::new().expect("an empty quarantine tree");
        let mut full = Vec::new();
        loop {
            let verdict = fresh
                .validate(Scope::All, &truth(), Delivered::Locally)
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
    /// backwards deletes the operator's own bundles.
    ///
    /// The second half is what makes a directory OURS. It is not a notification: `bundle new` and
    /// `bundle sign` in a terminal poke no poller, and a daemon that learned about local work only
    /// from the console deleted the operator's own freshly-signed bundle on its next tick. Both
    /// verbs are driven here through the same entry points the CLI uses, and the tree is already
    /// past [`MAX_BUNDLE_DIRS`], so every cap this pass has is against them.
    #[test]
    fn only_a_directory_that_arrived_past_the_cap_is_refused() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_dir_cap", 2, [0x11, 0x22]);
        let held = [&root];
        for nonce in 0..(MAX_BUNDLE_DIRS as u64 + 1) {
            seed_dir(&held, nonce);
        }

        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        let verdict = ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("the priming pass");
        assert!(
            verdict.refused_dirs.is_empty(),
            "a tree already over the cap keeps every bundle the operator had"
        );
        assert_eq!(verdict.dirs, MAX_BUNDLE_DIRS + 1);

        let arrived = seed_dir(&held, 900);
        let verdict = ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("the pass that sees it arrive");
        assert_eq!(verdict.refused_dirs, vec![arrived]);
        assert!(!bundle_dir(arrived).exists());

        let mine = crate::new(crate::sync::SyncMode::Off, intent(901)).expect("bundle new");
        let seed = crate::read_bundle(&bundle_dir(mine), mine).expect("read what it wrote");
        let response = signed(0x11, &seed);
        let signer = response.signer;
        crate::collect(crate::sync::SyncMode::Off, mine, response).expect("bundle sign");

        let verdict = ingest
            .validate(Scope::All, &truth(), Delivered::By("peer"))
            .expect("the pass that sees our own");
        assert!(
            verdict.refused_dirs.is_empty(),
            "a bundle this machine made is never evicted by a cap or a peer's quota"
        );
        assert!(bundle_dir(mine)
            .join(format!("{signer:#x}{BUNDLE_SUFFIX}"))
            .is_file());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn over_cap_cleanup_never_recurses_into_an_unexpected_directory() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_flat_directory_cleanup", 2, [0x11, 0x22]);
        let dir = root
            .join("bundles")
            .join(B256::from([0x77u8; 32]).to_string());
        std::fs::create_dir_all(dir.join("unexpected")).expect("make nested local data");
        std::fs::write(dir.join("unexpected").join("KEEP"), b"do not delete")
            .expect("write nested local data");

        assert!(remove_flat_directory(&dir).is_err());
        assert_eq!(
            std::fs::read(dir.join("unexpected").join("KEEP")).expect("nested data survives"),
            b"do not delete"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    /// Quarantining a peer's only file must reclaim the fresh digest directory too. Otherwise
    /// one invalid `unsigned.json` under each of 64 hashes permanently consumes the arrival cap
    /// and a later honest peer bundle is refused before its seed can be judged.
    #[test]
    fn invalid_arrivals_cannot_exhaust_the_bundle_directory_cap_with_empty_shells() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_empty_arrival_shells", 2, [0x11, 0x22]);
        let held = [&root];
        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("prime the empty tree");

        for nonce in 0..MAX_BUNDLE_DIRS as u64 {
            let seed = bundle(intent(nonce));
            let hash = seed.digest();
            let dir = root.join("bundles").join(hash.to_string());
            std::fs::create_dir(&dir).expect("make an arriving digest directory");
            std::fs::write(dir.join(SEED_FILE), b"not a bundle")
                .expect("write the peer's invalid seed");
        }

        let refused = ingest
            .validate(Scope::All, &truth(), Delivered::By("peer"))
            .expect("quarantine every invalid arrival");
        assert_eq!(refused.rejected.len(), MAX_DIRS_PER_PEER);
        assert_eq!(
            refused.refused_dirs.len(),
            MAX_BUNDLE_DIRS - MAX_DIRS_PER_PEER,
            "the rest is past this peer's share of the tree"
        );
        assert_eq!(refused.dirs, 0, "empty arrival shells are reclaimed");
        assert_eq!(
            std::fs::read_dir(root.join("bundles"))
                .expect("read the bundle root")
                .count(),
            1,
            "only safes.toml is left"
        );

        let honest = seed_dir(&held, 9_000);
        let accepted = ingest
            .validate(Scope::All, &truth(), Delivered::By("peer"))
            .expect("judge the later honest arrival");
        assert!(accepted.refused_dirs.is_empty());
        assert_eq!(accepted.dirs, 1);
        assert!(bundle_dir(honest).join(SEED_FILE).is_file());
    }

    #[test]
    fn file_and_scoped_directory_removals_invalidate_seen_state() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_removal_tracking", 2, [0x11, 0x22]);
        let held = [&root];
        let hash = seed_dir(&held, 9_100);
        let dir = bundle_dir(hash);
        let mut ingest = Ingest::new().expect("start validator");

        assert!(
            ingest
                .validate(Scope::All, &truth(), Delivered::Locally)
                .expect("prime the seed")
                .changed
        );
        assert!(
            !ingest
                .validate(Scope::All, &truth(), Delivered::Locally)
                .expect("settled tree")
                .changed
        );

        std::fs::remove_file(dir.join(SEED_FILE)).expect("remove the accepted seed");
        let removed_file = ingest
            .validate(Scope::One(hash), &truth(), Delivered::Locally)
            .expect("notice the file removal");
        assert!(removed_file.changed);
        assert_eq!(removed_file.judged, 0);

        std::fs::remove_dir(&dir).expect("remove the empty bundle directory");
        assert!(
            ingest
                .validate(Scope::One(hash), &truth(), Delivered::Locally)
                .expect("notice the scoped directory removal")
                .changed
        );
        assert!(!ingest.seen.contains_key(&hash));
    }

    #[test]
    fn poller_reloads_after_signature_removal_and_restoration() {
        let _env = HOME.lock();
        let root = home("hot_cheese_poller_signature_restoration", 2, [0x11, 0x22]);
        let seed = bundle(intent(9_200));
        let hash = seed.digest();
        let dir = root.join("bundles").join(hash.to_string());
        std::fs::create_dir(&dir).expect("make the bundle directory");
        std::fs::write(
            dir.join(SEED_FILE),
            serde_json::to_vec(&seed).expect("serialize seed"),
        )
        .expect("write seed");

        let mut signer_paths = Vec::new();
        for key in [0x11, 0x22] {
            let response = signed(key, &seed);
            let signer = response.signer;
            let mut one = SafeTxBundle {
                signatures: Vec::new(),
                ..seed.clone()
            };
            one.add(
                CollectedSignature {
                    signer,
                    signature: response.signature,
                },
                &crate::tests::owners_of([0x11, 0x22]),
            )
            .expect("build signer file");
            let path = dir.join(format!("{signer:#x}{BUNDLE_SUFFIX}"));
            let bytes = serde_json::to_vec(&one).expect("serialize signer file");
            std::fs::write(&path, &bytes).expect("write signer file");
            signer_paths.push((signer, path, bytes));
        }

        let mut poller = crate::poll::Poller::start().expect("prime poller");
        assert_eq!(poller.stock().expect("settled stock").ready, 1);

        let (restored_signer, restored_path, restored_bytes) = signer_paths.pop().unwrap();
        std::fs::remove_file(&restored_path).expect("remove one signature");
        let missing = poller.stock().expect("reload after removal");
        assert_eq!(missing.ready, 0);
        assert!(missing.arrivals.is_empty());

        std::fs::write(&restored_path, &restored_bytes).expect("restore the signature");
        let restored = poller.stock().expect("reload after restoration");
        assert_eq!(restored.ready, 1);
        assert_eq!(restored.arrivals.len(), 1);
        assert_eq!(restored.arrivals[0].signer, restored_signer);
    }

    /// Enforcing the per-bundle cap must not move a file this machine already had judged, which
    /// is as much of the "quarantine cannot eat your own signature" invariant as the cap leaves
    /// standing. The window it does NOT cover — a local write no pass has judged yet — is stated
    /// in this module's own doc and is not what this test claims.
    #[test]
    fn the_per_bundle_cap_keeps_the_seed_and_what_a_pass_already_judged() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_file_cap", 2, all_owners());
        let held = [&root];
        let seed = bundle(intent(7));
        let hash = seed_dir(&held, 7);
        let dir = bundle_dir(hash);
        let owners = crate::tests::owners_of(all_owners());
        let response = signed(0x11, &seed);
        let signer = response.signer;
        let mut ours = SafeTxBundle {
            signatures: Vec::new(),
            ..seed.clone()
        };
        ours.add(
            CollectedSignature {
                signer,
                signature: response.signature,
            },
            &owners,
        )
        .expect("our own signature over our own digest");
        let mine = format!("{signer:#x}{BUNDLE_SUFFIX}");
        std::fs::write(
            dir.join(&mine),
            serde_json::to_vec(&ours).expect("serialize"),
        )
        .expect("write our own file");

        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("the pass that puts our own file in seen");

        for seed_byte in all_owners() {
            if seed_byte == 0x11 {
                continue;
            }
            let response = signed(seed_byte, &seed);
            let peer = response.signer;
            let mut one = SafeTxBundle {
                signatures: Vec::new(),
                ..seed.clone()
            };
            one.add(
                CollectedSignature {
                    signer: peer,
                    signature: response.signature,
                },
                &owners,
            )
            .expect("a valid peer signature");
            std::fs::write(
                dir.join(format!("{peer:#x}{BUNDLE_SUFFIX}")),
                serde_json::to_vec(&one).expect("serialize peer file"),
            )
            .expect("write a peer's file");
        }
        std::fs::write(
            dir.join(format!("{:#x}{BUNDLE_SUFFIX}", Address::from([0x99u8; 20]))),
            b"not a bundle",
        )
        .expect("write the file that breaks the cap");

        let verdict = ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("the pass that enforces the cap");
        assert_eq!(verdict.crowded, vec![hash]);
        assert_eq!(verdict.refused_files, 1);
        assert!(dir.join(SEED_FILE).exists(), "the seed is kept first");
        assert!(
            dir.join(&mine).exists(),
            "then every file a pass has already judged"
        );
        assert!(std::fs::read_dir(&dir).expect("read the dir").count() <= MAX_FILES_PER_BUNDLE);

        std::fs::remove_dir_all(root).unwrap();
    }

    /// `rm` cannot be the end of it: no transfer here carries a deletion, so the next pull writes
    /// a retired bundle straight back and it goes on holding its (safe, chain, nonce) slot. The
    /// retirement is local truth a peer cannot write, and every pass enforces it again.
    #[test]
    fn a_retired_bundle_a_pull_brings_back_is_removed_again() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_tombstone", 2, [0x11, 0x22]);
        let held = [&root];
        let hash = seed_dir(&held, 5_000);
        crate::rm(hash).expect("retire it");
        assert!(!bundle_dir(hash).exists());

        seed_dir(&held, 5_000);
        assert!(bundle_dir(hash).is_dir(), "the peer still has it");
        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        let verdict = ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("judge the resurrected directory");
        assert_eq!(verdict.retired, vec![hash]);
        assert!(!bundle_dir(hash).exists());
        assert_eq!(verdict.dirs, 0);

        std::fs::remove_dir_all(root).unwrap();
    }

    /// A killed transfer leaves a temp file behind, and an over-cap arrival full of them used to
    /// abort the WHOLE pass — after which `sync::pull` refused every peer, for every bundle, until
    /// a human intervened. One interrupted transfer must cost itself and nothing else: the junk is
    /// cleaned, and the genuine signature that landed in the same pass is still judged.
    #[test]
    fn one_broken_arrival_cannot_deny_service_to_every_good_directory() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_junk_arrival", 2, [0x11, 0x22]);
        let held = [&root];
        let mut hashes = Vec::new();
        for nonce in 0..MAX_BUNDLE_DIRS as u64 {
            hashes.push(seed_dir(&held, nonce));
        }
        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("prime a full tree");

        let junk = bundle(intent(700)).digest();
        let junk_dir = bundle_dir(junk);
        std::fs::create_dir(&junk_dir).expect("make the arriving directory");
        std::fs::write(junk_dir.join(".unsigned.json.gk21Xa"), b"half a transfer")
            .expect("leave an rsync temp file behind");

        let seed = bundle(intent(0));
        let response = signed(0x11, &seed);
        let signer = response.signer;
        let mut one = SafeTxBundle {
            signatures: Vec::new(),
            ..seed.clone()
        };
        one.add(
            CollectedSignature {
                signer,
                signature: response.signature,
            },
            &crate::tests::owners_of([0x11, 0x22]),
        )
        .expect("a genuine signature");
        std::fs::write(
            bundle_dir(hashes[0]).join(format!("{signer:#x}{BUNDLE_SUFFIX}")),
            serde_json::to_vec(&one).expect("serialize"),
        )
        .expect("write it into a directory this machine already held");

        let verdict = ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("one broken arrival cannot abort the pass");
        assert_eq!(verdict.refused_dirs, vec![junk]);
        assert!(
            !junk_dir.exists(),
            "the temp artefact is cleaned, not stepped over"
        );
        assert_eq!(
            crate::load_dir(&bundle_dir(hashes[0]), hashes[0])
                .expect("the good directory still loads")
                .signatures
                .len(),
            1,
            "the signature that landed in the same pass was still judged"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    /// This home's own local truth, judging against `safes` at `now_ms`, so the expiry rules can
    /// be stated against a clock rather than waited for.
    fn truth_at(safes: crate::Safes, now_ms: u64) -> Truth {
        let held = truth();
        Truth {
            safes,
            ours: held.ours,
            signers: held.signers,
            retired: held.retired,
            now_ms,
        }
    }

    /// A `safes.toml` that describes some Safe, and not the fixture's.
    fn another_safe() -> crate::Safes {
        toml::from_str(&crate::tests::safes_toml(2, [0x11, 0x22]).replace(
            &format!("{:#x}", Address::from([0x11u8; 20])),
            &format!("{:#x}", Address::from([0x44u8; 20])),
        ))
        .expect("a safes.toml describing some other Safe")
    }

    /// A bundle naming a Safe this `safes.toml` does not describe can never become valid, so a
    /// PROPOSAL for one must not hold a (safe, chain, nonce) slot for the fortnight a proposal for
    /// a known Safe gets. What it must not do is destroy signatures on that ground: a directory
    /// holding a signature keeps the ordinary fortnight even when nothing can judge it, and a
    /// machine that describes no Safe at all makes no statement about any of them and expires
    /// nothing early — which is what a `safes.toml` that will not load must never be able to fake.
    #[test]
    fn an_unknown_safe_expires_a_proposal_and_never_a_signature() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_unknown_safe", 2, [0x11, 0x22]);
        let held = [&root];
        let hash = seed_dir(&held, 4_242);
        let dir = bundle_dir(hash);
        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        let mut verdict = Verdict::default();
        let now = now();
        let known = truth_at(safes(2, [0x11, 0x22]), now + UNKNOWN_SAFE_TTL_MS + 1);
        let unknown = truth_at(another_safe(), now + UNKNOWN_SAFE_TTL_MS + 1);
        let describes_nothing = truth_at(crate::Safes::default(), now + UNKNOWN_SAFE_TTL_MS + 1);

        let young = ingest
            .judge_dir(
                hash,
                &dir,
                false,
                &truth_at(another_safe(), now + UNKNOWN_SAFE_TTL_MS - 1),
                &mut verdict,
            )
            .expect("judge it while the operator might still add the Safe");
        assert!(matches!(young, Judged::Held(_)));
        assert!(dir.join(SEED_FILE).is_file());

        let nothing_to_be_unknown_against = ingest
            .judge_dir(hash, &dir, false, &describes_nothing, &mut verdict)
            .expect("judge it on a machine that describes no Safe");
        assert!(
            matches!(nothing_to_be_unknown_against, Judged::Held(_)),
            "a machine with no Safes states nothing about a Safe it does not name"
        );

        let signed = seed_dir(&held, 4_244);
        let signature = self::signed(0x11, &bundle(intent(4_244)));
        let mut one = SafeTxBundle {
            signatures: Vec::new(),
            ..bundle(intent(4_244))
        };
        one.add(
            CollectedSignature {
                signer: signature.signer,
                signature: signature.signature,
            },
            &crate::tests::owners_of([0x11, 0x22]),
        )
        .expect("a valid signature over that digest");
        std::fs::write(
            bundle_dir(signed).join(format!("{:#x}{BUNDLE_SUFFIX}", signature.signer)),
            serde_json::to_vec(&one).expect("serialize"),
        )
        .expect("write the signature");
        let kept_signature = ingest
            .judge_dir(signed, &bundle_dir(signed), false, &unknown, &mut verdict)
            .expect("judge a signature for a Safe this machine cannot judge");
        assert!(
            matches!(kept_signature, Judged::Held(_)),
            "an unknown Safe is a reason to ignore a bundle, not to destroy its signatures"
        );
        assert_eq!(
            std::fs::read_dir(bundle_dir(signed))
                .expect("read the directory")
                .count(),
            2
        );

        let expired = ingest
            .judge_dir(hash, &dir, false, &unknown, &mut verdict)
            .expect("judge the proposal once its short life is up");
        assert!(matches!(expired, Judged::Reclaimed));
        assert!(!dir.exists());

        let ours = seed_dir(&held, 4_243);
        let kept = ingest
            .judge_dir(ours, &bundle_dir(ours), false, &known, &mut verdict)
            .expect("judge a proposal for a Safe this machine does describe");
        assert!(
            matches!(kept, Judged::Held(_)),
            "an unsigned proposal for a known Safe still gets its fortnight"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    /// Local truth is all of it or none of it. A `safes.toml` an operator broke — an owner
    /// removed without lowering the threshold — used to be substituted with an EMPTY one, under
    /// which every file rules unknown, every directory reads as unsigned, and a fully-signed
    /// bundle is an hour from deletion. There is no such pass now: the load refuses by name, the
    /// callers that would have run it stop, the tree is untouched, and fixing the file resumes
    /// everything with the signatures still there.
    #[test]
    fn a_safes_toml_that_will_not_load_refuses_instead_of_emptying_local_truth() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_broken_truth", 2, [0x11, 0x22]);
        let held = [&root];
        let hash = seed_dir(&held, 8_100);
        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("prime a healthy tree");

        crate::tests::write_safes(&root, 2, [0x11]);
        assert!(matches!(
            Truth::load(),
            Err(crate::BundleErr::InvalidSafeThreshold { threshold: 2, .. })
        ));
        assert!(
            crate::poll::Poller::start().is_err(),
            "the daemon's poller refuses to run a pass with no truth to judge by"
        );
        assert!(bundle_dir(hash).join(SEED_FILE).is_file());

        crate::tests::write_safes(&root, 2, [0x11, 0x22]);
        let resumed = ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("the pass the operator's fix restored");
        assert_eq!(resumed.dirs, 1);
        assert!(resumed.retired.is_empty() && resumed.rejected.is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }

    /// The quota is a SHARE of the tree, not an allowance per pass. A peer that sends its full
    /// per-pass helping and waits used to own every slot four ticks later — two minutes at the
    /// default poll interval — while refusing nothing, which is the one signal the caller's flood
    /// backoff can see. Waiting must buy it nothing: past its share every later directory is
    /// refused, however many passes it spreads them over, and the slots it does hold come back
    /// only when those directories leave.
    #[test]
    fn one_peer_cannot_take_the_tree_by_spreading_it_over_passes() {
        let _env = HOME.lock();
        let root = home("hot_cheese_ingest_peer_quota", 2, [0x11, 0x22]);
        let held = [&root];
        let mut ingest = Ingest::new().expect("an empty quarantine tree");
        ingest
            .validate(Scope::All, &truth(), Delivered::Locally)
            .expect("prime the empty tree");

        let mut refused = 0usize;
        let mut nonce = 0u64;
        let mut dirs = 0usize;
        for _ in 0..6 {
            for _ in 0..MAX_DIRS_PER_PEER {
                seed_dir(&held, 9_000 + nonce);
                nonce += 1;
            }
            let verdict = ingest
                .validate(Scope::All, &truth(), Delivered::By("hostile"))
                .expect("judge one pass of one peer's flood");
            refused += verdict.refused_dirs.len();
            dirs = verdict.dirs;
        }
        assert_eq!(
            dirs, MAX_DIRS_PER_PEER,
            "six passes buy one peer exactly the share one pass does"
        );
        assert_eq!(
            refused,
            MAX_DIRS_PER_PEER * 5,
            "every pass past the share refuses, which is what engages the flood backoff"
        );

        let elsewhere = seed_dir(&held, 50_000);
        let other = ingest
            .validate(Scope::All, &truth(), Delivered::By("honest"))
            .expect("another peer's pass");
        assert!(
            other.refused_dirs.is_empty(),
            "one peer at its share must not spend another peer's"
        );
        assert!(bundle_dir(elsewhere).is_dir());

        let mut theirs = Vec::new();
        for (hash, peer) in &ingest.from {
            if peer == "hostile" {
                theirs.push(*hash);
            }
        }
        theirs.sort();
        assert_eq!(theirs.len(), MAX_DIRS_PER_PEER);
        std::fs::remove_dir_all(bundle_dir(theirs[0])).expect("the operator retires one of them");

        let freed = seed_dir(&held, 60_000);
        let after = ingest
            .validate(Scope::All, &truth(), Delivered::By("hostile"))
            .expect("the pass that frees a slot and fills it again");
        assert!(
            !after.refused_dirs.contains(&freed),
            "a slot comes back when the directory holding it leaves"
        );
        assert!(bundle_dir(freed).is_dir());

        std::fs::remove_dir_all(root).unwrap();
    }
}
