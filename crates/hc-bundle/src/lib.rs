//! Collecting owner signatures for one Safe transaction across several devices.
//!
//! A bundle is not secret. It is the transaction's FIELDS plus signatures over a digest anyone
//! can recompute, so it never touches the store and never rides a backup: it lives under
//! `<home>/bundles`, beside `adapters`, on a machine whose vault is deliberately not the other
//! machine's vault.
//!
//! Every device writes its OWN file, `0x<signer>.json`, holding a complete bundle carrying only
//! that device's signature. That is the whole concurrency design: two Macs signing the same
//! transaction at the same moment write two differently-named files, so there is no
//! last-writer-wins conflict to resolve — whoever reads takes the union in memory. A small
//! local lock now serialises validation and multi-step check/write sequences, but correctness
//! across machines still comes from the per-writer layout rather than that local lock. The
//! union is [`SafeTxBundle::merge`], which recomputes both digests and refuses a
//! file belonging to another transaction, so a misfiled drop-in cannot be absorbed silently.
//! It is also what makes [`sync`] correct: `rsync` without `--delete` over a per-writer layout
//! IS that union, so pulling and pushing in both directions converges with nothing to resolve.
//!
//! Nothing here prompts, unlocks, listens, or reaches a key. The one verb that needs a
//! signature takes it as an argument — [`intent_to_sign`] hands out what to sign and
//! [`collect`] takes the answer back — so the CLI and the console both drive it through
//! whichever unlock path they already own, and neither one grows a second route to a key.
pub mod ingest;
pub(crate) mod local;
#[doc(hidden)]
pub mod lock;
pub mod poll;
pub mod sync;
pub mod tailnet;

use crate::ingest::{
    MAX_BUNDLE_DIRS, MAX_ENUMERATED_ENTRIES, MAX_FILES_PER_BUNDLE, MAX_FILE_BYTES,
};
use crate::sync::SyncMode;
use alloy_primitives::{Address, Bytes, B256, U256};
use err_mac::create_err_with_impls;
use hashbrown::HashMap;
use hc_core::config::bundles_dir;
use hc_core::crypto::envelope::atomic_write_new;
use hc_sign::bundle::{CollectedSignature, Quorum, SafeTxBundle};
use hc_sign::grant::now_ms;
use hc_sign::intent::{Intent, SafeTxIntent};
use hc_sign::qr::{frames, QrKind};
use hc_sign::SignResponse;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The bundle a device writes before it holds any signature.
pub const SEED_FILE: &str = "unsigned.json";

/// Suffix every file in a bundle directory carries.
pub const BUNDLE_SUFFIX: &str = ".json";
pub const MAX_SAFES_BYTES: u64 = 64 * 1024;
pub const MAX_SAFES: usize = 256;
pub const MAX_SAFE_OWNERS: usize = 64;

create_err_with_impls!(
    #[derive(Debug)]
    pub BundleErr,
    Io(std::io::Error),
    Serde(serde_json::Error),
    Toml(toml::de::Error),
    Envelope(hc_core::crypto::envelope::EnvErr),
    Verify(hc_sign::bundle::BundleErr),
    Qr(hc_sign::qr::QrErr),
    Grant(hc_sign::grant::GrantErr),
    Lock(lock::LockErr),
    Ingest(ingest::IngestErr)
    ;
    NoSafesFile { path: PathBuf },
    UnknownSafe { safe: Address, chain_id: U256 },
    BundleExists { dir: PathBuf },
    NoSuchBundle { dir: PathBuf },
    EmptyBundle { dir: PathBuf },
    NotItsDigest { dir: PathBuf, digest: B256 },
    ForeignDigest { ours: B256, theirs: B256 },
    ThresholdNotMet { have: usize, threshold: u8 },
    TooManyBundleFiles { dir: PathBuf, found: usize, max: usize },
    TooManyDirectoryEntries { dir: PathBuf, max: usize },
    TooManySafes { found: usize, max: usize },
    InvalidSafeThreshold { safe: Address, threshold: u8, owners: usize },
    TooManySafeOwners { safe: Address, found: usize, max: usize },
    DuplicateSafeOwner { safe: Address, owner: Address },
    DuplicateSafe { safe: Address, chain_id: U256 },
    BundleFileTooLarge { size: usize, max: u64 },
    BundleFileConflict { path: PathBuf },
    InvalidBundleFileName { path: PathBuf },
    MisfiledBundle { path: PathBuf },
    TooManyLocalFacts { dir: PathBuf, max: usize },
    RetiredUnreadable { dir: PathBuf }
);

/// An exclusive, cross-process claim on the local bundle tree. MCP keeps one from its final
/// queue/slot check through creation, closing the check-then-file race; ordinary operations take
/// the same claim internally.
pub struct Mutation {
    _lock: lock::Lock,
}

impl Mutation {
    pub fn take() -> Result<Self, BundleErr> {
        Ok(Self {
            _lock: lock::Lock::take()?,
        })
    }

    /// Create one bundle while consuming this claim. The claim is deliberately dropped before
    /// the network push, so an asleep peer cannot block local readers and writers for a minute.
    pub fn new(self, sync: SyncMode, intent: SafeTxIntent) -> Result<B256, BundleErr> {
        let hash = new_local(intent)?;
        drop(self);
        sync.push(Scope::One(hash));
        Ok(hash)
    }
}

/// How much of the bundle tree an operation touches. Naming one bundle keeps a sync to the
/// directory the operator is actually working in, which is what makes weaving it into every
/// verb affordable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The whole tree.
    All,
    /// One bundle directory, named by its digest.
    One(B256),
}

/// One Safe this machine collects for.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeEntry {
    /// The Safe contract.
    pub address: Address,
    /// Chain it is deployed on.
    #[serde(with = "hc_core::wire::u256")]
    pub chain_id: U256,
    /// Owner signatures `execTransaction` requires.
    pub threshold: u8,
    /// Local mirror of the Safe's on-chain owner list; a stale one reverts on-chain.
    pub owners: Vec<Address>,
}

/// `<home>/bundles/safes.toml`. Not `policy.toml`: this states what a Safe IS, the policy states
/// what a key may sign, and the two are never merged. It is also the one file [`sync`] never
/// carries: a peer that could rewrite it could lower a threshold or plant an owner.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Safes {
    /// One `[[safe]]` table per Safe.
    #[serde(default)]
    pub safe: Vec<SafeEntry>,
}

impl Safes {
    pub fn load() -> Result<Self, BundleErr> {
        let root = bundles_dir();
        let path = root.join("safes.toml");
        if !owned_directory_exists(&root)? {
            return Err(BundleErr::NoSafesFile { path });
        }
        if !path.exists() {
            return Err(BundleErr::NoSafesFile { path });
        }
        let bytes = hc_core::read_regular_file_bounded(&path, MAX_SAFES_BYTES)?;
        let safes: Self = toml::from_str(
            std::str::from_utf8(&bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        )?;
        safes.validate()?;
        Ok(safes)
    }

    fn validate(&self) -> Result<(), BundleErr> {
        if self.safe.len() > MAX_SAFES {
            return Err(BundleErr::TooManySafes {
                found: self.safe.len(),
                max: MAX_SAFES,
            });
        }
        for (at, entry) in self.safe.iter().enumerate() {
            if entry.threshold == 0 || usize::from(entry.threshold) > entry.owners.len() {
                return Err(BundleErr::InvalidSafeThreshold {
                    safe: entry.address,
                    threshold: entry.threshold,
                    owners: entry.owners.len(),
                });
            }
            if entry.owners.len() > MAX_SAFE_OWNERS {
                return Err(BundleErr::TooManySafeOwners {
                    safe: entry.address,
                    found: entry.owners.len(),
                    max: MAX_SAFE_OWNERS,
                });
            }
            for (owner_at, owner) in entry.owners.iter().enumerate() {
                if entry.owners[owner_at + 1..].contains(owner) {
                    return Err(BundleErr::DuplicateSafeOwner {
                        safe: entry.address,
                        owner: *owner,
                    });
                }
            }
            if self.safe[at + 1..]
                .iter()
                .any(|other| other.address == entry.address && other.chain_id == entry.chain_id)
            {
                return Err(BundleErr::DuplicateSafe {
                    safe: entry.address,
                    chain_id: entry.chain_id,
                });
            }
        }
        Ok(())
    }

    /// The entry for a (Safe, chain) pair. An unknown Safe is a refusal: the threshold and the
    /// owner list are the only local facts a bundle is judged against, and guessing either is
    /// worse than stopping.
    pub fn find(&self, safe: Address, chain_id: U256) -> Result<&SafeEntry, BundleErr> {
        for entry in &self.safe {
            if entry.address == safe && entry.chain_id == chain_id {
                return Ok(entry);
            }
        }
        Err(BundleErr::UnknownSafe { safe, chain_id })
    }
}

/// One bundle as it sits on disk.
pub struct Loaded {
    /// The digest its directory is named for.
    pub hash: B256,
    /// The union of every per-signer file in that directory.
    pub bundle: SafeTxBundle,
    /// What it holds against what the LOCAL `safes.toml` requires today.
    pub quorum: Quorum,
}

/// What a bundle competes for. A Safe executes each nonce exactly once, so two different
/// digests under one of these are mutually exclusive transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slot {
    pub safe: Address,
    pub chain_id: U256,
    pub nonce: U256,
}

impl Slot {
    fn of(intent: &SafeTxIntent) -> Self {
        Slot {
            safe: intent.safe,
            chain_id: intent.chain_id,
            nonce: intent.nonce,
        }
    }
}

/// The merged view of one bundle, judged against `safes.toml` as it reads right now.
pub struct BundleStatus {
    /// The digest, and the directory name.
    pub hash: B256,
    /// The union of every per-signer file.
    pub bundle: SafeTxBundle,
    /// What it holds against what the LOCAL `safes.toml` requires today, carrying the threshold
    /// the file itself states when the two disagree.
    pub quorum: Quorum,
    /// Owners with no signature yet.
    pub missing: Vec<Address>,
    /// Other digests competing for the same (Safe, chain, nonce).
    pub rivals: Vec<B256>,
    /// Milliseconds since this machine's kernel stamped the bundle directory. `created_at_ms` is
    /// a peer's wall clock and a future one would render as brand new for ever, so age is taken
    /// from the local clock instead.
    pub age_ms: u64,
}

/// What a merge took in.
pub struct Merged {
    /// Signers whose signatures were not already held.
    pub added: Vec<Address>,
    /// The union afterwards.
    pub union: SafeTxBundle,
    /// What that union holds against what the LOCAL `safes.toml` requires today.
    pub quorum: Quorum,
}

/// The `execTransaction` call the operator broadcasts with their own tooling. hot_cheese has no
/// RPC client and never will: it assembles the blob and stops there.
#[derive(Serialize)]
pub struct Execution {
    /// The Safe to call `execTransaction` on.
    pub safe: Address,
    /// Chain the call belongs to.
    #[serde(with = "hc_core::wire::u256")]
    pub chain_id: U256,
    pub to: Address,
    #[serde(with = "hc_core::wire::u256")]
    pub value: U256,
    pub data: Bytes,
    /// `Enum.Operation` as the ABI takes it: 0 CALL, 1 DELEGATECALL.
    pub operation: u8,
    #[serde(with = "hc_core::wire::u256")]
    pub safe_tx_gas: U256,
    #[serde(with = "hc_core::wire::u256")]
    pub base_gas: U256,
    #[serde(with = "hc_core::wire::u256")]
    pub gas_price: U256,
    pub gas_token: Address,
    pub refund_receiver: Address,
    /// The Safe's own nonce, which the digest covers but `execTransaction` does not take.
    #[serde(with = "hc_core::wire::u256")]
    pub nonce: U256,
    /// The collected `r‖s‖v`, concatenated ascending by signer.
    pub signatures: Bytes,
}

/// Group bundles by the slot they compete for, ascending, each slot's bundles ascending by
/// digest. A slot holding more than one bundle is a rival pair: two mutually exclusive
/// transactions are in flight, and whichever lands first burns the other — which is why `list`
/// says so loudly instead of showing two healthy-looking rows.
pub fn slots(loaded: Vec<Loaded>) -> Vec<(Slot, Vec<Loaded>)> {
    let mut grouped: HashMap<Slot, Vec<Loaded>> = HashMap::new();
    for one in loaded {
        grouped
            .entry(Slot::of(&one.bundle.intent))
            .or_default()
            .push(one);
    }
    let mut out: Vec<(Slot, Vec<Loaded>)> = grouped.into_iter().collect();
    out.sort_by_key(|(slot, _)| *slot);
    for (_, bundles) in &mut out {
        bundles.sort_by_key(|one| one.hash);
    }
    out
}

pub fn bundle_dir(hash: B256) -> PathBuf {
    bundles_dir().join(hash.to_string())
}

/// Parse only the one spelling this crate creates and the transport admits. `B256::from_str`
/// also accepts upper-case and prefixless hex; treating those aliases as bundle directories
/// would let two paths occupy one in-memory hash slot and make incremental ingestion account for
/// whichever alias happened to sort last.
pub(crate) fn canonical_bundle_hash(name: &OsStr) -> Option<B256> {
    let text = name.to_str()?;
    let hash = text.parse::<B256>().ok()?;
    (text == hash.to_string()).then_some(hash)
}

pub(crate) fn canonical_bundle_file_name(name: &OsStr) -> bool {
    let Some(text) = name.to_str() else {
        return false;
    };
    text == SEED_FILE
        || text
            .strip_suffix(BUNDLE_SUFFIX)
            .and_then(|stem| stem.parse::<Address>().ok())
            .is_some_and(|address| text == format!("{address:#x}{BUNDLE_SUFFIX}"))
}

/// Open a final-component directory without following a symlink and require that this uid owns
/// it. Bundle paths are later used for writes and recursive retirement, so a directory-looking
/// symlink is not equivalent to a directory here.
pub(crate) fn owned_directory_exists(path: &Path) -> std::io::Result<bool> {
    let directory = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let metadata = directory.metadata()?;
    // SAFETY: `geteuid` has no preconditions and changes no process state.
    let ours = unsafe { libc::geteuid() };
    if !metadata.file_type().is_dir() || metadata.uid() != ours {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "bundle directory must be a real directory owned by this user: {}",
                path.display()
            ),
        ));
    }
    Ok(true)
}

/// Create an owner-only directory if absent, then validate it through an `O_NOFOLLOW` descriptor.
pub(crate) fn ensure_owned_directory(path: &Path) -> std::io::Result<()> {
    if !owned_directory_exists(path)? {
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = directory.metadata()?;
    // SAFETY: `geteuid` has no preconditions and changes no process state.
    let ours = unsafe { libc::geteuid() };
    if !metadata.file_type().is_dir() || metadata.uid() != ours {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "bundle directory is not owner-controlled",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// The Safe a bundle names, as the LOCAL `safes.toml` states it. Who may sign and how many must
/// are read here and nowhere else: both sit outside `safeTxHash`, so the copy in a bundle file is
/// whatever the device that wrote it chose, and the file that won a directory-creation race must
/// not get to state them for every peer. A Safe this machine does not describe is a refusal, since
/// there is then nothing to judge a signature against.
fn safe_of(intent: &SafeTxIntent) -> Result<SafeEntry, BundleErr> {
    Ok(Safes::load()?.find(intent.safe, intent.chain_id)?.clone())
}

/// What a bundle holds against what `safes.toml` requires today.
pub fn quorum(bundle: &SafeTxBundle) -> Result<Quorum, BundleErr> {
    Ok(bundle.quorum(safe_of(&bundle.intent)?.threshold))
}

/// The union of every file in `dir`, bound to the digest the directory is named for. Files are
/// merged in name order only so that a failure is reproducible; the merge itself is
/// commutative, so the result does not depend on it.
///
/// `threshold` and `created_at_ms` are not covered by `safeTxHash`, so they are neither evidence
/// nor grounds for refusal: every file is normalised onto the reference file's pair before the
/// merge, and a signature that is valid for the digest and made by an owner is taken whatever
/// coordination its file happened to carry. What the bundle is judged BY is [`safe_of`].
///
/// The structural check runs before the recovery, as ingestion does it: that a name binds its
/// contents costs a comparison, where recovering the signature it names costs an ecrecover.
fn load_dir(dir: &Path, hash: B256) -> Result<SafeTxBundle, BundleErr> {
    if !owned_directory_exists(dir)? {
        return Err(BundleErr::NoSuchBundle {
            dir: dir.to_path_buf(),
        });
    }
    let mut files = Vec::new();
    for (at, entry) in std::fs::read_dir(dir)?.enumerate() {
        if at >= MAX_ENUMERATED_ENTRIES {
            return Err(BundleErr::TooManyDirectoryEntries {
                dir: dir.to_path_buf(),
                max: MAX_ENUMERATED_ENTRIES,
            });
        }
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry.file_name().to_string_lossy().ends_with(BUNDLE_SUFFIX)
        {
            let name = entry.file_name();
            if !canonical_bundle_file_name(&name) {
                return Err(BundleErr::InvalidBundleFileName { path: entry.path() });
            }
            if files.len() >= MAX_FILES_PER_BUNDLE {
                return Err(BundleErr::TooManyBundleFiles {
                    dir: dir.to_path_buf(),
                    found: files.len() + 1,
                    max: MAX_FILES_PER_BUNDLE,
                });
            }
            files.push(entry.path());
        }
    }
    files.sort_by(|a, b| {
        let a_seed = a.file_name().is_some_and(|name| name == SEED_FILE);
        let b_seed = b.file_name().is_some_and(|name| name == SEED_FILE);
        b_seed.cmp(&a_seed).then_with(|| a.cmp(b))
    });
    let mut parsed = Vec::with_capacity(files.len());
    for path in &files {
        let bytes = hc_core::read_regular_file_bounded(path, MAX_FILE_BYTES)?;
        let one: SafeTxBundle = hc_core::wire::strict_json_from_slice(&bytes)?;
        let file = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| BundleErr::InvalidBundleFileName { path: path.clone() })?;
        let filed_correctly = if file == SEED_FILE {
            one.signatures.is_empty()
        } else {
            let owner = file
                .strip_suffix(BUNDLE_SUFFIX)
                .and_then(|stem| stem.parse::<Address>().ok());
            one.signatures.len() == 1 && owner == Some(one.signatures[0].signer)
        };
        if !filed_correctly {
            return Err(BundleErr::MisfiledBundle { path: path.clone() });
        }
        parsed.push(one);
    }
    if parsed.is_empty() {
        return Err(BundleErr::EmptyBundle {
            dir: dir.to_path_buf(),
        });
    }
    let mut merged = parsed.remove(0);
    let safe = safe_of(&merged.intent)?;
    merged.validate(&safe.owners)?;
    for mut one in parsed {
        one.threshold = merged.threshold;
        one.created_at_ms = merged.created_at_ms;
        merged.merge(one, &safe.owners)?;
    }
    let digest = merged.digest();
    if digest != hash {
        return Err(BundleErr::NotItsDigest {
            dir: dir.to_path_buf(),
            digest,
        });
    }
    Ok(merged)
}

/// Every bundle in the store, ascending by digest. A directory whose name is not a digest is
/// not a bundle and is skipped; one that will not load is skipped LOUDLY rather than taking
/// the listing down with it, because a peer can put bytes in this tree and one poisoned
/// directory must not cost the operator sight of the others.
///
/// [`MAX_BUNDLE_DIRS`] bounds the ecrecovers one listing spends, so past it the digest-lowest are
/// loaded and the overflow is reported: a tree that grew — which only this machine's own writes
/// can do, since arrivals are capped long before here — must not make every listing, and with it
/// every poll, fail outright.
fn load_all() -> Result<Vec<Loaded>, BundleErr> {
    let root = bundles_dir();
    if !owned_directory_exists(&root)? {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for (at, entry) in std::fs::read_dir(&root)?.enumerate() {
        if at >= MAX_ENUMERATED_ENTRIES {
            return Err(BundleErr::TooManyDirectoryEntries {
                dir: root.clone(),
                max: MAX_ENUMERATED_ENTRIES,
            });
        }
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if let Some(hash) = canonical_bundle_hash(&entry.file_name()) {
            found.push((hash, entry.path()));
        }
    }
    found.sort_by_key(|(hash, _)| *hash);
    if found.len() > MAX_BUNDLE_DIRS {
        tracing::warn!(
            found = found.len(),
            max = MAX_BUNDLE_DIRS,
            "more bundle directories than one listing loads; retire the ones this machine is done with"
        );
        found.truncate(MAX_BUNDLE_DIRS);
    }
    let mut out = Vec::with_capacity(found.len());
    for (hash, dir) in found {
        match load_one(&dir, hash) {
            Ok(one) => out.push(one),
            Err(e) => {
                tracing::warn!(%hash, error = %e, "skipping a bundle directory that will not load")
            }
        }
    }
    Ok(out)
}

/// One directory's union with the local quorum already counted for it.
fn load_one(dir: &Path, hash: B256) -> Result<Loaded, BundleErr> {
    let bundle = load_dir(dir, hash)?;
    Ok(Loaded {
        hash,
        quorum: quorum(&bundle)?,
        bundle,
    })
}

/// Whatever `scope` covers that actually loads.
pub(crate) fn loaded(scope: Scope) -> Result<Vec<Loaded>, BundleErr> {
    let Scope::One(hash) = scope else {
        return load_all();
    };
    let dir = bundle_dir(hash);
    if !owned_directory_exists(&dir)? {
        return Ok(Vec::new());
    }
    match load_one(&dir, hash) {
        Ok(one) => Ok(vec![one]),
        Err(e) => {
            tracing::warn!(%hash, error = %e, "skipping a bundle directory that will not load");
            Ok(Vec::new())
        }
    }
}

/// Take one signature into the bundle and return the file that signature owns. Both adds run
/// against a digest recomputed from OUR fields: the one into the union refuses a second,
/// different signature from a signer who already has one, and the one into the fresh bundle
/// produces exactly what `0x<signer>.json` holds — that signer's signature and nothing else.
fn take(
    held: &SafeTxBundle,
    sig: CollectedSignature,
    owners: &[Address],
) -> Result<SafeTxBundle, BundleErr> {
    held.validate(owners)?;
    let mut union = held.clone();
    union.add(sig.clone(), owners)?;
    let mut one = SafeTxBundle {
        signatures: Vec::new(),
        ..held.clone()
    };
    one.add(sig, owners)?;
    Ok(one)
}

fn serialized_bundle(one: &SafeTxBundle, owners: &[Address]) -> Result<Vec<u8>, BundleErr> {
    one.validate(owners)?;
    let bytes = serde_json::to_vec_pretty(one)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(BundleErr::BundleFileTooLarge {
            size: bytes.len(),
            max: MAX_FILE_BYTES,
        });
    }
    Ok(bytes)
}

/// Ingest a `SignResponse`, this machine's own or one another device handed over. The claimed
/// `safe_tx_hash` must equal the digest we rebuilt from our own fields; a device that signed a
/// different transaction, or a hand-copied character, fails here instead of landing a signature
/// that recovers to nobody on-chain. [`take`] then ecrecovers it.
pub fn take_response(
    held: &SafeTxBundle,
    response: SignResponse,
    owners: &[Address],
) -> Result<SafeTxBundle, BundleErr> {
    let ours = held.digest();
    if response.safe_tx_hash != ours {
        return Err(BundleErr::ForeignDigest {
            ours,
            theirs: response.safe_tx_hash,
        });
    }
    take(
        held,
        CollectedSignature {
            signer: response.signer,
            signature: response.signature,
        },
        owners,
    )
}

/// Write this signer's own file, once, and state locally that this machine has written under that
/// signer name — which is what later keeps a peer flooding the same directory from moving it out.
/// An existing file holding the same signature over the same transaction is the same file:
/// coordination metadata is outside the digest and outside local truth, so a difference there is
/// not a second, conflicting claim under this signer's name.
fn write_one(
    dir: &Path,
    signer: Address,
    one: &SafeTxBundle,
    owners: &[Address],
) -> Result<(), BundleErr> {
    let path = dir.join(format!("{signer:#x}{BUNDLE_SUFFIX}"));
    if one.signatures.len() != 1 || one.signatures[0].signer != signer {
        return Err(BundleErr::MisfiledBundle { path });
    }
    let bytes = serialized_bundle(one, owners)?;
    match atomic_write_new(&path, &bytes) {
        Ok(()) => local::sign_as(signer),
        Err(hc_core::crypto::envelope::EnvErr::StdIo(error))
            if error.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            let held = hc_core::read_regular_file_bounded(&path, MAX_FILE_BYTES)?;
            let held: SafeTxBundle = hc_core::wire::strict_json_from_slice(&held)?;
            if held.signatures == one.signatures && held.digest() == one.digest() {
                local::sign_as(signer)
            } else {
                Err(BundleErr::BundleFileConflict { path })
            }
        }
        Err(error) => Err(error.into()),
    }
}

/// Start a bundle from an intent. The threshold comes from `safes.toml`, so a Safe this
/// machine does not describe cannot be collected for at all. Pushes the new directory to every
/// enrolled peer, so a co-signer sees it without being told.
pub fn new(sync: SyncMode, intent: SafeTxIntent) -> Result<B256, BundleErr> {
    Mutation::take()?.new(sync, intent)
}

fn new_local(intent: SafeTxIntent) -> Result<B256, BundleErr> {
    let safe = safe_of(&intent)?;
    let threshold = safe.threshold;
    let bundle = SafeTxBundle {
        v: hc_sign::bundle::V,
        intent,
        threshold,
        signatures: Vec::new(),
        created_at_ms: now_ms()?,
    };
    let bytes = serialized_bundle(&bundle, &safe.owners)?;
    let hash = bundle.digest();
    let dir = bundle_dir(hash);
    ensure_owned_directory(&bundles_dir())?;
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(BundleErr::BundleExists { dir })
        }
        Err(error) => return Err(error.into()),
    }
    if let Err(error) = hc_core::crypto::envelope::atomic_write_new(&dir.join(SEED_FILE), &bytes) {
        let _ = std::fs::remove_dir(&dir);
        return Err(error.into());
    }
    local::revive(hash)?;
    tracing::info!(%hash, dir = %dir.display(), threshold, "created bundle");
    Ok(hash)
}

/// What a device has to sign to join this bundle, bound to a LOCAL keystore name. The name is
/// rebound in memory only — `key` is outside the EIP-712 encoding — so the digest, and
/// therefore the directory, is untouched. Pulls first, so a machine that has never seen this
/// bundle can still be asked to sign it.
pub fn intent_to_sign(sync: SyncMode, hash: B256, key: &str) -> Result<SafeTxIntent, BundleErr> {
    sync.pull(Scope::One(hash));
    let _mutation = Mutation::take()?;
    Ok(load_dir(&bundle_dir(hash), hash)?.intent_for(key))
}

/// Take a response into the bundle on disk, then hand back the union that is actually there
/// afterwards. Pushes it, so the co-signer's next read already has it.
///
/// The response is held on disk BEFORE anything that can fail runs, and holding it also claims
/// the bundle as this machine's own. A biometric was already spent on it, so a lock this process
/// could not take, a directory that would not load, or a write that ran out of disk must leave the
/// approval recoverable instead of dropping it: an approval is released only when the write it
/// authorised actually landed, and the next collect for this bundle takes whatever is still held.
/// The file this device writes states the threshold THIS machine knows, never the coordination a
/// peer put in whichever seed arrived first.
pub fn collect(
    sync: SyncMode,
    hash: B256,
    response: SignResponse,
) -> Result<SafeTxBundle, BundleErr> {
    local::hold(hash, &response)?;
    let mutation = Mutation::take()?;
    let dir = bundle_dir(hash);
    let mut held = load_dir(&dir, hash)?;
    let safe = safe_of(&held.intent)?;
    held.threshold = safe.threshold;
    let mut taken = Vec::new();
    let mut refused = None;
    for (path, pending) in local::held(hash)? {
        let signer = pending.signer;
        match take_response(&held, pending, &safe.owners)
            .and_then(|one| write_one(&dir, signer, &one, &safe.owners))
        {
            Ok(()) => {
                if let Err(error) = local::release(&path) {
                    tracing::warn!(%hash, %signer, %error, "cannot release an approval this collect landed");
                }
                taken.push(signer);
            }
            Err(error) => {
                tracing::warn!(%hash, %signer, %error, "a held approval did not join this bundle and stays held");
                if refused.is_none() {
                    refused = Some(error);
                }
            }
        }
    }
    if let Some(error) = refused {
        if taken.is_empty() {
            return Err(error);
        }
    }
    local::revive(hash)?;
    let after = load_dir(&dir, hash)?;
    let quorum = after.quorum(safe.threshold);
    tracing::info!(
        %hash,
        ?taken,
        have = quorum.have,
        threshold = quorum.threshold,
        met = quorum.met,
        "collected signature"
    );
    drop(mutation);
    sync.push(Scope::One(hash));
    Ok(after)
}

/// The merged view: who has signed, who is still expected, and what else competes for the same
/// nonce. Pulls the bundle's own directory first.
pub fn status(sync: SyncMode, hash: B256) -> Result<BundleStatus, BundleErr> {
    sync.pull(Scope::One(hash));
    let _mutation = Mutation::take()?;
    let dir = bundle_dir(hash);
    let held = load_dir(&dir, hash)?;
    let entry = safe_of(&held.intent)?;
    let mut missing = Vec::new();
    for owner in &entry.owners {
        if !held.signatures.iter().any(|sig| &sig.signer == owner) {
            missing.push(*owner);
        }
    }
    let mine = Slot::of(&held.intent);
    let mut rivals = Vec::new();
    for (slot, bundles) in slots(load_all()?) {
        if slot != mine {
            continue;
        }
        for other in &bundles {
            if other.hash != hash {
                rivals.push(other.hash);
            }
        }
    }
    Ok(BundleStatus {
        hash,
        age_ms: ingest::local_age_ms(&dir, now_ms()?)?,
        quorum: held.quorum(entry.threshold),
        bundle: held,
        missing,
        rivals,
    })
}

/// Every bundle, grouped by the slot it competes for. Pulls the whole tree first, because
/// finding out what a co-signer started is the entire point of asking.
pub fn list(sync: SyncMode) -> Result<Vec<(Slot, Vec<Loaded>)>, BundleErr> {
    sync.pull(Scope::All);
    let mutation = Mutation::take()?;
    list_locked(&mutation)
}

/// Read the grouped queue while a caller-held mutation claim prevents any check/file gap.
pub fn list_locked(_mutation: &Mutation) -> Result<Vec<(Slot, Vec<Loaded>)>, BundleErr> {
    Ok(slots(load_all()?))
}

/// Read a bundle a human moved by hand: a single file, or a whole directory copied over.
pub fn read_bundle(path: &Path, hash: B256) -> Result<SafeTxBundle, BundleErr> {
    if path.is_dir() {
        return load_dir(path, hash);
    }
    let bytes = hc_core::read_regular_file_bounded(path, MAX_FILE_BYTES)?;
    let bundle: SafeTxBundle = hc_core::wire::strict_json_from_slice(&bytes)?;
    bundle.validate(&safe_of(&bundle.intent)?.owners)?;
    Ok(bundle)
}

/// Union an external bundle into the store. Every signature lands in its own file, so an
/// import is byte-identical to what the signing device would have written, and the result is
/// pushed to the peers like any other write.
pub fn merge(sync: SyncMode, hash: B256, incoming: SafeTxBundle) -> Result<Merged, BundleErr> {
    let mutation = Mutation::take()?;
    let dir = bundle_dir(hash);
    let held = load_dir(&dir, hash)?;
    let theirs = incoming.digest();
    if theirs != hash {
        return Err(BundleErr::ForeignDigest { ours: hash, theirs });
    }
    let safe = safe_of(&held.intent)?;
    let mut held = held;
    held.threshold = safe.threshold;
    let mut union = held.clone();
    let mut incoming = incoming;
    incoming.threshold = union.threshold;
    incoming.created_at_ms = union.created_at_ms;
    union.merge(incoming.clone(), &safe.owners)?;
    let mut added = Vec::new();
    for sig in incoming.signatures {
        let signer = sig.signer;
        let already_held = held.signatures.iter().any(|held| held.signer == signer);
        write_one(&dir, signer, &take(&held, sig, &safe.owners)?, &safe.owners)?;
        if !already_held {
            added.push(signer);
        }
    }
    local::revive(hash)?;
    let quorum = union.quorum(safe.threshold);
    tracing::info!(%hash, have = quorum.have, threshold = quorum.threshold, met = quorum.met, "merged");
    drop(mutation);
    sync.push(Scope::One(hash));
    Ok(Merged {
        added,
        union,
        quorum,
    })
}

/// The assembled call. Everything it is judged against is read from `safes.toml` at this moment,
/// because this is the last one before gas is spent: the owner list through the re-validation the
/// union already ran under, and the threshold as the count below. The bundle file's own threshold
/// decides nothing here — a peer wrote it, and letting it disagree would hand any peer a veto over
/// executing. Pulls first, so the final signer assembles from everything that exists rather than
/// everything that reached this disk.
pub fn export(sync: SyncMode, hash: B256) -> Result<Execution, BundleErr> {
    sync.pull(Scope::One(hash));
    let _mutation = Mutation::take()?;
    let held = load_dir(&bundle_dir(hash), hash)?;
    let safe = safe_of(&held.intent)?;
    held.validate(&safe.owners)?;
    let quorum = held.quorum(safe.threshold);
    if !quorum.met {
        return Err(BundleErr::ThresholdNotMet {
            have: quorum.have,
            threshold: quorum.threshold,
        });
    }
    let i = &held.intent;
    Ok(Execution {
        safe: i.safe,
        chain_id: i.chain_id,
        to: i.to,
        value: i.value,
        data: i.data.clone(),
        operation: i.operation.as_u8(),
        safe_tx_gas: i.safe_tx_gas,
        base_gas: i.base_gas,
        gas_price: i.gas_price,
        gas_token: i.gas_token,
        refund_receiver: i.refund_receiver,
        nonce: i.nonce,
        signatures: held.packed(),
    })
}

/// Retire a bundle, locally and only locally. Manual, and honestly so: with no RPC client this
/// machine cannot learn the Safe's on-chain nonce. It deliberately does not sync — a push cannot
/// delete, because no transfer in this module carries `--delete` — so the retirement is recorded
/// where no peer writes, and the next pull that brings the directory back finds it removed again.
///
/// A directory that will not LOAD is retired anyway. A peer can leave one behind — a bundle for a
/// Safe this `safes.toml` no longer describes is the ordinary case — and a retirement that first
/// demanded a readable union is exactly how such a directory came to hold its (safe, chain, nonce)
/// slot with no way for the operator to get rid of it. The union is then the one thing this
/// cannot report, so it says so with [`BundleErr::RetiredUnreadable`] AFTER the bundle is gone.
pub fn rm(hash: B256) -> Result<SafeTxBundle, BundleErr> {
    let _mutation = Mutation::take()?;
    let dir = bundle_dir(hash);
    if !owned_directory_exists(&dir)? {
        return Err(BundleErr::NoSuchBundle { dir });
    }
    let held = load_dir(&dir, hash);
    local::retire(hash)?;
    if let Err(error) = local::discard(hash) {
        tracing::warn!(%hash, %error, "cannot clear the approvals held for a bundle being retired");
    }
    ingest::remove_flat_directory(&dir)?;
    match held {
        Ok(held) => {
            tracing::info!(
                %hash,
                had = held.signatures.len(),
                nonce = %held.intent.nonce,
                "retired bundle"
            );
            Ok(held)
        }
        Err(error) => {
            tracing::warn!(%hash, %error, "retired a bundle this machine could not read");
            Err(BundleErr::RetiredUnreadable { dir })
        }
    }
}

/// The transaction framed for another device's camera. The frame carries the FIELDS, so the far
/// device rebuilds the digest itself and shows its own decoded summary before its own
/// biometric — a QR that lied would be caught there, which is why no digest is transmitted.
pub fn qr_frames(hash: B256) -> Result<Vec<Vec<u8>>, BundleErr> {
    let _mutation = Mutation::take()?;
    let held = load_dir(&bundle_dir(hash), hash)?;
    Ok(frames(
        QrKind::SafeTxRequest,
        &serde_json::to_vec(&Intent::SafeTx(held.intent))?,
    )?)
}

/// A signature that was not there at the previous poll.
pub struct Arrival {
    /// The bundle it joined.
    pub hash: B256,
    /// Who signed.
    pub signer: Address,
    /// What the bundle holds afterwards against what the LOCAL `safes.toml` requires.
    pub quorum: Quorum,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hc_sign::intent::Operation;
    use k256::ecdsa::SigningKey;
    use std::os::unix::fs::symlink;

    pub(crate) fn intent(nonce: u64) -> SafeTxIntent {
        SafeTxIntent {
            key: "TRADER".into(),
            safe: Address::from([0x11u8; 20]),
            chain_id: U256::from(1u64),
            to: Address::from([0x22u8; 20]),
            value: U256::from(7u64),
            data: Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]),
            operation: Operation::Call,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::from(nonce),
        }
    }

    pub(crate) fn bundle(intent: SafeTxIntent) -> SafeTxBundle {
        SafeTxBundle {
            v: hc_sign::bundle::V,
            intent,
            threshold: 2,
            signatures: Vec::new(),
            created_at_ms: 1_700_000_000_000,
        }
    }

    /// One test at a time owns `HOT_CHEESE_HOME`: it is process-wide, and every path that reads
    /// local truth reads it through `home_dir()` on every call.
    pub(crate) static HOME: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// The address fixture key `seed` signs as.
    pub(crate) fn signer_of(seed: u8) -> Address {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("a fixed non-zero scalar is a key");
        let point = sk.verifying_key().to_encoded_point(false);
        Address::from_slice(&hc_core::crypto::keccak256(&point.as_bytes()[1..])[12..])
    }

    pub(crate) fn owners_of(seeds: impl IntoIterator<Item = u8>) -> Vec<Address> {
        let mut out = Vec::new();
        for seed in seeds {
            out.push(signer_of(seed));
        }
        out
    }

    /// What a device hands back after its own biometric: a signature over the digest IT rebuilt.
    pub(crate) fn signed(seed: u8, held: &SafeTxBundle) -> SignResponse {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("a fixed non-zero scalar is a key");
        let digest = held.digest();
        let (sig, recid) = sk
            .sign_prehash_recoverable(digest.as_slice())
            .expect("signing a fixed prehash with a fixed key");
        let mut raw = sig.to_bytes().to_vec();
        raw.push(27 + recid.to_byte());
        SignResponse {
            safe_tx_hash: digest,
            signature: Bytes::from(raw),
            signer: signer_of(seed),
        }
    }

    /// A throwaway home holding an empty bundle tree and the `safes.toml` every judgement in
    /// these tests is made against, pointed at by the environment.
    pub(crate) fn home(name: &str, threshold: u8, seeds: impl IntoIterator<Item = u8>) -> PathBuf {
        let root = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("bundles")).expect("make the test home");
        std::env::set_var("HOT_CHEESE_HOME", &root);
        write_safes(&root, threshold, seeds);
        root
    }

    /// The `safes.toml` these tests state their local truth in: the fixture Safe, its threshold,
    /// and the fixture keys that are its owners.
    pub(crate) fn safes_toml(threshold: u8, seeds: impl IntoIterator<Item = u8>) -> String {
        let mut listed = Vec::new();
        for owner in owners_of(seeds) {
            listed.push(format!("\"{owner:#x}\""));
        }
        format!(
            "[[safe]]\naddress = \"{:#x}\"\nchain_id = 1\nthreshold = {threshold}\nowners = [{}]\n",
            Address::from([0x11u8; 20]),
            listed.join(", ")
        )
    }

    pub(crate) fn write_safes(root: &Path, threshold: u8, seeds: impl IntoIterator<Item = u8>) {
        std::fs::write(
            root.join("bundles").join("safes.toml"),
            safes_toml(threshold, seeds),
        )
        .expect("write safes.toml");
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make the test dir");
        dir
    }

    #[test]
    fn bundle_directory_names_have_one_canonical_spelling() {
        let hash = B256::from([0xabu8; 32]);
        let canonical = hash.to_string();
        assert_eq!(canonical_bundle_hash(OsStr::new(&canonical)), Some(hash));
        assert_eq!(
            canonical_bundle_hash(OsStr::new(canonical.trim_start_matches("0x"))),
            None,
            "the parser accepts prefixless hex, but the bundle namespace must not"
        );
        assert_eq!(
            canonical_bundle_hash(OsStr::new(&canonical.to_uppercase())),
            None,
            "case aliases must not collide in the ingestion hash map"
        );
    }

    /// The whole point of one file per signer: two devices write two names with no lock and no
    /// coordination, and reading takes the union. The threshold is reached by that union alone,
    /// the packed blob is the ascending concatenation `checkNSignatures` demands, and the
    /// directory stays bound to the digest it is named for — a file for another transaction
    /// dropped into it is refused, never absorbed.
    #[test]
    fn two_devices_write_two_files_and_the_union_reaches_the_threshold() {
        let _env = HOME.lock();
        let root = home("hot_cheese_bundle_union", 2, [0x11, 0x22, 0x33]);
        let owners = owners_of([0x11, 0x22, 0x33]);
        let seed = bundle(intent(3));
        let hash = seed.digest();
        let dir = bundle_dir(hash);
        std::fs::create_dir_all(&dir).expect("make the bundle dir");

        for device in [0x11u8, 0x22u8] {
            let response = signed(device, &seed);
            let signer = response.signer;
            let one =
                take_response(&seed, response, &owners).expect("a signature over our own digest");
            assert_eq!(one.signatures.len(), 1);
            write_one(&dir, signer, &one, &owners).expect("write the signer's own file");
        }
        assert_eq!(
            std::fs::read_dir(&dir).expect("read the dir").count(),
            2,
            "two devices, two files, no collision"
        );

        let union = load_dir(&dir, hash).expect("the union loads");
        assert_eq!(union.signatures.len(), 2);
        assert!(quorum(&union).expect("the local quorum").met);
        assert_eq!(union.packed().len(), 130);
        let signers: Vec<Address> = union.signatures.iter().map(|s| s.signer).collect();
        let mut ascending = signers.clone();
        ascending.sort();
        assert_eq!(signers, ascending);

        let elsewhere = bundle(intent(4));
        let stray = signed(0x33, &elsewhere);
        let signer = stray.signer;
        let one = take_response(&elsewhere, stray, &owners)
            .expect("their own bundle takes their own signature");
        write_one(&dir, signer, &one, &owners).expect("misfile it");
        assert!(matches!(
            load_dir(&dir, hash),
            Err(BundleErr::Verify(
                hc_sign::bundle::BundleErr::DigestMismatch { .. }
            ))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bundle_writers_enforce_the_ingest_size_ceiling() {
        let mut oversized = bundle(intent(3));
        oversized.intent.data = Bytes::from(vec![0u8; MAX_FILE_BYTES as usize]);
        assert!(matches!(
            serialized_bundle(&oversized, &[]),
            Err(BundleErr::BundleFileTooLarge {
                max: MAX_FILE_BYTES,
                ..
            })
        ));
    }

    #[test]
    fn signer_files_are_create_only_and_idempotent() {
        let _env = HOME.lock();
        let root = home("hot_cheese_bundle_immutable_signer_home", 2, [0x11]);
        let dir = temp("hot_cheese_bundle_immutable_signer");
        let seed = bundle(intent(3));
        let response = signed(0x11, &seed);
        let signer = response.signer;
        let owners = owners_of([0x11]);
        let one = take_response(&seed, response, &owners).expect("valid signer file");
        let path = dir.join(format!("{signer:#x}{BUNDLE_SUFFIX}"));

        let compact = serde_json::to_vec(&one).expect("serialize compact fixture");
        std::fs::write(&path, &compact).expect("seed existing signer file");
        write_one(&dir, signer, &one, &owners).expect("the same semantic file is idempotent");
        assert_eq!(std::fs::read(&path).unwrap(), compact);

        let elsewhere = bundle(intent(4));
        let foreign = signed(0x11, &elsewhere);
        let foreign = take_response(&elsewhere, foreign, &owners).expect("valid foreign file");
        let foreign_bytes = serde_json::to_vec(&foreign).expect("serialize foreign fixture");
        std::fs::write(&path, &foreign_bytes).expect("replace fixture outside the writer");
        assert!(matches!(
            write_one(&dir, signer, &one, &owners),
            Err(BundleErr::BundleFileConflict { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), foreign_bytes);
        assert!(
            root.join("bundle-signers")
                .join(format!("{signer:#x}"))
                .is_file(),
            "the machine states the signer names it has written under"
        );

        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_bundle_directory_symlink_is_never_traversed() {
        let target = temp("hot_cheese_bundle_symlink_target");
        let hash = bundle(intent(3)).digest();
        let link = std::env::temp_dir().join("hot_cheese_bundle_symlink_link");
        let _ = std::fs::remove_file(&link);
        symlink(&target, &link).expect("make a directory-looking symlink");

        assert!(matches!(load_dir(&link, hash), Err(BundleErr::Io(_))));

        std::fs::remove_file(link).unwrap();
        std::fs::remove_dir_all(target).unwrap();
    }

    #[test]
    fn retirement_never_recurses_into_an_unexpected_nested_directory() {
        let dir = temp("hot_cheese_bundle_retire_nested");
        let seed = bundle(intent(37));
        std::fs::write(
            dir.join(SEED_FILE),
            serde_json::to_vec(&seed).expect("serialize seed"),
        )
        .unwrap();
        let nested = dir.join("not-bundle-state");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("KEEP"), b"unrelated").unwrap();

        assert!(matches!(
            ingest::remove_flat_directory(&dir),
            Err(ingest::IngestErr::NestedEntry { .. })
        ));
        assert_eq!(std::fs::read(nested.join("KEEP")).unwrap(), b"unrelated");
        assert!(dir.is_dir(), "the directory holding it is kept, and named");
        assert!(
            !dir.join(SEED_FILE).exists(),
            "the bundle's own state still goes, or its slot is held for ever"
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    /// `threshold` and `created_at_ms` are outside `safeTxHash`, so whichever device won the race
    /// to create the directory chose both, and every peer copies them. The union must therefore
    /// take the LOCAL `safes.toml` threshold, and must take a cryptographically valid signature
    /// whatever coordination its file claimed — otherwise one peer decides for ever how many
    /// signatures everyone needs, and every honest signature that disagrees is quarantined.
    #[test]
    fn the_local_safes_toml_states_the_threshold_and_a_peer_file_cannot() {
        let _env = HOME.lock();
        let root = home("hot_cheese_bundle_local_threshold", 3, [0x11, 0x22, 0x33]);
        let seed = bundle(intent(3));
        let hash = seed.digest();
        let dir = bundle_dir(hash);
        std::fs::create_dir_all(&dir).expect("make the bundle dir");
        std::fs::write(
            dir.join(SEED_FILE),
            serde_json::to_vec(&seed).expect("serialize the peer's seed"),
        )
        .unwrap();

        let response = signed(0x11, &seed);
        let signer = response.signer;
        let mut disagreeing = take_response(&seed, response, &owners_of([0x11, 0x22, 0x33]))
            .expect("a valid signature");
        disagreeing.threshold = 1;
        disagreeing.created_at_ms = 1;
        std::fs::write(
            dir.join(format!("{signer:#x}{BUNDLE_SUFFIX}")),
            serde_json::to_vec(&disagreeing).expect("serialize the disagreeing file"),
        )
        .unwrap();

        let union = load_dir(&dir, hash).expect("a valid signature is taken whatever it claimed");
        assert_eq!(union.signatures.len(), 1);
        let quorum = quorum(&union).expect("the local quorum");
        assert_eq!(quorum.threshold, 3, "safes.toml states it, not the file");
        assert!(!quorum.met);
        assert_eq!(
            quorum.stated,
            Some(2),
            "what a peer file claims is reported, never counted"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    /// A biometric is spent before the local write can run, so an approval that could not land —
    /// a claim another process held, a directory that would not load — must survive on disk and be
    /// taken by the next collect. Dropping it spends an operator's Touch ID for nothing.
    #[test]
    fn an_approval_held_after_a_failed_collect_lands_at_the_next_one() {
        let _env = HOME.lock();
        let root = home("hot_cheese_bundle_held_approval", 2, [0x11, 0x22]);
        let seed = bundle(intent(3));
        let hash = seed.digest();
        let dir = bundle_dir(hash);
        std::fs::create_dir_all(&dir).expect("make the bundle dir");
        std::fs::write(
            dir.join(SEED_FILE),
            serde_json::to_vec(&seed).expect("serialize the seed"),
        )
        .unwrap();

        local::hold(hash, &signed(0x11, &seed)).expect("an approval the write could not take");
        let after = collect(SyncMode::Off, hash, signed(0x22, &seed)).expect("the next collect");
        assert_eq!(
            after.signatures.len(),
            2,
            "the approval that was already spent is not lost"
        );
        assert!(local::held(hash).expect("the spool").is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }

    /// One file in the spool that cannot be READ must cost itself and nothing else. It used to
    /// cost every later collect for that bundle — after the biometric — which strands approvals
    /// for good, and the file is not even one this machine wrote.
    #[test]
    fn an_unreadable_held_file_cannot_poison_a_later_collect() {
        let _env = HOME.lock();
        let root = home("hot_cheese_bundle_spool_poison", 2, [0x11, 0x22]);
        let seed = bundle(intent(3));
        let hash = seed.digest();
        let dir = bundle_dir(hash);
        std::fs::create_dir_all(&dir).expect("make the bundle dir");
        std::fs::write(
            dir.join(SEED_FILE),
            serde_json::to_vec(&seed).expect("serialize the seed"),
        )
        .unwrap();

        let spool = root.join("bundle-spool").join(hash.to_string());
        std::fs::create_dir_all(&spool).expect("make the spool dir");
        let poison = spool.join(format!("{:#x}{BUNDLE_SUFFIX}", Address::ZERO));
        std::fs::write(&poison, b"{}").expect("plant unreadable bytes");
        std::fs::set_permissions(&poison, std::fs::Permissions::from_mode(0o000)).unwrap();

        for at in [0x11u8, 0x22u8] {
            let after = collect(SyncMode::Off, hash, signed(at, &seed))
                .expect("a collect behind a spent biometric still lands");
            assert_eq!(after.signatures.len(), usize::from(at == 0x22) + 1);
        }
        assert!(
            poison.exists(),
            "what cannot be read is kept, not destroyed"
        );

        std::fs::set_permissions(&poison, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A directory that will not LOAD must still be removable, or a peer's bundle for a Safe this
    /// machine stopped describing holds its (safe, chain, nonce) slot with nothing the operator
    /// can do about it. The retirement is what has to happen; the union is the one thing this
    /// cannot report, and it says so rather than refusing.
    #[test]
    fn a_bundle_that_will_not_load_is_still_retired() {
        let _env = HOME.lock();
        let root = home("hot_cheese_bundle_rm_unloadable", 2, [0x11, 0x22]);
        let seed = bundle(intent(3));
        let hash = seed.digest();
        let dir = bundle_dir(hash);
        std::fs::create_dir_all(&dir).expect("make the bundle dir");
        std::fs::write(
            dir.join(SEED_FILE),
            serde_json::to_vec(&seed).expect("serialize the seed"),
        )
        .unwrap();
        std::fs::write(dir.join(".unsigned.json.9Kx1"), b"half a transfer").unwrap();
        std::fs::write(root.join("bundles").join("safes.toml"), "safe = []\n").unwrap();

        assert!(matches!(
            load_dir(&dir, hash),
            Err(BundleErr::UnknownSafe { .. })
        ));
        assert!(matches!(rm(hash), Err(BundleErr::RetiredUnreadable { .. })));
        assert!(!dir.exists(), "including the transfer artefact it held");
        assert!(root
            .join("bundle-tombstones")
            .join(hash.to_string())
            .is_file());

        std::fs::remove_dir_all(root).unwrap();
    }

    /// A biometric is spent before the write, so the write failing — a full disk, a directory
    /// that turned read-only — must leave the approval exactly where it is. Releasing it on ANY
    /// error is how an approval was lost in the one case the spool exists for.
    #[test]
    fn an_approval_survives_a_write_that_failed() {
        let _env = HOME.lock();
        let root = home("hot_cheese_bundle_write_failure", 2, [0x11, 0x22]);
        let seed = bundle(intent(3));
        let hash = seed.digest();
        let dir = bundle_dir(hash);
        std::fs::create_dir_all(&dir).expect("make the bundle dir");
        std::fs::write(
            dir.join(SEED_FILE),
            serde_json::to_vec(&seed).expect("serialize the seed"),
        )
        .unwrap();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(collect(SyncMode::Off, hash, signed(0x11, &seed)).is_err());
        assert_eq!(
            local::held(hash).expect("the spool").len(),
            1,
            "an approval the write could not take is still held"
        );

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let after =
            collect(SyncMode::Off, hash, signed(0x22, &seed)).expect("the next collect takes both");
        assert_eq!(after.signatures.len(), 2);
        assert!(local::held(hash).expect("the spool").is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }

    /// A Safe executes each nonce once, so two digests under one (safe, chain_id, nonce) are
    /// transactions that cannot both land. Grouping has to put exactly those together and leave
    /// a different nonce — and a different chain — in slots of their own.
    #[test]
    fn rivals_are_the_bundles_sharing_a_safe_chain_and_nonce() {
        let mut other_payload = intent(3);
        other_payload.value = U256::from(9u64);
        let mut other_chain = intent(3);
        other_chain.chain_id = U256::from(8453u64);

        let mut all = Vec::new();
        for i in [intent(3), other_payload, other_chain, intent(4)] {
            let bundle = bundle(i);
            all.push(Loaded {
                hash: bundle.digest(),
                quorum: bundle.quorum(2),
                bundle,
            });
        }
        let digests: Vec<B256> = all.iter().map(|one| one.hash).collect();

        let grouped = slots(all);
        assert_eq!(grouped.len(), 3, "one rival pair plus two lone slots");
        let mut rivals = Vec::new();
        for (_, bundles) in &grouped {
            if bundles.len() > 1 {
                for one in bundles {
                    rivals.push(one.hash);
                }
            }
        }
        rivals.sort();
        let mut expected = vec![digests[0], digests[1]];
        expected.sort();
        assert_eq!(rivals, expected);
    }

    /// `add-sig` takes bytes a human moved between machines, so the hash they claim is checked
    /// against the one WE rebuilt from OUR fields before anything is stored: a device that
    /// signed a different transaction is refused, and so is a signature that does not recover
    /// to the address it claims.
    #[test]
    fn a_response_for_another_transaction_is_refused() {
        let ours = bundle(intent(3));
        let theirs = bundle(intent(4));

        let owners = owners_of([0x11]);
        assert!(take_response(&ours, signed(0x11, &ours), &owners).is_ok());
        assert!(matches!(
            take_response(&ours, signed(0x11, &theirs), &owners),
            Err(BundleErr::ForeignDigest { .. })
        ));

        let mut lying = signed(0x11, &ours);
        lying.signer = Address::from([0x99u8; 20]);
        assert!(matches!(
            take_response(&ours, lying, &owners),
            Err(BundleErr::Verify(
                hc_sign::bundle::BundleErr::SignerMismatch { .. }
            ))
        ));
    }

    /// `safes.toml` states the facts an assembled blob is judged against, so a term this build
    /// does not implement must fail to load rather than be dropped: an operator who wrote
    /// `quorum` would otherwise collect against a threshold nobody enforces.
    #[test]
    fn safes_toml_refuses_a_term_it_does_not_implement() {
        let good = concat!(
            "[[safe]]\n",
            "address = \"0x1111111111111111111111111111111111111111\"\n",
            "chain_id = 1\n",
            "threshold = 2\n",
            "owners = [\"0x2222222222222222222222222222222222222222\", \
             \"0x3333333333333333333333333333333333333333\"]\n",
        );
        let safes: Safes = toml::from_str(good).expect("the documented shape loads");
        let entry = safes
            .find(Address::from([0x11u8; 20]), U256::from(1u64))
            .expect("the entry is found by (safe, chain_id)");
        assert_eq!(entry.threshold, 2);
        assert_eq!(entry.owners.len(), 2);
        assert!(matches!(
            safes.find(Address::from([0x11u8; 20]), U256::from(8453u64)),
            Err(BundleErr::UnknownSafe { .. })
        ));

        assert!(toml::from_str::<Safes>(&format!("{good}quorum = 2\n")).is_err());

        let zero: Safes = toml::from_str(&good.replace("threshold = 2", "threshold = 0"))
            .expect("the shape parses before semantic validation");
        assert!(matches!(
            zero.validate(),
            Err(BundleErr::InvalidSafeThreshold { threshold: 0, .. })
        ));

        let duplicate_owner: Safes = toml::from_str(&good.replace(
            "\"0x3333333333333333333333333333333333333333\"",
            "\"0x2222222222222222222222222222222222222222\"",
        ))
        .expect("the duplicate list parses before semantic validation");
        assert!(matches!(
            duplicate_owner.validate(),
            Err(BundleErr::DuplicateSafeOwner { .. })
        ));
    }
}
