//! Collecting owner signatures for one Safe transaction across several devices.
//!
//! A bundle is not secret. It is the transaction's FIELDS plus signatures over a digest anyone
//! can recompute, so it never touches the store and never rides a backup: it lives under
//! `<home>/bundles`, beside `adapters`, on a machine whose vault is deliberately not the other
//! machine's vault.
//!
//! Every device writes its OWN file, `0x<signer>.json`, holding a complete bundle carrying only
//! that device's signature. That is the whole concurrency design: two Macs signing the same
//! transaction at the same moment write two differently-named files, so there is no lock to
//! take, no last-writer-wins, and no conflict to resolve — whoever reads takes the union in
//! memory. The union is [`SafeTxBundle::merge`], which recomputes both digests and refuses a
//! file belonging to another transaction, so a misfiled drop-in cannot be absorbed silently.
//! It is also what makes [`sync`] correct: `rsync` without `--delete` over a per-writer layout
//! IS that union, so pulling and pushing in both directions converges with nothing to resolve.
//!
//! Nothing here prompts, unlocks, listens, or reaches a key. The one verb that needs a
//! signature takes it as an argument — [`intent_to_sign`] hands out what to sign and
//! [`collect`] takes the answer back — so the CLI and the console both drive it through
//! whichever unlock path they already own, and neither one grows a second route to a key.
pub mod ingest;
pub mod sync;
pub mod tailnet;

use alloy_primitives::{Address, Bytes, B256, U256};
use err_mac::create_err_with_impls;
use hashbrown::{HashMap, HashSet};
use hc_core::config::bundles_dir;
use hc_core::crypto::envelope::atomic_write;
use hc_sign::bundle::{CollectedSignature, SafeTxBundle};
use hc_sign::grant::now_ms;
use hc_sign::intent::{Intent, SafeTxIntent};
use hc_sign::qr::{frames, QrKind};
use hc_sign::SignResponse;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use sync::SyncMode;

/// The bundle a device writes before it holds any signature.
pub const SEED_FILE: &str = "unsigned.json";

/// Suffix every file in a bundle directory carries.
pub const BUNDLE_SUFFIX: &str = ".json";

create_err_with_impls!(
    #[derive(Debug)]
    pub BundleErr,
    Io(std::io::Error),
    Serde(serde_json::Error),
    Toml(toml::de::Error),
    Envelope(hc_core::crypto::envelope::EnvErr),
    Verify(hc_sign::bundle::BundleErr),
    Qr(hc_sign::qr::QrErr),
    Grant(hc_sign::grant::GrantErr)
    ;
    NoSafesFile { path: PathBuf },
    UnknownSafe { safe: Address, chain_id: U256 },
    BundleExists { dir: PathBuf },
    NoSuchBundle { dir: PathBuf },
    EmptyBundle { dir: PathBuf },
    NotItsDigest { dir: PathBuf, digest: B256 },
    ForeignDigest { ours: B256, theirs: B256 },
    ThresholdNotMet { have: usize, threshold: u8 }
);

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
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeEntry {
    /// The Safe contract.
    pub address: Address,
    /// Chain it is deployed on.
    #[serde(with = "hc_sign::wire::u256")]
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
        let path = bundles_dir().join("safes.toml");
        if !path.exists() {
            return Err(BundleErr::NoSafesFile { path });
        }
        Ok(toml::from_str(&std::fs::read_to_string(&path)?)?)
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
    /// The threshold `safes.toml` states today; a bundle records the one in force when it was
    /// created, so a difference means the Safe was changed underneath it.
    pub safes_threshold: u8,
    /// Collected signers `safes.toml` does not list as owners; each one reverts on-chain.
    pub not_owners: Vec<Address>,
    /// Owners with no signature yet.
    pub missing: Vec<Address>,
    /// Other digests competing for the same (Safe, chain, nonce).
    pub rivals: Vec<B256>,
    /// Milliseconds since the bundle was created.
    pub age_ms: u64,
}

/// What a merge took in.
pub struct Merged {
    /// Signers whose signatures were not already held.
    pub added: Vec<Address>,
    /// The union afterwards.
    pub union: SafeTxBundle,
}

/// The `execTransaction` call the operator broadcasts with their own tooling. hot_cheese has no
/// RPC client and never will: it assembles the blob and stops there.
#[derive(Serialize)]
pub struct Execution {
    /// The Safe to call `execTransaction` on.
    pub safe: Address,
    /// Chain the call belongs to.
    #[serde(with = "hc_sign::wire::u256")]
    pub chain_id: U256,
    pub to: Address,
    #[serde(with = "hc_sign::wire::u256")]
    pub value: U256,
    pub data: Bytes,
    /// `Enum.Operation` as the ABI takes it: 0 CALL, 1 DELEGATECALL.
    pub operation: u8,
    #[serde(with = "hc_sign::wire::u256")]
    pub safe_tx_gas: U256,
    #[serde(with = "hc_sign::wire::u256")]
    pub base_gas: U256,
    #[serde(with = "hc_sign::wire::u256")]
    pub gas_price: U256,
    pub gas_token: Address,
    pub refund_receiver: Address,
    /// The Safe's own nonce, which the digest covers but `execTransaction` does not take.
    #[serde(with = "hc_sign::wire::u256")]
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

/// The union of every file in `dir`, bound to the digest the directory is named for. Files are
/// merged in name order only so that a failure is reproducible; the merge itself is
/// commutative, so the result does not depend on it.
fn load_dir(dir: &Path, hash: B256) -> Result<SafeTxBundle, BundleErr> {
    if !dir.is_dir() {
        return Err(BundleErr::NoSuchBundle {
            dir: dir.to_path_buf(),
        });
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry.file_name().to_string_lossy().ends_with(BUNDLE_SUFFIX)
        {
            files.push(entry.path());
        }
    }
    files.sort();

    let mut merged: Option<SafeTxBundle> = None;
    for path in &files {
        let one: SafeTxBundle = serde_json::from_slice(&std::fs::read(path)?)?;
        match &mut merged {
            None => merged = Some(one),
            Some(union) => union.merge(one)?,
        }
    }
    let Some(merged) = merged else {
        return Err(BundleErr::EmptyBundle {
            dir: dir.to_path_buf(),
        });
    };
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
fn load_all() -> Result<Vec<Loaded>, BundleErr> {
    let root = bundles_dir();
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
        match load_dir(&entry.path(), hash) {
            Ok(bundle) => out.push(Loaded { hash, bundle }),
            Err(e) => {
                tracing::warn!(%hash, error = %e, "skipping a bundle directory that will not load")
            }
        }
    }
    out.sort_by_key(|one| one.hash);
    Ok(out)
}

/// Whatever `scope` covers that actually loads.
fn loaded(scope: Scope) -> Result<Vec<Loaded>, BundleErr> {
    let Scope::One(hash) = scope else {
        return load_all();
    };
    let dir = bundle_dir(hash);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    match load_dir(&dir, hash) {
        Ok(bundle) => Ok(vec![Loaded { hash, bundle }]),
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
fn take(held: &SafeTxBundle, sig: CollectedSignature) -> Result<SafeTxBundle, BundleErr> {
    let mut union = held.clone();
    union.add(sig.clone())?;
    let mut one = SafeTxBundle {
        signatures: Vec::new(),
        ..held.clone()
    };
    one.add(sig)?;
    Ok(one)
}

/// Ingest a `SignResponse`, this machine's own or one another device handed over. The claimed
/// `safe_tx_hash` must equal the digest we rebuilt from our own fields; a device that signed a
/// different transaction, or a hand-copied character, fails here instead of landing a signature
/// that recovers to nobody on-chain. [`take`] then ecrecovers it.
pub fn take_response(
    held: &SafeTxBundle,
    response: SignResponse,
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
    )
}

fn write_one(dir: &Path, signer: Address, one: &SafeTxBundle) -> Result<(), BundleErr> {
    atomic_write(
        &dir.join(format!("{signer:#x}{BUNDLE_SUFFIX}")),
        &serde_json::to_vec_pretty(one)?,
    )?;
    Ok(())
}

/// Start a bundle from an intent. The threshold comes from `safes.toml`, so a Safe this
/// machine does not describe cannot be collected for at all. Pushes the new directory to every
/// enrolled peer, so a co-signer sees it without being told.
pub fn new(sync: SyncMode, intent: SafeTxIntent) -> Result<B256, BundleErr> {
    let threshold = Safes::load()?.find(intent.safe, intent.chain_id)?.threshold;
    let bundle = SafeTxBundle {
        v: hc_sign::bundle::V,
        intent,
        threshold,
        signatures: Vec::new(),
        created_at_ms: now_ms()?,
    };
    let hash = bundle.digest();
    let dir = bundle_dir(hash);
    if dir.exists() {
        return Err(BundleErr::BundleExists { dir });
    }
    std::fs::create_dir_all(&dir)?;
    atomic_write(&dir.join(SEED_FILE), &serde_json::to_vec_pretty(&bundle)?)?;
    tracing::info!(%hash, dir = %dir.display(), threshold, "created bundle");
    sync.push(Scope::One(hash));
    Ok(hash)
}

/// What a device has to sign to join this bundle, bound to a LOCAL keystore name. The name is
/// rebound in memory only — `key` is outside the EIP-712 encoding — so the digest, and
/// therefore the directory, is untouched. Pulls first, so a machine that has never seen this
/// bundle can still be asked to sign it.
pub fn intent_to_sign(sync: SyncMode, hash: B256, key: &str) -> Result<SafeTxIntent, BundleErr> {
    sync.pull(Scope::One(hash));
    Ok(load_dir(&bundle_dir(hash), hash)?.intent_for(key))
}

/// Take a response into the bundle on disk, then hand back the union that is actually there
/// afterwards. Pushes it, so the co-signer's next read already has it.
pub fn collect(
    sync: SyncMode,
    hash: B256,
    response: SignResponse,
) -> Result<SafeTxBundle, BundleErr> {
    let dir = bundle_dir(hash);
    let held = load_dir(&dir, hash)?;
    let signer = response.signer;
    write_one(&dir, signer, &take_response(&held, response)?)?;
    let after = load_dir(&dir, hash)?;
    tracing::info!(
        %hash,
        %signer,
        have = after.signatures.len(),
        threshold = after.threshold,
        met = after.met(),
        "collected signature"
    );
    sync.push(Scope::One(hash));
    Ok(after)
}

/// The merged view: who has signed, who is still expected, and what else competes for the same
/// nonce. Pulls the bundle's own directory first.
pub fn status(sync: SyncMode, hash: B256) -> Result<BundleStatus, BundleErr> {
    sync.pull(Scope::One(hash));
    let held = load_dir(&bundle_dir(hash), hash)?;
    let safes = Safes::load()?;
    let entry = safes.find(held.intent.safe, held.intent.chain_id)?;

    let mut not_owners = Vec::new();
    for sig in &held.signatures {
        if !entry.owners.contains(&sig.signer) {
            not_owners.push(sig.signer);
        }
    }
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
        age_ms: now_ms()?.saturating_sub(held.created_at_ms),
        bundle: held,
        safes_threshold: entry.threshold,
        not_owners,
        missing,
        rivals,
    })
}

/// Every bundle, grouped by the slot it competes for. Pulls the whole tree first, because
/// finding out what a co-signer started is the entire point of asking.
pub fn list(sync: SyncMode) -> Result<Vec<(Slot, Vec<Loaded>)>, BundleErr> {
    sync.pull(Scope::All);
    Ok(slots(load_all()?))
}

/// Read a bundle a human moved by hand: a single file, or a whole directory copied over.
pub fn read_bundle(path: &Path, hash: B256) -> Result<SafeTxBundle, BundleErr> {
    if path.is_dir() {
        return load_dir(path, hash);
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

/// Union an external bundle into the store. Every signature lands in its own file, so an
/// import is byte-identical to what the signing device would have written, and the result is
/// pushed to the peers like any other write.
pub fn merge(sync: SyncMode, hash: B256, incoming: SafeTxBundle) -> Result<Merged, BundleErr> {
    let dir = bundle_dir(hash);
    let held = load_dir(&dir, hash)?;
    let theirs = incoming.digest();
    if theirs != hash {
        return Err(BundleErr::ForeignDigest { ours: hash, theirs });
    }
    let mut union = held.clone();
    let mut added = Vec::new();
    for sig in incoming.signatures {
        let signer = sig.signer;
        let before = union.signatures.len();
        union.add(sig.clone())?;
        write_one(&dir, signer, &take(&held, sig)?)?;
        if union.signatures.len() != before {
            added.push(signer);
        }
    }
    tracing::info!(%hash, have = union.signatures.len(), threshold = union.threshold, met = union.met(), "merged");
    sync.push(Scope::One(hash));
    Ok(Merged { added, union })
}

/// The assembled call. The owner list is checked here because this is the last moment before
/// gas is spent: a signer `safes.toml` does not list means either the mirror is stale or the
/// signature is worthless, and both revert on-chain. Pulls first, so the final signer is
/// assembling from everything that exists rather than everything that reached this disk.
pub fn export(sync: SyncMode, hash: B256) -> Result<Execution, BundleErr> {
    sync.pull(Scope::One(hash));
    let held = load_dir(&bundle_dir(hash), hash)?;
    let safes = Safes::load()?;
    held.owners_ok(&safes.find(held.intent.safe, held.intent.chain_id)?.owners)?;
    if !held.met() {
        return Err(BundleErr::ThresholdNotMet {
            have: held.signatures.len(),
            threshold: held.threshold,
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
/// machine cannot learn the Safe's on-chain nonce. It deliberately does not sync — a pull
/// would resurrect what was just retired, and a push cannot delete, because no transfer in
/// this module carries `--delete`.
pub fn rm(hash: B256) -> Result<SafeTxBundle, BundleErr> {
    let dir = bundle_dir(hash);
    let held = load_dir(&dir, hash)?;
    std::fs::remove_dir_all(&dir)?;
    tracing::info!(
        %hash,
        had = held.signatures.len(),
        threshold = held.threshold,
        nonce = %held.intent.nonce,
        "retired bundle"
    );
    Ok(held)
}

/// The transaction framed for another device's camera. The frame carries the FIELDS, so the far
/// device rebuilds the digest itself and shows its own decoded summary before its own
/// biometric — a QR that lied would be caught there, which is why no digest is transmitted.
pub fn qr_frames(hash: B256) -> Result<Vec<Vec<u8>>, BundleErr> {
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
    /// Signatures held afterwards.
    pub have: usize,
    /// Signatures the Safe requires.
    pub threshold: u8,
    /// Whether that threshold is now covered.
    pub met: bool,
}

/// Which signers each watched bundle held last time, so a poll can name what just arrived.
///
/// The loop belongs to the caller: a terminal wants a sleep, a console wants its own tick, and
/// neither wants a library owning the process. Nothing here spawns or backgrounds anything.
pub struct Watch {
    scope: Scope,
    seen: HashMap<B256, HashSet<Address>>,
}

impl Watch {
    /// Prime from what is already on this disk, without syncing, so the first poll reports
    /// what ARRIVED rather than everything that was already there.
    pub fn start(scope: Scope) -> Result<Self, BundleErr> {
        let mut watch = Watch {
            scope,
            seen: HashMap::new(),
        };
        watch.take_stock(loaded(scope)?);
        Ok(watch)
    }

    /// How many bundles are being watched.
    pub fn watching(&self) -> usize {
        self.seen.len()
    }

    /// Pull, judge what landed, and report every signature that was not there last time.
    pub fn poll(&mut self, sync: SyncMode) -> Result<Vec<Arrival>, BundleErr> {
        sync.pull(self.scope);
        let mut arrivals = Vec::new();
        for one in loaded(self.scope)? {
            let seen = self.seen.entry(one.hash).or_default();
            for sig in &one.bundle.signatures {
                if seen.insert(sig.signer) {
                    arrivals.push(Arrival {
                        hash: one.hash,
                        signer: sig.signer,
                        have: one.bundle.signatures.len(),
                        threshold: one.bundle.threshold,
                        met: one.bundle.met(),
                    });
                }
            }
        }
        Ok(arrivals)
    }

    fn take_stock(&mut self, bundles: Vec<Loaded>) {
        for one in bundles {
            let seen = self.seen.entry(one.hash).or_default();
            for sig in &one.bundle.signatures {
                seen.insert(sig.signer);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hc_sign::intent::Operation;
    use k256::ecdsa::SigningKey;

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

    /// What a device hands back after its own biometric: a signature over the digest IT rebuilt.
    pub(crate) fn signed(seed: u8, held: &SafeTxBundle) -> SignResponse {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("a fixed non-zero scalar is a key");
        let digest = held.digest();
        let (sig, recid) = sk
            .sign_prehash_recoverable(digest.as_slice())
            .expect("signing a fixed prehash with a fixed key");
        let mut raw = sig.to_bytes().to_vec();
        raw.push(27 + recid.to_byte());
        let point = sk.verifying_key().to_encoded_point(false);
        SignResponse {
            safe_tx_hash: digest,
            signature: Bytes::from(raw),
            signer: Address::from_slice(
                &hc_core::crypto::keccak256(point.as_bytes()[1..].to_vec())[12..],
            ),
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make the test dir");
        dir
    }

    /// The whole point of one file per signer: two devices write two names with no lock and no
    /// coordination, and reading takes the union. The threshold is reached by that union alone,
    /// the packed blob is the ascending concatenation `checkNSignatures` demands, and the
    /// directory stays bound to the digest it is named for — a file for another transaction
    /// dropped into it is refused, never absorbed.
    #[test]
    fn two_devices_write_two_files_and_the_union_reaches_the_threshold() {
        let dir = temp("hot_cheese_bundle_union");
        let seed = bundle(intent(3));
        let hash = seed.digest();

        for device in [0x11u8, 0x22u8] {
            let response = signed(device, &seed);
            let signer = response.signer;
            let one = take_response(&seed, response).expect("a signature over our own digest");
            assert_eq!(one.signatures.len(), 1);
            write_one(&dir, signer, &one).expect("write the signer's own file");
        }
        assert_eq!(
            std::fs::read_dir(&dir).expect("read the dir").count(),
            2,
            "two devices, two files, no collision"
        );

        let union = load_dir(&dir, hash).expect("the union loads");
        assert_eq!(union.signatures.len(), 2);
        assert!(union.met());
        assert_eq!(union.packed().len(), 130);
        let signers: Vec<Address> = union.signatures.iter().map(|s| s.signer).collect();
        let mut ascending = signers.clone();
        ascending.sort();
        assert_eq!(signers, ascending);

        let elsewhere = bundle(intent(4));
        let stray = signed(0x33, &elsewhere);
        let signer = stray.signer;
        let one =
            take_response(&elsewhere, stray).expect("their own bundle takes their own signature");
        write_one(&dir, signer, &one).expect("misfile it");
        assert!(matches!(
            load_dir(&dir, hash),
            Err(BundleErr::Verify(
                hc_sign::bundle::BundleErr::DigestMismatch { .. }
            ))
        ));
        let _ = std::fs::remove_dir_all(&dir);
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

        assert!(take_response(&ours, signed(0x11, &ours)).is_ok());
        assert!(matches!(
            take_response(&ours, signed(0x11, &theirs)),
            Err(BundleErr::ForeignDigest { .. })
        ));

        let mut lying = signed(0x11, &ours);
        lying.signer = Address::from([0x99u8; 20]);
        assert!(matches!(
            take_response(&ours, lying),
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
    }
}
