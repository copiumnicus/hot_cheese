//! A SafeTx and the owner signatures collected for it so far, so several devices can each add
//! one and a final signer can execute.
//!
//! The bundle stores FIELDS and never a digest: [`SafeTxBundle::digest`] recomputes the
//! `safeTxHash` on every call, so there is nothing here a signer could be tempted to trust.
//! The local keystore name is the one field a device may rebind ([`SafeTxBundle::intent_for`]),
//! because `key` is not part of the EIP-712 encoding — the same transaction is signed under
//! whatever each device calls its key.
//!
//! Who may sign and how many must is LOCAL truth, read from this machine's `safes.toml` and
//! passed in: every path that takes a signature takes the owner list with it, and
//! [`SafeTxBundle::quorum`] counts against the local threshold. The `threshold` the file itself
//! carries is a peer's claim, reported as a disagreement and never counted against.
use crate::intent::SafeTxIntent;
use crate::{adapter, address_of};
use alloy_primitives::{Address, Bytes, B256};
use err_mac::create_err_with_impls;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The bundle schema this build writes and reads.
pub const V: u32 = 1;

/// Length of a Safe owner signature: `r‖s‖v`.
const SIGNATURE_BYTES: usize = 65;
/// Local bundle coordination is deliberately capped alongside the per-bundle file cap.
pub const MAX_SIGNATURES: usize = 64;

create_err_with_impls!(
    #[derive(Debug)]
    pub BundleErr,
    NonCanonicalSignatures,
    Ecdsa(k256::ecdsa::Error)
    ;
    BadSignatureLength { len: usize },
    BadRecoveryId { v: u8 },
    SignerMismatch { claimed: Address, recovered: Address },
    ConflictingSignature { signer: Address },
    DigestMismatch { ours: B256, theirs: B256 },
    NotAnOwner { signer: Address },
    UnsupportedVersion { found: u32 },
    InvalidKeyName { name: String },
    InvalidThreshold { found: u8 },
    TooManySignatures { found: usize, max: usize },
    ThresholdMismatch { ours: u8, theirs: u8 },
    CreatedAtMismatch { ours: u64, theirs: u64 }
);

/// One owner's signature over the bundle's digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectedSignature {
    /// The address this signature must recover to.
    pub signer: Address,
    /// The 65-byte `r‖s‖v`.
    pub signature: Bytes,
}

/// A SafeTx being collected: the fields, the threshold in force when it was created, and who
/// has signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeTxBundle {
    /// Bundle schema version; [`V`] is what this build writes.
    pub v: u32,
    /// The transaction, fields only.
    pub intent: SafeTxIntent,
    /// The threshold recorded when this bundle was created; a peer writes this file, so
    /// [`SafeTxBundle::quorum`] counts against local truth instead.
    pub threshold: u8,
    /// The signatures collected so far, ascending by signer address.
    pub signatures: Vec<CollectedSignature>,
    /// Unix milliseconds this bundle was created at.
    pub created_at_ms: u64,
}

/// How close a bundle is to executing, measured against the LOCAL `safes.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quorum {
    /// Signatures collected.
    pub have: usize,
    /// Signatures the local `safes.toml` requires today.
    pub threshold: u8,
    /// Whether `have` covers `threshold`.
    pub met: bool,
    /// The threshold the peer-written file states, when it is not the local one.
    pub stated: Option<u8>,
}

/// Recover the address `signature` was made by over `digest`, refusing anything that is not a
/// 65-byte `r‖s‖v` with a `v` of the 27-based form Safe signatures carry.
fn recover(digest: B256, signature: &Bytes) -> Result<Address, BundleErr> {
    if signature.len() != SIGNATURE_BYTES {
        return Err(BundleErr::BadSignatureLength {
            len: signature.len(),
        });
    }
    let sig = Signature::from_slice(&signature[..64])?;
    let v = signature[64];
    let recid = v
        .checked_sub(27)
        .and_then(RecoveryId::from_byte)
        .ok_or(BundleErr::BadRecoveryId { v })?;
    let recovered = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, recid)?;
    Ok(address_of(&recovered))
}

impl SafeTxBundle {
    /// Validate the coordination metadata and every stored signature against the Safe's local
    /// owner list. On-disk writers always sort and deduplicate with [`SafeTxBundle::add`], so a
    /// non-canonical vector is malformed — and a peer file holding a signature from anyone but
    /// an owner is refused here, before it can occupy a slot.
    pub fn validate(&self, owners: &[Address]) -> Result<(), BundleErr> {
        if self.v != V {
            return Err(BundleErr::UnsupportedVersion { found: self.v });
        }
        if !hc_core::is_valid_key_name(&self.intent.key) {
            return Err(BundleErr::InvalidKeyName {
                name: hc_core::safe_diagnostic_text(&self.intent.key),
            });
        }
        if self.threshold == 0 || usize::from(self.threshold) > MAX_SIGNATURES {
            return Err(BundleErr::InvalidThreshold {
                found: self.threshold,
            });
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(BundleErr::TooManySignatures {
                found: self.signatures.len(),
                max: MAX_SIGNATURES,
            });
        }
        let mut canonical = SafeTxBundle {
            signatures: Vec::new(),
            ..self.clone()
        };
        for signature in &self.signatures {
            canonical.add(signature.clone(), owners)?;
        }
        if canonical.signatures != self.signatures {
            return Err(BundleErr::NonCanonicalSignatures);
        }
        Ok(())
    }

    /// The `safeTxHash` every signature here is over, rebuilt from the fields on every call.
    pub fn digest(&self) -> B256 {
        adapter::safe_tx_hash(&self.intent)
    }

    /// This bundle's transaction bound to a local keystore name. `key` is outside the EIP-712
    /// digest, so rebinding it changes nothing a signature commits to.
    pub fn intent_for(&self, key: &str) -> SafeTxIntent {
        let mut intent = self.intent.clone();
        intent.key = key.to_string();
        intent
    }

    /// Add one signature. It must recover to the address it claims and that address must be an
    /// owner of the Safe, so a hostile peer cannot spend the slots on valid signatures from keys
    /// the Safe has never heard of. A byte-identical duplicate is a no-op, a second, different
    /// signature from the same signer is refused, and the count is capped at [`MAX_SIGNATURES`].
    /// The insert keeps the list ascending by signer address, because Gnosis `checkNSignatures`
    /// walks the recovered owners strictly ascending and refuses any other order.
    pub fn add(&mut self, sig: CollectedSignature, owners: &[Address]) -> Result<(), BundleErr> {
        let recovered = recover(self.digest(), &sig.signature)?;
        if recovered != sig.signer {
            return Err(BundleErr::SignerMismatch {
                claimed: sig.signer,
                recovered,
            });
        }
        if !owners.contains(&recovered) {
            return Err(BundleErr::NotAnOwner { signer: recovered });
        }
        for held in &self.signatures {
            if held.signer != sig.signer {
                continue;
            }
            if held.signature != sig.signature {
                return Err(BundleErr::ConflictingSignature { signer: sig.signer });
            }
            return Ok(());
        }
        if self.signatures.len() >= MAX_SIGNATURES {
            return Err(BundleErr::TooManySignatures {
                found: self.signatures.len() + 1,
                max: MAX_SIGNATURES,
            });
        }
        self.signatures.push(sig);
        self.signatures.sort_by_key(|held| held.signer);
        Ok(())
    }

    /// Take every signature `other` holds for the same transaction, all or nothing. A bundle for
    /// a different transaction is refused outright; otherwise each signature goes through
    /// [`SafeTxBundle::add`] against a candidate that only replaces this bundle once every one of
    /// them lands, so a rejected element leaves it exactly as it was. Merging is commutative and
    /// idempotent.
    pub fn merge(&mut self, other: SafeTxBundle, owners: &[Address]) -> Result<(), BundleErr> {
        self.validate(owners)?;
        other.validate(owners)?;
        let ours = self.digest();
        let theirs = other.digest();
        if ours != theirs {
            return Err(BundleErr::DigestMismatch { ours, theirs });
        }
        if self.threshold != other.threshold {
            return Err(BundleErr::ThresholdMismatch {
                ours: self.threshold,
                theirs: other.threshold,
            });
        }
        if self.created_at_ms != other.created_at_ms {
            return Err(BundleErr::CreatedAtMismatch {
                ours: self.created_at_ms,
                theirs: other.created_at_ms,
            });
        }
        let mut merged = self.clone();
        for sig in other.signatures {
            merged.add(sig, owners)?;
        }
        *self = merged;
        Ok(())
    }

    /// The `signatures` argument of `execTransaction`: the collected `r‖s‖v` in stored order.
    pub fn packed(&self) -> Bytes {
        let mut out = Vec::with_capacity(self.signatures.len() * SIGNATURE_BYTES);
        for held in &self.signatures {
            out.extend_from_slice(&held.signature);
        }
        Bytes::from(out)
    }

    /// How close this bundle is to executing, counted against `threshold` as the local
    /// `safes.toml` states it. The file's own `threshold` is a peer's claim: it decides nothing
    /// and is reported as [`Quorum::stated`] when the two disagree.
    pub fn quorum(&self, threshold: u8) -> Quorum {
        Quorum {
            have: self.signatures.len(),
            threshold,
            met: self.signatures.len() >= usize::from(threshold),
            stated: match self.threshold == threshold {
                true => None,
                false => Some(self.threshold),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::Operation;
    use alloy_primitives::U256;
    use k256::ecdsa::hazmat::SignPrimitive;
    use k256::ecdsa::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).expect("a fixed non-zero scalar is a valid key")
    }

    /// Sign `digest` the way a device does. `ad` is RFC-6979 additional data: an empty one
    /// reproduces `sign_prehash_recoverable` exactly, and any other yields a second, equally
    /// valid signature from the same key — which is what a randomised signer produces.
    fn sign(sk: &SigningKey, digest: B256, ad: &[u8]) -> CollectedSignature {
        let (sig, recid) = sk
            .as_nonzero_scalar()
            .try_sign_prehashed_rfc6979::<sha2::Sha256>(k256::FieldBytes::from_slice(&digest.0), ad)
            .expect("signing a fixed prehash with a fixed key");
        let recid = recid.expect("k256 returns the recovery id");
        let mut raw = sig.to_bytes().to_vec();
        raw.push(27 + recid.to_byte());
        CollectedSignature {
            signer: address_of(sk.verifying_key()),
            signature: Bytes::from(raw),
        }
    }

    fn intent() -> SafeTxIntent {
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
            nonce: U256::from(3u64),
        }
    }

    fn bundle() -> SafeTxBundle {
        SafeTxBundle {
            v: V,
            intent: intent(),
            threshold: 2,
            signatures: Vec::new(),
            created_at_ms: 1_700_000_000_000,
        }
    }

    /// What this machine's `safes.toml` says the owner set is.
    fn owners() -> Vec<Address> {
        let mut out = Vec::new();
        for seed in [0x11u8, 0x22, 0x33] {
            out.push(address_of(key(seed).verifying_key()));
        }
        out
    }

    /// Gnosis `checkNSignatures` walks the recovered owners strictly ascending, so the bundle
    /// must hold them that way whichever order the devices signed in, and `packed()` must
    /// concatenate in exactly that order. A signature that does not recover to the address it
    /// claims is refused, a byte-identical re-add is a no-op, and a second, different signature
    /// from one signer is a conflict rather than a silent overwrite.
    #[test]
    fn signatures_land_sorted_deduped_and_bound_to_their_signer() {
        let (a, b) = (key(0x11), key(0x22));
        let digest = bundle().digest();
        let (from_a, from_b) = (sign(&a, digest, b""), sign(&b, digest, b""));
        let (low, high) = if from_a.signer < from_b.signer {
            (from_a.clone(), from_b)
        } else {
            (from_b, from_a.clone())
        };

        let mut ascending = bundle();
        ascending
            .add(low.clone(), &owners())
            .expect("the first signature");
        ascending
            .add(high.clone(), &owners())
            .expect("the second signature");
        let mut descending = bundle();
        descending
            .add(high.clone(), &owners())
            .expect("the high signer first");
        descending
            .add(low.clone(), &owners())
            .expect("the low signer second");
        let signers: Vec<Address> = descending.signatures.iter().map(|s| s.signer).collect();
        assert_eq!(signers, vec![low.signer, high.signer]);
        assert_eq!(ascending.packed(), descending.packed());
        assert_eq!(
            descending.packed(),
            Bytes::from([low.signature.to_vec(), high.signature.to_vec()].concat())
        );

        descending
            .add(low.clone(), &owners())
            .expect("a re-add is a no-op");
        assert_eq!(descending.signatures.len(), 2);

        let variant = sign(&a, digest, b"another nonce");
        assert_ne!(variant.signature, from_a.signature);
        assert!(matches!(
            descending.add(variant, &owners()),
            Err(BundleErr::ConflictingSignature { signer }) if signer == from_a.signer
        ));
        assert_eq!(descending.signatures.len(), 2);

        let mut lying = low.clone();
        lying.signer = Address::from([0x99u8; 20]);
        assert!(matches!(
            bundle().add(lying, &owners()),
            Err(BundleErr::SignerMismatch { .. })
        ));

        let mut truncated = low;
        truncated.signature = Bytes::from(vec![0u8; 64]);
        assert!(matches!(
            bundle().add(truncated, &owners()),
            Err(BundleErr::BadSignatureLength { len: 64 })
        ));
    }

    /// A signature is only worth a slot if the Safe would honour it: a valid signature from a key
    /// the local `safes.toml` does not list as an owner is refused where it arrives, so a hostile
    /// peer cannot fill the bundle with signatures that recover to nobody the Safe knows. A file
    /// already holding one is refused as a whole.
    #[test]
    fn a_signature_from_a_key_the_safe_does_not_own_is_refused() {
        let digest = bundle().digest();
        let stranger = sign(&key(0x44), digest, b"");
        assert!(matches!(
            bundle().add(stranger.clone(), &owners()),
            Err(BundleErr::NotAnOwner { signer }) if signer == stranger.signer
        ));

        let planted = SafeTxBundle {
            signatures: vec![stranger],
            ..bundle()
        };
        assert!(matches!(
            planted.validate(&owners()),
            Err(BundleErr::NotAnOwner { .. })
        ));
        assert!(bundle()
            .add(sign(&key(0x11), digest, b""), &owners())
            .is_ok());
    }

    /// The threshold a peer wrote into the file decides nothing: quorum is counted against the
    /// local `safes.toml`, and the file's claim is reported as a disagreement instead of being
    /// preferred. A bundle two signatures short of local truth is not met however close its own
    /// `threshold` field says it is.
    #[test]
    fn quorum_counts_against_local_truth_not_the_file() {
        let digest = bundle().digest();
        let mut held = bundle();
        for seed in [0x11u8, 0x22] {
            held.add(sign(&key(seed), digest, b""), &owners())
                .expect("an owner signature");
        }
        assert_eq!(held.threshold, 2);

        let local = held.quorum(3);
        assert_eq!(
            local,
            Quorum {
                have: 2,
                threshold: 3,
                met: false,
                stated: Some(2),
            }
        );
        assert_eq!(
            held.quorum(2),
            Quorum {
                have: 2,
                threshold: 2,
                met: true,
                stated: None,
            }
        );
    }

    #[test]
    fn bundle_key_names_are_safe_for_later_policy_lookup() {
        let mut hostile = bundle();
        hostile.intent.key = "../../outside".to_string();
        assert!(matches!(
            hostile.validate(&owners()),
            Err(BundleErr::InvalidKeyName { .. })
        ));
    }

    /// Merging is how two devices meet, so it must refuse a bundle for a different transaction
    /// — the digest is recomputed from both sets of fields, never read out of the file — and
    /// otherwise land on the same bundle in either direction and under repetition.
    #[test]
    fn merge_refuses_another_transaction_and_is_commutative() {
        let (a, b) = (key(0x11), key(0x22));
        let digest = bundle().digest();

        let mut mine = bundle();
        mine.add(sign(&a, digest, b""), &owners())
            .expect("my signature");
        let mut theirs = bundle();
        theirs
            .add(sign(&b, digest, b""), &owners())
            .expect("their signature");

        let mut forward = mine.clone();
        forward.merge(theirs.clone(), &owners()).expect("merge in");
        forward
            .merge(theirs.clone(), &owners())
            .expect("merging twice is idempotent");
        let mut backward = theirs;
        backward
            .merge(mine, &owners())
            .expect("merge the other way");
        assert_eq!(forward.packed(), backward.packed());
        assert_eq!(forward.signatures.len(), 2);

        let mut other_tx = bundle();
        other_tx.intent.nonce = U256::from(4u64);
        assert!(matches!(
            forward.merge(other_tx, &owners()),
            Err(BundleErr::DigestMismatch { .. })
        ));

        let mut lowered = bundle();
        lowered.threshold = 1;
        assert!(matches!(
            bundle().merge(lowered, &owners()),
            Err(BundleErr::ThresholdMismatch { ours: 2, theirs: 1 })
        ));

        let mut zero = bundle();
        zero.threshold = 0;
        assert!(matches!(
            zero.validate(&owners()),
            Err(BundleErr::InvalidThreshold { found: 0 })
        ));
    }

    /// A merge that refuses one signature must refuse the whole file: a half-merged bundle is a
    /// bundle nobody wrote. The conflicting signer here sorts last, so the fresh signature ahead
    /// of it would have landed already under a merge that mutated as it went.
    #[test]
    fn a_refused_merge_leaves_the_bundle_byte_identical() {
        let digest = bundle().digest();
        let (a, b) = (key(0x11), key(0x22));
        let (from_a, from_b) = (sign(&a, digest, b""), sign(&b, digest, b""));
        let (fresh, contested_key) = match from_a.signer < from_b.signer {
            true => (from_a, b),
            false => (from_b, a),
        };
        let contested = sign(&contested_key, digest, b"");
        let held = sign(&contested_key, digest, b"another nonce");
        assert_ne!(held.signature, contested.signature);

        let mut mine = bundle();
        mine.add(held, &owners()).expect("the signature I hold");
        let before = serde_json::to_vec(&mine).expect("serialize the bundle");

        let mut theirs = bundle();
        theirs.add(fresh, &owners()).expect("a signature I lack");
        theirs
            .add(contested, &owners())
            .expect("and one that conflicts with mine");

        assert!(matches!(
            mine.merge(theirs, &owners()),
            Err(BundleErr::ConflictingSignature { .. })
        ));
        assert_eq!(
            serde_json::to_vec(&mine).expect("serialize the bundle"),
            before,
            "a refused merge must leave the bundle exactly as it was"
        );
    }
}
