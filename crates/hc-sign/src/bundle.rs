//! A SafeTx and the owner signatures collected for it so far, so several devices can each add
//! one and a final signer can execute.
//!
//! The bundle stores FIELDS and never a digest: [`SafeTxBundle::digest`] recomputes the
//! `safeTxHash` on every call, so there is nothing here a signer could be tempted to trust.
//! The local keystore name is the one field a device may rebind ([`SafeTxBundle::intent_for`]),
//! because `key` is not part of the EIP-712 encoding — the same transaction is signed under
//! whatever each device calls its key.
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

create_err_with_impls!(
    #[derive(Debug)]
    pub BundleErr,
    Ecdsa(k256::ecdsa::Error)
    ;
    BadSignatureLength { len: usize },
    BadRecoveryId { v: u8 },
    SignerMismatch { claimed: Address, recovered: Address },
    ConflictingSignature { signer: Address },
    DigestMismatch { ours: B256, theirs: B256 },
    NotAnOwner { signer: Address }
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

/// A SafeTx being collected: the fields, how many owners must sign, and who has.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeTxBundle {
    /// Bundle schema version; [`V`] is what this build writes.
    pub v: u32,
    /// The transaction, fields only.
    pub intent: SafeTxIntent,
    /// Owner signatures the Safe requires before `execTransaction` runs.
    pub threshold: u8,
    /// The signatures collected so far, ascending by signer address.
    pub signatures: Vec<CollectedSignature>,
    /// Unix milliseconds this bundle was created at.
    pub created_at_ms: u64,
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

    /// Add one signature. It must recover to the address it claims; a byte-identical duplicate
    /// is a no-op, and a second, different signature from the same signer is refused. The
    /// insert keeps the list ascending by signer address, because Gnosis `checkNSignatures`
    /// walks the recovered owners strictly ascending and refuses any other order.
    pub fn add(&mut self, sig: CollectedSignature) -> Result<(), BundleErr> {
        let recovered = recover(self.digest(), &sig.signature)?;
        if recovered != sig.signer {
            return Err(BundleErr::SignerMismatch {
                claimed: sig.signer,
                recovered,
            });
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
        self.signatures.push(sig);
        self.signatures.sort_by_key(|held| held.signer);
        Ok(())
    }

    /// Take every signature `other` holds for the same transaction. A bundle for a different
    /// transaction is refused outright; otherwise each signature goes through [`add`], so
    /// merging is commutative and idempotent.
    pub fn merge(&mut self, other: SafeTxBundle) -> Result<(), BundleErr> {
        let ours = self.digest();
        let theirs = other.digest();
        if ours != theirs {
            return Err(BundleErr::DigestMismatch { ours, theirs });
        }
        for sig in other.signatures {
            self.add(sig)?;
        }
        Ok(())
    }

    /// Check every collected signer against the Safe's owner list. Kept out of [`add`] so a
    /// device that does not know the owners can still collect signatures.
    pub fn owners_ok(&self, owners: &[Address]) -> Result<(), BundleErr> {
        for held in &self.signatures {
            if !owners.contains(&held.signer) {
                return Err(BundleErr::NotAnOwner {
                    signer: held.signer,
                });
            }
        }
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

    /// Whether the threshold is covered.
    pub fn met(&self) -> bool {
        self.signatures.len() >= self.threshold as usize
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
        ascending.add(low.clone()).expect("the first signature");
        ascending.add(high.clone()).expect("the second signature");
        let mut descending = bundle();
        descending.add(high.clone()).expect("the high signer first");
        descending.add(low.clone()).expect("the low signer second");
        let signers: Vec<Address> = descending.signatures.iter().map(|s| s.signer).collect();
        assert_eq!(signers, vec![low.signer, high.signer]);
        assert_eq!(ascending.packed(), descending.packed());
        assert_eq!(
            descending.packed(),
            Bytes::from([low.signature.to_vec(), high.signature.to_vec()].concat())
        );
        assert!(descending.met());

        descending.add(low.clone()).expect("a re-add is a no-op");
        assert_eq!(descending.signatures.len(), 2);

        let variant = sign(&a, digest, b"another nonce");
        assert_ne!(variant.signature, from_a.signature);
        assert!(matches!(
            descending.add(variant),
            Err(BundleErr::ConflictingSignature { signer }) if signer == from_a.signer
        ));
        assert_eq!(descending.signatures.len(), 2);

        let mut lying = low.clone();
        lying.signer = Address::from([0x99u8; 20]);
        assert!(matches!(
            bundle().add(lying),
            Err(BundleErr::SignerMismatch { .. })
        ));

        let mut truncated = low;
        truncated.signature = Bytes::from(vec![0u8; 64]);
        assert!(matches!(
            bundle().add(truncated),
            Err(BundleErr::BadSignatureLength { len: 64 })
        ));

        assert!(bundle().owners_ok(&[]).is_ok());
        assert!(matches!(
            descending.owners_ok(&[high.signer]),
            Err(BundleErr::NotAnOwner { .. })
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
        mine.add(sign(&a, digest, b"")).expect("my signature");
        let mut theirs = bundle();
        theirs.add(sign(&b, digest, b"")).expect("their signature");

        let mut forward = mine.clone();
        forward.merge(theirs.clone()).expect("merge in");
        forward
            .merge(theirs.clone())
            .expect("merging twice is idempotent");
        let mut backward = theirs;
        backward.merge(mine).expect("merge the other way");
        assert_eq!(forward.packed(), backward.packed());
        assert_eq!(forward.signatures.len(), 2);

        let mut other_tx = bundle();
        other_tx.intent.nonce = U256::from(4u64);
        assert!(matches!(
            forward.merge(other_tx),
            Err(BundleErr::DigestMismatch { .. })
        ));
    }
}
