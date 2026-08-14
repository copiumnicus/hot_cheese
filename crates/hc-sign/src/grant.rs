//! Per-payload signing grants: hardware-attested approval, enforced by the type system.
//!
//! A grant is one enclave ECDSA signature over the exact terms of ONE signature — the
//! keystore, the `safeTxHash` the daemon rebuilt, the digest of the policy bytes in force,
//! an adapter manifest digest, a nonce, and an expiry. It is taken under the same
//! pre-evaluated [`LaContext`] that approved the request, so it costs no second Touch ID and
//! exists only where a live human approved those exact bytes.
//!
//! [`verify`] is the only way to obtain a [`SignGrant`], and `HotApi::sign` takes one BY
//! VALUE, so the signing key is unreachable without one and one grant is one signature —
//! `SignGrant` is not `Clone`, so the move is the counter.
//!
//! What a grant does NOT buy: it is not a cryptographic weld to DEK decryption. An attacker
//! with code execution inside the daemon after the DEK is unwrapped can still sign. Nothing
//! here is persisted — no grant, no signature, no audit trail — and losing the grant key
//! costs a re-run of `hot_cheese enroll grant`.
use alloy_primitives::B256;
use err_mac::create_err_with_impls;
use hc_core::mac::local_auth::LaContext;
use hc_core::mac::secure_enclave::{grant_sign, SE_GRANT_KEY_LABEL};
use p256::ecdsa::signature::Verifier;
use serde::Deserialize;

create_err_with_impls!(
    #[derive(Debug)]
    pub GrantErr,
    NoPinnedGrantKey,
    Hex(hex::FromHexError),
    Ecdsa(p256::ecdsa::Error),
    Se(hc_core::mac::secure_enclave::SeErr),
    Clock(std::time::SystemTimeError)
    ;
    Expired { now_ms: u64, expires_at_ms: u64 }
);

/// Domain separator: these bytes are an approval grant and nothing else.
const DOMAIN: &[u8] = b"hotcheese/grant/v1";

/// Element separator. Key names are `[A-Za-z0-9_]` and every other element is fixed length,
/// so no two distinct term sets can encode to the same bytes.
const SEP: u8 = 0x00;

/// Signatures one grant authorizes. It is 1, and the move into `sign` is what enforces it.
const MAX_SIGNATURES: u8 = 1;

/// How long a minted grant stays verifiable. It is minted and consumed inside one call, so
/// this bounds the window between [`mint`] and [`verify`], not a human's deliberation.
pub const GRANT_TTL_MS: u64 = 5_000;

/// Which intent shape produced the digest a grant covers. An adapter manifest names the same
/// set in its `intent_kinds`, so there is one spelling of "what shape may be signed".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    SafeTx,
    TypedData,
}

impl IntentKind {
    fn tag(self) -> u8 {
        match self {
            IntentKind::SafeTx => 1,
            IntentKind::TypedData => 2,
        }
    }
}

/// The exact terms of ONE signature. The grant's identity IS `SHA-256(canonical_bytes)`.
pub struct GrantTerms {
    /// Keystore the signature is for.
    pub key_name: String,
    /// The `safeTxHash` the daemon rebuilt from the submitted fields.
    pub intent_digest: B256,
    /// SHA-256 of the exact policy file bytes loaded for this signature.
    pub policy_digest: B256,
    /// Adapter manifest digest; zero while no adapter runs.
    pub manifest_digest: B256,
    /// Which intent shape `intent_digest` came from.
    pub kind: IntentKind,
    /// Per-mint randomness, so two identical intents never share grant bytes.
    pub nonce: [u8; 16],
    /// Unix milliseconds after which [`verify`] refuses the grant.
    pub expires_at_ms: u64,
}

impl GrantTerms {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(DOMAIN.len() + 8 + self.key_name.len() + 32 * 3 + 1 + 16 + 8 + 1);
        out.extend_from_slice(DOMAIN);
        out.push(SEP);
        out.extend_from_slice(self.key_name.as_bytes());
        out.push(SEP);
        out.extend_from_slice(self.intent_digest.as_slice());
        out.push(SEP);
        out.extend_from_slice(self.policy_digest.as_slice());
        out.push(SEP);
        out.extend_from_slice(self.manifest_digest.as_slice());
        out.push(SEP);
        out.push(self.kind.tag());
        out.push(SEP);
        out.extend_from_slice(&self.nonce);
        out.push(SEP);
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.push(SEP);
        out.push(MAX_SIGNATURES);
        out
    }
}

/// Minted terms and the enclave's raw `r || s` over their canonical bytes.
pub struct Signed {
    terms: GrantTerms,
    signature: [u8; 64],
}

/// Proof that a live human approved exactly one payload, minted only by [`verify`]. Not
/// `Clone`, not `Copy`, not serializable: `HotApi::sign` takes it by value and drops it.
pub struct SignGrant {
    key_name: String,
    intent_digest: B256,
}

impl SignGrant {
    /// Keystore this grant authorizes, which must be the one being unlocked.
    pub fn key_name(&self) -> &str {
        &self.key_name
    }
    /// The digest `sign` is allowed to sign, and the only one it does sign.
    pub fn intent_digest(&self) -> B256 {
        self.intent_digest
    }
}

/// Sign `terms` with the Secure Enclave grant key. `auth` is the context the approval
/// already evaluated, so the enclave signature costs no second prompt. A session that
/// approved without one — the recovery-passphrase gate, whose unlocker ignores `auth` —
/// takes its own biometric here instead of refusing to sign; that is the only path that
/// shows a second sheet, and a machine with no usable biometric fails closed with
/// [`hc_core::mac::secure_enclave::SeErr::TouchIdDenied`].
pub fn mint(terms: GrantTerms, auth: Option<&LaContext>) -> Result<Signed, GrantErr> {
    let reason = format!(
        "Approve one hot_cheese signature for \"{}\" (intent {})",
        terms.key_name, terms.intent_digest
    );
    let msg = terms.canonical_bytes();
    let signature = match auth {
        Some(auth) => grant_sign(SE_GRANT_KEY_LABEL, &msg, Some(auth), &reason)?,
        None => {
            let own = LaContext::evaluate_biometric(&reason)?;
            grant_sign(SE_GRANT_KEY_LABEL, &msg, Some(&own), &reason)?
        }
    };
    Ok(Signed { terms, signature })
}

/// Check a minted grant against the uncompressed SEC1 hex `config.toml` pins and, only then,
/// mint the [`SignGrant`] that unlocks signing.
pub fn verify(signed: Signed, pinned_pub_hex: &str, now_ms: u64) -> Result<SignGrant, GrantErr> {
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&hex::decode(pinned_pub_hex)?)?;
    let signature = p256::ecdsa::Signature::from_slice(&signed.signature)?;
    verifying.verify(&signed.terms.canonical_bytes(), &signature)?;
    if now_ms > signed.terms.expires_at_ms {
        return Err(GrantErr::Expired {
            now_ms,
            expires_at_ms: signed.terms.expires_at_ms,
        });
    }
    Ok(SignGrant {
        key_name: signed.terms.key_name,
        intent_digest: signed.terms.intent_digest,
    })
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> Result<u64, GrantErr> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64)
}

/// Seconds since the Unix epoch. Every timestamp a status type publishes is this, so nothing
/// downstream has to know which of two units it was handed.
pub fn now_secs() -> Result<u64, GrantErr> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

/// A grant for the tests that exercise signing itself; it cannot exist in a real build.
#[cfg(any(test, feature = "test-util"))]
pub fn grant_for_test(key_name: &str, intent_digest: B256) -> SignGrant {
    SignGrant {
        key_name: key_name.to_string(),
        intent_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};

    fn terms() -> GrantTerms {
        GrantTerms {
            key_name: "TRADER".to_string(),
            intent_digest: B256::from([0x11u8; 32]),
            policy_digest: B256::from([0x22u8; 32]),
            manifest_digest: B256::ZERO,
            kind: IntentKind::SafeTx,
            nonce: [0x33u8; 16],
            expires_at_ms: 1_700_000_000_000,
        }
    }

    fn host_signature(sk: &SigningKey, terms: &GrantTerms) -> [u8; 64] {
        let signature: p256::ecdsa::Signature = sk.sign(&terms.canonical_bytes());
        let mut raw = [0u8; 64];
        raw.copy_from_slice(&signature.to_bytes());
        raw
    }

    /// The grant's identity is SHA-256 of its canonical encoding, so this frozen digest
    /// moves if a field is reordered, resized, added, or loses its separator.
    #[test]
    fn canonical_encoding_matches_its_golden_digest() {
        let bytes = terms().canonical_bytes();
        assert_eq!(bytes.len(), 148 + "TRADER".len());
        assert!(bytes.starts_with(DOMAIN));
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "de4243c043664c93f31d3b648440ef3e39df6f29c8c03fab7e3681a141790759"
        );
    }

    /// A grant is only proof if it verifies for the terms that were signed and nothing else:
    /// a signature lifted onto other terms, or one whose expiry has passed, must be refused
    /// before any `SignGrant` exists.
    #[test]
    fn verify_refuses_lifted_signatures_and_expired_terms() {
        let sk = SigningKey::random(&mut rand::rngs::OsRng);
        let pin = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let now = terms().expires_at_ms - 1;

        let granted = verify(
            Signed {
                signature: host_signature(&sk, &terms()),
                terms: terms(),
            },
            &pin,
            now,
        )
        .expect("a fresh grant over its own terms verifies");
        assert_eq!(granted.key_name(), "TRADER");
        assert_eq!(granted.intent_digest(), B256::from([0x11u8; 32]));

        let mut other = terms();
        other.intent_digest = B256::from([0x99u8; 32]);
        assert!(matches!(
            verify(
                Signed {
                    signature: host_signature(&sk, &terms()),
                    terms: other,
                },
                &pin,
                now,
            ),
            Err(GrantErr::Ecdsa(_))
        ));

        assert!(matches!(
            verify(
                Signed {
                    signature: host_signature(&sk, &terms()),
                    terms: terms(),
                },
                &pin,
                terms().expires_at_ms + 1,
            ),
            Err(GrantErr::Expired { .. })
        ));

        let other_key = SigningKey::random(&mut rand::rngs::OsRng);
        assert!(matches!(
            verify(
                Signed {
                    signature: host_signature(&other_key, &terms()),
                    terms: terms(),
                },
                &pin,
                now,
            ),
            Err(GrantErr::Ecdsa(_))
        ));
    }
}
