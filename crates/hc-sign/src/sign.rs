//! The signing flow, split at the biometric so every front end shares one implementation.
//!
//! [`prepare`] and [`prepare_typed_data`] run everything that can refuse — the policy, the typed
//! deconstruction, the rebuilt digest — and hand back the summary a human has to read. The
//! CALLER owns the human interaction: the daemon prints that text and takes Touch ID, a phone
//! shows a sheet and takes Face ID. [`finish`] then consumes the [`Approved`] that only those two
//! can mint, so "the policy ran before the prompt" is a fact of the type system rather than of
//! the call order — and because the summary and the digest leave the same function together, the
//! digest signed is the digest that was read. The caller also hands [`finish`] the keystore
//! container it validated before prompting, and that is the only container the signature sees, so
//! a same-uid writer cannot swap the file while the human decides.
use crate::adapter::{self, typed, Summary};
use crate::grant::{self, GrantTerms, IntentKind, SignGrant};
use crate::intent::{SafeTxIntent, TypedDataIntent};
use crate::manifest::Grant;
use crate::policy::{self, LoadedPolicy};
use crate::{address_of, SafeSignature, SignErr, SignResponse};
use alloy_primitives::{Bytes, B256};
use hc_core::config::Config;
use hc_core::crypto::envelope::parse_keystore;
use hc_core::is_valid_key_name;
use hc_core::mac::local_auth::LaContext;
use hc_core::mac::BackendImpl;
use rand::RngCore;
use zeroize::Zeroizing;

/// A payload that has passed its policy, holding the exact terms one grant will be minted over.
/// Not `Clone`: one preparation buys one signature, and [`finish`] takes it by value.
pub struct Approved {
    key: String,
    digest: B256,
    policy_digest: B256,
    manifest_digest: B256,
    kind: IntentKind,
}

/// Check `intent` against the policy in force, deconstruct every call it makes into typed
/// arguments the policy declared the shape of, rebuild its `safeTxHash`, and return the terms
/// [`finish`] will sign together with the summary the caller must put in front of a human.
/// Everything that can refuse runs here, before the prompt, so a refusal costs no biometric.
pub fn prepare(
    intent: SafeTxIntent,
    policy: &LoadedPolicy,
    grant: Option<&Grant>,
    manifest_digest: B256,
    config: &Config,
) -> Result<(Approved, Summary), SignErr> {
    if !is_valid_key_name(&intent.key) {
        return Err(SignErr::InvalidName);
    }
    require_policy_key(policy, &intent.key)?;
    policy::evaluate(&intent, &policy.policy)?;
    let admitted = adapter::admit(
        intent,
        &policy.policy,
        grant,
        grant::now_ms()? / MILLIS_PER_SECOND,
    )?;
    let digest = admitted.digest();
    let summary = admitted.summary(config);
    Ok((
        Approved {
            key: admitted.intent().key.clone(),
            digest,
            policy_digest: policy.digest,
            manifest_digest,
            kind: IntentKind::SafeTx,
        },
        summary,
    ))
}

/// The same split for an EIP-712 message: the schema is the policy's, the domain is the policy's,
/// and the message is coerced ONCE into the value that is both hashed and rendered here.
pub fn prepare_typed_data(
    intent: TypedDataIntent,
    policy: &LoadedPolicy,
    manifest_digest: B256,
    config: &Config,
) -> Result<(Approved, Summary), SignErr> {
    if !is_valid_key_name(&intent.key) {
        return Err(SignErr::InvalidName);
    }
    require_policy_key(policy, &intent.key)?;
    let admitted = typed::admit(
        &intent,
        &policy.policy,
        grant::now_ms()? / MILLIS_PER_SECOND,
    )?;
    let summary = admitted.summary(&intent.key, config);
    Ok((
        Approved {
            key: intent.key,
            digest: admitted.digest(),
            policy_digest: policy.digest,
            manifest_digest,
            kind: IntentKind::TypedData,
        },
        summary,
    ))
}

/// A policy's filename is the key-to-policy binding. Raw policy bytes may be parsed to validate
/// a bootstrap transfer, but until [`Policy::load`](crate::policy::Policy::load) supplies that
/// filename they authorize no signing key.
fn require_policy_key(policy: &LoadedPolicy, intent: &str) -> Result<(), SignErr> {
    match policy.key_name() {
        Some(key) if key == intent => Ok(()),
        Some(key) => Err(SignErr::PolicyKeyMismatch {
            policy: key.to_string(),
            intent: intent.to_string(),
        }),
        None => Err(SignErr::PolicyKeyMismatch {
            policy: "<unbound>".to_string(),
            intent: intent.to_string(),
        }),
    }
}

/// The repo's one clock reports milliseconds and every timestamp downstream is seconds.
const MILLIS_PER_SECOND: u64 = 1_000;

/// Mint the grant the approval just paid for, verify it against the pinned enclave public key,
/// and sign. `container` is the keystore the caller validated BEFORE the prompt, carried here by
/// value: the signing path never returns to the filesystem, so a same-uid writer replacing
/// `<store>/<KEY>` during the human's deliberation cannot change which key signs. `auth` is the
/// context the approval already evaluated, so neither the enclave grant signature nor the DEK
/// unwrap shows a second sheet. The verified grant carries every term the enclave signed, and all
/// of them are re-asserted here — as one [`GrantTerms::digest`] — before the key is reachable, so
/// what signs is what was approved and not merely a grant for the same keystore and payload.
pub fn finish(
    approved: Approved,
    container: Zeroizing<Vec<u8>>,
    backend: &dyn BackendImpl,
    pinned_grant_pub: &str,
    auth: Option<&LaContext>,
    reason: &str,
) -> Result<SignResponse, SignErr> {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let terms = GrantTerms {
        key_name: approved.key.clone(),
        intent_digest: approved.digest,
        policy_digest: approved.policy_digest,
        manifest_digest: approved.manifest_digest,
        kind: approved.kind,
        nonce,
        expires_at_ms: grant::now_ms()?
            .checked_add(grant::GRANT_TTL_MS)
            .ok_or(grant::GrantErr::ClockOverflow)?,
    };
    let asked = terms.digest();
    let signed = grant::mint(terms, auth)?;
    let granted = grant::verify(signed, pinned_grant_pub, grant::now_ms()?)?;
    if granted.terms_digest() != asked {
        return Err(SignErr::GrantTermsMismatch {
            approved: asked,
            granted: granted.terms_digest(),
        });
    }
    let sig = sign_with_grant(backend, &approved.key, container, reason, auth, granted)?;

    let mut raw = Vec::with_capacity(65);
    raw.extend_from_slice(sig.r.as_slice());
    raw.extend_from_slice(sig.s.as_slice());
    raw.push(sig.v);
    Ok(SignResponse {
        safe_tx_hash: approved.digest,
        signature: Bytes::from(raw),
        signer: sig.signer,
    })
}

/// Sign the digest `grant` attests, with the keystore `container` holds. Both preconditions
/// arrive BY VALUE: the grant covers exactly one signature and carries the digest, so nothing but
/// the approved payload can be signed, and the container is the bytes the caller validated before
/// the approval, so this reads no file and there is nothing for a concurrent writer to swap.
/// Unlocks the DEK (reusing the pre-evaluated `auth` context so no second prompt), decrypts the
/// key in memory, signs, verifies the signature recovers to the signer, then zeroizes both.
pub fn sign_with_grant(
    backend: &dyn BackendImpl,
    key: &str,
    container: Zeroizing<Vec<u8>>,
    reason: &str,
    auth: Option<&LaContext>,
    grant: SignGrant,
) -> Result<SafeSignature, SignErr> {
    use k256::ecdsa::{SigningKey, VerifyingKey};
    if !is_valid_key_name(key) {
        return Err(SignErr::InvalidName);
    }
    if grant.key_name() != key {
        return Err(SignErr::GrantKeyMismatch {
            grant: grant.key_name().to_string(),
            key: key.to_string(),
        });
    }
    let digest = grant.intent_digest();
    let dek = backend.unlock_dek(reason, auth)?;
    let secret = parse_keystore(&container)?.open(key, &dek)?;
    let sk = SigningKey::from_slice(&secret)?;
    let (sig, recid) = sk.sign_prehash_recoverable(digest.as_slice())?;
    let recovered = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, recid)?;
    if &recovered != sk.verifying_key() {
        return Err(SignErr::AddressMismatch);
    }
    let bytes = sig.to_bytes();
    Ok(SafeSignature {
        r: B256::from_slice(&bytes[..32]),
        s: B256::from_slice(&bytes[32..]),
        v: 27 + recid.to_byte(),
        signer: address_of(&recovered),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::crypto::envelope::{encrypt_file, Dek, KeyUse};
    use hc_core::unlock::UnlockErr;

    /// The signer is the last authority boundary around the keystore. Even a direct library
    /// caller holding a test grant cannot turn an invalid key name into an unlock attempt.
    #[test]
    fn an_invalid_granted_key_never_reaches_the_backend() {
        struct Untouchable;

        impl BackendImpl for Untouchable {
            fn unlock_dek(
                &self,
                _reason: &str,
                _auth: Option<&LaContext>,
            ) -> Result<Dek, UnlockErr> {
                panic!("an invalid name must be rejected before unlock")
            }

            fn store(&self) -> &str {
                panic!("the store is never consulted on the signing path")
            }
        }

        let invalid = "../OUTSIDE";
        let result = sign_with_grant(
            &Untouchable,
            invalid,
            Zeroizing::new(Vec::new()),
            "test",
            None,
            grant::grant_for_test(invalid, B256::ZERO),
        );
        assert!(matches!(result, Err(SignErr::InvalidName)));
    }

    /// The container validated before the approval is the one that signs: a same-uid writer that
    /// replaces `<store>/<KEY>` with another secret sealed under the same DEK, name and use —
    /// everything the AAD binds — cannot change which key the grant spends.
    #[test]
    fn a_keystore_swapped_on_disk_cannot_change_which_key_signs() {
        struct Unlocks {
            store: String,
        }

        impl BackendImpl for Unlocks {
            fn unlock_dek(
                &self,
                _reason: &str,
                _auth: Option<&LaContext>,
            ) -> Result<Dek, UnlockErr> {
                Ok(Dek::from_bytes([42u8; 32]))
            }

            fn store(&self) -> &str {
                &self.store
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_sign_swap_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the clock is after the epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create the store");
        let dek = Dek::from_bytes([42u8; 32]);
        let approved = [0x44u8; 32];
        let swapped = [0x55u8; 32];
        encrypt_file(&dir, "SWAP_ME", &dek, KeyUse::SignOnly, &approved)
            .expect("seal the approved key");
        let container = Zeroizing::new(
            std::fs::read(dir.join("SWAP_ME")).expect("read the approved container"),
        );
        encrypt_file(&dir, "SWAP_ME", &dek, KeyUse::SignOnly, &swapped)
            .expect("swap another key into the same file");

        let signature = sign_with_grant(
            &Unlocks {
                store: dir.to_string_lossy().into_owned(),
            },
            "SWAP_ME",
            container,
            "test",
            None,
            grant::grant_for_test("SWAP_ME", B256::from([0x77u8; 32])),
        )
        .expect("the carried container signs");

        let expected = k256::ecdsa::SigningKey::from_slice(&approved).expect("the approved key");
        let usurper = k256::ecdsa::SigningKey::from_slice(&swapped).expect("the swapped key");
        assert_ne!(
            address_of(expected.verifying_key()),
            address_of(usurper.verifying_key())
        );
        assert_eq!(signature.signer, address_of(expected.verifying_key()));

        std::fs::remove_dir_all(dir).expect("clean up the store");
    }

    /// Parsing is sufficient to validate policy bytes in transit, but only loading the policy
    /// from `<store>/policies/<KEY>.toml` binds those bytes to a signing key.
    #[test]
    fn parsed_policy_bytes_cannot_be_rebound_to_an_arbitrary_key() {
        let policy = crate::policy::Policy::parse(
            b"safe = \"0x1111111111111111111111111111111111111111\"\nchain_id = 1\n",
        )
        .expect("minimal policy bytes validate");
        let intent = SafeTxIntent {
            key: "OTHER_KEY".to_string(),
            safe: alloy_primitives::Address::from([0x11u8; 20]),
            chain_id: alloy_primitives::U256::from(1u64),
            to: alloy_primitives::Address::from([0x22u8; 20]),
            value: alloy_primitives::U256::ZERO,
            data: Bytes::new(),
            operation: crate::intent::Operation::Call,
            safe_tx_gas: alloy_primitives::U256::ZERO,
            base_gas: alloy_primitives::U256::ZERO,
            gas_price: alloy_primitives::U256::ZERO,
            gas_token: alloy_primitives::Address::ZERO,
            refund_receiver: alloy_primitives::Address::ZERO,
            nonce: alloy_primitives::U256::ZERO,
        };
        let config: Config =
            toml::from_str("service = \"\"\naccount = \"\"\nstore = \"/nonexistent\"\n")
                .expect("minimal config");
        assert!(matches!(
            prepare(intent, &policy, None, B256::ZERO, &config),
            Err(SignErr::PolicyKeyMismatch { policy, intent })
                if policy == "<unbound>" && intent == "OTHER_KEY"
        ));
    }
}
