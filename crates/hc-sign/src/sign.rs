//! The signing flow, split at the biometric so every front end shares one implementation.
//!
//! [`prepare`] and [`prepare_typed_data`] run everything that can refuse — the policy, the typed
//! deconstruction, the rebuilt digest — and hand back the summary a human has to read. The
//! CALLER owns the human interaction: the daemon prints that text and takes Touch ID, a phone
//! shows a sheet and takes Face ID. [`finish`] then consumes the [`Approved`] that only those two
//! can mint, so "the policy ran before the prompt" is a fact of the type system rather than of
//! the call order — and because the summary and the digest leave the same function together, the
//! digest signed is the digest that was read.
use crate::adapter::{self, typed};
use crate::grant::{self, GrantTerms, IntentKind, SignGrant};
use crate::intent::{SafeTxIntent, TypedDataIntent};
use crate::manifest::Grant;
use crate::policy::{self, LoadedPolicy};
use crate::{address_of, SafeSignature, SignErr, SignResponse};
use alloy_primitives::{Bytes, B256};
use hc_core::config::Config;
use hc_core::crypto::envelope::decrypt_file;
use hc_core::mac::local_auth::LaContext;
use hc_core::mac::BackendImpl;
use rand::RngCore;
use zeroize::Zeroize;

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
) -> Result<(Approved, String), SignErr> {
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
) -> Result<(Approved, String), SignErr> {
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

/// The repo's one clock reports milliseconds and every timestamp downstream is seconds.
const MILLIS_PER_SECOND: u64 = 1_000;

/// Mint the grant the approval just paid for, verify it against the pinned enclave public key,
/// and sign. `auth` is the context the approval already evaluated, so neither the enclave grant
/// signature nor the DEK unwrap shows a second sheet.
pub fn finish(
    approved: Approved,
    backend: &dyn BackendImpl,
    pinned_grant_pub: &str,
    auth: Option<&LaContext>,
    reason: &str,
) -> Result<SignResponse, SignErr> {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let signed = grant::mint(
        GrantTerms {
            key_name: approved.key.clone(),
            intent_digest: approved.digest,
            policy_digest: approved.policy_digest,
            manifest_digest: approved.manifest_digest,
            kind: approved.kind,
            nonce,
            expires_at_ms: grant::now_ms()? + grant::GRANT_TTL_MS,
        },
        auth,
    )?;
    let granted = grant::verify(signed, pinned_grant_pub, grant::now_ms()?)?;
    let sig = sign_with_grant(backend, &approved.key, reason, auth, granted)?;

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

/// Sign the digest `grant` attests, with keystore `key`. The grant is the precondition: it
/// arrives BY VALUE and is dropped here, so it covers exactly one signature, and it carries the
/// digest, so nothing but the approved payload can be signed. Unlocks the DEK (reusing the
/// pre-evaluated `auth` context so no second prompt), decrypts the key in memory, signs,
/// verifies the signature recovers to the signer, then zeroizes it.
pub fn sign_with_grant(
    backend: &dyn BackendImpl,
    key: &str,
    reason: &str,
    auth: Option<&LaContext>,
    grant: SignGrant,
) -> Result<SafeSignature, SignErr> {
    use k256::ecdsa::{SigningKey, VerifyingKey};
    if grant.key_name() != key {
        return Err(SignErr::GrantKeyMismatch {
            grant: grant.key_name().to_string(),
            key: key.to_string(),
        });
    }
    let digest = grant.intent_digest();
    let path = backend.store_path().join(key);
    if !path.exists() {
        return Err(SignErr::KeyNotExists);
    }
    let dek = backend.unlock_dek(reason, auth)?;
    let mut secret = decrypt_file(&path, key, &dek)?;
    let result = (|| {
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
    })();
    secret.zeroize();
    result
}
