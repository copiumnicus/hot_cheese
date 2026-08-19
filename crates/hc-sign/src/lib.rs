//! Scoped Gnosis Safe multisig signing.
//!
//! A service submits SafeTx FIELDS (never a hash). The [`adapter`] rebuilds `safeTxHash`
//! via alloy `sol!`; [`policy`] fail-closed-checks it per key; whoever owns the terminal
//! takes ONE Touch-ID prompt showing the decoded action; that same biometric mints the
//! [`grant`] the signing call demands; only `{r,s,v}` is returned.
//!
//! An out-of-process adapter reaches the same flow through its own socket, and its
//! [`manifest`] can only ever NARROW that key's policy — never widen it.
//!
//! [`sign`] is that flow split at the biometric, so the daemon and a phone run the same code
//! and only the human half differs. A [`bundle`] carries the intent plus the signatures
//! collected so far between devices, and [`qr`] frames one for a camera.
//!
//! The key itself is reachable through exactly one function, [`sign::sign_with_grant`]: it
//! demands a [`grant::SignGrant`] and the keystore container the caller validated before the
//! approval, both by value, decrypts under the DEK for one signature, and zeroizes. Everything
//! else here decides WHAT may be signed.
pub mod adapter;
pub mod bundle;
pub mod grant;
pub mod intent;
pub mod manifest;
pub mod policy;
pub mod qr;
pub mod schema;
pub mod sign;

use alloy_primitives::{Address, Bytes, B256};
use err_mac::create_err_with_impls;
use serde::{Deserialize, Serialize};

create_err_with_impls!(
    #[derive(Debug)]
    pub SignErr,
    KeyNotExists,
    AddressMismatch,
    ApprovalDenied,
    NoApprovalTerminal,
    IntentKeyMismatch,
    InvalidName,
    Serde(serde_json::Error),
    Policy(policy::PolicyErr),
    PolicyDenied(policy::PolicyDenied),
    ManifestDenied(manifest::ManifestDenied),
    Adapter(adapter::AdapterErr),
    Typed(adapter::typed::TypedDenied),
    Grant(grant::GrantErr),
    Unlock(hc_core::unlock::UnlockErr),
    Envelope(hc_core::crypto::envelope::EnvErr),
    Ecdsa(k256::ecdsa::Error),
    Se(hc_core::mac::secure_enclave::SeErr)
    ;
    GrantKeyMismatch { grant: String, key: String },
    GrantTermsMismatch { approved: B256, granted: B256 },
    PolicyKeyMismatch { policy: String, intent: String }
);

/// The recoverable ECDSA signature plus the address it recovers to.
pub struct SafeSignature {
    pub r: B256,
    pub s: B256,
    pub v: u8,
    pub signer: Address,
}

/// The signing response: the rebuilt hash, the 65-byte `r‖s‖v` signature, and the signer.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignResponse {
    pub safe_tx_hash: B256,
    pub signature: Bytes,
    pub signer: Address,
}

/// The EVM address of a recovered or derived public key: keccak of the uncompressed point,
/// last 20 bytes. The signer a signature reports and the signer a bundle recovers are the
/// same derivation, so they are the same code.
pub(crate) fn address_of(key: &k256::ecdsa::VerifyingKey) -> Address {
    let point = key.to_encoded_point(false);
    Address::from_slice(&hc_core::crypto::keccak256(&point.as_bytes()[1..])[12..])
}
