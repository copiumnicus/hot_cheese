//! Scoped Gnosis Safe multisig signing.
//!
//! A service submits SafeTx FIELDS (never a hash). The [`adapter`] rebuilds `safeTxHash`
//! via alloy `sol!`; [`policy`] fail-closed-checks it per key; [`approval`] takes ONE
//! Touch-ID prompt showing the decoded action; only `{r,s,v}` is returned.
pub mod adapter;
pub mod approval;
pub mod intent;
pub mod policy;
pub mod wire;

use alloy_primitives::{Address, Bytes, B256};
use err_mac::create_err_with_impls;
use serde::Serialize;

create_err_with_impls!(
    #[derive(Debug)]
    pub SignErr,
    KeyNotExists,
    AddressMismatch,
    ApprovalDenied,
    IntentKeyMismatch,
    InvalidName,
    Serde(serde_json::Error),
    Policy(policy::PolicyErr),
    Adapter(adapter::AdapterErr),
    Unlock(crate::unlock::UnlockErr),
    Envelope(crate::crypto::envelope::EnvErr),
    Ecdsa(k256::ecdsa::Error),
    Se(crate::mac::secure_enclave::SeErr)
    ;
);

/// The recoverable ECDSA signature plus the address it recovers to.
pub struct SafeSignature {
    pub r: B256,
    pub s: B256,
    pub v: u8,
    pub signer: Address,
}

/// The signing response: the rebuilt hash, the 65-byte `r‖s‖v` signature, and the signer.
#[derive(Serialize)]
pub struct SignResponse {
    pub safe_tx_hash: B256,
    pub signature: Bytes,
    pub signer: Address,
}
