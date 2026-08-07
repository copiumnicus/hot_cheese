//! Untrusted wire input: a service submits SafeTx FIELDS (never a hash).
use alloy_primitives::{Address, Bytes, U256};
use serde::{Deserialize, Serialize};

/// Safe `Enum.Operation`: a plain CALL or a DELEGATECALL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    #[default]
    Call,
    Delegatecall,
}

impl Operation {
    pub fn as_u8(self) -> u8 {
        match self {
            Operation::Call => 0,
            Operation::Delegatecall => 1,
        }
    }
}

/// A submitted signing intent. `kind` selects the versioned variant.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Intent {
    SafeTx(SafeTxIntent),
}

/// The ten Safe `execTransaction` fields plus the local keystore `key` to sign with. A field
/// this struct does not name is a refusal, not a silent drop: an intent carrying one is
/// something the daemon does not understand, and it is rejected before any approval.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeTxIntent {
    /// Local keystore name authorized to sign this intent.
    pub key: String,
    /// The Safe (EIP-712 verifying contract).
    pub safe: Address,
    #[serde(with = "crate::wire::u256")]
    pub chain_id: U256,
    pub to: Address,
    #[serde(default, with = "crate::wire::u256")]
    pub value: U256,
    #[serde(default)]
    pub data: Bytes,
    pub operation: Operation,
    #[serde(default, with = "crate::wire::u256")]
    pub safe_tx_gas: U256,
    #[serde(default, with = "crate::wire::u256")]
    pub base_gas: U256,
    #[serde(default, with = "crate::wire::u256")]
    pub gas_price: U256,
    #[serde(default)]
    pub gas_token: Address,
    #[serde(default)]
    pub refund_receiver: Address,
    #[serde(with = "crate::wire::u256")]
    pub nonce: U256,
}
