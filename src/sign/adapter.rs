//! Trusted adapter: rebuild `safeTxHash` from submitted fields and decode a human summary.
//!
//! The typehashes are derived by alloy's `sol!` from the struct/interface below — never
//! hardcoded — so the digest we sign always matches the canonical Safe EIP-712 encoding.
use crate::sign::intent::{Operation, SafeTxIntent};
use alloy_primitives::B256;
use alloy_sol_types::{sol, Eip712Domain, SolCall, SolStruct};
use err_mac::create_err_with_impls;

sol! {
    struct SafeTx { address to; uint256 value; bytes data; uint8 operation; uint256 safeTxGas; uint256 baseGas; uint256 gasPrice; address gasToken; address refundReceiver; uint256 nonce; }
    interface Known {
        function swapOwner(address prevOwner, address oldOwner, address newOwner);
        function addOwnerWithThreshold(address owner, uint256 threshold);
        function removeOwner(address prevOwner, address owner, uint256 threshold);
        function changeThreshold(uint256 threshold);
        function transfer(address to, uint256 amount);
        function approve(address spender, uint256 amount);
        function transferFrom(address from, address to, uint256 amount);
    }
}

/// The four Safe owner/threshold management selectors — the fail-closed rotation set.
pub const OWNER_MGMT: [[u8; 4]; 4] = [
    Known::swapOwnerCall::SELECTOR,
    Known::addOwnerWithThresholdCall::SELECTOR,
    Known::removeOwnerCall::SELECTOR,
    Known::changeThresholdCall::SELECTOR,
];

const KNOWN: [([u8; 4], &str); 7] = [
    (Known::swapOwnerCall::SELECTOR, "swapOwner"),
    (
        Known::addOwnerWithThresholdCall::SELECTOR,
        "addOwnerWithThreshold",
    ),
    (Known::removeOwnerCall::SELECTOR, "removeOwner"),
    (Known::changeThresholdCall::SELECTOR, "changeThreshold"),
    (Known::transferCall::SELECTOR, "transfer"),
    (Known::approveCall::SELECTOR, "approve"),
    (Known::transferFromCall::SELECTOR, "transferFrom"),
];

create_err_with_impls!(
    #[derive(Debug)]
    pub AdapterErr,
    ;
);

/// Rebuild the Safe EIP-712 `safeTxHash` from the submitted fields.
pub fn safe_tx_hash(i: &SafeTxIntent) -> B256 {
    let t = SafeTx {
        to: i.to,
        value: i.value,
        data: i.data.clone(),
        operation: i.operation.as_u8(),
        safeTxGas: i.safe_tx_gas,
        baseGas: i.base_gas,
        gasPrice: i.gas_price,
        gasToken: i.gas_token,
        refundReceiver: i.refund_receiver,
        nonce: i.nonce,
    };
    let domain = Eip712Domain {
        name: None,
        version: None,
        chain_id: Some(i.chain_id),
        verifying_contract: Some(i.safe),
        salt: None,
    };
    t.eip712_signing_hash(&domain)
}

/// A human-readable decode for the approval prompt: action, value, safe/chain, and the
/// gas-refund fields — with a loud `⚠ REFUND` prefix line whenever `gasPrice != 0` marks a
/// fund-drain, and an `⚠ OWNER ROTATION` head for owner/threshold calls against the Safe.
pub fn summary(i: &SafeTxIntent) -> String {
    let sel4 = i.data.get(..4).map(|s| {
        let mut a = [0u8; 4];
        a.copy_from_slice(s);
        a
    });
    let action = match sel4 {
        None => "raw call".to_string(),
        Some(s) => {
            let mut name = None;
            for (candidate, label) in KNOWN {
                if candidate == s {
                    name = Some(label);
                    break;
                }
            }
            match name {
                Some(label) => label.to_string(),
                None => format!("unknown 0x{}", hex::encode(s)),
            }
        }
    };
    let op = match i.operation {
        Operation::Call => "CALL",
        Operation::Delegatecall => "DELEGATECALL",
    };
    let rotation = matches!(sel4, Some(s) if i.to == i.safe && OWNER_MGMT.contains(&s));
    let head = if rotation {
        format!("\u{26a0} OWNER ROTATION: {action}")
    } else {
        action
    };
    let body = format!(
        "{head} -> {to}  value={value} op={op} nonce={nonce}\n  Safe={safe} chain={chain}\n  \
         refund: gas_price={gas_price} gas_token={gas_token} refund_receiver={refund_receiver} \
         base_gas={base_gas} safe_tx_gas={safe_tx_gas}",
        to = i.to,
        value = i.value,
        nonce = i.nonce,
        safe = i.safe,
        chain = i.chain_id,
        gas_price = i.gas_price,
        gas_token = i.gas_token,
        refund_receiver = i.refund_receiver,
        base_gas = i.base_gas,
        safe_tx_gas = i.safe_tx_gas,
    );
    if i.gas_price.is_zero() {
        body
    } else {
        format!(
            "\u{26a0} REFUND: pays (gasUsed+{base_gas})*{gas_price} of {gas_token} to \
             {refund_receiver}\n{body}",
            base_gas = i.base_gas,
            gas_price = i.gas_price,
            gas_token = i.gas_token,
            refund_receiver = i.refund_receiver,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keccak256;
    use alloy_primitives::{Address, Bytes, U256};

    fn addr_word(a: Address) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a.as_slice());
        w
    }
    fn u256_word(v: U256) -> [u8; 32] {
        v.to_be_bytes::<32>()
    }

    /// The alloy `sol!`-derived SafeTx/domain typehashes must reproduce the canonical Safe
    /// EIP-712 encoding — here recomputed by hand (0x1901 ‖ domainSep ‖ structHash) and
    /// compared against `safe_tx_hash`. A wrong struct definition would diverge.
    #[test]
    fn safe_tx_hash_matches_hand_rolled_eip712() {
        let i = SafeTxIntent {
            key: "trader".into(),
            safe: Address::from([0x11u8; 20]),
            chain_id: U256::from(1u64),
            to: Address::from([0x22u8; 20]),
            value: U256::from(1000u64),
            data: Bytes::from(vec![0x8d, 0x80, 0xff, 0x0a, 0xde, 0xad]),
            operation: Operation::Call,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::from(5u64),
        };

        let type_hash = keccak256(
            b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)".to_vec(),
        );
        let mut enc = Vec::new();
        enc.extend_from_slice(&type_hash);
        enc.extend_from_slice(&addr_word(i.to));
        enc.extend_from_slice(&u256_word(i.value));
        enc.extend_from_slice(&keccak256(i.data.to_vec()));
        enc.extend_from_slice(&u256_word(U256::from(i.operation.as_u8())));
        enc.extend_from_slice(&u256_word(i.safe_tx_gas));
        enc.extend_from_slice(&u256_word(i.base_gas));
        enc.extend_from_slice(&u256_word(i.gas_price));
        enc.extend_from_slice(&addr_word(i.gas_token));
        enc.extend_from_slice(&addr_word(i.refund_receiver));
        enc.extend_from_slice(&u256_word(i.nonce));
        let struct_hash = keccak256(enc);

        let domain_type =
            keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)".to_vec());
        let mut denc = Vec::new();
        denc.extend_from_slice(&domain_type);
        denc.extend_from_slice(&u256_word(i.chain_id));
        denc.extend_from_slice(&addr_word(i.safe));
        let domain_sep = keccak256(denc);

        let mut fin = vec![0x19u8, 0x01];
        fin.extend_from_slice(&domain_sep);
        fin.extend_from_slice(&struct_hash);
        let expected = keccak256(fin);

        assert_eq!(safe_tx_hash(&i).as_slice(), &expected);
    }

    /// The approval summary is the human's only view before signing, so a gas-refund drain must
    /// surface: a non-zero gasPrice adds a loud ⚠ REFUND line naming the receiver, while a
    /// zero-refund intent shows the fields but no warning.
    #[test]
    fn summary_flags_refund_drain() {
        let mut i = SafeTxIntent {
            key: "trader".into(),
            safe: Address::from([0x11u8; 20]),
            chain_id: U256::from(1u64),
            to: Address::from([0x22u8; 20]),
            value: U256::ZERO,
            data: Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]),
            operation: Operation::Call,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::ZERO,
        };
        let clean = summary(&i);
        assert!(!clean.contains("\u{26a0} REFUND"));
        assert!(clean.contains("gas_price=0"));

        let attacker = Address::from([0x55u8; 20]);
        i.gas_price = U256::from(7u64);
        i.refund_receiver = attacker;
        let drained = summary(&i);
        assert!(drained.contains("\u{26a0} REFUND"));
        assert!(drained.contains(&attacker.to_string()));
    }
}
