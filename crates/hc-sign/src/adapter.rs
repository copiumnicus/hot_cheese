//! Trusted adapter: rebuild `safeTxHash` from submitted fields and decode a human summary.
//!
//! The typehashes are derived by alloy's `sol!` from the struct/interface below — never
//! hardcoded — so the digest we sign always matches the canonical Safe EIP-712 encoding.
use crate::intent::{Operation, SafeTxIntent};
use alloy_primitives::{B256, U256};
use alloy_sol_types::{sol, Eip712Domain, SolCall, SolInterface, SolStruct};
use err_mac::create_err_with_impls;
use sha2::{Digest, Sha256};

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

/// Bit width past which an amount exceeds any plausible token supply.
const HUGE_AMOUNT_BITS: usize = 128;

/// Hex characters of the calldata digest shown when the arguments do not decode.
const DIGEST_CHARS: usize = 16;

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

fn selector4(data: &[u8]) -> Option<[u8; 4]> {
    let head = data.get(..4)?;
    let mut s = [0u8; 4];
    s.copy_from_slice(head);
    Some(s)
}

/// Render a quantity the operator has to judge with no decimals context: the exact integer,
/// called out when it is past anything a real payment carries.
fn amount(v: U256) -> String {
    if v == U256::MAX {
        return format!("{v} \u{26a0} UNLIMITED (2^256-1)");
    }
    if v.bit_len() > HUGE_AMOUNT_BITS {
        return format!("{v} \u{26a0} HUGE (>2^{HUGE_AMOUNT_BITS})");
    }
    v.to_string()
}

/// Decode the arguments of the calls the `sol!` interface declares and render them, so the
/// human approves WHO gets HOW MUCH instead of a selector label. Decoding is canonical-only:
/// calldata that does not re-encode to the exact submitted bytes is reported as undecoded,
/// named by its length and digest so two payloads can never render the same.
fn render_call(data: &[u8]) -> String {
    if data.is_empty() {
        return "no calldata (value transfer only)".to_string();
    }
    let decoded = match Known::KnownCalls::abi_decode(data, true) {
        Ok(decoded) => decoded,
        Err(_) => {
            let full = hex::encode(Sha256::digest(data));
            let short: String = full.chars().take(DIGEST_CHARS).collect();
            let len = data.len();
            return match selector4(data) {
                Some(s) => format!(
                    "UNDECODED CALL 0x{}: {len} bytes, sha256 {short}",
                    hex::encode(s)
                ),
                None => format!("UNDECODED CALL: {len} bytes, sha256 {short}"),
            };
        }
    };
    match decoded {
        Known::KnownCalls::transfer(c) => {
            format!("transfer(to={}, amount={})", c.to, amount(c.amount))
        }
        Known::KnownCalls::approve(c) => {
            format!(
                "approve(spender={}, amount={})",
                c.spender,
                amount(c.amount)
            )
        }
        Known::KnownCalls::transferFrom(c) => format!(
            "transferFrom(from={}, to={}, amount={})",
            c.from,
            c.to,
            amount(c.amount)
        ),
        Known::KnownCalls::swapOwner(c) => format!(
            "swapOwner(prevOwner={}, oldOwner={}, newOwner={})",
            c.prevOwner, c.oldOwner, c.newOwner
        ),
        Known::KnownCalls::addOwnerWithThreshold(c) => format!(
            "addOwnerWithThreshold(owner={}, threshold={})",
            c.owner,
            amount(c.threshold)
        ),
        Known::KnownCalls::removeOwner(c) => format!(
            "removeOwner(prevOwner={}, owner={}, threshold={})",
            c.prevOwner,
            c.owner,
            amount(c.threshold)
        ),
        Known::KnownCalls::changeThreshold(c) => {
            format!("changeThreshold(threshold={})", amount(c.threshold))
        }
    }
}

/// The human's only view of what they are signing: the call and whatever its calldata proves,
/// then destination, value, operation and nonce, then Safe/chain and the gas-refund fields.
/// The two fund-draining shapes lead — `⚠ REFUND` for a non-zero `gasPrice`, `⚠ OWNER ROTATION`
/// for an owner/threshold call against the Safe — because an approval sheet gets the head of
/// this text, never the tail.
pub fn summary(i: &SafeTxIntent) -> String {
    let op = match i.operation {
        Operation::Call => "CALL",
        Operation::Delegatecall => "DELEGATECALL",
    };
    let rotation =
        matches!(selector4(&i.data), Some(s) if i.to == i.safe && OWNER_MGMT.contains(&s));
    let call = render_call(&i.data);
    let head = if rotation {
        format!("\u{26a0} OWNER ROTATION: {call}")
    } else {
        call
    };
    let body = format!(
        "{head}\n  to={to} value={value} op={op} nonce={nonce}\n  Safe={safe} chain={chain}\n  \
         refund: gas_price={gas_price} gas_token={gas_token} refund_receiver={refund_receiver} \
         base_gas={base_gas} safe_tx_gas={safe_tx_gas}",
        to = i.to,
        value = amount(i.value),
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
    use alloy_primitives::{Address, Bytes, U256};
    use hc_core::crypto::keccak256;

    fn addr_word(a: Address) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a.as_slice());
        w
    }
    fn u256_word(v: U256) -> [u8; 32] {
        v.to_be_bytes::<32>()
    }

    const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

    /// Real ERC-20 `transfer` calldata, hand-encoded the way a caller puts it on the wire.
    fn transfer_data(to: Address, amount: U256) -> Bytes {
        let mut d = Vec::with_capacity(68);
        d.extend_from_slice(&TRANSFER);
        d.extend_from_slice(&addr_word(to));
        d.extend_from_slice(&u256_word(amount));
        Bytes::from(d)
    }

    /// An intent against the token the demo policy allow-lists, with no refund activity.
    fn base_intent() -> SafeTxIntent {
        SafeTxIntent {
            key: "trader".into(),
            safe: Address::from([0x11u8; 20]),
            chain_id: U256::from(1u64),
            to: Address::from([0x22u8; 20]),
            value: U256::ZERO,
            data: Bytes::new(),
            operation: Operation::Call,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::ZERO,
        }
    }

    fn sheet(summary: &str) -> String {
        summary.lines().take(3).collect::<Vec<_>>().join("\n")
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
        let mut i = base_intent();
        i.data = Bytes::from(TRANSFER.to_vec());
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

    /// The calldata arguments are the whole payload: two `transfer`s to the same allow-listed
    /// token, with the same native value and nonce, differ ONLY in recipient and amount, so
    /// they must differ on screen — and inside the first three lines, which is all the approval
    /// sheet shows, with and without a refund line ahead of them.
    #[test]
    fn two_transfers_never_render_the_same() {
        let vendor = Address::from([0x33u8; 20]);
        let attacker = Address::from([0x55u8; 20]);

        let mut i = base_intent();
        i.data = transfer_data(vendor, U256::from(1u64));
        let paid = summary(&i);
        i.data = transfer_data(attacker, U256::MAX);
        let drained = summary(&i);
        assert_ne!(paid, drained);

        assert!(sheet(&paid).contains(&format!("transfer(to={vendor}, amount=1)")));
        assert!(!paid.contains(&attacker.to_string()));

        let drained_sheet = sheet(&drained);
        assert!(drained_sheet.contains(&format!("transfer(to={attacker}, amount=")));
        assert!(drained_sheet.contains(&U256::MAX.to_string()));
        assert!(drained_sheet.contains("UNLIMITED"));

        i.gas_price = U256::from(7u64);
        let with_refund = sheet(&summary(&i));
        assert!(with_refund.starts_with("\u{26a0} REFUND"));
        assert!(with_refund.contains(&format!("transfer(to={attacker}, amount=")));
    }

    /// Arguments that do not decode canonically are never claimed as decoded, and two payloads
    /// that differ anywhere still read differently: a dirty address word is not a clean
    /// `transfer`, and two bodies under one unknown selector are told apart by their digests.
    #[test]
    fn undecodable_payloads_stay_distinguishable() {
        let mut i = base_intent();
        i.data = Bytes::from([&[0xde, 0xad, 0xbe, 0xef][..], &[0x01u8; 32][..]].concat());
        let one = summary(&i);
        i.data = Bytes::from([&[0xde, 0xad, 0xbe, 0xef][..], &[0x02u8; 32][..]].concat());
        let two = summary(&i);
        assert!(one.contains("UNDECODED CALL 0xdeadbeef: 36 bytes"));
        assert!(two.contains("UNDECODED CALL 0xdeadbeef: 36 bytes"));
        assert_ne!(one, two);

        let mut dirty = transfer_data(Address::from([0x33u8; 20]), U256::from(1u64)).to_vec();
        dirty[4] = 0xff;
        i.data = Bytes::from(dirty);
        let smuggled = summary(&i);
        assert!(smuggled.contains("UNDECODED CALL 0xa9059cbb: 68 bytes"));
        assert!(!smuggled.contains("transfer(to="));
    }
}
