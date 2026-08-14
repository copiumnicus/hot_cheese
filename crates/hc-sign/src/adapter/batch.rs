//! Splitting a Safe `multiSend` batch into the sub-calls it actually runs.
//!
//! This module reads boundaries and nothing else. Every entry it yields is handed straight back
//! to [`admit`](super::admit), which matches it against the policy in its own right, decodes it
//! against the signature that matched, and bounds every argument — so a batch is no longer a
//! hole the policy never looked inside, and an entry the policy does not permit refuses the
//! whole transaction.
//!
//! The cursor is stricter than the on-chain library ON PURPOSE. MultiSend's loop guard is
//! `lt(i, length)` with `i` starting at `0x20`, so it stops as soon as fewer than 32 bytes are
//! left: up to 32 trailing bytes are executed-invisible and calldata-visible at the same time, and
//! mirroring that tolerance would let two different calldatas render identically. Consuming the
//! payload EXACTLY refuses every such payload, and can never list an entry the library skips
//! either — an entry needs 85 bytes left and 85 > 32, so wherever this reads one the library's
//! guard still holds.
//!
//! A payload that does not parse yields NOTHING, and now refuses the signature outright: a
//! partly-parsed batch has no proven entry boundaries, so not even the entries "before" the bad
//! one are provably what would execute.
use super::{annotate, call, Body, TypedCall};
use crate::intent::Operation;
use crate::schema::Site;
use alloy_primitives::{Address, Bytes, U256};
use err_mac::create_err_with_impls;
use hc_core::config::Config;

/// Bytes of one entry's packed header: `operation ‖ to ‖ value ‖ dataLength`.
const HEADER: usize = 85;
/// Offset of the 20-byte destination in that header.
const TO: usize = 1;
/// Offset of the 32-byte native value in that header.
const VALUE: usize = 21;
/// Offset of the 32-byte data length in that header.
const DATA_LENGTH: usize = 53;
/// Nesting past which a sub-batch is refused; the transaction's own calldata is depth 0.
const MAX_BATCH_DEPTH: usize = 2;
/// Entries this admits at all, counted across the whole tree.
pub(super) const MAX_BATCH_ENTRIES: usize = 32;
/// Column the destination of every listed entry starts in, so a `DELEGATECALL` cannot hide by
/// being wider than its neighbours.
const OP_WIDTH: usize = 12;

create_err_with_impls!(
    #[derive(Debug)]
    pub BatchErr,
    ;
    Truncated { at: Vec<usize>, offset: usize, need: usize, have: usize },
    UnknownOperation { at: Vec<usize>, offset: usize, operation: u8 },
    DataLengthTooBig { at: Vec<usize>, offset: usize, data_length: U256 },
    DataLengthPastEnd { at: Vec<usize>, offset: usize, data_length: usize, have: usize },
    TooManyEntries { max: usize },
    TooDeep { at: Vec<usize>, max: usize }
);

/// Read a packed payload entry by entry: `operation` 1 byte, `to` 20, `value` 32, `dataLength`
/// 32, then `data`, exactly as `contracts/libraries/MultiSend.sol` loads them (offsets `0x00`,
/// `0x01`, `0x15`, `0x35`, `0x55`, next entry at `0x55 + dataLength`).
///
/// Every departure is a refusal. An `operation` byte other than 0 or 1 hits a `switch` with no
/// default arm, leaving `success` at 0 and reverting the whole transaction, so yielding such an
/// entry as something that executes would be a lie. A `dataLength` that does not fit `usize`, or
/// that reaches past the payload, is refused for the same reason. The `while p < len` guard is
/// what makes trailing bytes a hard failure: an entry needs 85 bytes, so any remainder shorter
/// than that is [`BatchErr::Truncated`] and `p` can only ever finish exactly on the end.
///
/// `left` is the entry budget for the WHOLE tree, and the depth cap is checked here so a nest
/// past it refuses rather than being named and left unread.
pub(super) fn split(
    payload: &[u8],
    parent: &Site,
    left: &mut usize,
) -> Result<Vec<Site>, BatchErr> {
    if parent.at.len() > MAX_BATCH_DEPTH {
        return Err(BatchErr::TooDeep {
            at: parent.at.clone(),
            max: MAX_BATCH_DEPTH,
        });
    }
    let mut out: Vec<Site> = Vec::new();
    let mut p = 0usize;
    while p < payload.len() {
        let have = payload.len() - p;
        if have < HEADER {
            return Err(BatchErr::Truncated {
                at: parent.at.clone(),
                offset: p,
                need: HEADER,
                have,
            });
        }
        let head = &payload[p..p + HEADER];
        let operation = match head[0] {
            0 => Operation::Call,
            1 => Operation::Delegatecall,
            operation => {
                return Err(BatchErr::UnknownOperation {
                    at: parent.at.clone(),
                    offset: p,
                    operation,
                })
            }
        };
        let declared = U256::from_be_slice(&head[DATA_LENGTH..HEADER]);
        let Ok(data_length) = usize::try_from(declared) else {
            return Err(BatchErr::DataLengthTooBig {
                at: parent.at.clone(),
                offset: p,
                data_length: declared,
            });
        };
        let body_have = have - HEADER;
        if data_length > body_have {
            return Err(BatchErr::DataLengthPastEnd {
                at: parent.at.clone(),
                offset: p,
                data_length,
                have: body_have,
            });
        }
        if *left == 0 {
            return Err(BatchErr::TooManyEntries {
                max: MAX_BATCH_ENTRIES,
            });
        }
        *left -= 1;
        let mut at = parent.at.clone();
        at.push(out.len() + 1);
        out.push(Site {
            to: Address::from_slice(&head[TO..VALUE]),
            chain_id: parent.chain_id,
            operation,
            value: U256::from_be_slice(&head[VALUE..DATA_LENGTH]),
            data: Bytes::copy_from_slice(&payload[p + HEADER..p + HEADER + data_length]),
            at,
        });
        p += HEADER + data_length;
    }
    Ok(out)
}

/// The sub-calls as an indented list, each printing its OWN operation, destination, native value
/// and decoded call. It prints its own operation because the transaction's policy rule pinned
/// only the outer one: an entry that delegatecalls runs arbitrary code as the Safe, and it had to
/// be permitted for that destination and that operation in its own right to be listed here at all.
pub(super) fn render(entries: &[TypedCall], config: &Config) -> String {
    let mut all = Vec::new();
    for entry in entries {
        entry.flatten(&mut all);
    }
    let mut out = "multiSend:".to_string();
    for entry in all {
        let what = match &entry.body {
            Body::Batch { entries, .. } => format!("multiSend: {} sub-calls", entries.len()),
            Body::Plain => call::render(entry, config),
        };
        out.push_str(&format!(
            "\n{indent}[{path}] {op:<width$} to={to} value={value} {what}",
            indent = "  ".repeat(entry.site.at.len()),
            path = entry.site.position(),
            op = match entry.site.operation {
                Operation::Call => "CALL",
                Operation::Delegatecall => "DELEGATECALL",
            },
            width = OP_WIDTH,
            to = annotate::address(entry.site.to, entry.site.chain_id, config),
            value = annotate::amount(entry.site.value, Address::ZERO, entry.site.chain_id, config),
        ));
    }
    out
}

/// One packed entry, laid out by hand the way a batch arrives on the wire.
#[cfg(test)]
pub(super) fn packed(operation: u8, to: Address, value: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + data.len());
    out.push(operation);
    out.extend_from_slice(to.as_slice());
    out.extend_from_slice(&U256::from(value).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
    out.extend_from_slice(data);
    out
}

/// `multiSend(bytes)` calldata carrying `payload`, hand-encoded: selector, offset word, length
/// word, then the payload padded to a 32-byte boundary.
#[cfg(test)]
pub(super) fn multi_send(payload: &[u8]) -> Bytes {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x8d, 0x80, 0xff, 0x0a]);
    out.extend_from_slice(&U256::from(32u64).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(payload.len()).to_be_bytes::<32>());
    out.extend_from_slice(payload);
    out.resize(4 + 64 + payload.len().div_ceil(32) * 32, 0);
    Bytes::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::tests::{addr_word, calldata, policy_with, rule_at, shown, u256_word};
    use crate::adapter::{admit, AdapterErr};
    use crate::intent::SafeTxIntent;
    use crate::policy::{CallDenied, Policy, PolicyDenied};
    use crate::schema::{unbounded_call, MULTI_SEND};

    const SAFE: Address = Address::new([0x11u8; 20]);
    const TOKEN: Address = Address::new([0x22u8; 20]);
    const VENDOR: Address = Address::new([0x33u8; 20]);
    const LIB: Address = Address::new([0x44u8; 20]);
    const ATTACKER: Address = Address::new([0x55u8; 20]);

    fn transfer(to: Address, amount: u64) -> Vec<u8> {
        calldata(
            "transfer(address,uint256)",
            &[addr_word(to), u256_word(U256::from(amount))],
        )
        .to_vec()
    }

    fn batching_policy() -> Policy {
        policy_with(vec![
            rule_at(
                LIB,
                Operation::Delegatecall,
                vec![unbounded_call(MULTI_SEND)],
            ),
            rule_at(
                TOKEN,
                Operation::Call,
                vec![unbounded_call("transfer(address,uint256)")],
            ),
        ])
    }

    fn batched(payload: &[u8]) -> SafeTxIntent {
        SafeTxIntent {
            key: "trader".into(),
            safe: SAFE,
            chain_id: U256::from(1u64),
            to: LIB,
            value: U256::ZERO,
            data: multi_send(payload),
            operation: Operation::Delegatecall,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::ZERO,
        }
    }

    fn three() -> Vec<Vec<u8>> {
        vec![
            packed(0, TOKEN, 0, &transfer(VENDOR, 1)),
            packed(0, TOKEN, 0, &transfer(VENDOR, 2)),
            packed(0, TOKEN, 0, &transfer(ATTACKER, 3)),
        ]
    }

    fn retag(entry: &mut [u8], data_length: U256) {
        entry[DATA_LENGTH..HEADER].copy_from_slice(&data_length.to_be_bytes::<32>());
    }

    /// A payload the batch cursor could not read may never pass for one it did — and under
    /// typed-only admission it may not be signed at all. Each malformed packing is its own
    /// refusal naming the offset that broke it, while the clean batch of the same three entries
    /// still admits and lists every one of them in the order they execute.
    #[test]
    fn a_malformed_batch_is_refused_and_a_clean_one_lists_every_entry() {
        let p = batching_policy();
        let clean = three().concat();
        let listed = shown(&batched(&clean), &p);
        assert!(listed.contains("multiSend:"), "{listed}");
        for (n, to) in [(1, VENDOR), (2, VENDOR), (3, ATTACKER)] {
            assert!(
                listed.contains(&format!("[{n}] {:<OP_WIDTH$} to={TOKEN} value=0 ", "CALL")),
                "{listed}"
            );
            assert!(
                listed.contains(&format!("transfer(a0={to}, a1=")),
                "{listed}"
            );
        }

        let mut entries = three();
        let last = entries.last_mut().expect("three entries");
        let one_past = U256::from(last.len() - HEADER + 1);
        retag(last, one_past);
        let past_end = entries.concat();

        let mut trailing = clean.clone();
        trailing.extend_from_slice(&[0u8; 8]);

        let mut bad_operation = clean.clone();
        bad_operation[0] = 2;

        let mut entries = three();
        retag(&mut entries[0], U256::from(1u64) << 64);
        let too_big = entries.concat();

        for (payload, expected) in [
            (past_end, "DataLengthPastEnd"),
            (trailing, "Truncated"),
            (bad_operation, "UnknownOperation"),
            (too_big, "DataLengthTooBig"),
        ] {
            let refused = admit(batched(&payload), &p, None, 0)
                .err()
                .expect("a malformed batch must refuse");
            let named = refused.to_string();
            assert!(
                matches!(&refused, AdapterErr::Batch(_)),
                "{expected}: {named}"
            );
            assert!(named.contains(expected), "{named}");
        }
    }

    /// A truncated list is the worst failure mode here, because entry 33 is where the drain
    /// goes. Both caps are therefore refusals and not display limits: a batch over the entry
    /// ceiling and a nest past the depth ceiling each refuse the whole signature.
    #[test]
    fn batch_caps_refuse_the_signature() {
        let p = batching_policy();
        let mut many = Vec::new();
        for _ in 0..MAX_BATCH_ENTRIES + 1 {
            many.push(packed(0, TOKEN, 0, &transfer(VENDOR, 1)));
        }
        assert!(matches!(
            admit(batched(&many.concat()), &p, None, 0),
            Err(AdapterErr::Batch(BatchErr::TooManyEntries { .. }))
        ));

        let mut nest = packed(0, TOKEN, 0, &transfer(VENDOR, 9));
        for _ in 0..=MAX_BATCH_DEPTH {
            nest = packed(1, LIB, 0, &multi_send(&nest));
        }
        assert!(matches!(
            admit(batched(&nest), &p, None, 0),
            Err(AdapterErr::Batch(BatchErr::TooDeep { max: 2, .. }))
        ));
    }

    /// The property this module was written waiting for: an entry is checked against the policy
    /// in its own right. An entry to a destination no rule names refuses the whole transaction,
    /// a rule for that destination admits it, and an entry carrying native value past that
    /// rule's ceiling refuses again — a ceiling that reached no batch entry before.
    #[test]
    fn a_batch_entry_is_checked_against_the_policy() {
        let tight = batching_policy();
        let stranger = packed(0, ATTACKER, 0, &transfer(VENDOR, 1));
        let refused = admit(batched(&stranger), &tight, None, 0);
        assert!(
            matches!(
                refused,
                Err(AdapterErr::Denied { source, .. })
                    if matches!(*source, PolicyDenied::Call(CallDenied::ToNotAllowed { .. }))
            ),
            "an entry outside the allow-list must refuse the whole transaction"
        );

        let mut open = batching_policy();
        open.allow.push(rule_at(
            ATTACKER,
            Operation::Call,
            vec![unbounded_call("transfer(address,uint256)")],
        ));
        assert!(admit(batched(&stranger), &open, None, 0).is_ok());

        let paid = packed(0, ATTACKER, 1, &transfer(VENDOR, 1));
        assert!(matches!(
            admit(batched(&paid), &open, None, 0),
            Err(AdapterErr::Denied { source, .. })
                if matches!(*source, PolicyDenied::Call(CallDenied::ValueTooHigh { .. }))
        ));

        let empty = packed(0, TOKEN, 0, &[]);
        assert!(
            matches!(
                admit(batched(&empty), &open, None, 0),
                Err(AdapterErr::Denied { source, .. })
                    if matches!(*source, PolicyDenied::Call(CallDenied::NoSelector))
            ),
            "a plain ETH send inside a batch has no selector any rule can permit"
        );
    }
}
