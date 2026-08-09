//! Unpacking a Safe `multiSend` batch into the sub-calls it actually runs.
//!
//! [`policy::evaluate`](crate::policy::evaluate) checks the transaction's destination, its
//! operation, the 4-byte selector and the NATIVE value it sends. For a `multiSend` delegatecall
//! that proves the library is allow-listed, that delegatecall is permitted for it, that the
//! selector matches and that the native value is under the ceiling — and it inspects NONE of the
//! N sub-calls inside. This decode is the only thing between the operator and whatever those
//! sub-calls do, which is why the roll-up says "none of them checked by policy" in as many words.
//! The real fix is a sub-policy evaluated over batch entries; until there is one, this is the
//! stopgap, and it must never overstate what it proved.
//!
//! The cursor is stricter than the on-chain library ON PURPOSE. MultiSend's loop guard is
//! `lt(i, length)` with `i` starting at `0x20`, so it stops as soon as fewer than 32 bytes are
//! left: up to 32 trailing bytes are executed-invisible and calldata-visible at the same time, and
//! mirroring that tolerance would let two different calldatas render identically. Consuming the
//! payload EXACTLY refuses every such payload, and can never list an entry the library skips
//! either — an entry needs 85 bytes left and 85 > 32, so wherever this reads one the library's
//! guard still holds.
//!
//! A payload that does not parse lists NOTHING. A partly-parsed batch has no proven entry
//! boundaries, so not even the entries "before" the bad one are provably what would be printed,
//! and a truncated list is the worst failure mode there is here: entry 33 is where the drain goes.
use super::{annotate, call, Alarm, Known, Raised, Site};
use crate::intent::{Operation, SafeTxIntent};
use alloy_primitives::{Address, Bytes, U256};
use err_mac::create_err_with_impls;
use hc_core::config::Config;
use sha2::{Digest, Sha256};

/// Bytes of one entry's packed header: `operation ‖ to ‖ value ‖ dataLength`.
const HEADER: usize = 85;
/// Offset of the 20-byte destination in that header.
const TO: usize = 1;
/// Offset of the 32-byte native value in that header.
const VALUE: usize = 21;
/// Offset of the 32-byte data length in that header.
const DATA_LENGTH: usize = 53;
/// Nesting past which a sub-batch is named and left unexpanded; the transaction's own calldata
/// is depth 0.
const MAX_BATCH_DEPTH: usize = 2;
/// Entries this will list at all, counted across the whole tree.
const MAX_BATCH_ENTRIES: usize = 32;
/// Column the destination of every listed entry starts in, so a `DELEGATECALL` cannot hide by
/// being wider than its neighbours.
const OP_WIDTH: usize = 12;

create_err_with_impls!(
    #[derive(Debug)]
    pub(super) BatchErr,
    ;
    Truncated { at: usize, need: usize, have: usize },
    UnknownOperation { at: usize, operation: u8 },
    DataLengthTooBig { at: usize, data_length: U256 },
    DataLengthPastEnd { at: usize, data_length: usize, have: usize },
    TooManyEntries { max: usize }
);

/// What one entry's calldata turned out to be.
enum Body {
    /// A canonically decoded call, never a `multiSend`.
    Decoded(Known::KnownCalls),
    /// Calldata that does not decode canonically.
    Undecoded,
    /// A nested `multiSend` and the entries it carries.
    Nested(Vec<Entry>),
    /// A nested `multiSend` past [`MAX_BATCH_DEPTH`], named but not expanded.
    Unexpanded,
}

/// One entry of a packed `multiSend` payload.
struct Entry {
    /// The call it makes, with its own operation and its position in the tree.
    site: Site,
    /// Native value it sends.
    value: U256,
    /// What its calldata turned out to be.
    body: Body,
}

/// Read a packed payload entry by entry: `operation` 1 byte, `to` 20, `value` 32, `dataLength`
/// 32, then `data`, exactly as `contracts/libraries/MultiSend.sol` loads them (offsets `0x00`,
/// `0x01`, `0x15`, `0x35`, `0x55`, next entry at `0x55 + dataLength`).
///
/// Every departure is a refusal. An `operation` byte other than 0 or 1 hits a `switch` with no
/// default arm, leaving `success` at 0 and reverting the whole transaction, so rendering such an
/// entry as something that executes would be a lie. A `dataLength` that does not fit `usize`, or
/// that reaches past the payload, is refused for the same reason. The `while p < len` guard is
/// what makes trailing bytes a hard failure: an entry needs 85 bytes, so any remainder shorter
/// than that is [`BatchErr::Truncated`] and `p` can only ever finish exactly on the end.
fn parse(
    payload: &Bytes,
    chain_id: U256,
    at: &[usize],
    left: &mut usize,
) -> Result<Vec<Entry>, BatchErr> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < payload.len() {
        let have = payload.len() - p;
        if have < HEADER {
            return Err(BatchErr::Truncated {
                at: p,
                need: HEADER,
                have,
            });
        }
        let head = &payload[p..p + HEADER];
        let operation = match head[0] {
            0 => Operation::Call,
            1 => Operation::Delegatecall,
            operation => return Err(BatchErr::UnknownOperation { at: p, operation }),
        };
        let value = U256::from_be_slice(&head[VALUE..DATA_LENGTH]);
        let declared = U256::from_be_slice(&head[DATA_LENGTH..HEADER]);
        let Ok(data_length) = usize::try_from(declared) else {
            return Err(BatchErr::DataLengthTooBig {
                at: p,
                data_length: declared,
            });
        };
        let body_have = have - HEADER;
        if data_length > body_have {
            return Err(BatchErr::DataLengthPastEnd {
                at: p,
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
        let data = Bytes::copy_from_slice(&payload[p + HEADER..p + HEADER + data_length]);
        p += HEADER + data_length;
        let mut here = at.to_vec();
        here.push(out.len() + 1);
        let body = match super::canonical(&data) {
            Some(Known::KnownCalls::multiSend(_)) if here.len() > MAX_BATCH_DEPTH => {
                Body::Unexpanded
            }
            Some(Known::KnownCalls::multiSend(c)) => {
                Body::Nested(parse(&c.transactions, chain_id, &here, left)?)
            }
            Some(decoded) => Body::Decoded(decoded),
            None => Body::Undecoded,
        };
        out.push(Entry {
            site: Site {
                to: Address::from_slice(&head[TO..VALUE]),
                chain_id,
                operation,
                data,
                at: here,
            },
            value,
            body,
        });
    }
    Ok(out)
}

/// The whole tree in the order it executes, so an entry's position is where it is printed.
fn flatten<'a>(entries: &'a [Entry], out: &mut Vec<&'a Entry>) {
    for entry in entries {
        out.push(entry);
        if let Body::Nested(inner) = &entry.body {
            flatten(inner, out);
        }
    }
}

/// The dotted position of an entry: `2` for the second sub-call, `2.1` for the first sub-call of
/// the second sub-call. It names the same entry in the list and in any alarm hoisted out of it.
pub(super) fn position(at: &[usize]) -> String {
    let mut out = String::new();
    for step in at {
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&step.to_string());
    }
    out
}

/// The line a batch that cannot be listed renders, both as its alarm and in place of the list.
/// Nothing here can be a summary of the entries, because there are no proven entries — so it is
/// the refusal itself, with the offending offsets, and the length and WHOLE digest of the payload
/// refused, which is the only thing that keeps two refused payloads from reading the same.
pub(super) fn unlistable(err: &BatchErr, payload: &Bytes) -> String {
    let bytes = payload.len();
    let digest = hex::encode(Sha256::digest(payload));
    match err {
        BatchErr::TooManyEntries { max } => {
            format!("\u{26a0} BATCH TOO LARGE: over {max} entries, {bytes} bytes, sha256 {digest}")
        }
        refused => format!("\u{26a0} MALFORMED BATCH ({refused}): {bytes} bytes, sha256 {digest}"),
    }
}

/// The sub-calls as an indented list, each printing its OWN operation, destination, native value
/// and decoded call. It prints its own operation because policy pinned only the outer one: an
/// entry that delegatecalls is arbitrary code running as the Safe that nothing in this system
/// looked at. An entry whose calldata does not decode is named by its length and digest right
/// there in the list — the batch does not become trustworthy because its other entries decoded.
pub(super) fn render(payload: &Bytes, site: &Site, config: &Config) -> String {
    let mut left = MAX_BATCH_ENTRIES;
    let parsed = match parse(payload, site.chain_id, &[], &mut left) {
        Ok(parsed) => parsed,
        Err(err) => return unlistable(&err, payload),
    };
    let mut all = Vec::new();
    flatten(&parsed, &mut all);
    let mut out = "multiSend:".to_string();
    for entry in all {
        let what = match &entry.body {
            Body::Decoded(decoded) => call::render(&entry.site, config, Some(decoded)),
            Body::Undecoded => call::render(&entry.site, config, None),
            Body::Nested(inner) => format!("multiSend: {} sub-calls", inner.len()),
            Body::Unexpanded => format!(
                "\u{26a0} NESTED BATCH BEYOND DEPTH {MAX_BATCH_DEPTH}: {} bytes, sha256 {}",
                entry.site.data.len(),
                hex::encode(Sha256::digest(&entry.site.data))
            ),
        };
        out.push_str(&format!(
            "\n{indent}[{path}] {op:<width$} to={to} value={value} {what}",
            indent = "  ".repeat(entry.site.at.len()),
            path = position(&entry.site.at),
            op = match entry.site.operation {
                Operation::Call => "CALL",
                Operation::Delegatecall => "DELEGATECALL",
            },
            width = OP_WIDTH,
            to = annotate::address(entry.site.to, entry.site.chain_id, config),
            value = annotate::amount(entry.value, Address::ZERO, entry.site.chain_id, config),
        ));
    }
    out
}

/// The roll-up naming how many sub-calls policy never looked at, then the alarms of each sub-call
/// that decoded, each carrying the position it came from so it competes for the three lines of an
/// approval sheet on rank rather than on where it sits in the batch.
///
/// A sub-call that does NOT decode hoists nothing and is counted in the roll-up instead: three
/// unreadable entries outrank everything else in this system, and hoisting them would push an
/// `enableModule` off the sheet with noise that says only "unknown". A nested batch left
/// unexpanded is counted the same way and for the same reason.
pub(super) fn alarms(payload: &Bytes, i: &SafeTxIntent, site: &Site) -> Vec<Raised> {
    let mut left = MAX_BATCH_ENTRIES;
    let parsed = match parse(payload, site.chain_id, &[], &mut left) {
        Ok(parsed) => parsed,
        Err(err) => {
            return vec![Raised {
                alarm: Alarm::BatchMalformed {
                    err,
                    payload: payload.clone(),
                },
                site: site.clone(),
            }]
        }
    };
    let mut all = Vec::new();
    flatten(&parsed, &mut all);
    let mut undecoded = 0usize;
    let mut unexpanded = 0usize;
    let mut hoisted = Vec::new();
    for entry in &all {
        match &entry.body {
            Body::Decoded(decoded) => {
                for alarm in super::alarms(i, &entry.site, Some(decoded)) {
                    hoisted.push(Raised {
                        alarm,
                        site: entry.site.clone(),
                    });
                }
            }
            Body::Undecoded => undecoded += 1,
            Body::Unexpanded => unexpanded += 1,
            Body::Nested(_) => {}
        }
    }
    let mut out = vec![Raised {
        alarm: Alarm::Batch {
            calls: all.len(),
            undecoded,
            unexpanded,
            payload: payload.clone(),
        },
        site: site.clone(),
    }];
    out.extend(hoisted);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolCall;

    const SAFE: Address = Address::new([0x11u8; 20]);
    const TOKEN: Address = Address::new([0x22u8; 20]);
    const VENDOR: Address = Address::new([0x33u8; 20]);
    const LIB: Address = Address::new([0x44u8; 20]);
    const ATTACKER: Address = Address::new([0x55u8; 20]);
    const MODULE: Address = Address::new([0x66u8; 20]);
    const VICTIM: Address = Address::new([0x77u8; 20]);

    /// One packed entry, laid out by hand the way a batch arrives on the wire.
    fn entry(operation: u8, to: Address, value: u64, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + data.len());
        out.push(operation);
        out.extend_from_slice(to.as_slice());
        out.extend_from_slice(&U256::from(value).to_be_bytes::<32>());
        out.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
        out.extend_from_slice(data);
        out
    }

    fn calldata(payload: &[u8]) -> Bytes {
        Bytes::from(
            Known::multiSendCall {
                transactions: Bytes::copy_from_slice(payload),
            }
            .abi_encode(),
        )
    }

    /// The whole approval summary of a Safe transaction that delegatecalls this payload.
    fn shown(payload: &[u8]) -> String {
        let config = toml::from_str("service = \"\"\naccount = \"\"\nstore = \"/nonexistent\"\n")
            .expect("a config with no annotation tables");
        let intent = SafeTxIntent {
            key: "trader".into(),
            safe: SAFE,
            chain_id: U256::from(1u64),
            to: LIB,
            value: U256::ZERO,
            data: calldata(payload),
            operation: Operation::Delegatecall,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::ZERO,
        };
        super::super::summary(&intent, &config)
    }

    fn approve_max() -> Vec<u8> {
        Known::approveCall {
            spender: ATTACKER,
            amount: U256::MAX,
        }
        .abi_encode()
    }

    fn pay_vendor() -> Vec<u8> {
        Known::transferCall {
            to: VENDOR,
            amount: U256::from(1_000_000u64),
        }
        .abi_encode()
    }

    fn enable_module() -> Vec<u8> {
        Known::enableModuleCall { module: MODULE }.abi_encode()
    }

    fn three() -> Vec<Vec<u8>> {
        vec![
            entry(0, TOKEN, 0, &approve_max()),
            entry(0, TOKEN, 0, &pay_vendor()),
            entry(0, SAFE, 0, &enable_module()),
        ]
    }

    /// Overwrite the `dataLength` word of one packed entry, which is the field the on-chain
    /// cursor trusts to find the next entry.
    fn retag(entry: &mut [u8], data_length: U256) {
        entry[DATA_LENGTH..HEADER].copy_from_slice(&data_length.to_be_bytes::<32>());
    }

    fn lists_nothing(shown: &str) {
        assert!(!shown.contains("multiSend:"), "{shown}");
        assert!(!shown.contains("] CALL"), "{shown}");
        assert!(!shown.contains("] DELEGATECALL"), "{shown}");
    }

    /// The one thing this decode may never do is let a payload the batch cursor could not read
    /// pass for one it did. Four packed payloads derived from one clean batch — a `dataLength`
    /// reaching one byte past the end, eight trailing bytes the on-chain loop guard would skip
    /// over, an `operation` byte the on-chain `switch` has no arm for, and a `dataLength` no
    /// `usize` holds — must each say so, must list NO entry (a partly-parsed batch has no proven
    /// boundaries, so not even the entries before the bad one are provably what would print), and
    /// all five renderings must differ from each other.
    #[test]
    fn a_malformed_batch_never_renders_as_a_clean_one() {
        let clean = three().concat();

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

        let renders = [
            shown(&clean),
            shown(&past_end),
            shown(&trailing),
            shown(&bad_operation),
            shown(&too_big),
        ];
        for refused in &renders[1..] {
            assert!(refused.contains("\u{26a0} MALFORMED BATCH"), "{refused}");
            assert!(!refused.contains("approve(spender="), "{refused}");
            assert!(!refused.contains("enableModule("), "{refused}");
            lists_nothing(refused);
        }
        assert!(renders[0].contains("multiSend:"), "{}", renders[0]);
        assert!(!renders[0].contains("MALFORMED"), "{}", renders[0]);
        for (n, one) in renders.iter().enumerate() {
            for other in &renders[n + 1..] {
                assert_ne!(one, other, "two batches rendered the same");
            }
        }
    }

    /// Policy checked the outer call and nothing inside it, so every sub-call has to reach the
    /// screen with its own operation, destination, value and decode, in the order it executes.
    /// The dangerous ones are hoisted into the alarm block by position; the unreadable one is
    /// NOT, so three unknown entries can never push an `enableModule` off a three-line sheet.
    #[test]
    fn a_batch_lists_every_sub_call_and_order_matters() {
        let opaque = [&[0xde, 0xad, 0xbe, 0xef][..], &[0x01u8; 32][..]].concat();
        let mixed = [
            entry(0, TOKEN, 0, &approve_max()),
            entry(1, LIB, 7, &opaque),
            entry(0, SAFE, 0, &enable_module()),
        ];
        let listed = shown(&mixed.concat());

        assert!(
            listed.contains(&format!(
                "[1] {:<OP_WIDTH$} to={TOKEN} value=0 approve(spender={ATTACKER}, amount=",
                "CALL"
            )),
            "{listed}"
        );
        assert!(
            listed.contains(&format!(
                "[2] {:<OP_WIDTH$} to={LIB} value=7 UNDECODED CALL 0xdeadbeef: 36 bytes",
                "DELEGATECALL"
            )),
            "{listed}"
        );
        assert!(
            listed.contains(&format!(
                "[3] {:<OP_WIDTH$} to={SAFE} value=0 enableModule(module={MODULE})",
                "CALL"
            )),
            "{listed}"
        );

        assert!(listed.contains("3 sub-calls (1 undecoded)"), "{listed}");
        assert!(
            listed.contains("\u{26a0} UNLIMITED APPROVAL [1]"),
            "{listed}"
        );
        assert!(listed.contains("\u{26a0} SAFE CONFIG [3]"), "{listed}");
        assert!(!listed.contains("\u{26a0} DELEGATECALL [2]"), "{listed}");

        let swapped = [mixed[2].clone(), mixed[1].clone(), mixed[0].clone()];
        assert_ne!(listed, shown(&swapped.concat()));
    }

    /// A truncated list is the worst failure mode here, because entry 33 is where the drain goes.
    /// Both caps are therefore all-or-nothing: a batch over the entry ceiling lists none of it,
    /// and a nest past the depth ceiling is named by its digest with none of its contents shown.
    #[test]
    fn batch_caps_refuse_to_render_a_partial_list() {
        let mut many = Vec::new();
        for n in 0..MAX_BATCH_ENTRIES + 1 {
            many.push(entry(0, VENDOR, n as u64, &[]));
        }
        let over = shown(&many.concat());
        assert!(
            over.contains(&format!(
                "\u{26a0} BATCH TOO LARGE: over {MAX_BATCH_ENTRIES} entries"
            )),
            "{over}"
        );
        lists_nothing(&over);

        let mut nest = entry(
            0,
            VICTIM,
            0,
            &Known::transferCall {
                to: VICTIM,
                amount: U256::from(9u64),
            }
            .abi_encode(),
        );
        for _ in 0..=MAX_BATCH_DEPTH {
            nest = entry(1, LIB, 0, &calldata(&nest));
        }
        let deep = shown(&nest);
        assert!(
            deep.contains(&format!(
                "[1.1.1] {:<OP_WIDTH$} to={LIB} value=0 \u{26a0} NESTED BATCH BEYOND DEPTH \
                 {MAX_BATCH_DEPTH}:",
                "DELEGATECALL"
            )),
            "{deep}"
        );
        assert!(deep.contains("3 sub-calls (1 unexpanded)"), "{deep}");
        assert!(!deep.contains(&VICTIM.to_string()), "{deep}");
        assert!(!deep.contains("transfer(to="), "{deep}");
    }
}
