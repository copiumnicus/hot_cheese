//! Trusted adapter: rebuild `safeTxHash` from submitted fields and decode a human summary.
//!
//! The typehashes are derived by alloy's `sol!` from the struct/interface below — never
//! hardcoded — so the digest we sign always matches the canonical Safe EIP-712 encoding.
//!
//! [`call`] turns the calldata into the line naming the action, [`Alarm`] ranks what that
//! action can still do once [`policy`](crate::policy) has said yes, [`batch`] unpacks the
//! sub-calls of a `multiSend` policy never looked inside, and [`annotate`] is the single point
//! where this machine's `config.toml` reaches any of that text — it can only ever add to it.
//! Nothing here is authoritative: policy decides what MAY be signed, and this decides what the
//! human SEES before they agree to it.
mod annotate;
mod batch;
mod call;

use crate::intent::{Operation, SafeTxIntent};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, Eip712Domain, SolCall, SolInterface, SolStruct};
use err_mac::create_err_with_impls;
use hc_core::config::Config;
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
        function increaseAllowance(address spender, uint256 addedValue);
        function decreaseAllowance(address spender, uint256 subtractedValue);
        function setApprovalForAll(address operator, bool approved);
        function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s);
        function enableModule(address module);
        function disableModule(address prevModule, address module);
        function setGuard(address guard);
        function setFallbackHandler(address handler);
        function approveHash(bytes32 hashToApprove);
        function safeTransferFrom(address from, address to, uint256 tokenId);
        function safeTransferFrom(address from, address to, uint256 tokenId, bytes data);
        function multiSend(bytes transactions);
    }
}

/// The four Safe owner/threshold management selectors — the fail-closed rotation set.
pub const OWNER_MGMT: [[u8; 4]; 4] = [
    Known::swapOwnerCall::SELECTOR,
    Known::addOwnerWithThresholdCall::SELECTOR,
    Known::removeOwnerCall::SELECTOR,
    Known::changeThresholdCall::SELECTOR,
];

/// The four Safe module/guard/fallback selectors: each hands one address permanent control of
/// the Safe without ever touching its owner set.
const SAFE_CONFIG: [[u8; 4]; 4] = [
    Known::enableModuleCall::SELECTOR,
    Known::disableModuleCall::SELECTOR,
    Known::setGuardCall::SELECTOR,
    Known::setFallbackHandlerCall::SELECTOR,
];

/// One call the Safe makes: the transaction's own, or one entry of a `multiSend` batch.
///
/// Policy pins the transaction's own destination and operation and nothing else, so a batch entry
/// carries its OWN — an entry that delegatecalls is arbitrary code running as the Safe under a
/// transaction policy only ever saw as one allow-listed call.
#[derive(Clone)]
struct Site {
    /// Where this call goes.
    to: Address,
    /// The chain it runs on, for annotation lookups.
    chain_id: U256,
    /// CALL or DELEGATECALL, as this call itself declares it.
    operation: Operation,
    /// This call's calldata.
    data: Bytes,
    /// Position in the batch tree, empty for the transaction's own call.
    at: Vec<usize>,
}

impl Site {
    /// The transaction's own call, at no position in any batch.
    fn own(i: &SafeTxIntent) -> Site {
        Site {
            to: i.to,
            chain_id: i.chain_id,
            operation: i.operation,
            data: i.data.clone(),
            at: Vec::new(),
        }
    }
}

/// What a payload does that nothing else in the system constrains.
///
/// [`policy`](crate::policy) has already pinned the destination, the selector, the operation and
/// the native value by the time a human sees any of this, so the ranking below is by what is
/// LEFT free once it has: unknown code running as the Safe first, then the Safe's own
/// configuration, then authority granted in arguments no ceiling reaches, and last the shapes
/// policy bounds tightly on its own.
enum Alarm {
    /// Unreadable code runs with the Safe's storage and balances.
    DelegatecallUndecoded,
    /// A batch whose sub-calls this refuses to list.
    BatchMalformed {
        /// What refused the packed payload.
        err: batch::BatchErr,
        /// The packed payload refused.
        payload: Bytes,
    },
    /// A batch whose sub-calls policy never inspected.
    Batch {
        /// Sub-calls the batch carries, across the whole tree.
        calls: usize,
        /// Of those, the ones whose calldata does not decode.
        undecoded: usize,
        /// Of those, the nested batches left unexpanded past the depth cap.
        unexpanded: usize,
        /// The packed payload they were read from.
        payload: Bytes,
    },
    /// Named code, still running as the Safe.
    DelegatecallDecoded,
    /// An unreadable payload aimed at the Safe itself.
    SelfCallUndecoded,
    /// A module, guard or fallback handler of the Safe changes.
    ModuleGuardFallback,
    /// The owner set or threshold changes, with arguments no policy term bounds.
    OwnerRotation,
    /// Any other decoded call against the Safe itself.
    SelfCall,
    /// An approval `max_value` cannot reach, because it bounds native value only.
    UnlimitedApproval,
    /// A hash approved without its contents.
    OpaqueHash,
    /// Gas-refund fields that pay someone out of the Safe.
    Refund,
    /// A plain call whose arguments do not decode.
    Undecoded,
}

/// One alarm and the call that raised it.
struct Raised {
    /// What is loose.
    alarm: Alarm,
    /// The call it came from: the transaction's own, or one entry of a batch.
    site: Site,
}

impl Alarm {
    fn rank(&self) -> u8 {
        match self {
            Alarm::DelegatecallUndecoded => 1,
            Alarm::BatchMalformed { .. } => 2,
            Alarm::Batch { .. } => 3,
            Alarm::DelegatecallDecoded => 4,
            Alarm::SelfCallUndecoded => 5,
            Alarm::ModuleGuardFallback => 6,
            Alarm::OwnerRotation => 7,
            Alarm::SelfCall => 8,
            Alarm::UnlimitedApproval => 9,
            Alarm::OpaqueHash => 10,
            Alarm::Refund => 11,
            Alarm::Undecoded => 12,
        }
    }
}

impl Raised {
    /// The alarm as one line, naming the sub-call that raised it when a batch did: policy pinned
    /// the transaction's destination and operation, so an alarm carrying `[2.1]` is one nothing
    /// in the system checked, and it has to say so where the human reads it.
    fn line(&self, i: &SafeTxIntent, config: &Config) -> String {
        let who = |a| annotate::address(a, i.chain_id, config);
        let at = if self.site.at.is_empty() {
            String::new()
        } else {
            format!(" [{}]", batch::position(&self.site.at))
        };
        match &self.alarm {
            Alarm::DelegatecallUndecoded => format!(
                "\u{26a0} DELEGATECALL{at}: unreadable code at {} runs with the storage and \
                 balances of {}",
                who(self.site.to),
                who(i.safe)
            ),
            Alarm::BatchMalformed { err, payload } => batch::unlistable(err, payload),
            Alarm::Batch {
                calls,
                undecoded,
                unexpanded,
                payload,
            } => format!(
                "\u{26a0} BATCH{at}: {calls} sub-calls{unread}, none of them checked by policy \
                 ({bytes} bytes, sha256 {digest})",
                unread = match (*undecoded, *unexpanded) {
                    (0, 0) => String::new(),
                    (0, deep) => format!(" ({deep} unexpanded)"),
                    (dark, 0) => format!(" ({dark} undecoded)"),
                    (dark, deep) => format!(" ({dark} undecoded, {deep} unexpanded)"),
                },
                bytes = payload.len(),
                digest = hex::encode(Sha256::digest(payload)),
            ),
            Alarm::DelegatecallDecoded => format!(
                "\u{26a0} DELEGATECALL{at}: the code at {} runs as {}",
                who(self.site.to),
                who(i.safe)
            ),
            Alarm::SelfCallUndecoded => format!(
                "\u{26a0} SELF-CALL{at}: an unreadable payload aimed at {}",
                who(i.safe)
            ),
            Alarm::ModuleGuardFallback => format!(
                "\u{26a0} SAFE CONFIG{at}: a module, guard or fallback handler of {} changes; the \
                 new address controls it permanently",
                who(i.safe)
            ),
            Alarm::OwnerRotation => format!(
                "\u{26a0} OWNER ROTATION{at}: the owner set or threshold of {} changes",
                who(i.safe)
            ),
            Alarm::SelfCall => {
                format!(
                    "\u{26a0} SELF-CALL{at}: this transaction calls {} itself",
                    who(i.safe)
                )
            }
            Alarm::UnlimitedApproval => format!(
                "\u{26a0} UNLIMITED APPROVAL{at}: the spender below may drain this Safe's holdings \
                 at {}, now and later",
                who(self.site.to)
            ),
            Alarm::OpaqueHash => format!(
                "\u{26a0} OPAQUE HASH{at}: approves a transaction whose contents are NOT in this \
                 payload"
            ),
            Alarm::Refund => format!(
                "\u{26a0} REFUND{at}: pays (gasUsed+{base_gas})*{gas_price} of {gas_token} to \
                 {refund_receiver}",
                base_gas = i.base_gas,
                gas_price = i.gas_price,
                gas_token = who(i.gas_token),
                refund_receiver = who(i.refund_receiver),
            ),
            Alarm::Undecoded => {
                format!("\u{26a0} UNDECODED{at}: the arguments of this call are not readable")
            }
        }
    }
}

/// Whether a decoded call hands out authority no `max_value` can bound: `max_value` is a ceiling
/// on the NATIVE value the Safe sends, and every shape here moves tokens the Safe already holds.
fn unlimited(call: &Known::KnownCalls) -> bool {
    match call {
        Known::KnownCalls::approve(c) => c.amount == U256::MAX,
        Known::KnownCalls::increaseAllowance(c) => c.addedValue == U256::MAX,
        Known::KnownCalls::permit(c) => c.value == U256::MAX,
        Known::KnownCalls::setApprovalForAll(c) => c.approved,
        _ => false,
    }
}

/// Every alarm ONE call raises — the transaction's own, or one entry of a batch. Shape-only
/// alarms fire on the SELECTOR, which is exactly what policy allow-lists and is proven even when
/// the arguments do not decode; value alarms need the decoded arguments and so fire only on a
/// canonical decode. The push order here is the order equal ranks keep on screen. The refund
/// fields belong to the transaction and not to any sub-call, so they are read only for the call
/// the transaction makes itself.
fn alarms(i: &SafeTxIntent, site: &Site, decoded: Option<&Known::KnownCalls>) -> Vec<Alarm> {
    let selector = selector4(&site.data);
    let rotation = matches!(selector, Some(s) if OWNER_MGMT.contains(&s));
    let safe_config = matches!(selector, Some(s) if SAFE_CONFIG.contains(&s));
    let opaque = selector == Some(Known::approveHashCall::SELECTOR);
    let mut out = Vec::new();
    match (site.operation, decoded) {
        (Operation::Delegatecall, Some(_)) => out.push(Alarm::DelegatecallDecoded),
        (Operation::Delegatecall, None) => out.push(Alarm::DelegatecallUndecoded),
        (Operation::Call, Some(_)) if site.to == i.safe && !rotation && !safe_config && !opaque => {
            out.push(Alarm::SelfCall)
        }
        (Operation::Call, None) if !site.data.is_empty() && site.to == i.safe => {
            out.push(Alarm::SelfCallUndecoded)
        }
        (Operation::Call, None) if !site.data.is_empty() => out.push(Alarm::Undecoded),
        (Operation::Call, _) => {}
    }
    if safe_config {
        out.push(Alarm::ModuleGuardFallback);
    }
    if rotation {
        out.push(Alarm::OwnerRotation);
    }
    if matches!(decoded, Some(c) if unlimited(c)) {
        out.push(Alarm::UnlimitedApproval);
    }
    if opaque {
        out.push(Alarm::OpaqueHash);
    }
    if site.at.is_empty() && !i.gas_price.is_zero() {
        out.push(Alarm::Refund);
    }
    out
}

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

/// The one decode of a payload, kept only when re-encoding it reproduces the submitted bytes
/// EXACTLY. `abi_decode`'s own `validate` is not that check: `bool`'s token validation requires
/// only that the first 31 bytes of the word are zero, so a final byte of 2 decodes as `true` and
/// would render byte-for-byte like the canonical `true` beside it. Two different payloads reading
/// the same is the one thing the decoded line may never do, so anything that fails this is
/// UNDECODED, named by its length and digest instead.
fn canonical(data: &[u8]) -> Option<Known::KnownCalls> {
    let call = Known::KnownCalls::abi_decode(data, true).ok()?;
    (call.abi_encode() == data).then_some(call)
}

/// The human's only view of what they are signing: every [`Alarm`] this payload raises, worst
/// first, then the decoded call, then destination/value/operation/nonce, Safe and chain, and the
/// gas-refund fields. The alarms lead because an approval sheet gets the head of this text, never
/// the tail, and they are sorted by [`Alarm::rank`] with a stable sort so equal ranks keep the
/// order [`alarms`] found them in and one payload always renders one way. The sub-calls of a
/// `multiSend` raise their alarms into that same block, so an `enableModule` buried at entry 30
/// competes for the head of the text on rank rather than on where it sits in the batch.
/// `config` supplies names and decimals only: with empty tables this renders the same bytes it
/// rendered before there were tables.
pub fn summary(i: &SafeTxIntent, config: &Config) -> String {
    let site = Site::own(i);
    let decoded = canonical(&i.data);
    let mut raised = Vec::new();
    for alarm in alarms(i, &site, decoded.as_ref()) {
        raised.push(Raised {
            alarm,
            site: site.clone(),
        });
    }
    if let Some(Known::KnownCalls::multiSend(c)) = &decoded {
        raised.extend(batch::alarms(&c.transactions, i, &site));
    }
    raised.sort_by_key(|r| r.alarm.rank());
    let op = match i.operation {
        Operation::Call => "CALL",
        Operation::Delegatecall => "DELEGATECALL",
    };
    let body = format!(
        "{call}\n  to={to} value={value} op={op} nonce={nonce}\n  Safe={safe} chain={chain}\n  \
         refund: gas_price={gas_price} gas_token={gas_token} refund_receiver={refund_receiver} \
         base_gas={base_gas} safe_tx_gas={safe_tx_gas}",
        call = call::render(&site, config, decoded.as_ref()),
        to = annotate::address(i.to, i.chain_id, config),
        value = annotate::amount(i.value, Address::ZERO, i.chain_id, config),
        nonce = i.nonce,
        safe = annotate::address(i.safe, i.chain_id, config),
        chain = i.chain_id,
        gas_price = i.gas_price,
        gas_token = annotate::address(i.gas_token, i.chain_id, config),
        refund_receiver = annotate::address(i.refund_receiver, i.chain_id, config),
        base_gas = i.base_gas,
        safe_tx_gas = i.safe_tx_gas,
    );
    let mut out = String::new();
    for alarm in &raised {
        out.push_str(&alarm.line(i, config));
        out.push('\n');
    }
    out.push_str(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, U256};
    use hc_core::crypto::keccak256;
    use sha2::{Digest, Sha256};

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

    /// A machine that annotates nothing, which is what every install has until an operator
    /// writes a `[[token]]` or `[[label]]` table.
    fn plain() -> Config {
        toml::from_str("service = \"\"\naccount = \"\"\nstore = \"/nonexistent\"\n")
            .expect("a config with no annotation tables")
    }

    fn summary(i: &SafeTxIntent) -> String {
        super::summary(i, &plain())
    }

    fn sheet(summary: &str) -> String {
        summary.lines().take(3).collect::<Vec<_>>().join("\n")
    }

    const A: Address = Address::new([0xa1u8; 20]);
    const B: Address = Address::new([0xb2u8; 20]);
    const C: Address = Address::new([0xc3u8; 20]);

    /// Just the decoded-call line, which is the line an argument has to reach.
    fn call_line(data: Vec<u8>) -> String {
        let mut i = base_intent();
        i.data = Bytes::from(data);
        let decoded = canonical(&i.data);
        assert!(
            decoded.is_some(),
            "the sol! encoder must produce canonically decodable calldata"
        );
        call::render(&Site::own(&i), &plain(), decoded.as_ref())
    }

    /// Assert every mutant — one argument changed — renders differently from the base.
    fn each_field_shows(base: Vec<u8>, mutants: Vec<Vec<u8>>) {
        let shown = call_line(base);
        for mutant in mutants {
            assert_ne!(
                shown,
                call_line(mutant),
                "a changed argument did not change the line: {shown}"
            );
        }
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

    /// An argument that never reaches the screen is an argument the human cannot approve, and a
    /// decoder that silently drops one is invisible until two different payloads read alike —
    /// which is exactly how two `transfer` calls once rendered identically. Every field of every
    /// decoder is changed on its own here, and every change must move the rendered line.
    #[test]
    fn every_decoded_field_reaches_the_screen() {
        let one = U256::from(1u64);
        let two = U256::from(2u64);
        let r = B256::new([0x01u8; 32]);
        let s = B256::new([0x02u8; 32]);

        let swap = Known::swapOwnerCall {
            prevOwner: A,
            oldOwner: B,
            newOwner: C,
        };
        each_field_shows(
            swap.abi_encode(),
            vec![
                Known::swapOwnerCall {
                    prevOwner: C,
                    ..swap.clone()
                }
                .abi_encode(),
                Known::swapOwnerCall {
                    oldOwner: A,
                    ..swap.clone()
                }
                .abi_encode(),
                Known::swapOwnerCall {
                    newOwner: A,
                    ..swap.clone()
                }
                .abi_encode(),
            ],
        );

        let add = Known::addOwnerWithThresholdCall {
            owner: A,
            threshold: one,
        };
        each_field_shows(
            add.abi_encode(),
            vec![
                Known::addOwnerWithThresholdCall {
                    owner: B,
                    ..add.clone()
                }
                .abi_encode(),
                Known::addOwnerWithThresholdCall {
                    threshold: two,
                    ..add.clone()
                }
                .abi_encode(),
            ],
        );

        let remove = Known::removeOwnerCall {
            prevOwner: A,
            owner: B,
            threshold: one,
        };
        each_field_shows(
            remove.abi_encode(),
            vec![
                Known::removeOwnerCall {
                    prevOwner: B,
                    ..remove.clone()
                }
                .abi_encode(),
                Known::removeOwnerCall {
                    owner: A,
                    ..remove.clone()
                }
                .abi_encode(),
                Known::removeOwnerCall {
                    threshold: two,
                    ..remove.clone()
                }
                .abi_encode(),
            ],
        );

        each_field_shows(
            Known::changeThresholdCall { threshold: one }.abi_encode(),
            vec![Known::changeThresholdCall { threshold: two }.abi_encode()],
        );

        let transfer = Known::transferCall { to: A, amount: one };
        each_field_shows(
            transfer.abi_encode(),
            vec![
                Known::transferCall {
                    to: B,
                    ..transfer.clone()
                }
                .abi_encode(),
                Known::transferCall {
                    amount: two,
                    ..transfer.clone()
                }
                .abi_encode(),
            ],
        );

        let approve = Known::approveCall {
            spender: A,
            amount: one,
        };
        each_field_shows(
            approve.abi_encode(),
            vec![
                Known::approveCall {
                    spender: B,
                    ..approve.clone()
                }
                .abi_encode(),
                Known::approveCall {
                    amount: two,
                    ..approve.clone()
                }
                .abi_encode(),
            ],
        );

        let transfer_from = Known::transferFromCall {
            from: A,
            to: B,
            amount: one,
        };
        each_field_shows(
            transfer_from.abi_encode(),
            vec![
                Known::transferFromCall {
                    from: B,
                    ..transfer_from.clone()
                }
                .abi_encode(),
                Known::transferFromCall {
                    to: A,
                    ..transfer_from.clone()
                }
                .abi_encode(),
                Known::transferFromCall {
                    amount: two,
                    ..transfer_from.clone()
                }
                .abi_encode(),
            ],
        );

        let increase = Known::increaseAllowanceCall {
            spender: A,
            addedValue: one,
        };
        each_field_shows(
            increase.abi_encode(),
            vec![
                Known::increaseAllowanceCall {
                    spender: B,
                    ..increase.clone()
                }
                .abi_encode(),
                Known::increaseAllowanceCall {
                    addedValue: two,
                    ..increase.clone()
                }
                .abi_encode(),
            ],
        );

        let decrease = Known::decreaseAllowanceCall {
            spender: A,
            subtractedValue: one,
        };
        each_field_shows(
            decrease.abi_encode(),
            vec![
                Known::decreaseAllowanceCall {
                    spender: B,
                    ..decrease.clone()
                }
                .abi_encode(),
                Known::decreaseAllowanceCall {
                    subtractedValue: two,
                    ..decrease.clone()
                }
                .abi_encode(),
            ],
        );

        let for_all = Known::setApprovalForAllCall {
            operator: A,
            approved: true,
        };
        each_field_shows(
            for_all.abi_encode(),
            vec![
                Known::setApprovalForAllCall {
                    operator: B,
                    ..for_all.clone()
                }
                .abi_encode(),
                Known::setApprovalForAllCall {
                    approved: false,
                    ..for_all.clone()
                }
                .abi_encode(),
            ],
        );

        let permit = Known::permitCall {
            owner: A,
            spender: B,
            value: one,
            deadline: one,
            v: 27,
            r,
            s,
        };
        each_field_shows(
            permit.abi_encode(),
            vec![
                Known::permitCall {
                    owner: B,
                    ..permit.clone()
                }
                .abi_encode(),
                Known::permitCall {
                    spender: A,
                    ..permit.clone()
                }
                .abi_encode(),
                Known::permitCall {
                    value: two,
                    ..permit.clone()
                }
                .abi_encode(),
                Known::permitCall {
                    deadline: two,
                    ..permit.clone()
                }
                .abi_encode(),
                Known::permitCall {
                    v: 28,
                    ..permit.clone()
                }
                .abi_encode(),
                Known::permitCall {
                    r: s,
                    ..permit.clone()
                }
                .abi_encode(),
                Known::permitCall {
                    s: r,
                    ..permit.clone()
                }
                .abi_encode(),
            ],
        );

        each_field_shows(
            Known::enableModuleCall { module: A }.abi_encode(),
            vec![Known::enableModuleCall { module: B }.abi_encode()],
        );

        let disable = Known::disableModuleCall {
            prevModule: A,
            module: B,
        };
        each_field_shows(
            disable.abi_encode(),
            vec![
                Known::disableModuleCall {
                    prevModule: B,
                    ..disable.clone()
                }
                .abi_encode(),
                Known::disableModuleCall {
                    module: A,
                    ..disable.clone()
                }
                .abi_encode(),
            ],
        );

        each_field_shows(
            Known::setGuardCall { guard: A }.abi_encode(),
            vec![Known::setGuardCall { guard: B }.abi_encode()],
        );

        each_field_shows(
            Known::setFallbackHandlerCall { handler: A }.abi_encode(),
            vec![Known::setFallbackHandlerCall { handler: B }.abi_encode()],
        );

        each_field_shows(
            Known::approveHashCall { hashToApprove: r }.abi_encode(),
            vec![Known::approveHashCall { hashToApprove: s }.abi_encode()],
        );

        let nft = Known::safeTransferFrom_0Call {
            from: A,
            to: B,
            tokenId: one,
        };
        each_field_shows(
            nft.abi_encode(),
            vec![
                Known::safeTransferFrom_0Call {
                    from: B,
                    ..nft.clone()
                }
                .abi_encode(),
                Known::safeTransferFrom_0Call {
                    to: A,
                    ..nft.clone()
                }
                .abi_encode(),
                Known::safeTransferFrom_0Call {
                    tokenId: two,
                    ..nft.clone()
                }
                .abi_encode(),
            ],
        );

        let nft_data = Known::safeTransferFrom_1Call {
            from: A,
            to: B,
            tokenId: one,
            data: Bytes::from(vec![0x01u8]),
        };
        each_field_shows(
            nft_data.abi_encode(),
            vec![
                Known::safeTransferFrom_1Call {
                    from: B,
                    ..nft_data.clone()
                }
                .abi_encode(),
                Known::safeTransferFrom_1Call {
                    to: A,
                    ..nft_data.clone()
                }
                .abi_encode(),
                Known::safeTransferFrom_1Call {
                    tokenId: two,
                    ..nft_data.clone()
                }
                .abi_encode(),
                Known::safeTransferFrom_1Call {
                    data: Bytes::from(vec![0x02u8]),
                    ..nft_data.clone()
                }
                .abi_encode(),
            ],
        );
    }

    /// Decoding is canonical-only, and the new argument types are no exception: an address word
    /// carrying dirty upper bits and a `bool` word holding 2 are both payloads whose re-encoding
    /// is not the bytes submitted, so neither may ever be claimed as a decoded call.
    #[test]
    fn a_non_canonical_encoding_stays_undecoded() {
        let mut i = base_intent();

        let mut dirty = Known::enableModuleCall { module: A }.abi_encode();
        dirty[4] = 0xff;
        i.data = Bytes::from(dirty);
        let module = summary(&i);
        assert!(module.contains("UNDECODED CALL 0x"), "{module}");
        assert!(!module.contains("enableModule("), "{module}");

        let mut two = Known::setApprovalForAllCall {
            operator: A,
            approved: true,
        }
        .abi_encode();
        let bool_word = two.len() - 1;
        two[bool_word] = 2;
        i.data = Bytes::from(two);
        let approval = summary(&i);
        assert!(approval.contains("UNDECODED CALL 0x"), "{approval}");
        assert!(!approval.contains("setApprovalForAll("), "{approval}");
    }

    /// The approval sheet is three lines, so the ranking of the alarm block decides what the
    /// human actually reads: an unlimited approval — bounded by nothing, since `max_value` caps
    /// native value only — must outrank a refund, which is denied outright without an opt-in and
    /// then bounded by two allow-lists and three ceilings. With no approval, the refund still
    /// leads, exactly as it did before there was a ranking.
    #[test]
    fn the_sheet_shows_the_worst_thing_first() {
        let attacker = Address::from([0x55u8; 20]);
        let mut i = base_intent();
        i.data = Bytes::from(
            Known::approveCall {
                spender: attacker,
                amount: U256::MAX,
            }
            .abi_encode(),
        );
        i.gas_price = U256::from(7u64);
        i.refund_receiver = attacker;
        let shown = sheet(&summary(&i));
        let approval = shown
            .find("\u{26a0} UNLIMITED APPROVAL")
            .expect("the unlimited approval is on the sheet");
        let refund = shown
            .find("\u{26a0} REFUND")
            .expect("the refund is on the sheet");
        assert!(approval < refund, "{shown}");
        assert!(
            shown.contains(&format!("approve(spender={attacker}, amount=")),
            "{shown}"
        );

        let mut only_refund = base_intent();
        only_refund.data = transfer_data(Address::from([0x33u8; 20]), U256::from(1u64));
        only_refund.gas_price = U256::from(7u64);
        assert!(summary(&only_refund).starts_with("\u{26a0} REFUND"));
    }

    /// The whole sha256 of undecodable calldata, not a prefix of it. A 16-hex-char prefix is a
    /// 64-bit hash: a birthday collision costs ~2^32 tries, so anyone who could propose a
    /// transaction could grind two payloads whose UNDECODED lines are byte-identical, which is
    /// the one property the line exists to deny them.
    #[test]
    fn the_undecoded_digest_is_the_whole_hash() {
        let mut i = base_intent();
        i.data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
        let printed = summary(&i);
        let expected = hex::encode(Sha256::digest(&i.data));
        assert_eq!(expected.len(), 64);
        assert!(printed.contains(&expected), "{printed}");
    }
}
