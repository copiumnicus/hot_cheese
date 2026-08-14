//! Trusted admission: rebuild `safeTxHash` from submitted fields, and deconstruct the payload
//! into typed calls the POLICY declared the shape of.
//!
//! The Safe transaction typehash is derived by alloy's `sol!` from the struct below — never
//! hardcoded — so the digest we sign always matches the canonical Safe EIP-712 encoding. Nothing
//! else here has a vocabulary of its own: [`admit`] decodes each call against the signature the
//! matching [`CallRule`] declared, so a shape the policy does not permit is not a shape this can
//! read. There is no undecoded representation and no hex fallback: whatever this cannot fully
//! deconstruct is a typed refusal, raised before any human is asked.
//!
//! [`call`] turns a decoded call into the line naming the action, [`Alarm`] ranks what that
//! action can still do once the policy has said yes, [`batch`] splits the packed payload of a
//! `multiSend` into the entries [`admit`] then matches one by one, [`typed`] does the same job
//! for an EIP-712 message, and [`annotate`] is the single point where this machine's
//! `config.toml` reaches any of that text — it can only ever add to it.
mod annotate;
mod batch;
mod call;
pub mod typed;

use crate::intent::{Operation, SafeTxIntent};
use crate::manifest::Grant;
use crate::policy::{match_call, match_site, CallDenied, Policy, PolicyDenied};
use crate::schema::{
    CallRule, FieldDenied, FieldNote, FieldWalk, Site, APPROVE_HASH, MULTI_SEND, OWNER_MGMT,
    SAFE_CONFIG,
};
use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, Eip712Domain, SolStruct};
use err_mac::create_err_with_impls;
use hc_core::config::Config;
use sha2::{Digest, Sha256};

sol! {
    struct SafeTx { address to; uint256 value; bytes data; uint8 operation; uint256 safeTxGas; uint256 baseGas; uint256 gasPrice; address gasToken; address refundReceiver; uint256 nonce; }
}

/// Which call a refusal is about, and what its calldata was. It names the payload by its whole
/// SHA-256 as well as its length, so two payloads refused for one reason never read the same.
#[derive(Debug)]
pub struct Refused {
    /// Position in the batch tree; empty for the transaction's own call.
    pub at: Vec<usize>,
    /// Where the call was aimed.
    pub to: Address,
    /// The canonical signature the policy declared for it.
    pub signature: String,
    /// Bytes of calldata submitted.
    pub len: usize,
    /// SHA-256 of those bytes.
    pub digest: B256,
}

create_err_with_impls!(
    #[derive(Debug)]
    pub AdapterErr,
    Batch(batch::BatchErr),
    Abi(alloy_dyn_abi::Error),
    Typed(typed::TypedDenied)
    ;
    Denied { at: Vec<usize>, to: Address, source: Box<PolicyDenied> },
    NotGranted { at: Vec<usize>, to: Address, source: Box<CallDenied> },
    GrantSignatureMismatch { at: Vec<usize>, to: Address, policy: String, grant: String },
    ArgumentsNotDecodable { call: Box<Refused>, source: Box<alloy_dyn_abi::Error> },
    EncodingNotCanonical { call: Box<Refused> },
    ArgUnruled { at: Vec<usize>, to: Address, signature: String, arg: usize },
    Field { at: Vec<usize>, to: Address, signature: String, source: Box<FieldDenied> }
);

/// What a permitted call's calldata turned out to be. There is no undecoded variant, which is
/// what makes "the daemon signs only what it fully deconstructed" a property of the type.
enum Body<'p> {
    /// A plain call, fully described by its decoded arguments.
    Plain,
    /// A `multiSend`, its packed payload, and every sub-call it runs — each matched against the
    /// policy in its own right, decoded against its own declared signature, bounded by its own
    /// rules.
    Batch {
        /// The packed payload the entries were read from.
        payload: Bytes,
        entries: Vec<TypedCall<'p>>,
    },
}

/// One call the Safe makes, the rule that permitted it, and its decoded arguments.
struct TypedCall<'p> {
    site: Site,
    /// The rule the POLICY matched, whose labels the human reads and whose shape this decoded
    /// against — so the text and the authority decision can never come from different rules.
    rule: &'p CallRule,
    args: Vec<DynSolValue>,
    body: Body<'p>,
    /// What this call's rules deliberately left free.
    notes: Vec<FieldNote>,
}

/// A Safe transaction fully deconstructed into typed calls, every one of them permitted by the
/// policy borrowed for the walk. Constructible only by [`admit`], so there is nothing to render
/// until the check has passed.
pub struct TypedTx<'p> {
    intent: SafeTxIntent,
    root: TypedCall<'p>,
}

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

/// Deconstruct `intent` into the calls it actually makes, refusing anything the policy does not
/// permit or this cannot fully decode. Every call — the transaction's own and every entry of
/// every `multiSend` — goes through the same three steps in the same order: the policy match
/// selects the declared shape, the decode runs against THAT shape, and the argument rules of
/// THAT rule bound the decoded values. Because the match runs first, calldata aimed at a
/// destination the policy never allowed is never handed to a decoder at all.
pub fn admit<'p>(
    intent: SafeTxIntent,
    policy: &'p Policy,
    grant: Option<&Grant>,
    now_secs: u64,
) -> Result<TypedTx<'p>, AdapterErr> {
    let mut left = batch::MAX_BATCH_ENTRIES;
    let root = admit_site(Site::own(&intent), policy, grant, now_secs, &mut left)?;
    Ok(TypedTx { intent, root })
}

fn admit_site<'p>(
    site: Site,
    policy: &'p Policy,
    grant: Option<&Grant>,
    now_secs: u64,
    left: &mut usize,
) -> Result<TypedCall<'p>, AdapterErr> {
    let rule = match_site(&site, policy).map_err(|source| AdapterErr::Denied {
        at: site.at.clone(),
        to: site.to,
        source: Box::new(source),
    })?;
    if let Some(grant) = grant {
        let granted = match_call(&grant.calls, &site).map_err(|source| AdapterErr::NotGranted {
            at: site.at.clone(),
            to: site.to,
            source: Box::new(source),
        })?;
        if granted.signature.canonical() != rule.signature.canonical() {
            return Err(AdapterErr::GrantSignatureMismatch {
                at: site.at.clone(),
                to: site.to,
                policy: rule.signature.canonical().to_string(),
                grant: granted.signature.canonical().to_string(),
            });
        }
    }

    let refused = || {
        Box::new(Refused {
            at: site.at.clone(),
            to: site.to,
            signature: rule.signature.canonical().to_string(),
            len: site.data.len(),
            digest: B256::from_slice(&Sha256::digest(&site.data)),
        })
    };
    let region = &site.data[4..];
    let args = rule
        .signature
        .function()
        .abi_decode_input(region, true)
        .map_err(|source| AdapterErr::ArgumentsNotDecodable {
            call: refused(),
            source: Box::new(source),
        })?;
    if rule.signature.function().abi_encode_input_raw(&args)? != region {
        return Err(AdapterErr::EncodingNotCanonical { call: refused() });
    }

    let mut walk = FieldWalk::new(now_secs, &[]);
    for (at, value) in args.iter().enumerate() {
        let Some(arg) = rule.at(at) else {
            return Err(AdapterErr::ArgUnruled {
                at: site.at.clone(),
                to: site.to,
                signature: rule.signature.canonical().to_string(),
                arg: at,
            });
        };
        walk.field(&arg.name, &arg.rule, value)
            .map_err(|source| AdapterErr::Field {
                at: site.at.clone(),
                to: site.to,
                signature: rule.signature.canonical().to_string(),
                source: Box::new(source),
            })?;
    }

    let body = match rule.signature.canonical() == MULTI_SEND {
        false => Body::Plain,
        true => {
            let DynSolValue::Bytes(payload) = &args[0] else {
                return Err(AdapterErr::EncodingNotCanonical { call: refused() });
            };
            let mut entries = Vec::new();
            for entry in batch::split(payload, &site, left)? {
                entries.push(admit_site(entry, policy, grant, now_secs, left)?);
            }
            Body::Batch {
                payload: Bytes::copy_from_slice(payload),
                entries,
            }
        }
    };

    Ok(TypedCall {
        site,
        rule,
        args,
        body,
        notes: walk.notes(),
    })
}

impl TypedCall<'_> {
    /// This call and every sub-call it runs, in the order they execute.
    fn flatten<'a>(&'a self, out: &mut Vec<&'a TypedCall<'a>>) {
        out.push(self);
        if let Body::Batch { entries, .. } = &self.body {
            for entry in entries {
                entry.flatten(out);
            }
        }
    }
}

impl TypedTx<'_> {
    /// The fields the digest was rebuilt from, which is also what a bundle stores.
    pub fn intent(&self) -> &SafeTxIntent {
        &self.intent
    }

    /// The EIP-712 `safeTxHash` of the admitted transaction.
    pub fn digest(&self) -> B256 {
        safe_tx_hash(&self.intent)
    }

    /// The human's only view of what they are signing: every [`Alarm`] this payload raises,
    /// worst first, then the decoded call, then destination/value/operation/nonce, Safe and
    /// chain, and the gas-refund fields. The alarms lead because an approval sheet gets the head
    /// of this text, never the tail, and they are sorted by [`Alarm::rank`] with a stable sort so
    /// equal ranks keep the order they were found in and one payload always renders one way. The
    /// sub-calls of a `multiSend` raise their alarms into that same block, so an `enableModule`
    /// buried at entry 30 competes for the head of the text on rank rather than on position.
    /// `config` supplies names and decimals only: with empty tables this renders the same bytes
    /// it rendered before there were tables.
    pub fn summary(&self, config: &Config) -> String {
        let i = &self.intent;
        let mut flat = Vec::new();
        self.root.flatten(&mut flat);
        let mut raised = Vec::new();
        for one in &flat {
            for alarm in alarms(i, one) {
                raised.push(Raised {
                    alarm,
                    at: one.site.position(),
                });
            }
        }
        raised.sort_by_key(|r| r.alarm.rank());
        let op = match i.operation {
            Operation::Call => "CALL",
            Operation::Delegatecall => "DELEGATECALL",
        };
        let body = format!(
            "{call}\n  to={to} value={value} op={op} nonce={nonce}\n  Safe={safe} chain={chain}\n  \
             refund: gas_price={gas_price} gas_token={gas_token} \
             refund_receiver={refund_receiver} base_gas={base_gas} safe_tx_gas={safe_tx_gas}",
            call = call::render(&self.root, config),
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
            out.push_str(&alarm.alarm.line(&alarm.at, i.chain_id, config));
            out.push('\n');
        }
        out.push_str(&body);
        out
    }
}

/// What a payload does that nothing else in the system constrains.
///
/// The policy has already pinned the destination, the signature, the operation, the native value
/// and every argument by the time a human sees any of this, so the ranking below is by what is
/// LEFT free once it has: unknown code running as the Safe first, then whatever the policy
/// declared unbounded, then the Safe's own configuration, and last the shapes the policy bounds
/// tightly on its own.
enum Alarm {
    /// Named code, still running with the Safe's storage and balances.
    DelegatecallDecoded {
        /// The code that runs.
        to: Address,
        /// Whose storage and balances it runs with.
        safe: Address,
    },
    /// A field the policy deliberately did not bound, so the human is the only bound left.
    UnboundedField {
        /// Dotted path of the field inside its call.
        path: String,
    },
    /// An off-chain signature, valid at a contract without any transaction on this chain.
    TypedMessage,
    /// A batch, every sub-call of which had to be permitted in its own right.
    Batch {
        /// Sub-calls the batch carries, across the whole tree.
        calls: usize,
        /// The packed payload they were read from.
        payload: Bytes,
    },
    /// A module, guard or fallback handler of the Safe changes.
    ModuleGuardFallback {
        /// The Safe whose configuration changes.
        safe: Address,
    },
    /// The owner set or threshold changes.
    OwnerRotation {
        /// The Safe whose owners change.
        safe: Address,
    },
    /// Any other decoded call against the Safe itself.
    SelfCall {
        /// The Safe calling itself.
        safe: Address,
    },
    /// A hash approved without its contents.
    OpaqueHash,
    /// An accepted deadline further out than a day.
    DeadlineFar {
        /// Dotted path of the field.
        path: String,
        /// The unix-seconds value accepted.
        deadline: U256,
    },
    /// Gas-refund fields that pay someone out of the Safe.
    Refund {
        /// Flat gas added to the refund.
        base_gas: U256,
        /// Price each unit of gas is paid at.
        gas_price: U256,
        /// Token the refund is paid in.
        gas_token: Address,
        /// Who the refund is paid to.
        refund_receiver: Address,
    },
}

/// One alarm and the dotted position of the call that raised it.
struct Raised {
    /// What is loose.
    alarm: Alarm,
    /// Where it came from: empty for the transaction's own call, `2.1` for a batch entry.
    at: String,
}

impl Alarm {
    fn rank(&self) -> u8 {
        match self {
            Alarm::DelegatecallDecoded { .. } => 1,
            Alarm::UnboundedField { .. } => 2,
            Alarm::TypedMessage => 3,
            Alarm::Batch { .. } => 4,
            Alarm::ModuleGuardFallback { .. } => 5,
            Alarm::OwnerRotation { .. } => 6,
            Alarm::SelfCall { .. } => 7,
            Alarm::OpaqueHash => 8,
            Alarm::DeadlineFar { .. } => 9,
            Alarm::Refund { .. } => 10,
        }
    }

    /// The alarm as one line, naming the sub-call that raised it when a batch did: an alarm
    /// carrying `[2.1]` came from inside a batch, and it has to say so where the human reads it.
    fn line(&self, at: &str, chain_id: U256, config: &Config) -> String {
        let who = |a| annotate::address(a, chain_id, config);
        let at = match at.is_empty() {
            true => String::new(),
            false => format!(" [{at}]"),
        };
        match self {
            Alarm::DelegatecallDecoded { to, safe } => format!(
                "\u{26a0} DELEGATECALL{at}: the code at {} runs as {}",
                who(*to),
                who(*safe)
            ),
            Alarm::UnboundedField { path } => format!(
                "\u{26a0} UNBOUNDED FIELD{at} [{path}]: the policy places no bound on this value"
            ),
            Alarm::TypedMessage => "\u{26a0} TYPED MESSAGE: this signature is valid at the \
                 contract below with no transaction on this chain"
                .to_string(),
            Alarm::Batch { calls, payload } => format!(
                "\u{26a0} BATCH{at}: {calls} sub-calls, each matched against the policy in its own \
                 right ({bytes} bytes, sha256 {digest})",
                bytes = payload.len(),
                digest = hex::encode(Sha256::digest(payload)),
            ),
            Alarm::ModuleGuardFallback { safe } => format!(
                "\u{26a0} SAFE CONFIG{at}: a module, guard or fallback handler of {} changes; the \
                 new address controls it permanently",
                who(*safe)
            ),
            Alarm::OwnerRotation { safe } => format!(
                "\u{26a0} OWNER ROTATION{at}: the owner set or threshold of {} changes",
                who(*safe)
            ),
            Alarm::SelfCall { safe } => format!(
                "\u{26a0} SELF-CALL{at}: this transaction calls {} itself",
                who(*safe)
            ),
            Alarm::OpaqueHash => format!(
                "\u{26a0} OPAQUE HASH{at}: approves a transaction whose contents are NOT in this \
                 payload"
            ),
            Alarm::DeadlineFar { path, deadline } => format!(
                "\u{26a0} DEADLINE{at} [{path}]: valid until {deadline}, more than a day out"
            ),
            Alarm::Refund {
                base_gas,
                gas_price,
                gas_token,
                refund_receiver,
            } => format!(
                "\u{26a0} REFUND{at}: pays (gasUsed+{base_gas})*{gas_price} of {} to {}",
                who(*gas_token),
                who(*refund_receiver),
            ),
        }
    }
}

/// Every alarm ONE admitted call raises. The refund fields belong to the transaction and not to
/// any sub-call, so they are read only for the call the transaction makes itself.
fn alarms(i: &SafeTxIntent, call: &TypedCall) -> Vec<Alarm> {
    let canonical = call.rule.signature.canonical();
    let rotation = OWNER_MGMT.contains(&canonical);
    let safe_config = SAFE_CONFIG.contains(&canonical);
    let opaque = canonical == APPROVE_HASH;
    let mut out = Vec::new();
    if call.site.operation == Operation::Delegatecall {
        out.push(Alarm::DelegatecallDecoded {
            to: call.site.to,
            safe: i.safe,
        });
    }
    for note in &call.notes {
        out.push(match note {
            FieldNote::Unbounded { path } => Alarm::UnboundedField { path: path.clone() },
            FieldNote::DeadlineFar { path, deadline } => Alarm::DeadlineFar {
                path: path.clone(),
                deadline: *deadline,
            },
        });
    }
    if let Body::Batch { payload, entries } = &call.body {
        let mut flat = Vec::new();
        for entry in entries {
            entry.flatten(&mut flat);
        }
        out.push(Alarm::Batch {
            calls: flat.len(),
            payload: payload.clone(),
        });
    }
    if safe_config {
        out.push(Alarm::ModuleGuardFallback { safe: i.safe });
    }
    if rotation {
        out.push(Alarm::OwnerRotation { safe: i.safe });
    }
    if call.site.to == i.safe && !rotation && !safe_config && !opaque {
        out.push(Alarm::SelfCall { safe: i.safe });
    }
    if opaque {
        out.push(Alarm::OpaqueHash);
    }
    if call.site.at.is_empty() && !i.gas_price.is_zero() {
        out.push(Alarm::Refund {
            base_gas: i.base_gas,
            gas_price: i.gas_price,
            gas_token: i.gas_token,
            refund_receiver: i.refund_receiver,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AllowRule, OwnerMgmt};
    use crate::schema::{unbounded_call, ArgRule, CallRule, FieldRule, Signature};
    use alloy_primitives::Bytes;
    use hc_core::crypto::keccak256;

    const SAFE: Address = Address::new([0x11u8; 20]);
    const TOKEN: Address = Address::new([0x22u8; 20]);
    const VENDOR: Address = Address::new([0x33u8; 20]);
    const LIB: Address = Address::new([0x44u8; 20]);
    const ATTACKER: Address = Address::new([0x55u8; 20]);
    const MODULE: Address = Address::new([0x66u8; 20]);
    const REGISTRY: Address = Address::new([0x77u8; 20]);

    pub(crate) fn addr_word(a: Address) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a.as_slice());
        w
    }
    pub(crate) fn u256_word(v: U256) -> [u8; 32] {
        v.to_be_bytes::<32>()
    }

    /// Canonical calldata for one declared signature, hand-encoded the way a caller puts it on
    /// the wire, so no encoder of ours is on both sides of a decode assertion.
    pub(crate) fn calldata(signature: &str, words: &[[u8; 32]]) -> Bytes {
        let sig = Signature::try_from(signature.to_string()).expect("a canonical signature");
        let mut out = sig.selector().to_vec();
        for word in words {
            out.extend_from_slice(word);
        }
        Bytes::from(out)
    }

    fn transfer_data(to: Address, amount: U256) -> Bytes {
        calldata(
            "transfer(address,uint256)",
            &[addr_word(to), u256_word(amount)],
        )
    }

    fn bounded(signature: &str, rules: Vec<(usize, &str, FieldRule)>) -> CallRule {
        let signature =
            Signature::try_from(signature.to_string()).expect("a canonical signature parses");
        let mut arg = Vec::new();
        for (at, name, rule) in rules {
            arg.push(ArgRule {
                at,
                name: name.to_string(),
                rule,
            });
        }
        CallRule { signature, arg }
    }

    fn to_vendor() -> CallRule {
        bounded(
            "transfer(address,uint256)",
            vec![
                (
                    0,
                    "to",
                    FieldRule::OneOf {
                        addresses: vec![VENDOR],
                    },
                ),
                (
                    1,
                    "amount",
                    FieldRule::Max {
                        max: U256::from(1_000_000u64),
                        amount_of: TOKEN,
                    },
                ),
            ],
        )
    }

    pub(crate) fn rule_at(to: Address, operation: Operation, call: Vec<CallRule>) -> AllowRule {
        AllowRule {
            to,
            call,
            max_value: U256::ZERO,
            operation,
        }
    }

    pub(crate) fn policy_with(allow: Vec<AllowRule>) -> Policy {
        Policy {
            safe: SAFE,
            chain_id: U256::from(1u64),
            allow,
            owner_management: OwnerMgmt::default(),
            refunds: None,
            typed_data: Vec::new(),
        }
    }

    fn token_policy() -> Policy {
        policy_with(vec![rule_at(TOKEN, Operation::Call, vec![to_vendor()])])
    }

    pub(crate) fn base_intent() -> SafeTxIntent {
        SafeTxIntent {
            key: "trader".into(),
            safe: SAFE,
            chain_id: U256::from(1u64),
            to: TOKEN,
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
    pub(crate) fn plain() -> Config {
        toml::from_str("service = \"\"\naccount = \"\"\nstore = \"/nonexistent\"\n")
            .expect("a config with no annotation tables")
    }

    pub(crate) fn shown(i: &SafeTxIntent, policy: &Policy) -> String {
        admit(i.clone(), policy, None, 0)
            .expect("the fixture must admit")
            .summary(&plain())
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
            value: U256::from(1000u64),
            data: Bytes::from(vec![0x8d, 0x80, 0xff, 0x0a, 0xde, 0xad]),
            nonce: U256::from(5u64),
            ..base_intent()
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
        let p = token_policy();
        let mut i = base_intent();
        i.data = transfer_data(VENDOR, U256::from(1u64));
        let clean = shown(&i, &p);
        assert!(!clean.contains("\u{26a0} REFUND"));
        assert!(clean.contains("gas_price=0"));

        i.gas_price = U256::from(7u64);
        i.refund_receiver = ATTACKER;
        let drained = shown(&i, &p);
        assert!(drained.contains("\u{26a0} REFUND"));
        assert!(drained.contains(&ATTACKER.to_string()));
    }

    /// The calldata arguments are the whole payload: two `transfer`s to the same allow-listed
    /// token, with the same native value and nonce, differ ONLY in recipient and amount, so they
    /// must differ on screen — and inside the first three lines, which is all the approval sheet
    /// shows. Under an unbounded policy `U256::MAX` still says so, because the annotation layer
    /// marks it whatever the rule was.
    #[test]
    fn two_transfers_never_render_the_same() {
        let free = policy_with(vec![rule_at(
            TOKEN,
            Operation::Call,
            vec![unbounded_call("transfer(address,uint256)")],
        )]);
        let mut i = base_intent();
        i.data = transfer_data(VENDOR, U256::from(1u64));
        let paid = shown(&i, &free);
        i.data = transfer_data(ATTACKER, U256::MAX);
        let drained = shown(&i, &free);
        assert_ne!(paid, drained);

        assert!(
            paid.contains(&format!("transfer(a0={VENDOR}, a1=1)")),
            "{paid}"
        );
        assert!(!paid.contains(&ATTACKER.to_string()));
        assert!(
            drained.contains(&format!("transfer(a0={ATTACKER}, a1=")),
            "{drained}"
        );
        assert!(drained.contains(&U256::MAX.to_string()), "{drained}");
        assert!(drained.contains("UNLIMITED"), "{drained}");
    }

    /// Every argument of every declared signature has to reach the screen: a decoder that
    /// silently drops one is invisible until two different payloads read alike. Each argument is
    /// changed on its own here, and every change must move the rendered line.
    #[test]
    fn every_decoded_field_reaches_the_screen() {
        let one = u256_word(U256::from(1u64));
        let two = u256_word(U256::from(2u64));
        let a = addr_word(VENDOR);
        let b = addr_word(ATTACKER);
        let yes = u256_word(U256::from(1u64));
        let no = u256_word(U256::ZERO);
        let r = [0x01u8; 32];
        let s = [0x02u8; 32];

        for (signature, words, mutants) in [
            (
                "swapOwner(address,address,address)",
                vec![a, b, a],
                vec![vec![b, b, a], vec![a, a, a], vec![a, b, b]],
            ),
            (
                "addOwnerWithThreshold(address,uint256)",
                vec![a, one],
                vec![vec![b, one], vec![a, two]],
            ),
            (
                "removeOwner(address,address,uint256)",
                vec![a, b, one],
                vec![vec![b, b, one], vec![a, a, one], vec![a, b, two]],
            ),
            ("changeThreshold(uint256)", vec![one], vec![vec![two]]),
            (
                "transfer(address,uint256)",
                vec![a, one],
                vec![vec![b, one], vec![a, two]],
            ),
            (
                "transferFrom(address,address,uint256)",
                vec![a, b, one],
                vec![vec![b, b, one], vec![a, a, one], vec![a, b, two]],
            ),
            (
                "setApprovalForAll(address,bool)",
                vec![a, yes],
                vec![vec![b, yes], vec![a, no]],
            ),
            (
                "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                vec![a, b, one, one, one, r, s],
                vec![
                    vec![b, b, one, one, one, r, s],
                    vec![a, a, one, one, one, r, s],
                    vec![a, b, two, one, one, r, s],
                    vec![a, b, one, two, one, r, s],
                    vec![a, b, one, one, two, r, s],
                    vec![a, b, one, one, one, s, s],
                    vec![a, b, one, one, one, r, r],
                ],
            ),
            ("enableModule(address)", vec![a], vec![vec![b]]),
            (
                "disableModule(address,address)",
                vec![a, b],
                vec![vec![b, b], vec![a, a]],
            ),
            ("setGuard(address)", vec![a], vec![vec![b]]),
            ("setFallbackHandler(address)", vec![a], vec![vec![b]]),
            ("approveHash(bytes32)", vec![r], vec![vec![s]]),
            (
                "safeTransferFrom(address,address,uint256)",
                vec![a, b, one],
                vec![vec![b, b, one], vec![a, a, one], vec![a, b, two]],
            ),
        ] {
            let p = policy_with(vec![rule_at(
                TOKEN,
                Operation::Call,
                vec![unbounded_call(signature)],
            )]);
            let mut i = base_intent();
            i.data = calldata(signature, &words);
            let base = shown(&i, &p);
            for mutant in mutants {
                i.data = calldata(signature, &mutant);
                assert_ne!(
                    base,
                    shown(&i, &p),
                    "a changed argument did not change the line: {signature}"
                );
            }
        }
    }

    /// The one thing this admission may never do is let a payload it could not fully
    /// deconstruct pass for one it did. Every shape that used to render `UNDECODED CALL` and
    /// sign is now its own typed refusal, and each of them is raised before any human is asked.
    #[test]
    fn every_undecodable_shape_is_refused() {
        let p = token_policy();
        let admit = |i: &SafeTxIntent| admit(i.clone(), &p, None, 0);
        let mut i = base_intent();

        i.data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(matches!(
            admit(&i),
            Err(AdapterErr::Denied { source, .. })
                if matches!(*source, PolicyDenied::Call(CallDenied::SignatureNotAllowed { .. }))
        ));

        i.data = Bytes::new();
        assert!(matches!(
            admit(&i),
            Err(AdapterErr::Denied { source, .. })
                if matches!(*source, PolicyDenied::Call(CallDenied::NoSelector))
        ));

        let good = transfer_data(VENDOR, U256::from(1u64));
        i.data = Bytes::copy_from_slice(&good[..good.len() - 8]);
        assert!(matches!(
            admit(&i),
            Err(AdapterErr::ArgumentsNotDecodable { .. })
        ));

        let mut dirty = good.to_vec();
        dirty[4] = 0xff;
        i.data = Bytes::from(dirty);
        assert!(matches!(
            admit(&i),
            Err(AdapterErr::EncodingNotCanonical { .. })
        ));

        let mut trailing = good.to_vec();
        trailing.extend_from_slice(&[0u8; 32]);
        i.data = Bytes::from(trailing);
        assert!(matches!(
            admit(&i),
            Err(AdapterErr::EncodingNotCanonical { .. })
        ));

        let approvals = policy_with(vec![rule_at(
            TOKEN,
            Operation::Call,
            vec![unbounded_call("setApprovalForAll(address,bool)")],
        )]);
        let mut two = calldata(
            "setApprovalForAll(address,bool)",
            &[addr_word(VENDOR), u256_word(U256::from(1u64))],
        )
        .to_vec();
        let bool_word = two.len() - 1;
        two[bool_word] = 2;
        i.data = Bytes::from(two);
        assert!(matches!(
            super::admit(i.clone(), &approvals, None, 0),
            Err(AdapterErr::EncodingNotCanonical { .. })
        ));

        i.data = transfer_data(ATTACKER, U256::from(1u64));
        assert!(matches!(
            admit(&i),
            Err(AdapterErr::Field { source, .. })
                if matches!(*source, FieldDenied::AddressNotAllowed { .. })
        ));
        i.data = transfer_data(VENDOR, U256::from(1_000_001u64));
        assert!(matches!(
            admit(&i),
            Err(AdapterErr::Field { source, .. })
                if matches!(*source, FieldDenied::ValueTooHigh { .. })
        ));
    }

    /// The approval sheet is three lines, so the ranking of the alarm block decides what the
    /// human actually reads: a field the policy left unbounded must outrank a refund, which is
    /// denied outright without an opt-in and then bounded by two allow-lists and three ceilings.
    /// With every argument bounded, the refund leads on its own.
    #[test]
    fn the_sheet_shows_the_worst_thing_first() {
        let free = policy_with(vec![rule_at(
            TOKEN,
            Operation::Call,
            vec![unbounded_call("approve(address,uint256)")],
        )]);
        let mut i = base_intent();
        i.data = calldata(
            "approve(address,uint256)",
            &[addr_word(ATTACKER), u256_word(U256::MAX)],
        );
        i.gas_price = U256::from(7u64);
        i.refund_receiver = ATTACKER;
        let shown_free = sheet(&shown(&i, &free));
        let unbounded = shown_free
            .find("\u{26a0} UNBOUNDED FIELD")
            .expect("the unbounded argument is on the sheet");
        let refund = shown_free
            .find("\u{26a0} REFUND")
            .expect("the refund is on the sheet");
        assert!(unbounded < refund, "{shown_free}");

        let mut only_refund = base_intent();
        only_refund.data = transfer_data(VENDOR, U256::from(1u64));
        only_refund.gas_price = U256::from(7u64);
        assert!(shown(&only_refund, &token_policy()).starts_with("\u{26a0} REFUND"));
    }

    /// A batch's alarms compete for the head of the sheet on rank rather than on position, and
    /// the alarm names the entry it came from: a module change buried at entry 2 must still
    /// reach the three lines an approval sheet shows, and the bounded transfer beside it must
    /// raise nothing at all.
    #[test]
    fn a_batch_hoists_its_entry_alarms_by_rank() {
        let p = policy_with(vec![
            rule_at(
                LIB,
                Operation::Delegatecall,
                vec![unbounded_call(MULTI_SEND)],
            ),
            rule_at(TOKEN, Operation::Call, vec![to_vendor()]),
            rule_at(
                REGISTRY,
                Operation::Call,
                vec![unbounded_call("enableModule(address)")],
            ),
        ]);
        let entries = [
            batch::packed(0, TOKEN, 0, &transfer_data(VENDOR, U256::from(1u64))),
            batch::packed(
                0,
                REGISTRY,
                0,
                &calldata("enableModule(address)", &[addr_word(MODULE)]),
            ),
        ]
        .concat();
        let mut i = base_intent();
        i.to = LIB;
        i.operation = Operation::Delegatecall;
        i.data = batch::multi_send(&entries);
        let listed = shown(&i, &p);
        assert!(listed.contains("\u{26a0} SAFE CONFIG [2]"), "{listed}");
        assert!(listed.contains("2 sub-calls"), "{listed}");
        assert!(
            listed.contains(&format!("enableModule(a0={MODULE})")),
            "{listed}"
        );
        let sheet = sheet(&listed);
        assert!(sheet.starts_with("\u{26a0} DELEGATECALL"), "{sheet}");
        assert!(sheet.contains("\u{26a0} SAFE CONFIG [2]"), "{sheet}");
    }
}
