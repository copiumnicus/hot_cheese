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
//! [`call`] turns a decoded call into the line naming the action, [`Alarm`] says what that action
//! can still do once the policy has said yes and [`Class`] whether that is a change to who
//! controls the Safe, [`batch`] splits the packed payload of a
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
    CallRule, FieldDenied, FieldNote, FieldWalk, Site, APPROVE_HASH, CHANGE_THRESHOLD, MULTI_SEND,
    OWNER_MGMT, SAFE_CONFIG,
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

/// The human's whole view of one payload, in three parts so that no renderer can print it and
/// lose the half that matters. The alarms are not leading lines of a string a terminal may
/// scroll away or a prompt may cut: they are their own fields, split on the one question a
/// budget may never answer — whether the call changes who controls the Safe — and
/// [`Summary::head`] is how a surface with room for a few lines gets ALL of those and the worst
/// of the rest.
pub struct Summary {
    /// Alarms whose call changes who controls the Safe, or what may act on its behalf, collapsed
    /// and ordered by [`summarize`]. No surface drops one.
    pub authority: Vec<String>,
    /// Every other alarm, worst class first. These are the ones a short surface counts instead.
    pub evictable: Vec<String>,
    /// The decoded call, then the transaction's own fields.
    pub body: String,
}

impl Summary {
    /// Every alarm this payload raises, authority first, for a surface with no budget at all.
    pub fn alarms(&self) -> Vec<&str> {
        let mut out = Vec::with_capacity(self.authority.len() + self.evictable.len());
        for alarm in self.authority.iter().chain(&self.evictable) {
            out.push(alarm.as_str());
        }
        out
    }

    /// What a surface with room for `lines` alarms shows, which on the biometric sheet is the
    /// WHOLE of what the operator consents to: there is no body under it and nothing to scroll
    /// to, so an alarm that is not here was not shown at all.
    ///
    /// `lines` therefore budgets [`Summary::evictable`] and nothing else. Every authority alarm
    /// is printed, in full, before a line of that budget is spent — and when there are more of
    /// them than `lines` holds, the sheet opens by saying so in its own words instead of
    /// counting them away like an ordinary tail.
    pub fn head(&self, lines: usize) -> String {
        let mut out = String::new();
        if self.authority.len() > lines {
            out.push_str(&format!(
                "\u{26d4} {n} AUTHORITY CHANGES, THIS SHEET HOLDS {lines}: all {n} are below, \
                 none dropped",
                n = self.authority.len()
            ));
        }
        let budget = lines.saturating_sub(self.authority.len());
        for alarm in self
            .authority
            .iter()
            .chain(self.evictable.iter().take(budget))
        {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(alarm);
        }
        let dropped = self.evictable.len().saturating_sub(budget);
        if dropped > 0 {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!(
                "\u{26a0} {dropped} MORE: alarms this surface does not hold, listed in full at \
                 the terminal prompt"
            ));
        }
        out
    }
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for alarm in self.alarms() {
            writeln!(f, "{alarm}")?;
        }
        write!(f, "{}", self.body)
    }
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
    let granted = if let Some(grant) = grant {
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
        Some(granted)
    } else {
        None
    };

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
    let args = rule.signature.decode_input(region).map_err(|source| {
        AdapterErr::ArgumentsNotDecodable {
            call: refused(),
            source: Box::new(source),
        }
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
    if let Some(granted) = granted {
        let mut grant_walk = FieldWalk::new(now_secs, &[]);
        for (at, value) in args.iter().enumerate() {
            let Some(arg) = granted.at(at) else {
                return Err(AdapterErr::ArgUnruled {
                    at: site.at.clone(),
                    to: site.to,
                    signature: granted.signature.canonical().to_string(),
                    arg: at,
                });
            };
            grant_walk
                .field(&arg.name, &arg.rule, value)
                .map_err(|source| AdapterErr::Field {
                    at: site.at.clone(),
                    to: site.to,
                    signature: granted.signature.canonical().to_string(),
                    source: Box::new(source),
                })?;
        }
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
    /// split and ordered by [`summarize`], and separately the decoded call, then destination/
    /// value/operation/nonce, Safe and chain, and the gas-refund fields. The alarms are their own
    /// part of the [`Summary`] because an approval surface gets the head of this text and never
    /// the tail. The sub-calls of a `multiSend` raise their alarms into that same block, so an
    /// `enableModule` buried at entry 30 does not compete for the head at all — it changes who
    /// controls the Safe, and nothing that does is ever counted away. `config` supplies names and
    /// decimals only: with empty tables this renders the same bytes it rendered before there were
    /// tables.
    pub fn summary(&self, config: &Config) -> Summary {
        let i = &self.intent;
        let mut flat = Vec::new();
        self.root.flatten(&mut flat);
        let mut raised = Vec::new();
        for one in &flat {
            for alarm in alarms(i, one, config) {
                raised.push(Raised {
                    alarm,
                    at: one.site.position(),
                });
            }
        }
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
        summarize(raised, body, i.chain_id, config)
    }
}

/// Positions named on one collapsed alarm line before the remainder is counted instead.
const SHOWN_POSITIONS: usize = 4;

/// The alarm block an approval surface reads, split into the half a budget may summarise and the
/// half it may not.
///
/// Raisings that render the same line collapse into one line naming every position they came
/// from, so repeating a call cannot spend a sheet's budget on one fact. The collapsed alarms are
/// then emitted one CLASS at a time — every class shows once before any class shows twice — and
/// each round runs worst class first, so a volume of owner additions can never evict the
/// threshold collapse beside it. Within a class the smaller resulting threshold leads, and ties
/// break on the rendered text, so the order is a function of WHAT was submitted and never of the
/// order the requester packed it in.
///
/// The split by [`Class::changes_authority`] comes last and outranks all of it: ordering decides
/// what a short surface shows FIRST, and only this decides what it may not show at all.
fn summarize(raised: Vec<Raised>, body: String, chain_id: U256, config: &Config) -> Summary {
    struct Group {
        alarm: Alarm,
        /// The line with no position in it, which is what makes two raisings one alarm.
        text: String,
        /// Whether the transaction's own call raised it, which never merges with an entry's.
        root: bool,
        /// Every position it was raised at.
        at: Vec<String>,
    }

    let mut groups: Vec<Group> = Vec::new();
    for one in raised {
        let text = one.alarm.line("", chain_id, config);
        let root = one.at.is_empty();
        match groups
            .iter_mut()
            .find(|group| group.root == root && group.text == text)
        {
            Some(group) => group.at.push(one.at),
            None => groups.push(Group {
                alarm: one.alarm,
                text,
                root,
                at: vec![one.at],
            }),
        }
    }
    groups.sort_by(|a, b| {
        (a.alarm.class() as usize, a.alarm.threshold(), &a.text, &a.at).cmp(&(
            b.alarm.class() as usize,
            b.alarm.threshold(),
            &b.text,
            &b.at,
        ))
    });

    let mut shown: Vec<(Class, usize)> = Vec::new();
    let mut ordered = Vec::with_capacity(groups.len());
    for group in groups {
        let class = group.alarm.class();
        let round = match shown.iter_mut().find(|(of, _)| *of == class) {
            Some((_, count)) => {
                *count += 1;
                *count
            }
            None => {
                shown.push((class, 0));
                0
            }
        };
        ordered.push((round, class, group));
    }
    ordered.sort_by_key(|(round, class, _)| (*round, *class as usize));

    let mut authority = Vec::new();
    let mut evictable = Vec::new();
    for (_, class, group) in ordered {
        let mut at = String::new();
        for one in group.at.iter().take(SHOWN_POSITIONS) {
            if !at.is_empty() {
                at.push_str(", ");
            }
            at.push_str(one);
        }
        let dropped = group.at.len().saturating_sub(SHOWN_POSITIONS);
        if dropped > 0 {
            at.push_str(&format!(" +{dropped} more"));
        }
        let line = group.alarm.line(&at, chain_id, config);
        match class.changes_authority() {
            true => authority.push(line),
            false => evictable.push(line),
        }
    }
    Summary {
        authority,
        evictable,
        body,
    }
}

/// What a payload does that nothing else in the system constrains.
///
/// The policy has already pinned the destination, the signature, the operation, the native value
/// and every argument by the time a human sees any of this. The first question of what is left is
/// not how bad a call is but whether it changes who controls the Safe: the sheet shows only three
/// lines, and [`Class::changes_authority`] decides which alarms those three lines may not be
/// spent on. Ordering within each half is [`Class`]'s declared order, worst first. An alarm that
/// names a control-plane call carries the decoded call with it: "a config call happened" is not
/// an alarm unless it says what the call runs.
enum Alarm {
    /// Named code, still running with the Safe's storage and balances.
    DelegatecallDecoded {
        /// The code that runs.
        to: Address,
        /// Whose storage and balances it runs with.
        safe: Address,
        /// The decoded call that code is handed.
        call: String,
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
    /// A module, guard or fallback handler changes.
    ModuleGuardFallback {
        /// The contract this call is aimed at, whose configuration changes.
        to: Address,
        /// The decoded call, naming the address that takes control.
        call: String,
    },
    /// The signatures the Safe demands change.
    ThresholdChange {
        /// The contract this call is aimed at, whose threshold changes.
        to: Address,
        /// Signatures required after the call.
        threshold: U256,
    },
    /// The owner set changes.
    OwnerRotation {
        /// The contract this call is aimed at, whose owners change.
        to: Address,
        /// The decoded call, naming the owner it moves and any threshold it sets.
        call: String,
        /// Signatures required after the call, `U256::MAX` when it sets none.
        threshold: U256,
    },
    /// Any other decoded call against the Safe itself, which is where every Safe administration
    /// call this has no dedicated class for arrives.
    SelfCall {
        /// The Safe calling itself.
        safe: Address,
        /// The decoded call it makes on itself.
        call: String,
    },
    /// A hash approved without its contents, which is this owner's signature on a transaction
    /// nobody here can read.
    OpaqueHash {
        /// The contract that records the approval.
        to: Address,
        /// The decoded call, naming the hash approved.
        call: String,
    },
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

/// Declare the alarm classes, worst first, as the ONE list everything about them is derived
/// from: the order a short surface fills itself in, and the set every property is driven over. A
/// class exists only by being named here, so a class added later is one the tests already
/// enumerate and cannot quietly sit outside.
macro_rules! classes {
    ($($name:ident),+ $(,)?) => {
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        enum Class {
            $($name),+
        }

        impl Class {
            #[cfg(test)]
            const ALL: &'static [Class] = &[$(Class::$name),+];
        }
    };
}

classes!(
    Delegatecall,
    ModuleGuardFallback,
    ThresholdChange,
    OwnerRotation,
    OpaqueHash,
    SelfCall,
    UnboundedField,
    TypedMessage,
    Refund,
    DeadlineFar,
    Batch,
);

impl Class {
    /// Whether a call in this class changes who controls the Safe, or what may act on its
    /// behalf. Delegatecall rewrites the Safe's own storage; module, guard and fallback hand an
    /// address standing authority; the threshold and the owner set ARE who controls it; a call
    /// the Safe makes on itself is the rest of that same administrative surface; and an approved
    /// hash is this owner's signature on a transaction that can do any of it unseen. Nothing in
    /// this half is ever summarised away, whatever a surface's budget is.
    fn changes_authority(self) -> bool {
        match self {
            Class::Delegatecall
            | Class::ModuleGuardFallback
            | Class::ThresholdChange
            | Class::OwnerRotation
            | Class::OpaqueHash
            | Class::SelfCall => true,
            Class::UnboundedField
            | Class::TypedMessage
            | Class::Refund
            | Class::DeadlineFar
            | Class::Batch => false,
        }
    }
}

impl Alarm {
    /// The alarm's class, which decides both whether a surface may drop it and where it sits
    /// among the ones it may. Every class is shown once before any class is shown twice.
    fn class(&self) -> Class {
        match self {
            Alarm::DelegatecallDecoded { .. } => Class::Delegatecall,
            Alarm::ModuleGuardFallback { .. } => Class::ModuleGuardFallback,
            Alarm::ThresholdChange { .. } => Class::ThresholdChange,
            Alarm::OwnerRotation { .. } => Class::OwnerRotation,
            Alarm::OpaqueHash { .. } => Class::OpaqueHash,
            Alarm::SelfCall { .. } => Class::SelfCall,
            Alarm::UnboundedField { .. } => Class::UnboundedField,
            Alarm::TypedMessage => Class::TypedMessage,
            Alarm::Refund { .. } => Class::Refund,
            Alarm::DeadlineFar { .. } => Class::DeadlineFar,
            Alarm::Batch { .. } => Class::Batch,
        }
    }

    /// Signatures the Safe demands after this alarm's call, `U256::MAX` when it changes none, so
    /// within one class the call that collapses a threshold leads the ones that raise it.
    fn threshold(&self) -> U256 {
        match self {
            Alarm::ThresholdChange { threshold, .. }
            | Alarm::OwnerRotation { threshold, .. } => *threshold,
            _ => U256::MAX,
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
            Alarm::DelegatecallDecoded { to, safe, call } => format!(
                "\u{26a0} DELEGATECALL{at}: the code at {} runs {call} as {}",
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
            Alarm::ModuleGuardFallback { to, call } => format!(
                "\u{26a0} SAFE CONFIG{at}: {} runs {call}; the named address controls it \
                 permanently",
                who(*to)
            ),
            Alarm::ThresholdChange { to, threshold } => format!(
                "\u{26a0} THRESHOLD{at}: {} will require {} signature(s)",
                who(*to),
                annotate::count(*threshold)
            ),
            Alarm::OwnerRotation { to, call, .. } => format!(
                "\u{26a0} OWNER ROTATION{at}: {} runs {call}",
                who(*to)
            ),
            Alarm::SelfCall { safe, call } => format!(
                "\u{26a0} SELF-CALL{at}: {} runs {call} on itself",
                who(*safe)
            ),
            Alarm::OpaqueHash { to, call } => format!(
                "\u{26a0} OPAQUE HASH{at}: {} runs {call}, approving a transaction whose contents \
                 are NOT in this payload",
                who(*to)
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

/// The decoded call on ONE line: an alarm is a line, and a batch's rendering is a list, so a
/// batch names its entry count and leaves those entries to the alarms they raise themselves.
fn one_line(call: &TypedCall, config: &Config) -> String {
    match &call.body {
        Body::Plain => call::render(call, config),
        Body::Batch { entries, .. } => format!(
            "{}({} entries)",
            call.rule.signature.function().name,
            entries.len()
        ),
    }
}

/// Every alarm ONE admitted call raises. The refund fields belong to the transaction and not to
/// any sub-call, so they are read only for the call the transaction makes itself.
fn alarms(i: &SafeTxIntent, call: &TypedCall, config: &Config) -> Vec<Alarm> {
    let canonical = call.rule.signature.canonical();
    let rotation = OWNER_MGMT.contains(&canonical);
    let safe_config = SAFE_CONFIG.contains(&canonical);
    let opaque = canonical == APPROVE_HASH;
    let mut out = Vec::new();
    if call.site.operation == Operation::Delegatecall {
        out.push(Alarm::DelegatecallDecoded {
            to: call.site.to,
            safe: i.safe,
            call: one_line(call, config),
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
        out.push(Alarm::ModuleGuardFallback {
            to: call.site.to,
            call: one_line(call, config),
        });
    }
    if rotation {
        let threshold = match call.args.last() {
            Some(DynSolValue::Uint(v, _)) => *v,
            _ => U256::MAX,
        };
        out.push(match canonical == CHANGE_THRESHOLD {
            true => Alarm::ThresholdChange {
                to: call.site.to,
                threshold,
            },
            false => Alarm::OwnerRotation {
                to: call.site.to,
                call: one_line(call, config),
                threshold,
            },
        });
    }
    if call.site.to == i.safe && !rotation && !safe_config && !opaque {
        out.push(Alarm::SelfCall {
            safe: i.safe,
            call: one_line(call, config),
        });
    }
    if opaque {
        out.push(Alarm::OpaqueHash {
            to: call.site.to,
            call: one_line(call, config),
        });
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
    use crate::grant::IntentKind;
    use crate::manifest::Grant;
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
    const OPERATOR: Address = Address::new([0x88u8; 20]);
    const PREV: Address = Address::new([0x99u8; 20]);
    const RUNNER: Address = Address::new([0xaau8; 20]);
    const PARTNER: Address = Address::new([0xbbu8; 20]);
    const MANAGED: Address = Address::new([0xccu8; 20]);

    const PERMIT: &str = "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)";
    const SWAP: &str = "swapOwner(address,address,address)";
    const TRANSFER: &str = "transfer(address,uint256)";
    /// Lines the daemon's Touch ID sheet carries, which is the surface every property below is
    /// about.
    const SHEET: usize = 3;
    /// Unix seconds an accepted deadline sits at, further out than the day a summary calls out.
    const FAR: u64 = 100_000;
    /// The hash a pre-approval is taken over, which the operator can read and nothing else can.
    const HASH: [u8; 32] = [0x7eu8; 32];

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

    pub(crate) fn summarized(i: &SafeTxIntent, policy: &Policy) -> Summary {
        admit(i.clone(), policy, None, 0)
            .expect("the fixture must admit")
            .summary(&plain())
    }

    pub(crate) fn shown(i: &SafeTxIntent, policy: &Policy) -> String {
        summarized(i, policy).to_string()
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
            b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)",
        );
        let mut enc = Vec::new();
        enc.extend_from_slice(&type_hash);
        enc.extend_from_slice(&addr_word(i.to));
        enc.extend_from_slice(&u256_word(i.value));
        enc.extend_from_slice(&keccak256(&i.data));
        enc.extend_from_slice(&u256_word(U256::from(i.operation.as_u8())));
        enc.extend_from_slice(&u256_word(i.safe_tx_gas));
        enc.extend_from_slice(&u256_word(i.base_gas));
        enc.extend_from_slice(&u256_word(i.gas_price));
        enc.extend_from_slice(&addr_word(i.gas_token));
        enc.extend_from_slice(&addr_word(i.refund_receiver));
        enc.extend_from_slice(&u256_word(i.nonce));
        let struct_hash = keccak256(enc);

        let domain_type = keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)");
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

    #[test]
    fn an_adapter_grants_argument_bounds_are_enforced_at_request_time() {
        let policy = policy_with(vec![rule_at(
            TOKEN,
            Operation::Call,
            vec![bounded(
                "transfer(address,uint256)",
                vec![
                    (
                        0,
                        "to",
                        FieldRule::OneOf {
                            addresses: vec![VENDOR, ATTACKER],
                        },
                    ),
                    (
                        1,
                        "amount",
                        FieldRule::Max {
                            max: U256::from(1_000u64),
                            amount_of: TOKEN,
                        },
                    ),
                ],
            )],
        )]);
        let grant = Grant {
            key: "trader".to_string(),
            intent_kinds: vec![IntentKind::SafeTx],
            chain_ids: vec![U256::from(1u64)],
            safes: vec![SAFE],
            calls: vec![rule_at(
                TOKEN,
                Operation::Call,
                vec![bounded(
                    "transfer(address,uint256)",
                    vec![
                        (
                            0,
                            "recipient",
                            FieldRule::OneOf {
                                addresses: vec![VENDOR],
                            },
                        ),
                        (
                            1,
                            "amount",
                            FieldRule::Max {
                                max: U256::from(100u64),
                                amount_of: TOKEN,
                            },
                        ),
                    ],
                )],
            )],
            typed_data: Vec::new(),
            refunds: None,
        };
        let mut intent = base_intent();
        intent.data = transfer_data(VENDOR, U256::from(100u64));
        assert!(admit(intent.clone(), &policy, Some(&grant), 0).is_ok());

        intent.data = transfer_data(ATTACKER, U256::from(1u64));
        assert!(matches!(
            admit(intent.clone(), &policy, Some(&grant), 0),
            Err(AdapterErr::Field { source, .. })
                if matches!(*source, FieldDenied::AddressNotAllowed { .. })
        ));

        intent.data = transfer_data(VENDOR, U256::from(101u64));
        assert!(matches!(
            admit(intent, &policy, Some(&grant), 0),
            Err(AdapterErr::Field { source, .. })
                if matches!(*source, FieldDenied::ValueTooHigh { .. })
        ));
    }

    /// The approval sheet is a few lines, so the ranking of the alarm block decides what the
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
        let shown_free = summarized(&i, &free).head(3);
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

    /// A summary keeps its alarms as their own part, so a surface with room for three lines
    /// prints the three WORST alarms and says how many it is not showing — rather than the first
    /// three lines of a text whose tail is where the alarms would be. The body is never in that
    /// head, everything raised is still in the whole sheet, and seven loose fields do not bury
    /// the one line naming who the Safe is about to pay. Nothing here touches the Safe's
    /// authority, so nothing here is exempt from that budget either.
    #[test]
    fn a_short_surface_gets_the_worst_alarms_and_a_count_of_the_rest() {
        let (free, i) = nothing_authoritative();
        let summary = summarized(&i, &free);
        assert_eq!(summary.alarms().len(), 8, "{summary}");
        assert!(summary.authority.is_empty(), "{summary}");

        let head = summary.head(SHEET);
        assert_eq!(head.lines().count(), 4, "{head}");
        assert!(head.contains("\u{26a0} REFUND"), "{head}");
        assert!(
            !head.contains('\u{26d4}'),
            "a payload that changes nobody's authority says nothing about authority: {head}"
        );
        assert!(head.ends_with(
            "\u{26a0} 5 MORE: alarms this surface does not hold, listed in full at the terminal \
             prompt"
        ));
        for line in head.lines() {
            assert!(line.starts_with('\u{26a0}'), "{head}");
        }
        assert!(!head.contains("nonce="), "{head}");
        assert!(summary.to_string().contains("nonce="), "{summary}");
    }

    /// The requester packs the batch, so it must not get to pick which danger the sheet shows.
    /// Three owner additions — one of them submitted twice — cannot spend the three lines a
    /// Touch ID sheet has and evict the call that drops the Safe to a single signature, the
    /// repeat collapses into one line naming both positions it came from, and reversing the
    /// entries changes neither.
    #[test]
    fn a_volume_of_owner_additions_cannot_evict_the_threshold_collapse() {
        const OWNER_A: Address = Address::new([0xa1u8; 20]);
        const OWNER_B: Address = Address::new([0xb2u8; 20]);
        const OWNER_C: Address = Address::new([0xc3u8; 20]);
        const ADD: &str = "addOwnerWithThreshold(address,uint256)";

        let mut policy = policy_with(vec![rule_at(
            LIB,
            Operation::Delegatecall,
            vec![unbounded_call(MULTI_SEND)],
        )]);
        policy.owner_management = OwnerMgmt {
            allow: true,
            max_value: U256::ZERO,
            call: vec![
                bounded(
                    ADD,
                    vec![
                        (
                            0,
                            "owner",
                            FieldRule::OneOf {
                                addresses: vec![OWNER_A, OWNER_B, OWNER_C],
                            },
                        ),
                        (
                            1,
                            "threshold",
                            FieldRule::Max {
                                max: U256::from(10u64),
                                amount_of: Address::ZERO,
                            },
                        ),
                    ],
                ),
                bounded(
                    "changeThreshold(uint256)",
                    vec![(
                        0,
                        "threshold",
                        FieldRule::Max {
                            max: U256::from(10u64),
                            amount_of: Address::ZERO,
                        },
                    )],
                ),
            ],
        };

        let add = |owner: Address| {
            batch::packed(
                0,
                SAFE,
                0,
                &calldata(ADD, &[addr_word(owner), u256_word(U256::from(4u64))]),
            )
        };
        let collapse = batch::packed(
            0,
            SAFE,
            0,
            &calldata("changeThreshold(uint256)", &[u256_word(U256::from(1u64))]),
        );
        let submitted = [
            add(OWNER_A),
            add(OWNER_B),
            add(OWNER_C),
            collapse,
            add(OWNER_A),
        ];
        let mut reversed = submitted.clone();
        reversed.reverse();

        for order in [submitted, reversed] {
            let mut i = base_intent();
            i.to = LIB;
            i.operation = Operation::Delegatecall;
            i.data = batch::multi_send(&order.concat());
            let summary = summarized(&i, &policy);
            let sheet = summary.head(3);

            assert_eq!(
                summary.alarms().len(),
                6,
                "seven raisings must collapse to six lines: {summary}"
            );
            assert!(
                summary
                    .to_string()
                    .contains(&format!("OWNER ROTATION [1, 5]: {SAFE} runs addOwnerWithThreshold")),
                "the repeated addition is one line naming both its positions: {summary}"
            );
            assert!(
                sheet.contains("\u{26a0} THRESHOLD") && sheet.contains("will require 1 signature"),
                "the threshold collapse must reach a three-line sheet: {sheet}"
            );

            let mut rotations = Vec::new();
            for (n, line) in summary.authority.iter().enumerate() {
                if line.contains("OWNER ROTATION") {
                    rotations.push(n);
                }
            }
            let threshold = summary
                .authority
                .iter()
                .position(|line| line.contains("\u{26a0} THRESHOLD"))
                .expect("the threshold collapse changes who controls the Safe");
            assert_eq!(rotations.len(), 3, "{summary}");
            assert!(
                threshold < rotations[1],
                "no class may take a second line while another has none: {summary}"
            );
            assert!(
                summary
                    .evictable
                    .iter()
                    .any(|line| line.contains("\u{26a0} BATCH")),
                "a batch bounds nobody's authority and is the sheet's to summarise: {summary}"
            );
            assert!(
                !sheet.contains("\u{26a0} BATCH"),
                "no budget is spent below the authority block: {sheet}"
            );
        }
    }

    /// A batch's alarms compete for the head of the sheet on danger rather than on position, and
    /// the alarm names the entry it came from, the contract it is aimed at and the address the
    /// call hands control to: a module change buried at entry 2 must still reach the three lines
    /// an approval sheet shows, and the bounded transfer beside it must raise nothing at all.
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
        let summary = summarized(&i, &p);
        let listed = summary.to_string();
        assert!(listed.contains("2 sub-calls"), "{listed}");
        assert!(
            listed.contains(&format!("enableModule(a0={MODULE})")),
            "{listed}"
        );
        let sheet = summary.head(3);
        assert!(sheet.starts_with("\u{26a0} DELEGATECALL"), "{sheet}");
        assert!(
            sheet.contains(&format!(
                "\u{26a0} SAFE CONFIG [2]: {REGISTRY} runs enableModule(a0={MODULE})"
            )),
            "the alarm must name the contract the call is aimed at and the module it enables: \
             {sheet}"
        );
    }

    /// A payload whose every alarm is one a budget may summarise away: seven arguments the policy
    /// left free and a refund, and nothing that touches who controls the Safe.
    fn nothing_authoritative() -> (Policy, SafeTxIntent) {
        let free = policy_with(vec![rule_at(
            TOKEN,
            Operation::Call,
            vec![unbounded_call(PERMIT)],
        )]);
        let mut i = base_intent();
        i.data = calldata(
            PERMIT,
            &[
                addr_word(VENDOR),
                addr_word(ATTACKER),
                u256_word(U256::from(1u64)),
                u256_word(U256::from(2u64)),
                u256_word(U256::from(3u64)),
                [0x01u8; 32],
                [0x02u8; 32],
            ],
        );
        i.gas_price = U256::from(7u64);
        (free, i)
    }

    /// A `permit` every argument of which is free except the deadline, which is accepted further
    /// out than a day.
    fn loose_permit() -> CallRule {
        bounded(
            PERMIT,
            vec![
                (0, "a0", FieldRule::Unbounded),
                (1, "a1", FieldRule::Unbounded),
                (2, "a2", FieldRule::Unbounded),
                (
                    3,
                    "deadline",
                    FieldRule::Deadline {
                        within_secs: FAR * 2,
                    },
                ),
                (4, "a4", FieldRule::Unbounded),
                (5, "a5", FieldRule::Unbounded),
                (6, "a6", FieldRule::Unbounded),
            ],
        )
    }

    /// The noisiest payload this daemon decodes at all: one entry for every alarm a Safe
    /// transaction can raise, and every remaining entry of the ceiling spent on loose arguments
    /// and a far deadline. `managed` is whether the policy governs the transaction's own Safe,
    /// which is the shape the daemon signs — and the shape in which the Safe is reachable only
    /// through the rotation gate, so the call it makes on itself is raised from the other one.
    fn every_alarm(managed: bool) -> (Policy, SafeTxIntent) {
        let mut policy = policy_with(vec![
            rule_at(LIB, Operation::Call, vec![unbounded_call(MULTI_SEND)]),
            rule_at(
                RUNNER,
                Operation::Delegatecall,
                vec![unbounded_call(TRANSFER)],
            ),
            rule_at(
                REGISTRY,
                Operation::Call,
                vec![unbounded_call("enableModule(address)")],
            ),
            rule_at(PARTNER, Operation::Call, vec![unbounded_call(APPROVE_HASH)]),
            rule_at(TOKEN, Operation::Call, vec![loose_permit()]),
        ]);
        policy.owner_management = OwnerMgmt {
            allow: true,
            max_value: U256::ZERO,
            call: vec![unbounded_call(CHANGE_THRESHOLD), unbounded_call(SWAP)],
        };
        let rotated = match managed {
            true => SAFE,
            false => {
                policy.safe = MANAGED;
                policy
                    .allow
                    .push(rule_at(SAFE, Operation::Call, vec![unbounded_call(TRANSFER)]));
                MANAGED
            }
        };

        let mut entries = vec![
            batch::packed(1, RUNNER, 0, &transfer_data(VENDOR, U256::from(1u64))),
            batch::packed(
                0,
                REGISTRY,
                0,
                &calldata("enableModule(address)", &[addr_word(MODULE)]),
            ),
            batch::packed(
                0,
                rotated,
                0,
                &calldata(CHANGE_THRESHOLD, &[u256_word(U256::from(1u64))]),
            ),
            batch::packed(
                0,
                rotated,
                0,
                &calldata(
                    SWAP,
                    &[addr_word(PREV), addr_word(OPERATOR), addr_word(ATTACKER)],
                ),
            ),
            batch::packed(0, PARTNER, 0, &calldata(APPROVE_HASH, &[HASH])),
        ];
        if !managed {
            entries.push(batch::packed(
                0,
                SAFE,
                0,
                &transfer_data(VENDOR, U256::from(2u64)),
            ));
        }
        while entries.len() < batch::MAX_BATCH_ENTRIES {
            entries.push(batch::packed(
                0,
                TOKEN,
                0,
                &calldata(
                    PERMIT,
                    &[
                        addr_word(VENDOR),
                        addr_word(ATTACKER),
                        u256_word(U256::from(1u64)),
                        u256_word(U256::from(FAR)),
                        u256_word(U256::from(1u64)),
                        [0x01u8; 32],
                        [0x02u8; 32],
                    ],
                ),
            ));
        }

        let mut i = base_intent();
        i.to = LIB;
        i.data = batch::multi_send(&entries.concat());
        i.gas_price = U256::from(7u64);
        i.refund_receiver = ATTACKER;
        (policy, i)
    }

    /// The one payload with no Safe transaction in it at all.
    fn typed_message() -> Summary {
        const SCHEMA: &str = concat!(
            "[[typed_data]]\n",
            "schema = \"order\"\n",
            "primary_type = \"Order\"\n",
            "  [typed_data.domain]\n",
            "  chain_id = 1\n",
            "  verifying_contract = \"0x3333333333333333333333333333333333333333\"\n",
            "  [[typed_data.types]]\n",
            "  name = \"Order\"\n",
            "    [[typed_data.types.field]]\n",
            "    name = \"amount\"\n",
            "    type = \"uint256\"\n",
            "    rule = \"unbounded\"\n",
        );
        let text = format!(
            "safe = \"0x1111111111111111111111111111111111111111\"\nchain_id = 1\n\n{SCHEMA}"
        );
        let policy: Policy = toml::from_str(&text).expect("the declared schema must load");
        let intent = crate::intent::TypedDataIntent {
            key: "trader".to_string(),
            schema: "order".to_string(),
            chain_id: U256::from(1u64),
            verifying_contract: VENDOR,
            message: serde_json::json!({ "amount": "1" }),
        };
        typed::admit(&intent, &policy, 0)
            .expect("the fixture must admit")
            .summary(&intent.key, &plain())
    }

    /// Which payload raises an alarm class.
    #[derive(Clone, Copy)]
    enum Raiser {
        /// Every class a Safe transaction raises, under a policy that governs that Safe.
        Managed,
        /// The same, under a policy that governs another Safe — the one shape in which the
        /// transaction's own Safe is a destination like any other.
        Unmanaged,
        /// The EIP-712 message.
        Message,
    }

    impl Raiser {
        fn summary(self) -> Summary {
            match self {
                Raiser::Managed => {
                    let (policy, i) = every_alarm(true);
                    summarized(&i, &policy)
                }
                Raiser::Unmanaged => {
                    let (policy, i) = every_alarm(false);
                    summarized(&i, &policy)
                }
                Raiser::Message => typed_message(),
            }
        }
    }

    /// How one class is raised, what the operator has to read when it is, and whether it changes
    /// who controls the Safe.
    struct Case {
        /// The payload that raises it.
        by: Raiser,
        /// Text of the line it raises.
        needle: String,
        /// Whether it changes who controls the Safe, or what may act on its behalf.
        authority: bool,
    }

    /// Every class, its payload and its side of the split — stated HERE and never read back out
    /// of the code under test, so an alarm that stops declaring itself an authority change fails
    /// this rather than quietly agreeing with itself. The match is exhaustive over [`Class`], so
    /// a class added later does not compile until it declares all three, and the payload it
    /// names has to actually raise it or the assertions below fail.
    fn raised_by(class: Class) -> Case {
        let (by, needle, authority) = match class {
            Class::Delegatecall => (
                Raiser::Managed,
                format!(
                    "DELEGATECALL [1]: the code at {RUNNER} runs transfer(a0={VENDOR}, a1=1) as \
                     {SAFE}"
                ),
                true,
            ),
            Class::ModuleGuardFallback => (
                Raiser::Managed,
                format!("SAFE CONFIG [2]: {REGISTRY} runs enableModule(a0={MODULE})"),
                true,
            ),
            Class::ThresholdChange => (
                Raiser::Managed,
                format!("THRESHOLD [3]: {SAFE} will require 1 signature(s)"),
                true,
            ),
            Class::OwnerRotation => (
                Raiser::Managed,
                format!(
                    "OWNER ROTATION [4]: {SAFE} runs swapOwner(a0={PREV}, a1={OPERATOR}, \
                     a2={ATTACKER})"
                ),
                true,
            ),
            Class::OpaqueHash => (
                Raiser::Managed,
                format!(
                    "OPAQUE HASH [5]: {PARTNER} runs approveHash(a0=0x{})",
                    hex::encode(HASH)
                ),
                true,
            ),
            Class::SelfCall => (
                Raiser::Unmanaged,
                format!("SELF-CALL [6]: {SAFE} runs transfer(a0={VENDOR}, a1=2) on itself"),
                true,
            ),
            Class::UnboundedField => (
                Raiser::Managed,
                "[a0]: the policy places no bound on this value".to_string(),
                false,
            ),
            Class::TypedMessage => (
                Raiser::Message,
                "TYPED MESSAGE: this signature is valid at the".to_string(),
                false,
            ),
            Class::Refund => (
                Raiser::Managed,
                format!(
                    "REFUND: pays (gasUsed+0)*7 of {} to {ATTACKER}",
                    Address::ZERO
                ),
                false,
            ),
            Class::DeadlineFar => (
                Raiser::Managed,
                format!("[deadline]: valid until {FAR}, more than a day out"),
                false,
            ),
            Class::Batch => (
                Raiser::Managed,
                format!("BATCH: {} sub-calls", batch::MAX_BATCH_ENTRIES),
                false,
            ),
        };
        Case {
            by,
            needle,
            authority,
        }
    }

    /// The property the sheet exists for: an alarm that changes who controls the Safe, or what
    /// may act on its behalf, is never one of the alarms a surface summarises away. Every class
    /// is raised inside a batch packed to the entry ceiling, beside every other class the same
    /// payload can raise, and each authority class must still be readable — argument and all —
    /// in the three lines a Touch ID sheet carries. The classes that bound nobody's authority
    /// must land on the other side of that split, so a payload cannot buy silence by being loud.
    #[test]
    fn no_authority_alarm_is_ever_summarised_off_the_sheet() {
        for &class in Class::ALL {
            let case = raised_by(class);
            assert_eq!(
                case.authority,
                class.changes_authority(),
                "{class:?} changed which half of the sheet it belongs to"
            );
            let summary = case.by.summary();
            let block = match case.authority {
                true => &summary.authority,
                false => &summary.evictable,
            };
            assert!(
                block.iter().any(|line| line.contains(&case.needle)),
                "{class:?} is not raised by its payload, or landed on the wrong side of the \
                 split: {summary}"
            );
            if !case.authority {
                continue;
            }
            let sheet = summary.head(SHEET);
            assert!(
                sheet.contains(&case.needle),
                "{class:?} was summarised off a {SHEET}-line sheet: {sheet}"
            );
        }
    }

    /// More authority changes than the sheet holds is the loudest state a payload can be in, so
    /// it may never read like an ordinary tail: the sheet opens by naming the count, still
    /// carries every one of them, and spends nothing on the alarms that bound nobody's authority
    /// while it does. The payload that raises none of them is truncated in the ordinary way and
    /// says nothing about authority at all — the two sheets cannot be mistaken for each other.
    #[test]
    fn an_over_budget_authority_block_is_not_routine_truncation() {
        let (policy, i) = every_alarm(false);
        let summary = summarized(&i, &policy);
        let sheet = summary.head(SHEET);
        assert_eq!(summary.authority.len(), 6, "{summary}");
        assert!(
            sheet.starts_with(&format!(
                "\u{26d4} 6 AUTHORITY CHANGES, THIS SHEET HOLDS {SHEET}: all 6 are below, none \
                 dropped"
            )),
            "{sheet}"
        );
        for line in &summary.authority {
            assert!(sheet.contains(line.as_str()), "{sheet}");
        }
        for line in &summary.evictable {
            assert!(!sheet.contains(line.as_str()), "{sheet}");
        }
        assert_eq!(sheet.lines().count(), 8, "{sheet}");

        let (free, loose) = nothing_authoritative();
        let routine = summarized(&loose, &free).head(SHEET);
        assert!(!routine.contains('\u{26d4}'), "{routine}");
        assert!(
            routine.ends_with(
                "\u{26a0} 5 MORE: alarms this surface does not hold, listed in full at the \
                 terminal prompt"
            ),
            "{routine}"
        );
    }
}
