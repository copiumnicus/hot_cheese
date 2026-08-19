//! Fail-closed, per-key signing policy loaded from `<store>/policies/<name>.toml`.
use crate::intent::{Operation, SafeTxIntent};
use crate::schema::{
    check_call_rules, check_schemas, CallRule, RuleErr, Site, TypedDataSchema, OWNER_MGMT,
};
use alloy_primitives::{Address, FixedBytes, B256, U256};
use err_mac::create_err_with_impls;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

pub const MAX_POLICY_BYTES: u64 = 64 * 1024;
const MAX_ALLOW_RULES: usize = 128;
const MAX_REFUND_CHOICES: usize = 64;

/// One key's policy: which Safe, the mandatory chain pin, allowed contract calls, whether
/// owner/threshold rotations are permitted, any opt-in refund allowance, and the EIP-712
/// message shapes this key may sign.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub safe: Address,
    #[serde(with = "hc_core::wire::u256")]
    pub chain_id: U256,
    #[serde(default)]
    pub allow: Vec<AllowRule>,
    #[serde(default)]
    pub owner_management: OwnerMgmt,
    #[serde(default)]
    pub refunds: Option<RefundPolicy>,
    /// EIP-712 message schemas this key may sign, each complete: domain, types, constraints.
    #[serde(default)]
    pub typed_data: Vec<TypedDataSchema>,
}

/// Opt-in allowance for Safe gas-refund fields: only when present may an intent carry any
/// refund activity, and then only within these token/receiver allow-lists and gas ceilings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundPolicy {
    /// Gas tokens a refund may be paid in (`0x0` denotes native ETH).
    #[serde(default)]
    pub gas_tokens: Vec<Address>,
    /// Addresses a refund may be paid to; never `0x0`, which a Safe pays to `tx.origin`.
    #[serde(default)]
    pub refund_receivers: Vec<Address>,
    /// Ceiling on the intent's `gasPrice`.
    #[serde(default)]
    pub max_gas_price: U256,
    /// Ceiling on the intent's `baseGas`.
    #[serde(default)]
    pub max_base_gas: U256,
    /// Ceiling on the intent's `safeTxGas`.
    #[serde(default)]
    pub max_safe_tx_gas: U256,
}

/// A permitted destination: the calls it may receive, a native-value ceiling, and the required
/// operation. A term this struct does not name is a refusal to load, in a policy file and in an
/// adapter manifest alike: an unrecognised rule term is something the daemon does not enforce.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRule {
    pub to: Address,
    /// Calls permitted at this destination, each a full canonical signature plus its
    /// per-argument bounds. The 4-byte selector is derived from the signature.
    pub call: Vec<CallRule>,
    #[serde(default)]
    pub max_value: U256,
    #[serde(default)]
    pub operation: Operation,
}

/// Owner/threshold rotation policy for calls the Safe makes against itself.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerMgmt {
    pub allow: bool,
    /// Rotation calls permitted against the Safe, each of which must be one of
    /// [`OWNER_MGMT`](crate::schema::OWNER_MGMT).
    pub call: Vec<CallRule>,
    /// Native value a rotation call may carry. Zero unless an operator says otherwise: a
    /// rotation has no need to move value, and the ceiling never reached these calls before.
    #[serde(default)]
    pub max_value: U256,
}

create_err_with_impls!(
    #[derive(Debug)]
    pub CallDenied,
    NoSelector
    ;
    ToNotAllowed { to: Address },
    OperationNotAllowed { rule: Operation, got: Operation },
    SignatureNotAllowed { to: Address, selector: FixedBytes<4> },
    ValueTooHigh { value: U256, max: U256 }
);

create_err_with_impls!(
    #[derive(Debug)]
    pub RefundDenied,
    RefundNotAllowed
    ;
    GasTokenNotAllowed { gas_token: Address },
    RefundReceiverNotAllowed { refund_receiver: Address },
    GasPriceTooHigh { gas_price: U256, max: U256 },
    BaseGasTooHigh { base_gas: U256, max: U256 },
    SafeTxGasTooHigh { safe_tx_gas: U256, max: U256 }
);

create_err_with_impls!(
    #[derive(Debug)]
    pub PolicyDenied,
    NoSelector,
    OwnerManagementNotAllowed,
    Call(CallDenied),
    Refund(RefundDenied)
    ;
    SafeMismatch { expected: Address, got: Address },
    ChainMismatch { expected: U256, got: U256 },
    OwnerManagementValueTooHigh { value: U256, max: U256 }
);

create_err_with_impls!(
    #[derive(Debug)]
    pub PolicyErr,
    Denied(PolicyDenied),
    Io(std::io::Error),
    Rule(RuleErr),
    Toml(toml::de::Error),
    Utf8(std::string::FromUtf8Error),
    InactiveOwnerManagementTerms,
    EmptyOwnerManagementCalls
    ;
    DuplicateRule { to: Address, operation: Operation },
    TooManyEntries { location: String, found: usize, max: usize },
    EmptyCallSet { to: Address, operation: Operation },
    GeneralRuleTargetsSafe { safe: Address },
    UnsupportedOwnerManagementCall { signature: String },
    EmptyRefundChoices { field: String },
    DuplicateRefundChoice { field: String, address: Address },
    RefundReceiverResolvesToOrigin { field: String },
    InvalidName { name: String },
    TooLarge { size: u64, max: u64 }
);

/// A policy and the digest of the exact bytes it was parsed from.
pub struct LoadedPolicy {
    /// The parsed rules.
    pub policy: Policy,
    /// SHA-256 of the file bytes `policy` came from.
    pub digest: B256,
    /// Keystore name the policy filename bound these bytes to. `None` means [`Policy::parse`]
    /// validated transport bytes without granting them signing authority for any keystore.
    key_name: Option<String>,
}

impl LoadedPolicy {
    /// Keystore this policy was loaded for. Parsed transport bytes are deliberately unbound.
    pub fn key_name(&self) -> Option<&str> {
        self.key_name.as_deref()
    }
}

impl Policy {
    /// Parse and validate policy bytes received through a bounded external transport.
    pub fn parse(bytes: &[u8]) -> Result<LoadedPolicy, PolicyErr> {
        if bytes.len() as u64 > MAX_POLICY_BYTES {
            return Err(PolicyErr::TooLarge {
                size: bytes.len() as u64,
                max: MAX_POLICY_BYTES,
            });
        }
        let text = String::from_utf8(bytes.to_vec())?;
        let policy: Policy = toml::from_str(&text)?;
        if policy.allow.len() > MAX_ALLOW_RULES {
            return Err(PolicyErr::TooManyEntries {
                location: "allow".to_string(),
                found: policy.allow.len(),
                max: MAX_ALLOW_RULES,
            });
        }
        if policy.allow.iter().any(|rule| rule.to == policy.safe) {
            return Err(PolicyErr::GeneralRuleTargetsSafe { safe: policy.safe });
        }
        no_duplicate_rules(&policy.allow)?;
        check_call_rules(&policy.owner_management.call)?;
        match policy.owner_management.allow {
            false
                if !policy.owner_management.call.is_empty()
                    || policy.owner_management.max_value != U256::ZERO =>
            {
                return Err(PolicyErr::InactiveOwnerManagementTerms)
            }
            true if policy.owner_management.call.is_empty() => {
                return Err(PolicyErr::EmptyOwnerManagementCalls)
            }
            true => {
                for call in &policy.owner_management.call {
                    if !OWNER_MGMT.contains(&call.signature.canonical()) {
                        return Err(PolicyErr::UnsupportedOwnerManagementCall {
                            signature: call.signature.canonical().to_string(),
                        });
                    }
                }
            }
            false => {}
        }
        if let Some(refunds) = &policy.refunds {
            check_refunds(refunds)?;
        }
        check_schemas(&policy.typed_data)?;
        Ok(LoadedPolicy {
            digest: B256::from_slice(&Sha256::digest(text.as_bytes())),
            policy,
            key_name: None,
        })
    }

    /// Load `<store>/policies/<name>.toml`. A missing file is an error (deny by default).
    /// The digest is of the bytes actually read, so it names the policy in force for the
    /// signature this load is serving — a policy edited afterwards is a different digest.
    pub fn load(store: &Path, name: &str) -> Result<LoadedPolicy, PolicyErr> {
        if !hc_core::is_valid_key_name(name) {
            return Err(PolicyErr::InvalidName {
                name: hc_core::safe_diagnostic_text(name),
            });
        }
        let path = store.join("policies").join(format!("{name}.toml"));
        let mut bytes = Vec::new();
        hc_core::open_regular_file(&path)?
            .take(MAX_POLICY_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_POLICY_BYTES {
            return Err(PolicyErr::TooLarge {
                size: bytes.len() as u64,
                max: MAX_POLICY_BYTES,
            });
        }
        let mut loaded = Self::parse(&bytes)?;
        loaded.key_name = Some(name.to_string());
        Ok(loaded)
    }
}

/// Refuse an allow-list holding two rules for the same destination AND operation. [`match_call`]
/// takes the first such rule, so a later duplicate could never fire: an operator who wrote one
/// believes in a rule the daemon does not enforce. Both a policy file and an adapter manifest's
/// `grants.calls` are checked with this, at load, before anything can be evaluated against them —
/// and with it every rule's declared signatures and argument bounds.
pub(crate) fn no_duplicate_rules(rules: &[AllowRule]) -> Result<(), PolicyErr> {
    if rules.len() > MAX_ALLOW_RULES {
        return Err(PolicyErr::TooManyEntries {
            location: "allow rules".to_string(),
            found: rules.len(),
            max: MAX_ALLOW_RULES,
        });
    }
    for (i, rule) in rules.iter().enumerate() {
        if rule.call.is_empty() {
            return Err(PolicyErr::EmptyCallSet {
                to: rule.to,
                operation: rule.operation,
            });
        }
        for other in &rules[i + 1..] {
            if other.to == rule.to && other.operation == rule.operation {
                return Err(PolicyErr::DuplicateRule {
                    to: rule.to,
                    operation: rule.operation,
                });
            }
        }
        check_call_rules(&rule.call)?;
    }
    Ok(())
}

/// Refuse an allowance whose terms do not mean what they read. `refundReceiver = 0x0` is the one
/// address a Safe does not pay literally — `execTransaction` sends that refund to `tx.origin`, an
/// account the submitter chooses — while the approval sheet renders it as the zero address, so
/// allow-listing it is an allow-list on nobody in particular. It is refused where a policy or a
/// manifest is PARSED, so no such term ever reaches a prompt.
pub(crate) fn check_refunds(refunds: &RefundPolicy) -> Result<(), PolicyErr> {
    if refunds.refund_receivers.contains(&Address::ZERO) {
        return Err(PolicyErr::RefundReceiverResolvesToOrigin {
            field: "refunds.refund_receivers".to_string(),
        });
    }
    for (field, choices) in [
        ("gas_tokens", refunds.gas_tokens.as_slice()),
        ("refund_receivers", refunds.refund_receivers.as_slice()),
    ] {
        if choices.is_empty() {
            return Err(PolicyErr::EmptyRefundChoices {
                field: field.to_string(),
            });
        }
        if choices.len() > MAX_REFUND_CHOICES {
            return Err(PolicyErr::TooManyEntries {
                location: format!("refunds.{field}"),
                found: choices.len(),
                max: MAX_REFUND_CHOICES,
            });
        }
        for (at, address) in choices.iter().enumerate() {
            if choices[at + 1..].contains(address) {
                return Err(PolicyErr::DuplicateRefundChoice {
                    field: field.to_string(),
                    address: *address,
                });
            }
        }
    }
    Ok(())
}

/// Match one call against a list of [`AllowRule`]s: the rule is selected by destination AND
/// operation together, so two rules for one destination each govern their own operation, and then
/// the declared signature is selected by the 4 bytes the calldata starts with. A per-key policy's
/// `allow` and an adapter manifest's `grants.calls` are both lists of these, and this is the only
/// code that reads one — an adapter cannot be granted a call shape the policy language cannot
/// express.
///
/// The empty-calldata refusal lives here rather than in the decoder, because a call with no
/// selector is a call no [`AllowRule`] can permit: that is a policy verdict, not a decode failure.
pub fn match_call<'p>(rules: &'p [AllowRule], site: &Site) -> Result<&'p CallRule, CallDenied> {
    let mut matched = None;
    let mut other_operation = None;
    for rule in rules {
        if rule.to != site.to {
            continue;
        }
        if rule.operation == site.operation {
            matched = Some(rule);
            break;
        }
        other_operation = Some(rule.operation);
    }
    let Some(rule) = matched else {
        return match other_operation {
            Some(allowed) => Err(CallDenied::OperationNotAllowed {
                rule: allowed,
                got: site.operation,
            }),
            None => Err(CallDenied::ToNotAllowed { to: site.to }),
        };
    };
    let Some(head) = site.data.get(..4) else {
        return Err(CallDenied::NoSelector);
    };
    let selector = FixedBytes::<4>::from_slice(head);
    let Some(call) = rule
        .call
        .iter()
        .find(|c| c.signature.selector() == selector)
    else {
        return Err(CallDenied::SignatureNotAllowed {
            to: site.to,
            selector,
        });
    };
    if site.value > rule.max_value {
        return Err(CallDenied::ValueTooHigh {
            value: site.value,
            max: rule.max_value,
        });
    }
    Ok(call)
}

/// The authority check for ONE call the Safe makes — the transaction's own, or one entry of a
/// `multiSend` — returning the declared shape its calldata is then decoded against. Finding the
/// rule IS the authority decision, which is what makes "anything policy permits is decodable"
/// structural rather than a convention.
pub fn match_site<'p>(site: &Site, policy: &'p Policy) -> Result<&'p CallRule, PolicyDenied> {
    if site.to != policy.safe {
        return Ok(match_call(&policy.allow, site)?);
    }
    let Some(head) = site.data.get(..4) else {
        return Err(PolicyDenied::NoSelector);
    };
    let selector = FixedBytes::<4>::from_slice(head);
    let matched = policy
        .owner_management
        .call
        .iter()
        .find(|c| c.signature.selector() == selector);
    let allowed = policy.owner_management.allow
        && site.operation == Operation::Call
        && matches!(matched, Some(c) if OWNER_MGMT.contains(&c.signature.canonical()));
    let Some(call) = matched.filter(|_| allowed) else {
        return Err(PolicyDenied::OwnerManagementNotAllowed);
    };
    if site.value > policy.owner_management.max_value {
        return Err(PolicyDenied::OwnerManagementValueTooHigh {
            value: site.value,
            max: policy.owner_management.max_value,
        });
    }
    Ok(call)
}

/// Match an intent's gas-refund fields against an allowance. An absent allowance denies any
/// refund/gas activity at all, which is why an intent that leaves all five fields at their zero
/// value passes without one. A per-key policy's `refunds` and an adapter grant's `refunds`
/// are both allowances, and this is the only code that reads one.
pub fn match_refunds(
    allowance: Option<&RefundPolicy>,
    i: &SafeTxIntent,
) -> Result<(), RefundDenied> {
    let quiet = i.gas_price == U256::ZERO
        && i.gas_token == Address::ZERO
        && i.refund_receiver == Address::ZERO
        && i.base_gas == U256::ZERO
        && i.safe_tx_gas == U256::ZERO;
    if quiet {
        return Ok(());
    }
    let Some(refunds) = allowance else {
        return Err(RefundDenied::RefundNotAllowed);
    };
    if !refunds.gas_tokens.contains(&i.gas_token) {
        return Err(RefundDenied::GasTokenNotAllowed {
            gas_token: i.gas_token,
        });
    }
    if !refunds.refund_receivers.contains(&i.refund_receiver) {
        return Err(RefundDenied::RefundReceiverNotAllowed {
            refund_receiver: i.refund_receiver,
        });
    }
    if i.gas_price > refunds.max_gas_price {
        return Err(RefundDenied::GasPriceTooHigh {
            gas_price: i.gas_price,
            max: refunds.max_gas_price,
        });
    }
    if i.base_gas > refunds.max_base_gas {
        return Err(RefundDenied::BaseGasTooHigh {
            base_gas: i.base_gas,
            max: refunds.max_base_gas,
        });
    }
    if i.safe_tx_gas > refunds.max_safe_tx_gas {
        return Err(RefundDenied::SafeTxGasTooHigh {
            safe_tx_gas: i.safe_tx_gas,
            max: refunds.max_safe_tx_gas,
        });
    }
    Ok(())
}

/// Fail-closed check of an intent against its policy. Every failure carries the offending
/// value. Any gas-refund activity is denied unless the policy opts in via `refunds`, and
/// delegatecall is default-denied because no rule's operation defaults to it.
pub fn evaluate(i: &SafeTxIntent, policy: &Policy) -> Result<(), PolicyDenied> {
    if i.safe != policy.safe {
        return Err(PolicyDenied::SafeMismatch {
            expected: policy.safe,
            got: i.safe,
        });
    }
    if i.chain_id != policy.chain_id {
        return Err(PolicyDenied::ChainMismatch {
            expected: policy.chain_id,
            got: i.chain_id,
        });
    }
    match_refunds(policy.refunds.as_ref(), i)?;
    match_site(&Site::own(i), policy)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::unbounded_call;
    use alloy_primitives::Bytes;

    const SAFE: [u8; 20] = [0x11; 20];
    const TOKEN: [u8; 20] = [0x22; 20];
    const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

    fn base_intent() -> SafeTxIntent {
        SafeTxIntent {
            key: "k".into(),
            safe: Address::from(SAFE),
            chain_id: U256::from(1u64),
            to: Address::from(TOKEN),
            value: U256::ZERO,
            data: Bytes::from(TRANSFER.to_vec()),
            operation: Operation::Call,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::ZERO,
        }
    }

    fn contract_policy() -> Policy {
        Policy {
            safe: Address::from(SAFE),
            chain_id: U256::from(1u64),
            allow: vec![AllowRule {
                to: Address::from(TOKEN),
                call: vec![unbounded_call("transfer(address,uint256)")],
                max_value: U256::from(100u64),
                operation: Operation::Call,
            }],
            owner_management: OwnerMgmt::default(),
            refunds: None,
            typed_data: Vec::new(),
        }
    }

    /// The happy path and every fail-closed branch, plus the guarded owner-rotation allow —
    /// the non-trivial policy logic this module exists to enforce. A call with no selector is
    /// refused HERE, by the policy, which is what keeps a bare ETH transfer unsignable.
    #[test]
    fn each_deny_branch_and_rotation_allow() {
        let p = contract_policy();
        assert!(evaluate(&base_intent(), &p).is_ok());

        let mut i = base_intent();
        i.safe = Address::from([0x99; 20]);
        assert!(matches!(
            evaluate(&i, &p),
            Err(PolicyDenied::SafeMismatch { .. })
        ));

        let mut i = base_intent();
        i.chain_id = U256::from(10u64);
        assert!(matches!(
            evaluate(&i, &p),
            Err(PolicyDenied::ChainMismatch { .. })
        ));

        let mut i = base_intent();
        i.to = Address::from([0x33; 20]);
        assert!(matches!(
            evaluate(&i, &p),
            Err(PolicyDenied::Call(CallDenied::ToNotAllowed { .. }))
        ));

        let mut i = base_intent();
        i.operation = Operation::Delegatecall;
        assert!(matches!(
            evaluate(&i, &p),
            Err(PolicyDenied::Call(CallDenied::OperationNotAllowed { .. }))
        ));

        let mut i = base_intent();
        i.data = Bytes::from(vec![0x00, 0x01]);
        assert!(matches!(
            evaluate(&i, &p),
            Err(PolicyDenied::Call(CallDenied::NoSelector))
        ));

        let mut i = base_intent();
        i.data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(matches!(
            evaluate(&i, &p),
            Err(PolicyDenied::Call(CallDenied::SignatureNotAllowed { .. }))
        ));

        let mut i = base_intent();
        i.value = U256::from(101u64);
        assert!(matches!(
            evaluate(&i, &p),
            Err(PolicyDenied::Call(CallDenied::ValueTooHigh { .. }))
        ));

        // Rotation against the Safe itself is denied unless explicitly enabled, and even then
        // it may not move native value: `max_value` defaults to zero for a self-call.
        let swap = unbounded_call(OWNER_MGMT[0]);
        let mut rot = base_intent();
        rot.to = Address::from(SAFE);
        rot.data = Bytes::from(swap.signature.selector().to_vec());
        assert!(matches!(
            evaluate(&rot, &p),
            Err(PolicyDenied::OwnerManagementNotAllowed)
        ));

        let mut allow_rot = p.clone();
        allow_rot.owner_management = OwnerMgmt {
            allow: true,
            call: vec![swap],
            max_value: U256::ZERO,
        };
        assert!(evaluate(&rot, &allow_rot).is_ok());

        let mut paid_rot = rot.clone();
        paid_rot.value = U256::from(1u64);
        assert!(matches!(
            evaluate(&paid_rot, &allow_rot),
            Err(PolicyDenied::OwnerManagementValueTooHigh { .. })
        ));

        let mut not_rotation = rot;
        not_rotation.data = Bytes::from(TRANSFER.to_vec());
        assert!(
            matches!(
                evaluate(&not_rotation, &allow_rot),
                Err(PolicyDenied::OwnerManagementNotAllowed)
            ),
            "a self-call outside the rotation set is never owner management"
        );
    }

    /// Gas-refund fields drain funds independently of (to,value,data): any refund activity is
    /// denied without a `[refunds]` opt-in, and each token/receiver/cap breach is its own deny.
    #[test]
    fn refund_drain_fail_closed_then_opt_in() {
        let no_refunds = contract_policy();
        assert!(evaluate(&base_intent(), &no_refunds).is_ok());

        let token = Address::from([0x44u8; 20]);
        let attacker = Address::from([0x55u8; 20]);
        let mut drain = base_intent();
        drain.gas_price = U256::from(1u64);
        drain.gas_token = token;
        drain.refund_receiver = attacker;
        drain.base_gas = U256::from(1_000_000u64);
        assert!(matches!(
            evaluate(&drain, &no_refunds),
            Err(PolicyDenied::Refund(RefundDenied::RefundNotAllowed))
        ));
        let mut base_only = base_intent();
        base_only.base_gas = U256::from(1u64);
        let mut safe_only = base_intent();
        safe_only.safe_tx_gas = U256::from(1u64);
        for gas_only in [base_only, safe_only] {
            assert!(matches!(
                evaluate(&gas_only, &no_refunds),
                Err(PolicyDenied::Refund(RefundDenied::RefundNotAllowed))
            ));
        }

        let mut opt_in = contract_policy();
        opt_in.refunds = Some(RefundPolicy {
            gas_tokens: vec![token],
            refund_receivers: vec![attacker],
            max_gas_price: U256::from(1u64),
            max_base_gas: U256::from(1_000_000u64),
            max_safe_tx_gas: U256::ZERO,
        });
        assert!(evaluate(&drain, &opt_in).is_ok());

        let mut bad_token = drain.clone();
        bad_token.gas_token = Address::from([0x66u8; 20]);
        assert!(matches!(
            evaluate(&bad_token, &opt_in),
            Err(PolicyDenied::Refund(
                RefundDenied::GasTokenNotAllowed { .. }
            ))
        ));

        let mut bad_receiver = drain.clone();
        bad_receiver.refund_receiver = Address::from([0x77u8; 20]);
        assert!(matches!(
            evaluate(&bad_receiver, &opt_in),
            Err(PolicyDenied::Refund(
                RefundDenied::RefundReceiverNotAllowed { .. }
            ))
        ));

        let mut over_price = drain.clone();
        over_price.gas_price = U256::from(2u64);
        assert!(matches!(
            evaluate(&over_price, &opt_in),
            Err(PolicyDenied::Refund(RefundDenied::GasPriceTooHigh { .. }))
        ));

        let mut over_base = drain.clone();
        over_base.base_gas = U256::from(1_000_001u64);
        assert!(matches!(
            evaluate(&over_base, &opt_in),
            Err(PolicyDenied::Refund(RefundDenied::BaseGasTooHigh { .. }))
        ));

        let mut over_safe_tx = drain;
        over_safe_tx.safe_tx_gas = U256::from(1u64);
        assert!(matches!(
            evaluate(&over_safe_tx, &opt_in),
            Err(PolicyDenied::Refund(RefundDenied::SafeTxGasTooHigh { .. }))
        ));
    }

    /// `refundReceiver = 0x0` is the one refund address a Safe does not pay literally: it sends
    /// that refund to `tx.origin`, whoever submits the transaction, while the sheet renders the
    /// zero address. A policy may therefore not allow-list it, and the refusal is at PARSE so no
    /// such term reaches a prompt. `gasToken = 0x0` is the chain's own asset and stays legal.
    #[test]
    fn a_refund_receiver_of_zero_is_refused_when_the_policy_is_parsed() {
        let with_receiver = |receiver: &str| {
            format!(
                "safe = \"0x1111111111111111111111111111111111111111\"\nchain_id = 1\n\n\
                 [refunds]\ngas_tokens = [\"0x0000000000000000000000000000000000000000\"]\n\
                 refund_receivers = [\"{receiver}\"]\nmax_gas_price = \"1\"\n\
                 max_base_gas = \"1\"\nmax_safe_tx_gas = \"1\"\n"
            )
        };
        assert!(matches!(
            Policy::parse(with_receiver("0x0000000000000000000000000000000000000000").as_bytes()),
            Err(PolicyErr::RefundReceiverResolvesToOrigin { field })
                if field == "refunds.refund_receivers"
        ));
        let named =
            Policy::parse(with_receiver("0x5555555555555555555555555555555555555555").as_bytes())
                .expect("a named receiver is a receiver a human can read");

        let mut paying = base_intent();
        paying.gas_price = U256::from(1u64);
        paying.refund_receiver = Address::ZERO;
        assert!(
            matches!(
                match_refunds(named.policy.refunds.as_ref(), &paying),
                Err(RefundDenied::RefundReceiverNotAllowed { .. })
            ),
            "an intent refunding to tx.origin can no longer match any allowance"
        );
    }

    /// chain_id is a mandatory pin: the exact scripts/demo.sh policy still loads, but a policy
    /// omitting chain_id fails to load (= deny), closing the cross-chain replay hole. A policy
    /// still written in the retired `selectors` language fails to load for the same reason,
    /// naming the term it does not understand.
    #[test]
    fn chain_id_is_required_to_load() {
        let demo = concat!(
            "safe = \"0x1111111111111111111111111111111111111111\"\n",
            "chain_id = 1\n",
            "\n",
            "[[allow]]\n",
            "to = \"0x2222222222222222222222222222222222222222\"\n",
            "max_value = \"0\"\n",
            "operation = \"call\"\n",
            "\n",
            "  [[allow.call]]\n",
            "  signature = \"transfer(address,uint256)\"\n",
            "\n",
            "    [[allow.call.arg]]\n",
            "    at = 0\n",
            "    name = \"to\"\n",
            "    rule = { one_of = { addresses = \
             [\"0x3333333333333333333333333333333333333333\"] } }\n",
            "\n",
            "    [[allow.call.arg]]\n",
            "    at = 1\n",
            "    name = \"amount\"\n",
            "    rule = { max = { max = \"1000000000\", amount_of = \
             \"0x2222222222222222222222222222222222222222\" } }\n",
        );
        let p: Policy = toml::from_str(demo).expect("demo policy must load");
        assert_eq!(p.chain_id, U256::from(1u64));
        assert_eq!(p.allow.len(), 1);
        assert_eq!(
            p.allow[0].call[0].signature.canonical(),
            "transfer(address,uint256)"
        );

        let without_chain = "safe = \"0x1111111111111111111111111111111111111111\"\n";
        assert!(toml::from_str::<Policy>(without_chain).is_err());

        let retired = concat!(
            "safe = \"0x1111111111111111111111111111111111111111\"\n",
            "chain_id = 1\n",
            "\n",
            "[[allow]]\n",
            "to = \"0x2222222222222222222222222222222222222222\"\n",
            "selectors = [\"0xa9059cbb\"]\n",
            "max_value = \"0\"\n",
            "operation = \"call\"\n",
        );
        let refused = toml::from_str::<Policy>(retired).expect_err("selectors is retired");
        assert!(
            refused.to_string().contains("selectors"),
            "the refusal must name the term: {refused}"
        );
    }

    fn write_policy(dir: &Path, rules: &str) -> std::path::PathBuf {
        let policies = dir.join("policies");
        std::fs::create_dir_all(&policies).expect("make the policy dir");
        std::fs::write(
            policies.join("K.toml"),
            format!("safe = \"0x1111111111111111111111111111111111111111\"\nchain_id = 1\n{rules}"),
        )
        .expect("write the policy");
        dir.to_path_buf()
    }

    /// Two rules for one destination are only meaningful when they differ in operation, and then
    /// each must actually govern its own: matching on `to` alone made the second rule dead. A
    /// second rule that cannot differ — the same `(to, operation)` — is refused at load, so an
    /// operator can never write one that silently never fires.
    #[test]
    fn same_destination_rules_split_by_operation_and_duplicates_die_at_load() {
        let dir = std::env::temp_dir().join("hot_cheese_policy_rule_test");
        let _ = std::fs::remove_dir_all(&dir);
        let rule = |operation: &str, signature: &str| {
            format!(
                "[[allow]]\nto = \"0x2222222222222222222222222222222222222222\"\noperation = \
                 \"{operation}\"\n\n  [[allow.call]]\n  signature = \"{signature}\"\n\n    \
                 [[allow.call.arg]]\n    at = 0\n    name = \"a\"\n    rule = \"unbounded\"\n\n    \
                 [[allow.call.arg]]\n    at = 1\n    name = \"b\"\n    rule = \"unbounded\"\n\n"
            )
        };
        let split = format!(
            "{}{}",
            rule("delegatecall", "approve(address,uint256)"),
            rule("call", "transfer(address,uint256)")
        );
        let store = write_policy(&dir, &split);
        let loaded = Policy::load(&store, "K").expect("split rules load");

        let call = base_intent();
        assert!(
            evaluate(&call, &loaded.policy).is_ok(),
            "the second rule for this destination must still fire"
        );
        let mut delegate = base_intent();
        delegate.operation = Operation::Delegatecall;
        delegate.data = Bytes::from(vec![0x09, 0x5e, 0xa7, 0xb3]);
        assert!(evaluate(&delegate, &loaded.policy).is_ok());

        let mut crossed = base_intent();
        crossed.data = Bytes::from(vec![0x09, 0x5e, 0xa7, 0xb3]);
        assert!(
            matches!(
                evaluate(&crossed, &loaded.policy),
                Err(PolicyDenied::Call(CallDenied::SignatureNotAllowed { .. }))
            ),
            "each rule keeps its own declared signatures"
        );

        let duplicate = format!(
            "{}{}",
            rule("call", "transfer(address,uint256)"),
            rule("call", "approve(address,uint256)")
        );
        let store = write_policy(&dir, &duplicate);
        assert!(matches!(
            Policy::load(&store, "K"),
            Err(PolicyErr::DuplicateRule { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_lookup_never_accepts_a_path_as_a_key_name() {
        let dir = std::env::temp_dir().join("hot_cheese_policy_name_boundary");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("policies")).unwrap();
        std::fs::write(dir.join("OUTSIDE.toml"), b"not a policy").unwrap();
        assert!(matches!(
            Policy::load(&dir, "../OUTSIDE"),
            Err(PolicyErr::InvalidName { .. })
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
