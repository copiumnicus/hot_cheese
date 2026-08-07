//! Fail-closed, per-key signing policy loaded from `<store>/policies/<name>.toml`.
use crate::adapter::OWNER_MGMT;
use crate::intent::{Operation, SafeTxIntent};
use alloy_primitives::{Address, FixedBytes, B256, U256};
use err_mac::create_err_with_impls;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;

/// One key's policy: which Safe, the mandatory chain pin, allowed contract calls, whether
/// owner/threshold rotations are permitted, and any opt-in refund allowance.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub safe: Address,
    #[serde(with = "crate::wire::u256")]
    pub chain_id: U256,
    #[serde(default)]
    pub allow: Vec<AllowRule>,
    #[serde(default)]
    pub owner_management: OwnerMgmt,
    #[serde(default)]
    pub refunds: Option<RefundPolicy>,
}

/// Opt-in allowance for Safe gas-refund fields: only when present may an intent carry any
/// refund activity, and then only within these token/receiver allow-lists and gas ceilings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundPolicy {
    /// Gas tokens a refund may be paid in (`0x0` denotes native ETH).
    #[serde(default)]
    pub gas_tokens: Vec<Address>,
    /// Addresses a refund may be paid to.
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

/// A permitted destination: its selectors, a value ceiling, and the required operation. A
/// term this struct does not name is a refusal to load, in a policy file and in an adapter
/// manifest alike: an unrecognised rule term is something the daemon does not enforce.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRule {
    pub to: Address,
    pub selectors: Vec<FixedBytes<4>>,
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
    pub selectors: Vec<FixedBytes<4>>,
}

create_err_with_impls!(
    #[derive(Debug)]
    pub CallDenied,
    NoSelector
    ;
    ToNotAllowed { to: Address },
    OperationNotAllowed { rule: Operation, got: Operation },
    SelectorNotAllowed { selector: FixedBytes<4> },
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
    ChainMismatch { expected: U256, got: U256 }
);

create_err_with_impls!(
    #[derive(Debug)]
    pub PolicyErr,
    Denied(PolicyDenied),
    Io(std::io::Error),
    Toml(toml::de::Error)
    ;
    DuplicateRule { to: Address, operation: Operation }
);

/// A policy and the digest of the exact bytes it was parsed from.
pub struct LoadedPolicy {
    /// The parsed rules.
    pub policy: Policy,
    /// SHA-256 of the file bytes `policy` came from.
    pub digest: B256,
}

impl Policy {
    /// Load `<store>/policies/<name>.toml`. A missing file is an error (deny by default).
    /// The digest is of the bytes actually read, so it names the policy in force for the
    /// signature this load is serving — a policy edited afterwards is a different digest.
    pub fn load(store: &Path, name: &str) -> Result<LoadedPolicy, PolicyErr> {
        let path = store.join("policies").join(format!("{name}.toml"));
        let text = std::fs::read_to_string(&path)?;
        let policy: Policy = toml::from_str(&text)?;
        no_duplicate_rules(&policy.allow)?;
        Ok(LoadedPolicy {
            digest: B256::from_slice(&Sha256::digest(text.as_bytes())),
            policy,
        })
    }
}

/// Refuse an allow-list holding two rules for the same destination AND operation. [`match_call`]
/// takes the first such rule, so a later duplicate could never fire: an operator who wrote one
/// believes in a rule the daemon does not enforce. Both a policy file and an adapter manifest's
/// `grants.calls` are checked with this, at load, before anything can be evaluated against them.
pub(crate) fn no_duplicate_rules(rules: &[AllowRule]) -> Result<(), PolicyErr> {
    for (i, rule) in rules.iter().enumerate() {
        for other in &rules[i + 1..] {
            if other.to == rule.to && other.operation == rule.operation {
                return Err(PolicyErr::DuplicateRule {
                    to: rule.to,
                    operation: rule.operation,
                });
            }
        }
    }
    Ok(())
}

fn selector4(i: &SafeTxIntent) -> Option<[u8; 4]> {
    i.data.get(..4).map(|s| {
        let mut a = [0u8; 4];
        a.copy_from_slice(s);
        a
    })
}

/// Match an intent against a list of [`AllowRule`]s: the rule is selected by destination AND
/// operation together, so two rules for one destination each govern their own operation. A
/// per-key policy's `allow` and an adapter manifest's `grants.calls` are both lists of these,
/// and this is the only code that reads one — an adapter cannot be granted a call shape the
/// policy language cannot express.
pub fn match_call(rules: &[AllowRule], i: &SafeTxIntent) -> Result<(), CallDenied> {
    let mut matched = None;
    let mut other_operation = None;
    for rule in rules {
        if rule.to != i.to {
            continue;
        }
        if rule.operation == i.operation {
            matched = Some(rule);
            break;
        }
        other_operation = Some(rule.operation);
    }
    let Some(rule) = matched else {
        return match other_operation {
            Some(allowed) => Err(CallDenied::OperationNotAllowed {
                rule: allowed,
                got: i.operation,
            }),
            None => Err(CallDenied::ToNotAllowed { to: i.to }),
        };
    };
    let Some(sel) = selector4(i) else {
        return Err(CallDenied::NoSelector);
    };
    if !rule.selectors.contains(&FixedBytes::from(sel)) {
        return Err(CallDenied::SelectorNotAllowed {
            selector: FixedBytes::from(sel),
        });
    }
    if i.value > rule.max_value {
        return Err(CallDenied::ValueTooHigh {
            value: i.value,
            max: rule.max_value,
        });
    }
    Ok(())
}

/// Match an intent's gas-refund fields against an allowance. An absent allowance denies any
/// refund activity at all, which is why an intent that leaves all three refund fields at their
/// zero value passes without one. A per-key policy's `refunds` and an adapter grant's `refunds`
/// are both allowances, and this is the only code that reads one.
pub fn match_refunds(
    allowance: Option<&RefundPolicy>,
    i: &SafeTxIntent,
) -> Result<(), RefundDenied> {
    let quiet = i.gas_price == U256::ZERO
        && i.gas_token == Address::ZERO
        && i.refund_receiver == Address::ZERO;
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

    if i.to == policy.safe {
        let Some(sel) = selector4(i) else {
            return Err(PolicyDenied::NoSelector);
        };
        let allowed = policy.owner_management.allow
            && i.operation == Operation::Call
            && policy
                .owner_management
                .selectors
                .contains(&FixedBytes::from(sel))
            && OWNER_MGMT.contains(&sel);
        if !allowed {
            return Err(PolicyDenied::OwnerManagementNotAllowed);
        }
        return Ok(());
    }

    Ok(match_call(&policy.allow, i)?)
}

#[cfg(test)]
mod tests {
    use super::*;
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
                selectors: vec![FixedBytes::from(TRANSFER)],
                max_value: U256::from(100u64),
                operation: Operation::Call,
            }],
            owner_management: OwnerMgmt::default(),
            refunds: None,
        }
    }

    /// The happy path and every fail-closed branch, plus the guarded owner-rotation allow —
    /// the non-trivial policy logic this module exists to enforce.
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
            Err(PolicyDenied::Call(CallDenied::SelectorNotAllowed { .. }))
        ));

        let mut i = base_intent();
        i.value = U256::from(101u64);
        assert!(matches!(
            evaluate(&i, &p),
            Err(PolicyDenied::Call(CallDenied::ValueTooHigh { .. }))
        ));

        // Rotation against the Safe itself is denied unless explicitly enabled. The
        // selector is taken from the sol!-derived set so the test can't misname it.
        let swap_owner = OWNER_MGMT[0];
        let mut rot = base_intent();
        rot.to = Address::from(SAFE);
        rot.data = Bytes::from(swap_owner.to_vec());
        assert!(matches!(
            evaluate(&rot, &p),
            Err(PolicyDenied::OwnerManagementNotAllowed)
        ));

        let mut allow_rot = p.clone();
        allow_rot.owner_management = OwnerMgmt {
            allow: true,
            selectors: vec![FixedBytes::from(swap_owner)],
        };
        assert!(evaluate(&rot, &allow_rot).is_ok());
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

        let mut over_safe_tx = drain.clone();
        over_safe_tx.safe_tx_gas = U256::from(1u64);
        assert!(matches!(
            evaluate(&over_safe_tx, &opt_in),
            Err(PolicyDenied::Refund(RefundDenied::SafeTxGasTooHigh { .. }))
        ));
    }

    /// chain_id is a mandatory pin: the exact scripts/demo.sh policy (`chain_id = 1`, plus its
    /// allow rule) still loads, but a policy omitting chain_id fails to load (= deny), closing
    /// the cross-chain replay hole.
    #[test]
    fn chain_id_is_required_to_load() {
        let demo = concat!(
            "safe = \"0x1111111111111111111111111111111111111111\"\n",
            "chain_id = 1\n",
            "\n",
            "[[allow]]\n",
            "to = \"0x2222222222222222222222222222222222222222\"\n",
            "selectors = [\"0xa9059cbb\"]\n",
            "max_value = \"0\"\n",
            "operation = \"call\"\n",
        );
        let p: Policy = toml::from_str(demo).expect("demo policy must load");
        assert_eq!(p.chain_id, U256::from(1u64));
        assert_eq!(p.allow.len(), 1);

        let without_chain = "safe = \"0x1111111111111111111111111111111111111111\"\n";
        assert!(toml::from_str::<Policy>(without_chain).is_err());
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
        let split = concat!(
            "[[allow]]\n",
            "to = \"0x2222222222222222222222222222222222222222\"\n",
            "selectors = [\"0xdeadbeef\"]\n",
            "operation = \"delegatecall\"\n",
            "\n",
            "[[allow]]\n",
            "to = \"0x2222222222222222222222222222222222222222\"\n",
            "selectors = [\"0xa9059cbb\"]\n",
            "operation = \"call\"\n",
        );
        let store = write_policy(&dir, split);
        let loaded = Policy::load(&store, "K").expect("split rules load");

        let call = base_intent();
        assert!(
            evaluate(&call, &loaded.policy).is_ok(),
            "the second rule for this destination must still fire"
        );
        let mut delegate = base_intent();
        delegate.operation = Operation::Delegatecall;
        delegate.data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(evaluate(&delegate, &loaded.policy).is_ok());

        let mut crossed = base_intent();
        crossed.data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(
            matches!(
                evaluate(&crossed, &loaded.policy),
                Err(PolicyDenied::Call(CallDenied::SelectorNotAllowed { .. }))
            ),
            "each rule keeps its own selectors"
        );

        let duplicate = concat!(
            "[[allow]]\n",
            "to = \"0x2222222222222222222222222222222222222222\"\n",
            "selectors = [\"0xa9059cbb\"]\n",
            "operation = \"call\"\n",
            "\n",
            "[[allow]]\n",
            "to = \"0x2222222222222222222222222222222222222222\"\n",
            "selectors = [\"0xdeadbeef\"]\n",
            "operation = \"call\"\n",
        );
        let store = write_policy(&dir, duplicate);
        assert!(matches!(
            Policy::load(&store, "K"),
            Err(PolicyErr::DuplicateRule { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
