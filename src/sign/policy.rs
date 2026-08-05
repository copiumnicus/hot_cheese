//! Fail-closed, per-key signing policy loaded from `<store>/policies/<name>.toml`.
use crate::sign::adapter::OWNER_MGMT;
use crate::sign::intent::{Operation, SafeTxIntent};
use alloy_primitives::{Address, FixedBytes, U256};
use err_mac::create_err_with_impls;
use serde::Deserialize;
use std::path::Path;

/// One key's policy: which Safe, the mandatory chain pin, allowed contract calls, whether
/// owner/threshold rotations are permitted, and any opt-in refund allowance.
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub safe: Address,
    #[serde(with = "crate::sign::wire::u256")]
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

/// A permitted destination: its selectors, a value ceiling, and the required operation.
#[derive(Debug, Clone, Deserialize)]
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
pub struct OwnerMgmt {
    pub allow: bool,
    pub selectors: Vec<FixedBytes<4>>,
}

create_err_with_impls!(
    #[derive(Debug)]
    pub PolicyDenied,
    NoSelector,
    OwnerManagementNotAllowed,
    RefundNotAllowed
    ;
    SafeMismatch { expected: Address, got: Address },
    ChainMismatch { expected: U256, got: U256 },
    ToNotAllowed { to: Address },
    OperationNotAllowed { rule: Operation, got: Operation },
    SelectorNotAllowed { selector: FixedBytes<4> },
    ValueTooHigh { value: U256, max: U256 },
    GasTokenNotAllowed { gas_token: Address },
    RefundReceiverNotAllowed { refund_receiver: Address },
    GasPriceTooHigh { gas_price: U256, max: U256 },
    BaseGasTooHigh { base_gas: U256, max: U256 },
    SafeTxGasTooHigh { safe_tx_gas: U256, max: U256 }
);

create_err_with_impls!(
    #[derive(Debug)]
    pub PolicyErr,
    Denied(PolicyDenied),
    Io(std::io::Error),
    Toml(toml::de::Error)
    ;
);

impl Policy {
    /// Load `<store>/policies/<name>.toml`. A missing file is an error (deny by default).
    pub fn load(store: &Path, name: &str) -> Result<Self, PolicyErr> {
        let path = store.join("policies").join(format!("{name}.toml"));
        let text = std::fs::read_to_string(&path)?;
        Ok(toml::from_str(&text)?)
    }
}

fn selector4(i: &SafeTxIntent) -> Option<[u8; 4]> {
    i.data.get(..4).map(|s| {
        let mut a = [0u8; 4];
        a.copy_from_slice(s);
        a
    })
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

    let has_refund = i.gas_price != U256::ZERO
        || i.gas_token != Address::ZERO
        || i.refund_receiver != Address::ZERO;
    if has_refund {
        let Some(refunds) = policy.refunds.as_ref() else {
            return Err(PolicyDenied::RefundNotAllowed);
        };
        if !refunds.gas_tokens.contains(&i.gas_token) {
            return Err(PolicyDenied::GasTokenNotAllowed {
                gas_token: i.gas_token,
            });
        }
        if !refunds.refund_receivers.contains(&i.refund_receiver) {
            return Err(PolicyDenied::RefundReceiverNotAllowed {
                refund_receiver: i.refund_receiver,
            });
        }
        if i.gas_price > refunds.max_gas_price {
            return Err(PolicyDenied::GasPriceTooHigh {
                gas_price: i.gas_price,
                max: refunds.max_gas_price,
            });
        }
        if i.base_gas > refunds.max_base_gas {
            return Err(PolicyDenied::BaseGasTooHigh {
                base_gas: i.base_gas,
                max: refunds.max_base_gas,
            });
        }
        if i.safe_tx_gas > refunds.max_safe_tx_gas {
            return Err(PolicyDenied::SafeTxGasTooHigh {
                safe_tx_gas: i.safe_tx_gas,
                max: refunds.max_safe_tx_gas,
            });
        }
    }

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

    let rule = policy
        .allow
        .iter()
        .find(|r| r.to == i.to)
        .ok_or(PolicyDenied::ToNotAllowed { to: i.to })?;
    if rule.operation != i.operation {
        return Err(PolicyDenied::OperationNotAllowed {
            rule: rule.operation,
            got: i.operation,
        });
    }
    let Some(sel) = selector4(i) else {
        return Err(PolicyDenied::NoSelector);
    };
    if !rule.selectors.contains(&FixedBytes::from(sel)) {
        return Err(PolicyDenied::SelectorNotAllowed {
            selector: FixedBytes::from(sel),
        });
    }
    if i.value > rule.max_value {
        return Err(PolicyDenied::ValueTooHigh {
            value: i.value,
            max: rule.max_value,
        });
    }
    Ok(())
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
            Err(PolicyDenied::ToNotAllowed { .. })
        ));

        let mut i = base_intent();
        i.operation = Operation::Delegatecall;
        assert!(matches!(
            evaluate(&i, &p),
            Err(PolicyDenied::OperationNotAllowed { .. })
        ));

        let mut i = base_intent();
        i.data = Bytes::from(vec![0x00, 0x01]);
        assert!(matches!(evaluate(&i, &p), Err(PolicyDenied::NoSelector)));

        let mut i = base_intent();
        i.data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(matches!(
            evaluate(&i, &p),
            Err(PolicyDenied::SelectorNotAllowed { .. })
        ));

        let mut i = base_intent();
        i.value = U256::from(101u64);
        assert!(matches!(
            evaluate(&i, &p),
            Err(PolicyDenied::ValueTooHigh { .. })
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
            Err(PolicyDenied::RefundNotAllowed)
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
            Err(PolicyDenied::GasTokenNotAllowed { .. })
        ));

        let mut bad_receiver = drain.clone();
        bad_receiver.refund_receiver = Address::from([0x77u8; 20]);
        assert!(matches!(
            evaluate(&bad_receiver, &opt_in),
            Err(PolicyDenied::RefundReceiverNotAllowed { .. })
        ));

        let mut over_price = drain.clone();
        over_price.gas_price = U256::from(2u64);
        assert!(matches!(
            evaluate(&over_price, &opt_in),
            Err(PolicyDenied::GasPriceTooHigh { .. })
        ));

        let mut over_base = drain.clone();
        over_base.base_gas = U256::from(1_000_001u64);
        assert!(matches!(
            evaluate(&over_base, &opt_in),
            Err(PolicyDenied::BaseGasTooHigh { .. })
        ));

        let mut over_safe_tx = drain.clone();
        over_safe_tx.safe_tx_gas = U256::from(1u64);
        assert!(matches!(
            evaluate(&over_safe_tx, &opt_in),
            Err(PolicyDenied::SafeTxGasTooHigh { .. })
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
}
