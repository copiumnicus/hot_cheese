//! Adapter manifests: what one out-of-process adapter may ask this daemon to sign.
//!
//! A manifest lives at `<home>/adapters/<id>.toml` — the HOME dir, never the store. The store
//! is pushed to backup hosts and replicated by `bootstrap-from`; adapter trust is per-machine
//! local config and must not travel, so a bootstrapped machine starts with NO adapters, which
//! is the correct fail-closed default.
//!
//! A manifest can only ever NARROW the per-key policy, and only for requests carrying that
//! adapter's provenance. [`narrows`] is checked for every grant at `serve` startup, so a
//! manifest claiming more than `<store>/policies/<KEY>.toml` grants is a startup failure and
//! not a silent intersection. At request time both [`evaluate`] and `policy::evaluate` run
//! before any prompt: both must pass, there is no union and no override.
use crate::grant::IntentKind;
use crate::intent::{Operation, SafeTxIntent, TypedDataIntent};
use crate::policy::{
    check_refunds, match_call, match_refunds, no_duplicate_rules, AllowRule, CallDenied, Policy,
    RefundDenied, RefundPolicy,
};
use crate::schema::{CallRule, FieldRule, Site};
use alloy_primitives::{Address, B256, U256};
use err_mac::create_err_with_impls;
use hc_core::config::{adapter_socket, AdapterPin, Config};
use hc_core::is_valid_string_name;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

/// The only manifest schema this build understands.
pub const SCHEMA: &str = "hotcheese.adapter/v1";
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_GRANTS: usize = 64;
const MAX_GRANT_VALUES: usize = 64;

/// One adapter's whole authority. An unknown key anywhere in here is a refusal, not a
/// silently dropped term: a manifest the daemon does not fully understand grants nothing.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Schema tag; must be [`SCHEMA`].
    pub schema: String,
    /// Adapter id, which must be the one `config.toml` pinned.
    pub id: String,
    /// Per-keystore authority; no grant for a key means this adapter may not touch it.
    #[serde(default)]
    pub grants: Vec<Grant>,
}

/// What the adapter may ask for with one keystore.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// Keystore this grant is about.
    pub key: String,
    /// Intent shapes the adapter may submit.
    pub intent_kinds: Vec<IntentKind>,
    /// Chains it may sign for, decimal or `0x` hex; each must be the policy's chain.
    #[serde(with = "hc_core::wire::u256_list")]
    pub chain_ids: Vec<U256>,
    /// Safes it may sign for; each must be the policy's Safe.
    pub safes: Vec<Address>,
    /// Destinations, in the same rule language `policies/<KEY>.toml` uses.
    #[serde(default)]
    pub calls: Vec<AllowRule>,
    /// EIP-712 schema names it may name, each of which the policy must already declare.
    #[serde(default)]
    pub typed_data: Vec<String>,
    /// Gas-refund allowance, which may only narrow the policy's; absent means no refunds.
    #[serde(default)]
    pub refunds: Option<RefundPolicy>,
}

create_err_with_impls!(
    #[derive(Debug)]
    pub Widened,
    RefundsNotInPolicy
    ;
    Safe { safe: Address },
    Chain { chain_id: U256 },
    Call { to: Address, operation: Operation },
    Signature { to: Address, signature: String },
    Arg { to: Address, signature: String, at: usize },
    Schema { schema: String },
    MaxValue { to: Address, max_value: U256 },
    OwnerManagement { safe: Address },
    GasToken { gas_token: Address },
    RefundReceiver { refund_receiver: Address },
    MaxGasPrice { max_gas_price: U256 },
    MaxBaseGas { max_base_gas: U256 },
    MaxSafeTxGas { max_safe_tx_gas: U256 }
);

create_err_with_impls!(
    #[derive(Debug)]
    pub ManifestDenied,
    Call(CallDenied),
    Refund(RefundDenied)
    ;
    KeyNotGranted { key: String },
    IntentKindNotGranted { kind: IntentKind },
    SafeNotGranted { safe: Address },
    ChainNotGranted { chain_id: U256 },
    SchemaNotGranted { schema: String },
    OwnerManagementNotDelegable { safe: Address }
);

create_err_with_impls!(
    #[derive(Debug)]
    pub ManifestErr,
    Hex(hex::FromHexError),
    Io(std::io::Error),
    Policy(crate::policy::PolicyErr),
    Toml(toml::de::Error),
    Utf8(std::str::Utf8Error)
    ;
    InvalidId { id: String },
    InvalidKey { id: String, key: String },
    PinNotADigest { id: String, sha256: String },
    PinMismatch { id: String, pinned: B256, found: B256 },
    IdMismatch { pinned: String, declared: String },
    UnknownSchema { id: String, schema: String },
    TooLarge { size: u64, max: u64 },
    DuplicateId { id: String },
    TooManyGrants { id: String, found: usize, max: usize },
    DuplicateGrant { id: String, key: String },
    InvalidGrantField { id: String, key: String, field: String, reason: String },
    Widens { adapter: String, key: String, source: Widened }
);

/// A manifest, the digest of the exact bytes it was parsed from, and where those bytes live.
#[derive(Debug)]
pub struct LoadedManifest {
    /// The parsed authority.
    pub manifest: Manifest,
    /// SHA-256 of the file bytes, which `config.toml` pinned and a grant is bound to.
    pub digest: B256,
    /// The manifest file this was read from.
    pub path: PathBuf,
}

impl LoadedManifest {
    /// The one socket whose connections carry this adapter's provenance.
    pub fn socket(&self) -> PathBuf {
        adapter_socket(&self.manifest.id)
    }

    /// Refuse the whole manifest unless every grant narrows the key's policy. Loud beats
    /// silently intersecting: a manifest broader than policy means the operator believes
    /// something policy does not grant, and hiding that until an incident is the failure mode.
    pub fn check(&self, store: &Path) -> Result<(), ManifestErr> {
        for grant in &self.manifest.grants {
            let loaded = Policy::load(store, &grant.key)?;
            if let Err(source) = narrows(grant, &loaded.policy) {
                return Err(ManifestErr::Widens {
                    adapter: self.manifest.id.clone(),
                    key: grant.key.clone(),
                    source,
                });
            }
        }
        Ok(())
    }
}

/// Read the pinned manifest: read bytes, hash them, compare to the pin, and only THEN parse.
/// A mismatch means the file on disk is not the one the operator approved, so nothing about
/// its contents is trusted enough to parse.
pub fn load_pinned(pin: &AdapterPin) -> Result<LoadedManifest, ManifestErr> {
    if !is_valid_string_name(&pin.id) {
        return Err(ManifestErr::InvalidId { id: pin.id.clone() });
    }
    let pinned = hex::decode(&pin.sha256)?;
    if pinned.len() != B256::len_bytes() {
        return Err(ManifestErr::PinNotADigest {
            id: pin.id.clone(),
            sha256: pin.sha256.clone(),
        });
    }
    let path = pin.manifest_path();
    let mut bytes = Vec::new();
    hc_core::open_regular_file(&path)?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(ManifestErr::TooLarge {
            size: bytes.len() as u64,
            max: MAX_MANIFEST_BYTES,
        });
    }
    let found = B256::from_slice(&Sha256::digest(&bytes));
    if found != B256::from_slice(&pinned) {
        return Err(ManifestErr::PinMismatch {
            id: pin.id.clone(),
            pinned: B256::from_slice(&pinned),
            found,
        });
    }

    let manifest: Manifest = toml::from_str(std::str::from_utf8(&bytes)?)?;
    if manifest.schema != SCHEMA {
        return Err(ManifestErr::UnknownSchema {
            id: pin.id.clone(),
            schema: manifest.schema,
        });
    }
    if manifest.id != pin.id {
        return Err(ManifestErr::IdMismatch {
            pinned: pin.id.clone(),
            declared: manifest.id,
        });
    }
    if manifest.grants.len() > MAX_GRANTS {
        return Err(ManifestErr::TooManyGrants {
            id: manifest.id.clone(),
            found: manifest.grants.len(),
            max: MAX_GRANTS,
        });
    }
    for (at, grant) in manifest.grants.iter().enumerate() {
        if !hc_core::is_valid_key_name(&grant.key) {
            return Err(ManifestErr::InvalidKey {
                id: manifest.id.clone(),
                key: grant.key.clone(),
            });
        }
        if manifest.grants[at + 1..]
            .iter()
            .any(|other| other.key == grant.key)
        {
            return Err(ManifestErr::DuplicateGrant {
                id: manifest.id.clone(),
                key: grant.key.clone(),
            });
        }
        check_grant(grant, &manifest.id)?;
        no_duplicate_rules(&grant.calls)?;
        if let Some(refunds) = &grant.refunds {
            check_refunds(refunds)?;
        }
    }
    Ok(LoadedManifest {
        manifest,
        digest: found,
        path,
    })
}

fn invalid_grant(id: &str, grant: &Grant, field: &str, reason: impl Into<String>) -> ManifestErr {
    ManifestErr::InvalidGrantField {
        id: id.to_string(),
        key: grant.key.clone(),
        field: field.to_string(),
        reason: reason.into(),
    }
}

fn check_list<T: PartialEq + std::fmt::Debug>(
    values: &[T],
    id: &str,
    grant: &Grant,
    field: &str,
) -> Result<(), ManifestErr> {
    if values.is_empty() {
        return Err(invalid_grant(id, grant, field, "must not be empty"));
    }
    if values.len() > MAX_GRANT_VALUES {
        return Err(invalid_grant(
            id,
            grant,
            field,
            format!(
                "has {} entries; maximum is {MAX_GRANT_VALUES}",
                values.len()
            ),
        ));
    }
    for (at, value) in values.iter().enumerate() {
        if values[at + 1..].contains(value) {
            return Err(invalid_grant(
                id,
                grant,
                field,
                format!("contains duplicate {value:?}"),
            ));
        }
    }
    Ok(())
}

fn check_grant(grant: &Grant, id: &str) -> Result<(), ManifestErr> {
    check_list(&grant.intent_kinds, id, grant, "intent_kinds")?;
    check_list(&grant.chain_ids, id, grant, "chain_ids")?;
    let safe_tx = grant.intent_kinds.contains(&IntentKind::SafeTx);
    let typed_data = grant.intent_kinds.contains(&IntentKind::TypedData);

    match (safe_tx, grant.safes.is_empty(), grant.calls.is_empty()) {
        (true, true, _) => return Err(invalid_grant(id, grant, "safes", "safe_tx needs a Safe")),
        (true, _, true) => return Err(invalid_grant(id, grant, "calls", "safe_tx needs a call")),
        (false, false, _) => {
            return Err(invalid_grant(
                id,
                grant,
                "safes",
                "has entries without the safe_tx intent kind",
            ))
        }
        (false, _, false) => {
            return Err(invalid_grant(
                id,
                grant,
                "calls",
                "has entries without the safe_tx intent kind",
            ))
        }
        _ => {}
    }
    if safe_tx {
        check_list(&grant.safes, id, grant, "safes")?;
    }
    if !safe_tx && grant.refunds.is_some() {
        return Err(invalid_grant(
            id,
            grant,
            "refunds",
            "is present without the safe_tx intent kind",
        ));
    }

    match (typed_data, grant.typed_data.is_empty()) {
        (true, true) => {
            return Err(invalid_grant(
                id,
                grant,
                "typed_data",
                "typed_data needs a schema name",
            ))
        }
        (false, false) => {
            return Err(invalid_grant(
                id,
                grant,
                "typed_data",
                "has entries without the typed_data intent kind",
            ))
        }
        (true, false) => check_list(&grant.typed_data, id, grant, "typed_data")?,
        (false, true) => {}
    }
    for schema in &grant.typed_data {
        if !is_valid_string_name(schema) {
            return Err(invalid_grant(
                id,
                grant,
                "typed_data",
                format!("invalid schema name {schema:?}"),
            ));
        }
    }
    Ok(())
}

/// Every adapter `config.toml` pins, loaded, pin-checked and intersected with the policies in
/// force. `serve` calls this before it binds anything: any failure here is a refusal to start.
pub fn load_all(config: &Config) -> Result<Vec<LoadedManifest>, ManifestErr> {
    let store = config.store_path();
    let mut loaded: Vec<LoadedManifest> = Vec::with_capacity(config.adapters.len());
    for pin in &config.adapters {
        for other in &loaded {
            if other.manifest.id == pin.id {
                return Err(ManifestErr::DuplicateId { id: pin.id.clone() });
            }
        }
        let manifest = load_pinned(pin)?;
        manifest.check(&store)?;
        loaded.push(manifest);
    }
    Ok(loaded)
}

/// The startup intersection: `grant` may only narrow `policy`. Policy is the ceiling, so every
/// safe, chain, call rule and refund term the adapter claims must already be granted by the
/// policy file, and owner/threshold rotation is never delegable at all — that call stays
/// human-and-policy. A grant with no `refunds` term takes no refund allowance at all.
pub fn narrows(grant: &Grant, policy: &Policy) -> Result<(), Widened> {
    for safe in &grant.safes {
        if *safe != policy.safe {
            return Err(Widened::Safe { safe: *safe });
        }
    }
    for chain_id in &grant.chain_ids {
        if *chain_id != policy.chain_id {
            return Err(Widened::Chain {
                chain_id: *chain_id,
            });
        }
    }
    for rule in &grant.calls {
        if rule.to == policy.safe {
            return Err(Widened::OwnerManagement { safe: policy.safe });
        }
        let allowed = policy
            .allow
            .iter()
            .find(|r| r.to == rule.to && r.operation == rule.operation)
            .ok_or(Widened::Call {
                to: rule.to,
                operation: rule.operation,
            })?;
        for call in &rule.call {
            let permitted = allowed
                .call
                .iter()
                .find(|c| c.signature.canonical() == call.signature.canonical())
                .ok_or_else(|| Widened::Signature {
                    to: rule.to,
                    signature: call.signature.canonical().to_string(),
                })?;
            narrows_args(rule.to, call, permitted)?;
        }
        if rule.max_value > allowed.max_value {
            return Err(Widened::MaxValue {
                to: rule.to,
                max_value: rule.max_value,
            });
        }
    }
    for schema in &grant.typed_data {
        if !policy.typed_data.iter().any(|s| &s.schema == schema) {
            return Err(Widened::Schema {
                schema: schema.clone(),
            });
        }
    }
    let Some(refunds) = &grant.refunds else {
        return Ok(());
    };
    let Some(ceiling) = &policy.refunds else {
        return Err(Widened::RefundsNotInPolicy);
    };
    for gas_token in &refunds.gas_tokens {
        if !ceiling.gas_tokens.contains(gas_token) {
            return Err(Widened::GasToken {
                gas_token: *gas_token,
            });
        }
    }
    for refund_receiver in &refunds.refund_receivers {
        if !ceiling.refund_receivers.contains(refund_receiver) {
            return Err(Widened::RefundReceiver {
                refund_receiver: *refund_receiver,
            });
        }
    }
    if refunds.max_gas_price > ceiling.max_gas_price {
        return Err(Widened::MaxGasPrice {
            max_gas_price: refunds.max_gas_price,
        });
    }
    if refunds.max_base_gas > ceiling.max_base_gas {
        return Err(Widened::MaxBaseGas {
            max_base_gas: refunds.max_base_gas,
        });
    }
    if refunds.max_safe_tx_gas > ceiling.max_safe_tx_gas {
        return Err(Widened::MaxSafeTxGas {
            max_safe_tx_gas: refunds.max_safe_tx_gas,
        });
    }
    Ok(())
}

/// Every argument the grant bounds must be bounded at least as tightly as the policy bounds it.
/// The load check already proved both rules cover every declared position exactly once, so the
/// positions line up; what is checked here is the bound itself.
fn narrows_args(to: Address, grant: &CallRule, policy: &CallRule) -> Result<(), Widened> {
    for arg in &grant.arg {
        let Some(ceiling) = policy.arg.iter().find(|c| c.at == arg.at) else {
            return Err(Widened::Arg {
                to,
                signature: grant.signature.canonical().to_string(),
                at: arg.at,
            });
        };
        if !no_wider(&arg.rule, &ceiling.rule) {
            return Err(Widened::Arg {
                to,
                signature: grant.signature.canonical().to_string(),
                at: arg.at,
            });
        }
    }
    Ok(())
}

/// Whether `grant` permits nothing `policy` does not. The clause that matters is the last one:
/// anything is narrower than a policy `Unbounded`, and `Unbounded` is narrower than nothing
/// else — an adapter must not be able to unbind an argument the policy bound.
fn no_wider(grant: &FieldRule, policy: &FieldRule) -> bool {
    if matches!(policy, FieldRule::Unbounded) {
        return true;
    }
    match (grant, policy) {
        (FieldRule::OneOf { addresses }, FieldRule::OneOf { addresses: ceiling }) => {
            addresses.iter().all(|a| ceiling.contains(a))
        }
        (FieldRule::Max { max, .. }, FieldRule::Max { max: ceiling, .. }) => max <= ceiling,
        (FieldRule::Eq { eq }, FieldRule::Max { max: ceiling, .. }) => eq <= ceiling,
        (FieldRule::Eq { eq }, FieldRule::Eq { eq: ceiling }) => eq == ceiling,
        (FieldRule::BoolEq { eq }, FieldRule::BoolEq { eq: ceiling }) => eq == ceiling,
        (FieldRule::BytesEq { eq }, FieldRule::BytesEq { eq: ceiling }) => eq == ceiling,
        (
            FieldRule::Deadline { within_secs },
            FieldRule::Deadline {
                within_secs: ceiling,
            },
        ) => within_secs <= ceiling,
        (FieldRule::Enum { one_of }, FieldRule::Enum { one_of: ceiling }) => {
            one_of.iter().all(|s| ceiling.contains(s))
        }
        (
            FieldRule::Each { max_len, of },
            FieldRule::Each {
                max_len: ceiling,
                of: under,
            },
        ) => max_len <= ceiling && no_wider(of, under),
        (FieldRule::Struct, FieldRule::Struct) | (FieldRule::Batch, FieldRule::Batch) => true,
        _ => false,
    }
}

/// The request-time check, run only for a request that arrived on an adapter's own socket and
/// only after `policy::evaluate` has already passed. It returns the grant it checked against, so
/// the same one bounds every entry of a `multiSend` without a second lookup.
pub fn evaluate<'m>(i: &SafeTxIntent, manifest: &'m Manifest) -> Result<&'m Grant, ManifestDenied> {
    let grant = manifest
        .grants
        .iter()
        .find(|g| g.key == i.key)
        .ok_or_else(|| ManifestDenied::KeyNotGranted { key: i.key.clone() })?;
    if !grant.intent_kinds.contains(&IntentKind::SafeTx) {
        return Err(ManifestDenied::IntentKindNotGranted {
            kind: IntentKind::SafeTx,
        });
    }
    if !grant.safes.contains(&i.safe) {
        return Err(ManifestDenied::SafeNotGranted { safe: i.safe });
    }
    if !grant.chain_ids.contains(&i.chain_id) {
        return Err(ManifestDenied::ChainNotGranted {
            chain_id: i.chain_id,
        });
    }
    if i.to == i.safe {
        return Err(ManifestDenied::OwnerManagementNotDelegable { safe: i.safe });
    }
    match_refunds(grant.refunds.as_ref(), i)?;
    match_call(&grant.calls, &Site::own(i))?;
    Ok(grant)
}

/// The same request-time check for an EIP-712 message: the adapter must hold the key, be granted
/// the typed-data shape at all, be granted the chain, and have named this schema in its own
/// manifest. The schema's contents are the POLICY's — a grant can only ever pick from them.
pub fn evaluate_typed(i: &TypedDataIntent, manifest: &Manifest) -> Result<(), ManifestDenied> {
    let grant = manifest
        .grants
        .iter()
        .find(|g| g.key == i.key)
        .ok_or_else(|| ManifestDenied::KeyNotGranted { key: i.key.clone() })?;
    if !grant.intent_kinds.contains(&IntentKind::TypedData) {
        return Err(ManifestDenied::IntentKindNotGranted {
            kind: IntentKind::TypedData,
        });
    }
    if !grant.chain_ids.contains(&i.chain_id) {
        return Err(ManifestDenied::ChainNotGranted {
            chain_id: i.chain_id,
        });
    }
    if !grant.typed_data.contains(&i.schema) {
        return Err(ManifestDenied::SchemaNotGranted {
            schema: i.schema.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::OwnerMgmt;
    use crate::schema::{unbounded_call, ArgRule, OWNER_MGMT};
    use alloy_primitives::Bytes;

    const SAFE: [u8; 20] = [0x11; 20];
    const TOKEN: [u8; 20] = [0x22; 20];
    const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    const VENDOR: Address = Address::new([0x33u8; 20]);
    const STRANGER: Address = Address::new([0x99u8; 20]);

    const MANIFEST: &str = concat!(
        "schema = \"hotcheese.adapter/v1\"\n",
        "id = \"safe_treasury_bot\"\n",
        "\n",
        "[[grants]]\n",
        "key = \"TREASURY\"\n",
        "intent_kinds = [\"safe_tx\"]\n",
        "chain_ids = [\"1\"]\n",
        "safes = [\"0x1111111111111111111111111111111111111111\"]\n",
        "\n",
        "[[grants.calls]]\n",
        "to = \"0x2222222222222222222222222222222222222222\"\n",
        "max_value = \"0\"\n",
        "operation = \"call\"\n",
        "\n",
        "  [[grants.calls.call]]\n",
        "  signature = \"transfer(address,uint256)\"\n",
        "\n",
        "    [[grants.calls.call.arg]]\n",
        "    at = 0\n",
        "    name = \"to\"\n",
        "    rule = { one_of = { addresses = [\"0x3333333333333333333333333333333333333333\"] } }\n",
        "\n",
        "    [[grants.calls.call.arg]]\n",
        "    at = 1\n",
        "    name = \"amount\"\n",
        "    rule = { max = { max = \"1000\", amount_of = \
         \"0x2222222222222222222222222222222222222222\" } }\n",
    );

    fn manifest() -> Manifest {
        toml::from_str(MANIFEST).expect("the documented manifest must load")
    }

    fn bounded_transfer(recipients: Vec<Address>, max: u64) -> CallRule {
        let mut call = unbounded_call("transfer(address,uint256)");
        call.arg = vec![
            ArgRule {
                at: 0,
                name: "to".to_string(),
                rule: FieldRule::OneOf {
                    addresses: recipients,
                },
            },
            ArgRule {
                at: 1,
                name: "amount".to_string(),
                rule: FieldRule::Max {
                    max: U256::from(max),
                    amount_of: Address::from(TOKEN),
                },
            },
        ];
        call
    }

    fn policy() -> Policy {
        Policy {
            safe: Address::from(SAFE),
            chain_id: U256::from(1u64),
            allow: vec![AllowRule {
                to: Address::from(TOKEN),
                call: vec![
                    bounded_transfer(vec![VENDOR], 1_000),
                    unbounded_call("approve(address,uint256)"),
                ],
                max_value: U256::from(100u64),
                operation: Operation::Call,
            }],
            owner_management: OwnerMgmt {
                allow: true,
                call: vec![unbounded_call(OWNER_MGMT[0])],
                max_value: U256::ZERO,
            },
            refunds: None,
            typed_data: Vec::new(),
        }
    }

    fn grant() -> Grant {
        manifest().grants.into_iter().next().expect("one grant")
    }

    fn intent() -> SafeTxIntent {
        SafeTxIntent {
            key: "TREASURY".into(),
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

    /// The security-critical composition rule: policy is the ceiling and a manifest may only
    /// narrow it, so a grant that claims more in ANY dimension — safe, chain, destination,
    /// selector, value ceiling, operation — is refused before `serve` binds anything, while a
    /// strictly narrower grant is accepted.
    #[test]
    fn a_grant_broader_than_policy_is_refused_in_every_dimension() {
        assert!(narrows(&grant(), &policy()).is_ok());

        let mut wider = grant();
        wider.safes.push(Address::from([0x99u8; 20]));
        assert!(matches!(
            narrows(&wider, &policy()),
            Err(Widened::Safe { .. })
        ));

        let mut wider = grant();
        wider.chain_ids.push(U256::from(10u64));
        assert!(matches!(
            narrows(&wider, &policy()),
            Err(Widened::Chain { .. })
        ));

        let mut wider = grant();
        wider.calls[0].to = Address::from([0x33u8; 20]);
        assert!(matches!(
            narrows(&wider, &policy()),
            Err(Widened::Call { .. })
        ));

        let mut wider = grant();
        wider.calls[0].operation = Operation::Delegatecall;
        assert!(matches!(
            narrows(&wider, &policy()),
            Err(Widened::Call { .. })
        ));

        let mut wider = grant();
        wider.calls[0]
            .call
            .push(unbounded_call("increaseAllowance(address,uint256)"));
        assert!(matches!(
            narrows(&wider, &policy()),
            Err(Widened::Signature { .. })
        ));

        // The comparison is on CANONICAL TEXT and not on the four bytes, because two different
        // signatures can be ground to share a selector and a manifest is the lower-trust file:
        // comparing selectors would let it declare a different call under a permitted one.
        let mut collided = grant();
        collided.calls[0].call[0].signature =
            crate::schema::Signature::try_from("gasprice_bit_ether(int128)".to_string())
                .expect("a canonical signature parses");
        assert!(matches!(
            narrows(&collided, &policy()),
            Err(Widened::Signature { .. })
        ));

        // An adapter may not unbind an argument the policy bound, in any dimension.
        for loosened in [
            FieldRule::Unbounded,
            FieldRule::OneOf {
                addresses: vec![VENDOR, STRANGER],
            },
        ] {
            let mut wider = grant();
            wider.calls[0].call[0].arg[0].rule = loosened;
            assert!(matches!(
                narrows(&wider, &policy()),
                Err(Widened::Arg { at: 0, .. })
            ));
        }
        let mut wider = grant();
        wider.calls[0].call[0].arg[1].rule = FieldRule::Max {
            max: U256::from(1_001u64),
            amount_of: Address::from(TOKEN),
        };
        assert!(matches!(
            narrows(&wider, &policy()),
            Err(Widened::Arg { at: 1, .. })
        ));

        let mut schema = grant();
        schema.typed_data.push("permit2_usdc".to_string());
        assert!(matches!(
            narrows(&schema, &policy()),
            Err(Widened::Schema { .. })
        ));

        let mut wider = grant();
        wider.calls[0].max_value = U256::from(101u64);
        assert!(matches!(
            narrows(&wider, &policy()),
            Err(Widened::MaxValue { .. })
        ));

        // The policy above enables owner rotation for the human; a manifest may still never
        // take it, so naming the Safe itself as a destination is refused outright.
        let mut rotation = grant();
        rotation.calls[0].to = Address::from(SAFE);
        assert!(matches!(
            narrows(&rotation, &policy()),
            Err(Widened::OwnerManagement { .. })
        ));

        let mut narrower = grant();
        narrower.calls[0].max_value = U256::from(99u64);
        narrower.safes.clear();
        narrower.chain_ids.clear();
        assert!(narrows(&narrower, &policy()).is_ok());
    }

    /// Refunds drain a Safe independently of `(to, value, data)`, so an adapter must not inherit
    /// the human's relayer allowance: a grant with no `refunds` term takes none at all, a grant
    /// broader than the policy in ANY refund dimension is refused before `serve` binds, and only
    /// a strictly narrower one is accepted.
    #[test]
    fn a_grant_refund_term_may_only_narrow_the_policy() {
        let token = Address::from([0x44u8; 20]);
        let relayer = Address::from([0x55u8; 20]);
        let mut ceiling = policy();
        ceiling.refunds = Some(RefundPolicy {
            gas_tokens: vec![token, Address::ZERO],
            refund_receivers: vec![relayer],
            max_gas_price: U256::from(10u64),
            max_base_gas: U256::from(1_000u64),
            max_safe_tx_gas: U256::from(100u64),
        });
        let allowance = RefundPolicy {
            gas_tokens: vec![token],
            refund_receivers: vec![relayer],
            max_gas_price: U256::from(10u64),
            max_base_gas: U256::from(1_000u64),
            max_safe_tx_gas: U256::from(100u64),
        };

        let bare = grant();
        assert!(bare.refunds.is_none());
        assert!(narrows(&bare, &ceiling).is_ok());
        let mut refunding = bare.clone();
        refunding.refunds = Some(allowance.clone());
        assert!(narrows(&refunding, &ceiling).is_ok());

        let mut no_policy_refunds = ceiling.clone();
        no_policy_refunds.refunds = None;
        assert!(matches!(
            narrows(&refunding, &no_policy_refunds),
            Err(Widened::RefundsNotInPolicy)
        ));

        let mut wider = bare.clone();
        let mut term = allowance.clone();
        term.gas_tokens.push(Address::from([0x66u8; 20]));
        wider.refunds = Some(term);
        assert!(matches!(
            narrows(&wider, &ceiling),
            Err(Widened::GasToken { .. })
        ));

        let mut wider = bare.clone();
        let mut term = allowance.clone();
        term.refund_receivers.push(Address::from([0x77u8; 20]));
        wider.refunds = Some(term);
        assert!(matches!(
            narrows(&wider, &ceiling),
            Err(Widened::RefundReceiver { .. })
        ));

        let mut wider = bare.clone();
        let mut term = allowance.clone();
        term.max_gas_price = U256::from(11u64);
        wider.refunds = Some(term);
        assert!(matches!(
            narrows(&wider, &ceiling),
            Err(Widened::MaxGasPrice { .. })
        ));

        let mut wider = bare.clone();
        let mut term = allowance.clone();
        term.max_base_gas = U256::from(1_001u64);
        wider.refunds = Some(term);
        assert!(matches!(
            narrows(&wider, &ceiling),
            Err(Widened::MaxBaseGas { .. })
        ));

        let mut wider = bare.clone();
        let mut term = allowance.clone();
        term.max_safe_tx_gas = U256::from(101u64);
        wider.refunds = Some(term);
        assert!(matches!(
            narrows(&wider, &ceiling),
            Err(Widened::MaxSafeTxGas { .. })
        ));

        let mut narrower = allowance;
        narrower.gas_tokens.clear();
        narrower.max_gas_price = U256::from(1u64);
        let mut tight = bare;
        tight.refunds = Some(narrower);
        assert!(narrows(&tight, &ceiling).is_ok());
    }

    /// The request-time half of the same rule: a policy may allow a refund the adapter's own
    /// grant does not, and then the adapter's request is denied even though the policy passed.
    #[test]
    fn a_refund_the_grant_does_not_take_is_denied_at_request_time() {
        let mut drain = intent();
        drain.gas_price = U256::from(1u64);
        drain.gas_token = Address::from([0x44u8; 20]);
        drain.refund_receiver = Address::from([0x55u8; 20]);

        let mut m = manifest();
        assert!(matches!(
            evaluate(&drain, &m),
            Err(ManifestDenied::Refund(RefundDenied::RefundNotAllowed))
        ));

        m.grants[0].refunds = Some(RefundPolicy {
            gas_tokens: vec![drain.gas_token],
            refund_receivers: vec![drain.refund_receiver],
            max_gas_price: U256::from(1u64),
            max_base_gas: U256::ZERO,
            max_safe_tx_gas: U256::ZERO,
        });
        assert!(evaluate(&drain, &m).is_ok());
        assert!(
            evaluate(&intent(), &m).is_ok(),
            "an intent with no refund activity never needs an allowance"
        );

        let mut over = drain;
        over.gas_price = U256::from(2u64);
        assert!(matches!(
            evaluate(&over, &m),
            Err(ManifestDenied::Refund(RefundDenied::GasPriceTooHigh { .. }))
        ));
    }

    /// A grant that a policy simply has no rule for cannot be narrowed into existence, and an
    /// empty policy therefore grants an adapter nothing.
    #[test]
    fn an_empty_policy_narrows_every_call_away() {
        let mut empty = policy();
        empty.allow.clear();
        assert!(matches!(
            narrows(&grant(), &empty),
            Err(Widened::Call { .. })
        ));
    }

    /// Every struct in the schema denies unknown fields, which is the general form of "an
    /// unknown term is a deny": a typo, a term from a future schema, or an extra term smuggled
    /// into the refund allowance all fail to load rather than being dropped on the floor.
    #[test]
    fn an_unrecognised_term_anywhere_fails_to_load() {
        for extra in [
            ("id = \"safe_treasury_bot\"\n", "expires = \"never\"\n"),
            ("key = \"TREASURY\"\n", "sign_anything = true\n"),
            (
                "key = \"TREASURY\"\n",
                "refunds = { gas_tokens = [], refund_receivers = [], unmetered = true }\n",
            ),
            (
                "  signature = \"transfer(address,uint256)\"\n",
                "  required = \"anything\"\n",
            ),
            ("    name = \"to\"\n", "    optional = true\n"),
        ] {
            let smuggled = MANIFEST.replace(extra.0, &format!("{}{}", extra.0, extra.1));
            assert_ne!(smuggled, MANIFEST, "the fixture must contain {}", extra.0);
            assert!(
                toml::from_str::<Manifest>(&smuggled).is_err(),
                "an unknown term must be a deny: {}",
                extra.1
            );
        }
    }

    /// The request-time half: an adapter's own socket still only reaches what its manifest
    /// names, key by key, chain by chain, Safe by Safe — and never the Safe itself.
    #[test]
    fn a_request_outside_the_grant_is_denied() {
        let m = manifest();
        assert!(evaluate(&intent(), &m).is_ok());

        let mut other_key = intent();
        other_key.key = "OTHER".into();
        assert!(matches!(
            evaluate(&other_key, &m),
            Err(ManifestDenied::KeyNotGranted { .. })
        ));

        let mut other_safe = intent();
        other_safe.safe = Address::from([0x99u8; 20]);
        assert!(matches!(
            evaluate(&other_safe, &m),
            Err(ManifestDenied::SafeNotGranted { .. })
        ));

        let mut other_chain = intent();
        other_chain.chain_id = U256::from(10u64);
        assert!(matches!(
            evaluate(&other_chain, &m),
            Err(ManifestDenied::ChainNotGranted { .. })
        ));

        let mut rotation = intent();
        rotation.to = rotation.safe;
        rotation.data = Bytes::from(unbounded_call(OWNER_MGMT[0]).signature.selector().to_vec());
        assert!(matches!(
            evaluate(&rotation, &m),
            Err(ManifestDenied::OwnerManagementNotDelegable { .. })
        ));

        let mut other_call = intent();
        other_call.to = Address::from([0x33u8; 20]);
        assert!(matches!(
            evaluate(&other_call, &m),
            Err(ManifestDenied::Call(CallDenied::ToNotAllowed { .. }))
        ));
    }
}
