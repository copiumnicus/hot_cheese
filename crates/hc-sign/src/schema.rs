//! The rule language a policy file and an adapter manifest are both written in.
//!
//! A rule declares a full canonical signature — `transfer(address,uint256)` — and the 4-byte
//! selector is DERIVED from it, so anything the policy permits is decodable by construction and
//! an operator can no longer allow-list bytes nothing can read. The same [`FieldRule`] bounds a
//! call's arguments and an EIP-712 message's fields, and it has no default: a field an operator
//! forgot to bound does not parse, because an unconstrained permit is an infinite approval.
//!
//! Nothing here reads a clock, a config file or the filesystem. [`FieldWalk`] takes `now_secs`
//! from its caller, which is what keeps this module free of [`grant`](crate::grant).
use crate::intent::{Operation, SafeTxIntent};
use alloy_dyn_abi::{DynSolType, DynSolValue, PropertyDef, Resolver, Specifier, TypeDef};
use alloy_json_abi::Function;
use alloy_primitives::{Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_types::Eip712Domain;
use err_mac::create_err_with_impls;
use serde::Deserialize;

/// The four Safe owner/threshold management calls — the fail-closed rotation set. Compared
/// against a declared signature's canonical text, so it cannot drift from a selector table.
pub const OWNER_MGMT: [&str; 4] = [
    "swapOwner(address,address,address)",
    "addOwnerWithThreshold(address,uint256)",
    "removeOwner(address,address,uint256)",
    "changeThreshold(uint256)",
];

/// The four Safe module/guard/fallback calls: each hands one address permanent control of the
/// Safe without ever touching its owner set.
pub const SAFE_CONFIG: [&str; 4] = [
    "enableModule(address)",
    "disableModule(address,address)",
    "setGuard(address)",
    "setFallbackHandler(address)",
];

/// The Safe MultiSend entry point, whose single `bytes` argument is itself a list of calls.
pub const MULTI_SEND: &str = "multiSend(bytes)";

/// A hash approved without its contents travelling with it.
pub const APPROVE_HASH: &str = "approveHash(bytes32)";

/// Seconds past which an accepted deadline is still worth saying out loud.
const DEADLINE_FAR_SECS: u64 = 86_400;

/// Bit width past which a `Deadline` rule cannot be meant: a unix second needs 40 bits well
/// before any plausible expiry.
const DEADLINE_MIN_BITS: usize = 40;

create_err_with_impls!(
    #[derive(Debug)]
    pub RuleErr,
    Parse(alloy_json_abi::parser::Error),
    Abi(alloy_dyn_abi::Error)
    ;
    NotCanonical { declared: String, canonical: String },
    DuplicateSelector { selector: FixedBytes<4>, first: String, second: String },
    ArgOutOfRange { signature: String, at: usize, arity: usize },
    ArgUnruled { signature: String, at: usize },
    ArgDuplicated { signature: String, at: usize },
    ArgNameEmpty { signature: String, at: usize },
    ArgNameNotUnique { signature: String, name: String },
    RuleTypeMismatch { signature: String, at: usize, declared: String, rule: FieldRuleKind },
    BatchRuleMisplaced { signature: String, at: usize },
    BatchRuleMissing { signature: String },
    DuplicateSchema { schema: String },
    DuplicateType { schema: String, name: String },
    PrimaryTypeNotDeclared { schema: String, primary_type: String },
    SchemaNotResolvable { schema: String, primary_type: String },
    SchemaFieldTypeMismatch { schema: String, path: String, declared: String, rule: FieldRuleKind }
);

create_err_with_impls!(
    #[derive(Debug)]
    pub FieldDenied,
    ;
    AddressNotAllowed { path: String, got: Address, allowed: Vec<Address> },
    ValueTooHigh { path: String, got: U256, max: U256 },
    ValueNotExact { path: String, got: U256, want: U256 },
    BoolNotExact { path: String, got: bool, want: bool },
    BytesNotExact { path: String, got: Bytes, want: Bytes },
    DeadlineTooFar { path: String, deadline: U256, now_secs: u64, within_secs: u64 },
    StringNotAllowed { path: String, got: String, allowed: Vec<String> },
    TooManyElements { path: String, got: usize, max_len: usize },
    StructNotDeclared { path: String, name: String },
    StructArity { path: String, name: String, declared: usize, got: usize },
    TypeNotExpected { path: String, got: String, rule: FieldRuleKind }
);

/// A canonical function signature and the selector derived from it. The fields are private
/// because the selector is only ever `keccak256(canonical)[..4]`: there is no way to hold a
/// [`Signature`] whose selector names a different function from its text.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "String")]
pub struct Signature {
    /// The parsed function, whose `inputs` are the shape calldata is decoded against.
    function: Function,
    /// `keccak256(canonical)[..4]`, derived here and never written by an operator.
    selector: FixedBytes<4>,
    /// The canonical text, which is also the text the policy file must contain.
    canonical: String,
}

impl TryFrom<String> for Signature {
    type Error = RuleErr;

    fn try_from(declared: String) -> Result<Self, RuleErr> {
        let function = Function::parse(&declared)?;
        let canonical = function.signature();
        if canonical != declared {
            return Err(RuleErr::NotCanonical {
                declared,
                canonical,
            });
        }
        let selector = function.selector();
        Ok(Signature {
            function,
            selector,
            canonical,
        })
    }
}

impl Signature {
    /// The declared shape calldata is decoded against.
    pub fn function(&self) -> &Function {
        &self.function
    }
    /// The 4 bytes calldata must start with to match this rule.
    pub fn selector(&self) -> FixedBytes<4> {
        self.selector
    }
    /// The canonical text, which is the only spelling a policy file may carry.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }
}

/// A bound on one declared argument. `rule` has no default, so an unbounded argument must be
/// typed out as `kind = "unbounded"` and can never be left unbounded by omission.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgRule {
    /// Zero-based position in the declared signature.
    pub at: usize,
    /// The operator's label for this argument, shown to the human beside its value.
    pub name: String,
    pub rule: FieldRule,
}

/// One call shape and what its arguments may hold.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRule {
    /// The canonical signature; the 4-byte selector is derived from it.
    pub signature: Signature,
    /// One rule per declared argument, in any order, covering every position exactly once.
    pub arg: Vec<ArgRule>,
}

impl CallRule {
    /// The rule bounding the argument at position `at`, which [`check_call_rules`] proved exists
    /// for every declared position. `None` is a position this rule does not name, which is a
    /// value the renderer prints rather than a failure.
    pub fn at(&self, at: usize) -> Option<&ArgRule> {
        self.arg.iter().find(|a| a.at == at)
    }
}

/// Which constraint a [`FieldRule`] is, without its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldRuleKind {
    OneOf,
    Max,
    Eq,
    BoolEq,
    BytesEq,
    Deadline,
    Enum,
    Each,
    Struct,
    Batch,
    Unbounded,
}

/// What one declared field or argument may hold. There is no default: a field with no rule does
/// not parse, so "no bound" has to be typed out and is then said out loud on the approval sheet.
///
/// Externally tagged — `rule = { max = { max = "…", amount_of = "…" } }`, `rule = "unbounded"` —
/// because serde's `deny_unknown_fields` is INERT on an internally tagged enum's struct variants:
/// under `kind = "unbounded"` a stray `max = "100"` would parse and be silently dropped, which is
/// the operator believing in a ceiling that does not exist. Externally tagged, it is a refusal.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldRule {
    /// An address, and only these.
    OneOf { addresses: Vec<Address> },
    /// An integer up to and including `max`, rendered scaled against `amount_of`.
    Max {
        #[serde(with = "hc_core::wire::u256")]
        max: U256,
        /// The contract whose decimals scale this integer for the human; `0x0` is native.
        amount_of: Address,
    },
    /// Exactly this integer.
    Eq {
        #[serde(with = "hc_core::wire::u256")]
        eq: U256,
    },
    /// Exactly this boolean, which is what tells an infinite approval from a revocation.
    BoolEq { eq: bool },
    /// Exactly these bytes.
    BytesEq { eq: Bytes },
    /// A unix-seconds timestamp no more than `within_secs` ahead of now.
    Deadline { within_secs: u64 },
    /// Exactly one of these strings.
    Enum { one_of: Vec<String> },
    /// Every element bounded by `of`, and no more than `max_len` of them.
    Each { max_len: usize, of: Box<FieldRule> },
    /// A nested struct, bounded by its own declared type.
    Struct,
    /// A packed `multiSend` payload, every entry of which is matched against the policy in its
    /// own right. It carries no honest ceiling, and it is not unbounded.
    Batch,
    /// Deliberately unbounded. The summary says so, in the alarm block.
    Unbounded,
}

impl FieldRule {
    /// Which constraint this is, for a refusal that names the rule rather than quoting it.
    pub fn kind(&self) -> FieldRuleKind {
        match self {
            FieldRule::OneOf { .. } => FieldRuleKind::OneOf,
            FieldRule::Max { .. } => FieldRuleKind::Max,
            FieldRule::Eq { .. } => FieldRuleKind::Eq,
            FieldRule::BoolEq { .. } => FieldRuleKind::BoolEq,
            FieldRule::BytesEq { .. } => FieldRuleKind::BytesEq,
            FieldRule::Deadline { .. } => FieldRuleKind::Deadline,
            FieldRule::Enum { .. } => FieldRuleKind::Enum,
            FieldRule::Each { .. } => FieldRuleKind::Each,
            FieldRule::Struct => FieldRuleKind::Struct,
            FieldRule::Batch => FieldRuleKind::Batch,
            FieldRule::Unbounded => FieldRuleKind::Unbounded,
        }
    }

    /// Whether this rule can constrain a value of `ty` at all. Checked once at load, so a rule
    /// that could never fire is a refusal to load rather than a term nobody notices.
    fn applies(&self, ty: &DynSolType) -> bool {
        match self {
            FieldRule::OneOf { .. } => matches!(ty, DynSolType::Address),
            FieldRule::Max { .. } | FieldRule::Eq { .. } => matches!(ty, DynSolType::Uint(_)),
            FieldRule::BoolEq { .. } => matches!(ty, DynSolType::Bool),
            FieldRule::BytesEq { .. } => {
                matches!(ty, DynSolType::Bytes | DynSolType::FixedBytes(_))
            }
            FieldRule::Deadline { .. } => {
                matches!(ty, DynSolType::Uint(bits) if *bits >= DEADLINE_MIN_BITS)
            }
            FieldRule::Enum { .. } => matches!(ty, DynSolType::String),
            FieldRule::Each { of, .. } => match ty {
                DynSolType::Array(inner) | DynSolType::FixedArray(inner, _) => of.applies(inner),
                _ => false,
            },
            FieldRule::Struct => matches!(ty, DynSolType::CustomStruct { .. }),
            FieldRule::Batch => matches!(ty, DynSolType::Bytes),
            FieldRule::Unbounded => true,
        }
    }
}

/// Something a PERMITTED field is worth saying out loud, hoisted into the alarm block. A note is
/// never a refusal: it is what the policy deliberately left to the human.
pub enum FieldNote {
    /// The policy declared this field unbounded, so the human is the only remaining bound.
    Unbounded {
        /// Dotted path of the field, from the argument or message-field name down.
        path: String,
    },
    /// An accepted deadline further out than a day.
    DeadlineFar {
        /// Dotted path of the field.
        path: String,
        /// The unix-seconds value accepted.
        deadline: U256,
    },
}

/// One walk of the declared rules over a decoded value. It refuses what a rule forbids and
/// notes what a rule deliberately leaves free, and it carries the dotted path so a refusal names
/// the field rather than the position of a word.
pub struct FieldWalk<'s> {
    /// Unix seconds, supplied by the caller so this module never reads a clock.
    now_secs: u64,
    /// The struct declarations a `Struct` rule recurses into; empty for a call's arguments.
    types: &'s [TypeDecl],
    path: String,
    notes: Vec<FieldNote>,
}

impl<'s> FieldWalk<'s> {
    pub fn new(now_secs: u64, types: &'s [TypeDecl]) -> Self {
        FieldWalk {
            now_secs,
            types,
            path: String::new(),
            notes: Vec::new(),
        }
    }

    /// Check one named field or argument against its rule.
    pub fn field(
        &mut self,
        name: &str,
        rule: &FieldRule,
        value: &DynSolValue,
    ) -> Result<(), FieldDenied> {
        let mark = self.path.len();
        if !self.path.is_empty() {
            self.path.push('.');
        }
        self.path.push_str(name);
        let out = self.check(rule, value);
        self.path.truncate(mark);
        out
    }

    /// Everything the policy left free, in the order it was walked.
    pub fn notes(self) -> Vec<FieldNote> {
        self.notes
    }

    fn wrong(&self, value: &DynSolValue, rule: &FieldRule) -> FieldDenied {
        FieldDenied::TypeNotExpected {
            path: self.path.clone(),
            got: value
                .sol_type_name()
                .unwrap_or_else(|| "<none>".into())
                .into_owned(),
            rule: rule.kind(),
        }
    }

    fn check(&mut self, rule: &FieldRule, value: &DynSolValue) -> Result<(), FieldDenied> {
        match (rule, value) {
            (FieldRule::OneOf { addresses }, DynSolValue::Address(got)) => {
                if !addresses.contains(got) {
                    return Err(FieldDenied::AddressNotAllowed {
                        path: self.path.clone(),
                        got: *got,
                        allowed: addresses.clone(),
                    });
                }
                Ok(())
            }
            (FieldRule::Max { max, .. }, DynSolValue::Uint(got, _)) => {
                if got > max {
                    return Err(FieldDenied::ValueTooHigh {
                        path: self.path.clone(),
                        got: *got,
                        max: *max,
                    });
                }
                Ok(())
            }
            (FieldRule::Eq { eq }, DynSolValue::Uint(got, _)) => {
                if got != eq {
                    return Err(FieldDenied::ValueNotExact {
                        path: self.path.clone(),
                        got: *got,
                        want: *eq,
                    });
                }
                Ok(())
            }
            (FieldRule::BoolEq { eq }, DynSolValue::Bool(got)) => {
                if got != eq {
                    return Err(FieldDenied::BoolNotExact {
                        path: self.path.clone(),
                        got: *got,
                        want: *eq,
                    });
                }
                Ok(())
            }
            (FieldRule::BytesEq { eq }, DynSolValue::Bytes(got)) => {
                if got.as_slice() != eq.as_ref() {
                    return Err(FieldDenied::BytesNotExact {
                        path: self.path.clone(),
                        got: Bytes::copy_from_slice(got),
                        want: eq.clone(),
                    });
                }
                Ok(())
            }
            (FieldRule::BytesEq { eq }, DynSolValue::FixedBytes(got, n)) => {
                if &got[..*n] != eq.as_ref() {
                    return Err(FieldDenied::BytesNotExact {
                        path: self.path.clone(),
                        got: Bytes::copy_from_slice(&got[..*n]),
                        want: eq.clone(),
                    });
                }
                Ok(())
            }
            (FieldRule::Deadline { within_secs }, DynSolValue::Uint(deadline, _)) => {
                let horizon = U256::from(self.now_secs).saturating_add(U256::from(*within_secs));
                if *deadline > horizon {
                    return Err(FieldDenied::DeadlineTooFar {
                        path: self.path.clone(),
                        deadline: *deadline,
                        now_secs: self.now_secs,
                        within_secs: *within_secs,
                    });
                }
                if *deadline
                    > U256::from(self.now_secs).saturating_add(U256::from(DEADLINE_FAR_SECS))
                {
                    self.notes.push(FieldNote::DeadlineFar {
                        path: self.path.clone(),
                        deadline: *deadline,
                    });
                }
                Ok(())
            }
            (FieldRule::Enum { one_of }, DynSolValue::String(got)) => {
                if !one_of.contains(got) {
                    return Err(FieldDenied::StringNotAllowed {
                        path: self.path.clone(),
                        got: got.clone(),
                        allowed: one_of.clone(),
                    });
                }
                Ok(())
            }
            (
                FieldRule::Each { max_len, of },
                DynSolValue::Array(items) | DynSolValue::FixedArray(items),
            ) => {
                if items.len() > *max_len {
                    return Err(FieldDenied::TooManyElements {
                        path: self.path.clone(),
                        got: items.len(),
                        max_len: *max_len,
                    });
                }
                for (n, item) in items.iter().enumerate() {
                    let mark = self.path.len();
                    self.path.push_str(&format!("[{n}]"));
                    let out = self.check(of, item);
                    self.path.truncate(mark);
                    out?;
                }
                Ok(())
            }
            (
                FieldRule::Struct,
                DynSolValue::CustomStruct {
                    name,
                    prop_names,
                    tuple,
                },
            ) => {
                let Some(declared) = self.types.iter().find(|t| &t.name == name) else {
                    return Err(FieldDenied::StructNotDeclared {
                        path: self.path.clone(),
                        name: name.clone(),
                    });
                };
                if declared.field.len() != tuple.len() || prop_names.len() != tuple.len() {
                    return Err(FieldDenied::StructArity {
                        path: self.path.clone(),
                        name: name.clone(),
                        declared: declared.field.len(),
                        got: tuple.len(),
                    });
                }
                for (field, inner) in declared.field.iter().zip(tuple) {
                    self.field(&field.name, &field.rule, inner)?;
                }
                Ok(())
            }
            (FieldRule::Batch, DynSolValue::Bytes(_)) => Ok(()),
            (FieldRule::Unbounded, _) => {
                self.notes.push(FieldNote::Unbounded {
                    path: self.path.clone(),
                });
                Ok(())
            }
            (rule, value) => Err(self.wrong(value, rule)),
        }
    }
}

/// One call the Safe makes: the transaction's own, or one entry of a `multiSend`.
///
/// A batch entry carries its OWN destination, operation and value, because policy pinned only
/// the transaction's — an entry that delegatecalls is arbitrary code running as the Safe.
#[derive(Clone)]
pub struct Site {
    /// Where this call goes.
    pub to: Address,
    /// The chain it runs on.
    pub chain_id: U256,
    /// CALL or DELEGATECALL, as this call itself declares it.
    pub operation: Operation,
    /// Native value this call sends.
    pub value: U256,
    /// This call's calldata.
    pub data: Bytes,
    /// Position in the batch tree; empty for the transaction's own call.
    pub at: Vec<usize>,
}

impl Site {
    /// The transaction's own call, at no position in any batch.
    pub fn own(i: &SafeTxIntent) -> Site {
        Site {
            to: i.to,
            chain_id: i.chain_id,
            operation: i.operation,
            value: i.value,
            data: i.data.clone(),
            at: Vec::new(),
        }
    }

    /// The dotted position of this call: empty for the transaction's own, `2` for the second
    /// sub-call, `2.1` for the first sub-call of the second.
    pub fn position(&self) -> String {
        let mut out = String::new();
        for step in &self.at {
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(&step.to_string());
        }
        out
    }
}

/// Refuse a rule set that cannot mean what it says: two signatures sharing a selector (a
/// grinding attacker chooses that collision, and the decoder would have two candidate shapes for
/// one payload), an argument nothing bounds, a bound on an argument that does not exist, or a
/// constraint the argument's Solidity type can never satisfy. Checked once at load, for a policy
/// file and an adapter manifest alike.
pub fn check_call_rules(rules: &[CallRule]) -> Result<(), RuleErr> {
    for (n, rule) in rules.iter().enumerate() {
        for other in &rules[n + 1..] {
            if other.signature.selector == rule.signature.selector {
                return Err(RuleErr::DuplicateSelector {
                    selector: rule.signature.selector,
                    first: rule.signature.canonical.clone(),
                    second: other.signature.canonical.clone(),
                });
            }
        }
        check_one_call_rule(rule)?;
    }
    Ok(())
}

fn check_one_call_rule(rule: &CallRule) -> Result<(), RuleErr> {
    let signature = rule.signature.canonical.clone();
    let arity = rule.signature.function.inputs.len();
    let mut names: Vec<&str> = Vec::with_capacity(rule.arg.len());
    for (n, arg) in rule.arg.iter().enumerate() {
        if arg.at >= arity {
            return Err(RuleErr::ArgOutOfRange {
                signature,
                at: arg.at,
                arity,
            });
        }
        if rule.arg[n + 1..].iter().any(|other| other.at == arg.at) {
            return Err(RuleErr::ArgDuplicated {
                signature,
                at: arg.at,
            });
        }
        if arg.name.is_empty() {
            return Err(RuleErr::ArgNameEmpty {
                signature,
                at: arg.at,
            });
        }
        if names.contains(&arg.name.as_str()) {
            return Err(RuleErr::ArgNameNotUnique {
                signature,
                name: arg.name.clone(),
            });
        }
        names.push(&arg.name);
    }
    let batch = signature == MULTI_SEND;
    for at in 0..arity {
        let Some(arg) = rule.at(at) else {
            return Err(RuleErr::ArgUnruled { signature, at });
        };
        let declared = rule.signature.function.inputs[at].resolve()?;
        if !arg.rule.applies(&declared) {
            return Err(RuleErr::RuleTypeMismatch {
                signature,
                at,
                declared: declared.sol_type_name().into_owned(),
                rule: arg.rule.kind(),
            });
        }
        match (batch && at == 0, arg.rule.kind() == FieldRuleKind::Batch) {
            (true, false) => return Err(RuleErr::BatchRuleMissing { signature }),
            (false, true) => return Err(RuleErr::BatchRuleMisplaced { signature, at }),
            _ => {}
        }
    }
    Ok(())
}

/// One complete EIP-712 message shape a request may name. Everything the digest depends on is
/// here; a request supplies only field VALUES.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedDataSchema {
    /// The name a request uses to select this schema.
    pub schema: String,
    /// The struct a message is; must be one of `types`.
    pub primary_type: String,
    pub domain: DomainDecl,
    /// The primary type and every struct it references, transitively.
    pub types: Vec<TypeDecl>,
}

/// The EIP-712 domain, declared in full. Which optional members are PRESENT changes the domain
/// separator, so presence is pinned here and a request cannot vary it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainDecl {
    /// EIP-155 chain; mandatory, because a domain with no chain is replayable across chains.
    #[serde(with = "hc_core::wire::u256")]
    pub chain_id: U256,
    /// The contract that verifies the signature; mandatory.
    pub verifying_contract: Address,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub salt: Option<B256>,
}

/// One struct type of the schema.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeDecl {
    pub name: String,
    pub field: Vec<FieldDecl>,
}

/// One field: its Solidity type, the name a human reads, and what it may hold.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDecl {
    /// The field name, which is also the JSON key in a request's `message`.
    pub name: String,
    /// Its Solidity type, exactly as it appears in the EIP-712 `encodeType` string.
    #[serde(rename = "type")]
    pub ty: String,
    pub rule: FieldRule,
}

impl TypedDataSchema {
    /// The type graph, built from the DECLARATION and never from a request.
    pub fn resolver(&self) -> Result<Resolver, RuleErr> {
        let mut resolver = Resolver::default();
        for declared in &self.types {
            let mut props = Vec::with_capacity(declared.field.len());
            for field in &declared.field {
                props.push(PropertyDef::new(field.ty.clone(), field.name.clone())?);
            }
            resolver.ingest(TypeDef::new(declared.name.clone(), props)?);
        }
        Ok(resolver)
    }

    /// The domain the digest is taken under, built from the DECLARATION. Which members are
    /// `Some` is what the `EIP712Domain(…)` type string is made of, so this is the whole of it.
    pub fn domain(&self) -> Eip712Domain {
        Eip712Domain {
            name: self.domain.name.clone().map(Into::into),
            version: self.domain.version.clone().map(Into::into),
            chain_id: Some(self.domain.chain_id),
            verifying_contract: Some(self.domain.verifying_contract),
            salt: self.domain.salt,
        }
    }

    /// Refuse a schema that cannot mean what it says, at load rather than at the first request:
    /// a repeated type name, a primary type nothing declares, a type graph that will not resolve
    /// (a missing type or a cycle), or a field rule its declared Solidity type can never satisfy.
    pub fn check(&self) -> Result<(), RuleErr> {
        for (n, declared) in self.types.iter().enumerate() {
            if self.types[n + 1..].iter().any(|o| o.name == declared.name) {
                return Err(RuleErr::DuplicateType {
                    schema: self.schema.clone(),
                    name: declared.name.clone(),
                });
            }
        }
        if !self.types.iter().any(|t| t.name == self.primary_type) {
            return Err(RuleErr::PrimaryTypeNotDeclared {
                schema: self.schema.clone(),
                primary_type: self.primary_type.clone(),
            });
        }
        let resolver = self.resolver()?;
        if !matches!(
            resolver.resolve(&self.primary_type)?,
            DynSolType::CustomStruct { .. }
        ) {
            return Err(RuleErr::SchemaNotResolvable {
                schema: self.schema.clone(),
                primary_type: self.primary_type.clone(),
            });
        }
        for declared in &self.types {
            for field in &declared.field {
                let ty = resolver.resolve(&field.ty)?;
                if !field.rule.applies(&ty) {
                    return Err(RuleErr::SchemaFieldTypeMismatch {
                        schema: self.schema.clone(),
                        path: format!("{}.{}", declared.name, field.name),
                        declared: field.ty.clone(),
                        rule: field.rule.kind(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// An all-unbounded rule for one canonical signature, for the policy fixtures this crate's
/// tests build. Every argument is deliberately free, which is what these fixtures are about.
#[cfg(test)]
pub(crate) fn unbounded_call(text: &str) -> CallRule {
    let signature = Signature::try_from(text.to_string()).expect("a canonical signature parses");
    let mut arg = Vec::new();
    for at in 0..signature.function.inputs.len() {
        arg.push(ArgRule {
            at,
            name: format!("a{at}"),
            rule: match text == MULTI_SEND {
                true => FieldRule::Batch,
                false => FieldRule::Unbounded,
            },
        });
    }
    CallRule { signature, arg }
}

/// Refuse a policy that declares two schemas under one name: a request names a schema by that
/// string, so a duplicate is a rule set the daemon would pick from arbitrarily.
pub fn check_schemas(schemas: &[TypedDataSchema]) -> Result<(), RuleErr> {
    for (n, schema) in schemas.iter().enumerate() {
        if schemas[n + 1..].iter().any(|o| o.schema == schema.schema) {
            return Err(RuleErr::DuplicateSchema {
                schema: schema.schema.clone(),
            });
        }
        schema.check()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(text: &str) -> Signature {
        Signature::try_from(text.to_string()).expect("a canonical signature parses")
    }

    fn call_rule(text: &str, args: Vec<ArgRule>) -> CallRule {
        CallRule {
            signature: signature(text),
            arg: args,
        }
    }

    fn arg(at: usize, name: &str, rule: FieldRule) -> ArgRule {
        ArgRule {
            at,
            name: name.to_string(),
            rule,
        }
    }

    const A: Address = Address::new([0xa1u8; 20]);
    const B: Address = Address::new([0xb2u8; 20]);

    /// The four rotation signatures and the two other const sets are compared against a
    /// DECLARED signature's canonical text, so a typo in one of these strings would silently
    /// produce a set nothing ever matches. Each must parse and be canonical verbatim, and the
    /// selectors they derive must be the ones the migration table publishes.
    #[test]
    fn every_const_signature_is_canonical() {
        for text in OWNER_MGMT.iter().chain(SAFE_CONFIG.iter()) {
            assert_eq!(signature(text).canonical(), *text);
        }
        assert_eq!(signature(MULTI_SEND).canonical(), MULTI_SEND);
        assert_eq!(signature(APPROVE_HASH).canonical(), APPROVE_HASH);
    }

    /// The whole migration table: a policy file the README tells an operator to write from a
    /// 4-byte selector must derive that exact selector back, or the conversion advice is wrong.
    #[test]
    fn a_declared_signature_derives_its_own_selector() {
        for (selector, text) in [
            ("e318b52b", "swapOwner(address,address,address)"),
            ("0d582f13", "addOwnerWithThreshold(address,uint256)"),
            ("f8dc5dd9", "removeOwner(address,address,uint256)"),
            ("694e80c3", "changeThreshold(uint256)"),
            ("a9059cbb", "transfer(address,uint256)"),
            ("095ea7b3", "approve(address,uint256)"),
            ("23b872dd", "transferFrom(address,address,uint256)"),
            ("39509351", "increaseAllowance(address,uint256)"),
            ("a457c2d7", "decreaseAllowance(address,uint256)"),
            ("a22cb465", "setApprovalForAll(address,bool)"),
            (
                "d505accf",
                "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            ),
            ("610b5925", "enableModule(address)"),
            ("e009cfde", "disableModule(address,address)"),
            ("e19a9dd9", "setGuard(address)"),
            ("f08a0323", "setFallbackHandler(address)"),
            ("d4d9bdcd", "approveHash(bytes32)"),
            ("42842e0e", "safeTransferFrom(address,address,uint256)"),
            (
                "b88d4fde",
                "safeTransferFrom(address,address,uint256,bytes)",
            ),
            ("8d80ff0a", "multiSend(bytes)"),
        ] {
            assert_eq!(hex::encode(signature(text).selector()), selector, "{text}");
        }
    }

    /// One spelling per rule set, so the policy file's digest — which a grant is bound to —
    /// names one rule set and not a family of them. Every form below produces the same selector
    /// and is nonetheless refused, and the refusal names the text the operator must write.
    #[test]
    fn a_non_canonical_signature_is_refused() {
        for declared in [
            "transfer(address to, uint256 amount)",
            "function transfer(address,uint256)",
            "transfer(address,uint)",
            "transfer(address,uint256) returns (bool)",
        ] {
            let refused = Signature::try_from(declared.to_string());
            assert!(
                matches!(
                    &refused,
                    Err(RuleErr::NotCanonical { canonical, .. })
                        if canonical == "transfer(address,uint256)"
                ),
                "{declared} must be refused"
            );
        }
        assert!(matches!(
            Signature::try_from("not a signature".to_string()),
            Err(RuleErr::Parse(_))
        ));
    }

    /// Two different signatures can be ground to share a 4-byte selector, and a payload matching
    /// both would leave the decoder to pick a shape. Both at one destination is a refusal to
    /// load, not a coin flip at request time.
    #[test]
    fn two_signatures_sharing_a_selector_refuse_to_load() {
        let one = signature("transfer(address,uint256)");
        let other = Signature {
            function: one.function.clone(),
            selector: one.selector,
            canonical: "gasprice_bit_ether(int128)".to_string(),
        };
        assert!(matches!(
            check_call_rules(&[
                CallRule {
                    signature: one,
                    arg: vec![
                        arg(0, "to", FieldRule::Unbounded),
                        arg(1, "amount", FieldRule::Unbounded),
                    ],
                },
                CallRule {
                    signature: other,
                    arg: vec![arg(0, "x", FieldRule::Unbounded)],
                },
            ]),
            Err(RuleErr::DuplicateSelector { .. })
        ));
    }

    /// An operator who declares a call and forgets one of its arguments has written an infinite
    /// approval, so every declared position must carry a rule and every rule must be one its
    /// Solidity type can satisfy. `multiSend`'s packed payload is the one argument no ceiling
    /// describes, and it must be declared as the batch it is rather than as unbounded.
    #[test]
    fn a_rule_set_that_leaves_an_argument_free_is_refused() {
        assert!(matches!(
            check_call_rules(&[call_rule(
                "transfer(address,uint256)",
                vec![arg(0, "to", FieldRule::OneOf { addresses: vec![A] })],
            )]),
            Err(RuleErr::ArgUnruled { at: 1, .. })
        ));
        assert!(matches!(
            check_call_rules(&[call_rule(
                "changeThreshold(uint256)",
                vec![
                    arg(0, "threshold", FieldRule::Unbounded),
                    arg(1, "ghost", FieldRule::Unbounded),
                ],
            )]),
            Err(RuleErr::ArgOutOfRange {
                at: 1,
                arity: 1,
                ..
            })
        ));
        assert!(matches!(
            check_call_rules(&[call_rule(
                "transfer(address,uint256)",
                vec![
                    arg(0, "to", FieldRule::Unbounded),
                    arg(0, "to_again", FieldRule::Unbounded),
                ],
            )]),
            Err(RuleErr::ArgDuplicated { at: 0, .. })
        ));
        assert!(matches!(
            check_call_rules(&[call_rule(
                "transfer(address,uint256)",
                vec![
                    arg(0, "same", FieldRule::Unbounded),
                    arg(1, "same", FieldRule::Unbounded),
                ],
            )]),
            Err(RuleErr::ArgNameNotUnique { .. })
        ));
        assert!(matches!(
            check_call_rules(&[call_rule(
                "transfer(address,uint256)",
                vec![
                    arg(0, "to", FieldRule::Unbounded),
                    arg(
                        1,
                        "amount",
                        FieldRule::OneOf {
                            addresses: vec![A, B]
                        },
                    ),
                ],
            )]),
            Err(RuleErr::RuleTypeMismatch { at: 1, .. })
        ));
        assert!(matches!(
            check_call_rules(&[call_rule(
                MULTI_SEND,
                vec![arg(0, "transactions", FieldRule::Unbounded)],
            )]),
            Err(RuleErr::BatchRuleMissing { .. })
        ));
        assert!(matches!(
            check_call_rules(&[call_rule(
                "safeTransferFrom(address,address,uint256,bytes)",
                vec![
                    arg(0, "from", FieldRule::Unbounded),
                    arg(1, "to", FieldRule::Unbounded),
                    arg(2, "tokenId", FieldRule::Unbounded),
                    arg(3, "data", FieldRule::Batch),
                ],
            )]),
            Err(RuleErr::BatchRuleMisplaced { at: 3, .. })
        ));
        assert!(check_call_rules(&[call_rule(
            MULTI_SEND,
            vec![arg(0, "transactions", FieldRule::Batch)],
        )])
        .is_ok());
    }

    /// Every constraint the rule language can express, each refused one step outside its bound
    /// and accepted one step inside it — and `unbounded` accepting all of them, which is why it
    /// has to be typed out and why it raises a note the summary prints.
    #[test]
    fn a_constraint_violating_field_is_refused() {
        let now = 1_000_000u64;
        let mut walk = FieldWalk::new(now, &[]);

        assert!(walk
            .field(
                "to",
                &FieldRule::OneOf { addresses: vec![A] },
                &DynSolValue::Address(A)
            )
            .is_ok());
        assert!(matches!(
            walk.field(
                "to",
                &FieldRule::OneOf { addresses: vec![A] },
                &DynSolValue::Address(B)
            ),
            Err(FieldDenied::AddressNotAllowed { .. })
        ));

        let ceiling = FieldRule::Max {
            max: U256::from(100u64),
            amount_of: A,
        };
        assert!(walk
            .field(
                "amount",
                &ceiling,
                &DynSolValue::Uint(U256::from(100u64), 256)
            )
            .is_ok());
        assert!(matches!(
            walk.field(
                "amount",
                &ceiling,
                &DynSolValue::Uint(U256::from(101u64), 256)
            ),
            Err(FieldDenied::ValueTooHigh { .. })
        ));

        let exact = FieldRule::Eq {
            eq: U256::from(7u64),
        };
        assert!(matches!(
            walk.field("n", &exact, &DynSolValue::Uint(U256::from(8u64), 256)),
            Err(FieldDenied::ValueNotExact { .. })
        ));

        let revoke = FieldRule::BoolEq { eq: false };
        assert!(walk
            .field("approved", &revoke, &DynSolValue::Bool(false))
            .is_ok());
        assert!(matches!(
            walk.field("approved", &revoke, &DynSolValue::Bool(true)),
            Err(FieldDenied::BoolNotExact { .. })
        ));

        let deadline = FieldRule::Deadline { within_secs: 1_800 };
        assert!(walk
            .field(
                "d",
                &deadline,
                &DynSolValue::Uint(U256::from(now + 1_800), 256)
            )
            .is_ok());
        assert!(matches!(
            walk.field(
                "d",
                &deadline,
                &DynSolValue::Uint(U256::from(now + 1_801), 256)
            ),
            Err(FieldDenied::DeadlineTooFar { .. })
        ));

        let named = FieldRule::Enum {
            one_of: vec!["buy".to_string()],
        };
        assert!(matches!(
            walk.field("side", &named, &DynSolValue::String("sell".to_string())),
            Err(FieldDenied::StringNotAllowed { .. })
        ));

        let each = FieldRule::Each {
            max_len: 2,
            of: Box::new(FieldRule::OneOf { addresses: vec![A] }),
        };
        let two = DynSolValue::Array(vec![DynSolValue::Address(A), DynSolValue::Address(A)]);
        assert!(walk.field("hops", &each, &two).is_ok());
        let three = DynSolValue::Array(vec![
            DynSolValue::Address(A),
            DynSolValue::Address(A),
            DynSolValue::Address(A),
        ]);
        assert!(matches!(
            walk.field("hops", &each, &three),
            Err(FieldDenied::TooManyElements { .. })
        ));
        let stranger = DynSolValue::Array(vec![DynSolValue::Address(B)]);
        assert!(matches!(
            walk.field("hops", &each, &stranger),
            Err(FieldDenied::AddressNotAllowed { path, .. }) if path == "hops[0]"
        ));

        assert!(matches!(
            walk.field("to", &exact, &DynSolValue::Address(A)),
            Err(FieldDenied::TypeNotExpected { .. })
        ));

        for value in [
            DynSolValue::Address(B),
            DynSolValue::Uint(U256::MAX, 256),
            DynSolValue::Bool(true),
            three,
        ] {
            assert!(walk.field("free", &FieldRule::Unbounded, &value).is_ok());
        }
        let notes = walk.notes();
        assert_eq!(
            notes
                .iter()
                .filter(|n| matches!(n, FieldNote::Unbounded { path } if path == "free"))
                .count(),
            4,
            "every unbounded field must be noted where the human reads it"
        );
    }

    /// A term the rule language does not name must be a refusal, which is the whole reason the
    /// rule is externally tagged: `deny_unknown_fields` is inert on an internally tagged enum, so
    /// `{ kind = "unbounded", max = "100" }` would have parsed as an unbounded field carrying a
    /// ceiling nobody enforces. Two kinds at once and an unknown kind must die the same way.
    #[test]
    fn a_term_the_rule_language_does_not_name_is_refused() {
        #[derive(Deserialize)]
        struct Holder {
            rule: FieldRule,
        }
        let held: Holder = toml::from_str(
            "rule = { max = { max = \"1000000000\", amount_of = \
             \"0x2222222222222222222222222222222222222222\" } }\n",
        )
        .expect("a bounded rule parses from TOML");
        assert!(matches!(
            held.rule,
            FieldRule::Max { max, .. } if max == U256::from(1_000_000_000u64)
        ));

        let hex: Holder = toml::from_str("rule = { eq = { eq = \"0xff\" } }\n")
            .expect("this repo's u256 codec still accepts hex inside a rule");
        assert!(matches!(hex.rule, FieldRule::Eq { eq } if eq == U256::from(255u64)));

        for refused in [
            "rule = { unbounded = { max = \"100\" } }\n",
            "rule = { max = { max = \"1\", amount_of = \"0x2222222222222222222222222222222222222222\", ghost = 1 } }\n",
            "rule = { nonsense = {} }\n",
            "rule = { eq = { eq = 1 }, unbounded = {} }\n",
        ] {
            assert!(
                toml::from_str::<Holder>(refused).is_err(),
                "an unrecognised term must be a refusal: {refused}"
            );
        }
    }
}
