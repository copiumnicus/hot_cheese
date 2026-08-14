//! Admission for an EIP-712 message whose SHAPE the POLICY declared.
//!
//! A standard `eth_signTypedData_v4` payload carries `types`, `primaryType` and `domain`, and
//! hashing one of those would let the requester choose the field names a human reads and the
//! type string the digest commits to. So [`TypedDataIntent`] has no such fields at all: it names
//! a schema and supplies field VALUES, and a body carrying a shape fails to parse at the wire
//! boundary rather than being compared against something.
//!
//! Everything the digest depends on — the resolver, the domain, the struct name at every depth —
//! is a function of the policy file. The message is coerced ONCE, and that single value is both
//! what is hashed and what is rendered, so the digest signed is the digest read.
use super::{annotate, call, Alarm, Raised};
use crate::intent::TypedDataIntent;
use crate::policy::Policy;
use crate::schema::{
    FieldDecl, FieldDenied, FieldNote, FieldRule, FieldWalk, RuleErr, TypeDecl, TypedDataSchema,
};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::Eip712Domain;
use err_mac::create_err_with_impls;
use hc_core::config::Config;

create_err_with_impls!(
    #[derive(Debug)]
    pub TypedDenied,
    Rule(RuleErr),
    Abi(alloy_dyn_abi::Error)
    ;
    SchemaNotDeclared { schema: String },
    ChainMismatch { expected: U256, got: U256 },
    VerifyingContractMismatch { expected: Address, got: Address },
    PrimaryTypeNotAStruct { schema: String, primary_type: String },
    MessageNotAnObject { path: String },
    MessageNotAList { path: String },
    MessageFieldMissing { path: String, field: String },
    MessageFieldUnknown { path: String, field: String },
    FieldNotCoercible { path: String, declared: String, source: Box<alloy_dyn_abi::Error> },
    FixedBytesNotHex { path: String, source: alloy_primitives::hex::FromHexError },
    FixedBytesLength { path: String, declared: usize, got: usize },
    Field { source: FieldDenied }
);

/// An EIP-712 message admitted against a declared schema: the one coerced value, the digest
/// taken over it, and what the schema deliberately left free. Constructible only by [`admit`].
pub struct TypedMessage<'p> {
    schema: &'p TypedDataSchema,
    domain: Eip712Domain,
    /// The ONE coercion. Both the digest and the summary are derived from this value and from
    /// nothing else, so the two can never describe different messages.
    value: DynSolValue,
    digest: B256,
    notes: Vec<FieldNote>,
}

/// Deconstruct `intent` against the schema its key's policy declares, refusing anything the
/// declaration does not describe exactly. The raw JSON is walked BESIDE the coercion because
/// coercion erases two things it must not: an undeclared key is silently ignored, and a `bytesN`
/// is silently padded or truncated to N — so two different bodies would otherwise produce one
/// digest and one rendering.
pub fn admit<'p>(
    intent: &TypedDataIntent,
    policy: &'p Policy,
    now_secs: u64,
) -> Result<TypedMessage<'p>, TypedDenied> {
    let Some(schema) = policy.typed_data.iter().find(|s| s.schema == intent.schema) else {
        return Err(TypedDenied::SchemaNotDeclared {
            schema: intent.schema.clone(),
        });
    };
    if intent.chain_id != schema.domain.chain_id {
        return Err(TypedDenied::ChainMismatch {
            expected: schema.domain.chain_id,
            got: intent.chain_id,
        });
    }
    if intent.verifying_contract != schema.domain.verifying_contract {
        return Err(TypedDenied::VerifyingContractMismatch {
            expected: schema.domain.verifying_contract,
            got: intent.verifying_contract,
        });
    }

    let resolver = schema.resolver()?;
    let ty = resolver.resolve(&schema.primary_type)?;
    if !matches!(ty, DynSolType::CustomStruct { .. }) {
        return Err(TypedDenied::PrimaryTypeNotAStruct {
            schema: schema.schema.clone(),
            primary_type: schema.primary_type.clone(),
        });
    }
    check_json(&intent.message, &ty, &mut String::new())?;
    let value =
        ty.coerce_json(&intent.message)
            .map_err(|source| TypedDenied::FieldNotCoercible {
                path: String::new(),
                declared: schema.primary_type.clone(),
                source: Box::new(source),
            })?;

    let mut walk = FieldWalk::new(now_secs, &schema.types);
    let declared = declared_type(schema, &schema.primary_type)?;
    let DynSolValue::CustomStruct { tuple, .. } = &value else {
        return Err(TypedDenied::PrimaryTypeNotAStruct {
            schema: schema.schema.clone(),
            primary_type: schema.primary_type.clone(),
        });
    };
    for (field, inner) in declared.field.iter().zip(tuple) {
        walk.field(&field.name, &field.rule, inner)
            .map_err(|source| TypedDenied::Field { source })?;
    }

    let domain = schema.domain();
    let hash_struct = resolver.eip712_data_word(&value)?;
    let digest = digest(&domain, hash_struct);
    Ok(TypedMessage {
        schema,
        domain,
        value,
        digest,
        notes: walk.notes(),
    })
}

/// The EIP-712 signing hash: `keccak(0x19 0x01 ‖ domainSeparator ‖ hashStruct)`.
///
/// It shares no code with [`safe_tx_hash`](super::safe_tx_hash) deliberately. That one derives
/// its typehash from the compile-time `sol!` `SafeTx`, so what a Safe transaction IS cannot be
/// edited by an operator; this one derives its typehash from a policy file, which is the point.
fn digest(domain: &Eip712Domain, hash_struct: B256) -> B256 {
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain.separator().as_slice());
    buf[34..].copy_from_slice(hash_struct.as_slice());
    keccak256(buf)
}

fn declared_type<'p>(schema: &'p TypedDataSchema, name: &str) -> Result<&'p TypeDecl, TypedDenied> {
    schema
        .types
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| TypedDenied::PrimaryTypeNotAStruct {
            schema: schema.schema.clone(),
            primary_type: name.to_string(),
        })
}

/// Walk the RAW request JSON against the resolved declared type, refusing what coercion erases.
///
/// `custom_struct` coercion iterates the declared property names and never reads anything else,
/// so an undeclared key is invisible in the coerced value; `fixed_bytes` coercion copies
/// `min(N, supplied)` bytes into a zero word, so a short `bytes32` is padded and a long one is
/// truncated. Neither can be seen after coercion, and both let two different bodies read alike.
fn check_json(
    value: &serde_json::Value,
    ty: &DynSolType,
    path: &mut String,
) -> Result<(), TypedDenied> {
    match ty {
        DynSolType::CustomStruct {
            prop_names, tuple, ..
        } => {
            let Some(map) = value.as_object() else {
                return Err(TypedDenied::MessageNotAnObject { path: path.clone() });
            };
            for key in map.keys() {
                if !prop_names.contains(key) {
                    return Err(TypedDenied::MessageFieldUnknown {
                        path: path.clone(),
                        field: key.clone(),
                    });
                }
            }
            for (name, inner) in prop_names.iter().zip(tuple) {
                let Some(held) = map.get(name) else {
                    return Err(TypedDenied::MessageFieldMissing {
                        path: path.clone(),
                        field: name.clone(),
                    });
                };
                enter(path, name, |path| check_json(held, inner, path))?;
            }
            Ok(())
        }
        DynSolType::Array(inner) => {
            let Some(items) = value.as_array() else {
                return Err(TypedDenied::MessageNotAList { path: path.clone() });
            };
            for (n, item) in items.iter().enumerate() {
                enter(path, &format!("[{n}]"), |path| {
                    check_json(item, inner, path)
                })?;
            }
            Ok(())
        }
        DynSolType::FixedArray(inner, _) => {
            let Some(items) = value.as_array() else {
                return Err(TypedDenied::MessageNotAList { path: path.clone() });
            };
            for (n, item) in items.iter().enumerate() {
                enter(path, &format!("[{n}]"), |path| {
                    check_json(item, inner, path)
                })?;
            }
            Ok(())
        }
        DynSolType::Tuple(inner) => {
            let Some(items) = value.as_array() else {
                return Err(TypedDenied::MessageNotAList { path: path.clone() });
            };
            for (n, item) in items.iter().enumerate() {
                let Some(ty) = inner.get(n) else {
                    return Err(TypedDenied::MessageFieldUnknown {
                        path: path.clone(),
                        field: n.to_string(),
                    });
                };
                enter(path, &format!("[{n}]"), |path| check_json(item, ty, path))?;
            }
            Ok(())
        }
        DynSolType::FixedBytes(n) => {
            let Some(text) = value.as_str() else {
                return Ok(());
            };
            let supplied = alloy_primitives::hex::decode(text)
                .map_err(|source| TypedDenied::FixedBytesNotHex {
                    path: path.clone(),
                    source,
                })?
                .len();
            if supplied != *n {
                return Err(TypedDenied::FixedBytesLength {
                    path: path.clone(),
                    declared: *n,
                    got: supplied,
                });
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Run `body` with `step` appended to the dotted path, then put the path back.
fn enter<T>(
    path: &mut String,
    step: &str,
    body: impl FnOnce(&mut String) -> Result<T, TypedDenied>,
) -> Result<T, TypedDenied> {
    let mark = path.len();
    if !path.is_empty() && !step.starts_with('[') {
        path.push('.');
    }
    path.push_str(step);
    let out = body(path);
    path.truncate(mark);
    out
}

impl TypedMessage<'_> {
    /// The EIP-712 signing hash the grant is minted over and the key signs.
    pub fn digest(&self) -> B256 {
        self.digest
    }

    /// The human's only view of the message: the alarms first, worst-ranked first, then every
    /// declared field with the operator's own name beside the value that was coerced — the same
    /// value [`TypedMessage::digest`] was taken over.
    pub fn summary(&self, key: &str, config: &Config) -> String {
        let chain_id = self.schema.domain.chain_id;
        let mut raised = vec![Raised {
            alarm: Alarm::TypedMessage,
            at: String::new(),
        }];
        for note in &self.notes {
            raised.push(Raised {
                alarm: match note {
                    FieldNote::Unbounded { path } => Alarm::UnboundedField { path: path.clone() },
                    FieldNote::DeadlineFar { path, deadline } => Alarm::DeadlineFar {
                        path: path.clone(),
                        deadline: *deadline,
                    },
                },
                at: String::new(),
            });
        }
        raised.sort_by_key(|r| r.alarm.rank());

        let mut out = String::new();
        for one in &raised {
            out.push_str(&one.alarm.line(&one.at, chain_id, config));
            out.push('\n');
        }
        out.push_str(&self.schema.primary_type);
        self.fields(&mut out, &self.schema.primary_type, &self.value, 1, config);
        out.push_str(&format!(
            "\n  schema={schema} domain={domain} version={version} chain={chain}\n  \
             verifyingContract={contract}\n  key={key}",
            schema = self.schema.schema,
            domain = self.domain.name.as_deref().unwrap_or("<none>"),
            version = self.domain.version.as_deref().unwrap_or("<none>"),
            chain = chain_id,
            contract = annotate::address(self.schema.domain.verifying_contract, chain_id, config),
        ));
        out
    }

    /// Every declared field of `name`, in declaration order, indented under its struct. The
    /// order is the order `encodeData` hashes them in, so the nth line of the sheet is the nth
    /// word of the struct hash.
    fn fields(
        &self,
        out: &mut String,
        name: &str,
        value: &DynSolValue,
        depth: usize,
        config: &Config,
    ) {
        let Some(declared) = self.schema.types.iter().find(|t| t.name == name) else {
            return;
        };
        let DynSolValue::CustomStruct { tuple, .. } = value else {
            return;
        };
        for (field, inner) in declared.field.iter().zip(tuple) {
            out.push_str(&format!("\n{}{} = ", "  ".repeat(depth), field.name));
            self.nested(out, field, inner, depth, config);
        }
    }

    /// One field's value: a nested struct opens a deeper block, an integer under a `max` rule is
    /// scaled against the contract that rule names, and everything else renders by its own type.
    fn nested(
        &self,
        out: &mut String,
        field: &FieldDecl,
        value: &DynSolValue,
        depth: usize,
        config: &Config,
    ) {
        let chain_id = self.schema.domain.chain_id;
        match value {
            DynSolValue::CustomStruct { name, .. } => {
                out.push_str(name);
                self.fields(out, name, value, depth + 1, config);
            }
            DynSolValue::Uint(v, _) => match &field.rule {
                FieldRule::Max { amount_of, .. } => {
                    out.push_str(&annotate::amount(*v, *amount_of, chain_id, config))
                }
                _ => out.push_str(&annotate::count(*v)),
            },
            other => out.push_str(&call::plain(other, chain_id, config)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::tests::plain;
    use crate::policy::{OwnerMgmt, Policy};
    use alloy_dyn_abi::TypedData;
    use serde_json::json;

    const CONTRACT: Address = Address::new([0x99u8; 20]);
    const TOKEN: Address = Address::new([0xa0u8; 20]);
    const SPENDER: Address = Address::new([0x44u8; 20]);

    const SCHEMA: &str = concat!(
        "[[typed_data]]\n",
        "schema = \"permit2_usdc\"\n",
        "primary_type = \"PermitSingle\"\n",
        "\n",
        "  [typed_data.domain]\n",
        "  name = \"Permit2\"\n",
        "  chain_id = 1\n",
        "  verifying_contract = \"0x9999999999999999999999999999999999999999\"\n",
        "\n",
        "  [[typed_data.types]]\n",
        "  name = \"PermitSingle\"\n",
        "\n",
        "    [[typed_data.types.field]]\n",
        "    name = \"details\"\n",
        "    type = \"PermitDetails\"\n",
        "    rule = \"struct\"\n",
        "\n",
        "    [[typed_data.types.field]]\n",
        "    name = \"spender\"\n",
        "    type = \"address\"\n",
        "    rule = { one_of = { addresses = \
         [\"0x4444444444444444444444444444444444444444\"] } }\n",
        "\n",
        "    [[typed_data.types.field]]\n",
        "    name = \"sigDeadline\"\n",
        "    type = \"uint256\"\n",
        "    rule = { deadline = { within_secs = 1800 } }\n",
        "\n",
        "  [[typed_data.types]]\n",
        "  name = \"PermitDetails\"\n",
        "\n",
        "    [[typed_data.types.field]]\n",
        "    name = \"token\"\n",
        "    type = \"address\"\n",
        "    rule = { one_of = { addresses = \
         [\"0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0\"] } }\n",
        "\n",
        "    [[typed_data.types.field]]\n",
        "    name = \"amount\"\n",
        "    type = \"uint160\"\n",
        "    rule = { max = { max = \"1000000000\", amount_of = \
         \"0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0\" } }\n",
        "\n",
        "    [[typed_data.types.field]]\n",
        "    name = \"salt\"\n",
        "    type = \"bytes32\"\n",
        "    rule = \"unbounded\"\n",
    );

    const NOW: u64 = 1_000_000;

    fn policy() -> Policy {
        let text = format!(
            "safe = \"0x1111111111111111111111111111111111111111\"\nchain_id = 1\n\n{SCHEMA}"
        );
        let p: Policy = toml::from_str(&text).expect("the declared schema must load");
        crate::schema::check_schemas(&p.typed_data).expect("the declared schema must check");
        assert!(matches!(p.owner_management, OwnerMgmt { allow: false, .. }));
        p
    }

    fn message(amount: &str, salt: &str) -> serde_json::Value {
        json!({
            "details": {
                "token": TOKEN.to_string(),
                "amount": amount,
                "salt": salt,
            },
            "spender": SPENDER.to_string(),
            "sigDeadline": (NOW + 600).to_string(),
        })
    }

    fn intent(message: serde_json::Value) -> TypedDataIntent {
        TypedDataIntent {
            key: "TREASURY".to_string(),
            schema: "permit2_usdc".to_string(),
            chain_id: U256::from(1u64),
            verifying_contract: CONTRACT,
            message,
        }
    }

    /// The proof obligation of this module as an executable check: the digest taken over the ONE
    /// coerced value must equal the digest alloy computes for the same domain, the same resolver
    /// and the same message. Any future edit that lets the rendered value and the hashed value
    /// come from different coercions moves this.
    #[test]
    fn the_typed_digest_matches_alloys_own() {
        let p = policy();
        let body = message("1000000", &format!("0x{}", "11".repeat(32)));
        let admitted = admit(&intent(body.clone()), &p, NOW).expect("the message must admit");

        let schema = &p.typed_data[0];
        let alloy = TypedData {
            domain: schema.domain(),
            resolver: schema.resolver().expect("the resolver builds"),
            primary_type: schema.primary_type.clone(),
            message: body,
        };
        assert_eq!(
            admitted.digest(),
            alloy
                .eip712_signing_hash()
                .expect("alloy hashes the same message"),
        );
    }

    /// Coercion erases exactly two things, and both let two different request bodies produce one
    /// digest and one rendering: an undeclared key is never read, and a `bytesN` is padded or
    /// truncated to N. The raw-JSON walk beside the coercion is the whole mitigation, so each
    /// must be its own refusal — and a missing field must be refused before it is defaulted.
    #[test]
    fn coercion_looseness_is_closed_before_the_digest() {
        let p = policy();
        let good = format!("0x{}", "11".repeat(32));

        let mut extra = message("1000000", &good);
        extra["details"]["ghost"] = json!("1");
        assert!(matches!(
            admit(&intent(extra), &p, NOW),
            Err(TypedDenied::MessageFieldUnknown { .. })
        ));

        let mut missing = message("1000000", &good);
        missing["details"]
            .as_object_mut()
            .expect("details is an object")
            .remove("salt");
        assert!(matches!(
            admit(&intent(missing), &p, NOW),
            Err(TypedDenied::MessageFieldMissing { .. })
        ));

        for wrong in ["0xdeadbeef", &format!("0x{}", "11".repeat(64))] {
            assert!(
                matches!(
                    admit(&intent(message("1000000", wrong)), &p, NOW),
                    Err(TypedDenied::FixedBytesLength { .. })
                ),
                "a bytes32 of the wrong length must refuse: {wrong}"
            );
        }

        // The two short/long bodies would otherwise coerce to the SAME word.
        let short = format!("0x{}", "11".repeat(4));
        let padded = format!("0x{}{}", "11".repeat(4), "00".repeat(28));
        assert!(admit(&intent(message("1000000", &padded)), &p, NOW).is_ok());
        assert!(admit(&intent(message("1000000", &short)), &p, NOW).is_err());
    }

    /// The request may not describe its own shape, may not re-domain the message, and may not
    /// leave a declared bound behind: each is its own refusal, and all of them run before any
    /// human is asked.
    #[test]
    fn a_message_outside_its_declared_schema_is_refused() {
        let p = policy();
        let good = format!("0x{}", "11".repeat(32));

        let mut other = intent(message("1000000", &good));
        other.schema = "nothing_declared".to_string();
        assert!(matches!(
            admit(&other, &p, NOW),
            Err(TypedDenied::SchemaNotDeclared { .. })
        ));

        let mut chain = intent(message("1000000", &good));
        chain.chain_id = U256::from(137u64);
        assert!(matches!(
            admit(&chain, &p, NOW),
            Err(TypedDenied::ChainMismatch { .. })
        ));

        let mut contract = intent(message("1000000", &good));
        contract.verifying_contract = SPENDER;
        assert!(matches!(
            admit(&contract, &p, NOW),
            Err(TypedDenied::VerifyingContractMismatch { .. })
        ));

        assert!(matches!(
            admit(&intent(message("1000000001", &good)), &p, NOW),
            Err(TypedDenied::Field {
                source: FieldDenied::ValueTooHigh { .. }
            })
        ));

        let mut late = message("1000000", &good);
        late["sigDeadline"] = json!((NOW + 1_801).to_string());
        assert!(matches!(
            admit(&intent(late), &p, NOW),
            Err(TypedDenied::Field {
                source: FieldDenied::DeadlineTooFar { .. }
            })
        ));
    }

    /// Every field the operator declared has to reach the screen with the operator's own name
    /// beside the coerced value, and the field the schema left unbounded has to say so at the
    /// head of the sheet — that alarm is the only bound left on it.
    #[test]
    fn the_summary_shows_every_declared_field_and_its_unbounded_one() {
        let p = policy();
        let salt = format!("0x{}", "11".repeat(32));
        let admitted =
            admit(&intent(message("1000000", &salt)), &p, NOW).expect("the message must admit");
        let text = admitted.summary("TREASURY", &plain());
        assert!(text.starts_with("\u{26a0} UNBOUNDED FIELD"), "{text}");
        assert!(text.contains("[details.salt]"), "{text}");
        assert!(text.contains("\u{26a0} TYPED MESSAGE"), "{text}");
        assert!(text.contains("PermitSingle"), "{text}");
        assert!(text.contains("details = PermitDetails"), "{text}");
        assert!(text.contains(&format!("token = {TOKEN}")), "{text}");
        assert!(text.contains("amount = 1000000"), "{text}");
        assert!(text.contains(&format!("spender = {SPENDER}")), "{text}");
        assert!(text.contains("schema=permit2_usdc"), "{text}");
        assert!(text.contains("key=TREASURY"), "{text}");
        assert!(text.contains(&CONTRACT.to_string()), "{text}");
    }
}
