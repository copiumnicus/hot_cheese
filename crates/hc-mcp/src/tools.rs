//! The six tools. Five read; one writes, and only through [`Proposal`].
//!
//! The exposed surface is not a transaction encoder. The two transaction tools take
//! [`Erc20Transfer`] — seven fields, `deny_unknown_fields` — and the SERVER builds the calldata
//! from them, with its own one-function `sol!` declaration below. The signer no longer shares
//! that declaration: it decodes against the canonical signature the OPERATOR declared in the
//! key's policy. What keeps the two from disagreeing is stronger than sharing a type — a
//! mismatch is a REFUSAL. Bytes this server encodes that the policy does not declare as
//! `transfer(address,uint256)` never admit at all, and bytes that admit re-encode to exactly
//! what was proposed or `EncodingNotCanonical` refuses them. Everything else in the Safe
//! transaction is fixed here: `to` is the token, `value` is zero, the operation is a plain
//! [`Operation::Call`], and all five gas-refund fields are zero.
//!
//! What an agent therefore CANNOT express, rather than merely has denied: arbitrary calldata,
//! `delegatecall`, any owner or threshold rotation, any gas refund, and any native-value
//! transfer. Policy still runs on top of that — this narrowing is defence in depth beneath it,
//! not a replacement for it, and a policy gap can no longer be reached by a shape the surface
//! will not carry.
//!
//! The library stays general: [`SafeTxIntent`], `hc_bundle::new`, `hc_sign::sign::prepare` and
//! the console and CLI paths are untouched and still take any Safe transaction. Only this
//! server's surface is narrow.
//!
//! Extending it: a new supported transaction shape gets its OWN tool with its own constrained
//! arguments. Never widen one of these, and never add a generic escape hatch — an escape hatch
//! would put the whole surface back.
use crate::proposal::{slot_held, Proposal};
use crate::McpErr;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolCall};
use err_mac::create_err_with_impls;
use hc_bundle::sync::SyncMode;
use hc_bundle::Safes;
use hc_core::config::Config;
use hc_sign::adapter;
use hc_sign::intent::{Operation, SafeTxIntent};
use hc_sign::policy::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

sol! {
    interface Erc20 {
        function transfer(address to, uint256 amount);
    }
}

create_err_with_impls!(
    #[derive(Debug)]
    pub CallErr,
    Params(serde_json::Error),
    Tool(McpErr)
    ;
);

/// What an agent may ask for. A name this enum does not carry is a `-32601`, never a silent
/// no-op, and only [`Tool::ProposeErc20Transfer`] writes anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tool {
    ListSafes,
    ListSigningKeys,
    ListBundles,
    BundleStatus,
    PreviewErc20Transfer,
    ProposeErc20Transfer,
}

impl Tool {
    /// Every tool, in the order the listing publishes them.
    pub const ALL: [Tool; 6] = [
        Tool::ListSafes,
        Tool::ListSigningKeys,
        Tool::ListBundles,
        Tool::BundleStatus,
        Tool::PreviewErc20Transfer,
        Tool::ProposeErc20Transfer,
    ];

    /// Deserialize this tool's arguments, then run it. The parse is the whole boundary: what
    /// fails here is a malformed call the model must fix, and what fails inside is a refusal
    /// the model can correct and retry.
    pub fn call(self, arguments: Value) -> Result<Value, CallErr> {
        Ok(match self {
            Tool::ListSafes => list_safes()?,
            Tool::ListSigningKeys => list_signing_keys()?,
            Tool::ListBundles => list_bundles()?,
            Tool::BundleStatus => bundle_status(serde_json::from_value(arguments)?)?,
            Tool::PreviewErc20Transfer => {
                preview_erc20_transfer(serde_json::from_value(arguments)?)?
            }
            Tool::ProposeErc20Transfer => {
                propose_erc20_transfer(serde_json::from_value(arguments)?)?
            }
        })
    }

    fn describe(self) -> Value {
        match self {
            Tool::ListSafes => json!({
                "name": "list_safes",
                "description": "Every Safe this machine collects signatures for, from bundles/safes.toml: address, chain id, the number of owner signatures execTransaction requires, and the owner addresses. Read-only.",
                "inputSchema": no_arguments(),
            }),
            Tool::ListSigningKeys => json!({
                "name": "list_signing_keys",
                "description": "Every local signing key and the policy that bounds it: the Safe and chain it is pinned to, the destinations and the full canonical signatures it may call there, the native-value ceiling per rule, whether owner/threshold rotation is permitted, the EIP-712 schemas it may sign, and whether gas refunds are opted in. Key addresses are deliberately NOT returned: deriving one decrypts a keystore and prompts the operator for Touch ID. Owner addresses come from list_safes. Read-only.",
                "inputSchema": no_arguments(),
            }),
            Tool::ListBundles => json!({
                "name": "list_bundles",
                "description": "Every proposal waiting for signatures, grouped by the (Safe, chain, nonce) slot it competes for. A slot holding more than one bundle is flagged as a rival pair: a Safe executes each nonce exactly once, so whichever lands first burns the other. This is how you find a free nonce. Read-only, and does not contact the co-signing machines.",
                "inputSchema": no_arguments(),
            }),
            Tool::BundleStatus => json!({
                "name": "bundle_status",
                "description": "One proposal in detail: its fields, who has signed, which owners are still missing, what else claims its nonce, and the decoded summary the operator will read on the approval prompt. Read-only.",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["hash"],
                    "properties": {
                        "hash": {
                            "type": "string",
                            "description": "The bundle's safeTxHash, 0x-prefixed, exactly as list_bundles reports it.",
                        },
                    },
                },
            }),
            Tool::PreviewErc20Transfer => json!({
                "name": "preview_erc20_transfer",
                "description": "Judge one ERC-20 transfer and write NOTHING: returns the safeTxHash owners would sign, the decoded summary, whether the key's policy allows it (or the exact typed refusal with the offending values), whether the Safe is known here, and whether the nonce is already claimed. Call this before propose_erc20_transfer; it costs the operator nothing.",
                "inputSchema": erc20_transfer_schema(),
            }),
            Tool::ProposeErc20Transfer => json!({
                "name": "propose_erc20_transfer",
                "description": "File one ERC-20 transfer into the operator's review queue: the Safe calls transfer(recipient, amount) on token. This is the ONLY transaction shape this server can express and the only verb here that writes. THIS DOES NOT SIGN AND CANNOT SIGN. It runs the same policy check the signer runs and, only if that passes, writes an unsigned bundle and pushes it to the co-signing machines. A human then reads the decoded summary and approves with Touch ID; nothing reachable from here can do that for them. The server builds the calldata itself, sends no native currency, uses a plain CALL and never a delegatecall, and zeroes every gas-refund field — so no other transaction can be described through this tool at all. A refusal comes back as a tool error naming what was wrong, so you can correct it and retry; a refused proposal writes nothing at all.",
                "inputSchema": erc20_transfer_schema(),
            }),
        }
    }
}

/// The published surface: every tool, its description, and its JSON Schema.
pub fn listing() -> Value {
    let mut tools = Vec::with_capacity(Tool::ALL.len());
    for tool in Tool::ALL {
        tools.push(tool.describe());
    }
    json!({ "tools": tools })
}

/// A tool that takes nothing at all.
fn no_arguments() -> Value {
    json!({"type": "object", "additionalProperties": false, "properties": {}})
}

/// [`Erc20Transfer`] described for the model. `additionalProperties: false` mirrors the
/// `deny_unknown_fields` the deserializer actually enforces, and every field is required
/// because none of them has a default: there is nothing here the model may leave to the server.
fn erc20_transfer_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["key", "safe", "chain_id", "token", "recipient", "amount", "nonce"],
        "properties": {
            "key": {
                "type": "string",
                "description": "Local keystore name that will sign, made of [A-Za-z0-9_] only. Its policy file decides what may be signed; list the names and their policies with list_signing_keys.",
            },
            "safe": {
                "type": "string",
                "description": "0x-prefixed address of the Safe the tokens leave. Must be one list_safes returns, and must be the Safe the key's policy is pinned to.",
            },
            "chain_id": {
                "type": ["string", "integer"],
                "description": "Chain id as a decimal integer, or a decimal / 0x-hex string. Must equal the chain the key's policy pins.",
            },
            "token": {
                "type": "string",
                "description": "0x-prefixed address of the ERC-20 contract. This is the address the Safe calls, so it is the destination the key's policy must allow-list.",
            },
            "recipient": {
                "type": "string",
                "description": "0x-prefixed address that receives the tokens.",
            },
            "amount": {
                "type": ["string", "integer"],
                "description": "How many tokens, as a RAW INTEGER in the token's own base units — not a human decimal quantity. hot_cheese has no RPC client, so it cannot read the token's decimals and cannot scale this for you: 1 USDC at 6 decimals is 1000000, and 1 DAI at 18 decimals is 1000000000000000000. Decimal integer, or a decimal / 0x-hex string.",
            },
            "nonce": {
                "type": ["string", "integer"],
                "description": "The Safe's own nonce. hot_cheese has no RPC client and cannot read it from the chain, so you must supply it: call list_bundles and take a nonce no slot has claimed. Two proposals under one nonce are mutually exclusive and one of them will be wasted.",
            },
        },
    })
}

/// The only transaction shape this server exposes: one ERC-20 `transfer` out of one Safe.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Erc20Transfer {
    /// Local keystore name that will sign, `[A-Za-z0-9_]+`.
    key: String,
    /// The Safe the tokens leave.
    safe: Address,
    #[serde(with = "hc_core::wire::u256")]
    chain_id: U256,
    /// The ERC-20 contract, which is also the address the Safe calls.
    token: Address,
    /// Who receives the tokens.
    recipient: Address,
    /// How many tokens, as a raw integer in the token's own base units.
    #[serde(with = "hc_core::wire::u256")]
    amount: U256,
    /// The Safe's next nonce.
    #[serde(with = "hc_core::wire::u256")]
    nonce: U256,
}

impl Erc20Transfer {
    /// The one place these seven fields become a Safe transaction, so it is also the one place
    /// the key name is checked before it is joined onto a policy path. Everything the arguments
    /// do not carry is fixed here rather than defaulted, which is what makes the shapes this
    /// server cannot express unreachable instead of merely unset.
    fn intent(self) -> Result<SafeTxIntent, McpErr> {
        if !hc_core::is_valid_string_name(&self.key) {
            return Err(McpErr::InvalidKeyName { key: self.key });
        }
        let data = Erc20::transferCall {
            to: self.recipient,
            amount: self.amount,
        }
        .abi_encode();
        Ok(SafeTxIntent {
            key: self.key,
            safe: self.safe,
            chain_id: self.chain_id,
            to: self.token,
            value: U256::ZERO,
            data: Bytes::from(data),
            operation: Operation::Call,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: self.nonce,
        })
    }
}

/// One Safe as `safes.toml` describes it.
#[derive(Serialize)]
struct SafeView {
    address: Address,
    #[serde(with = "hc_core::wire::u256")]
    chain_id: U256,
    /// Owner signatures `execTransaction` requires.
    threshold: u8,
    owners: Vec<Address>,
}

/// One permitted destination.
#[derive(Serialize)]
struct RuleView {
    to: Address,
    /// The canonical signatures permitted here, which is also what the daemon decodes against.
    signatures: Vec<String>,
    #[serde(with = "hc_core::wire::u256")]
    max_value: U256,
    operation: Operation,
}

/// Whether the key may rotate its Safe's owners, and with which calls.
#[derive(Serialize)]
struct OwnerMgmtView {
    allow: bool,
    signatures: Vec<String>,
}

/// One key's policy, and never its address: deriving one decrypts a keystore.
#[derive(Serialize)]
struct KeyView {
    /// The name a transfer's `key` field must carry.
    name: String,
    safe: Address,
    #[serde(with = "hc_core::wire::u256")]
    chain_id: U256,
    allow: Vec<RuleView>,
    owner_management: OwnerMgmtView,
    /// EIP-712 message schemas this key may sign, by name.
    typed_data: Vec<String>,
    /// Whether the policy opts in to Safe gas refunds at all.
    refunds_configured: bool,
}

/// One bundle in a slot.
#[derive(Serialize)]
struct BundleView {
    hash: B256,
    /// The local keystore the bundle names; a device may rebind it when it signs.
    key: String,
    signatures: usize,
    threshold: u8,
    met: bool,
    created_at_ms: u64,
}

/// One (Safe, chain, nonce) and everything competing for it.
#[derive(Serialize)]
struct SlotView {
    safe: Address,
    #[serde(with = "hc_core::wire::u256")]
    chain_id: U256,
    #[serde(with = "hc_core::wire::u256")]
    nonce: U256,
    /// Whether more than one bundle claims this slot; whichever lands first burns the rest.
    rival: bool,
    bundles: Vec<BundleView>,
}

/// The bundle's `safeTxHash`, which is also its directory name.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HashArg {
    hash: B256,
}

/// The approval text of a stored proposal, or the fact that there is none: a bundle only has a
/// summary if it still admits under the policy in force, and a policy edited after it was filed
/// can take that away.
#[derive(Serialize)]
#[serde(tag = "summary", rename_all = "snake_case")]
enum SummaryView {
    /// The decoded text the operator reads before approving.
    Decoded { text: String },
    /// The policy in force refuses this proposal, so there is nothing to approve and nothing to
    /// read. `preview_erc20_transfer` reports the typed refusal for a transfer you can re-file.
    Refused,
}

/// The merged view of one bundle, in the words the approval prompt will use.
#[derive(Serialize)]
struct StatusView {
    hash: B256,
    summary: SummaryView,
    intent: SafeTxIntent,
    signers: Vec<Address>,
    threshold: u8,
    /// What `safes.toml` states today; a difference means the Safe changed under the bundle.
    safes_threshold: u8,
    met: bool,
    not_owners: Vec<Address>,
    missing: Vec<Address>,
    rivals: Vec<B256>,
    age_ms: u64,
}

/// What the policy says, without spending a write or a biometric.
#[derive(Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
enum Verdict {
    Allowed,
    /// The typed refusal, carrying the values that caused it.
    Denied {
        denial: String,
    },
}

/// A judged transfer that was not stored.
#[derive(Serialize)]
struct PreviewView {
    /// The EIP-712 digest every owner would sign, rebuilt from the intent the server built.
    safe_tx_hash: B256,
    summary: SummaryView,
    policy: Verdict,
    /// Whether `safes.toml` describes this (Safe, chain); an unknown one cannot be filed.
    safe_known: bool,
    /// Digests already claiming this (Safe, chain, nonce). Non-empty means pick another nonce.
    slot_taken: Vec<B256>,
}

/// A transfer that reached the review queue, and nothing more than that.
#[derive(Serialize)]
struct ProposedView {
    hash: B256,
    summary: String,
}

/// The canonical signatures of one destination's rules, which is the text an operator writes
/// into the policy file and the text the daemon decodes against.
fn signatures(rules: &[hc_sign::schema::CallRule]) -> Vec<String> {
    let mut out = Vec::with_capacity(rules.len());
    for rule in rules {
        out.push(rule.signature.canonical().to_string());
    }
    out
}

fn list_safes() -> Result<Value, McpErr> {
    let mut out = Vec::new();
    for entry in Safes::load()?.safe {
        out.push(SafeView {
            address: entry.address,
            chain_id: entry.chain_id,
            threshold: entry.threshold,
            owners: entry.owners,
        });
    }
    Ok(serde_json::to_value(out)?)
}

/// Every `<store>/policies/*.toml`, ascending by name. A policy that will not load is skipped
/// LOUDLY rather than taking the listing down with it, the way a bundle directory is.
fn list_signing_keys() -> Result<Value, McpErr> {
    let store = Config::load()?.store_path();
    let dir = store.join("policies");
    let mut names = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)? {
            let file = entry?.file_name().to_string_lossy().to_string();
            let Some(name) = file.strip_suffix(".toml") else {
                continue;
            };
            names.push(name.to_string());
        }
    }
    names.sort();

    let mut out = Vec::new();
    for name in names {
        let policy = match Policy::load(&store, &name) {
            Ok(loaded) => loaded.policy,
            Err(e) => {
                tracing::warn!(%name, error = %e, "skipping a policy that will not load");
                continue;
            }
        };
        let mut allow = Vec::new();
        for rule in policy.allow {
            allow.push(RuleView {
                to: rule.to,
                signatures: signatures(&rule.call),
                max_value: rule.max_value,
                operation: rule.operation,
            });
        }
        out.push(KeyView {
            name,
            safe: policy.safe,
            chain_id: policy.chain_id,
            allow,
            owner_management: OwnerMgmtView {
                allow: policy.owner_management.allow,
                signatures: signatures(&policy.owner_management.call),
            },
            typed_data: policy.typed_data.iter().map(|s| s.schema.clone()).collect(),
            refunds_configured: policy.refunds.is_some(),
        });
    }
    Ok(serde_json::to_value(out)?)
}

fn list_bundles() -> Result<Value, McpErr> {
    let mut out = Vec::new();
    for (slot, loaded) in hc_bundle::list(SyncMode::Off)? {
        let mut bundles = Vec::new();
        for one in &loaded {
            bundles.push(BundleView {
                hash: one.hash,
                key: one.bundle.intent.key.clone(),
                signatures: one.bundle.signatures.len(),
                threshold: one.bundle.threshold,
                met: one.bundle.met(),
                created_at_ms: one.bundle.created_at_ms,
            });
        }
        out.push(SlotView {
            safe: slot.safe,
            chain_id: slot.chain_id,
            nonce: slot.nonce,
            rival: loaded.len() > 1,
            bundles,
        });
    }
    Ok(serde_json::to_value(out)?)
}

fn bundle_status(arg: HashArg) -> Result<Value, McpErr> {
    let config = Config::load()?;
    let status = hc_bundle::status(SyncMode::Off, arg.hash)?;
    let mut signers = Vec::new();
    for sig in &status.bundle.signatures {
        signers.push(sig.signer);
    }
    let summary = match Policy::load(&config.store_path(), &status.bundle.intent.key) {
        Ok(loaded) => summary_of(status.bundle.intent.clone(), &loaded, &config),
        Err(_) => SummaryView::Refused,
    };
    Ok(serde_json::to_value(StatusView {
        hash: status.hash,
        summary,
        signers,
        threshold: status.bundle.threshold,
        safes_threshold: status.safes_threshold,
        met: status.bundle.met(),
        intent: status.bundle.intent,
        not_owners: status.not_owners,
        missing: status.missing,
        rivals: status.rivals,
        age_ms: status.age_ms,
    })?)
}

/// The approval text of one intent under one policy, which exists only if the policy admits it.
/// It comes out of the signer's own `prepare`, so the text here is the text the operator will
/// read — there is no second renderer that could disagree with it.
fn summary_of(
    intent: SafeTxIntent,
    policy: &hc_sign::policy::LoadedPolicy,
    config: &Config,
) -> SummaryView {
    match hc_sign::sign::prepare(intent, policy, None, B256::ZERO, config) {
        Ok((_approved, text)) => SummaryView::Decoded { text },
        Err(_) => SummaryView::Refused,
    }
}

/// Judge a transfer and store nothing. The verdict runs the signer's own `prepare`, so it is the
/// same answer `propose_erc20_transfer` will get; a policy file that will not load is itself a
/// denial, because a policy that cannot be read has authorized nothing.
fn preview_erc20_transfer(transfer: Erc20Transfer) -> Result<Value, McpErr> {
    let intent = transfer.intent()?;
    let config = Config::load()?;
    let safe_known = Safes::load()?.find(intent.safe, intent.chain_id).is_ok();
    let (policy, summary) = match Policy::load(&config.store_path(), &intent.key) {
        Ok(loaded) => {
            match hc_sign::sign::prepare(intent.clone(), &loaded, None, B256::ZERO, &config) {
                Ok((_approved, text)) => (Verdict::Allowed, SummaryView::Decoded { text }),
                Err(e) => (
                    Verdict::Denied {
                        denial: e.to_string(),
                    },
                    SummaryView::Refused,
                ),
            }
        }
        Err(e) => (
            Verdict::Denied {
                denial: e.to_string(),
            },
            SummaryView::Refused,
        ),
    };
    Ok(serde_json::to_value(PreviewView {
        safe_tx_hash: adapter::safe_tx_hash(&intent),
        summary,
        policy,
        safe_known,
        slot_taken: slot_held(&intent)?,
    })?)
}

fn propose_erc20_transfer(transfer: Erc20Transfer) -> Result<Value, McpErr> {
    let proposal = Proposal::check(transfer.intent()?)?;
    let summary = proposal.summary().to_string();
    let hash = proposal.file()?;
    tracing::info!(%hash, "an agent filed a proposal; it is unsigned and needs a human");
    Ok(serde_json::to_value(ProposedView { hash, summary })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: Address = Address::new([0x22u8; 20]);
    const RECIPIENT: Address = Address::new([0x33u8; 20]);

    fn arguments() -> Value {
        json!({
            "key": "AGENT",
            "safe": "0x1111111111111111111111111111111111111111",
            "chain_id": 1,
            "token": TOKEN.to_string(),
            "recipient": RECIPIENT.to_string(),
            "amount": "1000000",
            "nonce": 7,
        })
    }

    /// The narrowing itself: seven fields in, and a Safe transaction out whose every other term
    /// is fixed rather than supplied. The calldata is checked against hand-built canonical
    /// ERC-20 `transfer` bytes — selector, recipient word, amount word — so a swapped argument
    /// order or a wrong `sol!` signature fails here rather than on a chain.
    #[test]
    fn the_built_intent_carries_only_a_plain_erc20_transfer() {
        let amount = U256::from(1_000_000u64);
        let intent = serde_json::from_value::<Erc20Transfer>(arguments())
            .expect("the narrow arguments parse")
            .intent()
            .expect("a valid key name builds an intent");

        assert_eq!(intent.to, TOKEN, "the Safe calls the token and nothing else");
        assert_eq!(intent.value, U256::ZERO);
        assert_eq!(intent.operation, Operation::Call);
        assert_eq!(intent.safe_tx_gas, U256::ZERO);
        assert_eq!(intent.base_gas, U256::ZERO);
        assert_eq!(intent.gas_price, U256::ZERO);
        assert_eq!(intent.gas_token, Address::ZERO);
        assert_eq!(intent.refund_receiver, Address::ZERO);

        let mut expected = Vec::with_capacity(68);
        expected.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(RECIPIENT.as_slice());
        expected.extend_from_slice(&word);
        expected.extend_from_slice(&amount.to_be_bytes::<32>());
        assert_eq!(intent.data.as_ref(), expected.as_slice());
    }

    /// The generic fields are gone from the surface, not merely denied downstream: an arguments
    /// object carrying one is refused at the parse, so an agent cannot smuggle arbitrary
    /// calldata, a delegatecall, native value, a gas refund or its own destination back in.
    #[test]
    fn a_generic_field_cannot_be_smuggled_back_in() {
        for smuggled in ["data", "operation", "value", "gas_price", "to"] {
            let mut args = arguments();
            args[smuggled] = json!("0x00");
            assert!(
                serde_json::from_value::<Erc20Transfer>(args).is_err(),
                "{smuggled} must not parse into the narrow arguments"
            );
        }
    }

    /// A key name is joined onto a policy path, so a name that is not `[A-Za-z0-9_]+` must die
    /// at the one place these arguments become an intent rather than reach the filesystem.
    #[test]
    fn a_traversing_key_name_never_reaches_a_policy_path() {
        let mut args = arguments();
        args["key"] = json!("../../../etc/passwd");
        let transfer =
            serde_json::from_value::<Erc20Transfer>(args).expect("a key is any string on the wire");
        assert!(matches!(
            transfer.intent(),
            Err(McpErr::InvalidKeyName { .. })
        ));
    }
}
