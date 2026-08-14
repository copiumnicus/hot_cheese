# Stage 6 — Typed-only admission: policy-declared signatures and EIP-712 schemas

Input: `docs/plans/00-design-decisions.md` (decision 7 and 7a–7e), `CLAUDE.md`, and the verified
ground truth in `docs/plans/05-sign-path-collapse.md` §B.0. This file **supersedes** the
typed-only half of `05`; `05`'s Half A (deleting the human raw-JSON sign path) is unchanged and
still runs first.

Every alloy API named below was read from the **pinned** source, downloaded from crates.io and
extracted during the writing of this plan (`alloy-dyn-abi-0.8.26`, `alloy-json-abi-0.8.26`,
`alloy-sol-types-0.8.26`, `alloy-sol-type-parser-0.8.26`). `err_mac` was read at the pinned rev
`08f6335`. Line references into those crates are to the extracted 0.8.26 sources. Where something
could not be established it is marked **VERIFY** and is not asserted.

---

## 0. What changed since `05`, and why the shape is different

`05` read decision 7 as "only the 19 functions in the `sol!` block are signable". The owner has
ruled otherwise: **policy declares full canonical signatures, and EIP-712 typed data becomes a
first-class intent kind with operator-declared schemas.**

That single change collapses `05`'s three-pass `prepare` (transaction authority → admission →
entry authority) into **one pass**, and the reason is structural rather than stylistic:

> Under `05`, the decoder had a fixed vocabulary and could decode a call before anyone asked
> whether it was allowed. Under 7a the decoder has **no vocabulary of its own** — the shape it
> decodes against is the one the matching policy rule declared. You cannot decode a call until
> you have found its rule, and finding its rule *is* the authority check.

So admission and authority are the same walk. `05` §B.1's `evaluate_entries` as a separate pass
after `admit` is not merely unnecessary, it is unimplementable: `admit` cannot produce a decoded
tree without consulting the policy for every node.

Everything `05` established about *today's* behaviour (§B.0 (a)–(e), the fallback table, the
alarm/renderer inventory, the `AdapterErr`-is-empty fact, the `prepare`-runs-before-the-approver
fact) is re-confirmed below where relied on, and is not re-derived.

### The two VERIFY items `05` left open, now resolved

1. **Distinguishing "unknown selector" from "known selector, arguments fail to decode" at
   `alloy-sol-types = "=0.8.26"`.** Both candidates `05` guessed at *do* exist at 0.8.26:
   `SolInterface::valid_selector(selector: [u8; 4]) -> bool`
   (`alloy-sol-types-0.8.26/src/types/interface/mod.rs:48`) and
   `alloy_sol_types::Error::UnknownSelector { name: &'static str, selector: FixedBytes<4> }`
   (`alloy-sol-types-0.8.26/src/errors.rs:63-68`, constructor at `:153-157`).
   **Neither is used by this plan**, because the `sol!` interface is deleted (§3). Under 7a the
   distinction is drawn one layer up and for free: "no declared signature in any matching rule
   has this selector" is `CallDenied::SignatureNotAllowed`, raised by the policy match; "the
   arguments do not decode against the declared signature" is `AdapterErr::ArgumentsNotDecodable`,
   raised by `Function::abi_decode_input`. Two different code paths, no shared `Option`.

2. **The `err_mac` macro arms at rev `08f6335`.** Read from a clone of
   `https://github.com/copiumnicus/err_mac.git` at that exact rev. The whole crate is one
   `macro_rules!`:

   - Form: `create_err_with_impls!($(#[meta])* $vis $Name, $(Variant $(($Type))?),* ; $(Variant { $field: $Type ),* },* );`
   - `impl From<$Type> for $Name` is generated **only** for tuple variants `Variant(Type)` before
     the `;`. Struct variants after the `;` get no `From`. `05`'s claim holds exactly.
   - `impl Display` is `write!(f, "{:?}", self)`. There is no `#[error(...)]` attribute and the
     macro does **not** implement `std::error::Error`. The variant name is the label; the fields
     carry the values. Nothing is ever formatted into an error string.
   - The empty-list-before-`;` form (`pub AdapterErr, ;`) and the empty-list-after-`;` form are
     both exercised in-repo today (`adapter/mod.rs:310-314`, `batch.rs:47-56`).

---

# PART 1 — CALLS (decision 7a)

## 1. The new policy rule format

### 1.1 The declared signature type

A new module `crates/hc-sign/src/schema.rs` holds the rule language shared by `policy`,
`manifest` and `adapter`. It depends on nothing in the crate, which is what keeps the module
graph acyclic (§3.3).

```rust
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
    type Error = SignatureErr;

    fn try_from(declared: String) -> Result<Self, SignatureErr> {
        let function = Function::parse(&declared)?;
        let canonical = function.signature();
        if canonical != declared {
            return Err(SignatureErr::NotCanonical {
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
```

`#[serde(try_from = "String")]` is a serde derive attribute, not a hand-written `Deserialize`
(`CLAUDE.md`).

**Verified API, at the pinned version:**

| Item | Where | What it does |
|---|---|---|
| `alloy_json_abi::Function::parse(&str) -> parser::Result<Function>` | `alloy-json-abi-0.8.26/src/item.rs:503` | parses `$(function)? name($($inputs),*) [visibility] [mutability] $(returns (…))?` |
| `Function::signature() -> String` | `item.rs:519-521` → `utils.rs:25-36` | `name(` + `Param::selector_type()` of each input, comma-joined, `)` |
| `Function::selector() -> Selector` | `item.rs:546-548` → `utils.rs:121-123` | `keccak256(signature())[..4]`; `Selector = FixedBytes<4>` |
| `RootType::parse("uint") == RootType("uint256")` | `alloy-sol-type-parser-0.8.26/src/root.rs:90`, doc-test `:28` | aliases normalise; the match arms are exactly `"uint" => "uint256"` and `"int" => "int256"` and nothing else (`byte` is **not** normalised and is not a resolvable type) |
| `parser::Error` | `alloy-json-abi-0.8.26/src/lib.rs:24` re-exports `alloy_sol_type_parser as parser` | the `#[from]`-nested parse failure |

The `canonical != declared` check is what makes the file text the single spelling. It rejects
`transfer(address to, uint256 amount)`, `function transfer(address,uint256)`,
`transfer(address,uint)` and `transfer(address,uint256) returns (bool)` — all of which
`Function::parse` accepts and all of which produce the same selector. One spelling means the
policy file's SHA-256 (`policy.rs:133`, which the grant is bound to, `grant.rs:94`) names one
rule set and not a family of them, and it means §1.4's duplicate-selector check compares strings
rather than heuristics. The refusal names both texts in fields, so the operator is told what to
write.

### 1.2 The rule

```rust
/// A permitted destination: the calls it may receive, a native-value ceiling, and the
/// required operation. A term this struct does not name is a refusal to load.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRule {
    pub to: Address,
    /// Calls permitted at this destination, each a full canonical signature plus its
    /// per-argument bounds.
    pub call: Vec<CallRule>,
    #[serde(default)]
    pub max_value: U256,
    #[serde(default)]
    pub operation: Operation,
}

/// One call shape and what its arguments may hold.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRule {
    /// The canonical signature; the 4-byte selector is derived from it.
    pub signature: Signature,
    /// One rule per declared argument, keyed by the argument's name in `signature`.
    pub arg: Vec<ArgRule>,
}

/// A bound on one named argument. `rule` has no default: an unbounded argument must be
/// typed out as `kind = "unbounded"`, so it can never be left unbounded by omission.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgRule {
    /// The argument's name, which must be one `signature` declares.
    pub name: String,
    pub rule: FieldRule,
}
```

`AllowRule.selectors: Vec<FixedBytes<4>>` (`policy.rs:55`) is **deleted**, not kept alongside
(decision 7a). `OwnerMgmt.selectors` (`policy.rs:67`) becomes `OwnerMgmt.call: Vec<CallRule>` for
the same reason.

`FieldRule` is the shared constraint enum, defined once in `schema.rs` and used by both halves;
its variants and evaluation are §9.

### 1.3 Before / after, one real policy file

**Before** — `<store>/policies/TREASURY.toml` as it is written today (this is the shape
`scripts/demo.sh:42-72` and `README.md:598-603` produce):

```toml
safe = "0x1111111111111111111111111111111111111111"
chain_id = 1

[[allow]]
to = "0x2222222222222222222222222222222222222222"
selectors = ["0xa9059cbb", "0x095ea7b3"]
max_value = "0"
operation = "call"
```

Everything about the two calls beyond four bytes each is unconstrained: `transfer` to any
recipient of any amount, `approve` to any spender of any amount including `U256::MAX`.

**After:**

```toml
safe = "0x1111111111111111111111111111111111111111"
chain_id = 1

[[allow]]
to = "0x2222222222222222222222222222222222222222"
max_value = "0"
operation = "call"

  [[allow.call]]
  signature = "transfer(address,uint256)"

    [[allow.call.arg]]
    name = "to"
    rule = { kind = "one_of", addresses = ["0x3333333333333333333333333333333333333333"] }

    [[allow.call.arg]]
    name = "amount"
    rule = { kind = "max", max = "1000000000", amount_of = "0x2222222222222222222222222222222222222222" }

  [[allow.call]]
  signature = "approve(address,uint256)"

    [[allow.call.arg]]
    name = "spender"
    rule = { kind = "one_of", addresses = ["0x4444444444444444444444444444444444444444"] }

    [[allow.call.arg]]
    name = "amount"
    rule = { kind = "max", max = "1000000000", amount_of = "0x2222222222222222222222222222222222222222" }
```

The `sol!` interface's argument names (`to`, `amount`, `spender`) were only ever renderer labels.
Here they are the operator's handle on the arguments, taken from the declared signature — and
that forces the declaration to carry names. `Function::parse("transfer(address,uint256)")`
produces `inputs` with **empty** names (`mk_param`, `alloy-json-abi-0.8.26/src/utils.rs:149-163`,
sets `name` from `Option<&str>::unwrap_or_default()`), while `signature()` strips names from its
output (`utils.rs:25-36` uses `Param::selector_type()`, `param.rs:261-269`, which is the type
only). So a canonical signature has no argument names at all.

**Resolution: arguments are addressed by position, not by name, and the name is the operator's
own label.** `ArgRule` becomes:

```rust
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgRule {
    /// Zero-based position in the declared signature.
    pub at: usize,
    /// The operator's label for this argument, shown to the human beside its value.
    pub name: String,
    pub rule: FieldRule,
}
```

with the load check (§1.4) requiring `at` to be in range, every position covered exactly once,
and `name` non-empty and unique inside the rule. The file above becomes:

```toml
  [[allow.call]]
  signature = "transfer(address,uint256)"

    [[allow.call.arg]]
    at = 0
    name = "to"
    rule = { kind = "one_of", addresses = ["0x3333333333333333333333333333333333333333"] }

    [[allow.call.arg]]
    at = 1
    name = "amount"
    rule = { kind = "max", max = "1000000000", amount_of = "0x2222222222222222222222222222222222222222" }
```

This is strictly better than the status quo for the property `call.rs:1-8` already insists on
("A SELECTOR IS NOT A CONTRACT"): the label a human reads now comes from the operator who wrote
the policy, not from a `sol!` block that guessed which standard was meant.

### 1.4 Load-time checks

`Policy::load` (`policy.rs:127-137`) already calls `no_duplicate_rules` after parsing. It gains,
in `schema.rs` so `manifest::check` runs the same code over `grants.calls`:

| Check | Refusal |
|---|---|
| two `CallRule`s in one `AllowRule` with the same `selector` | `PolicyErr::DuplicateSelector { to, selector, first: String, second: String }` |
| an `ArgRule.at` past `signature.function.inputs.len()` | `PolicyErr::ArgOutOfRange { signature: String, at, arity }` |
| a declared argument position with no `ArgRule` | `PolicyErr::ArgUnruled { signature: String, at }` |
| two `ArgRule`s at the same position | `PolicyErr::ArgDuplicated { signature: String, at }` |
| an empty or repeated `ArgRule.name` inside one `CallRule` | `PolicyErr::ArgNameNotUnique { signature: String, name }` |
| a `FieldRule` whose kind cannot apply to the declared Solidity type | `PolicyErr::RuleTypeMismatch { signature: String, at, declared: String, rule: FieldRuleKind }` |

The duplicate-selector check is the one that is not obvious and is the one worth a test: two
*different* canonical signatures can share a 4-byte selector, and a grinding attacker chooses
that collision. If both are declared at one destination, the decoder has two candidate shapes for
the same bytes and would have to pick — so the load refuses instead. (`no_duplicate_rules`
already establishes the pattern and the reasoning, `policy.rs:139-155`.)

`RuleTypeMismatch` is what stops `kind = "max"` on an `address` argument or
`kind = "one_of"` on a `uint256`. It is checked once at load against
`Param::resolve()` (`alloy_dyn_abi::Specifier`, reachable via `alloy-dyn-abi-0.8.26/src/ext/abi.rs:166`,
which calls `param.resolve()?` to get a `DynSolType`), not per request.

---

## 2. Decoding arguments against a **declared** signature

### 2.1 The crate that does it, and whether it is reachable

`alloy-sol-types`' `sol!` is a proc macro: a signature that arrives as policy text at runtime can
never reach it. The runtime counterpart is **`alloy-dyn-abi`**, which is part of the same
`alloy-core` release train and therefore **exists at exactly `0.8.26`**. Verified by download:

- `alloy-dyn-abi-0.8.26/Cargo.toml`: `description = "Run-time ABI and EIP-712 implementations"`,
  `license = "MIT OR Apache-2.0"`, `rust-version = "1.81"`.
- Its dependencies are `alloy-json-abi 0.8.26`, `alloy-primitives 0.8.26`,
  `alloy-sol-type-parser 0.8.26`, `alloy-sol-types 0.8.26`, `const-hex ^1.14`, `itoa ^1`,
  `winnow ^0.7`, and behind the `eip712` feature `derive_more ^2.0`, `serde`, `serde_json`.

**It is not a dependency today.** `crates/hc-sign/Cargo.toml` lists `alloy-primitives` and
`alloy-sol-types` only.

### 2.2 What must be added, checked against `deny.toml`

Workspace `Cargo.toml`, beside the two existing alloy pins:

```toml
alloy-dyn-abi = { version = "=0.8.26", features = ["eip712"] }
alloy-json-abi = "=0.8.26"
```

and in `crates/hc-sign/Cargo.toml`:

```toml
alloy-dyn-abi.workspace = true
alloy-json-abi.workspace = true
```

**Effect on the lock, item by item, read from `Cargo.lock`:**

| Requirement of `alloy-dyn-abi 0.8.26` | Already in `Cargo.lock`? |
|---|---|
| `alloy-json-abi 0.8.26` | yes, `Cargo.lock:62-71` (optional dep of `alloy-sol-types`) |
| `alloy-primitives 0.8.26` | yes, `:74-98` |
| `alloy-sol-type-parser 0.8.26` | yes, `:158-166` |
| `alloy-sol-types 0.8.26` | yes, `:168-179` |
| `const-hex ^1.14` | yes, 1.19.1 at `:837` |
| `itoa ^1` | yes, 1.0.14 at `:2078` |
| `winnow ^0.7` | yes, 0.7.15 at `:4344`, already pulled by `alloy-sol-type-parser` (`:165`) |
| `derive_more ^2.0` (eip712) | yes, 2.1.1 at `:1038`, already pulled by `alloy-primitives` (`:83`) and `crossterm` (`:916`) |
| `serde`, `serde_json` (eip712) | yes, pinned in the workspace |

`alloy-dyn-abi`'s two **optional** dependencies, `arbitrary ^1.3` and `proptest ^1`, are not
activated by `features = ["eip712"]`, and this `Cargo.lock` records only *activated* optional
dependencies — proved in-lock by `rustls 0.23.20`, whose optional `aws-lc-rs` is absent from its
dependency list (`Cargo.lock` `rustls` block) while its activated `ring` is present, and by
`arbitrary` being absent from the whole lock despite `alloy-primitives` declaring it optional.
So neither is pulled.

**`alloy-dyn-abi` is therefore the only new `[[package]]` entry.** Consequences for `deny.toml`:

- `[bans] multiple-versions = "deny"` — no new version of anything is introduced, so no new
  `skip` entry is needed. The three `winnow` versions already in the lock (0.5.40 via `toml_edit`,
  0.7.15 via `alloy-sol-type-parser`, 1.0.4 via `toml_edit`/`toml_parser`; name lines
  `Cargo.lock:4335,4344,4353`) are pre-existing and unaffected; this change does not add a fourth
  and does not move any of them.
  **Those three are not covered by any `skip` or `skip-tree` entry in `deny.toml`, so
  `cargo deny check bans` is already failing today, before this change.** The step-1 gate below is
  therefore stated as a *differential*, not as "clean" — see §16 step 1.
- `[bans] wildcards = "deny"` — the new lines are `=`-pinned, matching every other alloy pin.
- `[licenses] allow` — `MIT OR Apache-2.0`, both present in the allow list.
- `[sources] unknown-registry = "deny"` — crates.io, already the only registry in use.
- `[advisories]` — the two existing alloy-family ignores (`RUSTSEC-2024-0436` `paste`,
  `RUSTSEC-2026-0173` `proc-macro-error2`) are compile-time proc-macro advisories reached through
  `alloy-sol-macro`, which is already in the tree. `alloy-dyn-abi` pulls no proc macro of its own.

The `eip712` feature turns on `alloy-sol-types/eip712-serde`, which is
`["dep:serde", "alloy-primitives/serde"]` (`alloy-sol-types-0.8.26/Cargo.toml`). Both are already
enabled: the workspace pins `alloy-primitives` with `features = ["serde"]` and `alloy-sol-types`
already lists `serde` as a dependency (`Cargo.lock:178`). Zero new packages from the feature.

**Verification step at implementation time:** capture `cargo deny check` (all four checks) *before*
the dependency lands, then run it again after, and diff the two. The baseline is not clean — the
three `winnow` versions above violate `multiple-versions = "deny"` today — so the gate is "the
after-set of findings equals the before-set". If `deny` reports a **new** duplicate, a new
advisory, or a new licence, this plan is wrong about something and the step stops there.

### 2.3 The decode, concretely

```rust
use alloy_dyn_abi::{DynSolValue, JsonAbiExt};

let Some(sel) = selector4(&site.data) else { return Err(AdapterErr::NoCalldata { .. }) };
let rule: &CallRule = /* from the policy match, §4.1 */;
let args: Vec<DynSolValue> = rule.signature.function.abi_decode_input(&site.data[4..], true)?;
if rule.signature.function.abi_encode_input_raw(&args)? != site.data[4..] {
    return Err(AdapterErr::EncodingNotCanonical { .. });
}
```

**Verified API:**

| Item | Where | Signature |
|---|---|---|
| `JsonAbiExt::abi_decode_input` | `alloy-dyn-abi-0.8.26/src/ext/abi.rs:59`, impl for `Function` at `:119-134` | `fn abi_decode_input(&self, data: &[u8], validate: bool) -> Result<Vec<DynSolValue>>` |
| `JsonAbiExt::abi_encode_input_raw` | same trait, `:50` | `fn abi_encode_input_raw(&self, values: &[DynSolValue]) -> Result<Vec<u8>>` — no selector prefix |
| the decode body | `ext/abi.rs:183-192` | `Decoder::new(data, validate)` then `param.resolve()?` and `ty.abi_decode_inner(...)` per input |
| the encode body | `ext/abi.rs:158-181` | type-checks each value against `param.resolve()?` then `DynSolValue::encode_seq` |
| `DynSolValue` variants | `alloy-dyn-abi-0.8.26/src/dynamic/value.rs:61-97` | `Bool`, `Int(I256, usize)`, `Uint(U256, usize)`, `FixedBytes(Word, usize)`, `Address`, `Function`, `Bytes`, `String`, `Array`, `FixedArray`, `Tuple`, and `CustomStruct` under `eip712` |

`abi_decode_input` takes the **argument region only** — it does not check or strip a selector
(`ext/abi.rs:131-133` passes `data` straight to `abi_decode`). The caller slices `[4..]` after
matching the selector, which is exactly what the policy match already established.

The re-encode comparison preserves, byte for byte, the property today's `canonical()`
(`adapter/mod.rs:353-356`) exists for, and for the same reason its comment gives at `:347-352`:
`validate = true` only requires a `bool`'s first 31 bytes to be zero, so a trailing byte of `2`
decodes as `true`. Under 0.8.26 the same `Decoder` with the same `validate` flag is used
(`ext/abi.rs:185`), so the same hole is present and the same re-encode closes it.

The re-encode also carries a second load: `abi_decode` (`ext/abi.rs:183-192`) decodes each input
from one `Decoder` and **never checks that the decoder consumed all of `data`**. Trailing bytes
after the argument region are invisible to `abi_decode_input` at any `validate` setting; they are
caught only because `abi_encode_input_raw` reproduces the canonical length. Deleting the re-encode
would reopen a trailing-bytes channel, not merely a `bool` one.

### 2.4 If dynamic decoding had not been available

It is available; no alternative is needed. Stated because the brief asks: had `alloy-dyn-abi`
not existed at 0.8.26, the honest fallback would have been to keep the compile-time `sol!`
interface as the vocabulary and let policy declare only signatures **already in it** — which is
`05`'s model with a nicer spelling, and would not have delivered 7a. It is not being proposed.

---

## 3. The `sol!` block and the hand-written renderers

### 3.1 Deleted

**`interface Known { … }` (`adapter/mod.rs:25-45`) is deleted in full.** Its only job was to be
the decoder's vocabulary, and the vocabulary is now the policy. `CLAUDE.md`'s delete-dead-paths
rule is not merely permissive here, it is binding: keeping the interface as a "fast path" would
mean two decoders that can disagree, and the one that wins would be decided by a code path rather
than by the policy file — which is precisely the hole 7a closes.

Deleted with it:

| Item | Where | Why it dies |
|---|---|---|
| `Known::KnownCalls` and all 19 `…Call` types | `mod.rs:25-45` | the interface |
| `canonical()` | `mod.rs:353-356` | replaced by §2.3, which needs a declared signature |
| `SAFE_CONFIG` | `mod.rs:58-63` | built from `Known::…::SELECTOR` |
| `unlimited()` | `mod.rs:258-266` | matched on `Known::KnownCalls` variants; superseded by `FieldRule` (§9), which bounds every argument by declaration instead of alarming on four hard-coded shapes |
| `call::render`'s 19-arm `match` | `call.rs:56-147` | one arm per `Known` variant |
| `call::render`'s undecoded branch and `DIGEST_CHARS` | `call.rs:25-29,42-53` | there is no undecoded representation after this stage |
| `call::render`'s empty-data branch | `call.rs:39-41` | `NoCalldata` is a refusal (§4.2) |
| `Alarm::{DelegatecallUndecoded, BatchMalformed, SelfCallUndecoded, Undecoded}` | `mod.rs:106-142` | each names a state that is now a refusal |
| `Alarm::Batch`'s `undecoded`/`unexpanded` counters and the `unread` clause | `mod.rs:116-125,199-204` | both counts are structurally zero |
| `Alarm::Batch`'s `"none of them checked by policy"` text | `mod.rs:197-198` | false after this stage; it must change in the same commit that makes it false |
| `batch::unlistable` | `batch.rs:191-200` | a malformed batch is refused, never rendered |
| `batch::Body::{Undecoded, Unexpanded}` | `batch.rs:63,67` | the deletion that makes the refusal structural |
| `policy::selector4` | `policy.rs:157-163` | one selector helper survives, in `schema` |
| `Alarm::UnlimitedApproval` | `mod.rs:136`, `:232-236` | superseded: an unbounded argument is now declared as `kind = "unbounded"` and rendered as such (§9), so the alarm fires from the rule rather than from a guess about which four selectors matter |

**`Known` has one consumer outside `hc-sign`, and the plan must carry it.**
`crates/hc-mcp/src/tools.rs:31` is `use hc_sign::adapter::{self, Known};` and `tools.rs:219`
builds its ERC-20 calldata with `Known::transferCall { … }.abi_encode()`. Deleting
`interface Known` therefore **breaks `hc-mcp`'s build**, and it breaks a stated security property:
`tools.rs:1-22` says the server "builds the calldata from them with the same alloy `sol!`
declaration [`adapter::summary`] decodes against, so what is proposed and what the operator reads
can never disagree." Under 7a the decoder has no `sol!` left to share.

The replacement that keeps the property is for `hc-mcp` to declare its **own** one-function
`sol! { interface Erc20 { function transfer(address to, uint256 amount); } }` and for the
"can never disagree" claim to be re-grounded: the encoder is `hc-mcp`'s, the decoder is the
operator's declared `transfer(address,uint256)`, and what makes them agree is that a mismatch is a
**refusal** (`SignatureNotAllowed` / `EncodingNotCanonical`), not a silent divergence. That is a
strictly stronger property than sharing a type, and `tools.rs:1-22` must be rewritten to say so in
the same commit. This is step 4 work; it is not optional and it is not cosmetic.

**AUDIT:** the alternative — `hc-mcp` builds its calldata through `alloy-dyn-abi` from the same
`Signature` type the policy declares — removes the last `sol!` from the proposal surface but adds
`alloy-dyn-abi` to `hc-mcp`'s dependency closure, which `hc-core/tests/boundary.rs` pins. Own
`sol!` is the smaller change; decide before step 4.

### 3.2 Kept

**`struct SafeTx { … }` (`mod.rs:24`) stays**, and stays inside a `sol!` block. It is not
vocabulary; it is the definition of the digest, pinned against a hand-rolled EIP-712 encoding by
`safe_tx_hash_matches_hand_rolled_eip712` (`mod.rs:502-551`). Making it policy-declarable would
let an operator redefine what a Safe transaction *is*. That is the one place where compile-time
beats declaration, and §11 says so again for the typed-data digest.

`annotate.rs` stays **entirely unchanged** (decision 7e). Its callers change — `amount` is now
reached through `FieldRule::Max { amount_of }` and `address` through `FieldRule::OneOf` and the
site fields — but nothing in the module moves, and its two tests
(`a_label_is_appended_to_the_whole_address_never_substituted_for_it` `:101-114`,
`an_amount_shows_the_scaled_and_the_raw_form_together` `:120-149`) stay green untouched.

`OWNER_MGMT` (`mod.rs:49-54`) **moves to `schema.rs` and changes representation**: it becomes
four canonical signature strings rather than four `Known::…Call::SELECTOR` constants.

```rust
/// The four Safe owner/threshold management calls — the fail-closed rotation set. Compared
/// against a declared signature's canonical text, so it cannot drift from a selector table.
pub const OWNER_MGMT: [&str; 4] = [
    "swapOwner(address,address,address)",
    "addOwnerWithThreshold(address,uint256)",
    "removeOwner(address,address,uint256)",
    "changeThreshold(uint256)",
];

/// The Safe MultiSend entry point, whose single `bytes` argument is itself a list of calls.
pub const MULTI_SEND: &str = "multiSend(bytes)";
```

A test asserts each parses and that `Signature::try_from` accepts it verbatim — which is what
proves the strings are canonical and that a typo cannot silently produce a rotation set nothing
matches.

`SAFE_CONFIG`'s four module/guard/fallback calls become the same kind of const array, keeping
`Alarm::ModuleGuardFallback` alive; it is a shape alarm about what a decoded call can still do,
which decision 7 does not touch.

### 3.3 The dependency graph, which is why `schema.rs` exists

Today `policy` depends on `adapter` for `OWNER_MGMT` (`policy.rs:2`) and `adapter` depends on
nothing in the crate. After this stage `adapter` must read `&Policy` to find the declared
signature for a call site — which would make the two mutually dependent. Moving the rule
language and the two const sets into `schema` resolves it:

```
schema   → intent (Operation), alloy
policy   → schema
manifest → schema, policy
adapter  → schema, policy
sign     → adapter, policy, manifest, grant
```

`schema → intent` is unavoidable and is not a cycle: `AllowRule.operation` and `Site.operation`
are `crate::intent::Operation`, and `intent` depends on nothing in the crate (`intent.rs:1-3`).

**`schema` must NOT depend on `grant`.** §9.3's field evaluator needs a clock for
`FieldRule::Deadline`; it takes `now_secs: u64` as a parameter from the caller rather than calling
`grant::now_ms()` itself, which would drag `GrantErr` into `FieldDenied` and make the graph
`schema → grant → hc_core::mac`. The two callers (`admit` and `prepare_typed_data`) each already
own a fallible-clock call site.

No cycle, no re-export shim (`CLAUDE.md`). `crate::adapter::OWNER_MGMT` becomes
`crate::schema::OWNER_MGMT` at its one use site (`policy.rs:285`, which becomes a canonical-text
comparison against the matched `CallRule`).

---

## 4. Batch handling under the new model

### 4.1 One walk: authority and admission together

```rust
/// One call the Safe makes: the transaction's own, or one entry of a `multiSend`.
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

/// What one call's calldata turned out to be. There is no undecoded variant.
enum Body<'p> {
    /// Decoded against the rule that permitted it.
    Call {
        rule: &'p CallRule,
        args: Vec<DynSolValue>,
    },
    /// A `multiSend`, and every sub-call it runs.
    Batch(Vec<TypedCall<'p>>),
}

struct TypedCall<'p> {
    site: Site,
    body: Body<'p>,
}

/// An intent fully deconstructed into typed calls, every one of them permitted by the policy
/// borrowed for the walk. Constructible only by [`admit`].
pub struct TypedTx<'p> {
    intent: SafeTxIntent,
    root: TypedCall<'p>,
}

pub fn admit<'p>(
    intent: SafeTxIntent,
    policy: &'p Policy,
    adapter: Option<&Manifest>,
) -> Result<TypedTx<'p>, AdapterErr>;

impl TypedTx<'_> {
    pub fn intent(&self) -> &SafeTxIntent;
    pub fn summary(&self, config: &Config) -> String;
}
```

`Body::Call` borrows the `CallRule` that admitted it, so the renderer reads the operator's
argument labels and the constraint kinds from the same rule the check used — the human's text and
the authority decision cannot come from different rules.

`summary` is a method on `TypedTx`, so it is **unreachable without an admission**. That is the
enforcement: not "check, then render", but "there is nothing to render until the check passed".
This is `05` §B.1's design and it survives unchanged.

Per site, `admit` does exactly this, in this order:

1. `data` shorter than 4 bytes → `AdapterErr::NoCalldata { at, to, value }`.
2. `site.to == policy.safe` → the owner-management branch: the matched `CallRule` must come from
   `policy.owner_management.call`, `policy.owner_management.allow` must be true,
   `site.operation` must be `Call`, and `rule.signature.canonical` must be in
   `schema::OWNER_MGMT`. Otherwise `PolicyDenied::OwnerManagementNotAllowed`, exactly as
   `policy.rs:275-289` refuses today.
3. Otherwise `schema::match_call(&policy.allow, site)` → `Result<&CallRule, CallDenied>`,
   which selects the rule by `(to, operation)` and then the `CallRule` by selector.
4. When `adapter` is `Some`, `schema::match_call(&grant.calls, site)` must also succeed and yield
   a `CallRule` with the same `canonical`. `narrows` (§4.4) already guarantees the manifest's set
   is a subset of the policy's at load, so this is a per-site confirmation, not a second policy.
5. `site.value > rule_of_the_destination.max_value` → `CallDenied::ValueTooHigh { value, max }`.
   Note this now fires for **batch entries too**, where today no ceiling reaches them.
   **AUDIT:** `OwnerMgmt` (`policy.rs:63-68`) has no `max_value` field, and today `evaluate`
   returns early for `to == policy.safe` (`policy.rs:289`) without reading `i.value` at all — so a
   self-call carrying native value is unbounded today. Step 2's owner-management branch must
   either give `OwnerMgmt` a `max_value` (defaulting to `0`, which is a narrowing and must be
   called out in §15) or state that step 5 does not apply to it. Decide; do not leave it implicit.
6. Decode and re-encode per §2.3.
7. Evaluate every `ArgRule` against the decoded argument at its position (§9).
8. If `rule.signature.canonical == schema::MULTI_SEND`, take the single `DynSolValue::Bytes`
   argument and recurse into `batch::parse`.

**AUDIT — `multiSend`'s argument has no honest `FieldRule`.** §1.4's `ArgUnruled` forces every
declared argument to carry a rule, and the only rule in §9.1 that a packed batch payload can
satisfy is `Unbounded`. So the argument this stage checks *hardest* — every entry matched,
decoded, re-encoded and bounded by step 8 — would render `⚠ UNBOUNDED FIELD` on every batch
approval, which inverts the alarm's meaning and trains the operator to ignore it. `FieldRule`
needs a `Batch` variant, applicable only to `bytes`, whose evaluation is "recurse into step 8" and
whose rendering is the entry list. Fold it into §9.1 before implementing, or the first real batch
policy written against this plan is a false alarm by construction.

Because step 3 runs before step 6, a request naming a destination the policy does not allow never
reaches the decoder — preserving the ordering property `05` §B.1 identified and
`scripts/dryrun.sh` phase 5 asserts.

### 4.2 The refusals, and where they come from

| Mode | Refusal | Raised by |
|---|---|---|
| `data` shorter than 4 bytes | `AdapterErr::NoCalldata { at, to, value }` | step 1 |
| no rule for `(to, operation)` | `CallDenied::ToNotAllowed` / `OperationNotAllowed` | step 3, unchanged code |
| no declared signature at this destination has these 4 bytes | `CallDenied::SignatureNotAllowed { to, selector }` | step 3 — replaces `SelectorNotAllowed` |
| arguments do not decode against the declared signature | `AdapterErr::ArgumentsNotDecodable { at, to, signature, len, digest, source }` | step 6 |
| arguments decode but do not re-encode to the submitted bytes | `AdapterErr::EncodingNotCanonical { at, to, signature, len, digest }` | step 6 |
| an argument violates its `FieldRule` | `AdapterErr::Field { at, to, signature, arg, name, source: FieldDenied }` | step 7 |
| packed batch payload malformed | `AdapterErr::Batch(BatchErr::{Truncated, UnknownOperation, DataLengthTooBig, DataLengthPastEnd})` | step 8 |
| over the entry cap | `AdapterErr::Batch(BatchErr::TooManyEntries { max })` | step 8 |
| nested past the depth cap | `AdapterErr::Batch(BatchErr::TooDeep { at, max })` | step 8 |

### 4.3 The depth limit and `Body::Unexpanded`

`Body::Unexpanded` (`batch.rs:67,140-142`) and its renderer line
`⚠ NESTED BATCH BEYOND DEPTH 2` (`batch.rs:221-225`) are **deleted**. `MAX_BATCH_DEPTH = 2`
(`batch.rs:40`) stops being a display cap and becomes a **refusal**: a `multiSend` whose entry is
itself a `multiSend` at depth 3 is `BatchErr::TooDeep { at: Vec<usize>, max: 2 }`.

`MAX_BATCH_ENTRIES = 32` (`batch.rs:42`) already refuses (`BatchErr::TooManyEntries`) and keeps
doing so, except that today the refusal only suppresses the listing (`batch.rs:254-263` converts
it into `Alarm::BatchMalformed`) and now it propagates out of `admit`.

Both stay constants, not config: they are safety caps, and putting a safety cap in the config
lets a machine widen its own admission rule. This is `05`'s open question 3 and the answer does
not change.

`BatchErr` becomes `pub` (it is `pub(super)` at `batch.rs:49`) and every variant gains
`at: Vec<usize>` — the tree path — so a refusal names *which* nested batch failed rather than a
byte offset in an unnamed payload. `TooManyEntries` keeps only `max`, since the cap is global to
the tree.

### 4.4 The manifest

`Grant.calls: Vec<AllowRule>` (`manifest.rs:59`) is the same type, so it gains `call: Vec<CallRule>`
for free. `narrows` (`manifest.rs:239-265`) changes at exactly one place:

```rust
for rule in &grant.calls {
    // … unchanged: same `to`, same `operation`, `max_value` ceiling, no Safe self-call …
    for call in &rule.call {
        let Some(permitted) = allowed.call.iter().find(|c| {
            c.signature.canonical() == call.signature.canonical()
        }) else {
            return Err(Widened::Signature {
                to: rule.to,
                signature: call.signature.canonical().to_string(),
            });
        };
        narrows_args(call, permitted)?;
    }
}
```

`Widened::Selector { to, selector }` (`manifest.rs:73`) becomes
`Widened::Signature { to, signature: String }`. **The comparison is on the canonical text, not on
the selector**, because two different signatures can share a selector and a manifest is a
lower-trust file than the policy: comparing four bytes would let a manifest declare a *different*
call that grinds to the same selector and pass the narrowing check.

`narrows_args` is new and is the non-trivial half: for every argument position, the manifest's
`FieldRule` must be no wider than the policy's. Concretely — `OneOf` ⊆ `OneOf`; `Max` ≤ `Max`;
`Eq` permitted under a `Max` it satisfies or an identical `Eq`; `Deadline` with a `within_secs`
no larger; anything under a policy `Unbounded`; and `Unbounded` under anything **except** a
policy `Unbounded` is `Widened::Arg { to, signature, at }`. That last clause is the one that
matters: an adapter must not be able to unbind an argument the policy bound.

---

## 5. Migration of existing policy files

**They refuse to load. Nothing is auto-converted.**

A 4-byte selector cannot be inverted into a signature — that is a keccak preimage — so an
auto-conversion could only work from a fixed table, and a table that covers the 19 old `sol!`
functions would silently *fail* to convert every other selector an operator wrote, producing a
policy narrower than the file says. Silent narrowing under cover of a migration is worse than a
refusal.

What happens exactly, on first run of the new binary against an old file:

- `AllowRule` is `#[serde(deny_unknown_fields)]` (`policy.rs:52`) and no longer has a `selectors`
  field, so `toml::from_str` at `policy.rs:130` fails with an unknown-key error naming
  `selectors` and its line and column.
- That arrives as `PolicyErr::Toml(toml::de::Error)` — an already-existing variant
  (`policy.rs:110`) nesting the library error with `#[from]`, per `CLAUDE.md`'s no-remapping
  rule. Its `Display` is `err_mac`'s `{:?}` of the enum, which prints the whole
  `toml::de::Error` including the key and the span. Nothing is formatted by us.
- `Policy::load` is called from `HotApi::sign_intent` (`hc-daemon/src/lib.rs:768`), from
  `LoadedManifest::check` for **every granted key at startup** (`manifest.rs:135-143`), and from
  `hc-mcp`'s `preview_erc20_transfer` (`tools.rs:483`). So on a machine with any adapter pinned,
  `hot_cheese serve` **refuses to start** until every policy file named by a grant is converted.
  That is the correct fail-closed behaviour and it must be stated in the README, not discovered.

**A typed refusal naming the offending rule** was considered and rejected: it requires either
keeping a zombie `selectors` field on `AllowRule` (which `CLAUDE.md`'s delete-dead-paths rule
forbids, and which would have to be private, breaking the struct-literal construction in
`policy.rs`'s and `manifest.rs`'s tests) or parsing the file twice. `PolicyErr::Toml` already
names the key, the line and the column, which is everything the operator needs.

**The migration aid is a table, and it costs no code.** These are the 19 signatures the old
`sol!` interface declared (`adapter/mod.rs:26-44`), which are the selectors any policy written
against the current daemon could usefully hold:

| Old selector | Canonical signature to declare |
|---|---|
| `0xe318b52b` | `swapOwner(address,address,address)` |
| `0x0d582f13` | `addOwnerWithThreshold(address,uint256)` |
| `0xf8dc5dd9` | `removeOwner(address,address,uint256)` |
| `0x694e80c3` | `changeThreshold(uint256)` |
| `0xa9059cbb` | `transfer(address,uint256)` |
| `0x095ea7b3` | `approve(address,uint256)` |
| `0x23b872dd` | `transferFrom(address,address,uint256)` |
| `0x39509351` | `increaseAllowance(address,uint256)` |
| `0xa457c2d7` | `decreaseAllowance(address,uint256)` |
| `0xa22cb465` | `setApprovalForAll(address,bool)` |
| `0xd505accf` | `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` |
| `0x610b5925` | `enableModule(address)` |
| `0xe009cfde` | `disableModule(address,address)` |
| `0xe19a9dd9` | `setGuard(address)` |
| `0xf08a0323` | `setFallbackHandler(address)` |
| `0xd4d9bdcd` | `approveHash(bytes32)` |
| `0x42842e0e` | `safeTransferFrom(address,address,uint256)` |
| `0xb88d4fde` | `safeTransferFrom(address,address,uint256,bytes)` |
| `0x8d80ff0a` | `multiSend(bytes)` |

**Both columns are verified.** The signatures in the right column are read verbatim from
`adapter/mod.rs:26-44`. Every selector in the left column was recomputed during this audit as
`keccak256(signature)[..4]` with an independent Keccak-256 implementation (sanity-checked against
`keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`); all 19 rows
match. The table may ship in the README as written. §16 test 7 still pins the pairs in-tree with
`Function::parse(sig).selector()`, so an alloy change cannot silently move them, and it can be
deleted with the table once the migration window closes.

Any selector an operator wrote that is **not** in this table names a call the daemon has never
been able to decode. It was signable (that is `05` §B.0 (a), the hole 7a closes). After this
stage the operator must write its real signature — which they can obtain from the contract's ABI
— and the call becomes both decodable and constrainable. That is the upgrade, and it is why the
narrowing in `05` §B.3 item 1 does **not** apply to this plan (§15).

---

# PART 2 — EIP-712 (decisions 7b, 7c)

## 6. The new `Intent` variant

```rust
/// A submitted signing intent. `kind` selects the versioned variant.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Intent {
    SafeTx(SafeTxIntent),
    TypedData(TypedDataIntent),
}

/// A request to sign ONE EIP-712 message against a schema the POLICY declared. It carries no
/// type definitions, no primary type and no domain object: the shape is not the requester's
/// to describe.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TypedDataIntent {
    /// Local keystore name authorized to sign this message.
    pub key: String,
    /// Name of the `[[typed_data]]` block in this key's policy that governs this message.
    pub schema: String,
    /// The chain the declared domain pins; a mismatch is a refusal, not a re-domaining.
    #[serde(with = "hc_core::wire::u256")]
    pub chain_id: U256,
    /// The contract that will verify the signature; a mismatch is a refusal.
    pub verifying_contract: Address,
    /// The message fields, read only against the declared schema.
    pub message: serde_json::Value,
}
```

`kind = "typed_data"` on the wire. `#[serde(tag = "kind")]` is serde's **internally tagged**
representation, which is what the existing single-variant `Intent` already uses
(`intent.rs:24-27`): the variant's fields are flattened into the same JSON object beside `kind`.
Adding a second variant changes nothing about how `safe_tx` parses.

`deny_unknown_fields` sits on the enum (`intent.rs:25`) and on each variant's struct
(`intent.rs:34`, and the new one). **The load-bearing one is the STRUCT attribute, not the enum
attribute.** For an internally tagged enum serde strips the tag and hands the remaining content to
the newtype variant's inner type, so the container-level `deny_unknown_fields` on `Intent` governs
only *struct* variants — of which `Intent` has none — and is inert here. Whoever implements this
must not "simplify" by dropping the attribute from `TypedDataIntent` on the belief that the enum
covers it: that would silently reopen §8.1.

The struct attribute is already proved to survive the tagged-enum wrapper in-tree:
`unparseable_bodies_are_refused_before_any_approval` (`hc-daemon/src/lib.rs:1118-1144`) feeds a
valid `kind = "safe_tx"` body with one extra key and asserts `BodyErr::Malformed`. §16 test 1 is
the same assertion for the new variant and belongs beside it.

### 6.1 The compiler enumerates every path that assumed one variant

`Intent` has exactly one variant today, so every destructuring in the workspace is an
irrefutable `let`. Adding a variant makes each a compile error, which is the desired behaviour:
the compiler produces the complete list. Grepped, all of them:

| Site | What it is | Fate |
|---|---|---|
| `crates/hc-daemon/src/lib.rs:758` | `sign_intent` parses the request body | becomes a `match`; `TypedData` routes to `sign_typed_data` (§13) |
| `crates/hc-daemon/src/lib.rs:598` | `check_body` type-checks the body | unchanged — it parses `Intent` and discards it |
| `crates/hc-cli/src/bundle.rs:118` | `bundle new --file` | `match` → `CliErr::NotBundleable { kind }` |
| `crates/hc-console/src/bundles.rs:530` | console "new bundle from file" | `match` → `MenuErr::NotBundleable { kind }` |
| `crates/hc-console/src/bundles.rs:377` | serializes a `SafeTxIntent` for the daemon | constructor; deleted by `05` §A.3 |
| `crates/hc-bundle/src/lib.rs:569` | writes a bundle's intent JSON | constructor, still `Intent::SafeTx` |
| `crates/hc-sign/src/qr.rs:265,269` | QR round-trip test | still `SafeTx`; add a `match` in the test |
| `crates/hc-cli/src/lib.rs:715,729` | `sign_intent_locally` | deleted / rewritten by `05` §A.3 |
| `crates/hc-console/src/menu.rs:640` | the Sign screen | deleted by `05` §A.1 |

**Typed data is not bundle-able, by type.** `SafeTxBundle.intent` is a `SafeTxIntent`
(`hc-sign/src/bundle.rs:51`) and `SafeTxBundle::digest()` is `adapter::safe_tx_hash`
(`bundle.rs:81-83`). There is no multi-device signature collection for typed data in this stage.
That is a real limitation for EIP-1271, and it is open question 3 (§17) rather than a silent gap.

---

## 7. The policy-declared schema

### 7.1 Format

`Policy` gains one field:

```rust
    /// EIP-712 message schemas this key may sign, each complete: domain, types, constraints.
    #[serde(default)]
    pub typed_data: Vec<TypedDataSchema>,
```

```rust
/// One complete EIP-712 message shape a request may name. Everything a digest depends on is
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

/// The EIP-712 domain, declared in full. Which optional members are PRESENT changes the
/// domain separator, so presence is pinned here and a request cannot vary it.
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

/// One field: its Solidity type, the label a human reads, and what it may hold.
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
```

`name`, `version` and `salt` are `Option` because `Eip712Domain`'s own members are
(`alloy-sol-types-0.8.26/src/eip712.rs:18,23,37`) and because **presence is semantic**:
`Eip712Domain::encode_type` (`eip712.rs:68`) builds the `EIP712Domain(…)` type string from
whichever members are `Some`, so declaring `name` changes the domain separator. `None` here is
the genuinely correct value for "this domain has no name", which is exactly `CLAUDE.md`'s
carve-out for `Option`. `chain_id` and `verifying_contract` carry no default and are therefore
mandatory, matching `Policy.chain_id`'s existing treatment (`policy.rs:16-17`).

### 7.2 Example — Uniswap Permit2 `PermitSingle`

```toml
safe = "0x1111111111111111111111111111111111111111"
chain_id = 1

[[typed_data]]
schema = "permit2_usdc"
primary_type = "PermitSingle"

  [typed_data.domain]
  name = "Permit2"
  chain_id = 1
  verifying_contract = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

  [[typed_data.types]]
  name = "PermitSingle"

    [[typed_data.types.field]]
    name = "details"
    type = "PermitDetails"
    rule = { kind = "struct" }

    [[typed_data.types.field]]
    name = "spender"
    type = "address"
    rule = { kind = "one_of", addresses = ["0x4444444444444444444444444444444444444444"] }

    [[typed_data.types.field]]
    name = "sigDeadline"
    type = "uint256"
    rule = { kind = "deadline", within_secs = 1800 }

  [[typed_data.types]]
  name = "PermitDetails"

    [[typed_data.types.field]]
    name = "token"
    type = "address"
    rule = { kind = "one_of", addresses = ["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"] }

    [[typed_data.types.field]]
    name = "amount"
    type = "uint160"
    rule = { kind = "max", max = "1000000000", amount_of = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" }

    [[typed_data.types.field]]
    name = "expiration"
    type = "uint48"
    rule = { kind = "deadline", within_secs = 86400 }

    [[typed_data.types.field]]
    name = "nonce"
    type = "uint48"
    rule = { kind = "unbounded" }
```

### 7.3 What is matched, and what is compared

**Nothing about the message's *shape* is compared, because the request does not carry one.** The
shape is constructed from the declaration. What runs, in order, all inside `prepare_typed_data`
before the approver:

| # | Check | Refusal |
|---|---|---|
| 1 | `intent.key` valid name, matches `ctx.key` | existing `SignErr::{InvalidName, IntentKeyMismatch}` (`hc-daemon/src/lib.rs:755-761`) |
| 2 | a `[[typed_data]]` with `schema == intent.schema` exists | `TypedDenied::SchemaNotDeclared { schema }` |
| 3 | `intent.chain_id == domain.chain_id` | `TypedDenied::ChainMismatch { expected, got }` |
| 4 | `intent.verifying_contract == domain.verifying_contract` | `TypedDenied::VerifyingContractMismatch { expected, got }` |
| 5 | the resolver built from `types` resolves `primary_type` to a `DynSolType::CustomStruct` | `TypedDenied::SchemaNotResolvable { schema, primary_type }`, with the `alloy_dyn_abi::Error` reaching the caller as `TypedDenied::Abi` via `?` — a **load-time** check too (§7.4) |
| 6 | `intent.message`'s key set equals the declared field set, recursively | `TypedDenied::MessageFieldUnknown { path, field }` / `MessageFieldMissing { path, field }` |
| 7 | each value coerces to its declared type | `TypedDenied::FieldNotCoercible { path, field, declared, source }` |
| 8 | each value satisfies its `FieldRule` | `TypedDenied::Field { path, field, source: FieldDenied }` |

Check 6 is **not** redundant with alloy. `custom_struct` coercion
(`alloy-dyn-abi-0.8.26/src/eip712/coerce.rs:145-172`) iterates the declared `prop_names` and
errors on a **missing** key (`:157-165`), but a key in the JSON object that the type does not
declare is simply never read — it is silently ignored. Such a key does not enter the digest, so
it is not a signing hazard; it *is* a hazard to decision 7's rule that the daemon signs only what
it can fully deconstruct, and it is a channel for a requester to leave text near a message a
human might read elsewhere. So the daemon walks the JSON object itself and refuses extras.

### 7.4 Load-time schema checks

`Policy::load` gains, beside `no_duplicate_rules`:

| Check | Refusal |
|---|---|
| two `[[typed_data]]` blocks with the same `schema` | `PolicyErr::DuplicateSchema { schema }` |
| two `[[typed_data.types]]` with the same `name` | `PolicyErr::DuplicateType { schema, name }` |
| a field type naming a struct that is not declared | `PolicyErr::TypeNotDeclared { schema, ty }` (surfaced from `Resolver::resolve`'s `Error::MissingType`, `alloy-dyn-abi-0.8.26/src/error.rs:16-18`) |
| a cycle in the type graph | `PolicyErr::TypeCycle { schema, ty }` (from `Error::CircularDependency`, `error.rs:20-21`; `Resolver::resolve` detects it at `resolver.rs:378-380`) |
| `primary_type` not among `types` | `PolicyErr::PrimaryTypeNotDeclared { schema, primary_type }` |
| a `FieldRule` kind that cannot apply to its declared type | `PolicyErr::RuleTypeMismatch { schema, path, declared, rule }` |
| a `FieldDecl` whose type is a declared struct but whose rule is not `struct` | same variant |

Doing 5 at load rather than only per request means a schema that can never resolve refuses the
policy file — and therefore refuses `serve` startup for any adapter granted that key
(`manifest.rs:135-143`) — instead of failing at the first request.

---

## 8. THE SECURITY CORE: the request's self-declared types

### 8.1 The channel is deleted, not audited

A standard `eth_signTypedData_v4` payload is
`{ types, primaryType, domain, message }`, and `alloy_dyn_abi::TypedData` is exactly that struct
(`typed_data.rs:66-83`): `domain: Eip712Domain`, `resolver: Resolver` deserialized from the
`types` key (`:74-75`), `primary_type: String`, `message: serde_json::Value`. Its
`eip712_signing_hash()` (`:207-222`) hashes through that resolver. **Deserializing a `TypedData`
straight off the wire is precisely the thing decision 7b forbids**, because the requester would
then choose the field names the human reads and the type string the digest commits to.

This plan's answer is not "compare the request's `types` against policy's and refuse on
difference". It is: **`TypedDataIntent` has no `types` field, no `primaryType` field and no
`domain` object.** With `#[serde(deny_unknown_fields)]` on the struct (§6's note on why the
enum-level attribute is inert), a request carrying any of them is a **parse failure**.

Where that parse failure lands, per surface, all of them before any approver:

| Surface | Refused at | Error |
|---|---|---|
| loopback TLS `/sign/<KEY>` | `check_body` (`hc-daemon/src/lib.rs:597-599`), called from `service_impl` at `:832` before `ctx` is even built at `:838` | `BodyErr::Malformed` → HTTP 400 |
| adapter socket `/sign/<KEY>` | same — adapter connections run the same `service_impl` and `parse_route(Surface::Adapter, …)` | `BodyErr::Malformed` → HTTP 400 |
| any body that somehow reaches it | the second parse inside `sign_intent` (`hc-daemon/src/lib.rs:758`), still above `prepare` at `:777` and the approver at `:778` | `SignErr::Serde` |
| CLI / console | **not reachable**: after `05` §A.3 those callers hand `sign_typed`/`sign_typed_data` a typed struct and never build JSON |

Adversarial cases, each refused: `{"kind":"typed_data",…,"types":{…}}` (unknown field `types`);
`…,"primaryType":"X"` (unknown field); `…,"domain":{…}` (unknown field); the same three nested one
level down inside a `"safe_tx"` body (unknown field on `SafeTxIntent`); a duplicate `"schema"` key
(serde reports a duplicate field). A `"types"` key **inside** `message` parses — `message` is
`serde_json::Value` — and is then refused by §7.3 check 6 as `MessageFieldUnknown`, which is where
it belongs.

A comparison is code that can be wrong: it can compare the wrong thing, compare loosely, or be
skipped on a path. An absent field cannot be any of those. This is the same argument the repo
already makes for `deny_unknown_fields` on `SafeTxIntent` (`intent.rs:29-32`), and it is why the
answer to "what happens when the request's declared types disagree with policy's" is **the
request cannot state a type at all; one that tries never parses.**

### 8.2 The digest and the rendering come from one coercion

The remaining risk after §8.1 is subtler: the daemon could coerce the message **twice** — once
to render and once to hash — and the two coercions could disagree. `TypedData::eip712_signing_hash`
re-coerces internally on every call (`typed_data.rs:190` calls `self.coerce()`), so calling it
after rendering would leave exactly that hole.

So the daemon coerces once and derives both from that one value:

```rust
let resolver = /* built from POLICY: Resolver::default() + ingest(TypeDef) per TypeDecl */;
let domain   = /* built from POLICY's DomainDecl */;
let ty       = resolver.resolve(&schema.primary_type)?;   // DynSolType::CustomStruct
check_json(&intent.message, schema)?;                     // RAW JSON: extras, missing, bytesN len
let value    = ty.coerce_json(&intent.message)?;          // ONE coercion
evaluate_fields(&value, schema, now_secs)?;               // FieldRule, over the coerced value
let hash_struct = resolver.eip712_data_word(&value)?;
let digest      = eip712_digest(&domain, hash_struct);
let summary     = render(&value, schema, config);         // the SAME `value`
```

**Verified API, at the pinned version:**

| Item | Where | Behaviour relied on |
|---|---|---|
| `Resolver: Default` | `alloy-dyn-abi-0.8.26/src/eip712/resolver.rs:206-208` | `#[derive(Clone, Debug, Default, PartialEq, Eq)]` |
| `Resolver::ingest(TypeDef)` | `resolver.rs:311-323` | inserts node + edges |
| `TypeDef::new(name, Vec<PropertyDef>) -> Result<TypeDef>` | `resolver.rs:116-120` | validates the name is a root type |
| `PropertyDef::new(type_name, name) -> Result<PropertyDef>` | `resolver.rs:43-51` | validates the type is a `TypeSpecifier` |
| `Resolver::resolve(&str) -> Result<DynSolType>` | `resolver.rs:377-382` | cycle-detects, then builds `DynSolType::CustomStruct { name, prop_names, tuple }` (`:400-417`) |
| `DynSolType::coerce_json(&serde_json::Value) -> Result<DynSolValue>` | `src/eip712/coerce.rs:10-38` | the one coercion |
| `Resolver::eip712_data_word(&DynSolValue) -> Result<B256>` | `resolver.rs:466-492` | for a `CustomStruct`, `keccak(type_hash(name) ‖ each data word)` — i.e. exactly EIP-712 `hashStruct` |
| `Resolver::type_hash(&str) -> Result<B256>` | `resolver.rs:441-443` | `keccak(encode_type)`, and `encode_type` (`:422-438`) sorts referenced types by name per the EIP-712 spec |
| `Eip712Domain::separator() -> B256` | `alloy-sol-types-0.8.26/src/eip712.rs:61` | `hash_struct()` of the domain (`:161`) |

**The two walks are over two different things and that is deliberate.** `check_json` walks the raw
`serde_json::Value` because an undeclared key and an over-long `bytesN` are *erased* by coercion
and cannot be seen in `value` (§7.3 check 6, §8.4). `evaluate_fields` and `render` walk `value`
because that is what the digest is taken over. Only `value` reaches the digest and the summary, so
the one-coercion property holds; `check_json` can only refuse, never alter.

`eip712_digest` is the five-line `0x19 0x01 ‖ separator ‖ hashStruct` concatenation, identical in
shape to `SolStruct::eip712_signing_hash` (`alloy-sol-types-0.8.26/src/types/struct.rs:100-107`),
which `safe_tx_hash` already relies on. §11 pins it with a test.

### 8.3 The proof obligation, stated as the chain it is

The claim is: **the digest the daemon signs is the digest of the message the human was shown.**
It holds because each link is a fact about a type or a call site, not about discipline:

1. `TypedDataIntent` cannot carry a shape (§8.1). The only requester-supplied input to any of the
   below is `message: serde_json::Value` plus two echoed domain scalars that must equal the
   declared ones.
2. `resolver`, `domain`, `ty` are functions of the policy file alone.
3. `value = ty.coerce_json(&message)` is computed once, and `value` is the only value passed to
   both the renderer and `eip712_data_word`.
4. `eip712_data_word(&value)` walks `value`'s `CustomStruct` tuple in `prop_names` order
   (`resolver.rs:473-479`), and the renderer walks the same tuple in the same order, so the
   *n*th line of the summary is the *n*th word of `encodeData`. Note that
   `eip712_data_word` takes the struct's *name* from `value` itself (`resolver.rs:473-474`), not
   from a parameter — and `value.name` came from `ty`, which came from
   `resolver.resolve(&schema.primary_type)`, so it is the policy's name. Nested structs get their
   names the same way (`resolve_root_type`, `resolver.rs:400-417`). The request never names a type
   at any depth.
5. `digest` is `keccak(0x1901 ‖ domain.separator() ‖ hashStruct)` and `domain` is from (2).
6. `prepare_typed_data` returns `(Approved { digest, … }, summary)` as one tuple, and `Approved`
   has private fields with no constructor but `prepare_typed_data`, exactly as `ApprovedSafeTx`
   does today (`sign.rs:22-27`). `finish` takes it by value. So "the summary and the digest came
   from the same value" is a property of `prepare_typed_data`'s signature.
7. `finish` mints the grant over `approved.digest` (`sign.rs:64-75`) and `sign_with_grant` signs
   `grant.intent_digest()` (`sign.rs:109`) and nothing else.

The test that pins (3)–(5) is §16's `the_typed_digest_matches_alloys_own` : build the same
`TypedData` from the policy-derived parts, and assert
`TypedData::eip712_signing_hash()` equals the one-coercion digest. It catches any future edit
that makes the render path and the hash path diverge.

### 8.4 Two coercion looseness facts that must be handled

Read from `alloy-dyn-abi-0.8.26/src/eip712/coerce.rs` and not obvious:

- **`fixed_bytes` silently pads and truncates** — CONFIRMED by reading `coerce.rs:78-88`:
  `let min = n.min(buf.len()); word[..min].copy_from_slice(&buf[..min])`. A `bytes32` field given
  `"0xdeadbeef"` coerces to `0xdeadbeef000…0`, and given 64 bytes of hex it keeps the first 32.
  **The daemon must refuse a `bytesN` whose supplied hex is not exactly `N` bytes**, in
  `check_json` over the raw JSON (§8.2), as
  `TypedDenied::FixedBytesLength { path, field, declared: usize, got: usize }`.
  Otherwise two different request bodies produce one digest and one rendering, which is the exact
  failure mode `batch.rs:14-18` and `call.rs:25-29` were written to prevent.
  The length check must decode the hex the way alloy will (`const_hex::decode`: optional `0x`
  prefix, even nibble count, error otherwise) or the check and the coercion can disagree about
  what "the supplied bytes" are.
- **`custom_struct` silently ignores undeclared JSON keys** — CONFIRMED by reading
  `coerce.rs:145-172`: it iterates `prop_names` and calls `map.get(name)`, erroring only on a
  **missing** key (`:157-165`). A key the type does not declare is never read and never observed.
  §7.3 check 6's raw-JSON walk is the whole mitigation, and it must run over the raw
  `serde_json::Value` for exactly this reason (§8.2).
- **`uint`/`int` accept a JSON number or a string** (`coerce.rs:58-77`), and the string parse is
  `U256`/`I256`'s `FromStr`, which accepts decimal and `0x` hex. That matches
  `hc_core::wire::u256`'s own contract (`hc-core/src/wire.rs:1-2`) and needs nothing. The width
  check (`x.bit_len() <= n`) is present and correct for `uint`. Note a bare JSON number above
  `u64::MAX` fails `as_u64()` and is then refused, so large values must arrive as strings — same
  rule the rest of the wire already has.
  **RESOLVED (was VERIFY):** `int(n, value)` checks `x.bits() <= n as u32` (`coerce.rs:66`), and
  `I256::bits` (`alloy-primitives-0.8.26/src/signed/int.rs:285`) is
  `unsigned_abs().bit_len()` plus one for the sign **except** when the value is zero or a negative
  power of two, so `-128` reports 8 and `128` reports 9. The width check is sign-correct.
  **`intN` is nonetheless refused at load** (`PolicyErr::RuleTypeMismatch`), for a different
  reason: `FieldRule::{Max, Eq}` carry `U256`, so no signed bound is *expressible*. Permitting
  `intN` would mean permitting it only as `Unbounded`, which is a blank cheque on a field type
  nothing in this repo needs. Add a signed bound variant first, or leave `intN` out.

---

## 9. Field-level constraints

### 9.1 The type, shared by both halves

```rust
/// What one declared field or argument may hold. There is no default: a field with no rule
/// does not parse, so an unbounded field must be written out as `kind = "unbounded"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldRule {
    /// An address, and only these.
    OneOf {
        addresses: Vec<Address>,
    },
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
    /// Exactly these bytes.
    BytesEq {
        eq: Bytes,
    },
    /// A unix-seconds timestamp no more than `within_secs` ahead of now.
    Deadline {
        within_secs: u64,
    },
    /// Exactly one of these strings.
    Enum {
        one_of: Vec<String>,
    },
    /// Every element bounded by `of`, and no more than `max_len` of them.
    Each {
        max_len: usize,
        of: Box<FieldRule>,
    },
    /// A nested struct, bounded by its own `[[typed_data.types]]` block.
    Struct,
    /// Deliberately unbounded. The summary says so, in the alarm block.
    Unbounded,
}
```

An enum, per `CLAUDE.md`'s fixed-set rule. Applicability, checked once at load
(`RuleTypeMismatch`):

| Rule | Applies to |
|---|---|
| `OneOf` | `address` |
| `Max`, `Eq` | `uintN` only — `intN` is refused at load, see §8.4 |
| `BytesEq` | `bytes`, `bytesN` |
| `Deadline` | `uintN`, `N >= 40` |
| `Enum` | `string` |
| `Each` | `T[]`, `T[k]` |
| `Struct` | a declared struct type |
| `Unbounded` | anything |

**AUDIT — two Solidity types this table can only reach through `Unbounded`, which is a
regression, not a neutral gap:**

- **`bool`.** Nothing here pins a `bool`, so `setApprovalForAll(address,bool)` can only be
  declared with `approved` unbounded — and §3.1 deletes `Alarm::UnlimitedApproval` on the grounds
  that "an unbounded argument is now declared as `kind = "unbounded"` and rendered as such". Today
  `setApprovalForAll(operator, true)` raises a specific `⚠ UNLIMITED APPROVAL` naming the drain;
  after this stage it raises a generic `⚠ UNBOUNDED FIELD approved`, and `false` (harmless) raises
  it identically. A `BoolEq { eq: bool }` variant restores the distinction and lets an operator
  permit revocation while refusing grant. Add it.
- **`bytes` carrying a batch** — see the AUDIT note in §4.1 step 8.

Until both are added, §3.1's claim that `FieldRule` *supersedes* `Alarm::UnlimitedApproval` is
overstated: for `approve`/`increaseAllowance`/`permit` (all `uint256`) it holds via `Max`; for
`setApprovalForAll` it does not.

### 9.2 Why an unconstrained permit cannot be written by accident

Three independent gates, each structural:

1. `FieldDecl.rule` and `ArgRule.rule` have **no `#[serde(default)]`**, so a field or argument
   without a rule is a **parse** error naming the missing key — before any load check runs.
2. `PolicyErr::ArgUnruled` (§1.4) refuses a `CallRule` that does not cover every declared
   argument position, so an operator cannot rule argument 0 and forget argument 1.
3. The only way to express "no bound" is to type `kind = "unbounded"`, which the summary renders
   as a leading alarm line (§12). An operator who means it says so and the human sees it said.

### 9.3 Evaluation

One recursive function in `schema.rs`, walking `(&FieldRule, &DynSolValue)` in lockstep and
carrying a `path: Vec<String>` for the refusal. It is reused by the call half and the typed-data
half, which is what earns it being a function (`CLAUDE.md`).

```rust
create_err_with_impls!(
    #[derive(Debug)]
    pub FieldDenied,
    ;
    AddressNotAllowed { got: Address, allowed: Vec<Address> },
    ValueTooHigh { got: U256, max: U256 },
    ValueNotExact { got: U256, want: U256 },
    BytesNotExact { got: Bytes, want: Bytes },
    DeadlineTooFar { deadline: U256, now_secs: u64, within_secs: u64 },
    StringNotAllowed { got: String, allowed: Vec<String> },
    TooManyElements { got: usize, max_len: usize },
    TypeNotExpected { got: String, rule: &'static str }
);
```

`Deadline` does **not** read a clock itself: the evaluator takes `now_secs: u64`, so `schema` stays
free of `grant` (§3.3). The caller obtains it as `grant::now_ms()? / 1_000` — `now_ms`
(`grant.rs:174`) is the repo's one clock and returns **milliseconds**, `Result<u64, GrantErr>`
with `Clock(std::time::SystemTimeError)` nested at `grant.rs:31`, and decision 12 says timestamps
are seconds everywhere, so the division is mandatory and belongs at the one call site rather than
inside the evaluator. The comparison is `U256::from(now_secs + within_secs) >= deadline`; an
already-past deadline is **not** refused, because a signature over an expired permit authorises
nothing and refusing it would add a failure mode with no security value. `now` never enters the
digest — it bounds admission only — and with `GRANT_TTL_MS = 5_000` (`grant.rs:48`) the window
between the check and the signature is at most five seconds.

`TypeNotExpected` exists for defence in depth: the load-time `RuleTypeMismatch` should make it
unreachable, but a `DynSolValue` that does not match its `FieldRule` at runtime must be a
refusal, never a fallthrough. It carries the value's own `sol_type_name` and the rule's name in
fields.

---

## 10. EIP-1271 Safe messages as a declared schema

Safe's message hash is EIP-712 over `SafeMessage(bytes message)` with the domain
`EIP712Domain(uint256 chainId,address verifyingContract)` and `verifyingContract` set to the Safe
itself. That domain shape is corroborated inside this repo: `safe_tx_hash` builds exactly it
(`adapter/mod.rs:330-336`, `name: None, version: None, chain_id: Some, verifying_contract: Some,
salt: None`), and `Eip712Domain::encode_type` (`alloy-sol-types-0.8.26/src/eip712.rs:68`) emits
the type string from whichever members are `Some` — a correspondence already pinned by
`safe_tx_hash_matches_hand_rolled_eip712` (`mod.rs:502-551`).

No special-cased code. It is a `[[typed_data]]` block like any other (decision 7c):

```toml
[[typed_data]]
schema = "safe_message"
primary_type = "SafeMessage"

  [typed_data.domain]
  chain_id = 1
  verifying_contract = "0x1111111111111111111111111111111111111111"

  [[typed_data.types]]
  name = "SafeMessage"

    [[typed_data.types.field]]
    name = "message"
    type = "bytes"
    rule = { kind = "unbounded" }
```

`kind = "unbounded"` is the honest declaration for a login challenge or a SIWE statement, and it
is exactly why `Unbounded` had to be typeable rather than omittable: the operator states that
this key signs arbitrary bytes at this contract, and every approval for it leads with
`⚠ UNBOUNDED FIELD message`. A deployment that only ever signs one fixed challenge writes
`rule = { kind = "bytes_eq", eq = "0x…" }` instead and the alarm goes away.

The renderer prints a `bytes` field as its hex **and**, when the bytes are valid UTF-8, the
decoded text beneath it — never instead of it, following `annotate.rs:1-7`'s additive-only rule
(a label is appended to an address, never substituted for it).

---

## 11. Digest computation, and its relationship to `safe_tx_hash`

```rust
/// The EIP-712 signing hash of a message the policy declared the shape of.
fn eip712_digest(domain: &Eip712Domain, hash_struct: B256) -> B256 {
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain.separator().as_slice());
    buf[34..].copy_from_slice(hash_struct.as_slice());
    keccak256(buf)
}
```

with `hash_struct = resolver.eip712_data_word(&value)?` (§8.2).

**It shares no code with `adapter::safe_tx_hash` (`mod.rs:317-338`), and that is deliberate.**
`safe_tx_hash` derives its type hash from the compile-time `sol!` `struct SafeTx`
(`mod.rs:24`) through `SolStruct::eip712_signing_hash`
(`alloy-sol-types-0.8.26/src/types/struct.rs:100-107`). The typed-data path derives its type
hash from a **policy file**. Routing `safe_tx_hash` through the runtime resolver would make the
definition of a Safe transaction operator-editable, which is a strictly worse property than a
little duplication. The duplicated part is five lines of `0x1901` concatenation, and both are
pinned by tests: `safe_tx_hash_matches_hand_rolled_eip712` for the compile-time one
(`mod.rs:502-551`), `the_typed_digest_matches_alloys_own` for the runtime one (§16).

`safe_tx_hash` therefore stays a free function over `SafeTxIntent` and is unmoved — as `05`
§B.1 required, because `SafeTxBundle::digest()` calls it (`bundle.rs:81-83`) and a bundle
directory is named for that digest.

**Confirmed available at 0.8.26 for the runtime path:** `Eip712Domain::separator`
(`eip712.rs:61`), `Eip712Domain::hash_struct` (`:161`), `Eip712Domain::encode_type` (`:68`),
`Eip712Domain::type_hash` (`:105`), `Resolver::{type_hash, encode_type, encode_data,
eip712_data_word}` (`resolver.rs:441,422,446,466`), `TypedData::eip712_signing_hash`
(`typed_data.rs:207`) for the cross-check test.

---

## 12. Rendering

### 12.1 A call, under the new generic renderer

`call::render` takes `(&Site, &CallRule, &[DynSolValue], &Config)` and emits
`name(label=value, …)` where each `label` is `ArgRule.name` and each `value` is rendered by the
argument's `FieldRule`:

| Rule | Rendering of the value |
|---|---|
| `OneOf` | `annotate::address(a, site.chain_id, config)` — full EIP-55 plus any `[[label]]` |
| `Max { amount_of }` | `annotate::amount(v, amount_of, site.chain_id, config)` — scaled and raw together |
| `Eq`, `Deadline`, other integers | `annotate::count(v)` — the exact integer, marked `⚠ HUGE` past 2^128 |
| `BytesEq`, unbounded `bytes` | `0x…` hex, plus a UTF-8 line when valid |
| `Enum` | the string, quoted |
| `Each` | `[` elements `]`, each by `of` |
| `Struct` | nested, indented |
| `Unbounded` | the value by its `DynSolValue` type, and an `⚠ UNBOUNDED` alarm line |

This is where the declaration pays for itself: today `call.rs` must guess that `permit`'s
`deadline` is a count and `permit`'s `value` is an amount, and it does so with a hand-written arm
per function (`call.rs:89-98`). Under the new model the operator has already said which is which,
per rule, and there is no arm to write for the twentieth function.

### 12.2 A typed-data approval, field by field

The summary keeps today's shape — alarms first, worst-ranked first, then the body — because the
approval sheet gets the head of the text and never the tail (`mod.rs:358-364`).

```
⚠ UNBOUNDED FIELD [details.nonce]: this value is not bounded by the policy
⚠ TYPED MESSAGE: a signature here is valid at the contract below until its deadline, with no
  transaction on this chain
PermitSingle
  details: PermitDetails
    token = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 (USDC)
    amount = 1000.000000 USDC (1000000000)
    expiration = 1755000000
    nonce = 0
  spender = 0x4444444444444444444444444444444444444444 (Permit2 router)
  sigDeadline = 1754998200
  schema=permit2_usdc  domain=Permit2  chain=1
  verifyingContract = 0x000000000022D473030F116dDEE9F6B43aC78BA3 (Permit2)
  key=TREASURY
```

The annotation machinery reaches this text through exactly the two functions it already reaches a
call summary through, and through no others:

- `annotate::address(a, chain_id, config)` (`annotate.rs:67-74`) for every `address` field and
  for `verifyingContract` — full checksummed address, a `[[label]]` name appended in parentheses
  and never substituted.
- `annotate::amount(v, amount_of, chain_id, config)` (`annotate.rs:56-61`) for every `Max`
  field — scaled form and raw integer together, `⚠ UNLIMITED` at `U256::MAX`, `⚠ HUGE` past
  2^128, and the raw integer alone when the contract has no `[[token]]` entry.

`chain_id` for the lookups is the **declared domain's**, not the request's, because they are
equal by check 3 of §7.3 and the declared one is the trusted copy.

Decision 7e is preserved exactly: a schema whose `verifyingContract` has no `[[label]]` and whose
token has no `[[token]]` renders every address and every integer in full and signs. Annotation
adds; it never gates.

### 12.3 The alarms a typed message raises

`Alarm` gains three variants and loses four (§3.1):

| Alarm | When | Why it ranks where it does |
|---|---|---|
| `UnboundedField { path }` | a `FieldRule::Unbounded` was exercised | rank 2 — it is the one thing the policy did not bound, and the human is the only remaining bound |
| `TypedMessage` | always, for a typed-data approval | rank 3 — an off-chain signature has no nonce and no gas, so "nothing happens on chain" is the thing people get wrong about it |
| `DeadlineFar { path, deadline, now_secs }` | an accepted deadline more than 24h out | rank 9 — allowed by policy, still worth reading |

`OpaqueHash` (`mod.rs:137`) keeps rank 10 and its meaning: `approveHash(bytes32)` still decodes,
is still admissible, and still leads the sheet when nothing worse is present. Typed-only bounds
what the decoder can read, never what a decoded call may authorise.

---

## 13. The grant

`IntentKind` (`grant.rs:52-64`) gains one variant and one tag:

```rust
pub enum IntentKind {
    SafeTx,
    TypedData,
}

impl IntentKind {
    fn tag(self) -> u8 {
        match self {
            IntentKind::SafeTx => 1,
            IntentKind::TypedData => 2,
        }
    }
}
```

`ApprovedSafeTx` (`sign.rs:22-27`) is renamed `Approved` and gains `kind: IntentKind`; `finish`
reads `approved.kind` instead of hard-coding `IntentKind::SafeTx` (`sign.rs:70`). No shim.
Grepped: the type is **named** only inside `hc-sign/src/sign.rs` (`:6, :22, :37, :42, :56`).
`hc-mcp/src/proposal.rs:79` binds it as `let (_approved, summary) = …` by inference and needs no
edit; the only other occurrences are two prose mentions in that file's module doc
(`proposal.rs:3` "mirrors `ApprovedSafeTx`" and `:9` "Its `ApprovedSafeTx` is"), which go stale
and must be reworded in the same step.

What a typed-data grant binds, term by term (`GrantTerms`, `grant.rs:67-82`):

| Term | Typed-data value |
|---|---|
| `key_name` | `intent.key`, unchanged |
| `intent_digest` | the EIP-712 signing hash of §11 — the same 32 bytes `sign_with_grant` signs (`sign.rs:109`) |
| `policy_digest` | SHA-256 of the policy file bytes (`policy.rs:133`), **which already covers the schema**, because the schema lives in that file. No second digest is introduced. |
| `manifest_digest` | unchanged: the adapter's digest, or `B256::ZERO` for loopback and CLI (`hc-daemon/src/lib.rs:762-768`) |
| `kind` | `IntentKind::TypedData`, tag `2`, inside `canonical_bytes()` at `grant.rs:98` |
| `nonce`, `expires_at_ms` | unchanged |

`kind` being inside the signed canonical bytes means a SafeTx grant can never be replayed as a
typed-data grant even if the two digests were somehow equal.

**No second prompt and no widened TTL.** The flow is the identical split:
`prepare_typed_data` → `approver.approve(ctx, &summary)` → `finish`, with `finish` reusing the
same `LaContext` (`sign.rs:64-77`, `grant.rs:133-140`). `GRANT_TTL_MS` stays `5_000`
(`grant.rs:48`). The `Approved` value has private fields and is consumed by value, so
"the policy ran before the prompt" stays a fact of the type system for the new kind too.

`HotApi` gains `sign_typed_data(&self, ctx, intent: TypedDataIntent, approver) -> Result<SignResponse, SignErr>`
beside `05` §A.3's `sign_typed`, and `sign_intent` (`hc-daemon/src/lib.rs:749`) becomes the wire
wrapper that matches on `Intent` and dispatches. Both guards stay in the per-kind functions, not
the wrapper: `is_valid_string_name(&ctx.key)` (`:755-757`) and `intent.key != ctx.key`
(`:759-761`).

`manifest::evaluate` gains a typed-data counterpart. The existing `IntentKindNotGranted` check
(`manifest.rs:312-316`) hard-codes `IntentKind::SafeTx` and becomes a check against the request's
own kind, so **the manifest language already gates this**: an adapter whose grant lists
`intent_kinds = ["safe_tx"]` cannot submit typed data, with no new term. One term is added:
`grants.typed_data: Vec<String>`, the schema names the adapter may name, which `narrows` must
check is a subset of the policy's declared `schema` names (`Widened::Schema { schema }`).

---

# BOTH PARTS

## 14. Typed refusals

Every refusal below is a variant, every offending value is a **field**, nothing is formatted into
a string, and there is no catch-all arm. Inner errors nest as tuple variants before the `;`,
which is the form `err_mac` at rev `08f6335` generates `From` for — so `?` propagates with no
`map_err` (`CLAUDE.md`'s errors rule).

`AdapterErr` is empty today (`mod.rs:310-314`) and already nested in `SignErr::Adapter`
(`hc-sign/src/lib.rs:44`), so every variant below reaches `CliErr::Sign`, `MenuErr::Sign`,
`OpErr::Sign` and `McpErr::Sign` with no new plumbing — `05` §B.2's finding, re-confirmed.

```rust
create_err_with_impls!(
    #[derive(Debug)]
    pub AdapterErr,
    Batch(batch::BatchErr),
    Abi(alloy_dyn_abi::Error),
    Typed(TypedDenied)
    ;
    NoCalldata { at: Vec<usize>, to: Address, value: U256 },
    ArgumentsNotDecodable { at: Vec<usize>, to: Address, signature: String, len: usize, digest: B256 },
    EncodingNotCanonical { at: Vec<usize>, to: Address, signature: String, len: usize, digest: B256 },
    Field { at: Vec<usize>, to: Address, signature: String, arg: usize, name: String, source: FieldDenied }
);

create_err_with_impls!(
    #[derive(Debug)]
    pub BatchErr,
    ;
    Truncated { at: Vec<usize>, offset: usize, need: usize, have: usize },
    UnknownOperation { at: Vec<usize>, offset: usize, operation: u8 },
    DataLengthTooBig { at: Vec<usize>, offset: usize, data_length: U256 },
    DataLengthPastEnd { at: Vec<usize>, offset: usize, data_length: usize, have: usize },
    TooManyEntries { max: usize },
    TooDeep { at: Vec<usize>, max: usize }
);

create_err_with_impls!(
    #[derive(Debug)]
    pub TypedDenied,
    Abi(alloy_dyn_abi::Error),
    Field(FieldDenied)
    ;
    SchemaNotDeclared { schema: String },
    ChainMismatch { expected: U256, got: U256 },
    VerifyingContractMismatch { expected: Address, got: Address },
    SchemaNotResolvable { schema: String, primary_type: String },
    MessageNotAnObject { path: Vec<String> },
    MessageFieldMissing { path: Vec<String>, field: String },
    MessageFieldUnknown { path: Vec<String>, field: String },
    FieldNotCoercible { path: Vec<String>, field: String, declared: String },
    FixedBytesLength { path: Vec<String>, field: String, declared: usize, got: usize }
);
```

`FieldDenied` is §9.3. `CallDenied` (`policy.rs:70-79`) loses
`SelectorNotAllowed { selector }` and gains `SignatureNotAllowed { to: Address, selector: FixedBytes<4> }`.
`PolicyErr` (`policy.rs:105-113`) gains the eight load-time variants of §1.4 and §7.4.
`PolicyDenied` (`policy.rs:93-103`) gains `Typed(TypedDenied)` so a typed-data refusal reaches
`SignErr::PolicyDenied` on the paths that check authority, and `AdapterErr::Typed` covers the
decode-side ones. `Widened` (`manifest.rs:65-81`) trades `Selector` for
`Signature { to, signature: String }` and gains `Arg { to, signature: String, at: usize }` and
`Schema { schema: String }`.

`alloy_dyn_abi::Error` (`alloy-dyn-abi-0.8.26/src/error.rs:15-71`) is the one library error
nested here. It carries `MissingType`, `CircularDependency`, `TypeMismatch { expected, actual }`,
`EncodeLengthMismatch`, `TypeParser`, `SolTypes` — all in fields, none of them prose we wrote.

**Mode → variant, complete:**

| Mode | Variant |
|---|---|
| calldata shorter than 4 bytes (own call or entry) | `AdapterErr::NoCalldata` |
| destination not allow-listed | `CallDenied::ToNotAllowed` |
| destination allow-listed for the other operation | `CallDenied::OperationNotAllowed` |
| no declared signature at this destination has these 4 bytes | `CallDenied::SignatureNotAllowed` |
| arguments do not decode against the declared signature | `AdapterErr::ArgumentsNotDecodable` |
| arguments decode but re-encode differently | `AdapterErr::EncodingNotCanonical` |
| an argument violates its rule | `AdapterErr::Field` wrapping `FieldDenied::*` |
| native value over the rule's ceiling (own call **or entry**) | `CallDenied::ValueTooHigh` |
| batch payload malformed / over the entry cap / too deep | `AdapterErr::Batch(BatchErr::*)` |
| owner-management call not permitted | `PolicyDenied::OwnerManagementNotAllowed` |
| refund activity outside the allowance | `RefundDenied::*`, unchanged |
| schema not declared for this key | `TypedDenied::SchemaNotDeclared` |
| request's chain or verifying contract ≠ the declared domain's | `TypedDenied::{ChainMismatch, VerifyingContractMismatch}` |
| message has a field the schema does not declare | `TypedDenied::MessageFieldUnknown` |
| message is missing a declared field | `TypedDenied::MessageFieldMissing` |
| a value does not coerce to its declared type | `TypedDenied::FieldNotCoercible` |
| a `bytesN` value is not exactly N bytes | `TypedDenied::FixedBytesLength` |
| a typed field violates its rule | `TypedDenied::Field` wrapping `FieldDenied::*` |
| request carries `types` / `primaryType` / `domain` | `BodyErr::Malformed(serde_json::Error)` at `check_body` (`hc-daemon/src/lib.rs:598`) on both wire surfaces; `SignErr::Serde` at the second parse (`:758`) — never `SignErr::Serde` *at* `check_body`, which returns `BodyErr` (§8.1) |
| policy file still uses `selectors` | `PolicyErr::Toml` |
| unannotated contract | **no variant** (decision 7e) |

## 15. What stops being signable

Stated plainly, as decision 7's hazard list demands. Compared against **today's** behaviour, not
against `05`'s.

**Refused after this stage, signable before it:**

1. **Every call whose selector is allow-listed but whose signature is not declared.** This is
   `05` §B.0 (a), the hole 7a exists to close: today any four bytes an operator writes into
   `selectors = [...]` sign, rendered as `UNDECODED CALL 0x…: N bytes, sha256 …`
   (`call.rs:46-52`). The route back is a **policy edit**, not a code change — which is the whole
   difference from `05` §B.3 item 1. The narrowing is therefore an operational one, not a
   permanent capability loss: any function whose ABI the operator has can be declared.
2. **Any payload whose arguments do not decode against the declared signature**, and any payload
   that decodes but re-encodes differently — padded, truncated, dirty address upper bits, a
   `bool` word holding `2`. Today all of these render `UNDECODED CALL` and sign
   (`05` §B.0 (b), (b′)).
3. **Any argument outside its declared rule.** New capability, and it makes previously-signable
   things unsignable in the good direction: `transfer` to an unlisted recipient, `approve` of
   `U256::MAX` under a `max`, a `permit` deadline a year out.
4. **Any `multiSend` whose packed payload has trailing bytes, an `operation` byte outside {0,1},
   or a `dataLength` past the end.** Today `Alarm::BatchMalformed`, display-only, and it signs
   (`batch.rs:254-263`).
5. **Any `multiSend` tree over 32 entries or nested past depth 2.** Today the depth cap only
   truncates the display (`Body::Unexpanded`).
6. **Any `multiSend` whose entries are not each individually permitted, decodable and
   argument-bounded.** Today entries are checked by nothing at all (`batch.rs:6-10` says so).
   In practice a policy that allow-lists only the MultiSend library for `delegatecall` will now
   refuse **every** batch until the operator adds a rule per destination the batch touches. This
   is the largest migration burden in the stage — see open question 2.
7. **`multiSend` entries carrying native value above the matching rule's `max_value`**, which
   today no ceiling reaches.
8. **`multiSend` entries with empty calldata** (a plain ETH send inside a batch) — `NoCalldata`.
   Today they render `no calldata (value transfer only)` (`call.rs:39-41`) and are counted as
   undecoded.
9. **For adapter provenance: `multiSend` entries outside the adapter's own manifest grant.**
   Today a batch is bounded by the manifest only at the outer call.
10. **Every existing policy file, until converted** (§5). `serve` refuses to start on a machine
    with a pinned adapter whose granted key still has a `selectors` policy.

**Refused before and after, but by a different variant:**

- **A plain ETH transfer as the transaction's own call** (`value > 0`, `data` empty). Refused
  today by `CallDenied::NoSelector` / `PolicyDenied::NoSelector` (`policy.rs:192-194,276-278`),
  which decision 7d keeps as *behaviour*. After this stage the refusal is raised **earlier and by
  a different layer**: §4.1 step 1 returns `AdapterErr::NoCalldata { at, to, value }` before the
  policy match at step 3 ever runs. The outcome is identical — refused inside `prepare`, no
  biometric, no way for `AllowRule` to permit it — but the variant an operator sees changes, and
  `dryrun.sh`/README text that names `NoSelector` must be updated with it.

  **AUDIT — decide the fate of `CallDenied::NoSelector` and `PolicyDenied::NoSelector`.** If step 1
  guarantees four bytes before any `match_call`, both become unreachable, and `CLAUDE.md`'s
  delete-dead-paths rule says delete them — which also deletes the `CallDenied::NoSelector`
  assertion in `each_deny_branch_and_rotation_allow` (`policy.rs:372-377`), a test the plan lists
  nowhere. The alternative is to keep step 1's check *inside* `match_call` so the policy layer
  still owns the refusal, which is closer to decision 7d's wording ("refused by the policy layer's
  `NoSelector`, **not** by the decoder"). The second reading is the safer one and is not what §4.1
  currently specifies. Resolve before step 3.

  Either way `AllowRule` still has no way to permit a call with no selector, so **the owner still
  cannot send ETH from the Safe through hot_cheese at all.** This stage does not fix it and does
  not pretend to; it is `05`'s open question 1 and remains open (§17).

**Newly signable, which must also be said out loud:**

- **Every function an operator can name.** The 19-function ceiling is gone.
- **EIP-712 typed messages** at a declared domain against a declared schema — new authority that
  did not exist before. It is bounded by: the schema must be in the key's policy; the domain is
  the policy's; every field must be declared and ruled; an adapter needs `typed_data` in
  `intent_kinds` **and** the schema name in `grants.typed_data`. But it is genuinely new, and an
  operator who declares a schema with every field `unbounded` has written a blank cheque with the
  word "unbounded" typed into it seven times.

**Still signable, unchanged:**

- **Calls to contracts with no `[[token]]`/`[[label]]` entry** (decision 7e). Annotation absence
  is not a decode failure; `annotate.rs:1-7`'s invariant and both its tests are untouched.
- **`approveHash`.** It decodes and is admissible; `Alarm::OpaqueHash` survives at rank 10.
- **`delegatecall` to a decodable payload.** `Alarm::DelegatecallDecoded` survives. Policy still
  default-denies it, since no `AllowRule.operation` defaults to it (`policy.rs:59`,
  `intent.rs:9-11`).
- **Owner rotation, module/guard/fallback changes, gas refunds.** All decode; all keep their
  alarms and existing gates.
- **MCP-proposed ERC-20 transfers**, *after* the §3.1 fix. Today `hc-mcp` does **not** have its
  own `sol!`: `tools.rs:31` imports `Known` from `hc_sign::adapter` and `tools.rs:219` encodes
  with `Known::transferCall`. Once `hc-mcp` declares its own one-function interface, its calldata
  is canonical ERC-20 `transfer(address,uint256)` and admits — provided the operator declares that
  signature, which the §5 table gives them verbatim. Until that fix lands the crate does not
  compile at all; it is not a "still signable" row, it is a step-4 work item.

---

## 16. Ordered steps

`05` Half A runs first and is unchanged. Every step below builds and passes on its own.

**Verification after every step, without exception:**

```
cargo build --release
cargo test --release --workspace
cargo clippy --release --all-targets -- -D warnings
```

`CLAUDE.md`: release only, and `#[allow(clippy::…)]` is banned — a clippy finding is fixed, not
silenced.

### Step 1 — the dependency, alone
Add `alloy-dyn-abi = { version = "=0.8.26", features = ["eip712"] }` and
`alloy-json-abi = "=0.8.26"` to the workspace and to `crates/hc-sign/Cargo.toml`. Nothing uses
them yet. **Additional verification: `cargo deny check` (all four checks) run BEFORE and AFTER,
with the two outputs diffed. The gate is "no new finding", not "clean" — the three `winnow`
versions already in the lock fail `multiple-versions = "deny"` today (§2.2).** Also assert
`git diff Cargo.lock` adds exactly one `[[package]]`, `alloy-dyn-abi 0.8.26`. If either check
fails, stop; §2.2 is wrong about something and the rest of the plan depends on it.

### Step 2 — `schema.rs`, with no callers
Create `crates/hc-sign/src/schema.rs` holding `Signature`, `CallRule`, `ArgRule`, `FieldRule`,
`FieldDecl`, `TypeDecl`, `DomainDecl`, `TypedDataSchema`, `FieldDenied`, `OWNER_MGMT`,
`MULTI_SEND`, `selector4`, `match_call`, the field evaluator, and the load-time checks. Nothing
imports it yet. Tests: `every_owner_mgmt_signature_is_canonical`,
`a_non_canonical_signature_is_refused`, `two_signatures_sharing_a_selector_refuse_to_load`.

### Step 3 — the policy speaks signatures
Replace `AllowRule.selectors` with `AllowRule.call`, `OwnerMgmt.selectors` with `OwnerMgmt.call`;
delete `policy::selector4`; move `OWNER_MGMT`'s use site to `schema`; rewrite `match_call` to
return `Result<&CallRule, CallDenied>` over a `&Site`; update `manifest::narrows` to compare
canonical text and add `narrows_args`. **`manifest::evaluate` (`manifest.rs:306-330`) also changes
in this step and is easy to miss**: its last line is `Ok(match_call(&grant.calls, i)?)`, which
stops type-checking the moment `match_call` returns `&CallRule`, and it takes a `&SafeTxIntent`
where `match_call` now wants a `&Site`. Decide there whether it keeps its own call match at all,
given §4.1 step 4 re-runs one per site; if it drops it, say so, because the request-time manifest
call check then exists in exactly one place. Update every policy fixture in `policy.rs`'s and
`manifest.rs`'s tests, including `each_deny_branch_and_rotation_allow` (`policy.rs:339-410`),
`same_destination_rules_split_by_operation_and_duplicates_die_at_load` (`policy.rs:519-574`) and
`chain_id_is_required_to_load` (`policy.rs:485-502`), all three of which embed `selectors = [...]`
fixtures verbatim. This step **breaks every existing policy file on disk**; that is §5 and it is
intended. It also leaves `scripts/demo.sh`'s and `scripts/dryrun.sh`'s policy heredocs broken
until step 7 — no compile break, but the scripts must not be run in between.

### Step 4 — the typed tree, with no undecoded representation
Delete the `sol!` `interface Known`, `canonical`, `SAFE_CONFIG`'s `Known`-derived form,
`unlimited`, `call::render`'s 19 arms and its two fallback branches, `DIGEST_CHARS`,
`batch::unlistable`, `Body::{Undecoded, Unexpanded}`, `Alarm::{DelegatecallUndecoded,
BatchMalformed, SelfCallUndecoded, Undecoded, UnlimitedApproval}` and `Alarm::Batch`'s two
counters. Add `Site.value`, `TypedCall`, `TypedTx`, `admit`, the generic `call::render`. Populate
`AdapterErr`; make `BatchErr` public with tree paths and `TooDeep`. Rewrite `batch.rs`'s module
doc (`batch.rs:1-22`) and `Alarm::Batch`'s line so it stops claiming the sub-calls are unchecked
(`mod.rs:197-198`) — **in the same commit that starts checking them, not one commit later.**
Change `prepare` to call `admit` and make `summary` a method on `TypedTx`.

Give `hc-mcp` its own `sol!` for `transfer(address,uint256)` and rewrite `tools.rs:1-22`'s
shared-`sol!` claim (§3.1) — without this the workspace does not build after `Known` goes.

Fix the two `hc-mcp` display surfaces that hold an intent which may not admit:
`StatusView.summary: String` (`hc-mcp/src/tools.rs:318-332`, written at `:462`) becomes a
two-variant tagged enum following `Verdict`'s in-repo *shape* precedent (`tools.rs:334-343`), and
`preview_erc20_transfer`'s `adapter::summary` call (`tools.rs:495`) handles the refusal.
Copy `Verdict`'s tagging, **not** its payload: `Verdict::Denied { denial: String }` is built from
`e.to_string()` (`tools.rs:486,490`), which is an error formatted into a string and is exactly
what `CLAUDE.md` bans. The new variant carries the refusal's own fields, or the variant name alone.

### Step 5 — the typed-data intent kind
Add `Intent::TypedData(TypedDataIntent)`; fix the nine destructuring sites of §6.1; add
`IntentKind::TypedData`; rename `ApprovedSafeTx` to `Approved` with a `kind` field; add
`prepare_typed_data`, `HotApi::sign_typed_data`, and the `sign_intent` dispatch. Schemas are not
declared yet, so every typed-data request refuses with `SchemaNotDeclared` — which is the correct
fail-closed intermediate state and makes the step self-contained.

### Step 6 — schemas, digests and rendering
Add `Policy.typed_data`, the load-time schema checks (§7.4), the policy-built `Resolver` and
`Eip712Domain`, the single-coercion digest (§8.2), the field-set walk (§7.3 check 6), the
`bytesN` length check (§8.4), the field evaluator's typed-data call site, and the typed-data
renderer with its three alarms. Add `manifest`'s `grants.typed_data` term and its `narrows`
check.

### Step 7 — scripts and docs
`scripts/demo.sh`'s policy heredoc (`05` §A.4's step 7) becomes the §1.3 "after" form.
`scripts/dryrun.sh` phase 5's three policy heredocs (`:940-948`, `:956-964`, and the 5b variant)
gain declared signatures; its selector-based policy becomes signature-based, and a new phase
asserts a typed-data refusal costs no biometric. Run `bash -n` on both.

`README.md`: the manifest example (`:589-604`, whose `[[grants.calls]]` block at `:599-603`
carries the `selectors` line — the README has **no** standalone `[[allow]]` example, so do not go
looking for one), the "same rule language" paragraph (`:606-610`), the narrowing table
(`:631-638`, whose `selectors ⊇` row becomes a canonical-text row), the §5 migration note, and the
typed-only rule replacing `README.md:1103-1105`'s now-false "you can still sign a delegatecall by
hand".

**`MIGRATION.md` is not optional and neither plan mentioned it.** It is the document that teaches
`selectors`, and after step 3 it teaches an unloadable file:
`:30-31` ("a policy `[[allow]]` rule carrying a term this build does not implement"), `§6` at
`:295-320` — the canonical `[[allow]]` example with `selectors = ["0xa9059cbb"]` at `:309` and its
explanation at `:317-318` — the manifest example at `:365-373` (`selectors` at `:371`), and
`:387-390`. Every one of those becomes wrong in the same step that makes it wrong. The §5
conversion table belongs here, beside §6, more than it belongs in the README.

### Step 8 (optional, purely nominal) — rename the module
`hc_sign::adapter` means two things: the EIP-712 rebuilder / admission layer, and an
out-of-process *signing adapter* pinned by manifest. Rename to `hc_sign::decode`. Call sites, all
of them: `hc-sign/src/sign.rs:11,39,40`, `hc-sign/src/lib.rs:18,44`, `hc-sign/src/bundle.rs:10,82`,
`hc-sign/src/qr.rs:189`, `hc-sign/src/policy.rs:2`, `hc-mcp/src/tools.rs:5,31,462,494,495`. No
re-export shim. Drop this step freely.

### Tests

Per `CLAUDE.md`: only new non-trivial logic and crucial invariants. No test that `if` works, that
arithmetic works, or that serde round-trips.

1. **`a_self_declared_shape_never_reaches_the_signer`** — added as new cases to the **existing**
   `unparseable_bodies_are_refused_before_any_approval` (`hc-daemon/src/lib.rs:1118-1144`) rather
   than as a new test in `hc-sign/src/intent.rs`. That test already asserts exactly this
   composition for `safe_tx` (`:1137-1143`); a second test asserting it again for `typed_data`
   somewhere else is the duplication `CLAUDE.md` warns about, and putting it beside `check_body`
   is what makes it assert the *boundary* (`BodyErr::Malformed`, before any approval) rather than
   just `serde_json::from_slice`. Bodies: `types`, `primaryType`, `domain` each beside
   `kind = "typed_data"`, and the same three inside a `safe_tx` body. This is the one serde
   assertion this stage earns, and it is the executable form of §8.1.
2. **`a_refusal_never_reaches_the_approver`** (`hc-daemon/src/lib.rs` test module). The brief's
   second mandatory test, and the ordering invariant the whole stage rests on. `TestBackend` +
   `Config::for_test` (`hc-core/src/config.rs:364-374`, which supplies a `grant_public_key`) and
   a counting approver over a `parking_lot::Mutex<usize>` (`CLAUDE.md`: parking_lot everywhere,
   including test fakes). Assert the count is **0** after: a policy-denied SafeTx; an
   allowed-destination SafeTx whose arguments do not decode; an argument over its rule; a
   typed-data request naming an undeclared schema; a typed-data request whose message has an
   extra field. Assert the five return different typed errors. Same shape as the existing
   `read_refuses_a_sign_only_key_before_any_unlock` (`hc-daemon/src/lib.rs:1023-1058`).
3. **`a_constraint_violating_field_is_refused`** (`hc-sign/src/schema.rs`). The brief's third
   mandatory test, one table over the shared evaluator: `OneOf` with an unlisted address; `Max`
   one over the ceiling; `Eq` off by one; `Deadline` one second past `now + within_secs`;
   `Enum` with an unlisted string; `Each` one element over `max_len`; and `Unbounded` accepting
   all of the above. Each asserts the specific `FieldDenied` variant and its fields.
4. **`every_undecodable_shape_is_refused`** (`hc-sign/src/adapter/mod.rs`). One table: unknown
   selector → `CallDenied::SignatureNotAllowed`; declared `transfer` with a truncated argument
   region → `ArgumentsNotDecodable`; canonical `transfer` with byte 4 set to `0xff` →
   `EncodingNotCanonical`; canonical `setApprovalForAll` whose `bool` word holds `2` →
   `EncodingNotCanonical`; empty `data` → `NoCalldata`; batch with 8 trailing bytes →
   `Batch(Truncated)`; `operation` byte 2 → `Batch(UnknownOperation)`; `dataLength` one past the
   end → `Batch(DataLengthPastEnd)`; `dataLength` of `1 << 64` → `Batch(DataLengthTooBig)`; 33
   entries → `Batch(TooManyEntries)`; a nest three deep → `Batch(TooDeep)`; a clean batch with one
   unknown-selector entry → `SignatureNotAllowed` with a non-empty `at`. Every fixture already
   exists in the tests being converted (`mod.rs:606-622,988-1009`, `batch.rs:400-440,494-533`);
   this test is their **inversion**.
5. **`a_batch_entry_is_checked_against_the_policy`** (`hc-sign/src/schema.rs`). A `multiSend`
   whose outer `delegatecall` to the library is permitted and whose single entry calls an
   undeclared destination → `CallDenied::ToNotAllowed`; with a rule for that destination → `Ok`;
   with the entry's value over the rule's `max_value` → `CallDenied::ValueTooHigh`. The property
   `batch.rs:6-10` was written waiting for.
6. **`the_typed_digest_matches_alloys_own`** (`hc-sign/src/adapter/typed.rs`). Build the
   policy-derived `Resolver`, `Eip712Domain` and `DynSolValue`; assert the single-coercion digest
   equals `TypedData { domain, resolver, primary_type, message }.eip712_signing_hash()`. This is
   the §8.3 proof obligation as an executable check, and it is the guard against a future edit
   that lets the rendered value and the hashed value diverge.
7. **`a_declared_signature_derives_its_own_selector`** (`hc-sign/src/schema.rs`). The 19-row
   migration table of §5: each canonical signature's `Function::parse(...).selector()` equals the
   published selector. Non-trivial because it is what makes the README's conversion table safe to
   follow, and it is deletable when the migration window closes.

**Converted, not deleted:** `undecodable_payloads_stay_distinguishable` (`mod.rs:606-622`),
`the_undecoded_digest_is_the_whole_hash` (`mod.rs:1053-1060`),
`a_non_canonical_encoding_stays_undecoded` (`mod.rs:988-1009`),
`a_malformed_batch_never_renders_as_a_clean_one` (`batch.rs:400-440`),
`batch_caps_refuse_to_render_a_partial_list` (`batch.rs:494-533`) all fold into test 4 — their
subject survives, their assertion inverts. `a_batch_lists_every_sub_call_and_order_matters`
(`batch.rs:446-488`) drops its `opaque` entry and keeps its order-matters half.
`every_decoded_field_reaches_the_screen` (`mod.rs:629-982`) is rewritten against the generic
renderer: same property (a changed argument must change the line), driven by declared signatures
instead of `sol!` variants.

**Untouched and must stay green:** `safe_tx_hash_matches_hand_rolled_eip712` (`mod.rs:502-551`),
`two_transfers_never_render_the_same` (`mod.rs:576-600`), `summary_flags_refund_drain`
(`mod.rs:558-570`), `the_sheet_shows_the_worst_thing_first` (`mod.rs:1017-1046`), both
`annotate.rs` tests (`:101-114`, `:120-149`), every `grant.rs` test, `hc-core/tests/boundary.rs`,
`hc-mcp/tests/fence.rs`.

---

## 17. Risks and open questions

### Open questions — decide before implementing

1. **A bare ETH transfer from the Safe is still not expressible.** `AllowRule` has no way to
   permit a call with no selector (`policy.rs:51-60,192-194`), decision 7d keeps that, and this
   stage makes it permanent in the decoder too (`AdapterErr::NoCalldata`). It predates the stage
   and it is the most obvious thing an owner plainly needs. **Recommendation: do not fix it
   here** — it is a policy-language change that *widens* what may be signed, and widening under
   cover of a stage about narrowing is how mistakes ship. Say it in the README.
2. **`admit` will refuse every batch on every existing policy** until operators add a rule per
   destination the batch touches, with declared signatures and argument rules for each. That is
   strictly more work than `05` foresaw, because `05` only needed a rule per destination and this
   needs a signature and every argument bounded. **Recommendation:** ship it, and lean on
   `bundle status`, which after step 4 shows the typed refusal for any stored bundle that no
   longer admits — that *is* the dry run, on a surface operators already use.
3. **Typed data has no multi-device signature collection.** `SafeTxBundle.intent` is a
   `SafeTxIntent` by type (`bundle.rs:51`), so a `SafeMessage` signed under §10 returns one
   signature from one device. A Safe's EIP-1271 `isValidSignature` runs `checkNSignatures` and
   therefore needs the threshold, exactly as a transaction does. So §10's schema is genuinely
   useful **only** on a 1-of-N Safe or for a contract that checks a single signer.
   **Recommendation: ship it and say so.** A `TypedDataBundle` is its own change with its own
   digest-naming, quarantine and rival semantics, and bolting it on here would double the stage.

   **Priced, so the owner can decide rather than guess.** The limitation is confirmed:
   `SafeTxBundle.intent` is a `SafeTxIntent` by type (`hc-sign/src/bundle.rs:52`) and
   `SafeTxBundle::digest()` is `adapter::safe_tx_hash(&self.intent)` (`bundle.rs:81-83`), so the
   directory name, the recovery digest and the union merge are all rooted in a Safe transaction.
   What multi-device typed data would actually cost:
   - `hc-sign/src/bundle.rs` (312 lines): `SafeTxBundle` becomes generic over the intent, or a
     second `TypedDataBundle` appears beside it. `recover` (`:62-77`), `owners_ok`, `met` and the
     `CollectedSignature` list are digest-agnostic and are reused as-is; the union-merge tests
     that decision 4 rests on are about the signature set, not the intent, and carry over.
   - `hc-bundle/src/lib.rs` (~700 lines): `new`, `collect`, `merge`, `status`, `load_dir`, `rm`,
     `list` and the `Safes` lookup all key off `(safe, chain_id)` and `digest()`. A typed message
     has a `verifyingContract` and a `chainId` but **no nonce**, so the `(safe, chain, nonce)`
     rival/slot logic has no counterpart and needs a decision, not a port. `export` has no
     counterpart at all — there is no `execTransaction` to assemble; the deliverable is the
     concatenated 65-byte signatures in ascending-signer order for `isValidSignature`.
   - Surfaces: `bundle new/sign/status/list/qr` in `hc-cli/src/bundle.rs`, the console's
     `bundles.rs` screens, `hc-mcp`'s `bundle_status`, and `hc-sign/src/qr.rs`'s framing.
   - Sync is free: it is union merge over per-signer digest-named files (decision 4) and does not
     look inside.

   **Estimate: comparable to stage 3, and larger than the whole of Part 2 of this plan.** The
   irreducible new design is the slot/rival semantics for a nonce-free message and what `export`
   means. Everything else is mechanical. It is a stage of its own, and pricing it here is the
   point of the question — not a reason to start it.
4. **Should the `FieldRule` TOML be internally tagged?** `#[serde(tag = "kind")]` requires serde's
   content buffering, and `hc_core::wire::u256`'s deserializer uses `deserialize_any`
   (`hc-core/src/wire.rs:36`). Un-buffered it demonstrably works under `toml = "=0.8.2"` today:
   `chain_id_is_required_to_load` (`policy.rs:485-502`) parses `chain_id = 1` from TOML through
   that exact codec. Buffering through `serde::__private::de::Content` is the only new variable.
   **VERIFY** it at implementation time — write one fixture parse of a
   `rule = { kind = "max", max = "1000000000", amount_of = "0x…" }` line before building anything
   on it. If it does not round-trip, the fallback is an externally tagged enum
   (`rule = { max = { max = "…", amount_of = "…" } }`), which is uglier in TOML but has no
   buffering. Note this decision is load-bearing for **every** TOML example in §1.3, §7.2 and §10.
5. **Is `Body::Call` borrowing `&'p CallRule` the right lifetime shape?** It ties `TypedTx` to the
   `&Policy` borrow for the whole of `prepare`. That is true today anyway (`prepare` holds
   `&LoadedPolicy`), but if it fights the borrow checker at the `hc-mcp` display sites, the
   alternative is to clone the matched `CallRule` into the tree. It is a small struct and cloning
   is honest; do not contort the lifetimes to avoid it.

### Risks

- **The policy files get much longer.** A rule that was one line of `selectors` becomes a block
  per call plus a block per argument. That is the cost of "an unconstrained permit must be
  impossible to express by accident", and it is paid by the operator every time. If it turns out
  to be intolerable in practice, the pressure will be to add a defaulted "unbounded" — **which
  must be refused**, because it re-creates exactly the accident §9.2 exists to prevent.
- **A 4-byte selector collision between two declared signatures at one destination** is refused
  at load (§1.4), but a collision between a *policy* signature and a *manifest* signature is
  caught only because `narrows` compares canonical text (§4.4). If a future edit "optimises" that
  comparison to compare selectors, the manifest regains the ability to declare a different call.
  The comparison-on-text is load-bearing and should say so in the test name.
- **Non-canonical encodings from real tooling.** The re-encode check is byte-exactness. It is
  already the rule for *display* (`mod.rs:347-356`); making it the rule for *admission* means any
  encoder whose output differs by a padding byte is refused. Unverified against real-world
  tooling, exactly as `05` flagged.
- **`alloy-dyn-abi`'s coercion is looser than it looks.** §8.4 documents two cases found by
  reading the source. There may be more. The mitigation that generalises is the §16 test 6
  cross-check plus rendering every value from the *coerced* form, so whatever alloy decided is
  what the human reads.
- **`admit` runs on untrusted input before any per-entry authority check exists to short-circuit
  it.** It is bounded — the body is capped at 64 KiB (`hc-daemon/src/lib.rs:561`), the tree at 32
  entries and depth 2 — and the policy match for each site runs *before* that site's decode, so
  the decoder only ever runs on bytes aimed at an allow-listed destination. No unbounded
  recursion: depth is bounded by `MAX_BATCH_DEPTH` and breadth by the shared `left` counter,
  exactly as `parse` already is (`batch.rs:129-134,140-145`).
- **A typed-data schema is new authority in a file operators already have.** Adding
  `[[typed_data]]` to a policy grants off-chain signing power that did not previously exist on
  this machine. The `serve` startup that loads every policy for `manifest::check` is the natural
  place to log the schema names in force, so an operator sees them at start rather than at
  incident.
- **`scripts/dryrun.sh` is a human-driven transcript with biometric-tap accounting**
  (`:982-983`, `:1010-1011`). Its phase 5 policies must be converted in the same step that
  converts the code, and the new typed-data phase must not move the tap counts — a refusal costs
  no biometric, which is exactly what §16 test 2 asserts in Rust and what the transcript asserts
  by hand.
