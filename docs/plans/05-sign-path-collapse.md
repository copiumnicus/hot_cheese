# Stage 5 — Delete the human raw-JSON sign path

Input: `docs/plans/00-design-decisions.md` (decisions 5, 6) and `CLAUDE.md`. This stage is
subtraction: the CLI `sign` subcommand and the console's type-a-file-path Sign screen go, and the
JSON round trip behind `bundle sign` collapses.

**Half B — typed-only enforcement — has moved to `docs/plans/06-typed-admission.md`.** What
survives here is §B.0, the ground truth about what the decoder does TODAY, because `06` builds on
it and does not restate it in full.

Every file:line below was read. Where something could not be established from the source in this
repo it is marked **VERIFY** and is not asserted.

---

## 0. The one door, confirmed

Every signature in the process funnels through:

`HotApi::sign_intent` (`crates/hc-daemon/src/lib.rs:749`) → `hc_sign::sign::prepare`
(`crates/hc-sign/src/sign.rs:32`) → the caller's approver → `hc_sign::sign::finish`
(`:55`) → `hc_sign::sign::sign_with_grant` (`:95`), which takes a `SignGrant` **by value**.

`prepare` is the whole refusal surface and it runs before the prompt:

```
crates/hc-sign/src/sign.rs:38-40
    policy::evaluate(&intent, &policy.policy)?;
    let digest = adapter::safe_tx_hash(&intent);
    let summary = adapter::summary(&intent, config);
```

`ApprovedSafeTx` has private fields and no constructor but `prepare`, and `finish` takes it by
value (`sign.rs:22-27,55`), so "the policy ran before the prompt" is a fact of the type system.
Everything `06-typed-admission.md` adds goes **inside `prepare`**, which is what preserves that
property for free.

Entry points that reach `prepare`:

| Entry | Where | Fate |
|---|---|---|
| CLI `hot_cheese sign [--file]` | `hc-cli/src/lib.rs:172-177,363,728-734` | **deleted** (decision 5) |
| CLI `bundle sign <hash> --key` | `hc-cli/src/bundle.rs:31-37,122-127` | kept |
| Console `Sign` screen (types a path at `inquire::Text`) | `hc-console/src/menu.rs:637-651` | **deleted** (decision 5) |
| Console `Bundles → Sign` (types nothing) | `hc-console/src/bundles.rs:371-398` | kept |
| HTTPS `/sign/<KEY>` loopback | `hc-daemon/src/lib.rs:426,516` | kept |
| Adapter socket `/sign/<KEY>` | `hc-daemon/src/lib.rs:433`, socket 0600 | kept |
| MCP `Proposal::check` (dry run only, drops its `ApprovedSafeTx`) | `hc-mcp/src/proposal.rs:79-81` | kept |

`hc-mcp` cannot sign structurally: it does not depend on `hc-daemon`
(`hc-mcp/src/lib.rs:1-35`, `hc-core/tests/boundary.rs`, `hc-mcp/tests/fence.rs`).

---

# HALF B — superseded, except for the ground truth below

The DESIGN of Half B is now `docs/plans/06-typed-admission.md`. It was written against a stricter
reading of decision 7 that would have left only the 19 functions in the `sol!` block signable; the
owner has since ruled that policy declares full canonical signatures and that EIP-712 typed data
becomes a first-class intent kind. `06` §0 records what carried over and resolves the two
**VERIFY** items this file left open — `SolInterface::valid_selector` and
`alloy_sol_types::Error::UnknownSelector` both exist at `alloy-sol-types = "=0.8.26"`, and the
`err_mac` macro arms at rev `08f6335` are exactly as described here.

§B.0 below is kept verbatim. It is not design; it is the record of what the code does today, and
`06` cites it rather than re-deriving it.

## B.0 CRUX: what happens today, with the code

`prepare` calls `adapter::summary` (`hc-sign/src/adapter/mod.rs:367`), whose only decode is:

```
crates/hc-sign/src/adapter/mod.rs:353-356
fn canonical(data: &[u8]) -> Option<Known::KnownCalls> {
    let call = Known::KnownCalls::abi_decode(data, true).ok()?;
    (call.abi_encode() == data).then_some(call)
}
```

`Known` is the `sol!` interface at `mod.rs:23-46`. It declares exactly **19 function
signatures** (18 names; `safeTransferFrom` is overloaded): `swapOwner`,
`addOwnerWithThreshold`, `removeOwner`, `changeThreshold`, `transfer`, `approve`,
`transferFrom`, `increaseAllowance`, `decreaseAllowance`, `setApprovalForAll`, `permit`,
`enableModule`, `disableModule`, `setGuard`, `setFallbackHandler`, `approveHash`,
`safeTransferFrom(address,address,uint256)`,
`safeTransferFrom(address,address,uint256,bytes)`, `multiSend`. **That set is the decoder's
entire vocabulary.** Nothing else exists.

### (a) An unrecognised 4-byte selector the policy nonetheless allows

**Signing proceeds.** `policy::match_call` reads only the first four bytes:

```
crates/hc-sign/src/policy.rs:195-199
    if !rule.selectors.contains(&FixedBytes::from(sel)) {
        return Err(CallDenied::SelectorNotAllowed { selector: FixedBytes::from(sel) });
    }
```

so any 4 bytes an operator writes into `selectors = [...]` passes. `canonical` then returns
`None`, `alarms` pushes `Alarm::Undecoded` (`mod.rs:289`), and the human is shown:

```
crates/hc-sign/src/adapter/call.rs:46-52
        return match selector4(&site.data) {
            Some(s) => format!("UNDECODED CALL 0x{}: {len} bytes, sha256 {short}", hex::encode(s)),
            None => format!("UNDECODED CALL: {len} bytes, sha256 {short}"),
        };
```

plus `"\u{26a0} UNDECODED{at}: the arguments of this call are not readable"` (`mod.rs:249-251`).
That is the hex/"unknown" fallback decision 7 deletes. Pinned today by
`undecodable_payloads_stay_distinguishable` (`mod.rs:606-622`) and
`the_undecoded_digest_is_the_whole_hash` (`mod.rs:1053-1060`).

### (b) A recognised selector whose ABI arguments fail to decode

**Signing proceeds, identically to (a).** Two materially different failures collapse into the
same `None` at `mod.rs:354-355`:

- `abi_decode` errors (truncated or malformed argument region);
- `abi_decode` succeeds but `call.abi_encode() != data` — a non-canonical encoding. The comment
  at `mod.rs:347-352` gives the reason the second check exists: `bool`'s token validation only
  requires the first 31 bytes of the word to be zero, so a final byte of `2` decodes as `true`.

Both render `UNDECODED CALL 0xa9059cbb: 68 bytes, sha256 …`. Pinned by
`undecodable_payloads_stay_distinguishable` (dirty address word, `mod.rs:616-621`) and
`a_non_canonical_encoding_stays_undecoded` (`mod.rs:988-1009`). If `to == safe` the alarm is
`SelfCallUndecoded` (`mod.rs:286-288`); under `Delegatecall` it is `DelegatecallUndecoded`
(`mod.rs:282`). All three permit the signature.

### (c) A batch whose inner calls cannot all be expanded

**Signing proceeds in all three sub-cases.**

1. **The packed payload does not parse.** `batch::parse` (`batch.rs:90-162`) returns
   `BatchErr::{Truncated, UnknownOperation, DataLengthTooBig, DataLengthPastEnd, TooManyEntries}`
   (`batch.rs:47-56`). `batch::alarms` converts that into a *display* alarm, not a refusal:

   ```
   crates/hc-sign/src/adapter/batch.rs:254-263
       Err(err) => {
           return vec![Raised { alarm: Alarm::BatchMalformed { err, payload: payload.clone() },
                                site: site.clone() }]
       }
   ```

   and `batch::render` prints `⚠ MALFORMED BATCH (…)` or `⚠ BATCH TOO LARGE: over 32 entries`
   with a length and sha256 (`batch::unlistable`, `batch.rs:191-200`). No entry is listed —
   correctly, since a partly-parsed batch has no proven boundaries (`batch.rs:20-22`) — and the
   transaction is still signable.
2. **An entry's calldata does not decode canonically** → `Body::Undecoded` (`batch.rs:147`),
   counted in the roll-up (`batch.rs:280`), rendered by the same `UNDECODED CALL` line
   (`batch.rs:219` → `call.rs:42`). It raises **no** hoisted alarm at all (`batch.rs:243-250`
   states why).
3. **A nested `multiSend` past `MAX_BATCH_DEPTH = 2`** → `Body::Unexpanded`
   (`batch.rs:140-142`), rendered `⚠ NESTED BATCH BEYOND DEPTH 2: N bytes, sha256 …`
   (`batch.rs:221-225`), counted as `unexpanded`. Signable.

Note the precondition: the batch is only walked when the *outer* calldata canonically decodes to
`multiSend` (`mod.rs:377-379`). A `multiSend` selector with non-canonical arguments never reaches
`batch::parse` at all — it is case (b).

Also note the roll-up's own wording, which this stage makes false:
`"{calls} sub-calls{unread}, none of them checked by policy"` (`mod.rs:196-198`), and the module
doc that calls itself a stopgap: *"The real fix is a sub-policy evaluated over batch entries;
until there is one, this is the stopgap"* (`batch.rs:9-10`).

### (d) `data` empty with non-zero `value` — a plain ETH transfer

**Signing does NOT proceed today, and the refusal is the policy's, not the decoder's.**

```
crates/hc-sign/src/policy.rs:157-163
fn selector4(i: &SafeTxIntent) -> Option<[u8; 4]> {
    i.data.get(..4).map(|s| { ... })
}
```

`get(..4)` on fewer than four bytes is `None`, so:

- `to != safe` → `match_call` reaches `policy.rs:192-194` → `CallDenied::NoSelector`;
- `to == safe` → `evaluate` reaches `policy.rs:276-278` → `PolicyDenied::NoSelector`.

Both are inside `prepare` before the approver, so a bare ETH transfer already costs no biometric
and already cannot be signed. The renderer's `"no calldata (value transfer only)"`
(`call.rs:39-41`) is therefore **unreachable for a transaction's own call**. It is reachable for a
*batch entry* with empty data — which decodes to `Body::Undecoded` (`abi_decode` on zero bytes
fails) and is counted as `undecoded` in the roll-up while printing that line
(`batch.rs:219` → `call.rs:39`) — and from `hc-mcp`'s `bundle_status`, which renders
`adapter::summary` for any stored bundle (`hc-mcp/src/tools.rs:462`) whether or not it is signable.

### (e) A call to a contract with no `[[token]]` / `[[label]]` annotation

**Signing proceeds, and nothing about the decode changes.** Annotation is purely additive:

```
crates/hc-sign/src/adapter/annotate.rs:56-61
pub(super) fn amount(v: U256, token: Address, chain_id: U256, config: &Config) -> String {
    match find(config, token, chain_id) {
        Some(t) => marked(format!("{} {} ({v})", scaled(v, t.decimals), t.symbol), v),
        None => count(v),
    }
}
```

`address` returns the full EIP-55 address and only appends a name (`annotate.rs:67-74`). The
module doc states the invariant (`annotate.rs:1-7`): an unconfigured `(address, chain_id)`
renders exactly what an empty table renders, pinned by
`a_label_is_appended_to_the_whole_address_never_substituted_for_it` (`annotate.rs:101-114`) and
`an_amount_shows_the_scaled_and_the_raw_form_together` (`annotate.rs:120-149`).

### Summary of the crux

| Case | Signs today? | What the human sees | Fallback? |
|---|---|---|---|
| (a) unknown selector | **yes** | `⚠ UNDECODED` + `UNDECODED CALL 0x…: N bytes, sha256 …` | hex-ish digest |
| (b) known selector, args undecodable | **yes** | same line | hex-ish digest |
| (b′) known selector, non-canonical encoding | **yes** | same line | hex-ish digest |
| (c1) batch payload malformed / over cap | **yes** | `⚠ MALFORMED BATCH` / `⚠ BATCH TOO LARGE`, no entries listed | length + sha256 |
| (c2) batch entry undecodable | **yes** | entry line `UNDECODED CALL …`, counted in roll-up | hex-ish digest |
| (c3) nested batch past depth 2 | **yes** | `⚠ NESTED BATCH BEYOND DEPTH 2 …` | length + sha256 |
| (d) empty data, non-zero value | **no** — policy `NoSelector` | n/a (refused in `prepare`) | none |
| (e) unannotated contract | **yes** | raw address + raw integer | not a fallback: this is correct |

---

The design that used to follow — §B.1 the admission rule, §B.2 the typed refusals, §B.3 what
stops being signable — is superseded by `06-typed-admission.md` §§1-15.

---

# HALF A — delete the human raw-JSON sign path

## A.1 Deletion list

### CLI (`crates/hc-cli/`)

| Delete | Where |
|---|---|
| `Commands::Sign { file }` clap variant + its doc line | `src/lib.rs:172-177` |
| the dispatch arm `Commands::Sign { file } => cmd_sign(file, unlock)` | `src/lib.rs:363` |
| `fn cmd_sign` and its doc | `src/lib.rs:726-734` |

**Not dead, do not delete:** `read_input` (`src/lib.rs:696-704`) is still used by
`bundle new` (`src/bundle.rs:118`), `bundle add-sig` (`:147`) and `bundle merge` (`:261`).
`sign_intent_locally` (`src/lib.rs:710-724`) is still used by `bundle sign` (`src/bundle.rs:124`);
it changes shape in A.3 but stays. `cli_context` (`src/lib.rs:1025-1031`) is used by five other
operations.

**Test that breaks and must be updated:**

```
crates/hc-cli/src/lib.rs:1347-1349
        let cli = Cli::try_parse_from(["hot_cheese", "--unlock", "se", "sign"])
            .expect("leading --unlock parses");
        assert_eq!(cli.unlock, Some(UnlockMethod::Se));
```

`"sign"` is no longer a subcommand, so `try_parse_from` fails and the test panics on the
`expect`. Replace the token with a surviving subcommand that takes no positional argument —
`"list"` — which preserves exactly what the test is for (a *leading* global `--unlock` parses).

### Console (`crates/hc-console/`)

| Delete | Where |
|---|---|
| `MenuState::Sign` | `src/menu.rs:78` |
| `MenuChoice::Sign` | `src/menu.rs:93` |
| its `Display` arm | `src/menu.rs:109` |
| its `Pick::describe` arm ("Signs one JSON intent file from disk…") | `src/menu.rs:131-134` |
| the `next()` arm `(_, MenuChoice::Sign) => MenuState::Sign` | `src/menu.rs:197` |
| the `screen()` arm `MenuState::Sign => sign_screen(console, approver)` | `src/menu.rs:492` |
| `MenuChoice::Sign` in `root_screen`'s option list | `src/menu.rs:510` |
| `fn sign_screen` in full | `src/menu.rs:637-651` |
| `resolve_path` from the `hc_core` import | `src/menu.rs:16` (only use is `:639`) |
| `use hc_sign::intent::Intent;` | `src/menu.rs:19` (only use is `:640`) |

**Not dead:** `MenuErr::Sign` and `MenuErr::Serde` stay. `MenuErr::Sign` is used by
`bundles.rs:383`, and after §A.3 replaces that call with `sign_typed` it is still a `SignErr`
propagation, so the variant survives. `MenuErr::Serde` is used at `bundles.rs:384` **and** at
`bundles.rs:530` (`new_bundle`); §A.3 deletes the first, so `:530` is what keeps it alive — check
`:530`, not `:384`, when confirming.
`is_valid_string_name` stays (`menu.rs:547,597,990`). `hc_daemon::{OpContext, Operation, Peer}`
stay (`menu.rs:554-561,576-583`).
`inquire::Text` stays: `sign_screen` is one of five users (`menu.rs:545,595,638,668,878`), so the
import at `menu.rs:20` is untouched. Only `resolve_path` and `Intent` become unused.

**`next()`'s tests (`menu.rs:1041-1091`) need exactly one update.** The first test iterates a
table:

```
crates/hc-console/src/menu.rs:1043-1052
        for (choice, state) in [
            (MenuChoice::Keys, MenuState::Keys),
            (MenuChoice::Sign, MenuState::Sign),
            ...
```

Remove the `(MenuChoice::Sign, MenuState::Sign)` tuple. Every assertion in the body is generic
over the table (`next(Root, choice) == state`, `next(state, choice) == state`,
`next(state, Back) == Root`, `next(state, Quit) == Quit`), so nothing else changes. The second
test (`transitions_nest_the_peers_screen_under_the_bundle_list`, `menu.rs:1066-1091`) never
mentions `Sign` and is untouched. Signing remains reachable from the root through
`MenuChoice::Bundles`, whose description already names it (`menu.rs:135-138`).

### No shims

Per `CLAUDE.md`, nothing is re-exported, aliased, or left behind as a deprecated stub. `sign` is
gone from `--help` and from the enum.

## A.2 What Half A does **not** delete, and why

- **`bundle new [--file]`** (`hc-cli/src/bundle.rs:25-30,117-121`) and the console's
  "New bundle from an intent file" (`hc-console/src/bundles.rs:334,525-536`) survive. Decision 5
  deletes the human *sign* path, not the human *propose* path; `bundle new` reaches no key,
  prompts nothing, and is what `scripts/demo.sh` is rewritten onto. The console's version uses a
  file **picker** (`bundles.rs:592-614`), not a typed path, which is the property decision 5 was
  about.
- **`bundle merge --file` / `bundle add-sig --file`** — they carry signatures, not intents.
- **The `/sign/<KEY>` route and the adapter sockets** — decision 5 keeps them explicitly.

## A.3 Collapsing the JSON round trip

Today, for `bundle sign` and the console's bundle sign, a `SafeTxIntent` that is already in hand
is serialized so the daemon can parse it back:

```
crates/hc-cli/src/lib.rs:715
    let body = serde_json::to_vec(&hc_sign::intent::Intent::SafeTx(intent.clone()))?;
crates/hc-daemon/src/lib.rs:758
    let hc_sign::intent::Intent::SafeTx(intent) = serde_json::from_slice(body)?;
```

and the same at `hc-console/src/bundles.rs:377` → `hc-daemon/src/lib.rs:758`, with the JSON
response then parsed straight back (`hc-cli/src/lib.rs:723`, `hc-console/src/bundles.rs:384`).

### Does removing it weaken "the summary is rendered from the bytes actually submitted"?

**No, and here is the argument.** The property has two halves and the round trip supports
neither:

1. *The summary and the digest come from the same value.* That is guaranteed by `prepare` taking
   **one** `SafeTxIntent` and deriving both from it (`sign.rs:38-40`, and after B.1 both from the
   one `TypedTx` `admit` produced). It is a property of `prepare`'s signature, not of how the
   intent reached it.
2. *The digest is rebuilt, never accepted.* `Intent` has no hash field (`intent.rs:26-60`) and
   `safe_tx_hash` recomputes the EIP-712 encoding from the submitted fields
   (`mod.rs:317-338`, pinned against a hand-rolled encoding by
   `safe_tx_hash_matches_hand_rolled_eip712`, `mod.rs:502-551`). Nothing in that touches JSON.

On the **wire** paths the bytes are genuinely untrusted, and there the parse *is* the boundary —
which is why it stays exactly where it is: `check_body` (`hc-daemon/src/lib.rs:597-599`) refuses
an unparseable body before any approval, `#[serde(deny_unknown_fields)]` on `Intent` and
`SafeTxIntent` (`intent.rs:25,34`) makes an unknown field a refusal rather than a silent drop, so
the parsed struct cannot be a lossy view of the bytes, and `sign_intent` parses again at `:758`.

On the **local** paths there are no submitted bytes: the JSON is manufactured from a struct
milliseconds earlier by the same process. Round-tripping it proves nothing about anything, and it
costs two `serde_json` conversions and forces a typed response back through `Vec<u8>`.

### The change

Split `HotApi::sign_intent` at the parse:

```rust
impl HotApi {
    pub fn sign_intent(
        &self,
        ctx: &OpContext,
        body: &[u8],
        approver: &dyn Approver,
    ) -> Result<Vec<u8>, SignErr> {
        let hc_sign::intent::Intent::SafeTx(intent) = serde_json::from_slice(body)?;
        Ok(serde_json::to_vec(&self.sign_typed(ctx, intent, approver)?)?)
    }

    pub fn sign_typed(
        &self,
        ctx: &OpContext,
        intent: SafeTxIntent,
        approver: &dyn Approver,
    ) -> Result<SignResponse, SignErr>;
}
```

`sign_typed` holds everything `sign_intent` does today from `:755` down, **including both
guards**: `is_valid_string_name(&ctx.key)` (`:755-757`, pinned by
`sign_intent_rejects_invalid_name`, `hc-daemon/src/lib.rs:985-996`) and
`intent.key != ctx.key → IntentKeyMismatch` (`:759-761`). Neither may migrate to the wire wrapper:
the local callers must keep paying for them too.

Callers:

- `execute` (`hc-daemon/src/lib.rs:516`) keeps calling `sign_intent` — it holds a `Bytes` body.
- `hc-cli`'s `sign_intent_locally` (`src/lib.rs:710-724`) becomes
  `fn sign_intent_locally(intent: SafeTxIntent, unlock: Option<UnlockMethod>) -> Result<SignResponse, CliErr>`,
  calling `api.sign_typed(&cli_context(&intent.key, Operation::Sign), intent, &ServeApprover)`.
  The `serde_json::to_vec` at `:715` and the `from_slice` at `:723` both go.
- `hc-console`'s `bundles::sign` (`src/bundles.rs:371-398`) drops `:377` and `:384` and calls
  `console.api.sign_typed(&ctx, intent, approver)?`, which already returns the `SignResponse` it
  needs at `:385-386`.

`SignErr::Serde` stays: the wire wrapper still needs it.

### The duplication that does *not* fully collapse — stated honestly

- **`OpContext` construction for a LOCAL sign** was three places (`hc-cli/src/lib.rs:719` via
  `cli_context` at `:1025-1031`, `hc-console/src/menu.rs:641-645`,
  `hc-console/src/bundles.rs:378-382`). Grepped, the workspace holds six more `OpContext` literals
  — `hc-daemon/src/lib.rs:838` (the wire path), `hc-daemon/src/approval.rs:89`,
  `hc-console/src/approval.rs:452`, `hc-console/src/menu.rs:554,576` and the daemon test helper at
  `lib.rs:888` — none of which is a local sign and none of which this stage touches. The console's Sign
  screen takes one with it, leaving two — in **different crates**, each a struct literal with a
  fixed `Peer::Cli`. A shared `OpContext::local(key, op)` constructor in `hc-daemon` would be a
  no-logic function, which `CLAUDE.md` bans. Recommendation: leave the two literals.
- **Obtaining JSON bytes** was three ways (`hc-cli/src/lib.rs:696 read_input`,
  `hc-console/src/bundles.rs:565-614 json_files`/`pick_json`, `hc-console/src/menu.rs:639` raw
  `fs::read`). The raw read dies with the Sign screen, leaving two — again in different crates,
  with genuinely different affordances (stdin/`--file` versus a picker that never types a path).
  No further collapse is honest.

## A.4 `scripts/demo.sh`

Current steps 7–8 (`scripts/demo.sh:42-72`) write a policy and drive
`"$BIN" sign --file "$HOT_CHEESE_HOME/demo_intent.json"` with a hand-written 9-key intent
including 138 hex characters of calldata. The intent survives (as a bundle seed); the verb does
not.

Facts the rewrite must satisfy, all read from the source:

- `hc_bundle::new` requires `bundles/safes.toml` to describe the Safe: `Safes::load()` errors
  `NoSafesFile` when the file is absent (`hc-bundle/src/lib.rs:104-110`) and `find` errors
  `UnknownSafe` for an unlisted `(safe, chain_id)` (`:115-122`). The threshold comes from that
  entry (`:374`).
- `hc_bundle::export` calls `owners_ok` against the same entry and refuses below threshold
  (`hc-bundle/src/lib.rs:515-525`), so `safes.toml` must list the demo key's **real** address as
  an owner and set `threshold = 1`.
- The bundle directory is named for `SafeTxBundle::digest()` = `safe_tx_hash(intent)`
  (`hc-sign/src/bundle.rs:81-83`), logged as `tracing::info!(%hash, …, "created bundle")`
  (`hc-bundle/src/lib.rs:389`). Capture it rather than hardcoding it.
- `--no-sync` maps to `SyncMode::Off` (`hc-cli/src/bundle.rs:112-115`) so no `rsync` and no
  `tailscale` is invoked. With `bundle_peers = []` sync is already a no-op
  (`hc-bundle/src/sync.rs:255-258,277-297`), but the flag makes it explicit.
- The demo calldata is canonical ERC-20 `transfer(0x3333…, 10)`, so it stays admissible under
  `06-typed-admission.md` — but the policy heredoc below still writes `selectors = [...]`, and
  `06` §16 step 7 rewrites it into the declared-signature form. The bash is this stage's; the
  policy body is `06`'s to update.
- `--no-sync` is `#[arg(long, global = true)]` on `Commands::Bundle`
  (`hc-cli/src/lib.rs:179-185`), so it parses **anywhere** on the line, which is what
  `README.md:410` already promises. Both `bundle new --no-sync --file …` and
  `bundle status "$HASH" --no-sync` below are valid.
- The hash capture works because `run` installs a `tracing_subscriber` for every subcommand
  (`hc-cli/src/lib.rs:339-341`), so `new`'s `tracing::info!(%hash, dir = …, threshold, "created
  bundle")` (`hc-bundle/src/lib.rs:389`) reaches stderr, `2>&1` collects it, and `hash` is emitted
  before `dir` so `head -1` takes the digest and not the path.

Replacement for steps 7–8, no comments (`CLAUDE.md`):

```bash
echo
echo "==> 5) read its address  (the Touch ID prompt IS the per-request unlock)"
DEMO_ADDR="$("$BIN" address evm DEMO_KEY 2>&1 | tee /dev/stderr | grep -o '0x[0-9a-fA-F]\{40\}' | head -1)"
[[ -n "$DEMO_ADDR" ]] || { echo "could not read DEMO_KEY's address" >&2; exit 1; }
```

```bash
echo
echo "==> 7) write a fail-closed signing policy for DEMO_KEY"
mkdir -p "$HOT_CHEESE_HOME/store/policies"
cat > "$HOT_CHEESE_HOME/store/policies/DEMO_KEY.toml" <<'POLICY'
safe = "0x1111111111111111111111111111111111111111"
chain_id = 1

[[allow]]
to = "0x2222222222222222222222222222222222222222"
selectors = ["0xa9059cbb"]
max_value = "0"
operation = "call"
POLICY

echo
echo "==> 8) describe the Safe this machine collects signatures for"
mkdir -p "$HOT_CHEESE_HOME/bundles"
cat > "$HOT_CHEESE_HOME/bundles/safes.toml" <<SAFES
[[safe]]
address = "0x1111111111111111111111111111111111111111"
chain_id = 1
threshold = 1
owners = ["$DEMO_ADDR"]
SAFES

echo
echo "==> 9) file the transaction as a bundle  (prompts nothing, unlocks nothing)"
cat > "$HOT_CHEESE_HOME/demo_intent.json" <<'INTENT'
{
  "kind": "safe_tx",
  "key": "DEMO_KEY",
  "safe": "0x1111111111111111111111111111111111111111",
  "chain_id": "1",
  "to": "0x2222222222222222222222222222222222222222",
  "value": "0",
  "data": "0xa9059cbb0000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000a",
  "operation": "call",
  "nonce": "0"
}
INTENT
HASH="$("$BIN" bundle new --no-sync --file "$HOT_CHEESE_HOME/demo_intent.json" 2>&1 | tee /dev/stderr | grep -o '0x[0-9a-f]\{64\}' | head -1)"
[[ -n "$HASH" ]] || { echo "bundle new did not report a safeTxHash" >&2; exit 1; }

echo
echo "==> 10) read the decoded summary the approval prompt will show"
"$BIN" bundle status "$HASH" --no-sync

echo
echo "==> 11) sign the bundle with DEMO_KEY"
echo "    ONE Touch ID prompt: that approval mints the per-payload grant AND unlocks the key."
echo "    Only {r,s,v} is filed — never the private key."
"$BIN" bundle sign "$HASH" --key DEMO_KEY --no-sync

echo
echo "==> 12) the assembled execTransaction call, threshold met"
"$BIN" bundle export "$HASH" --no-sync
```

Renumber the trailing banner accordingly. The demo now walks the flow decision 5 blesses:
propose → review → sign → export.

## A.5 `scripts/dryrun.sh` — **not in the brief, but it breaks**

Phase 5 (`scripts/dryrun.sh:842-1011`) drives `sign --file` in **seven** places — one success and
six refusals, which is what the phase's own tap accounting at `:1010-1011` means by "all six
refusals" — and asserts the exact typed refusal each produces:

| Line | Assertion |
|---|---|
| `:935` | `p5a_no_policy` expects `Policy(Io(` — no policy file |
| `:951` | `p5b_no_chain_id` expects `Policy(Toml(` — policy without `chain_id` |
| `:971` | `p5c_sign_ok` — the happy path, exactly one Touch ID (`:982-983`) |
| `:988` | `p5d_drain` expects `RefundNotAllowed` |
| `:993` | `p5e_bad_to` expects `ToNotAllowed` |
| `:998` | `p5f_bad_chain` expects `ChainMismatch` |
| `:1005` | `p5g_no_pin` expects `NoPinnedGrantKey` |

and `:1010-1011` asserts the whole phase cost one biometric — the same "a refusal costs no
biometric" invariant `06-typed-admission.md` must preserve.

Retarget every one onto `bundle sign`, which reaches the identical `prepare`. That needs, once,
before the phase: a `bundles/safes.toml` naming `$SAFE_ADDR` on chain 1 with `$ADDR_SE` as owner
and `threshold = 1`, and a `bundle new --no-sync --file` per fixture intent capturing each hash.
The four fixture *paths* are declared at `:848-851` and the JSON is written at `:853-928`;
unchanged. Three notes:

- The refusal strings the assertions grep for (`Policy(Io(`, `Policy(Toml(`, `RefundNotAllowed`,
  `ToNotAllowed`, `ChainMismatch`, `NoPinnedGrantKey`) all still appear, because `err_mac`'s
  `Display` is `{:?}` of the whole enum (verified at rev `08f6335`) and the new outer wrapper is
  `CliErr::Sign(SignErr::…)`, which nests rather than replaces. No assertion text changes.
- `bundle new` must run **before** 5a removes/omits the policy file, since 5a asserts the policy
  is absent (`:932-934`). `bundle new` does not read a policy, so ordering it first is free —
  but the `if [[ -e "$POLICY_FILE" ]]` guard at `:932-934` must stay ahead of the sign call and
  behind the `bundle new` calls.

- `bundle new` for `$INTENT_BAD_CHAIN` (chain 137, `:915`) will fail `Safes::find` unless
  `safes.toml` also lists the Safe on chain 137. Add a second `[[safe]]` entry, or move 5f's
  assertion to a bundle created on chain 1 whose *policy* pins another chain. The former is less
  surgery.
- `bundle new` is a *write*, so the rival guard is not involved but the `(safe, chain, nonce)`
  slot is: all four fixtures use `"nonce": "0"`. `hc_bundle::new` refuses a duplicate **directory**
  (`BundleExists`, `hc-bundle/src/lib.rs:384-386`) but different intents on one nonce are
  different digests and are merely reported as rivals, so four bundles on nonce 0 is fine and
  `bundle list` will flag them. Either accept the RIVAL warnings or give each fixture its own
  nonce. Recommendation: give each its own nonce; it is one character per file and keeps the
  transcript clean.

Phase 5's headline must also change from "scoped signing" to "scoped signing through a bundle".

## A.6 README and MIGRATION.md

Grepped for every prose reference to the subcommand, not just the ones in the brief.

**`README.md`:**

- `:395` — delete the `sign [--file <json>]` row from the command table.
- `:388` — `enroll grant`'s row says "Required before `serve` or `sign`." Drop `or sign`, or
  replace it with `bundle sign`, which is now the only signing verb.
- `:397` — `bundle sign`'s row says "same policy, same grant, same single Touch ID as `sign`."
  The comparand no longer exists; state the property directly.
- `:758-759` — "`bundle sign` reaches the key through the same call `hot_cheese sign` does" no
  longer names an existing command; rewrite to name `prepare`/`sign_intent`.
- `:886-887` — the pull/push table's `sign` entries are the **bundle** verb. Leave them.
- `:1103-1105` — "The library stays general … you can still sign a delegatecall by hand. Only the
  *MCP surface* is narrow." Typed-only makes this **false**, so it is rewritten by
  `06-typed-admission.md` §16 step 7, not here.
- `:1144` — "**Sign anything.** No `sign`, no `collect`, no `merge`." This is the MCP
  *can't-do* list; `sign` naming a gone subcommand still reads oddly. Reword.
- The `/sign` sections (`:507,529-`) stay; they gain the typed-only rule in `06`.

**`MIGRATION.md` — missed by the original brief and by this file's first pass. It names the
subcommand five times and all five go stale:**

- `:30` — "before `sign` will work" → `bundle sign`.
- `:295` — the §6 heading, "every key you will `sign` with".
- `:297` — "`sign` is fail-closed: it loads `<store>/policies/<NAME>.toml`…". The sentence is
  still true of the *flow*; it must name `bundle sign` or `prepare`.
- `:586` — "`bundle sign` is subject to it exactly as `sign` is" — the comparand is gone.
- `:675` — the list of verbs that unlock the DEK, "(`address`, `add`, `generate`, `sign`, `seal`,
  `enroll`, `migrate`)". `sign` leaves the list; `bundle sign` joins it.
- `:614` — "`list`, `watch` and `sign` pull first" is the bundle verb. Leave it.

---

# Ordered steps

Each step builds in release and passes tests on its own. This stage runs before
`06-typed-admission.md`, so that `06`'s `prepare` signature change touches the smallest possible
caller set.

**Verification after every step**, without exception:

```
cargo build --release
cargo test --release --workspace
cargo clippy --release --all-targets -- -D warnings
```

`CLAUDE.md`: release only; `#[allow(clippy::…)]` is banned, so a clippy finding is fixed, not
silenced.

### Step 1 — delete the CLI `sign` subcommand
Apply §A.1 (CLI) including the `lib.rs:1347` test fix. `cargo test -p hc-cli --release` and
`hot_cheese --help` no longer lists `sign`.

### Step 2 — delete the console Sign screen
Apply §A.1 (console) including the `menu.rs:1043-1052` table entry. `cargo test -p hc-console
--release`. Manually: the root menu shows eight entries and `Bundles → Sign` still works.

### Step 3 — collapse the JSON round trip
Apply §A.3: add `HotApi::sign_typed`, make `sign_intent` the wire wrapper, retarget
`hc-cli::sign_intent_locally` and `hc-console::bundles::sign`. `sign_intent_rejects_invalid_name`
(`hc-daemon/src/lib.rs:985-996`) must still pass unchanged — it calls `sign_intent` with a body.

### Step 4 — scripts
`scripts/demo.sh` per §A.4; `scripts/dryrun.sh` phase 5 per §A.5. Run
`bash -n scripts/demo.sh` and `bash -n scripts/dryrun.sh`; the demo itself needs macOS and is run
by the operator, not by this stage.

### Step 5 — README and `MIGRATION.md` per §A.6.

The steps that used to follow — the typed tree, the structural manifest, entry-level authority,
and the optional `hc_sign::adapter` -> `hc_sign::decode` rename — are superseded by
`06-typed-admission.md` §16, which reorders them around the policy-declared signature.

---

# Tests

Half B's tests move to `06-typed-admission.md` §16. Half A changes exactly two existing tests,
both described in §A.1:

1. **`next()`'s table loses one row** (`hc-console/src/menu.rs:1043-1052`) — the
   `(MenuChoice::Sign, MenuState::Sign)` tuple goes; every assertion in the body is generic over
   the table, so nothing else changes.
2. **The leading-`--unlock` parse test** (`hc-cli/src/lib.rs:1347-1349`) — `"sign"` is no longer a
   subcommand, so the token becomes `"list"`, which preserves exactly what the test is for.

---

# Risks and open questions

Half B's risks and open questions move to `06-typed-admission.md` §17.

## Risks (Half A)

- **`scripts/dryrun.sh` is a 1368-line human-driven transcript with biometric-tap accounting**
  (`:982-983`, `:1010-1011`). Retargeting phase 5 onto bundles adds `bundle new` calls, which
  prompt nothing and unlock nothing, so the tap counts do not move. Verify that claim by reading
  `hc-bundle/src/lib.rs:373-392` before editing — `new` touches no key and takes no `Unlocker`.
- **`scripts/demo.sh` drives `sign --file` directly** (`:42-72`) and breaks the moment the
  subcommand goes. §A.4 rewrites it onto the bundle flow; it must not be left broken.
