# hot_cheese — Production Cutover Runbook (OLD → NEW, Secure-Enclave mode)

The authoritative, ordered, copy-pasteable sequence to move a **production** install
from the legacy daemon (Web3 keystores under a single Keychain master) to **v1**
(per-file envelope under a DEK, unlocked per request by the Secure Enclave or a
recovery passphrase), in **Secure-Enclave mode**.

`migrate` is **non-destructive**: each legacy key is decrypted with the old master,
re-encrypted under the new DEK into `<new-store>.staging`, and verified (decrypt
round-trip **and** re-derived address) before anything commits. The old store is never
written; any failure removes the staging dir and aborts. Plan a **dual-run** and
decommission the legacy store only after v1 has served real traffic and pushed a good
backup.

## Cutover blockers — read first

- **§1 — `serve` (and every SE op) must run in your active GUI login session.** Touch ID
  cannot fire under pure `ssh` / `sudo` / a background launchd daemon. No code signing,
  Team ID, entitlements, or Apple Developer Program is required.
- **§2 — the TLS cert re-pins every client** unless you import the old one (needs the
  old private key on disk).
- **§3 — the Keychain identity must match the OLD install** before `migrate`, or it
  reads the wrong/no master.
- **§4b — `hot_cheese enroll grant` is required before `serve`.** An install cutting over
  from an earlier build has no grant key; `serve` now refuses to start without one and
  every signature verifies its grant against the `config.toml` pin. It prompts for nothing.
- **§5 — every key your services fetch over `/read` MUST be migrated `--shareable`.**
  Anything you do not name becomes `sign_only`, and `/read` then refuses it permanently.
  See the one-way-door warning in §5.
- **§6 — every signing key needs a policy file with `chain_id`** before `bundle sign` will work.
  A policy `[[allow]]` rule carrying a term this build does not implement now fails to load
  (= every signature denied) instead of dropping the term silently.
- **§6 — `selectors = [...]` is GONE and every policy file carrying it fails to load.** A rule
  now declares the full canonical signature and the daemon derives the selector from it, and
  every declared argument must carry its own bound. Nothing is auto-converted; §6c has the
  conversion table and the reasons. Convert every policy file **before** you restart `serve`.
- **§6b — adapters are optional and additive.** Nothing changes for the loopback client or
  the CLI if you configure none. If you do configure one, `serve` refuses to start when its
  manifest does not match its pin, or claims more than §6's policy grants.

## ⚠️ `sign_only` is a ONE-WAY DOOR — decide before §5

Every key now declares, at creation, whether it may ever leave the daemon:

| Use | `/read` | `/sign`, `address` | Reversible? |
| --- | --- | --- | --- |
| `shareable` | released to the client | yes | yes — `seal --use sign-only` tightens it |
| `sign_only` | **refused, always** | yes | **NO. Never. Not by any command.** |

The flag lives in the keystore file's cleartext header **and inside the AEAD additional
data**, so it is not advice the daemon can be talked out of: editing `"key_use"` on disk
does not unlock an export, it destroys the file (the AAD no longer matches and nothing —
not even the recovery passphrase — can decrypt it again).

**Loosening is therefore impossible by construction**: turning `sign_only` back into
`shareable` would mean decrypting the key and re-sealing it under the looser AAD, which is
exactly the export that `sign_only` forbids. `hot_cheese seal` refuses it with
`SealCannotLoosen`. The only route back is a fresh key: `generate --use shareable` (or
`add --use shareable`) and rotate every consumer to it.

**So: before you run `migrate`, list every key that some service fetches with `/read`, and
pass each one as `--shareable`.** If you get it wrong, those services break at cutover and
the fix is a key rotation, not a flag flip.

## Where everything lives: `HOT_CHEESE_HOME`

Every path below is under the **home dir**: `$HOT_CHEESE_HOME` if that variable is set,
otherwise `~/.config/hot_cheese`. It holds `config.toml`, `ssl-cert.pem`, `ssl-key.pem`,
the Secure Enclave key blob, `adapters/` (manifests and their sockets, §6b), `bundles/`
(multisig signature collection, §9), `bundle-quarantine/` (what a peer pushed that failed
verification, §9), and (by default) `store/`. Setting `HOT_CHEESE_HOME`
fully isolates an install — which is how you rehearse this runbook without touching
production:

```
export HOT_CHEESE_HOME=/tmp/hot_cheese_dryrun
```

Export it in **every** shell that runs a `hot_cheese` command for that install, including
the one running `serve`. Where this document writes `~/.config/hot_cheese/…`, read
`$HOT_CHEESE_HOME/…` if you set it.

---

## 1. Build and validate the Secure Enclave

The Secure Enclave KEK uses Apple CryptoKit (`SecureEnclave.P256`), which needs **no**
code signing, Team ID, entitlements, provisioning profile, `.app` wrapper, Developer ID,
or notarization — a plain release build carries the automatic ad-hoc signature that the
enclave accepts. Those are only needed later to **distribute** the binary to other Macs.

```
cargo build --release
./target/release/hot_cheese se-selftest
```

Run this in your **GUI login session** (a Terminal window on the Mac itself), not over
`ssh`. Expect **three** Touch ID prompts. `se-selftest` asserts Touch ID gating,
deterministic ECDH, SE/host ECDH equivalence, and — on the third prompt — that **one**
biometric covers **both** an enclave ECDH **and** an enclave grant signature that verifies
against the exported grant public key. **If it fails, stop and fix before touching real
keys.** If `se-selftest` reports the enclave is unavailable, the machine has no Secure
Enclave — use the recovery passphrase path only.

## 2. Preserve your TLS cert (avoid re-pinning live clients)

`init` mints the home dir + store, the DEK, and the TLS cert, and **requires a recovery
passphrase** (entered twice). To keep the existing cert so pinned clients keep working,
import the OLD cert **and** its private key (both are required):

```
hot_cheese init \
  --import-cert /path/to/old/src/conf/ssl-cert.pem \
  --import-key  /path/to/old/src/conf/ssl-key.pem
```

If you do **not** have the old private key, or you control every client, skip the
import and re-pin:

```
hot_cheese init
```

`init` prints the certificate **SHA-256 fingerprint** — distribute it to every client
out-of-band before cutover. **Record the recovery passphrase offline**: it is the only
cross-machine restore path for the DEK. Both `ssl-key.pem` and the SE key blob are written
**0600**; keep it that way.

`init` refuses to run when it finds a prior install — `config.toml`, a `store/keyring.json`,
or any keystore file — and names what it found:

```
ExistingStore { store: "…/store", keyring: true, keystores: 3 }
```

That guard exists because a second `init` mints a **new DEK**, which permanently orphans
every keystore encrypted under the old one. `--force` overrides it; pass it only when you
intend exactly that.

A second `init` also mints a **new vault id** (§8), so its backups land *beside* the old
ones at `<folder>/<new_id>/` rather than overwriting a vault whose keys may still be
needed. That is deliberate: nothing on the remote is destroyed by re-initializing.

## 3. Match the legacy Keychain identity BEFORE migrating

`migrate` reads the old master from the login Keychain using `service`/`account` from
`~/.config/hot_cheese/config.toml`. `init` wrote the defaults
`com.cc.hot_cheese` / `hot_cheese_master`. If the OLD install used different values
(from its `cheese_config.json`), edit them to match **now** — otherwise `migrate` reads
the wrong or no master:

```
service = "com.cc.hot_cheese"
account = "hot_cheese_master"
```

## 4. Enroll this machine's Secure Enclave

```
hot_cheese enroll se
```

**Expect exactly one prompt: the recovery passphrase. There is NO Touch ID here.** The
enclave key is *created* without a biometric, and the enrollment wraps the DEK with a
host-side ECDH against the enclave's **public** key — neither step needs the private key,
so neither prompts. (If you are waiting for a Touch ID sheet, the command already finished.)

Adds an SE unlock for the **same** DEK; the recovery passphrase remains the survivable
backstop. The first Touch ID sheet comes later, on the first command that actually unlocks
through the enclave (§5, §7).

## 4b. Enroll this machine's Secure Enclave grant key (REQUIRED)

```
hot_cheese enroll grant
```

**Expect NO prompt at all — no Touch ID, and no recovery passphrase.** This creates a
*second*, independent enclave key: a `SecureEnclave.P256.Signing` key whose only job is to
produce a biometric-gated ECDSA signature over an approval digest. It wraps no DEK and
decrypts nothing, so creating it and exporting its public half touch no private key
material and there is nothing to unlock.

The command prints the key's uncompressed SEC1 public key and writes it to `config.toml`:

```
grant_public_key = "04…"
```

**Run it before your next `serve`.** Signing is now gated on this key: for each signature
the daemon rebuilds `safeTxHash`, digests the policy bytes it just read, and — under the
*same* biometric that approved the request — has the enclave sign those terms. The result is
verified against the pin above before the signing key is reachable at all. So `serve`
refuses to start when nothing is pinned or the blob is gone
(`GrantKeyMissingRunEnrollGrant`), and when the blob on disk exports a *different* public
key (`GrantKeyPinMismatch { pinned, found }`).

**This still costs exactly one Touch ID.** The enclave grant signature reuses the approval's
`LAContext`, which is the property `se-selftest` proves on real hardware in §1. The one
exception is a session unlocked by the **recovery passphrase**: it has no biometric to reuse,
so the grant takes its own — one extra sheet, only there, so that an operator whose enclave
KEK died can still sign.

Nothing about a grant is written down: no terms, no signature, no audit trail. It is proof
inside the call that made it and nothing after.

**Be clear about what the pin buys you.** It is a startup identity check, not a security
boundary: it catches an accidentally swapped `se_grant_*.blob`, or a restore that carried
`config.toml` across but not the enclave key. It does **not** stop an attacker who can
already write your home dir — such an attacker can rewrite the pin as easily as the blob.

**Losing the grant key is benign.** Nothing is wrapped under it, so there is no data loss
and it needs no passphrase backstop — unlike the SE KEK, whose loss makes the DEK
unreachable except through the recovery passphrase. If a Touch ID re-enrollment invalidates
it, the machine dies, or the blob is deleted, recovery is:

```
rm -f $HOT_CHEESE_HOME/se_grant_hotcheese_se_grant_v1.blob   # only if a dead blob is still there
hot_cheese enroll grant                                      # creates a new key and re-pins it
```

Any grant signature made under the old key stops verifying, which is the intended effect of
rotating it.

## 5. Migrate the keys (non-destructive)

```
hot_cheese migrate \
  --old-store /path/to/legacy/store \
  --new-store ~/.config/hot_cheese/store \
  --shareable TRADING_BOT \
  --shareable SOLANA_TRADER
```

`--shareable <NAME>` is **repeatable** and names a key that keeps working over `/read`.
**Every key you do not name is migrated `sign_only` and can never be exported again** — see
the one-way-door warning above. A `--shareable` name that is not in `--old-store` aborts the
run before anything is written (`UnknownShareable { name }`), so a typo can never silently
seal a key your services still read. If nothing reads keys over `/read`, pass no
`--shareable` at all and the whole store lands sign-only, which is the safe default.

`--new-store` must be empty. Expect **three** prompts, in this order:

1. **Touch ID** — authorizes reading the legacy Keychain master.
2. **A login-Keychain access dialog** — *“hot_cheese wants to use your confidential
   information stored in "hot_cheese_master" in your keychain”*, with **Deny / Allow /
   Always Allow** and your **login password**. This is expected and is not a failure: the
   legacy master item's ACL lists the OLD binary, and the new `hot_cheese` binary is a
   different code identity, so macOS asks you to extend the ACL. **Allow** is enough for a
   one-shot migration; **Always Allow** avoids re-prompting if you re-run it.
3. **Touch ID** — unlocks the new DEK via the enrolled Secure Enclave. The sheet names the
   operation (`Unlock the hot_cheese DEK for migrate`).

Each key is decrypted, re-sealed under the DEK into `store.staging` (already v2, with its
use bound into the AAD), and verified before the atomic move. Identity is derived by secret
length: **32 bytes → EVM address**, **64 bytes → Solana pubkey**, otherwise **`sha256:<hex>`**.
On success it logs one line per key:
`migrated  name=<NAME>  identity=<address-or-hash>  key_use=<shareable|sign_only>`.

**Eyeball the printed manifest against your known addresses AND against your list of
`/read` consumers.** If an address differs, or a key your services read came out
`sign_only`, **stop** — the old store is untouched, so delete `--new-store` and re-run with
the right `--shareable` set. Optional independent spot-check (`list` prompts nothing; each
`address` prompts Touch ID, and the sheet names the key):

```
hot_cheese list                       # prints each keystore with its use, no unlock
hot_cheese address evm    <NAME>
hot_cheese address solana <NAME>
```

## 5b. Seal a store you migrated with an older build

Skip this if §5 was your first migration — those keys are already sealed. A store written
before per-key uses existed lists as `unsealed`, and an unsealed key **cannot be exported at
all** (`/read` returns `NotSealed`): it never declared a use, so there is nothing to
authorize the export. Bind each one:

```
hot_cheese list                                  # find every "unsealed" keystore
hot_cheese seal <NAME> --use shareable           # keys your services fetch over /read
hot_cheese seal --all                            # everything else -> sign_only
```

`seal` reads the cleartext headers first, so it unlocks the DEK **once** for the whole batch
(one Touch ID) and does nothing at all when there is nothing to do. Each file is re-sealed
in memory, re-opened from its new bytes and compared against the original plaintext, and
only then written atomically — a failed verification leaves the old file untouched.

`seal` only ever **tightens**, and `--all` is deliberately conservative:

- `--all` binds **only** the keystores that are still `unsealed`. It never re-decides a key
  whose use someone already chose, so the two commands above are safe in either order and
  re-running them changes nothing.
- A **named** key may be tightened: `shareable → sign_only` is allowed, a key already at the
  requested use is skipped, and `sign_only → shareable` is refused with
  `SealCannotLoosen { name, from, to }` — it is the one-way door, not a permission check.

## 6. Write a signing policy for every key you will `bundle sign` with

Signing is fail-closed: every signature — `bundle sign` at your terminal, `/sign/<NAME>` over
loopback, an adapter socket — loads `<store>/policies/<NAME>.toml` and **denies the signature**
if that file is missing or does not parse. `chain_id` is **required** — a policy without it
fails to load, which reads as "every signature denied", not as a warning.

```
mkdir -p ~/.config/hot_cheese/store/policies
cat > ~/.config/hot_cheese/store/policies/<NAME>.toml <<'POLICY'
safe = "0xYourSafeAddress"
chain_id = 1

[[allow]]
to = "0xContractYouCall"
max_value = "0"
operation = "call"

  [[allow.call]]
  signature = "transfer(address,uint256)"

    [[allow.call.arg]]
    at = 0
    name = "to"
    rule = { one_of = { addresses = ["0xWhoMayBePaid"] } }

    [[allow.call.arg]]
    at = 1
    name = "amount"
    rule = { max = { max = "1000000000", amount_of = "0xContractYouCall" } }
POLICY
```

- `safe` and `chain_id` pin the Safe and the chain; an intent for any other Safe or chain
  is denied (this is the cross-chain replay guard).
- Each `[[allow]]` rule permits one destination, up to `max_value`, and only with the listed
  `operation` (`call` unless you write `delegatecall`). A destination with no rule is denied.
- Each `[[allow.call]]` permits **one call shape at that destination**, named by its full
  canonical signature. The daemon derives the 4-byte selector from that text and decodes the
  calldata against exactly that shape, so a call the policy permits is decodable by
  construction — and a payload that does not decode, or that decodes but does not re-encode to
  the submitted bytes, is refused instead of being rendered as hex.
  `signature` must be the canonical spelling: no argument names, no `function` keyword, no
  `uint` alias for `uint256`, no `returns` clause. Anything else is refused at load with the
  text to write instead.
- Each `[[allow.call.arg]]` bounds **one argument**, by position (`at`), under the label the
  human will read (`name`). **Every declared position must carry a rule**: an argument you
  forget is a load failure, not an unbounded permit. The only way to say "no bound" is to type
  `rule = "unbounded"`, and then every approval leads with `⚠ UNBOUNDED FIELD [name]`.
  The rules are `one_of`, `max`, `eq`, `bool_eq`, `bytes_eq`, `deadline`, `enum`, `each`,
  `"struct"`, `"batch"` and `"unbounded"`; README's
  "Typed-only admission" section has the table of which applies to which Solidity type.
- **`multiSend` is no longer a hole.** Its `bytes` argument takes `rule = "batch"`, and every
  entry inside is then matched against the policy in its own right — its own destination, its
  own operation, its own native value, its own signature and its own argument bounds. A batch
  touching a destination your policy does not cover now refuses the whole transaction, so
  after conversion **add a rule for every destination your batches touch**.
- Gas-refund fields are **opt-in**: with no `[refunds]` table, an intent carrying any
  non-zero `gasPrice` / `gasToken` / `refundReceiver` is denied outright. Add the table only
  if you genuinely use refunds, and cap it:

```
[refunds]
gas_tokens = ["0x0000000000000000000000000000000000000000"]
refund_receivers = ["0xYourRelayer"]
max_gas_price = "1000000000"
max_base_gas = "100000"
max_safe_tx_gas = "0"
```

- Owner/threshold rotations (a call from the Safe to itself) are denied unless
  `[owner_management]` sets `allow = true` and lists the calls in the same
  `[[owner_management.call]]` form. It also carries `max_value`, which **defaults to zero**:
  a rotation has no need to move native value, and before this build no ceiling reached these
  calls at all. Set it explicitly if you genuinely need otherwise.
- A `[[typed_data]]` block makes an **EIP-712 message** signable with this key. The policy
  declares the domain and the complete struct schema; a request names the schema and supplies
  field values only. This is new authority in a file you already have — adding a block grants
  off-chain signing power that did not previously exist on this machine. README's
  "EIP-712 typed data" section has the shape.

Policies live inside the store, so they travel with the git backup.

The file is re-read for **every** signature, and its SHA-256 goes into the grant the approval
mints — so the human approves an intent *under a named policy*, and a policy edited between
the approval and the signature is a different policy than the one that was approved. An
intent carrying a field this daemon does not know is refused outright, before any prompt,
rather than having the field quietly dropped.

## 6b. (Optional) Trust an out-of-process signing adapter

Skip this whole section unless a separate process is going to submit intents. Adapters are
purely additive: with no `[[adapters]]` in `config.toml`, nothing below exists and the
loopback/CLI paths behave exactly as they did before.

An adapter is another process that turns a domain action into a typed intent. It never sees
key material and never supplies a digest — hot_cheese still rebuilds `safeTxHash` itself. It
gets its own `0600` unix socket, a SHA-256-pinned manifest, and a route table of `/health`
plus `/sign/<NAME>` only.

Adapter files live in the **home dir, never the store**:

```
mkdir -p ~/.config/hot_cheese/adapters
cat > ~/.config/hot_cheese/adapters/safe_treasury_bot.toml <<'MANIFEST'
schema = "hotcheese.adapter/v1"
id = "safe_treasury_bot"

[[grants]]
key = "TREASURY"
intent_kinds = ["safe_tx"]
chain_ids = ["1"]
safes = ["0xYourSafeAddress"]

[[grants.calls]]
to = "0xContractYouCall"
max_value = "0"
operation = "call"

  [[grants.calls.call]]
  signature = "transfer(address,uint256)"

    [[grants.calls.call.arg]]
    at = 0
    name = "to"
    rule = { one_of = { addresses = ["0xWhoMayBePaid"] } }

    [[grants.calls.call.arg]]
    at = 1
    name = "amount"
    rule = { max = { max = "1000000", amount_of = "0xContractYouCall" } }
MANIFEST
shasum -a 256 ~/.config/hot_cheese/adapters/safe_treasury_bot.toml
```

Then pin it in `config.toml`:

```
[[adapters]]
id = "safe_treasury_bot"
manifest = "adapters/safe_treasury_bot.toml"
sha256 = "<the shasum output>"
```

`[[grants.calls]]` uses the **same rule type** as `[[allow]]` in §6 — there is no second
policy language. Every struct denies unknown fields, so a typo or a term from a future schema
is a refusal to load rather than a silently ignored line. Note that this now applies to your
`[[allow]]` rules too: if a policy file carries a term hot_cheese does not implement, it stops
loading, which reads as "every signature denied".

**The manifest can only NARROW §6's policy.** At `serve` startup every grant is intersected
with `<store>/policies/<NAME>.toml`: `safes` and `chain_ids` must be the policy's; every
`calls` rule must be matched by a policy `allow` rule with the same `to` and `operation` and a
`max_value` at least as large; every declared `signature` must appear **verbatim** in that
policy rule; every argument bound must be no wider than the policy's at that position (an
adapter may not unbind an argument the policy bound); and every name in `grants.typed_data`
must be a schema the policy declares. If anything is broader, `serve` **refuses to start** with
an error naming the adapter, the key and the offending rule (`Widens { adapter, key, source }`).
That is deliberate: a manifest broader than policy means you believe something the policy does
not grant, and you should find that out now.

The signature comparison is on the canonical **text**, not on the four bytes: two different
signatures can be ground to share a selector, and a manifest is the lower-trust file.

Two things a manifest may never do: grant **owner/threshold rotation** (a `calls` rule naming
the Safe itself is refused at startup, and such an intent is denied at request time even when
§6 allows rotation for a human), and **widen refunds** (there is no refund term in the schema,
so writing one fails to load).

Check the whole picture before starting the daemon — this prompts nothing and unlocks nothing:

```
hot_cheese adapters
```

It prints each adapter's manifest path, pinned hash, computed hash, socket path and the
intersection verdict. Fix every `REFUSED` line before you run `serve`.

Operational notes:

- The socket is `~/.config/hot_cheese/adapters/<id>.sock`, mode `0600` inside a `0700`
  directory. Its **peer credentials are logged, not trusted**: they prove a uid, not an
  identity.
- Provenance comes from *which socket* accepted the connection, so the Touch ID sheet and the
  approval line name the adapter, and the manifest digest goes into the grant.
- If a socket path already exists at startup, `serve` connects to it: an answer means another
  daemon is live and this one refuses to start; only `ECONNREFUSED` licenses an unlink.
- hot_cheese does not spawn or supervise adapters. Run them as launchd jobs; see the
  `sandbox-exec` note in [README.md](./README.md#signing-adapters), including why confinement
  buys the adapter more than it buys hot_cheese.

## 6c. Convert a policy file written before typed-only admission

**Every policy or manifest still carrying `selectors = [...]` refuses to load.** `AllowRule` is
`deny_unknown_fields` and has no such field, so `toml::from_str` fails with an unknown-key error
naming `selectors` and its line and column, wrapped as `PolicyErr::Toml`. Nothing is
auto-converted, and that is on purpose: a 4-byte selector is a keccak image with no preimage, so
a conversion could only work from a fixed table and would silently fail to convert every
selector outside it — producing a policy narrower than the file says. Silent narrowing under
cover of a migration is worse than a refusal.

This reaches startup. `serve` loads every policy named by an adapter grant before it binds
anything, so on a machine with a pinned adapter the daemon **will not start** until every such
policy is converted. Convert first, restart second.

**Conversion table.** These are the nineteen signatures the previous decoder knew, which are the
selectors a policy written against an earlier build could usefully hold. Each row is pinned
in-tree by a test that recomputes the selector from the signature, so the table cannot drift.

| Old `selectors` entry | `signature` to declare |
| --- | --- |
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

Any selector you wrote that is **not** in this table names a call the daemon has never been able
to decode. It signed anyway, rendered as `UNDECODED CALL 0x…` for a human to eyeball — that hole
is what this change closes. Take the real signature from the contract's ABI and the call becomes
both decodable and constrainable.

Then bound every argument. The conversion is not mechanical, because a rule that used to say
only "these four bytes" now has to say what the arguments may hold, and **an argument with no
rule does not parse**. Write `rule = "unbounded"` where you genuinely mean it and the approval
sheet will lead with `⚠ UNBOUNDED FIELD` every time.

**What stops being signable after conversion**, so you can plan for it:

- every call whose selector you allow-listed but whose signature you have not declared;
- any payload whose arguments do not decode against the declared signature, or that decodes but
  re-encodes differently (padding, trailing bytes, dirty address upper bits, a `bool` word
  holding `2`);
- any argument outside its declared rule;
- **any `multiSend` whose entries are not each individually permitted** — this is the biggest
  item. A policy that allow-listed only the MultiSend library for `delegatecall` will refuse
  every batch until you add a rule per destination the batch touches. `bundle status` shows the
  typed refusal for any bundle you already hold, which is the dry run;
- a `multiSend` payload that is malformed, over 32 entries in the tree, or nested past depth 2;
- a `multiSend` entry with empty calldata, or one carrying native value past its rule's ceiling;
- an owner-management self-call carrying native value, unless `[owner_management].max_value`
  says otherwise.

**What becomes signable:** any function whose ABI you have, and EIP-712 typed messages under a
declared `[[typed_data]]` schema.

## 7. Run and verify

```
hot_cheese serve
```

Runs in the foreground on `127.0.0.1:5555` (override with `port` in `config.toml`).
Liveness check — this proves the daemon is up and serving TLS, and prompts no biometric:

```
curl --cacert ~/.config/hot_cheese/ssl-cert.pem https://127.0.0.1:5555/health   # -> ok
```

**That `curl` is a liveness check, not a pinning test.** macOS ships curl with the
SecureTransport backend (`curl --version` says so), where `--cacert` *adds* an anchor to the
system trust store instead of replacing it — a certificate signed by any system-trusted CA
would also pass. Real pinning is what the reference client does: it builds a
`RootCertStore` containing **only** `ssl-cert.pem`, so nothing else validates. Test it with:

```
cargo run --release -p hc-daemon --example pin_cert -- https://127.0.0.1:5555 <NAME>
```

It resolves the pinned cert from the same home dir the daemon uses (honouring
`HOT_CHEESE_HOME`), prints `health=ok`, then does **one** df-share read of `<NAME>` and
prints only `len=`, `digest=` (salted per read and truncated, so it is not a usable offline
commitment to the secret), and `evm_address=` — never the key bytes.

The `pin_cert` example reads a key, so point it at one you migrated `--shareable`; a
`sign_only` key answers `500` and the daemon logs
`Envelope(ExportRefused { key_use: SignOnly })` **without prompting for Touch ID at all** —
the refusal is decided from the cleartext header, before anything unlocks.

Then do **one** real read from your actual client (pinning the fingerprint from §2) to
confirm the end-to-end path. Every `/read` now prompts a **fresh Touch ID per request**, and
the sheet names the key (`Unlock "<NAME>" for read key`) — do not script or spam it;
`/health` is the only non-prompting endpoint.

## 8. Back up what the store backup does NOT cover

The git backup replicates **only the store dir** — which includes `keyring.json` (the
**wrapped DEK**) — so the remote never sees plaintext or the DEK. It does **not** include
the TLS cert/key or `config.toml` (those live under the home dir). Separately back up

```
~/.config/hot_cheese/{ssl-cert.pem,ssl-key.pem,config.toml}
```

to a **secure** location — plus `~/.config/hot_cheese/adapters/` if you configured any (§6b).
Do **not** push the TLS private key to untrusted backup hosts. To provision a fresh machine
from an authority host over SSH instead, use `hot_cheese bootstrap-from user@host` (transfers
the DEK + store).

Adapter manifests and their pins are deliberately **outside** the store, so they travel with
neither the backup nor `bootstrap-from`. A restored or bootstrapped machine comes up with
**no adapters at all** — which is the correct fail-closed default. Re-establish adapter trust
per machine, on purpose.

`bundles/` (§9) is outside the store for the same structural reason and needs no backup at
all: it holds no secret, and a lost bundle is re-created from the same intent onto the same
`safeTxHash`. It has its own replication — `[[bundle_peers]]`, rsync over ssh between your own
Macs, a **separate config key pointed at a separate directory with no vault namespace** — which
is exactly why it is not this one. Back up `bundles/safes.toml` with `config.toml` if you would
rather not retype it; it is deliberately excluded from bundle sync, because a peer that could
rewrite it could lower a threshold.

### Vault ids: one backup folder, several installs

`init` mints a **vault id** (`v_<32 hex>`) next to the DEK and stores it in cleartext in
`keyring.json`. Each vault owns its own bare repository on the remote:

```
git push <host>:<folder>/<vault_id>.git refs/heads/main:refs/heads/main
```

The remote host needs **`git`**, not `rsync`; the repository is created on the first push,
with `receive.denyNonFastForwards` and `receive.denyDeletes` set on it so no push can rewrite
or delete the backup. Because the id is cleartext, a push reads it **without unlocking
anything** — no Touch ID, no passphrase. Several installs with **different DEKs** (a desktop
and a laptop holding different multisig signer keys, on purpose) can therefore share one
`host` + `folder` without overwriting each other.

`bootstrap-from` hands machine B the **same** DEK, so B is the same vault — and under git the
two machines start unrelated histories, so B's first push is refused as a non-fast-forward.
Resolve that once, by hand, with `hot_cheese backup pull --force` on whichever machine's store
is stale.

Recovery on a bare machine, where all you have is the recovery passphrase and the remote.
The store must be **empty** first: `init` writes the `config.toml` you need, but it also
mints a throwaway DEK and vault id that the restore must not inherit.

```
hot_cheese init                          # config.toml + TLS cert (and a throwaway vault)
$EDITOR ~/.config/hot_cheese/config.toml # add the [[backup_remotes]] entry
rm -rf ~/.config/hot_cheese/store        # drop the just-minted keyring: different vault
hot_cheese backup list                      # vault ids under <folder>, flagging this install's
hot_cheese backup pull --force --vault v_…  # take exactly that one
```

Only run that `rm -rf` where the store holds nothing you need — at that point it contains
one keyring that encrypts nothing. Then unlock with the recovery passphrase.

Without `--vault`, a pull uses this install's own id. A pull is refused before anything is
fetched if the local store already belongs to a **different** vault, and the **remote's**
`keyring.json` is then read straight out of the fetched objects and checked before a single
file in the worktree is touched — so a wrong-vault remote can never land on disk at all.
`serve`'s clone follows the same rule, and on a machine with no keyring at all it takes the
remote's vault only when there is exactly one — with several it refuses and lists them.

**`backup pull --force` deletes local-only keystores.** It resets the worktree to the remote's
commit, so a key generated here and never pushed is gone. It names every such file and its
count first, and without `--force` it prints that list and stops.

**Migrating an existing install:** a `keyring.json` written before vault ids gets one
**automatically** the first time this version opens the store, and the store becomes a git
repository in the same pass — commit #1 contains everything already there, and nothing is
rewritten except the file modes, which are tightened to `0600`. The old rsync directory at
`<folder>/<vault_id>/` is a **different path** from the new `<folder>/<vault_id>.git`, so it
is left untouched beside it and becomes stale from the first push. Delete it yourself once you
are satisfied. While a fleet is half upgraded the two paths mean the machines stop seeing each
other's keys; `backup list` flags a plain `<vault_id>` directory beside our repository for
exactly that reason.

---

## 9. (Optional) Collect Safe signatures across your machines

Nothing in the cutover requires this, and skipping it changes nothing: `bundle` adds no
endpoint, no listener, and no daemon exposure — its sync is outbound-only, started and finished
by the command that runs it. Do it when one Safe's threshold needs owner
signatures from **two machines holding different signer keys** — the desktop and the MacBook
that §8 already keeps in separate vaults on purpose.

Bundles live beside `adapters/` and **outside the store**:

```
$HOT_CHEESE_HOME/bundles/
  safes.toml           # never synced: it states what a Safe IS
  <safeTxHash>/
    unsigned.json      # the bundle as created
    0x<signer>.json    # one file per signer, each a complete self-verifying bundle
$HOT_CHEESE_HOME/bundle-quarantine/
  <safeTxHash>/        # what a peer pushed that failed verification, moved aside
```

The store is what `backup push` replicates per vault, and the two machines are deliberately
different vaults — so bundles must never travel that path, and they do not. They are also not
secret: a bundle is the transaction's fields plus signatures over a public digest. Losing
`bundles/` costs you the signatures collected so far and nothing else; re-create the bundle
from the same intent and it lands on the same `safeTxHash`.

**One file per signer** is what makes two machines safe to use at once: each device writes
`0x<its-signer>.json`, so concurrent signing writes two different names — no lock, no
last-writer-wins, no merge conflict. Reading takes the union, and the union re-derives the
digest from the fields and refuses a file belonging to another transaction.

Describe each Safe once, in `$HOT_CHEESE_HOME/bundles/safes.toml`:

```toml
[[safe]]
address = "0x1111111111111111111111111111111111111111"
chain_id = 1
threshold = 2
owners = [
  "0x2222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333",
]
```

This is **not** `policy.toml` and does not replace §6 — the policy remains the signing ceiling
for each key, and `bundle sign` is subject to it exactly as `/sign/<NAME>` is. A term this build
does not implement fails to load rather than being dropped silently.

`owners` is a **local mirror of on-chain state**. hot_cheese has no RPC client, so it cannot
notice a rotation: a stale list makes `bundle export` produce a blob that reverts on-chain.
That is a loud, cheap failure — one reverted call — and it is preferred to a mirror that
refreshes itself over the network. Update it by hand when you rotate owners. For the same
reason, retiring a bundle is manual: `bundle list` shows age and flags `RIVAL` bundles
competing for one `(Safe, chain, nonce)`, and you decide.

```bash
# once per machine pair: enroll the other Mac off the tailnet
hot_cheese bundle peer add macbook                       # writes [[bundle_peers]] in config.toml

# desktop
hot_cheese bundle new --file intent.json                 # prints the safeTxHash, pushes it
hot_cheese bundle sign <hash> --key DESKTOP_SIGNER       # policy + grant + one Touch ID, pushes

# on the MacBook — nothing was copied by hand
hot_cheese bundle sign <hash> --key LAPTOP_SIGNER        # pulls, its own biometric, pushes
hot_cheese bundle status <hash>                          # pulls: 2/2, nobody missing, no rivals
hot_cheese bundle export <hash>                          # execTransaction fields + signatures
```

`--key` is each machine's own keystore name; it is outside the EIP-712 encoding, so both
machines produce the identical digest and the identical directory name.

**Transport is `rsync` over `ssh`, outbound only, woven into the verbs.** `status`, `export`,
`list` and `sign` pull first; `new`, `sign`, `merge` and `add-sig` push after; `rm`
never syncs, because a pull would resurrect what you just retired. A verb naming a hash moves
only that directory. It is **best-effort**: an asleep MacBook is a warning, never a failed
signature on the desktop, and `--no-sync` turns it off for one command. `bundle sync` forces
both directions, and a running `hot_cheese` or `hot_cheese serve` polls every peer on its own
timer, so waiting on a co-signer needs no command at all.

Peers come from `tailscale status --json` — MagicDNS **names**, never addresses, so nothing
needs maintaining when the tailnet re-addresses. `[[bundle_peers]]` is a separate config key
from `[[backup_remotes]]`, pointed at a separate directory, with **no vault namespace**: the
store is per-vault and must never cross machines, and it does not. There is **no `--delete` in
either direction** — one file per signer means plain `rsync` already *is* the union merge — and
`safes.toml` is excluded both ways, because a peer that could rewrite it could lower a
threshold or plant an owner.

**Nothing listens.** No port opens, no daemon is involved, and no child outlives the command.
Tailscale here is a **network path, not an authentication mechanism**: it grants no authority
because there is nothing to grant it to, and the most an attacker on it achieves is putting
bytes in a directory. Which is exactly why **every pull is validated before anything reads it**:
each ingested file must be named `unsigned.json` or `0x<signer>.json`, be at most 64 KiB, parse,
hash from its own fields to the directory it sits in, ecrecover every signature to the address
it claims, and carry only the signer its name binds it to. Anything else is **moved** — never
deleted — to `$HOT_CHEESE_HOME/bundle-quarantine/<hash>/`, which is outside `bundles/` so it is
never synced back out. Every one of those rules is one your own writes satisfy by construction,
so quarantine cannot eat your own signature.

Beyond that, every signer independently re-derives the digest from the fields, runs its own
policy fail-closed before any prompt, and shows the decoded call over the Touch ID sheet. What
a hostile channel *can* do is present a **plausible** intent you might approve — which is why
that decoded summary is load-bearing. Read the destination and the amount, every time.

`bundle export` never broadcasts: hot_cheese has no RPC client, prints the assembled call, and
stops. Send it with whatever tooling you already use.

---

## After cutover

- **Dual-run (N = 7–14 days).** Keep the legacy store and its Keychain master **intact
  and untouched** while v1 serves production. Keep at least one good backup current
  (`hot_cheese backup push`, after configuring `backup_remotes` in `config.toml`).
- **Decommission (only after a clean dual-run + verified backup):** final
  `hot_cheese backup push`; delete the legacy store dir; remove the legacy Keychain
  master (`security delete-generic-password` for the configured service/account). After
  this, all access flows through the v1 DEK (SE and/or recovery passphrase) only.
- **Rollback before decommission is trivial** (migrate never touched the old store):
  stop `hot_cheese serve`, restart the legacy daemon against the intact old store, and
  revert clients to the old cert fingerprint. Remove a stale `store.staging` if an
  aborted run left one (a clean run removes it; the next `migrate` also clears it first).

## Recovery: the Secure Enclave key is gone

The enclave key is device-bound and dies with the machine, with the blob file, or with a
**Touch ID re-enrollment** (the key's ACL is `.biometryCurrentSet`, so adding or removing a
fingerprint invalidates it). The store is **not** lost: the same DEK is also wrapped under
your recovery passphrase. Commands fail with an error naming the remedy — e.g.

```
command failed error=ApiBackend(Unlock(SeKeyUnavailableTryUnlockPassphrase))
```

The escape hatch is the global `--unlock <se|passphrase>` flag, accepted by every command
that unlocks the DEK (`address`, `add`, `generate`, `bundle sign`, `seal`, `enroll`, `migrate`),
either before or after the subcommand:

```
hot_cheese --unlock passphrase address evm <NAME>
hot_cheese address evm <NAME> --unlock se          # force the enclave instead of the default
```

Omitting `--unlock` keeps the existing behaviour exactly: the Secure Enclave when any SE
enrollment exists, otherwise a passphrase prompt. There is no silent fallback — a broken
enclave stays loud.

To get back to normal Touch ID operation:

```
rm $HOT_CHEESE_HOME/se_kek_hotcheese_se_kek_v1.blob   # or ~/.config/hot_cheese/…
hot_cheese --unlock passphrase enroll se
```

Deleting the blob is required when the key still exists but was invalidated: `enroll se`
reuses an existing blob and would otherwise re-enroll the dead key. The stale enrollment
record left in `keyring.json` is harmless — unlock skips any record whose `se_pub` is not
this machine's current enclave key.

`serve` deliberately **refuses** `--unlock passphrase` (`ServeRefusesPassphraseUnlock`): the
daemon holds its unlocker for its whole lifetime, so one startup passphrase would answer
every later request and silently delete the per-request human approval that is the point of
the daemon. Recover with the management commands above, re-enroll the enclave, then serve.

Losing the passphrase **and** the enclave key means the store is unrecoverable — that is the
design. `hot_cheese list` warns when no passphrase is enrolled.

## `migrate` failure reference

| Logged error | Meaning | Action |
| --- | --- | --- |
| `NewStoreNotEmpty` | `--new-store` already holds a key file. | Point at an empty dir. |
| `UnknownShareable { name }` | `--shareable <name>` names a key `--old-store` does not hold (usually a typo). | Nothing was written. Fix the name and re-run. |
| `VerifyMismatch(<name>)` | Round-trip or re-derived identity didn't match. | Aborted safely; old store intact. Investigate that source key; don't retry blindly. |
| `Crypto(..)` / `Envelope(..)` | A legacy file failed its MAC or isn't valid keystore JSON (wrong master, or a foreign file in `--old-store`). | Confirm the §3 service/account and that `--old-store` holds only real legacy keystores. |
| `SolanaKeypair` | A 64-byte secret didn't parse as a Solana keypair. | Inspect that source key. |
| `Address(..)` | A 32-byte secret didn't yield a valid EVM key. | Inspect that source key. |
| Touch ID denied | The biometric prompt for the legacy master was rejected. | Re-run and approve. |
| `GetPassword(NonzeroStatus(-25300))` | No legacy master under the configured `service`/`account`. | Fix §3 and re-run. |
| `GetPassword(NonzeroStatus(-128))` | The login-Keychain ACL dialog was cancelled. | Re-run and choose **Allow**. |
| `Unlock(SeKeyUnavailableTryUnlockPassphrase)` | This machine's Secure Enclave key is missing or unloadable. | Re-run with `--unlock passphrase`, then follow *Recovery* above. |

In every case the old store is left **byte-for-byte unchanged** and no partial new store
is produced.
