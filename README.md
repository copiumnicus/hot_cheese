# Hot Cheese 🔥🧀

**Hot Cheese** is a macOS HTTPS daemon that hands **EVM** and **Solana** signing
keys to local services when they restart. Keys live on disk as an **envelope**:
a random Data Encryption Key (DEK) encrypts each keystore, and the DEK is itself
wrapped under one or more **Key Encryption Keys (KEKs)** — a **Secure Enclave key
bound to Touch ID** and/or a **recovery passphrase**. There is **no extractable
master password** anymore.

Every key read is gated by a **cryptographic** Touch ID step (not a UI prompt you
could bypass) — or, for one `shareable` key at a time and only while the operator has
explicitly issued one, by a time-boxed [read grant](#read-grants) that caches no DEK.
Traffic is protected by **TLS certificate pinning**, and each
secret is delivered over a per-request **Diffie-Hellman key exchange** — an
ephemeral P-256 exchange whose transcript is bound into both the KDF and the AEAD —
so only the calling client can decrypt it. Because the DEK never touches disk in the
clear, the **key material** in the store is safe to back up anywhere (the key names
and policies beside it are not — see [Backups](#backups)), and a new machine can be
**bootstrapped over SSH** without the DEK ever crossing the wire in plaintext.

> **Breaking wire change: the `/read` exchange is no longer wire-compatible with
> df-share.** HKDF `info` is now `"hotcheese/share/v1/hkdf" ‖ client_pub ‖ server_pub`
> and the AES-GCM associated data is `"hotcheese/share" ‖ 0x00 ‖ key_name ‖ 0x00 ‖ 0x01`.
> An old client cannot decrypt a new daemon's response and a new client cannot decrypt an
> old daemon's. Upgrade both ends together. See [Client Integration](#client-integration).

> Upgrading from the old Keychain-master build? See **[MIGRATION.md](./MIGRATION.md)**
> for the non-destructive, verify-before-finalize cutover runbook.

---

## Table of Contents

1. [Key Features](#key-features)
2. [How It Works](#how-it-works)
2. [Key uses](#key-uses)
3. [Requirements](#requirements)
4. [Secure Enclave (no code signing required)](#secure-enclave-no-code-signing-required)
5. [Try It Without the Secure Enclave (demo)](#try-it-without-the-secure-enclave-demo)
6. [Quickstart](#quickstart)
   - [1. Initialize](#1-initialize)
   - [2. (Optional) Enroll the Secure Enclave](#2-optional-enroll-the-secure-enclave)
   - [3. Add or generate keys](#3-add-or-generate-keys)
   - [4. Serve](#4-serve)
6. [CLI Reference](#cli-reference)
7. [Configuration](#configuration)
8. [Server Endpoints](#server-endpoints)
   - [Read grants](#read-grants)
9. [Signing Adapters](#signing-adapters)
10. [Safe Bundles: several devices, one transaction](#safe-bundles-several-devices-one-transaction)
10. [MCP: an agent proposes, you sign](#mcp-an-agent-proposes-you-sign)
10. [Client Integration](#client-integration)
11. [Backups](#backups)
12. [SSH Bootstrap](#ssh-bootstrap)
13. [Migration](#migration)
14. [Security Model & Residual Risks](#security-model--residual-risks)
15. [FAQ](#faq)

---

## Key Features

1. **Envelope key storage** — a random DEK (XChaCha20-Poly1305) encrypts every
   keystore; the DEK is wrapped in `keyring.json` under each enrolled KEK. The
   plaintext DEK is **never** written to disk.
2. **Per-key sharability, enforced cryptographically** — every key declares at
   creation whether it may leave the daemon. A `sign_only` key can sign and derive
   an address but **`/read` can never export it**, and that is not a policy check:
   the flag is inside the AEAD additional data, so editing it on disk destroys the
   file instead of unlocking it. See [Key uses](#key-uses).
3. **Cryptographic Touch ID** — a Secure Enclave key bound to Touch ID is a real
   KEK. Each `/read` (and generate/address) unwraps the DEK by doing a
   Touch-ID-gated ECDH inside the Secure Enclave: no biometric ⇒ no ECDH ⇒ no DEK
   ⇒ no decrypt. Per-request human approval is preserved. An enclave key blob sitting
   at the key path is **adopted only when its public key is already recorded** —
   `se_pub` in `keyring.json`, `grant_public_key` in `config.toml` — so a planted
   non-biometric key is refused rather than inherited. `enroll` and `list` print that
   key's 16-hex fingerprint and enrolment says **MINTED** or **ADOPTED**, so a
   re-enrolment into a record somebody else planted is visible if you compare it. Read
   the residual in [Security Model & Residual Risks](#security-model--residual-risks)
   before you rely on it: `keyring.json` itself carries no MAC.
4. **Per-payload signing grants** — `/sign` cannot reach the signing key without a
   `SignGrant`, and the only way to obtain one is to verify a fresh Secure Enclave
   ECDSA signature over the exact payload (rebuilt hash, policy digest, nonce,
   expiry) against the grant key `config.toml` pins. The grant is taken under the
   same biometric that approved the request — still **one** Touch ID — and is moved
   into the signing call, so it covers exactly one signature. See
   [Server Endpoints](#server-endpoints).
5. **Recovery passphrase backstop** — an Argon2id-derived KEK that can unwrap the
   same DEK on any machine. It is the only cross-machine restore path (Secure
   Enclave keys are device-bound).
6. **Safe-to-replicate backups** — the store is a **git repository**. Every
   mutation auto-commits, a session pushes in the background, fetches on a timer,
   and validates remote history without applying it. A fast-forward proves ancestry,
   not authorship, so only an explicit `backup pull --force` can make remote state
   active. **Only the key material is ciphertext.** The remote also receives every key
   **name** (key names *are* the file names), every `policies/<name>.toml` in
   **plaintext**, the enrollment labels and public points in `keyring.json`, and a
   commit-by-commit **timeline of when each of those changed**. Each install owns its
   own **vault** repository, so machines holding different keys can share one backup
   host and folder.
7. **End-to-end encrypted reads** — per-request Diffie-Hellman exchange means the
   secret is encrypted specifically for the requesting client, on top of pinned
   TLS.
8. **SSH bootstrap ritual** — provision a fresh machine from an authority over
   SSH; the DEK is delivered via ECIES sealed to the new machine's Secure Enclave
   key and re-wrapped there under its own KEKs.
9. **Out-of-process signing adapters** — a domain service can be given its own
   `0600` unix socket, a SHA-256-pinned manifest, and a route table containing
   only `/health` and `/sign`. The manifest can only **narrow** the key's policy;
   a manifest that claims more stops `serve` from starting. Provenance comes from
   the socket, so the Touch ID sheet names which adapter asked. See
   [Signing Adapters](#signing-adapters).

---

## How It Works

```
                         keyring.json  (safe to back up — no plaintext DEK)
                        ┌──────────────────────────────────────────────┐
                        │  enrollment: Secure Enclave  → wrapped DEK     │
   Touch ID ─ ECDH ────▶│  enrollment: recovery passphrase → wrapped DEK │◀── Argon2id
   (Secure Enclave)     └──────────────────────────────────────────────┘
                                          │ unwraps
                                          ▼
                                    DEK (in memory only, zeroized after use)
                                          │ XChaCha20-Poly1305
                                          │ AAD = "hotcheese/keystore/v2" ‖ 0 ‖ name ‖ 0 ‖ use
                                          ▼
                        store/  EVM_KEY   SOLANA_TRADER   …   (encrypted keystores)
```

1. **At rest.** Each keystore file under `store/` is a small JSON container —
   `{"v":2,"key_use":…,"body":{…}}` — whose `body` is an XChaCha20-Poly1305
   envelope keyed by the DEK. The **AEAD additional data (AAD)** binds a domain
   separator, the **key name**, and the **declared use**, so a copied, renamed, or
   re-flagged file refuses to decrypt. The DEK only ever exists on disk in wrapped
   form, inside `keyring.json`.
2. **Unlocking.** Every operation that needs the DEK builds an *unlocker* and
   unwraps the DEK for that single operation, then drops (zeroizes) it. The DEK is
   never cached.
   - **Secure Enclave KEK** = `HKDF(ECDH(SE_priv, eph_pub))`. The SE private key
     never leaves the enclave and each ECDH requires a live Touch ID.
   - **Passphrase KEK** = `Argon2id(passphrase, salt)`. The costs are recorded per
     enrollment and validated on load as a **range**, not an exact match —
     `m_cost` 65 536…131 072, `t_cost` 3…5, `p_cost` 1…4 — so the floor keeps a
     downgrade rejected while a future build can still raise what it writes without
     refusing to open a vault written by this one. The **ceiling** is there because
     `keyring.json` is attacker-writable input that travels to untrusted backup
     remotes and comes back: `unlock` derives one KEK per passphrase enrollment and
     the keyring may hold 32, so an unbounded ceiling would let a planted keyring
     turn one unlock attempt into an arbitrarily long stall. At the current ceiling a
     derivation measures ≈0.29 s and a full 32-enrollment walk ≈9.4 s; the previous
     ceiling (1 GiB, `t_cost` 64, `p_cost` 16) measured ≈35 s and ≈19 minutes for the
     same walk.
3. **Serving.** `hot_cheese serve` binds HTTPS on loopback, presents the pinned
   self-signed certificate, and answers the endpoints below. Every one of those
   endpoints except `/health` is put in front of the operator for an explicit
   approval before anything unlocks. Secrets are returned through an ephemeral P-256
   Diffie-Hellman exchange so only the requesting client can read them.
4. **Replication.** Any mutation commits the store and the session pushes that
   commit to the configured remotes, into this install's vault repository
   (`<folder>/<vault_id>.git`). The secrets are ciphertext; the key names, the
   policies and the commit timeline are not (see [Backups](#backups)).

---

## Key uses

Every key declares at creation whether it may ever leave the daemon:

| Use | `/read` (export) | `/sign`, `address` | Reversible? |
| --- | --- | --- | --- |
| `shareable` | released to the client, and to a live [read grant](#read-grants) | yes | yes — `seal --use sign-only` tightens it, and ends any live grant with it |
| `sign_only` (**default**) | **refused, always** | yes | **no, by construction** |

```bash
hot_cheese generate evm TRADING_BOT --use shareable   # a service will fetch this key
hot_cheese generate evm SAFE_SIGNER                   # signs only; sign-only is the default
hot_cheese list                                       # shows the use, and prompts nothing
```

**Why it is not just a flag.** The use lives in the file's cleartext header *and* inside the
AEAD additional data. Rewriting `"key_use"` on disk does not authorize an export — it makes
the AAD wrong, so the file stops decrypting entirely (for everyone, including the recovery
passphrase). And `/read` does not consult the flag at all: it needs an *export permit*, a
value that only a header reading `shareable` can produce, minted **before** anything unlocks
the DEK. A refused export therefore costs **zero** Touch ID prompts.

**`sign_only` is a one-way door.** Loosening it would mean decrypting the key and re-sealing
it under a looser AAD — exactly the export `sign_only` forbids — so no command does it.
`hot_cheese seal` refuses with `SealCannotLoosen`; the only route back is a new key
(`generate --use shareable`) and a rotation.

Tightening a key is also the per-key kill switch for a token somebody already holds. A
[read grant](#read-grants) seals a **copy** of the key, so the daemon re-reads the keystore's
cleartext header on every token-authenticated `/read` and releases nothing unless that keystore
still exists and still declares `shareable`. `seal --use sign-only` and deleting the keystore
therefore stop a live grant on its next request, and `seal` names each grant that stopped.

`seal` binds an existing keystore, which is how a store written before uses existed (it
lists as `unsealed`, and an unsealed key cannot be exported) gets its declaration:

```bash
hot_cheese seal TRADING_BOT --use shareable   # a named key may also be tightened
hot_cheese seal --all                         # binds every still-unsealed key as sign_only
```

`--all` never re-decides a key that already declared a use, so those two are safe in either
order and re-running them is a no-op. The DEK is unlocked **once** for the whole batch, and
every file is re-opened from its new bytes and compared against the original plaintext
before it replaces the old one.

The HTTP `/evm_generate` and `/solana_generate` endpoints always mint `sign_only` keys: a
remote caller may never create itself an exportable key.

---

## Requirements

- **macOS with a Secure Enclave** (Apple Silicon, or a T2 Intel Mac) for the
  Touch ID path.
- **Rust toolchain** and the **Xcode Command Line Tools** (`swiftc`) to build the
  `hot_cheese` binary — the Secure Enclave bridge is a small Swift shim compiled and
  linked at build time.
- **`git`**, **`rsync`** and **`ssh`** on the host — `git` for backups, `rsync` for
  bundle sync, `ssh` for both and for the bootstrap ritual. The **backup host** now
  needs `git` where it used to need `rsync`; a host that has only `rsync` can no
  longer take backups.
- The Secure Enclave KEK needs **no code signing, Team ID, entitlements, or Apple
  Developer Program** — a plain `cargo build --release` works. It only requires that the
  daemon run in your **active GUI login session** (Touch ID can't fire under pure
  `ssh`/`sudo`/launchd). The recovery-passphrase unlocker works anywhere; the Secure
  Enclave can be added later.

---

## Secure Enclave (no code signing required)

The Secure Enclave KEK uses Apple **CryptoKit** (`SecureEnclave.P256`): the daemon
creates a Touch-ID-gated P-256 key inside the enclave and persists it as an opaque
blob file under the home dir (no keychain item). This needs **no** code-signing
identity, Team ID, entitlements, provisioning profile, `.app` wrapper, Developer ID, or
notarization — the automatic ad-hoc signature from a normal release build is enough:

```bash
cargo build --release
./target/release/hot_cheese se-selftest   # three Touch ID prompts; validates the SE path
```

Run `se-selftest` in your **GUI login session with the screen unlocked** (a Terminal on the
Mac itself), not over `ssh` — Touch ID cannot fire in a headless / `sudo` / launchd context,
and the enclave refuses to create the key at all while the screen is locked. It asserts Touch ID
gating, deterministic ECDH, SE/host ECDH equivalence, and that **one** biometric covers
**both** an enclave ECDH **and** an enclave ECDSA grant signature that verifies host-side
against the exported grant public key (the same check as the `#[ignore]`d
`se_key_lifecycle_and_deterministic_ecdh` test in `crates/hc-core/src/mac/secure_enclave.rs`). See
[Security Model & Residual Risks](#security-model--residual-risks).

The self-test creates and deletes its own throwaway keys under a `hotcheese.se.selftest`
label, so it never touches the enrolled KEK or grant key.

Code signing — a **Developer ID Application** certificate plus notarization — is only
needed to **distribute** the binary to *other* Macs without Gatekeeper warnings, never to
run it locally.

**What running unsigned costs you.** An ad-hoc signature carries no **hardened runtime**,
so there is no library validation and no `DYLD_INSERT_LIBRARIES` restriction: a same-uid
process can inject a dylib into `hot_cheese serve`. One injected read of the DEK turns a
single approved Touch ID into unlimited silent use of **every** key, because the injected
code is inside the process that holds the plaintext DEK. Nothing in this repo runs
`codesign --options runtime`, so this is the shipping configuration, not a corner case.
Treat "code execution as your uid" as full compromise of the store and size the machine's
other software accordingly.

---

## Try It Without the Secure Enclave (demo)

Want to feel the flow on a Mac **without** a Secure Enclave, or preview it without touching
the real enclave? Set `HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE=1` and the SE entry points use a
**software P-256 key in a file** instead of the enclave, still gated by a real Touch ID
prompt. You run the **identical** commands — `enroll se`, `serve`, `se-selftest` — and get
the same envelope / ECDH / per-request-unlock experience.

```bash
./scripts/demo.sh        # init → enroll se → generate → address → se-selftest, in /tmp
```

…or by hand:

```bash
export HOT_CHEESE_HOME=/tmp/hot_cheese_demo
export HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE=1
hot_cheese init                 # set a recovery passphrase; prints the cert fingerprint
hot_cheese enroll se            # creates a SOFTWARE "enclave" key (a file)
hot_cheese generate evm DEMO
hot_cheese address evm DEMO     # ← Touch ID prompt: this is the per-request DEK unlock
hot_cheese se-selftest          # ECDH determinism, SE/host equivalence, one-biometric grant
xxd /tmp/hot_cheese_demo/software_enclave_hotcheese_se_kek_v1.key   # readable — the point
```

> ⚠️ **Preview only.** The demo key sits on disk and is **extractable**, and Touch ID here is a
> gate, not hardware-enforced — exactly the weaknesses the real Secure Enclave removes. The env
> var must be set explicitly (it never engages by accident) and every unlock logs that it is a
> demo. Don't put real keys in a demo store. When convinced, unset the env var and the same
> commands run against the hardware enclave with the key sealed in the chip — no signing needed.

---

## Quickstart

Build / install the binary first:

```bash
cargo install --force --locked --profile release --bin hot_cheese --path crates/hc-cli
# or run in place:  cargo run --release -- <subcommand>
```

### 1. Initialize

```bash
hot_cheese init
```

`init`:

- creates the home dir + store,
- generates a self-signed **`localhost`** TLS cert (CN=`localhost`, SAN
  `DNS:localhost` + `IP:127.0.0.1`) and writes `ssl-cert.pem` / `ssl-key.pem`,
- mints a fresh random **DEK**,
- **requires a recovery passphrase** (entered twice) as the first, survivable
  enrollment — **at least 20 characters and at least 8 distinct characters**, so a
  long repetitive phrase is refused; the floors apply to a passphrase being *set*,
  never to one being used, so an existing enrollment keeps unlocking unchanged,
- prints the certificate **SHA-256 fingerprint** — record it for client pinning.

Record the recovery passphrase **offline** (treat it like a seed phrase): it is
the only cross-machine restore path for the DEK.

To **check the phrase you recorded**, run `hot_cheese --unlock passphrase` and type it at the
prompt. The prompt itself is the check: every command proves the passphrase against
`keyring.json` before it opens anything, so a wrong one is refused right there — it never
reaches a menu, a key, or a signature. It costs one Argon2 derivation, raises no Touch ID, and
releases nothing.

To **reuse an existing certificate** (so clients pinning the old fingerprint
don't have to re-pin):

```bash
hot_cheese init --import-cert <cert.pem> --import-key <key.pem>
```

`init` refuses to run when it finds a prior install — `config.toml`, a
`store/keyring.json`, or any keystore file — and its error names what it found
(`ExistingStore { store, keyring, keystores }`). The generated `ssl-key.pem` is
written `0600`.

`--force` no longer just overrides that. It first **enumerates every casualty** — each
keystore the new DEK orphans, by name, and each enrollment the new keyring discards, by
id and label — and then demands the phrase back, typed exactly:

```
destroy the existing hot_cheese keys
```

Anything else refuses (`ConfirmationRefused`). **There is no flag that carries the phrase.**
A `--force` with no terminal to type it on fails with `ConfirmationOnlyFromATerminal` and
changes nothing, so no script, cron job or agent running as you can reach the destruction —
see [A destructive command requires a terminal](#a-destructive-command-requires-a-terminal).
A store `init` finds empty skips the whole ceremony.

**A forced init is recoverable, and it tells you how.** Before the new DEK is minted, `init`
commits the keyring it is about to replace to the store's own git history, then prints that
commit and the exact line that checks it back out:

```
RECOVERY: this commit carries the keyring that unwraps the OLD DEK …
  commit=<40 hex>
  run=git -C <store> checkout <40 hex> -- keyring.json && chmod 600 <store>/keyring.json
```

Run that line and `hot_cheese --unlock passphrase address …` with the **old** recovery
passphrase reads every orphaned keystore again, byte for byte. The keys are unreadable by the
*new* install, not destroyed — for as long as **this store's git history** survives, which is
the only copy of that keyring on the machine.

### 2. (Optional) Enroll the Secure Enclave

On a Mac with a Secure Enclave (no signing required), add a Touch-ID-bound unlock
method for the **same** DEK:

```bash
hot_cheese enroll se
```

**It tells you whether the enclave key is new, and names it.** The last line is one of

```
MINTED a new Secure Enclave key: the set of enclave keys this store trusts CHANGED  se_key=<16 hex>
ADOPTED the Secure Enclave key already on this disk; stop unless this is the fingerprint you enrolled  se_key=<16 hex>
```

`se_key` is the first 8 bytes of `SHA-256(SEC1 public key)`, 16 lowercase hex characters —
the same form the bootstrap ritual names an enclave key by, and the `/read` prompt the
recipient key. **Write it down, off the machine, the first time you see it**, and compare
every later `enroll se` and `hot_cheese list` against it.

**MINTED and ADOPTED are not equally safe.** MINTED means this command created the key, so
the change to the trusted set is one you just caused. ADOPTED means a key was already at
this machine's enclave key path and was taken up — the normal case is re-running `enroll se`
on a machine you have already enrolled, and the *dangerous* case is a same-uid attacker who
planted both a key blob and a matching `keyring.json` record and waited for you to re-enrol
into it. `keyring.json` carries no MAC, so nothing else distinguishes those two; the
fingerprint does. An ADOPTED line whose `se_key` is not the one you recorded is an alarm —
stop and investigate, do not continue. See
[Security Model & Residual Risks](#security-model--residual-risks).

You can also enroll additional recovery passphrases:

```bash
hot_cheese enroll passphrase --label backup-phrase
```

Then create this machine's **grant key** — a second, independent enclave key that signs
approval digests instead of unwrapping anything. This one is **not optional if you sign**:

```bash
hot_cheese enroll grant
```

It prompts for **nothing** (no Touch ID, no passphrase: creating the key and exporting its
public half touch no private key material), prints the key's uncompressed SEC1 public key,
and pins it into `config.toml` as `grant_public_key`. Every `/sign` mints a grant under this
key and verifies it against that pin, so `serve` refuses to start when nothing is pinned or
the blob is gone (`GrantKeyMissingRunEnrollGrant`) and when the on-disk grant key exports a
different public key (`GrantKeyPinMismatch { pinned, found }`).

It prints the same kind of line as `enroll se`, under `grant_key`: **MINTED** when the key
`config.toml` pins CHANGED, **ADOPTED** when the key already on this disk is the one that was
already pinned. Record `grant_key` the first time and compare it afterwards, exactly as for
`se_key`.

That pin is an **identity check, not a security boundary**: it catches an accidentally
swapped `se_grant_*.blob` or a restore that brought `config.toml` but not the enclave key.
It does nothing against an attacker who can already write your home dir — they can rewrite
the pin as easily as the blob.

**Losing the grant key is benign.** Nothing is wrapped under it, so there is no data loss
and no passphrase backstop is needed — unlike the SE KEK, whose loss leaves the recovery
passphrase as the only way back to the DEK. Recovery is just `hot_cheese enroll grant`
again (deleting a dead blob first, if one is still there), which re-pins the new key. Old
grant signatures stop verifying, which is exactly what rotating it should do.

### 3. Add or generate keys

```bash
# Import an existing secret (prompted, hidden input):
hot_cheese add MY_EVM_KEY ethereum     # hex, 0x optional
hot_cheese add MY_SOL_KEY solana       # base58 keypair bytes
hot_cheese add MY_RAW     bytes        # raw UTF-8

# Generate a fresh key:
hot_cheese generate evm    TRADING_BOT
hot_cheese generate solana SOLANA_TRADER

# ...and a key a service will fetch over /read:
hot_cheese generate evm    EXPORTABLE_BOT --use shareable

# Inspect (prompts nothing; prints each key's use):
hot_cheese list
hot_cheese address evm    TRADING_BOT
hot_cheese address solana SOLANA_TRADER
```

Key names must match `[A-Za-z0-9_]+`.

`add` and `generate` both take `--use <shareable|sign-only>` and both **default to
`sign-only`**, which `/read` can never export and which can never be loosened afterwards —
read [Key uses](#key-uses) before you create a key some service is going to fetch.

### 4. Serve

```bash
hot_cheese serve
```

Binds HTTPS on `127.0.0.1:<port>` (default **5555**), plus one unix socket per
trusted adapter. If the local store has no `keyring.json` and a backup remote is
configured, `serve` **clones** the store first — this install's
[vault](#vaults-several-installs-one-backup-folder), or the remote's only vault
when there is no local keyring to name one. The clone needs an empty store dir and
refuses, naming what it found, rather than starting a second history over files
that are already there.

`serve` holds this install's store claim for its whole life, so it and the
interactive console cannot run at the same time; the second one refuses at once,
naming the lock file, and every mutating subcommand (`add`, `generate`, `seal`,
`enroll`, `migrate`, `backup push|fetch|pull`, `bootstrap-from`, `init --force`)
does the same rather than writing underneath a live daemon. `address`, `list`,
`adapters`, `backup status`, `backup list` and every `bundle` verb still work while
one is running.

Every viable request that arrives over the network surface — the loopback listener and
the adapter sockets — immediately raises a Touch ID sheet in the active GUI login session.
That biometric is the approval: there is no terminal `y` prompt to discover first. The sheet
names the request, key and caller, and signing requests include the highest-priority decoded
summary lines. The approved `LAContext` is reused for the Secure Enclave unlock, so approval
and key use still cost one Touch ID interaction.

Touch ID prompts are strictly serialized on the daemon's main thread and shown in arrival
order. Rejecting or cancelling the sheet denies that request; approving it lets only that
request reuse the resulting authentication context. Requests rejected by public validation or
policy checks never raise Touch ID.

A denied request answers **403**, deliberately not `500` — a client that retries every
server error would otherwise turn your refusal into a retry loop and starve itself. At
most **4** privileged operations may be queued behind the one on screen, and at most
**16** callers per listener may be waiting for a place in that queue; places are handed
out in **arrival order**, so a caller that submits without stopping can never get ahead
of one already waiting, and a caller is answered **503** with `Retry-After: 1` only after
waiting longer than two whole prompts without a place coming free. Both places are held
by the caller's own connection, so a caller that stops waiting for its answer stops
holding them, and the request it left behind is dropped without ever being shown to you.
A connection that opens and produces no request within **2 seconds** is dropped, so a
peer cannot hold listener slots without asking for anything.

---

## CLI Reference

| Command | What it does |
| --- | --- |
| `init [--import-cert <pem> --import-key <pem>] [--force]` | Create home/store, write the TLS cert, mint the DEK, require a recovery passphrase (≥20 chars, ≥8 distinct), print the cert fingerprint. `--force` over an existing store lists every keystore and enrollment it replaces, then requires the phrase `destroy the existing hot_cheese keys` **typed on a terminal**, commits the old keyring to the store's history, and prints the line that checks it back out. |
| `enroll se [--label <s>]` | Enroll this machine's Secure Enclave as a KEK for the same DEK. No code signing, and **no Touch ID prompt** — it needs only the enclave's public key. Ends on `MINTED` (new key, trusted set changed) or `ADOPTED` (key already on disk taken up), naming it as `se_key=<16 hex>`. Record it and compare it. |
| `enroll passphrase [--label <s>]` | Enroll an additional recovery passphrase. Records no enclave key, so it prints no fingerprint. |
| `enroll grant` | Create this machine's Secure Enclave **grant-signing** key and pin its public key in `config.toml`. Prompts nothing — no Touch ID, no passphrase. Required before `serve` or `bundle sign`. Prints `MINTED`/`ADOPTED` with `grant_key=<16 hex>`. Losing this key is benign; re-run to recover. |
| `add <name> <ethereum\|solana\|bytes> [--use <shareable\|sign-only>]` | Import an existing secret under `name` (read from a hidden prompt). Defaults to `sign-only`. |
| `generate <evm\|solana> <name> [--use <shareable\|sign-only>]` | Generate a fresh key under `name`. Defaults to `sign-only`. |
| `address <evm\|solana> <name>` | Print the public address / pubkey of a stored key. |
| `list` | List stored keystores (with each one's use) and keyring enrollments, each Secure Enclave enrollment carrying its `se_key=<16 hex>` fingerprint. Prompts nothing. |
| `adapters` | Show every trusted adapter: manifest path, pinned vs computed hash, socket path, and the policy-intersection verdict `serve` will act on. Prompts nothing, unlocks nothing. |
| `seal [<name>\|--all] [--use <shareable\|sign-only>]` | Bind a key's use into its envelope. Tightens only; `--all` binds just the still-unsealed keys. One unlock for the whole batch. Names every read grant that stops releasing as a result. |
| `read-grant allow <name> [--hours <n>]` | Reseal one **shareable** key under a fresh 256-bit token so an agent can pull it over `/read` with **no Touch ID** until it expires (default 48h, max 8760). Costs exactly one Touch ID now. Prints the token **once** with a block to hand the agent; nothing stores it, so it can never be shown again. A window outside `1..=8760` is refused while the argument is parsed, and a `sign_only` key from its cleartext header **before** anything unlocks, so neither costs a biometric. Re-running rotates the token and kills the previous one. |
| `read-grant list` | Every grant still in force, with its expiry, the time it has left, and whether the key it names would still be released — a grant whose key was sealed `sign_only` or deleted lists as **DEAD**. Expired ones are deleted as they are read, unless the clock has moved further past the expiry than the grant's whole window, which is treated as a clock to refuse on rather than destroy grants on. No claim, no unlock, no prompt — it runs while the console holds the store. |
| `read-grant revoke <name>` | Delete one grant now, so the token an agent holds releases nothing on its next request. No claim, no unlock, no prompt. |
| `bundle new [--file <json>]` | Start a bundle from a JSON intent; the threshold comes from `bundles/safes.toml`. Refuses a Safe that file does not describe. Prompts nothing. **Pushes.** |
| `bundle sign <hash> --key <name>` | Sign the bundle with a local key and file the signature under this device's signer address. The **only** bundle verb that prompts, and the only human signing verb there is: policy-checked, grant-gated, one Touch ID. Needs `enroll grant`. **Pulls, then pushes.** |
| `bundle status <hash>` | Merged view: signatures collected vs threshold, which owners are still missing, rivals, packed length, age. Prompts nothing. **Pulls.** |
| `bundle list` | Every bundle, grouped by the `(Safe, chain, nonce)` it competes for, with a loud `RIVAL` line when two digests share one slot. Prompts nothing. **Pulls the whole tree.** |
| `bundle merge <hash> [--file <path>]` | Union an external bundle file, a whole bundle directory, or one on stdin into the store. Prompts nothing. **Pushes.** |
| `bundle add-sig <hash> <--file <json>\|--stdin>` | Ingest another device's JSON sign response (a phone, say). Prompts nothing. **Pushes.** |
| `bundle export <hash>` | Print the `execTransaction` fields plus the packed signatures as JSON. hot_cheese never broadcasts. Prompts nothing. **Pulls.** |
| `bundle qr <hash>` | Render the transaction as a QR for another device's camera. Prompts nothing. |
| `bundle rm <hash>` | Retire a bundle on this machine. Deliberately never syncs. |
| `bundle sync [<hash>]` | Exchange with every enrolled peer, both directions, right now. Rarely needed — the verbs above already do it. |
| `bundle peer list` | Every machine on the tailnet, with its MagicDNS name, whether it is online, and whether it is enrolled. |
| `bundle peer add <name>` | Enroll a tailnet machine, once, after checking it answers and has a bundles dir. Writes `[[bundle_peers]]`. |
| `bundle peer rm <name>` | Stop syncing with a machine. |
| `bundle … --no-sync` | Do the verb and touch no peer. Accepted on every bundle verb, anywhere in the line. |
| `serve` | Run the HTTPS daemon and the adapter sockets. Takes this install's store claim and immediately raises Touch ID for each viable incoming request—no terminal confirmation first. Refuses to start without a local store or an enrolled grant key matching the `config.toml` pin. Restore a missing store explicitly with `backup pull --force` first. |
| `backup status` | Print this install's vault, its local commit, and every configured remote. No network, no write, no claim. |
| `backup push` | Push this install's commits to every configured remote, under its vault id. Fails only when **every** remote failed. |
| `backup fetch` | Fetch and validate every remote without changing the active store. Reports `remote ahead` or fails with `Diverged` when histories fork. |
| `backup pull --force [--vault <id>]` | **Destructive.** Throw away this machine's commits for the first remote's. Without `--force` it names every file it would delete and refuses. A pull that is **not** a purely additive fast-forward — one that forks, rewinds onto an ancestor, deletes store files, adds ones this machine never had, or replaces store files with older content — additionally requires the phrase `roll this store back` **typed on a terminal**, and one that strands every enrollment requires `give up every unlock path on this machine` as well. |
| `backup list` | List the vaults sharing the first remote's folder, flagging this install's. Prompts nothing. |
| `accept-deletions` | Record store files or enrollments that are **already gone**, which every other command refuses to commit. Names each one, then requires the phrase `record the loss of these hot_cheese files` **typed on a terminal**. CLI-only, and the only way out of a store wedged by a missing file. |
| `discard-enclave-key <se\|grant>` | Remove an enclave key blob squatting this machine's key path, which otherwise blocks the Secure Enclave path for good. Prints the path, the squatter's fingerprint, every fingerprint this install records, and whether the store's **history** holds a keyring that records it, then requires the phrase `discard this unrecorded hot_cheese enclave key` **typed on a terminal**. **Refuses outright** to touch a key this install DOES record. |
| `migrate --old-store <dir> --new-store <dir> [--shareable <name>]…` | Migrate legacy Keychain-master keystores into the envelope format. Everything not named `--shareable` lands `sign_only` (see [MIGRATION.md](./MIGRATION.md)). |
| `bootstrap-from <user@host> [--recovery-passphrase]` | Bootstrap this machine's DEK + store from an authority machine over SSH. Enrolls this machine's Secure Enclave only, unless `--recovery-passphrase` also enrolls a recovery passphrase read from a masked prompt (or from stdin with no terminal). |

`--unlock <se|passphrase>` is global: it works before or after any subcommand and selects
which enrolled KEK unwraps the DEK. Omit it and nothing changes — the Secure Enclave is used
whenever an SE enrollment exists, otherwise you are prompted for a passphrase. Pass
`--unlock passphrase` to reach the recovery enrollment while an SE enrollment exists; that is
the escape hatch when this machine's enclave key is lost or was invalidated by a Touch ID
re-enrollment, and **every** enclave failure names it — `SeKeyUnavailableTryUnlockPassphrase`
when the blob is gone, `SeKeyUnusableTryUnlockPassphrase` when the enclave refuses the blob it
has, `SeKeyPresentButUnprovenTryUnlockPassphraseDoNotReenroll` when a key is there that this
vault cannot prove is its own. There is no silent fallback. `serve` refuses `--unlock passphrase`, because a daemon holding a passphrase
unlocker would answer every request from one startup prompt and lose the per-request human
approval — recover, `enroll se` again, then serve.

**The two KEKs prove themselves at different moments, deliberately.** A passphrase is proven at
the prompt: the entry is derived and tried against `keyring.json` before the command opens a
session, so a wrong one is `WrongPassphrase` right there — a terminal is asked again, piped
input gets the refusal as the command's answer. The Secure Enclave is proven when it is used,
because its proof *is* the Touch ID sheet: checking it at startup would raise one biometric to
open the session and a second to do the work, and an operator who is taught that sheets are
routine stops reading them. So the path with a prompt to answer verifies eagerly, and the path
whose verification the operator watches happen stays lazy.

Logging defaults to `INFO`; override with `RUST_LOG=debug` (or `trace`/`warn`/`error`).

### A destructive command requires a terminal

Five operations can cost you key material or history, and each takes consent as an exact
phrase typed back:

| Command | Phrase |
| --- | --- |
| `init --force` over a store that holds anything | `destroy the existing hot_cheese keys` |
| `backup pull --force` that is not a purely additive fast-forward | `roll this store back` |
| `backup pull --force` that strands every enrollment | `give up every unlock path on this machine` |
| `accept-deletions` | `record the loss of these hot_cheese files` |
| `discard-enclave-key <se\|grant>` | `discard this unrecorded hot_cheese enclave key` |

**None of them can be answered by an argument.** There is no `--yes`, and no flag carries any
of these phrases. If stdin is not a terminal the command fails with
`ConfirmationOnlyFromATerminal { required }` and changes nothing — no ref moves, no file is
removed, no DEK is minted.

That is deliberate, and it is the whole guard rather than a convenience. Every phrase above is
a **public constant in this source**, so any process running as you — a shell script, a CI job,
a coding agent with your shell — can read the phrase and repeat it. What it cannot produce is a
terminal on your session. Taking the phrases off the command line does not make them secret; it
makes the destruction unreachable to anything that is not a human at a keyboard. Automating
around it (a pty, an `expect` script) is automating a decision the tool deliberately declines to
take on your behalf.

Nothing else changes: the destructive verbs all still exist, because disaster recovery needs
them. `backup pull --force` still restores a lost store and `accept-deletions` still unwedges
one. They ask you, at a terminal, first.

---

## Configuration

Config lives at **`$HOT_CHEESE_HOME/config.toml`**, defaulting to
**`~/.config/hot_cheese/config.toml`**. The TLS cert/key (`ssl-cert.pem` /
`ssl-key.pem`) live in that same home dir. `init` writes a sane default; you only
need to edit it to change the port or add backup remotes. A legacy
`config.json` is migrated to `config.toml` automatically on first load.

**This file is read only when it is a regular file owned by your account**, because a running
daemon re-reads it every cycle and obeys what it finds: `grant_public_key` is the pin every
signature is verified against and `backup_remotes` is where the store gets pushed. It holds no
secret, so its *mode* is not a refusal — hot_cheese **tightens** a config left readable or
writable by group or other to `0600` before it reads the bytes, and says so. You see the line
once, because the next read finds it already closed:

```
WARN hc_core::config: config.toml was open to other accounts; tightened to 0600 before reading it path=/Users/you/.config/hot_cheese/config.toml was=0644
```

That is the normal outcome for a config an editor wrote back at your umask, or one written by a
build older than this one, and nothing else changes: the command carries on. Two cases a `chmod`
cannot honestly fix are still refusals, and each names the fix:

| Refusal | Means | Fix |
| --- | --- | --- |
| `ChownConfigToYourUser { path, owner, ours }` | Another account owns the file, so it can rewrite the grant-key pin and the backup remotes behind you. Tightening someone else's file would not change that. | `sudo chown $(id -un) <path>` — the mode is then hot_cheese's problem, not yours. |
| `ReplaceConfigWithARegularFile { path, found }` | The path is a `Symlink`, a `Directory`, or something stranger. A final symlink is never followed to a config. | Put the real file at that path. A dotfiles symlink cannot survive here anyway: `enroll grant`, `bundle peer add` and friends rewrite `config.toml` by atomic rename, which replaces the link with a regular file. |

```toml
service = "com.cc.hot_cheese"
account = "hot_cheese_master"
store = "~/.config/hot_cheese/store"
port = 5555
grant_public_key = "04…"
bundle_watch_secs = 30
approval_timeout_secs = 60

[mcp]
max_pending = 16
keys = ["TREASURY_SIGNER"]
safes = ["0x1111111111111111111111111111111111111111"]
nonce_window = 8
proposal_ttl_mins = 1440
proposals_per_hour = 16
lock_cooldown_ms = 100

[[mcp.anchor]]
safe = "0x1111111111111111111111111111111111111111"
chain_id = 1
nonce = 42

[[backup_remotes]]
host = "user@1.2.3.4"
folder = "hot_cheese_store"

[[adapters]]
id = "safe_treasury_bot"
manifest = "adapters/safe_treasury_bot.toml"
sha256 = "1d13b720834fa111c19f60f53c7951776aab556937f7a8e29cf6cd86ce48110b"

[[bundle_peers]]
host = "macbook.tail1a2b.ts.net"

[[token]]
address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
chain_id = 1
symbol = "USDC"
decimals = 6
standard = "erc20"

[[label]]
address = "0x2222222222222222222222222222222222222222"
chain_id = 1
name = "Vendor payouts"
```

| Field | Meaning |
| --- | --- |
| `service`, `account` | **Legacy** Keychain identifiers, used **only** by `migrate` to read the old master. Ignored by the envelope path. |
| `store` | Directory holding the encrypted keystores + `keyring.json` (`~/` is expanded). |
| `port` | HTTPS listen port for both the console and `serve`, and the reverse-tunnel remote port (optional; defaults to `5555`; `0` is refused). |
| `grant_public_key` | Uncompressed SEC1 hex (65 bytes, `04`-prefixed) of the Secure Enclave grant key, written by `enroll grant`. **Required to sign**: every signature verifies its grant against this key, and `serve` refuses to start without it (`GrantKeyMissingRunEnrollGrant`) or when the on-disk grant key exports something else (`GrantKeyPinMismatch`). The *pin* is an identity check against a swapped or restored blob — **not** a defence against someone who can write the home dir. |
| `backup_remotes` | List of `{ host, folder }` git remotes reached over `ssh`. `folder` is relative to the remote home dir unless absolute, and several installs may share one — each pushes to its own bare repository at `<folder>/<vault_id>.git` (see [Backups](#backups)). The host needs `git`. `host` is `[user@]hostname`, optionally followed by the exact suffix ` -i <identity-file>` (for example, `nixos@tprime2 -i ~/.ssh/copium2`); both pieces accept only a single safe word, and no other SSH option is accepted. A bare IPv6 literal or embedded `:port` is refused at load. **The hostname must be directly reachable, not a `~/.ssh/config` alias** — backup SSH passes `-F /dev/null`, so settings from that file are ignored. See [SSH options](#ssh-options-what-is-pinned-and-what-that-breaks). |
| `adapters` | List of `{ id, manifest, sha256 }` trusted signing adapters. `manifest` resolves under the home dir when relative; `sha256` is the pin the file's bytes must hash to *before* they are parsed. `serve` refuses to start on a mismatch, or when a manifest claims more than the key's policy grants. See [Signing Adapters](#signing-adapters). |
| `bundle_peers` | List of `{ host, dir }` machines to exchange **bundles** with, written by `bundle peer add`. `host` is a Tailscale MagicDNS name (optionally `user@`-prefixed); `dir` is optional and defaults to `.config/hot_cheese/bundles`, relative to the peer's home dir. A **separate key from `backup_remotes`, pointed at a separate directory, with no vault namespace** — the store never travels this path. See [Bundle sync](#transport-tailscale-discovery-rsync-over-ssh-outbound-only). |
| `bundle_watch_secs` | Seconds between ticks of the background bundle poller a session runs (optional; defaults to `30`, floored at `5`). The name is kept so an existing `config.toml` is not silently ignored. |
| `backup_fetch_secs` | Seconds a session waits between backup fetches (optional; defaults to `300`). `0` disables the timer, leaving pushes-after-mutation and the manual verbs; re-enabling it takes a restart. |
| `approval_timeout_secs` | Seconds one approval prompt waits for an answer before it denies itself (optional; defaults to `60`, accepted range `5`–`600`, refused at config load outside it as `InvalidApprovalTimeout`). A prompt additionally waits a random extra up to a third of this, drawn afresh for each one, so the caller told the instant its request was refused learns nothing about when the screen next changes. A caller waiting for a place in the approval line is told to come back after twice this. |
| `mcp.max_pending` | Unsigned bundles the MCP proposal server may leave waiting before it refuses to file another (optional; defaults to `16`). The queue is read by a human, so it is bounded by what a human will read. See [MCP](#mcp-an-agent-proposes-you-sign). |
| `mcp.keys` | Allow-list of keystore names the agent may propose against (optional). **Absent or empty is every key in the store**, which is what an install that never states this gets. |
| `mcp.safes` | Allow-list of Safe addresses the agent may propose against (optional). **Absent or empty is every Safe `bundles/safes.toml` describes.** |
| `mcp.nonce_window` | How far above the anchor a proposal's Safe nonce may sit (optional; defaults to `8`). Without it the agent picks the nonce with no upper bound, and one human approval becomes a cheque the agent can arrange to have executed at a nonce of its choosing. |
| `mcp.proposal_ttl_mins` | Minutes an **unsigned** proposal keeps counting toward `max_pending` and keeps holding its `(safe, chain, nonce)` slot (optional; defaults to `1440`, one day). |
| `mcp.proposals_per_hour` | Proposals one agent session may file per hour (optional; defaults to `16`). Charged on the **attempt**, so a rejected proposal still spends allowance and an agent cannot wedge the queue here and on every peer by retrying. |
| `mcp.lock_cooldown_ms` | Milliseconds a session must leave between tool calls that take the exclusive bundle lock (optional; defaults to `100`), so a busy agent cannot starve your own CLI of the lock. |
| `mcp.anchor` | List of `{ safe, chain_id, nonce }` **operator-declared** absolute nonce anchors, written as `[[mcp.anchor]]` **after** the scalar `[mcp]` keys. hot_cheese has no RPC client, so a Safe's real nonce is not knowable here: this is you stating the nonce you read on chain. Without an anchor for a Safe, `nonce_window` is measured from the local queue instead. |
| `token` | List of `{ address, chain_id, symbol, decimals, standard }` contracts the approval summary may also render **scaled**: `1.000000 USDC (1000000)` — always both forms, so a wrong `decimals` is bounded by the integer beside it. `address = "0x0…0"` annotates the chain's native `value`. `standard` is `erc20`, `erc721` or `erc1155`; a non-fungible standard must carry `decimals = 0`, because scaling a `tokenId` would render token #42 as `0.000042`. **An unlisted contract is not guessed at** — it renders the raw integer, exactly as it did before the table existed. |
| `label` | List of `{ address, chain_id, name }` names the approval summary may show **beside** an address: `0x2222… (Vendor payouts)`. The full EIP-55 address is always printed — a name never replaces one, and nothing is ever truncated, because two addresses sharing their leading digits are trivial to grind. `name` is refused at load if it is empty, longer than 32 chars, holds anything but printable ASCII and spaces, holds a parenthesis, or starts with `0x`; a second `token` or `label` for one `(address, chain_id)` is refused too, since it could never fire. |

There is **no compile-time config** anymore — nothing is `include_bytes!`'d into
the binary, so the store path, port, certs, and remotes can change without a
rebuild.

---

## Server Endpoints

All endpoints are served over pinned HTTPS on loopback. Every endpoint but `/health`
is a privileged operation: it is printed on the daemon's terminal and answered `y`
by the operator, and then prompts for **Touch ID** (when a Secure Enclave enrollment
is in use). The one exception is a `/read` carrying a read-grant token the operator
issued for that key — see [Read grants](#read-grants). A prompt that replaced one you never answered says so and is answerable
only by `y<number>` carrying that request's own number, so a keystroke you were
composing for the request that vanished can never approve the one that took its place.
Names must match `[A-Za-z0-9_]+`. A request the operator **refuses** answers
`403 FORBIDDEN`; one whose wait for a place in the approval line ran out answers
`503 SERVICE_UNAVAILABLE` with `Retry-After: 1`; every other failure is
`500 INTERNAL_SERVER_ERROR`.

| Endpoint | Method | Description |
| --- | --- | --- |
| `/health` | GET | Returns `ok` if the server is running. |
| `/read/<name>` | POST | Ephemeral P-256 Diffie-Hellman read: the body carries the client's ephemeral public key; the response is the secret encrypted so only that client can decrypt it. Works for both EVM and Solana keys. **Only for a `shareable` key** — see below. |
| `/sign/<name>` | POST | Sign a Safe transaction. The body is a JSON intent carrying the `execTransaction` **fields**, never a hash; the response is `{safe_tx_hash, signature, signer}`. Policy-checked and grant-gated — see below. |
| `/evm_generate/<name>` | POST | Generate a new secp256k1 key, **always `sign_only`**, then commit the store and push it in the background. |
| `/evm_address/<name>` | POST | Return the Ethereum address derived from `<name>`. |
| `/solana_generate/<name>` | POST | Generate a new Ed25519 keypair, **always `sign_only`**, then commit the store and push it in the background. |
| `/solana_address/<name>` | POST | Return the Solana pubkey of `<name>`. |

Every privileged POST requires `Content-Type: application/json`, including the body-less
generate/address routes. Besides making the wire format explicit, this prevents an HTML form
from issuing a cross-origin localhost request; the server exposes no CORS preflight response.

`/read` is the only endpoint that exports a key, and it serves **only** a key sealed
`shareable`. A `sign_only` (or still-`unsealed`) key answers `500` and the daemon logs
`Envelope(ExportRefused { key_use: SignOnly })` / `Envelope(NotSealed)`. That decision is
made from the file's cleartext header **before the approval prompt and before any unlock**, so
a refused export costs the owner **no approval and no biometric at all**. The generate endpoints always mint `sign_only`: a remote
caller can never create itself an exportable key. See [Key uses](#key-uses).

> TLS cert-pinning is **unchanged**, but the Diffie-Hellman transfer is **not**: the
> exchange is now bound to its own transcript and is no longer wire-compatible with
> df-share or with any pre-hardening client. An old client gets an AEAD failure, not a
> readable secret. Rebuild your key consumers against the current
> `hc_core::share` before upgrading the daemon. See
> [Client Integration](#client-integration).

The table above is the **loopback** surface. An adapter's own unix socket routes `/health` and
`/sign/<name>` and nothing else — `/read` and every generate/address route are not in its
table at all, so an adapter cannot reach them by construction, not by a check that could
regress. See [Signing Adapters](#signing-adapters).

### Read grants

An agent on another machine that restarts a service needs one key, repeatedly, and cannot
put a finger on your Mac. `hot_cheese read-grant allow <name> --hours 48` costs **one**
Touch ID and mints a random 256-bit token, rendered base58 and printed once:

- The token **is** the key material. An HKDF-SHA256 KEK derived from it seals that one key's
  plaintext into `<home>/read-grants/<name>` (file `0600`, directory `0700`). The token is
  written nowhere, so the file alone is inert and nothing can show the token a second time.
- The AAD binds a domain separator, the key name and the window, so a grant file moved to
  another name, or given a later expiry on disk, stops opening rather than covering more.
- Only an **export permit** mints one, which exists only for a key sealed `shareable`. A
  `sign_only` key is refused from its cleartext header before any unlock, so a wrong key
  costs no biometric.
- A grant holds a **copy**, so the daemon re-reads that keystore's cleartext header on every
  release — no DEK, no enclave, no prompt — and refuses unless the key is still there and
  still shareable. `seal --use sign-only` and deleting the keystore end a live grant; the
  refusal is the same `403` a junk token gets, so it is not a way to probe what the store
  holds. `read-grant list` marks such a grant **DEAD**.
- Grants live under the **home dir, never the store**: the store is a git repository that
  replicates to every backup remote, and a live credential must not reach a backup. Its path
  grammar (`keyring.json`, `<KEY>`, `policies/<KEY>.toml`) would refuse the directory anyway.

The agent presents it as `x-hot-cheese-read-grant: <token>` on `POST /read/<name>` — and on
no other route: a token offered on `/sign`, on `/health`, on an unknown path, or on an
adapter socket is `403` rather than ignored. `HOT_CHEESE_READ_GRANT` makes the reference
client in `crates/hc-daemon/examples/pin_cert.rs` send it for you.

At serve time the DEK is **never unwrapped and the enclave is never called**: the token's own
KEK opens the sealed key on the connection task, which never reaches the thread that owns
Touch ID. The answer still goes back through the same per-request ECDH layer, so the key is
sealed to that caller and nobody else. A wrong, expired or absent grant, and one whose key is
no longer shareable, all end in the same refusal — one `403`, one empty body, nothing to
distinguish and nothing to time — and it costs **no approval**, so junk tokens can never be
sprayed into prompts on your screen. Every token-authenticated release is logged at `warn` with
the key, the time and the caller's ephemeral-key fingerprint; the token itself is never logged
at any level. That line is deferred while an approval prompt is on your screen, like every
other line an unauthenticated peer can cause — a token holder must not be able to scroll the
request you are answering away — and the count, the window it covers and the rate it implies
are reported the moment the prompt is answered, so the record survives the deferral. An expired
grant is refused, and its file deleted unless the clock has moved further past the expiry than
the grant's whole window: a clock that jumped is a reason to refuse, not to destroy grants.

This is deliberately narrower than `serve --unlock passphrase`, which stays refused: no DEK is
cached, so the blast radius of a grant is exactly the one `shareable` key it names, for exactly
as long as it lasts, rather than every key for the daemon's lifetime.

### `/sign` and the per-payload grant

`/sign` never accepts a hash. The daemon parses the intent (an unknown field is a refusal,
not a silently dropped field), rebuilds `safeTxHash` itself from the submitted fields, loads
`<store>/policies/<name>.toml` **fresh for this signature**, and evaluates it. All of that
runs **before** anything prompts, so a refused request costs no biometric.

Only then does it ask the human. That single approval does two things:

1. it mints a **grant** — a Secure Enclave ECDSA signature over
   `"hotcheese/grant/v1" ‖ key ‖ rebuilt-hash ‖ policy-digest ‖ manifest-digest ‖ kind ‖
   nonce ‖ expiry ‖ 1` — using the *same* pre-evaluated `LAContext`, so **no second sheet**;
2. it unlocks the DEK through the enclave ECDH, reusing that same context.

The grant is verified host-side against `grant_public_key` from `config.toml` before it
becomes a `SignGrant`, and `HotApi::sign` takes that `SignGrant` **by value**. It is the type
that carries the digest to be signed, so the signing key is unreachable without a verified
grant and no signature other than the approved one can be produced. The grant is not `Clone`:
being moved in is what makes it single-use — there is no counter.

Because the policy digest is over the bytes read for *this* signature, editing the policy
between approval and signing changes what the grant covers.

**What this does not buy.** A grant is (a) hardware proof that a human approved this exact
intent under this exact policy, and (b) a compile-time-enforced precondition on signing. It
is **not** a cryptographic weld to DEK decryption: an attacker with code execution inside the
daemon *after* the DEK is unwrapped can still sign. Nothing is persisted either — no grant,
no signature, no audit trail — so a grant proves something only inside the call that made it.

A session unlocked by the **recovery passphrase** has no biometric to reuse (its unlocker
ignores one), so there the grant takes its own `LAContext` and you see exactly one extra
sheet. That is deliberate: an operator whose enclave *KEK* died can still sign. If biometrics
are unavailable entirely, the signature fails closed.

### Typed-only admission: the policy declares the shape

**The daemon signs only what it can fully deconstruct, and it deconstructs against a shape the
POLICY declared — never against a shape the request described about itself.** There is no
"unknown selector", no `UNDECODED CALL 0x…`, no hex blob for a human to eyeball. Anything that
cannot be read against a declared shape is a typed refusal, raised before any prompt.

A rule therefore names the **full canonical signature** and the daemon derives the four bytes
from it, and every declared argument carries its own bound:

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
    at = 0
    name = "to"
    rule = { one_of = { addresses = ["0x3333333333333333333333333333333333333333"] } }

    [[allow.call.arg]]
    at = 1
    name = "amount"
    rule = { max = { max = "1000000000", amount_of = "0x2222222222222222222222222222222222222222" } }
```

`signature` must be the **canonical** spelling — no argument names, no `function` keyword, no
`uint` alias, no `returns` clause — because the file's SHA-256 is what a grant is bound to and
one rule set must have one spelling. A non-canonical form is refused at load and the refusal
prints the text to write instead.

`at` is the argument's position and `name` is the label the human reads beside its value, so
the words on the approval sheet come from the operator who wrote the policy rather than from a
table that guessed which standard was meant.

**A field with no rule does not parse.** Every declared position must carry one, and the only
way to say "no bound" is to type it out:

| `rule` | Applies to | Means |
| --- | --- | --- |
| `{ one_of = { addresses = […] } }` | `address` | one of these addresses |
| `{ max = { max = "…", amount_of = "0x…" } }` | `uintN` | at most this, rendered scaled against `amount_of`'s `[[token]]` decimals |
| `{ eq = { eq = "…" } }` | `uintN` | exactly this |
| `{ bool_eq = { eq = true } }` | `bool` | exactly this — what tells an infinite `setApprovalForAll` from a revocation |
| `{ bytes_eq = { eq = "0x…" } }` | `bytes`, `bytesN` | exactly these bytes |
| `{ deadline = { within_secs = 1800 } }` | `uintN`, N ≥ 40 | a unix-seconds timestamp no further out than this |
| `{ enum = { one_of = […] } }` | `string` | one of these strings |
| `{ each = { max_len = 4, of = … } }` | `T[]`, `T[k]` | every element bounded by `of`, at most `max_len` of them |
| `"struct"` | a declared EIP-712 struct | bounded by its own `[[typed_data.types]]` block |
| `"batch"` | `multiSend`'s `bytes` | a packed batch; every entry is matched against the policy in its own right |
| `"unbounded"` | any type that does **not** reach a declared struct | **deliberately unbounded**, and every approval says so at the head of the sheet |

Rules are **externally tagged** so an unrecognised term inside one is a refusal to load rather
than a silently dropped field: `{ unbounded = { max = "100" } }` does not parse.

**`"unbounded"` is legal only on a scalar.** Applying it to a struct-typed field — or to an
array or tuple that reaches a declared struct — is a **parse-time refusal**
(`SchemaFieldTypeMismatch`), because only `"struct"` makes the walk descend into a struct's
own fields: one word would otherwise have silently disabled every rule beneath it while
reading as a single loose value. Use `"struct"` there and declare the fields.

`multiSend` is no longer a hole. Every entry of a batch is matched against the policy — its own
destination, its own operation, its own native value, its own declared signature and its own
argument bounds — so a batch whose entries the policy does not cover refuses the whole
transaction. A malformed packing, more than 32 entries in the tree, or a nest deeper than 2 are
all refusals now, not display limits.

### EIP-712 typed data

A `[[typed_data]]` block makes an off-chain message signable. The **policy** declares the
domain and the complete struct schema; a request names the schema and supplies field VALUES and
nothing else. It carries no `types`, no `primaryType` and no `domain` object — those are not
fields of the wire type at all, so a body that states one fails to parse at the boundary.

```toml
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
    name = "spender"
    type = "address"
    rule = { one_of = { addresses = ["0x4444444444444444444444444444444444444444"] } }

    [[typed_data.types.field]]
    name = "sigDeadline"
    type = "uint256"
    rule = { deadline = { within_secs = 1800 } }
```

A request is `{"kind":"typed_data","key":"…","schema":"permit2_usdc","chain_id":1,
"verifying_contract":"0x…","message":{…}}`. The echoed `chain_id` and `verifying_contract` must
equal the declared domain's or it is a refusal, never a re-domaining. The message's field set
must equal the declared set exactly — an extra key and a missing key are each their own
refusal — and a `bytesN` value that is not exactly N bytes is refused rather than silently
padded or truncated.

The message is coerced **once**, and that single value is both what is hashed and what is
rendered, so the digest signed is the digest read.

EIP-1271 Safe messages are one such declared schema (`SafeMessage(bytes message)` with a
`chainId`/`verifyingContract`-only domain), not special-cased code. There is **no multi-device
signature collection for typed data**: a bundle carries a Safe transaction by type, so a typed
message yields one signature from one device. That is useful on a 1-of-N Safe or for a contract
checking a single signer, and nothing more.

---

## Signing Adapters

An **adapter** is a separate OS process that turns a domain action ("pay this invoice") into
a **typed intent**. It never sees key material and it never supplies a digest — hot_cheese
re-derives `safeTxHash` from the fields, exactly as it does for a loopback client. hot_cheese
does **not** spawn, supervise or sandbox adapters; it only decides what an adapter that is
already running may ask for.

Each adapter gets:

| | |
| --- | --- |
| a **manifest** | `$HOT_CHEESE_HOME/adapters/<id>.toml`, pinned by SHA-256 in `config.toml` |
| a **socket** | `$HOT_CHEESE_HOME/adapters/<id>.sock`, mode `0600` in a `0700` directory |
| a **route table** | `/health` and `/sign/<KEY>`. That is the whole table |
| **provenance** | taken from the listener that accepted the connection, never from the request |

Adapters live in the **home dir, not the store**. The store is pushed to backup hosts and
replicated by `bootstrap-from`; adapter trust is per-machine local config and must not travel.
A bootstrapped machine therefore starts with **no adapters at all**, which is the correct
fail-closed default.

### The manifest

```toml
schema = "hotcheese.adapter/v1"
id = "safe_treasury_bot"

[[grants]]
key = "TREASURY"
intent_kinds = ["safe_tx"]
chain_ids = ["1"]
safes = ["0x1111111111111111111111111111111111111111"]

[[grants.calls]]
to = "0x2222222222222222222222222222222222222222"
max_value = "0"
operation = "call"

  [[grants.calls.call]]
  signature = "transfer(address,uint256)"

    [[grants.calls.call.arg]]
    at = 0
    name = "to"
    rule = { one_of = { addresses = ["0x3333333333333333333333333333333333333333"] } }

    [[grants.calls.call.arg]]
    at = 1
    name = "amount"
    rule = { max = { max = "1000000000", amount_of = "0x2222222222222222222222222222222222222222" } }
```

`[[grants.calls]]` is the **same rule language** `policies/<KEY>.toml` uses — the same
`AllowRule` type, not a second dialect. A rule declares the **full canonical signature** and
the daemon derives the 4-byte selector from it, so anything a manifest or a policy permits is
decodable by construction. Every struct in the schema is `deny_unknown_fields`, and
`FieldRule` is externally tagged for the same reason: a term the daemon does not implement is
a **refusal to load**, never a silently dropped field.

A grant may also name EIP-712 schemas:

```toml
[[grants]]
key = "TREASURY"
intent_kinds = ["safe_tx", "typed_data"]
typed_data = ["permit2_usdc"]
```

`intent_kinds` gates the shape and `typed_data` gates which of the policy's `[[typed_data]]`
blocks this adapter may name. Both are needed; the schema's contents are always the policy's.

Pin it in `config.toml`, and point `serve` at it:

```toml
[[adapters]]
id = "safe_treasury_bot"
manifest = "adapters/safe_treasury_bot.toml"
sha256 = "1d13b720834fa111c19f60f53c7951776aab556937f7a8e29cf6cd86ce48110b"
```

The load order is **read the bytes → SHA-256 → compare to the pin → *then* parse**. A file
that is not the one you approved is never parsed at all, and `serve` refuses to start
(`PinMismatch`). Get the hash with `shasum -a 256 <manifest>`.

### Composition with `policy.toml`: strict intersection

The per-key `<store>/policies/<KEY>.toml` is **unchanged, still mandatory, still fail-closed**.
A manifest can only ever **narrow** it, and only for requests carrying that adapter's
provenance. At `serve` startup, for every grant:

| Startup check | Refusal |
| --- | --- |
| `grants.safes` ⊆ `{policy.safe}` | `Widens { source: Safe { safe } }` |
| `grants.chain_ids` ⊆ `{policy.chain_id}` | `Widens { source: Chain { chain_id } }` |
| every `grants.calls` rule has a policy `allow` rule with the same `to` **and** `operation` | `Widens { source: Call { to, operation } }` |
| every grant `signature` appears verbatim in the policy rule, compared as **canonical text** | `Widens { source: Signature { to, signature } }` |
| every grant argument rule is no wider than the policy's at that position | `Widens { source: Arg { to, signature, at } }` |
| `grants.typed_data` ⊆ the policy's declared schema names | `Widens { source: Schema { schema } }` |
| policy rule's `max_value` ≥ the grant's | `Widens { source: MaxValue { to, max_value } }` |
| no `grants.calls` rule targets the Safe itself | `Widens { source: OwnerManagement { safe } }` |

The signature comparison is on the canonical **text**, not on the four bytes. Two different
signatures can be ground to share a selector, and a manifest is the lower-trust file: comparing
selectors would let it declare a *different* call under a permitted one.

Every refusal names the **adapter**, the **key** and the offending rule, and it stops the
daemon from starting. Refusing loudly beats silently intersecting: a manifest broader than
policy means the operator believes something policy does not grant, and hiding that until an
incident is precisely the failure mode this design exists to avoid.

Two things a manifest can **never** do:

- **grant owner/threshold rotation.** A `calls` rule naming the Safe itself is a startup
  refusal, and an intent whose `to` is the Safe is denied at request time
  (`OwnerManagementNotDelegable`) even if the policy permits rotation for the human.
- **widen refunds.** The schema has no refund term at all, so `deny_unknown_fields` turns an
  attempt to add one into a load failure. Gas-refund allowances stay human-and-policy-only.

At request time `policy::evaluate` runs **first**, then `manifest::evaluate` — **both** must
pass. No union, no override. Requests with no adapter provenance (the loopback client, the
CLI, the console) are evaluated against `policy.toml` alone, exactly as before.

### Transport and provenance

TCP loopback is open to every local uid; a `0600` socket is not, so each adapter gets its own
unix socket rather than a port. The wire is still HTTP — hyper serves a `UnixStream` and a TLS
stream through the same code path — but there is **no TLS**, because these bytes never leave
the kernel.

Provenance is unforgeable *because* it is one socket per adapter: the request body carries
**only** the intent (with `deny_unknown_fields`, sending an id or a manifest hash is a hard
parse failure), and the daemon derives "which adapter is this" from **which listener accepted
the connection**. A shared socket plus a handshake would be forgeable by anything that can
open the socket. That provenance is rendered into `OpContext::reason()`, so the **Touch ID
sheet and the approval line name which adapter asked**, and the adapter's manifest SHA-256
fills the grant's `manifest_digest` — binding the hardware approval to the exact adapter build
that requested it.

The peer credentials of a unix connection (`uid`, `gid`, `pid`) are recorded as a **log field
only**. They are *not* authentication: `ssh -R` can forward into a unix socket, and pids
recycle, so they narrow the caller to "a process running as this uid" and nothing more.

**Stale sockets.** On start, if the socket path exists, `serve` connects to it. A successful
connect means another daemon is live, so this one **refuses to start**; only `ECONNREFUSED`
proves the file outlived its process, and only then is it unlinked. Nothing is ever
blind-unlinked. A clean exit unlinks its own sockets.

Both front ends bind the adapter sockets: they are the same runtime with a different way of
asking the operator. Both bind the configured loopback `port` (default `5555`), and a reverse
tunnel publishes that same port number on the remote. At startup, either front end refuses if
an `ssh -R` left by an earlier process still points at the port.

A console session and a serving daemon therefore **cannot** run at the same time: the second
one refuses immediately with the store claim's typed error naming `<home>/.store.lock`, rather
than half-binding a set of adapter sockets. A passphrase-unlocked console binds nothing at all
— no listener and no adapter socket — because a session with no per-request biometric may not
answer a request either.

```bash
hot_cheese adapters
```

prints each adapter's id, manifest path, pinned hash, computed hash, socket path and the
policy-intersection verdict. It prompts nothing and unlocks nothing.

An adapter then signs by POSTing an intent to its own socket:

```bash
curl --unix-socket "$HOT_CHEESE_HOME/adapters/safe_treasury_bot.sock" \
     -H 'Content-Type: application/json' \
     --data @intent.json http://localhost/sign/TREASURY
```

That costs the owner one Touch ID, like every other sign.

### Running an adapter (operator-side)

hot_cheese ships **no supervision and no confinement code**: child-process management inside
the DEK-holding process is exactly the TCB growth that ruled out in-process plugins. Run
adapters as ordinary launchd jobs. A minimal
`~/Library/LaunchAgents/com.example.safe-treasury-bot.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>              <string>com.example.safe-treasury-bot</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/safe-treasury-bot</string>
  </array>
  <key>RunAtLoad</key>          <true/>
  <key>KeepAlive</key>          <true/>
  <key>ProcessType</key>        <string>Background</string>
  <key>StandardErrorPath</key>  <string>/usr/local/var/log/safe-treasury-bot.log</string>
</dict>
</plist>
```

If you want the adapter confined, wrap it in `sandbox-exec` with a profile that allows the
socket and little else:

```scheme
(version 1)
(deny default)
(import "/System/Library/Sandbox/Profiles/bsd.sb")
(allow file-read* (subpath "/usr/local/bin"))
(allow network-outbound (literal "/Users/you/.config/hot_cheese/adapters/safe_treasury_bot.sock"))
(allow file-read-metadata (subpath "/Users/you/.config/hot_cheese/adapters"))
```

`sandbox-exec` is **deprecated per its own man page** but still functional. Be clear about
what this buys: confinement limits what a compromised adapter can do to **its own** assets
(its config, its network, its files). It does **almost nothing** for hot_cheese, whose
exposure to that adapter is already bounded by *policy ∩ manifest ∩ a human biometric* — a
sandboxed adapter and an unsandboxed one can ask for exactly the same signatures.

---

## Safe Bundles: several devices, one transaction

A Gnosis Safe with a threshold of 2 needs two owner signatures over one `safeTxHash` before
`execTransaction` will run. Those signatures come from **different keys on different
machines** — a desktop and a MacBook holding deliberately separate signer keys, in separate
vaults, with separate blast radii, and later a phone as a third. `hot_cheese bundle` is how
one transaction collects them.

**The key daemon is not involved.** A bundle is the transaction's *fields* plus signatures
over a digest anyone can recompute. There is no secret in it, no new endpoint, no new
listener, and no change to what `serve` exposes. `bundle sign` reaches the key through
`HotApi::sign_typed` and `hc_sign::sign::prepare` — the same policy check, the same grant and
the same single Touch ID that `/sign/<name>` pays — and every other verb prompts nothing and
unlocks nothing.

### Layout

Bundles live under the home dir, **beside `adapters/` and outside the store**:

```
$HOT_CHEESE_HOME/bundles/
  safes.toml                   # never synced: it states what a Safe IS
  0x44ae…87b5/                 # the safeTxHash, recomputed and never trusted from a file
    unsigned.json              # the bundle as created, before any signature
    0xaaa…001.json             # desktop's signature
    0xbbb…002.json             # MacBook's signature
$HOT_CHEESE_HOME/bundle-quarantine/
  0x44ae…87b5/                 # what a peer pushed that failed verification, moved aside
```

The store is key material, and `backup push` replicates it per vault. The two Macs hold
different vaults **on purpose**, so a bundle must never ride that path — hence `bundles/`,
which no backup, no `bootstrap-from`, and no vault touches.

**One file per signer is the whole concurrency design.** Each file is a complete,
self-verifying bundle carrying exactly one device's signature, named for that device's signer
address. Two machines signing the same transaction at the same second write two
differently-named files. There is therefore no lock to take, no last-writer-wins, and no
conflict to resolve: whoever reads takes the **union in memory**. The union re-derives the
digest from both sets of fields and refuses anything that belongs to another transaction, so
a file dropped into the wrong directory fails loudly instead of being absorbed.

### `safes.toml`

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

| Field | Meaning |
| --- | --- |
| `address` | The Safe contract. |
| `chain_id` | Chain it is deployed on; `(address, chain_id)` is the lookup key. |
| `threshold` | Owner signatures `execTransaction` requires. Recorded into the bundle at `new`. |
| `owners` | Local mirror of the Safe's on-chain owner list. |

A term this build does not implement fails to load — `quorum = 2` is a parse error, not a
silently dropped line.

This is **not** `policy.toml`. The policy is the signing ceiling for a key and stays minimal;
`safes.toml` states what a Safe *is*. They are never merged, and neither one can widen the
other.

**`owners` is a mirror, and mirrors go stale.** hot_cheese has no RPC client, so it cannot
learn that an owner was rotated out last week. A stale list means `bundle status` reports the
wrong people as missing and `bundle export` hands you a blob that **reverts on-chain**. That
is a loud, cheap failure — one reverted call, no funds moved — and it is deliberately
preferred to a mirror that quietly refreshes itself from a network hop.

Retirement is manual for the same reason: nothing here can read the Safe's nonce, so `list`
and `status` surface **age** and **rivals** and let you decide. A `RIVAL` line means two
different digests are competing for one `(Safe, chain, nonce)`: they are mutually exclusive,
whichever lands first burns the other, and signing both is signing against yourself.

### Flow

```bash
# once per machine pair: enroll the other Mac off the tailnet
hot_cheese bundle peer add macbook

# desktop: describe the Safe once, then start the bundle
hot_cheese bundle new --file intent.json      # prints the safeTxHash; pushes it to macbook
hot_cheese bundle sign 0x44ae…87b5 --key DESKTOP_SIGNER   # one Touch ID; pushes the signature

# MacBook — nothing was copied by hand:
hot_cheese bundle sign 0x44ae…87b5 --key LAPTOP_SIGNER    # pulls, one Touch ID, pushes
hot_cheese bundle status 0x44ae…87b5          # pulls first: 2/2, nobody missing, no rivals
hot_cheese bundle export 0x44ae…87b5          # the execTransaction fields + packed signatures
```

`--key` names each machine's **local** keystore. The keystore name is not part of the EIP-712
encoding, so rebinding it changes nothing a signature commits to: the digest, and therefore
the directory, is identical on both machines.

`export` refuses below the threshold and refuses a signer `safes.toml` does not list as an
owner — the last cheap moment before gas is spent. **hot_cheese never broadcasts.** It has no
RPC client and will not grow one; the JSON goes to whatever you already send transactions
with.

A phone signs via `bundle qr` (the fields on screen, no digest — a claimed hash would ask a
human to compare 64 hex characters, which humans do not do) and comes back through
`bundle add-sig`, which checks the response's `safe_tx_hash` against the digest **we** rebuilt
from **our** fields, ecrecovers the signature, and requires the recovered address to equal the
claimed signer. Four mechanical checks; a typo fails instead of being accepted.

### Transport: Tailscale discovery, rsync over ssh, outbound only

Enroll the other machine **once**, and every verb after that syncs by itself:

```bash
hot_cheese bundle peer list          # every machine on the tailnet, online flag, enrolled flag
hot_cheese bundle peer add macbook   # checks it answers and has a bundles dir, then writes config.toml
```

`peer add` takes whatever you call the machine — its hostname, its short MagicDNS label, or the
fully-qualified name, optionally `user@`-prefixed when the account differs. What is **stored** is
always the fully-qualified MagicDNS name, so nothing needs maintaining when the tailnet
re-addresses. It refuses, by name, a machine the tailnet does not know, one that is offline, one
whose name is ambiguous, one with no MagicDNS name, one ssh cannot reach (`PeerUnreachable` — run
`ssh <host> true` once by hand to accept the host key), and one with no bundles dir
(`PeerHasNoBundlesDir`).

**Discovery** shells out to `tailscale status --json` and reads three fields: MagicDNS name,
hostname, online. The binary is found on `$PATH` first, then at
`/Applications/Tailscale.app/Contents/MacOS/Tailscale`; if neither exists the error lists every
path it tried. A backend that is not `Running` is a refusal naming the state — `NeedsLogin`,
`Stopped`, `Starting`, `NeedsMachineAuth` — never an empty peer list, so "nobody is here" and
"you are logged out" cannot be confused.

**Which verb moves which way:**

| Direction | Verbs |
| --- | --- |
| Pull first | `status`, `export`, `list`, `sign` (so a machine that has never seen the bundle can still be asked to sign it) |
| Push after | `new`, `sign`, `merge`, `add-sig` |
| Both, on demand | `sync` |
| Never | `rm` (a pull would resurrect it), `qr` |

Every verb that names a hash syncs **only that directory**; `list` and `sync` move the whole
tree. `--no-sync` suppresses it anywhere on the line.

**Enrolment has to be mutual.** A session pulls from every peer and pushes back **only** the
bundles this device itself wrote into — it is deliberately not a relay, so nothing a peer sent us
is ever redistributed unattended. Signatures converge because every machine pulls from every
machine, which means a one-sided `peer add` is a one-way street: A's signatures reach B, B's never
reach A. Run `bundle peer add` on **both** machines. `bundle peer list` shows each side's own
enrolment; nothing can check the other side's without asking it, and asking is a wire protocol
this design does not have.

Sync is **best-effort and non-fatal**: an asleep laptop produces a warning and the command
succeeds. `bundle sign` on the desktop cannot be broken by the MacBook being shut. ssh runs with
`BatchMode=yes` and a 5-second connect timeout, so nothing ever stops to ask for a password
behind a biometric prompt.

The transport itself:

```
# push          rsync -az --exclude=safes.toml --exclude=*.hctmp \
#                     -e "ssh -o BatchMode=yes -o ConnectTimeout=5" \
#                     ~/.config/hot_cheese/bundles/          macbook…:~/.config/hot_cheese/bundles/
# pull          rsync -az --exclude=safes.toml --exclude=*.hctmp --max-size=65536 \
#                     -e "ssh -o BatchMode=yes -o ConnectTimeout=5" \
#                     macbook…:~/.config/hot_cheese/bundles/  ~/.config/hot_cheese/bundles/
# one bundle    …the source becomes …/bundles/<hash> with NO trailing slash, so rsync copies the
#                directory itself and a bundle the peer does not have creates nothing at all.
```

**There is no `--delete`, in either direction, ever.** That is not an oversight, it is the design:
one file per signer means `rsync` without `--delete` *is* the union merge, so both machines
converge with no lock, no last-writer-wins and nothing to resolve. Deletion would turn that into
a race — a peer that pulled before we pushed would take our signatures away again — which is also
why `bundle rm` is local-only.

`safes.toml` is **excluded in both directions**. It states what a Safe *is* — its threshold and its
owners — and a peer that could rewrite it could lower a threshold or plant an owner. That is the
only way bytes on this channel could ever matter, and it is closed.

**Nothing listens.** No port opens, no daemon is involved, no child outlives the command; the
process starts `rsync`, waits, and returns. `[[bundle_peers]]` is a **separate config key from
`[[backup_remotes]]`, pointed at a separate directory, with no vault namespace** — the encrypted
store never travels this path, because the two Macs hold deliberately different DEKs.

Be precise about what Tailscale is here: **a network path, not an authentication mechanism.**
It grants no authority, because **nothing listens**. There is no bundle endpoint, no bundle
port, and no process waiting for a bundle to arrive; a file lands on a disk and a command reads
it later. Being on the tailnet buys an attacker the ability to put bytes in a directory, and
nothing else — no key access, no signature, no approval.

### Every ingested bundle is verified locally

Because the channel grants nothing, it is also trusted with nothing. A peer — or anyone who has
taken one — can write arbitrary bytes into `bundles/`. None of it can forge a signature: every
signature is checked against a digest **we** rebuild from **our** fields. But one unparseable file
would make the whole directory refuse to load, which turns a write primitive into a denial of
service against a transaction that is otherwise fine.

So **every pull is followed by a validation pass** before anything reads what arrived. Each file
in each `<safeTxHash>/` directory must:

1. be named `unsigned.json` or `0x<signer>.json` — anything else is `Name`;
2. be at most **64 KiB** — bigger is `Size`, and the pull's `--max-size=65536` means it was never
   written in the first place;
3. parse as a bundle — `Parse`;
4. hash, from its own fields, to the **directory it sits in** — `Digest`;
5. ecrecover every signature to the address that signature claims, with no two contradicting
   signatures from one signer — `Signature`;
6. carry **only** the signer its filename names, and none at all in `unsigned.json` — `Misfiled`;
7. carry **at most one** signature, which is all any writer here produces — `Stuffed`. This is
   checked *before* the ecrecover loop, so one file cannot cost 300 recoveries by repeating a
   valid signature.

A file that fails is **moved**, never deleted, to `$HOT_CHEESE_HOME/bundle-quarantine/<hash>/`,
which is outside `bundles/` so nothing quarantined is ever synced back out. Every rule above is
one this machine's own writes satisfy by construction, so **quarantine can never eat your own
signature** on any of them.

The caps then bound the work. A pass **judges** at most **4160** files — the ones whose local
identity (inode, ctime, length) moved since the last pass, so an unchanged file costs an `open`
and an `fstat` and nothing else — and leaves the rest to the next pass rather than never judging
them. A directory holding more than **65** files (one seed plus the 64 owner signatures a Safe
can carry) keeps 65 (`unsigned.json` first, then what has already been judged, then name order)
and the overflow is **moved to quarantine, not deleted**: this is the one rule that can catch a
valid local signature no pass has judged yet, which is exactly why it is reversible. A **65th
bundle directory that arrives** is removed whole; one that was already here, or one this device
wrote into, never is.

**Arrival slots are shared per peer, durably.** One peer holds at most **16** of the 64
directory slots (`MAX_DIRS_PER_PEER`). A slot is spent when *that peer's* pull delivers a new
directory and freed only when that directory leaves this machine — it is a **share, not a
per-pass allowance**, so a flooding peer gains nothing by waiting for the next pass, and one
peer can never crowd the others out of the tree. Everything past the share is refused, which is
also the only thing the poller's flood backoff can see. **The honest limit:** the map from
directory to delivering peer is in memory only (an index on disk would sit in the tree peers
write to, where a peer could mark its own arrivals as somebody else's), so a daemon restart
re-grants every peer a fresh share.

**Slots also expire, so nothing needs reclaiming by hand.** A bundle nobody has signed keeps
its `(Safe, chain, nonce)` slot for **14 days** — a Safe executes each nonce once, so a dead
proposal would otherwise block every later transaction for that nonce. A directory holding
nothing but files for a Safe this machine's `safes.toml` does **not** describe keeps its slot
for only **1 hour**: nothing in it can become valid until you add that Safe, and the peer still
has it, so the pull after you do brings it straight back.

**The quarantine tree self-heals.** It stops at **1024** files, but a sweep drops evidence older
than **7 days** and evidence whose bundle directory is gone, and a sweep that has to make room
evicts **oldest-first** down to 768. It sweeps once at startup and thereafter no more often
than every 15 minutes, when a file is being quarantined. So a saturated install recovers on its
own and needs **no operator action**; only a rejected file arriving at a tree that is full of
evidence no sweep can yet reclaim is deleted instead of moved.

**A hostile peer can therefore waste bounded disk, and nothing else.** Bandwidth is not bounded:
nothing tells rsync "never fetch this path again", so a peer that re-sends what we quarantined
re-sends it every tick until the backoff engages.

**The security lives at the signer, not on the wire.** Every device independently:

1. re-derives `safeTxHash` from the fields in the file (nothing ever trusts a transmitted
   digest — bundles store fields and recompute, and the QR frame carries no hash at all),
2. runs that key's own `policy.toml`, fail-closed, **before** any prompt, and
3. shows the **decoded call** — `transfer(to=…, amount=…)`, `⚠ REFUND`, `⚠ OWNER ROTATION` —
   and takes a Touch ID over exactly that.

So a hostile channel cannot forge a signature, cannot replay one onto another transaction,
and cannot smuggle a payload past a policy. What it **can** do is put a **plausible intent**
in front of you — a transfer to an address that looks like your vendor's, a nonce that
collides with one you are already collecting — and hope you approve it. That is the real
residual risk of an automatic transport, and it is exactly why the decoded summary is
load-bearing rather than decorative: it is the only thing standing between a plausible intent
and your signature. Read the destination and the amount on the prompt, every time.

### Waiting on a co-signer

Nothing to run. `hot_cheese` and `hot_cheese serve` both carry a background poller on their own
thread: every `bundle_watch_secs` (30 by default) it pulls the whole tree from each enrolled peer
in turn, judges only the files that pull actually changed, and pushes back the bundles this device
wrote into. The console's bundle list shows what it last found — how many bundles are here, how
many have met their threshold, how many peers answered, how long ago, and what was quarantined —
and every bundle's own row still shows `met` when it is ready.

A peer is an untrusted writer, and a poller makes that continuous rather than occasional, so the
caps are enforced rather than reported: 64 KiB per file, 65 files per bundle directory (the
overflow is **moved to `bundle-quarantine`**, never deleted), 64 bundle directories of which any
one peer holds at most 16 — an arrival past either cap is removed, one that was already here is
never touched — 1024 files in the quarantine tree, one signature per per-signer file, and 4160
files judged per tick, with the rest left to the next tick. A peer that trips those is skipped
for a doubling number of ticks, up to 32, which self-clears; it stays enrolled, and the console
says why it went quiet.

With no session running there is no poller: `hot_cheese bundle sync` remains the scriptable
one-shot exchange, and `bundle list` / `bundle status` still pull for themselves.

---

## MCP: an agent proposes, you sign

`hot_cheese_mcp` is a second binary: a [Model Context Protocol](https://modelcontextprotocol.io)
server that lets a local coding agent **draft** Safe transactions into the review queue you
already have. You tell the agent *"pay that invoice in USDC"*; it reads the Safes, the policies
and the nonces already in flight, drafts the transfer, and files it as an unsigned bundle. Then
you look at it — with the decoded summary, the policy ceiling and the biometric all exactly where
they were before.

**It proposes and it cannot sign, and that is structural rather than a promise.** The crate does
not depend on `hc-daemon`, so the signing API is not merely unused there, it is *unnameable*:
Rust hands out no path to a crate that is not a dependency, and reaching for one is a compile
error rather than a code-review comment. `crates/hc-core/tests/boundary.rs` asserts that against
the real build graph, so it cannot be quietly re-added.

**And the surface is a transaction *shape*, not a transaction encoder.** Today that shape is
exactly one thing: an ERC-20 transfer out of a Safe. The agent never hands over calldata, a
destination, an operation, a native value or a gas-refund field — it hands over a token, a
recipient and an amount, and the server builds the rest.

### Wiring it up

```bash
./install.sh                       # installs hot_cheese AND hot_cheese_mcp
```

`.mcp.json`, in your project or your agent's global config:

```json
{
  "mcpServers": {
    "hot_cheese": {
      "type": "stdio",
      "command": "/Users/you/.cargo/bin/hot_cheese_mcp",
      "args": [],
      "env": { "HOT_CHEESE_HOME": "/Users/you/.config/hot_cheese" }
    }
  }
}
```

Transport is **stdio**: no port, no socket, no listener, and no HTTP client anywhere in the
crate. `HOT_CHEESE_HOME` is the only thing it needs from the environment — it points at the same
home dir the CLI uses, which is where `config.toml`, `bundles/safes.toml` and the policies live.
Logs go to **stderr**, because stdout is the protocol.

### Bounding the agent: the `[mcp]` table

The agent limits all live in `[mcp]` in the **one** `config.toml` — there is no separate
`mcp.toml`. Every key is optional and every default preserves what an install that never
states it already had, so upgrading changes nothing until you tighten something:

| Key | Default | What it bounds |
| --- | --- | --- |
| `keys` | *(empty — every key in the store)* | Which keystores the agent may propose against. Without it, **every** key in the store is proposable. |
| `safes` | *(empty — every Safe in `safes.toml`)* | Which Safes the agent may propose against. |
| `nonce_window` | `8` | How far above the anchor a proposal's Safe nonce may sit. Without an upper anchor the agent picks the nonce freely, and one approval becomes a cheque executable whenever the agent decides. |
| `proposal_ttl_mins` | `1440` | How long an **unsigned** proposal keeps counting toward `max_pending` and keeps holding its `(safe, chain, nonce)` slot. |
| `proposals_per_hour` | `16` | Proposals one agent session may file per hour, **charged on the attempt** — an agent cannot wedge the queue here and on every peer by retrying. |
| `lock_cooldown_ms` | `100` | Minimum gap between tool calls that take the exclusive bundle lock, so a busy agent cannot starve your own CLI. |
| `max_pending` | `16` | Unsigned bundles waiting before the server refuses to file another. |
| `[[mcp.anchor]]` | *(none)* | `{ safe, chain_id, nonce }` you read **on chain** and state here; it anchors that Safe's window absolutely. hot_cheese has no RPC client, so with no anchor the window is measured from the local queue instead. Write these tables **after** the scalar keys. |

Set `keys` and `safes` if the store holds anything the agent has no business touching, and
set an `[[mcp.anchor]]` per Safe if you want the nonce window to mean something absolute.

### What the agent can do

| Tool | Writes? | What it does |
| --- | --- | --- |
| `list_safes` | no | Every Safe from `bundles/safes.toml`: address, chain, threshold, owners. |
| `list_signing_keys` | no | Every key's **policy**: pinned Safe and chain, allowed destinations and the full canonical signatures permitted at each, value ceilings, owner-rotation flag, declared EIP-712 schema names, whether refunds are opted in. |
| `list_bundles` | no | Every proposal waiting, grouped by the `(Safe, chain, nonce)` slot it competes for, rival slots flagged. This is how the agent picks a free nonce. |
| `bundle_status` | no | One proposal in full, plus the decoded summary the approval prompt will show. |
| `preview_erc20_transfer` | **no** | The verdict without a write: `safeTxHash`, decoded summary, `allowed` or the exact typed refusal with its offending values, whether the Safe is known, whether the nonce is taken. |
| `propose_erc20_transfer` | yes | The only verb that writes. Files an **unsigned** bundle and pushes it to the co-signers. |

### The narrow schema

Both transaction tools take the same seven fields and **nothing else** — `deny_unknown_fields`
on the deserializer, `additionalProperties: false` in the published schema, and every field
required because none of them has a default. A field that is not one of these seven is a hard
`-32602`, never a term silently dropped on the way to a policy check:

| Field | Type | What it is |
| --- | --- | --- |
| `key` | string | Local keystore name, `[A-Za-z0-9_]+`. Its policy decides what may be signed. |
| `safe` | address | The Safe the tokens leave. Must be one `list_safes` returns. |
| `chain_id` | u256 | Decimal integer, or a decimal / `0x`-hex string. |
| `token` | address | The ERC-20 contract — which is also the address the Safe calls, so it is the destination the policy must allow-list. |
| `recipient` | address | Who receives the tokens. |
| `amount` | u256 | **Raw integer in the token's own base units.** |
| `nonce` | u256 | The Safe's own nonce, from `list_bundles`. |

`amount` is a base-unit integer because hot_cheese has no RPC client and so cannot read a token's
`decimals()` to scale for you: 1 USDC (6 decimals) is `1000000`, 1 DAI (18 decimals) is
`1000000000000000000`. The tool description says so, and the approval summary shows you the same
raw integer.

The server builds the calldata itself, encoding `transfer(address,uint256)` with **the same
alloy `sol!` declaration `adapter::summary` decodes against** — so what is proposed and what you
read on the approval prompt cannot disagree. Everything else in the Safe transaction is fixed in
the server, not supplied by the agent:

```text
to              = token
data            = transfer(recipient, amount)
value           = 0
operation       = CALL
safe_tx_gas     = 0        base_gas        = 0        gas_price = 0
gas_token       = 0x0      refund_receiver = 0x0
```

So these are not "denied", they are **inexpressible** — there is no field to put them in:

- **Arbitrary calldata.** The agent supplies a recipient and an amount, never bytes.
- **`delegatecall`.** The operation is always a plain `CALL`.
- **Any owner or threshold change.** `swapOwner`, `addOwnerWithThreshold`, `removeOwner`,
  `changeThreshold` are calls against the Safe with calldata the agent cannot write.
- **Any gas refund.** All five refund fields are zero, so the `execTransaction` drain that runs
  independently of `to`/`value`/`data` has no reachable input.
- **Any native-value transfer.** `value` is zero; an ERC-20 transfer moves no ETH.

Policy still runs on top of all of that. This is defence in depth *beneath* the policy check, not
a replacement for it: if a policy ever has a gap, the agent no longer has a way to describe the
exotic transaction that would walk through it.

**The library stays general.** `SafeTxIntent`, `hc_bundle::new`, `hc_sign::sign::prepare` and the
whole CLI and console path are unchanged and still carry any Safe transaction the policy
declares a shape for — a delegatecall included. Only the *MCP surface* is narrow. What bounds
every path equally is [typed-only admission](#typed-only-admission-the-policy-declares-the-shape):
the daemon signs nothing it cannot deconstruct against a declared signature.

**Extending it:** a new supported transaction shape gets its **own tool** with its own
constrained arguments — `propose_erc20_approve`, say, or `propose_safe_owner_swap`. Never widen
one of these tools, and never add a generic "advanced" escape hatch: an escape hatch puts the
whole general encoder back and makes every line above untrue.

`propose_erc20_transfer` runs, in this order and **all of it before any write**:

1. **Unknown Safe** → refused. `safes.toml` is the only local statement of what a Safe *is*.
2. **Rival guard** → if a bundle already occupies that `(Safe, chain, nonce)`, refused, naming
   the digest that holds it. A Safe executes each nonce exactly once, so this is the agent's
   most likely mistake and the one that would quietly waste your signature.
3. **Pending cap** → refused once `bundles/` holds `[mcp] max_pending` directories. The queue is
   read by a human, so it is bounded by what a human will read.
4. **Dry run** → the signer's own `prepare`: the same policy check, on the same code path,
   producing the same typed denial. Its approval token is dropped on the spot; this crate has no
   way to spend one.

Only if all four pass is the bundle written. **A denied proposal is refused, not stored** — a
stored denial would be a permanently unsignable row filling the very queue the dry run exists to
protect. A refusal comes back as a *tool result* with `isError: true`, not a JSON-RPC error, so
the client feeds it back to the model and the agent corrects itself instead of aborting.

Then you sign it, exactly as you would any other bundle:

```bash
hot_cheese bundle list                      # the agent's proposal is just another row
hot_cheese bundle status 0x44ae…87b5        # read the decoded summary
hot_cheese bundle sign 0x44ae…87b5 --key TRADER
```

### What the agent cannot do

Not "is not supposed to" — **cannot**, because the code is not linked, the type is not
constructible, the field does not exist on the tool, or the verb does not exist in the crate:

- **Describe any transaction but an ERC-20 transfer.** No calldata field, no `operation` field,
  no `value` field, no refund fields, no `to` field. See [the narrow schema](#the-narrow-schema).
- **Sign anything.** No `bundle sign`, no `collect`, no `merge`. The daemon is not a dependency.
- **Read or derive a key.** No `/read`, no key export, and deliberately **no key addresses in
  `list_signing_keys`** — deriving one decrypts a keystore and would prompt *you* for Touch ID,
  so an agent in a loop could spam a human. Owner addresses come from `list_safes`, a plain TOML
  read.
- **Change the rules.** No writes to any policy, to `safes.toml`, or to `config.toml`. No
  `peer add`/`peer rm`, no `enroll`, no `generate`, no `seal`, no `backup`.
- **Broadcast.** No `bundle export`: that yields the assembled `execTransaction` blob, and
  hot_cheese has no RPC client by design.
- **Retire a bundle**, discover tailnet machines, or render QR frames.
- **Call the chain.** There is no RPC client, which is why the agent must *supply* the nonce and
  why `list_bundles` exists.

### Threat model, honestly

A hostile or confused agent — prompt-injected, mistaken, or actively adversarial — gets exactly
one thing: **a row in your review queue, and that row is an ERC-20 transfer.** That is the entire
blast radius, and it is not zero:

- It can propose a transfer that is *within policy* but not what you wanted — the wrong
  recipient, or the right recipient and far too many base units. The policy bounds the token, the
  declared signature and whatever each argument rule says; it does not know your intent. A
  `one_of` on the recipient and a `max` on the amount are what turn "within policy" into
  something narrow, and an argument left `"unbounded"` puts the whole weight back on you.
  **The decoded summary on the approval prompt is the last thing that catches this**, which is
  why it renders the actual arguments under the names you gave them —
  `transfer(to=0x…, amount=…)` — leads with `⚠ UNBOUNDED FIELD` for anything the policy did not
  bound, and flags `⚠ UNLIMITED` and `⚠ HUGE` amounts in the first three lines. Read it, every
  time, and read the amount as base units.
- It can fill the queue up to `max_pending` (default 16), which is noise, not loss — and
  only at `proposals_per_hour` (default 16) per session, charged on the attempt, so it
  cannot wedge the queue here and on every peer by retrying. An unsigned proposal stops
  counting after `proposal_ttl_mins` (default 1440).
- It can claim a nonce, which the rival guard makes visible rather than silent — and only
  within `nonce_window` (default 8) above the anchor, so it cannot reserve a far-future
  slot. **Set `[[mcp.anchor]]` if you want that anchor to be the chain's real nonce**;
  without one the window is measured from your local queue, which the agent also writes to.
- It can propose against any key and any Safe, unless you narrow `mcp.keys` /
  `mcp.safes`. Both default to "everything", so this is the setting most installs should
  actually change.

What it cannot reach: the DEK, the keystore, the enclave, the grant key, and the biometric. Every
signature still costs one Touch ID over a payload *you* read. An agent that proposes a hundred
transactions still produces zero signatures on its own.

The rival guard reads the local queue **without syncing** (a sync shells out to `rsync` over
`ssh` with a five-second timeout per peer, and an agent may poll). A rival a co-signer started
and has not pushed yet is therefore invisible to it: it keeps your queue clean, it is not a
distributed lock. The write itself *does* push, because a proposal a co-signer cannot see is
half a proposal.

---

## Client Integration

Clients **pin the certificate** that `init` printed and verify its SHA-256
fingerprint out-of-band the first time. The reference client is
[`crates/hc-daemon/examples/pin_cert.rs`](./crates/hc-daemon/examples/pin_cert.rs) — copy `HotCheeseAgent` into your
own key consumers. It reads the pinned cert at runtime from the daemon's own home dir
(`$HOT_CHEESE_HOME`, else `~/.config/hot_cheese`), so it is per-machine, not compiled in:

```rust
// from crates/hc-daemon/examples/pin_cert.rs — the ONLY trusted root is that one certificate
let agent = HotCheeseAgent::new("https://localhost:5555")?;

let health = agent.health()?;                 // "ok"
let addr   = agent.address("TRADING_BOT")?;   // EVM address
let sol    = agent.solana_address("SOLANA_TRADER")?;
let secret = agent.read("TRADING_BOT")?;      // ephemeral DH read; needs a `shareable` key
```

Anything a client `read`s must have been created (or sealed) `shareable` — a `sign_only`
key answers `500` and no amount of client-side retrying changes that. See
[Key uses](#key-uses).

Run it as a live pinning check against a serving daemon (both arguments are optional):

```bash
cargo run --release -p hc-daemon --example pin_cert -- https://127.0.0.1:5555 TRADING_BOT
```

It prints `health=ok`, then performs **one** `/read` — which costs the owner one Touch ID —
and reports only `len=`, `digest=`, and `evm_address=`. The digest is salted per read and
truncated, so it is not a usable offline commitment to the secret. It never prints key
bytes and zeroizes the recovered secret.

Set `HOT_CHEESE_READ_GRANT` to a token from `hot_cheese read-grant allow <name>` and the same
client sends it as `x-hot-cheese-read-grant`, so the read costs the owner nothing at all until
the grant expires. That is the only path on which a `/read` does not prompt — see
[Read grants](#read-grants):

```bash
export HOT_CHEESE_READ_GRANT=<the token printed once by read-grant allow>
cargo run --release --example pin_cert -- https://localhost:5555 TRADING_BOT
```

Note that `curl --cacert` is **not** an equivalent test on macOS: the system curl uses the
SecureTransport backend, which treats `--cacert` as an *additional* anchor on top of the
system trust store. Use it for liveness (`/health`), and this client for pinning.

The Diffie-Hellman handshake and certificate pinning happen inside the agent, so
the private key is encrypted end-to-end for the calling process.

**The `/read` exchange changed, and it is not backward compatible.** The share layer now
binds the transcript: HKDF `info` is `"hotcheese/share/v1/hkdf" ‖ client_pub ‖ server_pub`
(both validated 65-byte uncompressed SEC1 points, in that order), and the AES-GCM
associated data is `"hotcheese/share" ‖ 0x00 ‖ key_name ‖ 0x00 ‖ 0x01` — a domain
separator, the **requested key name**, and the protocol version. A response obtained for
one key therefore cannot be replayed to a client that asked for another, and substituting
or swapping either public key yields a different key.

The cost is that this is **wire-incompatible in both directions** with df-share and with
any client built before the hardening: an old client decrypting a new response gets an AEAD
failure, and so does a new client against an old daemon. There is no negotiation and no
version fallback. Rebuild every key consumer against the current `hc_core::share` (copying
`HotCheeseAgent` from `pin_cert.rs` again is the simplest route) and roll the clients and
the daemon together.

---

## Backups

Because the store is an envelope (the DEK never appears on disk in plaintext), the
**key material** is confidential on untrusted remotes: a remote that reads everything it
holds cannot recover a private key. Only the **store dir** is synced; certs/keys under
the home dir are deliberately never replicated. That does not make the remote an
integrity authority either: fetched state is never applied automatically.

**What the remote does learn.** Only the secrets are ciphertext. `git log -p` on the
backup repository gives its holder:

- **every key name**, because a keystore's file name *is* the key name (`store/EVM_KEY`);
- **every signing policy in plaintext** — `store/policies/<name>.toml` is never encrypted,
  so the remote reads which Safes, which destinations, which canonical call signatures and
  which value ceilings each key is allowed;
- **`keyring.json` in plaintext apart from the wrapped DEK**: the vault id, each
  enrollment's id, its human label, its creation time, the Secure Enclave public points,
  and the Argon2 salt and costs of every passphrase enrollment;
- **a mutation timeline.** Every mutation is its own commit. The message is deliberately
  only `hot_cheese <vault> <unix secs>` and never names the operation, but the diff shows
  which file changed, so the remote reconstructs when each key was created, re-sealed or
  re-policied, and when enrollments were added.

Treat that as real metadata leakage: "which keys exist, what each is permitted to sign,
and when you last touched it" is a useful map for anyone deciding which of your machines
to attack. It is not a reason to skip backups; it is a reason not to put one on a host you
would not tell that to.

**The store is a git repository.** `<store>/.git` holds the history, the branch is
always `main`, and `<store>/.git/info/exclude` keeps a half-written `*.hctmp` out of
it. There is no `.gitignore` and there are no named remotes: `config.toml` is the
only place a backup target is written down.

Backups are automatic:

- **After every mutation** — `init`, `add`, `generate`, `seal`, `enroll`, `migrate`
  and the HTTP `/evm_generate` / `/solana_generate` endpoints commit the store. A
  failed **commit** is an error you see; a failed **push** is a warning the status
  carries. A mutation that changed nothing commits nothing.
- **Pushing** — a session coalesces commits and pushes in the background; a
  subcommand run with no daemon pushes before it returns. Every remote is attempted,
  and only *all* of them failing is an error.
- **Fetching** — a session fetches every `backup_fetch_secs` (default 300), validates
  the remote tree/keyring and reports ancestry, but never changes the active store.
  A fast-forward proves ancestry, not who authored the new commit.
- **Divergence** — when both sides have moved, nothing is merged, nothing is pushed
  and nothing is deleted. It is a reported state, and only
  `hot_cheese backup pull --force` resolves it.
- **On `serve`** — a missing `keyring.json` is a refusal. Restore it explicitly with
  `backup pull --force` before starting the daemon.
- **Manually** — `backup status`, `backup push`, `backup fetch`,
  `backup pull --force`.

Configure targets in `backup_remotes` (see [Configuration](#configuration)).

**A routine commit refuses to replicate a loss.** If staging finds that a committed store
file is gone, the commit fails with `CommitWouldDeleteStoreFiles { paths }`; if the staged
keyring no longer wraps an enrollment the committed one did, it fails with
`CommitWouldDropEnrollments { ids }`. That is the right default — the backup exists to
survive exactly that loss, and a deletion replicates as a clean fast-forward the remote can
never put back — but the refusal is permanent, and opening the store *is* a commit. One
store file legitimately going missing therefore takes `serve`, `generate` and the forced-pull
recovery down with it, for good.

`hot_cheese accept-deletions` is the way out, and the only one:

```bash
hot_cheese accept-deletions
```

It names every missing file and every dropped enrollment first, then requires the phrase back,
typed exactly:

```
record the loss of these hot_cheese files
```

Anything else is `ConfirmationRefused`. No flag carries the phrase: with no terminal the run
fails with `ConfirmationOnlyFromATerminal` and records nothing, which is what stops a script
or an agent from committing your loss for you
([details](#a-destructive-command-requires-a-terminal)). A store
with nothing gone answers `NoDeletionsToAccept` and writes nothing. The consent covers exactly
the loss it named: if the store loses something else while the question is open, the commit is
refused (`LossPreviewStale`) rather than recorded against an answer nobody gave.

**It is CLI-only.** The interactive console cannot recover a wedged store, because its runtime
calls `git.open()` at startup and that open is the commit which is already failing.
`accept-deletions` deliberately runs outside that path.

**It cannot recover a missing `keyring.json`.** If the keyring itself is the file that is gone
there is no vault to commit under, and the command fails with `LocalKeyringMissing { store }`.
That store is restored with `backup pull --force`, not with this.

`backup pull --force` is therefore an explicit integrity trust decision. Before it
touches the worktree, it rejects symlinks, gitlinks, unexpected paths, oversized
files, malformed keyrings and wrong vault ids; it then names every tracked file it
will change and every untracked file it will delete. It also refuses if the local
store changes between that preview and confirmation. It cannot cryptographically
prove that the backup host preserved the newest authentic commit.

**A rewinding pull needs a second, separate confirmation.** `--force` alone now buys only a
**purely additive** fast-forward. The pull classifies what it is about to do and, for any of
these four grounds, demands the phrase `roll this store back` typed back before it applies
anything (they are tested in this order, and the first one that matches is the one you are
shown):

| Classification | What the remote's tip is |
| --- | --- |
| `Fork` | **diverged**: both sides moved, so the incoming tip does not contain this machine's commits |
| `Backwards` | an **ancestor** of your local commit — older history, replayed over the newer |
| `Deletes` | a fast-forward that **drops store files** your local commit has |
| `Contents` | a fast-forward that deletes nothing and discards no commit, and **replaces** the content of security-relevant store files with older bytes |

No flag carries that phrase either: with no terminal the pull fails with
`ConfirmationOnlyFromATerminal` instead of applying
([details](#a-destructive-command-requires-a-terminal)). The
preview and the commit the confirmation refers to are pinned, so a background fetch between
the question and the answer cannot change what you agreed to.

**Why the extra gate.** A fast-forward proves ancestry and nothing else — not authorship,
not freshness. The backup host chooses which history it serves and the `remote_at`
timestamp is chosen freely by whoever wrote the commit. A hostile or rolled-back remote
could otherwise hand you an older, perfectly ancestor-consistent state and silently undo a
`seal`, restore a key you rotated away, or reinstate a policy you tightened — all inside
what a plain `--force` would have applied without comment.

**Why `Contents` is a separate ground.** The first three all describe a *loss* — a discarded
commit or a deleted path — and a hostile remote does not need any of them. It can commit a
**child of your own tip** whose tree keeps every path and merely reverts the bytes inside
them: ancestry then passes cleanly, nothing is deleted, no local commit is discarded, and
every affected path reports only as *modified*. The store grammar admits nothing but
security-relevant paths — the keyring, a policy, a keystore — so that alone revives a retired
keystore, restores an older `keyring.json`, or reinstates a looser policy. The console asks it
in exactly those terms:

```
OLDER CONTENT: nothing is deleted and no local commit is discarded — the incoming tip
REPLACES 2 security-relevant file(s) with older content — EVM_KEY, policies/EVM_KEY.toml.
Ancestry proves neither who wrote this history nor that it is current, so a hostile backup
host can serve exactly it: this can revive a retired keystore, restore an older keyring.json,
or reinstate a looser policy. Accept this rollback?
```

**History is forever, and now replicated.** Every version of every keystore stays in
the history on every remote; a key removed from the store is still recoverable from
any clone. Under the old rsync backup a deleted keystore also survived on the remote,
so this is not new — but it is now permanent and distributed, and
`receive.denyNonFastForwards` on the remote deliberately forbids rewriting it away.

**This upgrade is one-way per machine.** Rolling a machine back to a pre-git build
would rsync the whole `.git` into the old plain folder and then commit whatever rsync
landed. Nothing in either binary detects the mismatch.

### Vaults: several installs, one backup folder

Each install owns a **vault id** — a random 16-byte label rendered `v_<32 hex>`,
minted by `init`, stored **in cleartext** in `keyring.json`. It is a label, not a
secret: a push reads it without unlocking anything, so replication never prompts
for Touch ID or a passphrase.

Every install pushes to its **own bare repository**:

```
git push  <host>:<folder>/<vault_id>.git refs/heads/main:refs/heads/main   # push
git fetch <host>:<folder>/<vault_id>.git refs/heads/main                   # fetch
```

The repository is created on first contact with
`git init --bare`, its `HEAD` is pointed at `main` so a plain `git clone` of it
checks something out, and `receive.denyNonFastForwards` plus `receive.denyDeletes`
are set on it so no push from this code — or from a future bug in it — can rewrite
or delete the backup.

So a desktop and a laptop holding **different** multisig signer keys (different
DEKs, deliberately) can point at the same `host` + `folder` and never clobber each
other. `bootstrap-from` is the opposite case: B receives A's DEK, so it is the same
vault — A's vault id travels in the bootstrap `OFFER` frame and B records it, and
both machines replicate into the same subtree.

| Command | What it does |
| --- | --- |
| `backup status` | Print this install's vault, its local commit and every configured remote. No network, no write, no store claim. |
| `backup list` | List the vault ids sharing the first remote's folder, flagging which one is this install's. Prompts nothing, unlocks nothing. |
| `backup pull --force --vault <id>` | Take a named vault — disaster recovery onto a bare machine, where all you have is the recovery passphrase and the remote. |

**A pull only ever lands the vault you asked for.** A pull into a store whose
`keyring.json` names a *different* vault is refused before anything is fetched, and
the **remote's** `keyring.json` is then read straight out of the fetched objects and
checked before a single file in the worktree is touched. That is strictly stronger
than the old rsync guard, which could only re-check after it had already overwritten
the local keyring.

**`backup pull --force` is the one command here that can destroy key material.** It
resets the worktree to the remote's commit and cleans up after itself, so a keystore
generated on this machine and never pushed is **deleted**. It therefore names every
such file and its count first, and without `--force` it prints that list and does
nothing else. The discarded commits are still in the local reflog and object store
until git garbage-collects them.

Restoring a vault onto a bare machine therefore starts from an **empty store**. You
still need a `config.toml` naming the remote, and `init` writes one — along with a
throwaway DEK and vault id, which the restore must not inherit:

```bash
hot_cheese init                          # config.toml + TLS cert (and a throwaway vault)
$EDITOR ~/.config/hot_cheese/config.toml # add the [[backup_remotes]] entry
rm -rf ~/.config/hot_cheese/store        # drop the just-minted keyring: different vault
hot_cheese backup list                   # which vaults are on the remote?
hot_cheese backup pull --force --vault v_…  # then unlock with the recovery passphrase
```

Only run that `rm -rf` on a machine whose store holds nothing you need — here it
contains one keyring that encrypts nothing. Skip `init` entirely if you would rather
write `config.toml` and the cert by hand.

`serve`'s clone uses this install's vault id. On a machine with **no keyring at all**
it cannot know its id: it takes the remote's vault if there is exactly one, and
refuses when there are several, listing them so you can run
`backup pull --force --vault <id>`. It never guesses. The clone also refuses when the
store dir is not empty, naming what it found, rather than starting a second history
on top of files that are already there.

**A fresh `init` mints a new DEK *and* a new vault id.** It therefore lands *beside*
the previous backup — `<folder>/<new_id>.git` — instead of overwriting a vault whose
keys you may still need. The old repository stays exactly where it was; delete it
yourself once you are sure.

**Keyrings written before vault ids** get one **automatically**, the first time this
version opens the store. There is no un-namespaced git layout to keep, so there is
nothing to opt into and `backup adopt` is gone.

**An older rsync backup is left alone, not migrated.** The bare repository is
`<folder>/<vault_id>.git`, a different path from the old `<folder>/<vault_id>/`, so
the two sit side by side and the old directory becomes a stale last-known-good copy
the moment this version first pushes. Nothing deletes it and nothing reports its age;
delete it yourself once you are satisfied. While a fleet is **half** upgraded the two
paths mean the machines no longer see each other's keys — `backup list` flags a plain
`<vault_id>` directory beside our repository for exactly that reason.

**Two machines sharing one vault will diverge on first git contact.** `bootstrap-from`
gives B the same DEK and the same vault id, and under rsync both merged into one
subtree. Under git they start unrelated histories and the second push is refused as a
non-fast-forward. Resolve it once, by hand, with `backup pull --force` on whichever
machine's store is stale. Nothing auto-heals this, because the auto-heal would be the
silent overwrite the whole design refuses.

**Still never backed up:** the TLS cert/key (`ssl-cert.pem`, `ssl-key.pem`) and
`config.toml`. Only the store dir is replicated. Re-`init` or hand-copy those.

---

## SSH Bootstrap

Provision a brand-new machine **B** from an authority machine **A** over SSH:

```bash
# on the new machine B (which has its own Secure Enclave key):
hot_cheese bootstrap-from user@authority-host
```

`bootstrap-from` runs `hot_cheese bootstrap-serve` on the authority over SSH and
speaks a framed protocol over that pipe — no new network listener is opened. The
DEK is transferred with **ephemeral-static ECIES sealed to B's Secure Enclave
key**, so it **never crosses the wire in plaintext**:

1. **B** sends its SE public key.
2. **A** (which holds the DEK, and authorizes the transfer with a **live Touch
   ID on A**) generates an ephemeral P-256 keypair, derives a wrap key via
   `HKDF(ECDH(ephemeral, B_se_pub))`, and seals the DEK (AAD binds both
   endpoints).
3. **B** recomputes the shared secret inside its enclave (Touch ID on B), opens
   the sealed DEK, and **re-wraps it under B's own KEKs** — a fresh `keyring.json`
   enrolling B's Secure Enclave, and a recovery passphrase **only** if you passed
   `--recovery-passphrase`. A's keyring is never copied.

### Enrolling a recovery passphrase on B

```bash
hot_cheese bootstrap-from user@authority-host --recovery-passphrase
```

The passphrase is read from a **masked, confirmed prompt** when stdin is a terminal, and
from **stdin** otherwise. It is collected *before* the ritual opens, so a mistyped
confirmation costs nobody a Touch ID. The same ≥20-character / ≥8-distinct-character floors
apply as at `init`.

> **Upgrade note.** `HOT_CHEESE_BOOTSTRAP_PASSPHRASE` is **deleted**, with no fallback. It
> leaked the passphrase to any same-uid process through `ps eww`, into shell history, and
> into the ssh child's environment. If your provisioning script set it, `bootstrap-from`
> now **silently enrolls the Secure Enclave only** — B ends up with no recovery enrollment
> and no cross-machine restore path. Add the `--recovery-passphrase` flag, or run
> `hot_cheese enroll passphrase` on B afterwards; `hot_cheese list` warns while none is
> enrolled.

Channel authentication comes from SSH host keys, checked strictly:
`bootstrap-from` execs `/usr/bin/ssh` with `-F /dev/null`,
`StrictHostKeyChecking=yes`, `UserKnownHostsFile=~/.ssh/known_hosts` and
`BatchMode=yes`. That means **A's host key must already be in your `known_hosts`** —
first contact is refused rather than prompted, so put it there deliberately and verify
the fingerprint out-of-band. A MITM that fully impersonates A could serve a DEK of its
choosing, but cannot **learn** B's DEK, because confidentiality rests on B's enclave key,
not on the channel.

### SSH options: what is pinned, and what that breaks

Backup push/fetch/pull, the bootstrap pipe, and bundle peer sync use `/usr/bin/ssh` with a
pinned option list rather than whatever the environment supplies. A backup target may append
its one explicit identity file. The console's reverse-tunnel path is the exception: it reads
the normal user and system SSH configuration, so `Host` aliases work there.

| Path | `StrictHostKeyChecking` | Also always |
| --- | --- | --- |
| Backup transport (`backup push`/`fetch`/`pull`, `serve`'s clone) | `yes` | `-F /dev/null`, `UserKnownHostsFile=~/.ssh/known_hosts`, `BatchMode=yes`, `PermitLocalCommand=no`, `ForkAfterAuthentication=no`, `ControlMaster=no`, `ControlPath=none`, `ConnectionAttempts=1`, plus the target's optional `-i <identity-file>` |
| `bootstrap-from` | `yes` | the same fixed options, with no per-target identity, plus `ClearAllForwardings=yes`, and a cleared environment except `SSH_AUTH_SOCK` |
| Bundle peer sync (tailnet) | `accept-new` | the same fixed options, with no per-target identity; a **first** contact enrolls the key, a **changed** key is refused |

`-F /dev/null` is load-bearing on those three paths: without it a same-uid process that can
write `~/.ssh/config` attaches its own `ProxyCommand` to your backup connection. With it, the
host key is the only thing authenticating the far end, which is why the known-hosts file is
named explicitly too (`ssh` expands `~` from the passwd database, not `$HOME`).

> **This breaks `~/.ssh/config` aliases, and it will break real setups on upgrade.**
> `-F /dev/null` discards that file entirely, so a `Host` alias and everything under it —
> `HostName`, `Port`, `User`, `IdentityFile`, `IdentityAgent`, `ProxyJump` — is ignored.
> A `backup_remotes` entry or a `bundle_peers` entry written as an alias
> (`host = "backup"`) now fails to resolve. Rewrite it as a directly reachable
> `user@host`; a backup entry alone may use `user@host -i ~/.ssh/key`, while bundle peers
> still require an agent-held key. `SSH_AUTH_SOCK` is the one variable the bootstrap child
> keeps. Check with `hot_cheese backup fetch` before relying on it.
> A non-default port cannot be expressed in a `backup_remotes` `host` at all.

---

## Migration

Coming from the legacy Keychain-master daemon? The migrator decrypts each legacy
keystore with the old master, re-encrypts it under the new DEK into a staging
directory, and **verifies a decrypt round-trip + re-derived address before
committing anything** — the old store is never written, and any single failure
aborts the whole run.

```bash
hot_cheese migrate --old-store ~/HOT_CHEESE_MASTER --new-store ~/.config/hot_cheese/store \
  --shareable TRADING_BOT --shareable SOLANA_TRADER
```

`--shareable <NAME>` is repeatable and names a key that must keep working over `/read`.
**Every key you do not name is migrated `sign_only`, permanently** — a name that is not in
`--old-store` aborts the run before anything is written, so a typo cannot silently seal a
key your services still read. Read [Key uses](#key-uses) first.

This is a non-destructive, verify-before-finalize cutover with a dual-run and
rollback plan. **Do not** improvise it — follow the full runbook in
**[MIGRATION.md](./MIGRATION.md)**.

### Policy files written before typed-only admission

**Every policy file still carrying `selectors = [...]` refuses to load**, and nothing is
auto-converted: a 4-byte selector is a keccak image with no preimage, so a table-driven
conversion would silently fail to convert every selector not in the table and produce a policy
narrower than the file says. `AllowRule` is `deny_unknown_fields` and has no `selectors` field,
so `toml::from_str` fails with an unknown-key error naming `selectors` and its line and column,
inside `PolicyErr::Toml`.

That is fail-closed and it reaches startup: `serve` loads every policy named by an adapter
grant before it binds anything, so on a machine with a pinned adapter the daemon **refuses to
start** until every such policy is converted.
[MIGRATION.md §6c](./MIGRATION.md) carries the conversion table for the nineteen signatures the
old decoder knew, and `docs/plans/06-typed-admission.md` records why nothing is converted for
you. Any selector not in that table names a call this daemon could never decode; write its real
signature from the contract's ABI and it becomes both decodable and constrainable.

**Still not expressible: a bare ETH transfer from the Safe.** An `[[allow]]` rule has no way to
permit a call with no selector, and the policy layer refuses one (`NoSelector`) before any
prompt. That predates this change and is unchanged by it — widening the policy language under
cover of a change about narrowing is how mistakes ship.

---

## Security Model & Residual Risks

This section is deliberately blunt. These are real properties and real limits.

**What this protects against.** At-rest / stolen-disk / stolen-backup /
keychain-dump scenarios. There is no extractable master password: a stolen disk or
backup yields only ciphertext and a wrapped DEK that cannot be opened without a
Secure Enclave key (device-bound) or the recovery passphrase (offline).

**What it does *not* protect against.** A live attacker who already has **code
execution on the unlocked host**. Such an attacker can solicit reads at the Touch
ID bar exactly like a legitimate client — this is unchanged from the previous
version and is inherent to a local signing service. Worse, because the binary runs
without the hardened runtime (see below), such an attacker does not have to ask at all.

Specific residual risks:

- **The binary has no hardened runtime, so `DYLD_INSERT_LIBRARIES` works.** A plain
  `cargo build --release` is ad-hoc signed: no entitlements, no library validation, no
  dyld-injection restriction. A same-uid process can inject a dylib into `hot_cheese
  serve` and read the DEK out of the process that just unwrapped it, converting **one**
  approved Touch ID into unlimited silent use of **every** key. This is the price of
  "no code signing required", and it is a real one. Hardening it would mean a Developer
  ID certificate and `codesign --options runtime`, which this repo does not do.
- **The Touch ID gate's authority is `keyring.json`, and `keyring.json` carries no MAC.**
  A Secure Enclave key blob planted at the well-known path is no longer adopted on its
  own: it is taken as this machine's key only when its public point is **already
  recorded** — `se_pub` in a `keyring.json` enrollment for the KEK, `grant_public_key` in
  `config.toml` for the grant key — and an unrecorded blob is refused outright
  (`UnrecordedEnclaveKeyAtKeyPath`, which names the squatter's fingerprint next
  to every fingerprint this install records and recommends nothing, because whether the
  key at that path is a squatter or the previous keyring's is a question only the store's
  history answers — `enroll se` and `discard-enclave-key` look there). That
  closes the path where a same-uid process planted a
  **non-biometric** enclave key and the next enrollment adopted it as the KEK, after
  which the DEK unwrapped with no biometric at all. What remains: `keyring.json` is plain
  JSON with no integrity tag, so a same-uid attacker who plants **both** a non-biometric
  blob **and** a matching enrollment record can still wait for you to re-enrol into it.
  **What makes that visible is the enclave key fingerprint, and comparing it is your job.**
  `enroll se`, `enroll grant` and `list` all print it — `se_key` / `grant_key`, the first 8
  bytes of `SHA-256(SEC1 public key)` as 16 lowercase hex characters, 64 bits: short enough
  to write on paper, wide enough that an attacker cannot arrange a match. Enrolment says
  which of the two happened:

  - **MINTED** — this command created the key, so the trusted set changing is something you
    just caused.
  - **ADOPTED** — a key already on this disk was taken up. Benign when you are re-enrolling
    a machine you already enrolled; it is also **exactly what a planted blob plus a planted
    `keyring.json` record produces**. Nothing else can tell those apart.

  So record `se_key` and `grant_key` the first time you see them, keep them **off the
  machine**, and compare them at every later `enroll` and `list`. An ADOPTED line naming a
  fingerprint you did not record is an alarm, not drift — stop there. (`bootstrap-from` logs
  `recipient_key_sha256` in the same 16-hex form, and the authority's Touch ID sheet names it,
  so the same comparison works across a bootstrap.)

- **The recovery passphrase is as powerful as the Secure Enclave.** Anyone with
  it can unwrap the DEK on any machine. Store it **offline, like a seed phrase**.
  It is also the **only cross-machine restore path**: Secure Enclave keys are
  device-bound and are **invalidated if you re-enroll Touch ID**, so without a
  passphrase enrollment (or a still-enrolled second machine) a lost SE key means a
  lost store. `hot_cheese list` warns when no passphrase is enrolled. Reaching that
  enrollment is an explicit `--unlock passphrase` — the CLI never falls back silently,
  so a broken enclave is always visible.
- **`/read` authorization rests on TLS cert pinning + loopback binding + the
  per-request Touch ID + the key's own `shareable` declaration.** There is **no
  mutual-TLS / client auth** — any local process that pins the cert, combined with a
  present human approving Touch ID, can solicit a **shareable** key. Touch ID gives
  human-presence, not caller identity. Marking a key `sign_only` is what removes it from
  that exposure entirely, and is the reason `sign_only` is the default.
- **A [read grant](#read-grants) is a bearer token, and it replaces the human for its
  window.** Anyone holding one can pull that one `shareable` key over `/read` until it
  expires, with no biometric and nothing on your screen — that is what you asked for when
  you issued it. Its blast radius is bounded on purpose: one named key, one route, one
  expiry, no cached DEK, and no reach into `/sign` or any other key. What replaces the human
  is the audit trail, so read the `warn` lines naming the key, the time and the caller's
  ephemeral-key fingerprint — and the deferred-line report that stands in for them while you
  are at an approval prompt. Treat the token like the key itself: it is 256 bits of CSPRNG
  and there is no rate limit, so guessing it is not the threat — pasting it somewhere it
  outlives its purpose is. `read-grant revoke` ends one immediately, re-running
  `read-grant allow` rotates the token, which silently kills whatever was holding the old
  one, and `seal --use sign-only` (or deleting the keystore) ends it as the per-key kill
  switch, because every release re-reads that key's live header. This is deliberately narrower than `serve --unlock passphrase`, which stays refused:
  that would drop the biometric for **every** key for the daemon's whole lifetime.
- **No anti-rollback.** Keystore files bind AEAD AAD = domain ‖ key name ‖ use (a
  wrong-DEK, renamed, or re-flagged file won't decrypt), but **version/epoch
  anti-rollback is not implemented**. An attacker who can write **old ciphertexts (under
  the same DEK)** back into your store could roll a key back to a previous value — and,
  if it was `shareable` before you tightened it, back to a state whose header authorizes
  export. Unattended fetches cannot activate such a replay, and an incoming tip that
  replaces the content of store files is now classified `Contents` and needs the
  `roll this store back` phrase even though its ancestry is clean — but the phrase is a
  question put to you, not a proof, and an explicit forced pull still trusts the selected
  remote snapshot. Protect backup integrity and read the named REPLACED files before
  confirming a pull.
- **SE/ECDH equivalence is validated in software.** The host-side half of the
  Secure Enclave ECDH (that `ECDH(eph_priv, se_pub)` equals the enclave's
  `ECDH(se_priv, eph_pub)`) is covered by a non-ignored software test. The **full
  Touch ID round-trip must be confirmed once on a Mac with Secure Enclave hardware**
  by running `hot_cheese se-selftest` (the `#[ignore]`d
  `se_key_lifecycle_and_deterministic_ecdh` test in `crates/hc-core/src/mac/secure_enclave.rs`).
- **One biometric per payload needs hardware to prove.** That a single pre-evaluated
  `LAContext` covers both the enclave ECDH and an enclave grant signature — the property
  per-payload approvals rest on — cannot be checked without a Secure Enclave. It is the
  third leg of `se-selftest`, which fails loudly (`GrantReuseWindowExceeded`) rather than
  passing quietly if the two operations do not both land inside the Touch ID reuse window.
- **The `grant_public_key` pin is not a security boundary.** It catches a swapped or
  restored `se_grant_*.blob` at `serve` startup. Anyone who can write the home dir can
  rewrite the pin too.
- **A signing grant is not a weld to decryption.** It is hardware proof that a human
  approved this exact intent under this exact policy, plus a precondition the compiler
  enforces on the signing call — nothing more. The DEK is still unwrapped by the same
  process a moment later, so an attacker with code execution *inside the daemon* after that
  point can sign. What the grant removes is the class of bugs where a code path reaches the
  signing key without a human, or signs a payload other than the approved one.
- **Grants are not an audit trail.** Nothing about a grant is persisted — not the terms,
  not the enclave signature, not the fact that it was minted. It proves something only
  inside the call that made it, and it is gone when that call returns. If you need an
  after-the-fact record of what was approved, this does not give you one.
- **An adapter socket authenticates a uid, not an adapter.** The `0600` mode keeps other
  local users out; it does not distinguish your adapter from anything else you run, and
  `ssh -R` can forward into a unix socket exactly as it can into a loopback port. What the
  socket *does* establish is which manifest the request is evaluated against, because that
  comes from the listener and not from the request. The peer credentials in the log are
  descriptive, never a decision. See [Signing Adapters](#signing-adapters).
- **Sandboxing an adapter protects the adapter, not hot_cheese.** hot_cheese spawns nothing
  and confines nothing by design. A compromised adapter's reach into your keys is bounded by
  *policy ∩ manifest ∩ a human biometric* whether it is sandboxed or not; `sandbox-exec`
  limits what it can do to its **own** assets.
- **A pinned manifest is not a security boundary either.** Like `grant_public_key`, it
  catches a swapped file at `serve` startup. Anyone who can write the home dir can rewrite
  the manifest *and* its pin — but not the per-key policy in the store, which is checked
  independently and is the ceiling a manifest can only narrow.

---

## FAQ

**Why Touch ID?**
It is no longer just a UI gate — the Secure Enclave key is a cryptographic KEK.
*Unwrapping* the DEK requires a present, authorized human to complete the
Touch-ID-gated ECDH. No biometric, no unwrap. It bounds unwraps, not what the process
does with a DEK it already unwrapped: see the two residuals — dyld injection and the
unauthenticated `keyring.json` — under
[Security Model & Residual Risks](#security-model--residual-risks).

**What if I lose the master key?**
There is no master key. The DEK is wrapped under multiple independent KEKs: your
recovery passphrase and any Secure Enclave enrollments. As long as you have the
recovery passphrase (or a machine whose Secure Enclave you enrolled), you can
restore. Keep the passphrase offline and enroll more than one unlock method.

**What if I re-enroll Touch ID, or get a new Mac?**
Secure Enclave keys are device-bound and are invalidated when Touch ID is
re-enrolled — that SE enrollment stops working. The blob is still on disk, so the
failure is `SeKeyUnusableTryUnlockPassphrase` (or `SeKeyUnavailableTryUnlockPassphrase`
if the blob is gone too). Your keys are untouched. Recover with the **recovery
passphrase**:

```bash
rm ~/.config/hot_cheese/se_kek_hotcheese_se_kek_v1.blob   # only if the blob is stale
hot_cheese --unlock passphrase enroll se                  # re-bind a fresh enclave key
```

That `rm` is for **your own** stale key, the one whose fingerprint `list` shows. If the key at
that path is one this install never recorded — the failure says so, and prints its fingerprint
next to the recorded ones — do not `rm` it blind: `hot_cheese discard-enclave-key se` removes
exactly that case behind a typed phrase, and refuses a key this install records.

Any command takes `--unlock passphrase` in the meantime. To move to a new Mac, use
[`bootstrap-from`](#ssh-bootstrap) (which carries the vault id, so both machines keep
backing up to one subtree) or restore a backup into an empty store and unlock with the
passphrase — see [Backups](#backups) for the `backup list` / `--vault` recipe.

**Is it safe to back up the store to a remote / cloud?**
Yes. The store is envelope-encrypted and `keyring.json` holds the DEK only in
wrapped form, so a remote sees ciphertext only. That is the whole point of the
redesign — see [Backups](#backups).

**Can I use this on non-macOS systems?**
No. The Secure Enclave + Touch ID path is macOS-specific. The envelope/passphrase
crypto is portable in principle, but the daemon targets macOS.

**Do I need to set up signing before I can use it?**
No — not even for the Secure Enclave. The SE KEK uses CryptoKit and works from a plain
`cargo build --release` (the automatic ad-hoc signature); no identity, Team ID, or
entitlements are required to run it. Code signing (Developer ID + notarization) is only
needed to **distribute** the binary to other Macs. The one runtime requirement for the SE
is that the daemon run in your active GUI login session so Touch ID can prompt.

**How do I change the store directory, port, or cert?**
Edit `~/.config/hot_cheese/config.toml` (`store`, `port`, `backup_remotes`); no
rebuild needed. For the cert, re-run `init --import-cert/--import-key`, or
regenerate and re-pin clients to the new fingerprint. Saving it at your umask is fine:
the next command tightens it back to `0600` and carries on.

**Every command fails with `Config(ChownConfigToYourUser …)` or
`Config(ReplaceConfigWithARegularFile …)` — and `init` says `AlreadyInitialized`.**
`init` is right to refuse: your install exists, only its `config.toml` is unreadable. Neither
refusal is about the mode (a loose mode is tightened, not refused). Fix the path the refusal
names — `chown` it back to yourself, or replace a symlink/directory with the real file — and the
same command works. See [Configuration](#configuration).

**Can I import an existing key?**
Yes — `hot_cheese add <name> <ethereum|solana|bytes>` reads the secret from a
hidden prompt and stores it under the envelope. Add `--use shareable` if a service is
going to fetch it over `/read`; the default `sign-only` cannot be loosened later.

**My client's `/read` started returning 500 — what changed?**
The key is `sign_only` (or, on an old store, `unsealed`) and `/read` will never export it.
Check with `hot_cheese list`, which prints each key's use and prompts nothing. If the key is
`unsealed`, `hot_cheese seal <NAME> --use shareable` fixes it. If it is already `sign_only`,
that is permanent by design: generate a new `--use shareable` key and rotate the consumer.
See [Key uses](#key-uses).

---

**Hot Cheese** 🔥🧀 — handing out hot keys with the perfect blend of envelope
encryption, the Secure Enclave, and seamless local integration. Enjoy your
cryptographic fondue!
