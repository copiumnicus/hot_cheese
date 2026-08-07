# Hot Cheese 🔥🧀

**Hot Cheese** is a macOS HTTPS daemon that hands **EVM** and **Solana** signing
keys to local services when they restart. Keys live on disk as an **envelope**:
a random Data Encryption Key (DEK) encrypts each keystore, and the DEK is itself
wrapped under one or more **Key Encryption Keys (KEKs)** — a **Secure Enclave key
bound to Touch ID** and/or a **recovery passphrase**. There is **no extractable
master password** anymore.

Every key read is gated by a **cryptographic** Touch ID step (not a UI prompt you
could bypass), traffic is protected by **TLS certificate pinning**, and each
secret is delivered over a per-request **Diffie-Hellman key exchange** (via
[df-share](https://github.com/copiumnicus/df-share)) so only the calling client
can decrypt it. Because the DEK never touches disk in the clear, the store is
**safe to back up anywhere**, and a new machine can be **bootstrapped over SSH**
without the DEK ever crossing the wire in plaintext.

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
9. [Signing Adapters](#signing-adapters)
10. [Safe Bundles: several devices, one transaction](#safe-bundles-several-devices-one-transaction)
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
   ⇒ no decrypt. Per-request human approval is preserved.
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
6. **Safe-to-replicate backups** — best-effort `rsync` push after every mutation,
   auto-pull on `serve` when the local store is missing, and manual
   `backup push` / `backup pull`. The remote only ever sees ciphertext, and each
   install replicates into its own **vault** subtree, so machines holding different
   keys can share one backup host and folder.
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
   - **Passphrase KEK** = `Argon2id(passphrase, salt)`.
3. **Serving.** `hot_cheese serve` binds HTTPS on loopback, presents the pinned
   self-signed certificate, and answers the endpoints below. Secrets are returned
   through a df-share Diffie-Hellman exchange so only the requesting client can
   read them.
4. **Replication.** After any mutation the store is best-effort `rsync`-pushed to
   the configured remotes, into this install's vault subtree
   (`<folder>/<vault_id>/`); ciphertext only.

---

## Key uses

Every key declares at creation whether it may ever leave the daemon:

| Use | `/read` (export) | `/sign`, `address` | Reversible? |
| --- | --- | --- | --- |
| `shareable` | released to the client | yes | yes — `seal --use sign-only` tightens it |
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
- **`rsync`** and **`ssh`** on the host (for backups and the bootstrap ritual).
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
cargo install --force --locked --profile release --bin hot_cheese --path .
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
  enrollment,
- prints the certificate **SHA-256 fingerprint** — record it for client pinning.

Record the recovery passphrase **offline** (treat it like a seed phrase): it is
the only cross-machine restore path for the DEK.

To **reuse an existing certificate** (so clients pinning the old fingerprint
don't have to re-pin):

```bash
hot_cheese init --import-cert <cert.pem> --import-key <key.pem>
```

`init` refuses to run when it finds a prior install — `config.toml`, a
`store/keyring.json`, or any keystore file — and its error names what it found
(`ExistingStore { store, keyring, keystores }`). Pass `--force` to deliberately
reinitialize: that re-mints the DEK and **permanently orphans** any keystore
already written under the previous DEK. The generated `ssl-key.pem` is written
`0600`.

### 2. (Optional) Enroll the Secure Enclave

On a Mac with a Secure Enclave (no signing required), add a Touch-ID-bound unlock
method for the **same** DEK:

```bash
hot_cheese enroll se
```

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

Binds HTTPS on `127.0.0.1:<port>` (default **5555**). If the local store is empty
and a backup remote is configured, `serve` auto-pulls the store first — this
install's [vault](#vaults-several-installs-one-backup-folder), or the remote's only
vault when there is no local keyring to name one.

---

## CLI Reference

| Command | What it does |
| --- | --- |
| `init [--import-cert <pem> --import-key <pem>] [--force]` | Create home/store, write the TLS cert, mint the DEK, require a recovery passphrase, print the cert fingerprint. |
| `enroll se [--label <s>]` | Enroll this machine's Secure Enclave as a KEK for the same DEK. No code signing, and **no Touch ID prompt** — it needs only the enclave's public key. |
| `enroll passphrase [--label <s>]` | Enroll an additional recovery passphrase. |
| `enroll grant` | Create this machine's Secure Enclave **grant-signing** key and pin its public key in `config.toml`. Prompts nothing — no Touch ID, no passphrase. Required before `serve` or `sign`. Losing this key is benign; re-run to recover. |
| `add <name> <ethereum\|solana\|bytes> [--use <shareable\|sign-only>]` | Import an existing secret under `name` (read from a hidden prompt). Defaults to `sign-only`. |
| `generate <evm\|solana> <name> [--use <shareable\|sign-only>]` | Generate a fresh key under `name`. Defaults to `sign-only`. |
| `address <evm\|solana> <name>` | Print the public address / pubkey of a stored key. |
| `list` | List stored keystores (with each one's use) and keyring enrollments. Prompts nothing. |
| `adapters` | Show every trusted adapter: manifest path, pinned vs computed hash, socket path, and the policy-intersection verdict `serve` will act on. Prompts nothing, unlocks nothing. |
| `seal [<name>\|--all] [--use <shareable\|sign-only>]` | Bind a key's use into its envelope. Tightens only; `--all` binds just the still-unsealed keys. One unlock for the whole batch. |
| `sign [--file <json>]` | Sign a Safe transaction from a JSON intent (stdin by default). Policy-checked, grant-gated, one Touch ID. Needs `enroll grant`. |
| `bundle new [--file <json>]` | Start a bundle from a JSON intent; the threshold comes from `bundles/safes.toml`. Refuses a Safe that file does not describe. Prompts nothing. **Pushes.** |
| `bundle sign <hash> --key <name>` | Sign the bundle with a local key and file the signature under this device's signer address. The **only** bundle verb that prompts — same policy, same grant, same single Touch ID as `sign`. **Pulls, then pushes.** |
| `bundle status <hash>` | Merged view: signatures collected vs threshold, which owners are still missing, rivals, packed length, age. Prompts nothing. **Pulls.** |
| `bundle list` | Every bundle, grouped by the `(Safe, chain, nonce)` it competes for, with a loud `RIVAL` line when two digests share one slot. Prompts nothing. **Pulls the whole tree.** |
| `bundle merge <hash> [--file <path>]` | Union an external bundle file, a whole bundle directory, or one on stdin into the store. Prompts nothing. **Pushes.** |
| `bundle add-sig <hash> <--file <json>\|--stdin>` | Ingest another device's JSON sign response (a phone, say). Prompts nothing. **Pushes.** |
| `bundle export <hash>` | Print the `execTransaction` fields plus the packed signatures as JSON. hot_cheese never broadcasts. Prompts nothing. **Pulls.** |
| `bundle qr <hash>` | Render the transaction as a QR for another device's camera. Prompts nothing. |
| `bundle rm <hash>` | Retire a bundle on this machine. Deliberately never syncs. |
| `bundle sync [<hash>]` | Exchange with every enrolled peer, both directions, right now. Rarely needed — the verbs above already do it. |
| `bundle watch [<hash>]` | Foreground poll loop that reports signatures as they arrive; stops when a named bundle's threshold is met. Ctrl-C ends it. |
| `bundle peer list` | Every machine on the tailnet, with its MagicDNS name, whether it is online, and whether it is enrolled. |
| `bundle peer add <name>` | Enroll a tailnet machine, once, after checking it answers and has a bundles dir. Writes `[[bundle_peers]]`. |
| `bundle peer rm <name>` | Stop syncing with a machine. |
| `bundle … --no-sync` | Do the verb and touch no peer. Accepted on every bundle verb, anywhere in the line. |
| `serve` | Run the HTTPS daemon (auto-pulls the store from the first backup remote if absent). Refuses to start without an enrolled grant key matching the `config.toml` pin. |
| `backup push` | Push the store to every configured remote, under this install's vault id. |
| `backup pull [--vault <id>]` | Pull one vault from the first configured remote. Defaults to this install's own vault id. |
| `backup list` | List the vaults sharing the first remote's folder, flagging this install's. Prompts nothing. |
| `backup adopt` | Mint a vault id for a keyring written before vault ids existed. |
| `migrate --old-store <dir> --new-store <dir> [--shareable <name>]…` | Migrate legacy Keychain-master keystores into the envelope format. Everything not named `--shareable` lands `sign_only` (see [MIGRATION.md](./MIGRATION.md)). |
| `bootstrap-from <user@host>` | Bootstrap this machine's DEK + store from an authority machine over SSH. |

`--unlock <se|passphrase>` is global: it works before or after any subcommand and selects
which enrolled KEK unwraps the DEK. Omit it and nothing changes — the Secure Enclave is used
whenever an SE enrollment exists, otherwise you are prompted for a passphrase. Pass
`--unlock passphrase` to reach the recovery enrollment while an SE enrollment exists; that is
the escape hatch when this machine's enclave key is lost or was invalidated by a Touch ID
re-enrollment (the failure names it: `SeKeyUnavailableTryUnlockPassphrase`). There is no
silent fallback. `serve` refuses `--unlock passphrase`, because a daemon holding a passphrase
unlocker would answer every request from one startup prompt and lose the per-request human
approval — recover, `enroll se` again, then serve.

Logging defaults to `INFO`; override with `RUST_LOG=debug` (or `trace`/`warn`/`error`).

---

## Configuration

Config lives at **`$HOT_CHEESE_HOME/config.toml`**, defaulting to
**`~/.config/hot_cheese/config.toml`**. The TLS cert/key (`ssl-cert.pem` /
`ssl-key.pem`) live in that same home dir. `init` writes a sane default; you only
need to edit it to change the port or add backup remotes. A legacy
`config.json` is migrated to `config.toml` automatically on first load.

```toml
service = "com.cc.hot_cheese"
account = "hot_cheese_master"
store = "~/.config/hot_cheese/store"
port = 5555
grant_public_key = "04…"
bundle_watch_secs = 15

[[backup_remotes]]
host = "user@1.2.3.4"
folder = "hot_cheese_store"

[[adapters]]
id = "safe_treasury_bot"
manifest = "adapters/safe_treasury_bot.toml"
sha256 = "1d13b720834fa111c19f60f53c7951776aab556937f7a8e29cf6cd86ce48110b"

[[bundle_peers]]
host = "macbook.tail1a2b.ts.net"
```

| Field | Meaning |
| --- | --- |
| `service`, `account` | **Legacy** Keychain identifiers, used **only** by `migrate` to read the old master. Ignored by the envelope path. |
| `store` | Directory holding the encrypted keystores + `keyring.json` (`~/` is expanded). |
| `port` | HTTPS listen port (optional; defaults to `5555`). |
| `grant_public_key` | Uncompressed SEC1 hex (65 bytes, `04`-prefixed) of the Secure Enclave grant key, written by `enroll grant`. **Required to sign**: every signature verifies its grant against this key, and `serve` refuses to start without it (`GrantKeyMissingRunEnrollGrant`) or when the on-disk grant key exports something else (`GrantKeyPinMismatch`). The *pin* is an identity check against a swapped or restored blob — **not** a defence against someone who can write the home dir. |
| `backup_remotes` | List of `{ host, folder }` rsync targets. `folder` is relative to the remote home dir, and several installs may share one — each replicates into `<folder>/<vault_id>/` (see [Backups](#backups)). |
| `adapters` | List of `{ id, manifest, sha256 }` trusted signing adapters. `manifest` resolves under the home dir when relative; `sha256` is the pin the file's bytes must hash to *before* they are parsed. `serve` refuses to start on a mismatch, or when a manifest claims more than the key's policy grants. See [Signing Adapters](#signing-adapters). |
| `bundle_peers` | List of `{ host, dir }` machines to exchange **bundles** with, written by `bundle peer add`. `host` is a Tailscale MagicDNS name (optionally `user@`-prefixed); `dir` is optional and defaults to `.config/hot_cheese/bundles`, relative to the peer's home dir. A **separate key from `backup_remotes`, pointed at a separate directory, with no vault namespace** — the store never travels this path. See [Bundle sync](#transport-tailscale-discovery-rsync-over-ssh-outbound-only). |
| `bundle_watch_secs` | Seconds between polls in `bundle watch` (optional; defaults to `15`). |

There is **no compile-time config** anymore — nothing is `include_bytes!`'d into
the binary, so the store path, port, certs, and remotes can change without a
rebuild.

---

## Server Endpoints

All endpoints are served over pinned HTTPS on loopback. Every key access prompts
for **Touch ID** (when a Secure Enclave enrollment is in use). Names must match
`[A-Za-z0-9_]+`. On failure the server returns `500 INTERNAL_SERVER_ERROR`.

| Endpoint | Method | Description |
| --- | --- | --- |
| `/health` | GET | Returns `ok` if the server is running. |
| `/read/<name>` | GET (with body) | df-share Diffie-Hellman read: the body carries the client's ephemeral public key; the response is the secret encrypted so only that client can decrypt it. Works for both EVM and Solana keys. **Only for a `shareable` key** — see below. |
| `/sign/<name>` | GET (with body) | Sign a Safe transaction. The body is a JSON intent carrying the `execTransaction` **fields**, never a hash; the response is `{safe_tx_hash, signature, signer}`. Policy-checked and grant-gated — see below. |
| `/evm_generate/<name>` | GET | Generate a new secp256k1 key, **always `sign_only`**, then best-effort backup push. |
| `/evm_address/<name>` | GET | Return the Ethereum address derived from `<name>`. |
| `/solana_generate/<name>` | GET | Generate a new ed25519 keypair, **always `sign_only`**, then best-effort backup push. |
| `/solana_address/<name>` | GET | Return the Solana pubkey of `<name>`. |

`/read` is the only endpoint that exports a key, and it serves **only** a key sealed
`shareable`. A `sign_only` (or still-`unsealed`) key answers `500` and the daemon logs
`Envelope(ExportRefused { key_use: SignOnly })` / `Envelope(NotSealed)`. That decision is
made from the file's cleartext header **before any unlock**, so a refused export prompts the
owner for **no biometric at all**. The generate endpoints always mint `sign_only`: a remote
caller can never create itself an exportable key. See [Key uses](#key-uses).

> TLS cert-pinning and the df-share Diffie-Hellman transfer are **unchanged** — existing
> clients keep working as long as the pinned certificate is the same and the keys they read
> are `shareable`.

The table above is the **loopback** surface. An adapter's own unix socket routes `/health` and
`/sign/<name>` and nothing else — `/read` and every generate/address route are not in its
table at all, so an adapter cannot reach them by construction, not by a check that could
regress. See [Signing Adapters](#signing-adapters).

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

Adapters live in the **home dir, not the store**. The store is rsynced to backup hosts and
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
selectors = ["0xa9059cbb"]
max_value = "0"
operation = "call"
```

`[[grants.calls]]` is the **same rule language** `policies/<KEY>.toml` uses — the same
`AllowRule` type, not a second dialect. Every struct in the schema is
`deny_unknown_fields`: a term the daemon does not implement is a **refusal to load**, never a
silently dropped field. (That now holds for `[[allow]]` rules in a policy file too, since it
is the same type.)

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
| policy rule's `selectors` ⊇ the grant's | `Widens { source: Selector { to, selector } }` |
| policy rule's `max_value` ≥ the grant's | `Widens { source: MaxValue { to, max_value } }` |
| no `grants.calls` rule targets the Safe itself | `Widens { source: OwnerManagement { safe } }` |

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

Adapter sockets belong to **`hot_cheese serve`**. The interactive console binds a
kernel-chosen loopback port for the lifetime of its session and opens no adapter sockets, so
a console session and a serving daemon never contend for the same path.

```bash
hot_cheese adapters
```

prints each adapter's id, manifest path, pinned hash, computed hash, socket path and the
policy-intersection verdict. It prompts nothing and unlocks nothing.

An adapter then signs by POSTing an intent to its own socket:

```bash
curl --unix-socket "$HOT_CHEESE_HOME/adapters/safe_treasury_bot.sock" \
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
listener, and no change to what `serve` exposes. `bundle sign` reaches the key through the
same call `hot_cheese sign` does — one policy check, one grant, one Touch ID — and every
other verb prompts nothing and unlocks nothing.

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
| Pull first | `status`, `export`, `list`, `watch`, `sign` (so a machine that has never seen the bundle can still be asked to sign it) |
| Push after | `new`, `sign`, `merge`, `add-sig` |
| Both, on demand | `sync` |
| Never | `rm` (a pull would resurrect it), `qr` |

Every verb that names a hash syncs **only that directory**; `list`, `sync` and a bare `watch` move
the whole tree. `--no-sync` suppresses it anywhere on the line.

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
6. carry **only** the signer its filename names, and none at all in `unsigned.json` — `Misfiled`.

A file that fails is **moved**, never deleted, to `$HOT_CHEESE_HOME/bundle-quarantine/<hash>/`,
which is outside `bundles/` so nothing quarantined is ever synced back out. Every rule is one this
machine's own writes satisfy by construction, so **quarantine can never eat your own signature**,
whatever a peer floods the directory with.

Two caps bound the work rather than the correctness: a directory holding more than **64** files is
reported as `CROWDED` (nothing is moved — those signatures are individually valid, and `export`
already refuses a signer `safes.toml` does not list), and a pass stops after **4096** files and
says it stopped. A bundle directory that still will not load is skipped with a warning instead of
taking `bundle list` down with it.

**A hostile peer can therefore waste disk, and nothing else.**

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

```bash
hot_cheese bundle watch 0x44ae…87b5    # polls the peers, prints each signature as it lands
```

A **foreground** loop on `bundle_watch_secs` (15 by default). It pulls, validates, and reports
only what was not there at the previous poll; naming a hash makes it stop as soon as that
bundle's threshold is met. Ctrl-C ends it, and takes any `rsync` it happened to be running down
with it — nothing is backgrounded, nothing is spawned, nothing is left behind. Omit the hash to
watch the whole tree until you stop it.

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
let secret = agent.read("TRADING_BOT")?;      // df-share DH read; needs a `shareable` key
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

Note that `curl --cacert` is **not** an equivalent test on macOS: the system curl uses the
SecureTransport backend, which treats `--cacert` as an *additional* anchor on top of the
system trust store. Use it for liveness (`/health`), and this client for pinning.

The Diffie-Hellman handshake and certificate pinning happen inside the agent, so
the private key is encrypted end-to-end for the calling process.

---

## Backups

Because the store is an envelope (the DEK never appears on disk in plaintext), the
entire store directory is **safe to replicate to untrusted remotes** — the remote
only ever sees ciphertext and `keyring.json` (which holds the DEK only in wrapped
form). Only the **store dir** is synced; the certs/keys under the home dir are
deliberately never replicated.

Backups are automated:

- **After every mutation** — `add`, `generate`, `seal`, `migrate`, and the HTTP
  `/evm_generate` / `/solana_generate` endpoints trigger a best-effort `rsync`
  push to every configured remote. Failures are logged, not fatal.
- **On `serve`** — if the local store is absent, it is auto-pulled from the first
  configured remote before the daemon starts.
- **Manually** — `hot_cheese backup push` (all remotes) and
  `hot_cheese backup pull` (first remote).

Configure targets in `backup_remotes` (see [Configuration](#configuration)).

### Vaults: several installs, one backup folder

Each install owns a **vault id** — a random 16-byte label rendered `v_<32 hex>`,
minted by `init`, stored **in cleartext** in `keyring.json`. It is a label, not a
secret: a push reads it without unlocking anything, so replication never prompts
for Touch ID or a passphrase.

Every install replicates into its **own subtree**:

```
rsync -az <store>/ <host>:~/<folder>/<vault_id>/     # push
rsync -az <host>:~/<folder>/<vault_id>/ <store>/     # pull
```

So a desktop and a laptop holding **different** multisig signer keys (different
DEKs, deliberately) can point at the same `host` + `folder` and never clobber each
other. `bootstrap-from` is the opposite case: B receives A's DEK, so it is the same
vault — A's vault id travels in the bootstrap `OFFER` frame and B records it, and
both machines replicate into the same subtree.

| Command | What it does |
| --- | --- |
| `backup list` | List the vault ids sharing the first remote's folder, flagging which one is this install's. Prompts nothing, unlocks nothing. |
| `backup pull --vault <id>` | Pull a named vault — disaster recovery onto a bare machine, where all you have is the recovery passphrase and the remote. |
| `backup adopt` | Mint a vault id for a pre-vault keyring (see below). |

**A pull only ever lands the vault you asked for.** Before rsync runs, a pull into
a store whose `keyring.json` names a *different* vault is refused; after rsync, the
pulled `keyring.json` must carry the requested id or the command fails naming both.
`rsync -az` carries no `--delete`, so a mixed pull would merge, leaving keystores
this install's DEK cannot open — refusing is safer than deleting, and no `--delete`
is ever added.

Restoring a vault onto a bare machine therefore starts from an **empty store**. You
still need a `config.toml` naming the remote, and `init` writes one — along with a
throwaway DEK and vault id, which the restore must not inherit:

```bash
hot_cheese init                          # config.toml + TLS cert (and a throwaway vault)
$EDITOR ~/.config/hot_cheese/config.toml # add the [[backup_remotes]] entry
rm -rf ~/.config/hot_cheese/store        # drop the just-minted keyring: different vault
hot_cheese backup list                   # which vaults are on the remote?
hot_cheese backup pull --vault v_…       # then unlock with the recovery passphrase
```

Only run that `rm -rf` on a machine whose store holds nothing you need — here it
contains one keyring that encrypts nothing. Skip `init` entirely if you would rather
write `config.toml` and the cert by hand.

`serve`'s auto-pull uses this install's vault id. On a machine with **no store at
all** it cannot know its id: it adopts the remote's vault if there is exactly one,
and refuses when there are several, listing them so you can run
`backup pull --vault <id>`. It never guesses.

**A fresh `init` mints a new DEK *and* a new vault id.** It therefore lands *beside*
the previous backup — `<folder>/<new_id>/` — instead of overwriting a vault whose
keys you may still need. The old subtree stays exactly where it was; delete it
yourself once you are sure.

**Keyrings written before vault ids** (i.e. an existing `~/.config/hot_cheese/store`)
keep working untouched: they have no id, and they push and pull the un-namespaced
`<host>:~/<folder>/` exactly as before. Nothing mints an id behind your back — run
`hot_cheese backup adopt` when you want one. After adopting, backups move to
`<folder>/<vault_id>/`; the old un-namespaced copy is left alone at the folder root.
One caveat while you stay un-namespaced: pulling the folder root pulls *everything*
under it, including any sibling `v_…/` vault directories (inert locally — they are
directories, and only files are read as keystores). Adopt an id and that stops.

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
   enrolling B's Secure Enclave (and a recovery passphrase if
   `HOT_CHEESE_BOOTSTRAP_PASSPHRASE` is set). A's keyring is never copied.

Channel authentication comes from SSH (known_hosts / TOFU) — verify A's SSH host
key fingerprint out-of-band before the first connect. A MITM that fully
impersonates A could serve a DEK of its choosing, but cannot **learn** B's DEK,
because confidentiality rests on B's enclave key, not on the channel.

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
version and is inherent to a local signing service.

Specific residual risks:

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
- **No anti-rollback.** Keystore files bind AEAD AAD = domain ‖ key name ‖ use (a
  wrong-DEK, renamed, or re-flagged file won't decrypt), but **version/epoch
  anti-rollback is not implemented**. An attacker who can write **old ciphertexts (under
  the same DEK)** back into your store could roll a key back to a previous value — and,
  if it was `shareable` before you tightened it, back to a state whose header authorizes
  export. Mitigate by protecting store/backup integrity.
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
A read physically requires a present, authorized human to complete the
Touch-ID-gated ECDH that unwraps the DEK. No biometric, no decryption.

**What if I lose the master key?**
There is no master key. The DEK is wrapped under multiple independent KEKs: your
recovery passphrase and any Secure Enclave enrollments. As long as you have the
recovery passphrase (or a machine whose Secure Enclave you enrolled), you can
restore. Keep the passphrase offline and enroll more than one unlock method.

**What if I re-enroll Touch ID, or get a new Mac?**
Secure Enclave keys are device-bound and are invalidated when Touch ID is
re-enrolled — that SE enrollment stops working, and commands fail with
`SeKeyUnavailableTryUnlockPassphrase`. Recover with the **recovery passphrase**:

```bash
rm ~/.config/hot_cheese/se_kek_hotcheese_se_kek_v1.blob   # only if the blob is stale
hot_cheese --unlock passphrase enroll se                  # re-bind a fresh enclave key
```

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
regenerate and re-pin clients to the new fingerprint.

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
