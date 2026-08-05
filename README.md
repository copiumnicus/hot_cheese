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
9. [Client Integration](#client-integration)
10. [Backups](#backups)
11. [SSH Bootstrap](#ssh-bootstrap)
12. [Migration](#migration)
13. [Security Model & Residual Risks](#security-model--residual-risks)
14. [FAQ](#faq)

---

## Key Features

1. **Envelope key storage** — a random DEK (XChaCha20-Poly1305) encrypts every
   keystore; the DEK is wrapped in `keyring.json` under each enrolled KEK. The
   plaintext DEK is **never** written to disk.
2. **Cryptographic Touch ID** — a Secure Enclave key bound to Touch ID is a real
   KEK. Each `/read` (and generate/address) unwraps the DEK by doing a
   Touch-ID-gated ECDH inside the Secure Enclave: no biometric ⇒ no ECDH ⇒ no DEK
   ⇒ no decrypt. Per-request human approval is preserved.
3. **Recovery passphrase backstop** — an Argon2id-derived KEK that can unwrap the
   same DEK on any machine. It is the only cross-machine restore path (Secure
   Enclave keys are device-bound).
4. **Safe-to-replicate backups** — best-effort `rsync` push after every mutation,
   auto-pull on `serve` when the local store is missing, and manual
   `backup push` / `backup pull`. The remote only ever sees ciphertext.
5. **End-to-end encrypted reads** — per-request Diffie-Hellman exchange means the
   secret is encrypted specifically for the requesting client, on top of pinned
   TLS.
6. **SSH bootstrap ritual** — provision a fresh machine from an authority over
   SSH; the DEK is delivered via ECIES sealed to the new machine's Secure Enclave
   key and re-wrapped there under its own KEKs.

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
                                          │ XChaCha20-Poly1305  (AAD = key name)
                                          ▼
                        store/  EVM_KEY   SOLANA_TRADER   …   (encrypted keystores)
```

1. **At rest.** Each keystore file under `store/` is an XChaCha20-Poly1305
   envelope keyed by the DEK, with the **key name as AEAD additional data (AAD)**
   so a copied or renamed file refuses to decrypt. The DEK only ever exists on
   disk in wrapped form, inside `keyring.json`.
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
   the configured remotes; ciphertext only.

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
./target/release/hot_cheese se-selftest   # a couple of Touch ID prompts; validates the SE path
```

Run `se-selftest` in your **GUI login session with the screen unlocked** (a Terminal on the
Mac itself), not over `ssh` — Touch ID cannot fire in a headless / `sudo` / launchd context,
and the enclave refuses to create the key at all while the screen is locked. It asserts Touch ID
gating, deterministic ECDH, and SE/host ECDH equivalence (the same check as the
`#[ignore]`d `se_key_lifecycle_and_deterministic_ecdh` test in
`src/mac/secure_enclave.rs`). See
[Security Model & Residual Risks](#security-model--residual-risks).

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
hot_cheese se-selftest          # validates ECDH determinism + SE/host equivalence
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

### 3. Add or generate keys

```bash
# Import an existing secret (prompted, hidden input):
hot_cheese add MY_EVM_KEY ethereum     # hex, 0x optional
hot_cheese add MY_SOL_KEY solana       # base58 keypair bytes
hot_cheese add MY_RAW     bytes        # raw UTF-8

# Generate a fresh key:
hot_cheese generate evm    TRADING_BOT
hot_cheese generate solana SOLANA_TRADER

# Inspect:
hot_cheese list
hot_cheese address evm    TRADING_BOT
hot_cheese address solana SOLANA_TRADER
```

Key names must match `[A-Za-z0-9_]+`.

### 4. Serve

```bash
hot_cheese serve
```

Binds HTTPS on `127.0.0.1:<port>` (default **5555**). If the local store is empty
and a backup remote is configured, `serve` auto-pulls the store first.

---

## CLI Reference

| Command | What it does |
| --- | --- |
| `init [--import-cert <pem> --import-key <pem>] [--force]` | Create home/store, write the TLS cert, mint the DEK, require a recovery passphrase, print the cert fingerprint. |
| `enroll se [--label <s>]` | Enroll this machine's Secure Enclave as a KEK for the same DEK. No code signing, and **no Touch ID prompt** — it needs only the enclave's public key. |
| `enroll passphrase [--label <s>]` | Enroll an additional recovery passphrase. |
| `add <name> <ethereum\|solana\|bytes>` | Import an existing secret under `name` (read from a hidden prompt). |
| `generate <evm\|solana> <name>` | Generate a fresh key under `name`. |
| `address <evm\|solana> <name>` | Print the public address / pubkey of a stored key. |
| `list` | List stored keystores and keyring enrollments. |
| `serve` | Run the HTTPS daemon (auto-pulls the store from the first backup remote if absent). |
| `backup push` | Push the store to every configured remote. |
| `backup pull` | Pull the store from the first configured remote. |
| `migrate --old-store <dir> --new-store <dir>` | Migrate legacy Keychain-master keystores into the envelope format (see [MIGRATION.md](./MIGRATION.md)). |
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

[[backup_remotes]]
host = "user@1.2.3.4"
folder = "hot_cheese_store"
```

| Field | Meaning |
| --- | --- |
| `service`, `account` | **Legacy** Keychain identifiers, used **only** by `migrate` to read the old master. Ignored by the envelope path. |
| `store` | Directory holding the encrypted keystores + `keyring.json` (`~/` is expanded). |
| `port` | HTTPS listen port (optional; defaults to `5555`). |
| `backup_remotes` | List of `{ host, folder }` rsync targets. `folder` is relative to the remote home dir. |

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
| `/read/<name>` | GET (with body) | df-share Diffie-Hellman read: the body carries the client's ephemeral public key; the response is the secret encrypted so only that client can decrypt it. Works for both EVM and Solana keys. |
| `/evm_generate/<name>` | GET | Generate a new secp256k1 key, then best-effort backup push. |
| `/evm_address/<name>` | GET | Return the Ethereum address derived from `<name>`. |
| `/solana_generate/<name>` | GET | Generate a new ed25519 keypair, then best-effort backup push. |
| `/solana_address/<name>` | GET | Return the Solana pubkey of `<name>`. |

> The endpoints, TLS cert-pinning, and df-share Diffie-Hellman transfer are
> **unchanged** from the previous version — existing clients keep working as long
> as the pinned certificate is the same.

---

## Client Integration

Clients **pin the certificate** that `init` printed and verify its SHA-256
fingerprint out-of-band the first time. The reference client is
[`examples/pin_cert.rs`](./examples/pin_cert.rs) — copy `HotCheeseAgent` into your
own key consumers. It reads the pinned cert at runtime from the daemon's own home dir
(`$HOT_CHEESE_HOME`, else `~/.config/hot_cheese`), so it is per-machine, not compiled in:

```rust
// from examples/pin_cert.rs — the ONLY trusted root is that one certificate
let agent = HotCheeseAgent::new("https://localhost:5555")?;

let health = agent.health()?;                 // "ok"
let addr   = agent.address("TRADING_BOT")?;   // EVM address
let sol    = agent.solana_address("SOLANA_TRADER")?;
let secret = agent.read("TRADING_BOT")?;      // df-share DH read
```

Run it as a live pinning check against a serving daemon (both arguments are optional):

```bash
cargo run --release --example pin_cert -- https://127.0.0.1:5555 TRADING_BOT
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

- **After every mutation** — `add`, `generate`, `migrate`, and the HTTP
  `/evm_generate` / `/solana_generate` endpoints trigger a best-effort `rsync`
  push to every configured remote. Failures are logged, not fatal.
- **On `serve`** — if the local store is absent, it is auto-pulled from the first
  configured remote before the daemon starts.
- **Manually** — `hot_cheese backup push` (all remotes) and
  `hot_cheese backup pull` (first remote).

Configure targets in `backup_remotes` (see [Configuration](#configuration)). Each
remote is `rsync -az` to/from `<host>:~/<folder>/`.

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
hot_cheese migrate --old-store ~/HOT_CHEESE_MASTER --new-store ~/.config/hot_cheese/store
```

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
  per-request Touch ID.** There is **no mutual-TLS / client auth** — any local
  process that pins the cert, combined with a present human approving Touch ID,
  can solicit a key. Touch ID gives human-presence, not caller identity.
- **No anti-rollback.** Keystore files bind AEAD AAD = key name (a wrong-DEK or
  renamed file won't decrypt), but **version/epoch anti-rollback is not
  implemented**. An attacker who can write **old ciphertexts (under the same DEK)**
  back into your store could roll a key back to a previous value. Mitigate by
  protecting store/backup integrity.
- **SE/ECDH equivalence is validated in software.** The host-side half of the
  Secure Enclave ECDH (that `ECDH(eph_priv, se_pub)` equals the enclave's
  `ECDH(se_priv, eph_pub)`) is covered by a non-ignored software test. The **full
  Touch ID round-trip must be confirmed once on a Mac with Secure Enclave hardware**
  by running `hot_cheese se-selftest` (the `#[ignore]`d
  `se_key_lifecycle_and_deterministic_ecdh` test in `src/mac/secure_enclave.rs`).

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
[`bootstrap-from`](#ssh-bootstrap) or restore a backup and unlock with the
passphrase.

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
hidden prompt and stores it under the envelope.

---

**Hot Cheese** 🔥🧀 — handing out hot keys with the perfect blend of envelope
encryption, the Secure Enclave, and seamless local integration. Enjoy your
cryptographic fondue!
