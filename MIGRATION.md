# hot_cheese — Migration & Cutover Runbook

Moving from the **legacy** key daemon (Web3 keystores unlocked by a single
Keychain *master* password behind Touch ID) to **v1** (per-file envelope
encryption under a Data Encryption Key — DEK — that is itself wrapped in a
keyring and unlocked per request by the Secure Enclave or a recovery
passphrase).

The migration is **non-destructive and verify-before-finalize**: every legacy
key is decrypted with the old master, re-encrypted under the new DEK into a
staging directory, and *both* a decrypt round-trip and a re-derived public
address are checked before anything is committed. The old store is never
written. If a single key fails to verify, the whole run aborts and the staging
directory is removed. See `src/migrate.rs`.

> Plan for a **dual-run** period (run old and new side by side for N days) and
> only decommission the legacy store after you have served real traffic from v1
> and pushed at least one good backup.

---

## 0. What changes for clients (read first)

- **New keys are unreadable with the old master.** v1 keystores are
  XChaCha20-Poly1305 envelopes keyed by the DEK, not scrypt+AES under the
  Keychain master. The DEK is recoverable on a new machine **only** via the
  recovery passphrase (or a machine whose Secure Enclave you enrolled). **Record
  the recovery passphrase offline.**
- **The TLS certificate may change, which re-pins every client.** `hot_cheese
  init` mints a fresh self-signed `localhost` cert by default and prints its
  **SHA-256 fingerprint**. Clients that pin the old fingerprint will reject the
  new server until you update them.
  - To **avoid re-pinning**, keep your existing cert:
    `hot_cheese init --import-cert <old.pem> --import-key <old-key.pem>`.
  - Otherwise, **distribute the new fingerprint** to every client out-of-band
    before cutover.

---

## 1. Prerequisites

- **Binary distribution**
  - **Secure Enclave path (recommended for production):** you need a
    **code-signed** `hot_cheese` binary with Secure Enclave entitlements.
    Touch ID-bound SE keys cannot be created from an unsigned build —
    `enroll se` will refuse with a clear message on an unsigned binary.
  - **Passphrase-only path (fine to start / for an unsigned build):** skip
    `enroll se`. The recovery passphrase minted at `init` is a fully functional
    unlock method; you can add SE later once you have a signed binary.
- **The legacy master is reachable.** The old master still lives in the login
  Keychain under the service/account in your config (defaults:
  `com.cc.hot_cheese` / `hot_cheese_master`). Migration will prompt **one Touch
  ID** to read it. Do **not** delete the Keychain item yet.
- **You can authenticate at the console.** `init`, `enroll`, and `migrate` all
  prompt interactively (passphrase entry and/or Touch ID); run them in a real
  terminal on the host, not over a pipe.
- **Know where the old store is.** The legacy keystores live in a directory
  (commonly `~/HOT_CHEESE_MASTER`). The migrator reads every regular file there
  whose name is `[A-Za-z0-9_]+`; it ignores `keyring.json`, dotfiles, and
  subdirectories.
- **Same filesystem for the new store.** Staging happens in
  `<new-store>.staging` next to the destination so the finalizing move is a
  same-filesystem atomic rename. The default new store is
  `~/.config/hot_cheese/store`.
- **Have your own address manifest.** Before cutover, write down the expected
  EVM address / Solana pubkey for each key (from your existing records). You
  will diff this against what `migrate` prints.

---

## 2. Cutover (step by step)

Run these on the host that owns the keys. Set logging with
`RUST_LOG=info` (the default) so the informational output below is shown.

### 2.1 Update the binary

Install the new `hot_cheese` binary (signed, if you intend to use the Secure
Enclave). Stop the legacy daemon. Confirm:

```
hot_cheese --version
```

### 2.2 Initialize v1

```
hot_cheese init
```

This creates the home dir + store, writes the TLS cert/key, mints the DEK, and
**requires a recovery passphrase** (entered twice). On success it logs:

- `initialized hot_cheese` with the home and store paths,
- `TLS certificate written` with the cert path,
- `certificate fingerprint (pin this on the client)` with the **SHA-256**.

**Do now, offline:**
- Record the **recovery passphrase** in your secrets manager / on paper. It is
  the only cross-machine restore path for the DEK.
- Record the printed **cert SHA-256 fingerprint** for client pinning.

To keep the existing certificate (no client re-pin), instead run:

```
hot_cheese init --import-cert <old-cert.pem> --import-key <old-key.pem>
```

> `init` refuses to overwrite an existing config; pass `--force` only if you
> deliberately want to reinitialize (this re-mints the DEK and invalidates any
> keystores already written under the previous DEK).

### 2.3 (Optional) Enroll the Secure Enclave

Only on a **code-signed** binary with SE entitlements:

```
hot_cheese enroll se
```

This adds a Touch ID-bound unlock method for the **same** DEK (the recovery
passphrase still works as the survivable backstop). On an unsigned binary this
command fails with guidance to use the passphrase instead — that is expected;
skip it.

### 2.4 Migrate the legacy keys

```
hot_cheese migrate \
  --old-store ~/HOT_CHEESE_MASTER \
  --new-store ~/.config/hot_cheese/store
```

What happens:
- **One Touch ID** prompt authorizes reading the legacy master from the
  Keychain.
- The new DEK is unlocked (Secure Enclave if enrolled, else a recovery
  passphrase prompt).
- Each legacy key is decrypted, re-encrypted under the DEK into
  `~/.config/hot_cheese/store.staging`, and **verified** (decrypt round-trip +
  re-derived address). Identity is derived by secret length:
  **32 bytes → EVM address**, **64 bytes → Solana pubkey**, **otherwise →
  `sha256:<hex>` of the bytes**.
- Only after *all* keys verify is the destination store populated (atomic
  renames out of staging). On any failure the run aborts, removes the staging
  dir, and **leaves the old store byte-for-byte unchanged**.

On success it logs `migration complete` and one line per key:
`migrated  name=<NAME>  identity=<address-or-hash>`.

> Note: `migrate` requires that `init` has already run (it loads the v1 config +
> keyring). The destination store must not already contain a key file, or the
> command fails with `NewStoreNotEmpty`.
>
> If you have already configured a backup remote, `migrate` will additionally do
> a best-effort backup push at the end. If you would rather verify locally
> first, configure the remote **after** this step (see 2.7).

### 2.5 Verify the address manifest

Diff the printed `identity` for every `name` against the records you prepared in
§1. **They must match exactly.** If any address differs, **stop** — do not serve
or delete anything; investigate the source key. (A mismatch cannot be caused by
the re-encryption itself: the migrator re-derives and checks each address before
committing, so a discrepancy means the *input* secret was not what you expected.)

Spot-check independently if you like:

```
hot_cheese list
hot_cheese address evm    <NAME>
hot_cheese address solana <NAME>
```

### 2.6 End-to-end read test

Start the daemon and exercise a real client read:

```
hot_cheese serve
```

Point a client at `https://localhost:<port>` (pinning the fingerprint from
§2.2) and perform **one `read`** of a migrated key end-to-end. Confirm the
returned secret is correct on the client side. A successful authenticated read
proves the DEK unlock path, the envelope, and TLS pinning all work together.

### 2.7 Push a backup

Configure at least one backup remote (in `config.json`), then:

```
hot_cheese backup push
```

This stores the **encrypted** store (keystores remain envelope-encrypted at
rest; the remote never sees plaintext or the DEK). Confirm the push succeeds.
From here on, a fresh machine can `serve` and auto-pull, then unlock with the
recovery passphrase.

### 2.8 Dual-run for N days

Keep the legacy store **intact and untouched** and the new daemon serving real
traffic for a soak period (suggest **N = 7–14 days**, per your risk tolerance).
During this window:
- Serve production reads from v1.
- Keep at least one good backup current.
- Do **not** modify or delete the legacy store or its Keychain master.

---

## 3. Decommission (only after a successful dual-run)

When you are confident v1 is serving correctly and you have verified backups:

1. **Final backup:** `hot_cheese backup push`.
2. **Delete the old store directory** (e.g. `rm -rf ~/HOT_CHEESE_MASTER`).
3. **Remove the legacy Keychain master item** — delete the password entry for
   the configured service/account (defaults `com.cc.hot_cheese` /
   `hot_cheese_master`) via Keychain Access or `security delete-generic-password`.

After this, the legacy master is gone and all key access flows exclusively
through the v1 DEK (Secure Enclave and/or recovery passphrase).

---

## 4. Rollback

Because migration never touches the old store, rollback before decommission is
trivial:

- **During §2 (pre-decommission):** stop `hot_cheese serve`, restart the legacy
  daemon against the still-intact old store, and revert clients to the old cert
  fingerprint. Optionally `rm -rf ~/.config/hot_cheese/store.staging` if an
  aborted run left a stale staging dir (a clean run removes it automatically;
  the next `migrate` also clears a stale one first).
- **After §3 (post-decommission):** the legacy store and Keychain master are
  gone — recovery is via the v1 backups and the **recovery passphrase** only.
  This is why §2.7 (a verified backup) and an offline copy of the passphrase are
  mandatory before you ever reach §3.

---

## 5. Failure reference (`migrate`)

| Symptom (logged error) | Meaning | Action |
| --- | --- | --- |
| `NewStoreNotEmpty` | The destination store already holds a key file. | Point `--new-store` at an empty dir, or clear the intended one if it was a false start. |
| `VerifyMismatch(<name>)` | A key's round-trip or re-derived address didn't match. | Aborted safely; old store intact, no staging left. Investigate that source key; do not retry blindly. |
| `Crypto(MacMismatch)` / `Crypto(SerdeJson..)` | A legacy file failed its MAC or isn't valid keystore JSON (wrong master, or a corrupt/foreign file in the old store). | Confirm you authorized the correct Keychain master and that `--old-store` contains only real legacy keystores. |
| `SolanaKeypair` | A 64-byte secret didn't parse as a valid Solana keypair. | Inspect that source key; it isn't a well-formed ed25519 keypair. |
| `Address(..)` | A 32-byte secret didn't yield a valid EVM key. | Inspect that source key. |
| Touch ID denied | The biometric prompt for the legacy master was rejected. | Re-run `migrate` and approve the prompt. |

In every failure case above, the old store is left **byte-for-byte unchanged**
and no partial new store is produced.
