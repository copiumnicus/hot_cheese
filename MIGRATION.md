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
- **§6 — every signing key needs a policy file with `chain_id`** before `sign` will work.

## Where everything lives: `HOT_CHEESE_HOME`

Every path below is under the **home dir**: `$HOT_CHEESE_HOME` if that variable is set,
otherwise `~/.config/hot_cheese`. It holds `config.toml`, `ssl-cert.pem`, `ssl-key.pem`,
the Secure Enclave key blob, and (by default) `store/`. Setting `HOT_CHEESE_HOME` fully
isolates an install — which is how you rehearse this runbook without touching production:

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
`ssh`. Expect a couple of Touch ID prompts. `se-selftest` asserts Touch ID gating,
deterministic ECDH, and SE/host ECDH equivalence. **If it fails, stop and fix before
touching real keys.** If `se-selftest` reports the enclave is unavailable, the machine has
no Secure Enclave — use the recovery passphrase path only.

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

## 5. Migrate the keys (non-destructive)

```
hot_cheese migrate \
  --old-store /path/to/legacy/store \
  --new-store ~/.config/hot_cheese/store
```

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

Each key is decrypted, re-encrypted under the DEK into `store.staging`, and verified before
the atomic move. Identity is derived by secret length: **32 bytes → EVM address**,
**64 bytes → Solana pubkey**, otherwise **`sha256:<hex>`**. On success it logs one line per
key: `migrated  name=<NAME>  identity=<address-or-hash>`.

**Eyeball the printed manifest against your known addresses.** If any differs, **stop** —
the old store is untouched; investigate the source key. Optional independent spot-check
(each `address` prompts Touch ID, and the sheet names the key — `Unlock "<NAME>" for get
address`):

```
hot_cheese list
hot_cheese address evm    <NAME>
hot_cheese address solana <NAME>
```

## 6. Write a signing policy for every key you will `sign` with

`sign` is fail-closed: it loads `<store>/policies/<NAME>.toml` and **denies every signature**
if that file is missing or does not parse. `chain_id` is **required** — a policy without it
fails to load, which reads as "every signature denied", not as a warning.

```
mkdir -p ~/.config/hot_cheese/store/policies
cat > ~/.config/hot_cheese/store/policies/<NAME>.toml <<'POLICY'
safe = "0xYourSafeAddress"
chain_id = 1

[[allow]]
to = "0xContractYouCall"
selectors = ["0xa9059cbb"]
max_value = "0"
operation = "call"
POLICY
```

- `safe` and `chain_id` pin the Safe and the chain; an intent for any other Safe or chain
  is denied (this is the cross-chain replay guard).
- Each `[[allow]]` rule permits one destination: only the listed 4-byte `selectors`, up to
  `max_value`, and only with the listed `operation` (`call` unless you write `delegatecall`).
  A destination with no rule is denied.
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
  `[owner_management]` sets `allow = true` and lists the selectors.

Policies live inside the store, so they travel with the rsync backup.

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
cargo run --release --example pin_cert -- https://127.0.0.1:5555 <NAME>
```

It resolves the pinned cert from the same home dir the daemon uses (honouring
`HOT_CHEESE_HOME`), prints `health=ok`, then does **one** df-share read of `<NAME>` and
prints only `len=`, `digest=` (salted per read and truncated, so it is not a usable offline
commitment to the secret), and `evm_address=` — never the key bytes.

Then do **one** real read from your actual client (pinning the fingerprint from §2) to
confirm the end-to-end path. Every `/read` now prompts a **fresh Touch ID per request**, and
the sheet names the key (`Unlock "<NAME>" for read key`) — do not script or spam it;
`/health` is the only non-prompting endpoint.

## 8. Back up what the store backup does NOT cover

The rsync backup replicates **only the store dir** — which includes `keyring.json` (the
**wrapped DEK**) — so the remote never sees plaintext or the DEK. It does **not** include
the TLS cert/key or `config.toml` (those live under the home dir). Separately back up

```
~/.config/hot_cheese/{ssl-cert.pem,ssl-key.pem,config.toml}
```

to a **secure** location. Do **not** rsync the TLS private key to untrusted backup
hosts. To provision a fresh machine from an authority host over SSH instead, use
`hot_cheese bootstrap-from user@host` (transfers the DEK + store).

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
that unlocks the DEK (`address`, `add`, `generate`, `sign`, `enroll`, `migrate`), either
before or after the subcommand:

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
