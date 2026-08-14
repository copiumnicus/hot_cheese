#!/usr/bin/env bash
set -euo pipefail

export HOT_CHEESE_HOME="${HOT_CHEESE_HOME:-/tmp/hot_cheese_demo}"
export HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE=1
BIN="${BIN:-./target/release/hot_cheese}"

if [[ ! -x "$BIN" ]]; then
  echo "Building release binary first..." >&2
  cargo build --release
  BIN="./target/release/hot_cheese"
fi

echo "==> Fresh demo home at $HOT_CHEESE_HOME"
rm -rf "$HOT_CHEESE_HOME"

echo
echo "==> 1) init  (set a recovery passphrase when prompted, twice)"
"$BIN" init

echo
echo "==> 2) enroll the 'Secure Enclave'  (DEMO: a software key on disk)"
"$BIN" enroll se

echo
echo "==> 3) enroll the grant key  (prompts nothing; signing refuses to run without it)"
"$BIN" enroll grant

echo
echo "==> 4) generate an EVM key"
"$BIN" generate evm DEMO_KEY

echo
echo "==> 5) read its address  (the Touch ID prompt IS the per-request unlock)"
DEMO_ADDR="$("$BIN" address evm DEMO_KEY 2>&1 | tee /dev/stderr | grep -o '0x[0-9a-fA-F]\{40\}' | head -1 || true)"
[[ -n "$DEMO_ADDR" ]] || { echo "could not read DEMO_KEY's address" >&2; exit 1; }

echo
echo "==> 6) self-test the (software) enclave path  (Touch ID, three times)"
"$BIN" se-selftest

echo
echo "==> 7) write a fail-closed signing policy for DEMO_KEY"
mkdir -p "$HOT_CHEESE_HOME/store/policies"
cat > "$HOT_CHEESE_HOME/store/policies/DEMO_KEY.toml" <<'POLICY'
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
    rule = { max = { max = "1000", amount_of = "0x2222222222222222222222222222222222222222" } }
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
HASH="$("$BIN" bundle new --no-sync --file "$HOT_CHEESE_HOME/demo_intent.json" 2>&1 | tee /dev/stderr | grep -o '0x[0-9a-f]\{64\}' | head -1 || true)"
[[ -n "$HASH" ]] || { echo "bundle new did not report a safeTxHash" >&2; exit 1; }

echo
echo "==> 10) read the filed bundle: who signed, who is still missing, the threshold"
"$BIN" bundle status "$HASH" --no-sync

echo
echo "==> 11) sign the bundle with DEMO_KEY"
echo "    ONE Touch ID prompt: that approval mints the per-payload grant AND unlocks the key."
echo "    Only {r,s,v} is filed — never the private key."
"$BIN" bundle sign "$HASH" --key DEMO_KEY --no-sync

echo
echo "==> 12) the assembled execTransaction call, threshold met"
"$BIN" bundle export "$HASH" --no-sync

echo
echo "============================================================================"
echo "The demo 'enclave' private keys are just files you can read — THIS is exactly"
echo "what the real Secure Enclave fixes; in hardware they can never leave the chip:"
ls -l "$HOT_CHEESE_HOME"/software_enclave_*.key "$HOT_CHEESE_HOME"/software_grant_*.key || true
echo
echo "Everything else — the envelope, the Touch ID UX, per-request unlock, serve,"
echo "backups, bootstrap — is IDENTICAL to the production Secure Enclave path."
echo "To go live (no code signing needed): unset HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE,"
echo "'cargo build --release', then 'hot_cheese se-selftest' and 'hot_cheese enroll se'."
echo "============================================================================"
