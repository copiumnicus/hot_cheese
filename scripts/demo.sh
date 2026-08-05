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
echo "==> 3) generate an EVM key"
"$BIN" generate evm DEMO_KEY

echo
echo "==> 4) read its address  (the Touch ID prompt IS the per-request unlock)"
"$BIN" address evm DEMO_KEY

echo
echo "==> 5) self-test the (software) enclave path  (Touch ID, twice)"
"$BIN" se-selftest

echo
echo "==> 6) write a fail-closed signing policy for DEMO_KEY"
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
echo "==> 7) sign a scoped Safe transfer intent"
echo "    ONE Touch ID prompt: the approval biometric is reused for the key unlock."
echo "    Only {r,s,v} comes back — never the private key."
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
"$BIN" sign --file "$HOT_CHEESE_HOME/demo_intent.json"

echo
echo "============================================================================"
echo "The demo 'enclave' private key is just a file you can read — THIS is exactly"
echo "what the real Secure Enclave fixes; in hardware it can never leave the chip:"
ls -l "$HOT_CHEESE_HOME"/software_enclave_*.key || true
echo
echo "Everything else — the envelope, the Touch ID UX, per-request unlock, serve,"
echo "backups, bootstrap — is IDENTICAL to the production Secure Enclave path."
echo "To go live (no code signing needed): unset HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE,"
echo "'cargo build --release', then 'hot_cheese se-selftest' and 'hot_cheese enroll se'."
echo "============================================================================"
