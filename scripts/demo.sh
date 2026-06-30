#!/usr/bin/env bash
# Preview the FULL Secure-Enclave flow with NO $99 Apple Developer Program and NO code
# signing. It runs the real commands (init / enroll se / generate / address / se-selftest)
# against a SOFTWARE "enclave" — a P-256 key in a file — gated by a real Touch ID prompt
# (LAContext works on an unsigned binary). The ONLY thing the real Secure Enclave changes is
# moving that one key into hardware so it can never be read off disk.
#
# This is a DEMO. Do not put real keys in it. It uses a throwaway HOT_CHEESE_HOME so it never
# touches a real install.
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
echo "============================================================================"
echo "The demo 'enclave' private key is just a file you can read — THIS is exactly"
echo "what the real Secure Enclave (\$99 + signing) fixes; in hardware it can never"
echo "leave the chip:"
echo "  $HOT_CHEESE_HOME/software_enclave.key"
ls -l "$HOT_CHEESE_HOME/software_enclave.key" || true
echo
echo "Everything else — the envelope, the Touch ID UX, per-request unlock, serve,"
echo "backups, bootstrap — is IDENTICAL to the production Secure Enclave path."
echo "To go live: fill __TEAM_ID__ in hotcheese.entitlements, run scripts/sign.sh,"
echo "then 'hot_cheese se-selftest' (real enclave) and 'hot_cheese enroll se'."
echo "============================================================================"
