#!/usr/bin/env bash
set -euo pipefail
export NO_COLOR=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

BIN="$REPO_ROOT/target/release/hot_cheese"
DRY_PORT="${DRY_PORT:-5599}"
SKIP_SELFTEST="${SKIP_SELFTEST:-}"
SKIP_SERVE="${SKIP_SERVE:-}"
RUN_MIGRATE="${RUN_MIGRATE:-}"
HC_DRYRUN_ALLOW_ANY_PATH="${HC_DRYRUN_ALLOW_ANY_PATH:-}"

SE_LABEL="hotcheese.se.kek.v1"
GRANT_LABEL="hotcheese.se.grant.v1"
SE_BLOB_NAME="se_kek_hotcheese_se_kek_v1.blob"
GRANT_BLOB_NAME="se_grant_hotcheese_se_grant_v1.blob"
SELFTEST_BLOB_NAME="se_kek_hotcheese_se_selftest.blob"
SELFTEST_GRANT_BLOB_NAME="se_grant_hotcheese_se_selftest.blob"

EVM_KEY="DRYRUN_EVM"
SHARE_KEY="DRYRUN_SHARE"
SOL_KEY="DRYRUN_SOL"
BYTES_KEY="DRYRUN_BYTES"

SAFE_ADDR="0x1111111111111111111111111111111111111111"
TOKEN_ADDR="0x2222222222222222222222222222222222222222"
OTHER_ADDR="0x3333333333333333333333333333333333333333"
GAS_TOKEN_ADDR="0x4444444444444444444444444444444444444444"
ATTACKER_ADDR="0x5555555555555555555555555555555555555555"
ZERO_ADDR="0x0000000000000000000000000000000000000000"
TRANSFER_DATA="0xa9059cbb0000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000a"

FOREIGN_GRANT_PUB="046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
EXAMPLE_FOLDER="hot_cheese_store"

LEGACY_PASSWORD="grOQ8QDnGHvpYJf"
LEGACY_KEY_NAME="LEGACY_EVM"
LEGACY_SHARE_NAME="LEGACY_SHARE"
LEGACY_EXPECTED_ADDR="0xaeca03483e2dba25dc43baedc9f811330d634d46"
MIG_SERVICE="com.cc.hot_cheese.dryrun"
MIG_ACCOUNT="hot_cheese_dryrun_master"

BIO_PREDICATE='process == "coreauthd" AND eventMessage CONTAINS "has matched by"'

PASS_COUNT=0
FAIL_COUNT=0
RUN_RC=0
RUN_LOG=""
OUT_DIR=""
SNAP_DIR=""
CFG_FILE=""
KEYRING_FILE=""
SERVE_LOG=""
ADDR_PASS=""
ADDR_SE=""
ADDR_SHARE=""
SOL_ADDR=""
VAULT_INIT=""
TAPS_EXPECTED=0
BIO_LOG=""
BIO_START=""
BIO_PHASE=""
RUN_START=""
CFG_SERVICE=""
CFG_ACCOUNT=""
CFG_STORE=""
CFG_GRANT_PUB=""
LEGACY_FIXTURE=""
PIN_CERT_MANIFEST=""

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "  PASS  $*"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "  FAIL  $*"
}

fatal() {
  echo
  echo "ABORT: $*" >&2
  exit 1
}

phase() {
  echo
  echo "================================================================"
  echo "$*"
  echo "================================================================"
}

assert_eq() {
  if [[ "$2" == "$3" ]]; then
    pass "$1"
  else
    fail "$1 [want='$2' got='$3']"
  fi
}

assert_contains() {
  if [[ -f "$3" ]] && grep -qF -- "$2" "$3"; then
    pass "$1"
  else
    fail "$1 [missing '$2' in $3]"
  fi
}

assert_not_contains() {
  if [[ -f "$3" ]] && grep -qF -- "$2" "$3"; then
    fail "$1 [unexpected '$2' in $3]"
  else
    pass "$1"
  fi
}

assert_matches() {
  if [[ -f "$3" ]] && grep -qE -- "$2" "$3"; then
    pass "$1"
  else
    fail "$1 [no match for /$2/ in $3]"
  fi
}

assert_file_mode() {
  local got=""
  got="$(stat -f '%A' "$3" 2>/dev/null || true)"
  assert_eq "$1" "$2" "$got"
}

assert_list_use() {
  local line=""
  line="$(grep -E "key=$2([[:space:]]|$)" "$1" 2>/dev/null | head -1 || true)"
  if [[ "$line" == *"key_use=\"$3\""* || "$line" == *"key_use=$3"* ]]; then
    pass "list reports $2 as $3"
  else
    fail "list reports $2 as $3 [line='$line']"
  fi
}

bio_taps_since() {
  /usr/bin/log show --start "$1" --style compact --predicate "$BIO_PREDICATE" 2>/dev/null |
    grep -c 'MechanismTouchId' || true
}

bio_window_start() {
  local mark="" now=""
  mark="$(date '+%Y-%m-%d %H:%M:%S')"
  now="$mark"
  while [[ "$now" == "$mark" ]]; do
    sleep 0.05
    now="$(date '+%Y-%m-%d %H:%M:%S')"
  done
  printf '%s' "$now"
}

assert_taps() {
  if [[ -z "$BIO_LOG" ]]; then
    fail "$1 [unified logging is not queryable here, so Touch ID sheets could not be counted]"
    return 0
  fi
  assert_eq "$1" "$2" "$(bio_taps_since "$3")"
}

ask_tty() {
  local answer=""
  printf '\n  ?? %s ' "$1" > /dev/tty
  IFS= read -r answer < /dev/tty || answer=""
  printf '%s' "$answer"
}

run_cmd() {
  local tag="$1"
  shift
  RUN_LOG="$OUT_DIR/$tag.log"
  echo "  ---> $*"
  set +o pipefail
  "$@" < /dev/null 2>&1 | tee "$RUN_LOG"
  RUN_RC=${PIPESTATUS[0]}
  set -o pipefail
}

run_tty() {
  local tag="$1"
  shift
  RUN_LOG="$OUT_DIR/$tag.log"
  echo "  ---> $*"
  set +o pipefail
  "$@" 2>&1 | tee "$RUN_LOG"
  RUN_RC=${PIPESTATUS[0]}
  set -o pipefail
}

assert_cmd_fails_with() {
  local tag="$1" needle="$2"
  shift 2
  run_cmd "$tag" "$@"
  if [[ "$RUN_RC" -eq 0 ]]; then
    fail "$tag: expected a non-zero exit, got 0"
  else
    pass "$tag: exited $RUN_RC as expected"
  fi
  assert_contains "$tag: error names $needle" "$needle" "$RUN_LOG"
}

field_value() {
  local raw=""
  raw="$(grep -o "$2=[^[:space:]]*" "$1" 2>/dev/null | head -1 || true)"
  printf '%s' "${raw#*=}"
}

toml_value() {
  grep -E "^[[:space:]]*$2[[:space:]]*=" "$1" 2>/dev/null | head -1 | cut -d'"' -f2 || true
}

lower() {
  printf '%s' "$1" | tr 'A-Z' 'a-z'
}

find_repo_file() {
  local candidate=""
  for candidate in "$REPO_ROOT/$1" "$REPO_ROOT/crates"/*/"$1"; do
    if [[ -e "$candidate" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  printf ''
}

assert_binary_newer_than() {
  local path=""
  path="$(find_repo_file "$1")"
  if [[ -z "$path" ]]; then
    fail "could not locate $1 in this checkout, so its staleness is unverifiable"
  elif [[ "$BIN" -nt "$path" ]]; then
    pass "binary is newer than $path"
  else
    fail "binary is OLDER than $path — you are about to test a stale enclave path"
  fi
}

port_pids() {
  lsof -nP -iTCP:"$DRY_PORT" -sTCP:LISTEN -t 2>/dev/null || true
}

snapshot_dir() {
  local dir="$1" list="$2" hashes="$3" rel=""
  : > "$list"
  : > "$hashes"
  if [[ ! -d "$dir" ]]; then
    echo "__ABSENT__" > "$list"
    return 0
  fi
  (cd "$dir" && find . -type f -print 2>/dev/null || true) | LC_ALL=C sort > "$list"
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    (cd "$dir" && shasum -a 256 "$rel" 2>/dev/null || true) >> "$hashes"
  done < "$list"
}

write_config() {
  local grant_line=""
  if [[ -n "$3" ]]; then
    grant_line="grant_public_key = \"$3\""
  fi
  cat > "$CFG_FILE" <<TOML
service = "$1"
account = "$2"
store = "$CFG_STORE"
port = $DRY_PORT
$grant_line
backup_remotes = []
TOML
}

forge_key_use() {
  local file="$1" from="$2" to="$3" tmp=""
  tmp="$file.forged"
  sed "s/\"key_use\":\"$from\"/\"key_use\":\"$to\"/" "$file" > "$tmp"
  mv "$tmp" "$file"
}

on_exit() {
  local rc=$?
  echo
  echo "================================================================"
  echo "EXIT GUARD (never kills processes)"
  echo "================================================================"
  if [[ -n "$SNAP_DIR" && -f "$SNAP_DIR/before.list" ]]; then
    snapshot_dir "$REAL_HOME" "$SNAP_DIR/exit.list" "$SNAP_DIR/exit.hashes"
    if cmp -s "$SNAP_DIR/before.list" "$SNAP_DIR/exit.list" &&
      cmp -s "$SNAP_DIR/before.hashes" "$SNAP_DIR/exit.hashes"; then
      echo "  OK    real home is byte-identical to the phase-0 snapshot: $REAL_HOME"
      rm -rf "$SNAP_DIR"
    else
      echo "  ALERT real home DIFFERS from the phase-0 snapshot: $REAL_HOME"
      echo "  ALERT diff $SNAP_DIR/before.hashes against $SNAP_DIR/exit.hashes; that dir is kept"
      rc=1
    fi
  else
    echo "  OK    real-home baseline was already verified and removed"
    if [[ -n "$SNAP_DIR" && -d "$SNAP_DIR" ]]; then
      rm -rf "$SNAP_DIR"
    fi
  fi
  echo "  note  if you started 'serve' in a second terminal, stop it there with Ctrl-C"
  echo "  note  dry-run home (deleted only by phase 9): ${HOT_CHEESE_HOME:-unset}"
  exit $rc
}

LEGACY_FIXTURE="$(find_repo_file test-keys/key-scrypt.json)"
PIN_CERT_SRC="$(find_repo_file examples/pin_cert.rs)"
PIN_CERT_MANIFEST="$REPO_ROOT/Cargo.toml"
if [[ -n "$PIN_CERT_SRC" ]]; then
  PIN_CERT_MANIFEST="$(dirname "$(dirname "$PIN_CERT_SRC")")/Cargo.toml"
fi

echo "================================================================"
echo "hot_cheese PRE-CUTOVER DRY RUN — REAL Secure Enclave, REAL TLS"
echo "================================================================"
echo "This is the OPPOSITE of scripts/demo.sh."
echo "  demo.sh    sets HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE=1 and unlocks with an"
echo "             extractable P-256 key sitting in a file on disk. A preview, never real keys."
echo "  dryrun.sh  REFUSES to run if that variable is set. Every unlock below is a real"
echo "             CryptoKit SecureEnclave.P256 ECDH gated by a real Touch ID sheet."
echo
echo "It rehearses the FULL envelope flow in a throwaway HOT_CHEESE_HOME so you can"
echo "hit every failure mode BEFORE migrating production keys per MIGRATION.md."
echo "Your real install at \$HOME/.config/hot_cheese is snapshotted and never written."
echo
echo "PROMPT BUDGET — sit down with a finger free:"
echo "  phases 0-9 total: 12 Touch ID sheets + 6 recovery-passphrase entries"
echo "    phase 0  3 Touch ID   (se-selftest: two fresh enclave ECDHs, then ONE sheet that has"
echo "                           to cover a third ECDH AND an enclave grant signature)"
echo "    phase 1  2 passphrase (init: new passphrase, entered twice)"
echo "    phase 2  3 passphrase + 1 Touch ID"
echo "    phase 3  6 Touch ID   (five key operations, then one on a file whose use flag was"
echo "                           forged; plus one short secret you type at a hidden prompt)"
echo "    phase 4  0            (enroll grant prompts NOTHING: no Touch ID, no passphrase)"
echo "    phase 5  1 Touch ID   (the allowed sign; all six refusals cost 0)"
echo "    phase 6  1 Touch ID   (the shareable /read; the sign-only /read costs 0)"
echo "    phase 7  1 passphrase (the recovery escape hatch, SE blob moved aside)"
echo "    phase 8  0            (vault-aware backup, read locally, no ssh and no rsync)"
echo "    phase 9  0"
echo "  with RUN_MIGRATE=1 add phase M: 2 Touch ID + 1 login-keychain access dialog"
echo "    (budget up to 4 taps in case macOS re-prompts)"
echo
echo "You are NEVER asked to remember how many Touch ID sheets you saw. Sheets are counted"
echo "from macOS unified logging (coreauthd biometric matches) inside each command's window."
echo "'log show --start' resolves WHOLE SECONDS only, so each window first waits for the second"
echo "to tick over: without that, the previous command's tap bleeds into the next count."
echo
echo "Env switches: DRY_PORT SKIP_SELFTEST SKIP_SERVE RUN_MIGRATE HC_DRYRUN_ALLOW_ANY_PATH"
echo "Run this in your GUI login session. Touch ID cannot prompt over ssh or sudo."

phase "PHASE 0 — isolation, interlock, provenance"

if [[ -z "${HOT_CHEESE_HOME:-}" ]]; then
  fatal "HOT_CHEESE_HOME is not set. Export a throwaway one, e.g. /tmp/hot_cheese_dryrun. This script rm -rf's it."
fi
HOT_CHEESE_HOME="${HOT_CHEESE_HOME%/}"
export HOT_CHEESE_HOME
if [[ "$HOT_CHEESE_HOME" != /* ]]; then
  fatal "HOT_CHEESE_HOME must be an absolute path, got '$HOT_CHEESE_HOME'"
fi
if [[ -n "${HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE:-}" ]]; then
  fatal "HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE is set. That is the demo software key on disk, not the enclave. unset it and re-run."
fi
if [[ -z "${HOME:-}" ]]; then
  fatal "HOME is not set, so the real install location cannot be determined"
fi
REAL_HOME="$HOME/.config/hot_cheese"
if [[ "$HOT_CHEESE_HOME" == "$REAL_HOME" ]]; then
  fatal "HOT_CHEESE_HOME points at the REAL install $REAL_HOME"
fi
case "$HOT_CHEESE_HOME/" in
  "$REAL_HOME"/*) fatal "HOT_CHEESE_HOME lives inside the real install $REAL_HOME" ;;
esac
case "$REAL_HOME/" in
  "$HOT_CHEESE_HOME"/*) fatal "the real install $REAL_HOME lives inside HOT_CHEESE_HOME, which this script rm -rf's" ;;
esac
if [[ -z "$HC_DRYRUN_ALLOW_ANY_PATH" ]]; then
  case "$HOT_CHEESE_HOME" in
    /tmp/* | /private/tmp/* | /var/folders/*) ;;
    *) fatal "HOT_CHEESE_HOME must be under /tmp, /private/tmp or /var/folders (this script rm -rf's it). Set HC_DRYRUN_ALLOW_ANY_PATH=1 to override." ;;
  esac
fi
case "$DRY_PORT" in
  '' | *[!0-9]*) fatal "DRY_PORT must be a plain port number, got '$DRY_PORT'" ;;
esac
CFG_FILE="$HOT_CHEESE_HOME/config.toml"
echo "  OK    dry home:  $HOT_CHEESE_HOME"
echo "  OK    real home: $REAL_HOME  (read-only baseline, never written)"
echo "  OK    dry port:  $DRY_PORT"
echo "  OK    software-enclave demo backend is NOT enabled"

SNAP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hot_cheese_dryrun_snap.XXXXXX")"
case "$SNAP_DIR/" in
  "$HOT_CHEESE_HOME"/*) fatal "the snapshot dir landed inside the dry home; set TMPDIR elsewhere" ;;
esac
trap on_exit EXIT INT TERM
snapshot_dir "$REAL_HOME" "$SNAP_DIR/before.list" "$SNAP_DIR/before.hashes"
if [[ -d "$REAL_HOME" ]]; then
  echo "  OK    snapshotted $(grep -c . "$SNAP_DIR/before.hashes" || true) file(s) of the real home into $SNAP_DIR"
else
  echo "  OK    the real home does not exist yet; snapshot records it as absent"
fi

PORT_PIDS="$(port_pids)"
if [[ -n "$PORT_PIDS" ]]; then
  fatal "something is already listening on the dry port $DRY_PORT (pid(s): $PORT_PIDS). Pick another with DRY_PORT= or stop it yourself; this script never kills processes."
fi
echo "  OK    dry port $DRY_PORT has no listener"

echo
echo "==> wiping the dry home and creating the output archive"
rm -rf "$HOT_CHEESE_HOME"
OUT_DIR="$HOT_CHEESE_HOME/dryrun_out"
SERVE_LOG="$OUT_DIR/serve.log"
mkdir -p "$OUT_DIR"
RUN_START="$(date '+%Y-%m-%d %H:%M:%S')"
echo "  OK    every command's output is archived under $OUT_DIR"

echo
echo "==> required tools"
for tool in cargo swiftc openssl curl shasum lsof security cmp stat find tr sed; do
  if command -v "$tool" > /dev/null 2>&1; then
    pass "tool present: $tool"
  else
    fail "tool MISSING: $tool"
  fi
done

echo
echo "==> the biometric counter: coreauthd logs one 'MechanismTouchId ... has matched by' line"
echo "    per Touch ID sheet you actually complete, so every tap count below is machine-read."
if /usr/bin/log show --last 1m --style compact --predicate "$BIO_PREDICATE" > /dev/null 2>&1; then
  BIO_LOG=1
  pass "unified logging answers the coreauthd biometric query"
else
  fail "unified logging did NOT answer the coreauthd biometric query — every tap count below fails"
fi

echo
echo "==> building the release binary (the enclave path needs the real swiftc bridge)"
run_cmd p0_build cargo build --locked --release
if [[ "$RUN_RC" -eq 0 ]]; then
  pass "cargo build --locked --release"
else
  fail "cargo build --locked --release exited $RUN_RC"
fi
if [[ -x "$BIN" ]]; then
  pass "binary present: $BIN"
else
  fail "binary MISSING: $BIN"
fi
assert_binary_newer_than swift/se_bridge.swift
assert_binary_newer_than src/mac/secure_enclave.rs
if [[ -n "$PIN_CERT_SRC" ]]; then
  pass "phase 6's pinning client lives at $PIN_CERT_SRC"
else
  fail "could not locate examples/pin_cert.rs, so phase 6 has no client to read with"
fi

if [[ -n "$SKIP_SELFTEST" ]]; then
  echo
  echo "==> SKIP_SELFTEST is set: skipping se-selftest (saves 3 Touch ID prompts)"
else
  echo
  echo "==> se-selftest on real Secure Enclave hardware"
  echo "    Expect THREE Touch ID sheets. It creates throwaway enclave KEK and grant keys,"
  echo "    proves the ECDH is deterministic AND equals the host-side ECDH used at enrollment,"
  echo "    then proves ONE biometric covers both an enclave ECDH and an enclave grant"
  echo "    signature — the property every single-tap signature depends on — and deletes both."
  TAPS_EXPECTED=$((TAPS_EXPECTED + 3))
  BIO_START="$(bio_window_start)"
  run_cmd p0_selftest "$BIN" se-selftest
  assert_eq "se-selftest exit code" "0" "$RUN_RC"
  assert_contains "se-selftest reports PASSED" "Secure Enclave self-test PASSED" "$RUN_LOG"
  assert_contains "one biometric covered the enclave ECDH AND the enclave grant signature" \
    "one biometric covered both" "$RUN_LOG"
  assert_matches "the reuse window was measured, not assumed" 'elapsed_ms=[0-9]+' "$RUN_LOG"
  assert_taps "se-selftest cost exactly three Touch ID sheets" "3" "$BIO_START"
  if [[ -e "$HOT_CHEESE_HOME/$SELFTEST_BLOB_NAME" ]]; then
    fail "se-selftest left its throwaway KEK blob behind: $HOT_CHEESE_HOME/$SELFTEST_BLOB_NAME"
  else
    pass "se-selftest left no throwaway KEK blob"
  fi
  if [[ -e "$HOT_CHEESE_HOME/$SELFTEST_GRANT_BLOB_NAME" ]]; then
    fail "se-selftest left its throwaway grant blob behind: $HOT_CHEESE_HOME/$SELFTEST_GRANT_BLOB_NAME"
  else
    pass "se-selftest left no throwaway grant blob"
  fi
  LEFTOVER="$(find "$HOT_CHEESE_HOME" -maxdepth 1 \( -name 'se_kek_*.blob' -o -name 'se_grant_*.blob' \) 2>/dev/null || true)"
  assert_eq "no enclave blob of any label remains after se-selftest" "" "$LEFTOVER"
fi

phase "PHASE 1 — init with cert import (2 passphrase entries, 0 taps)"

IMPORT_DIR="$HOT_CHEESE_HOME/dryrun_in"
IMPORT_CERT="$IMPORT_DIR/import-cert.pem"
IMPORT_KEY="$IMPORT_DIR/import-key.pem"
mkdir -p "$IMPORT_DIR"
echo "==> minting a throwaway localhost cert with the same shape init mints via rcgen"
echo "    (CN=localhost, SAN DNS:localhost + IP:127.0.0.1, EKU serverAuth) so phase 6 serves"
echo "    the same cert shape your production clients pin."
run_cmd p1_openssl openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$IMPORT_KEY" -out "$IMPORT_CERT"
assert_eq "openssl minted the throwaway pair" "0" "$RUN_RC"

chmod 0644 "$IMPORT_KEY"
echo
echo "==> the source key is deliberately left mode 644: a TLS key exported from an old"
echo "    install is often world-readable, and init must install it 0600 regardless."

echo
echo "==> negative: --import-cert without --import-key must be refused"
assert_cmd_fails_with p1_init_half "CertKeyPairRequired" "$BIN" init --import-cert "$IMPORT_CERT"
if [[ -e "$CFG_FILE" ]]; then
  fail "the refused init still wrote a config.toml"
else
  pass "the refused init wrote no config.toml"
fi

echo
echo "==> init --import-cert --import-key"
echo "    YOU WILL BE PROMPTED TWICE for a NEW recovery passphrase. Use a throwaway one"
echo "    and remember it: phase 2 asks for it three more times."
run_tty p1_init "$BIN" init --import-cert "$IMPORT_CERT" --import-key "$IMPORT_KEY"
assert_eq "init exit code" "0" "$RUN_RC"
assert_contains "init printed the pinning fingerprint" "sha256=" "$RUN_LOG"

FINGERPRINT="$(field_value "$RUN_LOG" sha256)"
VAULT_INIT="$(field_value "$RUN_LOG" vault)"
CERT_INSTALLED="$HOT_CHEESE_HOME/ssl-cert.pem"
KEY_INSTALLED="$HOT_CHEESE_HOME/ssl-key.pem"
INDEPENDENT_FP="$(openssl x509 -in "$CERT_INSTALLED" -outform DER 2>/dev/null | shasum -a 256 | cut -d' ' -f1 || true)"
assert_eq "printed fingerprint equals an independent sha256 over the cert DER" "$INDEPENDENT_FP" "$FINGERPRINT"
assert_matches "init minted and logged a v_<32 hex> vault id" 'vault=v_[0-9a-f]{32}' "$RUN_LOG"

if cmp -s "$IMPORT_CERT" "$CERT_INSTALLED"; then
  pass "installed ssl-cert.pem is byte-identical to the imported cert"
else
  fail "installed ssl-cert.pem DIFFERS from the imported cert"
fi
if cmp -s "$IMPORT_KEY" "$KEY_INSTALLED"; then
  pass "installed ssl-key.pem is byte-identical to the imported key"
else
  fail "installed ssl-key.pem DIFFERS from the imported key"
fi

KEY_MODE="$(stat -f '%A' "$KEY_INSTALLED" 2>/dev/null || true)"
echo "  note  installed ssl-key.pem mode is $KEY_MODE (imported source was deliberately 644)"
assert_file_mode "ssl-key.pem is 600" "600" "$KEY_INSTALLED"

if [[ -f "$CFG_FILE" ]]; then
  pass "config.toml exists"
else
  fail "config.toml missing"
fi
if [[ -f "$HOT_CHEESE_HOME/store/keyring.json" ]]; then
  pass "store/keyring.json exists"
else
  fail "store/keyring.json missing"
fi
assert_not_contains "a fresh install pins no grant key yet" "grant_public_key" "$CFG_FILE"

run_cmd p1_list "$BIN" list
assert_eq "list exit code" "0" "$RUN_RC"
N_PASS="$(grep -cE 'kind="?passphrase' "$RUN_LOG" || true)"
N_SE="$(grep -cE 'kind="?secure_enclave' "$RUN_LOG" || true)"
assert_eq "exactly one passphrase enrollment after init" "1" "$N_PASS"
assert_eq "zero secure_enclave enrollments after init" "0" "$N_SE"

CFG_SERVICE="$(toml_value "$CFG_FILE" service)"
CFG_ACCOUNT="$(toml_value "$CFG_FILE" account)"
CFG_STORE="$(toml_value "$CFG_FILE" store)"
if [[ -n "$CFG_SERVICE" && -n "$CFG_ACCOUNT" && -n "$CFG_STORE" ]]; then
  pass "read service/account/store back out of the generated config.toml"
else
  fail "could not read service/account/store out of $CFG_FILE"
fi
assert_eq "store lives under the dry home" "$HOT_CHEESE_HOME/store" "$CFG_STORE"
KEYRING_FILE="$CFG_STORE/keyring.json"

echo
echo "==> rewriting config.toml with the same service/account/store plus port and backup_remotes"
write_config "$CFG_SERVICE" "$CFG_ACCOUNT" ""
run_cmd p1_list_reparse "$BIN" list
assert_eq "the rewritten config.toml still parses" "0" "$RUN_RC"
assert_matches "the dry run configures NO backup remote, so nothing can be pushed off this Mac" \
  '^[[:space:]]*backup_remotes[[:space:]]*=[[:space:]]*\[\]' "$CFG_FILE"

phase "PHASE 2 — enroll se and the SAME-DEK invariant (3 passphrase, 1 Touch ID)"

echo "This is the phase that matters most. 'enroll se' must wrap the EXISTING DEK, not mint"
echo "a new one: if it re-minted, the keystore generated a moment earlier would stop opening."
echo "The proof is that the SAME key yields the SAME address before and after enrollment,"
echo "read once through the passphrase and once through the enclave."
echo
echo "The next three commands each ask for the recovery passphrase from phase 1."

run_cmd p2_generate "$BIN" generate evm "$EVM_KEY"
assert_eq "generate evm $EVM_KEY" "0" "$RUN_RC"
assert_contains "an unqualified generate declares the TIGHT use" "key_use=sign_only" "$RUN_LOG"

run_cmd p2_addr_pass "$BIN" address evm "$EVM_KEY"
assert_eq "address evm via the passphrase unlocker" "0" "$RUN_RC"
ADDR_PASS="$(lower "$(field_value "$RUN_LOG" addr)")"
assert_matches "passphrase-path address is a 0x EVM address" 'addr=0x[0-9a-f]{40}' "$RUN_LOG"

run_cmd p2_enroll_se "$BIN" enroll se
assert_eq "enroll se" "0" "$RUN_RC"

echo
echo "==> the SAME command again. It must now prompt TOUCH ID instead of the passphrase,"
echo "    because the keyring gained a Secure Enclave enrollment."
TAPS_EXPECTED=$((TAPS_EXPECTED + 1))
run_cmd p2_addr_se "$BIN" address evm "$EVM_KEY"
assert_eq "address evm via the Secure Enclave unlocker" "0" "$RUN_RC"
ADDR_SE="$(lower "$(field_value "$RUN_LOG" addr)")"

if [[ -n "$ADDR_PASS" ]]; then
  pass "captured the pre-enrollment address"
else
  fail "could not capture the pre-enrollment address"
fi
assert_eq "SAME-DEK INVARIANT: enroll se wrapped the existing DEK" "$ADDR_PASS" "$ADDR_SE"

SE_BLOB="$HOT_CHEESE_HOME/$SE_BLOB_NAME"
if [[ -f "$SE_BLOB" ]]; then
  pass "SE key blob written at $SE_BLOB"
else
  fail "SE key blob MISSING at $SE_BLOB"
fi
assert_file_mode "SE key blob is 600" "600" "$SE_BLOB"
BLOB_SIZE="$(stat -f '%z' "$SE_BLOB" 2>/dev/null || echo 0)"
if [[ "$BLOB_SIZE" -gt 0 && "$BLOB_SIZE" -lt 1024 ]]; then
  pass "SE key blob size $BLOB_SIZE is within the 1024-byte bound"
else
  fail "SE key blob size $BLOB_SIZE is outside (0,1024)"
fi
REAL_BLOBS="$(find "$REAL_HOME" -maxdepth 1 \( -name 'se_kek_*.blob' -o -name 'se_grant_*.blob' \) 2>/dev/null || true)"
assert_eq "no enclave blob appeared in the real home" "" "$REAL_BLOBS"

run_cmd p2_list "$BIN" list
N_PASS="$(grep -cE 'kind="?passphrase' "$RUN_LOG" || true)"
N_SE="$(grep -cE 'kind="?secure_enclave' "$RUN_LOG" || true)"
assert_eq "one passphrase enrollment survives as the recovery backstop" "1" "$N_PASS"
assert_eq "one secure_enclave enrollment was added" "1" "$N_SE"
assert_list_use "$RUN_LOG" "$EVM_KEY" "sign_only"

ANSWER="$(ask_tty "Did the LAST 'address evm' prompt Touch ID (t) or a recovery passphrase (p)? [t/p]")"
assert_eq "the unlocker switched to the Secure Enclave path" "t" "$(lower "$ANSWER")"

phase "PHASE 3 — declared key uses on real hardware (6 Touch ID)"

echo "A key now declares at birth whether it may EVER leave the daemon. sign-only is the"
echo "default and is a one-way door. This phase creates one of each, proves 'list' reports"
echo "the declared use, proves the door only turns one way, and then forges the flag on disk"
echo "to prove the header is bound into the AEAD and buys an attacker nothing."
TAPS_EXPECTED=$((TAPS_EXPECTED + 6))

run_cmd p3_gen_sol "$BIN" generate solana "$SOL_KEY"
assert_eq "generate solana $SOL_KEY" "0" "$RUN_RC"

run_cmd p3_addr_sol "$BIN" address solana "$SOL_KEY"
assert_eq "address solana $SOL_KEY" "0" "$RUN_RC"
SOL_ADDR="$(field_value "$RUN_LOG" addr)"
if [[ -n "$SOL_ADDR" ]]; then
  pass "solana pubkey is non-empty"
else
  fail "solana pubkey is empty"
fi
assert_matches "solana pubkey is base58" 'addr=[1-9A-HJ-NP-Za-km-z]{32,44}([[:space:]]|$)' "$RUN_LOG"

echo
echo "==> the ONE key in this run that a client may ever fetch over /read has to say so."
run_cmd p3_gen_share "$BIN" generate evm "$SHARE_KEY" --use shareable
assert_eq "generate evm $SHARE_KEY --use shareable" "0" "$RUN_RC"
assert_contains "the shareable use is echoed back at creation" "key_use=shareable" "$RUN_LOG"

run_cmd p3_addr_share "$BIN" address evm "$SHARE_KEY"
assert_eq "address evm $SHARE_KEY" "0" "$RUN_RC"
ADDR_SHARE="$(lower "$(field_value "$RUN_LOG" addr)")"
assert_matches "the shareable key has its own EVM address" 'addr=0x[0-9a-f]{40}' "$RUN_LOG"
if [[ -n "$ADDR_SHARE" && "$ADDR_SHARE" != "$ADDR_SE" ]]; then
  pass "the shareable key is a DIFFERENT key from the signing key"
else
  fail "the shareable key resolved to the same address as $EVM_KEY [share='$ADDR_SHARE']"
fi

echo
echo "==> importing an opaque secret. The prompt is hidden and reads /dev/tty, so it cannot"
echo "    be piped: type a SHORT throwaway string like 'dryrun-secret' and press Enter."
run_tty p3_add_bytes "$BIN" add "$BYTES_KEY" bytes
assert_eq "add $BYTES_KEY bytes" "0" "$RUN_RC"
assert_contains "an unqualified add declares the TIGHT use" "key_use=sign_only" "$RUN_LOG"

BYTES_FILE="$CFG_STORE/$BYTES_KEY"
SOL_FILE="$CFG_STORE/$SOL_KEY"
SHARE_FILE="$CFG_STORE/$SHARE_KEY"
assert_contains "$BYTES_KEY is stored as the AEAD envelope" '"cipher":"xchacha20poly1305"' "$BYTES_FILE"
assert_contains "$BYTES_KEY is a v2 keystore" '"v":2' "$BYTES_FILE"
assert_contains "$BYTES_KEY carries its use in cleartext" '"key_use":"sign_only"' "$BYTES_FILE"
assert_contains "$SHARE_KEY carries the loose use in cleartext" '"key_use":"shareable"' "$SHARE_FILE"

run_cmd p3_list "$BIN" list
assert_eq "list exit code" "0" "$RUN_RC"
assert_contains "list shows $EVM_KEY" "key=$EVM_KEY" "$RUN_LOG"
assert_contains "list shows $SOL_KEY" "key=$SOL_KEY" "$RUN_LOG"
assert_contains "list shows $SHARE_KEY" "key=$SHARE_KEY" "$RUN_LOG"
assert_contains "list shows $BYTES_KEY" "key=$BYTES_KEY" "$RUN_LOG"
assert_list_use "$RUN_LOG" "$EVM_KEY" "sign_only"
assert_list_use "$RUN_LOG" "$SOL_KEY" "sign_only"
assert_list_use "$RUN_LOG" "$BYTES_KEY" "sign_only"
assert_list_use "$RUN_LOG" "$SHARE_KEY" "shareable"
N_PASS="$(grep -cE 'kind="?passphrase' "$RUN_LOG" || true)"
N_SE="$(grep -cE 'kind="?secure_enclave' "$RUN_LOG" || true)"
assert_eq "still one passphrase enrollment" "1" "$N_PASS"
assert_eq "still one secure_enclave enrollment" "1" "$N_SE"

echo
echo "==> 3a: sign-only is a ONE-WAY door. Loosening it would mean exporting the key, so"
echo "    'seal' refuses from the cleartext header alone — no unlock, no biometric."
BIO_START="$(bio_window_start)"
assert_cmd_fails_with p3_seal_loosen "SealCannotLoosen" "$BIN" seal "$EVM_KEY" --use shareable
assert_contains "the refusal names the use it will not leave" "SignOnly" "$RUN_LOG"
assert_contains "and names the key it is protecting" "$EVM_KEY" "$RUN_LOG"

run_cmd p3_seal_noop "$BIN" seal "$SHARE_KEY" --use shareable
assert_eq "re-sealing a key under the use it already has exits 0" "0" "$RUN_RC"
assert_contains "and does nothing, so it never unlocks the DEK" "nothing to seal" "$RUN_LOG"
assert_taps "neither seal decision cost a biometric: both are read from cleartext headers" \
  "0" "$BIO_START"

echo
echo "==> 3b: the flag is TAMPER-EVIDENT. The cleartext header is free to lie — it is inside"
echo "    the body's AAD, so promoting sign_only to shareable on disk yields a file that"
echo "    nothing can open. The next command WILL ask for Touch ID and MUST then fail:"
echo "    the unlock succeeds and the AEAD refuses, which is the whole point."
SOL_SHA_BEFORE="$(shasum -a 256 "$SOL_FILE" 2>/dev/null | cut -d' ' -f1 || true)"
assert_contains "$SOL_KEY is sealed sign_only before the forgery" '"key_use":"sign_only"' "$SOL_FILE"
forge_key_use "$SOL_FILE" sign_only shareable
assert_contains "the on-disk header now claims shareable" '"key_use":"shareable"' "$SOL_FILE"

run_cmd p3_list_forged "$BIN" list
assert_eq "list still parses the forged file" "0" "$RUN_RC"
assert_list_use "$RUN_LOG" "$SOL_KEY" "shareable"
echo "  note  list believes the header, because reading a header decrypts nothing. Now decrypt."

BIO_START="$(bio_window_start)"
assert_cmd_fails_with p3_forged_addr "Aead" "$BIN" address solana "$SOL_KEY"
assert_taps "the forged key cost a REAL unlock and still refused to open" "1" "$BIO_START"

forge_key_use "$SOL_FILE" shareable sign_only
SOL_SHA_AFTER="$(shasum -a 256 "$SOL_FILE" 2>/dev/null | cut -d' ' -f1 || true)"
assert_eq "the restored keystore is byte-identical" "$SOL_SHA_BEFORE" "$SOL_SHA_AFTER"
run_cmd p3_list_restored "$BIN" list
assert_list_use "$RUN_LOG" "$SOL_KEY" "sign_only"

phase "PHASE 4 — the grant key serve refuses to start without (0 prompts)"

echo "Every signature now costs a per-payload grant: an enclave ECDSA signature over the exact"
echo "terms of ONE signature, verified against the public half config.toml pins. 'serve' checks"
echo "that pin before it binds anything, so a daemon that could not prove an approval never"
echo "starts. Enrolling the grant key prompts NOTHING — it wraps nothing and unwraps nothing."
BIO_PHASE="$(bio_window_start)"

if grep -qF "grant_public_key" "$CFG_FILE"; then
  fail "config.toml already pins a grant key, so the pre-enrollment refusal cannot be tested"
else
  pass "no grant key is pinned yet"
  echo
  echo "==> serve must refuse, name the command that fixes it, and never touch the port"
  assert_cmd_fails_with p4_serve_no_grant "GrantKeyMissingRunEnrollGrant" "$BIN" serve
  PORT_PIDS="$(port_pids)"
  assert_eq "the refused serve never bound the dry port" "" "$PORT_PIDS"
fi

if [[ -e "$HOT_CHEESE_HOME/$GRANT_BLOB_NAME" ]]; then
  fail "a grant blob already exists at $HOT_CHEESE_HOME/$GRANT_BLOB_NAME"
else
  pass "no grant blob exists yet"
fi

echo
echo "==> enroll grant: creates this machine's enclave signing key and pins its public half"
run_cmd p4_enroll_grant "$BIN" enroll grant
assert_eq "enroll grant exit code" "0" "$RUN_RC"
assert_contains "enroll grant reports the pin it wrote" "pinned it in config.toml" "$RUN_LOG"
GRANT_LOGGED="$(field_value "$RUN_LOG" grant_public_key)"
CFG_GRANT_PUB="$(toml_value "$CFG_FILE" grant_public_key)"
assert_matches "config.toml now pins an uncompressed SEC1 point" \
  '^[[:space:]]*grant_public_key[[:space:]]*=[[:space:]]*"04[0-9a-f]{128}"' "$CFG_FILE"
assert_eq "the pin on disk is the one enroll grant printed" "$GRANT_LOGGED" "$CFG_GRANT_PUB"

GRANT_BLOB="$HOT_CHEESE_HOME/$GRANT_BLOB_NAME"
if [[ -f "$GRANT_BLOB" ]]; then
  pass "grant key blob written at $GRANT_BLOB"
else
  fail "grant key blob MISSING at $GRANT_BLOB"
fi
assert_file_mode "grant key blob is 600" "600" "$GRANT_BLOB"
GRANT_SIZE="$(stat -f '%z' "$GRANT_BLOB" 2>/dev/null || echo 0)"
if [[ "$GRANT_SIZE" -gt 0 && "$GRANT_SIZE" -lt 1024 ]]; then
  pass "grant key blob size $GRANT_SIZE is within the 1024-byte bound"
else
  fail "grant key blob size $GRANT_SIZE is outside (0,1024)"
fi
if [[ -f "$SE_BLOB" ]] && ! cmp -s "$SE_BLOB" "$GRANT_BLOB"; then
  pass "the grant key is a SECOND, independent enclave key, not the unlock key reused"
else
  fail "the grant blob and the KEK blob are the same bytes"
fi

echo
echo "==> and the pin is an identity check, not a shape check: point it at another valid"
echo "    P-256 public key and serve must still refuse."
write_config "$CFG_SERVICE" "$CFG_ACCOUNT" "$FOREIGN_GRANT_PUB"
assert_cmd_fails_with p4_serve_wrong_pin "GrantKeyPinMismatch" "$BIN" serve
assert_contains "the mismatch names the key it expected" "$FOREIGN_GRANT_PUB" "$RUN_LOG"
PORT_PIDS="$(port_pids)"
assert_eq "the mismatched serve never bound the dry port either" "" "$PORT_PIDS"

write_config "$CFG_SERVICE" "$CFG_ACCOUNT" "$CFG_GRANT_PUB"
assert_eq "the honest pin is back in config.toml" "$CFG_GRANT_PUB" "$(toml_value "$CFG_FILE" grant_public_key)"
assert_taps "the entire grant phase cost ZERO biometrics" "0" "$BIO_PHASE"
echo "  note  'serve succeeds once the grant key is enrolled' is phase 6; that the pinned key"
echo "  note  actually VERIFIES an enclave grant is phase 5, which cannot sign without one."

phase "PHASE 5 — scoped signing (1 Touch ID; every denial costs 0)"

echo "Policy load and evaluation, and the grant pin lookup, all run BEFORE the approval sheet,"
echo "so the six refusals below cost no biometric at all."
POLICY_DIR="$CFG_STORE/policies"
POLICY_FILE="$POLICY_DIR/$EVM_KEY.toml"
INTENT_OK="$OUT_DIR/intent_ok.json"
INTENT_DRAIN="$OUT_DIR/intent_drain.json"
INTENT_BAD_TO="$OUT_DIR/intent_bad_to.json"
INTENT_BAD_CHAIN="$OUT_DIR/intent_bad_chain.json"

cat > "$INTENT_OK" <<JSON
{
  "kind": "safe_tx",
  "key": "$EVM_KEY",
  "safe": "$SAFE_ADDR",
  "chain_id": "1",
  "to": "$TOKEN_ADDR",
  "value": "0",
  "data": "$TRANSFER_DATA",
  "operation": "call",
  "safe_tx_gas": "0",
  "base_gas": "0",
  "gas_price": "0",
  "gas_token": "$ZERO_ADDR",
  "refund_receiver": "$ZERO_ADDR",
  "nonce": "0"
}
JSON

cat > "$INTENT_DRAIN" <<JSON
{
  "kind": "safe_tx",
  "key": "$EVM_KEY",
  "safe": "$SAFE_ADDR",
  "chain_id": "1",
  "to": "$TOKEN_ADDR",
  "value": "0",
  "data": "$TRANSFER_DATA",
  "operation": "call",
  "safe_tx_gas": "0",
  "base_gas": "1000000",
  "gas_price": "1",
  "gas_token": "$GAS_TOKEN_ADDR",
  "refund_receiver": "$ATTACKER_ADDR",
  "nonce": "0"
}
JSON

cat > "$INTENT_BAD_TO" <<JSON
{
  "kind": "safe_tx",
  "key": "$EVM_KEY",
  "safe": "$SAFE_ADDR",
  "chain_id": "1",
  "to": "$OTHER_ADDR",
  "value": "0",
  "data": "$TRANSFER_DATA",
  "operation": "call",
  "safe_tx_gas": "0",
  "base_gas": "0",
  "gas_price": "0",
  "gas_token": "$ZERO_ADDR",
  "refund_receiver": "$ZERO_ADDR",
  "nonce": "0"
}
JSON

cat > "$INTENT_BAD_CHAIN" <<JSON
{
  "kind": "safe_tx",
  "key": "$EVM_KEY",
  "safe": "$SAFE_ADDR",
  "chain_id": "137",
  "to": "$TOKEN_ADDR",
  "value": "0",
  "data": "$TRANSFER_DATA",
  "operation": "call",
  "safe_tx_gas": "0",
  "base_gas": "0",
  "gas_price": "0",
  "gas_token": "$ZERO_ADDR",
  "refund_receiver": "$ZERO_ADDR",
  "nonce": "0"
}
JSON

echo
echo "==> 5a: no policy file at all. Deny by default: a perfectly valid intent must still fail."
BIO_PHASE="$(bio_window_start)"
if [[ -e "$POLICY_FILE" ]]; then
  fail "a policy file already exists at $POLICY_FILE"
fi
assert_cmd_fails_with p5a_no_policy "Policy(Io(" "$BIN" sign --file "$INTENT_OK"
assert_not_contains "5a showed no approval banner" "policy: ALLOWED" "$RUN_LOG"

echo
echo "==> 5b: a policy WITHOUT chain_id must fail to LOAD. This is exactly what a stale"
echo "    production policy file will do at cutover — the cross-chain replay pin is mandatory."
mkdir -p "$POLICY_DIR"
cat > "$POLICY_FILE" <<TOML
safe = "$SAFE_ADDR"

[[allow]]
to = "$TOKEN_ADDR"
selectors = ["0xa9059cbb"]
max_value = "0"
operation = "call"
TOML
assert_cmd_fails_with p5b_no_chain_id "Policy(Toml(" "$BIN" sign --file "$INTENT_OK"
assert_not_contains "5b showed no approval banner" "policy: ALLOWED" "$RUN_LOG"

echo
echo "==> 5c: the good policy, then the allowed transfer."
cat > "$POLICY_FILE" <<TOML
safe = "$SAFE_ADDR"
chain_id = 1

[[allow]]
to = "$TOKEN_ADDR"
selectors = ["0xa9059cbb"]
max_value = "0"
operation = "call"
TOML
echo "    Read the decoded summary, then type y and press Enter. ONE Touch ID sheet follows,"
echo "    and that single biometric does THREE enclave things: it mints the per-payload grant,"
echo "    it lets the grant verify, and it unlocks the key. Only {r,s,v} comes back."
TAPS_EXPECTED=$((TAPS_EXPECTED + 1))
BIO_START="$(bio_window_start)"
run_tty p5c_sign_ok "$BIN" sign --file "$INTENT_OK"
assert_eq "sign exit code" "0" "$RUN_RC"
assert_contains "policy reported ALLOWED" "policy: ALLOWED" "$RUN_LOG"
assert_matches "safe_tx_hash is 0x + 64 hex" '"safe_tx_hash":"0x[0-9a-f]{64}"' "$RUN_LOG"
assert_matches "signature is 0x + 130 hex" '"signature":"0x[0-9a-f]{130}"' "$RUN_LOG"
SIGNER="$(grep -o '"signer":"0x[0-9a-fA-F]*"' "$RUN_LOG" | head -1 | cut -d'"' -f4 || true)"
assert_eq "the signer is $EVM_KEY's address" "$ADDR_SE" "$(lower "$SIGNER")"
echo "  note  a signature exists at all only because the enclave grant verified under the"
echo "  note  pinned public key: sign takes the verified grant BY VALUE and cannot be reached"
echo "  note  without one, so this is the hardware proof phase 4 could not take on its own."

assert_taps "one sign, one sheet: the grant signature AND the key unlock reused the approval (2+ means the reuse broke)" \
  "1" "$BIO_START"

echo
echo "==> 5d: the gas-refund DRAIN. Allowed 'to', allowed selector, value 0 — and it still"
echo "    drains the Safe through the refund fields. Fail-closed without a [refunds] opt-in."
assert_cmd_fails_with p5d_drain "RefundNotAllowed" "$BIN" sign --file "$INTENT_DRAIN"
assert_not_contains "5d showed no approval banner" "policy: ALLOWED" "$RUN_LOG"

echo
echo "==> 5e: a destination outside the allow-list."
assert_cmd_fails_with p5e_bad_to "ToNotAllowed" "$BIN" sign --file "$INTENT_BAD_TO"
assert_not_contains "5e showed no approval banner" "policy: ALLOWED" "$RUN_LOG"

echo
echo "==> 5f: the right Safe on the wrong chain."
assert_cmd_fails_with p5f_bad_chain "ChainMismatch" "$BIN" sign --file "$INTENT_BAD_CHAIN"
assert_not_contains "5f showed no approval banner" "policy: ALLOWED" "$RUN_LOG"

echo
echo "==> 5g: the same allowed intent with the grant pin removed from config.toml. There is"
echo "    nothing left to verify an approval against, so it must die BEFORE the human is asked."
write_config "$CFG_SERVICE" "$CFG_ACCOUNT" ""
assert_cmd_fails_with p5g_no_pin "NoPinnedGrantKey" "$BIN" sign --file "$INTENT_OK"
assert_not_contains "5g showed no approval banner" "policy: ALLOWED" "$RUN_LOG"
write_config "$CFG_SERVICE" "$CFG_ACCOUNT" "$CFG_GRANT_PUB"
assert_eq "the honest pin is back in config.toml" "$CFG_GRANT_PUB" "$(toml_value "$CFG_FILE" grant_public_key)"

assert_taps "the whole of phase 5 cost one sheet: all six refusals cost no biometric" \
  "1" "$BIO_PHASE"

if [[ -n "$SKIP_SERVE" ]]; then
  phase "PHASE 6 — SKIPPED (SKIP_SERVE is set)"
  echo "The live daemon, TLS pinning, the export refusal and the /read path were NOT exercised."
else
  phase "PHASE 6 — serve, the export refusal, and one live /read (1 Touch ID, two terminals)"

  echo "The daemon is NEVER backgrounded by this script. You run it, you stop it. It starts"
  echo "at all only because phase 4 enrolled the grant key it refused to run without."
  echo
  echo "  1. Open a SECOND terminal."
  echo "  2. Paste EXACTLY this — the tee is REQUIRED, this phase reads the daemon's own log —"
  echo "     and leave it running in the foreground:"
  echo
  echo "     HOT_CHEESE_HOME=\"$HOT_CHEESE_HOME\" NO_COLOR=1 \"$BIN\" serve 2>&1 | tee \"$SERVE_LOG\""
  echo
  echo "  3. Wait for the 'hot_cheese serving over https' line."
  ANSWER="$(ask_tty "Press Enter here once serve is running in terminal B.")"

  PORT_PIDS="$(port_pids)"
  if [[ -n "$PORT_PIDS" ]]; then
    pass "the daemon is listening on 127.0.0.1:$DRY_PORT (pid(s): $PORT_PIDS)"
  else
    fail "nothing is listening on 127.0.0.1:$DRY_PORT — did serve start, and is port=$DRY_PORT in the dry config.toml?"
  fi
  if [[ -f "$SERVE_LOG" ]]; then
    pass "the daemon's log is being teed to $SERVE_LOG"
  else
    fail "no daemon log at $SERVE_LOG — terminal B must run the EXACT command above, tee included"
  fi
  assert_contains "the daemon got past the grant gate and bound the socket" \
    "hot_cheese serving over https" "$SERVE_LOG"

  echo
  echo "==> /health is the ONLY endpoint that does not decrypt a key. No prompt."
  run_cmd p6_health curl -sS --cacert "$CERT_INSTALLED" \
    "https://127.0.0.1:$DRY_PORT/health"
  assert_eq "curl /health exit code" "0" "$RUN_RC"
  assert_contains "/health answered ok over the pinned TLS cert" "ok" "$RUN_LOG"

  echo
  echo "==> the assertion this whole feature exists for: /read of a SIGN-ONLY key. The permit"
  echo "    is minted from the cleartext header before anything unlocks, so the refusal is"
  echo "    structural and FREE. Nobody's finger is spent telling an attacker no."
  BIO_START="$(bio_window_start)"
  run_cmd p6_read_signonly cargo run --release --manifest-path "$PIN_CERT_MANIFEST" \
    --example pin_cert -- "https://127.0.0.1:$DRY_PORT" "$EVM_KEY"
  if [[ "$RUN_RC" -eq 0 ]]; then
    fail "/read HANDED OUT the sign-only key $EVM_KEY"
  else
    pass "/read of the sign-only key $EVM_KEY exited $RUN_RC"
  fi
  assert_contains "the client got an error status, not a secret" "500" "$RUN_LOG"
  assert_not_contains "the client printed no secret length" "len=" "$RUN_LOG"
  assert_contains "the daemon refused it as ExportRefused" "ExportRefused" "$SERVE_LOG"
  assert_contains "and named the use that refused" "SignOnly" "$SERVE_LOG"
  assert_taps "THE EXPORT REFUSAL COST ZERO TOUCH ID SHEETS" "0" "$BIO_START"

  echo
  echo "==> now the same read against the key that DECLARED itself shareable. ONE Touch ID"
  echo "    sheet, raised by the daemon in terminal B. The key is encrypted end-to-end to the"
  echo "    client process: the client prints only its length and digest, never the bytes."
  TAPS_EXPECTED=$((TAPS_EXPECTED + 1))
  BIO_START="$(bio_window_start)"
  run_cmd p6_pin_cert cargo run --release --manifest-path "$PIN_CERT_MANIFEST" \
    --example pin_cert -- "https://127.0.0.1:$DRY_PORT" "$SHARE_KEY"
  assert_eq "pin_cert exit code" "0" "$RUN_RC"
  assert_contains "the read returned a 32-byte secret" "len=32" "$RUN_LOG"
  assert_contains "the client printed a salted digest of the secret" "digest=" "$RUN_LOG"
  PIN_ADDR="$(field_value "$RUN_LOG" evm_address)"
  assert_eq "the live daemon served the SHAREABLE key, and the same one the CLI reports" \
    "$ADDR_SHARE" "$(lower "$PIN_ADDR")"
  echo "  note  the digest is salted and truncated to 8 hex, so the longest hex run the client may"
  echo "  note  legitimately print is the 40-char EVM address. Anything longer is raw key bytes."
  if grep -qE '[0-9a-fA-F]{41}' "$RUN_LOG"; then
    fail "the client output contains a hex run longer than an EVM address — a private key may have been printed: $RUN_LOG"
  else
    pass "the client output contains no hex run longer than an EVM address"
  fi

  assert_taps "one live /read of a shareable key costs exactly one biometric" "1" "$BIO_START"
  echo "  note  this read succeeding after the refusal is also how you know the refusal did not"
  echo "  note  take the daemon down with it: one refused export is not a denial of service."

  echo
  echo "==> now stop it: press Ctrl-C in terminal B."
  ANSWER="$(ask_tty "Press Enter here once terminal B has exited.")"
  echo "  ...  polling port $DRY_PORT for up to 10s; a Ctrl-C'd daemon needs a moment to let go"
  PORT_PIDS="$(port_pids)"
  POLLS=0
  while [[ -n "$PORT_PIDS" && "$POLLS" -lt 20 ]]; do
    sleep 0.5
    POLLS=$((POLLS + 1))
    PORT_PIDS="$(port_pids)"
  done
  if [[ -z "$PORT_PIDS" ]]; then
    pass "port $DRY_PORT is free again"
  else
    fail "port $DRY_PORT is STILL held 10s after terminal B was reported gone, pid(s): $PORT_PIDS"
    echo "  FAIL  this script will NOT kill it: it could be your real daemon. Inspect it with:"
    echo "  FAIL      ps -p $PORT_PIDS -o pid,command"
    echo "  FAIL  and stop it yourself."
  fi
fi

phase "PHASE 7 — Secure-Enclave loss and the recovery backstop (0 Touch ID, 1 passphrase)"

echo "An enclave key dies with its Mac: a logic board swap, a wiped machine, a rotated"
echo "fingerprint set. This phase removes the SE blob and proves the failure is loud, typed,"
echo "and silent — no fallback prompt, no fallback tap, no partial read. Then it proves the"
echo "recovery passphrase still opens the same DEK with the enclave key gone."

SE_BLOB_ASIDE="$OUT_DIR/se_kek.blob.aside"
BLOB_SHA_BEFORE="$(shasum -a 256 "$SE_BLOB" 2>/dev/null | cut -d' ' -f1 || true)"
mv "$SE_BLOB" "$SE_BLOB_ASIDE"
if [[ -e "$SE_BLOB" ]]; then
  fail "the SE blob is still in place at $SE_BLOB"
else
  pass "SE blob moved aside; the enclave key is now unreachable"
fi

echo
echo "==> the next command must fail immediately and in silence. If a passphrase prompt does"
echo "    appear, that is the failure: press Ctrl-D to close it and answer the question below."
BIO_START="$(bio_window_start)"
assert_cmd_fails_with p7_no_se "SeKeyUnavailableTryUnlockPassphrase" "$BIN" address evm "$EVM_KEY"
assert_taps "the SE-loss failure raised no Touch ID sheet" "0" "$BIO_START"
echo
echo "==> the error must also POINT AT the recovery route. An error that only says a key is"
echo "    missing strands an operator who does hold the passphrase."
if grep -qi 'passphrase' "$RUN_LOG"; then
  pass "the failure names the recovery-passphrase escape hatch"
else
  fail "the failure does NOT name the recovery passphrase — an operator holding it is told only that a key is gone"
fi

ANSWER="$(ask_tty "That command failed. Did it STOP and print a 'Recovery passphrase:' prompt waiting for you to type? Expected: no, it failed instantly. [y/N]")"
assert_eq "the SE-loss failure never falls back to a passphrase prompt" "n" "$(lower "${ANSWER:-n}")"

echo
echo "==> now the escape hatch itself, with the enclave key still missing. This one SHOULD"
echo "    ask for the phase-1 recovery passphrase."
run_tty p7_pass_unlock "$BIN" --unlock passphrase address evm "$EVM_KEY"
assert_eq "the passphrase escape hatch exits 0 with no enclave key" "0" "$RUN_RC"
assert_eq "it recovers the same address" "$ADDR_SE" "$(lower "$(field_value "$RUN_LOG" addr)")"

mv "$SE_BLOB_ASIDE" "$SE_BLOB"
BLOB_SHA_AFTER="$(shasum -a 256 "$SE_BLOB" 2>/dev/null | cut -d' ' -f1 || true)"
assert_eq "the restored SE blob is byte-identical" "$BLOB_SHA_BEFORE" "$BLOB_SHA_AFTER"

phase "PHASE 8 — vault-namespaced backup, read entirely locally (0 prompts, no ssh, no rsync)"

echo "Backups are namespaced per install: a push lands in <folder>/<vault_id>/, so two Macs"
echo "with DIFFERENT DEKs can share one backup host without overwriting each other. The vault"
echo "id is cleartext in keyring.json, which is why a push never has to unlock anything."
echo "This phase touches NO network: it reads the id three independent ways and checks the"
echo "commands that would reach a remote refuse outright when none is configured."
BIO_PHASE="$(bio_window_start)"

assert_matches "keyring.json carries a v_<32 hex> vault id, in cleartext" \
  '"vault_id"[[:space:]]*:[[:space:]]*"v_[0-9a-f]{32}"' "$KEYRING_FILE"
VAULT_KEYRING="$(grep -oE 'v_[0-9a-f]{32}' "$KEYRING_FILE" | head -1 || true)"
assert_eq "the vault id on disk is the one init minted, unchanged by every command since" \
  "$VAULT_INIT" "$VAULT_KEYRING"

assert_cmd_fails_with p8_adopt "VaultAlreadyAdopted" "$BIN" backup adopt
assert_contains "the refusal names this install's own vault id" "$VAULT_KEYRING" "$RUN_LOG"

echo
echo "==> with backup_remotes = [] there is nothing to talk to, and both remote-reading"
echo "    subcommands must say so instead of guessing a host."
assert_cmd_fails_with p8_list "NoBackupRemote" "$BIN" backup list
assert_cmd_fails_with p8_pull "NoBackupRemote" "$BIN" backup pull

PUSH_TARGET="$EXAMPLE_FOLDER/$VAULT_KEYRING/"
echo
echo "  note  no remote is configured here, so nothing is pushed anywhere. With a remote whose"
echo "  note  folder is '$EXAMPLE_FOLDER', THIS install's store would replicate into:"
echo "  note      <host>:~/$PUSH_TARGET"
if [[ "$PUSH_TARGET" =~ ^[A-Za-z0-9_.-]+/v_[0-9a-f]{32}/$ ]]; then
  pass "a push target composed from this config + this keyring is <folder>/<vault_id>/"
else
  fail "the composed push target is not <folder>/<vault_id>/ [got='$PUSH_TARGET']"
fi
assert_taps "the whole backup phase cost zero biometrics" "0" "$BIO_PHASE"

if [[ -n "$RUN_MIGRATE" ]]; then
  phase "PHASE M — migrate rehearsal (2 Touch ID + 1 login-keychain dialog)"

  echo "This rehearses MIGRATION.md §5 against a SYNTHETIC legacy store built from the repo's"
  echo "own test fixture. It does not touch any real legacy store. The fixture is copied under"
  echo "TWO names so one run proves both halves of the cutover rule: a key you name with"
  echo "--shareable stays fetchable over /read, and every key you DON'T name is sealed"
  echo "sign-only forever."
  echo
  echo "IT WILL WRITE ONE ITEM TO YOUR LOGIN KEYCHAIN:"
  echo "    service = $MIG_SERVICE"
  echo "    account = $MIG_ACCOUNT"
  echo "    secret  = the PUBLIC test-fixture password from ${LEGACY_FIXTURE:-test-keys/key-scrypt.json}"
  echo "That is NOT the production $CFG_SERVICE / $CFG_ACCOUNT pair. This phase DELETES the"
  echo "item at the end and asserts it is gone."
  echo
  echo "Expect: one Touch ID sheet to authorize reading the legacy master, one macOS dialog"
  echo "asking to allow hot_cheese access to that keychain item, then one Touch ID sheet to"
  echo "unlock the new DEK through the enclave."
  TAPS_EXPECTED=$((TAPS_EXPECTED + 2))

  if [[ "$MIG_SERVICE" == "$CFG_SERVICE" || "$MIG_ACCOUNT" == "$CFG_ACCOUNT" ]]; then
    fail "the dry-run keychain identity collides with the production one; refusing to touch the keychain"
  elif [[ -z "$LEGACY_FIXTURE" ]]; then
    fail "legacy fixture test-keys/key-scrypt.json not found in this checkout"
  elif security find-generic-password -s "$MIG_SERVICE" -a "$MIG_ACCOUNT" > /dev/null 2>&1; then
    fail "a keychain item named $MIG_SERVICE/$MIG_ACCOUNT already exists; refusing to overwrite or delete it"
  else
    MIG_ROOT="$HOT_CHEESE_HOME/migrate_rehearsal"
    MIG_OLD="$MIG_ROOT/old_store"
    MIG_NEW="$MIG_ROOT/new_store"
    mkdir -p "$MIG_OLD"
    cp "$LEGACY_FIXTURE" "$MIG_OLD/$LEGACY_KEY_NAME"
    cp "$LEGACY_FIXTURE" "$MIG_OLD/$LEGACY_SHARE_NAME"
    snapshot_dir "$MIG_OLD" "$SNAP_DIR/legacy_before.list" "$SNAP_DIR/legacy_before.hashes"

    echo "  ---> security add-generic-password -s $MIG_SERVICE -a $MIG_ACCOUNT -w <fixture>"
    if security add-generic-password -s "$MIG_SERVICE" -a "$MIG_ACCOUNT" \
      -w "$LEGACY_PASSWORD" > "$OUT_DIR/pm_keychain_add.log" 2>&1; then
      pass "wrote the throwaway legacy master to the login keychain"
    else
      fail "could not write the throwaway keychain item (see $OUT_DIR/pm_keychain_add.log)"
    fi

    write_config "$MIG_SERVICE" "$MIG_ACCOUNT" "$CFG_GRANT_PUB"
    run_cmd pm_migrate "$BIN" migrate --old-store "$MIG_OLD" --new-store "$MIG_NEW" \
      --shareable "$LEGACY_SHARE_NAME"
    assert_eq "migrate exit code" "0" "$RUN_RC"
    assert_contains "migrate reported the unnamed fixture key" "name=$LEGACY_KEY_NAME" "$RUN_LOG"
    assert_contains "migrate reported the named fixture key" "name=$LEGACY_SHARE_NAME" "$RUN_LOG"
    assert_contains "the migrated identity matches the fixture's known EVM address" \
      "identity=$LEGACY_EXPECTED_ADDR" "$RUN_LOG"
    assert_matches "the key nobody named was sealed sign_only, permanently" \
      "name=$LEGACY_KEY_NAME .*key_use=sign_only" "$RUN_LOG"
    assert_matches "the key named --shareable stayed fetchable" \
      "name=$LEGACY_SHARE_NAME .*key_use=shareable" "$RUN_LOG"

    snapshot_dir "$MIG_OLD" "$SNAP_DIR/legacy_after.list" "$SNAP_DIR/legacy_after.hashes"
    if cmp -s "$SNAP_DIR/legacy_before.hashes" "$SNAP_DIR/legacy_after.hashes"; then
      pass "the legacy store is byte-for-byte unchanged"
    else
      fail "THE LEGACY STORE WAS MODIFIED — migrate must never write to --old-store"
    fi
    if [[ -e "$MIG_NEW.staging" ]]; then
      fail "a staging dir survived the run: $MIG_NEW.staging"
    else
      pass "no staging dir remains"
    fi
    assert_contains "the migrated key is a real envelope file" \
      '"cipher":"xchacha20poly1305"' "$MIG_NEW/$LEGACY_KEY_NAME"
    assert_contains "and its use is bound in cleartext" \
      '"key_use":"sign_only"' "$MIG_NEW/$LEGACY_KEY_NAME"
    assert_contains "as is the named key's" \
      '"key_use":"shareable"' "$MIG_NEW/$LEGACY_SHARE_NAME"

    run_cmd pm_keychain_del security delete-generic-password \
      -s "$MIG_SERVICE" -a "$MIG_ACCOUNT"
    assert_eq "deleted the throwaway keychain item" "0" "$RUN_RC"
    if security find-generic-password -s "$MIG_SERVICE" -a "$MIG_ACCOUNT" > /dev/null 2>&1; then
      fail "the throwaway keychain item $MIG_SERVICE/$MIG_ACCOUNT IS STILL PRESENT — delete it by hand"
    else
      pass "the throwaway keychain item is gone"
    fi

    write_config "$CFG_SERVICE" "$CFG_ACCOUNT" "$CFG_GRANT_PUB"
  fi
fi

phase "PHASE 9 — teardown (0 prompts)"

LOG_KEEP="${TMPDIR:-/tmp}/hot_cheese_dryrun_logs_$$"
if [[ -d "$OUT_DIR" ]]; then
  rm -rf "$LOG_KEEP"
  mkdir -p "$LOG_KEEP"
  cp -R "$OUT_DIR/." "$LOG_KEEP/" 2>/dev/null || true
  echo "  note  command logs copied out of the dry home to $LOG_KEEP"
fi

rm -rf "$HOT_CHEESE_HOME"
if [[ -e "$HOT_CHEESE_HOME" ]]; then
  fail "the dry home survived teardown: $HOT_CHEESE_HOME"
else
  pass "dry home removed"
fi

HOME_DIFF=0
snapshot_dir "$REAL_HOME" "$SNAP_DIR/after.list" "$SNAP_DIR/after.hashes"
if cmp -s "$SNAP_DIR/before.list" "$SNAP_DIR/after.list"; then
  pass "the real home's file list is unchanged"
else
  HOME_DIFF=1
  fail "THE REAL HOME'S FILE LIST CHANGED — compare $SNAP_DIR/before.list and $SNAP_DIR/after.list"
fi
if cmp -s "$SNAP_DIR/before.hashes" "$SNAP_DIR/after.hashes"; then
  pass "the real home's file hashes are unchanged"
else
  HOME_DIFF=1
  fail "THE REAL HOME'S FILE HASHES CHANGED — compare $SNAP_DIR/before.hashes and $SNAP_DIR/after.hashes"
fi

REAL_BLOBS="$(find "$REAL_HOME" -maxdepth 1 \( -name 'se_kek_*.blob' -o -name 'se_grant_*.blob' \) 2>/dev/null || true)"
assert_eq "no se_kek_*.blob or se_grant_*.blob in the real home" "" "$REAL_BLOBS"

PORT_PIDS="$(port_pids)"
if [[ -z "$PORT_PIDS" ]]; then
  pass "dry port $DRY_PORT is free"
else
  fail "dry port $DRY_PORT still has listener pid(s): $PORT_PIDS — stop it yourself, this script never kills processes"
fi

echo "  note  the keychain check below queries generic-password items by service and by label;"
echo "  note  it deliberately does not dump the keychain, which would raise access dialogs."
for label in "$SE_LABEL" "$GRANT_LABEL"; do
  if security find-generic-password -s "$label" > /dev/null 2>&1; then
    fail "a login-keychain generic password exists with service $label"
  else
    pass "no login-keychain generic password with service $label"
  fi
  if security find-generic-password -l "$label" > /dev/null 2>&1; then
    fail "a login-keychain generic password exists with label $label"
  else
    pass "no login-keychain generic password with label $label"
  fi
done

if [[ "$HOME_DIFF" -eq 0 ]]; then
  rm -rf "$SNAP_DIR"
  pass "snapshot dir removed"
else
  echo "  note  KEEPING $SNAP_DIR so you can diff the before/after listings yourself"
fi

phase "SUMMARY"
echo "  PASSED: $PASS_COUNT"
echo "  FAILED: $FAIL_COUNT"
echo "  command logs: ${LOG_KEEP:-none}"
echo "  Touch ID expected for the phases actually run: $TAPS_EXPECTED"
if [[ -n "$BIO_LOG" ]]; then
  echo "  Touch ID counted in the log since this run started: $(bio_taps_since "$RUN_START")"
  echo "  note  that window is the whole run, so a sheet raised by any other app lands in it too;"
  echo "  note  the per-command counts above are the ones that assert anything."
fi
echo
if [[ "$FAIL_COUNT" -eq 0 ]]; then
  echo "  DRY RUN CLEAN. The enclave path, the envelope, the declared key uses, the grant gate,"
  echo "  the policy gate, the daemon, the vault namespace and the teardown all behaved."
  echo "  Proceed with MIGRATION.md against the real home."
  exit 0
fi
echo "  DRY RUN FAILED with $FAIL_COUNT failure(s). Do NOT migrate production keys yet."
exit 1
