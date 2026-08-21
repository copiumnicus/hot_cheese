#!/usr/bin/env bash
set -euo pipefail
export NO_COLOR=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

BIN="$REPO_ROOT/target/release/hot_cheese"
DRY_PORT="${DRY_PORT:-5599}"
DRY_LOG_DIR="${DRY_LOG_DIR:-$REPO_ROOT/dryrun-logs}"
SKIP_SELFTEST="${SKIP_SELFTEST:-}"
SKIP_SERVE="${SKIP_SERVE:-}"
RUN_MIGRATE="${RUN_MIGRATE:-}"
HC_DRYRUN_ALLOW_ANY_PATH="${HC_DRYRUN_ALLOW_ANY_PATH:-}"
FROM_PHASE="${FROM_PHASE:-}"
ONLY_PHASES="${ONLY_PHASES:-}"
DRY_APPROVAL_SECS="${DRY_APPROVAL_SECS:-20}"
PTY_SETTLE_SECS="${PTY_SETTLE_SECS:-0.6}"

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
TRANSFER_TO_ATTACKER="0xa9059cbb0000000000000000000000005555555555555555555555555555555555555555000000000000000000000000000000000000000000000000000000000000000a"
UNDECLARED_DATA="0xdeadbeef0000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000a"

FOREIGN_GRANT_PUB="046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
EXAMPLE_FOLDER="hot_cheese_store"

GRANT_HEADER_NAME="x-hot-cheese-read-grant"
GRANT_ENV_NAME="HOT_CHEESE_READ_GRANT"
READ_PROBE_PUBK="0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
JUNK_GRANT_TOKEN="11111111111111111111111111111111"
DISCARD_PHRASE="discard this unrecorded hot_cheese enclave key"
ACCEPT_DELETION_PHRASE="record the loss of these hot_cheese files"
PULL_REWIND_PHRASE="roll this store back"
PULL_LOST_ENROLLMENTS_PHRASE="give up every unlock path on this machine"
TOUCH_ID_BUDGET=15
PASSPHRASE_BUDGET=6
STARTLE_BANNER="*** THE SCREEN CHANGED"
EXPIRED_LINE="denying a request the operator never answered"
UNATTRIBUTED_LINE="an answer that did not carry the request number denied it"
GRANT_RELEASE_LINE="released a key on a read grant: nobody was asked to approve it"

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
LOG_KEEP=""
LOGS_KEPT=""
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
BUNDLE_HASH=""
GRANT_TOKEN=""
GRANT_FILE=""
GRANT_DIR=""
REAL_ARCHIVE=""
DRY_ARCHIVE=""
LAST_READ_SEQ=""
CFG_APPROVAL_SECS=""
ALL_PHASES="0 1 2 3 4 5 6 7 8 9"
PHASES=""
PARTIAL_RUN=""
STATE_FILE=""
STATE_VARS="FINGERPRINT VAULT_INIT CERT_INSTALLED KEY_INSTALLED CFG_SERVICE CFG_ACCOUNT CFG_STORE KEYRING_FILE ADDR_PASS ADDR_SE SE_KEY_FP SE_BLOB SOL_ADDR ADDR_SHARE BYTES_FILE SOL_FILE SHARE_FILE GRANT_TOKEN GRANT_FILE CFG_GRANT_PUB TAPS_EXPECTED"
GUARD_DIR=""
GUARD_PID=""
SERVE_PID=""
SERVE_PID_FILE=""
SERVE_TEE_PID=""
SERVE_FIFO=""
RUN_INTERRUPTED=""
TORN_DOWN=""
APPROVAL_MAX_SECS=$((DRY_APPROVAL_SECS + DRY_APPROVAL_SECS / 3))

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

select_phases() {
  local wanted="" p=""
  if [[ -n "$ONLY_PHASES" && -n "$FROM_PHASE" ]]; then
    fatal "set ONLY_PHASES or FROM_PHASE, not both"
  fi
  if [[ -n "$ONLY_PHASES" ]]; then
    for p in ${ONLY_PHASES//,/ }; do
      case " $ALL_PHASES " in
        *" $p "*) wanted="$wanted$p " ;;
        *) fatal "ONLY_PHASES names '$p'; the phases are: $ALL_PHASES" ;;
      esac
    done
    PARTIAL_RUN=1
  elif [[ -n "$FROM_PHASE" ]]; then
    case " $ALL_PHASES " in
      *" $FROM_PHASE "*) ;;
      *) fatal "FROM_PHASE is '$FROM_PHASE'; the phases are: $ALL_PHASES" ;;
    esac
    for p in $ALL_PHASES; do
      if [[ "$p" -ge "$FROM_PHASE" ]]; then
        wanted="$wanted$p "
      fi
    done
    if [[ "$FROM_PHASE" != "0" ]]; then
      PARTIAL_RUN=1
    fi
  else
    for p in $ALL_PHASES; do
      wanted="$wanted$p "
    done
  fi
  PHASES=" $wanted"
}

want_phase() {
  case "$PHASES" in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

save_state() {
  local name="" value=""
  if [[ -z "$STATE_FILE" || ! -d "$OUT_DIR" ]]; then
    return 0
  fi
  : > "$STATE_FILE"
  chmod 600 "$STATE_FILE"
  for name in $STATE_VARS; do
    eval "value=\${$name-}"
    printf '%s=%q\n' "$name" "$value" >> "$STATE_FILE"
  done
}

load_state() {
  if [[ ! -f "$STATE_FILE" ]]; then
    fatal "a partial run needs the state $STATE_FILE that an earlier run wrote, and there is none. Run the whole thing once, or add phase 1 to what you selected."
  fi
  . "$STATE_FILE"
}

phase() {
  save_state
  echo
  echo "================================================================"
  echo "$*"
  echo "================================================================"
}

skipped_phase() {
  echo
  echo "================================================================"
  echo "$1 — NOT RUN ($2)"
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

run_pty() {
  local tag="$1" typed="$2"
  shift 2
  RUN_LOG="$OUT_DIR/$tag.log"
  echo "  ---> $*"
  echo "  ---> typed into the pty: '$typed'"
  set +o pipefail
  { sleep "$PTY_SETTLE_SECS"; printf '%s\n' "$typed"; sleep "$PTY_SETTLE_SECS"; } |
    script -q /dev/null "$@" 2>&1 | tee "$RUN_LOG"
  RUN_RC=${PIPESTATUS[1]}
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

assert_pty_fails_with() {
  local tag="$1" needle="$2" typed="$3"
  shift 3
  run_pty "$tag" "$typed" "$@"
  if [[ "$RUN_RC" -eq 0 ]]; then
    fail "$tag: expected a non-zero exit, got 0"
  else
    pass "$tag: exited $RUN_RC as expected"
  fi
  assert_contains "$tag: error names $needle" "$needle" "$RUN_LOG"
}

bundle_new() {
  local tag="$1" file="$2"
  run_cmd "$tag" "$BIN" bundle new --no-sync --file "$file"
  BUNDLE_HASH="$(grep -o '0x[0-9a-f]\{64\}' "$RUN_LOG" 2>/dev/null | head -1 || true)"
  if [[ "$RUN_RC" -ne 0 || -z "$BUNDLE_HASH" ]]; then
    fatal "$tag: bundle new exited $RUN_RC without reporting a safeTxHash"
  fi
  pass "$tag: filed $file as bundle $BUNDLE_HASH"
}

field_value() {
  local raw=""
  raw="$(grep -o "$2=[^[:space:]]*" "$1" 2>/dev/null | head -1 || true)"
  printf '%s' "${raw#*=}"
}

read_probe() {
  local tag="$1" token="$2" route="$3"
  local header=()
  if [[ -n "$token" ]]; then
    header=(-H "$GRANT_HEADER_NAME: $token")
  fi
  run_cmd "$tag" curl -sS -o /dev/null -w 'http_code=%{http_code}\n' --max-time 240 \
    --cacert "$CERT_INSTALLED" -H 'content-type: application/json' \
    ${header[@]+"${header[@]}"} \
    --data "{\"pubk\":\"$READ_PROBE_PUBK\"}" "https://127.0.0.1:$DRY_PORT$route"
}

serve_log_holds() {
  local needle="$1" within="$2" waited=0
  while [[ "$waited" -lt "$within" ]]; do
    if [[ -f "$SERVE_LOG" ]] && grep -qF -- "$needle" "$SERVE_LOG"; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

assert_serve_log() {
  if serve_log_holds "$2" "${3:-15}"; then
    pass "$1"
  else
    fail "$1 [missing '$2' in $SERVE_LOG]"
  fi
}

last_read_seq() {
  grep -o '=== hot_cheese Read request #[0-9]*' "$SERVE_LOG" 2>/dev/null |
    tail -1 | grep -o '[0-9]*$' || true
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

GUARD_SCRIPT='
trap "" HUP INT TERM QUIT
parent="$1"
pidfile="$2"
bin="$3"
while :; do
  now="$(ps -o ppid= -p $$ 2>/dev/null | tr -d " ")"
  if [ -n "$now" ] && [ "$now" != "$parent" ]; then
    break
  fi
  kill -0 "$parent" 2>/dev/null || break
  sleep 1
done
pid="$(cat "$pidfile" 2>/dev/null)"
case "$pid" in
  "" | *[!0-9]*) exit 0 ;;
esac
case "$(ps -ww -o args= -p "$pid" 2>/dev/null)" in
  "$bin "*) ;;
  *) exit 0 ;;
esac
kill -TERM "$pid" 2>/dev/null
n=0
while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 40 ]; do
  sleep 0.25
  n=$((n + 1))
done
kill -KILL "$pid" 2>/dev/null
exit 0
'

arm_guard() {
  GUARD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hot_cheese_dryrun_guard.XXXXXX")"
  case "$GUARD_DIR/" in
    "$HOT_CHEESE_HOME"/*) fatal "the guard dir landed inside the dry home, which phase 9 rm -rf's out from under it; set TMPDIR elsewhere" ;;
  esac
  SERVE_PID_FILE="$GUARD_DIR/serve.pid"
  SERVE_FIFO="$GUARD_DIR/serve.fifo"
  : > "$SERVE_PID_FILE"
  /bin/sh -c "$GUARD_SCRIPT" hot_cheese_dryrun_guard "$$" "$SERVE_PID_FILE" "$BIN" &
  GUARD_PID=$!
}

start_serve() {
  : > "$SERVE_LOG"
  chmod 600 "$SERVE_LOG"
  rm -f "$SERVE_FIFO"
  mkfifo -m 600 "$SERVE_FIFO"
  tee -a "$SERVE_LOG" /dev/tty < "$SERVE_FIFO" > /dev/null 2>&1 &
  SERVE_TEE_PID=$!
  /bin/sh -c 'echo $$ > "$1"; shift; exec "$@"' hot_cheese_dryrun_serve \
    "$SERVE_PID_FILE" "$BIN" serve < /dev/tty > "$SERVE_FIFO" 2>&1 &
  SERVE_PID=$!
}

reap_pid() {
  local pid="$1" left="$2"
  while kill -0 "$pid" 2>/dev/null && [[ "$left" -gt 0 ]]; do
    sleep 0.25
    left=$((left - 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    return 1
  fi
  return 0
}

stop_serve() {
  local pid="$SERVE_PID" stopped=0
  if [[ -z "$pid" ]]; then
    return 0
  fi
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    if ! reap_pid "$pid" 40; then
      kill -KILL "$pid" 2>/dev/null || true
      reap_pid "$pid" 20 || stopped=1
    fi
  fi
  if [[ "$stopped" -eq 0 ]]; then
    { wait "$pid"; } 2>/dev/null || true
  fi
  if [[ -n "$SERVE_TEE_PID" ]]; then
    if ! reap_pid "$SERVE_TEE_PID" 20; then
      kill -TERM "$SERVE_TEE_PID" 2>/dev/null || true
    fi
    { wait "$SERVE_TEE_PID"; } 2>/dev/null || true
    SERVE_TEE_PID=""
  fi
  rm -f "$SERVE_FIFO"
  if [[ "$stopped" -ne 0 ]]; then
    return 1
  fi
  SERVE_PID=""
  : > "$SERVE_PID_FILE" 2>/dev/null || true
  return 0
}

disarm_guard() {
  if [[ -n "$GUARD_PID" ]]; then
    kill -KILL "$GUARD_PID" 2>/dev/null || true
    { wait "$GUARD_PID"; } 2>/dev/null || true
    GUARD_PID=""
  fi
  if [[ -n "$GUARD_DIR" && -d "$GUARD_DIR" ]]; then
    rm -rf "$GUARD_DIR"
  fi
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

enclave_blob_lines() {
  grep -E '[[:space:]]\./(se_kek_|se_grant_)[^/]*\.blob$' "$1" 2>/dev/null || true
}

write_config_at() {
  local file="$1" grant_line="" approval_line=""
  if [[ -n "$5" ]]; then
    grant_line="grant_public_key = \"$5\""
  fi
  if [[ -n "$CFG_APPROVAL_SECS" ]]; then
    approval_line="approval_timeout_secs = $CFG_APPROVAL_SECS"
  fi
  cat > "$file" <<TOML
service = "$2"
account = "$3"
store = "$4"
store_archive = "$DRY_ARCHIVE"
port = $DRY_PORT
$grant_line
$approval_line
backup_remotes = []
TOML
  chmod 600 "$file"
}

write_config() {
  write_config_at "$CFG_FILE" "$1" "$2" "$CFG_STORE" "$3"
}

forge_key_use() {
  local file="$1" from="$2" to="$3" tmp=""
  tmp="$file.forged"
  sed "s/\"key_use\":\"$from\"/\"key_use\":\"$to\"/" "$file" > "$tmp"
  mv "$tmp" "$file"
}

keep_logs() {
  local src=""
  if [[ -z "$LOG_KEEP" || ! -d "$OUT_DIR" ]]; then
    return 0
  fi
  mkdir -p "$LOG_KEEP" 2>/dev/null || return 0
  for src in "$OUT_DIR"/*.log "$OUT_DIR"/*.json; do
    [[ -f "$src" ]] || continue
    cp "$src" "$LOG_KEEP/" 2>/dev/null || true
  done
  LOGS_KEPT=1
}

on_exit() {
  local rc=$?
  echo
  echo "================================================================"
  echo "EXIT GUARD (kills only the daemon this script started, by recorded pid)"
  echo "================================================================"
  if [[ -n "$RUN_INTERRUPTED" ]]; then
    echo "  note  this run was ended by SIG$RUN_INTERRUPTED"
  fi
  save_state
  if [[ -z "$SERVE_PID" ]]; then
    echo "  OK    this script has no daemon of its own running"
    disarm_guard
  elif stop_serve; then
    echo "  OK    the daemon this script started is stopped and the dry port is released"
    disarm_guard
  else
    echo "  ALERT the daemon this script started (pid $SERVE_PID) would not stop"
    echo "  ALERT the parent-death guard is left ARMED and kills it the moment this script exits"
    rc=1
  fi
  keep_logs
  if [[ -n "$LOGS_KEPT" ]]; then
    echo "  OK    command logs archived at $LOG_KEEP"
  else
    echo "  note  no command log was archived: nothing had been captured yet"
  fi
  if [[ -n "$SNAP_DIR" && -f "$SNAP_DIR/before.list" ]]; then
    snapshot_dir "$REAL_HOME" "$SNAP_DIR/exit.list" "$SNAP_DIR/exit.hashes"
    snapshot_dir "$REAL_ARCHIVE" "$SNAP_DIR/arch_exit.list" "$SNAP_DIR/arch_exit.hashes"
    if cmp -s "$SNAP_DIR/before.list" "$SNAP_DIR/exit.list" &&
      cmp -s "$SNAP_DIR/before.hashes" "$SNAP_DIR/exit.hashes" &&
      cmp -s "$SNAP_DIR/arch_before.list" "$SNAP_DIR/arch_exit.list" &&
      cmp -s "$SNAP_DIR/arch_before.hashes" "$SNAP_DIR/arch_exit.hashes"; then
      echo "  OK    real home is byte-identical to the phase-0 snapshot: $REAL_HOME"
      echo "  OK    real store archive is byte-identical to it too: $REAL_ARCHIVE"
      rm -rf "$SNAP_DIR"
    else
      echo "  ALERT real home or real store archive DIFFERS from the phase-0 snapshot"
      echo "  ALERT home:    $REAL_HOME"
      echo "  ALERT archive: $REAL_ARCHIVE"
      echo "  ALERT diff before.hashes against exit.hashes (and arch_*) under $SNAP_DIR; that dir is kept"
      rc=1
    fi
  else
    echo "  OK    real-home baseline was already verified and removed"
    if [[ -n "$SNAP_DIR" && -d "$SNAP_DIR" ]]; then
      rm -rf "$SNAP_DIR"
    fi
  fi
  PORT_PIDS="$(port_pids)"
  if [[ -n "$PORT_PIDS" ]]; then
    echo "  ALERT something is STILL listening on the dry port $DRY_PORT, pid(s): $PORT_PIDS"
    echo "  ALERT this script did not start it, so it will not kill it. Inspect it with:"
    echo "  ALERT     ps -p $PORT_PIDS -o pid,command"
    rc=1
  fi
  if [[ -n "$TORN_DOWN" ]]; then
    echo "  OK    phase 9 removed the dry home and the throwaway store archive"
  elif [[ -e "${HOT_CHEESE_HOME:-}" || -e "${DRY_ARCHIVE:-}" ]]; then
    echo "  LEFT  phase 9 did not remove them, so these are still on disk:"
    if [[ -e "${HOT_CHEESE_HOME:-}" ]]; then
      echo "  LEFT      dry home:    $HOT_CHEESE_HOME"
    fi
    if [[ -e "${DRY_ARCHIVE:-}" ]]; then
      echo "  LEFT      dry archive: $DRY_ARCHIVE"
    fi
    echo "  LEFT  remove them with:"
    echo "  LEFT      rm -rf \"${HOT_CHEESE_HOME:-}\" \"${DRY_ARCHIVE:-}\""
    echo "  LEFT  or keep them and carry on where this stopped, without repeating a biometric:"
    echo "  LEFT      HOT_CHEESE_HOME=\"${HOT_CHEESE_HOME:-}\" FROM_PHASE=<n> $0"
  else
    echo "  OK    this run created no dry home and no throwaway archive to leave behind"
  fi
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
echo "Your real install at \$HOME/.config/hot_cheese is snapshotted and never written, and so"
echo "is the store archive at \$HOME/Library/Application Support/hot_cheese/store-archive,"
echo "which lives OUTSIDE any HOT_CHEESE_HOME and so is not covered by the throwaway one."
echo
echo "PROMPT BUDGET — sit down with a finger free:"
echo "  phases 0-9 total: $TOUCH_ID_BUDGET Touch ID sheets + $PASSPHRASE_BUDGET recovery-passphrase entries"
echo "    phase 0  3 Touch ID   (se-selftest: two fresh enclave ECDHs, then ONE sheet that has"
echo "                           to cover a third ECDH AND an enclave grant signature)"
echo "    phase 1  2 passphrase (init: new passphrase, entered twice)"
echo "    phase 2  3 passphrase + 1 Touch ID"
echo "    phase 3  7 Touch ID   (five key operations, one on a file whose use flag was forged,"
echo "                           and one to mint the read grant; the read grant a sign-only key"
echo "                           is refused costs 0; plus one short secret at a hidden prompt)"
echo "    phase 4  0            (enroll grant prompts NOTHING; discard-enclave-key asks for its"
echo "                           phrase, and this script types that into a pty of its own)"
echo "    phase 5  1 Touch ID   (the allowed sign; all six refusals cost 0)"
echo "    phase 6  2 Touch ID   (the shareable /read, and the ONE attributable answer at the"
echo "                           challenged prompt; the sign-only /read, the expired prompt,"
echo "                           the plain-y denial, the granted read and both refused tokens"
echo "                           are 0 each. The daemon runs in THIS terminal, started and"
echo "                           stopped by this script, and answers three prompts here)"
echo "    phase 7  1 passphrase (the recovery escape hatch, SE blob moved aside)"
echo "    phase 8  1 Touch ID   (sealing the shareable key sign-only, which kills its grant;"
echo "                           the git backup and the loss-recovery verbs cost 0)"
echo "    phase 9  0"
echo "  with RUN_MIGRATE=1 add phase M: 2 Touch ID + 3 passphrase + 1 login-keychain dialog"
echo "    (phase M now initializes its OWN throwaway install, because migrate refuses any"
echo "     --new-store that is not the configured store and refuses one holding keystores;"
echo "     budget up to 4 taps in case macOS re-prompts)"
echo
echo "NO DESTRUCTION IN THIS RUN IS TYPED BY YOU, AND NONE OF THEM IS REACHABLE FROM AN"
echo "ARGUMENT ANY MORE. accept-deletions, discard-enclave-key, init --force and a rewinding"
echo "backup pull take their phrase from a terminal and from nowhere else — the flags that used"
echo "to carry one are gone. Every destructive phase below therefore does two things: it checks"
echo "that the command REFUSES with no terminal, which is what stops a script or an agent, and"
echo "then types the phrase into a pty the way a human at a terminal would."
echo
echo "EVERY NEW PASSPHRASE THIS RUN ASKS FOR MUST BE AT LEAST 20 CHARACTERS AND USE AT LEAST"
echo "8 DISTINCT CHARACTERS. The rule is enforced at the prompt, before any file is written,"
echo "and a refused entry is asked again — which would put the counts above out by one. Pick"
echo "one throwaway line now, e.g. 'dryrun throwaway passphrase 42', and reuse it everywhere."
echo
echo "READ THIS BEFORE THE FIRST APPROVAL PROMPT. There are TWO shapes of prompt and they take"
echo "DIFFERENT ANSWERS. Answering the second one with a plain 'y' DENIES it."
echo
echo "  ORDINARY:   Approve request #7? [y/N]"
echo "              Type y. This prompt replaced nothing, so a plain y approves it."
echo
echo "  CHALLENGED: *** THE SCREEN CHANGED: the request you were reading ended WITHOUT your"
echo "              answer. ... ***"
echo "              Approve request #8? [y8/N]"
echo "              Type EXACTLY what the square brackets show — y8 for request #8. A plain y"
echo "              DENIES it, because a plain y is a line you could have composed for the"
echo "              request that vanished. 'q8' denies it and the whole backlog."
echo
echo "The rule that produces the challenge: a prompt that ends WITHOUT an answer — you walked"
echo "away, you were reading one of these instruction blocks, the daemon timed it out — makes"
echo "EVERY later prompt on that daemon challenged until you answer one with its own number."
echo "Phase 6 deliberately lets one expire and then checks both halves, so do not be surprised"
echo "there. Everywhere else, answer the prompt in front of you and do not let one run out."
echo
echo "At every approval prompt: an answer typed within 400ms of the prompt appearing is"
echo "reported and asked again rather than used; an unanswered prompt denies itself on a"
echo "deliberately jittered deadline, so it is not a clock you can read; and 'q' denies this"
echo "request AND everything already queued behind it."
echo
echo "How long a prompt waits is a config key now, approval_timeout_secs, and this run sets it"
echo "per phase so you are not made to sit out a minute of nothing:"
echo "  phase 5   the CLI's own sign prompt, at the 60s default: 60 to 80 seconds"
echo "  phase 6   the daemon, which this run configures to ${DRY_APPROVAL_SECS}s: $DRY_APPROVAL_SECS to $APPROVAL_MAX_SECS seconds"
echo "Phase 6 deliberately lets ONE prompt expire, and that is the whole reason the key exists"
echo "here: at the default it was an 80-second wait doing nothing. Raise it with"
echo "DRY_APPROVAL_SECS=<n> if ${DRY_APPROVAL_SECS}s is not enough time for you to read and answer."
echo
echo "ONE TERMINAL. This script starts, supervises and stops the daemon itself, in this same"
echo "terminal: its output is teed to the run's serve.log AND to your screen, and it takes your"
echo "answers from this terminal's keyboard. It cannot be stranded — an independent guard"
echo "process kills it by recorded pid the moment this script stops existing, whether this"
echo "script exits, fails, is Ctrl-C'd, is SIGTERMed or is SIGKILLed. It kills NOTHING it did"
echo "not itself start: a daemon already on the dry port stops this run at phase 0 instead."
echo
echo "RESUMING. A failure late in the run does not cost you the whole ritual again:"
echo "  FROM_PHASE=8   run phase 8 onwards against the store the last run left behind"
echo "  ONLY_PHASES=6  run exactly that phase, and leave the store where it is"
echo "Either one keeps the dry home instead of wiping it, reloads what the earlier phases"
echo "captured, and is reported as a PARTIAL RUN. A partial run is NOT a pass and never says"
echo "it is: only a full run clears you to migrate."
echo
echo "You are NEVER asked to remember how many Touch ID sheets you saw. Sheets are counted"
echo "from macOS unified logging (coreauthd biometric matches) inside each command's window."
echo "'log show --start' resolves WHOLE SECONDS only, so each window first waits for the second"
echo "to tick over: without that, the previous command's tap bleeds into the next count."
echo
echo "Env switches: DRY_PORT DRY_LOG_DIR SKIP_SELFTEST SKIP_SERVE RUN_MIGRATE FROM_PHASE"
echo "              ONLY_PHASES DRY_APPROVAL_SECS HC_DRYRUN_ALLOW_ANY_PATH"
echo "Run this in your GUI login session. Touch ID cannot prompt over ssh or sudo."

phase "PHASE 0 — isolation, interlock, provenance"

select_phases
case "$DRY_APPROVAL_SECS" in
  '' | *[!0-9]*) fatal "DRY_APPROVAL_SECS must be a plain number of seconds, got '$DRY_APPROVAL_SECS'" ;;
esac
if [[ "$DRY_APPROVAL_SECS" -lt 5 || "$DRY_APPROVAL_SECS" -gt 600 ]]; then
  fatal "DRY_APPROVAL_SECS is $DRY_APPROVAL_SECS; approval_timeout_secs only accepts 5..600 and the daemon refuses to load anything else"
fi
if ! { true > /dev/tty; } 2>/dev/null; then
  fatal "this run has no terminal. It answers the daemon's approval prompts on /dev/tty, so it must be run from a terminal and not from a pipeline or a job with none."
fi
echo "  OK    phases selected:$PHASES"
if [[ -n "$PARTIAL_RUN" ]]; then
  echo "  note  THIS IS A PARTIAL RUN. It does not wipe the dry home, it reloads what an earlier"
  echo "  note  run captured, and it is NOT a pass however many assertions it clears."
fi

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
REAL_ARCHIVE="$HOME/Library/Application Support/hot_cheese/store-archive"
if [[ "$HOT_CHEESE_HOME" == "$REAL_HOME" ]]; then
  fatal "HOT_CHEESE_HOME points at the REAL install $REAL_HOME"
fi
case "$HOT_CHEESE_HOME/" in
  "$REAL_ARCHIVE"/*) fatal "HOT_CHEESE_HOME lives inside the real store archive $REAL_ARCHIVE" ;;
esac
case "$REAL_ARCHIVE/" in
  "$HOT_CHEESE_HOME"/*) fatal "the real store archive $REAL_ARCHIVE lives inside HOT_CHEESE_HOME, which this script rm -rf's" ;;
esac
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
GRANT_DIR="$HOT_CHEESE_HOME/read-grants"
DRY_ARCHIVE="${HOT_CHEESE_HOME}_archive"
if [[ "$DRY_ARCHIVE" == "$REAL_ARCHIVE" || "$DRY_ARCHIVE" == "$REAL_HOME" ]]; then
  fatal "the throwaway archive path collides with a real one: $DRY_ARCHIVE"
fi
case "$DRY_ARCHIVE/" in
  "$REAL_HOME"/* | "$REAL_ARCHIVE"/*) fatal "the throwaway archive $DRY_ARCHIVE lives inside a real one, and this script rm -rf's it" ;;
esac
case "$REAL_HOME/" in
  "$DRY_ARCHIVE"/*) fatal "the real install lives inside the throwaway archive $DRY_ARCHIVE, which this script rm -rf's" ;;
esac
case "$REAL_ARCHIVE/" in
  "$DRY_ARCHIVE"/*) fatal "the real store archive lives inside the throwaway archive $DRY_ARCHIVE, which this script rm -rf's" ;;
esac
case "$HOT_CHEESE_HOME/" in
  "$DRY_ARCHIVE"/*) fatal "the dry home lives inside the throwaway archive $DRY_ARCHIVE, and the archive may not contain the store" ;;
esac
if [[ -z "$HC_DRYRUN_ALLOW_ANY_PATH" ]]; then
  case "$DRY_ARCHIVE" in
    /tmp/* | /private/tmp/* | /var/folders/*) ;;
    *) fatal "the throwaway archive $DRY_ARCHIVE must be under /tmp, /private/tmp or /var/folders (this script rm -rf's it)" ;;
  esac
fi
echo "  OK    dry home:     $HOT_CHEESE_HOME"
echo "  OK    dry archive:  $DRY_ARCHIVE  (throwaway, removed by phase 9)"
echo "  OK    real home:    $REAL_HOME  (read-only baseline, never written)"
echo "  OK    real archive: $REAL_ARCHIVE  (read-only baseline, never written)"
echo "  OK    dry port:     $DRY_PORT"
echo "  OK    software-enclave demo backend is NOT enabled"
echo "  note  the store archive is deliberately OUTSIDE the home and OUTSIDE the store, so a"
echo "  note  throwaway HOT_CHEESE_HOME does not contain it and phase 9's rm -rf would not reach"
echo "  note  it: an unredirected dry run would leave throwaway ciphertext in YOUR archive, which"
echo "  note  nothing in hot_cheese ever prunes. This run points config.toml at its own instead,"
echo "  note  and phase 9 asserts your real one is byte-identical."

SNAP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hot_cheese_dryrun_snap.XXXXXX")"
case "$SNAP_DIR/" in
  "$HOT_CHEESE_HOME"/*) fatal "the snapshot dir landed inside the dry home; set TMPDIR elsewhere" ;;
esac
trap on_exit EXIT
trap 'RUN_INTERRUPTED=INT; exit 130' INT
trap 'RUN_INTERRUPTED=TERM; exit 143' TERM
arm_guard
echo "  OK    parent-death guard armed at pid $GUARD_PID before anything could bind the port"
snapshot_dir "$REAL_HOME" "$SNAP_DIR/before.list" "$SNAP_DIR/before.hashes"
snapshot_dir "$REAL_ARCHIVE" "$SNAP_DIR/arch_before.list" "$SNAP_DIR/arch_before.hashes"
if [[ -d "$REAL_HOME" ]]; then
  echo "  OK    snapshotted $(grep -c . "$SNAP_DIR/before.hashes" || true) file(s) of the real home into $SNAP_DIR"
else
  echo "  OK    the real home does not exist yet; snapshot records it as absent"
fi
if [[ -d "$REAL_ARCHIVE" ]]; then
  echo "  OK    snapshotted $(grep -c . "$SNAP_DIR/arch_before.hashes" || true) file(s) of the real store archive too"
else
  echo "  OK    the real store archive does not exist yet; snapshot records it as absent"
fi

PORT_PIDS="$(port_pids)"
if [[ -n "$PORT_PIDS" ]]; then
  fatal "something is already listening on the dry port $DRY_PORT (pid(s): $PORT_PIDS). Pick another with DRY_PORT= or stop it yourself; this script only ever kills the daemon it started itself, and it has not started one."
fi
echo "  OK    dry port $DRY_PORT has no listener"

OUT_DIR="$HOT_CHEESE_HOME/dryrun_out"
SERVE_LOG="$OUT_DIR/serve.log"
STATE_FILE="$OUT_DIR/state.env"
echo
if want_phase 1; then
  echo "==> wiping the dry home and its throwaway store archive, and creating the output archive"
  rm -rf "$HOT_CHEESE_HOME"
  rm -rf "$DRY_ARCHIVE"
  mkdir -p "$OUT_DIR"
else
  echo "==> KEEPING the dry home: phase 1 is not in this run, so the install it builds has to be"
  echo "    the one an earlier run left at $HOT_CHEESE_HOME"
  if [[ ! -d "$HOT_CHEESE_HOME" ]]; then
    fatal "there is no dry home at $HOT_CHEESE_HOME to carry on from. Run the whole thing once, or include phase 1."
  fi
  mkdir -p "$OUT_DIR"
  load_state
  TAPS_EXPECTED=0
  echo "  OK    reloaded the addresses, the grant token and the pins an earlier run captured,"
  echo "  OK    from $STATE_FILE"
  echo "  note  the tap counts below are this run's alone, not the earlier run's plus this one"
fi
RUN_START="$(date '+%Y-%m-%d %H:%M:%S')"
LOG_KEEP="$DRY_LOG_DIR/$(date '+%Y%m%d-%H%M%S')"
echo "  OK    every command's output is archived under $OUT_DIR"
echo "  OK    and its .log and .json files are copied to $LOG_KEEP on exit, abort included"

echo
echo "==> required tools"
for tool in cargo swiftc openssl curl shasum lsof security cmp stat find tr sed script; do
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

if ! want_phase 0; then
  echo
  echo "==> phase 0 is not in this run: skipping se-selftest (saves 3 Touch ID prompts)"
elif [[ -n "$SKIP_SELFTEST" ]]; then
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

if want_phase 1; then
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
echo "==> rewriting config.toml with the same service/account/store plus port, backup_remotes"
echo "    and a THROWAWAY store_archive. The archive defaults to a path outside every"
echo "    HOT_CHEESE_HOME — your real one — and nothing in hot_cheese ever prunes it, so an"
echo "    unredirected dry run would leave its throwaway keystores in your archive for good."
echo "    config.toml pins the grant key every signature is verified against, so loading one"
echo "    that any other account can read is refused: it is held to the same 0600 bar as a key."
assert_file_mode "config.toml as init wrote it is 600" "600" "$CFG_FILE"
write_config "$CFG_SERVICE" "$CFG_ACCOUNT" ""
assert_file_mode "and the rewritten one is 600 too" "600" "$CFG_FILE"
assert_eq "config.toml points the store archive at the throwaway path" \
  "$DRY_ARCHIVE" "$(toml_value "$CFG_FILE" store_archive)"
run_cmd p1_list_reparse "$BIN" list
assert_eq "the rewritten config.toml still parses" "0" "$RUN_RC"
assert_matches "the dry run configures NO backup remote, so nothing can be pushed off this Mac" \
  '^[[:space:]]*backup_remotes[[:space:]]*=[[:space:]]*\[\]' "$CFG_FILE"

echo
echo "==> negative: a config.toml any other account could read must be refused outright"
chmod 0644 "$CFG_FILE"
assert_cmd_fails_with p1_unsafe_config "UnsafeConfigFile" "$BIN" list
chmod 0600 "$CFG_FILE"
run_cmd p1_list_restored "$BIN" list
assert_eq "and 0600 restores it" "0" "$RUN_RC"
else
  skipped_phase "PHASE 1" "not selected for this run"
fi

if want_phase 2; then
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
echo "  note  an enclave blob file proves nothing on its own: any process running as you can"
echo "  note  mint an enclave key with no biometric policy at all. So enroll DISTINGUISHES a key"
echo "  note  it minted from one it merely found already recorded, and names it by fingerprint."
assert_contains "the first enroll se says it MINTED, not that it adopted something" \
  "MINTED a new Secure Enclave key" "$RUN_LOG"
assert_matches "and names the new enclave key by its 16-hex fingerprint" \
  'se_key=[0-9a-f]{16}([[:space:]]|$)' "$RUN_LOG"
SE_KEY_FP="$(field_value "$RUN_LOG" se_key)"

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
snapshot_dir "$REAL_HOME" "$SNAP_DIR/p2.list" "$SNAP_DIR/p2.hashes"
assert_eq "no enclave blob appeared in the real home, and the baseline's are unchanged" \
  "$(enclave_blob_lines "$SNAP_DIR/before.hashes")" "$(enclave_blob_lines "$SNAP_DIR/p2.hashes")"

run_cmd p2_list "$BIN" list
N_PASS="$(grep -cE 'kind="?passphrase' "$RUN_LOG" || true)"
N_SE="$(grep -cE 'kind="?secure_enclave' "$RUN_LOG" || true)"
assert_eq "one passphrase enrollment survives as the recovery backstop" "1" "$N_PASS"
assert_eq "one secure_enclave enrollment was added" "1" "$N_SE"
assert_list_use "$RUN_LOG" "$EVM_KEY" "sign_only"
if [[ -n "$SE_KEY_FP" ]]; then
  assert_contains "list names the SAME enclave key enroll printed, so the two are comparable" \
    "se_key=$SE_KEY_FP" "$RUN_LOG"
else
  fail "enroll se printed no se_key fingerprint, so list has nothing to be compared against"
fi

ANSWER="$(ask_tty "Did the LAST 'address evm' prompt Touch ID (t) or a recovery passphrase (p)? [t/p]")"
assert_eq "the unlocker switched to the Secure Enclave path" "t" "$(lower "$ANSWER")"
else
  skipped_phase "PHASE 2" "not selected for this run"
fi

if want_phase 3; then
phase "PHASE 3 — declared key uses and the read grant on real hardware (7 Touch ID)"

echo "A key now declares at birth whether it may EVER leave the daemon. sign-only is the"
echo "default and is a one-way door. This phase creates one of each, proves 'list' reports"
echo "the declared use, proves the door only turns one way, and then forges the flag on disk"
echo "to prove the header is bound into the AEAD and buys an attacker nothing. It ends by"
echo "minting the READ GRANT phase 6 pulls a key with: one Touch ID now, none per request."
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

echo
echo "==> 3c: a READ GRANT is a time-boxed token that releases ONE key over /read with no"
echo "    Touch ID per request. It is minted from the same export permit /read is, so a"
echo "    sign-only key is refused from the cleartext header BEFORE anything unlocks — no"
echo "    passphrase, no biometric, no grant file."
BIO_START="$(bio_window_start)"
assert_cmd_fails_with p3_grant_signonly "ExportRefused" "$BIN" read-grant allow "$EVM_KEY"
assert_contains "the refusal names the use that refused" "SignOnly" "$RUN_LOG"
assert_taps "refusing to grant a sign-only key cost no biometric" "0" "$BIO_START"
if [[ -e "$GRANT_DIR/$EVM_KEY" ]]; then
  fail "the refused grant still wrote $GRANT_DIR/$EVM_KEY"
else
  pass "the refused grant wrote no grant file"
fi

echo
echo "==> and a window outside 1..8760 hours is refused while the argument is PARSED, so a"
echo "    typo there cannot cost a finger either."
assert_cmd_fails_with p3_grant_zero_hours "is not in 1..=8760" "$BIN" read-grant allow "$SHARE_KEY" --hours 0

echo
echo "==> 3d: now the same command against the key that DECLARED itself shareable. ONE Touch"
echo "    ID, and the token is printed ONCE and stored nowhere: the grant file on disk is the"
echo "    key sealed under a KEK derived from that token, so the file alone opens for nobody."
TAPS_EXPECTED=$((TAPS_EXPECTED + 1))
BIO_START="$(bio_window_start)"
run_cmd p3_grant_allow "$BIN" read-grant allow "$SHARE_KEY"
assert_eq "read-grant allow exit code" "0" "$RUN_RC"
assert_taps "minting a grant costs exactly one biometric" "1" "$BIO_START"
GRANT_TOKEN="$(grep -E '^token[[:space:]]+' "$RUN_LOG" 2>/dev/null | head -1 | awk '{print $2}' || true)"
GRANT_FILE="$GRANT_DIR/$SHARE_KEY"
assert_contains "the handoff names the key it releases and nothing else" \
  "hot_cheese will hand you the key \"$SHARE_KEY\"" "$RUN_LOG"
assert_contains "and names the header a consumer presents it on" "$GRANT_HEADER_NAME" "$RUN_LOG"
assert_contains "and names the one command that ends it early" "seal --use sign-only" "$RUN_LOG"
if [[ -f "$GRANT_FILE" ]]; then
  pass "the grant is on disk at $GRANT_FILE"
else
  fail "no grant file at $GRANT_FILE"
fi
assert_file_mode "the grant file is 600" "600" "$GRANT_FILE"
assert_file_mode "and the directory holding it is 700" "700" "$GRANT_DIR"

echo
echo "==> a grant is a per-machine capability, not store state: it must never be in the store"
echo "    and never reach a backup, or restoring a backup would hand the key to whoever holds"
echo "    a token the operator issued on another Mac."
if [[ -d "$CFG_STORE/read-grants" ]]; then
  fail "a grants directory landed inside the store at $CFG_STORE"
else
  pass "no grant landed inside the store"
fi
run_cmd p3_grant_tracked git -C "$CFG_STORE" ls-files
assert_not_contains "and git tracks no grant, so a push carries none" "read-grant" "$RUN_LOG"

run_cmd p3_grant_list "$BIN" read-grant list
assert_eq "read-grant list exit code" "0" "$RUN_RC"
assert_contains "list names the granted key" "grant=$SHARE_KEY" "$RUN_LOG"
assert_not_contains "the live grant is not reported DEAD while its key is still shareable" \
  "DEAD" "$RUN_LOG"

if [[ -n "$GRANT_TOKEN" ]]; then
  pass "the handoff block printed a token phase 6 can present"
  assert_not_contains "the grant file does NOT contain the token that opens it" \
    "$GRANT_TOKEN" "$GRANT_FILE"
  assert_not_contains "and git tracks nothing carrying it" "$GRANT_TOKEN" "$OUT_DIR/p3_grant_tracked.log"
  assert_not_contains "and list never shows it again" "$GRANT_TOKEN" "$OUT_DIR/p3_grant_list.log"
  echo "  note  the token IS in this run's archived p3_grant_allow.log, which is what makes the"
  echo "  note  rest of this run able to present it. Phase 8 revokes the grant and proves the"
  echo "  note  archived token then releases nothing, so the log archive is left inert."
else
  fail "read-grant allow printed no token line, so phase 6 has nothing to present"
fi
else
  skipped_phase "PHASE 3" "not selected for this run"
fi

if want_phase 4; then
phase "PHASE 4 — the grant key serve refuses to start without, and the squatter at its path (0 prompts)"

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
assert_contains "enroll grant reports the pin it wrote" \
  "pinned the Secure Enclave grant key in config.toml" "$RUN_LOG"
assert_contains "the first enroll grant says it MINTED, not that it adopted something" \
  "MINTED a new Secure Enclave grant key" "$RUN_LOG"
assert_matches "and names the new grant key by its 16-hex fingerprint" \
  'grant_key=[0-9a-f]{16}([[:space:]]|$)' "$RUN_LOG"
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
echo "==> and enroll will not ADOPT a blob it cannot prove is its own. Any process running as"
echo "    you can mint an enclave key with no biometric policy at all and leave it on this path,"
echo "    so a blob is taken as this machine's key ONLY when config.toml already pins its public"
echo "    half. Drop the pin, leave the blob, and the SAME command that just succeeded refuses."
GRANT_SHA_BEFORE="$(shasum -a 256 "$GRANT_BLOB" 2>/dev/null | cut -d' ' -f1 || true)"
write_config "$CFG_SERVICE" "$CFG_ACCOUNT" ""
assert_cmd_fails_with p4_unrecorded_grant "UnrecordedEnclaveKeyRunDiscardEnclaveKey" "$BIN" enroll grant
assert_contains "and the refusal names the command that clears it" "discard-enclave-key" "$RUN_LOG"
assert_contains "the refusal names the blob it declined to adopt" "$GRANT_BLOB" "$RUN_LOG"
assert_not_contains "and it minted nothing over the top of it" "MINTED" "$RUN_LOG"
assert_eq "the refused enroll left the blob byte-identical" \
  "$GRANT_SHA_BEFORE" "$(shasum -a 256 "$GRANT_BLOB" 2>/dev/null | cut -d' ' -f1 || true)"
assert_eq "and left no grant key pinned" "" "$(toml_value "$CFG_FILE" grant_public_key)"

write_config "$CFG_SERVICE" "$CFG_ACCOUNT" "$CFG_GRANT_PUB"
run_cmd p4_enroll_grant_again "$BIN" enroll grant
assert_eq "with the pin back, the same blob is recognised and enroll grant exits 0" "0" "$RUN_RC"
assert_contains "and says ADOPTED, so an operator can tell a re-run from a rotation" \
  "ADOPTED the Secure Enclave grant key already on this disk" "$RUN_LOG"
assert_eq "adopting it rotated nothing: the blob is still the same bytes" \
  "$GRANT_SHA_BEFORE" "$(shasum -a 256 "$GRANT_BLOB" 2>/dev/null | cut -d' ' -f1 || true)"
assert_eq "and the pin is unchanged" "$CFG_GRANT_PUB" "$(toml_value "$CFG_FILE" grant_public_key)"

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

echo
echo "==> 4b: that refusal is permanent, so there has to be a way out of it. discard-enclave-key"
echo "    is it, and its whole safety is that it will NOT act on a key this install records:"
echo "    the phrase is asked for AFTER the key is identified, so the refusals below never reach"
echo "    a prompt at all. Both of this machine's enclave keys are recorded right now."
echo "    NOTHING here is typed by you: no flag carries a destruction phrase any more, so this"
echo "    script types each one into a pty of its own, exactly as a human at a terminal would."
SE_SHA_GUARDED="$(shasum -a 256 "$SE_BLOB" 2>/dev/null | cut -d' ' -f1 || true)"
assert_cmd_fails_with p4_discard_recorded_se "RecordedEnclaveKeyNotDiscardable" \
  "$BIN" discard-enclave-key se
if [[ -n "$SE_KEY_FP" ]]; then
  assert_contains "and it names the enclave key it is protecting, by the fingerprint list shows" \
    "$SE_KEY_FP" "$RUN_LOG"
else
  fail "phase 2 captured no se_key fingerprint to compare the refusal against"
fi
assert_eq "the refused discard left the KEK blob byte-identical" \
  "$SE_SHA_GUARDED" "$(shasum -a 256 "$SE_BLOB" 2>/dev/null | cut -d' ' -f1 || true)"
assert_cmd_fails_with p4_discard_recorded_grant "RecordedEnclaveKeyNotDiscardable" \
  "$BIN" discard-enclave-key grant
assert_eq "and left the grant blob byte-identical" \
  "$GRANT_SHA_BEFORE" "$(shasum -a 256 "$GRANT_BLOB" 2>/dev/null | cut -d' ' -f1 || true)"

echo
echo "==> now drop the pin again, which is exactly the state the refusal above leaves an"
echo "    operator in: a blob at the grant path that nothing records. WITHOUT A TERMINAL the"
echo "    destruction is not reachable at all — this is the assertion that stands between an"
echo "    automated process running as you and a destroyed key, now that no flag carries the"
echo "    phrase. Then the wrong phrase, typed into a pty, must still refuse and leave the blob."
write_config "$CFG_SERVICE" "$CFG_ACCOUNT" ""
assert_cmd_fails_with p4_discard_no_terminal "ConfirmationOnlyFromATerminal" \
  "$BIN" discard-enclave-key grant
assert_contains "the refusal states the phrase a terminal would have to type" \
  "$DISCARD_PHRASE" "$RUN_LOG"
assert_eq "the no-terminal refusal destroyed nothing" \
  "$GRANT_SHA_BEFORE" "$(shasum -a 256 "$GRANT_BLOB" 2>/dev/null | cut -d' ' -f1 || true)"
assert_pty_fails_with p4_discard_wrong_phrase "ConfirmationRefused" "yes" \
  "$BIN" discard-enclave-key grant
assert_contains "and the refusal states the phrase it wanted" "$DISCARD_PHRASE" "$RUN_LOG"
assert_eq "the wrong phrase destroyed nothing" \
  "$GRANT_SHA_BEFORE" "$(shasum -a 256 "$GRANT_BLOB" 2>/dev/null | cut -d' ' -f1 || true)"

echo
echo "==> and the right phrase, typed at a terminal, removes that ONE file and nothing else."
run_pty p4_discard_grant "$DISCARD_PHRASE" "$BIN" discard-enclave-key grant
assert_eq "discard-enclave-key grant exit code" "0" "$RUN_RC"
assert_contains "it named the key it was about to remove, by fingerprint" "found=" "$RUN_LOG"
assert_contains "it said this install records none of that kind" \
  "this install records NO enclave key of this kind" "$RUN_LOG"
assert_contains "and it looked in the store's HISTORY too, before destroying anything" \
  "no keyring in this store's history records this enclave key" "$RUN_LOG"
assert_contains "and it points at the command that mints a replacement" "enroll grant" "$RUN_LOG"
if [[ -e "$GRANT_BLOB" ]]; then
  fail "the grant blob survived the discard: $GRANT_BLOB"
else
  pass "the grant blob is gone"
fi
if [[ -f "$SE_BLOB" ]]; then
  pass "and the KEK blob beside it was not touched"
else
  fail "the discard took the KEK blob $SE_BLOB with it"
fi
assert_cmd_fails_with p4_discard_twice "NoEnclaveKeyToDiscard" \
  "$BIN" discard-enclave-key grant

echo
echo "==> with the pin back but the key it names gone, serve must refuse for the OTHER reason"
echo "    the same error covers: a pinned key this machine can no longer produce."
write_config "$CFG_SERVICE" "$CFG_ACCOUNT" "$CFG_GRANT_PUB"
assert_cmd_fails_with p4_serve_blob_gone "GrantKeyMissingRunEnrollGrant" "$BIN" serve
PORT_PIDS="$(port_pids)"
assert_eq "and it never bound the dry port" "" "$PORT_PIDS"

echo
echo "==> enroll grant mints a REPLACEMENT and re-pins it. A new grant key is a new pin, and"
echo "    every later phase is verified against this one."
run_cmd p4_enroll_grant_replacement "$BIN" enroll grant
assert_eq "enroll grant after a discard exits 0" "0" "$RUN_RC"
assert_contains "and says MINTED, because the discarded key is not coming back" \
  "MINTED a new Secure Enclave grant key" "$RUN_LOG"
GRANT_PUB_OLD="$CFG_GRANT_PUB"
CFG_GRANT_PUB="$(toml_value "$CFG_FILE" grant_public_key)"
if [[ -n "$CFG_GRANT_PUB" && "$CFG_GRANT_PUB" != "$GRANT_PUB_OLD" ]]; then
  pass "config.toml now pins a DIFFERENT grant key from the discarded one"
else
  fail "the pin did not change across the discard [old='$GRANT_PUB_OLD' new='$CFG_GRANT_PUB']"
fi
if [[ -f "$GRANT_BLOB" ]]; then
  pass "a fresh grant blob is back at $GRANT_BLOB"
else
  fail "grant blob MISSING at $GRANT_BLOB after enroll grant"
fi
assert_file_mode "and the replacement is 600 too" "600" "$GRANT_BLOB"

assert_taps "the entire grant phase, discard and re-enroll included, cost ZERO biometrics" \
  "0" "$BIO_PHASE"
echo "  note  'serve succeeds once the grant key is enrolled' is phase 6; that the pinned key"
echo "  note  actually VERIFIES an enclave grant is phase 5, which cannot sign without one."
else
  skipped_phase "PHASE 4" "not selected for this run"
fi

if want_phase 5; then
phase "PHASE 5 — scoped signing through a bundle (1 Touch ID; every denial costs 0)"

echo "Signing has exactly one human entry point: a transaction is filed as a bundle, then"
echo "'bundle sign' takes it through the policy, the typed deconstruction, the grant pin and"
echo "one approval. Policy load and evaluation, the argument bounds and the grant pin lookup"
echo "all run BEFORE the approval sheet, so every refusal below costs no biometric at all."
POLICY_DIR="$CFG_STORE/policies"
POLICY_FILE="$POLICY_DIR/$EVM_KEY.toml"
BUNDLE_DIR="$HOT_CHEESE_HOME/bundles"
APPROVAL_BANNER="=== hot_cheese Sign request #"
INTENT_OK="$OUT_DIR/intent_ok.json"
INTENT_DRAIN="$OUT_DIR/intent_drain.json"
INTENT_BAD_TO="$OUT_DIR/intent_bad_to.json"
INTENT_BAD_CHAIN="$OUT_DIR/intent_bad_chain.json"
INTENT_BAD_ARG="$OUT_DIR/intent_bad_arg.json"
INTENT_UNDECLARED="$OUT_DIR/intent_undeclared.json"
INTENT_TYPED="$OUT_DIR/intent_typed.json"

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
  "nonce": "1"
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
  "nonce": "2"
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
  "nonce": "3"
}
JSON

cat > "$INTENT_BAD_ARG" <<JSON
{
  "kind": "safe_tx",
  "key": "$EVM_KEY",
  "safe": "$SAFE_ADDR",
  "chain_id": "1",
  "to": "$TOKEN_ADDR",
  "value": "0",
  "data": "$TRANSFER_TO_ATTACKER",
  "operation": "call",
  "safe_tx_gas": "0",
  "base_gas": "0",
  "gas_price": "0",
  "gas_token": "$ZERO_ADDR",
  "refund_receiver": "$ZERO_ADDR",
  "nonce": "4"
}
JSON

cat > "$INTENT_UNDECLARED" <<JSON
{
  "kind": "safe_tx",
  "key": "$EVM_KEY",
  "safe": "$SAFE_ADDR",
  "chain_id": "1",
  "to": "$TOKEN_ADDR",
  "value": "0",
  "data": "$UNDECLARED_DATA",
  "operation": "call",
  "safe_tx_gas": "0",
  "base_gas": "0",
  "gas_price": "0",
  "gas_token": "$ZERO_ADDR",
  "refund_receiver": "$ZERO_ADDR",
  "nonce": "5"
}
JSON

cat > "$INTENT_TYPED" <<JSON
{
  "kind": "typed_data",
  "key": "$EVM_KEY",
  "schema": "nothing_declared",
  "chain_id": "1",
  "verifying_contract": "$SAFE_ADDR",
  "message": {}
}
JSON

echo
echo "==> 5 setup: name the Safe this machine collects for, on both chains the fixtures use,"
echo "    then file all four transactions. bundle new takes no unlocker and reaches no key,"
echo "    so every one of these costs zero biometrics."
mkdir -p "$BUNDLE_DIR"
cat > "$BUNDLE_DIR/safes.toml" <<SAFES
[[safe]]
address = "$SAFE_ADDR"
chain_id = 1
threshold = 1
owners = ["$ADDR_SE"]

[[safe]]
address = "$SAFE_ADDR"
chain_id = 137
threshold = 1
owners = ["$ADDR_SE"]
SAFES

bundle_new p5_new_ok "$INTENT_OK"
HASH_OK="$BUNDLE_HASH"
bundle_new p5_new_drain "$INTENT_DRAIN"
HASH_DRAIN="$BUNDLE_HASH"
bundle_new p5_new_bad_to "$INTENT_BAD_TO"
HASH_BAD_TO="$BUNDLE_HASH"
bundle_new p5_new_bad_chain "$INTENT_BAD_CHAIN"
HASH_BAD_CHAIN="$BUNDLE_HASH"
bundle_new p5_new_bad_arg "$INTENT_BAD_ARG"
HASH_BAD_ARG="$BUNDLE_HASH"
bundle_new p5_new_undeclared "$INTENT_UNDECLARED"
HASH_UNDECLARED="$BUNDLE_HASH"

echo
echo "==> 5a: no policy file at all. Deny by default: a perfectly valid intent must still fail."
BIO_PHASE="$(bio_window_start)"
if [[ -e "$POLICY_FILE" ]]; then
  fail "a policy file already exists at $POLICY_FILE"
fi
assert_cmd_fails_with p5a_no_policy "Policy(Io(" "$BIN" bundle sign "$HASH_OK" --key "$EVM_KEY" --no-sync
assert_not_contains "5a showed no approval banner" "$APPROVAL_BANNER" "$RUN_LOG"

echo
echo "==> 5b: a policy WITHOUT chain_id must fail to LOAD. This is exactly what a stale"
echo "    production policy file will do at cutover — the cross-chain replay pin is mandatory."
mkdir -p "$POLICY_DIR"
cat > "$POLICY_FILE" <<TOML
safe = "$SAFE_ADDR"

[[allow]]
to = "$TOKEN_ADDR"
max_value = "0"
operation = "call"

  [[allow.call]]
  signature = "transfer(address,uint256)"

    [[allow.call.arg]]
    at = 0
    name = "to"
    rule = "unbounded"

    [[allow.call.arg]]
    at = 1
    name = "amount"
    rule = "unbounded"
TOML
assert_cmd_fails_with p5b_no_chain_id "Policy(Toml(" "$BIN" bundle sign "$HASH_OK" --key "$EVM_KEY" --no-sync
assert_not_contains "5b showed no approval banner" "$APPROVAL_BANNER" "$RUN_LOG"

echo
echo "==> 5b2: a policy still written in the retired selectors language. A 4-byte selector"
echo "    cannot be inverted into a signature, so nothing is auto-converted: the file refuses"
echo "    to load and the refusal names the term the operator has to replace."
cat > "$POLICY_FILE" <<TOML
safe = "$SAFE_ADDR"
chain_id = 1

[[allow]]
to = "$TOKEN_ADDR"
selectors = ["0xa9059cbb"]
max_value = "0"
operation = "call"
TOML
assert_cmd_fails_with p5b2_selectors "Policy(Toml(" "$BIN" bundle sign "$HASH_OK" --key "$EVM_KEY" --no-sync
assert_contains "the refusal names the retired term" "selectors" "$RUN_LOG"
assert_not_contains "5b2 showed no approval banner" "$APPROVAL_BANNER" "$RUN_LOG"

echo
echo "==> 5c: the good policy, then the allowed transfer. The rule declares the FULL canonical"
echo "    signature, so the selector is derived from it and every argument carries its own"
echo "    bound: a recipient allow-list and a ceiling on the amount."
cat > "$POLICY_FILE" <<TOML
safe = "$SAFE_ADDR"
chain_id = 1

[[allow]]
to = "$TOKEN_ADDR"
max_value = "0"
operation = "call"

  [[allow.call]]
  signature = "transfer(address,uint256)"

    [[allow.call.arg]]
    at = 0
    name = "to"
    rule = { one_of = { addresses = ["$OTHER_ADDR"] } }

    [[allow.call.arg]]
    at = 1
    name = "amount"
    rule = { max = { max = "10", amount_of = "$TOKEN_ADDR" } }
TOML
echo "    Read the decoded summary, then type y and press Enter. ONE Touch ID sheet follows,"
echo "    and that single biometric does THREE enclave things: it mints the per-payload grant,"
echo "    it lets the grant verify, and it unlocks the key. Only {r,s,v} is filed."
TAPS_EXPECTED=$((TAPS_EXPECTED + 1))
BIO_START="$(bio_window_start)"
run_tty p5c_sign_ok "$BIN" bundle sign "$HASH_OK" --key "$EVM_KEY" --no-sync
assert_eq "bundle sign exit code" "0" "$RUN_RC"
assert_contains "the approval prompt was reached" "$APPROVAL_BANNER" "$RUN_LOG"
assert_contains "the signature was filed into the bundle" "collected signature" "$RUN_LOG"
SIG_FILE="$BUNDLE_DIR/$HASH_OK/$ADDR_SE.json"
assert_matches "the filed signature is 0x + 130 hex" '"signature": ?"0x[0-9a-f]{130}"' "$SIG_FILE"
assert_contains "and it is filed under the signing key's own address" "$ADDR_SE" "$SIG_FILE"
assert_contains "the bundle's threshold of 1 is met" "met=true" "$RUN_LOG"
echo "  note  a signature exists at all only because the enclave grant verified under the"
echo "  note  pinned public key: sign takes the verified grant BY VALUE and cannot be reached"
echo "  note  without one, so this is the hardware proof phase 4 could not take on its own."

assert_taps "one sign, one sheet: the grant signature AND the key unlock reused the approval (2+ means the reuse broke)" \
  "1" "$BIO_START"

echo
echo "==> and the signer the bundle reports is ecrecovered from the signature, against the owner"
echo "    list safes.toml states — so this is the store's own answer, not the signer's claim."
run_cmd p5c_status "$BIN" bundle status "$HASH_OK" --no-sync
assert_eq "bundle status exit code" "0" "$RUN_RC"
SIGNER="$(field_value "$RUN_LOG" signer)"
assert_eq "the signer is $EVM_KEY's address" "$ADDR_SE" "$(lower "$SIGNER")"
assert_contains "and the quorum reads as met there too" "met=true" "$RUN_LOG"
assert_not_contains "no rival competes for that Safe, chain and nonce" "RIVAL" "$RUN_LOG"

echo
echo "==> 5d: the gas-refund DRAIN. Allowed 'to', allowed selector, value 0 — and it still"
echo "    drains the Safe through the refund fields. Fail-closed without a [refunds] opt-in."
assert_cmd_fails_with p5d_drain "RefundNotAllowed" "$BIN" bundle sign "$HASH_DRAIN" --key "$EVM_KEY" --no-sync
assert_not_contains "5d showed no approval banner" "$APPROVAL_BANNER" "$RUN_LOG"

echo
echo "==> 5e: a destination outside the allow-list."
assert_cmd_fails_with p5e_bad_to "ToNotAllowed" "$BIN" bundle sign "$HASH_BAD_TO" --key "$EVM_KEY" --no-sync
assert_not_contains "5e showed no approval banner" "$APPROVAL_BANNER" "$RUN_LOG"

echo
echo "==> 5f: the right Safe on the wrong chain."
assert_cmd_fails_with p5f_bad_chain "ChainMismatch" "$BIN" bundle sign "$HASH_BAD_CHAIN" --key "$EVM_KEY" --no-sync
assert_not_contains "5f showed no approval banner" "$APPROVAL_BANNER" "$RUN_LOG"

echo
echo "==> 5g: the same allowed intent with the grant pin removed from config.toml. There is"
echo "    nothing left to verify an approval against, so it must die BEFORE the human is asked."
write_config "$CFG_SERVICE" "$CFG_ACCOUNT" ""
assert_cmd_fails_with p5g_no_pin "NoPinnedGrantKey" "$BIN" bundle sign "$HASH_OK" --key "$EVM_KEY" --no-sync
assert_not_contains "5g showed no approval banner" "$APPROVAL_BANNER" "$RUN_LOG"
write_config "$CFG_SERVICE" "$CFG_ACCOUNT" "$CFG_GRANT_PUB"
assert_eq "the honest pin is back in config.toml" "$CFG_GRANT_PUB" "$(toml_value "$CFG_FILE" grant_public_key)"

echo
echo "==> 5h: the allowed destination, the allowed signature, a recipient the rule does not"
echo "    list. Before typed admission an argument was bounded by nothing at all."
assert_cmd_fails_with p5h_bad_arg "AddressNotAllowed" "$BIN" bundle sign "$HASH_BAD_ARG" --key "$EVM_KEY" --no-sync
assert_contains "the refusal names the recipient it refused" "$ATTACKER_ADDR" "$RUN_LOG"
assert_not_contains "5h showed no approval banner" "$APPROVAL_BANNER" "$RUN_LOG"

echo
echo "==> 5i: four bytes the policy declares no signature for. There is no undecoded"
echo "    representation left, so this cannot be rendered as hex for a human to eyeball."
assert_cmd_fails_with p5i_undeclared "SignatureNotAllowed" "$BIN" bundle sign "$HASH_UNDECLARED" --key "$EVM_KEY" --no-sync
assert_not_contains "5i showed no approval banner" "$APPROVAL_BANNER" "$RUN_LOG"

echo
echo "==> 5j: an EIP-712 typed-data intent. It is a first-class intent kind, but its shape is"
echo "    the POLICY's and there is no multi-device collection for it, so a bundle refuses it."
assert_cmd_fails_with p5j_typed "NotBundleable" "$BIN" bundle new --no-sync --file "$INTENT_TYPED"
assert_not_contains "5j showed no approval banner" "$APPROVAL_BANNER" "$RUN_LOG"

assert_taps "the whole of phase 5 cost one sheet: every refusal cost no biometric" \
  "1" "$BIO_PHASE"
else
  skipped_phase "PHASE 5" "not selected for this run"
fi

if ! want_phase 6; then
  skipped_phase "PHASE 6" "not selected for this run"
elif [[ -n "$SKIP_SERVE" ]]; then
  phase "PHASE 6 — SKIPPED (SKIP_SERVE is set)"
  echo "The live daemon, TLS pinning, the export refusal, the /read path, the attribution"
  echo "challenge and the read grant were NOT exercised."
else
  phase "PHASE 6 — serve, the export refusal, the attribution challenge and the read grant (2 Touch ID, one terminal)"

  echo "The daemon runs HERE, started and stopped by this script, in the terminal you are"
  echo "reading. It starts at all only because phase 4 enrolled the grant key it refused to run"
  echo "without. There is no second terminal and no handoff: its output is teed to this screen"
  echo "AND to $SERVE_LOG, and it takes your answers from this keyboard."
  echo
  echo "It cannot be left behind. A guard process armed in phase 0 kills it BY THE PID this"
  echo "script recorded the instant this script stops existing — a clean exit, a failed"
  echo "assertion, Ctrl-C, SIGTERM, or this script being SIGKILLed outright. It kills nothing"
  echo "else: a daemon this script did not start is a daemon it refuses to touch."
  echo
  echo "  THIS PHASE ASKS YOU FOR THREE DIFFERENT ANSWERS AND SAYS WHICH ONE EACH TIME. In"
  echo "  order: one ordinary y, then ONE PROMPT YOU DELIBERATELY DO NOT ANSWER, then a plain"
  echo "  y that MUST be rejected, then the yN the brackets show. Read each block BEFORE you"
  echo "  type; the daemon is one process, so a prompt you let expire by accident makes every"
  echo "  later prompt in this phase a challenged one."
  echo
  echo "  Every prompt below denies itself in $DRY_APPROVAL_SECS to $APPROVAL_MAX_SECS seconds, because this run puts"
  echo "  approval_timeout_secs = $DRY_APPROVAL_SECS in the dry config.toml for the length of this phase."

  echo
  echo "==> first: a nonsensical deadline must stop the command at config load, not at an"
  echo "    incident. This costs nothing: nothing unlocks, nothing binds."
  CFG_APPROVAL_SECS=0
  write_config "$CFG_SERVICE" "$CFG_ACCOUNT" "$CFG_GRANT_PUB"
  assert_cmd_fails_with p6_bad_timeout "InvalidApprovalTimeout" "$BIN" list
  CFG_APPROVAL_SECS="$DRY_APPROVAL_SECS"
  write_config "$CFG_SERVICE" "$CFG_ACCOUNT" "$CFG_GRANT_PUB"
  assert_eq "config.toml now states the prompt deadline this phase runs on" \
    "approval_timeout_secs = $DRY_APPROVAL_SECS" \
    "$(grep -E '^[[:space:]]*approval_timeout_secs' "$CFG_FILE" || true)"
  run_cmd p6_timeout_parses "$BIN" list
  assert_eq "and an ordinary command still loads that config" "0" "$RUN_RC"

  echo
  echo "==> starting the daemon under the guard"
  start_serve
  echo "  ...  waiting up to 30s for it to bind"
  if serve_log_holds "hot_cheese serving over https" 30; then
    pass "the daemon got past the grant gate and bound the socket"
  else
    fail "the daemon never reported binding; see $SERVE_LOG"
  fi
  PORT_PIDS="$(port_pids)"
  if [[ -n "$PORT_PIDS" ]]; then
    pass "the daemon is listening on 127.0.0.1:$DRY_PORT (pid(s): $PORT_PIDS)"
  else
    fail "nothing is listening on 127.0.0.1:$DRY_PORT — is port=$DRY_PORT in the dry config.toml?"
  fi
  assert_eq "the pid the guard would kill is the pid this script started" \
    "$SERVE_PID" "$(cat "$SERVE_PID_FILE" 2>/dev/null || true)"
  assert_eq "and that pid is the daemon itself, not a shell wrapping it" \
    "$BIN serve" "$(ps -ww -o args= -p "$SERVE_PID" 2>/dev/null || true)"
  if [[ -s "$SERVE_LOG" ]]; then
    pass "the daemon's log is being teed to $SERVE_LOG"
  else
    fail "no daemon log at $SERVE_LOG"
  fi

  echo
  echo "==> /health is the ONLY endpoint that does not decrypt a key. No prompt."
  run_cmd p6_health curl -sS --cacert "$CERT_INSTALLED" \
    "https://127.0.0.1:$DRY_PORT/health"
  assert_eq "curl /health exit code" "0" "$RUN_RC"
  assert_contains "/health answered ok over the pinned TLS cert" "ok" "$RUN_LOG"

  echo
  echo "==> the assertion this whole feature exists for: /read of a SIGN-ONLY key. The permit"
  echo "    is minted from the cleartext header BEFORE the approval prompt and before anything"
  echo "    unlocks, so the refusal is structural and FREE: you are not asked anything,"
  echo "    and nobody's finger is spent telling an attacker no."
  echo "    The client is handed the fingerprint phase 1 read back out of the installed cert, so"
  echo "    it pins THAT certificate and writes no first-use record into your real home dir."
  BIO_START="$(bio_window_start)"
  run_cmd p6_read_signonly env "HOT_CHEESE_CERT_SHA256=$FINGERPRINT" \
    cargo run --release --manifest-path "$PIN_CERT_MANIFEST" \
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
  assert_not_contains "no approval prompt was ever put in front of the operator for it" \
    "=== hot_cheese Read request #" "$SERVE_LOG"
  assert_taps "THE EXPORT REFUSAL COST ZERO TOUCH ID SHEETS" "0" "$BIO_START"

  echo
  echo "==> now the same read against the key that DECLARED itself shareable. The daemon will"
  echo "    print the request below and stop at 'Approve request #N? [y/N]'. ANSWER IT WITH y HERE."
  echo "    Only then does the ONE Touch ID sheet appear. The key is encrypted end-to-end to"
  echo "    the client process: the client prints only its length and digest, never the bytes."
  TAPS_EXPECTED=$((TAPS_EXPECTED + 1))
  BIO_START="$(bio_window_start)"
  run_cmd p6_pin_cert env "HOT_CHEESE_CERT_SHA256=$FINGERPRINT" \
    cargo run --release --manifest-path "$PIN_CERT_MANIFEST" \
    --example pin_cert -- "https://127.0.0.1:$DRY_PORT" "$SHARE_KEY"
  assert_eq "pin_cert exit code" "0" "$RUN_RC"
  assert_contains "this one WAS put in front of the operator first" \
    "=== hot_cheese Read request #" "$SERVE_LOG"
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
  echo "================================================================"
  echo "6c — THE ATTRIBUTION CHALLENGE. READ ALL OF THIS BEFORE ANSWERING ANYTHING."
  echo "================================================================"
  echo "A prompt you never answered leaves the screen on its own, and whatever is on screen"
  echo "next is a DIFFERENT request that you have not read. The control this phase exercises is"
  echo "that such a prompt can only be approved by a line carrying its own number: a plain 'y'"
  echo "is a line you could have composed for the request that vanished, so it DENIES."
  echo
  echo "Three requests follow, in this order:"
  echo "  1. one you DO NOT ANSWER. Type nothing. It denies itself in $DRY_APPROVAL_SECS to $APPROVAL_MAX_SECS seconds"
  echo "     and this script waits for the daemon to say so — do not press anything."
  echo "  2. one you answer with a PLAIN y. It must be REFUSED. That is the assertion."
  echo "  3. one you answer with the yN the prompt's brackets show — y then the request number,"
  echo "     no space. That one is approved and costs the single Touch ID sheet of this block."
  echo
  echo "==> 6c-1: the request nobody answers. HANDS OFF THE KEYBOARD for $APPROVAL_MAX_SECS seconds."
  BIO_START="$(bio_window_start)"
  SEQ_BEFORE="$(last_read_seq)"
  read_probe p6c_expire "" "/read/$SHARE_KEY"
  assert_contains "the unanswered request was refused with a 403" "http_code=403" "$RUN_LOG"
  assert_serve_log "the daemon recorded that nobody answered it, rather than inventing an answer" \
    "$EXPIRED_LINE" 30
  assert_serve_log "and the screen said so where the operator would read it" \
    "expired with no answer and was DENIED" 15
  assert_taps "an expired prompt costs no biometric at all" "0" "$BIO_START"
  SEQ_EXPIRED="$(last_read_seq)"
  if [[ -n "$SEQ_EXPIRED" && "$SEQ_EXPIRED" != "$SEQ_BEFORE" ]]; then
    pass "request #$SEQ_EXPIRED is the one that expired"
  else
    fail "no new request number appeared for the expiring request [before='$SEQ_BEFORE' after='$SEQ_EXPIRED']"
  fi

  echo
  echo "==> 6c-2: the SAME read again. The daemon now prints '*** THE SCREEN CHANGED ...' above"
  echo "    the request, and the prompt ends in [yN/N] instead of [y/N]. ANSWER IT WITH A PLAIN"
  echo "    y — one character — and press Enter. It MUST be refused, and that refusal is the"
  echo "    whole point: the answer you had ready was for a request that is no longer there."
  BIO_START="$(bio_window_start)"
  read_probe p6c_plain_y "" "/read/$SHARE_KEY"
  assert_contains "the plain y was refused with a 403" "http_code=403" "$RUN_LOG"
  assert_serve_log "the prompt announced that it had replaced an unanswered one" \
    "$STARTLE_BANNER" 15
  assert_serve_log "and the daemon says exactly why it denied it" "$UNATTRIBUTED_LINE" 15
  assert_taps "A PLAIN y AT A CHALLENGED PROMPT RELEASES NOTHING AND COSTS NO BIOMETRIC" \
    "0" "$BIO_START"
  SEQ_CHALLENGED="$(last_read_seq)"
  if [[ -n "$SEQ_CHALLENGED" ]]; then
    assert_serve_log "the prompt showed the answer it would have taken" \
      "[y$SEQ_CHALLENGED/N]" 15
  else
    fail "could not read the challenged request's number out of $SERVE_LOG"
  fi

  echo
  echo "==> 6c-3: once more. The prompt is STILL challenged, because a denial that carried no"
  echo "    number does not end the run. This time answer with the yN the brackets show — for"
  echo "    'Approve request #12? [y12/N]' you type y12 — and the ONE Touch ID sheet follows."
  TAPS_EXPECTED=$((TAPS_EXPECTED + 1))
  BIO_START="$(bio_window_start)"
  run_cmd p6c_attributed env "HOT_CHEESE_CERT_SHA256=$FINGERPRINT" \
    cargo run --release --manifest-path "$PIN_CERT_MANIFEST" \
    --example pin_cert -- "https://127.0.0.1:$DRY_PORT" "$SHARE_KEY"
  assert_eq "the attributable answer released the key" "0" "$RUN_RC"
  assert_contains "and it is the same 32-byte secret" "len=32" "$RUN_LOG"
  assert_eq "and the same shareable key" "$ADDR_SHARE" "$(lower "$(field_value "$RUN_LOG" evm_address)")"
  assert_taps "the attributable answer costs exactly the one sheet an approved read always did" \
    "1" "$BIO_START"
  LAST_READ_SEQ="$(last_read_seq)"
  if [[ -n "$LAST_READ_SEQ" && -n "$SEQ_CHALLENGED" && "$LAST_READ_SEQ" != "$SEQ_CHALLENGED" ]]; then
    assert_serve_log "this prompt was challenged too, and named its own number" \
      "[y$LAST_READ_SEQ/N]" 15
  else
    fail "no third request number appeared [challenged='$SEQ_CHALLENGED' last='$LAST_READ_SEQ']"
  fi
  echo "  note  the run of challenged prompts ended here: you answered one with its own number,"
  echo "  note  so 6d onwards is back to ordinary prompts. Nothing below asks you for one."

  echo
  echo "==> 6d: the READ GRANT phase 3 minted. It releases the SAME key over the SAME route with"
  echo "    NO approval prompt and NO Touch ID at all, until it expires — which is the entire"
  echo "    reason it exists, and the entire reason it is bounded and revocable."
  BIO_START="$(bio_window_start)"
  SEQ_BEFORE="$(last_read_seq)"
  if [[ -z "$GRANT_TOKEN" ]]; then
    fail "phase 3 captured no grant token, so the token path cannot be exercised"
  else
    run_cmd p6d_granted env "HOT_CHEESE_CERT_SHA256=$FINGERPRINT" \
      "$GRANT_ENV_NAME=$GRANT_TOKEN" \
      cargo run --release --manifest-path "$PIN_CERT_MANIFEST" \
      --example pin_cert -- "https://127.0.0.1:$DRY_PORT" "$SHARE_KEY"
    assert_eq "the granted read exit code" "0" "$RUN_RC"
    assert_contains "it returned the 32-byte secret" "len=32" "$RUN_LOG"
    assert_eq "and it is the SAME key an approved read hands out" \
      "$ADDR_SHARE" "$(lower "$(field_value "$RUN_LOG" evm_address)")"
    assert_serve_log "the daemon records the release as one no human saw" \
      "$GRANT_RELEASE_LINE" 15
    assert_eq "NOBODY WAS ASKED: no new request number reached the operator's screen" \
      "$SEQ_BEFORE" "$(last_read_seq)"
    assert_taps "A GRANTED READ COSTS ZERO TOUCH ID SHEETS" "0" "$BIO_START"
  fi

  echo
  echo "==> 6e: a token that opens nothing. It must be refused with the same status and the same"
  echo "    empty body a dead grant gets, so spraying tokens tells an attacker nothing and — the"
  echo "    part that matters — never turns into a prompt on your screen."
  BIO_START="$(bio_window_start)"
  SEQ_BEFORE="$(last_read_seq)"
  read_probe p6e_junk_token "$JUNK_GRANT_TOKEN" "/read/$SHARE_KEY"
  assert_contains "the junk token got a 403" "http_code=403" "$RUN_LOG"
  assert_serve_log "the daemon logged that the grant released nothing" \
    "a read grant released nothing" 15
  assert_eq "and raised no approval prompt" "$SEQ_BEFORE" "$(last_read_seq)"
  assert_taps "a wrong token costs no biometric" "0" "$BIO_START"

  echo
  echo "==> 6f: a token on a route that has no grants. A credential with a second use is one"
  echo "    nobody can reason about, so it is refused on sight rather than ignored — and the"
  echo "    refusal lands before the route would have asked anyone anything."
  BIO_START="$(bio_window_start)"
  SEQ_BEFORE="$(last_read_seq)"
  read_probe p6f_wrong_route "$JUNK_GRANT_TOKEN" "/evm_address/$SHARE_KEY"
  assert_contains "a token offered on /evm_address got a 403" "http_code=403" "$RUN_LOG"
  assert_serve_log "and was refused before anything could be approved" \
    "a read-grant token was refused before any approval" 15
  assert_eq "so it raised no approval prompt either" "$SEQ_BEFORE" "$(last_read_seq)"
  assert_taps "a token on the wrong route costs no biometric" "0" "$BIO_START"

  echo
  echo "==> 6g: minting a grant needs the store, and the daemon is holding it. 'allow' must say"
  echo "    so rather than race it, while 'list' — which writes nothing and unlocks nothing —"
  echo "    still answers, so an operator can audit grants without stopping their daemon."
  assert_cmd_fails_with p6g_allow_while_serving "Flock(Held" "$BIN" read-grant allow "$SHARE_KEY"
  run_cmd p6g_list_while_serving "$BIN" read-grant list
  assert_eq "read-grant list answers while the daemon holds the claim" "0" "$RUN_RC"
  assert_contains "and still names the live grant" "grant=$SHARE_KEY" "$RUN_LOG"

  echo
  echo "==> 6h: and the script stops the daemon it started. Nothing is asked of you here: the"
  echo "    SIGTERM the daemon handles, then SIGKILL if it will not go, then the port."
  STOPPED_PID="$SERVE_PID"
  if stop_serve; then
    pass "the daemon at pid $STOPPED_PID stopped when this script told it to"
  else
    fail "the daemon at pid $STOPPED_PID survived SIGTERM and SIGKILL"
  fi
  assert_serve_log "and it said so on its way out, in the log this phase read all along" \
    "closing every tunnel, unlinking every socket, and leaving" 10
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
    fail "port $DRY_PORT is STILL held 10s after the daemon was stopped, pid(s): $PORT_PIDS"
    echo "  FAIL  this script did not start that one, so it will NOT kill it. Inspect it with:"
    echo "  FAIL      ps -p $PORT_PIDS -o pid,command"
    echo "  FAIL  and stop it yourself."
  fi
  CFG_APPROVAL_SECS=""
  write_config "$CFG_SERVICE" "$CFG_ACCOUNT" "$CFG_GRANT_PUB"
  assert_eq "and config.toml is back to the 60s default the rest of the run uses" \
    "" "$(grep -E '^[[:space:]]*approval_timeout_secs' "$CFG_FILE" || true)"
fi

if want_phase 7; then
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
echo "==> and with nothing at the key path, discard-enclave-key has nothing to offer either."
echo "    'the key is gone' and 'something else is squatting on your key path' are different"
echo "    problems, and this is the one command that must never confuse them."
BIO_START="$(bio_window_start)"
assert_cmd_fails_with p7_discard_absent "NoEnclaveKeyToDiscard" \
  "$BIN" discard-enclave-key se
assert_contains "and it names the empty path it looked at" "$SE_BLOB" "$RUN_LOG"
assert_taps "that refusal cost no biometric" "0" "$BIO_START"

echo
echo "==> now the escape hatch itself, with the enclave key still missing. This one SHOULD"
echo "    ask for the phase-1 recovery passphrase."
run_tty p7_pass_unlock "$BIN" --unlock passphrase address evm "$EVM_KEY"
assert_eq "the passphrase escape hatch exits 0 with no enclave key" "0" "$RUN_RC"
assert_eq "it recovers the same address" "$ADDR_SE" "$(lower "$(field_value "$RUN_LOG" addr)")"

mv "$SE_BLOB_ASIDE" "$SE_BLOB"
BLOB_SHA_AFTER="$(shasum -a 256 "$SE_BLOB" 2>/dev/null | cut -d' ' -f1 || true)"
assert_eq "the restored SE blob is byte-identical" "$BLOB_SHA_BEFORE" "$BLOB_SHA_AFTER"
else
  skipped_phase "PHASE 7" "not selected for this run"
fi

if want_phase 8; then
phase "PHASE 8 — the store as a git repository, and losing pieces of it (1 Touch ID, no network)"

echo "The store is a git repository and every mutation commits it. Backups are namespaced per"
echo "install: a push lands in <folder>/<vault_id>.git, so two Macs with DIFFERENT DEKs can"
echo "share one backup host without overwriting each other. The vault id is cleartext in"
echo "keyring.json, which is why a push never has to unlock anything. This phase touches NO"
echo "network: it reads the id three independent ways, checks that every earlier phase left the"
echo "store committed, and checks the commands that would reach a remote refuse outright when"
echo "none is configured."
BIO_PHASE="$(bio_window_start)"

assert_matches "keyring.json carries a v_<32 hex> vault id, in cleartext" \
  '"vault_id"[[:space:]]*:[[:space:]]*"v_[0-9a-f]{32}"' "$KEYRING_FILE"
VAULT_KEYRING="$(grep -oE 'v_[0-9a-f]{32}' "$KEYRING_FILE" | head -1 || true)"
assert_eq "the vault id on disk is the one init minted, unchanged by every command since" \
  "$VAULT_INIT" "$VAULT_KEYRING"

if [[ -d "$CFG_STORE/.git" ]]; then
  pass "the store is a git repository"
else
  fail "the store has no .git after every earlier phase [$CFG_STORE]"
fi

echo
echo "==> phase 5 wrote its policy file into the store BY HAND, the way an operator does. Take"
echo "    it through the store's own chokepoint first, so the clean check below is a statement"
echo "    about hot_cheese's mutations and not about this harness' editing. A key already sealed"
echo "    under the use it is asked for is decided from the cleartext header, so this opens and"
echo "    commits the store without unlocking anything."
run_cmd p8_flush "$BIN" seal "$SHARE_KEY" --use shareable
assert_eq "opening the store to commit a hand-written policy exits 0" "0" "$RUN_RC"
assert_contains "and it re-sealed nothing, so it never reached the DEK" "nothing to seal" "$RUN_LOG"

STORE_STATUS="$(git -C "$CFG_STORE" status --porcelain 2>&1 || true)"
if [[ -z "$STORE_STATUS" ]]; then
  pass "every mutation so far committed itself: the store is clean and unmodified"
else
  fail "the store has uncommitted changes after every earlier phase [$STORE_STATUS]"
fi
run_cmd p8_log git -C "$CFG_STORE" log --oneline
assert_contains "the commit messages name this install's vault and nothing else" \
  "hot_cheese $VAULT_KEYRING" "$RUN_LOG"
run_cmd p8_author git -C "$CFG_STORE" log -1 --format=%an%ae
assert_contains "the committer identity is pinned, so no hostname or operator email is recorded" \
  "hot_cheesehot_cheese@localhost" "$RUN_LOG"

run_cmd p8_tracked git -C "$CFG_STORE" ls-files
for tracked in "$EVM_KEY" "$SOL_KEY" "$SHARE_KEY" "$BYTES_KEY" keyring.json "policies/$EVM_KEY.toml"; do
  assert_contains "the backup carries $tracked" "$tracked" "$RUN_LOG"
done
assert_not_contains "and carries no half-written temp file" ".hctmp" "$RUN_LOG"

run_cmd p8_status "$BIN" backup status
assert_eq "backup status reads the local state with no remote configured" "0" "$RUN_RC"
assert_contains "backup status names this install's vault" "$VAULT_KEYRING" "$RUN_LOG"

echo
echo "==> with backup_remotes = [] there is nothing to talk to, and both remote-reading"
echo "    subcommands must say so instead of guessing a host."
assert_cmd_fails_with p8_list "NoBackupRemote" "$BIN" backup list
assert_cmd_fails_with p8_pull "NoBackupRemote" "$BIN" backup pull

echo
echo "==> a forced pull still has two separate confirmations, because it can cost two different"
echo "    things: history it rewinds, and the last enrollment this machine can unwrap its own"
echo "    DEK with. NEITHER IS REACHABLE FROM AN ARGUMENT: the flags that used to carry them are"
echo "    gone, so the parser must refuse both spellings outright. That is what closes the door"
echo "    an automated process running as you would otherwise walk through."
assert_cmd_fails_with p8_no_rewind_flag "unexpected argument '--confirm-rewind' found" \
  "$BIN" backup pull --force --confirm-rewind "$PULL_REWIND_PHRASE"
assert_cmd_fails_with p8_no_lost_flag "unexpected argument '--confirm-lost-enrollments' found" \
  "$BIN" backup pull --force --confirm-lost-enrollments "$PULL_LOST_ENROLLMENTS_PHRASE"
assert_cmd_fails_with p8_pull_forced "NoBackupRemote" "$BIN" backup pull --force
run_cmd p8_pull_help "$BIN" backup pull --help
assert_not_contains "pull offers no argument that carries a destruction phrase" \
  "--confirm" "$RUN_LOG"
assert_contains "and says the phrase is typed on a terminal" "typed on a terminal" "$RUN_LOG"
assert_contains "and says a pull can ADD files this machine never had, which is also a rewind" \
  "adds ones this machine never had" "$RUN_LOG"
echo "  note  every ground a forced pull refuses on — an older tip, a fork, a deletion, replaced"
echo "  note  contents, ADDING a store file this machine never had, and a store holding files no"
echo "  note  commit here records — needs a second machine's history over ssh. This run"
echo "  note  configures no remote by design, so watch for all of them on the first real"
echo "  note  cross-machine pull. The addition is the one that reads as harmless and is not: an"
echo "  note  incoming policies/<key>.toml where you had none turns deny-by-default into allow."
echo "  note  each of those phrases is typed at YOUR terminal on that pull. There is no argument"
echo "  note  that carries one, so a pull run from a script or an agent stops at the question."

PUSH_TARGET="$EXAMPLE_FOLDER/$VAULT_KEYRING.git"
echo
echo "  note  no remote is configured here, so nothing is pushed anywhere. With a remote whose"
echo "  note  folder is '$EXAMPLE_FOLDER', THIS install's store would push to:"
echo "  note      <host>:$PUSH_TARGET"
if [[ "$PUSH_TARGET" =~ ^[A-Za-z0-9_.-]+/v_[0-9a-f]{32}\.git$ ]]; then
  pass "a push target composed from this config + this keyring is <folder>/<vault_id>.git"
else
  fail "the composed push target is not <folder>/<vault_id>.git [got='$PUSH_TARGET']"
fi

echo
echo "==> the git history above lives INSIDE the store, so it dies with the store. The archive"
echo "    is the copy that does not: add-only snapshots written on every mutation, outside the"
echo "    home and outside the store, that nothing in hot_cheese ever removes. This run pointed"
echo "    it at a throwaway directory; a real install's is under ~/Library and is yours to prune."
run_cmd p8_archive_list "$BIN" archive list
assert_eq "archive list exit code" "0" "$RUN_RC"
assert_contains "and it names the directory config.toml pointed it at" \
  "archive=$DRY_ARCHIVE" "$RUN_LOG"
assert_matches "the mutations of phases 1-7 left snapshots in it" 'snapshots=[1-9][0-9]*' "$RUN_LOG"
assert_matches "each one is named by the digest of its own bytes" \
  'digest=[0-9a-f]{64}([[:space:]]|$)' "$RUN_LOG"
assert_file_mode "the archive directory is 700" "700" "$DRY_ARCHIVE"
SNAPSHOT_FILE="$(find "$DRY_ARCHIVE" -type f -name '*.json' 2>/dev/null | LC_ALL=C sort | head -1 || true)"
if [[ -n "$SNAPSHOT_FILE" ]]; then
  assert_file_mode "and a snapshot is read-only on disk, which is what add-only means" \
    "400" "$SNAPSHOT_FILE"
else
  fail "no snapshot file under $DRY_ARCHIVE"
fi
case "$DRY_ARCHIVE/" in
  "$HOT_CHEESE_HOME"/* | "$CFG_STORE"/*)
    fail "the archive is inside the home or the store, so a wipe of either takes the copies with it" ;;
  *) pass "the archive is outside both the home and the store, which is the only reason it survives either" ;;
esac

echo
echo "==> 8b: A KEYSTORE VANISHED. This is the failure this dry run exists to rehearse, and it"
echo "    has two halves that must never be confused. restore-missing puts back what this Mac's"
echo "    OWN history still holds: it moves no ref, records nothing and tells no backup, so"
echo "    getting it wrong costs a re-run. accept-deletions records the loss, which replicates"
echo "    to every backup as an ordinary fast-forward and cannot be undone. Reach for the first."
echo "    Neither one unlocks anything, so this whole block costs no prompt of any kind."
assert_cmd_fails_with p8_restore_nothing "NothingToRestore" "$BIN" restore-missing
assert_cmd_fails_with p8_accept_nothing "NoDeletionsToAccept" "$BIN" accept-deletions
echo "  note  a store with nothing missing is answered before any phrase is asked for: the"
echo "  note  phrase authorizes a loss that already happened, it does not create one."

HEAD_BEFORE="$(git -C "$CFG_STORE" rev-parse HEAD 2>/dev/null || true)"
LOST_SHA_BEFORE="$(shasum -a 256 "$SOL_FILE" 2>/dev/null | cut -d' ' -f1 || true)"
rm -f "$SOL_FILE"
if [[ -e "$SOL_FILE" ]]; then
  fail "could not delete $SOL_FILE to rehearse the loss"
else
  pass "deleted $SOL_KEY out of the store, the way a bad rm or a failed sync would"
fi

echo
echo "==> with a file genuinely gone, this is the destruction an unattended process would want."
echo "    It has no way to reach it: there is no flag, and stdin is not a terminal, so the"
echo "    commit is refused outright. This assertion is the whole guard now — read it as the"
echo "    one that keeps a script, a cron job or an agent from recording your loss for you."
assert_cmd_fails_with p8_accept_no_terminal "ConfirmationOnlyFromATerminal" \
  "$BIN" accept-deletions
assert_contains "the refusal states the phrase a terminal would have to type" \
  "$ACCEPT_DELETION_PHRASE" "$RUN_LOG"
assert_eq "the no-terminal refusal moved no ref" \
  "$HEAD_BEFORE" "$(git -C "$CFG_STORE" rev-parse HEAD 2>/dev/null || true)"

echo
echo "==> accept-deletions must NAME what is gone and point at restore-missing BEFORE it takes"
echo "    any phrase, and a phrase that is not the exact one must record nothing. This script"
echo "    types both into a pty, exactly as a human at a terminal would."
assert_pty_fails_with p8_accept_wrong_phrase "ConfirmationRefused" "yes" \
  "$BIN" accept-deletions
assert_contains "it named the file that is gone" "GONE: a store file the last commit still has" "$RUN_LOG"
assert_contains "and named it by name" "file=$SOL_KEY" "$RUN_LOG"
assert_contains "and said recording the loss replicates it to every backup" \
  "recording their loss replicates it to every backup" "$RUN_LOG"
assert_contains "and pointed at the reversible half FIRST" \
  "RUN \`hot_cheese restore-missing\` FIRST" "$RUN_LOG"
assert_contains "and states the phrase it actually wants" "$ACCEPT_DELETION_PHRASE" "$RUN_LOG"
assert_eq "the refused accept-deletions moved no ref" \
  "$HEAD_BEFORE" "$(git -C "$CFG_STORE" rev-parse HEAD 2>/dev/null || true)"
if [[ -e "$SOL_FILE" ]]; then
  fail "the refused accept-deletions put the file back, which is not its job"
else
  pass "and put nothing back, which is not its job either"
fi

echo
echo "==> now the half an operator should have reached for. It is a checkout out of this Mac's"
echo "    own tip, so the file comes back byte-for-byte and HEAD does not move."
run_cmd p8_restore "$BIN" restore-missing
assert_eq "restore-missing exit code" "0" "$RUN_RC"
assert_contains "it named what the worktree had lost" \
  "MISSING: a store file the last commit still has" "$RUN_LOG"
assert_contains "and reported putting that one back" "RESTORED out of this machine's own history" "$RUN_LOG"
assert_contains "and says plainly that it recorded nothing and told no backup" \
  "no ref moved, nothing was recorded and no backup was told" "$RUN_LOG"
assert_eq "the restored keystore is byte-identical to the one that was deleted" \
  "$LOST_SHA_BEFORE" "$(shasum -a 256 "$SOL_FILE" 2>/dev/null | cut -d' ' -f1 || true)"
assert_file_mode "and comes back 600, not whatever the checkout felt like" "600" "$SOL_FILE"
assert_eq "and HEAD is exactly where it was: nothing about the loss reached history" \
  "$HEAD_BEFORE" "$(git -C "$CFG_STORE" rev-parse HEAD 2>/dev/null || true)"
STORE_STATUS="$(git -C "$CFG_STORE" status --porcelain 2>&1 || true)"
assert_eq "and the store is clean again" "" "$STORE_STATUS"

echo
echo "==> the worst version of the same loss: keyring.json itself. Nothing downstream can even"
echo "    name the vault without it, so serve must refuse and must name the command that fixes"
echo "    it rather than offer to pull a backup over the top of a store that is still here."
KEYRING_SHA_BEFORE="$(shasum -a 256 "$KEYRING_FILE" 2>/dev/null | cut -d' ' -f1 || true)"
rm -f "$KEYRING_FILE"
BIO_START="$(bio_window_start)"
assert_cmd_fails_with p8_serve_no_keyring "StoreMissingRunRestoreMissing" "$BIN" serve
PORT_PIDS="$(port_pids)"
assert_eq "and the refused serve never bound the dry port" "" "$PORT_PIDS"
assert_taps "and never reached a biometric" "0" "$BIO_START"
run_cmd p8_restore_keyring "$BIN" restore-missing
assert_eq "restore-missing exit code with no keyring at all" "0" "$RUN_RC"
assert_contains "it says it put the keyring back first, because nothing else can run without it" \
  "the store had no keyring.json and this machine's own history did" "$RUN_LOG"
assert_eq "and keyring.json is byte-identical" \
  "$KEYRING_SHA_BEFORE" "$(shasum -a 256 "$KEYRING_FILE" 2>/dev/null | cut -d' ' -f1 || true)"
assert_eq "and HEAD still has not moved" \
  "$HEAD_BEFORE" "$(git -C "$CFG_STORE" rev-parse HEAD 2>/dev/null || true)"
assert_eq "the vault id survived the round trip" "$VAULT_INIT" \
  "$(grep -oE 'v_[0-9a-f]{32}' "$KEYRING_FILE" | head -1 || true)"
STORE_STATUS="$(git -C "$CFG_STORE" status --porcelain 2>&1 || true)"
assert_eq "and the store is clean after both recoveries" "" "$STORE_STATUS"
run_cmd p8_after_restore "$BIN" list
assert_eq "and an ordinary read-only command works again" "0" "$RUN_RC"
assert_contains "with every keystore still there" "key=$SOL_KEY" "$RUN_LOG"

assert_taps "the whole backup and loss-recovery block cost zero biometrics" "0" "$BIO_PHASE"

echo
echo "==> 8c: and the last thing a read grant is: a COPY of a key, which only the key's LIVE"
echo "    header keeps alive. Tightening $SHARE_KEY to sign-only kills the grant phase 3 minted"
echo "    on the spot — no revocation list, no expiry to wait out, no daemon involved. This is"
echo "    the ONE Touch ID sheet of phase 8, spent decrypting and re-sealing the key."
TAPS_EXPECTED=$((TAPS_EXPECTED + 1))
BIO_START="$(bio_window_start)"
run_cmd p8_seal_tighten "$BIN" seal "$SHARE_KEY" --use sign-only
assert_eq "seal --use sign-only exit code" "0" "$RUN_RC"
assert_contains "the key is sealed sign_only now" "key_use=sign_only" "$RUN_LOG"
assert_contains "and seal itself tells the operator the grant is dead" \
  "a read grant for this key releases nothing now" "$RUN_LOG"
assert_taps "tightening one key costs exactly one biometric" "1" "$BIO_START"
assert_contains "and the file on disk says so in cleartext" '"key_use":"sign_only"' "$SHARE_FILE"

run_cmd p8_grant_dead "$BIN" read-grant list
assert_eq "read-grant list exit code" "0" "$RUN_RC"
assert_contains "list still shows the grant, because the token is still out there" \
  "grant=$SHARE_KEY" "$RUN_LOG"
assert_contains "but reports that it releases nothing" "DEAD" "$RUN_LOG"

echo
echo "==> and the one-way door holds for the grant too: loosening it back is refused from the"
echo "    cleartext header alone, so a token somebody was handed cannot be brought back to life."
assert_cmd_fails_with p8_grant_reloosen "SealCannotLoosen" "$BIN" seal "$SHARE_KEY" --use shareable

run_cmd p8_grant_revoke "$BIN" read-grant revoke "$SHARE_KEY"
assert_eq "revoke exit code" "0" "$RUN_RC"
assert_contains "revoke says the token releases nothing now" \
  "its token releases nothing now" "$RUN_LOG"
if [[ -e "$GRANT_FILE" ]]; then
  fail "the grant file survived revoke: $GRANT_FILE"
else
  pass "the grant file is gone, so this run's archived token now opens nothing at all"
fi
assert_cmd_fails_with p8_grant_revoke_twice "NoSuchGrant" "$BIN" read-grant revoke "$SHARE_KEY"
else
  skipped_phase "PHASE 8" "not selected for this run"
fi

if [[ -n "$RUN_MIGRATE" ]]; then
  phase "PHASE M — migrate rehearsal (2 Touch ID + 3 passphrase + 1 login-keychain dialog)"

  echo "This rehearses MIGRATION.md §5 against a SYNTHETIC legacy store built from the repo's"
  echo "own test fixture. It does not touch any real legacy store. The fixture is copied under"
  echo "TWO names so one run proves both halves of the cutover rule: a key you name with"
  echo "--shareable stays fetchable over /read, and every key you DON'T name is sealed"
  echo "sign-only forever."
  echo
  echo "migrate writes into THE CONFIGURED STORE and refuses any other --new-store, and it"
  echo "refuses a destination that already holds a keystore. So this phase does not aim at the"
  echo "store phases 1-8 filled: it initializes a SECOND throwaway install, side by side, and"
  echo "migrates into that one — which is exactly the shape of a real cutover."
  echo
  echo "IT WILL WRITE ONE ITEM TO YOUR LOGIN KEYCHAIN:"
  echo "    service = $MIG_SERVICE"
  echo "    account = $MIG_ACCOUNT"
  echo "    secret  = the PUBLIC test-fixture password from ${LEGACY_FIXTURE:-test-keys/key-scrypt.json}"
  echo "That is NOT the production $CFG_SERVICE / $CFG_ACCOUNT pair. This phase DELETES the"
  echo "item at the end and asserts it is gone."
  echo
  echo "Expect, in order: the new passphrase twice (init), the passphrase once more (enroll se"
  echo "wraps the DEK it just minted), one Touch ID sheet to authorize reading the legacy"
  echo "master, one macOS dialog asking to allow hot_cheese access to that keychain item, then"
  echo "one Touch ID sheet to unlock the new DEK through the enclave. The same throwaway"
  echo "passphrase you used in phase 1 is fine; the 20-character rule applies here too."
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
    MIG_HOME="$MIG_ROOT/home"
    MIG_NEW="$MIG_HOME/store"
    MIG_CFG="$MIG_HOME/config.toml"
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

    echo
    echo "==> the second throwaway install the legacy keys land in. NEW passphrase, twice."
    run_tty pm_init env "HOT_CHEESE_HOME=$MIG_HOME" "$BIN" init
    assert_eq "the rehearsal install initialized" "0" "$RUN_RC"
    assert_matches "and minted a vault id of its own" 'vault=v_[0-9a-f]{32}' "$RUN_LOG"
    MIG_VAULT="$(field_value "$RUN_LOG" vault)"
    if [[ -n "$MIG_VAULT" && "$MIG_VAULT" != "$VAULT_KEYRING" ]]; then
      pass "a second install is a second vault, so the two never share a backup subtree"
    else
      fail "the rehearsal install reused the dry run's vault id [$MIG_VAULT]"
    fi

    echo
    echo "==> point it at the throwaway legacy Keychain identity, then enroll its enclave key."
    write_config_at "$MIG_CFG" "$MIG_SERVICE" "$MIG_ACCOUNT" "$MIG_NEW" ""
    assert_file_mode "the rehearsal config.toml is 600" "600" "$MIG_CFG"
    run_cmd pm_enroll_se env "HOT_CHEESE_HOME=$MIG_HOME" "$BIN" enroll se
    assert_eq "enroll se on the rehearsal install" "0" "$RUN_RC"
    assert_contains "which mints an enclave key of its own, not the dry run's" \
      "MINTED a new Secure Enclave key" "$RUN_LOG"
    MIG_SE_BLOB="$MIG_HOME/$SE_BLOB_NAME"
    if [[ -f "$MIG_SE_BLOB" ]] && ! cmp -s "$MIG_SE_BLOB" "$SE_BLOB"; then
      pass "the rehearsal enclave key is a separate blob from the dry run's"
    else
      fail "the rehearsal install did not get its own enclave key blob at $MIG_SE_BLOB"
    fi

    echo
    echo "==> negative: --new-store must be the store config.toml names, or nothing is written."
    assert_cmd_fails_with pm_wrong_store "WrongNewStore" \
      env "HOT_CHEESE_HOME=$MIG_HOME" "$BIN" migrate \
      --old-store "$MIG_OLD" --new-store "$MIG_ROOT" --shareable "$LEGACY_SHARE_NAME"

    echo
    echo "==> negative: a --shareable name the legacy store does not hold aborts BEFORE any"
    echo "    prompt, because a typo there seals a key your services still read, permanently."
    BIO_START="$(bio_window_start)"
    assert_cmd_fails_with pm_unknown_shareable "UnknownShareable" \
      env "HOT_CHEESE_HOME=$MIG_HOME" "$BIN" migrate \
      --old-store "$MIG_OLD" --new-store "$MIG_NEW" --shareable NOT_A_LEGACY_KEY
    assert_taps "the typo cost no biometric and reached no keychain" "0" "$BIO_START"

    echo
    echo "==> the migration itself."
    run_cmd pm_migrate env "HOT_CHEESE_HOME=$MIG_HOME" "$BIN" migrate \
      --old-store "$MIG_OLD" --new-store "$MIG_NEW" --shareable "$LEGACY_SHARE_NAME"
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
    MIG_STAGING="$(find "$MIG_HOME" -maxdepth 1 -name '.hot_cheese_migrate_*.staging' 2>/dev/null || true)"
    assert_eq "no staging dir remains beside the new store" "" "$MIG_STAGING"
    assert_contains "the migrated key is a real envelope file" \
      '"cipher":"xchacha20poly1305"' "$MIG_NEW/$LEGACY_KEY_NAME"
    assert_contains "and its use is bound in cleartext" \
      '"key_use":"sign_only"' "$MIG_NEW/$LEGACY_KEY_NAME"
    assert_contains "as is the named key's" \
      '"key_use":"shareable"' "$MIG_NEW/$LEGACY_SHARE_NAME"

    MIG_STATUS="$(git -C "$MIG_NEW" status --porcelain 2>&1 || true)"
    if [[ -z "$MIG_STATUS" ]]; then
      pass "migrate committed what it wrote, so a backup of the new install carries both keys"
    else
      fail "the migrated store has uncommitted changes [$MIG_STATUS]"
    fi

    echo
    echo "==> and the dry run's own install was never touched by any of it."
    assert_eq "the dry config still names the production Keychain identity" \
      "$CFG_SERVICE" "$(toml_value "$CFG_FILE" service)"
    assert_eq "and still points at the dry store" "$CFG_STORE" "$(toml_value "$CFG_FILE" store)"
    assert_eq "and still pins the dry run's grant key" \
      "$CFG_GRANT_PUB" "$(toml_value "$CFG_FILE" grant_public_key)"

    run_cmd pm_keychain_del security delete-generic-password \
      -s "$MIG_SERVICE" -a "$MIG_ACCOUNT"
    assert_eq "deleted the throwaway keychain item" "0" "$RUN_RC"
    if security find-generic-password -s "$MIG_SERVICE" -a "$MIG_ACCOUNT" > /dev/null 2>&1; then
      fail "the throwaway keychain item $MIG_SERVICE/$MIG_ACCOUNT IS STILL PRESENT — delete it by hand"
    else
      pass "the throwaway keychain item is gone"
    fi
  fi
fi

if want_phase 9; then
phase "PHASE 9 — teardown (0 prompts)"

keep_logs
if [[ -n "$LOGS_KEPT" ]]; then
  echo "  note  command logs copied out of the dry home to $LOG_KEEP"
else
  echo "  note  no command log could be copied to $LOG_KEEP"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
  echo "  note  $FAIL_COUNT failure(s) above, so the dry home and its archive are KEPT: a run you"
  echo "  note  have to diagnose is one you should not have to build again from a fresh init."
  echo "  note  Re-run just what failed, on this same store, with:"
  echo "  note      HOT_CHEESE_HOME=\"$HOT_CHEESE_HOME\" FROM_PHASE=<n> $0"
  echo "  note  and remove both by hand when you are done with them:"
  echo "  note      rm -rf \"$HOT_CHEESE_HOME\" \"$DRY_ARCHIVE\""
else
  rm -rf "$HOT_CHEESE_HOME"
  if [[ -e "$HOT_CHEESE_HOME" ]]; then
    fail "the dry home survived teardown: $HOT_CHEESE_HOME"
  else
    pass "dry home removed"
  fi
  if [[ -e "$GRANT_DIR" ]]; then
    fail "the read-grants directory survived teardown: $GRANT_DIR"
  else
    pass "phase 3 pinned the grants at $GRANT_DIR, so removing the home removed them too"
  fi
  rm -rf "$DRY_ARCHIVE"
  if [[ -e "$DRY_ARCHIVE" ]]; then
    fail "the throwaway store archive survived teardown: $DRY_ARCHIVE"
  else
    pass "throwaway store archive removed (it is add-only, so nothing else would have)"
  fi
  if [[ "$FAIL_COUNT" -eq 0 ]]; then
    TORN_DOWN=1
  fi
fi

HOME_DIFF=0
snapshot_dir "$REAL_HOME" "$SNAP_DIR/after.list" "$SNAP_DIR/after.hashes"
snapshot_dir "$REAL_ARCHIVE" "$SNAP_DIR/arch_after.list" "$SNAP_DIR/arch_after.hashes"
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
echo "  note  the store archive is the one location a throwaway HOT_CHEESE_HOME does not cover:"
echo "  note  it is add-only, it is never pruned by anything in hot_cheese, and yours lives at"
echo "  note      $REAL_ARCHIVE"
if cmp -s "$SNAP_DIR/arch_before.list" "$SNAP_DIR/arch_after.list" &&
  cmp -s "$SNAP_DIR/arch_before.hashes" "$SNAP_DIR/arch_after.hashes"; then
  pass "the real store archive is byte-identical: this dry run left no throwaway ciphertext there"
else
  HOME_DIFF=1
  fail "THE REAL STORE ARCHIVE CHANGED — some command ran against the default archive instead of this run's store_archive, so throwaway keystores are now in YOUR archive and nothing prunes them. Compare $SNAP_DIR/arch_before.hashes and $SNAP_DIR/arch_after.hashes, then remove what this run added BY HAND"
fi

assert_eq "no se_kek_*.blob or se_grant_*.blob appeared in the real home, and the baseline's are unchanged" \
  "$(enclave_blob_lines "$SNAP_DIR/before.hashes")" "$(enclave_blob_lines "$SNAP_DIR/after.hashes")"

PORT_PIDS="$(port_pids)"
if [[ -z "$PORT_PIDS" ]]; then
  pass "dry port $DRY_PORT is free"
else
  fail "dry port $DRY_PORT still has listener pid(s): $PORT_PIDS — this script did not start it, so stop it yourself"
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

echo
echo "==> and the budget printed at the top must be the one the phases actually spent, or the"
echo "    operator was asked to plan for the wrong number of fingerprints."
if [[ -z "$SKIP_SELFTEST" && -z "$SKIP_SERVE" && -z "$RUN_MIGRATE" && -z "$PARTIAL_RUN" ]]; then
  assert_eq "the advertised Touch ID budget is what phases 0-9 actually spend" \
    "$TOUCH_ID_BUDGET" "$TAPS_EXPECTED"
else
  echo "  note  a skip, a partial run or RUN_MIGRATE is set, so the advertised budget of"
  echo "  note  $TOUCH_ID_BUDGET is not the number this run should have spent and is not checked against it."
fi
else
  skipped_phase "PHASE 9" "not selected for this run"
fi

phase "SUMMARY"
echo "  PHASES RUN:$PHASES"
echo "  PASSED: $PASS_COUNT"
echo "  FAILED: $FAIL_COUNT"
if [[ -n "$LOGS_KEPT" ]]; then
  echo "  LOG ARCHIVE: $LOG_KEEP"
else
  echo "  LOG ARCHIVE: nothing was copied out of $OUT_DIR"
fi
echo "  Touch ID expected for the phases actually run: $TAPS_EXPECTED  (advertised: $TOUCH_ID_BUDGET)"
if [[ -n "$BIO_LOG" ]]; then
  echo "  Touch ID counted in the log since this run started: $(bio_taps_since "$RUN_START")"
  echo "  note  that window is the whole run, so a sheet raised by any other app lands in it too;"
  echo "  note  the per-command counts above are the ones that assert anything."
fi
echo
if [[ "$FAIL_COUNT" -ne 0 ]]; then
  echo "  DRY RUN FAILED with $FAIL_COUNT failure(s). Do NOT migrate production keys yet."
  exit 1
fi
if [[ -n "$PARTIAL_RUN" || -n "$SKIP_SELFTEST" || -n "$SKIP_SERVE" ]]; then
  echo "  PARTIAL RUN CLEAN — AND A PARTIAL RUN IS NOT A PASS."
  echo "  Only phase(s)$PHASES ran, and phase 0's self-test and phase 6's daemon obey"
  echo "  SKIP_SELFTEST and SKIP_SERVE on top of that. Every assertion that did run, passed."
  echo "  Nothing here says anything about a phase this run did not execute, and the Touch ID"
  echo "  budget was not checked, because it only holds for the whole sequence."
  echo "  Run it end to end with no FROM_PHASE, no ONLY_PHASES and no skips before you migrate."
  exit 0
fi
echo "  DRY RUN CLEAN. The enclave path, the envelope, the declared key uses, the grant gate,"
echo "  the policy gate, the daemon, the vault namespace and the teardown all behaved."
echo "  Proceed with MIGRATION.md against the real home."
exit 0
