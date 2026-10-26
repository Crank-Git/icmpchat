#!/usr/bin/env bash
#
# e2e_remote.sh — end-to-end ICMP chat test over the LAN.
#
# The full receive path needs a raw ICMP socket, so this script must run as
# root (sudo) on each host.
#
# Usage:
#   # Single-host self-delivery test (validates the receive path on one host):
#   sudo scripts/e2e_remote.sh <this-host-lan-ip> <name>
#
#   # Two-host test (run on host A; drives host B over ssh):
#   sudo scripts/e2e_remote.sh <host-b-ip> <name-A> <user@host-b>
#
# It builds icmpchat, launches a chat as root, exchanges a cleartext message, a
# long chunked message, and an encrypted message in both directions, and
# verifies each delivery by grepping the logs. Exits non-zero on any failure.
set -euo pipefail

PEER="${1:?usage: e2e_remote.sh <peer-ip> <name> [user@host]}"
NAME="${2:?provide a name}"
REMOTE="${3:-}"
KEY="e2e-shared-key"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
cleanup() {
  [ -n "${A_PID:-}" ] && kill "$A_PID" 2>/dev/null || true
  [ -n "${B_PID:-}" ] && kill "$B_PID" 2>/dev/null || true
  [ -n "${REMOTE}" ] && ssh -O stop "${REMOTE}" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

pass=0
fail=0
check() {
  local desc="$1" needle="$2" file="$3"
  if grep -qF -- "$needle" "$file"; then
    echo "  ✓ $desc"
    pass=$((pass + 1))
  else
    echo "  ✗ $desc (did not find '$needle')"
    fail=$((fail + 1))
  fi
}

echo "== building icmpchat =="
( cd "$ROOT_DIR" && go build -o "$WORK/icmpchat" . )

# launch <bin> <peer> <name> <keyflag...> <stdin> <logfile> <varname>
launch() {
  local bin="$1" peer="$2" name="$3" keyflag="$4" stdin="$5" log="$6" var="$7"
  eval "$var=\"\$( { \"$bin\" --peer \"$peer\" --name \"$name\" $keyflag < \"$stdin\" > \"$log\" 2>&1 & echo \$! ; } )\""
}

LONG="$(python3 -c 'print("x"*2500)')"

if [ -z "$REMOTE" ]; then
  # ---- Single-host self-delivery mode ----
  echo "== single-host self-delivery (peer=$PEER) =="
  FIFO="$WORK/in"
  mkfifo "$FIFO"
  launch "$WORK/icmpchat" "$PEER" "$NAME" "" "$FIFO" "$WORK/log" A_PID
  {
    printf 'ping from %s\n' "$NAME"; sleep 0.6
    printf '%s\n' "$LONG"; sleep 1.0
    printf 'keyed message from %s\n' "$NAME"; sleep 0.6
  } >"$FIFO" &
  wait
  check "cleartext self-delivered" "ping from $NAME" "$WORK/log"
  check "chunked self-delivered" "xxxxx" "$WORK/log"
  check "keyed self-delivered" "keyed message from $NAME" "$WORK/log"
else
  # ---- Two-host mode: drive the remote peer over ssh ----
  echo "== two-host mode (local=$NAME, remote via $REMOTE, peer=$PEER) =="
  scp "$WORK/icmpchat" "${REMOTE}:/tmp/icmpchat" || {
    # Build directly on the remote host instead.
    ( cd "$ROOT_DIR" && scp go.mod go.sum "$REMOTE:/" )
    ( cd "$ROOT_DIR" && scp $(ls *.go) "$REMOTE:/" )
    ssh "$REMOTE" "cd /tmp && go build -o icmpchat ."
    rm -f "$REMOTE"/go.mod "$REMOTE"/go.sum "$REMOTE"/*.go
  }
  chmod +x "$WORK/icmpchat"

  # Remote chat (encrypted), driven by ssh.
  REMOTE_IN="$WORK/rin"
  mkfifo "$REMOTE_IN"
  {
    ssh "$REMOTE" "sudo /tmp/icmpchat --peer '$PEER' --name remote --key '$KEY'" >"$WORK/remote.log" 2>&1 &
    RPID=$!
    sleep 0.6
    printf 'hello from local\n'; sleep 0.7
    printf '%s\n' "$LONG"; sleep 1.2
    printf 'keyed from local\n'; sleep 0.7
    printf '\x04'
    wait "$RPID" 2>/dev/null || true
  } >"$REMOTE_IN"
  check "remote received cleartext" "hello from local" "$WORK/remote.log"
  check "remote received chunked" "xxxxx" "$WORK/remote.log"
  check "remote received keyed" "keyed from local" "$WORK/remote.log"

  # Local chat (encrypted), driven by a FIFO.
  LOCAL_IN="$WORK/lin"
  mkfifo "$LOCAL_IN"
  {
    launch "$WORK/icmpchat" "$PEER" "$NAME" "--key '$KEY'" "$LOCAL_IN" "$WORK/local.log" A_PID
    sleep 0.6
    printf 'hello from remote\n'; sleep 0.7
    printf '%s\n' "$LONG"; sleep 1.2
    printf 'keyed from remote\n'; sleep 0.7
    printf '\x04'
  } >"$LOCAL_IN"
  sleep 0.5
  check "local received cleartext" "hello from remote" "$WORK/local.log"
  check "local received chunked" "xxxxx" "$WORK/local.log"
  check "local received keyed" "keyed from remote" "$WORK/local.log"
fi

echo
echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
