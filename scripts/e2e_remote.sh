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
# Local host LAN IP, used by the remote peer to reach this host in two-host
# mode. macOS: ipconfig; Linux: first global address.
LOCAL_IP=""
if command -v ipconfig >/dev/null 2>&1; then
  LOCAL_IP="$(ipconfig getifaddr en0 2>/dev/null)"
fi
if [ -z "$LOCAL_IP" ]; then
  LOCAL_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi

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
#
# Backgrounds the chat process in the current shell and records its PID in the
# named variable. It deliberately avoids a $(...) command substitution: such a
# subshell inherits the script's `trap cleanup EXIT`, so it would fire cleanup
# (which rm -rf's $WORK and its FIFO) the instant the substitution returns,
# while the freshly launched process is still opening that FIFO.
launch() {
  local bin="$1" peer="$2" name="$3" keyflag="$4" stdin="$5" log="$6" var="$7"
  sudo "$bin" --peer "$peer" --name "$name" $keyflag < "$stdin" > "$log" 2>&1 &
  eval "$var=\$!"
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
  WPID=$!
  wait "$WPID" 2>/dev/null || true  # wait only for the writer to finish sending
  sleep 3                           # allow delivery (and any acks) to land
  kill "$A_PID" 2>/dev/null || true # stop icmpchat; do not block on its EOF
  sleep 0.5
  check "cleartext self-delivered" "ping from $NAME" "$WORK/log"
  check "chunked self-delivered" "xxxxx" "$WORK/log"
  check "keyed self-delivered" "keyed message from $NAME" "$WORK/log"
else
  # ---- Two-host mode: each host chats with the other over the LAN ----
  # The local host (this machine) uses --peer $PEER (the remote). The remote
  # must use --peer <local-ip> so it sends to, and filters from, this host.
  echo "== two-host mode (local=$NAME via $LOCAL_IP, remote via $REMOTE, peer=$PEER) =="
  # Remote workdir: a fresh temp dir on the remote so a stray /tmp/icmpchat
  # directory (from a prior run) never shadows the built binary. Build the
  # binary natively on the remote, since the local build may target a
  # different architecture (e.g. macOS arm64) than the remote host.
  REMOTE_WORK="$(ssh "$REMOTE" 'mktemp -d')"
  ( cd "$ROOT_DIR" && scp go.mod go.sum "$REMOTE:${REMOTE_WORK}/" )
  ( cd "$ROOT_DIR" && scp $(ls *.go) "$REMOTE:${REMOTE_WORK}/" )
  ssh "$REMOTE" "cd '$REMOTE_WORK' && go build -o icmpchat . && chmod +x icmpchat"
  rm -f "$REMOTE":${REMOTE_WORK}/go.mod "$REMOTE":${REMOTE_WORK}/go.sum "$REMOTE":${REMOTE_WORK}/*.go

  # Remote chat (encrypted), driven by ssh stdin. It sends to the local host
  # ($LOCAL_IP) and receives from it.
  REMOTE_IN="$WORK/rin"
  mkfifo "$REMOTE_IN"
  {
    ssh "$REMOTE" "sudo ${REMOTE_WORK}/icmpchat --peer '$LOCAL_IP' --name remote --key '$KEY'" >"$WORK/remote.log" 2>&1 &
    RPID=$!
    sleep 0.6
    printf 'hello from remote\n'; sleep 0.8
    printf '%s\n' "$LONG"; sleep 1.0
    printf 'keyed from remote\n'; sleep 0.8
    printf '\x04'
    wait "$RPID" 2>/dev/null || true
  } >"$REMOTE_IN"
  # Local chat (encrypted), driven by a FIFO. It sends to the remote ($PEER)
  # and receives from it.
  LOCAL_IN="$WORK/lin"
  mkfifo "$LOCAL_IN"
  {
    launch "$WORK/icmpchat" "$PEER" "$NAME" "--key '$KEY'" "$LOCAL_IN" "$WORK/local.log" A_PID
    sleep 0.6
    printf 'hello from local\n'; sleep 0.8
    printf '%s\n' "$LONG"; sleep 1.0
    printf 'keyed from local\n'; sleep 0.8
    printf '\x04'
  } >"$LOCAL_IN"
  sleep 0.5
  # Each side's log shows the messages it RECEIVED from the other side.
  check "remote received cleartext" "hello from local" "$WORK/remote.log"
  check "remote received chunked" "xxxxx" "$WORK/remote.log"
  check "remote received keyed" "keyed from local" "$WORK/remote.log"
  check "local received cleartext" "hello from remote" "$WORK/local.log"
  check "local received chunked" "xxxxx" "$WORK/local.log"
  check "local received keyed" "keyed from remote" "$WORK/local.log"
fi

echo
echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
