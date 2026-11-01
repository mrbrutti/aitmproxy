#!/usr/bin/env bash
# t5-live-proof-macos — the T5 (L4 packet lane) live proof on the Mac, through
# the product's own packet-capture helper. Run from the repo root.
#
# THIS SCRIPT NEVER ESCALATES. It types no sudo line, installs nothing, changes
# no /dev/bpf* permission and never runs `aitm-l4-helper bpf-permissions` or
# `bpf-revert` for real. Those two run only as launchd root, triggered by the
# app ("Allow Packet Capture…" / "Remove Packet Capture…") after Matt's
# explicit yes relayed by the coordinator (the l4-capture-privilege spec's spike
# rule; silence is not go). The script records the state before, tells the
# operator exactly what the app will do, waits, verifies read-only, runs the
# cells, and documents (does not run) the revert.
#
# Modes:
#   scripts/t5-live-proof-macos.sh record        # state before: /dev/bpf*, access_bpf, LaunchDaemons, helper --dry-run
#   scripts/t5-live-proof-macos.sh verify        # state after the grant, incl. the l4.privilege report
#   scripts/t5-live-proof-macos.sh cells         # lane-level live_loopback + the three test_t5_* e2e cells
#   scripts/t5-live-proof-macos.sh restore-doc   # prints the revert path (does not run it)
#   scripts/t5-live-proof-macos.sh all           # record -> apply prompt -> verify -> cells -> restore-doc
# Flags:
#   --record-only   with `record`/`all`: record the state and stop, exit 0 even when
#                   the helper is absent (a plain `record` exits 77 then)
#   --out DIR       evidence root (default: $TMPDIR/t5-proof, else /tmp/claude/t5-proof)
#
# Exit codes: 0 done; 77 the helper or the privilege is absent (one-line reason;
# never 1 for a missing privilege); 1 a verify mismatch or a failing cell;
# 2 usage.
#
# Evidence: <out>/evidence/<UTC stamp>/{before.txt,verify.txt,after.txt,...};
# no token is ever written (the l4.privilege reply holds none, and the lo0
# capture, when tcpdump is allowed at all, records no TCP payload).

set -u

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
MODE=""
RECORD_ONLY=0
OUT_ROOT=""
while [ $# -gt 0 ]; do
  case "$1" in
    record|verify|cells|restore-doc|all) MODE=$1 ;;
    --record-only) RECORD_ONLY=1 ;;
    --out) shift; OUT_ROOT=${1:-} ;;
    --out=*) OUT_ROOT=${1#--out=} ;;
    -h|--help|help)
      awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"
      exit 0 ;;
    *)
      echo "usage: $0 {record|verify|cells|restore-doc|all} [--record-only] [--out DIR]" >&2
      exit 2 ;;
  esac
  shift
done
if [ -z "$MODE" ]; then
  echo "usage: $0 {record|verify|cells|restore-doc|all} [--record-only] [--out DIR]" >&2
  exit 2
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "$OUT_ROOT" ]; then
  OUT_ROOT="${TMPDIR:-/tmp/claude}/t5-proof"
fi
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$OUT_ROOT/evidence/$STAMP"
mkdir -p "$OUT"

# The literals the l4-capture-privilege spec pins (§3.1, verify/restore readers).
BPF_BEFORE='crw------- root wheel'
BPF_AFTER='crw-rw---- root access_bpf'
RECEIPT='/Library/Application Support/Aitmproxy/l4-helper.json'
DAEMON_LABEL='com.mrbrutti.aitmproxy.l4-helper'
# The exact SKIP reason the cells print on a Mac without the grant.
SKIP_REASON='packet-capture permission not granted (aitm-l4-helper phase 1 pending)'

say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }
# rec <file> <line...>: print and append to an evidence file
rec()  { local f=$1; shift; printf '%s\n' "$*" | tee -a "$f"; }
# run_rec <file> <cmd...>: print the command, run it, keep stdout+stderr; tolerate failure
run_rec() {
  local f=$1; shift
  printf '$ %s\n' "$*" | tee -a "$f"
  "$@" 2>&1 | sed 's/^/  /' | tee -a "$f"
  return 0
}

# find_helper: the product helper, release bundle first, then the dev tree.
find_helper() {
  local c
  for c in /Applications/Aitmproxy.app/Contents/MacOS/aitm-l4-helper \
           "$HOME/Applications/Aitmproxy.app/Contents/MacOS/aitm-l4-helper" \
           "$ROOT/target/debug/aitm-l4-helper"; do
    if [ -x "$c" ]; then printf '%s\n' "$c"; return 0; fi
  done
  return 1
}

bpf0_mode() { stat -f '%Sp %Su %Sg' /dev/bpf0 2>/dev/null || echo 'stat failed'; }

# ---------------------------------------------------------------------------
# record: the state before anything is applied (read-only)
# ---------------------------------------------------------------------------
do_record() {
  local f="$OUT/before.txt"
  hdr "record: state before, read-only -> $f"
  rec "$f" "t5 macos live proof: record $STAMP"
  rec "$f" "host: $(uname -a)"
  rec "$f" "user: $(id -un) (admin: $(id -Gn | tr ' ' '\n' | grep -qx admin && echo yes || echo no))"
  rec "$f" "source: $(git -C "$ROOT" log --oneline -1 2>/dev/null || echo 'unknown')"
  run_rec "$f" ls -l /dev/bpf0 /dev/bpf1
  rec "$f" "stat /dev/bpf0: $(bpf0_mode)   (expected before the grant: $BPF_BEFORE)"
  rec "$f" "group access_bpf (absent is normal before the grant):"
  run_rec "$f" dscl . -read /Groups/access_bpf GroupMembership
  rec "$f" "aitmproxy LaunchDaemons (absent is normal before the grant):"
  printf '$ ls /Library/LaunchDaemons | grep -i aitmproxy\n' | tee -a "$f"
  local plist found=0
  for plist in /Library/LaunchDaemons/*[Aa][Ii][Tt][Mm][Pp][Rr][Oo][Xx][Yy]*; do
    [ -e "$plist" ] || continue
    found=1
    rec "$f" "  $(basename "$plist")"
  done
  [ "$found" -eq 1 ] || rec "$f" "  (none)"
  rec "$f" "receipt $RECEIPT: $([ -e "$RECEIPT" ] && echo present || echo absent)"

  local helper
  if helper=$(find_helper); then
    rec "$f" "helper: $helper ($("$helper" version 2>&1 | head -1))"
    rec "$f" "dry runs change nothing and run as this user (spec §3.1):"
    run_rec "$f" "$helper" bpf-permissions --dry-run
    run_rec "$f" "$helper" bpf-revert --dry-run
    run_rec "$f" "$helper" probe
    rec "$f" "stat /dev/bpf0 after the dry runs: $(bpf0_mode)   (must still be: $BPF_BEFORE)"
    HELPER_PRESENT=1
  else
    rec "$f" "aitm-l4-helper not present: Mac leg pending the notarized bundle (units p3/p4)"
    rec "$f" "  (searched /Applications/Aitmproxy.app/Contents/MacOS, ~/Applications/..., $ROOT/target/debug)"
    HELPER_PRESENT=0
  fi
  say "recorded: $f"
}

# ---------------------------------------------------------------------------
# apply: the script applies NOTHING. It says what the operator does and waits.
# ---------------------------------------------------------------------------
do_apply_prompt() {
  hdr "apply: nothing is applied by this script"
  cat <<TXT
This step needs Matt's explicit yes, relayed by the coordinator (the
l4-capture-privilege spec's spike rule). Silence is not go. Nobody types sudo.

What the operator does, in the app:
  1. Open Aitmproxy.app.
  2. Choose "Allow Packet Capture…" (the app calls l4.privilege.request and
     registers its SMAppService daemon $DAEMON_LABEL).
  3. Approve the macOS Login Items prompt (System Settings > General > Login
     Items & Extensions, if it does not surface on its own).
  4. launchd then runs, as root, exactly: aitm-l4-helper bpf-permissions
     (the plan the dry run above printed: group access_bpf, /dev/bpf0..255 to
     root:access_bpf 0660, the console user added, the receipt written).

Nothing else changes on this Mac. When the app reports the grant (or if Matt
said no), come back here.
TXT
  if [ -t 0 ]; then
    printf 'Press Enter to verify (Ctrl-C to stop here): '
    read -r _
  else
    say "(stdin is not a terminal; not waiting)"
  fi
}

# ---------------------------------------------------------------------------
# verify: read-only checks of the state after the grant
# ---------------------------------------------------------------------------
do_verify() {
  local f="$OUT/verify.txt" mismatch=0 mode
  hdr "verify: state after the grant, read-only -> $f"
  rec "$f" "t5 macos live proof: verify $STAMP"
  mode=$(bpf0_mode)
  rec "$f" "stat /dev/bpf0: $mode"
  if [ "$mode" = "$BPF_BEFORE" ]; then
    rec "$f" "privilege absent: /dev/bpf0 is still '$BPF_BEFORE' (the grant was not applied)"
    say "exit 77: packet-capture permission not granted on this Mac"
    exit 77
  elif [ "$mode" != "$BPF_AFTER" ]; then
    rec "$f" "MISMATCH /dev/bpf0: expected '$BPF_AFTER', got '$mode'"
    mismatch=1
  else
    rec "$f" "ok: /dev/bpf0 is '$BPF_AFTER'"
  fi
  rec "$f" "/dev/bpf255: $([ -e /dev/bpf255 ] && echo exists || echo missing)"
  run_rec "$f" dscl . -read /Groups/access_bpf GroupMembership
  if dscl . -read /Groups/access_bpf GroupMembership 2>/dev/null | grep -qw "$(id -un)"; then
    rec "$f" "ok: $(id -un) is in access_bpf (directory)"
  else
    rec "$f" "MISMATCH: $(id -un) is not listed in access_bpf"
    mismatch=1
  fi
  if id -Gn | tr ' ' '\n' | grep -qx access_bpf; then
    rec "$f" "ok: this shell session already carries access_bpf"
  else
    rec "$f" "note: this shell session does not carry access_bpf yet (spec spike S4: log out and in once; record that for fork ii)"
  fi
  rec "$f" "receipt:"
  run_rec "$f" cat "$RECEIPT"
  rec "$f" "daemon:"
  printf '$ launchctl print system/%s | head\n' "$DAEMON_LABEL" | tee -a "$f"
  { launchctl print "system/$DAEMON_LABEL" 2>&1 | head; } | sed 's/^/  /' | tee -a "$f"

  rec "$f" "l4.privilege report (expected capture and inject {\"state\":\"available\",\"via\":\"process\"}):"
  local aitm="$ROOT/target/debug/aitm"
  if [ -x "$aitm" ]; then
    # One-shot CLI dispatch: `aitm l4 privilege` is `l4.privilege` on an in-process
    # core running as this user, which is exactly the privilege the cells' own
    # cores get. The e2e harness reads the same verb over the loopback-TCP bus
    # (tests/e2e/aitm_e2e/bus.py: one {"token": ...} line, then JSON-RPC
    # tools/call "l4.privilege"); there is no curl form, the bus is not HTTP.
    printf '$ %s l4 privilege\n' "$aitm" | tee -a "$f"
    local reply
    reply=$("$aitm" l4 privilege 2>&1)
    printf '%s\n' "$reply" | sed 's/^/  /' | tee -a "$f" > "$OUT/privilege.json.txt"
    local verdict
    verdict=$(printf '%s' "$reply" | python3 -c '
import json, sys
raw = sys.stdin.read()
try:
    start = raw.index("{")
    rep = json.loads(raw[start:])
except Exception as e:  # noqa: BLE001
    print("unparsed: " + str(e)); sys.exit(0)
caps = rep.get("capabilities") or {}
bad = [n for n in ("capture", "inject")
       if (caps.get(n) or {}).get("state") != "available" or (caps.get(n) or {}).get("via") != "process"]
print("ok" if not bad else "not available/process: " + ", ".join(bad))
' 2>&1)
    rec "$f" "l4.privilege verdict: $verdict"
    case "$verdict" in
      ok) ;;
      not\ available*) rec "$f" "privilege absent per l4.privilege"; say "exit 77: l4.privilege says capture/inject are not available via process"; exit 77 ;;
      *) rec "$f" "note: could not read l4.privilege via the one-shot CLI (the verb lands with unit p1b): $verdict" ;;
    esac
  else
    rec "$f" "no $aitm: build it (cargo build -p aitm) to read l4.privilege; the cells read it themselves over the bus"
  fi

  if [ "$mismatch" -ne 0 ]; then
    rec "$f" "verify: MISMATCH (see the lines above marked MISMATCH)"
    exit 1
  fi
  say "verified: $f"
}

# ---------------------------------------------------------------------------
# cells: the lane-level live tests and the three e2e cells
# ---------------------------------------------------------------------------
do_cells() {
  local f="$OUT/after.txt" rc1 rc2 pcap tcpd=""
  hdr "cells: lane-level live_loopback then the three test_t5_* e2e cells -> $f"
  rec "$f" "t5 macos live proof: cells $STAMP"
  rec "$f" "source: $(git -C "$ROOT" log --oneline -1 2>/dev/null || echo 'unknown')"
  rec "$f" "stat /dev/bpf0: $(bpf0_mode)"

  # An unprivileged witness on lo0 with the narrow filter (no TCP payload, so
  # no bus token). The access_bpf group is what allows it; if it refuses, we
  # record that and rely on the cells' own capture observer (plan task 6.4).
  pcap="$OUT/lo0.pcap"
  say "tcpdump -i lo0 -nn -U -w $pcap 'icmp or udp or (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)'   (unprivileged; deleted after the excerpts)"
  tcpdump -i lo0 -nn -U -w "$pcap" 'icmp or udp or (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)' > "$OUT/lo0.tcpdump.log" 2>&1 &
  tcpd=$!
  sleep 1
  if ! kill -0 "$tcpd" 2>/dev/null; then
    rec "$f" "tcpdump refused on lo0 (recorded; relying on the cells' own observer): $(head -1 "$OUT/lo0.tcpdump.log")"
    tcpd=""
  fi

  say "AITM_L4_TESTS=1 cargo test -p aitm-scan-l4-packet --test live_loopback -- --ignored --nocapture --test-threads=1   (log: $OUT/lane.log)"
  (cd "$ROOT" && AITM_L4_TESTS=1 cargo test -p aitm-scan-l4-packet --test live_loopback -- --ignored --nocapture --test-threads=1) > "$OUT/lane.log" 2>&1
  rc1=$?
  rec "$f" "lane exit: $rc1; result lines:"
  grep -nE '^(test |reaction:|crash:|counters:|classes:|closed (udp|tcp) port:|SKIP 77|test result:)' "$OUT/lane.log" | sed 's/^/  /' | tee -a "$f"

  say "AITM_E2E_LEDGER_DIR=$OUT/ledger python3 tests/e2e/run.py scan   (no --build; log: $OUT/scan.log)"
  (cd "$ROOT" && AITM_E2E_LEDGER_DIR="$OUT/ledger" python3 tests/e2e/run.py scan) > "$OUT/scan.log" 2>&1
  rc2=$?
  rec "$f" "runner exit: $rc2; T5 cell lines:"
  grep -E '^(PASS|FAIL|SKIP) +scan/test_t5_' "$OUT/scan.log" | sed 's/^/  /' | tee -a "$f"
  rec "$f" "summary line: $(grep -E '^e2e summary:' "$OUT/scan.log" | tail -1)"
  rec "$f" "ledger (spec D3):"
  sed -n '/^scan verb ledger (spec D3):/,/^ledger: /p' "$OUT/scan.log" | sed 's/^/  /' | tee -a "$f"

  if [ -n "$tcpd" ]; then
    kill -INT "$tcpd" 2>/dev/null; wait "$tcpd" 2>/dev/null
    rec "$f" "lo0 excerpts (the pcap itself is deleted now):"
    {
      echo "frames total: $(tcpdump -nn -r "$pcap" 2>/dev/null | wc -l | tr -d ' ')"
      echo "first ICMP lines:"; tcpdump -nn -ttt -r "$pcap" icmp 2>/dev/null | head -10
      echo "first RST lines:";  tcpdump -nn -r "$pcap" 'tcp[tcpflags] & tcp-rst != 0' 2>/dev/null | head -3
    } | sed 's/^/  /' | tee -a "$f" "$OUT/lo0-excerpts.txt" >/dev/null
    cat "$OUT/lo0-excerpts.txt"
    rm -f "$pcap"
  fi

  # Verdict: all three PASS -> 0; a FAIL -> 1; the privilege SKIP -> 77.
  if grep -qE '^FAIL ' "$OUT/scan.log" || [ "$rc1" -ne 0 ]; then
    rec "$f" "cells: a failure (see $OUT/scan.log and $OUT/lane.log)"
    exit 1
  fi
  # The cells print the Python literal; the lane prints "SKIP 77: L4 packet lane live proof skipped: ...".
  if grep -qF "$SKIP_REASON" "$OUT/scan.log" || grep -qE '^SKIP 77' "$OUT/lane.log"; then
    rec "$f" "cells skipped: $SKIP_REASON"
    say "exit 77: $SKIP_REASON"
    exit 77
  fi
  if [ "$(grep -cE '^PASS +scan/test_t5_' "$OUT/scan.log")" -ne 3 ]; then
    rec "$f" "cells: fewer than three PASS test_t5_* lines, and not the privilege SKIP; read $OUT/scan.log"
    exit 1
  fi
  say "cells passed: $f"
}

# ---------------------------------------------------------------------------
# restore-doc: the revert path, printed, never run here
# ---------------------------------------------------------------------------
do_restore_doc() {
  hdr "restore-doc: how the grant is reverted (this script does not run it)"
  cat <<TXT
Per Matt's decision (plan Q3) the grant STAYS INSTALLED after this proof so the
Mac remains provable; the grant's lifetime belongs to the product helper, not to
this PR. When it is to be removed:

  1. In the app choose "Remove Packet Capture…". The registered daemon runs, as
     root, exactly: aitm-l4-helper bpf-revert
     (chown root:wheel + chmod 0600 on /dev/bpf0..255, remove the receipt's
     members_added from access_bpf, delete the receipt).
  2. Expected afterwards (read-only checks):
       stat -f '%Sp %Su %Sg' /dev/bpf0
         -> $BPF_BEFORE
       dscl . -read /Groups/access_bpf GroupMembership
         -> no longer lists $(id -un) (or the group is gone)
       ls "$RECEIPT"
         -> No such file
  3. Nobody types sudo, chmod or chown for this; the only privileged actor is
     the launchd daemon the app registered.
TXT
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
HELPER_PRESENT=0
case "$MODE" in
  record)
    do_record
    if [ "$HELPER_PRESENT" -eq 0 ] && [ "$RECORD_ONLY" -eq 0 ]; then
      say "exit 77: aitm-l4-helper not present: Mac leg pending the notarized bundle (units p3/p4)"
      exit 77
    fi
    ;;
  verify)      do_verify ;;
  cells)       do_cells ;;
  restore-doc) do_restore_doc ;;
  all)
    do_record
    if [ "$RECORD_ONLY" -eq 1 ]; then
      say "--record-only: stopping after record"
      exit 0
    fi
    if [ "$HELPER_PRESENT" -eq 0 ]; then
      say "exit 77: aitm-l4-helper not present: Mac leg pending the notarized bundle (units p3/p4)"
      exit 77
    fi
    do_apply_prompt
    do_verify
    do_cells
    do_restore_doc
    ;;
esac
say "evidence: $OUT"
exit 0
