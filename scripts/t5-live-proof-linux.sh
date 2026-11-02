#!/usr/bin/env bash
# t5-live-proof-linux — the T5 (L4 packet lane) live proof on the Linux rig.
#
# Run INSIDE the Linux rig (the Lima VM cis-lab) from the synced source tree
# root (~/aitm-src). Everything it drives is real: the real aitm core, the real
# aitm-testtarget, the real e2e runner and tcpdump as an independent witness on
# the loopback interface. Raw-capture privilege comes from FILE CAPABILITIES on
# the freshly built binary and from nothing else: cargo never runs as root, the
# core never runs as root, and the runner is invoked WITHOUT --build so a
# rebuild cannot strip the caps behind our back.
#
# Modes:
#   scripts/t5-live-proof-linux.sh lane    # lane-level tests/live_loopback.rs, caps on the test binary
#   scripts/t5-live-proof-linux.sh cells   # the three test_t5_* e2e cells over a real bus, with the ledger
#   scripts/t5-live-proof-linux.sh all     # both (default)
#
# Environment:
#   AITM_E2E_BUS_PORT   if set, UDP to/from that port is excluded from the capture
#                       as well (belt and braces; the bus is TCP and TCP payload is
#                       never captured in any case, see "capture filter" below)
#   T5_BUILD=1          run `cargo build -p aitm -p aitm-testtarget` (as this user,
#                       never root) before setcap. Off by default: the plan builds
#                       beforehand and the script only stamps the binaries it found.
#
# Evidence goes to ~/t5-proof/<UTC stamp>/ with a summary.txt the PR body can
# quote. The pcap files STAY ON THE RIG: only the textual excerpts the script
# prints belong in a PR or a doc (plan 2026-11-01-t5-live-proof, shared fact 5).
#
# Capture filter: 'icmp or udp or (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)'.
# No TCP payload segment is ever written, so the bus's plaintext {"token": ...}
# line (the lesson of PR #205) cannot land in a pcap. What the proof needs is
# the ICMP port-unreachable replies, the UDP datagrams to the echo/crash
# services and the RST from the closed TCP port, and that is all this records.

set -u

MODE=${1:-all}
case "$MODE" in
  lane|cells|all) ;;
  -h|--help|help)
    awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"
    exit 0 ;;
  *)
    echo "usage: $0 [lane|cells|all]" >&2
    exit 2 ;;
esac

# ---------------------------------------------------------------------------
# Where we are and where the evidence goes
# ---------------------------------------------------------------------------
ROOT=$(pwd)
if [ ! -f "$ROOT/Cargo.toml" ] || [ ! -f "$ROOT/tests/e2e/run.py" ]; then
  echo "refusing: run this from the source tree root (Cargo.toml + tests/e2e/run.py); pwd=$ROOT" >&2
  exit 2
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$HOME/t5-proof/$STAMP"
if ! mkdir -p "$OUT"; then
  echo "refusing: cannot create the evidence dir $OUT" >&2
  exit 2
fi
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"

say()  { printf '%s\n' "$*"; }
# rec: print a line and keep it in the summary
rec()  { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
step() { printf '\n== %s ==\n' "$*" | tee -a "$SUMMARY"; }

FAILS=0

# The tcpdump filter. TCP: SYN/RST flags only (no payload, ever). UDP: all of
# it, minus the bus port when the caller knows it. ICMP: all of it.
if [ -n "${AITM_E2E_BUS_PORT:-}" ]; then
  FILTER="icmp or (udp and not port ${AITM_E2E_BUS_PORT}) or (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)"
else
  FILTER="icmp or udp or (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)"
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# require_caps <binary>: refuse to proceed unless getcap shows both raw caps.
# The caps are the ONLY privilege this proof uses; without them the run would
# silently become a SKIP-77 run and prove nothing.
require_caps() {
  local bin=$1 caps
  caps=$(getcap "$bin" 2>&1)
  rec "getcap: ${caps:-<empty>}"
  case "$caps" in
    *cap_net_admin*cap_net_raw*=ep*|*cap_net_raw*cap_net_admin*=ep*) return 0 ;;
  esac
  rec "refusing: $bin carries no cap_net_raw,cap_net_admin file capabilities; setcap did not take"
  exit 2
}

# grant_caps <binary>: file capabilities on one binary, nothing else.
grant_caps() {
  local bin=$1
  say "sudo setcap cap_net_raw,cap_net_admin+ep $bin   (CAP_NET_RAW: pcap open/inject; CAP_NET_ADMIN: promiscuous open)"
  if ! sudo setcap cap_net_raw,cap_net_admin+ep "$bin"; then
    rec "refusing: setcap failed on $bin"
    exit 2
  fi
  require_caps "$bin"
}

TCPD_PID=""
PCAP=""
# start_capture <pcap path>: tcpdump on lo with the narrow filter, in the background.
start_capture() {
  PCAP=$1
  say "tcpdump -i lo -nn -U -w $PCAP '$FILTER'   (independent witness; the pcap stays on this rig)"
  # shellcheck disable=SC2024  # the log is meant to be ours, under $OUT; only tcpdump needs root
  sudo tcpdump -i lo -nn -U -w "$PCAP" "$FILTER" > "$PCAP.tcpdump.log" 2>&1 &
  TCPD_PID=$!
  sleep 1
  if ! kill -0 "$TCPD_PID" 2>/dev/null; then
    rec "warning: tcpdump did not start (see $PCAP.tcpdump.log); continuing without the witness"
    TCPD_PID=""
  fi
}

# stop_capture: SIGINT so tcpdump flushes, then make the file ours to read.
stop_capture() {
  [ -n "$TCPD_PID" ] || return 0
  # Run 4 (2026-11-01) lost the last three exchanges of the echo test from the pcap while the lane itself
  # had every reply: under load the VM's tcpdump had not yet read them from the ring when it was stopped.
  # Give it a few seconds after the last frame before the SIGINT.
  sleep 3
  sudo kill -INT "$TCPD_PID" 2>/dev/null
  wait "$TCPD_PID" 2>/dev/null
  sleep 1
  sudo chown "$(id -u):$(id -g)" "$PCAP" 2>/dev/null || true
  TCPD_PID=""
}

# pcap_excerpts: the textual evidence from a pcap. Frame counts, the first ICMP
# lines (-ttt shows the spacing: Linux rate-limits ICMP errors to about one per
# second per destination), the first RST lines, and the busiest UDP ports.
pcap_excerpts() {
  local pcap=$1
  if [ ! -r "$pcap" ]; then
    rec "pcap: $pcap is not readable; no excerpts"
    return 0
  fi
  rec "pcap frames total: $(tcpdump -nn -r "$pcap" 2>/dev/null | wc -l | tr -d ' ')"
  rec "pcap frames icmp:  $(tcpdump -nn -r "$pcap" icmp 2>/dev/null | wc -l | tr -d ' ')"
  rec "pcap frames udp:   $(tcpdump -nn -r "$pcap" udp 2>/dev/null | wc -l | tr -d ' ')"
  rec "pcap frames rst:   $(tcpdump -nn -r "$pcap" 'tcp[tcpflags] & tcp-rst != 0' 2>/dev/null | wc -l | tr -d ' ')"
  rec "first ICMP lines (tcpdump -ttt = delta from the previous frame):"
  tcpdump -nn -ttt -r "$pcap" icmp 2>/dev/null | head -25 | sed 's/^/  /' | tee -a "$SUMMARY"
  rec "ICMP reactions other than the kernel's errors for our own source port 40000 (closed-port lines; -ttt deltas show the amendment-46 pace of ~1.1 s):"
  tcpdump -nn -ttt -r "$pcap" icmp 2>/dev/null | grep -v 'port 40000' | head -14 | sed 's/^/  /' | tee -a "$SUMMARY"
  rec "first RST lines:"
  tcpdump -nn -r "$pcap" 'tcp[tcpflags] & tcp-rst != 0' 2>/dev/null | head -3 | sed 's/^/  /' | tee -a "$SUMMARY"
  rec "UDP datagrams by destination port (top 6; the echo service shows up as 105 = 100 cases + 1 baseline + 4 probes):"
  tcpdump -nn -r "$pcap" udp 2>/dev/null \
    | sed -n 's/.* > 127\.0\.0\.1\.\([0-9]*\):.*/\1/p' | sort | uniq -c | sort -rn | head -6 \
    | sed 's/^/  /' | tee -a "$SUMMARY"
}

# ---------------------------------------------------------------------------
# Preflight: what this rig is and what source it runs
# ---------------------------------------------------------------------------
step "t5 linux live proof $STAMP (mode: $MODE)"
rec "evidence dir: $OUT"
rec "kernel: $(uname -a)"
if [ -f "$ROOT/.synced-sha" ]; then
  rec "source commit (.synced-sha): $(cat "$ROOT/.synced-sha")"
else
  rec "source commit (git): $(git -C "$ROOT" log --oneline -1 2>/dev/null || echo 'unknown: no .synced-sha and no .git')"
fi
rec "workspace version: $(grep -m1 '^version' "$ROOT/Cargo.toml")"
rec "cargo: $(cargo --version 2>/dev/null || echo 'cargo not found')"
rec "capture filter: $FILTER"
rec "icmp sysctls (expected 1000 / 6168 / 1000 / 50):"
sysctl net.ipv4.icmp_ratelimit net.ipv4.icmp_ratemask net.ipv4.icmp_msgs_per_sec net.ipv4.icmp_msgs_burst 2>&1 | sed 's/^/  /' | tee -a "$SUMMARY"

for tool in sudo setcap getcap tcpdump python3 cargo; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    rec "refusing: $tool is not installed on this rig"
    exit 2
  fi
done

# ---------------------------------------------------------------------------
# lane: tests/live_loopback.rs on the real kernel, caps on the test binary
# ---------------------------------------------------------------------------
run_lane() {
  step "lane 1/4: build the live_loopback test binary (no run yet)"
  local build_log="$OUT/lane-build.log" bin
  say "cargo test -p aitm-scan-l4-packet --test live_loopback --no-run   (log: $build_log)"
  if ! cargo test -p aitm-scan-l4-packet --test live_loopback --no-run > "$build_log" 2>&1; then
    tail -5 "$build_log"
    rec "lane: the test binary did not build; read $build_log"
    FAILS=$((FAILS + 1))
    return
  fi
  tail -3 "$build_log"
  bin=$(grep -o 'target/debug/deps/live_loopback-[0-9a-f]*' "$build_log" | tail -1)
  if [ -z "$bin" ] || [ ! -x "$ROOT/$bin" ]; then
    rec "lane: could not find the test binary in $build_log"
    FAILS=$((FAILS + 1))
    return
  fi
  rec "lane test binary: $bin ($(stat -c '%y' "$ROOT/$bin"))"

  step "lane 2/4: file capabilities on the test binary (not on cargo, not on a shell)"
  grant_caps "$ROOT/$bin"

  step "lane 3/4: run the three ignored live tests with tcpdump watching lo"
  local log="$OUT/lane.log"
  start_capture "$OUT/lane.pcap"
  say "AITM_L4_TESTS=1 $bin --ignored --nocapture --test-threads=1   (log: $log)"
  AITM_L4_TESTS=1 "$ROOT/$bin" --ignored --nocapture --test-threads=1 > "$log" 2>&1
  local rc=$?
  stop_capture
  rec "lane exit: $rc"

  step "lane 4/4: what the lane printed, and what tcpdump saw"
  rec "lane result lines (from $log):"
  grep -nE '^(test |reaction:|crash:|counters:|classes:|closed (udp|tcp) port:|SKIP 77|test result:)' "$log" \
    | sed 's/^/  /' | tee -a "$SUMMARY"
  pcap_excerpts "$OUT/lane.pcap"
  [ "$rc" -eq 0 ] || FAILS=$((FAILS + 1))
}

# ---------------------------------------------------------------------------
# cells: python3 tests/e2e/run.py scan over a real bus, caps on the core
# ---------------------------------------------------------------------------
run_cells() {
  step "cells 1/4: the binaries the runner boots"
  if [ "${T5_BUILD:-0}" = "1" ]; then
    say "T5_BUILD=1: cargo build -p aitm -p aitm-testtarget   (as $(id -un), never root; setcap comes after)"
    if ! cargo build -p aitm -p aitm-testtarget > "$OUT/cells-build.log" 2>&1; then
      rec "cells: cargo build failed (see $OUT/cells-build.log)"
      FAILS=$((FAILS + 1))
      return
    fi
  fi
  local core="$ROOT/target/debug/aitm" tt="$ROOT/target/debug/aitm-testtarget-serve"
  if [ ! -x "$core" ] || [ ! -x "$tt" ]; then
    rec "cells: missing $core or $tt; build first with: cargo build -p aitm -p aitm-testtarget (or T5_BUILD=1)"
    FAILS=$((FAILS + 1))
    return
  fi
  # shellcheck disable=SC2012  # two named files, human-readable listing is the point
  ls -l "$core" "$tt" | sed 's/^/  /' | tee -a "$SUMMARY"

  step "cells 2/4: file capabilities on the core only"
  grant_caps "$core"

  step "cells 3/4: the real e2e runner, scan surface, WITHOUT --build, with the ledger, tcpdump watching lo"
  local log="$OUT/scan.log" ledger="$OUT/ledger"
  start_capture "$OUT/cells.pcap"
  say "AITM_E2E_LEDGER_DIR=$ledger python3 tests/e2e/run.py scan   (log: $log)"
  AITM_E2E_LEDGER_DIR="$ledger" python3 tests/e2e/run.py scan > "$log" 2>&1
  local rc=$?
  stop_capture
  rec "runner exit: $rc"
  rec "runner first lines (must show no build step):"
  head -5 "$log" | sed 's/^/  /' | tee -a "$SUMMARY"

  step "cells 3b/4: each T5 cell once more on its own, stdout kept (the runner prints a cell's lines only when it FAILs)"
  mkdir -p "$OUT/cells-direct"
  local cell
  for cell in test_t5_bounded_clean test_t5_pins_dryrun test_t5_crash_oracle; do
    say "python3 tests/e2e/scan/$cell.py   (log: $OUT/cells-direct/$cell.log)"
    python3 "tests/e2e/scan/$cell.py" > "$OUT/cells-direct/$cell.log" 2>&1
    rec "direct $cell exit: $? ($(grep -c '\[ok\]' "$OUT/cells-direct/$cell.log") ok lines, $(grep -c '\[FAIL\]' "$OUT/cells-direct/$cell.log") FAIL lines)"
  done

  step "cells 4/4: the three T5 cells, the ledger, and what tcpdump saw"
  rec "T5 cell lines:"
  grep -E '^(PASS|FAIL|SKIP) +scan/test_t5_' "$log" | sed 's/^/  /' > "$OUT/t5-lines.txt"
  tee -a "$SUMMARY" < "$OUT/t5-lines.txt"
  rec "summary line: $(grep -E '^e2e summary:' "$log" | tail -1)"
  rec "ledger (spec D3), from the runner:"
  sed -n '/^scan verb ledger (spec D3):/,/^ledger: /p' "$log" | sed 's/^/  /' | tee -a "$SUMMARY"
  rec "ledger files: $(find "$ledger" -maxdepth 1 -type f -printf '%f ' 2>/dev/null)"
  pcap_excerpts "$OUT/cells.pcap"
  local n_pass
  n_pass=$(grep -cE '^PASS +scan/test_t5_' "$log")
  if [ "$n_pass" -ne 3 ] || grep -qE '^FAIL ' "$log"; then
    rec "cells: expected 3 PASS test_t5_* lines, got $n_pass PASS (see $log)"
    FAILS=$((FAILS + 1))
  fi
}

case "$MODE" in
  lane)  run_lane ;;
  cells) run_cells ;;
  all)   run_lane; run_cells ;;
esac

step "done"
rec "evidence: $OUT (summary: $SUMMARY; pcaps stay here, quote only the text)"
rec "failures: $FAILS"
exit "$FAILS"
