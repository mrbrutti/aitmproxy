#!/usr/bin/env bash
#
# Lane-level live proof for the L4 stream lane (plan task 23a): start T10's
# real `aitm-testtarget-serve --l4` in one mode, point `tests/live_t10.rs` at
# its control origin, run the lane against all eight speakers, stop the target,
# repeat for the other mode.
#
# This is the interim proof while the bus-level engine (T1b) is unavailable.
# It is NOT the bus-level acceptance run for T6-1..T6-5.
#
#   usage: live_t10.sh [<path-to-aitm-testtarget-serve>] [vulnerable|patched|both]
#
# Both arguments are optional. With no binary the script uses this worktree's
# `target/debug/aitm-testtarget-serve`. The mode argument also accepts the `V`
# and `P` labels used in the report file names and the `LIVE` summary lines.
#
# Reports and logs land in $AITM_T6_LIVE_OUT (default /tmp/claude/t6-live):
#   serve-<V|P>.log   the target's own stdout/stderr
#   test-<V|P>.log    the cargo test output
#   <V|P>-<service>.json  one report per speaker
#
# Exits non-zero if any mode failed.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT="${AITM_T6_LIVE_OUT:-/tmp/claude/t6-live}"
DEFAULT_BIN="$ROOT/target/debug/aitm-testtarget-serve"

# How long to wait for the target's `control http://...` and `ready` lines.
STARTUP_TIMEOUT_S=20
# How long a TERMed target gets before it is KILLed.
SHUTDOWN_GRACE_S=3

# --- arguments -------------------------------------------------------------

USAGE="usage: live_t10.sh [<path-to-aitm-testtarget-serve>] [vulnerable|patched|both]"

BIN=""
MODE_ARG="both"
for arg in "$@"; do
  case "$arg" in
    both | V | P | vulnerable | patched)
      MODE_ARG="$arg"
      ;;
    -h | --help)
      sed -n '2,22p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    -*)
      echo "live_t10.sh: unknown option '$arg'" >&2
      echo "  $USAGE" >&2
      exit 2
      ;;
    *)
      # Anything else is the binary. A second one is a typo, most likely a
      # misspelled mode, and is refused rather than silently used as a path.
      if [[ -n "$BIN" ]]; then
        echo "live_t10.sh: unexpected argument '$arg'" >&2
        echo "  $USAGE" >&2
        exit 2
      fi
      BIN="$arg"
      ;;
  esac
done
BIN="${BIN:-$DEFAULT_BIN}"

# Exhaustive: the loop above only ever stores one of these five tokens.
case "$MODE_ARG" in
  both) MODES=(vulnerable patched) ;;
  V | vulnerable) MODES=(vulnerable) ;;
  P | patched) MODES=(patched) ;;
esac

if [[ ! -x "$BIN" ]]; then
  echo "live_t10.sh: no executable target at '$BIN'" >&2
  echo "  build it first: cargo build -p aitm-testtarget --bin aitm-testtarget-serve" >&2
  exit 2
fi

mkdir -p "$OUT"

# --- helpers ---------------------------------------------------------------

SERVE_PID=""

stop_target() {
  [[ -n "$SERVE_PID" ]] || return 0
  kill -TERM "$SERVE_PID" 2>/dev/null || true
  for _ in $(seq 1 $((SHUTDOWN_GRACE_S * 10))); do
    kill -0 "$SERVE_PID" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$SERVE_PID" 2>/dev/null; then
    kill -KILL "$SERVE_PID" 2>/dev/null || true
  fi
  wait "$SERVE_PID" 2>/dev/null || true
  SERVE_PID=""
}

trap stop_target EXIT INT TERM

# Poll $1 for a line matching the regex $2, for up to STARTUP_TIMEOUT_S.
wait_for_line() {
  local log="$1" pattern="$2" i
  for ((i = 0; i < STARTUP_TIMEOUT_S * 10; i++)); do
    if grep -Eq "$pattern" "$log" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# --- the run ---------------------------------------------------------------

overall=0

for mode in "${MODES[@]}"; do
  case "$mode" in
    vulnerable) label="V" ;;
    patched) label="P" ;;
  esac

  serve_log="$OUT/serve-$label.log"
  test_log="$OUT/test-$label.log"
  : >"$serve_log"

  echo "=== live_t10: --mode $mode ($label) ==="
  # The target picks its own ports; the control origin is read off its stdout,
  # never assumed.
  "$BIN" --mode "$mode" --port 0 --control-port 0 --l4 >"$serve_log" 2>&1 &
  SERVE_PID=$!

  if ! wait_for_line "$serve_log" '^control http://'; then
    echo "live_t10.sh: no 'control http://...' line within ${STARTUP_TIMEOUT_S}s in $serve_log" >&2
    sed -n '1,40p' "$serve_log" >&2
    overall=1
    stop_target
    continue
  fi
  if ! wait_for_line "$serve_log" '^ready$'; then
    echo "live_t10.sh: no 'ready' line within ${STARTUP_TIMEOUT_S}s in $serve_log" >&2
    sed -n '1,40p' "$serve_log" >&2
    overall=1
    stop_target
    continue
  fi

  control="$(grep -m1 -E '^control http://' "$serve_log" | awk '{print $2}')"
  echo "live_t10.sh: control origin $control (pid $SERVE_PID)"

  AITM_T10_CONTROL="$control" AITM_T6_LIVE_OUT="$OUT" \
    cargo test --manifest-path "$ROOT/Cargo.toml" -p aitm-scan-l4-stream --offline \
    --test live_t10 -- --ignored --nocapture --test-threads=1 2>&1 | tee "$test_log"
  status="${PIPESTATUS[0]}"
  echo "live_t10.sh: --mode $mode exited $status"
  [[ "$status" -eq 0 ]] || overall=1

  stop_target
done

# --- the summary -----------------------------------------------------------

echo
echo "=== LIVE summary (reports in $OUT) ==="
for mode in "${MODES[@]}"; do
  case "$mode" in
    vulnerable) label="V" ;;
    patched) label="P" ;;
  esac
  if [[ -f "$OUT/test-$label.log" ]]; then
    grep -E '^LIVE (V|P) l4-' "$OUT/test-$label.log" | sort -u
  fi
done

exit "$overall"
