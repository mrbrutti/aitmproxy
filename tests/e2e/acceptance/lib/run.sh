#!/usr/bin/env bash
# Release acceptance runner (spec 2026-11-01-release-acceptance-operator-journeys §D9).
#
#   tests/e2e/acceptance/lib/run.sh <version> [--manual] [--journeys cli,mac,tui,web,negatives]
#
# Runs from a REAL shell (the Terminal panel), on the operator's installed build and real state.
# Order: preflight (state-before) → cli-livecore → mac → n5 (negatives) → tui → web → cli-nocore →
# preflight (state-after) → diff → secret grep → report skeleton. Every `yes` step is performed
# ONLY when its id is listed in ACCEPT_YES (e.g. ACCEPT_YES=MAC-6,MAC-7,MAC-14,MAC-15); everything
# else that changes machine state is SKIP "needs Matt's yes". `hand` steps pause only with --manual
# (AITM_E2E_MANUAL=1), else SKIP; the cells keep THIS shell's stdin (`<&0`) so a pause can read the
# operator's Enter (a backgrounded command would otherwise get /dev/null). UI driving needs
# ACCEPT_WINDOW=1 (the orchestrator's display lock).
# Each run writes into /tmp/claude/acceptance/<version>/run-<UTC timestamp>/ and points
# /tmp/claude/acceptance/<version>/latest at it, so every *-steps.tsv is fresh.
# Each cell runs under a watchdog (ACCEPT_CELL_TIMEOUT seconds, default 1200): at the cap the cell
# gets SIGINT, up to 30 s to run its `finally` (restore trap, Scope cleanup, step file), then
# SIGTERM (the cells turn it into SystemExit(2) so `finally` still runs), 10 s, then SIGKILL. A
# killed cell is an ERROR row and the run exits 2. The system proxy is recorded at the run start
# (state-before.json); after any ERROR cell it is compared with `scutil --proxy` and the recorded
# per-service state is replayed if it differs (spec D1 `error`: "re-read and restored regardless").
# Exit: 0 = pass (every step PASS or N/A), 77 = incomplete (no FAIL, but a step was SKIP/BLOCKED for
# want of a yes, a hand or a free port: NOT green), 1 = a performed step FAILed or a secret leaked,
# 2 = runner error (a cell killed by the watchdog or exited 2, report.py failed, bad usage).
# `--journeys` is the builder's debugging aid (not in the spec): it narrows the cells; a report from
# a narrowed run is never the release report.
# The durable audit is the TUI journey's only bus truth, so AITM_AUDIT_LOG is never set to off here.
# Secrets: the embedded core's token VALUES are collected right after the first bus_truth.py (the
# app may have quit by the end) and again at the end, unioned with AITM_WEB_TOKEN and the web
# cell's `#t=` bearer values (written by the web cell to $ACCEPT_OUT/.secrets, 0600, one per line);
# the grep takes them through `-f <(…)` (never argv), then the file is overwritten and deleted
# before the report is written.
# BSD sed only (/usr/bin/sed): no \s, no \S anywhere in this file. bash 3.2-compatible (no wait -n).
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
e2e="$(cd "$here/../.." && pwd)"
ver="${1:-}"; shift || true
[ -n "$ver" ] || { echo "usage: run.sh <version> [--manual] [--journeys cli,mac,tui,web,negatives]" >&2; exit 2; }
journeys="cli,mac,tui,web,negatives"
while [ $# -gt 0 ]; do
  case "$1" in
    --manual) export AITM_E2E_MANUAL=1;;
    --journeys) journeys="$2"; shift;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac; shift
done
export ACCEPT_YES="${ACCEPT_YES:-}"
unset AITM_AUDIT_LOG AITM_BIN
cell_timeout="${ACCEPT_CELL_TIMEOUT:-1200}"
ROOT="/tmp/claude/acceptance/$ver"
OUT="$ROOT/run-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$OUT"; export ACCEPT_OUT="$OUT"
rm -f "$ROOT/latest"; ln -s "$OUT" "$ROOT/latest"
log="$OUT/run.log"; exec > >(tee -a "$log") 2>&1
echo "== release acceptance $ver  $(date -u +%FT%TZ)"
echo "   yes-list: ${ACCEPT_YES:-(none: every machine-state step is SKIP)}"
echo "   manual:   ${AITM_E2E_MANUAL:-0}   window: ${ACCEPT_WINDOW:-0}   journeys: $journeys   cell timeout: ${cell_timeout}s"
echo "   out:      $OUT  (latest -> $ROOT/latest)"

py_installed() { # <python one-liner body using `installed`>  args...   (the shared module, token never printed)
  local body="$1"; shift
  python3 -c "import sys; sys.path.insert(0, sys.argv[1]); from aitm_e2e import installed; sys.argv = sys.argv[1:]; $body" "$e2e" "$@"
}

# The system proxy as it is NOW, recorded for the ERROR path (a cell that died before its own trap).
state_json="$OUT/state-before.json"
py_installed 'installed.record_state_file(sys.argv[1])' "$state_json" && echo "state-before.json recorded (scutil + per-service)"
scutil_start="$(scutil --proxy)"

restore_after_error() { # after an ERROR cell: replay the recorded state iff scutil differs from the run start; say what was done
  if [ "$(scutil --proxy)" = "$scutil_start" ]; then
    echo "   system proxy: identical to the run-start reading; nothing to restore"
    return
  fi
  echo "   system proxy: DIFFERS from the run-start reading; replaying the recorded per-service state from state-before.json"
  if py_installed 'sys.exit(installed.replay_file(sys.argv[1]))' "$state_json"; then
    echo "   restored: scutil --proxy identical to the run-start reading again"
  else
    echo "   !! replay ran but scutil --proxy still differs (or networksetup refused); see state-after.txt"
  fi
}

fail=0; incomplete=0; error=0; results="$OUT/results.tsv"; : >"$results"
alive() { kill -0 "$1" 2>/dev/null; }
wait_gone() { # pid secs   — poll up to secs for the pid to exit
  local i=0
  while alive "$1" && [ "$i" -lt "$2" ]; do sleep 1; i=$((i+1)); done
  ! alive "$1"
}
run_cell() { # name cmd...   (watchdog: INT at the cap, 30 s, TERM, 10 s, KILL; a killed cell = ERROR, exit 2)
  local name="$1"; shift
  echo; echo "---- $name  $(date -u +%H:%M:%S)"
  # Asynchronous commands of a non-interactive bash start with SIGINT IGNORED (Python then never
  # installs KeyboardInterrupt, a bash cell cannot trap it): the launcher resets SIGINT to default
  # and execs the cell, so the watchdog's INT reaches its `finally`. `<&0`: the cell keeps this
  # shell's stdin for `pause()` (a plain `&` would hand it /dev/null).
  python3 -c 'import os, signal, sys; signal.signal(signal.SIGINT, signal.SIG_DFL); os.execvp(sys.argv[1], sys.argv[1:])' "$@" <&0 >"$OUT/$name.out" 2>&1 & local pid=$!
  ( exec sleep "$cell_timeout" ) & local w=$!   # exec: killing $w kills the sleep itself, nothing is left behind
  while alive "$pid" && alive "$w"; do sleep 1; done
  local fired=0
  if alive "$pid"; then
    fired=1
    echo "!! $name reached the ${cell_timeout}s cap: SIGINT (30 s for its finally), then SIGTERM (10 s), then SIGKILL"
    kill -INT "$pid" 2>/dev/null; wait_gone "$pid" 30 || { kill -TERM "$pid" 2>/dev/null; wait_gone "$pid" 10 || kill -KILL "$pid" 2>/dev/null; }
  fi
  wait "$pid" 2>/dev/null; local rc=$?
  kill "$w" 2>/dev/null; wait "$w" 2>/dev/null
  cat "$OUT/$name.out"
  if [ "$fired" = 1 ]; then
    printf '%s\tERROR\tkilled by the watchdog after %ss (exit %s)\n' "$name" "$cell_timeout" "$rc" >>"$results"; error=1
    echo "!! $name killed by the watchdog after ${cell_timeout}s (exit $rc)"; restore_after_error; return
  fi
  case "$rc" in
    0) printf '%s\tPASS\n' "$name" >>"$results";;
    77) printf '%s\tSKIP\t%s\n' "$name" "$(grep -m1 -E '^[A-Z0-9-]+ +(SKIP|BLOCKED|N/A) ' "$OUT/$name.out" | head -c 200)" >>"$results"; incomplete=1;;
    2) printf '%s\tERROR\texit 2\n' "$name" >>"$results"; error=1; restore_after_error;;
    *) printf '%s\tFAIL\texit %s\n' "$name" "$rc" >>"$results"; fail=1;;
  esac
}

# Secret VALUES for the leak grep: the embedded core's operator + agent tokens through the shared
# finder (never echoed anywhere else), unioned into `secrets`.
secrets=()
add_secret() { local s v="$1"; [ -n "$v" ] || return 0; for s in "${secrets[@]+"${secrets[@]}"}"; do [ "$s" = "$v" ] && return 0; done; secrets+=("$v"); }
collect_core_secrets() {
  local v
  while IFS= read -r v; do add_secret "$v"; done < <(python3 - "$e2e" <<'PY' 2>/dev/null
import sys
sys.path.insert(0, sys.argv[1])
from aitm_e2e.installed import embedded_secret_lines, find_embedded_core
try:
    core = find_embedded_core()
except RuntimeError:
    core = None
if core:
    print("\n".join(embedded_secret_lines(core)))
PY
)
}

bash "$here/preflight.sh" "$OUT/state-before.txt" >/dev/null
echo "state-before written"
python3 "$here/bus_truth.py" --embedded >"$OUT/bus-truth-before.txt" 2>&1 || echo "bus truth: $(tail -1 "$OUT/bus-truth-before.txt")"
collect_core_secrets   # now, while the app is still up (it may have quit by the end)
echo "   known secret values at start: ${#secrets[@]}"

cells="$here/.."
# CLI-4/5/7/9/10 need the app's core up; CLI-1/2/3/6/8 need the ports free. Two halves, two preconditions.
case ",$journeys," in *,cli,*) run_cell cli-livecore bash "$here/cli_journey.sh" livecore "$OUT/cli";; esac
case ",$journeys," in *,mac,*) run_cell mac python3 "$cells/test_mac_journey.py";; esac
case ",$journeys," in *,mac,*|*,negatives,*) run_cell n5 python3 "$cells/test_n5_wrong_token.py";; esac
case ",$journeys," in *,tui,*) run_cell tui python3 "$cells/test_tui_journey.py";; esac
case ",$journeys," in *,web,*) run_cell web python3 "$cells/test_web_journey.py";; esac
case ",$journeys," in *,cli,*) run_cell cli-nocore bash "$here/cli_journey.sh" nocore "$OUT/cli";; esac

bash "$here/preflight.sh" "$OUT/state-after.txt" >/dev/null
python3 "$here/bus_truth.py" --embedded >"$OUT/bus-truth-after.txt" 2>&1 || true
echo; echo "---- restore diff (state-before vs state-after; timestamps and pids differ by design)"
volatile() { # strip timestamps, pids, sizes and dates, keep every line (so a new file or process still shows)
  sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+//; s/^([0-9]+) /<pid> /; s/pid [0-9]+/pid <n>/g; s/^(.rw|drw)[^ ]+ +[0-9]+ +[a-z]+ +[a-z]+ +[0-9]+ +[A-Z][a-z]{2} +[0-9]+ +[0-9:]+ /<ls> /; s/^total [0-9]+/total <n>/; s/^written to .*//; s/aitm-embedded-core\/[0-9A-F-]{36}/aitm-embedded-core\/<uuid>/g; s/127\.0\.0\.1:[0-9]{4,5}/127.0.0.1:<port>/g; s/"at":[0-9]+/"at":<ms>/g' "$1"
}
diff <(volatile "$OUT/state-before.txt") <(volatile "$OUT/state-after.txt") >"$OUT/state-diff.txt" \
  && echo "identical" || { echo "DIFFERS:"; cat "$OUT/state-diff.txt"; }

echo; echo "---- secret leak check (operator token value, agent token value, web #t= values, AITM_WEB_TOKEN)"
leak=0
collect_core_secrets   # again: a restarted core (MAC-13) minted new values
[ -n "${AITM_WEB_TOKEN:-}" ] && add_secret "$AITM_WEB_TOKEN"
secrets_file="$OUT/.secrets"
if [ -f "$secrets_file" ]; then
  while IFS= read -r v; do add_secret "$v"; done <"$secrets_file"
fi
echo "   known secret values: ${#secrets[@]}"
if [ "${#secrets[@]}" -gt 0 ]; then
  # Patterns through -f (a process substitution), never argv; the .secrets file itself is excluded, then destroyed.
  hits=$(grep -rlF --exclude=.secrets -f <(printf '%s\n' "${secrets[@]}") "$OUT" 2>/dev/null || true)
  [ -n "$hits" ] && { echo "SECRET VALUE present in: $hits"; leak=1; }
fi
if [ -f "$secrets_file" ]; then
  rm -P "$secrets_file" 2>/dev/null || { : >"$secrets_file"; rm -f "$secrets_file"; }
  echo "   .secrets overwritten and deleted"
fi
tok_hits=$(grep -rElI '#t=[A-Za-z0-9_-]{12,}|operator_token: *"?[A-Za-z0-9_-]{16,}' "$OUT" 2>/dev/null || true)
[ -n "$tok_hits" ] && { echo "TOKEN-SHAPED STRING in: $tok_hits"; leak=1; }
[ "$leak" = 1 ] && fail=1 || echo "none"

if python3 "$here/report.py" "$ver" "$OUT" >"$OUT/README.md"; then
  echo "report skeleton: $OUT/README.md"
else
  echo "!! report.py failed (exit $?): no README written; the run is an ERROR"; error=1
fi
echo; echo "---- summary"; column -t -s $'\t' "$results"
if [ "$error" = 1 ]; then echo "VERDICT: ERROR (a cell was killed or exited 2, or report.py failed; no verdict for the release)"; exit 2; fi
if [ "$fail" = 1 ]; then echo "VERDICT: FAIL (blocks the tap bump)"; exit 1; fi
if [ "$incomplete" = 1 ]; then echo "VERDICT: INCOMPLETE (SKIP/BLOCKED steps remain; not green)"; exit 77; fi
echo "VERDICT: PASS"; exit 0
