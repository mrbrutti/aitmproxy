#!/usr/bin/env bash
# Release acceptance runner (spec 2026-11-01-release-acceptance-operator-journeys §D9).
#
#   tests/e2e/acceptance/run.sh <version> [--manual] [--journeys cli,mac,tui,web]
#
# Runs from a REAL shell (the Terminal panel), on the operator's installed build and real state.
# Order: preflight (state-before) → cli → mac → tui → web → preflight (state-after) → diff →
# report skeleton. Every `yes` step is performed ONLY when its id is listed in ACCEPT_YES
# (e.g. ACCEPT_YES=MAC-6,MAC-7,MAC-14,MAC-15); everything else that changes machine state is
# SKIP "needs Matt's yes". `hand` steps pause only with --manual (AITM_E2E_MANUAL=1), else SKIP.
# Exit: 0 = pass (every step PASS), 77 = incomplete (no FAIL, but a step was SKIP/BLOCKED for want
# of a yes, a hand or a free port: NOT green), 1 = a performed step FAILed, 2 = runner error.
# The durable audit is the TUI journey's only bus truth, so AITM_AUDIT_LOG is never set to off here.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../../.." && pwd)"
ver="${1:-}"; shift || true
[ -n "$ver" ] || { echo "usage: run.sh <version> [--manual] [--journeys cli,mac,tui,web]" >&2; exit 2; }
journeys="cli,mac,tui,web"
while [ $# -gt 0 ]; do
  case "$1" in
    --manual) export AITM_E2E_MANUAL=1;;
    --journeys) journeys="$2"; shift;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac; shift
done
export ACCEPT_YES="${ACCEPT_YES:-}"
unset AITM_AUDIT_LOG AITM_BIN
OUT="/tmp/claude/acceptance/$ver"; mkdir -p "$OUT"; export ACCEPT_OUT="$OUT"
log="$OUT/run.log"; exec > >(tee -a "$log") 2>&1
echo "== release acceptance $ver  $(date -u +%FT%TZ)"
echo "   yes-list: ${ACCEPT_YES:-(none: every machine-state step is SKIP)}"
echo "   manual:   ${AITM_E2E_MANUAL:-0}   journeys: $journeys   out: $OUT"

fail=0; incomplete=0; results="$OUT/results.tsv"; : >"$results"
run_cell() { # name cmd...
  local name="$1"; shift
  echo; echo "---- $name"
  "$@" >"$OUT/$name.out" 2>&1; local rc=$?
  cat "$OUT/$name.out"
  case "$rc" in
    0) printf '%s\tPASS\n' "$name" >>"$results";;
    77) printf '%s\tSKIP\t%s\n' "$name" "$(grep -m1 '\[SKIP\]' "$OUT/$name.out" | head -c 200)" >>"$results"; incomplete=1;;
    *) printf '%s\tFAIL\texit %s\n' "$name" "$rc" >>"$results"; fail=1;;
  esac
}

bash "$here/preflight.sh" "$OUT/state-before.txt" >/dev/null
echo "state-before written"
python3 "$here/bus_truth.py" --embedded >"$OUT/bus-truth-before.txt" 2>&1 || echo "bus truth: $(tail -1 "$OUT/bus-truth-before.txt")"

cells="$here/.."
# CLI-4/5/7 need the app's core up; CLI-1/2/3/6/8 need the ports free. Two halves, two preconditions.
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
cfg=$(pgrep -fl '^/Applications/Aitmproxy.app/Contents/Resources/core/aitm' 2>/dev/null | sed -nE 's/^[0-9]+ \/Applications\/Aitmproxy.app\/Contents\/Resources\/core\/aitm --config (.+\/config\.yaml)$/\1/p' | head -1)
secrets=()
[ -n "$cfg" ] && while IFS= read -r v; do [ -n "$v" ] && secrets+=("$v"); done < <(grep -E '^\s*(operator_token|token):' "$cfg" | sed -E 's/^[^:]+:\s*"?([^"]+)"?$/\1/')
[ -n "${AITM_WEB_TOKEN:-}" ] && secrets+=("$AITM_WEB_TOKEN")
for v in "${secrets[@]}"; do
  hits=$(grep -rlF -- "$v" "$OUT" 2>/dev/null || true)
  [ -n "$hits" ] && { echo "SECRET VALUE present in: $hits"; leak=1; }
done
tok_hits=$(grep -rElI '#t=[A-Za-z0-9_-]{12,}|operator_token: *"?[A-Za-z0-9_-]{16,}' "$OUT" 2>/dev/null || true)
[ -n "$tok_hits" ] && { echo "TOKEN-SHAPED STRING in: $tok_hits"; leak=1; }
[ "$leak" = 1 ] && fail=1 || echo "none"

python3 "$here/report.py" "$ver" "$OUT" >"$OUT/README.md" && echo "report skeleton: $OUT/README.md"
echo; echo "---- summary"; column -t -s $'\t' "$results"
if [ "$fail" = 1 ]; then echo "VERDICT: FAIL (blocks the tap bump)"; exit 1; fi
if [ "$incomplete" = 1 ]; then echo "VERDICT: INCOMPLETE (SKIP/BLOCKED steps remain; not green)"; exit 77; fi
echo "VERDICT: PASS"; exit 0
