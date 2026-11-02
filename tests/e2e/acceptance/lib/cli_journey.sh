#!/usr/bin/env bash
# Release acceptance, journey CLI (spec §D6) on the INSTALLED aitm, the operator's real HOME.
# Read-only on the operator's state except CLI-9's `set`/`unset`, which run ONLY with
# ACCEPT_YES containing CLI-9 (before-state recorded first, EXIT trap replays it). No --yes, no
# ca install, no config edit.
#
# Usage: cli_journey.sh <livecore|nocore|all> [outdir]      AITM=/opt/homebrew/bin/aitm by default
#   livecore: CLI-4, CLI-5 (+ bus-side check and removal), CLI-7, CLI-9, CLI-10, N4-CLI, CLI-0
#             — precondition: the app's core holds 8080
#   nocore:   CLI-1, CLI-2, CLI-3, CLI-6, CLI-8                — precondition: 8080/8081/8082 all free
#             (checked before CLI-3; a serving `aitm` binds all three)
# Every step writes $OUT/<id>.{out,err,exit}; a step line is `<id> <PASS|FAIL|SKIP|BLOCKED> <detail>`;
# $OUT/../cli-steps.tsv gets the report rows (any id of the half not reached: `SKIP not reached`).
# Exit 0 = all performed PASS, 77 = a SKIP/BLOCKED, 1 = a FAIL.
#
# CLI-9 `set` (spec Constraints "Bypass is a precondition, not a promise", D9): the one-shot passes
# the operator's config.yaml `system_proxy.bypass`, so `set` runs only when that list names his
# tooling (installed.tooling_mentioned on installed.config_bypass), else SKIP `bypass list absent in
# config.yaml system_proxy.bypass`; after the flip `scutil --proxy`'s ExceptionsList must carry them
# (installed.bypass_applied, whole entries) or the cell restores at once (`unset`, then the trap)
# and records FAIL `bypass not applied`.
#
# The hosts CLI-5/CLI-6 add are `acceptance-cli5.invalid` / `acceptance-cli6.invalid`: `.invalid`
# is reserved (RFC 2606), so a one-shot that DOES reach the running core can never touch a host
# that is really in his Scope, and a leftover is unmistakable. When CLI-5's host reaches the core
# (the live-core PR), it is removed again with `aitm scope remove --host …` and verified over the bus.
set -uo pipefail
MODE="${1:-all}"; shift || true
OUT="${1:-/tmp/claude/acceptance/cli}"
AITM="${AITM:-/opt/homebrew/bin/aitm}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
e2e="$(cd "$here/../.." && pwd)"
mkdir -p "$OUT"; STEPS="$(dirname "$OUT")/cli-steps.tsv"; LEFT="$(dirname "$OUT")/leftovers.txt"
[ "$MODE" = nocore ] || : >"$STEPS"   # the live-core half runs first and starts the file fresh; nocore appends
PASS=0; FAIL=0; SKIP=0; DONE=","
want() { [ "$MODE" = all ] || [ "$MODE" = "$1" ]; }
yes_has() { case ",${ACCEPT_YES:-}," in *,"$1",*) return 0;; esac; return 1; }
res() { # id verdict detail [truth] [explains]
  case "$2" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; SKIP|BLOCKED) SKIP=$((SKIP+1));; esac
  DONE="$DONE$1,"
  printf '%-7s %-7s %s\n' "$1" "$2" "$3"
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$(printf '%s' "$3" | tr '\t\n' '  ')" "$(printf '%s' "${4:-}" | tr '\t\n' '  ')" "${5:-}" >>"$STEPS"
}
finish() { # every id of the half that was never written
  local ids="$1" id
  for id in $ids; do case "$DONE" in *,"$id",*) ;; *) res "$id" SKIP "not reached";; esac; done
}
run() { # id secs -- cmd...   (capped; SIGINT at the cap so a serving mode exits orderly)
  local id="$1" secs="$2"; shift 2
  ( trap - INT; exec "$@" ) >"$OUT/$id.out" 2>"$OUT/$id.err" & local pid=$!   # background jobs inherit SIGINT-ignore; reset it so the cap's INT reaches aitm
  ( sleep "$secs"; kill -INT "$pid" 2>/dev/null; sleep 2; kill "$pid" 2>/dev/null ) & local w=$!
  wait "$pid" 2>/dev/null; local rc=$?; kill "$w" 2>/dev/null; wait "$w" 2>/dev/null
  echo "$rc" >"$OUT/$id.exit"; return "$rc"
}
lines() { wc -l <"$1" | tr -d ' '; }
loader() { grep -c 'loaded script\|script loaded into the host' "$1"; }
clean() { grep -hv 'loaded script\|script loaded into the host' "$@" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'; }
holder() { lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1" pid "$2}'; }
# Over the running core's bus (installed.find_embedded_core → operator bus): one verb, compact JSON. Never prints the token.
bus_json() { python3 - "$e2e" "$1" <<'PY' 2>/dev/null
import json, sys
sys.path.insert(0, sys.argv[1])
from aitm_e2e.installed import connect, find_embedded_core
core = find_embedded_core()
if core is None:
    sys.exit(3)
print(json.dumps(connect(core).call(sys.argv[2], {}), separators=(",", ":")))
PY
}
# installed.<fn>(...) through the shared module; prints the function's return (never a token).
py_installed() { python3 -c "import sys; sys.path.insert(0, sys.argv[1]); from aitm_e2e import installed; sys.argv = sys.argv[1:]; $1" "$e2e" "${@:2}" 2>/dev/null; }
h8080=$(holder 8080)
held=""   # "port N held by X" for the first busy default port (the no-core half needs all three free)
for p in 8080 8081 8082; do hp=$(holder "$p"); if [ -n "$hp" ]; then held="port $p held by $hp"; break; fi; done

echo "mode: $MODE   aitm: $AITM -> $(readlink "$AITM" 2>/dev/null || echo "$AITM")   HOME: $HOME"
echo "8080 holder: ${h8080:-none}   default ports: ${held:-all free}"; echo

# ---------------------------------------------------------------- nocore half
if want nocore; then
  if [ -n "$held" ]; then
    for id in CLI-1 CLI-2 CLI-3 CLI-6 CLI-8; do res "$id" SKIP "$held; the no-core half needs 8080, 8081 and 8082 free"; done
  else
    # CLI-1 --version: one line `aitm <version>`, exit 0, nothing else on either stream (required: #271).
    run CLI-1 10 "$AITM" --version; rc=$?
    if [ "$rc" = 0 ] && [ "$(lines "$OUT/CLI-1.out")" = 1 ] && grep -qE '^aitm [0-9]+\.[0-9]+\.[0-9]+' "$OUT/CLI-1.out" && [ "$(lines "$OUT/CLI-1.err")" = 0 ]; then
      res CLI-1 PASS "$(cat "$OUT/CLI-1.out")"
    else
      res CLI-1 FAIL "exit $rc; stdout $(lines "$OUT/CLI-1.out") lines ($(loader "$OUT/CLI-1.out") loader), stderr $(lines "$OUT/CLI-1.err") lines; stderr first: $(clean "$OUT/CLI-1.err" | head -1 | head -c 100)" "" "PR #271"
    fi
    # CLI-2 --help: synopsis incl. tui/web/operator-token, exit 0, no loader lines.
    run CLI-2 10 "$AITM" --help; rc=$?
    if [ "$rc" = 0 ] && grep -q 'tui' "$OUT/CLI-2.out" && grep -q 'web' "$OUT/CLI-2.out" && grep -q 'operator-token' "$OUT/CLI-2.out" && [ "$(loader "$OUT/CLI-2.out")" = 0 ]; then
      res CLI-2 PASS "exit 0, synopsis on stdout (tui, web, operator-token listed)"
    else
      res CLI-2 FAIL "exit $rc; stdout $(lines "$OUT/CLI-2.out") lines ($(loader "$OUT/CLI-2.out") loader); groups seen: tui=$(grep -c tui "$OUT/CLI-2.out") web=$(grep -c web "$OUT/CLI-2.out") operator-token=$(grep -c operator-token "$OUT/CLI-2.out"); stderr first: $(clean "$OUT/CLI-2.err" | head -1 | head -c 100)" "" "PR #271"
    fi
    # CLI-3 bare aitm: the ready card within 10 s (proxy address, bus, CA state, Scope advice), no loader lines on stdout, orderly exit on SIGINT.
    run CLI-3 10 "$AITM"; rc=$?
    card=$(clean "$OUT/CLI-3.out" | grep -ciE 'proxy|listening|bus|CA (trusted|untrusted)|Scope')
    if [ "$(loader "$OUT/CLI-3.out")" = 0 ] && [ "$card" -ge 3 ] && grep -qiE 'CA (trusted|untrusted)' "$OUT/CLI-3.out"; then
      res CLI-3 PASS "ready card: $(clean "$OUT/CLI-3.out" | grep -iE 'proxy|bus|CA' | tr '\n' ' ' | head -c 160)"
    else
      res CLI-3 FAIL "no ready card: stdout $(lines "$OUT/CLI-3.out") lines ($(loader "$OUT/CLI-3.out") loader), non-log lines: $(clean "$OUT/CLI-3.out" | grep -v '^[[:space:]]*$' | head -3 | tr '\n' '|' | head -c 160); exit $rc" "" "PR #271"
    fi
    # CLI-6 scope add with NO core: refusal, exit 1, never the host echoed as success.
    run CLI-6 10 "$AITM" scope add --host acceptance-cli6.invalid; rc=$?
    if [ "$rc" != 0 ] && ! grep -qx 'acceptance-cli6.invalid' "$OUT/CLI-6.out"; then
      res CLI-6 PASS "refused, exit $rc: $(clean "$OUT/CLI-6.err" | head -1 | head -c 120)"
    else
      res CLI-6 FAIL "exit $rc with no core running; stdout last line: $(clean "$OUT/CLI-6.out" | tail -1 | head -c 80) (success for a no-op)" "no core to check" "claude/cli-oneshot-live-core"
    fi
    # CLI-8 web port held by a PLAIN listener on 8082 (not a core: 8080 must stay free so the web-port panel is reached).
    python3 -m http.server 8082 --bind 127.0.0.1 >/dev/null 2>&1 & hp=$!
    sleep 0.7
    if [ "$(holder 8082)" != "Python pid $hp" ] && [ "$(holder 8082)" != "python3 pid $hp" ]; then
      kill "$hp" 2>/dev/null; wait "$hp" 2>/dev/null
      res CLI-8 SKIP "could not hold 8082 with a plain listener (holder: $(holder 8082)); not starting aitm web against a live port"
    else
      run CLI-8 10 "$AITM" web; rc=$?
      kill "$hp" 2>/dev/null; wait "$hp" 2>/dev/null
      if [ "$rc" != 0 ] && grep -q 'cannot start' "$OUT/CLI-8.err" && grep -q '8082' "$OUT/CLI-8.err" && ! grep -qE 'Web UI +http' "$OUT/CLI-8.out"; then
        res CLI-8 PASS "$(clean "$OUT/CLI-8.err" | grep -m1 'cannot start' | head -c 120)"
      else
        res CLI-8 FAIL "exit $rc; stderr: $(clean "$OUT/CLI-8.err" | grep -m1 -iE 'cannot start|in use|rror' | head -c 160); card printed? $(grep -cE 'Web UI +http' "$OUT/CLI-8.out")"
      fi
    fi
  fi
  finish "CLI-1 CLI-2 CLI-3 CLI-6 CLI-8"
fi

# ---------------------------------------------------------------- livecore half
if want livecore; then
  res CLI-0 SKIP "release run only; brew upgrade is Matt's"
  if [ -z "$h8080" ]; then
    for id in CLI-4 CLI-5 CLI-9 CLI-10 N4-CLI; do res "$id" SKIP "no core on 8080; the live-core half needs the app's embedded core up"; done
  else
    # CLI-4 proxy status: must describe the RUNNING core (listening true) or refuse exactly; never its own in-process state.
    run CLI-4 10 "$AITM" proxy status; rc=$?
    if grep -q '"listening": *true' "$OUT/CLI-4.out"; then
      res CLI-4 PASS "reports the running core ($h8080)"
    else
      res CLI-4 FAIL "a core runs on 8080 ($h8080) but the one-shot printed $(grep -oE '"listening": *[a-z]+' "$OUT/CLI-4.out" | head -1), $(grep -oE '"version": *"[^"]+"' "$OUT/CLI-4.out" | head -1) (its own in-process state)" "running core: proxy.status.listening true" "claude/cli-oneshot-live-core"
    fi
    # CLI-5 scope add: the host must reach the RUNNING core's scope.list (bus-side check through the embedded core's bus).
    run CLI-5 10 "$AITM" scope add --host acceptance-cli5.invalid; rc=$?
    truth=$(bus_json scope.list | head -c 300)
    if [ "$rc" = 0 ] && echo "$truth" | grep -q 'acceptance-cli5.invalid'; then
      res CLI-5 PASS "the running core lists it" "scope.list contains acceptance-cli5.invalid"
      # It reached his core: take it out again through the same surface, verify over the bus.
      if [ "${ACCEPT_KEEP_SCOPE:-0}" = 1 ]; then
        printf 'acceptance-cli5.invalid\tkept\tcli\n' >>"$LEFT"
      else
        run CLI-5-rm 10 "$AITM" scope remove --host acceptance-cli5.invalid
        if bus_json scope.list | grep -q 'acceptance-cli5.invalid'; then printf 'acceptance-cli5.invalid\tfailed\tcli\n' >>"$LEFT"; else printf 'acceptance-cli5.invalid\tremoved\tcli\n' >>"$LEFT"; fi
      fi
    else
      res CLI-5 FAIL "exit $rc, printed '$(clean "$OUT/CLI-5.out" | tail -1 | head -c 60)' but the running core's scope.list does not contain it (false success; nothing to remove)" "scope.list ${truth:-unreadable}" "claude/cli-oneshot-live-core"
    fi
    # N4-CLI: `aitm web` while 8080 is held must print the cannot-start panel, exit 1, no card first.
    run N4-CLI 10 "$AITM" web; rc=$?
    if [ "$rc" != 0 ] && grep -q 'cannot start' "$OUT/N4-CLI.err" && ! grep -qE 'Web UI +http' "$OUT/N4-CLI.out"; then
      res N4-CLI PASS "$(clean "$OUT/N4-CLI.err" | grep -m1 'cannot start' | head -c 120); $(loader "$OUT/N4-CLI.out") loader lines on stdout first" "" "log noise: PR #271"
    else
      res N4-CLI FAIL "exit $rc; stderr: $(clean "$OUT/N4-CLI.err" | grep -m1 -iE 'cannot start|in use|rror' | head -c 160); card printed? $(grep -cE 'Web UI +http' "$OUT/N4-CLI.out")"
    fi
    # CLI-9 proxy system: `status` is read-only and always runs; `set`/`unset` only with Matt's yes.
    run CLI-9-status 10 "$AITM" proxy system status; rc9=$?
    st_bus=$(bus_json proxy.system.status | head -c 200)
    st_cli=$(clean "$OUT/CLI-9-status.out" | grep -oE '"(state|managed_by_us)": *[^,}]+' | tr '\n' ' ' | head -c 120)
    byp=$(py_installed 'print(", ".join(installed.config_bypass()))')
    if ! yes_has CLI-9; then
      res CLI-9 SKIP "status read (exit $rc9: ${st_cli:-no state/managed_by_us in the output}); set/unset need Matt's yes (ACCEPT_YES=CLI-9)" "proxy.system.status over the bus: ${st_bus:-unreadable}"
    elif [ "$(py_installed 'print("yes" if installed.tooling_mentioned(installed.config_bypass()) else "no")')" != yes ]; then
      # The precondition (spec Constraints): the one-shot passes config.yaml's system_proxy.bypass; without the tooling in it, no flip.
      res CLI-9 SKIP "bypass list absent in config.yaml system_proxy.bypass (${byp:-none}); add the operator's tooling there first — status read (exit $rc9: ${st_cli:-no state/managed_by_us}); set/unset not run" "proxy.system.status over the bus: ${st_bus:-unreadable}"
    else
      rec="$OUT/CLI-9-before.json"
      python3 -c "import sys; sys.path.insert(0, sys.argv[1]); from aitm_e2e.installed import record_state_file; record_state_file(sys.argv[2])" "$e2e" "$rec"
      sc_before=$(scutil --proxy)
      # The trap replays the recorded per-service state iff scutil still differs at exit.
      trap 'python3 -c "import sys; sys.path.insert(0, sys.argv[1]); from aitm_e2e.installed import replay_file; sys.exit(replay_file(sys.argv[2]))" "$e2e" "$rec" || echo "CLI-9 trap: replay left scutil different from the recording"' EXIT
      echo "== window CLI-9 start $(date -u +%H:%M:%S)"
      run CLI-9-set 15 "$AITM" proxy system set; rcs=$?
      sc_set=$(scutil --proxy)
      refusal=$(clean "$OUT/CLI-9-set.err" "$OUT/CLI-9-set.out" 2>/dev/null | grep -m1 -E 'needs a running core|no running core' | head -c 160)
      if [ "$sc_set" != "$sc_before" ]; then
        # Judge the flip: points at 8080 AND the ExceptionsList carries the tooling as whole entries (installed.bypass_applied).
        applied=$(printf '%s' "$sc_set" | py_installed 'print("yes" if installed.bypass_applied(sys.stdin.read()) else "no")')
        if echo "$sc_set" | grep -q 'HTTPPort : 8080'; then at_us=1; else at_us=0; fi
        run CLI-9-unset 15 "$AITM" proxy system unset; rcu=$?   # restore at once, whatever the judgement; the trap replays if this left a difference
        sc_after=$(scutil --proxy)
        same_after=$([ "$sc_after" = "$sc_before" ] && echo yes || echo NO)
        if [ "$applied" != yes ]; then
          res CLI-9 FAIL "bypass not applied: set changed scutil (points at 8080: $at_us) but the ExceptionsList lacks the tooling hosts; restored at once (unset exit $rcu, scutil identical to before: $same_after$([ "$same_after" = NO ] && echo ' — the trap replays'))" "$(echo "$sc_set" | tr '\n' ' ' | head -c 200)"
        elif [ "$at_us" = 1 ] && [ "$same_after" = yes ]; then
          res CLI-9 PASS "status exit $rc9 (${st_cli}); set acted on the Mac (8080, ExceptionsList carries the tooling), unset restored it byte for byte" "proxy.system.status before ${st_bus}; after $(bus_json proxy.system.status | head -c 120)"
        else
          res CLI-9 FAIL "set changed scutil (points at 8080: $at_us, bypass applied: yes); unset exit $rcu, scutil identical to before: $same_after$([ "$same_after" = NO ] && echo ' — the trap replays')" "$(echo "$sc_set" | tr '\n' ' ' | head -c 200)"
        fi
      elif [ -n "$refusal" ] && [ "$rcs" != 0 ]; then
        res CLI-9 PASS "status exit $rc9 (${st_cli}); set refused honestly: $refusal; scutil unchanged (unset not run: nothing was set)" "proxy.system.status over the bus ${st_bus}" "claude/cli-oneshot-live-core (the live-core requirement)"
      else
        res CLI-9 FAIL "set exit $rcs printed '$(clean "$OUT/CLI-9-set.out" | tail -1 | head -c 80)' while scutil is unchanged and no refusal sentence was printed (a success line without an effect)" "proxy.system.status over the bus ${st_bus}" "claude/cli-oneshot-live-core"
      fi
      echo "== window CLI-9 end $(date -u +%H:%M:%S)"
    fi
    # CLI-10 flow list vs the running core's flow.table ids (needs MAC-8 rows on the core).
    ids_bus=$(bus_json flow.table | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(str(f.get("id")) for f in d.get("flows", [])))' 2>/dev/null)
    if [ -z "$ids_bus" ]; then
      res CLI-10 BLOCKED "MAC-8: the running core has no flows to compare against"
    else
      run CLI-10 10 "$AITM" flow list; rc=$?
      n_bus=$(echo "$ids_bus" | wc -w | tr -d ' '); n_hit=0
      for fid in $ids_bus; do grep -qF -- "$fid" "$OUT/CLI-10.out" && n_hit=$((n_hit+1)); done
      if [ "$rc" = 0 ] && [ "$n_hit" = "$n_bus" ]; then
        res CLI-10 PASS "the one-shot lists the running core's $n_bus flow(s)" "flow.table ids: $n_bus"
      else
        res CLI-10 FAIL "exit $rc; the running core has $n_bus flow(s), the one-shot's output matches $n_hit of their ids: $(clean "$OUT/CLI-10.out" | head -c 80)" "flow.table ids: $n_bus" "claude/cli-oneshot-live-core"
      fi
    fi
  fi
  # CLI-7 ca status: read-only, runs with or without a core; must agree with the keychain.
  run CLI-7 10 "$AITM" ca status; rc=$?
  tr7=$(python3 -c 'import json,sys; t=open(sys.argv[1]).read(); i=t.find("{"); d=json.loads(t[i:]); u=d["stores"]["user"]; print("user installed="+u["installed"]+" trusted="+u["trusted"])' "$OUT/CLI-7.out" 2>/dev/null || echo "unparseable")
  kc=$(security find-certificate -a -c aitmproxy -Z "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null | grep -c 'SHA-1')
  if [ "$rc" = 0 ] && { { [ "$kc" -ge 1 ] && echo "$tr7" | grep -q 'installed=present'; } || { [ "$kc" = 0 ] && echo "$tr7" | grep -q 'installed=absent'; }; }; then
    res CLI-7 PASS "$tr7 (keychain has $kc aitmproxy cert); $(loader "$OUT/CLI-7.out") loader lines before the JSON" "ca.status over the bus agrees" "log noise: PR #271"
  else
    res CLI-7 FAIL "exit $rc; $tr7 vs keychain count $kc"
  fi
  finish "CLI-0 CLI-4 CLI-5 CLI-7 CLI-9 CLI-10 N4-CLI"
fi

echo; echo "PASS=$PASS FAIL=$FAIL SKIP/BLOCKED=$SKIP  outputs in $OUT"
[ "$FAIL" -gt 0 ] && exit 1
[ "$SKIP" -gt 0 ] && exit 77
exit 0
