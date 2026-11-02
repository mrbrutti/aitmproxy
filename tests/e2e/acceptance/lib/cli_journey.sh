#!/usr/bin/env bash
# Release acceptance, journey CLI (spec §D6) on the INSTALLED aitm, the operator's real HOME.
# Read-only on the operator's state: no --yes, no ca install, no system proxy verbs, no config edit.
#
# Usage: cli_journey.sh <livecore|nocore|all> [outdir]      AITM=/opt/homebrew/bin/aitm by default
#   livecore: CLI-4, CLI-5 (+ bus-side check), CLI-7, N4-CLI  — precondition: the app's core holds 8080
#   nocore:   CLI-1, CLI-2, CLI-3, CLI-6, CLI-8                — precondition: 8080/8081/8082 free
# Every step writes $OUT/<id>.{out,err,exit}; a step line is `<id> <PASS|FAIL|SKIP> <detail>`;
# $OUT/../cli-steps.tsv gets the report rows. Exit 0 = all performed PASS, 77 = a SKIP, 1 = a FAIL.
set -uo pipefail
MODE="${1:-all}"; shift || true
OUT="${1:-/tmp/claude/acceptance/cli}"
AITM="${AITM:-/opt/homebrew/bin/aitm}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUT"; STEPS="$(dirname "$OUT")/cli-steps.tsv"; touch "$STEPS"
PASS=0; FAIL=0; SKIP=0
want() { [ "$MODE" = all ] || [ "$MODE" = "$1" ]; }
res() { # id verdict detail [truth] [explains]
  case "$2" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; SKIP) SKIP=$((SKIP+1));; esac
  printf '%-7s %-5s %s\n' "$1" "$2" "$3"
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-}" "${5:-}" >>"$STEPS"
}
run() { # id secs -- cmd...   (capped; SIGINT at the cap so a serving mode exits orderly)
  local id="$1" secs="$2"; shift 2
  ( "$@" ) >"$OUT/$id.out" 2>"$OUT/$id.err" & local pid=$!
  ( sleep "$secs"; kill -INT "$pid" 2>/dev/null; sleep 2; kill "$pid" 2>/dev/null ) & local w=$!
  wait "$pid" 2>/dev/null; local rc=$?; kill "$w" 2>/dev/null; wait "$w" 2>/dev/null
  echo "$rc" >"$OUT/$id.exit"; return "$rc"
}
lines() { wc -l <"$1" | tr -d ' '; }
loader() { grep -c 'loaded script\|script loaded into the host' "$1"; }
clean() { grep -v 'loaded script\|script loaded into the host' "$1" | sed 's/\x1b\[[0-9;]*m//g'; }
holder() { lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1" pid "$2}'; }
h8080=$(holder 8080)

echo "mode: $MODE   aitm: $AITM -> $(readlink "$AITM" 2>/dev/null || echo "$AITM")   HOME: $HOME"
echo "8080 holder: ${h8080:-none}"; echo

# ---------------------------------------------------------------- nocore half
if want nocore; then
  if [ -n "$h8080" ]; then
    for id in CLI-1 CLI-2 CLI-3 CLI-6 CLI-8; do res "$id" SKIP "port 8080 held by $h8080; the no-core half needs the ports free"; done
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
    if [ "$rc" = 0 ] && grep -q 'tui' "$OUT/CLI-2.out" && grep -q 'web' "$OUT/CLI-2.out" && [ "$(loader "$OUT/CLI-2.out")" = 0 ]; then
      res CLI-2 PASS "exit 0, synopsis on stdout"
    else
      res CLI-2 FAIL "exit $rc; stdout $(lines "$OUT/CLI-2.out") lines ($(loader "$OUT/CLI-2.out") loader); stderr first: $(clean "$OUT/CLI-2.err" | head -1 | head -c 100)" "" "PR #271"
    fi
    # CLI-3 bare aitm: the ready card within 10 s (proxy address, bus, CA state, Scope advice), no loader lines on stdout, orderly exit on SIGINT.
    run CLI-3 10 "$AITM"; rc=$?
    card=$(clean "$OUT/CLI-3.out" | grep -ciE 'proxy|listening|bus|CA (trusted|untrusted)|Scope')
    if [ "$(loader "$OUT/CLI-3.out")" = 0 ] && [ "$card" -ge 3 ] && grep -qiE 'CA (trusted|untrusted)' "$OUT/CLI-3.out"; then
      res CLI-3 PASS "ready card: $(clean "$OUT/CLI-3.out" | grep -iE 'proxy|bus|CA' | tr '\n' ' ' | head -c 160)"
    else
      res CLI-3 FAIL "no ready card: stdout $(lines "$OUT/CLI-3.out") lines ($(loader "$OUT/CLI-3.out") loader), non-log lines: $(clean "$OUT/CLI-3.out" | grep -v '^\s*$' | head -3 | tr '\n' '|' | head -c 160); exit $rc" "" "PR #271"
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
    sleep 0.5
    run CLI-8 10 "$AITM" web; rc=$?
    kill "$hp" 2>/dev/null; wait "$hp" 2>/dev/null
    if [ "$rc" != 0 ] && grep -q 'cannot start' "$OUT/CLI-8.err" && grep -q '8082' "$OUT/CLI-8.err" && ! grep -qE 'Web UI +http' "$OUT/CLI-8.out"; then
      res CLI-8 PASS "$(clean "$OUT/CLI-8.err" | grep -m1 'cannot start' | head -c 120)"
    else
      res CLI-8 FAIL "exit $rc; stderr: $(clean "$OUT/CLI-8.err" | grep -m1 -iE 'cannot start|in use|rror' | head -c 160); card printed? $(grep -cE 'Web UI +http' "$OUT/CLI-8.out")"
    fi
  fi
fi

# ---------------------------------------------------------------- livecore half
if want livecore; then
  if [ -z "$h8080" ]; then
    for id in CLI-4 CLI-5 N4-CLI; do res "$id" SKIP "no core on 8080; the live-core half needs the app's embedded core up"; done
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
    truth=$(python3 "$here/bus_truth.py" --embedded 2>/dev/null | sed -n '/== scope.list/,/== proxy.status/p' | sed '1d;$d' | tr -d '\n ' | head -c 200)
    if [ "$rc" = 0 ] && echo "$truth" | grep -q 'acceptance-cli5.invalid'; then
      res CLI-5 PASS "the running core lists it" "scope.list contains acceptance-cli5.invalid"
    else
      res CLI-5 FAIL "exit $rc, printed '$(clean "$OUT/CLI-5.out" | tail -1 | head -c 60)' but the running core's scope.list does not contain it (false success)" "scope.list ${truth:-unreadable}" "claude/cli-oneshot-live-core"
    fi
    # N4-CLI: `aitm web` while 8080 is held must print the cannot-start panel, exit 1, no card first.
    run N4-CLI 10 "$AITM" web; rc=$?
    if [ "$rc" != 0 ] && grep -q 'cannot start' "$OUT/N4-CLI.err" && ! grep -qE 'Web UI +http' "$OUT/N4-CLI.out"; then
      res N4-CLI PASS "$(clean "$OUT/N4-CLI.err" | grep -m1 'cannot start' | head -c 120); $(loader "$OUT/N4-CLI.out") loader lines on stdout first" "" "log noise: PR #271"
    else
      res N4-CLI FAIL "exit $rc; stderr: $(clean "$OUT/N4-CLI.err" | grep -m1 -iE 'cannot start|in use|rror' | head -c 160); card printed? $(grep -cE 'Web UI +http' "$OUT/N4-CLI.out")"
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
fi

echo; echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP  outputs in $OUT"
[ "$FAIL" -gt 0 ] && exit 1
[ "$SKIP" -gt 0 ] && exit 77
exit 0
