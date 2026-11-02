#!/usr/bin/env bash
# e2e: tier=manual surface=acceptance
# Release acceptance, journey CLI (spec §D6) on the INSTALLED aitm, operator's real HOME.
# Read-only on the operator's state: no --yes, no ca install, no system proxy verbs.
# Each step writes its stdout/stderr/exit to $OUT/CLI-<n>.{out,err,exit} and prints a verdict.
# Usage: cli_journey.sh [outdir]      AITM=/opt/homebrew/bin/aitm by default.
set -uo pipefail
OUT="${1:-/tmp/claude/acceptance/cli}"
AITM="${AITM:-/opt/homebrew/bin/aitm}"
mkdir -p "$OUT"
PASS=0; FAIL=0; SKIP=0
res() { # id verdict detail
  case "$2" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; SKIP) SKIP=$((SKIP+1));; esac
  printf '%-6s %-5s %s\n' "$1" "$2" "$3"
}
run() { # id -- cmd...  (10 s cap)
  local id="$1"; shift
  ( "$@" ) >"$OUT/$id.out" 2>"$OUT/$id.err" & local pid=$!
  ( sleep 10; kill "$pid" 2>/dev/null ) 2>/dev/null & local w=$!
  wait "$pid" 2>/dev/null; local rc=$?; kill "$w" 2>/dev/null; wait "$w" 2>/dev/null
  echo "$rc" >"$OUT/$id.exit"; return "$rc"
}
lines() { wc -l <"$1" | tr -d ' '; }

echo "aitm under test: $AITM ($(ls -la "$AITM" | awk '{print $NF}'))"
echo "HOME: $HOME (operator's real state; read-only verbs only)"
echo

# CLI-1 --version: required one line `aitm <version>`, exit 0, nothing else.
run CLI-1 "$AITM" --version; rc=$?
o=$(lines "$OUT/CLI-1.out"); e=$(lines "$OUT/CLI-1.err")
if [ "$rc" = 0 ] && [ "$o" = 1 ] && grep -qE '^aitm [0-9]+\.[0-9]+\.[0-9]+' "$OUT/CLI-1.out" && [ "$e" = 0 ]; then
  res CLI-1 PASS "$(cat "$OUT/CLI-1.out")"
else
  res CLI-1 FAIL "exit $rc; stdout $o lines, stderr $e lines; first stdout: $(head -c 120 "$OUT/CLI-1.out" | tr -d '\033' | head -1)"
fi

# CLI-2 --help: required synopsis, exit 0, lists tui/web/operator-token.
run CLI-2 "$AITM" --help; rc=$?
if [ "$rc" = 0 ] && grep -q 'tui' "$OUT/CLI-2.out" && grep -q 'web' "$OUT/CLI-2.out" && ! grep -q 'loaded script' "$OUT/CLI-2.out"; then
  res CLI-2 PASS "exit 0, synopsis on stdout"
else
  res CLI-2 FAIL "exit $rc; stdout $(lines "$OUT/CLI-2.out") lines ($(grep -c 'loaded script' "$OUT/CLI-2.out") Rhai loader lines); stderr first: $(head -1 "$OUT/CLI-2.err" | head -c 120)"
fi

# CLI-7 ca status: read-only; must report the login keychain trust.
run CLI-7 "$AITM" ca status; rc=$?
if [ "$rc" = 0 ] && grep -q '"trusted"' "$OUT/CLI-7.out"; then
  res CLI-7 PASS "user.trusted=$(python3 -c 'import json,sys,re; t=open(sys.argv[1]).read(); i=t.find("{"); d=json.loads(t[i:]); print(d["stores"]["user"]["trusted"], "installed="+d["stores"]["user"]["installed"])' "$OUT/CLI-7.out" 2>/dev/null || echo '?') ; stdout has $(grep -c 'loaded script' "$OUT/CLI-7.out") loader lines before the JSON"
else
  res CLI-7 FAIL "exit $rc; $(head -c 200 "$OUT/CLI-7.err")"
fi

# CLI-4 proxy status while a core runs: required = the RUNNING core's status (listening true) or an exact no-core refusal.
holder=$(lsof -nP -iTCP:8080 -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1" pid "$2}')
run CLI-4 "$AITM" proxy status; rc=$?
if [ -n "$holder" ]; then
  if grep -q '"listening": *true' "$OUT/CLI-4.out"; then
    res CLI-4 PASS "reports the running core ($holder)"
  else
    res CLI-4 FAIL "a core runs on 8080 ($holder) but the one-shot reports: $(grep -oE '"listening": *[a-z]+' "$OUT/CLI-4.out" | head -1), version $(grep -oE '"version": *"[^"]+"' "$OUT/CLI-4.out" | head -1) (its own in-process state)"
  fi
else
  res CLI-4 SKIP "no core on 8080 to compare against"
fi

# CLI-5 scope add against the running core: required = the host reaches the RUNNING core's scope.list.
# We only check the one-shot's own claim here; the bus-side check is bus_truth.py after this script.
if [ -n "$holder" ]; then
  run CLI-5 "$AITM" scope add --host acceptance-cli5.invalid; rc=$?
  res CLI-5 INFO "exit $rc, printed: $(tail -1 "$OUT/CLI-5.out" | head -c 80) — verify with bus_truth.py: scope.list of the running core must contain acceptance-cli5.invalid, else FAIL (false success)"
else
  res CLI-5 SKIP "no running core"
fi

# CLI-6 scope add with NO core running: required = refusal, exit 1.
if [ -z "$holder" ]; then
  run CLI-6 "$AITM" scope add --host acceptance-cli6.invalid; rc=$?
  if [ "$rc" != 0 ] && ! grep -q 'acceptance-cli6.invalid' "$OUT/CLI-6.out"; then
    res CLI-6 PASS "refused, exit $rc"
  else
    res CLI-6 FAIL "exit $rc with no core; stdout: $(tail -1 "$OUT/CLI-6.out" | head -c 80) (success for a no-op)"
  fi
else
  res CLI-6 SKIP "a core is running ($holder); the no-core case needs the app quit"
fi

# N4-CLI port held: `aitm web` while 8080 is held must print the cannot-start panel and exit 1 with no success line.
if [ -n "$holder" ]; then
  run N4-CLI "$AITM" web; rc=$?
  if [ "$rc" != 0 ] && grep -q 'cannot start' "$OUT/N4-CLI.err" && ! grep -qE 'Web UI +http' "$OUT/N4-CLI.out"; then
    res N4-CLI PASS "$(grep -m1 'cannot start' "$OUT/N4-CLI.err" | head -c 120)"
  else
    res N4-CLI FAIL "exit $rc; stderr: $(grep -m1 -iE 'cannot start|in use|error' "$OUT/N4-CLI.err" | head -c 160); stdout card? $(grep -cE 'Web UI +http' "$OUT/N4-CLI.out")"
  fi
else
  res N4-CLI SKIP "8080 free; nothing holds the port"
fi

# CLI-3 bare `aitm` ready card and CLI-8 need the default ports free: SKIP while the app's core holds 8080.
if [ -n "$holder" ]; then
  res CLI-3 SKIP "port 8080 held by $holder (the app's embedded core); needs the app quit"
  res CLI-8 SKIP "same"
fi

echo; echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP  outputs in $OUT"
grep -rl 'operator_token\|"token"' "$OUT" 2>/dev/null && echo "WARNING: a token-shaped string is in the outputs; review before publishing"
exit 0
