#!/usr/bin/env bash
# ST-AC5 + ST-AC10 tripwire (spec 2026-10-31-macos-status-page-and-first-run-design §4): the
# connection state — core, bus, capture extension — has ONE home, the toolbar's connection
# cluster, and every indicator that exists (that cluster, the Status page, the Core Log header,
# the Settings rows) draws its words from `ConnectionSummary`.
#
# Rule 1: no view in the APP target spells a lane word as a quoted literal. The Kit models that
#         define them (ConnectionSummary, CaptureAdvice, CaptureCapability) are outside the scan root.
# Rule 2: only the allow-listed files read `connectionSummary`; the sidebar and the status bar
#         (Matt, 2026-10-31: "status in the top AND the sidebar AND the status bar — pick one")
#         must not mention it, `LaneDot`, `LaneState` or `ConnectionSummary` at all.
# Exit 0 + PASS on a clean tree; exit 1 listing each offence otherwise.
set -u
set -o pipefail
export LC_ALL=C
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
status=0

words='"(running|not running|starting…|restarting…|stopped|failed|external|connected|connecting…|offline|bus failed|capture on|capture off|capture degraded|extension on|extension off|extension degraded|all apps on|all apps off|all apps degraded|waiting for approval|on, nothing in scope|no extension|Capturing|Approved|Awaiting approval|core running|core failed)"'
# Skipped: comments, the self-test (it ASSERTS the words), and filter values (`FilterRow(.state, …, "failed")`
# is a flow-state query, not a connection word).
hits=$(grep -rnE --include='*.swift' -e "$words" Sources/Aitmproxy | grep -vE ':[0-9]+:[[:space:]]*///?' | grep -vE '^Sources/Aitmproxy/SelfTest(\+[A-Za-z]+)?\.swift:' | grep -vE ':[0-9]+:.*FilterRow\(\.[a-z]+,' ; echo "rc=${PIPESTATUS[0]}")
rc=${hits##*rc=}; hits=${hits%rc=*}
if [ "$rc" -gt 1 ]; then
  echo "FAIL check-connection-words: grep could not read Sources/Aitmproxy (exit $rc)"
  status=1
fi
if [ -n "${hits//[[:space:]]/}" ]; then
  printf '%s\n' "$hits"
  echo "FAIL check-connection-words: a view spells a connection state word; read it from ConnectionSummary instead"
  status=1
fi

# Rule 2: one home. Readers of connectionSummary, by file.
readers='^Sources/Aitmproxy/(Shell/ShellToolbar|Panels/StatusPanel|Panels/CoreLogPanel|SettingsView|Session\+Connection|SelfTest|SnapshotScenes)\.swift$'
others=$(grep -rlE --include='*.swift' -e 'connectionSummary' Sources/Aitmproxy | grep -vE "$readers" || true)
if [ -n "$others" ]; then
  printf '%s\n' "$others"
  echo "FAIL check-connection-words: a file outside the allow-list reads connectionSummary; the toolbar cluster is the one indicator"
  status=1
fi
for f in Sources/Aitmproxy/Shell/SidebarView.swift Sources/Aitmproxy/Shell/StatusBar.swift; do
  # A missing file is not a passing file: if it moved, the rule must move with it.
  if [ ! -f "$f" ]; then
    echo "FAIL check-connection-words: $f not found; update this script to the file that replaced it"
    status=1
    continue
  fi
  bad=$(grep -nHE -e 'connectionSummary|LaneDot|LaneState|ConnectionSummary' "$f" || true)
  if [ -n "$bad" ]; then
    printf '%s\n' "$bad"
    echo "FAIL check-connection-words: $f carries connection state; it belongs to the toolbar only"
    status=1
  fi
done
# The allow-list must stay honest: the cluster really is the indicator.
if ! grep -q 'connectionSummary' Sources/Aitmproxy/Shell/ShellToolbar.swift; then
  echo "FAIL check-connection-words: Shell/ShellToolbar.swift no longer reads connectionSummary — where did the indicator go?"
  status=1
fi

[ "$status" -eq 0 ] && echo "PASS check-connection-words"
exit "$status"
