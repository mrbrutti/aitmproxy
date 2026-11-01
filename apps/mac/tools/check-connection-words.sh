#!/usr/bin/env bash
# ST-AC5 + ST-AC10 tripwire (spec 2026-10-31-macos-status-page-and-first-run-design §4): the
# connection state — core, bus, capture extension — has ONE home, the toolbar's connection
# cluster, and every indicator that exists (that cluster, the Status page, the Core Log header,
# the Settings rows) draws its words from `ConnectionSummary`.
#
# Rule 1: no view in the APP target spells a lane word as a quoted literal. The Kit models that
#         define them (ConnectionSummary, CaptureAdvice, CaptureCapability) are outside the scan root.
#         The traffic-route words (spec 2026-10-31-mac-traffic-route-advice-design §D9, TR-AC7) join
#         it as opening-quote PREFIXES, because the route lines interpolate the address
#         ("system proxy on · 127.0.0.1:8080") and a whole-literal match would never see them.
# Rule 2: only the allow-listed files read `connectionSummary`; the sidebar and the status bar
#         (Matt, 2026-10-31: "status in the top AND the sidebar AND the status bar — pick one")
#         must not mention it, `LaneDot`, `LaneState` or `ConnectionSummary` at all.
# Rule 3: one route derivation (§D9, TR-AC7). `trafficRoutes` is defined exactly once, in
#         Session+Connection.swift, as `connectionSummary.routes`; the views (Shell/ShellView.swift,
#         Shell/RouteBanner.swift) read `trafficRoutes` and never `connectionSummary`.
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

# Rule 1, route words (spec §D9): an opening quote followed by a route line's head. Same scan root
# and the same exclusions as `words`; the Kit (TrafficRoutes in ConnectionSummary.swift) is outside it.
prefixes='"(system proxy off|system proxy on|All Apps on|All Apps off|All Apps waiting|All Apps degraded|Nothing is decrypted|Scope:|HTTPS is not captured|Trust the aitmproxy CA|CA trusted|trusting CA|CA trust needs)'
rhits=$(grep -rnE --include='*.swift' -e "$prefixes" Sources/Aitmproxy | grep -vE ':[0-9]+:[[:space:]]*///?' | grep -vE '^Sources/Aitmproxy/SelfTest(\+[A-Za-z]+)?\.swift:' | grep -vE ':[0-9]+:.*FilterRow\(\.[a-z]+,' ; echo "rc=${PIPESTATUS[0]}")
rrc=${rhits##*rc=}; rhits=${rhits%rc=*}
if [ "$rrc" -gt 1 ]; then
  echo "FAIL check-connection-words: grep could not read Sources/Aitmproxy for route words (exit $rrc)"
  status=1
fi
if [ -n "${rhits//[[:space:]]/}" ]; then
  printf '%s\n' "$rhits"
  echo "FAIL check-connection-words: a view spells a route word; read it from ConnectionSummary.routes instead"
  status=1
fi

# Rule 2: one home. Readers of connectionSummary, by file.
readers='^Sources/Aitmproxy/(Shell/ShellToolbar|Shell/SetupSheet|Panels/StatusPanel|Panels/CoreLogPanel|SettingsView|Session\+Connection)\.swift$'
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

# Rule 3: one route derivation. `trafficRoutes` is defined exactly once, in Session+Connection.swift,
# and that one line is `connectionSummary.routes`; a second definition (even an identical one) is a
# second place the predicate could drift. RouteBanner.swift reads trafficRoutes only, so it may not
# mention connectionSummary, ConnectionSummary, LaneDot or LaneState; a missing file is a FAIL, as
# rule 2 treats the sidebar.
defs=$(grep -rnE --include='*.swift' -e 'var[[:space:]]+trafficRoutes' Sources/Aitmproxy || true)
ndefs=$(printf '%s' "$defs" | grep -c . || true)
if [ "$ndefs" -ne 1 ]; then
  [ -n "$defs" ] && printf '%s\n' "$defs"
  echo "FAIL check-connection-words: trafficRoutes is defined $ndefs times; it is derived exactly once, in Session+Connection.swift"
  status=1
else
  case "$defs" in
    Sources/Aitmproxy/Session+Connection.swift:*) ;;
    *)
      printf '%s\n' "$defs"
      echo "FAIL check-connection-words: trafficRoutes is defined outside Session+Connection.swift"
      status=1 ;;
  esac
  if ! grep -q 'connectionSummary.routes' <<<"$defs"; then
    printf '%s\n' "$defs"
    echo "FAIL check-connection-words: trafficRoutes is not connectionSummary.routes; the routes have one derivation"
    status=1
  fi
fi
banner=Sources/Aitmproxy/Shell/RouteBanner.swift
if [ ! -f "$banner" ]; then
  echo "FAIL check-connection-words: $banner not found; update this script to the file that replaced it"
  status=1
else
  bad=$(grep -nHE -e 'connectionSummary|ConnectionSummary|LaneDot|LaneState' "$banner" || true)
  if [ -n "$bad" ]; then
    printf '%s\n' "$bad"
    echo "FAIL check-connection-words: $banner reads connection state directly; it reads session.trafficRoutes only"
    status=1
  fi
fi

[ "$status" -eq 0 ] && echo "PASS check-connection-words"
exit "$status"
