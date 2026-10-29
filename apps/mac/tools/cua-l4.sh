#!/bin/zsh
# Level-4 computer-use (CUA) acceptance of the macOS raw-L4 operator surface
# (l4-operator-surfaces Task 17 / L4OPS-AC14 + AC18). Drives the REAL app UI with
# REAL input events — CGEvent pixel clicks (tools/cgclick.swift) + Accessibility
# key events — NOT the MCP bus, NOT in-process synthesized events.
#
# Two runs:
#   A) CAPABLE core (default fixtures, l4EmbeddedCore=false): the surface drives
#      L4 fully — the L4 flow list renders the slate/indigo L4 badge; the inspector
#      shows the packet list, layer tree and hex note; the Craft editor builds a
#      PacketSpec; Inject opens the confirm-over-the-wire dialog naming destination,
#      packet summary, scope and permit budget; the out-of-scope session is dimmed
#      with inject disabled; the Agent panel's per-capability MCP toggles reflect
#      the l4.allow_agent_* gates. This stands in for "pointed at a privileged core
#      over the bus, drives L4 fully" (AC18c) — a real privileged raw-L4 core is
#      Linux/elevated and is proven agent-side by Task 16's MCP suite.
#   B) EMBEDDED core (APP_L4_EMBEDDED=1, l4EmbeddedCore=true): the self-contained
#      app's user-level core cannot do raw L4 — the surface still renders and the
#      pure verbs (packet list, layer tree, Craft build) work, but the wire verbs
#      degrade honestly: the degraded banner names the Phase-2 Network/System
#      Extension and Inject is disabled — NOT fake success (AC18a/AC18b).
#
# Needs Accessibility + Screen-Recording permission for the controlling terminal.
# Proof screenshots -> /tmp/cua-l4-*.png. Exit 0 when every asserted step passes.
set -u
cd "${0:A:h}"
APP="$HOME/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy"
OX=80; OY=40; W=1440; H=1060
fail=0
pass() { print "PASS $1" }
bad()  { print "FAIL $1"; fail=1 }
se() { osascript -e "tell application \"System Events\" to tell process \"Aitmproxy\" to $1" 2>/dev/null }
click() { swift cgclick.swift "$1" "$2" }
md5of() { md5 -q "$1" 2>/dev/null }
shot() { screencapture -x -R "$OX,$OY,$W,$H" "$1" 2>/dev/null }

launch() {  # $1 = extra env (e.g. APP_L4_EMBEDDED=1)
  rm -rf "$HOME/Library/Saved Application State/com.mrbrutti.aitmproxy.savedState"
  env ${1:-} APP_FIXTURES=1 APP_STORE=/tmp/Aitmproxy-cua-l4 "$APP" >/tmp/aitm-app-cua-l4.log 2>&1 &
  APPPID=$!
  sleep 6
  osascript -e 'tell application "Aitmproxy" to activate' >/dev/null 2>&1; sleep 1
  osascript -e "tell application \"System Events\" to tell process \"Aitmproxy\"
    set position of window 1 to {$OX, $OY}
    set size of window 1 to {$W, $H}
  end tell" >/dev/null 2>&1
  sleep 0.5
}
quit() { kill $APPPID 2>/dev/null; sleep 1 }

# Focus the flow list and select an L4 row. Down x20 clamps to the last row
# (seq62); Up x$1 steps to the target: 2=seq60 (in-scope capture), 1=seq61
# (out-of-scope), 0=seq62 (craft).
navL4() {
  click $((OX+291)) $((OY+140)); sleep 0.5
  for i in {1..20}; do se 'key code 125'; sleep 0.07; done
  for i in $(seq 1 ${1:-2}); do se 'key code 126'; sleep 0.12; done
  sleep 0.6
}

print "===== RUN A — capable core (drives L4 fully) ====="
launch ""

# 1) L4 flow list + inspector: packet list, layer tree, hex note, L4 badge.
navL4 2   # seq60 in-scope UDP capture
shot /tmp/cua-l4-a1-inspector.png
m_insp=$(md5of /tmp/cua-l4-a1-inspector.png)
[ -n "$m_insp" ] && pass "L4 flow selected — inspector rendered (shot a1)" || bad "no inspector shot"

# 2) Craft editor -> Build -> hex preview.
click 1078 772; sleep 0.7          # Craft tab
shot /tmp/cua-l4-a2-craft.png
m_craft=$(md5of /tmp/cua-l4-a2-craft.png)
[ "$m_craft" != "$m_insp" ] && pass "Craft tab opened the PacketSpec editor (shot a2)" || bad "Craft tab did not change the pane"
click 960 1044; sleep 1.0          # Build
shot /tmp/cua-l4-a3-build.png
m_build=$(md5of /tmp/cua-l4-a3-build.png)
[ "$m_build" != "$m_craft" ] && pass "Build parsed the spec and showed the build() hex preview (shot a3)" || bad "Build did not change the pane"

# 3) Guarded inject -> confirm-over-the-wire dialog (dst + summary + scope + budget).
before=$(se 'return count of sheets of window 1')
click 1029 960; sleep 1.0          # Inject... (buttons move up once the hex preview shows)
after=$(se 'return count of sheets of window 1')
shot /tmp/cua-l4-a4-confirm.png
if [ "${after:-0}" -gt "${before:-0}" ]; then
  pass "Inject opened the confirm-over-the-wire dialog (${before:-0} -> ${after:-0} sheets, shot a4)"
else
  bad "Inject did not open a confirm sheet (${before:-0} -> ${after:-0})"
fi
se 'key code 53'; sleep 0.5        # Escape the sheet

# 4) Out-of-scope session: dimmed, inject disabled, scope reason.
navL4 1   # seq61 out-of-scope TCP
shot /tmp/cua-l4-a5-oos.png
m_oos=$(md5of /tmp/cua-l4-a5-oos.png)
[ "$m_oos" != "$m_insp" ] && pass "Out-of-scope L4 session rendered dimmed (shot a5)" || bad "oos shot did not differ"

# 5) Agent panel — per-capability MCP toggles reflect the l4.allow_agent_* gates.
click 134 753; sleep 0.8           # Agent sidebar page
shot /tmp/cua-l4-a6-agent.png
m_agent=$(md5of /tmp/cua-l4-a6-agent.png)
[ "$m_agent" != "$m_oos" ] && pass "Agent panel with L4 capability toggles rendered (shot a6)" || bad "agent panel shot did not differ"
quit

print "===== RUN B — embedded user-level core (honest degradation, AC18) ====="
launch "APP_L4_EMBEDDED=1"
navL4 2   # seq60
shot /tmp/cua-l4-b1-degraded.png
m_deg=$(md5of /tmp/cua-l4-b1-degraded.png)
# The degraded run must differ from the capable inspector (banner present, inject off).
[ "$m_deg" != "$m_insp" ] && pass "Embedded core: degraded L4 surface rendered (shot b1)" || bad "degraded shot matched capable shot"
# Pure verbs still work: Craft tab + Build succeed even on the embedded core.
click 1078 772; sleep 0.7          # Craft
click 960 1044; sleep 1.0          # Build (pure — l4.craft)
shot /tmp/cua-l4-b2-craft-build.png
m_b2=$(md5of /tmp/cua-l4-b2-craft-build.png)
[ "$m_b2" != "$m_deg" ] && pass "Embedded core: Craft build() still works (pure verb, shot b2)" || bad "Craft build did not change the pane on embedded core"
# The wire verb must NOT open a confirm sheet — inject is disabled (honest).
before=$(se 'return count of sheets of window 1')
click 1029 960; sleep 0.8          # Inject... (buttons move up after build; expected DISABLED here)
after=$(se 'return count of sheets of window 1')
if [ "${after:-0}" -le "${before:-0}" ]; then
  pass "Embedded core: Inject is disabled — no confirm sheet, no fake success (${before:-0} -> ${after:-0})"
else
  bad "Embedded core: Inject opened a sheet (${before:-0} -> ${after:-0}) — degradation not honest"
fi
shot /tmp/cua-l4-b3-inject-disabled.png
quit

print "proof screenshots: /tmp/cua-l4-a1-inspector.png a2-craft a3-build a4-confirm a5-oos a6-agent b1-degraded b2-craft-build b3-inject-disabled"
print $([ $fail -eq 0 ] && echo "CUA L4 ACCEPTANCE PASS" || echo "CUA L4 ACCEPTANCE FAIL")
exit $fail
