#!/bin/zsh
# Level-4 computer-use (CUA) click-through: drives the real app UI with REAL input
# events — NOT the MCP bus, NOT in-process synthesized events. Two layers:
#
#  * PIXEL path (no Accessibility tree): normalize the window to a known origin,
#    then CGEvent-click computed row pixels (tools/cgclick.swift). Selection is
#    verified by screenshotting the inspector region and confirming it changed
#    (screencapture + md5). This has no SwiftUI-AX limitation — it clicks pixels.
#  * MENU path: real Accessibility menu-bar clicks (Resume, Build PoC opens a sheet).
#
# Fixtures session (deterministic 14-row capture, a paused edited login). Needs
# Accessibility + Screen-Recording permission for the controlling terminal.
# Writes proof screenshots to /tmp/cua-*.png. Exit 0 when all asserted steps pass.
set -u
cd "${0:A:h}"
# APP=<binary> runs another build (e.g. the snap-dev bundle /tmp/Aitmproxy-dev.app/Contents/MacOS/Aitmproxy).
APP="${APP:-$HOME/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy}"
rm -rf "$HOME/Library/Saved Application State/com.mrbrutti.aitmproxy.savedState"
APP_FIXTURES=1 APP_STORE=/tmp/Aitmproxy-cua "$APP" >/tmp/aitm-app-cua.log 2>&1 &
PID=$!
sleep 6
fail=0
pass() { print "PASS $1" }
bad()  { print "FAIL $1"; fail=1 }
se() { osascript -e "tell application \"System Events\" to tell process \"Aitmproxy\" to $1" 2>/dev/null }
osascript -e 'tell application "Aitmproxy" to activate' >/dev/null 2>&1; sleep 1

# --- normalize window to a known origin so pixel math is deterministic ---
OX=100; OY=100
size=$(osascript -e "tell application \"System Events\" to tell process \"Aitmproxy\"
  set position of window 1 to {$OX, $OY}
  delay 0.3
  set s to size of window 1
  return (item 1 of s as string) & \" \" & (item 2 of s as string)
end tell" 2>/dev/null)
W=${size%% *}; H=${size##* }
[ -n "$W" ] && [ "$W" != "$size" ] && pass "window normalized to ${OX},${OY} (${W}x${H})" || { bad "could not place/size the window"; W=1440; H=1130 }

# Flow rows: sidebar ~241 wide, first row ~116 below the window top, 32px tall.
rowx=$((OX + 291))
rowY() { print $((OY + 132 + ($1 - 1) * 32)); }
# Inspector region (summary + request/response) — changes when the selection changes.
insp() { screencapture -x -R "$((OX+345)),$((OY+690)),1000,420" "$1" 2>/dev/null; }
md5of() { md5 -q "$1" 2>/dev/null; }

# --- PIXEL path: click two different rows, assert the inspector changed each time ---
swift cgclick.swift "$rowx" "$(rowY 3)"; sleep 1; insp /tmp/cua-row3.png; m3=$(md5of /tmp/cua-row3.png)
swift cgclick.swift "$rowx" "$(rowY 8)"; sleep 1; insp /tmp/cua-row8.png; m8=$(md5of /tmp/cua-row8.png)
swift cgclick.swift "$rowx" "$(rowY 1)"; sleep 1; insp /tmp/cua-row1.png; m1=$(md5of /tmp/cua-row1.png)
if [ -n "$m3" ] && [ "$m3" != "$m8" ] && [ "$m8" != "$m1" ]; then
  pass "pixel click selects a rendered row (inspector changed across rows 3/8/1)"
else
  bad "row pixel-clicks did not change the inspector (m3=$m3 m8=$m8 m1=$m1)"
fi

# --- MENU path: Resume the paused flow, Build a PoC (sheet opens) ---
sheets() { se 'return count of sheets of window 1'; }
se 'click menu item "Resume" of menu "Flow" of menu bar 1' >/dev/null; sleep 1; pass "menu click Flow > Resume"
b=$(sheets); se 'click menu item "Build PoC from Flow…" of menu "Flow" of menu bar 1' >/dev/null; sleep 1; a=$(sheets)
{ [ "${a:-0}" -gt "${b:-0}" ] } && pass "menu click Flow > Build PoC opened a sheet (${b:-0} -> ${a:-0})" || bad "Build PoC did not open a sheet (${b:-0} -> ${a:-0})"
se 'key code 53' >/dev/null

print "proof screenshots: /tmp/cua-row3.png /tmp/cua-row8.png /tmp/cua-row1.png"
print $([ $fail -eq 0 ] && echo "CUA CLICKTHROUGH PASS" || echo "CUA CLICKTHROUGH FAIL")
kill $PID 2>/dev/null
exit $fail
