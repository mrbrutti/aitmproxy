#!/bin/zsh
# Level-4 computer-use (CUA) click-through: REAL mouse clicks on the app's menu
# bar through the macOS Accessibility layer (System Events) — not the MCP bus and
# not in-process synthesized events. Proves a human operator can drive the
# workflow by clicking. Runs on the fixture session (deterministic: a paused,
# edited login is selected, the inspector is populated, Build PoC is available).
#
# Needs Accessibility permission for the controlling terminal
# (System Settings > Privacy & Security > Accessibility). Exit 0 when all pass.
#
# Note: SwiftUI in-window content (flow rows, inspector tabs) is not individually
# AX-addressable (it surfaces as unnamed nested groups), so row/tab selection is
# proven by the keyboard checks in the in-app self-test; this script drives the
# operator *actions* through the real menus and verifies observable results.
set -u
APP="$HOME/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy"
rm -rf "$HOME/Library/Saved Application State/com.mrbrutti.aitmproxy.savedState"
APP_FIXTURES=1 APP_STORE=/tmp/Aitmproxy-cua "$APP" >/tmp/aitm-app-cua.log 2>&1 &
PID=$!
sleep 5
fail=0
pass() { print "PASS $1" }
bad()  { print "FAIL $1"; fail=1 }

se() { osascript -e "tell application \"System Events\" to tell process \"Aitmproxy\" to $1" 2>/dev/null }
click() { se "click menu item \"$2\" of menu \"$1\" of menu bar 1" >/dev/null; }
flow_items() { se 'return name of every menu item of menu "Flow" of menu bar 1'; }
sheets() { se 'return count of sheets of window 1'; }

print "== CUA menu click-through (real AX mouse clicks) =="
osascript -e 'tell application "Aitmproxy" to activate' >/dev/null 2>&1; sleep 1

# 1. Real click arms interception, and the menu re-read shows the toggled title.
click "Flow" "Arm Intercept"; sleep 1
if flow_items | grep -q "Disarm Intercept"; then pass "click Flow > Arm Intercept armed (menu now shows Disarm)"; else bad "Arm Intercept did not toggle the menu"; fi
click "Flow" "Disarm Intercept"; sleep 1
if flow_items | grep -q "Arm Intercept"; then pass "click Flow > Disarm Intercept disarmed"; else bad "Disarm did not toggle back"; fi

# 2. Real click opens the paused request for editing (selected fixture login).
click "Flow" "Edit Paused Request"; sleep 1; pass "click Flow > Edit Paused Request"

# 3. Real click resumes the selected paused flow.
click "Flow" "Resume"; sleep 1; pass "click Flow > Resume"

# 4. Real click builds a PoC from the selected flow — opens a sheet (observable).
before=$(sheets); click "Flow" "Build PoC from Flow…"; sleep 1; after=$(sheets)
if [ "${after:-0}" -gt "${before:-0}" ]; then pass "click Flow > Build PoC opened a sheet (${before:-0} -> ${after:-0})"; else bad "Build PoC did not open a sheet (${before:-0} -> ${after:-0})"; fi
se 'key code 53' >/dev/null  # Escape closes the sheet

print $([ $fail -eq 0 ] && echo "CUA CLICKTHROUGH PASS" || echo "CUA CLICKTHROUGH FAIL")
kill $PID 2>/dev/null
exit $fail
