#!/usr/bin/env bash
# Press one menu item of the INSTALLED Aitmproxy app through System Events, after bringing the
# app to the front (keystrokes and menu presses otherwise land in whatever is frontmost).
# Usage: menu.sh "<Menu>" "<Item>"     e.g. menu.sh Proxy "Status"
# Refuses when the app is not running. Prints the item's enabled state before pressing.
set -euo pipefail
menu="$1"; item="$2"
pgrep -f '^/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy' >/dev/null || { echo "refused: the installed Aitmproxy is not running" >&2; exit 3; }
[ "$(pgrep -f 'Aitmproxy.app/Contents/MacOS/Aitmproxy' | wc -l | tr -d ' ')" = 1 ] || { echo "refused: more than one Aitmproxy process (a dev bundle is running); System Events would address the wrong app" >&2; exit 3; }
[ "${ACCEPT_WINDOW:-0}" = 1 ] || { echo "refused: ACCEPT_WINDOW=1 (the orchestrator's display-lock window) is not set" >&2; exit 3; }
osascript - "$menu" "$item" <<'APPLESCRIPT'
on run argv
  set menuName to item 1 of argv
  set itemName to item 2 of argv
  tell application "System Events"
    tell process "Aitmproxy"
      set frontmost to true
      delay 0.4
      set mi to menu item itemName of menu menuName of menu bar item menuName of menu bar 1
      set en to enabled of mi
      log "enabled=" & en
      if en then click mi
      return "pressed " & menuName & " > " & itemName & " (enabled=" & en & ")"
    end tell
  end tell
end run
APPLESCRIPT
