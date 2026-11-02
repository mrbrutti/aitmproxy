#!/usr/bin/env bash
# Click the INSTALLED Aitmproxy app at screen coordinates (System Events `click at`, a synthesized
# mouse click), after bringing the app to the front. Two clicks 0.9 s apart: an inactive window
# swallows the first (the live-proof memory's NSTableView trap). Refuses without the window,
# when the app is not running, or when a dev bundle is also running (the wrong app could be hit).
# Usage: click.sh <x> <y>
set -euo pipefail
x="$1"; y="$2"
case "$x$y" in *[!0-9]*) echo "refused: coordinates must be integers" >&2; exit 2;; esac
pgrep -f '^/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy' >/dev/null || { echo "refused: the installed Aitmproxy is not running" >&2; exit 3; }
[ "$(pgrep -f 'Aitmproxy.app/Contents/MacOS/Aitmproxy' | wc -l | tr -d ' ')" = 1 ] || { echo "refused: more than one Aitmproxy process (a dev bundle is running)" >&2; exit 3; }
[ "${ACCEPT_WINDOW:-0}" = 1 ] || { echo "refused: ACCEPT_WINDOW=1 (the orchestrator's display-lock window) is not set" >&2; exit 3; }
osascript - "$x" "$y" <<'APPLESCRIPT'
on run argv
  set x to (item 1 of argv) as integer
  set y to (item 2 of argv) as integer
  tell application "System Events"
    tell process "Aitmproxy"
      set frontmost to true
      delay 0.4
      click at {x, y}
      delay 0.9
      click at {x, y}
    end tell
  end tell
  return "clicked " & x & "," & y
end run
APPLESCRIPT
