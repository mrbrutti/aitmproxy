#!/usr/bin/env bash
# Press one accessibility button of the INSTALLED Aitmproxy app's main window by its label (the
# title or the accessibility description), after bringing the app to the front. Used for the
# controls that are not menu items: the Scope page's "Remove <host> from Scope" and the sidebar's
# "Apps" entry. Refuses when the app is not running, when a dev bundle also runs, or outside the
# orchestrator's display-lock window (ACCEPT_WINDOW=1). Prints `pressed <label>` or exits 4 when
# no such button exists (nothing is pressed).
# Usage: ax_press.sh "<label>"
set -euo pipefail
label="${1:-}"
[ -n "$label" ] || { echo "usage: ax_press.sh \"<label>\"" >&2; exit 2; }
pgrep -f '^/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy' >/dev/null || { echo "refused: the installed Aitmproxy is not running" >&2; exit 3; }
[ "$(pgrep -f 'Aitmproxy.app/Contents/MacOS/Aitmproxy' | wc -l | tr -d ' ')" = 1 ] || { echo "refused: more than one Aitmproxy process (a dev bundle is running)" >&2; exit 3; }
[ "${ACCEPT_WINDOW:-0}" = 1 ] || { echo "refused: ACCEPT_WINDOW=1 (the orchestrator's display-lock window) is not set" >&2; exit 3; }
osascript - "$label" <<'APPLESCRIPT'
on run argv
  set wanted to item 1 of argv
  tell application "System Events" to tell process "Aitmproxy"
    set frontmost to true
    delay 0.3
    set els to entire contents of window 1
    repeat with e in els
      try
        if role of e is "AXButton" then
          set t to ""
          try
            set t to title of e as text
          end try
          set d to ""
          try
            set d to description of e as text
          end try
          if t is wanted or d is wanted then
            click e
            return "pressed " & wanted
          end if
        end if
      end try
    end repeat
  end tell
  error "no button titled or described \"" & wanted & "\"" number 4
end run
APPLESCRIPT
