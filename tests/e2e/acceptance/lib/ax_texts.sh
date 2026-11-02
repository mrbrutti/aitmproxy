#!/usr/bin/env bash
# Read every static text, button title and menu-item title the INSTALLED Aitmproxy app's main
# window exposes through accessibility, one per line. Read-only; no click, no keystroke.
# Usage: ax_texts.sh            (window 1 of the Aitmproxy process)
#        ax_texts.sh menu Proxy (the titles of one menu, with enabled state)
set -euo pipefail
pgrep -f 'Aitmproxy.app/Contents/MacOS/Aitmproxy' >/dev/null || { echo "refused: Aitmproxy is not running" >&2; exit 3; }
if [ "${1:-}" = menu ]; then
  osascript - "$2" <<'APPLESCRIPT'
on run argv
  set menuName to item 1 of argv
  set out to {}
  tell application "System Events" to tell process "Aitmproxy"
    repeat with mi in menu items of menu menuName of menu bar item menuName of menu bar 1
      try
        set end of out to (name of mi) & " [enabled=" & (enabled of mi) & "]"
      end try
    end repeat
  end tell
  set text item delimiters to linefeed
  return out as text
end run
APPLESCRIPT
  exit 0
fi
osascript <<'APPLESCRIPT'
set out to {}
tell application "System Events" to tell process "Aitmproxy"
  set w to window 1
  set els to entire contents of w
  repeat with e in els
    try
      set r to role of e
      if r is "AXStaticText" or r is "AXButton" or r is "AXCheckBox" or r is "AXTextField" or r is "AXPopUpButton" then
        set v to ""
        try
          set v to value of e as text
        end try
        set t to ""
        try
          set t to title of e as text
        end try
        set d to ""
        try
          set d to description of e as text
        end try
        set rowText to r & "	" & t & "	" & v & "	" & d
        set end of out to rowText
      end if
    end try
  end repeat
end tell
set text item delimiters to linefeed
return out as text
APPLESCRIPT
