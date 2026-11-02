#!/usr/bin/env bash
# Read every static text, button title and menu-item title the INSTALLED Aitmproxy app's main
# window exposes through accessibility, one per line. Read-only; no click, no keystroke.
# Usage: ax_texts.sh            (window 1 of the Aitmproxy process; rows are role, title, value,
#                                 description, and for text fields also identifier, position x,y, size w,h)
#        ax_texts.sh menu Proxy (the titles of one menu, with enabled state)
#        ax_texts.sh bounds     (window 1 as `x,y,w,h` for `screencapture -R`)
set -euo pipefail
pgrep -f '^/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy' >/dev/null || { echo "refused: the installed Aitmproxy is not running" >&2; exit 3; }
[ "$(pgrep -f 'Aitmproxy.app/Contents/MacOS/Aitmproxy' | wc -l | tr -d ' ')" = 1 ] || { echo "refused: more than one Aitmproxy process (a dev bundle is running)" >&2; exit 3; }
if [ "${1:-}" = bounds ]; then
  osascript -e 'tell application "System Events" to tell process "Aitmproxy" to get {position, size} of window 1' | tr -d ' '
  exit 0
fi
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
# Fast path (2026-11-02): the AXUIElement walk in ax_texts.swift — the AppleScript walk below costs one
# Apple Event per attribute and took 49.7 s for 142 rows on an idle 0.5.15, past the cells' 30 s
# budget even with the app fully idle. Built once per source change into a cache dir; falls back to
# the AppleScript walk when swiftc is missing or the build fails. Same rows, same column order.
here=$(cd "$(dirname "$0")" && pwd)
cache=${AX_TEXTS_CACHE:-/tmp/claude/acceptance/ax-cache}
bin="$cache/ax_texts-$(shasum -a 256 "$here/ax_texts.swift" | cut -c1-12)"
if [ ! -x "$bin" ]; then
  if ! command -v swiftc >/dev/null 2>&1; then
    echo "ax_texts.sh: swiftc not found, using the slow AppleScript walk" >&2
  elif [ ! -e "$cache/build-failed-$(basename "$bin")" ]; then
    # build to a temp name and move into place, so a concurrent caller never execs a half-linked binary
    mkdir -p "$cache"
    if swiftc -O -o "$bin.$$.tmp" "$here/ax_texts.swift" 2>"$cache/build.log"; then
      mv -f "$bin.$$.tmp" "$bin"
    else
      rm -f "$bin.$$.tmp"; touch "$cache/build-failed-$(basename "$bin")"
      echo "ax_texts.sh: ax_texts.swift failed to build (see $cache/build.log), using the slow AppleScript walk" >&2
    fi
  else
    echo "ax_texts.sh: ax_texts.swift failed to build earlier (see $cache/build.log), using the slow AppleScript walk" >&2
  fi
fi
[ -x "$bin" ] && exec "$bin"
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
        if r is "AXTextField" then
          -- three more columns for text fields only: accessibility identifier, position, size
          -- (the harness clicks a field's centre before typing into it)
          set ident to ""
          try
            set ident to (value of attribute "AXIdentifier" of e) as text
          end try
          set p to {0, 0}
          set z to {0, 0}
          try
            set p to position of e
            set z to size of e
          end try
          set rowText to rowText & "	" & ident & "	" & (item 1 of p as text) & "," & (item 2 of p as text) & "	" & (item 1 of z as text) & "," & (item 2 of z as text)
        end if
        set end of out to rowText
      end if
    end try
  end repeat
end tell
set text item delimiters to linefeed
return out as text
APPLESCRIPT
