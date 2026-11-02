#!/usr/bin/env bash
# Click a text field of the INSTALLED Aitmproxy app by locating it through accessibility right
# before EACH click (no stale coordinates): the field is found by its accessibility identifier when
# given (and its description must match too), else by its description; the click goes to the
# centre of the frame read a moment earlier, and the second click (0.9 s later: an inactive window
# swallows the first) re-reads the frame and refuses if the field moved or went away. The app is
# brought to the front first. Same refusals as the other drivers (no window, app not running, a
# dev bundle present). Prints `clicked x,y` on success.
# Usage: click.sh "<description>" ["<accessibility identifier>"]
set -euo pipefail
desc="${1:-}"; ident="${2:-}"
[ -n "$desc" ] || { echo "usage: click.sh \"<description>\" [\"<identifier>\"]" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
e2e="$(cd "$here/../.." && pwd)"
pgrep -f '^/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy' >/dev/null || { echo "refused: the installed Aitmproxy is not running" >&2; exit 3; }
[ "$(pgrep -f 'Aitmproxy.app/Contents/MacOS/Aitmproxy' | wc -l | tr -d ' ')" = 1 ] || { echo "refused: more than one Aitmproxy process (a dev bundle is running); the wrong app could be clicked" >&2; exit 3; }
[ "${ACCEPT_WINDOW:-0}" = 1 ] || { echo "refused: ACCEPT_WINDOW=1 (the orchestrator's display-lock window) is not set" >&2; exit 3; }

centre() { # prints "x y" of the field's centre from a fresh AX dump, or nothing
  bash "$here/ax_texts.sh" 2>/dev/null | python3 -c '
import sys
sys.path.insert(0, sys.argv[1])
from aitm_e2e.installed import field_center
c = field_center(sys.stdin.read(), sys.argv[2], sys.argv[3] or None)
print(f"{c[0]} {c[1]}" if c else "")
' "$e2e" "$desc" "$ident"
}
click_at() { osascript - "$1" "$2" <<'APPLESCRIPT'
on run argv
  set x to (item 1 of argv) as integer
  set y to (item 2 of argv) as integer
  tell application "System Events" to tell process "Aitmproxy"
    set frontmost to true
    delay 0.3
    click at {x, y}
  end tell
end run
APPLESCRIPT
}
p1="$(centre)"; [ -n "$p1" ] || { echo "refused: field '$desc' not found with a real frame" >&2; exit 4; }
set -- $p1; x1="$1"; y1="$2"
click_at "$x1" "$y1"
sleep 0.9
p2="$(centre)"; [ -n "$p2" ] || { echo "refused: field '$desc' gone after the first click; no second click" >&2; exit 4; }
set -- $p2; x2="$1"; y2="$2"
dx=$(( x1 > x2 ? x1 - x2 : x2 - x1 )); dy=$(( y1 > y2 ? y1 - y2 : y2 - y1 ))
[ "$dx" -le 4 ] && [ "$dy" -le 4 ] || { echo "refused: field '$desc' moved ($x1,$y1 -> $x2,$y2); no second click" >&2; exit 4; }
click_at "$x2" "$y2"
echo "clicked $x2,$y2"
