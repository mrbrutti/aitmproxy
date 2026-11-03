#!/usr/bin/env bash
# Type text into the INSTALLED Aitmproxy app's focused field (spec D9 "pbcopy+⌘V for text the
# keyboard cannot type"): bring the app to the front, put the text on the pasteboard, paste with
# ⌘V through System Events, then press Return. The operator's pasteboard is saved first (pbpaste:
# its PLAIN-TEXT representation only — an image, a file reference or rich text on the pasteboard
# comes back as plain text or empty) and put back afterwards.
#
# Usage: type.sh "<text>"              paste <text>, then Return
#        type.sh --no-return "<text>"  paste <text> WITHOUT Return (the focus probe after a core
#                                      restart was not seen: nothing is submitted into an
#                                      unknown target; the text stays in whatever field has focus)
#        type.sh --probe               keystroke a single "1" (focus probe; no Return) — read it
#                                      back with ax_texts.sh, then clear it with --clear
#        type.sh --clear               ⌘A then Delete in the focused field
#        type.sh --escape              one Escape (closes an attached sheet; an attached sheet makes
#                                      AppKit refuse the app's quit — -128 "User canceled")
# Refuses when the app is not running, when more than one Aitmproxy process exists (a dev bundle),
# or when ACCEPT_WINDOW=1 (the orchestrator's display-lock window) is not set.
set -euo pipefail
mode="${1:-}"
with_return=1
if [ "$mode" = --no-return ]; then with_return=0; mode="${2:-}"; fi
[ -n "$mode" ] || { echo "usage: type.sh \"<text>\" | --no-return \"<text>\" | --probe | --clear | --escape" >&2; exit 2; }
pgrep -f '^/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy' >/dev/null || { echo "refused: the installed Aitmproxy is not running" >&2; exit 3; }
[ "$(pgrep -f 'Aitmproxy.app/Contents/MacOS/Aitmproxy' | wc -l | tr -d ' ')" = 1 ] || { echo "refused: more than one Aitmproxy process (a dev bundle is running)" >&2; exit 3; }
[ "${ACCEPT_WINDOW:-0}" = 1 ] || { echo "refused: ACCEPT_WINDOW=1 (the orchestrator's display-lock window) is not set" >&2; exit 3; }

front() {
  osascript -e 'tell application "System Events" to tell process "Aitmproxy" to set frontmost to true' >/dev/null
  sleep 0.3
}

case "$mode" in
  --probe)
    front
    osascript -e 'tell application "System Events" to keystroke "1"'
    echo "probed: typed 1"
    ;;
  --clear)
    front
    osascript -e 'tell application "System Events" to keystroke "a" using command down' -e 'tell application "System Events" to key code 51'
    echo "cleared the field"
    ;;
  --escape)
    front
    osascript -e 'tell application "System Events" to key code 53'
    echo "pressed Escape"
    ;;
  *)
    saved="$(pbpaste 2>/dev/null || true)"
    front
    printf '%s' "$mode" | pbcopy
    osascript -e 'tell application "System Events" to keystroke "v" using command down'
    sleep 0.15
    if [ "$with_return" = 1 ]; then
      osascript -e 'tell application "System Events" to keystroke return'
    fi
    printf '%s' "$saved" | pbcopy
    if [ "$with_return" = 1 ]; then echo "typed ${#mode} chars + Return (pasteboard restored as plain text)"; else echo "typed ${#mode} chars, NO Return (pasteboard restored as plain text)"; fi
    ;;
esac
