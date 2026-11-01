#!/bin/zsh
# Real-input drive of the INSTALLED app's capture extension + scope path (computer use, not the
# bus): open Settings ▸ Capture and shoot it, add a host to Scope through the sheet, browse that
# host in Safari (no proxy settings: only the system extension can see it), and shoot the main
# window so the capture state, the Scope banner and the flow list can be read off real pixels.
# Usage: tools/cua-ne-drive.sh <app pid> [host]        shots → /tmp/aitm-ne-*.png
set -u
cd "${0:A:h}"
pid=${1:?app pid}
host=${2:-example.com}
se() { osascript -e "tell application \"System Events\" to tell process \"Aitmproxy\" to $1" 2>/dev/null }
se 'set frontmost to true'; sleep 0.5
se 'keystroke "," using command down'; sleep 2
se 'click button "Capture" of toolbar 1 of window 1' >/dev/null; sleep 2
swift winshot.swift "$pid" /tmp/aitm-ne-5.png Capture
se 'keystroke "w" using command down'; sleep 1
# Proxy ▸ Scope… once shows the page, twice opens the add sheet.
se 'click menu item "Scope…" of menu "Proxy" of menu bar 1' >/dev/null; sleep 1
se 'click menu item "Scope…" of menu "Proxy" of menu bar 1' >/dev/null; sleep 1.5
se "keystroke \"$host\""; se 'key code 36'; sleep 1
swift winshot.swift "$pid" /tmp/aitm-ne-6.png aitmproxy
se 'key code 53'; sleep 1
open -a Safari "http://$host/?ne=1"; sleep 8
se 'set frontmost to true'; sleep 0.5
swift winshot.swift "$pid" /tmp/aitm-ne-7.png aitmproxy
ls -la /tmp/aitm-ne-5.png /tmp/aitm-ne-6.png /tmp/aitm-ne-7.png
