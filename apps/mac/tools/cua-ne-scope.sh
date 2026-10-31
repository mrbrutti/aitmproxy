#!/bin/zsh
# Second half of the extension drive: the Scope page's Add field only takes typing after a real
# click (the page opens calm), so click it by pixel, add the host, browse it in Safari and shoot.
# Usage: tools/cua-ne-scope.sh <app pid> <host>       shots → /tmp/aitm-ne-8/9.png
set -u
cd "${0:A:h}"
pid=${1:?app pid}; host=${2:?host}
se() { osascript -e "tell application \"System Events\" to tell process \"Aitmproxy\" to $1" 2>/dev/null }
se 'set frontmost to true'; sleep 0.5
se 'click menu item "Scope…" of menu "Proxy" of menu bar 1' >/dev/null; sleep 1
# Window origin + size from the shot helper, then the page's Add field (sidebar 290 pt, field row ~85 pt down).
read -r _ wx wy ww wh <<< "$(swift winshot.swift "$pid" /tmp/aitm-ne-probe.png aitmproxy)"
swift cgclick.swift $((wx + 600)) $((wy + 85)); sleep 0.5
se "keystroke \"$host\""; sleep 0.3; se 'key code 36'; sleep 1.5
swift winshot.swift "$pid" /tmp/aitm-ne-8.png aitmproxy
open -a Safari "http://$host/?ne=2"; sleep 10
se 'set frontmost to true'; sleep 0.5
se 'click menu item "Connection Log" of menu "Proxy" of menu bar 1' >/dev/null; sleep 1.5
swift winshot.swift "$pid" /tmp/aitm-ne-9.png aitmproxy
ls -la /tmp/aitm-ne-8.png /tmp/aitm-ne-9.png
