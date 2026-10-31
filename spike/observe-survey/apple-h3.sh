#!/bin/bash
# Apple HTTP stack (URLSession, assumesHTTP3Capable) under the active proxy, then with capture OFF, then back ON.
D=/tmp/claude/ne-survey; exec > >(tee "$D/apple-h3.out") 2>&1
se() { osascript -e "tell application \"System Events\" to tell process \"Aitmproxy\" to $1" 2>&1; }
flows_last() { log show --last "$1" --style compact --predicate 'process == "AitmproxyNE"' 2>/dev/null | grep -c 'New flow: NEFlow'; }
echo "== $(date) =="
echo "-- compiling"; swiftc -O -o "$D/apple-h3" "$D/apple-h3.swift" 2>&1 | grep -v warning | head -5
echo "== capture ON =="; systemextensionsctl list 2>&1 | grep -E 'aitmproxy.ne.*activated'
"$D/apple-h3"
echo "-- Safari once more (open -> Alt-Svc known now?)"; open -a Safari https://cloudflare-quic.com/; sleep 9
echo "-- UDP:443 flows from Apple's stack / Safari in the last 90 s:"
log show --last 90s --style compact --predicate 'process == "AitmproxyNE"' 2>/dev/null | grep 'New flow: NEFlow type = datagram' | grep -E 'apple-h3|Safari|nsurlsessiond|WebKit' | sed -E 's/.*app = ([^,]*), name = ([^,]*), [^ ]+ <-> ([^,]+).*/\1 \2 -> \3/' | sort | uniq -c | sort -rn | head -8
echo "== capture OFF =="
se 'set frontmost to true'; sleep 0.7; se 'click menu item "Disable Capture" of menu "Proxy" of menu bar 1' >/dev/null; sleep 8
echo "-- flows in last 6 s (expect 0): $(flows_last 6s)"
"$D/apple-h3"
echo "== capture back ON =="
se 'set frontmost to true'; sleep 0.7; se 'click menu item "Enable Capture" of menu "Proxy" of menu bar 1' >/dev/null; sleep 10
dig @1.1.1.1 example.com +short +time=2 +tries=1 >/dev/null; sleep 3
echo "-- flows in last 15 s (expect >0): $(flows_last 15s)"; systemextensionsctl list 2>&1 | grep -E 'aitmproxy.ne.*activated'
echo "APPLE-H3 DONE $(date)"
