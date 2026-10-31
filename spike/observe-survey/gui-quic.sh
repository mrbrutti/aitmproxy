#!/bin/bash
# HTTP/3 check in the real GUI: Firefox with a throwaway profile (its own instance), then Safari.
# cloudflare-quic.com renders "your browser used HTTP/3" or "HTTP/2". Window shots via winshot.swift.
tag=${1:-run}; D=/tmp/claude/ne-survey; W=/Users/matt/Security/aitmproxy/.claude/worktrees/cranky-vaughan-0e27b2/apps/mac/tools/winshot.swift
exec > >(tee "$D/gui-quic-$tag.out") 2>&1
echo "== $(date) tag=$tag =="
systemextensionsctl list 2>&1 | grep -E 'aitmproxy.ne.*activated'
FP=$D/ff-gui-prof-$tag; rm -rf "$FP"; mkdir -p "$FP"
printf 'user_pref("network.http.http3.enable", true);\nuser_pref("browser.shell.checkDefaultBrowser", false);\nuser_pref("browser.startup.homepage_override.mstone","ignore");\nuser_pref("datareporting.policy.dataSubmissionEnabled", false);\n' > "$FP/user.js"
echo "-- Firefox (own instance, temp profile): load, wait, reload twice"
open -na Firefox --args --no-remote --new-instance -profile "$FP" https://cloudflare-quic.com/
sleep 14
ffpid=$(pgrep -f "ff-gui-prof-$tag" | head -1); echo "   firefox pid $ffpid"
for i in 1 2; do osascript -e "tell application \"System Events\" to tell (first process whose unix id is $ffpid) to set frontmost to true" >/dev/null 2>&1; sleep 0.5; osascript -e 'tell application "System Events" to keystroke "r" using command down' >/dev/null 2>&1; sleep 6; done
swift "$W" "$ffpid" "$D/ff-gui-$tag.png" 2>&1 | tail -1
kill "$ffpid" 2>/dev/null; sleep 1
echo "-- Safari: open the page in a tab, reload twice, shoot"
open -a Safari https://cloudflare-quic.com/
sleep 10
for i in 1 2; do osascript -e 'tell application "Safari" to activate' >/dev/null 2>&1; sleep 0.5; osascript -e 'tell application "System Events" to keystroke "r" using command down' >/dev/null 2>&1; sleep 6; done
osascript -e 'tell application "Safari" to get {URL, name} of current tab of front window' 2>&1
swift "$W" Safari "$D/safari-$tag.png" QUIC 2>&1 | tail -1
echo "-- UDP :443 flows the provider saw from the browsers (last 3 min)"
log show --last 3m --style compact --predicate 'process == "AitmproxyNE"' 2>/dev/null | grep 'New flow: NEFlow type = datagram' | grep ':443,' | sed -E 's/.*app = ([^,]*), name = ([^,]*), [^ ]+ <-> ([^,]+).*/\1 \2 -> \3/' | sort | uniq -c | sort -rn | head -8
echo "-- TCP :443 flows from the browsers to cloudflare-quic (last 3 min)"
log show --last 3m --style compact --predicate 'process == "AitmproxyNE"' 2>/dev/null | grep 'New flow: NEFlow type = stream' | grep -i 'cloudflare-quic' | sed -E 's/.*app = ([^,]*), name = ([^,]*), [^ ]+ <-> ([^,]+).*/\1 \2 -> \3/' | sort | uniq -c | sort -rn | head -6
ls -la "$D"/ff-gui-$tag.png "$D"/safari-$tag.png 2>&1
echo "GUI QUIC DONE"
