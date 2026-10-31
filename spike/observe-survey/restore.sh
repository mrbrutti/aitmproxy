#!/bin/bash
# Restore Matt's released v0.5.3 app over the experiment build, from the Homebrew cask's cached DMG.
set -u
D=/tmp/claude/ne-survey
exec > >(tee "$D/restore.out") 2>&1
echo "== $(date) =="
echo "== before: app build $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' /Applications/Aitmproxy.app/Contents/Info.plist) =="
systemextensionsctl list 2>&1 | grep aitmproxy
osascript -e 'quit app "Aitmproxy"' 2>/dev/null || true; sleep 3
echo "== brew reinstall --cask aitmproxy (cached, sha-verified DMG) =="
brew reinstall --cask aitmproxy 2>&1 | tail -8
echo "== after: app build $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' /Applications/Aitmproxy.app/Contents/Info.plist), sysex build $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' /Applications/Aitmproxy.app/Contents/Library/SystemExtensions/com.mrbrutti.aitmproxy.ne.systemextension/Contents/Info.plist) =="
codesign -dv /Applications/Aitmproxy.app 2>&1 | grep -E 'Authority=Developer|TeamIdentifier'
spctl -a -t exec -vv /Applications/Aitmproxy.app 2>&1
shasum -a 256 "$HOME/Library/Caches/Homebrew/downloads/"*--Aitmproxy-0.5.3.dmg
echo "== launch =="
open /Applications/Aitmproxy.app; sleep 12
systemextensionsctl list 2>&1 | grep aitmproxy
log show --last 2m --style compact --predicate 'process == "sysextd"' 2>&1 | grep -i -E 'aitmproxy|replac|approv|activat|error' | tail -6 | cut -c1-220
echo "RESTORE DONE"
