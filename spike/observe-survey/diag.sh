#!/bin/bash
# Read-only diagnostics for the observe-survey experiment (runs in Matt's shell, outside the sandbox).
echo "== date =="; date
echo "== systemextensionsctl list =="; systemextensionsctl list 2>&1
echo "== processes =="; pgrep -fl 'Aitmproxy|AitmproxyNE|aitm ' 2>&1
echo "== rendezvous =="; ls -la /private/tmp/aitmproxy-capture.rendezvous 2>&1; cat /private/tmp/aitmproxy-capture.rendezvous 2>&1; echo
echo "== installed app =="; /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' /Applications/Aitmproxy.app/Contents/Info.plist; /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' /Applications/Aitmproxy.app/Contents/Info.plist
codesign -dvvv /Applications/Aitmproxy.app 2>&1 | grep -E '^Authority|TeamIdentifier|^Identifier|flags='
echo "== sysex in bundle =="; /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' /Applications/Aitmproxy.app/Contents/Library/SystemExtensions/com.mrbrutti.aitmproxy.ne.systemextension/Contents/Info.plist
echo "== spctl =="; spctl -a -t exec -vv /Applications/Aitmproxy.app 2>&1
echo "== stapled? =="; xcrun stapler validate /Applications/Aitmproxy.app 2>&1 | tail -1
echo "== identities (login keychain) =="; security find-identity -v -p codesigning "$HOME/Library/Keychains/login.keychain-db" 2>&1
echo "== identities (all) =="; security find-identity -v -p codesigning 2>&1
echo "== cert in A1 sysex profile =="; security cms -D -i "$HOME/Library/MobileDevice/Provisioning Profiles/Aitmproxy NE DeveloperID.provisionprofile" 2>/dev/null | plutil -extract DeveloperCertificates xml1 -o - - 2>/dev/null | sed -n 's/.*<data>//;s/<\/data>.*//p' | head -1 | base64 -d 2>/dev/null | openssl x509 -inform DER -noout -fingerprint -sha1 -subject 2>&1
echo "== notary creds =="; ls "$HOME/.appstoreconnect/private_keys/" 2>&1; xcrun notarytool history --keychain-profile aitm-notary 2>&1 | head -4
echo "== brew cask =="; brew list --cask 2>&1 | grep -i aitm
echo "== cask info =="; brew info --cask mrbrutti/aitmproxy/aitmproxy 2>&1 | head -5
echo "== NE log volume last 24h (framework reject lines per hour) =="
log show --last 24h --style compact --predicate 'process == "AitmproxyNE"' 2>&1 | grep -c 'rejected new flow'
log show --last 24h --style compact --predicate 'process == "AitmproxyNE"' 2>&1 | grep 'rejected new flow' | awk '{print substr($1,1,13)}' | sort | uniq -c | tail -30
echo "== sample lines =="; log show --last 2h --style compact --predicate 'process == "AitmproxyNE"' 2>&1 | tail -8
echo "== DIAG DONE =="
