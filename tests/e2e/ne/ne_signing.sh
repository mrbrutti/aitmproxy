#!/usr/bin/env bash
# e2e: surface=ne tier=auto
# Ground-truth checks on the SIGNED + NOTARIZED macOS app and its embedded system
# extension: entitlements, Gatekeeper, the version-bump discipline, and the activated
# sysex state. Runs only against a NOTARIZED build — a stapled ticket is the mark of the
# Task-18 build; a dev or DMG build at /Applications (Developer-ID-signed but unnotarized)
# is skipped rather than failed on checks it was never meant to pass. Until build.sh
# produces + installs the notarized build (Task 18), this SKIPs loudly and stays green.
set -u
source "$(dirname "$0")/../lib/contract.sh"

[ "$(uname -s)" = "Darwin" ] || e2e_skip "macOS-only checks"

app="/Applications/Aitmproxy.app"
sysex="$app/Contents/Library/SystemExtensions/com.mrbrutti.aitmproxy.ne.systemextension"

[ -d "$app" ] || e2e_skip "no NE build installed at $app (build.sh is Task 18)"
[ -d "$sysex" ] || e2e_skip "app at $app has no embedded sysex (dev build, or not an NE build)"
# A stapled notarization ticket marks THE Task-18 build; a dev/DMG build lacks one, so skip
# it rather than fail on notarization checks it cannot pass.
stapler validate "$app" >/dev/null 2>&1 || e2e_skip "installed app is not notarized (no stapled ticket) — Task 18 build.sh not run here"
e2e_check 0 "notarization ticket stapled"

# Host app entitlements: NE provider + system-extension install + the real app id.
ents="$(codesign -d --entitlements :- "$app" 2>/dev/null)"
echo "$ents" | grep -q "app-proxy-provider-systemextension" || e2e_fail "host app missing app-proxy-provider-systemextension"
echo "$ents" | grep -q "com.apple.developer.system-extension.install" || e2e_fail "host app missing system-extension.install"
echo "$ents" | grep -q "995PCLM9KH.com.mrbrutti.aitmproxy" || e2e_fail "host app wrong application-identifier"
e2e_check 0 "host app entitlements: NE provider + system-extension.install + app id"

# Sysex entitlements: NE provider + the sysex app id.
sents="$(codesign -d --entitlements :- "$sysex" 2>/dev/null)"
echo "$sents" | grep -q "app-proxy-provider-systemextension" || e2e_fail "sysex missing app-proxy-provider-systemextension"
echo "$sents" | grep -q "995PCLM9KH.com.mrbrutti.aitmproxy.ne" || e2e_fail "sysex wrong application-identifier"
e2e_check 0 "sysex entitlements: NE provider + sysex app id"

# Signature valid + Gatekeeper accepts a notarized build.
codesign -vvv --deep --strict "$app" >/dev/null 2>&1
e2e_check $? "codesign --deep --strict valid on the app"
spctl -a -vvv -t exec "$app" >/dev/null 2>&1
e2e_check $? "spctl accepts the app (notarized / Developer ID)"

# CFBundleVersion must be a real timestamp, not the __BUILD__ placeholder (version-bump discipline, NE-AC14).
ver="$(plutil -extract CFBundleVersion raw "$sysex/Contents/Info.plist" 2>/dev/null)"
case "$ver" in
  '' | *[!0-9]*) e2e_fail "sysex CFBundleVersion is not a numeric timestamp: '$ver'" ;;
  *) e2e_check 0 "sysex CFBundleVersion is a numeric timestamp ($ver)" ;;
esac

# If the extension is activated, confirm it reads [activated enabled]; activation itself is
# the manual 2-click gate (test_live_capture.py), so not-yet-activated is fine here.
if systemextensionsctl list 2>/dev/null | grep -q "com.mrbrutti.aitmproxy.ne"; then
  if systemextensionsctl list 2>/dev/null | grep "com.mrbrutti.aitmproxy.ne" | grep -q "activated enabled"; then
    e2e_check 0 "systemextensionsctl shows the sysex [activated enabled]"
  else
    e2e_fail "sysex present but not [activated enabled] (approve it in System Settings)"
  fi
else
  echo "  [ok] sysex not yet activated (activation is the manual 2-click gate)"
fi

e2e_pass "NE signing + notarization + sysex state verified"
