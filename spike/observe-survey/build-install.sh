#!/bin/zsh
# Build, notarize and install the observe-survey provider variant over /Applications/Aitmproxy.app.
# Runs in Matt's shell (Terminal panel). Throwaway experiment; restore v0.5.3 afterwards (restore.sh).
set -euo pipefail
REPO=/Users/matt/Security/aitmproxy/.claude/worktrees/cranky-vaughan-0e27b2
OUT=/tmp/claude/ne-survey
TARBALL="$HOME/Library/Caches/Homebrew/downloads/faf0c660196c6087f3a740b43f8892ca021874af2ab6a55ac621dc5535c52527--aitm-0.5.3-aarch64-apple-darwin.tar.gz"
IDENT=1D24F95FCA65C06129134FA5ABE114DF9C728B98
APP=/Applications/Aitmproxy.app
SYSEX="$APP/Contents/Library/SystemExtensions/com.mrbrutti.aitmproxy.ne.systemextension"
cd "$REPO"
echo "== $(date) tree $(git rev-parse --short HEAD) =="
echo "== installed before: app build $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Contents/Info.plist"), sysex build $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$SYSEX/Contents/Info.plist") =="
tmpd=$(mktemp -d)
(cd "$tmpd" && codesign -d --extract-certificates "$SYSEX" 2>/dev/null && openssl x509 -inform DER -in codesign0 -noout -fingerprint -sha1) | tee "$OUT/installed-sysex-cert.txt"
want=$(print -r -- "$IDENT" | sed 's/../&:/g; s/:$//')
grep -qi "$want" "$OUT/installed-sysex-cert.txt" || { echo "ABORT: the installed sysex leaf cert is not $IDENT"; exit 1; }
if pgrep -fl 'swift-build|swift-frontend|/apps/mac/build\.sh' >/dev/null; then echo "ABORT: a sibling swift build is running"; pgrep -fl 'swift-build|swift-frontend|/apps/mac/build\.sh'; exit 1; fi
[[ -f "$TARBALL" ]] || { echo "ABORT: no core tarball at $TARBALL"; exit 1; }
echo "== quit the running app =="
osascript -e 'quit app "Aitmproxy"' 2>/dev/null || true
sleep 3
pgrep -x Aitmproxy >/dev/null && { echo "app still running, waiting"; sleep 5; } || true
echo "== build --ne --allow-unnotarized =="
NE_SIGN_IDENTITY=$IDENT CORE_TARBALL="$TARBALL" apps/mac/build.sh --ne --allow-unnotarized 2>&1 | tee "$OUT/build.log"
grep -q "^installed $APP" "$OUT/build.log" || { echo "ABORT: build.sh did not report an install"; exit 1; }
echo "== built: app build $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Contents/Info.plist"), sysex build $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$SYSEX/Contents/Info.plist") =="
codesign -dvvv "$SYSEX" 2>&1 | grep -E '^Authority=Developer|TeamIdentifier|flags='
echo "survey strings in the sysex binary: $(strings "$SYSEX/Contents/MacOS/AitmproxyNE" | grep -c 'SURVEY' || true)"
echo "== notarize the app bundle (zip -> notarytool --wait -> staple) =="
ZIP=$OUT/Aitmproxy-survey.zip; rm -f "$ZIP"
ditto -c -k --keepParent "$APP" "$ZIP"
ls -lh "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile aitm-notary --wait 2>&1 | tee "$OUT/notarize.log"
grep -q 'status: Accepted' "$OUT/notarize.log" || { echo "ABORT: notarization was not Accepted"; exit 1; }
xcrun stapler staple "$APP" 2>&1 | tail -2
echo "== verify =="
spctl -a -t exec -vv "$APP" 2>&1
xcrun stapler validate "$APP" 2>&1 | tail -1
codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | tail -2
echo "== launch =="
open "$APP"
sleep 10
systemextensionsctl list 2>&1 | grep -E 'aitmproxy'
echo "BUILD-INSTALL DONE $(date)"
