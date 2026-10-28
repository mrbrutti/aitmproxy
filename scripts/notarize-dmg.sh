#!/usr/bin/env bash
# Re-sign Aitmproxy.app with a Developer ID + hardened runtime, package it into a
# DMG, notarize the DMG with Apple, and staple the ticket — so the download opens
# with no Gatekeeper prompt.
#
# Output: dist/Aitmproxy-<version>.dmg, signed + notarized + stapled.
#
# Credentials (never stored in the repo):
#   DEV_ID          signing identity (default: the first "Developer ID Application"
#                   in the keychain)
#   ASC_KEY         App Store Connect API key .p8 (default: the single file in
#                   ~/.appstoreconnect/private_keys/)
#   ASC_KEY_ID      key id (default: derived from the AuthKey_<id>.p8 filename)
#   ASC_ISSUER_ID   issuer id (required; from App Store Connect > Users and Access
#                   > Integrations)
#   APP             the .app to sign (default: ~/Applications/Aitmproxy.app)
#
# Needs: codesign, hdiutil, xcrun (notarytool, stapler), /usr/libexec/PlistBuddy.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

app=${APP:-$HOME/Applications/Aitmproxy.app}
[ -d "$app" ] || { echo "notarize-dmg.sh: no app at $app — run apps/mac/build.sh first" >&2; exit 1; }

# Match by SHA-1 (field 2), not the name: the same team can hold two "Developer
# ID Application" certs across keychains, which makes the name ambiguous to
# codesign. Prefer the login keychain.
dev_id=${DEV_ID:-$(security find-identity -v -p codesigning "$HOME/Library/Keychains/login.keychain-db" \
    | awk '/Developer ID Application/ {print $2; exit}')}
[ -n "$dev_id" ] || { echo "notarize-dmg.sh: no 'Developer ID Application' identity in the login keychain (set DEV_ID)" >&2; exit 1; }

asc_key=${ASC_KEY:-$(ls "$HOME"/.appstoreconnect/private_keys/AuthKey_*.p8 2>/dev/null | head -1)}
[ -n "${asc_key:-}" ] && [ -f "$asc_key" ] || { echo "notarize-dmg.sh: no App Store Connect .p8 key (set ASC_KEY)" >&2; exit 1; }
asc_key_id=${ASC_KEY_ID:-$(basename "$asc_key" | sed -E 's/^AuthKey_(.*)\.p8$/\1/')}
: "${ASC_ISSUER_ID:?set ASC_ISSUER_ID (App Store Connect issuer id)}"

echo "notarize-dmg.sh: identity   $dev_id"
echo "notarize-dmg.sh: asc key    $asc_key (id $asc_key_id)"

# 1. Re-sign the app: hardened runtime + secure timestamp are required for
#    notarization. The bundle has no nested code, so one pass seals it.
codesign --force --options runtime --timestamp --sign "$dev_id" "$app"
codesign --verify --deep --strict --verbose=2 "$app"

# 2. Build the DMG from the re-signed app.
bash "$repo_root/scripts/make-dmg.sh"
name=$(/usr/libexec/PlistBuddy -c "Print :CFBundleName" "$app/Contents/Info.plist")
version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$app/Contents/Info.plist")
dmg="dist/${name}-${version}.dmg"

# 3. Sign the DMG itself (Developer ID + timestamp) so Gatekeeper's signature
#    assessment on the image passes, not only the stapled ticket.
codesign --force --timestamp --sign "$dev_id" "$dmg"

# 4. Notarize the DMG and wait for Apple's verdict.
echo "notarize-dmg.sh: submitting $dmg to notarytool (this talks to Apple)…"
xcrun notarytool submit "$dmg" \
    --key "$asc_key" --key-id "$asc_key_id" --issuer "$ASC_ISSUER_ID" \
    --wait

# 4. Staple the ticket so the DMG verifies offline.
xcrun stapler staple "$dmg"

# 5. Prove it.
echo "notarize-dmg.sh: verification"
xcrun stapler validate "$dmg"
spctl -a -t open --context context:primary-signature -vv "$dmg" || true
echo "notarize-dmg.sh: wrote $dmg"
ls -lh "$dmg"
