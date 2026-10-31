#!/usr/bin/env bash
# Re-sign Aitmproxy.app with a Developer ID + hardened runtime, package it into a
# DMG, notarize the DMG with Apple, and staple the ticket — so the download opens
# with no Gatekeeper prompt.
#
# Output: dist/Aitmproxy-<version>.dmg, signed + notarized + stapled.
#
# This is a CREDENTIALED, MANUAL step. Run it in the Terminal panel on Matt's Mac,
# with his Developer ID Application identity in the login keychain and his App
# Store Connect API key (key id G638JVUND7, team 995PCLM9KH). It is never run by CI
# or an agent sandbox. No secret is stored or automated here: the key, the identity
# and the issuer id all come from Matt's keychain, files and environment.
#
# Network-extension (NE) release. When the app embeds a system extension
# (Contents/Library/SystemExtensions/*.systemextension, put there by
# apps/mac/build.sh), this script signs it the way build.sh does, inside-out: any
# code nested in the extension, then the extension itself with
# apps/mac/Extension/Aitmproxy-Extension.entitlements, then the embedded core, then
# the app LAST with apps/mac/Aitmproxy.entitlements. It then checks the signatures
# and entitlements and refuses to continue (exit 1) before building or notarizing
# the DMG if any are wrong. An NE build installs to /Applications (macOS rejects
# the extension from ~/Applications), so an NE release runs as:
#
#   APP=/Applications/Aitmproxy.app ASC_ISSUER_ID=<issuer> bash scripts/notarize-dmg.sh
#
# A build with no embedded extension is signed and notarized exactly as before
# (no NE entitlements, nothing else changes). The extension's and the app's
# provisioning profiles must already be embedded by build.sh; this script re-signs
# over them, never copies them, and fails if either is missing.
#
# Credentials (never stored in the repo):
#   DEV_ID          signing identity (default: the first "Developer ID Application"
#                   in the keychain)
#   ASC_KEY         App Store Connect API key .p8 (default: the single file in
#                   ~/.appstoreconnect/private_keys/)
#   ASC_KEY_ID      key id (default: derived from the AuthKey_<id>.p8 filename)
#   ASC_ISSUER_ID   issuer id (required; from App Store Connect > Users and Access
#                   > Integrations)
#   APP             the .app to sign (default: ~/Applications/Aitmproxy.app; an NE
#                   release sets /Applications/Aitmproxy.app)
#
# Needs: codesign, hdiutil, find, spctl, xcrun (notarytool, stapler),
# /usr/libexec/PlistBuddy.
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

asc_key=${ASC_KEY:-}
if [ -z "$asc_key" ]; then
    # First AuthKey_*.p8 (the glob sorts, like the `ls | head -1` it replaces; an
    # unmatched glob stays literal and fails the -f test, leaving asc_key empty).
    for candidate in "$HOME"/.appstoreconnect/private_keys/AuthKey_*.p8; do
        if [ -f "$candidate" ]; then
            asc_key=$candidate
            break
        fi
    done
fi
[ -n "${asc_key:-}" ] && [ -f "$asc_key" ] || { echo "notarize-dmg.sh: no App Store Connect .p8 key (set ASC_KEY)" >&2; exit 1; }
asc_key_id=${ASC_KEY_ID:-$(basename "$asc_key" | sed -E 's/^AuthKey_(.*)\.p8$/\1/')}
: "${ASC_ISSUER_ID:?set ASC_ISSUER_ID (App Store Connect issuer id)}"

echo "notarize-dmg.sh: identity   $dev_id"
echo "notarize-dmg.sh: asc key    $asc_key (id $asc_key_id)"

# 1. Re-sign inside-out with Developer ID + hardened runtime + secure timestamp
#    (all required for notarization). The embedded core (aitm + obscura) lives in
#    Contents/Resources/core; nested Mach-O there must be signed before the app,
#    since signing the outer bundle does not seal executables under Resources.
core="$app/Contents/Resources/core"
# A shipped release must bundle the embedded core (aitm + obscura) — the whole
# point of the self-contained app. build.sh skips the core when none is staged
# (dev falls back to an external core), so guard the release path here: refuse to
# notarize a core-less app rather than ship one silently. Fix: run
# scripts/package.sh, then apps/mac/build.sh (or set AITM_CORE_DIR/CORE_TARBALL),
# before this script.
for bin in obscura aitm; do
    [ -f "$core/$bin" ] || { echo "notarize-dmg.sh: $app is missing its embedded core ($core/$bin). Run scripts/package.sh then apps/mac/build.sh so the app bundles aitm + obscura, then re-run." >&2; exit 1; }
done
# The core's default detection catalogue must ship beside it: aitm discovers the
# bundled Rhai scripts at <exe_dir>/share/aitm/scripts (crates/aitm/src/bundled.rs),
# so without core/share/aitm/scripts the embedded core loads zero detections and
# the app's Scripts page shows 0 active. The 0.5.4 DMG shipped exactly that.
# build.sh stages the catalogue from the package.sh tarball; refuse to notarize
# an app that lacks it rather than ship it silently again.
catalogue="$core/share/aitm/scripts"
rhai_count=0
special=""
if [ -d "$catalogue" ]; then
    # Both finds check their own status, like the nested-code find below: under
    # pipefail an errored find would otherwise end the script through set -e with
    # no line naming the cause or the fix.
    rhai_count=$(find "$catalogue" -type f -name '*.rhai' | wc -l | tr -d ' ') || { echo "notarize-dmg.sh: listing the detection catalogue in $catalogue failed (find exited non-zero)" >&2; exit 1; }
    # Only regular files and directories ship in the sealed bundle: a symlink or a
    # special file in the catalogue is not something the signature should seal
    # (build.sh refuses to stage one; the core's loader never follows symlinks).
    special=$(find "$catalogue" ! -type f ! -type d -print -quit) || { echo "notarize-dmg.sh: listing the detection catalogue in $catalogue failed (find exited non-zero)" >&2; exit 1; }
fi
[ "$rhai_count" -gt 0 ] || { echo "notarize-dmg.sh: $app has no bundled detection catalogue ($catalogue holds no *.rhai). Run scripts/package.sh then apps/mac/build.sh so the catalogue is bundled beside the core, then re-run." >&2; exit 1; }
[ -z "$special" ] || { echo "notarize-dmg.sh: $catalogue contains a symlink or special file ($special); only regular files ship in the bundle. Re-run apps/mac/build.sh from a clean catalogue (it refuses to stage one like this), then re-run." >&2; exit 1; }
echo "notarize-dmg.sh: catalogue  $rhai_count scripts in $catalogue"

# Hardened runtime + secure timestamp: the Developer ID is a real identity, so the
# timestamp is always wanted (build.sh drops it only for an ad-hoc dev identity).
runtime_opts=(--options runtime --timestamp)

# codesign that ABORTS the release on a real failure while hiding the benign
# "replacing existing signature" chatter. Ported from apps/mac/build.sh. A plain
# `codesign … | grep -v … || true` would let grep's exit status mask codesign's, so
# a failed restricted-entitlement sign would still read as success and reach
# notarytool. Never call this inside $(…): the exit would only leave the subshell.
cs() {
    local out
    if ! out=$(codesign "$@" 2>&1); then
        printf '%s\n' "$out" >&2
        echo "notarize-dmg.sh: codesign failed: codesign $*" >&2
        exit 1
    fi
    printf '%s\n' "$out" | grep -v "replacing existing signature" || true
}

# assert_contains <what> <haystack> <ERE>: stop the release unless the pattern is
# in the text. A here-string, not a pipe, so pipefail cannot turn a grep -q early
# exit into a false failure.
assert_contains() {
    if ! grep -E -q -- "$3" <<<"$2"; then
        echo "notarize-dmg.sh: verification failed: $1 (expected /$3/). Not building or notarizing the DMG." >&2
        exit 1
    fi
}

# Detect the embedded system extension (a network-extension build). There is at
# most one (bundle id com.mrbrutti.aitmproxy.ne). Detection is by presence inside
# $app, so it works whether APP is /Applications or ~/Applications.
sysex_bundle=""
sysex_count=0
for sysex_candidate in "$app"/Contents/Library/SystemExtensions/*.systemextension; do
    [ -d "$sysex_candidate" ] || continue # an unmatched glob stays literal
    sysex_bundle=$sysex_candidate
    sysex_count=$((sysex_count + 1))
done
[ "$sysex_count" -le 1 ] || { echo "notarize-dmg.sh: $app embeds $sysex_count system extensions; expected exactly one" >&2; exit 1; }

if [ -n "$sysex_bundle" ]; then
    echo "notarize-dmg.sh: network-extension build; signing $sysex_bundle inside-out"
    # The restricted NE entitlements are authorised by embedded provisioning
    # profiles, which build.sh placed. Re-signing keeps them; a missing one cannot
    # be fixed here (and an extension without its profile cannot activate).
    [ -f "$app/Contents/embedded.provisionprofile" ] || { echo "notarize-dmg.sh: $app has no Contents/embedded.provisionprofile; run apps/mac/build.sh with the NE profiles (this script never copies them)" >&2; exit 1; }
    [ -f "$sysex_bundle/Contents/embedded.provisionprofile" ] || { echo "notarize-dmg.sh: $sysex_bundle has no Contents/embedded.provisionprofile; run apps/mac/build.sh with the NE profiles (this script never copies them)" >&2; exit 1; }
    # (a) Any code nested inside the extension, deepest first (find -depth lists a
    #     directory's contents before the directory). Today the extension is a lone
    #     Contents/MacOS/AitmproxyNE, sealed by signing the bundle, so this finds
    #     nothing; it keeps the recipe valid if the extension ever gains a framework.
    #     The list goes to a file first, not into `done < <(find ...)`: a process
    #     substitution discards find's exit status (set -e and pipefail never see
    #     it), so a find that errored half way would leave nested code unsigned and
    #     the release would carry on. Here a failed find aborts before anything is signed.
    nested_list=$(mktemp "${TMPDIR:-/tmp}/notarize-nested.XXXXXX") || { echo "notarize-dmg.sh: cannot create a temp file for the nested-code list" >&2; exit 1; }
    trap 'rm -f "$nested_list"' EXIT
    find "$sysex_bundle/Contents" -depth \( -type d \( -name '*.framework' -o -name '*.xpc' -o -name '*.appex' -o -name '*.app' \) -o -type f -name '*.dylib' \) -print0 >"$nested_list" || { echo "notarize-dmg.sh: listing the code nested in $sysex_bundle failed (find exited non-zero); not signing a partial list" >&2; exit 1; }
    while IFS= read -r -d '' nested; do
        cs --force "${runtime_opts[@]}" --sign "$dev_id" "$nested"
    done <"$nested_list"
    # (b) The extension bundle, with its own restricted NE entitlements.
    cs --force "${runtime_opts[@]}" --entitlements "$repo_root/apps/mac/Extension/Aitmproxy-Extension.entitlements" --sign "$dev_id" "$sysex_bundle"
fi

# (c) The embedded core. obscura (Chromium-based) needs JIT entitlements under the
# hardened runtime or it SIGTRAPs on V8 init ("embedded browser unavailable"); aitm
# needs none.
obscura_ent="$repo_root/apps/mac/EmbeddedObscura.entitlements"
cs --force "${runtime_opts[@]}" --entitlements "$obscura_ent" --sign "$dev_id" "$core/obscura"
cs --force "${runtime_opts[@]}" --sign "$dev_id" "$core/aitm"

# (d) The app, LAST. An NE build signs it WITH the NE host entitlements; without
# --entitlements, codesign --force strips them all, and the extension can never
# activate (the v0.5.1 regression). A build with no extension keeps the plain,
# entitlement-less signature.
if [ -n "$sysex_bundle" ]; then
    cs --force "${runtime_opts[@]}" --entitlements "$repo_root/apps/mac/Aitmproxy.entitlements" --sign "$dev_id" "$app"
else
    cs --force "${runtime_opts[@]}" --sign "$dev_id" "$app"
fi
codesign --verify --deep --strict --verbose=2 "$app"

# Verify-or-fail BEFORE the DMG is built or anything goes to Apple: a stripped
# entitlement or an unsigned extension notarizes fine and then ships broken, so
# prove them here. codesign's own exit status is checked on every capture.
if [ -n "$sysex_bundle" ]; then
    echo "notarize-dmg.sh: verifying the nested system extension and the NE entitlements"
    sysex_sig=$(codesign -dv --verbose=4 "$sysex_bundle" 2>&1) || { printf '%s\n' "$sysex_sig" >&2; echo "notarize-dmg.sh: codesign -dv failed on $sysex_bundle" >&2; exit 1; }
    app_sig=$(codesign -dv --verbose=4 "$app" 2>&1) || { printf '%s\n' "$app_sig" >&2; echo "notarize-dmg.sh: codesign -dv failed on $app" >&2; exit 1; }
    # `--entitlements -` prints the text dump of the entitlements; the `:-` form is
    # deprecated and, on current macOS, reports an invalid blob instead of the dump.
    app_ents=$(codesign -d --entitlements - "$app" 2>&1) || { printf '%s\n' "$app_ents" >&2; echo "notarize-dmg.sh: reading the entitlements of $app failed" >&2; exit 1; }
    sysex_ents=$(codesign -d --entitlements - "$sysex_bundle" 2>&1) || { printf '%s\n' "$sysex_ents" >&2; echo "notarize-dmg.sh: reading the entitlements of $sysex_bundle failed" >&2; exit 1; }
    assert_contains "the nested system extension is signed by a Developer ID Application identity" "$sysex_sig" 'Authority=Developer ID Application'
    assert_contains "the nested system extension has the hardened runtime (flags=...runtime)" "$sysex_sig" 'flags=.*runtime'
    # Both bundles must carry the team the entitlement files hard-code (995PCLM9KH, in
    # com.apple.application-identifier and team-identifier). A bundle signed by another
    # team still reads "Developer ID Application", notarizes, and then fails AMFI on the
    # user's Mac. The patterns are anchored: not a longer id, and not `not set`.
    assert_contains "the nested system extension is signed by team 995PCLM9KH" "$sysex_sig" '^TeamIdentifier=995PCLM9KH$'
    assert_contains "the app is signed by team 995PCLM9KH" "$app_sig" '^TeamIdentifier=995PCLM9KH$'
    assert_contains "the app carries the app-proxy-provider-systemextension NE entitlement" "$app_ents" 'app-proxy-provider-systemextension'
    assert_contains "the app carries com.apple.developer.system-extension.install" "$app_ents" 'com.apple.developer.system-extension.install'
    assert_contains "the system extension carries the app-proxy-provider-systemextension NE entitlement" "$sysex_ents" 'app-proxy-provider-systemextension'
    # Gatekeeper pre-check. Advisory: before notarization a Developer ID app is
    # typically "Unnotarized Developer ID"; the authoritative check runs after the
    # ticket is stapled.
    if ! spctl -a -t exec -vvv "$app"; then
        echo "notarize-dmg.sh: spctl does not accept $app yet (advisory before notarization; continuing)"
    fi
fi

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
