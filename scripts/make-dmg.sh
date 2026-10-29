#!/usr/bin/env bash
# Package the installed Aitmproxy.app into a drag-to-install .dmg under dist/.
#
# Output: dist/Aitmproxy-<version>.dmg — a compressed read-only image with the
# app and an /Applications symlink, so the user drags the app onto Applications.
#
# The app is whatever `apps/mac/build.sh` installed (dev-signed when a signing
# identity is present, else ad-hoc). The DMG is not notarized: a download gets
# Gatekeeper-quarantined, so first launch needs right-click > Open or
# `xattr -dr com.apple.quarantine` (see dist/INSTALL.md).
#
# Environment:
#   APP   path to the .app to package (default: ~/Applications/Aitmproxy.app)
#
# Needs: hdiutil, /usr/libexec/PlistBuddy (both stock macOS).
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

app=${APP:-$HOME/Applications/Aitmproxy.app}
if [ ! -d "$app" ]; then
    echo "make-dmg.sh: no app at $app — run apps/mac/build.sh first (or set APP=)" >&2
    exit 1
fi

name=$(/usr/libexec/PlistBuddy -c "Print :CFBundleName" "$app/Contents/Info.plist")
version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$app/Contents/Info.plist")

echo "make-dmg.sh: ${name} ${version} from ${app}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
stage="$work/stage"
mkdir -p "$stage"
# ditto preserves the signature and resource forks that cp -R can drop.
ditto "$app" "$stage/$(basename "$app")"
ln -s /Applications "$stage/Applications"

mkdir -p dist
out="dist/${name}-${version}.dmg"
rm -f "$out"
hdiutil create -volname "$name" -srcfolder "$stage" -ov -format UDZO "$out" >/dev/null

echo "make-dmg.sh: wrote ${out}"
hdiutil verify "$out" >/dev/null && echo "make-dmg.sh: image verified"
ls -lh "$out"
