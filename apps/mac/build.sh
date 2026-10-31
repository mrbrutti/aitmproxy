#!/bin/zsh
# Builds Aitmproxy and installs it to ~/Applications/Aitmproxy.app.
# Build products live in ~/Library/Developer/Aitmproxy, outside the repo
# (and outside Dropbox or iCloud, which would try to sync them).
#
# Usage: ./build.sh            release build, install to ~/Applications
#        ./build.sh --debug    debug build, install to ~/Applications
#        ./build.sh --open     install, then quit the running copy and open the new one
#        ./build.sh --ne       Network Extension build: Developer ID signing, the sysex
#                              embedded, installed to /Applications (the only place a
#                              sysex activates from). Never inferred from the presence of
#                              the NE profiles: without --ne, /Applications is not touched.
#        ./build.sh --replace  allow replacing an installed bundle whose
#                              CFBundleShortVersionString differs from the one being built
#                              (without it the build refuses, and says what it would have
#                              overwritten). Same-version rebuilds need no flag.
#        ./build.sh --ne --allow-unnotarized
#                              accept that the embedded system extension is not notarized.
#                              macOS refuses an unnotarized Developer ID sysex ("code
#                              signature invalid"), so an --ne build on its own can never
#                              activate capture: it is the INPUT to scripts/notarize-dmg.sh,
#                              and without this flag it exits 1 after installing to say so.
# Day-to-day iteration without installing anything: tools/snap-dev.sh (DEV_TAG=<tag>).
set -euo pipefail
here=${0:A:h}
name="Aitmproxy"
scratch="$HOME/Library/Developer/$name/build"
config=release
[[ " $* " == *" --debug "* ]] && config=debug
want_ne=0; [[ " $* " == *" --ne "* ]] && want_ne=1
allow_replace=0; [[ " $* " == *" --replace "* ]] && allow_replace=1
allow_unnotarized=0; [[ " $* " == *" --allow-unnotarized "* ]] && allow_unnotarized=1

# Sign with your Apple Development certificate when you have one (Xcode >
# Settings > Accounts). Otherwise sign ad hoc, which is fine for your own Mac.
identity="${SIGN_IDENTITY:-}"
if [[ -z "$identity" ]]; then
  identity=$(security find-identity -v -p codesigning 2>/dev/null | grep -m1 -o '"Apple Development: [^"]*"' | tr -d '"' || true)
fi
[[ -n "$identity" ]] || identity=-

# A Network/System Extension build is an explicit --ne opt-in: it needs a Developer ID
# identity that both A1 provisioning profiles authorise (tools/ne-preflight.sh resolves
# it by SHA — a team can hold several same-named certs, and a sysex signed with one the
# embedded profile does not list fails activation with "code signature invalid"), and it
# installs to /Applications (the Task-1 spike proved the sysex is rejected from
# ~/Applications with OSSystemExtensionError Code=3). Inferring it from the presence of
# the profiles made a plain `--debug` build replace the released app in /Applications
# (2026-10-31), so without --ne the profiles are ignored and the build stays in
# ~/Applications.
ne_app_profile="${NE_APP_PROFILE:-$HOME/Library/MobileDevice/Provisioning Profiles/Aitmproxy Host DeveloperID.provisionprofile}"
ne_sysex_profile="${NE_SYSEX_PROFILE:-$HOME/Library/MobileDevice/Provisioning Profiles/Aitmproxy NE DeveloperID.provisionprofile}"
ne_identity=""
if (( want_ne )); then
  ne_identity=$("$here/tools/ne-preflight.sh" "$ne_app_profile" "$ne_sysex_profile") || exit 1
fi

# An NE build (--ne) installs to /Applications (required for sysex activation); the
# normal dev loop keeps ~/Applications so snapshot/selftest tooling is unaffected.
apps_dir="$HOME/Applications"
(( want_ne )) && apps_dir="/Applications"
app="$apps_dir/$name.app"
# The app version tracks the workspace release (Cargo.toml [workspace.package]) so
# the DMG name, the bus handshake, and the cask all agree; APP_VERSION overrides.
version="${APP_VERSION:-$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version *= *"\([^"]*\)".*/\1/p' "${here:h:h}/Cargo.toml" | head -1)}"
[[ -n "$version" ]] || { echo "build failed: no app version (set APP_VERSION)"; exit 1; }
# Say what is about to be overwritten, and refuse to replace a bundle of another
# version (a released app the operator still uses) unless --replace says so.
# CFBundleVersion is a per-build timestamp, so the comparison is on the version string.
if [[ -d "$app" ]]; then
  installed_version=$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist" 2>/dev/null || echo "?")
  installed_build=$(plutil -extract CFBundleVersion raw -o - "$app/Contents/Info.plist" 2>/dev/null || echo "?")
  echo "replacing $app (version $installed_version, build $installed_build) with version $version ($config)"
  if [[ "$installed_version" != "$version" ]] && (( ! allow_replace )); then
    echo "refused: installed version $installed_version differs from $version; pass --replace to overwrite it"
    exit 1
  fi
else
  echo "installing $app (version $version, $config)"
fi

swift build -c $config --package-path "$here" --scratch-path "$scratch" 2>&1 | grep -E "error|warning|Build complete" | grep -v "^\[" || true
bin="$scratch/$config/$name"
[[ -x "$bin" ]] || { echo "build failed"; exit 1; }
# swift build can report success while an edited file failed to compile. Catch that.
stale=$(find "$here/Sources" -name '*.swift' -newer "$bin" | head -1)
if [[ -n "$stale" ]]; then
  echo "build failed: binary is older than $stale"
  swift build -c $config --package-path "$here" --scratch-path "$scratch" 2>&1 | grep -E "error" | head -20
  exit 1
fi

mkdir -p "$apps_dir"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin" "$app/Contents/MacOS/$name"
sed -e "s/__BUILD__/$(date +%Y%m%d%H%M)/" -e "s/__VERSION__/$version/" "$here/Info.plist.in" > "$app/Contents/Info.plist"
# The icon: Icon/AppIcon.icon -> Resources/Assets.car + AppIcon.icns, rebuilt when it changed.
if [[ -d "$here/Icon/AppIcon.icon" ]]; then
  car="$here/Resources/Assets.car"
  if [[ ! -f "$car" || -n "$(find "$here/Icon/AppIcon.icon" -newer "$car" | head -1)" ]]; then
    "$here/tools/make_icon.sh"
  fi
  cp -X "$car" "$here/Resources/AppIcon.icns" "$app/Contents/Resources/"
fi

# Bundle the embedded core (aitm + obscura) so the app spawns it from inside the
# bundle with no separate install (core-connection spec AC6/AC11). EmbeddedCore
# discovers them at Contents/Resources/core/{aitm,obscura}. The binaries are the
# release artifacts from scripts/package.sh; point at them with AITM_CORE_DIR (a
# directory holding both) or CORE_TARBALL (a package.sh tarball), else the newest
# dist/aitm-*-<target>.tar.gz is used. Absent => skip, and the app falls back to
# an external core (EmbeddedCore.discoverBundled returns nil off-bundle).
coredir="$app/Contents/Resources/core"
target=$(rustc -vV 2>/dev/null | sed -n 's/host: //p')
src_aitm="" src_obscura=""
if [[ -n "${AITM_CORE_DIR:-}" ]]; then
  src_aitm="$AITM_CORE_DIR/aitm"; src_obscura="$AITM_CORE_DIR/obscura"
else
  tarball="${CORE_TARBALL:-}"
  if [[ -z "$tarball" ]]; then
    repo_root=$(cd "$here/../.." && pwd)
    tarball=$(ls -t "$repo_root"/dist/aitm-*-"${target:-}".tar.gz 2>/dev/null | head -1 || true)
  fi
  if [[ -n "$tarball" && -f "$tarball" ]]; then
    coretmp=$(mktemp -d)
    tar -xzf "$tarball" -C "$coretmp"
    src_aitm="$coretmp/aitm"; src_obscura="$coretmp/obscura"
  fi
fi
if [[ -x "$src_aitm" && -x "$src_obscura" ]]; then
  mkdir -p "$coredir"
  cp "$src_aitm" "$coredir/aitm"
  cp "$src_obscura" "$coredir/obscura"
  chmod 755 "$coredir/aitm" "$coredir/obscura"
  echo "bundled embedded core: $coredir/{aitm,obscura}"
else
  echo "no embedded core bundled (set AITM_CORE_DIR or CORE_TARBALL, or run scripts/package.sh); app will use an external core"
fi

# --- Network/System Extension capture path (Band C Task 10/14) ---------------
# Build and embed the sysex for an --ne build. ne_identity and the two profiles were
# resolved near the top (where --ne also selected /Applications as the install dir).
# The restricted NE entitlements must be authorised by an embedded Developer ID
# profile, and the Task-1 spike proved the sysex activates only when the app is
# Developer-ID-signed, NOTARIZED, and in /Applications. A normal ad-hoc or Apple
# Development dev build leaves sysex_bundle empty and is unaffected.
sysex_id="com.mrbrutti.aitmproxy.ne"
sysex_bundle=""
if [[ -n "$ne_identity" ]]; then
  ext="$here/Extension"
  sdk=$(xcrun --show-sdk-path --sdk macosx)
  nebin="$scratch/AitmproxyNE"
  xcrun swiftc -sdk "$sdk" -target "$(uname -m)-apple-macos26.0" -module-name AitmproxyNE \
      -framework NetworkExtension -o "$nebin" "$ext/Sources/"*.swift
  sysex_bundle="$app/Contents/Library/SystemExtensions/$sysex_id.systemextension"
  mkdir -p "$sysex_bundle/Contents/MacOS"
  cp "$nebin" "$sysex_bundle/Contents/MacOS/AitmproxyNE"
  sed -e "s/__BUILD__/$(date +%Y%m%d%H%M)/" -e "s/__VERSION__/$version/" "$ext/Info.plist" > "$sysex_bundle/Contents/Info.plist"
  cp "$ne_sysex_profile" "$sysex_bundle/Contents/embedded.provisionprofile"
  cp "$ne_app_profile" "$app/Contents/embedded.provisionprofile"
  echo "built + embedded system extension: $sysex_bundle"
else
  echo "no system extension embedded (pass --ne; it needs a Developer ID identity + the two NE profiles, see NE_SIGN_IDENTITY / NE_APP_PROFILE / NE_SYSEX_PROFILE)"
fi

xattr -cr "$app"
# Sign inside-out: Mach-O binaries nested in Resources are not sealed by signing
# the outer bundle, so sign the embedded core first (hardened runtime), then the
# app. notarize-dmg.sh repeats this with the Developer ID identity for release.
# An NE build signs the whole bundle (core + sysex + app) with the Developer ID
# identity for a coherent, notarizable bundle; otherwise use the dev identity.
sign_identity="${ne_identity:-$identity}"
runtime_opts=(--options runtime)
[[ "$sign_identity" != "-" ]] && runtime_opts+=(--timestamp)
# codesign that ABORTS the build on a real failure while hiding the benign
# "replacing existing signature" chatter. A plain `… | grep -v … || true` lets
# grep's exit status mask codesign's, so a failed restricted-entitlement sign would
# still read as success — the very class of bug this NE work fixes.
cs() {
  local out
  if ! out=$(codesign "$@" 2>&1); then
    print -r -- "$out" >&2
    echo "build failed: codesign $*" >&2
    exit 1
  fi
  print -r -- "$out" | grep -v "replacing existing signature" || true
}
# obscura is Chromium-based: under the hardened runtime it needs JIT entitlements
# or it crashes (SIGTRAP) on V8 init. aitm (plain Rust) needs none.
obscura_ent="$here/EmbeddedObscura.entitlements"
if [[ -f "$coredir/obscura" ]]; then
  cs --force "${runtime_opts[@]}" --entitlements "$obscura_ent" --sign "$sign_identity" "$coredir/obscura"
fi
if [[ -f "$coredir/aitm" ]]; then
  cs --force "${runtime_opts[@]}" --sign "$sign_identity" "$coredir/aitm"
fi
# The system extension signs inside-out BEFORE the app, with its own restricted
# NE entitlements (Task 14). The app is then signed with its NE entitlements too,
# fixing the prior --force/no---entitlements regression that silently blocks
# activation. Non-NE dev builds keep the plain app signature (no entitlements).
app_sign_opts=(--force)
if [[ -n "$sysex_bundle" ]]; then
  cs --force "${runtime_opts[@]}" --entitlements "$here/Extension/Aitmproxy-Extension.entitlements" --sign "$sign_identity" "$sysex_bundle"
  app_sign_opts+=("${runtime_opts[@]}" --entitlements "$here/Aitmproxy.entitlements")
fi
cs "${app_sign_opts[@]}" --sign "$sign_identity" "$app"
echo "installed $app (signed: ${sign_identity})"

# Nothing here notarizes, and macOS refuses an unnotarized Developer ID system
# extension at activation (Settings ▸ Capture: "Degraded — Extension activation failed:
# code signature invalid", measured 2026-10-31). Say so where it cannot be missed.
if [[ -n "$sysex_bundle" ]]; then
  echo "WARNING: system extension embedded but NOT notarized — activation will fail with 'code signature invalid' until scripts/notarize-dmg.sh runs; the notarized DMG is the only path to a working capture extension"
  if (( ! allow_unnotarized )); then
    echo "build.sh: exit 1 — pass --allow-unnotarized when this build is the input to scripts/notarize-dmg.sh (APP=$app)"
    exit 1
  fi
fi

if [[ " $* " == *" --open "* ]]; then
  osascript -e "quit app \"$name\"" 2>/dev/null || true
  sleep 0.5
  open "$app"
fi
