#!/bin/zsh
# Builds Aitmproxy and installs it to ~/Applications/Aitmproxy.app.
# Build products live in ~/Library/Developer/Aitmproxy, outside the repo
# (and outside Dropbox or iCloud, which would try to sync them).
#
# Usage: ./build.sh            release build, install
#        ./build.sh --debug    debug build, install
#        ./build.sh --open     install, then quit the running copy and open the new one
set -euo pipefail
here=${0:A:h}
name="Aitmproxy"
scratch="$HOME/Library/Developer/$name/build"
config=release
[[ " $* " == *" --debug "* ]] && config=debug

# Sign with your Apple Development certificate when you have one (Xcode >
# Settings > Accounts). Otherwise sign ad hoc, which is fine for your own Mac.
identity="${SIGN_IDENTITY:-}"
if [[ -z "$identity" ]]; then
  identity=$(security find-identity -v -p codesigning 2>/dev/null | grep -m1 -o '"Apple Development: [^"]*"' | tr -d '"' || true)
fi
[[ -n "$identity" ]] || identity=-

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

app="$HOME/Applications/$name.app"
mkdir -p "$HOME/Applications"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin" "$app/Contents/MacOS/$name"
# The app version tracks the workspace release (Cargo.toml [workspace.package]) so
# the DMG name, the bus handshake, and the cask all agree; APP_VERSION overrides.
version="${APP_VERSION:-$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version *= *"\([^"]*\)".*/\1/p' "${here:h:h}/Cargo.toml" | head -1)}"
[[ -n "$version" ]] || { echo "build failed: no app version (set APP_VERSION)"; exit 1; }
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

xattr -cr "$app"
# Sign inside-out: Mach-O binaries nested in Resources are not sealed by signing
# the outer bundle, so sign the embedded core first (hardened runtime), then the
# app. notarize-dmg.sh repeats this with the Developer ID identity for release.
runtime_opts=(--options runtime)
[[ "$identity" != "-" ]] && runtime_opts+=(--timestamp)
# obscura is Chromium-based: under the hardened runtime it needs JIT entitlements
# or it crashes (SIGTRAP) on V8 init. aitm (plain Rust) needs none.
obscura_ent="$here/EmbeddedObscura.entitlements"
if [[ -f "$coredir/obscura" ]]; then
  codesign --force "${runtime_opts[@]}" --entitlements "$obscura_ent" --sign "$identity" "$coredir/obscura" 2>&1 | grep -v "replacing existing signature" || true
fi
if [[ -f "$coredir/aitm" ]]; then
  codesign --force "${runtime_opts[@]}" --sign "$identity" "$coredir/aitm" 2>&1 | grep -v "replacing existing signature" || true
fi
codesign --force --sign "$identity" "$app" 2>&1 | grep -v "replacing existing signature" || true
echo "installed $app (signed: ${identity})"

if [[ " $* " == *" --open "* ]]; then
  osascript -e "quit app \"$name\"" 2>/dev/null || true
  sleep 0.5
  open "$app"
fi
