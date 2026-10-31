#!/bin/zsh
# Debug-build page snapshots WITHOUT signing or touching ~/Applications/Aitmproxy.app
# (the copy you run day to day). Builds to a redesign scratch dir, assembles a
# throwaway bundle in /tmp by reusing the installed bundle's Info.plist + icon,
# swaps in the fresh debug binary, and captures light + dark snapshots there.
# This is the iteration loop; ./build.sh signs + installs and is for releases.
#
# Usage: tools/snap-dev.sh              all pages
#        tools/snap-dev.sh connections  one page (or a comma list)
#        DEV_TAG=insp tools/snap-dev.sh  own scratch/bundle/shots per session, so two
#                                        sessions (or worktrees) never overwrite each other
set -u
here=${0:A:h:h}
name=Aitmproxy
[[ -z ${DEV_TAG:-} || $DEV_TAG =~ ^[A-Za-z0-9_-]+$ ]] || { echo "DEV_TAG must match [A-Za-z0-9_-]+"; exit 1; }
tag=${DEV_TAG:+-$DEV_TAG}
scratch="$HOME/Library/Developer/$name/ui-redesign$tag"
pages=${1:-}

echo "== build (debug)"
swift build -c debug --package-path "$here" --scratch-path "$scratch" 2>&1 \
  | grep -E "error:|Build complete" || true
bin="$scratch/debug/$name"
[[ -x "$bin" ]] || { echo "build failed: no binary at $bin"; exit 1; }
# swift build can report success while an edited file failed to compile. Catch that.
stale=$(find "$here/Sources" -name '*.swift' -newer "$bin" | head -1)
[[ -z "$stale" ]] || { echo "build failed: binary is older than $stale"; exit 1; }

dev="/tmp/$name-dev$tag.app"
# With a tag the executable is "Aitmproxy-<tag>", so its process name differs from the installed
# app's and computer-use scripts (System Events, cgclick) can target this build while the real
# one keeps running. The bundle id stays the same so the fixture/snapshot defaults are shared.
exe="$name$tag"
# The installed bundle to borrow Info.plist, icons and the embedded core from: INSTALLED_APP, else
# the first of ~/Applications and /Applications (the DMG install) that carries Resources/core,
# else whichever exists (a stale coreless dev install must not win over the real app).
installed="${INSTALLED_APP:-}"
if [[ -z "$installed" ]]; then
  for candidate in "$HOME/Applications/$name.app" "/Applications/$name.app"; do
    [[ -d "$candidate/Contents/Resources/core" ]] && { installed="$candidate"; break; }
  done
fi
if [[ -z "$installed" ]]; then
  for candidate in "$HOME/Applications/$name.app" "/Applications/$name.app"; do
    [[ -d "$candidate" ]] && { installed="$candidate"; break; }
  done
fi
rm -rf "$dev"
mkdir -p "$dev/Contents/MacOS" "$dev/Contents/Resources"
cp "$bin" "$dev/Contents/MacOS/$exe"
if [[ -f "$installed/Contents/Info.plist" ]]; then
  plutil -convert xml1 -o "$dev/Contents/Info.plist" "$installed/Contents/Info.plist"
  cp "$installed/Contents/Resources/"*.icns "$dev/Contents/Resources/" 2>/dev/null || true
  cp "$installed/Contents/Resources/"*.car "$dev/Contents/Resources/" 2>/dev/null || true
else
  sed -e "s/__BUILD__/0/" -e "s/__VERSION__/0.0.0-dev/" "$here/Info.plist.in" > "$dev/Contents/Info.plist"
fi
plutil -replace CFBundleExecutable -string "$exe" "$dev/Contents/Info.plist"
# The installed bundle's embedded core (aitm + obscura), when present, so the dev build can also
# run LIVE (no APP_FIXTURES) against its own core for end-to-end checks; snapshots never spawn it.
# CORE_DIR=<dir with aitm + obscura> (e.g. the repo's target/release) overrides the installed
# bundle's core, so a dev build can run live against a core built from the current main.
if [[ -n "${CORE_DIR:-}" && -x "$CORE_DIR/aitm" ]]; then
  mkdir -p "$dev/Contents/Resources/core"
  cp "$CORE_DIR/aitm" "$dev/Contents/Resources/core/aitm"
  [[ -x "$CORE_DIR/obscura" ]] && cp "$CORE_DIR/obscura" "$dev/Contents/Resources/core/obscura"
  echo "== core from $CORE_DIR"
elif [[ -d "$installed/Contents/Resources/core" ]]; then
  cp -R "$installed/Contents/Resources/core" "$dev/Contents/Resources/core"
fi
echo "== bundle $dev ($exe)"

store="/tmp/$name-dev-state$tag"
shots="/tmp/$name-shots-dev$tag"
rm -rf "$HOME/Library/Saved Application State/com.mrbrutti.aitmproxy.savedState" "$store" "$shots"
mkdir -p "$store"
[[ -n "$pages" ]] && export APP_SNAPSHOT_PAGES="$pages"
echo "== snapshot ${pages:-all} -> $shots"
APP_STORE="$store" APP_FIXTURES=1 APP_SNAPSHOT="$shots" "$dev/Contents/MacOS/$exe"
echo "== done: $shots"
ls "$shots" 2>/dev/null
