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
installed="$HOME/Applications/$name.app"
rm -rf "$dev"
mkdir -p "$dev/Contents/MacOS" "$dev/Contents/Resources"
cp "$bin" "$dev/Contents/MacOS/$name"
if [[ -f "$installed/Contents/Info.plist" ]]; then
  cp "$installed/Contents/Info.plist" "$dev/Contents/Info.plist"
  cp "$installed/Contents/Resources/"*.icns "$dev/Contents/Resources/" 2>/dev/null || true
  cp "$installed/Contents/Resources/"*.car "$dev/Contents/Resources/" 2>/dev/null || true
else
  sed -e "s/__BUILD__/0/" -e "s/__VERSION__/0.0.0-dev/" "$here/Info.plist.in" > "$dev/Contents/Info.plist"
fi

store="/tmp/$name-dev-state$tag"
shots="/tmp/$name-shots-dev$tag"
rm -rf "$HOME/Library/Saved Application State/com.mrbrutti.aitmproxy.savedState" "$store" "$shots"
mkdir -p "$store"
[[ -n "$pages" ]] && export APP_SNAPSHOT_PAGES="$pages"
echo "== snapshot ${pages:-all} -> $shots"
APP_STORE="$store" APP_FIXTURES=1 APP_SNAPSHOT="$shots" "$dev/Contents/MacOS/$name"
echo "== done: $shots"
ls "$shots" 2>/dev/null
