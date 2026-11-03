#!/bin/zsh
# Build a debug dev bundle and launch it LIVE against its embedded core on an isolated APP_STORE,
# WITHOUT signing or touching ~/Applications/Aitmproxy.app (the copy you run day to day). Builds to
# a scratch dir, assembles a throwaway bundle in /tmp by reusing the installed bundle's Info.plist
# + icon, swaps in the fresh debug binary, copies a core in, and starts it. This is the iteration
# loop; ./build.sh signs + installs and is for releases.
#
# Usage: DEV_TAG=<tag> CORE_DIR=<dir with aitm> tools/snap-dev.sh
#        NO_LAUNCH=1 DEV_TAG=<tag> CORE_DIR=<dir> tools/snap-dev.sh   only builds and assembles
#        DEV_TAG gives each session (or worktree) its own scratch dir, bundle and store, so two
#        never overwrite each other. CORE_DIR (e.g. the repo's target/release) is the core the
#        bundle runs; without it the installed app's embedded core is borrowed.
set -u
here=${0:A:h:h}
name=Aitmproxy
[[ -z ${DEV_TAG:-} || $DEV_TAG =~ ^[A-Za-z0-9_-]+$ ]] || { echo "DEV_TAG must match [A-Za-z0-9_-]+"; exit 1; }
tag=${DEV_TAG:+-$DEV_TAG}
scratch="$HOME/Library/Developer/$name/ui-redesign$tag"

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
# one keeps running. The bundle id stays the same.
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
# The borrowed installed plist predates the NSApplication subclass and would silently run stock
# NSApplication; the value comes from the template rather than being spelled here, so it cannot drift.
principal_class="$(plutil -extract NSPrincipalClass raw -o - "$here/Info.plist.in")"
plutil -replace NSPrincipalClass -string "$principal_class" "$dev/Contents/Info.plist"
# The installed bundle's embedded core (aitm + obscura), when present, so the dev build runs
# LIVE against its own core for end-to-end checks.
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
echo "== bundle $dev ($exe) · principal class $principal_class"

if [[ ${NO_LAUNCH:-} == 1 ]]; then
  echo "== build only (NO_LAUNCH=1) · $dev"
  exit 0
fi
# A fresh, isolated store per tag: the harness defaults suite is wiped at startup under APP_STORE,
# so the dev bundle never reads or writes the operator's settings or database. Wiped only on a
# launch, below the NO_LAUNCH exit: a build-only run while a dev bundle is running must not delete
# its store from under it.
store="/tmp/$name-dev-state$tag"
rm -rf "$HOME/Library/Saved Application State/com.mrbrutti.aitmproxy.savedState" "$store"
# /tmp is shared: nothing legitimate can exist at $store after the rm -rf above, so a plain
# mkdir (no -p) fails on anything that appeared in between, and the check refuses a symlink
# (-O and -d follow links; -L does not) as well as a directory another user owns.
mkdir "$store" || { echo "store $store already exists; refusing to launch"; exit 1; }
[[ ! -L $store && -O $store && -d $store ]] || { echo "store $store is not a directory we own; refusing to launch"; exit 1; }
# Live launch: the bundle talks to the core copied in above (or, under APP_LIVE=1 + AITM_CONFIG,
# to an external one). There is no fixture, snapshot or gallery mode to launch instead.
unsetopt bg_nice  # zsh nices background jobs by default; the app runs at normal priority, as from Finder
APP_STORE="$store" "$dev/Contents/MacOS/$exe" &
pid=$!
# Stopping: SIGTERM ends the app without its AppKit teardown, so the embedded core and its
# obscura child survive (parent 1) — reap them by the bundle path (scoped; never a global pkill).
echo "== launched pid $pid · store $store"
echo "== stop: kill $pid; pkill -f $dev/Contents/Resources/core/"
