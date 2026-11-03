#!/usr/bin/env bash
# Focus one element of the INSTALLED Aitmproxy app by accessibility identifier (ax_focus.swift, built once
# per source hash into the same cache as ax_texts.sh). Prints `focused <identifier>` on success; exits
# non-zero with `refused: …` otherwise. Same refusals as the other drivers (app not running, a dev bundle
# present, no window) and the display-lock window is required because it changes keyboard focus.
# Usage: ax_focus.sh "<accessibility identifier>"
set -euo pipefail
ident="${1:-}"
[ -n "$ident" ] || { echo "usage: ax_focus.sh \"<identifier>\"" >&2; exit 2; }
pgrep -f '^/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy' >/dev/null || { echo "refused: the installed Aitmproxy is not running" >&2; exit 3; }
[ "$(pgrep -f 'Aitmproxy.app/Contents/MacOS/Aitmproxy' | wc -l | tr -d ' ')" = 1 ] || { echo "refused: more than one Aitmproxy process (a dev bundle is running)" >&2; exit 3; }
[ "${ACCEPT_WINDOW:-0}" = 1 ] || { echo "refused: ACCEPT_WINDOW=1 (the orchestrator's display-lock window) is not set" >&2; exit 3; }
here=$(cd "$(dirname "$0")" && pwd)
cache=${AX_TEXTS_CACHE:-/tmp/claude/acceptance/ax-cache}
bin="$cache/ax_focus-$(shasum -a 256 "$here/ax_focus.swift" | cut -c1-12)"
if [ ! -x "$bin" ]; then
  command -v swiftc >/dev/null 2>&1 || { echo "refused: swiftc not found; ax_focus needs the Xcode toolchain" >&2; exit 3; }
  [ -e "$cache/build-failed-$(basename "$bin")" ] && { echo "refused: ax_focus.swift failed to build earlier (see $cache/ax_focus-build.log)" >&2; exit 3; }
  mkdir -p "$cache"
  if swiftc -O -o "$bin.$$.tmp" "$here/ax_focus.swift" 2>"$cache/ax_focus-build.log"; then
    mv -f "$bin.$$.tmp" "$bin"
  else
    rm -f "$bin.$$.tmp"; touch "$cache/build-failed-$(basename "$bin")"; echo "refused: ax_focus.swift failed to build (see $cache/ax_focus-build.log)" >&2; exit 3
  fi
fi
exec "$bin" "$ident"
