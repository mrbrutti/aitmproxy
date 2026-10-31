#!/usr/bin/env bash
#
# sync-release-version.sh — rewrite every hard-coded release version in the
# README and the static site so they match the release manifest.
#
# site.js fills the version, release link and asset names at runtime from
# site/downloads.json, but the markup carries a literal fallback for readers
# without JavaScript, and README.md is never scripted. This keeps both current.
# The release workflow runs it right after regenerating the manifest and commits
# the result alongside it.
#
# Usage:
#   sync-release-version.sh [tag]
#
#   tag   release tag, e.g. v0.5.2. Defaults to the "tag" in site/downloads.json.
#
# Idempotent: running it twice with the same tag changes nothing.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
manifest="$root/site/downloads.json"

tag=${1:-}
if [ -z "$tag" ]; then
  if [ ! -f "$manifest" ]; then
    echo "error: no tag given and $manifest not found" >&2
    exit 2
  fi
  tag=$(sed -n 's/^[[:space:]]*"tag":[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -1)
fi
case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "error: tag must look like vX.Y.Z, got '$tag'" >&2; exit 2 ;;
esac
version=${tag#v}

# Each pattern anchors on a shape only a release version appears in, so prose
# that mentions an older version historically ("what shipped in v0.5.0") is
# left alone.
V='[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*'
rewrite() {
  local f=$1
  sed -i.bak \
    -e "s#\(data-release-tag[^>]*>\)v${V}<#\1${tag}<#g" \
    -e "s#releases/tag/v${V}#releases/tag/${tag}#g" \
    -e "s#releases/download/v${V}/#releases/download/${tag}/#g" \
    -e "s#aitm-${V}-#aitm-${version}-#g" \
    -e "s#Aitmproxy-${V}\.dmg#Aitmproxy-${version}.dmg#g" \
    -e "s#badge/release-v${V}-#badge/release-${tag}-#g" \
    "$f"
  rm -f "$f.bak"
}

changed=0
for f in "$root"/README.md "$root"/site/*.html; do
  before=$(cksum < "$f")
  rewrite "$f"
  after=$(cksum < "$f")
  if [ "$before" != "$after" ]; then
    echo "updated ${f#"$root"/}"
    changed=1
  fi
done
if [ "$changed" = 0 ]; then
  echo "already at ${tag}; nothing to change"
fi
