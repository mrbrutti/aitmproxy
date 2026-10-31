#!/usr/bin/env bash
# Bundle a release `aitm` with the obscura fork binary for the host target.
#
# Output: dist/aitm-<aitm version>-<target>.tar.gz containing `aitm`,
# `aitm-tui`, and `obscura` side by side. `aitm` finds `obscura` next to its own
# executable, so extracting the tarball anywhere is enough (spec M2 §D3,
# M2-AC19). `aitm-tui` is the detached operator UI shipped alongside the CLI
# (distribution spec §A).
#
# Environment:
#   OBSCURA_TAG   release tag on mrbrutti/obscura to fetch (default: aitm-v1)
#
# Needs: cargo, rustc, gh (authenticated), shasum, tar; xattr on macOS.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

tag=${OBSCURA_TAG:-aitm-v1}
fork_repo=mrbrutti/obscura

target=$(rustc -vV | sed -n 's/host: //p')
if [ -z "$target" ]; then
    echo "package.sh: could not detect the host target triple from rustc -vV" >&2
    exit 1
fi
asset="obscura-${target}.tar.gz"

# `cargo pkgid` prints `…/crates/aitm#0.1.0` (or `…#aitm@0.1.0`); keep the
# version after the last `#` or `@`.
version=$(cargo pkgid -p aitm | sed 's/.*[#@]//')

echo "package.sh: aitm ${version}, target ${target}, obscura ${tag}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Build the web UI FIRST. `aitm`'s build.rs embeds apps/web/dist at compile time;
# dist/ is git-ignored, so without this step the release binary ships an empty
# asset table and `aitm web` serves the "not built" placeholder. The prebuild
# hook runs `npm run tokens`; `build` is `tsc --noEmit && vite build`.
echo "package.sh: building the web UI (apps/web)"
( cd apps/web && npm ci && npm run build )

echo "package.sh: cargo build --release -p aitm"
cargo build --release -p aitm

echo "package.sh: cargo build --release -p aitm-tui"
cargo build --release -p aitm-tui

echo "package.sh: downloading ${asset} and SHA256SUMS from ${fork_repo}@${tag}"
gh release download "$tag" --repo "$fork_repo" --dir "$work" \
    --pattern "$asset" --pattern SHA256SUMS

# SHA256SUMS is `sha256sum` output for every asset; check only ours.
expected=$(awk -v a="$asset" '$2 == a' "$work/SHA256SUMS")
if [ -z "$expected" ]; then
    echo "package.sh: SHA256SUMS at ${tag} has no entry for ${asset}" >&2
    exit 1
fi
(cd "$work" && printf '%s\n' "$expected" | shasum -a 256 -c -)

stage="$work/stage"
mkdir -p "$stage"
tar -xzf "$work/$asset" -C "$stage" obscura
cp "target/release/aitm" "$stage/aitm"
cp "target/release/aitm-tui" "$stage/aitm-tui"
chmod 755 "$stage/aitm" "$stage/aitm-tui" "$stage/obscura"

# Ship the default detection catalogue beside the binary; aitm discovers it at
# `<exe_dir>/share/aitm/scripts` and loads the passive detectors by default.
mkdir -p "$stage/share/aitm/scripts"
# `/.` copies the CONTENTS of scripts/bundled (active/, http/, l4/, ws/, README)
# into the dest on both BSD cp (macOS) and GNU cp — a bare `scripts/bundled/`
# nests under `bundled/` on GNU cp, so pin the contents form.
cp -R scripts/bundled/. "$stage/share/aitm/scripts/"

# A download on macOS may carry Gatekeeper's quarantine flag; `aitm` would
# otherwise fail to spawn `obscura`. Absent attribute is fine.
if [ "$(uname -s)" = Darwin ]; then
    xattr -d com.apple.quarantine "$stage/obscura" 2>/dev/null || true
fi

mkdir -p dist
out="dist/aitm-${version}-${target}.tar.gz"
tar -czf "$out" -C "$stage" aitm aitm-tui obscura share

echo "package.sh: wrote ${out}"
tar -tzf "$out"
