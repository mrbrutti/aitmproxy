#!/usr/bin/env bash
# Build Linux native packages (.deb and .rpm) for aitmproxy, one target triple
# per invocation, from the single scripts/nfpm.yaml definition.
#
# Usage: scripts/package-linux.sh <target-triple>
#   scripts/package-linux.sh x86_64-unknown-linux-gnu
#   scripts/package-linux.sh aarch64-unknown-linux-gnu
#
# Output under dist/:
#   aitm-<ver>-<debarch>.deb   (debarch: amd64 | arm64)
#   aitm-<ver>-<rpmarch>.rpm   (rpmarch: x86_64 | aarch64)
#
# Payload per package (spec §B / docs/research/10-linux-packaging.md):
#   /usr/lib/aitmproxy/{aitm,obscura,aitm-tui}
#   /usr/bin/aitm      -> /usr/lib/aitmproxy/aitm       (symlink)
#   /usr/bin/aitm-tui  -> /usr/lib/aitmproxy/aitm-tui   (symlink)
# obscura is NOT in /usr/bin; aitm discovers it beside the resolved aitm.
#
# Environment:
#   OBSCURA_TAG        release tag on mrbrutti/obscura to fetch (default: aitm-v1)
#   MAINTAINER         package maintainer field (default below)
#   CARGO_BUILD_FLAGS  extra `cargo build` flags, e.g. "--target
#                      aarch64-unknown-linux-gnu" (cross) for a non-host arch;
#                      when it contains --target the binaries are read from
#                      target/<triple>/release. Leave empty to build for host.
#
# Needs: cargo, gh (authenticated), shasum, tar, npm, nfpm.
set -euo pipefail

target=${1:-}
if [ -z "$target" ]; then
    echo "package-linux.sh: usage: $0 <target-triple>" >&2
    exit 1
fi

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

tag=${OBSCURA_TAG:-aitm-v1}
fork_repo=mrbrutti/obscura
export MAINTAINER=${MAINTAINER:-"aitmproxy maintainers <noreply@anthropic.com>"}

# Map the Rust target triple to the obscura asset name and the nfpm arch
# values. nfpm's `arch` field takes a GOARCH value (amd64/arm64) and emits the
# correct deb arch; rpm names it differently, so track both for the output
# filenames.
case "$target" in
    x86_64-unknown-linux-gnu)
        goarch=amd64; debarch=amd64; rpmarch=x86_64 ;;
    aarch64-unknown-linux-gnu)
        goarch=arm64; debarch=arm64; rpmarch=aarch64 ;;
    *)
        echo "package-linux.sh: unsupported target '$target'" \
             "(expected x86_64/aarch64-unknown-linux-gnu)" >&2
        exit 1 ;;
esac
asset="obscura-${target}.tar.gz"

# `cargo pkgid` prints `…/crates/aitm#0.1.0` (or `…#aitm@0.1.0`); keep the
# version after the last `#` or `@`.
version=$(cargo pkgid -p aitm | sed 's/.*[#@]//')

echo "package-linux.sh: aitm ${version}, target ${target}, obscura ${tag}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Build the web UI FIRST: aitm's build.rs embeds apps/web/dist at compile time;
# dist/ is git-ignored, so without this the release binary ships an empty asset
# table and `aitm web` serves the "not built" placeholder.
echo "package-linux.sh: building the web UI (apps/web)"
( cd apps/web && npm ci && npm run build )

# Build aitm + aitm-tui for the target. CARGO_BUILD_FLAGS lets CI pass a cross
# target (e.g. "--target aarch64-unknown-linux-gnu") or swap in `cross` by
# pre-setting it; the host build needs no flag.
echo "package-linux.sh: cargo build --release -p aitm -p aitm-tui ${CARGO_BUILD_FLAGS:-}"
# shellcheck disable=SC2086
cargo build --release -p aitm -p aitm-tui ${CARGO_BUILD_FLAGS:-}

# A --target flag nests artifacts under target/<triple>/release.
bindir="target/release"
if printf '%s' "${CARGO_BUILD_FLAGS:-}" | grep -q -- '--target'; then
    bindir="target/${target}/release"
fi

echo "package-linux.sh: downloading ${asset} and SHA256SUMS from ${fork_repo}@${tag}"
gh release download "$tag" --repo "$fork_repo" --dir "$work" \
    --pattern "$asset" --pattern SHA256SUMS

# SHA256SUMS is `sha256sum` output for every asset; verify only ours.
expected=$(awk -v a="$asset" '$2 == a' "$work/SHA256SUMS")
if [ -z "$expected" ]; then
    echo "package-linux.sh: SHA256SUMS at ${tag} has no entry for ${asset}" >&2
    exit 1
fi
(cd "$work" && printf '%s\n' "$expected" | shasum -a 256 -c -)

# Stage the §B install layout under a prototype tree nfpm reads via STAGEDIR.
proto="$work/proto"
libdir="$proto/usr/lib/aitmproxy"
mkdir -p "$libdir"
tar -xzf "$work/$asset" -C "$libdir" obscura
cp "$bindir/aitm" "$libdir/aitm"
cp "$bindir/aitm-tui" "$libdir/aitm-tui"
chmod 755 "$libdir/aitm" "$libdir/aitm-tui" "$libdir/obscura"

mkdir -p dist

# These four are consumed by scripts/nfpm.yaml via ${...} expansion.
export VERSION="$version"
export ARCH="$goarch"
export STAGEDIR="$proto"

deb_out="dist/aitm-${version}-${debarch}.deb"
rpm_out="dist/aitm-${version}-${rpmarch}.rpm"

echo "package-linux.sh: nfpm pkg --packager deb -> ${deb_out}"
nfpm pkg --config scripts/nfpm.yaml --packager deb --target "$deb_out"

echo "package-linux.sh: nfpm pkg --packager rpm -> ${rpm_out}"
nfpm pkg --config scripts/nfpm.yaml --packager rpm --target "$rpm_out"

echo "package-linux.sh: wrote ${deb_out} and ${rpm_out}"
