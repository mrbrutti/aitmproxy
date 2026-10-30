#!/usr/bin/env bash
# Drop the forked obscura browser engine next to the dev `aitm` binaries, so a
# plain checkout can drive the browser without a full release package build.
#
# `aitm` discovers obscura beside its own executable (`current_exe()` →
# `<exe_dir>/obscura`). `cargo build`/`cargo run -p aitm` put `aitm` in
# `target/debug/` (or `target/release/` with `--release`), but nothing puts
# `obscura` there — this script does, for both profiles, so `cargo run -p aitm`,
# local demos, and agent sessions all find it. Packaged installs get obscura
# from `scripts/package.sh` / `scripts/package-linux.sh` instead.
#
# It downloads the correct asset for the host target from the obscura fork's
# GitHub Release and verifies it against the release `SHA256SUMS` — the same
# trusted recipe `package.sh` uses.
#
# Environment:
#   OBSCURA_TAG        release tag on mrbrutti/obscura to fetch (default: aitm-v1)
#   OBSCURA_GH_TOKEN   PAT with read access to the private mrbrutti/obscura repo;
#                      used as GH_TOKEN if set. Otherwise an authenticated `gh`
#                      (`gh auth login`) is used.
#   CARGO_TARGET_DIR   honoured when set, so the binaries land beside your actual
#                      build output (default: <repo>/target).
#
# Needs: rustc, gh (authenticated or OBSCURA_GH_TOKEN), shasum, tar; xattr on macOS.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

tag=${OBSCURA_TAG:-aitm-v1}
fork_repo=mrbrutti/obscura

# Let a PAT drive `gh` without an interactive login (CI, fresh machines).
if [ -n "${OBSCURA_GH_TOKEN:-}" ]; then
    export GH_TOKEN="$OBSCURA_GH_TOKEN"
fi

target=$(rustc -vV | sed -n 's/host: //p')
if [ -z "$target" ]; then
    echo "fetch-obscura-dev.sh: could not detect the host target triple from rustc -vV" >&2
    exit 1
fi
asset="obscura-${target}.tar.gz"

target_dir=${CARGO_TARGET_DIR:-$repo_root/target}

echo "fetch-obscura-dev.sh: host target ${target}, obscura ${tag} from ${fork_repo}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "fetch-obscura-dev.sh: downloading ${asset} and SHA256SUMS"
gh release download "$tag" --repo "$fork_repo" --dir "$work" \
    --pattern "$asset" --pattern SHA256SUMS

# SHA256SUMS is `sha256sum` output for every asset; check only ours.
expected=$(awk -v a="$asset" '$2 == a' "$work/SHA256SUMS")
if [ -z "$expected" ]; then
    echo "fetch-obscura-dev.sh: SHA256SUMS at ${tag} has no entry for ${asset}" >&2
    exit 1
fi
(cd "$work" && printf '%s\n' "$expected" | shasum -a 256 -c -)

# Extract just the obscura member once; copy it into each profile dir.
tar -xzf "$work/$asset" -C "$work" obscura

# Defence in depth: the member must be a real file, not a symlink that the `cp`
# below would dereference. A SHA-verified tarball is trusted, but assert anyway.
if [ ! -f "$work/obscura" ] || [ -L "$work/obscura" ]; then
    echo "fetch-obscura-dev.sh: extracted obscura is not a regular file" >&2
    exit 1
fi

copied=()
for profile in debug release; do
    dest_dir="$target_dir/$profile"
    mkdir -p "$dest_dir"
    dest="$dest_dir/obscura"
    cp "$work/obscura" "$dest"
    chmod 755 "$dest"
    # A download on macOS may carry Gatekeeper's quarantine flag; `aitm` would
    # otherwise fail to spawn `obscura`. Absent attribute is fine.
    if [ "$(uname -s)" = Darwin ]; then
        xattr -d com.apple.quarantine "$dest" 2>/dev/null || true
    fi
    copied+=("$dest")
done

echo "fetch-obscura-dev.sh: installed obscura:"
for dest in "${copied[@]}"; do
    echo "  $dest"
done

# Best-effort sanity check; never fail the fetch on it.
version=$("${copied[0]}" --version 2>/dev/null | head -n1 || true)
if [ -n "$version" ]; then
    echo "fetch-obscura-dev.sh: obscura reports: ${version}"
fi

echo "fetch-obscura-dev.sh: done. 'cargo run -p aitm' (debug) and"
echo "fetch-obscura-dev.sh: 'cargo run --release -p aitm' now find obscura beside aitm."
