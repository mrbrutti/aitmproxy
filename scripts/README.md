# scripts

`package.sh` builds `aitm` in release mode, downloads the matching
`obscura-<target>.tar.gz` for the host from the obscura fork's GitHub Release
(`mrbrutti/obscura`, tag `OBSCURA_TAG`, default `aitm-v1`), verifies it against
the release's `SHA256SUMS`, strips macOS quarantine, and writes
`dist/aitm-<version>-<target>.tar.gz` containing exactly three files: `aitm`,
`aitm-tui`, and `obscura`. Extract that tarball anywhere and run `./aitm`: the
browser engine discovers `obscura` next to the `aitm` executable automatically,
so no `PATH` entry, config key, or `AITM_OBSCURA_BIN` is needed. `aitm-tui` is
the detached operator UI, shipped alongside the CLI.

`package-linux.sh <target-triple>` builds the Linux native packages for one
target (`x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu`). It prebuilds
the web UI, `cargo build --release -p aitm -p aitm-tui`, downloads and
SHA256SUMS-verifies the matching `obscura-<triple>.tar.gz` (same source and
verification as `package.sh`), stages the install layout, and runs `nfpm`
(`scripts/nfpm.yaml`) twice to write `dist/aitm-<ver>-<arch>.deb` and
`dist/aitm-<ver>-<arch>.rpm`. The three binaries install to
`/usr/lib/aitmproxy/{aitm,obscura,aitm-tui}` with `/usr/bin/aitm` and
`/usr/bin/aitm-tui` symlinks; `obscura` is not in `/usr/bin` — `aitm` discovers
it beside the resolved `aitm` binary. `.deb` depends on `libc6, libgcc-s1`;
`.rpm` requires `glibc, libgcc` (from `docs/research/10-linux-packaging.md`).
Needs `nfpm` on `PATH` (install via `go install` or its release binary). Set
`CARGO_BUILD_FLAGS="--target <triple>"` to cross-build a non-host arch.

For the full end-to-end release procedure — tag, let CI build the Linux
artifacts, build/sign/notarize the macOS DMG + tarball on Matt's Mac, re-run the
`finalize` job, and update the Homebrew tap — see the ordered runbook in
[`docs/RELEASE.md`](../docs/RELEASE.md).
