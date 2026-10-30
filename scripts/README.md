# scripts

`package.sh` builds the web UI (`apps/web`, via `npm ci && npm run build`, because
`aitm` embeds it at compile time), then `aitm` and `aitm-tui` in release mode,
downloads the matching
`obscura-<target>.tar.gz` for the host from the obscura fork's GitHub Release
(`mrbrutti/obscura`, a private repository, so `gh` must be authenticated with read
access to it; tag `OBSCURA_TAG`, default `aitm-v1`), verifies it against
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

`fetch-obscura-dev.sh` is the **development** counterpart: it drops the obscura
engine next to the dev binaries without a full package build. `aitm` discovers
obscura beside its own executable, but `cargo build`/`cargo run -p aitm` only put
`aitm` in `target/debug/` (or `target/release/`) — nothing puts `obscura` there.
Run `scripts/fetch-obscura-dev.sh` once: it detects the host target, downloads
and SHA256SUMS-verifies the matching `obscura-<triple>.tar.gz` (same source and
verification as `package.sh`), and copies a real `obscura` into both
`target/debug/` and `target/release/` (honouring `CARGO_TARGET_DIR`). Then
`cargo run -p aitm` and local demos drive the browser with no config, `PATH`
entry, or `AITM_OBSCURA_BIN`. Override the release tag with `OBSCURA_TAG`; supply
a PAT via `OBSCURA_GH_TOKEN` if `gh` is not logged in. See
[`docs/DEVELOPMENT.md`](../docs/DEVELOPMENT.md).

The macOS and release helpers:

- `make-dmg.sh` packages the `Aitmproxy.app` that `apps/mac/build.sh` installed
  into `dist/Aitmproxy-<version>.dmg` (`APP=` overrides the app path). It does not
  sign or notarize.
- `notarize-dmg.sh` re-signs that app with a Developer ID and the hardened
  runtime, builds the DMG with `make-dmg.sh`, notarizes it with `notarytool`, and
  staples the ticket. It needs `ASC_ISSUER_ID` (plus an App Store Connect `.p8`
  key) and refuses an app that does not bundle its embedded `aitm` + `obscura`
  core, so run `package.sh` then `apps/mac/build.sh` first.
- `gen-downloads-manifest.sh <tag> <owner/repo> <SHA256SUMS> <asset-name>...`
  prints the `site/downloads.json` manifest; the release workflow's `finalize`
  job runs it.
- `bus-agent-check.py` drives a live `aitm` over its loopback MCP bus the way an
  agent does and reports what works; `tui-live-check.sh embed|bus` drives the real
  TUI by keystrokes under tmux. Both bind ports, so run them in a real shell; see
  [`crates/aitm-tui/README.md`](../crates/aitm-tui/README.md).

For the full end-to-end release procedure — tag, let CI build the Linux
artifacts, build/sign/notarize the macOS DMG + tarball on Matt's Mac, re-run the
`finalize` job, and update the Homebrew tap — see the ordered runbook in
[`docs/RELEASE.md`](../docs/RELEASE.md).
