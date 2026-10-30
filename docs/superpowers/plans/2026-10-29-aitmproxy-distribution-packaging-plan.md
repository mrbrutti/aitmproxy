# Cross-platform distribution & packaging implementation plan

**Status:** draft
**Spec:** `docs/superpowers/specs/2026-10-29-aitmproxy-distribution-packaging-design.md`
**Branch / worktree:** `claude/obscura-everywhere-packaging-e546ac`

## Overview

The work is shell scripts, one GitHub Actions workflow, static web assets, and
docs — no Rust. Task 1 (verify obscura's Linux deps + the symlink discovery) is a
prerequisite fact-finding step and gates the package definition. Task 2
(tarball payload) and Task 5/Task 6 (website) are independent of each other and
can fan out. Task 3 (nfpm packages) depends on Task 1 and Task 2's staging. Task 4
(release workflow) depends on Tasks 2 and 3. Task 7 (docs/runbook) depends on the
final layout but only for wording. Tasks marked **[Terminal]** need the human
Terminal panel (git/gh/download/install); tasks marked **[Matt/Apple]** need
Matt's signing identity and are runbook steps, not code the agent runs.

Because none of this is Rust, each task's "gate" is: `cargo fmt --check &&
cargo clippy --all-targets -- -D warnings && cargo test` still passes unchanged
(AC12), plus the task's own command assertions.

## Tasks

### Task 1: Verify obscura Linux runtime deps and symlink discovery  **[Terminal]**

- **Satisfies:** AC3, AC4
- **Depends on:** none
- **Files:** `docs/research/10-linux-packaging.md` (create); add an index row to `docs/research/README.md`.
- **Change:** Download `obscura-x86_64-unknown-linux-gnu.tar.gz` (and the aarch64 asset) from `mrbrutti/obscura@aitm-v1` via `gh`, extract into an isolated dir, and record: (a) whether `obscura` is a single self-contained binary or carries sibling `.so`/sandbox/resource files (list them); (b) `ldd obscura` output — the shared libraries it needs → the `Depends:`/`Requires:` package names for Debian/Ubuntu and Fedora/RHEL families; (c) a check that `std::env::current_exe()`-based discovery resolves a `/usr/bin/aitm` symlink to its `/usr/lib/aitmproxy` target (install the payload layout by hand or reason from the discovery code and confirm with a `readlink -f` + a manual `aitm` browser probe). Write the dependency list and the "obscura is/ isn't self-contained" verdict as the authoritative input for Task 3.
- **Test:** `docs/research/10-linux-packaging.md` states, with the actual `ldd`/`tar -tzf` output quoted, (1) the obscura payload file list, (2) the concrete `Depends`/`Requires` strings, (3) the discovery verdict. Reviewer confirms the quoted commands were run (evidence, not assertion).
- **Done when:** the note exists with quoted command output and a dependency list Task 3 can paste, and the gate passes.

### Task 2: Add `aitm-tui` to the generic tarball payload

- **Satisfies:** AC1, AC11
- **Depends on:** none
- **Files:** `scripts/package.sh` (modify); `scripts/README.md` (modify — payload note).
- **Change:** In `package.sh`, also `cargo build --release -p aitm-tui`, copy `target/release/aitm-tui` into the stage dir beside `aitm` and `obscura`, `chmod 755` it, and add it to the final `tar -czf … aitm aitm-tui obscura`. Keep the existing web-UI prebuild, obscura download + SHA256SUMS verification, and macOS quarantine strip. Do not add `aitm-testtarget-serve`.
- **Test:** run `bash scripts/package.sh` on the host, then `tar -tzf "$(ls -t dist/aitm-*-$(rustc -vV | sed -n 's/host: //p').tar.gz | head -1)" | sort` — expected exactly, in order: `aitm`, `aitm-tui`, `obscura`. Assert `aitm-testtarget-serve` is not in the listing.
- **Done when:** the tar listing equals those three names and the gate passes.

### Task 3: nfpm config + Linux package build script (.deb/.rpm)

- **Satisfies:** AC2, AC4, AC11
- **Depends on:** Task 1 (dependency list), Task 2 (staging shape)
- **Files:** `scripts/nfpm.yaml` (create — templated with `${…}` env vars for version/arch/deps); `scripts/package-linux.sh` (create); `scripts/README.md` (modify).
- **Change:** `package-linux.sh` takes a target triple, builds/stages `aitm` + `aitm-tui` + `obscura` (reuse Task 2's staging: build web UI, `cargo build --release -p aitm -p aitm-tui`, download+verify obscura) into a prototype tree `/usr/lib/aitmproxy/{aitm,obscura,aitm-tui}` with symlinks `/usr/bin/aitm` and `/usr/bin/aitm-tui`, then invokes `nfpm pkg --packager deb` and `--packager rpm` using `scripts/nfpm.yaml`. `nfpm.yaml` sets name `aitmproxy`, license `MIT OR Apache-2.0`, maintainer/homepage, the `contents:` entries (three files + two symlinks with the §B paths), and `depends:`/`recommends:` from Task 1. Arch is passed per invocation (`amd64`/`arm64` for deb, `x86_64`/`aarch64` for rpm). Output: `dist/aitm-<ver>-<arch>.deb` and `.rpm`.
- **Test:** `bash scripts/package-linux.sh x86_64-unknown-linux-gnu`, then `dpkg-deb --contents dist/aitm-*-amd64.deb` — expected to include lines for `./usr/lib/aitmproxy/aitm`, `./usr/lib/aitmproxy/obscura`, `./usr/lib/aitmproxy/aitm-tui`, and symlinks `./usr/bin/aitm -> /usr/lib/aitmproxy/aitm` and `./usr/bin/aitm-tui -> /usr/lib/aitmproxy/aitm-tui`; and `rpm -qlp dist/aitm-*-x86_64.rpm` lists `/usr/lib/aitmproxy/aitm`, `/usr/lib/aitmproxy/obscura`, `/usr/lib/aitmproxy/aitm-tui`, `/usr/bin/aitm`, `/usr/bin/aitm-tui`. `dpkg-deb --info` shows a non-empty `Depends:` matching Task 1 (or an in-file comment justifying empty).
- **Done when:** both listings match exactly and the gate passes. (nfpm installed via `go install`/release binary; builder's choice.)

### Task 4: Release workflow `.github/workflows/release.yml`  **[Terminal to tag]**

- **Satisfies:** AC5, AC6, AC7
- **Depends on:** Task 2, Task 3
- **Files:** `.github/workflows/release.yml` (create).
- **Change:** `on: push: tags: ['v*']` + `workflow_dispatch` (input `tag`). `permissions: { contents: write }`. Jobs: (1) `version-guard` — fail if the tag `v<X>` != `cargo pkgid -p aitm` version. (2) `linux` matrix over `{x86_64, aarch64}` — install Node + Rust (+ `cross` or aarch64 toolchain), run `scripts/package.sh` and `scripts/package-linux.sh`, upload `dist/*.tar.gz *.deb *.rpm` to the Release (`gh release upload` / `softprops/action-gh-release`). (3) `finalize` — `needs: [linux]`, also runnable standalone via `workflow_dispatch` after macOS assets are uploaded; downloads all Release assets, writes `SHA256SUMS` (one `shasum -a 256` line per asset), uploads it, then runs `scripts/gen-downloads-manifest.sh` (Task 5) to write `site/downloads.json` and commits it to `main`. No Windows job; no macOS build job (macOS assets are uploaded by Matt per the runbook).
- **Test:** `actionlint .github/workflows/release.yml` exits 0. Static assertions: the file contains `tags:` with `v*`, `workflow_dispatch`, a `version-guard` step comparing tag to `cargo pkgid`, a matrix with both triples, and a `finalize` job producing `SHA256SUMS`. (A live run is a Terminal/tag step recorded in the runbook, not a sandbox test.)
- **Done when:** `actionlint` passes, the structural assertions hold, and the Rust gate passes.

### Task 5: Website manifest generator + download-page rendering

- **Satisfies:** AC8, AC9
- **Depends on:** none (manifest schema is fixed by the spec §D)
- **Files:** `scripts/gen-downloads-manifest.sh` (create); `site/downloads.json` (create — a valid checked-in example for the current/placeholder version); `site/download.html` (modify — add a `data-downloads` container with the static Homebrew/source block as fallback); `site/site.js` (modify — fetch `downloads.json`, render rows).
- **Change:** `gen-downloads-manifest.sh` takes a tag + the owner/repo + the list of uploaded asset names and emits the §D JSON (version, tag, released date, release_url, assets[] each with platform/arch/format/name/url/sha256, sha256 read from `SHA256SUMS`). `site.js` fetches `downloads.json`, and if present builds one row per asset (platform, arch, format, SHA-256 short, download link) into `data-downloads`; on fetch failure it leaves the static fallback untouched and logs nothing to the console.
- **Test:** (a) schema — a Python `-I` check asserts `site/downloads.json` has keys `version, tag, release_url, assets`, and each asset has `platform, arch, format, name, url, sha256`; expected exit 0. (b) render — a minimal DOM check (jsdom or a documented manual check) that, given the example manifest, `site.js` inserts N `<tr>`/row nodes equal to `assets.length` into `data-downloads`, and that removing the manifest leaves the fallback block visible. State the literal expected row count from the example manifest.
- **Done when:** the schema check exits 0, the render produces exactly `assets.length` rows, the fallback survives a missing manifest, and the gate passes.

### Task 6: INSTALL.md Linux native-package section

- **Satisfies:** AC10
- **Depends on:** Task 3 (final layout)
- **Files:** `INSTALL.md` (modify).
- **Change:** Add a "Linux native packages" section: `.deb` (`sudo apt install ./aitm-<ver>-<arch>.deb` / `dpkg -i`) and `.rpm` (`sudo dnf install ./aitm-<ver>-<arch>.rpm`) one-liners; the `/usr/lib/aitmproxy` + `/usr/bin` layout; that `aitm-tui` is included and `obscura` is auto-discovered beside the resolved `aitm` (no config/env needed); the arch list (x86_64, aarch64) and that Windows is unsupported. Keep the from-source/cargo obscura-requirement text from PR #57.
- **Test:** `INSTALL.md` contains a "Linux native packages" heading, both `.deb` and `.rpm` install commands, the `/usr/lib/aitmproxy` path, and the word `aitm-tui`. (Prose; reviewer confirms accuracy against Task 3's actual layout.)
- **Done when:** the section is present and matches Task 3's real paths, and the gate passes.

### Task 7: Release runbook `docs/RELEASE.md`  **[Matt/Apple]**

- **Satisfies:** AC10
- **Depends on:** Task 4 (workflow shape), Task 3 (macOS/tap steps reference)
- **Files:** `docs/RELEASE.md` (create); `scripts/README.md` (modify — link it).
- **Change:** Ordered runbook: (1) bump `aitm` version, commit; (2) push tag `v<ver>` **[Terminal]** → CI builds + attaches Linux artifacts; (3) on Matt's Mac **[Matt/Apple]**: `scripts/package.sh`, `apps/mac/build.sh`, `ASC_ISSUER_ID=… scripts/notarize-dmg.sh`, then `gh release upload` the DMG + the `aarch64-apple-darwin.tar.gz`; (4) re-run the `finalize` job (`workflow_dispatch`) so `SHA256SUMS` + `site/downloads.json` cover the macOS assets; (5) update the private `mrbrutti/homebrew-aitmproxy` tap (formula + cask versions/sha) **[Terminal, out-of-band]**; (6) verify `brew fetch`. Call out every step needing the Terminal panel or Matt's Apple identity, and record the KEY decisions (signing local vs CI, release repo visibility, tap push-vs-manual, macOS arm64-only) as the runbook's assumptions.
- **Test:** `docs/RELEASE.md` lists the numbered steps in order, marks the `[Terminal]`/`[Matt/Apple]` steps, names `release.yml`, the three macOS scripts, and the tap repo. (Prose; reviewer confirms completeness against the spec KEY list.)
- **Done when:** the runbook is present and complete, and the gate passes.

## Review log

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|

## Shipped

Filled at stage 7.
