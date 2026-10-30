# Cross-platform distribution & packaging design

**Status:** draft
**Research inputs:** `docs/research/06-obscura-embedding.md`, `docs/research/07-ca-install.md`; memory `aitmproxy-release-pipeline`, `aitmproxy-mac-app-pipeline`; existing `scripts/package.sh`, `scripts/notarize-dmg.sh`, `apps/mac/build.sh`, `.github/workflows/pages.yml`, `site/download.html`, `INSTALL.md`.

## Intent

aitmproxy builds release artifacts by hand today: `scripts/package.sh` makes one host-triple `.tar.gz` (aitm + obscura), the macOS DMG is built and notarized locally, and the private Homebrew tap is updated out-of-band. There is no CI that builds or publishes anything, no native Linux packages (`.deb`/`.rpm`), the generic tarball omits `aitm-tui`, and the website download page is hardcoded marketing copy with no real per-platform links. This milestone makes releases reproducible and complete: one tag produces every per-platform artifact — each carrying all the binaries a user needs — attaches them to a GitHub Release, and surfaces them on the website, while keeping the one step that cannot be automated (Apple signing on Matt's Mac) local and explicit.

## Goals

- Every shipped artifact contains all the binaries a user needs for that surface (at minimum `aitm` + `obscura`; `aitm-tui` added everywhere), with a single documented payload matrix.
- Native Linux packages `.deb` and `.rpm` for `x86_64` and `aarch64`, plus the existing generic `.tar.gz`, built from one package definition.
- A GitHub Actions release workflow, triggered by a `v*` tag (and `workflow_dispatch`), that builds every Linux artifact, attaches them to the GitHub Release, generates a combined `SHA256SUMS`, and emits a machine-readable downloads manifest the website consumes.
- `site/download.html` presents real, current, per-platform download links driven by that manifest, with no site build step.
- The macOS signed/notarized DMG + macOS tarball and the Homebrew tap update remain part of a single documented release runbook, with their manual (Matt-only) steps called out.

## Non-goals

- Windows artifacts — obscura publishes no Windows asset. Explicitly out.
- An APT/YUM repository or GPG-signed Linux packages. Packages are attached to the Release and downloaded directly; no hosted package repo. (Future.)
- AppImage / Flatpak / Snap. (Future; see Design rationale.)
- man pages and shell completions — `aitm` does not generate them today; not added here.
- Changing obscura itself, the tap's private-download strategy, or the macOS app's bundle/sign mechanics (already landed; this milestone only orchestrates and documents them).
- Shipping `aitm-testtarget-serve` to end users.

## Anti-goals

- A release that Gatekeeper blocks (unsigned macOS binaries reaching users) or whose Linux package installs an `aitm` that cannot find `obscura`.
- A release workflow that requires Matt's Apple Developer ID or App Store Connect key to live in CI secrets without his explicit decision.
- A website download page that silently goes stale (links a version no longer current) or links assets a tokenless visitor cannot fetch.
- Two packaging code paths that can drift (e.g. a tarball payload that disagrees with the `.deb` payload).

## Constraints

- **Rust gate** unchanged: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`. This milestone adds shell/CI/web/doc files and no Rust; the gate must still pass.
- **Sandbox**: git, `gh`, port binding, and all Apple signing happen only in the human Terminal panel / on Matt's Mac, never in the Claude sandbox. Plan tasks that need them are marked.
- **obscura discovery** (frozen contract, `crates/aitm-browser/src/obscura.rs::discover_binary`): `browser.obscura.binary` → `AITM_OBSCURA_BIN` → `obscura` next to the resolved `aitm` executable (`std::env::current_exe()`, which resolves symlinks on Linux/macOS) → `obscura` on `PATH`. The Linux install layout is designed around step 3.
- **Web UI embed**: `aitm`'s `build.rs` embeds `apps/web/dist` at compile time; any path that builds a release `aitm` MUST run `apps/web` `npm ci && npm run build` first (already done in `package.sh`).
- **obscura source of truth**: `mrbrutti/obscura` tag `aitm-v1`, assets `obscura-<triple>.tar.gz` + `SHA256SUMS`, verified by checksum before bundling (already done in `package.sh`).

## Design

### A. Payload matrix (the "all necessary binaries" decision)

Every user-facing artifact carries `aitm`, `obscura`, and `aitm-tui`. `aitm-testtarget-serve` is excluded (dev/acceptance target, dual-use). The web UI is not a binary (embedded in `aitm`).

| Artifact | Arches | aitm | obscura | aitm-tui | testtarget | Built by |
|---|---|---|---|---|---|---|
| `aitm-<ver>-<triple>.tar.gz` (Linux) | `x86_64/aarch64-unknown-linux-gnu` | yes | yes | yes | no | CI (`package.sh`) |
| `aitm-<ver>-<triple>.deb` | `amd64`, `arm64` | yes | yes | yes | no | CI (`nfpm`) |
| `aitm-<ver>-<triple>.rpm` | `x86_64`, `aarch64` | yes | yes | yes | no | CI (`nfpm`) |
| `aitm-<ver>-aarch64-apple-darwin.tar.gz` (macOS) | `aarch64` | yes | yes | yes | no | Matt, local (`package.sh`, ad-hoc signed as today) |
| `Aitmproxy-<ver>.dmg` (macOS app) | `aarch64` | bundled in `Contents/Resources/core` | bundled | — (app drives the core; TUI not in the app) | no | Matt, local (`build.sh` → `notarize-dmg.sh`) |
| `SHA256SUMS` | — | covers every asset above | | | | CI finalize job |

**Decision — add `aitm-tui` to every CLI artifact (Architect's call).** The TUI is a separate standalone binary that connects to a running bus; a CLI user who installs `aitm` reasonably expects `aitm tui`'s standalone counterpart too. The in-`aitm` `aitm tui` subcommand stays; `aitm-tui` is the detached operator UI. Cost is one extra `cargo build -p aitm-tui`. It is **not** bundled in the macOS `.app` (the app is its own UI).

### B. Linux format & tool decision

**Decision — `nfpm` for both `.deb` and `.rpm` (Architect's call).** One `scripts/nfpm.yaml` templated per target produces both formats from a staged payload directory. Rationale vs `cargo-deb` + `cargo-generate-rpm`: (1) one config, two formats, no duplicated metadata; (2) nfpm packages arbitrary staged files — it fits aitm (a cargo artifact) + obscura (a downloaded, checksum-verified binary) + aitm-tui equally, whereas the cargo plugins are oriented to cargo build outputs and need per-crate `[package.metadata]`; (3) nfpm is a single static Go binary run in CI, needs no per-distro build host and no Ruby/rpmbuild toolchain; (4) it is arch-agnostic — the same config emits `amd64`/`arm64` deb and `x86_64`/`aarch64` rpm by flag.

**Install layout (Architect's call):**
- `/usr/lib/aitmproxy/aitm`, `/usr/lib/aitmproxy/obscura`, `/usr/lib/aitmproxy/aitm-tui`
- symlinks `/usr/bin/aitm` → `/usr/lib/aitmproxy/aitm`, `/usr/bin/aitm-tui` → `/usr/lib/aitmproxy/aitm-tui`
- `obscura` is **not** linked into `/usr/bin` (not a user command). It is found by discovery step 3: `current_exe()` resolves `/usr/bin/aitm` to `/usr/lib/aitmproxy/aitm`, so `exe_dir = /usr/lib/aitmproxy` and `obscura` sits beside it. (A plan task verifies this on a real install.)
- Package metadata: name `aitmproxy`, license `MIT OR Apache-2.0`, homepage/maintainer set; `Depends`/`Requires` set from the obscura runtime-dependency finding (Task 1), not guessed.

### C. Release trigger & workflow design

**Trigger:** push of a tag matching `v*`, plus `workflow_dispatch` (input: `tag`). Version is `v<cargo-pkgid aitm version>`; the tag and the crate version must agree (a workflow check fails otherwise).

**Split by trust boundary (Architect's call — recommend path (b)):**
- **CI (`ubuntu-latest`) builds all Linux artifacts.** A matrix over `{x86_64, aarch64}` builds the web UI, builds `aitm` + `aitm-tui`, runs `package.sh` for the tarball, and `scripts/package-linux.sh` (nfpm) for `.deb`/`.rpm`. `aarch64` is cross-built (`cross` or an `aarch64` runner — builder's choice, Left to builder). Each job uploads its artifacts to the GitHub Release.
- **macOS signed artifacts are built locally by Matt** on his Mac (`package.sh` → `build.sh` → `notarize-dmg.sh`) and uploaded to the same Release. CI does not sign. Rationale: the Developer ID cert + ASC key are Matt's identity and already live only on his Mac; putting them in CI secrets is a separate, higher-risk decision (KEY #1).
- **A `finalize` job** (runs after Linux jobs; re-runnable by `workflow_dispatch` once the macOS assets are uploaded) downloads every Release asset, computes a combined `SHA256SUMS`, uploads it, and generates `site/downloads.json` (manifest, §D), committing it to `main` (or opening a PR) so `pages.yml` redeploys the download page.

The workflow is net-new: `.github/workflows/release.yml`. Least-privilege `permissions:` (`contents: write` for the release + the manifest commit).

**KEY #1 (Matt):** local-signing vs CI-secrets for macOS. Recommended: local. The alternative (a `macos-14` runner with the Developer ID cert and ASC `.p8` as encrypted secrets) is specced as a fallback but gated on Matt's explicit approval because it exposes his signing identity to CI.

### D. Website downloads design

**Decision — generated manifest consumed by static JS (Architect's call).** The site has no build step; the only per-release change must be data, not hand-edited HTML. The `finalize` job writes `site/downloads.json`:

```
{ "version": "0.1.0", "tag": "v0.1.0", "released": "2026-10-29",
  "release_url": "https://github.com/<owner>/<repo>/releases/tag/v0.1.0",
  "assets": [ { "platform": "linux", "arch": "x86_64", "format": "deb",
               "name": "aitm-0.1.0-amd64.deb", "url": "https://…", "sha256": "…" }, … ] }
```

`download.html` gains a `data-downloads` container; `site/site.js` fetches `downloads.json` and renders a per-platform/format table with name, size/arch, and SHA-256. If the fetch fails or predates the manifest, the existing static Homebrew/source instructions remain as the fallback (progressive enhancement; no JS-only dead end).

**KEY #2 (Matt):** download links must be fetchable by a tokenless website visitor. That requires the GitHub Release (and its repo, or at least its release assets) to be **public**. Releases currently live in the private tap repo. Decision needed: host the public Release in the main `aitmproxy` repo (and make it/its releases public), vs keep private + have the site link only to Homebrew/source. Recommended: public Release in the main repo.

### E. Docs & runbook

- `INSTALL.md`: add a Linux "native packages" section (`.deb`/`.rpm` install one-liners, the `/usr/lib/aitmproxy` layout, that `aitm-tui` is included and `obscura` is auto-discovered). Keep the from-source/cargo obscura-requirement section (PR #57).
- `scripts/README.md` and a new `docs/RELEASE.md` runbook: the exact ordered release steps — tag, let CI build Linux, run the three macOS scripts locally, upload the DMG + macOS tarball, re-run `finalize`, update the private tap (KEY #3). The runbook names which steps need the Terminal panel and Matt's Apple identity.

**KEY #3 (Matt):** the Homebrew tap `mrbrutti/homebrew-aitmproxy` is a separate private repo; the release updates it out-of-band. Decision: does the workflow push the tap update (needs a token with write access to that private repo as a CI secret), or does Matt update the tap manually from the runbook? Recommended: manual in the runbook for now.

### F. Decisions deferred to Matt (summary, see Acceptance & KEY list)

macOS universal/Intel (KEY #4): recommend **arm64-only** shipped macOS artifacts now (matches current app/tap/Matt's Mac; universal needs a universal Swift build + both obscura darwin slices + Intel validation). obscura ships `x86_64-apple-darwin`, so adding an Intel macOS tarball later is cheap; the notarized universal app is the expensive part. Flagged for Matt.

## Acceptance criteria

1. **AC1 — payload complete (tarball).** `scripts/package.sh` on a given host produces `dist/aitm-<ver>-<triple>.tar.gz` whose `tar -tzf` listing is exactly `aitm`, `aitm-tui`, `obscura` (and nothing else). `aitm-testtarget-serve` is absent.
2. **AC2 — deb contents & layout.** `scripts/package-linux.sh` (nfpm) produces a `.deb` whose `dpkg-deb --contents` lists `./usr/lib/aitmproxy/aitm`, `./usr/lib/aitmproxy/obscura`, `./usr/lib/aitmproxy/aitm-tui`, and symlinks `./usr/bin/aitm` and `./usr/bin/aitm-tui`; and an `.rpm` whose `rpm -qlp` lists the same paths.
3. **AC3 — obscura discovery on a real install.** After installing the `.deb` on a matching Linux host, running `/usr/bin/aitm` (with the browser engine) resolves `obscura` at `/usr/lib/aitmproxy/obscura` via discovery step 3 (no `AITM_OBSCURA_BIN`, no config key) — verified by the probe succeeding or by a logged `obscura probed binary=/usr/lib/aitmproxy/obscura`.
4. **AC4 — obscura runtime deps recorded.** The `.deb`/`.rpm` `Depends`/`Requires` list is derived from an actual inspection of the Linux obscura tarball (ldd / contents), documented, and non-empty-or-justified-empty — not guessed.
5. **AC5 — release workflow validates.** `.github/workflows/release.yml` passes `actionlint`; it triggers on `v*` tags and `workflow_dispatch`; it builds the Linux matrix, attaches tarball+deb+rpm per arch, and the `finalize` job produces `SHA256SUMS`.
6. **AC6 — tag/version guard.** The workflow fails fast when the pushed tag `v<X>` does not equal `cargo pkgid -p aitm`'s version.
7. **AC7 — combined checksums.** `SHA256SUMS` attached to the Release has one verifiable line per published asset; `shasum -a 256 -c SHA256SUMS` passes against the downloaded assets.
8. **AC8 — website manifest schema.** `site/downloads.json` validates against the documented shape (version, tag, release_url, assets[] with platform/arch/format/name/url/sha256); a checked-in example validates.
9. **AC9 — website renders downloads.** `site/download.html` + `site/site.js` render one row per manifest asset (platform, arch, format, SHA-256, link) when the manifest is present, and fall back to the static Homebrew/source instructions when it is absent, with no console error.
10. **AC10 — docs.** `INSTALL.md` documents `.deb`/`.rpm` install + layout + included `aitm-tui`; `docs/RELEASE.md` gives the ordered runbook and marks the Terminal-panel / Apple-identity steps.
11. **AC11 — no Windows, no testtarget.** No artifact or workflow job targets Windows; no artifact contains `aitm-testtarget-serve`.
12. **AC12 — gate.** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` still passes (no Rust changed).

## Left to the builder

- Whether `aarch64` Linux is built with `cross`, a native `aarch64` runner, or QEMU — any that yields a correct binary and passes AC2.
- The exact nfpm YAML field layout and the small staging-dir helper shape, as long as the payload and layout match §B.
- The `site.js` DOM/rendering details and `download.html` container markup, within the project's existing style, as long as AC9 holds.
- Whether `finalize` commits `downloads.json` directly to `main` or opens a PR.

## Open questions

See **KEY decisions for Matt** — these are the only blocking ones:

1. **macOS signing: local vs CI secrets?** (Recommended: local — Linux in CI, macOS DMG + tarball built & signed on Matt's Mac and uploaded.) Needs Matt's Apple Developer ID + App Store Connect key, which cannot be used by an agent.
2. **Where does the public GitHub Release live, and is it public?** The website needs tokenless download links. (Recommended: public Release in the main `aitmproxy` repo.) Current releases are in the private tap repo.
3. **Homebrew tap update: workflow-pushed or manual?** The tap is a separate private repo. Workflow-push needs a write-scoped token as a CI secret. (Recommended: manual via the runbook for now.)
4. **macOS universal/Intel?** (Recommended: arm64-only shipped artifacts now; add an Intel tarball later cheaply.) Universal notarized app is the expensive part.
5. **Linux package Depends/Requires + target distros:** confirm the distro set (Debian/Ubuntu + Fedora/RHEL families) so Task 1's dependency names are right; and confirm packages stay unsigned / no hosted repo for now.

---

**Summary.** One tag drives a `release.yml` that builds every Linux artifact — generic `.tar.gz`, `.deb`, and `.rpm` for `x86_64` and `aarch64`, each carrying `aitm` + `obscura` + `aitm-tui` under `/usr/lib/aitmproxy` with `/usr/bin` symlinks so obscura auto-discovers — attaches them to a public GitHub Release with a combined `SHA256SUMS`, and writes `site/downloads.json` that the static download page renders. macOS stays arm64-only: the signed/notarized DMG and macOS tarball are built on Matt's Mac and uploaded, because the signing identity cannot live in CI without his say-so. `nfpm` builds both Linux package formats from one config; Windows and hosted package repos are out.

**Architect's calls (approve or correct):** add `aitm-tui` to every CLI artifact (not the app); `nfpm` over the cargo plugins; install to `/usr/lib/aitmproxy` + `/usr/bin` symlinks relying on symlink-resolving `current_exe()`; CI does Linux only, Matt signs macOS locally (path b); arm64-only macOS for now; generated `site/downloads.json` manifest + static JS rather than hardcoded links or a live GitHub API call; unsigned Linux packages, no hosted repo; no man pages/completions; Windows out.
