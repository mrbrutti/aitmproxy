# Release runbook

How to cut a public aitmproxy release: one tag drives CI, which builds and
attaches every Linux artifact; Matt builds, signs, and uploads the macOS
artifacts on his Mac; a re-run of the `finalize` job rolls the macOS assets
into `SHA256SUMS` and the website manifest; and the private Homebrew tap is
updated out-of-band.

A release produces, on a public GitHub Release for tag `v<ver>`:

- Linux (per arch `x86_64` and `aarch64`): `aitm-<ver>-<triple>.tar.gz`,
  `aitm-<ver>-<arch>.deb`, `aitm-<ver>-<arch>.rpm` — built in CI.
- macOS (`aarch64` only): `aitm-<ver>-aarch64-apple-darwin.tar.gz` and
  `Aitmproxy-<ver>.dmg` — built, signed, and notarized on Matt's Mac.
- `SHA256SUMS` covering every asset, and `site/downloads.json` — written by the
  `finalize` job.

Legend: steps marked **[Terminal]** must run in the human Terminal panel (git,
`gh`, downloads — the Claude sandbox cannot reach GitHub or create `.git`).
Steps marked **[Matt/Apple]** need Matt's Apple Developer ID and App Store
Connect key and can only run on his Mac; an agent cannot do them.

## Assumptions / KEY decisions

These are the four KEY decisions from the design spec
(`docs/superpowers/specs/2026-10-29-aitmproxy-distribution-packaging-design.md`,
"KEY decisions for Matt") recorded here as the runbook's operating assumptions.
If any changes, this runbook changes with it:

1. **macOS is signed locally, not in CI (KEY #1).** The Developer ID cert and
   App Store Connect `.p8` key are Matt's identity and live only on his Mac;
   they are deliberately kept out of CI secrets. So CI builds Linux only, and
   steps 3 below run on Matt's Mac.
2. **The public Release lives in the main `aitmproxy` repo (KEY #2).** The
   website's download links must be fetchable by a tokenless visitor, so the
   Release and its assets are public, in the main repo — not in the private
   tap repo.
3. **The Homebrew tap is updated manually (KEY #3).** `mrbrutti/homebrew-aitmproxy`
   is a separate private repo. The release workflow does **not** push to it (that
   would need a write-scoped token as a CI secret); Matt bumps the formula and
   cask by hand per step 5.
4. **macOS is arm64-only for now (KEY #4).** Only `aarch64-apple-darwin`
   artifacts ship. An Intel macOS tarball can be added later cheaply; a
   universal notarized app is deferred.

The full Rust gate must be green before you tag:

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

## Steps

### 1. Bump the version and commit

Bump the `aitm` crate version in its `Cargo.toml` to the new `<ver>`, then
commit. The tag you push in step 2 must be exactly `v<ver>` where `<ver>`
equals `cargo pkgid -p aitm`'s version — CI's `version-guard` job fails the
release otherwise.

### 2. Tag → CI builds the Linux artifacts  **[Terminal]**

Push the tag:

```bash
git push origin v<ver>
```

The push of a `v*` tag triggers `.github/workflows/release.yml`:

- `version-guard` fails fast unless the tag `v<ver>` matches
  `cargo pkgid -p aitm`.
- `linux` (matrix over `x86_64` and `aarch64`) builds the web UI, builds
  `aitm` + `aitm-tui`, runs `scripts/package.sh` (tarball) and
  `scripts/package-linux.sh` (nfpm `.deb` + `.rpm`), and uploads each artifact
  to the Release.

Wait for the `linux` jobs to finish and confirm the tarball, `.deb`, and
`.rpm` for both arches are attached to the Release before continuing.

### 3. Build, sign, and upload the macOS artifacts  **[Matt/Apple]**

On Matt's Mac, in the repo checkout at the tagged commit:

```bash
# a. Build the macOS arm64 tarball (aitm + aitm-tui + obscura).
scripts/package.sh

# b. Bundle the embedded core (aitm + obscura) into Aitmproxy.app.
#    build.sh picks up the newest dist/aitm-*-<target>.tar.gz from step a.
apps/mac/build.sh

# c. Re-sign with the Developer ID + hardened runtime, build the DMG,
#    notarize it with Apple, and staple the ticket.
ASC_ISSUER_ID=<issuer-id> scripts/notarize-dmg.sh
```

`notarize-dmg.sh` refuses to notarize a core-less app, so step (a) and (b) must
run first. Then upload the two macOS assets to the Release **[Terminal]**:

```bash
gh release upload v<ver> \
  dist/Aitmproxy-<ver>.dmg \
  dist/aitm-<ver>-aarch64-apple-darwin.tar.gz
```

### 4. Re-run `finalize` so the checksums and manifest cover macOS

Now that every asset (Linux from CI + macOS from step 3) is attached, re-run the
`finalize` job via `workflow_dispatch` (input: `tag = v<ver>`). It downloads all
Release assets, writes a combined `SHA256SUMS` (one line per asset) and uploads
it, then runs `scripts/gen-downloads-manifest.sh` to regenerate
`site/downloads.json` and commits it to `main` so `pages.yml` redeploys the
download page with the macOS rows included.

Confirm `SHA256SUMS` and the updated `site/downloads.json` list the macOS DMG and
tarball.

### 5. Update the private Homebrew tap  **[Terminal, out-of-band]**

In the private tap repo `mrbrutti/homebrew-aitmproxy`, bump the formula and the
cask to the new release: update the version and the `sha256` values to match the
new Release assets (take the hashes from the `SHA256SUMS` from step 4), then
commit and push the tap repo. This is manual by decision (KEY #3); the release
workflow does not touch the tap.

### 6. Verify

- Homebrew: `brew fetch` (or `brew install`) from the updated tap and confirm it
  pulls the new version and its checksum matches.
- Linux: spot-check one package, e.g. `dpkg-deb --contents` /
  `dpkg -i ./aitm-<ver>-<arch>.deb` on Debian/Ubuntu or
  `rpm -qlp` / `sudo dnf install ./aitm-<ver>-<arch>.rpm` on Fedora/RHEL, and
  confirm `aitm` launches and finds `obscura` at `/usr/lib/aitmproxy/obscura`.
- Website: open the download page and confirm the new version's links resolve.
- Checksums: `shasum -a 256 -c SHA256SUMS` against the downloaded assets.
