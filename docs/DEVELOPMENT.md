# Local development

## Getting the obscura browser engine

aitmproxy drives an embedded browser — the forked **obscura** engine (a Rust
headless browser engine that embeds V8 and speaks CDP; it is not Chromium),
released as prebuilt binaries in the private `mrbrutti/obscura` repo. `aitm`
finds it at runtime in this order (`crates/aitm-browser/src/obscura.rs`,
`discover_binary`):

1. `browser.obscura.binary` in your config, if set;
2. `AITM_OBSCURA_BIN`, if set;
3. **`obscura` next to the `aitm` executable** (`current_exe()` → `<dir>/obscura`);
4. `obscura` on `PATH`.

A packaged install (the release `.deb`/`.rpm`/tarball, built by
`scripts/package-linux.sh` and `scripts/package.sh`) stages `obscura` beside
`aitm`, so step 3 just works. A plain `git clone` + `cargo build` does **not**: `cargo` puts `aitm` in
`target/debug/` (or `target/release/`), but nothing puts `obscura` there.

### One command

```bash
scripts/fetch-obscura-dev.sh
```

It detects your host target, downloads the matching `obscura-<triple>.tar.gz`
from `mrbrutti/obscura` (tag `aitm-v1`), verifies it against the release
`SHA256SUMS`, and copies a real `obscura` into both `target/debug/` and
`target/release/` (and clears macOS quarantine). After that:

```bash
cargo run -p aitm -- <args>            # debug build finds obscura (e.g. `-- web`, `-- tui`)
cargo run --release -p aitm -- <args>  # release build finds obscura
```

Re-run the script any time; it is idempotent and overwrites. It honours
`CARGO_TARGET_DIR`.

### Requirements

- `rustc`, `gh`, `shasum`, `tar` (`xattr` on macOS).
- Read access to the private `mrbrutti/obscura` repo. Either `gh auth login`, or
  set `OBSCURA_GH_TOKEN` to a PAT with read access (used as `GH_TOKEN`).
- Override the release tag with `OBSCURA_TAG` if you need a different obscura
  build.

### Troubleshooting

If a browser-driving command fails with **"obscura (the embedded browser engine)
was not found"**, obscura is not beside your `aitm` binary — run
`scripts/fetch-obscura-dev.sh` (the error message says the same, and lists the
`AITM_OBSCURA_BIN` / `browser.obscura.binary` overrides). If it fails with
**"is not the aitmproxy obscura fork"**, the binary found is some other
`obscura` (its `--help` does not list `--ca-cert`), not the aitmproxy fork;
re-run the fetch script or point `AITM_OBSCURA_BIN` at the fork.

## Running the obscura-backed tests

The browser integration tests are inert unless pointed at a real engine, so
`cargo test` stays hermetic. To run them against a fetched obscura:

```bash
scripts/fetch-obscura-dev.sh
AITM_OBSCURA=1 AITM_OBSCURA_BIN="$PWD/target/debug/obscura" \
  cargo test -p aitm-browser --test obscura_lifecycle -- --nocapture
```
