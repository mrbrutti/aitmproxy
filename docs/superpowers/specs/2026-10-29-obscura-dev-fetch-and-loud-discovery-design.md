# Spec: obscura dev-fetch + loud discovery

Status: Approved (autonomous, per Matt's standing autonomous-operation instruction — self-approve specs/plans/merges, ping only for KEY calls).
Date: 2026-10-29
Author: obscura-packaging-fix session

## Problem

`aitm` discovers the forked `obscura` browser engine next to its own executable
(`current_exe()` → `<exe_dir>/obscura`), via `AITM_OBSCURA_BIN`, or via a config
key. Release packaging (`scripts/package.sh`, `scripts/package-linux.sh`) fetches
`obscura` from the private `mrbrutti/obscura` release and stages it beside `aitm`,
so a packaged install has it.

But there is **no supported path to get obscura into a development checkout**.
After `cargo build`/`cargo run -p aitm`, `target/debug/aitm` (and
`target/release/aitm`) have no `obscura` beside them, so every local run, demo,
and agent session that drives the browser fails. The failure, when it comes, is a
discovery error that lists probe paths but does not tell the operator the one
command that fixes it. Two concrete gaps:

1. **No dev-fetch.** Nothing drops the correct `obscura` asset next to the dev
   binaries without a full release package build.
2. **Quiet failure.** "obscura not found" does not name the fix.

Packaging itself (`package.sh`) is believed to work but has never been proven
end-to-end on this host; the v0.1.0 release died on a now-fixed nfpm bug.

## Goals

- A `scripts/fetch-obscura-dev.sh` that downloads the correct `obscura` asset for
  the host target from `mrbrutti/obscura` tag `aitm-v1` (override via
  `OBSCURA_TAG`), verifies it against the release `SHA256SUMS`, and drops a real
  `obscura` binary next to `target/debug/aitm` **and** `target/release/aitm`
  (honouring `CARGO_TARGET_DIR`), so `cargo run -p aitm`, local demos, and agent
  sessions have the browser with no package build.
- The "obscura not found" error names the exact fixes, dev path first:
  `scripts/fetch-obscura-dev.sh`, install a package, or set
  `AITM_OBSCURA_BIN`/`browser.obscura.binary`.
- Documentation in `scripts/README.md` and `docs/DEVELOPMENT.md`.
- Proof, not assertion: `package.sh` run on this host with the staged dir shown;
  the dev-fetch run and `aitm` shown spawning obscura.

## Non-goals

- No change to the discovery **order** or to packaging layout/behaviour.
- No new `xtask` crate or `Makefile` (neither exists today; the script is the
  entry point — the parent brief made these "if it fits", and neither fits
  cleanly).
- No root `README.md` (the repo intentionally has none; `scripts/README.md` and
  `docs/DEVELOPMENT.md` are the homes for this).
- No change to CI release flow (`release.yml` already builds Linux packages).

## Design

### `scripts/fetch-obscura-dev.sh`

Mirrors `package.sh`'s fetch+verify for consistency and so there is one trusted
download recipe:

1. `target=$(rustc -vV | sed -n 's/host: //p')`; `asset="obscura-${target}.tar.gz"`.
2. `tag=${OBSCURA_TAG:-aitm-v1}`, repo `mrbrutti/obscura`.
3. `gh release download "$tag" --repo mrbrutti/obscura --pattern "$asset"
   --pattern SHA256SUMS` into a temp dir.
4. Verify `$asset` against its `SHA256SUMS` line with `shasum -a 256 -c -`; a
   missing entry is a hard error (same guard as `package.sh`).
5. Extract `obscura` from the tarball once.
6. Resolve the target dir: `${CARGO_TARGET_DIR:-target}`. For each of
   `debug` and `release`, `mkdir -p` the profile dir and copy `obscura` into it,
   `chmod 755`, and on macOS clear `com.apple.quarantine`.
7. Print where it landed and the obscura `--version`.

Idempotent (re-running overwrites). Needs: `rustc`, `gh` (authenticated or
`GH_TOKEN`/`OBSCURA_GH_TOKEN`), `shasum`, `tar`; `xattr` on macOS.

### Loud discovery error (`crates/aitm-browser/src/obscura.rs`)

`discover_binary`'s not-found `bail!` becomes a multi-line, actionable message
that lists the paths tried and the fixes, dev path first. The "not the fork"
`bail!` in `probe` gains the same "run scripts/fetch-obscura-dev.sh" hint. No
behavioural change to discovery.

## Acceptance criteria

- **AC1** `scripts/fetch-obscura-dev.sh` on this host downloads
  `obscura-aarch64-apple-darwin.tar.gz`, verifies its SHA, and leaves an
  executable `obscura` beside `target/debug/aitm` and `target/release/aitm`.
- **AC2** With obscura fetched, a built `aitm` resolves obscura via
  `current_exe()` and spawns it (obscura-backed lifecycle test passes with
  `AITM_OBSCURA=1`).
- **AC3** The not-found error text contains `scripts/fetch-obscura-dev.sh` and
  the package/`AITM_OBSCURA_BIN` fixes (unit-tested).
- **AC4** `scripts/package.sh` on this host produces
  `dist/aitm-<ver>-aarch64-apple-darwin.tar.gz` whose staged dir and tarball
  contain a real `obscura` beside `aitm`/`aitm-tui` (shown with `ls -l`/`tar
  -tzf`); a freshly unpacked `aitm` resolves and spawns obscura.
- **AC5** Full Rust gate passes; three-reviewer panel has no open findings.

## Discovered: pre-existing red gate on `main` (blocks AC5)

While running the gate for AC5, `cargo test` failed on a test unrelated to this
change: `aitm-poc` `runner::tests::protocol_step_dispatches_through_registered_command`.
Root cause: PR #68 added that test; PR #66 (a later commit on `main`) added the
`poc.run` agent-run gate at the top of `run_poc_command`
(`crates/aitm-poc/src/runner.rs`), which refuses a default (`Frontend::Mcp`) host
with no `poc.allow_agent_run`. PR #73 ("unbreak main gate") fixed the sibling
`l4_pocstep_wiring` poc.run tests but missed this one, so `main`'s CI has been
**red since #66** (confirmed via `gh run list`; last green run was #68). A red
gate blocks AC5 and would make this PR's CI red through no fault of this change,
so unbreaking it is in scope for "make aitmproxy ship properly … CI green".

Resolution: this was fixed independently on `main` by PR #74 ("fix: unbreak main
- poc.run agent gate refused protocol_step dispatch test"), which landed the same
fix (the test opts into `poc.allow_agent_run`) while this branch was in review.
This branch was rebased onto that commit and its own redundant `runner.rs` commit
dropped, so the PR no longer carries a `runner.rs` change — `main` is green again
via #74, and this PR is purely the obscura dev-fetch + loud-discovery work.

## File scope

- New: `scripts/fetch-obscura-dev.sh`, `docs/DEVELOPMENT.md`,
  this spec, the plan.
- Edit: `crates/aitm-browser/src/obscura.rs` (two error strings),
  `crates/aitm-browser/tests/obscura_spawn.rs` (assert AC3),
  `scripts/README.md` (document the script).
- (The gate-unbreak `crates/aitm-poc/src/runner.rs` edit was dropped: PR #74
  landed the same fix on `main` first; this branch rebased onto it.)
