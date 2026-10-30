# Plan: obscura dev-fetch + loud discovery

Status: Approved (autonomous, per Matt's standing autonomous-operation instruction).
Spec: ../specs/2026-10-29-obscura-dev-fetch-and-loud-discovery-design.md
Date: 2026-10-29

Small change; implemented in one worktree/branch, one commit, then gate + panel.

## Task 1 — dev-fetch script

- Write `scripts/fetch-obscura-dev.sh` per spec §Design.
- Test: run it on this host; assert an executable `obscura` lands beside
  `target/debug/aitm` and `target/release/aitm` and prints a version (AC1).

## Task 2 — loud discovery error (test-first)

- In `crates/aitm-browser/tests/obscura_spawn.rs`, extend `discovery_order` (or
  add a focused test) to assert the not-found error text contains
  `scripts/fetch-obscura-dev.sh` and the package/`AITM_OBSCURA_BIN` hints. Watch
  it fail.
- In `crates/aitm-browser/src/obscura.rs`, rewrite the not-found `bail!` in
  `discover_binary` and the "not the fork" `bail!` in `probe` to the actionable
  multi-line messages. Watch the test pass. No discovery-order change (AC3).

## Task 3 — docs

- Add a `fetch-obscura-dev.sh` paragraph to `scripts/README.md`.
- Create `docs/DEVELOPMENT.md`: how to get obscura into a dev checkout, the
  discovery order, and the troubleshooting line for the loud error.

## Verification

- AC2: `AITM_OBSCURA=1 cargo test -p aitm-browser --test obscura_lifecycle`
  (obscura fetched by Task 1) — the obscura-backed lifecycle test spawns it.
- AC4: `scripts/package.sh`; show staged dir `ls -l`, `tar -tzf` the output,
  unpack into a clean dir, and run the unpacked `aitm` so it resolves + spawns
  obscura.
- AC5: `cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
  cargo test`; then security/quality/spec reviewers in parallel.

## Review log

(filled during panel review)

## Shipped

(filled at integration)
