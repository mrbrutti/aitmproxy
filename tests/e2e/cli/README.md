# CLI first-run e2e tests

Real functional tests for the `aitm` CLI's default first-run experience. They
boot the **real** `aitm` binary (no mocks) and assert the behaviour an operator
sees on a fresh install — the class of bug that green unit/snapshot tests kept
missing (obscura not found on a Homebrew install; `aitm web` printing success
and then crashing on a port it never checked).

## Run

```bash
tests/e2e/cli/cli-startup.sh
```

Exit status is non-zero if any assertion fails. Every test uses an isolated
`HOME` and its own free ports, so it never touches your real config/CA and never
needs 8080/8081/8082 to be free. Runnable repeatedly.

### Prerequisites

- A built `aitm` (`cargo build -p aitm`) — or set `AITM_BIN=/path/to/aitm`.
- For the obscura-discovery tests, the `obscura` engine beside the binary
  (`scripts/fetch-obscura-dev.sh`) — or set `OBSCURA=/path/to/obscura`. Absent,
  those cases are skipped (reported, not silently passed).

### Environment

| Var        | Default                                   |
|------------|-------------------------------------------|
| `AITM_BIN` | `target/debug/aitm`, else `target/release/aitm` |
| `OBSCURA`  | the `obscura` beside `AITM_BIN`           |

## What it asserts

- **obscura discovery** across package layouts: beside the binary (dev), the
  Homebrew `bin`→`libexec` symlink (single and the real double symlink), and a
  real `bin/aitm` with the engine only in a sibling `libexec/`.
- **`aitm web` starts clean**: prints the one-time agent URL, binds the proxy
  port too, and the web UI answers HTTP 200.
- **port conflict is graceful**: a taken proxy port yields one clear, actionable
  error *before* any success line — never `os error 48` after it — and a
  non-zero exit, for both `aitm web` and bare `aitm`.
- **one-shot verbs / operator-token / bad config**: `flow list` exits 0;
  `operator-token generate` writes the config and refuses to clobber without
  `--force`; a malformed config is a clear error naming the file, not a panic.

## Note for the tests/e2e runner (e2e-test-arch)

This script is self-contained (its own temp dirs, ports, PASS/FAIL tally, and
non-zero exit on failure) so it can run standalone today and be adopted by the
shared `tests/e2e/` runner later without rework.
