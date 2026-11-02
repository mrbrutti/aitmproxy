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

## Terminal reporting

`tests/e2e/cli/term-reporting.sh` is the live proof for the wave-1 terminal
reporting (spec `docs/superpowers/specs/2026-11-01-cli-terminal-reporting-design.md`,
plan `docs/superpowers/plans/2026-11-01-cli-terminal-reporting-wave1-plan.md`,
Task 14). It boots the real binary and asserts the plan's literal
expectations, section by section: pre-boot `--version`/`--help` (nothing
created, < 100 ms), the plain piped startup (zero ESC bytes, one line per
phase, the `Label: value` card), the port-in-use panel, exit codes and usage
panels, the `0600` log file (content, `-vv`, rotation at 10 MiB,
`AITM_LOG_FILE`), warnings and the browser line, an unwritable log
directory, the raw `RUST_LOG`/`-v`/`-q` stream, stdout silence on the stdio
transport, token hygiene, `cli-startup.sh` unchanged, `live-env.mjs`
readiness, timing and thread count against the previous release, and the
`script`-recorded TTY sessions (in-place drawing, braille spinner, the M1
final screen, ASCII glyphs under `LC_ALL=C`, `NO_COLOR`/`CI`/`CLICOLOR_FORCE`/
`--color` precedence, the `aitm tui` handover).

```bash
tests/e2e/cli/term-reporting.sh                      # everything
AITM_TERM_SECTIONS=preboot,exitcodes tests/e2e/cli/term-reporting.sh
```

### Prerequisites

- A built `aitm` (`cargo build -p aitm`) — or set `AITM_BIN=/path/to/aitm`.
- `python3` on `PATH`: the script uses it to find free loopback ports, hold a
  port, grow the log for the rotation check, count bytes in the `script`
  casts and mint the test secrets. Without it the script exits 2 at once
  (`FATAL: python3 is required`) rather than mis-reporting every section as
  a sandbox that cannot bind a port.
- For section 14, `script` able to allocate a pty (see the SKIP reasons).

Run it **directly in a terminal** (not through `| tee`): section 14 records
real TTY sessions and is guarded by `[ -t 1 ]`; when stdout is a pipe it
SKIPs with that reason. Capture the output with `script -q <log> tests/e2e/cli/term-reporting.sh`
if you need a file. Exit status is non-zero if any assertion fails. Every
section uses an isolated `HOME` under a scratch dir with its own free ports;
nothing touches `~/Library/Application Support/aitmproxy`, the system proxy
or a keychain. Sections 2 and 14 run in a fresh `HOME`, where the newly
minted CA is in no trust store, so they prove the untrusted-CA path
(`· CA untrusted`, `▸ aitm ca install`, the `System proxy` row); the trusted
path is the recipe's run on the operator's own `HOME`.

### Environment

| Var                   | Default / meaning |
|-----------------------|-------------------|
| `AITM_BIN`            | `target/debug/aitm`, else `target/release/aitm`; the binary under test |
| `AITM_OLD_BIN`        | `/opt/homebrew/bin/aitm` when it exists; the previous release for the section-13 timing and thread-count comparison |
| `AITM_EXPECT_VERSION` | the workspace `Cargo.toml` `version`; what `aitm --version` must print |
| `AITM_TERM_SECTIONS`  | `all`; a comma list of sections by number or name (`preboot piped portinuse exitcodes log warnings unwritable raw stdout tokens clistartup liveenv perf tty`) |

The runner's own `RUST_LOG`, `NO_COLOR`, `CLICOLOR_FORCE`, `AITM_TERM`, `CI`,
`AITM_LOG_FILE`, `AITM_OBSCURA_BIN`, `AITM_TUI_LOG`, `AITM_CONFIG` and
`XDG_CONFIG_HOME` are unset for the run; each section states the variables it
needs on the command line.

### Documented SKIP reasons

A missing precondition is reported as `SKIP: …` (counted, never a FAIL):

- section 14, TTY recordings: stdout is not a TTY (`[ -t 1 ]`), or `script`
  cannot allocate a pty (the Claude sandbox);
- section 13, performance: `AITM_OLD_BIN` unset or not executable, or the old
  binary cannot read the generated config (warm-up failed);
- section 12, `live-env.mjs`: `apps/web/node_modules` missing or `node` not
  on `PATH`;
- the `obscura probed <version>` check: no `obscura` beside `AITM_BIN`
  (`scripts/fetch-obscura-dev.sh`);
- the `aitm-tui --help` check: no `aitm-tui` beside `AITM_BIN`
  (`cargo build -p aitm-tui`);
- section 7, unwritable log directory: running as root (`chmod 500` is not
  enforced).

### Token hygiene

Bus, bridge and operator tokens are generated into `0600` files, read into
shell variables and only ever compared with `grep -c -F`; the script never
prints one, and the failure-context dumps redact `#t=` URL fragments.

## Help

`tests/e2e/cli/help.sh` is the live proof for the wave-2 help product (spec
`docs/superpowers/specs/2026-11-01-cli-terminal-reporting-design.md`,
AC-W2-1 … AC-W2-10; plan
`docs/superpowers/plans/2026-11-01-cli-terminal-reporting-wave2-plan.md`,
Task 16). It runs the real binary and asserts the plan's literal
expectations, section by section: the top page (`aitm --help` = `aitm -h` =
`aitm help`, byte-identical; the first line, the `Groups:`/`Options:`/
`Examples:`/`Learn more:` headings, 19 groups with the bundled catalogue and
18 with `AITM_NO_BUNDLED_SCRIPTS=1`, zero ESC bytes when piped, nothing
created, median wall < 100 ms, no new package in `Cargo.lock`), every group
page (`aitm <group>` = `aitm help <group>` = `aitm <group> --help`; the
`scope` verbs and footer), every verb page (`Usage:`, `Flags:` with types
and `[required]`, `Examples:`; nothing booted, no log written), did-you-mean
and the no-dotted-names rule over six usage errors, the `Usage:`-form mode
errors and the Homebrew pins (`web operator UI`, `aitm-tui --help`), the
`[y/N]` prompt of `aitm ca install` recorded on a pty and **declined with
`n`** (the fingerprint on its own line; `--yes` is never passed, so no
keychain is written), the two sibling scripts, and the rich TTY rendering
(dim descriptions, bold headings, no cursor movement, `NO_COLOR`, and the
SGR-stripped page equal to the piped one line for line).

```bash
tests/e2e/cli/help.sh                                  # everything
AITM_HELP_SECTIONS=top,groups,verbs tests/e2e/cli/help.sh
```

### Prerequisites

- A built `aitm` (`cargo build -p aitm`) — or set `AITM_BIN=/path/to/aitm`.
  For the 19-group count, the bundled catalogue must be discoverable beside
  the binary (`scripts/bundled` for a dev build, `share/aitm/scripts` for an
  installed one); otherwise section 1 notes it and asserts 18.
- `aitm-tui` beside the binary (`cargo build -p aitm-tui`) for the
  `aitm-tui --help` pin; absent, that one check SKIPs.
- `python3` on `PATH` (the binary's real path for the catalogue lookup, byte
  counts in the `script` casts). Without it the script exits 2 at once
  (`FATAL: python3 is required`), as `term-reporting.sh` does.
- For sections 6 and 8, `script` able to allocate a pty (see the SKIP
  reasons).

Run it **directly in a terminal** (not through `| tee`): sections 6 (the
prompt) and 8 (the TTY rendering) record real TTY sessions and are guarded by
`[ -t 1 ]`; when stdout is a pipe they SKIP with that reason. Capture the
output with `script -q <log> tests/e2e/cli/help.sh` if you need a file. Exit
status is non-zero if any assertion fails. Every section uses a fresh,
isolated `HOME` under a scratch dir; no section serves a bus or opens a
port, nothing touches `~/Library/Application Support/aitmproxy`, the system
proxy or a keychain (section 6 reads the login keychain before and after
the declined prompt, on macOS, to show it is unchanged).

### Environment

| Var                   | Default / meaning |
|-----------------------|-------------------|
| `AITM_BIN`            | `target/debug/aitm`, else `target/release/aitm`; the binary under test |
| `AITM_EXPECT_VERSION` | the workspace `Cargo.toml` `version`; what the top page's first line must carry |
| `AITM_HELP_SECTIONS`  | `all`; a comma list of sections by number or name (`top groups verbs dym usage prompt siblings tty`) |

The runner's own `RUST_LOG`, `NO_COLOR`, `CLICOLOR_FORCE`, `AITM_TERM`, `CI`,
`AITM_LOG_FILE`, `AITM_CONFIG`, `XDG_CONFIG_HOME`, `AITM_NO_BUNDLED_SCRIPTS`,
`AITM_BUNDLED_SCRIPTS` and `AITM_SCRIPTS` are unset for the run; each section
states the variables it needs on the command line.

### Documented SKIP reasons

A missing precondition is reported as `SKIP: …` (counted, never a FAIL):

- sections 6 and 8, the prompt and the TTY rendering: stdout is not a TTY
  (`[ -t 1 ]`), or `script` cannot allocate a pty (the Claude sandbox);
- the `aitm-tui --help` pin: no `aitm-tui` beside `AITM_BIN`
  (`cargo build -p aitm-tui`);
- the `Cargo.lock` check: `git` unavailable, or neither
  `claude/cli-ux-terminal-reporting-64b09b` nor `origin/main` is a known ref.

Section 7 runs `cli-startup.sh` and `term-reporting.sh` (sections `preboot`
and `exitcodes`) against the same binary and needs what they need
(`python3`, loopback sockets); it takes a few minutes.
