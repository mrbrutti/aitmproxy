# `aitm web` exits on SIGTERM from every launch shape (no stdio transport on a terminal) design

**Status:** approved (2026-11-03, orchestrator self-approval under the autonomous approve/merge mode; Open questions 1 and 2 stay Matt's and do not block this fix. Note on question 2: `aitm web`'s ready card prints `Bus: ready` (M6), not `stdio (MCP)`, so the row is already truthful in the withheld case)
**Research inputs:** `docs/research/26-aitm-web-sigterm-stopped-by-sigttin.md` (the runtime evidence, §4; the faithful reproduction, §5; directions A–C, §7), `docs/superpowers/specs/2026-11-01-cli-oneshot-live-core-design.md` (D2 the operator bus and its `Dedicated` lifecycle, D4 the pointer file, AC-R14-10, the §9 stdin-EOF exit), `docs/testing/2026-11-03-release-acceptance-0.5.18/README.md` run A (N4-WEB).
**Base:** `main` 1e891779 (v0.5.20). Branch `fix/web-sigterm-stdio-tty`.

## Intent

The 0.5.18 acceptance recorded "`aitm web` does not exit on SIGTERM", and the v0.5.19 and v0.5.20 release notes carry it as a known issue. The research shows the signal handling is present and works: the process was **stopped by SIGTTIN**. `aitm web` serves the default `mcp.transport: stdio` on whatever stdin it was given; when that stdin is the controlling terminal and the process is in a background process group (`aitm web &`, a nohup'd runner, a harness cell that keeps the shell's tty as stdin), its first `read(0)` stops the whole group, SIGTERM stays pending forever, and the proxy ports, the web port, the operator bus and the `run/cores/<pid>.json` pointer are all held until SIGKILL. This spec applies the TUI's existing rule to the web mode: a terminal stdin is not an MCP channel, so `aitm web` does not read it. After the fix, `aitm web` exits within a second of SIGTERM in every launch shape, with the durable audit flushed and the pointer removed, and a supervisor that hands it a pipe keeps today's stdio transport and the R14 stdin-EOF exit.

## Goals

- G1. `aitm web` started with a terminal as stdin from a background process group is never stopped (`ps` state not `T`); it serves the web UI, the proxy ports and the operator bus, and SIGTERM ends it with exit status 0 within 1 s, the web port refusing connections and the pointer gone.
- G2. `aitm web` started with a pipe as stdin behaves exactly as today: the stdio MCP transport is served on it, the R14 stdin-EOF exit still applies, and SIGTERM ends it with exit status 0 within 2 s (the R14 1 s grace for the blocked stdin read, plus teardown; measured 1.15 s).
- G3. On SIGTERM, in both shapes, a durable audit record written before the signal (the control stream, `mcp.audit_log`) is on disk after the exit, and `run/cores/<pid>.json` is removed. (Already what `run()` does; pinned here as acceptance criteria because the 0.5.18 run could not observe either.)
- G4. The decision is visible once, in the log, as a single `info` line with exact wording, and the operator-facing surfaces (reporter checklist, ready card, stderr) are unchanged.

## Non-goals

- Bare `aitm` with a terminal stdin. It is the stdio MCP server by design; its Ctrl-D exit is documented (R14 §9). Direction C of the research is a separate product decision, listed under Open questions for Matt, not changed here.
- `aitm tui`: `tui::build_servers` already refuses the stdio transport ("mcp.transport is stdio, which would share the terminal with the TUI; the agent transport is not served"). Not touched.
- The ready card. Its wording is pinned by the acceptance cells and spec rows (memory `aitmproxy-acceptance-cells-pin-panel-words`); no card text changes, including the `Bus  stdio (MCP)` row.
- Changing `runtime.shutdown_timeout(1 s)` (R14, PR #302) or anything about how the blocked stdin read is abandoned on the pipe path.
- Ignoring SIGTTIN (direction B). Rejected: the read would return `EIO`, the stdio arm would end with an error and a backgrounded `aitm web` would exit at launch instead of serving.
- Making the stdio transport interactive-aware in `aitm-mcp` (`serve_stdio` stays as it is; the decision lives in the binary's mode logic, as the TUI's does).
- Any change to the acceptance harness (`tests/e2e/acceptance/lib/run.sh`); the fix makes its existing shape work.

## Anti-goals

- A backgrounded `aitm web` that exits at launch, or that serves but whose SIGTERM exit leaks the pointer or an unflushed audit record. Either would turn a stop into a different failure.
- A foreground `aitm web` that starts reading the operator's keystrokes as JSON-RPC under some condition this spec did not name. The rule is exactly "stdin is a terminal → not served".
- A pipe-stdin `aitm web` (an MCP client or supervisor) that silently loses its stdio transport, or loses the R14 stdin-EOF exit.
- A token (web agent token, operator bridge token, `mcp.operator_token`) in the new log line, in any test log file, or in the test's own temp artefacts other than the `0600` config and the ready card on the pty.
- A second phase line, note, or warning on the operator's terminal for the first-run checklist.

## Constraints

- **Lint.** The workspace lint `unsafe_code = "forbid"` (`Cargo.toml:52`) is inherited by `crates/aitm` through `[lints] workspace = true` and covers its integration-test targets. `forbid` cannot be overridden by an `allow`. **No `unsafe` anywhere in this change, production or test** (see D4 for how the pty test gets its terminal without it). Restating the lint as `deny` in `crates/aitm/Cargo.toml` (the `aitm-peer-token` precedent) only to allow a test is rejected: it would weaken the lint on the main binary crate.
- **Dependencies.** No new Cargo dependency. `libc` is already a dependency of `crates/aitm` (constants only); nothing in this change uses it.
- **Security.** Never log a token. The new log line carries no path, no token, no port. `is_terminal()` is `isatty(3)`, a `tcgetattr` ioctl, which raises no job-control signal from a background group (only `read` raises SIGTTIN; only output and settings changes raise SIGTTOU), so the check itself cannot stop the process.
- **Operator surfaces.** The first-run reporter stays quiet: the decision is one `info` tracing line, not a reporter note, phase or warning, and not a `warn!` (the TUI's line is a `warn!`; here a terminal stdin is the expected shape of a terminal-launched `aitm web`, so nothing is wrong). **(Architect's call.)** The ready card is byte-for-byte unchanged in every mode.
- **R14.** `runtime.shutdown_timeout(Duration::from_secs(1))` in `main` is unchanged. The pipe path's measured exit after SIGTERM stays about 1.15 s; the AC bound is 2 s.
- **Where the tests run.** The two binary tests bind loopback sockets and spawn the binary, so they **cannot run in the coder sandbox** (memory `aitmproxy-sandbox-no-socket-binds`); they run from the Terminal panel, and in CI (`ubuntu-latest`, `cargo test`). They are part of the default `cargo test` set, not gated behind an env var, and must pass on macOS and Linux.
- **Hermetic tests.** Both binary tests use `env_clear()` plus `PATH`, `RUST_LOG=info`, `HOME`/`XDG_CONFIG_HOME` in the temp dir (the `audit_log_binary.rs` spawn pattern), `--config <temp>/config.yaml`, `AITM_RUN_DIR=<temp>/run/cores` for the pointer dir, `ca.dir` and `ca.audit_log` under the temp dir, `mcp.audit_log: <temp>/audit/audit.jsonl` with `AITM_AUDIT_LOG` unset (`env_clear` guarantees it), `listen`, `browser.proxy_addr` and `web --listen` on free ports (bind-and-release), `browser.obscura.binary` pointing at a nonexistent path inside the temp dir (so an installed obscura is never launched; the binary logs `embedded browser unavailable` and keeps serving), `--no-open`. `system_proxy.auto` defaults to `false`, so no OS state is touched; the state file lands beside the temp `ca.audit_log`. Obscura is not required: do not set or require `AITM_OBSCURA`.
- **Compatibility.** Behaviour of bare `aitm`, `aitm tui`, every one-shot verb, the macOS app's embedded core (launched over loopback TCP with a non-tty stdin) and any `aitm web` with a non-terminal stdin is unchanged.

## Design

### D1. The rule

In `run()` (`crates/aitm/src/main.rs`), in the server/web branch, the agent transport is served by `mcp.serve()` **unless all three hold**: `mode == Mode::Web`, `cfg.mcp.transport` is `McpTransport::Stdio`, and `std::io::stdin().is_terminal()` (the std trait `std::io::IsTerminal`, imported where used; `aitm-term/src/caps.rs` uses it on stdout and stderr today). When the three hold, the `select!` arm that today is `mcp.serve()` is `std::future::pending()` (the shape `web_run` already uses for the no-web case), so **no stdin read is ever issued**, and the `McpServer` built for the agent transport is dropped unused. The web bridge's second `McpServer` (`bus`, fed to `WebState`) and the operator bus are untouched: they are what a terminal-launched `aitm web` is for.

The decision is a pure function so a unit test can pin it without a terminal:

```rust
/// Whether the agent transport is served by `mcp.serve()` this run.
fn serve_agent_transport(mode: &Mode, transport_is_stdio: bool, stdin_is_terminal: bool) -> bool
```

`false` only for `(Mode::Web, true, true)`; `true` for every other combination (`Mode::Server` with a terminal stdin stays the stdio MCP server; a loopback or HTTP transport is unaffected by stdin; a pipe stdin in web mode is served). `Mode::Tui` never reaches this branch.

### D2. The log line

When the rule withholds the transport, `run()` emits exactly one `info!` line before the `select!`, with the message held in one place so the unit test and the call site cannot drift:

```rust
const WEB_STDIO_TTY_NOTE: &str =
    "mcp.transport is stdio and stdin is a terminal; aitm web does not serve the agent transport on it (an MCP client hands aitm a pipe)";
```

**(Architect's call** on the wording; it names the config key, the condition, the consequence and the one way to get the transport, in the voice of the TUI's existing line.) Default tracing target, `info` level, no fields. Nothing is printed by the reporter: no phase, no note, no warning. The ready card is printed exactly as today (`Bus  stdio (MCP)` included).

### D3. The stdin-EOF note

`stdio_eof_note(transport_is_stdio, &result)` keeps its signature and its text (`stdin closed · stdio MCP transport ended`, AC-W1-32). Its first argument becomes "the stdio transport was **served**": `stdio_transport && serve_agent_transport(..)`. With the transport withheld the arm is `pending()`, so it can never end `Ok` and the note is never produced; passing `false` makes that explicit and unit-testable without a terminal. The reporter's last line in the withheld case is therefore whatever ends the run (a SIGTERM run ends silently, as the loopback-TCP variant does today).

### D4. The regression test's terminal, without `unsafe`

The pty test (AC1) needs `aitm web` to hold the **controlling terminal as stdin while in a background process group**. The research shape uses `libc::openpty` + `setsid` + `TIOCSCTTY`, which is `unsafe` and forbidden here (Constraints). **(Architect's call:)** the test obtains the terminal through `python3 -c` and the standard library's `pty.fork()`, which does openpty + fork + `setsid` + controlling-tty in one call on both macOS and Linux. The Python child `exec`s `bash -c 'set -m; <aitm cmd> <&0 & echo PID $!; wait $!; echo EXIT $?'` (the research's exact shape, `set -m` putting the `&` job in its own process group so its tty read raises SIGTTIN before the fix); the Python parent relays the pty master to its stdout until EOF and waits for the child, so the Rust test reads `PID <n>`, the ready card and `EXIT <code>` as plain lines through `Command::output`-style pumping (the `pump` helper of `tests/shutdown.rs`). The Rust side sends `kill -TERM <pid>` itself and inspects `ps -o stat= -p <pid>` (first character `T` = stopped, identical on macOS and Linux). `python3` is on `PATH` on `ubuntu-latest` and on Matt's machine; when it is absent the test **fails** with a message naming it rather than skipping, because a regression test that silently skips is not a regression test. **(Architect's call.)** The Python is a short inline program passed as one argument (no file written next to the test, no interpreter run from a data directory); the plan carries it verbatim.

Rejected alternatives: `script(1)` (BSD and util-linux disagree on argument order, so one test would need two code paths; and CI is Linux while the bug was seen on macOS); restating the lint as `deny` (Constraints); gating the test behind an env var (it would never run in CI, where the bug's mechanism, tty job control, exists identically).

### D5. What the pipe-parity test proves in one run

One `aitm web` run with a **held pipe** stdin (the `ChildStdin` kept alive until after the signal) proves four things in order: (a) the stdio transport is served (an `initialize` JSON-RPC line written to stdin gets its reply line on stdout, which carries only JSON-RPC in stdio mode because tracing never writes to stdout, pin `tests/no_stdout_tracing.rs`); (b) the operator bus works and audits (a `scope.add` over the loopback operator bus through `tests/support/scripted_driver.rs::Client`, connecting to the `bus` address read from the pointer `AITM_RUN_DIR/<pid>.json` with the operator token the first run **minted** into the test config, read back from the `0600` config file as `tests/operator_token_dispatch.rs::token_in` does); (c) SIGTERM ends the run with status 0 within 2 s; (d) after exit the web port refuses connections, the pointer is gone, and `audit.jsonl` (the control stream) holds a line containing `"command":"scope.add"`. This is the parity figure of research §3 made permanent, and it is also the test AC4 asks for (no existing test drives the stdio transport over a pipe in web mode; `audit_log_binary.rs`'s web tests use a loopback-TCP transport and a null stdin).

### D6. Shutdown facts this spec relies on (unchanged code)

After the `select!` ends by the signal arm, `run()` restores the system proxy (a no-op with `auto: false`), quiesces the reporter, reaps the browser (none launched), flushes the durable audit (`handle.shutdown(SHUTDOWN_BUDGET)`), returns; dropping `OperatorBus` aborts the dedicated listener task, whose `LoopbackTcp` drop removes the pointer (R14 D2/D4). In the withheld-stdio case no blocking stdin read exists, so `runtime.shutdown_timeout(1 s)` returns at once and the whole exit takes the loopback-TCP variant's ~0.13 s. In the pipe case the read is still blocked and the exit takes ~1.15 s. The 1 s / 2 s bounds in the ACs follow.

### D7. Release note

The release note of the version that ships this drops the "`aitm web` does not exit on SIGTERM" Known-issues entry and adds one Fixed line: "`aitm web` launched from a terminal in the background (`aitm web &`, a nohup'd runner) was stopped by the terminal at its first stdin read and could only be ended by SIGKILL; it no longer serves the stdio MCP transport on a terminal stdin (a pipe stdin still gets it) and exits within a second of SIGTERM." Written at release time by the release step, not in this PR's source tree, unless a release-notes file exists on the branch at that time.

## Acceptance criteria

Observable on the real `aitm` binary (`CARGO_BIN_EXE_aitm`) unless marked *unit*. AC1 and AC2 are new binary tests in `crates/aitm/tests/web_sigterm.rs`; they run from the Terminal panel and in CI, never in the coder sandbox.

1. **AC1, pty regression (G1, G3).** `aitm --config <tmp>/config.yaml web --no-open --listen 127.0.0.1:<free>` with the default (stdio) transport, started through D4's shape so its stdin is its controlling terminal and it sits in a background process group: (a) its log (relayed from the pty) contains `WEB_STDIO_TTY_NOTE` exactly; (b) once the web port accepts a TCP connect, `ps -o stat= -p <pid>` does not start with `T` (and stays so for two further checks 100 ms apart); (c) `<tmp>/run/cores/<pid>.json` exists; (d) after `kill -TERM <pid>` the bash wrapper prints `EXIT 0` within 1 s of the signal; (e) a TCP connect to the web port is then refused; (f) the pointer file is gone; (g) the relayed output contains `shutdown signal received` and does not contain `stdin closed · stdio MCP transport ended`. Before the fix this test fails at (b) with state `T` (the research's §5 observation).
2. **AC2, pipe parity (G2, G3).** The same command with `stdin(Stdio::piped())`, the pipe held open by the test: (a) a JSON-RPC `initialize` request written to stdin is answered on stdout with a line whose `id` matches and that has a `result`; (b) a `Client::connect(<pointer bus addr>, <minted operator token>)` followed by `tool_call("scope.add", {"host": "example.test"})` returns a result (the argument name is the registry's; the builder confirms it); (c) after `kill -TERM <pid>`, with the pipe still held, the process exits with status 0 within 2 s; (d) the web port refuses connections; (e) the pointer file is gone; (f) `<tmp>/audit/audit.jsonl` exists and contains a line containing `"command":"scope.add"`; (g) the log does not contain `WEB_STDIO_TTY_NOTE`.
3. **AC3, *unit*, the rule (G4).** In `main.rs` tests: `serve_agent_transport(&Mode::Web, true, true) == false`; `serve_agent_transport(&Mode::Web, true, false) == true`; `serve_agent_transport(&Mode::Web, false, true) == true`; `serve_agent_transport(&Mode::Server, true, true) == true`.
4. **AC4, *unit*, the words (G4).** `WEB_STDIO_TTY_NOTE == "mcp.transport is stdio and stdin is a terminal; aitm web does not serve the agent transport on it (an MCP client hands aitm a pipe)"`, and the string contains none of `token`, `http://`, `/#t=`.
5. **AC5, *unit*, no EOF note when withheld (G4).** `stdio_eof_note(false, &Ok(()))` is `None` (what the call site passes when `serve_agent_transport(&Mode::Web, true, true)` is `false`), and the existing `stdio_eof_note(true, &Ok(()))` still yields `Some("stdin closed · stdio MCP transport ended")` (the existing test `stdio_eof_note_only_for_stdio_ok` stays green).
6. **AC6, card and reporter unchanged.** `cargo test` on the branch passes every existing card and reporter pin (`crates/aitm/src/startup/card.rs` tests, `tests/web.rs`, `tests/audit_log_binary.rs`), and `git diff main -- crates/aitm/src/startup/card.rs crates/aitm-term` is empty.
7. **AC7, gate.** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` passes from the Terminal panel; `grep -rn "unsafe" crates/aitm/tests/web_sigterm.rs` is empty; `git diff main -- Cargo.toml Cargo.lock crates/aitm/Cargo.toml` is empty.
8. **AC8, live proof on the installed build (release acceptance, not a cargo test).** With the next installed build, the research's §5 chain (`/tmp/claude/web-harness-chain.sh` shape, or the acceptance runner's N4-WEB cell) shows `aitm web` in state `S`/`R`, not `T`, and `kill -TERM` ends it within 1 s with the port free and the pointer removed. Recorded in that release's acceptance report; the Known-issues entry is dropped (D7).

## Left to the builder

- The exact placement of the `serve_agent_transport` call and the `info!` within the web branch of `run()`, provided the line is emitted before the `select!` and exactly once per run.
- Test helper reuse: copy or share `TempDir`, `free_addr`, `pump`, `strip_ansi`, `wait_until`, `accepting` from `tests/shutdown.rs` / `tests/audit_log_binary.rs` (a `tests/common` or `tests/support` module is acceptable; do not edit those tests' behaviour).
- The Python relay's details (reading the master until `EIO`/EOF, `os.waitpid`, unbuffered stdout) and the exact `bash` quoting of temp paths.
- Polling intervals and the startup timeout (a cold binary; 40 s as `shutdown.rs` uses is fine). The 1 s and 2 s exit bounds are not negotiable.
- Whether AC1 and AC2 share one `serial()` mutex (recommended: one `aitm` at a time in this test binary).

## Open questions

1. **Bare `aitm` with a terminal stdin** (research direction C): today it is the stdio MCP server and parses keystrokes as JSON-RPC; backgrounded from a terminal it is stopped exactly like `aitm web` was. Keep as designed (this spec), or make the same terminal rule apply to bare `aitm` in a later spec? Not blocking this fix.
2. **The `Bus  stdio (MCP)` card row** stays as printed in the withheld case, where nothing serves stdio. The card wording is pinned by acceptance cells and this spec does not change it; is a later card variant (for example `stdio (MCP) · not served on a terminal`) wanted, with the cell updates it implies? Not blocking this fix.

## Summary

`aitm web` was never deaf to SIGTERM; launched from a terminal into a background process group it was stopped by SIGTTIN at the first read of the default stdio MCP transport on the terminal, holding its ports and pointer until SIGKILL. This spec applies the TUI's rule to the web mode: when `mcp.transport` is `stdio` and stdin is a terminal, `aitm web` serves nothing on stdin (one `info` log line says so, the stdin-EOF note never applies, the card and reporter are unchanged); a pipe stdin keeps today's stdio transport and the R14 stdin-EOF exit. Two hermetic binary tests, run from the Terminal and in CI, pin it: a pty-backgrounded `aitm web` that is not stopped and exits 0 within 1 s of SIGTERM with the port free and the pointer gone, and a pipe-stdin `aitm web` whose stdio transport answers, whose operator-bus `scope.add` is on disk in `audit.jsonl` after a SIGTERM exit within 2 s. No `unsafe`, no new dependency, no change to `shutdown_timeout`, bare `aitm` and `aitm tui` untouched.

## Calls made in this spec (veto any)

1. The log line is `info`, not `warn` (a terminal stdin is the expected shape of a terminal-launched `aitm web`; nothing is wrong), and it is log-only: no reporter phase, note or warning.
2. Exact wording: `mcp.transport is stdio and stdin is a terminal; aitm web does not serve the agent transport on it (an MCP client hands aitm a pipe)`, held in a `const` pinned by a unit test.
3. The decision is a pure function `serve_agent_transport(&Mode, bool, bool) -> bool` in `main.rs`, and the withheld arm is `std::future::pending()` in place of `mcp.serve()`; `stdio_eof_note` keeps its signature and receives "served", not "configured".
4. **No `unsafe`** in the test, because the workspace `forbid` reaches test targets and must not be weakened for a test: the pty comes from `python3 -c` with `pty.fork()`, a tool-level prerequisite (present on CI and Matt's machine), not a Cargo dependency; a missing `python3` fails the test rather than skipping it.
5. The pipe-parity test also serves as the "pipe stdin still serves stdio" test (an `initialize` reply on stdout), since no existing test covers that in web mode.
6. Both new binary tests live in `crates/aitm/tests/web_sigterm.rs`, are in the default `cargo test` set (Terminal and CI), use `browser.obscura.binary` at a nonexistent path, and never require `AITM_OBSCURA`.
7. Exit bounds: 1 s for the terminal case, 2 s for the pipe case; `shutdown_timeout(1 s)` unchanged.
8. The release note change is a release-time edit (D7), not a file in this PR.
