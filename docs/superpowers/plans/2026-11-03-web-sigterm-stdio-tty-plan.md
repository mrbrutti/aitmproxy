# `aitm web` exits on SIGTERM from every launch shape (no stdio transport on a terminal) implementation plan

**Status:** approved (2026-11-03, orchestrator self-approval under the autonomous approve/merge mode)
**Spec:** `docs/superpowers/specs/2026-11-03-web-sigterm-stdio-tty-design.md` (approved 2026-11-03)
**Branch / worktree:** `fix/web-sigterm-stdio-tty` / `/Users/matt/Security/aitmproxy/.claude/worktrees/web-sigterm`
**Base:** `main` 1e891779 (v0.5.20)

## Overview

Two tasks, two disjoint files. Task 1 is the production change and its unit
tests in `crates/aitm/src/main.rs` (spec D1, D2, D3; AC3, AC4, AC5). Task 2 is
the new binary test file `crates/aitm/tests/web_sigterm.rs` (spec D4, D5; AC1,
AC2). They are **independent** (no shared file) and may be written by two
coders at once, but they are **executed in the order Task 2, then Task 1**
(test first on the branch, architect's call, see "Order and the pre-fix red"
below): Task 2's pty test is the regression test, and the only way to watch it
fail for the right reason is to run it against the unfixed binary. The two
binary tests bind loopback sockets and spawn the real binary, so **they cannot
run in the coder sandbox** (memory `aitmproxy-sandbox-no-socket-binds`); the
Coder of Task 2 compiles them (`cargo test -p aitm --test web_sigterm --no-run`)
and runs everything else it can; the orchestrator runs them from the Terminal
panel and pastes the output into the Coder's report and the PR.

### Order and the pre-fix red

1. Task 2 lands first as its own commit (`test(web): …`). The orchestrator runs
   `cargo test -p aitm --test web_sigterm -- --nocapture` from the Terminal on
   that commit and records:
   - `web_on_a_terminal_in_a_background_group_is_not_stopped_and_exits_on_sigterm`
     **FAILED** with a panic whose message starts with the literal
     `aitm web (pid ` and contains `is stopped (ps stat "T` (AC1 step (b); the
     research §5 observation). Any other failure (a missing `python3`, a
     timeout waiting for the web port, a failure at (a)) is **not** the expected
     red and stops the plan: report it.
   - `web_on_a_pipe_keeps_the_stdio_transport_and_exits_on_sigterm` **ok**
     (the pipe path already works today; this test is a parity pin, spec D5,
     and is expected green before and after the fix).
2. Task 1 lands as its own commit (`fix(web): …`). The orchestrator re-runs the
   same command and records both tests **ok**, then the full gate.

If the Coders run in parallel, the orchestrator still performs step 1 on Task
2's commit **before** Task 1's commit is on the branch (or on a detached
checkout of Task 2's commit); the recorded pre-fix output is evidence for
stage 5 and the PR.

### Rules both tasks follow

- No `unsafe` anywhere (workspace `forbid`, spec Constraints). No new Cargo
  dependency; `git diff main -- Cargo.toml Cargo.lock crates/aitm/Cargo.toml`
  stays empty (AC7).
- Never print a token: not in a log line, not in a panic message, not in a
  test artefact other than the `0600` config (spec Anti-goals). Task 2's
  failure messages print the child's output with every `#t=<value>` masked
  (copy `mask_link_tokens` from `tests/audit_log_binary.rs`).
- Do not edit `tests/shutdown.rs`, `tests/audit_log_binary.rs`,
  `tests/operator_token_dispatch.rs`, `tests/support/*`, `startup/card.rs` or
  anything under `crates/aitm-term` (AC6). Helpers are **copied** into the new
  test file.
- Coder sandbox: `cargo --offline` works (memory `cargo-offline-in-sandbox`);
  `cargo test -p aitm --bin aitm` (the unit tests) runs in the sandbox;
  anything that binds a socket does not.
- Commit each task on its own; parallel coders in one worktree commit by path
  (`git add <file>`), never `git add -A`, never `cargo fmt` on the crate
  (memory `aitmproxy-parallel-coders-shared-worktree`; `rustfmt <leaf file>`
  only). Task 1's file is `main.rs`, a crate root for the bin target: run
  `cargo fmt --check -p aitm` and, if it complains, `rustfmt --edition 2021
  crates/aitm/src/main.rs` and verify the diff touches only the lines you
  changed (memory `rustfmt-crate-root-rewrites-whole-crate`).

### Sandbox facts the Task 2 Coder must not fight

Checked by the architect on 2026-11-03 in the coder sandbox: `python3 -c`
with `pty.fork()` fails there with `OSError: out of pty devices` (`/dev/ptmx`
is denied), and `ps` is refused outright (`operation not permitted: ps`). So
the pty relay, the `ps -o stat=` check and both binary tests can be
**compiled** in the sandbox but never **run** there, even with a trivial bash
line. The Coder does not try; it reports the expected Terminal outcome.

**Pre-dispatch smoke check (orchestrator, Terminal panel, before Task 2 is
dispatched; no `aitm` involved).** Write the plan's `PTY_RELAY` program
verbatim to `/tmp/claude/pty-relay.py` (the sandbox may write there), then
run from the Terminal:

```bash
python3 -I /tmp/claude/pty-relay.py 'set -m; sleep 30 <&0 & echo PID $!; sleep 0.3; ps -o stat= -p $!; kill -TERM $!; wait $!; echo EXIT $?'; echo rc=$?
```

Expected: a `PID <n>` line, a `ps` state line whose first character is `S`
(a sleeping `sleep` does not read the tty, so it is not stopped), `EXIT 143`
(SIGTERM) and `rc=143`. Then the control for the mechanism the test relies on:

```bash
python3 -I /tmp/claude/pty-relay.py 'set -m; cat <&0 & echo PID $!; sleep 0.3; ps -o stat= -p $!; kill -KILL $!; wait $!; echo EXIT $?'; echo rc=$?
```

Expected: the `ps` state line starts with `T` (a background `cat` reading the
controlling tty is stopped by SIGTTIN: the research §5 `(cat > file) &`
control). If either expectation fails on this machine, stop and report before
dispatching Task 2; the test's harness would be wrong, not the binary.

## Tasks

### Task 1: the rule, the note, the withheld arm (production + unit tests)

- **Satisfies:** AC3, AC4, AC5; the production half of AC1 and AC2; AC6 (by
  touching nothing else).
- **Depends on:** none (file-independent of Task 2; executed after it, see
  "Order and the pre-fix red").
- **Files:** `crates/aitm/src/main.rs` (modify) — nothing else.
- **Change:**

  1. Add, at module level beside `stdio_eof_note` (after `configured_agent_port`
     is fine), with doc comments in the file's voice:

     ```rust
     const WEB_STDIO_TTY_NOTE: &str =
         "mcp.transport is stdio and stdin is a terminal; aitm web does not serve the agent transport on it (an MCP client hands aitm a pipe)";
     ```

     ```rust
     /// Whether the agent transport is served by `mcp.serve()` this run (spec D1).
     fn serve_agent_transport(mode: &Mode, transport_is_stdio: bool, stdin_is_terminal: bool) -> bool
     ```

     `false` only when `mode == &Mode::Web && transport_is_stdio &&
     stdin_is_terminal`; `true` otherwise. `Mode` already derives `PartialEq`.

  2. In `run()`, in the server/web branch, immediately after the existing
     `let stdio_transport = matches!(cfg.mcp.transport, McpTransport::Stdio);`
     (today at `main.rs:1424`) and before the `tokio::select!`:

     - compute `let serve_agent = serve_agent_transport(&mode, stdio_transport,
       std::io::stdin().is_terminal());` using the std trait
       `std::io::IsTerminal` (import it in the `use std::io::...` line at the
       top of the file: `use std::io::{IsTerminal as _, Write as _};` or
       equivalent; it is **not** imported anywhere in `main.rs` today);
     - when `!serve_agent`, emit exactly once `info!("{WEB_STDIO_TTY_NOTE}")`
       (default target, `info` level, no fields, no path, no port, no token;
       **not** a `reporter.note`/`warn`/phase);
     - replace the arm `result = mcp.serve() => { stdio_eof =
       stdio_eof_note(stdio_transport, &result); result }` with an arm over a
       future that is `mcp.serve()` when `serve_agent` and
       `std::future::pending()` otherwise (`McpServer::serve(self)` consumes the
       server, so build the future once before the `select!` in the shape
       `web_run` already uses: an `async move` block that matches on
       `serve_agent`; the unused `McpServer` is dropped with the future). The
       arm body becomes `stdio_eof = stdio_eof_note(stdio_transport &&
       serve_agent, &result); result` (spec D3: "served", not "configured").
     - `stdio_eof_note`'s signature and text are unchanged.

     Nothing else in `run()` moves: the web bridge's second `McpServer`
     (`bus`), the operator bus, the ready card, the reporter, the
     `shutdown_timeout(1 s)` in `main`, the post-`select!` restore / quiesce /
     reap / audit flush all stay exactly as they are (spec D6).

  3. The existing `no_tracing_call_site_logs_a_tokened_url` pin scans
     `main.rs` lines containing `info!` for `ui_url` / `#t=`; the new line
     carries neither. The existing `stdio_eof_note_only_for_stdio_ok` stays as
     it is.

- **Test:** in `mod tests` of `main.rs`, three new tests. Write them first,
  run `cargo test -p aitm --bin aitm -- serve_agent_transport
  web_stdio_tty_note stdio_eof_note` in the sandbox, watch the first two fail
  to compile (the symbols do not exist yet), then add the code.

  - `serve_agent_transport_is_withheld_only_for_web_stdio_on_a_terminal`
    (AC3):
    `assert!(!super::serve_agent_transport(&super::Mode::Web, true, true));`
    `assert!(super::serve_agent_transport(&super::Mode::Web, true, false));`
    `assert!(super::serve_agent_transport(&super::Mode::Web, false, true));`
    `assert!(super::serve_agent_transport(&super::Mode::Server, true, true));`
  - `web_stdio_tty_note_words_and_no_secrets` (AC4):
    `assert_eq!(super::WEB_STDIO_TTY_NOTE, "mcp.transport is stdio and stdin is a terminal; aitm web does not serve the agent transport on it (an MCP client hands aitm a pipe)");`
    and `for needle in ["token", "http://", "/#t="] {
    assert!(!super::WEB_STDIO_TTY_NOTE.contains(needle), "{needle}"); }`.
  - `stdio_eof_note_is_none_when_the_transport_was_withheld` (AC5):
    `assert_eq!(super::stdio_eof_note(false, &Ok(())), None);` beside a
    re-assertion that `super::stdio_eof_note(true, &Ok(()))` is
    `Some("stdin closed · stdio MCP transport ended")` (the existing
    `stdio_eof_note_only_for_stdio_ok` must still pass unchanged).

  Expected after the change, in the sandbox:
  `cargo test -p aitm --bin aitm` reports the three new tests and
  `stdio_eof_note_only_for_stdio_ok` and `no_tracing_call_site_logs_a_tokened_url`
  as `ok`; `cargo clippy -p aitm --all-targets -- -D warnings` is clean;
  `cargo fmt --check -p aitm` is clean.

- **Done when:** the four unit tests above pass; `cargo test -p aitm --bin aitm`
  and the card/reporter pins (`cargo test -p aitm --bin aitm startup`,
  `cargo test -p aitm --test web`, both sandbox-safe for their non-socket
  parts) are green; `git diff main -- crates/aitm/src/startup/card.rs
  crates/aitm-term Cargo.toml Cargo.lock crates/aitm/Cargo.toml` is empty;
  the orchestrator's Terminal run of `cargo test -p aitm --test web_sigterm`
  shows both Task 2 tests `ok`; the full gate passes from the Terminal.
  Commit: `fix(web): aitm web does not serve the stdio MCP transport on a
  terminal stdin (SIGTTIN stopped a backgrounded aitm web; SIGTERM now exits)`.

### Task 2: the two binary tests (pty regression, pipe parity)

- **Satisfies:** AC1, AC2 (and, by running them, AC7's `grep -rn "unsafe"
  crates/aitm/tests/web_sigterm.rs` is empty).
- **Depends on:** none (file-independent of Task 1; executed **before** it).
- **Files:** `crates/aitm/tests/web_sigterm.rs` (create) — nothing else.
- **Where it runs:** both tests bind sockets. The Coder writes them, proves
  they compile with `cargo test -p aitm --test web_sigterm --no-run` (sandbox,
  `--offline` if needed), runs `cargo clippy -p aitm --tests -- -D warnings`
  and `rustfmt --check crates/aitm/tests/web_sigterm.rs`, and reports the
  expected Terminal outcome (pre-fix: AC1 red at (b) with the literal below,
  AC2 green). The orchestrator runs them from the Terminal panel and pastes
  the output. The tests are in the default `cargo test` set (CI
  `ubuntu-latest` runs `cargo test`; `python3` is present there and on Matt's
  machine). They must pass on macOS and Linux; a missing `python3` **fails**
  the pty test with a message naming it (spec D4, never a skip).

- **Change:** one file, module doc naming the spec and plan, this layout:

  ```rust
  #[path = "support/scripted_driver.rs"]
  mod scripted_driver;        // as tests/m4_scripted_e2e.rs does; support/mod.rs does not export it
  ```

  Constants:
  - `const WEB_STDIO_TTY_NOTE: &str = "mcp.transport is stdio and stdin is a terminal; aitm web does not serve the agent transport on it (an MCP client hands aitm a pipe)";`
    (a literal copy: a test binary cannot import from the `aitm` bin target;
    AC4 pins the production const to the same bytes).
  - `const STDIN_EOF_NOTE: &str = "stdin closed · stdio MCP transport ended";`
  - `const SHUTDOWN_LINE: &str = "shutdown signal received";`
  - `const STARTUP_TIMEOUT: Duration = Duration::from_secs(40);`
    `const TTY_EXIT_BOUND: Duration = Duration::from_secs(1);`
    `const PIPE_EXIT_BOUND: Duration = Duration::from_secs(2);`
    `const POLL_INTERVAL: Duration = Duration::from_millis(50);`

  Helpers (copied, not shared, from `tests/shutdown.rs` /
  `tests/audit_log_binary.rs`, same bodies): `serial() -> MutexGuard<'static, ()>`,
  `struct TempDir(PathBuf)` (`new(tag)`, `path()`, `Drop` removes), `pump(reader,
  tx)` **plus** `.trim_end_matches('\r')` on every line (a pty's ONLCR ends
  lines `\r\n`), `strip_ansi`, `accepting(&SocketAddr) -> bool`,
  `wait_until(Duration, impl Fn() -> bool) -> bool`, `mask_link_tokens(&str)`,
  and `token_in(config: &Path) -> Option<String>` copied from
  `tests/operator_token_dispatch.rs` verbatim (the minted line is
  `  operator_token: <64 hex>`, unquoted).

  New helpers:

  - `struct Ports { listen: SocketAddr, browser: SocketAddr, web: SocketAddr }`
    with `fn free() -> Ports` (three listeners held until all are chosen, as
    `audit_log_binary.rs::Ports::free` does; no bus port: the transport is
    stdio and the operator bus is ephemeral).
  - `fn write_config(dir: &Path, ports: &Ports) -> PathBuf` writing
    `<dir>/config.yaml` with **exactly** these keys and no `mcp.transport`
    (the default is stdio) and no `operator_token` (the first run mints it):

    ```yaml
    listen: <ports.listen>
    ca:
      dir: "<dir>/ca"
      audit_log: "<dir>/ca-audit.jsonl"
    mcp:
      audit_log: "<dir>/audit/audit.jsonl"
    browser:
      proxy_addr: <ports.browser>
      obscura:
        binary: "<dir>/no-such-obscura"
    ```

  - `fn aitm_env(cmd: &mut Command, home: &Path, run_dir: &Path)` applying the
    hermetic environment both tests share: `env_clear()`, then `PATH` (the
    test's own), `RUST_LOG=info`, `HOME=<home>`, `XDG_CONFIG_HOME=<home>`,
    `AITM_RUN_DIR=<run_dir>` (`<tmp>/run/cores`), `AITM_LOG_FILE=<home>/aitm.log`
    (keeps the startup log inside the temp dir on both platforms; `RUST_LOG`
    set non-empty puts the same `info` lines on stderr, which is what both
    tests read, `startup/log.rs::raw_stream`). `AITM_AUDIT_LOG` and
    `AITM_OBSCURA*` are unset by `env_clear`.
  - `fn aitm_args(config: &Path, web: SocketAddr) -> Vec<String>`:
    `["--config", <config>, "web", "--no-open", "--listen", "<web>"]`.
  - `fn ps_stat(pid: u32) -> String`: `ps -o stat= -p <pid>`, stdout trimmed
    (empty when the pid is gone).
  - `fn kill(pid: u32, signal: &str)`: `kill -<signal> <pid>`, asserting
    success.
  - `fn pointer_path(run_dir: &Path, pid: u32) -> PathBuf`:
    `<run_dir>/<pid>.json`.
  - `fn bus_addr_from_pointer(path: &Path) -> SocketAddr`: parse the file as
    JSON (`serde_json`) and read the `"bus"` string field (pointer keys:
    `v,pid,bus,operator,config,started_unix,version`,
    `crates/aitm-mcp/src/pointer.rs`).
  - `fn audit_lines_with(path: &Path, needle: &str) -> usize`: count of lines
    in `path` containing `needle` (0 when the file is missing).

  **The pty harness (AC1, spec D4).** The test spawns `python3` as the child,
  never `aitm` directly:

  ```text
  python3 -I -c <PTY_RELAY> <BASH_LINE>
  ```

  `PTY_RELAY` is this program, carried as one `const PTY_RELAY: &str` (a raw
  string), passed as the single `-c` argument, verbatim:

  ```python
  import errno, fcntl, os, pty, struct, sys, termios
  script = sys.argv[1]
  pid, fd = pty.fork()
  if pid == 0:
      os.execvp("bash", ["bash", "-c", script])
  fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
  while True:
      try:
          data = os.read(fd, 65536)
      except OSError as e:
          if e.errno == errno.EIO:
              break
          raise
      if not data:
          break
      os.write(1, data)
  _, status = os.waitpid(pid, 0)
  sys.exit(os.waitstatus_to_exitcode(status))
  ```

  (`pty.fork()` does openpty + fork + `setsid` + controlling tty on macOS and
  Linux; the window size is set so a 0×0 pty cannot change the reporter's
  layout, memory `aitmproxy-tui-pty-proof-traps`; the parent relays the
  master to its own stdout unbuffered until the slave side closes, then
  exits with bash's status. `python3 -I` isolates it from the environment
  and cwd; the program is ours, not data.)

  `BASH_LINE` is the research's exact shape, built with `format!` from the
  shell-quoted binary path, config path and web address (quote each path
  with single quotes; temp paths contain no `'`):

  ```bash
  set -m; '<aitm>' --config '<config>' web --no-open --listen <web> <&0 & echo PID $!; wait $!; echo EXIT $?
  ```

  `set -m` puts the `&` job in its own process group; `<&0` keeps the tty as
  its stdin (a non-interactive bash would otherwise give it `/dev/null`,
  research §5 note); `echo PID $!` tells the test the pid; `wait $!; echo
  EXIT $?` reports the exit status as a plain line.

  The python child's stdin is `Stdio::null()`, stdout and stderr are piped
  and pumped into one line channel (the relayed pty carries aitm's stderr:
  the reporter, the ready card and, with `RUST_LOG=info`, the tracing
  lines). The environment is `aitm_env` applied to the **python** command
  (bash and aitm inherit it; `PATH` must contain `bash`, `aitm` is given by
  absolute path `env!("CARGO_BIN_EXE_aitm")`). A `struct PtyRun { child:
  Child, lines: Receiver<String>, seen: Vec<String>, aitm_pid: Option<u32> }`
  with `Drop` that `kill -KILL`s `aitm_pid` (a stopped process still dies to
  SIGKILL) and then kills and reaps the python child, so a failed run leaks
  nothing. `python3` missing from `PATH` is detected by the spawn error and
  reported as `python3 is required on PATH for the pty regression test (spec
  D4); it was not found` (a failure, not a skip).

- **Test 1** — `web_on_a_terminal_in_a_background_group_is_not_stopped_and_exits_on_sigterm` (AC1)

  Steps, in this order (the order is what makes the pre-fix failure land at
  (b) rather than at (a)):

  1. `serial()`, `TempDir::new("tty")`, `Ports::free()`, `write_config`, run
     dir `<tmp>/run/cores` (not created by the test; the binary creates it).
  2. Spawn the pty harness; `wait_for_line(STARTUP_TIMEOUT, |l| l.starts_with("PID "))`,
     parse the pid (digits after `PID `).
  3. `wait_until(STARTUP_TIMEOUT, || accepting(&ports.web))` — assert true,
     message `the web port never accepted`.
  4. **(b)** three checks 100 ms apart: `ps_stat(pid)`; each must be non-empty
     and must **not** start with `'T'`. On failure panic with exactly this
     shape (the orchestrator's pre-fix confirmation grep is on it):
     `aitm web (pid {pid}) is stopped (ps stat "{stat}"): its stdin read raised SIGTTIN from the background process group (spec AC1 b)`.
  5. **(c)** `wait_until(2 s, || pointer_path(run_dir, pid).exists())` — assert
     true.
  6. Note `Instant::now()`, `kill(pid, "TERM")`.
  7. **(d)** `wait_for_line(TTY_EXIT_BOUND, |l| l.starts_with("EXIT "))`; assert
     the line is exactly `EXIT 0` and that the elapsed time since the kill is
     `<= TTY_EXIT_BOUND` (message `aitm web took {elapsed:?} to exit after
     SIGTERM; the bound is 1 s`).
  8. **(e)** `wait_until(500 ms, || !accepting(&ports.web))` — assert true.
  9. **(f)** `wait_until(1 s, || !pointer_path(run_dir, pid).exists())` — assert
     true (pointer removal rides the `OperatorBus` drop, spec D6).
  10. Wait for the python child (`wait_exit(5 s)`), status `0`; `settle()`;
      collect `said()` joined.
  11. **(a)** assert the joined output contains `WEB_STDIO_TTY_NOTE`;
      **(g)** assert it contains `SHUTDOWN_LINE` and does **not** contain
      `STDIN_EOF_NOTE`. Failure messages print the output through
      `mask_link_tokens`.

  Expected pre-fix (Terminal): FAILED at step 4 with `aitm web (pid N) is
  stopped (ps stat "T…")`. Expected post-fix: `ok`, and the elapsed figure in
  a `--nocapture` run well under 1 s (the loopback-TCP variant measured
  0.13 s, research §3).

- **Test 2** — `web_on_a_pipe_keeps_the_stdio_transport_and_exits_on_sigterm` (AC2)

  1. `serial()`, `TempDir::new("pipe")`, `Ports::free()`, `write_config`.
  2. Spawn `aitm` directly: `Command::new(env!("CARGO_BIN_EXE_aitm"))` with
     `aitm_args`, `aitm_env`, `stdin(Stdio::piped())`, `stdout(Stdio::piped())`,
     `stderr(Stdio::piped())`. Keep the `ChildStdin` in a local
     (`let mut stdin = child.stdin.take()…`) until step 9. Pump **stdout
     into its own channel** (JSON-RPC only; tracing never writes to stdout,
     pin `tests/no_stdout_tracing.rs`) and stderr into the log channel.
  3. `wait_until(STARTUP_TIMEOUT, || accepting(&ports.web))`.
  4. **(a)** write one line to stdin:
     `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"web-sigterm-test","version":"0"}}}` + `\n`,
     flush; read stdout lines (10 s) until one parses as JSON with `id == 1`;
     assert it has a `result` key (and no `error`).
  5. **(b)** `wait_until(2 s, || pointer exists)`; `bus = bus_addr_from_pointer`;
     `token = token_in(&config).expect("the first run minted mcp.operator_token into the config")`.
     On a `tokio::runtime::Builder::new_current_thread().enable_all()` runtime:
     `let mut c = scripted_driver::Client::connect(bus, &token).await?;
     c.initialize().await?;
     let added = c.tool_call("scope.add", json!({"host": "example.test"})).await?;`
     — assert `Ok` (the `scope.add` argument is `host`, registry
     `crates/aitm-plugins/src/scope.rs::ScopeAdd`; an operator-token
     connection is trusted control, so no `scope.allow_agent_widen` is
     needed). The token is read from the `0600` config and never printed.
  6. `kill(child.id(), "TERM")` with the stdin pipe **still held**; note
     `Instant::now()`.
  7. **(c)** `exits_within(PIPE_EXIT_BOUND)`: status `success()`; message on
     failure `aitm web did not exit within 2 s of SIGTERM with a held pipe
     stdin` (measured 1.15 s, research §3).
  8. **(d)** `wait_until(500 ms, || !accepting(&ports.web))`; **(e)**
     `wait_until(1 s, || !pointer exists)`.
  9. Drop the `ChildStdin` now; `settle()`.
  10. **(f)** `audit_lines_with(&<tmp>/audit/audit.jsonl, "\"command\":\"scope.add\"") >= 1`
      (the control stream; `audit.jsonl` must exist, else panic naming the
      path). **(g)** the stderr log does **not** contain `WEB_STDIO_TTY_NOTE`.

  Expected pre-fix and post-fix (Terminal): `ok`.

- **Done when:** `cargo test -p aitm --test web_sigterm --no-run` builds in
  the sandbox; `cargo clippy -p aitm --tests -- -D warnings` and `rustfmt
  --check crates/aitm/tests/web_sigterm.rs` are clean; `grep -n unsafe
  crates/aitm/tests/web_sigterm.rs` prints nothing; the Coder's report states
  the literal expected pre-fix line for Test 1; the orchestrator's Terminal
  run on this commit shows Test 1 FAILED at (b) and Test 2 ok, and after Task
  1 both ok. Commit: `test(web): pin that aitm web is not stopped on a
  terminal stdin and exits on SIGTERM (pty and pipe shapes)`.

## Task independence

| Task | Files | Independent of |
|---|---|---|
| 1 | `crates/aitm/src/main.rs` | Task 2 (disjoint files; may be written in parallel) |
| 2 | `crates/aitm/tests/web_sigterm.rs` | Task 1 (disjoint files; may be written in parallel) |

Execution order for evidence: Task 2's commit is run from the Terminal first
(pre-fix red at AC1 (b)), then Task 1's commit (both green), then the full
gate `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo
test` from the Terminal. A Linux pass of the new test file via the cis-lab
(memory `aitmproxy-linux-check-via-cis-lab`) before merge is recommended since
CI is the only Linux run of the pty shape.

## Acceptance map

| AC | Proven by |
|---|---|
| AC1 | Task 2 Test 1 (Terminal, CI) |
| AC2 | Task 2 Test 2 (Terminal, CI) |
| AC3 | Task 1 `serve_agent_transport_is_withheld_only_for_web_stdio_on_a_terminal` |
| AC4 | Task 1 `web_stdio_tty_note_words_and_no_secrets` |
| AC5 | Task 1 `stdio_eof_note_is_none_when_the_transport_was_withheld` + existing `stdio_eof_note_only_for_stdio_ok` |
| AC6 | Task 1 "Done when" diff check; existing card/reporter pins in the gate |
| AC7 | Full gate from the Terminal; the `grep unsafe` and `git diff` checks in both "Done when" lists |
| AC8 | Release acceptance on the next installed build (not a plan task) |

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
