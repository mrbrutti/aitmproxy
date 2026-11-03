# `aitm web` "ignores SIGTERM": the process is stopped by SIGTTIN

**Date:** 2026-11-03. **Status:** root cause confirmed with runtime evidence.
**Origin:** v0.5.18 release acceptance, run A (`docs/testing/2026-11-03-release-acceptance-0.5.18/README.md`),
listed under Known issues in the v0.5.19 and v0.5.20 release notes as "`aitm web` does not exit on SIGTERM".

## 1. The reported defect

N4-WEB started `/opt/homebrew/bin/aitm web` (pid 68521, 0.5.18) at 18:52:17Z. It bound 8080 to 8082,
published `run/cores/68521.json`, and was still holding them six minutes later. A `kill -TERM 68521`
from the orchestrator's Terminal changed nothing for 10 s; `kill -9` ended it. The orchestrator
recorded it as "web serving mode does not exit on SIGTERM" (claims log 2026-11-03, lines 495 to 496).

## 2. What the code does today

`crates/aitm/src/main.rs` runs every serving mode (bare `aitm`, `aitm web`, `aitm tui`) through one
`tokio::select!` whose arms are the proxy accept loops, `mcp.serve()`, the web server, the operator bus
and `aitm::shutdown_signal_unless_held` (SIGINT/SIGTERM, `crates/aitm/src/lib.rs`). After the select
`run()` restores the system proxy, reaps the browser, flushes the durable audit log
(`handle.shutdown(SHUTDOWN_BUDGET)`), and dropping `OperatorBus` removes the core pointer. `main`
then gives the runtime `shutdown_timeout(1 s)` for the blocked stdin read thread (PR #302, R14).

So the web path does **not** lack the signal arm. `git log v0.5.18..main` shows no change to
`main.rs`, `lib.rs`, `web/` or `operator_bus.rs`: current main is the code that failed.

## 3. Direct reproduction attempts that did NOT reproduce it

Script `/tmp/claude/web-sigterm-repro2.sh` (kept outside the repo), debug build and the installed
0.5.20 binary, `aitm web --no-open --listen 127.0.0.1:<free>`, stdin held open by a FIFO (a
supervisor's pipe), SIGTERM after the web port accepted:

| variant | binary | exit after SIGTERM | port after | pointer after |
|---|---|---|---|---|
| loopback-TCP transport | debug | 0.13 s | free | n/a (shared bus) |
| stdio transport (default) | debug | 1.15 s | free | removed |
| stdio + held `/bus` websocket | debug | 1.14 s | free | removed |
| stdio + held `/bus` websocket | installed 0.5.20 | 1.16 s | free | removed |

The 1.1 s is the R14 `shutdown_timeout(1 s)` waiting for the blocking stdin read; everything in
`run()` (pointer removal, audit flush, obscura stop) had already happened. The log shows
`shutdown signal received` in each run.

## 4. The evidence that names the mechanism

1. The shared log `~/Library/Application Support/aitmproxy/logs/aitm.log` has pid 68521's
   `web UI listening bound=127.0.0.1:8082` at 18:52:18.387Z and **no** `shutdown signal received`
   from an `aitm` (non-`tui`) target until 18:58:33Z, which belongs to the embedded core (preceded by
   `macOS capture feeder stopped`). The SIGTERM handler never ran.
2. `/tmp/claude/p0-check2.log` (the orchestrator's `ps` at 18:58Z): `68521 68439 ... aitm web` with
   parent `68439 python3 .../test_n5_wrong_token.py` **still alive**. The 0.5.18 cell was
   `subprocess.run([AITM, "web"], capture_output=True, timeout=5)`, which SIGKILLs its child after
   5 s. It had not, six minutes later: the Python harness itself was not running.
3. `/tmp/claude/acceptance-0.5.18-window-A.log` stops at `---- n5  18:52:05`, the cell's start line;
   `run.sh` never printed again. The whole runner was frozen from the moment `aitm web` started.
4. `run.sh` runs each cell as `python3 ... <&0 &` (the comment at `tests/e2e/acceptance/lib/run.sh:11`
   says why: the cell keeps the shell's stdin for `pause()`), and the run was launched as a
   background job of the Terminal tab. The cell's `aitm web` therefore had the **controlling terminal
   as stdin while in a background process group**.
5. `aitm web`'s default `mcp.transport` is `stdio` (`McpConfig::default()`), and `aitm web` serves it:
   `transport::serve_stdio` reads `tokio::io::stdin()` on a blocking thread. A read of the
   controlling tty by a process whose group is not the terminal's foreground group raises **SIGTTIN**
   to that group; the default action stops every member. The TUI already refuses this transport for
   that reason (`crates/aitm/src/tui.rs`: "mcp.transport is stdio, which would share the terminal with
   the TUI; the agent transport is not served"); the web mode does not.

## 5. Faithful reproduction (installed 0.5.20, 2026-11-03 23:33Z)

`/tmp/claude/web-harness-chain.sh` mirrors the chain: Terminal tab zsh → `nohup bash chain.sh … &`
(background job) → `python3 cell.py <&0 &` → `subprocess.run([aitm, "web", …], capture_output=True,
timeout=5)`. Observed from a second tab (`/tmp/claude/web-chain-2-check.out`):

```
66165 TN   66165  bash /tmp/claude/web-harness-chain.sh …
66219 TN   66165  python3 /tmp/claude/web-harness-cell.py …
66221 TN   66165  /opt/homebrew/bin/aitm --config …/config.yaml web --no-open --listen 127.0.0.1:58398
tty fg pgrp: 66681
web port 58398 holder: [66221 ] pointer: [66221.json ]
-- kill -TERM 66221
after 3 s: 66221 TN   port holder: [66221 ] pointer: [66221.json ]
-- kill -CONT 66221
after CONT: alive=yes in 10.95 s; port holder: [66221 ] pointer: [66221.json ]
```

`T` = stopped. SIGTERM stays pending on a stopped process. SIGCONT does not help: the restarted
`read(0)` raises SIGTTIN again at once. Once the chain was resumed and its Python killed the child,
Python reported `TimeoutExpired after 69.46s`: its own 5 s cap fired 64 s late because it had been
stopped too. A control probe in the same tab (`(cat > file) &`) is reported by zsh as
`suspended (tty input)`, so this is ordinary tty job-control semantics, not an aitm signal bug.

Note for anyone re-running this: inside a **non-interactive** bash, `cmd &` gives `cmd` `/dev/null`
as stdin unless `<&0` is written, so the stop does not happen and `aitm web` exits at stdin EOF
(`stdin closed · stdio MCP transport ended`) within 0.6 s. That is why the first probes exited cleanly.

## 6. Consequences

- Any `aitm web` started from a terminal and backgrounded (`aitm web &`, a nohup'd runner, a
  harness cell with the tty as stdin) stops at its first stdin read. It keeps the proxy ports, the
  web port, the operator bus and the pointer, and no signal but SIGKILL ends it. In run A this also
  made the restarted embedded core fall back to an ephemeral port.
- In the foreground, the same `aitm web` parses the operator's keystrokes as JSON-RPC and exits on
  Ctrl-D. The web UI and the operator bus are the surfaces a terminal-launched `aitm web` is for.
- A supervisor or MCP client that launches `aitm web` with a **pipe** on stdin is unaffected and
  keeps the stdio transport (the R14 stdin-EOF exit still applies there).

## 7. Directions for the spec

- **A (recommended).** In web mode, when `mcp.transport` is `stdio` and stdin is a terminal
  (`std::io::IsTerminal`), do not serve the stdio transport: no stdin read, one `info` line in the log
  naming the reason, the stdio-EOF note never applies. Pipe stdin keeps today's behaviour. This is
  the TUI's existing rule applied to the web mode. SIGTERM then ends the process the same way the
  loopback-TCP variant does (0.13 s measured).
- **B.** Ignore SIGTTIN so the read returns EIO. Rejected: the stdio arm would end with an error and
  the backgrounded `aitm web` would exit at launch.
- **C.** Make bare `aitm` behave the same with a terminal stdin. Out of this fix's scope: bare `aitm`
  is the stdio MCP server by design and its Ctrl-D exit is documented (R14 §9). Worth a separate
  decision.
- **Test shape that reproduces the bug.** `libc::openpty` (libc is already a dependency of `aitm`), the
  child made session leader of the pty (`setsid`, `TIOCSCTTY`) and `aitm web` started as a background
  job of `bash -c 'set -m; … <&0 & echo PID $!; wait $!; echo EXIT $?'` so it reads the tty from a
  non-foreground group. Before the fix the child is `T` and never exits on SIGTERM; after it, SIGTERM
  ends it with `EXIT 0`, the web port refuses connections and the pointer is gone within 1 s. A
  second test with a pipe stdin pins the parity figure (exit within 2 s: the R14 1 s grace plus
  teardown) and that `audit.jsonl` holds a record written before the signal (an operator-bus
  `scope.add` through `tests/support/scripted_driver.rs::Client`, control stream).
- Sockets cannot bind in the coder sandbox: these tests run from the Terminal panel.
