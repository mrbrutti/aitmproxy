# 24 - CLI terminal reporting: startup, progress, warnings, errors, help and results in place

**Stage:** 1 Research. **Author:** Researcher engine. **Read/run date for every source below:** 2026-11-01 unless a row says otherwise.
**Worktree:** `.claude/worktrees/cli-ux-terminal-reporting-64b09b` (branch `claude/cli-ux-terminal-reporting-64b09b`).
**Related:** `docs/research/MEMORY.md`, `docs/design/operator-ui-foundation.md`, `docs/design/tokens.json`, `docs/superpowers/specs/2026-10-30-aitm-web-startup-hygiene-design.md`, `docs/superpowers/specs/2026-10-31-macos-status-page-and-first-run-design.md`.

## 1. Question

How do the best modern command-line tools present startup, progress, warnings, errors, help and command results in place in the terminal, and how do they degrade when the terminal is not interactive, so that aitmproxy can design a small reusable Rust terminal-reporting layer for the `aitm` CLI?

(The scope was widened mid-task by Matt, via the orchestrator, from "startup" to the whole command-line experience: sections A to D of the brief are covered in Parts A, B, C and C4 below.)

## 2. Short answer

Good CLIs keep three channels apart: results on stdout, human status/progress/errors on stderr, diagnostics in a file or behind `-v`. They animate only when the stream is a TTY, `TERM` is not `dumb`, `NO_COLOR` and CI are absent; otherwise they print plain lines. aitm inverts this today: `tracing` writes 98 ANSI-coloured INFO lines to stdout before any command that boots the host, `--version` boots the host and exits 1, results are raw JSON, errors carry no fix line. Rust crates exist for every route; `indicatif`+`console` adds 4 lock entries, a `crossterm` renderer adds 0, `console` alone adds 1.

## 3. Findings

How to read this part. Findings are numbered F1... Each carries `(read 2026-11-01; source)`. Source keys `[Sn]` point at section 6. Facts I could not observe are marked **unverified** or **source-verified only**. The sandbox gave me no pty (`OSError: out of pty devices`), no port binds, and no `curl` to crates.io or raw.githubusercontent.com (the sandbox proxy denied both); web pages were read through WebFetch. Consequence: **no TTY rendering was observed by me**; everything said about in-place drawing comes from source and docs, and Matt's no-fixture rule means the real proof must be a Terminal-panel run later.

### Part A. The CLI as an operator meets it today (real binary)

**F1. Method (read 2026-11-01; [S1]).** I ran the installed `/opt/homebrew/bin/aitm` (Homebrew Cellar `0.5.10`, a 36 MB arm64 Mach-O, `bin/aitm -> ../libexec/aitm`) with `HOME=$TMPDIR/aitm-critique-home` (empty, no config, no token), stdin `/dev/null`, stdout and stderr captured separately through pipes, via a small Python `subprocess` harness; ANSI sequences were counted on the raw bytes and stripped only for display. I did not run bare `aitm`, `aitm web` or `aitm tui` (they bind ports); those are described from source. One early probe (`aitm --help | head -3`, to see whether the binary existed) ran before I set the isolated HOME, so it used the real HOME for one process; it failed at argument classification (exit 1) after the normal host boot, which loads an existing CA or creates one if absent; Matt already has a trusted CA, so no change is expected, but I did not check his directory.

**F2. What one command costs (read 2026-11-01; [S1]).** The first command in the fresh HOME, `aitm --version`, created `~/Library/Application Support/aitmproxy/ca/ca.key` (mode 0600), `ca.crt` and `ca-audit.jsonl` (file birth times 11:24:44 equal the first run). So **a version query mints a root-CA private key on disk**. No `config.yaml` is created. Timing, 15 runs each, wall clock through `subprocess` (min / median / max ms): `aitm --version` 17.4 / 21.3 / 23.9; `aitm flow list` 18.4 / 21.1 / 26.0; `aitm web --help` (answered before any boot) 10.9 / 15.3 / 20.0; `aitm tui --bad` 8.8 / 11.2 / 14.0. The 49 scripts load in about 9 ms (timestamps 19:24:44.033789 to .042368). So latency is not the problem; output and side effects are. Comparison, single runs through the same harness: `cargo --version` 33-42 ms, `gh --version` 146 ms, `uv --version` 15 ms warm (594 ms cold first call), `npm --version` 290 ms, `brew --version` 366 ms, `mitmdump --version` 4,920 ms.

**F3. Verbatim captures (read 2026-11-01; [S1]).** Each block gives exit code, stdout and stderr line counts, ESC byte counts, and the first 10 lines (last 3 when longer). Where stdout starts with the 98 tracing lines, I show them once (under `--version`) and say so; the lines after them are the command's real payload. `$HOME` below is the isolated home.

```text
$ aitm --version
exit 1 | stdout 98 lines (98 tracing + 0 payload; 1568 ESC bytes) | stderr 189 lines (0 ESC bytes)
-- stdout, first 10 of 98 (ANSI stripped for display; cut at 150 chars):
2026-11-01T19:24:44.033789Z  INFO aitm_plugin_rhai::loader: loaded script script=check-command-injection path=/opt/homebrew/Cellar/aitm/0.5.10/libexe…
2026-11-01T19:24:44.033994Z  INFO aitm_plugin_rhai::loader: loaded script script=check-cors path=/opt/homebrew/Cellar/aitm/0.5.10/libexec/share/aitm/…
2026-11-01T19:24:44.034202Z  INFO aitm_plugin_rhai::loader: loaded script script=check-crlf-injection path=/opt/homebrew/Cellar/aitm/0.5.10/libexec/s…
2026-11-01T19:24:44.034424Z  INFO aitm_plugin_rhai::loader: loaded script script=check-http-methods path=/opt/homebrew/Cellar/aitm/0.5.10/libexec/sha…
2026-11-01T19:24:44.034680Z  INFO aitm_plugin_rhai::loader: loaded script script=check-ldap-injection path=/opt/homebrew/Cellar/aitm/0.5.10/libexec/s…
2026-11-01T19:24:44.034923Z  INFO aitm_plugin_rhai::loader: loaded script script=check-nosql-injection path=/opt/homebrew/Cellar/aitm/0.5.10/libexec/…
2026-11-01T19:24:44.035089Z  INFO aitm_plugin_rhai::loader: loaded script script=check-open-redirect path=/opt/homebrew/Cellar/aitm/0.5.10/libexec/sh…
2026-11-01T19:24:44.035245Z  INFO aitm_plugin_rhai::loader: loaded script script=check-path-traversal path=/opt/homebrew/Cellar/aitm/0.5.10/libexec/s…
2026-11-01T19:24:44.035387Z  INFO aitm_plugin_rhai::loader: loaded script script=check-security-headers path=/opt/homebrew/Cellar/aitm/0.5.10/libexec…
2026-11-01T19:24:44.035734Z  INFO aitm_plugin_rhai::loader: loaded script script=check-sensitive-paths path=/opt/homebrew/Cellar/aitm/0.5.10/libexec/…
-- stdout, last 3:
2026-11-01T19:24:44.042365Z  INFO aitm::scripts: script loaded into the host script=ws-cross-site-hijack-indicator
2026-11-01T19:24:44.042367Z  INFO aitm::scripts: script loaded into the host script=ws-pii-in-frame
2026-11-01T19:24:44.042368Z  INFO aitm::scripts: script loaded into the host script=ws-secret-in-frame
-- stderr, first 10 of 189:
expected a command before flags, got `--version`
usage: aitm <command> [--flag value]...
(a value that itself starts with `--` must be given as --flag=value;
--yes answers a command's confirmation prompt without asking)

commands:
  flow list
      List the ids of every captured flow, oldest first.
  flow get --id <flow-id>
      Summarize one captured flow: kind, request line, status, state.
-- stderr, last 3:
  findings remove --id <string>
      Delete a recorded finding's YAML (the runs.jsonl history is kept). Operator/CLI only.

```

```text
$ aitm --help
exit 1 | stdout 98 lines (98 tracing + 0 payload; 1568 ESC bytes) | stderr 189 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stderr, first 10 of 189:
expected a command before flags, got `--help`
usage: aitm <command> [--flag value]...
(a value that itself starts with `--` must be given as --flag=value;
--yes answers a command's confirmation prompt without asking)

commands:
  flow list
      List the ids of every captured flow, oldest first.
  flow get --id <flow-id>
      Summarize one captured flow: kind, request line, status, state.
-- stderr, last 3:
  findings remove --id <string>
      Delete a recorded finding's YAML (the runs.jsonl history is kept). Operator/CLI only.

```

```text
$ aitm help
exit 1 | stdout 98 lines (98 tracing + 0 payload; 1568 ESC bytes) | stderr 1 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stderr, first 1 of 1:
unknown command `help`; run with no arguments to list commands
```

```text
$ aitm foo
exit 1 | stdout 98 lines (98 tracing + 0 payload; 1568 ESC bytes) | stderr 1 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stderr, first 1 of 1:
unknown command `foo`; run with no arguments to list commands
```

```text
$ aitm ca status
exit 0 | stdout 122 lines (98 tracing + 24 payload; 1568 ESC bytes) | stderr 0 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stdout payload, first 10 of 24:
{
  "detail": [
    "macOS: presence from `security find-certificate`; trust from `security verify-cert` (basic policy, local only; our install sets the ssl and basi…
    "the embedded browser (obscura) does not use the OS trust store; it trusts this CA through --ca-cert at launch"
  ],
  "dir": "/tmp/claude-501/aitm-critique-home/Library/Application Support/aitmproxy/ca",
  "exists": true,
  "fingerprint_sha1": "AC:A2:9F:20:EE:01:07:21:A6:37:E7:32:D9:B4:FB:B2:A3:84:6B:A9",
  "fingerprint_sha256": "5B:A7:31:83:97:1A:96:38:4E:93:78:8D:54:AA:3E:EA:49:17:18:6E:50:A4:52:A7:66:E3:93:15:3E:8F:DB:AE",
  "path": "/tmp/claude-501/aitm-critique-home/Library/Application Support/aitmproxy/ca/ca.crt",
-- stdout payload, last 3:
    }
  }
}
```

```text
$ aitm ca export
exit 0 | stdout 109 lines (100 tracing + 9 payload; 1624 ESC bytes) | stderr 0 lines (0 ESC bytes)
-- stdout: the same shape of 100 tracing lines as above come first (not repeated)
-- stdout payload, first 9 of 9:
{
  "certificate": "-----BEGIN CERTIFICATE-----\nMIIBpDCCAUqgAwIBAgIUT5W2oW+NGgDfPq2QQEldSwX+1h0wCgYIKoZIzj0EAwIw\nMDEaMBgGA1UEAwwRYWl0bXByb3h5IHJvb3Qg…
  "dir": "/tmp/claude-501/aitm-critique-home/Library/Application Support/aitmproxy/ca",
  "fingerprint_sha1": "AC:A2:9F:20:EE:01:07:21:A6:37:E7:32:D9:B4:FB:B2:A3:84:6B:A9",
  "fingerprint_sha256": "5B:A7:31:83:97:1A:96:38:4E:93:78:8D:54:AA:3E:EA:49:17:18:6E:50:A4:52:A7:66:E3:93:15:3E:8F:DB:AE",
  "format": "pem",
  "path": "/tmp/claude-501/aitm-critique-home/Library/Application Support/aitmproxy/ca/ca.crt",
  "written_to": null
}
-- the 2 extra tracing lines `ca export` adds (cut at 150):
2026-11-01T19:24:59.945274Z  INFO aitm_ca::audit: ca audit command="ca.export" frontend="cli" outcome="ok" scope="" platform="" fingerprint_sha256="5…
2026-11-01T19:24:59.945290Z  INFO aitm_ca: root certificate exported fingerprint_sha256="5B:A7:31:83:97:1A:96:38:4E:93:78:8D:54:AA:3E:EA:49:17:18:6E:…
```

```text
$ aitm scope list
exit 0 | stdout 99 lines (98 tracing + 1 payload; 1568 ESC bytes) | stderr 0 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stdout payload, first 1 of 1:
[]
```

```text
$ aitm scope add
exit 1 | stdout 98 lines (98 tracing + 0 payload; 1568 ESC bytes) | stderr 1 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stderr, first 1 of 1:
missing required flag --host for `scope.add`
```

```text
$ aitm scope add --host
exit 1 | stdout 98 lines (98 tracing + 0 payload; 1568 ESC bytes) | stderr 1 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stderr, first 1 of 1:
flag --host needs a value
```

```text
$ aitm scope add --host example.test
exit 0 | stdout 99 lines (98 tracing + 1 payload; 1568 ESC bytes) | stderr 0 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stdout payload, first 1 of 1:
example.test
```

```text
$ aitm flow list
exit 0 | stdout 99 lines (98 tracing + 1 payload; 1568 ESC bytes) | stderr 0 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stdout payload, first 1 of 1:
[]
```

```text
$ aitm findings list
exit 0 | stdout 99 lines (98 tracing + 1 payload; 1568 ESC bytes) | stderr 0 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stdout payload, first 1 of 1:
[]
```

```text
$ aitm proxy status
exit 0 | stdout 121 lines (98 tracing + 23 payload; 1568 ESC bytes) | stderr 0 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stdout payload, first 10 of 23:
{
  "address": "127.0.0.1:8080",
  "capturing": true,
  "decrypt": {
    "advice": "Nothing is decrypted until a host is in Scope.",
    "decrypting": false,
    "scope_hosts": 0
  },
  "flows": 0,
  "intercept_armed": false,
-- stdout payload, last 3:
  },
  "version": "0.5.10"
}
```

```text
$ aitm scan
exit 1 | stdout 98 lines (98 tracing + 0 payload; 1568 ESC bytes) | stderr 1 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stderr, first 1 of 1:
unknown command `scan`; run with no arguments to list commands
```

```text
$ aitm web --help
exit 0 | stdout 14 lines (0 tracing + 14 payload; 0 ESC bytes) | stderr 0 lines (0 ESC bytes)
-- stdout payload, first 10 of 14:
Usage: aitm [--config <path>] web [--listen <addr>] [--token <token>] [--no-open]

Run the proxy (as `aitm` does) and also serve the web operator UI.

Options:
  --listen <addr>   Bind address for the UI and its /bus bridge
                    [default: 127.0.0.1:8082; env: AITM_WEB_LISTEN]
  --token <token>   Bridge token the UI must present as its first message
                    [default: generated; env: AITM_WEB_TOKEN]
  --no-open         Do not open a browser (accepted; nothing is opened yet)
-- stdout payload, last 3:

Non-loopback addresses are refused until TLS for remote access lands (F15);
use an SSH tunnel, or set AITM_WEB_INSECURE_BIND=1 to bind anyway.
```

```text
$ aitm tui --bad
exit 2 | stdout 0 lines (0 tracing + 0 payload; 0 ESC bytes) | stderr 1 lines (0 ESC bytes)
-- stderr, first 1 of 1:
usage: aitm [--config <path>] tui (takes no further arguments)
```

```text
$ aitm operator-token
exit 2 | stdout 0 lines (0 tracing + 0 payload; 0 ESC bytes) | stderr 1 lines (0 ESC bytes)
-- stderr, first 1 of 1:
usage: aitm [--config <path>] operator-token generate [--force]
```

```text
$ aitm --config /nonexistent.yaml scope list
exit 1 | stdout 0 lines (0 tracing + 0 payload; 0 ESC bytes) | stderr 4 lines (0 ESC bytes)
-- stderr, first 4 of 4:
Error: reading config file /nonexistent.yaml

Caused by:
    No such file or directory (os error 2)
```

```text
$ aitm --config $HOME/bad.yaml scope list   # bad.yaml = `listen: [`
exit 1 | stdout 0 lines (0 tracing + 0 payload; 0 ESC bytes) | stderr 5 lines (0 ESC bytes)
-- stderr, first 5 of 5:
Error: in config file /tmp/claude-501/aitm-critique-home/bad.yaml

Caused by:
    0: parsing config YAML
    1: listen: invalid type: sequence, expected socket address at line 1 column 9
```

```text
$ aitm flow table
exit 0 | stdout 101 lines (98 tracing + 3 payload; 1568 ESC bytes) | stderr 0 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stdout payload, first 3 of 3:
{
  "flows": []
}
```

```text
$ aitm script list
exit 0 | stdout 590 lines (98 tracing + 492 payload; 1568 ESC bytes) | stderr 0 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stdout payload, first 10 of 492:
[
  {
    "api": "1",
    "enabled": true,
    "hooks": [
      "load"
    ],
    "last_error": null,
    "name": "check-command-injection",
    "path": "/opt/homebrew/Cellar/aitm/0.5.10/libexec/share/aitm/scripts/active/check-command-injection.rhai"
-- stdout payload, last 3:
    "path": "/opt/homebrew/Cellar/aitm/0.5.10/libexec/share/aitm/scripts/ws/ws-secret-in-frame.rhai"
  }
]
```

```text
$ aitm config get
exit 0 | stdout 127 lines (98 tracing + 29 payload; 1568 ESC bytes) | stderr 0 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stdout payload, first 10 of 29:
{
  "browser": {
    "engine": "obscura"
  },
  "ca": {
    "allow_agent_install": false,
    "dir": "/tmp/claude-501/aitm-critique-home/Library/Application Support/aitmproxy/ca"
  },
  "limits": {
    "global_rps": 150,
-- stdout payload, last 3:
  },
  "ssl_insecure": false
}
```

```text
$ aitm findings get --id nope
exit 1 | stdout 98 lines (98 tracing + 0 payload; 1568 ESC bytes) | stderr 1 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stderr, first 1 of 1:
findings.get: no findings directory is configured
```

```text
$ aitm flow get --id nope
exit 1 | stdout 98 lines (98 tracing + 0 payload; 1568 ESC bytes) | stderr 1 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stderr, first 1 of 1:
flag --id: not a valid flow id: invalid character: found `n` at 0
```

```text
$ aitm flow list --bogus 1
exit 1 | stdout 98 lines (98 tracing + 0 payload; 1568 ESC bytes) | stderr 1 lines (0 ESC bytes)
-- stdout: the same shape of 98 tracing lines as above come first (not repeated)
-- stderr, first 1 of 1:
unknown flag --bogus for `flow.list`; accepted: (none)
```

More counts from the same runs ([S1], read 2026-11-01): `aitm script list` = 590 stdout lines (98 tracing + 492 JSON lines: 49 objects, each carrying a 100-character install path); `aitm capture status` = 19 payload lines; `aitm poc list` = `[]`; `aitm map list` = `{"maps": []}`; `aitm tls passthrough list` = `{"hosts": []}`; `aitm agent status` = `{"actions_last_minute": 0, "connected_clients": [], "policy": "auto"}` pretty-printed (5 lines); `aitm scan report` = `{"index": [], "report_md": "# aitmproxy findings report\n\n0 findings, 0 reproduced against a patched control.\n\n"}`; `aitm config get` shows `"mcp": {"transport": "stdio"}` (the default transport, runtime-verified). The bundled catalogue is 49 scripts (active 15, http 27, l4 3, ws 4; hooks: `load` 18, `on_request` 5, `on_response` 22, `on_ws_start` 2, `on_ws_message` 2), which is why 98 lines appear. Sibling binary `aitm-tui`: `--help` exits 2 with a 3-line usage on stderr, `--version` exits 2 with "unknown argument `--version`".

**F4. Server-mode startup, from source (read 2026-11-01; [S2]; not run).** `run` (main.rs:313-930) does, in order: install tracing (stdout subscriber for `Server`/`Cli`/`Web`; file-or-nothing for `Tui`); load config and env overrides; append the bundled catalogue (`bundled::apply`, debug-level only); build the script tier (the 49 `loaded script` INFO lines from `crates/aitm-plugin-rhai/src/loader.rs:274` plus 49 `script loaded into the host` INFO lines from `main.rs:459`); assemble the proxy (the CA key is created somewhere on this path: a version query on a fresh HOME produced it, F2; the exact call site was not traced); for `Mode::Cli` dispatch once, print, exit; otherwise pre-bind the proxy, browser-proxy and web ports (`bind_service_port`), run system-proxy startup recovery, launch obscura (INFO `obscura probed`, `obscura started`, `CDP endpoint is loopback-only and unauthenticated`, `obscura CDP attached`), mark `listening`, print the Scope advice as one INFO line (bare `aitm`/`aitm tui`) or as the `Scope` row of the web card, then `select!` over the accept loops, the MCP server, the web server, the capture feeder and the shutdown signal. The only "ready" signals are INFO records (`proxy listening listen=… ssrf=…` at `crates/aitm-core/src/proxy.rs:142`; `web UI listening bound=…` at `web/mod.rs:214`). `aitm web` additionally `println!`s `startup_summary` (web/mod.rs:230-256): a 60-column `─` rule, `  aitm web`, a rule, then label rows padded to one column (`Web UI`, `Operator` when configured, `Proxy`, `Browser  … (SSRF-filtered)`, `Bus  ready`, `Scope  Nothing is decrypted until a host is in Scope.`), then a closing rule. The `#t=` token appears in the Web UI and Operator rows on purpose (spec `2026-10-30-aitm-web-startup-hygiene-design.md`: "The token is allowed only in the stdout URL/summary the operator reads, never in logs").

**F5. The stream inversion (read 2026-11-01; [S2][S3][S4][S5]).** (a) `init_tracing` is `fmt().with_env_filter(filter).try_init()` (main.rs:1076-1080) and `tracing_subscriber::fmt::Layer`'s default writer type is `W = fn() -> Stdout` (docs.rs 0.3.23 struct signature), so **tracing writes to stdout**; (b) the docs say of ANSI: "ANSI colors are enabled by default unless the NO_COLOR environment variable is set to a non-empty value" and give no TTY test, which is exactly what the 1,568 ESC bytes in piped stdout show; (c) `render_cli_value` (crates/aitm/src/render.rs) writes results to stdout, so logs and results share a stream; (d) the default MCP transport is stdio (`crates/aitm-core/src/config.rs:358`, confirmed by `aitm config get`), `serve_stdio` reads `tokio::io::stdin()` and writes `tokio::io::stdout()` (`crates/aitm-mcp/src/transport.rs:263-264`), and the MCP stdio rule is "The server MUST NOT write anything to its `stdout` that is not a valid MCP message" with logging allowed "to its standard error (stderr)" ([S5]). So in bare `aitm` the INFO lines and the `aitm web` card share a stream with JSON-RPC. **Source-verified, runtime-unverified** (I cannot bind); `tests/e2e/cli/cli-startup.sh` merges both streams (`>"$log" 2>&1`) and holds stdin open with `< <(sleep 300)`, so it cannot see this.

**F6. Who else consumes today's text (read 2026-11-01; [S6][S7][S8][S9]).** (1) `tests/e2e/cli/cli-startup.sh` greps the merged log for `proxy listening` (readiness, lines 106 and 231), `obscura probed` (lines 160-206), `already in use`, the proxy port, and the absence of `os error 48` (lines 251-269), `config file` (bad config), `operator`/`operator_token`, and the `http://127.0.0.1:N/#t=<hex>` URL from the web card (line ~218). (2) The Homebrew formula (`mrbrutti/homebrew-aitmproxy` `Formula/aitm.rb`, local tap checkout and the upstream `main` read through WebFetch agree) has `test do` = `assert_match "web operator UI", shell_output("#{bin}/aitm web --help")` and `assert_match "usage: aitm-tui", shell_output("#{bin}/aitm-tui --help 2>&1", 2)`; its `caveats` print `Run the proxy: aitm (listens on 127.0.0.1:8080)`, `Trust the MITM CA: aitm ca install`, `Web operator UI: aitm web (prints the URL + token)`. (3) The macOS app spawns `aitm --config <file>` with `standardOutput`/`standardError` as `Pipe()`s, removes `RUST_LOG`, and feeds every line into a 1000-line Core Log ring (`apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift:210-224`, `AitmproxyKit/CoreHealth.swift:69-85`); a grep of those files and `CoreLogPanel.swift` finds no ANSI handling, so escape bytes probably reach the panel today (**unverified at runtime**). (4) `web::log_listening` and its token-free test (`crates/aitm/src/web/mod.rs`) are pinned by the hygiene spec ("Keep `web::log_listening` exactly as-is"). (5) The mac `CoreHealthTests` uses the literal `proxy listening on 127.0.0.1:8080`. Any redesign must keep, move or deliberately re-pin each of these.

### A.3 Rough edges, numbered for the spec to cite

Evidence is in F2 to F6 and the captures above.

- **R1.** There is no `--version`, `-V` or `version`. `aitm --version` is classified as a registry command, boots the whole host (98 INFO lines, a root-CA key on a fresh HOME, R11), then exits 1 with "expected a command before flags, got `--version`" and the usage dump. The version exists only inside `proxy status` JSON (`"version": "0.5.10"`, `crates/aitm-plugins/src/control.rs:133`).
- **R2.** Help exists only as an error: `aitm --help` is the same 189-line, 18.9 KB stderr dump, exit 1. `aitm help` answers "unknown command `help`". There is no top-level `-h` (`aitm web` has its own). (`cargo --help` 41 lines, `uv --help` 68, `gh --help` 72: all on stdout, exit 0, 0 ESC bytes when piped.)
- **R3.** The usage dump is an ungrouped, unstyled list: 91 commands in registry order (so `flow` verbs are split by `scan` verbs), the longest line 763 characters (descriptions are not wrapped), no headings, no examples, no "learn more" footer, no colour, to stderr.
- **R4.** Misleading hint: "unknown command `foo`; run with no arguments to list commands". Running `aitm` with no arguments starts the proxy (`parse_mode`: `None => Ok(Mode::Server)`, main.rs:89); the list is reachable only by a flag-first mistake.
- **R5.** No did-you-mean and no namespace help: `aitm scan`, `aitm ca`, `aitm flow` all answer "unknown command" although `scan discover/passive/report` exist. (`cargo biuld` suggests `build`; `uv biuld` says `tip: some similar subcommands exist: 'build-backend', 'build'`.)
- **R6.** Dotted wire names leak into prose: usage shows `scope add`, errors say `scope.add`, `flow.list`, `findings.get:`.
- **R7.** Errors say what, not why or fix: `findings.get: no findings directory is configured` (which key, which file?); ``flag --id: not a valid flow id: invalid character: found `n` at 0`` (parser text, no example id); `flag --host needs a value`; config: `Caused by: No such file or directory (os error 2)` with no "create it with / pass --config".
- **R8.** Logs go to stdout and precede the payload: `aitm flow list | jq` receives 98 non-JSON lines first. (render.rs's own comment assumes stdout is for results.)
- **R9.** ANSI colour on non-TTY: 1,568 ESC bytes in piped stdout (tracing's `ansi` honours only `NO_COLOR`).
- **R10.** Two INFO lines per bundled script, each with the 100-character install path and `hooks=[…]`; every one-shot command loads the full catalogue (18 of the 49 are invoke-only `load`-hook scripts), so noise is O(scripts).
- **R11.** Side effects of read-only commands: `--version` (the first command on the fresh HOME) created the CA key, certificate and audit file; `--help`, `help`, `foo` and every other command run the same boot path (each printed the same 98 tracing lines), though only the first run could show the creation; `ca export` adds two more INFO audit lines (100 tracing lines).
- **R12.** Everything is pretty JSON; nothing is rendered for humans: `ca status` 24 lines, `proxy status` 23, `config get` 29, `script list` 492, `flow table` prints `{"flows": []}`, `scan report` returns Markdown inside a JSON string with `\n` escapes. There is no `--json` switch because JSON is the only mode.
- **R13.** `ca export` prints a JSON object whose `certificate` field is the PEM with `\n` escapes, so `aitm ca export > ca.pem` is not a PEM (needs `--out` or a JSON parser), although `render.rs` documents "A string is the operator's text (a PEM, a message)".
- **R14.** Silent, ambiguous success: `aitm scope add --host example.test` prints the bare string `example.test`, exit 0; the next process's `aitm scope list` prints `[]`. A one-shot builds a fresh in-memory proxy, so the entry did not outlive the command, and nothing says so. (Whether one-shot verbs should reach a running core is a design question; flagged, not researched.)
- **R15.** Exit codes are inconsistent: mode usage errors exit 2 (`tui --bad`, `operator-token`), registry and config errors exit 1, `web --help` exits 0, `aitm-tui --help` exits 2 (the Homebrew test pins that 2).
- **R16.** Usage forms differ: `Usage:` (web, stdout, capitalised, with Options table), `usage:` (tui, operator-token, one line, stderr), `usage: aitm <command> [--flag value]...` (registry).
- **R17.** Words differ from the other surfaces: JSON says `"trusted": "no"` / `"installed": "absent"`; the TUI and web say `· CA trusted`, `· CA untrusted`, `· CA trusting…`; the mac Status page uses lane words (`running`, `connected`, `capture off`); the TUI says `not serving` where one-shot `proxy status` says `"listening": false`.
- **R18.** Server startup has no ready banner for bare `aitm` or `aitm tui`; `aitm web` prints its card amid INFO records; readiness is otherwise an INFO line.
- **R19.** Port-in-use error (source + Matt's paste): anyhow's `Error: ` prefix, four lines, and the fix command shares a line with prose (`Find the holder with:  lsof -nP -iTCP:8080 -sTCP:LISTEN`); it is printed after the INFO flood. (It is, however, one clear error with the config path; keep that.)
- **R20.** A security-relevant notice is INFO noise: `CDP endpoint is loopback-only and unauthenticated` (`crates/aitm-browser/src/obscura.rs:500`).
- **R21.** No terminal controls: no `-v/-q`, no `--color`, no `AITM_*` terminal variables; only `RUST_LOG` (default directive `info,chromiumoxide=warn,tungstenite=warn,…`) and, by accident, `NO_COLOR`.
- **R22.** No width or paging awareness: `script list` is 590 lines, `--help` 189; nothing is paged or wrapped.
- **R23.** `aitm-tui --help` is a 3-line usage whose first line exceeds 200 characters and `--version` is unsupported.
- **R24.** `aitm web --help` documents `--no-open` as "accepted; nothing is opened yet" (a flag that does nothing).
- **R25.** The confirmation prompt (source-verified, not run): `ca install` asks one unwrapped ~300-character sentence plus ` [y/N] ` on stderr; non-TTY refuses with "needs confirmation but stdin is not a terminal; pass --yes to confirm non-interactively". The refusal is a good what/fix shape; keep it.

**What already works and is worth keeping** (read 2026-11-01): the config error names the file and the YAML line and column (`Error: in config file …bad.yaml` / `Caused by: 0: parsing config YAML 1: listen: invalid type: sequence, expected socket address at line 1 column 9`); `aitm web --help` is readable prose with defaults and env names; `TtyConfirmer` already uses `std::io::IsTerminal` and sends the prompt to stderr; `NOTHING_DECRYPTED_ADVICE` is one shared sentence; `aitm tui` already refuses to let tracing touch the terminal and tells the operator where its log went; `bind_service_port` pre-binds before any "listening" claim.


### Part B. Inventory of every current CLI output path

**F7. Direct prints and error exits (read 2026-11-01; [S2][S10][S11]).** There are only six `println!/print!/eprintln!` sites in the CLI-visible source (a seventh, `tui.rs:468`, is a test-only skip message), plus the `main()` return path and the registry usage text.

| # | file:line | stream | what it prints |
|---|---|---|---|
| 1 | `crates/aitm/src/main.rs:241` `print!("{}", web::USAGE)` | stdout, exit 0 | `aitm web --help`: `Usage:` line, one prose line, an `Options:` block with defaults and env names, one closing paragraph (14 lines) |
| 2 | `main.rs:251-252` `eprintln!("{usage}")` then `exit(2)` | stderr, exit 2 | one-line usage for `tui`, `operator-token`, `sysproxy-watchdog` (hidden) mode errors |
| 3 | `main.rs:301` `println!(confirmation_message)` | stdout, exit 0 | `operator access enabled: wrote mcp.operator_token to <path>` + `restart the proxy (and any aitm web/aitm-tui --bus/mac session) for it to take effect.` (never echoes the token; unit-tested) |
| 4 | `main.rs:555` `stdout.write_all(&render_cli_value(&value))` | stdout | every one-shot command result (see render rules below) |
| 5 | `main.rs:560-561` `eprintln!("{err}")` then `exit(1)` | stderr, exit 1 | one-shot dispatch error: `Display` of the `anyhow` error only (no `Caused by` chain); includes the whole usage text when argv is empty or flag-first |
| 6 | `main.rs:870` `println!(startup_summary(...))` | stdout | the `aitm web` card (F4); shares stdout with the stdio MCP transport |
| 7 | `main()` return (`main.rs:268`, `-> anyhow::Result<()>`) | stderr, exit 1 | Rust's default `Error: {:?}`: first line `Error: <top message>`, then `Caused by:` chain; used for config errors, port-in-use, `--bus-endpoint-file` misuse, strict script failures |
| 8 | `crates/aitm-cli/src/confirm.rs:36-57` | stderr | `<prompt> [y/N] ` (prompt text from `Command::confirm_prompt`; `ca.install` is `Install the aitmproxy root CA (SHA-256 …) into <location> (scope <scope>)? Every TLS client that uses that store will then trust certificates this proxy mints. (The embedded obscura browser is unaffected; it trusts the CA via --ca-cert.)`); non-TTY stdin: error "needs confirmation but stdin is not a terminal; pass --yes to confirm non-interactively" |
| 9 | `crates/aitm-cli/src/dispatch.rs:171-196` `usage()` | (returned string; stderr via row 5 or 7) | the 189-line registry dump described in R2/R3: header, then per command `  <name with spaces> --flag <type> [--opt <type>]` and an indented description |
| 10 | `dispatch.rs:198-217`, `parse_flags` | (error strings) | ``expected a command before flags, got `X` `` plus the usage; ``unknown command `X`; run with no arguments to list commands``; ``unexpected argument `X` for `cmd`; flags are `--name value` ``; ``unknown flag --X for `cmd`; accepted: …``; `flag --X given more than once`; `flag --X needs a value`; ``missing required flag --X for `cmd` `` |

**F8. Tracing records a first-time operator sees (read 2026-11-01; [S2][S12]).** All go through the stdout `fmt` subscriber in `Server`, `Cli` and `Web` modes; in `Tui` mode nothing prints and a file is written only when `RUST_LOG` is set.

| file:line | level / target | message | when |
|---|---|---|---|
| `crates/aitm-plugin-rhai/src/loader.rs:274` | INFO `aitm_plugin_rhai::loader` | `loaded script script=… path=… hooks=[…]` | per script (49), every mode that builds the tier, i.e. every command |
| `crates/aitm/src/main.rs:459` | INFO `aitm::scripts` | `script loaded into the host script=…` | per script (49) |
| `main.rs:450`, `loader.rs:253/259` | WARN / ERROR | script load errors, strict failures | only on error |
| `main.rs:465` | WARN `aitm::scripts` | `limits.max_body_bytes exceeds the rhai string/blob limits…` | config-dependent |
| `crates/aitm-core/src/proxy.rs:142` | INFO | `proxy listening listen=… ssrf=…` | server modes |
| `crates/aitm/src/web/mod.rs:214` | INFO | `web UI listening bound=…` (token deliberately absent) | `aitm web` |
| `crates/aitm-browser/src/obscura.rs:268/482/499/500/615/709` | INFO | `removed stale obscura run directories`, `obscura probed`, `obscura started`, `CDP endpoint is loopback-only and unauthenticated`, `obscura stopped`, `obscura CDP attached` | server modes |
| `main.rs:684` | WARN | `embedded browser unavailable; browser.* commands will error` | obscura missing |
| `main.rs:760` | INFO target `aitm` | `Nothing is decrypted until a host is in Scope.` (the shared advice sentence) | bare `aitm`, `aitm tui`, empty Scope |
| `main.rs:853` | WARN | web UI bound off loopback without TLS | `AITM_WEB_INSECURE_BIND=1` |
| `main.rs:902`, `tui.rs:415` | INFO | `shutdown signal received` | on SIGINT/SIGTERM |
| `main.rs:190`, `crates/aitm-sysproxy/src/lib.rs:1054/1074/1164/1189/1262/1271/1294` | WARN / INFO | system-proxy recovery, adoption and restore outcomes | server modes |
| `crates/aitm-ca/src/commands.rs:160/511/1016` | INFO | `ca audit command=… frontend=… outcome=… fingerprint_sha256=…` and `root certificate exported …` | `ca.*` commands (the two extra lines on `ca export`) |
| `crates/aitm/src/wire.rs:520-521` | INFO / WARN | `L4 enabled; capture/inject and in-path privilege present` or the missing-privilege warning | `l4.enabled` |
| `crates/aitm-plugin-rhai/src/engine.rs:383`, `host_core.rs:238/247` | INFO | a script's `print(...)` and host log calls | whenever a script prints |
| `crates/aitm/src/lib.rs:27/39`, `tui.rs:328` | WARN | signal handler install failure; `mcp.transport is stdio, which would share the terminal with the TUI; the agent transport is not served` | rare |
| `crates/aitm/src/web/bridge.rs:287` | WARN | refused bad-token connection (rate-limited) | stale browser tab |

The default filter is `DEFAULT_LOG_DIRECTIVE = "info,chromiumoxide=warn,tungstenite=warn,tokio_tungstenite=warn,hyper=warn,hyper_util=warn,rustls=warn,tower=warn,reqwest=warn"` (main.rs:1052-1060); `RUST_LOG`, when set and non-empty, replaces it wholesale (`build_env_filter`, main.rs:1066).

**F9. `render_cli_value` is the single result renderer (read 2026-11-01; [S13]).** `crates/aitm/src/render.rs:12`: `Value::Str(s)` becomes `"{s}\n"`; `Value::Bytes(b)` is written raw (so a DER or screenshot can be redirected); anything else is `format!("{:#}\n", to_json(other))`, i.e. pretty-printed JSON. The module comment says a string is "the operator's text (a PEM, a message)", but `ca.export` returns an object (R13).

**F10. Result shapes, classified (read 2026-11-01; [S1][S14]).** Classification uses each command's `result: TypeDesc` in the schema plus what the real binary returned. "Table" means an array of objects (or `{xs: [objects]}`), "card" a single object of fields, "list" an array of scalars, "scalar" one value, "bytes" raw.

| Command (CLI form) | Declared result / observed | Class an operator would want |
|---|---|---|
| `flow list` | `Array<FlowId>` / `[]` | list of ids, or the `flow table` rows |
| `flow table` | `Object{flows: […]}` / `{"flows": []}` | **table** |
| `flow get`, `flow detail` | `Object(summary_fields)` / `Object` | card (+ body pane for `detail`) |
| `flow replay`, `flow mutate`, `request send` | `FlowId` | scalar (new flow id) |
| `flow resume`, `flow kill`, `flow comment`, `ws frame` | `Str` | scalar sentence |
| `flow mark` | `Array<Str>` | list |
| `flow export`, `flow import`, `session save/load` | `Object{bytes/ids/flows…}` | scalar summary or bytes |
| `scope add` | `Str` / `example.test` | scalar confirmation |
| `scope remove` | `Bool` | scalar |
| `scope list`, `tls passthrough list` | `Array<Str>` / `Object{hosts}` | **list** |
| `proxy status` | `Object` nested (address, decrypt{advice}, system_proxy{…}, version) | **card** (status block with the TUI/mac words) |
| `proxy pause/resume`, `proxy system *` | `Object{capturing}` / `Any` | scalar sentence / card |
| `config get` | `Object` nested (29 lines) | tree (YAML-like), not JSON |
| `ca status` | `Object` (platform, fingerprints, stores{user,system}{installed,trusted,location}, detail[]) | **card plus a 2-row store table**; one verdict word (`CA trusted` / `CA untrusted`) |
| `ca export` | `Object` (certificate PEM, path, fingerprints, written_to) | **bytes/text** (PEM to stdout) |
| `ca install/uninstall` | `Change{changed,scope,location,commands[],detail[]}` (from the struct; the command's reply was not run) | steps/card |
| `findings list` | `Array<Object>` (id, title, class, severity, target, when, reproduction) | **table** |
| `findings get/record/remove` | `Object` | card / scalar id |
| `script list` | `Any` (array of `{api, enabled, hooks[], last_error, name, path}`) | **table** (name, enabled, hooks, last_error; path dimmed or `--wide`) |
| `script validate/reload/save/findings/enable/disable` | `Any` | card / list |
| `poc list` | `Array<Object>` | **table** |
| `poc get`, `poc run` | `Object` | text (YAML) / card with per-assertion rows |
| `poc artifact`, `browser screenshot` | `Bytes` | bytes |
| `poc build` | `Str` | scalar |
| `map list` | `Object{maps: […]}` | **table** |
| `map add` | `Object{id}` | scalar |
| `agent status` | `Object{policy, connected_clients[], actions_last_minute}` | card |
| `agent activity` | `Array<Object>` (at, …) | **table** |
| `capture status` | `Object` nested (capability, feeder, provider, flows_handed_off…) | card (three lanes like the mac Status page) |
| `scan discover/passive` | `Object` | card/table of findings |
| `scan report` | `Object{index, report_md}` | **Markdown text** |
| `check *`, `l4 *` (Rhai command scripts) | script-defined | script-defined |
| `l4.flow.list`, `l4.interfaces`, `l4.scope.list` (when `l4.enabled`) | arrays of strings or objects | list / table |

I did not machine-count the 91 verbs. Reading the schemas, table-shaped results are a small minority (`flow table`, `findings list`, `script list`, `poc list`, `map list`, `agent activity`, scan results, L4 lists), single-object cards are the largest group, and lists, scalars and bytes make up the rest.


### Part C. Prior art

#### C1. Startup, progress, warnings, errors in the tools people copy

**F11. cargo (read 2026-11-01; [S21][S22]; piped run observed locally).**
- *Status lines.* `Shell::status` is documented "Shortcut to right-align and color green a status message"; the justification is `write!(&mut buffer, "{style}{status:>12}{style:#}")` ("the max width that will right align is 12 chars"); the header style is `AnsiColor::BrightGreen ... BOLD`. A real piped build (stderr to a file, 0 ESC bytes) printed exactly `   Compiling hello v0.1.0 (/private/tmp/…/hello)` and ``    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.41s``. Status lines are on **stderr**; verbs are right-aligned so the object names form one left-aligned column.
- *Levels.* `warn` is "an amber 'warning' message" (not justified), `error` "a red 'error' message", `note` cyan; `Verbosity` is `Verbose | Normal | Quiet`; `print` is silent under `Quiet`, `error` still prints. Flags `-v` (twice for "very verbose"), `-q`, `--color auto|always|never`; config and env `term.verbose`/`CARGO_TERM_VERBOSE`, `term.quiet`/`CARGO_TERM_QUIET`, `term.color`/`CARGO_TERM_COLOR`, `term.progress.when auto|always|never`/`CARGO_TERM_PROGRESS_WHEN`, `term.progress.width`/`CARGO_TERM_PROGRESS_WIDTH`, `term.hyperlinks`, `term.unicode` ("Control whether output can be rendered using non-ASCII unicode characters"/`CARGO_TERM_UNICODE`), `term.progress.term-integration`.
- *Progress.* `Progress` is created only when `term.progress.when` is `always`, or `auto` and `progress_supported()`, which is false for Quiet, `TERM=dumb`, or `cargo_util::is_ci()`. Its `Throttle` allows the first draw only after **500 ms** and later draws every **100 ms** (`Duration::from_millis(500)` / `(100)`); the line is clipped to width with an ellipsis, padded to a fixed width, written with a trailing `\r`, and removed with `shell.err_erase_line()`. So a phase shorter than half a second never shows a bar.
- *Width.* `TtyWidth` is `NoTty | Known(n) | Guess(n)`; diagnostics use only a `Known` width and otherwise the renderer's default; Windows guesses are capped at 60.
- *Errors.* Observed: ``error: no such command: `biuld` `` / blank / ``help: a command with a similar name exists: `build` `` / blank / ``help: view all installed commands with `cargo --list` `` / ``help: find a package to install `biuld` with `cargo search cargo-biuld` ``, exit **101**; a bad flag prints ``error: unexpected argument '--bogus' found`` / `Usage: cargo build [OPTIONS]` / ``For more information, try '--help'.``, exit **1**. Messages follow rustc's rule (F34).
- *Version.* `cargo --version` prints `cargo 1.97.1 (c980f4866 2026-06-30) (Homebrew)`; `--version --verbose` 8 lines (release, commit-hash, commit-date, host, libgit2…).
- *Stack.* anstream 1.0.0, anstyle 1.0.14, anstyle-hyperlink, supports-hyperlinks, annotate-snippets, unicode-width, tracing (`CARGO_LOG`) per its workspace `Cargo.toml`.

**F12. uv and ruff (read 2026-11-01; [S23][S24]; offline runs observed locally).**
- *Channel and quiet.* Status lines go to stderr: `uv sync --offline` printed ``Using CPython 3.11.15 interpreter at: …`` / `Creating virtual environment at: .venv` / `Resolved 1 package in 34ms` / `Checked in 0.36ms` (0 ESC bytes piped); `--quiet` printed nothing; docs: `-q` "Use quiet output", "`-qq` … a silent mode in which uv will write no output to stdout"; `--no-progress` / `UV_NO_PROGRESS` "Disables all progress output. For example, spinners and progress bars."
- *Collapse.* Work is summarised as `Resolved N packages in Xms` and `Checked in Yms` rather than per-package lines; timings are part of the message.
- *Colour.* `--color auto|always|never` ("auto: Enables colored output only when the output is going to a terminal or TTY with support"); env: `NO_COLOR` "(takes precedence over `FORCE_COLOR`)", `FORCE_COLOR`, `CLICOLOR_FORCE` ("Use to control color via `anstyle`"); `RUST_LOG` drives `-v` output ("Accepts any filter compatible with the `tracing_subscriber` crate"), `UV_LOG_CONTEXT`, `UV_NO_WRAP` ("disable line wrapping for diagnostics"), `COLUMNS` ("Overrides terminal width used for wrapping. This variable is not read by uv directly."), `PAGER`.
- *Errors.* Usage errors are clap's (exit **2**): ``error: unrecognized subcommand 'biuld'`` / blank / `  tip: some similar subcommands exist: 'build-backend', 'build'` / blank / `Usage: uv [OPTIONS] <COMMAND>` / blank / ``For more information, try '--help'.``; resolution failures use `×` and `╰─▶` plus an indented `hint:` paragraph, exit 1 (observed, with the glyphs present even though stderr was a pipe).
- *Version.* `uv --version` = `uv 0.11.15 (3cffe97c2 2026-05-18 aarch64-apple-darwin)`.
- *Stack.* (uv workspace `Cargo.toml`) anstream 1.0.0 (`auto`,`wincon`), clap 4.5 (`wrap_help`, `suggestions`, `string`…), console 0.16 (`std`), indicatif 0.18 (`unicode-width`), owo-colors 4.1, terminal_size 0.4, textwrap 0.16, tracing-subscriber 0.3 (`ansi`,…).
- *ruff* offers `output-format`: `full` (default), `concise`, `grouped`, `json`, `junit`, `github` ("GitHub Actions annotations"), `gitlab`, `pylint`, `azure`: one core, many renderers; none is auto-selected by the documented default.

**F13. pnpm and Bun (read 2026-11-01; [S25]).** pnpm `--reporter`: "For TTY stdout: default; For non-TTY stdout: append-only"; `append-only` = "the output is always appended to the end. No cursor manipulations are performed"; `ndjson` = "the most verbose reporter. Prints all logs in ndjson format"; `silent` = "no output is logged to the console, not even fatal errors". Bun documents `--silent` ("Don't log anything"), `--verbose`, `--no-progress` ("Disable the progress bar"), `--no-summary` ("Don't print a summary") and maps npm's `--loglevel=error|warn` to `--quiet` which "hides the progress bar, not warnings". Bun's and Deno's actual install output and non-TTY behaviour: **unverified** (neither installed here; Deno's `install --quiet` is documented as suppressing diagnostics, progress indicators, download information and success messages).

**F14. gh (read 2026-11-01; [S26]; local `gh` 2.96.0 runs observed).**
- *Spinner.* `StartProgressIndicatorWithLabel` does nothing unless `progressIndicatorEnabled`, which `System()` sets only "when both stdout and stderr are TTYs"; it uses `spinner.CharSets[11]` (the braille-dot set, per the code comment), interval **120 ms**, colour `fgCyan`, writer **stderr**; with `GH_SPINNER_DISABLED` a textual indicator (default label `Working...` with an ellipsis, on stderr) replaces it.
- *Status icons.* `✓` (success), `!` (yellow warning), `X` (failure) from `pkg/iostreams/color.go`; all status lines of `gh auth login` go to `ErrOut` (`%s Authentication complete.`, `%s Logged in as %s`, `%s Configured git protocol`, `%s Authentication credentials saved in plain text`).
- *TTY decision.* `isTTY = IsTerminal(os.Stdout)`; `GH_FORCE_TTY` forces it ("When the value is a number, it is interpreted as the number of columns"); colour is `IsColorForced() || (!IsColorDisabled() && stdoutIsTTY)` with `NO_COLOR != ""` or `CLICOLOR == "0"` disabling and `CLICOLOR_FORCE` forcing (in the normal case `CLICOLOR_FORCE` beats `NO_COLOR`; under `GH_FORCE_TTY` it is ignored). Width: `GH_FORCE_TTY` override, else `term.GetSize`, else **80**; `COLUMNS` is not read.
- *Tables.* `tableprinter.New`: in a TTY "the output will be human-readable, column-formatted to fit available width" with truncation by `...`, upper-cased coloured headers and relative times (`FuzzyAgo`); "In non-terminal mode, the output is tab-separated and all truncation of values is disabled" with no header and RFC3339 times.
- *Machine output.* `--json <fields>`, `--jq`, `--template` (`tablerow`, `tablerender`, `autocolor` "only emits color to terminals", `timeago`, `hyperlink`); "When connected to a terminal, the output is automatically pretty-printed."
- *Pager.* `GH_PAGER`/`PAGER`; `StartPager` returns immediately if the command is empty or `cat` or **stdout is not a TTY**; sets `LESS=FRX` and `LV=-c` only when unset.
- *Errors and exits.* Not logged in: `To get started with GitHub CLI, please run:  gh auth login` / `Alternatively, populate the GH_TOKEN environment variable with a GitHub API authentication token.` exit **4**; unknown command prints `unknown command "biuld" for "gh"`, a Usage block and the full "Available commands" list (40 lines), exit 1; unknown flag prints `unknown flag: --bogus` plus the command's Usage and Flags (20 lines). Documented exit codes: 0, 1, 2 ("cancelled"), 4 ("requires authentication"); commands may add more.
- *Notices.* `GH_NO_UPDATE_NOTIFIER`: update notice "displayed on standard error"; `GH_PROMPT_DISABLED`; `GH_DEBUG` "verbose output on standard error".
- *Version.* `gh version 2.96.0 (2026-07-02)` + a release URL line.

**F15. npm (read 2026-11-01; [S27]).** `progress` default is "`true` when not in CI and both stderr and stdout are TTYs and not in a dumb terminal"; `color` default "true unless the NO_COLOR environ is set to something other than '0'" (and with `true` "only prints color codes for tty file descriptors"); `loglevel` default `notice`; `logs-dir` default "A directory named `_logs` inside the cache", `logs-max` 10 ("If set to 0, no log files will be written"); `--json`; `--parseable` ("For `npm search`, this will be tab-separated table format"); `unicode` "false on windows, true on mac/unix systems with a unicode locale". On failure npm closes with `A complete log of this run can be found in: <cache>/_logs/<timestamp>-debug-0.log` (web search results, several user reports, not the npm source).

**F16. Docker/BuildKit (read 2026-11-01; [S28]).** `--progress` (env `BUILDKIT_PROGRESS`): `auto` (default) "Uses the `tty` mode if the client is a TTY, or `plain` otherwise"; `tty` "An interactive stream of the output with color and redrawing"; `plain` "Prints the raw build progress in a plaintext format"; `rawjson` "Prints the raw build progress as JSON lines"; `quiet` suppresses output and prints the image ID.

**F17. Dev-server cards: Vite and Next (read 2026-11-01; [S29]).**
- *Vite* prints `VITE v{version}` (bold, green) then dim `ready in N ms`, then `server.printUrls()`: green `➜` + bold `Local:`/`Network:` rows, and when no network URL exists a dim hint: `➜  Network: use --host to expose` (bold `--host`); then keyboard-shortcut hints. Its logger prefixes `[vite]`, optional dim timestamps, `warnOnce` de-duplication; screen clearing is gated by `process.stdout.isTTY && !process.env.CI`; info uses `console.log` (stdout), warn/error `console.warn`/`console.error`.
- *Next.js* uses one glyph per level: `○` wait (white bold), `⨯` error (red), `⚠` warn (yellow), `▲` ready (no colour), `✓` event (green), `»` trace (magenta); the banner is `▲ Next.js {version}` (bold purple) followed by plain rows `- Local:         url`, `- Network:       url`, `- Environments: …`. Both keep the card to one screen and put the single URL the user needs first.

**F18. Deno (read 2026-11-01; [S30]).** Only the `install --quiet` flag description was confirmed; progress style and non-TTY behaviour are **unverified**.

**F19. Summary matrix.** (All rows as read above.)

| Tool | Human channel | In-place progress when | When piped or CI | Verbosity controls | Colour controls | Error shape |
|---|---|---|---|---|---|---|
| cargo | stderr | TTY, not CI, not `TERM=dumb`, first draw after 500 ms, then 100 ms steps | status lines stay, no bar, 0 ESC (observed) | `-v/-vv/-q`, `CARGO_TERM_*` | `--color`, `CARGO_TERM_COLOR`; anstream auto-detect (honours `NO_COLOR`) | `error:` + `help:` lines, exit 101 / 1 |
| uv | stderr | TTY (indicatif), `--no-progress` | status lines stay, 0 ESC (observed) | `-q/-qq/-v`, `RUST_LOG` | `--color`, `NO_COLOR`, `FORCE_COLOR`, `CLICOLOR_FORCE` | `error:` + `tip:` / `hint:`, exit 2 usage / 1 |
| gh | results stdout, status stderr | spinner only if stdout **and** stderr are TTYs | TSV tables, no headers, no truncation, RFC3339 times | `GH_DEBUG` | `NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE`, `GH_FORCE_TTY` | one or two lines, or usage; exit 1 / 2 / 4 |
| pnpm | not confirmed | `default` reporter when stdout is a TTY | `append-only`, no cursor moves | `--reporter`, loglevel | not read | not read |
| npm | not confirmed | progress `true` only if not CI and both streams are TTYs | none | `loglevel`, log file under `_logs` | `color`, `NO_COLOR` | log-path line on failure |
| docker buildx | not confirmed | `tty` mode if the client is a TTY | `plain` | `--progress` | not read | not read |
| Vite / Next | stdout (`console.log`) | Vite clears the screen only if stdout is a TTY and `CI` is unset | plain lines | not read | picocolors | one glyph per level |


#### C2. charmbracelet (gum, bubbletea, lipgloss, log, fang)

**F20. Conventions (read 2026-11-01; [S33]).**
- *Spinners (bubbles `spinner.go`).* `Line` `| / - \` at 10 fps; `Dot` `⣾ ⣽ ⣻ ⢿ ⡿ ⣟ ⣯ ⣷` at 10 fps; `MiniDot` `⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏` at 12 fps; `Jump` (braille), `Pulse` `█ ▓ ▒ ░` at 8 fps, `Points` `∙∙∙ ●∙∙ ∙●∙ ∙∙●` at 7 fps, `Meter` `▱▱▱ ▰▱▱ …`, `Hamburger` `☱ ☲ ☴ ☲`, `Ellipsis` (empty, `.`, `..`, `...`) at 3 fps, plus emoji sets (`Globe`, `Moon`, `Monkey`). `gum spin` lists `line, dot, minidot, jump, pulse, points, globe, moon, monkey, meter, hamburger`; it runs a command and stops when it exits; "To view or pipe the command's output, use the `--show-output` flag".
- *Colour degradation (lipgloss README).* "Lip Gloss was designed to handle this gracefully by automatically downsampling colors to the best available profile", "stripping colors (and ANSI) entirely when output is not a TTY"; profiles ANSI 16, ANSI 256, TrueColor and a 1-bit ASCII profile, handled by the `colorprofile` library; standalone use is `lipgloss.Println`/`Sprint` ("a drop-in replacement for the `fmt` package"). Borders: Normal, Rounded, Thick, Double, Markdown, ASCII; a `lipgloss/table` sub-package with styled header, per-cell style function, border presets including Markdown and ASCII.
- *charmbracelet/log.* Formatters `TextFormatter` (default), `JSONFormatter`, `LogfmtFormatter`; examples print `INFO <cookies/oven.go:123> Starting oven degree=400` with `key=value` pairs, values with spaces quoted; "Styling is disabled if the output is not a TTY"; every example passes `os.Stderr` to `log.New`; styles are `Levels`, `Keys`, `Values` set through lipgloss. `gum log` offers `--level` and `--structured`.
- *bubbletea.* "You can't really log to stdout with Bubble Tea because your TUI is busy occupying that!" and suggests `tea.LogToFile`; "Bubble Tea apps assume control of stdin and stdout"; apps can be "either inline, full-window, or a mix of both" (the inline mode is the one a CLI progress block would use).
- *glamour and gum.* glamour is "Stylesheet-based markdown rendering for your CLI apps" (word wrap default 80; style from `GLAMOUR_STYLE`, which gh also reads, with gh's `GH_MDWIDTH` capping wrapping at "the lesser of the terminal width, this value, or 120"); its README says nothing about the `notty`/`ascii` styles or about non-terminal output, and notes that it "doesn't have access to the terminal's capabilities", so colour downsampling needs lipgloss. `gum format` "can parse markdown, template strings, and named emojis"; `gum table` is a row **picker** ("Select a row from some tabular data"), not a static table renderer. `scan report` returns Markdown (R12), so a Markdown-to-terminal step is the closest analogue.
- *fang.* A Cobra add-on: "fully styled help and usage pages", "fully styled errors", automatic `--version`, hidden `man` command, `completion` command, themes, and "Silent `usage` output (help is not shown after a user error)". Its README says nothing about non-TTY degradation.

#### C3. Help, tables and paging

**F21. Help layouts (read 2026-11-01; [S26][S21][S23][S34]; real `--help` runs, all piped, all 0 ESC).**
- *cargo* (41 lines, stdout, exit 0): one-line tagline, `Usage:` lines, an `Options:` table with aligned short/long flags and descriptions, a `Commands:` list with aliases (`build, b`), an `...  See all commands with --list` row, and the footer `See 'cargo help <command>' for more information on a specific command.`
- *uv* (68 lines): tagline, `Usage: uv [OPTIONS] <COMMAND>`, `Commands:` (21 verbs, two-column), then **option groups under their own headings** (`Cache options:`, `Python options:`, `Global options:`…) each flag annotated with its env var (`[env: UV_NO_CACHE=]`), and the footer ``Use `uv help` for more details.`` in uv's own output `-h, --help` is "Display the concise help for this command" and `uv help` gives the long form.
- *gh* (72 lines): tagline, `USAGE`, then **headed command groups** `CORE COMMANDS`, `GITHUB ACTIONS COMMANDS`, `ALIAS COMMANDS`, `ADDITIONAL COMMANDS` (names padded `rpad(name+":", 14)`), `HELP TOPICS` (`environment`, `exit-codes`, `formatting`, `reference`, …, each a page behind `gh help <topic>`), `FLAGS` (`--help`, `--version`), an `EXAMPLES` block (`$ gh issue create`, `$ gh repo clone cli/cli`, `$ gh pr checkout 321`), and `LEARN MORE`: ``Use `gh <command> <subcommand> --help` for more information about a command.`` / `Read the manual at https://cli.github.com/manual` / ``Learn about exit codes using `gh help exit-codes` ``. Subcommand help (`gh pr list --help`) carries `# comment` + `$ command` example pairs.
- *clap 4.6.7* (what uv and cargo use; docs.rs read): `Command::styles` with `Styles` fields `header, error, usage, literal, placeholder, valid, invalid, context, context_value`; `subcommand_help_heading` (default "Commands"), `next_help_heading` / `Arg::help_heading` for option groups, `after_help` (shown for `-h`) and `after_long_help` (for `--help`), `help_template` tags (`{name} {version} {about-section} {usage-heading} {usage} {all-args} {options} {positionals} {subcommands} {tab} {after-help} {before-help}`), `term_width` / `max_term_width` (feature `wrap_help`; width defaults to the terminal width and "if that can't be determined, the default is 100"), `-h` = short help and `--help` = long help when `long_about`/`long_help` is set. Its deps: `clap_builder` (anstyle, clap_lex, anstream, terminal_size, strsim, unicase, unicode-width, optional backtrace) and optional `clap_derive`.
- *Observed replies to a typo*: cargo `help:` lines (6 lines), uv `tip:` (7 lines), gh a Usage block plus the command list (40 lines); none approaches aitm's 189 lines.

**F22. Table crates (read 2026-11-01; [S35][S36]).**
- `comfy-table 8.0.1` (MIT, MSRV 1.88; default feature `tty` = optional `crossterm ^0.29`, deps `unicode-segmentation`, `unicode-width`): `Table::new()`, `set_header`, `add_row`, `set_content_arrangement(ContentArrangement::Dynamic)`; presets `NOTHING`, `ASCII_NO_BORDERS`, `ASCII_BORDERS_ONLY`, `UTF8_FULL`, `UTF8_HORIZONTAL_ONLY`, `UTF8_NO_BORDERS`; `is_tty()` "By default, the library checks whether `stdout` is a tty" (`use_stderr` switches to stderr, `force_no_tty` overrides); `force_no_tty` disables width lookup and "Styling and attributes on cells"; `Dynamic` "won't work" without a width ("If terminal width cannot be determined and no table_width is set via `Table::set_width`") and falls back to `Disabled`.
- `tabled 0.22.0` (MIT; no MSRV on crates.io): default features `derive`, `macros`, `assert` pull `tabled_derive` (proc-macro, syn 2), `papergrid` (+ `bytecount`), `testing_table`; ANSI handling behind the `ansi` feature (`ansi-str`, `ansitok`). Heavier; `default-features = false` would shrink it (**unverified how far**).
- `cli-table 0.5.0` (MIT/Apache-2.0, last updated 2025-03-18): **not read beyond its crate metadata**.
- gh's own rule (F14) is the model for both: aligned and truncated in a TTY, tab-separated raw values when piped.

**F23. Paging (read 2026-11-01; [S26][S43][S36]).** git: `core.pager` order "`$GIT_PAGER`, then `core.pager` configuration, then `$PAGER`, then ... (usually 'less')"; "When the `LESS` environment variable is unset, Git sets it to `FRX`" (and `LV=-c`); `-p/--paginate` "if standard output is a terminal"; `-P/--no-pager`; `GIT_PAGER` empty or `cat` means no pager. gh does the same (F14: `FRX`, only when stdout is a TTY). `less -FRX` = quit if one screen (`F`), pass colour escapes (`R`), do not clear the screen on exit (`X`) (the `F` meaning is in git's docs; `R`/`X` from general knowledge, **unverified in a fetched source**). Rust options: `pager 0.16.1` (Apache-2.0/MIT, last updated 2022-09-22) forks the process and replaces the parent with the pager (`PAGER`, fallback `more`; `NOPAGER` disables; `skip_on_notty()`); `minus 5.8.0` (MIT/Apache-2.0) is "A library for asynchronous terminal paging". A hand-rolled pager that spawns `$PAGER` with `std::process::Command` when stdout is a TTY needs no crate and no `unsafe`. None of `pager`, `minus` is in `Cargo.lock`.

#### C4. First-run prior art

**F24. How others lead a new user through one-time steps (read 2026-11-01; [S26][S31][S32][S41]).**
- *gh* `auth login` prints icon-led lines to stderr: `✓ Authentication complete.`, `✓ Logged in as <name>` (bold name), `! Authentication credentials saved in plain text`; when unauthenticated, any command prints the next step itself: `To get started with GitHub CLI, please run:  gh auth login`.
- *mkcert* `-install` (source): `The local CA is already installed in the system trust store! [thumbs-up emoji]`, `The local CA is now installed in the system trust store! [high-voltage emoji]`, `Note: the local CA is not installed in the system trust store.`, `Run "mkcert -install" for certificates to be trusted automatically [warning-sign emoji]`, plus Firefox (`[fox emoji]`, "requires browser restart") and Java (`[hot-beverage emoji]`) variants. Wording is exactly what/next, but **emoji-laden**, which our brand forbids.
- *mitmproxy*: first run "creates the keys for a certificate authority (CA) in the config directory" (`~/.mitmproxy`: `mitmproxy-ca.pem`, `mitmproxy-ca-cert.pem`, `.p12`, `.cer`); guidance is "visit the magic domain mitm.it" / "browse to http://mitm.it" for "a simple page to install the mitmproxy Certificate Authority"; default listen `http://localhost:8080`. The tool itself prints `Proxy server listening at http://*:8080` (web search of several sources; wording varies by version: `http://[::]:8080`, `http://0.0.0.0:8080`, `*:8080`); `mitmweb` adds `Web server listening at http://0.0.0.0:8081/`.
- *Proxyman* (docs via web search): certificate install is a menu action ("Install Certificate on this Mac…"); automatic mode "needs root privileges" and runs `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain …`; by default it changes proxy settings with `networksetup` ("slow"), and offers a privileged helper on first launch (declinable, installable later in Settings → Advanced); "Automatic Setup → Open New Terminal" opens a pre-configured shell. State is shown in the app UI, not the terminal.
- *Burp*: "By default, Burp creates a single listener on port 8080 of the loopback interface"; intercept is a toggle labelled "Intercept on"/"Intercept off"; "Open Browser" launches a browser "preconfigured to work with Burp right out of the box". Startup errors for a listener on a busy port: **not described** on the pages read.
- *Our own shipped wording* (Homebrew `caveats`, upstream and local identical): `Run the proxy: aitm (listens on 127.0.0.1:8080)`, `Trust the MITM CA: aitm ca install`, `Web operator UI: aitm web (prints the URL + token)`. The mac Status page models the same idea as a live checklist: five `✓`/`○` rows (`Core is running`, `Bus connected as operator`, `Capture extension on`, `Add a host to Scope`, `Point a client at 127.0.0.1:8080, or open the browser`), with the explicit rule "No onboarding tour, splash, or wizard (rule 76)" and "Getting started … a live checklist, not a sequence the operator is pushed through".

#### C5. Proxyman, Burp and mitmproxy startup tone (short)

**F25. (read 2026-11-01; [S31][S32]).** mitmdump's logger writes to **stdout** by default (`self.file: IO[str] = out or sys.stdout` in `termlog.py`), takes `termlog_verbosity` (default `"info"`), and asks the platform whether VT codes work (`vt_codes.ensure_supported(self.file)`) rather than testing `isatty`; it is a log-stream tool, where stdout logging is the product. Burp and Proxyman communicate state in GUI chrome (listener table, Intercept toggle, helper-tool prompts), so their wording is a tone reference only: short noun phrases, state first (`Intercept on`), no sentences, the privileged step named once with its reason.


### Part D. Rust crates, versions, verified APIs, weight and licence

**F26. Versions and licences (crates.io API through WebFetch, read 2026-11-01; [S35]).** The last column counts the `Cargo.lock` entries each choice would add, from the crates.io dependency lists against the current `Cargo.lock` (410 packages); it is **not** a `cargo tree` result (cargo could not reach the registry from the sandbox), and the lock lists Windows-only crates too, so Windows-target dependencies count even though only macOS and Linux ship. `unsafe_code = "forbid"` (workspace lint) applies to our crates only, not to dependencies.

| Crate | Version read | Licence | MSRV | In `Cargo.lock` now | New lock entries if added (default features unless noted) |
|---|---|---|---|---|---|
| indicatif | 0.18.6 (2026-07-01) | MIT | 1.85 | no | `indicatif`, `unit-prefix 0.5.2` (MIT); `console` below; `portable-atomic 1.15.0`, `unicode-width 0.2.3`, `web-time 1.1.0`, `libc` already present (default features `unicode-width`, `wasmbind`) |
| console | 0.16.6 (2026-09-10) | MIT | 1.71 | no | `console`, plus `encode_unicode` (Windows target); `libc`, `unicode-width`, `windows-sys 0.61.2` present |
| owo-colors | 4.4.0 (2026-08-27) | MIT | 1.83 | no | 1 (`owo-colors`); with `supports-colors`: + `supports-color 3.0.2` (Apache-2.0, MSRV 1.70) + `is_ci 1.2.0` (ISC) = 3 |
| supports-color | 3.0.2 (2024-11-26) | Apache-2.0 | 1.70 | no | 2 (`supports-color`, `is_ci`) |
| supports-unicode | 3.0.0 (2024-02-04) | Apache-2.0 | 1.70 | no | 1 (its own deps not read) |
| anstyle | 1.0.14 (2026-03-13) | MIT OR Apache-2.0 | 1.66 | no | 1 |
| anstream | 1.0.0 (2026-02-11) | MIT OR Apache-2.0 | 1.66 | no | `anstream`, `anstyle`, `anstyle-parse 1.0.0`, `colorchoice 1.0.5`, `is_terminal_polyfill 1.70.2`, `anstyle-query 1.1.5` = 6; Windows adds `anstyle-wincon` and `once_cell_polyfill`; `utf8parse 0.2.2` present |
| terminal_size | 0.4.4 (2026-03-23) | MIT OR Apache-2.0 | 1.71 | no | 1 (`rustix 1.1.6` present) |
| crossterm | 0.29.0 (2025-04-05) | MIT | 1.63 | **yes, 0.29.0** (linked into `aitm` through `aitm-tui`) | 0 (the `aitm` crate must declare it itself; `IsTty` needs its `libc` feature) |
| yansi | 1.0.1 (2024-03-13) | MIT OR Apache-2.0 | 1.63 | no | 1 (`detect-tty` also wants `is-terminal`, optional) |
| nu-ansi-term | 0.50.3 (2025-10-10) | MIT | 1.62.1 | **yes, 0.50.3** (via `tracing-subscriber`'s `ansi` feature) | 0 |
| unicode-width | 0.2.3 | MIT OR Apache-2.0 | 1.66 | **yes, 0.2.3** | 0 |
| unicode-truncate | 3.0.0 latest; lock has 2.0.1 | MIT OR Apache-2.0 | 1.85 (latest) | **yes, 2.0.1** (transitive via `ratatui-core`) | 0 |
| tracing-subscriber | 0.3.23 | MIT | 1.65 | **yes, 0.3.23** (`env-filter`; default features include `ansi`, `fmt`, `registry`, `std`) | 0 |
| tracing-appender | 0.2.5 (2026-04-17) | MIT | 1.63 | no | `tracing-appender`, `symlink 0.1.0` = 2 (`crossbeam-channel`, `thiserror 2.0.21`, `time`, `tracing-subscriber` present) |
| indicatif-log-bridge | 0.2.3 (2024-08-24) | MIT | none | no | 1 (bridges the `log` crate, not `tracing`; `log 0.4.34` present) |
| tracing-indicatif | 0.3.14 (2025-12-03) | MIT | none | no | 1 on top of indicatif (deps `indicatif`, `tracing`, `tracing-core`, `tracing-subscriber`) |
| comfy-table | 8.0.1 (2026-09-25) | MIT | 1.88 | no | 1 (`crossterm`, `unicode-width`, `unicode-segmentation` present) |
| tabled | 0.22.0 (2026-09-05) | MIT | none | no | with defaults about 5 (`tabled`, `papergrid`, `tabled_derive`, `bytecount`, `testing_table`; `syn 2`, `quote`, `heck` present); fewer without defaults (**unverified**) |
| cli-table | 0.5.0 (2025-03-18) | MIT/Apache-2.0 | none | no | not read |
| miette | 7.6.0 (2025-04-27) | Apache-2.0 | 1.70 | no | with `fancy`: at least 9 (`miette`, `backtrace`, `backtrace-ext`, `owo-colors`, `supports-color`, `supports-hyperlinks`, `supports-unicode`, `terminal_size`, `textwrap`, + their deps) |
| ariadne | 0.6.0 (2025-10-28) | MIT | none | no | not read |
| color-eyre | 0.6.5 (2025-05-30) | MIT OR Apache-2.0 | 1.65 | no | not read (eyre family) |
| clap | 4.6.7 (2026-09-14) | MIT OR Apache-2.0 | 1.85 | no | `clap`, `clap_builder`, `clap_lex`, + anstream's 6 + `terminal_size` (`wrap_help`) + `unicase` (opt.) ≈ 10-12; `strsim`, `unicode-width`, `utf8parse` present; `clap_derive` optional |
| textwrap | 0.16.4 | MIT | 1.88 | no | not counted |
| pager | 0.16.1 (2022-09-22) | Apache-2.0/MIT | none | no | not counted |
| minus | 5.8.0 (2026-09-19) | MIT OR Apache-2.0 | none | no | not counted |
| dirs | 7.0.0 latest; lock has 5.0.1 | MIT OR Apache-2.0 | none | **yes, 5.0.1** (via `aitm-core`, `aitm-ca`) | 0 |

Already in `Cargo.lock` from the brief's list, exact versions: **`crossterm 0.29.0`, `nu-ansi-term 0.50.3`, `unicode-width 0.2.3`, `tracing-subscriber 0.3.23`** (with `tracing 0.1.44`, `tracing-core 0.1.36`, `tracing-log 0.2.0`). Not present: `indicatif`, `console`, `owo-colors`, `supports-color`, `anstyle`, `anstream` (and its `anstyle-parse`, `anstyle-query`, `colorchoice`, `is_terminal_polyfill`), `terminal_size`, `yansi`, `tracing-appender`, `textwrap`, `comfy-table`, `tabled`, `miette`, `clap`, `pager`, `minus`. Related terminal crates present for reference: `unicode-segmentation 1.13.3`, `unicode-truncate 2.0.1`, `ratatui 0.30.2` (+ `ratatui-core 0.1.2`, `ratatui-crossterm 0.1.2`, `ratatui-widgets 0.3.2`), `utf8parse 0.2.2`, `dirs 5.0.1`, `log 0.4.34`, `thiserror 1.0.69` and `2.0.21`, `time 0.3.55`, `crossbeam-channel 0.5.17`, `rustix 1.1.6`, `libc 0.2.191`, `nix 0.29.0` and `0.31.3`, `signal-hook 0.3.18`, `mio 1.2.4`, `portable-atomic 1.15.0`, `web-time 1.1.0`, `strsim 0.11.1`, `heck 0.5.0`, `parking_lot 0.12.5`; `termwiz 0.23.3`, `terminfo 0.9.0`, `termina 0.3.3`, `termios 0.3.3` are in the lock but **not compiled** into `aitm` (`cargo tree --offline -i termwiz` printed nothing). The `aitm` crate itself depends on `tracing-subscriber` with `env-filter` only and has `crossterm 0.29` as a **dev**-dependency; `aitm-tui` depends on `crossterm 0.29` (`event-stream`), `ratatui 0.30`, `unicode-width 0.2`.

**F27. Verified APIs, per crate (docs.rs and source pages read 2026-11-01; [S36]).**

*indicatif 0.18.6.* `ProgressDrawTarget::stderr()` ("Draw to a buffered stderr terminal at a max of 20 times a second. This is the default draw target for progress bars"), `stderr_with_hz(u8)`, `term(Term, u8)` ("if the terminal is not user attended the entire progress bar will be hidden. This is done so that piping to a file will not produce useless escape codes in that file. Progress bars will also be hidden if `TERM` is unset/`dumb`"; source: `if !term.is_term() || is_dumb() { return Self::hidden(); }`), `hidden()`, `is_hidden()` (`Hidden`, or `!term.is_term()`), `term_like(Box<dyn TermLike>)` (no default refresh rate). `ProgressBar::new_spinner()` (draws to stderr, default spinner style), `with_style`, `enable_steady_tick(Duration)` ("Spawns a background thread to tick the progress bar"), `tick`, `inc`, `set_message`, `finish`, `finish_and_clear`, `finish_with_message`, `abandon`, `with_finish`, `println` ("If the progress bar is hidden (e.g. when standard output is not a terminal), `println()` will not do anything. If you want to write to the standard output in such cases as well, use `ProgressBar::suspend()`"), `suspend(f)` ("Hide the progress bar temporarily, execute `f`, then redraw the progress bar", lock held while `f` runs), `set_draw_target`. `MultiProgress::new()` (15 Hz, stderr), `add`, `insert`, `insert_before`, `insert_after`, `remove`, `println` ("Print a log line above all progress bars"), `suspend`, `set_move_cursor` ("can reduce flickering, but do not enable it if you intend to change the number of progress bars"), `set_alignment`; "a bar that draws before being added can corrupt the screen"; dropped bars leave "zombie lines". `ProgressStyle::with_template(&str) -> Result<_, TemplateError>`, `tick_chars`/`tick_strings` ("the last string is used as the final tick string. At least two strings are required"), `progress_chars` ("All passed grapheme clusters need to be of equal width"); default spinner tick string `⠁⠁⠉⠙⠚⠒⠂⠂⠒⠲⠴⠤⠄⠄⠤⠠⠠⠤⠦⠖⠒⠐⠐⠒⠓⠋⠉⠈⠈ ` (final frame a space), default templates `{spinner} {msg}` and `{wide_bar} {pos}/{len}`, default `progress_chars` `█░`; template placeholders `{key:options}`, keys include `bar`, `spinner`, `msg`, `prefix`, `pos`, `len`, `percent`, `bytes`, `elapsed`, `elapsed_precise`, `eta`, `per_sec`, styles like `{bar:40.cyan/blue}` applied through `console`. "Spinners don't tick automatically by default". **Unverified:** how it re-measures width after a resize or for a line longer than the terminal; there is no first-draw delay like cargo's 500 ms (emulate by creating the bar late).

*console 0.16.6.* `Term::stdout()/stderr()`, `is_term()` (the stored `is_tty`), `features()`, `size()` (= `size_checked().unwrap_or((24, DEFAULT_WIDTH))`; the constant's value was not on the pages read), `size_checked() -> Option<(u16, u16)>` (ioctl on the Term's own fd, `None` if it is not a terminal or a dimension is 0; **no** `/dev/tty` fallback), `clear_line`, `move_cursor_up(n)`, `hide_cursor`, `show_cursor`, `clear_last_lines(n)`, `write_line`; free functions `colors_enabled()`, `colors_enabled_stderr()`, `set_colors_enabled(_stderr)`, `user_attended(_stderr)`, `is_dumb()`, `measure_text_width(&str) -> usize`, `truncate_str(s, width, tail) -> Cow<str>` ("escape codes are not screwed up"), `strip_ansi_codes`, `pad_str`; `Style::new().for_stderr().force_styling(bool).bold().dim().cyan()…apply_to(x)`. Colour rule from source: `default_colors_enabled(out) = (out.features().colors_supported() && CLICOLOR != "0") || CLICOLOR_FORCE != "0"`; `colors_supported` = is a terminal **and** `NO_COLOR` is not set (**any** value, empty included: `env::var("NO_COLOR").is_ok()`) **and** not dumb. So in console `CLICOLOR_FORCE` overrides `NO_COLOR`.

*owo-colors 4.4.0 / supports-color 3.0.2.* `if_supports_color(stream, |t| t.bright_blue())` needs a feature (`supports-colors` pulls the v3 crate under the alias `supports-color-2`; `supports-color` pulls v2; the aliasing is confusing, **verify before use**). `supports_color::on(Stream) -> Option<ColorLevel{has_basic,has_256,has_16m}>`, `on_cached`; order: `FORCE_COLOR` (`"true"` or empty = 1, `"false"` = 0, number capped at 3) then `CLICOLOR_FORCE != "0"`; then 0 if `NO_COLOR` (set and not `"0"`) or `TERM=dumb` or not a tty (`IGNORE_IS_TERMINAL` bypasses); then `COLORTERM`/`TERM`/`TERM_PROGRAM` for 16m (3) and 256 (2); then `COLORTERM` set, non-dumb `TERM`, `CLICOLOR != "0"` or CI for 1.

*anstream 1.0.0 / anstyle-query 1.1.5 / anstyle 1.0.14.* `anstyle::Style` renders ANSI through `Display` and does no detection. `anstream::{stdout(), stderr()}` return `AutoStream`s, `print!/println!/eprint!/eprintln!/panic!` macros adapt; `ColorChoice` global override; `StripStream` "Only pass printable data to the inner `Write`". `AutoStream` auto order, from `auto.rs`: `NO_COLOR` non-empty -> never; `CLICOLOR_FORCE` non-empty -> always; `CLICOLOR=0` -> never; else always only if the stream is a terminal and (`TERM` is set and not `dumb`, or `CLICOLOR` is set to non-`0`, or `CI` is present); otherwise never, which **strips** escape codes from whatever was written. `anstyle_query`: `no_color` (non-empty), `clicolor` (set, value != "0"), `clicolor_force` (non-empty), `term_supports_color`, `truecolor` (`COLORTERM` = `truecolor`/`24bit`), `is_ci` ("`CI` is set"; comment: "who would be setting `CI=false`?").

*crossterm 0.29.0.* Styling: `Stylize` on `&str`/`String`, `style::force_color_output(bool)` ("Forces colored output on or off globally, overriding NO_COLOR"; "crossterm supports NO_COLOR … to disabled colored output"), `Colored::ansi_color_disabled()` = `NO_COLOR` set and non-empty (memoised); **no TTY test anywhere in styling**, so escapes go into pipes unless the caller gates; `available_color_count()` reads `COLORTERM` then `TERM` (default 8, "does not always provide a good result"). Terminal: `terminal::size()` = `window_size()` which opens **`/dev/tty`** and falls back to stdout's fd (then `tput cols/lines`), so it can return a size even when stdout and stderr are pipes; `Clear(ClearType::{All, Purge, FromCursorDown, FromCursorUp, CurrentLine, UntilNewLine})`, `BeginSynchronizedUpdate`/`EndSynchronizedUpdate`, `EnableLineWrap`/`DisableLineWrap`; `cursor::{Hide, Show, MoveUp, MoveToColumn, SavePosition, RestorePosition, position()}`; `queue!`/`execute!` take any `std::io::Write` ("Queued commands must be flushed"); `tty::IsTty` is only available on Unix with the `libc` feature, whereas `std::io::IsTerminal` (Rust 1.70+, already used by `aitm-cli`) needs nothing.

*yansi 1.0.1.* `Condition::{ALWAYS, NEVER, DEFAULT, STDOUT_IS_TTY, STDERR_IS_TTY, CLICOLOR, YES_COLOR, TTY_AND_COLOR}` (the last three need `detect-env`; the TTY ones need `detect-tty`), set globally with `yansi::whenever(...)` or per value with `.whenever(...)`.

*nu-ansi-term 0.50.3.* A styling library ("controlling colors and formatting … on ANSI terminals"); the page states no TTY or `NO_COLOR` detection.

*unicode-width 0.2.3 / unicode-truncate.* `UnicodeWidthStr::width()` counts Ambiguous-width characters as 1 column (`width_cjk()` as 2); the page says nothing about escapes or emoji. `UnicodeTruncateStr::unicode_truncate(max_width) -> (&str, usize)`, `unicode_pad(target_width, Alignment, truncate)` are available (via ratatui-core) in the tree already.

*tracing-subscriber 0.3.23.* `fmt::Layer` default writer `fn() -> Stdout`; `with_writer(MakeWriter)`, `with_ansi(bool)` ("ANSI colors are enabled by default unless the NO_COLOR environment variable is set to a non-empty value"), `with_target`, `with_level`, `without_time`, `with_timer`, `event_format`, `.compact()`, `.json()`; `Registry` ("tracks per-span data and exposes it to Layers"; features `registry`+`std`); `Layer::on_event(&self, &Event, Context)`, `Layer::with_filter(F) -> Filtered<Self, F, S>`; per-layer filtering: "A span or event will be recorded if it is enabled by any per-layer filter" and "skipped by the layers whose filters did not enable it" (docs example: `.with(access_log.with_filter(filter_fn(...))).with(fmt_layer.with_filter(LevelFilter::INFO))`); `reload::Layer::new(filter) -> (layer, handle)`, `handle.modify(|f| *f = LevelFilter::INFO)` ("introduces a (relatively small) amount of overhead").

*tracing-appender 0.2.5.* `non_blocking(writer) -> (NonBlocking, WorkerGuard)` (guard "ensure[s] buffered logs are flushed … in the case of abrupt terminations"), `NonBlockingBuilder::lossy(bool)` (default lossy: "logs will be dropped when the buffered limit is reached"), `buffered_lines_limit`, `thread_name` (default `"tracing-appender"`), `finish(writer)`; `rolling::Builder::rotation(Rotation::{MINUTELY,HOURLY,DAILY,NEVER})` (default `NEVER`), `filename_prefix`, `filename_suffix`, `max_log_files(n)` ("Keeps the last `n` log files on disk"; `0` removes nothing; keep `m` files needs `m + 1`), `build(dir) -> Result<RollingFileAppender, InitError>`; names like `myapp.log.2019-01-01`.

*comfy-table 8.0.1 and tabled 0.22.0* are in F22; *miette 7.6.0* is in F34.

*tokio 1.54.1 (the locked version; `SignalKind::window_change()`).* `pub const fn window_change() -> Self`: "On Unix systems this signal is sent when the terminal window is resized." It is "ignored by default". `aitm` already enables tokio's `signal` feature.


### Part E. The degradation contract

**F28. The de-facto rules, with the places the tools disagree (read 2026-11-01; [S37][S36][S26][S27][S21]).**
1. **`NO_COLOR`** (no-color.org): "should check for a `NO_COLOR` environment variable that, when present and not an empty string (regardless of its value), prevents the addition of ANSI color"; "User-level configuration files and per-instance command-line arguments should override the NO_COLOR environment variable"; it is "a hint to the software … to suppress addition of color". *Disagreement on the empty string:* non-empty only: crossterm, anstyle-query/anstream, tracing-subscriber, gh (`!= ""`); set at all: console (`env::var("NO_COLOR").is_ok()`); set and not `"0"`: supports-color, npm ("set to something other than '0'"). Homebrew: `HOMEBREW_NO_COLOR` defaults to `$NO_COLOR`.
2. **`CLICOLOR` / `CLICOLOR_FORCE`** (bixense.com/clicolors, marked deprecated, recommends `FORCE_COLOR`/`NO_COLOR` for new software): "Empty variables are treated as though they were unset"; `CLICOLOR_FORCE` set (and `NO_COLOR` unset) = "ANSI colors should be enabled no matter what"; `CLICOLOR` set = "colors … should be used when the program is writing to a terminal"; `CLICOLOR=0` disables. *Precedence disagreement:* anstream and uv: `NO_COLOR` beats `CLICOLOR_FORCE` ("takes precedence over `FORCE_COLOR`"); console, gh (normal case) and supports-color: the force variable beats `NO_COLOR`.
3. **`FORCE_COLOR`**: read by supports-color (`true`/empty = 1, `false` = 0, digits) and uv; the CLICOLOR page says to treat it as an alias of `CLICOLOR_FORCE`.
4. **`TERM=dumb` or unset**: no colour and no progress (anstyle-query `term_supports_color`, indicatif `is_dumb()`, cargo `progress_supported`, supports-color level 0, npm progress default).
5. **CI**: cargo and npm turn the progress bar off; Vite stops clearing the screen (`!process.env.CI`); anstream and supports-color treat a present `CI` as "colour is fine even without a usable `TERM`" (both still require the stream to be a terminal). `CI=true` is set by GitHub Actions ("Always set to `true`", plus `GITHUB_ACTIONS=true`) and GitLab CI (`CI`, `GITLAB_CI` = `true`); `anstyle_query::is_ci` tests only that `CI` is present.
6. **Streams.** Results go to stdout, human status and progress to stderr (cargo, uv, gh); gh additionally requires **both** stdout and stderr to be TTYs before it shows a spinner, npm requires both for its progress bar; indicatif and anstream decide per stream (each `AutoStream`/`ProgressDrawTarget` looks only at its own stream). A log-stream tool such as mitmdump writes its log to stdout by design. With stdout piped and stderr a TTY (`aitm flow list > out.json`) the tools keep status styled and in place on stderr and send the plain result to the pipe; with stderr piped and stdout a TTY, in-place output stops. Matrix, derived from the rules above (not a tool's documented table):

| stdout | stderr | status/progress | result |
|---|---|---|---|
| TTY | TTY | styled, in place, animated | styled (tables, colour) |
| pipe | TTY | styled, in place (stderr decides) | plain, machine-readable (TSV/JSON) |
| TTY | pipe/file | plain lines, no animation | styled |
| pipe | pipe/file | plain lines, no animation, no ESC | plain |

7. **Unknown width.** gh falls back to 80 (and ignores `COLUMNS`), miette 80, clap 100 ("if that can't be determined, the default is 100"), cargo hands diagnostics a width only when it is `Known`, comfy-table `Dynamic` turns itself off without a width. uv says `COLUMNS` "Overrides terminal width used for wrapping. This variable is not read by uv directly." **Trap:** crossterm's `terminal::size()` opens `/dev/tty` first, so a process whose stdout and stderr are pipes can still receive a width from its controlling terminal; gate on `IsTerminal` of the stream you write to before trusting it. console's `Term::size_checked()` queries the stream's own fd and returns `None` for a non-terminal. (That bash does not export `COLUMNS` to children is **unverified** here.)
8. **SIGWINCH.** `tokio::signal::unix::SignalKind::window_change()` exists ("sent when the terminal window is resized", ignored by default). Whether indicatif or cargo re-measure on each redraw or on this signal is **unverified**.
9. **Unicode and fonts.** Fall back to ASCII when `TERM=linux` or the locale is not UTF-8 (supports-unicode: non-TTY always true; `TERM == linux` false; else `LC_ALL`/`LC_CTYPE`/`LANG` must end in `UTF-8`/`UTF8`; is-unicode-supported: non-Windows returns `TERM !== 'linux'`); cargo exposes `term.unicode`/`CARGO_TERM_UNICODE`, npm `unicode`; log-symbols' fallbacks are `i`, `√`, `‼`, `×` (Latin-1/CP437 characters, **not** ASCII).
10. **Explicit flags beat environment**: no-color.org and cargo (`--color`), uv (`--color`), gh (`--json`, `GH_FORCE_TTY`). **Prompts**: gh `GH_PROMPT_DISABLED`; aitm's `TtyConfirmer` already refuses without a TTY and names `--yes`.
11. **Hyperlinks** (OSC 8): cargo `term.hyperlinks`/`CARGO_TERM_HYPERLINKS`, off for iTerm in its code (`TERM_PROGRAM == "iTerm.app"`); `supports-hyperlinks 3.2.0` is cargo's detector. Optional for a CLI whose URLs are short.
12. **Windows (one line).** crossterm, anstream (`anstyle-wincon`) and console (`windows-sys`) carry Windows/ConPTY paths; aitmproxy's shipped targets are macOS and Linux, so no Windows work is needed.

**F29. What the tree already detects (read 2026-11-01; [S15][S10]).** `aitm-tui`'s `TermCaps::from_env` reads `COLORTERM`, `TERM`, `TERM_PROGRAM`, `KITTY_WINDOW_ID`, `WEZTERM_PANE`, `TMUX` for truecolor, kitty and sixel graphics and OSC 52; it reads neither `NO_COLOR` nor any TTY flag (it only runs inside an alternate-screen app). `aitm-cli`'s `TtyConfirmer::from_stdin` uses `std::io::IsTerminal`. tracing-subscriber's `ansi` honours `NO_COLOR` only. There is no shared detector.

**F30. The mode matrix a reporting layer must serve (derived from source, read 2026-11-01; [S2][S3][S8]).**

| Invocation | stdout is | stderr is | Likely TTY state |
|---|---|---|---|
| one-shot `aitm <verb>` | the command result | errors | operator terminal, or a pipe/script |
| bare `aitm` (default `mcp.transport: stdio`) | **the MCP JSON-RPC channel** | the only safe human channel | an agent launcher: stdin/stdout/stderr pipes; or a terminal when run by hand |
| bare `aitm` with `loopback_tcp`/streamable HTTP | free | free | terminal or service manager |
| `aitm web` | the card (token URL) **and**, with stdio MCP, JSON-RPC | logs | terminal; `< /dev/null` exits on stdin EOF (memory `aitmproxy-web-stdin-eof-exit`) |
| `aitm tui` | owned by ratatui | owned by ratatui | terminal; tracing already goes to a file or nowhere |
| mac embedded core (`aitm --config <file>`) | `Pipe()` read into Core Log | `Pipe()` read into Core Log | never a TTY |
| e2e harness | merged into a log file | merged | never a TTY |

### Part F. Structured logs beside the human view

**F31. Where tools keep logs and how they cap them (read 2026-11-01; [S38][S27][S21][S23][S26]).**
- cargo: `CARGO_LOG` (tracing) "usually only used during debugging"; the Cargo Book environment page does not say where those logs go. uv: `RUST_LOG`/`-v` ("tracing_subscriber"-compatible filters). gh: `GH_DEBUG` "verbose output on standard error", `api` adds HTTP. None of the three keeps a log file.
- npm: a per-run `*-debug-0.log` in `_logs` inside the cache, `logs-max` 10 (older ones are pruned), `logs-dir` configurable; the failure message prints the path once.
- Homebrew: `HOMEBREW_LOGS` "Use this directory to store log files": macOS `~/Library/Logs/Homebrew`, Linux `${XDG_CACHE_HOME}/Homebrew/Logs` or `~/.cache/Homebrew/Logs`.
- Platform guidance: Apple's File System Programming Guide, table row `Logs`: "Contains log files for the console and specific system services. Users can also view these logs using the Console app" (it gives no rule for third-party apps); `Application Support`: "app-specific data and support files … in a subdirectory whose name matches the bundle identifier". XDG: "$XDG_STATE_HOME … user-specific state files"; "If … not set or empty, a default equal to $HOME/.local/state should be used"; its listed examples include "actions history (logs, history, recently used files, …)".
- `dirs 5.0.1` (in lock): `state_dir()` is `$XDG_STATE_HOME` or `$HOME/.local/state` on Linux and `None` on macOS and Windows; there is no log-dir function in that version; `dirs::config_dir()` on macOS is `~/Library/Application Support`, which is why aitm's CA and audit files live in `~/Library/Application Support/aitmproxy/` (`crates/aitm-core/src/config.rs` `default_aitm_dir`).
- aitm today: `aitm tui` writes `$AITM_TUI_LOG` or `aitm-tui-<pid>.log` under `std::env::temp_dir()`, mode 0600, only when `RUST_LOG` is set, and tells the operator in its startup toast (`embedded proxy · set RUST_LOG to write a log file` / `embedded proxy · log: <path>`); the CA audit log is `ca-audit.jsonl` beside the CA dir.

**F32. Folding WARN+ events into an in-place UI without a second subscriber (read 2026-11-01; [S36]).** The documented pieces: one `tracing_subscriber::registry()` composed of several layers (`Registry` + `.with(layer)`), each layer with its own `with_filter(...)` ("recorded if it is enabled by any per-layer filter … skipped by the layers whose filters did not enable it"); a file layer (`fmt::layer().with_ansi(false).with_writer(file_or_non_blocking)`) at the user's `RUST_LOG`/`-v` level; a small custom `Layer` whose `on_event(&self, &Event, Context)` calls `event.record(&mut visitor)` with a `tracing::field::Visit` implementation (`record_debug` is required; `record_str`, `record_i64`, `record_u64`, `record_bool`, `record_error` default to it) and sends `{level, target, message, fields}` through a channel that the renderer drains on its tick; `event.metadata()` gives level and target. A runtime `-v` switch is `reload::Layer::new(env_filter)` plus `handle.modify(...)`. `tracing-indicatif 0.3.14` is the packaged variant for indicatif (`IndicatifLayer`, `get_stderr_writer()` so log lines do not clobber bars); its non-TTY behaviour is **not stated** on the page read. That the message text arrives as a field named `message` is conventional but **not stated** on the two docs pages fetched.

**F33. In-tree precedents for the log side (read 2026-11-01; [S2]).** `tui::init_tracing` returns a `TuiLog { Off, File(path), Unavailable{path, why} }` and builds a subscriber with `fmt().with_env_filter(filter).with_ansi(false).with_writer(Mutex::new(file))`; the file is opened owner-read/write on Unix. `main.rs` tests already use a custom `MakeWriter` over `Arc<Mutex<…>>` to capture records. The bridge token must never reach a sink (hygiene spec), and `web::log_listening` is pinned to a token-free line.

### Part G. Error presentation and exit codes

**F34. Shapes (read 2026-11-01; [S40][S21][S23][S26][S36]).**
- *rustc's rules* (rustc-dev-guide): levels `error`, `warning`, `help` ("show changes the user can possibly make to fix the problem"), `note` ("other context, facts, and online resources"); "The error or warning portion should _not_ suggest how to fix the problem, only the 'help' sub-diagnostic should"; messages "start with a lowercase letter and do not end with punctuation", "should be succinct"; suggestions "should not be a question" and avoid "did you mean".
- *cargo*: `error:` then blank then `help:` lines (observed, F11). *uv*: `error:` then `tip:` (clap) or an indented `hint:` paragraph inside the `×`/`╰─▶` frame (observed, F12). *gh*: plain sentences, or Usage + flags for flag errors, and a next-step sentence for auth (F14). *aitm today*: `Error: <message>` with a `Caused by:` chain from anyhow's Debug (config errors), or bare one-liners (registry errors), or an unstructured multi-line paragraph (port in use).
- *miette 7.6.0* (Apache-2.0): `MietteHandlerOpts` options read: colours "used only if the terminal supports them", `unicode(bool)` ("If set to false, forces ASCII art display"), `force_graphical`, `force_narrated` ("forces use of the narrated renderer"), terminal links auto-detected, `width` "Defaults to 80"; its `fancy` feature is what brings `supports-color 3`, `supports-hyperlinks 3`, `supports-unicode 3`, `terminal_size`, `owo-colors`, `textwrap`, `backtrace`, `backtrace-ext`. Which handler it picks from `NO_GRAPHICS` or `NO_COLOR` is **not stated** on the pages read. *ariadne 0.6.0* renders source-snippet reports; *color-eyre 0.6.5* prints an `Error:` chain plus `SPANTRACE` and `Suggestion:` sections, verbosity via `RUST_LIB_BACKTRACE` and `RUST_SPANTRACE`, installed with `color_eyre::install()`; its non-TTY/`NO_COLOR` behaviour is **not stated**. These are source-code diagnostics libraries; none of the CLIs read uses them for plain operator errors.
- *Fix commands.* cargo, uv and gh all embed the command **inline** in a sentence or between backticks (``view all installed commands with `cargo --list` ``; `To get started with GitHub CLI, please run:  gh auth login`); gh puts command examples on their own `$ `-prefixed lines only in help `EXAMPLES`; Homebrew's `caveats` align commands in a column. A command on its own line with no surrounding prose is therefore a **candidate** for copy-safety, not observed prior art.

**F35. Exit codes (read 2026-11-01; [S40][S26]; observed where marked).** sysexits (FreeBSD `sysexits(3)`): `EX_USAGE 64`, `EX_DATAERR 65`, `EX_NOINPUT 66`, `EX_NOUSER 67`, `EX_NOHOST 68`, `EX_UNAVAILABLE 69` ("A service is unavailable"), `EX_SOFTWARE 70`, `EX_OSERR 71`, `EX_OSFILE 72`, `EX_CANTCREAT 73`, `EX_IOERR 74`, `EX_TEMPFAIL 75`, `EX_PROTOCOL 76`, `EX_NOPERM 77`, `EX_CONFIG 78` ("misconfigured state"); the same page says "This interface has been deprecated and is retained only for compatibility. Its use is discouraged." and "This interface is not portable." What the tools actually use: cargo 101 for an unknown command and 1 for a bad flag (observed), uv 2 for clap usage errors and 1 for failures (observed), gh 0/1/2 (cancelled)/4 (needs auth) (documented, 4 observed), aitm 1 and 2. None of the three Rust/Go tools read uses sysexits.

### Part H. `--version` and Homebrew

**F36. (read 2026-11-01; [S7][S39][S1]).** One plain line, `name version (sha date [target])`: `cargo 1.97.1 (c980f4866 2026-06-30) (Homebrew)`, `uv 0.11.15 (3cffe97c2 2026-05-18 aarch64-apple-darwin)`, `gh version 2.96.0 (2026-07-02)` + a release URL; `--version --verbose` adds fields in cargo (8 lines). Wall times measured here (single runs): cargo 33-42 ms, uv 15 ms warm, gh 146 ms, npm 290 ms, brew 366 ms, mitmdump 4.9 s, so the premise "typically under 10 ms" did not hold for any of them on this machine; aitm's own pre-boot paths take 9-15 ms (a 36 MB Mach-O). Homebrew's Formula Cookbook: "`foo --version` and `foo --help` are bad tests" but "a bad test is better than no test at all", preferring "tests that don't require any user input and test the basic functionality"; real formulae: `gh` asserts `gh version #{version}` from `gh --version` plus help text of subcommands; `uv` runs `uv pip compile` and `uvx ruff --version`; `ripgrep` writes `Hello.txt` and runs `rg "Hello World!"`. **aitm's own formula avoids `--version`**: it asserts `web operator UI` in `aitm web --help` and exit 2 with `usage: aitm-tui` in `aitm-tui --help` (F6). `main()` already has a pre-boot dispatch point for `operator-token` and `sysproxy-watchdog` ("exit before anything is built — no config load, no tracing sink, no service, no runtime"), and `web --help` is answered before config load (`parse_invocation`, main.rs:226-260).

### Part I. Brand constraints, words, glyphs and spinner frames

**F37. Brand rules on record (read 2026-11-01; [S19][S17][S18]).**
- Matt, 2026-10-27 (memory `aitmproxy-ui-icon-editorial-rule`): icons "flat and minimal - monochrome … glyphs with no … capsule, no backing, no bevels, no heavy chrome", paired with an "editorial direction: typography-forward hierarchy, generous whitespace, hue only on data, crisp grid alignment, calm chrome and empty states"; it "overrides `docs/design/operator-ui-foundation.md` where the two conflict and is the shared rule for the web and TUI surfaces too". Matt, 2026-10-28 (memory `aitmproxy-operator-first-run-hygiene`): "Don't flood the terminal with logs", "Never expose the token in the terminal or logs", expected/benign errors must be `debug`. Matt's words for this task (via the orchestrator): "on brand nice way of reporting things loading ideally fully animated and with in place UI that does not just spits things like a web server".
- Foundation and tokens (`docs/design/tokens.json`, `operator-ui-foundation.md`): TUI maps weight to bold, tertiary to dim, selection to reverse; "truecolor terminals use the dark hex; 256/16-color terminals use the `tui` ANSI name"; ANSI names: accent `blue`, intercept `yellow`, agent `cyan`, `state.success` `green`, `state.warning` `yellow`, `state.danger` `red`, `state.neutral` `white`; "Degrades, never drops"; motion: "Feedback only; nothing on screen performs an entrance. Keyboard-initiated actions … never animate. Reduced-motion drops travel"; "New flows append with no animation"; the only pulse is the armed-intercept dot. Product mark `›•‹` ("the TUI prints it as text"), wordmark `aitmproxy`.
- **The glyph table contains emoji.** `icon.glyph.tui` lists `U+270B` (intercept), `U+1F513` (lockOpen), `U+1F512` (lock), which are East Asian Wide (2 columns) emoji; the TUI's `tokens.rs` test pins them. They conflict with the "monochrome, no emoji" rule; a CLI should not copy them.

**F38. The words to reuse (read 2026-11-01; [S15][S16][S3][S18]).**
- Shared sentence, `NOTHING_DECRYPTED_ADVICE` (`crates/aitm-core/src/config.rs:176`), verbatim: **"Nothing is decrypted until a host is in Scope."** Frontends "print it; they never compose their own".
- CA words: the TUI (`crates/aitm-tui/src/model.rs:646-657`) and web (`apps/web/src/state/caTrust.ts:44-48`) use **`· CA trusted`**, **`· CA untrusted`** and the in-flight **`· CA trusting…`**. The brief expected "CA not trusted"; the code says **"untrusted"**. When every store answers `unknown`, or there is no certificate, **no word is shown** ("an unread state never renders as 'untrusted'", D17.5). The reduction rule: any store `trusted == "yes"` means trusted; else any `"no"` means untrusted; else unread. Raw vocabulary from the core: `Presence` `present | absent | stale | unknown`, `Trust` `yes | no | unknown`, `Platform` `macos | linux-debian | linux-fedora | windows | unsupported`, `Scope` `user | system` (`crates/aitm-ca/src/store.rs`); `proxy.status.decrypt` = `{scope_hosts, decrypting, advice}` and `version` (`crates/aitm-plugins/src/control.rs`).
- The TUI pill, composed in `crates/aitm-tui/src/ui/bars.rs:71-107`: `● aitmproxy · listening 127.0.0.1:8080 · CA trusted · intercept armed`, with states `· capture paused`, `not serving`, `bus disconnected`, `connecting to the bus…`; the foundation's version: `● aitmproxy · 127.0.0.1:8080 · HTTP/2`.
- mac lane words (spec `2026-10-31-macos-status-page-and-first-run-design.md`): Core `running` / `starting…` / `failed` / `stopped` / `external`; Bus `connected` / `connected as agent` / `connecting…` / `bus failed` / `offline`; Capture `capture off` / `waiting for approval` / `capture degraded` / `on, nothing in scope` / `capture on · n hosts in scope`; the glossary says Core is "not server, daemon, backend", Getting started is "not onboarding, wizard, tour"; checklist rows use `✓` and `○`; the Status mock-up uses `●`, `◐`, `○`, `✓` and `─` rules.
- The `aitm web` card labels today: `Web UI`, `Operator`, `Proxy`, `Browser`, `Bus`, `Scope`, padded to one column under 60-column `─` rules.

**F39. Glyph safety (read/run 2026-11-01; [S42][S45]).**
- *Width class* (Python `unicodedata` 16.0.0 `east_asian_width`, run locally): **Ambiguous** (drawn 2 columns in CJK-ambiguous-wide terminals, which breaks in-place alignment): `─ │ ┌ ┐ └ ┘ ├ ┤ ┬ ┴ ┼ ═ ║ ╭ ╮ ╰ ╯ ● ○ ◐ ◆ ◇ · • █ ▓ ▒ ▲ ▶ → ‖`; **Neutral** (stable): `▸ ▪ ✓ ✗ ✔ ✖ ✕ ⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏ ⣾ ⣽ ⣻ ⢿ ⡿ ⣟ ⣯ ⣷ ➜ › ↻ ⇄ ⚠ ⨯ » ░ ▱ ▰`; **Wide** (2 columns, emoji): `U+270B U+1F513 U+1F512`; ASCII is `Na`. `unicode-width 0.2.3`'s `width()` counts Ambiguous as 1 column, `width_cjk()` as 2.
- *Font coverage* (GitHub issue `YoanWai/agent-manager#627`, which checked **font files, not live terminals**; a third-party source, weak): `●` and `○` absent from Ubuntu Mono and Monaco; `◐` absent from Ubuntu Mono, Monaco, SF Mono, Courier New; `✓` absent from Liberation Mono, Ubuntu Mono, Monaco, Courier New; `▸` absent from Liberation Mono, Ubuntu Mono, Monaco, Courier New; braille `⠋` "absent from every face except Cascadia Mono" (the eight faces: Menlo, Monaco, SF Mono, Courier New, DejaVu Sans Mono 2.37, Liberation Mono 2.1.5, Ubuntu Mono 0.83, Cascadia Mono); the set present in all eight: `° ¶ · × é – — • … − ─ │ ├ ┤ █`. The corners `┌ ┐ └ ┘` were not on the issue's lists (**unverified**). The issue notes "the terminal substitutes a glyph that may look wrong", i.e. terminals fall back per glyph (Terminal.app, iTerm2, VS Code behaviour **unverified here**; Terminal.app's default profile font was reported inconsistently, Menlo versus SF Mono, in the search results; no authoritative Apple source found).
- *Linux console* (`TERM=linux`): "the console draws text from a single kernel font of at most 512 glyphs" (several search results: `markcheck#171`, `libvtty#217`, a BRLTTY post, a Hacker News comment): box-drawing is present, `◐ ⊘ ❯ ↻ ⇅` and ballot marks are absent, braille needs a braille console font, and Terminus "does not support Braille in any way"; supports-unicode and is-unicode-supported both answer "no unicode" for `TERM=linux`.
- *Tools' own sets*: gh `✓` `!` `X`; Next `○ ⨯ ⚠ ▲ ✓ »`; Vite `➜`; uv `× ╰─▶`; log-symbols `ℹ ✔ ⚠ ✖` (fallback `i √ ‼ ×`); charm `● ∙`.
- *ASCII fallback set* (candidate, not tool-verified as a set): spinner `- \ | /`; status `*` or `o` for `● ○`, `+` or `ok` for `✓`, `x` for `✗`, `!` for warning, `>` for `▸`, `-` for a rule and `|` for a column rule, `...` for `…`, `-` for `·`.
- *Spinner frames and cadence*: braille `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` is cli-spinners' `dots` (80 ms), bubbles' `MiniDot` (12 fps), and gh's set (120 ms interval, braille per its comment); the line set `- \ | /` is cli-spinners' `line` (130 ms, order `- \ | /`) and bubbles' `Line` (10 fps, order `| / - \`); indicatif's own default is a different braille string ending in a space (final frame); the calm `simpleDots` set `.  ` `.. ` `...` runs at 400 ms. Pick braille when the stream is a TTY, the locale is UTF-8 and `TERM != linux`; otherwise the line set; and none at all when the stream is not a TTY. All braille frames are Neutral width (stable 1 column). Cargo shows nothing before 500 ms, which matters here: the real startup phases finish in about 9 ms, so a spinner would never be seen unless it is deliberately delayed or the work grows.


## 4. Candidate directions for the Architect

Nothing below is a decision. Where the evidence points at an option it is marked **evidence points here**.

### 4.0 Dimensions every direction must settle (independent of the library)

1. **Channel contract.** Results to stdout, human status/progress/errors to stderr, diagnostics to a file or behind `-v` is what cargo, uv and gh all do (F11, F12, F14, F19); aitm's stdout `fmt` subscriber breaks it (R8, R9, F5), and in bare `aitm` with stdio MCP it also collides with the JSON-RPC channel that the MCP spec reserves (F5, F30). **Evidence points here:** tracing must stop writing to stdout in every mode whatever else changes.
2. **Pre-boot fast paths** for `--version`, `--help`/`help`, `-h`, usage errors, so they print without a tracing sink, config load, script tier or CA creation (R1, R2, R11, F2, F36). `main()` already has this shape for `operator-token` and `sysproxy-watchdog`; the Homebrew formula test already depends on `aitm web --help` and `aitm-tui --help` (exit 2) (F6, F36).
3. **Mode matrix** (F30): one-shot, bare server with stdio MCP, `aitm web`, `aitm tui`, the mac child with `Pipe()`s, the e2e harness. The mac child and e2e must get plain lines without escape bytes (F6).
4. **Pinned text** to keep, move or re-pin on purpose (F6): `proxy listening`, `obscura probed`, `already in use`, the port, no `os error 48`, `config file`, the `#t=` URL pattern, `web operator UI`, `usage: aitm-tui` with exit 2, the token-free `web UI listening` line.
5. **Vocabulary and glyph set** shared with TUI, web and mac (F37-F39): `Nothing is decrypted until a host is in Scope.`, `CA trusted`/`CA untrusted`, lane words, `●`/`○`/`✓`/`─` plus an ASCII set.
6. **Verbosity ladder, log file location, exit-code scheme** (F31-F35); **one-shot semantics** for verbs that change state (R14) is a product question, not a rendering one.
7. **Proof.** No pty was available to me; Matt's no-fixture rule means in-place rendering must be proven in a real terminal through the Terminal panel. `indicatif`'s `ProgressDrawTarget::term_like(Box<dyn TermLike>)` is a hermetic capture seam for unit tests (signature verified), and a hand renderer can write to any `io::Write`.

### 4.A Direction A: `indicatif` + `console` (optionally `tracing-indicatif`)

- *What it gives (verified):* bars and spinners that hide themselves when the stream is not a terminal or `TERM` is `dumb`, stderr by default, `MultiProgress` with `println`/`suspend` so log lines and bars do not clobber each other, templates with styles, a steady-tick thread, `console::Style`, `measure_text_width`, `truncate_str`, `Term::size_checked`, NO_COLOR/CLICOLOR handling; uv ships this combination (indicatif 0.18 + console 0.16 + anstream + owo-colors) (F12, F27).
- *Cost:* 4 new lock entries (`indicatif`, `console`, `unit-prefix`, `encode_unicode`), +1 with `tracing-indicatif`; MIT; MSRV 1.85 and 1.71, both below the workspace's 1.97 (F26). One background thread per steady-ticking bar.
- *Trade-offs:* least custom drawing code and the most battle-tested line accounting; but (a) `ProgressBar::println` does nothing when hidden, so the non-TTY plain-line path is still ours to write (use `suspend` or print directly when `is_hidden()`); (b) console's colour precedence is "`CLICOLOR_FORCE` beats `NO_COLOR`", the opposite of anstream and uv (F28); (c) a checklist card (`✓ Core ready`, rows that turn from spinner to glyph) is expressible with `MultiProgress` plus per-bar finish messages but is not what the default bar templates draw; (d) no first-draw delay (cargo's 500 ms), so a delayed-creation wrapper is needed to avoid flashing 9 ms phases; (e) resize and over-long-line behaviour **unverified**.

### 4.B Direction B: own small renderer on `crossterm 0.29` (already in the tree) + styling

- *B1, zero new crates:* `crossterm` is already linked into `aitm` through `aitm-tui`; add it as a direct dependency of the `aitm` crate (the lock gains nothing). Use `Stylize`, `Clear(ClearType::CurrentLine)`, `MoveUp`, `MoveToColumn`, `Hide`/`Show`, `BeginSynchronizedUpdate`/`EndSynchronizedUpdate`, `std::io::IsTerminal` per stream, `unicode-width`/`unicode-truncate` (both in the lock), a `Drop` guard for the cursor, tokio's `SignalKind::window_change()` for resize (F27). crossterm styling honours a non-empty `NO_COLOR` and `force_color_output` but **never tests for a TTY**, and `terminal::size()` uses `/dev/tty` (F27, F28 rule 7), so the gating and the width trap are ours.
- *B2, + `anstyle`/`anstream`:* 6 new lock entries (+2 for Windows) buy the verified auto order (`NO_COLOR` > `CLICOLOR_FORCE` > `CLICOLOR=0` > terminal+`TERM`/CI) and stripping: write styled text, get plain text on non-TTY streams for free, the same stack cargo and clap use (F11, F27).
- *Trade-offs:* full control of brand glyphs, cadence (a 500 ms first draw, 80-120 ms frames), the checklist layout, the ASCII set, a log-channel layer that feeds the same renderer, and no `unsafe` (crossterm hides the ioctls); in exchange the line-accounting corner cases that indicatif and console already solved (a line wider than the terminal, resize during a draw, cursor restore on SIGINT/panic, interleaved tracing output) become our code and our tests. Estimated at a few hundred lines; that figure is my judgement, not a sourced number.

### 4.C Direction C: `console` only, no animation

- *What it gives:* styled, aligned, one-line-per-event output with no thread: cargo-style right-aligned verbs or gh-style icon lines on stderr, a one-line summary per phase (`49 detection scripts loaded`), `Term::is_term`, width-aware `truncate_str`/`pad_str`, `Style` with stream-aware colour; one new lock entry (+`encode_unicode` for Windows); every line stands alone, so degradation to a pipe, the mac Core Log and the e2e log is trivial and the pinned strings (`proxy listening`, …) can stay greppable.
- *Trade-offs:* does not deliver "fully animated … in place" (Matt's wording). The evidence suggests the loss is small for the paths measured: cargo itself draws nothing for the first 500 ms (F11), the 49-script load takes about 9 ms (F2), and one-shot commands take about 20 ms; the phases that can be long (obscura launch, system-proxy recovery, a port wait) were **not measurable** in the sandbox. A static layer can be built first and an animated phase line added later on top of it (A or B), since both need the same channel contract and plain-line fallback.

### 4.D Orthogonal candidates

- **Logging plumbing.** (i) Registry with a file `fmt` layer (own `OpenOptions` 0600 file as `aitm tui` already does: 0 new crates; or `tracing-appender` 0.2.5: +2 crates `tracing-appender`, `symlink`, adds non-blocking writes and `max_log_files`) plus a small channel `Layer` for WARN+ that the renderer drains (F32); (ii) a stderr subscriber at `warn` by default with `-v`/`-vv`/`RUST_LOG` raising it (cargo/uv model); (iii) both. Location candidates: macOS `~/Library/Logs/aitmproxy/` (Apple's `Logs` row; Homebrew precedent) or the existing `~/Library/Application Support/aitmproxy/`; Linux `$XDG_STATE_HOME/aitmproxy` or `~/.local/state/aitmproxy` (XDG; `dirs 5.0.1::state_dir()` returns `None` on macOS, so a macOS path needs code or a newer `dirs`) (F31).
- **Help and usage.** (i) Hand-render grouped help from `Registry::commands()` (it already supplies the dotted name, description, typed params and required flag; group by first segment, wrap to width, add `EXAMPLES` and a `LEARN MORE` footer as gh does); (ii) adopt `clap` (4.6.7) for `--help`/`-h`, did-you-mean, `help_heading`, `after_help`, colour styles and `--version`: roughly 10-12 new lock entries; the 91 verbs come from a runtime registry, so only the builder API with owned strings would apply (the `string` feature uv enables; **unverified for this use**).
- **Result rendering.** The shapes in F10 suggest a four-way renderer (table, card, list, scalar/bytes) behind a `--json` escape hatch, with gh's rule (aligned and truncated on a TTY, tab-separated raw values when piped) as prior art (F14, F22); `comfy-table` 8.0.1 (+1 entry, reuses `crossterm`) or a hand table over `unicode-width`.
- **Pager.** spawn `$PAGER` with `LESS=FRX` only when stdout is a TTY (gh, git); no crate needed (F23).

### 4.E Summary of trade-offs

| | A indicatif + console | B1 crossterm renderer | B2 B1 + anstyle/anstream | C console only |
|---|---|---|---|---|
| New lock entries | 4 (+1 tracing-indicatif) | 0 | 6 (+2 Windows) | 1 (+1 Windows) |
| In-place animation | yes, library-drawn | yes, ours | yes, ours | no |
| Plain-line fallback | ours (println is a no-op when hidden) | ours | ours, colour stripped by anstream | native |
| Colour precedence | console's (force beats `NO_COLOR`) | crossterm: non-empty `NO_COLOR`, no TTY test | anstream's verified order | console's |
| Width trap (`/dev/tty`) | avoided (own-fd ioctl) | present, must gate | present, must gate | avoided |
| Hermetic test seam | `term_like` | any `io::Write` | any `io::Write` | any `io::Write` |
| Custom drawing code | least | most | most | none |
| Background thread | steady tick | ours | ours | none |

## 5. Open questions

1. **No TTY evidence.** I could not allocate a pty, so no in-place rendering (cargo bar, uv bar, gh spinner, indicatif) was observed; TTY behaviour in this note is from source and docs. A Terminal-panel recording is needed before any design is accepted (Matt's no-fixture rule).
2. **Bare `aitm` stdout collision (F5)** is source-verified only; confirm in the Terminal panel with `aitm 2>/dev/null | head` (or an MCP client attached) that INFO lines really precede JSON-RPC on stdout.
3. **Mac Core Log and ANSI (F6).** Does the Core Log panel show raw escape bytes from the embedded core today? Untested.
4. **How long the long phases take** (obscura launch, system-proxy recovery, waiting on a busy port): not measurable here; they decide whether animation is ever visible.
5. **Font and terminal coverage** for braille and the geometric glyphs in Terminal.app, iTerm2 and VS Code was not tested; the only coverage data is a third-party font-file check (F39). Terminal.app's default font is reported inconsistently.
6. **indicatif details:** resize behaviour, over-long lines, hidden-target behaviour of `MultiProgress` redraws, whether a `TermLike` capture reproduces real cursor moves. uv's progress implementation beyond its dependency list.
7. **`NO_COLOR` empty-string and `CLICOLOR_FORCE` vs `NO_COLOR` precedence** differ between libraries (F28); which rule aitm follows is open.
8. **Which `owo-colors` feature maps to which `supports-color` major** (F27); only matters if Option owo-colors is wanted.
9. **`message` field name** in a custom tracing `Layer` (F32) is conventional but not confirmed on the pages read; `tracing-indicatif`'s non-TTY behaviour is not stated.
10. **Bun, Deno, pnpm, Docker, npm output** were read from docs only, not run; Deno's and Bun's non-TTY behaviour is unverified.
11. **Exit-code scheme** (sysexits vs cargo/uv/gh habits vs today's 1/2): no tool read uses sysexits; sysexits is documented as deprecated and non-portable.
12. **Product questions surfaced, not researched:** should one-shot verbs reach a running core instead of a fresh in-memory proxy (R14); should `--version` and `--help` ever create a CA (R11); the `aitm web` stdio-EOF exit (memory `aitmproxy-web-stdin-eof-exit`) interacts with any "ready" banner.
13. `cli-table`, `ariadne`, `color-eyre`, `supports-unicode` internals, `textwrap`, `pager`, `minus` were read at metadata level only; `tabled`'s lock weight without default features is unverified.
14. mitmproxy's current `listening` line text (varies by version in search results) was not observed; `mitmdump` cannot bind in the sandbox.


## 6. Sources

All read or run on 2026-11-01. "WebFetch" pages were summarised by the fetch tool; where a quote matters it is the tool's quotation of the page, and I flagged anything it could not show as unverified. Direct `curl` to `crates.io` and `raw.githubusercontent.com` was refused by the sandbox proxy.

**Local runs and repo files**
- [S1] Real binary: `/opt/homebrew/bin/aitm` 0.5.10 (`/opt/homebrew/Cellar/aitm/0.5.10/libexec/aitm`, `aitm-tui`, `share/aitm/scripts`, 49 `.rhai` files), driven through Python `subprocess` with `HOME=$TMPDIR/aitm-critique-home`; comparison runs of `cargo 1.97.1`, `gh 2.96.0` (isolated `GH_CONFIG_DIR`, sanitised environment), `uv 0.11.15` (offline), `npm 11.17.0`, `brew`, `mitmdump 12.2.2` (`--version` only). Python `unicodedata` 16.0.0 for East Asian Width.
- [S2] `crates/aitm/src/main.rs`, `web/mod.rs`, `tui.rs`, `operator_token.rs`, `bundled.rs`, `config_file.rs`, `lib.rs`, `wire.rs`, `scripts.rs`.
- [S3] `crates/aitm-core/src/config.rs`, `crates/aitm-mcp/src/transport.rs`, `crates/aitm-plugins/src/control.rs`.
- [S6] `tests/e2e/cli/cli-startup.sh`.
- [S7] `/opt/homebrew/Library/Taps/mrbrutti/homebrew-aitmproxy/Formula/aitm.rb` and `https://raw.githubusercontent.com/mrbrutti/homebrew-aitmproxy/main/Formula/aitm.rb` (WebFetch; identical `test do` and `caveats`).
- [S8] `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift`, `apps/mac/Sources/AitmproxyKit/CoreHealth.swift`.
- [S9] `docs/superpowers/specs/2026-10-30-aitm-web-startup-hygiene-design.md`.
- [S10] `crates/aitm-cli/src/confirm.rs`. [S11] `crates/aitm-cli/src/dispatch.rs`.
- [S12] `crates/aitm-plugin-rhai/src/loader.rs`, `engine.rs`, `host_core.rs`; `crates/aitm-core/src/proxy.rs`; `crates/aitm-browser/src/obscura.rs`; `crates/aitm-ca/src/commands.rs`; `crates/aitm-sysproxy/src/lib.rs`.
- [S13] `crates/aitm/src/render.rs`.
- [S14] command schemas: `crates/aitm-plugins/src/*.rs`, `crates/aitm-ca/src/commands.rs`, `crates/aitm-findings/src/commands.rs`, `crates/aitm-plugin-scanner/src/commands.rs`, `crates/aitm-plugin-rhai/src/commands.rs`, `crates/aitm-plugin-maprules`, `-passthrough`, `-sessionio`, `-wsctl`, `crates/aitm-poc`, `crates/aitm-proto-l4/src/commands`.
- [S15] `crates/aitm-tui/src/model.rs`, `ui/bars.rs`, `caps.rs`, `tokens.rs`; `apps/web/src/state/caTrust.ts`.
- [S16] `crates/aitm-ca/src/store.rs`, `commands.rs`.
- [S17] `docs/design/tokens.json`, `docs/design/operator-ui-foundation.md`.
- [S18] `docs/superpowers/specs/2026-10-31-macos-status-page-and-first-run-design.md`.
- [S19] Memory notes `aitmproxy-ui-icon-editorial-rule`, `aitmproxy-operator-first-run-hygiene`, `aitmproxy-web-stdin-eof-exit`, `aitmproxy-cli-first-run-fixes` (user auto-memory store), `docs/research/MEMORY.md`.
- [S20] `Cargo.toml`, `Cargo.lock` (410 packages), `crates/aitm/Cargo.toml`, `crates/aitm-tui/Cargo.toml`, `cargo tree --offline -i …`.

**Web, prior art**
- [S4] https://docs.rs/tracing-subscriber/0.3.23/tracing_subscriber/fmt/struct.Layer.html, `.../fmt/index.html`, `.../layer/index.html`, `.../layer/trait.Layer.html`, `.../reload/index.html`, `.../registry/index.html`; https://docs.rs/tracing/0.1.44/tracing/field/trait.Visit.html; https://docs.rs/tracing-core/0.1.36/tracing_core/struct.Event.html.
- [S5] https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
- [S21] https://doc.rust-lang.org/cargo/reference/config.html ; https://doc.rust-lang.org/cargo/reference/environment-variables.html ; https://doc.rust-lang.org/cargo/commands/cargo.html
- [S22] https://raw.githubusercontent.com/rust-lang/cargo/master/crates/cargo-util-terminal/src/shell.rs ; `.../style.rs` ; https://doc.rust-lang.org/stable/nightly-rustc/src/cargo/util/progress.rs.html ; https://raw.githubusercontent.com/rust-lang/cargo/master/Cargo.toml
- [S23] https://docs.astral.sh/uv/reference/environment/ ; https://docs.astral.sh/uv/reference/cli/ ; https://raw.githubusercontent.com/astral-sh/uv/main/Cargo.toml
- [S24] https://docs.astral.sh/ruff/settings/
- [S25] https://pnpm.io/cli/install ; https://bun.com/docs/pm/cli/install ; https://bun.com/docs/runtime/bunfig
- [S26] https://cli.github.com/manual/gh_help_environment ; `.../gh_help_formatting` ; `.../gh_help_exit-codes` ; https://raw.githubusercontent.com/cli/cli/trunk/pkg/iostreams/iostreams.go ; `.../pkg/iostreams/color.go` ; `.../internal/tableprinter/table_printer.go` ; `.../pkg/cmd/root/help.go` ; `.../pkg/cmd/root/root.go` ; `.../pkg/cmd/auth/login/login.go` ; `.../pkg/cmd/auth/shared/login_flow.go` ; https://raw.githubusercontent.com/cli/go-gh/trunk/pkg/tableprinter/table.go ; `.../go-gh/trunk/pkg/term/env.go`
- [S27] https://docs.npmjs.com/cli/v11/using-npm/config ; web search "npm error A complete log of this run can be found in" (user reports, not npm source)
- [S28] https://docs.docker.com/reference/cli/docker/buildx/build/
- [S29] https://raw.githubusercontent.com/vitejs/vite/main/packages/vite/src/node/cli.ts ; `.../logger.ts` ; https://raw.githubusercontent.com/vercel/next.js/canary/packages/next/src/build/output/log.ts ; `.../server/lib/app-info-log.ts`
- [S30] https://docs.deno.com/runtime/reference/cli/install/
- [S31] https://raw.githubusercontent.com/mitmproxy/mitmproxy/main/mitmproxy/addons/termlog.py ; https://docs.mitmproxy.org/stable/overview/getting-started/ ; https://docs.mitmproxy.org/stable/concepts/certificates/ ; web search "Proxy server listening at" (several sources, version-dependent wording)
- [S32] https://proxyman.com/docs/ ; web search results for https://proxyman.com/docs/debug-devices/macos and `.../basic-features/proxy-setting-tool` ; https://portswigger.net/burp/documentation/desktop/getting-started/intercepting-http-traffic ; https://portswigger.net/burp/documentation/desktop/settings/tools/proxy
- [S33] https://raw.githubusercontent.com/charmbracelet/bubbles/main/spinner/spinner.go ; https://raw.githubusercontent.com/charmbracelet/log/main/README.md ; https://raw.githubusercontent.com/charmbracelet/gum/main/README.md ; https://raw.githubusercontent.com/charmbracelet/fang/main/README.md ; https://raw.githubusercontent.com/charmbracelet/lipgloss/main/README.md ; https://raw.githubusercontent.com/charmbracelet/bubbletea/main/README.md ; https://raw.githubusercontent.com/charmbracelet/glamour/master/README.md
- [S34] https://docs.rs/clap/latest/clap/struct.Command.html (clap 4.6.7) ; https://docs.rs/clap/latest/clap/builder/struct.Styles.html
- [S35] crates.io API (WebFetch): https://crates.io/api/v1/crates/{indicatif, console, owo-colors, supports-color, supports-unicode, anstyle, anstream, anstyle-query, anstyle-parse, colorchoice, is_terminal_polyfill, is_ci, unit-prefix, terminal_size, crossterm, yansi, nu-ansi-term, unicode-width, unicode-truncate, tracing-subscriber, tracing-appender, symlink, indicatif-log-bridge, tracing-indicatif, comfy-table, tabled, cli-table, miette, ariadne, color-eyre, clap, textwrap, pager, minus, dirs} and `.../{indicatif/0.18.6, console/0.16.6, anstream/1.0.0, owo-colors/4.4.0, supports-color/3.0.2, terminal_size/0.4.4, tracing-appender/0.2.5, comfy-table/8.0.1, tabled/0.22.0, papergrid/0.18.0, tabled_derive/0.12.0, indicatif-log-bridge/0.2.3, tracing-indicatif/0.3.14, clap/4.6.7, clap_builder/4.6.7}/dependencies` and the version pages for `features`.
- [S36] docs.rs: https://docs.rs/indicatif/0.18.6/indicatif/ (`struct.ProgressDrawTarget`, `struct.ProgressBar`, `struct.MultiProgress`, `style/struct.ProgressStyle`, `src/indicatif/draw_target.rs.html`, `src/indicatif/style.rs.html`) ; https://docs.rs/console/0.16.6/console/ (`struct.Term`, `struct.Style`, `fn.truncate_str`, `fn.measure_text_width`, `src/console/utils.rs.html`, `term.rs.html`, `unix_term.rs.html`) ; https://docs.rs/owo-colors/4.4.0/ (`trait.OwoColorize`, `docs.rs/crate/owo-colors/4.4.0/features`) ; https://docs.rs/supports-color/3.0.2/src/supports_color/lib.rs.html ; https://docs.rs/supports-unicode/3.0.0/src/supports_unicode/lib.rs.html ; https://docs.rs/anstream/1.0.0/ (`src/anstream/auto.rs.html`) ; https://docs.rs/anstyle-query/1.1.5/src/anstyle_query/lib.rs.html ; https://docs.rs/anstyle/1.0.14/anstyle/struct.Style.html ; https://docs.rs/crossterm/0.29.0/ (`style`, `terminal`, `cursor`, `tty/trait.IsTty`, `terminal/enum.ClearType`, `macro.queue`, `src/crossterm/style/types/colored.rs.html`, `src/crossterm/terminal/sys/unix.rs.html`, `src/crossterm/style.rs.html`, `docs.rs/crate/crossterm/0.29.0/features`) ; https://docs.rs/yansi/1.0.1/yansi/struct.Condition.html ; https://docs.rs/nu-ansi-term/0.50.3/ ; https://docs.rs/tracing-appender/0.2.5/ (`rolling/struct.Builder`, `non_blocking/struct.NonBlockingBuilder`) ; https://docs.rs/tracing-indicatif/0.3.14/ ; https://docs.rs/comfy-table/8.0.1/ (`struct.Table`, `presets`, `enum.ContentArrangement`) ; https://docs.rs/miette/7.6.0/miette/struct.MietteHandlerOpts.html and `docs.rs/crate/miette/7.6.0/features` ; https://docs.rs/color-eyre/0.6.5/ ; https://docs.rs/terminal_size/0.4.4/ ; https://docs.rs/pager/0.16.1/ ; https://docs.rs/minus/5.8.0/ ; https://docs.rs/dirs/5.0.1/dirs/fn.state_dir.html ; https://docs.rs/tokio/latest/tokio/signal/unix/struct.SignalKind.html
- [S37] https://no-color.org/ ; http://bixense.com/clicolors/
- [S38] http://specifications.freedesktop.org/basedir/latest/ ; https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/MacOSXDirectories/MacOSXDirectories.html ; https://docs.brew.sh/Manpage
- [S39] https://docs.brew.sh/Formula-Cookbook ; https://raw.githubusercontent.com/Homebrew/homebrew-core/master/Formula/g/gh.rb, `.../u/uv.rb`, `.../r/ripgrep.rb`
- [S40] https://man.freebsd.org/cgi/man.cgi?query=sysexits&sektion=3 ; https://rustc-dev-guide.rust-lang.org/diagnostics.html
- [S41] https://raw.githubusercontent.com/FiloSottile/mkcert/master/main.go (the "created a new local CA" strings live in another file and were not read)
- [S42] https://github.com/YoanWai/agent-manager/issues/627 ; web search results citing `donnex/markcheck#171`, `TragicWarrior/libvtty#217`, a BRLTTY mailing-list post, Terminus font home page, a Hacker News comment (Linux console 512 glyphs) ; https://raw.githubusercontent.com/sindresorhus/is-unicode-supported/main/index.js ; https://raw.githubusercontent.com/sindresorhus/cli-spinners/main/spinners.json ; https://raw.githubusercontent.com/sindresorhus/log-symbols/main/symbols.js
- [S43] https://raw.githubusercontent.com/git/git/master/Documentation/config/core.adoc ; https://git-scm.com/docs/git ; https://docs.github.com/en/actions/reference/workflows-and-actions/variables ; https://docs.gitlab.com/ci/variables/predefined_variables/
- [S45] https://docs.rs/unicode-width/0.2.3/unicode_width/trait.UnicodeWidthStr.html ; https://docs.rs/unicode-truncate/2.0.1/unicode_truncate/trait.UnicodeTruncateStr.html
