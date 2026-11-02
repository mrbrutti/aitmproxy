# One-shot verbs on a running core (R14) design

**Status:** approved 2026-11-01 (session lead, under Matt's autonomous-approve mode; decisions (a)–(h) and the product rule are Matt's and the orchestrator's; Architect's calls 1–13 stand)
**Research inputs:** `docs/research/25-one-shot-verbs-on-a-running-core.md` (F1–F27, §4 directions, §5 items 1–11), `docs/research/24-cli-terminal-reporting.md` (R11, R14), the approved wave-1 spec `docs/superpowers/specs/2026-11-01-cli-terminal-reporting-design.md` (design system T1–T7, mock-ups M1–M7, D4/D6/D10/D13/D14, Non-goals, Open question 1), `docs/superpowers/specs/2026-10-31-per-host-decryption-design.md` (the draft release note at lines 382–388), memories `aitmproxy-mac-live-proof-recipe`, `aitmproxy-operator-first-run-hygiene`, `aitmproxy-per-host-decryption-decision`.
**Prior specs touched:** the wave-1 spec (its R14 Non-goals bullet and Open question 1 now point here; this spec re-pins AC-W1-6, AC-W1-30 and AC-W3-7 as stated in §D14), `2026-10-29-operator-token-ux-design.md` (the `operator-token generate` command, its surgical editor and its confirmation line stay; the token is now also minted automatically on a serving first run, §D3).
**Decisions already taken (Matt and the orchestrator, 2026-11-01), treated as given:** (a) discovery through a per-core pointer file written by the loopback transport, precedence `--bus`/`AITM_BUS` → config → pointer dir, refusal on two live cores; (b) a core that serves no bus is unreachable and says so, the ready card's Scope next step must be true; (c) the four `Frontend::Cli`-only gates are refused remotely with their own sentence, widening them is a follow-up for Matt; (d) the refusal is a W1 `ErrorReport`, `Failure`, exit 1, stdout empty, every variant with exact text; (e) verbs are live by default with a named local set enforced by a registry-walking test; (f) the remote result is rendered through the same renderer as the local one; (g) connect and per-call deadlines, long verbs get a longer budget behind a spinner; (h) **yes** — every surface serves a loopback operator bus by default; and the confirmation that a one-shot with no reachable core **refuses** in this PR (auto-start is the next PR, §D15).

## Intent

A one-shot `aitm <group> <verb>` today builds its own throwaway proxy, acts on it and exits: `aitm scope add --host example.test` prints `example.test` and changes nothing the operator can see (research F15, F16, F21; the wave-1 spec's M5 "this one-shot proxy only" clause). The ready card of wave 1 tells a new operator to run exactly that command. This spec makes the command true. Every surface — bare `aitm`, `aitm web`, `aitm tui`, the macOS app's embedded core — launches with a running core whose operator bus is reachable on loopback, publishes a pointer to it, and a one-shot verb becomes a client of that core: it finds the core, connects with the operator token, runs the verb there and renders the core's answer exactly as it rendered its own. When no core is reachable it refuses with a panel that says what it looked for, that nothing was changed, and the one true fix.

## The product rule (Matt, 2026-11-01)

Matt, verbatim: *"it is a basic expectation of the app to launch with the core running otherwise how they will work"* and *"we can always have it pass a different core location, if we ever support remote cores, but for now they should by default start one"*. As a rule:

1. Every surface launches **with** a running core whose operator bus is reachable on loopback, by default, with no flag: bare `aitm`, `aitm web` and `aitm tui` start one in-process (as they already do) and add the operator bus; the macOS app spawns one (as it already does, over a loopback bus with an operator token).
2. One-shot verbs are **clients** of that core, never substitutes for it. A one-shot that finds no reachable core states that in its own words and offers the start; there is no silent in-process fallback for a verb that acts on core state.
3. The default of every surface is to **start** a local core and attach to it. `--bus`/`AITM_BUS` (today's `aitm-tui --bus` semantics, kept) and any future remote-core option are the explicit way to point a surface at a **different** core; they are the override, never the default. No surface waits for or requires a pre-existing core.
4. A core that serves no operator bus is the explicit opt-out, `mcp.operator_bus.enabled: false` (§D2), never the default.

## Goals

- G1. `aitm scope add --host <host>` run from a second shell against a default bare `aitm`, `aitm web`, `aitm tui` or the mac app's embedded core adds the host to **that** core's Scope; `aitm scope list`, the TUI, the web UI and `tools/call scope.list` over the bus all show it (AC-R14-13/14).
- G2. Every serving core publishes a `0600` pointer file under the per-user run directory while it runs, naming its operator bus address and the config file that holds the operator token, never the token (AC-R14-10).
- G3. Every entry point serves a loopback operator bus by default on an ephemeral port, with the operator token minted into the `0600` config on a serving first run; the MCP agent transport (stdio by default), the agent policy and the agent token are unchanged (AC-R14-1…9).
- G4. A one-shot with no reachable core never prints success: it refuses with a W1 panel whose headline names what it tried, whose body ends in `Nothing was changed.`, and whose fix command is true (AC-R14-15…21).
- G5. The verb rule is written down and enforced: live by default, a named local set, a test that fails on a verb nobody classified (AC-R14-22).
- G6. The remote result renders byte-identically to the local one for the same value, on stdout; human lines stay on stderr through `aitm-term` (AC-R14-24).
- G7. The W1 ready card tells the truth about the bus: an `Operator bus` row, and the Scope next step only when a one-shot can reach the card's own core (AC-R14-1/5/6).
- G8. The shipped sentences that say a one-shot cannot reach a running core are rewritten, and the release note records the posture change (AC-R14-30, §D13).

## Non-goals

- Auto-starting a detached core from a one-shot that finds none (§D15, the next PR with the `aitm core start|stop|status` lifecycle in wave 3's command surface).
- Widening the four `Frontend::Cli`-only gates (`tls passthrough add|remove`, `map add|remove`, `session save|load` and `flow export|import` with a path, `script validate --path`) to the operator role (research F14, §4.2 option ii): a follow-up for Matt; this PR refuses them remotely with their own sentence (§D9 R9).
- Remote cores off loopback, TLS on the bus (core follow-up F15), `--allow-remote-bus` for one-shots.
- Standalone `aitm-tui` discovering a core without `--bus` (follow-up; its token read needs a YAML parse the TUI crate does not have). `aitm-tui --bus` keeps its override semantics.
- The mac app reading the pointer file instead of its newest-directory rule (research §5 item 11): a Swift change for the mac lane, listed in the follow-ups; the pointer's content is a contract the app can rely on (§D4).
- Wave 3's human renderers and `--json`; this spec only guarantees that both paths feed the same renderer with the same `Value`.
- Skipping the local host boot for a remote verb (research F24c, R11): the one-shot still assembles its registry as today until wave 2's schema-only registry lands (§D8, follow-up).
- Windows.

## Anti-goals

- Printing success for a no-op: a verb that acts on core state never runs against a throwaway proxy, in any mode, under any fallback.
- A token in the pointer file, in any panel, phase line, warning, log file or `Debug` output; a token read from a file that is not a regular file owned by the current user.
- A fix command that is not true for the operator's situation (`aitm` as the fix when the core it starts would be unreachable; `use the TUI` for a verb the TUI is refused too).
- Guessing between cores: "newest wins" (memory `aitmproxy-mac-live-proof-recipe`), or dialing the first pointer found when two are live.
- Sending the operator token to a dead pointer's port before checking the process is alive.
- A second vocabulary: `core`, `bus`, `operator bus`, `Scope`, never `daemon`, `server`, `backend` (mac glossary §5 Words).
- Breaking a consumer: the python e2e harness, `cli-startup.sh`, `term-reporting.sh`, the mac app's external lane, the Homebrew pins (§D12).

## Constraints

- **Frozen files.** `crates/aitm/src/wire.rs` (until PR #267 merges; the brief names it as `aitm-core/src/wire.rs`, the file lives in `crates/aitm/src/`): no edit, no new variant. `crates/aitm/src/main.rs` (another session, p1b, edits it): additive, small, the LAST task, every hook listed with its line range (§Claims). `crates/aitm/src/tui.rs` and `tui::services` (PR #232): **not touched**; the operator bus for `aitm tui` starts from `main.rs` before `tui::run`.
- **Wave-2 lane.** The approved wave-2 (help) plan claims `crates/aitm-cli/src/{lib,dispatch,confirm}.rs`, `crates/aitm-cli/tests/cli.rs`, `crates/aitm-cli/Cargo.toml`, `crates/aitm-term/src/{lib,caps,error,help,prompt}.rs`, `crates/aitm/src/startup/{mod,args,errors}.rs`, two `pub mod` lines in `crates/aitm/src/lib.rs`, the help parse in `main.rs`, `tui.rs` `USAGE`, `web/mod.rs` `USAGE`/`parse_args`. This spec's code lives in NEW modules (`crates/aitm/src/oneshot/`, `crates/aitm/src/operator_bus.rs`, `crates/aitm-mcp/src/pointer.rs`); it touches `crates/aitm-cli/src/dispatch.rs` on exactly one line (`fn parse_flags` → `pub fn parse_flags`), adds two `pub mod` lines to `crates/aitm/src/lib.rs`, and never edits `startup/{mod,args,errors}.rs`; under `aitm-term` only the visibility of `text::sanitize` (plus one doc sentence) changes, per the Claims list (2026-11-01).
- **Zero new crates.** `aitm` already depends on `aitm-bus-client`, `aitm-mcp`, `aitm-cli`, `aitm-term`, `tokio` (`time`), `libc`, `serde_json`, `serde_yaml`, `uuid`; `aitm-mcp` on `aitm-core`, `tokio`, `serde_json`, `uuid`; `aitm-core` on `dirs`. New edges: none. `Cargo.lock` unchanged.
- **Security.** `unsafe_code = "forbid"` holds. The operator token is read from a regular file owned by the run directory's owner (the trust anchor, §D10; the operator's own uid in every configuration the operator did not deliberately redirect) only; a group- or world-readable token-bearing config draws one warning line, never a refusal (§D7 rule 6, research Q5). The pointer file carries no token. Operator access is loopback-only: the operator bus binds `127.0.0.1`, a `--bus` off loopback is a usage error. A pointer whose writer no longer holds its advisory lock is never dialed (research Q6); liveness is the lock (`std::fs::File::try_lock` / `try_lock_shared`, safe `std`, released by the kernel on any exit including SIGKILL), never a pid probe, because the workspace forbids `unsafe` and a one-shot spawns no process (W1 amendment A). The token-bearing config is written atomically with mode `0600` (closes research F7), fsynced before the rename (security S4, 2026-11-01). No token reaches a sink, line, file or `Debug` impl (W1 AC-W1-22 extended, AC-R14-28/31).
- **Brand and words.** Wave-1 design system T1–T7 verbatim: glyphs `✕ ▸ · !`, lowercase headlines we compose, core sentences verbatim, dotted names never in prose we compose, 14-column labels, `~` in cards and phases, full paths in panels.
- **Proof.** Live, never fixtures: the real `target/release/aitm` against a real running core in a real terminal from the Terminal panel (the coder sandbox cannot bind or connect loopback, so coders prove the client and protocol pieces with in-process duplex tests over `aitm_bus_client::InProcessTransport` and the pure functions, and the socket suites run from the Terminal). Nothing in the recipe installs a CA, touches the system proxy, or reads a token-bearing file with `cat`.
- **Performance.** `aitm scope list` against a running core completes within 2× the wall time of `aitm ca status` (the local path with the same boot); the operator bus adds no phase line a serving core did not already print except `operator token written` on the first run; a one-shot still prints nothing on stderr on success.

## Design

### D1. Words

- **core**: a running aitmproxy process that holds the flow store, guard, scripts and policy (bare `aitm`, `aitm web`, `aitm tui`, the mac app's embedded `aitm`).
- **agent transport**: `mcp.transport` (stdio by default; loopback TCP; streamable HTTP). Unchanged by this spec.
- **operator bus**: the loopback-TCP listener that accepts the operator token and classifies the connection `Frontend::Operator`. It is the agent transport itself when that is loopback TCP (as the mac app and INSTALL.md's external core do today), otherwise a dedicated operator-only listener (§D2).
- **pointer**: the `run/cores/<pid>.json` file a core writes while its operator bus is bound (§D4).
- **one-shot**: `aitm <group> <verb> [--flag <value>]…`, `Mode::Cli`.
- **local verb / live verb**: §D6.
- **resolve**: how a one-shot finds the core and the token (§D7).

### D2. The operator bus

**Config** (`aitm_core::McpConfig`, `crates/aitm-core/src/config.rs`; YAML in `crates/aitm/src/config_file.rs`):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorBusConfig {
    /// Serve a loopback operator bus and mint the operator token on first run. Default `true`.
    pub enabled: bool,
    /// The port of the dedicated operator listener; `0` (the default) is ephemeral.
    /// Ignored when `mcp.transport` is loopback TCP (that bus carries operator access).
    pub port: u16,
}
impl Default for OperatorBusConfig { /* enabled: true, port: 0 */ }
pub struct McpConfig { /* …existing fields…, */ pub operator_bus: OperatorBusConfig }
```

```yaml
mcp:
  operator_bus:          # optional; shown with its defaults
    enabled: true        # false = the explicit opt-out: no operator bus, no minting
    port: 0              # 0 = ephemeral
```

`McpConfig::default()` keeps `transport: Stdio`, `policy: Auto`, `stdio_role: Mcp`, `agent_token: None`, `operator_token: None` (AC-R14-7 pins all five). The doc comment on `operator_token` flips from "Off by default: without it, every loopback connection is an agent" to "Minted into the config on a serving first run (§D3); `None` only before that run, or when `operator_bus.enabled` is false and `operator-token generate` was never run". **This is the posture change** the release note records (§D13): operator access is on by default for a same-user local process that can read the `0600` config. The one place in the tree that builds `McpConfig` with a struct literal (`crates/aitm-plugins/tests/control.rs:267`) gains the field.

**Mode rule** (pure function `operator_bus::plan(&McpConfig) -> Plan`, `crates/aitm/src/operator_bus.rs`):

| `mcp.transport` | `operator_bus.enabled` | `operator_token` after §D3 | Plan |
|---|---|---|---|
| loopback TCP | any | non-empty | `Shared`: the agent transport accepts the operator token (`with_operator_token`, as today); no second listener; `operator_bus.port` ignored (one `debug!`) |
| loopback TCP | any | none (mint failed or opted out) | `Off("no mcp.operator_token")` |
| stdio or streamable HTTP | true | non-empty | `Dedicated(port)`: an operator-only loopback listener on `127.0.0.1:<port>` |
| stdio or streamable HTTP | true | none (mint failed) | `Off("could not write mcp.operator_token to <path>")` |
| stdio or streamable HTTP | false | any | `Off("mcp.operator_bus.enabled: false")` |

**Transport pieces** (`crates/aitm-mcp/src/transport.rs`, additive): `LoopbackTcp.agent_token` becomes `Option<Arc<str>>`; `LoopbackTcp::bind_operator_only(port: u16, operator_token: String) -> anyhow::Result<Self>` binds `(Ipv4Addr::LOCALHOST, port)` with no agent token and a non-empty operator token (empty → error); `classify_token(line, agent: Option<&str>, operator: Option<&str>)` returns `Operator` for the operator token, `Mcp` for the agent token when one exists, else `None` (constant-time compares kept). `McpServer::serve_on(self, listener: LoopbackTcp) -> anyhow::Result<()>` (`crates/aitm-mcp/src/server.rs`) serves an already-bound listener; `serve`'s loopback arm becomes `self.serve_on(LoopbackTcp::bind(..).await?.with_operator_token(..))` so nothing else changes. `serve_on` publishes the pointer file once the listener serves, when a context is published (§D4, with `operator` = whether the listener accepts an operator token); `Drop for LoopbackTcp` removes it beside the endpoint file.

**Start** (`operator_bus::start(cfg, &services, &agent_state, &audit_ring, push_tx, on_bound) -> anyhow::Result<OperatorBus>`, called once from `run()` right after `tui::services(..)` is built, before the ready card, in every serving mode — bare `aitm`, `aitm web` and `aitm tui`; the one-shot never calls it):

- `Shared` → returns `OperatorBus { word: OperatorBusWord::Shared, task: None }` (the agent transport binds inside `mcp.serve()` as today).
- `Dedicated(port)` → `LoopbackTcp::bind_operator_only(port, token).await` **now** (so a fixed-port conflict is the M2 panel: `StartupError::PortInUse { role: "the operator bus", addr, remedy }` with the remedy `Free it, or set mcp.operator_bus.port to another port in <config>.`), calls `on_bound(addr)` (the L4 self-port hook, L4PAR-AC34), builds the server as `tui::with_shared_governance(tui::server(cfg, McpTransport::Stdio /* a label only, as the TUI's in-process server does */, &services), &agent_state, &audit_ring).with_mcp_roles(cfg.mcp.operator_token.clone(), cfg.mcp.stdio_role).with_push(push_tx)` and spawns `server.serve_on(listener)` as a tokio task held in `OperatorBus { word: Dedicated(addr), task: Some(JoinHandle) }`. Dropping `OperatorBus` aborts the task, which drops the listener, which removes the pointer: Ctrl-C, SIGTERM, the stdin-EOF exit and the TUI's `q` all end `run()` and so the bus.
- `Off(reason)` → `OperatorBus { word: Off(reason), task: None }`; the mint-failure reason was already warned by §D3.

Table footnote (2026-11-01, Task 6): a stdio/HTTP transport with `operator_bus.enabled` and no token but no mint-failure reason to quote (the mint never ran, e.g. a caller that skipped it) is `Off("no mcp.operator_token")`, the loopback row's word.

Hardening (security S1, 2026-11-01): a connection that sends no token line within `TOKEN_LINE_TIMEOUT` (10 s; `LoopbackTcp::with_token_line_timeout` for tests) is closed with one content-free `debug!`; an `accept()` error is logged and the loop continues after a 100 ms pause on EVERY accept error (so a persistent `EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM` can never spin the listener; S7, 2026-11-01) instead of ending the listener; `OperatorBus::finished()` lets `run()` observe a died dedicated bus (it pends forever for `Shared`/`Off`), so Task 13 adds it as one `select!` arm.

**Why not a new `McpTransport` variant:** every `match` on the enum across six crates would change, `wire.rs` is frozen, and the operator bus is not a transport the operator configures but a property every core has.

### D3. The operator token is minted on a serving first run

`operator_token::mint_if_absent(path: &Path, create_if_missing: bool) -> anyhow::Result<Minted>` (`crates/aitm/src/operator_token.rs`):

```rust
pub struct OperatorToken(String);           // Debug prints `OperatorToken(<redacted>)`; no Display
pub enum Minted { Present, Written { path: PathBuf, token: OperatorToken }, Skipped { reason: String } }
```

- Called from `run()` after `reading config` and the env bridge, before `loading detections`, **in serving modes only**; `Mode::Cli` never mints (a one-shot never writes the operator's config).
- `path` is the effective config path (`--config` → `AITM_CONFIG` → default). `create_if_missing` is true only when no explicit path was given (so a mistyped `--config` is still the `in config file …` error, never a new file).
- `Present` when the file has a non-empty `mcp.operator_token`. `Written` when a token was inserted with `insert_operator_token` (the surgical editor: every other byte, comment and line ending kept; an absent `mcp:` block appended; an absent file created as `mcp:\n  operator_token: <64 hex>\n`), the parent directory created `0700` if absent, the file written through `write_atomically`, which now creates its temp file with mode `0600` so the renamed result is `0600` whatever the umask and whatever the old mode was (research F7; also fixes `operator-token generate`), and `sync_all`s the temp file before the rename, with a best-effort directory fsync behind a `debug!` (security S4, 2026-11-01). `Skipped` on `InlineMcpSection`, an unwritable or unreadable file or directory, a non-regular file at the path, or a **symlink** at the path (checked first with `symlink_metadata`; reason `<path> is a symlink: aitm does not write a token through it; add mcp.operator_token yourself or set mcp.operator_bus.enabled: false` — an automatic first-run write must neither replace a dotfile manager's link with a regular file nor write a secret through it into a tracked repo; reading a token still follows symlinks, §D7 rule 6): never fatal. Signature `mint_if_absent(path, create_if_missing) -> Minted` (every failure is a `Skipped`).
- On `Written`, `run()` sets `cfg.mcp.operator_token = Some(token.0)` and the checklist prints one phase, `creating operator token` → done `operator token written · <config path>` (`~`-shortened on a TTY, plain `operator token written · /full/path` piped). On `Present`, no phase (serving-mode checklists print every phase they open, plan C4, so the phase is opened only when writing). On `Skipped`, one warning `! operator access off: could not write mcp.operator_token to <path> · <reason>` (plain: `warning: operator access off: …`) and the operator bus is `Off(..)`.
- The token value never appears in any phase line, warning, log record or `Debug` output (AC-R14-28/31). `aitm operator-token generate [--force]` is unchanged: it still refuses without a config file and still rotates with `--force` (the confirmation line still says to restart).

**First-run checklist** (bare `aitm`, fresh `HOME`, TTY), the two new lines in context:

```text
›•‹ aitmproxy 0.5.11

  ✓ config defaults · ~/Library/Application Support/aitmproxy/config.yaml not found
  ✓ operator token written · ~/Library/Application Support/aitmproxy/config.yaml
  ✓ 49 detections ready
  ✓ CA created · ~/Library/Application Support/aitmproxy/ca/ca.crt
  ✓ obscura probed 0.3.1
  ✓ proxy listening 127.0.0.1:8080 · browser proxy 127.0.0.1:8081
```

The `config defaults … not found` line stays truthful (the file did not exist when it was read); the next line says what was then created. W1's `^config ` pin still matches.

### D4. The pointer file (a contract)

- **Directory:** `<aitm dir>/run/cores/`, where `<aitm dir>` is derived exactly as the W1 log directory is, `aitm_core::CaConfig::default().audit_log.with_file_name("run").join("cores")`: `~/Library/Application Support/aitmproxy/run/cores/` on macOS, `$XDG_CONFIG_HOME/aitmproxy/run/cores/` (default `~/.config/aitmproxy/run/cores/`) on Linux. Created `0700` (both `run` and `cores`) when the core creates them; a `run/cores` that already exists (an `AITM_RUN_DIR` the operator chose, or a data dir they set up) keeps its mode, with one `debug!` when wider than `0700` (security S3, 2026-11-01). Override for both writer and reader: `AITM_RUN_DIR=<dir>` (non-empty), for test harnesses that must not touch the operator's directory.
- **Name:** `<pid>.json`, the writing process's pid in decimal.
- **Content:** one JSON object, one line, trailing newline, `serde_json` compact:

  ```json
  {"v":1,"pid":4821,"bus":"127.0.0.1:50512","operator":true,"config":"/Users/matt/Library/Application Support/aitmproxy/config.yaml","started_unix":1761998645,"version":"0.5.11"}
  ```

  | Field | Type | Meaning | Stability |
  |---|---|---|---|
  | `v` | integer | schema version, `1` | bumped only on an incompatible change; a reader rejects a `v` it does not know |
  | `pid` | integer | the core's pid | never reused for another meaning |
  | `bus` | string | the operator bus address as `SocketAddr` displays it; always loopback | a reader must refuse to dial a non-loopback value |
  | `operator` | boolean | whether this bus accepts an operator token (`false` for an agent-only loopback transport) | |
  | `config` | string | absolute path of the config file the core read; the file that holds `mcp.operator_token` when `operator` is true | the only token locator; never the token |
  | `started_unix` | integer | epoch seconds when the bus bound | informational (relative age in panels) |
  | `version` | string | `CARGO_PKG_VERSION` of the writer | informational |

  Unknown fields are ignored by readers (additive growth); fields never change type or meaning within `v: 1`. The file is complete whenever it exists: written to `<pid>.json.tmp` with mode `0600` and renamed over `<pid>.json` (same directory, atomic). **No token, no secret, no URL with a token, ever.**
- **Lifecycle:** written by `McpServer::serve_on` when the listener starts serving, **when** a process context has been published. The writer takes an exclusive advisory lock (`std::fs::File::try_lock`) on the temp file **before** the rename, so the final inode is locked from the first instant it is visible, and keeps the locked handle inside `LoopbackTcp` for the listener's lifetime. Removed in `Drop for LoopbackTcp` on every orderly end (clean exit, error, SIGINT/SIGTERM through `shutdown_signal`, the stdin-EOF exit, the TUI's quit). Not removed on SIGKILL or a crash: **stale**.
- **Context:** `aitm_mcp::pointer::publish(PointerContext { config: PathBuf })` is a write-once `OnceLock`, set by `main.rs` in `run()` for the serving modes only, right after the effective config path is known (the same precedent as W1's `current_log_path()`). `LoopbackTcp` reads it when `serve_on` starts serving (the pointer is published then, a few milliseconds after the bind; aligned 2026-11-01 with the lifecycle bullet). **Consequences:** the mac app's embedded core (`aitm --config <tmp>/config.yaml`) publishes a pointer naming that per-launch config with zero Swift changes; the python e2e harness and `live-env.mjs`, which spawn the real binary, publish pointers too (removed on their SIGTERM; set `AITM_RUN_DIR` to isolate); every in-process `McpServer` built by an integration test publishes nothing (no context), so `cargo test` never writes into the developer's data directory (AC-R14-12); a one-shot never publishes (it never binds).
- **Staleness:** a reader treats a pointer as live only if its writer still holds the lock: `File::try_lock_shared` on the pointer fails with `WouldBlock` → alive; succeeds → the writer is gone (the kernel released the lock when the process ended, SIGKILL and crashes included) → the reader unlocks and **deletes** the file (same uid; one `debug!`) and never dials it, so the operator token is never written to a port a dead core's address may have been recycled to (research F18/Q6). Any other lock error is `Unknown` and treated as alive. A pointer whose writer holds the lock but whose address refuses the connection is refused with its own panel (§D9 R4) and **kept** (the core may be starting or shutting down; the panel says to delete the file if it has exited). `pid` and `started_unix` are informational, for the panels.
- **Trust:** a reader ignores (never dials, never deletes) a pointer that is not a regular file, is not owned by the run directory's owner (§D10), is wider than `0600`, fails to parse, has an unknown `v`, or names a non-loopback `bus`.
- **Follow-up (mac lane, research §5 item 11):** the app's `EmbeddedCore` today polls its per-launch `bus.endpoint` and its self-test picked a stale core from the newest `aitm-embedded-core/<UUID>/` directory; reading `run/cores/*.json` and testing liveness by the pointer's advisory lock (or by connect) would close that trap. This spec fixes the content above so that Swift change needs no core change.

### D5. The ready card

`startup::card::ReadyInputs` gains `operator_bus: OperatorBusWord` (`pub enum OperatorBusWord { Shared, Dedicated(SocketAddr), Off(String) }`, defined in `startup/card.rs`; `operator_bus.rs` returns it). Rows (`crates/aitm/src/startup/card.rs`; the renderer in `aitm-term` is untouched):

| `operator_bus` | `Bus` row (Server card; the Web card's value stays `ready`) | `Operator bus` row (new, directly after `Bus`) |
|---|---|---|
| `Shared` | `loopback 127.0.0.1:9090 · operator` / `loopback 127.0.0.1 (ephemeral port) · operator` (Web: `ready · operator`) | omitted |
| `Dedicated(a)` | `stdio (MCP)` / `http <addr>` as today (Web: `ready`) | `127.0.0.1:50512` (plain role) |
| `Off(reason)` | as today | `off · <reason>` (warning role), e.g. `off · mcp.operator_bus.enabled: false`, `off · no mcp.operator_token`, `off · could not write mcp.operator_token to /path` |

The label `Operator bus` is 12 characters, within T3's 14-column label. Piped: `Operator bus: 127.0.0.1:50512`, `Bus: loopback 127.0.0.1:9090 · operator`, `Operator bus: off · mcp.operator_bus.enabled: false`.

**Scope next step** (`scope_row(n, reachable: bool)`): the `▸ aitm scope add --host <host>` line appears when Scope is empty **and** `operator_bus` is `Shared` or `Dedicated` (a one-shot can reach this core as an operator); with `Off(..)` the row is `Nothing is decrypted until a host is in Scope.` with no next step, and the `Operator bus  off · …` row carries the reason. Scope non-empty: `n hosts in Scope`, no next step, as W1. This re-pins AC-W1-6 (decision (b); the unconditional clause is superseded, see §D14).

`aitm web`: the `Operator` URL row (M6) appears when `mcp.operator_token` is non-empty, which after §D3 is every run unless opted out; its shape is unchanged (D13 `live-env.mjs` pins hold).

**Bare `aitm`, default config, after first run (TTY):**

```text
● aitmproxy · listening 127.0.0.1:8080 · CA untrusted
  Bus           stdio (MCP)
  Operator bus  127.0.0.1:50512
  Scope         Nothing is decrypted until a host is in Scope.
                ▸ aitm scope add --host <host>
  CA            untrusted
                ▸ aitm ca install
  System proxy  off
                ▸ aitm proxy system set
  Log           ~/Library/Application Support/aitmproxy/logs/aitm.log
```

Piped: `Bus: stdio (MCP)` / `Operator bus: 127.0.0.1:50512` / `Scope: Nothing is decrypted until a host is in Scope. · aitm scope add --host <host>` / … as M1p.

### D6. The verb rule

**Rule.** A verb is **local** only when its whole effect is on this machine's disk or OS and it reads nothing from a core: the CA files and trust store, the findings and PoC directories, a report rendered from the findings directory, a static script compile, undoing the OS proxy setting. Everything that reads or writes a store, guard, client, browser, script host, policy, capture feeder, or the core's own configuration is **live**, even where a one-shot copy could run it to some effect (research F16; `poc run` and `findings record` are live because they use the core's client, guard and store, and a PoC or finding that names a flow id names the core's flow — **Architect's call**, the alternative "local" is one word in the table). Unknown verbs and script verbs are live (decision (e)).

**Table** (`crates/aitm/src/oneshot/verbs.rs`: `pub const LOCAL_VERBS: &[&str]`, `pub const LONG_RUNNING_VERBS: &[&str]`, `pub fn placement(dotted: &str) -> Placement { Local | Live }`, `pub fn budget(dotted: &str, known_locally: bool) -> Duration`):

| Placement | Verbs |
|---|---|
| **Local** | `ca.status`, `ca.export`, `ca.install`, `ca.uninstall`, `findings.list`, `findings.get`, `findings.remove`, `poc.list`, `poc.get`, `poc.artifact`, `scan.report`, `script.validate`, `proxy.system.unset` |
| **Live** (everything else) | `agent.*`, `browser.*`, `capture.status`, `check.*` (script), `config.get`, `findings.record`, `flow.*`, `l4.*`, `map.*`, `poc.build`, `poc.run`, `proxy.status`, `proxy.pause`, `proxy.resume`, `proxy.system.status`, `proxy.system.set`, `request.send`, `scan.discover`, `scan.passive`, `scope.*`, `script.list`, `script.findings`, `script.enable`, `script.disable`, `script.reload`, `script.save`, `session.*`, `tls.*`, `ws.*`, and every verb the local registry does not know |

`config get` and `proxy system status` are live (research §4.3's `?` rows): they describe a running core's configuration and the OS proxy relative to **its** listen address; a no-core refusal names the config file the operator can read. `proxy system unset` stays local (documented "works one-shot", `plugin.rs:189`): with no core it is the recovery for a dead proxy left as the OS proxy. **Architect's calls.**

**Long-running** (budget 10 min, §D8): `poc.run`, `scan.discover`, `scan.passive`, `request.send`, `flow.replay`, `browser.navigate`, `browser.click`, `browser.type`, `browser.eval`, `browser.screenshot`, `browser.get_dom`, `l4.recon`, `l4.tcp_probe`, `l4.udp_probe`, `l4.send_recv`, `l4.inject`, `l4.intercept.*`, every `check.*`, and every verb the local registry does not know. Everything else: 30 s.

**The test** (`crates/aitm/tests/oneshot_verbs.rs`, the `m4_sensitivity.rs` pattern over the full assembly): holds its own `EXPECTED: &[(&str, Placement)]` for every built-in verb (the 73 of the default registry, plus the native `l4.*` verbs with `l4.enabled`), asserts the registry's name set equals the table's (a verb added without a decision fails with `unclassified verb <name>: add it to EXPECTED and, if local, to LOCAL_VERBS`), asserts `placement(name)` matches for each, asserts every `LOCAL_VERBS` and `LONG_RUNNING_VERBS` entry (prefix entries like `check.*` aside) is a registered name and every `LONG_RUNNING_SCRIPT_VERBS` entry (`l4.recon`, `l4.tcp_probe`, `l4.udp_probe`: bundled scripts, research F13) is not, and asserts no registered command declares a param named `bus` or `token-file` (the one-shot's own flags, §D7).

### D7. How a one-shot resolves the core

**Flags and env** (`oneshot::args::split_bus_args(argv) -> Result<(BusArgs, Vec<String>), String>`, recognised anywhere a subcommand is not, exactly as `--config` is): `--bus <host:port>` / `--bus=<host:port>`, `--token-file <path>` / `--token-file=<path>`; env `AITM_BUS`, `AITM_BUS_TOKEN` (the TUI's names, decision (a); an empty value counts as unset, as `aitm-tui` treats it). Usage errors (exit 2, `ErrorKind::Usage`, command `aitm --help`): `--bus requires a host:port`, `--token-file requires a path`, `--bus 10.0.0.5:9090 is not a loopback address` (why: `The operator bus is loopback-only; a core elsewhere needs a local tunnel.`), `--bus needs --token-file <path> or AITM_BUS_TOKEN`, `--token-file needs --bus <host:port> or AITM_BUS`, `--bus <text>: <parse error>`. An inline `--token` is not a one-shot flag (it stays whatever the verb's registry says; **Architect's call**: a token in shell history is worse than the TUI's `ps` exposure). With a **local** verb, `--bus`/`--token-file` are ignored with one warning `! --bus ignored · ca status runs on this machine, not on a core`; `AITM_BUS` alone is ambient and ignored silently.

**Precedence** (`oneshot::resolve::resolve(&BusArgs, env, &Config, effective_path, &dyn PidAlive) -> Result<Target, Refusal>`):

1. **Explicit:** `--bus` or `AITM_BUS` → `Target::Explicit { addr, token }`; the token from `--token-file` (`aitm_bus_client::read_token_file`), else `AITM_BUS_TOKEN`. Nothing else is consulted.
2. **Config:** the loaded config's `mcp.transport` is loopback TCP → the address is the `endpoint_file`'s content when that file exists and parses as a loopback `SocketAddr` (`Target::Config { addr, from: EndpointFile(path) }`), else `127.0.0.1:<port>` when `port != 0` (`from: Port`); the token is the same config's `mcp.operator_token`, non-empty, else **R6** (no operator token). A stdio or HTTP transport, or `port: 0` without an endpoint file, gives no address: fall through.
3. **Pointer dir:** scan `run/cores/*.json` (§D4 trust rules; pointers whose lock is free are deleted). Prefer the live pointers whose `config` equals the effective config path (both canonicalized). Exactly one preferred → it; none preferred and exactly one live → it; none live → **R1** (or **R5** when the loaded config opts out); two or more candidates at the same preference → **R11**. The token is read from the pointer's `config` (rule 6); `operator: false` → **R6** without dialing.

4. **Pre-dial checks:** the address is loopback; for a pointer, its writer still holds the lock (checked before any byte is sent).
5. **Dial** (§D8): a refused connection is **R2** (config port), **R3** (endpoint file), **R4** (pointer whose writer holds the lock), or **R2'** (explicit); `-32001` is **R7**; `role != operator` is **R8**.
6. **Reading a token-bearing config** (`oneshot::resolve::read_operator_token(path) -> Result<Option<String>, TokenProblem>`): follow symlinks (dotfile managers), then the target must be a regular file owned by the run directory's owner (§D10), else **R15**; when its mode has any group or other bit, one warning `! <path> is readable by other users · chmod 600 <path>` and proceed (research Q5: refusing would strand every config `operator-token generate` left `0644` before this PR); parse with `config_file::load(Some(path))` and take `mcp.operator_token`.

### D8. The remote invocation path

**Crates.** `crates/aitm/src/oneshot/` owns the one-shot: `args.rs` (§D7 flags), `verbs.rs` (§D6), `resolve.rs` (§D7), `remote.rs` (this section), `refuse.rs` (§D9), `run.rs` (the entry `pub async fn run(inputs: Inputs) -> anyhow::Result<()>`), `mod.rs` (declarations only). `aitm-bus-client` is used unchanged (`TcpTransport`, `BusClient`, `BusError`, `read_token_file`); `aitm_mcp::json::{to_json, from_json}` carry values; `aitm_cli::dispatch::parse_flags` (made `pub`) parses typed flags; `render::render_cli_value` prints.

**The local host still boots** (research F15): `run()` reaches the `Mode::Cli` arm with the proxy assembled, exactly as today, so the registry, the `Confirmer`, and the local services exist. Wave 2's schema-only registry lets a later change skip the boot for live verbs; until then the one-shot pays today's cost on both paths (and `--version`/`--help` stay pre-boot).

**Sequence for `aitm scope add --host example.com`** (default config, a default bare `aitm` running):

1. `main`: `pre_boot` no; `parse_invocation` splits `--config`, `--script`, `--bus-endpoint-file`, `--bus`/`--token-file` (`Invocation.bus_args`); `Mode::Cli(["scope","add","--host","example.com"])`.
2. `run()`: `reading config` (defaults; the file now exists from the core's first run, with the token), env bridge, no minting (a one-shot), `loading detections`, `preparing CA`; `tui::services`; the `Mode::Cli` arm calls `oneshot::run(Inputs { argv, bus_args, cfg, effective_path, services, reporter, log_path })`.
3. **Prepare:** `scope add` → `scope.add` in the local registry; `--yes` removed; `parse_flags(["--host","example.com"], &schema, "scope.add")` → `Params { host: Str("example.com") }`. A verb the registry lacks → `Prepared::Unresolved { dotted, raw_flags }` (decided by the core, step 6) — rule (Task 10): a single word with no `.` can never be a verb and is today's `unknown command` usage error; a dotted name the local registry lacks is `Unresolved`. Usage errors here exit 2 exactly as today (AC-W1-13 holds: `aitm nonsense` → `unknown command`, `aitm flow list --bogus 1` → `unknown flag`).
4. **Classify:** `placement("scope.add") == Live`. (A local verb dispatches here through today's `Cli::dispatch` and returns.)
5. **Resolve:** config transport is stdio → pointer dir → one live pointer, `config` equals the default path → token read from it (rule 6). Pre-dial: loopback address, the pointer's lock is still held.
6. **Connect:** `TcpTransport::connect(addr, &token)` then `BusClient::initialize("aitm-cli", CARGO_PKG_VERSION)`, both under one **2 s** handshake budget (`tokio::time::timeout`); `ServerInfo.role` must be `Some("operator")` else **R8**; `-32001` → **R7**. For `Unresolved`, `tools_list()` (same budget) must contain the dotted name, else the W1 usage panel `unknown command \`<name>\`` (exit 2); its flags are parsed generically (`--k v` → JSON if `v` parses as JSON else a string; a bare `--k` → `true`; `--k=v` accepted) and validated by the core.
7. **Call:** `client.call("scope.add", to_json(&params))` under the verb's budget (30 s; 10 min for `LONG_RUNNING_VERBS` and unknown verbs). A `Phase` is opened for the call with label `scope add · core 127.0.0.1:50512` and done summary `scope add answered · core 127.0.0.1:50512`; in one-shot mode (`checklist(false)`) it draws only past 100 ms, so a fast call leaves stderr empty and a long `poc run` shows the spinner on a TTY (plan C4; `-v` appends ` · in <n> ms`, C24).
8. **Confirm handshake** (research F20): a result `{status:"needs_confirmation", prompt, confirm_token}` → without `--yes` the local `Confirmer` asks the **core's** `prompt` (`<prompt> [y/N] ` on stderr; off a TTY the existing refusal that points at `--yes`); yes or `--yes` → the identical call plus `_confirm: <token>` on the same connection; no → `aborted: scope add not run` (exit 1, today's wording with the space form).
9. **Errors:** `BusError::Tool(text)` → a `Failure` panel whose `what` is the core's text verbatim (T6), exit 1; when the text is one of the four Cli-only gate sentences (it contains `from an agent frontend`), the panel is **R9**. `BusError::Rpc{-32001}` → **R7**; other `Rpc` → `Failure` with the message; `Transport` during connect or the handshake → **R2/R2'/R3/R4** by `Source` (a listener that accepts and closes at once surfaces here, AC-R14-25), during the call → **R12**; the budget elapsing → **R10** (the handshake deadline covers connect + `initialize` + `tools/list` and its panel always says `2 s`).
10. **Render:** `from_json(&result, &schema.result)` rebuilds the `Value` (`Bytes` from base64, research F10); for `Unresolved` verbs `TypeDesc::Any`; `render_cli_value(&value)` → stdout; exit 0. For this verb: stdout `example.com\n`, stderr empty. Flags named `poc_path` or `path` of type `Str` on a live verb are made absolute against the one-shot's working directory before step 7, so a relative path means the operator's directory, not the core's (research F24a; **Architect's call**).

**Parity (decision (f)):** both paths end in `render_cli_value(&Value)`; for the same `Value` the stdout bytes are identical (AC-R14-24), and wave 3's `--json` prints `to_json(&value)` — the bus object — on both. **Audit (research F24b):** the core records the call as origin `operator`, `client_label` `aitm-cli` (not a reserved label), command `scope.add`; a local verb still writes no line.

### D9. The refusal panels

Shape: W1 `ErrorReport`, `ErrorKind::Failure`, exit 1, stdout empty, the body wrapped greedily by the W1 renderer at the terminal's width (the R1 block below shows width 100; the sentences, not the line breaks, are the contract), the `Log` footer when a log file was opened, every text sanitized by the renderer (W1 D4). `<config>` is the full config path (panels never shorten paths, T6); `<verb>` is the space form (`scope add`); every `why` whose outcome is known states `Nothing was changed.` at the end of its outcome sentence (R2 may follow it with the line that names a different running core). Edge (tester observation d, 2026-11-01): a loopback transport with `port: 0`, no endpoint file, `operator_bus.enabled: false` and no token yields **R1**, whose fix starts an `Off` core; the next one-shot then gets **R6** with the true fix — two panels explain a misconfiguration in order, accepted.

**R1 — nothing found to dial.** TTY:

```text
✕ no running core found
  Looked for a core started from /Users/matt/Library/Application Support/aitmproxy/config.yaml and
  for any core published under /Users/matt/Library/Application Support/aitmproxy/run/cores; none is
  running, so scope add has nothing to change. Nothing was changed.
  Start aitm, or use the app's Scope page.

  ▸ aitm

  Log           ~/Library/Application Support/aitmproxy/logs/aitm.log
```

Piped:

```text
error: no running core found
  Looked for a core started from /Users/matt/Library/Application Support/aitmproxy/config.yaml and for any core published under /Users/matt/Library/Application Support/aitmproxy/run/cores; none is running, so scope add has nothing to change. Nothing was changed.
  Start aitm, or use the app's Scope page.
  fix: aitm
  log: /Users/matt/Library/Application Support/aitmproxy/logs/aitm.log
```

The command is `aitm` (true since §D2: it starts a core with an operator bus), or `aitm --config <path>` when `--config`/`AITM_CONFIG` named one.

| Id | When | `what` | `why` | `fix` | `command` |
|---|---|---|---|---|---|
| **R2** | the config's `port` refuses | `no running core at 127.0.0.1:9090` | `<config> sets mcp.transport.loopback_tcp.port 9090, but nothing is listening there, so <verb> has nothing to change. Nothing was changed.` + when live pointers exist: `A different core is running at 127.0.0.1:50512 (pid 4821, started 12 min ago, config <path>); pass --bus 127.0.0.1:50512 to use it.` | `Start aitm with that config, or use the app's Scope page.` | `aitm --config <config>` (`aitm` for the default path) |
| **R2'** | `--bus`/`AITM_BUS` refuses | `no running core at <addr>` | `Nothing is listening at the address --bus named, so <verb> has nothing to change. Nothing was changed.` (`AITM_BUS named` for the env) | `Start aitm, or drop --bus to let aitm find the core.` | `aitm` |
| **R3** | the config's `endpoint_file` address refuses | `no running core at 127.0.0.1:60680` | `The endpoint file <path> names an address nothing is listening on; the core that wrote it has exited. Nothing was changed.` | `Start aitm, or use the app's Scope page.` | `aitm --config <config>` / `aitm` |
| **R4** | a pointer's writer holds the lock, its address refuses | `no running core at 127.0.0.1:50512` | `The core pointer <pointer path> names process 4821, which is running but not listening there, so <verb> has nothing to change. If that core has exited, delete the file. Nothing was changed.` | `Start aitm, or use the app's Scope page.` | `aitm` |
| **R5** | nothing found and the loaded config has `operator_bus.enabled: false` with a stdio or HTTP transport | `this config serves MCP over stdio and no operator bus, which a second client cannot reach` (`over HTTP` for that transport) | `<config> sets mcp.operator_bus.enabled: false, so a core started from it has no address a one-shot can dial. Nothing was changed.` | `Remove mcp.operator_bus.enabled: false from <config> (or set mcp.transport.loopback_tcp and mcp.operator_token) and restart aitm, or use the app's Scope page.` | none |
| **R6** | the resolved core has no operator token (config `operator_token` empty; pointer `operator: false`) | `the core at 127.0.0.1:9090 has no operator token` | `<config> sets no mcp.operator_token, so a one-shot could only connect as an agent, and an agent may not change Scope. Nothing was changed.` | `Generate one and restart the core.` | `aitm operator-token generate` when `<config>` exists, else none (the prose adds `Create <config> first.`) |
| **R7** | `-32001` | `the core at 127.0.0.1:9090 refused the operator token in <config>` (`in <token file>` / `in AITM_BUS_TOKEN` for the explicit case) | `The config changed after that core started; a rotated token only takes effect on restart. Nothing was changed.` (explicit: `It matched neither the agent nor the operator token of that core. Nothing was changed.`) | `Restart the core, or pass --config for the config it was started with.` (explicit: `Check the token, or drop --bus to let aitm find the core.`) | none |
| **R8** | `initialize.role` is not `operator` | `the core at 127.0.0.1:9090 would treat this as an agent` | token from a config: `The token in <config> is that core's agent token, not its operator token, and an agent may not change Scope. Nothing was changed.`; token from `--token-file`/`AITM_BUS_TOKEN` (explicit source, 2026-11-01 quality Q1): `The token in <token file> | AITM_BUS_TOKEN is that core's agent token, not its operator token, and an agent may not change Scope. Nothing was changed.` | config: `Set mcp.operator_token to a different value and restart the core.`; explicit: `Pass that core's operator token, or drop --bus to let aitm find the core.` | config: `aitm operator-token generate --force`; explicit: none (the one-shot never read that core's config, so no command it could offer is known to be true) |
| **R9** | the core's `isError` text is a Cli-only gate sentence (research F14) | the core's sentence verbatim, e.g. `tls.passthrough.add refused: changing the TLS passthrough list from an agent frontend is disabled. Set tls.allow_agent_passthrough = true in the aitmproxy config to allow it, or change the list from the human CLI.` | `This one-shot reached the core at 127.0.0.1:50512 as an operator; that verb admits only an in-process CLI, which has no running core to change. The app and the TUI are refused by the same gate. Nothing was changed.` | `Set the config key the sentence names in <config> and restart the core.` (explicit `--bus`/`AITM_BUS` source: `Set the config key the sentence names in the config that core was started with, and restart it.` — the one-shot cannot name a file it did not resolve; 2026-11-01 quality Q1) | none |
| **R10** | the budget elapses | `the core at 127.0.0.1:50512 accepted the connection but did not answer <verb> within 30 s` (`10 min` for a long verb); for the handshake budget, before any verb is sent, `the core at 127.0.0.1:50512 accepted the connection but did not answer within 2 s` (no verb) | `The call may still be running there. Whether anything changed is unknown.` | `Check the core's log, then retry.` | none |
| **R11** | two or more live cores at the same preference | `two running cores found` (`3 running cores found`) | one line per core, `127.0.0.1:50512 · pid 4821 · started 12 min ago · <config>`, then `Neither was started from <config>, so aitm cannot tell which one <verb> means. Nothing was changed.` (`None of them` for three or more; `Both were started from <config>` when the tie is among two matching pointers, `All of them were started from <config>` for three or more matching) | `Pass --bus with the address of the one you mean, or --config with the config it was started with.` | `aitm --bus <addr> <argv as typed>` (`<addr>` is a literal placeholder, like `<host>`) |
| **R12** | the connection drops mid-call | `lost the core at 127.0.0.1:50512 while running <verb>` | `<bus error text>. Whether anything changed is unknown.` | `Check the core's log, then retry.` | none |
| **R13** | the token-bearing config cannot be read or parsed (Task 8) | W1's generic `report_for` shape: `reading config file <path>` / `in config file <path>` with the cause chain, no fix line | | | none |
| **R14** | a `--token-file` cannot be read (Task 8) | `reading the bus token file <path>` with the cause, no fix line | | | none |
| **R15** | the token-bearing config is not a regular file owned by this user | `the config <path> is not a regular file owned by this user` | `aitm reads an operator token only from a regular file it owns. Nothing was changed.` | `Fix the file's owner, or pass --bus with --token-file.` | none |

R9 deviates from decision (c)'s "one line saying to use the app or the TUI": every operator-token surface (TUI, web, mac) is refused by the same `!= Frontend::Cli` gate (F14), so that sentence would be false; the panel says so and names the only true fix. The age `started 12 min ago` is derived from `started_unix` (`just now` under 60 s, then minutes, hours, days).

### D10. Security

- **The posture change.** Before: operator access was off until the operator wrote `mcp.operator_token`; a same-user local process could reach a terminal core only over the agent token (if a loopback transport was configured) or stdio. After: every serving core accepts an operator-token connection on `127.0.0.1`; the token sits in the operator's `0600` `config.yaml`. A same-user local process that can read that file could already read the agent token, the CA key (`ca/ca.key`, same directory) and the session's audit log, and the macOS app and the TUI already accept exactly this exposure (the app's per-launch `config.yaml`, `0600`, and `aitm-tui --token-file`). Other users on the machine gain nothing: `0600` file, `0700` run dir, loopback bind. The agent policy, the stdio agent transport and the agent token are untouched (AC-R14-7). **Review requirement:** the security reviewer's report must sign off the token handling in `operator_token::mint_if_absent`, `write_atomically`, `oneshot::resolve::read_operator_token`, and the pointer writer (no token, atomic, modes), by name.
- **First-run minting** writes one file the operator did not ask for by name: the default `config.yaml` (or inserts one line into the one they pointed at). The checklist says so (`operator token written · <path>`). Opt-out: `mcp.operator_bus.enabled: false`.
- **The pointer file** never carries a token; it is `0600` in a directory the core created `0700` (or the operator's own `AITM_RUN_DIR`, whose mode is theirs — S3); a reader ignores foreign, wide, non-regular or non-loopback pointers; a pointer whose writer no longer holds the lock is deleted before any byte is sent (research F18/Q6). The config-port case (`port: 9090`, no pid) keeps parity with the mac app's external lane and `aitm-tui --bus`: the token is sent to whatever listens there, by the operator's own configuration; `AITM_BUS`/`--bus` likewise.
- **Recycled port:** the lock, not the connect, decides whether a pointer is dialed; a writer that holds the lock but refuses is not dialed again by that run and the pointer is kept for the operator to inspect (R4). No pid probe exists: `kill(pid, 0)` would need `unsafe`, which the workspace forbids, and `ps` would be a process spawn in a one-shot.
- **Config read:** regular file, same uid, follow symlinks, warn on wide modes (§D7 rule 6); the parse is `config_file::load`, side-effect free. **Trust anchor (Task 8, for the security reviewer):** "same uid" is the owner of the run directory, which the operator's own process creates `0700` under its data dir by default; `AITM_RUN_DIR` is an explicit override in the operator's own environment, so pointing it at another user's directory is the operator's choice (that user's pointers would then pass trust and the operator's own config would read as foreign, R15). The workspace forbids `unsafe`, so `geteuid()` is not available; the reviewer may ask for a stronger anchor.
- **Remote text:** every string from the core (error text, confirm prompt, `tools/list` names) passes through the W1 renderer's sanitizer before the terminal; prompts go through the `Confirmer`'s own `write!`, so the one-shot sanitizes the prompt with `aitm_term::text::sanitize` before asking.
- **Loopback only:** `bind_operator_only` binds `Ipv4Addr::LOCALHOST`; `--bus` off loopback is a usage error; a pointer with a non-loopback `bus` is ignored. The TUI's `--allow-remote-bus` has no one-shot counterpart.
- **No secrets in memory beyond need:** the `OperatorToken` wrapper has a redacting `Debug` and no `Display`; no zeroization (parity with the TUI; no crate).

### D11. Compatibility

| Consumer | Today | After this spec |
|---|---|---|
| `tests/e2e/aitm_e2e/core.py` | spawns `aitm --config … --bus-endpoint-file <workdir>/bus.addr`, reads the address, dials with its config's `operator_token` | unchanged; its loopback transport is `Shared`; it now also publishes a pointer under the runner's `run/cores` while running (removed on its SIGTERM); set `AITM_RUN_DIR=<workdir>` to isolate (optional, not required) |
| `apps/web/scripts/live-env.mjs` | spawns `aitm web` with a loopback config and an operator secret | unchanged; `Shared`; same pointer note |
| mac app, embedded core (`EmbeddedCore.swift`, `EmbeddedCoreLaunch.swift`) | loopback transport, `operator_token`, `endpoint_file` in a `0700` per-launch dir | unchanged behaviour; `Shared`; the core publishes `run/cores/<pid>.json` naming the per-launch config, so a one-shot reaches it with no flags; the app's own newest-dir trap is a follow-up |
| mac app, external lane (`BusEndpoint.fromConfigFile`) | reads `loopback_tcp.port`/`token` (the agent token) from the default config; the operator token is pasted | unchanged; INSTALL.md gains one sentence: the operator token now exists in `config.yaml` after the core's first run |
| `aitm-tui --bus` / `AITM_BUS` | attaches to an existing core | unchanged: the override semantics every surface keeps; `aitm-tui` with no flags still prints its usage (follow-up) |
| Homebrew formula pins (`aitm web --help` ⊃ `web operator UI`; `aitm-tui --help` exit 2) | — | unchanged |
| `tests/e2e/cli/cli-startup.sh:288,314` | runs the one-shot `aitm flow list` with a loopback config and no core, expects exit 0 / a config error | `flow list` is live and would refuse: both lines become `aitm ca status` (a local verb; the bad-config case still fails on the config) |
| `tests/e2e/cli/term-reporting.sh` §4 | `aitm flow list --bogus 1` → 2, `aitm --config /nonexistent.yaml flow list` → 1, `aitm findings get --id nope` → 1 | unchanged: usage and config errors precede resolution; `findings get` is local |
| same, §5/§13 (`aitm -vv scope list`, the rotation run, the 11-run timing vs 0.5.10) | one-shot `scope list` | the verb word becomes `ca status` (local, same boot) in all of them; AC-W1-30's subject is re-pinned (§D14) |
| same, §2/§14 card pins | `^Bus: loopback 127\.0\.0\.1:`, `^Scope: … · aitm scope add --host <host>$`, `  Bus           loopback 127.0.0.1:` | hold: the script's loopback configs are `Shared` (the token is minted into the temp config on first run when absent), `Bus:` keeps its prefix (` · operator` is a suffix), the Scope next step appears (reachable) |
| same, §9 (stdio config, stdin-EOF exit) | last line `stdin closed · stdio MCP transport ended` | holds: the operator bus task ends with `run()` silently |
| same, §10 (token absence) | greps the bridge and operator tokens | the R14 proof adds the minted token (read from the `0600` file by the script, never echoed) to the same greps |
| `web_bus_*`, `tui_live_bus`, `l4_*`, `audit_log_*` integration tests | build `McpServer`s in-process | unchanged; no published context, no pointer (AC-R14-12) |
| `crates/aitm-plugins/tests/control.rs:267` | `McpConfig { … }` literal | gains `operator_bus: OperatorBusConfig::default()` |
| `README.md`, `site/*.html`, `docs/scanner.md`, `INSTALL.md` | say the one-shot cannot reach a running core | §D13 |
| `crates/aitm/src/startup/args.rs` `SYNOPSIS` footer `Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>` | — | not edited (wave-2 lane); the sentence is now true; wave 2 inherits the one-shot wording rule when it restyles help |

### D12. Lanes and frozen files

Summarised in Constraints; the claims list below names every file. `main.rs` receives six hooks (§Claims) in the last task; `tui.rs`, `wire.rs`, `startup/{mod,args,errors}.rs`, `apps/mac/**` are not edited; `aitm-term/**` only for the one `pub fn sanitize` (Claims, 2026-11-01).

### D13. Docs and the release note

Every shipped sentence that says the one-shot cannot reach a running core is replaced (research F27). Before → after:

- `README.md:665-669` — "The one-shot CLI (`aitm <family> <verb> --flag value`) runs a single command in its own process, which makes it the right tool for self-contained commands such as `aitm ca status` or `aitm ca export`; it does not steer a proxy that is already running." → "The one-shot CLI (`aitm <family> <verb> --flag value`) acts on the running core: it finds the core's operator bus (every `aitm`, `aitm web`, `aitm tui` and the macOS app's core serve one on loopback by default), runs the command there and prints the answer; with no core running it refuses and says so. A few verbs run on this machine instead of a core: `ca`, `findings list|get|remove`, `poc list|get|artifact`, `scan report`, `script validate`, `proxy system unset`."
- `README.md:303-306` — "No `cli` line is written today, because one-shot CLI commands run in their own process and build no writer." → "A one-shot that reaches a running core is recorded by that core as `operator` with the client label `aitm-cli`; a verb that runs locally (`aitm ca status`) still writes no line."
- `README.md:356-358` — "…and one-shot CLI commands such as `aitm ca status`, which run in their own process with no writer." → "…and the local one-shot verbs such as `aitm ca status`, which run in their own process with no writer (a one-shot that reaches a running core is recorded by that core)."
- `README.md:519-521` — "it needs a running core with the embedded browser, so the one-shot CLI cannot crawl." → "it needs the running core's embedded browser; `aitm scan discover` reaches that core and crawls with it."
- `site/docs.html:184` — the callout "The CLI is one-shot. … Use the one-shot form for commands that stand alone: …" → "**The CLI talks to the running core.** `aitm <family> <verb>` finds the core you started with `aitm`, `aitm web`, `aitm tui` or the macOS app (every one serves an operator bus on loopback by default), runs the command there and prints the answer, so `aitm flow list`, `aitm flow mutate` and `aitm flow resume` see and release that core's held flows. With no core running it refuses and tells you how to start one. `ca` and the other local verbs (`findings list`, `poc list`, `scan report`, `script validate`, `proxy system unset`) run on this machine without a core."
- `docs/scanner.md:69-86` — the "CLI (one-shot, no crawl)" section → "CLI": "`aitm scan discover --target …` runs on the running core, with its embedded browser and its flow store, and prints the same result the UIs and MCP show. With no core running it refuses (`no running core found`) rather than returning `pages_crawled: 0`. Scope is the core's: add the host with `aitm scope add --host <host>` first."
- `site/features.html:103` ("the flow it captures is gone when it exits") → "`aitm request send` runs on the running core, so the flow lands in that core's store and the UIs"; `:254` ("has no browser and an empty store, so it cannot crawl") → "`aitm scan discover` runs on the running core and crawls with its browser"; `:326` ("has no browser handle") → "the `browser.*` commands run on the running core's browser from the CLI too".
- `site/scripting.html:276` → "`aitm script validate` compiles a file on this machine; `aitm script list|enable|disable|reload|save` act on the running core's scripts."
- `site/poc.html:190` → "`aitm poc run` runs on the running core, browser steps included; `aitm poc list|get|artifact` read the PoC directory on this machine."
- `INSTALL.md` (after the external-core YAML) — add: "Every core mints `mcp.operator_token` into its `config.yaml` (mode `0600`) on its first run and serves a loopback operator bus; `aitm scope add --host <host>` and the other one-shot verbs use it."

**D13 addendum (2026-11-01; the Task 12 coder found the site items above given as fragments). Exact spans, whole element where marked:**

- `site/features.html` lead paragraph (line 41), the last sentence only: "The one-shot CLI (`aitm <family> <verb>`) runs a single command in its own process, so for anything that acts on live flows the hand side is a UI action instead." → "The one-shot CLI (`aitm <family> <verb>`) is a client of that running core too: it finds the core, runs the command there and prints the answer, so the hand side is either a UI action or that one line." (HTML entities for `<family>`/`<verb>` and the `<code>` span kept.)
- `site/features.html:103`, whole `<p>`: → "The one-shot `aitm request send` runs on the running core, so the flow lands in that core's store and shows up in the UIs; keep editing it from there, or over MCP."
- `site/features.html:254`, whole `<p>`: → "A real crawl needs a running core with its embedded browser. The one-shot `aitm scan discover` reaches that core and crawls with its browser; with no core running it refuses rather than returning an empty result."
- `site/features.html:326`, whole `<p>`: → "The `browser.*` commands drive the running core's browser from a UI, a PoC, a plugin, over MCP, or from the one-shot CLI, which reaches the same core."
- `site/scripting.html:276`, whole `<p>`: → "From a terminal, `aitm script validate` compiles a file on this machine and needs no core. `aitm script list`, `enable`, `disable`, `reload` and `save` act on the running core's scripts, the same core MCP and the UIs talk to."
- `site/poc.html`, the `cli` row of the pair above line 190: its file `pocs/status-check.yaml` becomes `pocs/reflected-xss-search-q.yaml` (the same file as the `agent` row; the different file existed only because the one-shot had no browser). The `<p>` at line 190, whole: → "The one-shot `aitm poc run` runs on the running core, so `browser` steps and `browser-eval` matchers work from a terminal too; the same file runs by agent or from a UI's Findings panel (*Run again*). Either way the result has the same shape, and the CLI prints it as JSON:" (the `<em>` kept).
- `site/poc.html:212`, the last sentence of the `<li>`: "The one-shot CLI's store ends with the command, so the id matters most in a long-lived core." → "A one-shot `aitm poc run` records into the running core's store, so the id stays valid for as long as that core runs."
- `site/poc.html:229`, the second sentence: "Operator sessions and the one-shot CLI are never gated: the terminal UI and the macOS app's own core are operator sessions, and the web UI becomes one when `mcp.operator_token` is set." → "Operator sessions are never gated: the terminal UI, the macOS app's own core and the one-shot CLI (which connects to the running core as the operator) are operator sessions, and the web UI is one through the operator URL on its ready card."
- `docs/scanner.md:60`: "and register `scan.discover`. Drive it through one of those, not the one-shot CLI." → "and register `scan.discover`. Drive it through any of them; the one-shot CLI reaches the same running core."
- `docs/scanner.md:196`: "(obscura not found, or a one-shot CLI call)" → "(obscura not found)".
- Left as they are (still true): `site/features.html:41`'s other sentences, `site/docs.html:82` ("runs one-shot commands"), `docs/scanner.md:54` ("reachable from MCP, the one-shot CLI and the UIs").
- AC-R14-30 gains: `grep -c 'runs its own core' site/features.html` → 0, `grep -c 'has no browser' site/features.html site/poc.html` → 0 in both, `grep -c 'not the one-shot CLI' docs/scanner.md` → 0, `grep -c 'poc_path pocs/reflected-xss-search-q.yaml' site/poc.html` → 1 (the pair's `cli` row; the terminal figure below it keeps its `status-check` sample run, a valid run of a different PoC).

**Release note** (exact text for the PR body and the next release; records the posture change):

> **Every surface starts a core you can talk to.** Bare `aitm`, `aitm web` and `aitm tui` now serve a loopback operator bus by default (an ephemeral `127.0.0.1` port, shown on the ready card as `Operator bus`), mint an operator token into `config.yaml` (mode `0600`) on their first run, and publish a pointer under `run/cores/` while they run; the macOS app's core already did. One-shot verbs — `aitm scope add --host <host>`, `aitm flow list`, `aitm poc run` and the rest — now act on that running core and refuse, naming what they looked for and the one fix, when none is reachable; they no longer run against a throwaway in-process proxy that printed success and changed nothing. `ca`, `findings list|get|remove`, `poc list|get|artifact`, `scan report`, `script validate` and `proxy system unset` still run on their own. **Posture:** operator access is on by default for a same-user local process that can read the `0600` config — the exposure the TUI and the macOS app already accept; set `mcp.operator_bus.enabled: false` to opt out. The MCP agent transport (stdio by default), the agent token and the agent policy are unchanged.

The per-host spec's draft note ("add the hosts you are authorised to inspect with `aitm scope add --host <host>` (or the Scope sheet)") becomes true with this PR and needs no edit.

### D14. Wave-1 criteria this spec re-pins

The wave-1 spec is edited in two places only (its R14 Non-goals bullet and Open question 1, both pointing here); the following wave-1/3 criteria are read as amended by this spec:

- **AC-W1-6:** the `▸ aitm scope add --host <host>` line appears when Scope is empty **and** the card's own core is reachable by a one-shot (`operator_bus` is `Shared` or `Dedicated`); with the operator bus off the row has no next step (§D5).
- **AC-W1-30:** the one-shot timing subject is `aitm ca status` (a local verb with the same boot), not `aitm scope list`, which now needs a core (§D11).
- **AC-W3-7 and M5:** the honest stderr line's clause `this one-shot proxy only; a running aitm does not see it` applies to local verbs only; for live verbs wave 3 names the core (`· core 127.0.0.1:50512`), wording fixed in the wave-3 plan.

### D15. Pending: auto-start from a one-shot (not in this PR)

The orchestrator confirmed (2026-11-01): **a one-shot with no reachable core refuses**, in both the default-discovery and the `--bus`/`AITM_BUS` cases, with the panels of §D9; the fix command `aitm` is true because every surface now starts a core with a bus. The alternative reading — a one-shot that finds no core spawns `current_exe()` detached (new session, stdio to the log file), polls `run/cores` for its pointer up to a bounded wait, acts on it and leaves it running — is the **next PR**, designed together with an `aitm core start|stop|status` lifecycle in wave 3's command surface: who stops that core, how it is listed, where its log goes, and that the W1 ready card is never seen for it. Nothing in this spec depends on it; it has no plan task here.

## Acceptance criteria

Each is observable on the real binary unless marked (unit). "Fresh `HOME`" means an empty directory; "default core" means bare `aitm` started there with no flags and no config file.

**Surfaces and the operator bus**

1. **AC-R14-1** A default core's ready card (TTY) contains the rows `  Bus           stdio (MCP)` and `  Operator bus  127.0.0.1:<port>` with `<port>` ≠ 0, and the piped card (`2>file`) contains `Bus: stdio (MCP)` and `Operator bus: 127.0.0.1:<port>`; `lsof -nP -p <pid> -iTCP -sTCP:LISTEN` shows that port bound on `127.0.0.1` only. The Scope row carries `▸ aitm scope add --host <host>` (TTY) / `· aitm scope add --host <host>` (plain).
2. **AC-R14-2** `aitm web --no-open` in the same `HOME` shows the same `Operator bus` row plus the `Operator` URL row; `aitm tui` publishes a pointer (`run/cores/<pid>.json` exists while it runs) and a one-shot reaches it (AC-R14-14).
3. **AC-R14-3** After the first start of a default core, `<HOME>/Library/Application Support/aitmproxy/config.yaml` (Linux: `$XDG_CONFIG_HOME/aitmproxy/config.yaml`) exists, `stat` mode is `600`, it contains exactly one line matching `^  operator_token: [0-9a-f]{64}$` under `mcp:`; the checklist printed `operator token written · <path>`; a second start prints no such line and leaves the file's bytes and mtime unchanged.
4. **AC-R14-4** A pre-existing config without `operator_token` (with comments and a `listen:` line) gains exactly the one `operator_token:` line, every other byte unchanged, mode `600` afterwards even if it was `644` before; a config with a token is not written. `aitm operator-token generate --force` still rotates it and the file stays `600` (unit + live).
5. **AC-R14-5** With `mcp.operator_bus: {enabled: false}` and the default transport: no third listener, no token written, the card shows `Operator bus  off · mcp.operator_bus.enabled: false` (warning role) and the Scope row has no next-step line; piped `Operator bus: off · mcp.operator_bus.enabled: false`.
6. **AC-R14-6** With a loopback transport and an operator token the card's Bus row reads `loopback 127.0.0.1:<port> · operator` (or `loopback 127.0.0.1 (ephemeral port) · operator`), no `Operator bus` row is printed, and the process holds exactly one bus listener.
7. **AC-R14-7** (unit) `McpConfig::default()` has `transport == Stdio`, `policy == Auto`, `stdio_role == Mcp`, `agent_token == None`, `operator_token == None`, `operator_bus == OperatorBusConfig { enabled: true, port: 0 }`; `parse_settings("")` yields the same; `parse_settings("mcp:\n  operator_bus:\n    enabled: false\n    port: 9091\n")` yields `{ enabled: false, port: 9091 }`; an unknown key under `operator_bus` is a parse error.
8. **AC-R14-8** (socket, Terminal) `LoopbackTcp::bind_operator_only(0, token)` binds an address whose `ip()` is `127.0.0.1`; with `mcp.operator_bus.port: N` the live card shows `127.0.0.1:N`; a connection presenting the operator token is `role: "operator"` and one presenting any other string gets `-32001` and a closed socket.
9. **AC-R14-9** With a holder on `127.0.0.1:N` and `mcp.operator_bus.port: N`, bare `aitm` exits 1 with the M2-shaped panel whose headline is `cannot start: the operator bus port 127.0.0.1:N is already in use` and whose remedy names `mcp.operator_bus.port`; stdout empty.

**The pointer**

10. **AC-R14-10** While a default core runs, `run/cores/<pid>.json` exists with mode `600` in a `700` directory, is one line of JSON whose keys are exactly `v,pid,bus,operator,config,started_unix,version` with `v == 1`, `pid` the core's pid, `bus` a `127.0.0.1:<port>` string equal to the card's `Operator bus` value, `operator == true`, `config` the absolute default config path, and contains no substring of the operator token; while the core runs, `python3 -c` opening it and calling `fcntl.flock(fd, LOCK_SH | LOCK_NB)` raises `BlockingIOError` (the writer holds the lock); it is gone within 1 s after SIGTERM, after Ctrl-C, and after the stdin-EOF exit; it survives SIGKILL with its lock released (the same `flock` then succeeds).
11. **AC-R14-11** With `AITM_RUN_DIR=<dir>` set for both the core and the one-shot, the pointer is written under `<dir>` and `aitm scope add` finds it there; nothing is written under the default run dir.
12. **AC-R14-12** (unit) Serving a `LoopbackTcp` in a test with no published context writes no pointer (the transport never reads the environment, plan C2: the test asserts `listener.pointer.is_none()` after `publish_pointer()`); publishing a context then serving writes the file and dropping the listener removes it (socket part in the Terminal; amended 2026-11-01, Sp7).

**One-shot verbs**

13. **AC-R14-13** Against a default core, from a second shell in the same `HOME`: `aitm scope add --host example.com` exits 0, stdout is exactly `example.com\n`, stderr is empty; `aitm scope list` exits 0 with stdout exactly `[\n  "example.com"\n]\n`; `tools/call scope.list` over the operator bus (a python client reading the address from the pointer and the token from the `0600` config, never echoing it) returns `["example.com"]`; the core's `audit.jsonl` gains a line with `"origin":"operator"`, `"client_label":"aitm-cli"`, `"command":"scope.add"`.
14. **AC-R14-14** The same two commands succeed against `aitm web --no-open`, against `aitm tui` (the TUI's Scope view shows the host), and, when the mac app is running, against its embedded core (the app's Scope page shows the host) — all with no flags.
15. **AC-R14-15** With no core running (fresh `HOME`, no pointer, default config), `aitm scope add --host example.com` exits 1, stdout is empty, stderr is the R1 panel: TTY headline `✕ no running core found`, body ending `Nothing was changed.`, fix line exactly `  ▸ aitm`, a `Log` footer; piped: `error: no running core found`, `  fix: aitm`, `  log: <path>`.
16. **AC-R14-16** With `--config` naming a file whose `mcp.transport.loopback_tcp.port` is a free port and no core: the R2 panel, headline `no running core at 127.0.0.1:<port>`, fix line `aitm --config <path>`, exit 1; when a default core is also running, the body contains `A different core is running at 127.0.0.1:<its port>`.
17. **AC-R14-17** After `kill -KILL` of a default core, the next `aitm scope list` prints R1 (exit 1), not R4, and the stale `run/cores/<pid>.json` no longer exists: the reader found the lock free, deleted the file and dialed nothing.
18. **AC-R14-18** With `mcp.operator_bus: {enabled: false}` in the one-shot's config and no core: the R5 panel, headline `this config serves MCP over stdio and no operator bus, which a second client cannot reach`, no fix line, exit 1.
19. **AC-R14-19** With two cores running in one `HOME` (core A on the default config, core B on a second config that only moves `listen` and `browser.proxy_addr` to free ports; the one-shot runs with a third config that matches neither, so the preference tie-break finds two candidates — plan call C14), `aitm scope list` exits 1 with `two running cores found`, two `127.0.0.1:<port> · pid <pid> · started <age> · <config>` lines, and the fix line `aitm --bus <addr> scope list`; `aitm --bus 127.0.0.1:<one port> --token-file <file holding the token> scope list` then succeeds.
20. **AC-R14-20** After `aitm operator-token generate --force` while the core keeps running, `aitm scope list` prints R7 (`refused the operator token in <config>`), exit 1; after restarting the core it succeeds again.
21. **AC-R14-21** Against a default core, `aitm tls passthrough add --host example.com` exits 1 with the R9 panel: the headline is the core's sentence (starts `tls.passthrough.add refused:`), the body names the core's address and `The app and the TUI are refused by the same gate.`, no fix line; `aitm tls passthrough list` then prints `[]`.
22. **AC-R14-22** (unit) `tests/oneshot_verbs.rs` passes on the tree: every registered verb is in `EXPECTED`, `placement` matches, every `LOCAL_VERBS`/`LONG_RUNNING_VERBS` name is registered, no param is named `bus` or `token-file`; a verb added to `EXPECTED` under a wrong placement fails. Live: with no core, `aitm ca status` exits 0 and `aitm proxy status` prints R1.
23. **AC-R14-23** `aitm --bus 127.0.0.1:<port> --token-file <file> scope list` (the token copied by the recipe into a `0600` file, never echoed) succeeds; `AITM_BUS=… AITM_BUS_TOKEN=… aitm scope list` succeeds; `aitm --bus 10.0.0.5:9090 --token-file x scope list` exits 2 with `--bus 10.0.0.5:9090 is not a loopback address`; `aitm --bus 127.0.0.1:1 scope list` (no token) exits 2 with `--bus needs --token-file <path> or AITM_BUS_TOKEN`; `aitm --bus 127.0.0.1:1 --token-file x ca status` exits 0 and stderr has one line `warning: --bus ignored · ca status runs on this machine, not on a core` (plain).
24. **AC-R14-24** (unit, in-process) Over `InProcessTransport` wrapping `McpServer::handle_on(&ConnCtx::new(Frontend::Operator), ..)`: `remote::call` for `scope.add {host}` then `scope.list` yields `Value::Array([Str("example.com")])`; `render_cli_value` of the remote value equals `render_cli_value` of `Cli::dispatch` on the same registry byte for byte; a test command returning `Value::Bytes(b"\x89PNG")` round-trips through base64 to identical bytes; the `needs_confirmation` handshake re-sends with `_confirm` after a fake `Confirmer` says yes and aborts with `aborted: … not run` when it says no; `isError` text becomes a `Failure` report with that `what`; a gate sentence becomes R9; `role: "agent"` becomes R8.
25. **AC-R14-25** With `AITM_BUS` pointing at a python listener that accepts and never answers, `aitm scope list` exits 1 within 4 s with R10, headline `the core at <addr> accepted the connection but did not answer within 2 s` (the handshake form, no verb); with a listener that closes at once, R2' (`no running core at <addr>`).
26. **AC-R14-26** `aitm scope list` against a default core, median of 11 runs, is ≤ 2× the median of `aitm ca status` in the same `HOME`, both printed.
27. **AC-R14-27** The W1 pins still pass: `tests/e2e/cli/cli-startup.sh` and `tests/e2e/cli/term-reporting.sh` end `0 failed` with their verb-word swaps (§D11).
28. **AC-R14-28** The minted token (read by the proof script from the `0600` config into a variable, never echoed) occurs zero times in: the core's stderr and stdout, the log file, the pointer file, every one-shot's stderr and stdout, and the `RUST_LOG=info` raw stream of a run.
29. **AC-R14-29** (unit) `format!("{:?}", Minted::Written { .. })` contains `<redacted>` and not the token; `OperatorToken` has no `Display`.
30. **AC-R14-30** The docs sentences of §D13 are replaced: `grep -c 'does not steer a proxy that is already running' README.md` is 0, `grep -c 'The CLI is one-shot' site/docs.html` is 0, `grep -c 'one-shot, in-process' docs/scanner.md` is 0, and each replacement sentence is present; the release-note paragraph is in the PR body.
31. **AC-R14-31** (unit) `read_operator_token` on a `0644` temp config returns the token and the reporter receives one warning line `<path> is readable by other users · chmod 600 <path>`; on a `0600` file, no warning; on a directory or a FIFO at the path, `TokenProblem::NotRegular` (R15).
32. **AC-R14-32** (unit) `resolve` with a temp run dir: one live pointer (the test holds its lock) → `Target::Pointer`; an unlocked pointer is deleted and ignored; two live pointers, one matching the effective config → that one; two matching → `Refusal::TwoCores` naming both; a pointer with `bus: "10.0.0.5:1"`, a `0644` pointer, a foreign-uid pointer (simulated by the trust function's injected metadata) → ignored; `v: 2` → ignored.

## Left to the builder

- The exact `Msg`/`Target`/`Refusal` enum shapes inside `oneshot`, as long as every §D9 text is a literal in `refuse.rs` with a unit test per variant (rich and plain).
- The relative-age formatter's thresholds beyond `just now` / minutes / hours / days.
- Whether `serve_on` takes `LoopbackTcp` by value or an `Arc`; whether the operator-bus task is a `JoinHandle` or an abort-on-drop guard type.
- The liveness and uid seams (`&dyn Fn(&Path) -> Liveness` over the lock probe, the owner uid read from the run directory) used by the unit tests.
- The generic flag parser for verbs the local registry lacks (JSON-if-it-parses else string; bare flag → `true`).
- Where `OperatorToken` lives (`operator_token.rs` is suggested) and how `run()` moves it into `cfg.mcp.operator_token`.
- Temp-dir and env-closure conventions: follow the W1 plan (C23; env as `&dyn Fn(&str) -> Option<String>`).

## Open questions

None for Matt. Facts the Architect could not verify in the sandbox (loopback connect and `ps` are denied) and that the live proof settles: whether the other two `aitm-embedded-core/<UUID>/` cores on this Mac are alive (research §5 item 4; irrelevant to the design, which never picks by directory); the published v0.5.9 GitHub release body (research §5 item 9; the local notes carry no `aitm scope add` sentence, so nothing shipped needs correcting beyond §D13); whether the mac app's Scope page refreshes on a bus-side `scope.add` without a manual reload (AC-R14-14 reads the page after a reconnect if not).

## Claims list (every file the implementation touches)

**New files**

- `crates/aitm-mcp/src/pointer.rs` — schema, run dir, publish/context, atomic write, read/trust/delete.
- `crates/aitm/src/operator_bus.rs` — `plan`, `start`, `OperatorBus`.
- `crates/aitm/src/oneshot/mod.rs` (declarations only), `args.rs`, `verbs.rs`, `resolve.rs`, `remote.rs`, `refuse.rs`, `run.rs`.
- `crates/aitm/tests/oneshot_verbs.rs`, `crates/aitm/tests/oneshot_remote.rs`, `crates/aitm/tests/operator_bus_defaults.rs`, `crates/aitm/tests/operator_bus_live.rs` (socket; Terminal).
- `tests/e2e/cli/oneshot-live-core.sh`.

**Edited files**

- `crates/aitm-mcp/src/lib.rs` — one line, `pub mod pointer;`.
- `crates/aitm-mcp/src/transport.rs` — `agent_token: Option<Arc<str>>`, `bind_operator_only`, `classify_token` signature, the pointer publish when serving starts (`serve_on`, D4), pointer removal in `Drop`.
- `crates/aitm-mcp/src/server.rs` — `serve_on` (additive; `serve`'s loopback arm delegates to it).
- `crates/aitm-core/src/config.rs` — `OperatorBusConfig`, `McpConfig.operator_bus`, the `operator_token` doc comment; `crates/aitm-core/src/lib.rs` — the `OperatorBusConfig` re-export (one line; added to the claims 2026-11-01, spec Sp2).
- `crates/aitm-plugins/tests/control.rs` — the one `McpConfig { .. }` literal gains the field.
- `crates/aitm/src/config_file.rs` — `operator_bus` under `McpFile`, tests.
- `crates/aitm/src/operator_token.rs` — `write_atomically` creates `0600`; `mint_if_absent`, `Minted`, `OperatorToken`.
- `crates/aitm/src/startup/card.rs` — `OperatorBusWord`, `ReadyInputs.operator_bus`, the `Operator bus` row, `scope_row(n, reachable)`, tests.
- `crates/aitm/src/lib.rs` — two lines, `pub mod oneshot;` and `pub mod operator_bus;`.
- `crates/aitm-cli/src/dispatch.rs` — one line: `fn parse_flags(` → `pub fn parse_flags(` (line 224 today), with its doc comment kept.
- `crates/aitm-term/src/text.rs` — one word plus one doc sentence (added 2026-11-01, Task 10): `pub(crate) fn sanitize` → `pub fn sanitize` and the doc names the remote path as a user, so core-sent text is sanitized with the renderer's own sanitizer instead of a copy; wave 2 does not touch this file.
- `crates/aitm/src/main.rs` — LAST task, six hooks, nothing else: (1) `parse_invocation` (lines 260–295): one `let (bus_args, argv) = oneshot::args::split_bus_args(argv)…` after the `--bus-endpoint-file` split and `bus_args` stored in `Invocation`; (2) `run()` after `apply_bus_endpoint_file` (line ~457): for serving modes, `mint_if_absent` with its phase/warning (≈6 lines) and `aitm_mcp::pointer::publish(..)` (1 line); (3) `run()` after `tui::services(..)` (line ~866): `let operator_bus = operator_bus::start(..).await?;` (≈2 lines); (4) the `print_ready_card` closure (line ~1052): `operator_bus: operator_bus.word(),` (1 line); (5) the `Mode::Cli` arm (lines 653–684): its body becomes `return oneshot::run(Inputs { .. }).await;` keeping the `handles.bind_proxy`/`tier.error_sink.bind` lines (≈10 lines replace ≈20); (6) one `result = operator_bus.finished() => result` arm in each of the two `select!`s (≈2 lines; security S1, Sp10/Sp21, 2026-11-01). Why they cannot be avoided: `main.rs` owns argv splitting, the effective config path, the mode, the service handles and the card inputs; each hook is one call into a new module.
- `tests/e2e/cli/term-reporting.sh` — `scope list` → `ca status` at the §5 and §13 call sites (lines 693, 700, 966–1002 today); §10 greps gain the minted token.
- `tests/e2e/cli/cli-startup.sh` — `flow list` → `ca status` at lines 288 and 314.
- `tests/e2e/cli/README.md` — a section for the new script.
- `README.md`, `site/docs.html`, `site/features.html`, `site/scripting.html`, `site/poc.html`, `docs/scanner.md`, `INSTALL.md` — §D13.
- `docs/superpowers/specs/2026-11-01-cli-terminal-reporting-design.md` — the R14 Non-goals bullet and Open question 1 (pointers here).

**Frozen or other-lane files, not touched**

`crates/aitm/src/wire.rs`, `crates/aitm/src/tui.rs`, `crates/aitm/src/web/**`, `crates/aitm/src/startup/{mod,args,errors,log}.rs`, `crates/aitm-term/**` except the one word in `text.rs`, `crates/aitm-cli/src/{lib,confirm}.rs`, `crates/aitm-cli/tests/**`, `crates/aitm-cli/Cargo.toml`, `crates/aitm-tui/**`, `apps/mac/**`, `apps/web/**`, `tests/e2e/aitm_e2e/**`, every `Cargo.toml` and `Cargo.lock`.

## Follow-ups (not this PR)

1. Auto-start from a one-shot with the `aitm core start|stop|status` lifecycle (§D15; wave 3's command surface).
2. Widen the four `Frontend::Cli`-only gates to `caller_is_trusted_control()` (research F14 option ii) — Matt's call; until then R9.
3. Mac lane: `EmbeddedCore` reads `run/cores/*.json` with liveness by connect instead of the newest directory (research §5 item 11); `BusEndpoint.fromConfigFile` may read `operator_token` so the external lane needs no paste.
4. Standalone `aitm-tui` with no `--bus` resolves the core like a one-shot (needs a YAML token read in the TUI crate, or a token-file companion written by the core — the latter is rejected here: no second token-bearing file).
5. Skip the local host boot for live verbs once wave 2's schema-only registry lands (research F24c, R11).
6. Wave 3: the honest stderr line names the core for live verbs (§D14).
7. Harness isolation: `tests/e2e/aitm_e2e/core.py` and `live-env.mjs` set `AITM_RUN_DIR` to their work dir.

## Summary

Every aitmproxy surface now starts with a core that can be talked to: a loopback operator bus on an ephemeral port, an operator token minted once into the `0600` config, and a `run/cores/<pid>.json` pointer (address, config path, pid; never a token) written by the loopback transport itself, so the macOS app's embedded core is found with no Swift change. One-shot verbs become clients of that core: `aitm scope add --host x` resolves the core (`--bus`/`AITM_BUS` → config → pointer dir), connects as the operator, runs the verb there and prints the answer through the same renderer as before; thirteen local verbs (CA, findings, PoC files, reports, script validation, undoing the OS proxy) still run on their own; everything else, unknown verbs included, is live, enforced by a registry-walking test. With no reachable core the one-shot refuses with a W1 panel — fifteen variants, each with exact text, each ending `Nothing was changed.`, each with a fix that is true now that `aitm` starts a reachable core. The W1 card gains an `Operator bus` row and promises `aitm scope add` only when it can keep the promise; the docs and the release note say so.

## Calls made in this spec (veto any)

Amendment dates: every sentence in D2–D10 and D13 marked "(Task N)", "amended", "aligned", "added" or carrying a reviewer id (Q1, Sp2, Sp7, …) was written on 2026-11-01 during stages 4–6; the plan's matching rows carry the same date.

Decided inputs followed: (a)–(h) and the product rule verbatim; refuse, never auto-start, for a one-shot with no core.

Architect's calls:
1. The operator bus is **the loopback agent transport when one is configured, else a dedicated operator-only listener** (`bind_operator_only`), never a new `McpTransport` variant (six crates match on it; `wire.rs` is frozen).
2. Config surface `mcp.operator_bus: { enabled: true, port: 0 }` as the opt-out and the fixed-port knob; the `operator_token` doc comment is the posture flip.
3. Minting happens in `run()` for serving modes only, creates the default file only when no explicit path was given, is never fatal (`Skipped` → one warning, bus off), and prints one phase `operator token written · <path>` only when it writes; `write_atomically` always creates `0600` (closes F7).
4. Pointer schema `{v,pid,bus,operator,config,started_unix,version}`, `run/cores/<pid>.json`, atomic rename, `AITM_RUN_DIR` override, write-once process context published by `main.rs` (so tests never publish), liveness by advisory lock (safe `std`, no FFI, no spawn), reader deletes pointers whose writer no longer holds the lock and keeps locked-but-refusing ones.
5. The card shows a new `Operator bus` row for a dedicated bus and ` · operator` on the Bus row for a shared one; the Scope next step depends on reachability; `aitm-term` is untouched.
6. Verb table: the thirteen local verbs of §D6; `poc run`, `findings record`, `config get`, `proxy system status` live; `proxy system unset` local; long-running set with a 10 min budget; 30 s otherwise; 2 s handshake.
7. The remote path keeps today's local boot and uses the local registry for parsing (parity, exit codes), falling back to the core's `tools/list` and a generic flag parser for verbs the registry lacks (so core-only verbs work and `aitm nonsense` still exits 2).
8. `--token` inline is not a one-shot flag; `--bus` with a local verb warns and runs locally; path-typed flags (`poc_path`, `path`) are made absolute before forwarding.
9. R9's fix text replaces decision (c)'s "use the app or the TUI", which F14 shows to be false for those four gates; the true fix (the config key, restart) is given and the gate widening stays a follow-up for Matt.
10. Q5: warn, never refuse, on a group/world-readable token config; refuse a non-regular or foreign-uid file. Q6: lock liveness before dialing a pointer; parity with the TUI/mac for configured ports and `--bus`.
11. `clientInfo.name` is `aitm-cli`; the phase label for a remote call is `<verb> · core <addr>`.
12. `cli-startup.sh` and `term-reporting.sh` switch their one-shot subject from `flow list`/`scope list` to `ca status`; AC-W1-6/AC-W1-30/AC-W3-7 are re-pinned here rather than edited in the W1 spec (two pointer edits only).
13. Standalone `aitm-tui` discovery and the mac app's pointer read are follow-ups, not this PR.
