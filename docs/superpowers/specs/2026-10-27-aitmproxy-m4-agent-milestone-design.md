# aitmproxy M4 — agent-driven real-test milestone design

**Status:** draft
**Research inputs:** `docs/research/04-playwright-cua.md`, `docs/research/05-synthesis.md`, `docs/research/07-ca-install.md`
**Design inputs:** `docs/superpowers/specs/2026-10-27-aitmproxy-platform-design.md` (the roadmap "Agent-driven vuln-finding site" product goal, the tool/agent split, the command bus, the PoC engine), `docs/design/operator-ui-foundation.md` §4 (command-bus contract) and §5 (core follow-ups F1–F15), and the operator-commands Coder blocker analysis (`side-session-notes/.../operator-commands-CODER-BLOCKER.md`).
**Companion / downstream specs:** the additive operator commands **F5** (`flow.detail`), **F6** (`flow.mark`/`flow.comment`), **F7** (`proxy.status`/`pause`/`resume`, `flow.clear`, `config.get`), **F12** (`scope.remove` + agent-widen gate), **F13** (`poc.list`/`poc.get`/`poc.artifact`) are being specced and built as their own spec+plan elsewhere; M4 **depends on** them and references their shapes from the foundation doc, it does not redesign them. **F2** (command-invocation audit ring + `notifications/aitm/agent`) is **owned by M4** and designed here as one coherent operator/agent-channel story with F1 (identity) and F4 (push): it is what lights up the operator "Agent" page while the agent works.

**Verified live-wire facts (ground truth; the foundation doc has drifted).** The macOS surface confirmed the following against the running core over its in-process bus; `docs/design/operator-ui-foundation.md` §4.3 is stale on these, so where this spec or the agent driver surface names a command shape, **these win**: `browser.eval` takes `expr` (not `script`); `browser.click` takes x/y floats **or** a selector; `browser.type` **requires** a selector (operators pass `":focus"`); `poc.build` returns the **YAML text** (not a path); `ca.status` reports installed/trusted as `yes|no|unknown`. The agent skill set (D7) and the report/artifact handling (D8) are written to these shapes.

## Intent

This milestone proves aitmproxy's reason to exist: **a Claude agent, given nothing but the MCP command bus and a skill set, autonomously drives aitmproxy against a real, seeded-vulnerable target using real browsers, and finds → reproduces → reports vulnerabilities end to end** — the agent-first thesis demonstrated on a real target, not on synthetic data or hardcoded answers. The platform spec names this as the roadmap's "product-level goal … an AI agent autonomously driving aitmproxy against a vulnerability-seeded test website and finding the bugs by itself." M4 is that milestone.

To make that possible, M4 also builds the **operator/agent command architecture** that the three UIs and the agent both need and that was deliberately deferred here from the operator-UI foundation work: the per-connection operator-vs-agent identity split (**F1**), the server-push channel that the live agent loop and the live flow list both ride (**F4**), and the confirm-over-the-wire mechanism that closes the hole where confirm-gated commands (`ca.install`) are reachable over the bus with no confirmation. These are architectural core changes — they are M4's, not additive drop-ins — and they are the heart of this spec.

The agent only ever **finds and reproduces**. It never exploits beyond the minimum proof that a finding is real (the existing three-artifact PoC). That boundary is an anti-goal below and is enforced structurally by deny-by-default scope, the rate/SSRF guards, and the shape of the agent's skill set.

## Goals

Observable outcomes:

1. **A Claude agent driver surface** — a committed Claude plugin / skill set (SKILL.md + skills + MCP wiring) that an agent uses to operate aitmproxy over the MCP bus: browse, intercept, mutate, replay, scope, run PoCs, and report. It encodes the *strategy* (the observe→reason→act→reproduce loop); the tool keeps all deterministic machinery (tool/agent split).
2. **F1 — per-connection operator/agent identity + the agent on/off policy.** A connection authenticates as either an **operator** or an **agent** token class; `call_tool` no longer hard-codes `Frontend::Mcp`. An `AgentPolicy { All, ReadOnly, Paused }` is enforced in the MCP server before `invoke`; `agent.status` / `agent.set` expose and change it; the agent cannot un-pause itself.
3. **F4 — server push + F2 — the agent/activity channel.** A subscription channel (`flow.subscribe` / `flow.unsubscribe`) over which the server writes unsolicited `notifications/aitm/{flow,state,agent}` lines on both transports, overturning today's strict request/response invariant; and a **command-invocation audit ring (F2)** that records every call from every role and feeds the `notifications/aitm/agent` stream, so the operator "Agent" page sees every agent action as it happens. The live agent loop and the three UIs both consume the channel. F1/F2/F4 are one operator/agent-channel story.
4. **Confirm-over-the-wire.** An operator connection can satisfy a command's `confirm_prompt` through a defined two-phase handshake; an agent connection still cannot (its gated commands stay governed by config flags such as `ca.allow_agent_install`). The `ca.install`-reachable-with-no-confirm hole is closed.
5. **A real, seeded-vulnerable test target** — a hermetic, self-contained web app seeded with a documented, enumerated set of real vulnerabilities (reflected XSS, stored XSS, SSRF, broken access control/IDOR, auth bypass, open redirect), plus patched control variants, run with no external network. The planted-vuln manifest is visible only to the grader, never to the agent.
6. **Real agent-driven e2e through real browsers on a custom, non-system proxy** — the agent exercises the target through the embedded **obscura** engine **and** an **external Chrome** (via `--proxy-server`), with **Firefox** (via its own profile proxy prefs + cert store) added as a second external engine. Never the OS proxy; never synthetic-only.
7. **A reporting contract** — the agent assembles, per finding, the existing three PoC artifacts plus reproduction steps into a human-friendly markdown report and a machine-readable index, consistent with the `poc.build`/`poc.run` model. The tool produces artifacts; the agent writes prose.
8. **A milestone exit gate** with two tiers: a **deterministic** functional gate (a scripted driver that uses only the public command surface drives find→reproduce→report against the seeded target and the grader passes, through the Rust gate) and a **live-agent acceptance** (an actual Claude agent, unaided, finds and reports the seeded vulns), the latter being the product-thesis proof.

## Non-goals

- **No automated-scanner plugin.** M4 does not build the Burp-style scanner-as-a-plugin (that is its own roadmap milestone). The *intelligence* in M4 lives in the Claude agent's skill set, not in a new Rust discovery engine. The tool gains no crawl/discovery/fuzz-orchestration logic; it gains the command architecture and the test target the agent needs.
- **No report prose or remediation advice in the tool.** As in M1: the tool emits artifacts; the agent writes the report. M4 defines the report *contract*, not a tool-side report generator.
- **No new protocols and no L4.** Raw-L4/packet MITM is a separate milestone (see the milestone-numbering note in the Design). M4 is HTTP/S + WebSocket only, as shipped.
- **No new interception semantics.** Response-phase interception and breakpoint rules (**F3**) are out of scope; M4 uses request-phase intercept/mutate/resume as they exist.
- **No remote/network transport or web bridge (F15) as an M4 deliverable.** M4's push channel works on the existing stdio + loopback-TCP transports. F15 (network TLS + `aitm web` + WS bridge) is referenced but not built here; the web UI consuming the push channel remotely is downstream.
- **No signing/validation of PoCs or of the agent's reports** (deferred platform-wide).
- **No change to the PoC artifact model or the YAML PoC language.** M4 consumes `poc.build`/`poc.run`/F13 as they are.

## Anti-goals

- **An agent that exploits.** If the agent does anything beyond proving a finding reproduces — exfiltrates data beyond the marker that proves the bug, pivots, persists, mutates target state destructively, or attacks anything the scope does not name — the milestone has failed, even if it finds every vuln. Reproduction is the terminal action.
- **Hardcoded answers.** If discovery works only because the agent (or the scripted driver) was told where the vulns are, the proof is worthless. The planted-vuln manifest must be unreachable by the driver; findings must come from observed traffic and tool feedback.
- **Synthetic-only or OS-proxy e2e.** If the "real browser" test routes through the OS proxy, or replaces the browser with a synthetic HTTP client, the milestone's core claim is unproven. Traffic must flow through a browser configured with aitmproxy as a *custom* upstream and must land in the flow store.
- **Core edits for the agent.** If supporting the agent required editing `aitm-core`'s flow/event model or protocol seams (beyond the additive command/registry/transport changes F1/F4 are), the architecture has failed. F1/F4 are additive to the command/transport layer; they do not touch the protocol modules or the `Flow`/`Event` enums.
- **An agent that can disable its own guardrails.** If the agent can un-pause itself, widen its own scope without the configured gate, self-confirm a confirm-gated command, or install the CA without `ca.allow_agent_install`, the operator/agent split has failed.
- **A push channel that leaks or blocks.** Unbounded per-connection notification buffers (memory blow-up — violates the platform's bounded-memory requirement), or a slow subscriber stalling the core, are failures. Backpressure/drop policy is required, not optional.

## Constraints

- **Language/gate:** Rust for all core/tool work. `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` must pass before any review. The Claude plugin/skill set is markdown + config, not Rust, and is linted/validated by its own checks, not the Rust gate.
- **Hermetic & cross-platform:** the seeded target, the grader, and the deterministic e2e must run with **no external network**, on **macOS and Linux**, inside `cargo test`. No Docker, no Node runtime, no vendored multi-hundred-MB app in the default gate (see the build-vs-vendor call).
- **Deny-by-default everywhere:** every new command (`agent.*`, `flow.subscribe`/`unsubscribe`) is registered through the existing `Registry`, carries a typed `ParamSchema`, and is subject to the capability model. `agent.set` is operator-only. Active actions stay scope/rate/SSRF-gated; the agent widens scope only if `scope.allow_agent_widen` (F12) is set, installs the CA only if `ca.allow_agent_install` is set.
- **Additive to the command/transport layer:** F1/F4/confirm extend `Command`, `Registry`, `CommandHost`, `Frontend`, and the MCP transport. They must not change the `Flow`/`Event` enums, the `ProtocolModule` seam, or any protocol crate. `Frontend` is `#[non_exhaustive]`; `Command::mutates()` has a safe default. Existing command signatures are unchanged.
- **Bounded memory under push:** per-connection notification queues are bounded; the drop/backpressure policy is explicit; a stalled subscriber never grows core memory without bound and never blocks the proxy data path. (Consistent with the platform's hard memory requirement.)
- **Human-friendly artifacts:** the agent's report (markdown + index) and the PoC YAML it references stay readable and writable by a human, not agent-only (`[[aitmproxy-human-friendly-scripting]]`). This is agent-first, but a human operator drives and reviews it too.
- **TLS/CA fidelity for external browsers:** external Chrome and Firefox must trust the MITM CA through a *per-browser/profile* mechanism, never by mutating the operator's OS trust store as a side effect of the test. The CA private key stays `0600` and is never read/logged/exported by new code (only the cert file path is handed out), per the M2 CA posture.
- **Workflow:** every change travels the seven stages in `docs/superpowers/WORKFLOW.md`.

## Design

The parts of the *how* that are decided. Defaults the architect chose are marked **(Architect's call)**; the one decision reserved for Matt is in Open questions.

### D0. Milestone shape, dependencies, and numbering

**What M4 owns (new work):**

1. The operator/agent command architecture: **F1** (identity split + agent policy), **F2** (command-invocation audit ring + the `notifications/aitm/agent` stream), **F4** (server push), and the **confirm-over-the-wire** mechanism — one coherent operator/agent-channel story. Rust, in `aitm-core` + `aitm-mcp`.
2. The **seeded-vulnerable test target** + the **grader** harness. Rust, a new test-support crate.
3. The **Firefox** external-browser driver option and the **multi-browser agent-driven e2e**.
4. The **Claude agent driver surface** (plugin/skill set) and the **report contract**. Markdown/config, committed in the repo.

**What M4 depends on but does not build (referenced, built elsewhere):** **F5** `flow.detail` (the agent inspects headers/bodies/conn/timing through it), **F6** `flow.mark`/`flow.comment` (the agent annotates its working set), **F7** `proxy.status`/`flow.clear`/`config.get`, **F12** `scope.remove` + the `scope.allow_agent_widen` gate, **F13** `poc.list`/`poc.get`/`poc.artifact` (the agent gathers artifacts for the report). M4's plan must declare these as prerequisites; if a prerequisite is not yet merged, the dependent acceptance criterion is blocked and the plan says so rather than M4 re-implementing it.

**Milestone-numbering call (Architect's call, flag for Matt).** A sibling architect is speccing raw-L4/packet MITM; its working note currently labels that work "M4," while the brief for *this* session labels the agent-driven real-test milestone "M4" and L4 "M5." The platform roadmap lists both as later milestones without fixed numbers. **This spec claims M4 = the agent-driven real-test milestone and treats L4 as M5**, per this session's brief. The two specs must not both ship as "M4"; the numbering is flagged in Open questions and a hand-over note is left for the L4 session.

### D1. Connection identity and token classes (F1, part 1)

**Problem (verified in code).** `McpServer::call_tool` builds its `CommandHost` with `.with_frontend(Frontend::Mcp)` hard-coded (`crates/aitm-mcp/src/server.rs:273`), and `McpServer::handle(&self, message: &str) -> Option<String>` (`server.rs:158`) is connectionless — one JSON-RPC line in, at most one line out, with no per-connection state. The three human UIs connect over the *same* MCP transport as the agent, so today they would all be treated as `Frontend::Mcp` (an agent), which is wrong for confirmations and for the policy gate. `Frontend` today is `{ Cli, Mcp }`, `#[non_exhaustive]`, deriving `Copy` (`crates/aitm-core/src/ctx.rs:54–61`).

**Decision — a connection's role is the token class it presented.** Config gains a second MCP token so the transport can distinguish the two classes:

```rust
// aitm-core config (additive)
pub struct McpConfig {
    pub transport: McpTransport,
    pub agent_token: Option<String>,      // the token an agent presents
    pub operator_token: Option<String>,   // the token a human surface presents
    pub policy: AgentPolicy,              // default policy for agent connections (D2)
}
```

- For **stdio** there is one connection and no token line; its role is configurable, default **agent** (**Architect's call** — stdio is the agent-attach transport in M1/M2; an operator surface uses loopback TCP). A config flag `mcp.stdio_role` may override to `operator` for a human attached over stdio.
- For **loopback TCP**, the existing first-line auth (`{"token":"…"}`, `server.rs`/`transport.rs`) is extended: the presented token is matched against `agent_token` then `operator_token`; a match sets the connection's role, a miss is refused `-32001 UNAUTHORIZED` as today. An agent therefore **cannot** claim to be an operator — it does not hold the operator token.

**Decision — `Frontend` gains a Copy-safe `Operator` role; the client label rides `CommandHost` separately (Architect's call, refines the blocker note).** The blocker-note sketch used `Frontend::Operator { client: String }`, but `Frontend` derives `Copy`; a `String`-carrying variant would force dropping `Copy` and ripple through every `Frontend` use. Instead:

```rust
// aitm-core (additive; Frontend stays Copy)
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frontend {
    Cli,
    Mcp,                 // retained: an agent over MCP
    Operator,            // a human surface over MCP (new)
}
```

The human-readable client label (from `initialize.clientInfo.name`, e.g. `aitm-mac`/`aitm-web`/`aitm-tui`) is carried for audit as an additive, optional field on `CommandHost` (`with_client_label(&str)`), not inside the enum. Policy and confirmation decisions key off the `Copy` role; only the audit log reads the label.

**Decision — thread the role through a per-connection context.** `handle` becomes connection-aware without changing the single-message contract: a small `ConnCtx { role: Frontend, client_label: Option<String>, out: NotificationSink }` is built once per connection by the transport (after auth) and passed into message handling (`handle_on(&self, conn: &ConnCtx, message) -> Option<String>`, with the old `handle` kept as a thin wrapper that builds a default agent `ConnCtx` for back-compat/tests). `call_tool` reads `conn.role` instead of hard-coding `Frontend::Mcp`, and builds the `CommandHost` with that role and the client label. `NotificationSink` is the push handle from D3.

### D2. Agent policy and the on/off toggle (F1, part 2)

**Decision — `AgentPolicy` enforced in the MCP server, read-only-ness declared by the command.**

```rust
// aitm-core (additive)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPolicy { All, ReadOnly, Paused }

pub trait Command {
    // … existing methods …
    /// Whether this command changes state. Default true: a command is mutating
    /// unless it declares otherwise, so the read-only set is opt-in and safe.
    fn mutates(&self) -> bool { true }
}
```

The read-only commands (`flow.list`, `flow.get`, `flow.detail`, `scope.list`, `ca.status`, `agent.status`, `proxy.status`, `config.get`, `poc.list`, `poc.get`, `browser.get_dom`, `browser.screenshot`) override `mutates()` to `false`. Enforcement lives in `call_tool`, **only for the agent role**:

- `conn.role == Operator` or `Cli` → policy does not apply (a human surface is never auto-paused; the operator *is* the control).
- `conn.role == Mcp` (agent) and `policy == Paused` → the call returns a tool error `"agent paused by operator"` before `invoke`.
- agent and `policy == ReadOnly` and `cmd.mutates()` → the same refusal.
- otherwise → proceed.

**Commands** (registered by a tiny first-party `AgentPlugin`, so they appear in `tools/list` like any other):

| Command | Params → result | mutates | Notes |
|---|---|---|---|
| `agent.status` | `{}` → `{policy, actions_last_minute, connected_clients: [{role, client, since}]}` | false | any role may read |
| `agent.set` | `{policy: "all"\|"readonly"\|"paused"}` → `{policy}` | true | **refused when `conn.role == Mcp`** — the agent cannot change its own policy; operator/CLI only |

`agent.set` carries no `confirm_prompt` for a human (the toggle is itself the deliberate act). The default policy for agent connections is `mcp.policy` (see Open questions for the default value).

### D3. Server push, subscriptions, and the agent/activity channel (F4 + F2)

**Problem (verified).** `serve_lines<R,W>` (`crates/aitm-mcp/src/transport.rs:23`) is a strict read→`handle`→write-one-reply loop; the server "never pushes." Loopback TCP already gives each connection its own task and its own `write_half` (`serve_connection`, `transport.rs:108`), so a per-connection writer exists; it is just only ever fed replies.

**Decision — split the connection's write side behind a sink; a subscription registry fans core events out to subscribed sinks.**

1. **Per-connection sink.** `serve_lines` is restructured so the write half is owned by a dedicated writer task draining a bounded `mpsc<String>` (`NotificationSink`). Both request replies and server-initiated notifications go through the sink, so writes are serialized per connection and the read loop never blocks on a slow socket. The sink is the `conn.out` carried in `ConnCtx` (D1).
2. **Subscription commands.**

   | Command | Params → result | mutates |
   |---|---|---|
   | `flow.subscribe` | `{filter?: FlowFilter, since?: FlowId}` → `{sub_id}` | false |
   | `flow.unsubscribe` | `{sub_id}` → `{}` | false |

   A subscription records `{sub_id, sink, filter}` in a server-side registry keyed by connection; dropping the connection drops its subscriptions. `since` replays the backlog of matching flows already in the store (the catch-up the UIs and a reconnecting agent need) before live events begin.
3. **Core event source — a first-party `SubscriptionPlugin` (Architect's call).** Rather than tapping the core from outside, a tiny plugin registered in the chain forwards lifecycle `Event`s to a `tokio::sync::broadcast`, keeping "everything is a plugin" true and leaving `aitm-core`'s event model untouched. The MCP server holds the broadcast receiver and a dispatcher task that, for each event, renders the matching `notifications/aitm/flow` line and pushes it to every subscription whose filter matches.
4. **The three streams** (shapes from foundation §4.4):
   - `notifications/aitm/flow` — `{event: created|request|response|ws_message|intercepted|released|killed|mutated|meta, id, summary}` (summary is the `flow.get` shape; full detail stays a `flow.detail` pull, F5).
   - `notifications/aitm/state` — `{listening, intercept_armed, paused, agent: all|readonly|paused, throughput}` on change.
   - `notifications/aitm/agent` — `{origin, command, args, result, at}` per invocation, sourced from the F2 audit ring (D3a, owned by M4).
5. **Backpressure / drop policy (decided).** Each `NotificationSink` is bounded (size a builder choice, e.g. a few thousand lines). On overflow the server **drops the oldest flow/state notifications for that connection and sets a `lagged` marker** delivered on the next successful write (`notifications/aitm/state {lagged: true}`), so a slow subscriber degrades to "catch up with `flow.list`/`since`" rather than growing core memory or blocking the data path. Replies to the subscriber's own requests are never dropped. The broadcast from the core uses a bounded ring; a lagged *dispatcher* likewise signals lag rather than blocking the plugin chain. This satisfies the bounded-memory constraint.
6. **Both transports.** Stdio gets the same sink/writer split (one connection). Loopback TCP already is per-connection. No network transport is added (F15 out of scope).

### D3a. The command-invocation audit ring and agent stream (F2)

F2 is the record behind the operator "Agent" page: who ran what, with what result, over the whole session. It is designed here with F1/F4 as one channel, and it is what the agent toggle and the activity log read.

1. **The ring (decided).** A bounded, in-memory ring on the core/server records one `AuditEntry { at, origin: Frontend, client_label, command, args_summary, result: ok|error }` per `invoke`, appended by `call_tool` (and by the CLI dispatch path) **after** the policy/confirm gates, so the ring reflects what actually ran and what was refused (a refusal is an entry with `result: error` and the reason). `args_summary` is a redacted, size-capped rendering — secrets (tokens, the CA key path content, auth headers) are never placed in the ring, consistent with the M2 CA posture. The ring is bounded (builder-chosen capacity) so it satisfies the bounded-memory constraint; it is the *live* view.
2. **Durable audit — generalize what the CA plugin already keeps.** The CA plugin already writes a fail-closed JSONL audit log; F2 generalizes that into a core audit sink so **every** command invocation (not just `ca.*`) can be appended as a JSONL line when a durable audit path is configured. The CA entries remain a subset; no second log format is introduced. Durable audit is opt-in by config; the in-memory ring is always on.
3. **The agent stream.** Each new ring entry is rendered as a `notifications/aitm/agent` line and pushed to subscribers through the same per-connection sink and backpressure policy as D3 (drop-oldest + `lagged`). The operator surfaces colour agent-origin entries (teal, per the UI foundation); the `origin`/`client_label` on each entry is exactly the F1 role + label, so the channel names who acted without the surfaces guessing.
4. **Query command.** `agent.activity {since?, limit?}` → `[AuditEntry]` (read-only, `mutates()==false`) lets a surface or a reconnecting agent catch up on recent activity without replaying the whole stream, mirroring `flow.subscribe {since}`.
5. **This is the audit that makes the live-agent run reviewable.** AC-M4-17's autonomous run is fully reconstructable after the fact from the ring/JSONL: every scope add, replay, mutate, PoC run, and refusal, in order, by origin.

### D4. Confirm-over-the-wire

**Problem (verified).** `Command::confirm_prompt(args) -> Option<String>` exists (`crates/aitm-core/src/command.rs:55`) and the CLI asks a human via a `Confirmer`, but the MCP path never surfaces it: the server built `Frontend::Mcp` and relied purely on config gates. So an **operator** surface on the bus had no way to satisfy a confirm (it would be silently treated as an agent), and the TUI panel observed that `ca.install` is reachable over the bus with no confirmation path at all until F1 exists.

**Decision — a two-phase confirm handshake for the operator role; the agent path is unchanged.**

- `tools/list` entries gain a static boolean **`confirmable`** (true iff the command ever returns a `confirm_prompt`), so a surface knows which commands may require a confirmation without calling them. (Additive to the MCP tool JSON; does not expose `confirm_prompt` logic itself.)
- When `conn.role == Operator` and `cmd.confirm_prompt(args)` is `Some(prompt)` and the call did **not** carry an acknowledgment, the server returns a structured, non-error tool result:

  ```json
  {"status":"needs_confirmation","prompt":"<the confirm_prompt text>","confirm_token":"<opaque, bound to {command,args,connection}>"}
  ```

  The surface shows `prompt` to the human; on approval it re-sends the identical call with `_confirm: "<confirm_token>"` in `arguments`. The server validates the token (same command + args + connection, short TTL, single use) and then runs `invoke`. The `_confirm` key is a reserved argument stripped before the typed `Params` are built, so it never reaches the command.
- When `conn.role == Mcp` (agent), `confirm_prompt` is **not** offered as a handshake. Confirm-gated commands remain governed by their own config gate exactly as today (e.g. `ca.install`/`ca.uninstall` require `ca.allow_agent_install`, else refused; the fail-closed JSONL audit still records the attempt). The agent can never self-confirm.
- `Cli` is unchanged (its `Confirmer` asks the local human).

This closes the hole: the operator path now has a real, auditable confirmation; the agent path cannot reach a confirm-gated capability except through its explicit config gate.

### D5. The seeded-vulnerable test target and grader

**Decision — build a hermetic Rust target crate, do not vendor (Architect's call).**

- **Build vs vendor.** Vendoring OWASP Juice Shop / DVWA / WebGoat pulls Node or PHP + a large, nondeterministic surface and an external toolchain, breaking the "runs inside `cargo test`, no external network, mac+Linux, no Docker" constraint. Instead M4 ships a small **`aitm-testtarget`** crate: an in-process `axum`/`hyper` app the test harness binds on loopback and the proxy MITMs like any other HTTPS origin. It is deterministic, seedable, and under our control, so the vuln set and the patched controls are exact. (This extends M1's bundled reflected-XSS vulnerable+patched pair to a multi-vuln site, as the platform roadmap anticipated.)
- **Vulnerability set (enumerated, each with a vulnerable path and a patched control path).** A small, high-signal set (**Architect's call** on the exact members; the builder may adjust within the classes):
  1. **Reflected XSS** — a search/echo endpoint reflecting a parameter unescaped.
  2. **Stored XSS** — a comment/guestbook store rendered unescaped to a later reader.
  3. **SSRF** — a "fetch preview" endpoint that server-side-requests a user URL (ties to the browser/SSRF-guard story; the control validates the host).
  4. **Broken access control / IDOR** — an object endpoint (`/account/{id}`) that does not check ownership; the control enforces it.
  5. **Auth bypass** — a logic flaw (e.g. a trust-the-client role header, or a predictable token), reproducible without credential theft; the control fixes it.
  6. **Open redirect** — a `?next=` redirect with no allowlist; the control allowlists.

  Plus several **benign decoy endpoints** (parameters that look injectable but are safe) so discovery is non-trivial and false positives are penalized.
- **Seeding and the manifest.** Each planted vuln is described in a `manifest` (a typed Rust table, also emitted as YAML for humans) with `{id, class, vulnerable_path, patched_path, trigger_hint, success_signal}`. **The manifest is consumed only by the grader; it is never served, never reachable over the proxy, and never handed to the agent or the scripted driver.** The app selects vulnerable vs patched behavior per-path from a seed/config the harness sets, so the same binary serves both the vulnerable origin and its patched control.
- **The grader.** A harness-side component that takes the agent's (or scripted driver's) produced findings — the PoC artifacts and the report index (D7) — and scores them against the manifest: a planted vuln counts as **found-and-reproduced** iff there is a PoC whose `poc.run` **passes against the vulnerable path and fails against the patched control**, matched to the planted vuln by endpoint + class (not by the agent naming an id it was given). The grader reports: planted vs found, reproduced count, and **false-positive PoCs** (a passing PoC not corresponding to any planted vuln, e.g. on a decoy). The gate threshold (how many of N, false-positive ceiling) is stated in the acceptance criteria.

### D6. Real browsers on a custom, non-system proxy

The e2e drives the target through real browsers, each pointed at aitmproxy as a **custom** upstream (never the OS proxy) and trusting the MITM CA through a per-browser mechanism. M2 already parametrizes **obscura** and **external Chrome** behind the `BrowserDriver` seam and `BrowserConfig.engine`; M4 adds **Firefox**.

- **obscura** (default) — `--ca-cert <path>` + `--proxy-server`, the M2 path, via the existing `BrowserDriver`. Ignores the OS store.
- **external Chrome** — launched with `--proxy-server=http://127.0.0.1:<port>` and CA trust via CDP `Security.setIgnoreCertificateErrors` (or `--ignore-certificate-errors`), as research 04 and M2 describe. The proxy is per-process, not the OS setting.
- **Firefox (new, Architect's call on how; additive engine).** Firefox ignores `--proxy-server` and the OS store; the driver therefore writes a **throwaway profile** whose `user.js` sets `network.proxy.type=1`, `network.proxy.http/ssl=127.0.0.1`, `network.proxy.http_port/ssl_port=<port>`, `network.proxy.allow_hijacking_localhost=true`, and trusts the CA either by `security.enterprise_roots.enabled` + an OS-store-free `certutil` import into that profile's `cert9.db`, or by a `policies.json` `Certificates.Install` entry pointing at the exported CA **cert file** (never the key). The profile is created in a temp dir and discarded after the run; the operator's real Firefox profile and OS store are untouched. Because Firefox's CDP support is partial, the M4 gate requires Firefox only for **capture-through-custom-proxy** (navigate → the page's requests appear as captured flows) and screenshot; full `eval`/DOM parity is a stretch, flagged, not gate-blocking. `BrowserConfig.engine` gains `firefox` and a `firefox` sub-config (binary path, timeouts), mirroring the `obscura` sub-config.
- **The invariant under test.** For every engine, the e2e asserts the target's requests land in the flow store as captured flows produced by that browser — proof that traffic went through aitmproxy's custom proxy, not around it. A negative check confirms no capture occurs when the browser is *not* pointed at the proxy (guarding against accidental OS-proxy routing).

### D7. The Claude agent driver surface

A committed Claude plugin / skill set (not Rust), the companion the M1 spec deferred. It lives in the repo (e.g. `agent/` with a `plugin.json`/`.mcp.json` wiring the loopback-TCP agent token, a `SKILL.md`, and per-phase skills) and is the only "intelligence" in the loop; everything it does is a call to a public command.

**The operating loop (observe → reason → act → reproduce → report):**

1. **Scope & arm.** The operator (or the harness) adds the target host to scope and sets `agent.set {all}`. The agent confirms via `agent.status` and `scope.list`. (The agent cannot widen scope itself unless `scope.allow_agent_widen` is set — it works within what the human authorized.)
2. **Observe.** The agent drives a browser (`browser.navigate`/`click`/`type`) to crawl the in-scope target and subscribes (`flow.subscribe`) to watch flows arrive; it pulls detail with `flow.detail` (F5) and marks interesting flows (`flow.mark`/`flow.comment`, F6) to build its working set. All passive — no gating.
3. **Reason.** From observed requests/responses it enumerates candidate injection/abuse points (parameters, headers, object ids, redirect targets) — strategy that lives in the skill, not the tool.
4. **Act (bounded).** It tests a candidate with the deterministic primitives — `flow.replay`, `flow.mutate`+`flow.resume`, `request.send`, or a `browser.*` action — each scope/rate/SSRF-gated by the core. It reads the result (`flow.detail`, `browser.eval`/`get_dom`, `browser.screenshot`) to judge whether the behavior is anomalous.
5. **Reproduce (the finding bar).** When the agent believes a candidate is a real vuln it calls `poc.build` to parameterize it, then `poc.run`. **A finding is "reproduced" iff `poc.run` returns `passed: true` and emits the three artifacts, and — where a control is available — the same PoC `poc.run`s against the patched path and returns `passed: false`.** This is the identical bar as M1 AC14, now reached by discovery rather than by a known target. `poc.run` is the terminal action for that candidate — the agent does not go further (anti-goal: no exploitation beyond proof).
6. **Report.** After the pass, the agent gathers artifacts via `poc.list`/`poc.get`/`poc.artifact` (F13) and writes the report (D8).

**Why this honors the split.** Every verb above is an existing/registered command; the agent adds no capability to the tool. Remove the agent and the same commands reproduce every finding deterministically (that is exactly what the scripted-driver gate proves). The agent supplies crawl strategy, candidate selection, payload choice, and triage — the intelligence the platform spec puts on the agent side.

### D8. Reporting contract

Consistent with the `poc.build`/`poc.run` three-artifact model (finding capture, replayable PoC YAML, screenshot). The **tool** produces those three per finding; the **agent** assembles them into a deliverable:

- **`report.md`** — human-friendly markdown: a title/summary, then one section per finding with `{title, severity, class/CWE, affected endpoint, reproduction steps, PoC path, screenshot (inline or linked), the finding-capture flow id}`. No tool-generated prose; the agent writes it.
- **`findings.index.json`** (or YAML) — a machine-readable index the grader consumes: a list of `{poc_path, target_path, class, passed, control_passed, finding_capture, screenshot_path}`. This is what lets the grader score discovery without the agent self-asserting against the manifest.

Both are written under the configured PoC/report out-dir; a remote surface reads the PoC artifacts through `poc.artifact` (F13). The report stays readable and editable by a human, who is the final reviewer.

### D9. Safety and capability model (how deny-by-default extends)

- **New commands behind the guards.** `agent.status`/`flow.subscribe`/`flow.unsubscribe` are read-only (`mutates()==false`), observation-only, and leak nothing an operator surface cannot already see; they are still subject to the policy gate for an agent (read-only commands pass `ReadOnly`, all are blocked under `Paused`). `agent.set` is mutating and **operator/CLI-only** (refused for the agent role).
- **The agent cannot escalate.** It cannot un-pause itself (`agent.set` refused for `Mcp`), cannot self-confirm (D4), cannot widen scope without `scope.allow_agent_widen`, cannot install the CA without `ca.allow_agent_install`. All active actions pass `ScopeRateGuard::check_active` and the browser SSRF guard unchanged.
- **Reproduction-only boundary.** The skill set's act phase is bounded to tests that prove a finding and stops at `poc.run`; there is no "exploit"/"pivot"/"exfiltrate" skill. The seeded target's success signals are markers (a reflected token, a stored marker, an SSRF callback to an in-scope sink), not real secrets, so even a passing PoC proves reproduction without taking data.
- **Push respects observation semantics.** Subscriptions deliver flow lifecycle events (passive capture, already allowed); they do not perform or authorize any active action, and the backpressure policy (D3) bounds their cost.
- **Audit.** Every invocation from every role is recorded (F2 ring + the generalized JSONL audit the CA plugin keeps), surfaced as `notifications/aitm/agent` and the UIs' activity log. The live-agent run is fully auditable after the fact.

## Acceptance criteria

Verification is **TDD unit tests AND functional/behavioral tests that drive the real tool**, per the platform's milestone-gate philosophy. The **deterministic functional gate** is AC-M4-13..16 (scripted-driver e2e + grader through real browsers); the **live-agent acceptance** is AC-M4-17. All run on macOS + Linux through `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` except AC-M4-17 (live model, operator-run).

**F1 — identity & policy**

1. **AC-M4-1 — token class sets role:** a loopback-TCP connection presenting `operator_token` is treated as `Frontend::Operator`; one presenting `agent_token` as `Frontend::Mcp`; an unknown token is refused `-32001`. Asserted via a command whose behavior differs by role.
2. **AC-M4-2 — `call_tool` no longer hard-codes the frontend:** an operator-role connection invoking a `confirm_prompt`-bearing command gets the confirmation handshake (AC-M4-7), proving the role is read from the connection, not hard-coded.
3. **AC-M4-3 — `mutates()` default & read-only set:** `Command::mutates()` defaults to `true`; the declared read-only commands return `false`. Asserted by iterating the registry.
4. **AC-M4-4 — policy enforcement for the agent:** with `policy==Paused`, every agent `tools/call` returns the paused tool error; with `ReadOnly`, a mutating command is refused and a read-only one succeeds; with `All`, both succeed. An **operator** connection is unaffected by policy in all three states.
5. **AC-M4-5 — `agent.status`/`agent.set`:** `agent.status` returns the current policy and connected clients; `agent.set` changes it; `agent.set` is **refused when called over the agent role** and succeeds over operator/CLI.

**F4 + F2 — push & audit**

6. **AC-M4-6 — subscribe & push:** after `flow.subscribe`, a new flow through the proxy produces a `notifications/aitm/flow {event:created,…}` line on that connection without any further request; `flow.unsubscribe` stops it; the `state` stream emits on change. A bounded-sink overflow sets `lagged` rather than growing memory or blocking the proxy (asserted with a deliberately slow reader).
7. **AC-M4-6b — audit ring & agent stream (F2):** every `invoke` from any role appends one redacted `AuditEntry` to the ring (including refusals, with the reason); `agent.activity {since?, limit?}` returns recent entries; a subscriber receives each new entry as a `notifications/aitm/agent` line carrying the F1 `origin`/`client_label`; secrets never appear in `args_summary`. With a durable audit path configured, the same entries are appended as JSONL (the CA log a subset of it).

**Confirm-over-the-wire**

7. **AC-M4-7 — operator confirm handshake:** an operator-role call to a confirm-gated command (e.g. `ca.install`) returns `needs_confirmation` with a prompt and token; re-sending with the matching `_confirm` token runs it; a wrong/expired/replayed token is refused.
8. **AC-M4-8 — agent cannot self-confirm:** an agent-role call to `ca.install` with `ca.allow_agent_install` unset is refused (no handshake offered); with it set, it runs and is audited. `tools/list` marks the command `confirmable`.

**Seeded target & grader**

9. **AC-M4-9 — hermetic multi-vuln target:** the target crate serves all enumerated vulnerable paths and their patched controls over HTTPS on loopback with no external network, on mac+Linux, inside `cargo test`.
10. **AC-M4-10 — manifest is grader-only:** a test asserts the planted-vuln manifest is not reachable over the proxy and is not an input to the driver/agent (only the grader reads it).
11. **AC-M4-11 — grader scores against controls:** given a set of PoCs, the grader counts a vuln found-and-reproduced iff its PoC passes on the vulnerable path and fails on the patched control, and counts PoCs on decoys/non-planted paths as false positives.

**Real browsers on a custom proxy**

12. **AC-M4-12 — custom-proxy capture per engine:** navigating the target through **obscura**, **external Chrome**, and **Firefox** (each pointed at aitmproxy as a custom upstream, trusting the CA per-browser) yields that page's requests as captured flows; a negative check confirms no capture when the browser is not pointed at the proxy. (Firefox gate: capture + screenshot; eval/DOM parity is a flagged stretch.)

**Deterministic end-to-end (the functional gate)**

13. **AC-M4-13 — scripted driver finds via observation:** a scripted driver using only public commands (no manifest access) crawls the target through a real browser, enumerates candidates from `flow.detail`, and tests them.
14. **AC-M4-14 — scripted driver reproduces:** for each discovered vuln the driver `poc.build`s and `poc.run`s a PoC that passes on the vulnerable path and fails on the patched control, emitting the three artifacts.
15. **AC-M4-15 — scripted driver reports:** the driver writes `report.md` + `findings.index.json` in the D8 contract, gathering artifacts via F13.
16. **AC-M4-16 — grader gate green:** the grader confirms the scripted driver found-and-reproduced **all** enumerated vulns with **zero** false-positive PoCs. This is the deterministic exit gate.

**Live-agent acceptance (the product-thesis proof, operator-run)**

17. **AC-M4-17 — a Claude agent, unaided, finds & reports:** using the committed plugin/skill set over the MCP bus (agent token, `policy==All`), with only the target host in scope and no manifest access, a live Claude agent drives the loop and the grader confirms it found-and-reproduced at least the agreed threshold of the enumerated vulns and produced the report. Operator-run and signed off (a demo-grade gate, not CI), because it needs a live model.

**Gate**

18. **AC-M4-18 — Rust gate green:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` passes for the workspace; `unsafe` (if any) carries a `// SAFETY:` note and a security-reviewer sign-off.
19. **AC-M4-19 — core untouched beyond the additive surface:** a diff check confirms M4 changed only the command/registry/transport/config layer and added crates; the `Flow`/`Event` enums and the `ProtocolModule`/protocol crates are unchanged.

## Left to the builder

- Exact members of the vulnerability set within the named classes, the decoy endpoints, the success-signal markers, and the target's internal layout (framework handlers, templating), so long as each class has a vulnerable path + a patched control and AC-M4-9..11 hold.
- The scripted driver's candidate-enumeration and payload lists (it must discover from traffic, not the manifest), and the live threshold number in AC-M4-17 (proposed in Open questions, confirmed with Matt).
- The subscription registry's internal structure, the exact sink bound and drop granularity, and whether the core event broadcast is one channel or several (so long as D3's backpressure guarantees hold).
- The `confirm_token` encoding and TTL, and the reserved `_confirm` argument name, consistent with D4.
- The Firefox trust mechanism choice (`certutil` into the throwaway profile vs `policies.json`), and the per-engine launch details, consistent with D6.
- The plugin/skill-set file layout, skill wording, and MCP wiring, consistent with the D7 loop and the human-friendly constraint.
- Whether stdio defaults to agent or exposes `mcp.stdio_role`, and the config key names, consistent with D1.

## Open questions

Only Matt can answer these; kept to the few that are genuinely his call.

1. **Agent-policy default (`mcp.policy`).** `All` (the agent acts freely the moment it connects, until an operator pauses it) or `ReadOnly` (it observes until a human promotes it)?
   - **`All` — recommended (Architect's call pending Matt).** M4's whole premise is autonomous agent-driven testing, the toggle is one action away, and every active action is still deny-by-default scope + rate + SSRF gated and fully audited, so "free" never means "unbounded" or "out of scope." The live-agent acceptance (AC-M4-17) sets the policy explicitly regardless, so the default does not affect the gate — only the out-of-the-box posture for real use.
   - **`ReadOnly` — the safer default** if you want a human to deliberately arm the agent every session; costs one `agent.set {all}` at the start of each run and makes "nothing acts until I say so" the default story.
   I lean **`All`**, but this is the one posture call I'm flagging for you.

2. **Milestone numbering.** This spec claims **M4 = the agent-driven real-test milestone** and treats **raw-L4/packet MITM as M5**, per this session's brief; the sibling L4 spec's working note currently labels L4 "M4." Please confirm the numbering so the two specs don't collide (a hand-over note has been left for the L4 session either way).

3. **Live-agent threshold (AC-M4-17).** Must the live agent find **all** enumerated vulns to pass, or a stated majority (e.g. ≥ N of 6) with zero false positives? The deterministic gate (AC-M4-16) already requires *all* with zero false positives from the scripted driver; the live-agent bar can be the same or a notch lower given model variance. I propose **≥ all-but-one with zero false positives**, but it's your call what "the thesis is proven" means.

---

### Architect's calls (recorded)

1. **M4 owns F1 + F2 + F4 + confirm-over-the-wire** as one coherent operator/agent-channel story (core/transport work); **F5/F6/F7/F12/F13 are referenced dependencies** built elsewhere. The plan declares those referenced ones as prerequisites and blocks dependent ACs rather than re-implementing.
11. **F2 audit ring is owned by M4:** a bounded in-memory ring appended after the policy/confirm gates (refusals included), secrets redacted, feeding `notifications/aitm/agent` + `agent.activity`; the CA plugin's JSONL log is generalized into a core audit sink (a superset, one format), durable audit opt-in. It is what makes the live-agent run (AC-M4-17) reviewable.
12. **Verified live-wire shapes are ground truth over the (stale) foundation doc:** `browser.eval` uses `expr`; `browser.click` x/y-or-selector; `browser.type` requires a selector (`":focus"`); `poc.build` returns YAML text; `ca.status` reports `yes|no|unknown`. The agent skill set is written to these.
2. **`Frontend` stays `Copy`:** add a unit `Operator` role; carry the client label separately on `CommandHost` (refines the blocker note's `Operator { client: String }`).
3. **Connection role = token class presented** (`agent_token` vs `operator_token`); stdio defaults to the agent role (overridable). A per-connection `ConnCtx` threads role + client label + the push sink into message handling; the old `handle` stays as a back-compat wrapper.
4. **`AgentPolicy { All, ReadOnly, Paused }` enforced in `call_tool` for the agent role only**, with read-only-ness declared by `Command::mutates()` (default true). `agent.set` is operator/CLI-only.
5. **Push via a first-party `SubscriptionPlugin` → broadcast → per-connection bounded sink**, with an explicit drop-oldest + `lagged`-marker backpressure policy; no network transport added.
6. **Two-phase confirm handshake for operators** (`needs_confirmation` + `confirm_token`, reserved `_confirm` arg); the agent path keeps config-gate-only, closing the `ca.install` hole.
7. **Build a hermetic Rust `aitm-testtarget` crate, do not vendor** Juice Shop/DVWA; multi-vuln (reflected/stored XSS, SSRF, IDOR, auth bypass, open redirect) + patched controls + decoys; a **grader** scores against a manifest the agent never sees.
8. **Firefox added as an additive `BrowserConfig.engine`** using a throwaway profile's proxy prefs + per-profile CA trust (never the OS store); its M4 gate is capture + screenshot, eval/DOM parity flagged as a stretch.
9. **The agent driver is a committed Claude plugin/skill set**, not Rust; `poc.run` pass (+ control fail) is the reproduction bar and the terminal action; the report is the agent's markdown + a machine index for the grader.
10. **Two-tier exit gate:** a deterministic scripted-driver e2e + grader (AC-M4-16, the CI gate) and a live-agent acceptance (AC-M4-17, the product-thesis proof, operator-run).
