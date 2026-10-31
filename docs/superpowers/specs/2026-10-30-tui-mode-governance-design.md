# `aitm tui` agent governance design

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's autonomous-approve mode, per the lead session's brief)
**Research inputs:** sibling spec `docs/superpowers/specs/2026-10-30-web-bus-agent-governance-design.md` (Design 3, 4, 6, 7, 8) and its plan; code reading on `bd0f9b7` of `crates/aitm/src/{tui,main,wire,config_file}.rs`, `crates/aitm-mcp/src/server.rs` (`McpServer::new`, `serve`, `run_tool`, `policy_decision`, `read_refusal`, `park_for_approval`, `handle_approve`, `handle_subscription`, `record_audit`), `crates/aitm-plugins/src/agent.rs`, `crates/aitm-core/src/audit.rs`, `crates/aitm-tui/src/{bus,app}.rs`, and every caller of `tui::{build_servers, run, server, services}`.

## Intent

In `aitm tui` the operator's emergency stop fails open. The loopback (or
streamable-HTTP) **agent** server that `tui::build_servers` builds has the wrong
policy state and the wrong audit ring. `agent.set paused` from the TUI is reported
but not enforced, and the agent's calls never show in `agent.activity`. This change
puts that server on the core's own state and ring through the existing
`tui::with_shared_governance`. A sealed `Governance` value, required by
`build_servers` and `tui::run`, makes TUI mode impossible to wire without them.

## Goals

- A live `agent.set` governs the TUI-mode loopback agent on its next call, with no
  reconnect. It can come from the TUI itself or from any operator-token client.
- `agent.status.policy` equals what that agent's gate enforces.
- Each of that agent's calls, allowed or refused, appears in `agent.activity` with
  origin `"mcp"` and is counted in `actions_last_minute`.
- In TUI mode, leaving governance out is a compile error. `main.rs` cannot hand in
  a fresh state instead of the core's.
- The TUI's own in-process operator server stays ungated and stays out of the
  shared ring.

## Non-goals

These are named follow-ups or explicitly out of scope:

- **Feeding `push_tx`** to the TUI-mode agent server (Design 4). Follow-up
  "tui-mode push".
- **Approving parked calls from the TUI's own UI** (Design 5.4). Part of
  "unified agent hub".
- **Auditing the TUI's own operator calls** (Design 5.5). Part of
  "audit signal-to-noise".
- **A `mcp.policy` config key, env var, or flag** (Design 3). Follow-up
  "configurable startup policy".
- **Anything PR 145 owns:** the bare-`aitm` and `aitm web` wiring (the `else`
  branch of `main.rs`, `src/web/`), `with_shared_governance`, and the signatures of
  `services()` and `server()`.
- **Edits in other crates:** nothing under `crates/aitm-mcp`, `aitm-core`,
  `aitm-tui`, or `aitm-bus-client`.

## Anti-goals

- **A snapshot fix**, meaning any fresh `AgentState` seeded from config. It passes a
  "starts readonly" test and still ignores `agent.set`. AC1 fails it, and the
  sealed type makes it a compile error in `main.rs`.
- **An optional or defaulted parameter**, such as `Option<Governance>` or a second
  convenience `build_servers`. Either brings the omission back.
- **Gating or auditing the TUI's in-process operator server.** Gating would lock
  the operator out of their own UI. Auditing would flood the shared ring
  (Design 2).
- **A rig that hand-builds the agent server.** It would stay green while
  `build_servers` drifts.

## Constraints

- **Files.** Edits stay in `crates/aitm`: `src/{tui,wire,main}.rs`,
  `tests/support/mod.rs`, the call sites in `tests/{tui_embed,tui_live_bus,l4_cua_tui}.rs`,
  and two new test files.
- **`main.rs` scope.** It changes only where it binds `Assembled` (to call
  `.governance()` before destructuring) and in the `Mode::Tui` branch (one
  argument and a comment).
- **Fail closed.** The gate, `read_refusal`, and the trusted-control bypass are
  untouched. Only which `AgentState` and `AuditRing` they read changes. The hot
  path stays at one atomic load and one ring append per call.
- **No new dependencies, no `unsafe`.**
- **Test placement.** `aitm-core`'s `trust_gate_scan` rejects comparisons of the
  form `== Frontend::Mcp` in any `crates/*/src` file, including `#[cfg(test)]`
  code. New tests therefore live in `crates/aitm/tests/`.
- **Where tests run.** In-process tests and doctests run in the sandbox. AC7,
  `tui_live_bus`, and `l4_cua_tui` bind sockets and skip on `PermissionDenied`.
  Their evidence is a Terminal-panel run with no skip note in the output.

## Design

### 1. The defect, re-verified on `bd0f9b7`

**Where the two `Arc`s come from.** `wire.rs` `assemble_with_scripts` creates
`AgentState::new(cfg.mcp.policy)` and `AuditRing::default()`, gives both to
`AgentPlugin::new(..).with_audit_ring(..)`, and returns them in `Assembled`.

**Who reads and writes them.**

- `agent.set` writes the plugin's state.
- `agent.status` reads that state, plus `count_since(now - 60 s)` over all origins.
- `agent.activity` reads the plugin's ring.
- On the server side (`server.rs`), `policy_decision` and `read_refusal` read
  `self.agent_state`, and `record_audit` appends to `self.audit_ring`.
  `McpServer::new` defaults both to private instances.

**What TUI mode actually wires.** The agent arm of `build_servers` calls
`.with_agent_state(Arc::new(AgentState::new(cfg.mcp.policy)))` and then
`.with_mcp_roles(..)`. It never calls `.with_audit_ring` or `.with_push`.
`main.rs` destructures `agent_state`, `push_tx`, and `audit_ring`, but its
`Mode::Tui` branch calls
`tui::run(&cfg, &proxy, services, proxy_listener, browser_listener)` and uses
none of them. `serve()` rebuilds the server and carries `agent_state` and
`audit_ring` across unchanged, so what `build_servers` attaches is what gets
served.

**What the operator sees.** The TUI polls `agent.status` every 3 s, so it shows
`paused` while the agent keeps running at the seeded policy.

### 2. Shape: a sealed `Governance`, required by `build_servers` and `tui::run` (Architect's call)

**Decided.** In `wire.rs`, beside `Assembled`:

- `pub struct Governance` holds `agent_state: Arc<AgentState>` and
  `audit_ring: Arc<AuditRing>`. Both fields are `pub(crate)`. It derives `Clone`
  and has no public constructor and no public accessors.
- `impl Assembled { pub fn governance(&self) -> Governance }` clones the two `Arc`s
  and is the only public source of a `Governance`.

`tui::build_servers(cfg: &Config, services: Services, governance: Governance) -> (Option<McpServer>, InProcessHandler)`
builds its agent arm as
`with_shared_governance(server(cfg, cfg.mcp.transport.clone(), &services), &governance.agent_state, &governance.audit_ring)`
followed by the existing `.with_mcp_roles(..)`. Its TUI-facing arm is unchanged.

`tui::run(cfg: &Config, proxy: &Proxy, services: Services, governance: Governance, main_listener: TcpListener, browser_listener: TcpListener) -> anyhow::Result<()>`
passes `governance` through to `build_servers`.

`main.rs` binds the `assemble_with_scripts` result, calls `.governance()`,
destructures as today, and passes `governance` to `tui::run`. `main.rs` is a
separate binary crate, so it has no other way to obtain a `Governance`.

| Shape | Omission a compile error? | Callers that change | TUI operator server |
|---|---|---|---|
| Fields on `Services`, applied by `server()` | yes, every server | every `services()` caller: `main.rs` x2 (one is the CLI path, which builds no server), `support/mod.rs`, `discover_e2e`, `l4_cua_tui`, PR 145's `web_bus_governance` / `web_bus_ask_split`, `tui.rs` tests | governed and audited by construction unless `server()` branches |
| Required params of `tui::server` | yes, every server | `main.rs` x2, `web_bus_governance`, `web_bus_ask_split`, `discover_e2e`, `tui.rs` tests x2, `build_servers` x2; `with_shared_governance` becomes redundant | must take them too, or needs a second builder |
| **Sealed `Governance` on `build_servers` + `run`** | **yes in TUI mode; `main.rs` cannot forge one** | `tui.rs` (2 fns), `main.rs` (1 call), `support/mod.rs` (1 fn), `tui_embed` x2, `tui_live_bus` x1, `l4_cua_tui` x1 | untouched |

Why this shape:

- **Smallest change that makes the omission a compile error.** The other two shapes
  rewrite `services()` or `server()` and touch every caller, including PR 145's
  files.
- **Leaves PR 145's surface untouched.** `services()`, `server()`,
  `with_shared_governance`, and every PR 145 file stay as they are.
- **Sealing closes the snapshot fix.** With no public constructor, the snapshot
  anti-goal becomes a compile error in `main.rs`.

**The operator server stays ungoverned, deliberately.** It is still built by
`server()` alone, so it keeps `McpServer::new`'s private state and ring.

- **The state is irrelevant.** As `Frontend::Operator` it bypasses the gate by
  role, so its private state is never read.
- **The ring would be noise.** Reading `aitm-tui/src/bus.rs`, the TUI calls
  `flow.list` every 500 ms, plus five panel reads (`scope.list`, `agent.status`,
  `poc.list`, `findings.list`, `proxy.status`) every 3 s. That is about 220 calls
  a minute at idle, plus a `flow.get` for each unsettled flow.
- **What auditing it would cost.** The 4096-entry ring would turn over in about
  19 minutes. The TUI's own Agent panel would show `actions_last_minute` ≥ 220 with
  no agent connected.

The split between the two arms lives in one function. AC5 and AC6 pin it; the
types do not.

**What this still cannot force:**

1. **Correct use inside `build_servers`.** An unused parameter trips
   `unused_variables` under `-D warnings`, but not if it is renamed `_governance`.
   AC1, AC5, AC7, and AC9 prove the wiring.
2. **Servers built outside `build_servers`.** The bare path relies on
   `with_shared_governance` by convention. That is PR 145's residual risk, not
   reopened here.
3. **Minting inside the library.** Lib-internal code can still create a
   `Governance` through `pub(crate)`. And because `Assembled`'s two fields stay
   `pub`, a hand-built server can still be given a fresh state.
4. **Push.**

### 3. Seeded policy (Architect's call: no observable change)

Today the plugin's state (`wire.rs`) and the gate's state (`build_servers`) are
both seeded with `AgentState::new(cfg.mcp.policy)`. They agree until the first
`agent.set`, so startup behaviour is identical under every seed. After the fix
there is a single object.

There is still no way to set the policy outside code. `config_file.rs` `McpFile`
is `#[serde(deny_unknown_fields)]` with only `transport`, `operator_token`, and
`stdio_role`, and there is no `mcp.policy` key, env var, or flag. Production
`aitm tui` therefore starts at `auto`, and only a live `agent.set` changes it.
Tests seed by setting `Config.mcp.policy` before `assemble`; `Paused` is legal
there.

### 4. Push stays unfed (Architect's call: not a governance dependency)

Governance works without `push_tx`:

- `record_audit` pushes `notifications/aitm/agent` through the server's own
  `subscriptions.fanout_state`.
- `park_for_approval` uses `subscriptions.any_role(Operator)` and `fanout_role`.
- `spawn_push_dispatcher` returns early when there is no `push_tx`.

The missing `.with_push(push_tx)` only means that a loopback subscriber on
`aitm tui` receives audit and approval lines but no `notifications/aitm/flow`.
That is follow-up "tui-mode push"; the `main.rs` comment says so.

### 5. Operational consequences in `aitm tui` (the PR description repeats them)

1. **Under the default `auto`, enforcement is unchanged.** Same seed, same gate.
   The visible change is that the TUI Agent panel's `actions_last_minute` and
   `agent.activity` now show the loopback agent's calls. Today they always show
   zero.
2. **`agent.set` now governs the loopback agent, in both directions.**
   - `paused` refuses every agent tool call with "the agent policy is `paused`".
     `initialize`, `tools/list`, and `ping` still answer.
   - `readonly` allows Read only.
   - `all` relaxes the agent; per-command gates such as `scope.allow_agent_widen`
     still apply.
3. **While the agent is paused, the operator keeps full control.**
   - The TUI is `Frontend::Operator`. It can intercept, mutate, kill, replay, run
     `scope.add`, and `agent.set` back. Operator-token loopback clients can too.
   - `paused` does not revoke standing subscriptions or already-parked requests.
     That is pre-existing on every surface (PR 145 Review log) and unchanged here.
4. **Under `ask`, only an operator on the same server can approve.**
   - **Who can.** A loopback agent's Sensitive call parks only if an
     operator-token client is connected to that same server and has
     `flow.subscribe`d. That client receives `approval_requested` and answers with
     `agent.approve`.
   - **The TUI cannot.** Its in-process server is a different `McpServer`, and the
     Ask machinery is per server (sibling Design 4). Its `ConnCtx` has no push
     sink, so `flow.subscribe` is refused ("only meaningful over a streaming MCP
     connection"). Its `agent.approve` finds "no parked request". `aitm-tui` has
     no approval action either.
   - **So, with only the TUI attached,** `ask` refuses every agent Sensitive call
     at once with "no operator is connected to approve it". It never parks and
     never waits out the 120 s approval timeout.
   - **This is a behaviour change.** Today this server can never park.
   - **Architect's call: accepted.** It fails closed. The positive path is the
     generic per-server machinery that `web_bus_ask_split` already pins on a server
     built through the same `with_shared_governance`. TUI approval routing belongs
     to "unified agent hub".
5. **The TUI's own operator actions stay out of `agent.activity`, as today.**
   Operator-token loopback clients *are* recorded, with origin `"operator"`,
   because the agent-facing server records every call. That asymmetry is accepted
   and filed under "audit signal-to-noise".
6. **No new bound is needed.** Parking stays capped at 64 per server
   (`MAX_PARKED_REQUESTS`) plus the approval timeout, as on the primary.

### 6. Tests drive the production `build_servers`

**Rig.** Set up a loopback-TCP transport (port 0) and an `operator_token`, and set
`cfg.mcp.policy` when seeding. Then build through the production path:

1. `aitm::wire::assemble(&cfg)` gives `assembled`. Keep it alive for the whole
   test.
2. `assembled.governance()`.
3. `tui::services(&assembled.proxy, &cfg, None, TuiLog::Off)`.
4. `tui::build_servers(&cfg, services, governance)`, which yields
   `(Some(agent), handler)`.

Agent calls go through `agent.handle_on(&ConnCtx::new(Frontend::Mcp), line)`. TUI
calls go through `handler(line)`, the TUI's real in-process path.

Probe commands:

- Read: `flow.list`, `agent.status`.
- Write: `flow.kill`.
- Sensitive: `scope.add`.

Refused probes need no arguments, because the gate runs before
`params_from_json`. A call that may park gets `scope.add {host: "example.com"}`.

**Layout (Architect's call):**

- `crates/aitm/tests/tui_mode_governance.rs`: in-process, AC1-AC6, sandbox.
- `crates/aitm/tests/tui_mode_governance_live.rs`: AC7 only, in the style of
  `tui_live_bus.rs`, Terminal panel.
- A `compile_fail` doctest and a compiling companion on `Governance` in `wire.rs`
  (AC8).

**Red/green.** The mutation point is in production code.

1. Land the new signatures with today's agent arm, binding the parameter as
   `_governance`. Run: this is the red run.
2. Switch the arm to `with_shared_governance`. Run: this is the green run.

The red set is AC1, AC2, AC5, and AC7. The guards, which pass either way, are AC3
(the seed carries over), AC4 (default `auto`), and AC6 (the operator is ungated,
unrecorded, and cannot approve).

## Acceptance criteria

Legend:

- `[in-process]` runs in the sandbox. `[socket]` runs in the Terminal panel only.
- "TUI" is the `InProcessHandler` returned by `build_servers`.
- "Agent" is that call's agent server, called as `Frontend::Mcp`.
- Every text check is a `contains`.

1. **AC1** `[in-process]` **Live pause from the TUI.** Default seed.
   - Agent `flow.list` → `isError: false`.
   - TUI `agent.set {policy: "paused"}` → `structuredContent.policy == "paused"`.
   - On the same agent `ConnCtx`, `flow.list`, `agent.status`, and
     `flow.subscribe {}` each → `isError: true` with "the agent policy is
     `paused`".
   - TUI `agent.status.policy == "paused"`.
   - TUI `agent.set {policy: "auto"}`, then agent `flow.list` → `isError: false`.
2. **AC2** `[in-process]` **Live readonly and ask.**
   - After TUI `agent.set readonly`: agent `flow.list` → `isError: false`. Agent
     `flow.kill` → `isError: true` with "`flow.kill` refused" and "the agent policy
     is `readonly`".
   - After TUI `agent.set ask`: agent `scope.add {host: "example.com"}` returns
     within 5 s → `isError: true` with "no operator is connected to approve it".
3. **AC3** `[in-process]` guard. **Seed carries over.**
   - With `cfg.mcp.policy = ReadOnly`: the agent's first call, `flow.kill`, is
     refused with "the agent policy is `readonly`". TUI
     `agent.status.policy == "readonly"`.
   - With `cfg.mcp.policy = Ask`: agent `scope.add {host: "example.com"}` returns
     within 5 s with "no operator is connected to approve it". TUI
     `agent.status.policy == "ask"`.
4. **AC4** `[in-process]` guard. **Default `auto` unchanged.**
   - Agent `flow.list` → `isError: false`.
   - Agent `scope.add` → `isError: true` with "the agent policy is `auto`".
   - TUI `agent.status.policy == "auto"`.
5. **AC5** `[in-process]` **One audit trail.** Seeded `ReadOnly`, fresh rig.
   - Agent `agent.status` → `isError: false`, then agent `flow.kill` →
     `isError: true`.
   - The TUI's first call, `agent.status`, gives `actions_last_minute == 2`.
   - The TUI's next call, `agent.activity`, returns exactly 2 rows:
     - `[0]` = {`origin "mcp"`, `command "agent.status"`, `result "ok"`}
     - `[1]` = {`origin "mcp"`, `command "flow.kill"`, `result.error` containing
       "readonly"}
   - Then `assembled.audit_ring.len() == 2`.
   - The audit assertions run first, so the red cause is the count (`0` where `2`
     is expected).
6. **AC6** `[in-process]` guard. **The TUI operator surface.** Seeded `Paused`.
   - TUI `flow.list` → `isError: false`, `structuredContent == []`.
   - TUI `agent.status.policy == "paused"`.
   - TUI `flow.intercept {enabled: true}` → `isError: false`,
     `structuredContent.enabled == true`.
   - TUI `flow.subscribe {}` → `isError: true` with "only meaningful over a
     streaming MCP connection".
   - TUI `agent.approve {request_id: "apr_none", allow: true}` → `isError: true`
     with "no parked request".
   - Afterwards `assembled.audit_ring.len() == 0`.
7. **AC7** `[socket]` **Real loopback, no reconnect.** The `build_servers` agent
   server is run with `serve()` on `127.0.0.1:0`.
   - On one agent-token TCP connection, `initialize` echoes `role "agent"` and
     `flow.list` → `isError: false`.
   - TUI `agent.set paused`.
   - The same connection's next `flow.list` → `isError: true` with "the agent
     policy is `paused`".
   - TUI `agent.activity` rows `[0]` and `[1]` are `origin "mcp"`,
     `command "flow.list"`, with results `"ok"` and then `error` containing
     "paused".
   - The test output contains no skip note.
8. **AC8** `[compile]` **Shape.**
   - The Design 2 signatures hold, and every listed caller is migrated.
   - `Governance` has no public field, constructor, or accessor.
   - A `compile_fail` doctest builds `Governance` with a struct literal from outside
     the crate.
   - A companion doctest with the same imports compiles
     `assemble(..)?.governance()` passed into `build_servers`.
   - `cargo test -p aitm --doc` shows both as `ok`.
9. **AC9** **Mutation check.**
   - Revert the agent arm to today's
     `.with_agent_state(Arc::new(AgentState::new(cfg.mcp.policy)))`: no ring, and
     the parameter becomes `_governance`.
   - AC1, AC2, AC5, and AC7 must then fail on a policy or audit assertion, not on a
     compile, connect, or rig error.
   - AC3, AC4, and AC6 must still pass.
   - Both runs go in the report. The revert is not committed.
10. **AC10** **Docs stop lying.**
    - Each of these greps prints nothing:
      `grep -n "Not yet on" crates/aitm/src/tui.rs`,
      `grep -n "does not use it yet" crates/aitm/src/tui.rs`, and
      `grep -rn "tui-mode governance" crates/aitm/src`.
    - Review-checked in `tui.rs`: the module doc, the `server()` doc, the
      `build_servers` doc and its agent-arm comment, and the `run` doc state
      Design 2.
    - The `with_shared_governance` doc names `build_servers` as a caller and says
      TUI mode is compile-enforced while the bare path is by convention.
    - The `Assembled::agent_state` and `audit_ring` docs name the `aitm tui` agent
      server and `Assembled::governance`.
    - The `Mode::Tui` branch of `main.rs` has a comment naming the shared governance
      and the unfed `push_tx`.
    - PR 145's `else`-branch comment is unchanged.
11. **AC11** **Nothing else moves.**
    - `tui_embed` (3 tests), `tui_live_bus`, and `l4_cua_tui` pass with only
      call-site or rig lines changed and no assertion edited.
    - `support::assemble_services` returns `(Proxy, Services, Governance)`.
    - These files are unmodified and pass: `web_bus_governance.rs`,
      `web_bus_ask_split.rs`, `web_bus_roles.rs`, `web_bus_concurrency.rs`,
      `web_bus_push.rs`, and `discover_e2e.rs`.
    - The existing `tui.rs` unit tests and `with_shared_governance` are unchanged.
12. **AC12** **Gate and diff.**
    - The Rust gate passes on a full Terminal-panel run.
    - `git diff --stat bd0f9b7..HEAD -- crates/aitm-mcp crates/aitm-core crates/aitm-tui crates/aitm-bus-client crates/aitm/src/web`
      prints nothing.

## Left to the builder

- **Governance fields.** Either `pub(crate)` fields or `pub(crate)` accessors.
  Nothing may be public except the type, its `Clone`, and `Assembled::governance`.
- **The AC7 agent client.** Raw `tokio` TCP with the token line, or
  `aitm_bus_client`.
- **The 5 s bound in AC2 and AC3.** For example, a thread plus `recv_timeout`. The
  panic message should say the call parked.
- **JSON-RPC helpers.** Copy them into each file (house style), or put them in a
  **new** `tests/support/` file. `support/mod.rs` changes only in
  `assemble_services`.
- **Wording.** Doc and PR text, as long as all six consequences in Design 5 are
  stated.

## Open questions

None. Every fork is decided as an Architect's call below and can be corrected at
approval.

## Summary and calls for approval

In `aitm tui`, the loopback agent server runs on a fresh `AgentState` and a private
audit ring. So `agent.set paused` is reported but not enforced, and the agent's
calls never appear in the audit trail. The fix shares the core's state and ring
with that server through `with_shared_governance`. They travel in a sealed
`Governance` value that only `Assembled::governance()` can create, and both
`build_servers` and `tui::run` require it. TUI mode therefore cannot be wired
without governance, or with a snapshot of it. The TUI's own operator server stays
ungated and unrecorded. Tests drive the real `build_servers`: four fail on today's
wiring, three are guards that pass either way, and one doctest proves the type is
sealed.

1. **Shape.** A sealed `wire::Governance` that `build_servers` and `tui::run`
   require. Not fields on `Services`, and not parameters of `tui::server`.
2. **The TUI's operator server stays ungoverned and unaudited.** Its polling, about
   220 calls a minute, would flood the ring.
3. **`push_tx` stays unfed.** Governance does not depend on it (follow-up
   "tui-mode push").
4. **The seeded policy behaves the same as before.** No `mcp.policy` YAML key
   exists.
5. **Under `ask`, only a subscribed operator-token loopback client can approve.**
   The TUI cannot. This fails closed, and I accept it ("unified agent hub").
6. **The TUI's own operator actions stay out of `agent.activity`** ("audit
   signal-to-noise").
7. **Test layout.** One in-process file, one Terminal-only loopback file, and a
   doctest. The mutation point is in `build_servers`.
8. **Test support.** `support::assemble_services` returns `Governance`; no second
   helper is added.
