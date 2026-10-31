# `aitm web` agent governance design

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's autonomous-approve mode, per the lead session's brief)
**Research inputs:** code reading of `crates/aitm/src/{main,tui,wire}.rs`, `crates/aitm/src/web/{bridge,mod}.rs`, `crates/aitm-mcp/src/server.rs` (`McpServer`, `call_tool`, `run_tool`, `policy_decision`, `read_refusal`, `park_for_approval`, `handle_approve`, `record_audit`, `spawn_push_dispatcher`, `Subscriptions::add`), `crates/aitm-plugins/src/agent.rs`, `crates/aitm-core/src/{agent,audit,config}.rs`, `crates/aitm/src/config_file.rs`, `crates/aitm/tests/web_bus_push.rs`, `apps/web/src/state/app.ts` (poll cadence). PR #137 (web `/bus` push) is merged as `2bdcb07`, the base of this change, and its code was read: `bridge.rs` (one `ConnCtx` and `NotificationSink` per bridge connection, unique `conn_id`), `spawn_push_dispatcher`, the closed-sink and 32-per-connection caps in `Subscriptions::add`, the web `bus` wiring in `main.rs`, and its socket tests including a hand-built `Ask` rig.

## Intent

`aitm web` serves its `/bus` WebSocket bridge from a **second** `McpServer`
(`main.rs`: `bus` is `tui::server(&cfg, cfg.mcp.transport.clone(), &services)` plus
`.with_push(push_tx)` and `bus.spawn_push_dispatcher()`), separate from the primary
agent server `mcp`. Only the primary is handed the
shared agent policy (`.with_agent_state(agent_state)`) and audit ring
(`.with_audit_ring(audit_ring)`), the same two `Arc`s `wire::assemble` also gave
to `AgentPlugin`. The web server keeps `McpServer::new`'s private defaults: its
own `AgentState::new(AgentPolicy::Auto)` and an empty private `AuditRing`. An
agent-token `/bus` connection is `Frontend::Mcp` (`bridge.rs`, `classify_token`),
so it is gated like any agent, but by the **wrong policy**: an operator's
`agent.set paused` (or `readonly`, `ask`, `all`) governs every agent surface
except the web one, which stays pinned at `auto`. The web agent's calls are also
recorded in a ring nobody reads, so they never appear in `agent.activity` or
`agent.status.actions_last_minute`, and `agent.status` reports a policy the web
gate does not enforce. This spec closes that by sharing the primary's two `Arc`s
with the web server through **one** library function that production and tests
both call, so the wiring cannot drift again.

## Goals

- One policy governs every agent-class connection: a web agent-token connection
  follows the configured/seeded policy **and** every live `agent.set`, with no
  reconnect and no restart.
- One audit trail: a web agent call, allowed or refused, appears in
  `agent.activity` (origin `"mcp"`) and counts in `agent.status.actions_last_minute`.
- `agent.status.policy` equals what the web gate enforces.
- Refusals carry the policy's own reason text, not a generic error.
- The operator bridge connection stays un-gated.
- The wiring lives in one function in the `aitm` library that `main.rs` calls for
  both servers and the new tests call too, so a test cannot pass while `main.rs`
  is mis-wired in this way.
- The split of the `Ask` machinery between the two servers is stated, tested,
  and fails closed.

## Non-goals

- **Unifying the subscription/approval hub across the two servers.** Decided
  below (Design 4); named follow-up **"unified agent hub"**.
- **TUI mode** (`tui::build_servers`). Same class of gap, verified by reading,
  not fixed here: named follow-up **"tui-mode governance"** (Design 7).
- **A `mcp.policy` config key, env var, or CLI flag.** None exists today (see
  Design 6); adding one is its own change with its own questions. Named
  follow-up **"configurable startup policy"**.
- **Audit-noise mitigation** (not recording trusted-control Read calls, per-origin
  rings, UI-poll exemption). Accepted cost, Design 6; named follow-up **"audit
  signal-to-noise"**.
- Wiring `durable_audit` (nothing sets it in production; nothing to share).
- Any edit to `crates/aitm-mcp` or `crates/aitm-core`. No new `McpServer` API.
- `flow.subscribe` push over `/bus`, `.with_push`, and the web server's push
  dispatcher: landed in #137 and kept exactly as it is. This change only adds the
  governance helper beside them.
- Changing the default policy (`auto`), the default web link's role (agent), or
  how bridge tokens resolve to roles.
- Migrating `web_bus_roles.rs` / `web_bus_concurrency.rs` / `web_bus_push.rs` onto
  the helper. The first two pin role routing and concurrency, not governance, and
  run under `Auto`, where the hand-built server and production agree.
  `web_bus_push.rs` pins push mechanics; it hand-builds its server with
  `.with_agent_state(..)` (shared policy, no shared ring) and its `Ask` test stays
  valid. None of the three is modified. Optional later.
- Making the `Ask` refusal text name which server it speaks for.

## Anti-goals

- Fixing `main.rs` only. A test rig that hand-builds the server would stay green
  while production drifted again; the point is one shared function.
- A **snapshot** fix: giving the web server a fresh `AgentState` seeded from
  config. It would pass a "starts readonly" test and still ignore `agent.set`.
  The live-follow criterion (AC3) exists to fail it.
- Giving the web server a *separate* ring to keep UI polling out of the shared
  one. That is today's defect (invisible web agent activity) with a reason attached.
- Gating the operator bridge, or loosening the agent gate so the default UI keeps
  working under `paused`/`readonly`.
- A half-unified `Ask`: letting one server's operator approve another server's
  parked call without a shared hub, or announcing a request to operators who
  cannot resolve it.
- Any new path where the web agent bridge runs a command the primary's gate
  would refuse under the same policy.

## Constraints

- **Edits stay in `crates/aitm`** (`src/tui.rs`, `src/main.rs`, doc comments in
  `src/wire.rs` and `src/web/mod.rs`, new tests) plus this spec/plan. `aitm-mcp`
  and `aitm-core` are untouched (diff-checkable, AC15).
- **`main.rs` edit is tiny and local.** It sits next to the lines #137 already
  landed on the web `bus` (`Arc::new(tui::server(..).with_push(push_tx))`, then
  `bus.spawn_push_dispatcher()`): the helper wraps each `tui::server(..)` call and
  the existing `.with_push(..)` and `spawn_push_dispatcher()` stay as they are. No
  rebase hazard remains. The primary currently *moves* `agent_state`/`audit_ring`
  into its builder chain; the helper takes references so the same pair can be
  applied to both servers with no ownership juggling.
- **Fail closed.** The policy gate, `read_refusal`, and trusted-control bypass
  logic stay in `aitm-mcp` exactly as they are; this change only changes which
  `AgentState` they read.
- **Hot path unchanged.** `AgentState` is one atomic; `AuditRing::append` is one
  short `Mutex` section per `tools/call`, now shared by two servers. Negligible.
- Ordering: `AgentState` uses `Relaxed` atomics. That is sufficient for AC3
  because each `agent.set` reply is received before the next agent call is sent
  (the socket round trip orders them).
- No new dependencies, no `unsafe`.
- Sandbox: tests that bind a loopback socket (`web::serve` on `127.0.0.1:0`) run
  from the Terminal panel. In-process tests run anywhere.

## Design

### 1. What is shared, and why

The two `Arc`s `Assembled` already carries: `agent_state: Arc<AgentState>` and
`audit_ring: Arc<AuditRing>`. These are the very objects `AgentPlugin::new(
agent_state.clone()).with_audit_ring(audit_ring.clone())` holds inside the shared
`Registry` (`wire.rs`, `assemble_with_scripts`). So handing them to a server
makes the gate read what `agent.set` writes, and makes `call_tool`'s
`record_audit` append to what `agent.activity`/`agent.status` read. Nothing new is
created; the web server is simply connected to what already exists.

`agent.status` and `agent.activity` are `AgentPlugin` commands served from the
shared registry, so they already read the primary's state and ring. The
observable defects are therefore (a) `agent.status` says one thing while the web
gate enforces another, (b) web calls are recorded in the web server's private ring
and never surface, and (c) `agent.set` never reaches the web gate.

### 2. The one function (Architect's call: `tui.rs`, free function)

In `crates/aitm/src/tui.rs`, beside `server()`:

`pub fn with_shared_governance(server: McpServer, agent_state: &Arc<AgentState>, audit_ring: &Arc<AuditRing>) -> McpServer`

It applies `with_agent_state` and `with_audit_ring` with clones of the given
`Arc`s and nothing else (no push, no roles, no timeouts). **Why `tui.rs`:**
`server()` there is already documented as "the one way every server in this binary
is built", and its doc says the gate/audit are "wired by the caller"; the helper
is the other half of that sentence, and it is where gap D's fix will land.
**Why a free function over a method on `Assembled`:** `main.rs` destructures
`Assembled`, so a method would be unreachable at the call sites. **Why references:**
the same pair of `Arc`s is applied twice.

### 3. `main.rs`

Both `McpServer`s the web run builds go through the helper: the primary
(`mcp = with_shared_governance(tui::server(..), &agent_state, &audit_ring)` then
its existing `.with_mcp_roles(..)` and `.with_push(..)`) and the web `bus`
(`with_shared_governance(tui::server(..), ..)` then the `.with_push(push_tx)` #137
added, with `bus.spawn_push_dispatcher()` unchanged). The stale comment above them ("The web bridge and the TUI are operator frontends,
built by `tui::server` without the gate") is wrong for the web bridge, whose agent
token is `Frontend::Mcp`, and is rewritten. The `Assembled` field docs
(`agent_state`, `audit_ring`) and the `web/mod.rs` module doc say "apply with
`tui::with_shared_governance` to every agent-facing server".

**Residual risk, stated plainly.** The helper makes tests and production share a
*function*; it cannot force `main.rs` to call it for a future third server. The
compile-time fix (carry the two `Arc`s in `Services` so `tui::server` applies them
by construction, or make them required parameters) changes the `services()`
signature and every `Services` literal, and alters TUI-mode behaviour that gap D
owns. It is the recommended shape of the "tui-mode governance" follow-up, not this
change. A source-grep test over `main.rs` was rejected as brittle.

### 4. The `Ask` split: not unified, documented, fails closed

**Decision: do not unify.** `Subscriptions`, `ParkedRequests` (`parked`),
`ConfirmTokens`, and the `conn_seq` counter are created per `McpServer` in
`McpServer::new` and no `with_*` builder can replace them. Consequently:

| State | Shared after this change? | Observable effect |
|---|---|---|
| Policy (`AgentState`) | **yes** | one policy for every agent surface |
| Audit ring (`AuditRing`) | **yes** | one `agent.activity` / `actions_last_minute` |
| `Subscriptions` | no, per server | flow, state, and `notifications/aitm/agent` pushes reach only that server's subscribers |
| `ParkedRequests` | no, per server | `agent.approve` resolves only calls parked on the **same** server |
| `ConfirmTokens`, `conn_seq` | no, per server | confirm handshake and connection ids are per server |

So a web agent's `Sensitive` call under `Ask` is announced only to operators
subscribed on the web server (`park_for_approval` checks
`subscriptions.any_role(Frontend::Operator)`; `push_approval_request` uses
`fanout_role`) and is approvable only by `agent.approve` on the web server, and
vice versa for TCP/stdio/HTTP agents on the primary. The ring is unified but live
push is not: a web subscriber sees `notifications/aitm/agent` lines only for web
calls even though `agent.activity` lists all.

**Fail-closed behaviours (each is an acceptance criterion):**
1. No operator subscribed on the web server (including: an operator subscribed
   only on the primary): a web agent `Sensitive` call under `Ask` is refused at
   once with the existing reason "...no operator is connected to approve it...".
   It never parks and never waits out the approval timeout.
2. An operator subscribed on the web server is announced the parked call
   (`notifications/aitm/agent`, `event: "approval_requested"`) and can resolve it
   with `agent.approve` on the web server.
3. `agent.approve` for a web-parked `request_id` sent to the *other* server is the
   plain error "no parked request ... is awaiting approval". It approves nothing;
   the call stays parked until resolved on the right server or timed out.

**Evidence on this base.** `bridge.rs` builds one `ConnCtx` per bridge connection,
with a `NotificationSink` and a unique `conn_id` (PR #137, merged), so
`flow.subscribe` works over `/bus` and an operator bridge connection can be a
subscriber. All three behaviours are therefore reachable over a real socket. The
in-process tests (AC9-AC11: fast, sandbox-runnable, a hand-built operator
`ConnCtx` that carries a `NotificationSink`) pin the split on both servers,
including behaviour 3, which needs a second server; one socket test (AC16) proves
behaviour 2 end to end through the real bridge.

**This is a behaviour change, not only a visibility fix.** Before this change
production web could never park: it ran a private, fixed `Auto`, under which a
`Sensitive` agent call is refused outright and never reaches `park_for_approval`.
Under `ask` a web agent's `Sensitive` call now parks, or is refused at once when no
operator is subscribed on the web server. Only an operator with
`mcp.operator_token` configured (so an operator bridge token exists), connected
over `/bus` and subscribed with `flow.subscribe` on the web server, can see and
approve it. An operator on the primary (TCP, stdio, HTTP) cannot.

**Why not unify (confirmed, with evidence).** A shared hub needs: one
`Subscriptions` + `ParkedRequests` + `ConfirmTokens` + `conn_seq` injected into
both servers (new `aitm-mcp` builders, which do not exist); exactly one push
dispatcher (since #137 each server runs its own over its own registry; over a
shared registry two would deliver every flow notification twice to shared
subscribers); and globally unique connection ids (`drop_connection(conn_id)`
removes by id, and each server's counter starts at 1, so ids would collide and one
server's connection ending would drop the other's subscriptions). That is a
cross-crate change about the size of #137 for a hub whose absence fails closed.
#137 has landed, so the unified hub (the named follow-up "unified agent hub") is
now unblocked; it is not part of this change.

### 5. Roles: what stays un-gated

`policy_decision` and `read_refusal` return early for
`Frontend::is_trusted_control()` roles, and `agent.approve`'s `handle_approve`
requires it. The bridge's `classify_token` is untouched: the operator bridge token
resolves to `Frontend::Operator` only when `mcp.operator_token` is non-empty
(`main.rs` derives `operator_token` from it). Under `paused`, `tools/call` from
the agent role is refused for every sensitivity (including `agent.status`,
`agent.activity`, `flow.subscribe`); `initialize`, `tools/list`, and `ping` are
not tool calls and are still answered.

### 6. Operational consequences (stated plainly; the PR description repeats them)

1. **There is no way to configure a non-default policy today.** `McpConfig.policy`
   defaults to `AgentPolicy::Auto` (`aitm-core/src/config.rs`), but the YAML loader's
   `McpFile` (`config_file.rs`) has `#[serde(deny_unknown_fields)]` and only the keys
   `transport`, `operator_token`, `stdio_role`; there is no env var or flag for it.
   By reading, `mcp: {policy: readonly}` in a config file is rejected as an unknown
   field (not run). So in production the policy leaves `Auto` only through a live
   operator `agent.set`. This change therefore delivers, in practice, "the web
   agent follows `agent.set`". The seeded-from-config path is real code and is
   tested by setting `Config.mcp.policy` programmatically. (The M4 live-acceptance
   doc, `docs/superpowers/m4-live-acceptance.md`, shows `mcp: policy: auto`; that
   example does not match the loader. Reported, out of this spec's write scope.)
2. **Under the default `auto` nothing changes in enforcement.** The web server was
   `Auto`; the primary seeds `Auto`. What changes under `auto` is only visibility
   (item 4).
3. **Governance now follows in both directions.** After an operator `agent.set`,
   the default web link goes **read-only** (`readonly`) or **dead** for tool calls
   (`paused`), by design: the default `aitm web` link on stdout is the *agent*
   bridge token. Conversely `agent.set all` now also relaxes the web agent from its
   old fixed `auto` (per-command config gates such as `scope.allow_agent_widen`
   still apply). To act while the agent is restricted, set `mcp.operator_token` and
   use the operator URL, which is un-gated.
4. **The shared ring now records the web UI's own calls.** The UI polls
   `flow.list` every 500 ms and `proxy.status` every 2 s
   (`POLL_MS`/`STATUS_EVERY_MS` in `apps/web/src/state/app.ts`), about 150 calls a
   minute at idle plus `flow.detail` per new flow. With the default link these are
   `Frontend::Mcp` calls, so they are indistinguishable from an agent's (`origin:
   "mcp"`); with the operator link they are `origin: "operator"`, as the macOS
   app's loopback calls already are. Consequences: `actions_last_minute` is
   inflated while a UI tab is open, and `DEFAULT_AUDIT_CAPACITY` (4096) turns over
   in roughly 27 minutes, evicting older entries. **Architect's call: accept, keep
   out of scope.** Reasons: it is the same behaviour every operator UI on the
   primary already has, not a new class; the alternative (a private ring) is the
   defect being fixed; each entry carries `origin`, so clients can filter; and a
   real fix (skip auditing trusted-control Reads, a per-origin ring) changes audit
   semantics in `aitm-mcp` for every surface and needs its own spec. This is the
   one cost that is not fully benign, and the follow-up is named.
5. **`durable_audit` is not wired in production.** `McpServer::with_durable_audit`
   has no caller outside its definition and there is no config key, so there is
   nothing to share. The in-memory ring is the only audit record.
6. **Parked web calls are bounded by what already bounds the primary:** 64 parked
   requests per server (`MAX_PARKED_REQUESTS`), the approval timeout, and the
   bridge's 16 in-flight frames per connection. No new cap.
7. **Under `ask`, a call can now park on the web server, and only a web operator
   can approve it.** Before this change that was impossible (fixed `Auto`). Now
   only an operator bridge connection (it exists only when `mcp.operator_token` is
   configured) that is subscribed on the web server (`flow.subscribe`, possible
   since #137) is announced `approval_requested` and can `agent.approve`. With none
   subscribed there, a web agent's `Sensitive` call is refused at once; an operator
   on the primary cannot approve it (Design 4).

### 7. Same-class gap, out of scope (verified by reading)

In `aitm tui`, `tui::build_servers` builds the loopback agent server with
`.with_agent_state(Arc::new(AgentState::new(cfg.mcp.policy)))`: a fresh state that
is **not** the `AgentPlugin`'s `Arc`, with no `.with_audit_ring` and no
`.with_push`. `main.rs` destructures `agent_state`, `push_tx`, and `audit_ring` from
`Assembled` but uses them only in the non-TUI branch. So in TUI mode an operator's
`agent.set` (it runs through the registry's `AgentPlugin`) never reaches the
loopback agent gate, and that server's calls land in a private ring. Named
follow-up **"tui-mode governance"**; see the residual-risk note in Design 3 for its
likely shape. Not touched here.

### 8. Tests: they exercise the production wiring

The rig for every governance test builds the web server as `main.rs` does:
`aitm::wire::assemble(&cfg)` for `Assembled`, `aitm::tui::services(&proxy, &cfg,
None, TuiLog::Off)`, `tui::server(&cfg, cfg.mcp.transport.clone(), &services)`,
then `tui::with_shared_governance(.., &assembled.agent_state, &assembled.audit_ring)`.
The socket rig also does what `main.rs` does after that (`.with_push(push_tx)`,
`Arc::new`, `spawn_push_dispatcher()`) so the served server is the production
shape; the in-process rigs drive `handle_on` with no runtime and omit the push
wiring, which does not touch governance (it is pinned by `web_bus_push.rs`).
Seeding a non-default policy sets `cfg.mcp.policy` before `assemble`. Commands
used (registered, with the sensitivities `m4_sensitivity.rs` pins): **Read**
`agent.status`, `flow.list`; **Write** `flow.kill`; **Sensitive** `scope.add`;
plus the server-handled `flow.subscribe` and `agent.approve`. A refused call never
reaches argument validation (the gate runs before `params_from_json`), so refused
probes need no valid arguments. A **parked** call is different: give it valid
arguments (`scope.add {host: "example.com"}`), because the approval prompt reads
them.

Layout (Architect's call): `crates/aitm/tests/web_bus_governance.rs` (real
loopback WebSocket against `web::serve`, style of `web_bus_roles.rs`; holds AC1-AC6
and AC16; **needs the Terminal panel**), `crates/aitm/tests/web_bus_ask_split.rs`
(in-process via `McpServer::handle_on`, AC9-AC11, **sandbox-runnable**), and helper
unit tests in the `#[cfg(test)]` module of `tui.rs` (in-process, AC7 and AC8).
`web_bus_push.rs` already pins the `Ask` mechanics over the bridge with a
hand-built rig and a `test.sensitive` command (operator subscribes, agent parks,
`approval_requested` reaches only the operator, `agent.approve` denies). AC16 does
not repeat that; it proves that the **production wiring** (the helper) makes the
web server enforce the shared `Ask` policy against the real `scope.add`, which the
hand-built rig cannot show.

**Red/green.** The Coder writes the tests against a rig that builds the web server
as today's `main.rs` does (`tui::server` only, no helper), runs them and records
the failures (red), then adds the helper and the rig applies it (green). The red
run is repeated once at the end by temporarily omitting the helper call in the
rig (AC12); both runs go in the Coder's report. Not every criterion can be red:
AC4 and AC6 pin behaviour that must **not** change (operator un-gated; default
`auto` enforcement) and pass with or without the helper, which is why they are
guards and not evidence of the fix.

## Acceptance criteria

`[socket]` = real loopback WebSocket, Terminal panel. `[in-process]` = sandbox.
`origin` is the audit ring's label for the agent role, `"mcp"` (`origin_label`),
not the `initialize` echo `"agent"` (`role_str`).

1. **AC1** `[socket]` Seeded `mcp.policy = ReadOnly`; web **agent** token:
   `agent.status` (Read) returns `isError: false` and `structuredContent.policy ==
   "readonly"`; `flow.kill` (Write) and `scope.add` (Sensitive) each return a tool
   result with `isError: true` whose text contains "`flow.kill` refused" /
   "`scope.add` refused" and "the agent policy is `readonly`". (Covers the
   policy-reason and status-agreement requirements.)
2. **AC2** `[socket]` Seeded `Paused`; web agent token: `agent.status`, `flow.list`,
   `flow.kill`, `scope.add`, and `flow.subscribe` each return `isError: true` with
   text containing "the agent policy is `paused`" (`flow.subscribe` via
   `read_refusal`, the rest via `policy_decision`). `initialize` still answers
   `role: "agent"` and `tools/list` still lists tools.
3. **AC3** `[socket]` **Live follow, no reconnect.** Seeded `Auto`; one long-lived
   agent connection and one operator connection (operator bridge token
   configured). Agent `flow.list` succeeds. Operator `agent.set {policy:
   "paused"}` returns `structuredContent.policy == "paused"`; the **same** agent
   connection's next `flow.list` is refused with "the agent policy is `paused`".
   Operator `agent.set {policy: "auto"}`; the same connection's next `flow.list`
   succeeds again. At each step the operator's `agent.status.policy` equals the
   state the agent just experienced.
4. **AC4** `[socket]` **Operator stays un-gated.** Seeded `Paused`; the operator
   bridge connection's `initialize` reports `role: "operator"`, and its
   `agent.status` and `flow.list` (Read) and `agent.set {policy: "auto"}`
   (Sensitive) all return `isError: false`.
5. **AC5** `[socket]` **Audit and counts.** Seeded `ReadOnly`, fresh server; web agent
   issues `agent.status` (allowed) then `flow.kill` (refused). An operator then
   reads, as its first call, `agent.status`: `actions_last_minute == 2`. Its next
   call, `agent.activity`, lists those two entries first and in order, both with
   `origin: "mcp"`, commands `"agent.status"` then `"flow.kill"`, results `"ok"`
   and `{error: <text containing "readonly">}`; any entry from the operator
   connection carries `origin: "operator"`.
6. **AC6** `[socket]` Seeded the default `Auto`: web agent `flow.list` succeeds and
   `scope.add` is refused with "the agent policy is `auto`". Pins "under the
   default nothing changes in enforcement".
7. **AC7** `[in-process]` **One trail across surfaces.** Two servers built from one
   `Assembled` through the helper (a primary-like and a web-like), one agent call
   on each: the shared ring (`audit_ring.recent(None, None)`) and one
   `agent.activity` hold both, in call order.
8. **AC8** `[in-process]` **Helper unit test** (`tui.rs` tests): a server passed
   through `with_shared_governance(server, &state, &ring)` is refused under
   `state.set_policy(AgentPolicy::Paused)` for an agent `ConnCtx` with the paused
   reason, the refused call adds exactly one entry with `origin == Frontend::Mcp`
   to `ring`, and an operator `ConnCtx` is not refused.
9. **AC9** `[in-process]` **Ask split 1.** Policy `Ask`, two governed servers P and W,
   an operator subscribed on **P only** (`flow.subscribe` with a
   `NotificationSink`), `approval_timeout` set to 60 s. A web agent `scope.add` on
   W returns within 5 s with `isError: true` and text containing "no operator is
   connected to approve it"; P's operator sink receives no `approval_requested`.
10. **AC10** `[in-process]` **Ask split 2.** Operator subscribed on **W**; web agent
    `scope.add` on W (on its own thread) parks: the operator's sink receives a
    `notifications/aitm/agent` line with `params.event == "approval_requested"`,
    `params.command == "scope.add"`, and a `params.request_id` starting `apr_`.
    Operator `agent.approve {request_id, allow: false}` **on W** returns `isError:
    false` and the parked call returns `isError: true` with text containing "an
    operator denied the parked sensitive command".
11. **AC11** `[in-process]` **Ask split 3.** As AC10, but first an operator
    `agent.approve {request_id, allow: true}` **on P** returns `isError: true` with
    text containing "no parked request", and the web call has not returned; then
    `allow: false` on W succeeds and the web call's final result is the denial.
    (Had P's approve worked, W's approve would error and the call would have run.)
12. **AC12** `[socket + in-process]` **Mutation check.** With the rig's
    `with_shared_governance` call omitted, AC1, AC2, AC3, AC5, AC9, AC10, AC11, and
    AC16 each fail with the policy or audit assertion as the cause (not a compile or
    connect error): the web server then enforces its private `Auto` and records to
    its private ring. AC4 and AC6 are guards and pass either way. The report shows
    the red run and the green run.
13. **AC13** Review-checked, not machine-enforced: both `tui::server(` call sites in
    `main.rs` are wrapped by `tui::with_shared_governance`; the stale "operator
    frontends ... without the gate" comment is gone; the `Assembled` field docs and
    `web/mod.rs` doc point to the helper and state the Ask split.
14. **AC14** The Rust gate passes (`cargo fmt --check && cargo clippy --all-targets
    -- -D warnings && cargo test`), and `web_bus_roles.rs` /
    `web_bus_concurrency.rs` / `web_bus_push.rs` pass unmodified.
15. **AC15** The diff touches nothing under `crates/aitm-mcp` or `crates/aitm-core`.
16. **AC16** `[socket]` **Ask over the real bridge.** Seeded `Ask`; an operator
    bridge connection subscribes with `flow.subscribe` (reply carries a `sub_id`);
    a web agent connection calls `scope.add {host: "example.com"}`, which parks (no
    reply yet). The operator's socket receives a `notifications/aitm/agent` frame
    with `params.event == "approval_requested"`, `params.command == "scope.add"`,
    and a `params.request_id` starting `apr_`. The operator sends `agent.approve
    {request_id, allow: false}` over the same bridge connection and gets
    `isError: false`; the agent's `scope.add` then returns `isError: true` with text
    containing "an operator denied the parked sensitive command". The operator's
    `agent.status.policy` is `"ask"`. (Denial, not approval, because an approved
    agent `scope.add` still meets the command's own gate,
    `scope.allow_agent_widen`, which is off by default.)

## Left to the builder

- Duplicating the small socket helpers per test file (house style in
  `web_bus_roles.rs` / `web_bus_push.rs`) or factoring them into a **new** file under
  `tests/support/`. Not by editing an existing test file (AC14).
- Exact assertion form for reason text: `contains` on the quoted fragments above.
- How AC9-AC11 run the parked agent call (`std::thread` over an `Arc<McpServer>`)
  and bound the waits, as long as AC9's "returns without waiting for the approval
  timeout" is asserted with a bound far below it.
- Whether the AC3 "next call succeeds" probe is `flow.list` or another Read.
- The wording of the doc-comment sentences and the PR description, provided the
  seven consequences in Design 6 are stated.

## Open questions

1. **Non-blocking, default stated.** Should `mcp.policy` become a real config key
   (and env/flag) so the seeded-policy path is reachable in production? **Default:
   no, not in this change**; follow-up "configurable startup policy". It needs a
   name, precedence rules, and a decision on whether `paused` is a legal startup
   value. Nothing in this spec waits on it.
