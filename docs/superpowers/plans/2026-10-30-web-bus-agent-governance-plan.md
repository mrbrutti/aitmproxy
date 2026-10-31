# `aitm web` agent governance implementation plan

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's autonomous-approve mode, per the lead session's brief)
**Spec:** `docs/superpowers/specs/2026-10-30-web-bus-agent-governance-design.md`
**Branch / worktree:** `claude/loving-cartwright-2e400f` in `/Users/matt/Security/aitmproxy/.claude/worktrees/loving-cartwright-2e400f`, cut from `origin/main` `2bdcb07` (PR 137, web `/bus` push, already merged). Base SHA for every diff and Tester/panel dispatch: `2bdcb07`.

## Overview

One new library function, `tui::with_shared_governance`, applies the primary
server's `AgentState` and `AuditRing` to any `McpServer`. `main.rs` calls it for
both servers the web run builds; every governance test builds its web server
through it. Four tasks, **all sequential**: Task 1 adds the helper plus the
in-process tests; Task 2 adds the real-socket tests; Task 3 wires `main.rs` and
edits three doc comments; Task 4 is an orchestrator checkpoint (full gate, the
AC12 mutation re-run on the final head, the AC14/AC15 diff checks).

Order and independence, stated once. Task 1 first: everything calls its helper.
Tasks 2 and 3 touch disjoint files (a new test file versus `main.rs`, `wire.rs`,
`web/mod.rs`) and could in principle fan out, but they share one worktree and one
cargo target directory, and Task 2 has an orchestrator checkpoint in the Terminal
panel between its two coder passes. Default: run 1, 2, 3, 4 in order. Task 4 is
always last. Task 3 needs Task 1's helper to compile, so it never runs before or
beside Task 1.

### Where each command runs (read this before dispatching)

- **Bash sandbox (Coder and Tester sub-agents: Read, Grep, Glob, Bash, Write, Edit).**
  `cargo build`, `cargo fmt --check`, `cargo clippy`, and any test that binds no
  socket: `cargo test -p aitm --lib tui::` (filtered to the `tui` module, because
  other lib modules are not guaranteed socket-free), `cargo test -p aitm --test
  web_bus_ask_split`. Also `cargo test -p aitm --test web_bus_governance --no-run`
  (compile only). If cargo cannot resolve dependencies offline, stop and ask the
  orchestrator to run `cargo fetch` in the Terminal panel; do not report a result
  you did not get.
- **Terminal panel (orchestrator only).** Every git command. Every test that binds
  a loopback socket: `cargo test -p aitm --test web_bus_governance` (it serves
  `web::serve` on `127.0.0.1:0`) and the full `cargo test`. A Coder or Tester must
  never claim a socket test passed or failed; it reports "compiled, NOT RUN
  (socket)" and the orchestrator supplies the output.
- **Coders do not commit.** The sandbox cannot run git, so this plan overrides step 5
  of `coder.md`: the Coder reports the files it changed and the orchestrator commits
  in the Terminal panel after the task's Tester passes. Commit messages name the plan
  and task (`feat(web): task 1 - with_shared_governance helper (plan
  2026-10-30-web-bus-agent-governance)`) and avoid any word that starts with `#`
  (the terminal hook refuses it): write "PR 137", not the hash form.
- **Evidence, verbatim.** Every red and green run goes into the Coder's (or the
  orchestrator's) report as the literal command and the literal output lines named in
  the task. "It failed as expected" is not a report.
- **Stale target directories.** If `CARGO_TARGET_DIR` is shared with other worktrees,
  `touch` the edited sources before a red or green run so cargo does not reuse a
  stale artifact. A red run on a stale binary is worthless.
- **Gate exit status, not grep.** Where the orchestrator gates on a full run, redirect
  to a log and read the exit status; `grep` output is for display only.

### Symbols the rigs use (confirmed by reading; all `pub`, none missing)

`aitm::wire::assemble(&Config) -> anyhow::Result<Assembled>` with `pub` fields
`proxy`, `agent_state: Arc<AgentState>`, `push_tx`, `audit_ring: Arc<AuditRing>`
(`wire.rs`); `aitm::tui::services(&Proxy, &Config, Option<Arc<dyn BrowserDriver>>,
TuiLog) -> Services`, `aitm::tui::server(&Config, McpTransport, &Services) ->
McpServer`, `aitm::tui::TuiLog` (`Off`) (`tui.rs`); `aitm::web::{serve, WebState}`
(`WebState { mcp: Arc<McpServer>, agent_token: String, operator_token:
Option<String> }`, `serve(TcpListener, Arc<WebState>)`); `aitm_mcp::{McpServer,
ConnCtx, NotificationSink}` (`ConnCtx` has `pub` fields `role`, `client_label`,
`conn_id`, `out`; `McpServer::handle_on`, `with_push`, `spawn_push_dispatcher`,
`with_approval_timeout` are `pub`); `aitm_core::{AgentPolicy, AgentState, AuditRing,
AuditEntry, AuditResult, Frontend, Config}`. `Config.mcp.policy` and `Config.ca.dir`
are `pub`. The one new symbol, `tui::with_shared_governance`, is created in Task 1.

### Claims in the spec, verified by reading on `2bdcb07` (none false)

- `scope.add` is `Sensitivity::Sensitive` (`aitm-plugins/src/scope.rs`), `flow.kill`
  is `Write` (`intercept.rs`), `flow.list` is `Read` (`capture.rs`), `agent.status`
  and `agent.activity` are `Read`, `agent.set` and `agent.approve` are `Sensitive`
  (`agent.rs`). `m4_sensitivity.rs` pins the first four.
- A policy-refused call never reaches argument validation. In
  `McpServer::run_tool`, `policy_decision` (and `read_refusal` for the subscription
  verbs) returns before `params_from_json`, so refused probes need no valid
  arguments.
- Two nuances the Coder must know, neither a spec error. (a) A **parked** call
  (`Ask`) does read its arguments, for the approval prompt (`approval_prompt` falls
  back to a generic prompt if they are invalid), so parked calls get valid arguments
  (`scope.add {host: "example.com"}`). (b) With the helper omitted (the red state) a
  `Write` call such as `flow.kill` is allowed through the private `Auto` gate and
  then fails argument validation with a JSON-RPC `error`, not a tool result; the red
  run therefore shows a reply with no `result.isError`, which is still the policy
  assertion failing. Assert on the whole reply and print it in the message.

### AC coverage

| AC | Task | Test (exact name) |
|---|---|---|
| AC1 | 2 | `readonly_web_agent_reads_but_cannot_write_or_widen` |
| AC2 | 2 | `paused_web_agent_is_refused_everything_but_the_handshake` |
| AC3 | 2 | `web_agent_follows_a_live_agent_set_without_reconnecting` |
| AC4 | 2 | `operator_bridge_connection_stays_ungated_under_paused` (guard) |
| AC5 | 2 | `web_agent_calls_land_in_the_shared_audit_trail` |
| AC6 | 2 | `default_auto_still_refuses_a_sensitive_web_agent_call` (guard) |
| AC16 | 2 | `ask_parks_a_web_agent_call_for_an_operator_on_the_same_bridge` |
| AC7 | 1 | `with_shared_governance_gives_two_servers_one_audit_trail` |
| AC8 | 1 | `with_shared_governance_gates_an_agent_and_audits_into_the_shared_ring` |
| AC9 | 1 | `no_operator_on_the_web_server_refuses_a_web_call_at_once` |
| AC10 | 1 | `an_operator_on_the_web_server_is_asked_and_resolves_on_the_web_server` |
| AC11 | 1 | `an_approve_sent_to_the_primary_approves_nothing_parked_on_the_web_server` |
| AC12 | 1, 2, 4 | red runs in Tasks 1 and 2; final-head re-run in Task 4 |
| AC13 | 3 | literal greps plus panel reading |
| AC14, AC15 | 4 | gate; `git diff` checks |

### Calls made in this plan (Architect's calls, for Matt to correct)

1. AC7 lives in the `tui.rs` unit tests beside AC8, not in `web_bus_ask_split.rs`;
   both call the helper by name, so their red run uses an **inert stub** of the real
   signature, not an omitted call.
2. Task 2 has two Coder passes around one orchestrator Terminal run: pass A writes
   the socket tests against a rig without the helper (red), pass B adds the one
   helper line (green). The branch is never committed red.
3. The helper call in each web-server rig is its own one-line statement tagged with
   a `MUTATION-POINT` comment, so AC12 is a scripted one-line delete.
4. The panel runs once on the whole branch, with a Tester pass after each task (the
   orchestrator's brief). WORKFLOW says the panel runs "after each task"; the change is
   one helper, a few wiring lines and tests, so per-task panels would re-read the same
   lines three times. Add a panel on Task 1 if per-task review is wanted.
5. AC16 asserts the **denial** path, not approval: an approved agent `scope.add` still
   meets the command's own gate (`scope.allow_agent_widen`, off by default) and
   would be refused anyway.
6. The socket rig also applies `.with_push(..)` and `spawn_push_dispatcher()` as
   `main.rs` does; the in-process rigs omit them (no runtime, push is not governance).
7. Test helpers are copied into the new files (house style), not factored into
   `tests/support/`; no existing test file or `support/` is edited.
8. `main.rs` drops its now-redundant direct `.with_agent_state(..)` /
   `.with_audit_ring(..)` calls; the helper is the only path.

## Tasks

### Task 1: the helper, and the in-process tests (AC7-AC11, AC12 in-process half)

- **Satisfies:** AC7, AC8, AC9, AC10, AC11; AC12 (in-process half).
- **Depends on:** none.
- **Files:** `crates/aitm/src/tui.rs` (modify: helper, doc, two unit tests),
  `crates/aitm/tests/web_bus_ask_split.rs` (create).
- **Change:**
  - `tui.rs`: add `AuditRing` to the existing `aitm_core` import. Add, directly after
    `server()`, `pub fn with_shared_governance(server: McpServer, agent_state:
    &Arc<AgentState>, audit_ring: &Arc<AuditRing>) -> McpServer`. Final body: apply
    `with_agent_state` and `with_audit_ring` with clones of the two `Arc`s and
    nothing else (no push, roles, timeouts). Its doc comment must state: it is the
    one function production (`main.rs`) and the tests share; it shares exactly the
    policy state and the audit ring; it does **not** share the `Ask` machinery
    (`Subscriptions`, parked requests, confirm tokens, connection ids stay per
    server, so `agent.approve` resolves only calls parked on the same server and an
    `approval_requested` push reaches only that server's subscribed operators); and
    the residual risk (it cannot force a future third server to call it). Add one
    sentence to the doc of `server()` pointing at the helper as the other half of "the
    gate and audit are wired by the caller".
  - `crates/aitm/tests/web_bus_ask_split.rs` (in-process, no sockets, no runtime):
    the rig `fn rig(tag: &str) -> Rig` seeds `cfg.mcp.policy = AgentPolicy::Ask` with a
    unique `cfg.ca.dir`, calls `assemble`, `services(&assembled.proxy, &cfg, None,
    TuiLog::Off)`, and builds two servers over the same `Assembled`, each with
    `.with_approval_timeout(Duration::from_secs(60))`: **P** (primary-like) through
    `tui::with_shared_governance(tui::server(..), ..)` and **W** (web-like) built the
    same way except as the phases below say. `Rig` keeps the `Proxy` alive and holds
    `primary: Arc<McpServer>`, `web: Arc<McpServer>`. Local helpers to write (names
    free): a JSON-RPC `tools/call` line builder; `subscribe_operator(&McpServer) ->
    (ConnCtx, NotificationSink)` that builds `ConnCtx { role: Frontend::Operator,
    client_label: None, conn_id: 1, out: Some(sink) }`, calls `flow.subscribe {}` and
    asserts the reply has a `u64` `structuredContent.sub_id`; `wait_for_approval_request(&NotificationSink,
    Duration) -> Option<JsonValue>` that polls `sink.drain()` every 10 ms and returns
    the first line whose `method == "notifications/aitm/agent"` and `params.event ==
    "approval_requested"` (other lines, such as audit lines, are skipped); and a
    `spawn_agent_call(&Arc<McpServer>, ..) -> JoinHandle<JsonValue>` that runs a
    `scope.add {host: "example.com"}` call as `ConnCtx::new(Frontend::Mcp)` on a
    `std::thread` (a parked call blocks its thread).
  - W's helper statement is its own one-line `let` ending with a comment
    `// MUTATION-POINT`, short enough that `cargo fmt` leaves it on one line (bind
    `state`/`ring` first). P's helper call carries no marker. Exactly one
    `MUTATION-POINT` in the file.
- **Tests (write first; each must fail first):**
  - `tui.rs` `#[cfg(test)]`: `with_shared_governance_gates_an_agent_and_audits_into_the_shared_ring`
    (AC8). `assemble` with a unique temp CA dir, `services`, `server(.., McpTransport::Stdio,
    ..)`, through the helper; `assembled.agent_state.set_policy(AgentPolicy::Paused)`. An
    agent `ConnCtx::new(Frontend::Mcp)` `flow.list` returns `result.isError == true`
    with text containing "the agent policy is `paused`"; then `ring.len() == 1`,
    `ring.recent(None, None)[0].origin == Frontend::Mcp`, `.command == "flow.list"`,
    `.result` is `AuditResult::Error(t)` with `t` containing "paused". An operator
    `ConnCtx::new(Frontend::Operator)` `flow.list` returns `isError == false` and
    `structuredContent == []`; afterwards exactly one ring entry still has origin
    `Mcp`.
  - `tui.rs` `#[cfg(test)]`: `with_shared_governance_gives_two_servers_one_audit_trail`
    (AC7). Default policy; two servers through the helper from one `Assembled`; one
    agent `flow.list` on the first, one agent `agent.status` on the second.
    `assert_eq!(ring.len(), 2)`; entries in order have commands `"flow.list"` then
    `"agent.status"`, both origin `Mcp`; an operator `agent.activity` on the first
    server returns `structuredContent[0].command == "flow.list"`,
    `structuredContent[1].command == "agent.status"`, `[0].origin == "mcp"`.
  - `web_bus_ask_split.rs`: `no_operator_on_the_web_server_refuses_a_web_call_at_once`
    (AC9): operator subscribed on **P only**; the web agent `scope.add` runs on a
    thread whose reply comes back over `mpsc` with `recv_timeout(5 s)` (panic text:
    "the web call did not return within 5s: it parked instead of refusing"); the
    reply has `isError == true` and text containing "no operator is connected to
    approve it"; `wait_for_approval_request(&p_sink, 300 ms)` is `None`.
    `an_operator_on_the_web_server_is_asked_and_resolves_on_the_web_server` (AC10):
    operator subscribed on **W**; web agent `scope.add` on a thread;
    `wait_for_approval_request(&w_sink, 5 s)` returns a line with `params.command ==
    "scope.add"` and `params.request_id` starting `apr_`; the thread is not finished;
    operator `agent.approve {request_id, allow: false}` **on W** returns `isError ==
    false`; the thread's reply has `isError == true` with text containing "an operator
    denied the parked sensitive command". On a timeout waiting for the request, the
    panic message includes the agent thread's reply when `is_finished()` (this is what
    makes the red run read "refused: the agent policy is `auto`").
    `an_approve_sent_to_the_primary_approves_nothing_parked_on_the_web_server` (AC11):
    as AC10 up to the `request_id`; then operator `agent.approve {request_id, allow:
    true}` **on P** returns `isError == true` with text containing "no parked
    request"; sleep 200 ms, then the thread is still not finished; then `allow: false`
    on W returns `isError == false` and the thread's reply is the denial text.
- **Procedure, in this order (all in the Bash sandbox; paste each output):**
  1. Add the helper as an **inert stub**: the real signature and doc comment, body
     returns `server` unchanged. `cargo build -p aitm` must end `Finished`.
  2. Write the two `tui.rs` tests. `cargo test -p aitm --lib with_shared_governance`.
     **Red must show** `test result: FAILED. 0 passed; 2 failed` and failures that are
     assertions on behaviour (AC8: the agent call was not refused, `isError` is
     `false` where `true` is expected; AC7: `left: 0` against `right: 2` on the ring
     length), not compile errors.
  3. Write `web_bus_ask_split.rs` with **W built through `tui::server(..)` only** (no
     helper line, no marker yet) and P through the (still inert) helper.
     `cargo test -p aitm --test web_bus_ask_split`. **Red must show** `test result:
     FAILED. 0 passed; 3 failed`; AC9's failure quotes a refusal text containing "the
     agent policy is `auto`" where "no operator is connected to approve it" is
     expected; AC10 and AC11 fail with "no approval_requested within 5s" and the agent
     reply "the agent policy is `auto`".
  4. Replace the stub body with the real one. `cargo test -p aitm --lib
     with_shared_governance` **must show** `2 passed; 0 failed`. Re-run
     `cargo test -p aitm --test web_bus_ask_split`: **must still show** `3 failed`
     (W still omits the helper, P is now truly governed), which proves the red cause
     is W's wiring.
  5. Add W's marked helper line. `cargo test -p aitm --test web_bus_ask_split` **must
     show** `test result: ok. 3 passed; 0 failed`.
  6. `cargo fmt --check` (exit 0), `cargo clippy -p aitm --all-targets -- -D warnings`
     (exit 0), `cargo test -p aitm --lib tui::` (all pass, including the existing
     `tui` tests).
- **Tester (stage 5, after the Coder):** inputs per the dispatch contract (spec, plan,
  worktree, base `2bdcb07`, head SHA, "Task 1"). Map AC7-AC11 to the five tests;
  re-run steps 4-6 in the sandbox and quote them; confirm exactly one `MUTATION-POINT`
  in `web_bus_ask_split.rs`; confirm no file other than the two declared changed
  (`git diff --name-only` is run by the orchestrator and handed over).
- **Done when:** the red runs of steps 2, 3 and the still-red of step 4 are in the
  report, the green runs of steps 4 and 5 are in the report, and step 6 is clean. The
  orchestrator then commits.

### Task 2: the real-socket tests (AC1-AC6, AC16, AC12 socket half)

- **Satisfies:** AC1, AC2, AC3, AC4, AC5, AC6, AC16; AC12 (socket half).
- **Depends on:** Task 1 (the helper).
- **Files:** `crates/aitm/tests/web_bus_governance.rs` (create). Edit no other file:
  not `web_bus_roles.rs`, `web_bus_concurrency.rs`, `web_bus_push.rs`, `tests/support/`.
- **Socket tests cannot run in the sandbox.** The Coder writes and compiles; the
  orchestrator runs them in the Terminal panel.
- **Change:**
  - Copy, as small private helpers, what the file needs from `web_bus_push.rs` (shapes
    at lines ~80-89, ~395-535 there): `temp_ca_dir`; a `Server { addr, task, _proxy }`
    whose `Drop` aborts the serve task; `ws_connect`, `send_text`, `next_frame`,
    `recv_until` (deadline, and the skipped frames in the panic message), `drain_for`,
    `call_line_with`, `open_bus(server, token, expected_role)` (sends the token line, then
    `initialize`, asserts the `role` echo). Add `async fn call(ws, id, name, arguments) ->
    JsonValue` that sends one `tools/call` and returns the **whole reply** whose `id`
    matches (notifications skipped); tests assert on `reply["result"]` and print the whole
    reply in every assertion message. Constants: `AGENT_TOKEN`, `OPERATOR_TOKEN` (64
    distinct hex characters each), `TIMEOUT` 10 s, `FAST` 5 s, `QUIET` 300 ms.
  - The rig, `async fn start(tag: &str, policy: AgentPolicy) -> Server`, always with the
    operator bridge token configured, built as `main.rs` builds the web server: set
    `cfg.mcp.policy = policy` and a unique `cfg.ca.dir`; `assemble(&cfg)`;
    `services(&assembled.proxy, &cfg, None, TuiLog::Off)`; `tui::server(&cfg,
    cfg.mcp.transport.clone(), &services)`; the **marked helper line** (its own
    one-line statement ending `// MUTATION-POINT`, with `state`/`ring` bound first so
    `cargo fmt` keeps it on one line); then `.with_push(assembled.push_tx.clone())` and
    `.with_approval_timeout(TIMEOUT)`; `Arc::new`; `spawn_push_dispatcher()`;
    `WebState { mcp, agent_token, operator_token: Some(..) }`; bind `127.0.0.1:0`;
    `tokio::spawn(web::serve(listener, state))`. Exactly one `MUTATION-POINT` in the file.
- **Tests** (exact names; each `#[tokio::test]`; literal expected values from the spec):
  - `readonly_web_agent_reads_but_cannot_write_or_widen` (AC1). Seed `ReadOnly`; agent
    token. `agent.status` -> `result.isError == false`, `structuredContent.policy ==
    "readonly"`. `flow.kill` and `scope.add` (no arguments) -> `isError == true`, text
    contains "`flow.kill` refused" / "`scope.add` refused" and "the agent policy is
    `readonly`".
  - `paused_web_agent_is_refused_everything_but_the_handshake` (AC2). Seed `Paused`;
    agent token. `agent.status`, `flow.list`, `flow.kill`, `scope.add`, `flow.subscribe`
    each -> `isError == true`, text contains "the agent policy is `paused`". The
    `initialize` echo is `role == "agent"` (via `open_bus`); `tools/list` returns a
    non-empty `result.tools` containing `"flow.list"`.
  - `web_agent_follows_a_live_agent_set_without_reconnecting` (AC3). Seed `Auto`; one
    long-lived agent connection and one operator connection, both opened first. Agent
    `flow.list` -> `isError == false`. Operator `agent.set {policy: "paused"}` ->
    `structuredContent.policy == "paused"`; operator `agent.status.policy == "paused"`;
    the **same** agent connection's next `flow.list` -> `isError == true`, "the agent
    policy is `paused`". Operator `agent.set {policy: "auto"}`; operator
    `agent.status.policy == "auto"`; the same agent connection's `flow.list` ->
    `isError == false`.
  - `operator_bridge_connection_stays_ungated_under_paused` (AC4, guard). Seed
    `Paused`; operator token. `initialize` echo `role == "operator"` (via `open_bus`);
    `agent.status` and `flow.list` -> `isError == false`; `agent.set {policy: "auto"}`
    -> `isError == false`, `structuredContent.policy == "auto"`.
  - `web_agent_calls_land_in_the_shared_audit_trail` (AC5). Seed `ReadOnly`, fresh
    server. Agent: `agent.status` then `flow.kill`; keep both replies and assert them
    **last** (`isError` `false`, then `true`). Then a **new** operator connection whose
    first tool call is `agent.status` -> `structuredContent.actions_last_minute == 2`;
    its next call, `agent.activity`, returns an array whose `[0]` is `origin "mcp"`,
    `command "agent.status"`, `result "ok"` and whose `[1]` is `origin "mcp"`, `command
    "flow.kill"`, `result.error` containing "readonly"; any entry beyond `[1]` has
    `origin "operator"`. The audit assertions run before the agent-reply assertions so
    that, without the helper, the failure is the audit count (`0` where `2` is
    expected), which is the criterion this test exists for.
  - `default_auto_still_refuses_a_sensitive_web_agent_call` (AC6, guard). Seed `Auto`;
    agent token. `flow.list` -> `isError == false`; `scope.add` -> `isError == true`,
    text contains "the agent policy is `auto`".
  - `ask_parks_a_web_agent_call_for_an_operator_on_the_same_bridge` (AC16). Seed `Ask`.
    Operator connection sends `flow.subscribe {}`; the reply (found by `id`; a
    notification may arrive first) has a `u64` `structuredContent.sub_id`. Agent
    connection sends `scope.add {host: "example.com"}` and the test does **not** wait
    for its reply. The operator socket receives, within `FAST`, a frame with `method ==
    "notifications/aitm/agent"`, `params.event == "approval_requested"`,
    `params.command == "scope.add"`, `params.request_id` starting `apr_`. If it does not
    arrive, the panic message includes whatever `drain_for(agent, QUIET)` returns (so
    the red run shows the agent's "the agent policy is `auto`" refusal). The agent
    socket has delivered no reply for its call yet (`drain_for(agent, QUIET)` holds no
    frame with that `id`). Operator `agent.approve {request_id, allow: false}` over the
    same bridge connection -> `isError == false`. The agent's `scope.add` reply then
    arrives: `isError == true`, text contains "an operator denied the parked sensitive
    command". Operator `agent.status` -> `structuredContent.policy == "ask"`.
- **Procedure:**
  - **Pass A (Coder, sandbox).** Write the file with the rig **without** the marked
    helper line (so `tui::server(..)` is the web server, exactly as `main.rs` built it
    before this change). Run `cargo test -p aitm --test web_bus_governance --no-run`
    (**must end** `Finished` and print `Executable ... web_bus_governance`), `cargo fmt
    --check`, and `cargo clippy -p aitm --all-targets -- -D warnings` (both exit 0).
    Report: compile output only, plus "socket tests compiled, NOT RUN". Do not commit.
  - **Red run (orchestrator, Terminal panel):**
    `cargo test -p aitm --test web_bus_governance > /tmp/web-bus-governance-red.log 2>&1; echo "exit=$?"; grep -E "^test |^test result" /tmp/web-bus-governance-red.log`
    **Must show** `exit=101`, five `FAILED` and two `ok`, and `test result: FAILED. 2
    passed; 5 failed`. `ok`: `operator_bridge_connection_stays_ungated_under_paused` and
    `default_auto_still_refuses_a_sensitive_web_agent_call` (the guards). `FAILED`:
    AC1 (policy `"auto"` where `"readonly"` is expected), AC2 (`agent.status` not
    refused), AC3 (the agent's `flow.list` after `agent.set paused` not refused), AC5
    (`actions_last_minute` is `0` where `2` is expected), AC16 (no `approval_requested`
    within 5 s). Any other failure cause (a connect error, a compile error, a panic
    in the rig) means the test is wrong: send it back to the Coder, do not proceed.
    Save the log; its lines go in the report.
  - **Pass B (Coder, sandbox, second dispatch of "Task 2 pass B").** Add the marked
    helper line to the rig. `--no-run`, `cargo fmt --check`, `cargo clippy` as above.
    Report the compile output; exactly one `MUTATION-POINT` in the file.
  - **Green run (orchestrator, Terminal panel):**
    `cargo test -p aitm --test web_bus_governance > /tmp/web-bus-governance-green.log 2>&1; echo "exit=$?"; grep -E "^test |^test result" /tmp/web-bus-governance-green.log`
    **Must show** `exit=0` and `test result: ok. 7 passed; 0 failed`. Also run
    `cargo test -p aitm --test web_bus_roles --test web_bus_concurrency --test web_bus_push`
    in the Terminal: `exit=0` (AC14, unmodified files).
- **Tester (stage 5):** inputs as Task 1 with "Task 2", plus the two Terminal logs as
  attached files. Map AC1-AC6 and AC16 to the seven tests; flag any assertion that
  would pass on a default (for example a test that never reads `result.isError`);
  re-run `--no-run`, fmt, clippy in the sandbox. The Tester **must not** report a
  socket test as run unless its output is attached; it may add tests only inside
  `web_bus_governance.rs`.
- **Done when:** the red log (5 failed, 2 ok) and the green log (7 passed) are in the
  report, the three existing web_bus binaries pass, and fmt and clippy are clean.
  The orchestrator then commits.

### Task 3: production wiring and the three doc comments (AC13)

- **Satisfies:** AC13.
- **Depends on:** Task 1 (the helper). Tests from Task 2 are the regression net.
- **Files:** `crates/aitm/src/main.rs` (modify, the web run block only),
  `crates/aitm/src/wire.rs` (modify, doc comments on two `Assembled` fields only),
  `crates/aitm/src/web/mod.rs` (modify, module doc only).
- **Change:**
  - `main.rs`, in the non-TUI branch. **Primary:** wrap its `tui::server(..)` in
    `tui::with_shared_governance(.., &agent_state, &audit_ring)` and delete the two now
    redundant direct calls, `.with_agent_state(agent_state)` and
    `.with_audit_ring(audit_ring)`; keep `.with_mcp_roles(..)` and
    `.with_push(push_tx.clone())`. **Web `bus`:** wrap its `tui::server(..)` the same
    way, then keep the existing `.with_push(push_tx)`, the `Arc::new(..)`, and
    `bus.spawn_push_dispatcher()` exactly as PR 137 left them. The helper takes
    references, so nothing is moved twice. Do not touch the `tui::run` branch,
    `build_servers`, `wire::assemble_with_scripts`, or any other line.
  - Rewrite the stale comment above the primary ("The web bridge and the TUI are
    operator frontends, built by `tui::server` without the gate"). New content, in the
    same place: the bare-`aitm` server path carries the operator/agent token classes,
    the shared agent policy gate, the push fan-out and the audit ring; the **web bridge
    is not exempt**: its agent bridge token resolves to `Frontend::Mcp`, so it is gated
    like any agent and must read the policy `agent.set` writes and record into the ring
    `agent.activity` reads, which is why both servers go through
    `tui::with_shared_governance`; only the operator bridge token (present only when
    `mcp.operator_token` is configured) is un-gated, by role; the TUI's own in-process
    server (in `tui::build_servers`) is the operator and bypasses the gate by role.
  - `wire.rs`: replace the doc comments of `Assembled::agent_state` and
    `Assembled::audit_ring`. Each must say: apply it with `tui::with_shared_governance`
    to **every agent-facing server** (the primary and the `aitm web` bridge server), and
    each must state the `Ask` split in one sentence (the shared pair does not share the
    approval hub: each server parks and approves its own calls, so `agent.approve`
    resolves only calls parked on the same server). Use plain backticks, not intra-doc
    links. Keep the existing statements about `agent.set` / `agent.activity` /
    `AgentPlugin`.
  - `web/mod.rs`: add a paragraph to the module doc saying the `McpServer` in `WebState`
    is agent-facing (the agent bridge token is `Frontend::Mcp`), is to be built with
    `tui::with_shared_governance`, and that the `Ask` split applies (a web agent's
    `Sensitive` call under `ask` parks only for an operator bridge connection subscribed
    on this server; `agent.approve` must be sent on this server). Change nothing else
    in the file.
- **Test:** no new automated test. The spec makes AC13 review-checked (a source-grep
  test over `main.rs` was rejected as brittle), and the behaviour the wiring selects is
  already pinned through the same helper by Tasks 1 and 2. The proof is these literal
  checks, run by the Coder in the sandbox, output pasted:
  - `grep -c 'tui::server(' crates/aitm/src/main.rs` prints `2`.
  - `grep -n 'with_shared_governance(' crates/aitm/src/main.rs` prints exactly two
    lines (the two call sites).
  - `grep -n 'operator frontends' crates/aitm/src/main.rs` prints nothing (exit 1).
  - `grep -n 'with_agent_state\|with_audit_ring' crates/aitm/src/main.rs` prints nothing
    (exit 1).
  - `grep -n 'with_shared_governance' crates/aitm/src/wire.rs` has a hit inside the
    `agent_state` doc and a hit inside the `audit_ring` doc; the same grep on
    `crates/aitm/src/web/mod.rs` has at least one hit; `grep -n 'Ask'` on both files
    shows the split sentence.
  - The new comments may name `tui::server` and `tui::with_shared_governance` but not
    with a trailing opening parenthesis, so the two greps above count call sites only.
  - `cargo build -p aitm` ends `Finished`; `cargo fmt --check` and `cargo clippy -p aitm
    --all-targets -- -D warnings` exit 0; `cargo test -p aitm --lib tui::` and
    `cargo test -p aitm --test web_bus_ask_split` still pass (sandbox). The Coder
    states plainly that it could not run the socket tests.
- **Tester (stage 5):** inputs as Task 1 with "Task 3". Re-run the greps and the
  sandbox commands; read the `main.rs` diff against the bullet list above (both servers
  wrapped, nothing else moved, the three comments say what the spec's Design 3 says);
  confirm the diff touches only the three declared files.
- **Done when:** every literal check prints what is stated, the sandbox commands are
  clean, and the orchestrator has committed.

### Task 4: orchestrator checkpoint (Terminal panel; no Coder, no retained edits)

- **Satisfies:** AC12 (final head), AC14, AC15; spot-checks AC13.
- **Depends on:** Tasks 1-3 committed.
- **Files:** none retained. The AC12 step temporarily edits two test files and
  restores them.
- **Steps and required output** (orchestrator, Terminal panel):
  1. **Full gate**, on the final head:
     `(cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test) > /tmp/web-bus-governance-gate.log 2>&1; echo "gate exit=$?"`
     **Must print** `gate exit=0`. Then
     `grep -E "Running tests/web_bus|^test result" /tmp/web-bus-governance-gate.log`
     lists `web_bus_ask_split`, `web_bus_concurrency`, `web_bus_governance`,
     `web_bus_push`, `web_bus_roles`, each followed by `ok`. Known flake: if
     `rhai_e2e::script_cannot_escape_or_exceed_scope` is the only failure, re-run once and
     judge by whether this diff touches Rhai (it does not); record it in the Review log.
  2. **AC12 mutation (final head).**
     `sed -i.bak '/MUTATION-POINT/d' crates/aitm/tests/web_bus_governance.rs crates/aitm/tests/web_bus_ask_split.rs`
     then
     `cargo test -p aitm --no-fail-fast --test web_bus_governance --test web_bus_ask_split > /tmp/web-bus-governance-mutated.log 2>&1; echo "exit=$?"; grep -E "^test |^test result" /tmp/web-bus-governance-mutated.log`
     (`--no-fail-fast`, so the second binary runs after the first fails.)
     **Must show** `exit=101` and fourteen tests in all (seven socket, seven in-process;
     the Tester added four in-process edge tests and an AC9 control after this plan was
     written, so the original "ten tests, eight FAILED, `3 failed`" counts are superseded):
     exactly twelve `FAILED`, namely AC1, AC2, AC3, AC5, AC16 (socket) and all seven
     in-process tests, with the two guards (AC4, AC6) `ok`. The summary lines read
     `test result: FAILED. 2 passed; 5 failed` for `web_bus_governance` and `test result:
     FAILED. 0 passed; 7 failed` for `web_bus_ask_split`. Each failure message must name
     the policy or audit cause (the `"auto"` policy, a missing refusal,
     `actions_last_minute` `0`, no `approval_requested`), not a connect or compile
     error. Then restore:
     `mv crates/aitm/tests/web_bus_governance.rs.bak crates/aitm/tests/web_bus_governance.rs && mv crates/aitm/tests/web_bus_ask_split.rs.bak crates/aitm/tests/web_bus_ask_split.rs`
     and `git status --short` prints nothing for those two files and no `.bak` file
     remains; re-run the same cargo command: `exit=0`, `7 passed` and `7 passed`.
  3. **AC15 and AC14 diff checks** (explicit base SHA, since `origin/main` moves):
     `git diff --stat 2bdcb07..HEAD -- crates/aitm-mcp crates/aitm-core` prints nothing;
     `git diff --stat 2bdcb07..HEAD -- crates/aitm/tests/web_bus_roles.rs crates/aitm/tests/web_bus_concurrency.rs crates/aitm/tests/web_bus_push.rs`
     prints nothing; `git diff --name-only 2bdcb07..HEAD` lists only:
     `crates/aitm/src/main.rs`, `crates/aitm/src/tui.rs`, `crates/aitm/src/web/mod.rs`,
     `crates/aitm/src/wire.rs`, `crates/aitm/tests/web_bus_ask_split.rs`,
     `crates/aitm/tests/web_bus_governance.rs`, plus this plan and the spec.
  4. **AC13 spot-check:** re-run Task 3's literal greps on the head.
- **Done when:** all four steps print what is stated, with the logs saved and quoted in
  the whole-branch Tester report.

## Whole-branch stage 5 and stage 6

1. **Whole-branch Tester** (after Task 4): inputs per the dispatch contract (spec,
   plan, worktree, base `2bdcb07`, head SHA, "whole branch"), with the Task 4 logs
   attached. Every criterion AC1-AC16 maps to a test or a literal check; the Tester
   quotes the gate output. PASS or FAIL with reasons.
2. **Panel, in parallel, fresh contexts:** `security-reviewer`, `quality-reviewer`,
   `spec-reviewer`, each given the spec, plan, worktree, base `2bdcb07`, head SHA, "whole
   branch", the Coders' reports, and the Tester report. Suggested focus, not a limit.
   Security: the web agent cannot reach any command the primary's gate would refuse
   under the same policy; the operator bridge stays un-gated and the agent role still
   cannot `agent.approve`; a web agent can now park a blocking thread under `ask` (bounded
   by 64 parked per server, the approval timeout, 16 in-flight frames per connection),
   and the shared ring is now written by two servers. Quality: duplicated socket helpers
   (accepted by the spec), the `MUTATION-POINT` markers, test determinism (bounded
   waits, no sleeps standing in for sync except the one stated 200 ms negative check),
   comment accuracy in `main.rs`/`wire.rs`/`web/mod.rs`. Spec: AC1-AC16 against the
   tests, that nothing outside `crates/aitm` and the spec/plan changed, that the spec's
   `Status` line is untouched, that the seven consequences in Design 6 are in the PR
   description.
3. The orchestrator records every finding and disposition in the Review log below.
   Critical and Important findings go to a fresh Coder as a fix task, then Tester and
   panel run again on the fix with the prior report. No merge with an open finding.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 1 | Tester | Important (gate) | AC8 unit test in `tui.rs` compared `e.origin == Frontend::Mcp`, the deny-list shape `aitm-core`'s `trust_gate_scan` rejects in any `src`; the full gate exited 101 on head `3de6b00`. | Fixed in `2d2a932` (exact origin-list assertion, stricter). Gate re-run green: `gate2 exit=0`. |
| 1-3 | Tester | n/a | Four new `Ask` edge tests (agent cannot approve its own call; agent cannot `agent.set` under `ask`; malformed approve resolves nothing; web call refused at once after the operator disconnects) plus an AC9 control. | Added in `2d2a932`, inside the declared test file. |
| all | Spec | none | PASS; no findings. Notes: plan counts stale after the four extra tests (mutated `web_bus_ask_split` expects `0 passed; 7 failed`, 12 FAILED of 14 with AC4/AC6 ok); plan Task 2 red expectation for AC1 names the policy where the actual red is `flow.kill`. | Plan-text drift recorded here; no defect. |
| all | Quality | Minor | Helper doc claims a test rig cannot pass while the binary is wired differently; its own last paragraph says otherwise. | Fixed in b11c510 (doc reworded). |
| all | Quality + Security | Minor | "every agent-facing server" in `tui.rs`/`wire.rs` docs is false for the `aitm tui` loopback agent server (spec Design 7). | Fixed in b11c510 (docs say "both servers the bare-`aitm` run builds"; comment at `build_servers`). Underlying gap is the named follow-up "tui-mode governance" (proposed as a task card). |
| 2 | Quality | Minor | `state` shadowed by an unrelated type in the socket rig; `Arc::clone`s not needed. | Fixed in b11c510. |
| 1 | Quality | Minor | `assert_denied` doc wrong and defined after use; thread/`mpsc`/`recv_timeout` block copied. | Fixed in b11c510 (see the fix task report for what was folded). |
| 1 | Quality | Minor | Hard-coded "5s" in panic messages; `is_none()` assertions drop the offending push. | Fixed in b11c510. |
| 2 | Quality | Minor | Socket tests leave throwaway CA keys in the temp dir. | Fixed in b11c510 (`Server::drop` removes the CA dir). |
| 1-2 | Quality | Minor | "Tester:" role labels in comments; `MUTATION-POINT` markers carry no reason. | Fixed in b11c510. |
| 3 | Quality | Minor | The `Ask`-hub caveat is repeated in four places. | Fixed in b11c510 (full statement on the helper only). |
| 3 | Quality | Minor (optional) | Bind `main.rs`'s two near-identical wrapper call sites in one local closure. | Not adopted: two call sites, different builder tails, and it widens the `main.rs` diff that PR 137 and its follow-ups also edit. Accepted (autonomous-approve mode). |
| all | Quality | Residual | Tests would not catch a third server (or a reverted `main.rs`) that skips the helper. | Accepted: the spec states this residual risk (Design 3); a real-binary e2e canary is a named follow-up. |
| 3 | Security | Minor | Tightening the policy (`paused`, or leaving `ask`) does not revoke standing push subscriptions or already-parked requests; identical on every agent surface; an `aitm-mcp` change (AC15 forbids it here). | Accepted for this change (autonomous-approve mode): pre-existing on every surface, not a bypass of the primary's gate. Stated in the PR description; follow-up proposed as a task card. |
| 3 | Security | Minor | Shared ring: a web agent can flood it (4096 calls in one burst) and evict other surfaces' evidence; web-bridge entries (`origin: mcp`, `client_label: null`) are indistinguishable from a TCP agent that sent no `clientInfo`. | Accepted for this change (autonomous-approve mode): same class as Design 6.4, the cheap fix (a fixed bridge `client_label`) changes persisted findings and CA-audit labels and edits `bridge.rs` outside this spec. Stated in the PR description; follow-up proposed as a task card. |
| all | Security | Minor | Nothing guards that `main.rs` actually calls the helper. | Accepted: spec Design 3 residual risk; a real-binary e2e canary is a named follow-up. |
| fix | Quality (re-review of b11c510) | none open | PASS: all 8 Minors verified fixed, no assertion weakened, production `src` delta comments only. One new Minor: "The tests never run `main.rs` itself" overstates (`shutdown.rs` spawns the real binary under `AITM_OBSCURA=1`). | Fixed in the next commit (reworded to "No test exercises the governance wiring in `main.rs`"; comment only). |

## Shipped

Branch `claude/loving-cartwright-2e400f`, cut from `origin/main` `2bdcb07` (PR 137), opened as a PR against `main`; no open Critical or Important finding, every Minor fixed or accepted above.

**What shipped.** `tui::with_shared_governance` (one function, `crates/aitm/src/tui.rs`) puts the `aitm web` bridge server on the primary's `AgentState` and `AuditRing`; `main.rs` calls it for both servers. Tests: `tui.rs` unit tests (AC7, AC8), `web_bus_ask_split.rs` (7 in-process, AC9-AC11 plus four edge tests), `web_bus_governance.rs` (7 real-socket, AC1-AC6, AC16). Doc comments in `tui.rs`, `wire.rs`, `web/mod.rs`, and the rewritten comment in `main.rs`.

**Evidence.** Socket tests red without the helper (`5 failed; 2 passed`, the 2 are the guards) and green with it (`7 passed`). Full gate `gate3 exit=0` on `b11c510` (1767 passed, 0 failed); the head `d7e7efa` differs from it by one doc comment and this plan, with `cargo fmt --check` and `cargo clippy -p aitm --all-targets -- -D warnings` re-run clean. Final-head AC12 mutation (helper line deleted from both rigs): `0 passed; 7 failed` for `web_bus_ask_split`, `2 passed; 5 failed` for `web_bus_governance` (the 2 are the AC4/AC6 guards), every failure on the private-`auto` gate or the empty ring, none a compile or connect error; files restored, tree clean. AC14: `web_bus_roles` 5, `web_bus_concurrency` 11, `web_bus_push` 10, unmodified. AC15: nothing under `crates/aitm-mcp` or `crates/aitm-core`.

**Cut / deviations.** Per-task Tester passes were consolidated into one whole-branch Tester pass (Tasks 1-3 are small and file-disjoint); the panel ran once on the branch, plus a quality re-review of the fix.

**Follow-ups (each a proposed task card).** (1) "tui-mode governance": `aitm tui`'s loopback agent server has a private `AgentState` and ring, so `agent.set` does not reach its gate (Design 7). (2) `paused` / leaving `ask` should revoke standing push subscriptions and already-parked requests (an `aitm-mcp` change). (3) Audit signal-to-noise: ring flooding by one web agent, web-bridge attribution (a fixed bridge `client_label` changes persisted findings and CA-audit labels, so it needs its own change). Also named in the spec, not proposed: a real-binary e2e canary for the `main.rs` wiring; the unified `Ask` hub (now unblocked by PR 137); a configurable startup policy (open question for Matt: should `mcp.policy` be a real config key / env / flag).
