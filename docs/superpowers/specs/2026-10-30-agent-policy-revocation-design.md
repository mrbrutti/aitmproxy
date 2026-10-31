# Agent policy revocation design

**Status:** Approved (self-approved in autonomous-approve mode, 2026-10-30; no open question needs Matt, both defaults stand)
**Research inputs:** code reading of `crates/aitm-mcp/src/server.rs` (`McpServer::policy_decision`, `read_refusal`, `park_for_approval`, `handle_approve`, `push_flow_event`, `push_state`, `push_agent`, `record_audit`, `subscribe`, `replay_since`, `Subscriptions` and its three `fanout_*` functions, `SubState`, `NotificationSink::{push, drain}`, `ParkedRequests`, `ParkSlot`, the in-file `mod tests`), `crates/aitm-core/src/{agent,ctx}.rs` (`AgentPolicy`, `AgentState`, `Frontend::is_trusted_control`), `crates/aitm-core/tests/trust_gate_scan.rs`, `crates/aitm-plugins/src/agent.rs` (`agent.set`), `crates/aitm-mcp/src/{transport,http}.rs` and `crates/aitm/src/web/bridge.rs` (where sinks and roles come from), `crates/aitm-mcp/tests/mcp.rs` (the push, `Ask`, and loopback-socket rigs), `crates/aitm/src/tui.rs` (`with_shared_governance`, `build_servers`). The finding being closed is the Security reviewer's Minor, Review log row 3, in `docs/superpowers/plans/2026-10-30-web-bus-agent-governance-plan.md`. Nearest prior spec for tone: `docs/superpowers/specs/2026-10-30-web-bus-agent-governance-design.md`. Base: `main` at `bd0f9b7`.

## Intent

The agent policy gate (`policy_decision`, `read_refusal`) only looks at **new** `tools/call` requests. Tightening the policy therefore does not revoke what an agent-role connection was already granted. Two grants outlive a tightening today. (a) A subscription made with `flow.subscribe` keeps receiving `notifications/aitm/flow` summaries (method, authority, path, status; the path is not redacted) and every `notifications/aitm/agent` audit line after an operator runs `agent.set paused`, because the fan-out functions consult no policy. (b) A Sensitive call parked under `ask` stays approvable through `agent.approve` after the policy has left `ask`, and approving it then runs the command even though the policy is, say, `paused`. `AgentPolicy::Paused` is documented "Nothing from the agent runs", and an operator who pauses an agent expects the agent's access to stop, not only its next request. This change makes the policy a live decision on the push path and on the parked-request path, so a tightening takes effect on grants already made, on every agent surface, with no reconnect.

## Goals

- After `agent.set paused`, no agent-role connection is sent any new `notifications/aitm/{flow,state,agent}` line, on any `McpServer` that shares the policy state.
- Relaxing the policy again resumes delivery on the same connection and the same subscription, with no re-subscribe, and tells the agent that it has a gap (the existing `lagged` state line) exactly when something was suppressed.
- Operator and CLI connections are never muted. An operator pausing an agent in the middle of an incident keeps its full stream.
- A Sensitive call parked under `ask` never runs after the policy has left `ask`: it is denied, promptly, and the operator who tries to approve it is told why.
- One predicate decides both "may this agent subscribe now" and "does this agent receive pushes now", so the two cannot drift.
- The guarantee and its accepted residuals are stated precisely enough to test (Design 6).

## Non-goals

- **Closing, killing, or disconnecting agent connections** on a policy change (Design 9, alternative 1).
- **Unregistering subscriptions** on a policy change. They stay registered and are muted (Design 9, alternative 2).
- **Any change to `aitm-core` or `crates/aitm`.** `AgentState` stays one `AtomicU8`. No watcher, callback list, generation counter, or notify is added there, and `agent.set` is not hooked.
- **Replaying what was suppressed** when delivery resumes. The agent is told it has a gap and catches up with `flow.list` / `flow.subscribe {since}`.
- **Purging lines already queued in an agent sink** when the policy tightens (Design 6, residual R1).
- **A new operator-facing event** announcing that a parked request was withdrawn. The audit line that records the denial is the signal (open question 1).
- **A real `/bus` WebSocket test.** The two-servers-one-state rig in `aitm-mcp` reproduces the `/bus` topology; a `crates/aitm` test is out of the scope fence.
- **TUI mode.** `tui::build_servers` still gives the loopback agent server a private `AgentState`, so `agent.set` never reaches its gate, and therefore never reaches this revocation either. Same named follow-up as in the PR 145 spec (Design 7, "tui-mode governance"). Not touched here.
- Changing any refusal text for a new call, the policy matrix (`policy_decision`), the default policy, `Ask` routing (`any_role(Frontend::Operator)`, `fanout_role(Frontend::Operator, ..)`), or the `NotificationSink` API.
- Redacting the `path` in flow summaries. Muting removes the exposure under `paused`; whether `readonly` agents should see unredacted paths is the existing posture of `flow.list`, not this change's question.

## Anti-goals

- A **snapshot** mute: a flag flipped at `agent.set` time on the server that ran it. The web `/bus` server is a second `McpServer` that shares the primary's `AgentState` but has its own `Subscriptions` and `ParkedRequests`; a flag set on one server never reaches the other. The policy is read at use, from the shared state.
- Muting that leaks while paused: a "you are muted" notice, the `lagged` marker emitted while the policy is still `paused`, or any other line that tells a paused agent that something happened.
- Grant by side effect: a policy change that approves or runs a parked call, or a resume that replays suppressed lines.
- Two predicates: one in `read_refusal` for subscribing and another in the fan-out for delivering.
- Muting an operator or CLI stream, or comparing against the agent role (`== Frontend::Mcp`, `matches!`, `if let`) to decide who is muted. `crates/aitm-core/tests/trust_gate_scan.rs` rejects those shapes in any `crates/*/src` file; use `is_trusted_control()`.
- Widening the diff into code sibling sessions are editing: `run_tool`, `call_tool`, `subscribe`, `enforce_verb_schema`, `Subscriptions::{add, remove, any_role}`.

## Constraints

- **Edits stay in `crates/aitm-mcp`**: `src/server.rs` (production code and its existing in-file `#[cfg(test)] mod tests`) and `tests/mcp.rs`. `aitm-core`, `aitm-plugins`, and `crates/aitm` are untouched (diff-checkable, AC19).
- **Fail closed.** A parked request that cannot be proven still valid under `ask` is denied. An unknown future `AgentPolicy` posture is not `Ask`, so it denies parked requests. The one place the repo's "a future posture fails closed" doctrine is deliberately not followed is the read predicate (Design 1): `read_refusal` today allows an unknown future posture, and the push predicate follows it so the two stay equal. Whoever adds a new `AgentPolicy` variant decides that posture in the one helper.
- **Hot path.** The policy read is one `Relaxed` atomic load per fan-out call (not per subscription), taken after the registry lock. The recheck in a parked waiter is one atomic load per slice. Both negligible. The registry lock and the sink lock keep their present nesting (registry lock outside, sink lock inside); nothing new is taken while the registry lock is held. The park slot's mutex is held only around its own state and the lock-free policy load.
- **Ordering.** `AgentState` uses `Relaxed` atomics. That is sufficient for the stated guarantee because the guarantee is about causally ordered events: the operator's `agent.set` reply is received before the follow-up request is sent, and a single atomic is read in modification order. Same argument the PR 145 spec made.
- **No new dependencies, no `unsafe`.**
- **Sandbox.** The one loopback-socket test (AC18) binds `127.0.0.1:0` and runs from the Terminal panel, like the existing loopback tests in `tests/mcp.rs`. Every other test is in-process (threads, no ports) and runs anywhere.
- **The gate.** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` passes.

## Design

### 1. Principle and the one predicate

A push is a read channel: everything on it (flow summaries, audit lines) is available to the agent through a `Read` command (`flow.list`, `agent.activity`) whenever it may read. So pushes are allowed to exactly the extent that reads are, and `read_refusal` already defines that extent: it refuses `flow.subscribe` and `flow.unsubscribe` for a non-trusted-control role under `Paused` and nothing else.

**Decision.** Extract that one decision into a private free function in `server.rs`, `fn agent_reads_allowed(policy: AgentPolicy) -> bool` (Architect's call: name and placement). It returns `false` for `Paused` and `true` for every other value, including an unknown future posture, which keeps `read_refusal`'s present behaviour byte for byte. `read_refusal` is rewritten to ask it. A private `McpServer` method (proposed `agent_pushes_muted(&self) -> bool`, builder's name) is the other caller: it is `!agent_reads_allowed(self.agent_state.policy())` and is what the push path asks.

**Invariant.** For a subscription whose connection role is not trusted control, a push is delivered iff a fresh `flow.subscribe` from that role would be accepted by `read_refusal` at that moment. (Other subscribe refusals, a closed sink and the per-connection cap, are about registration, not policy, and are outside the invariant.) AC5 tests it over all five policies.

The `read_refusal` text for `paused` must stay byte-identical (existing tests assert "the agent policy is `paused`"). Building it from `policy.label()` is allowed and keeps it identical for `paused`.

### 2. Behaviour table

Pushes. Rows are the policy in effect when the push is made.

| Policy | Agent-role subscription (`flow`, `state`, `agent` lines) | Trusted-control subscription (Operator, Cli) |
|---|---|---|
| `all`, `auto`, `ask`, `readonly` | delivered (unchanged) | delivered |
| `paused` | **not enqueued**; the connection is marked as having a gap | delivered |
| a future `#[non_exhaustive]` posture | delivered (follows `read_refusal`) | delivered |

The three push kinds behave identically; AC4 checks each. `approval_requested` lines go to Operator subscriptions only, under every policy, and never to agent subscriptions: unchanged. The first line delivered to an agent-role connection after a gap is immediately preceded by one `notifications/aitm/state {"lagged":true}` line (Design 4).

Parked Sensitive agent call (parked under `ask`).

| What happens while it is parked | Before | After |
|---|---|---|
| Policy stays `ask`; operator `agent.approve allow:true` | runs | runs (unchanged) |
| Policy stays `ask`; operator `agent.approve allow:false` | refused | refused (unchanged) |
| Policy stays `ask`; nothing happens until the approval timeout | refused on timeout | refused on timeout, text unchanged |
| Policy re-set to `ask` (no change) | n/a | **not** denied |
| Policy moves to any other value; operator `agent.approve allow:true` | **runs** | approve returns an error; request denied; command does not run |
| Policy moves to any other value; operator `agent.approve allow:false` | refused | refused; reply is success (a denial is always honoured) |
| Policy moves to any other value; nobody approves | stays parked until the timeout; a late approve would run it | denied by the waiter within one recheck slice, naming the policy change |
| Operator approves, then policy moves before the waiter wakes | runs | denied (the waiter rechecks after waking) |
| Policy leaves `ask` and returns to `ask` inside one slice, with no approve call between | n/a | not observed; still parked and approvable under the policy then in force (residual R3) |

### 3. Muting pushes: one chokepoint, and the gap bit

`Subscriptions` has three near-duplicate fan-out loops (`fanout_role`, `fanout_flow`, `fanout_state`), each calling `sub.sink.push` itself. **Decision (Architect's call):** collapse them onto one private helper that is the only code in `server.rs` that pushes to a subscription's sink on a fan-out. The three entry points keep their names and differ only in the per-subscription "wants this line" test (role equals, filter matches the flow, always). A required argument carries the mute decision into the helper, so a future fourth fan-out cannot forget it. AC21 greps for the single `sub.sink.push`.

Per fan-out call, under the registry lock, the helper reads the policy **once**, after the lock is taken (the read is as late as possible and one snapshot covers every subscription in that call). Mechanism is the builder's: pass `&AgentState`, or a `&dyn Fn() -> bool` built from `McpServer::agent_pushes_muted`, into the helper. `Subscriptions` is built before `with_agent_state` can replace the state, so it cannot hold the state itself.

Per-subscription rule, in registry order, once per connection as today: skip a subscription the entry point does not want; if its role is not trusted control (`sub.role.is_trusted_control()`) and pushes are muted, record a gap for that connection and enqueue nothing; otherwise, if a gap is recorded for that connection, enqueue the marker and clear the gap, then enqueue the line.

**Where the gap bit lives (Architect's call, changed from the brief's lean).** A single `bool` in `SubState` is wrong: it is cleared by the first delivery, so with two agent connections the second never gets its marker. The gap is per connection. Add one small collection of connection ids to `SubState` (builder's choice of `Vec<u64>` or a set; it is bounded by the live connections that hold a subscription). It is written and cleared only inside the helper, under the registry lock that is already held; it is removed for a connection in `drop_connection` (required, or it leaks); `remove` need not touch it. A connection that unsubscribes after resume and before any delivery keeps a stale gap and may get one spurious marker if it later re-subscribes. That marker is harmless ("you may have missed something" is true of a connection that was not listening) and clearing it is optional.

A connection is marked **only** if a line it would have received was suppressed: the "wants" test runs before the mute check, so an agent whose filter (`{host: ...}`) matches none of the suppressed flows is not marked (AC8).

Replays are not fan-outs. `replay_since` pushes straight to the sink and sits behind `read_refusal`, so under `paused` it is never reached. It is untouched.

### 4. The gap marker

**Decision: keep it** (Architect's call, agreeing with the brief). Cost: one id collection and about ten lines in the helper. Benefit: without it an agent that resumes has a silent hole in its stream (a web UI on the agent link would show missing flows with no signal), and the repo already has the exact contract for it: the sink's overflow marker `notifications/aitm/state {"lagged":true}` means "catch up via `flow.list`". What the marker tells a resumed agent (that something matching its subscriptions happened while it was paused) it could learn by calling `flow.list`, which the resumed policy lets it do. It carries no capability.

**Mechanism (Architect's call, changed from the brief's leaning).** Enqueue `lagged_state_line()` as an ordinary note immediately before the line being delivered. Do not set the sink's `lagged` flag at suppression time: `NotificationSink::drain` would emit it on the next drain, which can happen while the policy is still `paused` (any reply wakes the writer), and that would leak a bit under pause. Setting the flag at the first post-gap delivery would also work and is allowed (builder's choice) as long as AC6 and AC7 hold. If the sink is also in overflow a second marker may follow from `drain`; harmless.

**Rules.** The marker is never emitted while paused (AC7). It rides the first delivery after the resume; if no delivery ever follows, none is sent (proactive emission would need a hook at resume time, rejected in Design 9). The marker the overflow path emits in `drain` is not a fan-out and is unaffected.

**Real pause/resume always marks.** Through the real verb, `agent.set paused` is itself an audited call whose audit line is pushed after the policy flipped, so that line is suppressed for every agent subscriber. Therefore every real pause then resume with an agent subscriber produces a marker (AC9). The "no marker when nothing was suppressed" case (AC8) can only be reached by flipping `AgentState` directly.

### 5. Parked requests

All four pieces read the live policy; none relies on a hook.

**5.1 `agent.approve` checks the live policy first.** `handle_approve` keeps its role gate and its parameter checks in their present order, then reads the policy. If it is `Ask`, behaviour is unchanged. Otherwise:

- `allow:true`: resolve `request_id` as **denied** (waking the waiter) and return a tool error whose text contains "no longer `ask`" and "denied" (proposed text: "agent.approve: the agent policy is no longer `ask` (it is `<label>`), so parked request `<id>` was denied, not approved. The agent may re-issue the call under the current policy."). If no request by that id exists, return the existing "no parked request `<id>` is awaiting approval" error unchanged, so an unknown or already-handled id is still told apart from a policy refusal.
- `allow:false` (Architect's call, changed from the brief): resolve as denied and return a **success**, the same as today. The operator's intent, to deny, was met, and an error would suggest the request is still pending. A denial is always safe.

This check is about operator honesty and defence in depth, not the only barrier: without it an approve under `paused` would return success and the waiter would then deny.

**5.2 The waiter rechecks after waking, and in slices.** `park_for_approval` currently blocks in one `ParkSlot::wait(approval_timeout)`. Change it to wait in slices of a constant `PARK_POLICY_RECHECK: Duration = 200 ms` (Architect's call; the brief proposed 100 to 250 ms). After each slice the waiter reads the policy; if it is not `Ask`, it stops waiting. The total wait never exceeds `approval_timeout` (the last slice is shortened to the remaining time), and a resolved slot ends the wait at once. Shape (builder may reshape): `ParkSlot::wait(&self, timeout: Duration, recheck: Duration, still_ask: &dyn Fn() -> bool) -> ParkWait` with `enum ParkWait { Resolved(bool), TimedOut, PolicyChanged }`.

Cost: at most `MAX_PARKED_REQUESTS` (64) waiters per server, five wakeups a second each, one atomic load each.

**5.3 One pure decision after the wait.** The mapping from the wait result and the live policy to `ParkOutcome` is one small pure function (proposed `settle_park(name: &str, wait: ParkWait, policy: AgentPolicy) -> ParkOutcome`; builder's name), evaluated after the wait returns with the slot's guard released:

| Wait result | Live policy | Outcome |
|---|---|---|
| `Resolved(true)` | `Ask` | `Approved` |
| `Resolved(true)` | anything else | `Refused`, "the agent policy changed" + new label |
| `Resolved(false)` | any | `Refused`, "an operator denied the parked sensitive command." (unchanged text) |
| `TimedOut` | any | `Refused`, "no operator approved ... within the approval timeout." (unchanged text) |
| `PolicyChanged` | any | `Refused`, "the agent policy changed" + new label |

"Anything else" includes an unknown future posture (not `Ask`, so fail closed). The policy-change text (proposed): "`<cmd>` refused: the agent policy changed from `ask` to `<label>` while this sensitive command awaited operator approval, so it was not run. Re-issue it if the new policy allows." It must contain "the agent policy changed" and the new label in backticks. Being pure, the function lets the approve-then-pause race be tested deterministically (AC13).

**5.4 Unchanged.** `any_role(Frontend::Operator)` refusal when no operator is subscribed, the `MAX_PARKED_REQUESTS` cap, the `forget` cleanup after every wait, and `push_approval_request`.

**Lock order.** `handle_approve`: the table lock is released before the slot's mutex is taken (as today); the policy load takes no lock. The waiter: the policy load happens while the slot's mutex may be held, and takes no lock; `forget` (table lock) runs after the wait returns with the slot guard dropped (as today). Fan-outs never touch the table or the slot. No new nesting.

### 6. The guarantee, stated precisely, and what is accepted

**G1 (pushes).** Once `agent.set` (or any `AgentState::set_policy`) to `paused` has returned, a fan-out that starts afterwards, on any `McpServer` sharing that state, enqueues nothing to any non-trusted-control sink.

**G2 (parked).** Once a change to a non-`ask` policy has returned: (i) no `agent.approve allow:true` causes a parked request to run; (ii) a parked call already resolved as approved, but not yet past its post-wake recheck, does not run; (iii) every parked call is denied within one `PARK_POLICY_RECHECK` slice plus scheduling.

Accepted residuals, each stated so a reviewer can disagree with it:

- **R1. Lines already in an agent sink.** Lines enqueued before the change may still be written to the wire; they were legitimately granted when queued. The bound is the sink capacity (default 4096, `DEFAULT_PUSH_CAPACITY`) and, in practice, the writer's drain latency; a stalled reader can hold the full capacity. Purging needs a set-time hook (the writer drains on its own schedule, so polling at fan-out cannot reach a quiet sink), and a revocation can never recall what an agent has already received. AC12 pins that nothing is purged, so adding a purge later is a deliberate change.
- **R2. A subscribe in flight.** A `flow.subscribe {since}` that passed `read_refusal` just before the flip may enqueue its `since` replay just after it. Same class as any command already past the gate: not interrupted. Closing it would touch `subscribe`, which a sibling session is editing.
- **R3. A flap shorter than one slice.** `AgentState` is one atomic with no generation, so a parked waiter cannot see `ask` to `paused` to `ask` inside a slice. The request stays parked, and any approval is applied under `ask`, the policy then in force. Catching this needs a generation counter in `aitm-core`, out of scope.
- **R4. A call past its post-wake recheck.** A parked call that has passed the recheck is in flight (argument coercion, then `invoke`), exactly like a call that passed the gate; the window is microseconds.
- **R5. A push computed concurrently with the flip.** A fan-out that read the policy just before the flip may enqueue just after it, for the same reason as R4. The read is taken inside the registry lock to keep this window to the loop body.

### 7. Races and edge cases, answered

- **Subscribe racing `agent.set paused`.** A subscription registered just after the flip is muted at the next fan-out like any other. Nothing special.
- **`flow.unsubscribe` under paused.** Still refused by `read_refusal` (unchanged), so a paused agent cannot unsubscribe; its subscriptions stay registered, muted, until it disconnects or the policy relaxes.
- **Audit lines about the agent's own refused calls under pause** are muted like the rest. The agent already has the refusal in the tool reply.
- **`notifications/aitm/state` lines from `push_state`** are muted for agents under pause. (`push_state` has no production caller today; it is public API and is covered anyway.)
- **The operator's `agent.set paused` audit line** is itself suppressed for agents (pushed after the flip). The operator's `agent.set auto` audit line is delivered after the flip, preceded by the marker.
- **`readonly`, `ask`, `auto`, `all` are not muted.** Under each, the agent can still read the same data with `flow.list` / `agent.activity`, so muting would remove nothing it cannot fetch.
- **Resume under a different non-paused policy** (`paused` to `readonly`) resumes delivery. Under every non-paused policy the agent could re-subscribe itself, so resuming grants nothing new.
- **Two connections, one subscription each, one filter.** Gaps are per connection (Design 3). One connection's delivery never clears another's gap.
- **`Frontend::Cli` over MCP** is trusted control and never muted.
- **A parked call whose connection is gone.** Unchanged: the waiter holds the thread until resolved, denied, or timed out.

### 8. Coverage: surfaces and servers

The fan-out helper and the parked path are the only chokepoints, so every transport that registers a subscription or parks a call is covered by the same edit: loopback TCP, stdio, and the `aitm web` `/bus` bridge. (The streamable-HTTP POST path builds `ConnCtx::new(Frontend::Mcp)` with no sink, so it holds no subscriptions today; it can park a call, so G2 covers it. If it ever holds subscriptions they go through the same registry.)

`aitm web` runs two `McpServer`s. After PR 145 they share the primary's `Arc<AgentState>` and `Arc<AuditRing>` through `tui::with_shared_governance` but keep separate `Subscriptions` and `ParkedRequests`. Because each server reads the shared state at use, an `agent.set` run on either server mutes the subscribers of both and denies the parked calls of both (AC10, AC17). A hook in `agent.set` or in `call_tool` would only reach the server that ran it.

### 9. Alternatives rejected

| # | Alternative | Why not |
|---|---|---|
| 1 | Close agent connections on `paused` | Heavy: the server has no handle on a transport connection except its sink, `/bus` multiplexes many frames on one connection, and in-flight non-push work dies with it. Irreversible: resume needs a reconnect and a re-subscribe. Mute gives the same guarantee reversibly. |
| 2 | Unregister agent subscriptions on `paused` | Resume then silently delivers nothing and the agent is not told. Needs a set-time hook. |
| 3 | A watcher task, callback list, or `Notify` in `AgentState` / `agent.set` | `aitm-core` change (out of scope) in a type that is one lock-free atomic by design. Polling at use needs none of it. |
| 4 | A hook in `McpServer::call_tool` when `agent.set` runs | Reaches only the server that ran it; P and W share state but not registries. Also misses any other `set_policy` caller. |
| 5 | Policy-aware `drain` (mute at the sink's writer) | The most exact, but `NotificationSink` knows neither role nor policy; it would touch the sink API, three transports, and the bridge, and collide with sibling sessions. Lines already enqueued were granted at enqueue time (R1). |
| 6 | Purge queued notes from agent sinks on `paused` | Needs a set-time hook (R1). |
| 7 | One registry-wide gap `bool` | Cleared by the first delivery; the second agent connection never gets its marker (Design 3). |
| 8 | Set the sink's `lagged` flag when a push is suppressed | `drain` emits it while still paused: a leak (Design 4). |
| 9 | Silent gap, no marker | The resumed agent cannot know it missed anything; the overflow contract already says how to signal this. |
| 10 | Emit the marker proactively at resume | Needs a resume-time hook; piggybacking on the next delivery needs none. |
| 11 | Keep parked requests parked across a policy change, or approve them when the policy relaxes (`ask` to `all`) | Limbo, or a grant by side effect: the operator approved specific arguments under `ask`, not under a different posture. Denial is fail-closed and the agent can re-issue under the new policy (under `all` it runs through the command's own gate). |
| 12 | Refuse the approve only, with no waiter polling | The parked call hangs up to the approval timeout (default 120 s) after the agent was paused, holds a blocking-pool thread, and a race still lets a resolved waiter run. |
| 13 | A generation counter in `AgentState` to catch a sub-slice flap | `aitm-core` change for residual R3. |
| 14 | A real `/bus` WebSocket test in `crates/aitm` | Outside the scope fence; the two-server `aitm-mcp` rig covers the topology. |

### 10. Tests

Rigs are built from existing helpers and patterns in `tests/mcp.rs`, and are in-process unless AC18.

- **Push rig.** A server over a registry with `SubscriptionPlugin` (so `flow.subscribe` has its published schema, as `push_server` does) and `AgentPlugin` over the same `Arc<AgentState>` (so the real `agent.set` is available), services over a `MemFlowStore`, the state under test. An agent `ConnCtx` (role `Mcp`) and an operator `ConnCtx` (role `Operator`), each with its own `NotificationSink::new(64)` and a `conn_id` from `next_conn_id()`, each subscribed with `flow.subscribe` (the agent subscribes under `Auto`). Pushes: `push_flow_event(&Event::RequestHeaders(id))` for a flow inserted with `http_flow("example.com:443", "/x")`; `push_state(json!({"k": 1}))`; an audited command call by the operator connection (its audit line is what `push_agent` fans out). Assertions read `sink.drain()` (no timing) and `sink.lagged()`.
- **Marker.** "The marker" means a line that parses to method `notifications/aitm/state` and `params == {"lagged": true}`.
- **Parked rig.** As `ask_server` (a gateless Sensitive stub that returns the string `ran` if invoked, the real `AgentPlugin`, a bounded `approval_timeout`), with an operator subscribed so the call parks. The agent call runs on its own thread and reports through a channel; waits use `recv_timeout`.
- **Private-state tests** (AC11 to AC13) live in the existing `#[cfg(test)] mod tests` in `server.rs`, because they need `ParkedRequests::try_park`, `ParkSlot`, and the pure decision function. They park a slot without a waiter (`try_park()`), which makes the approve reply deterministic regardless of the slice timer.
- **Socket rig (AC18).** The pattern of `serve_still_spawns_the_push_dispatcher`: `McpServer::new(.., McpTransport::LoopbackTcp {port: 0, token: "tok", ..})`, `.with_mcp_roles(Some("op".into()), Frontend::Mcp)`, `.with_push(tx)`, `.on_bound(..)`, `.serve()` spawned. Negative socket assertions use a **fence**, never a bare sleep: the operator, in the same fan-out, receives the push first (so the agent's sink already holds whatever it was going to hold), then the agent sends `ping` and reads its reply (a reply wakes its writer and any queued note would be written in the same batch), and only then waits 250 ms for a line that must not come.
- **Red first.** Per the workflow the Coder writes each test, runs it against the unmodified code and records the failure, then implements. The guards (AC3, AC12, AC16) pass either way and are not evidence of the fix.

## Acceptance criteria

`[in-process]` = no ports, runs in the sandbox. `[unit]` = in-file `mod tests` in `server.rs`. `[socket]` = real loopback TCP, Terminal panel. "Drain" means `NotificationSink::drain()` on that connection's sink.

1. **AC1** `[in-process]` **Paused mutes flow pushes.** Agent subscribed under `Auto`. A flow push under `Auto` gives the agent drain exactly one line, method `notifications/aitm/flow`. After `state.set_policy(AgentPolicy::Paused)`, a flow push for a new flow gives the agent drain `[]`, `queued_len() == 0`, and `lagged() == false`.
2. **AC2** `[in-process]` **Paused mutes state and agent pushes.** Under `Paused`, `push_state(json!({"k":1}))` and an operator-run audited command call each leave the agent drain `[]`, while the operator's drain receives the `notifications/aitm/state` line and a `notifications/aitm/agent` line.
3. **AC3** `[in-process]` **Trusted control is never muted** (guard; passes without the fix). For each role in `[Operator, Cli]`, subscribed with its own sink, under `Paused`: one flow push, one state push, and one audit push give exactly three lines, in the order `notifications/aitm/flow`, `notifications/aitm/state`, `notifications/aitm/agent`, and no marker.
4. **AC4** `[in-process]` **The behaviour table, and resume.** For each policy in `[All, Auto, Ask, ReadOnly]` the agent drain after one flow, one state, and one audit push has exactly three lines; under `Paused` it has none. Then, from `Paused`, `set_policy(Auto)` and a flow push deliver that flow's line to the same connection and the same subscription (no re-subscribe), preceded by the marker (AC6).
5. **AC5** `[in-process]` **One predicate.** For each of the five policies `P`, with agent connection A subscribed under `Auto`: set `P`; a fresh `flow.subscribe` from a second agent connection B is accepted iff `P` is not `Paused`; a flow push reaches A iff `P` is not `Paused`. The two outcomes are equal for every `P`, and both are false only for `Paused`.
6. **AC6** `[in-process]` **The marker comes exactly once, in front of the first post-gap line.** Agent subscribed. `Paused`; one suppressed flow push; `set_policy(Auto)`; next flow push. The agent drain is exactly two lines: the marker, then the flow line. A further flow push drains exactly one line, the flow line, with no marker. With two agent connections both subscribed with no filter, each gets exactly one marker in front of its own first post-gap line.
7. **AC7** `[in-process]` **No marker while paused.** With a suppressed push pending and the policy still `Paused`, `drain()` returns `[]` and `lagged()` is false, after each suppressed push and again after a further `drain()`. (The `[socket]` AC18 repeats this through a real writer.)
8. **AC8** `[in-process]` **No marker when nothing was suppressed for that connection.** (i) `Paused` then `Auto` flipped directly on `AgentState` with no push in between: the next flow push drains exactly the flow line. (ii) Agent A subscribed with `filter {host: "a.example"}` and agent B unfiltered; under `Paused` one flow for `b.example` is pushed (suppressed for B, not wanted by A); after resume a flow for `a.example` drains exactly one line, the flow line, for A and exactly two (marker, flow line) for B.
9. **AC9** `[in-process]` **The real verb marks.** With `AgentPlugin` registered, operator `agent.set {"policy":"paused"}` leaves the agent drain `[]` (its own audit line is suppressed). Operator `agent.set {"policy":"auto"}` then leaves the agent drain exactly two lines: the marker, then one `notifications/aitm/agent` line whose `params.command == "agent.set"`.
10. **AC10** `[in-process]` **Cross-server pushes.** Two `McpServer`s P and W over one registry and one `Arc<AgentState>`, each with its own `Subscriptions`. An agent connection subscribed on W under `Auto` and an operator connection subscribed on W. The operator runs `agent.set {"policy":"paused"}` **on P**. A flow push on W then leaves the agent drain on W `[]` and gives W's operator the flow line. After `agent.set {"policy":"auto"}` on P, a flow push on W drains the marker then the flow line for the agent.
11. **AC11** `[unit]` **Approve after leaving `ask` is refused and denies.** For each `P` in `[Paused, ReadOnly, Auto, All]`: a server with `AgentState::new(Ask)` and `AgentPlugin`; one slot parked with `try_park()` (no waiter); `state.set_policy(P)`; operator `agent.approve {request_id, allow: true}` returns `isError: true`, text containing "no longer `ask`" and "denied"; the slot's state is `Some(false)`; the table is empty. A second identical approve returns `isError: true` with text containing "no parked request `<id>`". With the state left at `Ask`, `allow: true` on a fresh slot returns `isError: false` and the slot's state is `Some(true)` (unchanged behaviour).
12. **AC12** **A denial is always honoured, and queued lines are not purged** (guards on accepted behaviour). (i) `[unit]` Same setup as AC11 with `P = Paused` and `allow: false`: `isError: false`, slot `Some(false)`, table empty. (ii) `[in-process]` In the push rig, a line enqueued while `Auto` and not yet drained is still returned by `drain()` after `set_policy(Paused)` (pins residual R1).
13. **AC13** `[unit]` **The post-wait decision, including approve-then-pause.** The pure decision of Design 5.3, over its full table: `(Resolved(true), Ask)` is `Approved`; `(Resolved(true), P)` for `P` in `[All, Auto, ReadOnly, Paused]` is `Refused` with text containing "the agent policy changed" and `` `<P.label()>` ``; `(Resolved(false), any)` is `Refused` containing "an operator denied the parked sensitive command"; `(TimedOut, any)` is `Refused` containing "approval timeout"; `(PolicyChanged, any)` is `Refused` containing "the agent policy changed". Plus an end-to-end case in the same module: a real `park_for_approval` waiter on a thread, `set_policy(Paused)`, then the slot resolved as approved **directly through the table** (bypassing `agent.approve`): the call returns `Refused` with "the agent policy changed" and the stub did not run, whichever of the slice recheck or the direct resolve gets there first.
14. **AC14** `[in-process]` **The waiter denies promptly with no approve call.** For each `P` in `[Paused, ReadOnly, Auto, All]`: `ask_server` with `approval_timeout` 60 s and an operator subscribed; the agent thread calls the Sensitive stub and parks (the operator's stream shows `approval_requested`); the test then calls `state.set_policy(P)` and does nothing else. The agent call returns within 5 s (the design bound is about one slice, 200 ms) with `isError: true` and text containing "the agent policy changed" and `` `<P.label()>` ``; the result is not `ran`.
15. **AC15** `[in-process]` **`ask` to `ask` does not deny.** With a call parked, the operator runs `agent.set {"policy":"ask"}` (no change) and the test waits 800 ms (four slices); the agent call has not returned. Operator `agent.approve {request_id, allow: true}` then returns `isError: false` and the agent call returns `isError: false` with `structuredContent == "ran"`.
16. **AC16** `[in-process]` **Existing `Ask` flows are unchanged** (guard). Approve, deny, timeout, and no-operator behave exactly as the existing tests `ask_parks_then_approves`, `ask_deny_refuses`, `ask_timeout_refuses`, `ask_without_operator_refuses`, and `agent_cannot_approve_own_request` pin; those tests are not modified and still pass.
17. **AC17** `[in-process]` **Cross-server parked call.** P and W as in AC10 with `Ask`; an operator subscribed on W; an agent call parked on W; the operator runs `agent.set {"policy":"paused"}` on P. The call on W returns within 5 s with `isError: true`, text containing "the agent policy changed" and "`paused`", and the stub did not run.
18. **AC18** `[socket]` **End to end over real loopback TCP, with a real agent and a real operator.** Registry with `SubscriptionPlugin` and `AgentPlugin`; agent token `tok`, operator token `op`; policy `Auto`; `with_push(tx)` and a `MemFlowStore`. Agent connection A and operator connection O each authenticate and send `flow.subscribe {}`; both replies carry a `sub_id`.
    1. Flow F1 (`/one`) is inserted and `Event::RequestHeaders(F1)` is sent on `tx`. A and O each receive one `notifications/aitm/flow` line with `params.id == F1` and `params.summary.path == "/one"`.
    2. O sends `agent.set {"policy":"paused"}`; the reply has `structuredContent.policy == "paused"`. F2 (`/two`) is inserted and sent. O receives a flow line for F2 (the fence). A sends `ping` and receives its reply (`result == {}`), then **no further line arrives within 250 ms**. A has received no line naming F2 and no `notifications/aitm/agent` line for the `agent.set`.
    3. O sends `agent.set {"policy":"auto"}`; F3 (`/three`) is inserted and sent. The first line A receives is the marker; A then receives a flow line for F3 (and may receive the `agent.set` audit line before it). Exactly one marker is received, and no line A received at any point contains F2's id.
19. **AC19** **Scope.** `git diff --name-only <base>..HEAD` lists only `crates/aitm-mcp/src/server.rs`, `crates/aitm-mcp/tests/mcp.rs`, and this spec and its plan. `git diff --stat <base>..HEAD -- crates/aitm-core crates/aitm crates/aitm-plugins` prints nothing. (`<base>` is the plan's base SHA, `bd0f9b7` when this was written; `origin/main` moves.)
20. **AC20** **Nothing existing changes.** `git diff <base>..HEAD -- crates/aitm-mcp/tests/mcp.rs` contains no removed lines; the same holds for the existing tests in the `server.rs` `mod tests` (additions only). The whole Rust gate passes. `cargo test -p aitm --test web_bus_governance --test web_bus_push --test web_bus_ask_split --test web_bus_roles --test web_bus_concurrency` (Terminal panel) passes unmodified. `crates/aitm-core/tests/trust_gate_scan.rs` passes: no `==`, `!=`, `matches!`, or `if let` against `Frontend::Mcp` was introduced.
21. **AC21** Review-checked, plus two greps. In `server.rs`, `sub.sink.push` appears exactly once (inside the shared fan-out helper), and `agent_reads_allowed` is called from both `read_refusal` and the mute decision. The doc comments on `push_flow_event`, `push_state`, `push_agent`, `read_refusal`, `park_for_approval`, `handle_approve`, `ParkSlot::wait`, the helper, and `PARK_POLICY_RECHECK` state the new behaviour, and the helper's or `park_for_approval`'s doc states residuals R1 to R5. The `read_refusal` text for `paused` is byte-identical to before.
22. **AC22** **Mutation check** (Tester, at the final head). (a) Make `agent_pushes_muted` return `false` unconditionally: AC1, AC2, AC4, AC5, AC6, AC7, AC8, AC9, AC10, and AC18 fail on the missing suppression, not on a compile or connect error. (b) Remove the policy check from `handle_approve` and the recheck and slicing from the waiter: AC11, AC13, AC14, AC17 fail on a missing denial. AC3, AC12, AC15, and AC16 pass either way. The report shows the red run and the green run.

## Left to the builder

- Names: `agent_reads_allowed`, `agent_pushes_muted`, `settle_park`, `ParkWait`, the helper, and the gap collection, except `PARK_POLICY_RECHECK` and the text fragments the ACs quote.
- The shape of `ParkSlot::wait` and how the policy is handed to the fan-out helper (`&AgentState` or a closure), provided the read happens once per fan-out call, after the registry lock is taken.
- `Vec<u64>` or a set for the gap collection; whether `remove` clears it when a connection's last subscription goes.
- Marker placement: `sink.push(lagged_state_line())` before the line (recommended), or setting the sink's lagged flag at the first post-gap delivery. Not at suppression time.
- Wording of the two new refusal texts beyond the quoted fragments.
- Whether the end-to-end parked tests use threads and `mpsc` or the existing duplex-connection helpers, as long as waits are bounded by `recv_timeout` and a failing run releases any parked waiter (deny it) so no thread outlives the test by the approval timeout.
- Test and stub names; whether to factor shared setup into a helper in `tests/mcp.rs`.

## Risks

- **Merge conflicts with sibling sessions.** One is editing `aitm-mcp` request validation and another the `/bus` registry. This change edits `Subscriptions`' three fan-outs, `SubState` (one added field), `read_refusal`, `park_for_approval`, `handle_approve`, and `ParkSlot::wait`. It avoids `run_tool`, `call_tool`, `subscribe`, `enforce_verb_schema`, and `Subscriptions::{add, remove, any_role}`. If the registry session adds a field to `SubState`, the merge is mechanical.
- **Timing in tests.** AC14, AC15, and AC17 depend on a 200 ms slice. Their bounds are generous (5 s against a 200 ms design bound; 800 ms for four slices) and AC11 to AC13 avoid the timer by parking a slot with no waiter. A negative socket assertion is only sound with the fence of Design 10.
- **A UI or agent on the agent link goes quiet under `paused`.** By design, and consistent with PR 145's stated consequence that the default `aitm web` link is the agent token and goes dead for tool calls under `paused`. The web UI currently polls rather than subscribes, so it is not newly affected; once it adopts push, the marker on resume tells it to refetch. The operator link is unaffected.
- **A pause during a long parked wait now ends the wait early.** An agent whose Sensitive call was parked sees a refusal naming the policy change instead of a timeout 120 s later. That is the intent.
- **`ask` to `all` denies a parked request.** An operator who relaxes to `all` expecting parked calls to proceed will see them denied and must let the agent re-issue. Fail-closed by choice (Design 9, alternative 11).
- **The `read_refusal` fail-open for an unknown future posture is now also the push posture.** Stated in Constraints and Design 1; one helper to change.
- **TUI mode is not covered** because its gate does not follow `agent.set` at all (Non-goals).

## Open questions

Neither blocks; each has a default.

1. **Announce withdrawn approvals?** When a parked request is auto-denied on a policy change, operator UIs holding an approval card for it get no event; the denial appears in the audit stream (`notifications/aitm/agent`, command name, refusal text naming the policy change) and the operator's own `agent.approve` is answered with the explanation. **Default: no new event**, because a new event type is a wire-contract change for the web, macOS, and TUI operator surfaces, and timeouts already clear cards without one. Follow-up if wanted.
2. **A real `/bus` test.** Should a follow-up add a `crates/aitm` socket test of the agent `/bus` connection being muted, now that `aitm-mcp` is fixed? **Default: no**; the two-server rig (AC10, AC17) is the same topology.

## Files the implementation may touch

- `crates/aitm-mcp/src/server.rs` (production code and the existing `#[cfg(test)] mod tests`)
- `crates/aitm-mcp/tests/mcp.rs` (additions only)
- `docs/superpowers/specs/2026-10-30-agent-policy-revocation-design.md` and `docs/superpowers/plans/2026-10-30-agent-policy-revocation-plan.md` (Architect, orchestrator status lines, Review log, Shipped)

Nothing else. In particular not `crates/aitm-core`, `crates/aitm-plugins`, `crates/aitm`, the other `aitm-mcp` source files, or any existing test.
