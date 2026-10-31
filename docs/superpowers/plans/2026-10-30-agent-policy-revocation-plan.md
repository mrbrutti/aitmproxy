# Agent policy revocation implementation plan

**Status:** Approved (self-approved in autonomous-approve mode, 2026-10-30)
**Spec:** `docs/superpowers/specs/2026-10-30-agent-policy-revocation-design.md` (Approved 2026-10-30)
**Branch / worktree:** `claude/ecstatic-lehmann-199e83` in `/Users/matt/Security/aitmproxy/.claude/worktrees/ecstatic-lehmann-199e83`, first cut from `main` `bd0f9b7`, rebased onto `origin/main` v0.5.2 (`592a377`), then rebased a final time onto `origin/main` `9fb8cfa` (after PR 162, which put `aitm tui`'s agent server under the shared agent policy). **Base SHA for every diff and Tester/panel dispatch: `9fb8cfa`.** The branch commits, oldest first, are the spec-and-plan commit, the Task 1 commit, the Task 2 commit, the Task 3 commit, the Tester duplex-test commit, the panel-fix commit, the docs-amendment commit, the comment-only commit, and the Review-log-and-Shipped commit. This plan names them by those labels, not by hash, because every rebase rewrites the hashes; list them with `git log --oneline 9fb8cfa..HEAD`. Wherever this plan says "the previous task's commit" or `<task-N-sha>`, read the Task N commit from that list. For a per-task Tester, the base is the previous task's commit.

## Overview

The whole change is two files: `crates/aitm-mcp/src/server.rs` (production code plus
the existing in-file `mod tests`) and `crates/aitm-mcp/tests/mcp.rs` (additions
only). Task 1 makes the push path read the live policy (one predicate, one fan-out
helper, a per-connection gap set, the `lagged` marker). Task 2 makes the
parked-request path read it (approve check, sliced waiter, one pure post-wait
decision). Task 3 adds the one real-socket test. Task 4 is an orchestrator
checkpoint (full gate, the AC22 mutation checks, the AC19/AC20/AC21 checks), not a
Coder task.

**All four tasks are sequential, and no task fans out.** Every task edits
`server.rs`, `tests/mcp.rs`, or both, and two writers never share a file, so
there is no independent pair. The order is also the dependency order: Task 3's test
needs Task 1's muting, and Task 2 reuses the test-section layout Task 1 creates.
The Coder is a fresh sub-agent per task, in the one worktree. Tasks 1 and 2 are
each a mechanism plus its tests; if a Coder's context runs short in Task 1, the
natural seam is "mute and rigs (AC1-AC5, AC10, AC12(ii))" versus "marker
(AC6-AC9)", but do not split unless it happens.

A Coder that finds the spec or this plan wrong **stops and reports**; it does not
improvise (WORKFLOW "Stop on gaps").

### Where each command runs (read before dispatching)

- **Bash sandbox (Coder and Tester sub-agents).** `cargo build -p aitm-mcp`,
  `cargo fmt --check`, `cargo clippy -p aitm-mcp --all-targets -- -D warnings`, and
  the socket-free test commands below. **Always use a filter; never run the bare
  binaries**, because `tests/mcp.rs` and `transport.rs`'s lib tests bind loopback
  sockets and the sandbox refuses that:
  - `cargo test -p aitm-mcp --test mcp revoke_push` (Task 1 tests, in-process)
  - `cargo test -p aitm-mcp --test mcp revoke_park` (Task 2 tests, in-process)
  - `cargo test -p aitm-mcp --lib revoke_` (the new unit tests in `server.rs`)
  - `cargo test -p aitm-mcp --lib server::tests` (all unit tests in `server.rs`,
    existing plus new; socket-free). **Never bare `cargo test -p aitm-mcp --lib`**:
    it also runs `transport::tests`, which bind a port.
  - `cargo test -p aitm-core --test trust_gate_scan` (reads source files only)
  - the existing in-process regression set, one command:
    `cargo test -p aitm-mcp --test mcp -- ask_parks_then_approves ask_deny_refuses ask_timeout_refuses ask_without_operator_refuses agent_cannot_approve_own_request subscribe_under_paused_refuses_only_the_agent subscription_refusal_is_audited_but_success_is_not subscribe_pushes_created_on_new_flow unsubscribe_stops_push state_pushed_on_change slow_subscriber_lags_not_blocks`
  If cargo cannot resolve dependencies offline, stop and ask the orchestrator to run
  `cargo fetch` in the Terminal panel; never report a result you did not get.
- **Terminal panel (orchestrator only).** Every git command. Every test that binds a
  socket: `cargo test -p aitm-mcp --test mcp revoke_socket` (Task 3), the whole
  crate `cargo test -p aitm-mcp`, the `aitm` web_bus binaries, and the full gate.
  A Coder or Tester never claims a socket test passed or failed: it reports
  "compiled, NOT RUN (socket)" and the orchestrator supplies the output.
- **Coders do not run git.** The sandbox cannot create `.git`, so the orchestrator
  commits each task through the Terminal panel after that task's Tester passes. The
  Coder reports the files it changed. Commit subjects name the plan and task; they
  never contain a word that starts with a hash character (the terminal hook refuses
  it): write "PR 145", not the numeric hash form. Each commit ends with the
  session's attribution trailer.
- **Evidence, verbatim.** Every red and green run goes into the Coder's report as
  the literal command and the literal `test result:` line plus the failing
  assertion text named in the task. "It failed as expected" is not a report. Each
  Coder report quotes its red run and its green run.
- **Stale target directories.** If `CARGO_TARGET_DIR` is shared with other
  worktrees, `touch crates/aitm-mcp/src/server.rs crates/aitm-mcp/tests/mcp.rs`
  before a red or green run, so cargo does not reuse a stale artifact. A red run on
  a stale binary is worthless.
- **Gate exit status, not grep.** Where the orchestrator gates, redirect to a log and
  read the exit status; `grep` output is for display only.

### Traps found by reading (carry into every Coder brief)

1. **`trust_gate_scan` reads `server.rs` including its `mod tests`.**
   `crates/aitm-core/tests/trust_gate_scan.rs` scans every `crates/*/src/**/*.rs`
   (comments and string literals blanked) for `==`/`!=`/`matches!`/`if let`/`let ..
   else` against `Frontend::Mcp`. Nothing in `server.rs`, tests included, may compare
   against it. Decide who is muted with `role.is_trusted_control()`. In unit tests
   build an agent context with `ConnCtx::agent()` (construction is fine). Do not
   evade the scan by aliasing either; the intent is the same. `tests/mcp.rs` is not
   scanned but follows the same discipline. A new `AgentPolicy` comparison
   (`policy == AgentPolicy::Ask`) is fine; it is not an untrusted role.
2. **`serve()` destructures every `McpServer` field and rebuilds the struct.** Adding
   a field to `McpServer` means editing both lists. Do not add one: the gap set goes
   in `SubState`, and the policy is read through the existing `agent_state`.
3. **`tests/mcp.rs` is additions-only (AC20), and the file already has file-wide
   imports.** Do not edit the top import block or any existing line. Append one new
   section at the end of the file with its own new `use` lines, separated from older
   code by a banner comment so rustfmt never re-sorts old lines. Names already
   imported file-wide, which must **not** be imported again (E0252): `Duration`,
   `Event`, `NotificationSink`, `SubscriptionPlugin`, `broadcast`, `AtomicUsize`,
   `AgentPlugin`, `AgentPolicy`, `AgentState`, `Frontend`, `ConnCtx`, `McpServer`,
   `MemFlowStore`, `Registry`, `Sensitivity`, `StdGuard`, `TcpStream`, `BufReader`,
   `AsyncBufReadExt`, `AsyncWriteExt`, `json`, `JsonValue`. Qualify the rest
   (`std::sync::mpsc`, `std::thread`, `tokio::time::timeout`). Existing helpers to
   **call, not edit**: `http_flow`, `StubClient`, `ungated`, `subscribe_on`,
   `sub_id_of`, `is_refused`, `call_as_args`, `read_until`, `next_json`,
   `write_req`, `open_push_conn`, `TierCmd`.
4. **The same additions-only rule covers the existing `mod tests` in `server.rs`.**
   New unit tests go at the end of that module; add any new `use` there as new
   lines (`AtomicUsize` is not imported in that module; `use super::*` supplies
   `Arc`, `Mutex`, `Duration`, `Command`, `CommandHost`, `Sensitivity`; the module
   already imports `HttpFlow`, `MemFlowStore`, `ParamSchema`, `Params`, `StdGuard`,
   `TypeDesc`, `Value`, and defines `NoClient` and `EgressProbe`).
5. **Test-name prefixes are the sandbox contract.** In-process push tests are
   `revoke_push_*`, in-process parked tests `revoke_park_*`, the socket test
   `revoke_socket_*`, unit tests `revoke_*`. The filters above never select a socket
   test, provided no in-process test is named `revoke_socket*`.
6. **The AC21 grep is literal.** `sub.sink.push` must appear **once** in `server.rs`
   (the marker and the line go out through one loop; see Task 1), and no unit test or
   comment in that file may spell it either (the grep counts text, not code).
7. **Mandated shapes (so the AC22 mutations are one-line edits).** (a)
   `McpServer::agent_pushes_muted` has a one-line signature, exactly one body line,
   and a closing brace; the body is exactly `!agent_reads_allowed(self.agent_state.policy())`.
   (b) the free function `ask_still_in_force(policy: AgentPolicy) -> bool` has a
   one-line signature, exactly one body line (`policy == AgentPolicy::Ask`), and a
   closing brace. Both are one-statement functions on purpose.

### Symbols the work touches (confirmed by reading `bd0f9b7`; none missing)

`server.rs`, private unless stated: `McpServer::{push_flow_event (pub),
push_state (pub), push_agent (pub), push_approval_request, record_audit,
policy_decision, park_for_approval, handle_approve, read_refusal, subscribe,
replay_since, drop_connection (pub)}`; `Subscriptions` (an `Arc` held by
`McpServer`, built in `McpServer::new`) with `inner: Mutex<SubState>`, `SubState {
next_sub, subs }`, `Subscription { sub_id, conn_id, role, sink, filter }`,
`Subscriptions::{add, remove, any_role, drop_connection, fanout_role,
fanout_flow, fanout_state}`; `lagged_state_line() -> String`;
`NotificationSink::{push, drain, queued_len, lagged}` (pub); `ParkedRequests {
inner, cap }` with `try_park() -> Option<(String, Arc<ParkSlot>)>`, `resolve(&str,
bool) -> bool`, `forget(&str)`, and `#[cfg(test)] len()`; `ParkSlot { state:
Mutex<Option<bool>>, cv: Condvar }` with `resolve(bool)` and `wait(Duration) ->
Option<bool>` (called only from `park_for_approval`); `enum ParkOutcome {
Approved, Refused(String) }`; free fns `is_operator_only`, `defers_to_command_gate`,
`policy_refusal_reason` (the natural neighbours for the new free fns).
`aitm-core`: `AgentPolicy { All, Auto, Ask, ReadOnly, Paused }` (`#[non_exhaustive]`,
`Copy`, `PartialEq`, `label()`), `AgentState::{new, policy, set_policy}` (one
`Relaxed` atomic), `Frontend::is_trusted_control`. `aitm-plugins`: `AgentPlugin`
(`agent.status`, `agent.set`, `agent.activity`, `agent.approve`),
`SubscriptionPlugin`; `aitm-plugins` is a dev-dependency of `aitm-mcp` and does not
depend on it, so the in-file unit tests may use it.

### Claims in the spec, verified by reading (none false), and how the plan resolves the loose ends

- `read_refusal` is reached only for `flow.subscribe`/`flow.unsubscribe` and
  refuses only `Paused`, only for a non-trusted-control role. Every push goes through
  exactly four callers: `push_flow_event` (also what the dispatcher calls),
  `push_state`, `push_agent` (from `record_audit`), and `push_approval_request`
  (`fanout_role(Frontend::Operator)`). `replay_since` writes straight to the sink,
  behind `read_refusal`. `agent.set` flips the state inside `invoke`, and
  `call_tool` audits and `push_agent`s after, so the pause's own audit line is
  post-flip (AC9 relies on it). `park_for_approval` pushes `approval_requested`
  before it blocks in `slot.wait`.
- **Loose end 1: AC21's literal grep versus the recommended marker.** The spec
  recommends `sink.push(lagged_state_line())` before the line, and AC21 greps
  `sub.sink.push` for exactly one hit. Two direct calls would be two hits. Not
  infeasible: the helper builds the one or two lines to deliver and sends them
  through a single `for` loop, so the literal grep holds (Task 1).
- **Loose end 2: Design 10's fence.** "The operator receives the push first, so the
  agent's sink already holds whatever it was going to hold" is true only when the
  agent is **ahead of the operator in registry order** (the helper walks
  subscriptions in insertion order). AC18 therefore subscribes A first, then O
  (Task 3). Not a spec defect; the spec does not state the order.
- **Loose end 3: AC22(a) lists AC8, but AC8(i) passes under that mutation** (a direct
  flip with no suppressed push never marked anything). Only AC8(ii) fails. The plan
  splits AC8 into two tests so each has a clean red or guard status.
- **Loose end 4: AC22(b) needs the post-wake recheck removed too**, or AC13's
  end-to-end case would still deny on the live policy. One shared predicate,
  `ask_still_in_force`, is used by the approve check, the waiter's slice recheck,
  and `settle_park`, so one body edit removes all three layers and fails AC11,
  AC13, AC14, AC17 exactly as the spec lists. `settle_park`'s signature is the
  spec's.
- **Loose end 5: residuals R1-R5 doc location.** AC21 says "the helper's or
  `park_for_approval`'s doc". The helper's doc carries all five; `park_for_approval`'s
  doc repeats R3 and R4 (the parked-request ones) in a sentence each.

### AC coverage

| AC | Task | Test or check (exact name) |
|---|---|---|
| AC1 | 1 | `revoke_push_paused_mutes_flow_pushes` |
| AC2 | 1 | `revoke_push_paused_mutes_state_and_agent_pushes` |
| AC3 | 1 | `revoke_push_trusted_control_is_never_muted` (guard) |
| AC4 | 1 | `revoke_push_policy_table_and_resume` |
| AC5 | 1 | `revoke_push_one_predicate_for_subscribe_and_delivery` |
| AC6 | 1 | `revoke_push_marker_exactly_once_before_first_post_gap_line` |
| AC7 | 1 | `revoke_push_no_marker_while_paused` |
| AC8 | 1 | (i) `revoke_push_direct_flip_without_a_suppressed_push_has_no_marker` (guard); (ii) `revoke_push_connection_with_nothing_suppressed_gets_no_marker` |
| AC9 | 1 | `revoke_push_real_verb_pause_then_resume_marks` |
| AC10 | 1 | `revoke_push_cross_server_pause_mutes_the_other_server` |
| AC12 | 1, 2 | (ii) `revoke_push_queued_lines_are_not_purged` (guard, Task 1); (i) `revoke_park_deny_after_leaving_ask_is_honoured` (guard, unit, Task 2) |
| AC11 | 2 | `revoke_park_approve_after_leaving_ask_is_refused_and_denies` (unit) |
| AC13 | 2 | `revoke_park_settle_decision_table` and `revoke_park_approve_then_pause_is_denied_end_to_end` (unit) |
| AC14 | 2 | `revoke_park_waiter_denies_promptly_when_the_policy_leaves_ask` |
| AC15 | 2 | `revoke_park_ask_to_ask_does_not_deny` (guard) |
| AC16 | 2 | the five existing `Ask` tests, unmodified (guard) |
| AC17 | 2 | `revoke_park_cross_server_pause_denies_the_other_servers_call` |
| AC18 | 3 | `revoke_socket_paused_agent_goes_quiet_and_resumes_with_a_marker` (socket) |
| AC19 | 4 | `git diff` scope checks |
| AC20 | 1-4 | no removed lines per task; gate, web_bus binaries, trust-gate scan at Task 4 |
| AC21 | 1, 2, 4 | literal greps plus doc review |
| AC22 | 3 (AC18 red), 4 | mutation runs (a) and (b) |

Plan additions, not spec ACs (each strengthens a spec statement): unit tests
`revoke_read_refusal_text_is_unchanged` (guard, Task 1: byte-identity of the
refusal text, AC21), `revoke_gap_is_dropped_with_its_connection` (Task 1: Design 3
"required, or it leaks"), `revoke_park_slot_wait_honours_timeout_resolve_and_recheck`
(Task 2: Design 5.2's "never exceeds the timeout, a resolved slot ends the wait at
once").

### Calls made in this plan (Architect's calls, for Matt to correct)

1. The task split is the brief's suggestion unchanged: push (1), parked (2), socket
   (3), verification (4).
2. One predicate on the parked side too, `ask_still_in_force(policy)`, mirroring
   `agent_reads_allowed` on the push side. It is also the single mutation point for
   AC22(b).
3. Mute mechanism: the fan-out helper takes `&dyn Fn() -> bool` (built from
   `McpServer::agent_pushes_muted`), read once after the registry lock. The gap
   collection is `SubState::gapped: Vec<u64>`, matching the file's existing `seen:
   Vec<u64>` style.
4. The marker is enqueued as an ordinary note immediately before the line, through
   one send loop, so the AC21 grep is literally true.
5. AC8 is two tests (a guard and a red), not one.
6. Three added tests (named above) that pin spec statements no AC pins.
7. Test-name prefixes `revoke_push_`, `revoke_park_`, `revoke_socket_` so sandbox
   filters never select a socket test.
8. Task 3's test has no unmodified-code red (Task 1's production code already
   exists), so its red is AC22(a) run by the orchestrator in the Terminal panel,
   plus a Coder-side mutation red for the two unit tests written after their
   implementation.
9. A Tester runs after each Coder task; the panel runs once on the whole branch.
   WORKFLOW says the panel runs after each task; every task edits the same two
   files and Tasks 1 and 2 are one mechanism, so per-task panels would re-read the
   same lines. Add a Task 1 panel if per-task review is wanted. Same call as PR 145.
10. In AC18 the agent subscribes before the operator (loose end 2).
11. `PARK_POLICY_RECHECK` is a private `const`; the integration tests use literal
    durations (800 ms is four slices at 200 ms).
12. `agent.approve allow:false` under a non-`ask` policy takes the unchanged
    resolve-and-succeed path (spec Design 5.1), with no policy read needed for it.

### Deviations (as executed; added after the stage-6 panel, 2026-10-30)

Where the run departed from this plan, so a reviewer does not have to find out from the logs.

1. **No separate whole-branch Tester pass.** Each task had its own Tester pass; the
   "Whole-branch stage 5" item below was not run as a separate dispatch. What stands in for it: the
   per-task Testers; the orchestrator's final-head full gate and the AC22 mutation runs, logged at
   `/tmp/apr-gate.log`, `/tmp/apr-mut-a.log`, `/tmp/apr-mut-b.log`, and `/tmp/apr-final-revoke.log`; and
   the Task 3 socket logs, `/tmp/apr-t3-*.log`. The panel built its own AC-to-test map. (These
   logs use the short `/tmp/apr-*` names, not the `/tmp/agent-policy-revocation-*` names Task 4 writes.)
2. **One panel for the whole branch**, as Call 9 said; there were no per-task panels.
3. **The Testers added 32 of the 55 `revoke_` tests** (Task 1: 10, Task 2: 19, and 3 more duplex tests in
   the Tester duplex-test commit). They were committed inside the `feat(mcp): task N` commits, except the
   three in the Tester duplex-test commit.
   The Coders wrote the other 23 (the 7 unit and 16 integration tests this plan names). The counts in Task 4
   are the true totals; the per-task red summaries in Tasks 1 and 2 describe the Coders' tests only.
4. **AC22(b), the clause "AC16 passes either way", was accepted on reasoning, not run.** The five existing `Ask`
   tests keep the policy at `ask` and are not selected by the `revoke_` filter, so the mutation run never
   executes them; they cannot fail on the mutation because it only changes behaviour when the policy leaves
   `ask`.
5. **Spec amended after the panel** (see the spec's "Amendments after panel"): the read predicate
   `agent_reads_allowed` is an allow-list (Task 1's bullet and Task 2's parenthetical are corrected in place);
   there are now six residuals, R1 to R6, stated in plain words in the source, with the labels living in the
   spec. Wherever Task 1, Loose end 5, or Task 4 as first written say "R1 to R5" or ask for R-labelled source
   docs, read R1 to R6 and plain words. AC21's grep is "no `sink.push` outside `Subscriptions::fanout` and
   `replay_since`". Task 4 steps 4 and 5 are updated to match.
6. **Base rebased twice**: onto `origin/main` v0.5.2 (`592a377`), then onto `origin/main` `9fb8cfa` (after PR 162);
   see the header. Counts and scope figures quoted below as "measured" were taken before the final rebase onto
   `9fb8cfa` (the base was then `592a377`), unless a line says otherwise; the full gate was re-run after it
   (Shipped, Evidence). The scope commands in Task 4 now use `9fb8cfa`. Branch commits are named by label, not
   hash, because the rebases rewrote the hashes.
7. **The `aitm tui` caveat was retired by the final rebase.** The panel's Security finding that `aitm tui`'s
   loopback agent server has a private `AgentState` (Review log) was true when written. PR 162 (on `origin/main`
   as `9fb8cfa`) puts that server on the core's shared `AgentState` and `AuditRing` through
   `tui::with_shared_governance`, so `aitm tui` is covered with no edit in `crates/aitm`, and this branch still
   does not touch `crates/aitm`. The spec's Amendments item 6 records it. The only tui caveat left is PR 162's own
   follow-up "tui-mode push": that server's flow push feed is not wired, so no live flow pushes occur there.

### PR description checklist (requested by the panel)

The PR body states each of these, in plain words, so a reader does not have to open the spec:

- [ ] **Residuals R1 to R6** (spec Design 6), one line each: R1 lines already queued in an agent sink (and a
  sink's own overflow `lagged` marker set before the pause) may still be written; R2 a `flow.subscribe
  {since}` past the gate just before the flip may replay just after; R3 a flap shorter than one parked-waiter
  slice is not seen; R4 a parked call past its post-wake recheck is in flight; R5 a fan-out that read the policy
  just before the flip may enqueue just after; R6 a call that passed the gate before the pause keeps running
  and its reply is delivered, and work already started (an armed intercept, a running scan) is not stopped by
  a pause.
- [ ] **`ask` to `all` (or to any non-`ask` policy) denies a parked request**, and the agent must re-issue the
  call under the new policy.
- [ ] **The other spec Risks:** the read side now fails closed for an unknown future posture (a behaviour
  change, no shipped policy affected, pinned by reading because no test can construct the variant); **`aitm tui`
  is covered** (PR 162 shares the core's `AgentState` with its agent server through
  `tui::with_shared_governance`, so a pause mutes its audit lines and a policy change denies its parked calls;
  this change adds nothing tui-specific; the only tui caveat is that its server has no flow push feed yet, PR 162's
  follow-up "tui-mode push"); the agent link goes quiet under `paused` (the operator
  link does not); a pause during a parked wait ends it early; and the agent-visible reason after
  `agent.approve allow:true` outside `ask` can read "an operator denied ..." or "the agent policy changed".
- [ ] **AC18 is Terminal-panel-only.** It binds `127.0.0.1:0`, so it ran outside the sandbox; attach or quote
  its red run (AC22(a) at task scope) and its green run, `/tmp/apr-t3-*.log`.
- [ ] **The true counts, as measured at the Tester duplex-test commit, before the post-panel fix commit and
  before the final rebase onto `9fb8cfa`** (the fix commit may add or change tests; if it does, the
  orchestrator re-measures and the Review log, not this plan, carries the new figures): `cargo test -p aitm-mcp --lib revoke_` is 24 passed; `cargo test -p aitm-mcp --test mcp revoke_`
  is 31 passed (23 `revoke_push_*`, 7 `revoke_park_*`, 1 `revoke_socket_*`); 55 in all, 32 of them added by
  the Testers. Mutation (a) fails 2 unit and 20 integration tests (22 unit and 11 integration pass);
  mutation (b) fails 10 unit and 6 integration tests (14 unit and 25 integration pass).

## Tasks

### Task 1: mute agent pushes under `paused`, with the gap marker (AC1-AC10, AC12(ii), AC21 push half)

- **Satisfies:** AC1, AC2, AC3, AC4, AC5, AC6, AC7, AC8, AC9, AC10, AC12(ii);
  AC20 (additions-only, scan); AC21 (single push site, shared predicate, push-side
  docs, byte-identical refusal text); plus the two Task 1 plan additions.
- **Depends on:** none.
- **Files:** `crates/aitm-mcp/src/server.rs` (modify), `crates/aitm-mcp/tests/mcp.rs`
  (append only). Nothing else.
- **Coder input (dispatch contract):** spec
  `docs/superpowers/specs/2026-10-30-agent-policy-revocation-design.md`, plan
  `docs/superpowers/plans/2026-10-30-agent-policy-revocation-plan.md`, "Task 1",
  worktree `/Users/matt/Security/aitmproxy/.claude/worktrees/ecstatic-lehmann-199e83`.
- **Terminal panel needed:** no. Everything is sandbox-safe with the filters above.

**Change (production, `server.rs`).**

- `fn agent_reads_allowed(policy: AgentPolicy) -> bool` (private free fn, next to
  `is_operator_only`). **Amended after the panel (spec Design 1, Amendments 2):** it is
  an allow-list. It returns `true` for exactly `All`, `Auto`, `Ask`, and `ReadOnly`, and
  `false` for `Paused` and for any posture it does not name, including a future
  `#[non_exhaustive]` variant, so the read side fails closed like `policy_decision` and
  `ask_still_in_force`. (The first draft, "`true` for every other value, exactly
  `read_refusal`'s present behaviour, `policy != AgentPolicy::Paused` is enough", is
  superseded: a deny-list of one posture compiles silently when a variant is added.) The
  `paused` refusal text and the five known policies' behaviour are unchanged; no test can
  construct an unknown variant, so this is pinned by reading and by the doc. Doc: the one
  decision behind "may an agent-role caller subscribe now" and "does it receive pushes
  now"; it is an allow-list, so a new variant is not allowed until it is added here.
- `McpServer::agent_pushes_muted(&self) -> bool`: one-line body, exactly
  `!agent_reads_allowed(self.agent_state.policy())` (trap 7a).
- `read_refusal(&self, conn: &ConnCtx, name: &str) -> Option<String>`: same role gate;
  read the policy once and ask `agent_reads_allowed`; the `Some(..)` text for `paused`
  stays **byte-identical**: `` `<name>` refused: the agent policy is `paused`; no agent command runs. An operator can change it with agent.set. `` (building the word from `policy.label()` is allowed). Doc updated: it is the read-side half of the one predicate.
- `SubState` gains `gapped: Vec<u64>`: the connections that had a line suppressed and
  have not yet been told. Doc: written and cleared only inside the fan-out helper and
  `drop_connection`, under the registry lock.
- `Subscriptions::fanout(&self, pushes_muted: &dyn Fn() -> bool, wants: &dyn Fn(&Subscription) -> bool, line: &str)`:
  the **only** code that sends to a subscription's sink on a fan-out. Rules, in order:
  1. take the registry lock, then call `pushes_muted()` **once**, and bind
     `let st = &mut *guard;` so `subs` and `gapped` borrow disjointly;
  2. walk `st.subs` in order with a `seen` list of connection ids, as today: skip a
     subscription whose connection is already `seen` or that `wants` says no to (a
     subscription skipped by `wants` does **not** mark its connection seen, as today);
  3. otherwise mark the connection seen;
  4. if the mute is on **and** `!sub.role.is_trusted_control()`: ensure the connection
     is in `st.gapped` (once) and send nothing; continue;
  5. otherwise build the lines to send: `lagged_state_line()` first **iff** the
     connection is in `st.gapped` (remove it from `gapped` now), then `line`;
  6. send them with one `for` loop calling `sub.sink.push(..)`. This is the only
     `sub.sink.push` in the file (trap 6).
  Docs on the helper (AC21): the single send site and why (a future fan-out cannot
  forget the mute); the policy read once per call after the lock; the per-connection
  gap (never a registry-wide flag, which the first delivery would clear); that the
  marker rides the first delivery after the gap, is never sent while muted, and is
  not the sink's own overflow flag (setting that at suppression time would leak a bit
  under pause through `drain`); and **residuals R1 to R5**, one line each, labelled
  `R1` to `R5`, in the spec's Design 6 words: R1 lines already queued in an agent
  sink may still be written (bounded by the sink capacity, nothing is purged); R2 a
  `flow.subscribe {since}` past the gate just before the flip may replay just after;
  R3 a flap shorter than one parked-waiter slice is not seen; R4 a parked call past
  its post-wake recheck is in flight; R5 a fan-out that read the policy just before
  the flip may enqueue just after.
- The three entry points keep their names and add `pushes_muted: &dyn Fn() -> bool` as
  a **last** parameter: `fanout_role(&self, role: Frontend, line: &str, pushes_muted:
  &dyn Fn() -> bool)`, `fanout_flow(&self, flow: &Flow, line: &str, pushes_muted: ..)`,
  `fanout_state(&self, line: &str, pushes_muted: ..)`. Each is a thin wrapper that
  supplies its `wants` (`sub.role == role` for the variable `role`; `sub.filter.matches(flow)`;
  always true). Comparing against the *parameter* `role` is not a scan hit; never
  spell `Frontend::Mcp` in a comparison.
- `Subscriptions::drop_connection(&self, conn_id: u64)`: also removes `conn_id` from
  `gapped`, under the same lock. Doc says so.
- Callers: `push_flow_event`, `push_state`, `push_agent`, `push_approval_request` pass
  `&|| self.agent_pushes_muted()`. Update the docs of `push_flow_event`, `push_state`,
  and `push_agent` (and `drop_connection`) to state the new behaviour: not enqueued
  for a non-trusted-control subscription while the policy is `paused`; a gap is
  recorded; the marker rides the first delivery after resume; operator and CLI
  subscriptions are never muted.
- **Do not touch:** `add`, `remove`, `any_role`, `subscribe`, `replay_since`,
  `run_tool`, `call_tool`, `enforce_verb_schema`, `NotificationSink`, anything in the
  `McpServer` field list (trap 2), or any other crate.

**Tests (write first; names exact; in-process, plain `#[test]`, no ports, no runtime).**

Rig, appended to `tests/mcp.rs` under a banner comment (all helper names free;
shapes fixed here). Build a registry holding `SubscriptionPlugin::new(tx)` (with a
`broadcast::channel::<Event>(64)`, as `push_registry` does) and
`AgentPlugin::new(state.clone())`. A server is `McpServer::new(registry,
McpTransport::Stdio).with_agent_state(state.clone()).with_services(store,
Arc::new(StubClient), Arc::new(StdGuard::default()), None)` over a `MemFlowStore`.
A connection is a `ConnCtx { role, client_label: None, conn_id: srv.next_conn_id(),
out: Some(sink) }` with its own `NotificationSink::new(64)`, subscribed with the
existing `subscribe_on(&srv, &conn, json!({}))` and `sub_id_of`. Pushes: a flow is
`store.insert(http_flow("example.com:443", "/x"))` then
`srv.push_flow_event(&Event::RequestHeaders(id))`; a state push is
`srv.push_state(json!({"k": 1}))`; an audit push is an `agent.status` call through
`srv.handle_on` by a **separate, sinkless** `ConnCtx::new(Frontend::Operator)` (its
audit line is fanned to every subscriber, so the subscriber under test receives
exactly that one audit line; the subscriber's own successful `flow.subscribe` is not
audited). Assertions
read `sink.drain()` parsed to JSON (no timing); a "marker" is a line with method
`notifications/aitm/state` and `params == {"lagged": true}`. A pair rig builds P and W
over one registry and one `Arc<AgentState>`, each with its own `Subscriptions`
(two `McpServer::new`).

`tests/mcp.rs`, filter `revoke_push`. The literal expected values are the spec's AC
text; this table adds each test's red.

| Test | Asserts (spec AC) | Against unmodified code |
|---|---|---|
| `revoke_push_paused_mutes_flow_pushes` | AC1 | **FAILS**: after `set_policy(Paused)` the drain holds one `notifications/aitm/flow` line where `[]` is expected. The first half (one line under `Auto`) passes. |
| `revoke_push_paused_mutes_state_and_agent_pushes` | AC2 | **FAILS**: the agent drain holds the state and agent lines where `[]` is expected; the operator half passes. |
| `revoke_push_trusted_control_is_never_muted` | AC3, roles `[Operator, Cli]`, exactly three lines in order flow, state, agent, no marker | passes (guard) |
| `revoke_push_policy_table_and_resume` | AC4 | **FAILS** on the `Paused` row (three lines where none are expected); rows `All`, `Auto`, `Ask`, `ReadOnly` pass. |
| `revoke_push_one_predicate_for_subscribe_and_delivery` | AC5, all five policies, pairs `(accepted, reached)` | **FAILS** on the `Paused` iteration (subscribe refused, push reached: `(false, true)`), the other four pass. Order the policies with `Paused` last. |
| `revoke_push_marker_exactly_once_before_first_post_gap_line` | AC6, including the two-agent-connection part | **FAILS**: after resume the first line is a flow line, not the marker (the paused push was delivered). |
| `revoke_push_no_marker_while_paused` | AC7 | **FAILS**: the drain returns the flow line where `[]` is expected. |
| `revoke_push_direct_flip_without_a_suppressed_push_has_no_marker` | AC8(i) | passes (guard) |
| `revoke_push_connection_with_nothing_suppressed_gets_no_marker` | AC8(ii). Also assert both drains are `[]` straight after the suppressed push, so the failure is read at the cause. | **FAILS** at B's drain straight after the suppressed push (B received the paused flow; `[]` expected). |
| `revoke_push_real_verb_pause_then_resume_marks` | AC9 | **FAILS**: after the operator's `agent.set paused` the agent drain holds the `agent.set` audit line where `[]` is expected. |
| `revoke_push_cross_server_pause_mutes_the_other_server` | AC10 (`agent.set` runs on P, pushes on W) | **FAILS**: W's agent drain holds the flow line where `[]` is expected. |
| `revoke_push_queued_lines_are_not_purged` | AC12(ii), pins residual R1 | passes (guard) |

Expected red summary: `test result: FAILED. 3 passed; 9 failed`, the three `ok`
being AC3, AC8(i), AC12(ii). Every failure must be on the assertion named above with
the drained lines in the message, and the setup assertions (the `sub_id` of each
subscribe) must pass; a connect or setup panic, or a compile error, means the test
is wrong, not red.

`server.rs` `mod tests` (unit, filter `--lib revoke_`):

- `revoke_read_refusal_text_is_unchanged` (guard, AC21). Build a server over
  `AgentState::new(Paused)`. `read_refusal(&ConnCtx::agent(), "flow.subscribe")` is
  `Some(..)` holding exactly `` `flow.subscribe` refused: the agent policy is `paused`; no agent command runs. An operator can change it with agent.set. ``
  (asserted with `assert_eq!` against the full string); the same with `flow.unsubscribe`
  as the name. `read_refusal` for a `Frontend::Operator` and a
  `Frontend::Cli` context is `None` under `Paused`; for the agent context it is
  `None` under each of `All`, `Auto`, `Ask`, `ReadOnly`. **Passes against unmodified
  code and after.**
- `revoke_gap_is_dropped_with_its_connection` (written **after** the implementation;
  see the procedure). An agent connection (`ConnCtx { role: Frontend::Mcp, conn_id:
  srv.next_conn_id(), out: Some(sink), .. }`, built by struct literal, never compared)
  subscribes with the real `flow.subscribe` through `handle_on` under `Auto`; then
  `set_policy(Paused)` and one flow push records a gap, so
  `srv.subscriptions.lock().gapped` contains the connection's id. Then
  `srv.drop_connection(conn_id)`: `gapped` is empty (message: "gapped must be empty
  after drop_connection").
  Connection ids are monotonic and never reused, so the leak is observable only
  through the private field, which the in-file module can read. Add `use
  aitm_plugins::AgentPlugin;` as a new line in that module if the server needs the
  plugin (the subscribe verb itself needs no registry entry: `enforce_verb_schema`
  skips an unregistered verb).

**Procedure, in this order (all in the Bash sandbox; paste each output).**

1. Write the rig, the 12 `revoke_push_*` tests, and `revoke_read_refusal_text_is_unchanged`.
   **No production edit yet.** `cargo test -p aitm-mcp --test mcp revoke_push --no-run`
   ends `Finished`.
2. **Red.** `cargo test -p aitm-mcp --test mcp revoke_push` must show
   `test result: FAILED. 3 passed; 9 failed` with the failures above. Also
   `cargo test -p aitm-mcp --lib revoke_` shows `1 passed; 0 failed`. Paste both,
   including each failing test's assertion line.
3. Implement the Change list.
4. **Green.** `cargo test -p aitm-mcp --test mcp revoke_push` shows `12 passed; 0 failed`.
5. Write `revoke_gap_is_dropped_with_its_connection`. **Red by mutation:**
   `cp crates/aitm-mcp/src/server.rs "$TMPDIR/server.rs.orig"`, temporarily delete the
   one statement in `drop_connection` that clears `gapped`, run
   `cargo test -p aitm-mcp --lib revoke_gap` and show the failure on "`gapped` is empty",
   restore from the copy, and show `diff "$TMPDIR/server.rs.orig"
   crates/aitm-mcp/src/server.rs` printing nothing. Then
   `cargo test -p aitm-mcp --lib revoke_` shows `2 passed; 0 failed`.
6. Literal checks, output pasted: `grep -c 'sub\.sink\.push' crates/aitm-mcp/src/server.rs`
   prints `1`; `grep -n 'agent_reads_allowed(' crates/aitm-mcp/src/server.rs` shows
   the definition, `read_refusal`, and `agent_pushes_muted`;
   `grep -n 'fn agent_pushes_muted' -A2 crates/aitm-mcp/src/server.rs` shows the
   signature, one body line, and `}`; `grep -n '\bR[1-5]\b' crates/aitm-mcp/src/server.rs`
   lists R1 to R5 in the helper's doc; `cargo test -p aitm-core --test trust_gate_scan`
   passes.
7. `cargo fmt --check` (exit 0); `cargo clippy -p aitm-mcp --all-targets -- -D warnings`
   (exit 0); `cargo test -p aitm-mcp --lib server::tests` (all pass); the existing
   in-process regression command from "Where each command runs" (all pass).
8. Report: files changed; the two red outputs, the mutation red, the green outputs;
   state plainly that no socket test was run (none exist yet). The orchestrator, not
   the Coder, checks that no existing line of `tests/mcp.rs` changed (`git diff
   --numstat`, below).

- **Orchestrator checkpoint (Terminal panel, after the Tester passes):**
  `git diff --numstat 9fb8cfa -- crates/aitm-mcp/tests/mcp.rs` shows `<N>\t0\t..`
  (zero removed lines); `touch` both sources; then
  `cargo test -p aitm-mcp > /tmp/agent-policy-revocation-t1.log 2>&1; echo "exit=$?"`
  prints `exit=0` (the whole crate, including the existing socket tests). Then commit.
- **Tester (stage 5, after the Coder):** inputs per the dispatch contract (spec, plan,
  worktree, base `9fb8cfa`, head SHA, "Task 1"). Map AC1-AC10 and AC12(ii) to the tests
  in the table; re-run steps 4-7 in the sandbox and quote them; confirm the shapes in
  trap 7a, the single `sub.sink.push`, the helper doc names R1-R5, no comparison against
  `Frontend::Mcp` was written, and the helper reads the policy once after the lock. The
  Tester may add tests only inside the two declared test locations.
- **Commit (orchestrator):** `feat(mcp): task 1 - mute agent pushes under paused, gap marker on resume (plan 2026-10-30-agent-policy-revocation)`.
- **Done when:** the red runs of steps 2 and 5 and the green runs of steps 4 and 5 are
  in the report, step 6 prints what is stated, step 7 is clean, the orchestrator
  checkpoint passed, and the orchestrator has committed.

### Task 2: parked requests follow the live policy (AC11-AC17, AC21 parked half)

- **Satisfies:** AC11, AC12(i), AC13, AC14, AC15, AC16, AC17; AC20; AC21 (parked-side
  docs, shared predicate); plus the Task 2 plan addition.
- **Depends on:** Task 1 (same two files; the test-section layout and the cross-server
  pair rig idea).
- **Files:** `crates/aitm-mcp/src/server.rs` (modify), `crates/aitm-mcp/tests/mcp.rs`
  (append only).
- **Coder input:** spec, plan, "Task 2", worktree (paths as Task 1).
- **Terminal panel needed:** no. The unit tests park a slot with no waiter; the
  integration tests use threads and `mpsc`, no ports.

**Change (production, `server.rs`).**

- `const PARK_POLICY_RECHECK: Duration = Duration::from_millis(200);` (private). Doc: how
  often a parked waiter re-reads the policy, the G2(iii) bound ("within one slice plus
  scheduling"), and the cost (at most `MAX_PARKED_REQUESTS` waiters, five wakeups a
  second each, one atomic load each).
- `enum ParkWait { Resolved(bool), TimedOut, PolicyChanged }` (private; derive `Debug,
  Clone, Copy, PartialEq, Eq`), with a doc line per variant.
- `fn ask_still_in_force(policy: AgentPolicy) -> bool` (private free fn): one-line
  body `policy == AgentPolicy::Ask` (trap 7b). Doc: the one test for "the policy a
  request was parked under still holds"; an unknown future posture is **not** `Ask`, so
  it fails closed (as `agent_reads_allowed` does too, after the panel amendment).
- `ParkSlot::wait` is **replaced** by `fn wait(&self, timeout: Duration, recheck: Duration,
  still_ask: &dyn Fn() -> bool) -> ParkWait`. Behaviour, in order: compute the deadline
  once on entry; lock the slot state; loop: (1) if the state is `Some(allow)` return
  `Resolved(allow)`; (2) if no time remains return `TimedOut`; (3) wait on the condvar
  for `min(recheck, remaining)` while the state is `None` (poison tolerated as today);
  (4) if the state is now `Some(allow)` return `Resolved(allow)`; (5) if `!still_ask()`
  return `PolicyChanged`; repeat. `Resolved` always wins over `PolicyChanged`; there is no
  policy read before the first slice; `still_ask` is lock-free and may run with the slot
  mutex held; the total wait never exceeds `timeout`. Doc says all of this.
- `fn settle_park(name: &str, wait: ParkWait, policy: AgentPolicy) -> ParkOutcome`
  (private, pure), exactly the spec's table: `(Resolved(true), p)` is `Approved` iff
  `ask_still_in_force(p)`, else `Refused` with the policy-changed text; `(Resolved(false),
  _)` is `Refused` with the **unchanged** text "`<name>` refused: an operator denied the
  parked sensitive command."; `(TimedOut, _)` is `Refused` with the **unchanged** text
  "`<name>` refused: no operator approved the parked sensitive command within the
  approval timeout."; `(PolicyChanged, p)` is `Refused` with the policy-changed text.
  Policy-changed text (proposed; the fragments "the agent policy changed" and the new
  label in backticks are fixed): "`<name>` refused: the agent policy changed from `ask`
  to `<label>` while this sensitive command awaited operator approval, so it was not run.
  Re-issue it if the new policy allows." A one-line `#[derive(Debug)]` on `ParkOutcome`
  is allowed (tests may otherwise `match`).
- `park_for_approval`: keep everything before the wait. Replace the tail with: wait via
  `slot.wait(self.approval_timeout, PARK_POLICY_RECHECK, &|| ask_still_in_force(self.agent_state.policy()))`;
  `self.parked.forget(&request_id)` (slot guard already released); then
  `settle_park(cmd.name(), waited, self.agent_state.policy())`, with the policy read
  **after** the wait returns. Doc updated: the live-policy behaviour, and sentences for **R3** (a flap
  shorter than one slice is not seen; the request stays parked and any approval is
  applied under the policy then in force) and **R4** (a call past its post-wake recheck
  is in flight, a microsecond window).
- `handle_approve`: role gate and the two parameter checks stay in their present order.
  Then read the policy once. If `ask_still_in_force(policy)`: the unchanged path. If not,
  and `allow` is `true`: resolve the request as **denied** (`self.parked.resolve(request_id,
  false)`); if it existed return a tool error with text (proposed) "agent.approve: the
  agent policy is no longer `ask` (it is `<label>`), so parked request `<id>` was denied,
  not approved. The agent may re-issue the call under the current policy." (fixed
  fragments: "no longer `ask`" and "denied"); if it did not exist return the **existing**
  "no parked request `<id>` is awaiting approval ..." error unchanged. If not `ask` and
  `allow` is `false`: the unchanged path (resolve as denied, success). Doc updated.
- **Do not touch** `any_role(Frontend::Operator)`, `MAX_PARKED_REQUESTS`, `forget`,
  `push_approval_request`, `policy_decision`, or the existing refusal texts.

**Tests (write first).**

`server.rs` `mod tests`, filter `--lib revoke_park`. Rig: a stub `Command` (Sensitive,
name `demo.sensitive`, returns `Value::Str("ran")`, increments a shared `AtomicUsize` when
invoked; add `use std::sync::atomic::AtomicUsize;` as a new line), a registry with it
and `AgentPlugin::new(state.clone())`, `McpServer::new(.., McpTransport::Stdio)
.with_agent_state(state.clone()).with_approval_timeout(60 s).with_services(Arc::new(MemFlowStore::new()),
Arc::new(NoClient), Arc::new(StdGuard::default()), None)` (a long timeout, so only a
policy change or a release can end a wait inside the test's 5 s bound). The agent context is
`ConnCtx::agent()`, the operator's is `ConnCtx::new(Frontend::Operator)`; all calls go
through `handle_on`.

| Test | Asserts (spec AC) | Against unmodified code |
|---|---|---|
| `revoke_park_approve_after_leaving_ask_is_refused_and_denies` | AC11: for `P` in `[Paused, ReadOnly, Auto, All]`, `AgentState::new(Ask)`, `srv.parked.try_park()` (no waiter), `state.set_policy(P)`, operator `agent.approve {request_id, allow: true}` is `isError: true` with "no longer `ask`" and "denied"; the slot's state is `Some(false)`; `srv.parked.len() == 0`. A second identical approve is `isError: true` with "no parked request `<id>`". With the state left at `Ask`, `allow: true` on a fresh slot is `isError: false` and the slot is `Some(true)`. | **FAILS** on the first `P`: approve returns `isError: false` (it resolved `allow: true`). |
| `revoke_park_deny_after_leaving_ask_is_honoured` | AC12(i): as above with `P = Paused` and `allow: false`: `isError: false`, slot `Some(false)`, table empty. | passes (guard) |
| `revoke_park_settle_decision_table` | AC13 table: `(Resolved(true), Ask)` is `Approved`; `(Resolved(true), P)` for `P` in `[All, Auto, ReadOnly, Paused]` is `Refused` containing "the agent policy changed" and `` `<P.label()>` ``; `(Resolved(false), any)` contains "an operator denied the parked sensitive command"; `(TimedOut, any)` contains "approval timeout"; `(PolicyChanged, any)` contains "the agent policy changed". | with the inert stub (procedure step 2) **FAILS** at `(Resolved(true), All)`: `Approved` where `Refused` is expected. |
| `revoke_park_approve_then_pause_is_denied_end_to_end` | AC13 end to end: the server is in an `Arc`; register an operator subscription directly with `srv.subscriptions.add(conn_id, Frontend::Operator, sink, FlowFilter::default())` so a call can park; an agent `tools/call demo.sensitive` runs on a `std::thread` and reports over `mpsc`; poll `srv.parked.len() == 1` (10 ms steps, 5 s cap), read the id from `srv.parked.lock().entries[0].0`; `state.set_policy(Paused)`; resolve the slot as **approved directly through the table** (`srv.parked.resolve(&id, true)`, ignore the bool: the waiter may already have denied); `recv_timeout(5 s)`: the reply is `isError: true` with "the agent policy changed" and "`paused`", and the stub's counter is `0`. On a timeout, deny the slot (`resolve(&id, false)`) so the thread ends, then panic. | **FAILS**: the reply is `isError: false` with `structuredContent == "ran"` (the approved call ran; counter `1`). |
| `revoke_park_slot_wait_honours_timeout_resolve_and_recheck` (written **after** the implementation) | `ParkSlot::new()` directly: (a) `wait(50 ms, 2 s, || true)` is `TimedOut` in at least 50 ms and under 1 s (the last slice is shortened); (b) a thread resolves `true` after 50 ms while the main thread is in `wait(30 s, 10 s, || true)`: `Resolved(true)` in under 5 s; (c) `wait(30 s, 20 ms, || false)` on an unresolved slot is `PolicyChanged` in under 5 s; (d) a slot already resolved `true` with `still_ask` returning `false` is `Resolved(true)`. | n/a (does not compile before the implementation); mutation red below |

`tests/mcp.rs`, filter `revoke_park`. Rig: `revoke_ask_rig(approval_timeout) -> (Arc<McpServer>,
Arc<AgentState>)`, built like the existing `ask_server` (which hides its state, so it
cannot be reused and is not edited): `TierCmd { name: "demo.sensitive", sens:
Sensitivity::Sensitive }`, `AgentPlugin::new(state.clone())`, `.with_agent_state`,
`.with_approval_timeout`, `.with_services(..)`. A pair rig builds P and W over one
`Arc<Registry>` and one `Arc<AgentState>` (two `McpServer::new`). Helpers: an operator
connection subscribed on a server (`ConnCtx` with its own sink, existing `subscribe_on`);
`wait_for_approval_request(&sink, 5 s) -> String` polling `sink.drain()` every 10 ms for the
line whose `params.event == "approval_requested"` and returning `params.request_id`
(panic text includes every drained line); `spawn_agent_call(&Arc<McpServer>) ->
mpsc::Receiver<JsonValue>` running a `demo.sensitive` call as `ConnCtx::new(Frontend::Mcp)`
on a `std::thread`; and `recv_or_release(rx, srv, request_id, within, what) -> JsonValue`:
`recv_timeout(within)`, and on a timeout **first** send operator `agent.approve {request_id,
allow: false}` on that server (so no thread outlives the test by the approval timeout), then
panic with `what`. `approval_timeout` is 60 s in all three tests.

| Test | Asserts (spec AC) | Against unmodified code |
|---|---|---|
| `revoke_park_waiter_denies_promptly_when_the_policy_leaves_ask` | AC14: for `P` in `[Paused, ReadOnly, Auto, All]`, a fresh rig each time: operator subscribed; agent call parks (the operator sink shows `approval_requested`); `state.set_policy(P)` and nothing else; the call returns within 5 s with `isError: true`, "the agent policy changed" and `` `<P.label()>` ``; the result is not `ran`. | **FAILS** on `Paused` after 5 s: "the agent call did not return within 5s after set_policy(paused)" (the waiter sleeps to its 60 s timeout; the helper then releases it). |
| `revoke_park_ask_to_ask_does_not_deny` | AC15: with a call parked, operator `agent.set {"policy":"ask"}`; `recv_timeout(800 ms)` is a timeout (the call has not returned); operator `agent.approve {request_id, allow: true}` is `isError: false`; the agent reply is `isError: false` with `structuredContent == "ran"`. | passes (guard) |
| `revoke_park_cross_server_pause_denies_the_other_servers_call` | AC17: P and W share registry and state, `Ask`; operator subscribed on W; agent call parked on W; operator `agent.set {"policy":"paused"}` **on P**; the W call returns within 5 s with `isError: true`, "the agent policy changed" and "`paused`", not `ran`. | **FAILS** after 5 s, same message shape as AC14. |

AC16 is the five existing tests (`ask_parks_then_approves`, `ask_deny_refuses`,
`ask_timeout_refuses`, `ask_without_operator_refuses`, `agent_cannot_approve_own_request`),
not modified. `ask_timeout_refuses` (300 ms) also exercises the shortened last slice.

**Procedure, in this order (all in the Bash sandbox; paste each output).**

1. Write `revoke_park_approve_after_leaving_ask_is_refused_and_denies`,
   `revoke_park_deny_after_leaving_ask_is_honoured`, and
   `revoke_park_approve_then_pause_is_denied_end_to_end` (all compile against unmodified
   code).
2. Add the **inert scaffolding** the table test needs, and nothing else: the real
   `ParkWait` enum and an inert `fn settle_park(..) -> ParkOutcome` whose body returns
   `ParkOutcome::Approved`. Production behaviour is unchanged (nothing calls it).
   Write `revoke_park_settle_decision_table`. In `tests/mcp.rs` write the rig and the three
   `revoke_park_*` integration tests.
3. **Red.** `cargo test -p aitm-mcp --lib revoke_park` must show `test result: FAILED.
   1 passed; 3 failed` (AC12(i) ok; AC11, the table, and the end-to-end test failed, on
   the assertions in the table). `cargo test -p aitm-mcp --test mcp revoke_park` must show
   `test result: FAILED. 1 passed; 2 failed` (AC15 ok; AC14 and AC17 failed after about
   5 s each). Paste both.
4. Implement the Change list (replace the inert `settle_park` with the real one).
5. **Green.** `cargo test -p aitm-mcp --lib revoke_park` shows `4 passed; 0 failed` (AC11,
   AC12(i), the table, the end-to-end test) and `cargo test -p aitm-mcp --test mcp revoke_park`
   shows `3 passed; 0 failed` (AC14, AC15, AC17). Then write
   `revoke_park_slot_wait_honours_timeout_resolve_and_recheck`. **Red by mutation:** copy
   `server.rs` aside as in Task 1, temporarily remove the `min(recheck, remaining)`
   shortening in `ParkSlot::wait` (so a slice always lasts `recheck`), run
   `cargo test -p aitm-mcp --lib revoke_park_slot` and show it fail on part (a) (about 2 s
   against a 1 s bound), restore, and show `diff` printing nothing. Then
   `cargo test -p aitm-mcp --lib revoke_park` shows `5 passed; 0 failed`.
6. AC16: the five existing tests pass, in one `cargo test -p aitm-mcp --test mcp -- ...`
   command listing them.
7. Literal checks, output pasted: `grep -n 'ask_still_in_force(' crates/aitm-mcp/src/server.rs`
   shows the definition, `handle_approve`, the waiter's closure, and `settle_park`;
   `grep -n 'fn ask_still_in_force' -A2 ..` shows one body line; `grep -n
   'PARK_POLICY_RECHECK' ..` shows the definition, its doc, and the one use;
   `grep -c 'sub\.sink\.push' ..` still prints `1`; `cargo test -p aitm-core --test
   trust_gate_scan` passes.
8. `cargo fmt --check`, `cargo clippy -p aitm-mcp --all-targets -- -D warnings`,
   `cargo test -p aitm-mcp --lib server::tests`, and the Task 1 test set
   (`--test mcp revoke_push`, `--lib revoke_`) all pass.
9. Report: files changed; both red outputs; the mutation red; the green outputs; "no
   socket test run".

- **Orchestrator checkpoint (Terminal panel, after the Tester):** `git diff --numstat
  <task-1-sha> -- crates/aitm-mcp/tests/mcp.rs` shows zero removed lines; the awk check of
  Task 4 step 4c on the `server.rs` test region; `touch` both sources;
  `cargo test -p aitm-mcp > /tmp/agent-policy-revocation-t2.log 2>&1; echo "exit=$?"`
  prints `exit=0`. Then commit.
- **Tester (stage 5):** inputs as Task 1 with "Task 2" and base = Task 1's commit. Map AC11-AC17
  to the tests; confirm AC14/AC15/AC17 bound every wait with `recv_timeout` and release a
  parked waiter on failure; confirm `ask_still_in_force` is the only place `Ask` is tested for
  the parked path and that `handle_approve`, the waiter, and `settle_park` all call it; confirm
  the policy is read after the wait returns and the slot guard is released first; confirm the
  fixed text fragments appear and the unchanged texts are byte-identical; re-run steps 5-8 and
  quote them.
- **Commit (orchestrator):** `feat(mcp): task 2 - deny parked requests when the policy leaves ask (plan 2026-10-30-agent-policy-revocation)`.
- **Done when:** the red runs of steps 3 and 5 and the green runs of step 5 are in the report,
  steps 6-8 are clean, the checkpoint passed, and the orchestrator has committed.

### Task 3: the one real-socket test (AC18)

- **Satisfies:** AC18; AC20 (additions only); AC22(a) for AC18 (the red).
- **Depends on:** Task 1 (the muting; Task 2 is not required but this task is sequential after it).
- **Files:** `crates/aitm-mcp/tests/mcp.rs` (append only). Edit no other file.
- **Coder input:** spec, plan, "Task 3", worktree.
- **Terminal panel needed: yes, for every run of this test.** It binds `127.0.0.1:0`. The Coder writes and
  compiles; the orchestrator runs.

**Change.** One `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]` named
`revoke_socket_paused_agent_goes_quiet_and_resumes_with_a_marker`, in the new section of
`tests/mcp.rs`, plus its small private helpers (names free). Rig, in the pattern of
`serve_still_spawns_the_push_dispatcher`: a registry with `SubscriptionPlugin` and
`AgentPlugin::new(state.clone())`; `McpServer::new(registry, McpTransport::LoopbackTcp {
port: 0, token: "tok".into(), endpoint_file: None }).with_agent_state(state.clone())
.with_services(store.clone(), Arc::new(StubClient), Arc::new(StdGuard::default()), None)
.with_mcp_roles(Some("op".into()), Frontend::Mcp).with_push(tx.clone())`, `AgentState::new(Auto)`,
`broadcast::channel::<Event>(16)`; `.on_bound(..)` sends the bound address over a `oneshot`;
`tokio::spawn(srv.serve())`. Each connection is a `TcpStream` that writes its token line
(`{"token":"tok"}` for A, `{"token":"op"}` for O) then its requests, reads through
`BufReader::lines()`, and writes with the borrowed halves from `s.split()`. Every read has a
deadline (`tokio::time::timeout`, 5 s for an expected line); every line each connection
receives is **collected**, and every assertion prints the collected lines.

Steps, as AC18, with these refinements:

0. **A subscribes first, then O** (registry order; this is what makes O's receipt a real
   fence, loose end 2). Each sends `flow.subscribe {}`; both replies carry a `u64`
   `structuredContent.sub_id`.
1. F1 (`/one`) is inserted and `Event::RequestHeaders(F1)` sent on `tx`. A and O each receive a
   `notifications/aitm/flow` line with `params.id == F1` and `params.summary.path == "/one"`.
2. O sends `agent.set {"policy":"paused"}`; its reply has `structuredContent.policy == "paused"`.
   F2 (`/two`) is inserted and sent. O reads until it has a flow line with `params.id == F2` (the
   fence; it may first read the `agent.set` audit line). A then sends `{"jsonrpc":"2.0","id":N,
   "method":"ping"}` and reads until its reply (`result == {}`); then
   `tokio::time::timeout(250 ms, ..)` on A's next line must **elapse**. Assert, printing A's
   collected lines: none names F2's id; none is a `notifications/aitm/agent` line for `agent.set`;
   none is a marker.
3. O sends `agent.set {"policy":"auto"}` and waits for its reply; F3 (`/three`) is inserted and sent.
   A reads until a flow line naming F3. Assert on A's lines since step 2: the first is the marker
   (method `notifications/aitm/state`, `params == {"lagged": true}`); the `agent.set` audit line may
   follow; then the F3 flow line; exactly one marker in all; and no line A received at any point
   contains F2's id.

**Procedure.**

1. **Coder (sandbox):** write the test; `cargo test -p aitm-mcp --test mcp revoke_socket --no-run`
   ends `Finished` and prints an `Executable ... mcp` line; `cargo fmt --check` and `cargo clippy -p
   aitm-mcp --all-targets -- -D warnings` exit 0. Report "compiled, NOT RUN (socket)". Do not
   run git; do not commit (the orchestrator checks the additions-only rule with `--numstat`, step 4).
2. **Red (orchestrator, Terminal panel), AC22(a) at task scope.** Preconditions:
   `grep -c 'fn agent_pushes_muted' crates/aitm-mcp/src/server.rs` prints `1`; `n=$(grep -n 'fn
   agent_pushes_muted' crates/aitm-mcp/src/server.rs | cut -d: -f1); sed -n "${n},$((n+2))p"
   crates/aitm-mcp/src/server.rs` shows the signature, exactly one body line, and `}`. Then
   `cp crates/aitm-mcp/src/server.rs /tmp/agent-policy-revocation-server.rs.orig`,
   `sed -i.bak "$((n+1))s/.*/        false/" crates/aitm-mcp/src/server.rs`, `touch` the sources, and
   `cargo test -p aitm-mcp --test mcp revoke_socket > /tmp/agent-policy-revocation-t3-red.log 2>&1; echo "exit=$?"; grep -E "^test |^test result|panicked" /tmp/agent-policy-revocation-t3-red.log`.
   **Must show** `exit=101` and `test result: FAILED. 0 passed; 1 failed`, with the panic message
   naming A's collected lines and F2's id (or the unexpected line) at step 2. Any other cause (a
   connect error, an unauthorised token, a rejected `ping`, a panic in the rig) means the test is
   wrong: send it back to the Coder. Restore with `mv crates/aitm-mcp/src/server.rs.bak
   crates/aitm-mcp/src/server.rs`; `diff /tmp/agent-policy-revocation-server.rs.orig
   crates/aitm-mcp/src/server.rs` prints nothing and `git status --short` shows no `.bak` and no
   `server.rs` change.
3. **Green (orchestrator, Terminal panel):** `touch` the sources;
   `cargo test -p aitm-mcp --test mcp revoke_socket > /tmp/agent-policy-revocation-t3-green.log 2>&1; echo "exit=$?"; grep -E "^test |^test result" /tmp/agent-policy-revocation-t3-green.log`
   **must show** `exit=0` and `test result: ok. 1 passed; 0 failed`. Run it three times; a flake is a
   defect in the test, not something to retry past.
4. `git diff --numstat <task-2-sha> -- crates/aitm-mcp/tests/mcp.rs` shows zero removed lines.

- **Tester (stage 5):** inputs as Task 1 with "Task 3", plus the two Terminal logs attached. Read the
  test against the three steps above and AC18 (every literal value present; A before O; deadlines on
  every read; the negative assertion follows a fence); flag any assertion that would pass on a default.
  The Tester must not report the socket test as run unless the log is attached.
- **Commit (orchestrator):** `test(mcp): task 3 - real-socket revocation test (plan 2026-10-30-agent-policy-revocation)`.
- **Done when:** the red log (`0 passed; 1 failed`, failing on the F2/quiet assertion) and the green log
  (`1 passed`, three runs) are attached, the restore is proven, and the orchestrator has committed.

### Task 4: orchestrator checkpoint (Terminal panel; no Coder, no retained edits)

- **Satisfies:** AC19, AC20, AC21 (greps), AC22; confirms AC1-AC18 on the final head.
- **Depends on:** Tasks 1-3 committed.
- **Files:** none retained. The AC22 steps temporarily edit `server.rs` and restore it.

Steps and required output (orchestrator, Terminal panel; `touch` both sources before each run). Counts below are
the true totals measured at the Tester duplex-test commit, before the post-panel fix commit and before the final
rebase onto `9fb8cfa` (the base was then `592a377`); the fix commit may add or change tests,
in which case the orchestrator re-measures and the Review log carries the new figures. The run used the short log
names `/tmp/apr-gate.log`, `/tmp/apr-mut-a.log`, `/tmp/apr-mut-b.log`, `/tmp/apr-final-revoke.log` where this
section writes `/tmp/agent-policy-revocation-*.log` (see Deviations).

1. **Full gate** on the final head:
   `(cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test) > /tmp/agent-policy-revocation-gate.log 2>&1; echo "gate exit=$?"`
   **must print** `gate exit=0`. Display only: `grep -E "Running .*mcp|^test result" /tmp/agent-policy-revocation-gate.log`.
   Known flake: if `rhai_e2e::script_cannot_escape_or_exceed_scope` is the only failure, re-run
   once and judge by whether this diff touches Rhai (it does not); record it in the Review log.
2. **Web bus regression (AC20, unmodified binaries):**
   `cargo test -p aitm --test web_bus_governance --test web_bus_push --test web_bus_ask_split --test web_bus_roles --test web_bus_concurrency > /tmp/agent-policy-revocation-webbus.log 2>&1; echo "webbus exit=$?"`
   **must print** `webbus exit=0`; record the five `test result:` counts (all `ok`, zero failed).
3. **Final-head `revoke_` run (all green, with the socket test):**
   `cargo test -p aitm-mcp --lib --test mcp revoke_ > /tmp/agent-policy-revocation-revoke.log 2>&1; echo "exit=$?"`
   **must print** `exit=0`, `24 passed` for the unit binary (the Coders' 7 plus 17 added by the Testers), and
   `31 passed` for `tests/mcp.rs` (23 `revoke_push_*`, 7 `revoke_park_*`, 1 `revoke_socket_*`; the Coders'
   16 plus 15 added by the Testers): 55 `revoke_` tests in all.
4. **Scope (AC19, AC20), explicit base SHA (`origin/main` moves); the base is `9fb8cfa`:**
   a. `git diff --name-only 9fb8cfa..HEAD` lists exactly four paths: `crates/aitm-mcp/src/server.rs`,
      `crates/aitm-mcp/tests/mcp.rs`,
      `docs/superpowers/plans/2026-10-30-agent-policy-revocation-plan.md`, and
      `docs/superpowers/specs/2026-10-30-agent-policy-revocation-design.md`.
   b. `git diff --stat 9fb8cfa..HEAD -- crates/aitm-core crates/aitm crates/aitm-plugins` prints nothing (this
      branch still does not touch `crates/aitm`; PR 162's edits to it are already in the base).
   c. `git diff --numstat 9fb8cfa..HEAD -- crates/aitm-mcp/tests/mcp.rs` shows `<N>\t0\t..` (zero removed).
      For `server.rs`, no removal inside the existing test module. Do not hard-code its line: read where
      `mod tests` starts in the base, and use the line before it (the `#[cfg(test)]` attribute) as the
      threshold, `st-1`. At `9fb8cfa` `mod tests` is at line 2220 (the same line as at `592a377`: PR 162 changed
      nothing under `crates/aitm-mcp`), so `st-1` is 2219:
      `st=$(git show 9fb8cfa:crates/aitm-mcp/src/server.rs | grep -n '^mod tests' | cut -d: -f1); echo "base mod tests line=$st"`
      prints `base mod tests line=2220`, then
      `git diff -U0 9fb8cfa..HEAD -- crates/aitm-mcp/src/server.rs | grep '^@@' | awk -v t=$((st-1)) '{split($2,a,","); n=(a[2]==""?1:a[2]); s=substr(a[1],2); if (n>0 && (s+0)>=t) print "REMOVAL IN TEST REGION: " $0}'`
      prints nothing. (Run both in one shell invocation so `st` is still set.)
5. **AC21 checks (as amended).** `grep -n 'sink\.push' crates/aitm-mcp/src/server.rs`: every hit is inside
   `Subscriptions::fanout` or `replay_since`, and none is in the `mod tests` module (inside `fanout` the marker
   and the line may be one loop or two pushes; the check is where, not how many);
   `grep -n 'agent_reads_allowed(' ..` shows `read_refusal` and `agent_pushes_muted` as callers, and the function
   itself is an allow-list (`true` for exactly `All`, `Auto`, `Ask`, `ReadOnly`);
   `grep -n 'ask_still_in_force(' ..` shows `handle_approve`, the waiter, and `settle_park`;
   `grep -n 'PARK_POLICY_RECHECK' ..` shows the doc'd definition and the use;
   the helper's doc (and `park_for_approval`'s, for the parked ones) states the six residuals of spec Design 6
   in plain words (no grep: the labels R1 to R6 live in the spec and the source need not carry them);
   `cargo test -p aitm-core --test trust_gate_scan` is `ok` (also inside the gate). The Tester reads the
   docs on `push_flow_event`, `push_state`, `push_agent`, `read_refusal`, `park_for_approval`,
   `handle_approve`, `ParkSlot::wait`, the helper, and `PARK_POLICY_RECHECK`, and the `paused` text.
6. **AC22(a), mutation of the push side.** Preconditions and edit exactly as Task 3 step 2 (backup,
   one-body-line check, replace the body line with `false`). Run
   `cargo test -p aitm-mcp --no-fail-fast --lib --test mcp revoke_ > /tmp/agent-policy-revocation-mut-a.log 2>&1; echo "exit=$?"; grep -E "^test |^test result" /tmp/agent-policy-revocation-mut-a.log`
   **Must show** `exit=101` and:
   - `tests/mcp.rs`: `test result: FAILED. 11 passed; 20 failed`. The failures include AC1, AC2, AC4, AC5,
     AC6, AC7, AC8(ii), AC9, AC10 and the socket test AC18, plus the Testers' additional push tests that assert
     a suppression. The eleven `ok` are the guards and the parked tests, which the mute does not affect (named
     guards: `revoke_push_trusted_control_is_never_muted`,
     `revoke_push_direct_flip_without_a_suppressed_push_has_no_marker`,
     `revoke_push_queued_lines_are_not_purged`; the per-test list is in the log).
   - unit binary: `test result: FAILED. 22 passed; 2 failed`; the failures include
     `revoke_gap_is_dropped_with_its_connection` (no gap is ever recorded).
   Each failure message names the missing suppression, a policy cause (a line where `[]` was expected, a
   missing marker, F2 reaching A), never a compile or connect error. Restore, prove with `diff` against the
   backup and `git status --short` (no `.bak`, no `server.rs` change).
7. **AC22(b), mutation of the parked side.** `grep -c 'fn ask_still_in_force' ..` prints `1`; `n=$(grep -n
   'fn ask_still_in_force' .. | cut -d: -f1); sed -n "${n},$((n+2))p" ..` shows the signature, one body line,
   `}`. Backup, `sed -i.bak "$((n+1))s/.*/        true/" ..`, then the same command into
   `/tmp/agent-policy-revocation-mut-b.log`. **Must show** `exit=101` and:
   - `tests/mcp.rs`: `test result: FAILED. 25 passed; 6 failed`; the failures include AC14 and AC17 (each fails
     on "did not return within 5s", the waiter never wakes and the helper releases it) and the Testers'
     additional `revoke_park_*` integration tests that assert a denial; AC15 and every `revoke_push_*` and the
     socket test are `ok`.
   - unit binary: `test result: FAILED. 14 passed; 10 failed`; the failures include
     `revoke_park_approve_after_leaving_ask_is_refused_and_denies` (AC11),
     `revoke_park_settle_decision_table` and `revoke_park_approve_then_pause_is_denied_end_to_end` (AC13), and
     the Testers' additional unit tests that assert a denial; `revoke_park_deny_after_leaving_ask_is_honoured`
     (AC12(i)), `revoke_park_slot_wait_honours_timeout_resolve_and_recheck`,
     `revoke_read_refusal_text_is_unchanged`, and `revoke_gap_is_dropped_with_its_connection` are `ok`.
   Restore and prove as in step 6. Then re-run step 3's command: `exit=0`, `24 passed` and `31 passed`.
   (These are measured counts, not predictions. If a later commit changes the number of tests, the orchestrator
   re-measures and records the new figures in the Review log; a mismatch that is not a counting difference is a
   finding.)
8. The Tester report for the whole branch quotes steps 1-7 with the logs attached.

- **Done when:** all eight steps print what is stated, the logs are saved and quoted in the whole-branch
  Tester report, and `git status --short` is clean.

## Whole-branch stage 5 and stage 6

1. **Whole-branch Tester** (after Task 4): inputs per the dispatch contract (spec, plan, worktree, base
   `9fb8cfa`, head SHA, "whole branch"), with the Task 4 logs attached. Every criterion AC1-AC22 maps to a
   test, a literal check, or a mutation run; the Tester quotes the gate output. PASS or FAIL with reasons.
   (As executed this was not a separate dispatch; see Deviations, item 1.)
2. **Panel, in parallel, fresh contexts:** `security-reviewer`, `quality-reviewer`, `spec-reviewer`, each given
   the spec, plan, worktree, base `9fb8cfa`, head SHA, "whole branch", the Coders' reports, and the Tester
   report. Suggested focus, not a limit.
   Security: G1 and G2 hold on every surface whose server shares the `AgentState` (loopback, stdio, `/bus`,
   including a second `McpServer` sharing state, and `aitm tui`'s loopback agent server, which PR 162 puts on
   the shared state; that server's flow push feed is not wired yet, PR 162's follow-up "tui-mode push", so on it
   only audit lines and parked calls are governed); trusted control is never muted (allow-list through `is_trusted_control`, including
   a future `Frontend` variant); nothing leaks under `paused` (no marker, no notice, no audit line, bar the
   sink's own earlier overflow marker, R1); both sides fail closed (the parked path denies an unknown future
   posture, and the read predicate is an allow-list that refuses one); lock order (registry lock outside, sink
   lock inside, the policy read lock-free, the slot mutex never held across the table lock); the 200 ms
   wakeups are bounded (at most 64 waiters); residuals R1-R6 are accurately stated and acceptable.
   Quality: one predicate on each side; one send site; names and docs; determinism of the new tests (bounded
   waits, the fence, no sleeps standing in for synchronisation except the stated 250 ms and 800 ms negative
   checks); the additions-only rule held; test-section layout in `tests/mcp.rs`.
   Spec: AC1-AC22 against the tests; the file fence (only `server.rs`, `tests/mcp.rs`, the spec and this plan);
   the spec's `Status` line untouched; R1-R6 and the "`ask` to `all` denies a parked request" consequence are
   in the PR description (the "PR description checklist" above, before Task 1, lists everything the PR body states).
3. The orchestrator records every finding and disposition in the Review log below. Critical and Important
   findings go to a fresh Coder as a fix task (input: the findings report), then Tester and panel run again on
   the fix with the prior report. No merge with an open finding.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 1 | Tester | n/a | Two production mutants survived the Coder's suite: `drop_connection` clearing every connection's gap, and a gap that is not de-duplicated (grows per suppressed push; spurious second marker). | Fixed in the Task 1 commit: the Tester added 10 tests (2 unit, 8 integration) that kill both; all other 13 mutants were already killed. |
| 2 | Tester | n/a | Eight of 27 production mutants survived: policy change winning over an already-resolved slot, resolved slot with a zero timeout reported as timed out, `Instant + Duration::MAX` overflow, `forget` dropped or a no-op (table entry leak), zero-length and 1 ms recheck slices, a poisoned slot mutex. | Fixed in the Task 2 commit: the Tester added 19 tests (15 unit, 4 integration); all 29 mutants then killed, including the plan's AC22(b) edit. |
| 3 | Tester | none | PASS. Optional hardening not adopted: step 2 could assert A's full stream, step 1 does not assert "exactly one" F1 line, step 3 does not check F3's path; the `[marker, flow F3]` variant in step 3's allowed list is dead for a correct implementation. | Accepted (autonomous-approve mode, 2026-10-30): none can make the test flaky or vacuous; the Tester's own duplex test (the Tester duplex-test commit) pins the exact whole-stream sequences through the real writer. |
| 3 | Tester | n/a | Added 3 sandbox-runnable real-writer duplex tests (two agents plus an operator pause and resume with exact streams; an agent dropping while paused; a paused agent still gets every reply but no push). | Added in the Tester duplex-test commit. |
| all | Spec | Minor | The whole-branch Tester did not run and the plan did not record the deviation. | Accepted (autonomous-approve mode): recorded in the plan's Deviations (item 1) and under Shipped; the per-task Testers, the orchestrator's final-head gate and AC22 runs, and the panel's own AC-to-test map stand in for it. |
| all | Spec | Minor | The plan's counts, AC table and base SHA were stale at head (the Testers added tests; `origin/main` moved). | Fixed in the docs-amendment commit (counts, base `592a377` as it was then, scope commands corrected). The AC table is not extended to the 32 Tester additions; the panel's AC map is the record. |
| all | Spec | Minor | Tester additions for Tasks 1 and 2 sit inside the `feat(mcp): task N` commits, not `test(...): tester -` commits. | Accepted: tests only, inside the two declared test locations; the Review log rows above name them and their count (32 of the 55 `revoke_` tests). |
| all | Spec | Minor | AC22(b)'s "AC16 passes either way" clause is not shown in the mutation log (the `revoke_` filter does not select the five existing `Ask` tests). | Accepted on reasoning: those tests keep the policy at `ask`, so a `true`-returning `ask_still_in_force` equals the real value; AC3, AC12, AC15 are shown passing under (b). |
| 1-2 | Security | Minor | `agent_reads_allowed` was a deny-list of `Paused`: an unknown future `#[non_exhaustive]` posture would still subscribe and receive pushes, while `policy_decision` and `ask_still_in_force` fail closed. | Fixed in the panel-fix commit: allow-list of All, Auto, Ask, ReadOnly; everything else refused. Spec Design 1, Constraints, the behaviour table and Risks amended in the docs-amendment commit. Not testable (no test can construct an unknown variant); pinned by reading and the doc. |
| all | Security | Minor | Residual list omits calls already past the gate keeping running (R6), the sink's own overflow `lagged` flag (R1 gap), and `aitm tui`'s private `AgentState` (Intent over-claimed "every agent surface"). | Fixed in the panel-fix commit (source docs, plain words) and the docs-amendment commit (spec: R6, R1 extended, Intent reworded to "every surface whose server shares the AgentState"); caveats moved onto `with_agent_state` in the comment-only commit. (The `aitm tui` clause: Superseded by PR 162 on main; see Shipped.) |
| 2 | Security | Minor | A policy-driven denial (`agent.approve allow:true` after the policy left `ask`) is recorded for the agent as "an operator denied", contradicting the operator's own `agent.approve` error. | Accepted (autonomous-approve mode, 2026-10-30): spec 5.1/5.3 mandate the wording, the outcome is safe and the operator's reply carries the reason; fixing it needs a three-valued slot. Recorded in the spec amendments and as a follow-up. |
| all | Quality | Minor | `RvSock` and `RvWire` test clients are the same harness written twice; `read_until` is a third copy. | Accepted (autonomous-approve mode): test-only; the socket half cannot be exercised in the sandbox so a refactor cannot be verified there; both copies are mutation-checked. Follow-up. |
| all | Quality | Minor | Coder and Tester wrote overlapping scenarios; a few tests (constant band, computed-oracle cross product, 1 MiB payloads) are change-detectors. | Accepted: deleting risks reopening mutants the Tester recorded as killed (the constant-band test is the only guard of the 100 to 250 ms recheck bound); they are fast. |
| all | Quality | Minor | Setup, release and naming helpers sprawl (`rv_`, `Rv*`, `revoke_*`, `revoke_tester_*`; three release mechanisms). | Accepted: reading cost only; follow-up with the harness dedupe. |
| 2 | Quality | Minor | `ParkSlot::wait` builds an `Option<Instant>` deadline with a `None` branch for overflow. | Fixed in the panel-fix commit: `start` Instant plus `saturating_sub(start.elapsed())`; the `Duration::MAX` tests still pass. |
| 1 | Quality | Minor | The marker block is contorted (`Option<String>` + `chain`) to keep exactly one `sub.sink.push`. | Fixed in the panel-fix commit (plain `if let` + two pushes); AC21 relaxed to "no sink push outside `fanout` and `replay_since`" in the docs-amendment commit. |
| all | Quality | Minor | Production docs are long, narrate the code, carry spec-private R/G labels, and put parked-path residuals on the fan-out doc. | Fixed in the panel-fix commit (rewritten in plain words, no labels in source; residuals split between `fanout` and `park_for_approval`). |
| all | Quality | Minor | Test comments carry workflow provenance; imports sit mid-module. | Fixed in the panel-fix commit for the lines this branch added; the remaining mid-file `use` lines predate the base. |
| 1 | Quality | Minor | Two tests pin the `Vec` representation of `gapped` and one pins the poisoned-slot setup. | Accepted: the leak on `drop_connection` has no externally visible effect, so reading the private field is the only way to test it. |
| 1-2 | Quality | Minor | `fanout`'s parameter order differs from its wrappers; the `push_approval_request` call passes a mute that can never be true. | Fixed in the panel-fix commit (same order; one-line comment). |
| all | Quality | Minor | Plan text drift (counts, base SHA, test-region threshold). | Fixed in the docs-amendment commit. |
| fix | Security (re-review) | Minor | Two comments imprecise after the fix: `run_tool` still said the verbs are "blocked only under `Paused`"; the `fanout` doc said "at most one line per call". | Fixed in the comment-only commit (after the docs-amendment commit). |
| fix | Quality (re-review) | Minor | `G2(iii)` and "pins residual R1" labels and six "guard, passes without the fix" notes remain in test comments; two feature-wide caveats sit on the `fanout` doc; a flap caveat is stated twice. | Fixed in the comment-only commit (after the docs-amendment commit): caveats on `with_agent_state` and once on `park_for_approval`. |
| fix | Quality (re-review) | Note | `cargo doc` warns about an unresolved `await_reply_capacity` link at `server.rs:125`. | Not this branch: it predates the base (commit 42448959). Not changed. |
| fix | Spec (re-review) | Minor | Seven plan passages still prescribe a single `sub.sink.push` in one loop (grep count 1); HEAD has two pushes inside `fanout` (count 2). | Accepted as plan-text drift: AC21 in the spec is amended; the count at head is 2 for `sub.sink.push` and exactly three `sink.push` sites in all (`fanout` x2, `replay_since`). |
| fix | Spec (re-review) | Minor | The plan's `fanout` signature (`pushes_muted, wants, line`) differs from HEAD (`wants, line, pushes_muted`). | Accepted: the spec leaves it to the builder; HEAD matches its three wrappers. |
| fix | Spec (re-review) | Minor | The fix hoisted `use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};` into the top import block of `tests/mcp.rs`, against plan trap 3. | Accepted: a pure added line; `git diff --numstat 592a377 -- crates/aitm-mcp/tests/mcp.rs` was `2248 0` (measured at the panel-fix commit, before the final rebase onto `9fb8cfa`; the base was then `592a377`), AC20 holds. After the comment-only commit the figure is `2247 0` (that commit removed one of this branch's own added lines, never a base line). |
| fix | Spec (re-review) | Minor | The plan header's commit list and counts note predate the fix commits. | Re-measured at the fix head: unchanged (24 unit, 31 integration; mutation (a) 2 + 20 failures, (b) 10 + 6). Commits after that rebase, oldest first: the spec-and-plan commit, the Task 1, Task 2 and Task 3 commits, the Tester duplex-test commit, the panel-fix commit, the docs-amendment commit, plus the comment-only commit. |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7 by the main session.

Branch `claude/ecstatic-lehmann-199e83`, rebased onto `origin/main` `9fb8cfa` (after v0.5.2 `592a377` and PR 162), opened as a PR against `main`. No open Critical or Important finding at any point; every Minor is fixed or accepted in the Review log above.

**What shipped.** A policy change on the shared `AgentState` now takes effect on grants already made, in `crates/aitm-mcp` only (`src/server.rs`, plus tests in `tests/mcp.rs`; `aitm-core`, `aitm`, `aitm-plugins` untouched).
- **Pushes.** `Subscriptions::fanout` is the single fan-out send path. It reads the live policy once per call under the registry lock; while the policy is `paused`, a non-trusted-control subscription is enqueued nothing, and its connection is recorded as gapped. The first delivery after the policy relaxes is preceded by one `notifications/aitm/state {"lagged":true}` marker (per connection, never while paused, never the sink's own overflow flag). Operator and CLI subscriptions are never muted. One predicate, `agent_reads_allowed`, an allow-list of the four known non-paused postures, serves both `read_refusal` (subscribe) and the push gate.
- **Parked requests.** A Sensitive call parked under `ask` is bound to that policy: `agent.approve allow:true` after the policy left `ask` denies it and says why (`allow:false` is still a success); the waiter rechecks the live policy every 200 ms (`PARK_POLICY_RECHECK`) and again after waking, so approve-then-pause does not run the command; one pure `settle_park` decides the outcome; one predicate, `ask_still_in_force`, serves all three layers.
- Works across the `aitm web` pair of servers that share the `AgentState` (each reads the shared state at use).
- Also covers `aitm tui`'s loopback agent server, with no tui-specific edit: PR 162 (already on `main`) shares the core's `AgentState` and `AuditRing` with it through `tui::with_shared_governance`, so `agent.set` reaches its gate and this revocation. Its one caveat is that it has no flow push feed yet (PR 162's follow-up "tui-mode push"), so on it only audit lines and parked calls are governed.

**Evidence** (the figures below were measured at the final head before the last rebase, which was then on `592a377`, unless a line says otherwise).
- Full gate `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`: `gate3 exit=0`, 2025 passed, 0 failed (log `/tmp/apr-gate3.log`); an earlier gate at the code-identical panel-fix commit also `exit=0`, 2025 passed.
- Full gate re-run after the final rebase onto `9fb8cfa` (PR 162 merged): `gate4 exit=0`, 2044 passed, 0 failed (log `/tmp/apr-gate4.log`; the difference from 2025 is the tests main gained since, PR 162's `aitm tui` governance tests among them). The five `aitm` web_bus binaries pass unmodified inside it (governance 7, push 10, ask_split 7, roles 5, concurrency 11); `trust_gate_scan` 9 passed.
- `revoke_` tests: 24 unit (`--lib revoke_`) and 31 integration (23 `revoke_push_*`, 7 `revoke_park_*`, 1 `revoke_socket_*`).
- AC22 mutation runs at the final code: (a) `agent_pushes_muted` forced `false`: 2 unit + 20 integration failures (push, socket and unit-gap tests; every parked test passes); (b) `ask_still_in_force` forced `true`: 10 unit + 6 integration failures (parked tests only; no push or socket test fails). Both restored byte-identical (logs `/tmp/apr-mut-a2.log`, `/tmp/apr-mut-b2.log`).
- Task 3 real-socket test (Terminal panel): red with the mute off, `0 passed; 1 failed`, `step 2: no line A received names F2` (`/tmp/apr-t3-red.log`); green three times, `1 passed` each (`/tmp/apr-t3-green{1,2,3}.log`).
- Scope, measured before the final rebase onto `9fb8cfa` (the base was `592a377`): `git diff --name-only 592a377..HEAD` is `server.rs`, `tests/mcp.rs`, the spec and this plan; `crates/aitm-core`, `crates/aitm`, `crates/aitm-plugins` diff empty; `tests/mcp.rs` numstat `2248 0` (no removed line); no removed line inside the base `mod tests`.
- Scope, re-checked after the final rebase (read-only git, at the committed head when this line was written): `git diff --name-only 9fb8cfa..HEAD` is the same four paths; `git diff --stat 9fb8cfa..HEAD -- crates/aitm-core crates/aitm crates/aitm-plugins` prints nothing; `tests/mcp.rs` numstat is `2247 0` (zero removed; one fewer than `2248` because the comment-only commit trimmed one of the branch's own added lines); the base `mod tests` is at line 2220 at `9fb8cfa`, as it was at `592a377`.
- Panel: spec, security and quality reviews of the whole branch, then a re-review of the fix: all PASS, Minors only (Review log).

**Cut / deviations.**
- Per-task Tester passes, but no separate whole-branch Tester run: the per-task Testers, the orchestrator's final-head gate and AC22 runs and the panel's AC-to-test map stand in for it. One panel for the whole branch plus a re-review of the fix, not one per task (same call as PR 145).
- The Testers added 32 of the 55 `revoke_` tests (Task 1: 10, Task 2: 19, plus 3 duplex tests in the Tester duplex-test commit) after surviving production mutants; they sit inside the `feat(mcp): task N` commits except the Tester duplex-test commit.
- The base moved twice during the work (`bd0f9b7` to `592a377`, v0.5.2, then to `9fb8cfa`, after PR 162); the branch was rebased after each move. The plan's counts and scope commands were corrected in the docs-amendment commit, and the base in them is now `9fb8cfa`.
- The unknown-future-posture fail-closed behaviour is not testable (the enum is `#[non_exhaustive]` and `AgentState` cannot produce an unknown value); it is pinned by reading and the doc.

**Follow-ups.**
- `aitm tui` mode governance is not a follow-up of this change: it landed in PR 162, which this branch is rebased onto, so `aitm tui` is covered. PR 162's own follow-up "tui-mode push" (feeding that server's `push_tx`, so flow lines exist there to be governed) stays open and is not part of this change.
- A three-valued park slot so the agent-visible reason for a policy-driven denial is accurate (today it can read "an operator denied").
- An operator-facing "approval withdrawn" event for UIs holding an approval card (wire-contract change for web, macOS, TUI).
- A real `/bus` WebSocket test in `crates/aitm` for the muted agent link.
- Purging already-queued lines from agent sinks on a tighten (needs a set-time hook), and a generation counter in `aitm-core` for a sub-slice policy flap.
- Test cleanup: merge the `RvSock`/`RvWire` clients, unify helper naming and release mechanisms.
