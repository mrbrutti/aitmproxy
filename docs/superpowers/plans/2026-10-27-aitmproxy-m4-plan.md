# aitmproxy Milestone 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** approved (2026-10-28 by Matt)
**Spec:** `docs/superpowers/specs/2026-10-27-aitmproxy-m4-agent-milestone-design.md` (approved 2026-10-28 by Matt; AC-M4-1 … AC-M4-19, incl. AC-M4-5b/6b/8b/15b/16b)
**Branch / worktree:** `feat/aitmproxy-m4`
**Execution:** subagent-driven (Matt, 2026-10-28) — one fresh Coder per task in the `feat/aitmproxy-m4` worktree, panel review between tasks.

**Goal:** Prove the agent-first thesis — an AI agent (harness-neutral; Claude the reference) autonomously drives aitmproxy against a real, seeded-vulnerable target through real browsers and finds → reproduces → reports vulnerabilities — by building the operator/agent command architecture (F1 identity+policy, F2 audit/agent stream, F4 push, confirm/approve-over-the-wire, tool-output-quality result rendering), a persistent findings store, a hermetic multi-vuln test target + grader, a Firefox browser engine, and the harness-neutral driver surface, with a deterministic scripted-driver exit gate and a live-agent acceptance.

**Architecture:** Five streams. **A — operator/agent command architecture** (`aitm-core`, `aitm-mcp`, `aitm-plugins`): a per-connection `ConnCtx` carries an operator-vs-agent role (set by token class) and a bounded push sink; `call_tool` reads the role instead of hard-coding `Frontend::Mcp`; a five-mode `AgentPolicy` is enforced against a declared `Command::sensitivity`; a `SubscriptionPlugin` taps the event chain into a broadcast that fans `notifications/aitm/{flow,state,agent}` to subscribers; the confirm/approve handshake serves operator confirmations and the `Ask` policy; results carry a `summarize` one-liner and a formatted rendering. **B — findings store** (`aitm-findings`): a persistent, human-readable `FindingStore` with `findings.*` commands. **C — target + grader** (`aitm-testtarget`): a hermetic axum app with planted vulns + patched controls + decoys and a grader that scores against a manifest the agent never sees. **D — browsers** (`aitm-browser`): a Firefox engine behind the unchanged `BrowserDriver`, plus the multi-browser custom-proxy e2e. **E — driver surface + gate** (`agent/`, `aitm/tests`): the portable playbook + per-harness adapters, a non-LLM scripted driver that drives the whole loop, the deterministic grader gate, and the documented live-agent acceptance. Everything is additive to the command/registry/transport/config layer — no `Flow`/`Event`/`ProtocolModule` edits.

**Tech Stack:** Rust; tokio (`sync::broadcast`, `sync::mpsc`, `process`), serde/serde_yaml/serde_json, axum or hyper (test target), chromiumoxide 0.9 (`Browser::connect`, Firefox over its remote-debugging), the existing `aitm-*` crates; the driver surface is markdown + `.mcp.json`/config (Claude plugin, OpenAI/Codex adapter, generic MCP client).

## Global Constraints

Every task's requirements implicitly include these (verbatim from the spec where quoted):

- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` before any review. Default `cargo test` is **hermetic**: no real browser, no network, no OS trust store, no live model. Gated tests: `AITM_CHROME=1`, `AITM_OBSCURA=1`, `AITM_FIREFOX=1`; the live-agent acceptance is operator-run, never in CI.
- **TDD:** no production code without a failing test first; the Coder's report includes both runs.
- **Additive only.** F1/F2/F4/confirm/result-rendering/findings extend `Command`, `Registry`, `CommandHost`, `Frontend`, the MCP transport, and config. **No change to** the `Flow`/`Event` enums, the `ProtocolModule` seam, any `aitm-proto-*` crate, or the `aitm-poc` PoC model / YAML language. `Frontend` stays `#[non_exhaustive]` and `Copy`. Existing command signatures are unchanged; new trait methods are defaulted.
- **Declared signatures are authoritative.** Types, fields, and method signatures in the spec and in this plan's Interfaces blocks are copied exactly; bodies and file layout inside a module are the builder's.
- **Deny-by-default.** Every new command carries a `ParamSchema` and a declared `sensitivity()`; the fail-closed default is `Sensitive`. `agent.set`/`agent.approve`/`findings.remove` are operator/CLI-only. Active actions stay scope/rate/SSRF-gated; the agent widens scope only with `scope.allow_agent_widen` (F12) and installs the CA only with `ca.allow_agent_install`.
- **Bounded memory under push:** per-connection notification queues are bounded; overflow drops oldest flow/state notifications and sets a `lagged` marker; a slow subscriber never grows core memory without bound and never blocks the proxy data path.
- **Secrets never leave the process in the clear:** tokens, auth headers, and the CA key path's content never appear in an `AuditEntry`, a `FindingRecord`, a `summarize` line, or a pushed notification (same redaction posture as the M2 CA audit).
- **Verified live-wire shapes (ground truth over the foundation doc):** `browser.eval` param is `expr`; `browser.click` x/y floats OR selector; `browser.type` requires a selector (`":focus"`); `poc.build` returns YAML text; `ca.status` reports `yes|no|unknown`. The driver surface and scripted driver use these.
- **Harness neutrality via MCP only:** no provider SDK (Anthropic/OpenAI) and no model logic in any `aitm-*` crate. Per-harness code lives only under `agent/`.
- **External prerequisites (referenced, built elsewhere — do NOT reimplement):** **F5** `flow.detail`, **F6** `flow.mark`/`flow.comment`, **F7** `proxy.status`/`flow.clear`/`config.get`, **F12** `scope.remove` + `scope.allow_agent_widen`, **F13** `poc.list`/`poc.get`/`poc.artifact`. A task that consumes one declares it under **Prereq**; if that command is not yet merged when the task runs, the task stops and reports (per `coder.md`), it does not build the missing command.
- **Open-question defaults adopted** (Matt approved the spec 2026-10-28; he may override any of these during plan review — each is a one-line change): default `mcp.policy = Auto`; this milestone is **M4** and L4 is **M5**; the live-agent threshold is **≥ all-but-one planted vuln with zero false positives**; the live gate runs **Claude only**, with the OpenAI/Codex adapter shipped and runnable on demand (the deterministic AC-M4-16b proves neutrality).
- **Git/gh run through the Terminal panel** (`run_in_terminal`), never the sandboxed shell (`CLAUDE.md`).

## Review Focus

Input classes the spec implies but no happy-path test exercises; each is pinned to a test in the owning task:

1. **A stalled/slow subscriber.** A client that subscribes (F4) then stops reading must not grow core memory or block the proxy: its bounded sink drops oldest flow/state notifications and the next write carries `lagged:true`. Pinned in Task 7 (`slow_subscriber_lags_not_blocks`).
2. **The agent trying to escalate.** An agent-role connection must be refused when it calls `agent.set`, `agent.approve`, widens scope without `scope.allow_agent_widen`, installs the CA without `ca.allow_agent_install`, or (under `Ask`) approves its own parked request. Pinned in Task 4 (`agent_cannot_set_policy`), Task 9 (`agent_cannot_approve_own_request`), Task 5 (`agent_gets_no_confirm_handshake`).
3. **Secrets in audit / findings / summaries.** An `Authorization` header or a token in a command's args must not appear in the `AuditEntry`, the pushed `agent` line, a `summarize` string, or a `FindingRecord`. Pinned in Task 8 (`audit_redacts_secrets`) and Task 10 (`finding_record_has_no_secrets`).
4. **`Ask` with no operator present.** A Sensitive agent call under `Ask` with no operator connected, or an approval that never arrives, must refuse with a clear error on a bounded timeout — never hang. Pinned in Task 9 (`ask_without_operator_refuses`, `ask_timeout_refuses`).
5. **A browser routing around the proxy.** An external browser (Chrome/Firefox) must capture **only** because it was pointed at aitmproxy's custom proxy, never the OS proxy/OS trust store; a run with the proxy unset must capture nothing. Pinned in Task 14 (`no_capture_without_custom_proxy`) and Task 13 (`firefox_uses_throwaway_profile_only`).

---

## Overview

**Stream A (Tasks 1–9)** is the operator/agent command architecture and is the critical path; **B (10)**, **C (11–12)**, **D (13–14)** are largely independent of A and of each other; **E (15–20)** integrates everything into the driver surface and the two-tier gate. The longest sequential chain is 1 → 3 → 7 → 8 → 9 → 17 → 18 → 20.

**Parallel groups (disjoint files, after dependencies land):**

| Group | Tasks | Why disjoint |
|---|---|---|
| **P1** | 1 ∥ 11 ∥ 13 | `aitm-core/command.rs` vs new `aitm-testtarget` vs `aitm-browser/firefox.rs` |
| **P2** | 5 ∥ 6 (after 3,4) | confirm handshake vs result rendering, both in `server.rs` but separable fns — sequence if the same reviewer prefers |
| **P3** | 10 ∥ 12 ∥ 14 (after their deps) | `aitm-findings` vs grader vs the e2e test file |
| **P4** | 15 ∥ 16 (after 10) | report renderer vs the `agent/` driver surface |

## Tasks

### Stream A — operator/agent command architecture

### Task 1: `Command` sensitivity + `mutates` + `summarize`; classify every command

- **Satisfies:** AC-M4-3, AC-M4-8b (summarize default); the fail-closed `Sensitivity` default (unclassified ⇒ `Sensitive`) that makes Review Focus #2 safe by construction.
- **Depends on:** none. **Independent:** P1.
- **Files:** Modify `crates/aitm-core/src/command.rs` (the `Command` trait); every `impl Command` across `crates/aitm-plugins/src/{scope,intercept,mutate,capture,replay,ratelimit}.rs`, `crates/aitm-browser/src/commands.rs`, `crates/aitm-ca/src/commands.rs`, `crates/aitm-poc/src/{builder,runner}.rs`; tests in `crates/aitm-core/tests/`.
- **Interfaces — Produces:**
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum Sensitivity { Read, Write, Sensitive }
  pub trait Command {
      // … existing …
      fn sensitivity(&self) -> Sensitivity { Sensitivity::Sensitive }   // fail-closed default
      fn mutates(&self) -> bool { self.sensitivity() != Sensitivity::Read }
      fn summarize(&self, _args: &Params, _result: &Value) -> Option<String> { None }
  }
  ```
- **Change:** add the enum and the two defaulted methods. Declare each existing command's tier per spec D2: **Read** — `flow.list/get`, `scope.list`, `ca.status`, `browser.get_dom/screenshot`; **Write** — `flow.replay/mutate/resume/kill`, `request.send`, `poc.build/run`, `browser.navigate/click/type/eval`; **Sensitive** — `ca.install/uninstall`, `scope.add`. (Commands from F5/F6/F7/F12/F13 and this plan's new commands declare their own tier in their own task.)
- **Test:** `sensitivity_is_declared_for_every_command` iterates the wired registry (reuse the wiring from `aitm/src/wire.rs` test harness) and asserts the exact tier of each named command above, and that an undiclared stub command reports `Sensitivity::Sensitive`; `mutates_is_derived` asserts `mutates()==false` iff `Read`; `summarize_defaults_none` asserts a command with no override returns `None`.
- **Done when:** the tests pass and the full gate passes.

### Task 2: `Frontend::Operator`, client label on `CommandHost`, `AgentPolicy`

- **Satisfies:** AC-M4-1 (type surface), AC-M4-4 (enum); supports F1 throughout.
- **Depends on:** none (pairs with Task 1). **Independent:** yes.
- **Files:** Modify `crates/aitm-core/src/ctx.rs` (`Frontend`, `CommandHost`); create `crates/aitm-core/src/agent.rs` (`AgentPolicy`); modify `crates/aitm-core/src/lib.rs` (re-export); tests in `crates/aitm-core/tests/`.
- **Interfaces — Produces:**
  ```rust
  // ctx.rs — Frontend stays #[non_exhaustive] + Copy
  pub enum Frontend { Cli, Mcp, Operator }
  impl<'a> CommandHost<'a> {
      pub fn with_client_label(self, label: impl Into<String>) -> Self;
      pub fn client_label(&self) -> Option<&str>;
  }
  // agent.rs
  #[non_exhaustive]
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum AgentPolicy { All, Auto, Ask, ReadOnly, Paused }
  ```
- **Change:** add the `Operator` variant; add an optional `client_label: Option<String>` field to `CommandHost` with the two accessors; define `AgentPolicy`. No behavior change yet — enforcement is Task 4.
- **Test:** `frontend_operator_is_distinct` (`Operator != Mcp != Cli`, and `Frontend: Copy` still holds via a `fn assert_copy<T: Copy>()`); `client_label_round_trips` (`with_client_label("aitm-mac").client_label() == Some("aitm-mac")`, default `None`).
- **Done when:** tests pass and the gate passes.

### Task 3: Per-connection `ConnCtx`; token class → role; `call_tool` reads the role

- **Satisfies:** AC-M4-1, AC-M4-2.
- **Depends on:** Task 2.
- **Files:** Modify `crates/aitm-mcp/src/server.rs` (`McpServer`, `handle` → `handle_on`, `call_tool`), `crates/aitm-mcp/src/transport.rs` (`serve_lines`, `serve_connection`, auth), `crates/aitm-core/src/config.rs` (`McpConfig`, `McpTransport`); tests in `crates/aitm-mcp/tests/`.
- **Interfaces — Produces:**
  ```rust
  // server.rs
  pub struct ConnCtx { pub role: Frontend, pub client_label: Option<String>, /* out: NotificationSink added in Task 7 */ }
  impl McpServer { pub fn handle_on(&self, conn: &ConnCtx, message: &str) -> Option<String>; }
  // config.rs (additive)
  pub struct McpConfig { pub transport: McpTransport, pub agent_token: Option<String>,
                         pub operator_token: Option<String>, pub policy: AgentPolicy,
                         pub stdio_role: Frontend /* default Mcp */ }
  ```
- **Change:** `serve_connection` matches the presented auth token against `operator_token` then `agent_token`; a match sets `ConnCtx.role` (`Operator`/`Mcp`) and the `clientInfo.name` label; a miss stays `-32001`. Stdio builds a `ConnCtx` from `stdio_role` (default `Mcp`). `serve_lines` threads the `ConnCtx` into `handle_on`. `call_tool` builds the `CommandHost` with `conn.role` and `conn.client_label` **instead of** the hard-coded `.with_frontend(Frontend::Mcp)` (`server.rs:273`). `handle(&self, msg)` is kept as a wrapper building a default agent `ConnCtx` (back-compat for existing tests).
- **Test:** `operator_token_sets_operator_role` / `agent_token_sets_agent_role` (two tokens configured; a stub command that returns `host.frontend()` shows `Operator` vs `Mcp`); `unknown_token_refused` (`-32001`); `stdio_default_role_is_agent`.
- **Done when:** tests pass and the gate passes.

### Task 4: `AgentPolicy` enforcement + `AgentPlugin` (`agent.status`/`agent.set`)

- **Satisfies:** AC-M4-4, AC-M4-5 (status/set parts); Review Focus #2.
- **Depends on:** Tasks 1, 2, 3.
- **Files:** Create `crates/aitm-plugins/src/agent.rs` (`AgentPlugin`, the commands); modify `crates/aitm-mcp/src/server.rs` (`call_tool` gate), `crates/aitm/src/wire.rs` (register), `crates/aitm-plugins/src/lib.rs`; tests in `crates/aitm-mcp/tests/`.
- **Interfaces — Produces:** commands `agent.status {} -> {policy, actions_last_minute, connected_clients:[{role,client,since}]}` (Read), `agent.set {policy:"all"|"auto"|"ask"|"readonly"|"paused"} -> {policy}` (Sensitive). Shared policy state: `Arc<AgentState>` holding the current `AgentPolicy` (seeded from `McpConfig.policy`), readable by `call_tool`.
- **Change:** `call_tool`, **only when `conn.role == Mcp`**, applies the D2 matrix before `invoke` using `cmd.sensitivity()` and the current policy: `Paused` → refuse all; `ReadOnly` → allow `Read` only; `Auto` → allow `Read`+`Write`, **always refuse `Sensitive`**; `All` → allow `Read`+`Write` and let `Sensitive` through to the command's own config gate (which runs iff its `*.allow_agent_*` flag is on); `Ask` branch is Task 9. The policy dimension and the per-capability config gate are **independent** — a Sensitive agent action needs both (spec D2). `Operator`/`Cli` bypass the gate. `agent.set` is refused when `conn.role == Mcp` and mutates the `AgentState`.
- **Test:** `policy_matrix_for_agent` (parametrized over the five policies × {a Read, a Write, a Sensitive stub command} → the D2 outcomes; `Auto`+Sensitive → refuse; `All`+Sensitive → defers to the command's gate); `all_sensitive_honors_config_gate` (a Sensitive command under `All` with its gate off → refused, on → runs); `operator_bypasses_policy` (operator role runs a Write under `Paused`); `agent_cannot_set_policy` (agent `agent.set` → tool error; operator `agent.set` → ok); `agent_status_readable_by_any_role`.
- **Done when:** tests pass and the gate passes.

### Task 5: Confirm-over-the-wire (operator handshake) + `confirmable` in `tools/list`

- **Satisfies:** AC-M4-7, AC-M4-8.
- **Depends on:** Task 3. **Independent:** P2 with Task 6.
- **Files:** Modify `crates/aitm-mcp/src/server.rs` (`call_tool`), `crates/aitm-mcp/src/schema.rs` (`to_mcp_tool` adds `confirmable`); tests in `crates/aitm-mcp/tests/`.
- **Interfaces — Produces:** `tools/list` entries gain `"confirmable": bool` (= `cmd.confirm_prompt` can be `Some`). An operator confirm response: `{"status":"needs_confirmation","prompt":<str>,"confirm_token":<opaque>}`. A re-send carries reserved arg `_confirm:"<token>"` (stripped before typed `Params`).
- **Change:** when `conn.role == Operator` and `cmd.confirm_prompt(args)` is `Some(prompt)` and no valid `_confirm` was supplied → return the `needs_confirmation` result; a re-send with a token matching `{command,args,connection}` (short TTL, single-use) runs `invoke`. When `conn.role == Mcp`, **no** handshake is offered — confirm-gated commands stay governed by their config gate (`ca.allow_agent_install`), refused otherwise, and the attempt is audited (Task 8). `Cli` unchanged.
- **Test:** `operator_confirm_handshake` (operator `ca.install` → `needs_confirmation`; re-send with the token → runs); `confirm_token_wrong_or_expired_or_replayed_refused`; `agent_gets_no_confirm_handshake` (agent `ca.install` with gate off → refused, no `needs_confirmation`; with gate on → runs); `tools_list_marks_confirmable`.
- **Done when:** tests pass and the gate passes.

### Task 6: Tool-output-quality result rendering (`summarize` + formatted `content`)

- **Satisfies:** AC-M4-8b.
- **Depends on:** Task 1 (`summarize`). **Independent:** P2 with Task 5.
- **Files:** Modify `crates/aitm-mcp/src/server.rs` (the `tools/call` success path, `server.rs:274-280`); add a small render helper (same file or `crates/aitm-mcp/src/render.rs`); tests in `crates/aitm-mcp/tests/`.
- **Change:** the success result keeps `structuredContent` as the exact `to_json(&value)` (unchanged) and `isError:false`; its `content[0].text` becomes `summarize(args,result)` (when `Some`) + `"\n"` + a **pretty**, stable-key-ordered JSON of the value (not the current single-line `structured.to_string()`). Provide `summarize` for a representative set: `flow.replay`, `poc.run`, `scope.add`, `request.send` (each in its own `impl Command`, grounded in that command's result fields).
- **Test:** `content_is_formatted_summary_plus_pretty` (a `poc.run`-shaped result → `content` text starts with the summary line and contains indented JSON; `structuredContent` equals the raw value byte-for-byte); `summarize_present_for_representative_set` (the four commands return `Some`).
- **Done when:** tests pass and the gate passes.

### Task 7: Push transport — per-connection sink + `SubscriptionPlugin` + `flow.subscribe`/`unsubscribe`

- **Satisfies:** AC-M4-6; Review Focus #1.
- **Depends on:** Task 3. (**Prereq awareness:** flow summary shape reuses `flow.get`; full detail stays F5.)
- **Files:** Modify `crates/aitm-mcp/src/transport.rs` (split read loop / writer task), `crates/aitm-mcp/src/server.rs` (subscription registry, `ConnCtx.out`); create `crates/aitm-plugins/src/subscription.rs` (`SubscriptionPlugin`); modify `crates/aitm/src/wire.rs`; tests in `crates/aitm-mcp/tests/`.
- **Interfaces — Produces:**
  ```rust
  pub struct NotificationSink(/* bounded mpsc<String> sender */);
  impl NotificationSink { pub fn push(&self, line: String); /* drop-oldest + lag flag on overflow */ }
  // commands
  // flow.subscribe {filter?: FlowFilter, since?: FlowId} -> {sub_id}    (Read)
  // flow.unsubscribe {sub_id} -> {}                                     (Read)
  // notifications: notifications/aitm/flow {event,id,summary}; notifications/aitm/state {...}
  ```
- **Change:** `serve_lines` becomes a read task that calls `handle_on` and enqueues replies to the connection's `NotificationSink`, plus a writer task that drains the sink to the socket; `ConnCtx` gains `out: NotificationSink`. A `SubscriptionPlugin` on the chain forwards lifecycle `Event`s to a `tokio::sync::broadcast`; `McpServer` holds a dispatcher task that renders `notifications/aitm/flow` for each event and pushes to every subscription whose `filter` matches. `flow.subscribe`/`unsubscribe` manage a per-connection registry (dropped with the connection). `since` replays matching store entries before live events. Overflow: drop oldest flow/state lines, set `lagged`, delivered as `notifications/aitm/state {lagged:true}`; replies are never dropped.
- **Test:** `subscribe_pushes_created_on_new_flow` (subscribe, drive a flow, read a `notifications/aitm/flow {event:"created"}` with no further request); `unsubscribe_stops_push`; `state_pushed_on_change`; `slow_subscriber_lags_not_blocks` (RF#1: a reader that stops; assert the sink bounds, a later `lagged:true`, and that a second connection's flows still flow).
- **Done when:** tests pass and the gate passes.

### Task 8: F2 audit ring + `notifications/aitm/agent` + `agent.activity`; generalize the CA JSONL

- **Satisfies:** AC-M4-6b; Review Focus #3.
- **Depends on:** Tasks 3, 7. (Touches `aitm-ca/audit.rs` — coordinate; additive.)
- **Files:** Create `crates/aitm-core/src/audit.rs` (`AuditEntry`, `AuditSink` trait, in-memory ring); modify `crates/aitm-mcp/src/server.rs` (append after the gate, push `agent` line), `crates/aitm-plugins/src/agent.rs` (`agent.activity`), `crates/aitm-ca/src/audit.rs` (implement/route through the core sink), `crates/aitm/src/wire.rs`; tests in `crates/aitm-mcp/tests/` and `crates/aitm-ca/tests/`.
- **Interfaces — Produces:**
  ```rust
  pub struct AuditEntry { pub at: SystemTime, pub origin: Frontend, pub client_label: Option<String>,
                          pub command: String, pub args_summary: String, pub result: AuditResult /* Ok|Error(reason) */ }
  pub trait AuditSink: Send + Sync { fn append(&self, e: AuditEntry); }
  // command: agent.activity {since?: Timestamp, limit?: u32} -> [AuditEntry]   (Read)
  // notification: notifications/aitm/agent {origin, command, args, result, at}
  ```
- **Change:** `call_tool` appends one `AuditEntry` after the policy/confirm gates (a refusal is `AuditResult::Error(reason)`), with `args_summary` **redacted** (drop/omit `authorization`, `token`, `_confirm`, and any value a command marks secret) and size-capped. Each append renders a `notifications/aitm/agent` line pushed via the Task 7 channel, and is kept in a bounded ring that `agent.activity` reads. The CA plugin's existing JSONL becomes an `AuditSink` implementation (durable, opt-in via config), so CA entries are a subset of one format; a general durable JSONL path is config-gated.
- **Test:** `every_invoke_is_audited_including_refusals` (a successful and a policy-refused call each produce an entry; refusal carries the reason); `audit_redacts_secrets` (RF#3: a call with an `Authorization` header / a token arg → the entry/line contain neither); `agent_activity_returns_recent` (`since`/`limit`); `ca_audit_is_a_subset` (a `ca.status` call appears in both the ring and, when durable is on, the JSONL).
- **Done when:** tests pass and the gate passes.

### Task 9: `Ask` policy — parked Sensitive calls + `agent.approve`

- **Satisfies:** AC-M4-5b; Review Focus #2, #4.
- **Depends on:** Tasks 4, 5, 7, 8.
- **Files:** Modify `crates/aitm-mcp/src/server.rs` (`call_tool` Ask branch, parked-request table), `crates/aitm-plugins/src/agent.rs` (`agent.approve`); tests in `crates/aitm-mcp/tests/`.
- **Interfaces — Produces:** command `agent.approve {request_id, allow: bool} -> {}` (Sensitive, operator/CLI-only). Notification `notifications/aitm/agent {event:"approval_requested", command, args_summary, prompt, request_id}`.
- **Change:** under `policy == Ask`, an agent **Sensitive** call is **parked** (not run, not returned to the agent as `needs_confirmation`): the server stores `{request_id, command, args, agent_conn}`, pushes `approval_requested` to connected operator(s), and the agent's call awaits resolution on a bounded timeout. `agent.approve {allow:true}` (operator/CLI only) runs the parked `invoke` and returns its result to the waiting agent; `{allow:false}`, timeout, or **no operator connected** → the agent call is refused with a clear reason. An agent calling `agent.approve` is refused.
- **Test:** `ask_parks_then_approves` (agent Sensitive call under Ask parks; operator `agent.approve{allow:true}` → the agent call completes); `ask_deny_refuses`; `ask_timeout_refuses` (RF#4); `ask_without_operator_refuses` (RF#4); `agent_cannot_approve_own_request` (RF#2).
- **Done when:** tests pass and the gate passes.

### Stream B — persistent findings store

### Task 10: `aitm-findings` crate + `FindingStore` + `findings.*` commands

- **Satisfies:** AC-M4-15; Review Focus #3.
- **Depends on:** Task 1 (`sensitivity`); reuses `aitm-poc` `Severity` and `FlowId`. **Independent:** P3.
- **Files:** Create crate `crates/aitm-findings/` (`lib.rs`, `store.rs`, `record.rs`, `commands.rs`); modify `crates/aitm-core/src/config.rs` (`findings.dir`), `crates/aitm/src/{config_file,wire}.rs`, workspace `Cargo.toml`; tests in `crates/aitm-findings/tests/`.
- **Interfaces — Produces:**
  ```rust
  pub struct FindingRecord { pub id: String, pub title: String, pub class: String, pub severity: Severity,
      pub target: String, pub discovered_at: SystemTime, pub origin: Frontend, pub client_label: Option<String>,
      pub poc_ref: String, pub reproduction: Reproduction, pub artifacts: FindingArtifacts,
      pub flows: Vec<FlowId>, pub notes: Option<String> }
  pub struct Reproduction { pub passed: bool, pub control_passed: Option<bool>, pub run_at: SystemTime }
  pub struct FindingArtifacts { pub finding_capture: FlowId, pub poc_path: String, pub screenshot_path: String }
  pub trait FindingStore: Send + Sync {
      fn record(&self, r: FindingRecord) -> Result<String>;   // writes a YAML file + a runs.jsonl line; returns id
      fn get(&self, id: &str) -> Option<FindingRecord>;
      fn list(&self, f: &FindingFilter) -> Vec<FindingSummary>;
      fn remove(&self, id: &str) -> Result<()>;
  }
  // commands: findings.list {filter?} (Read), findings.get {id} (Read),
  //           findings.record {title,class,severity,target,poc_ref,flows?,notes?} -> {id} (Write),
  //           findings.remove {id} (Sensitive, operator/CLI)
  ```
- **Change:** `record` writes one human-readable YAML per finding under `findings.dir` plus an append-only `runs.jsonl` line (`{finding_id, poc_ref, passed, control_passed, at, origin}`); `list`/`get` read from disk; `remove` deletes the YAML (keeps the runs log). Commands register through a `FindingsPlugin`. Secrets never copied into a record (redaction shared with Task 8).
- **Test:** `record_then_get_and_list` (record → `get(id)` equals it; `list` with a `target`/`class`/`severity`/`since` filter returns it); `findings_persist_across_restart` (new `FindingStore` over the same dir sees it); `findings_distinct_from_poc_library` (a `poc.list` fixture and a `findings.list` return different sets); `finding_record_has_no_secrets` (RF#3); `findings_record_is_policy_gated` (agent under `Paused`/`ReadOnly` refused; `remove` refused for agent).
- **Done when:** tests pass and the gate passes.

### Stream C — seeded target + grader

### Task 11: `aitm-testtarget` crate — multi-vuln app + patched controls + decoys + manifest

- **Satisfies:** AC-M4-9, AC-M4-10.
- **Depends on:** none. **Independent:** P1.
- **Files:** Create crate `crates/aitm-testtarget/` (`lib.rs`, `app.rs`, `manifest.rs`, `seed.rs`); workspace `Cargo.toml`; tests in `crates/aitm-testtarget/tests/`.
- **Interfaces — Produces:**
  ```rust
  pub struct TestTarget { /* axum app + bound addr */ }
  impl TestTarget { pub async fn start(mode: SeedMode) -> TestTarget; pub fn base_url(&self) -> &str; }
  pub enum SeedMode { Vulnerable, Patched }
  pub struct PlantedVuln { pub id: String, pub class: String, pub vulnerable_path: String,
                           pub patched_path: String, pub trigger_hint: String, pub success_signal: String }
  pub fn manifest() -> &'static [PlantedVuln];   // grader-only; never served
  ```
- **Change:** an in-process HTTPS-capable app (bound on loopback; the proxy MITMs it) serving, per `SeedMode`, a vulnerable and a patched variant of each class in spec D5: reflected XSS, stored XSS, SSRF (fetch-preview), IDOR (`/account/{id}`), auth bypass (logic), open redirect (`?next=`), plus ≥3 benign decoy endpoints. Success signals are markers, not real secrets. `manifest()` is a pure table, also emitted to YAML for humans; it is never wired into a route.
- **Test:** `each_vuln_path_triggers_in_vulnerable_mode` (per class, the trigger yields its `success_signal`); `each_patched_path_is_safe` (the same trigger on the patched variant does not); `manifest_not_served` (RF/AC-M4-10: GET of every manifest field/path that could leak it → 404; a scan of the router confirms no route reads `manifest()`); `hermetic` (no outbound connection attempted; asserted by a deny-all resolver/connector in the test).
- **Done when:** tests pass and the gate passes.

### Task 12: Grader — score findings against the manifest

- **Satisfies:** AC-M4-11.
- **Depends on:** Task 11 (manifest), Task 10 (`FindingRecord`). **Independent:** P3.
- **Files:** Create `crates/aitm-testtarget/src/grader.rs`; tests in `crates/aitm-testtarget/tests/`.
- **Interfaces — Produces:**
  ```rust
  pub struct GradeReport { pub planted: usize, pub found: usize, pub reproduced: usize, pub false_positives: usize,
                           pub missing: Vec<String>, pub spurious: Vec<String> }
  pub fn grade(findings: &[FindingRecord]) -> GradeReport;   // matches by endpoint+class, not by id
  ```
- **Change:** a finding counts **found-and-reproduced** iff `reproduction.passed && reproduction.control_passed == Some(false)` and its `target`+`class` match a planted vuln (never by an id the agent supplies); a passing finding matching no planted vuln (e.g. a decoy) is a **false positive**.
- **Test:** `grade_counts_reproduced` (synthetic findings covering all planted → `reproduced == planted`, `false_positives == 0`); `decoy_finding_is_false_positive`; `uncontrolled_pass_not_counted` (`control_passed == Some(true)` or `None` → not reproduced); `match_is_by_endpoint_not_id` (a finding naming a wrong id but right endpoint+class still matches).
- **Done when:** tests pass and the gate passes.

### Stream D — browsers

### Task 13: Firefox browser engine behind the unchanged `BrowserDriver`

- **Satisfies:** AC-M4-12 (Firefox leg); Review Focus #5.
- **Depends on:** none (reuses the M2 `BrowserDriver`/engine-select pattern). **Independent:** P1.
- **Files:** Create `crates/aitm-browser/src/firefox.rs`; modify `crates/aitm-browser/src/lib.rs` (engine select), `crates/aitm-core/src/config.rs` (`BrowserConfig.engine += firefox`, `firefox` sub-config), `crates/aitm/src/{config_file,wire}.rs`; gated tests in `crates/aitm-browser/tests/`.
- **Interfaces — Produces:** `BrowserConfig.engine` accepts `firefox`; a `FirefoxConfig { binary: PathBuf, start_timeout, nav_timeout }`; a `FirefoxDriver` implementing the existing `BrowserDriver` (navigate/click/type/screenshot/eval/get_dom — eval/DOM best-effort).
- **Change:** launch Firefox with a **throwaway profile** in a temp dir whose `user.js` sets `network.proxy.type=1`, `network.proxy.{http,ssl}=127.0.0.1`, `network.proxy.{http_port,ssl_port}=<port>`, `network.proxy.allow_hijacking_localhost=true`, and trusts the MITM CA **into that profile only** (`policies.json` `Certificates.Install` → the exported CA **cert file**, or `certutil` into the profile's `cert9.db`); the profile is deleted after the run. The OS proxy and OS trust store are never touched. Drive via Firefox's remote debugging; `eval`/`get_dom` are best-effort and the gate requires only navigate+screenshot+capture.
- **Test** (`#[cfg_attr(not(AITM_FIREFOX), ignore)]`): `firefox_captures_through_custom_proxy` (navigate a local HTTPS fixture → its request appears as a captured flow; screenshot is a valid PNG); `firefox_uses_throwaway_profile_only` (RF#5: the launched profile dir is the temp one, is removed after, and no write touches the default profile / OS store — asserted by pointing `$HOME`/profile root at a sandbox and checking it is untouched).
- **Done when:** the gated tests pass where Firefox exists (reported as skipped otherwise) and the non-gated gate is green everywhere.

### Task 14: Multi-browser custom-proxy capture e2e

- **Satisfies:** AC-M4-12; Review Focus #5.
- **Depends on:** Tasks 11, 13 (and the M2 obscura/Chrome drivers). **Independent:** P3.
- **Files:** Create `crates/aitm/tests/m4_browser_capture.rs`.
- **Change:** for each engine present (`obscura` under `AITM_OBSCURA`, `chrome` under `AITM_CHROME`, `firefox` under `AITM_FIREFOX`), start the `aitm-testtarget` (Vulnerable), launch the engine pointed at aitmproxy's custom proxy with CA trust, navigate a target page, and assert its requests land in the flow store as flows tagged with that browser. Include the negative check.
- **Test:** `capture_through_custom_proxy_per_engine` (per gated engine → page requests captured); `no_capture_without_custom_proxy` (RF#5: launch the engine with the proxy unset → zero target flows captured).
- **Done when:** the gated legs pass where their browser exists (skips reported) and the gate is green.

### Stream E — driver surface, scripted driver, reporting, gate

### Task 15: Report renderer — `report.md` + `findings.index.json` from the findings store

- **Satisfies:** AC-M4-15b (report half). **Prereq:** F13 (`poc.artifact`) for remote artifact bytes; local runs read paths directly.
- **Depends on:** Task 10. **Independent:** P4.
- **Files:** Create `crates/aitm-findings/src/report.rs` (a pure renderer); tests in `crates/aitm-findings/tests/`.
- **Interfaces — Produces:**
  ```rust
  pub fn render_report(findings: &[FindingRecord]) -> String;          // human markdown (D8)
  pub fn render_index(findings: &[FindingRecord]) -> serde_json::Value; // {poc_path,target_path,class,passed,control_passed,finding_capture,screenshot_path}[]
  ```
- **Change:** `render_report` emits a title/summary + one section per finding `{title, severity, class/CWE, endpoint, reproduction steps, PoC path, screenshot link, finding-capture id}`; `render_index` emits the machine list the grader reads. Pure functions over `FindingRecord`; no tool prose beyond structure.
- **Test:** `report_has_one_section_per_finding` (N findings → N sections, each naming its endpoint + PoC path); `index_matches_findings` (round-trip fields; the grader `grade`s the index to the same `GradeReport` as grading the records).
- **Done when:** tests pass and the gate passes.

### Task 16: The harness-neutral driver surface (portable playbook + adapters)

- **Satisfies:** AC-M4-16b (surface half); spec D7.
- **Depends on:** the command surface existing (Tasks 1–10) for the tool list it documents. **Independent:** P4.
- **Files:** Create `agent/PLAYBOOK.md` (portable), `agent/claude/` (plugin `.mcp.json` + `SKILL.md` + per-phase skills), `agent/openai/` (Codex MCP config + instructions), `agent/generic/` (a generic MCP-client config + README); a validator test in `crates/aitm/tests/agent_surface.rs`.
- **Change:** the **portable playbook** states the observe→reason→act→reproduce→record→report loop, the candidate heuristics, the reproduction bar (`poc.run` passes + control fails → `findings.record`), and the human-friendly report contract — assuming only the MCP tool list and the verified wire shapes. Each adapter is a thin shell pointing its harness at the loopback-TCP agent token and loading the playbook. No provider SDK anywhere.
- **Test:** `adapters_are_well_formed` (each adapter's config parses; the Claude `.mcp.json` and the generic config name the bus transport + token file; the playbook references only commands that exist in a `tools/list` fixture); `no_provider_sdk_in_workspace` (a check that no `aitm-*` `Cargo.toml` depends on an Anthropic/OpenAI SDK).
- **Done when:** tests pass and the gate passes.

### Task 17: Scripted driver — the deterministic find→reproduce→record→report loop

- **Satisfies:** AC-M4-13, AC-M4-14, AC-M4-15b (driver half). **Prereq:** F5 (`flow.detail`), F13 (`poc.*` artifacts).
- **Depends on:** Tasks 6, 7, 10, 11, 13, 15; the M2 browser + poc commands.
- **Files:** Create `crates/aitm/tests/support/scripted_driver.rs` (a non-LLM MCP client) and `crates/aitm/tests/m4_scripted_e2e.rs`.
- **Interfaces — Consumes:** the MCP bus only (a generic JSON-RPC client over loopback TCP with the agent token) — no in-process shortcuts, to prove the public surface suffices.
- **Change:** the driver crawls the Vulnerable target through a real browser (gated engine), subscribes, enumerates candidates **from `flow.detail`** (params/headers/object-ids/redirect targets — never the manifest), tests each with `flow.replay`/`flow.mutate`+`resume`/`request.send`/`browser.*`, and on a confirmed anomaly `poc.build`s + `poc.run`s a PoC (pass on vulnerable, fail on patched control), then `findings.record`s it and renders `report.md` + `findings.index.json` (Task 15).
- **Test** (`#[cfg_attr(not(AITM_OBSCURA), ignore)]`, obscura the default engine): `scripted_driver_finds_from_observation` (candidates derive from `flow.detail`, asserted by the driver never reading `manifest()`); `scripted_driver_reproduces_each` (each discovered vuln's PoC passes on vulnerable, fails on patched, emits three artifacts); `scripted_driver_records_and_reports` (a `FindingRecord` per vuln + a rendered report/index).
- **Done when:** the gated test passes under obscura and the non-gated gate is green.

### Task 18: Deterministic exit gate + harness-neutral proof

- **Satisfies:** AC-M4-16, AC-M4-16b.
- **Depends on:** Tasks 12, 16, 17.
- **Files:** Create `crates/aitm/tests/m4_grader_gate.rs`.
- **Change:** run the Task 17 scripted driver (which is a **generic MCP client, not the Claude plugin**) end to end against the seeded target, feed its recorded findings to `grade`, and assert `reproduced == planted` and `false_positives == 0`. A second assertion confirms the same driver works unchanged with the `agent/generic` config, proving nothing is Claude-specific.
- **Test** (gated on a browser engine): `grader_gate_all_reproduced_zero_false_positives`; `generic_mcp_client_drives_full_loop` (RF/AC-M4-16b).
- **Done when:** the gated gate passes and the non-gated gate is green.

### Task 19: Live-agent acceptance procedure (operator-run)

- **Satisfies:** AC-M4-17.
- **Depends on:** Tasks 16, 18.
- **Files:** Create `docs/superpowers/m4-live-acceptance.md`.
- **Change:** a documented, reproducible operator procedure: start `aitm` with the seeded target in scope and `agent.set` to an autonomous policy (`Auto`/`All`), attach a live Claude agent via `agent/claude`, let it run unaided (no manifest), then run `grade` on its findings and confirm **≥ all-but-one planted vuln, zero false positives** (adopted threshold) and a produced report. Notes how to re-run under `agent/openai`. This gate is a signed-off demo, not CI.
- **Test:** none automated (live model); the doc includes the exact commands and the pass/fail check (`grade` output). Verified by an operator run recorded in the Review log / Shipped.
- **Done when:** the procedure is complete and has been run once with a green `grade` (recorded by the main session).

### Task 20: Milestone exit — full gate + core-untouched check

- **Satisfies:** AC-M4-18, AC-M4-19.
- **Depends on:** all prior tasks.
- **Files:** Create `crates/aitm/tests/m4_core_untouched.rs` (or a scripted diff check in CI docs).
- **Change:** run the full Rust gate; assert (by `git diff --stat main...` scoped check, or a path-allowlist test) that M4 changed only the command/registry/transport/config layer and added crates (`aitm-findings`, `aitm-testtarget`, `agent/`), and that `crates/aitm-core/src/flow.rs`/`event.rs` (the `Flow`/`Event` enums) and `crates/aitm-proto-*` are unchanged.
- **Test:** `gate_green` (the three gate commands exit 0, output quoted in the report); `core_and_protocols_untouched` (the diff/path check).
- **Done when:** the gate is green and the core-untouched check passes; the milestone exit criteria (AC-M4-1 … AC-M4-19) are all green (AC-M4-17 by the Task 19 operator run).

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|

## Shipped

Filled at stage 7.
