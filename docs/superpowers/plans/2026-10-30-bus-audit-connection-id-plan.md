# Server-assigned connection id on audit lines implementation plan

**Status:** approved (orchestrator, 2026-10-30, under Matt's standing autonomous-approval rule)
**Spec:** `docs/superpowers/specs/2026-10-30-bus-audit-connection-id-design.md` (approved; Ambiguities 1 is resolved: the spec's AC21 literal 6 stands and the spec's status line no longer says otherwise)
**Branch / worktree:** `feat/bus-audit-conn-id` in `/Users/matt/Security/aitmproxy/.claude/worktrees/adoring-cartwright-385dea` (base `8315880`)

## Overview

Server only. Eighteen small tasks in four waves: `aitm-core` and `aitm-ca` pieces first (T1-T5), then the `aitm-mcp` / `aitm-plugins` behavior (T6-T11, strictly sequential: `server.rs`, `mcp.rs` and `agent.rs` are shared), then the `aitm` integration tests (T12-T13), then the e2e suites (T14-T17, independent of each other), then one whole-branch gate (T18). Each task is test-first, ends green and is committable alone. **No task touches `apps/`, `crates/aitm-tui`, `crates/aitm/src/web/` or `crates/aitm-mcp/src/http.rs`** (AC25): the UI consumer is a separate PR. The three-reviewer panel (security, quality, spec) runs per WORKFLOW stage 6 as the orchestrator dispatches it, after the last task, and once on the whole branch before integration.

**Conventions every task obeys.**
- Re-verify every `file:line` below before editing; the tree may differ slightly. Touch only the files the task declares; need another, stop and report.
- Per-task gate is crate-scoped (named in each task); the whole-workspace gate runs in T18. `cargo fmt --check` is part of every gate.
- **Sandbox vs Terminal panel.** `cargo` works offline in the Bash sandbox; anything that binds a loopback port, and all `git`, runs through the Terminal panel (`run_in_terminal`). Socket-free here: `aitm-ca` (whole crate), the filtered unit tests named below, the in-process `mcp.rs` tests, AC18. Full-crate runs of `aitm-core` (`proxy.rs` binds), `aitm-plugins`, `aitm-mcp` and `aitm` bind ports: Terminal. Mark in the report which run was where.
- Gate on exit code (redirect `cargo test` to a log, test `$?`), never on a grep pipeline. Commit bodies must not contain a word starting with `#`.
- Commit: `feat(<area>): task N — <title> (plan 2026-10-30-bus-audit-connection-id)`, with the `Co-Authored-By` trailer for the running model.
- **Trap (all tasks):** `crates/aitm-core/tests/trust_gate_scan.rs` scans every `crates/*/src` file, including `#[cfg(test)]` modules, and rejects `==`, `!=`, `matches!` and `if let` against `Frontend::Mcp`. In `src` tests compare roles with `assert_eq!` on arrays or lists, never those shapes. `visible_to` delegates to `Frontend::is_trusted_control` only.
- A literal count that does not reproduce when the coder runs it: stop and report; never edit the literal to match.

**Step 0 (orchestrator, Terminal, before T1 lands).** Build the baseline binary for the e2e "red" runs: in this worktree at `8315880`, touch a source file (shared `CARGO_TARGET_DIR` can serve stale artifacts), `cargo build -p aitm`, copy `target/debug/aitm` aside as `$AITM_BASE_BIN`. T14-T16 run their new test against it (`AITM_BIN=$AITM_BASE_BIN`) to show red, then against a fresh build to show green.

### Who touches what

| Task | Files | Depends on | Parallel with |
|---|---|---|---|
| T1 | `aitm-core/src/audit.rs`, `aitm-mcp/src/server.rs` (1 literal), `aitm-ca/tests/audit.rs` (1 literal) | none | T4 |
| T2 | `aitm-core/src/audit.rs` | T1 | T4, T5 |
| T3 | `aitm-core/src/audit.rs`, `aitm-core/src/lib.rs` | T2 | T4, T5 |
| T4 | `aitm-core/src/ctx.rs` | none | T1, T2, T3, T5 |
| T5 | `aitm-ca/src/audit.rs`, `aitm-ca/tests/audit.rs` | T1 | T2, T3, T4 |
| T6 | `aitm-mcp/src/server.rs`, `aitm-mcp/tests/mcp.rs` | T1 | none |
| T7 | same two | T4, T6 | none |
| T8 | `aitm-mcp/src/transport.rs`, `server.rs` (doc only), `mcp.rs` | T3, T7 | none |
| T9 | `server.rs`, `mcp.rs` | T2, T8 | none |
| T10 | `aitm-plugins/src/agent.rs`, `mcp.rs` | T2, T6, T9 | none |
| T11 | `agent.rs`, `mcp.rs` | T4, T7, T10 | none |
| T12 | `aitm/tests/web_bus_audit_identity.rs` (new) | T6 | T10, T11 (disjoint files) |
| T13 | same new file | T9, T12 | T10, T11 |
| T14 | `tests/e2e/web/test_bus_push_ui_contract.py` | T6, T9 | T15, T16, T17 |
| T15 | `tests/e2e/web/test_bus_audit_visibility.py` (new) | T11 | T14, T16, T17 |
| T16 | `tests/e2e/audit/test_audit_identity.py` (new) | T8, T11 | T14, T15, T17 |
| T17 | `tests/e2e/neg/test_nonexistent_flow_error.py` | T10 | T14, T15, T16 |
| T18 | none (verification) | all | none |

T6 to T11 never overlap: they all edit `server.rs`/`mcp.rs`/`agent.rs`. T12/T13 only touch their own new file, so they may overlap T10/T11 once T6/T9 are in; cargo build contention makes sequential the default. T14-T17 are disjoint files and need all Rust tasks merged.

## Tasks

### Task 1: `AuditEntry.connection_id` and its rendering

- **Satisfies:** AC1
- **Depends on:** none
- **Files:** `crates/aitm-core/src/audit.rs` (modify: struct `:44-58`, `to_value :73-101`, test helper `entry :207-216`, new test), `crates/aitm-mcp/src/server.rs` (modify: the one `AuditEntry { .. }` literal in `record_audit :1631-1638`), `crates/aitm-ca/tests/audit.rs` (modify: literal in `ca_status_entry :135-146`)
- **Change:** `AuditEntry` gains `pub connection_id: Option<String>` after `client_label` (doc: server-assigned, opaque, `None` = not attributable to a streaming connection). `to_value` always inserts key `"connection_id"` as `Value::Str` or `Value::Null`. Fix the three struct literals in this same commit so the workspace compiles: `connection_id: None` in all three (the `server.rs` one is interim, T6 replaces it).
- **Test:** `audit::tests::to_value_carries_connection_id`: an entry with `Some("conn_ab-1")` renders `m["connection_id"] == Value::Str("conn_ab-1")`; with `None` renders `Value::Null`; the key set of the `Value::Object` is exactly `["args","at","client_label","command","connection_id","origin","result"]` (7).
- **Run:** `cargo test -p aitm-core --lib audit::tests::to_value_carries_connection_id`. **Red:** compile error `E0560` (`AuditEntry` has no field `connection_id`). Green after the change.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-core -p aitm-ca -p aitm-mcp --all-targets -- -D warnings && cargo test -p aitm-core --lib audit:: && cargo test -p aitm-ca --test audit && cargo check --workspace --all-targets` (all sandbox).
- **Done when:** the test passes and the gate is clean.

### Task 2: `visible_to`, `recent_for`, `count_since_for`

- **Satisfies:** AC2, AC3, AC4, AC6
- **Depends on:** Task 1
- **Files:** `crates/aitm-core/src/audit.rs` (modify: `impl AuditEntry`, `impl AuditRing` near `recent :155` and `count_since :172`, tests)
- **Change:** `impl AuditEntry { pub fn visible_to(&self, viewer: Frontend) -> bool }` = `viewer.is_trusted_control() || !self.origin.is_trusted_control()`. `impl AuditRing { pub fn recent_for(&self, viewer: Frontend, since: Option<SystemTime>, limit: Option<usize>) -> Vec<AuditEntry>; pub fn count_since_for(&self, viewer: Frontend, since: SystemTime, exclude_connection: Option<&str>) -> usize }`. `recent_for` keeps `recent`'s `since` (strictly after) and oldest-first order and applies the visibility filter **before** `limit`. `count_since_for` counts entries with `at >= since` that are visible and whose `connection_id` is not `Some(exclude)`; an entry with `connection_id == None` is never excluded. Doc comments on `recent` and `count_since`: no surface a role reads may use them (the in-process tests and the durable sink keep them). Test helper `entry_of(origin, connection_id: Option<&str>, command)` added beside `entry`.
- **Test (all in `audit.rs` `mod tests`):**
  - `visible_to_matrix`: origins in order `[Cli, Operator, Mcp]`; viewer `Cli` gives `[true,true,true]`, viewer `Operator` `[true,true,true]`, viewer `Mcp` `[false,false,true]` (compare arrays with `assert_eq!`, see the trap).
  - `recent_for_applies_the_limit_after_the_filter`: ring oldest first `op1 (Operator), ag1 (Mcp), op2 (Operator), ag2 (Mcp), op3 (Operator)`: `recent_for(Mcp, None, Some(2))` commands `["ag1","ag2"]`; `recent_for(Operator, None, Some(2))` `["ag2","op3"]`; `recent_for(Mcp, None, None)` `["ag1","ag2"]`.
  - `count_since_for_filters_and_excludes`: `t0 = now` taken first, then 3 entries (Mcp,"A"), 2 (Mcp,"B"), 4 (Operator,"O"), 1 (Mcp,None): `(Mcp,t0,None)=6`; `(Mcp,t0,Some("A"))=3`; `(Mcp,t0,Some("nope"))=6`; `(Operator,t0,None)=10`; `(Operator,t0,Some("O"))=6`.
- **Run:** `cargo test -p aitm-core --lib audit::tests`. **Red:** compile errors, no method `visible_to` / `recent_for` / `count_since_for`.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-core --all-targets -- -D warnings && cargo test -p aitm-core --lib audit:: && cargo test -p aitm-core --test trust_gate_scan --test classifier_wildcard_free` (AC6; sandbox).
- **Done when:** the three tests and both scan tests pass.

### Task 3: `cap_client_label`

- **Satisfies:** AC5
- **Depends on:** Task 2 (same file, sequential)
- **Files:** `crates/aitm-core/src/audit.rs` (modify), `crates/aitm-core/src/lib.rs` (modify: extend the `pub use audit::{..}` at `:32-35`)
- **Change:** `pub const MAX_CLIENT_LABEL_BYTES: usize = 128;` and `pub fn cap_client_label(name: &str) -> Option<String>`, both re-exported from `lib.rs`. Order is fixed: `None` if `name` is empty; replace every `char::is_control` char with `?`; cut to a private 512-byte window at a char boundary; `crate::redact::scrub_text` over the window; cut the scrubbed text at the last char boundary at or below 128 bytes, no ellipsis. The final cut comes after the scrub because masking lengthens text.
- **Test (`audit.rs` `mod tests`, one function per line, literal values):** `cap_client_label_cuts_ascii_at_128`: `"x".repeat(300)` gives `len() == 128`. `..._cuts_on_a_char_boundary`: `"é".repeat(100)` gives 128 bytes (64 chars); `"€".repeat(50)` gives 126 bytes (42 chars). `..._survives_the_window_boundary`: `"€".repeat(300)` (900 bytes) gives 126 bytes, no panic. `..._leaves_a_short_name`: `"aitm-mac"` unchanged. `..._replaces_control_chars`: `"a\u{1b}[31mred"` gives `"a?[31mred"`. `..._scrubs_secrets`: `"agent token=abc123"` contains `token=[redacted]` and not `abc123`. `..._cuts_after_the_scrub`: `"token=a,".repeat(40)` (320 bytes; masking makes it about 680) gives `len() <= 128`. `..._empty_is_none`: `""` gives `None`.
- **Run:** `cargo test -p aitm-core --lib audit::tests::cap_client_label`. **Red:** `E0425` cannot find function `cap_client_label`.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-core --all-targets -- -D warnings && cargo test -p aitm-core --lib audit:: && cargo test -p aitm-core --test trust_gate_scan --test classifier_wildcard_free` (sandbox).
- **Done when:** all eight tests pass.

### Task 4: `CommandHost.connection_id`

- **Satisfies:** AC15 (plumbing; end-to-end proof in T7 and T11)
- **Depends on:** none
- **Files:** `crates/aitm-core/src/ctx.rs` (modify: struct `:224-236`, `CommandHost::new :243`, beside `with_client_label :348` / `client_label :354`; new test module)
- **Change:** `CommandHost` gains private `connection_id: Option<String>` (`None` in `new`), `pub fn with_connection_id(mut self, id: impl Into<String>) -> Self`, `pub fn connection_id(&self) -> Option<&str>`. Doc: the server-assigned opaque id of the calling connection; `None` for an in-process caller; never derived from the label; policy keys off `frontend()`, not this.
- **Test:** new `#[cfg(test)] mod host_identity_tests` in `ctx.rs` (uses the module-level `NoopClient`, `StdGuard`, `MemFlowStore` as `trust_tests` does): `connection_id_defaults_to_none_and_follows_with_connection_id`: a fresh host's `connection_id()` is `None`; after `.with_connection_id("conn_ab-1")` it is `Some("conn_ab-1")`; a host given only `with_client_label("x")` still has `connection_id() == None`.
- **Run:** `cargo test -p aitm-core --lib ctx::host_identity_tests`. **Red:** `E0599` no method `with_connection_id`.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-core --all-targets -- -D warnings && cargo test -p aitm-core --lib ctx:: && cargo test -p aitm-core --test trust_gate_scan --test classifier_wildcard_free` (sandbox).
- **Done when:** the test passes. No literal builds `CommandHost` outside `new`, so nothing else breaks.

### Task 5: `aitm-ca` durable renderer parity

- **Satisfies:** AC17
- **Depends on:** Task 1
- **Files:** `crates/aitm-ca/src/audit.rs` (modify: `entry_to_jsonl :194`), `crates/aitm-ca/tests/audit.rs` (modify: add one test beside `ca_audit_is_a_subset :151`)
- **Change:** `entry_to_jsonl` adds `"connection_id": entry.connection_id` (string or null) to its object; update its doc comment (one shape shared with `to_value`).
- **Test:** `durable_line_has_the_same_keys_as_to_value`: `AuditEntry { connection_id: Some("conn_ab-1".into()), ..ca_status_entry() }`; the key set of `serde_json::from_str::<serde_json::Value>(&entry_to_jsonl(&e))` equals the key set of `e.to_value()` (`aitm_core::Value::Object` keys), which is the 7 keys of T1; and the parsed `value["connection_id"] == "conn_ab-1"`. The existing `ca_audit_is_a_subset` stays unchanged and green.
- **Run:** `cargo test -p aitm-ca --test audit durable_line_has_the_same_keys_as_to_value`. **Red:** assertion failure, durable keys are 6, `to_value` keys are 7.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-ca --all-targets -- -D warnings && cargo test -p aitm-ca` (whole crate, sandbox).
- **Done when:** both audit tests pass.

### Task 6: Salt, `McpServer::connection_id`, `initialize` echo, audit stamp

- **Satisfies:** AC7, AC8, AC9, AC10
- **Depends on:** Task 1
- **Files:** `crates/aitm-mcp/src/server.rs` (modify), `crates/aitm-mcp/tests/mcp.rs` (modify: add tests and helpers only)
- **Change (`server.rs`):** a private `conn_salt: u64` field on `McpServer` in all three places (struct `:796`, `new :878` drawn once from `uuid::Uuid::new_v4()`, and both the destructure `:1139-1163` and rebuild `:1165-1189` in `serve`; the compiler fails if one is missed). `pub fn connection_id(&self, conn: &ConnCtx) -> Option<String>`: `None` when `conn.conn_id == 0`, else the rendering `conn_<16 lowercase hex of the salt>-<conn_id decimal>` (at most 64 bytes of printable ASCII; the exact rendering inside those limits is the builder's). `dispatch("initialize")` (`:1288`, beside `"role": role_str(conn.role)` at `:1297`) adds a top-level `"connection_id"` (string or null), never inside `serverInfo`. `record_audit` (`:1631`) replaces T1's interim literal with `connection_id: self.connection_id(conn)`. Nothing a request carries is read into the id. `ConnCtx` and `conn_id` semantics do not change (subscriptions and confirm tokens still key on `conn_id`).
- **Test helpers (new, test-only, in `mcp.rs`, reused by T7-T11; do not edit existing fixtures):** `fn minted(srv: &McpServer, role: Frontend) -> ConnCtx` (`conn_id: srv.next_conn_id()`, no label, no sink); `fn call_on(srv: &McpServer, conn: &ConnCtx, name: &str, args: JsonValue) -> JsonValue` (whole parsed reply); `fn init_id(srv: &McpServer, conn: &ConnCtx) -> String` (sends `initialize`, returns `result.connection_id` as a string, panicking if it is not one); `fn watcher(srv: &McpServer, role: Frontend) -> ConnCtx` (minted, `out: Some(NotificationSink::new(64))`, already `flow.subscribe {}`d).
- **Tests (`mcp.rs`, in-process, sandbox):**
  - `initialize_echoes_connection_id`: on `minted(srv, Mcp)`, `result.connection_id` is a non-empty string of at most 64 bytes; equal across two `initialize` calls on that connection; different for a second minted connection of the same server; `result.serverInfo.connection_id` is null.
  - `initialize_connection_id_is_null_without_a_connection`: `ConnCtx::new(Operator)` gives `result["connection_id"] == Null` and `result.as_object().unwrap().contains_key("connection_id")`.
  - `audit_entries_carry_the_connections_id`: over `audit_server(ring)` (`:3046`, unmodified) with an operator `watcher`; minted A and B (Mcp) each call `demo.read`, then `ConnCtx::new(Mcp)` calls it. `ring.recent(None,None)` entry 0 `connection_id == Some(A's init id)`, entry 1 `Some(B's)`, they differ, entry 2 `None`; the watcher's three `notifications/aitm/agent` lines carry `params.connection_id` equal to the three entries' (string, string, null).
  - `connection_ids_are_distinct_across_servers`: two fresh servers, each `next_conn_id() == 1`; the `initialize` id of that connection differs between them (`assert_ne!`).
  - `forged_claims_never_change_the_connection_id`: `initialize` with params `{"clientInfo":{"name":"conn_victim","connection_id":"conn_victim"},"_meta":{"connection_id":"conn_victim"},"connection_id":"conn_victim"}` returns an id `!= "conn_victim"` and equal to a plain `initialize`'s; the connection's later `demo.read` entry carries that id.
- **Run:** `cargo test -p aitm-mcp --test mcp -- initialize_echoes_connection_id initialize_connection_id_is_null audit_entries_carry connection_ids_are_distinct forged_claims`. **Red:** `result["connection_id"]` is `null` (the non-empty-string assertion fails); `audit_entries_...` fails `left: None, right: Some("conn_...")`; the null-key test fails on `contains_key`.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-mcp --all-targets -- -D warnings`, then the five tests (sandbox), then full `cargo test -p aitm-mcp` (**Terminal**: binds ports).
- **Done when:** the five tests pass and the full crate passes.

### Task 7: `host.with_connection_id` in `run_tool`

- **Satisfies:** AC15 (plumbing)
- **Depends on:** Task 4, Task 6
- **Files:** `crates/aitm-mcp/src/server.rs` (modify: the host builder in `run_tool`, `:1548-1567`, beside `with_client_label`), `crates/aitm-mcp/tests/mcp.rs` (modify)
- **Change:** where `run_tool` builds the `CommandHost`, attach `self.connection_id(conn)` through `with_connection_id` when it is `Some`.
- **Test:** new fixture command `ConnectionIdCmd` (`demo.connection`, `Sensitivity::Read`, returns `host.connection_id().unwrap_or("<none>")`, modelled on `ClientLabelCmd :295`) and a new `fn connection_server()` that registers it (no edit to `registry()` or `audit_server`). `command_host_carries_the_connection_id`: on `minted(srv, Mcp)`, `tools/call demo.connection` returns `structuredContent == init_id(..)`; on `ConnCtx::new(Mcp)` it returns `"<none>"`.
- **Run:** `cargo test -p aitm-mcp --test mcp -- command_host_carries_the_connection_id`. **Red:** `left: "<none>", right: "conn_..."`.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-mcp --all-targets -- -D warnings`, the test (sandbox), full `cargo test -p aitm-mcp` (**Terminal**).
- **Done when:** the test passes.

### Task 8: Ingestion cap at the one call site

- **Satisfies:** AC11
- **Depends on:** Task 3, Task 7 (sequential on `mcp.rs`)
- **Files:** `crates/aitm-mcp/src/transport.rs` (modify: `client_label_from_initialize :141-148`), `crates/aitm-mcp/src/server.rs` (modify: doc comment on `ConnCtx.client_label :85` only), `crates/aitm-mcp/tests/mcp.rs` (modify)
- **Change:** `client_label_from_initialize` returns `aitm_core::cap_client_label(name)` instead of `(!name.is_empty()).then(..)`. Doc on `ConnCtx.client_label`: set only through `cap_client_label`. The bridge and HTTP keep not setting a label.
- **Test:** `client_label_is_capped_at_ingestion` (`#[tokio::test]`, no ports): a server over `role_registry()` (`:962`) with `.with_audit_ring(ring.clone())`, `serve_lines` over `tokio::io::duplex` of at least 4 MiB (rig of `stdio_default_role_is_agent :1099`, spawned); send `initialize` with `clientInfo.name = "a".repeat(1 << 20)` then `tools/call demo.client`. Assert on `.len()` so the red output stays short: the `demo.client` result string has `len() == 128` (and equals `"a".repeat(128)`), and the audit entry's `client_label.unwrap().len() == 128`.
- **Run:** `cargo test -p aitm-mcp --test mcp -- client_label_is_capped_at_ingestion`. **Red:** `left: 1048576, right: 128`.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-mcp --all-targets -- -D warnings`, the test (sandbox), full `cargo test -p aitm-mcp` (**Terminal**; keeps `client_label_captured_from_initialize :1138` green).
- **Done when:** the test passes.

### Task 9: Role-filtered push

- **Satisfies:** AC12
- **Depends on:** Task 2, Task 8
- **Files:** `crates/aitm-mcp/src/server.rs` (modify: `Subscriptions` near `fanout_state :519`, `push_agent :1650`), `crates/aitm-mcp/tests/mcp.rs` (modify)
- **Change:** `Subscriptions::fanout_audit(&self, entry: &AuditEntry, line: &str)`: under the registry lock, once per connection (same `seen` dedup as `fanout_state`), push only to subscriptions whose `role` satisfies `entry.visible_to(role)`. `push_agent` renders the line once and calls it. `push_state` and `approval_requested` unchanged.
- **Test:** `an_agent_subscriber_never_receives_operator_audit_lines`: over `audit_server(ring)` with `watcher(Operator)` O and `watcher(Mcp)` G; O calls `demo.read`, then G calls `demo.read`. O's sink holds exactly 2 `notifications/aitm/agent` lines with origins `["operator","mcp"]`; G's sink holds exactly 1, origin `"mcp"` (filter drained lines by `method`).
- **Run:** `cargo test -p aitm-mcp --test mcp -- an_agent_subscriber_never_receives_operator_audit_lines`. **Red:** G's sink holds 2 (`left: 2, right: 1`).
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-mcp --all-targets -- -D warnings`, the test (sandbox), full `cargo test -p aitm-mcp` (**Terminal**), and regression `cargo test -p aitm --test web_bus_push --test web_bus_governance` (**Terminal**).
- **Done when:** the test passes and the regressions are green.

### Task 10: `agent.activity` viewer filter and schema

- **Satisfies:** AC13, AC16 (activity half)
- **Depends on:** Task 2, Task 6, Task 9
- **Files:** `crates/aitm-plugins/src/agent.rs` (modify: `AgentActivity` `:208-283`, new `#[cfg(test)] mod tests`), `crates/aitm-mcp/tests/mcp.rs` (modify)
- **Change:** `AgentActivity::invoke` takes `host` (not `_host`) and returns `AuditRing::recent_for(host.frontend(), since, limit)`. Schema: the result object gains a `connection_id` param (`TypeDesc::Str`, `required: false`, "The server-assigned id of the connection that made the call; null when not attributable"); the description gains the sentence that a caller that is not trusted control does not see entries made by trusted control (operator, CLI) — the description must contain the literal text `trusted control` (this plan's choice). Update the struct doc comment.
- **Tests:**
  - `agent_activity_hides_trusted_control_entries_from_agents` (`mcp.rs`, `audit_server`, minted O and G): O `demo.read` x2, G `demo.read`; then G `agent.activity` returns 1 entry (command `demo.read`, origin `mcp`); O `agent.activity` returns 4 entries with origins `["operator","operator","mcp","mcp"]` (G's own `agent.activity` is the fourth); G `agent.activity {limit:1}` returns one entry, command `agent.activity`, origin `mcp` (not the operator's).
  - `agent_activity_schema_declares_connection_id` (in `agent.rs`): build a `Registry` with `AgentPlugin::new(Arc::new(AgentState::new(AgentPolicy::Auto)))`, take `reg.command("agent.activity").unwrap().schema()`; the result is `TypeDesc::Array(Object(fields))` with a field `connection_id`, `required == false`; `description.contains("trusted control")`.
- **Run:** `cargo test -p aitm-mcp --test mcp -- agent_activity_hides` and `cargo test -p aitm-plugins --lib agent::tests`. **Red:** G sees 3 (`left: 3, right: 1`) and the limit case returns the operator's entry; the schema test fails for the missing field.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-plugins -p aitm-mcp --all-targets -- -D warnings`, the tests above (sandbox), then `cargo test -p aitm-plugins` and `cargo test -p aitm-mcp` (**Terminal**).
- **Done when:** both tests pass; `agent_activity_returns_recent` and `agent_status_readable_by_any_role` stay green unmodified.

### Task 11: `agent.status` viewer-filtered count and `exclude_self`

- **Satisfies:** AC14, AC15, AC16 (status half)
- **Depends on:** Task 4, Task 7, Task 10
- **Files:** `crates/aitm-plugins/src/agent.rs` (modify: `AgentStatus :79-145`, tests), `crates/aitm-mcp/tests/mcp.rs` (modify)
- **Change:** `AgentStatus::schema` `params` becomes one optional `exclude_self` (`TypeDesc::Bool`, `required: false`); description gains the literal text `trusted control` (the count covers only entries the caller may see). `invoke(&self, args, host)` reads `exclude_self` (absent or `false` means off), and counts with `count_since_for(host.frontend(), now - 60 s, exclude)`, where `exclude` is `host.connection_id()` only when `exclude_self` is true (no own id excludes nothing). A non-bool value is rejected by the existing schema coercion as `-32602`; add no custom check.
- **Tests (`mcp.rs`, over `audit_server(ring)`, fresh ring each; the count never includes the call itself because the entry is recorded after `invoke`):**
  - `agent_status_counts_only_what_the_caller_may_see`. Ring after each call: O `demo.read` x4 (4 operator entries); A `demo.read` x3 (7); B `agent.status {}` returns `actions_last_minute == 3` (A's three; the operator's four are hidden; ring 8); O `agent.status {}` returns `== 8` (4 + 3 + B's status).
  - `agent_status_exclude_self_skips_only_the_callers_connection`. A `demo.read` x3, B `demo.read` x2 (5 agent entries); A `agent.status {exclude_self:true}` returns `2` (ring 6); A `agent.status {}` returns `6` (ring 7); `ConnCtx::new(Mcp)` `agent.status {exclude_self:true}` returns `7` (no own id, nothing excluded); `{exclude_self:"yes"}` is a `-32602` reply (`error.code == -32602`, not audited). `tools/list`: the `agent.status` entry has `inputSchema.properties.exclude_self.type == "boolean"` and `exclude_self` is not in `required` (the key may be absent).
  - `agent_status_schema_declares_exclude_self` (`agent.rs`, same rig as T10): `agent.status` has a `Bool` param `exclude_self`, `required == false`; `description.contains("trusted control")`.
- **Run:** `cargo test -p aitm-mcp --test mcp -- agent_status_` and `cargo test -p aitm-plugins --lib agent::tests`. **Red:** B reads `7` (`left: 7, right: 3`); `exclude_self:true` is a `-32602` unknown-param error so `structuredContent` is `null`; the schema test fails.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-plugins -p aitm-mcp --all-targets -- -D warnings`, the tests (sandbox), then `cargo test -p aitm-plugins`, `cargo test -p aitm-mcp` and `cargo test -p aitm --test web_bus_governance --test web_bus_ask_split --test web_bus_push --test frontends` (**Terminal**; `frontends` pins tool names only).
- **Done when:** all three pass and the regressions are green. AC16 is covered by T10's and this task's schema tests together (the spec names one test; see Ambiguities 3).

### Task 12: Two governed servers never share an id (in process)

- **Satisfies:** AC18
- **Depends on:** Task 6
- **Files:** `crates/aitm/tests/web_bus_audit_identity.rs` (create)
- **Change:** test-only. Rig copied from `web_bus_ask_split.rs:71-93` (`temp_ca_dir`, `assemble`, `tui::services`, `tui::server`, `tui::with_shared_governance` on both servers, policy `Auto`), no sockets.
- **Test:** `governed_servers_sharing_a_ring_never_share_an_id`: two servers from one `Assembled`; on each, an agent `ConnCtx { role: Frontend::Mcp, client_label: None, conn_id: 1, out: None }` calls `flow.list` and `initialize`. The shared `audit_ring.recent(None,None)` has 2 entries, both `connection_id.is_some()`, and `assert_ne!` between them; the two `initialize` `result.connection_id` strings are also different.
- **Run:** `cargo test -p aitm --test web_bus_audit_identity governed_servers_sharing_a_ring_never_share_an_id` (sandbox). **Red by mutation** (no production change in this task): temporarily make the salt in `McpServer::new` the constant `0`, run, see the `assert_ne!` fail (equal ids); restore it and confirm `server.rs` has no diff (`git diff --stat -- crates/aitm-mcp` via Terminal).
- **Gate:** `cargo fmt --check && cargo clippy -p aitm --all-targets -- -D warnings && cargo test -p aitm --test web_bus_audit_identity governed_servers` (sandbox).
- **Done when:** green with the real salt, red with the mutation shown, mutation reverted.

### Task 13: Real `/bus` bridge: server-assigned ids and a role-filtered stream `[socket]`

- **Satisfies:** AC19
- **Depends on:** Task 9, Task 12
- **Files:** `crates/aitm/tests/web_bus_audit_identity.rs` (modify)
- **Change:** test-only. Add the loopback `/bus` rig copied from `web_bus_governance.rs` (`Server`, `start :96-128` with `AGENT_TOKEN` and `OPERATOR_TOKEN`, `ws_connect`, `send_text`, `next_frame`, `try_recv_until`, `recv_until`, `drain_for`, `open_bus`), policy `Auto`. That file's `call` discards the notification frames it skips; write a local call helper that **keeps** them in a per-connection `Vec<JsonValue>`.
- **Test:** `bridge_ids_are_server_assigned_and_the_stream_is_role_filtered`. (1) Agent G and operator O open the bus; each `initialize` reply carries a non-empty `result.connection_id` string of at most 64 bytes; `gid != oid`. (2) Both `flow.subscribe {}` (a `sub_id` u64 each). (3) G re-sends `initialize` with `{"clientInfo":{"name":"conn_victim","connection_id":"conn_victim"},"_meta":{"connection_id":"conn_victim"},"connection_id":"conn_victim"}`: the reply's id is still `gid`. (4) G `flow.list`: G's stream gets a `notifications/aitm/agent` line with `params.command == "flow.list"`, `params.connection_id == gid`, `params.client_label == null`, `params.origin == "mcp"`. (5) O `proxy.status`: O's stream gets a line with `origin == "operator"` and `connection_id == oid`. (6) Barrier: G `flow.list` again and wait for that second line on G's stream; across every frame G's stream delivered, none has `params.origin == "operator"` and none has `params.command == "proxy.status"`.
- **Run (Terminal):** `cargo test -p aitm --test web_bus_audit_identity bridge_ids_are_server_assigned_and_the_stream_is_role_filtered`. **Red by mutation:** temporarily skip the `visible_to` check inside `Subscriptions::fanout_audit` and see step 6 fail (G holds the operator line). Restore; `server.rs` diff empty.
- **Gate (Terminal):** `cargo fmt --check && cargo clippy -p aitm --all-targets -- -D warnings && cargo test -p aitm --test web_bus_audit_identity --test web_bus_governance --test web_bus_ask_split --test web_bus_push --test web_bus_roles` (those four existing files stay unmodified, AC24).
- **Done when:** both new tests pass, the existing four files pass untouched, mutation reverted.

### Task 14: e2e `test_bus_push_ui_contract.py` sections 6 and 7 `[e2e]`

- **Satisfies:** AC20
- **Depends on:** Task 6, Task 9
- **Files:** `tests/e2e/web/test_bus_push_ui_contract.py` (modify)
- **Change:** append sections 6 and 7 **after** section 5 (earlier exact-count checks keep their meaning; move the final `ok(...)` after them; add them to the module docstring; the `client_label is None` pin stays). Import `PROTOCOL_VERSION` from `aitm_e2e.bus`. Close the second client in `finally`.
- **Test:** *Section 6:* `a = ws.initialize()` and `b = ws.initialize()`; `cid = a["connection_id"]` is a `str` of 1 to 64 bytes and `b["connection_id"] == cid`; one more `ws.call("flow.list")`; every `flow.list` audit line on the stream (at least 2) has `connection_id == cid` and `client_label is None`. *Section 7:* `ws2 = WsBusClient.web_agent(core)`; `cid2 = ws2.initialize()["connection_id"]` is a `str` and `!= cid`; `ws2.call("proxy.status")`; the first connection's stream receives exactly one `proxy.status` line with `origin == "mcp"` and `connection_id == cid2`; then `ws.rpc("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "aitm-web", "version": "0"}})` returns `connection_id == cid`, and a following `ws.call("flow.list")` line has `connection_id == cid` and `client_label is None`.
- **Run (Terminal):** `cargo build -p aitm`, then `AITM_BIN=$AITM_BASE_BIN python3 tests/e2e/web/test_bus_push_ui_contract.py` **(red:** a `[FAIL]` at section 6, `connection_id` absent / not a str) and `python3 tests/e2e/web/test_bus_push_ui_contract.py` (green, exit 0).
- **Gate:** the green run, plus `python3 tests/e2e/run.py web` (the two sibling suites untouched and green).
- **Done when:** red against the baseline binary, green against the branch binary.

### Task 15: e2e `test_bus_audit_visibility.py` (new) `[e2e]`

- **Satisfies:** AC21
- **Depends on:** Task 11
- **Files:** `tests/e2e/web/test_bus_audit_visibility.py` (create; header `# e2e: tier=T1 surface=web`)
- **Change:** boots `Aitm.web(CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(), scope_entries=["127.0.0.1"]))` (the config's default operator token enables the operator link); copies the `operator_bridge_token(core)` parser from `tests/e2e/web/test_web_intercept.py:89-100` (copy, do not edit the harness; a missing token is a FAIL). Agent `A = WsBusClient.web_agent(core)` and operator `O = WsBusClient.web_operator(core, token)`, both `flow.subscribe {}`. The core is fresh and only A and O act, in this order, so the literals below are exact (ring after each call; an entry is recorded after the call returns, so a call never counts itself):

  | # | call | returns | ring after |
  |---|---|---|---|
  | 1 | O `proxy.status` | line on O's stream, `origin == "operator"`; never on A's | 1 (O) |
  | 2 | A `proxy.status` (barrier: wait for A's own line) | line on A's and on O's stream, `origin == "mcp"` | 2 |
  | 3 | A `agent.activity` | 1 entry, command `proxy.status`, origin `mcp` | 3 |
  | 4 | O `agent.activity` | 3 entries, origins `["operator","mcp","mcp"]` | 4 |
  | 5 | A `agent.status {exclude_self:true}` | `actions_last_minute == 0` | 5 |
  | 6 | A `agent.status {}` | `== 3` (A's proxy.status, activity, status-exclude) | 6 |
  | 7 | O `agent.status {}` | `== 6` (O proxy.status, A proxy.status, A activity, **O activity**, A status-exclude, A status) | 7 |

  Also: after step 2, assert no line with `origin == "operator"` is in A's stream, and A's `agent.activity` entry's `connection_id` equals A's `initialize` id. The spec's status line says step 7 is `5`; that list omits O's own step-4 `agent.activity`, which is audited, so the correct literal is **6** (Ambiguities 1). If the live run shows anything but 6, stop and report.
- **Run (Terminal):** `AITM_BIN=$AITM_BASE_BIN python3 tests/e2e/web/test_bus_audit_visibility.py` **(red:** A's stream holds the operator line; A's first `agent.activity` returns 2) then the same without `AITM_BIN` against the fresh build (green).
- **Gate:** `python3 tests/e2e/run.py web` (Terminal).
- **Done when:** red on baseline, green on the branch binary.

### Task 16: e2e `test_audit_identity.py` (new) `[e2e]`

- **Satisfies:** AC22
- **Depends on:** Task 8, Task 11
- **Files:** `tests/e2e/audit/test_audit_identity.py` (create; header `# e2e: tier=T1 surface=audit`)
- **Change:** boots `Aitm.server(CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(), scope_entries=["127.0.0.1"]))` (its own core, so it needs no `AITM_BUS_ADDR`). Agents A and B are `BusClient(host, port, core.cfg.agent_token, client_name="aitm-e2e-ident-a" / "-b").connect()` (distinct labels so entries are findable); operator is `BusClient.operator(core)`. Order, with the literals (fresh ring; entries recorded after each call):

  | # | call | returns |
  |---|---|---|
  | 1-3 | A `scope.list` x3 | ring 3 |
  | 4-5 | B `scope.list` x2 | ring 5 |
  | 6 | A `agent.status {exclude_self:true}` | `actions_last_minute == 2` (5 agent entries minus A's 3); ring 6 |
  | 7 | A `agent.status {}` | `== 6`; ring 7 |
  | 8 | O `agent.status {}` | `== 7` (O has made no audited call yet) |
  | 9 | O `agent.activity` | entries labelled `...-a` all carry A's `initialize` id, `...-b` all carry B's; the two ids are different non-empty strings |
  | 10 | label step, last so the counts stay exact: `X = BusClient(.., client_name="x" * (1 << 20)).connect()`, `X.call("scope.list")`, `idx = X.initialize()["connection_id"]` | O `agent.activity`: the entry with `connection_id == idx` has `len(client_label) == 128` and `== "x" * 128` |

  Assert on lengths so a failure never prints 1 MiB. No pre-count read of the ring is possible (it would add an operator entry and move step 8), so the exact counts double as the freshness check.
- **Run (Terminal):** `AITM_BIN=$AITM_BASE_BIN python3 tests/e2e/audit/test_audit_identity.py` **(red:** step 6 gets a `-32602` unknown param or, if reordered, the label is 1048576 bytes) then against the fresh build (green).
- **Gate:** `python3 tests/e2e/run.py audit` (Terminal; `test_audit_log.py` will SKIP without `--shared-core`, which is expected here and covered in T18).
- **Done when:** red on baseline, green on the branch binary.

### Task 17: e2e `neg/test_nonexistent_flow_error.py` reads the audit as the operator `[e2e]`

- **Satisfies:** AC23
- **Depends on:** Task 10
- **Files:** `tests/e2e/neg/test_nonexistent_flow_error.py` (modify one line)
- **Change:** at `:550`, `entries = activity_since(rd, t0_ms)` becomes `activity_since(op or rd, t0_ms)`, with a one-line comment: the ground-truth leg asserts `origin == "operator"` entries, which an agent-role reader no longer receives (spec D3). No other line changes; when no operator token exists, `op` is `None` and `rd` is used as before.
- **Run (Terminal):** `cargo build -p aitm -p aitm-testtarget`. With the line unmodified: `python3 tests/e2e/run.py --shared-core neg` **(red:** `FAIL neg/test_nonexistent_flow_error.py` at the `audit: flow.export by operator on ...` check). After the edit, the same command is green. (`--shared-core` is required: the `neg` suites SKIP without a runner-provided core, which would hide AC23.)
- **Gate:** `python3 tests/e2e/run.py --shared-core neg` exit 0, no `neg` SKIP.
- **Done when:** red before the edit and green after it, against the branch binary.

### Task 18: Whole-branch verification

- **Satisfies:** AC24, AC25, and every AC end to end
- **Depends on:** Tasks 1-17
- **Files:** none
- **Change:** none. Verification only (Terminal panel for all of it).
- **Steps and expected results:**
  1. `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test > $TMPDIR/gate.log 2>&1; echo $?` prints `0`. The known flake `rhai_e2e::script_cannot_escape_or_exceed_scope` may fail under the full run; this change touches no Rhai, so rerun it once alone and record both results rather than reading it as ours.
  2. `cargo build -p aitm -p aitm-testtarget`, then `python3 tests/e2e/run.py --shared-core web audit neg` exits 0; its summary is `0 fail` and no `audit/*` or `neg/*` suite is `SKIP` (the new `web/test_bus_audit_visibility.py` and `audit/test_audit_identity.py` boot their own cores; `audit/test_audit_log.py` and `neg/*` need the shared core). Recommended extra, not in the spec's gate: also run `scope`, which reads `agent.activity` as the agent.
  3. AC25: `git diff --stat 8315880..HEAD -- apps crates/aitm-tui crates/aitm/src/web crates/aitm-mcp/src/http.rs` is empty.
  4. AC24: `git diff 8315880..HEAD -- crates/aitm/tests/web_bus_push.rs crates/aitm/tests/web_bus_governance.rs crates/aitm/tests/web_bus_ask_split.rs` is empty, and `git diff 8315880..HEAD -- crates/aitm-mcp/tests/mcp.rs | grep -c '^-[^-]'` prints `0` (additions only).
  5. Hand the diff to the Tester (every AC maps to a test) and then the three-reviewer panel on the whole branch.
- **Done when:** all five hold.

## Ambiguities found while planning, and the resolution

1. **AC21 operator count.** The spec's status-line amendment says `5` with entries "O proxy.status, A proxy.status, A agent.activity, A agent.status exclude_self, A agent.status". That list omits the operator's own `agent.activity` at AC21's fourth step, which is audited when it returns (`record_audit` runs after `invoke`, and AC13 relies on `agent.activity` being audited). Six audited calls precede the operator's final `agent.status` (O proxy.status, A proxy.status, A activity, O activity, A status-exclude, A status), so it reads **6**, which is what AC21's body text already says. The plan uses 6 (T15). I did not edit the spec; its status-line amendment should be reverted. If the orchestrator disagrees, T15's table is the place to check.
2. **Gate command.** `python3 tests/e2e/run.py web audit neg` without `--shared-core` SKIPs `audit/test_audit_log.py` and all `neg/*` (they read `AITM_BUS_ADDR`), so AC23 would never run. The plan uses `--shared-core` (T17, T18).
3. **AC16 names one test**; the activity and status schema changes land in different tasks, so it is two in-crate tests (T10, T11) asserting the same facts. The "viewer filter" wording is pinned as the literal `trusted control` in both descriptions (this plan's choice).
4. **D1 says `connection_id()` is called in exactly two places**; it is three (`record_audit`, `initialize`, and `run_tool` via D4's `with_connection_id`, T7). No effect on behavior.
5. **AC18 and AC19 are integration pins** over behavior built in T6 and T9, so they are green on arrival; their red is shown by mutation (T12, T13). Every other AC is red first against a real missing piece.
6. **Docs not touched.** `docs/research/mcp-tool-catalog.txt` (the spec allows "refresh or leave") is a dated `aitm --help` snapshot used as a research input; left. `aitmproxy-plugin/docs/tool-reference.md`, which the spec does not name, also quotes the two description strings, is generated (`node aitmproxy-plugin/scripts/gen-tool-reference.mjs`) and already drifts per its own header; no test pins it; left. Both are follow-ups for the Shipped section, not tasks.
7. **e2e red needs a baseline binary** the spec does not mention: Step 0. T17's red is against the branch binary instead (the failure only exists once D3 lands).
8. **Source-scan trap.** In-`src` tests (`audit.rs`) are scanned by `trust_gate_scan`; the plan tells each task to compare roles with `assert_eq!` on arrays (see Conventions).

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
