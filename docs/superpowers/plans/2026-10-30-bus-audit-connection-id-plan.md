# Server-assigned connection id on audit lines implementation plan

**Status:** approved (orchestrator, 2026-10-30, under Matt's standing autonomous-approval rule). **Amendment 1 (reconciliation tasks R1-R5, last section of this file): approved by the orchestrator, 2026-10-30, under the standing autonomy rule (spec A10 Q1 and Q2 take their defaults: D3 stands and five PR 166 tests are amended; the whitespace port into PR 171's sanitiser is done).**
**Spec:** `docs/superpowers/specs/2026-10-30-bus-audit-connection-id-design.md` (approved; Ambiguities 1 is resolved: the spec's AC21 literal 6 stands and the spec's status line no longer says otherwise)
**Branch / worktree:** `feat/bus-audit-conn-id` in `/Users/matt/Security/aitmproxy/.claude/worktrees/adoring-cartwright-385dea` (base `8315880`; after main moved, merged with `origin/main` twice, at `0d50cf4` and then at `840e520`, see Amendment 1)

## Overview

Server only. Eighteen small tasks in four waves: `aitm-core` and `aitm-ca` pieces first (T1-T5), then the `aitm-mcp` / `aitm-plugins` behavior (T6-T11, strictly sequential: `server.rs`, `mcp.rs` and `agent.rs` are shared), then the `aitm` integration tests (T12-T13), then the e2e suites (T14-T17, independent of each other), then one whole-branch gate (T18). Each task is test-first, ends green and is committable alone. **No task touches `apps/`, `crates/aitm-tui`, `crates/aitm/src/web/` or `crates/aitm-mcp/src/http.rs`** (AC25): the UI consumer is a separate PR. The three-reviewer panel (security, quality, spec) runs per WORKFLOW stage 6 as the orchestrator dispatches it, after the last task, and once on the whole branch before integration. **[Amended: `## Amendment 1: reconciliation tasks` at the end governs after the merge with `origin/main` at `0d50cf4`; where a task below conflicts with it, the amendment wins.]**

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

### Task 3: `cap_client_label` **[SUPERSEDED by Amendment 1: PR 171's `sanitize_client_label` replaces it; R1 removes the function, the constant, the export and all 17 of its tests]**

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
- **Change (`server.rs`):** a private `conn_salt: u64` field on `McpServer` in all three places (struct `:796`, `new :878` drawn once from `uuid::Uuid::new_v4()`, and both the destructure `:1139-1163` and rebuild `:1165-1189` in `serve`; the compiler fails if one is missed). `pub fn connection_id(&self, conn: &ConnCtx) -> Option<String>` **[Amended: it is a private `fn connection_id` since the round-1 quality fix, because nothing outside `McpServer` calls it]**: `None` when `conn.conn_id == 0`, else the rendering `conn_<16 lowercase hex of the salt>-<conn_id decimal>` (at most 64 bytes of printable ASCII; the exact rendering inside those limits is the builder's). `dispatch("initialize")` (`:1288`, beside `"role": role_str(conn.role)` at `:1297`) adds a top-level `"connection_id"` (string or null), never inside `serverInfo`. `record_audit` (`:1631`) replaces T1's interim literal with `connection_id: self.connection_id(conn)`. Nothing a request carries is read into the id. `ConnCtx` and `conn_id` semantics do not change (subscriptions and confirm tokens still key on `conn_id`).
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

### Task 8: Ingestion cap at the one call site **[SUPERSEDED in part by Amendment 1: `client_label_from_initialize` calls PR 171's `declared_client_label`; the test keeps its rig and its literals become 64 characters (R1)]**

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
- **Test:** `bridge_ids_are_server_assigned_and_the_stream_is_role_filtered`. (1) Agent G and operator O open the bus; each `initialize` reply carries a non-empty `result.connection_id` string of at most 64 bytes; `gid != oid`. (2) Both `flow.subscribe {}` (a `sub_id` u64 each). (3) G re-sends `initialize` with `{"clientInfo":{"name":"conn_victim","connection_id":"conn_victim"},"_meta":{"connection_id":"conn_victim"},"connection_id":"conn_victim"}`: the reply's id is still `gid`. (4) G `flow.list`: G's stream gets a `notifications/aitm/agent` line with `params.command == "flow.list"`, `params.connection_id == gid`, `params.client_label == null` **[Amended: `params.client_label == "web-bridge"` after PR 171, R1 step 7 and spec A6 AC19]**, `params.origin == "mcp"`. (5) O `proxy.status`: O's stream gets a line with `origin == "operator"` and `connection_id == oid`. (6) Barrier: G `flow.list` again and wait for that second line on G's stream; across every frame G's stream delivered, none has `params.origin == "operator"` and none has `params.command == "proxy.status"`.
- **Run (Terminal):** `cargo test -p aitm --test web_bus_audit_identity bridge_ids_are_server_assigned_and_the_stream_is_role_filtered`. **Red by mutation:** temporarily skip the `visible_to` check inside `Subscriptions::fanout_audit` and see step 6 fail (G holds the operator line). Restore; `server.rs` diff empty.
- **Gate (Terminal):** `cargo fmt --check && cargo clippy -p aitm --all-targets -- -D warnings && cargo test -p aitm --test web_bus_audit_identity --test web_bus_governance --test web_bus_ask_split --test web_bus_push --test web_bus_roles` (those four existing files stay unmodified, AC24).
- **Done when:** both new tests pass, the existing four files pass untouched, mutation reverted.

### Task 14: e2e `test_bus_push_ui_contract.py` sections 6 and 7 `[e2e]` **[Amended: every null `client_label` check is `"web-bridge"` after PR 171; see R4]**

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

### Task 16: e2e `test_audit_identity.py` (new) `[e2e]` **[Amended: the label length is 64 characters, not 128 bytes; see R4]**

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

### Task 18: Whole-branch verification **[Amended: its diff base is the merge base, `git merge-base HEAD origin/main`, and its final run is Amendment 1 R5]**

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

Kept by the main session during stage 6. One row per finding. Rows under Round 1 were written before main moved (branch at c8c249a); where a row names code the merge later removed (`cap_client_label`, `fanout_where`, a deleted `count_since`), the row is history and the replacement is described in Round 2 and in the spec's Amendment 1.

### Round 1 (pre-merge)

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| plan | spec (pre-panel) | Minor | The orchestrator's first-pass doubt that AC21's operator count was 6 | retracted: the operator's own `agent.activity` is audited, so 6 is right (spec status line reworded, plan Ambiguity 1) |
| T17 | orchestrator run | Minor | The unedited `neg/test_nonexistent_flow_error.py` fails first at `agent.activity has >= 70 entries (63)`, not at the `flow.export` check the plan names | same cause (an agent no longer reads operator entries); the one-line `op or rd` fix clears both, green run recorded |
| whole branch | tester | Important-grade gaps | AC4 (count window), AC3 (`since`), AC5 (control/scrub order), AC11 (length only), AC12 (dedup), AC13 to AC15 each had a test that survived the removal of its behaviour | fixed in 108bf98: 18 tests, each mutation-checked in a scratch copy |
| whole branch | spec | Minor | Spec "Hot path" sentence false: `connection_id` is built once in `run_tool` and again in `record_audit` | fixed in c8c249a (spec reworded to "one or two") |
| whole branch | spec | Minor | Commit subjects use `test(...)` and an ASCII hyphen where the plan's convention line shows `feat(...)` and an em dash | accepted (orchestrator, 2026-10-30, standing autonomy rule): the terminal refuses non-ASCII, `test(...)` is the honest prefix; squash merge makes it moot |
| whole branch | security | Minor | `cap_client_label` turned `\t \n \r` into `?` before the scrub, so `"agent Bearer\tabc123"` kept its token | fixed in c8c249a (whitespace controls become a space; three red-first tests) |
| whole branch | security | Minor | Bidi, zero-width and BOM characters pass through the label (display spoofing in operator tables) | fixed in c8c249a (explicit range list replaced by `?`; red-first tests including range edges) |
| whole branch | security | Minor | The id is salt plus per-server ordinal, so an agent can compute lower-numbered ids; hidden-entry volume is observable from ring aging | accepted (orchestrator, 2026-10-30): the id is not a secret and nothing accepts it as input; unforgeability rests on the server stamping it from `ConnCtx`. Spec D1 exposure text, the anti-goal, R7 and wire-contract note 6 reworded in c8c249a |
| whole branch | security | hardening | `AuditRing::recent` stays `pub` and unfiltered; no scan test guards a future role-facing caller | not done: deleting `count_since` and a doc warning in c8c249a; a `trust_gate_scan`-style tripwire is a follow-up (renaming `recent` would edit base test lines, AC24) |
| whole branch | quality | Minor | `AuditRing::count_since` dead code with false docs; stale `ConnCtx`, `conn_id` and module docs | fixed in c8c249a |
| whole branch | quality | Minor | `fanout_audit` a fourth copy of the dedup loop | fixed in c8c249a (`fanout_where`) |
| whole branch | quality | Minor | `prefix_at_char_boundary` hand-rolls `floor_char_boundary`; `McpServer::connection_id` pub without a caller | fixed in c8c249a |
| whole branch | quality | Minor | Process-narrating comments; the unforgeability sentence repeated at seven sites; false "integration tests cannot share a module" comment | fixed in c8c249a (one full statement at `McpServer::connection_id`, pointers elsewhere; rig comment corrected) |
| whole branch | quality | Minor | Two tests duplicate others (`the_cli_viewer_reads_and_counts_every_origin`, `cap_client_label_huge_multibyte_name_is_cut_not_split`) | fixed in c8c249a (deleted) |
| whole branch | quality | Minor | About 400 further test lines "deletable", tests pinning marker text such as `[redacted]`, redundant assertions | accepted (orchestrator, 2026-10-30): each kept test failed under a targeted mutation in the tester run; marker text is pinned by one function, `scrub_text` |
| whole branch | quality | Minor | Test helper duplication in `mcp.rs` and the audit unit tests; the `/bus` rig copied a sixth time | accepted (orchestrator, 2026-10-30): AC24 forbids editing the donor tests, so copying is the price; migrating the six copies into `tests/support/` is a follow-up |
| whole branch | quality | Minor | `connection_id` computed twice per audited call | accepted: a ~40-byte allocation; spec reworded, no plumbing added |
| fix task | coder | open point | No sandbox test exercised the `fanout_role` role check after the `fanout_where` refactor | covered by `web_bus_push::agent_role_never_gets_operator_only_pushes`, run in the Terminal panel in the final gate |

### Round 2 (merged tree: main at 840e520, branch head f93ddd8 before the round-2 fixes)

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|
| merge | orchestrator | Important | PR 171 (two-lane fair ring, `web-bridge` label, sanitiser), PR 166 (pause revokes grants), PR 162 and PR 173 landed on main in the same files: six files conflicted, spec D2 became redundant, and D3 contradicted five PR 166 tests | handled by spec and plan Amendment 1 (R1 to R5); merge commits de4c065 and e8a8cf3; the two open questions (D3 against PR 166, port of the whitespace fix) took their defaults under the autonomy rule |
| R1 | coder | Minor | Spec A6's stated red for AC11 (mutate ingestion only) is wrong: the server re-sanitises at consumption | fixed in 26ecfbd (spec says both points must be mutated) |
| R1 | coder | Minor | `revoke_push_policy_table_and_resume` stays green under the `fanout_audit` mutation | accepted (orchestrator): its loop now uses an agent-origin fixture and its paused leg already expects a marker; the filter is pinned by AC12, AC30 and four other amended tests |
| R1 | coder | Minor | Two of our own tests failed after the merge and were amended minimally: `serve_lines_sanitises_a_hostile_client_name_and_survives_malformed_ones` (PR 171 deletes controls instead of writing `?`) and `a_refused_subscribe_is_audited_under_its_callers_id_and_fanned_by_role` (PR 166 mutes agent pushes under Paused) | accepted (orchestrator): forced by main's behaviour, assertions as strong as before |
| merge | orchestrator | Minor | PR 173 added `WebState.bad_token_throttle`; `web_bus_audit_identity.rs` no longer compiled after the merge | fixed in ca81356 by a one-line edit made by the orchestrator, not a coder (the same line PR 173 added to seven donor test files); noted as outside a task |
| R5 | orchestrator | Important, not ours | `neg/test_nonexistent_flow_error.py` fails at `flow.detail of the REAL flow is byte-identical`: the real flow gains `marks: [missing-nosniff, version-disclosure]` from the bundled detection scripts of PR 169 | not fixed here (plan R5: do not fix main); the identical failure was reproduced on plain `origin/main` 840e520 in a throwaway worktree (since removed); follow-up for the owner of PR 169; the AC23 edit `op or rd` remains correct |
| whole branch | tester | Minor | Gaps on the merged surface: the file sink path of the durable log, a fair-share bucket keyed by id, `exclude_self` for trusted callers, a visible line gapping a paused agent, U+2029 and `\r \v \f`, both-lane combinations | fixed in f93ddd8 (9 tests, each killed a mutant nothing else caught) |
| whole branch | spec | Important (docs only) | The plan's Shipped section still described the retired 128-byte label cap and a U+2028 gap that R2 closed | fixed: Shipped rewritten below |
| whole branch | spec | Minor | AC24, AC25 and R5 fences used base 0d50cf4 after main moved to 840e520; the second merge was recorded nowhere | fixed in the round-2 fix commit (merge-base recipe, `--diff-algorithm=patience` note, "merged twice" line) |
| whole branch | spec | Minor | Unmarked stale statements in the plan and spec; post-merge deviations unrecorded | markers added in the round-2 fix commit; deviations recorded in the R1 and merge rows above |
| whole branch | security | Minor | Eviction timing channel: the filter is read-side only, so a hidden operator evidence-lane entry still evicts the fullest bucket; an agent that fills the lane with its own failing calls can watch its entries vanish and learn the count and timing (not ids, commands or arguments) of operator write, sensitive, refused or failed calls | accepted (orchestrator) for this PR; spec A4, contract note 6, A8 N3 and R7 now state the measured channel; follow-up: choose the eviction victim within the inserting entry's own visibility class first (changes PR 171's fair-share semantics, needs its own spec) |
| whole branch | security | Minor | Four unamended PR 166 tests' Paused audit leg passes because the operator line is hidden, not because of the mute | fixed in the round-2 fix commit as docs and assertion messages only (the covering tests `a_visible_agent_line_gaps_a_paused_agent_a_hidden_one_does_not_and_trusted_control_is_never_muted` and `a_hidden_audit_line_neither_reaches_nor_gaps_a_paused_agent` are named); accepted that those legs now assert hiddenness |
| whole branch | quality | Minor | `AuditRing::count_since` pub and unfiltered with test-only callers | fixed in the round-2 fix commit (`#[cfg(test)]`, delegates to `count_since_for`) |
| whole branch | quality | Minor | Docs and comments the merge made false | fixed in the round-2 fix commit |
| whole branch | quality | Minor | Parallel test helpers beside main's | partly fixed (local closures, `entry_at_ms`); rest accepted (orchestrator): the donor test file stays frozen, the durable test keeps its own rig |
| whole branch | quality | Minor | Deletable tests | partly fixed: two earlier tests deleted after the later two-lane tests were shown to kill the same four mutants, the durable test trimmed; the ctx builder test and the `serve_lines` sanitiser wiring test kept |
| whole branch | quality | Minor | Process narration in test files | fixed for the files this branch added; the remaining plan-id headers in `mcp.rs`, one `audit.rs` test comment and `(Task 8)` in the `agent.rs` module doc are in files the branch did not add and are left (cheap follow-up) |
| whole branch | quality | Minor | Literals that depend on call history; one 100-character test name | accepted (orchestrator) |

Acceptances marked "orchestrator" were made under Matt's standing autonomous-approval rule and are listed in the PR so Matt can overrule any of them.

## Shipped

**What merged:** a server-minted opaque `connection_id` (`conn_<16 hex salt>-<ordinal>`, null when there is no streaming connection) on every audit entry (ring, `notifications/aitm/agent`, `agent.activity`, durable JSONL) and on the `initialize` result next to `role`; audit entries of trusted-control origin hidden from agent-role viewers on push, on `agent.activity` and in the count, through one predicate `AuditEntry::visible_to` applied read-side over PR 171's two-lane ring (a hidden line neither reaches nor gap-marks a paused agent); an optional `agent.status {exclude_self}` keyed on the caller's server-assigned id; and one fix to PR 171's `sanitize_client_label` (whitespace controls become a blank so `Bearer<TAB>token` is still masked). Server and tests only, nothing under `apps/`. The client-label bound is PR 171's (64 characters, `web-bridge` for bridge connections): this change's own cap was retired by the merge (spec Amendment 1, A2).

**What was cut or left out:** our own `client_label` cap (D2, superseded by PR 171); attributing HTTP POST and embedded-TUI calls to a connection (they carry null); wiring `with_durable_audit` in production; making `actions_last_minute` agent-origin only for everyone (spec OQ2).

**Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and the full `cargo test` pass on the merged tree; `python3 tests/e2e/run.py --shared-core web audit neg` is 13 pass, 0 skip, 1 fail, the one failure being `neg/test_nonexistent_flow_error.py`, which fails identically on plain `origin/main` (bundled scripts of PR 169 mark the flow). Panel round 2 (security, quality, spec): no Critical findings; every Minor fixed or accepted above.

**Follow-ups (none is in this PR):**
1. `apps/web`: read `connection_id` from the `initialize` result, drop exactly its own background reads on `line.connection_id === bus.connectionId()` (the spec's wire-contract table lists what the UI may rely on), feature-detect `exclude_self` before sending it, and retire the origin-based same-token residual in `bus/noise.ts`. Because the UI's default link is the agent token, it will no longer receive operator-origin lines; the operator link shows them.
2. `neg/test_nonexistent_flow_error.py` is red on `main` since PR 169 (bundled detection scripts mark the test's real flow, so the byte-identical `flow.detail` check fails). It needs its own fix by the owner of PR 169, for example starting that core without the bundled catalogue or comparing everything but `meta.marks`.
3. Class-aware eviction (choose the victim among buckets of the inserting entry's own visibility class first) to close the eviction timing channel recorded in the security row above; changes PR 171's fair-share semantics, needs its own spec.
4. A `trust_gate_scan`-style tripwire that fails when `crates/*/src` calls the unfiltered `AuditRing::recent` from a role-facing path.
5. Move the copied loopback `/bus` rig into `crates/aitm/tests/support/` and migrate the six copies.
6. Regenerate `aitmproxy-plugin/docs/tool-reference.md` and refresh `docs/research/mcp-tool-catalog.txt`: both still quote the old `agent.status` and `agent.activity` descriptions.
7. Reword the remaining plan-id and `Task N` headers in `crates/aitm-mcp/tests/mcp.rs`, one `audit.rs` test comment and the `agent.rs` module doc.

## Amendment 1: reconciliation tasks

**Why.** Main moved from `2eae896` to `0d50cf4` (PR 171 audit ring and label sanitiser, PR 166 policy revocation, PR 162 TUI governance) and the orchestrator is merging it into this branch. The design is the spec's `## Amendment 1`. The merge stops with textual conflicts in six files; this section is five tasks that finish it. **Where a task above conflicts with this section, this section wins:** T3 and T8's `cap_client_label` call are dropped; T13's `client_label == null` check is `"web-bridge"` (R1 step 7); the label literals of T14 and T16 follow R4; T18's diff base is the merge base, `git merge-base HEAD origin/main` (R5). The branch was merged with main twice: first at `0d50cf4`, then at `840e520` (PR 173, which changed `apps/web` and `crates/aitm/src/web/`), so a fence measured against `0d50cf4` reads non-empty.

**Rules for R1-R5.**
- Read both sides of every hunk before editing: ours is `HEAD`, theirs is `git show origin/main:<path>`; `git diff --name-only --diff-filter=U` lists the six files. Touch only the files a task declares. Do not change main's behaviour beyond what a task names; a test of main's that fails for a reason not named here: stop and report.
- Sandbox versus Terminal as in the Conventions above. R1 is a merge resolution: the coder edits files and leaves the tree resolved and green; the orchestrator stages and commits the merge (git runs in the Terminal panel). R2 to R4 commit as `fix(<area>): R<n> - <title> (plan 2026-10-30-bus-audit-connection-id)` with the trailer; gate on exit status; no commit-body word starts with `#`.
- The `trust_gate_scan` trap of the Conventions holds for new `src` code and `src` tests: compare roles only through `assert_eq!` on lists or `origin_label`, never `==`, `matches!` or `if let` against `Frontend::Mcp`.

### Who touches what

| Task | Files | Depends on | Parallel with |
|---|---|---|---|
| R1 | `aitm-core/src/{audit,lib}.rs`, `aitm-mcp/src/{server,transport}.rs`, `aitm-plugins/src/agent.rs`, `aitm-mcp/tests/mcp.rs`, `aitm/tests/web_bus_audit_identity.rs` | the merge in progress | none |
| R2 | `aitm-core/src/audit.rs`, `aitm-mcp/tests/audit_integrity.rs` | R1 | R4 |
| R3 | `aitm-core/src/audit.rs`, `aitm-mcp/tests/mcp.rs` | R1, R2 (same `audit.rs`) | R4 |
| R4 | `tests/e2e/web/test_bus_push_ui_contract.py`, `tests/e2e/audit/test_audit_identity.py` | R1 | R2, R3 |
| R5 | none | R1 to R4 | none |

R1 cannot be split: the six files compile only together. Do it in the order below and check each crate before the next.

### R1: Resolve the six files, drop D2, amend the colliding tests

- **Satisfies:** AC1-AC4, AC6-AC18 on the merged tree; AC11 (retargeted), AC19, AC31 (spec A6).
- **Resolution, file by file** (A is ours, B is main's; hunks counted by `<<<<<<<` from the top):
  1. `crates/aitm-core/src/audit.rs`, 7 hunks. H1 module doc: keep B's `# Labels and reasons` and `# The ring keeps a fair, bounded record` sections and add A's viewer-filter and `connection_id` paragraph after them. H2 constants: B wins; A's `MAX_CLIENT_LABEL_BYTES` and `CLIENT_LABEL_SCRUB_WINDOW_BYTES` go. H3: B wins (`is_label_noise`, `sanitize_client_label`, `label_skeleton`, `reads_as_reserved`, `declared_client_label`, `AuditLane`, `lane_for`); A's `is_label_format_char`, `label_char`, `cap_client_label` go. H4: keep B's `append_in`, and rewrite B's `recent` body as `fn recent_where(&self, since: Option<SystemTime>, limit: Option<usize>, keep: impl Fn(&AuditEntry) -> bool) -> Vec<AuditEntry>` (add `.filter(|(_, e)| keep(e))` after the `since` filter and before `collect`; the sort by seq and the skip to `limit` stay); `recent(since, limit)` calls it with `|_| true` and keeps B's doc plus A's "unfiltered, in-process tests only" line; `recent_for(&self, viewer: Frontend, since: Option<SystemTime>, limit: Option<usize>) -> Vec<AuditEntry>` calls it with `|e| e.visible_to(viewer)` and keeps A's doc (the filter runs before `limit`). H5: keep B's `count_since(&self, since: SystemTime) -> usize` and A's `count_since_for(&self, viewer: Frontend, since: SystemTime, exclude_connection: Option<&str>) -> usize`, both through one private `fn count_where(&self, since: SystemTime, keep: impl Fn(&AuditEntry) -> bool) -> usize` over `state.evidence.entries().chain(state.routine.entries())` with `e.at >= since`; the `count_since` doc says no role-facing surface may call it. **[Amended in round 2: `count_where` is inlined into `count_since_for` and deleted, and `count_since` is `#[cfg(test)]`, `count_since_for(Frontend::Operator, since, None)`.]** H6 and H7 (tests): keep both sides' tests; delete A's 17 `cap_client_label_*` tests wherever they sit (they are spread outside the hunks too); keep A's `entry_of`, `entry_at_ms`, `at_ms`, `visible_to_matrix`, `recent_for_*`, `count_since_for_*`, `to_value_carries_connection_id`; add `connection_id: None` to B's helpers `entry` and `sourced`. If one of A's ring tests encoded single-deque behaviour, rewrite it to lane semantics and say so in the report.
  2. `crates/aitm-core/src/lib.rs`: B's export list; A's `cap_client_label` and `MAX_CLIENT_LABEL_BYTES` are not exported.
  3. `crates/aitm-mcp/src/transport.rs`, 2 hunks: B wins (`declared_client_label`, B's doc).
  4. `crates/aitm-mcp/src/server.rs`, 8 hunks. H1 and H2 (`ConnCtx` and `client_label` docs): B's text, keeping A's `conn_id` sentence (`0` means not a streaming connection; sole input of `McpServer::connection_id`), no mention of `cap_client_label`. H3 to H5 (`Subscriptions`): B's `fanout(wants, line, pushes_muted)`, `fanout_role`, `fanout_flow`, `fanout_state` win and A's `fanout_where` is deleted; keep A's role filter as `fn fanout_audit(&self, entry: &AuditEntry, line: &str, pushes_muted: &dyn Fn() -> bool)`, which is `self.fanout(&|sub| entry.visible_to(sub.role), line, pushes_muted)`, with a doc that `wants` runs before the mute accounting so a hidden line never gaps an agent. H6 (`record_audit` literal): both lines, `client_label: conn_audit_label(conn), connection_id: self.connection_id(conn),`. H7 (`push_agent` doc): B's mute paragraph plus one sentence on role visibility. H8: `self.subscriptions.fanout_audit(entry, &line, &|| self.agent_pushes_muted());`. The auto-merged `run_tool` block already has `conn_audit_label` and `with_connection_id`; leave it. The salt, the `initialize` echo and `connection_id()` are untouched.
  5. `crates/aitm-plugins/src/agent.rs`, 4 hunks: module doc: A's `exclude_self` sentence plus B's lane paragraph; `actions_last_minute` text, the `AgentActivity` doc and the `agent.activity` description exactly as spec A5 (B's wording, A's `trusted control` sentence, "at most"); the `agent.status` description keeps `trusted control`.
  6. `crates/aitm-mcp/tests/mcp.rs`, 3 hunks, each both-sides-appended at the file end: keep both blocks (no item name occurs on both sides; checked). Then: in `client_label_is_capped_at_ingestion` every 128 becomes 64; add `fn rv_audit_as_agent(srv: &McpServer)` beside `rv_audit` (a sinkless `Frontend::Mcp` `agent.status` through `call_as`, asserting `!is_refused`); amend the five tests of spec AC31 exactly as listed there, the renamed one being `revoke_push_real_verb_pause_then_resume_without_a_visible_push_has_no_marker`.
  7. `crates/aitm/tests/web_bus_audit_identity.rs`: the two bridge-line label assertions (ours `:501-503`, `:566`) expect `"web-bridge"` instead of null; fix their messages and the doc line that says null. AC18's in-process `client_label: None` literal stays.
- **Order and checks (sandbox unless marked).** (a) `cargo test -p aitm-core --lib audit::` and `cargo test -p aitm-core --test trust_gate_scan --test classifier_wildcard_free`. (b) `cargo check --workspace --all-targets`. (c) `cargo test -p aitm-ca`; `cargo test -p aitm-plugins --lib agent::tests`. (d) in-process `mcp.rs` subsets: `cargo test -p aitm-mcp --test mcp -- initialize_ audit_entries connection_ forged an_agent_subscriber agent_activity_ agent_status_ client_label_ command_host_ revoke_push_policy revoke_push_real_verb revoke_push_paused`. (e) **Terminal:** `cargo test -p aitm-core -p aitm-mcp -p aitm-plugins -p aitm-ca`, then `cargo test -p aitm --test web_bus_push --test web_bus_governance --test web_bus_ask_split --test web_bus_audit_label --test web_bus_audit_identity --test tui_mode_governance --test tui_mode_governance_live --test frontends`.
- **Red/green evidence.** The five amended `revoke_*` tests and `an_agent_subscriber_never_receives_operator_audit_lines` must go red when `fanout_audit`'s `wants` is temporarily `|_| true` and green when restored; the report quotes both runs and shows `server.rs` unchanged by the mutation afterwards. AC11's red is the mutation named in spec A6.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-core -p aitm-mcp -p aitm-plugins -p aitm-ca -p aitm --all-targets -- -D warnings`, plus (e).
- **Done when:** no conflict marker remains, (a) to (e) pass, the mutation evidence is in the report.

### R2: Port gap (a) into PR 171's sanitiser

- **Satisfies:** AC26, AC27. **Depends on:** R1.
- **Files:** `crates/aitm-core/src/audit.rs` (`sanitize_client_label`, about `:240` on main, and tests), `crates/aitm-mcp/tests/audit_integrity.rs` (one test).
- **Change.** In `sanitize_client_label(raw: &str) -> Option<String>` replace `.filter(|c| !is_label_noise(*c)).collect()` by a `.filter_map` that yields `Some(' ')` for a character that is noise and `char::is_whitespace`, `None` for any other noise character, `Some(c)` otherwise. Nothing else changes: not `is_label_noise`, not `declared_client_label`, not the redactor, not the two `trim()` calls or the 64-character cut. Update the doc comment: whitespace controls become one blank so `Bearer\tabc` keeps the blank the scrubber needs; every other noise character is dropped.
- **Test, red first.** Add `sanitize_client_label_masks_a_bearer_token_after_a_whitespace_control` and `sanitize_client_label_turns_whitespace_controls_into_a_blank` with the literals of spec AC26; run them on R1's code and quote the failure (`"agent Bearer\tabc123"` gives `Some("agent Bearerabc123")`, so `!s.contains("abc123")` fails). Then change the function, then make the five edits of AC27 (three in `audit.rs`, two literals in `audit_integrity.rs`) and no other edit to those tests.
- **Run (sandbox):** `cargo test -p aitm-core --lib audit::tests::sanitize`; `cargo test -p aitm-core --lib audit::`; `cargo test -p aitm-mcp --test audit_integrity a_directly_assigned_label`; `cargo test -p aitm-mcp --lib client_label_from_initialize` (main's `..._cleans_a_hostile_name` stays green unmodified).
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-core -p aitm-mcp --all-targets -- -D warnings && cargo test -p aitm-core --lib audit:: && cargo test -p aitm-mcp --test audit_integrity`.
- **Done when:** red shown, then green; the diff of main's tests is exactly the five literals. If Matt declines the port (spec A10 Q2) skip R2 and log gap (a) as accepted.

### R3: D3 over the lanes: pins for the filter, the order and the mute

- **Satisfies:** AC28, AC29, AC30. **Depends on:** R1, R2 (same `audit.rs`).
- **Files:** `crates/aitm-core/src/audit.rs` (tests only), `crates/aitm-mcp/tests/mcp.rs` (one test). The code landed in R1, so these are integration pins, green on arrival; their red is by mutation.
- **Tests (literals in spec A6):** in `audit.rs` `mod tests`, `the_viewer_filter_does_not_change_what_the_ring_keeps` (build entries with B's `sourced(origin, label, command)`, append through `AuditSink::append`) and `recent_for_and_count_since_for_span_both_lanes` (A's `entry_of(origin, connection_id, command)` through `append_in(AuditLane::..., ..)`); compare commands as lists. In `mcp.rs`, `a_hidden_audit_line_neither_reaches_nor_gaps_a_paused_agent` over `RvRig`, `rv_subscribe`, `rv_audit`, `rv_audit_as_agent`, `rv_assert_silent`, `rv_drain`.
- **Red by mutation** (apply, show the test failing, revert, show the source diff empty beyond R1): (i) in `recent_where` apply `limit` before `keep`: AC29's `recent_for(Mcp,None,Some(2))` fails; (ii) make `recent_for` call `recent`: AC28's `["m2","m3"]` fails; (iii) `fanout_audit`'s `wants` becomes `|_| true`: AC30 fails with `["marker","agent agent.status"]`.
- **Run (sandbox):** `cargo test -p aitm-core --lib audit::tests`; `cargo test -p aitm-mcp --test mcp -- a_hidden_audit_line`.
- **Gate:** `cargo fmt --check && cargo clippy -p aitm-core -p aitm-mcp --all-targets -- -D warnings`, both runs above, `cargo test -p aitm-core --test trust_gate_scan --test classifier_wildcard_free`.
- **Done when:** three tests pass, three mutation reds are quoted, no source change.

### R4: e2e alignment `[e2e]`

- **Satisfies:** AC20 and AC22 as amended. **Depends on:** R1.
- **Files:** `tests/e2e/web/test_bus_push_ui_contract.py`, `tests/e2e/audit/test_audit_identity.py`.
- **Change.** `test_bus_push_ui_contract.py`: every `client_label is None` / null check becomes `== "web-bridge"` (ours `:189`, `:261-263`, `:319-321`); reword the docstring (`:19, :29, :34`) and the comment at `:177-188`: since PR 171 the bridge labels every connection `web-bridge` (a path name, never `clientInfo.name`), and own-ness comes from `connection_id`; the re-`initialize` with `clientInfo.name == "aitm-web"` check asserts the label is still `"web-bridge"`, not `"aitm-web"`. `test_audit_identity.py`: `MAX_LABEL_BYTES = 128` becomes `MAX_LABEL_CHARS = 64` with its comment; the `"x" * 128` literal and the length checks and messages follow.
- **Run (Terminal: builds and binds loopback).** `cargo build -p aitm -p aitm-testtarget`. Red first, on the merged binary and the unedited files: `python3 tests/e2e/web/test_bus_push_ui_contract.py` must show `[FAIL]` at section 4 ("agent line client_label is null over /bus (got 'web-bridge')": a main regression since PR 171) and `python3 tests/e2e/audit/test_audit_identity.py` must fail its label-length check (64 against 128). Then edit; both exit 0.
- **Gate (Terminal):** `python3 tests/e2e/run.py --shared-core web audit`.
- **Done when:** red shown, then green.

### R5: Whole-branch verification (Terminal)

- **Satisfies:** AC24, AC25 (as amended) and every AC end to end. **Depends on:** R1 to R4. **Files:** none.
- **Steps and expected results.**
  1. `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test > $TMPDIR/gate.log 2>&1; echo $?` prints `0`. The known flake `rhai_e2e::script_cannot_escape_or_exceed_scope` may fail: rerun it alone and record both results.
  2. `cargo build -p aitm -p aitm-testtarget`, then `python3 tests/e2e/run.py --shared-core web audit neg` exits 0, summary `0 fail`, no `audit/*` or `neg/*` SKIP. A red outside the areas spec A8 N8 names: stop and report; do not fix main.
  3. AC25: `BASE=$(git merge-base HEAD origin/main)` (`840e520` at the round-2 review), then `git diff --stat $BASE..HEAD -- apps crates/aitm-tui crates/aitm/src/web crates/aitm-mcp/src/http.rs` is empty. Against `0d50cf4` it reads non-empty: PR 173, the second merge, changed `apps/web` and `crates/aitm/src/web/` on main.
  4. AC24: `git diff $BASE..HEAD -- crates/aitm/tests/web_bus_push.rs crates/aitm/tests/web_bus_governance.rs crates/aitm/tests/web_bus_ask_split.rs` is empty; `git diff --diff-algorithm=minimal $BASE..HEAD -- crates/aitm-mcp/tests crates/aitm-core/src/audit.rs | grep '^-[^-]'` prints only the edited lines named in spec AC27 and AC31 (three literal lines in `audit.rs`, two in `audit_integrity.rs`, the amended lines of the five `revoke_*` tests), the sanitiser's filter line, and doc-comment, comment and assertion-message text (the module doc, the `sanitize_client_label` and `count_since` docs in `audit.rs`; the doc of `a_directly_assigned_label_is_stripped_and_scrubbed_at_the_server`; and, from round 2, the helper docs and messages of `rv_audit`, four `revoke_push_*` tests and the `revoke_socket_paused_agent_*` test); print them and compare, since no other assertion or literal of main's may change. The default diff algorithm reports PR 166's moved test block as removed and re-added (about 200 lines), so it needs `--diff-algorithm=minimal` (or `patience`).
  5. Hand `0d50cf4..HEAD` plus the merge commit to the Tester (every AC maps to a test; the mutation reds of R1 and R3 are re-run), then to the three-reviewer panel (security, quality, spec) on the whole branch. The panel runs again because the merge changed the ring, the sanitiser, the push path and the tests it reviewed; the orchestrator adds Review-log rows for spec A2 (gap (a) disposition) and A4 (the nine amended tests).
- **Done when:** all five hold.

### Ambiguities found while reconciling

1. The brief counted about 25 `cap_client_label` tests; there are 17 (`cap_client_label_*` in `audit.rs`), and R1 removes all of them.
2. `AuditRing::count_since`, deleted by our panel as dead code, is restored because main's tests call it; it stays unfiltered and in-process only.
3. Whether R2's whitespace port touches PR 171's literals is the one place this plan edits another session's pinned behaviour on its own initiative; spec A10 Q2 gives the fallback.
