# Server-assigned connection id on audit lines, and the audit stream's trust boundary design

**Status:** approved (orchestrator, 2026-10-30, under Matt's standing autonomous-approval rule; the task named all four decisions as ours to make). OQ1 is the one call worth Matt's veto and is flagged in the PR; every other open point has a default. (Plan stage checked AC14, AC15, AC21 and AC22's literal counts against call order; all stand as written. A first-pass doubt about AC21's 6 was wrong: the operator's own `agent.activity` call is audited too.)
**Research inputs:** none new. Follow-up to `docs/superpowers/specs/2026-10-30-web-ui-bus-push-design.md` (D7 and its amendments, R2, the wire-facts table; plan Review log and Shipped follow-ups 1, 3, 7) and `docs/superpowers/specs/2026-10-30-web-bus-agent-governance-design.md` (PR #145: the web server shares the primary's `AuditRing` and policy; `Subscriptions`, `ParkedRequests`, `ConfirmTokens` and the `conn_id` counter stay per server). Reads: `crates/aitm-core/src/{audit.rs, ctx.rs, lib.rs}`, `crates/aitm-core/tests/{trust_gate_scan.rs, classifier_wildcard_free.rs}`, `crates/aitm-mcp/src/{server.rs, transport.rs, http.rs, json.rs}`, `crates/aitm/src/{tui.rs, web/bridge.rs}`, `crates/aitm-plugins/src/agent.rs`, `crates/aitm-ca/src/audit.rs`, `crates/aitm-mcp/tests/mcp.rs`, `crates/aitm/tests/{frontends.rs, web_bus_ask_split.rs, web_bus_governance.rs, web_bus_push.rs}`, `crates/aitm-tui/src/model.rs`, `apps/mac/Sources/**/{Activity.swift, BusService.swift, EmbeddedCore.swift}`, `apps/web/src/{bus/ws.ts, bus/noise.ts, bus/normalize.ts, shell/Sidebar.tsx, panels/AgentPanel.tsx}`, `tests/e2e/**`. All line numbers below were re-checked against `2eae896`.

## Intent

PR #157 made the web UI subscribe over `/bus`; its security review showed that a client-declared label can never decide "is this line mine", and the bridge labels nothing, so the UI's flood rule infers own-ness from `origin` and keeps a documented same-token second-client residual. This change finishes the server half. It (1) stamps every audit line with an opaque, server-assigned connection id the client can learn only about itself, so a client can drop exactly its own background reads; (2) caps the one client-declared string that flows into every audit surface, `client_label`, which today is unbounded and multiplied by the ring size; (3) stops an agent-role connection from reading the trusted principal's audit lines, on push and on pull alike; and (4) stops `agent.status.actions_last_minute` from counting the asker's own polling. Server only (`crates/`) plus the tests that pin it; the UI consumer is a separate PR, so this spec also fixes the wire contract that PR will read.

## Goals

- An audit line (push, `agent.activity`, durable JSONL) names the connection that made the call by an id the server minted, never by anything a client sent.
- A connection learns its own id from the `initialize` reply, before its first audited call.
- No two connections that ever shared an audit ring carry the same id, across the primary and web servers and across restarts.
- `client_label` is at most 128 bytes wherever it is stored or pushed, whatever the client sent.
- An agent-role caller never receives, by push, by `agent.activity`, or by count, an audit entry whose origin is trusted control (operator, CLI). Trusted-control callers see everything.
- `agent.status` can report the agent action rate without the asking connection's own calls.
- Every existing decoder of audit lines keeps working unchanged.

## Non-goals

- **Any change under `apps/`, `crates/aitm-tui`, `crates/aitm/src/web/` or `crates/aitm-mcp/src/http.rs`.** The web UI adopts the id in its own PR. The bridge needs no change: it already mints a non-zero `conn_id` (`bridge.rs:251-257`).
- **A new MCP tool.** Rejected in D1.
- Attributing Streamable-HTTP POST calls or the embedded TUI's calls to a connection. Both build a fresh `ConnCtx` with `conn_id == 0` per message (`http.rs:257-262`, `tui.rs:297`), so they carry `null`. See R3.
- Wiring `with_durable_audit` in production (nothing calls it; governance spec Design 6.5). The durable renderer is still kept in step (D1, AC17).
- Unifying `Subscriptions` or the `conn_id` counter across servers (the "unified agent hub" follow-up). The id must not wait for it.
- Filling `agent.status.connected_clients` (still `[]`, `agent.rs:142`).
- Changing what `actions_last_minute` means for a trusted-control caller beyond the exclusion in D4 (OQ2).
- The `approval_requested` push line (already role-routed, `server.rs:477`, `:1795`); it is not an audit entry and gets no id.
- The CPU amplification in `serve_lines`: for a connection that never declares a label, every message is parsed once by `client_label_from_initialize` (`transport.rs:82-86`) and again by `handle_on`. Noticed, out of scope.

## Anti-goals

- Any decision keyed on a client-declared value: `clientInfo.name`, a `_meta` field, an argument, a header. The id and the viewer role come only from state the transport built after authentication (`ConnCtx`).
- A line that carries someone else's id, or an id a client can make a line carry. A client may reach its own id and may read others'; it must not be able to write one.
- An id derived from the auth token, peer address or port. Nothing secret or network-identifying enters it.
- A filter applied to the push alone. `agent.activity` is the same ring, readable by any role (`agent.rs:219-224`), so a push-only filter is theater.
- An agent that stops seeing its own lines. Own lines are always visible to their author.
- `exclude_self` that can lower what any other connection sees or counts.
- Leaking a trusted-control connection's id to an agent-role viewer on the stream, in `agent.activity` or in the count. This is a visibility rule, not a secrecy guarantee: the id is the per-server `salt` plus the per-server ordinal, so an agent that reads its own id can compute the ids of lower-numbered connections on the same server. That is accepted: the id is not a secret and no tool, token or approval accepts it as input. Unforgeability rests on the server stamping the id from `ConnCtx`, not on its secrecy.
- A decoder (TUI, mac, web, e2e) that breaks because a key was added.

## Constraints

- **Additive wire changes only.** No field is removed or renamed. `client_label` stays, with a bounded value.
- **Deny by default, fail closed.** The visibility predicate delegates to `Frontend::is_trusted_control`; it never compares a role with `==` or matches `Frontend::Mcp` (`ctx.rs:57-77`; `trust_gate_scan.rs:11-14` rejects those shapes in any `crates/*/src` file). A viewer of an unknown future variant is gated as an agent.
- **No new dependency.** `uuid` is already an `aitm-mcp` dependency (`server.rs:609`).
- **Secrets stay out of every audit surface.** The id is minted from OS randomness and a counter, so it carries no secret; the label is scrubbed at ingestion (D2).
- **Memory stays bounded.** Worst case per ring slot is at most 64 bytes of id and 128 bytes of label, so 4096 slots hold under 1 MiB of identity. (Today a 16 MiB label times 4096 slots is 64 GiB: `server.rs:1634` clones it into every entry. See D2.)
- **Hot path.** One or two short `format!`s per audited streaming call (`connection_id` is computed once for the `CommandHost` and once for the audit entry, and once per streaming `initialize`) and one predicate call per subscriber per line, under the registry lock that `fanout_state` already holds (`server.rs:519-529`).
- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`, plus `python3 tests/e2e/run.py web audit neg`. Tests that bind loopback run from the Terminal panel.

## Facts the design rests on (verified at `2eae896`)

| Fact | Where |
|---|---|
| `ConnCtx {role, client_label, conn_id, out}`; `conn_id` is `0` for in-process `McpServer::handle`; `ConnCtx::new` gives `0` | `server.rs:81-111`, `:1230-1232` |
| `conn_id` comes from a per-server `AtomicU64` counter starting at 1, minted by `next_conn_id()` | `server.rs:896`, `:1004-1006` |
| `conn_id` is minted for TCP/stdio in `serve_lines`, for the bridge in `relay`, and for the HTTP SSE GET lane; **HTTP POST never uses it** (`ConnCtx::new(Frontend::Mcp)` per message, so `0`) | `transport.rs:56-58`, `bridge.rs:252-257`, `http.rs:290`, `:257-262` |
| `conn_id` also keys subscriptions and confirm tokens, so its meaning must not change | `server.rs:393-403`, `:546-600` |
| Two servers sharing one ring each count from 1: `web_bus_ask_split.rs` literally gives the operator `conn_id: 1` on both the primary and the web server | `web_bus_ask_split.rs:149-153`; ring sharing at `tui.rs:184-193` |
| `AuditEntry {at, origin, client_label, command, args_summary, result}`; `to_value` renders keys `at, origin, client_label, command, args, result` | `audit.rs:44-58`, `:73-101` |
| `record_audit` builds the entry with `client_label: conn.client_label.clone()` and appends to ring, durable sink, and `push_agent` | `server.rs:1631-1643` |
| `push_agent` renders `to_value` and calls `fanout_state`, which sends to **every** subscribed connection of any role, once each | `server.rs:1650-1658`, `:517-529` |
| Subscriptions already carry the subscriber's role (`Subscription.role`), and `fanout_role` already routes by it | `server.rs:393-403`, `:477-487` |
| The durable JSONL is **not** rendered by `to_value`: `aitm-ca` has a second hand-written renderer with its own key list | `aitm-ca/src/audit.rs:166-208`; test compares only against that renderer (`aitm-ca/tests/audit.rs:174-180`) |
| `with_durable_audit` has no production caller | `server.rs:925` and no other `crates/**/src` call |
| `initialize` answers `{protocolVersion, role, capabilities, serverInfo}`; `role` is top-level, additive | `server.rs:1288-1312` |
| The UI reads `role` from the `initialize` result before it subscribes and before it marks the bus open | `ws.ts:202-218` |
| The only production writer of `ConnCtx.client_label` is `serve_lines`, which copies any non-empty `clientInfo.name` of the first `initialize`; the bridge and HTTP never set it | `transport.rs:80-86`, `:139-148`; `bridge.rs:254`; `http.rs:258` |
| Consumers of the label: every audit entry and pushed line, `CommandHost::with_client_label` (findings recorder, PoC runner), and `scrub_text` is applied only when findings are persisted | `server.rs:1564-1567`, `aitm-findings/src/commands.rs:472`, `aitm-poc/src/runner.rs:496`, `aitm-findings/src/store.rs:84-90` |
| `agent.status` ignores its host and counts every ring entry of the last minute, of **any origin**; `agent.activity` returns `ring.recent(since, limit)` unfiltered; both take no role into account | `agent.rs:129-144`, `:265-283`; `audit.rs:155-174` |
| `CommandHost` already carries `frontend` and `client_label`; there is no connection id | `ctx.rs:224-236`, `:348-356` |
| An unknown tool argument is `INVALID_PARAMS` | `json.rs:130-132` |
| `agent.status`'s input schema is not in any pinned snapshot (`OPERATOR_TOOLS` omits it); only the tool *name* is pinned | `frontends.rs:25`, `:99-117` |
| mac counts agent-origin entries client-side for its badge; the web Sidebar badge and the Agent panel both render the same store value | `Activity.swift:166-170`; `Sidebar.tsx:199`, `AgentPanel.tsx:49` |

## Design

### D1. The connection id

**Name and shape (Architect's call).** The wire name is `connection_id`: a string, or `null` when the call did not come over a streaming connection. It is **opaque**: a client compares it for equality and nothing else. The shape is `conn_<16 lowercase hex>-<decimal>`, for example `conn_9f2c41b07a3e5d68-3`, at most 64 bytes of printable ASCII. The builder may change the rendering inside those limits; the e2e tests pin only "non-empty string, at most 64 bytes".

**How it is minted (Architect's call).** The id is a pure function of two server-held values: a per-`McpServer` random 64-bit salt drawn once in `McpServer::new` (from `uuid::Uuid::new_v4`), and the connection's existing `conn_id`. `McpServer::connection_id(&self, conn: &ConnCtx) -> Option<String>` returns `None` when `conn.conn_id == 0` and the rendering otherwise. It is called in three places: `dispatch("initialize")` (echoes it), the `CommandHost` build in `run_tool` (so a command can read it), and `record_audit` (stamps the entry). Nothing a client sends is read into it.

- *Why not the raw counter.* It collides: each server counts from 1, and since #145 the primary and the web server share one ring, so "operator, conn 1" exists on both (`web_bus_ask_split.rs:149-153`). That is not only a correctness bug but a forgery path: an agent can read the UI's id from `agent.activity`, open connections on the *other* server until its own counter reaches that value, and have its lines carry the UI's id, hiding them from the UI's noise rule. The counter also restarts at 1, so it is ambiguous in a durable log. The salt closes both.
- *Why no new `ConnCtx` field.* A stored random id would need a field on a struct that seven sites build by literal (`bridge.rs:252`; `mcp.rs:1651, 3115, 3179, 3318, 3347, 4073`; `web_bus_ask_split.rs:149`) and a mint call in every transport; one that forgets mints nothing and the line goes unattributed. Deriving it from the `conn_id` every transport already sets leaves nothing to forget, and `conn_id` keeps its job as the subscription and confirm-token key unchanged. The salt is a new field on `McpServer`: three places (`server.rs` struct, `new`, and the destructure/rebuild in `serve`, which fails to compile if one is missed).
- *Why not a process-global counter.* It would change the semantics of the key the registry uses and entangle this change with the unified-hub follow-up.

**Where it lives.** `AuditEntry` gains `pub connection_id: Option<String>`. `to_value` always emits the key (`Value::Str` or `Value::Null`), like `client_label`, so every surface keeps one shape. The new key appears in: the `notifications/aitm/agent` params, every `agent.activity` entry, and the durable JSONL. `aitm-ca`'s `entry_to_jsonl` is a separate renderer and is edited too; a parity test pins the two key sets together (AC17). `AuditEntry` is built by literal at three sites (`server.rs:1631`, `aitm-ca/tests/audit.rs:136`, `aitm-core/src/audit.rs:208`), each gains the field.

**What carries `null`.** Calls with `conn_id == 0`: in-process `McpServer::handle`, Streamable-HTTP POST, and the embedded TUI's per-line `ConnCtx`. `null` means "not attributable to a connection". A consumer must treat it as "not mine"; it never matches an own id.

**How the client learns its id (decided; alternatives rejected).** An additive top-level field on the `initialize` result, beside `role`: `connection_id: string | null` (`server.rs:1288-1312`; never inside `serverInfo`). `initialize` is the first request on every connection, is not a `tools/call` (never audited), and the UI already awaits it and reads `role` before it subscribes (`ws.ts:202-218`), so every audited line of the connection arrives after its id is known. A repeated `initialize` returns the same id.
- *A field on the `flow.subscribe` result:* rejected. The subscribe is refusable (an agent under `Paused`, `read_refusal`), swallowed on failure and timed out in the UI, absent on an older core, and never sent by non-subscribing clients; own-ness would depend on a call that can fail, and a refusal line would carry an id its client never received.
- *A new tool* (for example `connection.whoami`): rejected. `tools/list` is pinned by name (`frontends.rs:25` and the `ac7_exact_tool_set` test), so it ripples into the pin, the mac and TUI tool fixtures, the web mock and the docs catalog; it would itself be audited and refused under `Paused`, so it fails the "known before the first audited call" property.
- *A hello notification:* rejected. Only subscribed streaming connections have a sink, and under load the drop-oldest lane could drop the hello (`server.rs:32`).
- *A WebSocket upgrade header:* rejected. Bridge only; the TCP and stdio transports could not use it.

**Threat model.** Anyone with the token can see every id on the stream they are allowed to see (D3) and in `agent.activity`; they cannot make a line carry an id other than their own connection's, because the id is stamped from `ConnCtx`, which the transport builds after authentication and which no request field reaches. A visible id grants nothing: no tool, token or approval accepts it as input. An attacker can open more connections, but each carries its own fresh id and none carries the UI's, so none can hide behind the UI's noise rule. The id leaks the per-server connection ordinal, a count of connections since start, which is accepted (R7). Not covered: a script that drives the UI's own socket (script injection in the page) emits lines under the UI's id; the UI's rule only drops successful background reads, never writes or errors, which is the same boundary the UI already is.

**Exposure by role.** `initialize` returns only the caller's own id to the caller. Under D3 an agent-role viewer receives only non-trusted-control lines, so it never sees an operator or CLI connection's id; operator viewers see all ids. No tool lists connection ids.

The id is not a secret, and this section does not make it one. It is the per-server `salt` plus the per-server ordinal, so an agent that reads its own id can compute the ids of lower-numbered connections on the same server, an operator's included. That is accepted: no tool, token or approval accepts an id as input, so knowing one grants nothing. Unforgeability rests on the server stamping the id from `ConnCtx`, not on its secrecy (R7).

### D2. Cap and sanitize `client_label` at ingestion

**Truncate, never refuse (Architect's call).** Refusing the `initialize` would break any client with a long name and would not save the parse work already spent on a message of up to 16 MiB (`transport.rs:22`); truncating keeps compatibility and bounds memory. It is a real memory bug, not hygiene: `record_audit` clones the label into each entry (`server.rs:1634`), so a 16 MiB name times the 4096-entry ring is 64 GiB reachable with one token and 4096 cheap reads.

**One function, one call site.** `aitm_core::cap_client_label(name: &str) -> Option<String>` (in `audit.rs`, re-exported from `lib.rs`) with `pub const MAX_CLIENT_LABEL_BYTES: usize = 128`. In order: replace the whitespace controls (`\t \n \r \x0B \x0C`, U+0085) with one ASCII space and every other control character, and every bidi, zero-width or byte-order-mark format character (U+061C, U+200B-U+200F, U+202A-U+202E, U+2060-U+2064, U+2066-U+2069, U+FEFF; std has no `is_format`, so the list is explicit), with `?` (a name is rendered in TUI and mac tables and written to logs, an ANSI escape must not drive the operator's terminal, and a bidi override must not reorder a table cell; Architect's call, OQ3). Whitespace controls become a space, not `?`, because the scrubber's `\s` patterns need real whitespace (`Bearer\tabc123`, `token\t=abc123`, `password\n: hunter2` would otherwise slip past it as `Bearer?abc123`) and no newline may remain for a `.+` pattern to stop at; cut to a work-bounding window of 512 bytes at a char boundary; run `redact::scrub_text` over that window so a name like `agent token=abc123` is masked in the ring, the push and the durable log (today only the findings store scrubs it, `store.rs:90`; Architect's call, OQ3); then cut the scrubbed text at the last char boundary at or below 128 bytes, with no ellipsis; return `None` if the input was empty. The final cut comes **after** the scrub because masking lengthens text (`token=a,` is 8 bytes, `token=[redacted],` is 17), so cutting first could leave a result over 128 bytes; scrubbing a 512-byte window instead of the whole message keeps the work bounded, and a secret that starts inside the first 128 output bytes always starts inside the window. `client_label_from_initialize` (`transport.rs:141-148`) calls it, and that is the only ingestion point: the bridge and HTTP never set a label (`bridge.rs:254`, `http.rs:258`) and the bridge keeps **not** copying `clientInfo.name`. The consumers read the capped value through `conn.client_label`, so the findings recorder, `CommandHost::with_client_label`, the PoC runner and the audit entry are all covered by the one cut. A doc comment on `ConnCtx.client_label` says it must be set only through `cap_client_label`; a future transport that bypasses it is the residual (R9).

### D3. Role-filter the audit stream: yes, on push, pull and count (Architect's call; OQ1)

**Decision.** One predicate in `aitm-core`, `AuditEntry::visible_to(&self, viewer: Frontend) -> bool`: `viewer.is_trusted_control() || !self.origin.is_trusted_control()`. A trusted-control viewer (Operator, Cli) sees every entry; any other viewer sees only entries whose origin is not trusted control, which always includes its own. It delegates to the one trust predicate and never compares a role, so a new `Frontend` variant is classified once in `CallerTrust::from` and gated here automatically.

Applied at three places, because the ring is one object and a partial filter leaks through the others:
1. **Push.** `push_agent` (`server.rs:1650`) sends the line only to subscriptions whose role satisfies `entry.visible_to(role)`; the line is rendered once. The filter lives inside `push_agent`, which is `pub`, so every caller is covered. `push_state` and `approval_requested` are unchanged.
2. **Pull.** `agent.activity` calls a new `AuditRing::recent_for(viewer, since, limit)` that applies the predicate **before** `limit`, so an agent asking for the last N gets N visible entries rather than fewer. The caller's role is `host.frontend()`; a `CommandHost` that was never given a frontend defaults to the agent role (`ctx.rs:256-258`), which fails closed.
3. **Count.** `agent.status` uses `AuditRing::count_since_for(viewer, since, exclude)` (D4). With `exclude = None`, `actions_last_minute` equals the number of entries `agent.activity {since: now - 60 s}` would return to the same caller.

The unfiltered `recent` and `count_since` stay (the in-process tests and `tui.rs` tests read the ring directly, and the durable sink must keep the full record) with doc comments saying no surface a role reads may use them. The durable JSONL and the ring itself are never filtered.

**Why filter.** The agent token is the *untrusted* principal: it drives hostile web content through this proxy and may be prompt-injected. An operator-origin line carries what the human is doing: hosts and URLs (`scope.add`, `browser.navigate`, `request.send`), flow ids and file paths (`flow.export`, `poc.run`), policy changes, approvals, each redacted by key and content but still target-revealing. Letting the agent read that is cross-principal disclosure with no legitimate use, and there is a precedent: `approval_requested` is already operator-only (`server.rs:1795`). Agent-to-agent visibility is kept (same trust class).

**What it costs, said plainly.**
- The default `aitm web` link is the agent token (governance spec Design 6.3), so its Activity panel stops showing operator-origin lines made by other surfaces (the mac app and a CLI on the primary, an operator-token browser tab). Today those reach it only in the bootstrap `agent.activity` snapshot (since #145) and, for calls over `/bus`, by push; `Subscriptions` is per server, so primary-transport lines never reached the web push. It still shows everything agents did, including itself. **That is the right outcome:** the agent-token page is the agent's view by definition. To see the whole session an operator uses the operator link (`web UI (operator): …&expect=operator`, which exists when `mcp.operator_token` is configured, `web/mod.rs:196-201`).
- It narrows an M4 contract: `agent.activity` "readable by any role" (D3a.4, `agent.rs:13-14`, `:219-224`) stays callable by any role but returns less to a non-trusted one. The schema descriptions say so.
- The mac app on an external core without a pasted operator token (`BusService.swift:248-256`) is an agent and loses operator rows; the embedded core uses an operator token (`EmbeddedCore.swift:152`) and is unaffected. Its badge counts agent-origin entries client-side (`Activity.swift:166-170`) and is unaffected.

**Casualties found by grep and their disposition.**
- `tests/e2e/neg/test_nonexistent_flow_error.py:408-421, :552-554`: the reader is the **agent** connection under `auto`/`all`/`ask`/`readonly`, and the ground-truth leg asserts `origin == "operator"` entries for the operator's `flow.export`. Under D3 an agent cannot read those, so the test reads the audit through `op or rd` (AC23). One-line change to the test, no change to what it proves.
- Everything else reads as an operator, or asserts only agent-origin entries, or only the connection's own: `tests/e2e/audit/test_audit_log.py` (`rd = op or ag`, entries are the agent's or read by the operator), `neg/test_bad_params_error.py`, `neg/test_unknown_tool_error.py`, `scope/test_scope_remove_clear.py`, `crates/aitm/tests/web_bus_governance.rs:442-470` (operator reader), `web_bus_push.rs:768-775` (the connection's own lines), `mcp.rs:3115-3160` and `:1796-1812` (operator watchers; a refused subscribe is visible to its own author).

### D4. `agent.status.actions_last_minute`: exclude the asker's own connection, on request (Architect's call)

**The defect.** The count covers every ring entry of any origin (`agent.rs:129-144`). The web UI polls on the agent token, so its own `flow.list`/`proxy.status` polling (about 130 calls a minute) reads as agent activity. Candidates, evaluated:
- *Count by role (agent-origin only).* Rejected as the fix. The UI's polling **is** agent-origin on the default link, so a role count cannot separate it from a real agent; it would also change the number for every operator surface (mac already computes agent-only client-side, so the server's all-origin meaning is a pre-existing inconsistency, OQ2).
- *Client-side derivation from entries that now carry the id.* Rejected. It makes a second definition of the number (the UI's log is capped at 500, filtered and lossy on `lagged`), needs a minute of lines the UI does not fetch, and helps no other consumer.
- *Record why not.* Rejected: the defect is user-visible and the fix is small.
- **Chosen: an optional `exclude_self` boolean on `agent.status`**, default `false`. When `true`, entries whose `connection_id` equals the caller's own are not counted. With no own id (an in-process caller) it excludes nothing, so it can only err toward counting more. It cannot hide anything from anyone else: it changes only the number the caller itself receives, and the exclusion is keyed on the caller's server-assigned id, not on a label. The count is also viewer-filtered (D3).

**Plumbing (PR #63 seam).** `CommandHost` gains `connection_id: Option<String>`, `with_connection_id(impl Into<String>)` and `connection_id() -> Option<&str>`, beside `client_label` (`ctx.rs:348-356`). `run_tool` sets it from `McpServer::connection_id(conn)` where it builds the host (`server.rs:1548-1567`). `AgentStatus::invoke` reads `host.frontend()` and `host.connection_id()`. The role is not read from the label, ever.

**Ripple of the schema change** (`params: []` becomes one optional boolean): `tools/list` input schema for `agent.status` (no pinned snapshot contains it; `frontends.rs:99-117` omits it; the tool name stays); the `agent.status` and `agent.activity` description strings; `docs/research/mcp-tool-catalog.txt` (a doc, not pinned: refresh by hand or leave); the tool fixtures in `crates/aitm-tui/fixtures/bus-fixture.json:60` and `apps/mac/.../Fixtures+Tools.swift` (fixtures, not compared with the real core; left); `apps/web/src/bus/mock.ts:708` (UI PR). An older core rejects the unknown argument with `-32602` (`json.rs:130-132`), so a client must feature-detect (below).

### Wire contract for the UI consumer (apps/web, separate PR)

| Surface | Before | After |
|---|---|---|
| `initialize` result | `{protocolVersion, role, capabilities, serverInfo}` | adds top-level `connection_id: string \| null` |
| audit line (`notifications/aitm/agent` params) and `agent.activity` entry | `{at, origin, client_label, command, args, result}` | adds `connection_id: string \| null`; for an agent-role viewer, trusted-control entries are absent |
| `client_label` | any length, as declared | at most 128 bytes, control characters `?`, scrubbed; still `null` on every `/bus` line |
| `agent.status` | `{}` -> `{policy, actions_last_minute, connected_clients}` | optional `{exclude_self: boolean}`; the count is viewer-filtered |

What the UI may rely on: (1) `initialize` is answered before any audited call of that connection, so read `connection_id` where `role` is read (`ws.ts:209`) and before `setState('open')`. (2) Compare for equality only; `null` and an absent key never match; ids are never reused within a process or across restarts. (3) One id per socket: clear it on close and re-read it after reconnect; trailing lines from the previous socket carry the old id and may be dropped by remembering the ids used in the page session. (4) Own-ness becomes `line.connection_id != null && line.connection_id === bus.connectionId()`, combined with the existing command filter (successful background reads): the id answers whose, the set answers which. (5) Feature detection: no `connection_id` key in the `initialize` result means an older core, so keep the origin-based rule; send `exclude_self` only when `tools/list` shows `agent.status` `inputSchema.properties.exclude_self`, because a refused call would leave the badge un-updated (`refreshSide` swallows errors). (6) An agent-role page sees an agent view, and no line or field marks what is hidden. An agent can still infer the volume of hidden entries from its own old entries aging out of the shared ring sooner than its own call rate explains; the content stays hidden.

## Acceptance criteria

Tests are named by file and function. Each is written red first; the line after the criterion says what fails before the change. `[socket]` and `[e2e]` need the Terminal panel; the rest run in the sandbox.

*aitm-core (`crates/aitm-core/src/audit.rs`, `#[cfg(test)] mod tests`)*

1. AC1: `to_value_carries_connection_id`: an entry with `connection_id: Some("conn_ab-1")` renders `to_value()["connection_id"] == Value::Str("conn_ab-1")`; with `None` it renders `Value::Null`; the key set is exactly `{args, at, client_label, command, connection_id, origin, result}` (7 keys). Red: the field does not exist.
2. AC2: `visible_to_matrix`: for every pair, `entry(origin).visible_to(viewer)` is, in the order (Cli, Operator, Mcp) of origins for viewers Cli, Operator, Mcp: Cli viewer `[true, true, true]`, Operator viewer `[true, true, true]`, Mcp viewer `[false, false, true]`. Red: no predicate.
3. AC3: `recent_for_applies_the_limit_after_the_filter`: a ring holding, oldest first, `op1 (Operator), ag1 (Mcp), op2 (Operator), ag2 (Mcp), op3 (Operator)`: `recent_for(Mcp, None, Some(2))` commands are `["ag1","ag2"]`; `recent_for(Operator, None, Some(2))` are `["ag2","op3"]`; `recent_for(Mcp, None, None)` are `["ag1","ag2"]`. Red: no method.
4. AC4: `count_since_for_filters_and_excludes`: a ring of 3 entries (Mcp, `connection_id` "A"), 2 (Mcp, "B"), 4 (Operator, "O"), 1 (Mcp, `None`), all at or after `t0`: `count_since_for(Mcp, t0, None) == 6`; `(Mcp, t0, Some("A")) == 3`; `(Mcp, t0, Some("nope")) == 6`; `(Operator, t0, None) == 10`; `(Operator, t0, Some("O")) == 6`. Red: no method.
5. AC5: `cap_client_label_*`: `"x".repeat(300)` gives 128 bytes; `"é".repeat(100)` gives 128 bytes (64 chars); `"€".repeat(50)` gives 126 bytes (42 chars, boundary-safe); `"aitm-mac"` is unchanged; `"a\u{1b}[31mred"` gives `"a?[31mred"`; `"agent Bearer\tabc123"`, `"agent token\t=abc123"` and `"password\n: hunter2"` are masked (each contains `[redacted]` and not `abc123` / `hunter2`), and `"a\tb\nc"` gives `"a b c"`, with no newline left in any result; `"\u{202E}gnp.exe"` gives `"?gnp.exe"`, `"aitm\u{200B}-mac"` gives `"aitm?-mac"`, and `"naïve-é-€"` is unchanged (tests `cap_client_label_whitespace_controls_become_a_space`, `cap_client_label_scrubs_a_bearer_token_after_a_tab`, `cap_client_label_scrubs_a_token_pair_with_a_tab_before_the_separator`, `cap_client_label_scrubs_a_password_pair_with_a_newline_before_the_separator`, `cap_client_label_format_characters_become_question_marks`, `cap_client_label_leaves_a_clean_multibyte_name`); `"agent token=abc123"` contains `token=[redacted]` and not `abc123`; `"token=a,".repeat(40)` (320 bytes, which masking would lengthen) gives a result of at most 128 bytes; `""` gives `None`. Red: no function.
6. AC6: `cargo test -p aitm-core --test trust_gate_scan --test classifier_wildcard_free` stays green with `visible_to` present (it uses `is_trusted_control` only).

*aitm-mcp (`crates/aitm-mcp/tests/mcp.rs`)*

7. AC7: `initialize_echoes_connection_id`: for a connection `ConnCtx { conn_id: srv.next_conn_id(), .. }` the `initialize` result has a top-level `connection_id` that is a non-empty string of at most 64 bytes, equal across two `initialize` calls on the connection, different for a second connection of the same server, and `result.serverInfo.connection_id` is null; `initialize_connection_id_is_null_without_a_connection`: `ConnCtx::new(Operator)` gives `result["connection_id"] == null` with the key present. Red: key absent.
8. AC8: `audit_entries_carry_the_connections_id`: connections A and B (Mcp, minted ids) each call `demo.read`; `ring.recent(None,None)` entry 0 has `connection_id == Some(A's initialize id)`, entry 1 `Some(B's)`, and they differ; a call on `ConnCtx::new(Mcp)` records `connection_id == None`; the line pushed to an operator watcher has `params.connection_id` equal to the ring entry's. Red: field absent.
9. AC9: `connection_ids_are_distinct_across_servers`: two `McpServer`s built fresh, each `next_conn_id() == 1`, give different `initialize` ids for that connection. Red against the raw counter (equal).
10. AC10: `forged_claims_never_change_the_connection_id`: `initialize` with params `{"clientInfo":{"name":"conn_victim","connection_id":"conn_victim"},"_meta":{"connection_id":"conn_victim"},"connection_id":"conn_victim"}` returns an id different from `"conn_victim"` and equal to the one a plain `initialize` returns; the connection's later entries carry that id. Red: `connection_id` is absent from the result, so the first assertion fails.
11. AC11: `client_label_is_capped_at_ingestion`: through `serve_lines` over `tokio::io::duplex` (the rig at `mcp.rs:~1100`), an `initialize` whose `clientInfo.name` is `"a".repeat(1 << 20)` followed by `demo.client` makes `demo.client` return `"a".repeat(128)`, and the audit entry's `client_label` has length 128. Red: 1048576.
12. AC12: `an_agent_subscriber_never_receives_operator_audit_lines`: an operator watcher O and an agent watcher G (both subscribed) on one server; O runs `demo.read`, then G runs `demo.read`; O's sink holds 2 `notifications/aitm/agent` lines with origins `["operator","mcp"]`; G's sink holds exactly 1, origin `"mcp"`. Red: G holds 2.
13. AC13: `agent_activity_hides_trusted_control_entries_from_agents`: operator `demo.read` x2, then agent `demo.read`, then agent `agent.activity` returns 1 entry (command `demo.read`, origin `mcp`); the operator's `agent.activity` returns 4 entries with origins `["operator","operator","mcp","mcp"]`; the agent's `agent.activity {limit:1}` then returns one entry with command `agent.activity` and origin `mcp` (not the operator's). Red: the agent sees 3, and the limit case returns the operator's.
14. AC14: `agent_status_counts_only_what_the_caller_may_see`: fresh ring; operator `demo.read` x4; agent A `demo.read` x3; agent B `agent.status` has `actions_last_minute == 3`; then the operator's `agent.status` has `== 8` (4 + 3 + B's status). Red: 7 for B.
15. AC15: `agent_status_exclude_self_skips_only_the_callers_connection`: A `demo.read` x3, B `demo.read` x2; A `agent.status {exclude_self:true}` gives `2`; A `agent.status {}` gives `6`; a `ConnCtx::new(Mcp)` `agent.status {exclude_self:true}` gives `7` (nothing to exclude); `{exclude_self:"yes"}` is `-32602`. `tools/list` shows `agent.status` `inputSchema.properties.exclude_self.type == "boolean"` and `exclude_self` not in `required`. Red: unknown param error.

*aitm-plugins, aitm-ca*

16. AC16: `agent_schemas_declare_the_new_fields` (in-crate test in `crates/aitm-plugins/src/agent.rs`): the `agent.activity` result object has a `connection_id` param with `required == false`; `agent.status` has an `exclude_self` bool param with `required == false`; both description strings mention the viewer filter. Red: absent.
17. AC17: `durable_line_has_the_same_keys_as_to_value` (`crates/aitm-ca/tests/audit.rs`): for `ca_status_entry()` with `connection_id: Some("conn_ab-1")`, the keys of `serde_json::from_str(entry_to_jsonl(..))` equal the keys of `to_value()` (7) and `value["connection_id"] == "conn_ab-1"`. Red: 6 keys.

*aitm (`crates/aitm/tests/web_bus_audit_identity.rs`, new)*

18. AC18: `governed_servers_sharing_a_ring_never_share_an_id` (in-process): two servers built through `tui::with_shared_governance` from one `Assembled`, one agent connection each with `conn_id: 1`; both calls land in the shared ring with different non-null `connection_id` values, and the web server's `initialize` id differs from the primary's. Red: equal (both `1`-derived with no salt).
19. AC19 `[socket]`: `bridge_ids_are_server_assigned_and_the_stream_is_role_filtered`: over a real `/bus` bridge, an agent connection's `initialize` carries a `connection_id` string; after it sends a forged `clientInfo.name` and `_meta.connection_id`, its subscribed audit lines carry the server's id and `client_label == null` (the pin stays); an operator bridge connection's `proxy.status` produces a line on the operator's stream and none on the agent's (barrier: the agent's own next audit line, which is fanned after, has arrived). Red: the agent receives the operator line, and `connection_id` is absent.

*e2e (`python3 tests/e2e/run.py web audit neg`, against a built `target/debug/aitm`)*

20. AC20 `[e2e]` `tests/e2e/web/test_bus_push_ui_contract.py` (extended, new sections 6 and 7 after the existing five so the earlier exact-count checks keep their meaning): the existing `client_label is None` pin **stays**, because the bridge keeps not copying `clientInfo.name`; added: a repeated `ws.initialize()` returns the same `connection_id` (a `str`, 1 to 64 bytes) that every `flow.list` audit line of this connection carries; a second `WsBusClient.web_agent(core)` has a different id, and its `proxy.status` line arrives on the first connection's stream with `origin == "mcp"` and the second's id; a re-`initialize` with `clientInfo.name == "aitm-web"` leaves the id and the `null` label unchanged. Red: `connection_id` is absent.
21. AC21 `[e2e]` `tests/e2e/web/test_bus_audit_visibility.py` (new; boots `Aitm.web` with the config's operator token, parses the operator bridge token the way `test_web_intercept.py:89-100` does): agent bridge A and operator bridge O subscribed; O's `proxy.status` line appears on O's stream with `origin == "operator"` and never on A's (after A's own barrier call line arrives); A's `proxy.status` line appears on both. The core is fresh and only A and O act, in this order: O `proxy.status`; A `proxy.status` (its line is the barrier); A `agent.activity` returns 1 entry (command `proxy.status`, origin `mcp`); O `agent.activity` returns 3 entries with origins `["operator","mcp","mcp"]`; A `agent.status {exclude_self:true}` gives `actions_last_minute == 0`; A `agent.status {}` gives `3`; O `agent.status {}` gives `6`. Red: A sees the operator line, and A's first `agent.activity` returns 2.
22. AC22 `[e2e]` `tests/e2e/audit/test_audit_identity.py` (new; boots `Aitm.server`): a `BusClient` named `"x" * (1 << 20)` makes a call, and the operator's `agent.activity` entry for it has `client_label == "x" * 128`; two agent connections get different `initialize` ids that their entries carry; on the fresh core, A `scope.list` x3, B `scope.list` x2, then A's `agent.status {exclude_self:true}` is `2`, A's `agent.status {}` is `6`, the operator's `agent.status` is `7`; the label step runs after the counting steps so those counts stay exact. Red: the label is 1048576 bytes.
23. AC23 `[e2e]`: `tests/e2e/neg/test_nonexistent_flow_error.py` reads the ground-truth audit through `op or rd` (`:550`) and passes alongside the rest of `neg` and `audit`. Red: it fails once D3 lands, for the operator `flow.export` entry.

*Gate and scope*

24. AC24: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` is green, with `crates/aitm-mcp/tests/mcp.rs`, `web_bus_push.rs`, `web_bus_governance.rs` and `web_bus_ask_split.rs` unmodified except where AC7-AC15 add tests to `mcp.rs`.
25. AC25 (diff-checkable): the diff touches nothing under `apps/`, `crates/aitm-tui`, `crates/aitm/src/web/` or `crates/aitm-mcp/src/http.rs`.

## Left to the builder

- The exact id rendering within D1's limits, and where the salt is stored and drawn.
- Whether the fan-out filter is a new `Subscriptions` method taking a closure or a role-set computed first; whether `recent_for`/`count_since_for` take `Option<SystemTime>` as `recent` does.
- Names of internal helpers, and whether `cap_client_label` is split into two small functions internally.
- The size of the scrub window in D2 (any value of at least four times the cap).
- Error wording for a wrongly typed `exclude_self` (the existing `-32602` envelope).
- Sharing the operator-bridge-token parser between the two web e2e files by copying it (preferred, to avoid editing the shared harness).

## Risks and the defaults chosen

- **R1. The agent-token page loses operator-origin rows.** *Default: accept (OQ1); the operator link shows them.*
- **R2. Agent-to-agent visibility remains.** Two agents on one proxy see each other's redacted lines. *Default: accept; same trust class.*
- **R3. HTTP POST and the embedded TUI carry `null`.** They build a fresh `ConnCtx` per message (`http.rs:257-262`, `tui.rs:297`). Their lines are never "mine" for any consumer, which fails safe. *Default: accept; a session id for HTTP is its own design.*
- **R4. A closed socket's trailing audit lines carry the old id** (the bridge detaches running frames, `bridge.rs:264-272`) and look foreign to the reconnected UI. *Default: accept; the UI may remember the ids it used (contract note 3).*
- **R5. `exclude_self` lets a caller under-count its own actions in its own reply.** It affects nobody else. *Default: accept.*
- **R6. An older core rejects `exclude_self`.** *Default: UI feature-detects (contract note 5).*
- **R7. The id reveals the per-server connection ordinal, and so lets any holder of one id compute the others on that server.** *Default: accept (D1, "Exposure by role"); the id is not a secret and nothing accepts it as input.*
- **R8. The salt is per `McpServer`, not per process.** If the unified hub later shares the counter across servers the salt becomes redundant but harmless. *Default: accept.*
- **R9. A future transport could write `ConnCtx.client_label` without `cap_client_label`.** *Default: a doc comment on the field and AC11 through the real `serve_lines`; accept the residual.*
- **R10. `scrub_text` can over-redact a legitimate name containing `token=`-style framing.** *Default: accept; it errs toward masking.*
- **R11. `agent.activity {limit}` semantics shift:** N now means N *visible* entries. A fix, not a break.
- **R12. `actions_last_minute` stays an all-visible-origins count for trusted viewers** (it already counted every origin). *Default: keep (OQ2).*

## Open questions

None needs Matt to unblock the plan; each has a default.

1. **OQ1 (the one worth a veto): narrow the audit view for the agent role.** Default: yes (D3), on push, pull and count together. Veto path: drop D3; D1, D2 and D4 stand alone, and D4's count then covers every origin.
2. **OQ2: should `actions_last_minute` mean agent-origin only for everyone?** Default: no; keep the all-visible-origins meaning for trusted viewers. It is a separate change with its own audience (TUI, CLI).
3. **OQ3: sanitize and scrub the label at ingestion (control characters to `?`, `scrub_text`).** Default: yes; the cap alone would leave an ANSI-escape or `Bearer` name in every surface.
4. **OQ4: give the embedded TUI a stable connection id** so it can use `exclude_self`. Default: no (R3); it belongs with the "tui-mode governance" follow-up.

## Summary

Every audit line gains `connection_id`, a server-minted opaque string derived from a per-server random salt and the connection's existing `conn_id` (so the web and primary servers can never collide and restarts never repeat), delivered to its own client in the `initialize` result next to `role`; `client_label` is truncated to 128 bytes, stripped of control characters and scrubbed at the single ingestion point; audit entries of trusted-control origin are hidden from agent-role viewers on push, on `agent.activity` and in the count through one `AuditEntry::visible_to` predicate; and `agent.status` gains an optional `exclude_self` so the web UI's own polling stops inflating `actions_last_minute`. The bridge, HTTP transport and every client are untouched.

## Architect's calls, for approval

1. Wire name `connection_id`, a string or `null`, opaque, at most 64 bytes, rendering `conn_<16 hex>-<n>`.
2. The id is derived from a per-`McpServer` salt and `conn_id`; no new `ConnCtx` field; `conn_id` keeps its subscription and confirm-token job. Raw counter and process-global counter rejected.
3. Delivered on the `initialize` result; `flow.subscribe` result, a new tool, a hello notification and an upgrade header rejected.
4. HTTP POST, in-process and embedded-TUI calls carry `null`.
5. `aitm-ca`'s separate durable renderer is edited and pinned to `to_value` by a parity test.
6. `client_label`: truncate (never refuse) at 128 bytes on a char boundary, whitespace controls to a space and other control and bidi/zero-width/BOM characters to `?`, then `scrub_text`; one function, one call site; the bridge keeps not copying `clientInfo.name`, so the `client_label is None` e2e pin stays.
7. Role filter: yes, one predicate delegating to `is_trusted_control`, applied to push, `agent.activity` (limit after filter) and the count; durable log and ring unfiltered; own lines always visible. (OQ1)
8. `actions_last_minute`: optional `exclude_self` keyed on the caller's server-assigned id, viewer-filtered; role count and client-side derivation rejected; `CommandHost` gains `connection_id`.
9. The existing e2e `neg/test_nonexistent_flow_error.py` is amended to read the audit as the operator.
