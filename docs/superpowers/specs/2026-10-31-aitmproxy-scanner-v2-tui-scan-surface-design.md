# Scanner v2: TUI Scan surface (track T7) design

**Status:** approved (2026-10-31 by the T7 session under Matt's autonomous-approval mandate; child of the approved scanner v2 umbrella spec; one amendment to T7-16 recorded below)
**Parent:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (approved): Constraints, D3, D5, D6, D10, D11, D12 (T7 row), Verification, UI-1/2/3/5. Where this spec and the umbrella differ, the umbrella wins.
**Research inputs:** `docs/research/20-scanner-v2-current-state.md` §3.2, §3.8; the contract crate `crates/aitm-scan-model/src/*` and fixture pack `crates/aitm-scan-model/fixtures/` (T1a, merged); the TUI at this worktree's HEAD (`crates/aitm-tui/src/{app,action,keys,bus,lib,l4}.rs`, `src/ui/{mod,scan,l4,overlays}.rs`, `tests/{scan_surface,l4_surface}.rs`, `tests/common/mod.rs`); `tests/e2e/tui/test_tui_flows_render.py`; `crates/aitm-mcp/src/server.rs` (`needs_confirmation`, line 731) and `schema.rs` (`object_schema`).

## Intent

Replace the TUI's one-shot `scan.discover` panel with the umbrella's shared Scan surface (D10): Profiles, Jobs, Site map and Issues, driven by the D3 verb family over the real bus, refreshed by `notifications/aitm/job` pushes and proven only by the real `aitm-tui` binary on a pty against a real core and a real job. The operator launches, watches, cancels and triages a scan from the terminal with the same model the web and macOS surfaces implement.

## Goals

- From the Profiles tab, start a `standard` job and watch its Jobs row's probes counter rise, its phase change, and its state reach `cancelled` after `x`; every number matches a concurrent `scan.status` read (UI-1).
- Issues appear grouped by severity while the job runs; an issue's detail shows its evidence, opens a probe flow in the inspector and its PoC in Findings; `f` round-trips `false_positive` through `scan.issue.update` (UI-2).
- An L4 profile shows the server's "may disrupt the target" prompt and performs the `_confirm` handshake; without an L4 inject scope entry the launch key is inert and the reason is on screen (UI-3).
- The Site map tab renders nodes and insertion points from a real `scan.sitemap` (UI-5).
- The TUI subscribes on a live bus and routes job pushes to scan refreshes only; the flow sweep is never triggered by a job line.
- Every verb result is parsed with serde into an `aitm-scan-model` type; every `scan: <code>: ...` error gets fixed operator wording.

## Non-goals

- No pause/resume of jobs (no verb exists). No profile YAML editing inside the TUI (the editor edits a typed `ScanProfile`; `scan.profile.save` writes the YAML). No live active audit from the TUI beyond what a job does. Nothing is removed from the legacy `scan.discover` path (umbrella non-goal; it is removed in a later release). No change to `CORE_TOOLS` or `bus-fixture.json` (T1b re-pins them). No web or mac work.

## Anti-goals

- A counter that lies or goes backwards: a number on screen that was computed locally, extrapolated, or taken from a push line instead of a verb result.
- A fixture, snapshot or in-process-model screen offered as proof of anything.
- A launch that reaches the wire without the server's confirm when the server asked for one, or a client-side `y/N` that double-prompts.
- A session value (cookie or header value) anywhere on screen; names only, by contract (D7).
- A job push that triggers the `flow.list` + `flow.get` sweep.

## Constraints

- **Ownership (umbrella D12 T7 row, plus the track owner's claim):** `crates/aitm-tui/src/**` including the `lib.rs` module tree but **excluding the `CORE_TOOLS` constant**; `crates/aitm-tui/fixtures/**` except `bus-fixture.json`; `crates/aitm-tui/tests/**`; `crates/aitm-tui/Cargo.toml` (adds `aitm-scan-model = { workspace = true }`, already a workspace dependency; no other new dependency); the new pty cell `tests/e2e/tui/test_tui_scan_live.py` (`tests/e2e/scan/` is T10's; the umbrella's `test_t7_tui_live.py` name is satisfied by this cell and T10 may alias it).
- **Integration-shared, not edited by this track's tasks:** `crates/aitm-tui/src/lib.rs` `CORE_TOOLS`, `crates/aitm-tui/fixtures/bus-fixture.json`, `crates/aitm/tests/frontends.rs`. Tests add tools with the existing `tools(&[...])` helper in `tests/common/mod.rs` and load the T1a pack with `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../aitm-scan-model/fixtures/<file>"))`. A sibling PR adds `confirmable: bool` to `aitm_bus_client::ToolDef`: no `ToolDef` literal is built outside that helper.
- **Rust gate** before any review: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`; `cargo test` stays hermetic.
- **Given facts (track owner, cited not re-derived):** (1) the TUI never calls `flow.subscribe` (`bus.rs`), so on a live bus it receives no push today; D3 fan-out reaches only subscribed connections. (2) Today every notification becomes a full flow `Refresh`; a job emits up to 4 `progress` lines per second. (3) `scan.start` returns immediately; `scan.discover` blocks the connection for its whole run. (4) The fixture pack is the inner loop only; acceptance is the real binary over a pty against a real core and `aitm-testtarget`. (5) to (7) as in the ownership bullets above.
- **Found while reading (binding on the builder):** `crates/aitm-mcp/src/schema.rs` `object_schema` never declares `_confirm` and sets `additionalProperties: false`; the TUI's `bus.rs` `prune()` keeps only declared properties. A re-issued `_confirm` call is therefore stripped on a live bus today (the L4 test asserts the `BusRequest`, before pruning). `prune()` MUST pass the reserved `_confirm` key through (the server strips it itself, `server.rs` 1692-1702).
- Design rules of the project: flat monochrome glyphs, hue only on data (severity, job state), editorial restraint, dense where density earns it; reuse `Theme` tokens (`severity()`, `accent()`, `text_*()`, `rule()`, `selection()`); every tab has explicit empty, degraded (verb absent), in-flight, error and refused states; below 100 columns panes stack vertically; the 40x4 minimum of `ui::render` stands.

## Design

### D1. Module shape (decided)

`crate::scan` is a model module directory replacing `ScanState`, `ScanFocus`, `InjectionPointRow`, `scan_target_url` and `scan_host` in `app.rs`, on the `l4.rs` precedent: plain data, `App::update` folds, `ui` draws, parse helpers return `Option`/`Result` and never panic.

| File | Holds |
|---|---|
| `src/scan/mod.rs` | `ScanState`, `ScanTab`, `ScanError`, the tag helpers, re-exports |
| `src/scan/profiles.rs` | `ProfilesState`, `ProfileEditor`, `EditorField`, `TriState`, the origin picker |
| `src/scan/jobs.rs` | `JobsState`, row helpers (bars, elapsed text) |
| `src/scan/sitemap.rs` | `SitemapState`, `SitemapQuery` |
| `src/scan/issues.rs` | `IssuesState`, `IssueFilters`, `IssuePane` |
| `src/scan/launch.rs` | `LaunchState`, `PendingLaunch`, `WireConfirm` (generalised from `l4::L4Confirm`), the L4 gate reason |
| `src/scan/legacy.rs` | today's `scan.discover` state (`running`, `target`, `endpoints`, `endpoint_flows`, `points`) moved verbatim |
| `src/ui/scan/mod.rs` | tab strip, pane layout (side by side at >= 100 columns, stacked below), state banners, dispatch per tab |
| `src/ui/scan/{profiles,jobs,sitemap,issues}.rs` | one view per tab |
| `src/ui/scan/confirm.rs` | the wire-confirm overlay for `l4.*` and `scan.*` (replaces `ui::l4::confirm`) |

`app.rs` keeps the reducer arms and the bus-result dispatch only. `keys.rs`, `action.rs`, `bus.rs` gain what D4 and D5 list. `src/ui/scan.rs` is deleted.

### D2. Mode, tabs, feature detection (decided; matrix is the Architect's)

One `Mode::Scan` with `ScanTab { Profiles, Jobs, SiteMap, Issues }`. The sidebar `Scan` row and the view are offered when the bus has `scan.start` **or** `scan.discover`. First open lands on Profiles when `scan.start` is present, on Jobs otherwise; later opens return to the last tab **(Architect's call)**.

| Bus offers | Sidebar row | Profiles | Jobs | Site map | Issues | Launch verbs |
|---|---|---|---|---|---|---|
| `scan.start` (v2) | yes; count = open issues total from the newest non-terminal job, else `-` | full | full | `scan.sitemap` | full | start `scan.start`; map `scan.map`, else `scan.discover`, else key inert with reason |
| only `scan.discover` (legacy) | yes; count = legacy points | degraded banner: "profiles need scan.profile.list (scanner v2)" | legacy launcher: `r`/`s` run `scan.discover`, one row for the one-shot (running / done / error) | legacy result: endpoints as nodes, points as points | degraded banner: "issues need scan.issues (scanner v2)" (literal fixed on panel review 2026-11-01) | `scan.discover { target }` |
| neither | no row | `:scan` opens the view with "the scanner is not on this bus (scan.start / scan.discover)" in every tab | | | | none |

Within v2, each control is gated by its own verb (`has_tool`): Issues needs `scan.issues` + `scan.issue`; status controls `scan.issue.update`; Site map `scan.sitemap`; Profiles list `scan.profile.list`; editor save/delete `scan.profile.save`/`scan.profile.delete`; the check tree `scan.checks`; session names `scan.session.preview`; cancel `scan.cancel`; the L4 gate `l4.scope.list`. A missing verb renders that control inert with the inline text `<verb> is not on this bus`.

### D3. State types (names and fields; the builder picks derives and helpers)

- `ScanState { tab: ScanTab, profiles: ProfilesState, jobs: JobsState, sitemap: SitemapState, issues: IssuesState, launch: LaunchState, legacy: LegacyState, inflight: BTreeSet<String>, last_error: Option<ScanError>, opened_at_tick: Option<u64> }`.
- `ProfilesState { list: Vec<ProfileListEntry>, cursor: usize, pane: ProfilePane { List, Fields, Origins, Checks }, editor: Option<ProfileEditor>, checks: Vec<CheckMeta>, previews: BTreeMap<String, SessionProfile>, error: Option<ScanError> }`.
- `ProfileEditor { loaded_from: Option<String>, builtin: bool, draft: ScanProfile, dirty: bool, field: usize, tree_cursor: usize, collapsed: BTreeSet<String>, origin_cursor: usize, origin_choices: Vec<OriginChoice { origin: String, source: FromScope | FromFlows | Typed }> }`. `EditorField` is a fixed ordered list: `name, origins, l4_targets, lane_http, lane_ws, lane_l4_packet, lane_l4_stream, intensity, speed, accuracy, checks, crawl_strategy, use_browser, max_depth, max_pages, submit_forms, session_mode, on_lost, budget_probes, budget_time_s, budget_max_issues, http_version, record_probes`. Fields of `ScanProfile` not in this list round-trip untouched inside `draft` (the whole typed copy is sent; `ScanProfile` is `deny_unknown_fields`, so the TUI never builds it from loose JSON).
- `TriState { Default, Include, Exclude }` per tree node; a check node is `Include` when its `id` is in `checks.include`, `Exclude` when in `checks.exclude`; a class node when `<class>` (the bare class selector of D2) is listed; a lane node when `lane:<lane>` is listed. Toggling writes exactly those selectors; an id listed under a listed class is left as is (the engine resolves precedence; the tree shows the node's own selector only).
- `JobsState { order: Vec<JobId>, summaries: BTreeMap<JobId, JobSummary>, full: BTreeMap<JobId, JobStatus>, cursor: usize, pane: JobPane { List, Detail }, detail_scroll: u16, listed_at_tick: u64 }`. `order` is `scan.list`'s order (newest first) with jobs this TUI started inserted at the front until the next list. `JobsState` carries `started_here: BTreeSet<JobId>`: a `StartResult` fold inserts the id, a `scan.list` that carries the id removes it, and `fold_list` keeps at the front exactly the `started_here` ids the list omits (ruling on panel review 2026-11-01; a job learned only from a push line is not kept when a list omits it).
- `SitemapState { nodes: Vec<SiteNode>, points: Vec<InsertionPoint>, next_cursor: Option<String>, node_cursor: usize, point_cursor: usize, pane: MapPane { Nodes, Points }, query: SitemapQuery { job: Option<JobId>, target: Option<String> }, fetched_at_tick: u64, error: Option<ScanError> }`.
- `IssuesState { list: Vec<IssueSummary>, rows: Vec<IssueRow> (bounded display rows built once per fold), by_severity: BySeverity, next_cursor: Option<String>, filters: IssueFilters { severity_min: Option<aitm_poc::Severity>, confidence_min: Option<Confidence>, lane: Option<LaneKind>, status: Option<IssueStatus>, job: Option<JobId> }, cursor: usize, pane: IssuePane { List, Detail }, detail: Option<Issue>, flow_cursor: usize, fetched_at_tick: Option<u64> (None = never opened), fetched: BTreeSet<String> (ids read once; pruned per fold), pending_read: Option<String> (the one `scan.issue` in flight), error: Option<ScanError> }` (fields re-aligned with the Task 7 hand-offs and fix round D, 2026-11-01).
- `LaunchState { pending: Option<PendingLaunch { call: String, args: Value, profile_name: Option<String> }>, blocked: Option<String> }`; `blocked` is the UI-3 reason, recomputed whenever the draft, `app.l4.scope` or `app.tools` change.
- `WireConfirm { call: String, args: Value, prompt: String, token: String }` with `from_reply(call, args, reply) -> Option<Self>` and `confirmed_args() -> Value`, moved from `l4.rs` (no alias remains: the `pub type L4Confirm` first planned had no user and was dropped on panel review 2026-11-01). It lives in `App.wire_confirm: Option<WireConfirm>`; `L4State.confirm` is removed. `Mode::L4Confirm` becomes `Mode::WireConfirm`, `Action::L4Confirm(bool)` becomes `Action::WireConfirm(bool)`; `tests/l4_surface.rs` changes those identifiers only, its assertions byte-identical **(Architect's call)**.
- `ScanError { tag: String, verb: String, code: Option<ScanErrorCode>, detail: String }` (`tag` is the request tag the error answers, the bare verb for single-slot verbs; amended 2026-11-01 for D13's per-tag clearing) with `fn wording(&self) -> String` (table D9) and `fn from_message(verb: &str, message: &str) -> Self` using `ScanErrorCode::parse_message`.

### D4. `Action`, `PromptKind`, `BusRequest`, `BusEvent` additions

- `Action`: `ScanTab(ScanTab)`, `ScanPaneNext`, `ScanPanePrev` (replace `ScanFocusToggle`), `ScanStart`, `ScanMap`, `ScanCancel`, `ScanEdit` (edit the field under the cursor), `ScanToggle` (Space: lane/bool/tri-state), `ScanSave`, `ScanDelete`, `ScanNextPage`, `ScanIssueStatus(IssueStatus)`, `ScanFilter(IssueFilterKey { Severity, Confidence, Lane, Status, Job })`, `ScanFilterReset`, `ScanOpenPoc`, `ScanOriginPrompt`, `ScanNewProfile`, `WireConfirm(bool)`. `OpenScan` and `ScanLaunch` (legacy `r`) stay.
- `PromptKind`: `ScanOrigin` (any origin, typed), `ScanField` (number or text field, prefilled), `ScanProfileName` (save-as for a builtin or a new profile), `ScanL4Target` (`ip:port[/tcp|udp][ grammar]`).
- `BusRequest::CallTagged { tag: String, name: String, args: Value }` and `BusEvent::CallTaggedOk { tag, name, value }` / `CallTaggedFailed { tag, name, message }` **(Architect's call)**. Reason: `CallOk` carries no arguments, so a `scan.status` reply cannot be matched to its job on failure, and the generic `CallOk` arm toasts the value and pushes a flow `Refresh` for every reply (`app.rs`, end of the `CallOk` arm), which a 1 s poll must not do. The bus task handles `CallTagged` exactly like `Call` (prune, `call_and_report`) and echoes the tag; it stays verb-agnostic. Every `scan.*` call goes through `CallTagged`; tags are `<verb>` for single-slot verbs (`scan.list`, `scan.issues`, `scan.sitemap`, `scan.checks`, `scan.profile.list`, `scan.start`, `scan.map`, `scan.profile.save`) and `<verb>:<key>` for keyed ones (`scan.status:<job>`, `scan.cancel:<job>`, `scan.issue:<id>`, `scan.issue.update:<id>`, `scan.profile.get:<name>`, `scan.profile.delete:<name>`, `scan.session.preview:<origin>`). A tag already in `inflight` is not re-issued; the reply (ok or failed) removes it; `Disconnected` clears the set.

### D5. Bus task: subscribe, route, prune (decided)

- After the handshake (every reconnect), when the bus offers `flow.subscribe`, `bus.rs` calls `flow.subscribe {}` once; a tool error is a `Toast(Warn, "flow.subscribe failed: <msg>; scan progress will poll only")`, not a session loss. The in-process server in `aitm tui` has no push sink (research §3.2); the poll cadence of D6 is the truth there.
- The reducer routes `BusEvent::Notification(v)` by `v["method"]`: `notifications/aitm/job` with `params.kind == "scan"` is parsed as `JobNotification` and handled by D6; an unparseable job line is ignored. Any other method sets `flows_dirty = true`, and `Action::Tick` issues at most one `Refresh` per tick for it **(Architect's call**, because subscribing newly brings flow lines the TUI never received; coalescing to the 250 ms tick keeps the sweep bounded; the timer poll is unchanged).
- `prune()` keeps `_confirm` in addition to the declared properties (Constraints finding).

### D6. Refresh cadence: push is a trigger, poll is truth (decided; numbers are the Architect's)

| Trigger | Requests |
|---|---|
| `OpenScan`, and every 40 ticks (10 s) while `Mode::Scan` | `scan.list {}`; for every job in the result with no entry in `full`, one `scan.status {job}` |
| job line `started`/`phase`/`progress` | `scan.status {job}` |
| job line `issue`, `finished`, `cancelled`, `failed` | `scan.status {job}` and `scan.issues {filters}` (when the Issues tab was ever opened or the sidebar count needs it) |
| every 4th `Tick` (about 1 s) while any job in `summaries`/`full` is non-terminal | `scan.status {job}` per such job |
| entering Issues, any filter change, and every 20 ticks (5 s) while Issues is shown and a filtered job is non-terminal | `scan.issues {filters, limit: 512}` |
| cursor lands on an issue row | `scan.issue {id}` (once per id until a status update or a terminal line replaces it) |
| entering Site map, `n`, a terminal line for a job matching `query`, every 40 ticks while shown and a job is `crawling` | `scan.sitemap {query, cursor?}` |
| entering Profiles the first time; after `scan.profile.save`/`delete` | `scan.profile.list {}`, `scan.checks {}` |
| `⏎` on a profile row (open editor) | `scan.profile.get {name}`; then `scan.session.preview {target: first origin}` when `session.mode` is `observed` |

At most one `scan.status` per job is in flight (tag dedupe), so replies arrive in order and the row shows the latest reply verbatim; `elapsed_ms` is displayed as received, never advanced locally. A job's status stops being polled when its state `is_terminal()`. **Hostile-core bounds (added on panel review 2026-11-01):** a `scan.status`/`scan.cancel` reply is folded only when its `job` equals the key of the tag it answers (a mismatch is an uncoded `ScanError` "reply named a different job" and nothing is folded); a job id from a push line or a `scan.list` row is used only when it matches `scan-` followed by eight lowercase hex digits, the rest are ignored; at most `MAX_STATUS_FOLLOWUPS = 16` `scan.status` requests leave the reducer per `scan.list` fold (in list order) and per status-timer firing (the cursor's job first, then `order`; the rest wait for the next firing) **(Architect's number)**; `fold_list` drops `full` entries for jobs the list no longer carries unless `started_here` holds them. The same discipline applies to issues (added on the Task 7 panel, 2026-11-01): an issue id from a `scan.issues` row or an `issue` push line is used only when it matches `issue-` followed by eight lowercase hex digits; a `scan.issue`/`scan.issue.update` reply is folded only when its `id` equals the tag's key (mismatch: uncoded error "reply named a different issue"); `scan.issues` pages are truncated client-side to `ISSUES_PAGE_LIMIT`; the per-id `fetched` set is pruned on every fold to the ids of the current page plus the open detail; at most one `scan.issue` read is in flight at a time; row strings are bounded once at fold time, not per frame.

### D7. Launch and confirm (decided)

- `ScanStart`/`ScanMap` build args: from the editor `{ profile: <draft> }` (serialised with serde from `ScanProfile`); from the Profiles list `{ profile_name }`; from `:scan <origin>` `{ target }`. `scan.map` falls back to `scan.discover { target: first origin }` when absent (D2). The call is tagged `scan.start`/`scan.map`, recorded in `launch.pending`, and refused locally only when a launch is already in flight ("a launch is already in flight").
- `scan.start` is **not** added to `CONFIRM_TOOLS`. A reply whose `status` is `needs_confirmation` (`WireConfirm::from_reply`) opens `Mode::WireConfirm`; the overlay shows the server's `prompt` verbatim; `y` sends the identical args plus `_confirm` under the same tag; `n`/`Esc` cancels with the toast `<call> cancelled`. A `StartResult` reply inserts `status` into `full`, the id at the front of `order`, switches to Jobs with the cursor on it, and toasts `scan-xxxx started: <profile> (<lanes.run>)`; a non-empty `clamped` list is a second Warn toast naming each field. A `Vec<SkippedLane>` is shown in the detail pane, not toasted.
- Overlay title and footnote by call name: `l4.*` keeps "Confirm over the wire: guarded L4 action" and its footnote; `scan.*` reads "Confirm over the wire: scan launch" with the footnote "Confirming starts the job now; x in Jobs cancels it at any time." The box is `centered`, 40 to 90 columns, 7 to 16 rows.
- **UI-3 gate.** When `draft.lanes` contains `l4_packet` or `l4_stream`: if `l4.scope.list` is absent, `blocked = "L4 launch disabled: the L4 layer is not on this bus (l4.scope.list)"`; else if `draft.target.l4` is empty, `blocked = "L4 launch disabled: add an L4 target (ip, port, proto) first"`; else if no `app.l4.scope` entry has `capability == "inject"`, `blocked = "L4 launch disabled: no L4 scope entry with the inject capability. Add one with interface \"*\", direction outbound, <ip>/32 ports <port>, capability inject (l4.scope.add)."` with the first L4 target's ip and port filled in. While `blocked` is `Some`, `s` is inert and the editor footer shows the text; coverage of a specific CIDR is the server's check (`out_of_scope`, D9) **(Architect's call**: the client checks presence, the server checks coverage).

### D8. Origins and the `http://` bug (decided)

The origin picker lists one choice per concrete (non-wildcard) entry of `app.scope`: `http://host[:port]` for every distinct plain-http authority the TUI holds a captured flow for (`FlowRow.scheme == "http"`, port kept when not 80), else `https://host`; a host with both schemes yields both; wildcard entries are shown greyed with "type an origin (o)". `o` opens `PromptKind::ScanOrigin`; a typed origin keeps its scheme, a bare host gets the same rule, and a host `scope_covers` rejects is refused with the toast "Out of scope: add `<host>` to scope to scan it" (today's rule). `:scan <origin>` applies the same rule and calls `scan.start { target }` (or `scan.discover` on a legacy bus). `scan_target_url` (the hard-coded `http://`) is deleted.

### D9. Errors by code (decided; wording is the Architect's)

Every `CallTaggedFailed` for a `scan.*` verb becomes a `ScanError`; the wording is shown inline in the owning tab's error line and as an Error toast; an unparseable message is shown verbatim as `<verb>: <message>`.

| Code | Operator wording (then `: <detail>`) |
|---|---|
| `not_found` | "No longer known to the core (it may have restarted); the list is being refreshed" (the reducer drops the id and requests `scan.list`) |
| `busy` | "Scanner busy: the job limit is reached or this origin already has a running job; wait or cancel one in Jobs (x)" |
| `out_of_scope` | "Out of scope: add the HTTP host to Scope (S) or an L4 scope entry with the inject capability covering the target" |
| `refused_agent` | "Refused for the agent role: this client is not the operator; check the token the TUI was started with" |
| `refused_l4` | "L4 refused: enable `l4.enabled` in config (and the agent L4 gates for an agent-started job)" |
| `lane_unavailable` | "No requested lane can run on this core; pick other lanes or a build that has them" |
| `invalid_profile` | "Profile rejected; fix the named field and launch or save again" |
| `unknown_check` | "Unknown check selector; remove it from include/exclude (the tree lists only loaded checks)" |
| `confirm_required` | "The core wanted a confirmation this client did not send (the token may have expired); launch again to get a fresh prompt" |

### D10. Verb result parsing (decided)

| Verb | Parsed as (`aitm_scan_model`) | Folded into |
|---|---|---|
| `scan.start`, `scan.map` | `StartResult` | `jobs.full[job]`, `jobs.order`, `launch.pending = None` |
| `scan.status`, `scan.cancel` | `JobStatus` | `jobs.full[job]`; `summaries[job] = status.summary()` |
| `scan.list` | `ListResult` | `jobs.order`, `jobs.summaries` (full entries kept) |
| `scan.issues` | `IssuesResult` | `issues.list`, `by_severity`, `next_cursor` |
| `scan.issue`, `scan.issue.update` | `Issue` | `issues.detail`; the matching `list` row is replaced by `issue.summary()` |
| `scan.sitemap` | `SitemapResult` | `sitemap.nodes/points` (appended on `n`, replaced otherwise), `next_cursor` |
| `scan.checks` | `ChecksResult` | `profiles.checks` |
| `scan.profile.list` | `ProfileListResult` | `profiles.list` |
| `scan.profile.get` | `ScanProfile` | `profiles.editor.draft` |
| `scan.profile.save` | `ProfileSaveResult` | toast `saved <name> at <path>`; `dirty = false`; list refresh |
| `scan.profile.delete` | `ProfileDeleteResult` | toast; list refresh |
| `scan.session.preview` | `SessionProfile` | `profiles.previews[origin]` (names only are in the type) |
| push `notifications/aitm/job` | `JobNotification` | a trigger only (D6); `status`/`issue` payloads are not folded |
| `scan.discover` (legacy) | today's hand-rolled read, moved to `scan/legacy.rs` unchanged | `legacy.*` |

A result that fails to parse is a `ScanError` with `code: None`, detail `"reply did not match the contract (<serde error>)"` (the `wording()` of an uncoded error already prefixes `<verb>: `, so the detail carries no verb; amended on panel review 2026-11-01); the previous state stays on screen.

### D11. The four tabs

Common chrome: a tab strip `1 Profiles  2 Jobs  3 Site map  4 Issues` under the box title, the active tab bold; a one-line state banner to its right on the same row (`idle`, `refreshing...`, the `ScanError` wording, or the degraded text; amended on panel review 2026-11-01, the mockups already drew it there); the status bar hints (in `bars.rs`) list the tab's keys. Keys shared by every tab:

| Key | Action |
|---|---|
| `1` `2` `3` `4` | `ScanTab(..)` |
| `Tab` / `BackTab` | `ScanPaneNext` / `ScanPanePrev` |
| `↑↓ j k PgUp PgDn g G` | `nav()` on the focused pane |
| `⏎` | open or act (per tab) |
| `Esc` / `q` | close the detail/editor pane if one is focused, else back to Flows |
| `F` | `OpenFindings`; `:` palette; `?` help |

**Profiles** (panes: List, Fields, Origins, Checks): `⏎` on a row opens the editor; `s` `ScanStart`, `m` `ScanMap`, `w` `ScanSave` (a builtin asks `ScanProfileName`), `D` `ScanDelete` (non-builtin; a one-line `y/N` through the existing `PromptKind::Confirm` text "delete profile <name>? y/N"), `N` `ScanNewProfile` (editor over `ScanProfile::default()`), `e` or `⏎` on a field `ScanEdit` (enum fields cycle forward, bool toggles, number/text open `ScanField`, origins focus the Origins pane, checks focus the Checks pane), `Space` `ScanToggle` (lane, bool, tri-state node), `o` `ScanOriginPrompt`, `a` in Origins adds the highlighted choice, `d` removes, `t` opens `ScanL4Target`, `←→ h l` in Checks collapse/expand a node. The session line reads `session: observed · sid, authorization (names) · canary GET /account` from the preview, or `session: none`.

**Jobs** (panes: List, Detail): row = `id · profile · targets · state/phase · probes sent/budget [bar] · points audited/found · issues [stacked severity bar] · elapsed`; `profile` and `targets` read `...` until the first `scan.status`. `x` `ScanCancel` (tag `scan.cancel:<job>`, idempotent, no extra prompt; terminal jobs: key inert, banner "already <state>"), `⏎` opens Issues with `filters.job = <id>`, `s`/`m` start/map with the Profiles cursor's profile (toast names it), `r` is the legacy one-shot on a legacy bus only. Detail: lanes requested/run/skipped with reasons, `started_by` (frontend and client label), `probes` (sent/budget, errors, timeouts, rate waits, by lane), `clamped` rows, `stopped_reason`, `error`, session (`reused`, `lost`, canary, `browser_partial`), `checks` (done/scheduled and `running`), `crawl`, `points.skipped`, `l4` counters when present (the `started_by`, `probes` and done/scheduled lines were accepted on the Task 6 panel, 2026-11-01).

**Site map** (panes: Nodes, Points): nodes grouped under `host[:port]` headers as `METHOD path_template  flows n · points n · ✓` (audited mark); the right pane lists the selected node's points as `kind name path traits example` (example rendered verbatim; it is redacted at the source). `⏎` on a node opens its first flow, on a point its `flow`, both through `row()` with the existing "not in the flow list" toast; `n` `ScanNextPage` while `next_cursor` is `Some`; `J` toggles `query.job` between the Jobs cursor's job and none.

**Issues** (panes: List, Detail): the list is grouped under `CRITICAL n / HIGH n / MEDIUM n / LOW n / INFO n` headers from `by_severity` (a header with 0 is shown greyed); a row = `confidence glyph · name · METHOD path_template · kind:name · status`. Filters: `S` severity minimum (none, low, medium, high, critical), `C` confidence minimum (none, firm, certain), `L` lane (none, http, ws, l4_packet, l4_stream), `T` status (none, open, confirmed, false_positive), `J` job (Jobs cursor's job / none), `R` reset; the active filters print on the list pane's first row as the filter line (`filters: job scan-1a2b3c4d · S none · C none · L none · T none`), while the strip banner carries state only (placement fixed on the Task 7 panel, 2026-11-01). The Issues tab's degraded text under V2 names whichever of `scan.issues` and `scan.issue` is missing. Status controls: `c` confirmed, `f` false_positive, `u` open (each `scan.issue.update {id, status}`; the reply replaces the issue). Detail: name, severity, confidence, status, class, check id, lane, location; description; evidence (`payload`, `matched`, timing as a `requested_s | observed_ms | baseline_ms` table with `slope`/`r`, diff lengths, L4 evidence fields when present); probe flows and baseline flow as a walkable list (`↑↓` when Detail is focused, `⏎` opens through `row()`); `poc_ref` (`P` `ScanOpenPoc`: opens Findings with `finding_cursor` on the first finding whose `poc_path` contains the ref or whose title equals the issue name, else toast "PoC <ref> is not in the Findings list"), `finding_id`, remediation, note, `occurrences`, first/last seen.

**Layout mockups.** Wide frames are drawn at 120 columns for the page; at 200x50 the same regions hold with wider columns (proportions 45/55 for list/detail). Narrow frames are 90x40 literal: panes stack, list above, detail below.

```
┌ Scan ────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1 Profiles  2 Jobs  3 Site map  4 Issues            refreshing scan.list...                              │
│ name            lanes        int.    speed  │ profile standard (builtin)                     dirty       │
│ passive-only ·  http         passive normal │ origins   http://127.0.0.1:8080                            │
│ map-only     ·  http         passive normal │ lanes     [x] http  [x] ws  [ ] l4_packet  [ ] l4_stream   │
│ light-http   ·  http         light   fast   │ intensity medium   speed normal   accuracy normal          │
│>standard     ·  http ws      medium  normal │ checks    ◆ http  ▸ ◆ reflected-xss  ▸ ○ sqli-error        │
│ thorough     ·  http ws      medium  thoro. │ crawl     normal · browser auto · depth 3 · pages 200      │
│ l4-stream-safe  l4_stream    medium  normal │ session   observed · sid, authorization (names) · GET /acc │
│ l4-full         l4_packet l4 medium  normal │ budget    probes 2000 · time 600 s · issues 1024           │
│ team-staging    http         light   fast   │ s start · m map · w save as · e edit · Space toggle        │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
Jobs, wide:
```
│ 1 Profiles  2 Jobs  3 Site map  4 Issues            2 jobs · 1 running                                   │
│ job            profile    targets                state/phase    probes            points    issues   el. │
│>scan-1a2b3c4d  standard   http://127.0.0.1:8080  running/audit  418/2000 ▰▰▱▱▱▱   80/120    ▆▆▃      42s │
│ scan-9e8f7a6b  light-http http://127.0.0.1:8080  cancelled      120/800  ▰▱▱▱▱▱   30/30     ▃        12s │
│ ───────────────────────────────────────────────────────────────────────────────────────────────────────  │
│ scan-1a2b3c4d  lanes requested http ws · run http · skipped ws (lane not available on this build)        │
│ session reused · canary GET /account · checks running http.reflected-xss, http.sqli-error               │
│ x cancel · ⏎ issues of this job · s start · m map                                                        │
```
Site map, wide:
```
│ 1 Profiles  2 Jobs  3 Site map  4 Issues            12 nodes · 2 points of node-1 · n next page          │
│ 127.0.0.1:8080                               │ kind        name   path                  traits  example │
│> GET  /account/{id}      flows 1 · pts 2 · ✓ │>json_value  city   profile.address.city  json    Lisbon  │
│  POST /account           flows 3 · pts 4     │ cookie      theme  -                     id      <redact>│
│  GET  /search            flows 9 · pts 1 · ✓ │                                                          │
```
Issues, wide:
```
│ 1 Profiles  2 Jobs  3 Site map  4 Issues            filters: job scan-1a2b3c4d · S none · C none        │
│ CRITICAL 0                                   │ Reflected cross-site scripting   high · certain · open   │
│ HIGH 1                                       │ GET /search  query q   http.reflected-xss                │
│> ●● Reflected XSS   GET /search  q    open   │ payload  <script>aitm-canary()</script>                  │
│ MEDIUM 1                                     │ matched  reflected marker aitm-canary in an HTML text... │
│  ●○ Error-based SQLi  POST /login  u  open   │ flows    550e8400… (probe)  7c9e6679… (probe)  16fd27… (b│
│ LOW 1                                        │ poc      poc-3b1c (P)   finding finding-7a21             │
│  ○○ Debug marker    GET /        -    open   │ c confirm · f false positive · u reopen · ⏎ open flow    │
```
Narrow (90x40), Jobs; the other tabs stack the same way (list 40 %, detail 60 %):
```
┌ Scan ──────────────────────────────────────────────────────────────────────────────┐
│ 1 Profiles  2 Jobs  3 Site map  4 Issues      2 jobs · 1 running                   │
│ job            state/phase    probes          points   issues  el.                 │
│>scan-1a2b3c4d  running/audit  418/2000 ▰▰▱▱   80/120   ▆▆▃     42s                 │
│ scan-9e8f7a6b  cancelled      120/800  ▰▱▱▱   30/30    ▃       12s                 │
│ ────────────────────────────────────────────────────────────────────────────────── │
│ scan-1a2b3c4d  standard  http://127.0.0.1:8080                                     │
│ lanes requested http ws · run http · skipped ws (lane not available on this build) │
│ x cancel · ⏎ issues · s start · m map                                              │
└────────────────────────────────────────────────────────────────────────────────────┘
```
Confirm overlay (both widths, centred):
```
┌ Confirm over the wire: scan launch ────────────────────────────────┐
│ scan.start                                                         │
│ This scan sends malformed traffic to 127.0.0.1:7000/tcp and may    │
│ disrupt the target. Continue?                                      │
│ Confirming starts the job now; x in Jobs cancels it at any time.   │
│ y confirm (re-issues with _confirm) · n / Esc cancel               │
└────────────────────────────────────────────────────────────────────┘
```

### D12. Legacy path (decided)

With only `scan.discover` on the bus, nothing changes in behaviour: `OpenScan` seeds the display target by the D8 rule (no `http://` default), `r`/`:scan <host>` run the one-shot, the Jobs tab shows one synthetic row (`one-shot · crawling... / done / error`), and the Site map tab renders `legacy.endpoints` as nodes (one per URL, `flows` from `endpoint_flows`) and `legacy.points` as points. `tests/scan_surface.rs` keeps passing with its assertions unchanged except where D8 changes the wire: the seed URL (the fixture host has only https flows, so the expected seed becomes `https://auth.shop-staging.test`), the typed target (`:scan https://api.shop-staging.test:8443/admin?x=1` now sends `https://api.shop-staging.test:8443`, scheme and port kept, path dropped), and the page-size literal in `page_keys_move_the_injection_point_cursor`, which the new tab strip, banner and column header shift (the Coder recomputes and records it) **(Architect's call**, ruled by the T7 session on plan review: D8 wins over a literal reading of this sentence; the `http://` seed is the bug D10 names and the tests pin the fix). The two legacy lists are walked through `SitemapState.pane` (Nodes = endpoints, Points = points); the legacy `focus` field is gone.

### D13. States and design rules (decided)

Each tab draws exactly one of: **empty** ("no profiles yet", "no jobs yet: start one from Profiles (s)", "no site map yet", "no issues yet"), **degraded** (D2 text), **in flight** (banner `refreshing <verb>...` while its tag is in `inflight` and the pane is empty; a populated pane keeps its content), **error** (`ScanError.wording`, until the next successful reply of that verb; for a keyed verb, of that verb with the same key, so job B's success never clears job A's error; granularity fixed on panel review 2026-11-01), **refused** (an `out_of_scope`/`refused_*`/`confirm_required` error is shown in the launch footer in the warning hue, and the launch key stays live). Hue only on data: severity cells use `Theme::severity`, job state uses the status tokens (`running` accent, `done` success, `failed` server-error, `cancelled` tertiary); glyphs are flat monochrome; bars are box-drawing cells.

## Acceptance criteria

Inner loop (`cargo test -p aitm-tui`; `tests/scan_surface.rs` for the legacy path, new `tests/scan_v2_*.rs` files for the rest; these prove the reducer, parsing and rendering and are **not** acceptance evidence):

1. T7-1 Parsing: every file of the fixture pack parses through D10's type into the state it names; `scan.status.json` yields a Jobs row containing `418/2000`, `80/120`, `running/audit`; a `scan.status` reply with an unknown key still parses; a malformed reply leaves the prior row and sets `ScanError { code: None }`.
2. T7-2 Routing: a `Notification` whose method is `notifications/aitm/job` (`job.progress.json` params) yields exactly `CallTagged { tag: "scan.status:scan-1a2b3c4d", .. }` and no `Refresh`; a `notifications/aitm/flow` line yields no request itself and exactly one `Refresh` on the next `Tick`; four `progress` lines in a row yield one in-flight `scan.status` (tag dedupe).
3. T7-3 Cadence: with one non-terminal job, 8 `Tick`s yield exactly 2 `scan.status` requests when each is answered in between and 1 when the first is not; after a `done` reply, 40 `Tick`s yield 0.
4. T7-4 Launch args: `ScanStart` from the editor sends `scan.start { profile }` whose `profile` deserialises back into the same `ScanProfile`; from the list sends `{ profile_name: "standard" }`; `:scan https://auth.shop-staging.test` sends `{ target: "https://auth.shop-staging.test" }`; `:scan evil.test` sends nothing and toasts the out-of-scope text; `scan.start` is not in `CONFIRM_TOOLS`.
5. T7-5 Confirm: a `CallTaggedOk` for `scan.start` with `status: needs_confirmation`, `prompt: "P"`, `confirm_token: "tok-1"` sets `Mode::WireConfirm`; the rendered overlay contains `P` and `scan launch`; `WireConfirm(true)` yields the identical args plus `"_confirm": "tok-1"`; `WireConfirm(false)` yields nothing and toasts `scan.start cancelled`; `tests/l4_surface.rs` passes with identifiers renamed only.
6. T7-6 UI-3 gate: an editor draft with `lanes: [l4_stream]`, one L4 target `127.0.0.1:7000/tcp` and an `app.l4.scope` without an `inject` entry renders the D7 reason containing `interface "*"`, `direction outbound`, `127.0.0.1/32`, `7000`, `capability inject`, and `ScanStart` yields no request; after an `L4Scope` event with an `inject` entry the same `ScanStart` yields one `scan.start`.
7. T7-7 Errors: for each of the nine codes, `CallTaggedFailed { message: "scan: <code>: d" }` renders the D9 wording and `: d` in the owning tab and as a toast; `"boom"` renders `scan.start: boom`; `not_found` on `scan.status:<job>` drops the job and requests `scan.list`.
8. T7-8 Jobs: `scan.list.json` then `scan.status.json` renders rows newest first with profile/targets filled only for the status'd job; `ScanCancel` sends `scan.cancel { job }` once while a second `ScanCancel` before the reply sends nothing; `⏎` opens Issues with `filters.job` set and sends `scan.issues { job }`.
9. T7-9 Issues: `scan.issues.json` renders the five severity headers with their `by_severity` counts and each row under its header; moving the cursor sends `scan.issue { id }` once; `ScanIssueStatus(FalsePositive)` sends `scan.issue.update { id, status: "false_positive" }` and the `scan.issue.update.json` reply replaces the row; `⏎` on a probe flow not in the store toasts "not in the flow list"; `ScanOpenPoc` with a matching finding switches to `Mode::Findings` with the cursor on it, else toasts.
10. T7-10 Site map: `scan.sitemap.json` renders `GET /account/{id}` with `flows 1 · pts 2` and the audited mark, the two points with `<redacted>` verbatim, and `n` sends `scan.sitemap { cursor: "node-2" }` appending nodes; with `next_cursor: null`, `n` sends nothing.
11. T7-11 Profiles: `scan.profile.list.json` renders seven rows with the builtin mark; `scan.checks.json` renders a lane → class → check tree; toggling `sqli-error` to Exclude writes `checks.exclude == ["http.sqli-error"]`; toggling the class node writes `"sqli-error"`; `ScanSave` on a builtin opens `ScanProfileName` and sends `scan.profile.save` with the typed name; the session line from `scan.session.preview.json` contains `sid, authorization` and no `=`.
12. T7-12 Origins: with scope `["auth.shop-staging.test"]` and only https flows to it, the picker offers `https://auth.shop-staging.test`; after a `Flows` event adding an `http` flow to `auth.shop-staging.test:8080`, it offers both that and `http://auth.shop-staging.test:8080`.
13. T7-13 Feature matrix: with `scan.discover` only, the view renders the legacy launcher and `OpenScan` sends no `scan.*` call; with neither verb, the sidebar has no Scan row and `:scan` renders the D2 text; with `scan.start` but no `scan.cancel`, `x` renders `scan.cancel is not on this bus` and sends nothing.
14. T7-14 Layout: every tab renders without panic at 200x50, 90x40, 100x30 and 40x4; at 90 columns the detail pane starts below the list (its first line's row index is greater than the last list row's).
15. T7-15 Bus task: `prune()` keeps `_confirm` on a tool whose schema does not declare it; a `CallTagged` reply arrives as `CallTaggedOk` with the same tag.

Live (the only acceptance evidence; `tests/e2e/tui/test_tui_scan_live.py`, header `# e2e: tier=T1 surface=scan needs=aitm-tui`, real `aitm-tui --bus --token-file` on a 200x50 pty against a self-booted or runner core with `CoreConfig(scope_entries=[target host], l4_enabled=True)` and `Target("vulnerable")`; the harness's operator `BusClient` is the independent observer and a second `BusClient` with a `flow.subscribe` counts `notifications/aitm/job` lines; exit 0/1/77):

16. T7-16 (UI-1) The cell opens Scan, enters the `standard` editor, picks the target origin, presses `s`; the Jobs row appears with the id the harness reads from `scan.list`; across at least three screen samples the `sent` value is non-decreasing and each sample lies between the `probes.sent` of the `scan.status` read the harness took just before the sample and the one it took just after (bracketing reads, since the counter moves between two observations; amended by the T7 session on approval); the phase text changes at least once; `x` yields `cancelled` on screen and in `scan.status`; the second client received at least one `progress` and one `cancelled` line.
17. T7-17 (UI-2) With a job that produces at least one issue (the vulnerable target's reflected-xss route), the Issues tab shows the issue under its severity header while the job is still `running`; its detail shows the `payload` the harness reads from `scan.issue`; `⏎` on the first probe flow enters the inspector showing that flow's path; `f` yields `false_positive` on screen and in `scan.issue`; `u` restores `open`; `P` opens Findings on the matching PoC when `finding_id` is set (else the cell records the toast and passes this sub-step as "no PoC for this issue").
18. T7-18 (UI-3) The cell selects `l4-stream-safe`, adds target `127.0.0.1:<port>/tcp`; with no inject scope entry the screen shows the D7 reason and `s` produces no job (`scan.list` unchanged for 3 s); after `l4.scope.add` of an `interface: "*"`, `direction: outbound`, `capability: inject` entry covering the target, `s` shows the overlay containing "may disrupt the target"; `y` re-issues and the screen then shows either a Jobs row for the new job or the `refused_l4`/`lane_unavailable` wording, whichever the core answers, matching the harness's own `scan.start` attempt; `n` on a fresh prompt shows `scan.start cancelled` and no job appears.
19. T7-19 (UI-5) After a `map-only` job reaches `done`, the Site map tab shows every `host`, `METHOD path_template` and point `name` of the harness's `scan.sitemap` read for that job (compared to the rendered text, not to a fixture); `⏎` on a node opens its first flow in the inspector.
20. T7-20 Hygiene: at no time does the pty screen contain a cookie or `Authorization` value the harness seeded through the proxy (the harness greps the screen log for the seeded secret); the TUI exits 0 on `q`.

## Left to the builder

Exact glyphs for the confidence pair, the audited mark, the tri-state (`◆ ◇ ○` or similar), the builtin mark and the stacked bar; column widths and truncation per terminal width; wrap rules in the detail panes; the mini-bar cell count; scroll-offset arithmetic; the help overlay text for the Scan keys; where `bars.rs` hints wrap at narrow widths; test file split and names under `tests/scan_v2_*.rs`; how the pty cell waits (polling the screen model) and its timeouts.

## Open questions

None found in the umbrella contract. Two wrinkles are resolved by assumption: (a) D3's `scan.list` returns `JobSummary`, which has no `profile_name`/`targets`, while the Jobs row shows both; the TUI fills them from one `scan.status` per listed job (D6, first row of the table). (b) The umbrella names the live cell `test_t7_tui_live.py` under `tests/e2e/scan/`; this track writes `tests/e2e/tui/test_tui_scan_live.py` and T10 may alias it (Constraints).

## Summary

The TUI gets one `Mode::Scan` with four tabs over a `crate::scan` model module, parsing every verb result with serde into `aitm-scan-model` types and polling `scan.status` once a second per live job, with `notifications/aitm/job` lines acting only as triggers now that `bus.rs` subscribes after the handshake and routes job lines away from the flow sweep. Launches go to `scan.start`/`scan.map` with the typed profile, the server's `needs_confirmation` opens a generalised wire-confirm overlay shared with L4, and the UI-3 L4 gate is computed from the TUI's L4 scope with a reason that names the needed entry. The nine error codes get fixed wording, origins come from the scope and the captured flows (no `http://` default), the legacy `scan.discover` path stays intact, and only the pty cell against a real core counts as proof.

### Architect's calls (for the T7 session to approve or correct)

1. First open lands on Profiles with `scan.start`, on Jobs otherwise; later opens restore the last tab (D2).
2. `BusRequest::CallTagged` / `BusEvent::CallTaggedOk|Failed` with a tag per call, tag dedupe for in-flight requests, and no flow `Refresh` from scan replies (D4).
3. Flow-method notifications are coalesced to one `Refresh` per 250 ms tick instead of one per line (D5).
4. `prune()` passes `_confirm` through (a live-path bug found in the existing L4 confirm) (Constraints, D5).
5. Cadence numbers: status every 4 ticks per live job, list every 40 ticks, issues every 20 ticks while shown, sitemap every 40 ticks while crawling, `scan.issues` `limit: 512` (D6).
6. `Mode::L4Confirm`/`Action::L4Confirm` renamed to `WireConfirm`, no `L4Confirm` alias kept (amended 2026-11-01), `tests/l4_surface.rs` edited for identifiers only (D3).
7. UI-3 client gate checks presence of an `inject` entry and an L4 target; CIDR coverage is left to the server's `out_of_scope` (D7).
8. The nine error wordings and the `not_found` self-heal (drop the id, refresh the list) (D9).
9. Filter keys `S C L T J R`, status keys `c f u`, `P` for the PoC, `N` new profile, `w` save, `D` delete, `o` typed origin, `t` L4 target, `n` next page (D11).
10. The legacy test's seed expectation moves to the D8 rule (`https://` for a host with only https flows) (D12).
11. Issue list grouping shows zero-count severity headers greyed rather than hiding them (D11).
12. The live cell runs with `l4_enabled=True` and adds the inject scope entry over the bus so UI-3 is observable on a machine without L4 capture privilege (T7-18).
