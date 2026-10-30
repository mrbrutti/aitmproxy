# aitmproxy-plugin (MCP Apps rich UI + ChatGPT connectivity) implementation plan

**Status:** Approved by Matt (orchestrator, autonomous mode) 2026-10-29
**Spec:** `docs/superpowers/specs/2026-10-29-aitmproxy-plugin-design.md`
**Branch / worktree:** `feat/aitmproxy-plugin` — `/Users/matt/Security/aitmproxy/.worktrees/aitmproxy-plugin`

## Overview

The work is the additive MCP-server changes (W1–W4), the widget bundles (W5),
the plugin package (W6–W9), and the docs + test harness (W10–W11). It is
scheduled into five waves that keep the spec's dependency edges valid and never
let two tasks in the same wave write the same file.

The sequencing spine is `W4 flow.table → W2 resources+widgets → W3 tool overlay`,
because W3 overlays a tool that W4 registers and reads the widget registry W2
owns, and because W2 and W3 both edit `server.rs` (W2 owns the
`initialize`/`resources/*` arms, W3 owns the `tools/list` arm — different waves).
W1 (HTTP transport) is independent of W2–W5 except for one-line `lib.rs`/`main.rs`
touch-points, which are isolated into W1's own wave slot so no wave shares
`lib.rs`. W2 ships **placeholder** widget HTML so `widgets.rs` compiles; W5
replaces each placeholder with the real rich widget in a later wave (per-file,
fully fan-out). W6–W9 under `aitmproxy-plugin/` are mutually independent and only
need the final tool/widget names. Docs and the full test harness land last.

**Shared-file ownership (the whole feature):**
- `crates/aitm-mcp/src/lib.rs`: module list — `pub mod widgets;` added by Task 3
  (Wave 1); `pub mod http;` added by Task 4 (Wave 2). Never the same wave.
- `crates/aitm-mcp/src/server.rs`: `initialize` + `resources/*` arms owned by
  Task 3 (Wave 1); `tools/list` arm owned by Task 5 (Wave 2). Never the same wave.
- `crates/aitm-mcp/src/widgets.rs`: created and fully owned by Task 3. Task 5
  only `use`s `WidgetMeta`/`widget_meta_for` from it; it does not edit it.
- `crates/aitm-mcp/widgets/*.html`: placeholders created by Task 3; each real
  widget file is replaced by exactly one Wave-3 task.
- `crates/aitm-mcp/Cargo.toml`: edited only by Task 4.
- `crates/aitm/src/main.rs`: edited only by Task 4.

**CLI fact verified for Tasks 14/15 and 18:** bare `aitm` with **no arguments**
is `Mode::Server` — it starts the proxy plus the configured MCP transport
(default stdio). There is **no `aitm mcp` subcommand** (`crates/aitm/src/main.rs`
`enum Mode`). The stdio MCP wiring in `.mcp.json`/`mcp.json` is therefore
`{"command":"${AITM_BIN:-aitm}","args":[]}`, not `args:["mcp"]`.

## Waves and fan-out

- **Wave 0:** Task 1.
- **Wave 1 (parallel):** Task 2, Task 3, Task 6.
- **Wave 2 (parallel):** Task 4, Task 5.
- **Wave 3 (parallel):** Task 7, Task 8, Task 9, Task 10, Task 11, Task 12,
  Task 13, Task 14, Task 15, Task 16, Task 17.
- **Wave 4 (parallel):** Task 18, Task 19, Task 20.

Total: **20 tasks.**

---

## Tasks

### Task 1: W4 — `flow.table` data tool

- **Wave:** 0
- **Satisfies:** AC7 (and enables AC4/AC5 coverage of `flow.table` in Task 5)
- **Depends on:** none
- **Files:** `crates/aitm-plugins/src/capture.rs` (modify),
  `crates/aitm-plugins/tests/capture.rs` (modify)
- **Change:**
  - Add `struct FlowTable;` and `impl Command for FlowTable` beside `FlowList`.
    - `fn name(&self) -> &str { "flow.table" }`
    - `fn sensitivity(&self) -> aitm_core::Sensitivity { aitm_core::Sensitivity::Read }`
    - `fn schema(&self) -> ParamSchema`: description `"Per-flow summaries for a
      flows table: method, URL, status, duration, state, and marks, oldest first.
      Read-only."`; `params: vec![]`; `result: TypeDesc::Object(vec![ ParamDef {
      name: "flows", ty: TypeDesc::Array(Box::new(TypeDesc::Object(row_fields()))),
      required: true, description: "..." } ])`.
    - `fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value>`:
      iterate `host.store().list()` oldest-first, `host.store().get(id)` each,
      build one row per flow, return `Value::Object({"flows": Value::Array(rows)})`.
  - Add `fn row_fields() -> Vec<ParamDef>` and `fn flow_row(flow: &Flow) -> Value`.
    Row keys (required: `id`,`kind`,`state`,`marks`; optional/nullable:
    `method`,`authority`,`path`,`status`,`duration_ms`): `id` from `flow.id()`;
    `kind` `"http"`/`"websocket"`; HTTP fields from the request (null for WS
    rows); `status` from the response or null; `state` from the flow's
    `InterceptState::label()`; `duration_ms` from `FlowMeta.duration`
    (`None` → `Value::Null`, else whole milliseconds as `Value::Int`); `marks`
    from `FlowMeta.marks` as `Value::Array(Str)`. No headers, no bodies.
  - Register it: `reg.add_command(Arc::new(FlowTable));` in `CapturePlugin::load`.
  - **Leave `FlowList`, `FlowGet`, `summarize`, `summary_fields` byte-identical.**
- **Test:** in `crates/aitm-plugins/tests/capture.rs`, `fn flow_table_rows()`:
  load `CapturePlugin`, insert two flows into the store — one HTTP `GET` with a
  `200` response, one WebSocket — call `flow.table`, assert the result object has
  key `flows` whose array `len() == 2`; the HTTP row has `method == "GET"`,
  `status == 200`, `state == "observed"`; the WS row has `kind == "websocket"`
  and `method == Value::Null`. Add `fn flow_list_unchanged_ids_only()` asserting
  `flow.list` still returns a bare array of id strings (ids-only, AC7 tail).
- **Done when:** both tests pass and the full gate passes.

---

### Task 2: W1a — `McpTransport::StreamableHttp` config variant

- **Wave:** 1
- **Satisfies:** AC11 (default-loopback bind, config half); groundwork for AC8–AC13
- **Depends on:** none
- **Files:** `crates/aitm-core/src/config.rs` (modify)
- **Change:** add a third variant to `enum McpTransport`:
  ```
  StreamableHttp {
      bind: SocketAddr,             // default 127.0.0.1:8084
      token: String,               // REQUIRED, non-empty
      allowed_origins: Vec<String>,// exact Origin allowlist; empty = none
      path: String,                // default "/mcp"
  }
  ```
  Provide a constructor/helper `McpTransport::streamable_http_default(token:
  String) -> Self` returning `bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),
  8084)`, `allowed_origins: vec![]`, `path: "/mcp".into()`. Keep `Stdio` and
  `LoopbackTcp` unchanged. Do not change `McpConfig` defaults (`Stdio` stays the
  default transport). Update any exhaustive `match` on `McpTransport` in
  `config.rs` only (other crates' matches are updated by the tasks that own them —
  Task 4 for `server.rs`/`main.rs`); if a non-owned match breaks compilation,
  **stop and report** rather than editing another task's file.
- **Test:** in `crates/aitm-core/src/config.rs` tests module,
  `fn streamable_http_default_binds_loopback()`: assert
  `matches!(McpTransport::streamable_http_default("t".into()),
  McpTransport::StreamableHttp { bind, .. } if bind.ip().is_loopback() &&
  bind.port() == 8084)` and that `path == "/mcp"` and `allowed_origins` is empty.
- **Done when:** the test passes and `cargo test -p aitm-core` plus the full gate
  pass.

---

### Task 3: W2 — `resources/*`, `initialize` capability, widgets module + placeholders

- **Wave:** 1
- **Satisfies:** AC1, AC2, AC3 (and exposes the registry Task 5 consumes)
- **Depends on:** none
- **Files:** `crates/aitm-mcp/src/widgets.rs` (create),
  `crates/aitm-mcp/src/lib.rs` (modify — add `pub mod widgets;` and re-exports),
  `crates/aitm-mcp/src/server.rs` (modify — `initialize` arm + new
  `resources/list`/`resources/read` arms only),
  `crates/aitm-mcp/widgets/flows.html`,`flow-detail.html`,`findings.html`,
  `finding-detail.html`,`scope.html`,`poc-result.html`,`proxy-status.html`
  (create — minimal placeholders),
  `crates/aitm-mcp/tests/mcp.rs` (modify — add tests).
- **Change:**
  - `widgets.rs`:
    - `pub const RESOURCE_MIME: &str = "text/html;profile=mcp-app";`
    - `pub const WIDGET_DOMAIN: &str = "aitmproxy.widget";` (placeholder origin,
      Design H; documented as a submission-time swap).
    - `pub struct Widget { pub uri: &'static str, pub name: &'static str, pub
      title: &'static str, pub description: &'static str, pub prefers_border:
      bool, pub html: &'static str }`
    - `pub fn widgets() -> &'static [Widget]` — exactly seven entries, URIs
      `ui://aitm/flows`, `.../flow-detail`, `.../findings`, `.../finding-detail`,
      `.../scope`, `.../poc-result`, `.../proxy-status`; each `html` is
      `include_str!("../widgets/<file>.html")`.
    - `pub fn resource_meta(w: &Widget) -> serde_json::Value` — builds both
      `ui.csp`/`openai/widgetCSP` (empty `connect`/`resource` domain arrays),
      `ui.domain`/`openai/widgetDomain` (= `WIDGET_DOMAIN`), `ui.prefersBorder`
      (= `w.prefers_border`), `openai/ui` `{availableDisplayModes:["inline"]}`.
    - `pub struct WidgetMeta { pub resource_uri: Option<&'static str>, pub
      invoking: &'static str, pub invoked: &'static str, pub read_only: bool,
      pub destructive: bool, pub open_world: bool, pub widget_accessible: bool }`
      (**defined here so Task 5 can `use` it; `resource_uri` is `Option` so the
      data-only `tls.passthrough.list` maps to `None`**).
    - `pub fn widget_meta_for(tool_name: &str) -> Option<WidgetMeta>` — maps the
      eight widget tool names to their overlay (`flow.table`→`ui://aitm/flows`,
      `flow.detail`→`.../flow-detail`, `findings.list`→`.../findings`,
      `findings.get`→`.../finding-detail`, `scope.list`→`.../scope`,
      `poc.run`/`poc.get`→`.../poc-result`, `proxy.status`→`.../proxy-status`),
      all `read_only:true, destructive:false, open_world:false,
      widget_accessible:false` **except `poc.run`** (`read_only:false,
      open_world:true`); plus `tls.passthrough.list` → `WidgetMeta {
      resource_uri: None, widget_accessible: true, read_only: true, .. }`.
      Each `invoking`/`invoked` string ≤ 64 chars (builder picks exact wording).
  - `lib.rs`: add `pub mod widgets;` and
    `pub use widgets::{Widget, WidgetMeta, widget_meta_for, widgets};`.
  - `server.rs`:
    - `initialize` arm: change `capabilities` to
      `{"tools":{}, "resources":{}, "extensions":{"io.modelcontextprotocol/ui":
      {"mimeTypes":["text/html;profile=mcp-app"]}}}`. **Keep** the top-level
      `role` echo, `serverInfo`, and `protocolVersion` exactly as they are.
    - add `"resources/list"` arm → `{"resources":[ one entry per widget ]}`, each
      `{uri,name,title,description,mimeType:RESOURCE_MIME,_meta:resource_meta(w)}`.
    - add `"resources/read"` arm reading `params.uri`: on match return
      `{"contents":[{uri,mimeType:RESOURCE_MIME,text:w.html,_meta:resource_meta(w)}]}`;
      unknown/missing uri → `Err(RpcError::new(INVALID_PARAMS, format!("unknown
      resource {uri}")))`. Served regardless of transport/role.
    - **Do not touch** the `tools/list` or `tools/call` arms (Task 5 owns
      `tools/list`).
  - placeholder HTML files: each a minimal, CSP-clean, lint-clean document
    beginning `<!DOCTYPE html>` with an inlined `<style>` and `<script
    type="module">` and a `<main>` host node — just enough to satisfy AC3 and the
    widget-lint; Wave-3 tasks replace them.
- **Test:** in `crates/aitm-mcp/tests/mcp.rs`:
  - `fn initialize_advertises_resources()`: `initialize` result `capabilities`
    has both `tools` and `resources` keys and
    `capabilities.extensions["io.modelcontextprotocol/ui"].mimeTypes[0] ==
    "text/html;profile=mcp-app"`, and the top-level `role` and `serverInfo` are
    still present (AC1).
  - `fn resources_list_seven()`: `resources/list` returns exactly 7 entries; each
    `mimeType == "text/html;profile=mcp-app"`, `uri` starts `ui://aitm/`, and
    `_meta` has `ui.csp.connectDomains == []`, `openai/widgetCSP`,
    `ui.domain == "aitmproxy.widget"`, `ui.prefersBorder` present,
    `openai/ui.availableDisplayModes == ["inline"]` (AC2).
  - `fn resources_read_doctype_and_unknown()`: `resources/read` for each of the
    7 URIs returns `contents[0].mimeType == "text/html;profile=mcp-app"` and
    `contents[0].text` starts `"<!DOCTYPE html>"`; an unknown uri
    (`ui://aitm/nope`) returns a JSON-RPC error with code `INVALID_PARAMS` (AC3).
- **Done when:** the three tests pass and the full gate passes.

---

### Task 4: W1b — streamable-HTTP transport + wiring + threat-model-ready endpoint

- **Wave:** 2
- **Satisfies:** AC8, AC9, AC10, AC11, AC12, AC13
- **Depends on:** Task 2 (the config variant)
- **Files:** `crates/aitm-mcp/src/http.rs` (create),
  `crates/aitm-mcp/Cargo.toml` (modify — add deps),
  `crates/aitm-mcp/src/lib.rs` (modify — add `pub mod http;` + re-export),
  `crates/aitm-mcp/src/server.rs` (modify — **only** the `McpTransport` match arm
  inside `McpServer::serve`, to dispatch the new variant; Task 5 does not touch
  this arm),
  `crates/aitm/src/main.rs` (modify — wire/accept the variant where
  `McpTransport` is matched, incl. the bus-endpoint applier ~L559),
  `crates/aitm/src/config_file.rs` (modify — add `TransportFile::StreamableHttp`
  so the transport is selectable from config),
  `crates/aitm-plugins/src/control.rs` (modify — the status renderer match ~L283),
  `crates/aitm/src/tui.rs` (modify — the transport-descriptor match ~L222),
  `crates/aitm-mcp/tests/http.rs` (create).

  **Amendment (orchestrator, 2026-10-29): Task 4 owns the full `McpTransport`
  variant ripple.** Adding the variant (Task 2) makes several exhaustive
  production matches non-exhaustive that no task had claimed (found by Task 1 at
  `control.rs:283`). Task 4 adds a `StreamableHttp` arm to EVERY exhaustive
  production match so the whole workspace compiles: `control.rs` (report the
  transport name/bind, NEVER the token), `tui.rs` (treat as an addressable agent
  endpoint, mirror `LoopbackTcp`), `main.rs` bus-endpoint applier (StreamableHttp
  does not use the loopback-bus `endpoint_file`; follow the `Stdio` pattern), the
  `server.rs` serve arm (dispatch to the http module). Also add the
  `TransportFile::StreamableHttp { bind, token, #[serde(default)] allowed_origins,
  #[serde(default)] path }` config-file variant + its `From` arm, with a
  config round-trip test, so an operator can actually enable it.
- **Change:**
  - `Cargo.toml`: add `hyper = { version = "1", features = ["server","http1"] }`,
    `hyper-util`, `http-body-util` (pin alongside the existing `tokio` features;
    same pattern as `aitm-testtarget`).
  - `http.rs`:
    - `pub struct StreamableHttp { listener: TcpListener, local_addr: SocketAddr,
      token: String, allowed_origins: Vec<String>, path: String }`
    - `pub async fn bind(cfg: StreamableHttpCfg) -> anyhow::Result<Self>` (take the
      four config fields; bind `cfg.bind`). Reject an empty token with an error.
    - `pub fn local_addr(&self) -> SocketAddr`
    - `pub async fn serve(self, server: Arc<McpServer>) -> anyhow::Result<()>` —
      one endpoint at `path`:
      - **POST** `path`: guards (below) then dispatch each JSON-RPC message
        through `server.handle_on(&ConnCtx::new(Frontend::Mcp), msg)`; reply
        `Content-Type: application/json` (single-JSON answers are acceptable in
        v1).
      - **GET** `path`: open a `text/event-stream` writer lane for
        `notifications/aitm/*` (mirror `transport::serve_lines`' writer task).
      - **Guards, in this order, fail-closed, before any dispatch:**
        1. **Auth** — `Authorization: Bearer <token>` constant-time-equal to the
           configured token, else `401` with no token echoed.
        2. **Origin** — if an `Origin` header is present it must be in
           `allowed_origins`, else `403` (empty allowlist ⇒ any present Origin is
           rejected; absent Origin is allowed).
        3. **Host** — `Host` must be a loopback literal (`127.0.0.1[:port]`,
           `[::1][:port]`, `localhost[:port]`) or explicitly allowlisted, else
           `403`.
        4. Non-`POST`/`GET` → `405`; wrong path → `404`.
      - **Hygiene:** never log the token or the `Authorization` header; emit the
        single startup line to **stderr**: `"MCP streamable HTTP listening on
        <addr><path>"`. No `println!`.
  - `lib.rs`: add `pub mod http;` and `pub use http::StreamableHttp;`.
  - `server.rs`: in the `serve` transport match, add a `McpTransport::StreamableHttp
    { .. }` arm that builds `StreamableHttp::bind(..).await?` and
    `.serve(server).await`. Touch nothing else in `server.rs`.
  - `main.rs`: extend any `McpTransport` match so the new variant compiles/wires;
    no behaviour change for `Stdio`/`LoopbackTcp`.
- **Test:** in `crates/aitm-mcp/tests/http.rs`, bind the transport on
  `127.0.0.1:0`, spawn `serve`, and drive it with a raw `hyper` client:
  - `fn rejects_missing_and_wrong_token()`: POST with no `Authorization` → `401`;
    POST with wrong Bearer → `401`; neither reaches a tool. Correct token → `200`
    (AC8).
  - `fn rejects_foreign_origin()`: POST with `Origin: https://evil.test` and
    correct token → `403`; same request with no `Origin` → `200` (AC9).
  - `fn rejects_rebound_host()`: POST with `Host: attacker.example` and correct
    token → `403`; `Host: 127.0.0.1:<port>` → `200` (AC10).
  - `fn binds_loopback_by_default()`: after `bind` of the default config,
    `local_addr().ip().is_loopback()` is `true` (AC11).
  - `fn end_to_end_matches_stdio()`: authorized same-origin `initialize`,
    `tools/list`, and `resources/read` over POST return the same shapes AC1–AC3
    assert (AC12).
  Regression (AC13): the existing `transport.rs`/`mcp.rs` stdio and loopback-TCP
  tests remain green under the gate.
- **Done when:** all five HTTP tests pass, existing transport tests still pass,
  and the full gate passes. No `unsafe`.

---

### Task 5: W3 — tool-descriptor `_meta`/`outputSchema`/`annotations` overlay + no-regression snapshot

- **Wave:** 2
- **Satisfies:** AC4, AC5, AC6
- **Depends on:** Task 1 (`flow.table` registered), Task 3 (`WidgetMeta` +
  `widget_meta_for` + URIs)
- **Files:** `crates/aitm-mcp/src/schema.rs` (modify),
  `crates/aitm-mcp/src/server.rs` (modify — **only** the `tools/list` arm),
  `crates/aitm-mcp/tests/mcp.rs` (modify — add tests)
- **Change:**
  - `schema.rs`: add `pub ui: Option<crate::widgets::WidgetMeta>` (default `None`)
    to `McpTool`; set it to `None` in `StdSchemaDerive::to_mcp_tool`. Change
    `McpTool::to_json` so that **only when `ui` is `Some`** it appends:
    - `annotations` — all three of `readOnlyHint`/`destructiveHint`/`openWorldHint`
      from the `WidgetMeta` booleans;
    - `outputSchema` — from `type_schema(&result)` of the tool's command result
      (so object tools get `type:"object"`, `findings.list`/`scope.list` get
      `type:"array"`);
    - `_meta` — when `resource_uri` is `Some`: `ui.resourceUri` ==
      `openai/outputTemplate` == that URI, plus `openai/toolInvocation.invoking`/
      `.invoked` (each ≤ 64 chars); when `resource_uri` is `None` but
      `widget_accessible` (the `tls.passthrough.list` case): `ui.visibility ==
      ["model","app"]` + legacy `openai/widgetAccessible == true`, and **no**
      `resourceUri`.
    - When `ui` is `None`, `to_json` output is **byte-identical** to today.
    - `to_mcp_tool` needs the command result `TypeDesc` for `outputSchema`; carry
      it on `McpTool` (e.g. `pub result: TypeDesc` set from `cmd.schema().result`)
      or thread it where `to_json` builds the overlay — builder's call, but it must
      not change the `ui == None` output.
  - **Amendment (orchestrator, 2026-10-29): do the overlay in `schema.rs`, NOT
    `server.rs`.** So T4 (serve arm) and T5 can run in parallel without both
    editing `server.rs`: have `StdSchemaDerive::to_mcp_tool` itself set
    `ui = crate::widgets::widget_meta_for(cmd.name())` (returns `None` for
    non-widget tools, keeping their `to_json` byte-identical per AC6). The
    `server.rs` `tools/list` arm stays byte-identical (still just
    `StdSchemaDerive.to_mcp_tool(cmd).to_json()`). **T5 does not touch
    `server.rs`** — its only files are `schema.rs` and `tests/mcp.rs`.
- **Test:** in `crates/aitm-mcp/tests/mcp.rs`:
  - `fn widget_tools_carry_meta()`: in `tools/list`, for `flow.table` assert
    `_meta.ui.resourceUri == "ui://aitm/flows"` and equals
    `_meta["openai/outputTemplate"]`, and both `invoking`/`invoked` are ≤ 64
    chars; `tls.passthrough.list` has `_meta.ui.visibility == ["model","app"]`,
    `_meta["openai/widgetAccessible"] == true`, and **no** `resourceUri` (AC4).
  - `fn widget_annotations_and_output_schema()`: every widget tool has all three
    annotation hints; all are `readOnlyHint:true` except `poc.run`
    (`readOnlyHint:false, openWorldHint:true`); `outputSchema.type == "object"`
    for object tools and `== "array"` for `findings.list` and `scope.list`
    (AC5).
  - `fn non_widget_tools_byte_identical()`: build `tools/list` and assert every
    entry whose name is **not** in the widget set ∪ `{tls.passthrough.list,
    flow.table}` has no `annotations`/`outputSchema`/`_meta` keys and equals the
    `StdSchemaDerive::to_mcp_tool(..).to_json()` output for that command (AC6
    no-regression snapshot). Also assert no `tools/call` result gains `_meta`
    (call one widget tool, e.g. `proxy.status`, and assert the result has no
    `_meta`).
- **Done when:** the three tests pass and the full gate passes.

---

### Task 6: W5 — token→CSS generator + committed `tokens.css`

- **Wave:** 1
- **Satisfies:** supports AC14 (colours come from custom properties); no code AC
- **Depends on:** none (reads `docs/design/tokens.json` only)
- **Files:** `crates/aitm-mcp/widgets/build.mjs` (create — or `build.sh`),
  `crates/aitm-mcp/widgets/tokens.css` (create — committed output),
  `crates/aitm-mcp/widgets/README.md` (create — the regen command)
- **Change:** a Node (or shell) generator that reads `docs/design/tokens.json`
  and emits `tokens.css` as CSS custom properties: a `:root` block with the light
  values and a dark block under both `@media (prefers-color-scheme: dark)` and
  `[data-theme="dark"]`. Cover the groups the widgets need: `method.*`,
  `status.*`, `severity.*`, `mark.*`, `intercept.*`, `agent.*`, `accent.*`,
  `syntax.*`, `l4.*`, plus `ground/line/text` and `fontFamily`/`fontWeight`.
  Naming convention e.g. `--color-method-get-fg`, `--color-method-get-bg`,
  `--color-severity-high-fg`, `--font-data`. The committed `tokens.css` is the
  source Wave-3 widgets inline; **the Rust build must never need Node**. Document
  the regen command in `README.md`.
- **Test / done check (non-Rust):** `tokens.css` exists and is non-empty; it
  defines the custom properties the widgets reference and contains **no** literal
  6-digit hex outside `$value` translation into `--*` properties (the hexes *are*
  the property values here — the AC14 ban on raw hex applies to the widget
  `*.html`, not to `tokens.css`). Verify re-running the generator reproduces the
  committed file byte-for-byte (`node build.mjs > /tmp/t && diff tokens.css
  /tmp/t`). No Rust gate impact (not compiled), but the generator must not break
  `cargo fmt/clippy/test`.
- **Done when:** the generator reproduces the committed `tokens.css` and the full
  gate still passes.

---

### Tasks 7–13: W5 — the seven widget bundles (one task each)

Each task **replaces** the Wave-1 placeholder for its widget with the full rich
HTML5 document: inlined `<style>` (importing/pasting the relevant `:root` and
dark blocks from Task 6's `tokens.css`), inlined `<script type="module">` using
the standard MCP Apps `App` bridge (`ontoolresult`/`callServerTool`) with
`window.openai` feature-detection and theme tracking (`window.openai.theme` +
`openai:set_globals`, fallback `prefers-color-scheme`, set `data-theme` on
`<html>`), and renders the tool output. **Safety (anti-goal / AC14):** every
flow-derived string written with `textContent` / safe DOM construction — never
`innerHTML`, `eval`, `new Function`, or inline `on*=` handlers; colours only via
the CSS custom properties, no literal hex. Each widget must render correctly in
both light and dark. Handlers check `event.source === window.parent` and
`jsonrpc === "2.0"`.

- **Common Satisfies:** AC14 (per-file); supports MV1/MV2 (manual)
- **Common Depends on:** Task 3 (URIs/mime/`include_str!` seam), Task 5
  (outputSchema/annotations shapes), Task 1 (`flow.table` shape), Task 6
  (`tokens.css`)
- **Common done check (non-Rust, per file):** a grep/node lint on that one file:
  begins `<!DOCTYPE html>`; contains **no** `innerHTML`, `eval`, `new Function`,
  or `on<event>=` attribute; contains **no** `#RRGGBB` literal; has exactly one
  inlined `<style>` and one `<script type="module">`; references the expected
  `toolOutput` field (below). The Rust build stays green (the `include_str!` is
  already wired by Task 3). The comprehensive AC14 test lives in Task 20.

| Task | Wave | File (modify) | Reads `toolOutput` | Palette groups |
|---|---|---|---|---|
| **7** flows table | 3 | `crates/aitm-mcp/widgets/flows.html` | `.flows[]` (from `flow.table`) | method.*, status.*, mark.*, intercept.*, agent.* |
| **8** flow detail | 3 | `crates/aitm-mcp/widgets/flow-detail.html` | `flow.detail` object | method.*, status.*, syntax.* |
| **9** findings list | 3 | `crates/aitm-mcp/widgets/findings.html` | `findings.list` **array** | severity.* |
| **10** finding detail | 3 | `crates/aitm-mcp/widgets/finding-detail.html` | `findings.get` object | severity.*, syntax.* |
| **11** scope | 3 | `crates/aitm-mcp/widgets/scope.html` | `scope.list` **array** + bridge call to `tls.passthrough.list` | accent.* |
| **12** PoC result | 3 | `crates/aitm-mcp/widgets/poc-result.html` | `poc.run`/`poc.get` object | severity.*, status.* |
| **13** proxy status | 3 | `crates/aitm-mcp/widgets/proxy-status.html` | `proxy.status` object | status.*, intercept.*, agent.*, l4.* |

- **Task 11 note:** the scope widget issues a secondary MCP Apps bridge call
  (`callServerTool` / `window.openai.callTool`) to `tls.passthrough.list` and
  renders both sections; both data shapes are top-level arrays.
- **Task 9/Task 11 note:** these read top-level **array** `structuredContent`
  (open decision 2, array-first); write the widget to also accept an
  object-wrapped shape so the MV3 fallback needs no widget change.

---

### Task 14: W6 — Claude plugin manifests + `.mcp.json`

- **Wave:** 3
- **Satisfies:** supports MV5 (manual `claude plugin validate`)
- **Depends on:** Tasks 1–5 (final tool/widget names)
- **Files:** `aitmproxy-plugin/.claude-plugin/plugin.json` (create),
  `aitmproxy-plugin/.claude-plugin/marketplace.json` (create),
  `aitmproxy-plugin/.mcp.json` (create)
- **Change:**
  - `plugin.json`: `name:"aitmproxy"` (kebab, non-reserved), `version`,
    `description`, `author{name:"Matt …"}`, `homepage`, `license`, `keywords`,
    `skills` → shared `skills/`; `commands/` auto-discovered.
  - `marketplace.json`: `name:"aitmproxy-marketplace"`, `owner`,
    `plugins:[{name:"aitmproxy", source:"."}]` (entry `name` == `plugin.json`
    `name`).
  - `.mcp.json`: `{"mcpServers":{"aitm":{"command":"${AITM_BIN:-aitm}","args":[],
    "env":{}}}}` — **`args:[]`**, since bare `aitm` is the stdio MCP server
    (verified; see Overview).
- **Test / done check (non-Rust):** each file is valid JSON (`node -e
  "JSON.parse(require('fs').readFileSync(...))"` or `jq .`); `marketplace.json`'s
  `plugins[0].name` equals `plugin.json`'s `name`; `.mcp.json` `mcpServers.aitm.args`
  is `[]`. (MV5 `claude plugin validate` runs manually in the Terminal panel.)
- **Done when:** the JSON checks pass; gate unaffected (no Rust).

---

### Task 15: W7 — OpenAI Agent-Plugins manifest

- **Wave:** 3
- **Satisfies:** supports MV1/MV5 (manual)
- **Depends on:** Tasks 1–5 (final tool names)
- **Files:** `aitmproxy-plugin/plugin.json` (create — root, OpenAI),
  `aitmproxy-plugin/mcp.json` (create — no leading dot)
- **Change:**
  - root `plugin.json`: `$schema`
    `"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"`, `name`,
    `version`, `description`, `extensions.com.openai` with
    `interface`/`onboardingSkill` → the `overview` skill. Auto-discovers
    `skills/<name>/SKILL.md`.
  - `mcp.json`: committed default `type:"stdio"`,
    `{"command":"${AITM_BIN:-aitm}","args":[]}`; include a **commented/sibling**
    documented `type:"streamable-http"`, `url:"https://<host>/mcp"` block for the
    submission path (Design H; the stdio form is the committed default).
    No hooks.
- **Test / done check (non-Rust):** both files valid JSON; root `plugin.json` has
  `extensions.com.openai.onboardingSkill == "overview"`; `mcp.json` default entry
  `args == []`. 
- **Done when:** JSON checks pass; gate unaffected.

---

### Task 16: W8 — shared skills

- **Wave:** 3
- **Satisfies:** supports MV1/MV2 (manual); the Claude-Code rendering story
- **Depends on:** Tasks 1–5 (final tool names); conceptually Task 6/Task 7–13
  (palette names) but only references names, not files
- **Files:** `aitmproxy-plugin/skills/overview/SKILL.md`,
  `aitmproxy-plugin/skills/rendering/SKILL.md`,
  `aitmproxy-plugin/skills/flows/SKILL.md`,
  `aitmproxy-plugin/skills/intercept/SKILL.md`,
  `aitmproxy-plugin/skills/findings-poc/SKILL.md`,
  `aitmproxy-plugin/skills/scope-tls/SKILL.md` (all create)
- **Change:** `overview` teaches the authorized-testing workflow (scope →
  capture → intercept/mutate → replay → findings/poc) and names the key tools per
  stage; it is also the OpenAI `onboardingSkill`. `rendering` teaches a text-only
  host (Claude Code) to turn `structuredContent` into markdown — tables for
  `flow.table`/`findings.list`, method/status/severity badges mapped to named
  palette colours/emoji/backticked labels, how to read `flow.detail`, and the
  note that on success Claude Code sees `structuredContent` not `content` text.
  The four focused skills are short per-cluster references. **Authorized-security-
  testing framing throughout.** Keep each loaded description within Claude Code's
  4,096-char trim where it matters.
- **Test / done check (non-Rust):** each `SKILL.md` exists with valid front
  matter (name/description); a content check greps each file for the
  authorized-testing framing phrase and that `rendering/SKILL.md` mentions
  `structuredContent` and the three badge families (method/status/severity).
- **Done when:** the content checks pass; gate unaffected.

---

### Task 17: W9 — Claude commands

- **Wave:** 3
- **Satisfies:** supports MV2 (manual); mirrors the mock actions
- **Depends on:** Tasks 1–5 (final tool names)
- **Files:** `aitmproxy-plugin/commands/fetch-flows.md`, `explain-request.md`,
  `generate-curl.md`, `map-remote.md`, `triage.md`, `scope.md`, `findings.md`,
  `intercept.md` (all create under `aitmproxy-plugin/commands/`)
- **Change:** each is a prompt that drives the MCP tools — `fetch-flows` →
  `flow.table`; `explain-request`/`generate-curl` → `flow.detail`; `map-remote` →
  `map.add`; `triage`/`findings` → `findings.*`; `scope` → `scope.*`;
  `intercept` → `flow.intercept`/`proxy.*`. Authorized-testing framing in each.
  Agent-side text transforms, not widgets.
- **Test / done check (non-Rust):** all eight files exist; each names at least one
  real tool from the registry and contains the authorized-testing framing phrase
  (grep check).
- **Done when:** the checks pass; gate unaffected.

---

### Task 18: W10a — tool-reference generator + generated `tool-reference.md`

- **Wave:** 4
- **Satisfies:** docs goal; no automated AC (feeds MV items)
- **Depends on:** Task 1, Task 5 (final tool set/shapes)
- **Files:** a generator — **builder's call** either a Rust example
  `crates/aitm-mcp/examples/tool_reference.rs` or a script over `aitm` CLI output
  (create); `aitmproxy-plugin/docs/tool-reference.md` (create — committed output)
- **Change:** walk the registry (or `aitm` help) and emit name/description/
  params/result per tool into `tool-reference.md`; document the regen command at
  the top of the file. If a Rust example, it must build under the gate.
- **Test / done check:** `tool-reference.md` lists every registered tool
  (including `flow.table`); re-running the generator reproduces the committed file
  (diff clean). If implemented as a Rust example, `cargo build --examples` is
  green under the gate.
- **Done when:** the regen diff is clean and the full gate passes.

---

### Task 19: W10b — prose docs: plugin README, rendering guide, security/threat model, top-level README

- **Wave:** 4
- **Satisfies:** docs goal; W1c threat-model note; supports MV1/MV2/MV6
- **Depends on:** Task 4 (HTTP transport details), Tasks 14/15 (install story),
  Task 1/5 (tool set)
- **Files:** `aitmproxy-plugin/README.md` (create),
  `aitmproxy-plugin/docs/rendering.md` (create),
  `aitmproxy-plugin/docs/security.md` (create),
  `README.md` at repo root (create)
- **Change:**
  - `aitmproxy-plugin/README.md`: orient the plugin; install+test for Claude
    Desktop (stdio), Claude Code (`claude plugin marketplace add ./aitmproxy-plugin`
    → `claude plugin install aitmproxy@aitmproxy-marketplace`, text via the
    `rendering` skill), and ChatGPT dev mode (Secure MCP Tunnel over the stdio
    server, then the streamable-HTTP transport at `http://127.0.0.1:8084/mcp`,
    the MCP Inspector check, the `chatgpt.com` add-server flow). State the bare-`aitm`
    stdio fact.
  - `docs/rendering.md`: palette mapping, the seven widget families, how each
    `structuredContent` shape maps to a widget.
  - `docs/security.md`: the W1c HTTP-transport threat model — control-plane blast
    radius, token-only authN, loopback-default, Origin+Host as the only
    DNS-rebinding defence, no in-process TLS (front with a tunnel/HTTPS),
    non-loopback bind is an explicit operator decision, and the note that the
    security reviewer must sign it off (MV6).
  - root `README.md`: short repo orientation linking `docs/` and
    `aitmproxy-plugin/`.
- **Test / done check (non-Rust):** files exist; a grep check confirms
  `security.md` contains the loopback-default, token-only, Origin+Host, and
  no-TLS points; `aitmproxy-plugin/README.md` contains the three host sections and
  the `:8084/mcp` endpoint; root `README.md` links `aitmproxy-plugin/`.
- **Done when:** the content checks pass; gate unaffected.

---

### Task 20: W11 — full test harness: comprehensive widget-lint + protocol/validate coverage

- **Wave:** 4
- **Satisfies:** AC14 (comprehensive); closes any AC coverage gap; MV5 doc step
- **Depends on:** Tasks 7–13 (all real widgets present), Tasks 1–5 (protocol),
  Task 4 (HTTP e2e already in Task 4 — do not duplicate)
- **Files:** `crates/aitm-mcp/tests/widget_lint.rs` (create); extend
  `crates/aitm-mcp/tests/mcp.rs` only if a protocol AC is still uncovered; a
  `claude plugin validate` doc-step line added to `aitmproxy-plugin/README.md`'s
  test section (if not already present from Task 19 — coordinate: Task 19 owns
  that file, so this task instead records MV5 in the plan's Shipped checklist and
  does not edit README).
- **Change:** `widget_lint.rs` walks every committed
  `crates/aitm-mcp/widgets/*.html` and asserts, per file: no `innerHTML`, `eval`,
  `new Function`, or inline `on*=` handler; and no literal 6-digit hex colour
  outside the inlined token block (colours via CSS custom properties). This is the
  single comprehensive AC14 gate; the per-widget checks in Tasks 7–13 are the
  fast local version.
- **Test:** `fn no_unsafe_dom_in_widgets()` and `fn no_literal_hex_in_widgets()`
  in `widget_lint.rs`, each iterating the seven files and asserting the bans. The
  expected value: both tests pass over all seven committed widgets.
- **Done when:** the lint tests pass over all seven real widgets and the full gate
  passes.

---

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.

**Manual verification checklist (MV1–MV6 — Matt only, post-merge; not merge gates):**

- [ ] **MV1** ChatGPT dev mode: add the server (Secure MCP Tunnel over stdio,
      then the HTTP transport); confirm each widget renders richly and light/dark
      track the host theme.
- [ ] **MV2** Claude Desktop / claude.ai: widgets render over stdio; Claude Code:
      clean text output and `ui://` resources do not pollute `@`-completion.
- [ ] **MV3** ChatGPT accepts `text/html;profile=mcp-app`; if it rejects the
      array `structuredContent`/`outputSchema` on `findings.list`/`scope.list`,
      trigger the open-decision-2 fallback (object-wrapping `findings.table`/
      `scope.summary` render tools; the widgets already read both shapes).
- [ ] **MV4** No client rejects `_meta` keys containing `/`; Claude Code ignores
      unknown `_meta`.
- [ ] **MV5** `claude plugin validate ./aitmproxy-plugin` in the Terminal panel
      returns "Validation passed"; install and list the plugin locally.
- [ ] **MV6** Security reviewer signs off the HTTP-transport threat model
      (`aitmproxy-plugin/docs/security.md`) before any non-loopback use.
</content>
</invoke>
