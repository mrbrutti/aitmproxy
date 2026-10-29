# Operator-token UX across the standalone bus frontends implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Status:** approved (2026-10-29 by Matt); implemented, panel-reviewed, fixes applied
**Spec:** `docs/superpowers/specs/2026-10-29-operator-token-ux-design.md` (approved 2026-10-29)
**Branch / worktree:** `feat/operator-token-ux` (one worktree, cut from the plan
branch; parallel tasks get child worktrees per
`superpowers:using-git-worktrees`, merged back when their panel passes)

## Overview

The server's two-token role model is done; this change is client-side UX plus
two small server-adjacent wirings. Work splits into three waves. **Wave 1**
(parallel, disjoint files): the bus-client `role` field (Task 1), the server
`initialize` role echo (Task 2), and the mac app operator-token UX (Task 7).
**Wave 2** (parallel, disjoint files): the TUI operator UX (Task 3, needs Task 1)
and the web `/bus` role routing + `WebState` split (Task 4, needs Task 2; owns
`crates/aitm/src/main.rs`). **Wave 3** (parallel, disjoint files): the
generate-and-store command (Task 5, needs Task 4 — it shares
`crates/aitm/src/main.rs` and `lib.rs`) and the web UI role banner (Task 6,
needs Task 4). Within a wave no two tasks write the same file.

## Global Constraints

Every task's requirements implicitly include these (copied from the spec):

- **Additive / back-compatible.** New fields are optional; old single-token
  agent clients and the current `initialize` result shape keep working. A
  missing `role` means "role unknown", never an assertion of a role.
- **Agent gate intact.** The agent-policy gate stays fully enforced for
  `Frontend::Mcp`; an agent must never reach operator privilege.
- **Role is token-class driven.** No client declares its role; it presents a
  token and the server/bridge classifies it. No new wire field lets a client
  ask for a role. `--expect-role`/the mac picker/the web `expect` fragment are
  **client-side only**, never sent to the server, and only drive a warning.
- **Constant-time token comparison only.** Tokens are checked with
  `classify_token` / `token_line_matches` / `constant_time_eq`; no task adds a
  non-constant-time compare.
- **Token never printed/logged.** No task prints or logs the mcp agent or
  operator token at the default log level. (The *web bridge* token is an
  ephemeral per-run generated token and is allowed in the start-up URL, exactly
  as the agent URL already is.)
- **The two role wire strings are exactly `"operator"` and `"agent"`**
  (`Frontend::Operator` → `"operator"`, every other `Frontend` → `"agent"`).
- **Rust gate per task:** `cargo fmt --check && cargo clippy --all-targets -- -D
  warnings && cargo test` must pass. `unsafe` needs a `// SAFETY:` comment and
  reviewer sign-off (none expected here).
- **Mac tooling** per `apps/mac/CLAUDE.md`: `./build.sh`, `swift test
  --scratch-path …`, `tools/selftest-live.sh`, `tools/snap.sh` + grid lint.
  **Web tooling** per `apps/web/package.json`: `npm run typecheck`, `npm test`
  (vitest), `npm run build`.

## Review Focus

Inputs the spec implies but no task's happy path exercises, most likely to bite
first. Each has a test added to the owning task.

- **Empty-string `operator_token` in config** (`operator_token: ""`, hand-edited)
  must be treated as *not configured* — it must not enable operator and must not
  let an empty presented token match. → Task 2 test.
- **Operator URL opened but connection resolves to agent** (operator not
  configured, or wrong token) must warn, not silently proceed as agent. → Task
  6 test (web) and Task 3 test (TUI).
- **`operator-token generate` on an unusual config file** (CRLF line endings,
  tabs, trailing comments, no `mcp:` block, inline `mcp: {…}` flow mapping) must
  either edit cleanly or refuse with a clear error — never corrupt the file or
  silently drop keys. → Task 5 tests.
- **`--expect-role` with a bad value** (`--expect-role admin`, empty) must error
  clearly, not panic or be ignored. → Task 3 test.
- **Mac operator token set while config still has an agent token**: the app must
  present the operator token and show the resolved role, warning on mismatch,
  not silently use the config agent token. → Task 7 test.

---

## Tasks

### Task 1: bus-client `ServerInfo.role`

- **Satisfies:** AC7 (TUI reads the echoed role), AC10 (additive).
- **Depends on:** none. **Parallel-safe** (Wave 1).
- **Files:**
  - Modify: `crates/aitm-bus-client/src/lib.rs` (`ServerInfo`, `BusClient::initialize`).
- **Interfaces produced:** `ServerInfo` gains `pub role: Option<String>`
  (`Some("operator")`, `Some("agent")`, or `None` when the server did not echo);
  `initialize` populates it from the top-level `result.role`.
- **Change:** add the field to `ServerInfo`; in `initialize`, after reading
  `serverInfo`, set `role: result.get("role").and_then(Value::as_str).map(str::to_string)`.
  Do not make it required — a missing `role` is `None`, not an error.
- **Test:** in the `lib.rs` test module, over a stub `BusTransport` whose
  `initialize` reply is `{"protocolVersion":"…","serverInfo":{"name":"aitmproxy","version":"x"},"role":"operator"}`:
  - `test_initialize_reads_role` → `info.role == Some("operator".to_string())`.
  - `test_initialize_missing_role_is_none` with the same reply minus `role` →
    `info.role == None` and the call still `Ok` (AC10).
- **Done when:** both tests pass and the full gate passes.

### Task 2: server `initialize` role echo

- **Satisfies:** AC6 (role echoed on LoopbackTcp), AC10 (additive). Review
  Focus: empty `operator_token` not configured.
- **Depends on:** none. **Parallel-safe** (Wave 1).
- **Files:**
  - Modify: `crates/aitm-mcp/src/server.rs` (`dispatch` `"initialize"` arm; add a
    private `fn role_str(role: Frontend) -> &'static str`).
- **Interfaces produced:** the `initialize` result object gains a top-level
  `"role"` key alongside `"protocolVersion"`.
- **Change:** add `fn role_str(role: Frontend) -> &'static str` returning
  `"operator"` for `Frontend::Operator` and `"agent"` for every other variant;
  insert `"role": role_str(conn.role)` into the `json!({…})` the `"initialize"`
  arm returns. `conn` is already in scope. Confirm (do not change) that
  `classify_token` treats an empty/absent `operator_token` as "no operator
  token" so an empty presented token never resolves to operator.
- **Test:** in `server.rs` tests, build a server and call `handle_on`:
  - `initialize_echoes_operator_role`: `handle_on(&ConnCtx::new(Frontend::Operator), <initialize>)`
    → parsed `result["role"] == "operator"`.
  - `initialize_echoes_agent_role`: `handle_on(&ConnCtx::agent(), <initialize>)`
    → `result["role"] == "agent"`.
  - `empty_operator_token_is_not_operator`: a server built with
    `with_mcp_roles(Some(String::new()), Frontend::Mcp)` classifies a presented
    empty token line as **not** operator (resolves to agent / refused per the
    transport's existing contract), so no empty-token path yields `"operator"`.
- **Done when:** the three tests pass and the full gate passes.

### Task 3: TUI operator UX (`--expect-role`, role display, reworded refusal)

- **Satisfies:** AC1, AC2 (operator/agent over the bus — already works; this
  surfaces it), AC7 (role shown in status line), AC8 (mismatch warns), AC13
  (token never printed). Review Focus: operator expected but agent resolved;
  bad `--expect-role` value.
- **Depends on:** Task 1 (consumes `ServerInfo.role`). **Parallel-safe with Task
  4** (disjoint files; `crates/aitm-tui/*` only). (Wave 2.)
- **Files:**
  - Modify: `crates/aitm-tui/src/main.rs` (`Args`, `parse`, `USAGE`).
  - Modify: `crates/aitm-tui/src/bus.rs` (`REFUSED`, carry role into `Connected`).
  - Modify: `crates/aitm-tui/src/action.rs` (`BusEvent::Connected`).
  - Modify: `crates/aitm-tui/src/app.rs` (`BusStatus::Connected`, mismatch flag).
  - Modify: `crates/aitm-tui/src/render.rs` (status-line role indicator).
- **Interfaces consumed:** `ServerInfo.role: Option<String>` (Task 1).
- **Interfaces produced:** `Args.expect_role: Option<String>`;
  `BusEvent::Connected { server, tools, role: Option<String> }`;
  `BusStatus::Connected { server, address, role: Option<String> }`.
- **Change:**
  - `Args` gains `expect_role: Option<String>`; `parse` handles `--expect-role
    <agent|operator>` and rejects any other value with a usage error; `USAGE`
    documents it.
  - `bus.rs`: reword `REFUSED` to a string that does not imply the token must
    come from a file and reads for either intended role, e.g. `"bus refused the
    token: it matched neither the agent nor the operator token (check the token
    you supplied)"`. Pass `info.role` into the emitted `Connected`.
  - `action.rs`/`app.rs`: thread `role` through; when `expect_role` is `Some` and
    differs from the resolved role (or the resolved role is `None`), set a
    visible mismatch warning on the status/toast.
  - `render.rs`: show the resolved role (and the warning when set) in the status
    line.
- **Test:**
  - `main.rs`: `parse(["--bus","127.0.0.1:9090","--token","t","--expect-role","operator"])`
    → `Args.expect_role == Some("operator".to_string())`;
    `parse([… ,"--expect-role","admin"])` → `Err` containing `expect-role`.
  - `app.rs` (model): feeding `BusEvent::Connected { role: Some("agent"), … }`
    with `expect_role == Some("operator")` sets the mismatch warning
    (`assert!(app.<warning accessor>())`); with matching roles it does not.
  - A test asserting the new `REFUSED` literal (so the reword is pinned).
- **Done when:** the tests pass and the full gate passes.

### Task 4: web `/bus` role routing + `WebState` split

- **Satisfies:** AC3 (web operator runs Sensitive), AC4 (web agent gated), AC6
  (role echoed through the bridge), AC9 (`-32001` on unknown token), AC11/AC12
  (agent-only when operator not configured), AC16 (operator URL uses an
  ephemeral bridge token).
- **Depends on:** Task 2 (role echo makes the browser's `initialize` reply carry
  `role`). **Parallel-safe with Task 3** (disjoint files). **Owns
  `crates/aitm/src/main.rs`** this wave. (Wave 2.)
- **Files:**
  - Modify: `crates/aitm/src/web/mod.rs` (`WebState`; add `operator_ui_url`).
  - Modify: `crates/aitm/src/web/bridge.rs` (`relay` token classify, `dispatch`).
  - Modify: `crates/aitm/src/main.rs` (construct `WebState`, print operator URL).
- **Interfaces produced:**
  - `WebState { mcp: Arc<McpServer>, agent_token: String, operator_token: Option<String> }`
    (the field `token` is renamed to `agent_token`).
  - `pub fn operator_ui_url(bound: SocketAddr, token: &str) -> String` returning
    `http://{bound}/#t={token}&expect=operator` (agent `ui_url` unchanged).
- **Change:**
  - `WebState`: rename `token` → `agent_token`; add `operator_token: Option<String>`.
  - `bridge.rs relay`: classify the first-line token in constant time —
    `token_line_matches(first, &state.agent_token)` → `Frontend::Mcp`; else if
    `state.operator_token.as_deref()` is `Some(op)` and
    `token_line_matches(first, op)` → `Frontend::Operator`; else refuse with the
    existing `UNAUTHORIZED_REPLY` (`-32001`). Carry the resolved `Frontend`
    through to `dispatch`.
  - `bridge.rs dispatch`: call `srv.handle_on(&ConnCtx::new(role), &line)` instead
    of `srv.handle(&line)`.
  - `main.rs`: when `cfg.mcp.operator_token.is_some()`, generate an operator
    **bridge** token via `web::generate_token()`, set `WebState.operator_token`,
    and `println!` the operator URL via `operator_ui_url` next to the existing
    agent URL; when `None`, `operator_token: None` and only the agent URL prints.
    The mcp `operator_token` value is never put in a URL or log.
- **Test:** in `crates/aitm/tests/` (new `web_bus_roles.rs`) or `bridge.rs`
  tests, drive `relay`/`dispatch` with a `WebState` holding distinct agent and
  operator bridge tokens:
  - operator bridge token then an `initialize` line → reply `result["role"] ==
    "operator"`.
  - agent bridge token then `initialize` → `result["role"] == "agent"`.
  - unknown token → the `-32001` unauthorized reply and the socket closes.
  - `WebState.operator_token == None` + operator bridge token → refused `-32001`
    (operator-off-by-default, AC12).
  - `operator_ui_url(addr, "deadbeef")` → literal
    `"http://127.0.0.1:8082/#t=deadbeef&expect=operator"` for `addr =
    127.0.0.1:8082`.
- **Done when:** the tests pass and the full gate passes.

### Task 5: `aitm operator-token generate` command

- **Satisfies:** AC14 (writes config), AC15 (quiet, non-destructive by default),
  AC12 (still off by default until run). Review Focus: unusual config files.
- **Depends on:** Task 4 (shares `crates/aitm/src/main.rs` and
  `crates/aitm/src/lib.rs`). **Parallel-safe with Task 6** (disjoint files).
  (Wave 3.)
- **Files:**
  - Create: `crates/aitm/src/operator_token.rs`.
  - Modify: `crates/aitm/src/lib.rs` (`pub mod operator_token;`).
  - Modify: `crates/aitm/src/main.rs` (`parse_mode` recognises `operator-token`;
    `run` dispatches before services are built).
- **Interfaces produced:**
  - `pub fn insert_operator_token(yaml: &str, token: &str, force: bool) -> Result<String, OperatorTokenError>`
    — a **pure** function: returns the new file text with `mcp.operator_token`
    set to `token`, preserving all other content; creates a `mcp:` block if
    absent; `Err(OperatorTokenError::AlreadySet)` when a non-empty
    `operator_token` exists and `!force`.
  - `pub fn generate_and_store(config_path: &Path, force: bool) -> anyhow::Result<PathBuf>`
    — reads the file, calls `insert_operator_token` with a freshly generated
    CSPRNG token, writes it back, returns the path. Errors if the file is absent.
  - `pub enum OperatorTokenError { AlreadySet, NoConfigFile, … }`.
- **Change:** `parse_mode` returns a new `Mode::OperatorToken { force: bool }`
  for argv starting with `operator-token generate` (reject unknown sub-verbs with
  a usage line; accept `--force`). In `run`, before building services, resolve
  the config path exactly as the binary already does (`--config`, `AITM_CONFIG`,
  default), call `generate_and_store`, then print a confirmation naming the path
  and that operator access is enabled and the proxy must be restarted — **never**
  the token. Generate the token with a CSPRNG (non-empty).
- **Test:** unit tests on the pure function in `operator_token.rs`:
  - `inserts_into_existing_mcp_block`: input a YAML string with an `mcp:` block
    and no `operator_token`; call with `token="abc123"`, `force=false`; assert
    `config_file::parse(&out).unwrap().mcp.operator_token == Some("abc123".into())`
    and that an unrelated top-level key present in the input is still present in
    `out`.
  - `creates_mcp_block_when_absent`: input YAML with no `mcp:` key →
    `parse(&out).unwrap().mcp.operator_token == Some("abc123".into())`.
  - `refuses_existing_without_force`: input YAML already carrying
    `operator_token: old` → `Err(OperatorTokenError::AlreadySet)` and the token
    is unchanged.
  - `force_replaces_existing`: same input with `force=true`, `token="new999"` →
    `parse(&out).unwrap().mcp.operator_token == Some("new999".into())`.
  - `preserves_crlf_and_comments`: input with a trailing `# comment` line and
    CRLF endings → the comment line survives in `out`.
  - A test that the confirmation-message builder contains the config path and
    does **not** contain the token value (AC15, AC13).
- **Done when:** the tests pass and the full gate passes.

### Task 6: web UI resolved-role banner

- **Satisfies:** AC7 (web shows role), AC8 (mismatch warns). Review Focus:
  operator URL opened but resolved agent.
- **Depends on:** Task 4 (bridge routing + `operator_ui_url`'s `expect=operator`
  fragment) and Task 2. **Parallel-safe with Task 5** (disjoint files;
  `apps/web/*` only). (Wave 3.)
- **Files:**
  - Modify: `apps/web/src/bus/types.ts` (`ServerInfo`/initialize result type gains
    `role?: 'operator' | 'agent'`).
  - Modify: `apps/web/src/bus/index.ts` (read `expect` from the `#…` fragment
    alongside `t`).
  - Modify: `apps/web/src/bus/ws.ts` (read `result.role` from `initialize`,
    expose resolved role + expectation on the bus client).
  - Modify/Create: the role-banner UI component and its wiring (existing web UI
    conventions; builder's visual design per the spec's "left to the builder").
- **Interfaces produced:** the bus client exposes the resolved role (from
  `initialize` result `role`) and the `expect` fragment value; a mismatch flag
  is `true` when `expect` is set and differs from the resolved role (or the
  server echoed no role).
- **Change:** parse `expect` from the fragment in `createBus` (store beside the
  token; strip from the URL as the token already is). In `ws.ts`, capture
  `result.role` during `initialize`. The banner shows the resolved role and a
  warning when the mismatch flag is set.
- **Test (vitest):**
  - `reads_role_from_initialize`: a mocked `initialize` reply with
    `role: 'operator'` → the client's resolved role is `'operator'`.
  - `mismatch_when_expect_operator_but_agent`: `expect='operator'` with a reply
    `role: 'agent'` → mismatch flag `true`; matching roles → `false`.
  - `missing_role_with_expectation_warns`: reply with no `role` and
    `expect='operator'` → mismatch flag `true` (cannot confirm).
- **Done when:** the vitest suite passes, `npm run typecheck` and `npm run build`
  pass.

### Task 7: mac app operator-token entry + role display

- **Satisfies:** AC5 (mac operator/agent over the live bus), AC7 (mac shows
  role), AC8 (mismatch warns), AC13 (token never logged). Review Focus: operator
  token set while config has an agent token.
- **Depends on:** Task 2 for the live AC5/AC7 end-to-end (role echo). **Code is
  parallel-safe** (Wave 1; `apps/mac/*` only, disjoint from every other task).
- **Files:**
  - Modify: `apps/mac/Sources/AitmBusClient/ToolDescriptor.swift` (`ServerInfo`).
  - Modify: `apps/mac/Sources/Aitmproxy/SettingsView.swift` (`BusSettings`).
  - Modify: `apps/mac/Sources/Aitmproxy/Session.swift` (use operator token;
    resolved-role state; mismatch warning).
  - Modify (if needed): `apps/mac/Sources/AitmBusClient/BusEndpoint.swift`
    (operator-token source).
  - Test: `apps/mac/Tests/AitmproxyKitTests/…` (ServerInfo parse + mismatch).
- **Interfaces produced:** `ServerInfo.role: String?` read from
  `result["role"]?.stringValue`.
- **Change:** `ServerInfo(initializeResult:)` reads `role`. `BusSettings` adds a
  `SecureField` operator-token entry (never logged) and an "Expected role"
  `Picker` (agent/operator), per `apps/mac/CLAUDE.md` (grouped `Form`, system
  styles, menu item + shortcut for any new action, no hard-coded colors).
  `Session` presents the operator token when set (otherwise the config agent
  token), surfaces the resolved role as a status element (`Label`/status text),
  and warns when the expected and resolved roles differ.
- **Test:**
  - `swift test`: `ServerInfo(initializeResult:)` on a result containing
    `"role":"operator"` → `info.role == "operator"`; without `role` → `nil`.
  - A mismatch-logic test: expected `.operator`, resolved `"agent"` → the
    mismatch flag is set.
  - Per CLAUDE.md: `./build.sh` clean, `tools/snap.sh` + `tools/grid-lint.sh`
    PASS (look at light/dark Settings snapshots), and `tools/selftest-live.sh`
    against a live `aitm` with `mcp.operator_token` configured proves AC5 (a
    Sensitive action succeeds as operator, is gated as agent).
- **Done when:** `swift test` passes, the build is clean, snapshots and grid
  checks pass, and the live self-test proves the operator/agent paths.

---

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|
| whole branch | security + spec | **Important** | Empty-string `operator_token: ""` enabled the web operator path (`main.rs` gated on `.is_some()` while loopback filters empty); violates AC12 | Fixed in 2e96e5a — non-empty gate + web empty-string test |
| whole branch | security | Minor | `generate_and_store` overwrote config non-atomically / followed symlinks | Fixed in 2e96e5a — write-temp-then-rename |
| whole branch | quality | Minor | `asRole` role-narrowing duplicated in web `ws.ts` | Fixed in 2e96e5a — exported and reused |
| whole branch | quality | Minor | YAML editor matched `operator_token:` at any depth in the `mcp:` block | Fixed in 2e96e5a — direct-child indent check + nested-key test |
| whole branch | quality | Minor | `generate_operator_token` comment overstated entropy (256 vs ~244 bits) | Fixed in 2e96e5a — comment reworded |
| whole branch | spec | **Important** | Unrequested mac "Reconnect Bus" command + `⌃⌘R` in undeclared files | Accepted by Matt 2026-10-29 — it applies a pasted operator token without an app restart; `apps/mac/CLAUDE.md` requires a menu item + shortcut per action |
| whole branch | quality | Minor | mac picker cannot return to "no expectation" once set | Accepted by Matt 2026-10-29 — default-unset reads as no-warning; behavior safe |
| whole branch | quality | Minor | mac mismatch warning recomputed only on (re)connect | Accepted by Matt 2026-10-29 — explicit Reconnect affordance covers it |
| whole branch | spec | Minor | status-line role indicator landed in `ui/bars.rs`, not the plan's named `render.rs` | Accepted 2026-10-29 — plan filename was wrong; code is in the correct place |
| whole branch | spec | Minor | several undeclared files touched to propagate declared interface changes | Accepted 2026-10-29 — required consequence of the declared signatures, not scope creep |
| whole branch | spec | Minor | AC3/AC4/AC13 covered indirectly (role echo + pre-existing M4 `Frontend` gate) rather than a literal `flow.intercept` assertion | Accepted 2026-10-29 — causal chain holds; the gate is M4-tested on `Frontend` |

## Shipped

- **Merged into `feat/operator-token-ux`** (Waves 1–3 + panel fix): the additive `initialize` `role` echo (server); `ServerInfo.role` in the Rust bus client; TUI `--expect-role`, status-line role indicator and reworded refusal; web `/bus` role routing (two bridge tokens, `handle_on` dispatch) + resolved-role banner; mac operator-token Settings entry, resolved-role display, mismatch warning and Reconnect Bus; and the CLI-only `aitm operator-token generate [--force]`. All 16 acceptance criteria implemented and tested.
- **Gate:** whole-branch `cargo fmt --check && cargo clippy --all-targets -D warnings && cargo test` green (one load-sensitive flake, green in isolation); web `typecheck` + 293 vitest green.
- **Cut:** nothing.
- **Follow-ups:** `main` advanced ~40 commits during the work; landing this branch needs a merge-conflict resolution in 4 files (`crates/aitm/src/main.rs` + 3 `apps/mac` Swift files). PR opened against `main`; conflicts to be resolved at merge time.
