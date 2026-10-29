# Operator-token UX across the standalone bus frontends design

**Status:** approved (2026-10-29 by Matt) — open questions resolved: **F2** (a generate-and-store operator-token command that writes the token into `config.yaml` without printing it) and **web operator access tied to `mcp.operator_token` being configured** (no separate `aitm web` opt-in).
**Research inputs:** `docs/research/05-synthesis.md`, `docs/research/MEMORY.md`,
`docs/superpowers/specs/2026-10-27-aitmproxy-m4-agent-milestone-design.md`
(the agent-policy gate and the two-token role model this spec builds on).

## Intent

M4 gave the MCP server a two-token role model: a connection that presents the
**operator token** is `Frontend::Operator` and bypasses the agent-policy gate
(and gets the D4 confirm-over-the-wire handshake); a connection that presents
the **agent token** is `Frontend::Mcp` and is gated. The server side is
complete and correct. But only the *embedded* `aitm tui` runs as operator
(in-process, `Frontend::Operator`); the three **standalone bus frontends** —
`aitm-tui --bus`, the web `/bus` bridge, and the mac app — have no operator
path or no role feedback, so a human sitting at one of them is treated as an
agent and cannot arm intercept, mutate, resume, or kill. This change gives a
human operator at each standalone frontend a clear, consistent way to
authenticate as operator and to see which role they got, while a genuine agent
stays gated. It is almost entirely client-side UX and wiring; the server model
does not change.

## Goals

- A human operator at `aitm-tui --bus`, the web UI, and the mac app can connect
  as operator and run a Sensitive command (e.g. `flow.intercept`) that an agent
  is refused.
- Each of those frontends still connects as a plain agent when given the agent
  token, and is gated exactly as today.
- Each frontend shows the operator which role the connection resolved to, and
  warns when they expected operator but got agent.
- An agent can never self-promote to operator through any of these surfaces.
- Existing single-token agent clients keep working unchanged (additive, back
  compatible).

## Non-goals

- Remote-operator authentication. The bus is loopback-only; the token travels
  cleartext on loopback today and the TLS bus is core follow-up F15. This spec
  designs nothing for off-loopback operator auth.
- Changing the role/gate model, the classification rules, the confirm-over-the-
  wire handshake, or the policy gate. Those are done and stay as they are.
- Auto-generating or auto-enabling the operator token. Operator access is
  **off by default** by design; this spec does not flip that default.
- Server-side change beyond the single additive `initialize` role echo
  (Decision C) and the wiring needed to route the web bridge by role.

## Anti-goals

- A frontend that *claims* to put you in operator mode but silently connects as
  agent, so the operator thinks a Sensitive command will work and it is refused
  with a confusing message. Silent role mismatch is the failure this change
  exists to prevent.
- Any path by which presenting the agent token, or no token, yields operator
  privileges on any frontend.
- Printing or logging the operator (or agent) token to the terminal or logs,
  violating the operator-first-run hygiene rule.
- New required flags or config that break the current single-token agent
  clients.

## Constraints

- **Loopback-only posture.** Do not design remote-operator auth. `aitm-tui`
  already refuses a non-loopback bus without `--allow-remote-bus`; keep that.
- **Agent gate intact.** The agent-policy gate must stay fully enforced for
  `Frontend::Mcp`. An agent must never reach operator privilege.
- **Additive / back-compatible.** Old single-token agent clients, and the
  current `initialize` result shape, keep working. New fields are optional and
  ignored by clients that do not read them.
- **Minimize server-side change.** The only sanctioned server change is the
  optional `initialize` role echo (Decision C). Everything else is client UX
  plus wiring the web bridge to dispatch by role.
- **Operator-first-run hygiene.** Quiet default logs; never print/log the
  token; keep the client-vs-server relationship obvious (the frontend is a
  client of the proxy's bus).
- **Constant-time token comparison** stays the only way tokens are checked
  (`classify_token` / `token_line_matches` / `constant_time_eq`).

## Design

### What is already in place and unchanged

Verified in source; this spec depends on it and does not touch it:

- `McpConfig { agent_token, operator_token: Option<String>, stdio_role, policy }`
  — `crates/aitm-core/src/config.rs:268`. `operator_token` is `None` by default.
- YAML surfaces both — `crates/aitm/src/config_file.rs:432` (`operator_token`,
  `stdio_role: agent|operator`).
- `classify_token(line, agent, operator)` (constant time) returns
  `Frontend::Operator` for the operator token, `Frontend::Mcp` for the agent
  token, `None` otherwise — `crates/aitm-mcp/src/transport.rs:248`.
  `LoopbackTcp::with_operator_token` / `McpServer::with_mcp_roles` wire it.
- Operator bypasses the gate and gets the confirm handshake; role is read from
  `conn.role` in `run_tool`/`call_tool` — `crates/aitm-mcp/src/server.rs:1162`.
- `McpServer::handle_on(conn, msg)` dispatches against a role; `handle(msg)` is
  the back-compat wrapper that uses `ConnCtx::agent()` —
  `crates/aitm-mcp/src/server.rs:1075`.
- The LoopbackTcp transport already classifies the first-line token and serves
  with the resolved role. So **`aitm-tui --bus` and the mac app already become
  operator when they present the operator token** — they connect straight to
  LoopbackTcp. Their gap is feedback, not capability. The **web bridge is the
  one functional gap**: it is hard-wired to agent (below).

### Decision A — the role model stays token-class driven

A client never *declares* its role to the server. It presents a token; the
server classifies the token and assigns the role. Every decision below respects
that: no new wire field lets a client ask for a role, and the agent gate stays
the server's to enforce.

### Decision B — how the operator supplies the token *(Architect's call)*

**Keep one token input per frontend; the token's class decides the role.** No
frontend gains a flag that *sets* a role. Rationale: it matches Decision A (the
server classifies; the client cannot pick), it adds zero new wire or server
surface, and existing single-token agent clients are unaffected — the same
`--token`/`--token-file`/`AITM_BUS_TOKEN` (CLI), config token (mac), or bridge
token (web) simply resolves to operator when it is the operator token.

To close the silent-mismatch anti-goal, add an **optional client-side
*expectation*** that is checked against the echoed role (Decision C), never sent
to the server and never deciding anything:

- `aitm-tui --bus`: a new optional flag `--expect-role <agent|operator>`.
- mac app: an "Expected role" choice alongside the token field in Settings.
- web: the launch that produced the operator URL knows the expectation; the UI
  banner (below) compares it to the echoed role.

When the expectation is set and the resolved role differs (or cannot be
confirmed because the server did not echo a role), the frontend shows a visible
warning instead of failing silently. When no expectation is set, the frontend
just displays the resolved role. The exact flag/field *names* are the
Architect's call and are reversible; the *shape* (one token input + optional
expectation + visible resolved role) is the decision.

### Decision C — echo the resolved role in `initialize` *(Architect's call; the one sanctioned server change)*

The `initialize` result gains one **optional, additive** top-level field,
`role`, a string that is `"operator"` or `"agent"`
(`Frontend::Operator` → `"operator"`, `Frontend::Mcp` → `"agent"`). It is
emitted for every bus connection. It sits at the top level of the result
alongside `protocolVersion` (not inside `serverInfo`) because it describes
*this connection*, not the server's identity, and because both the Rust and
Swift clients already read a top-level sibling (`protocolVersion`) during
`initialize`, so the parse is symmetric and low-risk.

- Server: `McpServer::dispatch`'s `"initialize"` arm already has `conn` in
  scope; it adds `"role": <conn.role mapped to the string>` to the result
  object. Nothing else server-side changes.
- Back-compat: the field is additive. A client built before this change ignores
  it. A client built after this change treats a **missing** `role` as "role
  unknown" and, if an expectation was set, warns that it could not be confirmed
  rather than asserting a role.
- Clients: `aitm-bus-client::ServerInfo` (`crates/aitm-bus-client/src/lib.rs:366`)
  and the mac `ServerInfo` (`apps/mac/Sources/AitmBusClient/ToolDescriptor.swift:2`)
  each gain an optional `role` field read from the result; the web UI reads
  `result.role`. This is the mechanism every surface uses to display the role
  and to implement Decision B's mismatch warning. It is the only server change
  the spec allows beyond web-bridge wiring.

### Decision D — route the web `/bus` bridge by role *(Architect's call)*

Today the bridge authenticates one `state.token` (a separate 64-hex *bridge*
token, generated at `crates/aitm/src/web/mod.rs:163`, distinct from the mcp
agent/operator tokens) and dispatches every line via `srv.handle(&line)`, the
`ConnCtx::agent()` wrapper — so the browser is always an agent.

**Keep the bridge token separate from the mcp tokens, and carry two role-tagged
bridge tokens.** The mcp agent/operator tokens must never travel to the
browser; the bridge-token indirection is deliberate and stays. Concretely:

- `WebState` (`crates/aitm/src/web/mod.rs:55`) gains a second, optional bridge
  token: it holds `agent_token: String` (as today, renamed from `token` for
  clarity — Architect's call) and `operator_token: Option<String>`. Both are
  the bridge's own tokens, not the mcp tokens.
- The relay classifies the presented first-line token in constant time against
  both bridge tokens: a match on the operator bridge token resolves to
  `Frontend::Operator`, a match on the agent bridge token to `Frontend::Mcp`,
  anything else is refused `-32001` exactly as today. `token_line_matches` /
  `constant_time_eq` stay the comparison primitives.
- `dispatch` (`crates/aitm/src/web/bridge.rs:176`) calls
  `srv.handle_on(&ConnCtx::new(role), &line)` with the resolved role instead of
  `srv.handle(&line)`. Because `dispatch` now carries the role, the browser's
  own `initialize` reply automatically carries the correct `role` (Decision C),
  so the UI can show its role banner for free.
- The operator bridge token exists **only when operator access is enabled for
  the web UI**, which is gated on whether `mcp.operator_token` is configured
  (operator role exists at all) — **Q2, resolved: tied to config, no separate
  `aitm web` opt-in**. "Operator configured ⇒ web offers an operator URL" is
  the behavior; there is no `aitm web` flag that enables or disables the
  operator path independently of `mcp.operator_token`. When operator is not
  configured, `WebState` has `operator_token: None`, the only bridge token is
  the agent one, and the web UI is agent-only exactly as today.
- Launch: when operator access is enabled, `aitm web` produces a second launch
  URL carrying the operator bridge token in the fragment (mirroring the
  existing `ui_url` agent URL, `crates/aitm/src/web/mod.rs:173`); the UI moves
  it into sessionStorage as today. The operator obtains that URL exactly as
  they obtain the agent URL today: `aitm web` already prints the agent URL with
  its bridge token in the fragment (`crates/aitm/src/main.rs`, `println!("web
  UI: {url}")`), because the **bridge** token is an ephemeral, per-run,
  generated token — distinct from the secret mcp operator token and never the
  value the hygiene rule protects. The operator URL is printed the same way.
  The mcp `operator_token` itself never travels to the browser and is never
  printed. This resolves Decision F's web half (see Decision F below).
- UI: the web UI shows a banner/status with the resolved role from
  `result.role`, and warns if the operator opened the operator URL but
  connected as agent.

### Decision E — mac operator-token entry and role display *(Architect's call)*

Per `apps/mac/CLAUDE.md`: Apple controls and system styles, one Settings tab
per topic in a grouped `Form`, a menu item + shortcut for every action, role
shown with system components (`Label`, status text), no hard-coded colors.

- The app keeps reading the agent token from config.yaml
  (`mcp.transport.loopback_tcp.token`) as the default, so it stays agent by
  default and existing installs are unaffected (`BusEndpoint.fromConfigFile`,
  `apps/mac/Sources/AitmBusClient/BusEndpoint.swift`).
- Settings gains an optional **operator token** entry (a `SecureField`, never
  echoed to logs) and an **Expected role** choice (Decision B). When the
  operator pastes the operator token, the app presents that token; its class
  makes the connection operator. `--token`/`--token-file` via
  `BusEndpoint.fromArguments` already lets a launch supply the operator token
  with no code change.
- The app shows the **resolved role** (from `ServerInfo.role`, Decision C) in
  the UI as a status element, and warns when the expected role and the resolved
  role differ. The exact Settings layout and the status element are left to the
  builder with the mac design skills; the behavior (optional operator token
  entry, resolved-role display, mismatch warning) is the decision.

### Decision F — a generate-and-store operator-token command *(resolved: F2; Architect's call on shape)*

The operator needs a way to turn operator access on without hand-writing a
secret into `config.yaml` and without the token ever reaching the terminal or
logs. **F2 is chosen:** add a command that generates a cryptographically random
operator token and writes it into the config file quietly; the operator reads
it back from the file (or, more often, never reads it — the mac app and TUI
read it from the same config). This is modeled on the existing `aitm ca`
command family's shape and UX (`aitm ca export/status/install/uninstall`,
`crates/aitm-ca/src/commands.rs`), but it is **CLI-only**: unlike the `ca.*`
family it is **not** registered as a registry/MCP tool, so no agent can ever
invoke it. Writing the operator secret is a human-at-the-keyboard action and
stays off the agent bus entirely (reinforcing the no-self-promotion anti-goal).

- **Verb (Architect's call, reversible):** `aitm operator-token generate`,
  with an optional `--force`. It is recognized as its own top-level mode in the
  binary's argument classifier (alongside `tui`/`web`,
  `crates/aitm/src/main.rs` `parse_mode`), **not** dispatched through the CLI
  registry, because it edits the config file before any server or service is
  built.
- **What it writes:** it resolves the config path the same way the rest of the
  binary does (`--config <path>`, else `AITM_CONFIG`, else the default path),
  reads the existing `config.yaml`, and sets `mcp.operator_token` to a freshly
  generated token. The edit is **surgical** — it inserts/replaces only the
  `operator_token` value (creating the `mcp:` block if absent) and preserves
  the rest of the file's content, comments, and formatting; it does not do a
  full serde round-trip that would rewrite the document. If the resolved config
  file does not exist, it errors and tells the operator to create a config
  first (it does not fabricate a new config).
- **Token quality:** the generated value is cryptographically random (CSPRNG)
  and non-empty, consistent with the project's CSPRNG-token requirement. The
  exact length/encoding is the builder's call provided it is a CSPRNG secret.
- **Never printed/logged:** the command writes the token to the file and prints
  **only** a non-sensitive confirmation — the config path it updated, that web
  and bus operator access is now enabled, and a reminder to restart the proxy.
  It never prints or logs the generated value, nor any pre-existing value.
- **Idempotency / overwrite:** if `mcp.operator_token` is already present and
  non-empty, the command **refuses by default** (clear message, non-zero exit,
  file unchanged) so it never silently rotates a token and locks out existing
  operators. `--force` rotates it: generate a new value and replace the
  existing one (again printing nothing sensitive).
- **How the operator then connects:** once the token is in `config.yaml` and
  the proxy is restarted, the mac app and `aitm-tui --bus`/the TUI read it from
  config (mac `BusEndpoint.fromConfigFile` / the TUI's token inputs) and the
  web operator URL is produced per Decision D. The operator never has to see or
  copy the raw token for the mac and config-driven paths.

### Decision B applied to `aitm-tui --bus`

No change to how the token is supplied (`--token`/`--token-file`/
`AITM_BUS_TOKEN`, `crates/aitm-tui/src/main.rs`); presenting the operator token
already makes the session operator over LoopbackTcp. The TUI adds:

- the optional `--expect-role <agent|operator>` flag (Decision B);
- a **resolved-role** indicator in the status line, from the `role` the bus
  client now carries (Decision C), and a mismatch warning when `--expect-role`
  disagrees;
- a clearer refusal message: the current `REFUSED` text
  (`crates/aitm-tui/src/bus.rs:31`, "bus refused the token — check
  --token-file") is reworded so it does not imply the token must come from a
  file and so it reads sensibly whether the operator meant to be agent or
  operator. Exact wording is the builder's, within this intent.

### Data flow summary

1. Client presents its token (CLI/mac: the mcp agent/operator token to
   LoopbackTcp; web: an agent/operator *bridge* token to the `/bus` relay).
2. Server/bridge classifies the token in constant time and assigns the role; an
   unknown token is refused `-32001`.
3. `initialize` runs on that role and echoes `role` in its result (Decision C).
4. The client displays the resolved role and, if an expectation was set, warns
   on mismatch. Sensitive commands then succeed for operator and are gated for
   agent exactly as the server already enforces.

## Acceptance criteria

Roles below mean the server-resolved `Frontend`. "Sensitive command" means one
the agent policy refuses under the default `Auto` policy (e.g.
`flow.intercept`). "Gated" means refused with the policy gate's error, not run.

1. **TUI operator runs Sensitive.** With `operator_token` configured on the
   proxy, `aitm-tui --bus` given the operator token resolves to operator and a
   `flow.intercept` request succeeds (not gated).
2. **TUI agent is gated.** `aitm-tui --bus` given the agent token resolves to
   agent and the same `flow.intercept` request is refused by the policy gate.
3. **Web operator runs Sensitive.** With operator access enabled, a `/bus`
   connection presenting the operator bridge token dispatches via `handle_on`
   as operator and a `flow.intercept` request succeeds.
4. **Web agent is gated.** A `/bus` connection presenting the agent bridge
   token dispatches as agent and `flow.intercept` is refused by the gate.
5. **Mac operator runs Sensitive.** The mac app configured with the operator
   token connects as operator and a Sensitive action succeeds over the live
   bus; configured with the agent token it connects as agent and the same
   action is gated.
6. **Role is echoed.** The `initialize` result includes `role: "operator"` for
   an operator connection and `role: "agent"` for an agent connection, on the
   LoopbackTcp transport and through the web `/bus` bridge.
7. **Role is surfaced.** Each frontend displays its resolved role to the
   operator (TUI status line, web banner, mac status element), reading the
   echoed `role`.
8. **Mismatch warns, does not fail silently.** When the operator sets the
   expectation to operator but the connection resolves to agent (or the server
   echoed no role), each frontend shows a visible warning rather than silently
   proceeding as agent.
9. **No self-promotion.** On every frontend, presenting the agent token (or the
   agent bridge token), or presenting no token or an unknown token, never yields operator;
   an unknown token is refused `-32001`.
10. **Role echo is additive.** A client that does not read `role` (or an
    `initialize` result consumer predating this change) is unaffected: the
    result still parses and the connection behaves as before.
11. **Existing single-token clients unaffected.** An agent client that presents
    only the agent token, with no operator token configured and no new flags,
    connects and is gated exactly as before this change; `aitm web` with no
    operator configured is agent-only and behaves as today.
12. **Operator off by default.** With no `operator_token` configured, no
    frontend offers or produces an operator path: the TUI has only the agent
    token, `aitm web` emits only the agent URL with no operator bridge token,
    and the mac app stays agent.
13. **Token never printed.** Running each frontend's connect path at the default
    log level prints/logs neither the agent nor the operator token.
14. **`operator-token generate` writes config.** Run against a config file that
    has no `operator_token`, `aitm operator-token generate` writes a non-empty
    `mcp.operator_token`, exits 0, preserves the rest of the file (other keys,
    comments), and the resulting file reloads (`config_file::load`/`parse`) with
    `mcp.operator_token` set so operator access is enabled.
15. **`operator-token generate` is quiet and non-destructive by default.** Its
    stdout and stderr contain neither the generated token nor any pre-existing
    token value. Run a second time with no `--force` it refuses with a non-zero
    exit and leaves the existing token unchanged; run with `--force` it replaces
    the token with a new non-empty value (and still prints nothing sensitive).
16. **Web operator URL uses an ephemeral bridge token.** With `mcp.operator_token`
    configured, `aitm web` emits a second operator launch URL whose fragment
    carries the generated operator *bridge* token, never the mcp operator token;
    the mcp operator token appears in no printed URL and no log.

## Left to the builder

- Exact names of the `--expect-role` flag and its mac Settings equivalent, and
  the exact refusal/warning wording, within Decision B's intent.
- The web UI banner and the mac status element's visual design (using the
  existing web UI conventions and the mac design skills/tokens).
- The internal `WebState` field name when the single `token` is split into
  agent/operator bridge tokens (Decision D).
- The precise string mapping helper for `Frontend → "operator"/"agent"`, as
  long as the two wire strings are exactly `"operator"` and `"agent"`.
- Whether the resolved-role display is a persistent element or shown on connect,
  per each frontend's existing conventions.
- The exact verb spelling for the generate-and-store command (Decision F; the
  spec fixes `aitm operator-token generate` but the precise subcommand shape is
  reversible), the generated token's length/encoding (any CSPRNG secret), and
  the exact non-sensitive confirmation wording.

## Open questions

None. Both prior open questions are resolved: **F = F2** (the generate-and-store
operator-token command, Decision F) and **Q2 = tied to config** (web operator
access is enabled iff `mcp.operator_token` is configured, confirmed in
Decision D).

---

**Summary.** The server's two-token role model is complete; the gap is that the
three standalone bus frontends don't let a human be an operator or don't show
which role they got. This spec keeps the model intact and token-class driven
(Decision A/B: one token input per frontend, class decides role, plus an
optional client-side role *expectation*), adds exactly one additive server
change — an `initialize` `role` echo (Decision C) — wires the web `/bus` bridge
to dispatch by role via two role-tagged *bridge* tokens that keep the mcp tokens
off the browser (Decision D), gives the mac app an operator-token entry and
role display (Decision E), and adds a CLI-only generate-and-store command that
writes `mcp.operator_token` into `config.yaml` without ever printing it
(Decision F). Agents stay gated, agents can't self-promote, and existing
single-token clients are untouched.

**Calls I made:**
- B: one token input per frontend, class decides role; add an optional
  client-side `--expect-role`/equivalent that only warns on mismatch.
- C: adopt the `initialize` role echo as a top-level additive `role` string
  (`"operator"`/`"agent"`); the single sanctioned server change.
- D: give the web bridge two role-tagged *bridge* tokens (keeping mcp tokens
  off the browser) and dispatch via `handle_on`; operator bridge token exists
  only when `mcp.operator_token` is configured (Q2: tied to config, no separate
  `aitm web` opt-in). The operator web URL carries the ephemeral generated
  bridge token, printed as the agent URL already is; the mcp operator token is
  never printed.
- E: optional operator-token `SecureField` + expected-role choice + resolved-
  role display in the mac app, agent-by-default preserved.
- F (resolved as F2): a CLI-only `aitm operator-token generate [--force]` that
  surgically writes a CSPRNG `mcp.operator_token` into the resolved config file,
  prints nothing sensitive, and refuses to overwrite an existing token without
  `--force`. Not exposed as an MCP/registry tool, so no agent can invoke it.
- Reworded the TUI `REFUSED`/role messaging.

**Questions only you can answer:** none remaining — F and Q2 are resolved above.
