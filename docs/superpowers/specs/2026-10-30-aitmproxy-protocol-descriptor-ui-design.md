# Protocol-descriptor-driven UI design

**Status:** draft (2026-10-30, architect scope). Design only. No build commitment, and approving this spec does not schedule it. The milestone is parallel to the v0.6 NE/scanner push, not ahead of it.
**Research inputs:** `docs/research/11-protocol-descriptor-ui-current-state.md` (this milestone's survey), `docs/research/05-synthesis.md`. Builds on approved specs: protocol-extensible languages (`2026-10-28-...-protocol-extensible-languages-design.md`), per-invocation seam context (`2026-10-29-...-seam-per-invocation-context-design.md`), L4 operator surfaces (`2026-10-28-...-l4-operator-surfaces-design.md`), UI scripting/highlight/L4 (`2026-10-27-...-ui-scripting-highlight-l4-design.md`).
**Queued milestone:** project memory `aitmproxy-milestone-protocol-descriptor-ui` (Matt, 2026-10-29).

## Intent

Today every operator UI hard-codes how each protocol looks. The TUI, the web UI and the macOS app each carry their own closed `FlowKind`, their own L4 and WebSocket list rows, inspectors, verbs and gate strings, about 2,000 LOC and 15 to 35 kind-branch sites per surface. That is why the web siloed L4 in a separate panel while the TUI and macOS unified it. A new protocol (DNS, gRPC, QUIC) would repeat the cost three times.

This milestone makes a protocol **describe itself**. A protocol crate registers a typed, validated **descriptor** with the core (badge, how a list row is built, which panes the inspector shows, which verbs exist, which capabilities gate them). The core serves it over the bus. Each UI becomes a **generic renderer** of that descriptor. A new protocol that fits the generic vocabulary ships a descriptor and zero per-UI code. Deny-by-default action gating is keyed off the same descriptor, so a UI can show the truth ("disabled: needs CAP_NET_RAW") instead of offering verbs the core will refuse.

The survey changes the starting point. The checked-in `docs/design/languages/flow-kinds.json` is prose that **no UI consumes** (the TUI, web and macOS generated files its README promises do not exist). The milestone reuses its field vocabulary as a seed, replaces the file with a machine contract, and corrects the README.

## Goals

- **One descriptor, served by the core.** `protocol.describe` returns a versioned, validated descriptor for every compiled-in protocol (http, websocket, l4), authored in each protocol's own crate.
- **Three generic renderers.** TUI, web and macOS render the unified flow list, badges, status cells, inspector panes, per-kind verbs and unknown-kind placeholders from the descriptor, with no per-kind branch outside a small named built-in registry.
- **A truthful capability seam.** `protocol.availability` tells each connection which actions are enabled for its role, policy, gates and privilege, with a reason and remedy when not. The core stays the only enforcer.
- **Zero per-UI code for a conforming new protocol.** Proven by a synthetic fourth protocol that all three UIs render with no UI diff.
- **Parity, measured.** The L4, WebSocket and HTTP presentation after migration equals the pre-milestone golden output, except for diffs listed and approved in the plan.
- **No row ever vanishes.** An unknown kind, pane type, format or viewer renders as a labelled placeholder (fixes macOS dropping rows and the TUI mapping unknowns to HTTP).
- **Staged and stoppable.** Each stage ends in a verified state Matt can stop at.

## Non-goals

- **No product rewrite.** Capture, proxy, TLS, the flow stores, the guards and the policy gate are untouched.
- **No declarative HTTP exchange viewer.** HTTP request/response editing, the body pipeline, the virtualized list engines and the craft editor internals stay as code. The HTTP exchange pane is the one named built-in.
- **No dynamic or third-party descriptor loading in v1.** Descriptors are compiled-in Rust, like `ProtocolLanguage` (non-goal there too). Rhai or plugin-supplied descriptors are an open question (Q3).
- **No new transport.** The bus stays MCP JSON-RPC. The wire gains two `Read` commands and nothing else.
- **No change to `Flow`, `FlowStore` or the L4-owned store** (M5 decision OQ1). Unifying L4 into `flow.list` is a separate, optional stage (Q2).
- **No generic panels for capture controls, scope editing, the scan panel or agent-gate toggles in v1** (Q4). They are the "surfaces" follow-on.
- **No per-protocol icons or color images.** Flat, monochrome, editorial (memory `aitmproxy-ui-icon-editorial-rule`). A badge is text plus a palette slot.
- **No fixing of the unrelated bugs the survey found** (research 11, "Bugs and gaps"), except where a stage's generic path replaces the buggy code by construction (wrong L4 verbs on macOS, kind-blind menus, role-blind gating).

## Anti-goals

- **A descriptor DSL that grows into a second programming language.** The vocabulary is closed and small. No expressions, loops, regexes or scripts in a descriptor.
- **The descriptor as authority.** If a UI could make a refused call succeed, or hide a refusal, because of descriptor content, the design failed. The server enforces every call exactly as today.
- **Three divergent interpretations.** If TUI, web and macOS format the same row differently, the contract is not a contract. Shared fixtures catch this.
- **The README-promised generation that never happened.** No claim that a surface "builds from" a descriptor unless a test proves it.
- **Custom widgets sneaking back in.** If the count of non-HTTP built-in renderers rises above zero, the vocabulary is too weak and must grow once, centrally, not per UI.
- **A ragged table.** Per-kind column sets would break persisted layouts and sorting. Kinds fill shared column slots.
- **Silent degradation.** A descriptor feature a UI cannot render must say so on screen.

## Constraints

- **Additive on the wire.** New commands and fields only. An old UI on a new core and a new UI on an old core both keep working: a new UI without `protocol.describe` uses a **bundled snapshot** of the same descriptors and behaves as today.
- **`aitm-tui` stays a bus client.** It depends on `aitm-bus-client`, not `aitm-core`. Shared Rust descriptor types therefore live in a new leaf crate with no `aitm-core` dependency.
- **Rust gate** (`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`), `node --test docs/design/languages/` and its successor, web `npm run gen && tsc --noEmit && vitest run`, macOS `swift test` plus the in-app `--selftest`. macOS builds and the live L4 and port-binding checks run in the Terminal panel only (CLAUDE.md, memory `aitmproxy-mac-app-pipeline`). `unsafe` stays forbidden.
- **Performance.** The HTTP list is the hot path (50,000-flow store, 500 ms poll, virtualized). Bindings compile once per descriptor, only visible rows are projected, and the migrated list stays within +10% of the pre-milestone baseline measured in Stage 0.
- **Descriptor input is untrusted on the client.** An external core (operator-supplied host and token, core-connection spec) can send anything. Labels render as text, sizes and path depth are capped, unknown palette tokens neutralize.
- **No new `rhai` edge.** `aitm-descriptor` and `aitm-plugin` stay rhai-free.
- **Merge hotspots.** `wire.rs`, `registry.rs`, `aitm/tests/frontends.rs` (pinned 56-tool list) and the three UIs' `app.ts`/`app.rs`/`Session.swift` are also hot for the NE and scanner work. Stage 1 stays small and rebases often.

## Design

### D1. What the survey forces

1. `flow-kinds.json` is a seed, not an asset. Its `list_cells` are English prose, it names viewers that exist nowhere (`protobuf`, `msgpack`, `sse`, `markdown`), it cites a command that does not exist (`flow.detail.messages`) and carries a stale `status`. It becomes a **generated snapshot** of real descriptors.
2. L4 is not a `Flow`. `l4.flow.list` returns **ids only** and rows need an N+1 `l4.flow.get` per poll. `flow.list` is ids only too, with `flow.table` as the bulk row command for http and websocket. The descriptor must therefore describe **sources** (bulk table, or ids plus per-id summary), and the client unions kinds. A core-side unified list is possible later (Q2) but is not needed to make the UIs generic.
3. Availability is role-blind. `tools/list` is not role-filtered, roles are display-only in all three UIs, and refusals surface at call time. A descriptor that only lists verbs would repeat that. Availability is a separate, dynamic, role-aware answer.

### D2. Two artifacts, two Read commands

| | `protocol.describe` | `protocol.availability` |
|---|---|---|
| What | the static **descriptor set** (shape, sources, bindings, panes, actions) | the dynamic **availability** of kinds and actions for **this connection** |
| Changes | only with the binary | with role, `AgentPolicy`, `*.allow_agent_*` gates, privilege probe, config, module enablement |
| Cache | by `schema_version` plus build id | by `revision` (`if_revision` returns `{unchanged:true}`) |
| Tier | `Read` | `Read` |
| Registered by | the protocol's crate, validated by the registry | computed by the core from the live policy and per-protocol resolvers |

Splitting keeps the descriptor deterministic (golden-testable, snapshot-able, safe to cache) and keeps role and policy out of it. Both are added to the pinned tool list in `aitm/tests/frontends.rs`. **(Architect's call.)**

### D3. Descriptor anatomy

A **descriptor set** is `{schema_version, vocab_version, kinds[]}`. Each **kind** is one of http, websocket, l4, or a future protocol. Illustrative L4 entry (field names are normative once the S1 JSON Schema lands; this shows the shape):

```json
{
  "kind": "l4", "aliases": [], "label": "L4",
  "badge":  { "token": "l4", "sub": "$.proto" },
  "source": {
    "table":   { "command": "l4.flow.table", "rows": "$.flows", "id": "$.id" },
    "summary": { "command": "l4.flow.get", "id_param": "id" },
    "poll_ms": 1500
  },
  "row": {
    "target": { "format": "text",  "from": "$.target" },
    "status": { "format": "state", "from": "$.state",
                "map": { "capture": "active", "intercept": "warn", "craft": "neutral", "send_recv": "neutral" } },
    "in":     { "format": "count", "from": "$.packet_count",   "unit": "pkt" },
    "out":    { "format": "count", "from": "$.injected_count", "unit": "inj" },
    "scope":  { "from": "$.in_scope" }
  },
  "detail": { "panes": [
    { "id": "session", "type": "fields", "fields": [ { "label": "Interface", "from": "$.interface" } ] },
    { "id": "packets", "type": "message-stream", "items": "$.packets", "select": "packet",
      "columns": [ { "id": "dir", "format": "direction", "from": "$.dir" },
                   { "id": "len", "format": "bytes",     "from": "$.length" },
                   { "id": "sum", "format": "join",      "from": "$.layers", "sep": "/" } ] },
    { "id": "layers", "type": "tree", "of": "packet", "from": "$.layers" },
    { "id": "craft",  "type": "compose", "format": "yaml", "submit": "inject",
      "preview": { "command": "l4.craft", "result": "$.hex", "viewer": "hex" } }
  ] },
  "actions": [
    { "id": "forward", "label": "Forward", "command": "l4.intercept.forward", "args": { "flow": "$row.id" },
      "intent": "resume", "when": { "state": ["intercept"], "scope": "in" },
      "placement": ["bar", "row-menu"], "requires": ["l4.intercept"] },
    { "id": "inject", "label": "Inject", "command": "l4.inject", "args": { "spec": "$pane.craft" },
      "when": { "scope": "in" }, "placement": ["bar"], "requires": ["l4.inject"] }
  ],
  "capabilities": [ { "id": "l4.intercept", "label": "Intercept" }, { "id": "l4.inject", "label": "Inject packets" } ]
}
```

HTTP and WebSocket are the same shape. HTTP's `source.table` is `flow.table` (with `kind_path: "$.kind"`, because `flow.table` serves http and websocket together), its `badge.token` is the template `method.{method}`, its row `target` uses the `host-path` format, and its single detail pane is `{ "type": "builtin", "name": "http.exchange" }`. WebSocket is a `fields` pane plus a `message-stream` plus a `compose` pane whose submit action is `ws.send`.

**Closed vocabularies** (the whole language; `vocab_version` bumps when one grows):

| Facet | Members (v1) |
|---|---|
| Bindings | `from` is a **mini-path**: `$` then `.key` and `[n]` only. No wildcards, filters or functions. Max depth 8. `$row`, `$pane.<id>`, `$selection.<id>` scope action args. |
| Row slots | `target`, `status`, `in`, `out`, `duration`, `secure`, `scope`, plus badge sub-label. The core-owned columns (sequence, time, client, edited, origin, mark) stay generic and need no kind. Exact slot set derives from the existing 14 columns (builder). |
| Formats | `text`, `join`, `count`, `bytes`, `duration`, `time`, `state`, `http-status`, `host-path`, `direction`, `flag`, `hex`. Each yields a **cell**: `{text, segments?, class?}`. Output strings are fixed by conformance fixtures. |
| Status classes | `neutral`, `muted`, `ok`, `info`, `active`, `warn`, `error` |
| Pane types | `fields`, `message-stream`, `tree`, `bytes`, `compose`, `builtin` |
| Viewers | `text`, `json-tree`, `hex`, `image`. Only viewers every UI ships. |
| Action placements | `bar`, `row-menu`. The command palette stays driven by `tools/list`. |
| Action intents | `resume`, `kill`, `edit`, `replay`, `forward`, `drop`, `mutate`, `send`. Global shortcuts route to the selected kind's action with that intent. |
| `when` predicates | `state` (any-of raw status values), `scope` (`in` or `any`), `selected` (a pane has a selection). Evaluated client-side per row. |
| Badge palette | `tokens.json` gains slots `kind.1` to `kind.8`. Existing tokens (`method.*`, `method.ws`, `l4`) stay as named aliases. **(Architect's call.)** |

Rules that make the vocabulary safe:

- **Kind ids are open strings.** `aliases` absorb wire spellings (`"ws"` for `"websocket"`, today's push-notification quirk). Every UI replaces its closed `FlowKind` enum with a string newtype.
- **Sources describe what exists.** `table` (bulk rows) is preferred. `ids` plus `summary` is the fallback. When two kinds share a command (`flow.table`), the client calls it once and routes rows by `kind_path`. A source with one kind omits `kind_path`. This matters for L4, whose own `kind` field is the session subtype (`capture`, `intercept`), not the flow kind.
- **Honest degradation, by rule.** A UI that does not know a kind, pane type, format or viewer renders a labelled placeholder naming it. It never drops, hides or re-labels a row.
- **Descriptor strings are data.** Labels, messages and map keys are length-capped text. No markup is interpreted.

### D4. Authoring, registration and validation (core)

- **New leaf crate `aitm-descriptor`** (serde and serde_json only, no `aitm-core`, no `rhai`). It holds the descriptor types, the JSON Schema, the closed vocabularies, the mini-path and predicate evaluators and the reference formatters. `aitm-tui` and the core both depend on it. **(Architect's call.)**
- **Registration.** `Registry::add_descriptor(KindDescriptor)` (a sibling of `add_command`) is called from `Plugin::load` (L4, which is command-driven) and from `wire.rs` for module-driven protocols (http, ws). The descriptor lives in the protocol's own crate (`aitm-proto-http`, `-ws`, `-l4`), beside its `ProtocolLanguage`. L4's descriptor registers whenever the crate is compiled in; `protocol.availability` reports it disabled with a remedy when `l4.enabled` is false. That replaces silent absence with a truthful, remediable state.
- **Validation, failing at startup and in tests.** `add_descriptor` checks what is local: unique kind and alias ids; every format, pane type, viewer, intent and predicate in the closed set; mini-paths parse; sizes capped (set under 256 KiB, 64 kinds, labels under 80 chars). `validate_descriptors`, run once at the end of `wire::build` when every command is registered, checks cross-references: every `command` resolves to a registered command, every `id_param` and action arg is a declared `ParamSchema` parameter, every `requires` id is declared in `capabilities`.
- **Drift guards**, modelled on `aitm-plugin-rhai/tests/api_catalog.rs`: the descriptor set equals the checked-in snapshot; every `ProtocolModule` or flow-owning plugin registers a descriptor; the snapshot validates against `descriptor.schema.json`.
- **Files.** `docs/design/protocols/descriptors.json` (generated snapshot, replaces `flow-kinds.json`), `descriptor.schema.json` (the wire contract), `conformance.json` (hand-authored fixtures, see D6) and a README ("add a protocol in one page"). The false README paragraph is corrected in Stage 0. `flow-kinds.json` stays, marked deprecated, until its last consumer (the web L4 model) migrates in Stage 3, then it is deleted.
- **New `l4.flow.table` (Read, additive)** so L4 has a bulk row command like `flow.table`, and **additive keys on `flow.table`** (scheme, request and response bytes, start time) where the HTTP list needs them. Stage 0 records which columns each UI reads from `flow.get` versus `flow.detail` versus `flow.table` before this is sized.

### D5. The capability seam

Goal: the same gate that enforces also explains, with one implementation.

- **Capabilities are declared by the protocol** (`capabilities[]` in its descriptor) and referenced by actions via `requires`. Examples: `l4.inject`, `l4.intercept`, `l4.capture`, `l4.widen`.
- **A core `CapabilityResolver` trait** (fail-closed default) is registered per protocol: `Registry::add_capability_resolver(protocol_id, Arc<dyn CapabilityResolver>)`. L4's resolver wraps `L4AgentGates` and the cached `L4Privilege` probe. A protocol with no resolver has all its capabilities denied.
- **`protocol.availability` composes four checks per action, in order**, and stops at the first denial: (1) the command is registered, else `absent`; (2) the connection's role and `AgentPolicy` against `Command::sensitivity()`, through a **single pure helper extracted from `McpServer::policy_decision`** (the same function, not a copy; this also reads `defers_to_command_gate` and `is_operator_only`), else `role` or `policy` (a Sensitive agent call under the `Ask` policy is parked for operator approval, so it reports `enabled:true` with `reason.code:"approval"`, informational); (3) each required capability through its resolver, else `gate` or `privilege`; (4) module enablement, else `config`. The result per action is `{enabled}` or `{enabled:false, reason:{code, message, remedy?}}`. Reason codes are a closed set: `absent`, `role`, `policy`, `gate`, `privilege`, `config`, `approval`. The policy step only gates the agent role today (`Operator` and `Cli` always pass), so for an operator-role UI the answer mostly reflects absence, privilege and config; the role and gate codes pay off when a UI is connected with a non-operator token, which today is a display-only warning (`--expect-role`).
- **Fail closed everywhere.** Unknown capability, missing resolver, unclassified command (default `Sensitive`) and any resolver error all produce `enabled:false`. A UI treats a missing availability entry as disabled.
- **Advisory, never authoritative.** `tools/call` is unchanged. An action that availability shows enabled can still be refused (scope, rate, guard, `L4Unavailable`); the UI renders the server's verbatim refusal, as today. An action shown disabled is still refused by the core if called directly.
- **Per-row conditions stay client-side.** `when.state` and `scope` are evaluated from the row. Out-of-scope rows dim and `scope: "in"` actions disable with the scope reason, which the guards enforce server-side regardless (scope-as-authorization).
- **Live changes.** Availability carries a `revision`, a stable content hash of the computed answers, so it changes exactly when any answer changes (policy set, `l4.agent.set`, config reload, privilege change, module (un)load) and needs no invalidation hooks. UIs poll `protocol.availability {if_revision}` on their existing slow tick. Push is a later optimization (no UI subscribes today).

The seam deliberately **does not** move `defers_to_command_gate` and `is_operator_only` out of `server.rs`. A single source of truth for those lists is a worthwhile follow-up, but not here.

### D6. The generic renderer, three layers per UI

Build-time generation (the README's unfulfilled promise) cannot work, because descriptors arrive at runtime from the core. Instead each UI gets three layers.

1. **Model layer (pure, no UI toolkit).** Parse and validate a descriptor set, index by kind and alias, compile bindings once, then `project_row`, `project_detail`, `format`, `eval_when` and `resolve_availability` into **view models** (`RowVM`, `PaneVM`, `ActionVM`). Same API names in Rust (`aitm-descriptor` reference, reused directly by the TUI), TypeScript (`apps/web/src/descriptor/`) and Swift (`AitmproxyKit/Descriptor/`, no SwiftUI, per the Kit rule). This is where parity lives.
2. **Widget layer (the toolkit).** Roughly ten generic widgets per UI, most of which already exist in some form: badge, cell renderer, tab and pane host, message-stream list (WS frames and L4 packets are near copies today), fields table, tree, bytes viewer (existing viewers, keyed by name), compose pane (YAML editor with command preview), action bar and row menu. The web already has `lib/schema-form`; the TUI palette already prompts from `inputSchema` via `ToolSchema`; macOS `PaneTabs` is already generic.
3. **Built-in registry.** `builtin` panes resolve by name to a UI-native renderer. v1 has exactly one: `http.exchange`.

**One shared fixture file proves the three model layers identical.** `docs/design/protocols/conformance.json` is hand-authored (as `filter.conformance.json` is): `[{ name, descriptor, rows|detail|availability, expected_vm }]`, covering every format with its exact output string, every predicate, mini-path edge cases, availability composition and the placeholder rules. A reference checker in `validate.test.mjs` proves the fixtures self-consistent. Each UI's test suite consumes the same file (`cargo test`, `vitest`, `swift test`), so a UI that drifts fails in its own loop.

**Data flow per UI.** At connect: if `protocol.describe` exists, fetch the descriptor set, else load the **bundled snapshot** (the generated `descriptors.json`, embedded at build; also the fixture and mock data, so mocks never hand-roll kinds). Each poll tick: call each distinct source command once, project rows by kind, merge into the one list. Slow tick: `protocol.availability {if_revision}`. Selecting a row fetches `summary` or the kind's detail command and builds panes.

**What changes per UI** is bounded to: the kind type (enum to string newtype), the row model (fixed `FlowRow` with `wsFrames` and `l4: L4RowInfo?` becomes a kind plus a cell map), the list cell and badge renderers, the inspector dispatch, the per-kind verbs, the per-kind gate strings, and deletion of the L4 and WS list and inspector code that the generic widgets replace.

### D7. Migration order

**Protocol order, in every UI: L4, then WebSocket, then HTTP list, with the HTTP exchange pane staying built-in.** L4 is the most divergent surface, the least tested live, has no persisted-layout risk and has the fewest users of the legacy path. HTTP is last because it is the hot path and carries the persisted columns and virtualization risk; its list adoption is a separate, cuttable task.

**UI order: TUI, then web, then macOS.** The TUI shares Rust types with the core, so it proves the schema end to end for the least cost and already has snapshot tests. The web has the worst L4 structure (a separate polled store appended unvirtualized after the HTTP rows) and the best fast verification loop (vitest, dev-server preview), so it follows with the two proofs behind it. macOS goes last: it builds only in the Terminal under the bama pipeline, its `NSTableView` columns persist to `columns.json`, and its live L4 path does not exist yet, so it gains most from two prior implementations and settled fixtures. **(Architect's call; the order is reversible per stage.)**

### D8. Honest tiers of "zero per-UI code"

- **Tier 1, zero UI code.** A protocol whose list row, panes, verbs and gates fit the closed vocabulary. This is the promise. Candidates: DNS, a binary RPC with a message-stream, QUIC streams.
- **Tier 2, one vocabulary bump.** A protocol that needs a pane type or format the vocabulary lacks. The cost is one change to `aitm-descriptor` plus a widget in each UI, amortized over every later protocol that uses it. It is not per-protocol and not per-UI-per-protocol.
- **Out of promise.** Bespoke editors (the HTTP exchange editor). They stay named built-ins.

The milestone's exit test is a Tier 1 protocol that all three UIs render with no diff to UI source (AC10).

### D9. Stages and greenlight points (detail in the plan)

| Stage | Delivers | Stop here and you have |
|---|---|---|
| **S0** Baseline | golden snapshots and a perf baseline per UI; column-source audit; correct the false README | a trustworthy "before", fewer lies in the docs |
| **S1** Core contract | `aitm-descriptor`, registry validation, `protocol.describe`/`availability`, http/ws/l4 descriptors, `l4.flow.table`, snapshot, schema, conformance, drift guards | a published contract and truthful availability, zero UI risk |
| **S2** Model layers | pure model layer in TUI, web, macOS, passing shared conformance, unused by UI | three conforming implementations, no visible change |
| **S3** Unified list | L4, then WS, then HTTP list descriptor-driven in each UI; unknown-kind placeholder; open kind type | the divergence is gone from the list |
| **S4** Inspector, actions, gates | generic pane host and widgets; per-kind verbs by intent; availability in the UI; `http.exchange` as the only built-in; legacy per-kind code deleted | L4 and WS fully generic, gates truthful |
| **S5** Proof | synthetic fourth protocol, zero-diff acceptance, "add a protocol" README | the promise, demonstrated |
| **S6** Surfaces (optional, go/no-go) | generic command surfaces (capture controls, scan panel, agent-gate toggles) and filter atoms | Matt's call at the S5 review |

Greenlight points: **G1** after S1, **G2** after S3, **G3** after S5. S6 needs its own scope.

### D10. Security

- The descriptor is **inert data authored in-tree**; no script runs from it. The registry validates it at startup.
- The UI is the trust boundary for descriptors from an **external core**: bounded size and path depth, no markup, unknown tokens neutralized, `command` names are only ever called through the same authenticated bus connection.
- Availability is advisory. The enforcement path (`policy_decision`, `ScopeRateGuard`, `L4Guard`, `confirm_prompt`) is not modified, and a test asserts the existing agent-policy and L4 gate suites pass untouched.
- A descriptor must not introduce a way for a UI to send `_confirm` without the operator confirm step. Actions whose command is `confirmable` always go through the existing confirm handshake in each UI.

## Acceptance criteria

1. **AC1, registration validates.** `Registry::add_descriptor` rejects immediately, with a typed error naming kind and field: a format, pane type, viewer or intent outside the closed set, a malformed mini-path, a duplicate kind or alias, and an oversize set. `Registry::validate_descriptors`, which `wire::build` calls after every module and plugin has registered, rejects cross-references: a command that is not registered, an `id_param` or action arg not in the command's `ParamSchema`, and an undeclared `requires` id. `wire::build` registers http, websocket and l4 descriptors and a test asserts every referenced command resolves.
2. **AC2, `protocol.describe`.** Returns `schema_version`, `vocab_version` and the three descriptors, as a `Read` command listed in `tools/list` and the pinned list in `aitm/tests/frontends.rs`. The output equals `docs/design/protocols/descriptors.json` byte for byte (drift test) and validates against `descriptor.schema.json` (`node --test`).
3. **AC3, availability by role.** For an operator connection `l4.inject` is enabled iff the privilege probe passed. For an agent (`Frontend::Mcp`) connection with `l4.allow_agent_inject` off it is `enabled:false, reason.code:"gate"`; turning the flag on via `l4.agent.set` flips it and changes `revision`. With `l4.enabled: false`, kind `l4` is reported disabled with `reason.code:"config"` and a remedy.
4. **AC4, fail closed.** An action whose capability has no resolver, whose command is unclassified, or whose resolver errors is `enabled:false`. A test registers a descriptor with an unknown capability and asserts denial.
5. **AC5, enforcement unchanged.** With descriptors and availability present, an agent `tools/call l4.inject` with the gate off is still refused and nothing reaches the wire; the existing `frontends.rs` policy tests and the L4 gate tests pass without edits. Availability computation uses the same extracted policy helper as `policy_decision` (a test calls both on the same inputs).
6. **AC6, shared conformance.** `conformance.json` holds at least one case per format, per predicate, per placeholder rule, per mini-path edge and per availability composition. The Rust reference, the TypeScript model layer and the Swift model layer each pass the whole file in their own test suite.
7. **AC7, list parity.** For each UI, rendering the fixture core's http, websocket and l4 rows through the descriptor equals the Stage 0 golden snapshot, except diffs listed and approved in the plan's Review log.
8. **AC8, no vanishing rows.** A descriptor kind unknown to the UI renders a row with a label badge, target and status cells and a placeholder inspector naming the kind. A pane type, format or viewer the UI does not support renders a labelled placeholder naming it. Asserted in each UI against the same conformance cases.
9. **AC9, open kind type.** `FlowKind` as a closed enum or union is gone from TUI, web and macOS production code. A guard test per UI fails if a kind-discriminant literal (`"l4"`, `"websocket"`, `.l4`, `FlowKind::L4`) appears in UI source outside the named built-in registry, the bundled-snapshot loader and the test fixtures.
10. **AC10, zero-code proof.** Each UI's test suite renders the synthetic `test` protocol (a descriptor plus a fake table and summary command pair from `aitm-proto-test`, loaded from `docs/design/protocols/`, not from UI source) through its real widgets: row, `fields` and `message-stream` inspector, and one action. AC9's guard shows no kind literal exists in UI source. A walkthrough script then adds a second synthetic protocol with descriptor and fixtures only, runs the three UI suites, and asserts `git diff --name-only` stays inside `crates/aitm-proto-test/**`, `docs/design/protocols/**` and UI fixture directories.
11. **AC11, verbs by intent.** On an L4 intercept row, the global resume shortcut in each UI calls `l4.intercept.forward` and the kill shortcut calls `l4.intercept.drop`, never `flow.resume` or `flow.kill`. Row menus and the inspector bar list only actions whose `when` holds for the row and whose availability is enabled; a disabled action shows the server's `reason.message`.
12. **AC12, HTTP list budget.** The descriptor-driven HTTP list stays within +10% of the Stage 0 baseline (rows projected and rendered for a 50,000-flow store, visible window only) in each UI; the baseline method is recorded in Stage 0.
13. **AC13, old core, new UI.** Against a core without `protocol.describe`, each UI loads the bundled snapshot and renders as it does before the milestone (asserted with a mock core).
14. **AC14, untrusted descriptors.** A descriptor with an oversize string, a path deeper than 8, an unknown palette token or markup in a label is rejected or neutralized in each model layer; the web renders labels as text nodes. Covered by conformance cases.
15. **AC15, docs match code.** The false README paragraph is gone; `docs/design/protocols/README.md` lets a reader add a Tier 1 protocol in one page, and its steps are exactly what the AC10 test performs.

## Left to the builder

- Exact JSON field names and optional keys inside the schema (the shape and vocabularies above are fixed; the schema task finalizes spellings and the L4 example).
- The exact shared slot set (derived from the existing 14 columns and what each UI reads from `flow.get`, `flow.detail` and `flow.table`).
- Mini-path edge syntax (quoting of keys with dots), formatter output strings (fixed by the fixtures, not by this spec), the short human names for status classes in each toolkit.
- Whether the Rust reference evaluator lives in `aitm-descriptor` or the TUI re-exports it.
- File layout in TS and Swift; polling cadence for availability; how the bundled snapshot is embedded (build script versus checked-in generated file).
- Which `flow.table` keys to add for HTTP, once the Stage 0 audit shows what the UIs actually read.

## Open questions

Only Matt can answer these. Each has a recommended default so work is never blocked.

1. **Q1. The scope of the promise.** *Recommended: Tier 1 only (D8).* The HTTP exchange pane stays a built-in, the descriptor drives HTTP's list row but not its inspector. The alternative, declaring the HTTP exchange editor in the descriptor, would roughly double the vocabulary and the schema and is the main way this milestone becomes a rewrite.
2. **Q2. Where the list is unified.** *Recommended: client-side union through descriptor sources (D1, D3).* The alternative is a core-unified row feed (`Flow::L4`, about 45 `Flow` match sites in about 17 files, or a new `flow.rows` command) that moves sort, filter and pagination into the core and makes L4 push-capable. It also reverses the M5 decision that the L4 store is protocol-owned. Reasonable as a later, separate milestone.
3. **Q3. Who may author a descriptor.** *Recommended: compiled-in Rust only, consistent with `ProtocolLanguage`.* Allowing Rhai or plugin-supplied descriptors would let a script add a protocol with no rebuild, at the cost of a new untrusted-metadata surface in front of the operator (a descriptor could label an action misleadingly). It needs its own security review.
4. **Q4. Are "surfaces" in this milestone?** *Recommended: out, decided at G3.* Capture controls, the L4 scope view, agent-gate toggles and the scanner panel are command-driven surfaces rather than flow kinds. The scanner is the strongest case (three bespoke Scan panels today, a result type that is untyped `Object(vec![])`), but it needs a typed result contract first.
5. **Q5. When.** Matt's standing sequencing is "after everything else ships". *Recommended: nothing starts before the v0.6 NE and scanner work lands; Stage 0 and Stage 1 are the only stages that can safely run earlier, and only if they avoid the merge hotspots listed under Constraints.* This spec asks for no scheduling decision.

## Summary

Protocols describe themselves. A new leaf crate `aitm-descriptor` holds a closed-vocabulary descriptor (badge, row bindings into shared column slots, sources, inspector panes, verbs with intents, declared capabilities). Protocol crates register it, the registry validates it, and two Read commands serve it: `protocol.describe` (static, cacheable) and `protocol.availability` (per connection, role and gate aware, fail closed, advisory). Each UI gets a pure model layer proven identical by one shared conformance fixture, a small set of generic widgets, and a one-entry built-in registry (`http.exchange`). Migration runs L4, then WebSocket, then HTTP list, in TUI, then web, then macOS, ending with a synthetic fourth protocol that renders in all three with no UI diff. The existing `flow-kinds.json` is unconsumed prose, so it is a seed rather than a base.

**Architect's calls:** split describe and availability (D2); leaf crate `aitm-descriptor` (D4); L4 descriptor registers even when disabled and reports disabled (D4); extract one policy helper shared with `policy_decision` and leave the hard-coded name lists in place (D5); `kind.1` to `kind.8` palette slots (D3); sources describe existing commands and add `l4.flow.table` (D1, D4); build-time generation rejected in favor of runtime descriptors plus a bundled snapshot (D6); migration order L4, WS, HTTP and TUI, web, macOS (D7); the three-tier promise (D8); per-stage greenlight points G1 to G3 (D9).
