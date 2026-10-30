# Protocol-descriptor-driven UI implementation plan

**Status:** draft (2026-10-30, architect scope). Not approved. No build commitment; approving this plan does not schedule it.
**Spec:** `docs/superpowers/specs/2026-10-30-aitmproxy-protocol-descriptor-ui-design.md`
**Branch / worktree:** none yet. One branch and worktree **per stage**, cut from `main` when the stage starts and merged to `main` after that stage's final panel review (`feat/pdui-s0-baseline`, `feat/pdui-s1-core`, ...). **(Architect's call; a deviation from WORKFLOW.md's one-branch-per-plan, because the stages are independently shippable and greenlit separately, and a months-long branch would rot against the NE and scanner work. Needs Matt's OK.)**

## Overview

37 tasks in six stages. Stage 0 builds a trustworthy "before" (golden output and a perf baseline per UI). Stage 1 is Rust only and additive: the `aitm-descriptor` crate, registry validation, the two Read commands, the http/ws/l4 descriptors, the shared snapshot, schema and conformance fixtures. Stages 2 to 4 repeat one shape per UI in three parallel tracks (TUI, web, macOS): pure model layer, then unified list (L4, then WebSocket, then HTTP), then inspector, actions and gates. Stage 5 proves the promise with a synthetic fourth protocol. Stage 6 (generic command surfaces, filter atoms) is deliberately **not planned** here; it needs its own scope after G3.

**Independent (fan out, disjoint files):** Tasks 1 to 4; Task 8 at any time; Tasks 10 and 11 once Task 7 lands (11 also needs 8); the three UI tracks in Stages 2, 3 and 4 (each track is sequential inside itself). **Sequential:** within Stage 1, 5 then 6 and 7, then 9 after 7 and 8, then 12 after 6, 9, 10 and 11, then 13. Stage 2 needs Task 12's fixtures. Stage 3 needs Task 9 live (or the mock). Stage 5 needs everything.

**Tooling notes.** Every macOS task builds and tests in the Terminal panel only (bama pipeline; memory `aitmproxy-mac-app-pipeline`). Port-binding and live-core tests run in the Terminal panel. `git` and `gh` run in the Terminal panel. Coder sub-agents for security-sensitive Rust (Tasks 8, 9, 11) often capacity-fall-back; retry on Fable or do it directly (memory `aitmproxy-coder-opus5-cyber-fallback`).

## Migration order (spec D7)

Protocols: **L4, then WebSocket, then HTTP list** (HTTP exchange stays built-in). UIs: **TUI, then web, then macOS**. Reasons are in spec D7. Each is reversible per stage.

## Greenlight points

| Point | After | Matt decides |
|---|---|---|
| **G0** | this PR | approve spec and plan; answer Q1 to Q5 (defaults stand if silent) |
| **G1** | Stage 1 (Tasks 5 to 13) | the contract and truthful availability are worth having even if no UI adopts them yet |
| **G2** | Stage 3 (Tasks 20 to 25) | the divergence is gone from the list; continue into inspectors, or stop with generic lists |
| **G3** | Stage 5 (Tasks 35 to 37) | the promise is demonstrated; scope Stage 6 (surfaces) or close the milestone |

## Risks

| # | Risk | Mitigation | Retired by |
|---|---|---|---|
| R1 | HTTP list regresses (50k flows, 500 ms poll, virtualized) | bindings compile once; only visible rows projected; +10% budget measured against the Task 1 to 3 baselines; HTTP list adoption is its own cuttable task per UI | Tasks 21, 23, 25 |
| R2 | The vocabulary is too weak and custom widgets creep back | exit metric: non-HTTP built-in renderers equal zero; a gap means one central vocabulary bump (Tier 2), not a per-UI patch | Task 34 |
| R3 | Three languages drift on formats, paths, predicates | one hand-authored `conformance.json`, consumed by all three test suites; AC6 | Tasks 12, 14, 16, 18 |
| R4 | The survey's pre-existing live-bus gaps distort parity (macOS L4 fixtures-only; web no `flow.subscribe`; `confirmable` vs `confirm`) | Stage 0 goldens use fixtures; Task 24 wires macOS L4 live as a side effect of source-driven polling; the other bugs stay out of scope and are listed in research 11 | Tasks 24, 1 to 3 |
| R5 | Availability is mistaken for enforcement | spec D5: advisory only, AC5 asserts unchanged refusals, mandatory security review on Tasks 8, 9, 11 | Task 9 |
| R6 | Extracting the policy helper (Task 8) subtly changes enforcement | parity table test over every (role, policy, tier, gate) combination; the existing `frontends.rs` and L4 gate suites must pass unedited | Task 8 |
| R7 | The web cannot fold non-HTTP kinds into the virtualized, sortable, keyboard-navigable pipeline cheaply (L4 rows are an unvirtualized block today) | Task 22 is sized as the hardest web task; if it overruns, split into pipeline unification and descriptor wiring and re-plan | Task 22 |
| R8 | macOS `FlowRow` and `NSTableView` column persistence resist a generic row | slots map one-to-one onto today's `FlowColumn` cases so `columns.json` stays valid; Task 25 is cuttable | Task 25 |
| R9 | `flow.table` lacks columns the HTTP list reads (size, scheme) | Task 4 audits which columns each UI reads from which command, Task 10 adds keys additively | Tasks 4, 10 |
| R10 | Merge conflicts with NE and scanner work in hot files | Stage 1 touches `wire.rs`, `registry.rs`, `frontends.rs` in small commits; rebase daily; Stages 2 to 4 start only after v0.6 lands (Q5) | process |
| R11 | An external core sends a hostile descriptor | untrusted-input rules in each model layer (AC14); labels as text nodes | Tasks 6, 14, 16, 18 |
| R12 | The schema freezes too early | `schema_version` and `vocab_version` from day one; the vocabulary grows by version, never by silent field | Task 5 |

## Tasks

### Stage 0: Baseline (all four tasks independent)

### Task 1: TUI golden snapshots and perf baseline

- **Satisfies:** AC7, AC12 (baseline)
- **Depends on:** none
- **Files:** `crates/aitm-tui/tests/golden_kinds.rs` (create), `crates/aitm-tui/tests/golden/*.txt` (create), `crates/aitm-tui/src/fixture.rs` (modify: a mixed http, websocket, l4 fixture if absent), `crates/aitm-tui/benches/` or an `#[ignore]` timing test (create)
- **Change:** render the unified list and the inspector for one http, one websocket and three l4 rows (capture, craft, intercept) at 120x40 and 100x30 through the existing snapshot path into checked-in text goldens. Add an ignored timing test that projects and renders a 50,000-row list's visible window and prints the median of 20 runs; record the number in the test's doc comment.
- **Test:** `golden_kinds::list_and_inspector_match_goldens` compares rendered text to the golden files byte for byte (literal expected text lives in the files). `list_render_baseline` is `#[ignore]` and prints `median_us=<n>`.
- **Done when:** goldens are committed, the test passes on current code with no source change beyond the fixture, and the full gate passes.

### Task 2: Web golden snapshots and perf baseline

- **Satisfies:** AC7, AC12 (baseline)
- **Depends on:** none
- **Files:** `apps/web/src/flows/__golden__/kinds.test.tsx` (create), `apps/web/src/flows/__golden__/*.snap` (create), `apps/web/src/flows/__golden__/list.bench.ts` (create), `apps/web/src/bus/fixtures.ts` (modify: mixed fixture)
- **Change:** vitest renders the unified `FlowList` (including the appended L4 block) and the inspector for the same fixture rows as Task 1 and snapshots the rendered text per row and column. A vitest bench projects 50,000 `FlowEntry` rows and measures the visible-window render.
- **Test:** `kinds.test.tsx` asserts `toMatchFileSnapshot` equality; the bench records `mean` in a comment.
- **Done when:** snapshots committed, `npm run gen && tsc --noEmit && vitest run` passes.

### Task 3: macOS golden snapshots and perf baseline

- **Satisfies:** AC7, AC12 (baseline)
- **Depends on:** none
- **Files:** `apps/mac/Tests/AitmproxyKitTests/GoldenKindsTests.swift` (create), `apps/mac/Tests/AitmproxyKitTests/__golden__/*.txt` (create), `apps/mac/Sources/AitmproxyKit/Fixtures+L4.swift` (modify only if the mixed fixture is missing)
- **Change:** assert the cell text produced for each `FlowColumn` of the http, websocket and three l4 fixture rows (the data `FlowCellView.configure` consumes) against checked-in goldens, and add a `measure` test over 50,000 rows.
- **Test:** `GoldenKindsTests.cellsMatchGoldens`; `listProjectionBaseline` prints the median.
- **Done when:** `swift test` passes in the Terminal panel; goldens committed.

### Task 4: Column-source audit and README correction

- **Satisfies:** AC15 (partial), informs Task 10
- **Depends on:** none
- **Files:** `docs/research/12-descriptor-column-source-audit.md` (create), `docs/research/README.md` (modify index), `docs/design/languages/README.md` (modify: the `flow-kinds.json` paragraph)
- **Change:** a table of every list column per UI with the command that supplies it today (`flow.get`, `flow.detail`, `flow.table`, `l4.flow.get`) and whether `flow.table` already carries it; confirm what supplies L4 layer-tree detail. Replace the README's false claim that three generated per-kind renderers exist with the true state and a pointer to the spec.
- **Test:** none (docs). Reviewer checks every cell against the code.
- **Done when:** the audit names a source for all 14 columns in all three UIs and the README no longer cites `flow_kinds.rs`, `flow-kinds.ts` or `FlowKind.swift`.

### Stage 1: Core contract (Rust, additive; G1 follows)

### Task 5: `aitm-descriptor` crate, types and closed vocabularies

- **Satisfies:** AC1 (structural), AC2 (shape), AC14 (core side)
- **Depends on:** none (Stage 0 not required)
- **Files:** `crates/aitm-descriptor/Cargo.toml` (create), `crates/aitm-descriptor/src/lib.rs`, `src/model.rs`, `src/vocab.rs`, `src/error.rs` (create), `Cargo.toml` (modify: workspace member and dependency)
- **Change:** `pub struct DescriptorSet { pub schema_version: u32, pub vocab_version: u32, pub kinds: Vec<KindDescriptor> }`; `KindDescriptor { kind, aliases, label, badge, source, row, detail, actions, capabilities }`; enums `Format`, `PaneType`, `Viewer`, `StatusClass`, `Placement`, `Intent`, `ScopeMode`; availability wire types `Availability { Enabled, Disabled(Reason) }`, `Reason { code: ReasonCode, message, remedy: Option<String> }`; `DescriptorSet::from_json(&str) -> Result<DescriptorSet, DescriptorError>` enforcing size caps (256 KiB set, 64 kinds, 80-char labels). No `aitm-core`, no `rhai`.
- **Test:** `parses_spec_l4_example` parses the spec's L4 JSON and asserts `kinds[0].kind == "l4"` and `row["in"].unit == Some("pkt")`. `rejects_unknown_format` expects `DescriptorError::UnknownFormat { path: "kinds[0].row.target.format", value: "banana" }`. `rejects_oversize_label` (81 chars) expects `DescriptorError::LabelTooLong`.
- **Done when:** tests pass; `cargo tree -p aitm-descriptor` shows only serde and serde_json; full gate passes.

### Task 6: Mini-path, predicates, formatters, reference row projection

- **Satisfies:** AC6 (Rust reference), AC14
- **Depends on:** Task 5
- **Files:** `crates/aitm-descriptor/src/path.rs`, `src/format.rs`, `src/predicate.rs`, `src/project.rs` (create)
- **Change:** `Path::parse(&str) -> Result<Path, PathError>` (`$`, `.key`, `[n]`, max depth 8); `Path::resolve<'a>(&self, &'a Value) -> Option<&'a Value>`; `format_cell(Format, &FormatArgs, &[Option<&Value>]) -> Cell { text, segments, class }`; `eval_when(&When, &RowFacts) -> bool`; `project_row(&KindDescriptor, &Value) -> RowVm`. Descriptors compile bindings once (`CompiledKind::new`).
- **Test:** `path_too_deep` expects `PathError::TooDeep { max: 8 }` for nine segments. `l4_row_projection` projects `{"id":"7","state":"intercept","packet_count":3,"injected_count":0}` against the L4 descriptor and asserts `cells["in"].text == "3 pkt"`, `cells["out"].text == "-"`, `cells["status"].class == StatusClass::Warn`. Format examples (fixture-fixed in Task 12): `bytes(1536) == "1.5 KB"`, `duration_ms(1500) == "1.5 s"`.
- **Done when:** the Rust reference passes every case Task 12 later adds to `conformance.json`; full gate passes.

### Task 7: Registry integration and cross-reference validation

- **Satisfies:** AC1
- **Depends on:** Task 5
- **Files:** `crates/aitm-core/Cargo.toml` (modify: depend on `aitm-descriptor`), `crates/aitm-core/src/registry.rs` (modify), `crates/aitm-core/src/error.rs` (modify)
- **Change:** `Registry::add_descriptor(&mut self, KindDescriptor) -> Result<(), DescriptorRegistryError>` (duplicate kind or alias, vocabulary, size); `Registry::validate_descriptors(&self) -> Result<(), Vec<DescriptorRegistryError>>` (every `command` registered, every `id_param` and `args` key a declared `ParamSchema` parameter, every `requires` id declared); `Registry::descriptors(&self) -> &[KindDescriptor]`.
- **Test:** `add_descriptor_rejects_duplicate_alias` expects `Err(DuplicateId { id: "ws" })`. `validate_flags_unknown_command` expects the message ``kind `l4` action `inject`: command `l4.nope` is not registered``. `validate_flags_undeclared_capability`.
- **Done when:** tests pass; no behavior change to any existing command; full gate passes.

### Task 8: `CapabilityResolver` and the shared policy helper

- **Satisfies:** AC3 (logic), AC4, AC5
- **Depends on:** none (independent of Tasks 5 to 7; Task 9 joins them)
- **Files:** `crates/aitm-core/src/capability.rs` (create), `crates/aitm-core/src/agent.rs` (modify), `crates/aitm-core/src/lib.rs` (modify), `crates/aitm-mcp/src/server.rs` (modify: `policy_decision` delegates; the two name lists `defers_to_command_gate` and `is_operator_only` move to `aitm-core` unchanged)
- **Change:** `trait CapabilityResolver: Send + Sync { fn resolve(&self, capability: &str, caller: CallerTrust) -> Availability; }` with a fail-closed default resolver; `Registry::add_capability_resolver(protocol_id, Arc<dyn CapabilityResolver>)`; `pub fn policy_check(frontend: Frontend, policy: AgentPolicy, cmd: &dyn Command) -> PolicyOutcome { Allow, Park, Refuse(reason) }` extracted from `McpServer::policy_decision` (which keeps `PolicyDecision` as its own type and maps from it), preserving the `Ask`-parks-Sensitive and `#[non_exhaustive]`-fails-closed arms. Pure data move for the two lists, no logic change.
- **Test:** `policy_check_parity_table` runs every (Frontend, AgentPolicy, Sensitivity) combination through both `policy_check` and the pre-extraction `policy_decision` expectations (a literal table with one row per combination) and asserts equal outcomes. `unknown_capability_is_denied`.
- **Done when:** the existing `aitm/tests/frontends.rs` and `aitm-mcp` suites pass **unedited**; security review mandatory; full gate passes.

### Task 9: `protocol.describe` and `protocol.availability`

- **Satisfies:** AC2, AC3, AC4, AC5
- **Depends on:** Tasks 7, 8
- **Files:** `crates/aitm-plugins/src/protocol.rs` (create), `crates/aitm-plugins/src/lib.rs` (modify), `crates/aitm/src/wire.rs` (modify: register commands, call `validate_descriptors` last), `crates/aitm/tests/frontends.rs` (modify: pinned tool list)
- **Change:** `ProtocolDescribe` (`Read`) returns the `DescriptorSet`. `ProtocolAvailability` (`Read`, param `if_revision: Str?`) returns `{revision, role, kinds, actions}` by composing, per action: command registered, then `policy_check` for the calling `Frontend` (its `AgentState` handle is passed to the command at construction in `wire.rs`, as `agent.status` does; `Park` maps to `enabled` with reason code `approval`), then each required capability's resolver, then module enablement; fail closed. `revision` is a stable 64-bit content hash of the availability map as 16 hex chars, so it changes exactly when an answer changes and needs no invalidation hooks. **(Architect's call.)**
- **Test:** `availability_if_revision_unchanged` returns `{"unchanged":true,"revision":"<same>"}` on the second call. `agent_with_gate_off_is_disabled` asserts `actions["l4/inject"].reason.code == "gate"` for an `Mcp` caller and `enabled == true` for an `Operator` caller with privilege. `enforcement_unchanged` calls `tools/call l4.inject` as an agent with the gate off and asserts it is still refused and the wire stub saw zero writes. Pinned list gains `protocol.describe`, `protocol.availability` (and `l4.flow.table` in Task 11).
- **Done when:** tests pass, `tools/list` shows both commands, security review mandatory, full gate passes.

### Task 10: http and websocket descriptors, additive `flow.table` keys

- **Satisfies:** AC1, AC2, AC7 (data side)
- **Depends on:** Tasks 4, 7
- **Files:** `crates/aitm-proto-http/src/descriptor.rs` (create), `crates/aitm-proto-ws/src/descriptor.rs` (create), `crates/aitm-plugins/src/capture.rs` (modify: additive row keys the Task 4 audit names, for example `scheme`, `req_bytes`, `resp_bytes`, `started_ms`), `crates/aitm/src/wire.rs` (modify: register)
- **Change:** `pub fn descriptor() -> KindDescriptor` in each crate. HTTP: `source.table = flow.table` with `kind_path "$.kind"`, badge token template `method.{method}`, `target` with `host-path`, one `builtin` pane `http.exchange`. WebSocket: aliases `["ws"]`, `fields`, `message-stream` and `compose` panes, submit action `ws.send`, intents mapped to `ws.intercept`.
- **Test:** `http_descriptor_validates_against_real_registry` builds the registry as `wire::build` does and asserts `validate_descriptors()` is `Ok`. `flow_table_additive_keys` asserts a known fixture flow yields `req_bytes == 512` while the pre-existing keys are unchanged.
- **Done when:** both descriptors validate; existing `flow.table` consumers and tests pass unedited; full gate passes.

### Task 11: L4 descriptor, `l4.flow.table`, L4 capability resolver

- **Satisfies:** AC1, AC2, AC3, AC4
- **Depends on:** Tasks 7, 8
- **Files:** `crates/aitm-proto-l4/src/descriptor.rs` (create), `crates/aitm-proto-l4/src/commands/flow.rs` (modify: add `FlowTable`), `crates/aitm-proto-l4/src/gates.rs` (modify: `L4CapabilityResolver`), `crates/aitm-proto-l4/src/module.rs` (modify: register descriptor, table command, resolver), `crates/aitm/tests/frontends.rs` (modify: pinned list)
- **Change:** `l4.flow.table` (`Read`) returns `{"flows":[{id, session, interface, filter, queue, target, state, proto, packet_count, injected_count, in_scope}]}` in one call. The L4 descriptor registers whenever the crate is compiled in; the resolver wraps `L4AgentGates` and the cached `L4Privilege` probe and reports `config` when `l4.enabled` is false.
- **Test:** `l4_flow_table_one_call` seeds three flows and asserts `flows.len() == 3` and `flows[2].state == "intercept"`. `availability_matrix` asserts, as a literal table: operator with privilege `enabled`; operator without privilege `privilege`; agent with `allow_agent_inject` off `gate`; agent with it on and privilege `enabled`; `l4.enabled: false` kind `config`.
- **Done when:** tests pass, existing L4 gate and guard suites pass unedited, security review mandatory, full gate passes.

### Task 12: Snapshot, JSON Schema, conformance fixtures, drift guards

- **Satisfies:** AC2, AC6 (fixtures), AC15 (partial)
- **Depends on:** Tasks 6, 9, 10, 11
- **Files:** `docs/design/protocols/descriptors.json` (create, generated), `docs/design/protocols/descriptor.schema.json` (create), `docs/design/protocols/conformance.json` (create, hand-authored), `docs/design/protocols/validate.test.mjs` (create), `docs/design/protocols/README.md` (create, draft), `crates/aitm/tests/descriptor_snapshot.rs` (create), `docs/design/languages/README.md` (modify: mark `flow-kinds.json` deprecated, superseded by `protocols/`)
- **Change:** `descriptor_snapshot` regenerates the descriptor set from the live registry and fails if it differs from `descriptors.json`; `validate.test.mjs` validates the snapshot against the schema and checks fixture self-consistency with a small reference checker; `conformance.json` holds `[{name, descriptor, input, expected_vm}]` covering every format, predicate, mini-path edge, placeholder rule, untrusted-input case and availability composition. `flow-kinds.json` stays until its consumers are removed (Task 22).
- **Test:** `descriptor_snapshot::snapshot_matches_live_registry`; `node --test docs/design/protocols/` passes; the Task 6 Rust reference passes every conformance case.
- **Done when:** all three pass and the full gate passes. **G1 follows Panel review of Stage 1.**

### Task 13: Synthetic `test` protocol descriptor in `aitm-proto-test`

- **Satisfies:** AC10 (data side), AC6
- **Depends on:** Tasks 7, 12
- **Files:** `crates/aitm-proto-test/src/descriptor.rs` (create), `crates/aitm-proto-test/src/commands.rs` (create: `test.flow.table`, `test.flow.get`, test-only), `docs/design/protocols/conformance.json` (modify: add `test` cases)
- **Change:** a descriptor for kind `test` using only Tier 1 vocabulary (a `fields` pane, a `message-stream` pane, one action with intent `send`), plus fake `Read` commands returning fixed rows. Registered only by test wiring, never by `wire::build`.
- **Test:** `test_kind_validates_and_projects` asserts the row projection of the fixed row equals the literal `RowVm` also stored in `conformance.json`.
- **Done when:** passes; full gate passes.

### Stage 2: UI model layers (three parallel tracks; no visible change)

### Task 14: TUI model layer and conformance

- **Satisfies:** AC6, AC13, AC14
- **Depends on:** Task 12
- **Files:** `crates/aitm-tui/Cargo.toml` (modify: add `aitm-descriptor`), `crates/aitm-tui/build.rs` (modify: embed `docs/design/protocols/descriptors.json`), `crates/aitm-tui/src/descriptor/mod.rs` (create), `crates/aitm-tui/tests/conformance.rs` (create)
- **Change:** `DescriptorBook::bundled() -> DescriptorBook` and `DescriptorBook::from_bus(&Value) -> DescriptorBook`; `kind(&str) -> KindHandle` resolving aliases and returning an `Unknown` handle for an unrecognized id (never `None`). Reuses the `aitm-descriptor` reference projector directly.
- **Test:** `conformance::all_cases_pass` runs the whole shared `conformance.json` and asserts every `expected_vm` equal. `unknown_kind_handle_is_labelled` asserts `kind("zzz").label() == "zzz"`.
- **Done when:** passes; `aitm-tui` still has no `aitm-core` dependency (`cargo tree -p aitm-tui` check); full gate passes.

### Task 15: TUI bus integration (describe, availability, fallback)

- **Satisfies:** AC13
- **Depends on:** Tasks 9, 14
- **Files:** `crates/aitm-tui/src/bus.rs` (modify), `crates/aitm-tui/src/app.rs` (modify: `descriptors` and `availability` fields, slow-tick refresh), `crates/aitm-tui/tests/descriptor_bus.rs` (create)
- **Change:** at connect, call `protocol.describe` if `has_tool` else use the bundled book; on the slow tick call `protocol.availability` with `if_revision`; store `ActionVm`-ready availability. No rendering change.
- **Test:** `old_core_uses_bundled_snapshot` runs against the existing in-process mock bus without `protocol.describe` and asserts the book equals `bundled()`. `unchanged_revision_keeps_state`.
- **Done when:** passes; Task 1 goldens unchanged; full gate passes.

### Task 16: Web model layer and conformance

- **Satisfies:** AC6, AC13, AC14
- **Depends on:** Task 12
- **Files:** `apps/web/src/descriptor/{types,path,format,predicate,project,book}.ts` (create), `apps/web/scripts/gen-langs.mjs` (modify: also emit `src/descriptor/bundled.gen.ts` from `descriptors.json`), `apps/web/src/descriptor/conformance.test.ts` (create)
- **Change:** TypeScript implementations of the Task 6 API with the same names (`projectRow`, `formatCell`, `evalWhen`, `DescriptorBook.kind(id)` returning an `Unknown` handle). Types generated from `descriptor.schema.json` where practical.
- **Test:** `conformance.test.ts` iterates the shared `conformance.json` and asserts `toEqual(expected_vm)` for every case; `unknown_kind_is_labelled`; `label_is_text_not_markup` asserts a `<img onerror>` label is returned as literal text.
- **Done when:** `npm run gen && tsc --noEmit && vitest run` passes; Task 2 snapshots unchanged.

### Task 17: Web bus integration

- **Satisfies:** AC13
- **Depends on:** Tasks 9, 16
- **Files:** `apps/web/src/bus/ws.ts` (modify), `apps/web/src/state/app.ts` (modify: descriptor and availability signals), `apps/web/src/bus/mock.ts` (modify: serve bundled snapshot for `protocol.describe`), `apps/web/src/descriptor/bus.test.ts` (create)
- **Change:** fetch `protocol.describe` when `tools` includes it, else bundled; poll `protocol.availability {if_revision}` on the slow timer; mock returns the snapshot so no hand-rolled kinds remain in `fixtures.ts`.
- **Test:** `falls_back_to_bundled_without_describe`; `availability_revision_roundtrip`.
- **Done when:** passes; Task 2 snapshots unchanged.

### Task 18: macOS model layer and conformance

- **Satisfies:** AC6, AC13, AC14
- **Depends on:** Task 12
- **Files:** `apps/mac/Sources/AitmproxyKit/Descriptor/*.swift` (create: `DescriptorSet`, `MiniPath`, `Formatter`, `Predicate`, `RowProjector`, `DescriptorBook`), `apps/mac/tools/gen-langs.swift` (modify: embed the snapshot into `LanguageDefs.swift`), `apps/mac/Tests/AitmproxyKitTests/DescriptorConformanceTests.swift` (create)
- **Change:** Swift implementations with the same API names, no SwiftUI import (Kit rule). `DescriptorBook.kind(_:)` returns an `.unknown(id)` handle.
- **Test:** `allConformanceCasesPass` loads the shared `conformance.json` and compares every `expected_vm`; `unknownKindIsLabelled`; `oversizeLabelRejected`.
- **Done when:** `swift test` passes in the Terminal panel; Task 3 goldens unchanged.

### Task 19: macOS bus integration

- **Satisfies:** AC13
- **Depends on:** Tasks 9, 18
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (modify), `apps/mac/Sources/Aitmproxy/Session+Descriptor.swift` (create), `apps/mac/Tests/AitmBusClientTests/DescriptorBusTests.swift` (create, uses `FakeBusServer`)
- **Change:** fetch `protocol.describe` through `listTools` presence, else bundled; availability on the existing poll cadence with `if_revision`; expose `session.descriptors` and `session.availability`.
- **Test:** `oldCoreFallsBackToBundled`; `unchangedRevisionNoChurn`.
- **Done when:** `swift test` passes in the Terminal panel; no visible change.

### Stage 3: Unified list (three parallel tracks; G2 follows)

### Task 20: TUI list for L4 and WebSocket through descriptors

- **Satisfies:** AC7, AC8, AC9 (TUI, non-HTTP kinds)
- **Depends on:** Tasks 1, 15, 11
- **Files:** `crates/aitm-tui/src/model.rs` (modify: `FlowKind` enum to `KindId(Arc<str>)`; `FlowRow` to `{kind, cells}`), `crates/aitm-tui/src/ui/flows.rs` (modify: one generic row renderer; delete `l4_row_line`), `crates/aitm-tui/src/bus.rs` (modify: source-driven poll replaces `l4_poll`'s N+1), `crates/aitm-tui/src/l4.rs` (modify: drop row model), `crates/aitm-tui/tests/kind_guard.rs` (create)
- **Change:** rows for non-HTTP kinds come from `DescriptorBook` and `l4.flow.table`; an unknown kind renders a labelled placeholder row; badge colors come from palette slots.
- **Test:** Task 1 goldens equal for the l4 and websocket rows. `unknown_kind_renders_row` feeds a `zzz` kind and asserts the rendered line contains the badge text `zzz` and the placeholder inspector text `no renderer for kind zzz`. `kind_guard` greps `src/` for `FlowKind::L4` and `"l4"` literals outside the allowlist and expects zero hits.
- **Done when:** goldens, AC8, AC9 (non-HTTP) pass; full gate passes.

### Task 21: TUI HTTP list through descriptors (cuttable)

- **Satisfies:** AC7, AC12
- **Depends on:** Task 20
- **Files:** `crates/aitm-tui/src/ui/flows.rs` (modify), `crates/aitm-tui/src/model.rs` (modify), `crates/aitm-tui/src/theme.rs` (modify: badge palette slots), `crates/aitm-tui/tests/golden/` (unchanged)
- **Change:** HTTP rows use the descriptor path (`host-path`, `http-status`, `method.{method}`); the chip and `Chip::matches` kind arms read the book.
- **Test:** Task 1 goldens equal for the http row; `list_render_budget` (ignored, run in Terminal) asserts the median is within 110% of the Task 1 baseline.
- **Done when:** golden and budget hold, or the task is cut and HTTP stays built-in (Matt's call at G2).

### Task 22: Web unified list, L4 and WebSocket through descriptors

- **Satisfies:** AC7, AC8, AC9 (web, non-HTTP kinds), AC13
- **Depends on:** Tasks 2, 17
- **Files:** `apps/web/src/model/flow.ts`, `apps/web/src/bus/normalize.ts`, `apps/web/src/state/app.ts`, `apps/web/src/flows/FlowList.tsx`, `apps/web/src/flows/columns.ts` (modify); `apps/web/src/flows/L4FlowRow.tsx`, `apps/web/src/flows/UnionFlowList.tsx` if present (delete); `apps/web/src/panels/l4/model.ts` (modify: drop `KNOWN_KINDS` and `kindDescriptor`); `apps/web/scripts/gen-langs.mjs` (modify: stop emitting `flowKinds`); `docs/design/languages/flow-kinds.json` (delete); `docs/design/languages/validate.test.mjs` (modify: drop its flow-kinds checks); `apps/web/src/flows/kind-guard.test.ts` (create)
- **Change:** one `FlowEntry` pipeline for every kind (virtualized, sortable, keyboard-navigable) fed by source-driven polling of `flow.table` and `l4.flow.table`; remove the appended unvirtualized L4 block and the dual `FlowKind` types; unknown kinds render a labelled row. Sized as the hardest web task (R7); split if it overruns.
- **Test:** Task 2 snapshots equal for the l4 and websocket rows. `unknown_kind_renders_row` asserts the cell text `zzz` and the placeholder `no renderer for kind zzz`. `kind_guard` fails on `'l4'` or `'websocket'` literals outside the allowlist (builtin registry, bundled loader, fixtures). `moveSelection_crosses_kinds` asserts keyboard selection moves from an http row to an l4 row (it does not today).
- **Done when:** the gate passes, `flow-kinds.json` has no remaining reader, and a dev-server preview shows the mixed list.

### Task 23: Web HTTP list through descriptors (cuttable)

- **Satisfies:** AC7, AC12
- **Depends on:** Task 22
- **Files:** `apps/web/src/flows/FlowRow.tsx`, `apps/web/src/flows/columns.ts`, `apps/web/src/state/app.ts` (`matchesChip`, `fieldValue`), `apps/web/src/flows/chips.ts` (modify)
- **Change:** HTTP rows project through the descriptor; the `kind === 'websocket'` branches in `FlowRow` and `columns.ts` go.
- **Test:** Task 2 snapshot equality for the http row; `list.bench.ts` mean within 110% of baseline.
- **Done when:** parity and budget hold, or the task is cut at G2.

### Task 24: macOS list for L4 and WebSocket through descriptors, L4 live

- **Satisfies:** AC7, AC8, AC9 (macOS, non-HTTP kinds), AC11 (data side)
- **Depends on:** Tasks 3, 19, 11
- **Files:** `apps/mac/Sources/AitmproxyKit/Flow.swift` (modify: `FlowKind` enum to `KindId`), `FlowSummary.swift` (modify: never `nil` for an unknown kind), `L4.swift` (modify: drop row mapping, keep gates), `apps/mac/Sources/Aitmproxy/FlowTable/FlowCellView.swift` (modify: generic cell renderer), `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (modify: source-driven poll including `l4.flow.table`), `apps/mac/Tests/AitmproxyKitTests/KindGuardTests.swift` (create)
- **Change:** `FlowRow` becomes `{kind, cells}` over the existing slots; L4 flows load live over the bus through the descriptor's table source (the fixtures-only path goes); unknown kinds render a labelled row instead of being dropped by `compactMap`.
- **Test:** Task 3 goldens equal for l4 and websocket. `unknownKindRowIsKept` feeds kind `zzz` through `FlowSummary` and asserts the row count is 1 (it is 0 today). `KindGuardTests` greps `Sources/` for `.l4`, `FlowKind.websocket` and string literals outside the allowlist, expecting zero.
- **Done when:** `swift test` passes in the Terminal panel; a live check against a real core with `l4.enabled: true` shows L4 rows over the bus.

### Task 25: macOS HTTP list through descriptors (cuttable)

- **Satisfies:** AC7, AC12
- **Depends on:** Task 24
- **Files:** `apps/mac/Sources/Aitmproxy/FlowTable/FlowColumns.swift`, `FlowTableView.swift`, `FlowCellView.swift`, `FlowRowActions.swift` (modify), `apps/mac/Sources/AitmproxyKit/ContentCategory.swift` (modify: WebSocket chip from the book)
- **Change:** HTTP rows project through the descriptor; `FlowColumn` stays as the slot set so persisted `columns.json` and sort keys remain valid.
- **Test:** Task 3 goldens equal for http; `listProjectionBudget` within 110% of baseline; a saved `columns.json` from the previous build loads unchanged (`persistedColumnsRoundTrip`).
- **Done when:** parity and budget hold, or the task is cut at G2.

### Stage 4: Inspector, actions, gates (three parallel tracks)

### Task 26: TUI generic pane host and widgets

- **Satisfies:** AC7, AC8, AC9
- **Depends on:** Task 20
- **Files:** `crates/aitm-tui/src/ui/panes/{mod,fields,stream,tree,bytes}.rs` (create), `crates/aitm-tui/src/ui/inspector.rs` (modify: dispatch by descriptor panes; `http.exchange` as a registry entry), `crates/aitm-tui/src/ui/l4.rs` (delete the inspector parts the widgets replace), `crates/aitm-tui/src/app.rs` (modify: `tab_step`, `InspectorPaneToggle`, `REQUEST_TABS`/`RESPONSE_TABS` become the built-in's own)
- **Change:** `fields`, `message-stream`, `tree` and `bytes` widgets; WS frames and L4 packets share the one stream widget; an unsupported pane type renders `unsupported pane type <name>`.
- **Test:** Task 1 inspector goldens equal for websocket and l4 (compose area excluded until Task 27). `unsupported_pane_is_labelled`.
- **Done when:** goldens pass; full gate passes.

### Task 27: TUI compose pane and confirm handshake

- **Satisfies:** AC7, AC11
- **Depends on:** Task 26
- **Files:** `crates/aitm-tui/src/ui/panes/compose.rs` (create), `crates/aitm-tui/src/l4.rs` (modify: craft buffer moves behind the generic pane; delete the rest), `crates/aitm-tui/src/ui/overlays.rs` (modify: the confirm overlay becomes command-agnostic), `crates/aitm-tui/src/keys.rs` (modify)
- **Change:** a YAML compose pane with a `preview` command rendering hex, submit through the action, and the existing `needs_confirmation` / `_confirm` handshake for any `confirmable` command.
- **Test:** `compose_preview_calls_l4_craft` asserts the mock bus saw `l4.craft` with the buffer text; `confirmable_submit_requires_confirm` asserts no wire command is issued before the operator confirms.
- **Done when:** passes; the L4 craft and inject flow matches Task 1 goldens.

### Task 28: TUI actions by intent, availability, legacy deletion

- **Satisfies:** AC3 (UI side), AC11, AC9
- **Depends on:** Tasks 15, 27
- **Files:** `crates/aitm-tui/src/app.rs` (modify: `Resume`, `Kill`, `Edit`, `Replay` route by the selected kind's actions and intents; delete the per-kind overloads and the 105 hard-coded L4 and WS tool-name literals the descriptor now carries), `crates/aitm-tui/src/ui/bars.rs` (modify: key hints from actions), `crates/aitm-tui/src/ui/overlays.rs` (modify: availability-driven disabled text)
- **Change:** disabled actions show the server's `reason.message`; the stale "needs F9" strings are replaced by descriptor-driven reasons.
- **Test:** `resume_on_l4_intercept_calls_forward` asserts the mock bus saw `l4.intercept.forward` (and no `flow.resume`). `disabled_action_shows_reason` asserts the hint text equals the fixture `reason.message`. `kind_guard` still reports zero literals.
- **Done when:** passes; full gate passes.

### Task 29: Web generic pane host and widgets

- **Satisfies:** AC7, AC8, AC9
- **Depends on:** Task 22
- **Files:** `apps/web/src/inspector/panes/{PaneHost,Fields,Stream,Tree,Bytes}.tsx` (create), `apps/web/src/inspector/Inspector.tsx` (modify), `apps/web/src/inspector/ResponsePane.tsx` (modify: drop `WS_TABS`/`isWs`), `apps/web/src/inspector/WsFrames.tsx`, `apps/web/src/panels/l4/{PacketList,LayerTree}.tsx` (delete after migration), `apps/web/src/shell/Shell.tsx` (modify: drop `selectedIsL4` dispatch)
- **Change:** one pane host; the stream widget replaces `WsFrames` and `PacketList`; `http.exchange` resolves from a registry of one.
- **Test:** Task 2 inspector snapshots equal for websocket and l4 (compose excluded); `unsupported_pane_is_labelled`.
- **Done when:** gate passes; dev-server preview shows WS and L4 inspectors.

### Task 30: Web compose pane and confirm handshake

- **Satisfies:** AC7, AC11
- **Depends on:** Task 29
- **Files:** `apps/web/src/inspector/panes/Compose.tsx` (create), `apps/web/src/panels/l4/{CraftEditor,ConfirmInject,inject}.ts*` (delete after migration), `apps/web/src/lib/schema-form/` (reuse; modify only if a gap appears)
- **Change:** generic compose pane (YAML editor, `preview` command to hex, submit through the action, command-agnostic confirm using the existing `needs_confirmation` / `_confirm` flow).
- **Test:** `compose_preview_calls_l4_craft`; `confirmable_submit_requires_confirm`.
- **Done when:** gate passes; L4 craft and inject parity with Task 2.

### Task 31: Web actions by intent, availability, legacy deletion

- **Satisfies:** AC3 (UI side), AC11, AC9
- **Depends on:** Tasks 17, 30
- **Files:** `apps/web/src/flows/ContextMenu.tsx`, `apps/web/src/inspector/InterceptBar.tsx`, `apps/web/src/state/app.ts` (modify: `matchesSidebar` and `select` L4 special cases go), `apps/web/src/shell/Sidebar.tsx` (modify: kind filters from the book), `apps/web/src/panels/agent/L4Toggles.tsx` (unchanged in v1)
- **Change:** menus and bars come from descriptor actions filtered by `when` and availability; disabled-with-reason replaces the three ad-hoc gate-string sources; global shortcuts route by intent.
- **Test:** `resume_on_l4_intercept_calls_forward`; `disabled_action_shows_reason`; `kind_guard` zero literals.
- **Done when:** gate passes; no `selectedIsL4` or `l4Ids` remain.

### Task 32: macOS generic pane host and widgets

- **Satisfies:** AC7, AC8, AC9
- **Depends on:** Task 24
- **Files:** `apps/mac/Sources/Aitmproxy/Inspector/Panes/{PaneHost,FieldsPane,StreamPane,TreePane,BytesPane}.swift` (create), `InspectorView.swift` (modify: dispatch by panes), `WebSocketInspector.swift` and the packet-list and layer-tree parts of `L4Inspector.swift` (delete after migration)
- **Change:** `PaneTabs` hosts descriptor panes; `StreamPane` replaces `WSFramesList` and `L4PacketList`; `http.exchange` is the registry's one entry. Fix the L4 `SummaryStrip` badge colour by construction (same palette slot as the list).
- **Test:** `PaneGoldenTests` equal to Task 3 inspector goldens for websocket and l4; `unsupportedPaneIsLabelled`.
- **Done when:** `swift test` passes in the Terminal panel.

### Task 33: macOS compose pane and confirm handshake

- **Satisfies:** AC7, AC11
- **Depends on:** Task 32
- **Files:** `apps/mac/Sources/Aitmproxy/Inspector/Panes/ComposePane.swift` (create), `apps/mac/Sources/AitmproxyKit/L4.swift` (modify: craft parser moves behind the generic pane or is deleted), `L4Inspector.swift` (delete remainder)
- **Change:** generic compose pane (YAML, `preview` to hex, submit through the action, command-agnostic confirm sheet). The craft editor's YAML parser stays as Kit code behind the pane.
- **Test:** `composePreviewCallsL4Craft`; `confirmableSubmitRequiresConfirm`.
- **Done when:** `swift test` passes; live L4 craft and inject works against a real core in the Terminal panel.

### Task 34: macOS actions by intent, availability, legacy deletion; Stage 4 exit metric

- **Satisfies:** AC3 (UI side), AC9, AC11; R2 exit metric
- **Depends on:** Tasks 19, 33
- **Files:** `apps/mac/Sources/Aitmproxy/FlowTable/FlowRowActions.swift`, `FlowTableView.swift`, `apps/mac/Sources/Aitmproxy/App.swift` (menu), `Session+Verbs.swift` (modify), `apps/mac/Sources/AitmproxyKit/L4.swift` (delete the rest of the per-kind code)
- **Change:** Flow menu and row menu become kind-aware through actions; an L4 intercept row's Resume and Kill call `l4.intercept.*` (fixes the survey bug by construction); the L4 session no longer maps to `.paused`.
- **Test:** `resumeOnL4InterceptCallsForward`; `disabledActionShowsReason`; `nonHttpBuiltinCountIsZero` asserts the built-in registry holds exactly `http.exchange`.
- **Done when:** `swift test` passes; the three UIs' kind-guard tests report zero literals outside the allowlist.

### Stage 5: Proof (G3 follows)

### Task 35: Foreign-kind render tests in all three UIs

- **Satisfies:** AC8, AC10
- **Depends on:** Tasks 13, 28, 31, 34
- **Files:** `crates/aitm-tui/tests/foreign_kind.rs`, `apps/web/src/descriptor/foreign-kind.test.tsx`, `apps/mac/Tests/AitmproxyKitTests/ForeignKindTests.swift` (create); each loads the `test` descriptor and rows from `docs/design/protocols/`, not from UI source
- **Change:** each UI renders the synthetic protocol's list row, `fields` and `message-stream` inspector and one action end to end through its real widgets.
- **Test:** each asserts the badge text `TEST`, the row cell text from the fixture, the stream's three message lines, and the action's enabled state, as literals from `conformance.json`.
- **Done when:** all three pass; the Task 20, 22, 24 kind guards still report zero.

### Task 36: Zero-diff walkthrough script

- **Satisfies:** AC10, AC15
- **Depends on:** Task 35
- **Files:** `scripts/check-descriptor-zero-diff.sh` (create), `docs/design/protocols/README.md` (modify: final "add a protocol in one page")
- **Change:** the script adds a second synthetic protocol `test2` (descriptor plus fixture rows only), runs the three UI test suites, and asserts `git diff --name-only` lies inside `crates/aitm-proto-test/**`, `docs/design/protocols/**` and UI fixture directories, then reverts. The README documents exactly these steps.
- **Test:** the script exits 0 and prints the allowed-path set; run once in the Terminal panel and once in CI.
- **Done when:** exits 0; the README steps are the script's steps.

### Task 37: Documentation sweep

- **Satisfies:** AC15
- **Depends on:** Task 36
- **Files:** `docs/design/operator-ui-foundation.md` (modify: flow-kind references), `docs/design/languages/README.md` (modify: remove the deprecated `flow-kinds.json` entry), `docs/research/MEMORY.md` (modify), `CLAUDE.md` (modify: pointer only if Matt wants one)
- **Change:** every doc reference to per-UI generated flow-kind files or `flow-kinds.json` points at `docs/design/protocols/`.
- **Test:** `grep -rn "flow-kinds.json\|flow_kinds.rs\|FlowKind.swift" docs/ apps/ crates/` returns only this plan, the spec and research 11.
- **Done when:** the grep is clean and the final whole-branch panel review of the milestone has no open findings. **G3.**

### Stage 6: Generic command surfaces (not planned)

Capture controls, the L4 scope view, agent-gate toggles, the scanner panel and filter atoms. Needs its own scope after G3, and a typed scanner result contract first. Spec Q4.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
