# Operator-UI scripting / highlight / L4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give all three operator UIs edit-path syntax highlighting + autocomplete for Rhai and PoC-YAML, one portable filter grammar, an authorable Scripts panel, and L4/full flow-kind coverage — all driven from shared checked-in definitions.

**Architecture:** One source of truth per language/flow-kind under `docs/design/languages/` (data, not code), consumed by each surface's existing generation/loading path exactly as `tokens.json` is. Shared **conformance fixtures** prove the three surfaces stay identical. Per-surface realization reuses each surface's existing tokenizer/viewer/filter machinery.

**Tech Stack:** JSON data definitions; web = SolidJS + CodeMirror 6 (`apps/web`); TUI = Rust + ratatui (`crates/aitm-tui`); macOS = Swift/SwiftUI + AppKit (`apps/mac`); core follow-ups = Rust (`aitm-core`, `aitm-plugin-rhai`).

**Spec:** `docs/superpowers/specs/2026-10-27-aitmproxy-ui-scripting-highlight-l4-design.md`

## Global Constraints

- Colour uses the foundation `syntax.*` tokens (`key`/`string`/`number`/`boolean`/`punct`) plus additive `comment`/`keyword`; colour on data, never chrome. (foundation §2.2)
- Data face (monospace) carries all code; six-size scale; keyboard-triggered actions do not animate; popovers radius 10, `floating` shadow, 160ms. (foundation §2.3, §2.8)
- Surfaces are bus clients; new capability = a new `Command`, never a side channel; feature-detect from `tools/list` and degrade honestly when absent. (foundation §4)
- Shipped M3 scripting bus surface is exactly `script.validate { path }`, `script.reload { name }`, `findings.list { limit? }`; scripts are a config `scripts:` list (no folder scan); registry sealed after build (reload swaps hooks only). (verified `origin/feat/aitmproxy-m3`)
- A surface never hard-codes a keyword, host-function name, PoC key, or filter atom — all come from the definition files.
- Gate per surface: web `npm run test && npm run typecheck && npm run build`; Rust `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`; macOS `swift test` + `tools/verify.sh`.

## Review Focus

Inputs the spec implies but that no single happy-path task exercises; each gets its pinned test in the owning task:

- **Malformed / partial source while typing** — an unterminated string, a half-written `flow.` , an odd YAML line must still render (tolerant colorizer), not throw or blank the editor. (Tasks 3, 6, 9 — highlighter tolerance tests)
- **A filter string valid on one surface parses identically on another** — the portability guarantee; the conformance fixture is the test. (Task 2 defines it; Tasks 5, 8, 11 assert it per surface)
- **Catalog lists a function the engine doesn't provide (or omits one)** — drift silently breaks completion/trust. (Task 12 drift-guard)
- **Remote/web Save with no disk access** — must disable with "needs core F8b", never silently no-op. (Tasks 4, 7, 10 — degradation test)
- **An unknown/absent flow kind** — must render a labelled placeholder row, never an empty one. (Tasks 6, 9, 11 — flow-kind fallback test)

---

## Phases, worktrees & external dependencies (read before executing)

The three UIs are on **separate unmerged branches** (web PR #3, TUI PR #5, macOS in flight). A single worktree cannot build all three. Work is therefore phased:

- **Phase A — shared definitions** (Tasks 1–2): data + a self-validation test. Buildable **now** on a `feat/ui-ext-defs` worktree off `main`. Unblocks every surface.
- **Phase B — per surface** (web Tasks 3–6, TUI Tasks 7–9*, macOS Tasks 10–11*): each runs **on that surface's branch** (or on `main` after that surface's foundation PR merges). Each depends on Phase A being merged/available to it.
- **Phase C — core follow-ups** (Task 12 drift-guard here; F8a/F8b/F8c are **their own spec+plan**, Rust core, referenced not detailed).

**External gates** (feature-detected; UI ships degraded until present): `script.list` (F8a), `script.validate{source}`+`script.save` (F8b), `script.enable/disable` (F8c), `flow.detail.messages` (F5), `ws.send` (F9), the `l4.*` command set (M5). L4 inspector content (Tasks 6/9/11 Part 3) is **M5-gated** and built against fixtures until M5 lands.

> **Sequencing is Matt's call** (raised at handoff): either (a) merge the three UI PRs to `main` first, then run all of Phase B in one `feat/ui-ext` worktree; or (b) run each surface's Phase-B tasks on its own branch and merge per surface. The task list below is identical either way; only the worktree each task runs in differs.

---

## Tasks

### Task 1: Shared language-definition files

**Files:**
- Create: `docs/design/languages/rhai.grammar.json`, `rhai.api.json`, `poc-yaml.schema.json`, `filter.grammar.json`, `flow-kinds.json`
- Create: `docs/design/languages/README.md` (what each file is, who generates from it)
- Test: `docs/design/languages/validate.test.mjs` (node, no framework dep) — runs in CI via the web `npm run test` wiring or a standalone `node --test`.

**Interfaces:**
- Produces: the five JSON files. Shapes (keys) as spec §Part-1.1 / §3.1: `rhai.grammar.json` {keywords[], operators[], punctuation[], lexical{comment,string,number,identifier}, map_token{}}; `rhai.api.json` {api_version, hooks[], flow{}, msg{}, globals{}, dsl[]} each entry {name, signature?, description}; `poc-yaml.schema.json` key-tree with {description, enum?} per node; `filter.grammar.json` {atoms[], combinators[], stacked_fields[], operators[], bijection}; `flow-kinds.json` [{kind, badge{label,token}, list_cells, inspector, detail_cmd, realtime}].

- [ ] **Step 1: Write the failing test** — `validate.test.mjs`: asserts each file parses as JSON; `rhai.api.json.hooks` contains the nine hook names from the spec; `poc-yaml.schema.json` top-level has `id/info/variables/steps/success`; `filter.grammar.json.atoms` includes `~u ~m ~s ~l4 ~tcp ~udp ~icmp`; `flow-kinds.json` has kinds `http`, `websocket`, `l4`.
- [ ] **Step 2: Run it — expect FAIL** (files absent). `node --test docs/design/languages/validate.test.mjs`
- [ ] **Step 3: Author the five files** from spec §Part-1.1 and §3.1, copying the Rhai hook/flow/host-fn/DSL catalog verbatim from the plugin-system spec §"Host functions"/§"flow object" and the PoC keys from the PoC-language spec §"Step types"/§"Matcher/extractor DSL". The L4 badge token = `l4` (slate/indigo, Open-question-1 resolved).
- [ ] **Step 4: Run it — expect PASS.**
- [ ] **Step 5: Commit** — `docs(design): shared language-definition files for UI highlighting/completion`.

**Done when:** the files exist, `validate.test.mjs` passes.

### Task 2: Conformance fixtures

**Files:**
- Create: `docs/design/languages/filter.conformance.json`, `rhai.completion.conformance.json`, `poc.completion.conformance.json`
- Test: extend `validate.test.mjs` (fixtures parse + reference only atoms/keys defined in Task 1's files).

**Interfaces:**
- Consumes: Task 1 files.
- Produces: `filter.conformance.json` = [{input, tokens:[{type,text}], ast}] used by Tasks 5/8/11; the two completion fixtures = [{context, caret, expected_candidates[]}] used by the per-surface completion tasks.

- [ ] **Step 1: Write the failing test** — fixtures parse; every atom in `filter.conformance.json` exists in `filter.grammar.json.atoms`; every candidate in the completion fixtures exists in `rhai.api.json`/`poc-yaml.schema.json`.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Author the fixtures** — ≥12 filter strings covering each atom, combinators, precedence, bare-word=`~u`, and a copy-between-surfaces round-trip pair; completion fixtures covering top-level hooks, `flow.`/`flow.request.`/`msg.` members, YAML key-position + enum-after-`:`.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit.**

**Done when:** fixtures validated; they reference only Task-1-defined symbols.

### Task 3: Web — Rhai + YAML CodeMirror languages (highlight)

**Files:** Modify `apps/web/src/viewers/codemirror.ts` (add `Lang.rhai`, `Lang.yaml`); create `apps/web/src/viewers/lang/rhai.ts`, `lang/yaml.ts`, generated from the Task-1 files via `apps/web/scripts/gen-langs.mjs` (create). Test: `apps/web/src/viewers/lang/rhai.test.ts`, `lang/yaml.test.ts`. Satisfies AC1, AC2 (web). Depends on Task 1.

**Interfaces:** Consumes `rhai.grammar.json`, `poc-yaml.schema.json`. Produces `Lang.rhai`/`Lang.yaml` usable by `CodeViewer.tsx` in edit mode.

- [ ] Step 1: failing tests — tokenizing `fn on_request(flow){ let x="a"; // c }` yields keyword/identifier/string/comment token classes mapped to `syntax.*`; a malformed unterminated string still tokenizes (Review Focus: tolerance).
- [ ] Step 2: run — FAIL.
- [ ] Step 3: implement the StreamLanguage tokenizers + `gen-langs.mjs`; wire into `codemirror.ts`; **delete `apps/web/src/panels/findings/yaml.ts`** and point the Findings editor at `Lang.yaml` (both view + edit).
- [ ] Step 4: run — PASS; `npm run typecheck && npm run build`.
- [ ] Step 5: commit.

**Done when:** tests pass, gate green, `yaml.ts` removed.

### Task 4: Web — completion sources + authorable Scripts panel

**Files:** Create `apps/web/src/viewers/lang/complete-rhai.ts`, `complete-yaml.ts`; modify `apps/web/src/panels/ScriptsPanel.tsx` (editor + Validate + Save & Reload + list + corrected empty state). Test: `complete-rhai.test.ts`, `ScriptsPanel.test.ts`. Satisfies AC3, AC4, AC7–AC11 (web). Depends on Tasks 2, 3.

**Interfaces:** Consumes the completion fixtures + `rhai.api.json`/`poc-yaml.schema.json`; the bus `script.validate`/`script.reload`, feature-detecting F8a/F8b/F8c.

- [ ] Step 1: failing tests — completion source returns the fixture's expected candidates for each context; Validate on a bad script surfaces a positioned error; Save disabled with "needs core F8b" when `script.save` absent (Review Focus: remote Save); empty state contains no "scripts folder" text (AC9).
- [ ] Step 2: run — FAIL.
- [ ] Step 3: implement completion sources (CM `autocompletion`), wire ScriptsPanel to the bus with feature-detection + restart banner (AC10) + agent-gate display (AC11).
- [ ] Step 4: run — PASS; gate.
- [ ] Step 5: commit.

### Task 5: Web — filter grammar from shared definition

**Files:** Modify `apps/web/src/flows/FilterBar.tsx` + create `apps/web/src/flows/filter-grammar.ts` (generated). Test: `filter-grammar.test.ts` runs `filter.conformance.json`. Satisfies AC6 (web). Depends on Task 2.

- [ ] Step 1: failing test — each conformance entry parses to the expected AST + token spans.
- [ ] Step 2: run — FAIL. Step 3: generate the parser/highlighter from `filter.grammar.json`; replace the hand-rolled parser. Step 4: PASS; gate. Step 5: commit.

### Task 6: Web — flow-kind model + L4 (inert) + WS gated pieces

**Files:** Create `apps/web/src/flows/flow-kinds.ts` (from `flow-kinds.json`); modify the flow-list row + inspector to iterate `FlowKind`; create `apps/web/src/panels/l4/*` (packet list, layer tree reusing `JsonTree`, hex reusing `HexViewer`, craft editor reusing Task 3 langs). Test: `flow-kinds.test.ts`. Satisfies AC12–AC14 (web). Depends on Tasks 1, 3.

- [ ] Step 1: failing tests — an `l4` fixture row renders the L4 badge + packet inspector; an unknown kind renders a labelled placeholder (Review Focus); WS frames show "needs core F5" when `flow.detail` absent and send-frame "needs core F9" (AC14); out-of-L4-scope packet actions disabled (AC13).
- [ ] Step 2: run — FAIL. Step 3: implement against L4 fixtures. Step 4: PASS; gate. Step 5: commit.

### Task 7: TUI — Rhai + YAML tokenizer + filter + completion popup

**Files:** Create `crates/aitm-tui/src/syntax/{mod,rhai,yaml}.rs` (generated from Task-1 files by `build.rs`); modify `crates/aitm-tui/build.rs`, `src/filter.rs` (pin to `filter.grammar.json`), create `src/ui/complete.rs`. Test: `crates/aitm-tui/tests/syntax.rs`, `tests/filter_conformance.rs`, `tests/complete.rs`. Satisfies AC1–AC4, AC6 (TUI). Depends on Tasks 1, 2.

- [ ] Step 1: failing tests — tokenizer maps Rhai/YAML to `theme.rs` styles incl. a malformed line (tolerance); `filter_conformance.rs` runs `filter.conformance.json`; completion popup candidates match the completion fixtures.
- [ ] Step 2: run — FAIL. Step 3: implement tokenizers, generation in `build.rs`, the popup overlay, and pin `filter.rs` to the shared grammar. Step 4: PASS; `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`. Step 5: commit.

### Task 8: TUI — authorable Scripts view

**Files:** Modify the Scripts view (`src/ui/sidebar.rs` + a new `src/ui/scripts.rs`); wire `script.validate`/`script.reload` via the bus task, external `$EDITOR` path per foundation §3.8, feature-detect F8a–F8c. Test: `tests/scripts.rs`. Satisfies AC7–AC11 (TUI). Depends on Task 7.

- [ ] Steps as Task 4, TUI-shaped (positioned error in the console pane; corrected empty state; disabled actions with "needs core F*"); gate; commit.

### Task 9: TUI — flow-kind + L4 (inert) + WS gated pieces

**Files:** Create `crates/aitm-tui/src/flow_kinds.rs`; add an `l4` viewer set under `src/viewers/` (packet list reusing the WS frame renderer, layer tree, hex via existing `hex.rs`); modify `model.rs`/`ui/flows.rs`/`ui/inspector.rs`. Test: `tests/flow_kinds.rs` + a snapshot. Satisfies AC12–AC14 (TUI). Depends on Tasks 1, 7.

- [ ] Steps as Task 6, TUI-shaped (placeholder row for unknown kind; L4 against fixtures; WS gated text); snapshot reviewed; gate; commit.

### Task 10: macOS — Syntax.swift Rhai/YAML + completion + authorable Scripts

**Files:** Modify `apps/mac/Sources/AitmproxyKit/Syntax.swift` (Rhai + YAML token sets from Task-1 files via `tools/gen-langs.swift` (create)); modify `apps/mac/Sources/Aitmproxy/Panels/ScriptsPanel.swift` (editor + completion provider + Validate/Save&Reload + **fix the empty-state copy**), `FilterExpressionSyntax.swift` (pin to shared grammar). Test: `apps/mac/Tests/AitmproxyKitTests/SyntaxTests.swift`, `FilterConformanceTests.swift`, `ScriptsTests.swift`. Satisfies AC1–AC4, AC6–AC11 (macOS). Depends on Tasks 1, 2.

- [ ] Step 1: failing tests — token sets colour Rhai/YAML incl. a malformed line; `FilterConformanceTests` runs `filter.conformance.json`; completion provider returns fixture candidates; empty state has no "scripts folder" text (AC9); Save disabled sans F8b.
- [ ] Step 2: run — FAIL. Step 3: implement `Syntax.swift` sets + `gen-langs.swift`, NSTextView completion controller, ScriptsPanel bus wiring + restart banner + agent-gate, pin filter syntax. Step 4: PASS; `swift test` + `tools/verify.sh`. Step 5: commit.

### Task 11: macOS — flow-kind + L4 (inert) + WS gated pieces

**Files:** Create `apps/mac/Sources/AitmproxyKit/FlowKind.swift` (from `flow-kinds.json`); create `apps/mac/Sources/Aitmproxy/Panels/L4/*` (packet list, layer tree reusing `JSONTree.swift`, hex reusing `HexDump.swift`, craft editor); modify the flow table + inspector to iterate `FlowKind`. Test: `FlowKindTests.swift` + snapshots. Satisfies AC12–AC15 (macOS). Depends on Tasks 1, 10.

- [ ] Steps as Task 6, macOS-shaped; placeholder for unknown kind; L4 against fixtures; WS gated; light+dark snapshot review (AC15); gate; commit.

### Task 12: Rhai API-catalog drift guard (core)

**Files:** Create a test in `crates/aitm-plugin-rhai/tests/api_catalog.rs` that loads `docs/design/languages/rhai.api.json` and asserts every `globals`/`flow`/`msg`/`dsl` entry maps to a registered `register_fn`/member, and vice-versa. Satisfies AC5. Runs wherever the rhai crate lives (post-M3-merge). Depends on Task 1.

- [ ] Step 1: failing test — catalog ↔ engine bijection; add a deliberately-stale entry to confirm it fails. Step 2: run — FAIL. Step 3: implement; remove the stale entry. Step 4: run — PASS; Rust gate. Step 5: commit.

> **Core follow-ups F8a / F8b / F8c** (`script.list`; `script.validate{source}` + `script.save` + `registers` field + `scripts.allow_agent_authoring`; `script.enable/disable`) are **each their own spec + plan** (Rust core), per the spec. They unblock the live Scripts list, remote Save, and live toggles; until shipped, Tasks 4/8/10 ship degraded against feature-detection. Not detailed here.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|

## Shipped

Filled at stage 7.
