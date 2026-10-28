# Shared language definitions

One checked-in definition per language and per flow-kind set, as **data, not
code**, so the three operator UIs (web, TUI, macOS) never diverge. They sit
beside `docs/design/tokens.json` and are consumed the same way: each surface's
existing generation or loading step reads them, and no surface hard-codes a
keyword, host-function name, PoC key or filter atom. Source of truth for what
they contain: the approved spec
`docs/superpowers/specs/2026-10-27-aitmproxy-ui-scripting-highlight-l4-design.md`
(§1.1, §3.1), the plugin-system spec (Rhai catalog) and the PoC-language spec.

Check them with `node --test docs/design/languages/validate.test.mjs` (built-in
runner, no dependencies).

## Definition files

**`rhai.grammar.json`** is the Rhai token grammar: keywords, literals,
operators, punctuation, the lexical rules for comments, strings, numbers and
identifiers, and `map_token`, which sends each lexical class to a foundation
`syntax.*` token (plus the additive `comment`, `keyword` and `text`). It is
enough to colour, not to parse. It feeds the web `StreamLanguage` tokenizer
(`apps/web/scripts/gen-langs.mjs` → `Lang.rhai`), the TUI tokenizer
(`crates/aitm-tui/build.rs` → `src/syntax/`) and the macOS token set
(`tools/gen-langs.swift` → `Syntax.swift`).

**`rhai.api.json`** is the completion and hover catalog: the ten hooks (with a
top-level snippet each), the `flow` object members, the WebSocket `msg` members,
the host globals and the DSL helpers, every entry `{ name, kind, signature?,
description }` with fully qualified names (`flow.request.headers.get`). It
mirrors the plugin-system spec exactly so the drift guard
(`crates/aitm-plugin-rhai/tests/api_catalog.rs`, plan Task 12) can compare it with
the engine's registered functions. The same three generators consume it for
completion; the web `autocompletion` source, the TUI `src/ui/complete.rs` popup
and the macOS `NSTextView` completion provider all read it.

**`poc-yaml.schema.json`** is the PoC document as a key tree: each node has a
`type`, `description` and, where it exists, an `enum`; `keys` and `items` give the
nesting and `$ref` points into `$defs` for the shared matcher and extractor
shapes. It drives schema-aware YAML completion (keys at the right nesting,
enum values after a key) and the YAML highlighter's key set, through the same
three generation paths. If the builder's validation `poc-schema` ships, this
file should be generated from it.

**`filter.grammar.json`** is the one filter grammar: the `~`-atoms (with
argument kind), the combinators and precedence, the bare-word rule, the token
types and their `syntax.*` mapping, the error codes, and the stacked-filter
fields and operators with their documented bijection to the text form. Web
(`apps/web/src/flows/filter-grammar.ts`, generated), TUI (`src/filter.rs`,
checked against it by `build.rs`) and macOS (`FilterExpressionSyntax.swift` /
`Filter.swift`) all parse and highlight filters only from this file.

**`flow-kinds.json`** is the flow-kind model: one descriptor each for `http`,
`websocket` and `l4` (badge `{label, token}` — the L4 token is `l4`, slate/indigo —
list cells, inspector panes and viewers, `detail_cmd` and its gate, realtime
subscription, and a `status`). The flow list and inspector iterate it, so an
unknown kind renders a labelled placeholder rather than nothing. Web
(`flow-kinds.ts`), TUI (`flow_kinds.rs`) and macOS (`FlowKind.swift`) build their
per-kind renderers from it.

## Conformance fixtures

Each fixture proves the three surfaces stay identical; a surface test fails
when *its* implementation drifts. `validate.test.mjs` checks the fixtures
themselves (including a small reference filter parser) so they can be trusted.

**`filter.conformance.json`** — `[{ input, tokens, ast, canonical?, error?,
roundtrip_with? }]`. `tokens` are `{ type, text, start, end }` (half-open spans
into `input`, whitespace not emitted; types from `filter.grammar.json`
`token_types`). `ast` is `null` for an empty filter or an error, else
`{ op: "and"|"or", left, right }`, `{ op: "not", arg }` or `{ op: "atom", atom,
arg? }` with `arg = { kind: "wild"|"literal"|"regex", value }` (quotes and `/…/`
delimiters stripped, regex source kept verbatim; a bare word is `~u`; `~t` is
normalised to `~c`). `canonical` is the text a surface emits from the AST:
`~atom arg` terms joined by ` & ` / ` | `, `!` prefixed, parentheses only where
precedence needs them, an argument quoted only when it needs it.
`parse(canonical)` must give the same AST. `error` is a code from
`error_codes` and `tokens` are still the full token list. `roundtrip_with`
links the copy-between-surfaces pair (TUI-typed juxtaposition ↔ GUI advanced
view): different text, identical AST, one canonical form.

**`rhai.completion.conformance.json`** and **`poc.completion.conformance.json`**
— `[{ name, context, caret, kind, path, expected_candidates }]`. `caret` is a
0-based offset into `context`; the *prefix* is the identifier text immediately
left of it, and every candidate starts with it. Rhai: `kind` is `top-level`
(`path` is `""`; the candidates must be offered but a surface may offer more,
e.g. keywords and other catalogued names) or `member` (`path` is the receiver
chain, e.g. `flow.request`; the candidate set is **exactly** that receiver's
catalogued children, prefix-filtered). PoC YAML: `kind` is `key` (key position;
`path` is the enclosing mapping, e.g. `steps[].http`, exactly its `keys`) or
`enum` (after `key:`; `path` is the key itself, e.g. `info.severity`, exactly its
`enum`), where `[]` steps into a list's `items`.
