# dsl prelude helper namespace design

**Status:** Approved (orchestrator, on Matt's delegation, 2026-10-29)
**Research inputs:** `docs/superpowers/specs/2026-10-27-aitmproxy-plugin-system-design.md` (§"Tier 2 — Rhai scripting plugins", host-function catalogue lines 295-297), `docs/design/languages/rhai.api.json` (`dsl[]`, lines 136-147), `docs/design/languages/validate.test.mjs` (DSL golden lines 106-117, mirror assert 166-169)

## Intent

The Rhai host-function catalogue (`rhai.api.json`) lists ten `dsl` helper
functions — `b64_encode`, `b64_decode`, `url_encode`, `hex_encode`, `sha256`,
`md5`, `rand_text_alpha`, `rand_int`, `regex_match`, `regex_extract` — as part of
API 1. They are documented and golden-tested on the JSON side, but **not
registered in the hardened Rhai engine**: a script or PoC Rhai `script:` step
that calls `b64_encode("x")` today hits `ErrorFunctionNotFound`. This change
flips the `dsl` namespace from catalogued-only to built: it registers all ten as
flat global functions in the shared engine and adds a Rust drift guard that
proves the engine's registered `dsl` set equals the catalogue's. We want it now
because the catalogue advertises a contract the engine does not honour, and the
helpers are the everyday payload-shaping vocabulary (encode/hash/match/random)
that scripts and PoCs lean on.

## Goals

- All ten `dsl` helpers are callable, as flat unqualified functions
  (`b64_encode(s)`, not `dsl.b64_encode(s)`), from any Rhai script and from a
  PoC Rhai `script:` step, because they are registered on the one shared engine.
- A Rust test proves each of the ten runs and returns the specified value.
- The pre-existing Rust bijection guard
  (`tests/api_catalog.rs::catalog_matches_engine_host_surface`) proves the
  engine's registered `dsl` set equals the catalogue's — catalogue ≡ engine, in
  both directions. This guard already exists and already covers `dsl`; the only
  change it needs is that each helper's catalogue entry moves out of the
  `"status": "planned"` bucket as the helper lands (that is how the guard's own
  doc comment prescribes "planned → built").
- The existing node golden (`validate.test.mjs`) stays green; `rhai.api.json` is
  edited **only** to drop the `"status": "planned"` field from the ten `dsl`
  entries (names, signatures, order, and structure unchanged — the golden checks
  name + shape, not status).
- Behaviour matches the parallel `aitm-poc::dsl` implementations where one
  exists (`url_encode`, base64 alphabet, `rand_text_alpha` charset).

## Non-goals

- No change to the ten `dsl` **names or signatures** in the catalogue
  (`rhai.api.json`), and no change to the node golden. The ten names and
  signatures are fixed input; this change makes the engine match them. The one
  permitted catalogue edit is dropping `"status": "planned"` from each `dsl`
  entry as its helper lands (required by the pre-existing `api_catalog.rs`
  bijection guard — see Drift guard).
- No new helper, no renamed helper, no changed signature. The vocabulary is
  exactly the plugin-system spec's ten.
- **No change to the PoC `{{...}}` template / matcher DSL evaluator**
  (`aitm-poc::dsl::call`, `crates/aitm-poc/src/dsl.rs`). That is a separate
  surface with its own, partly different, function names (it exposes `base64`,
  not `b64_encode`, and has no `sha256`/`md5`/`regex_*`). Aligning the two
  vocabularies is out of scope and raised as an open question.
- No guard, scope check, rate limit, SSRF decision, or network/store/filesystem
  access for these helpers — they are pure (see Constraints).
- The full-catalogue drift guard comparing `globals`/`flow`/`msg` against the
  engine (the plugin-system plan's unbuilt "Task 12") stays out of scope; only
  the `dsl` slice of that guard is built here.

## Anti-goals

- Hand-rolling cryptographic or codec primitives (a bespoke MD5, SHA-256, or
  base64 decoder) when a vetted crate exists. Correctness of hashing/decoding
  must come from audited code, not new unreviewed byte-twiddling.
- A `dsl.` receiver object. The catalogue lists these unqualified and
  `validate.test.mjs` line 181 deliberately omits `dsl` from the injected
  namespace-object list; a dotted surface would break that golden and the
  "every dotted member's parent is catalogued" assertion.
- Silent wrong answers: a bad base64 input or an invalid regex must surface a
  catchable error, never a corrupted or empty string that hides the bug.
- Widening the sandbox. These helpers add no ambient authority.

## Constraints

- **Purity / security.** All ten are pure functions of their arguments (plus a
  process-lifetime RNG for `rand_*`). They touch no network, store, scope,
  browser, clock, or filesystem, and are therefore **not** routed through
  `ScopeRateGuard` or the SSRF check. This is a deliberate security property:
  deny-by-default is unaffected because nothing here reaches outside the engine.
- **Output is bounded** by the engine's existing operation/time budget: every
  helper's output is a bounded function of its input length (`rand_text_alpha(n)`
  by `n`), and a runaway script is already aborted by `max_operations` /
  `hook_timeout`. No new amplification path.
- **Determinism.** Every helper is deterministic except `rand_text_alpha` and
  `rand_int`, which draw from `aitm-poc::dsl`'s thread-local xorshift RNG seeded
  once from process start time. This is **not** cryptographically secure and is
  documented as such; it exists for unique markers, not secrets.
- **No circular dependency.** `aitm-plugin-rhai` already depends on `aitm-poc`
  (verified in `crates/aitm-plugin-rhai/Cargo.toml` line 14); `aitm-poc` does
  not depend on `aitm-plugin-rhai`. Reuse flows plugin-rhai → poc only.
- **Dependency hygiene.** `sha2`/`md-5` are RustCrypto, pure Rust, no heavy
  transitive weight. `regex = "1"` is already the version used in four crates;
  `base64 = "0.22"` is already in the workspace (`aitm-plugin-sessionio`).
- **Engine hardening unchanged.** Helpers register through the existing
  `ScriptCapability` seam; `rhai` stays on `features = ["sync"]`, never
  `unchecked`/`internals`. The bare-engine audit
  (`tests/engine.rs::allowed_global_functions_are_pinned`) builds `build_engine`
  *without* capabilities and is therefore unaffected.
- **Gate.** `cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
  cargo test`, plus `node --test docs/design/languages/`.

## Design

### Registration mechanism — a `DslCapability` through the existing seam

The ten helpers are registered as **flat global functions** through the M3
`ScriptCapability` seam (`crates/aitm-plugin-rhai/src/host_core.rs:151-160`),
not via a `dsl.` receiver and not via `prelude.rhai` (which is plain Rhai and
cannot reach base64/regex/hashing crates).

- New module `crates/aitm-plugin-rhai/src/dsl.rs` exposing:
  - `pub struct DslCapability;`
  - `impl ScriptCapability for DslCapability` with `namespace() -> "dsl"`,
    `min_api() -> "1"`, and `register(&self, engine, _services)` that delegates
    to `register_dsl(engine)` (it needs no services).
  - `pub fn register_dsl(engine: &mut Engine)` — registers all ten with
    `engine.register_fn(<bare name>, ..)` so each is an unqualified global.
  - `pub const DSL_FUNCTIONS: &[&str]` — the ten names, the single source the
    drift guard compares against the catalogue.
- `DslCapability` is added to `m3_capabilities()`
  (`crates/aitm-plugin-rhai/src/loader.rs:213-223`), growing the returned array
  from `[…; 7]` to `[…; 8]`. It is unconditional (like `LogCapability`): a pure
  helper set is always offered, deny-by-default does not apply.
- `mod dsl;` / `pub mod dsl;` added to the crate root.

**Why the seam and not `register_global_module`:** the seam is the project's one
way to add a namespace of verbs; routing `dsl` through it keeps every
first-party namespace discoverable in one list, gives it a `min_api`, and lets a
future protocol crate follow the same pattern. The functions are still flat
(registered by bare name), which is what the catalogue and golden require.
**(Architect's call.)**

**Why a free `register_dsl(engine)` as well:** `DslCapability` uses no
`ScriptServices`, so tests should not have to assemble a store/client/guard just
to exercise pure helpers. The free function lets the registration and drift-guard
tests register `dsl` onto a bare `build_engine` directly. **(Architect's call.)**

### Dependency ruling (resolved up front, Task 1)

| Helper(s) | Source | Why |
|---|---|---|
| `url_encode` | reuse `aitm_poc::dsl::url_encode` | already `pub`, RFC 3986, guarantees parity |
| `rand_text_alpha` | reuse `aitm_poc::dsl::rand_text_alpha` | already `pub`, shared charset + RNG |
| `rand_int` | **add** `pub fn rand_int(a, b)` to `aitm_poc::dsl`, reuse it | keeps one RNG / one determinism story; the existing xorshift is private, so expose a sibling helper rather than duplicate the RNG |
| `b64_encode`, `b64_decode` | **add** `base64 = "0.22"` (STANDARD engine) | the decode half must validate; hand-rolling a base64 decoder is an anti-goal. Using the crate for both keeps the encode/decode pair symmetric. STANDARD output is byte-identical to `aitm_poc::dsl::base64`, so parity holds |
| `sha256`, `md5` | **add** `sha2 = "0.10"` + `md-5 = "0.10"` (RustCrypto) | `ring` (the workspace's other hasher) has no MD5, so RustCrypto is required for `md5` regardless; taking `sha256` from the same ecosystem gives one `Digest` API and avoids mixing two hashing stacks in one crate |
| `hex_encode` (and the hex rendering of `sha256`/`md5`) | hand-roll a private `to_hex(&[u8]) -> String` | four lines, lowercase, no new crate; reused by the two hashers |
| `regex_match`, `regex_extract` | **add** `regex = "1"` | the version already used in `aitm-core`/`aitm-poc`/`aitm-tui`/`aitm-rules` |

Net new dependencies on `aitm-plugin-rhai`: `base64 = "0.22"`, `regex = "1"`,
`sha2 = "0.10"`, `md-5 = "0.10"`. Reuse strategy: **depend on `aitm-poc`**
(already a dependency) for the three helpers it has or can grow; do **not**
create a new shared crate — moving three functions out of `aitm-poc` into a new
crate and re-pointing `aitm-poc` at it is more churn than the reuse is worth.

Alternatives considered and rejected (recorded so they are not re-litigated):
*(A)* reuse `ring` for `sha256` + `md-5` for `md5` — mixes `ring` and RustCrypto
in one crate for no gain, since `md-5` is needed anyway; *(C)* hand-roll both
hashers — an anti-goal (unreviewed crypto-adjacent code). Both are reasonable but
the table above is the chosen default.

### Signatures registered

- `b64_encode(&str) -> String`
- `b64_decode(&str) -> Result<String, Box<EvalAltResult>>`
- `url_encode(&str) -> String`
- `hex_encode(&str) -> String`
- `sha256(&str) -> String`
- `md5(&str) -> String`
- `rand_text_alpha(i64) -> String`
- `rand_int(i64, i64) -> Result<i64, Box<EvalAltResult>>`
- `regex_match(&str pat, &str s) -> Result<bool, Box<EvalAltResult>>`
- `regex_extract(&str pat, &str s, i64 group) -> Result<String, Box<EvalAltResult>>`

(Rhai's integer type is `i64`.)

### Error and edge behaviour (decided; Architect's call where noted)

- **`b64_encode`** — STANDARD base64 (`A–Za–z0–9+/`, `=` padding). Total.
- **`b64_decode`** — STANDARD decode of `s`. On invalid base64, returns a
  **catchable** `EvalAltResult::ErrorRuntime`. On valid base64 whose bytes are
  not valid UTF-8, also a catchable error (never a lossy/corrupted string).
  Returns the decoded bytes as a `String`. *(Architect's call: a `Blob` return
  would be more faithful to binary payloads but less ergonomic for the
  string-in/string-out shape of the namespace; recorded as an open question.)*
- **`url_encode`** — percent-encodes everything outside the RFC 3986 unreserved
  set, uppercase hex digits, identical to `aitm_poc::dsl::url_encode`. Total.
- **`hex_encode`** — lowercase hex of the input's UTF-8 bytes. Total.
- **`sha256` / `md5`** — lowercase-hex digest of the input's UTF-8 bytes;
  fixed-length (64 / 32 chars). Total. `md5` is documented as a legacy,
  non-secure digest provided because target applications use it.
- **`rand_text_alpha(n)`** — `n` letters from `[A–Za–z]`; `n <= 0` yields `""`
  (matches `aitm_poc::dsl`). RNG is the shared thread-local xorshift,
  non-cryptographic.
- **`rand_int(a, b)`** — a random integer in the **inclusive** range `[a, b]`;
  `rand_int(5, 5) == 5`. If `a > b`, a catchable `ErrorRuntime`. *(Architect's
  call: inclusive range and error-on-reversed, over clamping/swapping.)*
- **`regex_match(pat, s)`** — `true` iff `pat` matches anywhere in `s`. Invalid
  `pat` → catchable `ErrorRuntime` (a script bug, surfaced not swallowed).
- **`regex_extract(pat, s, group)`** — the text of capture `group` of the first
  match. No match, or a group that did not participate, or a group index out of
  range → `""` (empty). Invalid `pat` → catchable `ErrorRuntime`. *(Architect's
  call: empty-on-no-match is the ergonomic nuclei-style behaviour; a bad pattern
  is still an error because it is a script defect.)*

### Drift guard — reuse the pre-existing `api_catalog.rs` bijection

The project already has the canonical catalogue ≡ engine guard:
`crates/aitm-plugin-rhai/tests/api_catalog.rs::catalog_matches_engine_host_surface`.
It enumerates every registered host token and fails on a catalogue entry the
engine does not register OR a registered token missing from the catalogue —
**excluding** entries marked `"status": "planned"` (its doc comment names the
`dsl` crypto/encoding helpers as exactly that bucket, and says "when they land
they move out of `planned`"). So once `DslCapability` is wired into
`m3_capabilities()` and each helper's `"status": "planned"` is dropped, this
existing guard proves the `dsl` bijection with no new drift test needed.

A **bespoke** `dsl`-slice drift test is therefore NOT built — it would duplicate
`api_catalog.rs` for one invariant. What `tests/dsl.rs` adds instead is the
behaviour proof: it registers `register_dsl` on a bare `build_engine` and runs a
Rhai snippet calling each of the ten, asserting the literal results below (the
callable sweep). The full-catalogue `globals`/`flow`/`msg` reconciliation (the
plugin-system plan's unbuilt "Task 12") remains out of scope and is unaffected.

## Acceptance criteria

1. **AC1** — `register_dsl` registers exactly the ten `DSL_FUNCTIONS` as flat
   global functions; `DslCapability.namespace() == "dsl"` and `min_api() == "1"`.
2. **AC2** — With `register_dsl` applied to a hardened engine, each helper runs
   and returns:
   - `b64_encode("foobar") == "Zm9vYmFy"`
   - `b64_decode("Zm9vYmFy") == "foobar"`
   - `url_encode("a b/c") == "a%20b%2Fc"`
   - `hex_encode("AB") == "4142"`
   - `sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"`
   - `md5("abc") == "900150983cd24fb0d6963f7d28e17f72"`
   - `rand_text_alpha(8)` has length 8 and is all ASCII letters
   - `rand_int(5, 5) == 5`
   - `regex_match("^a.c$", "abc") == true`
   - `regex_extract("(\\d+)", "abc123", 1) == "123"`
3. **AC3** — `DslCapability` is in `m3_capabilities()`; a script loaded through
   `RhaiLoader` and a PoC Rhai `script:` step can both call the helpers
   (same shared engine).
4. **AC4** — Error behaviour: `b64_decode("!!!")` and `regex_match("(", "x")`
   and `rand_int(5, 1)` each raise a **catchable** `EvalAltResult::ErrorRuntime`;
   `regex_extract("z+", "abc", 0) == ""`.
5. **AC5** — Bijection: with `DslCapability` wired into `m3_capabilities()` and
   the ten `dsl` entries un-planned, the pre-existing
   `tests/api_catalog.rs::catalog_matches_engine_host_surface` passes (engine ≡
   catalogue, both directions). No bespoke `dsl` drift test is added.
6. **AC6** — The node golden `docs/design/languages/validate.test.mjs` passes
   unchanged; `rhai.api.json` is edited **only** to remove `"status": "planned"`
   from the ten `dsl` entries (names, signatures, order, and structure
   unchanged).
7. **AC7** — `aitm_poc::dsl::rand_int(a, b)` exists, is `pub`, returns a value in
   `[a, b]`, uses the module's existing thread-local RNG, and `rand_int(7, 7) == 7`.
8. **AC8** — Parity: `url_encode`, the base64 alphabet, and the
   `rand_text_alpha` charset match `aitm_poc::dsl`.
9. **AC9** — Full gate passes: `cargo fmt --check`, `cargo clippy --all-targets
   -- -D warnings`, `cargo test`, and `node --test docs/design/languages/`.

## Left to the builder

- Exact phrasing of error messages (must contain enough to diagnose, e.g. the
  word `base64` / `regex`).
- Whether `to_hex` is a module-private free function or an inline closure.
- Ordering of `register_fn` calls and internal grouping within `register_dsl`.
- The exact Rhai snippet(s) the registration test uses, as long as every helper
  is exercised with the AC2 literals.
- Human-readable doc comments on each helper (the spec requires they read
  clearly; wording is the builder's).

## Open questions — RESOLVED

1. **PoC `{{...}}` template vocabulary — DECIDED: out of scope for this build.**
   The PoC template / matcher evaluator (`aitm-poc::dsl::call`) is a *different*
   surface that today exposes `base64` (not `b64_encode`) and lacks
   `sha256`/`md5`/`hex_encode`/`regex_*`/`rand_int`. Aligning it to the ten names
   would rename `base64` → `b64_encode` and could break existing PoC YAML and
   matchers. This build does NOT touch it. Unifying the two DSLs is offered to
   Matt as a *separate* follow-up (its own spec, since it is a breaking change to
   the PoC-language surface), not folded in here.
2. **`b64_decode` return type — DECIDED: `String` with a catchable error on
   invalid base64 or non-UTF-8 bytes.** Matches the string-in/string-out shape of
   the namespace and reads clearly. If decoding arbitrary binary payloads turns
   out to matter, a `Blob`-returning sibling is an additive follow-up, not a
   change to this signature.

---

## Summary

This spec builds the `dsl` namespace the Rhai catalogue already advertises:
ten flat, pure helper functions registered through the existing
`ScriptCapability` seam as a new `DslCapability`, reusing `aitm-poc` for
`url_encode`/`rand_text_alpha`/a new `rand_int` and adding `base64`, `regex`,
`sha2`, and `md-5` for the rest. A Rust drift guard asserts the engine's `dsl`
set equals the catalogue's and that each helper runs; the node golden and the
catalogue are untouched. The helpers add no ambient authority and bypass the
guard precisely because they are pure.

## Architect's calls

- Register via a `DslCapability` through the `ScriptCapability` seam (not
  `prelude.rhai`, not `register_global_module`), with a free `register_dsl` for
  service-free tests.
- Dependency ruling: reuse `aitm-poc` (no new shared crate) for `url_encode`,
  `rand_text_alpha`, and a new `pub rand_int`; add `base64 0.22`, `regex 1`,
  `sha2 0.10`, `md-5 0.10`; hand-roll only `hex_encode`.
- `b64_decode` returns `String` and errors on invalid/base64-non-UTF-8 input.
- `rand_int` is inclusive `[a, b]` and errors when `a > b`.
- `regex_extract` returns `""` on no-match / out-of-range group but errors on an
  invalid pattern; `regex_match` errors on an invalid pattern.
- Reuse the pre-existing `api_catalog.rs` bijection as the catalogue ≡ engine
  guard (un-plan the `dsl` entries as helpers land); do NOT add a bespoke `dsl`
  drift test — `tests/dsl.rs` adds only the callable sweep. Leave the
  `globals/flow/msg` full-catalogue reconciliation (plugin-system "Task 12") out
  of scope. *(Amends the original "build the `dsl` slice" call after the
  `api_catalog.rs` mechanism, which the draft missed, was found.)*
- PoC `{{...}}` template DSL alignment is out of scope (open question 1).
