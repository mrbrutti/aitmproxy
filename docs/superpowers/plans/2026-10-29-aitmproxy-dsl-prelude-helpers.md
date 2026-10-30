# dsl prelude helper namespace implementation plan

**Status:** Approved (orchestrator, on Matt's delegation, 2026-10-29) — live for Stage 4
**Spec:** `docs/superpowers/specs/2026-10-29-aitmproxy-dsl-prelude-helpers-design.md`
**Branch / worktree:** `feat/dsl-prelude-helpers` (off current `main`)

## Overview

Six tasks. Task 1 resolves every dependency choice up front: it adds the four
new crate dependencies to `aitm-plugin-rhai` and grows `aitm-poc::dsl` with a
`pub rand_int` reusing the existing RNG. Tasks 2–5 build the `dsl` namespace one
family at a time, all editing the single new file
`crates/aitm-plugin-rhai/src/dsl.rs`, so they are **sequential** (shared file),
not parallel. Each of Tasks 2–5 also drops `"status": "planned"` from exactly the
`dsl` catalogue entries it registers, so the pre-existing
`tests/api_catalog.rs::catalog_matches_engine_host_surface` bijection stays green
at every task boundary (that guard, not a bespoke test, is the catalogue ≡ engine
check — amended in after the draft, which had specced a redundant `dsl` drift
guard, missed it). Task 6 adds the callable sweep and confirms the bijection.
Order: 1 → 2 → 3 → 4 → 5 → 6. Task 1 and Task 2 could in principle start in parallel
(disjoint files) but Task 2 compiles against Task 1's deps, so run 1 first.
All tests are written before the code they prove (TDD).

Literal digests used below are the published test vectors:
`sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`,
`md5("abc") = 900150983cd24fb0d6963f7d28e17f72`,
`base64("foobar") = Zm9vYmFy`.

## Tasks

### Task 1: Dependencies and the shared `rand_int`

- **Satisfies:** AC7 (and unblocks AC1–AC5)
- **Depends on:** none
- **Files:**
  - `crates/aitm-plugin-rhai/Cargo.toml` (modify — add deps)
  - `crates/aitm-poc/src/dsl.rs` (modify — add `rand_int`)
  - `crates/aitm-poc/tests/` — add a test module or extend an existing dsl test
    (create `crates/aitm-poc/tests/dsl_rand_int.rs` if no unit test home exists)
- **Change:**
  - In `crates/aitm-plugin-rhai/Cargo.toml` `[dependencies]` add:
    `base64 = "0.22"`, `regex = "1"`, `sha2 = "0.10"`, `md-5 = "0.10"`.
  - In `crates/aitm-poc/src/dsl.rs` add `pub fn rand_int(a: i64, b: i64) -> i64`
    that draws from the module's existing thread-local xorshift (`next_u64`) and
    returns a value in the inclusive range `[a.min(b), a.max(b)]`. (The Rhai
    layer, Task 4, enforces the `a > b` error; `aitm-poc`'s own helper is
    total.) Reuse `next_u64`; do not add a second RNG.
- **Test:** `rand_int_is_within_inclusive_bounds` in the chosen test home:
  - `aitm_poc::dsl::rand_int(7, 7)` equals `7`.
  - 1000 draws of `aitm_poc::dsl::rand_int(3, 9)` are each `>= 3 && <= 9`.
  - `aitm_poc::dsl::rand_int(9, 3)` is `>= 3 && <= 9` (order-insensitive).
- **Done when:** the test passes and `cargo build -p aitm-plugin-rhai` resolves
  the four new deps (full gate at Task 6).

### Task 2: `DslCapability` scaffold + encoding family

- **Satisfies:** AC1, AC2 (encoding rows), AC3, AC8 (url_encode)
- **Depends on:** Task 1
- **Files:**
  - `crates/aitm-plugin-rhai/src/dsl.rs` (create)
  - `crates/aitm-plugin-rhai/src/lib.rs` (modify — add `pub mod dsl;`)
  - `crates/aitm-plugin-rhai/src/loader.rs` (modify — add `DslCapability` to
    `m3_capabilities`, array `[…; 7]` → `[…; 8]`)
  - `crates/aitm-plugin-rhai/tests/dsl.rs` (create — encoding cases now; later
    tasks extend the same file)
  - `docs/design/languages/rhai.api.json` (modify — drop `"status": "planned"`
    from the four encoding entries: `b64_encode`, `b64_decode`, `url_encode`,
    `hex_encode`; names/signatures/order unchanged)
- **Change:**
  - New module with `pub struct DslCapability;`, `impl ScriptCapability`
    (`namespace() -> "dsl"`, `min_api() -> "1"`, `register` delegating to
    `register_dsl`), `pub fn register_dsl(engine: &mut rhai::Engine)`, and
    `pub const DSL_FUNCTIONS: &[&str]` holding all ten names (used in full now so
    AC5 can land at Task 6; the functions themselves fill in across 2–5).
  - Register the encoding family in `register_dsl`:
    - `b64_encode(&str) -> String` via `base64::engine::general_purpose::STANDARD`.
    - `b64_decode(&str) -> Result<String, Box<EvalAltResult>>` — STANDARD decode;
      invalid base64 or non-UTF-8 bytes → catchable `ErrorRuntime`.
    - `url_encode(&str) -> String` delegating to `aitm_poc::dsl::url_encode`.
    - `hex_encode(&str) -> String` via a private `to_hex(&[u8]) -> String`
      (lowercase).
  - Add `DslCapability` to the `m3_capabilities` array.
- **Test:** in `tests/dsl.rs`, `encoding_helpers_run` builds `build_engine(&RhaiLimits::default(), Duration::from_secs(2))`, calls `register_dsl(&mut engine)`, and `engine.eval::<T>` each:
  - `b64_encode("foobar")` == `"Zm9vYmFy"`
  - `b64_decode("Zm9vYmFy")` == `"foobar"`
  - `url_encode("a b/c")` == `"a%20b%2Fc"`
  - `hex_encode("AB")` == `"4142"`
  - `b64_decode("!!!")` returns `Err`, and a `try { b64_decode("!!!") } catch(e) { "caught" }` script yields `"caught"` (catchable).
- **Done when:** the test passes, the crate compiles with the new capability
  wired in, and — with the four encoding entries un-planned — `cargo test -p
  aitm-plugin-rhai --test api_catalog` and `node --test docs/design/languages/`
  are both green. (Every later task keeps both green by un-planning exactly the
  entries it registers.)

### Task 3: Hashing family (`sha256`, `md5`)

- **Satisfies:** AC2 (hashing rows)
- **Depends on:** Task 2 (same `register_dsl`, same `to_hex`)
- **Files:**
  - `crates/aitm-plugin-rhai/src/dsl.rs` (modify)
  - `crates/aitm-plugin-rhai/tests/dsl.rs` (modify — add hashing cases)
  - `docs/design/languages/rhai.api.json` (modify — un-plan `sha256`, `md5`)
- **Change:** register in `register_dsl`:
  - `sha256(&str) -> String` via `sha2::Sha256`, rendered with `to_hex`
    (lowercase, 64 chars).
  - `md5(&str) -> String` via `md5::Md5` (crate `md-5`), rendered with `to_hex`
    (lowercase, 32 chars). Doc comment notes MD5 is legacy / non-secure.
- **Test:** `hashing_helpers_run` (same engine harness):
  - `sha256("abc")` == `"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"`
  - `md5("abc")` == `"900150983cd24fb0d6963f7d28e17f72"`
  - both results are length 64 / 32 and lowercase.
- **Done when:** the test passes.

### Task 4: Random family (`rand_text_alpha`, `rand_int`)

- **Satisfies:** AC2 (random rows), AC4 (`rand_int` reversed), AC8 (charset)
- **Depends on:** Task 1 (`aitm_poc::dsl::rand_int`), Task 2 (scaffold)
- **Files:**
  - `crates/aitm-plugin-rhai/src/dsl.rs` (modify)
  - `crates/aitm-plugin-rhai/tests/dsl.rs` (modify — add random cases)
  - `docs/design/languages/rhai.api.json` (modify — un-plan `rand_text_alpha`,
    `rand_int`)
- **Change:** register in `register_dsl`:
  - `rand_text_alpha(i64) -> String` delegating to
    `aitm_poc::dsl::rand_text_alpha(n.max(0) as usize)`.
  - `rand_int(i64, i64) -> Result<i64, Box<EvalAltResult>>` — `a > b` →
    catchable `ErrorRuntime`; otherwise `aitm_poc::dsl::rand_int(a, b)`
    (inclusive).
- **Test:** `random_helpers_run`:
  - `rand_text_alpha(8)` yields a string of length `8`, every char
    `is_ascii_alphabetic()`.
  - `rand_int(5, 5)` == `5`.
  - a `try { rand_int(5, 1) } catch(e) { "caught" }` script yields `"caught"`.
- **Done when:** the test passes.

### Task 5: Regex family (`regex_match`, `regex_extract`)

- **Satisfies:** AC2 (regex rows), AC4 (regex errors / empty group)
- **Depends on:** Task 2 (scaffold)
- **Files:**
  - `crates/aitm-plugin-rhai/src/dsl.rs` (modify)
  - `crates/aitm-plugin-rhai/tests/dsl.rs` (modify — add regex cases)
  - `docs/design/languages/rhai.api.json` (modify — un-plan `regex_match`,
    `regex_extract`)
- **Change:** register in `register_dsl`:
  - `regex_match(&str, &str) -> Result<bool, Box<EvalAltResult>>` — compile
    `pat` (invalid → catchable `ErrorRuntime`), return `re.is_match(s)`.
  - `regex_extract(&str, &str, i64) -> Result<String, Box<EvalAltResult>>` —
    compile `pat` (invalid → error); first match's capture `group` as text; no
    match / absent / out-of-range group → `""`.
- **Test:** `regex_helpers_run`:
  - `regex_match("^a.c$", "abc")` == `true`
  - `regex_match("^a.c$", "xyz")` == `false`
  - `regex_extract("(\\d+)", "abc123", 1)` == `"123"`
  - `regex_extract("z+", "abc", 0)` == `""`
  - a `try { regex_match("(", "x") } catch(e) { "caught" }` script yields
    `"caught"`.
- **Done when:** the test passes.

### Task 6: Callable sweep + confirm the `api_catalog.rs` bijection

- **Satisfies:** AC1 (full set), AC3, AC5, AC6
- **Depends on:** Tasks 2–5 (all ten registered and un-planned)
- **Files:**
  - `crates/aitm-plugin-rhai/tests/dsl.rs` (modify — add the full callable sweep)
- **Change:**
  - `all_ten_dsl_helpers_are_callable` — register `register_dsl`, run one Rhai
    script that calls all ten helpers and returns a success sentinel; assert it
    evaluates without `ErrorFunctionNotFound`.
  - Do NOT add a bespoke `dsl` drift guard: the pre-existing
    `tests/api_catalog.rs::catalog_matches_engine_host_surface` already proves
    engine ≡ catalogue for `dsl` once the entries are un-planned (Tasks 2–5). If
    `DSL_FUNCTIONS` is left unused after this, remove it (clippy `-D warnings`).
- **Test:** the callable sweep passes; `cargo test -p aitm-plugin-rhai --test
  api_catalog` is green (bijection holds with all ten `dsl` helpers registered
  and un-planned).
- **Done when:** the callable sweep + `api_catalog` guard pass, `node --test
  docs/design/languages/` is green (only `"status": "planned"` removed from the
  ten `dsl` entries), and the full gate (`cargo fmt --check && cargo clippy
  --all-targets -- -D warnings && cargo test`) passes.

## Independence

- Tasks 2, 3, 4, 5, 6 all edit `crates/aitm-plugin-rhai/src/dsl.rs` and/or
  `crates/aitm-plugin-rhai/tests/dsl.rs` — **sequential, no fan-out**.
- Task 1 edits different files (`Cargo.toml`, `aitm-poc`) and is the only one
  that could run alongside Task 2's scaffold, but Task 2 needs Task 1's deps, so
  run Task 1 first.

## Review log

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|

## Shipped

_Filled at stage 7._
