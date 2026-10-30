# Rhai `on_response` mutation contract implementation plan

**Status:** approved (2026-10-30 by Matt — self-approved under the autonomous-operate mandate) | shipped (pending)
**Spec:** `docs/superpowers/specs/2026-10-30-rhai-on-response-contract-design.md`
**Branch / worktree:** `claude/rhai-onresponse-fix-fb8217`

## Overview

One small, cohesive change in `crates/aitm-plugin-rhai`: a thread-local
"response already forwarded" phase marker set only for the `on_response` hook,
checked by the three response-write paths so a response mutation in `on_response`
throws a catchable error instead of silently applying. Plus the catalog doc and a
real-traffic e2e proof. Tasks 1 and 2 are the one code change (setters + the
dispatcher that sets the phase) and are done together, test-first. Task 3 is the
e2e suite. Task 4 is the catalog doc. The order is Task 1/2 → Task 3 → Task 4;
the unit tests in Task 1/2 and the e2e in Task 3 are the evidence.

## Tasks

### Task 1: refuse response mutation in `on_response` (setters + phase marker)

- **Satisfies:** AC1, AC2, AC3, AC4, AC5
- **Depends on:** none
- **Files:** `crates/aitm-plugin-rhai/src/flow_api.rs` (modify),
  `crates/aitm-plugin-rhai/src/plugin.rs` (modify),
  `crates/aitm-plugin-rhai/tests/plugin.rs` (modify — add tests)
- **Change:**
  - `flow_api.rs`: add `thread_local! { static RESPONSE_FORWARDED: Cell<bool> }`;
    a `pub struct ResponsePhase { previous: bool }` with
    `ResponsePhase::forwarded()` (replace-and-store true) and a `Drop` that
    restores; a `fn response_forwarded() -> bool`; a `const RESPONSE_FORWARDED_ERR`
    and `fn check_response_mutable() -> ScriptResult`. Call
    `check_response_mutable()?` at the top of `ScriptResponse::edit`; at the top of
    `ScriptHeaders::edit` guarded by `matches!(self.1,
    HeaderSide::ResponseHeaders)`; and in the `set_response` registered closure
    (changed to return `ScriptResult`, `Ok(())` on success).
  - `plugin.rs`: `call_hook` takes a `response_forwarded: bool`; inside the
    `blocking(...)` closure add `let _phase = response_forwarded.then(ResponsePhase::forwarded);`
    next to `_active` / `_seed`. `dispatch` passes
    `matches!(ev, Event::Response(_))`.
- **Test (`tests/plugin.rs`, driving the real chain via `Harness`):**
  - add `http_flow_with_response()` (a 200 flow whose response body is
    `b"upstream-body"`).
  - `on_response_body_write_is_refused`: `fn on_response(flow){ flow.response.body
    = "tampered"; }` over `Event::Response` → `Verdict::Continue`, stored response
    body still `upstream-body`, one `Event::Error` whose message contains
    `on_response_headers`.
  - `on_response_set_response_is_refused`: `fn on_response(flow){
    flow.set_response(503, #{}, "late"); }` → stored response still 200 /
    `upstream-body`, error names `on_response_headers`.
  - `on_response_header_write_is_refused`: `fn on_response(flow){
    flow.response.headers.set("X-Late","1"); }` → header absent, error names
    `on_response_headers`.
  - `on_response_headers_mutation_applies`: `fn on_response_headers(flow){
    flow.response.status = 201; flow.response.headers.set("X-H","1");
    flow.response.body = "rewritten"; }` over `Event::ResponseHeaders` → stored
    response is 201 / `X-H:1` / body `rewritten`, no error (phase-scoped).
  - `on_response_observe_only_is_allowed`: `fn on_response(flow){ if
    flow.response.status == 200 { flow.mark("ok"); flow.comment =
    flow.response.body; } }` → marks `["ok"]`, comment `upstream-body`, no error.
- **Done when:** the new tests fail before the `flow_api`/`plugin` change and pass
  after, and the full gate passes.

### Task 2: (folded into Task 1 — the dispatcher phase wiring)

The `plugin.rs` `call_hook`/`dispatch` change is listed under Task 1 because the
setters cannot be tested without it; implemented and committed together.

### Task 3: real-traffic e2e proof

- **Satisfies:** AC6
- **Depends on:** Task 1
- **Files:** `tests/e2e/scripting/test_on_response_contract.py` (create)
- **Change:** a suite using `lib/harness.py` that boots a real `aitm` with two
  boot-loaded scripts against a real testtarget:
  - `rewrite.rhai` with `on_response_headers` that replaces the body with a known
    marker; curl the target through the proxy and assert the body received equals
    the marker (correct hook reaches the client on the wire).
  - `late.rhai` with `on_response` that attempts `flow.response.body = ...` and
    `flow.set_response(...)`; assert (a) the client body is the original (not the
    attempted value) and (b), polling `script.list` (operator) with a bounded
    timeout, `late`'s `last_error` is non-null and names `on_response_headers` —
    proving a loud refusal, not a silent no-op.
- **Test:** the suite is the test; `python3 tests/e2e/run.py scripting` reports
  PASS. (Port-binding → Terminal panel.)
- **Done when:** the scripting e2e suite passes.

### Task 4: document the contract in the API catalog

- **Satisfies:** AC7
- **Depends on:** none
- **Files:** `docs/design/languages/rhai.api.json` (modify)
- **Change:** update the `on_response_headers` and `on_response` descriptions per
  the spec.
- **Test:** `cargo test` (the catalog has a conformance/shape test) stays green;
  the two descriptions read as specified.
- **Done when:** the gate passes and the descriptions are updated.

## Review log

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|

## Shipped

Pending.
