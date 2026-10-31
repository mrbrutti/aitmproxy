# Rhai `on_response` mutation contract design

**Status:** approved (2026-10-30 by Matt — self-approved under the autonomous-operate mandate; a real-traffic e2e footgun, fix determined by the streaming architecture)
**Research inputs:** core-features-e2e REAL e2e report (finding 5), `crates/aitm-proto-http/src/module.rs` + `src/h2.rs` (response forwarding timing), `crates/aitm-plugin-rhai/src/{plugin,flow_api,flow_state}.rs`

## Intent

A real-traffic e2e campaign found that a Rhai script's `on_response` hook cannot
mutate the client-bound response, and does so **silently**: a script that edits
`flow.response` (status / headers / body) or calls `flow.set_response(...)`
inside `on_response` compiles and runs with no error, the edit lands in the
stored flow, but the client already received the original bytes. `on_response`
fires on the `Response` event, which the HTTP modules emit **after** the full
response has been streamed to the client (`module.rs` h1 `ResponseComplete` →
`emit(Event::Response)`; `h2.rs` `finish_response` → `emit(Event::Response)`).
The response's mutation point is `on_response_headers`, which fires at the
response breakpoint before any byte reaches the client. Today nothing tells the
author this, so `on_response` response edits are a silent footgun.

## Goals

- A response mutation attempted inside `on_response` is **refused loudly**: a
  catchable Rhai runtime error that names `on_response_headers` as the response
  mutation hook, surfaced on the bus as `Event::Error` and in
  `script.list`'s `last_error` — never a silent no-op.
- `on_response_headers` remains the hook that mutates the client-bound response
  (status, headers, and body replacement), proven to reach the client on the
  wire.
- `on_response` stays fully usable as an **observe-only** hook: reading the
  complete response (status, headers, full captured body), marking, commenting,
  recording findings, and `halt()` all keep working.
- The API catalog (`rhai.api.json`) documents the contract.

## Non-goals

- Making `on_response` able to mutate the client-bound response by buffering the
  whole response before forwarding. That would defeat the streaming design the
  proxy depends on (response bodies stream chunk-by-chunk while a bounded copy is
  captured), and `on_response_headers` already covers pre-forward mutation
  including whole-body replacement. See Design / alternatives.
- Gating **request** mutations in `on_response` / `on_response_headers` (the
  request is likewise already forwarded by then, a separate and lower-severity
  footgun). Tracked as a follow-up; out of scope here to keep the change
  surgical.
- A new "buffer this response and call me back" opt-in hook. Possible future
  feature; not this fix.

## Anti-goals

- Breaking any existing observe-only `on_response` use (e.g. the `tagger` example
  that marks 5xx and logs). A regression there means the fix is too broad.
- A contract that only warns in logs but still silently drops the edit with no
  bus/`script.list` signal — the author must be able to see it from the control
  surface, not only in server logs.

## Constraints

- The enforcement runs on the hot dispatch path (every response), so it must be
  O(1) and allocation-free in the common (no-write) case.
- Hooks run under `block_in_place` on the dispatching worker thread; any phase
  marker must be set on that same thread for the duration of the hook call
  (alongside the existing `ActiveFlow` / `seed_call_context` guards in
  `LoadedScript::call_hook`).
- The refusal must reuse the existing hook-error machinery (throw → snapshot
  dropped unapplied → `Event::Error` on the bus → `last_error` recorded), so the
  flow stays byte-for-byte unchanged and behaviour matches the established
  `NO_RESPONSE` (response-write-in-request-phase) contract.
- Must hold for both HTTP/1 and HTTP/2 (both emit `Event::Response` post-forward).

## Design

**Decision: a loud, catchable contract, enforced at the response setters.**

A new thread-local phase marker records, for the hook currently running, whether
the response has already been forwarded to the client. Only the `on_response`
hook (the `Response` event) enters that phase; every other hook leaves it unset.
The Rhai response-mutation surface checks the marker and, when the response is
already forwarded, returns a catchable runtime error instead of recording the
edit.

- `crates/aitm-plugin-rhai/src/flow_api.rs`
  - Add a thread-local `RESPONSE_FORWARDED: Cell<bool>` and a guard
    `ResponsePhase` (save/restore-on-drop, exactly like `ActiveFlow`), plus a
    `response_forwarded()` reader.
  - A shared `RESPONSE_FORWARDED_ERR` message and a `check_response_mutable()`
    helper returning `ScriptResult`.
  - Gate the three response-write paths with `check_response_mutable()?`:
    1. `ScriptResponse::edit` (covers `response.status`, `response.body`,
       `response.bytes`);
    2. `ScriptHeaders::edit` **only** when the side is
       `HeaderSide::ResponseHeaders` (covers `response.headers.set/remove` and
       the indexer);
    3. the `set_response` registered fn — change its closure to return
       `ScriptResult` and check first.
  - Reads (`ScriptResponse::read`, `ScriptHeaders::read`) are untouched: observe
    still works.
- `crates/aitm-plugin-rhai/src/plugin.rs`
  - `LoadedScript::dispatch` computes `response_forwarded = matches!(ev,
    Event::Response(_))` and passes it to `call_hook`, which enters
    `ResponsePhase` inside the `blocking(...)` closure (same thread as the eval)
    for the duration of the hook.
- `docs/design/languages/rhai.api.json`
  - `on_response_headers`: note it is where you mutate the response (status,
    headers, or replace the body) before it streams to the client.
  - `on_response`: note the response has already been forwarded, so it is
    observe-only; editing the response here is refused — mutate in
    `on_response_headers`.

**One nuance (uniform by design):** on the normal streamed path `Event::Response`
is strictly post-forward. On the HTTP/1 plugin-answered *short-circuit* path
(`module.rs` ~579-588, a request answered by `set_response` in a request-phase
hook) `Event::Response` is emitted just *before* the committed response is
flushed, so a response edit in `on_response` there could technically still be
read back. The contract refuses it there too, on purpose: one rule the author can
rely on ("mutate in `on_response_headers`, observe in `on_response`") is better
than a path-dependent one that works only after a short-circuit. The refusal is
fail-closed and `on_response_headers` fires on that path as well, so nothing is
lost. The error wording says "committed to the client" rather than "forwarded" to
stay accurate for both paths.

**Why the setter, not the apply step:** throwing at the setter points the error
at the exact offending line, fires immediately, and flows through the existing
hook-error path with zero new control flow. It is the same shape as the existing
`NO_RESPONSE` error for a response write in the request phase (flow_api.rs module
docs), so the tier gains no new error model — one more phase in the same one.

**Alternatives considered (rejected):**

- *Make `on_response` mutate the client-bound response* by buffering the entire
  response before forwarding. Rejected: it removes streaming (unbounded buffering
  / latency for large responses, against the throughput design), and
  `on_response_headers` already replaces status/headers/body pre-forward
  (`forward_chunks=false` path in both modules), so there is no mutation
  `on_response_headers` cannot already do. `on_response`'s unique value is the
  complete captured body for observation, which it keeps.
- *Detect the mutation at `apply_to` and drop it with a warning.* Rejected: the
  error would not point at the offending line, and silent-drop-plus-log is weaker
  than a catchable throw the author sees on the bus and in `script.list`.

## Acceptance criteria

1. **AC1** — A `flow.response.body` / `.status` / `.bytes` write inside
   `on_response` is refused: the hook errors (chain still `Continue`), the stored
   response is unchanged, and the bus `Event::Error` / `script.list.last_error`
   message names `on_response_headers`.
2. **AC2** — A `flow.response.headers.set(...)` (and indexer / `remove`) inside
   `on_response` is refused the same way.
3. **AC3** — A `flow.set_response(...)` call inside `on_response` is refused the
   same way; the stored response is unchanged.
4. **AC4** — The same mutations inside `on_response_headers` still apply: a
   status / header / body edit there is written to the flow (phase-scoped, not a
   global ban), and `set_response` in the request phase is unaffected.
5. **AC5** — `on_response` observe-only use still works: reading
   `flow.response.status` / `.body` / headers, `flow.mark`, `flow.comment`, and
   `halt()` run without error.
6. **AC6** — On the wire (real e2e): a body rewrite in `on_response_headers`
   reaches the client (curl sees the rewritten body), and a body/`set_response`
   attempt in `on_response` does **not** reach the client **and** is reported
   loudly (`script.list.last_error` names `on_response_headers`), proving it is a
   refusal, not a silent no-op.
7. **AC7** — `rhai.api.json` documents `on_response_headers` as the response
   mutation hook and `on_response` as observe-only.

## Left to the builder

- Exact wording of the error and catalog descriptions (must name
  `on_response_headers` and convey "already forwarded / observe-only").
- Whether `ResponsePhase` is entered unconditionally with a bool or only for the
  response event, as long as non-`on_response` hooks are unaffected.
- Test file layout within the cited crates and `tests/e2e/scripting/`.

## Open questions

None.
