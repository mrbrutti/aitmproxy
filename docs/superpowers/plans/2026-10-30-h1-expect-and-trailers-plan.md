# HTTP/1 `Expect: 100-continue` and chunked-trailer conformance implementation plan

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's standing autonomous-mode instruction). Amended 2026-10-30 after the Stage 6 panel: Task 9 is "run the two e2e scripts for real, do not land them" (their owner session lands them test-only after the merge) and Task 11 is the panel fix task; see the Review log. Base note: PR 129 was merged into PR 108's already-squash-merged branch, so its hardening was re-landed on `main` as PR 133; this branch is rebased onto that work and its PR has base `main` (the Branch/worktree paragraph below predates this; the 40-literal sweep in Task 3 must be done against the rebased tree, since `main` has literals the older base lacks).
**Spec:** `docs/superpowers/specs/2026-10-30-h1-expect-and-trailers-design.md`
**Branch / worktree:** `fix/http1-conformance` in
`/Users/matt/Security/aitmproxy/.claude/worktrees/pbb-sec-review-1c8088`, cut from
`fix/http1-path-hardening` (PR #129, itself stacked on PR #108). Open the PR with base
`fix/http1-path-hardening`; retarget as each parent merges.

## Overview

Two HTTP/1 conformance bugs, each fixed test-first. Bug 1 (Tasks 1 and 2): the machine
tracks an unanswered `100-continue` expectation and `serve` answers it at head time, before
the body is read and before any plugin dispatch. Bug 2 (Tasks 3 to 7): `HttpResponse` gains a
separate `trailers` field (a mechanical sweep of 40 struct literals in 35 files, Task 3), the
machine captures the trailer section within caps (Task 4), the writer forwards the
non-forbidden fields and `serve` stores them (Task 5), and the bus and the native session
format carry them (Tasks 6 and 7). Task 8 adds loopback tests, Task 9 runs the two e2e
scripts for real against a core built from this branch (Terminal panel only; the scripts are
not added to the branch, Architect's call 27), Task 10 is the whole-branch tester pass, and
Task 11 is the fix task for the Stage 6 panel (the flow store's byte accounting, a typed
`Event::Error` for a refused origin response, and smaller items).

**Base SHA** for diffs and the AC30/AC31 checks: `4eb6cb5`, the docs-only commit (spec and
plan) on top of `main` at `112e9e8`, which already carries the HTTP/1 hardening change;
`git diff 4eb6cb5..HEAD` is exactly this change. The branch was cut at `2884ec0` and rebased
onto it; the baselines below are as measured at `2884ec0`. The Task 3 sweep counted 42
struct literals in 36 files on the rebased tree, not the 40 in 35 files counted at `2884ec0`:
the two extra literals are in `crates/aitm-plugin-scanner/src/inject.rs`.

**Baselines at `2884ec0`** (sandbox, for "existing tests unchanged"): `cargo test -p
aitm-proto-http --lib` 68 passed; `cargo test -p aitm-proto-http --test sansio` 27 passed;
`cargo test -p aitm-plugins --test detail` 8 passed.

**Files touched, and what that means for scheduling**

| Task | Files | Shares a file with |
|---|---|---|
| T1 | `crates/aitm-proto-http/src/sansio.rs` | T3, T4, T5 |
| T2 | `crates/aitm-proto-http/src/module.rs` | T3, T5 |
| T3 | 35 files in 9 crates at `2884ec0`, 36 on the rebased tree (the sweep; listed in the task), including `sansio.rs`, `module.rs`, `h2.rs`, `translate.rs`, `tests/h2_mitm.rs`, `aitm-plugins/tests/detail.rs`, and `sessionio/{src/native.rs,tests/session_roundtrip.rs}` | T1, T2, T4, T5, T6, T7 |
| T4 | `crates/aitm-proto-http/src/sansio.rs`, `crates/aitm-proto-http/tests/sansio.rs`, `crates/aitm-proto-http/src/sender.rs` (in-file tests only) | T1, T3, T5 |
| T5 | `crates/aitm-proto-http/src/sansio.rs`, `crates/aitm-proto-http/src/module.rs` | T1, T2, T3, T4 |
| T6 | `crates/aitm-plugins/src/detail.rs`, `crates/aitm-plugins/tests/detail.rs` | T3 (`tests/detail.rs`) |
| T7 | `crates/aitm-plugin-sessionio/src/native.rs`, `crates/aitm-plugin-sessionio/tests/session_roundtrip.rs` | T3 |
| T8 | `crates/aitm-proto-http/tests/h1_conformance.rs` (new) | none |
| T9 | none (a run, not a change: the scripts stay in the main checkout and are not added to the branch) | none |
| T10 | none expected (tests only, if it must strengthen any) | none |
| T11 | `crates/aitm-core/src/store.rs`, `crates/aitm-core/tests/store.rs`, `crates/aitm-proto-http/src/module.rs`, `crates/aitm-proto-http/src/sansio.rs` (one visibility keyword), `crates/aitm-plugin-sessionio/src/har.rs`, `crates/aitm-plugin-sessionio/src/mitmproxy.rs` (a comment each), plus whatever test or comment clean-ups the findings report names | T1, T2, T3, T5 (`module.rs`, `sansio.rs`, `tests/store.rs`), T7 (`har.rs`, `mitmproxy.rs`) |

**Serial, one coder at a time in this worktree:** T1, T2, T3, T4, T5. They all edit
`sansio.rs` or `module.rs`, and T3 edits both (literal sites) as well as 33 other files, so it
runs between the two bugs' machine work and may not overlap any of them. T2 needs T1 (it calls
the new methods). T4 and T5 need T3 (they read and write `HttpResponse.trailers`); T5 needs T4
(it forwards what T4 captures).

**Independent (may fan out) once T3 is merged:** T6 and T7. Each touches two files nobody else
edits after T3, in different crates, and neither depends on T4 or T5 (they render and persist the
field from hand-built flows). Run them in child worktrees on branches cut from this one, each
merged back when its panel passes, in parallel with the T4 then T5 lane. T8 needs T2 and T5.
T9 needs T8 (and T2 for the optional checkpoint run) and is a run, not a change: it has no
files, so nothing can conflict with it; it is run again on the final head after Task 11.
T10 is the whole-branch tester pass. Task 11 is the Stage 6 fix task: it is serial after T10
(it edits `module.rs` and `sansio.rs`), and the Tester and the panel run again on it. Inside T11
the parts are independent by file (the store accounting in `aitm-core`; the two comments in
`har.rs` and `mitmproxy.rs`; the `serve` and `sansio.rs` edits) and could fan out; they ride
in one fix task because each is a few lines.

```
T1 (sansio) --> T2 (module) --> T3 (sweep, 36 files) --+--> T4 (sansio, tests, sender) --> T5 (sansio, module) --+
                                                       |                                                        |
                                                       +--> T6 (detail.rs)   [parallel with the T4/T5 lane]     +--> T8 (new loopback file) --> T9 (e2e run, no files) --> T10 --> T11 (panel fix) --> T9 re-run
                                                       +--> T7 (native.rs)   [parallel with the T4/T5 lane] ----+
```

If Matt wants the cross-crate sweep out of this PR, Task 3 is one self-contained commit: cut
it (with Tasks 4 to 7) into its own PR stacked on Task 2's commit; Bug 1 (Tasks 1 and 2) has no
dependency on it.

**Execution notes (every task).**

- **Rust gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  must pass before any review. Gate with `cargo test --no-fail-fast`, and re-run before judging
  a failure of the `aitm-tui` wall-clock test
  `five_thousand_flows_ingest_and_render_within_bounds` (it flakes under machine load; it does not
  depend on `aitm-proto-http`). The workspace gate includes tests that bind ports, so the full
  gate runs in the Terminal panel. Inside the Bash sandbox run the socket-free subset while
  developing: `cargo test -p aitm-proto-http --lib`, `cargo test -p aitm-proto-http --test sansio`,
  `cargo test -p aitm-plugins --test detail`, `cargo test -p aitm-plugin-sessionio --test
  session_roundtrip`, `cargo test -p aitm-core --test store`, `cargo fmt --check`,
  `cargo clippy -p <touched crates> --all-targets -- -D warnings`, and, for Task 3,
  `cargo check --workspace --all-targets`. Do not run the whole workspace gate in the sandbox; it
  contends with other sessions.
- **Stale artifacts:** when worktrees share a `CARGO_TARGET_DIR`, `touch` every crate source before
  a gate or a live test so cargo does not reuse another worktree's artifacts:
  `find crates -name '*.rs' -exec touch {} +`.
- **Terminal panel only:** every `git` and `gh` command; `crates/aitm-proto-http/tests/h1_conformance.rs`
  (Task 8); the existing integration files that bind loopback ports (`tests/stale_upstream.rs`,
  `tests/http1_hardening.rs`, `tests/https_capture.rs`, `tests/response_park.rs`, `tests/h2_*.rs`,
  `tests/sender.rs`) and the cross-crate suites named in AC29; the e2e runs (Task 9); the full
  workspace gate. Gate a commit on the exit status of a `cargo test` redirected to a log, not on a
  `grep | tail` pipeline. The Terminal tool refuses command words that begin with `#`, so keep
  `#[...]` out of commit bodies. Push with an explicit refspec (`git push origin
  fix/http1-conformance`).
- **Red evidence:** each task's Coder report quotes the failing run and the passing run
  (`superpowers:test-driven-development`). The sandbox-runnable unit tests in Tasks 1 to 7 are the
  authoritative red-to-green record; Tasks 8 and 9 are corroboration. Where a new method or field
  does not exist yet, the Coder first adds the minimum stub (a method returning `false`, a no-op)
  so the tests compile and fail behaviourally, pastes that run, then implements.
- **Commits:** one commit per task, message `<type>(<scope>): <what> (plan: h1-expect-and-trailers)`.
- **Known flake:** `rhai_e2e::script_cannot_escape_or_exceed_scope` is non-deterministic. This
  change edits Rhai code only mechanically (Task 3: one production literal and six test literals,
  no behaviour), so if it fails, re-run it at the base SHA as well; the same failure there makes it
  the known flake, not this change.
- **Never:** touch `crates/aitm-core/src/{guard,proxy,authority,egress,ctx}.rs`, add a dial path
  (`TcpStream::connect` in `module.rs`), add a dependency, change `Event`, `FlowError` or a plugin
  signature, or log a trailer name or value.

## Tasks

### Task 1: The machine tracks an unanswered `100-continue` expectation (Bug 1, machine half)

- **Satisfies:** AC12; the machine halves of AC3, AC5, AC6
- **Depends on:** none (independent of Tasks 3 to 7 logically; serial with them by file)
- **Files:** `crates/aitm-proto-http/src/sansio.rs` (modify: production code and its in-file `mod tests`)
- **Change:**
  - `const CONTINUE_RESPONSE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";` (25 bytes), private.
  - New field `continue_pending: bool` on `Http1Machine`, `false` in `new`.
  - Private `fn expects_100_continue(headers: &HeaderMap) -> bool`: true iff some header line named
    `expect` (every line, not only the first), split on commas and trimmed, has a member equal to
    `100-continue` ASCII case-insensitively (whole member: `100-continue-ish` and `100-continue;x=1`
    do not match).
  - In `on_client_bytes`'s `Phase::Head` arm, after `request_framing` succeeds, assign
    `self.continue_pending` for EVERY request (so it resets): true iff the request-line version token
    is not `HTTP/1.0`, `expects_100_continue(&req.headers)`, the framing is `Framing::Length(n)` with
    `n > 0` or `Framing::Chunked`, and `self.client.buf.is_empty()` after the head was taken. The
    version token is read at parse time (a second return value from `parse_request`, or a small
    private helper over the request line); the model keeps recording `HttpVersion::Http11`.
  - `pub(crate) fn expects_continue(&self) -> bool` returns the flag.
  - `pub(crate) fn enqueue_continue(&mut self)`: when the flag is set, append `CONTINUE_RESPONSE` to
    `out_client` and clear the flag; otherwise do nothing.
  - No change to `HttpSansIoEvent`, to any `pub` signature, or to how heads parse.
  - Nothing calls the two new methods until Task 2, so each carries a temporary
    `#[cfg_attr(not(test), allow(dead_code))]` with a comment naming Task 2; Task 2 removes
    both (Architect's call 23).
- **Test (in-file `mod tests` of `sansio.rs`, sandbox-runnable).** A helper
  `fn after_request(raw: &[u8]) -> (Http1Machine, Vec<HttpSansIoEvent>)` feeds `raw` on
  `Side::Client`. Heads below are `POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n` plus the
  stated `Expect` line(s) plus `\r\n`, unless said otherwise.
  - `expectation_is_pending_when_the_body_has_not_arrived`: `Expect: 100-continue`, no body:
    `expects_continue()` is `true`; events are exactly `[RequestHeaders(id)]`.
  - `expectation_is_not_pending_when_the_body_arrived_with_the_head`: same plus `hello` in the same
    call: `false`; events `[RequestHeaders(id), RequestBodyChunk{flow: id, bytes: b"hello"},
    RequestComplete(id)]`.
  - `expectation_is_ignored_on_http_1_0`: request line `POST /u HTTP/1.0`: `false`.
  - `expectation_is_not_pending_when_no_content_follows`: `Content-Length: 0` gives `false` and events
    `[RequestHeaders(id), RequestComplete(id)]`; a head with no length at all gives `false`.
  - `a_chunked_request_has_a_pending_expectation_until_a_chunk_arrives`: `Transfer-Encoding: chunked`
    instead of the length: `true` with no body; `false` with `5\r\nhello\r\n` appended.
  - `expectation_matching_is_case_insensitive_and_whole_member`: table over the `Expect` value, with a
    `Content-Length: 5` head and no body: `100-Continue` true; `foo, 100-continue` true;
    `100-continue, foo` true; `foo` false; `100-continue-ish` false; `100-continue;x=1` false; empty
    value false. Plus two lines (`Expect: foo`, then `Expect: 100-continue`): true.
  - `enqueue_continue_queues_the_interim_once`: after the pending case, `enqueue_continue()` then
    `poll_outbound(Side::Client) == Some(b"HTTP/1.1 100 Continue\r\n\r\n".to_vec())`;
    `expects_continue()` is `false`; a second `enqueue_continue()` leaves `poll_outbound(Side::Client)`
    `None`.
  - `enqueue_continue_with_nothing_pending_queues_nothing`: a bare `GET`: `poll_outbound(Side::Client)`
    is `None` after the call.
  - `the_expectation_flag_resets_for_the_next_request`: request 1 (pending, answered, body fed,
    completed, server `HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n`), then `GET /x HTTP/1.1\r\nHost:
    h\r\n\r\n`: `expects_continue()` is `false`.
  - **Red protocol:** (1) write the tests; (2) add the constant, the field, and both methods as stubs
    (`expects_continue` returns `false`, `enqueue_continue` does nothing) so everything compiles; (3) run
    `cargo test -p aitm-proto-http --lib -- expectation enqueue_continue the_expectation_flag` and paste:
    the three pending-`true` cases and `enqueue_continue_queues_the_interim_once` fail, the rest pass;
    (4) implement; (5) re-run and paste: all pass.
- **Done when:** the tests pass, the 68 existing lib tests and the 27 `tests/sansio.rs` tests still pass,
  `cargo fmt --check` and `cargo clippy -p aitm-proto-http --all-targets -- -D warnings` are clean.

### Task 2: `serve` answers the expectation at head time (Bug 1, serve half)

- **Satisfies:** AC2, AC3, AC4, AC5, AC6, AC7, AC8, AC9, AC10 (AC1 by Tasks 8 and 9, AC11 by Task 4)
- **Depends on:** Task 1 (same crate; calls its methods)
- **Files:** `crates/aitm-proto-http/src/module.rs` (modify: `serve`, plus `mod tests`);
  `crates/aitm-proto-http/src/sansio.rs` (only to delete the two temporary `allow(dead_code)`
  attributes Task 1 added)
- **Change:** in `serve`'s request loop, in the `HttpSansIoEvent::RequestHeaders` arm, after
  `ctx.store().insert(...)` and before `ctx.emit(Event::RequestHeaders(id)).await`:
  - when `machine.expects_continue()`:
    - read the declared length with the machine's own parser, `sansio::content_length(headers: &HeaderMap)
      -> Result<Option<u64>>` (made `pub(crate)`; the machine already rejected a malformed or conflicting
      value before this event, so `.ok().flatten()` yields the length or none); if it is larger than
      `max_body`, set `request_oversized = true` and write nothing (the existing oversize branch then writes
      the `413` and closes). Task 2 first built a private `declared_length` helper in `module.rs`; Task 11
      replaced it with this call and deleted it (Architect's call 24);
    - otherwise `machine.enqueue_continue()` and `flush(&mut machine, Side::Client, &mut client).await`;
      if the flush fails, `return Ok(())` (the client went away; no error is logged).
  - Update the `serve` doc comment to say the proxy answers a `100-continue` expectation at head time.
  - Do not touch the connect step, the dial paths, `Event` emission order for requests without an
    expectation, or the oversize branch itself.
- **Test (`module.rs` `mod tests`, sandbox-runnable).** New test-only helpers, placed after the existing
  client helpers: `const STRICT_HEAD: &str = "POST /up HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Length:
  5\r\nExpect: 100-continue\r\n\r\n";` and `const CONTINUE: &str = "HTTP/1.1 100 Continue\r\n\r\n";`;
  `async fn read_interim(io: &mut DuplexStream, within: Duration) -> Option<String>` (reads until a blank
  line, returns the text, or `None` when nothing complete arrives within `within`; panics on EOF);
  `async fn origin_replying(io: DuplexStream, seen: Arc<Mutex<Vec<u8>>>, exchanges: Vec<Vec<&'static str>>)`
  (for each inner `Vec`, one exchange: read one request head and its `Content-Length` body, recording every
  byte into `seen`, then write that exchange's reply segments with
  `tokio::time::sleep(Duration::from_millis(10))` between; after the last exchange hold the connection open
  until the proxy hangs up); `struct ParkRequestHeaders` implementing `EventSink` (its `emit` for
  `Event::RequestHeaders(_)` awaits a shared `tokio::sync::Notify`; every other event continues);
  `async fn read_status_response_keep(io: &mut DuplexStream, pending: &mut Vec<u8>) -> (u16, String)` (like
  `read_response_keep` but returns the status and the `Content-Length` body without asserting 200). Every
  wait on the proxy uses `STALL_GUARD`. Cleartext cases use `Conn::plain(unknown_peer(), None)` and one
  in-memory upstream from `ctx_with` or `ctx_recording`.
  - `serve_answers_a_100_continue_expectation_before_the_body_arrives` (RED today): write `STRICT_HEAD`
    only; `read_interim(.., 1s)` is `Some("HTTP/1.1 100 Continue\r\n\r\n")` exactly (25 bytes); then write
    `hello`; the origin (`origin_replying`, reply `HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok`) is
    answered; the client reads body `"ok"` through `read_response_keep` and `pending` is empty. Today
    `read_interim` is `None` after 1 s.
  - `serve_sends_the_interim_once_when_the_body_trickles_in` (RED today): head, read the 100, then `hel`,
    then `lo` in two writes; the full byte stream the client reads is exactly
    `CONTINUE + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"`; the text contains `100 Continue` once.
  - `serve_omits_the_interim_when_the_body_arrived_with_the_head` (passes before and after): head and
    `hello` in one write; the first bytes the client reads are `HTTP/1.1 200 OK`; no `100` anywhere.
  - `serve_ignores_an_expectation_on_an_http_1_0_request` (passes before and after): `POST /up HTTP/1.0`
    with the same headers; `read_interim(.., 300ms)` is `None`; after the body, a 200 arrives with no 1xx.
  - `serve_sends_no_interim_when_no_content_follows` (passes before and after): `Content-Length: 0` with
    `Expect: 100-continue`: the request is complete at once, so the first head the client reads is the final
    `HTTP/1.1 200 OK` (its `read_interim` text starts with that, not with `HTTP/1.1 100`), and no `100`
    appears in anything the client reads.
  - `serve_matches_the_expectation_case_insensitively_inside_a_list` (RED today): for the `Expect` values
    `100-Continue`, `foo, 100-continue`, and two lines (`Expect: foo`, `Expect: 100-continue`), the client
    reads the 100; the origin's recorded bytes contain the original `Expect` text unchanged; and for
    `100-continue-ish` and `100-continue;x=1` `read_interim(.., 300ms)` is `None`.
  - `serve_does_not_answer_an_unknown_expectation_and_forwards_it` (passes before and after): `Expect:
    bogus`, `Content-Length: 5`: no interim in 300 ms; after the body the origin (which replies `HTTP/1.1
    417 Expectation Failed\r\nContent-Length: 0\r\n\r\n`) is answered; `read_status_response_keep` returns
    `(417, "")`; the origin's recorded request contains `Expect: bogus\r\n`.
  - `serve_forwards_the_expect_header_untouched_and_skips_the_origin_interim` (RED today for the 100; run
    with `ctx_recording`, in two variants: the origin's first exchange is `HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 302
    Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n` as ONE segment, and as TWO segments; its second
    exchange, for the plain `GET`, is `HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok`): the origin's
    recorded bytes equal exactly `POST /up HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nExpect: 100-continue\r\nContent-Length:
    5\r\n\r\nhello`; the client reads the proxy's 100, then `HTTP/1.1 302 Found\r\nLocation:
    /c\r\nContent-Length: 0\r\n\r\n`, nothing else; the recording sink holds exactly one
    `Event::ResponseHeaders`, one `Event::Response` and no `Event::Error` for the POST; `stored_http(&ctx, "/up")`
    has `response.status == 302`, request header `expect` == `100-continue` and a `Body::Bytes` request body of
    `hello`; a second plain `GET /next` on the same client connection (the first upstream stays live, so no
    second one is needed) returns `ok` with `pending` empty, and no 1xx leaked into it.
  - `serve_sends_the_interim_before_the_request_headers_event_returns` (RED today): context built with a
    `ParkRequestHeaders` sink; write `STRICT_HEAD`; `read_interim(.., 1s)` is the 100 while the sink is still
    parked (assert the sink has not been released); then release it, send `hello`, and the exchange
    completes.
  - `serve_refuses_a_declared_length_over_the_cap_before_asking_for_the_body` (RED today): call `serve`
    directly with `max_body = 4`; write a head with `Content-Length: 10` and `Expect: 100-continue`; the
    first and only bytes the client reads begin `HTTP/1.1 413 Payload Too Large\r\n`, then EOF; the client
    never wrote a body; `read_interim` saw no 100; the dial log is empty; `stored_http` has
    `metadata.truncated == true`. Companion `serve_still_reads_an_oversized_body_without_an_expectation`
    (passes before and after): the same with no `Expect` and a client that sends its 10 bytes: `413`, EOF.
  - `serve_answers_the_expectation_in_a_tls_tunnel_and_a_cleartext_tunnel` (RED today): once with
    `tunnel_conn()` and `Some(upstream)` (reconnect `None`), once with `cleartext_tunnel_conn("127.0.0.1:8080",
    "127.0.0.1:8080")`: the client reads the 100 first in both and the exchange completes.
  - **Red run (Task 1 in, `serve` unchanged):** paste the RED-marked tests failing (the 100 never arrives,
    `read_interim` is `None`) and the characterization tests passing; then the green run.
- **Done when:** the tests pass, all 68 existing lib tests pass, fmt and clippy are clean.

### Task 3: `HttpResponse.trailers`, the mechanical sweep (Bug 2, model)

- **Satisfies:** AC27 (the h2 half), and the compile-time precondition of AC14 to AC26
- **Depends on:** Task 2 (it edits `module.rs` and `sansio.rs`; serial)
- **Files:** `crates/aitm-core/src/flow.rs` (modify), and one `trailers: HeaderMap::new()` line (plus a
  `HeaderMap` import where missing) in each of these 40 literal sites, at the base:
  - `aitm-core`: `tests/store.rs` (14), `tests/store_control.rs` (36)
  - `aitm-findings`: `tests/recorder_e2e.rs` (21)
  - `aitm-plugin-maprules`: `src/lib.rs` (430)
  - `aitm-plugin-rhai`: `src/flow_state.rs` (185), `tests/flow_state.rs` (212), `tests/budget.rs` (108),
    `tests/command.rs` (231), `tests/poc_step.rs` (69), `tests/host_net.rs` (88, 330)
  - `aitm-plugin-scanner`: `src/passive.rs` (236, inside its `mod tests`); on the rebased tree also
    `src/inject.rs` (two literals, which the `2884ec0` count did not have)
  - `aitm-plugin-sessionio`: `src/native.rs` (259), `src/har.rs` (268), `src/mitmproxy.rs` (229),
    `tests/har_roundtrip.rs` (64), `tests/session_roundtrip.rs` (64, 98)
  - `aitm-plugins`: `src/intercept.rs` (434), `tests/scope_rate.rs` (23), `tests/control.rs` (56),
    `tests/mutate.rs` (92, 110), `tests/meta.rs` (29), `tests/detail.rs` (48), `tests/replay.rs` (55),
    `tests/capture.rs` (29)
  - `aitm-poc`: `tests/script_runner.rs` (29), `tests/dvwa_fixes.rs` (31), `tests/run.rs` (59),
    `tests/protocol_step.rs` (34), `tests/script_command.rs` (30), `tests/builder.rs` (38)
  - `aitm-proto-http`: `src/sansio.rs` (674 `parse_response`, 1048 in `mod tests`), `src/translate.rs`
    (79 `response_from_h2`, 206 in `mod tests`), `src/h2.rs` (416), `src/module.rs` (1059
    `oversized_response`), `tests/h2_mitm.rs` (605)
  - Line numbers are at the base and will have shifted; the compiler finds every one. The three literals
    that use struct update (`h2.rs:524`, `module.rs:850`, `sender.rs:298`) compile unchanged and are not
    edited. `maprules/tests/map_local.rs:452` is an `impl`, not a literal.
- **Change:** in `flow.rs`, `pub struct HttpResponse` gains `pub trailers: HeaderMap`, placed after
  `headers`, with a doc comment: trailer fields received after a chunked body (RFC 9110 6.5), in wire order
  with duplicates kept; held apart from `headers` on purpose and never merged into them; a capture field
  that no code path writes to a wire without the forbidden-name filter; only HTTP/1.1 chunked responses
  produce trailers today (h2 trailers are still dropped). The field takes `Flow`'s `Http` variant to 224
  bytes, over clippy's `large_enum_variant` threshold of 200, so `pub enum Flow` gets
  `#[allow(clippy::large_enum_variant)]` with a comment giving the reason (Architect's call 21; boxing
  `Flow::Http` ripples through every use of the variant in the workspace, and boxing only the new field
  saves 16 bytes). Every literal gets `trailers: HeaderMap::new()`.
  Every value is empty in this task, including `native.rs` (Task 7 maps it) and `sansio.rs:674` (Task 4
  fills it). The `h2.rs` and `translate.rs` edits are exactly the one-line initialisers (and the
  `translate.rs` test literal); nothing else in those files changes. No behaviour changes anywhere.
- **Test:** in `crates/aitm-core/tests/store.rs`, `a_response_keeps_trailers_beside_its_headers_never_in_them`:
  build an `HttpResponse` with `headers` `[("Content-Type", "text/plain")]` and `trailers` `[("X-Sum",
  "abc"), ("x-sum", "def")]`, insert it in a flow, read the flow back from the store; expect
  `trailers.iter().collect::<Vec<_>>() == [("X-Sum", "abc"), ("x-sum", "def")]` (order, case, duplicate),
  `headers.get("x-sum") == None`, `headers.len() == 1`. And, in `translate.rs`'s `mod tests`,
  `a_translated_h2_response_has_no_trailers`: with `parts` from `http::Response::builder().status(200).body(())
  .unwrap().into_parts()`, `response_from_h2(&parts).trailers.is_empty()` is `true`; and
  `h2_response_from_ignores_trailers`: a model whose `trailers` are `[("X-Sum", "abc")]` gives an
  `http::Response` whose `headers().contains_key("x-sum")` is `false`.
  **Red:** write both tests first; `cargo test -p aitm-core --test store` fails to compile with `no field
  trailers on type HttpResponse` (paste it). Then add the field, run `cargo check --workspace
  --all-targets`, and follow the errors to every literal; paste the passing `cargo check` and the two tests.
- **Done when:** `cargo check --workspace --all-targets` exits 0, the two tests pass,
  `git grep -n 'HttpResponse {' -- '*.rs'` shows every non-`impl`, non-`..` literal followed by a
  `trailers:` line, `cargo fmt --check` is clean, `cargo clippy -p aitm-core -p aitm-proto-http -p aitm-plugins
  -p aitm-plugin-sessionio -p aitm-plugin-maprules -p aitm-plugin-rhai -p aitm-plugin-scanner -p aitm-poc -p
  aitm-findings --all-targets -- -D warnings` is clean, and `cargo test -p aitm-proto-http --lib` (68 + the
  Task 1 and 2 additions) still passes.

### Task 4: The machine captures the trailer section; the sender returns it (Bug 2, machine half)

- **Satisfies:** AC14, AC15, AC16 (machine and sender halves), AC17, AC21 (machine half), AC24, AC28, and
  AC11
- **Depends on:** Task 3 (reads `HttpResponse.trailers`; same file as Task 1)
- **Files:** `crates/aitm-proto-http/src/sansio.rs` (modify), `crates/aitm-proto-http/tests/sansio.rs`
  (modify), `crates/aitm-proto-http/src/sender.rs` (add an in-file `#[cfg(test)] mod tests`; no production
  change)
- **Change:** in `sansio.rs`:
  - Private consts `MAX_TRAILER_BYTES: usize = 16 * 1024` and `MAX_TRAILER_FIELDS: usize = 64`, with doc
    comments giving the unit (bytes counted are each field line's length plus its CRLF; the terminating
    blank line is not counted).
  - Private `#[derive(Default)] struct Trailers { fields: HeaderMap, bytes: usize }`; `Reader` gains
    `trailers: Trailers`.
  - Private `fn parse_field_line(line: &str, into: &mut HeaderMap) -> Result<()>`: the name/value split,
    token check and `try_set` that `parse_headers` does per line, extracted so `parse_headers` calls it with
    identical behaviour (heads must parse exactly as before).
  - `fn step_chunked(buf: &mut Vec<u8>, phase: &mut ChunkPhase, trailers: &mut Trailers) -> Result<Step>`.
    The `ChunkPhase::Trailers` arm: take a line with `take_line(buf, MAX_TRAILER_BYTES)`; add the line
    length plus 2 to `trailers.bytes` and `bail!` naming the limit if it exceeds `MAX_TRAILER_BYTES`; an empty
    line is `Step::Done`; a line starting with SP or HT is an error; the line must be UTF-8; if
    `trailers.fields.len() == MAX_TRAILER_FIELDS` before adding, `bail!` naming the limit; otherwise
    `parse_field_line`. Error messages contain the word `trailer`.
  - Server `Phase::Chunked` arm: on `Step::Done`, move `std::mem::take(&mut self.server.trailers.fields)`
    into `self.response`'s `trailers` (and reset `bytes`), then `finish_response` as before. Client
    `Phase::Chunked` arm: on `Step::Done`, discard (`self.client.trailers = Trailers::default()`).
  - Update the doc comments of `response()`, `ChunkPhase::Trailers` and the module header to say trailers are
    captured on the response model and that request trailers are parsed, bounded and dropped.
  - No new `HttpSansIoEvent`, no change to any `pub` signature.
- **Test.**
  *`tests/sansio.rs` (public API, sandbox-runnable).* Helper: `fn get_exchange() -> (Http1Machine, FlowId)`
  (the existing `exchange(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")`). Response prefix `CH` =
  `HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-A, X-B\r\n\r\n4\r\nwxyz\r\n`.
  - `chunked_response_trailers_are_captured_in_order` (RED today: `trailers` empty): `CH + "0\r\nX-A:
    1\r\nx-b: two words\r\nX-A: 3\r\n\r\n"`; events exactly `[ResponseHeaders(id), ResponseBodyChunk{flow: id,
    bytes: b"wxyz"}, ResponseComplete(id)]`; `response().unwrap().trailers.iter()` collects to `[("X-A", "1"),
    ("x-b", "two words"), ("X-A", "3")]`; `response().unwrap().headers.get("x-a")` is `None` and
    `.get("trailer")` is `Some("X-A, X-B")`; `take_leftover(Side::Server)` is empty.
  - `trailers_split_at_every_position_give_the_same_result` (RED today): the section after `4\r\nwxyz\r\n`
    fed as two calls split at every byte index, and once one byte at a time; events concatenate to the same
    three and `trailers` equal the three pairs above.
  - `a_chunked_response_without_trailers_has_none` (passes before and after): `CH + "0\r\n\r\n"` gives the same
    three events and `trailers.is_empty()`.
  - `a_response_with_trailers_leaves_the_machine_ready_for_the_next_exchange` (RED today for the trailers
    assertion): after the first test's exchange, feed a second request `GET /y HTTP/1.1\r\nHost: h\r\n\r\n`
    then `HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok`: events `[RequestHeaders(id2), RequestComplete(id2)]`
    then `[ResponseHeaders(id2), ResponseBodyChunk{flow: id2, bytes: b"ok"}, ResponseComplete(id2)]`, `id2 !=
    id`, and the second response's `trailers` are empty (no carry-over).
  - `trailer_caps_fail_closed`: `CH + "0\r\n"` then (each in its own machine): 64 fields `f0: v` to `f63: v` +
    `\r\n` is `Ok`; 65 fields is `Err` and the error text contains `trailer`; one field `x-a: ` + 16377 `v`
    bytes + CRLF + `\r\n` (exactly 16384 counted bytes) is `Ok`; the same with 16378 `v` bytes (16385) is
    `Err`; 16385 bytes with no CRLF fed in one call is `Err`; feeding `a: b\r\n` repeated in 16 KiB reads
    returns `Err` by the 65th line.
  - `trailer_syntax_fails_closed`: `Err` for each of `x-a: v\x01\r\n\r\n`, `bad name: v\r\n\r\n`,
    `no-colon\r\n\r\n`, ` x-a: v\r\n\r\n` (leading SP), `\tx-a: v\r\n\r\n` (leading tab).
  - `request_trailers_are_parsed_bounded_and_dropped`: `POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding:
    chunked\r\n\r\n2\r\nab\r\n0\r\nX-T: 1\r\n\r\n` gives `[RequestHeaders(id), RequestBodyChunk{flow: id,
    bytes: b"ab"}, RequestComplete(id)]` (unchanged from today) and the machine then parses a following
    request; the same with 65 trailer fields is `Err`.
  *`sender.rs` in-file tests (sandbox-runnable, `tokio::io::duplex`, `drive` called directly).* Helper: an
  origin task that reads the request until it holds the head plus `Content-Length` body bytes, records them,
  then writes its segments with a 10 ms sleep between.
  - `drive_returns_the_trailers_of_a_chunked_response` (RED today): request `GET /x` (`Host: 127.0.0.1:8080`);
    origin writes `HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n5\r\nhello\r\n0\r\nX-Sum:
    abc\r\nServer-Timing: origin;dur=1\r\n\r\n` in one write: the returned response has `body` `Body::Bytes(b"hello")`,
    `trailers` `[("X-Sum", "abc"), ("Server-Timing", "origin;dur=1")]`, `headers.get("x-sum") == None`.
  - `drive_returns_trailers_that_arrive_in_a_later_read` (RED today): the same with the head and chunk in the
    first write and the trailer fields each in its own later write.
  - `drive_fails_on_a_trailer_section_over_the_cap` (RED today: the lines are dropped silently and `drive`
    returns `Ok`): 65 trailer fields; expect `Err` whose text contains `trailer`.
  - `drive_writes_an_expect_request_head_and_body_together` (passes before and after): `POST /up` with
    headers `Host: 127.0.0.1:8080` and `Expect: 100-continue`, body `Body::Bytes(b"hello")`; the origin's
    recorded bytes equal exactly `POST /up HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nExpect: 100-continue\r\nContent-Length:
    5\r\n\r\nhello`, read without the origin having sent anything first.
  - `drive_skips_an_origin_interim_100_for_a_request_that_carries_expect` (passes before and after): origin
    replies `HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n`; the
    returned `status` is 302, `headers.get("location")` is `Some("/c")`, `body` is `Body::Empty`.
  - **Red run:** with Task 3 in and this task's production change not yet made, paste `cargo test -p
    aitm-proto-http --test sansio -- trailer` and `cargo test -p aitm-proto-http --lib -- sender::tests`: the
    RED-marked tests fail (empty trailers, no `Err`), the characterization tests pass; then the green run after
    the implementation.
- **Done when:** the tests pass, the 27 existing `tests/sansio.rs` tests (including
  `chunked_response_streams_and_completes`, whose assertions do not change) and all lib tests pass,
  `cargo test -p aitm-proto-http --test sender` (Terminal) is unaffected, fmt and clippy are clean.

### Task 5: The writer forwards the allowed trailers and `serve` stores them (Bug 2, write and store)

- **Satisfies:** AC16 (the `serve` half), AC18, AC19, AC20, AC21 (the `serve` half), AC22, AC23
- **Depends on:** Task 4 (same files; forwards what Task 4 captures)
- **Files:** `crates/aitm-proto-http/src/sansio.rs` (modify, with in-file tests), `crates/aitm-proto-http/src/module.rs`
  (modify: `serve`, with `mod tests`)
- **Change:**
  - `sansio.rs`: a private `const FORBIDDEN_TRAILERS: &[&str]` holding exactly these 37 lowercase names, grouped
    by comment into the spec's categories: `transfer-encoding`, `content-length`, `host`, `cache-control`,
    `expect`, `max-forwards`, `pragma`, `range`, `te`, `if-match`, `if-none-match`, `if-modified-since`,
    `if-unmodified-since`, `if-range`, `authorization`, `proxy-authorization`, `www-authenticate`,
    `proxy-authenticate`, `authentication-info`, `proxy-authentication-info`, `cookie`, `set-cookie`, `age`,
    `date`, `expires`, `location`, `retry-after`, `vary`, `warning`, `content-encoding`, `content-type`,
    `content-range`, `trailer`, `connection`, `keep-alive`, `proxy-connection`, `upgrade`; and a private
    `fn is_forbidden_trailer(name: &str) -> bool` (whole name, ASCII case-insensitive).
  - `pub(crate) fn enqueue_body_end_with_trailers(&mut self, to: Side, trailers: &HeaderMap) -> usize`: for a
    chunk-framed `to`, append `0\r\n`, then `name: value\r\n` for each field that is not forbidden (in order),
    then `\r\n`; return how many fields were not written. For a body not framed chunked, write nothing and
    return `trailers.len()`. Reset the framing as `enqueue_body_end` does. The public
    `enqueue_body_end(&mut self, to: Side)` keeps its signature and calls it with an empty map, discarding the
    count. With no fields written the bytes are `0\r\n\r\n`, byte for byte as before.
  - `module.rs` `serve`, in the `HttpSansIoEvent::ResponseComplete` arm: first
    `let trailers = machine.response().map(|r| r.trailers.clone()).unwrap_or_default();`; inside `if
    forward_chunks`, call `machine.enqueue_body_end_with_trailers(Side::Client, &trailers)` instead of
    `enqueue_body_end`, flush as before, and if the returned count is non-zero emit one `tracing::debug!`
    with a `withheld` count field and a fixed message, no names or values; in the store update, set
    `resp.trailers = trailers` beside the body. Everything else in the arm (order: wire write, then store
    update, then `Event::Response`) is unchanged.
  - `module.rs` `serve`, in the `HttpSansIoEvent::ResponseHeaders` arm: the head stored for the streamed
    response has its `trailers` cleared (an empty `HeaderMap`) whatever the machine's `response()` holds. A
    response that arrives whole in one read has already parsed its trailer section into the machine's model
    by the time this event is handled; without the clearing a plugin would see trailers at
    `Event::ResponseHeaders` for one split of the origin's bytes and not for another (Architect's call 22).
- **Test.**
  *In-file `sansio.rs` tests (sandbox-runnable).* A helper builds a machine whose client-bound framing is
  chunked by calling `enqueue_response` with a `Body::Streamed(StreamBody)` response whose headers carry
  `Transfer-Encoding: chunked` (as the existing in-file egress tests do) and drains the head with
  `poll_outbound(Side::Client)`.
  - `trailer_terminator_without_fields_is_unchanged`: `enqueue_body_end_with_trailers(Side::Client, &empty)`
    then `poll_outbound(Side::Client) == Some(b"0\r\n\r\n".to_vec())`, returns `0`; and `enqueue_body_end`
    gives the same bytes.
  - `trailer_terminator_writes_allowed_fields_in_order`: trailers `[("x-sum", "abc"), ("X-E2E", "m1")]` give
    `Some(b"0\r\nx-sum: abc\r\nX-E2E: m1\r\n\r\n".to_vec())`, returns `0`.
  - `every_forbidden_trailer_name_is_withheld` (the table test): for each of the 37 names, in lower case and
    in upper case, trailers `[(name, "1"), ("x-ok", "1")]` produce exactly `b"0\r\nx-ok: 1\r\n\r\n"` and
    return `1`; and the list has exactly 37 distinct entries.
  - `trailers_are_not_written_for_an_unframed_body`: a machine whose client framing is raw: nothing is queued
    and the return is the field count.
  *`module.rs` `mod tests` (sandbox-runnable).* New test-only helpers: `async fn origin_chunked(io:
  DuplexStream, segments: Vec<&'static [u8]>)` (reads one request head, then writes each segment with a 10 ms
  sleep between, then holds the connection open); `async fn read_exact_bytes(io: &mut DuplexStream, n: usize)
  -> Vec<u8>` and `async fn assert_quiet(io: &mut DuplexStream, within: Duration)` (no byte arrives within
  `within`). Head `OH` = `HTTP/1.1 200 OK\r\nTrailer: x-sum, x-e2e\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n`;
  expected client bytes `WANT` = `HTTP/1.1 200 OK\r\nTrailer: x-sum, x-e2e\r\nTransfer-Encoding:
  chunked\r\n\r\n5\r\nhello\r\n0\r\nx-sum: abc\r\nx-e2e: m1\r\n\r\n`.
  - `serve_forwards_the_origin_trailers_in_order` (RED today: the client gets `0\r\n\r\n`): origin segments
    `[OH + "0\r\nx-sum: abc\r\nx-e2e: m1\r\n\r\n"]` (one write), and in a second variant `[OH, "0\r\n",
    "x-sum: abc\r\n", "x-e2e: m1\r\n\r\n"]`; the client reads exactly `WANT` (`read_exact_bytes`) and then
    `assert_quiet`.
  - `serve_keeps_the_connection_in_sync_after_a_response_with_trailers` (RED today for the first read): on one
    client connection, a request answered by the chunked-with-trailers origin segment set above, then a plain
    `GET` answered `HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok`: the client reads `WANT`, then body `"ok"`
    through `read_response_keep`, `pending` empty.
  - `serve_without_trailers_still_ends_the_body_with_a_bare_terminator` (passes before and after): origin
    `OH + "0\r\n\r\n"`: client reads `HTTP/1.1 200 OK\r\nTrailer: x-sum, x-e2e\r\nTransfer-Encoding:
    chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n`.
  - `serve_withholds_forbidden_trailers_from_the_wire_but_captures_them` (RED today): origin trailer section
    `Content-Length: 0\r\nHost: evil.test\r\nSet-Cookie: s=1\r\nAuthorization: Bearer x\r\nX-Keep:
    yes\r\nLocation: /x\r\n\r\n`; the client's bytes end with `0\r\nX-Keep: yes\r\n\r\n`; `stored_http(..)`
    `response.trailers` collects to `[("Content-Length", "0"), ("Host", "evil.test"), ("Set-Cookie", "s=1"),
    ("Authorization", "Bearer x"), ("X-Keep", "yes"), ("Location", "/x")]` and `response.headers.get("set-cookie")`,
    `.get("host")`, `.get("content-length")` (the head's own, which is absent in a chunked response) are `None`.
  - `serve_does_not_forward_origin_trailers_after_a_replaced_body` (RED today for the capture assertion): a
    test sink (sharing the store with its context, like `RewriteSink`) that, on `Event::ResponseHeaders`, replaces
    the stored response's body with `Body::Bytes(b"replaced")` and drops its `Transfer-Encoding` and `Trailer`
    headers; the client reads exactly `HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nreplaced` and nothing else (no
    `0\r\n` anywhere); `stored_http(..)` `response.trailers` still holds the origin's two fields.
  - `serve_exposes_trailers_to_plugins_at_response_time` (RED today): a sink holding the store that, on
    `Event::Response(id)`, records `response.trailers.len()` and `response.headers.get("x-sum")`: expect `2` and
    `None`. The same sink also records at `Event::ResponseHeaders(id)` and expects `0` and `None` there, for
    every delivery shape (the whole response in one read, and the trailer fields in later reads): this pins the
    `ResponseHeaders` clearing of call 22.
  - `serve_fails_closed_on_an_oversized_trailer_section` (RED today: the lines are dropped and the response
    completes): origin segments `[OH, "0\r\n" + 65 lines "f{n}: v\r\n" + "\r\n"]` (the head and the first chunk in
    an earlier write than the trailer section, so they are processed and flushed first); `serve` returns `Err`
    whose text contains `trailer`; the client has read `HTTP/1.1 200 OK\r\nTrailer: x-sum,
    x-e2e\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n` and never `0\r\n`, and then sees EOF (the one
    `Event::Error` this scenario also produces is asserted by Task 11's AC35 test, not here). A companion
    assertion in the same test file notes, in a comment, that when head, chunk and the over-cap section arrive in
    ONE read `on_bytes` returns `Err` for the whole read and the client receives nothing before the close; that
    case is fail-closed too and is not asserted separately.
  - `serve_never_logs_trailer_names_or_values` (RED today for the debug assertion): with
    `capture_events(tracing::Level::TRACE)`, a response whose trailers are `x-trailertoken-91c2: val-trailertoken-91c2`
    and a forbidden `Set-Cookie: s=1`: no captured event's message or any field contains `trailertoken` (case
    insensitive); exactly one `DEBUG` event whose fields are `{withheld: "1"}`; for a response whose trailers are
    all allowed, no event from this change.
  - **Red run (Tasks 3 and 4 in, this task's change not made):** paste the RED-marked tests failing and the
    characterization tests passing; then green.
- **Done when:** the tests pass, all existing lib and `tests/sansio.rs` tests pass, fmt and clippy are clean, and
  `grep -c 'connect_upstream(' crates/aitm-proto-http/src/module.rs` is still `3` and `grep -c
  'TcpStream::connect' crates/aitm-proto-http/src/module.rs` is `0`.

### Task 6: `flow.detail` renders the trailers (Bug 2, bus)

- **Satisfies:** AC25
- **Depends on:** Task 3 (needs the field; independent of Tasks 4 and 5; may run in a child worktree)
- **Files:** `crates/aitm-plugins/src/detail.rs` (modify), `crates/aitm-plugins/tests/detail.rs` (modify)
- **Change:** in `fn response(resp: Option<&HttpResponse>, ...)`, after `headers` is inserted, insert a
  `trailers` entry built by the same `headers(..)` helper (an array of `[name, value]` string pairs) only when
  `!r.trailers.is_empty()`. Update the module doc comment to mention `response.trailers`. No change to `request`,
  to `put_body`, to the `flow.detail` schema (its result type is an open object), or to any other key.
- **Test (`tests/detail.rs`, sandbox-runnable).**
  - `http_detail_renders_response_trailers_as_name_value_pairs` (RED today: no `trailers` key): a flow built like
    `flow_with_bodies()` but whose response has `trailers` `[("X-Checksum-SHA256", "abc"), ("Server-Timing",
    "origin;dur=1")]`; `obj(&d, "response").get("trailers")` equals `Some(&Value::Array(vec![Value::Array(vec![
    Value::Str("X-Checksum-SHA256".into()), Value::Str("abc".into())]), Value::Array(vec![Value::Str("Server-Timing".into()),
    Value::Str("origin;dur=1".into())])]))`; and the response `headers` array is unchanged (one pair,
    `content-type`).
  - `http_detail_response_has_no_trailers_key_when_there_are_none` (passes before and after): for
    `flow_with_bodies()` the keys of `obj(&d, "response")`, collected in order, are exactly
    `["body", "body_size", "body_truncated", "headers", "status", "version"]`.
  - `http_detail_request_object_is_unchanged_by_trailers` (passes before and after): the `request` object's keys
    for the trailers flow equal those of `flow_with_bodies()`.
  - **Red run:** the first test failing, the other two passing; then green.
- **Done when:** `cargo test -p aitm-plugins --test detail` passes (8 existing + 3), the other `aitm-plugins`
  suites that build a response still pass (`capture`, `mutate`, `replay`, `control`, `meta`, `scope_rate`), fmt and
  clippy are clean.

### Task 7: Native sessions carry the trailers (Bug 2, persistence; the first item to cut)

- **Satisfies:** AC26
- **Depends on:** Task 3 (independent of Tasks 4 to 6; may run in a child worktree)
- **Files:** `crates/aitm-plugin-sessionio/src/native.rs` (modify), `crates/aitm-plugin-sessionio/tests/session_roundtrip.rs`
  (modify)
- **Change:** `RespRec` gains `pub trailers: Vec<(String, String)>` with `#[serde(default, skip_serializing_if =
  "Vec::is_empty")]`; `resp_to_rec` fills it with `headers_to_rec(&r.trailers)`; `rec_to_resp` rebuilds the map
  with `rec_to_headers(&r.trailers)` (the trusted-source `set` path, which drops an invalid pair). `SCHEMA` stays
  `aitm-session/1`. The session format's `FlowRecord` mirrors `Flow`, so it gets the same
  `#[allow(clippy::large_enum_variant)]` and reason that `Flow` got in Task 3 (Architect's call 21).
  `har.rs` and `mitmproxy.rs` keep their empty initialisers from Task 3 (HAR 1.2 has no trailers
  field; mitmproxy import is not mapped); say so in a comment at each. The Task 7 Coder did not
  add those two comments (the files were outside its ownership), so the drop was undocumented in
  code; Task 11 adds them.
- **Test (`tests/session_roundtrip.rs`, sandbox-runnable).**
  - `native_session_roundtrips_response_trailers` (RED today: restored trailers are empty): a flow whose response
    has `trailers` `[("X-A", "1"), ("x-a", "2")]`; `session.save` to a temp path then `session.load` into a fresh
    store (the existing test's pattern); the restored response's trailers collect to `[("X-A", "1"), ("x-a", "2")]`.
  - `a_flow_without_trailers_serialises_without_a_trailers_key` (passes before and after): `flow.export` with no
    path returns `bytes`; for a store holding only `seeded_flow()` the UTF-8 text does not contain `"trailers"`;
    for the trailers flow it does.
  - `an_older_document_loads_with_empty_trailers` (passes before and after): export a store, remove nothing (the
    export of a no-trailers flow IS the old shape), `flow.import` it into a fresh store: the response `trailers`
    are empty.
  - **Red run:** the first test failing, the other two passing; then green.
- **Done when:** `cargo test -p aitm-plugin-sessionio` passes, fmt and clippy are clean.

### Task 8: Loopback integration tests

- **Satisfies:** the loopback corroboration of AC1, AC2, AC7, AC13, AC16, AC18, AC21, AC24
- **Depends on:** Tasks 2 and 5 (needs both fixes in the proxy; Task 4 covers the sender)
- **Files:** `crates/aitm-proto-http/tests/h1_conformance.rs` (create). No other file.
- **Change:** a new integration test file with a header comment stating that it binds loopback ports and runs in the
  Terminal panel. Copy the minimal helpers from `tests/http1_hardening.rs` rather than refactoring it: `provider`,
  `temp_dir`, `free_port`, `read_head`, `run_proxy` (returning the proxy address, root PEM and the store, with
  `HttpModule::with_ca(ca).with_insecure(true)`), `connect_tunnel`, `wait_for_flows`, `flow_for_path`, and a raw
  `TcpListener` origin helper whose per-connection behaviour is a closure. Every wait is bounded by `IO_TIMEOUT`
  and fails with a message naming what it waited for; no fixed ports.
- **Test.** All Terminal panel only.
  - `a_strict_expect_client_gets_100_continue_before_it_sends_the_body`: forward-proxy `POST http://<origin>/up`
    with `Content-Length: 65536` and `Expect: 100-continue`, head only; the client reads exactly `HTTP/1.1 100
    Continue\r\n\r\n` within 2 s; then writes the 65536-byte body; the origin (reads head and the whole body, records
    both, answers `HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n`)
    sees the head containing `expect: 100-continue` case-insensitively and exactly 65536 body bytes, once; the client
    reads `HTTP/1.1 302 Found` and no other 1xx; a plain `GET http://<origin>/next` on the same connection returns `200`
    with nothing left over; the store holds the POST flow with `response.status == 302` and request header `expect`.
  - `an_eager_expect_client_in_a_cleartext_tunnel_gets_one_final_response`: `CONNECT <origin>`; head and body in one
    write; the final status is `302`; at most one interim, and it is a `100`.
  - `chunked_trailers_reach_the_client_and_the_store`: raw origin writes `HTTP/1.1 200 OK\r\nTrailer: x-sum,
    x-e2e\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n`, sleeps 50 ms, writes `x-sum: abc\r\n`, sleeps,
    writes `x-e2e: m1\r\n\r\n`; a raw client sends `TE: trailers` and `Connection: TE`, decodes the chunks and the
    trailer section: body `hello`, trailers `[("x-sum", "abc"), ("x-e2e", "m1")]`; a second plain request on the same
    connection returns its `Content-Length` body intact; the store flow has `response.trailers` equal to those pairs
    and `response.headers.get("x-sum")` `None`.
  - `a_trailer_section_over_the_cap_ends_the_connection_without_a_terminator`: the origin writes the head and the first
    chunk, pauses 50 ms, then writes 65 trailer fields; the client reads the body chunk and then EOF, never `0\r\n`.
  - `the_replay_sender_returns_the_trailers_of_a_chunked_response`: `Http1Sender::new().send(&request)` against a raw
    origin answering the chunked-with-trailers response then closing: the returned `HttpResponse.trailers` equal the
    origin's pairs and the body is `hello`.
  - `a_forbidden_trailer_is_withheld_from_the_wire_but_kept_in_the_store` (a sixth test, added at implementation): an
    origin trailer section that carries a forbidden field next to an allowed one reaches the client without the
    forbidden field, and the store's `response.trailers` holds both.
  - **Red evidence:** copy only the new test file into a scratch worktree at the base SHA, run it there in the Terminal
    panel and paste the failures (the strict test times out waiting for the 100; the trailer tests see no trailers);
    then paste the green run on the branch. The sender test does not compile at base only if it names `.trailers`; in
    that case paste the compile error and run the rest.
  - Also run, in the Terminal panel, the existing `cargo test -p aitm-proto-http` integration files and paste the
    result: nothing here may regress them.
- **Done when:** all six tests pass on the branch, fmt and clippy are clean, and the full gate passes in the Terminal
  panel.

### Task 9: Run the two e2e scripts against a real core; do not land them (Terminal panel only)

Superseded scope (Architect's call 27). This task used to copy the two scripts into `tests/e2e/proto/` on this
branch. Another session owns those scripts and lands them test-only after this change merges; the copies in the
main checkout changed while this work was under way, so copies here would go stale or collide add/add. The task is
now a run, with no repository file created or changed.

- **Satisfies:** AC1, AC13 (by the exit status of the run); the loopback half of AC32 is Task 8's. AC32's checksum
  clause is not checked on this branch: it moves to the landing PR, where the `shasum -a 256` comparison happens.
- **Depends on:** Task 8 (and Task 2 for the optional checkpoint run); run again on the final head after Task 11
- **Files:** none. Do not add, copy or edit either script, `tests/e2e/aitm_e2e`, or the runner; `git status` and
  `git diff <base>..HEAD --stat -- tests/e2e` show nothing from this task.
- **Change:** run the scripts for real, unchanged, against a core built from this worktree, with the e2e fanout
  harness assembled in a scratch directory outside the repository:
  1. **Checkpoint run, after Task 2** (optional but recommended; it shows Bug 1 fixed while Bug 2 is still open): `zsh
     "/Users/matt/Library/Application Support/Claude-3p/side-session-notes/local_9ea8a296-48d1-40bb-8f9e-76f4046f1419/e2e-proto.sh"
     h1c-after-task2`. Expect `test_h1_100_continue.py` to pass and `test_chunked_trailers.py` to still fail on the
     trailer-fidelity check only.
  2. **Final run, on the final head (after Task 11):** the same script with label `final`. It touches every crate source,
     builds `aitm` and `aitm-testtarget` from this worktree, copies the runner (`run_all.py`, `_lib`), `tests/e2e/aitm_e2e`
     and the two scripts from the fanout backup and the MAIN checkout into its scratch directory, exports `AITM_BIN` and
     `AITM_TESTTARGET_BIN` at the binaries it just built, boots a real core with `python3 .../run_all.py --boot
     --no-build -j 1 proto`, and runs both scripts. Logs are `e2e-build-final.log` and `e2e-final.log` in the notes
     directory. Paste the grep summary the script prints and the tail of `e2e-final.log`.
  Evidence already held: `e2e-baseline.log` (before any fix: both scripts fail) and `e2e-fixed1.log` (after Tasks 1 to 5, head
  `c11ee84`: both pass); the production code at the final head must be re-run, not assumed.
- **Test (the literal expected output).** In `e2e-final.log`: `PASS proto/test_chunked_trailers.py`, `PASS
  proto/test_h1_100_continue.py`, `TOTAL 2 passed, 0 failed, 0 skipped`, and the script's `E2E exit=0`. The runner prints
  only `PASS` or `FAIL` per script, so the sentences AC1 and AC13 quote (the 100 "N ms after the head", "trailer fidelity
  ... (0 problem(s))") are not expected in this log; the exit status is the proof.
- **Done when:** both logs are pasted and show the above, on the final head. Record in the Review log that the scripts and
  the harness they import were run from outside the branch and are not on it.

### Task 10: Whole-branch tester pass

- **Satisfies:** AC27 (suites), AC29, AC30, AC31, AC32 (loopback file; no `tests/e2e` file in the diff), AC33 (and
  confirms every other AC, AC34 and AC35 included, maps to a test)
- **Depends on:** Tasks 1 to 9; the Tester runs it again on the whole branch after Task 11
- **Files:** none expected; the Tester may add or strengthen tests only.
- **Change:** run as the Tester engine (spec, plan, worktree, base and head SHA, "whole branch"). Touch every crate source
  first (`find crates -name '*.rs' -exec touch {} +`). Then, quoting actual output:
  - the full gate in the Terminal panel: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
    --no-fail-fast` (exit status gated, output to a log; re-run before judging a failure of the `aitm-tui` wall-clock test
    `five_thousand_flows_ingest_and_render_within_bounds`);
  - the named suites from AC29, each on its own: `cargo test -p aitm-proto-http`, `-p aitm-core`, `-p aitm-findings`, `-p
    aitm-plugins`, `-p aitm-plugin-sessionio`, `-p aitm-plugin-maprules`, `-p aitm-plugin-rhai`, `-p aitm-plugin-scanner`, `-p
    aitm-poc`, `-p aitm-proto-ws`, `-p aitm-plugin-wsctl`, `-p aitm-plugin-passthrough`;
  - AC30: `git diff <base>..HEAD --stat -- crates/aitm-core` lists exactly `src/flow.rs`, `src/store.rs`,
    `tests/store.rs`, `tests/store_control.rs`; `git diff <base>..HEAD --stat -- crates/aitm-proto-http/src/sender.rs` shows only the added
    in-file test module (`git diff <base>..HEAD -- crates/aitm-proto-http/src/sender.rs` has no hunk above the new `mod
    tests`); the `h2.rs` and `translate.rs` hunks are exactly the one-line initialisers, the test literal and the two new `translate.rs` tests; `grep -c
    'connect_upstream(' crates/aitm-proto-http/src/module.rs` prints `3` and `grep -c 'TcpStream::connect'
    crates/aitm-proto-http/src/module.rs` prints `0`;
  - AC31: `git diff <base>..HEAD --stat -- Cargo.toml Cargo.lock 'crates/*/Cargo.toml'` prints nothing;
  - AC32: `git diff <base>..HEAD --stat -- tests/e2e` prints nothing (the scripts are run, not landed, and their
    checksum comparison belongs to the landing PR), and the loopback file's six tests pass;
  - the mac decoder claim from the spec: if `swift test` for the `AitmproxyKit` package is cheap to run in the Terminal
    panel, run `FlowDetailWireTests` and record the result; otherwise record "not run" (it is not part of the gate);
  - a table mapping AC1 to AC35 to the test that proves each (AC1 and AC13 map to Task 9's run, not to a file), flagging any AC with only a weak or indirect test and
    strengthening it (in particular: every one of the 37 deny-set names is exercised, the 64/65 and 16384/16385 boundaries
    are exercised, the interim is checked for exactly-once, and no test passes against a `serve` that writes the 100
    after `Event::RequestHeaders`);
  - mutation spot checks, each reverted afterwards, with the test that catches it: write the 100 after the `RequestHeaders`
    emit; drop the `continue_pending` reset; match `expect` only on the first header line; merge trailers into `headers`;
    forward a forbidden name; use `>` instead of `>=` at either cap; write trailers after a replaced body.
- **Test:** the table above, with the literal command outputs; every AC has a passing test.
- **Done when:** the report is accepted, and the panel (security, quality, spec reviewers in parallel, on the whole branch)
  has no open findings.

### Task 11: Stage 6 fix task (store accounting, typed error, early 413, documented drops)

Added after the Stage 6 panel, which reviewed the work of Tasks 1 to 10. Its input is the panel's findings report (the
workflow's fix-task rule); this entry fixes the scope and the literal expected values. Tester and the panel run again on
it afterwards.

- **Satisfies:** AC34, AC35 (its test drives AC16's `serve` scenario, so it also covers the `Event::Error` that scenario
  produces), AC30 as amended (`src/store.rs` joins `aitm-core`'s diff), and the documented-drop comments Task 7 specified;
  implements Architect's call 24.
- **Depends on:** Tasks 1 to 10 (serial: it edits `module.rs` and `sansio.rs`, which Tasks 1 to 5 also edited)
- **Files:** `crates/aitm-core/src/store.rs`, `crates/aitm-core/tests/store.rs`, `crates/aitm-proto-http/src/module.rs`,
  `crates/aitm-proto-http/src/sansio.rs` (one visibility keyword), `crates/aitm-plugin-sessionio/src/har.rs` and
  `crates/aitm-plugin-sessionio/src/mitmproxy.rs` (a comment each). No other production file.
- **Change:**
  - **A. Store accounting (AC34).** In `store.rs`, `fn flow_size(flow: &Flow) -> usize`: the `Flow::Http` response term
    counts `header_bytes(&r.trailers)` as well as the headers and the body, with the same `header_bytes` helper (the sum of
    every pair's name length and value length). No signature changes; nothing else in the file changes.
  - **B. A typed error for a refused response (AC35).** In `module.rs`, `serve`'s response read loop, where the read bytes
    are fed with `machine.on_bytes(Side::Server, &buf[..n])` (the `n > 0` path; `on_eof` is untouched and keeps its own
    "upstream closed before completing the response" event): on `Err`, first `ctx.emit(Event::Error { flow: id, kind:
    aitm_core::FlowError::Upstream("malformed response from upstream".to_string()) }).await`, then return the machine's
    error unchanged. The string is a literal in `serve`, never built from the error or from any read byte. `Event` and
    `FlowError` are not changed (the variant exists). A comment says why: event consumers see a response only through its
    events, and the machine's text can quote the origin.
  - **C. The early 413 reuses the machine's parser (call 24).** In `sansio.rs` `fn content_length(headers: &HeaderMap) ->
    Result<Option<u64>>` becomes `pub(crate)`, with no behaviour change. In `module.rs`, `serve`'s `expects_continue()` block
    reads the declared length with it (`.ok().flatten()`), and the private `declared_length` helper is deleted. Nothing
    else in that block changes, and Task 2's boundary test (a declared length equal to the cap gets the 100, one byte over
    gets the `413`) keeps passing.
  - **D. Documented drops.** `har.rs` and `mitmproxy.rs`: a comment at the response literal's empty `trailers` initialiser
    saying HAR 1.2 has no trailers field so export does not write them, and the mitmproxy importer does not map them, so the
    field is empty on import. Comments only.
  - **E. Test and provenance clean-ups.** Exactly the ones the findings report lists (test helpers, test comments, and
    comments that name a task or a source), each noted in the Coder's report; no behaviour change and no new production code.
- **Test.**
  *`crates/aitm-core/tests/store.rs` (sandbox-runnable; names free).*
  - `trailers_count_toward_resident_bytes` (RED today: the difference is `0`): two stores each holding one terminal flow with
    no body that differs only in its response's `trailers`, `[("X-Sum", "abc"), ("x-sum", "def")]` against none:
    `resident_bytes()` is at least `16` greater (5 + 3 + 5 + 3) for the one with trailers.
  - `a_trailer_costs_what_the_same_header_costs` (RED today): the same pairs as `trailers` on one flow and as `headers` on
    another give equal `resident_bytes()`.
  - `update_adding_trailers_counts_toward_byte_budget` (RED today: nothing is evicted): `MemFlowStore::with_limits(10_000,
    10_000)` holding 20 terminal flows; `update` each flow's response to gain one trailer of 1000 bytes of field text (name
    `X-Pad` and a 995-byte value); afterwards `resident_bytes() <= 10_000` and `list().len() < 20`.
  *`module.rs` `mod tests` (sandbox-runnable).*
  - `serve_reports_a_malformed_trailer_section_as_one_typed_error` (RED today: no `Event::Error`): the origin sends the head,
    a first chunk and a 65-field trailer section, once in a write after the head and chunk and once with all three in one
    write; in each case `serve` returns `Err` whose text contains `trailer`; the recording sink's `Event::Error`s for the
    flow equal exactly `[FlowError::Upstream("malformed response from upstream".to_string())]`; the sink holds no
    `Event::Response` for the flow; and the `Debug` text of every event the sink saw contains none of the origin's trailer
    field names.
  - **Red run:** write the four tests first; paste them failing (the byte differences are `0`, nothing is evicted, the typed
    error is absent); then make changes A and B and paste them passing. Changes C and D have no red test of their own: C is
    held by the existing 413 tests, D is comments.
- **Done when:** the four tests pass; `cargo test -p aitm-core --test store`, `cargo test -p aitm-proto-http --lib` and `cargo
  test -p aitm-plugin-sessionio` pass; `cargo fmt --check` and `cargo clippy -p aitm-core -p aitm-proto-http -p
  aitm-plugin-sessionio --all-targets -- -D warnings` are clean; `grep -c 'connect_upstream(' crates/aitm-proto-http/src/module.rs`
  prints `3` and `grep -c 'TcpStream::connect' crates/aitm-proto-http/src/module.rs` prints `0`; `git diff <base>..HEAD
  --stat -- crates/aitm-core` lists exactly `src/flow.rs`, `src/store.rs`, `tests/store.rs`, `tests/store_control.rs`. Then
  Task 9's final run (Terminal panel), the whole-branch Tester pass of Task 10 and the panel run again.

## Review log

Kept by the main session during stage 6. One row per finding. "Accepted" means accepted by the orchestrating session under Matt's standing autonomous-mode instruction (2026-10-30); Matt can reverse any of them. Base SHA for the whole branch: `4eb6cb5`.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| T9, AC1, AC13, AC32 | Spec (round 1) | Important | The spec and plan said the two e2e scripts are copied into `tests/e2e/proto/` on this branch; they are not. Their owner session (e2e-test-arch) lands them test-only after this merges, because the main-checkout copies changed during this work (a copy here would go stale or conflict add/add). | Recorded as a deliberate supersession (Architect's call 27): the scripts are run for real against a core built from this branch (fanout `run_all.py --boot --no-build`) and their exit status proves AC1/AC13; the AC32 `shasum` comparison moves to the landing PR. The copies that ran have sha256 `5e18b7d369d4...` (100-continue) and `f872bd861e15...` (trailers) at the time of the final run. Spec and plan text amended. |
| whole | Spec (round 1) | Important | AC33: the only full gate on the range was red (one failing test); the head had not been gated. | The one failure was a defect in the T7 test (`a_flow_without_trailers_serialises_without_a_trailers_key` compared JSON keys in iteration order; `aitm-tui` enables `serde_json/preserve_order` only in a whole-workspace build): fixed in bae612b, re-checked in workspace context. The full gate is re-run at the final head (see Shipped). |
| whole | Security (round 1) | Important | The flow store's resident-byte budget (`aitm-core/src/store.rs` `flow_size`) did not count `HttpResponse.trailers`: a hostile origin could attach up to 16 KiB of trailers to every response outside the budget (unbounded with `max_flows = 0`). | fixed in 420b815 (`flow_size` charges trailers like headers; 3 tests: red first). AC34. |
| whole | Security (round 1) | Minor | A trailer-section (or any response-parse) failure ended the connection with no `Event::Error`, so scanner, findings and Rhai hooks never saw the response. | fixed in 420b815 (one `Event::Error` with fixed wording before the connection ends; test red first). AC35. |
| whole | Security (round 1) | Minor | The 37-name deny-set leaves other fields a non-compliant client could treat as headers (`set-cookie2`, `content-disposition`, `content-security-policy`, `strict-transport-security`, `alt-svc`, `link`, `refresh`, `content-location`, `clear-site-data`). | Accepted: residual risk the spec already states (F9); optional hardening later. |
| T5 | Tester | Minor | The sessionio test failure above; plus weak or missing tests (HTTP/1.x versions, partial body with the head, chunked upload with Expect, failed interim write, request-trailer caps per read, EOF inside the trailer section, empty trailer value). | fixed in bae612b and a28105d (9 tests added; 38 production mutations run: 36 killed, 2 equivalent survivors: an unreachable writer branch (`HeaderMap` cannot hold an invalid pair) and a writer call that writes nothing for a non-chunk-framed body). |
| whole | Quality (round 1) | Minor | The plan's documented-drop comments missing in `har.rs`/`mitmproxy.rs`; a second Content-Length parser in `serve` (`declared_length`); a port race in the loopback `run_proxy`; one duplicated test helper; spec/process wording in test names and comments; three over-claiming doc comments; a dead `Framing::Length(n) => n > 0` arm. | fixed in 420b815. |
| whole | Quality (round 1) | Minor | Test-helper copies across the two loopback files and about 120 lines of scaffolding duplicated; `mod tests` is about 70 percent of `module.rs`; some redundant tests (the store round trip, the serve-level case-insensitive match, a leftover-length assertion, an old-document test built from the new exporter). | Accepted and deferred: a `tests/common` module and moving `mod tests` out are one mechanical follow-up (also noted by the hardening change's Review log); the redundant tests are cheap and each pins a distinct failure. |
| T2 | Quality (round 1) | Minor | A failed interim write leaves a head-only flow in the store with no `RequestHeaders` event. | Accepted: the spec states a quiet `Ok` (call 2); the same orphan already exists for a client that leaves mid-request. |
| T3, T7 | Spec (round 1) | Minor | The two `#[allow(clippy::large_enum_variant)]` (`aitm_core::Flow`, sessionio `FlowRecord`) were not in the spec or plan. | Accepted: the minimal consequence of the required 24-byte field under `-D warnings` (224 bytes against a 200 threshold); boxing `Flow::Http` ripples workspace-wide, boxing the field saves only 16 bytes. Recorded as Architect's call 21 (the `FlowRecord` allow mirrors `Flow`; approval stated there). |
| T2 | Spec (round 1) | Minor | T2's commit touched `sansio.rs` (removing the dead-code allowance T1 added). | Accepted and recorded (call 23). |
| T4 | Spec (round 1) | Minor | AC17's non-token-name clause had no direct test. | fixed in 420b815 (`x@a: v` case). |
| T10 | Spec (round 1) | Minor | The mac `FlowDetailWireTests` result is required by the plan and was not produced; the MCP flow-detail widget also reads `flow.detail`. | Not run (Swift, outside the Rust gate, needs the Terminal and a mac build). The change is additive (a new key that is omitted when empty), the widget reads named keys and ignores the rest, and the e2e `proto` suites read the key over the bus. Recorded as not run. |
| T6 | Spec (round 1) | Minor | The e2e evidence is the non-verbose runner summary (exit 0), so the literal check lines are not captured. | A verbose run of both scripts is captured at the final head (see Shipped). |
| T4 | Quality (round 1) | Minor | HEAD/204/304 with a mis-declared chunked head still get a stray `0\r\n\r\n` (the hardening spec's F2). | Accepted, unchanged by this work (the tester confirmed the writer emits the same 5 bytes the base did). |

## Shipped

Filled at stage 7 (the merge): see the PR. Follow-ups, none done here: HTTP/2 `Expect: 100-continue` (`send_informational` in the vendored `h2`), request-side trailers, h2 trailers, rendering trailers in the TUI, web UI and mac app, the shared-constant and `Tunnel` struct debts from the hardening spec, `tests/common` for the integration-test helpers.
