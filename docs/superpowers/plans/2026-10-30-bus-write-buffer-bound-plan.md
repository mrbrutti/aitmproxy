# Bus write-buffer bound implementation plan

**Status:** Approved 2026-10-30 by the orchestrator under Matt's autonomous-approve delegation (flagged in the PR body for Matt's review). Implementation is held until PR 156 merges. **G1 ruled: the plan default stands** (retire the one AC23 socket test and replace its call-site proof, Task 6), conditional on Task 6 step 0 measuring the outcome the plan predicts; if the measurement contradicts the prediction, stop and report. After Task 0 the architect amends the spec for G1 to G6 (AC13's unmodified-suite clause, AC2's bound, AC6(d), AC4 duplex, AC3 wording) before Task 5 is dispatched.
**Spec:** `docs/superpowers/specs/2026-10-30-bus-write-buffer-bound-design.md` (approved 2026-10-30 by the orchestrator under Matt's autonomous-approve delegation; flagged for Matt's review in the PR body)
**Branch / worktree:** `claude/jovial-lamport-62defb` in `/Users/matt/Security/aitmproxy/.claude/worktrees/jovial-lamport-62defb` (it carries the spec and this plan). If the orchestrator prefers the WORKFLOW's `feat/<topic>` name, cut `feat/bus-write-buffer-bound` from this branch after the rebase in Task 0. Independent tasks may fan out to child branches cut from the plan branch (Overview says which).

**Implementation starts only after the bus-hardening PR has merged to `main`, from a worktree rebased on `main`.** That PR is open as https://github.com/mrbrutti/aitmproxy/pull/156 (branch `claude/vibrant-proskuriakova-e98cfd`). It is not merged by this effort: Matt decides, and nothing here starts before he does. It carries the code this plan builds on: `send_within`, `refuse_unauthorized`, `CLOSE_DRAIN_TIMEOUT`, the write deadline, the bounded subscription registry, `crates/aitm/tests/support/web_bus.rs` and `web_bus_write_deadline.rs`. All signatures and file pointers below were read, without checking out, at that branch's current head **`8db420a`** (re-checked unchanged when this plan was finished). The spec was written at `e35a421`; `8db420a` is `e35a421` plus the round 2 fix and a merge of `main` (which already contains `a771996`); see Task 0's drift record. Line numbers are indicative only. **Task 0 is: rebase, re-check the spec's code references against `main`, record any drift in this plan, stop and report if the spec is wrong.** Task 0 also re-runs the PR's AC23 test on the rebased tree and records what it finds (G1).

## Spec gaps

Found while planning. The spec is not edited; the orchestrator rules on G1 before dispatching Task 6, and the rest are resolved by the plan's default.

- **G1 (blocks AC13 and Task 6): the pre-auth Pong drain defeats the PR's AC23 test.** `web_bus_write_deadline.rs::an_unauthenticated_pinging_peer_is_dropped_at_the_refusal_deadline` (bus-hardening AC23, in PR 156) floods 20 MiB of Pings (165,130 of them) before the token, then sends a bad token behind them, inside a 6 s `FLOOD_BOUND`, and expects the server to have read all of it and to reach `refuse_unauthorized`, dropping the peer at the 5 s refusal deadline. With Design 1's pre-auth drain (`flush_within` after each Ping, bounded by the time left in the handshake window) the server stops reading at the first Pong the socket will not take, so the peer is now dropped at the **handshake** deadline by the flush, and the bad-token frame is **never read**. By reading the code, the client's flood stalls at the kernel buffers (about 21.6 MB of Pings against a few MiB of buffering; this test does not shrink the listener's `SO_RCVBUF`) and the 6 s bound panics ("sending ... pings and the bad token took more than 6s"). **This is a prediction from the code, not a measurement:** Task 0 runs the test on the rebased tree (baseline, expected green) and Task 6 runs it **unmodified** against the fixed bridge, before touching it, and records the real outcome. Either outcome ends in the same place: (A) it fails as predicted, so AC13's "passes unmodified" cannot hold; or (B) it passes only because the peer is dropped at the handshake deadline and the bad token is never read, in which case it no longer discriminates what it was written for (a bridge whose refusal send is unbounded still passes it, because the refusal is never reached). The server only ever sends Pongs before authentication, each flushed before the next read, so no socket test can put a Ping-filled send path in front of the refusal any more. AC13 says that file passes unmodified, so a needed change to that test is a spec gap to report, not to improvise. **Plan default, needs the orchestrator's ruling before Task 6 is dispatched:** Task 6 retires that one socket test (the file otherwise stays as is; five tests remain) with its now-unused constants and imports, fixes the module-doc bullets, and fixes the stale `HANDSHAKE_TIMEOUT` mention at line 101 of that file (it names a constant Task 2 removes). Its two jobs move: "a pinging pre-auth peer is dropped and never sent a refusal or Close" is now AC3(b); "the refusal's call site in `relay` is bounded" becomes a sandbox test in `bridge.rs` over a write-stalled stream (`relay_bounds_the_bad_token_refusal_on_a_send_path_that_never_drains`, about 5 s, red by mutation if the call site sends unbounded or with the 30 s write deadline). This feature's own discriminators are AC1, AC2 and AC3, not AC23. If the ruling is "keep the file untouched", Task 6 cannot be accepted and the spec needs an amendment first.
- **G2 (minor): AC13 names four suites; more exercise `relay`.** `web_bus_governance.rs` (own rig, not the shared harness; it serves the real `web::serve`), `web.rs`, and `aitm-mcp`'s `tests/mcp.rs` go through the changed code; `web_bus_ask_split.rs` is an in-process rig with no websocket and is unaffected. None sends a Ping. They run as regression in every Terminal gate; none is edited (Task 13 is an optional, out-of-criteria cleanup of the governance rig).
- **G3 (minor wording): AC6(d) says the TCP first-line reader "returns an error"; Design 4 says an over-limit first line "is a bad token" and gets the usual refusal.** Plan reading: the reader returns a `TooLong` outcome (not an `Err`) having buffered exactly `limit + 2` bytes, and `serve_connection` turns it into the existing `unauthorized` refusal. AC6(d) asserts `TooLong` and a 770-byte buffer. Say so if a literal `Err` was meant.
- **G4 (minor, tightens a bound): AC2's "within 5 s" races its own RED.** On unfixed code the pre-auth flood ends in the 100 ms `pre_auth_timeout` and `close` then drains for `CLOSE_DRAIN_TIMEOUT` (5 s), so `relay` returns `Ok(())` at about 5.1 s, a 100 ms margin against a 5 s outer bound. The plan uses a 3 s outer bound for AC2 (fixed code returns in about 100 ms) so RED fails on "relay returns within 3 s" unambiguously. AC1 keeps 5 s (unfixed `relay` never returns).
- **G5 (minor): AC4's duplex half cannot issue `flow.list`** (a bare `Registry` has no commands). The duplex test uses the server-handled JSON-RPC `ping` request; the socket test uses `flow.list` as written.
- **G6 (minor): AC3 says the stopped peer's "stream ends within ...", but a peer that is not reading cannot observe that.** Plan: the flooding task ends when the server drops the connection (bounded wait), the Ask probe shows the subscription gone, then the test resumes reading and requires the end of stream, as `web_bus_write_deadline.rs` does today.

## Overview

Twelve tasks plus the Task 0 rebase and an optional Task 13 (outside the acceptance criteria). The work is two serial chains on two hot files with a few independent starts. **Bridge chain** (`bridge.rs`): Task 2 seams, Task 5 post-auth Pong drain, Task 6 pre-auth Pong drain, Task 8 web first-line bound. **Transport chain** (`transport.rs`): Task 4 seam, Task 7 first-line bound, Task 9 TCP pre-auth deadline, Task 10 drop guard. Task 1 (`McpServer` pre-auth timeout seam) gates both chains; Task 3 (harness additions plus the AC5 guard) gates the socket tests; Task 8 also needs Task 7 (`auth_line_limit` lives in `transport.rs`). Task 11 is the Tester's mutation pass and the AC13 checks; Task 12 sweeps docs.

| Wave | Tasks (run in parallel) | Files they own (disjoint within a wave) |
|---|---|---|
| A | Task 1, Task 4 | T1 `aitm-mcp/src/{server,lib}.rs`; T4 `aitm-mcp/src/transport.rs` |
| B | Task 2 (after 1), Task 3 (after 1), Task 7 (after 4) | T2 `aitm/src/web/bridge.rs`; T3 `aitm/tests/support/web_bus.rs` + `aitm/tests/web_bus_write_buffer.rs` (create); T7 `transport.rs` |
| C | Task 5 (after 2 and 3), Task 9 (after 7 and 1) | T5 `bridge.rs`, `web_bus_write_buffer.rs`, `server.rs` (one doc paragraph only); T9 `transport.rs` |
| D | Task 6 (after 5), Task 10 (after 9) | T6 `bridge.rs`, `web_bus_write_buffer.rs`, `web_bus_write_deadline.rs`; T10 `transport.rs` |
| E | Task 8 (after 6 and 7) | `bridge.rs`, `web_bus_first_line.rs` (create) |
| F | Task 11, the Tester | tests only |
| G | Task 12 | doc comments in `bridge.rs`, `transport.rs`, `server.rs` |
| H (optional) | Task 13 | `aitm/tests/support/web_bus.rs`, `aitm/tests/web_bus_governance.rs`; after everything else, only if cheap |

Sequential fallback order: 1, 4, 2, 3, 7, 5, 9, 6, 10, 8, 11, 12 (then 13 if taken).

Who owns which file, in the only order they may be edited (two writers never share a file; the four hot files are `bridge.rs`, `transport.rs`, `server.rs`, `support/web_bus.rs`):

| File | Tasks, serial |
|---|---|
| `crates/aitm-mcp/src/server.rs` | 1; 5 (doc paragraph on `write_timeout` only); 12 |
| `crates/aitm-mcp/src/lib.rs` | 1 |
| `crates/aitm/src/web/bridge.rs` | 2, 5, 6, 8, 12 |
| `crates/aitm-mcp/src/transport.rs` | 4, 7, 9, 10, 12 |
| `crates/aitm/tests/support/web_bus.rs` | 3 (additive only); 13 (optional, additive only) |
| `crates/aitm/tests/web_bus_write_buffer.rs` (new) | 3, 5, 6 |
| `crates/aitm/tests/web_bus_first_line.rs` (new) | 8 |
| `crates/aitm/tests/web_bus_write_deadline.rs` | 6 (only if G1 is ruled as planned) |
| `crates/aitm/tests/web_bus_governance.rs` | 13 (optional) |

Hard edges: T2, T3 and T9 need T1's `pre_auth_timeout()`. T5 needs T2 (generic `relay`) and T3 (harness). T6 needs T5. T7 needs T4 (generic `serve_connection`). T8 needs T6 (same file) and T7 (`auth_line_limit`). T9 needs T7 (same function). T10 needs T9 (same file). T11 needs all of 1 to 10; T12 needs T11 green or can run beside it only if the Tester is not touching docs (it does not).

## Plan calls

Mine, so the orchestrator can approve or correct them:

1. **Two commits per fix task** (Tasks 5 to 10): a test commit that is expected red on the named assertions, then the fix commit. The orchestrator runs the Terminal-only tests at the test commit to capture RED and at the fix commit for GREEN. The pair is one review unit; the red commit is never pushed alone. Seam and guard tasks (1 to 4) are single commits.
2. **`serve_connection` becomes generic over its two halves**, not over the stream: `LoopbackTcp::serve` still calls `into_split()` (no lock on the hot path) and tests pass `tokio::io::split(duplex)` halves. So AC8 is `[duplex]`; AC7's TCP half still gets one real-loopback test.
3. **`bus_config()`** (a private fn in `bridge.rs`) is the one place the production `WebSocketConfig` is built, used by `run` and by every duplex test, so the tests run `relay` under the production config and the AC11 write-buffer mutation has one line to change.
4. **Each task adds only helpers its own tests use**, because an unused test helper is a `dead_code` warning and clippy runs with `-D warnings`. That is why the flood fixtures arrive in Task 5, not Task 2.
5. **Task 3 creates `web_bus_write_buffer.rs` with the AC5 guard**, so the harness additions have a test of their own (AC5 passes before and after the fix; its job is the AC11 mutation).
6. **The AC7 web test lives in a new file, `web_bus_first_line.rs`**, so it does not share `web_bus_write_buffer.rs` with the Pong tasks.
7. **`test.blob {bytes: N}`** returns `N - 1` bytes of `b` and a final `z` so the last byte is checkable; with no argument it is exactly today's 1 MiB of `b`. `bytes` outside `1..=128 MiB` is an error (a test-support guard).
8. **Socket "accepted bytes"** is counted as completed `feed` calls times 131 (a masked 125-byte Ping is 2 + 4 + 125 bytes). That overstates the kernel's accepted bytes by at most the client's 128 KiB write buffer, which is far inside the 8 MiB bound.
9. **Docs ride in the task that changes the behaviour**; Task 12 is a grep-and-fix sweep for AC12.

## Verification notes for every task

- **Sandbox versus Terminal.** `[duplex]`, unit and lib tests run in the Bash sandbox. Anything that binds loopback (the harness `start`, `LoopbackTcp::bind`) needs the Terminal panel: the sandbox returns `EPERM` on bind. Each task says which of its tests are which. The Coder runs the sandbox tests, writes the Terminal tests, compiles them (`cargo test -p <crate> --no-run`) and says plainly which it could not run. The orchestrator runs the Terminal ones and shows red then green.
- **Git.** No Coder runs git. The orchestrator runs every `git` and `gh` command through the Terminal panel (`run_in_terminal`): `git add` of exactly the task's files, then the commit with the subject line given in the task and the attribution trailer. Pushes are `git push origin <branch>` only (never a bare `git push`). A commit message word that starts with `#` is refused by the Terminal hook, so none of the subjects below contain one.
- **Gate per task:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` on the touched crates (the whole workspace gate runs in Task 11 and 12). If `CARGO_TARGET_DIR` is shared across worktrees, touch the edited sources first so stale artifacts are not reused.
- **Existing-suite constraint (AC13).** `web_bus_roles.rs`, `web_bus_concurrency.rs` and `web_bus_push.rs` pass unmodified and are not edited. `web_bus_write_deadline.rs` passes unmodified except for the one retirement in Task 6 (G1). Harness changes are additive and default to today's behaviour. Regression set run in the Terminal after Tasks 3, 5, 6, 8 and in Task 11: the four named suites plus `web_bus_governance`, `web_bus_ask_split`, `web` (G2) and `cargo test -p aitm-mcp`.
- **Not changed anywhere:** `Cargo.lock`, any `Cargo.toml`, `crates/aitm-core`, `WebSocketConfig` beyond what `bus_config()` already says, `MAX_MESSAGE_BYTES`, the tungstenite versions. No `unsafe`, no counting allocator, no tokio `test-util`.
- **Shared test constants** (used from Task 5 on; each task defines its own copy where it uses them): flood = 64 MiB (`64 << 20`) of Ping frames with 125-byte payloads, 131 bytes each on the wire (client frames are masked; an all-zero mask key is enough). Accepted-bytes bound: 1 MiB over `duplex(4096)`, 8 MiB over real sockets with 4096-byte `SO_RCVBUF` on the client and on the listener and `SO_SNDBUF` 4096 on the listener. Token for bridge tests: 64 hex characters.

## Tasks

### Task 0: rebase, re-check the spec's code references, record drift

- **Satisfies:** none directly; it gates everything.
- **Depends on:** the bus-hardening PR merged to `main`.
- **Parallel with:** nothing.
- **Files:** this plan (the orchestrator fills the drift record below); no source.
- **Who:** the orchestrator, git through the Terminal panel. No Coder.
- **Steps:**
  1. Confirm the bus-hardening PR is on `origin/main` (`git log origin/main --oneline`, look for the merge or squash of branch `claude/vibrant-proskuriakova-e98cfd`). If it is not, stop: nothing here starts.
  2. `git fetch origin`, then rebase this branch onto `origin/main` (or cut `feat/bus-write-buffer-bound` from it).
  3. Check each reference below against the rebased tree and record the result in the drift record.
  3a. **Re-run the PR's AC23 on the rebased tree, unmodified,** in the Terminal: `cargo test -p aitm --test web_bus_write_deadline an_unauthenticated_pinging_peer_is_dropped_at_the_refusal_deadline`. Expected on the tree before this work: green, about 7 s plus the flood. Record the outcome and read the test to answer, in writing: what it discriminates today (a bridge whose bad-token refusal send is unbounded, or bounded by a limit above 5 s, must fail it), and whether that survives Design 1. The analysis in G1 predicts it does not (the pre-auth drain stops the server reading, so the token behind the flood is never read). This step is the baseline; the post-fix run is Task 6 step 0. Do not edit the test here.
  4. **Stop and report, do not improvise, if** any of these is false on `main`: `send_within` and `refuse_unauthorized` exist and are generic over `S: AsyncRead + AsyncWrite + Unpin`; `CLOSE_DRAIN_TIMEOUT` is 5 s and private to `bridge.rs`; `HANDSHAKE_TIMEOUT` is a private 10 s constant read in `relay`; `McpServer` has `write_timeout`/`with_write_timeout` and `serve(self)` destructures and rebuilds every field; `serve_connection` reads the first line with `read_message` and no deadline; `classify_token` exists in both `bridge.rs` (`(first: &str, state: &WebState)`) and `transport.rs` (`(line: &str, agent: &str, operator: Option<&str>)`); `serve_lines` runs teardown as straight-line code after its poll_fn race; `Cargo.lock` still has tungstenite and tokio-tungstenite at 0.28.0 (a newer tokio-tungstenite that exposes `set_config` would reopen Design 2 (a')); `WebSocketConfig` in `run` still sets only `max_message_size` and `max_frame_size`; the web bridge is still the only `/bus` writer of `Message::Ping` handling (no new Ping sender).
- **Drift record** (found while planning against `8db420a`; Task 0 completes it against `main`):

| Where | Spec says / plan assumes | Found | Effect |
|---|---|---|---|
| bus-hardening head | `e35a421` | `8db420a` (= `e35a421`, the round 2 fix `8154e62`, and a merge of `main`) | none on any code reference |
| `bridge.rs` tests | AC22 tests as at `e35a421` | the fill step of `the_bad_token_refusal_gives_up_on_a_peer_whose_send_path_is_full` is wrapped in a 2 s `timeout`; two doc comments re-wrapped | none |
| `support/web_bus.rs` | `Drained { replies, close_code, ended }` | also `saw_close: bool` | additive; Task 6 uses it |
| `web_bus_write_deadline.rs` | five or six socket tests, not described | six, the sixth being the pre-auth Ping flood test (AC23), plus `connect_stopped` split from `open_stopped` | **G1** |
| `web/mod.rs` | not mentioned | module doc gained the shared-governance paragraph | none |
| tests on `main` | four `web_bus_*` suites | also `web_bus_governance.rs`, `web_bus_ask_split.rs` (own rigs) | **G2** |
| AC23 baseline on the rebased tree | (not in the spec) | to be filled by step 3a: outcome, what it discriminates today, and whether that survives Design 1 | **G1** |

- **Done when:** the drift record is complete (including the step 3a finding), the branch is rebased, and the whole workspace builds (`cargo build --all-targets` in the Terminal). If anything in step 4 was false, the report says which and the plan stops here.

### Task 1: pre-auth timeout seam on `McpServer`

- **Satisfies:** AC10 (the `McpServer` clauses)
- **Depends on:** Task 0
- **Parallel with:** Task 4
- **Files:** `crates/aitm-mcp/src/server.rs` (modify), `crates/aitm-mcp/src/lib.rs` (modify, re-export)
- **Change:**
  - `pub const DEFAULT_PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(10);` after `DEFAULT_WRITE_TIMEOUT`, documented: how long a peer may take to present its token after connecting; absolute, so activity cannot extend it; applies to the web bridge and the loopback TCP bus.
  - A `pre_auth_timeout: Duration` field on `McpServer`, defaulted in `McpServer::new`, and carried in **both** the destructure and the rebuilt struct inside `serve(self)` (the trap the write deadline hit; both are compile-enforced).
  - `pub fn with_pre_auth_timeout(mut self, timeout: Duration) -> Self`, storing `timeout.max(Duration::from_millis(1))`.
  - `pub fn pre_auth_timeout(&self) -> Duration`.
  - `lib.rs`: add `DEFAULT_PRE_AUTH_TIMEOUT` to the `pub use server::{..}` list beside `DEFAULT_WRITE_TIMEOUT`.
- **Test** (in `server.rs` `mod tests`, next to the two `write_timeout` tests):
  - `pre_auth_timeout_defaults_to_10_seconds`: `McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio).pre_auth_timeout()` equals `Duration::from_secs(10)`, and `DEFAULT_PRE_AUTH_TIMEOUT` equals `Duration::from_secs(10)`.
  - `with_pre_auth_timeout_sets_it_and_clamps_zero`: `with_pre_auth_timeout(Duration::from_secs(7)).pre_auth_timeout()` equals `Duration::from_secs(7)`; `with_pre_auth_timeout(Duration::ZERO).pre_auth_timeout()` equals `Duration::from_millis(1)`.
- **RED:** a compile error (no such const or methods). This is the seam itself, so a compile-red is the honest red. **GREEN:** both tests pass.
- **Runs:** sandbox (`cargo test -p aitm-mcp --lib`).
- **Commit:** `feat(mcp): add a pre-auth timeout seam on McpServer (bus write-buffer plan task 1)`
- **Done when:** both pass and `cargo fmt --check && cargo clippy -p aitm-mcp --all-targets -- -D warnings && cargo test -p aitm-mcp --lib` is clean.

### Task 2: bridge seams, generic `relay`, pre-auth timeout read from the server

- **Satisfies:** AC10 (the `bridge.rs` clause: no `HANDSHAKE_TIMEOUT` constant); the seam Design 9 requires for AC1, AC2, AC4 and AC6
- **Depends on:** Task 1
- **Parallel with:** Task 3, Task 7 (disjoint files)
- **Files:** `crates/aitm/src/web/bridge.rs` (modify)
- **Change:**
  - `fn bus_config() -> WebSocketConfig`: exactly today's `WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE_BYTES)).max_frame_size(Some(MAX_MESSAGE_BYTES))`. `run` calls it.
  - Make generic over `S: AsyncRead + AsyncWrite + Unpin`: `async fn relay<S>(mut ws: WebSocketStream<S>, state: &WebState) -> anyhow::Result<()>`; `async fn refuse<S>(ws: WebSocketStream<S>, in_flight: FuturesUnordered<FrameTask>, guard: ConnGuard, code: CloseCode, reason: &'static str) -> anyhow::Result<()>`; `async fn close<S>(ws: WebSocketStream<S>, code: CloseCode, reason: &'static str) -> anyhow::Result<()>`. Production instantiates them with `TokioIo<Upgraded>`. Delete `type Ws` (it would be dead).
  - Delete `const HANDSHAKE_TIMEOUT`. At the top of `relay`: read `state.mcp.pre_auth_timeout()` once and use it for the absolute `deadline`. Replace the four doc mentions of `HANDSHAKE_TIMEOUT` (module doc, `CLOSE_DRAIN_TIMEOUT` doc, `refuse_unauthorized` doc) with `McpServer::pre_auth_timeout`. Add a doc comment on `relay` stating the three phases (pre-auth under `pre_auth_timeout`; post-auth sends under `write_timeout`; the refusal and close under `CLOSE_DRAIN_TIMEOUT`).
  - Tests-only fixtures in `mod tests`, used by this task's two tests: `const AGENT_TOKEN: &str` (64 hex characters) and `fn test_state(mcp: McpServer, operator_token: Option<&str>) -> Arc<WebState>`. The server is `McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio)` with the builder under test; `Registry` and `McpTransport` come from `aitm_core`.
- **Test** (in `bridge.rs` `mod tests`; both are guards, green after, compile-red before because `relay` is not generic):
  - `relay_over_a_duplex_authenticates_and_answers_a_request`: `relay` on the server end of `duplex(64 * 1024)` (`WebSocketStream::from_raw_socket(.., Role::Server, Some(bus_config()))`) spawned as a task; the client end is `WebSocketStream::from_raw_socket(.., Role::Client, None)`. The client sends the text frame `{"token":"<AGENT_TOKEN>"}` then the text frame `{"jsonrpc":"2.0","id":7,"method":"ping"}`; within 5 s the next text frame parses to a value with `id == 7` and `result == {}` (the server-handled `ping`).
  - `relay_over_a_duplex_closes_a_silent_peer_at_the_pre_auth_timeout`: server built with `with_pre_auth_timeout(Duration::from_millis(100))`; the client sends nothing and reads; within 2 s the first frame is `Message::Close(Some(frame))` with `frame.code == CloseCode::Policy` and `frame.reason == "authentication timeout"`; the client keeps reading to the end of stream and the `relay` task then returns `Ok(())`. This proves the deadline comes from the server (AC10).
- **AC10 grep:** `rg -n "HANDSHAKE_TIMEOUT" crates/aitm/src/web/bridge.rs` matches nothing.
- **Runs:** all sandbox (`cargo test -p aitm --lib web::bridge`).
- **Commit:** `refactor(web): make the bus relay generic and read the pre-auth timeout from McpServer (bus write-buffer plan task 2)`
- **Done when:** the two tests pass, every pre-existing `bridge.rs` test still passes unchanged (capture `cargo test -p aitm --lib web::bridge -- --list` before editing and compare), the grep matches nothing, and `cargo fmt --check && cargo clippy -p aitm --all-targets -- -D warnings && cargo test -p aitm --lib` is clean.

### Task 3: harness additions and the AC5 guard

- **Satisfies:** AC5; the harness half of Design 9
- **Depends on:** Task 1 (for `with_pre_auth_timeout`)
- **Parallel with:** Task 2, Task 7 (disjoint files)
- **Files:** `crates/aitm/tests/support/web_bus.rs` (modify, **additive only**), `crates/aitm/tests/web_bus_write_buffer.rs` (create)
- **Change (harness, every default reproduces today's behaviour):**
  - `ServerOptions.pre_auth_timeout: Option<Duration>` (applied with `McpServer::with_pre_auth_timeout` when `Some`) and `ServerOptions.recv_buffer: Option<u32>` (the listener's `SO_RCVBUF`), both `None` by default. In `start`, build the listener through `TcpSocket` when either `send_buffer` or `recv_buffer` is `Some`, setting each present size before `bind` and `listen`; otherwise the plain `TcpListener::bind` as today.
  - `BlobCmd` declares an optional `bytes` parameter (`TypeDesc::Int`, `required: false`; the server enforces declared schemas, so an undeclared argument would be refused) and returns `Value::Str` of exactly `bytes` bytes (`bytes - 1` `b` then one `z`) when given, and exactly today's `BLOB_BYTES` of `b` when not. `bytes` outside `1..=128 MiB` is an `Err`. Its description line names the argument.
  - `pub async fn connect_with_recv_buffer(server: &Server, recv_buffer: u32) -> Ws`: a `TcpSocket` with `set_recv_buffer_size` before `connect`, upgraded with `client_async` (the same construction as `connect_stopped` in `web_bus_write_deadline.rs`, which keeps its own private copy).
  - `pub async fn connect_with_config(server: &Server, config: WebSocketConfig) -> Ws`: `connect_async_with_config(request, Some(config), false)`, same `Ws` type.
  - `pub async fn wait_until_no_operator(server: &Server, bound: Duration) -> Probe`: the loop `web_bus_write_deadline.rs` has locally (probe the Ask gate until its text contains `NO_OPERATOR`, panic with the last reason after `bound`).
- **Change (new test file):** `web_bus_write_buffer.rs` includes the module the way the other suites do (`#[path = "support/web_bus.rs"] #[allow(dead_code)] mod web_bus;`) and holds the AC5 test. Tasks 5 and 6 add to it.
- **Test:** `a_legitimate_large_reply_still_goes_through` (`#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`): default `ServerOptions`; `connect_with_config` with `WebSocketConfig::default().max_message_size(Some(128 << 20)).max_frame_size(Some(128 << 20))` (tungstenite's client defaults would reject the reply); `authenticate(ws, AGENT_TOKEN, "agent")`; send `call_line_with(1, "test.blob", json!({"bytes": 27 << 20}))`; read frames with an explicit 60 s bound (not the harness's 10 s helpers) until the text frame with `id == 1` arrives. Assert the frame is at least `2 * (27 << 20)` = 56,623,104 bytes long; `result.isError` is not `true`; `result.structuredContent` is a string of length 28,311,552 ending in `z`. Failure message when the stream ends first: "the connection ended before the 54 MiB reply arrived; a write-buffer cap below a legitimate reply refuses it".
- **RED:** none; it is a guard that passes on the unfixed code and must pass after (its job is the AC11 mutation, `max_write_buffer_size` 16 MiB). **GREEN:** passes. If it fails here, the harness change is wrong, not the bridge.
- **Runs:** `cargo test -p aitm --test web_bus_write_buffer --no-run` in the sandbox; the AC5 test and the regression set in the Terminal (`web_bus_write_deadline`'s `test.blob` test is the proof the 1 MiB default is unchanged).
- **Commit:** `test(web): harness options for the pre-auth timeout and listener receive buffer, test.blob bytes, large-reply guard (bus write-buffer plan task 3)`
- **Done when:** the AC5 test passes in the Terminal; `--list` of `web_bus_roles`, `web_bus_concurrency`, `web_bus_push` and `web_bus_write_deadline` is identical to before; those four pass in the Terminal; `git diff` of the harness shows only added lines or the `start` listener branch; fmt and clippy clean.

### Task 4: `serve_connection` over its halves

- **Satisfies:** the Design 9 seam for AC7 and AC8
- **Depends on:** Task 0
- **Parallel with:** Task 1
- **Files:** `crates/aitm-mcp/src/transport.rs` (modify)
- **Change:**
  - `async fn serve_connection<R, W>(server: Arc<McpServer>, reader: R, mut writer: W, agent_token: &str, operator_token: Option<&str>) -> anyhow::Result<()> where R: AsyncRead + Unpin + Send, W: AsyncWrite + Unpin + Send + 'static`. Same behaviour as today: `BufReader::new(reader).take(MAX_MESSAGE_BYTES as u64)`, `read_message` for the first line, the same refusal, then `serve_lines(server, reader.into_inner(), writer, ConnCtx::new(role))`. `AsyncRead` needs adding to the `tokio::io` imports.
  - `LoopbackTcp::serve` calls `stream.into_split()` and passes the two halves (no `tokio::io::split` lock in production).
  - Test helper in `mod tests`: `struct ConnClient { writer: WriteHalf<DuplexStream>, lines: Lines<BufReader<ReadHalf<DuplexStream>>>, task: JoinHandle<anyhow::Result<()>> }` and `fn serve_connection_over_duplex(server: &Arc<McpServer>, agent: &str, operator: Option<&str>) -> ConnClient` (a `duplex(64 * 1024)`, `tokio::io::split` on the server end, the future spawned). Tasks 7 and 9 reuse it.
- **Test** (guards, compile-red before, green after):
  - `serve_connection_over_a_duplex_answers_an_authenticated_request`: send `{"token":"tok"}` then `{"jsonrpc":"2.0","id":1,"method":"ping"}`; within 5 s the next line parses to `id == 1`, `result == {}`.
  - `serve_connection_over_a_duplex_refuses_a_bad_token_and_closes`: send `{"token":"nope"}`; the next line parses to `id == null`, `error.code == -32001`, `error.message == "unauthorized"`; the next read is end of file (`next_line()` is `Ok(None)`) within 2 s, and the task returns `Ok(())`.
- **Runs:** sandbox.
- **Commit:** `refactor(mcp): serve_connection takes its read and write halves (bus write-buffer plan task 4)`
- **Done when:** both pass, every existing `transport.rs` and `mcp.rs` test still passes (capture `--list` before), and `cargo fmt --check && cargo clippy -p aitm-mcp --all-targets -- -D warnings && cargo test -p aitm-mcp` is clean (the loopback TCP tests in it need the Terminal).

### Task 5: post-auth Pong drain

- **Satisfies:** AC1, AC3(a), AC4 (post-auth, duplex and socket), AC12 (module doc, `relay` doc, the Ping-site comment, `McpServer::write_timeout` doc)
- **Depends on:** Task 2, Task 3
- **Parallel with:** Task 9
- **Files:** `crates/aitm/src/web/bridge.rs` (modify), `crates/aitm/tests/web_bus_write_buffer.rs` (modify), `crates/aitm-mcp/src/server.rs` (modify: the `write_timeout` doc paragraph only)
- **Change:**
  - `async fn flush_within<S>(ws: &mut WebSocketStream<S>, limit: Duration) -> anyhow::Result<()> where S: AsyncRead + AsyncWrite + Unpin` next to `send_within`: `ws.flush()` under `tokio::time::timeout(limit, ..)` (the sink's item type is `Message`, so the call is spelled `SinkExt::<Message>::flush`); expiry is an error whose text contains `timed out after` (same marker as `send_within`); a transport error passes through.
  - In `relay`'s read arm, split `Some(Ok(Message::Ping(_) | Message::Pong(_)))` into `Some(Ok(Message::Ping(_)))`, which awaits `flush_within(&mut ws, write_timeout)` and propagates the error with `?` (no Close attempted; `ConnGuard` runs on return), and `Some(Ok(Message::Pong(_)))`, which keeps the `debug!("websocket ping/pong")`. A comment at the Ping site says why the flush must finish before the next `ws.next()`: tungstenite queues one Pong per Ping read and keeps it in user space while the socket is full, so reading on would let a peer that never reads grow server memory.
  - Docs: the module doc and the new `relay` doc describe the post-auth Pong drain under the write deadline; `McpServer::write_timeout`'s doc says it also bounds the flush of the automatic Pong reply.
  - Test fixtures in `bridge.rs` `mod tests`, used by this task's tests: `fn client_frame(opcode: u8, payload: &[u8]) -> Vec<u8>` (FIN set, masked with an all-zero key, the 7-bit, 16-bit and 64-bit length forms); `fn ping_chunk() -> Vec<u8>` (500 Ping frames of 125-byte payloads, 65,500 bytes); `struct Flood` with `fn accepted(&self) -> usize`, and `fn spawn_flood(writer: WriteHalf<DuplexStream>, total: usize) -> Flood`, which writes `ping_chunk()` repeatedly until at least `total` bytes are written, counting what each `write` call completes (a stalled or failed write stops the count). `FLOOD_BYTES = 64 << 20`.
- **Test** (written first):
  - `bridge.rs`, `relay_ends_an_authenticated_peer_that_floods_pings_and_never_reads` (AC1, sandbox): `relay` on `duplex(4096)` spawned as a task, server `with_write_timeout(Duration::from_millis(100))`; the client writes the token frame (`client_frame(0x1, ..)` of `{"token":"<AGENT_TOKEN>"}`), then `spawn_flood(.., FLOOD_BYTES)`, and keeps **both** client halves alive without reading (dropping the read half would turn the failure into a broken pipe). Within 5 s the `relay` task returns `Err` whose text contains `timed out after`, and `flood.accepted() < 1 << 20`. **RED on unfixed code:** `relay` never returns, so the assertion that fails is "relay must return within 5 s of a 100 ms write deadline" (and had it returned, 64 MiB would show as accepted). **GREEN:** returns in about 100 ms with about 12 KiB accepted (measured shape, E1).
  - `bridge.rs`, `relay_answers_a_reading_clients_keepalive_pings` (AC4 duplex, guard, sandbox, about 3 s): authenticated agent on `duplex(64 * 1024)` with a real client `WebSocketStream`; 30 rounds, 100 ms apart, each sending `Message::Ping` with a distinct 8-byte payload and the request `{"jsonrpc":"2.0","id":<round>,"method":"ping"}`; within 5 s the client has received both a `Message::Pong` with exactly that payload and the text reply with that id. Green before and after.
  - `web_bus_write_buffer.rs`, `a_pinging_operator_that_never_reads_is_disconnected_by_the_write_deadline` (AC3(a), Terminal): `ServerOptions { policy: AgentPolicy::Ask, write_timeout: Some(1 s), send_buffer: Some(4096), recv_buffer: Some(4096), ..default }`; `connect_with_recv_buffer(&server, 4096)`, `authenticate(.., OPERATOR_TOKEN, "operator")`, `subscribe`; then a spawned flood task that takes the `Ws`, `feed`s `PINGS = (64 << 20) / 131` (512,281) `Message::Ping` frames of 125 bytes counting completed feeds times 131, and returns the `Ws` when it finishes or the connection errors; the test never reads meanwhile. Assertions in order: the flood task ends within `1 s + 5 s` ("the flood was still blocked: the server never stopped consuming"); accepted bytes under `8 << 20`; `wait_until_no_operator(&server, 1 s + 5 s)` returns (the `Ask` probe reports `NO_OPERATOR`, so the guard ran and the subscription is gone); then `stream_ends_within(&mut ws, FAST)` is true. **RED on unfixed code:** the flood runs to the end, so the assertion that fails is accepted bytes under 8 MiB (64 MiB shown), and the operator stays subscribed. **GREEN:** the server drops the connection at the write deadline.
  - `web_bus_write_buffer.rs`, `a_reading_client_gets_every_pong_and_every_reply` (AC4 socket, guard, Terminal, about 3 s): `open_agent`; 30 rounds 100 ms apart, each a Ping with a distinct payload and a `call_line(id, "flow.list")`; within 5 s each round receives the Pong with that payload and a reply with that id and `isError == false`. Green before and after.
- **Mutation proof by the Coder** (shown once, then restored): replace the Ping arm's flush with nothing; AC1 and AC3(a) go red as above.
- **Runs:** AC1 and the AC4 duplex test in the sandbox; the two `web_bus_write_buffer.rs` tests in the Terminal (the Coder compiles them with `--no-run` and says it did not run them). Regression set in the Terminal.
- **Commits:** `test(web): Pong flood after authentication, keepalive guards (bus write-buffer plan task 5, red)` then `fix(web): drain each Pong under the write deadline after authentication (bus write-buffer plan task 5)`
- **Done when:** both duplex tests pass in the sandbox, both socket tests pass in the Terminal with the RED run at the first commit shown, the regression set passes, `rg -n "Message::Ping" crates/aitm/src/web/bridge.rs` shows the post-auth arm with its comment, and fmt and clippy are clean.

### Task 6: pre-auth Pong drain, and the AC23 reconciliation (G1)

- **Satisfies:** AC2, AC3(b), AC4 (pre-auth, duplex and socket), AC12 (the second Ping-site comment, the pre-auth wording), AC13 (the G1 edit)
- **Depends on:** Task 5; the orchestrator's ruling on G1
- **Parallel with:** Task 10
- **Files:** `crates/aitm/src/web/bridge.rs` (modify), `crates/aitm/tests/web_bus_write_buffer.rs` (modify), `crates/aitm/tests/web_bus_write_deadline.rs` (modify, G1 only)
- **Step 0 (before any edit to `web_bus_write_deadline.rs`): measure AC23 against the fix.** Apply the pre-auth change below, then run the PR's AC23 test **unmodified** in the Terminal and record in the Task 6 report: pass or fail; if it fails, the panic text and how long it took; if it passes, whether the bad token was ever read (add a temporary `debug!` or `eprintln!` at the refusal branch in `relay`, reverted afterwards) and the mutation result of making the refusal send unbounded (expected: still green, which shows the test no longer discriminates its call site). This is the evidence G1 rests on; if the prediction is wrong in a way that lets the test keep its job (it passes and the refusal is still reached), stop and report, do not retire it.
- **Change:**
  - In `relay`'s token loop, add `Some(Ok(Message::Ping(_)))` before the catch-all `Some(Ok(_)) => continue`: it awaits `flush_within(&mut ws, deadline.saturating_duration_since(tokio::time::Instant::now()))` and returns the error without a Close. The handshake deadline stays absolute, so a flood cannot extend it. A comment at the site gives the same reason as Task 5's. `Pong` and `Frame` keep falling to `continue`.
  - **G1 (as planned):** delete `an_unauthenticated_pinging_peer_is_dropped_at_the_refusal_deadline` from `web_bus_write_deadline.rs` together with the constants and imports only it used (`REFUSAL_DEADLINE`, `REFUSAL_MARGIN`, `PING_PAYLOAD_BYTES`, `PONG_FRAME_BYTES`, `PONG_VOLUME`, `PINGS`, `FLOOD_BOUND`, `BAD_TOKEN`, `drain_until_end`, `Bytes`, `Message`, `SinkExt`), drop its bullet and the AC23 mentions from the module doc, and change the module doc to say the pre-auth Ping flood is now covered by `web_bus_write_buffer.rs` (AC3(b)) and the refusal's call site by `bridge.rs`. Fix the comment that names `HANDSHAKE_TIMEOUT`. No other line of that file changes; the five remaining tests are byte-identical.
  - Test fixtures in `bridge.rs` `mod tests`: `struct WriteStalled<S>(S)`, an `AsyncRead + AsyncWrite` wrapper whose reads pass through and whose `poll_write`, `poll_flush` and `poll_shutdown` return `Poll::Pending` forever (the `StuckFlush` in `transport.rs` tests is the precedent).
- **Test** (written first):
  - `bridge.rs`, `relay_ends_an_unauthenticated_peer_that_floods_pings_and_never_reads` (AC2, sandbox): as Task 5's AC1 but no token is sent and the server is `with_pre_auth_timeout(Duration::from_millis(100))`. Within **3 s** (G4) the `relay` task returns `Err` whose text contains `timed out after`, and accepted bytes are under `1 << 20`. An `Ok(())` fails the test (that is the authentication-timeout Close path). **RED on unfixed code:** the loop `continue`s on every Ping and accepts the flood; the assertion that fails is "relay must return within 3 s of a 100 ms pre-auth timeout" (it ends with `Ok(())` after the 5 s close drain). **GREEN:** `Err` in about 100 ms.
  - `bridge.rs`, `relay_answers_pings_before_the_token_and_then_authenticates` (AC4 duplex pre-auth, guard, sandbox): a client `WebSocketStream` sends five Pings with distinct payloads, reading a `Message::Pong` with exactly each payload before the next; then sends the token frame and `{"jsonrpc":"2.0","id":1,"method":"ping"}` and receives `id == 1`, `result == {}`. Green before and after.
  - `bridge.rs`, `relay_bounds_the_bad_token_refusal_on_a_send_path_that_never_drains` (the AC23 replacement, sandbox, about 5 s): `relay` over `WriteStalled<DuplexStream>` on a server with the default 30 s write timeout and 10 s pre-auth timeout; the client sends a bad token frame. Within 8 s the `relay` task returns `Err` whose text contains `timed out after`, and at least 4 s have elapsed (so the bound that fired is `CLOSE_DRAIN_TIMEOUT`, not an immediate error and not a longer one). Guard on the fixed and unfixed pre-auth drain; **red by mutation** if the call site sends the reply unbounded or under `write_timeout` (the 8 s outer bound fails).
  - `web_bus_write_buffer.rs`, `an_unauthenticated_pinging_peer_is_dropped_at_the_pre_auth_deadline` (AC3(b), Terminal): options as AC3(a) but `pre_auth_timeout: Some(1 s)` and default policy; `connect_with_recv_buffer(&server, 4096)`, no token; the same flood task. Assertions in order: the flood task ends within `1 s + 5 s`; accepted bytes under `8 << 20`; then `drain_until_end(&mut ws, TIMEOUT)` has `ended == true`, `saw_close == false` (the flush-expiry path sends no Close) and no text replies. **RED on unfixed code:** accepted bytes (64 MiB). **GREEN:** the server drops the connection at the 1 s pre-auth deadline.
  - `web_bus_write_buffer.rs`, `pings_before_the_token_are_answered_and_the_token_still_authenticates` (AC4 socket pre-auth, guard, Terminal): `ws_connect`, five Pings each answered by a Pong with its payload, then `authenticate(ws, AGENT_TOKEN, "agent")`. Green before and after.
- **Mutation proof by the Coder** (once, restored): remove the new pre-auth arm; AC2 and AC3(b) go red as above.
- **Runs:** AC2, the AC4 duplex test and the refusal test in the sandbox; the two socket tests, and the `web_bus_write_deadline` regression (five tests, after G1), in the Terminal.
- **Commits:** `test(web): Pong flood before authentication, refusal call-site test, retire the superseded flood test (bus write-buffer plan task 6, red)` then `fix(web): drain each Pong under the pre-auth deadline (bus write-buffer plan task 6)`
- **Done when:** the step 0 findings are recorded; the sandbox tests pass; the Terminal tests pass with the RED run shown; `cargo test -p aitm --test web_bus_write_deadline -- --list` lists exactly the five unchanged names; `web_bus_roles`, `web_bus_concurrency`, `web_bus_push`, `web_bus_governance`, `web_bus_ask_split` and `web` pass; fmt and clippy clean.

### Task 7: first-line bound on the TCP bus

- **Satisfies:** AC6 (the TCP clauses (a), (b), (c), (d)), AC7 (TCP half)
- **Depends on:** Task 4
- **Parallel with:** Task 2, Task 3
- **Files:** `crates/aitm-mcp/src/transport.rs` (modify)
- **Change:**
  - `pub fn auth_line_limit(agent: &str, operator: Option<&str>) -> usize`: `8 * (longest configured token, in bytes) + 256`. Documented: the 8 covers the worst JSON expansion of a byte (`\u00XX`, 6 bytes) with room, the 256 covers `{"token":""}`, whitespace and the line ending; derived from the tokens so a long user-supplied `--token` is never locked out; shared with the web bridge.
  - `enum LineRead { Eof, Line, TooLong }` (private; derives `Debug`, `PartialEq`, `Eq`) and `async fn read_line_within<R: AsyncBufRead + Unpin>(reader: &mut Take<R>, buf: &mut String, limit: usize) -> io::Result<LineRead>`: clears `buf`, sets the take limit to `limit`, `read_line`; `Eof` when nothing was read, `TooLong` when the line did not end in `\n` and the limit was exhausted, `Line` otherwise. It never puts more than `limit` bytes in `buf`.
  - `read_message(reader: &mut Take<R>, buf: &mut String) -> anyhow::Result<bool>` keeps its signature and every behaviour (including the text `message exceeds {MAX_MESSAGE_BYTES} bytes`) as a thin wrapper over `read_line_within` with `MAX_MESSAGE_BYTES`.
  - `classify_token(line, agent, operator)`: a trimmed line longer than `auth_line_limit(agent, operator)` is `None` before any parse. Update its doc.
  - `serve_connection`: read the first line with `read_line_within(&mut reader, &mut first, auth_line_limit(agent_token, operator_token) + 2)` (the line, `\r`, `\n`); `Eof` returns `Ok(())`; `TooLong` and a `None` classification share the existing `unauthorized` refusal and shutdown. Never log the line.
- **Test** (written first, in `transport.rs` `mod tests`):
  - `classify_token_refuses_a_padded_token_line_unparsed` (AC6(a), sandbox): agent token of 64 hex characters; the line `{"token":"<token>"` followed by 5,000 spaces then `}` returns `None`. **RED today:** it returns `Some(Frontend::Mcp)` (it parses to a valid token); this compiles against today's signature. **GREEN:** `None`.
  - `classify_token_accepts_every_shape_the_clients_send` (AC6(b), sandbox, guard): for the agent token and for the operator token (agent `d`x64, operator `e`x64), `{"token":"<t>"}`, `{"token": "<t>"}`, and each of those with leading and trailing spaces and `\r\n`, classify to `Frontend::Mcp` and `Frontend::Operator` respectively; and a 40-byte token of `"\u{1}".repeat(40)`, whose compact JSON line is asserted to be exactly 252 bytes first, classifies to its role. Green before and after.
  - `auth_line_limit_is_eight_times_the_longest_token_plus_256` (AC6(c), sandbox): two 64-character tokens give exactly 768; `("tok", None)` gives 280; a 1,000-byte token gives 8,256. Compile-red today.
  - `read_line_within_never_buffers_more_than_limit_plus_two` (AC6(d), sandbox): over `BufReader::new(&[b'a'; 1 << 20][..]).take(0)` with limit 770, the result is `Ok(LineRead::TooLong)` and `buf.len() == 770` (G3). Compile-red today.
  - `serve_connection_refuses_an_oversized_first_line_without_reading_it_all` (sandbox, duplex through Task 4's helper): the client writes 1 MiB with no newline (ignoring the write error once the server has refused), then reads one line parsing to `error.code == -32001`, then end of file, within 2 s. **RED today:** the server keeps reading toward 16 MiB and the read of the refusal times out.
  - `a_padded_first_line_is_refused_over_tcp` and `the_accepted_first_line_shapes_authenticate_over_tcp` (AC7 TCP, Terminal): `LoopbackTcp::bind(0, "tok".into(), None)` with `.with_operator_token(Some("op".into()))`, `serve` spawned, a plain `TcpStream` client. Padded: `{"token":"tok"` + 5,000 spaces + `}` then `\n` gets one `unauthorized` line and end of stream; **RED today:** it authenticates and the refusal read times out at 2 s. Shapes: each AC6(b) shape for both tokens authenticates (`initialize` replies with `role` `agent` or `operator`; the existing tests show how a reply is read).
- **Runs:** all but the last two in the sandbox; the last two in the Terminal.
- **Commits:** `test(mcp): first-line bound on the TCP bus (bus write-buffer plan task 7, red)` then `fix(mcp): refuse a pre-auth first line over the derived bound before parsing it (bus write-buffer plan task 7)`
- **Done when:** the sandbox tests pass, the Terminal pair passes with RED shown, every existing `transport.rs` and `mcp.rs` test passes, `rg -n "read_message" crates/aitm-mcp/src/transport.rs` shows it used only by `read_loop`, and fmt and clippy are clean.

### Task 8: first-line bound on the web bridge

- **Satisfies:** AC6 (the web clauses (a), (b)), AC7 (web half)
- **Depends on:** Task 6 (same file), Task 7 (`auth_line_limit`)
- **Parallel with:** nothing
- **Files:** `crates/aitm/src/web/bridge.rs` (modify), `crates/aitm/tests/web_bus_first_line.rs` (create)
- **Change:**
  - `bridge.rs` imports `aitm_mcp::transport::auth_line_limit`. `classify_token(first: &str, state: &WebState) -> Option<Frontend>` returns `None` first thing when `first.len() > auth_line_limit(&state.agent_token, state.operator_token.as_deref())`, before either `token_line_matches` call, so `relay`'s existing bad-token branch (`refuse_unauthorized`) runs. `lines_of` has already trimmed the line. Update the doc: over-limit is refused, never truncated, and the library has already received the frame (the residual in Design 3).
  - New test file `web_bus_first_line.rs` (includes the harness like the others); it holds a local `async fn authenticate_line(ws: Ws, line: &str, role: &str) -> Ws` that sends a given first line, then `initialize`, and checks the role echo.
- **Test** (written first):
  - `bridge.rs`, `classify_token_refuses_a_padded_token_line_unparsed` (AC6(a), sandbox): `test_state` with a 64-hex agent token; `{"token":"<token>"` + 5,000 spaces + `}` returns `None`. **RED today:** `Some(Frontend::Mcp)`. This task adds `const OPERATOR_TOKEN: &str` to the fixtures.
  - `bridge.rs`, `classify_token_accepts_every_shape_the_clients_send` (AC6(b), sandbox, guard): the compact and spaced shapes for the agent and the operator token resolve to `Frontend::Mcp` and `Frontend::Operator` (the line is passed as `lines_of` hands it over, trimmed; leading and trailing spaces and `\r\n` are covered on the wire below), and the 252-byte control-character token resolves to its role.
  - `web_bus_first_line.rs`, `a_padded_first_line_is_refused_and_the_connection_closed` (AC7 web, Terminal): `ws_connect`, send the padded line as one text frame; `drain_until_end(&mut ws, FAST)` has `replies[0]` containing `"code":-32001`, `close_code == Some(CloseCode::Policy)` and `ended == true`. **RED today:** it authenticates, nothing is sent back, and `ended` is false after `FAST`.
  - `web_bus_first_line.rs`, `the_accepted_first_line_shapes_authenticate_as_agent_and_operator` (AC7 web, guard, Terminal): each shape (compact, spaced, with leading and trailing spaces, with `\r\n`) for both tokens authenticates with the right role echo. Green before and after.
- **Runs:** the two unit tests in the sandbox; the two socket tests in the Terminal.
- **Commits:** `test(web): first-line bound on the web bridge (bus write-buffer plan task 8, red)` then `fix(web): refuse a pre-auth first line over the derived bound before parsing it (bus write-buffer plan task 8)`
- **Done when:** the unit tests pass, the socket tests pass in the Terminal with RED shown, the regression set passes, fmt and clippy clean.

### Task 9: pre-auth deadline on the TCP bus

- **Satisfies:** AC8, AC10 (AC8's tests reach the deadline only through `with_pre_auth_timeout`)
- **Depends on:** Task 7, Task 1
- **Parallel with:** Task 5
- **Files:** `crates/aitm-mcp/src/transport.rs` (modify)
- **Change:** in `serve_connection`, wrap the whole first-line read in `tokio::time::timeout(server.pre_auth_timeout(), ..)`. The budget is absolute, so a peer that drips one byte at a time cannot extend it. Expiry returns an error (text names the timeout; never a token or a line) without writing a reply and drops the connection, which the accept loop already logs at debug; the deadline covers only the first line. Test helper: `fn server_with_pre_auth(timeout: Duration) -> Arc<McpServer>`.
- **Test** (written first; sandbox, duplex through Task 4's helper; each uses `with_pre_auth_timeout(Duration::from_millis(100))`):
  - `a_silent_connection_is_dropped_at_the_pre_auth_deadline` (AC8(a)): the client sends nothing; a read returns `Ok(0)` (end of file) within 100 ms + 2 s. **RED today:** the connection stays open and the read bound fails: "the connection must reach end of file within 2.1 s".
  - `a_dripping_connection_is_dropped_at_the_same_deadline` (AC8(b)): the client writes one byte every 20 ms with no newline, for up to 2 s; end of file arrives in under 1 s from the start (activity does not extend the deadline). **RED today:** same.
  - `an_authenticated_idle_connection_is_not_timed` (AC8(c), guard): a valid `{"token":"tok"}` sent at 50 ms; then a `ping` request answered; 300 ms later the task is not finished and a second `ping` request is answered (the deadline is pre-auth only). Green before and after.
- **Runs:** all sandbox.
- **Commits:** `test(mcp): pre-auth deadline on the TCP bus (bus write-buffer plan task 9, red)` then `fix(mcp): end the TCP bus first-line read at the pre-auth deadline (bus write-buffer plan task 9)`
- **Done when:** the three pass, the Task 7 and Task 4 tests still pass, fmt and clippy clean, `cargo test -p aitm-mcp` clean (loopback tests in the Terminal).

### Task 10: `serve_lines` tears down on cancellation

- **Satisfies:** AC9, AC12 (the `serve_lines` doc)
- **Depends on:** Task 9 (same file)
- **Parallel with:** Task 6
- **Files:** `crates/aitm-mcp/src/transport.rs` (modify)
- **Change:** a private `struct ConnTeardown { server: Arc<McpServer>, conn_id: u64, sink: NotificationSink }` whose `Drop` does exactly the two calls teardown makes today, in the same order: `sink.close()` then `server.drop_connection(conn_id)`. `serve_lines` creates it once `conn_id` is known and drops it explicitly at today's teardown point (replacing the two straight-line calls), so the order relative to joining the writer is unchanged. If the future is dropped or unwinds earlier, `Drop` runs the same two calls; the writer, seeing its sink closed, drains and exits and releases the socket half. The `serve_lines` doc says teardown runs on cancellation too.
- **Test** (written first): `a_cancelled_serve_lines_tears_the_connection_down` (AC9, sandbox, in `mod tests`): `serve_over_tiny_pipe(&server, NotificationSink::new(64))`, `client.subscribe().await`, then `client.task.abort()` and await the join (it resolves to a cancelled `JoinError`). Assertions in order: `client.sink.is_closed()` is true; after `push_padded(&server, 1)` the client's next read, bounded at 2 s, is end of file (`next_line()` is `Ok(None)`), never the pushed line. The client keeps reading so the writer is idle, not parked in a write. **RED today:** the sink stays open (the first assertion fails: "the sink must be closed when the connection's future is dropped"); the subscription still feeds it and the pushed line arrives. **GREEN:** closed, end of file.
- **Runs:** sandbox.
- **Commits:** `test(mcp): serve_lines teardown on cancellation (bus write-buffer plan task 10, red)` then `fix(mcp): tear a connection down when serve_lines is dropped (bus write-buffer plan task 10)`
- **Done when:** the test passes, the existing teardown tests (`a_stopped_line_reader_ends_the_connection_after_the_write_deadline`, `a_panicking_writer_ends_the_connection` and the rest of the `serve_lines` set) still pass, fmt and clippy clean.

### Task 11: the Tester's pass, mutation checks and AC13

- **Satisfies:** AC11, AC13
- **Depends on:** Tasks 1 to 10
- **Parallel with:** Task 12 only if the Tester touches no production file (it does not)
- **Files:** tests only (it may strengthen a weak test); a report with quoted output. No production edit; no spec edit.
- **Who:** the Tester. Bash sandbox for unit and duplex mutations; the Terminal panel (through the orchestrator) for socket ones.
- **Change:** run each mutation **once, one at a time**, record red then green, restore, and confirm the failing assertion is the stated one and not a compile or connect error:

| # | Mutation | Must go red | Failing assertion |
|---|---|---|---|
| 1 | In `relay`'s read arm, remove the Ping arm's `flush_within` (log only) | AC1 `relay_ends_an_authenticated_peer_that_floods_pings_and_never_reads`; AC3(a) `a_pinging_operator_that_never_reads_is_disconnected_by_the_write_deadline` | AC1: "relay must return within 5 s"; AC3(a): accepted bytes under 8 MiB |
| 2 | In the token loop, remove the pre-auth Ping arm's `flush_within` (`continue` again) | AC2; AC3(b) | AC2: "relay must return within 3 s"; AC3(b): accepted bytes under 8 MiB |
| 3a | Delete the length guard in `bridge.rs` `classify_token` | AC6(a) web; AC7 web `a_padded_first_line_is_refused_and_the_connection_closed` | `None` expected; `ended` expected |
| 3b | Delete the trimmed-length check in `transport.rs` `classify_token` | AC6(a) TCP | `None` expected. AC7 TCP stays green here by design: the bounded reader still refuses the padded line |
| 3c | Make `serve_connection` read its first line with `read_message` (the 16 MiB bound) again | `serve_connection_refuses_an_oversized_first_line_without_reading_it_all` | the refusal line is expected within 2 s |
| 3d | Do both 3b and 3c | AC7 TCP `a_padded_first_line_is_refused_over_tcp` | the `unauthorized` line is expected |
| 4 | Delete the `timeout` around the TCP first-line read | AC8(a), AC8(b) | end of file within 2.1 s / 1 s |
| 5 | Replace `ConnTeardown` with the straight-line teardown | AC9 | `sink.is_closed()` expected |
| 6 | In `bus_config()` add `.max_write_buffer_size(16 << 20)` (above `write_buffer_size`; below that panics) | AC5 `a_legitimate_large_reply_still_goes_through` | "the connection ended before the 54 MiB reply arrived". To show the cause is `WriteBufferFull`, temporarily print the error in `run`'s `debug!("websocket bridge ended with an error")` branch for this one run and quote "Write buffer is full" (the harness installs no tracing subscriber); revert it with the mutation. **This mutation does not interact with the refusal tests:** the bad-token refusal reply is under 100 bytes, far below a 16 MiB cap, so a `WriteBufferFull` cannot make the refusal send fail at once and blunt them (a cap that small is not what is mutated, and the design adds no cap). The Tester confirms it by running `relay_bounds_the_bad_token_refusal_on_a_send_path_that_never_drains` and the `bridge.rs` AC22 tests under this mutation and recording that they stay green; AC23 is not a discriminator of this feature (G1) |

  The Tester also runs the AC13 checks: `git diff <base>..HEAD -- Cargo.lock` is empty; `rg -n "unsafe" ` over the diff finds nothing added; `git diff --stat <base>..HEAD -- crates/aitm-core` is empty; `git diff <base>..HEAD --stat -- crates/aitm/tests/web_bus_roles.rs crates/aitm/tests/web_bus_concurrency.rs crates/aitm/tests/web_bus_push.rs` is empty; `web_bus_write_deadline.rs`'s diff is exactly the G1 change; the harness diff is additive; the Task 2 and Task 3 `--list` captures match. Then the full gate over the workspace: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` (sandbox for what binds nothing; the rest in the Terminal), and the regression set.
- **Done when:** the report has six red-then-green rows with the failing assertions quoted, every AC13 check with its output, the full gate output, and an AC to test map with no unmapped criterion.

### Task 12: docs sweep (AC12)

- **Satisfies:** AC12
- **Depends on:** Tasks 2, 5, 6, 10 (their own docs), Task 11
- **Parallel with:** nothing (it edits the three hot files' doc comments)
- **Files:** doc comments in `crates/aitm/src/web/bridge.rs`, `crates/aitm-mcp/src/transport.rs`, `crates/aitm-mcp/src/server.rs`; nothing else
- **Change:** a grep-and-fix sweep, no behaviour change, for what the tasks left stale:
  - `bridge.rs`: the module doc and `relay`'s doc describe the Pong drain (post-auth under the write deadline, pre-auth under the time left to the pre-auth deadline), the three phases and their budgets, and name no `HANDSHAKE_TIMEOUT`; the comment at each of the two Ping sites says why the flush must finish before the next `ws.next()`.
  - `server.rs`: `McpServer::write_timeout`'s doc says it also bounds the Pong flush; `pre_auth_timeout`'s doc matches what both transports do now (web token wait and each Pong flush before the token; TCP first-line read).
  - `transport.rs`: the `serve_lines` doc says teardown runs on cancellation; the module doc and `LoopbackTcp` doc mention the first-line bound and the deadline.
- **Test:** `rg -n "HANDSHAKE_TIMEOUT" crates/aitm/src` matches nothing; `rg -n "flush_within" crates/aitm/src/web/bridge.rs` shows the helper and both sites; the AC12 bullets are checked by the reviewers (they are review-checked, not machine-enforced).
- **Done when:** the greps hold, fmt and clippy clean, and the workspace gate passes (the Terminal for loopback tests).

### Task 13 (optional, outside the acceptance criteria): fold `web_bus_governance.rs` onto the shared harness

- **Satisfies:** no acceptance criterion. Cleanup the starting session offered; it is taken only if it fits cheaply, and skipping it is not a defect. Record "not done" in Shipped if skipped.
- **Depends on:** Tasks 1 to 12 (it edits the shared harness, so it must come after every task that does, and the whole branch should be green first)
- **Parallel with:** nothing
- **Files:** `crates/aitm/tests/support/web_bus.rs` (modify, additive only), `crates/aitm/tests/web_bus_governance.rs` (modify)
- **Scope finding (so nobody over-reads the offer):** only `web_bus_governance.rs` carries its own copy of the websocket helpers (`Server`, `start`, `ws_connect`, `send_text`, `next_frame`, `try_recv_until`, `recv_until`, `drain_for`, `call_line_with`, `open_bus`, `open_agent`, `open_operator`, about 280 lines). `web_bus_ask_split.rs` has no websocket at all: it is a synchronous in-process rig over `McpServer` and `NotificationSink`, so there is nothing to convert and it stays as is. Governance is not a drop-in either, for two reasons: it builds its server through `aitm::tui::services`, `tui::server` and `tui::with_shared_governance` rather than the harness's `McpServer::new(..).with_services(..)`; and the `with_shared_governance` line carries a `MUTATION-POINT` marker that the governance spec's own AC12 mutation check depends on, so it must stay a single, findable line.
- **Change (only if it needs no more than this):** one additive `ServerOptions` field (for example `shared_governance: bool`, default `false`) that makes `start` build the bridge's `McpServer` through the `tui` path as governance does, keeping the `MUTATION-POINT` comment on the `with_shared_governance` line; `web_bus_governance.rs` then includes the module, keeps thin local wrappers with its current signatures (`start(tag, policy) -> Server`, its tokens and `QUIET` of 300 ms stay file-local if the shared ones differ), and deletes the duplicated helpers. No test body changes.
- **Test:** no red phase (refactor). Before editing, save `cargo test -p aitm --test web_bus_governance -- --list`; after, the names are identical and every test body is byte-identical from the first test to end of file; the suite passes in the Terminal; deleting the `with_shared_governance` line (its own mutation) still turns it red.
- **Skip if:** it needs a second harness field, touches any test body, moves or reworded the `MUTATION-POINT` line, or changes a default the other suites rely on. Stop and report instead of improvising.
- **Runs:** Terminal for the suite; sandbox for `--no-run` and clippy.
- **Commit:** `test(web): run the governance suite on the shared bus harness (bus write-buffer plan task 13)`
- **Done when:** as above, the regression set passes, fmt and clippy are clean.

## Acceptance criteria coverage

| AC | Task | Test (file, name) |
|---|---|---|
| AC1 | 5 | `bridge.rs` `relay_ends_an_authenticated_peer_that_floods_pings_and_never_reads` (duplex) |
| AC2 | 6 | `bridge.rs` `relay_ends_an_unauthenticated_peer_that_floods_pings_and_never_reads` (duplex, 3 s bound, G4) |
| AC3 | 5 (a), 6 (b) | `web_bus_write_buffer.rs` `a_pinging_operator_that_never_reads_is_disconnected_by_the_write_deadline`, `an_unauthenticated_pinging_peer_is_dropped_at_the_pre_auth_deadline` (socket) |
| AC4 | 5 (post-auth), 6 (pre-auth) | duplex: `bridge.rs` `relay_answers_a_reading_clients_keepalive_pings`, `relay_answers_pings_before_the_token_and_then_authenticates`; socket: `web_bus_write_buffer.rs` `a_reading_client_gets_every_pong_and_every_reply`, `pings_before_the_token_are_answered_and_the_token_still_authenticates` |
| AC5 | 3 (mutation in 11) | `web_bus_write_buffer.rs` `a_legitimate_large_reply_still_goes_through` (socket) |
| AC6 | 7 (TCP (a) to (d)), 8 (web (a), (b)) | `transport.rs` `classify_token_refuses_a_padded_token_line_unparsed`, `classify_token_accepts_every_shape_the_clients_send`, `auth_line_limit_is_eight_times_the_longest_token_plus_256`, `read_line_within_never_buffers_more_than_limit_plus_two`; `bridge.rs` `classify_token_refuses_a_padded_token_line_unparsed`, `classify_token_accepts_every_shape_the_clients_send` |
| AC7 | 7 (TCP), 8 (web) | `transport.rs` `a_padded_first_line_is_refused_over_tcp`, `the_accepted_first_line_shapes_authenticate_over_tcp` (and the duplex `serve_connection_refuses_an_oversized_first_line_without_reading_it_all`); `web_bus_first_line.rs` `a_padded_first_line_is_refused_and_the_connection_closed`, `the_accepted_first_line_shapes_authenticate_as_agent_and_operator` |
| AC8 | 9 | `transport.rs` `a_silent_connection_is_dropped_at_the_pre_auth_deadline`, `a_dripping_connection_is_dropped_at_the_same_deadline`, `an_authenticated_idle_connection_is_not_timed` (duplex, via Task 4) |
| AC9 | 10 | `transport.rs` `a_cancelled_serve_lines_tears_the_connection_down` (duplex) |
| AC10 | 1, 2 (9 and 6 use it) | `server.rs` `pre_auth_timeout_defaults_to_10_seconds`, `with_pre_auth_timeout_sets_it_and_clamps_zero`; `bridge.rs` `relay_over_a_duplex_closes_a_silent_peer_at_the_pre_auth_timeout`; grep for `HANDSHAKE_TIMEOUT` |
| AC11 | 11 | the six mutations in the Task 11 table, recorded red then green |
| AC12 | 2, 5, 6, 10 (own docs), 12 (sweep) | review-checked; the greps in Task 12 |
| AC13 | 11, and the gate in every task | Task 11's checks; existing suites unmodified except the G1 retirement |

AC1 to AC13 are all mapped; no criterion is covered only by review except AC12 (review-checked by the spec's own wording). Task 13 maps to no criterion on purpose.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
