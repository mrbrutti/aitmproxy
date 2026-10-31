# aitm web startup/UX hygiene implementation plan

**Status:** Approved (self-approved by orchestrator under Matt's autonomous-approve mode) 2026-10-30
**Spec:** `docs/superpowers/specs/2026-10-30-aitm-web-startup-hygiene-design.md`
**Branch / worktree:** `feat/aitm-web-startup-hygiene`

## Overview

Four tasks. Three run fully in parallel; two of them share files and must be
ordered within their track:

- **Track A — Task 1** (obscura reap): `crates/aitm-browser/*`. Independent.
- **Track B — Task 4** (web client): `apps/web/src/*`. Independent.
- **Track C — Task 2 then Task 3**: both touch `crates/aitm/src/main.rs` and
  `crates/aitm/src/web/mod.rs`, so run **Task 2 first, then Task 3** (Task 3 also
  touches `crates/aitm/src/web/bridge.rs`). Not disjoint from each other.

Tasks 1 and 4 are disjoint from everything and from each other (safe to fan
out). Every task is TDD: write the failing test, watch it fail, implement,
watch it pass, then run the full gate. The sandbox cannot bind ports; all tests
here are hermetic. Live `aitm web` confirmation is the orchestrator's, in the
Terminal panel, after merge-readiness.

## Tasks

### Task 1: Safely reap stale obscura run dirs

- **Satisfies:** AC1, AC2 (and contributes to AC7).
- **Depends on:** none. **Independent** (disjoint files from all other tasks).
- **Files:**
  - `crates/aitm-browser/src/obscura.rs` (modify)
  - `crates/aitm-browser/Cargo.toml` (modify)
- **Change:**
  - Replace `fn warn_stale_run_dirs()` with:
    - `fn reap_stale_run_dirs_in(base: &Path, is_alive: impl Fn(u32) -> bool) -> usize`
      — scan `base`; for each entry whose name starts with `RUN_DIR_PREFIX` and
      `entry.path().is_dir()`, parse the pid (integer between `aitm-obscura-` and
      the next `-`); if it parses and `!is_alive(pid)`, call `remove_run_dir()`
      and count it. Return the count. No logging.
    - `fn reap_stale_run_dirs()` — call
      `reap_stale_run_dirs_in(&std::env::temp_dir(), pid_is_alive)`; when the
      returned `n > 0`, emit exactly one `info!(removed = n, …)`; otherwise
      silent/`debug!`.
    - `fn pid_is_alive(pid: u32) -> bool` — `#[cfg(unix)]`:
      `nix::sys::signal::kill(Pid::from_raw(pid as i32), None)`; `true` on `Ok`,
      `false` only on `Err(Errno::ESRCH)`, `true` on any other `Err` (`EPERM` etc).
      `#[cfg(not(unix))]`: returns `true`. No local `unsafe` (`nix` wraps the libc
      call), so the crate keeps the workspace `unsafe_code = "forbid"`.
  - Update the call site in `ObscuraProcess::start()`: `warn_stale_run_dirs();` →
    `reap_stale_run_dirs();`.
  - `Cargo.toml`: add `[target.'cfg(unix)'.dependencies]` /
    `nix = { version = "0.29", features = ["signal"] }`; keep `[lints] workspace = true`.
- **Test:** `reap_removes_only_provably_dead_dirs` (new, in the `obscura` tests
  module). Build a temp base dir; create subdirs `aitm-obscura-111-aaa`,
  `aitm-obscura-222-bbb`, a non-matching dir `not-ours`, and a matching **file**
  `aitm-obscura-333-ccc`. Call
  `reap_stale_run_dirs_in(&base, |pid| pid == 222)`. Assert: return value is
  `1`; `aitm-obscura-111-aaa` no longer exists; `aitm-obscura-222-bbb`, `not-ours`,
  and the file `aitm-obscura-333-ccc` all still exist. Keep
  `run_dir_is_private_and_unpredictable` passing.
- **Done when:** the test passes and the full Rust gate passes.

### Task 2: Clean, prominent `aitm web` startup summary

- **Satisfies:** AC3 (and contributes to AC7).
- **Depends on:** none to start; **shares files with Task 3** (run Task 2 first).
- **Files:**
  - `crates/aitm/src/web/mod.rs` (modify: add `startup_summary` + test)
  - `crates/aitm/src/main.rs` (modify: web arm print site)
- **Change:**
  - In `web/mod.rs`, add
    `pub fn startup_summary(web_url: &str, operator_url: Option<&str>, proxy: SocketAddr, browser: SocketAddr, bus: &str) -> String`
    returning one labelled multi-line block: Web UI URL (`web_url`, token
    included), Operator URL line only when `operator_url` is `Some`, proxy addr,
    browser/obscura addr (labelled SSRF-filtered), and bus state (`bus`).
  - Keep `web::log_listening(bound)` unchanged.
  - In `main.rs`, before the `web_server` match block, capture
    `let proxy_addr = proxy_listener.local_addr()?;` and
    `let browser_addr = browser_listener.local_addr()?;`. In the `Some(settings),
    Some(listener)` arm, build
    `let operator_url = operator_token.as_ref().map(|op| web::operator_ui_url(bound, op));`
    and replace the two bare `println!` lines (agent + operator) with
    `println!("{}", web::startup_summary(&url, operator_url.as_deref(), proxy_addr, browser_addr, "ready"));`.
- **Test:** `startup_summary_lists_every_endpoint` (new, in `web/mod.rs` tests).
  - With operator `Some`: call
    `startup_summary("http://127.0.0.1:8082/#t=deadbeef", Some("http://127.0.0.1:8082/#t=optok&expect=operator"), "127.0.0.1:8080".parse().unwrap(), "127.0.0.1:8081".parse().unwrap(), "ready")`;
    assert the result contains each of `"http://127.0.0.1:8082/#t=deadbeef"`,
    `"127.0.0.1:8080"`, `"127.0.0.1:8081"`, `"ready"`, and
    `"http://127.0.0.1:8082/#t=optok&expect=operator"`.
  - With operator `None`: call the same with `None`; assert the result contains
    the web URL, proxy addr, browser addr, and does **not** contain
    `"expect=operator"`.
  - Keep `log_listening_never_carries_the_token` passing (token out of tracing).
- **Done when:** both tests pass and the full Rust gate passes.

### Task 3: Rate-limit the bad-token refusal warn

- **Satisfies:** AC6 (and contributes to AC7).
- **Depends on:** **Task 2** (shares `crates/aitm/src/main.rs` and
  `crates/aitm/src/web/mod.rs`; rebase on Task 2's commit). Also touches
  `bridge.rs` (disjoint from Task 2).
- **Files:**
  - `crates/aitm/src/web/bridge.rs` (modify: add `BadTokenThrottle` + test, use
    it at the refusal site)
  - `crates/aitm/src/web/mod.rs` (modify: add `WebState` field)
  - `crates/aitm/src/main.rs` (modify: construct the field in the `WebState`
    literal)
- **Change:**
  - In `bridge.rs`: `pub const BAD_TOKEN_WINDOW: Duration = Duration::from_secs(60);`;
    `#[derive(Default)] pub struct BadTokenThrottle` over a `std::sync::Mutex` of
    `{ pending: u64, window_start: Option<std::time::Instant> }`; and
    `pub fn record(&self, now: std::time::Instant) -> Option<u64>` with the
    window semantics from spec D3 (`saturating_duration_since`, emit on
    first-ever and first-after-window, reset `pending` and `window_start` on
    emit).
  - At the refusal site in `relay()`, replace
    `warn!("web bus: refused a connection with a bad token");` with
    `if let Some(n) = state.bad_token_throttle.record(std::time::Instant::now()) { warn!(refusals = n, "web bus: refused connections with a bad token (suppressing repeats)"); }`.
    Leave the `UNAUTHORIZED_REPLY` send and `close(ws, CloseCode::Policy, …)`
    unchanged.
  - In `web/mod.rs`, add `pub bad_token_throttle: bridge::BadTokenThrottle` to
    `WebState`.
  - In `main.rs`, add `bad_token_throttle: Default::default(),` to the existing
    `WebState { … }` literal.
- **Test:** `bad_token_throttle_emits_then_suppresses_until_the_window` (new, in
  `bridge.rs` tests). With `let t = BadTokenThrottle::default(); let t0 = std::time::Instant::now();`
  assert: `t.record(t0) == Some(1)`; `t.record(t0 + Duration::from_secs(1)) == None`;
  `t.record(t0 + Duration::from_secs(2)) == None`;
  `t.record(t0 + Duration::from_secs(61)) == Some(3)`.
- **Done when:** the test passes and the full Rust gate passes.

### Task 4: Client stops hammering on a stale token and surfaces it

- **Satisfies:** AC4, AC5 (and contributes to AC7).
- **Depends on:** none. **Independent** (disjoint files from all other tasks).
- **Files:**
  - `apps/web/src/bus/types.ts` (modify: `BusState`)
  - `apps/web/src/bus/ws.ts` (modify: auth-failure handling)
  - `apps/web/src/shell/StatusBar.tsx` (modify: hue + label for `'unauthorized'`)
  - `apps/web/src/bus/ws.test.ts` (modify: add three cases)
- **Change:**
  - `types.ts`: add `'unauthorized'` to `BusState`.
  - `ws.ts`: add `let authFailed = false;`, const
    `UNAUTHORIZED_MESSAGE = "token expired — reopen the URL printed by \`aitm web\`"`,
    and `markAuthFailed()` (sets `authFailed`, state `'unauthorized'`, `lastError`
    to the message, `failAllPending`, `settleReady`). In `onMessage`, add a branch
    before the numeric-id branch: `(msg.id === null || msg.id === undefined) &&
    msg.error?.code === -32001 → markAuthFailed(); continue;`. In `onclose`, call
    `markAuthFailed()` when `ev.code === 1008`. Guard `scheduleReconnect()` with
    `if (closedByUser || authFailed) return;`. Guard the `onopen` catch with
    `if (authFailed) return;`. Reset `authFailed = false` in `connect()`.
  - `StatusBar.tsx`: `busHue()` maps `'unauthorized'` → `'server-error'`; show a
    short `bus token expired` label when `state() === 'unauthorized'` (full
    message stays in the existing `title` tooltip from `lastError`).
- **Test:** add to `ws.test.ts` a `describe('createWsBus auth failure')` block:
  1. `a_1008_close_stops_reconnecting`: connect, `sock.onopen?.()`, then
     `sock.onclose?.({ code: 1008 })`; assert `client.state() === 'unauthorized'`,
     `client.lastError()` contains `"reopen"`, and after a short sleep
     `FakeWebSocket.count === 1`.
  2. `a_minus32001_reply_stops_reconnecting`: connect, `sock.onopen?.()`, deliver
     `{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"unauthorized"}}`
     via `sock.onmessage`; assert state `'unauthorized'` and
     `FakeWebSocket.count === 1` after a short sleep.
  3. `a_1006_close_still_reconnects`: connect, `sock.onopen?.()`,
     `sock.onclose?.({ code: 1006 })`; assert `client.state() === 'reconnecting'`
     (regression guard — a non-auth close must not be treated as auth failure).
- **Done when:** the three new cases pass, the existing `ws.test.ts` cases stay
  green, and `npm run build` + `npm test` pass in `apps/web`.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.

Known follow-up (out of scope here): the bare `aitm` and `aitm tui` startup
output is not reworked and could get the same summary treatment later.
