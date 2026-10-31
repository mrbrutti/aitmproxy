# aitm web startup/UX hygiene design

**Status:** Approved (self-approved by orchestrator under Matt's autonomous-approve mode) 2026-10-30
**Research inputs:** orchestrator live investigation (ground truth, see Intent); memory notes `aitmproxy-operator-first-run-hygiene`, `aitmproxy-obscura-multisession-hazards`, `aitmproxy-web-cua-operator-l4`, `aitmproxy-web-bus-push-pr137`

## Intent

`aitm web` boots the proxy, the embedded obscura browser, and the operator web
UI, and prints one link the operator pastes into a browser. Today two rough
edges spoil that first run. First, ~20 `WARN … stale obscura run directory …`
lines print before the link, burying the one line that matters; the leftover
run dirs are never cleaned. Second, a browser tab left open from a *prior*
`aitm web` run reconnects forever with its now-stale bridge token, so the
console fills with one `WARN … refused a connection with a bad token` every
~5 s and the stale tab never tells its user why. This change makes the startup
quiet and legible and makes a stale token fail fast and loud on the client,
quiet and rate-limited on the server. The diagnosis is the orchestrator's,
confirmed by live run and code reading; this spec formalizes it, it does not
re-derive it.

## Goals

- `aitm web` cleans up obscura run dirs whose owning `aitm` is provably dead,
  safely, printing at most one concise line instead of a warn per dir.
- `aitm web` prints one clear, prominent startup summary (stdout) carrying the
  Web UI URL (with its `#t=` token), the operator URL when configured, the
  proxy and browser/obscura listen addresses, and the bus state.
- A web UI client whose token is rejected (stale tab) stops reconnecting and
  shows a clear "token expired — reopen the URL" state instead of hammering.
- The server rate-limits the bad-token refusal warning to at most one line per
  window with a suppressed count, keeping the security signal without the flood.

## Non-goals

- Reworking the startup output of bare `aitm` or `aitm tui`. Only the `aitm web`
  summary is in scope. (Noted as a follow-up.)
- Changing the bridge's refusal behaviour (the `UNAUTHORIZED_REPLY` and the
  `CloseCode::Policy` close are unchanged); only the *logging* of a refusal is
  throttled.
- Changing how tokens are minted, where they travel, or the operator-access
  gating (`mcp.operator_token`). The `#t=` token stays in the printed URL on
  purpose — that is how the operator opens the UI.
- Persisting a token across runs, or any server-side way to re-admit a stale
  tab. A new run mints a fresh token by design; the stale tab must be reopened.
- Cross-session obscura process management. We never manage another session's
  obscura; we only reap *directories* whose owner is dead.

## Anti-goals

- Deleting, killing, or `pgrep`/`pkill`-ing any obscura process, or removing any
  run dir that might belong to a live sibling session. A false positive here
  breaks another operator's running session — that is the worst outcome and must
  be impossible by construction.
- Leaking the bridge token into a tracing sink (stderr/log files). The token is
  allowed only in the stdout URL/summary the operator reads, never in logs.
- A client that silently stops working on a stale token with no visible reason,
  or one that stops reconnecting on an ordinary transient blip (that would make
  a valid current-run UI fail to recover).

## Constraints

- Platforms: macOS and Linux (both unix). A `cfg(not(unix))` fallback must
  compile but may be a conservative no-op.
- Liveness check is `libc::kill(pid, 0)` via errno, never a process scan. `libc`
  0.2.x is already in `Cargo.lock` transitively; add it as a direct, unix-gated
  dependency of `crates/aitm-browser`.
- TDD throughout: a failing test precedes every change. Rust unit tests must be
  hermetic — no port binding, no spawned obscura, no real sibling processes
  (inject the liveness predicate and the clock). Web tests run under vitest with
  the existing `FakeWebSocket` harness.
- Rust gate must pass: `cargo fmt --check && cargo clippy --all-targets -- -D
  warnings && cargo test`. Web gate must pass: `npm run build` and `npm test`
  (vitest) in `apps/web`.
- Keep `web::log_listening` exactly as-is; the existing tests in
  `crates/aitm/src/web/mod.rs` (and any in `main.rs`) that assert the
  `"web UI listening"` line and that it never carries the token must stay green.
- Throttle state is shared across connections via the `Arc`-shared `WebState`;
  keep it lock-light and its decision in a pure, clock-injectable unit.
- The Bash sandbox cannot bind ports; live `aitm web` verification happens in the
  Terminal panel and is the orchestrator's job, not a unit test's.

## Design

Four disjoint changes, grouped so independent files can fan out to parallel
coders.

### D1 — Safely reap stale obscura run dirs (`crates/aitm-browser/src/obscura.rs`)

Run dirs are named `make_run_dir()` as
`aitm-obscura-<OWNING_AITM_PID>-<token>`, so the owning `aitm` pid is embedded
in the directory name (not obscura's pid).

- Rename `warn_stale_run_dirs()` to `reap_stale_run_dirs()` and split out a pure,
  testable core:
  - `fn reap_stale_run_dirs_in(base: &Path, is_alive: impl Fn(u32) -> bool) -> usize`
    — scans `base`, and for each entry whose name starts with `RUN_DIR_PREFIX`
    **and is a directory**, parses the pid (the integer between `aitm-obscura-`
    and the next `-`). If the pid parses *and* `is_alive(pid)` is `false`, it
    removes the dir via the existing `remove_run_dir()` and counts it. It returns
    the number removed. It logs nothing (deterministic).
  - `fn reap_stale_run_dirs()` — calls `reap_stale_run_dirs_in(&std::env::temp_dir(), pid_is_alive)`
    and, only when the count `n > 0`, emits exactly one `info!(removed = n, …)`
    line (wording to match the file; e.g. "removed stale obscura run
    directories"). `n == 0` is silent (or `debug!`). Dirs left in use are never
    warned (at most `debug!`).
  - `fn pid_is_alive(pid: u32) -> bool` — on unix, `libc::kill(pid as i32, 0)`:
    returns `true` on success (exists: us, a sibling, or a recycled pid →
    LEAVE), `true` on `EPERM` (exists under another uid → LEAVE), `false` **only**
    on `ESRCH` (no such process → owner dead → REMOVE). On `cfg(not(unix))`,
    returns `true` (conservative: leave).
- **Conservative direction:** remove only when provably dead. Unparseable name,
  non-dir entry, ambiguous `kill` → LEAVE. PID reuse at worst leaves a dir; it
  never deletes a live sibling's. **(Architect's call — matches the hard hazard
  in the brief.)**
- Call site in `ObscuraProcess::start()` changes `warn_stale_run_dirs();` to
  `reap_stale_run_dirs();` (same place, before `make_run_dir()`).
- `Cargo.toml`: add `[target.'cfg(unix)'.dependencies] libc = "0.2"`.
- The existing `run_dir_is_private_and_unpredictable` test stays green.

### D2 — Clean, prominent startup summary (`crates/aitm/src/web/mod.rs`, `crates/aitm/src/main.rs`)

- Add a pure formatter in `web/mod.rs`:
  `pub fn startup_summary(web_url: &str, operator_url: Option<&str>, proxy: SocketAddr, browser: SocketAddr, bus: &str) -> String`.
  It returns a single multi-line labelled block (a small ASCII box or clean
  labelled lines — **Architect's call: a labelled block, legible over clever**)
  containing: the Web UI URL (token included — this is stdout), the Operator URL
  on its own labelled line only when `operator_url` is `Some`, the proxy listen
  addr, the browser/obscura listen addr (noted SSRF-filtered), and the bus state.
- `main.rs` (web arm): capture `let proxy_addr = proxy_listener.local_addr()?;`
  and `let browser_addr = browser_listener.local_addr()?;` into locals **before**
  the `web_server` block (both listeners are still owned there; they move into
  `proxy.run_on`/`run_browser_on` later). Keep `web::log_listening(bound)` as-is.
  Replace the two bare `println!("web UI (agent): …")` / `println!("web UI
  (operator): …")` lines with a single
  `println!("{}", web::startup_summary(&url, operator_url.as_deref(), proxy_addr, browser_addr, "ready"))`,
  where `operator_url` is `operator_token.as_ref().map(|op| web::operator_ui_url(bound, op))`.
- Separation of channels is preserved: tracing (incl. `log_listening`) goes to
  stderr and never carries the token; the summary (with token) is stdout.

### D3 — Throttle the bad-token refusal warn (`crates/aitm/src/web/bridge.rs`, `crates/aitm/src/web/mod.rs`, `crates/aitm/src/main.rs`)

- Pure, clock-injectable unit in `bridge.rs`:
  - `pub const BAD_TOKEN_WINDOW: Duration = Duration::from_secs(60);`
  - `#[derive(Default)] pub struct BadTokenThrottle` wrapping a
    `std::sync::Mutex` over `{ pending: u64, window_start: Option<std::time::Instant> }`.
  - `pub fn record(&self, now: std::time::Instant) -> Option<u64>`: increments
    `pending`; if `window_start` is `None` **or** `now.saturating_duration_since(window_start) >= BAD_TOKEN_WINDOW`,
    it returns `Some(pending)`, then resets `pending = 0` and `window_start = Some(now)`;
    otherwise returns `None`. So the first refusal and the first refusal after the
    window emit (with the accumulated count); refusals inside the window are
    suppressed.
- `WebState` (in `web/mod.rs`) gains `pub bad_token_throttle: bridge::BadTokenThrottle`.
  `main.rs` constructs it as `bad_token_throttle: Default::default()` in the
  existing `WebState { … }` literal.
- At the refusal site in `relay()`, replace the unconditional
  `warn!("web bus: refused a connection with a bad token")` with
  `if let Some(n) = state.bad_token_throttle.record(std::time::Instant::now()) { warn!(refusals = n, "web bus: refused connections with a bad token (suppressing repeats)"); }`.
  The reply (`UNAUTHORIZED_REPLY`) and the `CloseCode::Policy` close are
  unchanged.

### D4 — Client: stop hammering, surface the state (`apps/web/src/bus/ws.ts`, `types.ts`, `shell/StatusBar.tsx`)

- `types.ts`: extend `BusState` to
  `'idle' | 'connecting' | 'open' | 'reconnecting' | 'closed' | 'unauthorized'`.
- `ws.ts`:
  - Add module/closure state `let authFailed = false;`, a constant
    `const UNAUTHORIZED_MESSAGE = "token expired — reopen the URL printed by \`aitm web\`";`,
    and `function markAuthFailed()` that sets `authFailed = true`, `setState('unauthorized')`,
    `setLastError(UNAUTHORIZED_MESSAGE)`, `failAllPending(UNAUTHORIZED_MESSAGE)`,
    and `settleReady()`.
  - **Signal A (definitive reply):** in `onMessage`, before the numeric-id
    branch, treat a line with `(msg.id === null || msg.id === undefined)` and
    `msg.error?.code === -32001` as an auth failure → `markAuthFailed(); continue;`.
    (Notifications — `method` set, `id` undefined — are still handled by their
    own earlier branch and are unaffected.)
  - **Signal B (close):** in `onclose`, when `ev.code === 1008` (Policy),
    `markAuthFailed()` before the reconnect decision.
  - `scheduleReconnect()` returns early when `authFailed` (as it already does for
    `closedByUser`), so no further connect happens.
  - The `onopen` catch guards `if (authFailed) return;` so a rejected pending
    `initialize` does not overwrite the unauthorized `lastError`/state.
  - `connect()` resets `authFailed = false` so an explicit reconnect can retry.
  - Non-auth closes (1006, 1001, network error) are **not** auth failures and
    still reconnect with backoff.
- `StatusBar.tsx`: `busHue()` maps `'unauthorized'` to `'server-error'`; the bus
  label reads a short `bus token expired` when `state === 'unauthorized'` (the
  full reopen message is already in the existing `title` tooltip via
  `lastError`). **Architect's call: the status-label swap + existing tooltip is
  the minimal legible surface — no new inline banner, keeping the StatusBar
  layout and avoiding scope creep; the load-bearing behaviour (stop
  reconnecting, clear message) is tested in `ws.test.ts`.**

## Acceptance criteria

1. **AC1 — reaping is quiet.** Starting `aitm web` with N leftover
   `aitm-obscura-*` dirs whose owners are dead produces zero per-dir warns and at
   most one concise `info` line; the dead dirs are gone; any dir owned by a live
   pid is untouched. *Proven by a hermetic unit test on `reap_stale_run_dirs_in`
   with an injected liveness predicate.*
2. **AC2 — reaping is sibling-safe.** Cleanup never kills obscura and never calls
   a process scan, and never removes a dir whose owning pid is alive, unparseable,
   or ambiguous. *Proven by the same unit test: `aitm-obscura-111-aaa` (dead) is
   removed, `aitm-obscura-222-bbb` (alive) is kept, a non-matching dir and a
   matching *file* are untouched, and the return value is `1`.*
3. **AC3 — one clear summary, token out of logs.** `startup_summary(...)` returns
   a single block containing the Web UI URL with its `#t=` token, the proxy
   addr, the browser addr, the bus state, and the operator URL when `Some`
   (absent when `None`). The token never appears in a tracing sink. *Proven by a
   unit test on `startup_summary` plus the retained `log_listening_never_carries_the_token`
   test.*
4. **AC4 — stale token fails fast and clear.** On a rejected token (a 1008 close
   *or* an `id:null` / code `-32001` reply) the client stops reconnecting, sets
   state `'unauthorized'`, and sets `lastError` to the reopen-the-URL message.
   *Proven by two `ws.test.ts` cases asserting state, `lastError` contains
   "reopen", and `FakeWebSocket.count` stays `1`.*
5. **AC5 — transient blips still recover.** A non-auth close (1006) still
   schedules a reconnect. *Proven by a `ws.test.ts` case asserting state
   `'reconnecting'` after a 1006 close.*
6. **AC6 — server warn is rate-limited.** The bad-token refusal logs at most once
   per `BAD_TOKEN_WINDOW` with an accumulated count; the refusal reply and close
   are unchanged. *Proven by a unit test on `BadTokenThrottle::record` returning
   `Some(1)`, `None`, `None`, `Some(3)` for records at `t0`, `t0+1s`, `t0+2s`,
   `t0+61s`.*
7. **AC7 — gates green.** `cargo fmt --check && cargo clippy --all-targets -- -D
   warnings && cargo test` pass, and `npm run build` + `npm test` pass in
   `apps/web`.

## Left to the builder

- Exact wording of the single reap `info` line and whether `n == 0` is silent or
  `debug!`.
- The exact glyphs/layout of the summary block (ASCII box vs. labelled lines),
  as long as it is one legible block carrying every field in AC3.
- Internal field names of `BadTokenThrottle`'s inner struct.
- The exact short bus-label text for the `'unauthorized'` state in StatusBar,
  provided the full reopen message remains reachable (tooltip).

## Open questions

None.
