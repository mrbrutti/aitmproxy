# Core-connection model and a self-contained macOS app — implementation plan

**Status:** draft
**Spec:** `docs/superpowers/specs/2026-10-28-aitmproxy-core-connection-model-design.md`
**Branch / worktree:** `feat/core-connection-model`

## Overview

The work lands in three layers that match the spec. **Layer A (Rust log/token
hygiene, Tasks 1–3)** is independently shippable and merges first (spec O6); it
depends on nothing below it. **Layer B (connection abstraction + `CoreID`, Tasks
4–5)** is pure macOS-Kit model work, disjoint from the Rust tree, so it runs in
parallel with Layer A. **Layer C (the self-contained macOS app, Tasks 6–10)** sits
on top of both: it needs the Rust `--bus-endpoint-file` from Task 3 and the
`CoreConnection`/`CoreID` model from Tasks 4–5.

Parallelism: within Layer A, Task 1 (`proxy.rs`) is disjoint from Tasks 2–3
(`main.rs`), which serialize on that file. Layer B's Tasks 4–5 serialize (5 needs
4) but run concurrently with Layer A. In Layer C, Tasks 8 and 9 are disjoint from
each other once Task 6 lands; Task 10 is last (docs follow the bundle).

All git/`gh` and every macOS build/verify tool run in the **Terminal panel**
(SwiftPM and `.git` are unavailable in the Claude sandbox). The macOS app is built
with the bama pipeline: `apps/mac/build.sh --debug`, `tools/verify.sh`,
`tools/selftest-live.sh`; `Tokens.swift` stays generated.

Note: the Homebrew **cask/formula live in the separate tap repo**
(`mrbrutti/homebrew-aitmproxy`); Task 10's in-repo work is `INSTALL.md` and the
app's Bus-settings help text, and it *specifies* the cask change as a release-side
edit in the tap, not a commit in this repo.

## Tasks

### Task 1: Classify connection-handler errors; demote benign disconnects

- **Satisfies:** AC1
- **Depends on:** none (disjoint from Tasks 2–3)
- **Files:** `crates/aitm-core/src/proxy.rs` (modify), a new classifier module or
  inline fn in the same crate (create/modify), tests in `crates/aitm-core`
  (create).
- **Change:** add `fn is_benign_disconnect(err: &anyhow::Error) -> bool` (name the
  builder's call) that returns true for a named, tested set — client TLS-handshake
  abort/alert from the TLS layer, `io::ErrorKind::{ConnectionReset,
  BrokenPipe, UnexpectedEof}`, and EOF-before-a-request — by walking the error
  chain / downcasting, **not** by matching message substrings. At the log site
  (`proxy.rs:95`), log `debug!` when benign, keep `warn!` otherwise.
- **Test:** `benign_disconnects_are_debug_real_errors_warn` — construct errors of
  each demoted kind and assert `is_benign_disconnect` is `true`; construct a
  genuine handler error (e.g. a parse/upstream failure) and assert `false`.
  Expected: all demoted kinds `true`, the genuine error `false`.
- **Done when:** the test passes and the full gate passes.

### Task 2: Keep the bus/web token out of the structured log stream

- **Satisfies:** AC2
- **Depends on:** none (serializes with Task 3 on `main.rs`)
- **Files:** `crates/aitm/src/main.rs` (modify), a test in `crates/aitm` or a
  small extracted fn to test (create/modify).
- **Change:** at `main.rs:284–286`, change the "web UI listening" log to record the
  **address only** (`info!(addr = %local_addr, "web UI listening")`), dropping the
  tokened `url` field; keep the single `println!("web UI: {url}")` as the one
  deliberate stdout disclosure. Audit the `tui`/server paths for any other
  `tracing` call carrying a tokened URL and apply the same rule.
- **Test:** `web_listening_log_has_no_token` — exercise the log-field builder (or a
  small extracted `fn listening_fields(addr, url)`) and assert the structured
  fields contain the address and **not** the token string; a repo grep assertion
  that no `tracing` macro call site includes `#t=`/`token` in a URL field.
  Expected: address present, token absent.
- **Done when:** the test passes and the full gate passes.

### Task 3: Curated default log filter + `--bus-endpoint-file` rendezvous

- **Satisfies:** AC3; enables AC6 (the app learns the bus port)
- **Depends on:** Task 2 (shares `main.rs`)
- **Files:** `crates/aitm/src/main.rs` (modify `init_tracing`), `crates/aitm-core/src/config.rs`
  and `crates/aitm/src/config_file.rs` (add the endpoint-file option), the bus
  bind path in `crates/aitm-mcp/src/transport.rs` / `crates/aitm-mcp/src/server.rs`
  (write the file after bind), tests in the touched crates (create).
- **Change:** (a) replace `EnvFilter::new("info")` with a curated default directive
  that keeps lifecycle/`info` for operator targets while pinning noisy per-connection
  and dependency targets lower; `RUST_LOG` still overrides wholesale. (b) add an
  optional bus **endpoint-file** path (config field `mcp.transport.loopback_tcp.endpoint_file`
  and/or a `--bus-endpoint-file <path>` flag); after the loopback transport binds,
  write the resolved bus `host:port` (no token) to that path `0600`, and remove it
  on clean exit — mirroring the obscura ready-file (`crates/aitm-browser/src/obscura.rs`).
- **Test:** `default_filter_quiets_connection_noise` — build the default
  `EnvFilter` and assert a benign per-connection target is filtered while an
  operator lifecycle target passes. `endpoint_file_written_after_bind` — bind the
  loopback transport on port 0 with an endpoint-file path, assert the file contains
  the bound `127.0.0.1:<port>` and **no** token, and is removed on drop. Expected:
  file content equals the bound address, token absent, gone after shutdown.
- **Done when:** both tests pass and the full gate passes.

### Task 4: `CoreConnection` model + `CoreID` (macOS Kit)

- **Satisfies:** AC5
- **Depends on:** none (disjoint from Layer A; runs in parallel)
- **Files:** `apps/mac/Sources/AitmproxyKit/CoreConnection.swift` (create),
  `apps/mac/Tests/AitmproxyKitTests/CoreConnectionTests.swift` (create). Reuses
  `BusEndpoint` from `AitmBusClient`.
- **Change:** add `struct CoreID: Hashable, Sendable` (opaque, e.g. a UUID-backed
  string) and `struct CoreConnection` with `id: CoreID`, `kind: Kind` (`enum Kind {
  case embedded; case external; case remote }` — `remote` is a reserved case with
  no behaviour), `endpoint: BusEndpoint`, `status: Status` (`.starting`,
  `.connecting`, `.ready`, `.degraded(reason)`, `.stopped`), `label: String`. Add a
  tiny `ConnectionRegistry` keyed by `CoreID` that can hold more than one entry and
  tracks a single `activeID`.
- **Test:** `connection_registry_holds_many_exposes_one_active` — construct an
  embedded and an external `CoreConnection`, insert both, assert the registry holds
  two and returns the chosen active one; assert `Kind.remote` constructs but is not
  selectable as active (or is explicitly unsupported). Expected: count 2, active ==
  the chosen id.
- **Done when:** the test passes; `swift test` and `tools/selftest.sh` pass.

### Task 5: Thread `CoreID` onto every flow/row

- **Satisfies:** AC4
- **Depends on:** Task 4
- **Files:** `apps/mac/Sources/AitmproxyKit/` flow/row model + store keys (modify),
  `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (set the id on arriving flows),
  `apps/mac/Tests/AitmproxyKitTests/` (create/modify).
- **Change:** add `coreID: CoreID` to the flow/row model and to the store keys that
  index flows; set it to the active connection's id when a flow arrives over the
  bus (`BusService`) or from fixtures. With one connection this is a constant, but
  the field is present everywhere a flow is keyed.
- **Test:** `flows_carry_their_core_id` — feed a flow through the bus/fixture
  ingestion with a known active `CoreID` and assert the resulting row's `coreID`
  equals it. Expected: `row.coreID == activeID`.
- **Done when:** the test passes; `swift test` + self-test pass.

### Task 6: `EmbeddedCore` — spawn, lifecycle, rendezvous, port auto-pick

- **Satisfies:** AC6, AC7, AC8, AC9 (core side)
- **Depends on:** Task 3 (`--bus-endpoint-file`), Task 4 (`CoreConnection`)
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift` (create),
  `apps/mac/Sources/AitmproxyKit/` small pure helpers for token-gen / config-write
  / endpoint-file parse / free-port probe (create), `apps/mac/Tests/AitmproxyKitTests/`
  (create), `apps/mac/Sources/Aitmproxy/App.swift` (wire start on launch / stop on
  quit).
- **Change:** an actor owning one `aitm` child: generate a fresh CSPRNG **token**
  per launch (never persisted/logged); **auto-pick a free proxy/browser-proxy port**
  (probe, or alternate on bind-failure); write a `0600` per-launch temp config in
  the app container (bus `port: 0`, the token, the chosen proxy ports, the curated
  log level, `endpoint_file` path, and the bundled `obscura` path); spawn the
  bundled `aitm`; watch the **rendezvous endpoint-file** for the bound bus
  `host:port`, build a `BusEndpoint`, and hand it to the existing `BusClient`.
  Lifecycle: start on app launch; on quit `SIGTERM` → grace budget → `SIGKILL`,
  reap, delete temp/rendezvous files; **restart on unexpected exit** with bounded
  exponential backoff and a cap, then `.degraded` with the captured stderr tail;
  capture stdout/stderr for the log panel; detect and clean a stale rendezvous file
  from a killed prior run. Map lifecycle to `CoreConnection.status`.
- **Test:** pure-helper unit tests — `token_is_fresh_and_high_entropy`,
  `generated_config_is_0600_and_tokenless_in_world_readable_sense`,
  `endpoint_file_parses_to_bus_endpoint`, `free_port_probe_returns_an_unused_port`,
  each asserting a literal expected shape. The full end-to-end spawn is covered by
  Task 9's live self-test (AC6/AC7).
- **Done when:** the helper tests pass; `swift test` + self-test pass; the manager
  compiles and wires into `App.swift`.

### Task 7: Active connection as switchable, persistent state + Settings

- **Satisfies:** AC10
- **Depends on:** Task 6
- **Files:** `apps/mac/Sources/Aitmproxy/SettingsView.swift` (modify `BusSettings`),
  `apps/mac/Sources/Aitmproxy/Session*.swift` + `Bus/` (active-connection state),
  `apps/mac/Sources/AitmproxyKit/` (persisted choice + transition logic),
  `apps/mac/Tests/AitmproxyKitTests/` (create).
- **Change:** a persisted `activeKind`/connection choice (Application Support, via
  `@AppStorage` or the Store). Default `.embedded`. Selecting external makes it
  active and **stops/does-not-spawn** the embedded core; selecting embedded
  (re)starts and makes it active. The choice persists across launches and never
  permanently disables embedded. Wire the `BusSettings` toggle set
  (embedded ⇄ external host/port/token-file / "from config.yaml") to this state.
- **Test:** `active_connection_switches_both_ways_without_disabling_embedded` —
  drive the transition embedded→external→embedded over the state machine (with a
  fake core controller) and assert: external active ⇒ embedded not running; back to
  embedded ⇒ embedded running and active; the persisted choice round-trips.
  Expected: the asserted running/active flags at each step.
- **Done when:** the test passes; `swift test` + self-test + a Settings snapshot
  (light/dark) pass.

### Task 8: Health dot + on-demand core-log panel

- **Satisfies:** AC9 (visibility), AC8 (degraded surfacing); spec C4
- **Depends on:** Task 6 (disjoint from Task 9)
- **Files:** `apps/mac/Sources/Aitmproxy/` a status-area health view + the existing
  Connection Log surface (modify), `Snapshot.swift` (add a capture), tests/self-test
  (modify).
- **Change:** an **always-visible health dot** mapping `CoreConnection.status` to
  **running / restarting / failed**; it also shows the auto-chosen proxy port (C3)
  and, on `.degraded`, the reason + stderr tail. An **on-demand log view panel**
  (not an always-on tail) that shows captured core stdout/stderr when opened, with a
  menu item + shortcut (add to `CommandMap`, per the brief's command-map rule).
- **Test:** self-test menu/`CommandMap` check for the new log-panel item; a
  snapshot of the health dot in each state (running/restarting/failed) reviewed
  light+dark. Expected: menu item present and keyed; dot renders per state.
- **Done when:** self-test passes, grid-lint PASS, snapshots reviewed, gate green.

### Task 9: Bundle `aitm` + `obscura` into the `.app`; sign & notarize (arm64)

- **Satisfies:** AC6, AC7, AC11
- **Depends on:** Task 6 (the manager runs the bundled binaries)
- **Files:** `apps/mac/build.sh` (modify: copy + nested-sign the two binaries),
  `scripts/notarize-dmg.sh` (modify: sign nested binaries before the outer app),
  `scripts/package.sh` (confirm it still yields the arm64 `aitm`+`obscura`),
  `apps/mac/Info.plist.in` (only if a helper placement needs it). App Sandbox stays
  **off**; arm64-only.
- **Change:** `build.sh` copies `aitm` and `obscura` into the bundle (e.g.
  `Contents/Resources/core/`, obscura beside aitm) and signs each with hardened
  runtime before signing the app; the `EmbeddedCore` points at the bundled `aitm`
  and sets the bundled `obscura` path. `notarize-dmg.sh` signs the nested binaries
  first so notarization staples cleanly.
- **Test:** `tools/selftest-live.sh` run against the **bundled** core with **no
  external `aitm`** on PATH and no `config.yaml` — asserts connect + live flows
  through the embedded proxy (AC6); a post-quit process/file check asserts no
  surviving `aitm`/`obscura` and no rendezvous/temp files (AC7); `codesign
  --verify --deep` + `spctl` on the built app assert the nested binaries are signed
  (AC11). Expected: live checks green, zero surviving processes/files, codesign OK.
- **Done when:** the live self-test and the post-quit/codesign checks pass (Terminal
  panel), gate green.

### Task 10: Install docs + cask self-sufficiency + Settings help

- **Satisfies:** AC12
- **Depends on:** Task 9
- **Files:** in-repo: `INSTALL.md` (create/modify), the app's Bus-settings help
  text in `SettingsView.swift` (modify). Release-side (specified here, applied in
  the `mrbrutti/homebrew-aitmproxy` tap, not committed in this repo):
  `Casks/aitmproxy.rb` note that the cask is self-sufficient; `Formula/aitm.rb`
  stays for CLI/headless.
- **Change:** document that the cask ships a self-contained app (embedded core, no
  separate `aitm` needed); the `aitm` formula remains for CLI/headless/external-core
  operators; the Bus-settings help explains embedded-default and how to point at an
  external core (Settings ▸ Bus, `--bus`, or `config.yaml`).
- **Test:** `tools/selftest.sh` still green; a Settings-Bus snapshot shows the
  updated help; a docs-lint/readback that `INSTALL.md` states cask self-sufficiency
  and the external-connector steps. Expected: snapshot + self-test green, doc
  assertions pass.
- **Done when:** self-test + snapshot pass and the docs read correctly; the tap cask
  change is written up for the release step.

## Review log

Stage-6 panel ran 2026-10-29 on the whole branch (`ad47182..7e8c73d`): security-reviewer,
quality-reviewer, spec-reviewer in parallel. Rust gate green (fmt + clippy -D + test, 116
binaries, 0 fail). Consolidated verdict **FAIL** (1 Important + 3 Critical + dispositions).

| # | Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|---|
| S1 | 6 | security | Important | Child-stop grace 3s < core's obscura teardown budget (~6s); SIGKILL can orphan obscura (AC7 anti-goal) | FIX (fix-task cc-fix) |
| SP1 | 9 | spec | Critical | AC6 cask-only embedded spawn has no committed test; `selftest-live.sh` still drives an external core | FIX — add embedded-path live self-test / capture run evidence |
| SP2 | 6/9 | spec | Critical | AC7 teardown/no-orphans unverified (no process/file check) | FIX — post-quit process/file assertion |
| SP3 | 6 | spec | Critical | AC8 restart/backoff/cap untested (only `.degraded→failed` mapping covered) | FIX — extract pure restart helper + unit tests |
| Q1 | 8 | quality | Minor | Health→colour mapping duplicated (`CoreHealthDot` + `CoreLogPanel`) | FIX — extract `CoreHealth.dotColor` |
| Q2 | 6 | quality | Minor | `failPermanently` keeps 40 tail lines, surfaces 8 (misleading constant) | FIX — name the surfaced count |
| Q3 | 6 | quality | Minor | Backoff `min(restarts-1,16)` guard dead given restart cap | FIX — drop or comment |
| S2 | 3/6 | security | Minor | Endpoint/config files opened without `O_NOFOLLOW` | FIX Swift (`O_NOFOLLOW`); Rust accepted — not reachable (0700 dir); document endpoint-file dir must be operator-writable only |
| S3 | 6 | security | Minor | YAML config built by interpolation without escaping paths | FIX — escape `"`/`\`, reject newlines |
| S4 | 6 | security | Minor | Rendezvous host trusted verbatim (not pinned loopback) | FIX — reject non-loopback host in `parseEndpoint` |
| SR | — | security | Rec | `cargo audit` not in the gate | Accepted — follow-up, out of this branch's scope |
| SP4 | 9 | spec | Important | `scripts/make-dmg.sh` undeclared file | Accepted — needed for packaging; declared here in Task 9 scope |
| SP5 | 9 | spec | Important | `EmbeddedObscura.entitlements` undeclared; grants JIT to obscura | Accepted — JIT is intentional, scoped to obscura only (security-reviewer signed off); declared here |
| SP6 | 9 | spec | Important | AC11 codesign/spctl evidence not captured in range | VERIFY at integration — capture `codesign --verify`/`spctl`/`stapler` output |
| SP7 | 8 | spec | Minor | `CoreLogPanel` new view vs reusing Connection Log | Accepted — C4 is an Architect's-call area |
| SP8 | 6/8 | spec | Minor | A few files outside their task's literal list (within feature dirs) | Accepted — within the feature's directories |
| SP9 | 3 | spec | Minor | `tracing` dep added to `aitm-mcp` | Accepted — functionally justified (debug line on rendezvous removal) |

Fix task **cc-fix** addresses S1–S4, Q1–Q3, SP1–SP3 (and documents the S2 Rust side). SP4/SP5/SP9/SP7/SP8/SR accepted above (pending Matt's ratification at integration); SP6/AC11 verified at integration.

### Review log (template, for later rounds)

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
