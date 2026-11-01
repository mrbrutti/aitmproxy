# L4 parity fixes implementation plan

**Status:** Approved for the pre-approved small fixes (Matt, 2026-10-31, via the orchestrator); unit (a)'s
operator scope add (spec question ii) merges last pending Matt's word. Orchestrator sequencing
(2026-10-31): (a) and (e) GO; (b) waits for the fixture-removal TUI PR, then runs before
system-proxy-auto PR 2; (c) waits for the fixture-removal web PR (bus/noise.ts is deleted: drop it)
and runs before system-proxy PR 3; (d) waits for the removal mac PR, BusService.swift for S-041 then
mac-architecture 2a, Session.swift for #197 + #201 + the removal PR. The architect's three
questions, decided by the audit session as routine calls (Matt may override): (1) the Mac Scope page
hosts the L4 availability line and the L4 scope section; no row-less Craft sheet, so the in-app
half of L4PAR-AC27 is "blocked: needs D0" and the sample is proved by the Kit unit test plus
`l4.craft` over the bus with the sample text; (2) unit (a) makes `l4.intercept.list` return parked
packets in arrival order (oldest first) and every UI acts on the first; (3) the TUI displays the
`auto` and `ask` policies; full support is a separate change.
**Spec:** `docs/superpowers/specs/2026-10-31-l4-parity-fixes-design.md` (approved for the small fixes, 2026-10-31; questions i–iii on their recommended defaults; unit (a)'s operator scope-add merges last)
**Research:** `docs/research/12-l4-parity-audit.md` (D0–D15)
**Branches / worktrees:** five, one per unit, each cut from `origin/main` (5eac2a5 or later) and each with its own PR against `main`:

| Unit | Branch | Worktree (created by the orchestrator, Terminal) | Tasks |
|---|---|---|---|
| (a) core | `fix/l4-parity-core` | `.claude/worktrees/l4par-core` | A1–A9 |
| (b) TUI | `fix/l4-parity-tui` | `.claude/worktrees/l4par-tui` | B1–B9 |
| (c) web | `fix/l4-parity-web` | `.claude/worktrees/l4par-web` | C1–C10 |
| (d) macOS | `fix/l4-parity-mac` | `.claude/worktrees/l4par-mac` | D1–D9 |
| (e) docs | `docs/l4-parity` | `.claude/worktrees/l4par-docs` | E1–E2 |

## Overview

Five independent PRs fix D1–D15 on top of the fixture-removal PR from another session (its merge SHA is `R`; the orchestrator sends it). Each branch is cut from `origin/main` now and **rebases once on `R`** when the orchestrator sends the SHA; a Coder who has not yet received `R` must not touch a file `R` deletes.

**Independence.** Units are independent of each other: disjoint file lists (spec §7), so the five units fan out in parallel, one worktree each. **Inside a unit, tasks are sequential** (A1 → A2 → …), one fresh Coder per task, test-first, one commit per task.

**Merge order (spec §8).** (c) merges **before** (a) or the same day ((c) reads both status shapes). (b) and (d) are independent of (a) for merge, but their live checks marked "with (a)" run on a local integration (below). (e) merges **after** (a). (a)'s operator scope-add (A6) is in the same PR as the rest of (a), so (a) merges last of the code units.

**Local integration for "with (a)" live checks.** When a UI task's live check needs (a) (scope-add confirm, the status objects, the `l4.flow.get` window), the Coder asks the orchestrator for a throwaway integration worktree on `local/l4par-<unit>-with-core` = the unit branch merged with the current `fix/l4-parity-core` head. It is built and run like any rig build, **never pushed, never merged**, and deleted when the check is done. The verdict line names both SHAs.

### Rule for every task (Matt, 2026-10-31; repeat it in every Coder report)

**No fixture, snapshot, self-test or seeded-store run counts as evidence or as a gate.** That covers macOS `Fixtures+*.swift` data, `tools/snap.sh` / `snap-dev.sh` snapshot images, `selftest.sh` with `APP_FIXTURES`, the web mock bus (`?bus=mock`, `bus/mock.ts`) and TUI `--fixture` / `fixture.rs`. Evidence is exactly one of: **(1)** a unit test of pure logic whose input is built in the test; **(2)** a source tripwire (grep or a test that reads source) that stops the named regression; **(3)** the live check: the real frontend against a real core on the rig with real traffic, or the honest **blocked** verdict (`blocked: needs D0` / `blocked: no Linux rig`) with the core's reason quoted. A green fixture or snapshot suite is never cited. A suite CI runs must not be left red.

`snap-dev.sh` is used **only** to build the dev bundle; its snapshot images are not evidence.

### Coordination (every Coder, every task)

1. Before the first edit of a task, send the orchestrator session the task's **Files** list (the claim). Edit nothing outside it. If the task needs a file not in its unit's spec §7 list, **stop and report**; do not edit it.
2. Every PR number goes to the orchestrator the moment it exists.
3. **Nobody merges.** No Coder, Tester or reviewer merges or closes a PR. Integration is stage 7, the orchestrator's, after Matt's go.
4. The rig is a shared resource: claim it through the orchestrator like a file. One rig core at a time on bus 27431 / web 28182.

### Known traps (read before starting)

- **The sandbox cannot bind ports or reach GitHub.** Starting `aitm web`, the http/udp targets, the TUI against the bus, the mac bundle, `npm ci`, `git push`, `gh` all run in the **Terminal panel**. Push with an explicit refspec: `git push origin fix/l4-parity-<unit>` (after the `R` rebase: `git push --force-with-lease origin fix/l4-parity-<unit>`). Keep Terminal lines short and single-purpose: long compound git lines get mangled; do local git (commit, rebase) in the sandbox.
- **Stale cargo artifacts.** The target dir can serve stale artifacts across worktrees. `touch` the crate's `src/lib.rs` (and `crates/aitm/build.rs` for web-embedding builds) before every gate and every release build. Gate on the **exit status** written to a log (`…; echo EXIT=$?`), never on a grep of the output.
- **Never `./build.sh` in `apps/mac`.** Build with `DEV_TAG=<tag> apps/mac/tools/snap-dev.sh`. SwiftPM (`swift build`, `swift test`) runs only in the Terminal.
- **Never kill a process you did not start.** Note the PIDs of the rig core, targets, TUI and dev bundle you launch; stop only those. Never `pkill -f` by name.
- **Never print a bus token.** Read tokens from files (`/tmp/claude/l4-rig/op.token`, `/tmp/claude/l4-rig/agent.token`) into env vars or `--token-file`; never echo them, never paste the Operator URL (it carries the token) into a report or commit.
- **`aitm web` exits on stdin EOF.** Hold stdin open: `sleep 86400 | AITM_CONFIG=… aitm web …`.
- **Disk.** Release builds in five worktrees fill the disk; if a build fails ENOSPC, ask the orchestrator to clear idle siblings' `target/`.
- **Shared Swift scratch path.** `~/Library/Developer/Aitmproxy/test-build` is shared; do not run two `swift test` at once.

### The rig (spec §6; every live check)

Build in the sandbox, offline, from the worktree under test (or its `local/…-with-core` integration):

```bash
touch crates/aitm/build.rs crates/aitm-proto-l4/src/lib.rs
cargo build --release --offline -p aitm -p aitm-tui > /tmp/claude/l4-rig/<unit>-build.log 2>&1; echo EXIT=$?
```

Start in the Terminal (write these lines into `/tmp/claude/l4-rig/<unit>-up.sh` and run that, so the Terminal sees one short command):

```bash
python3 -m http.server 9099 --bind 127.0.0.1 > /tmp/claude/l4-rig/<unit>-http.log 2>&1 &
python3 /tmp/claude/l4-rig/udpecho.py > /tmp/claude/l4-rig/<unit>-udp.log 2>&1 &
sleep 86400 | AITM_CONFIG=/tmp/claude/l4-rig/config.yaml <worktree>/target/release/aitm web --listen 127.0.0.1:28182 > /tmp/claude/l4-rig/<unit>-aitm.log 2>&1 &
```

- Config: `/tmp/claude/l4-rig/config.yaml` (proxy 28180, browser 28181, bus 27431, web 28182; `l4.enabled: true`; three config `l4.scope` entries on lo0 `127.0.0.1/32` ports `9000-9999`, one each for capture/inject/intercept; **no** `l4.intercept` block).
- Real HTTP rows: `curl -s -x http://127.0.0.1:28180 http://127.0.0.1:9099/ >/dev/null` (a few times).
- Bus from python (Terminal), env model of `tests/e2e/aitm_e2e/bus.py`: `AITM_BUS_ADDR=127.0.0.1:27431`, `AITM_BUS_OPERATOR_TOKEN` and `AITM_BUS_TOKEN` read from the token files.
- **Counting calls a frontend made** (AC11, AC15, AC23, AC25): a separate operator `BusClient` reads `agent.activity {since: <t0 ms>}` and counts entries whose `command` starts with `l4.` and whose `client_label` is `aitm-tui` / `web-bridge` / `aitm-mac`. (The spec's "core debug log or audit ring" is satisfied by the audit ring.)
- This Mac is the **unprivileged rig**: `/dev/bpf*` is root-only. Reasons on it, verbatim:
  - `R_CAP` = `no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)`
  - `R_INT` = `in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)`
  - `R_WIDEN` = ``runtime L4 scope widening is disabled; declare scope in the `l4.scope` config block or set `l4.allow_agent_widen` ``
- TUI: the real `target/release/aitm-tui` in a pty, driven like `/tmp/claude/l4-rig/tui_drive.py` (160×44, `--bus 127.0.0.1:27431 --token-file /tmp/claude/l4-rig/op.token --expect-role operator`). Point `AITM_TUI_BIN` at the worktree's binary, not the main checkout's.
- Web: the in-app browser at the **Operator URL** the core prints in `<unit>-aitm.log` (do not copy the URL into the report), light and dark.
- macOS: `DEV_TAG=l4par apps/mac/tools/snap-dev.sh` (build only), then `apps/mac/tools/cua-l4-live.sh` (task D9; until it exists, `/tmp/claude/l4-rig/mac-live.sh` with `APP_STORE` and `APP_DEFAULTS_SUITE` pointed at fresh dirs/names), screenshots with `swift apps/mac/tools/winshot.swift Aitmproxy <out.png>`, light and dark (`-AppleInterfaceStyle Dark` as a launch argument; verify it took).

### Gates (before any panel review of a unit)

| Unit | Gate (all must exit 0, output quoted) |
|---|---|
| (a), (b) | sandbox: `cargo fmt --check && cargo clippy --all-targets --offline -- -D warnings && cargo test --offline` (touch first; exit status from the log) |
| (c) | Terminal once per worktree: `npm ci` in `apps/web`. Then `cd apps/web && npm run typecheck && npm test && npm run build` (the actual `package.json` scripts; each runs `npm run gen` first). Plus the Rust gate, because `aitm` embeds `apps/web/dist` (only `cargo build` is affected; no Rust file changes). |
| (d) | Terminal: `DEV_TAG=l4par apps/mac/tools/snap-dev.sh` (build half; it must print `Build complete` and no `build failed`), `cd apps/mac && swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`, and `apps/mac/tools/grid-lint.sh` **only if** a task changed layout (D5, D7). Plus `apps/mac/tools/check-l4-live.sh`. |
| (e) | the AC32 diff check (E1) and a Markdown link check by eye; no code. |

### Unit close (Tester, then the orchestrator, per unit)

Every AC of the unit maps to a named unit test, tripwire, or a live check with its output quoted, or to an explicit `blocked: needs D0` / `blocked: no Linux rig` line with the core's reason. AC33 is recorded per UI unit (its half). The security reviewer confirms no agent path widens (AC33 second half).

---

## Unit (a) core — `fix/l4-parity-core`

Spec §7(a) file list: `crates/aitm-proto-l4/src/{commands/flow.rs, craft.rs, commands/capture.rs, commands/intercept.rs, commands/mod.rs, commands/scope.rs, guard.rs, module.rs, language.rs}`, `crates/aitm-proto-l4/tests/{surface.rs, operator_surfaces.rs, inpath.rs, active_roundtrip.rs, language.rs}` (shape updates only), `crates/aitm/tests/{l4_operator_surfaces.rs, l4_acceptance_mcp.rs}`, `tests/e2e/l4/{test_l4_capture_flow.py, test_l4_scope_self_exclusion.py}`, new `tests/e2e/l4/{test_l4_parity_core.py, test_l4_parity_priv.py}`.

Constraint for every (a) task: **zero `aitm-core` edits** (AC9). `L4Privilege` keeps its two public fields unchanged, because `crates/aitm/tests/l4_wiring.rs` (not in the list) builds it by struct literal.

Any existing test in the list that a task's shape change breaks is updated **in that task** (shape only; agent assertions untouched).

### Task A1: pure packet endpoint decode

- **Satisfies:** AC1 (groundwork)
- **Depends on:** none
- **Files:** `crates/aitm-proto-l4/src/craft.rs` (modify)
- **Change:** next to `PacketSpec::summarize`, add
  - `#[derive(Debug, Clone, PartialEq, Eq, Default)] pub struct PacketEndpoints { pub proto: Option<&'static str>, pub src: Option<std::net::IpAddr>, pub dst: Option<std::net::IpAddr>, pub src_port: Option<u16>, pub dst_port: Option<u16> }`
  - `impl PacketSpec { #[must_use] pub fn endpoints(bytes: &[u8]) -> PacketEndpoints }`, over the existing `parse_frame`. `proto` is `"TCP" | "UDP" | "ICMP" | "ICMPv6"` (the same names `summarize` uses); ports only for TCP/UDP; never panics; an undecodable buffer returns `PacketEndpoints::default()`.
- **Test first** (`cargo test --offline -p aitm-proto-l4 --lib craft::tests::endpoints`), in `craft.rs` `mod tests`:
  - `endpoints_of_crafted_ipv4_udp`: build `[Ipv4{src 127.0.0.1, dst 127.0.0.1}, Udp{src_port 40000, dst_port 9053}, Raw(b"hello-l4")]` → `PacketEndpoints { proto: Some("UDP"), src: Some(127.0.0.1), dst: Some(127.0.0.1), src_port: Some(40000), dst_port: Some(9053) }`.
  - `endpoints_of_undecodable_is_default`: `[0xde, 0xad]` → `PacketEndpoints::default()`.
  - `endpoints_of_tcp_icmp_ipv6`: TCP `10.0.0.1:1234 → 10.0.0.2:80` → `proto Some("TCP")`, ports `Some(1234)`/`Some(80)`; ICMP to 127.0.0.1 → `proto Some("ICMP")`, both ports `None`; IPv6/UDP `::1 → ::1` port 9 → `proto Some("UDP")`, `src Some(::1)`.
- **Minimum code:** one function reading `p.net` and `p.transport` from `parse_frame`.
- **Live check:** none here (A9).
- **Done when:** the tests pass and the (a) gate passes.

### Task A2: `l4.flow.get` packet and flow fields

- **Satisfies:** AC1
- **Depends on:** A1
- **Files:** `crates/aitm-proto-l4/src/commands/flow.rs` (modify), `crates/aitm/tests/l4_operator_surfaces.rs` (modify)
- **Change:** in `flow_to_value`, each packet object keeps `dir`, `length`, `injected`, `layers` and gains `bytes` (`Value::Bytes(p.bytes.clone())`), `timestamp` (`Value::Int`, ms since the Unix epoch of `p.timestamp`; a pre-epoch time is `0`), `proto` (`Str` or `Null`), `src`, `dst` (`Str` via `IpAddr::to_string`, or `Null`), `src_port`, `dst_port` (`Int` or `Null`), from `PacketSpec::endpoints`. The flow object gains `started_at` (`Int` ms of `metadata.created`) and flow-level `proto`, `src`, `dst`, `src_port`, `dst_port` from the **first packet whose `endpoints().proto` is `Some`** (all `Null` when none). Add a private `fn epoch_ms(t: SystemTime) -> i64`. Update `flow_fields()` so the schema lists every new field (`bytes` is `TypeDesc::Bytes`, the address fields `required: false`).
- **Test first:**
  - `cargo test --offline -p aitm-proto-l4 --lib commands::flow::tests`: new `mod tests` in `flow.rs`. `flow_get_reports_bytes_time_and_addresses`: an `InMemoryL4FlowStore` holding one Capture flow with `metadata.created = UNIX_EPOCH + 1_700_000_000_000 ms` and one packet, the A1 crafted IPv4/UDP bytes at `timestamp = UNIX_EPOCH + 1_700_000_000_123 ms`; `FlowGet::new(store).invoke({id}, &host)` → packet `proto == Str("UDP")`, `src == Str("127.0.0.1")`, `dst == Str("127.0.0.1")`, `src_port == Int(40000)`, `dst_port == Int(9053)`, `bytes == Bytes(<the crafted bytes>)`, `timestamp == Int(1_700_000_000_123)`; flow `started_at == Int(1_700_000_000_000)`, flow `dst_port == Int(9053)`. `flow_get_undecodable_packet_is_null_addressed`: packet bytes `[0xde, 0xad]` → `proto, src, dst, src_port, dst_port` all `Null`, `bytes == Bytes(vec![0xde, 0xad])`, flow-level address fields `Null`.
  - `cargo test --offline -p aitm --test l4_operator_surfaces flow_get_bytes_are_base64_on_the_wire`: a server whose `L4Module` is built with `L4Module::with_shared(guard, store, None, L4Privilege::available())` over a store the test holds; insert the `[0xde, 0xad]` flow; operator `l4.flow.get {id}` → `result.structuredContent.packets[0].bytes == "3q0="`.
- **Minimum code:** the field inserts and the schema entries.
- **Live check:** none here (A9; real packets are [D0]).
- **Done when:** both tests pass and the (a) gate passes.

### Task A3: bounded `l4.flow.get` window

- **Satisfies:** AC2
- **Depends on:** A2
- **Files:** `crates/aitm-proto-l4/src/commands/flow.rs`, `crates/aitm-proto-l4/src/language.rs` (call site only)
- **Change:** in `flow.rs`:
  - `pub const FLOW_GET_DEFAULT_LIMIT: usize = 256;` and `pub const FLOW_GET_MAX_LIMIT: usize = 4096;`
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub(crate) struct PacketWindow { pub(crate) offset: usize, pub(crate) limit: usize }` with `pub(crate) const DEFAULT: PacketWindow = PacketWindow { offset: 0, limit: FLOW_GET_DEFAULT_LIMIT };` and `pub(crate) fn from_params(args: &Params) -> anyhow::Result<PacketWindow>` (absent ⇒ default; negative ⇒ error ``"`offset` must be a non-negative integer"`` / ``"`limit` must be a non-negative integer"``; `limit` clamped to `FLOW_GET_MAX_LIMIT`).
  - `pub(crate) fn flow_to_value(flow: &L4Flow, window: PacketWindow) -> Value`: `packets` is the slice `[offset, offset+limit)` of the log (empty past the end); `packet_count` and `injected_count` stay totals over the whole log; the reply gains `offset` (`Int`).
  - Schema params become `id` (required), `offset` (`Int`, optional, "First packet index to return (default 0)."), `limit` (`Int`, optional, "How many packets to return (default 256, at most 4096; 0 returns none)."); description says list polling should pass `limit: 0`.
  - `language.rs`: the Rhai `l4.flow.get` call passes `PacketWindow::DEFAULT`.
- **Test first** (`cargo test --offline -p aitm-proto-l4 --lib commands::flow::tests::window`): a 300-packet flow → default call returns 256 packets, `packet_count 300`, `offset 0`; `{offset 290, limit 50}` → 10 packets, `offset 290`; `{limit 0}` → `packets []`, `packet_count 300`; a 5000-packet flow with `{limit 100000}` → exactly 4096 packets; `{offset 400}` on the 300-packet flow → `packets []`; `{limit -1}` → `Err` containing ``"`limit` must be a non-negative integer"``; `FlowGet` schema param names are `["id", "offset", "limit"]` with `offset`/`limit` `required: false`.
- **Minimum code:** the window type, the slice, the schema.
- **Live check:** in A9 (`tools/list` inputSchema of `l4.flow.get` has optional `offset` and `limit`).
- **Done when:** tests pass, the (a) gate passes.

### Task A4: honest `capture.status` / `intercept.status` (the D0 seam)

- **Satisfies:** AC3, AC4, AC9 (unit half)
- **Depends on:** A3
- **Files:** `crates/aitm-proto-l4/src/module.rs`, `src/commands/mod.rs`, `src/commands/capture.rs`, `src/commands/intercept.rs`, `tests/surface.rs`, `tests/inpath.rs`
- **Change:**
  - `module.rs`: `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum L4AvailabilityCode { Available, NeedsPrivilege, UnsupportedPlatform, NotConfigured }` with `pub fn as_str(self) -> &'static str` (`"available"`, `"needs_privilege"`, `"unsupported_platform"`, `"not_configured"`); `#[derive(Debug, Clone, PartialEq, Eq)] pub struct L4Availability { pub code: L4AvailabilityCode, pub reason: Option<String> }` with `pub fn available() -> Self` and `pub fn is_available(&self) -> bool`; `impl L4Privilege { pub fn capture_availability(&self) -> L4Availability; pub fn intercept_availability(&self, configured: bool) -> L4Availability }`. The code is derived from the class and the compile-time OS (no new `L4Privilege` field): capture reason `Some` ⇒ `NeedsPrivilege` on macOS and Linux, `UnsupportedPlatform` elsewhere; intercept reason `Some` ⇒ `NeedsPrivilege` on Linux, `UnsupportedPlatform` elsewhere (macOS included); intercept reason `None` and `!configured` ⇒ `NotConfigured` with reason `INTERCEPT_NOT_CONFIGURED`. **Privilege outranks configuration** (so the rig reads `unsupported_platform`, AC4).
  - `module.rs` `load()`: computes both availabilities from the cached `self.privilege` and passes them into the command builders; `gate()` leaves `l4.capture.status` and `l4.intercept.status` unwrapped (a `const NEVER_PRIVILEGE_GATED: [&str; 2]`), so the status verbs and the gated verbs read the same cached probe.
  - `commands/mod.rs`: `wire_commands(guard, store, capture: L4Availability)`; `pub(crate) fn availability_object(av: &L4Availability, payload_key: &str, payload: Vec<Value>) -> Value` → `{available: Bool, code: Str, reason: Str|Null, <payload_key>: Array}`, payload forced to `[]` when unavailable.
  - `capture.rs`: `CaptureStatus::new(registry: Arc<CaptureRegistry>, availability: L4Availability)`; result type `Object{available, code, reason (optional), captures: Array(Str)}`; description: "Report whether capture is available on this core (`available`, `code`, `reason`) and the flow ids of running captures. Always answers, never `L4 unavailable`."
  - `intercept.rs`: `pub(crate) const INTERCEPT_NOT_CONFIGURED: &str = "in-path interception is disabled (no `intercept` config)";` used by `InterceptStart` and the availability; `InterceptStatus::new(sessions, availability)`; `intercept_commands(guard, store, sessions, config, availability: L4Availability)`; result `Object{available, code, reason, sessions: Array(Object(session_fields()))}`.
- **Test first** (`cargo test --offline -p aitm-proto-l4`):
  - `module.rs` tests: `status_verbs_answer_when_privileged`: `L4Module::with_privilege(cfg_with_intercept, L4Privilege::available())` → `l4.capture.status` = `{available: true, code: "available", reason: null, captures: []}`; `l4.intercept.status` = `{available: true, code: "available", reason: null, sessions: []}`. `intercept_status_not_configured`: same privilege, `cfg.intercept = None` → `{available: false, code: "not_configured", reason: "in-path interception is disabled (no `intercept` config)", sessions: []}`. `#[cfg(target_os = "macos")] macos_probe_intercept_is_unsupported_platform`: `L4Privilege::probe().intercept_availability(false)` → `code UnsupportedPlatform`, `reason Some(R_INT)`.
  - `tests/surface.rs` `unprivileged_wire_verbs_unavailable_pure_verbs_work` gains: `l4.capture.status` returns **`Ok`** `{available: false, reason: "missing CAP_NET_RAW / /dev/bpf access", captures: []}` with `code` `"needs_privilege"` on macOS/Linux; `l4.intercept.status` returns `Ok` `{available: false, reason: "missing CAP_NET_ADMIN", sessions: []}` with `code` `"needs_privilege"` on Linux and `"unsupported_platform"` on macOS; `l4.capture.start` still `L4Error::Unavailable` (AC9: the status verbs are not `L4Gated`).
  - `tests/inpath.rs` `intercept_start_fail_closed_via_registry` additionally asserts `l4.intercept.status` is `Ok` with `available: false`.
- **Minimum code:** the types, the two constructors, the gate exemption.
- **Live check:** in A9.
- **Done when:** tests pass, `git diff --stat origin/main...HEAD -- crates/aitm-core` is empty, the (a) gate passes.

### Task A5: `l4.scope.list` provenance

- **Satisfies:** AC5 (the `source` half)
- **Depends on:** A4
- **Files:** `crates/aitm-proto-l4/src/commands/mod.rs`, `src/commands/scope.rs` (tests)
- **Change:** `scope_entry_to_value` inserts `"source"`: `"config"` for `L4ScopeSource::Config`, `"runtime"` for `Runtime`; `scope_entry_fields()` lists `source` (`Str`, required, "`config` (operator config block) or `runtime` (added over the bus)."). Rhai `l4.scope.list` gets the field for free (shared function).
- **Test first** (`cargo test --offline -p aitm-proto-l4 --lib commands::scope::tests`): new `mod tests` in `scope.rs`; `scope_list_reports_source`: a guard built from a config with one entry, plus one entry pushed through the test-only `add_scope` with `source = Runtime` → `l4.scope.list` returns two objects with `source` `"config"` then `"runtime"`.
- **Live check:** in A9.
- **Done when:** test passes, gate passes.

### Task A6: operator scope add through confirm-over-the-wire

- **Satisfies:** AC5, AC6, AC7
- **Depends on:** A5
- **Files:** `crates/aitm-proto-l4/src/guard.rs`, `src/commands/scope.rs`, `src/commands/mod.rs`, `tests/operator_surfaces.rs`, `tests/language.rs`, `crates/aitm/tests/l4_operator_surfaces.rs`
- **Change:**
  - `guard.rs`: `pub(crate) fn add_operator_scope(&self, mut entry: L4ScopeEntry) -> L4ScopeId`: forces `entry.source = L4ScopeSource::Runtime`, pushes, **no** widen check. Doc comment: the only caller is `ScopeAdd`'s trusted-control branch; scripts and agents use `add_runtime_scope`.
  - `commands/mod.rs`: make `cidr_to_string` and `ports_to_string` `pub(crate)`.
  - `scope.rs`: `ScopeAdd::confirm_prompt(&self, args: &Params) -> Option<String>` **always `Some`**: with valid args, `"Confirm l4.scope.add: {capability} scope for {cidr} ports {ports} on {interface} ({direction}), inject rate {pps}pps/{burst}burst. A runtime entry never lifts the dangerous-destination denylist. Re-issue with `_confirm` to add."`; with missing/invalid args (including empty), `"Confirm l4.scope.add: add an L4 scope entry ({error}). Re-issue with `_confirm` to add."`. `invoke` builds the entry, then `if host.caller_is_trusted_control() { self.guard.add_operator_scope(entry) } else { self.guard.add_runtime_scope(entry)? }`. Update the struct doc comment (the widen gate now governs untrusted callers only).
  - `language.rs` is **not** changed: Rhai and the PoC `l4:` step keep `add_runtime_scope`.
- **Test first:**
  - `cargo test --offline -p aitm-proto-l4 --lib`: `scope.rs` `confirm_prompt_some_for_empty_args` (`Params::default()` → `Some(_)`); `confirm_prompt_summarises_entry` (AC5 args `{cidr "127.0.0.1/32", ports "9100-9199", interface "lo0", direction "inbound", capability "capture"}` → contains each of `127.0.0.1/32`, `9100-9199`, `lo0`, `inbound`, `capture`). `guard.rs` `operator_scope_cannot_lift_denylist` (AC7): config with `dangerous_dst_override: true`; `add_operator_scope` of `169.254.169.254/32` eth0 outbound inject (passed in with `source: Config`) → the stored entry's `source == Runtime`, and `check(L4Action::Inject, 169.254.169.254:80 on eth0)` → `Err(L4GuardError::DangerousDestinationBlocked("169.254.169.254".into()))`.
  - `cargo test --offline -p aitm-proto-l4 --test operator_surfaces`: `operator_scope_add_skips_widen_gate`: widen off; `ScopeAdd` invoked with `CommandHost::…with_frontend(Frontend::Operator)` → `Ok(Str(id))` and `l4.scope.list` gains a `source: "runtime"` entry; same with `Frontend::Cli` → `Ok`; with `Frontend::Mcp` → `Err` whose text is `R_WIDEN` and the list is unchanged. Tripwire `add_operator_scope_has_one_caller`: `include_str!` of `src/language.rs`, `src/commands/mod.rs`, `src/commands/agent.rs`, `src/commands/inject.rs` contains no `add_operator_scope`.
  - `cargo test --offline -p aitm-proto-l4 --test language rhai_scope_add_trusted_caller_still_widen_gated` (AC6 unit): a Rhai `l4.scope.add(#{…})` evaluated with a trusted-control caller in its `HostCallCtx` while widen is off → refused with `R_WIDEN`.
  - `cargo test --offline -p aitm --test l4_operator_surfaces`: `operator_scope_add_confirm_handshake`: widen off; operator call → `structuredContent.status == "needs_confirmation"`, a `confirm_token`, the prompt contains the five AC5 strings; re-issue with `_confirm` → a non-error string id; `l4.scope.list` has that id with `source: "runtime"` and the config entries with `source: "config"`; `l4.agent.status.widen == false` before and after; `l4.scope.remove {id}` → `true`. `agent_scope_add_not_offered_confirmation`: `Frontend::Mcp`, policy `All` → `is_error`, text contains `runtime L4 scope widening is disabled`, `structuredContent.confirm_token` is null. `scope_add_is_confirmable_in_tools_list`: `tools/list` entry for `l4.scope.add` has `confirmable: true`. The existing L4OPS-AC5 tests (`auto_refuses_all_sensitive_l4`, `all_requires_the_per_capability_flag`, `agent_cannot_self_grant`) pass **unmodified**.
- **Minimum code:** the guard method, the prompt, the branch.
- **Live check:** in A9 (AC5, AC6 on the rig).
- **Done when:** all tests pass, the (a) gate passes, the security reviewer is told this task is the one that changes an authority path.

### Task A7: per-OS PoC `l4:` default interface

- **Satisfies:** AC8
- **Depends on:** A6
- **Files:** `crates/aitm-proto-l4/src/language.rs`
- **Change:** `DEFAULT_INTERFACE` becomes `"lo0"` under `cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))` and `"lo"` otherwise. Any catalog description text naming `lo` as the default says "`lo0` on macOS/BSD, `lo` on Linux".
- **Test first** (`cargo test --offline -p aitm-proto-l4 --lib language::tests::step_default_interface`): `step_interface(&serde_yaml::from_str("op: craft").unwrap())` equals `"lo0"` under `#[cfg(target_os = "macos")]` and `"lo"` under `#[cfg(target_os = "linux")]`; with `interface: en0` it is `"en0"`.
- **Live check:** live send on lo0 is [D0].
- **Done when:** test passes, gate passes.

### Task A8: e2e shape and docstrings

- **Satisfies:** AC3 (shape), AC32 (the `tests/e2e/l4` part)
- **Depends on:** A7
- **Files:** `tests/e2e/l4/test_l4_capture_flow.py`, `tests/e2e/l4/test_l4_scope_self_exclusion.py`, `crates/aitm/tests/l4_acceptance_mcp.rs` (shape only, if any reads `capture.status`/`flow.get`)
- **Change:** read `l4.capture.status` through a local helper `capture_ids(reply)` that accepts the object (`reply["captures"]`) and the old bare array; when `available` is false, SKIP (77) with the core's `reason`. Replace every claim that pcap capture needs the Network/System Extension ("on macOS the approved+enabled Network/System Extension", "NE/root", "macOS NE", "the L4/NE rig", "approve the extension") with the truth: `l4.capture.start` is pcap/BPF only (`/dev/bpf*` read+write on macOS, `CAP_NET_RAW` on Linux).
- **Test first (tripwire):** `grep -nE "Network Extension|System Extension|NE/root|macOS NE|L4/NE|approve the extension" tests/e2e/l4/*.py` prints nothing (exit 1 from grep); `python3 -m py_compile` on both files exits 0.
- **Live check (rig, (a) build):** `python3 tests/e2e/l4/test_l4_capture_flow.py` exits **77** and its SKIP line contains `R_CAP`.
- **Done when:** tripwire and live output quoted, gate passes.

### Task A9: unprivileged live checks and the blocked-aware privileged walk

- **Satisfies:** AC2 (live), AC3, AC4, AC5, AC6, AC9, AC1/AC8 [D0] verdicts
- **Depends on:** A8
- **Files:** `tests/e2e/l4/test_l4_parity_core.py` (create), `tests/e2e/l4/test_l4_parity_priv.py` (create)
- **Change:** two scripts in the `aitm_e2e` env model (header `# e2e: tier=T1 surface=l4 needs=l4`, exit 0 pass / 1 fail / 77 skip, soft-assert battery like `test_l4_capture_flow.py`).
  - `test_l4_parity_core.py`, as operator and agent: (1) `tools/list`: 25 `l4.*` names; `l4.flow.get` inputSchema has `offset` and `limit`, neither in `required`; `l4.scope.add` `confirmable: true`. (2) AC3: `l4.capture.status` as operator **and** as agent returns, without error, exactly `{available: false, code: "needs_privilege", reason: R_CAP, captures: []}`; `l4.capture.start {interface: "lo0"}` errors with text `L4 unavailable: ` + `R_CAP`. (3) AC4: `l4.intercept.status` = `{available: false, code: "unsupported_platform", reason: R_INT, sessions: []}`; `l4.intercept.start {interface: "lo0"}` errors. (4) AC5: with `l4.agent.status.widen == false`, operator `l4.scope.add` (AC5 args) → `needs_confirmation`, token, prompt with the five strings; re-issue with `_confirm` → id; `l4.scope.list` shows it `source: "runtime"` and the three config entries `source: "config"`; widen still false; `l4.scope.remove {id}` → true. (5) AC6: operator sets agent policy `all` (`agent.set`), agent `l4.scope.add` → error text contains `runtime L4 scope widening is disabled`, no `needs_confirmation`, list unchanged; policy `auto` → refused by policy; restore the original policy. Prints each check's verbatim reply (tokens never printed).
  - `test_l4_parity_priv.py`: the privileged walk from `/tmp/claude/l4-rig/walk4.py` (capture lo0 → real HTTP via the proxy, raw TCP to 9099, UDP to the echo → `l4.flow.get` shows `bytes/timestamp/proto/src/dst/src_port/dst_port` → craft + inject to `127.0.0.1:9053` → `l4.send_recv` gets the echo → inject to an out-of-scope port refused). First step reads `l4.capture.status`; when `available` is false it prints `blocked: needs D0: <reason>` and exits 77.
- **Test first:** `python3 -m py_compile` both; run `test_l4_parity_core.py` against a rig built from `origin/main` (before (a)): it must **fail** (exit 1) on (2) and (4), which shows the script tests the change.
- **Live check:** rig built from this branch: `test_l4_parity_core.py` exits **0**; `test_l4_parity_priv.py` exits **77** printing `blocked: needs D0: ` + `R_CAP`. AC9: `git diff --stat origin/main...HEAD -- crates/aitm-core` prints nothing.
- **Done when:** both runs and the diff check are quoted, the (a) gate passes.

---

## Unit (b) TUI — `fix/l4-parity-tui`

Spec §7(b) file list: `crates/aitm-tui/src/{app.rs, bus.rs, l4.rs, model.rs, filter.rs, keys.rs, action.rs, ui/l4.rs, ui/overlays.rs, ui/flows.rs, ui/sidebar.rs, ui/bars.rs, ui/complete.rs}`, new `crates/aitm-tui/tests/l4_parity.rs`, `crates/aitm/tests/l4_cua_tui.rs`, new `tests/e2e/l4/test_l4_tui_live.py`.

`tests/l4_parity.rs` builds the app with `App::new(TermCaps::from_env(|_| None), "127.0.0.1:27431")`, feeds `App::on_bus(BusEvent::…)` with JSON built in the test, drives `App::update(Action::…)` / `App::run_command(…)`, and asserts on the returned `Vec<BusRequest>` and on `App` state. It never uses `fixture.rs`, `fixture_app_from` or a rendered snapshot as proof. Shared helpers at the top of the file: `l4_tools() -> Vec<ToolInfo>` (the 25 rig `l4.*` names, with `l4.flow.get` declaring `offset`/`limit`), `connected(app)`, `intercept_flow("F")`.

**Row-less L4 surface (plan call):** the TUI has no L4 view without a selected L4 row, and the unprivileged rig has no L4 rows, so AC11 and AC15 need one. B3 adds an **L4 panel** (`Mode::L4`, opened by `:l4` and a key listed in help) showing capture and intercept availability, running captures and the capture commands. The inspector's intercept bar shows the same line when an L4 row is selected.

### Task B1: availability, parked-packet and §2 models

- **Satisfies:** AC10, AC11, AC15 (groundwork)
- **Depends on:** none
- **Files:** `crates/aitm-tui/src/l4.rs`, `src/action.rs`, `tests/l4_parity.rs` (create)
- **Change:**
  - `l4.rs`: `#[derive(Debug, Clone, PartialEq, Eq)] pub struct L4Availability { pub available: bool, pub code: Option<String>, pub reason: Option<String> }` with `pub fn from_reply(v: &Value) -> Self` (object with bool `available` → copy `code`/`reason`; bare array → available; anything else → unavailable, reason `"unrecognised l4 status reply"`), `pub fn from_error(message: &str) -> Option<Self>` (`Some(unavailable, reason = message)` iff it contains `L4 unavailable`), `pub fn pending() -> Self` (unavailable, reason `"reading L4 availability…"`). `pub fn status_ids(v: &Value, key: &str) -> Vec<String>` (object `[key]` or the bare array). `#[derive(Debug, Clone, PartialEq, Eq)] pub struct L4Parked { pub id: String, pub flow: String, pub state: String, pub length: u64, pub layers: Vec<String> }` with `pub fn list_from_json(v: &Value) -> Vec<Self>`. `L4State` gains `pub capture: L4Availability, pub intercept: L4Availability, pub captures: Vec<String>, pub parked: Vec<L4Parked>` and `pub fn parked_for(&self, flow: &str) -> Option<&L4Parked>` (the **first listed** entry for that flow). `L4Packet` gains `timestamp: Option<i64>, proto/src/dst: Option<String>, src_port/dst_port: Option<u16>, bytes: Option<Vec<u8>>` (base64 via `crate::base64`); `L4Flow` gains `started_at: Option<i64>` and flow-level `src/dst/src_port/dst_port`, all optional so an older core still parses. `pub fn supports_window(tools: &[ToolInfo]) -> bool` (the `l4.flow.get` inputSchema `properties` has `limit`) and `pub fn flow_get_args(id: &str, window: bool) -> Value` (`{"id": id, "limit": 0}` / `{"id": id}`).
  - `action.rs`: two new events, `BusEvent::L4Availability { capture: L4Availability, intercept: L4Availability, captures: Vec<String> }` and `BusEvent::L4Parked(Vec<Value>)`.
- **Test first** (`cargo test --offline -p aitm-tui --test l4_parity models`): `from_reply(json!({"available": false, "code": "needs_privilege", "reason": R_CAP, "captures": []}))` → `{available: false, code: Some("needs_privilege"), reason: Some(R_CAP)}`; `from_reply(json!([]))` and `from_reply(json!(["C1"]))` → `available: true`; `from_error("l4.capture.status: L4 unavailable: X")` → `Some(available false, reason Some("l4.capture.status: L4 unavailable: X"))`; `from_error("connection reset")` → `None`; `status_ids(&json!({"captures": ["C1"]}), "captures") == ["C1"]` and `status_ids(&json!(["C1"]), "captures") == ["C1"]`; `L4Parked::list_from_json` of `[{id:"P1", flow:"F", state:"parked", dir:"inbound", length:60, layers:["IPv4","TCP"]}]` → one entry `id "P1"`; `flow_get_args("F", true) == json!({"id":"F","limit":0})`, `(…, false) == json!({"id":"F"})`; an `l4.flow.get` object without the §2 fields still parses (`L4Flow::from_json` is `Some`).
- **Live check:** none here.
- **Done when:** tests pass, the (b) gate passes.

### Task B2: bus polling of status, parked list and windowed list reads

- **Satisfies:** AC11, AC15 (groundwork), spec §2 "list polling uses `limit: 0`", spec §1 "re-read on the slow poll"
- **Depends on:** B1
- **Files:** `crates/aitm-tui/src/bus.rs`, `src/app.rs` (`on_bus` arms), `src/l4.rs` (helper), `tests/l4_parity.rs`
- **Change:** `bus.rs` slow pass: when offered, read `l4.capture.status` and `l4.intercept.status` (a tool error is mapped with `L4Availability::from_error`, a transport error still ends the session) and emit `BusEvent::L4Availability`; read `l4.intercept.list` **only** when the intercept availability just read is `available`, emitting `BusEvent::L4Parked`. `l4_poll` sends `l4::flow_get_args(id, supports_window)`. A pure `pub fn slow_l4_reads(has: impl Fn(&str) -> bool, intercept_available: bool) -> Vec<&'static str>` in `l4.rs` is the list the slow pass walks. `app.rs` `on_bus` stores the availabilities, captures and parked list in `self.l4`; an availability change never toasts.
- **Test first** (`cargo test --offline -p aitm-tui --test l4_parity polling`): `slow_l4_reads(|_| true, false)` contains `"l4.capture.status"` and `"l4.intercept.status"` and **not** `"l4.intercept.list"`; `slow_l4_reads(|_| true, true)` contains `"l4.intercept.list"`; after `on_bus(L4Availability{capture: from_reply(AC3 object), …})`, `app.l4.capture.reason == Some(R_CAP)`.
- **Live check:** with B9 (the audit ring shows no `l4.intercept.list` from `aitm-tui` on the rig).
- **Done when:** tests pass, gate passes.

### Task B3: L4 panel and capture commands

- **Satisfies:** AC15
- **Depends on:** B2
- **Files:** `crates/aitm-tui/src/app.rs`, `src/ui/l4.rs`, `src/keys.rs`, `src/ui/complete.rs`, `src/ui/sidebar.rs` (an L4 entry), `tests/l4_parity.rs`
- **Change:** `Mode::L4` and `pub fn panel(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer)` in `ui/l4.rs`: lines `capture: available` or `capture unavailable — <reason>`, the intercept documented-limited line (B4), running capture ids, and hints for `:l4 capture <iface> [inbound|outbound]` and `:l4 stop [<id>]`. `run_command`: `l4` with no args opens the panel; `l4 capture <iface> [inbound|outbound]`: when `self.l4.capture.available` is false, **no request**, toast `capture unavailable: <reason>`; else `BusRequest::Call { name: "l4.capture.start", args: {"interface", "direction"} }` (direction default `inbound`; another word → toast `direction must be inbound or outbound`, no request). `l4 stop <id>` → one `l4.capture.stop {id}`; `l4 stop` → one per id in `self.l4.captures` (none → toast `no running capture`). Completion offers `capture`, `stop`, interface names from `l4.interfaces` when known, and `inbound`/`outbound`. Help lists the commands and the panel key.
- **Test first** (`cargo test --offline -p aitm-tui --test l4_parity capture_commands`): capture unavailable (AC3 object) → `run_command("l4 capture lo0") == vec![]` and the current toast contains `R_CAP`; capture available → `run_command("l4 capture lo0") == vec![Call{name: "l4.capture.start", args: json!({"interface":"lo0","direction":"inbound"})}]` and `"l4 capture lo0 outbound"` → direction `"outbound"`; `"l4 capture lo0 sideways"` → `vec![]`; with captures `["C1","C2"]`, `run_command("l4 stop")` → two calls `{"id":"C1"}`, `{"id":"C2"}`; `run_command("l4 stop C1")` → one call.
- **Live check:** in B9 (AC15 [now]).
- **Done when:** tests pass, gate passes.

### Task B4: Forward / Drop by parked id, documented-limited bar

- **Satisfies:** AC10, AC11
- **Depends on:** B3
- **Files:** `crates/aitm-tui/src/app.rs` (`l4_intercept_verb`), `src/ui/l4.rs` (intercept bar), `tests/l4_parity.rs`
- **Change:** `fn l4_intercept_verb(&mut self, tool: &str, flow: &crate::l4::L4Flow) -> Vec<BusRequest>`: if `!self.l4.intercept.available` → toast `in-path intercept unavailable: <reason>`, no request; else take `self.l4.parked_for(&flow.id)` (none → toast `no parked packet on this flow`, no request) and send `json!({"id": parked.id})`, keeping the existing scope gate and `self.l4.pending` for the confirm overlay. The flow id is never sent. The inspector bar and the L4 panel render one documented-limited line with the core's `reason` when intercept is unavailable, with no key hints for Forward/Drop/Mutate.
- **Test first** (`cargo test --offline -p aitm-tui --test l4_parity parked_id`): intercept available, flow `F` selected, parked `[{id "P1", flow "F"}]` → `update(Action::Resume) == vec![Call{name: "l4.intercept.forward", args: json!({"id":"P1"})}]`, `update(Action::Kill)` → the same with `"l4.intercept.drop"`; no emitted args ever equal `json!({"id":"F"})`; no parked entry → `vec![]`; intercept unavailable (AC4 object) → `vec![]` for Resume, Kill and Edit, toast contains `R_INT`.
- **Live check:** AC11 in B9; live forward on a parked packet is [Linux].
- **Done when:** tests pass, gate passes.

### Task B5: Mutate and Revert from the craft pane

- **Satisfies:** AC12
- **Depends on:** B4
- **Files:** `crates/aitm-tui/src/action.rs` (`Action::L4MutateParked`, `Action::L4RevertParked`), `src/app.rs`, `src/keys.rs`, `src/ui/l4.rs` (craft pane hints), `tests/l4_parity.rs`
- **Change:** in the craft pane of an intercept flow with a parked packet and intercept available, "apply to parked packet" sends `l4.intercept.mutate {id: <parked id>, spec: <the spec the craft pane's Build sends to l4.craft for the same buffer>}`; "revert" sends `l4.intercept.revert {id}`. Same unavailable/no-parked/scope refusals as B4. Keys are the builder's; help lists them.
- **Test first** (`cargo test --offline -p aitm-tui --test l4_parity mutate`): with a craft buffer set in the test, capture the `spec` the Build action sends to `l4.craft`; then `update(Action::L4MutateParked) == vec![Call{name: "l4.intercept.mutate", args: json!({"id":"P1","spec": <that spec>})}]`; `update(Action::L4RevertParked) == vec![Call{name: "l4.intercept.revert", args: json!({"id":"P1"})}]`; intercept unavailable → both `vec![]`.
- **Live check:** [Linux].
- **Done when:** tests pass, gate passes.

### Task B6: L4 scope section and `:scope add l4`

- **Satisfies:** AC13
- **Depends on:** B5
- **Files:** `crates/aitm-tui/src/app.rs` (`run_command` `scope`, `CallOk` routing), `src/l4.rs` (`L4ScopeEntry` gains `id: Option<String>`, `source: Option<String>`), `src/ui/overlays.rs` (`scope` panel), `src/ui/complete.rs`, `tests/l4_parity.rs`
- **Change:** the scope panel gains an "L4 scope" section listing `self.l4.scope` (interface, cidr, ports, direction, capability, `config`/`runtime`). `scope add l4 <cidr> <ports> <iface> <inbound|outbound> <capture|inject|intercept>` → `BusRequest::Call { name: "l4.scope.add", args: {"cidr","ports","interface","direction","capability"} }`; a wrong arity or word → toast with the usage line, no request. A `needs_confirmation` reply to `l4.scope.add` opens the existing `Mode::L4Confirm` with the core's prompt (add `"l4.scope.add"` to the `CallOk` arms that parse `L4Confirm::from_reply`); confirming re-issues with `_confirm`; success re-reads `l4.scope.list` on the next slow pass. `scope add <host>` is unchanged. Completion offers `l4` after `scope add`.
- **Test first** (`cargo test --offline -p aitm-tui --test l4_parity scope_add_l4`): `run_command("scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture") == vec![Call{name: "l4.scope.add", args: json!({"cidr":"127.0.0.1/32","ports":"9100-9199","interface":"lo0","direction":"inbound","capability":"capture"})}]`; then `on_bus(CallOk{name: "l4.scope.add", value: json!({"status":"needs_confirmation","prompt":"P","confirm_token":"tok-1"})})` → `app.mode == Mode::L4Confirm`, the confirm's prompt `"P"`; confirming emits the same call with `"_confirm": "tok-1"`; `run_command("scope add l4 127.0.0.1/32")` → `vec![]`; `run_command("scope add api.test") == vec![BusRequest::ScopeAdd("api.test".into())]`.
- **Live check:** AC13 in B9 (needs the `local/l4par-tui-with-core` build).
- **Done when:** tests pass, gate passes.

### Task B7: L4 chips, filter atoms, help

- **Satisfies:** AC14
- **Depends on:** B6
- **Files:** `crates/aitm-tui/src/app.rs` (`Chip`), `src/filter.rs`, `src/keys.rs` (help), `src/ui/bars.rs` (chip bar, filter hint), `src/ui/complete.rs` (filter completion), `src/ui/flows.rs` (only if the row needs the proto for the chip), `tests/l4_parity.rs`
- **Change:** `Chip::{Tcp, Udp, L4}` after `WebSocket` (`Chip::ALL` becomes 18 long: `All, Http, Https, WebSocket, Tcp, Udp, L4, H1, H2, Json, …`), labels `TCP`, `UDP`, `L4`; `L4` matches `row.kind == FlowKind::L4`, `Tcp`/`Udp` match `row.l4.proto == "TCP"/"UDP"`. `filter.rs` atoms `~l4`, `~tcp`, `~udp`, `~icmp` (`Expr::L4`, `Expr::L4Proto(&'static str)`), documented in the module header. Help and the filter hint list `~l4 ~tcp ~udp ~icmp`.
- **Test first** (`cargo test --offline -p aitm-tui --test l4_parity chips_filters` and `cargo test --offline -p aitm-tui --lib filter`): with an L4 row from `FlowRow::from_l4` (TCP layers) and an HTTP row built in the test: `parse("~l4")` matches the L4 row only; `parse("~tcp")` matches it, `parse("~udp")` does not; `parse("~icmp")` parses; `Chip::L4.matches` is false for the HTTP row; `Chip::ALL[4..7]` labels are `["TCP","UDP","L4"]`; the help text contains `~l4 ~tcp ~udp ~icmp`.
- **Live check:** AC14 in B9.
- **Done when:** tests pass, gate passes.

### Task B8: no HTTP verbs on L4 rows, honest agent overlay

- **Satisfies:** AC16, AC17
- **Depends on:** B7
- **Files:** `crates/aitm-tui/src/app.rs`, `src/model.rs` (`AgentPolicy`), `src/ui/overlays.rs`, `src/keys.rs`, `src/ui/bars.rs` (policy colour match), `tests/l4_parity.rs`
- **Change:**
  - On a selected row with `kind == FlowKind::L4`, `Action::Mark` (and the mark it would emit), `Comment`, `Replay`, `BuildPoc` emit no request and toast `<Verb> is not available for L4 flows`.
  - D10c root cause: the core's policies are `all | auto | ask | readonly | paused`; the TUI's `AgentPolicy` knows only three, so `apply_status` drops `auto` (the rig default) and the overlay falls back to the stale F1 line. Add `AgentPolicy::Auto` and `AgentPolicy::Ask` (parse/wire/label `"auto"`, `"ask"`), list them in the overlay with keys listed in help, and replace the `None` branch text with `agent policy not reported by agent.status`. Remove every `core follow-up F1` reference that is no longer true (`app.rs` `Action::AgentSet` toast → `agent.set is not on this bus`; the CA panel line in `ui/overlays.rs` describes what install/uninstall do now, checked against `app.rs`).
- **Test first** (`cargo test --offline -p aitm-tui --test l4_parity -- no_http_verbs_on_l4 agent_overlay`): L4 row selected → `update(Action::Replay)`, `Mark` (and the mark pick), `Comment` submit, `BuildPoc` each `== vec![]`, toast contains `not available for L4 flows`; an HTTP row → `Replay` still emits `BusRequest::Replay(id)`. `AgentPolicy::parse("auto") == Some(AgentPolicy::Auto)`, `parse("ask") == Some(AgentPolicy::Ask)`; `AgentState::apply_status(&json!({"policy":"auto","actions_last_minute":0,"connected_clients":[]}))` → `policy == Some(Auto)`. **Tripwire** `no_stale_f1_in_tui_src`: walk `concat!(env!("CARGO_MANIFEST_DIR"), "/src")`, and assert no file contains `core follow-up F1` **followed by a non-digit or end of text** (the spec's literal string is a prefix of the live `F10`/`F12`/`F13`/`F14`/`F15` notes, which stay).
- **Live check:** AC16 with a real L4 row is [D0]; AC17 in B9.
- **Done when:** tests pass, gate passes.

### Task B9: live TUI against the rig, real-core CUA update

- **Satisfies:** AC11, AC13, AC14, AC15, AC17, AC33 (TUI half)
- **Depends on:** B8
- **Files:** `tests/e2e/l4/test_l4_tui_live.py` (create), `crates/aitm/tests/l4_cua_tui.rs` (modify)
- **Change:**
  - `test_l4_tui_live.py`: spawn the worktree's `aitm-tui` in a pty (the `Terminal` class from `tests/e2e/tui/test_tui_intercept.py`, 160×44, `--token-file`), against `AITM_BUS_ADDR`; a separate operator `BusClient` reads `agent.activity`. Checks: (AC17) open the Agent overlay → first line starts `policy: auto ·` (or the rig's current policy); (AC15) open the L4 panel → `capture unavailable` and `R_CAP` on screen; type `:l4 capture lo0` → screen shows the reason and the audit ring has **no** `l4.capture.start` from `aitm-tui` since t0; (AC11) the panel's intercept line shows `R_INT`; press the Forward/Drop/Mutate keys → no `l4.intercept.*` from `aitm-tui`; (AC14) with real HTTP rows on screen, the `L4` chip is visible, help shows `~l4 ~tcp ~udp ~icmp`, `/~l4` leaves zero HTTP rows; (AC13, with (a)) the scope panel shows the "L4 scope" section with the three config entries (lo0, 127.0.0.1/32, 9000-9999, capture/inject/intercept); `:scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture` opens a confirm with the core's prompt, `y` adds it, the entry appears within one slow poll, then remove it over the bus; `:scope add 127.0.0.1:9100` still adds HTTP scope (removed after). (AC33) no `L4 unavailable` result in the audit ring for `aitm-tui` after any enabled control. Prints each screen region checked.
  - `l4_cua_tui.rs`: its intercept and capture steps follow the new behaviour (parked-id verdicts; documented-limited bar on this unprivileged host; `:l4 capture` refused locally with the reason); it stays a real spawned core and bus. Run in the Terminal: `cargo test -p aitm --test l4_cua_tui -- --nocapture`.
- **Test first:** run `test_l4_tui_live.py` against `origin/main`'s `aitm-tui` on the rig: it must fail (no L4 panel, stale F1 line).
- **Live check:** on the `local/l4par-tui-with-core` rig: `test_l4_tui_live.py` exits 0 with output quoted; on this branch alone the AC13 block reports `needs (a)` and the rest pass. Verdicts quoted for AC10/AC12 `[Linux]` and AC14/AC15/AC16 `[D0]` halves.
- **Done when:** live output and the Terminal `l4_cua_tui` run quoted, the (b) gate passes.

---

## Unit (c) web — `fix/l4-parity-web`

Spec §7(c) file list: `apps/web/src/panels/l4/{store.ts, model.ts, CaptureControls.tsx, L4CaptureBar.tsx, L4InterceptBar.tsx, L4InspectorPanel.tsx, L4Inspector.tsx, PacketList.tsx, LayerTree.tsx, model.test.ts}`, new `apps/web/src/panels/l4/args.test.ts`, `apps/web/src/panels/agent/L4Toggles.tsx`, `apps/web/src/shell/{chips.ts, shortcuts.ts, RoleBanner.tsx}`, `apps/web/src/state/app.ts`, `apps/web/src/flows/{FlowList.tsx, ContextMenu.tsx}`, `apps/web/src/bus/noise.ts`, `apps/web/scripts/{cua-l4.mjs, CUA-L4-RUN-RECORD.md}`.

Placement rules that keep (c) inside its list: **every pure builder and rule lives in `panels/l4/model.ts`** (the spec lists `args.test.ts` but no `args.ts`); the 1.5 s timer in `state/context.tsx` (not in the list) is untouched, and **the back-off lives inside `store.refresh()`**, which returns early when its poll plan says nothing is due; the `noise.ts` test case goes in `args.test.ts` unless the orchestrator adds `apps/web/src/bus/noise.test.ts` to the claim (it is not in spec §7(c)).

Web tests run with `cd apps/web && npx vitest run src/panels/l4/<file>` (red first), then the full web gate.

### Task C1: wire types, availability, argument builders

- **Satisfies:** AC18 (unit), AC19 (unit), AC20 (unit), compatibility rule spec §1
- **Depends on:** none
- **Files:** `apps/web/src/panels/l4/model.ts`, `apps/web/src/panels/l4/args.test.ts` (create)
- **Change** (exports from `model.ts`):
  - `L4PacketWire` gains optional `bytes?: string; timestamp?: number; proto?: string | null; src?: string | null; dst?: string | null; src_port?: number | null; dst_port?: number | null`; `L4FlowWire` gains optional `started_at`, `proto`, `src`, `dst`, `src_port`, `dst_port`, `offset`; `L4ScopeEntryWire` gains `source?: 'config' | 'runtime'`; `interface L4ParkedWire { id: string; flow: string; state: 'parked' | 'mutated'; dir: 'inbound' | 'outbound'; length: number; layers: string[] }`. Update the "no raw bytes" comment.
  - `interface L4Availability { available: boolean; code: string | null; reason: string | null }`; `availabilityFromReply(reply: unknown): L4Availability`; `availabilityFromError(message: string): L4Availability | null`; `statusIds(reply: unknown, key: 'captures' | 'sessions'): unknown[]`; `PENDING_AVAILABILITY` (`available: false`, reason `Reading L4 availability…`).
  - `captureStartArgs(iface: string, direction: 'inbound' | 'outbound')`, `captureStopArgs(id: string)`, `stopAllArgs(ids: readonly string[])`, `verdictArgs(parkedId: string)`, `mutateArgs(parkedId: string, spec: PacketSpec)`, `revertArgs(parkedId: string)`, `interface L4ScopeDraft { cidr; ports; interface; direction; capability }`, `scopeAddArgs(d: L4ScopeDraft)`, `supportsFlowWindow(tools: readonly { name: string; inputSchema?: unknown }[]): boolean`, `flowGetArgs(id: string, mode: 'list' | 'inspect', window: boolean)`, `parkedFor(parked: readonly L4ParkedWire[], flowId: string): L4ParkedWire | null` (first listed), and `L4_ARG_BUILDERS: readonly { tool: string; keys: readonly string[] }[]` (every builder's tool and emitted keys).
- **Test first** (`npx vitest run src/panels/l4/args.test.ts`): `captureStartArgs('lo0','inbound')` deep-equals `{interface: 'lo0', direction: 'inbound'}` and `Object.keys` is exactly `['interface','direction']`; `stopAllArgs(['C1','C2'])` → `[{id:'C1'},{id:'C2'}]`; `verdictArgs('P1')` → `{id:'P1'}`; `mutateArgs('P1', spec)` → `{id:'P1', spec}`; `revertArgs('P1')` → `{id:'P1'}`; `scopeAddArgs(AC5 draft)` → `{cidr:'127.0.0.1/32', ports:'9100-9199', interface:'lo0', direction:'inbound', capability:'capture'}`; `flowGetArgs('F','list',true)` → `{id:'F', limit:0}`, `('F','inspect',true)` → `{id:'F', offset:0, limit:256}`, `('F','list',false)` → `{id:'F'}`; `availabilityFromReply({available:false, code:'needs_privilege', reason:R_CAP, captures:[]})` → `{available:false, code:'needs_privilege', reason:R_CAP}`; `availabilityFromReply([])` → `{available:true, code:null, reason:null}`; `availabilityFromError('l4.capture.status: L4 unavailable: X')` → `{available:false, code:null, reason:'l4.capture.status: L4 unavailable: X'}`; `availabilityFromError('boom')` → `null`; `parkedFor([{id:'P1',flow:'F',…},{id:'P2',flow:'G',…}], 'G').id === 'P2'`. **Live schema check** in the same file, `describe.skipIf(!process.env.AITM_BUS_ADDR)`: connect over TCP to `AITM_BUS_ADDR` with `AITM_BUS_OPERATOR_TOKEN`, read `tools/list`, and assert every `L4_ARG_BUILDERS` key is a property of that tool's `inputSchema` (it is skipped in the gate and run by hand on the rig in C10).
- **Live check:** the schema block in C10 (AC18 live).
- **Done when:** tests pass, the (c) gate passes.

### Task C2: poll plan and once-per-message logging

- **Satisfies:** AC23 (unit)
- **Depends on:** C1
- **Files:** `apps/web/src/panels/l4/model.ts`, `apps/web/src/panels/l4/model.test.ts`
- **Change:** `L4_ACTIVE_MS = 1500`, `L4_IDLE_FLOW_MS = 10_000`, `L4_IDLE_SLOW_MS = 60_000`; `interface L4PollClock { lastFlowAt: number | null; lastSlowAt: number | null }`; `l4PollPlan(now: number, clock: L4PollClock, idle: boolean): { flows: boolean; slow: boolean }` (`idle` = capture unavailable and `l4.flow.list` empty; not idle ⇒ both every call; idle ⇒ `flows` when ≥ 10 s since `lastFlowAt`, `slow` when ≥ 60 s since `lastSlowAt`, both on the first call); `createOnceLog(sink: (msg: string) => void): { log(msg: string): void; clear(): void }`. "Slow" is `l4.capture.status`, `l4.intercept.status`, `l4.scope.list`, `l4.agent.status`.
- **Test first** (`npx vitest run src/panels/l4/model.test.ts`): simulate calls at `t = 0, 1500, …, 58500` (40 calls) with `idle = true`, updating the clock when a plan fires → `flows` fires **6** times and `slow` **1** time, so `l4.*` calls in the minute = 6 + 4 = **10** (≤ 12); with `idle = false` → `flows` 40 times; `createOnceLog` given `['a','a','b','a']` calls the sink with `['a','b']`.
- **Live check:** AC23 in C10.
- **Done when:** tests pass, gate passes.

### Task C3: store wiring, windowed reads, honest noise rule

- **Satisfies:** AC20, AC23, spec §1 (re-read on the slow poll), §2 (list `limit: 0`)
- **Depends on:** C2
- **Files:** `apps/web/src/panels/l4/store.ts`, `apps/web/src/bus/noise.ts`, `apps/web/src/panels/l4/args.test.ts` (noise case; or `bus/noise.test.ts` if the orchestrator adds it to the claim)
- **Change:** `store.ts`: signals `captureAvailability`, `interceptAvailability` (start `PENDING_AVAILABILITY`), `parked: L4ParkedWire[]`, `inspected: L4FlowWire | null`; `refresh()` follows `l4PollPlan` (keeps a `L4PollClock`), reads the status verbs through `availabilityFromReply` / `availabilityFromError`, reads `l4.intercept.list` only when intercept is available, reads rows with `flowGetArgs(id, 'list', window)`, and routes read failures through `createOnceLog` into `app.notice`. `inspect(id)` fetches `flowGetArgs(id, 'inspect', window)` when the selection changes. Actions: `startCapture(iface, direction)`, `stopCapture(id)`, `forward/drop(parkedId)`, `mutate(parkedId, spec)`, `revert(parkedId)` (C5 uses them), all through the C1 builders. Remove `firstParkedId`. `noise.ts`: `l4.flow.get` is a background read **only** in the poll shape `{id, limit: 0}` (`isPollL4Get(args)`), because the inspector's window read now returns packet bytes; the doc comment says so.
- **Test first:** noise case: `isUiPollNoise({origin:'operator', command:'l4.flow.get', result:'ok', clientLabel:null, args:{id:'x', limit:0}}, {origin:'operator'}) === true` and with `args: {id:'x', offset:0, limit:256}` → `false`; `flow.detail` cases unchanged. Store wiring has no unit test of its own: its rules are C1/C2; it is proven live.
- **Live check:** AC23 in C10.
- **Done when:** test passes, gate passes.

### Task C4: capture controls

- **Satisfies:** AC18, AC19
- **Depends on:** C3
- **Files:** `apps/web/src/panels/l4/CaptureControls.tsx`, `apps/web/src/panels/l4/L4CaptureBar.tsx`, `apps/web/src/panels/l4/args.test.ts` (tripwire)
- **Change:** the filter input is replaced by a direction `<select>` (`inbound` / `outbound`, default `inbound`); Start capture calls `store.startCapture(iface, direction)`; when capture is unavailable, Start is disabled and the core's `reason` is visible text beside it (and its `title`); a Stop button per running capture id calls `store.stopCapture(id)`; props become `{ capture: L4Availability; running: readonly string[]; … }`.
- **Test first (tripwire)** in `args.test.ts`: read every non-test `.ts`/`.tsx` under `apps/web/src` (node `fs`), and assert no `l4.capture.start` call site passes a `filter` key (regex over the call's argument text, plus: the file `CaptureControls.tsx` contains no `filter` prop).
- **Live check:** AC19 in C10.
- **Done when:** test passes, gate passes.

### Task C5: intercept bar by parked id, documented-limited line

- **Satisfies:** AC20
- **Depends on:** C4
- **Files:** `apps/web/src/panels/l4/L4InterceptBar.tsx`, `L4InspectorPanel.tsx`, `L4Inspector.tsx`, `L4CaptureBar.tsx`, `model.ts`, `model.test.ts`
- **Change:** `model.ts` `interceptBarModel(avail: L4Availability, parked: readonly L4ParkedWire[], flowId: string | null): { kind: 'limited'; reason: string } | { kind: 'idle' } | { kind: 'parked'; id: string }`. When intercept is unavailable, the bar is one documented-limited line `In-path intercept is not available on this core: <reason>` with no Forward/Mutate/Drop buttons; the L4 focus view (`L4CaptureBar`) shows the same line so it is visible with no L4 row. Otherwise Forward/Drop go through the existing confirm path with `verdictArgs(parked.id)`; Mutate sends `mutateArgs(parked.id, <the craft editor's current spec>)`; Revert sends `revertArgs(parked.id)`. The "author the mutation…" stub notice is gone.
- **Test first** (`model.test.ts`): `interceptBarModel(AC4 availability, [], 'F')` → `{kind:'limited', reason:R_INT}`; available with `[{id:'P1', flow:'F'}]` → `{kind:'parked', id:'P1'}`; available with none for `F` → `{kind:'idle'}`.
- **Live check:** AC20 in C10; live verdicts are [Linux].
- **Done when:** tests pass, gate passes.

### Task C6: packet time, addresses and hex in the inspector

- **Satisfies:** spec Goal "packets carry bytes, timestamp…" for the web inspector (no own AC; real packets are [D0])
- **Depends on:** C5
- **Files:** `apps/web/src/panels/l4/PacketList.tsx`, `LayerTree.tsx`, `L4Inspector.tsx`, `model.ts`, `model.test.ts`
- **Change:** `packetHeadline(p: L4PacketWire): string` (`127.0.0.1:40000 → 127.0.0.1:9053 · UDP · 36 B`, falling back to the layer summary when addresses are null) and `formatPacketTime(ms: number): string` (local `HH:MM:SS.mmm`); the packet list shows time and headline; the inspector shows a hex dump of `bytes` (via `lib/bytes.base64ToBytes`) for the inspected window, and says "no bytes from this core" against an older core.
- **Test first** (`model.test.ts`): `packetHeadline({dir:'outbound', length:36, injected:false, layers:['IPv4','UDP'], proto:'UDP', src:'127.0.0.1', dst:'127.0.0.1', src_port:40000, dst_port:9053})` → `'127.0.0.1:40000 → 127.0.0.1:9053 · UDP · 36 B'`; with null addresses → `'IPv4 · UDP · 36 B'`.
- **Live check:** `blocked: needs D0` (no captured packet on the rig), quoted in C10.
- **Done when:** tests pass, gate passes.

### Task C7: L4 scope add with the operator confirm

- **Satisfies:** AC22
- **Depends on:** C6
- **Files:** `apps/web/src/panels/l4/CaptureControls.tsx`, `apps/web/src/panels/l4/store.ts`
- **Change:** the scope list shows `config` / `runtime` per entry; an add form (cidr, ports, interface, direction select, capability select) calls `store.addScope(draft)`, which uses `beginGuarded`/`confirmGuarded` from `inject.ts` with `scopeAddArgs(draft)` and shows the existing `ConfirmInject` dialog (imported, not edited) with the core's prompt; on success it re-reads `l4.scope.list`. Validation messages come from the core's reply.
- **Test first:** the builder is C1's (`scopeAddArgs`). Red check: on the `local/l4par-web-with-core` rig before this task, the form does not exist (AC22 live fails).
- **Live check:** AC22 in C10 (with (a)).
- **Done when:** gate passes.

### Task C8: TCP / UDP / L4 chips

- **Satisfies:** AC21
- **Depends on:** C7
- **Files:** `apps/web/src/shell/chips.ts`, `apps/web/src/state/app.ts` (`Chip`, `matchesChip`), `apps/web/src/flows/FlowList.tsx`, `apps/web/src/shell/shortcuts.ts` (only if ⌘-digits do not already follow `CHIPS` order), `apps/web/src/panels/l4/model.ts`, `model.test.ts`
- **Change:** `Chip` gains `'tcp' | 'udp' | 'l4'`; `CHIPS` gets `{id:'tcp', label:'TCP', group:true}, {id:'udp', label:'UDP'}, {id:'l4', label:'L4'}` after WebSocket, and `h1` keeps `group: true`; `model.ts` `isL4Chip(chip): boolean` and `l4ChipMatches(chip, row: UnionRow): boolean` (`l4` ⇒ every L4 row, `tcp`/`udp` ⇒ by the row's proto); `matchesChip` returns `false` for an L4 chip (no HTTP row passes); `FlowList` shows L4 rows under `all` and under the matching L4 chip. ⌘1–⌘9 follow bar order, so ⌘5 is TCP.
- **Test first** (`model.test.ts`): `CHIPS.map(c => c.label).slice(0, 9)` → `['All','HTTP','HTTPS','WebSocket','TCP','UDP','L4','h1','h2']`; `CHIPS[4].id === 'tcp'`; `l4ChipMatches('tcp', <TCP row>) === true`, `('udp', <TCP row>) === false`, `('l4', <UDP row>) === true`; `isL4Chip('http') === false`.
- **Live check:** AC21 in C10.
- **Done when:** tests pass, gate passes.

### Task C9: agent role, no HTTP verbs on L4 ids, operator-URL hint

- **Satisfies:** AC24, D9 (web), D12
- **Depends on:** C8
- **Files:** `apps/web/src/panels/agent/L4Toggles.tsx`, `apps/web/src/panels/l4/CaptureControls.tsx`, `L4InterceptBar.tsx`, `L4Inspector.tsx`, `apps/web/src/shell/RoleBanner.tsx`, `apps/web/src/flows/ContextMenu.tsx`, `apps/web/src/flows/FlowList.tsx`, `apps/web/src/shell/shortcuts.ts`, `apps/web/src/panels/l4/model.ts`, `model.test.ts`
- **Change:** `model.ts` `operatorOnlyReason(role: 'operator' | 'agent' | null): string | null` → `null` for `'operator'`, else `Operator only: reconnect with the Operator URL the core printed`; `httpVerbAllowed(id: string, l4Ids: ReadonlySet<string>): boolean`. On a non-operator connection, Start/Stop capture, Inject, scope add, Forward/Drop/Mutate/Revert and the four gate toggles render disabled with that reason and their handlers return before any `app.call`. The role banner, on an agent connection with L4 present, adds one line that L4 actions need the Operator URL. Replay/mark/comment/PoC (context menu and keys) return without a bus call when the selected id is an L4 id.
- **Test first** (`model.test.ts`): `operatorOnlyReason('operator') === null`; `operatorOnlyReason('agent')` and `(null)` equal the literal above; `httpVerbAllowed('l4-1', new Set(['l4-1'])) === false`, `('h-1', …) === true`.
- **Live check:** AC24 in C10.
- **Done when:** tests pass, gate passes.

### Task C10: live browser run on the rig

- **Satisfies:** AC18 (live), AC19, AC20, AC21, AC22, AC23, AC24, AC33 (web half)
- **Depends on:** C9
- **Files:** `apps/web/scripts/cua-l4.mjs`, `apps/web/scripts/CUA-L4-RUN-RECORD.md`
- **Change:** `cua-l4.mjs` (a real spawned `l4.enabled` core and real Chrome over CDP, as today) asserts the new behaviour: Start capture disabled showing `R_CAP`; the intercept line showing `R_INT` with no enabled Forward/Mutate/Drop; the chip bar order and ⌘5; the L4 scope add through the confirm dialog (when the spawned core has (a)); 60 s idle as operator → no L4 error entries in the activity log and ≤ 12 `l4.*` calls from `web-bridge` in `agent.activity`; on the agent URL every Sensitive L4 control disabled with the operator-only reason and none reaching `agent.activity`. Replace the old "`capture.status` succeeding ⇒ privileged" probe with `capture.status.available` (old shape tolerated). `CUA-L4-RUN-RECORD.md` records this run: date, SHAs, each step's PASS/FAIL/blocked line.
- **Test first:** run the updated `cua-l4.mjs` against an `origin/main` build: the new assertions FAIL.
- **Live check (Terminal, `local/l4par-web-with-core` build, `npm run build` then the release build):** `node apps/web/scripts/cua-l4.mjs` all PASS or explicit `blocked: needs D0`; `AITM_BUS_ADDR=… AITM_BUS_OPERATOR_TOKEN=… npx vitest run src/panels/l4/args.test.ts` runs the live schema block and passes (AC18). Then the in-app browser at the rig's Operator URL, light and dark: the L4 focus view (Start disabled + `R_CAP`, intercept line + `R_INT`), the chip bar with real proxied HTTP rows and `L4` selected showing zero HTTP rows, the scope add confirm, and the agent URL's disabled controls. Screenshots looked at and described in the report. Also run on this branch alone against an `origin/main` core (old status shapes): no crash, Start disabled with the old error text as reason.
- **Done when:** run output, record and screenshots delivered, the (c) gate passes.

---

## Unit (d) macOS — `fix/l4-parity-mac`

Spec §7(d) file list: `apps/mac/Sources/Aitmproxy/Bus/BusService.swift`, `Sources/Aitmproxy/Session.swift`, `Sources/Aitmproxy/Session+Verbs.swift`, `Sources/Aitmproxy/Inspector/L4Inspector.swift`, `Sources/Aitmproxy/Panels/ScopePanel.swift`, `Sources/Aitmproxy/Panels/ScopeSheet.swift`, `Sources/AitmproxyKit/L4.swift`, `Tests/AitmproxyKitTests/L4Tests.swift`, new `apps/mac/tools/check-l4-live.sh`, new `apps/mac/tools/cua-l4-live.sh`, `Sources/Aitmproxy/SelfTest+Live.swift` only if it survives `R`. Not touched: `apps/mac/Extension`, anything `R` removes, `ContentCategory.swift`.

Placement rules that keep (d) inside its list: the context-action model is `VerbTable.swift` (Kit, not listed), so the L4 verb gate is a pure function in `L4.swift` applied by `Session+Verbs.swift`; the craft editor's starting text moves from `L4Inspector.swift` (app target) into Kit as `PacketSpecDraft.sample` so a Kit unit can test it.

**Row-less L4 surface (plan call, question 1 below):** with no L4 rows on the unprivileged rig, the L4 inspector is unreachable, yet AC26–AC28 are tagged [now]. The plan's default: the **Scope page's new L4 section** (D7) is the row-less L4 home. It shows the capture and intercept availability lines with the core's reasons, the L4 scope list and add, and a "Craft packet…" button that opens `L4Inspector` in a row-less craft mode (D5). No synthetic row is created.

Kit tests: `cd apps/mac && swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build --filter L4Tests` (Terminal), red first.

### Task D1: availability from the status replies, parked-id verdict args

- **Satisfies:** AC26 (Kit), AC28 (Kit)
- **Depends on:** none
- **Files:** `apps/mac/Sources/AitmproxyKit/L4.swift`, `apps/mac/Tests/AitmproxyKitTests/L4Tests.swift`
- **Change:** `L4Availability` drops `embeddedReason` and `resolve(embeddedCore:wireError:)` and gains `public static func resolve(status: JSONValue?, error: String?) -> L4Availability` (object with bool `available`: `true` ⇒ `.available`, `false` ⇒ `.degraded(reason: reason ?? "L4 unavailable")`; bare array ⇒ `.available`; no status and an error ⇒ `.degraded(reason: error)`; neither ⇒ `.pending`) and `public static let pending = L4Availability.degraded(reason: "Reading L4 availability from the core…")`. `public struct L4ParkedPacket: Hashable, Sendable { public let id: String; public let flow: FlowID; public let state: String; public let length: Int; public let layers: [String] }` with `public static func list(_ json: JSONValue) -> [L4ParkedPacket]` and `public static func first(for flow: FlowID, in parked: [L4ParkedPacket]) -> L4ParkedPacket?` (first listed). `public enum L4Verdict { public static func args(parkedID: String) -> [String: JSONValue] }`. Old tests of the removed API are replaced.
- **Test first:** `testResolveReadsStatusObject`: AC3 object → `.degraded(reason: R_CAP)`; `["available": true]` → `.available`; `[]` → `.available`; `resolve(status: nil, error: "l4.capture.status: L4 unavailable: X")` → `.degraded(reason: "l4.capture.status: L4 unavailable: X")`. `testVerdictArgsCarryParkedID`: `L4Verdict.args(parkedID: "P1") == ["id": .string("P1")]`. `testParkedListAndFirst`: two entries for flows F and G → `first(for: FlowID("G"), …)?.id == "P2"`.
- **Live check:** in D9.
- **Done when:** tests pass (Terminal output quoted), the (d) gate's build passes.

### Task D2: §2 packet and flow fields, windowed reads, L4 scope items

- **Satisfies:** AC25, AC30 (groundwork)
- **Depends on:** D1
- **Files:** `apps/mac/Sources/AitmproxyKit/L4.swift`, `apps/mac/Tests/AitmproxyKitTests/L4Tests.swift`
- **Change:** `L4Packet` gains `bytes: Data?`, `timestamp: Date?`, `proto: String?`, `src: String?`, `dst: String?`, `srcPort: Int?`, `dstPort: Int?` (parsed when present; base64 `bytes`; ms `timestamp`); `L4Flow` gains `startedAt: Date?` and flow-level `src`, `dst`, `srcPort`, `dstPort`, and `target` becomes `lo0 → 127.0.0.1:9053` when `dst`/`dstPort` are present (the old interface/filter form otherwise). `public enum L4Wire { public static func supportsWindow(_ tools: [ToolDescriptor]) -> Bool; public static func flowGetArgs(id: FlowID, inspect: Bool, window: Bool) -> [String: JSONValue] }` (`["id", "limit": 0]` / `["id", "offset": 0, "limit": 256]` / `["id"]`). `public struct L4ScopeItem: Hashable, Sendable, Identifiable { id, cidr, ports, interface, direction, capability, source }` with `public static func list(_ json: JSONValue) -> [L4ScopeItem]`; `public struct L4ScopeDraft: Hashable, Sendable { cidr, ports, interface, direction, capability; public var args: [String: JSONValue] }`.
- **Test first:** `testPacketParsesSection2Fields` (a packet object with `bytes: "3q0="`, `timestamp: 1700000000123`, `proto "UDP"`, `src`, `dst`, ports → `bytes == Data([0xde, 0xad])`, `timestamp == Date(timeIntervalSince1970: 1700000000.123)`, `dstPort == 9053`); `testFlowTargetUsesDestination` → `"lo0 → 127.0.0.1:9053"`; `testOldFlowShapeStillParses`; `testFlowGetArgs` (three literals above); `testScopeItemsAndDraft` (two entries with `source` `config`/`runtime`; the AC5 draft's `args == ["cidr": "127.0.0.1/32", "ports": "9100-9199", "interface": "lo0", "direction": "inbound", "capability": "capture"]`).
- **Live check:** in D9.
- **Done when:** tests pass, build passes.

### Task D3: accepted craft sample, L4 row verb gate

- **Satisfies:** AC27 (Kit), AC29 (Kit)
- **Depends on:** D2
- **Files:** `apps/mac/Sources/AitmproxyKit/L4.swift`, `apps/mac/Tests/AitmproxyKitTests/L4Tests.swift`
- **Change:** `PacketSpecDraft.sample: String`:

  ```yaml
  layers:
    - ipv4:
        src: 127.0.0.1
        dst: 127.0.0.1
    - udp:
        src_port: 40000
        dst_port: 9
    - raw: "hello-l4"
  ```

  `PacketSpecDraft.parse` accepts a `raw` layer written inline as a quoted string (UTF-8 bytes) or a `[n, n, …]` list, and emits `{"raw": [bytes]}` (integers, so the core's `Vec<u8>` accepts them). `public enum L4RowVerbs { public static func gate(_ item: VerbItem, row: FlowRow) -> VerbItem }`: on a row with `kind == .l4`, the verbs whose `tableKey` is `.resume, .edit, .kill, .delete, .replay, .editAndReplay, .buildPoC, .resumeSelected, .killSelected, .mark(nil), .comment` come back `enabled: false` with `disabledReason: "Not available for L4 flows"`; other rows and verbs are unchanged.
- **Test first:** `testSampleSpecIsWhatTheCoreAccepts`: `PacketSpecDraft.parse(PacketSpecDraft.sample)` equals `{"layers": [{"ipv4": {"src": "127.0.0.1", "dst": "127.0.0.1"}}, {"udp": {"src_port": 40000, "dst_port": 9}}, {"raw": [104, 101, 108, 108, 111, 45, 108, 52]}]}` (`raw` has 8 elements; no `sport`, `dport` or `data` key anywhere). `testL4RowOffersNoHTTPVerbs`: for an L4 row built from `L4Flow(…).row(seq: 1, inScope: true)`, `VerbTable.items(for: VerbContext(row: row)).map { L4RowVerbs.gate($0, row: row) }` has no **enabled** item for mark, comment, replay or buildPoC; for an HTTP row the gate returns every item unchanged.
- **Live check:** AC27 in D9 (`l4.craft` on the rig returns `length 36`). Trap: if the bus encodes the byte list as floats, the core rejects it; the live Build is the proof.
- **Done when:** tests pass, build passes.

### Task D4: live L4 polling, availability from the core, tripwire

- **Satisfies:** AC25, AC26 (live wiring)
- **Depends on:** D3
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/BusService.swift`, `apps/mac/Sources/Aitmproxy/Session.swift`, `apps/mac/tools/check-l4-live.sh` (create)
- **Change:** `BusService.pollLoop`, when `tools` offers `l4.flow.list` and `l4.flow.get`: each poll calls `l4.flow.list` then `l4.flow.get` with `L4Wire.flowGetArgs(id:, inspect: false, window: L4Wire.supportsWindow(tools))` per id, builds `L4Flow`s into `session.l4Details` and rows with `row(seq:inScope:)` (in scope when an `L4ScopeItem` covers the flow's interface), and appends them after the HTTP rows in the one `session.rows` assignment. On the slow cadence (no faster than the HTTP poll; builder's interval) it reads `l4.capture.status`, `l4.intercept.status` (into `session.l4CaptureAvailability` / `l4InterceptAvailability` via `L4Availability.resolve`), `l4.scope.list` (into `session.l4Scope`), and `l4.intercept.list` only when intercept is available (into `session.l4Parked`). `Session.swift`: replace `l4EmbeddedCore`, `l4LastWireError` and the computed `l4Availability` with the stored `l4CaptureAvailability`, `l4InterceptAvailability` (start `.pending`), `l4Scope: [L4ScopeItem]`, `l4Parked: [L4ParkedPacket]`; no `APP_L4_EMBEDDED` read remains on a live path. `check-l4-live.sh`: exits 1 if `BusService.swift` lacks `l4.flow.list` or `l4.flow.get`, or if `APP_L4_EMBEDDED` appears in any file under `apps/mac/Sources` other than a `Fixtures*` file that survived `R`; prints `check-l4-live: ok` and exits 0 otherwise.
- **Test first:** `apps/mac/tools/check-l4-live.sh` run against `origin/main`'s tree **fails** (exit 1, naming `BusService.swift`); after the change it prints `check-l4-live: ok`.
- **Live check:** AC25 in D9 (`l4.flow.list` from `aitm-mac` on every poll in `agent.activity`).
- **Done when:** tripwire both runs quoted, build passes.

### Task D5: inspector: sample, parked ids, documented-limited bar, §2 display, row-less craft

- **Satisfies:** AC26 (Inject disabled), AC27, AC28
- **Depends on:** D4
- **Files:** `apps/mac/Sources/Aitmproxy/Inspector/L4Inspector.swift`
- **Change:** `craftYAML` starts from `PacketSpecDraft.sample` (`L4Inspector.sampleSpec` is deleted). `row: FlowRow?` (nil ⇒ the row-less craft mode used by D7: Craft tab only). Inject is disabled with `session.l4CaptureAvailability.reason` as its help and visible text when degraded. `L4InterceptBar` takes `availability: L4Availability` and `parked: L4ParkedPacket?`: degraded ⇒ one documented-limited line with the core's reason and **no** buttons; available with a parked packet ⇒ Forward/Drop sending `L4Verdict.args(parkedID:)` through the existing confirm handshake. The packet list and detail show time, `src:port → dst:port`, and a hex dump of `bytes` from a window fetch (`L4Wire.flowGetArgs(id:, inspect: true, …)`) when an L4 row is selected; "no bytes from this core" against an older core.
- **Test first:** the Kit units from D1–D3 cover the logic; red check: against the rig, `origin/main`'s Craft Build returns `invalid PacketSpec: invalid type: map, expected a sequence`.
- **Live check:** AC27 and AC28 in D9; `tools/grid-lint.sh` (layout changed).
- **Done when:** build and grid-lint pass.

### Task D6: no HTTP verbs on L4 rows

- **Satisfies:** AC29
- **Depends on:** D5
- **Files:** `apps/mac/Sources/Aitmproxy/Session+Verbs.swift`
- **Change:** `verbItems(for:)` and `verbItem(_:for:)` map through `L4RowVerbs.gate(_:row:)`; `perform(_:on:)` already refuses a disabled item, so an L4 row's mark, comment, replay, PoC, resume, kill and edit never reach `actions`.
- **Test first:** D3's `testL4RowOffersNoHTTPVerbs` is the logic test; this task is wiring only.
- **Live check:** with a real L4 row [D0].
- **Done when:** build passes.

### Task D7: Scope page L4 section and the row-less L4 home

- **Satisfies:** AC30, and hosts AC26/AC27/AC28's [now] surfaces
- **Depends on:** D6
- **Files:** `apps/mac/Sources/Aitmproxy/Panels/ScopePanel.swift`, `apps/mac/Sources/Aitmproxy/Panels/ScopeSheet.swift` (summary counts L4 entries)
- **Change:** when `session.l4Enabled`, an "L4 scope" section under the host list: the capture availability line and the intercept documented-limited line with the core's reasons; the `session.l4Scope` list (cidr, ports, interface, direction, capability, `config`/`runtime`); an add form (cidr, ports, interface, direction, capability) that sends `L4ScopeDraft.args` with `l4.scope.add`, shows the core's `needs_confirmation` prompt in the existing `L4ConfirmRequest` dialog, re-issues with `_confirm` and refreshes `l4.scope.list`; a remove action for `runtime` entries (`l4.scope.remove {id}`); and a "Craft packet…" button opening `L4Inspector(row: nil, detail: nil)` in a sheet. Within the foundation tokens and the icon/editorial rules.
- **Test first:** D2's `testScopeItemsAndDraft`; red check: the section does not exist on `origin/main`.
- **Live check:** AC30 in D9 (with (a)); `tools/grid-lint.sh`.
- **Done when:** build and grid-lint pass.

### Task D8: phantom pinned hosts (D15)

- **Satisfies:** AC31
- **Depends on:** D7
- **Files:** none expected. If the cause is in a file not in the (d) list, **stop and report** (spec §7(d)).
- **Change:** reproduce first: the dev bundle with a **new** `APP_DEFAULTS_SUITE` name and a **new empty** `APP_STORE` directory against the rig. Likely cause at 5eac2a5: `Session.loadFixtures()` sets `pins`, whose `didSet` writes `pins.json` into `Store.url`, so a fixture or self-test run that shared an `APP_STORE` left those hosts for the next live run. If the pins do not appear on `R`'s tree, record that (the fixture path is gone) with the screenshot and the `pins.json` listing, and change nothing. If they appear, find the writer and fix it only if it is in a listed file.
- **Test first:** the reproduction itself, before any change, on this branch rebased on `R`.
- **Live check:** AC31 screenshot (light and dark) of the sidebar's pinned section: no pinned hosts; `ls -la <APP_STORE>` shows no `pins.json`, or one with an empty `hosts` list.
- **Done when:** the verdict and evidence are in the report.

### Task D9: live CUA script and the macOS walk

- **Satisfies:** AC25, AC26, AC27, AC28, AC29, AC30, AC31, AC33 (mac half)
- **Depends on:** D8
- **Files:** `apps/mac/tools/cua-l4-live.sh` (create); `apps/mac/Sources/Aitmproxy/SelfTest+Live.swift` (only if it survived `R` and its L4 checks need the new shape)
- **Change:** `cua-l4-live.sh [--dark]`: launches `/tmp/Aitmproxy-dev-l4par.app` (from `DEV_TAG=l4par tools/snap-dev.sh`) with `APP_LIVE=1`, a fresh `APP_STORE` under `/tmp/claude/`, a fresh `APP_DEFAULTS_SUITE`, `AITM_CONFIG=/tmp/claude/l4-rig/config.yaml` and the operator token read from the 0600 config into the env (never printed); records the PID it started and stops only that PID on exit; takes winshot screenshots of the Flows page, the Scope page's L4 section, the Craft sheet after Build, and the pinned section; and reads `agent.activity` for `aitm-mac` through a small inline python over `tests/e2e/aitm_e2e/bus.py`.
- **Test first:** run it against `origin/main`'s bundle: AC25 (no `l4.flow.list` from `aitm-mac`) fails.
- **Live check (Terminal, `local/l4par-mac-with-core` build for AC26/AC30):** AC25 `l4.flow.list` from `aitm-mac` on every poll over 60 s (counts quoted); AC26 the Scope page's L4 section shows `R_CAP` and Inject in the Craft sheet is disabled with it; AC27 Build on the untouched sample → `l4.craft` on the rig returns `length 36`, the preview shows 36 bytes of hex; AC28 the intercept line shows `R_INT` with no clickable Forward/Drop; AC29 with real proxied HTTP rows, the `TCP UDP L4` chips are present and `L4` leaves zero HTTP rows; AC30 the three config L4 entries are listed and the AC5 entry is added through the operator confirm, then removed; AC31 (D8); AC33 no enabled control returned `L4 unavailable` in `agent.activity` for `aitm-mac`. Light and dark screenshots looked at and described. Live L4 rows, Forward/Drop live: `blocked: needs D0` / `blocked: no Linux rig`.
- **Done when:** the walk output and screenshots are delivered, the full (d) gate passes.

---

## Unit (e) docs — `docs/l4-parity`

Spec §7(e) file list: `docs/research/mcp-tool-catalog.txt`, `aitmproxy-plugin/docs/tool-reference.md`, `aitmproxy-plugin/skills/aitmproxy-overview/SKILL.md`, `aitmproxy-plugin/skills/aitmproxy-intercept-mutate/SKILL.md`. Starts after (a)'s branch is reviewed (it documents (a)); merges after (a).

### Task E1: the `l4.*` family in the catalogue and the tool reference

- **Satisfies:** AC32 (first half)
- **Depends on:** (a) A9 (behaviour final)
- **Files:** `docs/research/mcp-tool-catalog.txt`, `aitmproxy-plugin/docs/tool-reference.md`
- **Change:** regenerate both from an `l4.enabled` core built from `fix/l4-parity-core` (`AITM_CONFIG=/tmp/claude/l4-rig/config.yaml aitm --help` feeding `node aitmproxy-plugin/scripts/gen-tool-reference.mjs`, if `--help` lists `l4.*` under that config), or add the 25 `l4.*` entries by hand in the existing format. The tool reference drops "the family is not listed here" and states that `l4.*` appears only with `l4.enabled: true`.
- **Test first (the check):** in the Terminal, a python one-liner over `tests/e2e/aitm_e2e/bus.py` reads the rig's `tools/list`, takes the 25 `l4.*` names, and prints any name missing from each file; on `origin/main` it prints all 25 for both files.
- **Live check:** the same check prints nothing for both files (output quoted).
- **Done when:** check output quoted.

### Task E2: the agent skills

- **Satisfies:** AC32 (second half)
- **Depends on:** E1
- **Files:** `aitmproxy-plugin/skills/aitmproxy-overview/SKILL.md`, `aitmproxy-plugin/skills/aitmproxy-intercept-mutate/SKILL.md`
- **Change:** overview gains an "L4 (raw TCP/UDP)" section: `l4.capture.status` / `l4.intercept.status` answer `available`, `code`, `reason` (and what `needs_privilege`, `unsupported_platform`, `not_configured` mean); `l4.scope.add` is operator-confirmed and an agent is refused unless the operator opened the Widen gate; `l4.intercept.*` is Linux NFQUEUE only; verdict verbs take the **parked id** from `l4.intercept.list`, never the flow id; `l4.flow.get` takes `offset`/`limit`, `limit: 0` for listing. Intercept-mutate gains one paragraph separating HTTP `flow.intercept` / `flow.resume` from `l4.intercept.*`.
- **Test first (the check):** `grep -c` for `available`, `code`, `reason`, `l4.scope.add`, `parked`, `Linux` in the overview; each is 0 on `origin/main`.
- **Live check:** the same greps ≥ 1 each; human read-through by the spec reviewer.
- **Done when:** grep output quoted.

---

## Questions only Matt can answer (asked by the architect with this plan)

1. **macOS row-less L4 home.** With no L4 rows on an unprivileged core, the mac L4 inspector is unreachable, so AC26–AC28 [now] need a surface without a row. Default in this plan: the Scope page's new L4 section shows availability and opens a Craft sheet (D5, D7). Alternative: mark AC26–AC28's live halves `blocked: needs D0`.
2. **"Oldest parked packet."** The core sorts `l4.intercept.list` by parked-packet uuid, not arrival time, so no UI can know which packet is oldest. Default in this plan: every UI takes the **first listed** entry for the flow. Alternative: (a) adds arrival order to `l4.intercept.list` (an `intercept.rs` change inside (a)'s list, with its own test).
3. **TUI agent policies.** D10c's root cause is that the TUI does not know the core's `auto` and `ask` policies. B8 adds both to the TUI's policy model and overlay, which goes slightly beyond "remove the stale banner". Confirm, or limit B8 to parsing them for display only.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
