# L4 parity fixes implementation plan

**Status:** Approved for the pre-approved small fixes (Matt, 2026-10-31, via the orchestrator); fork (ii) decided 2026-11-01 (operator confirm), shipped as (a'); revised 2026-10-31 for the panel decisions below.
**Spec:** `docs/superpowers/specs/2026-10-31-l4-parity-fixes-design.md`
**Research:** `docs/research/12-l4-parity-audit.md` (D0–D15, D11a/D11b)
**Branches / worktrees:** one per unit, each cut from `origin/main` (5eac2a5 or later) unless noted, each with its own PR against `main`:

| Unit | Branch | Worktree (created by the orchestrator, Terminal) | Tasks |
|---|---|---|---|
| (a) core | `fix/l4-parity-core` | `.claude/worktrees/l4par-core` | A1–A4 (done), A7, A8, A14, A15, A10–A13, A9 |
| (a') core scope | `fix/l4-parity-core-scope`, cut from `main` after (a) merges | `.claude/worktrees/l4par-scope` | A6 |
| (b) TUI | `fix/l4-parity-tui` | `.claude/worktrees/l4par-tui` | B1–B7, B8a, B8b, B9 |
| (c) web | `fix/l4-parity-web` | `.claude/worktrees/l4par-web` | C1–C8, C9a, C9b, C10 |
| (d) macOS | `fix/l4-parity-mac` | `.claude/worktrees/l4par-mac` | M1, M2, M3a, M3b, M4a, M4b, M5–M9 |
| (e) docs | `docs/l4-parity` | `.claude/worktrees/l4par-docs` | E1–E2 |

### Decisions (2026-10-31, the orchestrator; Matt may override)

| # | Decision | Tasks |
|---|---|---|
| 1 | Status shape `{available, code, reason, captures\|sessions}` and the `code` vocabulary are (a)'s; the privilege spec only adds an optional `privilege` key. Tests assert `code`; literal reasons only in A9. | A4, A14, A9 |
| 2 | `l4.flow.get` bytes: the core never records its own listeners; `bytes` per packet: trusted callers always; an agent sees captured packets with its Capture gate open and injected packets with its Inject gate open (spec §2.2 as amended after the re-panel); at most 4 MiB of raw bytes per reply. | A10, A11, A12 |
| 3 | `l4.intercept.list` is arrival-ordered (oldest first, `parked_at`); every UI acts on the first listed entry for the flow (plan question 2, decided). | A13, B1, C1, M1 |
| 4 | Availability is read through an `AvailabilitySource` at invoke time, so D0 swaps in `PrivilegeState` without touching commands. | A14 |
| 5 | Operator scope add (fork ii, with Matt) moves to (a') as A6. A5 (`source` provenance on `l4.scope.list`) stays in (a): it landed as be9d15e4, is harmless on its own, and the UI units read `source` regardless of fork ii. UI scope-add controls render only when `tools/list` shows `l4.scope.add` `confirmable: true`. | A5, A6, B1, B6, C1, C7, M2, M7 |
| 6 | macOS has no row-less Craft sheet (plan question 1, decided): the Scope page hosts the availability lines and L4 scope; AC26's Inject-disabled evidence is the Scope page line; AC27's in-app half is "blocked: needs D0". No remove action on the Scope page. | M5, M7, M9 |
| 7 | The TUI parses, labels and displays the `auto` and `ask` policies only; setting them from the TUI is a separate change (plan question 3, decided). | B8b |
| 8 | Web status verbs poll on the 10 s idle tick (at most 30 `l4.*` calls/min, AC23). `bus/noise.ts` is deleted by `R` and dropped; the once-per-message rule lives in `store.ts`. | C2, C3, C10 |
| 9 | One pending literal `Reading L4 availability…` in TUI, web and mac (Swift `case pending`); the error fallback keeps only the text after `L4 unavailable: `. | B1, C1, M1 |
| 10 | Packet text is inert: bytes outside 0x20–0x7e render as `.`; no `innerHTML`; no raw control bytes to a terminal. | B1, C6, M5 |
| 11 | The `content`-text base64 omission is not in this plan (spec open question 2). | — |

## Overview

Independent PRs fix D1–D15 on top of the fixture-removal PR from another session (its merge SHA is `R`; the orchestrator sends it). Each branch rebases once on `R` when the SHA arrives; a Coder who has not received `R` must not touch a file `R` deletes.

**Independence.** Units (a), (b), (c), (d), (e) have disjoint file lists (spec §7) and fan out in parallel, one worktree each; (a') follows (a) on the same files. **Inside a unit, tasks are sequential** in the order of the table, one fresh Coder per task, test-first, one commit per task.

**Merge order (spec §8).** (c) merges before (a) or the same day ((c) reads both status shapes). (b) and (d) are independent of (a) for merge; their live checks marked "with (a)" or "with (a')" run on a local integration. (a') merges after Matt answers fork (ii); UI units may merge before it because their scope-add controls are gated on `confirmable`. (e) merges after (a) and (a').

**Local integration for "with (a)" live checks.** The Coder asks the orchestrator for a throwaway worktree on `local/l4par-<unit>-with-core` = the unit branch merged with the current `fix/l4-parity-core` (and, for scope checks, `fix/l4-parity-core-scope`) head. It is built and run like any rig build, **never pushed, never merged**, and deleted after the check. The verdict line names every SHA.

### Rule for every task (Matt, 2026-10-31; repeat it in every Coder report)

**No fixture, snapshot, self-test or seeded-store run counts as evidence or as a gate.** That covers macOS `Fixtures+*.swift` data, `tools/snap.sh` / `snap-dev.sh` snapshot images, `selftest.sh` with `APP_FIXTURES`, the web mock bus (`?bus=mock`, `bus/mock.ts`) and TUI `--fixture` / `fixture.rs`. Evidence is exactly one of: **(1)** a unit test of pure logic whose input is built in the test; **(2)** a source tripwire (grep or a test that reads source) that stops the named regression; **(3)** the live check: the real frontend against a real core on the rig with real traffic, or the honest **blocked** verdict (`blocked: needs D0` / `blocked: no Linux rig`) with the core's reason quoted. A green fixture or snapshot suite is never cited. A suite CI runs must not be left red. `snap-dev.sh` is used **only** to build the dev bundle.

### Coordination (every Coder, every task)

1. Before the first edit of a task, send the orchestrator session the task's **Files** list (the claim). Edit nothing outside it. If the task needs a file not in its unit's spec §7 list, **stop and report**.
2. Every PR number goes to the orchestrator the moment it exists.
3. **Nobody merges.** No Coder, Tester or reviewer merges or closes a PR. Integration is stage 7, the orchestrator's, after Matt's go.
4. The rig is a shared resource: claim it through the orchestrator like a file. One rig core at a time on bus 27431 / web 28182.

### Known traps (read before starting)

- **The sandbox cannot bind ports or reach GitHub.** `aitm web`, the targets, the TUI against the bus, the mac bundle, `npm ci`, `git push`, `gh` run in the **Terminal panel**. Push with an explicit refspec (`git push origin fix/l4-parity-<unit>`; after the `R` rebase `--force-with-lease`). Keep Terminal lines short; do local git in the sandbox.
- **Stale cargo artifacts.** `touch` the crate's `src/lib.rs` (and `crates/aitm/build.rs` for web-embedding builds) before every gate and release build. Gate on the **exit status** written to a log (`…; echo EXIT=$?`), never on a grep of the output.
- **Never `./build.sh` in `apps/mac`.** Build with `DEV_TAG=<tag> apps/mac/tools/snap-dev.sh`. SwiftPM runs only in the Terminal.
- **Never kill a process you did not start.** Note the PIDs you launch; stop only those. Never `pkill -f` by name.
- **Never print a bus token.** Read tokens from `/tmp/claude/l4-rig/op.token` and `agent.token` into env vars or `--token-file`; never echo them, never paste the Operator URL into a report or commit.
- **Rig hygiene.** `umask 077` first in every `<unit>-up.sh`; `config.yaml`, the token files and every log are mode 600; delete `<unit>-aitm.log` (it carries the Operator URL) once the check's output is quoted.
- **`aitm web` exits on stdin EOF.** Hold stdin open: `sleep 86400 | AITM_CONFIG=… aitm web …`.
- **Disk.** If a build fails ENOSPC, ask the orchestrator to clear idle siblings' `target/`.
- **Shared Swift scratch path.** `~/Library/Developer/Aitmproxy/test-build` is shared; never two `swift test` at once.

### The rig (spec §6; every live check)

Build in the sandbox, offline, from the worktree under test (or its integration):

```bash
touch crates/aitm/build.rs crates/aitm-proto-l4/src/lib.rs
cargo build --release --offline -p aitm -p aitm-tui > /tmp/claude/l4-rig/<unit>-build.log 2>&1; echo EXIT=$?
```

Start in the Terminal from `/tmp/claude/l4-rig/<unit>-up.sh` (one short command):

```bash
umask 077
python3 -m http.server 9099 --bind 127.0.0.1 > /tmp/claude/l4-rig/<unit>-http.log 2>&1 &
python3 /tmp/claude/l4-rig/udpecho.py > /tmp/claude/l4-rig/<unit>-udp.log 2>&1 &
sleep 86400 | AITM_CONFIG=/tmp/claude/l4-rig/config.yaml <worktree>/target/release/aitm web --listen 127.0.0.1:28182 > /tmp/claude/l4-rig/<unit>-aitm.log 2>&1 &
```

- Config: `/tmp/claude/l4-rig/config.yaml` (proxy 28180, browser 28181, bus 27431, web 28182; `l4.enabled: true`; three config `l4.scope` entries on lo0 `127.0.0.1/32` ports `9000-9999`, one each for capture/inject/intercept; **no** `l4.intercept` block).
- Real HTTP rows: `curl -s -x http://127.0.0.1:28180 http://127.0.0.1:9099/ >/dev/null` (a few times).
- Bus from python (Terminal), env model of `tests/e2e/aitm_e2e/bus.py`: `AITM_BUS_ADDR=127.0.0.1:27431`, `AITM_BUS_OPERATOR_TOKEN` and `AITM_BUS_TOKEN` read from the token files.
- **Counting calls a frontend made** (AC11, AC15, AC23, AC25): a separate operator `BusClient` reads `agent.activity {since: <t0 ms>}` and counts entries whose `command` starts with `l4.` and whose `client_label` is `aitm-tui` / `web-bridge` / `aitm-mac`.
- This Mac is the **unprivileged rig**: `/dev/bpf*` is root-only. Reasons on it today, verbatim (they change when D0 lands; only A9 asserts them literally):
  - `R_CAP` = `no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)`
  - `R_INT` = `in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)`
  - `R_WIDEN` = ``runtime L4 scope widening is disabled; declare scope in the `l4.scope` config block or set `l4.allow_agent_widen` ``
- TUI: the worktree's `target/release/aitm-tui` in a pty, driven like `/tmp/claude/l4-rig/tui_drive.py` (160×44, `--bus 127.0.0.1:27431 --token-file /tmp/claude/l4-rig/op.token --expect-role operator`); `AITM_TUI_BIN` points at the worktree's binary.
- Web: the in-app browser at the **Operator URL** the core prints in `<unit>-aitm.log` (never copied into a report), light and dark.
- macOS: `DEV_TAG=l4par apps/mac/tools/snap-dev.sh` (build only), then `apps/mac/tools/cua-l4-live.sh` (M9; until it exists, `/tmp/claude/l4-rig/mac-live.sh` with fresh `APP_STORE` and `APP_DEFAULTS_SUITE`), screenshots with `swift apps/mac/tools/winshot.swift Aitmproxy <out.png>`, light and dark (`-AppleInterfaceStyle Dark`; verify it took).

### Gates (before any panel review of a unit)

| Unit | Gate (all must exit 0, output quoted) |
|---|---|
| (a), (a'), (b) | sandbox: `cargo fmt --check && cargo clippy --all-targets --offline -- -D warnings && cargo test --offline` (touch first; exit status from the log) |
| (c) | Terminal once per worktree: `npm ci` in `apps/web`. Then `cd apps/web && npm run typecheck && npm test && npm run build`. Plus the Rust gate (`aitm` embeds `apps/web/dist`). |
| (d) | Terminal: `DEV_TAG=l4par apps/mac/tools/snap-dev.sh` (must print `Build complete`), `cd apps/mac && swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`, `apps/mac/tools/grid-lint.sh` only if a task changed layout (M5, M7), and `apps/mac/tools/check-l4-live.sh`. |
| (e) | the AC32 diff check (E1) and a Markdown link check by eye; no code. |

### Unit close (Tester, then the orchestrator, per unit)

Every AC of the unit maps to a named unit test, tripwire, or a live check with output quoted, or to an explicit `blocked: needs D0` / `blocked: no Linux rig` line with the core's reason. AC33 is recorded per UI unit. The security reviewer confirms no agent path widens (AC33 second half).

---

## Unit (a) core — `fix/l4-parity-core`

Spec §7(a) file list. Constraint for every (a) task: **zero `aitm-core` edits** (AC9). `L4Privilege` keeps its two public fields, because `crates/aitm/tests/l4_wiring.rs` builds it by struct literal. Any existing test in the list that a task's shape change breaks is updated **in that task** (shape only; agent assertions untouched).

### Tasks A1–A4 (done on `fix/l4-parity-core`)

- **A1** `PacketSpec::endpoints(bytes) -> PacketEndpoints` in `craft.rs` (2f4945b8). AC1 groundwork. Tests `craft::tests::endpoints_of_crafted_ipv4_udp` (127.0.0.1:40000 → 127.0.0.1:9053 UDP), `endpoints_of_undecodable_is_default` (`[0xde, 0xad]`), `endpoints_of_tcp_icmp_ipv6`.
- **A2** `l4.flow.get` packet fields `bytes, timestamp, proto, src, dst, src_port, dst_port` and flow `started_at` plus flow-level addresses in `commands/flow.rs` (5bcd243e). AC1. Tests `commands::flow::tests::flow_get_reports_bytes_time_and_addresses` (`timestamp == 1_700_000_000_123`, `started_at == 1_700_000_000_000`), `flow_get_undecodable_packet_is_null_addressed`, and `aitm --test l4_operator_surfaces flow_get_bytes_are_base64_on_the_wire` (`"3q0="`).
- **A3** bounded window `offset`/`limit` (default 256, max 4096), reply `offset`, `PacketWindow::from_params` (38f59484). AC2. Tests `commands::flow::tests::window` (300 → 256; `{290, 50}` → 10; `limit 0` → `[]`; 5000 with `limit 100000` → 4096; `{offset 400}` → `[]`; `limit -1` → ``"`limit` must be a non-negative integer"``; schema params `["id", "offset", "limit"]`).
- **A4** honest status verbs (66040081): status verbs outside `L4Gated`, `{available, code, reason, captures|sessions}`, privilege outranks configuration, `INTERCEPT_NOT_CONFIGURED`. AC3, AC4, AC9 unit half. Tests in `module.rs` (`status_verbs_answer_when_privileged`, `intercept_status_not_configured`, `macos_probe_intercept_is_unsupported_platform`), `tests/surface.rs` (`unprivileged_wire_verbs_unavailable_pure_verbs_work`: status verbs `Ok`, `capture.start` `L4Error::Unavailable`), `tests/inpath.rs` (`intercept_start_fail_closed_via_registry`).

### Task A7: per-OS PoC `l4:` default interface

- **Satisfies:** AC8
- **Depends on:** A4
- **Files:** `crates/aitm-proto-l4/src/language.rs`, `crates/aitm-proto-l4/tests/language.rs`, `crates/aitm/tests/l4_pocstep_wiring.rs`
- **Change:** `DEFAULT_INTERFACE` is `"lo0"` under `cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))` and `"lo"` otherwise; catalog text naming the default says "`lo0` on macOS/BSD, `lo` on Linux". The two test files make their `IFACE` per-OS (the scope they declare must match the new default) and build their Rhai scripts with `format!`, so the normative step bodies with no `interface` stay exactly as written.
- **Test first** (`cargo test --offline -p aitm-proto-l4 --lib language::tests::step_default_interface`): `step_interface(&serde_yaml::from_str("op: craft").unwrap())` is `"lo0"` under `#[cfg(target_os = "macos")]`, `"lo"` under Linux; with `interface: en0` it is `"en0"`. `cargo test --offline -p aitm --test l4_pocstep_wiring` and `-p aitm-proto-l4 --test language` pass on macOS.
- **Live check:** live send on lo0 is [D0].
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task A8: e2e shape and docstrings

- **Satisfies:** AC3 (shape), AC32 (the `tests/e2e/l4` part)
- **Depends on:** A7
- **Files:** `tests/e2e/l4/test_l4_capture_flow.py`, `tests/e2e/l4/test_l4_scope_self_exclusion.py`, `crates/aitm/tests/l4_acceptance_mcp.rs` (shape only, if it reads `l4.capture.status`/`l4.flow.get`)
- **Change:** read `l4.capture.status` through a local `capture_ids(reply)` accepting the object (`reply["captures"]`) and the old bare array; when `available` is false, SKIP (77) with the core's `reason`. Replace every claim that pcap capture needs the Network/System Extension with the truth: `l4.capture.start` is pcap/BPF only (`/dev/bpf*` read+write on macOS, `CAP_NET_RAW` on Linux).
- **Test first (tripwire):** `grep -nE "Network Extension|System Extension|NE/root|macOS NE|L4/NE|approve the extension" tests/e2e/l4/*.py` prints nothing; `python3 -m py_compile` on both exits 0.
- **Live check (rig, (a) build):** `python3 tests/e2e/l4/test_l4_capture_flow.py` exits **77** and its SKIP line contains `R_CAP`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task A14: availability read through an `AvailabilitySource`

- **Satisfies:** AC3, AC4, AC38
- **Depends on:** A8
- **Files:** `crates/aitm-proto-l4/src/module.rs`, `src/commands/{mod,capture,intercept}.rs`, `tests/surface.rs`, `tests/inpath.rs`
- **Change:**
  - `module.rs`: replace `L4AvailabilityCode` and the `L4Availability` struct with `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum UnavailableCode { NeedsPrivilege, UnsupportedPlatform, NotConfigured }` (`pub fn as_str(self) -> &'static str`) and `#[derive(Debug, Clone, PartialEq, Eq)] pub enum L4Availability { Available, Unavailable { code: UnavailableCode, reason: String } }` with `pub fn code_str(&self) -> &'static str` (`"available"` or the code), `pub fn reason(&self) -> Option<&str>`, `pub fn is_available(&self) -> bool`. `pub type AvailabilitySource = Arc<dyn Fn() -> L4Availability + Send + Sync>`. `L4Privilege::{capture_availability, intercept_availability(configured)}` return the enum (Linux intercept without `CAP_NET_ADMIN` is `NeedsPrivilege`). `load()` builds two sources, each closing over a clone of the cached `L4Privilege` (and `configured` for intercept), and passes them to the builders.
  - `commands/mod.rs`: `wire_commands(guard, store, capture: AvailabilitySource)`; `availability_object(av: &L4Availability, payload_key: &str, payload: Vec<Value>) -> Value` (payload `[]` when unavailable).
  - `capture.rs`: `CaptureStatus::new(registry: Arc<CaptureRegistry>, source: AvailabilitySource)`, calling `(self.source)()` in `invoke`. `intercept.rs`: `InterceptStatus::new(sessions, source)`; `intercept_commands(guard, store, sessions, config, availability: AvailabilitySource)`.
- **Test first** (`cargo test --offline -p aitm-proto-l4`): the A4 tests on the new enum, unchanged in what they assert; `commands::capture::tests::status_reads_source_at_invoke_time`: a `CaptureStatus` whose source reads an `Arc<AtomicBool>`; first invoke → `available: false, code: "needs_privilege"`, flip the bool, second invoke → `available: true, code: "available", reason: null`. `module::tests::linux_intercept_without_cap_net_admin_needs_privilege` (`#[cfg(target_os = "linux")]`): `L4Privilege { capture_inject: None, intercept: Some("missing CAP_NET_ADMIN".into()) }.intercept_availability(true).code_str() == "needs_privilege"`.
- **Live check:** in A9.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task A15: idioms on A1/A3

- **Satisfies:** AC1, AC2 (no behaviour change)
- **Depends on:** A14
- **Files:** `crates/aitm-proto-l4/src/{types,craft,language}.rs`, `src/commands/flow.rs`
- **Change:** `types.rs`: `impl L4Proto { #[must_use] pub fn wire_name(self) -> &'static str }` (`"TCP"`, `"UDP"`, `"ICMP"`, `"ICMPv6"`, `"other"`, `"raw"`). `craft.rs`: `PacketEndpoints` derives `Copy`; `proto: Option<L4Proto>` (only `Tcp`, `Udp`, `Icmp`, `IcmpV6`). `flow.rs`: `proto` is emitted with `wire_name()`; `FLOW_GET_DEFAULT_LIMIT` and `FLOW_GET_MAX_LIMIT` become `pub(crate)`; `impl Default for PacketWindow` replaces the associated `DEFAULT` (the `language.rs` call site uses `PacketWindow::default()`).
- **Test first:** `craft::tests::endpoints_*` expect `Some(L4Proto::Udp)` etc.; `types::tests::wire_names`: `[Tcp, Udp, Icmp, IcmpV6].map(L4Proto::wire_name) == ["TCP", "UDP", "ICMP", "ICMPv6"]`; `commands::flow::tests::window_default`: `PacketWindow::default() == PacketWindow { offset: 0, limit: 256 }`. A2's wire test still reads `proto "UDP"`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task A10: self-exclusion of the core's own listeners

> Amended after the panel (Review log): the choke point is `L4Guard::admit_frame`/`admit_endpoints`, used by every recorder (capture loop, send_recv reply listener, intercept park, NE ingress) and `main.rs`/`tui.rs` add bound ports with `add_self_ports` through the shared `self_port_hook` in `wire.rs`; `is_self_traffic` was dropped and `self_exclusion_bpf(interface)` is `pub(crate)` on the guard; files also include `sendrecv.rs`, `ingress.rs`, `tui.rs`.


- **Satisfies:** AC34
- **Depends on:** A15
- **Files:** `crates/aitm-proto-l4/src/{capture,guard,module}.rs`, `crates/aitm/src/wire.rs`, `crates/aitm/src/main.rs` (both in spec §7(a); name them in the claim)
- **Change:**
  - `guard.rs`: `L4Guard` gains a self-port set with `pub fn set_self_ports(&self, ports: impl IntoIterator<Item = u16>)`, `pub fn self_ports(&self) -> Vec<u16>` (ascending) and `pub fn is_self_traffic(&self, ep: &PacketEndpoints) -> bool` (true iff `src` or `dst` is a loopback address and `src_port` or `dst_port` is in the set).
  - `capture.rs`: `record_frame` returns before the scope check when `guard.is_self_traffic(&PacketSpec::endpoints(frame))`. `scope_filter(guard, interface)` on a loopback interface (`lo` or `lo<digits>`) with a non-empty set appends the exclusion: no scope clause → `not port 27431`; a clause → `(<clause>) and not port 27431`; several ports → `not (port 27431 or port 28182)`.
  - `module.rs`: `pub fn with_self_ports(self, ports: impl IntoIterator<Item = u16>) -> Self` (sets them on the module's guard).
  - `wire.rs`: `Features` gains `pub l4_self_ports: Vec<u16>` (default empty); assembly calls `with_self_ports` with the proxy and browser-proxy ports from `cfg` plus `features.l4_self_ports`.
  - `main.rs`: after binding, adds the bus loopback-TCP, web UI and MCP streamable-HTTP ports (each when bound) to the live guard via `set_self_ports` with the union of all five.
- **Test first** (`cargo test --offline -p aitm-proto-l4 --lib capture::tests`): `self_traffic_is_never_recorded`: capture scope lo0 `127.0.0.1/32` all ports, self ports `[27431]`; `record_frame` of TCP 127.0.0.1:51000 → 127.0.0.1:27431 and 27431 → 51000 leaves 0 packets; 51000 → 9099 adds 1. `scope_filter_excludes_self_ports`: that scope on `lo0` → `Some("(host 127.0.0.1) and not port 27431")`; scope `127.0.0.1/32` ports `9000-9999` with self ports `[28182, 27431]` → `Some("(host 127.0.0.1 and portrange 9000-9999) and not (port 27431 or port 28182)")`; on `mock0` the filter is unchanged.
- **Live check:** in A9 ([D0] half).
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task A11: bytes only to trusted callers

> Amended after the re-panel (Review log): the gate is per packet (captured→Capture gate, injected→Inject gate), not per caller or per flow kind; tests `…_per_packet`.


- **Satisfies:** AC35
- **Depends on:** A10
- **Files:** `crates/aitm-proto-l4/src/commands/{flow,mod}.rs`, `src/language.rs`, `crates/aitm/tests/l4_operator_surfaces.rs`
- **Change:** `FlowGet::new(store, gates: Arc<L4AgentGates>)` (`mod.rs` passes `guard.agent_gates()`); `invoke` computes `with_bytes = host.caller_is_trusted_control() || self.gates.allowed(AgentGate::Capture)` and calls `flow_to_value(flow, window, with_bytes)`, which inserts `bytes` only when true. Schema: `bytes` `required: false`, "present for the operator, the CLI, or an agent whose Capture gate is open". The Rhai `l4.flow.get` applies the same rule from its `HostCallCtx`.
- **Test first:** `commands::flow::tests::flow_get_bytes_only_for_trusted_or_capture_gate`: the `[0xde, 0xad]` flow; `host(&store, &client, &guard).with_frontend(Frontend::Mcp)` with gates closed → packet object has `length` and no `bytes` key; `gates.set(AgentGate::Capture, true)` → `bytes == Bytes(vec![0xde, 0xad])`; `Frontend::Operator` with gates closed → `bytes` present; a TCP packet 127.0.0.1:51000 → 127.0.0.1:27431 as agent → no `bytes`. `aitm --test l4_operator_surfaces agent_flow_get_has_no_bytes`: agent `l4.flow.get` → `structuredContent.packets[0]` has no `bytes`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task A12: reply byte budget

- **Satisfies:** AC36
- **Depends on:** A11
- **Files:** `crates/aitm-proto-l4/src/commands/flow.rs`
- **Change:** `pub(crate) const FLOW_GET_MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;`. When `with_bytes`, the window adds packets in order while the running sum of `bytes.len()` stays ≤ the budget, always at least one; stopping early sets `truncated: true` and `next_offset` = index of the first packet not returned; otherwise `truncated: false`, `next_offset: null`. Without bytes only `offset`/`limit` apply. Result schema lists both fields.
- **Test first** (`commands::flow::tests::window_byte_budget`): 300 packets of 60,000 bytes, operator, default window → 69 packets, `truncated == Bool(true)`, `next_offset == Int(69)`; a 3-packet flow → `truncated == Bool(false)`, `next_offset == Null`; the 300-packet flow as an agent with gates closed → 256 packets, `truncated == Bool(false)`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task A13: `l4.intercept.list` in arrival order

> Amended after the panel (Review log): the sequence is process-wide (`NEXT_PARKED_SEQ`), sort key `(parked_seq, id)`.


- **Satisfies:** AC37
- **Depends on:** A12
- **Files:** `crates/aitm-proto-l4/src/intercept/mod.rs`, `src/commands/intercept.rs`
- **Change:** `ParkedPacket` gains `pub parked_seq: u64` (from a per-session monotonic counter, assigned when parked) and `pub parked_at: SystemTime`; a `#[cfg(test)] ParkedId::from_u128`. `IntercepList::invoke` sorts by `parked_seq` instead of the id string; `parked_value` emits `parked_at` (`Int`, epoch ms); schema lists it.
- **Test first:** `commands::intercept::tests::intercept_list_is_arrival_ordered`, over the mock in-path backend the existing `commands::intercept` tests use: park `P2 = ParkedId::from_u128(2)` and then `P1 = from_u128(1)` on flow `F` → the list's ids are `["00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000001"]`, each `parked_at` is an `Int`, the first ≤ the second.
- **Live check:** [Linux].
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task A9: unprivileged live checks and the blocked-aware privileged walk

> Amended after the panel (Review log): the core cell asserts the 22 module verbs, not a total count; the AC6 agent scope-add check runs here and AC5 is skipped until (a').


- **Satisfies:** AC2 (live), AC3, AC4, AC9, AC34 [D0] verdict, AC1/AC8 [D0] verdicts
- **Depends on:** A13
- **Files:** `tests/e2e/l4/test_l4_parity_core.py` (create), `tests/e2e/l4/test_l4_parity_priv.py` (create)
- **Change:** two scripts in the `aitm_e2e` env model (header `# e2e: tier=T1 surface=l4 needs=l4`, exit 0 pass / 1 fail / 77 skip, soft-assert battery like `test_l4_capture_flow.py`).
  - `test_l4_parity_core.py`, as operator and agent: (1) `tools/list`: 25 `l4.*` names; `l4.flow.get` inputSchema has `offset` and `limit`, neither required. (2) AC3: `l4.capture.status` as operator **and** agent returns, without error, exactly `{available: false, code: "needs_privilege", reason: R_CAP, captures: []}`; `l4.capture.start {interface: "lo0"}` errors with `L4 unavailable: ` + `R_CAP`. (3) AC4: `l4.intercept.status` = `{available: false, code: "unsupported_platform", reason: R_INT, sessions: []}`; `l4.intercept.start {interface: "lo0"}` errors. Prints each verbatim reply (tokens never printed). Checks (4)–(5), the scope add, are added by A6 on (a').
  - `test_l4_parity_priv.py`: the walk from `/tmp/claude/l4-rig/walk4.py` (capture lo0 → real HTTP, raw TCP to 9099, UDP to the echo → `l4.flow.get` shows the §2 fields → craft + inject to 127.0.0.1:9053 → `l4.send_recv` gets the echo → out-of-scope inject refused), plus AC34: the capture holds no packet to or from bus port 27431 although the script's own bus connection ran throughout. First step reads `l4.capture.status`; when `available` is false it prints `blocked: needs D0: <reason>` and exits 77.
- **Test first:** `python3 -m py_compile` both; `test_l4_parity_core.py` against a rig built from `origin/main` **fails** (exit 1) on (2) and (3).
- **Live check:** rig from this branch: `test_l4_parity_core.py` exits **0**; `test_l4_parity_priv.py` exits **77** printing `blocked: needs D0: ` + `R_CAP`. AC9: `git diff --stat origin/main...HEAD -- crates/aitm-core` prints nothing.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

---

## Unit (a') core scope — `fix/l4-parity-core-scope`

Cut from `main` after (a) merges (spec §7(a'), fork (ii)). The security reviewer is told this unit changes an authority path.

### Task A5: `l4.scope.list` provenance

- **Satisfies:** AC5 (the `source` half)
- **Depends on:** (a) merged; cherry-pick of be9d15e4 where it applies
- **Files:** `crates/aitm-proto-l4/src/commands/{mod,scope}.rs`
- **Change:** `scope_entry_to_value` inserts `"source"`: `"config"` for `L4ScopeSource::Config`, `"runtime"` for `Runtime`; `scope_entry_fields()` lists `source` (`Str`, required). Rhai `l4.scope.list` gets it through the shared function.
- **Test first** (`commands::scope::tests::scope_list_reports_source`): one config entry plus one pushed with `source = Runtime` → two objects, `source` `"config"` then `"runtime"`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task A6: operator scope add through confirm-over-the-wire

- **Satisfies:** AC5, AC6, AC7
- **Depends on:** A5
- **Files:** `crates/aitm-proto-l4/src/guard.rs`, `src/commands/{scope,mod}.rs`, `tests/operator_surfaces.rs`, `tests/language.rs`, `crates/aitm/tests/l4_operator_surfaces.rs`, `tests/e2e/l4/test_l4_parity_core.py`, `aitmproxy-plugin/skills/aitmproxy-overview/SKILL.md`, `aitmproxy-plugin/docs/tool-reference.md` (the two 'not shipped yet' sentences only)
- **Change:**
  - `scope.rs`: `pub(crate) struct OperatorConfirmed(());` with its only constructor `pub(in crate::commands::scope) fn new() -> Self` (it proves a trusted-control dispatch; the confirmation step is the dispatcher's). `ScopeAdd::confirm_prompt` is always `Some` and never tells the caller how to confirm (the MCP server and the CLI explain their own handshake; under policy `ask` the same text is the agent approval card): with valid args `"Confirm l4.scope.add: {capability} scope for {cidr} {ports} on {interface} ({direction}), {rate}. A runtime entry never lifts the dangerous-destination denylist."`, where `{ports}` is `ports 9100-9199` or `all ports`, `{rate}` is `inject rate {pps}pps/{burst}burst` or `inject refused (rate 0)`, and a prefix shorter than /16 (IPv4) or /48 (IPv6) appends ` WARNING: /{n} is a wide range.`; with missing or invalid args `"Confirm l4.scope.add: add an L4 scope entry ({error})."`. `entry_from_params` refuses an `interface` outside `^[A-Za-z0-9._:-]{1,15}$` (IFNAMSIZ) on both add paths. `invoke` builds the entry, then trusted control → `self.guard.add_operator_scope(entry, OperatorConfirmed::new())`, else `self.guard.add_runtime_scope(entry)?`.
  - `guard.rs`: `pub(crate) fn add_operator_scope(&self, entry: L4ScopeEntry, _proof: OperatorConfirmed) -> L4ScopeId` (no widen check) and the existing `add_runtime_scope` both end in one private `fn push_runtime(&self, entry: L4ScopeEntry) -> L4ScopeId` that forces `source = Runtime`. `commands/mod.rs`: `cidr_to_string`, `ports_to_string` become `pub(crate)`. `language.rs` is not changed.
  - Docs: flip the 'not shipped yet' sentences in those two files (the overview's L4 scope paragraph and the tool-reference's `l4.scope.add` bullet) to state that the operator-confirmed add shipped.
- **Test first:**
  - `cargo test --offline -p aitm-proto-l4 --lib`: `scope::tests::confirm_prompt_some_for_empty_args`; `confirm_prompt_summarises_entry` (AC5 args → contains `127.0.0.1/32`, `9100-9199`, `lo0`, `inbound`, `capture`); `confirm_prompt_variants` (ports omitted → `all ports`; `inject_rate {pps: 0, burst: 0}` → `inject refused (rate 0)`; `10.0.0.0/8` → `WARNING: /8 is a wide range`); `scope::tests::interface_is_validated` (empty, 16 chars, control char, ANSI escape refused; `lo0`, `en0`, `utun3`, `br-1` accepted); `scope::tests::operator_scope_cannot_lift_denylist` (AC7, in the one module that can mint the proof: `dangerous_dst_override: true`; operator add of `169.254.169.254/32` eth0 outbound inject passed in with `source: Config` → stored `Runtime`; `check(Inject, 169.254.169.254:80 on eth0)` → `Err(DangerousDestinationBlocked("169.254.169.254".into()))`).
  - `--test operator_surfaces operator_scope_add_skips_widen_gate`: widen off; `ScopeAdd` invoked with `Parts::host(Frontend::Operator)` → `Ok(Str(id))`, list gains `source: "runtime"`; `Parts::host(Frontend::Cli)` → `Ok`; `Parts::host(Frontend::Mcp)` → `Err` with text `R_WIDEN`, list unchanged.
  - `--test language language_scope_add_trusted_caller_still_widen_gated` (AC6 unit; pin, green before and after A6): Rhai `l4.scope.add(#{…})` with a trusted-control `HostCallCtx`, widen off → refused with `R_WIDEN`.
  - `aitm --test l4_operator_surfaces`: `operator_scope_add_confirm_handshake` (`needs_confirmation`, token, the five strings; `_confirm` → id; list `runtime` + `config`; `widen == false` before and after; `l4.scope.remove {id}` → `true`), `agent_scope_add_not_offered_confirmation` (`Frontend::Mcp`, policy `All` → error containing `runtime L4 scope widening is disabled`, `confirm_token` null), `agent_scope_add_ask_approved_still_widen_gated` (policy `Ask`, widen off: the parked agent call is approved by the operator and still refused with the widen text; the approval card carries no `_confirm` instruction; list unchanged), `scope_add_is_confirmable_in_tools_list`. The L4OPS-AC5 tests pass **unmodified**.
- **Live check:** `test_l4_parity_core.py` gains (1b) `l4.scope.add` `confirmable: true`; (4) AC5 with `widen == false`: operator add → `needs_confirmation`, token, the five strings; `_confirm` → id; list shows it `runtime` and the three config entries `config`; widen still false; remove → true. (5) AC6: operator sets agent policy `all`, agent `l4.scope.add` → error containing `runtime L4 scope widening is disabled`, no `needs_confirmation`, list unchanged; policy `auto` → refused by policy; original policy restored. Exits 0 on the (a') rig.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

---

## Unit (b) TUI — `fix/l4-parity-tui`

Spec §7(b) file list. `tests/l4_parity.rs` builds the app with `App::new(TermCaps::from_env(|_| None), "127.0.0.1:27431")`, feeds `App::on_bus(BusEvent::…)` with JSON built in the test, drives `App::update(Action::…)` / `App::run_command(…)`, and asserts on the returned `Vec<BusRequest>` and on `App` state; never `fixture.rs`, `fixture_app_from` or a rendered snapshot. Shared helpers at the top of the file: `l4_tools(confirmable_scope_add: bool) -> Vec<ToolInfo>` (the 25 rig `l4.*` names; `l4.flow.get` declares `offset`/`limit`), `connected(app)`, `intercept_flow("F")`.

**Row-less L4 surface (plan call):** the unprivileged rig has no L4 rows, so B3 adds an **L4 panel** (`Mode::L4`, opened by `:l4` and a key listed in help) showing capture and intercept availability, running captures and the capture commands. The inspector's intercept bar shows the same line when an L4 row is selected.

### Task B1: availability, parked-packet, §2 and tool models

- **Satisfies:** AC10, AC11, AC15, AC39, AC40 (groundwork and units)
- **Depends on:** `R` (the fixture-removal TUI PR) merged; unit (b) lands before system-proxy-auto PR 2
- **Files:** `crates/aitm-tui/src/{l4,action,app}.rs`, `crates/aitm-tui/tests/l4_parity.rs` (create), `crates/aitm-bus-client/src/lib.rs`, `crates/aitm-tui/tests/{common/mod,fix_pass2,tester_components,tester_edge_cases}.rs` (struct literals only)
- **Change:**
  - `aitm-bus-client`: `ToolDef` gains `pub confirmable: bool`, read by `from_json` (absent ⇒ `false`); every `ToolDef { … }` / `ToolInfo { … }` literal adds `confirmable: false`.
  - `l4.rs`: `#[derive(Debug, Clone, PartialEq, Eq)] pub struct L4Availability { pub available: bool, pub code: Option<String>, pub reason: Option<String> }` with `from_reply(v: &Value) -> Self` (object with bool `available` → copy `code`/`reason`; bare array → available; else unavailable, reason `"unrecognised l4 status reply"`), `from_error(message: &str) -> Option<Self>` (`Some` iff it contains `L4 unavailable: `; reason = the text after it), `pending() -> Self` (unavailable, reason `"Reading L4 availability…"`). `status_ids(v, key) -> Vec<String>`. `L4Parked { id, flow, state, length, layers, parked_at: Option<i64> }` with `list_from_json`. `L4State` gains `capture`, `intercept`, `captures`, `parked` and `parked_for(&self, flow) -> Option<&L4Parked>` (first listed; the core lists oldest first). `L4Packet` gains `timestamp`, `proto`, `src`, `dst`, `src_port`, `dst_port`, `bytes: Option<Vec<u8>>`; `L4Flow` gains `started_at` and flow-level addresses, all optional. `supports_window(tools) -> bool`, `flow_get_args(id, window) -> Value` (`{"id", "limit": 0}` / `{"id"}`), `inspect_args(id) -> Value` (`{"id", "offset": 0, "limit": 256}`), `supports_operator_scope_add(tools: &[ToolInfo]) -> bool` (`l4.scope.add` present with `confirmable`). `ascii_column(bytes: &[u8]) -> String` (0x20–0x7e as themselves, every other byte `.`) and `hex_dump(bytes: &[u8]) -> Vec<String>` (16 bytes per row: offset, hex, `ascii_column`).
  - `action.rs`: `BusEvent::L4Availability { capture, intercept, captures: Vec<String> }`, `BusEvent::L4Parked(Vec<Value>)`.
- **Test first** (`cargo test --offline -p aitm-tui --test l4_parity models`): `from_reply(json!({"available": false, "code": "needs_privilege", "reason": "X", "captures": []}))` → `{false, Some("needs_privilege"), Some("X")}`; `from_reply(json!([]))` and `(json!(["C1"]))` → available; `from_error("l4.capture.status: L4 unavailable: X") == Some(L4Availability { available: false, code: None, reason: Some("X".into()) })`; `from_error("connection reset") == None`; `pending().reason == Some("Reading L4 availability…".into())`; `status_ids` of `{"captures": ["C1"]}` and `["C1"]` → `["C1"]`; `L4Parked::list_from_json` of `[{id:"P1", flow:"F", state:"parked", dir:"inbound", length:60, layers:["IPv4","TCP"], parked_at: 1700000000000}]` → one entry `id "P1"`, `parked_at Some(1700000000000)`; `flow_get_args("F", true) == json!({"id":"F","limit":0})`; `inspect_args("F") == json!({"id":"F","offset":0,"limit":256})`; an `l4.flow.get` object without §2 fields still parses; `supports_operator_scope_add(&l4_tools(true)) == true`, `(&l4_tools(false)) == false`, `(&[]) == false`; `ascii_column(&[0x1b, 0x5b, 0x41, 0x0a, 0x7f, 0x7e, 0x41]) == ".[A..~A"`; no `hex_dump` row of 0..=255 contains a char below `' '`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task B2: bus polling of status, parked list and windowed list reads

- **Satisfies:** AC11, AC15 (groundwork); spec §1 (re-read on the slow poll), §2 (list `limit: 0`)
- **Depends on:** B1
- **Files:** `crates/aitm-tui/src/{bus,app,l4}.rs`, `tests/l4_parity.rs`
- **Change:** the slow pass reads `l4.capture.status` and `l4.intercept.status` when offered (a tool error maps through `from_error`; a transport error still ends the session) and emits `BusEvent::L4Availability`; it reads `l4.intercept.list` only when intercept is available. `l4_poll` sends `flow_get_args(id, supports_window)`. Pure `slow_l4_reads(has: impl Fn(&str) -> bool, intercept_available: bool) -> Vec<&'static str>` in `l4.rs` is the list the pass walks. `on_bus` stores availabilities, captures and parked list; an availability change never toasts. Before the first reply both availabilities are `pending()`.
- **Test first** (`--test l4_parity polling`): `slow_l4_reads(|_| true, false)` contains both status verbs and not `"l4.intercept.list"`; `(|_| true, true)` contains it; after `on_bus(L4Availability{capture: from_reply(<AC3 object>), …})`, `app.l4.capture.code == Some("needs_privilege".into())`.
- **Live check:** in B9 (no `l4.intercept.list` from `aitm-tui` on the rig).
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task B3: L4 panel and capture commands

- **Satisfies:** AC15
- **Depends on:** B2
- **Files:** `crates/aitm-tui/src/{app,keys}.rs`, `src/ui/{l4,complete,sidebar}.rs`, `tests/l4_parity.rs`
- **Change:** `Mode::L4` and `ui::l4::panel(app, theme, area, buf)`: `capture: available` or `capture unavailable — <reason>`, the intercept documented-limited line (B4), running capture ids, hints for `:l4 capture <iface> [inbound|outbound]` and `:l4 stop [<id>]`. `run_command`: `l4` opens the panel; `l4 capture <iface> [dir]` with capture unavailable → no request, toast `capture unavailable: <reason>`; else `Call { name: "l4.capture.start", args: {"interface", "direction"} }` (default `inbound`; another word → toast `direction must be inbound or outbound`, no request). `l4 stop <id>` → one `l4.capture.stop {id}`; `l4 stop` → one per running id (none → toast `no running capture`). Completion offers `capture`, `stop`, known interface names, `inbound`/`outbound`. Help lists commands and the panel key.
- **Test first** (`--test l4_parity capture_commands`): unavailable (reason `"X"`) → `run_command("l4 capture lo0") == vec![]`, toast contains `X`; available → `== vec![Call{name: "l4.capture.start", args: json!({"interface":"lo0","direction":"inbound"})}]`, `"l4 capture lo0 outbound"` → `"outbound"`, `"l4 capture lo0 sideways"` → `vec![]`; captures `["C1","C2"]`, `run_command("l4 stop")` → `{"id":"C1"}`, `{"id":"C2"}`; `"l4 stop C1"` → one call.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task B4: Forward / Drop by parked id, documented-limited bar, packet hex

- **Satisfies:** AC10, AC11, AC40 (TUI)
- **Depends on:** B3
- **Files:** `crates/aitm-tui/src/app.rs` (`l4_intercept_verb`, inspect fetch), `src/ui/l4.rs`, `tests/l4_parity.rs`
- **Change:** `fn l4_intercept_verb(&mut self, tool: &str, flow: &L4Flow) -> Vec<BusRequest>`: intercept unavailable → toast `in-path intercept unavailable: <reason>`, no request; else `parked_for(&flow.id)` (none → toast `no parked packet on this flow`) and send `json!({"id": parked.id})`, keeping the scope gate and `self.l4.pending` for the confirm overlay. The flow id is never sent. The bar and the L4 panel render one documented-limited line with the core's reason, with no Forward/Drop/Mutate hints. Selecting an L4 row sends `l4.flow.get` with `inspect_args` when `supports_window`; the packet detail shows `hex_dump` of `bytes`, or `no bytes from this core`. No raw packet byte reaches the terminal.
- **Test first** (`--test l4_parity parked_id`): available, flow `F`, parked `[{id "P1", flow "F"}]` → `update(Action::Resume) == vec![Call{name: "l4.intercept.forward", args: json!({"id":"P1"})}]`, `Kill` → `"l4.intercept.drop"`; no emitted args equal `json!({"id":"F"})`; no parked entry → `vec![]`; unavailable (reason `"Y"`) → `vec![]` for Resume, Kill and Edit, toast contains `Y`.
- **Live check:** AC11 in B9; live forward is [Linux].
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task B5: Mutate and Revert from the craft pane

- **Satisfies:** AC12
- **Depends on:** B4
- **Files:** `crates/aitm-tui/src/{action,app,keys}.rs` (`Action::L4MutateParked`, `Action::L4RevertParked`), `src/ui/l4.rs`, `tests/l4_parity.rs`
- **Change:** in the craft pane of an intercept flow with a parked packet and intercept available, "apply to parked packet" sends `l4.intercept.mutate {id, spec}` with the spec the pane's Build sends to `l4.craft`; "revert" sends `l4.intercept.revert {id}`. Same refusals as B4. Keys are the builder's; help lists them.
- **Test first** (`--test l4_parity mutate`): craft buffer set in the test to `{"layers":[{"ipv4":{"src":"127.0.0.1","dst":"127.0.0.1"}},{"udp":{"src_port":40000,"dst_port":9}}]}` → `update(Action::L4MutateParked) == vec![Call{name: "l4.intercept.mutate", args: json!({"id":"P1","spec":{"layers":[{"ipv4":{"src":"127.0.0.1","dst":"127.0.0.1"}},{"udp":{"src_port":40000,"dst_port":9}}]}})}]`; `L4RevertParked` → `json!({"id":"P1"})`; unavailable → both `vec![]`.
- **Live check:** [Linux].
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task B6: L4 scope section and `:scope add l4`

- **Satisfies:** AC13, AC39 (TUI wiring)
- **Depends on:** B5
- **Files:** `crates/aitm-tui/src/app.rs`, `src/l4.rs` (`L4ScopeEntry` gains `id`, `source`), `src/ui/{overlays,complete}.rs`, `tests/l4_parity.rs`
- **Change:** the scope panel gains an "L4 scope" section (interface, cidr, ports, direction, capability, `config`/`runtime`). When `supports_operator_scope_add(&self.tools)`: `scope add l4 <cidr> <ports> <iface> <inbound|outbound> <capture|inject|intercept>` → `Call { name: "l4.scope.add", args: {cidr, ports, interface, direction, capability} }` (wrong arity or word → usage toast, no request); a `needs_confirmation` reply opens `Mode::L4Confirm` with the core's prompt (add `"l4.scope.add"` to the `CallOk` arms that parse `L4Confirm::from_reply`); confirming re-issues with `_confirm`; success re-reads `l4.scope.list`. When not supported: toast `this core cannot confirm an operator L4 scope add`, no request, and help omits the form. `scope add <host>` is unchanged. Completion offers `l4` only when supported.
- **Test first** (`--test l4_parity scope_add_l4`): with `l4_tools(true)`, `run_command("scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture") == vec![Call{name: "l4.scope.add", args: json!({"cidr":"127.0.0.1/32","ports":"9100-9199","interface":"lo0","direction":"inbound","capability":"capture"})}]`; `on_bus(CallOk{name: "l4.scope.add", value: json!({"status":"needs_confirmation","prompt":"P","confirm_token":"tok-1"})})` → `Mode::L4Confirm` with prompt `"P"`; confirming emits the call plus `"_confirm": "tok-1"`; `"scope add l4 127.0.0.1/32"` → `vec![]`; with `l4_tools(false)` the full command → `vec![]`; `"scope add api.test" == vec![BusRequest::ScopeAdd("api.test".into())]`.
- **Live check:** AC13 in B9.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task B7: L4 chips, filter atoms, help

- **Satisfies:** AC14
- **Depends on:** B6
- **Files:** `crates/aitm-tui/src/{app,filter,keys}.rs`, `src/ui/{bars,complete,flows}.rs` (`flows.rs` only if the row needs the proto), `tests/l4_parity.rs`
- **Change:** `Chip::{Tcp, Udp, L4}` after `WebSocket` (`Chip::ALL` 18 long: `All, Http, Https, WebSocket, Tcp, Udp, L4, H1, H2, Json, …`), labels `TCP`, `UDP`, `L4`; `L4` matches `row.kind == FlowKind::L4`, `Tcp`/`Udp` match `row.l4.proto`. `filter.rs` atoms `~l4 ~tcp ~udp ~icmp` (`Expr::L4`, `Expr::L4Proto(&'static str)`). Help and the filter hint list `~l4 ~tcp ~udp ~icmp`.
- **Test first** (`--test l4_parity chips_filters`, `--lib filter`): with an L4 row from `FlowRow::from_l4` (TCP layers) and an HTTP row: `parse("~l4")` matches the L4 row only; `~tcp` matches it, `~udp` does not; `~icmp` parses; `Chip::L4.matches(<http row>) == false`; `Chip::ALL[4..7]` labels `["TCP","UDP","L4"]`; help contains `~l4 ~tcp ~udp ~icmp`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task B8a: no HTTP verbs on L4 rows

- **Satisfies:** AC16
- **Depends on:** B7
- **Files:** `crates/aitm-tui/src/app.rs`, `tests/l4_parity.rs`
- **Change:** with a selected `FlowKind::L4` row, `Action::Mark` (and the mark it would emit), `Comment`, `Replay`, `BuildPoc` emit no request and toast `<Verb> is not available for L4 flows`.
- **Test first** (`--test l4_parity no_http_verbs_on_l4`): L4 row → `Replay`, `Mark` (and the pick), `Comment` submit, `BuildPoc` each `== vec![]`, toast contains `not available for L4 flows`; an HTTP row → `Replay` emits `BusRequest::Replay(id)`.
- **Live check:** with a real L4 row [D0].
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task B8b: honest agent overlay (display only)

- **Satisfies:** AC17
- **Depends on:** B8a
- **Files:** `crates/aitm-tui/src/{app,model}.rs`, `src/ui/{overlays,bars}.rs`, `tests/l4_parity.rs`
- **Change:** D10c's root cause: the core's policies are `all | auto | ask | readonly | paused` and `AgentPolicy` knows three, so `apply_status` drops `auto` and the overlay falls back to the stale F1 line. Add `AgentPolicy::Auto` and `AgentPolicy::Ask`, parsed and labelled (`"auto"`, `"ask"`) for **display only**: no new key sets them. The `None` branch reads `agent policy not reported by agent.status`. `Action::AgentSet`'s toast becomes `agent.set is not on this bus`. The CA panel line becomes exactly `" install/uninstall ask for a local y/N before the call."`. `bars.rs` colours the two new policies.
- **Test first** (`--test l4_parity agent_overlay`): `AgentPolicy::parse("auto") == Some(AgentPolicy::Auto)`, `("ask") == Some(AgentPolicy::Ask)`; `apply_status(&json!({"policy":"auto","actions_last_minute":0,"connected_clients":[]}))` → `policy == Some(Auto)`. **Tripwire** `no_stale_f1_in_tui_src`: walk `concat!(env!("CARGO_MANIFEST_DIR"), "/src")`; no file contains `core follow-up F1` followed by a non-digit or end of text (the live `F10`–`F15` notes stay).
- **Live check:** AC17 in B9.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task B9: live TUI against the rig, real-core CUA update

- **Satisfies:** AC11, AC13, AC14, AC15, AC17, AC33 (TUI half)
- **Depends on:** B8b
- **Files:** `tests/e2e/l4/test_l4_tui_live.py` (create), `crates/aitm/tests/l4_cua_tui.rs`
- **Change:** `test_l4_tui_live.py`: the worktree's `aitm-tui` in a pty (the `Terminal` class from `tests/e2e/tui/test_tui_intercept.py`, 160×44, `--token-file`) against `AITM_BUS_ADDR`; a separate operator `BusClient` reads `agent.activity`. Checks: (AC17) the Agent overlay's first line starts `policy: auto ·` (or the rig's policy); (AC15) the L4 panel shows `capture unavailable` and the core's capture reason; `:l4 capture lo0` shows the reason and the audit ring has **no** `l4.capture.start` from `aitm-tui` since t0; (AC11) the intercept line shows the core's intercept reason; the Forward/Drop/Mutate keys put no `l4.intercept.*` from `aitm-tui`; (AC14) with real HTTP rows, the `L4` chip shows, help shows `~l4 ~tcp ~udp ~icmp`, `/~l4` leaves zero HTTP rows; (AC13) the "L4 scope" section shows the three config entries; with (a') `:scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture` opens the core's confirm, `y` adds it, it appears within one slow poll, then it is removed over the bus; without (a') the command is refused locally with nothing on the bus; `:scope add 127.0.0.1:9100` still adds HTTP scope (removed after). (AC33) no `L4 unavailable` result for `aitm-tui` after any enabled control. `l4_cua_tui.rs`: intercept and capture steps follow the new behaviour; still a real spawned core (Terminal: `cargo test -p aitm --test l4_cua_tui -- --nocapture`).
- **Test first:** `test_l4_tui_live.py` against `origin/main`'s `aitm-tui` fails (no L4 panel, stale F1 line).
- **Live check:** on `local/l4par-tui-with-core` (with (a) and (a')) exits 0, output quoted; on this branch with (a) only, the AC13 add block takes the refused path and the rest pass. Verdicts quoted for AC10/AC12 [Linux] and AC14/AC15/AC16 [D0] halves.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

---

## Unit (c) web — `fix/l4-parity-web`

Spec §7(c) file list. Placement rules: **every pure builder and rule lives in `panels/l4/model.ts`** (the spec lists `args.test.ts` but no `args.ts`); the 1.5 s timer in `state/context.tsx` (not in the list) is untouched, and **the back-off lives inside `store.refresh()`**, which returns early when its poll plan says nothing is due. Tests: `cd apps/web && npx vitest run src/panels/l4/<file>` (red first), then the full web gate.

### Task C1: wire types, availability, argument builders

- **Satisfies:** AC18, AC19, AC20, AC39 (units); spec §1 compatibility
- **Depends on:** `R` (the fixture-removal web PR) merged; unit (c) lands before system-proxy PR 3
- **Files:** `apps/web/src/panels/l4/model.ts`, `apps/web/src/panels/l4/args.test.ts` (create)
- **Change** (exports from `model.ts`): `L4PacketWire` gains optional `bytes`, `timestamp`, `proto`, `src`, `dst`, `src_port`, `dst_port`; `L4FlowWire` gains optional `started_at`, flow-level addresses, `offset`, `truncated`, `next_offset`; `L4ScopeEntryWire` gains `source?: 'config' | 'runtime'`; `interface L4ParkedWire { id; flow; state: 'parked' | 'mutated'; dir; length; layers; parked_at?: number }`. `interface L4Availability { available: boolean; code: string | null; reason: string | null }`; `availabilityFromReply(reply: unknown)`; `availabilityFromError(message: string): L4Availability | null` (non-null iff the text contains `L4 unavailable: `; reason = the text after it); `statusIds(reply, key)`; `PENDING_AVAILABILITY` (`available: false`, reason `Reading L4 availability…`). Builders: `captureStartArgs(iface, direction)`, `captureStopArgs(id)`, `stopAllArgs(ids)`, `verdictArgs(parkedId)`, `mutateArgs(parkedId, spec)`, `revertArgs(parkedId)`, `interface L4ScopeDraft { cidr; ports; interface; direction; capability }`, `scopeAddArgs(d)`, `supportsFlowWindow(tools)`, `supportsOperatorScopeAdd(tools: readonly { name: string; confirmable?: unknown }[]): boolean` (`l4.scope.add` with `confirmable === true`), `flowGetArgs(id, mode: 'list' | 'inspect', window)`, `parkedFor(parked, flowId)` (first listed), `L4_ARG_BUILDERS: readonly { tool: string; keys: readonly string[] }[]`.
- **Test first** (`args.test.ts`): `captureStartArgs('lo0','inbound')` deep-equals `{interface:'lo0', direction:'inbound'}` with keys exactly `['interface','direction']`; `stopAllArgs(['C1','C2'])` → `[{id:'C1'},{id:'C2'}]`; `verdictArgs('P1')` → `{id:'P1'}`; `mutateArgs('P1', spec)` → `{id:'P1', spec}`; `revertArgs('P1')` → `{id:'P1'}`; `scopeAddArgs(<AC5 draft>)` → `{cidr:'127.0.0.1/32', ports:'9100-9199', interface:'lo0', direction:'inbound', capability:'capture'}`; `flowGetArgs('F','list',true)` → `{id:'F', limit:0}`, `('F','inspect',true)` → `{id:'F', offset:0, limit:256}`, `('F','list',false)` → `{id:'F'}`; `availabilityFromReply({available:false, code:'needs_privilege', reason:'X', captures:[]})` → `{available:false, code:'needs_privilege', reason:'X'}`; `availabilityFromReply([])` → `{available:true, code:null, reason:null}`; `availabilityFromError('l4.capture.status: L4 unavailable: X')` → `{available:false, code:null, reason:'X'}`; `availabilityFromError('boom')` → `null`; `PENDING_AVAILABILITY.reason === 'Reading L4 availability…'`; `parkedFor([{id:'P1',flow:'F',…},{id:'P2',flow:'G',…}], 'G').id === 'P2'`; `supportsOperatorScopeAdd([{name:'l4.scope.add', confirmable:true}]) === true`, `([{name:'l4.scope.add'}])` and `([{name:'l4.scope.add', confirmable:false}])` and `([])` → `false`. **Live schema block**, `describe.skipIf(!process.env.AITM_BUS_ADDR)`: read the rig's `tools/list` over TCP with `AITM_BUS_OPERATOR_TOKEN` and assert every `L4_ARG_BUILDERS` key is in that tool's `inputSchema` (skipped in the gate; run in C10).
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task C2: poll plan and once-per-message logging

- **Satisfies:** AC23 (unit)
- **Depends on:** C1
- **Files:** `apps/web/src/panels/l4/model.ts`, `model.test.ts`
- **Change:** `L4_ACTIVE_MS = 1500`, `L4_IDLE_TICK_MS = 10_000`, `L4_IDLE_SLOW_MS = 60_000`; `interface L4PollClock { lastTickAt: number | null; lastSlowAt: number | null }`; `l4PollPlan(now, clock, idle): { tick: boolean; slow: boolean }` (`idle` = capture unavailable and `l4.flow.list` empty; not idle ⇒ both every call; idle ⇒ `tick` when ≥ 10 s since `lastTickAt`, `slow` when ≥ 60 s since `lastSlowAt`, both on the first call). `tick` reads `l4.flow.list`, `l4.capture.status`, `l4.intercept.status`; `slow` reads `l4.scope.list`, `l4.agent.status`. `createOnceLog(sink): { log(msg); clear() }`.
- **Test first** (`model.test.ts`): calls at `t = 0, 1500, …, 58500` (40) with `idle = true`, updating the clock when a plan fires → `tick` fires **6** times and `slow` **1**, so `l4.*` calls in the minute = 6 × 3 + 1 × 2 = **20** (≤ 30); `idle = false` → `tick` 40 times; `createOnceLog` given `['a','a','b','a']` calls the sink with `['a','b']`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task C3: store wiring and windowed reads

- **Satisfies:** AC20, AC23; spec §1 (re-read on the slow poll), §2 (list `limit: 0`)
- **Depends on:** C2
- **Files:** `apps/web/src/panels/l4/store.ts`, `apps/web/src/panels/l4/args.test.ts` (tripwire)
- **Change:** signals `captureAvailability`, `interceptAvailability` (start `PENDING_AVAILABILITY`), `parked`, `inspected`, `tools`; `refresh()` follows `l4PollPlan` with an `L4PollClock`, reads the status verbs through `availabilityFromReply` / `availabilityFromError`, reads `l4.intercept.list` only when intercept is available, reads rows with `flowGetArgs(id, 'list', window)`, and routes every read failure through one `createOnceLog` into `app.notice`, so each distinct message is logged once. `inspect(id)` fetches `flowGetArgs(id, 'inspect', window)` on selection. Actions `startCapture`, `stopCapture`, `forward`, `drop`, `mutate`, `revert` go through the C1 builders. `firstParkedId` is removed.
- **Test first (tripwire)** `store_reads_through_builders` in `args.test.ts`: `store.ts` (read with node `fs`) contains no `firstParkedId`, no object literal passed directly to `'l4.flow.get'`, `'l4.capture.start'` or `'l4.intercept.` calls (each call's argument is a C1 builder call), and contains `createOnceLog(`. Red on `origin/main`'s `store.ts`.
- **Live check:** AC23 in C10.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task C4: capture controls

- **Satisfies:** AC18, AC19
- **Depends on:** C3
- **Files:** `apps/web/src/panels/l4/{CaptureControls.tsx, L4CaptureBar.tsx, args.test.ts}`
- **Change:** the filter input becomes a direction `<select>` (`inbound` / `outbound`, default `inbound`); Start calls `store.startCapture(iface, direction)`; when capture is unavailable Start is disabled with the core's `reason` as visible text and `title`; a Stop button per running id calls `store.stopCapture(id)`; props `{ capture: L4Availability; running: readonly string[]; … }`.
- **Test first (tripwire)** in `args.test.ts`: no non-test `.ts`/`.tsx` under `apps/web/src` passes a `filter` key to `l4.capture.start`, and `CaptureControls.tsx` has no `filter` prop.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task C5: intercept bar by parked id, documented-limited line

- **Satisfies:** AC20
- **Depends on:** C4
- **Files:** `apps/web/src/panels/l4/{L4InterceptBar.tsx, L4InspectorPanel.tsx, L4Inspector.tsx, L4CaptureBar.tsx, model.ts, model.test.ts}`
- **Change:** `interceptBarModel(avail, parked, flowId): { kind: 'limited'; reason: string } | { kind: 'idle' } | { kind: 'parked'; id: string }`. Unavailable → one line `In-path intercept is not available on this core: <reason>` with no Forward/Mutate/Drop, also shown in the L4 focus view (`L4CaptureBar`). Otherwise Forward/Drop use the existing confirm path with `verdictArgs(parked.id)`; Mutate sends `mutateArgs(parked.id, <editor spec>)`; Revert sends `revertArgs(parked.id)`. The "author the mutation…" stub is gone.
- **Test first** (`model.test.ts`): `interceptBarModel({available:false, code:'unsupported_platform', reason:'Y'}, [], 'F')` → `{kind:'limited', reason:'Y'}`; available with `[{id:'P1', flow:'F'}]` → `{kind:'parked', id:'P1'}`; none for `F` → `{kind:'idle'}`.
- **Live check:** AC20 in C10; live verdicts [Linux].
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task C6: packet time, addresses and inert hex in the inspector

- **Satisfies:** AC40 (web); spec §2 for the web inspector (real packets [D0])
- **Depends on:** C5
- **Files:** `apps/web/src/panels/l4/{PacketList.tsx, LayerTree.tsx, L4Inspector.tsx, model.ts, model.test.ts}`
- **Change:** `packetHeadline(p)` (`127.0.0.1:40000 → 127.0.0.1:9053 · UDP · 36 B`, falling back to the layer summary), `formatPacketTime(ms)` (local `HH:MM:SS.mmm`), `asciiColumn(bytes: Uint8Array): string` (0x20–0x7e as themselves, every other byte `.`), `hexRows(bytes): string[]`. The inspector renders `hexRows(base64ToBytes(bytes))` as text nodes only (never `innerHTML` / `dangerouslySetInnerHTML`), shows `no bytes from this core` without `bytes`, and `truncated: true` adds a "load more" that fetches from `next_offset`.
- **Test first** (`model.test.ts`): `packetHeadline({dir:'outbound', length:36, injected:false, layers:['IPv4','UDP'], proto:'UDP', src:'127.0.0.1', dst:'127.0.0.1', src_port:40000, dst_port:9053})` → `'127.0.0.1:40000 → 127.0.0.1:9053 · UDP · 36 B'`; null addresses → `'IPv4 · UDP · 36 B'`; `asciiColumn(Uint8Array.of(0x1b,0x5b,0x41,0x0a,0x7f,0x7e,0x41)) === '.[A..~A'`. Tripwire in `args.test.ts`: no file under `panels/l4/` contains `innerHTML`.
- **Live check:** `blocked: needs D0` (no captured packet on the rig), quoted in C10.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task C7: L4 scope add with the operator confirm, gated

- **Satisfies:** AC22, AC39 (web wiring)
- **Depends on:** C6
- **Files:** `apps/web/src/panels/l4/{CaptureControls.tsx, store.ts, args.test.ts}`
- **Change:** the scope list shows `config` / `runtime`. When `supportsOperatorScopeAdd(store.tools)`, an add form (cidr, ports, interface, direction, capability) calls `store.addScope(draft)`, which uses `beginGuarded`/`confirmGuarded` from `inject.ts` with `scopeAddArgs(draft)` and the existing `ConfirmInject` dialog (imported, not edited) showing the core's prompt, then re-reads `l4.scope.list`. Otherwise no form renders. Validation text comes from the core.
- **Test first (tripwire)** `scope_add_form_is_gated` in `args.test.ts`: `CaptureControls.tsx` renders the add form only inside a `supportsOperatorScopeAdd(` condition, and `store.ts` sends `l4.scope.add` only from `addScope` through `beginGuarded`. Red before this task (no form, no `addScope`).
- **Live check:** AC22 in C10 (with (a')).
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task C8: TCP / UDP / L4 chips

- **Satisfies:** AC21
- **Depends on:** C7
- **Files:** `apps/web/src/shell/chips.ts`, `apps/web/src/state/app.ts`, `apps/web/src/flows/FlowList.tsx`, `apps/web/src/shell/shortcuts.ts` (only if ⌘-digits do not follow `CHIPS`), `apps/web/src/panels/l4/{model.ts, model.test.ts}`
- **Change:** `Chip` gains `'tcp' | 'udp' | 'l4'`; `CHIPS` gets `{id:'tcp', label:'TCP', group:true}, {id:'udp', label:'UDP'}, {id:'l4', label:'L4'}` after WebSocket, `h1` keeps `group: true`; `isL4Chip(chip)`, `l4ChipMatches(chip, row)`; `matchesChip` is false for an L4 chip; `FlowList` shows L4 rows under `all` and the matching chip. ⌘5 is TCP.
- **Test first** (`model.test.ts`): `CHIPS.map(c => c.label).slice(0, 9)` → `['All','HTTP','HTTPS','WebSocket','TCP','UDP','L4','h1','h2']`; `l4ChipMatches('tcp', <TCP row>) === true`, `('udp', <TCP row>) === false`, `('l4', <UDP row>) === true`; `isL4Chip('http') === false`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task C9a: agent role (D12)

- **Satisfies:** AC24
- **Depends on:** C8
- **Files:** `apps/web/src/panels/agent/L4Toggles.tsx`, `apps/web/src/panels/l4/{CaptureControls.tsx, L4InterceptBar.tsx, L4Inspector.tsx, model.ts, model.test.ts}`, `apps/web/src/shell/RoleBanner.tsx`
- **Change:** `operatorOnlyReason(role: 'operator' | 'agent' | null): string | null` → `null` for operator, else `Operator only: reconnect with the Operator URL the core printed`. On a non-operator connection, Start/Stop capture, Inject, scope add, Forward/Drop/Mutate/Revert and the four gate toggles render disabled with that reason, and their handlers return before any `app.call`. The role banner adds one line that L4 actions need the Operator URL.
- **Test first** (`model.test.ts`): `operatorOnlyReason('operator') === null`; `('agent')` and `(null)` equal the literal above.
- **Live check:** AC24 in C10.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task C9b: no HTTP verbs on L4 ids

- **Satisfies:** D9 (web), AC33 (web part)
- **Depends on:** C9a
- **Files:** `apps/web/src/flows/{ContextMenu.tsx, FlowList.tsx}`, `apps/web/src/shell/shortcuts.ts`, `apps/web/src/panels/l4/{model.ts, model.test.ts}`
- **Change:** `httpVerbAllowed(id, l4Ids: ReadonlySet<string>): boolean`; Replay/mark/comment/PoC from the context menu and keys return without a bus call when the selected id is an L4 id.
- **Test first** (`model.test.ts`): `httpVerbAllowed('l4-1', new Set(['l4-1'])) === false`, `('h-1', new Set(['l4-1'])) === true`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task C10: live browser run on the rig

- **Satisfies:** AC18 (live), AC19, AC20, AC21, AC22, AC23, AC24, AC33 (web half)
- **Depends on:** C9b
- **Files:** `apps/web/scripts/cua-l4.mjs`, `apps/web/scripts/CUA-L4-RUN-RECORD.md`
- **Change:** `cua-l4.mjs` (real spawned `l4.enabled` core, real Chrome over CDP) asserts: Start capture disabled showing the core's capture reason; the intercept line showing the intercept reason with no enabled Forward/Mutate/Drop; chip order and ⌘5; the scope add through the confirm dialog when the core has (a'), and no form when it does not; 60 s idle as operator → no L4 error entries in the activity log and ≤ **30** `l4.*` calls from `web-bridge` in `agent.activity`; on the agent URL every Sensitive L4 control disabled with the operator-only reason and none reaching `agent.activity`. The old "`l4.capture.status` succeeding ⇒ privileged" probe becomes `available` (old shape tolerated). The record holds date, SHAs and each step's PASS/FAIL/blocked line.
- **Test first:** the updated script against an `origin/main` build fails the new assertions.
- **Live check (Terminal, `local/l4par-web-with-core`):** `node apps/web/scripts/cua-l4.mjs` all PASS or explicit `blocked: needs D0`; the live schema block of `args.test.ts` passes against the rig (AC18). Then the in-app browser at the Operator URL, light and dark: L4 focus view, chip bar with real HTTP rows and `L4` selected showing zero HTTP rows, the scope add confirm, the agent URL's disabled controls; screenshots looked at and described. Also on this branch alone against an `origin/main` core: no crash, Start disabled with the old error's text after `L4 unavailable: `.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

---

## Unit (d) macOS — `fix/l4-parity-mac`

Spec §7(d) file list. Not touched: `apps/mac/Extension`, anything `R` removes, `ContentCategory.swift`, the capture start/stop controls and `EmbeddedCoreLaunch.swift` (privilege spec). Placement rules: the context-action model is `VerbTable.swift` (Kit, not listed), so the L4 verb gate is a pure function in `L4.swift` applied by `Session+Verbs.swift`; the craft editor's starting text moves from `L4Inspector.swift` into Kit as `PacketSpecDraft.sample` so a Kit unit can test it. There is **no row-less Craft sheet** (Decision 6): the Scope page's L4 section is the row-less L4 home for availability and scope. Kit tests: `cd apps/mac && swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build --filter L4Tests` (Terminal), red first.

### Task M1: availability from the status replies, parked-id verdict args

- **Satisfies:** AC26 (Kit), AC28 (Kit)
- **Depends on:** `R` (the fixture-removal mac PR) merged
- **Files:** `apps/mac/Sources/AitmproxyKit/L4.swift`, `apps/mac/Tests/AitmproxyKitTests/L4Tests.swift`
- **Change:** `L4Availability` drops `embeddedReason` and `resolve(embeddedCore:wireError:)`, gains `case pending` (display text `Reading L4 availability…`) and `public static func resolve(status: JSONValue?, error: String?) -> L4Availability` (object with bool `available`: `true` ⇒ `.available`, `false` ⇒ `.degraded(reason: reason ?? "L4 unavailable")`; bare array ⇒ `.available`; no status and an error containing `L4 unavailable: ` ⇒ `.degraded(reason: <text after it>)`; neither ⇒ `.pending`). `public struct L4ParkedPacket: Hashable, Sendable { id: String; flow: FlowID; state: String; length: Int; layers: [String]; parkedAt: Date? }` with `list(_:)` and `first(for:in:)` (first listed; the core lists oldest first). `public enum L4Verdict { public static func args(parkedID: String) -> [String: JSONValue] }`. Tests of the removed API are replaced.
- **Test first:** `testResolveReadsStatusObject`: `["available": false, "code": "needs_privilege", "reason": "X", "captures": []]` → `.degraded(reason: "X")`; `["available": true]` and `[]` → `.available`; `resolve(status: nil, error: "l4.capture.status: L4 unavailable: X")` → `.degraded(reason: "X")`; `resolve(status: nil, error: nil)` → `.pending`, whose text is `Reading L4 availability…`. `testVerdictArgsCarryParkedID`: `L4Verdict.args(parkedID: "P1") == ["id": .string("P1")]`. `testParkedListAndFirst`: entries for F then G → `first(for: FlowID("G"), …)?.id == "P2"`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task M2: §2 fields, windowed reads, scope items, confirmable

- **Satisfies:** AC25, AC30, AC39 (Kit)
- **Depends on:** M1
- **Files:** `apps/mac/Sources/AitmproxyKit/L4.swift`, `apps/mac/Sources/AitmBusClient/ToolDescriptor.swift`, `apps/mac/Tests/AitmproxyKitTests/L4Tests.swift`
- **Change:** `L4Packet` gains `bytes: Data?`, `timestamp: Date?`, `proto`, `src`, `dst`, `srcPort`, `dstPort`; `L4Flow` gains `startedAt` and flow-level addresses; `target` becomes `lo0 → 127.0.0.1:9053` when `dst`/`dstPort` exist. `ToolDescriptor` gains `public let confirmable: Bool` (decoded from `tools/list`; init parameter defaulting to `false`). `public enum L4Wire { supportsWindow(_:) -> Bool; supportsOperatorScopeAdd(_ tools: [ToolDescriptor]) -> Bool; flowGetArgs(id:inspect:window:) -> [String: JSONValue] }`. `public struct L4ScopeItem: Hashable, Sendable, Identifiable { id, cidr, ports, interface, direction, capability, source }` with `list(_:)` and `public func covers(interface: String, dst: String, port: Int?) -> Bool` (same interface, `dst` inside `cidr`, `port` inside `ports` or `ports` is all); `public struct L4ScopeDraft { cidr, ports, interface, direction, capability; public var args: [String: JSONValue] }`.
- **Test first:** `testPacketParsesSection2Fields` (`bytes: "3q0="` → `Data([0xde, 0xad])`, `timestamp: 1700000000123` → `Date(timeIntervalSince1970: 1700000000.123)`, `dstPort == 9053`); `testFlowTargetUsesDestination` → `"lo0 → 127.0.0.1:9053"`; `testOldFlowShapeStillParses`; `testFlowGetArgs` (`["id", "limit": 0]`, `["id", "offset": 0, "limit": 256]`, `["id"]`); `testScopeItemsDraftAndCovers` (sources `config`/`runtime`; the AC5 draft's `args`; item `lo0 127.0.0.1/32 9000-9999` covers `("lo0", "127.0.0.1", 9053)`, not `("lo0", "127.0.0.1", 8999)`, not `("en0", "127.0.0.1", 9053)`, not `("lo0", "10.0.0.1", 9053)`); `testSupportsOperatorScopeAdd` (`confirmable: true` → `true`; `false`, absent tool → `false`).
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task M3a: the accepted craft sample

- **Satisfies:** AC27 (Kit)
- **Depends on:** M2
- **Files:** `apps/mac/Sources/AitmproxyKit/L4.swift`, `apps/mac/Tests/AitmproxyKitTests/L4Tests.swift`
- **Change:** `PacketSpecDraft.sample: String` is the YAML `layers: [ipv4 {src 127.0.0.1, dst 127.0.0.1}, udp {src_port 40000, dst_port 9}, raw "hello-l4"]` in block style; `PacketSpecDraft.parse` accepts a `raw` layer as a quoted string (UTF-8) or `[n, n, …]` and emits `{"raw": [bytes]}` as integers.
- **Test first:** `testSampleSpecIsWhatTheCoreAccepts`: `parse(sample)` equals `{"layers": [{"ipv4": {"src": "127.0.0.1", "dst": "127.0.0.1"}}, {"udp": {"src_port": 40000, "dst_port": 9}}, {"raw": [104, 101, 108, 108, 111, 45, 108, 52]}]}`; no `sport`, `dport` or `data` key anywhere.
- **Live check:** AC27 in M9 (`l4.craft` over the bus). Trap: a byte list encoded as floats is rejected by the core.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task M3b: L4 row verb gate

- **Satisfies:** AC29 (Kit)
- **Depends on:** M3a
- **Files:** `apps/mac/Sources/AitmproxyKit/L4.swift`, `apps/mac/Tests/AitmproxyKitTests/L4Tests.swift`
- **Change:** `public enum L4RowVerbs { public static func gate(_ item: VerbItem, row: FlowRow) -> VerbItem }`: on a `kind == .l4` row, items whose `tableKey` is `.resume, .edit, .kill, .delete, .replay, .editAndReplay, .buildPoC, .resumeSelected, .killSelected, .comment`, or any mark (matched with `if case .mark = item.tableKey`), come back `enabled: false`, `disabledReason: "Not available for L4 flows"`; other rows and verbs are unchanged.
- **Test first:** `testL4RowOffersNoHTTPVerbs`: for `L4Flow(…).row(seq: 1, inScope: true)`, `VerbTable.items(for: VerbContext(row: row)).map { L4RowVerbs.gate($0, row: row) }` has no enabled mark, comment, replay or buildPoC, and a `.mark(.red)` item built in the test comes back disabled; for an HTTP row every item is unchanged.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task M4a: availability, scope and parked state from the core

- **Satisfies:** AC26 (wiring)
- **Depends on:** M3b; `BusService.swift` waits for S-041 and then mac-architecture 2a; `Session.swift` waits for #197, #201 and `R`
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/BusService.swift`, `apps/mac/Sources/Aitmproxy/Session.swift`
- **Change:** `Session.swift`: replace `l4EmbeddedCore`, `l4LastWireError` and the computed `l4Availability` with stored `l4CaptureAvailability`, `l4InterceptAvailability` (start `.pending`), `l4Scope: [L4ScopeItem]`, `l4Parked: [L4ParkedPacket]`, `l4CanAddScope: Bool`; no `APP_L4_EMBEDDED` read remains. `BusService.pollLoop`, on the slow cadence (no faster than the HTTP poll): `l4.capture.status`, `l4.intercept.status` (through `L4Availability.resolve`), `l4.scope.list`, `l4.intercept.list` only when intercept is available, and `l4CanAddScope = L4Wire.supportsOperatorScopeAdd(tools)`.
- **Test first:** the Kit units of M1–M2 are the logic; red check: against the rig, `origin/main`'s bundle never calls `l4.capture.status` (audit ring).
- **Live check:** in M9.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task M4b: live L4 rows and the live-path tripwire

- **Satisfies:** AC25
- **Depends on:** M4a (same external waits)
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/BusService.swift`, `apps/mac/Sources/Aitmproxy/Session.swift`, `apps/mac/tools/check-l4-live.sh` (create)
- **Change:** when `tools` offers `l4.flow.list` and `l4.flow.get`, each poll calls `l4.flow.list`, then `l4.flow.get` with `L4Wire.flowGetArgs(id:, inspect: false, window:)` per id, builds `L4Flow`s into `session.l4Details` and rows with `row(seq:inScope:)`, where in scope means some capture `L4ScopeItem` `covers(interface:dst:port:)` the flow's interface, `dst` and `dstPort`, and appends them after the HTTP rows in the one `session.rows` assignment. `check-l4-live.sh` exits 1, naming the file, if `BusService.swift` lacks `l4.flow.list` or `l4.flow.get`, or if `APP_L4_EMBEDDED` appears anywhere under `apps/mac/Sources` or `apps/mac/tools` (except this script); else prints `check-l4-live: ok`. `R` deletes `apps/mac/tools/cua-l4.sh`; if it still exists, rebase on `R` first.
- **Test first:** `check-l4-live.sh` on `origin/main`'s tree fails (exit 1, naming `BusService.swift`); after the change it prints `check-l4-live: ok`.
- **Live check:** AC25 in M9.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task M5: inspector: sample, parked ids, documented-limited bar, §2 display

- **Satisfies:** AC27, AC28, AC40 (mac)
- **Depends on:** M4b
- **Files:** `apps/mac/Sources/Aitmproxy/Inspector/L4Inspector.swift`, `apps/mac/Sources/AitmproxyKit/L4.swift`, `apps/mac/Tests/AitmproxyKitTests/L4Tests.swift`, `apps/mac/tools/check-l4-live.sh`
- **Change:** `craftYAML` starts from `PacketSpecDraft.sample` (`L4Inspector.sampleSpec` is deleted). Inject is disabled with `session.l4CaptureAvailability`'s reason when degraded. `L4InterceptBar` takes `availability` and `parked: L4ParkedPacket?`: degraded ⇒ one documented-limited line with the core's reason and **no** buttons; available with a parked packet ⇒ Forward/Drop sending `L4Verdict.args(parkedID:)` through the existing confirm handshake. The packet list and detail show time, `src:port → dst:port`, and a hex dump from an inspect window fetch, rendered with Kit `L4Hex.asciiColumn(_ bytes: Data) -> String` and `L4Hex.rows(_:) -> [String]` through `Text` only; `no bytes from this core` otherwise. `check-l4-live.sh` gains the check `inspector-parked-id`: fails if `L4Inspector.swift` contains `sampleSpec` or lacks `L4Verdict.args`.
- **Test first:** `testAsciiColumnIsInert`: `L4Hex.asciiColumn(Data([0x1b, 0x5b, 0x41, 0x0a, 0x7f, 0x7e, 0x41])) == ".[A..~A"`; `check-l4-live.sh` fails `inspector-parked-id` before the change.
- **Live check:** AC28 in M9; `tools/grid-lint.sh`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task M6: no HTTP verbs on L4 rows

- **Satisfies:** AC29
- **Depends on:** M5
- **Files:** `apps/mac/Sources/Aitmproxy/Session+Verbs.swift`, `apps/mac/tools/check-l4-live.sh`
- **Change:** `verbItems(for:)` and `verbItem(_:for:)` map through `L4RowVerbs.gate(_:row:)`; `perform(_:on:)` already refuses a disabled item. `check-l4-live.sh` gains `verbs-gated`: fails if `Session+Verbs.swift` lacks `L4RowVerbs.gate`.
- **Test first:** `verbs-gated` fails before the change; M3b's Kit test is the logic.
- **Live check:** with a real L4 row [D0].
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task M7: Scope page L4 section

- **Satisfies:** AC26 (the Scope page line), AC28 (intercept line), AC30
- **Depends on:** M6
- **Files:** `apps/mac/Sources/Aitmproxy/Panels/{ScopePanel,ScopeSheet}.swift`, `apps/mac/tools/check-l4-live.sh`
- **Change:** when `session.l4Enabled`, an "L4 scope" section under the host list: the capture line `Capture and inject unavailable: <reason>` (or `Capture and inject available`), the intercept documented-limited line with the core's reason, and the `session.l4Scope` list (cidr, ports, interface, direction, capability, `config`/`runtime`). Only when `session.l4CanAddScope`, an add form sends `L4ScopeDraft.args` with `l4.scope.add`, shows the core's `needs_confirmation` prompt in the existing `L4ConfirmRequest` dialog, re-issues with `_confirm`, and refreshes `l4.scope.list`. No remove action, no Craft button. `ScopeSheet` counts L4 entries. Within the foundation tokens and the icon/editorial rules. `check-l4-live.sh` gains `scope-add-gated`: fails if `ScopePanel.swift` mentions `l4.scope.add` without `l4CanAddScope`, or mentions `l4.scope.remove`.
- **Test first:** M2's `testScopeItemsDraftAndCovers`; `scope-add-gated` red on a deliberately ungated draft, green after.
- **Live check:** AC26, AC30 in M9; `tools/grid-lint.sh`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task M8: phantom pinned hosts (D15)

- **Satisfies:** AC31
- **Depends on:** M7
- **Files:** none expected. If the cause is in a file not in the (d) list, **stop and report**.
- **Change:** reproduce first with a new `APP_DEFAULTS_SUITE` and a new empty `APP_STORE` against the rig. Likely cause at 5eac2a5: `Session.loadFixtures()` set `pins`, whose `didSet` wrote `pins.json` into a shared `APP_STORE`. If the pins do not appear on `R`'s tree, record that with the screenshot and the `pins.json` listing and change nothing; if they do, fix the writer only if it is in a listed file.
- **Live check:** AC31 screenshots (light and dark) of the pinned section: none; `ls -la <APP_STORE>` shows no `pins.json` or one with an empty `hosts` list.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task M9: live CUA script and the macOS walk

- **Satisfies:** AC25–AC31, AC33 (mac half)
- **Depends on:** M8
- **Files:** `apps/mac/tools/cua-l4-live.sh` (create); `apps/mac/Sources/Aitmproxy/SelfTest+Live.swift` (only if it survived `R` and its L4 checks need the new shape)
- **Change:** `cua-l4-live.sh [--dark]` launches `/tmp/Aitmproxy-dev-l4par.app` with `APP_LIVE=1`, a fresh `APP_STORE` under `/tmp/claude/`, a fresh `APP_DEFAULTS_SUITE`, and the operator token read from the 0600 config into the env (never printed); stops only the PID it started; takes winshot screenshots of the Flows page, the Scope page's L4 section and the pinned section; reads `agent.activity` for `aitm-mac` with a small inline python over `tests/e2e/aitm_e2e/bus.py`; and sends `l4.craft` with `PacketSpecDraft.sample` parsed (the same JSON as M3a) over the bus.
- **Test first:** against `origin/main`'s bundle, AC25 (no `l4.flow.list` from `aitm-mac`) fails.
- **Live check (Terminal, `local/l4par-mac-with-core`; (a') for AC30's add):** AC25 `l4.flow.list` from `aitm-mac` on every poll over 60 s (counts quoted); AC26 the Scope page reads `Capture and inject unavailable: ` + the core's reason; AC27 `l4.craft` returns `length 36` (in-app Build: `blocked: needs D0`); AC28 the intercept line shows the core's reason with no Forward/Drop; AC29 with real HTTP rows the `TCP UDP L4` chips are present and `L4` leaves zero HTTP rows; AC30 the three config entries are listed, and with (a') the AC5 entry is added through the confirm (then removed over the bus), without (a') no form; AC31 (M8); AC33 no enabled control returned `L4 unavailable` for `aitm-mac`. Light and dark screenshots looked at and described. Live L4 rows and Forward/Drop: `blocked: needs D0` / `blocked: no Linux rig`.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

---

## Unit (e) docs — `docs/l4-parity`

Spec §7(e) file list. Starts after (a) is reviewed; merges after (a) and (a').

### Task E1: the `l4.*` family in the catalogue and the tool reference

- **Satisfies:** AC32 (first half)
- **Depends on:** A9 and A6 (behaviour final)
- **Files:** `docs/research/mcp-tool-catalog.txt`, `aitmproxy-plugin/docs/tool-reference.md`
- **Change:** regenerate both from an `l4.enabled` core built from (a) + (a') (`AITM_CONFIG=/tmp/claude/l4-rig/config.yaml aitm --help` feeding `node aitmproxy-plugin/scripts/gen-tool-reference.mjs`, if `--help` lists `l4.*` under that config), or add the 25 entries by hand. The reference drops "the family is not listed here" and states that `l4.*` appears only with `l4.enabled: true`.
- **Test first (the check):** a python one-liner over `tests/e2e/aitm_e2e/bus.py` reads the rig's `tools/list` and prints any `l4.*` name missing from each file; on `origin/main` it prints all 25 for both.
- **Live check:** the same check prints nothing (output quoted).
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

### Task E2: the agent skills

- **Satisfies:** AC32 (second half)
- **Depends on:** E1
- **Files:** `aitmproxy-plugin/skills/aitmproxy-overview/SKILL.md`, `aitmproxy-plugin/skills/aitmproxy-intercept-mutate/SKILL.md`
- **Change:** overview gains an "L4 (raw TCP/UDP)" section: the status verbs answer `available`, `code`, `reason` (and what `needs_privilege`, `unsupported_platform`, `not_configured` mean); `l4.scope.add` is operator-confirmed and an agent is refused unless the operator opened the Widen gate; `l4.intercept.*` is Linux NFQUEUE only; verdict verbs take the **parked id** from `l4.intercept.list` (oldest first), never the flow id; `l4.flow.get` takes `offset`/`limit` (`limit: 0` for listing), returns `bytes` per packet: always to the operator or the CLI; to an agent only for captured packets when its Capture gate is open and for injected packets when its Inject gate is open, and pages with `next_offset` when `truncated`. Intercept-mutate gains one paragraph separating HTTP `flow.intercept` / `flow.resume` from `l4.intercept.*`.
- **Test first (the check):** `grep -c` for `available`, `code`, `reason`, `l4.scope.add`, `parked id`, `Linux`, `next_offset` in the overview; each 0 on `origin/main`.
- **Live check:** each ≥ 1; human read-through by the spec reviewer.
- **Done when:** the tests and checks above pass with their output quoted, and the unit's gate passes.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| (a) A10/A11 | security | Critical | Self-exclusion guarded only the capture loop; send_recv replies, Linux parks and NE ingress units reach the same store that `l4.flow.get` now serves with bytes | fixed: `L4Guard::admit_frame`/`admit_endpoints` choke point + intercept forwards self traffic (d9f01f95); send_recv BPF + Ignore, NE ingress, tui on_bound (53a95d1a) |
| (a) A11 | security | Important | Capture gate alone exposed bytes of intercept/craft flows an agent could not capture | fixed d9f01f95: bytes gate keyed on flow kind (Capture→Capture, SendRecv/craft→Inject, Intercept→Intercept); spec §2.2 amended |
| (a) A10 | security | Important | `aitm tui` with an ephemeral bus port never added it to the self-port set | fixed 53a95d1a (tui.rs on_bound hook) |
| (a) A13 | quality, spec | Important | `parked_seq` per session: unfiltered `l4.intercept.list` interleaved sessions | fixed d9f01f95: process-wide `NEXT_PARKED_SEQ`, sort `(parked_seq, id)`, tester's cross-session test un-ignored |
| (a) A9 | spec | Important | priv cell's BPF assertion false-fails on a multi-port rig | fixed 8b5fed22 (tester): parses both filter forms |
| (a) A9 | spec | Important | Agent scope-add live check (AC6) landed in (a) though planned for (a') | accepted by the orchestrator 2026-11-01: the check is correct and runs against R_WIDEN; A6's live check on (a') turns the AC5 skip into a pass |
| (a) A4/A10/A13/A15/e2e | quality | Minor ×14 | description whitespace, `epoch_ms`/`field` duplication, triple frame decode, three self-port writers, status verbs exempted by name, Rhai `flow.get` unpaged, `ParkedTable` leaks `entries`, test helper duplication, implementation-asserting tests, e2e helper duplication, never-ran `[ok]`, missing `serial`, hard-coded tool count, duplicated cfg list | fixed d9f01f95 except: e2e status-parsing helpers stay per cell (a shared `aitm_e2e/l4.py` is follow-up work for unit (e), file outside (a)) |
| (a) A4 | spec | Minor | macOS probe unit test asserted the literal reason | fixed d9f01f95: asserts `code` and a non-empty reason |
| (a) A7 | spec | Minor | `pub const DEFAULT_INTERFACE` not recorded | accepted by the orchestrator 2026-11-01: recorded here; needed so both test files share one per-OS constant |
| (a) A5 | spec | Minor | `commands/scope.rs` missing from §7(a); A5 filed under (a') | fixed: spec §7(a) lists it; A5 stays in (a) (Decision 5) |
| (a) A2 | security | Minor | `l4.flow.get` clones the whole flow under the store lock whatever the window | accepted by the orchestrator 2026-11-01 as follow-up (windowed store accessor in `src/flow.rs`, the store, outside (a)) |
| (a) §2.1 | security | Minor | Other cores on the host and the CDP port are not excluded | accepted; recorded as a known limit in spec §2.1 |
| (a) A14 | quality | Minor | `docs/design/languages/rhai.api.json` still lists `flow.get` with only `id` | fixed in (a) after the Terminal gate's `shipped_namespaces_equal_production_assembly` golden went red: the `l4` namespace entry regenerated to the production signature (offset, limit, per-packet bytes text); file claimed through the orchestrator |
| (a) A11 (re-panel) | security | Important | Per-flow-kind bytes gate let an Inject-only agent read captured send_recv replies | fixed 28af06e3: per-packet rule (captured→Capture gate, injected→Inject gate); spec §2.2/AC35 amended 262b15ab |
| (a) A13 (re-panel) | quality | Important | `expire_due` deep-cloned every parked packet per reader pass | fixed f3d5a4f2: `ParkedTable::due()` by reference |
| (a) fix 2 (re-panel) | security | Minor ×2 | NE ingress ran the frame decoder over UDP payloads (crafted payload could suppress a record); intercept self-check parsed as Ethernet while `ip_target` parses L3 | fixed e5ac6f63 (target-only admission), 0b95ef21 (one L3 parse) |
| (a) fix 2 (re-panel) | security | Minor | Intercept gate alone shows parked bytes | superseded by the per-packet rule (parked packets are captured → Capture gate) |
| (a) fix 1/2 (re-panel) | quality | Minor ×9 | source-grep tui test, dead `is_self_traffic`, caller-side loopback check for the BPF clause, `&[]` frame marker in ingress, duplicated self-port hook, triple transport mapping, needless clones in scoped send_recv, SeqCst + overclaiming doc, fifth fixture builder | fixed 7570eb39, 2e3514d2, e5ac6f63, 5d841ec9, 7f5aac56, fed99d25 (`is_self_traffic` deleted and `self_exclusion_bpf(interface)` in 2e3514d2) |
| (a) docs (re-panel) | spec | Important | §2.2 amendment not carried into Goals, AC35, Decision 2, A11, E2 | fixed 262b15ab (per-packet rule everywhere) |
| (a) docs (re-panel) | spec | Minor ×4 | AC34 names only the capture loop; Constraints bullet lacks tui/ingress; A10/A13/A9 task text drifted; Review log SHAs missing; `is_loopback_interface` pub | fixed 262b15ab; `is_loopback_interface` `pub(crate)` in 2e3514d2 |
| (a) merge | spec | Minor | `Cargo.lock` touched (d2261658) outside §7(a) | accepted by the orchestrator 2026-11-01: mechanical re-resolution after merging main 3d710ab (`aitm-sysproxy` 0.5.6→0.5.7, the workspace version); cargo makes the same edit on any build |
| (a) merge (pass 3) | security, quality | Minor / Important | Two fallible `local_addr()?` calls left after the system-proxy auto-set (restore-on-exit invariant); addresses read twice | fixed 5015b1f2 (pre-bound addresses), 340a5bfb (one iterator, duplicate configured-port add dropped) |
| (a) fix 3 (pass 3) | quality | Minor ×4 | tui bind test failed in the sandbox instead of skipping; `ip_endpoints` duplicated the address extraction; two adjacent bools in `bytes_visible`; test helpers duplicated again | fixed 340a5bfb (`PermissionDenied` skip, `endpoints_of`, `BytesView`, shared helpers) |
| (a) docs (pass 3) | spec | Minor ×3 | Review log SHAs; AC34 tui test name; `Cargo.lock` row | fixed d55b0fc9 and this row |
| (a) pass 3 | spec, security | PASS | third-pass verdicts: spec PASS, security PASS; quality FAIL only on the fallible-call item fixed in 5015b1f2 before its report landed | closed; fix task 4 touched Minors only, verified by the Terminal gate on the final head (no fourth panel pass) |
| (e) order | spec | Important | (e) merged after (a) only, ahead of (a') | accepted by the orchestrator 2026-11-01 (it released (e) after #215); A6 on (a') gains a step that flips the two 'not shipped' passages (overview scope paragraph; tool-reference L4 bullet) |
| (e) E2 | spec | Minor | frontmatter `description` edits in both skills | accepted by the orchestrator 2026-11-01: safe, single-line scalars, under 1024 chars, pinned phrases intact |
| (a') A6 | security | PASS; Minor ×4 | confirm prompt's "Re-issue with `_confirm`" sentence misled on the `ask` approval card; `interface` unvalidated (IFNAMSIZ, control/ANSI chars); no test that an `ask`-approved agent add is still widen-gated; `OperatorConfirmed` public with a `test_only` constructor | fixed c308df8d: items 1-4 of the fix task (prompt sentence dropped in both forms; `validate_interface` on both add paths; `agent_scope_add_ask_approved_still_widen_gated`; `pub(crate)` proof, `test_only` deleted, AC7 test moved into `commands::scope::tests`) |
| (a') A6 | quality | PASS; Minor ×8 | `test_only` escape hatch; magic `0..65535` in prompt and `parse_ports`; stale widen-gate comments in `commands/mod.rs` and `module.rs`; redundant `contains` loop and `ports`-stripping `ac5_params`; empty-args prompt asserted by prefix/suffix only; `rhai_` test name for a language-wide pin; e2e (5) double-counted the (1b) failure and (1b) had no agent detail, header named A9 only; tool-reference "/16 or /48" without families, overview wording and ragged wrap | fixed c308df8d: items 4-8 of the fix task (`PortRange::ANY`/`is_any`, comments rewritten, tests tightened, `language_scope_add_trusted_caller_still_widen_gated`, e2e note + detail + "(plan tasks A9, A6)", docs re-worded and re-wrapped); the Ask-card text fixed by item 1 |
| (a') A6 / docs | spec | A6 clean; Minor ×2 | parity spec Open questions still listed fork (ii) as open and §8 said "merges after Matt answers fork (ii)"; plan Status said fork (ii) is with Matt; `test_only()` deviated from the spec's "only constructor" sentence | fixed c308df8d: items 10-11 of the fix task (spec/plan marked decided 2026-11-01, operator confirm); the `test_only` deviation resolved by item 4 |
| (a') docs | spec | Important ×2 (privilege plan) | p1b "Cut after" ignored parity (a') though p1b modifies five files (a') touched; Status line did not record Question 2's blocking of P7.1 and the AC5 `all` half of P1b.17; the spike rule paraphrased the spec; §10 file map missed every Claims-table file the plan added, kept `L4.swift` (the plan decodes privilege in `PacketCapture.swift`), carried a broken Status paragraph and three stale "open question 6" references | fixed c308df8d: items 9-10 of the fix task (privilege plan row, Overlaps, Status, verbatim spike rule; privilege spec §10 "Architect's call" sub-list per unit with the six behaviour surfaces flagged for Matt, `L4.swift` removed, Status paragraph repaired, "the open item (headless `setcap` doc)") |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
