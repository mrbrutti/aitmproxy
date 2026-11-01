# System proxy automation implementation plan

**Status:** approved (2026-10-31, self-approved under Matt's mandate; see the spec's Status line; addendum PR 5 / Tasks 32–42 added 2026-10-31 for spec D17 (CA trust), approved under the same mandate — Task 41 additionally needs Matt's explicit go)
**Spec:** `docs/superpowers/specs/2026-10-31-system-proxy-automation-design.md`
(approved 2026-10-31; acceptance criteria SP-AC1 … SP-AC28, plus SP-AC29 … SP-AC38 from the D17 addendum)
**Research:** `docs/research/16-system-proxy.md`
**Branch / worktree (PR 1):** `claude/system-proxy-automation-a08c0c`
(`/Users/matt/Security/aitmproxy/.claude/worktrees/system-proxy-automation-a08c0c`,
main merged at `b109ca80` v0.5.5, which already contains PR #200 `capture.status`)

## Overview

Five PR groups, merged separately by the orchestrator, in this order (PR 5 was added by the D17 addendum):

| Group | What | Branch / gate |
|---|---|---|
| **PR 1 core** | new crate `crates/aitm-sysproxy`, `config_file.rs`, `wire.rs`, `control.rs`, `main.rs`, the three contract pins, `is_operator_only`, two live proofs | this worktree; unblocked (PR #200 is in) |
| **PR 2 TUI** | `:sysproxy`, key `s`, pill word | WAIT: after the fake-data-removal TUI PR and l4-parity's TUI unit; never touch `crates/aitm-tui/src/fixture.rs` |
| **PR 3 web** | pill menu button, `app.proxy.systemProxy` | WAIT: after the fake-data-removal web PR and l4-parity's web unit; never touch `apps/web/src/bus/mock.ts` or `apps/web/src/bus/noise.ts` |
| **PR 4 mac** | `SystemProxyFacts`, Settings ▸ Proxy, first-run sheet, nudge, menu, tripwire | WAIT: after PR 1 merges, after the mac fake-data-removal PR, after mac-attribution's PR lands `AitmproxyKit/SystemProxyState.swift`; `Bus/BusService.swift` only after S-041; `Session+Verbs.swift` after l4-parity's mac unit |
| **PR 5 CA trust** | `aitm-ca` operator gate + macOS trust read-back + `Cancelled`; TUI/web `· CA trusted` word and `scope: user`; mac `Session+CATrust.swift`, sheet CA row, `.trustCA`/`.openCAPanel`, tripwire; gated live proof | own branch from `main` after PR 1; core tasks unblocked; TUI task after PR 2, web task after PR 3; mac tasks after mac-attribution's `CATrustFacts` PR and PR 4 Task 28; **Task 41 only after Matt's explicit go** |

Within PR 1 the order is: Task 1 (skeleton) → Wave B {2, 3, 4, 5, 12} in parallel →
Task 7 (watchdog, needs 4) → Task 6 (the `SystemProxy` engine, needs 2, 3, 4, 7) →
Task 8 (plugin) → Task 9 (wiring) → {Task 10 main.rs ∥ Task 11 pins} → Task 13 docs
→ live proofs 14 (macOS) and 15 (Linux). Independent sets are listed at the end.

### Rules every task obeys

1. **Test first.** Write the failing test, run it, quote the red output; write the
   minimum code; run it green; quote that too. No production code before a red test.
2. **Rust gate**, every task, in the sandbox (cargo works offline):
   `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
   Once per PR group the FULL gate also runs in the **Terminal panel**: `tui_live_bus`
   binds a port and fails only there. A Coder that cannot bind says so; it does not
   skip the test.
3. **Evidence rule (Matt, verbatim from the spec's Constraints):** FIXTURE, SNAPSHOT,
   SELF-TEST, MOCK-BUS OR TUI-FIXTURE RUNS ARE NEVER EVIDENCE AND NEVER A REGRESSION
   GATE FOR ANY FRONTEND. Accepted evidence: Rust/Kit unit tests of pure logic
   (scripted executors, parsers, state-file round trips, watchdog decision logic),
   source tripwires, and the real frontend against a real core on a real machine
   with before/after `scutil --proxy` (macOS) or `gsettings get` (Linux, Lima VM
   `cis-lab`). Live proofs are quoted in the PR body.
4. **Never print a bus token**: not in a test, a log line, a PR body, a script's
   output. Scripts read tokens from `0600` files into variables and never `echo` them.
5. **Never change Matt's real system proxy** except in the final live-proof tasks
   (14, 15, 20, 24, 31), whose scripts record whatever is there first (Proxyman's
   `127.0.0.1:9090` today) and restore it in the same script, with a `trap` that
   restores on any exit.
6. **No `sudo`, no `osascript`, no "with administrator privileges"** anywhere in the
   code or UI text (SP-AC28 enforces it).
7. **Stop on gaps.** A Coder that finds the spec or this plan wrong, or needs a file
   its task does not list, stops and reports. It never redesigns.
8. **`unsafe_code = "forbid"`** holds; `grep -rn unsafe crates/aitm-sysproxy/src` is
   empty.
9. Shared Cargo `target/` across worktrees reuses stale artifacts: `touch` the files
   you changed before the gate if a result looks impossible.
10. **Never touch Matt's keychains.** No task runs `ca.install`, `security add-trusted-cert`
    or anything that writes a keychain or trust setting on Matt's Mac except Task 41,
    and Task 41 only after Matt's explicit go, only through the app's own step and the
    macOS dialog, and only into the login keychain (the System keychain is quoted
    before and after and must stay empty). Task 32 is read-only by construction.

### Plan-level calls (Architect; how the spec is read where it left wording open)

- **C1 Rendered-line expectations are built with `CmdLine::render()`** from the exact
  argv. For macOS they equal the spec's literal strings byte for byte (only the
  service name carries whitespace). For `gsettings … ignore-hosts "['localhost', …]"`
  and `dbus-send … string:''` the spec's shell spelling is shorthand for ONE argv
  word (`['localhost', '127.0.0.0/8', …]` and `string:` respectively); tests assert
  the argv and compare `runs()` to `CmdLine { .. }.render()` of that argv.
- **C2** `SystemProxy::detect`/`detect_with` run **no command**; the first shell-out
  is the first `status()`/`set()`. A public `SystemProxy::with_mechanism(..)`
  constructor exists so Linux ops are unit-tested on a macOS host.
- **C3** Service equality against `wrote` ("still equals what we wrote") compares
  both protocol endpoints (`enabled`, `host`, `port`) and not the bypass list; one
  free function `service_equals_wrote(&ServiceRow, &Wrote) -> bool` is the only
  implementation and `watchdog::decide` uses it.
- **C4** `State::Off` detail is `"HTTP and HTTPS off"`.
- **C5** `recover_at_startup` runs only in serving modes (`Server`, `Tui`, `Web`),
  never for a one-shot `Mode::Cli` process.
- **C6** `parse_settings` fills `system_proxy.state_file` with
  `core.ca.audit_log.with_file_name("system-proxy-state.json")` when the file
  leaves it unset, so `Settings.system_proxy.state_file` is always `Some`.
- **C7** A write failure after at least one service was written rolls back the
  written services from `previous`, then removes the state file; if the rollback
  itself fails the file is kept and `set` returns `Err` naming the file.
  `NeedsPrivilege` on the first mutating line removes the (already written) file and
  returns `Ok` with the state.
- **C8** Watchdog log line: `<rfc3339> <decision> services=<n> ms=<n>` where
  decision ∈ `file-gone`, `restored`, `left-alone`, `restore-failed`.
- **C9** Web pure logic lives in a new `apps/web/src/state/systemProxy.ts` (parse,
  pill word, menu state) with `systemProxy.test.ts`; `app.ts` only wires it.
- **C10** TUI: `Action::ToggleSysProxy`, `App.sysproxy_setting: bool` (the in-flight
  flag), key `s` in the flows table (free today).
- **C11** Mac: the facts type lives in a new `AitmproxyKit/SystemProxyFacts.swift`;
  the sheet is `Shell/SystemProxySheet.swift`; the menu shortcut is ⌥⌘P (free in
  `CommandMap.all`).
- **C12** If `crates/aitm-tui/fixtures/bus-fixture.json` still exists when Task 11
  runs, its three new entries move `tester_shell.rs`'s two `62` pins to `65`; if it
  is gone, those pins are gone with it and nothing is done.
- **C13** The macOS core-only live proof (Task 14) exercises `set` through
  `system_proxy.auto: true` (startup set, SIGTERM restore, `kill -9` watchdog) and
  through the real verb with the python `tests/e2e/aitm_e2e/bus.py` `BusClient`
  (operator token read from the `0600` config, never printed).
- **C14** `aitm-plugins` gains a dependency on `aitm-sysproxy` (no cycle:
  `aitm-sysproxy` depends only on `aitm-core`, `aitm-ca`).

---

## PR 1 — core (`claude/system-proxy-automation-a08c0c`)

### Task 1: crate skeleton — types, config, trait, Windows seam

- **Satisfies:** SP-AC4 (`classify`), SP-AC19 (the `SystemProxyConfig` half), the
  compile-everywhere constraint, D11.
- **Depends on:** none.
- **Files:** `Cargo.toml` (workspace: add `"crates/aitm-sysproxy"` to `members` and
  `aitm-sysproxy = { path = "crates/aitm-sysproxy" }` to `[workspace.dependencies]`),
  `Cargo.lock` (the one new member; no new external crate), 
  `crates/aitm-sysproxy/Cargo.toml` (create), `crates/aitm-sysproxy/src/lib.rs`
  (create), `src/config.rs` (create), `src/state.rs` (create, stub `//!` only),
  `src/watchdog.rs` (create, stub), `src/plugin.rs` (create, stub),
  `src/platform/mod.rs` (create), `src/platform/macos.rs` (create, stub),
  `src/platform/linux.rs` (create, stub), `src/platform/windows.rs` (create).
- **Change:**
  - `Cargo.toml` of the crate: `aitm-core.workspace`, `aitm-ca.workspace`, `anyhow`,
    `serde` (derive), `serde_json`, `time` (formatting, parsing), `tracing`;
    `[lints] workspace = true`; no dev-dependencies beyond what the workspace has.
  - `lib.rs` declares every module (`pub mod config; pub mod platform; pub mod state;
    pub mod watchdog; pub mod plugin;`) so later tasks never edit the module list,
    re-exports `config::SystemProxyConfig`, and defines, exactly as the spec §D2 types:
    ```rust
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Mechanism { Networksetup, Gsettings, Kde, None }
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum State { Off, PointsAtUs, Other { host: String, port: u16 }, Unsupported, NeedsPrivilege, Unknown }
    pub struct Endpoint { pub host: String, pub port: u16 }
    pub struct ProtocolProxy { pub enabled: bool, pub host: String, pub port: u16 }   // Serialize/Deserialize/PartialEq/Default
    pub struct ServiceRow { pub service: String, pub http: ProtocolProxy, pub https: ProtocolProxy, pub bypass: Vec<String> }
    pub struct Effective { pub http: ProtocolProxy, pub https: ProtocolProxy, pub bypass: Vec<String> }
    pub struct Wrote { pub host: String, pub port: u16, pub bypass: Vec<String> }
    pub struct SetRequest { pub bypass: Vec<String> }
    pub struct Summary { pub state: State, pub host: Option<String>, pub port: Option<u16>, pub managed_by_us: bool, pub setting: bool, pub supported: bool, pub detail: String }
    pub struct Status { pub state: State, pub detail: String, pub ours: Endpoint, pub mechanism: Mechanism, pub supported: bool, pub managed_by_us: bool, pub setting: bool, pub effective: Option<Effective>, pub services: Vec<ServiceRow>, pub bypass_default: Vec<String>, pub guidance: Option<String>, pub remedy: Option<String>, pub last_change_ms: Option<i64>, pub watchdog_pid: Option<u32>, pub state_file: std::path::PathBuf }
    pub struct UnsetOutcome { pub restored: Vec<String>, pub left_alone: Vec<String>, pub status: Status }
    pub enum ReadError { Unavailable(String), ToolMissing(String), Failed(String) }
    pub enum WriteError { NeedsPrivilege(String), ToolMissing(String), Failed(String), Hung(String) }
    // Shipped shape (F3, 2026-10-31): `NeedsPrivilege { line: String }` — the failing rendered line; the engine supplies the §D3 remedy.
    pub const BYPASS_DEFAULT: [&str; 5] = ["localhost", "127.0.0.1", "::1", "*.local", "169.254/16"];
    pub const STATE_FILE_NAME: &str = "system-proxy-state.json";
    pub const WATCHDOG_LOG_NAME: &str = "system-proxy-watchdog.log";
    pub fn classify(effective: &Effective, ours: &Endpoint) -> (State, String);
    pub fn service_equals_wrote(row: &ServiceRow, wrote: &Wrote) -> bool;          // C3
    pub fn merge_bypass(previous: &[String], extra: &[String]) -> Vec<String>;      // ordered, de-duplicated union (§D5)
    pub fn guidance_line(ours: &Endpoint) -> String;                                 // §D4 literal
    pub fn ours_from(listen: std::net::SocketAddr) -> Endpoint;                      // 127.0.0.1 for loopback/unspecified, else the IP literal (§D3)
    pub const NEEDS_PRIVILEGE_REMEDY: &str = "…";  // the §D3 sentence, verbatim, with `127.0.0.1:8080` replaced by `{ours}` through a `remedy(ours)` fn
    impl Status { pub fn to_value(&self) -> aitm_core::Value; pub fn summary(&self) -> Summary; }
    impl Summary { pub fn to_value(&self) -> aitm_core::Value; }
    impl State { pub fn as_str(&self) -> &'static str; }   // "off" | "points_at_us" | "other" | "unsupported" | "needs_privilege" | "unknown"
    ```
    `points_at_us` hosts: `{"127.0.0.1", "localhost", "::1", "[::1]", ours.host}`.
    `Status.to_value` emits exactly the §D6 field names; `host`/`port` only for `Other`.
    The `SystemProxy` struct itself is Task 6.
  - `config.rs`:
    ```rust
    #[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
    #[serde(default, deny_unknown_fields)]
    pub struct SystemProxyConfig { pub auto: bool, pub bypass: Vec<String>, pub state_file: Option<std::path::PathBuf> }
    impl SystemProxyConfig { pub fn default_state_file(ca_audit_log: &std::path::Path) -> std::path::PathBuf; }  // audit_log.with_file_name(STATE_FILE_NAME)
    ```
  - `platform/mod.rs`:
    ```rust
    pub(crate) trait PlatformOps: Send + Sync {
        fn mechanism(&self) -> Mechanism;
        fn detail_when_unsupported(&self) -> Option<String>;   // Windows: Some("Windows system proxy is not managed yet")
        fn read_effective(&self, exec: &dyn Executor) -> Result<Effective, ReadError>;
        fn read_services(&self, exec: &dyn Executor) -> Result<Vec<ServiceRow>, ReadError>;
        fn write(&self, exec: &dyn Executor, previous: &Previous, ours: &Endpoint, bypass_extra: &[String]) -> Result<Vec<String>, WriteError>;
        fn restore(&self, exec: &dyn Executor, previous: &Previous, only: &[String]) -> Result<Vec<String>, WriteError>;
        fn equals_wrote(&self, live: &[ServiceRow], wrote: &Wrote) -> Vec<(String, bool)>;   // default impl over service_equals_wrote
    }
    pub(crate) fn ops_for(mechanism: Mechanism) -> Box<dyn PlatformOps>;
    // Shipped shape (recorded by the panel, 2026-10-31): `detail_when_unsupported` and `equals_wrote`
    // were dropped; `fn snapshot(&self, exec) -> Result<Snapshot { previous, skipped, rows }, ReadError>` was
    // added (Task 6 + gap resolutions); `ops_for(Kde)` resolves the tool major at runtime (F1).   // Networksetup → macos::MacosOps, Gsettings → linux::GsettingsOps, Kde → linux::KdeOps, None → windows::NoneOps
    pub(crate) fn cmd(program: &str, args: &[&str], mutating: bool) -> aitm_ca::exec::CmdLine;
    ```
    `Previous` is declared in `state.rs` (Task 4); Task 1 declares it there as the
    bare enum so the trait compiles:
    `#[serde(tag = "kind", rename_all = "snake_case")] pub enum Previous { Networksetup { services: Vec<ServiceRow> }, Gsettings { keys: BTreeMap<String, String> }, Kde { kioslaverc: BTreeMap<String, String>, gsettings: Option<BTreeMap<String, String>> } }`.
  - `platform/windows.rs`: `pub(crate) struct NoneOps;` implementing the trait with
    `mechanism() == Mechanism::None`, reads returning `Err(ReadError::Unavailable(..))`,
    writes `Err(WriteError::Failed("unsupported"))`.
- **Test** (`lib.rs` `#[cfg(test)]`, SP-AC4): `classify_points_at_us_other_partial_off`
  with `ours = 127.0.0.1:8080`:
  both enabled at `127.0.0.1:8080` → `State::PointsAtUs`; both at `localhost:8080` →
  `PointsAtUs`; both at `127.0.0.1:9090` → `State::Other { host: "127.0.0.1".into(), port: 9090 }`
  with detail `"HTTP and HTTPS → 127.0.0.1:9090 (not this core)"`; HTTP at us + HTTPS
  `enabled: false` → `Other { host: "127.0.0.1", port: 8080 }` with detail exactly
  `"HTTP → 127.0.0.1:8080, HTTPS off"`; both disabled → `State::Off` with detail
  `"HTTP and HTTPS off"`. Plus `merge_bypass(&["*.local","169.254/16"], &["localhost","127.0.0.1","::1","*.local","169.254/16","corp.test"]) == ["*.local","169.254/16","localhost","127.0.0.1","::1","corp.test"]`,
  `guidance_line(&ours) == "export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080 no_proxy=localhost,127.0.0.1,::1"`,
  `ours_from("0.0.0.0:8080".parse().unwrap()).host == "127.0.0.1"`,
  `ours_from("[::]:8080".parse().unwrap()).host == "127.0.0.1"`,
  `ours_from("10.0.0.5:8080".parse().unwrap()).host == "10.0.0.5"`,
  `serde_json::from_str::<SystemProxyConfig>(r#"{"nope":true}"#).is_err()` (the YAML
  form of this check is Task 5's, in `config_file.rs`),
  and `Status::to_value` for an `Other` status contains `host` and `port`, for an
  `Off` status contains neither.
- **Done when:** the crate compiles on macOS (and `cargo check --target
  x86_64-unknown-linux-gnu` is NOT required; cfg-free code), tests green, gate green.

### Task 2: macOS mechanism (`platform/macos.rs`)

- **Satisfies:** SP-AC1, SP-AC2, SP-AC3 (parsers; the `status()` half is Task 6),
  SP-AC6 (restore rendering), the rendering half of SP-AC5 and SP-AC9.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-sysproxy/src/platform/macos.rs` (fill).
- **Change:**
  ```rust
  pub const NETWORKSETUP: &str = "/usr/sbin/networksetup";
  pub const SCUTIL: &str = "/usr/sbin/scutil";
  pub const ADMIN_ERROR: &str = "** Error: Command requires admin privileges.";
  pub fn parse_services(stdout: &str) -> Vec<String>;              // drop the header line and every `*`-prefixed line
  pub fn parse_get_proxy(stdout: &str) -> ProtocolProxy;           // Enabled: Yes|No, Server:, Port:
  pub fn parse_get_proxy_authenticated(stdout: &str) -> bool;      // `Authenticated Proxy Enabled: 1`
  pub fn parse_bypass(stdout: &str) -> Vec<String>;                // one per line; "There aren't any bypass domains set on <svc>." → []
  pub fn parse_scutil(stdout: &str) -> Result<Effective, ReadError>;  // `<dictionary> {\n}\n` or `AuthorizationCreate() failed` → Err(Unavailable)
  pub(crate) struct MacosOps;
  pub(crate) fn render_restore(previous: &[ServiceRow], only: &[String]) -> Vec<CmdLine>;  // pure; §D3 restore rules incl. `Empty`
  pub(crate) fn render_write(service: &str, ours: &Endpoint, bypass: &[String]) -> [CmdLine; 3];
  ```
  `MacosOps::read_services`: `-listallnetworkservices`, then per enabled service
  `-getwebproxy`, `-getsecurewebproxy`, `-getproxybypassdomains` (all `mutating: false`).
  Zero enabled services → `Err(ReadError::Unavailable("no enabled network service"))`.
  A service with `Authenticated Proxy Enabled: 1` is carried in the row list with a
  marker (`ServiceRow.service` unchanged; `MacosOps::write` skips it and returns the
  rendered lines plus the skip is reported by Task 6 as `detail` "skipped <svc>:
  authenticated proxy"). Hold the authenticated flag in a `pub(crate) struct
  MacosServices { rows: Vec<ServiceRow>, authenticated: Vec<String> }` returned by a
  `read_services_full` the trait method wraps. `write` renders, per service in order,
  `-setwebproxy <svc> <host> <port>`, `-setsecurewebproxy <svc> <host> <port>`,
  `-setproxybypassdomains <svc> <merged list…>` (`mutating: true`); any run with
  `code != Some(0)` or stdout/stderr containing `ADMIN_ERROR` → `Err(WriteError::NeedsPrivilege(remedy))`
  when the text matches, else `Err(WriteError::Failed(rendered))`; an `Err` from the
  executor whose message contains `timed out` → `WriteError::Hung(rendered)`.
  `restore`: for each service in `only`: non-empty previous host → `-setwebproxy <svc>
  <host> <port>` then `-setwebproxystate <svc> on|off`; empty host → only
  `-setwebproxystate <svc> off`; same pair for `-setsecurewebproxy`/`-setsecurewebproxystate`;
  then `-setproxybypassdomains <svc> <list…>` or `… <svc> Empty` when empty.
- **Test** (`macos.rs` `#[cfg(test)]`):
  - `parse_services_drops_header_and_disabled` (SP-AC1): input
    `"An asterisk (*) denotes that a network service is disabled.\nDisplay Ethernet\n*Thunderbolt Bridge\nWi-Fi\n"`
    → `vec!["Display Ethernet", "Wi-Fi"]`.
  - `parse_get_proxy_enabled_and_disabled` (SP-AC2): `"Enabled: Yes\nServer: 127.0.0.1\nPort: 9090\nAuthenticated Proxy Enabled: 0\n"`
    → `ProtocolProxy { enabled: true, host: "127.0.0.1".into(), port: 9090 }`;
    `"Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n"` → `{ enabled: false, host: "", port: 0 }`.
  - `parse_scutil_full_disabled_and_sandbox` (SP-AC3): the research 16 §3.2.1 dump
    (`<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n  }\n  FTPPassive : 1\n  HTTPEnable : 1\n  HTTPPort : 9090\n  HTTPProxy : 127.0.0.1\n  HTTPSEnable : 1\n  HTTPSPort : 9090\n  HTTPSProxy : 127.0.0.1\n}\n`)
    → both enabled at `127.0.0.1:9090`, `bypass == ["*.local", "169.254/16"]`;
    `"<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n}\n"` → both disabled, hosts `""`;
    `"<dictionary> {\n}\n"` → `Err(ReadError::Unavailable(_))`.
  - `restore_renders_the_spec_lines` (SP-AC6): from the two-service `previous` of the
    §D7 document, `render_restore(.., &["Display Ethernet", "Wi-Fi"])` renders, in order,
    `/usr/sbin/networksetup -setwebproxy 'Display Ethernet' 127.0.0.1 9090`,
    `/usr/sbin/networksetup -setwebproxystate 'Display Ethernet' on`,
    `/usr/sbin/networksetup -setsecurewebproxy 'Display Ethernet' 127.0.0.1 9090`,
    `/usr/sbin/networksetup -setsecurewebproxystate 'Display Ethernet' on`,
    `/usr/sbin/networksetup -setproxybypassdomains 'Display Ethernet' *.local 169.254/16`,
    `/usr/sbin/networksetup -setwebproxystate Wi-Fi off`,
    `/usr/sbin/networksetup -setsecurewebproxystate Wi-Fi off`,
    `/usr/sbin/networksetup -setproxybypassdomains Wi-Fi *.local 169.254/16`;
    with `Wi-Fi`'s previous bypass empty the last line is
    `/usr/sbin/networksetup -setproxybypassdomains Wi-Fi Empty`.
  - `write_renders_three_lines_per_service` (SP-AC5 half): `render_write("Display Ethernet", &ours, &merged)`
    renders `/usr/sbin/networksetup -setwebproxy 'Display Ethernet' 127.0.0.1 8080`,
    `/usr/sbin/networksetup -setsecurewebproxy 'Display Ethernet' 127.0.0.1 8080`,
    `/usr/sbin/networksetup -setproxybypassdomains 'Display Ethernet' *.local 169.254/16 localhost 127.0.0.1 ::1 corp.test`.
  - `admin_error_maps_to_needs_privilege` (SP-AC9 half): a `ScriptedExecutor` answering
    `… -setwebproxy 'Display Ethernet' 127.0.0.1 8080` with code 1 and stdout
    `** Error: Command requires admin privileges.` makes `MacosOps::write` return
    `Err(WriteError::NeedsPrivilege(r))` with `r` containing `"Require an administrator password"`,
    and `exec.runs()` contains exactly one line containing ` -set`.
- **Done when:** all six tests green; gate green.

### Task 3: Linux mechanisms (`platform/linux.rs`)

- **Satisfies:** SP-AC10, rendering halves of SP-AC11 and SP-AC12.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-sysproxy/src/platform/linux.rs` (fill).
- **Change:**
  ```rust
  pub const GSETTINGS: &str = "/usr/bin/gsettings";
  pub const GSETTINGS_KEYS: [(&str, &str); 6] = [("org.gnome.system.proxy", "mode"), ("org.gnome.system.proxy.http", "host"), ("org.gnome.system.proxy.http", "port"), ("org.gnome.system.proxy.https", "host"), ("org.gnome.system.proxy.https", "port"), ("org.gnome.system.proxy", "ignore-hosts")];
  pub const KDE_KEYS: [&str; 4] = ["ProxyType", "httpProxy", "httpsProxy", "NoProxyFor"];
  pub fn detect_mechanism(target_os: &str, env: &dyn Fn(&str) -> Option<String>, has_tool: &dyn Fn(&str) -> bool) -> Mechanism;
  pub fn gvariant_string(s: &str) -> String;                 // '127.0.0.1'
  pub fn gvariant_string_list(items: &[String]) -> String;   // ['a', 'b']
  pub fn parse_gvariant_string(s: &str) -> String;
  pub fn parse_gvariant_string_list(s: &str) -> Vec<String>;
  pub(crate) struct GsettingsOps;
  pub(crate) struct KdeOps { pub kwrite: &'static str, pub kread: &'static str, pub gsettings_too: bool }   // "kwriteconfig6"/"kreadconfig6" or the 5 variants
  ```
  `detect_mechanism` is the §D4 table: KDE when `XDG_CURRENT_DESKTOP` contains `KDE`
  and `kwriteconfig6` or `kwriteconfig5` is present; `Gsettings` when `gsettings` is
  present and (`DBUS_SESSION_BUS_ADDRESS` or `DISPLAY` or `WAYLAND_DISPLAY` is set);
  else `None`; any `target_os != "linux"` → `None` (macOS is decided by the caller,
  Task 6). `GsettingsOps::read_effective` = six `gsettings get` (non-mutating); the
  synthetic `ServiceRow { service: "gsettings", .. }` has `enabled = (mode == 'manual')`.
  `write`: the six `set`s in the §D4 order with `mode 'manual'` LAST, then the six
  `get`s again; any read-back differing from what was written →
  `Err(WriteError::Failed("gsettings did not persist the change (no dconf session?)"))`.
  `restore`: the six `set`s with the raw previous GVariant text, verbatim.
  `KdeOps::write`: `kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key ProxyType 1`,
  `… httpProxy 'http://127.0.0.1 8080'`, `… httpsProxy 'http://127.0.0.1 8080'`,
  `… NoProxyFor <comma list>`, then `dbus-send --type=signal /KIO/Scheduler org.kde.KIO.Scheduler.reparseSlaveConfiguration string:`
  (argv word `string:`, see C1); when `gsettings_too`, the gsettings writes come
  first and are snapshotted into `Previous::Kde.gsettings`. Unset writes the four
  previous values back (an absent key → `ProxyType 0`) and signals again. Tool
  programs resolved by name on `PATH` (`kwriteconfig6`, `kreadconfig6`, `dbus-send`);
  an executor `Err` whose message starts with `could not start` →
  `WriteError::ToolMissing(program)` / `ReadError::ToolMissing(program)`.
- **Test** (`linux.rs` `#[cfg(test)]`):
  - `detect_table` (SP-AC10): (`"linux"`, env `XDG_CURRENT_DESKTOP=KDE`, has_tool
    `kwriteconfig6`) → `Mechanism::Kde`; (`"linux"`, `gsettings` present,
    `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/501/bus`, no `DISPLAY`) → `Gsettings`;
    (`"linux"`, `gsettings` present, no bus, no display) → `None`; (`"windows"`, anything)
    → `None`. The guidance string for the third case is asserted in Task 6.
  - `gsettings_set_renders_in_order_and_reads_back` (SP-AC11): with a `ScriptedExecutor`
    whose six `get` lines answer `'none'`, `''`, `8080`, `''`, `0`,
    `['localhost', '127.0.0.0/8', '::1']` then (queued second answers) `'manual'`,
    `'127.0.0.1'`, `8080`, `'127.0.0.1'`, `8080`, and the written list,
    `GsettingsOps::write(&exec, &previous, &ours, &BYPASS_DEFAULT)` records, in order:
    the six `get`s, then argv `["set","org.gnome.system.proxy.http","host","'127.0.0.1'"]`,
    `[…".http","port","8080"]`, `[…".https","host","'127.0.0.1'"]`, `[…".https","port","8080"]`,
    `["set","org.gnome.system.proxy","ignore-hosts","['localhost', '127.0.0.0/8', '::1', '127.0.0.1', '*.local', '169.254/16']"]`,
    `["set","org.gnome.system.proxy","mode","'manual'"]` (last), then the six `get`s.
    Expected lines are `CmdLine::render()` of those argv with program `/usr/bin/gsettings`.
    A second executor whose read-back keeps `'none'` for `mode` makes `write` return
    `Err(WriteError::Failed(m))` with `m` containing `did not persist`.
  - `kde_set_and_unset_render` (SP-AC12): the four `kwriteconfig6` lines
    (`ProxyType 1`, `httpProxy 'http://127.0.0.1 8080'`, `httpsProxy 'http://127.0.0.1 8080'`,
    `NoProxyFor localhost,127.0.0.1,::1,*.local,169.254/16`) then the `dbus-send` line;
    `restore` from `Previous::Kde { kioslaverc: {ProxyType:"0", httpProxy:"", httpsProxy:"", NoProxyFor:""}, gsettings: None }`
    writes the four previous values back and ends with the same `dbus-send` line.
  - `gvariant_round_trips`: `parse_gvariant_string_list("['a', 'b c']") == ["a", "b c"]`,
    `gvariant_string_list(&["a".into(), "b c".into()]) == "['a', 'b c']"`,
    `parse_gvariant_string("'manual'") == "manual"`.
- **Done when:** four tests green; gate green.

### Task 4: the state file (`state.rs`)

- **Satisfies:** the round-trip half of SP-AC5, §D7.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-sysproxy/src/state.rs` (fill).
- **Change:**
  ```rust
  #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
  pub struct StateFile { pub version: u32, pub platform: String, pub mechanism: Mechanism, pub saved_at: String, pub pid: u32, pub wrote: Wrote, pub previous: Previous }
  impl StateFile {
      pub const VERSION: u32 = 1;
      pub fn new(mechanism: Mechanism, pid: u32, wrote: Wrote, previous: Previous) -> StateFile;   // platform = std::env::consts::OS mapped to "macos"/"linux"/"windows"; saved_at = time::OffsetDateTime::now_utc() RFC 3339
      pub fn load(path: &Path) -> anyhow::Result<Option<StateFile>>;   // absent → Ok(None); unreadable or version != 1 → rename to `<file>.corrupt-<unix secs>`, warn!, Ok(None)
      pub fn save_atomic(&self, path: &Path) -> anyhow::Result<()>;     // create parent dir, write `<path>.tmp-<pid>` with mode 0600 (std::os::unix::fs::OpenOptionsExt::mode; non-unix: plain), fsync, rename
      pub fn remove(path: &Path) -> anyhow::Result<bool>;               // Ok(false) when absent
      pub fn service_names(&self) -> Vec<String>;                       // Networksetup: each row; Gsettings: ["gsettings"]; Kde: ["kde"] (+ "gsettings" when present)
  }
  ```
- **Test** (`state.rs` `#[cfg(test)]`, temp dir = `std::env::temp_dir().join(format!("aitm-sysproxy-{tag}-{nanos}"))`, removed at the end):
  - `round_trips_the_spec_document`: parse the §D7 JSON document verbatim with
    `serde_json::from_str::<StateFile>`; `wrote.port == 8080`;
    `previous` is `Previous::Networksetup { services }` with `services[1].http.host == ""`;
    `save_atomic` then `load` returns `Some(equal)`; on unix the file mode `& 0o777 == 0o600`.
  - `corrupt_file_is_renamed_and_treated_absent`: write `{"version": 2}` → `load` is
    `Ok(None)` and a sibling named `system-proxy-state.json.corrupt-*` exists; write
    `not json` → same.
  - `remove_reports_presence`: `remove` on a saved file → `Ok(true)`; again → `Ok(false)`.
- **Done when:** three tests green; gate green.

### Task 5: `config_file.rs` — the `system_proxy` section

- **Satisfies:** SP-AC19.
- **Depends on:** Task 1 (the type). Independent of Tasks 2–4.
- **Files:** `crates/aitm/Cargo.toml` (add `aitm-sysproxy.workspace = true`),
  `crates/aitm/src/config_file.rs` (modify), `crates/aitm/tests/config_file.rs` (add tests).
- **Change:** `Settings` gains `pub system_proxy: aitm_sysproxy::SystemProxyConfig`;
  `ConfigFile` gains `system_proxy: Option<SystemProxyConfig>` (documented like
  `macos_capture`); `parse_settings` and the absent-file branch of `load_settings`
  fill it, then apply C6: `if system_proxy.state_file.is_none() { system_proxy.state_file = Some(SystemProxyConfig::default_state_file(&core.ca.audit_log)) }`.
  Every destructuring of `Settings` in the crate (`main.rs` line ~155) must add the
  field; this task adds `system_proxy: _` there only (Task 10 uses it).
- **Test** (`crates/aitm/tests/config_file.rs`):
  - `system_proxy_section_parses_with_default_state_file`:
    `parse_settings("system_proxy:\n  auto: true\n  bypass: [corp.test]\n")` →
    `system_proxy.auto == true`, `system_proxy.bypass == vec!["corp.test"]`,
    `system_proxy.state_file == Some(settings.core.ca.audit_log.with_file_name("system-proxy-state.json"))`.
  - `system_proxy_unknown_key_is_an_error`: `parse_settings("system_proxy:\n  nope: true\n").is_err()`.
  - `system_proxy_absent_is_off`: `parse_settings("listen: \"127.0.0.1:8080\"\n")` →
    `auto == false`, `bypass.is_empty()`, `state_file.is_some()`.
  - `system_proxy_block_the_mac_app_emits_parses` (the SP-AC25 twin, exact literal the
    mac task reuses): `parse_settings("system_proxy:\n  auto: true\n  bypass:\n    - \"corp.test\"\n")`
    → `auto == true`, `bypass == ["corp.test"]`.
- **Done when:** four tests green; gate green.

### Task 6: the `SystemProxy` engine (`lib.rs`)

- **Satisfies:** SP-AC3 (`status().state == Unknown` half), SP-AC5, SP-AC7, SP-AC8,
  SP-AC9 (behavioural half), SP-AC10 (guidance half), SP-AC11/12 (the no-file-left and
  detail halves), SP-AC14, SP-AC18 (the cache half).
- **Depends on:** Tasks 2, 3, 4, 7.
- **Files:** `crates/aitm-sysproxy/src/lib.rs` (modify).
- **Change:**
  ```rust
  pub struct SystemProxy { exec: Arc<dyn Executor>, ops: Box<dyn PlatformOps>, state_file: PathBuf, ours: Endpoint, config_bypass: Vec<String>, watchdog_exe: Option<PathBuf>, in_flight: AtomicBool, watchdog: Mutex<Option<watchdog::WatchdogHandle>>, cache: Mutex<Option<(Instant, Summary)>>, sticky_remedy: Mutex<Option<String>>, last_change_ms: Mutex<Option<i64>> }
  pub enum Recovery { Nothing, Set(Status), Adopted { pid: u32 }, Restored { restored: Vec<String>, left_alone: Vec<String> }, Forgot, Failed(String) }
  impl SystemProxy {
      pub fn detect(exec: Arc<dyn Executor>, cfg: &SystemProxyConfig, ours: Endpoint, watchdog_exe: Option<PathBuf>) -> SystemProxy;   // detect_with(std::env::consts::OS, std::env::var)
      pub fn detect_with(exec, cfg, ours, watchdog_exe, target_os: &str, env: &dyn Fn(&str) -> Option<String>) -> SystemProxy;   // "macos" → Networksetup; "linux" → linux::detect_mechanism(.., has_tool over env("PATH") with Path::is_file); else None
      pub fn with_mechanism(exec, cfg, ours, watchdog_exe, mechanism: Mechanism) -> SystemProxy;   // C2
      pub fn state_file(&self) -> &Path;
      pub fn status(&self) -> Status;
      pub fn summary(&self) -> Summary;            // cached ≤ 5 s; refreshed by set/unset/recover
      pub fn set(&self, req: &SetRequest) -> anyhow::Result<(Status, bool /*changed*/, Vec<String> /*commands*/)>;
      pub fn unset(&self) -> anyhow::Result<(UnsetOutcome, bool, Vec<String>)>;
      pub fn recover_at_startup(&self, auto: bool) -> Recovery;
      pub fn on_orderly_exit(&self) -> Recovery;
      pub fn is_setting(&self) -> bool;
  }
  ```
  `status()`: `mechanism == None` → `Unsupported` + `guidance`, no shell-out;
  `read_effective` Err → `Unknown` with the error text as `detail`, `services` empty;
  else `classify`, then `read_services` (macOS only; Linux `services` stays empty),
  `managed_by_us` = file present and every `service_names()` entry equal per
  `equals_wrote`; sticky `NeedsPrivilege` overrides `state` until a later write succeeds;
  `watchdog_pid` from the handle when `managed_by_us`.
  `set()`: `in_flight` CAS or `bail!("a system-proxy change is already in flight")`;
  status; if `PointsAtUs` and file exists → `changed: false`, no writes; else snapshot
  (`read_services` → `Previous`), `StateFile::save_atomic` BEFORE the first mutating
  line, `ops.write`, verify (`status()`), spawn the watchdog if `watchdog_exe` is Some
  and none alive (Task 7's `watchdog::spawn`), refresh the cache, `info!(target: "aitm_sysproxy", …)`
  one line, `debug!` per rendered command. `WriteError::NeedsPrivilege(r)` → remove the
  file, set `sticky_remedy`, return `Ok` with `state == NeedsPrivilege`, `remedy == Some(r)`.
  Other `WriteError` → C7 rollback. Authenticated services are skipped and named in `detail`.
  `unset()`: no file → `changed: false`, `detail` "not managed by this core; nothing to
  restore"; else `equals_wrote` per service, `ops.restore(only = equal ones)`,
  `left_alone` = the rest, remove the file, drop the watchdog handle (the process exits
  on its own when it sees the file gone), refresh the cache.
  `recover_at_startup(auto)` is the §D9 (c) table, returning the row's `Recovery`; it
  adopts by rewriting `pid` and spawning a watchdog. `on_orderly_exit` = `unset()` when
  `managed_by_us`, else `Nothing`. Both log one `info!` line.
- **Test** (`lib.rs` `#[cfg(test)]`; a helper `fn scripted_macos(tag) -> (Arc<ScriptedExecutor>, SystemProxy, PathBuf)` with `ScriptedExecutor::new().with_real_fs()`, `with_mechanism(.., Mechanism::Networksetup)`, `state_file` under a fresh temp dir; scripted answers for `-listallnetworkservices` (the SP-AC1 input), the three `-get*` per service, and `scutil --proxy`; queued second answers for the post-write verify reads):
  - `set_runs_reads_then_writes_and_saves_the_file_first` (SP-AC5): request bypass
    `["corp.test"]`; `exec.runs()` equals, in order: `-listallnetworkservices`, the three
    `-get*` for `'Display Ethernet'`, the three for `Wi-Fi`, the three `-set*` for
    `'Display Ethernet'` (lines of Task 2's test), the three for `Wi-Fi`, then
    `/usr/sbin/scutil --proxy` and the six `-get*` verify reads. "The file is written
    before the first `-set*`" is asserted with a small test-module `Executor` decorator
    around the `ScriptedExecutor` (`struct FileWatch { inner: ScriptedExecutor, state_file: PathBuf, seen: Mutex<Vec<(String, bool)>> }`)
    that records `(cmd.render(), state_file.exists())` on every `run`: the entry for the
    first line containing ` -set` is `true` and the entry for the last read before it is
    `false`. Round-trip: `StateFile::load` gives `wrote.port == 8080`,
    `previous.services[1].http.host == ""`.
  - `set_is_idempotent_when_pointing_at_us_with_a_file` (SP-AC7): scripted reads at
    `127.0.0.1:8080` enabled + a saved file → `changed == false`, zero lines containing ` -set`.
  - `set_adopts_a_hand_set_proxy_without_a_file`: same reads, no file → `changed == true`
    and a file exists afterwards.
  - `unset_restores_only_the_services_still_ours` (SP-AC8): file lists both; live `Wi-Fi`
    reads `127.0.0.1:8080`, live `'Display Ethernet'` reads `10.0.0.5:3128` →
    `restored == ["Wi-Fi"]`, `left_alone == ["Display Ethernet"]`, no run line contains
    both ` -set` and `Display Ethernet`, the state file is gone.
  - `needs_privilege_is_ok_sticky_and_leaves_no_file` (SP-AC9): first `-setwebproxy`
    answers exit 1 + `** Error: Command requires admin privileges.` → `Ok`,
    `state == NeedsPrivilege`, `remedy == Some(NEEDS_PRIVILEGE_REMEDY for ours)`, exactly
    one ` -set` line, no state file; a following `status()` still reports `NeedsPrivilege`.
  - `scutil_empty_dictionary_is_unknown_not_off` (SP-AC3 half): `scutil --proxy` answers
    `"<dictionary> {\n}\n"` → `status().state == State::Unknown`.
  - `unsupported_carries_guidance_and_runs_nothing` (SP-AC10 half): `with_mechanism(.., Mechanism::None)`
    → `status().state == Unsupported`, `guidance == Some("export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080 no_proxy=localhost,127.0.0.1,::1")`,
    `exec.runs().is_empty()`.
  - `gsettings_non_persisting_backend_is_unknown_and_leaves_no_file` (SP-AC11 tail):
    `with_mechanism(.., Gsettings)` with read-back `mode` staying `'none'` →
    `state == Unknown`, `detail` contains `did not persist`, no file, `guidance.is_some()`.
  - `summary_is_cached_five_seconds_and_refreshed_by_set` (SP-AC18 half): two `summary()`
    calls → one `/usr/sbin/scutil --proxy` run; `set` then `summary()` → `state ==
    PointsAtUs` and the `scutil` count did not grow after `set` returned.
  - `recover_follows_the_table` (SP-AC14), five cases: (absent, auto off) → `Nothing`,
    no mutating line; (absent, auto on) → `Set(_)` with `-set*` lines and a file;
    (present, equal, same endpoint, auto on) → `Adopted { .. }`, no `-set*`, file kept
    with the new `pid`; (present, equal, auto off) → `Restored { restored: both, .. }`,
    restore lines, file gone; (present, not equal) → `Forgot`, no `-set*`, file gone.
  - `on_orderly_exit_restores_when_managed`: after a successful `set`, `on_orderly_exit()`
    is `Restored { .. }` and the file is gone; called again → `Nothing`.
- **Done when:** eleven tests green; `cargo test -p aitm-sysproxy` green; gate green.

### Task 7: the watchdog (`watchdog.rs`)

- **Satisfies:** SP-AC13 (`decide`; the `parse_mode` half is Task 10), §D9 (b).
- **Depends on:** Tasks 1, 4 (and Task 2/3 ops for `run`'s restore; it compiles against
  the trait only).
- **Files:** `crates/aitm-sysproxy/src/watchdog.rs` (fill).
- **Change:**
  ```rust
  #[derive(Debug, PartialEq, Eq)]
  pub enum Decision { Exit0, Restore { only: Vec<String>, left_alone: Vec<String> } }
  pub fn decide(file: Option<&StateFile>, live: &[ServiceRow]) -> Decision;   // None → Exit0; else partition service_names() by service_equals_wrote over `live` (a name absent from `live` counts as not equal)
  pub struct WatchdogArgs { pub pid: u32, pub state: PathBuf, pub no_pipe: bool }
  pub struct WatchdogHandle { child: std::process::Child, _stdin: std::process::ChildStdin }
  impl WatchdogHandle { pub fn pid(&self) -> u32; pub fn is_alive(&mut self) -> bool; }   // try_wait().ok() == Some(None)
  pub fn spawn(exe: &Path, core_pid: u32, state: &Path) -> std::io::Result<WatchdogHandle>;   // args ["sysproxy-watchdog","--pid",pid,"--state",state]; stdin piped (kept open, never written); stdout/stderr null; #[cfg(unix)] CommandExt::process_group(0)
  pub fn run(args: &WatchdogArgs) -> i32;    // wait (stdin EOF, or 1 s liveness poll when no_pipe) → decide → restore via a SystemProxy built with `with_mechanism(file.mechanism)` and `RealExecutor::with_timeouts(10 s, 30 s)` → exit 0 / 3; appends C8 lines to WATCHDOG_LOG_NAME beside `state`, truncated at start
  pub fn is_alive(pid: u32, exec: &dyn Executor) -> bool;   // macOS: `/bin/ps -p <pid> -o pid=` non-empty stdout; Linux: Path `/proc/<pid>` exists; else false
  pub const EXIT_RESTORE_FAILED: i32 = 3; pub const EXIT_BAD_ARGS: i32 = 2;
  ```
  `run` must never print (the parent nulls its fds anyway) and must not need the
  core's config: the state file carries `wrote` (→ `ours`) and `mechanism`.
- **Test** (`watchdog.rs` `#[cfg(test)]`):
  - `decide_table` (SP-AC13): `decide(None, &[])` → `Exit0`; a two-service file and
    `live` equal → `Restore { only: ["Display Ethernet", "Wi-Fi"], left_alone: [] }`;
    `live` with `Display Ethernet` at `10.0.0.5:3128` → `Restore { only: ["Wi-Fi"], left_alone: ["Display Ethernet"] }`.
  - `is_alive_uses_ps_on_macos`: with a `ScriptedExecutor` answering
    `/bin/ps -p 4242 -o pid=` with `"4242\n"` → `true` (under `#[cfg(target_os = "macos")]`);
    answering `""` → `false`.
  - `no_pipe_run_restores_when_the_pid_is_dead_and_the_file_is_gone_exit_0`: write a
    state file, `run(&WatchdogArgs { pid: <a child `/usr/bin/true` that has already
    exited and been waited>, no_pipe: true, .. })` with the file REMOVED first → returns
    `0` and the log's last line contains `file-gone`. (Restoring a real proxy is not
    tested here; that is SP-AC21.)
  - `spawn_builds_the_hidden_argv`: `spawn(Path::new("/usr/bin/true"), 1, Path::new("/x"))`
    returns `Ok(handle)` whose child exits 0 when waited (`/usr/bin/true` ignores the
    args) — proves the pipe plumbing compiles and does not block.
- **Done when:** four tests green; gate green.

### Task 8: the three commands (`plugin.rs`)

- **Satisfies:** SP-AC15; the schema half of SP-AC17; D6 `summarize`; D10.
- **Depends on:** Task 6.
- **Files:** `crates/aitm-sysproxy/src/plugin.rs` (fill).
- **Change:**
  ```rust
  pub struct SysProxyPlugin { sp: Arc<SystemProxy>, listening: Arc<AtomicBool> }
  impl SysProxyPlugin { pub fn new(sp: Arc<SystemProxy>, listening: Arc<AtomicBool>) -> Self; }
  impl aitm_core::Plugin for SysProxyPlugin { fn name(&self) -> &str { "sysproxy" } fn load(&mut self, reg: &mut Registry) { /* ProxySystemStatus, ProxySystemSet, ProxySystemUnset */ } }
  pub(crate) struct ProxySystemStatus { sp };   // name "proxy.system.status", Sensitivity::Read, params []
  pub(crate) struct ProxySystemSet { sp, listening };   // "proxy.system.set", Sensitive, params [ParamDef { name: "bypass", ty: TypeDesc::Array(Box::new(TypeDesc::Str)), required: false, description: "Extra hosts that skip the system proxy (merged with the defaults and system_proxy.bypass)" }]
  pub(crate) struct ProxySystemUnset { sp };    // "proxy.system.unset", Sensitive, params []
  pub const OPERATOR_ONLY_MSG: &str = "proxy.system.set is operator-only: an agent can never change the system proxy";
  pub const NEEDS_RUNNING_CORE_MSG: &str = "proxy.system.set needs a running core: use the app, the TUI or the web UI, or start aitm with `system_proxy.auto: true`";
  ```
  `set`/`unset` `invoke`: `if host.frontend() == Frontend::Mcp { bail!(OPERATOR_ONLY_MSG) }`
  (unset's message names `proxy.system.unset`); `set` additionally
  `if !listening.load(..) { bail!(NEEDS_RUNNING_CORE_MSG) }`. Results: the `Status`
  value plus `changed`, `commands` (and `restored`, `left_alone` for unset).
  `summarize`: `"system proxy → 127.0.0.1:8080 (2 services, 1240 ms)"` /
  `"system proxy restored → 127.0.0.1:9090 (2 services, 980 ms)"` (ms from
  `last_change_ms` delta measured inside `invoke`; the restored endpoint is the first
  restored service's previous HTTP endpoint, or `off`).
- **Test** (`plugin.rs` `#[cfg(test)]`, a `CommandHost` built as `crates/aitm-core/src/ctx.rs`
  line ~629 does — `CommandHost::new(&store, &client, &guard, None).with_frontend(..)`
  with the in-crate test doubles copied from `aitm-ca`'s command tests if `aitm-core`
  exports none; the Coder checks `aitm_core::testing` first):
  - `set_refuses_mcp_with_zero_runs` (SP-AC15): `Frontend::Mcp` → `Err` containing
    `operator-only`; `exec.runs().is_empty()`.
  - `set_refuses_a_one_shot_process` (SP-AC15): `Frontend::Cli`, `listening == false`
    → `Err` containing `needs a running core`; zero runs.
  - `unset_and_status_work_one_shot` (SP-AC15): `Frontend::Cli`, `listening == false`:
    `proxy.system.status` → `Ok` object with `state`; `proxy.system.unset` with no file
    → `Ok` with `changed == Bool(false)`.
  - `set_schema_has_one_optional_bypass_array` (SP-AC17 half): `schema().params.len() == 1`,
    `params[0].name == "bypass"`, `required == false`, `ty == TypeDesc::Array(Box::new(TypeDesc::Str))`.
  - `operator_set_returns_changed_and_commands`: `Frontend::Operator`, `listening == true`,
    the SP-AC5 scripted macOS executor → `Ok` object with `changed == Bool(true)` and
    `commands` an `Array` of 6 `Str` lines containing ` -set`.
- **Done when:** five tests green; gate green.

### Task 9: wiring — `wire.rs`, `control.rs`

- **Satisfies:** SP-AC18 (the `proxy.status` half), D8, the `registered schema` half of SP-AC17.
- **Depends on:** Tasks 6, 8.
- **Files:** `crates/aitm-plugins/Cargo.toml` (add `aitm-sysproxy.workspace = true`, C14),
  `crates/aitm-plugins/src/control.rs` (modify), `crates/aitm/src/wire.rs` (modify).
- **Change:**
  - `control.rs`: `ControlPlugin` gains `system_proxy: Option<Arc<aitm_sysproxy::SystemProxy>>`
    and `pub fn with_system_proxy(mut self, sp: Arc<SystemProxy>) -> Self`; `ProxyStatus`
    carries the same `Option` and inserts `"system_proxy": sp.summary().to_value()` when
    present (the §D6 compact object: `state`, `host`, `port`, `managed_by_us`, `setting`,
    `supported`, `detail`); the `schema().description` names the new field. `ControlPlugin::new`
    is unchanged.
  - `wire.rs`: `Features` gains `pub sysproxy: Option<Arc<SystemProxy>>` (default `None`),
    `Features` gains `pub system_proxy: SystemProxyConfig` (default); `assemble_with_scripts`
    builds `features.sysproxy.clone().unwrap_or_else(|| Arc::new(SystemProxy::detect(Arc::new(RealExecutor::with_timeouts(Duration::from_secs(10), Duration::from_secs(30))), &features.system_proxy, aitm_sysproxy::ours_from(cfg.listen), std::env::current_exe().ok())))`,
    hands it to `ControlPlugin::new(armed, listening.clone()).with_system_proxy(sp.clone())`,
    registers `SysProxyPlugin::new(sp.clone(), listening.clone())` immediately after
    `ControlPlugin`, and `Assembled` gains `pub sysproxy: Arc<SystemProxy>`.
- **Test** (`wire.rs` `#[cfg(test)]`, pattern of the existing `macos_capture` wiring tests):
  - `sysproxy_verbs_are_registered_with_control`: `assemble_with(&cfg, &Features { sysproxy: Some(scripted), ..Default::default() })`;
    the registry lists `proxy.system.status`, `proxy.system.set`, `proxy.system.unset`;
    `proxy.system.set`'s schema has exactly one param `bypass` (SP-AC17 half).
  - `proxy_status_carries_system_proxy_cached_and_refreshed` (SP-AC18): with a scripted
    macOS executor (reads at `127.0.0.1:9090`), two `proxy.status` invocations → the
    result object has `system_proxy.state == Str("other")`, `system_proxy.host == Str("127.0.0.1")`,
    `system_proxy.port == Int(9090)`, and exactly one `/usr/sbin/scutil --proxy` in
    `exec.runs()`; `proxy.system.set {}` from an `Operator` host with `listening = true`
    (queued verify answers at `8080`), then `proxy.status` → `system_proxy.state ==
    Str("points_at_us")` and the `scutil --proxy` count equals what it was when `set`
    returned.
  - `unsupported_mechanism_reports_without_a_shell_out`: `with_mechanism(.., None)` →
    `proxy.status.system_proxy.state == Str("unsupported")`, `supported == Bool(false)`,
    `exec.runs().is_empty()`.
- **Done when:** three tests green; gate green (including `crates/aitm/tests/wiring*.rs`).

### Task 10: `main.rs` — hidden watchdog mode, recovery, orderly exit

- **Satisfies:** SP-AC13 (`parse_mode` half), §D9 (a) and (c), D10.
- **Depends on:** Tasks 7, 9.
- **Files:** `crates/aitm/src/main.rs` (modify).
- **Change:** `Mode` gains `SysproxyWatchdog { pid: u32, state: PathBuf, no_pipe: bool }`;
  `parse_mode`: `Some("sysproxy-watchdog") => parse_sysproxy_watchdog(&argv[1..])`
  (`--pid <n>`, `--state <path>`, optional `--no-pipe`; anything else → `Err(usage)`
  where the usage line is `"usage: aitm sysproxy-watchdog --pid <pid> --state <file> [--no-pipe]"`);
  in `run()`, right after the `OperatorToken` early return and before tracing:
  `if let Mode::SysproxyWatchdog { .. } = mode { std::process::exit(aitm_sysproxy::watchdog::run(&args)) }`.
  The `tui_log` match adds the arm. After `assembled` is destructured (`sysproxy`), and
  only when `mode` is `Server | Tui | Web` (C5), before the pre-bind / `select!`:
  `match sysproxy.recover_at_startup(system_proxy.auto) { Recovery::Failed(m) => warn!(..), other => info!(..) }`.
  After the `let result = …` block and BEFORE the browser reap: `sysproxy.on_orderly_exit()`
  for the same three modes, logged at `info!` when it restored. No usage text, CLI
  registry entry or `--help` mentions `sysproxy-watchdog`. `Settings` destructuring
  binds `system_proxy` (Task 5 left it `_`) and `features.system_proxy = system_proxy.clone()`.
- **Test** (`main.rs` `#[cfg(test)]`, beside `parse_mode` tests):
  - `parse_mode_sysproxy_watchdog` (SP-AC13): `parse_mode(args(&["sysproxy-watchdog","--pid","1","--state","/x"]))`
    `== Ok(Mode::SysproxyWatchdog { pid: 1, state: PathBuf::from("/x"), no_pipe: false })`;
    `parse_mode(args(&["sysproxy-watchdog","--pid","1"]))` is `Err(u)` with `u` containing
    `"usage: aitm sysproxy-watchdog"`; with `--no-pipe` → `no_pipe: true`.
  - `usage_does_not_mention_the_watchdog`: every `USAGE` constant reachable from
    `main.rs` (`tui::USAGE`, `web::USAGE`, the operator-token usage) and the CLI
    dispatcher's `usage()` over the assembled registry contain no `sysproxy-watchdog`.
  - Then `cargo test -p aitm --test shutdown` still green (the exit path still reaps).
- **Done when:** tests green; gate green; `./target/debug/aitm --help 2>&1 | grep -c sysproxy-watchdog` prints `0`.

### Task 11: contract pins + operator-only gate (unblocked; PR #200 is in the tree)

- **Satisfies:** SP-AC16, SP-AC17.
- **Depends on:** Task 9.
- **Files:** `crates/aitm-mcp/src/server.rs` (modify `is_operator_only` + tests),
  `crates/aitm/tests/frontends.rs` (modify), `crates/aitm-tui/src/lib.rs` (modify
  `CORE_TOOLS`), `crates/aitm-tui/fixtures/bus-fixture.json` (only if it still exists),
  `crates/aitm-tui/tests/tester_shell.rs` (only if the fixture still exists, C12).
- **Change:** `is_operator_only` becomes
  `matches!(name, "agent.set" | "agent.approve" | "l4.agent.set" | "proxy.system.set" | "proxy.system.unset")`;
  `defers_to_command_gate` is NOT touched. `EXPECTED_TOOLS: [&str; 59]` → `[&str; 62]`
  with the three verbs after `"proxy.resume"`. `CORE_TOOLS` gains the three after
  `"capture.status"` with a comment naming this spec. If `bus-fixture.json` exists: add
  three `{ "name", "description", "inputSchema" }` entries (set's schema has the one
  optional `bypass` array property) and move `assert_eq!(app.tools.len(), 62)` (two
  places, lines ~936 and ~993 today) to `65`.
- **Test:**
  - `server.rs` tests, `proxy_system_verbs_are_operator_only_never_parked` (SP-AC16):
    register two fake `Sensitive` commands named `proxy.system.set` / `proxy.system.unset`
    and a fake `Read` `proxy.system.status` (the `RevokeSensitive` fake at line ~3406 is
    the model); for each of `AgentPolicy::All`, `Auto`, `Ask` an agent-role `tools/call`
    on `set` and on `unset` returns a tool error whose text contains `operator` and the
    approval hub has zero pending entries (`Ask` would otherwise park); `proxy.system.status`
    under `ReadOnly` is allowed. Plus `assert!(is_operator_only("proxy.system.set"))`,
    `assert!(is_operator_only("proxy.system.unset"))`, `assert!(!defers_to_command_gate("proxy.system.set"))`,
    `assert!(!defers_to_command_gate("proxy.system.unset"))`.
  - `frontends.rs`: the existing `tools/list` equality test now passes with 62 names;
    the Coder quotes the red run (61 vs 62 mismatch) before editing.
  - `tester_shell.rs` (if present): `fixture_app_core_offers_exactly_the_core_tools…`
    passes with `65`. (A fixture test is a compile/consistency gate for the pin, never
    evidence of behaviour.)
- **Done when:** gate green in the sandbox AND the full gate run once in the Terminal
  panel (`tui_live_bus`).

### Task 12: SP-AC28 tripwire test

- **Satisfies:** SP-AC28; the grep half of SP-AC9.
- **Depends on:** Task 1. Independent of Tasks 2–11 (runs against whatever exists).
- **Files:** `crates/aitm-sysproxy/tests/tripwire.rs` (create).
- **Change/Test:** `no_privilege_escalation_strings_in_the_system_proxy_code`: walks
  `crates/aitm-sysproxy/src` recursively plus this fixed list of workspace files
  (relative to `CARGO_MANIFEST_DIR/../..`): `crates/aitm/src/main.rs`,
  `crates/aitm/src/wire.rs`, `crates/aitm/src/config_file.rs`,
  `crates/aitm-plugins/src/control.rs`, `crates/aitm-tui/src/model.rs`,
  `crates/aitm-tui/src/app.rs`, `crates/aitm-tui/src/keys.rs`, `crates/aitm-tui/src/ui/bars.rs`,
  `apps/web/src/state/app.ts`, `apps/web/src/state/systemProxy.ts`, `apps/web/src/shell/Toolbar.tsx`,
  `apps/mac/Sources/AitmproxyKit/SystemProxyFacts.swift`, `apps/mac/Sources/AitmproxyKit/ConnectionSummary.swift`,
  `apps/mac/Sources/Aitmproxy/Session+SystemProxy.swift`, `apps/mac/Sources/Aitmproxy/Shell/SystemProxySheet.swift`
  (a file that does not exist yet is skipped with a printed `NOTE`), and asserts no
  non-comment line contains `sudo `, `osascript` or `with administrator privileges`
  (a line whose trimmed text starts with `//`, `///`, `//!`, `#`, `*` or `/*` is a
  comment; the test's own source is excluded). `no_unsafe_in_the_crate`: no line under
  `crates/aitm-sysproxy/src` contains `unsafe`. Red run: plant `let x = "sudo ";` in a
  scratch copy and show the failure, then remove it.
- **Done when:** both tests green; gate green.

### Task 13: operator docs

- **Satisfies:** the "docs" item of PR 1's file ownership (spec Constraints).
- **Depends on:** Tasks 8, 10.
- **Files:** the operator config reference, if one exists (`grep -rl macos_capture docs/*.md docs/**/*.md`
  excluding `docs/research` and `docs/superpowers`; if none exists, `README.md`'s config
  section). Add the `system_proxy:` block from §D7 with its three keys, the three verbs
  with one line each, the recovery sentence ("restored on quit, after a crash by a
  watchdog, and at the next start; `aitm proxy system unset` restores by hand"), and the
  Linux headless `export` guidance. No code.
- **Test:** none (prose); the Coder quotes `git diff --stat`.
- **Done when:** the text matches the shipped field names and verb names exactly.

### Task 14: live proof, macOS core-only (SP-AC20 core half, SP-AC21)

- **Satisfies:** SP-AC21; the core half of SP-AC20 (the app press is Task 31).
- **Depends on:** Tasks 1–12 merged into the branch; release build.
- **Files:** none in the tree. Output goes into the PR body.
- **Terminal panel script shape** (run by the owner in Matt's real shell; the sandbox
  cannot run `networksetup` writes or bind ports):
  ```
  set -u; T=/tmp/claude/sysproxy-proof; mkdir -p $T
  # 0. record the before-state and arm the restore trap
  scutil --proxy > $T/before.scutil; for s in "Display Ethernet" "Wi-Fi"; do networksetup -getwebproxy "$s"; networksetup -getsecurewebproxy "$s"; networksetup -getproxybypassdomains "$s"; done > $T/before.services
  trap 'cd <worktree> && ./target/release/aitm --config $T/cfg.yaml proxy system unset >/dev/null 2>&1; echo RESTORE-TRAP; scutil --proxy' EXIT
  # 1. build and write a throwaway config (operator token generated into the 0600 file; never echoed)
  cargo build --release -p aitm
  printf 'listen: "127.0.0.1:18080"\nmcp:\n  transport:\n    loopback_tcp:\n      port: 0\n      token: "%s"\n      endpoint_file: "%s"\nsystem_proxy:\n  auto: true\n  state_file: "%s"\n' "$(openssl rand -hex 32)" "$T/bus.addr" "$T/state.json" > $T/cfg.yaml; chmod 600 $T/cfg.yaml
  ./target/release/aitm --config $T/cfg.yaml operator-token generate >/dev/null
  # 2. start with auto → set at startup
  ./target/release/aitm --config $T/cfg.yaml > $T/core.log 2>&1 & CORE=$!; sleep 3
  scutil --proxy | tee $T/after-set.scutil      # expect HTTPEnable : 1, HTTPProxy : 127.0.0.1, HTTPPort : 18080, same for HTTPS
  ./target/release/aitm --config $T/cfg.yaml proxy system status   # one-shot read: state points_at_us, managed_by_us true
  python3 -c 'import json;d=json.load(open("'$T'/state.json"));print(json.dumps(d["previous"],indent=1))' | tee $T/previous.json   # equals before.services
  curl -s -x http://127.0.0.1:18080 http://example.com -o /dev/null -w '%{http_code}\n'    # a flow through the core
  # 3. SIGTERM → orderly restore (SP-AC20 quit half)
  kill -TERM $CORE; wait $CORE; scutil --proxy | tee $T/after-term.scutil; diff $T/before.scutil $T/after-term.scutil && echo RESTORED-ON-TERM; test ! -e $T/state.json && echo STATE-FILE-GONE
  # 4. the verb path over the bus (operator token read from the 0600 config into a variable, never printed)
  ./target/release/aitm --config $T/cfg.yaml > $T/core2.log 2>&1 & CORE=$!; sleep 3
  PYTHONPATH=tests/e2e python3 - <<'EOF'   # uses aitm_e2e.bus.BusClient(host, port, token).connect(); calls proxy.system.unset then proxy.system.set {}; prints only state/changed/commands
  …
  EOF
  # 5. kill -9 → watchdog restore within 3 s (SP-AC21)
  kill -9 $CORE; sleep 3; scutil --proxy | tee $T/after-kill.scutil; diff $T/before.scutil $T/after-kill.scutil && echo RESTORED-BY-WATCHDOG; test ! -e $T/state.json && echo STATE-FILE-GONE; grep restored $T/system-proxy-watchdog.log
  trap - EXIT
  ```
  Note for the Coder writing the script: the state file's directory is `$T`, so the
  watchdog log is `$T/system-proxy-watchdog.log`. The PR body quotes `before.scutil`,
  `after-set.scutil`, `after-term.scutil`, `after-kill.scutil`, `previous.json` and the
  `restored` log line. `grep -c` of the hex token over the quoted output must be `0`.
  If the orderly restore takes over 5 s on Matt's Mac, note the measured time for Task 27.
- **Done when:** the four dumps and the log line are in the PR body, before == after
  for both restores, and no token appears.

### Task 15: live proof, Linux in Lima `cis-lab` (SP-AC22)

- **Satisfies:** SP-AC22.
- **Depends on:** Tasks 1–12.
- **Files:** none in the tree. Output goes into the PR body.
- **Terminal panel script shape:**
  ```
  # copy the branch (tracked files only) into the VM and build there with the VM-local cargo
  cd <worktree> && git ls-files -z | tar -c --null -T - | limactl shell cis-lab -- sh -c 'mkdir -p ~/aitm-src && tar -x -C ~/aitm-src'
  limactl shell cis-lab -- sh -c 'cd ~/aitm-src && CARGO_BUILD_JOBS=3 cargo build --release -p aitm'   # libpcap-dev is installed
  limactl shell cis-lab -- sh -c '
    set -u; T=/tmp/sp; mkdir -p $T
    for k in "org.gnome.system.proxy mode" "org.gnome.system.proxy.http host" "org.gnome.system.proxy.http port" "org.gnome.system.proxy.https host" "org.gnome.system.proxy ignore-hosts"; do echo "$k = $(gsettings get $k)"; done | tee $T/before     # mode = '"'"'none'"'"'
    trap "gsettings set org.gnome.system.proxy mode '"'"'none'"'"'" EXIT
    cd ~/aitm-src; <write $T/cfg.yaml as in Task 14 with listen 127.0.0.1:18080, system_proxy.auto: false, state_file $T/state.json>
    ./target/release/aitm --config $T/cfg.yaml > $T/core.log 2>&1 & CORE=$!; sleep 3
    PYTHONPATH=tests/e2e python3 - <<EOF    # BusClient operator: call proxy.system.set {} → print state only
    EOF
    gsettings get org.gnome.system.proxy mode; gsettings get org.gnome.system.proxy.http host   # '"'"'manual'"'"', '"'"'127.0.0.1'"'"'
    PYTHONPATH=tests/e2e python3 … proxy.system.unset …; gsettings get org.gnome.system.proxy mode   # '"'"'none'"'"' and the original hosts
    PYTHONPATH=tests/e2e python3 … proxy.system.set {} …; kill -9 $CORE; sleep 3; gsettings get org.gnome.system.proxy mode   # '"'"'none'"'"' again, by the watchdog
    cat $T/system-proxy-watchdog.log; trap - EXIT'
  ```
  No step needs root. The PR body quotes each `gsettings get` and the watchdog log.
- **Done when:** the quoted values read `'none'` → `'manual'`/`'127.0.0.1'` → `'none'`
  → (after `kill -9`) `'none'`, and the original `ignore-hosts` is back.

---

## PR 2 — TUI (`:sysproxy`, key `s`, pill word)

**WAIT:** after the fake-data-removal TUI PR and l4-parity's TUI unit have merged;
rebase onto main first. **`crates/aitm-tui/src/fixture.rs` and `fixtures/bus-fixture.json` were removed from main by #244 (2026-11-01); no fixture pin remains. Tests build on `App::new()`.**

### Task 16: model — `SystemProxyWord`

- **Satisfies:** SP-AC26 (parse half).
- **Depends on:** PR 1 merged.
- **Files:** `crates/aitm-tui/src/model.rs` (modify).
- **Change:**
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Default)]
  pub struct SystemProxyWord { pub state: String, pub host: Option<String>, pub port: Option<u16>, pub managed_by_us: bool, pub setting: bool, pub supported: bool, pub detail: String }
  impl SystemProxyWord {
      pub fn from_json(v: &Value) -> Option<Self>;          // None when the key is absent or not an object
      pub fn pill(&self, in_flight: bool) -> Option<String>; // the §D12 pill column: "· sys-proxy → us", "· sys-proxy → h:p", "· sys-proxy off", "· sys-proxy needs admin", "· sys-proxy setting…"; None for unsupported/unknown
  }
  pub struct ProxyStatus { …, pub system_proxy: Option<SystemProxyWord> }   // parsed from v["system_proxy"]
  ```
- **Test** (`model.rs` tests, beside `proxy_status_parses_the_control_plugin_shape`):
  `system_proxy_word_parses_and_renders`: `ProxyStatus::from_json(json!({"listening":true,"address":"127.0.0.1:8080","system_proxy":{"state":"other","host":"127.0.0.1","port":9090,"managed_by_us":false,"setting":false,"supported":true,"detail":"HTTP and HTTPS → 127.0.0.1:9090 (not this core)"}}))`
  → `system_proxy.as_ref().unwrap().pill(false) == Some("· sys-proxy → 127.0.0.1:9090".into())`;
  `state: "points_at_us"` → `Some("· sys-proxy → us")`; `state: "off"` → `Some("· sys-proxy off")`;
  `state: "needs_privilege"` → `Some("· sys-proxy needs admin")`; `state: "unsupported"` → `None`;
  any state with `pill(true)` → `Some("· sys-proxy setting…")`; a `proxy.status` without
  the key → `system_proxy == None`.
- **Done when:** test green; gate green.

### Task 17: app — `:sysproxy`, `Action::ToggleSysProxy`, key `s`, reply handling

- **Satisfies:** SP-AC26 (command and in-flight halves), D14.
- **Depends on:** Task 16.
- **Files:** `crates/aitm-tui/src/action.rs` (add `ToggleSysProxy`), `crates/aitm-tui/src/keys.rs`
  (`KeyCode::Char('s') => Action::ToggleSysProxy` in `flows(..)`; `s` is unbound there
  today — if it is bound when the task runs, pick another free key, use it everywhere
  this plan says `s`, and say so in the report), `crates/aitm-tui/src/app.rs` (modify),
  `crates/aitm-tui/src/bus.rs` (only if `BusRequest::Call` cannot carry it; expected: no change).
- **Change:** `App` gains `pub system_proxy: Option<SystemProxyWord>` (set from every
  `proxy.status` reply next to `capture_paused`) and `pub sysproxy_setting: bool`.
  `run_command`: `"sysproxy"` with `rest` ∈ `on|off|status`: gate `has_tool("proxy.system.set")`
  else toast `Level::Warn, "System proxy needs the core's proxy.system.* verbs"`; `on` →
  `sysproxy_setting = true` + `BusRequest::Call { name: "proxy.system.set".into(), args: json!({}) }`;
  `off` → `sysproxy_setting = true` + `Call "proxy.system.unset" {}`; `status` → `Call "proxy.system.status" {}`
  (its reply toasts `detail` and, when it parses, refreshes the word — amended 2026-11-01); other `rest` → `Level::Error` usage toast
  `"usage: :sysproxy on|off|status"`. `Action::ToggleSysProxy` → `on` when
  `system_proxy.state != "points_at_us"`, else `off`. Reply handling (the `match name`
  that handles `"proxy.pause" | "proxy.resume"`): `"proxy.system.set" | "proxy.system.unset"`
  → `sysproxy_setting = false`, `system_proxy = SystemProxyWord::from_json(&value)`, toast
  `Level::Info` with `detail`; a bus error for either → `sysproxy_setting = false` and the
  error text verbatim as `Level::Error`. The `Call`s for these two verbs carry no timeout
  (the TUI bus has none today; the Coder confirms and adds none).
- **Test** (`app.rs` tests, model: `C4` `:pause` test near line ~5413):
  - `sysproxy_on_calls_set_when_the_tool_exists` (SP-AC26): `app.tools.extend(tools(&["proxy.system.set","proxy.system.unset","proxy.system.status"]))`;
    `app.run_command(":sysproxy on") == vec![BusRequest::Call { name: "proxy.system.set".into(), args: json!({}) }]`
    and `app.sysproxy_setting == true`.
  - `sysproxy_without_the_tool_toasts`: no tool → `run_command(":sysproxy on")` is empty
    and the newest toast text is `"System proxy needs the core's proxy.system.* verbs"`.
  - `s_key_toggles_by_state`: `app.system_proxy = Some(SystemProxyWord { state: "points_at_us".into(), .. })`
    → `update(Action::ToggleSysProxy)` yields a `proxy.system.unset` call; with `state: "off"`
    → `proxy.system.set`. `keys::map(press(KeyCode::Char('s')), Mode::Main)` (or the flows
    mode's name) `== Some(Action::ToggleSysProxy)`.
  - `set_reply_clears_in_flight_and_updates_the_word`: feed the `BusEvent` reply for
    `proxy.system.set` with a `points_at_us` object → `sysproxy_setting == false`,
    `system_proxy.unwrap().state == "points_at_us"`.
- **Done when:** four tests green; gate green.

### Task 18: UI — pill word, help overlay, palette completion

- **Satisfies:** SP-AC26 (render half).
- **Depends on:** Task 17.
- **Files:** `crates/aitm-tui/src/ui/bars.rs` (modify `toolbar`), `crates/aitm-tui/src/ui/overlays.rs`
  (help line), `crates/aitm-tui/src/app.rs` — NOT `ui/complete.rs`, corrected 2026-11-01 — (`BUILTIN_COMMANDS` entry
  `("sysproxy on|off|status", "Set / restore the OS system proxy (s)")` — casing/wording amended 2026-11-01 on the quality panel's ask).
  A reconnect (`BusEvent::Connected`/`Disconnected`) drops the in-flight flag (added 2026-11-01, F-tui 6).
- **Change:** in `toolbar`, after `format!(" · {listen}")` and before `{state}`
  (`· intercept armed` / `· capture paused`), append `app.system_proxy.as_ref().and_then(|w| w.pill(app.sysproxy_setting)).map(|p| format!(" {p}")).unwrap_or_default()`.
  Help overlay: `k("s", "set / restore the system proxy (:sysproxy on|off|status)")` after the `b / l / t` line.
- **Test** (`crates/aitm-tui/tests/` — a new `sysproxy_pill.rs` rendering `toolbar` into a
  `Buffer` of 160 cols via the crate's existing render helpers, the way `tester_shell.rs`'s
  `text_of` does but on an `App::new()` populated by hand — NOT on `fixture_app`):
  `pill_shows_the_word_table`: `app.listening = Some("127.0.0.1:8080")`, `serving = Some(true)`,
  `system_proxy = Some(other 127.0.0.1:9090)` → the row text contains
  `"listening 127.0.0.1:8080 · sys-proxy → 127.0.0.1:9090"`; `points_at_us` →
  `"· sys-proxy → us"`; `sysproxy_setting = true` → `"· sys-proxy setting…"`;
  `system_proxy = None` → the text contains `"listening 127.0.0.1:8080"` and not `"sys-proxy"`.
- **Done when:** test green; gate green in the sandbox and once in the Terminal.

### Task 19: live proof, TUI (SP-AC27 TUI half)

- **Satisfies:** SP-AC27 (TUI).
- **Depends on:** Tasks 16–18.
- **Terminal panel script shape:** Task 14's step 0 (record + trap), then
  `./target/release/aitm --config $T/cfg.yaml tui` in a second Terminal tab (`system_proxy.auto: false`);
  press `s`; in the first tab `scutil --proxy | tee $T/tui-set.scutil` (HTTPPort = the
  config's port); press `s` again; `scutil --proxy | tee $T/tui-unset.scutil`;
  `diff before.scutil tui-unset.scutil && echo RESTORED`; `q`. The pill word change is
  observed within one poll (the PR body states the observed word). Both dumps in the PR body.
- **Done when:** the two dumps are quoted and before == after.

---

## PR 3 — web (pill menu, `app.proxy.systemProxy`)

**WAIT:** after the fake-data-removal web PR and l4-parity's web unit have merged.
**Never touch `apps/web/src/bus/mock.ts` or `apps/web/src/bus/noise.ts`.** Tests are
`vitest` (`npm test` in `apps/web`), pure functions only; no mock-bus run is evidence.

### Task 20: pure module — `state/systemProxy.ts` + `bus/types.ts`

- **Satisfies:** SP-AC27 (the parse/word logic it depends on), D15.
- **Depends on:** PR 1 merged.
- **Files:** `apps/web/src/bus/types.ts` (add `SystemProxyStatus`),
  `apps/web/src/state/systemProxy.ts` (create), `apps/web/src/state/systemProxy.test.ts` (create).
- **Change:**
  ```ts
  // types.ts
  export type SystemProxyState = 'off' | 'points_at_us' | 'other' | 'unsupported' | 'needs_privilege' | 'unknown';
  export interface SystemProxyStatus { state: SystemProxyState; host: string | null; port: number | null; managed_by_us: boolean; setting: boolean; supported: boolean; detail: string; guidance?: string | null; remedy?: string | null; }
  // systemProxy.ts
  export function parseSystemProxy(v: unknown): SystemProxyStatus | null;   // null when absent/not an object/unknown state string → state 'unknown'
  export function pillWord(s: SystemProxyStatus | null, inFlight: boolean): string | null;  // '· sys-proxy → us' | '· sys-proxy → h:p' | '· sys-proxy off' | '· sys-proxy needs admin' | '· sys-proxy setting…' | null
  export function menuState(s: SystemProxyStatus | null, inFlight: boolean, role: 'operator' | 'agent' | null): { checked: boolean; disabled: boolean; title: string | undefined; showCopyEnv: boolean };
  ```
  `menuState` titles: `'setting system proxy…'` while in flight, `'system proxy not available here'`
  when unsupported, `'connect with the operator token to change the system proxy'` when
  `role !== 'operator'`.
- **Test** (`systemProxy.test.ts`): `parseSystemProxy({state:'other',host:'127.0.0.1',port:9090,managed_by_us:false,setting:false,supported:true,detail:'x'})`
  → `.state === 'other'`, `.port === 9090`; `parseSystemProxy(undefined) === null`;
  `pillWord(other, false) === '· sys-proxy → 127.0.0.1:9090'`; `pillWord(pointsAtUs, false) === '· sys-proxy → us'`;
  `pillWord(off, false) === '· sys-proxy off'`; `pillWord(needsPrivilege, false) === '· sys-proxy needs admin'`;
  `pillWord(unsupported, false) === null`; `pillWord(off, true) === '· sys-proxy setting…'`;
  `menuState(pointsAtUs, false, 'operator').checked === true`; `menuState(off, true, 'operator').disabled === true`
  with `title === 'setting system proxy…'`; `menuState(off, false, 'agent').disabled === true`;
  `menuState({...unsupported, guidance: 'export …'}, false, 'operator').showCopyEnv === true`.
- **Done when:** `npm test` green; `npm run build` green.

### Task 21: store — parse on poll, two actions

- **Satisfies:** SP-AC27 (store half).
- **Depends on:** Task 20.
- **Files:** `apps/web/src/state/app.ts` (modify).
- **Change:** `ProxyState` gains `systemProxy: SystemProxyStatus | null` (initial `null`)
  and `systemProxySetting: boolean` (initial `false`); both `proxy.status` readers
  (`~line 710` and `~line 891`) set `systemProxy: parseSystemProxy(s.system_proxy)`;
  actions `setSystemProxy: () => guarded('system proxy', …)` calling
  `bus.call('proxy.system.set', {})` and `unsetSystemProxy` calling `bus.call('proxy.system.unset')`,
  each setting `systemProxySetting` true before and false after (also on error), then
  `setProxy('systemProxy', parseSystemProxy(result))`; a refusal/error reaches the
  status bar through the existing `notice(.., 'error')` (the `guarded` helper). No
  per-call timeout exists in `ws.ts`; add none.
- **Test** (`apps/web/src/state/app.sysproxy.test.ts`, pattern of `app.polling.test.ts`
  with the bridge-shaped test bus from `bridgeBus.testkit.ts` — a request/reply double of
  the live bridge frames, which this plan treats as a unit harness for the store's
  parsing, never as frontend evidence): a `proxy.status` reply carrying `system_proxy`
  `points_at_us` → `app.proxy.systemProxy?.state === 'points_at_us'`; `setSystemProxy()`
  sets `systemProxySetting` true until the reply, then false, and the reply's status is
  stored; a rejected call leaves `systemProxySetting === false` and `app.toast()?.kind === 'error'`.
- **Done when:** tests green; `npm run build` green.

### Task 22: toolbar — the pill becomes a menu button

- **Satisfies:** SP-AC27 (UI half), D15.
- **Depends on:** Task 21.
- **Files:** `apps/web/src/shell/Toolbar.tsx` (modify), `apps/web/src/shell/Toolbar.module.css`
  (a `.listenButton` reset so the pill keeps its look as a `<button>`), `apps/web/src/shell/StatusBar.tsx`
  (only if the error slot needs a change; expected: none, `notice` already renders).
- **Change:** the `div.listen` becomes a `<button type="button" aria-haspopup="menu">` that
  appends `pillWord(app.proxy.systemProxy, app.proxy.systemProxySetting)` after the
  address and before `· intercept armed`; on click a `Menu` (like the Agent menu) with:
  `{ label: 'Set as system proxy', checked, disabled, title, onSelect: () => checked ? app.unsetSystemProxy() : app.setSystemProxy() }`
  from `menuState(.., app.bus.role())`, `{ label: detail, disabled: true }`, and when
  `showCopyEnv` a `{ label: 'Copy env line', onSelect: () => navigator.clipboard.writeText(guidance) }`.
  Flat monochrome, no new icon beyond the existing dot (the editorial rule).
- **Test:** `npm run build` + `npm test` green (the pure logic is Task 20's); the UI is
  proven live in Task 23.
- **Done when:** build green; Task 23 passes.

### Task 23: live proof, web (SP-AC27 web half)

- **Satisfies:** SP-AC27 (web).
- **Depends on:** Task 22.
- **Terminal panel script shape:** Task 14's step 0, then
  `./target/release/aitm --config $T/cfg.yaml web --port 18081` (auto off); open the
  printed URL in a real browser (the token stays in the URL fragment; the PR body quotes
  no URL); click the pill → "Set as system proxy"; `scutil --proxy | tee $T/web-set.scutil`;
  click again; `scutil --proxy | tee $T/web-unset.scutil`; `diff before.scutil web-unset.scutil && echo RESTORED`.
  Observe the pill word changing within one 2 s poll; state the observed words in the PR body.
- **Done when:** the two dumps are quoted and before == after.

---

## PR 4 — macOS app

**WAIT:** after PR 1 merges; after the mac fake-data-removal PR; after mac-attribution's
PR lands `AitmproxyKit/SystemProxyState.swift` (`SystemProxyState`, `SystemProxyRoute`,
`ConnectionAction.openNetworkSettings`, the Proxy-menu group with "Network Settings…").
`Bus/BusService.swift` only after S-041; `Session+Verbs.swift` only after l4-parity's mac
unit. Swift coders in the sandbox write code and tests and run
`swiftc -parse -module-cache-path "$TMPDIR/mc" <files>`; the owner runs
`swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build` and the dev bundle
in the Terminal. Per the evidence rule, `tools/selftest.sh`, snapshots and fixtures are
never evidence; Kit unit tests and the live run are. Do not edit `Fixtures.rows`.

### Task 24: Kit — `SystemProxyFacts`, `ConnectionSummary` system-proxy fact

- **Satisfies:** SP-AC23.
- **Depends on:** PR 1 merged; mac-attribution's `SystemProxyState.swift` present.
- **Files:** `apps/mac/Sources/AitmproxyKit/SystemProxyFacts.swift` (create),
  `apps/mac/Sources/AitmproxyKit/ConnectionSummary.swift` (modify),
  `apps/mac/Tests/AitmproxyKitTests/SystemProxyFactsTests.swift` (create),
  `apps/mac/Tests/AitmproxyKitTests/ConnectionSummaryTests.swift` (add tests).
- **Change:**
  ```swift
  public struct SystemProxyFacts: Hashable, Sendable {
      public var state: SystemProxyState          // mac-attribution's enum; map the verb's `state` string onto it with `init?(verb: String, host: String?, port: Int?)`
      public var managedByUs: Bool?               // nil when only the CFNetwork read is available
      public var setting: Bool
      public var supported: Bool
      public var remedy: String?
      public var guidance: String?
      public init(state:managedByUs:setting:supported:remedy:guidance:)
      public static func parse(_ json: JSONValue?) -> SystemProxyFacts?   // the proxy.status.system_proxy sub-object; nil when absent
  }
  public struct SystemProxyFact: Hashable, Sendable { public let text: String; public let state: LaneState; public let remedy: String?; public let actions: [ConnectionAction] }
  public enum ConnectionAction { …, case setSystemProxy, unsetSystemProxy }   // titles "Set as System Proxy", "Restore System Proxy"
  public static let systemProxyLaneSentence = "System proxy → every proxy-aware app, regardless of Scope. All Apps → in-scope hosts of every app."
  public static let bypassFieldCopy = "Hosts that skip the system proxy. Add the hosts your own tools talk to (today's incident: a tool whose API calls were routed to another proxy)."
  // ConnectionSummary.make gains `systemProxy: SystemProxyFacts? = nil`; ConnectionSummary gains `public let systemProxy: SystemProxyFact?`
  ```
  The §D12 mac-fact column, verbatim: `points_at_us` managed → "system proxy → this core"
  (`.ok`, actions `[.unsetSystemProxy]`); `points_at_us` not managed → "system proxy →
  this core · set outside the app" (`.ok`, `[]`); `managedByUs == nil` → the first text
  without the suffix; `other(h,p)` → "system proxy → h:p, not this core" (`.warning`,
  remedy "Another app owns the system proxy. Set as System Proxy records its setting and
  restores it on quit.", `[.setSystemProxy]`); `off` → "system proxy off — proxy-aware
  apps bypass the core" (`.off`, remedy "Set as System Proxy so Safari and other
  proxy-aware apps use the core.", `[.setSystemProxy]`); `needs_privilege` → "system
  proxy needs an administrator" (`.warning`, remedy = the facts' `remedy`, `[]`);
  `unsupported` → "system proxy not available here (guidance shown in Settings)" (`.off`);
  `unknown` → "system proxy unknown" (`.off`); `setting` → "setting system proxy…"
  (`.working`, `[]`). `overall` and `worst` include the fact's state only when it is
  `.warning` or `.working`. The `.firstFlow` step: supported and not at us → title
  "Set aitmproxy as the system proxy, or open the browser", action `.setSystemProxy`;
  at us → "System proxy points at \(listenAddress) — waiting for the first flow",
  action `.openBrowser`; unsupported/unknown/nil → the existing "Point a client at …" text.
- **Test** (Swift Testing):
  - `SystemProxyFactsTests.parsesTheVerbSubObject`: parse the §D6 compact JSON
    (`state: "other"`, host, port 9090 …) → `.state == .other(host: "127.0.0.1", port: 9090)`
    (or mac-attribution's spelling), `managedByUs == false`, `supported == true`;
    `parse(nil) == nil`.
  - `ConnectionSummaryTests.systemProxyFactWordTable` (SP-AC23): with `core(.ready)`,
    bus connected, each facts row yields the text, state and actions above
    (eight `#expect`s, the texts quoted literally);
    `make(systemProxy: other).overall == .warning`; `make(systemProxy: needsPrivilege).overall == .warning`;
    `make(systemProxy: off).overall == make(systemProxy: nil).overall`.
  - `ConnectionSummaryTests.firstFlowStepFollowsTheSystemProxy`: `off` facts →
    `steps[4].title == "Set aitmproxy as the system proxy, or open the browser"` and
    `steps[4].action == .setSystemProxy`; `pointsAtUs` → `"System proxy points at 127.0.0.1:8080 — waiting for the first flow"`
    with `.openBrowser`; `unsupported` → `"Point a client at 127.0.0.1:8080, or open the browser"`.
- **Done when:** owner's `swift test` shows the three new tests passing and every
  existing `ConnectionSummaryTests` still passing.


> PR 4a (2026-11-01) shipped `SystemProxyState` as a struct of two endpoints plus `SystemProxyRoute { off, thisCore(http:https:), other(host:port:) }` and `init?(compact:listenAddress:)`; `SystemProxyFacts` carries `route: SystemProxyRoute`, not an enum `state`. Expected literal: `.route == .other(host: "127.0.0.1", port: 9090)`. Files: `apps/mac/Sources/AitmproxyKit/SystemProxyState.swift`, `apps/mac/Tests/AitmproxyKitTests/SystemProxyStateTests.swift` (PR #246). Tests shipped (Swift Testing): `anEndpointRendersAsHostColonPort`, the `settings*` family, `offHasNoEndpointsAndRoutesToOff`, `bothProtocolsAtOurAddressRouteToThisCore`, `localhostSpellingsMatchOurLoopbackAddress`, `aWildcardListenAddressMatchesALoopbackProxy`, `aDifferentPortIsAnotherProxy`, `aDifferentHostOnOurPortIsAnotherProxy`, `hostnameCaseDoesNotMatter`, `httpAtUsWithHttpsOffIsThisCoreForHttpOnly`, `oneProtocolAtUsAndTheOtherElsewhereIsStillThisCore`, `otherTakesTheHttpEndpointElseTheHttpsOne`, `anUnparsableListenAddressNeverMatches`, the `compact*` family incl. `other` at our own endpoint → nil, `aMalformedCompactObjectIsNil`, `theFullStatusObjectOfTheSpecParsesLikeTheCompactOne`, `anAddressParsesOnlyWithAHostAndAPortAndBracketsAroundIPv6`, `bracketsAroundAnIPv6HostDoNotMatter`, `compactOtherAtOurOwnListenAddressIsNil`, `aParsedBusObjectIsAccepted` (31 tests after the panel fix c8ed92f4; `statesAndRoutesAreHashableByValue` deleted).

### Task 25: Kit — `EmbeddedCoreLaunch.Config` emits the `system_proxy:` block

- **Satisfies:** SP-AC25.
- **Depends on:** PR 1 merged (for the literal); independent of Task 24.
- **Files:** `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift` (modify),
  `apps/mac/Tests/AitmproxyKitTests/EmbeddedCoreLaunchTests.swift` (add tests).
- **Change:** `Config` gains `public var systemProxyAuto: Bool = false` and
  `public var systemProxyBypass: [String] = []` (init parameters with defaults, after
  `scopeHosts`); `yaml()` appends, as the LAST tail (after `scope`), when
  `systemProxyAuto || !systemProxyBypass.isEmpty`:
  `"\nsystem_proxy:\n  auto: \(systemProxyAuto)\n"` and, when the list is non-empty,
  `"  bypass:\n"` + one `"    - \"\(escaped)\"\n"` per host (via `yamlDoubleQuoted(host, onNewline: ConfigError.hostContainsNewline)`).
- **Test:** `system_proxy_block_is_byte_identical_to_the_core_parse_input` (SP-AC25):
  `config(systemProxyAuto: true, systemProxyBypass: ["corp.test"]).yaml().hasSuffix("system_proxy:\n  auto: true\n  bypass:\n    - \"corp.test\"\n")`
  — the exact string Task 5's `system_proxy_block_the_mac_app_emits_parses` parses;
  `system_proxy_block_absent_when_off_and_empty`: default config's yaml does not contain
  `"system_proxy"`; `system_proxy_bypass_only_emits_auto_false`:
  `systemProxyBypass: ["a.test"]` → contains `"system_proxy:\n  auto: false\n  bypass:\n    - \"a.test\"\n"`;
  a host with a newline throws `ConfigError.hostContainsNewline`.
- **Done when:** owner's `swift test` green.

### Task 26: app — `Session+SystemProxy.swift`, facts in, summary wiring

- **Satisfies:** D13 "Facts in" and "Calls out"; the allow-list half of SP-AC24.
- **Depends on:** Task 24.
- **Files:** `apps/mac/Sources/Aitmproxy/Session+SystemProxy.swift` (create),
  `apps/mac/Sources/Aitmproxy/Session.swift` (modify: `var systemProxyFacts: SystemProxyFacts?`,
  parse it where `proxy.status` is consumed, `var systemProxySetting = false`),
  `apps/mac/Sources/Aitmproxy/Session+Connection.swift` (modify: pass `systemProxy:` to
  `ConnectionSummary.make` — the verb facts when present, else facts derived from
  mac-attribution's `SystemProxyState` read with `managedByUs: nil` (D1: the verb wins);
  `perform(connection:)` returns `false` for `.setSystemProxy`/`.unsetSystemProxy`).
- **Change:** `Session+SystemProxy.swift` holds the only two literals
  `"proxy.system.set"` and `"proxy.system.unset"`:
  ```swift
  extension Session {
      func setSystemProxy()      // systemProxySetting = true; call "proxy.system.set" with ["bypass": bypass list from Store.defaults "systemProxy.bypass"]; on reply parse SystemProxyFacts from the result and store; on error show the message; systemProxySetting = false
      func restoreSystemProxy()  // same with "proxy.system.unset"
      var systemProxyControlLive: Bool   // bus connected as operator && facts?.supported == true && !systemProxySetting
  }
  ```
  Calls go through the same path `Session+Verbs.swift`'s verbs use (its `perform(_:_:)`
  helper and the bus's call entry). If that path cannot be reached without editing
  `Bus/BusService.swift` and S-041 has not merged, stop and report.
- **Test:** no Kit unit (app target); the two call sites are proven by Task 29's
  tripwire and Task 31's live run. Sandbox syntax check only.
- **Done when:** `swiftc -parse` clean; owner's build clean; Task 29 passes.

### Task 27: app — Settings ▸ Proxy section, `EmbeddedCore` emission

- **Satisfies:** D13 "Settings ▸ Proxy"; SP-AC25's spawn half; the §D9 (a) budget note.
- **Depends on:** Tasks 25, 26.
- **Files:** `apps/mac/Sources/Aitmproxy/SettingsView.swift` (modify `ProxySettings`),
  `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift` (modify the spawn: read
  `Store.defaults` `systemProxy.auto` (Bool, default false) and `systemProxy.bypass`
  (String, comma/space separated → `[String]`) and pass `systemProxyAuto:`/`systemProxyBypass:`),
  `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift` (ONLY if Task 14 measured an
  orderly restore over 5 s: raise `childStopGraceSeconds` and its doc comment; otherwise
  untouched).
- **Change:** below the "Embedded proxy" section, a `Section("System proxy")` with:
  a live `Toggle("Set as system proxy", isOn: Binding(get: facts.state is pointsAtUs, set: { $0 ? session.setSystemProxy() : session.restoreSystemProxy() }))`
  disabled with a footnote reason when `!session.systemProxyControlLive` ("setting…",
  "not available here", or "connect as operator"); `Toggle("Set system proxy at launch")`
  bound to `@AppStorage("systemProxy.auto", store: Store.defaults)`; `TextField("Bypass hosts")`
  bound to `@AppStorage("systemProxy.bypass", store: Store.defaults)` with
  `ConnectionSummary.bypassFieldCopy` as its footnote; `ConnectionSummary.systemProxyLaneSentence`
  as the section footnote; the `guidance` line as selectable `Text` when unsupported; a
  disclosure listing per-service rows from the last `proxy.system.status` is optional
  (left to the builder). The launch toggle and bypass field apply on "Apply and Restart
  Core" (`canApply` already covers edits; extend its dirty check to the two new keys).
- **Test:** app target; proven by Task 31 (the Settings toggle is one of its steps) and
  Task 25's unit for the emitted block. Sandbox syntax check.
- **Done when:** owner's build clean; Task 31 step "Settings toggle" passes.

### Task 28: app — Status card fact, nudge, first-run sheet, menu

- **Satisfies:** D13 "First-run sheet", "No-traffic nudge", "Menu", "Getting started"
  (the Kit half is Task 24); the allow-list half of SP-AC24.
- **Depends on:** Task 26.
- **Files:** `apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` (Core card renders
  `summary.systemProxy` under its detail: text, remedy, its actions through `run(_:)`
  which routes `.setSystemProxy`/`.unsetSystemProxy` to `session.setSystemProxy()` /
  `session.restoreSystemProxy()`; the nudge banner), `apps/mac/Sources/Aitmproxy/Shell/SystemProxySheet.swift`
  (create: the first-run sheet view and the nudge banner view),
  `apps/mac/Sources/Aitmproxy/Shell/ShellToolbar.swift` (the Proxy switch's on-flip
  presents the sheet under the §D13 conditions; a `@State` on the shell), `apps/mac/Sources/Aitmproxy/App.swift`
  (menu item), `apps/mac/Sources/AitmproxyKit/CommandMap.swift` (entry
  `E("Proxy", "Set as / Restore System Proxy", "⌥⌘P", items: toggle(["Set as System Proxy", "Restore System Proxy"], "⌥⌘P"))`).
- **Change:** Sheet (`SystemProxySheet`): title "Set aitmproxy as the system proxy?";
  checklist, verbatim: "Route every proxy-aware app through aitmproxy", "Remember and
  restore your previous proxy setting", "Revert automatically if the app quits or
  crashes"; footnote `ConnectionSummary.systemProxyLaneSentence`; `Toggle("Don't ask again")`
  → `Store.defaults` `systemProxy.promptSuppressed`; buttons "Set as System Proxy"
  (`.keyboardShortcut(.defaultAction)`; sets `systemProxy.auto = true` AND calls
  `session.setSystemProxy()`; the caption under it reads exactly "Also turns on “Set
  system proxy at launch” in Settings ▸ Proxy") and "Not Now". Shown once per install
  (`systemProxy.sheetShown`) when the embedded core reaches `.ready`, the bus is operator,
  the fact is not at us, `systemProxy.auto` is off and not suppressed; also on the
  toolbar Proxy switch flip to on under the same conditions. Nudge: on launches where
  the sheet did not show, flows == 0 for 30 s after `.ready`, fact not at us, not
  setting, supported, not suppressed → a non-modal banner on the Status page and the
  flows list header: "No flows yet? Set aitmproxy as the system proxy so Safari and
  other apps use it." with "Set as System Proxy", "Not Now", `Toggle("Don't ask again")`;
  at most once per launch. Menu: in `CommandMenu("Proxy")`, directly above
  mac-attribution's "Network Settings…" in the group after the first `Divider()`,
  `Button(atUs ? "Restore System Proxy" : "Set as System Proxy") { … }`
  `.keyboardShortcut("p", modifiers: [.command, .option])`
  `.disabled(!session.systemProxyControlLive)`; palette entry via `CommandMap`.
  The views spell no lane words; they read `summary.systemProxy.text`.
- **Test:** `CommandMapTests` (existing) must still pass with the new entry; Task 29's
  tripwire pins the call sites; Task 31 proves the press.
- **Done when:** owner's build clean; `tools/check-connection-words.sh` exits 0; Task 29 passes.

### Task 29: tripwire — `tools/check-sysproxy-operator-only.sh`

- **Satisfies:** SP-AC24.
- **Depends on:** Tasks 26, 27, 28.
- **Files:** `apps/mac/tools/check-sysproxy-operator-only.sh` (create, executable).
- **Change:** the shape of `check-capture-operator-only.sh` (`scan`, `expect`, `deny`,
  the self-check): rule 1 — the literals `"proxy.system.set"` and `"proxy.system.unset"`
  appear only in `Sources/Aitmproxy/Session+SystemProxy.swift` (with `expect` lines for both);
  rule 2 — `setSystemProxy()` / `restoreSystemProxy()` are called only from
  `SettingsView.swift`, `Panels/StatusPanel.swift`, `Shell/ShellToolbar.swift`,
  `Shell/SystemProxySheet.swift`, `App.swift` (each with an `expect`); rule 3 — the
  agent-reachable surfaces (`Bus/BusService.swift`, `AitmproxyKit/CommandMap.swift` is
  allowed to carry the TITLE but not the verb or the method names, `Shell/CommandPalette.swift`,
  `Session+Palette.swift`, `Session+Verbs.swift`, `Panels/AgentPanel.swift`,
  `AitmproxyKit/Fixtures+Agent.swift`, `AitmproxyKit/Fixtures+Tools.swift`) match none of
  `proxy\.system\.|setSystemProxy|restoreSystemProxy|systemProxy\.auto`; rule 4 — the
  `systemProxy.auto` key is written in `SettingsView.swift` and `Shell/SystemProxySheet.swift`
  only, read in `Bus/EmbeddedCore.swift`. Self-check: `--self-check` copies the tree to
  `$TMPDIR`, plants `let _ = "proxy.system.set"` in `Session+Verbs.swift`, runs itself
  on the copy and expects exit 1.
- **Test** (SP-AC24): `tools/check-sysproxy-operator-only.sh` exits 0 and prints `PASS`;
  `tools/check-sysproxy-operator-only.sh --self-check` prints the planted violation and
  `SELF-CHECK PASS`; `tools/check-connection-words.sh` exits 0. All three outputs quoted.
- **Done when:** the three runs are quoted in the Coder's report.

### Task 30: Kit test for the facts' fallback (CFNetwork read vs verb)

- **Satisfies:** D1 (the verb's answer wins).
- **Depends on:** Task 24.
- **Files:** `apps/mac/Tests/AitmproxyKitTests/ConnectionSummaryTests.swift` (add one test).
- **Test:** `verbFactsWinOverTheCFNetworkRead`: `make(systemProxy: SystemProxyFacts(state: .pointsAtUs, managedByUs: true, …))`
  → `systemProxy?.text == "system proxy → this core"`; with `managedByUs: nil` (the
  CFNetwork-only shape) → the same text (no "· set outside the app" suffix); with
  `managedByUs: false` → `"system proxy → this core · set outside the app"`.
- **Done when:** owner's `swift test` green. (Small enough to fold into Task 24 if the
  same Coder does both; listed separately so it is not forgotten.)

### Task 31: live proof, mac app (SP-AC20, SP-AC21 with the dev bundle)

- **Satisfies:** SP-AC20, SP-AC21 (app path).
- **Depends on:** Tasks 24–29.
- **Terminal panel script shape:** Task 14's step 0 (record + trap, where the trap runs
  `networksetup` restore lines generated from `before.services`), then
  `cd apps/mac && DEV_TAG=sp CORE_DIR=<repo>/target/release tools/snap-dev.sh none`;
  `APP_STORE=/tmp/sp-store /tmp/Aitmproxy-dev-sp.app/Contents/MacOS/Aitmproxy-sp &`;
  wait for the Core card to read "running"; the first-run sheet appears (new store):
  press "Set as System Proxy"; `scutil --proxy | tee $T/app-set.scutil` (HTTPPort = the
  embedded core's port, shown in the Core card); load a page in Safari → flows appear in
  the app (state it in the PR body); the Core card reads "system proxy → this core";
  `cat` the state file's `previous` (path from `proxy.system.status` in the Core card's
  Status, or `~/Library/Application Support/aitmproxy/system-proxy-state.json` for the
  embedded core's config dir) and compare with `before.services`; Settings ▸ Proxy toggle
  off then on (two more `scutil --proxy` lines); ⌘Q → `scutil --proxy | tee $T/app-quit.scutil`;
  `diff before.scutil app-quit.scutil && echo RESTORED-ON-QUIT`. Then relaunch, set, and
  `kill -9 $(pgrep -f 'Aitmproxy-sp.*Contents/MacOS/aitm' | head -1)` (the embedded core
  pid, from the Core card or `pgrep -P <app pid>`; never a global `pkill`); within 3 s
  `scutil --proxy` equals before, the state file is gone, and
  `system-proxy-watchdog.log` holds a `restored` line. Quote all dumps and the log line;
  confirm no token in the quoted text.
- **Done when:** the PR body holds before, after-set, after-quit, after-kill dumps, the
  `previous` comparison, the Safari-flows statement and the watchdog line.

---

## PR 5 — CA trust (spec §D17, SP-AC29 … SP-AC38)

**Branch:** `feat/ca-trust-first-run`, cut from `main` after PR 1 merges (the core tasks
touch `crates/aitm-ca` only and share no file with PR 1–4). **WAIT** per group: the
mac tasks after mac-attribution's PR lands `CATrustFacts.init?(status:)`,
`CAStatus.trustedScope`/`trustReported`, the `.caTrusted` step and the Core-lane CA row
in `ConnectionSummary.swift`, and after PR 4 Task 28 lands `Shell/SystemProxySheet.swift`;
the TUI task after PR 2 (it appends to the same `toolbar` line); the web task after PR 3
(same pill). **Task 41 (live proof) runs only after Matt explicitly says the CA may be
trusted on his Mac** (spec D17.14, open question 6); until then nobody runs `ca.install`
on his machine by any path.

Order: {Task 32 (owner probe), Task 33, Task 35, Task 36, Task 42} in parallel →
Task 34 (needs 32 for the literals and 33 for `commands.rs`) → Task 37 (Kit, after
mac-attribution) → Task 38 → Task 39 (after PR 4 Task 28) → Task 40 → Task 41 (gated).

### Task 32: read-only probe — which macOS trust read-back works outside the sandbox

- **Satisfies:** the "probe" step of D17.3; fixes the literals SP-AC31 asserts.
- **Depends on:** none. Owner-run in the Terminal panel on Matt's Mac. **Read-only:
  nothing is installed, no keychain or trust setting is modified.**
- **Files:** none in the tree; the quoted output and the decision go into this task's
  "Result" line below (the orchestrator edits it) and into Task 34's dispatch.
- **Terminal panel script shape:**
  ```
  set -u; T=/tmp/claude/ca-probe; mkdir -p $T
  cargo build --release -p aitm
  CA=$(./target/release/aitm ca status | python3 -c 'import json,sys;print(json.load(sys.stdin)["path"])')   # the real ca.crt path; prints no token
  security find-certificate -c "Apple Root CA" -p /System/Library/Keychains/SystemRootCertificates.keychain > $T/apple-root.pem
  security verify-cert -c $T/apple-root.pem -l -L -p ssl; echo "apple-root exit=$?"        # expected: 0 + "...certificate verification successful."
  security verify-cert -c "$CA" -l -L -p ssl; echo "aitm-ca exit=$?"                        # expected: non-zero (not trusted today)
  security verify-cert -c "$CA" -l -L -p basic; echo "aitm-ca basic exit=$?"
  security trust-settings-export $T/user.plist; echo "export exit=$?"; grep -c '<key>' $T/user.plist; grep -m3 -A1 'trustList' $T/user.plist
  security dump-trust-settings; echo "dump exit=$?"
  ```
- **Decision table:** apple-root exit 0 with the success line **and** aitm-ca non-zero →
  **`verify-cert`** is the read-back (SP-AC31's first reading; quote both stdout/stderr
  lines as the literals). Otherwise, if `trust-settings-export` exits 0 and the plist
  has a `trustList` dict → **`trust-settings-export`** (SP-AC31's second reading; quote
  one key to settle whether keys are SHA-1 hex). Neither → stop; the Architect
  re-opens D17.3. Note whether any command showed a dialog (none is expected: all are
  reads).
- **Result:** _(orchestrator fills: tool chosen, the quoted lines, date)_
- **Done when:** the Result line is filled and Task 34's dispatch names the tool.

### Task 33: core — `Frontend::Operator` passes the `ca.install`/`ca.uninstall` agent gate

- **Satisfies:** SP-AC29, SP-AC30; D17.1, D17.2.
- **Depends on:** none.
- **Files:** `crates/aitm-ca/src/commands.rs` (modify the gate in `Change::invoke` and
  its doc comment, the `scope` param description, `Op::refusal` unchanged),
  `crates/aitm-ca/tests/commands.rs` (add tests).
- **Change:** the condition
  `frontend != Frontend::Cli && !args.dry_run && !shared.cfg.allow_agent_install`
  becomes `frontend == Frontend::Mcp && !args.dry_run && !shared.cfg.allow_agent_install`;
  the module doc's "Policy gate" sentence and the `schema` description say "Refused
  from an agent frontend (MCP) unless ca.allow_agent_install is set; the CLI and an
  operator-token connection (a present human) are not gated" — the `refusal()` text
  stays byte-identical (a test pins it). The `scope` param description becomes
  "user | system. Default: user on macOS and Windows (the login keychain / CurrentUser
  store; the OS shows its own authentication dialog), system on Linux (needs root)."
  No other behaviour changes.
- **Test** (`tests/commands.rs`, using the file's `h.call(name, frontend, args)` harness
  on a scripted macOS executor with `find-certificate` answering absent and
  `add-trusted-cert` exit 0):
  - `operator_install_passes_the_agent_gate` (SP-AC29): `h.call("ca.install", Frontend::Operator, &[])`
    is `Ok`, `changed == true`, `scope == "user"`, the executor's `runs()` contain
    `security add-trusted-cert -r trustRoot -p ssl -p basic -k <home>/Library/Keychains/login.keychain-db /ca/ca.crt`,
    and the audit record has `frontend == "operator"`, `outcome == "ok"`.
  - `mcp_install_is_still_refused_without_the_flag`: `Frontend::Mcp` → `Err` whose text
    starts with `ca.install refused` and `runs()` is empty (extend the existing test if
    one already asserts this); `Frontend::Mcp` with `dry_run: true` → `Ok`.
  - `scope_resolution_per_platform` (SP-AC30): macOS, no scope → result `scope == "user"`;
    macOS `scope: "user"` → `"user"`; Debian platform with `scope: "user"` → `Err` text
    `Linux has no per-user OS trust store; use --scope system`; Debian, no scope →
    `scope == "system"`; no rendered macOS user-scope line starts with `sudo`.
- **Done when:** the three tests are green and quoted, red first; gate green.

### Task 34: core — macOS trust read-back and the `Cancelled` kind

- **Satisfies:** SP-AC31, SP-AC32; D17.3, D17.4.
- **Depends on:** Task 32 (the tool and its literals), Task 33 (same `commands.rs`).
- **Files:** `crates/aitm-ca/src/platform/macos.rs` (modify), `crates/aitm-ca/src/store.rs`
  (add `TrustErrorKind::Cancelled`), `crates/aitm-ca/src/commands.rs` (`kind_name`
  yields `"cancelled"` for it: map via `format!("{:?}", kind).to_lowercase()` for this
  variant or a match arm; do not change the other names), `crates/aitm-ca/tests/macos.rs`
  (modify `status_present_absent_sha1_only` and
  `status_present_detail_names_unconfirmed_trust`, add tests).
- **Change** (`macos.rs`), with `verify-cert` chosen by Task 32:
  ```rust
  const VERIFY_SUCCESS: &str = "certificate verification successful";   // substring of stdout on exit 0 (Task 32's literal)
  const CANCEL_MARKER: &str = "cancel";                                   // case-insensitive, stderr
  const CANCELLED_MESSAGE: &str = "ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted";
  const DETAIL: &str = "macOS: presence from `security find-certificate`; trust from `security verify-cert` (ssl policy, local only)";
  impl Op<'_> {
      /// `security verify-cert -c <cert> -l -L -p ssl`, never sudo. `Yes` on exit 0 with
      /// VERIFY_SUCCESS in stdout; `No` on a non-zero exit (stderr tail returned for detail);
      /// `Err` only when the tool could not run (→ the caller reports `Trust::Unknown`).
      fn verify_trust(&mut self) -> Result<(Trust, Option<String>), TrustError>;
  }
  ```
  `status`: presence as today; when `Present`, `trusted` and an optional detail line
  come from `verify_trust` (`Err` → `Trust::Unknown` + the error text in `detail`);
  when `Absent`/`Unknown`, `trusted = Trust::No` with no verify run (`Unknown`
  presence keeps `Trust::Unknown`). `PRESENT_TRUST_UNCONFIRMED` is deleted.
  `install`: after a failed `add-trusted-cert`, classify before the rollback:
  headless markers → `HeadlessAuth` (as today); else stderr contains `CANCEL_MARKER`
  (case-insensitive) → `Cancelled` with `CANCELLED_MESSAGE` as the message head (the
  rollback suffix "; removed the untrusted copy it left behind" / "; an untrusted copy
  may remain in the keychain" is appended exactly as today); else `ToolFailed`.
  If Task 32 chose `trust-settings-export`, `verify_trust` instead runs
  `security trust-settings-export <tmp>` with the executor's real fs (a temp file under
  `std::env::temp_dir()`, removed after), parses the plist text for a `trustList` entry
  keyed by `cert.sha1_hex_upper()` (fallback: an `issuerName` `<data>` equal to the
  base64 of the subject DER), and treats an entry with empty `trustSettings` or no
  `kSecTrustSettingsResult` of `3` as `Yes`; the DETAIL line names
  `security trust-settings-export`.
- **Test** (`tests/macos.rs`, scripted executor; the literals below are replaced by
  Task 32's quoted ones):
  - `status_reads_trust_with_verify_cert` (SP-AC31): present + `security verify-cert -c /ca/ca.crt -l -L -p ssl`
    exit 0 stdout `/ca/ca.crt: certificate verification successful.` → `trusted == Trust::Yes`,
    `runs()` ends with that line; present + exit 1 stderr `/ca/ca.crt: certificate verification failed.`
    → `Trust::No` and `detail` contains the stderr; absent → `Trust::No` and no `verify-cert`
    run; present + verify unspawnable → `Trust::Unknown` and `detail` contains the failure
    text; every `detail` contains `` trust from `security verify-cert` ``.
  - `install_cancelled_is_calm_and_rolls_back` (SP-AC32): `add-trusted-cert` exit 1
    stderr `SecTrustSettingsSetTrustSettings: The authorization was canceled by the user.`,
    requery present, `delete-certificate` exit 0 → `Err` with `kind_of(&e) == TrustErrorKind::Cancelled`
    and `e.to_string() == "ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted; removed the untrusted copy it left behind"`;
    the runs contain `security delete-certificate -Z <sha256> <K_USER>`; the headless
    stderr still yields `HeadlessAuth` (`install_headless_rolls_back` unchanged).
  - `ca_status_json_reports_user_trust_yes` (`tests/commands.rs` or `tests/macos.rs`):
    through the plugin, `stores.user.trusted == "yes"` with the scripted success, and
    `kind_name` → `"cancelled"` surfaces in the `warn!` test if one exists (else skip).
  - Update the two existing status tests: their `assert_eq!(st.trusted, Trust::Unknown)`
    lines become `Trust::No` (absent) / the scripted answer (present); the `detail`
    assertion in `status_present_detail_names_unconfirmed_trust` becomes the new
    `DETAIL` text and the test is renamed `status_present_detail_names_the_trust_check`.
- **Done when:** red → green quoted for each new test; the full `aitm-ca` suite green;
  gate green.

### Task 35: TUI — `· CA trusted` / `· CA untrusted` pill word and `scope: user`

- **Satisfies:** SP-AC35; D17.11.
- **Depends on:** PR 2 merged (the pill line); independent of PR 5's core tasks (an
  older core answers `unknown` → no word).
- **Files:** `crates/aitm-tui/src/model.rs` (add `CaTrustWord`), `crates/aitm-tui/src/app.rs`
  (connect-time `ca.status` request where `self.tools = tools` lands; `ca_installing: bool`;
  the scope default in the `CONFIRM_TOOLS` path; the cancelled toast),
  `crates/aitm-tui/src/ui/bars.rs` (append the word after the sys-proxy word). Never
  `crates/aitm-tui/src/fixture.rs`.
- **Change:**
  ```rust
  // model.rs
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub struct CaTrustWord { pub platform: String, pub trusted: Option<bool> }   // None = every store unknown, or no stores
  impl CaTrustWord {
      pub fn from_json(v: &Value) -> Option<Self>;                 // None unless `exists` is a bool (the ca.status shape)
      pub fn pill(&self, in_flight: bool) -> Option<String>;        // "· CA trusting…" | "· CA trusted" | "· CA untrusted" | None
      pub fn default_scope(&self) -> Option<&'static str>;          // Some("user") for "macos" | "windows", None otherwise
  }
  // app.rs
  pub ca_installing: bool,
  pub fn ca_trust_word(&self) -> Option<String>;                   // from `ca_status` + `ca_installing`
  ```
  `run_command`/the `y` confirm for `ca.install`/`ca.uninstall`: when the parsed args
  (the existing `key=value` parser) carry no `scope` and `CaTrustWord::default_scope()`
  is `Some`, insert `"scope": "user"`; set `ca_installing = true` until the reply; a
  reply error whose text starts with `ca.install cancelled` is a `Level::Info` toast
  "CA trust cancelled". On connect, after `self.tools = tools`, push a `ca.status`
  request when `has_tool("ca.status")`.
- **Test:** `model.rs`: `ca_trust_word_parses_and_renders` — the `ca.status` JSON of
  SP-AC36 → `pill(false) == Some("· CA trusted")`; `trusted: "no"` → `Some("· CA untrusted")`;
  all `"unknown"` → `None`; `pill(true) == Some("· CA trusting…")`; `default_scope()`
  is `Some("user")` for `macos`, `None` for `linux-debian`. `app.rs` tests beside
  `ca_panel_shows_status_and_exports` (SP-AC35): with `ca_status` set to the macOS JSON,
  `run_command("ca.install")` then `y` yields one `BusRequest::Call { name: "ca.install", args }`
  with `args["scope"] == "user"`; with the Debian JSON, `args` has no `scope`;
  `run_command("ca.install scope=system")` keeps `"system"`; the connect path with
  `ca.status` in the tool list yields exactly one `ca.status` request.
  `tests/sysproxy_pill.rs` (PR 2's) gains `pill_shows_the_ca_word`: `"… · sys-proxy → us · CA untrusted"`.
- **Done when:** tests green and quoted; gate green in the sandbox and once in the Terminal.

### Task 36: web — `state/caTrust.ts`, pill word, "Trust the aitmproxy CA" setup action

- **Satisfies:** SP-AC36; D17.12.
- **Depends on:** PR 3 merged (the pill). Independent of the core tasks.
- **Files:** `apps/web/src/state/caTrust.ts` (create), `apps/web/src/state/caTrust.test.ts`
  (create), `apps/web/src/bus/types.ts` (add `CAStatusWire`), `apps/web/src/state/app.ts`
  (`ca: CATrustStatus | null`, `caInstalling: boolean`, `refreshCA()` after the tools
  bootstrap when `ca.status` exists and after any `ca.install`/`ca.uninstall` call
  completes), `apps/web/src/palette/groups.ts` (`SetupAction` gains `args?: Record<string, unknown>`),
  `apps/web/src/palette/CommandPalette.tsx` (pass `item.action.args` as the form's
  initial args when `item.action.tool` is selected), `apps/web/src/palette/setup.ts`
  (relabel + args), `apps/web/src/shell/Toolbar.tsx` (append the word). Never
  `apps/web/src/bus/mock.ts` / `noise.ts`.
- **Change:**
  ```ts
  // caTrust.ts
  export interface CATrustStatus { trusted: boolean; scope: 'user' | 'system' | null; platform: string; fingerprint: string | null; }
  export function parseCATrust(v: unknown): CATrustStatus | null;        // null when not the ca.status shape OR every store is 'unknown'
  export function caPillWord(s: CATrustStatus | null, inFlight: boolean): string | null;   // '· CA trusting…' | '· CA trusted' | '· CA untrusted' | null
  export function caInstallArgs(s: CATrustStatus | null): Record<string, unknown>;          // { scope: 'user' } for macos|windows, {} otherwise
  export function isCACancelled(message: string): boolean;                                   // startsWith('ca.install cancelled')
  ```
  `setup.ts`: `{ id: 'install-ca', label: 'Trust the aitmproxy CA', hint: 'Install the root CA into your user trust store; HTTPS is not captured until then', icon: 'lock', tool: 'ca.install', args: caInstallArgs(app.ca) }`;
  the palette `run` for `ca.install`/`ca.uninstall` sets `caInstalling`, then calls
  `app.refreshCA()`; a rejected call whose message `isCACancelled` is `app.notice(msg, 'info')`.
  `Toolbar.tsx`: after the sys-proxy word, `caPillWord(app.ca, app.caInstalling)`.
- **Test** (`caTrust.test.ts`, SP-AC36 verbatim): the eleven assertions listed there;
  `palette/groups.test.ts` and `setup` tests updated for the new label (`'Install CA'`
  → `'Trust the aitmproxy CA'` where asserted); `npm test` and `npm run build` green.
- **Done when:** tests green and quoted; build green.

### Task 37: mac Kit — `ConnectionAction.trustCA` / `.openCAPanel`, actions on the CA row and step, `caQuicCaveat`

- **Satisfies:** SP-AC33 (PR 5's half); D17.6 actions, D17.7, D17.9.
- **Depends on:** mac-attribution's PR merged (`CATrustFacts`, `CAStatus.trustedScope`,
  the `.caTrusted` step, the CA row on the Core lane).
- **Files:** `apps/mac/Sources/AitmproxyKit/ConnectionSummary.swift` (modify),
  `apps/mac/Tests/AitmproxyKitTests/ConnectionSummaryTests.swift` (add one test).
- **Change:**
  ```swift
  public enum ConnectionAction { …, case trustCA, openCAPanel }
  // titles: .trustCA → "Trust the aitmproxy CA"; .openCAPanel → "Certificate Authority…"
  public static let caQuicCaveat = "HTTPS apps that use QUIC are not captured until the CA is trusted; browsers fall back to TCP once it is."
  ```
  In mac-attribution's CA row: trusted → `actions: [.openCAPanel]`; not trusted →
  `[.trustCA, .openCAPanel]`; installing → `[]`; needs an administrator → `[.openCAPanel]`.
  In `steps`: the `.caTrusted` step's `action` is `.trustCA` when not trusted, `.openCAPanel`
  when the facts are `nil` (title "CA trust unknown — open the Certificate Authority
  panel") or need an administrator, `nil` when done. No other text changes (their words
  stand).
- **Test:** `caTrustActionsAndStepButton` exactly as SP-AC33 lists it (nine `#expect`s);
  `actionTitlesAreTitleCaseWithEllipsesWhereAViewOpens` still passes with the two new
  cases (`.openCAPanel` ends with an ellipsis, `.trustCA` does not).
- **Done when:** owner's `swift test` green with the new test; `tools/check-connection-words.sh`
  exits 0.

### Task 38: mac app — `Session+CATrust.swift`, the one call path; CAPanel routes through it

- **Satisfies:** D17.1, D17.4, D17.5, D17.10; the allow-list half of SP-AC34.
- **Depends on:** Task 37.
- **Files:** `apps/mac/Sources/Aitmproxy/Session+CATrust.swift` (create),
  `apps/mac/Sources/Aitmproxy/Session.swift` (`var caTrustInstalling = false`; feed it
  into `CATrustFacts.installing` where the facts are built), `apps/mac/Sources/Aitmproxy/Session+Connection.swift`
  (`perform(connection:)`: `.trustCA` → `return false`; `.openCAPanel` → `show(.ca)`,
  `return true`), `apps/mac/Sources/Aitmproxy/Panels/CAPanel.swift` (modify `change(install:status:)`).
- **Change:**
  ```swift
  extension Session {
      /// The only home of "ca.install": scope user on macOS/Windows, confirm-token re-call,
      /// `caTrustInstalling` for the duration, a `ca.install cancelled` error is silent,
      /// and the facts come from the forced `ca.status` re-read, never from the reply.
      func trustCA() async
      func untrustCA() async        // "ca.uninstall", same scope rule and re-read
      var caTrustControlLive: Bool  // bus connected as operator && !caTrustInstalling
      static func caScopeArgs(platform: String) -> [String: JSONValue]   // ["scope": .string("user")] for "macos"/"windows", [:] otherwise — pure, for the tripwire's `.string("user")` expectation
  }
  ```
  The forced re-read calls the same `ca.status` entry mac-attribution's poll uses (their
  refresh method on `Session`; if it is private, make it internal in this task and say so).
  `CAPanel.change(install:status:)` keeps its `NSAlert`, then calls `session.trustCA()` /
  `session.untrustCA()` and reloads from `session`'s facts; the hard-coded "Install
  finished but the CA is not trusted in the login keychain yet…" line is replaced by the
  facts' `remedy` shown only when the re-read says not trusted; the status block gains
  `ConnectionSummary.caQuicCaveat` as a footnote. Errors other than cancelled keep the
  panel's `actionError` path.
- **Test:** app target — sandbox `swiftc -parse`; proven by Task 40's tripwire and
  Task 41's live run.
- **Done when:** `swiftc -parse` clean; owner's build clean; Task 40 passes.

### Task 39: mac app — the sheet's CA row, Status routing, menu, Settings footnote

- **Satisfies:** D17.7, D17.8, D17.9 (the view half), D17.10 menu; the allow-list half
  of SP-AC34.
- **Depends on:** Task 38; PR 4 Task 28 merged (`Shell/SystemProxySheet.swift` exists).
- **Files:** `apps/mac/Sources/Aitmproxy/Shell/SystemProxySheet.swift` (modify),
  `apps/mac/Sources/Aitmproxy/Shell/ShellToolbar.swift` (widen the show-condition),
  `apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` (`run(_:)`: `.trustCA` →
  `Task { await session.trustCA() }`; `.openCAPanel` is handled by `perform`),
  `apps/mac/Sources/Aitmproxy/App.swift` (Proxy menu: `Button("Trust the aitmproxy CA") { Task { await session.trustCA() } }.disabled(!session.caTrustControlLive || trusted)`
  directly above the "Set as / Restore System Proxy" item), `apps/mac/Sources/AitmproxyKit/CommandMap.swift`
  (entry `E("Proxy", "Trust the aitmproxy CA", <free shortcut>)`), `apps/mac/Sources/Aitmproxy/SettingsView.swift`
  (Proxy tab: `ConnectionSummary.caQuicCaveat` as a footnote line under the lane sentence).
- **Change (sheet):** title "Set up aitmproxy on this Mac"; row 1 "Trust the aitmproxy
  CA": the CA fact's text from `summary.caTrust` (or the step title when the facts are
  `nil`), `PrimaryButton("Trust the aitmproxy CA") { Task { await session.trustCA() } }`
  hidden when trusted, disabled while installing (the text then reads "trusting CA…"),
  `ConnectionSummary.caQuicCaveat` under it; row 2 = Task 28's checklist, caption and
  "Set as System Proxy" button unchanged. Dismiss button "Not Now", retitled "Done"
  when the CA is trusted and the system proxy points at us. Show-condition: Task 28's
  **or** (`summary.caTrust != nil && !trusted`) under the same operator/ready/suppressed
  guards; the two `Store.defaults` keys are reused. The sheet performs no `NSAlert`
  before `trustCA()` (D17.8). The views spell no lane words beyond the button titles
  (`ConnectionAction.trustCA.title`); the facts' text comes from the summary.
- **Test:** `CommandMapTests` still pass with the new entry; Task 40's tripwire pins the
  call sites; Task 41 proves the press.
- **Done when:** owner's build clean; `tools/check-connection-words.sh` exits 0; Task 40 passes.

### Task 40: tripwire — `apps/mac/tools/check-ca-trust-path.sh`

- **Satisfies:** SP-AC34.
- **Depends on:** Tasks 38, 39.
- **Files:** `apps/mac/tools/check-ca-trust-path.sh` (create, executable).
- **Change:** the shape of `check-capture-operator-only.sh` (`scan`, `expect`, `deny`,
  `--self-check`): rule 1 — the literals `"ca.install"` and `"ca.uninstall"` appear only
  in `Sources/Aitmproxy/Session+CATrust.swift` (two `expect` lines); rule 2 — `trustCA(`
  and `untrustCA(` are called only from `Panels/CAPanel.swift`, `Shell/SystemProxySheet.swift`,
  `Panels/StatusPanel.swift`, `App.swift` (each with an `expect`); rule 3 —
  `Session+CATrust.swift` contains `.string("user")` (`expect`) and does not contain
  `"system"` (`deny`); rule 4 — the agent-reachable surfaces of SP-AC24's rule 3
  (`Bus/BusService.swift`, `AitmproxyKit/CommandMap.swift` title-only, `Shell/CommandPalette.swift`,
  `Session+Palette.swift`, `Session+Verbs.swift`, `Panels/AgentPanel.swift`,
  `AitmproxyKit/Fixtures+Agent.swift`, `AitmproxyKit/Fixtures+Tools.swift`) match none
  of `ca\.install|ca\.uninstall|trustCA|untrustCA`, with a file-level allow for a fixture
  tool list that still names `ca.install` if the fake-data-removal PR has not deleted it
  (the Coder checks and records which). `--self-check` copies the tree to `$TMPDIR`,
  plants `let _ = "ca.install"` in `Session+Verbs.swift`, expects exit 1.
- **Test:** `tools/check-ca-trust-path.sh` prints `PASS`, exit 0; `--self-check` prints
  the planted violation and `SELF-CHECK PASS`; `tools/check-connection-words.sh` exits 0.
  All three outputs quoted.
- **Done when:** the three runs are quoted in the Coder's report.

### Task 41: live proof, macOS (SP-AC37) and TUI/web (SP-AC38) — gated on Matt's go

- **Satisfies:** SP-AC37, SP-AC38; D17.14, D17.15 (the dialog question).
- **Depends on:** Tasks 33–40 merged into the branch; a release build; **Matt's
  explicit go** recorded in this task's "Go" line below. Without it the task does not
  run and the PR says so.
- **Go:** _(orchestrator fills: Matt's words, date)_
- **Files:** none in the tree. Output goes into the PR body.
- **Terminal panel script shape** (owner, Matt's real shell):
  ```
  set -u; T=/tmp/claude/ca-proof; mkdir -p $T
  L=~/Library/Keychains/login.keychain-db; S=/Library/Keychains/System.keychain
  q() { echo "== $1"; security find-certificate -a -c aitmproxy -Z "$2" | grep -E 'SHA-256|keychain' ; echo "(exit $?)"; }
  q login-before $L | tee $T/before-login.txt; q system-before $S | tee $T/before-system.txt     # both expected empty
  # dev bundle, fresh store (the sheet shows); Core card "running"
  cd apps/mac && DEV_TAG=ca CORE_DIR=<repo>/target/release tools/snap-dev.sh none; cd -
  APP_STORE=/tmp/ca-store /tmp/Aitmproxy-dev-ca.app/Contents/MacOS/Aitmproxy-ca > $T/app.log 2>&1 &
  # 1. the sheet's row 1 reads "HTTPS is not captured until the CA is trusted". Press "Trust the aitmproxy CA"; in the macOS dialog press CANCEL once.
  #    Expect: the row word unchanged, no error toast; the core log (Core Log… panel, or $T/app.log) has a warn line with kind=cancelled — copy its stderr text into $T/cancel.txt
  # 2. Press again; authenticate. Expect: the row and the Status checklist read "CA trusted (user keychain)".
  q login-after $L | tee $T/after-login.txt; q system-after $S | tee $T/after-system.txt       # login: one SHA-256 block; system: still empty
  ./target/release/aitm --config <dev bundle's config> ca status | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["fingerprint_sha256"].replace(":",""));print(d["stores"]["user"])'   # equals the SHA-256 line; trusted == "yes"
  # 3. Safari → an in-scope HTTPS host Safari has not loaded this session (system proxy at the core per SP-AC20, or All Apps on). Expect ≥ 1 https:// row for that host; note the host and the row's status in the PR body.
  # 4. Certificate Authority panel → "Uninstall…" → Remove. Expect: the word returns to "HTTPS is not captured until the CA is trusted".
  q login-uninstalled $L | tee $T/uninstalled-login.txt; q system-uninstalled $S | tee $T/uninstalled-system.txt   # both empty
  # 5. SP-AC38: once in `aitm tui` (:ca, i, y; then u) and once in `aitm web` (palette "Trust the aitmproxy CA"), repeating q before/after each; the pill word flips to "· CA trusted" and back; the core's debug log line for ca.install shows scope=user.
  grep -c "$(python3 -c 'import yaml,sys;print(yaml.safe_load(open(sys.argv[1]))["mcp"]["transport"]["loopback_tcp"]["token"])' <config>)" $T/*.txt   # must print 0 for every file
  ```
  If step 2 ends in `HeadlessAuth` instead of a dialog (D17.15), stop, quote the core's
  warn line, and report; the follow-up spec is then opened and the row word is verified
  to read "CA trust needs an administrator".
- **Done when:** the PR body holds the six `q` dumps, the `ca status` lines, the cancel
  stderr text, the Safari row statement, the TUI and web before/after pairs, and the
  `0` token count; the System keychain dumps are all empty.

### Task 42: operator docs — the CA step, the operator gate, the Linux limitation

- **Satisfies:** D17.7, D17.13 (documentation), the `ca.allow_agent_install` wording after
  D17.2.
- **Depends on:** none (prose; names the shipped behaviour).
- **Files:** `docs/design/operator-ui-foundation.md` (the one non-research doc that
  documents `allow_agent_install` today) and the operator config reference Task 13 used.
- **Change:** `ca.allow_agent_install` is described as gating **agents (MCP)** only — "the
  CLI and operator-token frontends (mac app, TUI, web) install after their own
  confirmation and the OS dialog"; a "First run on macOS" paragraph: Trust the
  aitmproxy CA (login keychain, macOS asks for your password) then Set as System
  Proxy, the D17.7 QUIC sentence verbatim, "trust state is read back from the keychain
  with `security verify-cert`" (or the Task 32 tool); a "Linux" paragraph: the trust
  store needs root, so the app/TUI/web show "CA trust needs an administrator" and
  `aitm ca install` from a terminal is the way, with the polkit and NSS follow-ups named
  as not yet done.
- **Test:** none (prose); the Coder quotes `git diff --stat`.
- **Done when:** the text matches the shipped strings exactly.

---

## Independent task sets (fan-out)

- **PR 1:** {Task 1} → **{Tasks 2, 3, 4, 5, 12} in parallel** (disjoint files) →
  {Task 7} (after 4; may overlap 2, 3, 5, 12) → {Task 6} → {Task 8} → {Task 9} →
  **{Tasks 10, 11} in parallel** → {Task 13} → {Tasks 14, 15} (live; 14 and 15 are
  independent of each other).
- **PR 2:** {Task 16} → {Task 17} → {Task 18} → {Task 19}. Sequential (shared `app.rs`).
- **PR 3:** {Task 20} → {Task 21} → {Task 22} → {Task 23}. Sequential.
- **PR 4:** **{Tasks 24, 25} in parallel** → {Task 26} → **{Tasks 27, 28, 30} in parallel**
  (27: SettingsView + EmbeddedCore; 28: StatusPanel + SystemProxySheet + ShellToolbar +
  App + CommandMap; 30: tests only) → {Task 29} → {Task 31}.
- **PR 5:** **{Tasks 32, 33, 35, 36, 42} in parallel** (32 owner-run read-only probe;
  33 `aitm-ca` commands; 35 TUI; 36 web; 42 docs — disjoint files) → {Task 34} (after
  32 and 33) → {Task 37} (Kit, after mac-attribution's PR) → {Task 38} → {Task 39}
  (after PR 4 Task 28) → {Task 40} → {Task 41} (gated on Matt's go). Tasks 33–34 are
  independent of 35–36 and of 37–40 (no shared file).

Task counts: PR 1 = 15 (Tasks 1–15), PR 2 = 4 (16–19), PR 3 = 4 (20–23), PR 4 = 8 (24–31),
PR 5 = 11 (32–42).

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 17 | security, quality, tester (PR 2) | Minor | no client-side guard against a second `s`/`:sysproxy` while a change is in flight; the core's refusal clears the flag for the first call | fixed in F-tui (guard + Warn toast "system proxy change already in flight") |
| 18 | security (PR 2) | Minor | `toolbar` sums four `u16` widths with plain `+`; an unbounded host could overflow in debug builds | fixed in F-tui (saturating / usize arithmetic) |
| 17 | quality (PR 2) | Minor | `"points_at_us"` literal compared in `app.rs` as well as `model.rs` | fixed in F-tui (`SystemProxyWord::points_at_us()`) |
| 17 | quality, spec (PR 2) | Minor | set/unset reply re-reads `detail` from raw JSON; `sysproxy_detail` falls back to `"<verb>: ok"` (not a spec string); `:sysproxy status` reply does not update the word | fixed in F-tui: the status reply updates the word when it parses; fallback kept and recorded (TUI-only string, only reachable on a malformed reply, pinned by the tester) |
| 18 | quality (PR 2) | Minor | `toolbar_hints_yield_to_the_pill_word` depends on ambient text widths; `palette_lists_the_sysproxy_command` asserts the const; palette description casing | fixed in F-tui (long-host + wide-width assertions, named constants; the tester's driven palette test covers the render); casing → "Set / restore the OS system proxy (s)" |
| 18 | spec (PR 2) | Minor | Task 18 edited `src/app.rs` (the plan named `ui/complete.rs`, which never held `BUILTIN_COMMANDS`); toolbar hints yield when the pill word would clip (beyond "append the word"); help box 36→37 rows | recorded: plan error on the file; the yield is required for the §D12 word to render whole at the plan's 160-col test width; accepted by the orchestrator in Matt's name |
| 17 | spec (PR 2) | Minor | set/unset reply keeps the previous word when the reply is not a status object (plan said replace unconditionally) | accepted (recorded): robustness reading; unreachable with a conforming core |
| tester (PR 2) | tester | Minor | `keys::flows()` ignores `ctrl` for plain letters so Ctrl-S also toggles (pre-existing convention); the help `:` list shows only the first 14 commands so `sysproxy` appears on the key line, not the list | recorded; no change |
| F-tui (PR 2) | quality+security+spec (PR 2, re-run on b44f498a) | Important | the F-tui in-flight guard had no reset on bus `Connected`/`Disconnected`: a dropped reply left `sysproxy_setting` up and locked `s` / `:sysproxy on|off` out for the rest of the run | fixed (F-tui 6): `App::forget_inflight()` (run on `Connected`/`Disconnected`) clears the flag with the browser and CA in-flight state; test `a_reconnect_drops_the_in_flight_flag_so_the_guard_lets_the_retry_through` |
| F-tui (PR 2) | security (PR 2, re-run) | Minor | the raw `:proxy.system.set|unset` and the palette's tool list bypassed the guard and did not raise the flag (a refusal could settle the wrong flight) | fixed (F-tui 7): `App::sysproxy_begin_change()` is the one guard, used by the `sysproxy` arm and `call_tool`; test `the_raw_verb_path_shares_the_in_flight_guard` |
| F-tui (PR 2) | quality (PR 2, re-run) | Minor | `toolbar_at`/`toolbar_text` duplicated across two test files; `PILL_GUTTER` doc said "each side" while two uses take it as the total gap; TUI and core spelled the in-flight refusal differently | fixed: `toolbar_at` lives in `tests/common/mod.rs`; doc reworded (arithmetic unchanged); the TUI toast is the core's exact sentence "a system-proxy change is already in flight" |
| F-tui (PR 2) | spec (PR 2, re-run) | Minor | plan Task 18 still spelled the old palette literal; Task 17 did not mention the status reply refreshing the word; the core-flag half of the guard can refuse on a `setting` up to 5 s stale | plan Tasks 17/18 amended (dated); the 5 s staleness recorded, no code change (self-heals on the next poll) |
| 19 (PR 2) | live proof (SP-AC27 TUI half) | — | run 1 (11:27 PST) flipped and restored the proxy but the pty had a 0×0 window (crossterm sizes by TIOCGWINSZ) so no text was drawn; run 2 (11:30:14–11:30:33 PST) with the window set: pill `off` → `setting…` → `→ us` → `setting…` → `off`, `scutil` HTTP/HTTPS 28080 while set, before == after, state file gone, token leak 0, a real CONNECT (api.apple-cloudkit.com, out of scope) rode through the proxy during the window | done 2026-11-01 on Matt's "Yes, both"; dumps in PR #258 |
| 16 | coder (stop-on-gap) | Minor | Task 16 declared only `model.rs`, but `ProxyStatus` is built with exhaustive struct literals in `src/app.rs` (test helper), `tests/core_sync.rs`, `tests/common/mod.rs`; adding `system_proxy` there is required to compile | file list extended to those three one-line edits, orchestrator 2026-11-01 |
| 24 (PR 4a) | quality (re-run) | Minor | `Endpoint.address` rendered a bare IPv6 host its own parser rejects; `settingsPort` truncated a fractional port where the wire path rejects | fixed in the follow-up commit (bracketed on render; `Int(exactly:)`) |
| 24 (PR 4a) | quality (re-run) | Minor | a second definition of "loopback spelling" beside `EmbeddedCoreLaunch.isLoopbackHost` | accepted (recorded) with a cross-reference comment; the two callers have different stakes (dial guard vs display match) |
| 24 (PR 4a) | quality | Important | `init?(compact:)` took `[String: Any]` and truncated ports; the Kit decodes bus objects as `JSONValue` with exact ints | fixed in c8ed92f4 |
| 24 (PR 4a) | spec | Important | `other` reported at our own listen address routed `.thisCore` (§D6 partial case) | fixed in c8ed92f4 (nil = unknown); spec §D13 paragraph states the rule |
| 24 (PR 4a) | spec | Important | spec §D13 / plan Task 24 / sibling plan Task 1 described an enum and claimed to create the files | docs amended in c5d30c99; sibling plan Files lines to be updated by the attribution session (text sent) |
| 24 (PR 4a) | quality, spec | Minor | bare IPv6 literal parsed as host:port; brackets whitelisted not stripped; parameterisation; Hashable test; private statics; one init form | fixed in c8ed92f4 |
| 24 (PR 4a) | spec | Minor | fields are `let` where the sibling contract said `var`; numeric-string port accepted on the wire; port range 1…65535 | accepted (recorded) by the orchestrator under Matt's mandate 2026-11-01: immutability is the better design; the leniencies are honest tightenings/widenings of §D6 |
| 24 (PR 4a) | quality | Minor | `settingsPort` truncates a Double port in the CFNetwork dictionary; `Endpoint(address: "[]:8080")` yields host `[]` (matches nothing) | accepted (recorded): CFNetwork returns integers; harmless |
| 7 | quality (F4) | Minor | `decide` rustdoc misstates the call graph; the `else { return 0 }` after `decide(Some(..))` is unreachable | accepted (recorded), orchestrator 2026-10-31; fold into the scaffolding follow-up (reword doc or `unreachable!`) |
| crate | quality (F4) | Minor | rustdoc intra-doc links to `pub(crate)` items (not gated) | accepted (recorded); `#![allow(rustdoc::private_intra_doc_links)]` or plain backticks in the follow-up |
| 10 | quality (F4) | Minor | config-path resolution spelled in both `main` and `run` | accepted (recorded); `Invocation::config_path()` in the follow-up |
| 4 | quality (re-run) | Important | two state-file tests compare against a `StateFile::new` stamped after the save (`saved_at` second boundary) — gate flaky (2/4 runs) | fixed in F4 56adfbe0 (expected built once before the save) |
| 6 | quality (re-run) | Minor | idempotent `set` reports `services` minus authenticated rows (Q4 side effect) | fixed in F4 56adfbe0 (`Snapshot.rows`) |
| 6 | quality (re-run) | Minor | `target_os: String` not fixed in F3 as recorded; residual `merge_bypass(&defaults(), …)` spelling | fixed in F4 56adfbe0 (`is_windows: bool`, `bypass_for(&[], …)`) |
| 10 | quality (re-run) | Minor | `OperatorToken` and the watchdog dispatched in two places; leftover `Mode::SysproxyWatchdog` arm | fixed in F4 56adfbe0 (both dispatched before the runtime) |
| 7 | quality (re-run) | Minor | `decide`/`Decision` has no production caller after Q5 | fixed in F4 56adfbe0 (`run_after_wake` routes through `decide`) |
| tests | quality (re-run) | Minor | test helper named `status_with` shadows the engine method; `err_text` wrapper; three fake-PATH helpers | first two fixed in F4 56adfbe0; helpers under the accepted scaffolding follow-up |
| tester (re-run) | tester | Minor | F3 claimed FIFO quarantine, single recovery log line and `service_names`≡`rows_of` without tests; S3 hit path only | closed by the tester's tests in b786b352 |
| 8 | spec (re-run) | Important | `proxy.system.status` 2 s cache for non-trusted callers (S3) had no spec sentence | spec §D6 + §D2 amended 2026-10-31; no code change |
| 3 | security (re-run) | Minor | a KDE tool absent at detection keeps its bare name and is spawned by PATH if it appears later | accepted (recorded), orchestrator 2026-10-31: same-privilege residual; the error message naming the tool is worth more |
| 6 | spec (re-run) | Minor | `Status::to_map` and `endpoints_equal_wrote` are `pub` | fixed in F4 56adfbe0 (`pub(crate)`) |
| 1 | spec (re-run) | Minor | plan Task 1 still spelled `NeedsPrivilege(String)`; §D2 PATH clause half-stale after S2 | plan annotated, spec §D2 amended 2026-10-31 |
| 14 (live) | owner | Important | First macOS live run: `auto` startup set ran before the port bind; port 18080 was held by another session's aitm, the core set the proxy then died; watchdog restored in ~1 s | fixed in 13f5809e (F2: `bind_then_recover_system_proxy`, test `port_conflict_never_sets_the_system_proxy`) |
| 6 | spec | Important | `status()` returned `off`/`other` from scutil when no network service is enabled; §D3 says `Unknown` + "no enabled network service" | fixed in F3 (5ac8fcce) |
| 6 | quality | Important | `read_status` swallowed the per-service read error; `managed_by_us: false` with no log and no reason | fixed in F3 (5ac8fcce) |
| F1 | spec | Important | `merge_previous` (re-set keeps the file's previous rows for services still ours) implemented without a spec sentence | spec §D6 amended 2026-10-31 (one sentence, recorded here); code kept |
| 6 | spec | Important | Task 6 touched `platform/{mod,macos,linux,windows}.rs` and `watchdog.rs` outside its declared `lib.rs`, reshaping the trait (`snapshot` added, `detail_when_unsupported`/`equals_wrote` dropped) | process deviation recorded; the orchestrator had authorised those files in the dispatch (gap resolutions 1–7); plan Task 1 signature block annotated |
| 4, 7 | security | Minor | state file / watchdog log opened through symlinks with a predictable temp name; `load` would block on a FIFO | fixed in F3 5ac8fcce (`create_new`, `symlink_metadata` quarantine) |
| 3 | security | Minor | KDE tools and `dbus-send` spawned by bare name on PATH | fixed in F3 5ac8fcce (resolved to absolute paths at detection) |
| 8 | security | Minor | `proxy.system.status` uncached and agent-reachable (process storm) | fixed in F3 5ac8fcce (2 s cache for non-trusted callers) |
| 10 | quality, spec | Minor | startup/exit recovery logged twice (engine + main.rs) | fixed in F3 5ac8fcce (`log_recovery` keeps only the `Failed` warn) |
| 2, 3, 6 | quality | Minor | §D5 bypass union assembled in three places | fixed in F3 5ac8fcce (`bypass_for`) |
| 2 | quality | Minor | `NeedsPrivilege(String)` carries two payloads | fixed in F3 5ac8fcce (`NeedsPrivilege { line }`) |
| 6 | quality | Minor | re-set reads every service three times | fixed in F3 5ac8fcce (idempotency from the snapshot rows) |
| 7 | quality | Minor | watchdog double load, unreachable arm, silent outcome for a file naming no service | fixed in F3 5ac8fcce (`left-alone services=0` line) |
| 4 | quality | Minor | `service_names` and `rows_of` encode the same partition | fixed in F3 (5ac8fcce) |
| 3 | quality | Minor | Linux `write` accepts a mismatched `Previous` kind | fixed in F3 (5ac8fcce) |
| various | quality | Minor | idioms: fabricated ServiceRow in `light_summary`, `target_os: String`, unreachable `object()` arm, `strings` duplicate, `ops_for` vs `Detected::ops`, watchdog dispatched inside the runtime, 5-tuple from the pre-bind helper | fixed in F3 (5ac8fcce) |
| tests | quality | Minor | scripted-macOS test scaffolding copied into six test modules | accepted as follow-up (a `testing` module), orchestrator 2026-10-31 under Matt's mandate |
| 6 | quality | Minor | `set`/`unset` return 3-tuples instead of outcome structs | accepted by plan (Task 6 specified the tuples); revisit before PR 2–4 consume them |
| 8 | spec | Minor | `summarize` spells `1240 ms`, spec said `1 240 ms` | spec aligned to the plan/code 2026-10-31 |
| 5, 9, 13 | spec | Minor | `Cargo.lock` touched by Tasks 5/9 (mechanical); Task 5 tests in `src/config_file.rs` not `tests/config_file.rs`; Task 13 edited README.md as well as the design doc | accepted (recorded), orchestrator 2026-10-31 |
| 1, 6, 8 | spec | Minor | unrequested public surface (`Mechanism::as_str`, `Display for Endpoint`, several `pub const`s, `SystemProxy::mechanism()/ours()`); quarantine name gains `-n` on collision | consts made `pub(crate)` in F3 where no external test needs them; the rest, plus `SystemProxy::status_cached()`/`state_file()` (spec F4 check), accepted (recorded) |
| spec | spec | Minor | §D5 "operator-critical hosts" added by the orchestrator after approval | flagged to Matt for countersign (wrap-up); frontends PR 2–4 depend on it |
| tester | tester | Minor | watchdog wrote no log line for a file naming no service; IPv6 literal unbracketed in guidance | first fixed in F3 (Q5); second accepted (spec says "the IP literal"; `ours_from` maps loopback/unspecified to 127.0.0.1) |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.

Follow-ups already known from the spec: a Plasma VM proof for the KDE mechanism
(unit-tested only in this milestone); the privileged helper (`SMAppService`) for standard
users and the "Require an administrator password" Mac; Windows (`platform/windows.rs` is
a seam); PAC/WPAD/SOCKS left alone by design. From the D17 addendum: an in-process
`SecTrustSettingsSetTrustSettings` path in the mac app if the embedded core's `security`
child cannot surface the macOS dialog (D17.15); a polkit/`pkexec` prompt and the
Firefox/Chromium NSS user databases on Linux (D17.13, research first).
