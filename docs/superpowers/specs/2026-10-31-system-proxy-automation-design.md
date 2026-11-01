# System proxy automation design

**Status:** approved (2026-10-31, self-approved by the system-proxy session under Matt's standing mandate; the three provisional answers below are flagged to Matt in the session wrap-up and he may overturn any of them)
**Research inputs:** `docs/research/16-system-proxy.md` (primary),
`docs/research/22-macos-system-proxy-toggle.md` (on branch
`claude/apps-attribution-8ab619`, pending; its §5b agrees with the live facts),
`docs/research/07-ca-install.md` (the Executor/shell-out pattern this reuses),
`docs/superpowers/specs/2026-10-31-macos-status-page-and-first-run-design.md`
(`ConnectionSummary`, the one home for connection words), and the session note
`system-proxy-live-facts.md` (Matt's Mac, 2026-10-31 16:32–16:40: admin user,
`networksetup` writes with no root and no dialog; both services carry
Proxyman's `127.0.0.1:9090`).

## Intent

The installed macOS app shows an empty flow list because the Mac's system proxy
is off: Safari and every proxy-honouring app bypass `127.0.0.1:8080`. Matt:
"those things should happen automatically in the app", "I should not have to do
anything in the command line", "if I need to use something as root you should
trigger the right permission" (the OS's own dialog, never a `sudo` line).
Proxyman is the reference for the flow ("Set as system proxy", remember and
restore the previous setting, revert if the app quits or crashes), not for its
chrome. This spec puts one implementation of that in the core, behind three bus
verbs, and gives each frontend the same honest word for what the system proxy
points at right now.

## Goals

- One switch, in every frontend, that makes the OS send every proxy-aware app's
  HTTP and HTTPS traffic through the running core, with no terminal step.
- A read-back that reports what the OS *effectively* uses, never what we last
  wrote: `off`, `points_at_us`, `other(host, port)`, `unsupported`,
  `needs_privilege`, `unknown`.
- The previous setting is saved before the first write and restored on unset,
  on every orderly exit, after a crash (a detached user-level watchdog), and at
  the next start if all else failed.
- A bypass list that keeps loopback and local tooling out of the proxy by
  default and lets the operator add their own hosts.
- Linux desktops (GNOME/XFCE via `gsettings`, KDE via `kwriteconfig`) with no
  privilege; a headless shell gets the exact `export http_proxy=…` line instead
  of a false success.
- An agent can never change the system proxy, under any policy.

## Non-goals

- A privileged helper (`SMAppService` root daemon). It is the documented
  follow-up for standard users, the "Require an administrator password" Mac,
  `SCPreferences` speed, and a root-daemon revert; it is not in this spec.
- Windows. One seam paragraph (§D11), nothing shipped.
- PAC files, auto-discovery (WPAD), SOCKS, authenticated proxies: not written;
  a PAC or discovery setting that is already on is recorded in `detail` and
  left alone.
- Changes to the Network Extension, its scope gate, or per-app proxying.
- Capturing `localhost` targets through the system proxy (Chrome and macOS skip
  loopback regardless; research 16 §3.1.9). The browser lane covers that.
- Live change notifications from `SCDynamicStore` (the mac app already reads
  `CFNetworkCopySystemProxySettings` once per poll; the core polls on demand).

## Anti-goals

- A green word that lies: "system proxy → this core" while the effective proxy
  is off, `127.0.0.1:9090`, or unknown because the read failed.
- Two vocabularies. One word table (§D12) feeds the mac app, the TUI and the web.
- An agent that can flip the proxy, even under `Ask`, even once.
- A `sudo` line, an `osascript … with administrator privileges`, or a
  hand-typed command anywhere in the product's UI text or code path.
- A proxy left pointing at a dead port with no named catcher for that failure.
- A set that overwrites another tool's setting without recording it, or an unset
  that "restores" over a setting the operator changed after us.

## Constraints

- Workspace `unsafe_code = "forbid"`: no SystemConfiguration FFI, no `libc`.
  Shell-outs only, through `aitm_ca::exec::Executor`. Process liveness and
  detachment use only safe `std` APIs (`std::process`, `CommandExt::process_group`).
- Every platform module compiles on every host and is unit-tested with
  `ScriptedExecutor` output; only detection consults the target OS and env.
- Three contract pins change in the same commit as the verbs:
  `crates/aitm/tests/frontends.rs` `EXPECTED_TOOLS`,
  `crates/aitm-tui/src/lib.rs` `CORE_TOOLS`, and
  `crates/aitm-tui/fixtures/bus-fixture.json` *if that file still exists when
  the task runs* (a separate session is deleting fixture/mock modes). Nothing in
  this spec depends on a fixture.
- Operator-only tripwire: `proxy.system.set` and `proxy.system.unset` are added
  to `is_operator_only` in `crates/aitm-mcp/src/server.rs` and are **not** added
  to `defers_to_command_gate`; the commands also refuse `Frontend::Mcp`
  themselves. Both layers are tested.
- **Evidence rule (Matt, verbatim intent):** FIXTURE, SNAPSHOT, SELF-TEST,
  MOCK-BUS OR TUI-FIXTURE RUNS ARE NEVER EVIDENCE AND NEVER A REGRESSION GATE
  FOR ANY FRONTEND. Accepted evidence: Rust/Kit unit tests of pure logic
  (scripted executors, parsers, state-file round trips, watchdog decision
  logic), source tripwires, and the real frontend against a real core on a real
  machine with before/after `scutil --proxy` (macOS) or `gsettings get`
  (Linux, Lima VM `cis-lab`). Matt's real system proxy is changed only in that
  final proof, recording and restoring whatever is there (Proxyman's
  `127.0.0.1:9090` today) in the same script. No bus token is ever printed.
- File ownership and PR order (orchestrator): PR 1 core (new crate, `wire.rs`,
  `main.rs`, `config_file.rs`, `control.rs`, docs; `is_operator_only` and the
  three pins rebase onto PR #200's SHA); PR 2 TUI and PR 3 web after the
  fake-data-removal and l4-parity PRs (never touch
  `crates/aitm-tui/src/fixture.rs`, `apps/web/src/bus/mock.ts`,
  `apps/web/src/bus/noise.ts`); PR 4 mac after PR 1 and the mac
  fake-data-removal PR; `ConnectionSummary.swift` only after mac-attribution's
  PR lands `SystemProxyState`; `Bus/BusService.swift` only after S-041.
- Operator-first-run hygiene: quiet logs at the info baseline (one line per
  set/unset/restore), command lines at `debug`, never a token.
- The verbs block for as long as the shell-outs take (Proxyman: "works, but
  slow"). Every frontend shows "setting…" while its call is in flight; no
  frontend's bus timeout for these two verbs may be under 30 s.

## Design

### D1. Shape: one core implementation, three verbs, three thin frontends

Decided. All OS logic lives in a new crate `crates/aitm-sysproxy`. The core
registers `proxy.system.status` (`Sensitivity::Read`), `proxy.system.set` and
`proxy.system.unset` (`Sensitivity::Sensitive`, operator-only). The mac app,
the TUI and the web UI call the verbs and render the words in §D12; none of
them touches the OS. The one exception is the mac app's existing *read* of
`CFNetworkCopySystemProxySettings` (mac-attribution's `SystemProxyState`), which
this spec consumes for the lane word between polls; the verb's answer wins
whenever both are present and disagree **(Architect's call)**, because the
verb's view carries `managed_by_us` and `setting`.

### D2. The `aitm-sysproxy` crate: public surface

Module layout: `lib.rs` (types, `SystemProxy`), `state.rs` (the state file),
`platform/{mod,macos,linux,windows}.rs`, `watchdog.rs`, `plugin.rs` (the three
`Command`s), `config.rs` (`SystemProxyConfig`). Dependencies: `aitm-core`,
`aitm-ca` (for `exec::{CmdLine, CmdOutput, Executor, RealExecutor}` and, as a
dev-dependency, `testing::ScriptedExecutor`), `serde`, `serde_json`, `time`,
`anyhow`, `tracing`.

```rust
pub enum Mechanism { Networksetup, Gsettings, Kde, None }
pub enum State { Off, PointsAtUs, Other { host: String, port: u16 }, Unsupported, NeedsPrivilege, Unknown }
pub struct Endpoint { pub host: String, pub port: u16 }
pub struct ProtocolProxy { pub enabled: bool, pub host: String, pub port: u16 }   // empty host allowed
pub struct ServiceRow { pub service: String, pub http: ProtocolProxy, pub https: ProtocolProxy, pub bypass: Vec<String> }
pub struct Effective { pub http: ProtocolProxy, pub https: ProtocolProxy, pub bypass: Vec<String> }
pub struct Status { /* the fields of §D6, as typed fields */ }
pub struct SetRequest { pub bypass: Vec<String> }
pub struct UnsetOutcome { pub restored: Vec<String>, pub left_alone: Vec<String>, pub status: Status }

pub struct SystemProxy { /* exec, platform ops, state_file, ours, bypass lists, in-flight flag, watchdog handle, cache */ }

impl SystemProxy {
    pub fn detect(exec: Arc<dyn Executor>, cfg: &SystemProxyConfig, ours: Endpoint, watchdog_exe: Option<PathBuf>) -> SystemProxy;
    pub fn detect_with(exec: Arc<dyn Executor>, cfg: &SystemProxyConfig, ours: Endpoint, watchdog_exe: Option<PathBuf>,
                       target_os: &str, env: &dyn Fn(&str) -> Option<String>) -> SystemProxy;   // the testable form
    pub fn status(&self) -> Status;                                  // fresh read: effective + per-service
    pub fn summary(&self) -> Summary;                                // cached (≤ 5 s old) compact view for proxy.status
    pub fn set(&self, req: &SetRequest) -> anyhow::Result<Status>;
    pub fn unset(&self) -> anyhow::Result<UnsetOutcome>;
    pub fn recover_at_startup(&self, auto: bool) -> Recovery;        // §D9 (c)
    pub fn on_orderly_exit(&self) -> Recovery;                       // §D9 (a)
}

pub(crate) trait PlatformOps: Send + Sync {
    fn mechanism(&self) -> Mechanism;
    fn read_effective(&self, exec: &dyn Executor) -> Result<Effective, ReadError>;       // scutil / gsettings get
    fn read_services(&self, exec: &dyn Executor) -> Result<Vec<ServiceRow>, ReadError>;  // networksetup -get* per service; Linux: one synthetic row
    fn write(&self, exec: &dyn Executor, previous: &Previous, ours: &Endpoint, bypass: &[String]) -> Result<Vec<String>, WriteError>;  // returns rendered lines
    fn restore(&self, exec: &dyn Executor, previous: &Previous, only: &[String]) -> Result<Vec<String>, WriteError>;
    fn equals_wrote(&self, live: &[ServiceRow], wrote: &Wrote) -> Vec<(String, bool)>;   // per service
}
```

`WriteError::NeedsPrivilege(remedy)` is produced when a `networksetup` mutation
exits non-zero or prints `** Error: Command requires admin privileges.` on
stdout or stderr; `ReadError::Unavailable` when a read prints
`AuthorizationCreate() failed` or `scutil --proxy` yields an empty dictionary
(the sandbox case): that maps to `State::Unknown`, never `Off`.

Absolute programs, resolved by the crate (`aitm_ca::exec::absolute_program` does
not know them): `/usr/sbin/networksetup`, `/usr/sbin/scutil`,
`/usr/bin/gsettings`; `kwriteconfig6`, `kwriteconfig5`, `kreadconfig6`,
`kreadconfig5`, `dbus-send` by name on `PATH` (a missing one is reported as the
mechanism's tool missing, never as "off"). Timeouts
**(Architect's call)**: `RealExecutor::with_timeouts(10 s, 30 s)`; a write that
takes longer than 30 s is a hang and is reported as an error naming the
rendered command.

### D3. macOS mechanism (`platform/macos.rs`)

Decided. Services: `networksetup -listallnetworkservices`; drop the header line
("An asterisk (*) denotes…") and every line starting with `*`. Zero enabled
services → `State::Unknown` with `detail` "no enabled network service". Per
enabled service, in list order:

| Step | Command (rendered form tests assert on) |
|---|---|
| snapshot | `/usr/sbin/networksetup -getwebproxy <svc>` → `Enabled: Yes\|No`, `Server: <host>`, `Port: <n>`, `Authenticated Proxy Enabled: 0\|1` |
| snapshot | `/usr/sbin/networksetup -getsecurewebproxy <svc>` (same shape) |
| snapshot | `/usr/sbin/networksetup -getproxybypassdomains <svc>` → one domain per line; the literal line `There aren't any bypass domains set on <svc>.` means empty |
| write | `/usr/sbin/networksetup -setwebproxy <svc> 127.0.0.1 8080` (this also enables it) |
| write | `/usr/sbin/networksetup -setsecurewebproxy <svc> 127.0.0.1 8080` |
| write | `/usr/sbin/networksetup -setproxybypassdomains <svc> <d1> <d2> …` (REPLACES the whole list) |
| verify | `/usr/sbin/scutil --proxy` and the two `-get*` reads again; the result is what `Status` reports |

Restore per service (research 16 §3.1.9, `sysproxy` crate precedent): if the
previous host is non-empty, `-setwebproxy <svc> <prev_host> <prev_port>` then
`-setwebproxystate <svc> on|off` to the previous `enabled`; if the previous host
is empty (never configured), only `-setwebproxystate <svc> off` (the endpoint
write with an empty host is unverified and skipped). Same for secure. Then
`-setproxybypassdomains <svc> <previous list…>`, or `-setproxybypassdomains <svc>
Empty` when the previous list was empty. An `Authenticated Proxy Enabled: 1`
service is **not written** and is reported in `detail` as "skipped <svc>:
authenticated proxy" **(Architect's call)**, because its password cannot be
restored.

The host we write is `127.0.0.1` when the configured listen address is loopback
or unspecified (`0.0.0.0`, `::`), otherwise the listen IP literal
**(Architect's call)**. `points_at_us` is true when the *effective* HTTP and
HTTPS proxies are both enabled, both ports equal our listen port, and both hosts
are in {`127.0.0.1`, `localhost`, `::1`, `[::1]`, the literal we write}.

Privilege: a successful write needs no root and no dialog for an admin user
(live fact 1). The failure text `** Error: Command requires admin privileges.`
yields `State::NeedsPrivilege` with this `remedy` **(Architect's call on the
sentence)**: "macOS asks for an administrator to change network settings on
this Mac (a standard user, or “Require an administrator password to access
system-wide settings” is on under System Settings ▸ Privacy & Security ▸
Advanced). Turn that option off or sign in as an administrator, or set HTTP and
HTTPS to 127.0.0.1:8080 under System Settings ▸ Network ▸ <service> ▸ Details ▸
Proxies." No `sudo`, no `osascript`, no retry. `NeedsPrivilege` is only known
after a failed write; it is sticky in `Status` until a later write succeeds.

### D4. Linux mechanisms (`platform/linux.rs`)

Decided mechanism table; detection is pure over (`target_os`, env, tool
presence) and unit-tested:

| Condition (first match) | Mechanism |
|---|---|
| `XDG_CURRENT_DESKTOP` contains `KDE` and `kwriteconfig6` or `kwriteconfig5` is on `PATH` | `Kde` |
| `gsettings` on `PATH` **and** (`DBUS_SESSION_BUS_ADDRESS` set **or** `DISPLAY`/`WAYLAND_DISPLAY` set) | `Gsettings` |
| anything else | `None` → `State::Unsupported` with `guidance` |

`guidance` (literal, with the real host:port): `export
http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080
no_proxy=localhost,127.0.0.1,::1`. It is shown by the frontends as text to
copy, never run.

`Gsettings` writes, in order: `gsettings set org.gnome.system.proxy.http host
'127.0.0.1'`, `… .http port 8080`, `… .https host '127.0.0.1'`, `… .https port
8080`, `gsettings set org.gnome.system.proxy ignore-hosts "['localhost', …]"`,
then `gsettings set org.gnome.system.proxy mode 'manual'` last (the switch).
`org.gnome.system.proxy.http enabled` is "Unused; ignore" and is not touched.
Snapshot and read-back are `gsettings get` of the same six keys, kept as raw
GVariant text and restored verbatim. **gsettings can succeed silently on the
memory backend**: after the writes, the six keys are read back; if any differs
from what was written, the result is `State::Unknown`, `detail` "gsettings did
not persist the change (no dconf session?)", the state file is removed, and
`guidance` is filled.

`Kde` writes `kwriteconfig6|5 --file kioslaverc --group 'Proxy Settings' --key
ProxyType 1`, `httpProxy 'http://127.0.0.1 8080'`, `httpsProxy
'http://127.0.0.1 8080'`, `NoProxyFor 'localhost,127.0.0.1,…'`, then `dbus-send
--type=signal /KIO/Scheduler org.kde.KIO.Scheduler.reparseSlaveConfiguration
string:''`; snapshot via `kreadconfig6|5` of the same four keys; unset writes
them back and `ProxyType 0` if it was absent. On KDE, when `gsettings` is also
present, the gsettings keys are written and snapshotted too (Throne issue 1017:
GTK apps otherwise stay unproxied) **(Architect's call)**. The KDE value format
(`http://host port`, `http://` scheme for both) is from field reports, not a
spec; KDE ships unit-tested only in this milestone (no Plasma machine; see Open
questions).

No privilege is needed anywhere on Linux; `NeedsPrivilege` is never produced
there.

### D5. Bypass list

Decided. On set, the exceptions list written is the ordered, de-duplicated
union: previous list (per service on macOS, the `ignore-hosts` array on Linux)
∪ default ∪ `system_proxy.bypass` from config ∪ `bypass` from the request.
Default literal: `localhost`, `127.0.0.1`, `::1`, `*.local`, `169.254/16`. The
whole previous list is restored on unset. UI copy next to the editable field:
"Hosts that skip the system proxy. Add the hosts your own tools talk to (today's
incident: a tool whose API calls were routed to another proxy)." The macOS
setter replaces the entire list, so the union is computed before the single
write.

### D6. Status model, verb schemas, example payloads

`proxy.system.status` — params: none. Result object (field names are the
contract):

```json
{
  "state": "other",
  "host": "127.0.0.1",
  "port": 9090,
  "detail": "HTTP and HTTPS → 127.0.0.1:9090 (not this core)",
  "ours": { "host": "127.0.0.1", "port": 8080 },
  "mechanism": "networksetup",
  "supported": true,
  "managed_by_us": false,
  "setting": false,
  "effective": {
    "http":  { "enabled": true, "host": "127.0.0.1", "port": 9090 },
    "https": { "enabled": true, "host": "127.0.0.1", "port": 9090 },
    "bypass": ["*.local", "169.254/16"]
  },
  "services": [
    { "service": "Display Ethernet",
      "http":  { "enabled": true, "host": "127.0.0.1", "port": 9090 },
      "https": { "enabled": true, "host": "127.0.0.1", "port": 9090 },
      "bypass": ["*.local", "169.254/16"] },
    { "service": "Wi-Fi", "http": { "...": "..." }, "https": { "...": "..." }, "bypass": ["*.local", "169.254/16"] }
  ],
  "bypass_default": ["localhost", "127.0.0.1", "::1", "*.local", "169.254/16"],
  "guidance": null,
  "remedy": null,
  "last_change_ms": null,
  "watchdog_pid": null,
  "state_file": "/Users/matt/Library/Application Support/aitmproxy/system-proxy-state.json"
}
```

- `state` ∈ `off | points_at_us | other | unsupported | needs_privilege | unknown`.
  `host`/`port` are present only for `other` (the effective HTTP endpoint, or
  the HTTPS one when HTTP is off). A partial state (one protocol at us, the
  other off or elsewhere) is `other` with `detail` saying which, e.g. "HTTP →
  127.0.0.1:8080, HTTPS off".
- `managed_by_us`: the state file exists **and** every service it lists still
  reads back equal to what we wrote (Linux: the written keys read back equal).
- `setting`: a set/unset is in flight in this process (another client's call).
- `mechanism` ∈ `networksetup | gsettings | kde | none`; `supported` = mechanism
  ≠ `none`.
- `guidance` is the env-var line when `state == "unsupported"`, else null.
- `remedy` is the privilege sentence when `state == "needs_privilege"`, else null.
- `last_change_ms`: wall-clock milliseconds of the last successful set or
  unset's write phase in this process, else null.
- `watchdog_pid`: the live watchdog's pid when `managed_by_us`, else null.
- `services` is empty on Linux and when the read failed.

`proxy.system.set` — params: `bypass: Array(Str)` (optional, default `[]`).
Result: the status object above plus `"changed": true|false` and `"commands":
[rendered lines]`. Idempotent: when the effective state already `points_at_us`
and the state file exists → `changed: false`, no writes, `commands: []`. When it
`points_at_us` with **no** state file (set by hand or by another instance), the
verb snapshots and writes anyway so that a file exists and restore is possible
(`changed: true`). Errors (`anyhow::Err`, so the frontends show the message):
the executor could not start a tool or timed out; a second change already in
flight ("a system-proxy change is already in flight"); the call came from a
process that is not serving (`listening == false`, see §D10); or a partial
write that could not be rolled back (the message names the state file).
`needs_privilege` and `unsupported` are **not** errors: they return `Ok` with
the state and its `remedy`/`guidance`.

`proxy.system.unset` — params: none. Result: the status object plus
`"changed"`, `"commands"`, `"restored": ["Wi-Fi", …]` and `"left_alone":
["Display Ethernet", …]`. The rule, decided: compare per service (Linux: per
key set). A service that still equals what we wrote is restored from the file;
a service that no longer does (another tool took over) is left exactly as it is
and listed in `left_alone`; the state file is removed either way; the watchdog
sees the file gone and exits. With no state file, unset is a no-op
(`changed: false`) and the status says why in `detail` ("not managed by this
core; nothing to restore").

`proxy.status` gains one compact sub-object **(Architect's call)**, refreshed
on demand when older than 5 s (one `scutil --proxy` / six `gsettings get`, no
per-service reads), and immediately after set/unset:

```json
"system_proxy": { "state": "points_at_us", "host": null, "port": null,
                  "managed_by_us": true, "setting": false, "supported": true,
                  "detail": "HTTP and HTTPS → 127.0.0.1:8080 (this core)" }
```

The TUI and the web read this (they already poll `proxy.status`); the mac app
reads it too and keeps `CFNetworkCopySystemProxySettings` as its between-poll
source. When `mechanism == none` the sub-object is present with
`state: "unsupported"` and no shell-out ever runs.

`summarize` for the two mutating verbs: `"system proxy → 127.0.0.1:8080 (2
services, 1 240 ms)"` / `"system proxy restored → 127.0.0.1:9090 (2 services,
980 ms)"`.

### D7. Config block and the state file

Config, a top-level section parsed in `crates/aitm/src/config_file.rs` exactly
like `macos_capture` (maps straight onto `aitm_sysproxy::SystemProxyConfig`,
`#[serde(default, deny_unknown_fields)]`, lives outside `aitm_core::Config`)
**(Architect's call)**:

```yaml
system_proxy:
  auto: false            # set at startup, restore at exit (frontends: "Set system proxy at launch")
  bypass: []             # operator's extra bypass hosts, merged per §D5
  state_file: ~          # default: <dir of ca.audit_log>/system-proxy-state.json
```

The default state-file path is the sibling of the CA audit log
(`CaConfig::audit_log.with_file_name("system-proxy-state.json")`), so it
follows the same directory rule and fallbacks. It is written with mode `0600`,
atomically (temp file + rename), **before the first mutating command**, and
removed only by an orderly unset, a completed restore, or the "another tool
owns it" rule.

```json
{
  "version": 1,
  "platform": "macos",
  "mechanism": "networksetup",
  "saved_at": "2026-10-31T17:02:11Z",
  "pid": 48213,
  "wrote": { "host": "127.0.0.1", "port": 8080,
             "bypass": ["*.local", "169.254/16", "localhost", "127.0.0.1", "::1"] },
  "previous": {
    "kind": "networksetup",
    "services": [
      { "service": "Display Ethernet",
        "http":  { "enabled": true, "host": "127.0.0.1", "port": 9090 },
        "https": { "enabled": true, "host": "127.0.0.1", "port": 9090 },
        "bypass": ["*.local", "169.254/16"] },
      { "service": "Wi-Fi",
        "http":  { "enabled": false, "host": "", "port": 0 },
        "https": { "enabled": false, "host": "", "port": 0 },
        "bypass": ["*.local", "169.254/16"] }
    ]
  }
}
```

Linux `previous` variants: `{ "kind": "gsettings", "keys": { "org.gnome.system.proxy mode": "'none'", "org.gnome.system.proxy.http host": "''", "org.gnome.system.proxy.http port": "8080", "org.gnome.system.proxy.https host": "''", "org.gnome.system.proxy.https port": "0", "org.gnome.system.proxy ignore-hosts": "['localhost', '127.0.0.0/8', '::1']" } }`
and `{ "kind": "kde", "kioslaverc": { "ProxyType": "0", "httpProxy": "", "httpsProxy": "", "NoProxyFor": "" }, "gsettings": { … } | null }`.
An unreadable or `version != 1` file is renamed to `<file>.corrupt-<timestamp>`
and treated as absent (logged at `warn`).

### D8. Where the instance lives (wiring)

`wire::Features` gains `sysproxy: Option<Arc<SystemProxy>>` (tests inject a
scripted one); `assemble_with` builds `SystemProxy::detect(Arc::new(RealExecutor::with_timeouts(..)),
&settings.system_proxy, ours_from(cfg.listen), std::env::current_exe().ok())`
when `None`, registers `aitm_sysproxy::SysProxyPlugin::new(arc.clone(),
listening.clone())` (the three verbs) after `ControlPlugin`, and hands the same
`Arc` to `ControlPlugin::with_system_proxy(arc)` **(Architect's call: a
builder method, so the existing `ControlPlugin::new` signature and its tests
stand)**. `Assembled.sysproxy: Arc<SystemProxy>` lets `main.rs` call
`recover_at_startup(auto)` before the `select!` and `on_orderly_exit()` after
it. `Settings` gains `system_proxy: SystemProxyConfig`.

### D9. Crash-safe revert: three catchers, each named with the failure it covers

Decided. Each catcher is independent; any one suffices.

**(a) Orderly exit — covers SIGINT, SIGTERM (the mac app's `EmbeddedCoreController`
SIGTERMs with a 5 s grace), and stdin EOF once that exit path exists.** After
`aitm::shutdown_signal()` wins the `select!`, `main.rs` calls
`on_orderly_exit()`: if `managed_by_us`, restore (the §D6 unset rule, per
service) and remove the file, within the exit path and before the browser
reap. This runs **whether or not `auto` is on** (decided here, answering the
brief's open point): the proxy was set for this core's lifetime and a dead port
is never acceptable, so the mac app never needs to call `proxy.system.unset` on
quit. Budget: the restore must complete inside the app's grace; if the live
proof measures more than 5 s on Matt's Mac, the builder raises
`EmbeddedCoreLaunch.childStopGraceSeconds` in PR 4 and (b) still covers the
SIGKILL that follows a timeout.

**(b) Watchdog — covers SIGKILL, a panic/abort, and any death that skips (a).**
On every successful set (and on adoption in (c)), when no watchdog from this
process is alive, the core spawns its own executable as `aitm sysproxy-watchdog
--pid <core pid> --state <state file>` with: its own process group
(`CommandExt::process_group(0)`, so a terminal's SIGINT to the core's group does
not take it), stdout/stderr → null, and **stdin piped from the core, which keeps
the write end open and never writes** **(Architect's call)**: the kernel closes
that pipe on any death of the core, so the watchdog wakes on stdin EOF at once
with no polling and no unsafe code; a 1 s liveness poll (`/bin/ps -p <pid> -o
pid=` on macOS, `/proc/<pid>` on Linux) is the fallback only when the pipe is
absent (`--no-pipe`, used by tests). The subcommand is hidden (not in usage,
never in the CLI registry, parsed in `parse_mode` like `operator-token`). On
wake it re-reads the state file: file gone → exit 0 (an orderly unset beat it);
file present → run the §D6 unset rule with a fresh `RealExecutor` (restore the
services that still equal `wrote`, leave the rest, remove the file) → exit 0;
restore failed → leave the file for (c), exit 3; bad arguments → exit 2. The
watchdog appends one line per decision to `system-proxy-watchdog.log` beside
the state file, truncated when it starts **(Architect's call)**. The decision
function is pure (`watchdog::decide(file: Option<&StateFile>, live:
&[ServiceRow]) -> Decision`) and unit-tested.

**(c) Next-start recovery — covers reboot, power loss, and a watchdog that was
itself killed.** Before serving, `recover_at_startup(auto)`:

| File | Live vs `wrote` | `auto` | Action |
|---|---|---|---|
| absent | — | off | nothing |
| absent | — | on | set |
| present | equal, and `wrote` endpoint == our current endpoint | on | **adopt**: keep the file, update `pid`, spawn a watchdog |
| present | equal | off, or endpoint differs | restore, remove file; then set if `auto` |
| present | not equal (another tool took over) | any | remove file (log the fact); then set if `auto` |

One `info!` line names the outcome (`system proxy: restored previous setting
from <file>` / `adopted` / `another tool owns the system proxy; forgot <file>`).

### D10. Frontend `Cli` and one-shot processes

`aitm proxy system status` and `aitm proxy system unset` work one-shot (the CLI
dispatcher already maps argv to `proxy.system.*`); unset is the recovery tool
for a leftover file. `aitm proxy system set` from a one-shot process is refused
with "proxy.system.set needs a running core: use the app, the TUI or the web UI,
or start aitm with `system_proxy.auto: true`" **(Architect's call)**, because
the process would exit and restore at once and a watchdog on it would be
pointless. The guard is `listening == false`.

### D11. Windows seam (not shipped)

`platform/windows.rs` implements `PlatformOps` with `mechanism() == None` and a
`detail` "Windows system proxy is not managed yet" so every host compiles and
status is honest. The future implementation writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet
Settings` (`ProxyEnable`, `ProxyServer`, `ProxyOverride`) and must notify
WinINET (`INTERNET_OPTION_SETTINGS_CHANGED`, `INTERNET_OPTION_REFRESH`), which
needs a shell-out (`powershell`/`rundll32`) or a tiny FFI crate; neither is
designed here.

### D12. Word table (the only place these strings live)

The mac app renders the "mac fact" column from `ConnectionSummary`; the TUI and
the web render the "pill word" column after the listening address. Same ideas,
one short and one full form; neither invents a third.

| Idea (`state`, `managed_by_us`, `setting`) | mac fact (Core lane, `SystemProxyFact.text`) | state hue | pill word (TUI/web) | actions |
|---|---|---|---|---|
| `points_at_us`, managed | system proxy → this core | ok | `· sys-proxy → us` | Restore System Proxy |
| `points_at_us`, not managed | system proxy → this core · set outside the app | ok | `· sys-proxy → us` | — |
| `other(h,p)` | system proxy → h:p, not this core | warning | `· sys-proxy → h:p` | Set as System Proxy |
| `off` | system proxy off — proxy-aware apps bypass the core | off (calm) | `· sys-proxy off` | Set as System Proxy |
| `needs_privilege` | system proxy needs an administrator | warning (remedy = §D3 sentence) | `· sys-proxy needs admin` | — |
| `unsupported` | system proxy not available here (guidance shown in Settings) | off | nothing | — |
| `unknown` | system proxy unknown | off | nothing | — |
| any, `setting` | setting system proxy… | working | `· sys-proxy setting…` | — (disabled) |

Remedies: `other` → "Another app owns the system proxy. Set as System Proxy
records its setting and restores it on quit."; `off` → "Set as System Proxy so
Safari and other proxy-aware apps use the core." Lane wording that says the two
lanes cover different traffic, verbatim where both appear (Settings ▸ Proxy
footnote, the first-run sheet, the Status page Core card tooltip): "System
proxy → every proxy-aware app, regardless of Scope. All Apps → in-scope hosts of
every app." Button titles: "Set as System Proxy", "Restore System Proxy",
"Not Now".

### D13. macOS app (PR 4)

- **Facts in.** `Session` polls `proxy.status` already; it parses
  `system_proxy` into `SystemProxyFacts { state: SystemProxyState, managedByUs:
  Bool, setting: Bool, supported: Bool, remedy: String?, guidance: String? }`
  (Kit, `Hashable`). `ConnectionSummary.make` gains one parameter
  `systemProxy: SystemProxyFacts?` (nil = no verb on this bus) and one output
  `systemProxy: SystemProxyFact?` (`text`, `state`, `remedy`, `actions`) that
  the Core card renders under its detail; `ConnectionAction` gains
  `.setSystemProxy` ("Set as System Proxy") and `.unsetSystemProxy` ("Restore
  System Proxy") — the case names reserved by mac-attribution. `overall` and the
  pill include the fact's state only when it is `warning` or `working`; `off`
  stays calm. The fact is computed from the verb facts when present, else from
  mac-attribution's `CFNetworkCopySystemProxySettings` read (then
  `managedByUs` is unknown and the text drops the "· set outside the app"
  suffix).
- **Calls out.** A new `Session+SystemProxy.swift` holds the only two call
  sites of `"proxy.system.set"` / `"proxy.system.unset"` (`setSystemProxy()`,
  `restoreSystemProxy()`), marks `setting` locally until the reply, and feeds
  the reply's status into the facts. `Session.perform(connection:)` returns
  `false` for the two actions; the views route them to these entries
  (operator-only, like capture).
- **Settings ▸ Proxy** gains, below the embedded-proxy section: a live toggle
  "Set as system proxy" (position = the fact, never a preference; disabled with
  the reason while `setting`, unsupported, or the bus is not connected as
  operator); a persisted toggle "Set system proxy at launch"
  (`Store.defaults` key `systemProxy.auto`, read by `EmbeddedCore` at spawn
  and emitted as a top-level `system_proxy:\n  auto: true\n` block in the
  per-launch config, like `macos_capture`); an editable "Bypass hosts" field
  (`systemProxy.bypass`, comma/space separated, emitted as `system_proxy.bypass`
  and passed as the `bypass` param on a live set); the §D12 lane sentence and
  the §D5 copy as footnotes; the `guidance` line as selectable text when
  unsupported. The launch toggle and the bypass field apply on Restart Core
  (the existing Apply & Restart rule).
- **First-run sheet** (once per install, `Store.defaults` key
  `systemProxy.sheetShown`): shown when the embedded core reaches `.ready`, the
  bus is connected as operator, the fact is not `points_at_us`, `systemProxy.auto`
  is off, and `systemProxy.promptSuppressed` is false; also when the operator
  flips the toolbar Proxy switch to on under the same conditions. Title "Set
  aitmproxy as the system proxy?"; checklist, verbatim: "Route every proxy-aware
  app through aitmproxy", "Remember and restore your previous proxy setting",
  "Revert automatically if the app quits or crashes"; the §D12 lane sentence as
  a footnote; checkbox "Don't ask again" (sets `systemProxy.promptSuppressed`);
  buttons "Set as System Proxy" (default) and "Not Now". **"Set as System Proxy"
  both sets now and turns on "Set system proxy at launch"** **(Architect's
  call)**, stated under the button ("Also turns on “Set system proxy at launch”
  in Settings ▸ Proxy"), because the core restores on quit and a one-time set
  would be gone at the next launch, which is not "automatically".
- **No-traffic nudge**: on launches where the sheet did not show, when flows
  have stayed 0 for 30 s after `.ready` with the fact not `points_at_us`, not
  `setting`, supported, and not suppressed: a non-modal banner on the Status
  page and the flows list header, "No flows yet? Set aitmproxy as the system
  proxy so Safari and other apps use it.", with "Set as System Proxy", "Not Now"
  and a "Don't ask again" checkbox; at most once per launch.
- **Getting started**: the `.firstFlow` step's undone title becomes "Set
  aitmproxy as the system proxy, or open the browser" (action
  `.setSystemProxy`) when supported and not at us; "System proxy points at
  127.0.0.1:8080 — waiting for the first flow" (action `.openBrowser`) when at
  us; the old "Point a client at …" wording when unsupported or unknown.
- **Menu**: Proxy ▸ "Set as System Proxy" / "Restore System Proxy" (one item,
  title follows the fact; shortcut chosen by the builder from the free set in
  `CommandMap`), palette entry included, both gated like the Settings toggle.
- **Quit**: nothing new. The embedded core's orderly SIGTERM path (§D9 a)
  restores; the watchdog (§D9 b) covers a force-kill.
- **Tripwire**: a new `apps/mac/tools/check-sysproxy-operator-only.sh`, the
  capture script's shape: the two verb strings appear only in
  `Session+SystemProxy.swift`; `setSystemProxy()`/`restoreSystemProxy()` are
  called only from `SettingsView.swift`, `Panels/StatusPanel.swift`,
  `Shell/ShellToolbar.swift` (the sheet), `App.swift` (the menu) and the sheet
  and nudge views; each allow-list entry has an `expect` line; the
  agent-reachable surfaces mention none of it.

### D14. TUI (PR 2)

- `ProxyStatus` (model) gains `system_proxy: Option<SystemProxyWord>` parsed
  from `proxy.status.system_proxy`; the listening pill appends the §D12 pill
  word after the address and before `· intercept armed` / `· capture paused`.
- `:sysproxy on|off|status` in `run_command`, gated on
  `has_tool("proxy.system.set")` (else the toast "System proxy needs the core's
  proxy.system.* verbs"); `on` sends `proxy.system.set {}` (the config bypass
  applies), `off` sends `proxy.system.unset`, `status` toasts the `detail`.
  Key `s` in the main flow list toggles it **(Architect's call; `s` is free in
  `keys.rs`'s main-mode table today; the builder picks another free key and
  records it in the help overlay if `s` is taken when the task runs)**.
- While the call is in flight the pill reads `· sys-proxy setting…`; the reply's
  `detail` (or the error) is a toast; a refusal from an agent-token bus is shown
  verbatim.
- Never touch `crates/aitm-tui/src/fixture.rs`.

### D15. Web (PR 3)

- `proxy.status` polling (already every 2 s) parses `system_proxy` into
  `app.proxy.systemProxy`; the toolbar listening pill appends the §D12 pill word.
- The pill becomes a menu button (like the Agent toggle): a checkbox item "Set
  as system proxy" (checked = `points_at_us`; disabled with a title while
  `setting`, unsupported, or the bus is not operator), a disabled line with
  `detail`, and, when `guidance` is present, a "Copy env line" item.
  Selecting calls `proxy.system.set {}` / `proxy.system.unset`; the pill shows
  `· sys-proxy setting…` until the reply; an error or refusal goes to the status
  bar message slot.
- Never touch `apps/web/src/bus/mock.ts` or `apps/web/src/bus/noise.ts`.

### D16. Logging and audit

One `info!` per set, unset, restore and adoption (target `aitm_sysproxy`:
outcome, service count, ms); every rendered command at `debug!`; no token, no
home-path noise at info. Bus calls land in the agent audit ring as every verb
does; no entry is written to the CA audit log.

## Acceptance criteria

Tags: **[rust-unit]** = `cargo test` with scripted executors or pure functions;
**[kit-unit]** = `swift test` in `AitmproxyKit`; **[tripwire]** = a source
check script or a test that greps/asserts source; **[live]** = a real frontend
against a real core on a real machine, output quoted in the PR. Per the
evidence rule, nothing tagged fixture, snapshot, self-test or mock counts.

1. **SP-AC1 [rust-unit]** `macos::parse_services` on the literal
   `"An asterisk (*) denotes that a network service is disabled.\nDisplay Ethernet\n*Thunderbolt Bridge\nWi-Fi\n"`
   returns `["Display Ethernet", "Wi-Fi"]`.
2. **SP-AC2 [rust-unit]** `macos::parse_get_proxy` on
   `"Enabled: Yes\nServer: 127.0.0.1\nPort: 9090\nAuthenticated Proxy Enabled: 0\n"`
   returns `ProtocolProxy { enabled: true, host: "127.0.0.1", port: 9090 }`; on
   `"Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n"` returns
   `{ enabled: false, host: "", port: 0 }`.
3. **SP-AC3 [rust-unit]** `macos::parse_scutil` on the research 16 §3.2.1 dump
   (HTTP and HTTPS `127.0.0.1:9090`, `ExceptionsList` `*.local`, `169.254/16`)
   yields `Effective` with both enabled at `127.0.0.1:9090` and bypass
   `["*.local", "169.254/16"]`; on `"<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n}\n"`
   both disabled with empty hosts; on `"<dictionary> {\n}\n"` (the sandbox case)
   `Err(ReadError::Unavailable)`, and `status().state == State::Unknown`.
4. **SP-AC4 [rust-unit]** `classify(effective, ours = 127.0.0.1:8080)`: both at
   `127.0.0.1:8080` → `PointsAtUs`; both at `localhost:8080` → `PointsAtUs`;
   both at `127.0.0.1:9090` → `Other { host: "127.0.0.1", port: 9090 }`; HTTP
   at us, HTTPS disabled → `Other { "127.0.0.1", 8080 }` with `detail ==
   "HTTP → 127.0.0.1:8080, HTTPS off"`; both disabled → `Off`.
5. **SP-AC5 [rust-unit]** A scripted macOS set with services `Display Ethernet`
   (previous `127.0.0.1:9090` on, bypass `*.local`, `169.254/16`) and `Wi-Fi`
   (previous off, empty host) and request bypass `["corp.test"]` runs, in this
   order and with these rendered lines: the three `-get*` reads per service
   (`/usr/sbin/networksetup -getwebproxy 'Display Ethernet'`, …), then
   `/usr/sbin/networksetup -setwebproxy 'Display Ethernet' 127.0.0.1 8080`,
   `… -setsecurewebproxy 'Display Ethernet' 127.0.0.1 8080`,
   `… -setproxybypassdomains 'Display Ethernet' *.local 169.254/16 localhost 127.0.0.1 ::1 corp.test`,
   the same three for `Wi-Fi`, then the verify reads. The state file is
   written **before** the first `-set*` line (asserted by the executor's run
   order against a `with_real_fs` temp dir) and round-trips through
   `serde_json` to the §D7 document with `wrote.port == 8080` and
   `previous.services[1].http.host == ""`.
6. **SP-AC6 [rust-unit]** Restore from that file renders
   `/usr/sbin/networksetup -setwebproxy 'Display Ethernet' 127.0.0.1 9090`,
   `… -setwebproxystate 'Display Ethernet' on`, the secure pair, and
   `… -setproxybypassdomains 'Display Ethernet' *.local 169.254/16`; for `Wi-Fi`
   only `… -setwebproxystate Wi-Fi off`, `… -setsecurewebproxystate Wi-Fi off`
   and `… -setproxybypassdomains Wi-Fi *.local 169.254/16` (no endpoint write
   for an empty host); an empty previous list renders `… -setproxybypassdomains
   Wi-Fi Empty`.
7. **SP-AC7 [rust-unit]** Idempotence: with the state file present and both
   services reading back `127.0.0.1:8080` enabled, `set` returns `changed:
   false` and the executor recorded zero mutating lines.
8. **SP-AC8 [rust-unit]** Partial takeover: the file lists both services; live
   `Wi-Fi` still equals `wrote`, live `Display Ethernet` reads `10.0.0.5:3128`.
   `unset` restores only `Wi-Fi`, returns `restored == ["Wi-Fi"]`,
   `left_alone == ["Display Ethernet"]`, runs no `-set*` naming `Display
   Ethernet`, and removes the state file.
9. **SP-AC9 [rust-unit]** A mutating `networksetup` response of exit 1 with
   stdout `** Error: Command requires admin privileges.` yields
   `Ok(Status { state: NeedsPrivilege, remedy: Some(<the §D3 sentence>) })`, no
   further `-set*` lines, no state file left behind, and no rendered line
   anywhere in the crate begins with `sudo` or `osascript` (a test greps the
   crate's source for `"sudo"` and `"osascript"` and expects zero matches
   outside comments and this test).
10. **SP-AC10 [rust-unit]** Linux detection, pure: (`linux`, `XDG_CURRENT_DESKTOP=KDE`,
    `kwriteconfig6` present) → `Kde`; (`linux`, `gsettings` present,
    `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/501/bus`, no `DISPLAY`) →
    `Gsettings` (the `cis-lab` case); (`linux`, `gsettings` present, no bus and
    no display) → `None` with `guidance ==
    "export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080 no_proxy=localhost,127.0.0.1,::1"`;
    (`windows`, anything) → `None`.
11. **SP-AC11 [rust-unit]** A scripted `Gsettings` set renders, in order,
    `/usr/bin/gsettings set org.gnome.system.proxy.http host '127.0.0.1'`,
    `… .http port 8080`, `… .https host '127.0.0.1'`, `… .https port 8080`,
    `… org.gnome.system.proxy ignore-hosts "['localhost', '127.0.0.0/8', '::1', '127.0.0.1', '*.local', '169.254/16']"`
    (previous list first, then the defaults not already present), then
    `… org.gnome.system.proxy mode 'manual'` last; the six `gsettings get`
    reads precede the first `set`; the read-back after the writes is asserted,
    and when the scripted read-back returns `'none'` for `mode` the result is
    `State::Unknown` with `detail` containing `did not persist` and no state
    file left.
12. **SP-AC12 [rust-unit]** A scripted `Kde` set renders the four
    `kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key …` lines
    (`ProxyType 1`, `httpProxy 'http://127.0.0.1 8080'`, `httpsProxy
    'http://127.0.0.1 8080'`, `NoProxyFor …`) followed by the exact `dbus-send
    --type=signal /KIO/Scheduler org.kde.KIO.Scheduler.reparseSlaveConfiguration
    string:''` line; unset writes the four previous values back and sends the
    signal again.
13. **SP-AC13 [rust-unit]** `watchdog::decide`: (`None`, any live) → `Exit0`;
    (`Some(file)`, live equal) → `Restore(all services)`; (`Some(file)`, one
    service differs) → `Restore(the equal ones)` with the other left; the
    binary's `parse_mode` maps `["sysproxy-watchdog", "--pid", "1", "--state", "/x"]`
    to `Mode::SysproxyWatchdog { pid: 1, state: "/x" }`, rejects a missing
    `--state` with exit code 2's usage line, and `aitm --help`/usage output does
    not contain `sysproxy-watchdog`.
14. **SP-AC14 [rust-unit]** `recover_at_startup` follows the §D9 (c) table for
    all five rows (scripted file + live + `auto`), asserting the mutating lines
    (none / set / none-and-file-kept / restore / file removed) and the
    resulting presence of the state file.
15. **SP-AC15 [rust-unit]** `proxy.system.set` invoked with `Frontend::Mcp`
    returns `Err` whose message contains `operator-only`, with zero executor
    runs; invoked with `listening == false` (`Frontend::Cli` one-shot) returns
    `Err` containing `needs a running core`; `proxy.system.unset` and
    `proxy.system.status` succeed one-shot.
16. **SP-AC16 [rust-unit, aitm-mcp]** Under each of `AgentPolicy::All`, `Auto`
    and `Ask`, an agent-role call to `proxy.system.set` and to
    `proxy.system.unset` is **refused, never parked** (`PolicyDecision::Refuse`,
    no entry in the approval hub); `is_operator_only("proxy.system.set")` and
    `is_operator_only("proxy.system.unset")` are `true`;
    `defers_to_command_gate` is `false` for both; `proxy.system.status` is
    allowed under `ReadOnly`.
17. **SP-AC17 [tripwire]** `EXPECTED_TOOLS` in `crates/aitm/tests/frontends.rs`
    and `CORE_TOOLS` in `crates/aitm-tui/src/lib.rs` list the three verbs (the
    array length in `frontends.rs` goes from 58 to 61 plus whatever PR #200
    added); `bus-fixture.json`, if present, lists them with their descriptions;
    the registered schema for `proxy.system.set` has exactly one optional param
    `bypass: Array(Str)`.
18. **SP-AC18 [rust-unit]** `proxy.status` carries `system_proxy` with the §D6
    compact fields; with a scripted executor, two `proxy.status` calls within
    5 s perform one `scutil --proxy`; a `set` in between refreshes it
    immediately (`state` flips to `points_at_us` on the next call with no new
    read).
19. **SP-AC19 [rust-unit]** `config_file::parse_settings("system_proxy:\n  auto: true\n  bypass: [corp.test]\n")`
    yields `auto == true`, `bypass == ["corp.test"]`, and a default `state_file`
    equal to `ca.audit_log.with_file_name("system-proxy-state.json")`;
    `"system_proxy:\n  nope: true\n"` is an error; an absent section yields
    `auto == false`.
20. **SP-AC20 [live, macOS]** On Matt's Mac with the dev bundle
    (`cd apps/mac && DEV_TAG=<tag> CORE_DIR=<repo>/target/release tools/snap-dev.sh none`,
    then `/tmp/Aitmproxy-dev-<tag>.app/Contents/MacOS/Aitmproxy-<tag>` with
    `APP_STORE=/tmp/<tag>-store`), one Terminal script records `scutil --proxy`
    and the per-service `-get*` **before**, presses Set as System Proxy in the
    app (or `:sysproxy on` in the TUI for PR 2), then shows: `scutil --proxy`
    with `HTTPEnable : 1`, `HTTPProxy : 127.0.0.1`, `HTTPPort : <core port>`,
    the same for HTTPS; Safari loading a page produces flows in the app; the
    Core card reads "system proxy → this core"; the state file exists with
    `previous` equal to the recorded before-state (Proxyman's `127.0.0.1:9090`
    today); quitting the app restores and the after `scutil --proxy` equals the
    before. The PR body quotes all three dumps. No bus token appears.
21. **SP-AC21 [live, macOS]** With the proxy set as in SP-AC20, `kill -9 <core
    pid>` from the Terminal: within 3 s `scutil --proxy` equals the before
    state, the state file is gone, and `system-proxy-watchdog.log` holds a
    `restored` line. The PR body quotes the dump and the log line.
22. **SP-AC22 [live, Linux]** In the Lima VM `cis-lab` (Ubuntu 24.04, gsettings
    + session bus, no desktop), with a real `aitm` serving: `gsettings get
    org.gnome.system.proxy mode` before (`'none'`), `aitm proxy system set` via
    the TUI or a bus client (not one-shot) → `'manual'` and `.http host`
    `'127.0.0.1'`; `proxy.system.unset` → `'none'` and the original hosts;
    `kill -9` → the watchdog restores `'none'`. The PR body quotes each
    `gsettings get`.
23. **SP-AC23 [kit-unit]** `ConnectionSummary.make` with `systemProxy` facts
    yields the §D12 mac-fact column for every row: text, state hue, actions;
    `overall` is `.warning` for `other` and `needsPrivilege`, unchanged for
    `off`; the `.firstFlow` step title is "Set aitmproxy as the system proxy,
    or open the browser" with action `.setSystemProxy` when supported and not at
    us, and "System proxy points at 127.0.0.1:8080 — waiting for the first
    flow" when at us.
24. **SP-AC24 [tripwire]** `apps/mac/tools/check-sysproxy-operator-only.sh`
    exits 0 on the tree and exits 1 when a `"proxy.system.set"` literal is
    planted in `Session+Verbs.swift` (the script's own self-check, the capture
    script's pattern); `tools/check-connection-words.sh` still exits 0 (the new
    strings live only in `ConnectionSummary.swift`).
25. **SP-AC25 [kit-unit]** `EmbeddedCoreLaunch.Config.yaml()` with
    `systemProxyAuto: true, systemProxyBypass: ["corp.test"]` emits a top-level
    block exactly `system_proxy:\n  auto: true\n  bypass:\n    - "corp.test"\n`
    that `config_file::parse_settings` accepts (SP-AC19's parser), and emits no
    `system_proxy:` block when auto is off and the list is empty.
26. **SP-AC26 [rust-unit, TUI]** `App::run_command(":sysproxy on")` with
    `proxy.system.set` in the tool list yields one `BusRequest::Call { name:
    "proxy.system.set", args: {} }`; without the tool, no request and the toast
    "System proxy needs the core's proxy.system.* verbs"; the pill renders
    `· sys-proxy → 127.0.0.1:9090` for an `other` status, `· sys-proxy → us` for
    `points_at_us`, `· sys-proxy setting…` while in flight, and nothing when
    `system_proxy` is absent.
27. **SP-AC27 [live, web + TUI]** The same SP-AC20 script, once each for `aitm
    tui` (key `s`, then `s` again) and `aitm web` (the pill menu checkbox),
    with the before/after `scutil --proxy` quoted; the pill word changes within
    one poll.
28. **SP-AC28 [tripwire]** No file under `crates/aitm-sysproxy/`,
    `crates/aitm/src/`, `apps/mac/Sources/`, `crates/aitm-tui/src/` or
    `apps/web/src/` touched by these PRs contains the strings `sudo `,
    `osascript`, or `with administrator privileges` (a grep in CI's gate script
    or a Rust test over the workspace tree); `grep -rn "unsafe" crates/aitm-sysproxy/src`
    is empty.

## Left to the builder

- Internal error enums beyond `ReadError`/`WriteError`, the exact `tracing`
  field names, and how the cache in `summary()` is guarded.
- The GVariant quoting helper for `ignore-hosts` and the exact escaping of a
  service name with a quote in it (render through `CmdLine`; never a shell).
- The watchdog's log line format and how `--no-pipe` tests the poll fallback.
- The TUI help-overlay line for `s`/`:sysproxy`; the web menu's icon; the mac
  menu shortcut (from the free set in `CommandMap`).
- Whether the mac nudge is a banner view or a `ContentUnavailableView` action
  row, within the design rules in `apps/mac/CLAUDE.md`.
- How the per-service rows are presented in Settings ▸ Proxy (a disclosure
  under the toggle is fine; nothing on the toolbar).

## Open questions

None left open. The three product questions below were answered provisionally
by the orchestrating session on 2026-10-31 under Matt's standing self-approval
mandate; each is flagged to Matt in the wrap-up and he may overturn it (a
one-line change in each case).

1. The first-run sheet's "Set as System Proxy" also turns on "Set system proxy
   at launch" (D13). **Provisional answer: keep the coupling.** Matt's words
   are "those things should happen automatically"; a one-time set that is gone
   at the next launch is not automatic. The sheet says so under the button.
2. In the toolbar pill, `other(host, port)` (Proxyman owning the proxy) is a
   warning hue (D12/D13). **Provisional answer: keep the warning.** The
   operator opened aitmproxy to see traffic and none is coming; the remedy
   sentence names the other proxy, so the warning is specific, not noise.
3. KDE ships unit-tested only (D4). **Provisional answer: accepted for this
   milestone**, with a Plasma VM proof as a follow-up listed in the plan's
   Shipped section.

---

## Wrap-up

**Summary.** One core implementation in a new `aitm-sysproxy` crate, behind
`proxy.system.status` (Read) and operator-only `proxy.system.set`/`unset`, sets
the OS HTTP/HTTPS proxy to the running core with `networksetup` (macOS, no root,
no dialog for an admin), `gsettings` or `kwriteconfig` (Linux, no privilege),
and reports the effective state honestly from `scutil --proxy`. The previous
setting is saved to a `0600` state file before the first write and comes back
on unset, on every orderly exit, from a detached stdin-pipe watchdog after a
crash, and at the next start. The bypass list keeps loopback and the operator's
own tools out. The mac app, TUI and web show one word table and call the verbs;
the Proxyman-style helper, PAC and Windows are explicit follow-ups.

**Architect's calls** (approve or correct): verb answer beats the CFNetwork
read when both exist (D1); executor timeouts 10 s/30 s (D2); skip authenticated
proxies and say so, write `127.0.0.1` for loopback/unspecified listens, the
`needs_privilege` remedy sentence (D3); KDE also writes gsettings, KDE
unit-only (D4); `proxy.status.system_proxy` cached ≤ 5 s (D6); config as a
top-level `system_proxy` section outside `aitm-core`, state file as the CA
audit log's sibling (D7); `ControlPlugin::with_system_proxy` builder (D8);
orderly-exit restore regardless of `auto`, stdin-pipe watchdog in its own
process group with a `system-proxy-watchdog.log` (D9); one-shot `set` refused
(D10); sheet also enables the launch toggle, nudge only on launches without the
sheet, `other` is a warning hue and `off` is calm (D12/D13); TUI key `s` (D14).
