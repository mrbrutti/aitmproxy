# System proxy automation design

**Status:** approved (2026-10-31, self-approved by the system-proxy session under Matt's standing mandate; the three provisional answers below are flagged to Matt in the session wrap-up and he may overturn any of them; addendum D17 added 2026-10-31 (CA trust), approved under the same mandate)
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
    pub fn status(&self) -> Status;                                  // fresh read: effective + per-service (see §D6 for the agent-side cache)
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

`WriteError::NeedsPrivilege { line }` (the failing rendered command line; the engine supplies the §D3 remedy sentence from `remedy(ours)`) is produced when a `networksetup` mutation
exits non-zero or prints `** Error: Command requires admin privileges.` on
stdout or stderr; `ReadError::Unavailable` when a read prints
`AuthorizationCreate() failed` or `scutil --proxy` yields an empty dictionary
(the sandbox case): that maps to `State::Unknown`, never `Off`.

Absolute programs, resolved by the crate (`aitm_ca::exec::absolute_program` does
not know them): `/usr/sbin/networksetup`, `/usr/sbin/scutil`,
`/usr/bin/gsettings`; `kwriteconfig6`, `kwriteconfig5`, `kreadconfig6`,
`kreadconfig5`, `dbus-send` located by name on `PATH` at detection and spawned by
the absolute path found (a missing one is reported as the mechanism's tool
missing, never as "off"). Timeouts
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

**Operator-critical hosts (added 2026-10-31 after the first live run; orchestrator's
requirement, flagged to Matt).** While the system proxy points at the core, every
proxy-aware process on the machine routes through it — including the operator's
own tooling (Claude Desktop, browsers, `gh`), which does not trust the MITM CA and
fails TLS for the duration. The product therefore ships a *recommended* bypass
list the frontends pre-fill into the editable "Bypass hosts" field on first run
(the operator may clear it): `*.anthropic.com`, `api.anthropic.com`, `claude.ai`,
`*.claude.ai`, `github.com`, `*.githubusercontent.com`. It is a UI default for
the `bypass` setting, not part of `BYPASS_DEFAULT` (the core's loopback/local
defaults stay minimal and testable), and every live proof on Matt's Mac uses it.

### D6. Status model, verb schemas, example payloads

`proxy.system.status` — params: none. A call from a caller that is not a
trusted control surface (an agent over MCP) is served from the last full status
when it is at most 2 s old, with `setting` always live; operator surfaces (mac
app, TUI, web, CLI) always get a fresh read (added 2026-10-31 from the security
panel, S3). Result object (field names are the
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
(`changed: true`). A set over an **existing** state file whose live state no longer
`points_at_us` keeps that file's `previous` row for every service still equal
to its `wrote` (our own endpoint is never recorded as "previous"); a service
another tool took over since takes its live row (Linux: the same rule per key
set). Added 2026-10-31 from fix F1, recorded by the panel. Errors (`anyhow::Err`, so the frontends show the message):
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
services, 1240 ms)"` / `"system proxy restored → 127.0.0.1:9090 (2 services,
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

The CA-trust rows of this same table (the sibling fact: "CA trusted (user
keychain)", "HTTPS is not captured until the CA is trusted", `· CA trusted`,
`· CA untrusted`, …) are in §D17.6, with the same columns and the same rule.

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
  would be gone at the next launch, which is not "automatically". **D17.8 adds the
  CA step to this sheet above the checklist, widens the show-condition to "or the CA
  is not trusted", and retitles it "Set up aitmproxy on this Mac".**
- **No-traffic nudge**: on launches where the sheet did not show, when flows
  have stayed 0 for 30 s after `.ready` with the fact not `points_at_us`, not
  `setting`, supported, and not suppressed: a non-modal banner on the Status
  page and the flows list header, "No flows yet? Set aitmproxy as the system
  proxy so Safari and other apps use it.", with "Set as System Proxy", "Not Now"
  and a "Don't ask again" checkbox; at most once per launch.
- **Step order and words (Matt, 2026-10-31, per-host decryption like Proxyman: only hosts in
  Scope are decrypted, the rest pass through, inline Add to Scope).** The first-run sheet and
  the Status checklist present the three automations in this order with these words: 1 "Set
  aitmproxy as the system proxy" (or point a client at it), 2 "Trust the aitmproxy CA" (D17),
  3 "Add a host to Scope — nothing is decrypted until a host is in Scope". Shared with
  mac-attribution's advice model; no change to the verbs.
- **Getting started**: the `.firstFlow` step's undone title becomes "Set
  aitmproxy as the system proxy, or open the browser" (action
  `.setSystemProxy`) when supported and not at us; "System proxy points at
  127.0.0.1:8080 — waiting for the first flow" (action `.openBrowser`) when at
  us; the old "Point a client at …" wording when unsupported or unknown. **D17.9 adds
  the `.caTrusted` step ("Trust the aitmproxy CA") between `.busConnected` and
  `.extensionOn`.**
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
  `· sys-proxy setting…` until the reply; an error or refusal goes to the existing
  notice toast above the status bar (the web has no separate message slot).
- **Full status on menu open (amended 2026-11-01 after the PR 3 panel).** The polled
  compact sub-object carries no `guidance`/`remedy` (§D6), so the pill menu, when it
  opens, calls `proxy.system.status` (gated on the tool being offered; operator
  surfaces get the fresh read) and stores the full object; the 2 s poll then keeps
  the last `guidance`/`remedy` when the compact object lacks them, until the next
  menu open or a set/unset reply replaces them. Without that call the "Copy env line"
  item and the privilege remedy would be unreachable.
- Never touch `apps/web/src/bus/mock.ts` or `apps/web/src/bus/noise.ts`.

### D16. Logging and audit

One `info!` per set, unset, restore and adoption (target `aitm_sysproxy`:
outcome, service count, ms); every rendered command at `debug!`; no token, no
home-path noise at info. Bus calls land in the agent audit ring as every verb
does; no entry is written to the CA audit log.

### D17. CA trust: the first-run sibling of the system proxy (addendum, 2026-10-31)

**Why.** The v0.5.5 acceptance run on Matt's Mac (NE session, relayed by the
orchestrator): the login and System keychains hold 0 aitmproxy certificates, so
every TLS interception fails its handshake; Safari silently retries over QUIC
(which the provider never claims since #190) and loads the page directly. Result:
zero HTTPS rows in 0.5.3–0.5.5 while plain HTTP works end to end. The CA panel
exists (`apps/mac/Sources/Aitmproxy/Panels/CAPanel.swift`) but nothing leads the
operator to it: not the first-run sheet, not the Status checklist, not the pill.
Under Matt's zero-CLI rule the app must get the CA trusted itself, as the sibling
of "Set as system proxy" in the same sheet and checklist, with the trust state
read back from the OS store, never from a client flag. Proxyman's equivalent is
its Settings ▸ General CA block ("Proxyman CA (not installed) / Generate new… /
More").

**What the core already has** (cited so the builder does not re-derive it):

- `ca.status` (`crates/aitm-ca/src/commands.rs`, read-only, not audited) answers
  `{exists, dir, path, fingerprint_sha256, fingerprint_sha1, platform, stores:
  {user|system: {installed: present|absent|stale|unknown, trusted: yes|no|unknown,
  location}}, detail: [..]}`, one `stores` entry per `Platform::scopes()`.
- `ca.install {scope?, dry_run?}` and `ca.uninstall` are `Sensitivity::Sensitive`
  with a `confirm_prompt` (the bus confirm-token round trip the mac panel already
  performs). `Change::resolve_scope` (`commands.rs`) takes the asked scope if the
  platform has it, else `Platform::default_scope()`; `store.rs` gives macOS and
  Windows `[User, System]` (default **User**) and Linux `[System]`.
- macOS user scope (`crates/aitm-ca/src/platform/macos.rs`) renders
  `security add-trusted-cert -r trustRoot -p ssl -p basic -k <home>/Library/Keychains/login.keychain-db <ca.crt>`
  with **no `sudo`**; the man page (research 07 §3.1): "When modifying per-user
  Trust Settings, user authentication is required via an authentication dialog".
  That dialog is the OS permission prompt Matt asked for. System scope renders
  `sudo -- security add-trusted-cert -d … /Library/Keychains/System.keychain`,
  needs a TTY, and is never the app's path. A failed add rolls back the untrusted
  copy the tool leaves behind (`install_headless_rolls_back` in
  `crates/aitm-ca/tests/macos.rs`).
- Linux (`platform/linux.rs`): `sudo -- tee <anchor>` + `update-ca-certificates`
  / `update-ca-trust extract`; `status` reads the anchor and the extracted bundle
  with no privilege, so `trusted` is already `yes|no` there.

**The three gaps this section closes:**

1. **The agent gate refuses the operator.** `Change::invoke` refuses when
   `frontend != Frontend::Cli && !dry_run && !allow_agent_install`
   (`commands.rs`, the policy gate). Every GUI/TUI/web client connects with the
   operator token and is `Frontend::Operator` (`crates/aitm-core/src/ctx.rs`:
   "a human operator over MCP … so policy and confirmation decisions can treat a
   present human differently from an autonomous agent"). With the flag off by
   default and the embedded core's generated config not setting it, the mac
   panel's Install… button is refused with the agent-frontend text after the
   operator has already confirmed. No first-run step can work until this is fixed.
2. **macOS trust is never read back.** `MacOsStore::status` reports presence from
   `find-certificate -a -Z` and always `Trust::Unknown` (its module docs cite
   research 07 §3.1: `verify-cert` was inconclusive **inside the sandbox**). So no
   frontend can ever say "trusted" on a Mac, and the CA panel's post-install line
   "Install finished but the CA is not trusted in the login keychain yet…" fires
   after every successful install.
3. **No frontend leads to the step.** The sheet (D13), the Getting-started list
   and the pill say nothing about trust.

**Decided.**

- **D17.1 Scope is explicit and always user on macOS.** Every frontend passes
  `scope: "user"` on `ca.install`/`ca.uninstall` when `ca.status.platform` is
  `macos` or `windows`, and passes no scope on Linux (the only scope there is
  `system`). The core's default is already `User` on macOS, so the explicit param
  changes nothing in behaviour; it makes the "(user keychain)" word provably true
  and keeps the literal `"system"` out of every frontend's CA path (tripwire).
  The app never touches `/Library/Keychains/System.keychain`.
- **D17.2 `Frontend::Operator` passes the agent gate.** `ca.install` and
  `ca.uninstall` refuse only `Frontend::Mcp` when `ca.allow_agent_install` is off;
  `Cli` and `Operator` proceed (the bus confirm step still applies, then the OS
  dialog). `defers_to_command_gate` in `crates/aitm-mcp/src/server.rs` keeps both
  verbs (an agent under `All` with the flag on may still install: the existing
  product decision is untouched). The audit record's `frontend` is `"operator"`.
  **(Architect's call, flagged to Matt: it widens who may change the trust store
  from "CLI only" to "CLI or a present human holding the operator token". The
  rationale is the one `ctx.rs` gives for the variant, and `proxy.system.set` in
  this spec already trusts `Operator` for a system-wide change.)**
- **D17.3 macOS trust read-back.** `MacOsStore::status` for a scope whose
  keychain holds the certificate runs one OS trust evaluation and reports
  `Trust::Yes|No`; for an absent certificate it reports `No` without running it;
  `Unknown` only when the evaluation tool itself could not run (missing, timed
  out), with the failure text in `detail`. The primary evaluation is
  `security verify-cert -c <ca.crt> -l -L -p ssl` (`-l`: the leaf is a CA, `-L`:
  no network): exit 0 and stdout containing `certificate verification
  successful` is `Yes`; any non-zero exit is `No` with the stderr tail in
  `detail`. Research 07 §3.1 saw `verify-cert` exit 1 for a trusted Apple root
  **inside the Bash sandbox** and marks the result unverified outside it; the
  Warren PR #18 report it cites used `verify-cert` successfully after a user-scope
  install. Plan Task 32 is a read-only probe on Matt's Mac that fixes the two
  literal outcomes before the Coder writes the parser. If the probe shows
  `verify-cert` cannot separate trusted from untrusted outside the sandbox either,
  the fallback is `security trust-settings-export <tmp.plist>` (user domain, no
  `-d`, no `sudo`; the admin-domain form is what mkcert imports/exports, research
  07 §3.5): `Yes` when the plist's `trustList` has an entry for our certificate
  (keyed by SHA-1 upper hex, **unverified**; matched by `issuerName` DER as the
  second key) whose `trustSettings` is empty or has no `kSecTrustSettingsResult`
  of `3` (deny). The two `detail` constants `DETAIL` and
  `PRESENT_TRUST_UNCONFIRMED` are replaced by one line naming what ran:
  "macOS: presence from `security find-certificate`; trust from `security
  verify-cert` (ssl policy, local only)". Trust settings are per user and per
  certificate hash, not per keychain; `status` therefore attaches the evaluation
  to the scope whose keychain holds the certificate, and when both keychains hold
  it both scopes report the same answer.
- **D17.4 A cancelled dialog is calm.** `TrustErrorKind` gains `Cancelled`.
  `MacOsStore::install` classifies a failed `add-trusted-cert` whose stderr
  contains `cancel` (case-insensitive: Apple spells it "canceled"; research 07 has
  only the headless text `The authorization was denied since no user interaction
  was possible`, so the cancel text is **unverified** until Task 40 quotes it) as
  `Cancelled`, after the same rollback of the untrusted copy, with the literal
  message `ca.install cancelled: the macOS authentication dialog was dismissed;
  the CA is not trusted`. `kind_name` maps it to `"cancelled"` for the audit
  record and the `warn!` line. Every frontend treats an error whose message
  starts with `ca.install cancelled` as an information toast at most, never an
  error, and re-reads `ca.status`.
- **D17.5 The fact comes from the read-back, never from the install.** After
  every `ca.install`/`ca.uninstall` reply (ok, cancelled, or error) every frontend
  calls `ca.status` and renders from it; the reply's `changed` is never a source
  of the word. In the mac app the type is mac-attribution's
  `CATrustFacts { trusted: Bool, scope: String?, fingerprint: String?, installing:
  Bool = false, remedy: String? = nil }` with the **failable**
  `CATrustFacts.init?(status: CAStatus)` in `AitmproxyKit`: `nil` when every store
  reports `trusted == "unknown"` (an older core, or the evaluation tool failed),
  so "unread" never renders as "not trusted"; otherwise `trusted` iff any store
  says `yes`, `scope` = `CAStatus.trustedScope` (`"user"` | `"system"`),
  `fingerprint` = `fingerprint_sha256`, `installing` set by `Session` while its
  call is in flight, `remedy` per the table below. `CAStatus`
  (`AitmproxyKit/Panels/CAStatus.swift`) gains `trustedScope: String?` and
  `trustReported: Bool` on mac-attribution's branch; PR 5 consumes them and adds
  nothing to the type. A `nil` facts slot renders no CA fact on the Core lane and
  no pill word; only the Getting-started step speaks (D17.9).
- **D17.6 Word table** (the CA rows of §D12; same columns, same rule that neither
  surface invents a third form). The mac fact renders on the Core lane under the
  system-proxy fact (`ConnectionSummary.caTrust`, mac-attribution's row); the TUI
  and web append the pill word after the sys-proxy word:

  | Idea | mac fact text | state hue | pill word (TUI/web) | actions |
  |---|---|---|---|---|
  | trusted (a store says yes) | CA trusted (user keychain) — "(System keychain)" when `scope == "system"` | ok | `· CA trusted` | `.openCAPanel` |
  | not trusted (a store says no, none yes) | HTTPS is not captured until the CA is trusted | warning | `· CA untrusted` | `.trustCA`, `.openCAPanel` |
  | `installing` | trusting CA… | working | `· CA trusting…` | — (disabled) |
  | needs an administrator (Linux `NeedsRoot`; macOS `HeadlessAuth` returned to a GUI frontend) | CA trust needs an administrator | warning | `· CA needs admin` | `.openCAPanel` |
  | facts `nil` (every store `unknown`) | no fact row; the step reads "CA trust unknown — open the Certificate Authority panel" | off (calm) | nothing | `.openCAPanel` |
  | `exists == false` | CA not generated yet — the core creates it on first start | off | nothing | — |

  Remedies: not trusted → "HTTPS is not captured until the CA is trusted —
  browsers using QUIC load directly until then" (mac-attribution's detail line,
  verbatim); needs an administrator on Linux → "Linux trust stores need root: run
  `aitm ca install` in a terminal where sudo can prompt" (the documented
  limitation, D17.13); needs an administrator on macOS (`HeadlessAuth`) →
  "macOS did not show its authentication dialog. Open the Certificate Authority
  panel, export the certificate and trust it in Keychain Access." (the fallback,
  D17.15). Action titles: `.trustCA` = "Trust the aitmproxy CA", `.openCAPanel` =
  "Certificate Authority…" (the existing menu title). `overall` and the pill
  include the CA fact's state only when it is `warning` or `working`, as for the
  system-proxy fact. The pill words `· CA trusting…` and `· CA needs admin` are
  **Architect's calls**; `· CA trusted` / `· CA untrusted` were agreed.
- **D17.7 The QUIC caveat, one sentence, verbatim wherever it appears** (the
  sheet's CA row, the CA panel's status block, the Settings ▸ Proxy footnote next
  to the §D12 lane sentence, the operator docs): "HTTPS apps that use QUIC are not
  captured until the CA is trusted; browsers fall back to TCP once it is." Honesty
  note for the proof, not for the UI: Safari keeps a per-host Alt-Svc h3 mapping
  for a while after loading a host, so the live proof uses a host Safari has not
  loaded in that session (or a fresh Safari window after Develop ▸ Empty Caches).
- **D17.8 The first-run sheet carries both steps.** `Shell/SystemProxySheet.swift`
  (plan C11; the file name stays) gains a CA row **above** the D13 checklist, so
  the sheet reads as two ordered steps: **1 Trust the aitmproxy CA** — the fact's
  word from the table, the button "Trust the aitmproxy CA" (hidden when trusted;
  the word reads "trusting CA…" while in flight), and the D17.7 sentence under it;
  **2 Set as System Proxy** — D13's checklist, caption and button, unchanged. The
  title becomes "Set up aitmproxy on this Mac" **(Architect's call: the sheet now
  asks two things, so D13's "Set aitmproxy as the system proxy?" would be a
  half-title)**. Show-conditions are D13's **or** (the CA facts are non-nil and not
  trusted) under the same bus-operator / core-ready / not-suppressed guards; the
  existing `Store.defaults` keys `systemProxy.sheetShown` and
  `systemProxy.promptSuppressed` now cover both steps (one sheet, one memory).
  "Not Now" closes it; when both rows read done the dismiss button's title is
  "Done". Pressing "Trust the aitmproxy CA" in the sheet performs the bus
  confirm-token re-call **without a second `NSAlert`** **(Architect's call: the row
  states what it does and macOS then shows its own password dialog; a third
  prompt is noise)**; the CA panel's "Install…"/"Uninstall…" keep their alert (the
  ellipsis promises one).
- **D17.9 Getting started.** mac-attribution's step `.caTrusted` sits between
  `.busConnected` and `.extensionOn` and ships from their branch without a button.
  PR 5 adds the two `ConnectionAction` cases it was waiting for — `.trustCA`
  ("Trust the aitmproxy CA") and `.openCAPanel` ("Certificate Authority…") — and
  wires them: done title "CA trusted (user keychain)" (no action); not trusted →
  "Trust the aitmproxy CA" with `.trustCA`; facts `nil` → "CA trust unknown — open
  the Certificate Authority panel" with `.openCAPanel`; needs an administrator →
  "CA trust needs an administrator" with `.openCAPanel`. The `.firstFlow` step is
  unchanged. This is the one place PR 5 edits `ConnectionSummary.swift`, after
  mac-attribution's PR has merged.
- **D17.10 One call path in the mac app.** A new `Session+CATrust.swift` holds the
  only two literals `"ca.install"` and `"ca.uninstall"` (`trustCA()`,
  `untrustCA()`), passes `["scope": .string("user")]` on macOS/Windows per D17.1,
  performs the confirm-token re-call, sets `caTrustInstalling` for the duration,
  maps a `ca.install cancelled` error to no toast, and always ends by forcing the
  `ca.status` re-read. The periodic read-back is mac-attribution's: `ca.status` at
  connect and on every 10th `proxy.status` poll tick (about every 5 s), because
  each read spawns `/usr/bin/security` per store; D17.3 adds one `verify-cert`
  spawn per scope whose keychain holds the certificate, so an untrusted Mac pays
  nothing extra and a trusted one pays one short process per 5 s. `CAPanel.swift`,
  the sheet and the Status card route through `trustCA()`;
  `Session.perform(connection:)` returns `false` for `.trustCA` (operator-only,
  like capture) and handles `.openCAPanel` as `show(.ca)`. Menu: Proxy ▸ "Trust
  the aitmproxy CA" (disabled when trusted or while installing; shortcut from the
  free set in `CommandMap`), with its `CommandMap` entry; uninstall stays in the
  panel. CAPanel's post-install line becomes true: it shows only when the re-read
  says not trusted, and reads the table's remedy.
- **D17.11 TUI.** On connect, when `ca.status` is in the tool list, the app asks
  it once (it already re-asks after `ca.install`/`ca.uninstall` replies,
  `app.rs`); `App::ca_trust_word()` renders the pill column from the last
  `ca.status` and the in-flight flag; `run_command` adds `scope: "user"` to
  `ca.install`/`ca.uninstall` when the last `ca.status.platform` is `macos` or
  `windows` and no scope was typed (key `i`/`u` in the `:ca` panel already route
  through `run_command`, `keys.rs`); a `ca.install cancelled` error is a
  `Level::Info` toast "CA trust cancelled". Never touch `crates/aitm-tui/src/fixture.rs`.
- **D17.12 Web.** `app.ca` (`CATrustStatus | null`) is filled from `ca.status` on
  connect (when the tool exists) and after every `ca.install`/`ca.uninstall` run
  from the palette; the listening pill appends the pill word after the sys-proxy
  word; the Setup action `install-ca` is relabelled "Trust the aitmproxy CA" with
  hint "Install the root CA into your user trust store; HTTPS is not captured
  until then" and passes `{ scope: 'user' }` on macOS/Windows; a cancelled reply
  is an `info` notice. Never touch `apps/web/src/bus/mock.ts` or
  `apps/web/src/bus/noise.ts`.
- **D17.13 Linux is a documented limitation, not a solved one.** `Platform::Linux`
  has only the `system` scope and every mutation is `sudo --`-prefixed
  (`linux.rs`); from a bus client with no TTY the write fails with `NeedsRoot`,
  and the word is "CA trust needs an administrator" with the CLI remedy above.
  There is no Linux app, so Matt's zero-CLI rule for the mac app is not broken,
  and the TUI already lives in a terminal. `ca.status` reads the bundle without
  privilege, so the word itself is honest. Follow-ups, **not designed here**: a
  polkit/`pkexec` prompt path (not covered by research 07; unverified), and the
  Firefox/Chromium NSS user databases (`certutil -d sql:$HOME/.pki/nssdb`) —
  research 07 §3.5 only notes that mkcert's `truststore_nss.go` drives `certutil`
  against profile databases and marks NSS out of scope, with no command lines
  observed, so that is a Researcher question before any spec.
- **D17.14 Gating, evidence, and the System keychain.** The agent rules are
  unchanged: `ca.install` stays Sensitive, confirm-gated, agent-gated by
  `ca.allow_agent_install`, and in `defers_to_command_gate`; it is **not** made
  operator-only (agents may install when the operator turns the flag on). The
  evidence rule of this spec applies: Rust unit tests (gate, scope, parser,
  cancel), Kit unit tests (mac-attribution's rows), the mac tripwire for the
  literal's single home, and the live proof — which runs **only after Matt
  explicitly says the CA may be trusted on his Mac**, and then only through the
  app's own step and the macOS dialog, never `aitm ca install` by hand, and never
  the System keychain (the proof quotes
  `security find-certificate -a -c aitmproxy -Z /Library/Keychains/System.keychain`
  before and after and both must be empty).
- **D17.15 If the dialog does not surface.** The core is the app's child and its
  `security` child inherits the Aqua session, so the authorization dialog is
  expected (research 07 §3.1 reports the headless failure for PKG scripts,
  daemons and `osascript … with administrator privileges`, not for a child of a
  GUI app; `CAPanel.swift`'s comment hedges without evidence). If Task 40 shows
  `HeadlessAuth` from the dev bundle, the word is "CA trust needs an
  administrator" with the Keychain Access remedy, and the follow-up is an
  in-process `SecTrustSettingsSetTrustSettings` call from the app itself
  (Proxyman's path; Security.framework, no `sudo`), as a separate spec.

## Acceptance criteria

Tags: **[rust-unit]** = `cargo test` with scripted executors or pure functions;
**[kit-unit]** = `swift test` in `AitmproxyKit`; **[tripwire]** = a source
check script or a test that greps/asserts source; **[live]** = a real frontend
against a real core on a real machine, output quoted in the PR. Per the
evidence rule, nothing tagged fixture, snapshot, self-test or mock counts.
SP-AC29 … SP-AC38 belong to the D17 addendum (PR 5).

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

29. **SP-AC29 [rust-unit]** (D17.2) `ca.install` invoked with `Frontend::Operator`,
    `allow_agent_install == false`, no `dry_run`, on a scripted macOS executor whose
    `find-certificate` answers absent and whose `add-trusted-cert` exits 0, **proceeds**:
    the executor's runs contain
    `security add-trusted-cert -r trustRoot -p ssl -p basic -k <home>/Library/Keychains/login.keychain-db /ca/ca.crt`,
    the result has `changed == true`, `scope == "user"`, and the audit record has
    `frontend == "operator"`, `outcome == "ok"`. The same call with `Frontend::Mcp`
    still returns `Err` whose message starts `ca.install refused` with zero executor
    runs (the existing test); `dry_run: true` from `Mcp` still proceeds.
30. **SP-AC30 [rust-unit]** (D17.1) `Change::resolve_scope(&Platform::MacOs, None) == Ok(Scope::User)`;
    `(&Platform::MacOs, Some(Scope::User)) == Ok(Scope::User)`;
    `(&Platform::Linux(LinuxFamily::Debian), Some(Scope::User))` is `Err` with kind
    `UnsupportedScope` and message `Linux has no per-user OS trust store; use --scope system`;
    `(&Platform::Linux(LinuxFamily::Debian), None) == Ok(Scope::System)`. No rendered
    line of a macOS user-scope install begins with `sudo`.
31. **SP-AC31 [rust-unit]** (D17.3) With the certificate present in the login keychain
    (scripted `find-certificate -a -Z` output) and scripted
    `security verify-cert -c /ca/ca.crt -l -L -p ssl` exit 0 stdout
    `/ca/ca.crt: certificate verification successful.`, `MacOsStore::status(User)` has
    `trusted == Trust::Yes` and `ca.status` JSON has `stores.user.trusted == "yes"`;
    with `verify-cert` exit 1 stderr `/ca/ca.crt: certificate verification failed.`
    → `Trust::No` and `detail` contains that stderr; with the certificate absent →
    `Trust::No` and **no** `verify-cert` line in the runs; with `verify-cert`
    unspawnable (`ToolMissing`) → `Trust::Unknown` and `detail` contains the failure
    text; the `detail` always contains `trust from \`security verify-cert\``. The
    exact stdout/stderr literals are replaced by Task 32's quoted ones before the
    test is written; if Task 32 selects `trust-settings-export`, this criterion
    reads: a fixture plist with our SHA-1 key and empty `trustSettings` → `Yes`, the
    same plist without our key → `No`, a key present with
    `kSecTrustSettingsResult` `3` → `No`.
32. **SP-AC32 [rust-unit]** (D17.4) A scripted `add-trusted-cert` exit 1 with stderr
    `SecTrustSettingsSetTrustSettings: The authorization was canceled by the user.`
    (the literal Task 40 confirms or corrects) followed by a requery showing the
    certificate present yields `Err` of kind `TrustErrorKind::Cancelled` whose message
    is exactly `ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted; removed the untrusted copy it left behind`,
    with `security delete-certificate -Z <sha256> <login keychain>` in the runs;
    `kind_name(&err) == "cancelled"`; the headless marker text still yields
    `HeadlessAuth`.
33. **SP-AC33 [kit-unit]** (D17.5, D17.6, D17.9) In `ConnectionSummaryTests`:
    `CATrustFacts(status:)` from a `ca.status` JSON with `stores.user.trusted == "yes"`
    is non-nil with `trusted == true`, `scope == "user"`; from
    `stores.user.trusted == "unknown"` and `stores.system.trusted == "unknown"` it is
    `nil` (mac-attribution's tests; re-run by PR 5). PR 5's own test
    `caTrustActionsAndStepButton`: `make(caTrust: notTrusted).caTrust?.actions == [.trustCA, .openCAPanel]`;
    `make(caTrust: trusted).caTrust?.actions == [.openCAPanel]`; the `.caTrusted` step
    (index 2) has title "Trust the aitmproxy CA" and `action == .trustCA` when not
    trusted, title "CA trusted (user keychain)" and `done == true` with no action when
    trusted, title "CA trust unknown — open the Certificate Authority panel" and
    `action == .openCAPanel` when `caTrust == nil`;
    `ConnectionAction.trustCA.title == "Trust the aitmproxy CA"`,
    `ConnectionAction.openCAPanel.title == "Certificate Authority…"`;
    `make(caTrust: notTrusted).overall == .warning`;
    `make(caTrust: nil).overall == make().overall`.
34. **SP-AC34 [tripwire]** (D17.10, D17.1) `apps/mac/tools/check-ca-trust-path.sh`
    exits 0 and prints `PASS` on the tree: the literals `"ca.install"` and
    `"ca.uninstall"` appear only in `Sources/Aitmproxy/Session+CATrust.swift`;
    `trustCA(` / `untrustCA(` are called only from `Panels/CAPanel.swift`,
    `Shell/SystemProxySheet.swift`, `Panels/StatusPanel.swift` and `App.swift` (each
    with an `expect` line); `Session+CATrust.swift` contains `.string("user")` and no
    `"system"`; the agent-reachable surfaces of SP-AC24's rule 3 match none of
    `ca\.install|ca\.uninstall|trustCA|untrustCA` (the palette's title
    "Certificate Authority…" is allowed; a fixture tool list that still names
    `ca.install` is allow-listed by file until the fake-data-removal PR deletes it).
    `--self-check` plants `let _ = "ca.install"` in `Session+Verbs.swift` and expects
    exit 1. `tools/check-connection-words.sh` still exits 0.
35. **SP-AC35 [rust-unit, TUI]** (D17.11) With `ca_status.platform == "macos"`,
    `run_command("ca.install")` then `y` yields `BusRequest::Call { name: "ca.install", args: {"scope": "user"} }`;
    with `platform == "linux-debian"` the args are `{}`; with
    `run_command("ca.install scope=system")` the typed scope wins (`{"scope": "system"}`);
    `ca_trust_word()` is `Some("· CA trusted")` when any store's `trusted == "yes"`,
    `Some("· CA untrusted")` when a store answers `"no"` and none `"yes"`,
    `Some("· CA trusting…")` while the install is in flight, `None` when every store
    is `"unknown"` or `ca_status` is `None`; on connect, a tool list containing
    `ca.status` produces exactly one `ca.status` request.
36. **SP-AC36 [web unit]** (D17.12) `apps/web/src/state/caTrust.ts`:
    `parseCATrust({exists:true, platform:'macos', fingerprint_sha256:'AB:CD', stores:{user:{installed:'present',trusted:'yes',location:'x'}}})`
    → `{ trusted: true, scope: 'user', platform: 'macos', fingerprint: 'AB:CD' }`; the same with every store `'unknown'` → `null`;
    `caPillWord(trusted, false) === '· CA trusted'`; `caPillWord(notTrusted, false) === '· CA untrusted'`;
    `caPillWord(any, true) === '· CA trusting…'`; `caPillWord(unknown, false) === null`;
    `caPillWord(null, false) === null`; `caInstallArgs(macos) → { scope: 'user' }`,
    `caInstallArgs(linux) → {}`, `caInstallArgs(null) → {}`;
    `isCACancelled('ca.install cancelled: …') === true`, `isCACancelled('ca.install refused: …') === false`.
37. **SP-AC37 [live, macOS; runs only after Matt's explicit go]** (D17.1, D17.3,
    D17.5, D17.8, D17.14) With the dev bundle on Matt's Mac, the Terminal script
    quotes `security find-certificate -a -c aitmproxy -Z ~/Library/Keychains/login.keychain-db`
    (empty) and `security find-certificate -a -c aitmproxy -Z /Library/Keychains/System.keychain`
    (empty) **before**; the first-run sheet shows the CA row reading "HTTPS is not
    captured until the CA is trusted"; pressing "Trust the aitmproxy CA" shows the
    macOS authentication dialog (pressed Cancel **once** first: the sheet word stays
    "HTTPS is not captured…", no error is shown, and the core log's `warn` line with
    `kind=cancelled` and the quoted stderr go into the PR body); approving it makes the
    login-keychain query print one `SHA-256 hash:` block equal to
    `ca.status.fingerprint_sha256` with the colons removed, the System-keychain query
    stays empty, the sheet row and the Status checklist read "CA trusted (user
    keychain)", and the core's `aitm_ca` log shows `OS trust store updated`
    `frontend=operator scope=user`; Safari loading an HTTPS page on an in-scope host
    it has not loaded this session (with the system proxy at the core per SP-AC20, or
    All Apps on) produces at least one `https://` flow row for that host, quoted;
    the CA panel's "Uninstall…" then empties the login-keychain query, the word returns
    to "HTTPS is not captured until the CA is trusted", and the System keychain is
    still empty. No bus token appears in anything quoted.
38. **SP-AC38 [live, TUI + web; same go]** (D17.11, D17.12) The same before/after
    `find-certificate` pair once in `aitm tui` (`:ca`, key `i`, `y`; then `u`) and
    once in `aitm web` (palette "Trust the aitmproxy CA"), the pill word flipping to
    `· CA trusted` within one poll and back to `· CA untrusted` after the uninstall;
    the sent `ca.install` args quoted from the core's debug log contain `scope=user`.

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

**D17 addendum (2026-10-31), answered provisionally under the same mandate and
flagged to Matt:**

4. `Frontend::Operator` passes the `ca.install`/`ca.uninstall` agent gate (D17.2).
   **Provisional answer: yes.** Without it the mac app's own CA step is refused on a
   default config; the operator token already authorises `proxy.system.set`.
5. The first-run sheet's title becomes "Set up aitmproxy on this Mac" and the CA
   row sits above the system-proxy checklist (D17.8). **Provisional answer: keep.**
6. **Not provisional — Matt's go is required:** the live proof (SP-AC37/38) installs
   the CA into Matt's login keychain through the app's step and the macOS dialog.
   Nobody runs it, and nobody runs `aitm ca install` on his Mac, until he says so.

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

**D17 addendum calls** (approve or correct): `Frontend::Operator` passes the CA
agent gate (D17.2); `verify-cert` as the macOS trust read-back with
`trust-settings-export` as the probe-decided fallback (D17.3); a `Cancelled`
error kind matched on `cancel` in stderr (D17.4); a `nil` facts slot renders no fact and the step word "CA trust unknown — open the
Certificate Authority panel" (D17.5, D17.9);
the pill words `· CA trusting…` and `· CA needs admin` (D17.6); the sheet title
"Set up aitmproxy on this Mac", the CA row above the checklist, and no second
`NSAlert` from the sheet (D17.8); the forced `ca.status` re-read after every change on top of
mac-attribution's 5 s cadence (D17.10); Linux stays a
documented `NeedsRoot` limitation with the CLI remedy (D17.13).
