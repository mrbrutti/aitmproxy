# `capture.status` verb design

**Status:** approved — self-approved 2026-10-31 by the orchestrating session (autonomous mode, memory `aitmproxy-autonomous-approve-merge-mode`). All ten Architect's calls accepted. One orchestrator correction: CS-AC15's no-leak scan dropped the substring `token` (the result's own key `scope_tokens` contains it; the key-set check in CS-AC14 already forbids any undeclared `token`/`pid` key).
**Research inputs:**
`docs/superpowers/specs/2026-10-30-aitmproxy-macos-ne-live-feeder-design.md`
(the feeder this verb reports on; its Open question 2 deferred exactly this),
`docs/superpowers/specs/2026-10-31-ne-no-scope-honest-state-design.md`
(the "Capturing while nothing is captured" incident), and the source files
the design cites: `crates/aitm/src/macos_capture/{feeder,capability,config,
scope_spec,listener,peer_auth,mod}.rs`, `crates/aitm/src/wire.rs`,
`crates/aitm/src/main.rs`, `crates/aitm-plugins/src/{control,agent,capture,
detail}.rs`, `crates/aitm-core/src/{command,value,registry,audit}.rs`,
`crates/aitm/tests/{frontends,macos_capture_capability,
macos_ne_feeder_loopback}.rs`, `apps/mac/Sources/AitmproxyKit/{CaptureCapability,
CaptureAdvice,FlowSummary}.swift`, `apps/mac/Sources/AitmproxyKit/Panels/CAStatus.swift`,
`apps/mac/Sources/AitmBusClient/JSONValue.swift`,
`docs/design/operator-ui-foundation.md` §4.3, `.github/workflows/ci.yml`.

## Intent

The macOS Network/System Extension capture path has a core-side feeder
(`CaptureSession` in `crates/aitm/src/macos_capture/feeder.rs`) that binds the
Unix sockets, publishes the rendezvous, verifies the provider's code signature,
pushes the scope spec and pumps claimed flows into `crate::ingress`. Nothing
exposes any of that over the bus. `CaptureCapability`
(`macos_capture/capability.rs`) exists to describe the capture path's state but
is dead code: only `crates/aitm/tests/macos_capture_capability.rs` names it. So
the macOS app infers "Capturing" from its own `NETransparentProxyManager`
tunnel status, and on 2026-10-31 it read "Capturing" while nothing was captured
because the core's scope was empty. A sibling session is designing one
Core/Bus/NE status UI and needs honest core facts to read. This spec adds one
read-only bus verb, `capture.status`, that reports what the core actually
knows: whether the on-switch is set, whether the feeder is listening, whether a
verified provider is attached, what scope it was last pushed, and how many
flows have been handed off.

`proxy.status` (`crates/aitm-plugins/src/control.rs`) already has a
`capturing` field that means the record/pause toggle, not the extension. This
verb is separate and that field is untouched.

## Goals

- A bus verb `capture.status` (`Sensitivity::Read`, no parameters) exists on
  every platform and every configuration, so `tools/list` is stable and a
  disabled or non-macOS core returns an honest shape rather than an error.
- The result carries the on-switch (`enabled`), the feeder state
  (`off`/`listening`/`bind_failed` with a reason), the provider state
  (`detached`/`attached` with attach time and the team id the signature was
  verified against), the scope tokens last pushed to the provider, per-kind
  handoff counts, the last handoff time, and the derived `CaptureCapability`
  as a wire string.
- `CaptureCapability` gains the two states the core can actually observe and
  stops being dead code: the verb derives it from core facts.
- `CaptureSession` records every state change into a shared, lock-light
  status handle; the hot path (one flow handed off) costs two relaxed atomic
  operations and takes no lock.
- The macOS Kit gains a decoder for the result (`CaptureStatus.swift`), tested,
  with no UI change.

## Non-goals

- No UI change: nothing under `apps/mac/Sources/Aitmproxy/`, nothing in
  `apps/web`, nothing in `crates/aitm-tui`. The Kit decoder is the only Swift
  change. The Kit's `CaptureCapability.swift` and `CaptureAdvice.swift` are not
  modified; the core's facts are not folded into the app's enum here (the UI
  session does that).
- No new `unsafe`, and no `kSecCodeInfoTeamIdentifier`. The safe
  `security-framework` 3.7 `SecCode` API has no signing-information accessor
  and the workspace forbids `unsafe` outside `aitm-peer-token`, so the real
  signing team id is not read. The verb reports the team id the satisfied
  requirement pins, and says so in its schema.
- No change to `proxy.status`, its `capturing` field, or its schema snapshot in
  `crates/aitm/tests/fixtures/operator-tool-schemas.json`.
- No push/subscription (`capture.subscribe`); polling only. No
  `capture.enable`/`disable`/`restart` verbs. No counters for shed, evicted,
  rejected-peer or refused flows (follow-up candidates). No per-flow detail
  (which flows): counts only. No persistence of counters across restarts.
- No install/approval state. The core cannot see system-extension
  installation or the System Settings approvals; those stay app-side facts.
- No change to the scope-spec emitter or the provider grammar.

## Anti-goals

- **Claiming "capturing" when nothing is captured.** The incident this fixes.
  The derived capability may read `capturing` only when a verified provider is
  attached and at least one flow has been handed off during that attachment.
- **A bus path that touches the feeder.** No verb may bind, start, stop,
  restart or reconfigure the feeder or widen its scope; `macos_capture.enabled`
  in the config file remains the only on-switch.
- **Leaking operator-private detail.** The result must never contain the bus
  token, a socket path or directory, the rendezvous path, an audit token, a
  pid, or any filesystem path at all.
- **Slowing the capture path.** No mutex on the per-flow handoff; no I/O in
  `snapshot()`.
- **Erroring where it should report.** `enabled: true` on a Linux build, or
  the one-shot CLI mode where the feeder never runs, must return the honest
  `off` shape with the right reason, never an error.
- **Destabilising `tools/list`.** The verb is registered unconditionally; a
  Linux CI build and a macOS build advertise the same tool set.

## Constraints

- **Rust gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`,
  on macOS (dev) and on `ubuntu-latest` (`.github/workflows/ci.yml`). The new
  module compiles and its sandbox tests pass on both; the only platform
  sensitivity is reading `cfg!(target_os = "macos")` as a boolean.
- **Dependency direction.** `aitm` depends on `aitm-plugins`, not the reverse,
  and the status handle must live beside the feeder. The verb therefore lives
  in the `aitm` crate (precedent: `struct PocCommands` in `wire.rs` implements
  `aitm_core::Plugin` locally).
- **Registration order.** `wire::assemble_with_scripts` registers every plugin
  and then calls `builder.build()`; `build_capture_session` is called later by
  `main.rs` (~line 444) with the `Assembled`'s `l4_ingress`/`l4_guard`. The
  status handle must be created inside `assemble_with_scripts`, handed to the
  verb's plugin before `build()`, exposed as a new `pub` field on `Assembled`,
  and threaded through `build_capture_session` into `CaptureSession`.
  `main.rs` destructures `Assembled` naming every `pub` field explicitly (its
  comment forbids absorbing a new field in `..`), so `main.rs` changes too.
- **Tripwires that must stay green.** `wire.rs::no_agent_path_to_capture_session`
  scans every `crates/*/src/**/*.rs` outside `aitm/src/main.rs`,
  `aitm/src/wire.rs` and `aitm/src/macos_capture/` for `build_capture_session(`
  and `CaptureSession::`; the status module adds no new way to build or run a
  session. `ingress.rs::one_choke_point_survives_ingress` still passes.
- **Tool-set contract.** `crates/aitm/tests/frontends.rs::EXPECTED_TOOLS`
  (`[&str; 58]`) is compared exactly against the default assembly's
  `tools/list` by `ac7_exact_tool_set`, and
  `tests/e2e/mcp/test_tool_list_complete.py` derives its expected set from that
  constant and calls every tool as the agent with empty arguments. Adding the
  verb means adding `"capture.status"` there (count 59); the e2e cell then
  classifies it `callable`.
  *Orchestrator amendment after the Terminal gate (2026-10-31):* a second
  contract exists. `crates/aitm/tests/tui_live_bus.rs` asserts every tool the
  live core serves is in `aitm_tui::CORE_TOOLS` (`crates/aitm-tui/src/lib.rs`),
  and `crates/aitm-tui/tests/tester_shell.rs` asserts the TUI bus fixture
  (`crates/aitm-tui/fixtures/bus-fixture.json`) filtered by `CORE_TOOLS` equals
  `CORE_TOOLS` (count 62 with this verb). Both must list `capture.status`.
- **No new third-party crate.** Timestamps use `std::time::SystemTime` only;
  `crates/aitm/Cargo.toml` gains no dependency.
- **`unsafe_code = "forbid"`** stays in force for the `aitm` crate.
- **Peer-verifier seam.** `PeerVerifier` (`peer_auth.rs`) gains only an
  additive default method; `verify`'s signature and fail-closed contract do not
  change, so `StubVerifier`, `PanickingVerifier` and `ScriptedVerifier`
  compile unchanged.
- **Swift.** Kit code only (`apps/mac/Sources/AitmproxyKit/` and
  `apps/mac/Tests/AitmproxyKitTests/`). Swift Testing (`@Suite struct`,
  `@Test func`, `#expect`). Tests run from `apps/mac` via
  `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build` in the
  Terminal panel. The new Kit file must not contain the token `capture.enabled`
  (the capture tripwires `apps/mac/tools/check-capture-operator-only.sh` and
  `check-capture-toggle.sh` grep Swift sources for it); both tripwires exit 0.
- **Tests that bind a real Unix socket** need the Terminal panel; every unit
  test here uses `UnixStream::pair()` or drives the handle directly, and only
  the existing loopback integration test
  (`crates/aitm/tests/macos_ne_feeder_loopback.rs`, Terminal-panel, skips
  itself when the bind is refused) is extended.

## Design

### D1. Module and types (`crates/aitm/src/macos_capture/status.rs`)

A new module, declared `pub mod status;` in `macos_capture/mod.rs`, holding
both the shared status handle and the bus verb **(Architect's call, confirming
the brief's recommendation)**: the verb needs the handle's private snapshot
type, both must stay inside `macos_capture` so the tripwire allow-list and the
`pub(super)` visibility below work, and a cross-crate trait in `aitm-plugins`
would invert the dependency direction for one read-only command.

The handle is split into a writer and a reader so "read-only from the verb" is
a type-level fact, not a review convention (precedent: the sealed `Governance`
type in `wire.rs`) **(Architect's call)**:

```rust
pub struct CaptureStatus;                      // the shared state; no pub fields
impl CaptureStatus {
    pub fn channel(enabled: bool) -> (CaptureStatusWriter, CaptureStatusReader);
    pub(crate) fn channel_on(enabled: bool, macos: bool) -> (CaptureStatusWriter, CaptureStatusReader);
}
#[derive(Clone)] pub struct CaptureStatusWriter(/* Arc<shared> */);
#[derive(Clone)] pub struct CaptureStatusReader(/* Arc<shared> */);
impl CaptureStatusReader { pub fn snapshot(&self) -> CaptureStatusSnapshot; }
```

`channel` evaluates `cfg!(target_os = "macos")` itself; `channel_on` lets a
test on this Mac exercise the non-macOS branch. The reader has exactly one
public method, `snapshot()`. A `compile_fail` doctest on `CaptureStatusReader`
shows that calling a writer method on a reader does not compile (precedent:
the `Governance` doctest in `wire.rs`).

Writer methods are `pub(super)` (visible to `macos_capture::*`, i.e. the
feeder and this module's tests; invisible to `wire.rs`, `main.rs`, every other
crate and every integration test):

```rust
impl CaptureStatusWriter {
    pub(super) fn listening(&self);
    pub(super) fn bind_failed(&self, reason: String);
    pub(super) fn stopped(&self);
    #[must_use] pub(super) fn attached(&self, team_id: Option<String>, tokens: Vec<String>) -> Attachment;
    pub(super) fn scope_pushed(&self, tokens: Vec<String>);
    pub(super) fn handed_off(&self, kind: FlowKind);
}
pub struct Attachment;   // RAII: Drop records the detach (D3)
pub(crate) fn scope_tokens(spec: &ScopeSpec) -> Vec<String>;   // spec.spec.split_ascii_whitespace()
```

Storage: one `std::sync::Mutex` over a small struct holding `FeederState`,
`ProviderState` and the `Vec<String>` of tokens (locked only at attach, detach,
scope push and `snapshot()`; recovered from poisoning with
`PoisonError::into_inner` as `feeder.rs::lock` does), plus atomics for the
counters and timestamps: `AtomicU64` `tcp_handed_off`, `udp_handed_off`,
`last_handoff_at_ms`, and the attach time. A timestamp of `0` means "none"
(a real epoch-millisecond value is never 0; a pre-1970 clock reads as none,
documented).

The snapshot:

```rust
pub struct CaptureStatusSnapshot {
    pub enabled: bool,
    pub feeder: FeederState,
    pub provider: ProviderState,
    pub scope_tokens: Vec<String>,
    pub tcp_handed_off: u64,
    pub udp_handed_off: u64,
    pub last_handoff_at_ms: Option<u64>,
}
pub enum FeederState { Off(OffReason), Listening, BindFailed(String) }
pub enum OffReason { Disabled, NotMacos, NotStarted, Stopped }   // as_str(): D7's closed vocabulary
pub enum ProviderState { Detached, Attached { attached_at_ms: u64, team_id: Option<String> } }
impl CaptureStatusSnapshot {
    pub fn capability(&self) -> CaptureCapability;   // D5
    pub fn to_value(&self) -> aitm_core::Value;        // D7, the exact wire shape
}
```

Initial state at `channel(enabled)`: counters 0, no timestamps, provider
`Detached`, tokens empty, and feeder `Off` with the reason derived from the
two facts the constructor has: `!enabled` → `Disabled`;
`enabled && !macos` → `NotMacos`; `enabled && macos` → `NotStarted`. This is
the state the verb reports when the feeder is never run: a disabled core, a
Linux core, the one-shot CLI mode (`Mode::Cli` in `main.rs` returns before the
session is built), or the window before `run` binds.

### D2. Semantics of each field

- `enabled`: `features.macos_capture.enabled` as passed to `channel`, fixed for
  the process. Only the config file sets it (`macos_capture/config.rs`).
- `feeder`: `off` (with one of the four reasons), `listening`, or
  `bind_failed` (with a reason). `bind_failed` is terminal for the session:
  `run_session` returns before its accept loop, so `stopped` is never recorded
  over it and the failure stays visible until the core restarts.
- `provider`: `detached` or `attached`. `attached_at` is the time the initial
  `Scope` was sent (the moment `feeder.rs` logs "capture provider attached").
  `team_id` is `PeerVerifier::team_id()` of the verifier that accepted the
  peer (D4).
- `scope_tokens`: the tokens of the `ScopeSpec` most recently sent to the
  attached provider, exactly as `provider_scope_spec` emitted them:
  `spec.split_ascii_whitespace()`, which round-trips because the emitter never
  emits a token containing whitespace (`scope_tokens(..).join(" ") == spec`).
  Empty when detached (no provider holds a scope). `scope_entries` is
  `scope_tokens.len()`.
- `flows_handed_off.{tcp,udp}` and `last_handoff_at`: per attachment
  **(Architect's call)**. Zeroed when a provider attaches and when it
  detaches, so they describe the current attachment only and a detached
  provider always shows zeros. A handoff is one pump spawned: a paired
  `FlowOpen` + data socket that claimed a concurrency slot in
  `CaptureSession::start_pump`; shed flows (cap reached) are not counted. The
  kind is `FlowOpen.kind` (`FlowKind::Tcp`/`Udp`, `listener.rs`).
- `capability` / `capability_reason`: D5.

Ordering guarantee: every write except `handed_off` happens on the attachment's
own task inside `serve_control`; `handed_off` is called synchronously from the
pairing code (`start_pump`, reached from the control read loop or a data
acceptor, both polled by the same `serve_attachment` task), never from inside a
pump. So within one attachment the writes are sequenced and a detach cannot
race a count. `snapshot()` reads the atomics after taking the mutex; it is a
consistent view at that granularity, not a transaction.

### D3. Update points in `feeder.rs`

`CaptureSession::new` gains a sixth parameter, `status: CaptureStatusWriter`
(required, not a builder method, so no caller can forget it):

```rust
pub fn new(ingress: Arc<CoreIngress>, l7_guard: Arc<dyn ScopeRateGuard>,
           l4_guard: Option<Arc<L4Guard>>, verifier: Arc<dyn PeerVerifier>,
           socket_dir: PathBuf, status: CaptureStatusWriter) -> Self;
```

| Where (today's code) | Record |
|---|---|
| `run_session`: `CaptureListener::bind` → `Err(e)` | `bind_failed("cannot bind the capture sockets (<e.kind()>)")` |
| `run_session`: `publish_rendezvous` → `Err(e)` | `bind_failed("cannot publish the rendezvous file (<e.kind()>)")` — same "cannot start" class |
| `run_session`: after the `info!("… listening")` | `listening()` |
| `serve_control`: after the initial `Scope` send succeeds, beside `info!("capture provider attached")` | `let _attachment = status.attached(verifier.team_id(), scope_tokens(&last_sent));` held for the rest of `serve_control` |
| `serve_control` `scope_loop`: after a re-push succeeds | `scope_pushed(scope_tokens(&spec))` |
| `serve_control` returns or its future is dropped | `Attachment::drop` records the detach (provider `Detached`, tokens cleared, counters and `last_handoff_at` zeroed). RAII, because at shutdown `run_session`'s `select!` drops `serve_attachment` mid-flight and the `info!("capture provider detached")` line never runs |
| `start_pump`: after `claim_slot` succeeds, before `spawn_pump` | `handed_off(open.kind)` |
| `run_session`: after the accept loop, beside `info!("… stopped")` | `stopped()` (feeder `Off(Stopped)`, provider forced `Detached`, tokens and counters cleared) |
| `run`: the `catch_unwind` error branch | `stopped()` too, via a writer clone taken before `run_session` is polled, so a panicked feeder never reads `listening` forever |

Reason strings for `bind_failed` use `io::ErrorKind`'s `Display`, not the
error's full `Display`: `listener.rs::refuse_symlink` and `rendezvous.rs` embed
the directory path in their messages, and the result must carry no path (the
operator log already has the full error with the path). The reason therefore
matches `^cannot (bind the capture sockets|publish the rendezvous file) \([^/]+\)$`.

### D4. Team id (`peer_auth.rs`)

Additive default method on the seam **(Architect's call: option (a))**:

```rust
pub trait PeerVerifier: Send + Sync {
    fn verify(&self, fd: RawFd) -> bool;                 // unchanged
    fn team_id(&self) -> Option<String> { None }         // new, default None
}
pub const PROVIDER_TEAM_ID: &str = "995PCLM9KH";         // new
```

`CodeSignatureVerifier` carries `team_id: Option<String>`: `Default` (the
production requirement) sets `Some(PROVIDER_TEAM_ID)`; `with_requirement(req)`
sets `None`, because an arbitrary requirement need not pin a team and the
verifier must not guess. No parsing of the requirement string. A test pins
`PROVIDER_REQUIREMENT.contains(PROVIDER_TEAM_ID)` so the constant cannot
drift from the requirement it describes (precedent:
`provider_requirement_matches_the_swift_constant`). The schema description of
`provider.team_id` reads: "The Apple team identifier the provider's code
signature was verified against (the requirement's pinned OU); not read from
the peer's signing information. Null when detached or when the verifier pins
no team."

Option (b), changing `verify` to return an identity, is rejected: it churns
every verifier and test for a value the safe API cannot supply anyway.

### D5. Deriving `CaptureCapability` (`capability.rs` + `status.rs`)

The core knows three facts: feeder `off`/`listening`/`bind_failed`, provider
`detached`/`attached`, handoffs this attachment. It cannot know installation
or approval. The existing enum has no honest variant for "listening, no
provider yet" (`Degraded` would alarm the operator during the normal
pre-approval window; `ExtensionNotInstalled`/`PendingApproval` would claim
knowledge the core lacks) nor for "feeder off". So the Rust enum gains two
variants **(Architect's call)** rather than reusing existing ones with caveats:

```rust
pub enum CaptureCapability {
    ExtensionNotInstalled,          // app-side; never produced by the verb
    PendingApproval,                // app-side; never produced by the verb
    ApprovedAttached,
    Capturing,
    Degraded(String),
    FeederOff(String),              // new: the core's feeder is off; carries the off reason
    AwaitingProvider,               // new: feeder listening, no verified provider attached
}
impl CaptureCapability { pub fn wire_name(&self) -> &'static str; }   // new, total
```

Wire names: `extension_not_installed`, `pending_approval`, `approved_attached`,
`capturing`, `degraded`, `feeder_off`, `awaiting_provider`.

Derivation (`CaptureStatusSnapshot::capability`), in precedence order:

| Facts | Capability | `capability_reason` |
|---|---|---|
| feeder `bind_failed(r)` | `Degraded(r)` | `r` |
| provider `attached`, `tcp + udp > 0` | `Capturing` | null |
| provider `attached`, `tcp + udp == 0` | `ApprovedAttached` | null |
| feeder `listening`, provider `detached` | `AwaitingProvider` | null |
| feeder `off(r)` | `FeederOff(r.as_str())` | `r.as_str()` |

A provider that passed the code-signature check and attached is necessarily
an approved, running extension, so `ApprovedAttached` is an honest inference.
`Capturing` requires a handoff in this attachment, which an empty scope can
never produce (the provider's `ScopeMatcher` matches nothing for an empty
spec), so the incident state reads `approved_attached` with
`scope_entries: 0`. If the scope is emptied after flows were captured, the
capability stays `capturing` for that attachment; the UI must combine
`capability` with `scope_entries == 0` for its "on, nothing in scope" advice,
exactly as `CaptureAdvice.make` already combines capability with the scope
count. The rule `capability_reason` is non-null iff the variant carries a
reason.

`is_attached()` is unchanged (`ApprovedAttached | Capturing`).
`gate_wire_verb` is unchanged; `degradation_reason`'s match is exhaustive, so
the compiler forces the two new arms:

- `FeederOff(why)`: "macOS capture runs through the Network/System Extension,
  but this core's capture feeder is off ({why}); it runs only on a macOS build
  with `macos_capture.enabled: true` in the config file".
- `AwaitingProvider`: "macOS capture runs through the Network/System
  Extension; the core is listening but no extension provider is attached —
  approve the extension in System Settings and turn capture on in the app to
  capture live" (contains "approve the extension", matching the existing
  test's expectation style).

`crates/aitm/tests/macos_capture_capability.rs` stays green unmodified.

### D6. The verb (`status.rs`)

```rust
pub struct CaptureStatusPlugin;                               // holds a CaptureStatusReader
impl CaptureStatusPlugin { pub fn new(reader: CaptureStatusReader) -> Self; }
impl aitm_core::Plugin for CaptureStatusPlugin { /* name() == "capture_status"; load() adds the command */ }
struct CaptureStatusCommand;                                  // holds the same reader
impl aitm_core::Command for CaptureStatusCommand {
    fn name(&self) -> &str;                                   // "capture.status"
    fn sensitivity(&self) -> Sensitivity;                     // Sensitivity::Read  (mutates() derives false)
    fn schema(&self) -> ParamSchema;                          // params: [], result: TypeDesc::Object(..) fully described
    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value>;  // ignores args; Ok(reader.snapshot().to_value())
}
```

`invoke` reads nothing from `args` or `host` and never errors. The schema's
`result` is a `TypeDesc::Object(Vec<ParamDef>)` describing every field, with
nested `TypeDesc::Object` for `feeder`, `provider` and `flows_handed_off`,
`TypeDesc::Array(Str)` for `scope_tokens`, `TypeDesc::Int` for counts and
epoch-millisecond times, and `TypeDesc::Bool` for `enabled` (precedent:
`summary_fields()`/`row_fields()` in `aitm-plugins/src/capture.rs`). Keys are
always present; nullable ones (`feeder.reason`, `provider.attached_at`,
`provider.team_id`, `last_handoff_at`, `capability_reason`) are marked
`required: false` and emitted as `Value::Null` when absent, as `flow.get`'s
`status` is. `Sensitivity::Read` makes the verb callable under the agent's
`ReadOnly` policy (`aitm-mcp/src/server.rs`), which is intended: the result
reveals nothing an agent cannot already read via `scope.list`, plus a public
team identifier and counters.

### D7. Wire shape

Keys sorted as `Value::Object`'s `BTreeMap` renders them. Timestamps are Unix
epoch milliseconds as integers (D9).

Disabled (the default build, any platform; also any config file without a
`macos_capture` section):

```json
{
  "capability": "feeder_off",
  "capability_reason": "macos_capture.enabled is false",
  "enabled": false,
  "feeder": { "reason": "macos_capture.enabled is false", "state": "off" },
  "flows_handed_off": { "tcp": 0, "udp": 0 },
  "last_handoff_at": null,
  "provider": { "attached_at": null, "state": "detached", "team_id": null },
  "scope_entries": 0,
  "scope_tokens": []
}
```

Enabled but off: the same shape with `"enabled": true` and `feeder.reason` /
`capability_reason` one of the other three vocabulary strings:
`"not a macOS build"` (any non-macOS build), `"not started"` (macOS, before
`run` binds, or the one-shot CLI mode), `"stopped"` (after shutdown). The
closed vocabulary of `feeder.reason` when `state == "off"` is exactly these
four strings, pinned by test, so clients may match on them.

Bind failed (macOS, enabled, the socket directory unusable):

```json
{
  "capability": "degraded",
  "capability_reason": "cannot bind the capture sockets (not a directory)",
  "enabled": true,
  "feeder": { "reason": "cannot bind the capture sockets (not a directory)", "state": "bind_failed" },
  "flows_handed_off": { "tcp": 0, "udp": 0 },
  "last_handoff_at": null,
  "provider": { "attached_at": null, "state": "detached", "team_id": null },
  "scope_entries": 0,
  "scope_tokens": []
}
```

Listening, no provider yet (macOS, enabled, extension not approved or the app
has capture off):

```json
{
  "capability": "awaiting_provider",
  "capability_reason": null,
  "enabled": true,
  "feeder": { "reason": null, "state": "listening" },
  "flows_handed_off": { "tcp": 0, "udp": 0 },
  "last_handoff_at": null,
  "provider": { "attached_at": null, "state": "detached", "team_id": null },
  "scope_entries": 0,
  "scope_tokens": []
}
```

Attached and capturing (L7 scope `example.com`, `*.example.com`; L4 capture
entry `198.51.100.7/32` any port):

```json
{
  "capability": "capturing",
  "capability_reason": null,
  "enabled": true,
  "feeder": { "reason": null, "state": "listening" },
  "flows_handed_off": { "tcp": 12, "udp": 3 },
  "last_handoff_at": 1761907305123,
  "provider": { "attached_at": 1761907200000, "state": "attached", "team_id": "995PCLM9KH" },
  "scope_entries": 3,
  "scope_tokens": ["example.com", "*.example.com", "198.51.100.7"]
}
```

The same attachment with `"flows_handed_off": { "tcp": 0, "udp": 0 }` and
`"last_handoff_at": null` reads `"capability": "approved_attached"`; with an
empty scope it additionally reads `"scope_entries": 0, "scope_tokens": []`,
which is the incident state, now honest.

### D8. Registration and wiring (`wire.rs`, `main.rs`)

In `assemble_with_scripts`, immediately before the plugin registrations:
`let (capture_status, capture_status_reader) = CaptureStatus::channel(features.macos_capture.enabled);`
then `.register_plugin(Box::new(CaptureStatusPlugin::new(capture_status_reader)))`
directly after `ControlPlugin` (beside `proxy.status`), on every platform and
for every `Features`. `Assembled` gains
`pub capture_status: CaptureStatusWriter` (documented: "write side of the
`capture.status` handle; move it into `build_capture_session`; dropping it
unused leaves the verb reporting the constructor's `off` state").

`build_capture_session` gains a seventh parameter and threads it through:

```rust
pub fn build_capture_session(features: &Features, ingress: CoreIngress,
    l7_guard: Arc<dyn ScopeRateGuard>, l4_guard: Option<Arc<L4Guard>>,
    verifier: Arc<dyn PeerVerifier>, socket_dir: PathBuf,
    status: CaptureStatusWriter) -> Option<CaptureSession>;
```

When `features.macos_capture.enabled` is false the writer is dropped and the
state stays `off`/`macos_capture.enabled is false`. `main.rs` names
`capture_status` in its `Assembled` destructure and passes it to
`build_capture_session` inside the existing `cfg!(target_os = "macos")` arm;
on other platforms the writer is dropped and the state stays
`off`/`not a macOS build` from construction. The existing wire tests'
`build_with` helper passes `CaptureStatus::channel(..).0`.

`crates/aitm/tests/frontends.rs`: `EXPECTED_TOOLS` becomes `[&str; 59]` with
`"capture.status"` added next to `"proxy.status"` (with a one-line comment
naming this spec). `OPERATOR_TOOLS` and `operator-tool-schemas.json` are not
touched. `crates/aitm/tests/macos_ne_feeder_loopback.rs::build_session` passes
a writer from `CaptureStatus::channel(true)` and returns the reader in its
`Observed` struct so the loopback test can assert the live transitions (D12).

### D9. Timestamps

Unix epoch milliseconds as `Value::Int`, matching `agent.activity`'s `at`
(`aitm-plugins/src/agent.rs`: "Unix-epoch milliseconds") and
`AuditEntry::at_millis` (`aitm-core/src/audit.rs`) **(Architect's call)**. The
RFC 3339 strings `flow.detail` emits need the `time` crate, which
`crates/aitm/Cargo.toml` does not depend on, and cannot be stored in an
atomic; millisecond integers need only `std::time` and fit the lock-free hot
path. Computed as `SystemTime::now().duration_since(UNIX_EPOCH)` in
milliseconds, stored in an `AtomicU64`, emitted as `i64`. `0` is the "none"
sentinel and is emitted as `null`.

### D10. Swift decoder (`apps/mac/Sources/AitmproxyKit/CaptureStatus.swift`)

```swift
public struct CaptureStatus: Hashable, Sendable {
    public enum Feeder: Hashable, Sendable {
        case off(reason: String?)
        case listening
        case bindFailed(reason: String)
        case unknown(state: String)          // a newer core's state; never a decode failure
    }
    /// The core's derived capability, as the wire string names it. Deliberately not the
    /// app's `CaptureCapability`: the UI layer folds the two.
    public enum CoreCapability: Hashable, Sendable {
        case feederOff, awaitingProvider, approvedAttached, capturing, degraded
        case unknown(String)
        public init(wire: String)
        public var wire: String
    }
    public var enabled: Bool
    public var feeder: Feeder
    public var providerAttached: Bool
    public var attachedAt: Date?
    public var teamID: String?
    public var scopeTokens: [String]
    public var tcpHandedOff: Int
    public var udpHandedOff: Int
    public var lastHandoffAt: Date?
    public var capability: CoreCapability
    public var capabilityReason: String?
    public init(/* memberwise with defaults, as CAStatus */)
    /// Nil unless `json` is a `capture.status` object: it must carry `enabled` (Bool),
    /// `feeder.state` (String) and `capability` (String).
    public init?(json: JSONValue)
}
```

Follows `Panels/CAStatus.swift` and `FlowSummary.swift`: `JSONValue`
subscripts and `boolValue/intValue/stringValue/arrayValue`. Milliseconds
convert with `Date(timeIntervalSince1970: Double(ms) / 1000)`; a negative or
non-integral number reads as `nil` (as `FlowSummary.size` rejects absurd
sizes). Counts below zero read as 0. `scope_entries` is not decoded;
`scopeTokens.count` is the count. Nothing in this file names the app's
`CaptureCapability` or `CaptureAdvice`, and it does not contain the token
`capture.enabled`.

Tests in `apps/mac/Tests/AitmproxyKitTests/CaptureStatusTests.swift`
(`@Suite struct CaptureStatusTests`): decode each D7 example (parsed with
`JSONValue.parse`) to the expected values, including
`attachedAt == Date(timeIntervalSince1970: 1_761_907_200)` and
`capability == .capturing`; `CaptureStatus(json: .object([:])) == nil`;
`"capability": "something_new"` decodes to `.unknown("something_new")`;
`"feeder": {"state": "weird"}` decodes to `.unknown(state: "weird")`; the four
`off` reasons decode verbatim.

### D11. Documentation

`docs/design/operator-ui-foundation.md` §4.3 table gains, after the
`ca.status/...` row:

`| \`capture.status\` | \`{}\` → \`{enabled, feeder: {state: off|listening|bind_failed, reason?}, provider: {state: detached|attached, attached_at?, team_id?}, scope_entries, scope_tokens: [String], flows_handed_off: {tcp, udp}, last_handoff_at?, capability, capability_reason?}\`; times are epoch ms | Settings ▸ Capture status and the Core/Bus/NE status UI (read-only; the on-switch stays \`macos_capture.enabled\` in the config file; \`proxy.status.capturing\` is the record toggle, not this) |`

### D12. Test strategy (what proves it; the plan assigns tasks)

- **`status.rs` unit tests (sandbox):** initial state for the three
  `channel_on` inputs; each writer transition and the resulting snapshot; the
  full D5 derivation table; `to_value()` equals the D7 literals (built as
  `Value` trees, compared with `assert_eq!`); the schema/value key-set
  equivalence walk; the no-leak scan; the `compile_fail` doctest; a
  registry-level invocation (`Registry::new()`, `add_plugin`,
  `CommandHost::new(&store, &client, &guard, None)` over a `MemFlowStore`,
  a stub `ProxyClient` and a `StdGuard`, as `aitm-plugins/tests/control.rs`
  does) with empty and with junk params.
- **`feeder.rs` unit tests (sandbox), reusing the existing harness**
  (`StubVerifier`, `TestGuard`, `session_with`, `control_pair`, `attach`,
  `next_frame`): `session_with` takes a `(writer, reader)` from
  `CaptureStatus::channel(true)`; the test clones the writer and calls
  `listening()` to mirror a bound session, then asserts after the provider
  receives `Scope`: attached, tokens, `attached_at` within the test's
  before/after bounds, team id from a `StubVerifier` whose `team_id()` returns
  `Some("995PCLM9KH")` and `None` from the default; after `add_scope` and the
  second `Scope`: tokens updated; after dropping the provider: detached with
  zeros and empty tokens, capability `awaiting_provider`; aborting the
  `attach` task (`JoinHandle::abort`) also records the detach (RAII);
  `start_pump` with a TCP `FlowOpen` increments `tcp` and sets
  `last_handoff_at` (a `#[cfg(test)]` constructor for `DataConnection` over a
  `UnixStream::pair()` half is acceptable, see Left to the builder);
  `run_returns_when_the_socket_dir_is_unusable` additionally asserts the
  `bind_failed` snapshot and reason shape.
- **`wire.rs` tests (sandbox):** `assemble_with(&cfg, &capture_features(false))`
  → invoke `capture.status` from `proxy.registry_arc()` → the D7 disabled
  literal; `capture_features(true)` → `enabled: true` and reason
  `not started` on macOS / `not a macOS build` elsewhere (branch on
  `cfg!(target_os = "macos")` in the assertion); `Assembled.capture_status` is
  the writer of the same channel the registered command reads (prove by
  identity: the `enabled` the verb reports follows the `Features` passed).
- **`frontends.rs` (sandbox):** `ac7_exact_tool_set` with the 59-entry list.
- **`macos_ne_feeder_loopback.rs` (Terminal panel):** inside
  `loopback_provider_feeds_in_scope_flows_and_shutdown_cleans_up`, assert the
  reader's snapshot at each phase: `listening`/`awaiting_provider` after the
  rendezvous appears; `attached`/`approved_attached` with the fixture's tokens
  after `Scope`; `capturing` with `tcp ≥ 1` after the first TCP flow and
  `udp ≥ 1` after the UDP flow; `off`/`stopped` with provider `detached` after
  shutdown.
- **`peer_auth.rs` (sandbox):** D4's three assertions.
- **`macos_capture_capability.rs`:** unchanged, green.
- **Swift (Terminal panel):** D10's tests; `swift test` green; the two capture
  tripwires exit 0.
- **e2e:** `tests/e2e/mcp/test_tool_list_complete.py` classifies
  `capture.status` as `callable` (no edit to the cell; it derives from
  `EXPECTED_TOOLS`).

## Acceptance criteria

Tags: **[sandbox]** runs under `cargo test` in the Bash sandbox;
**[terminal]** needs the Terminal panel (real UDS bind or `swift test`);
**[structural]** a source-level tripwire.

1. **CS-AC1 Registered everywhere.** The default assembly's `tools/list`
   contains `capture.status`; `EXPECTED_TOOLS` is `[&str; 59]` including
   `"capture.status"`; `ac7_exact_tool_set` passes on macOS and on
   `ubuntu-latest`. **[sandbox]** `aitm_tui::CORE_TOOLS` and the TUI bus
   fixture list it too, so `tui_live_bus` **[terminal]** and
   `tester_shell::fixture_app_core_offers_exactly_the_core_tools_with_the_agent_surface_lit`
   **[sandbox]** pass (orchestrator amendment, 2026-10-31).
2. **CS-AC2 Read-only, parameterless, inert.** `sensitivity() == Sensitivity::Read`,
   `mutates() == false`, `schema().params.is_empty()`. Invoking with
   `Params` containing `enabled: true`, `feeder: "listening"` and
   `provider: "attached"` returns the same `Value` as invoking with no params,
   and the reader's snapshot before and after both calls is identical.
   **[sandbox]**
3. **CS-AC3 Disabled shape, literally.** With `Features::default()` (and with
   `capture_features(false)`) the verb returns exactly the D7 disabled object
   (as a `Value` tree). **[sandbox]**
4. **CS-AC4 Honest off reasons.** `channel_on(true, false)` snapshots to
   `feeder: off`, reason `not a macOS build`; `channel_on(true, true)` to
   `not started`; `channel(false)` to `macos_capture.enabled is false`; after
   a session's `run` returns normally, `stopped`. The set of `off` reasons the
   verb can emit is exactly these four strings. **[sandbox]**
5. **CS-AC5 Bind failure is reported and terminal.** After
   `run_returns_when_the_socket_dir_is_unusable`'s `run` returns: `feeder.state
   == "bind_failed"`, `capability == "degraded"`, `capability_reason ==
   feeder.reason`, the reason matches
   `^cannot bind the capture sockets \([^/]+\)$`, and the state is not
   `stopped`. **[sandbox]**
6. **CS-AC6 Listening.** After a successful bind and rendezvous publish the
   snapshot is `listening`, provider `detached`, capability
   `awaiting_provider`, `feeder.reason == null`. **[terminal]** (loopback
   test); the writer-level mapping `listening()` → that snapshot is pinned
   **[sandbox]**.
7. **CS-AC7 Attach records the facts.** In the feeder harness, once the
   provider has received its initial `Scope`: `provider.state == "attached"`,
   `attached_at` is within the test's before/after millisecond bounds,
   `team_id` equals the verifier's `team_id()` (`Some("995PCLM9KH")` from a
   stub that returns it, `None` from the default `StubVerifier`),
   `scope_tokens == ["example.com"]`, `scope_entries == 1`,
   `flows_handed_off == {tcp: 0, udp: 0}`, `capability == "approved_attached"`.
   **[sandbox]**
8. **CS-AC8 Scope re-push updates the tokens.** After `add_scope("api.test")`
   and the provider receives the second `Scope`, `scope_tokens ==
   ["example.com", "api.test"]`; `scope_tokens(&spec).join(" ") == spec.spec`
   for the emitter's output over the pinned scope fixture. **[sandbox]**
9. **CS-AC9 Detach resets, including on cancellation.** After the provider
   drops its channel: `provider.state == "detached"`, `attached_at == null`,
   `team_id == null`, `scope_tokens == []`, counters 0, `last_handoff_at ==
   null`, capability `awaiting_provider` (feeder listening). Aborting the
   `serve_control` task instead of a clean detach yields the same snapshot.
   **[sandbox]**
10. **CS-AC10 Handoffs are counted by kind.** `start_pump` with a TCP
    `FlowOpen` and a data connection yields `tcp == 1`, `udp == 0`,
    `last_handoff_at` within bounds, capability `capturing`; a UDP open yields
    `udp == 1`. A pair offered at the concurrency cap (shed) does not
    increment. **[sandbox]** End to end: the loopback test sees `tcp ≥ 1` after
    its TCP flow and `udp ≥ 1` after its UDP flow. **[terminal]**
11. **CS-AC11 Shutdown is honest.** After the loopback test's shutdown:
    `feeder == {state: off, reason: stopped}`, provider `detached`, counters 0,
    capability `feeder_off`. **[terminal]**
12. **CS-AC12 Capability derivation table.** A test enumerates every
    combination of `FeederState` (the three, with all four `OffReason`s) ×
    `ProviderState` × handoffs ∈ {0, 1} and asserts the D5 table's variant and
    wire string; `wire_name()` is total over the seven variants with the seven
    strings named in D5; the verb never emits `extension_not_installed` or
    `pending_approval` (no derivation row produces them). **[sandbox]**
13. **CS-AC13 Gate texts for the new variants.** `FeederOff(_).gate_wire_verb()`
    is `Err(L4Unavailable(r))` with `r` containing `macos_capture.enabled`;
    `AwaitingProvider.gate_wire_verb()` is `Err(L4Unavailable(r))` with `r`
    containing `approve the extension`; `is_attached()` is false for both;
    `crates/aitm/tests/macos_capture_capability.rs` passes unmodified.
    **[sandbox]**
14. **CS-AC14 Fully described schema.** Walking `schema().result` and the
    emitted `Value` of every snapshot in the CS-AC12 matrix, the set of
    described field names equals the set of emitted keys at every nesting
    level, every `ParamDef.description` is non-empty, and every nullable field
    is `required: false`. **[sandbox]**
15. **CS-AC15 No leak.** For every snapshot in the CS-AC12 matrix plus the
    CS-AC5 bind-failure snapshot, the serialized result contains none of:
    the value of `feeder::DEFAULT_SOCKET_DIR`, `control.sock`, `data.sock`,
    `.rendezvous`, or the `/` character. The result carries no `pid`,
    `audit_token`, or bus-token key (CS-AC14's key-set equivalence pins the
    declared keys; `scope_tokens` is the only key containing `token`).
    **[sandbox]**
16. **CS-AC16 Type-level read-only.** `CaptureStatusReader` has exactly one
    `pub` method, `snapshot()`; a `compile_fail` doctest shows
    `reader.listening()` does not compile; the writer's mutators are
    `pub(super)`; `CaptureStatusPlugin::new` takes a reader, not a writer.
    **[structural]**
17. **CS-AC17 Tripwires.** `wire.rs::no_agent_path_to_capture_session` and
    `ingress.rs::one_choke_point_survives_ingress` pass; `status.rs` names
    neither `build_capture_session(` nor `CaptureSession::`. **[structural]**
18. **CS-AC18 Team id source.** `CodeSignatureVerifier::default().team_id() ==
    Some("995PCLM9KH".into())`;
    `CodeSignatureVerifier::with_requirement("identifier \"x\"").team_id() ==
    None`; `PROVIDER_REQUIREMENT.contains(PROVIDER_TEAM_ID)`; a `PeerVerifier`
    implementor that does not override `team_id` returns `None`; `verify`'s
    signature is unchanged. **[sandbox]**
19. **CS-AC19 Timestamps.** `attached_at` and `last_handoff_at` are
    `Value::Int` epoch milliseconds within the test's before/after bounds when
    present, and `Value::Null` (never `0`) when absent. **[sandbox]**
20. **CS-AC20 Wiring identity.** `assemble_with(cfg, capture_features(true))`'s
    registered `capture.status` reports `enabled: true` while
    `capture_features(false)`'s reports `enabled: false`; `build_capture_session`
    with a disabled feature set drops the writer and the verb still reports
    the disabled shape; `main.rs` names `capture_status` in its `Assembled`
    destructure (the `..` comment rule holds). **[sandbox]**
21. **CS-AC21 `proxy.status` untouched.** `git diff` for the branch shows no
    change to `crates/aitm-plugins/src/control.rs`,
    `crates/aitm-plugins/tests/control.rs` or
    `crates/aitm/tests/fixtures/operator-tool-schemas.json`; the control tests
    pass. **[structural]**
22. **CS-AC22 Swift decoder.** `CaptureStatusTests` passes under `swift test`:
    the four D7 examples decode to the expected values (including
    `attachedAt == Date(timeIntervalSince1970: 1_761_907_200)`,
    `lastHandoffAt == Date(timeIntervalSince1970: 1_761_907_305.123)`,
    `capability == .capturing`, `teamID == "995PCLM9KH"`, `scopeTokens ==
    ["example.com", "*.example.com", "198.51.100.7"]`), `CaptureStatus(json:
    .object([:])) == nil`, an unknown capability string decodes to
    `.unknown(_)`, an unknown feeder state to `.unknown(state:)`. **[terminal]**
23. **CS-AC23 Kit boundary.** `git diff` shows no change under
    `apps/mac/Sources/Aitmproxy/`, to `CaptureCapability.swift` or
    `CaptureAdvice.swift`; the new Kit file does not contain the token
    `capture.enabled`; `apps/mac/tools/check-capture-operator-only.sh` and
    `check-capture-toggle.sh` exit 0. **[structural]**
24. **CS-AC24 Docs.** `docs/design/operator-ui-foundation.md` §4.3 contains a
    `capture.status` row naming the result fields, epoch-ms times, and that
    `proxy.status.capturing` is the record toggle. **[structural]**
25. **CS-AC25 Gate.** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
    passes on macOS; the CI job on `ubuntu-latest` passes; no new dependency
    in `crates/aitm/Cargo.toml` or `Cargo.lock`; `unsafe_code = "forbid"`
    unchanged. **[sandbox]**

## Left to the builder

- The private layout of the shared state (one `Mutex<Inner>` plus atomics, as
  D1 describes, or an equivalent that keeps `handed_off` lock-free), the atomic
  orderings (`Relaxed` is sufficient; `snapshot()` takes the mutex first), and
  whether `Attachment` holds a writer clone or a borrowed `Arc`.
- How `run` obtains a writer for its panic branch (a clone before polling
  `run_session` is the obvious way).
- How the sandbox `start_pump` test obtains a `DataConnection`: a
  `#[cfg(test)] pub(crate)` constructor in `listener.rs` over one half of a
  `tokio::net::UnixStream::pair()` is acceptable; so is any other test-only
  seam that does not change production behaviour.
- The exact wording of `ParamDef.description`s beyond the `team_id` text D4
  fixes, and whether `Command::summarize` returns a one-liner (e.g.
  `capture: capturing, 12 tcp / 3 udp`) for the TUI; `None` is acceptable.
- Whether the registry-level test in `status.rs` builds its `CommandHost` over
  `MemFlowStore` + a stub client + `StdGuard` (the `control.rs` precedent) or
  reuses another in-crate stub.
- The Swift memberwise `init`'s default values and the exact `@Test` names.
- The one-line comment beside `"capture.status"` in `EXPECTED_TOOLS`.

## Open questions

None. Every decision here is either fixed by the brief or labelled an
Architect's call below for Matt to confirm or correct.

## Architect's calls (for approval)

1. **Module placement:** both the handle and the verb in
   `crates/aitm/src/macos_capture/status.rs`, registered unconditionally in
   `assemble_with_scripts` right after `ControlPlugin` (D1, D8).
2. **Writer/reader split** with `pub(super)` mutators and a `compile_fail`
   doctest, instead of one handle with convention-enforced read-only use (D1,
   CS-AC16).
3. **Two new `CaptureCapability` variants**, `FeederOff(String)` and
   `AwaitingProvider`, with wire names `feeder_off` / `awaiting_provider`, and
   the precedence table in D5; `ApprovedAttached` is inferred from a verified
   attachment; `Capturing` requires a handoff in the current attachment.
4. **Per-attachment counters:** `flows_handed_off` and `last_handoff_at` are
   zeroed at attach and at detach, so a detached provider shows zeros (D2).
5. **Detach via RAII** (`Attachment` guard) so shutdown cancellation records
   it; `stopped()` also forces `detached` (D3).
6. **`off` reason vocabulary** of exactly four strings:
   `macos_capture.enabled is false`, `not a macOS build`, `not started`,
   `stopped`; `not started` added for the pre-bind window and the one-shot CLI
   mode (D7, CS-AC4).
7. **Bind-failure reasons** carry `io::ErrorKind`'s text, not the error's full
   `Display`, so no path can leak (D3, CS-AC15).
8. **Team id via option (a):** additive `PeerVerifier::team_id()` defaulting
   to `None`; `CodeSignatureVerifier` returns `Some(PROVIDER_TEAM_ID)` only
   under the production requirement (D4).
9. **Epoch-millisecond integers** for timestamps, matching `agent.activity.at`,
   with `0` as the internal none-sentinel emitted as `null` (D9).
10. **Swift decoder shape:** a nested `CoreCapability` enum with an
    `unknown(String)` case and a `Feeder` enum with `unknown(state:)`, kept
    distinct from the app's `CaptureCapability`; `scope_entries` not decoded
    (D10).
