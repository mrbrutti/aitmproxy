# `capture.status` verb implementation plan

**Status:** approved — self-approved 2026-10-31 by the orchestrating session (autonomous mode, memory `aitmproxy-autonomous-approve-merge-mode`); plan-level calls P1–P4 accepted.
**Spec:** `docs/superpowers/specs/2026-10-31-capture-status-verb-design.md` (approved 2026-10-31, commit `ff1105d`)
**Branch / worktree:** `claude/blissful-boyd-34f6a5` (already cut; this worktree, no new one)

## Overview

Five tasks. **Tasks 1 → 2 → 3 are a sequential Rust chain**: Task 1 adds the
pure types (the status handle, the two `CaptureCapability` variants, the
`team_id()` seam); Task 2 wires the writer into the feeder and threads it through
`CaptureSession::new` → `build_capture_session` → `Assembled` → `main.rs`
(one compile unit, so it is one task) and proves every transition in the feeder
harness and the loopback test; Task 3 adds the bus verb, registers it, and pins
the tool-set contract. **Task 4 (Swift Kit decoder) and Task 5 (the §4.3 docs
row) are independent of each other and of the chain** and may run in parallel
with Task 1 from the start; they share no file with any other task.

```
Task 1 ──► Task 2 ──► Task 3
Task 4   (independent)
Task 5   (independent)
```

Plan-level calls, each explained at the task that carries it:

- **P1.** The wire/main plumbing (`Assembled.capture_status`, the channel in
  `assemble_with_scripts`, `build_capture_session`'s seventh parameter, the
  `main.rs` destructure) lives in **Task 2**, not Task 3: changing
  `CaptureSession::new` forces every caller to supply a writer in the same
  compile, and a throwaway writer inside `build_capture_session` would be a
  hack Task 3 then undoes. Task 2 leaves the reader unused (`_capture_status_reader`);
  Task 3 hands it to the plugin.
- **P2.** The loopback test's phase assertions (CS-AC6/10/11 **[terminal]**)
  live in **Task 2**, with `build_session`: they assert feeder transitions,
  which exist after Task 2, and the `Observed.status` field Task 2 must add
  would otherwise be an unread field (`dead_code` fails the gate).
- **P3.** Task 1's writer mutators are `pub(super)` (CS-AC16) and nothing calls
  them until Task 2, so the non-test lib build would fail `clippy -D warnings`
  on `dead_code`. Task 1 therefore carries **one scaffolding attribute**,
  `#[allow(dead_code)] // scaffolding: removed by plan Task 2, which wires feeder.rs`,
  on the `impl CaptureStatusWriter` block and on `scope_tokens`. Task 2's
  Done-when requires it gone. `channel_on` is not dead: `channel` delegates to it.
- **P4.** Per-task gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  from the worktree root. Tests that need a real Unix-socket bind self-skip in
  the Bash sandbox (the loopback test prints `skipped: UDS bind unavailable`);
  the orchestrator re-runs those in the Terminal panel. Swift builds and tests
  do not run in the sandbox at all (Task 4 notes); the orchestrator runs them.

Structural criteria no task may violate: **CS-AC21** (no change to
`crates/aitm-plugins/src/control.rs`, `crates/aitm-plugins/tests/control.rs`,
`crates/aitm/tests/fixtures/operator-tool-schemas.json`), **CS-AC23** (nothing
under `apps/mac/Sources/Aitmproxy/`, no change to `CaptureCapability.swift` or
`CaptureAdvice.swift`), **CS-AC25** (no new dependency; `unsafe_code = "forbid"`
unchanged). The Files lists below are exhaustive; a Coder needing another file
stops and reports.

Shared literals every Rust task uses (from spec D7; keys sorted as `BTreeMap`
renders them; build them as `aitm_core::Value` trees, never as JSON text):

- **disabled literal:** `{capability: "feeder_off", capability_reason: "macos_capture.enabled is false", enabled: false, feeder: {reason: "macos_capture.enabled is false", state: "off"}, flows_handed_off: {tcp: 0, udp: 0}, last_handoff_at: null, provider: {attached_at: null, state: "detached", team_id: null}, scope_entries: 0, scope_tokens: []}`
- **listening literal:** same keys; `capability: "awaiting_provider"`, `capability_reason: null`, `enabled: true`, `feeder: {reason: null, state: "listening"}`.
- **bind-failed literal:** `capability: "degraded"`, `capability_reason: "cannot bind the capture sockets (not a directory)"`, `enabled: true`, `feeder: {reason: <same string>, state: "bind_failed"}`, rest as disabled.
- **capturing literal:** `capability: "capturing"`, `capability_reason: null`, `enabled: true`, `feeder: {reason: null, state: "listening"}`, `flows_handed_off: {tcp: 12, udp: 3}`, `last_handoff_at: 1761907305123`, `provider: {attached_at: 1761907200000, state: "attached", team_id: "995PCLM9KH"}`, `scope_entries: 3`, `scope_tokens: ["example.com", "*.example.com", "198.51.100.7"]`.
- **off-reason vocabulary** (exactly four): `"macos_capture.enabled is false"`, `"not a macOS build"`, `"not started"`, `"stopped"`.
- **wire names** (seven): `extension_not_installed`, `pending_approval`, `approved_attached`, `capturing`, `degraded`, `feeder_off`, `awaiting_provider`.

## Tasks

### Task 1: status handle, capability variants, team-id seam

- **Satisfies:** CS-AC4 (writer level), CS-AC12, CS-AC13, CS-AC14 (the `to_value()` half; the schema half is Task 3), CS-AC15, CS-AC16, CS-AC17 (the `status.rs` clause), CS-AC18, CS-AC19 (null-never-0), the `to_value()` shape of CS-AC3/5/6.
- **Depends on:** none (root of the Rust chain).
- **Files:**
  - `crates/aitm/src/macos_capture/status.rs` (create)
  - `crates/aitm/src/macos_capture/mod.rs` (modify: add `pub mod status;` in alphabetical order, after `scope_spec`)
  - `crates/aitm/src/macos_capture/capability.rs` (modify)
  - `crates/aitm/src/macos_capture/peer_auth.rs` (modify)
- **Change:**

  `capability.rs` (spec D5):
  - Add variants `FeederOff(String)` and `AwaitingProvider` to `CaptureCapability`
    with doc comments ("the core's feeder is off; carries the off reason" /
    "feeder listening, no verified provider attached").
  - Add `pub fn wire_name(&self) -> &'static str` — total over the seven variants,
    returning the seven wire names above.
  - Two new arms in `degradation_reason` (the match is exhaustive; the compiler forces them):
    `FeederOff(why)` → `format!("macOS capture runs through the Network/System Extension, but this core's capture feeder is off ({why}); it runs only on a macOS build with `macos_capture.enabled: true` in the config file")`;
    `AwaitingProvider` → `"macOS capture runs through the Network/System Extension; the core is listening but no extension provider is attached — approve the extension in System Settings and turn capture on in the app to capture live"`.
  - `is_attached()` and `gate_wire_verb()` unchanged.

  `peer_auth.rs` (spec D4):
  - `pub trait PeerVerifier` gains `fn team_id(&self) -> Option<String> { None }` with a doc
    comment; `verify`'s signature is byte-for-byte unchanged.
  - `pub const PROVIDER_TEAM_ID: &str = "995PCLM9KH";` beside `PROVIDER_REQUIREMENT`.
  - `CodeSignatureVerifier` gains a private field `team_id: Option<String>`.
    `Default` sets `requirement: PROVIDER_REQUIREMENT.into(), team_id: Some(PROVIDER_TEAM_ID.into())`
    (it may no longer delegate to `with_requirement`); `with_requirement(req)` sets `team_id: None`.
    `impl PeerVerifier for CodeSignatureVerifier` adds `fn team_id(&self) -> Option<String> { self.team_id.clone() }`
    (outside any `cfg`, so it exists on every platform).

  `status.rs` (spec D1, D2, D5, D7, D9) — exactly these public items:
  ```rust
  pub struct CaptureStatus;
  impl CaptureStatus {
      pub fn channel(enabled: bool) -> (CaptureStatusWriter, CaptureStatusReader);          // = channel_on(enabled, cfg!(target_os = "macos"))
      pub(crate) fn channel_on(enabled: bool, macos: bool) -> (CaptureStatusWriter, CaptureStatusReader);
  }
  #[derive(Clone)] pub struct CaptureStatusWriter(Arc<Shared>);
  #[derive(Clone)] pub struct CaptureStatusReader(Arc<Shared>);
  impl CaptureStatusReader { pub fn snapshot(&self) -> CaptureStatusSnapshot; }             // the ONLY pub fn on the reader
  impl CaptureStatusWriter {                                                                 // all pub(super); P3 scaffolding allow on this block
      pub(super) fn listening(&self);
      pub(super) fn bind_failed(&self, reason: String);
      pub(super) fn stopped(&self);
      #[must_use] pub(super) fn attached(&self, team_id: Option<String>, tokens: Vec<String>) -> Attachment;
      pub(super) fn scope_pushed(&self, tokens: Vec<String>);
      pub(super) fn handed_off(&self, kind: FlowKind);
  }
  pub struct Attachment { /* private: a writer clone or Arc<Shared> */ }                     // impl Drop: records the detach
  pub(crate) fn scope_tokens(spec: &ScopeSpec) -> Vec<String>;                               // spec.spec.split_ascii_whitespace().map(str::to_owned).collect()
  #[derive(Debug, Clone, PartialEq, Eq)] pub struct CaptureStatusSnapshot { pub enabled: bool, pub feeder: FeederState, pub provider: ProviderState, pub scope_tokens: Vec<String>, pub tcp_handed_off: u64, pub udp_handed_off: u64, pub last_handoff_at_ms: Option<u64> }
  #[derive(Debug, Clone, PartialEq, Eq)] pub enum FeederState { Off(OffReason), Listening, BindFailed(String) }
  #[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum OffReason { Disabled, NotMacos, NotStarted, Stopped }
  impl OffReason { pub fn as_str(self) -> &'static str; }                                   // the four vocabulary strings, in that order
  #[derive(Debug, Clone, PartialEq, Eq)] pub enum ProviderState { Detached, Attached { attached_at_ms: u64, team_id: Option<String> } }
  impl CaptureStatusSnapshot { pub fn capability(&self) -> CaptureCapability; pub fn to_value(&self) -> aitm_core::Value; }
  ```
  Semantics (spec D1–D3, D5, D9), binding on the builder:
  - Initial state: counters 0, no timestamps, `Detached`, tokens empty, feeder
    `Off(Disabled)` if `!enabled`, `Off(NotMacos)` if `enabled && !macos`,
    `Off(NotStarted)` if `enabled && macos`.
  - Storage: one `std::sync::Mutex` over a small struct (feeder state, provider
    state, tokens) locked only in `attached`, `Attachment::drop`, `scope_pushed`,
    `listening`, `bind_failed`, `stopped`, `snapshot`; recovered from poisoning
    with `PoisonError::into_inner`. `AtomicU64` for `tcp_handed_off`,
    `udp_handed_off`, `last_handoff_at_ms` (and the attach time if kept outside
    the mutex). `handed_off` is two `Relaxed` atomic operations and takes no lock.
    `0` is the "none" timestamp sentinel; a pre-1970 clock reads as none.
  - Timestamps: `SystemTime::now().duration_since(UNIX_EPOCH)` in milliseconds,
    `u64::try_from(d.as_millis()).unwrap_or(0)`; emitted as `Value::Int(i64)`;
    `0`/`None` emitted as `Value::Null`.
  - `attached(team_id, tokens)`: sets `Attached { attached_at_ms: now, team_id }`,
    replaces tokens, zeroes both counters and `last_handoff_at_ms`, returns the guard.
  - `Attachment::drop`: `Detached`, tokens cleared, counters and `last_handoff_at_ms`
    zeroed. `stopped()`: feeder `Off(Stopped)` **and** the same detach clearing
    (idempotent: a later `Attachment::drop` re-clears and changes nothing else).
    `bind_failed(r)`: feeder `BindFailed(r)`. `listening()`: feeder `Listening`.
  - `capability()` in this precedence: `BindFailed(r)` → `Degraded(r)`;
    `Attached` with `tcp + udp > 0` → `Capturing`; `Attached` with `0` →
    `ApprovedAttached`; `Listening` + `Detached` → `AwaitingProvider`;
    `Off(r)` + `Detached` → `FeederOff(r.as_str().into())`. (Combinations the
    feeder cannot produce — `Off`/`BindFailed` with `Attached` — follow the same
    precedence: `BindFailed` wins over `Attached`, `Attached` wins over `Off`.)
  - `to_value()`: `Value::Object` with exactly the nine top-level keys of the
    literals; `scope_entries = scope_tokens.len()`; `capability` =
    `capability().wire_name()`; `capability_reason` = the carried string for
    `Degraded`/`FeederOff`, else `Null`; `feeder.reason` = `Null` for `Listening`,
    `as_str()` for `Off`, the string for `BindFailed`; `provider.attached_at`/`team_id`
    `Null` when `Detached`.
  - Doctests on `CaptureStatusReader` mirroring the `Governance` pair in `wire.rs`:
    one ```` ```compile_fail ```` block (`use aitm::macos_capture::status::CaptureStatus; let (_w, reader) = CaptureStatus::channel(true); reader.listening();`)
    and one plain runnable block identical except `let _ = reader.snapshot();`,
    so the `compile_fail` cannot pass for the wrong reason.

- **Test:** all **[sandbox]**, `cargo test -p aitm macos_capture` (plus
  `cargo test -p aitm --doc` for the doctests). Test module helpers Task 3
  reuses, define them with these names in `status::tests`:
  `fn now_ms() -> u64`, `fn disabled_literal() -> Value`, `fn listening_literal() -> Value`,
  `fn bind_failed_literal() -> Value`, `fn capturing_literal() -> Value`,
  `fn matrix() -> Vec<CaptureStatusSnapshot>` (every `FeederState` — the four
  `Off` reasons, `Listening`, `BindFailed("cannot bind the capture sockets (not a directory)")`
  — × `ProviderState` {`Detached`, `Attached { attached_at_ms: 1761907200000, team_id: Some("995PCLM9KH") }`}
  × handoffs {`(0,0)`, `(1,0)`, `(0,1)`}, with `enabled: true` and
  `scope_tokens: ["example.com"]` for attached rows; 36 snapshots).

  `status.rs`:
  - `channel_reports_the_three_initial_off_reasons` (CS-AC4): `channel(false).1.snapshot()`
    → `feeder == Off(Disabled)`, `enabled == false`, `to_value() == disabled_literal()`;
    `channel_on(true, false)` → `Off(NotMacos)`, `to_value()["feeder"]["reason"] == Str("not a macOS build")`,
    `["capability_reason"] == Str("not a macOS build")`, `["enabled"] == Bool(true)`;
    `channel_on(true, true)` → `Off(NotStarted)`, reason `Str("not started")`.
  - `off_reason_vocabulary_is_exactly_four` (CS-AC4): `[Disabled, NotMacos, NotStarted, Stopped].map(as_str)`
    == `["macos_capture.enabled is false", "not a macOS build", "not started", "stopped"]`.
  - `listening_then_stopped` (CS-AC4, CS-AC6 writer level): `channel_on(true, true)`; `w.listening()`
    → `to_value() == listening_literal()` and `capability() == AwaitingProvider`;
    `w.stopped()` → `feeder == Off(Stopped)`, `capability() == FeederOff("stopped".into())`,
    `to_value()["feeder"] == {reason: "stopped", state: "off"}`.
  - `bind_failed_is_degraded_and_terminal` (CS-AC5 writer level): `w.bind_failed("cannot bind the capture sockets (not a directory)".into())`
    → `to_value() == bind_failed_literal()`; `capability() == Degraded(<same string>)`;
    then `w.stopped()` is **not** called by the feeder on this path, so no assertion
    on it here (the feeder-level proof is Task 2).
  - `attach_records_facts_and_detach_resets` (CS-AC7/8/9/10 writer level, CS-AC19):
    `w.listening()`; `before = now_ms()`; `let a = w.attached(Some("995PCLM9KH".into()), vec!["example.com".into()])`;
    `after = now_ms()`; snapshot: `provider == Attached { attached_at_ms: t, team_id: Some("995PCLM9KH") }`
    with `before <= t && t <= after`, `scope_tokens == ["example.com"]`, counters `(0, 0)`,
    `last_handoff_at_ms == None`, `capability() == ApprovedAttached`,
    `to_value()["scope_entries"] == Int(1)`, `["last_handoff_at"] == Null`, `["provider"]["attached_at"] == Int(t as i64)`;
    twelve `w.handed_off(FlowKind::Tcp)` and three `Udp` → `(12, 3)`, `last_handoff_at_ms` within bounds,
    `capability() == Capturing`; `w.scope_pushed(vec!["example.com".into(), "api.test".into()])`
    → `scope_tokens == ["example.com", "api.test"]`; `drop(a)` → `Detached`, tokens `[]`,
    `(0, 0)`, `last_handoff_at_ms == None`, `capability() == AwaitingProvider`,
    `to_value()["provider"] == {attached_at: null, state: "detached", team_id: null}`.
  - `stopped_forces_detached_while_attached` (CS-AC4/11 writer level): attach, `w.stopped()`
    without dropping the guard → `Detached`, tokens `[]`, `(0, 0)`, `Off(Stopped)`;
    then `drop(guard)` leaves the snapshot identical.
  - `to_value_matches_the_capturing_literal` (CS-AC19): construct
    `CaptureStatusSnapshot { enabled: true, feeder: Listening, provider: Attached { attached_at_ms: 1761907200000, team_id: Some("995PCLM9KH") }, scope_tokens: ["example.com", "*.example.com", "198.51.100.7"], tcp_handed_off: 12, udp_handed_off: 3, last_handoff_at_ms: Some(1761907305123) }`
    → `to_value() == capturing_literal()`; the same with `(0, 0)` and `None` →
    `["capability"] == Str("approved_attached")`, `["last_handoff_at"] == Null`; the
    same with `scope_tokens: []` → `["scope_entries"] == Int(0)` (the incident state).
  - `capability_derivation_table` (CS-AC12): for every snapshot in `matrix()`, assert the
    variant and `wire_name()` from the precedence above (e.g. `BindFailed` + `Attached` + `(1,0)`
    → `Degraded`, `"degraded"`; `Off(Stopped)` + `Attached` + `(0,1)` → `Capturing`;
    `Listening` + `Detached` + any → `AwaitingProvider`); and that no row yields
    `ExtensionNotInstalled` or `PendingApproval`.
  - `result_never_leaks_paths_or_sockets` (CS-AC15): for every `matrix()` snapshot plus the
    `bind_failed` writer snapshot above, `format!("{:?}", s.to_value())` contains none of
    `super::super::feeder::DEFAULT_SOCKET_DIR`, `"control.sock"`, `"data.sock"`, `".rendezvous"`, `'/'`.
  - `scope_tokens_round_trips_the_emitter` (CS-AC8): `provider_scope_spec(&[ScopeEntry{host:"example.com"}, ScopeEntry{host:"*.example.com"}], &[<L4 capture entry 198.51.100.7/32, ports 0–65535, CAPTURE_INTERFACE, Outbound, Capture, RateCap{pps:0,burst:0}, Config>])`
    → `scope_tokens(&spec) == ["example.com", "*.example.com", "198.51.100.7"]` and
    `scope_tokens(&spec).join(" ") == spec.spec`; `scope_tokens(&ScopeSpec{spec: String::new()}) == []`.
  - `reader_has_exactly_one_pub_method` (CS-AC16, structural): `include_str!("status.rs")`;
    the slice from `"impl CaptureStatusReader {"` to its closing `"\n}"` contains exactly one
    `"pub fn "` and it is `"pub fn snapshot("`; the slice for `"impl CaptureStatusWriter {"`
    contains zero `"pub fn "` (only `pub(super) fn`).
  - `status_module_names_no_session_builder` (CS-AC17): `include_str!("status.rs")` contains
    neither `concat!("build_capture_", "session(")` nor `concat!("CaptureSession", "::")`.
  - Doctests: `cargo test -p aitm --doc` passes with the `compile_fail` and the runnable block.

  `capability.rs` (new `#[cfg(test)] mod tests`, CS-AC12/13):
  - `wire_name_is_total_over_seven_variants`: the seven variants → the seven wire names
    (`Degraded("x".into())` → `"degraded"`, `FeederOff("x".into())` → `"feeder_off"`).
  - `feeder_off_gate_names_the_config_switch`: `FeederOff("not started".into()).gate_wire_verb()`
    is `Err(L4GuardError::L4Unavailable(r))` with `r.contains("macos_capture.enabled")` and `r.contains("not started")`.
  - `awaiting_provider_gate_names_approval`: `AwaitingProvider.gate_wire_verb()` is
    `Err(L4Unavailable(r))` with `r.contains("approve the extension")`.
  - `new_variants_are_not_attached`: `!FeederOff("x".into()).is_attached()` and `!AwaitingProvider.is_attached()`.
  - `crates/aitm/tests/macos_capture_capability.rs` passes unmodified.

  `peer_auth.rs` (CS-AC18):
  - `default_verifier_pins_the_provider_team`: `CodeSignatureVerifier::default().team_id() == Some("995PCLM9KH".to_string())`.
  - `custom_requirement_pins_no_team`: `CodeSignatureVerifier::with_requirement("identifier \"x\"").team_id() == None`.
  - `team_id_constant_matches_the_requirement`: `PROVIDER_REQUIREMENT.contains(PROVIDER_TEAM_ID)`.
  - `team_id_defaults_to_none`: a local `struct Bare; impl PeerVerifier for Bare { fn verify(&self, _fd: RawFd) -> bool { false } }`
    compiles (proves `verify`'s signature is unchanged) and `Bare.team_id() == None`.

- **Done when:** every test above passes (sandbox), the doctests pass, the
  P3 scaffolding `#[allow(dead_code)]` is the only `allow` in `status.rs` and carries
  the exact comment above, and the full gate passes.

### Task 2: feeder update points, session plumbing, feeder and loopback proofs

- **Satisfies:** CS-AC4 (`stopped` after a normal `run` — loopback), CS-AC5, CS-AC6, CS-AC7, CS-AC8, CS-AC9, CS-AC10, CS-AC11, CS-AC19 (live bounds), CS-AC20 (the `main.rs` destructure clause and the "disabled drops the writer" clause at the handle level), CS-AC17 (tripwire stays green).
- **Depends on:** Task 1.
- **Files:**
  - `crates/aitm/src/macos_capture/feeder.rs` (modify)
  - `crates/aitm/src/macos_capture/listener.rs` (modify: test-only constructor)
  - `crates/aitm/src/macos_capture/status.rs` (modify: remove the P3 scaffolding `#[allow(dead_code)]` lines; nothing else)
  - `crates/aitm/src/wire.rs` (modify: plumbing + `build_with` + two tests)
  - `crates/aitm/src/main.rs` (modify: destructure + pass-through)
  - `crates/aitm/tests/macos_ne_feeder_loopback.rs` (modify: `build_session`, `Observed`, phase assertions)
- **Change:**

  `feeder.rs` (spec D3):
  - `use super::status::{scope_tokens, CaptureStatusWriter};`
  - `pub struct CaptureSession` gains `status: CaptureStatusWriter`.
  - ```rust
    pub fn new(ingress: Arc<CoreIngress>, l7_guard: Arc<dyn ScopeRateGuard>, l4_guard: Option<Arc<L4Guard>>,
               verifier: Arc<dyn PeerVerifier>, socket_dir: PathBuf, status: CaptureStatusWriter) -> Self
    ```
  - Update points, exactly:
    | Where | Record |
    |---|---|
    | `run`: before `self.run_session(shutdown)` is polled | `let status = self.status.clone();` and in the `catch_unwind` `is_err()` branch, `status.stopped();` |
    | `run_session`: `CaptureListener::bind` `Err(e)` | `self.status.bind_failed(format!("cannot bind the capture sockets ({})", e.kind()));` before `return` |
    | `run_session`: `publish_rendezvous` `Err(e)` | `self.status.bind_failed(format!("cannot publish the rendezvous file ({})", e.kind()));` before `return` |
    | `run_session`: after `info!(... "macOS capture feeder listening")` | `self.status.listening();` |
    | `run_session`: after the accept loop, beside `info!("macOS capture feeder stopped")` | `self.status.stopped();` |
    | `serve_control`: directly after `info!("capture provider attached")` | `let _attachment = self.status.attached(self.verifier.team_id(), scope_tokens(&last_sent));` — held to the end of `serve_control` |
    | `serve_control` `scope_loop`: after a successful re-push `writer.send(...)` | `self.status.scope_pushed(scope_tokens(&spec));` |
    | `start_pump`: after `claim_slot()` returns `Some(permit)`, before `spawn_pump` | `self.status.handed_off(open.kind);` |
    Reason strings use `io::ErrorKind`'s `Display` (`e.kind()`), never `e` itself, so no path
    can leak (the operator log already carries the full error).

  `listener.rs`: `impl DataConnection { #[cfg(test)] pub(crate) fn for_test(flow_id: u64, stream: UnixStream) -> Self }`
  (doc: "a data connection over an already-connected stream, for feeder tests that
  need one without a bound listener"). No production behaviour changes.

  `wire.rs` (spec D8, minus the plugin registration, which is Task 3):
  - `use crate::macos_capture::status::{CaptureStatus, CaptureStatusWriter};`
  - In `assemble_with_scripts`, immediately before the first `.register_plugin(` chain
    (after `map_guard`/`maprules` are built):
    `let (capture_status, _capture_status_reader) = CaptureStatus::channel(features.macos_capture.enabled);`
    with a comment `// Task 3 of the capture-status plan registers the reader's verb here.`
  - `pub struct Assembled` gains, after `l4_guard`:
    `/// Write side of the `capture.status` handle; move it into `build_capture_session`. Dropping it unused leaves the verb reporting the constructor's `off` state. pub capture_status: CaptureStatusWriter,`
    and the `Ok(Assembled { .. })` literal names it.
  - ```rust
    pub fn build_capture_session(features: &Features, ingress: CoreIngress, l7_guard: Arc<dyn ScopeRateGuard>,
        l4_guard: Option<Arc<L4Guard>>, verifier: Arc<dyn PeerVerifier>, socket_dir: PathBuf,
        status: CaptureStatusWriter) -> Option<CaptureSession>
    ```
    threading `status` as `CaptureSession::new`'s sixth argument.
  - Tests: `build_with(features)` passes `CaptureStatus::channel(features.macos_capture.enabled).0`.

  `main.rs`: name `capture_status,` in the `let Assembled { .. }` destructure (after `l4_guard`,
  with a one-line comment: the write side of `capture.status`, consumed by the feeder below)
  and pass `capture_status` as the seventh argument of `build_capture_session` inside the
  existing `cfg!(target_os = "macos")` arm. Both compilations move it there, so no
  unused-variable warning on Linux.

  `macos_ne_feeder_loopback.rs`: `use aitm::macos_capture::status::{CaptureStatus, CaptureStatusReader, FeederState, OffReason, ProviderState};`
  `struct Observed` gains `status: CaptureStatusReader`; `build_session` does
  `let (status_writer, status) = CaptureStatus::channel(true);`, passes `status_writer`
  to `CaptureSession::new`, and stores `status` in `Observed`.

- **Test:**

  **[sandbox]** `feeder.rs` tests, reusing the harness. Harness changes: `StubVerifier`
  gains `team: Option<String>`, `fn with_team(accept: bool, team: &str) -> Arc<Self>`,
  and `fn team_id(&self) -> Option<String> { self.team.clone() }`; `StubVerifier::new(accept)`
  keeps `team: None`. Add `fn session_with_status(verifier, guard, l4, status: CaptureStatusWriter) -> CaptureSession`
  and make `session_with` delegate to it with `CaptureStatus::channel(true).0`
  (existing tests unchanged). Add `fn now_ms() -> u64` (or import Task 1's if made `pub(super)`).
  - `attach_records_provider_facts` (CS-AC7, CS-AC19): `let (w, r) = CaptureStatus::channel(true); w.listening();`
    session via `session_with_status(StubVerifier::with_team(true, "995PCLM9KH"), TestGuard::with_hosts(&["example.com"]), None, w)`;
    `before = now_ms()`; Hello; `attach`; `next_frame == Some(scope("example.com"))`; `after = now_ms()`;
    `r.snapshot()`: `provider == Attached { attached_at_ms: t, team_id: Some("995PCLM9KH") }` with
    `before <= t <= after`, `scope_tokens == ["example.com"]`, `(tcp, udp) == (0, 0)`,
    `capability() == ApprovedAttached`; `to_value()["scope_entries"] == Int(1)`,
    `["provider"]["state"] == Str("attached")`, `["capability"] == Str("approved_attached")`.
  - `default_stub_verifier_reports_no_team` (CS-AC7): same with `StubVerifier::new(true)` → `team_id == None`,
    `to_value()["provider"]["team_id"] == Null`.
  - `scope_repush_updates_tokens` (CS-AC8): as `scope_change_triggers_resend`; after the second
    `Scope` (`"example.com api.test"`) → `r.snapshot().scope_tokens == ["example.com", "api.test"]`,
    `to_value()["scope_entries"] == Int(2)`.
  - `detach_resets_to_awaiting_provider` (CS-AC9): attach, `drop(provider)`, await the task →
    `Detached`, tokens `[]`, `(0, 0)`, `last_handoff_at_ms == None`, `capability() == AwaitingProvider`,
    `to_value()["provider"] == {attached_at: null, state: "detached", team_id: null}`.
  - `aborted_attachment_also_records_detach` (CS-AC9, RAII): attach; after the `Scope` frame,
    `task.abort(); let _ = task.await;` → the same detached snapshot as above.
  - `start_pump_counts_handoffs_by_kind` (CS-AC10, CS-AC19): `#[tokio::test]`; `w.listening()`;
    `let _guard = w.attached(None, vec![])` (hold it); `let (a, _provider_half) = tokio::net::UnixStream::pair()`;
    `before = now_ms()`; `session.start_pump(open(1), DataConnection::for_test(1, a))`; `after = now_ms()`
    → `(1, 0)`, `last_handoff_at_ms == Some(t)` with `before <= t <= after`, `capability() == Capturing`,
    `to_value()["flows_handed_off"] == {tcp: 1, udp: 0}`; then a `FlowOpen { kind: FlowKind::Udp, local: Some("127.0.0.1:5353".parse().unwrap()), ..open(2) }`
    over a second pair → `(1, 1)`.
  - `shed_pair_is_not_counted` (CS-AC10): `.with_max_concurrent_flows(0)`; `start_pump` once →
    `(0, 0)`, `last_handoff_at_ms == None`.
  - `run_returns_when_the_socket_dir_is_unusable` **extended** (CS-AC5): build with
    `CaptureStatus::channel(true)`; after `run` returns: `feeder == BindFailed(r)` with
    `r == "cannot bind the capture sockets (not a directory)"` (the harness path is `<file>/sub`,
    so `refuse_symlink` returns ENOTDIR; if a platform reports another kind, assert instead
    `r.starts_with("cannot bind the capture sockets (") && r.ends_with(')') && !r.contains('/')`
    and say so in the report); `capability() == Degraded(r.clone())`;
    `to_value()["feeder"]["state"] == Str("bind_failed")`, `["capability"] == Str("degraded")`,
    `["capability_reason"] == ["feeder"]["reason"]`; `feeder != Off(OffReason::Stopped)`.
  - `run_future_is_send` still compiles with the sixth argument.

  **[sandbox]** `wire.rs` tests:
  - `disabled_capture_session_leaves_status_off` (CS-AC20): `let (w, r) = CaptureStatus::channel(false);`
    `build_capture_session(&capture_features(false), CoreIngress::empty(), Arc::new(LateGuard::default()), None, Arc::new(CodeSignatureVerifier::default()), PathBuf::from("/nonexistent-wire-test-dir"), w).is_none()`
    and `r.snapshot().to_value() == <disabled literal>`.
  - `enabled_capture_session_is_not_started_until_run`: `channel(true)`; `build_capture_session(&capture_features(true), .., w).is_some()`
    and `r.snapshot().feeder == Off(if cfg!(target_os = "macos") { NotStarted } else { NotMacos })`.
  - `capture_session_absent_when_disabled`, `capture_session_present_when_enabled`,
    `no_agent_path_to_capture_session` (CS-AC17) pass unchanged.

  **[terminal]** `crates/aitm/tests/macos_ne_feeder_loopback.rs::loopback_provider_feeds_in_scope_flows_and_shutdown_cleans_up`
  (`cargo test -p aitm --test macos_ne_feeder_loopback -- --nocapture`; in the sandbox it
  prints `skipped: UDS bind unavailable (run via Terminal panel)` and passes — the Coder
  pastes that line; the orchestrator runs it in the Terminal). Insert, with `let s = seen.status.snapshot();` at each point:
  - after `wait_for_rendezvous()` (CS-AC6): `s.feeder == FeederState::Listening`, `s.provider == ProviderState::Detached`,
    `s.capability() == CaptureCapability::AwaitingProvider`, `s.to_value()["feeder"]["reason"] == Value::Null`.
  - after the `Scope` assertions (CS-AC7): `matches!(s.provider, Attached { team_id: None, .. })`
    (`ScriptedVerifier` does not override `team_id`), `s.scope_tokens == ["example.com", "198.51.100.7"]`,
    `(0, 0)`, `s.capability() == ApprovedAttached`.
  - after the in-scope TCP flow's `seen.spawns() == 1` assertion (CS-AC10): `s.tcp_handed_off >= 1`,
    `s.capability() == Capturing`.
  - after the in-scope UDP flow's packet assertions (CS-AC10): `s.udp_handed_off >= 1`.
  - after `running.shutdown().await` and `assert_cleaned_up` (CS-AC4, CS-AC11): `s.feeder == Off(OffReason::Stopped)`,
    `s.provider == Detached`, `(0, 0)`, `s.capability() == FeederOff("stopped".into())`,
    `s.to_value()["feeder"] == {reason: "stopped", state: "off"}`.

- **Done when:** all sandbox tests above pass; the loopback test prints its skip
  line in the sandbox and passes in the Terminal; `grep -n "allow(dead_code)" crates/aitm/src/macos_capture/status.rs`
  prints nothing; `main.rs`'s destructure names `capture_status` and still ends in the
  commented `..`; and the full gate passes.

### Task 3: the `capture.status` verb, registration, tool-set contract

- **Satisfies:** CS-AC1, CS-AC2, CS-AC3, CS-AC14 (schema half), CS-AC16 (`CaptureStatusPlugin::new` takes a reader), CS-AC20 (verb-level), CS-AC25.
- **Depends on:** Task 2.
- **Files:**
  - `crates/aitm/src/macos_capture/status.rs` (modify: add the plugin, the command, their tests)
  - `crates/aitm/src/wire.rs` (modify: registration; three tests)
  - `crates/aitm/tests/frontends.rs` (modify: `EXPECTED_TOOLS`)
- **Change:**

  `status.rs` (spec D6):
  ```rust
  pub struct CaptureStatusPlugin { reader: CaptureStatusReader }
  impl CaptureStatusPlugin { pub fn new(reader: CaptureStatusReader) -> Self }
  impl aitm_core::Plugin for CaptureStatusPlugin {
      fn name(&self) -> &str;                                   // "capture_status"
      fn load(&mut self, reg: &mut aitm_core::Registry);        // reg.add_command(Arc::new(CaptureStatusCommand { reader: self.reader.clone() }))
  }
  struct CaptureStatusCommand { reader: CaptureStatusReader }
  impl aitm_core::Command for CaptureStatusCommand {
      fn name(&self) -> &str;                                   // "capture.status"
      fn sensitivity(&self) -> Sensitivity;                     // Sensitivity::Read
      fn schema(&self) -> ParamSchema;                          // params: vec![], result: TypeDesc::Object(result_fields())
      fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value>;  // Ok(self.reader.snapshot().to_value()); never errors
  }
  fn result_fields() -> Vec<ParamDef>;
  ```
  `result_fields()` (precedent `summary_fields()` in `aitm-plugins/src/capture.rs`), every
  `description` non-empty, `required` exactly as listed:
  `enabled: Bool, true` · `feeder: Object([state: Str, true; reason: Str, false]), true` ·
  `provider: Object([state: Str, true; attached_at: Int, false; team_id: Str, false]), true` ·
  `scope_entries: Int, true` · `scope_tokens: Array(Str), true` ·
  `flows_handed_off: Object([tcp: Int, true; udp: Int, true]), true` ·
  `last_handoff_at: Int, false` · `capability: Str, true` · `capability_reason: Str, false`.
  Fixed text for `provider.team_id`'s description (spec D4): "The Apple team identifier the
  provider's code signature was verified against (the requirement's pinned OU); not read from
  the peer's signing information. Null when detached or when the verifier pins no team."
  `ParamSchema.description` names the verb's purpose, that times are Unix epoch milliseconds,
  that `feeder.reason` when `state == "off"` is one of the four vocabulary strings, and that
  `proxy.status.capturing` is the record toggle, not this. `summarize` may return
  `Some(format!("capture: {}, {} tcp / {} udp", ..))` or `None` (builder's call).

  `wire.rs`: rename `_capture_status_reader` → `capture_status_reader`, drop the Task 2
  placeholder comment, and add
  `.register_plugin(Box::new(CaptureStatusPlugin::new(capture_status_reader)))`
  **directly after** `.register_plugin(Box::new(ControlPlugin::new(armed, listening.clone())))`,
  unconditionally (every platform, every `Features`). Import `CaptureStatusPlugin`.

  `frontends.rs`: `const EXPECTED_TOOLS: [&str; 59]`; insert `"capture.status",` directly after
  `"proxy.status",` preceded by the comment
  `// capture.status (spec 2026-10-31-capture-status-verb-design): the macOS NE capture feeder's read-only state, registered on every platform.`
  `OPERATOR_TOOLS` and `fixtures/operator-tool-schemas.json` untouched (CS-AC21).

- **Test:** all **[sandbox]**.

  `status.rs` tests (a local `struct StubClient; impl ProxyClient` returning
  `anyhow::bail!("stub client")` as `aitm-plugins/tests/control.rs` does; host =
  `CommandHost::new(&MemFlowStore::new(), &StubClient, &StdGuard::default(), None)`):
  - `command_is_read_only_and_parameterless` (CS-AC2): `sensitivity() == Sensitivity::Read`,
    `mutates() == false`, `schema().params.is_empty()`; `let (w, r) = CaptureStatus::channel(true); w.listening();`
    `before = r.snapshot()`; `a = invoke(Params::default(), &host)?`;
    `b = invoke(Params::new([("enabled", Bool(true)), ("feeder", Str("listening")), ("provider", Str("attached"))].into()), &host)?`;
    `a == b == listening_literal()`; `r.snapshot() == before`.
  - `registry_invocation_returns_the_disabled_literal` (CS-AC3): `let (_w, r) = CaptureStatus::channel(false); let mut reg = Registry::new(); reg.add_plugin(Box::new(CaptureStatusPlugin::new(r)));`
    `reg.command("capture.status").unwrap().invoke(Params::default(), &host)? == disabled_literal()`.
  - `schema_describes_every_emitted_key` (CS-AC14): walk `schema().result` against `to_value()`
    of every `matrix()` snapshot recursively: at each `TypeDesc::Object` / `Value::Object` level
    the set of `ParamDef.name`s equals the set of keys; every `description` is non-empty;
    the set of `required: false` names, collected over the walk, is exactly
    `{"reason", "attached_at", "team_id", "last_handoff_at", "capability_reason"}`; every
    field that is `Value::Null` in some snapshot is `required: false`; `scope_tokens`'s type is
    `TypeDesc::Array(Str)`; `enabled`'s is `Bool`; the four counters/times are `Int`.

  `wire.rs` tests (host built from `crate::tui::services(&assembled.proxy, &cfg, None, TuiLog::Off)`:
  `CommandHost::new(&*s.store, &*s.client, &*s.guard, None)`; verb via
  `assembled.proxy.registry().command("capture.status").expect("registered")`):
  - `capture_status_verb_reports_the_disabled_literal` (CS-AC3): `assemble(&cfg)` (default
    `Features`) and `assemble_with(&cfg, &capture_features(false))` both return exactly the
    disabled literal.
  - `capture_status_verb_follows_the_feature_switch` (CS-AC20): `capture_features(true)` →
    `["enabled"] == Bool(true)`, `["capability"] == Str("feeder_off")`,
    `["feeder"]["reason"] == Str(if cfg!(target_os = "macos") { "not started" } else { "not a macOS build" })`.
  - `disabled_session_drops_the_writer_and_the_verb_stays_off` (CS-AC20): `assemble_with(&cfg, &capture_features(false))`;
    `build_capture_session(&capture_features(false), assembled.l4_ingress.take().unwrap(), assembled.proxy.guard(), None, Arc::new(CodeSignatureVerifier::default()), PathBuf::from("/nonexistent-wire-test-dir"), assembled.capture_status).is_none()`
    (destructure `Assembled` to move the fields); the registered verb still returns the disabled literal.

  `frontends.rs`: `ac7_exact_tool_set` passes with 59 entries (`cargo test -p aitm --test frontends ac7_exact_tool_set`).
  `tests/e2e/mcp/test_tool_list_complete.py` needs no edit (it derives from `EXPECTED_TOOLS`).

- **Done when:** the tests above pass; `cargo test -p aitm --test frontends` is green;
  `git diff --stat` for the task touches only the three files; `grep -c '"capture.status"' crates/aitm/tests/frontends.rs` is 1; and the full gate passes.

### Task 4: Swift Kit decoder `CaptureStatus`

- **Satisfies:** CS-AC22, CS-AC23.
- **Depends on:** none (independent of Tasks 1–3 and 5; D7/D10 fix the shape).
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/CaptureStatus.swift` (create)
  - `apps/mac/Tests/AitmproxyKitTests/CaptureStatusTests.swift` (create)
- **Change:** exactly spec D10's public surface:
  ```swift
  public struct CaptureStatus: Hashable, Sendable {
      public enum Feeder: Hashable, Sendable { case off(reason: String?); case listening; case bindFailed(reason: String); case unknown(state: String) }
      public enum CoreCapability: Hashable, Sendable {
          case feederOff, awaitingProvider, approvedAttached, capturing, degraded
          case unknown(String)
          public init(wire: String)      // the five wire names; anything else → .unknown(wire)
          public var wire: String        // the inverse; .unknown(s) → s
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
      public init(enabled: Bool, feeder: Feeder, providerAttached: Bool = false, attachedAt: Date? = nil, teamID: String? = nil,
                  scopeTokens: [String] = [], tcpHandedOff: Int = 0, udpHandedOff: Int = 0, lastHandoffAt: Date? = nil,
                  capability: CoreCapability, capabilityReason: String? = nil)
      public init?(json: JSONValue)
  }
  ```
  Decoding (precedents `Panels/CAStatus.swift`, `FlowSummary.swift`; `JSONValue`
  subscripts and `boolValue/intValue/stringValue/arrayValue`):
  `init?(json:)` returns nil unless `json["enabled"]?.boolValue`, `json["feeder"]?["state"]?.stringValue`
  and `json["capability"]?.stringValue` are all present. `feeder.state`: `"off"` → `.off(reason: json["feeder"]?["reason"]?.stringValue)`;
  `"listening"` → `.listening`; `"bind_failed"` → `.bindFailed(reason: reason ?? "")`; else `.unknown(state:)`.
  `providerAttached = json["provider"]?["state"]?.stringValue == "attached"`. Dates: a private
  `static func date(_ v: JSONValue?) -> Date?` returns nil unless `v?.intValue` is a non-negative
  integer, then `Date(timeIntervalSince1970: Double(ms) / 1000)`. Counts: `max(0, intValue ?? 0)`.
  `scopeTokens = json["scope_tokens"]?.arrayValue?.compactMap(\.stringValue) ?? []`; `scope_entries`
  is not decoded. `capabilityReason = json["capability_reason"]?.stringValue`.
  **Token rules (CS-AC23):** the file must not contain `capture.enabled` anywhere, including
  comments (so do not write the config key `macos_capture.enabled`; say "the core's config
  on-switch"), nor `CaptureSwitch`, `extensionController`, `.enable(`, `.disable(`,
  `activationRequest(`, `deactivationRequest(`, `submitRequest(` — the tripwires grep for these.
  The file names neither the app's `CaptureCapability` nor `CaptureAdvice`.

- **Test:** `apps/mac/Tests/AitmproxyKitTests/CaptureStatusTests.swift`,
  `import AitmBusClient; import Foundation; import Testing; @testable import AitmproxyKit`,
  `@Suite struct CaptureStatusTests`, fixtures as `static let` JSON strings parsed with
  `try JSONValue.parse(_:)` (as `ScanTests.swift`), one per D7 example:
  - `decodesTheDisabledShape`: `enabled == false`, `feeder == .off(reason: "macos_capture.enabled is false")`,
    `providerAttached == false`, `attachedAt == nil`, `teamID == nil`, `scopeTokens == []`,
    `tcpHandedOff == 0`, `udpHandedOff == 0`, `lastHandoffAt == nil`, `capability == .feederOff`,
    `capabilityReason == "macos_capture.enabled is false"`. (The string lives in the test file only;
    the tripwires scan `Sources/`, and CS-AC23 constrains the Kit file.)
  - `decodesTheBindFailedShape`: `feeder == .bindFailed(reason: "cannot bind the capture sockets (not a directory)")`,
    `capability == .degraded`, `capabilityReason == "cannot bind the capture sockets (not a directory)"`.
  - `decodesTheListeningShape`: `feeder == .listening`, `capability == .awaitingProvider`,
    `capabilityReason == nil`, `providerAttached == false`.
  - `decodesTheCapturingShape`: `feeder == .listening`, `providerAttached == true`,
    `attachedAt == Date(timeIntervalSince1970: 1_761_907_200)`,
    `lastHandoffAt == Date(timeIntervalSince1970: 1_761_907_305.123)`, `teamID == "995PCLM9KH"`,
    `scopeTokens == ["example.com", "*.example.com", "198.51.100.7"]`, `tcpHandedOff == 12`,
    `udpHandedOff == 3`, `capability == .capturing`, `capabilityReason == nil`.
  - `approvedAttachedWithEmptyScopeIsHonest`: the capturing fixture with `{tcp: 0, udp: 0}`,
    `last_handoff_at: null`, `scope_entries: 0`, `scope_tokens: []`, `capability: "approved_attached"`
    → `capability == .approvedAttached`, `scopeTokens.isEmpty`, `lastHandoffAt == nil`, `providerAttached == true`.
  - `rejectsAnObjectWithoutTheRequiredKeys`: `CaptureStatus(json: .object([:])) == nil`;
    also nil when only `enabled` is present.
  - `unknownCapabilityDecodesAsUnknown`: `"capability": "something_new"` → `capability == .unknown("something_new")` and `capability.wire == "something_new"`.
  - `unknownFeederStateDecodesAsUnknown`: `"feeder": {"state": "weird", "reason": null}` → `feeder == .unknown(state: "weird")`.
  - `offReasonsDecodeVerbatim`: the four vocabulary strings each → `.off(reason: <string>)`.
  - `absurdTimesAndCountsAreClamped`: `attached_at: -5` → `attachedAt == nil`; `attached_at: 1.5` → nil;
    `flows_handed_off: {tcp: -1, udp: -2}` → `(0, 0)`.
  - `capabilityWireRoundTrips`: for each of the five wire names `CoreCapability(wire: s).wire == s`.

  **Where the checks run.** `swift build` and `swift test` do **not** run in the Bash
  sandbox: probed 2026-10-31 from this worktree — `swift build --package-path apps/mac --scratch-path "$TMPDIR/swift-build"`
  fails at the manifest with `sandbox-exec: sandbox_apply: Operation not permitted`
  (SwiftPM's own sandbox cannot nest), and `--disable-sandbox` fails with XCBuild unable to
  write its manifest under `$TMPDIR` (`NSPOSIXErrorDomain Code=1`). What the Coder **can**
  run in the sandbox, and must paste: (1) `xcrun swiftc -parse apps/mac/Sources/AitmproxyKit/CaptureStatus.swift apps/mac/Tests/AitmproxyKitTests/CaptureStatusTests.swift`
  (syntax only; exit 0 — probed working); (2) `apps/mac/tools/check-capture-operator-only.sh`
  and `apps/mac/tools/check-capture-toggle.sh` (plain grep scripts; both exit 0 and print PASS);
  (3) `grep -c 'capture\.enabled' apps/mac/Sources/AitmproxyKit/CaptureStatus.swift` → `0`;
  (4) `git status --porcelain` shows only the two new files. The orchestrator then runs in
  the Terminal panel: `swift build --package-path apps/mac` and
  `swift test --package-path apps/mac --scratch-path ~/Library/Developer/Aitmproxy/test-build --filter CaptureStatusTests`
  **[terminal]**, and the Coder's report states that the type-check and tests are deferred to it.

- **Done when:** the four sandbox checks above pass as stated; the Terminal `swift build`
  has no errors and `swift test ... --filter CaptureStatusTests` is green; `git diff --stat`
  touches nothing under `apps/mac/Sources/Aitmproxy/`, `CaptureCapability.swift` or
  `CaptureAdvice.swift`. (No Rust gate: this task touches no Rust.)

### Task 5: `operator-ui-foundation.md` §4.3 row

- **Satisfies:** CS-AC24.
- **Depends on:** none (independent of every other task).
- **Files:** `docs/design/operator-ui-foundation.md` (modify)
- **Change:** in §4.3 "The command set, grouped by UI concern", insert one table row
  directly after the `ca.status/export/install/uninstall` row. Spec D11's text, with the
  pipes inside code spans escaped as `\|` so the row renders as one cell set (the table's
  own convention; see the `flow.get` row's `http\|websocket`):

  ```
  | `capture.status` | `{}` → `{enabled, feeder: {state: off\|listening\|bind_failed, reason?}, provider: {state: detached\|attached, attached_at?, team_id?}, scope_entries, scope_tokens: [String], flows_handed_off: {tcp, udp}, last_handoff_at?, capability, capability_reason?}`; times are epoch ms | Settings ▸ Capture status and the Core/Bus/NE status UI (read-only; the on-switch stays `macos_capture.enabled` in the config file; `proxy.status.capturing` is the record toggle, not this) |
  ```
- **Test:** `grep -c '^| `capture.status` |' docs/design/operator-ui-foundation.md` prints `1`;
  the row contains `epoch ms` and `proxy.status.capturing`; the row sits between the
  `ca.status` row and the `### 4.4` heading; `git diff --stat` shows one file, one line added.
- **Done when:** the greps hold and `cargo fmt --check` is trivially unaffected (no Rust
  change; the full gate is not required for a docs-only task, but running it must not regress).

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
