# Browser scope-confined egress mode implementation plan

**Status:** approved (2026-10-29 by Matt)
**Spec:** `docs/superpowers/specs/2026-10-29-aitmproxy-browser-egress-confinement-design.md`
**Branch / worktree:** `feat/browser-egress-confinement`

## Overview

Four tasks, mostly sequential. Task 1 adds the `EgressConfinement` posture type
and the config seed (self-contained, no other code depends on it yet). Task 2
extends the pure `ssrf_check` decision with the `confine_to_scope` branch (the
actual S2 fix; depends on nothing in Task 1 — it is a pure-function change and
can run in parallel with Task 1). Task 3 threads the Task-1 posture through the
proxy and the `SsrfConnector` so the Task-2 branch is driven by the runtime
posture (depends on 1 and 2). Task 4 adds the toggle surface — `CommandHost`
handle + the `browser.confine` command (depends on 1 and 3). Every task is
test-first and leaves the full gate green.

## Tasks

### Task 1: `EgressConfinement` posture + config seed

- **Satisfies:** AC6, AC8 (config half)
- **Depends on:** none
- **Files:** `crates/aitm-core/src/egress.rs` (create),
  `crates/aitm-core/src/lib.rs` (modify: `mod egress; pub use egress::{EgressConfinement, ConfinementToken};`),
  `crates/aitm-core/src/config.rs` (modify: add `confine_egress_to_scope: bool`
  to `BrowserConfig` + `false` in its `Default`).
- **Change:** `pub struct EgressConfinement` holding an `AtomicBool` base and an
  `AtomicUsize` hold-count. `new(base: bool)`, `confined(&self) -> bool`
  (`base.load(Acquire) || holds.load(Acquire) > 0`), `set_base(&self, on: bool)`,
  `confine(self: &Arc<Self>) -> ConfinementToken` (fetch_add 1). `ConfinementToken`
  holds `Arc<EgressConfinement>`; `Drop` does `fetch_sub 1`. Add the
  `confine_egress_to_scope: bool` config field documented as off-by-default.
- **Test** (`egress.rs` `#[cfg(test)]`): `confinement_defaults_off_and_composes` —
  `let c = Arc::new(EgressConfinement::new(false)); assert!(!c.confined());
  c.set_base(true); assert!(c.confined()); c.set_base(false);
  { let _t1 = c.confine(); assert!(c.confined()); { let _t2 = c.confine();
  assert!(c.confined()); } assert!(c.confined()); } assert!(!c.confined());`.
  Plus `config_default_is_free`: `assert!(!BrowserConfig::default().confine_egress_to_scope);`.
- **Done when:** both tests pass and the full gate passes.

### Task 2: confinement branch in `ssrf_check`

- **Satisfies:** AC1, AC2, AC3, AC4, AC5, AC10
- **Depends on:** none (pure-function change; may run parallel to Task 1)
- **Files:** `crates/aitm-core/src/guard.rs` (modify `ssrf_check`),
  `crates/aitm-core/tests/ssrf.rs` (create: the confinement cases),
  `crates/aitm-core/tests/guard.rs` (modify: thread the new `false` arg through
  the 12 pre-existing `ssrf_check` cases — this, not a pre-existing `tests/ssrf.rs`,
  is where they live), and the **two non-browser production callers** pass `false`:
  `crates/aitm-proto-http/src/sender.rs` (reissue sender — active path, not
  confined per the anti-goal) and `crates/aitm-browser/src/ssrf.rs` (`browser.navigate`
  pre-flight — authoritative gate is the connector). `crates/aitm-core/src/proxy.rs`
  carries a `false` stub here, swapped for the live posture in Task 3. *(Resolved
  during implementation: `ssrf_check` had three production callers, not one; see
  the spec's "`ssrf_check`'s other callers" section.)*
- **Change:** add `confine_to_scope: bool` as the 3rd parameter of `ssrf_check`
  (after `scope`, before `authority`). In the `if !blocked` branch, before
  `return Ok(())`, insert: `if confine_to_scope && !scope.iter().any(|e|
  host_in_scope(&host, &e.host)) { return Err(GuardError::OutOfScope(host)); }`.
  Nothing else in the function changes. Update the one production caller signature
  is deferred to Task 3; here, make `guard.rs` compile by updating any in-file
  callers/tests.
- **Test** (`tests/ssrf.rs`): `confined_refuses_out_of_scope_public`
  (empty scope, confine=true, public authority+dst → `Err(OutOfScope)`);
  `confined_allows_in_scope_public_exact_and_wildcard` (scope `target.example`
  then `*.target.example`, confine=true → `Ok`); `free_allows_out_of_scope_public`
  (empty scope, confine=false → `Ok`); `confinement_does_not_change_private`
  (out-of-scope private → `Err` under both confine values; scoped IP-literal
  private → `Ok` under both); `confinement_does_not_change_rebinding` (scoped
  **hostname** resolving private → `Err` under both). Use a public literal such
  as `203.0.113.*`? — no, that classifies **Private** (TEST-NET). Use a genuinely
  public literal, e.g. `93.184.216.34`, for the public dst; the refusal is
  decided before any dial so no network is touched.
- **Done when:** the new + updated tests pass and the full gate passes.

### Task 3: thread the posture through the proxy + connector

- **Satisfies:** AC7, AC8 (connector half)
- **Depends on:** Task 1 (the type), Task 2 (the `ssrf_check` arg)
- **Files:** `crates/aitm-core/src/proxy.rs` (modify).
- **Change:**
  - `ProxyInner` gains `egress: Arc<EgressConfinement>`.
  - `ProxyBuilder::build` constructs `let egress =
    Arc::new(EgressConfinement::new(config.browser.confine_egress_to_scope));`
    and stores it.
  - `SsrfConnector` gains `egress: Arc<EgressConfinement>`.
    `connect` calls `ssrf_check(&self.policy, &self.guard.list_scope(),
    self.egress.confined(), &authority, dst.ip())?`.
  - `handle_conn` and `Proxy::upstream_connector(true)` build `SsrfConnector`
    with `egress: inner.egress.clone()` / `self.inner.egress.clone()`.
  - Add `pub fn egress(&self) -> Arc<EgressConfinement> { self.inner.egress.clone() }`.
- **Test** (`proxy.rs` `#[cfg(test)]`, extend `upstream_connector_true_is_ssrf_guarded`
  neighborhood): `confined_connector_refuses_out_of_scope_public` — build a proxy
  from a `Config` with empty scope; take `proxy.egress()`, `set_base(true)`;
  assert `proxy.upstream_connector(true).connect("93.184.216.34",
  "93.184.216.34:80".parse().unwrap()).await` is `Err` (refused before dial).
  Then `set_base(false)` and assert a **private** out-of-scope target is still
  refused (private default unaffected). Keep the existing private-target test.
- **Done when:** the new + existing proxy tests pass and the full gate passes.

### Task 4: toggle surface — `CommandHost` handle + `browser.confine`

- **Satisfies:** AC9
- **Depends on:** Task 1, Task 3
- **Files:** `crates/aitm-core/src/ctx.rs` (modify: add `egress:
  Option<&'a EgressConfinement>` field + `with_egress` + `egress()` accessor to
  `CommandHost`), the builtin-command module that registers core commands
  (modify: add the `browser.confine` `Command` impl + register it),
  its test module (modify).
- **Change:** `CommandHost` carries an optional `&EgressConfinement`. A new
  `struct ConfineCommand` implementing `Command`: `name() = "browser.confine"`;
  `schema()` = one bool param `on`, result object `{ confined: bool }`;
  `sensitivity() = Sensitivity::Sensitive`; `invoke` reads `host.egress()`, calls
  `set_base(on)`, returns `{ confined: <posture>.confined() }` (error if no egress
  handle wired). Register it beside the other `browser.*`/core builtins.
- **Test:** `browser_confine_toggles_posture` — wire a `CommandHost` with an
  `EgressConfinement`, invoke `browser.confine {on:true}` → result
  `{confined:true}` and `confined()` true; `{on:false}` → false.
  `browser_confine_is_sensitive` — `ConfineCommand.sensitivity() ==
  Sensitivity::Sensitive`.
- **Done when:** both tests pass and the full gate passes.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|

## Shipped

Filled at stage 7.
