# Browser scope-confined egress mode design

**Status:** draft
**Research inputs:** scanner security-panel finding **S2** (PR #67 review);
`docs/superpowers/specs/2026-10-29-aitmproxy-scanner-plugin-design.md`
(anti-goal: *"a scanner that touches an out-of-scope host, from any caller … the
design has failed"*); memory `aitmproxy-obscura-private-network-policy` (audit
I15 / PR #39, the `engine_may_reach_private` gate); chokepoint code
`crates/aitm-core/src/{proxy.rs,guard.rs,config.rs}`.

## Intent

The embedded browser's upstream connector (`SsrfConnector`,
`crates/aitm-core/src/proxy.rs:318`) calls `guard::ssrf_check`
(`crates/aitm-core/src/guard.rs:242`), which blocks only **private/loopback**
targets. A **public** host always passes — `blocked_by_policy(Public, _)` is
hard-coded `false` (`guard.rs:206`). So when the browser renders an in-scope
page it autonomously follows 3xx / `meta refresh` / JS redirects and loads
sub-resources (`<img>/<script>/<iframe>/CSS/font`, `fetch`, beacons) to
**out-of-scope public hosts**, egressing before any scope check. This is
scanner finding **S2**, but it affects **every** browser-driven feature (the M4
agent crawl too), not just the deterministic scanner. In an authorized pentest,
touching out-of-scope third parties is an authorization-boundary violation.

The fix lives at the proxy chokepoint (the decision already taken by the scanner
architect, honored here): add a **scope-confined egress mode** to the
browser-facing connector. When the mode is active, an out-of-scope public host
is refused; when it is off, the browser-facing listener behaves exactly as
today. The mode is a **runtime posture**, not a static policy, so a scan
campaign (or an agent crawl that opts in) turns it on for its duration and the
general-interception path leaves it off.

## Goals

- In confined mode, a browser-facing upstream connection to an **out-of-scope
  public** host is refused with `GuardError::OutOfScope`, before any dial.
- In confined mode, an **in-scope** public host (exact entry **and** `*.wildcard`
  entry) still passes.
- In free mode (the default), an out-of-scope public host still passes — the
  general-interception browsing path is unchanged.
- Private/loopback handling — the block, the explicit-scope address lift, and the
  DNS-rebinding refusal — is **byte-for-byte unchanged** in both modes.
- The posture is togglable at runtime (a shared handle the scanner holds for a
  campaign via an RAII token; a command an operator / the M4 crawl can call) and
  its startup value comes from config, defaulting to **off**.

## Non-goals

- No change to the obscura `--allow-private-network` engine gate
  (`engine_may_reach_private`, `guard.rs:224`). That gate concerns
  **private/loopback** reachability; confinement concerns **public out-of-scope**
  hosts — orthogonal. The proxy connector stays the authoritative per-connection
  gate, exactly as audit I15 established.
- No confinement on the **main** client-facing listener (`Proxy::run`, which uses
  `PassiveConnector`, not SSRF). An intercepting proxy must relay what the client
  sends; confinement is a browser-**egress** concept only.
- No edits to `crates/aitm-plugin-scanner`. This branch delivers the core
  posture, enforcement, and command; the scanner *calling* it during a campaign
  is a scanner-side fast-follow.
- No new `GuardError` variant — an out-of-scope refusal reuses
  `GuardError::OutOfScope`.
- No out-of-band / collaborator egress tracking; this is a connect-time allow/deny
  only.

## Anti-goals

- A confinement that also gates the active-action paths (`flow.replay`,
  `request.send`, `poc.run`) or the main listener — it must touch **only** the
  browser-facing `SsrfConnector`. Those paths already enforce scope via
  `check_active`; widening confinement into them would double-gate and could
  break legitimate operator reissue.
- A mode that leaks its enabled state: if a scan enables confinement and then
  panics or errors, free browsing must not stay silently broken. Enable/disable
  must be crash-safe (RAII token, or a refcount that a dropped campaign releases).
- Weakening any existing refusal. Confinement only **adds** refusals; it never
  turns a current `Err` into `Ok`. In particular it must not open a path around
  the rebinding refusal.

## Constraints

- All enforcement stays in `aitm-core`; the decision function remains a **pure
  function over a scope slice** so it is unit-testable without a live guard or
  network, matching the existing `ssrf_check` tests (`ssrf.rs`, 14 cases).
- Deny-by-default is preserved: the restrictive direction (enabling confinement)
  is always permitted; the permissive direction (an out-of-scope public host) is
  allowed only in free mode, which is a deliberate operator posture.
- `ssrf_check` runs on every browser upstream connection, including redirects and
  sub-resources (`proxy.rs:104` comment) — so one connect-time gate covers all
  S2 vectors. It must stay cheap: an `Acquire` load of an atomic plus, only when
  confined and the target is public, one wildcard-aware scope scan.
- No new crate dependency.

## Design

### The posture: `EgressConfinement`

A new shared, runtime-mutable posture in `aitm-core` (new module
`crates/aitm-core/src/egress.rs`, re-exported from `lib.rs`):

```rust
/// Runtime egress-confinement posture for the browser-facing listener. When
/// confined, the SsrfConnector refuses an out-of-scope PUBLIC host (scanner
/// finding S2). Private/loopback handling is unaffected. Browser-path only —
/// the active-action guard (`check_active`) never consults this.
pub struct EgressConfinement { /* base: AtomicBool, holds: AtomicUsize */ }

impl EgressConfinement {
    pub fn new(base: bool) -> Self;        // startup value from config
    pub fn confined(&self) -> bool;        // base || holds > 0
    pub fn set_base(&self, on: bool);      // operator/command toggle of the base
    pub fn confine(self: &Arc<Self>) -> ConfinementToken; // RAII: +1 hold
}

/// Dropping the token releases one hold (campaign-scoped, crash-safe).
pub struct ConfinementToken { /* Arc<EgressConfinement> */ }
```

`confined()` is `base || holds > 0`. A **refcount of holds** (not a prev-restore
bool) is chosen so overlapping campaigns compose and a dropped/panicked campaign
always releases exactly its own hold — satisfying the "no leaked state"
anti-goal. The `base` bit is the config-seeded / command-toggled standing
posture; a `ConfinementToken` is a temporary campaign hold on top of it.
**(Architect's call: refcount over prev-restore.)**

### Config seed

Add to `BrowserConfig` (`config.rs`):

```rust
/// Start the browser-facing listener in scope-confined egress mode: refuse an
/// out-of-scope PUBLIC host (scanner S2). **Off by default** — the general
/// interception path must let an operator browse arbitrary public hosts. A scan
/// campaign or agent crawl turns it on at runtime.
pub confine_egress_to_scope: bool,   // Default: false
```

### The enforcement: extend `ssrf_check`

Add a `confine_to_scope: bool` parameter. The one new branch sits exactly where
S2 leaks — the "not blocked" (public) early-return at `guard.rs:256`:

```rust
pub fn ssrf_check(
    policy: &SsrfPolicy,
    scope: &[ScopeEntry],
    confine_to_scope: bool,     // NEW
    authority: &str,
    dst: IpAddr,
) -> Result<(), GuardError> {
    // ... compute `host` from authority (unchanged) ...
    let blocked = blocked_by_policy(classify_host(&host), policy)
        || blocked_by_policy(classify_ip(dst), policy);
    if !blocked {
        // Public target. In confined mode it must additionally be in scope.
        if confine_to_scope && !host_in_scope_any(&host, scope) {
            return Err(GuardError::OutOfScope(host));
        }
        return Ok(());
    }
    // ... existing private/loopback scope-lift + rebinding path UNCHANGED ...
}
```

`host_in_scope_any(host, scope)` reuses the existing wildcard-aware
`host_in_scope` helper (`guard.rs:444`): `scope.iter().any(|e| host_in_scope(host,
&e.host))` — the **same matching `StdGuard::in_scope` uses**, so a scoped public
hostname or `*.wildcard` passes. This is deliberately the *normal* scope match,
**not** the strict address-only `matches_scope_entry_exactly` the private-lift
path uses: the private lift must defeat rebinding (IP literals only), but public
confinement is a hostname allowlist (a scoped `*.example.com` legitimately
passes). The two checks never interact — confinement runs only on the
`!blocked` public branch; the private branch and its rebinding refusal are
untouched.

Matching on `host` (the requested authority's host), not the resolved `dst`, is
intentional and mirrors the scanner crawler's own `in_scope(host)` off-origin
drop: scope is expressed as hostnames, and a public `dst` IP is never scoped by
name. An unparseable authority yields an out-of-scope refusal under confinement
(deny-by-default).

### Threading through the proxy

- `ProxyInner` gains `egress: Arc<EgressConfinement>`, built in `ProxyBuilder::
  build` from `config.browser.confine_egress_to_scope`.
- `SsrfConnector` gains `egress: Arc<EgressConfinement>`; `connect` reads
  `self.egress.confined()` and passes it to `ssrf_check` (it already passes
  `self.guard.list_scope()`).
- `handle_conn` and `Proxy::upstream_connector(true)` construct `SsrfConnector`
  with the shared `egress` Arc.
- `Proxy` exposes `pub fn egress(&self) -> Arc<EgressConfinement>` (mirrors
  `guard()`), so the binary can hand it to the command/host wiring.

### The toggle surface

- `CommandHost` gains `egress: Option<&'a EgressConfinement>` with
  `with_egress(..)` + `egress()` accessors (mirrors `guard()`), so an in-process
  consumer (the scanner, later) reaches the handle.
- A new builtin command **`browser.confine`** `{ on: bool } -> { confined: bool }`
  sets the base posture. **Sensitivity: `Sensitive`** — toggling the
  browser-egress boundary is an authorization decision, so it is
  operator/CLI-gated by default (an agent may call it only under a permitting
  `AgentPolicy`), matching `scope.add`. Enabling *tightens* and disabling
  *widens*; a future refinement could let an agent self-tighten, but the
  fail-closed `Sensitive` tier is the safe default now. **(Architect's call.)**

The scanner's campaign-scoped `ConfinementToken` (future scanner work) and the
`browser.confine` command both drive the same `EgressConfinement`.

### Why one connect-time gate is sufficient for S2

The browser dials the proxy via `--proxy-server`, so **all** browser egress —
first navigation, 3xx/meta/JS redirects, every sub-resource, `fetch`, and
`browser.eval` traffic — flows through `SsrfConnector::connect` (confirmed by the
`proxy.rs:104` contract). The scanner crawler's existing `in_scope(host)` drop
only governs URLs the crawler itself enqueues; the browser follows redirects and
loads sub-resources **below** that layer. Confinement at the connector is the
layer that catches them. Observable effect in confined mode: an in-scope page
still renders, but an out-of-scope sub-resource fails to load and an out-of-scope
redirect fails the navigation — the desired campaign behavior.

## Acceptance criteria

1. **AC1:** `ssrf_check(policy, &[], /*confine=*/true, "evil.example:443",
   <public dst>)` returns `Err(GuardError::OutOfScope(_))`, with no dial.
2. **AC2:** With scope `["target.example"]`, confined, `ssrf_check(.., true,
   "target.example:443", <public dst>)` returns `Ok(())`; and with scope
   `["*.target.example"]`, `"app.target.example:443"` returns `Ok(())`.
3. **AC3:** `ssrf_check(policy, &[], /*confine=*/false, "evil.example:443",
   <public dst>)` returns `Ok(())` — free mode leaves public browsing open.
4. **AC4:** For a **private/loopback** target, the result is identical whether
   `confine` is true or false: out-of-scope private is refused; a scoped **IP
   literal / `localhost`** address still lifts the block (existing behavior).
5. **AC5:** DNS-rebinding refusal is unchanged — a scoped **hostname** that
   resolves to a private address is refused with `confine` true and false alike.
6. **AC6:** `EgressConfinement`: `confined()` is false by default; `set_base(true)`
   makes it true; a `confine()` token makes it true and dropping the token
   restores the prior value; two overlapping tokens both must drop before
   `confined()` returns to its base.
7. **AC7:** The browser-facing `SsrfConnector` consults the posture: with an
   empty scope and an **out-of-scope public** authority, `connect` returns `Err`
   when the shared `EgressConfinement` is confined, and does **not** refuse on
   confinement grounds when it is not (the private/loopback default still applies
   to private targets).
8. **AC8:** `BrowserConfig::default().confine_egress_to_scope == false`, and a
   proxy built from it starts in free mode (AC3 holds end-to-end through the
   connector).
9. **AC9:** `browser.confine { on: true }` sets `confined()` true and returns
   `{ confined: true }`; `{ on: false }` sets it false. Its `sensitivity()` is
   `Sensitive` (asserted), so the agent-policy gate treats it like `scope.add`.

## Left to the builder

- The exact internal representation of `EgressConfinement` (an `AtomicBool` base
  plus `AtomicUsize` holds, or an equivalent) provided the observable AC6
  semantics hold.
- Whether `host_in_scope_any` is a new named helper or an inline `any(..)` over
  the existing `host_in_scope`.
- The `browser.confine` schema/param plumbing and its unit test, following the
  existing builtin-command pattern.
- Test mechanics for AC7 (a public but non-routable authority so no real network
  is touched; the refusal is observable before dial).

## Open questions

Only Matt can decide these:

1. **Default posture.** Recommend `confine_egress_to_scope = false` by default
   (free browsing out of the box; confinement opt-in per campaign). Confirm, or
   choose on-by-default.
2. **Auto-enable during scans.** Should a scan campaign (and the M4 agent crawl)
   **automatically** hold confinement for its duration via the RAII token, or
   only when explicitly asked? Recommend auto-enable for the scanner (its whole
   purpose is scope-bounded; S2 is a real auth-boundary violation) and opt-in
   (via `browser.confine`) for the free-form M4 crawl. This governs the
   scanner/M4 fast-follow, not this core branch, but the answer shapes it.
3. **Command gating granularity.** Recommend `browser.confine` is wholesale
   `Sensitive`. Accept, or split so *enabling* (tighten) is `Write` and only
   *disabling* (widen) is `Sensitive`.
