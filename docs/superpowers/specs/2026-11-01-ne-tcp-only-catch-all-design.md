# macOS NE: TCP-only catch-all rule, UDP rules only for scoped L4 targets — design

**Status:** approved (2026-11-01, self-approved by the fix session under Matt's autonomous mandate,
memory `aitmproxy-autonomous-approve-merge-mode`; OQ9 itself was Matt's decision of 2026-11-01; calls
A–J accepted as recommended; TR-AC8 step 2 amended to name the L4-enabled core correctly, see below)
**Research inputs:** `docs/research/24-ne-tcp-only-catch-all-rule.md` (fact base: §4),
`docs/research/25-apple-feedback-ne-udp-dontfrag-draft.md` (a deliverable, not designed here),
`docs/research/experiments/2026-10-31-macos-ne-observe-survey.md` §R4, §R4b, §R5, "Carry into
the spec" item 5; `docs/research/10-macos-network-extension.md` §3.5, §3.9.
**Parent specs:** `2026-10-29-aitmproxy-macos-network-extension-design.md` (D1, D2, NE-AC2,
NE-AC5), `2026-10-30-macos-ne-core-prereqs-design.md` §Piece 2 (`ScopeSpec` grammar,
`l4_token`), `2026-10-31-ne-claim-rule-design.md` D1–D3 (what can claim a datagram),
`2026-10-31-macos-ne-observe-only-lane-design.md` (Constraints "An inherited UDP rule
defect", Part 2, Open question 9 — **decided by Matt 2026-11-01: option (a)**).

## Intent

The shipped provider (v0.5.3, v0.5.4) installs one catch-all `NENetworkRule` with
`protocol: .any`. The survey measured (§R4) that while that rule is active,
`setsockopt(IP_DONTFRAG)` on every connected non-loopback UDP socket returns `ECONNRESET`
(UDP:443, :53 and :123 alike; loopback fine; `send()` fine; all OK with capture off:
`/tmp/claude/ne-tcp/out/control-before.log`), even though the provider declines every UDP
flow. Chromium treats that error as fatal when it configures a QUIC socket: headless Chrome
with `--origin-to-force-quic-on` fails with `ERR_CONNECTION_RESET`, and ordinary browsing
silently falls back to HTTP/2 (DevForums 770707). Firefox and `URLSession` keep h3; Safari is
proven only for its first, always-TCP load, so no Safari claim is made. Matt decided (OQ9,
option (a)): the default rule set is **TCP-only**; UDP enters the provider **only when the
operator's scope holds a UDP (L4) target**. This spec is that small fix. It lands before the
observe-only lane's `[Mac]` acceptance.

## Goals

- With capture on and no UDP target scoped, `dontfrag-core.py` reports `setsockopt(DONTFRAG) ok`
  on UDP:443/:53/:123 and Chrome's forced-QUIC loads render over HTTP/3 — the same result
  as capture off.
- TCP claiming is byte-for-byte unchanged: `scope.add example.com` + `curl http://example.com/`
  still yields a claimed TCP flow and a row.
- When an L4 Capture entry for a UDP target exists, a datagram to that target reaches the
  provider, is claimed, and `capture.status` `udp_handed_off` increments (NE-AC2).
- Rule-set changes follow scope changes without an operator action and without a tunnel
  restart (primary mechanism), bounded to at most two settings applications per core restart.
- No wire change: `HANDOFF_PROTOCOL_VERSION` and `HandoffConfig.protocolVersion` stay `1`.

## Non-goals

- Fixing the OS defect, measuring `IP_RECVTOS`, or filing the Feedback: note 25 is Matt's to
  file; this spec only records it as the companion deliverable.
- The observe-only lane (protocol version 2, `FlowSeen`, `Observe`): owned by that spec's plan.
- UDP visibility by default in the observe lane (see "Observe-lane consequence").
- Any change to `ExtensionController`, `CaptureCapability`, the UIs, or the core's L4 scope
  model (`L4ScopeEntry` has no protocol field; an entry covers TCP and UDP alike — unchanged).
- Fixing FB21464147 (`startProxy` called twice on Tahoe); the design tolerates it, no more.

## Anti-goals

- A reconcile that can gate or delay a claim decision. Detach must keep meaning "every flow
  returns `false` immediately" (NE-AC5); re-applying settings is asynchronous and never on the
  claim path.
- Widening: a UDP rule for anything the `ScopeMatcher` could not claim (host/suffix tokens,
  `ip:53`/`:5353`/`:853` tokens). Under-inclusive is acceptable; over-inclusive never.
- A second rule-building code path (one pure function builds every rule set, startup included).
- Logging payload bytes or the addresses of user flows.

## Constraints

- **SDK facts (macOS 26 SDK, research 24 §3.1).** `NENetworkRule.Protocol` is `.any`/`.TCP`/
  `.UDP`; nil remote + nil local matches all traffic of that protocol/direction except loopback.
  `includedNetworkRules`: port `"0"` needs a non-wildcard address; a wildcard address needs a
  non-zero port; **port `"53"` is not allowed**; `matchLocalNetwork` nil; direction outbound. No
  documented rule-count limit. `/32` and `/128` host rules are unexemplified.
- **Runtime replacement is UNVERIFIED.** The header says `setTunnelNetworkSettings` "can be
  called multiple times during the lifetime of a particular tunnel"; a 2022 DTS reply (thread
  699972) says rule changes need a provider restart; nothing is measured on macOS 27. Hence the
  live-proof gate between T1 and T2 below.
- **Coordination with the observe-lane session (agreed 2026-11-01).** No wire change; version 2
  is theirs. Touchable regions: `TransparentProxyProvider.swift` — `startProxy` (rule
  construction moves to a pure helper), a new reconcile method + installed-rule-set state on a
  serial queue, `stopProxy`; NOT the first lines of `handleNewFlow`/`handleNewUDPFlow`.
  `FlowHandoff.swift` — `ScopeMatcher` gets one pure derived value; `CoreLink` gets one
  self-contained `onScopeChange` hook block; `FlowHandoff` a passthrough; `HandoffSelfCheck` one
  new check group + one line in `run()`. NOT `HandoffConfig`, `CoreMessage`, `HandoffMessages`,
  `SelfExclusion`, the pumps, the fixtures. New file `apps/mac/Extension/Sources/ProviderRules.swift`
  (compiled automatically: `build.sh` and `ne-selfcheck.sh` take `Extension/Sources/*.swift`).
  Rust: `scope_spec.rs` module doc only; `listener.rs`/`adapter.rs` untouched. Whoever merges
  second rebases onto the first.
- **Environment.** Swift builds, signing, notarization (`xcrun notarytool submit …
  --keychain-profile aitm-notary`), install to `/Applications`, and `log show` run only in the
  Terminal panel on Matt's Mac with his Developer ID. A same-team, newer-`CFBundleVersion` sysex
  replaces the active one without a System Settings prompt; notarizing the `.app` zip suffices.
  The Extension has no SwiftPM test target: its tests are `HandoffSelfCheck` checks run by
  `apps/mac/tools/ne-selfcheck.sh` (works in the Claude sandbox with
  `NE_SELFCHECK_SCRATCH="$TMPDIR/ne-selfcheck"`; PASSES on this tree). The sandbox runs the Rust
  gate offline but cannot bind sockets or reach GitHub. Never `pkill -f` browsers or obscura.
- **Gates.** Rust gate green; `ne-selfcheck.sh` PASS; `check-capture-toggle.sh` and
  `check-capture-operator-only.sh` exit 0; `swift test` (Kit) green; Stage-6 security review
  mandatory (the provider is touched).

## Design

### Signal: "a UDP target is scoped" is derived from the `ScopeSpec` the provider already has

The provider receives one `Scope` frame on attach and on every change (feeder, polled every
`DEFAULT_SCOPE_POLL` = 1 s). By claim-rule D1–D3 the only token that can claim a datagram is an
IP token (`ip` / `ip:port`), and those come only from `l4_token` (an L4 Capture entry on
`macos-ne`, outbound, host-prefix CIDR). So the condition is: **the `ScopeMatcher` has at least
one `.ip` entry whose port is nil or not in `neverClaimedDatagramPorts`.** An `ip:53`, `ip:5353`
or `ip:853` token can never claim a datagram (and `53` cannot even be named in a rule), so it
contributes nothing — under-inclusive, consistent with the matcher. **No new wire field.**

### A. Rule shape: R2, one `.UDP` rule per UDP-claimable IP token **(Architect's call)**

The wanted rule set is a pure function of `ScopeMatcher?`:

- Always: one rule `NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0,
  localNetworkEndpoint: nil, localPrefix: 0, protocol: .TCP, direction: .outbound)`.
- For each `.ip(address)` entry with `port == nil` or `port ∉ neverClaimedDatagramPorts`, one
  rule with `protocol: .UDP`, `direction: .outbound`, `localNetworkEndpoint: nil`,
  `remoteNetworkEndpoint` = the address with port `entry.port ?? 0` (`0` = any port, allowed
  because the address is non-wildcard), `remotePrefix` = `32` for IPv4, `128` for IPv6.
- Skip rules (emit nothing, log nothing): a wildcard address (`0.0.0.0`, `::` — the header
  forbids it with port 0 and no real flow has that destination); an address
  `Network.NWEndpoint.Host` does not parse as `.ipv4`/`.ipv6` (cannot happen for `IPText.canonical`
  output, kept as a guard); ports 53/5353/853 as above.
- Canonical form: UDP targets de-duplicated and sorted by address text then port (nil first), so
  two scopes with the same claimable IP set compare equal whatever the token order.
- **Amended after the stage-6 panel (2026-11-01, security Minors):** the skip set also covers
  loopback (`127/8`, `::1`), multicast and the IPv4 limited broadcast `255.255.255.255` — the
  kernel never diverts loopback and one kernel-rejected rule would block the whole set; and the
  UDP target list is capped at **256** after canonicalisation (first 256 in canonical order), the
  dropped count shown in the log `summary`. Both are under-inclusive, never over-inclusive.

Why R2 over R1 (one catch-all `.UDP` rule): it is exactly the matcher's UDP claim set (what the
kernel diverts ≡ what the provider can claim); if the kernel effect is per-match, the
`IP_DONTFRAG` breakage is confined to sockets aimed at the operator's own target (unmeasured;
the live proof measures it for free, TR-AC8 step 2d); and it stays a pure function the
self-check pins. R1 would cost Chromium HTTP/3 system-wide whenever any L4 target is scoped.
Cost of R2: `/32`/`/128` host rules are unverified; **fallback R1** (replace the per-target rules
with one `.UDP` nil-remote rule; pure-function change plus updated pins) is built only if the
live proof shows a `/32` rule does not divert the datagram (TR-AC8 ladder).

A bare `ip` token yields a port-0 rule that also diverts datagrams to `ip:53`; the provider then
declines them (claim rule D2) and such a socket suffers the defect. That is the operator's own
target; accepted and documented in the module doc.

### B. Transition: T1, the provider re-applies its settings in place **(Architect's call)**

**State**, owned by one serial `DispatchQueue` in `TransparentProxyProvider` (never read on the
claim path): `installed: ProviderRuleSet?` (last set whose `setTunnelNetworkSettings` completed
without error), `pendingWanted: ProviderRuleSet`, `inFlight: Bool`, `stopped: Bool`.

**Reconcile** `reconcileRules(for scope: ScopeMatcher?)`: hops onto the queue, computes
`wanted = ProviderRuleSet.wanted(for: scope)`, stores it as `pendingWanted`, and if `!inFlight
&& !stopped && wanted != installed` starts one apply. The apply builds a fresh
`NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")`, sets
`includedNetworkRules = wanted.networkRules()`, sets `reasserting = true`, calls
`setTunnelNetworkSettings`; its completion hops back onto the queue, clears `reasserting`, and
on success sets `installed = wanted` and logs the change (D); on error logs it and leaves
`installed` as it was; then clears `inFlight` and re-runs the check against `pendingWanted` —
after a **failure** only if a newer set arrived during the flight (the failed set is not
re-applied by itself; see "Failure semantics" below, which governs; wording corrected after the
stage-6 spec review) — (coalescing: at most one in flight plus one pending, so a burst of pushes
applies at most the last distinct set). **Debounce by construction:** a core restart is
detach → attach within seconds; with no UDP target scoped wanted == installed throughout and
nothing is applied; with one scoped, exactly two applications (TCP-only, then TCP+UDP).

`reasserting` is set only around reconcile applies (the session is Connected then; the header
says the flag has effect only in that state), never around the startup apply. The app ignores
`.reasserting` (`applyTunnelStatus`), so the capability state is undisturbed. It is the canonical
Apple pattern for re-applying settings; cost nil, benefit unverified, so it stays unless the
live proof shows it harms (**Architect's call**).

**Failure semantics.** An apply error changes nothing about claiming: `CoreLink.current()` still
governs every flow; the previous rule set stays installed in the kernel as far as we know, and
`installed` keeps saying so. The provider never retries on a timer; the next scope change
triggers the next attempt.

**Hook.** `CoreLink` gains `var onScopeChange: ((ScopeMatcher?) -> Void)?`, invoked **outside
`lock`** (a) in `readControl` after `scope = matcher` is stored, with the matcher; (b) in `detach`
with nil, **only when the `control === handle` guard was true** (a stale handle's detach must not
reset the rules of a live attachment); (c) at the start of `serve` after `scope = nil`, with nil.
The hook must return promptly: the provider's implementation is a single `queue.async`.
`FlowHandoff` exposes the same property as a passthrough. Ordering guarantee: by the time the
hook runs for a detach, `current()` already returns nil — fail-open is decided before any
settings work begins (TR-AC2).

**T2 contingency (specified, built only if TR-AC8 shows T1's rules have no kernel effect).** The
app's `ExtensionController` restarts the tunnel on a change of the UDP target set read from
`capture.status.scope_tokens` (IP tokens, same skip rules): `stopVPNTunnel()` → wait for
`.disconnected` via the existing observer → `startVPNTunnel(options: ["udp_targets": [String]])`,
and `startProxy(options:)` builds the rule set from that array (strings only; value types for
start options are undocumented beyond strings and numbers). The provider's hook then becomes a
no-op recorder and `ProviderRuleSet` is unchanged. Known costs (research 24 §5 A): claimed flows
are interrupted, the reconcile window applies, DTS discourages repeated hot restarts, and
`startProxy` may run twice on Tahoe. **Detection of a T1 failure:** after the "rules applied"
log line names a UDP rule for the target, a datagram to that target produces no
`NEFlow type = datagram` line for the provider in the framework log **and** `dontfrag-core.py`
against that target still reports `setsockopt(DONTFRAG) ok` (the defect is the kernel-side oracle
that a UDP rule covers the socket).

### C. Startup

`startProxy` applies `ProviderRuleSet.tcpOnly` through the same apply path (no `reasserting`;
the completion handler is called with the apply's result; on error `handoff.stop()` as today).
`handoff.start()` runs first, as today; a Scope that arrives before the startup apply completes
is coalesced as `pendingWanted` and applied right after. UDP rules therefore appear only after a
Scope push holding UDP-claimable IP tokens. `stopProxy` sets `stopped`, resets `installed`,
`pendingWanted` and `inFlight` on the queue, then `handoff.stop()`; a hook firing from the
resulting detach is dropped. **Amended after the stage-6 panel (2026-11-01):** a `startProxy`
completion still parked when `stopProxy` arrives is answered with a cancellation error
(`ECANCELED`), never dropped; a second `startProxy` without `stopProxy` (FB21464147) with a rule
set already installed answers its completion at once and keeps the installed set (no TCP-only
re-apply); a `Scope` reaching the queue before the startup apply is kept as `pendingWanted` and
applied right after it; a failed startup apply stops the reconciler before `handoff.stop()`. The class doc comment and the `startProxy` comment ("Provider
*rules* cannot be hot-edited without a restart") are rewritten to describe this design.

### D. Logging **(Architect's call on addresses)**

One `.default` line per completed rule-set change naming the count, the protocols and the UDP
targets, e.g. `provider rules applied: 1 rule (TCP catch-all)` and
`provider rules applied: 4 rules (TCP catch-all + UDP 198.51.100.7:any, [2001:db8::3]:443, 203.0.113.9:4433)`;
one `.error` line on apply failure: `provider rules apply failed; keeping N installed: <error>`.
Scoped target addresses are logged at default level: they are the operator's own configuration
(already visible in `capture.status.scope_tokens`), not user traffic, and the live proof needs
them to confirm which rules went in. Nothing is logged when wanted == installed. Never payload
bytes; never the addresses of user flows (the framework's own `New flow` lines are Apple's).

### E. Observe-lane consequence

With the default rule set the provider sees **no UDP flows at all**, so the observe-only lane,
when it lands, lists TCP connections only (no DNS or QUIC rows) unless an L4 UDP target is
scoped, in which case it sees datagrams to that target only. This is the consequence Matt
accepted under OQ9 option (a).

### F. Known unknowns (recorded, not resolved)

1. Runtime rule replacement on macOS 27 (header vs DTS 699972) — gated by TR-AC8; T2 is the
   fallback.
2. Whether a `/32`/`/128` rule diverts a single-host datagram (698626 reported prefix 0 failing
   and 16 working) — gated by TR-AC8; R1 is the fallback.
3. Whether R2 confines the `IP_DONTFRAG` breakage per-match or the defect is per-provider —
   measured by TR-AC8 step 2d, recorded either way.
4. Chrome over IPv6 beside a TCP-only rule (thread 698626): unmeasurable on Matt's Mac (no IPv6
   route; `EHOSTUNREACH` in the before-control).
5. What happens to a claimed TCP flow in progress when settings are re-applied (no source says);
   TR-AC8 step 2e observes it once.

### Rust side

`crates/aitm/src/macos_capture/scope_spec.rs` module doc gains one paragraph: IP tokens from
`l4_token` also select the provider's **UDP rule set** (one `.UDP` rule per claimable IP token;
`ip:53/5353/853` tokens contribute none; host/suffix tokens never do), so the default rule set is
TCP-only. No code change; no new test required.

## Acceptance criteria

1. **TR-AC1 (pure rule set, `HandoffSelfCheck` group `providerRules`, run by `ne-selfcheck.sh`).**
   With `ProviderRuleSet.wanted(for:)`:
   - `nil` and `ScopeMatcher(spec: "")` → exactly one rule; `.TCP`, `.outbound`, nil remote,
     `matchRemotePrefix == 0`.
   - `ScopeMatcher(spec: "example.com *.api.test:8443")` → the same single TCP rule.
   - `ScopeMatcher(spec: "198.51.100.7 203.0.113.9:4433 [2001:db8::3]:443 203.0.113.9:53 10.0.0.1:5353 example.com")`
     → exactly 4 rules in this order: the TCP rule; `.UDP` to `198.51.100.7` port `0`, prefix
     `32`; `.UDP` to `2001:db8::3` port `443`, prefix `128`; `.UDP` to `203.0.113.9` port `4433`,
     prefix `32`. The `:53` and `:5353` tokens contribute none. Every rule reads back
     `matchDirection == .outbound`, `matchLocalNetworkEndpoint == nil`, and the stated
     `matchProtocol`/`matchRemoteHostOrNetworkEndpoint`/`matchRemotePrefix`.
   - Wildcard skip: `ScopeMatcher(spec: "0.0.0.0 [::]:4433")` → the single TCP rule.
   - Equality/idempotence: `wanted(for: m) == wanted(for: m)` for each matcher above, and
     `wanted(for: ScopeMatcher(spec: "203.0.113.9:4433 198.51.100.7")) == wanted(for:
     ScopeMatcher(spec: "198.51.100.7 203.0.113.9:4433 198.51.100.7"))` (order and duplicates do
     not matter); `wanted(for: nil) == .tcpOnly`.
2. **TR-AC2 (hook and fail-open, same group).** Over a socketpair-served `CoreLink` with a
   recording hook: one `Scope` frame → the hook fires exactly once with a matcher equal to
   `ScopeMatcher(spec:)` of that frame; closing the core side → the hook fires once with nil
   and, inside that call, `link.current() == nil` already; a `FlowHandoff.claim` with the hook
   installed does not fire it (count unchanged). NE-AC5 holds: `current()` is nil immediately on
   detach, before any rule work.
3. **TR-AC3 (TCP unchanged).** Every existing `claimRule` and `coreLinkAndClaim` check still
   passes unmodified.
4. **TR-AC4 (no wire change).** `git diff ecbf58ac..HEAD -- crates/aitm/src/macos_capture/adapter.rs
   crates/aitm/src/macos_capture/listener.rs` is empty; `grep -n 'protocolVersion: UInt32 = 1'
   apps/mac/Extension/Sources/FlowHandoff.swift` matches; `HandoffConfig`, `CoreMessage`,
   `HandoffMessages` are not in the diff.
5. **TR-AC5 (Rust doc).** `grep -n 'UDP rule' crates/aitm/src/macos_capture/scope_spec.rs` returns
   a `//!` line; no other Rust file changes.
6. **TR-AC6 (gates, output quoted).** `cargo fmt --check && cargo clippy --all-targets -- -D warnings
   && cargo test`; `apps/mac/tools/ne-selfcheck.sh` exit 0 with `PASS`;
   `apps/mac/tools/check-capture-toggle.sh` and `check-capture-operator-only.sh` exit 0;
   `swift test --package-path apps/mac` green.
7. **TR-AC7 (code docs).** The class doc of `TransparentProxyProvider` and the `startProxy`
   comment describe TCP-only default, per-target UDP rules and in-place reconcile; `grep -n
   'hot-edited' TransparentProxyProvider.swift` returns nothing.
8. **TR-AC8 (`[Mac]` live proof, Terminal, after Matt's go relayed by the orchestrator; the
   notarized build of this branch replaces `/Applications/Aitmproxy.app`, release build restored
   afterwards).** With `log stream --predicate 'process == "AitmproxyNE"'` captured:
   1. Capture ON, Scope empty or L7-only: `dontfrag-core.py` reports `setsockopt(DONTFRAG) ok` on
      UDP:443, :53, :123 (matching `control-before.log`); headless Chrome
      `--origin-to-force-quic-on=cloudflare-quic.com:443` renders "your browser used HTTP/3" and
      `quic.nginx.org:443` renders "connected over QUIC"; the framework log shows **zero**
      `NEFlow type = datagram` lines for the provider while TCP `New flow` lines continue;
      `scope.add example.com` + `curl http://example.com/` produces a claimed TCP flow and a row;
      Firefox h3 unaffected.
   2. `l4.scope.add` against **an L4-enabled core that passes peer auth**. The app's embedded
      core is not L4-enabled (its generated `config.yaml` has no `l4:` block —
      `AitmproxyKit/EmbeddedCoreLaunch.swift` `yaml()`), and the provider's `PeerAuth` rejects
      an unsigned debug `aitm`, so the core is the **signed bundle core**
      `/Applications/Aitmproxy.app/Contents/Resources/core/aitm`, run from the Terminal with a
      config carrying `l4.enabled: true` and `macos_capture.enabled: true`, **with the app
      switched to external-core mode (Settings ▸ Bus) for the duration** so only one core
      publishes the rendezvous; `l4.scope.add` runs as operator with the confirm handshake.
      Driver (outside the repo, uses `tests/e2e/aitm_e2e`): `/tmp/claude/ne-tcp/udp-target-proof.py`.
      Entry: Capture, interface `macos-ne`, outbound, host CIDR for a UDP target, any-port or a
      single non-DNS port (the driver's default: `17.253.16.125/32` port `123`, so an NTP request
      to it exercises the rule). Then: (2a) the provider logs `provider rules applied: 2 rules
      (… UDP 17.253.16.125:123)`; (2b) `dontfrag-core.py`'s line for that IP:port reports
      `ECONNRESET` (kernel oracle: the rule covers the socket); (2c) the framework log shows the
      datagram flow to that target and `provider accepted new flow UDP`, and `capture.status`
      `flows_handed_off.udp` (`udp_handed_off` in `status.rs`) increments (NE-AC2); (2d) the
      script's other lines (104.18.27.14:443,
      142.250.73.110:443, 1.1.1.1:53) — record `ok` (per-match confinement) or `ECONNRESET`
      (per-provider) as the R2 measurement; (2e) a long-lived claimed TCP connection to an
      in-scope host opened before step 2 — record whether it survived.
   3. `l4.scope.remove` the entry: the provider logs `provider rules applied: 1 rule (TCP
      catch-all)` and `dontfrag-core.py` is clean again on every line.
   4. Restore the release build; `systemextensionsctl list` shows it `[activated enabled]`.
   **Ladder:** (2a) missing with an `.error` line → a construction bug, fix and re-prove; (2a)
   present but (2b) `ok` and (2c) absent → build T2 keeping R2 and re-prove; T2 still failing
   (2b)/(2c) → switch the mapping to R1 under T2 and re-prove. Each rung is its own plan task.

## Left to the builder

- Names: the `ProviderRuleSet` type and its members, the `ScopeMatcher` derived value, the
  queue label, the hook property name (as long as it is a stored optional closure on
  `CoreLink` with a `FlowHandoff` passthrough), the check labels.
- How `NWEndpoint` read-back is compared in TR-AC1 (pattern match on `.hostPort` or
  `description`), as long as the literal values above are asserted.
- Whether `ProviderRuleSet` stores UDP targets as a struct or an enum, as long as equality is
  canonical (sorted, de-duplicated).
- Exact log wording beyond the elements named in D.

## Open questions

None. OQ9 is decided; every other choice is an Architect's call listed below for Matt to
confirm or correct.

---

**Summary.** Replace the provider's single `.any` catch-all with a pure rule set: one `.TCP`
nil-remote outbound rule always, plus one `.UDP` rule per IP token the `ScopeMatcher` could
actually claim for a datagram (host prefix, token port or any; `ip:53/5353/853` tokens and
wildcards contribute none). The provider derives the set from the `Scope` frames it already
receives — no wire change, protocol version stays 1 — and re-applies `setTunnelNetworkSettings`
in place on a serial, coalescing queue, only when the wanted set differs from the installed
one, never on the claim path, so detach stays instantly fail-open. Because runtime replacement
is unverified on macOS 27, a `[Mac]` live proof gates it, with the app-restart path (T2) and the
single-UDP-catch-all shape (R1) specified as fallbacks. The observe lane consequently lists TCP
only by default. The Apple Feedback (note 25) is Matt's to file.

**Architect's calls:** (A) R2 per-target UDP rules with R1 as the proof-gated fallback;
(B) T1 in-place re-apply with `reasserting` around reconcile applies only, coalescing queue, no
timer retries, T2 as the proof-gated fallback and its detection rule; (C) startup TCP-only
through the same apply path, `stopProxy` drops late hooks; (D) scoped target addresses logged at
default level, silent on no-change; (E) observe lane TCP-only by default, stated plainly;
(F) five known unknowns recorded; (G) canonical (sorted, de-duplicated) rule-set equality;
(H) wildcard addresses skipped; (I) a bare `ip` token's port-0 rule also diverts that IP's
port-53 datagrams, accepted; (J) Rust change is one doc paragraph, no test.
