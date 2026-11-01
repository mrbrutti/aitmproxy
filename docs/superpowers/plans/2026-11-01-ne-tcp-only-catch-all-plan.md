# macOS NE: TCP-only catch-all rule, per-target UDP rules — implementation plan

**Status:** approved (2026-11-01, self-approved by the fix session under Matt's autonomous mandate;
no product decision beyond the approved spec; Tester after each task, the three-reviewer panel on the
whole branch before the PR and again after any fix)
**Spec:** `docs/superpowers/specs/2026-11-01-ne-tcp-only-catch-all-design.md` (approved 2026-11-01;
calls A–J accepted; TR-AC8 step 2 amended to name the signed bundle core).
**Branch / worktree:** `fix/ne-tcp-only-rule` in
`/Users/matt/Security/aitmproxy/.claude/worktrees/zealous-roentgen-4de7f1`, base `ecbf58ac`. The
branch already carries the research + Feedback-draft commit and will carry the spec/plan commit.
Coders commit by pathspec in this one worktree.
**Code read for this plan (2026-11-01, `ecbf58ac`):** `apps/mac/Extension/Sources/{TransparentProxyProvider,FlowHandoff,main}.swift`,
`apps/mac/tools/ne-selfcheck.sh`, `apps/mac/build.sh` (sysex compile), `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift`,
`apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift`, `crates/aitm/src/macos_capture/{scope_spec,feeder,adapter,status}.rs`,
`crates/aitm-proto-l4/src/types.rs`; the live-proof helpers outside the repo under `/tmp/claude/ne-tcp/`.
**Size:** four sandbox-testable code tasks (one Rust, three sysex), one real-Mac proof, two
contingency tasks built only if the proof's ladder says so.

## Overview

A new pure type `ProviderRuleSet` (new file `ProviderRules.swift`) maps a `ScopeMatcher?` to the
wanted `NENetworkRule` list: one `.TCP` catch-all always, one `.UDP` host rule per IP token the
matcher could claim a datagram through. `CoreLink` gains an `onScopeChange` hook fired outside
its lock on Scope, detach and serve-start; a small `RuleReconciler` (new file) owns the
installed/pending/in-flight state and coalesces applies; `TransparentProxyProvider` drives it on
one serial queue and re-applies `setTunnelNetworkSettings` in place. No wire change; protocol
version stays 1. Order: the Rust doc (Task 1) and the hook (Task 2) first in parallel; the rule
set (Task 3) after the hook because `wanted(for:)` consumes the matcher's new derived value and
adds one line to `run()`; the provider (Task 4) after both; then the Terminal build and the
`[Mac]` proof (Task 5), whose ladder decides whether Task 6 (T2) or Task 7 (R1) is built.

## Shared facts for every coder

- **TDD per task:** write the named check or test, run it and quote the red run (a compile
  error on a type or member that does not exist yet counts as red), implement, quote the green
  run. The Coder's report includes both runs verbatim.
- **The Extension's test gate is** `NE_SELFCHECK_SCRATCH="$TMPDIR/ne-selfcheck" apps/mac/tools/ne-selfcheck.sh`
  (run from the worktree root). It WORKS in the sandbox. It compiles every
  `apps/mac/Extension/Sources/*.swift` except `main.swift` with `-DDEBUG`, so a new file needs
  no build change and a compile error anywhere in the Extension (the provider included) exits
  `2`; failing checks print `FAIL …` and exit `1`; a clean tree prints `PASS: NE handoff
  self-check` and exits `0`. Checks live in `enum HandoffSelfCheck` (`FlowHandoff.swift`, under
  `#if DEBUG`); a group is a `static func <name>(_ r: Recorder)` listed in `run()`; a new file may
  add groups via `#if DEBUG extension HandoffSelfCheck { … }` and `Recorder.check(_:_:_:)`.
- **Rust in the sandbox:** `cargo fmt --check && cargo clippy --all-targets --offline -- -D warnings
  && cargo test --offline` (full gate) or `cargo test -p aitm --offline scope_spec` for the module.
- **The sandbox cannot** run SwiftPM (`swift test`, `build.sh`), bind sockets, reach GitHub, or
  run `git` network operations. The orchestrator runs `swift test --package-path apps/mac`,
  `apps/mac/tools/check-capture-toggle.sh`, `check-capture-operator-only.sh`, and
  `build.sh --ne` in the Terminal panel before the panel review.
- **Commits:** `git add <exact files> && git commit -- <exact files>`; never `git add -A`, never
  `cargo fmt` on a crate root (leaf files only), never `git stash`.
- **Observe-lane no-go regions (never touch; another session owns them):** `HandoffConfig`,
  `CoreMessage`, `HandoffMessages`, `SelfExclusion`, the pumps (`TCPFlowPump`, `UDPFlowPump`,
  `NETCPFlow`, `NEUDPFlow`), the fixtures (`checkRustFixtures`, `apps/mac/Extension/Fixtures`),
  the first lines of `handleNewFlow`/`handleNewUDPFlow`, `crates/aitm/src/macos_capture/listener.rs`,
  `crates/aitm/src/macos_capture/adapter.rs`. `HANDOFF_PROTOCOL_VERSION` and
  `HandoffConfig.protocolVersion` stay `1` (TR-AC4). Whoever merges second rebases onto the first.
- **Never** log payload bytes or user-flow addresses; never `pkill -f` browsers or obscura.

## Tasks

### Task 1 (D): `scope_spec.rs` module-doc paragraph

- **Satisfies:** TR-AC5; TR-AC4 (no `adapter.rs`/`listener.rs` change); TR-AC6 (Rust gate).
- **Depends on:** none. Independent of Tasks 2–4.
- **Files:** `crates/aitm/src/macos_capture/scope_spec.rs` (modify: the `//!` module doc only; no
  code, no test).
- **Change:** after the existing "**Transport.**" paragraph add one paragraph headed
  "**Provider rule set.**" stating: the IP tokens `l4_token` emits also select the provider's
  **UDP rule set**; the provider installs a TCP-only catch-all `NENetworkRule` by default and one
  `.UDP` host rule per IP token it could claim a datagram through (`ip` → any port, `ip:port` →
  that port); `ip:53`, `ip:5353`, `ip:853` tokens and host/suffix tokens contribute no UDP rule;
  so UDP enters the provider only when the operator scopes an L4 UDP target; a bare `ip` token's
  any-port rule also diverts that IP's port-53 datagrams, which the provider then declines. Cite
  the spec path.
- **Test:** `grep -n 'UDP rule' crates/aitm/src/macos_capture/scope_spec.rs` — red: no output,
  exit 1; green: at least one line beginning `//!`. Then the full Rust gate.
- **Done when:** the grep is green, `git diff --stat` shows only `scope_spec.rs`, and the full
  Rust gate passes with output quoted.

### Task 2 (B): `FlowHandoff.swift` — derived value, `onScopeChange` hook, passthrough, checks

- **Satisfies:** TR-AC2; TR-AC3 (existing checks still pass); spec Design "Signal" and "Hook".
- **Depends on:** none (parallel with Task 1).
- **Files:** `apps/mac/Extension/Sources/FlowHandoff.swift` (modify, four regions only:
  `ScopeMatcher`, `CoreLink`, `FlowHandoff`, `HandoffSelfCheck`).
- **Change:**
  - `ScopeMatcher`: `var udpClaimableIPEntries: [Entry]` — the entries whose `target` is `.ip`
    and whose `port` is `nil` or not in `neverClaimedDatagramPorts`, in entry order. Doc
    comment: this is the set a datagram can be claimed through, and the set the provider builds
    UDP rules from.
  - `CoreLink`: `var onScopeChange: ((ScopeMatcher?) -> Void)?` stored under `lock` (set under
    lock; read under lock into a local; **invoked only after the lock is released**). Fired:
    (a) in `readControl` after `scope = matcher` is stored, with `matcher`; (b) in `detach` with
    `nil`, **only when the `control === handle` guard was true**; (c) in `serve` after
    `scope = nil` is stored in the not-stopped branch, with `nil`. Doc comment: never under
    `lock`, never on the claim path (`current()`/`claim()` do not read it), must return promptly.
  - `FlowHandoff`: `var onScopeChange: ((ScopeMatcher?) -> Void)? { get { link.onScopeChange }
    set { link.onScopeChange = newValue } }`.
  - `HandoffSelfCheck`: new `private static func scopeChangeHook(_ r: Recorder)`; add
    `scopeChangeHook(r)` to `run()` after `coreLinkAndClaim(r)`; add the derived-value pins to
    `claimRule(_:)`.
- **Test (literal):**
  - Derived value, in `claimRule`: with `m = ScopeMatcher(spec: "198.51.100.7 203.0.113.9:4433
    [2001:db8::3]:443 203.0.113.9:53 10.0.0.1:5353 example.com")`, `m.udpClaimableIPEntries ==
    [Entry(target: .ip("198.51.100.7"), port: nil), Entry(target: .ip("203.0.113.9"), port: 4433),
    Entry(target: .ip("2001:db8::3"), port: 443)]`; `ScopeMatcher(spec: "example.com
    *.api.test:8443").udpClaimableIPEntries == []`; `ScopeMatcher(spec: "").udpClaimableIPEntries
    == []`; `ScopeMatcher(spec: "10.0.0.1:853 10.0.0.2:53").udpClaimableIPEntries == []`.
  - Hook, in `scopeChangeHook` (pattern of `coreLinkAndClaim` step 2: `pair()`,
    `ownIdentifierRequirement()`, `setRecvTimeout(core.fd, seconds: 5)`, serve on a `Thread`
    with a `DispatchSemaphore` signalled when `serve` returns): a recorder
    `Box<(ScopeMatcher?, Bool)>` appends `(matcher, link.current() == nil)` on each call; the
    hook is set **before** `serve`. After reading the Hello frame, wait (≤ 2 s, 20 ms polls)
    until `calls.count == 1` (the hook fires on the serve thread after the Hello write):
    `calls[0].0 == nil`, `calls[0].1 == true`. Write `{"Scope":{"spec":"example.com
    198.51.100.7"}}`; wait (≤ 2 s, 20 ms polls) until `calls.count == 2` (not merely
    `current() != nil`, which is observable before the hook runs): `link.current() != nil`,
    `calls[1].0 == ScopeMatcher(spec: "example.com 198.51.100.7")`, `calls[1].1 == false`.
    `FlowHandoff(link: link, …).claim(FlowDescriptor(kind: .tcp, remote: FlowEndpoint(ip:
    "8.8.8.8", port: 443), remoteHostname: "other.org", sourceApp: nil, local: nil)) == nil` and
    `calls.count == 2` still. `core.shutdownBoth()`; wait for the serve semaphore (≤ 5 s):
    `calls.count == 3`, `calls[2].0 == nil`, `calls[2].1 == true`, `link.current() == nil`.
  - Red: `ne-selfcheck.sh` exits `2` with `has no member 'udpClaimableIPEntries'` /
    `'onScopeChange'`. Green: `PASS: NE handoff self-check`, exit `0`.
- **Done when:** the gate is green; every pre-existing check label still passes;
  `grep -n 'protocolVersion: UInt32 = 1' apps/mac/Extension/Sources/FlowHandoff.swift` matches;
  `git diff` touches no no-go region.

### Task 3 (A): `ProviderRules.swift` — the pure rule set and its checks

- **Satisfies:** TR-AC1; spec Design A, G, H, I; the `summary` text of D.
- **Depends on:** Task 2 (`udpClaimableIPEntries`; the `run()` line is added to a file Task 2
  has finished with).
- **Files:** `apps/mac/Extension/Sources/ProviderRules.swift` (create);
  `apps/mac/Extension/Sources/FlowHandoff.swift` (modify: **one line**, `providerRules(r)` in
  `run()` after `scopeChangeHook(r)`; nothing else).
- **Change:**
  ```swift
  struct ProviderRuleSet: Equatable {
      struct UDPTarget: Equatable, Comparable { let address: String; let port: UInt16? }
      let udpTargets: [UDPTarget]                       // canonical: sorted, de-duplicated
      static let tcpOnly: ProviderRuleSet
      static func wanted(for scope: ScopeMatcher?) -> ProviderRuleSet
      func networkRules() -> [NENetworkRule]           // TCP rule first, then one .UDP rule per target
      var summary: String                              // for the log line (spec D)
  }
  ```
  `Comparable`: by `address` (string order), then `port` with `nil` first. `wanted(for:)`: from
  `scope?.udpClaimableIPEntries ?? []`, skip `0.0.0.0` and `::`, skip an address whose
  `Network.NWEndpoint.Host` is not `.ipv4`/`.ipv6`, collect, sort, de-duplicate. `networkRules()`:
  `NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0, localNetworkEndpoint: nil,
  localPrefix: 0, protocol: .TCP, direction: .outbound)`, then per target
  `NENetworkRule(remoteNetworkEndpoint: .hostPort(host: host, port: port.map { NWEndpoint.Port(rawValue: $0)! } ?? .any),
  remotePrefix: host is .ipv4 ? 32 : 128, localNetworkEndpoint: nil, localPrefix: 0, protocol:
  .UDP, direction: .outbound)`. `summary`: `"1 rule (TCP catch-all)"` or
  `"N rules (TCP catch-all + UDP a:any, [b]:443, …)"` (IPv6 bracketed, `any` for a nil port).
  Checks: `#if DEBUG extension HandoffSelfCheck { static func providerRules(_ r: Recorder) }` in
  the new file.
- **Test (literal, TR-AC1):** with `S6 = "198.51.100.7 203.0.113.9:4433 [2001:db8::3]:443
  203.0.113.9:53 10.0.0.1:5353 example.com"`:
  - `wanted(for: nil) == .tcpOnly`; `wanted(for: ScopeMatcher(spec: "")) == .tcpOnly`;
    `wanted(for: ScopeMatcher(spec: "example.com *.api.test:8443")) == .tcpOnly`;
    `wanted(for: ScopeMatcher(spec: "0.0.0.0 [::]:4433")) == .tcpOnly`.
  - `wanted(for: ScopeMatcher(spec: S6)).udpTargets == [UDPTarget("198.51.100.7", nil),
    UDPTarget("2001:db8::3", 443), UDPTarget("203.0.113.9", 4433)]`.
  - `wanted(for: ScopeMatcher(spec: "203.0.113.9:4433 198.51.100.7")) == wanted(for:
    ScopeMatcher(spec: "198.51.100.7 203.0.113.9:4433 198.51.100.7"))`.
  - `tcpOnly.networkRules()` has count `1`; `rules[0].matchProtocol == .TCP`, `.matchDirection
    == .outbound`, `.matchRemoteHostOrNetworkEndpoint == nil`, `.matchRemotePrefix == 0`,
    `.matchLocalNetworkEndpoint == nil`.
  - `wanted(for: ScopeMatcher(spec: S6)).networkRules()` has count `4`; `rules[0]` as above;
    `rules[1]`: `.UDP`, `.outbound`, endpoint `198.51.100.7` port `0`, prefix `32`; `rules[2]`:
    `.UDP`, endpoint `2001:db8::3` port `443`, prefix `128`; `rules[3]`: `.UDP`, endpoint
    `203.0.113.9` port `4433`, prefix `32`; every rule `matchLocalNetworkEndpoint == nil`.
    (Compare the endpoint by pattern-matching `.hostPort(host:port:)` and `"\(host)"`, or by
    `description`; the builder picks, the values above are asserted.)
  - `tcpOnly.summary == "1 rule (TCP catch-all)"`; `wanted(for: ScopeMatcher(spec: S6)).summary
    == "4 rules (TCP catch-all + UDP 198.51.100.7:any, [2001:db8::3]:443, 203.0.113.9:4433)"`.
  - Red: `ne-selfcheck.sh` exit `2`, `cannot find 'ProviderRuleSet' in scope` (write the check
    group and the `run()` line first). Green: `PASS`, exit `0`.
- **Done when:** gate green; `git diff --stat` shows the new file and a one-line change in
  `FlowHandoff.swift`.

### Task 4 (C): `RuleReconciler.swift` + `TransparentProxyProvider.swift`

- **Satisfies:** spec Design B, C, D; TR-AC7; the Goals' two-applications bound; NE-AC5 kept.
- **Depends on:** Tasks 2 and 3.
- **Files:** `apps/mac/Extension/Sources/RuleReconciler.swift` (create);
  `apps/mac/Extension/Sources/TransparentProxyProvider.swift` (modify: class doc comment,
  `startProxy`, `stopProxy`, new private members; **not** `handleNewFlow`/`handleNewUDPFlow`);
  `apps/mac/Extension/Sources/FlowHandoff.swift` (modify: one line `ruleReconciler(r)` in `run()`).
- **Change:**
  ```swift
  /// Coalescing apply state. NOT thread-safe by itself: the owner calls every method, and
  /// delivers every apply completion, on one serial queue.
  final class RuleReconciler {
      enum Event: Equatable {
          case applied(ProviderRuleSet)
          case applyFailed(wanted: ProviderRuleSet, kept: ProviderRuleSet?, message: String)
      }
      typealias Apply = (_ wanted: ProviderRuleSet, _ reasserting: Bool,
                         _ completion: @escaping (Error?) -> Void) -> Void
      init(apply: @escaping Apply, onEvent: @escaping (Event) -> Void)
      private(set) var installed: ProviderRuleSet?
      func begin(completion: @escaping (Error?) -> Void)   // startup: stopped = false, pending = .tcpOnly, apply with reasserting false; completion gets that apply's result
      func reconcile(for scope: ScopeMatcher?)             // pending = ProviderRuleSet.wanted(for:); applyIfNeeded(reasserting: true)
      func stop()                                           // stopped = true; installed = nil; an in-flight completion is then ignored
  }
  ```
  `applyIfNeeded`: return unless `!stopped && !inFlight && pending != installed`; set
  `inFlight`; call `apply(pending, reasserting)`; in the completion: `inFlight = false`; if
  `stopped` return; on `nil` error `installed = wanted` and `onEvent(.applied)`, else
  `onEvent(.applyFailed(kept: installed))`; then `applyIfNeeded(reasserting: true)` again
  (coalescing: at most one in flight plus one pending). Provider: `private let rulesQueue =
  DispatchQueue(label: "com.mrbrutti.aitmproxy.ne.rules")`; a `RuleReconciler` whose `apply`
  builds `NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")`, sets
  `includedNetworkRules = wanted.networkRules()`, sets `self.reasserting = true` iff asked, calls
  `setTunnelNetworkSettings`, and in its completion **hops onto `rulesQueue`**, clears
  `reasserting` iff it set it, then calls the reconciler's completion; `onEvent` logs per spec D
  (`.default` "provider rules applied: <summary>"; `.error` "provider rules apply failed; keeping
  <kept summary or none> installed: <error>"). `func reconcileRules(for scope: ScopeMatcher?) {
  rulesQueue.async { reconciler.reconcile(for: scope) } }`. `startProxy`: set
  `handoff.onScopeChange = { [weak self] in self?.reconcileRules(for: $0) }`, then
  `handoff.start()`, then on `rulesQueue` `reconciler.begin { error in … }` whose body keeps
  today's error handling (`os_log` + `handoff.stop()`) and calls `completionHandler(error)`.
  `stopProxy`: on `rulesQueue` `reconciler.stop()`, then `handoff.stop()`, then the completion
  (a hook fired by the resulting detach is enqueued after the stop and dropped). Rewrite the
  class doc and the `startProxy` comment to describe TCP-only default, per-target UDP rules and
  in-place reconcile (TR-AC7). Checks: `#if DEBUG extension HandoffSelfCheck { static func
  ruleReconciler(_ r: Recorder) }` in `RuleReconciler.swift`.
- **Test (literal):** a fake `apply` appends `(wanted, reasserting)` to `applied` and stashes
  each completion in `completions`; `events` records `onEvent`; `m1 = ScopeMatcher(spec:
  "example.com 198.51.100.7")`, `m2 = ScopeMatcher(spec: "198.51.100.7 203.0.113.9:4433")`,
  `w1 = ProviderRuleSet.wanted(for: m1)` (udpTargets `[UDPTarget("198.51.100.7", nil)]`):
  1. `begin` → `applied.count == 1`, `applied[0] == (.tcpOnly, false)`, `installed == nil`,
     startup completion not yet called.
  2. `completions[0](nil)` → `installed == .tcpOnly`, startup completion called with `nil`,
     `events == [.applied(.tcpOnly)]`.
  3. `reconcile(for: nil)` → `applied.count == 1`.
  4. `reconcile(for: m1)` → `applied.count == 2`, `applied[1] == (w1, true)`.
  5. In flight: `reconcile(for: m2)` then `reconcile(for: nil)` → `applied.count == 2`.
  6. `completions[1](nil)` → `installed == w1`, then `applied.count == 3`, `applied[2] ==
     (.tcpOnly, true)` (m2 coalesced away).
  7. `completions[2](nil)` → `installed == .tcpOnly`, `applied.count == 3`.
  8. `reconcile(for: m1)` → `applied.count == 4`; `completions[3](NSError(domain: "test", code:
     1))` → `installed == .tcpOnly`, `events.last` is `.applyFailed(wanted: w1, kept: .tcpOnly,
     message:)` with message containing `"test"`.
  9. `reconcile(for: m1)` → `applied.count == 5` (retried on the next change, not by timer);
     `completions[4](nil)` → `installed == w1`.
  10. `stop()` → `installed == nil`; `reconcile(for: nil)` → `applied.count == 5`.
  11. `begin` again (Tahoe double-`startProxy` tolerance) → `applied.count == 6`, `applied[5] ==
      (.tcpOnly, false)`.
  - Red: `ne-selfcheck.sh` exit `2`, `cannot find 'RuleReconciler' in scope`. Green: `PASS`,
    exit `0`. Also `grep -n 'hot-edited' apps/mac/Extension/Sources/TransparentProxyProvider.swift`
    prints nothing (TR-AC7).
- **Done when:** gate green; the diff of `TransparentProxyProvider.swift` leaves
  `handleNewFlow`/`handleNewUDPFlow` byte-identical; the orchestrator's Terminal
  `apps/mac/build.sh --ne …` compiles the sysex and `swift test --package-path apps/mac`,
  `check-capture-toggle.sh`, `check-capture-operator-only.sh` are green (TR-AC6).

### Task 5 (E): `[Mac]` live proof — TR-AC8

- **Satisfies:** TR-AC8 (all four steps and the ladder); confirms Goals 1–3.
- **Depends on:** Task 4; the Terminal build; **Matt's go relayed by the orchestrator** (the
  notarized build of this branch replaces `/Applications/Aitmproxy.app`).
- **Owner:** the orchestrator, in the Terminal panel. No coder.
- **Files:** none in the repo. Helpers outside it: `/tmp/claude/ne-tcp/{build-install.sh,
  control-before.sh, quic-check.sh, ne-log.sh, capture-toggle.sh, udp-target-proof.py,
  dontfrag-core.py, restore-release.sh}`; outputs under `/tmp/claude/ne-tcp/out/`
  (`control-before.log` already exists).
- **Steps:**
  0. `build-install.sh` (saves the release bundle, `build.sh --ne --allow-unnotarized --replace`,
     `notarytool … --keychain-profile aitm-notary --wait`, staple, launch); confirm
     `systemextensionsctl list` shows the new `CFBundleVersion` `[activated enabled]`, and
     `ne-log.sh 2m 'rules applied'` shows `provider rules applied: 1 rule (TCP catch-all)`.
  1. Capture ON, Scope empty or L7-only, the app's embedded core: `python3 -I dontfrag-core.py`
     → every non-loopback line `setsockopt(DONTFRAG) ok`; `quic-check.sh after` → "your browser
     used HTTP/3" and "connected over QUIC"; `ne-log.sh 5m 'datagram'` → zero `NEFlow type =
     datagram` lines for the provider while `New flow` TCP lines continue; `scope.add
     example.com` + `curl http://example.com/` → a claimed TCP flow and a row; Firefox h3 still
     renders.
  2. Switch the app to external-core mode (Settings ▸ Bus); run `udp-target-proof.py` (starts
     the signed bundle core with `l4.enabled` + `macos_capture.enabled`, waits for attach,
     `l4.scope.add` as operator with confirm for `17.253.16.125/32` port `123`, probes, removes).
     Record: (2a) `ne-log.sh … 'rules applied'` shows `… 2 rules (TCP catch-all + UDP
     17.253.16.125:123)`; (2b) the driver's `dontfrag_scoped.target` is `ECONNRESET`; (2c) the
     driver's `in-scope UDP flow handed off (NE-AC2)` step is PASS and `ne-log.sh` shows the
     datagram flow and `provider accepted new flow UDP`; (2d) `dontfrag_scoped.others` recorded
     as the R2 measurement (`ok` = per-match confinement, `ECONNRESET` = per-provider); (2e) a
     claimed TCP connection opened before step 2 to an in-scope host — record survived or not.
  3. The driver's removal half: `rules applied: 1 rule (TCP catch-all)` logged and
     `dontfrag_after_removal == "ok"`; re-run `dontfrag-core.py` → all `ok`.
  4. Switch the app back to the embedded core; `restore-release.sh`; `systemextensionsctl list`
     shows the release build `[activated enabled]`.
- **Ladder (decides Tasks 6/7):** (2a) missing with a `provider rules apply failed` line → a
  construction bug: a fix task on Task 3/4, re-prove. (2a) present, (2b) `ok` and (2c) FAIL →
  **Task 6**, re-prove. Task 6 built and (2b)/(2c) still failing → **Task 7**, re-prove.
- **Done when:** the Shipped section quotes the log lines, the driver's `SUMMARY` JSON, the
  Chrome text lines, and the 2d/2e observations, and step 4 is confirmed.

### Task 6 (F): contingency T2 — app-side tunnel restart with start options

- **Build only if** Task 5's ladder says so. Otherwise it is not built and this section stays
  as the record of what would be.
- **Satisfies:** spec Design B "T2 contingency"; TR-AC8 re-proof.
- **Depends on:** Task 5 verdict.
- **Files:** `apps/mac/Sources/AitmproxyKit/UDPRuleTargets.swift` (create),
  `apps/mac/Tests/AitmproxyKitTests/UDPRuleTargetsTests.swift` (create),
  `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift` (modify),
  `apps/mac/Extension/Sources/TransparentProxyProvider.swift` (modify: `startProxy(options:)`),
  `apps/mac/Sources/AitmproxyKit/CaptureCapability.swift` + `CaptureCapabilityTests.swift`
  (modify **only if** the restart's `.tunnelDisconnected` → `.tunnelConnected` pass needs a
  distinct state; otherwise untouched).
- **Change:** Kit `enum UDPRuleTargets { static func from(scopeTokens: [String]) -> [String] }`
  — keeps IP tokens (`ip`, `ip:port`, `[ip]:port`) whose port is absent or not 53/5353/853 and
  whose address is not `0.0.0.0`/`::`, input order, duplicates removed. `ExtensionController`:
  `func restartTunnel(udpTargets: [String]) async` — `stopVPNTunnel()`, await `.disconnected`
  through the existing observer (bounded 10 s), `startVPNTunnel(options: ["udp_targets":
  udpTargets as NSArray])`; called when the UDP target set derived from the polled
  `capture.status.scope_tokens` changes; operator-only surfaces untouched (the tripwire scripts
  must stay green). Provider: `startProxy(options:)` reads `options?["udp_targets"] as?
  [String]`, builds `ProviderRuleSet.wanted(for: ScopeMatcher(spec: tokens.joined(separator:
  " ")))` as the startup set in `begin`, and the hook becomes a log-only recorder.
- **Test (literal):** `UDPRuleTargets.from(scopeTokens: ["198.51.100.7", "203.0.113.9:4433",
  "[2001:db8::3]:443", "203.0.113.9:53", "10.0.0.1:5353", "example.com", "*.api.test:8443",
  "0.0.0.0", "198.51.100.7"]) == ["198.51.100.7", "203.0.113.9:4433", "[2001:db8::3]:443"]`;
  `from(scopeTokens: []) == []`. Run by `swift test --package-path apps/mac` (Terminal). The
  reconciler check from Task 4 gains a case: `begin(startup: w1)` → `applied[0] == (w1, false)`.
- **Done when:** Kit test green, tripwires green, Task 5 re-run with the ladder's verdict recorded.

### Task 7 (G): contingency R1 — one UDP catch-all rule instead of per-target rules

- **Build only if** Task 5's ladder says so (a `/32` rule does not divert the datagram).
- **Satisfies:** spec Design A fallback; TR-AC1 pins updated to the R1 shape.
- **Depends on:** Task 5 verdict (and Task 6 if it was built).
- **Files:** `apps/mac/Extension/Sources/ProviderRules.swift` (modify only).
- **Change:** `networkRules()` emits, when `udpTargets` is non-empty, **one**
  `NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0, localNetworkEndpoint: nil,
  localPrefix: 0, protocol: .UDP, direction: .outbound)` after the TCP rule instead of the
  per-target rules; `udpTargets` and equality are unchanged (the "no change" semantics still key
  on the claimable set); `summary` becomes `"2 rules (TCP catch-all + UDP catch-all)"`.
- **Test (literal):** `wanted(for: ScopeMatcher(spec: S6)).networkRules()` has count `2`;
  `rules[1].matchProtocol == .UDP`, `.matchDirection == .outbound`,
  `.matchRemoteHostOrNetworkEndpoint == nil`, `.matchRemotePrefix == 0`; `summary == "2 rules
  (TCP catch-all + UDP catch-all)"`; every TCP-only vector of Task 3 unchanged. Red: the Task 3
  pins fail (`FAIL …`, exit `1`) once the pins are rewritten; green: `PASS`.
- **Done when:** gate green; Task 5 re-run; the spec's Design A gets a one-line "R1 built,
  reason" note by the orchestrator in the Shipped section (the spec itself is not edited).

## Parallelization

| Wave | Tasks | Why this grouping |
|---|---|---|
| 1 | Task 1 (D) ∥ Task 2 (B) | disjoint files: `scope_spec.rs` vs `FlowHandoff.swift` |
| 2 | Task 3 (A) | needs `udpClaimableIPEntries` from Task 2 and adds one `run()` line to a file Task 2 has released |
| 3 | Task 4 (C) | needs `ProviderRuleSet` (Task 3) and `onScopeChange` (Task 2); adds one `run()` line |
| 4 | Terminal: `build.sh --ne`, `swift test`, tripwires, notarize; Task 5 (E) | orchestrator, after Matt's go |
| 5 | Task 6 (F) and/or Task 7 (G), then Task 5 again | only as the ladder directs; F and G touch disjoint files and may run in parallel if both are needed |

Two writers never share a file: `FlowHandoff.swift` is edited by Tasks 2, 3 and 4 strictly in
sequence (one line each for 3 and 4). Each task's Tester and panel run before the next wave.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

Filled at stage 7: what merged, the Task 5 evidence (log lines, driver `SUMMARY`, Chrome text,
2d/2e observations), which contingency (if any) was built and why, follow-ups (the Apple
Feedback in `docs/research/25-…` is Matt's to file; the observe-lane plan's Task 15
expectations assume this fix is on main).
