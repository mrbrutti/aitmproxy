# NE capture: provider claim rule (host tokens are TCP-only, DNS never claimed) — design (hotfix)

**Status:** approved — self-approved 2026-10-31 by the orchestrator session (autonomous
mode; hotfix routed after Matt's live NE verification on v0.5.3).
**Research inputs:** none new. Live evidence from Matt's Mac, 2026-10-31, v0.5.3 notarized
sysext + embedded core, reproduced three times with
`log stream --predicate 'process == "AitmproxyNE"'` (see Intent). Prior specs:
`docs/superpowers/specs/2026-10-30-macos-ne-core-prereqs-design.md` (scope-spec emitter),
`docs/superpowers/specs/2026-10-30-aitmproxy-macos-ne-live-feeder-design.md` (handoff).
**Milestone:** v0.5.4.
**Branch:** `fix/ne-claim-rule` off `main` 8b193a1, worktree
`/Users/matt/Security/aitmproxy/.claude/worktrees/quizzical-payne-463da0`.
**Scope change (coordinator, 2026-10-31):** the core-side half of the original brief
(authority-with-port in `dispatch_tcp`, WARN on a refused capture) is fixed by the
orchestrator in PR #185 and is **out of this PR**. See "Handled elsewhere".

## Intent

Capture never works for an operator who adds a host to Scope on v0.5.3, because the
provider claims the app's **DNS lookup**. macOS attributes an app's resolver datagram to
the app with the looked-up name attached:
`New flow: NEFlow type = datagram, app = com.apple.curl, name = www.example.com, 10.9.11.162:0 <-> 10.9.10.1:53`
→ `handleNewUDPFlow` → `provider accepted new flow UDP com.apple.curl` → `Destroying,
client tx 0, client rx 29, kernel tx 0`; curl: "Resolving timed out". `FlowHandoff.handleUDP`
routes UDP through the same `claim(descriptor)` → `ScopeMatcher.matches(hostname:ip:port:)`
as TCP, so a bare host token (`www.example.com`) matches the port-53 datagram by its
attributed hostname. The embedded user-level core has no L4 backend (`l4: None`), so the
handed-off datagram is `Unhandled`, the data socket closes, the pump ends, and the query
is never answered. Net effect: every bare hostname in Scope makes that host unresolvable
for every app using the system resolver; the only "working" runs had cached DNS. A
port-qualified token (`www.example.com:80`) was verified NOT to claim the port-53 flow.

This hotfix makes the provider's claim rule say what the core can actually do: host and
suffix tokens claim TCP only; UDP is claimable only through an IP token; and a datagram
to a DNS port is never claimed, whatever the scope says.

## Goals

- A bare host or `*.suffix` entry in Scope never black-holes DNS (or any UDP) for that host.
- A TCP flow to an in-scope host is claimed exactly as today (bare host: any port;
  `host:port`: that port only).
- UDP capture stays reachable for an operator who authors an L4 scope (IP tokens), minus
  DNS ports.
- The Extension's self-checks become runnable by one committed script, so a coder, the
  Tester, and the panel run the same gate.

## Non-goals

- The core-side fixes: `dispatch_tcp` gating on `host:dst_port` and logging a refused or
  unhandled capture above `debug` — PR #185 (see "Handled elsewhere"). This PR does not
  touch `crates/aitm/src/ingress.rs`, `crates/aitm/src/macos_capture/feeder.rs`, or
  `crates/aitm/src/macos_capture/adapter.rs`.
- Scope persistence across core restarts (session `local_9c8046c4` owns it; do not touch
  `AitmproxyKit/EmbeddedCoreLaunch.swift`, `BusService.refreshScope`, or Session scope state).
- Emitting the source app on `flow.get` / `flow.table` (next PR; do not touch
  `capture.rs summarize` or `FlowSummary`).
- A UDP relay or an L4 backend in the embedded core.
- Stale-attachment / shared-socket-directory hardening (follow-up, noted in Shipped).
- Any change under `apps/mac/Sources/Aitmproxy/**` (UI) or to the provider's NE rules
  (`TransparentProxyProvider.startProxy` keeps its catch-all `protocol: .any` rule; the
  per-flow decision is where scoping lives).
- Any change to `docs/research/`.

## Anti-goals

- Widening a claim. The provider is a coarse pre-filter under the core's authoritative
  guard; it must never claim a flow the core will refuse or cannot handle (that is the
  bug). Under-inclusive is acceptable; over-inclusive breaks the user's connection.
- Changing TCP claim behaviour as a side effect. The fix is datagram-only.
- A kind-less `matches` overload that lets a future caller skip the transport check.
- A "fix" that only excludes port 53 but still lets a host token claim QUIC (443/udp) or
  any other datagram flow into a core with no UDP backend.
- Shipping the self-check in the release binary (it stays under `#if DEBUG`).

## Constraints

- Swift 6.2, macOS 26 target, no new frameworks. The Extension is compiled by
  `apps/mac/build.sh` as `swiftc Sources/*.swift` without `-D DEBUG`.
- The Extension has **no SwiftPM test target**. Its tests are `enum HandoffSelfCheck`
  (`#if DEBUG`, `static func run() -> [String]`) at the bottom of `FlowHandoff.swift`,
  run by compiling the sources plus a one-line driver with `-D DEBUG`. They need no
  root, no entitlement, no NE: real `socketpair`s, fake flows, `$TMPDIR` only.
- The runner must work from the Claude sandbox (writes only under `$TMPDIR` / the
  chosen scratch dir) and from the Terminal panel.
- `apps/mac/tools/check-capture-toggle.sh` and `check-capture-operator-only.sh` read app
  sources this PR does not touch; they must still exit 0.
- Rust: doc-only change in `scope_spec.rs`; the full Rust gate still runs.
- Live verification is impossible before release: an unnotarized sysext does not
  activate on Matt's Mac, so CR-AC6 is verified on the v0.5.4 DMG.

## Design

### D1. The rule lives in `ScopeMatcher.matches`, keyed by flow kind **(Architect's call)**

`ScopeMatcher.matches` gains the transport as its first parameter:

```swift
func matches(kind: FlowOpenMessage.Kind, hostname: String?, ip: String, port: UInt16) -> Bool
```

`FlowHandoff.claim` passes `flow.kind` (already on `FlowDescriptor`). Reason: `matches`
is the single claim decision point `claim()` already consults, it is pure, and it is
where the existing self-checks live, so the new pins sit next to the old ones. The old
three-argument overload is **removed, not defaulted to `.tcp`**: a caller that forgets
the kind must fail to compile (Anti-goals). The existing self-checks that call it are
updated to pass `kind: .tcp`.

### D2. Rule order inside `matches`

1. `kind == .udp` and `port` ∈ `ScopeMatcher.neverClaimedDatagramPorts` (`53`, `5353`,
   `853`) → `false`, before any entry is consulted. Independent of scope, by design:
   the embedded core cannot answer a DNS query, so claiming one can only break the
   client (fail open).
2. For each entry, the existing port filter (`entry.port` nil or equal) applies.
3. `.ip(address)` entries match either kind by remote IP (as today).
4. `.host(name)` and `.suffix(suffix)` entries match only when `kind == .tcp`.

The constant is a `static let neverClaimedDatagramPorts: Set<UInt16>` on `ScopeMatcher`
(builder may rename, not relocate). `853` (DNS-over-TLS) is included because macOS's
attributed-name datagram path is the thing we are refusing; a TCP:853 flow is not
excluded (D3).

### D3. TCP is unchanged

Bare host claims TCP on any port, `host:port` on that port only, suffix on sub-domains
only. A TCP flow to port 53 from an in-scope host is still claimed, as today: the core's
stream path passes an unclaimed in-scope stream through to the original destination,
so it works, and excluding it would be a behaviour change this hotfix does not make.

### D4. Nothing changes on the wire or in the provider glue

`FlowOpenMessage`, the handoff framing, `handleTCP`, and `handleUDP`'s pump are
untouched. `handleUDP` still builds the descriptor and calls `claim`; the new rule
simply makes `claim` return `nil` for the flows above, and the provider returns `false`
(fail open), exactly its existing contract.

### D5. One committed runner for the self-checks: `apps/mac/tools/ne-selfcheck.sh` **(Architect's call on the shape)**

New file. It:

- resolves the mac dir from its own location (like the two `check-capture-*.sh`
  tripwires) and accepts an optional mac-dir argument;
- uses a scratch dir `${NE_SELFCHECK_SCRATCH:-$HOME/Library/Developer/Aitmproxy/ne-selfcheck}`
  (outside the repo, like `build.sh`; the sandbox sets it to `$TMPDIR/...`);
- writes a driver `main.swift` into the scratch dir that calls `HandoffSelfCheck.run()`,
  prints every returned failure line, and exits `1` if there was any, else prints `PASS`
  and exits `0`;
- compiles every `Extension/Sources/*.swift` **except `Sources/main.swift`** (the real
  entry point parks on `NEProvider.startSystemExtensionMode()` and would never return)
  plus the driver, with exactly:
  `xcrun swiftc -sdk "$(xcrun --show-sdk-path --sdk macosx)" -target "$(uname -m)-apple-macos26.0" -D DEBUG -framework NetworkExtension -module-name AitmproxyNESelfCheck`
  and `-module-cache-path "$scratch/ModuleCache"` so nothing is written outside the
  scratch dir;
- runs the binary; exit `0` = all checks pass, `1` = at least one `FAIL` line (printed
  verbatim), `2` = compile failure (compiler output printed).

Why a shell script and not a SwiftPM test target: the Extension sources are built by
`build.sh` straight from `swiftc`, outside the package; moving them into a package
target is a build-system change with its own review, not a hotfix.

### D6. Documentation in code

- `FlowHandoff.swift`: the GRAMMAR doc block above `struct ScopeMatcher` gains the rule
  (host/suffix tokens are TCP-only; IP tokens cover TCP and UDP; a datagram to
  53/5353/853 is never claimed); the `handleUDP` doc comment states that a UDP flow is
  claimable only through an IP token and never on a DNS port.
- `crates/aitm/src/macos_capture/scope_spec.rs`: the module doc states the same rule
  from the emitter's side — the L7 host/suffix tokens it emits gate TCP only, the L4 IP
  tokens (`l4_token`) are the only way a UDP flow is claimed, and DNS ports are never
  claimed by the provider. Doc-only; the four byte-assertion tests are unaffected.

### Handled elsewhere

- **CR-AC2 (core: `dispatch_tcp` gates on `host:dst_port`, so a `host:port` entry
  matches the handed-off flow on that port)** and **CR-AC3 (core: a `Refused` /
  `Unhandled` captured flow is logged above `debug` with authority, kind, and reason)**
  are delivered by the orchestrator in PR #185
  (https://github.com/mrbrutti/aitmproxy/pull/185). The numbers are reserved here so the
  orchestrator's references stay valid; this PR has no task for them and must not edit
  the files they touch. Note for CR-AC6: a `host:port` entry only yields TCP rows once
  #185 is in the same release.

## Acceptance criteria

1. **CR-AC1 (provider rule).** A datagram (UDP) flow is never claimed through a host or
   suffix token; it is claimable only when an IP token (`ip` or `ip:port`, as
   `scope_spec.rs` emits from the L4 scope) matches; and, independently of scope, a
   datagram whose remote port is 53, 5353, or 853 is never claimed. TCP behaviour is
   unchanged. Proven by `HandoffSelfCheck` checks (run via CR-AC7) that pin, with the
   spec `example.com, *.api.test, 93.184.216.34, 198.51.100.7:443, [2001:db8::1]:443, www.example.com:80`:
   - bare host, UDP: `matches(kind: .udp, hostname: "example.com", ip: "203.0.113.5", port: p)`
     is `false` for `p` in 53, 5353, 853, 443, 1234;
   - suffix, UDP: `matches(kind: .udp, hostname: "x.api.test", ip: "203.0.113.5", port: 443)` is `false`;
   - IP tokens, UDP: `matches(kind: .udp, hostname: nil, ip: "93.184.216.34", port: 443)` is `true`;
     `matches(kind: .udp, hostname: "unrelated.org", ip: "93.184.216.34", port: 4433)` is `true`;
     `matches(kind: .udp, hostname: nil, ip: "198.51.100.7", port: 443)` is `true` and
     `port: 444` is `false`; `matches(kind: .udp, hostname: nil, ip: "2001:db8::1", port: 443)` is `true`;
   - DNS never, even by IP: `matches(kind: .udp, hostname: nil, ip: "93.184.216.34", port: p)`
     is `false` for `p` in 53, 5353, 853;
   - TCP unchanged: `matches(kind: .tcp, hostname: "example.com", ip: "203.0.113.5", port: p)`
     is `true` for `p` in 443, 8080, 53; `matches(kind: .tcp, hostname: "www.example.com", ip: "203.0.113.5", port: 80)`
     is `true` and `port: 443` is `false`; `matches(kind: .tcp, hostname: "x.api.test", ip: "203.0.113.5", port: 8443)`
     is `true`; `matches(kind: .tcp, hostname: nil, ip: "93.184.216.34", port: 53)` is `true`;
   - claim level (in `coreLinkAndClaim`, link armed with `example.com`): a
     `FlowDescriptor(kind: .udp, remote: 93.184.216.34:53, remoteHostname: "example.com")`
     and one to `93.184.216.34:443` both make `claim` return `nil` and dial no data socket
     (`dialPaths` unchanged), while the existing TCP `inside` descriptor is still claimed.
2. **CR-AC2** — handled elsewhere (PR #185).
3. **CR-AC3** — handled elsewhere (PR #185).
4. **CR-AC4 (docs in code).** The GRAMMAR doc block above `ScopeMatcher` and the
   `handleUDP` doc comment in `FlowHandoff.swift`, and the module doc of
   `crates/aitm/src/macos_capture/scope_spec.rs`, each state: host/suffix tokens are
   TCP-only, IP tokens cover UDP, DNS ports (53/5353/853) are never claimed for a
   datagram. Observable by `grep -n '5353' ` on each file returning a doc-comment line.
   No change under `docs/research/`.
5. **CR-AC5 (gates).** All green, output quoted in the Tester's report:
   `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`;
   `swift test --package-path apps/mac --scratch-path ~/Library/Developer/Aitmproxy/test-build`;
   `apps/mac/tools/ne-selfcheck.sh` exit 0 with `PASS`;
   `apps/mac/tools/check-capture-toggle.sh` and `apps/mac/tools/check-capture-operator-only.sh`
   exit 0; three-lane panel with no open findings.
6. **CR-AC6 (manual, live — on the v0.5.4 DMG, not before).** An unnotarized sysext
   does not activate on Matt's Mac, so this is verified after release, on the notarized
   v0.5.4 build installed in `/Applications` (coordinate with the mac-review session
   before replacing `/Applications/Aitmproxy.app`). With capture on and
   `log stream --predicate 'process == "AitmproxyNE"'` running, the A/B scripts
   `/tmp/claude/nescope-test3.py` and `/tmp/claude/nescope-test4.py` (outside the repo;
   they add/remove the entry over the bus, run `curl`, count rows, restore scope) show:
   with Scope = `www.example.com`, the port-53 datagram flow for `com.apple.curl` is
   **not** accepted (no `client rx N, kernel tx 0` destroy on a datagram flow), `curl`
   resolves (`dns=` well under a second, `code=200`), the TCP flow is claimed, and a row
   for `www.example.com` appears; with Scope = `www.example.com:80`, the same (TCP rows
   require #185 in the release); Safari to an in-scope host produces rows. Recorded in
   the plan's Shipped section with the log lines.
7. **CR-AC7 (runner).** `apps/mac/tools/ne-selfcheck.sh` exists, is executable, builds
   as in D5, and: on a tree whose self-checks all pass it prints `PASS` and exits `0`;
   with any failing check it prints each `FAIL …` line and exits `1`; on a compile error
   it exits `2`. Proven by running it on the branch (exit 0) and once with a temporary,
   uncommitted `r.fail("FAIL probe")` added to `HandoffSelfCheck.run()` (exit 1, line
   printed), both outputs quoted in the Coder's report.

## Left to the builder

- Exact names of the new `HandoffSelfCheck` check labels, and whether the new matcher
  pins live in `scope(_:)` or a new `private static func claimRule(_ r: Recorder)`
  added to `run()`.
- The name of the port-set constant (D2) and whether `matches` early-returns or filters
  entries by kind in the loop, as long as D2's order holds.
- Runner details beyond D5: colour, a `--keep` flag, how the driver file is written
  (heredoc), whether compiler warnings are shown.
- Wording of the three doc comments, as long as CR-AC4's three facts are present.

## Open questions

None. The one product call hidden here — TCP:53 stays claimable (D3) — follows the
coordinator's "TCP behaviour is unchanged" and is pinned so a reversal is a visible edit.

## Summary and the Architect's calls

A datagram-only change to the provider's claim rule, keyed on the flow kind the
descriptor already carries, with the DNS-port exclusion applied before scope is
consulted; a committed runner so the Extension's in-file self-checks become a real gate;
and three doc comments. The core side is PR #185. Calls to confirm or correct:
(1) the rule lives in `ScopeMatcher.matches(kind:…)` with the kind-less overload removed;
(2) the DNS exclusion is datagram-only and TCP:53 stays claimable, pinned by a check;
(3) `853` is in the excluded set; (4) the runner's shape (scratch dir, three exit codes,
driver generated at run time, `main.swift` excluded, module cache inside the scratch dir);
(5) CR-AC2/CR-AC3 numbers are reserved rather than renumbered.
