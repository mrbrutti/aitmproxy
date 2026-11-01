# NE capture: provider claim rule — implementation plan (hotfix)

**Status:** approved — self-approved 2026-10-31 by the orchestrator session (autonomous mode)
**Spec:** `docs/superpowers/specs/2026-10-31-ne-claim-rule-design.md`
**Branch / worktree:** `fix/ne-claim-rule` off `main` 8b193a1, in
`/Users/matt/Security/aitmproxy/.claude/worktrees/quizzical-payne-463da0`

## Overview

Three file-disjoint tasks. **Run Task 2 first**: it adds the committed runner for the
Extension's in-file self-checks, which Task 1 uses as its red/green gate. Task 1 (the
provider rule plus its Swift doc comments) depends on Task 2. Task 3 (Rust doc-only) is
independent of both and may fan out immediately alongside Task 2. The core-side half of
the original brief is PR #185 and has no task here (spec, "Handled elsewhere"):
`crates/aitm/src/ingress.rs`, `macos_capture/feeder.rs`, and `macos_capture/adapter.rs`
are not edited on this branch.

Shared facts for every coder:

- The Extension has no SwiftPM test target. Its tests are `enum HandoffSelfCheck`
  (`#if DEBUG`) at the bottom of `apps/mac/Extension/Sources/FlowHandoff.swift`;
  `static func run() -> [String]` returns failure lines (each starts with `FAIL `) and
  is empty on success. A check is `r.check("label", <Bool>, <detail>)`.
- Swift builds need the Terminal panel or a sandbox-writable scratch dir: inside the
  sandbox run the runner as `NE_SELFCHECK_SCRATCH="$TMPDIR/ne-selfcheck" apps/mac/tools/ne-selfcheck.sh`.
- Gates (spec CR-AC5), run from the worktree root:
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`;
  `swift test --package-path apps/mac --scratch-path ~/Library/Developer/Aitmproxy/test-build`;
  `apps/mac/tools/ne-selfcheck.sh`; `apps/mac/tools/check-capture-toggle.sh`;
  `apps/mac/tools/check-capture-operator-only.sh`.

## Tasks

### Task 2: the self-check runner `apps/mac/tools/ne-selfcheck.sh`  (do this first)

- **Satisfies:** CR-AC7; enables CR-AC1's test and the `ne-selfcheck.sh` line of CR-AC5
- **Depends on:** none
- **Files:** `apps/mac/tools/ne-selfcheck.sh` (create, `chmod +x`)
- **Change:** a `#!/usr/bin/env bash` script with `set -euo pipefail`, modelled on the
  header style of `apps/mac/tools/check-capture-operator-only.sh`. Behaviour (spec D5):
  - `mac_dir=${1:-<the apps/mac that holds this script>}`; fails with a message if
    `$mac_dir/Extension/Sources/FlowHandoff.swift` is missing.
  - `scratch=${NE_SELFCHECK_SCRATCH:-$HOME/Library/Developer/Aitmproxy/ne-selfcheck}`;
    `mkdir -p "$scratch/ModuleCache"`.
  - Writes `$scratch/main.swift` (heredoc): calls `HandoffSelfCheck.run()`, prints each
    returned line to stdout, exits `1` if the array is non-empty, else prints `PASS: NE handoff self-check`
    and exits `0`.
  - Collects sources: every `$mac_dir/Extension/Sources/*.swift` except
    `Sources/main.swift` (the real entry point calls `NEProvider.startSystemExtensionMode()`
    and parks in `dispatchMain()`), plus `$scratch/main.swift`.
  - Compiles with exactly
    `xcrun swiftc -sdk "$(xcrun --show-sdk-path --sdk macosx)" -target "$(uname -m)-apple-macos26.0" -DDEBUG -framework NetworkExtension -module-name AitmproxyNESelfCheck -module-cache-path "$scratch/ModuleCache" -o "$scratch/AitmproxyNESelfCheck" <sources>`;
    on compiler failure prints the compiler output and exits `2`.
  - Runs `$scratch/AitmproxyNESelfCheck` and exits with its status (0 or 1).
  - Usage comment at the top: `tools/ne-selfcheck.sh [mac-dir]`, the env var, the three
    exit codes, and why `main.swift` is excluded.
- **Test:** no unit test (shell). Verification, both outputs quoted in the report:
  1. On the branch as checked out (before Task 1): `apps/mac/tools/ne-selfcheck.sh`
     prints `PASS: NE handoff self-check` and `echo $?` is `0`.
  2. Temporarily add `r.fail("FAIL probe")` as the first line of `HandoffSelfCheck.run()`
     after `let r = Recorder()`, run again: stdout contains the line `FAIL probe`,
     `echo $?` is `1`. Revert the probe (`git diff --stat` shows only the new script).
  3. `NE_SELFCHECK_SCRATCH="$TMPDIR/ne-selfcheck" apps/mac/tools/ne-selfcheck.sh` also
     exits `0` (sandbox path), and `ls "$TMPDIR/ne-selfcheck"` shows `main.swift`,
     `ModuleCache`, `AitmproxyNESelfCheck`.
  4. `apps/mac/tools/ne-selfcheck.sh /nonexistent` exits non-zero with a one-line message.
- **Done when:** the four verifications above hold; `git status` shows only the new
  executable file; `cargo` gate untouched (no Rust change) — state that, do not re-run it.

### Task 1: datagram claim rule in `ScopeMatcher` + self-checks + Swift doc comments

- **Satisfies:** CR-AC1; CR-AC4 (the two Swift doc comments)
- **Depends on:** Task 2 (its gate)
- **Files:** `apps/mac/Extension/Sources/FlowHandoff.swift` (modify) — nothing else
- **Change:**
  - `struct ScopeMatcher`: add `static let neverClaimedDatagramPorts: Set<UInt16> = [53, 5353, 853]`.
  - Replace `func matches(hostname: String?, ip: String, port: UInt16) -> Bool` with
    `func matches(kind: FlowOpenMessage.Kind, hostname: String?, ip: String, port: UInt16) -> Bool`.
    Order (spec D2): (1) `kind == .udp && Self.neverClaimedDatagramPorts.contains(port)` →
    `false` before the entry loop; (2) existing per-entry port filter; (3) `.ip` matches
    either kind; (4) `.host` / `.suffix` match only when `kind == .tcp`. Do **not** keep
    a kind-less overload or a default argument.
  - `FlowHandoff.claim(_:)`: the scope guard becomes
    `attachment.scope.matches(kind: flow.kind, hostname: …, ip: …, port: …)`.
  - Doc comments (CR-AC4): extend the GRAMMAR block above `struct ScopeMatcher`
    (currently `/// GRAMMAR (the Rust side …`) with the rule — host and `*.suffix`
    tokens claim TCP only; IP tokens claim TCP and UDP; a datagram to 53, 5353, or 853 is
    never claimed, whatever the spec says. Extend the `handleUDP` doc comment
    (`/// `handleNewUDPFlow` (macOS 15+ …`) with: a UDP flow is claimable only through
    an IP token and never on a DNS port; host/suffix entries never claim it.
  - `HandoffSelfCheck`: update the existing `scope(_:)` calls to pass `kind: .tcp`
    (same expectations). Add the CR-AC1 pins — either in `scope(_:)` or a new
    `private static func claimRule(_ r: Recorder)` registered in `run()` after `scope(r)`
    (builder's choice) — using
    `ScopeMatcher(spec: "example.com, *.api.test, 93.184.216.34, 198.51.100.7:443, [2001:db8::1]:443, www.example.com:80")`.
    In `coreLinkAndClaim(_:)`, after step 4 ("in scope is claimed"), add the two UDP
    claim checks against the armed `example.com` link.
- **Test** (the literal expected values; `kind:` abbreviated as `.udp` / `.tcp`):
  | check | call | expected |
  |---|---|---|
  | bare host never claims UDP | `.udp, "example.com", "203.0.113.5", p` for p in 53, 5353, 853, 443, 1234 | `false` ×5 |
  | suffix never claims UDP | `.udp, "x.api.test", "203.0.113.5", 443` | `false` |
  | bare IP token claims UDP | `.udp, nil, "93.184.216.34", 443` | `true` |
  | IP token ignores hostname | `.udp, "unrelated.org", "93.184.216.34", 4433` | `true` |
  | ip:port token, that port | `.udp, nil, "198.51.100.7", 443` | `true` |
  | ip:port token, other port | `.udp, nil, "198.51.100.7", 444` | `false` |
  | IPv6 token claims UDP | `.udp, nil, "2001:db8::1", 443` | `true` |
  | DNS never, even by IP | `.udp, nil, "93.184.216.34", p` for p in 53, 5353, 853 | `false` ×3 |
  | TCP bare host any port | `.tcp, "example.com", "203.0.113.5", p` for p in 443, 8080, 53 | `true` ×3 |
  | TCP host:port that port | `.tcp, "www.example.com", "203.0.113.5", 80` | `true` |
  | TCP host:port other port | `.tcp, "www.example.com", "203.0.113.5", 443` | `false` |
  | TCP suffix | `.tcp, "x.api.test", "203.0.113.5", 8443` | `true` |
  | TCP IP token on 53 | `.tcp, nil, "93.184.216.34", 53` | `true` |
  | claim: UDP DNS with matching name | `handoff.claim(FlowDescriptor(kind: .udp, remote: FlowEndpoint(ip: "93.184.216.34", port: 53), remoteHostname: "example.com", sourceApp: "com.apple.curl", local: nil))` | `nil`; `dialPaths.all` unchanged |
  | claim: UDP 443 with matching name | same with `port: 443` | `nil`; `dialPaths.all` unchanged |
  TDD order, both runs quoted: (a) add the checks first and run
  `apps/mac/tools/ne-selfcheck.sh` → exit `1` with `FAIL` lines for the UDP pins (the
  compile may also fail on the missing `kind:` label — that is the red run; show it);
  (b) implement; run again → `PASS: NE handoff self-check`, exit `0`.
- **Done when:** the runner passes; `grep -n '5353' apps/mac/Extension/Sources/FlowHandoff.swift`
  shows the constant and the two doc-comment lines; `grep -n 'func matches(' apps/mac/Extension/Sources/FlowHandoff.swift`
  shows exactly one signature and it starts with `kind:`; `swift test --package-path apps/mac …`,
  `check-capture-toggle.sh`, and `check-capture-operator-only.sh` all exit 0; no file
  other than `FlowHandoff.swift` changed.

### Task 3: `scope_spec.rs` module doc

- **Satisfies:** CR-AC4 (the Rust half)
- **Depends on:** none (independent of Tasks 1 and 2)
- **Files:** `crates/aitm/src/macos_capture/scope_spec.rs` (modify, doc comment only)
- **Change:** in the `//!` module doc (lines 1–15), add one short paragraph stating the
  provider's claim rule from the emitter's side: the L7 host / `host:port` / `*.suffix`
  tokens this module emits gate **TCP only**; a UDP flow is claimed only through an L4
  IP token (`ip` / `ip:port` from `l4_token`); and a datagram to port 53, 5353, or 853
  is never claimed regardless of tokens, because the embedded core has no UDP backend
  and the provider must fail open on the system resolver. No code change, no new tokens.
- **Test:** `cargo test -p aitm scope_spec` still passes (4 tests, unchanged
  byte-assertions); `grep -n '5353' crates/aitm/src/macos_capture/scope_spec.rs` prints
  a `//!` line; `cargo doc -p aitm --no-deps` emits no new warning for this module.
- **Done when:** the full Rust gate is green
  (`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`),
  output quoted; `git diff --stat` shows only `scope_spec.rs` with additions in comment
  lines only.

## Stage 5/6 notes for the orchestrator

- Tester on Task 1: besides re-running the runner, confirm no caller of the old
  three-argument `matches` survives (`grep -rn 'matches(hostname:' apps/mac/Extension`
  returns nothing) and that `TransparentProxyProvider.swift` is unchanged.
- Panel on the whole branch: the security lane should confirm the claim is strictly
  narrower than before (no new `true` path), and that `neverClaimedDatagramPorts` is
  consulted before any entry (fail open independent of scope).
- CR-AC6 is deferred to the v0.5.4 DMG (spec); record its log lines under Shipped.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| all | Tester (stage 5) | — | PASS conditional on the Terminal-only gates: every CR-AC mapped (CR-AC2/3 → PR #185, CR-AC6 → v0.5.4 DMG); 13/13 mutants against the rule killed (incl. DNS set applied to both kinds, `claim()` passing `.tcp`/`.udp` unconditionally, FlowOpen hard-coding Tcp, reverting `decodeCore`); 30 self-checks added, production region byte-identical to the coder's; `ne-selfcheck.sh` PASS ×4, fmt/clippy PASS, both tripwires PASS; sandbox `cargo test` cannot bind sockets (EPERM) | Terminal gates: `swift test` 408 + 27 green; `cargo test` see the row below |
| 1 | Tester | Minor | `decodeCore` now throws `malformed` for a `Scope` frame whose payload is not an object (base: silently ignored) — production change outside D1–D6, made so the pre-existing red self-check (`decode rejects {"Scope":"x"}`) no longer blocks the gate | ACCEPTED, recorded under Shipped: strictly narrower; the channel peer is already signature-verified, teardown → detach → fail open |
| 1 | Tester | Minor | `coreLinkAndClaim` self-check hung forever under a wrongly refused TCP claim (mutant `claim()` passes `.udp`), so the gate would hang instead of failing | FIXED by the tester (test code only): `setRecvTimeout` on the fake core fd and data-socket reads, as `framing(_:)` already did |
| 2 | Coder/Tester | Minor | Spec D5 and the plan said `-D DEBUG`; the runner uses the single token `-DDEBUG` (swiftc accepts either; one early failed run was misattributed to the spelling — quality review) | FIXED — spec, plan and the runner header say `-DDEBUG` without a causal claim |
| 3 | Coder | Minor | Rust test `ScopeMatcherMirror` in `scope_spec.rs` still cites the old three-argument Swift signature and line numbers (test-only drift, no `kind` dimension) | ACCEPTED as follow-up: add the `kind` dimension to the mirror with the L4 IP-token Rust test |
| all | Security (stage 6) | — | PASS with Minors: claim strictly narrower (TCP path textually equal to base; UDP only via IP tokens; rule 1 before any entry, pinned by `ip:53`/`ip:853` tokens); fail-open paths return before dial/FlowOpen; `#if DEBUG` block excluded from the shipped sysext; `decodeCore` teardown is the same fail-open as a disconnect | — |
| 2 | Security | Minor | Runner built the driver and binary at fixed names under a scratch root shared by every session, so two concurrent gates could overwrite each other and a result could belong to the wrong tree | FIXED — `mktemp -d "$scratch/run.XXXXXX"` per invocation, `trap rm -rf` on exit; ModuleCache stays shared |
| 1,3 | Security | Nit | Doc comments quoted Matt's LAN addresses | FIXED — RFC 5737 addresses in the GRAMMAR doc and the spec's evidence quote |
| 1 | Spec (stage 6) | Important | `decodeCore` behaviour change is production code the spec did not ask for (D4 said glue untouched); the builder should have stopped on the gap | FIXED by amendment — spec D7 + CR-AC8, Shipped note here; code kept (reverting re-reds the gate; the check is the stated contract) |
| all | Spec | Minor | Coder/Tester reports were not attached to the review log, so CR-AC7's "quoted in the Coder's report" clause was unverifiable | FIXED — the quoted gate outputs are summarised in this log (tester row above, coder outputs: red run `error: extra argument 'kind' in call` ×112 diagnostics then 15 `FAIL` lines with the rule unimplemented; green `PASS: NE handoff self-check`; runner probe `FAIL probe` exit 1, `/nonexistent` exit 2) |
| all | Spec | Minor | Implementation uncommitted across tasks; tester hunks not separable by commit prefix | FIXED — committed per task (runner, scope_spec doc, FlowHandoff rule + tester pins) before integration |
| all | Quality (stage 6) | — | PASS: `matches` structure maps 1:1 to D2 and fails closed for a future third kind; overload removal complete; tests literal, labels behavioural; own mutants A/B/C killed; runner shellcheck-clean, bash 3.2 OK | — |
| 2 | Quality | Minor | Runner header claimed `-D DEBUG` leaves `HandoffSelfCheck` undefined; the reviewer compiled with it and it passed | FIXED — header reworded; review-log row above reworded |
| 1 | Quality | Minor | Self-check header still said "run with a throwaway driver (see the task report) … `-D DEBUG`" | FIXED — points at `tools/ne-selfcheck.sh` and `-DDEBUG` |
| 3 | Quality | Minor | `ScopeMatcherMirror` doc cited the removed `matches(hostname:ip:port:)` and every Swift line citation in the module had drifted; the mirror did not say it models TCP only | FIXED — symbol names instead of line numbers; mirror header and `matches` doc say "TCP path only, UDP not modelled" |
| 1 | Quality | Minor | `setRecvTimeout` helper added but `framing(_:)` kept its inline copy and the data-socket timeout was set at two use sites | FIXED — `framing` uses the helper; the timeout is set once in the `dial` closure where every data pair is minted |
| 1,3 | Quality | Minor | The rationale (macOS attributes the DNS datagram to the app; no UDP backend) is restated in four doc comments | ACCEPTED as style: each site is where a reader lands; the three facts are short and the panel confirmed they agree |
| all | Orchestrator (CR-AC5) | Important (main) | After merging `main` (addac98+) both capture tripwires fail: TG-AC8 expects `@AppStorage("capture.enabled")` in SettingsView/App and two pins read `UserDefaults.standard`/`UserDefaultsActiveKindPersistence`, while #183 (`SettingsDomain`, `Store.defaults`) moved those; the operator-only allow-list misses a doc comment in `SettingsDomain.swift`. Pristine `origin/main` 5cb88cd is red on both; this branch's own changes pass them (pre-merge tree, tester) | NOT this PR's regression; recorded here and reported to the orchestrator. Follow-up PR (this session owns both scripts): realign the pins to `Store.defaults`/`SettingsDomain` and allow-list the doc comment |

## Shipped

Also changed, outside the original D1–D6 (recorded by the spec review, now spec D7 / CR-AC8):
`HandoffMessages.decodeCore` rejects a non-object `Scope` payload. Runner hardening from the
security review: one `mktemp -d` run directory per invocation under the scratch root.

What merged, what was cut, follow-ups. Filled at stage 7. Follow-ups already known:
stale-attachment / shared-socket-directory hardening; preserving the A/B scripts
(`/tmp/claude/nescope-test3.py`, `-test4.py`) under `tests/e2e/` as a live NE recipe;
CR-AC6 evidence from the v0.5.4 DMG.
