# CA trust first-run step: execution record

**Status:** in progress (2026-10-31; the spec is §D17 of
`docs/superpowers/specs/2026-10-31-system-proxy-automation-design.md`, approved under
Matt's standing mandate; the tasks are 32–42 of
`docs/superpowers/plans/2026-10-31-system-proxy-automation-plan.md`, approved the same
way; Task 41 additionally needs Matt's explicit go). This file is the CA-trust session's
own record so the system-proxy plan file is never edited by two sessions.

## What ships, in which PR

| PR | Tasks | Files |
|---|---|---|
| A core | 32 (probe), 33, 34, 42 | `crates/aitm-ca/src/{commands,store}.rs`, `crates/aitm-ca/src/platform/macos.rs`, `crates/aitm-ca/tests/{commands,macos}.rs`, `docs/design/operator-ui-foundation.md`, this file |
| B TUI | 35 | `crates/aitm-tui/src/{model,app}.rs`, `crates/aitm-tui/src/ui/bars.rs`, `crates/aitm-tui/tests/ca_pill.rs` |
| C web | 36 | `apps/web/src/state/caTrust.ts` (+ test), `bus/types.ts`, `state/app.ts`, `palette/{groups,setup}.ts`, `palette/CommandPalette.tsx`, `shell/Toolbar.tsx` |
| D mac | 37–41 | `Session+CATrust.swift` (new), `Session.swift`, `Session+Connection.swift`, `Bus/BusService.swift`, `Panels/{CAPanel,StatusPanel}.swift`, `App.swift`, `SettingsView.swift`, `Shell/ShellToolbar.swift`, `Shell/SetupSheet.swift` (new), `AitmproxyKit/CommandMap.swift`, `AitmproxyKit/CATrustFacts.swift` (new, the attribution spec's type, one home), `tools/check-ca-trust-path.sh` |

Deviations from the plan text, each stated where it applies:

- PR 2 (TUI sys-proxy pill) and PR 3 (web pill menu) have not merged, so the CA pill
  word is appended directly after the listening text; when the sys-proxy word lands it
  goes between them (§D12 order). The TUI test file is `tests/ca_pill.rs`, not an
  addition to PR 2's `tests/sysproxy_pill.rs`.
- PR 4 Task 28 (`Shell/SystemProxySheet.swift`) has not merged, so the first-run sheet
  is created here as `Shell/SetupSheet.swift` with the CA row as step 1 and a placeholder
  slot for the system-proxy row; PR 4 fills the slot.
- mac-attribution's traffic-route PR has not merged; `CATrustFacts` lives in
  `AitmproxyKit/CATrustFacts.swift` here with that spec's exact names, and
  `ConnectionSummary.swift` is not edited (orchestrator's claim).

## Task 32 result (read-only probe, Matt's Mac, Terminal panel, 2026-10-31 late)

Script `/tmp/claude/ca-probe/probe.sh` and `probe2.sh`; nothing installed, no keychain or
trust setting modified, no dialog appeared. The login and System keychains hold 0
aitmproxy certificates (`find-certificate -a -c aitmproxy -Z` → 0 `SHA-256` lines each).

| Command | Exit | Output |
|---|---|---|
| `security verify-cert -c apple-root.pem -l -L -p ssl` | 1 | `Cert Verify Result: Invalid Extended Key Usage for policy` |
| `security verify-cert -c apple-root.pem -l -L -p basic` | 0 | `...certificate verification successful.` |
| `security verify-cert -c apple-root.pem -L -p basic` | 0 | `...certificate verification successful.` |
| `security verify-cert -c probe.crt -l -L -p ssl` (untrusted self-signed CA) | 1 | `Cert Verify Result: CSSMERR_TP_NOT_TRUSTED` |
| `security verify-cert -c probe.crt -l -L -p basic` | 1 | `Cert Verify Result: CSSMERR_TP_NOT_TRUSTED` |
| `security trust-settings-export user.plist` | 0 | `...Trust Settings exported successfully.`; `trustList` keyed by SHA-1 upper hex (DigiCert `A8985D3A…5436` matches its `find-certificate -Z` SHA-1); entries carry `trustSettings` arrays with `kSecTrustSettingsPolicyName` (`sslServer`) and `kSecTrustSettingsResult` integers (1, 2, 4 seen) |
| `security dump-trust-settings` | 0 | 3 user-domain certs listed by name |

**Decision:** `verify-cert` is the read-back, with policy **`basic`** (the `ssl` policy
rejects every CA certificate with "Invalid Extended Key Usage for policy", trusted or not,
so it cannot separate the two). Rendered line:
`security verify-cert -c <ca.crt> -l -L -p basic`. Literals: success = exit 0 and stdout
containing `certificate verification successful`; not trusted = non-zero exit (the output
tail, `Cert Verify Result: CSSMERR_TP_NOT_TRUSTED`, goes into `detail`). Caveat recorded in
`detail`: our install sets both the `ssl` and `basic` policies, and Keychain Access's
"Always Trust" sets all, so a `basic` evaluation reflects HTTPS trust for every path the app
offers; a certificate trusted for `ssl` only by hand would read as not trusted.
`trust-settings-export` stays the documented fallback (keys are SHA-1 upper hex, confirmed).

## Task 41 go

_(Matt's words and date go here; until then the live install step has not run.)_

## Review log

| Date | PR | Reviewer | Finding | Severity | Disposition |
|---|---|---|---|---|---|

## Shipped

_(filled by the orchestrator at merge)_

## PR D design as built (Tasks 37–40 adapted to the claims and the merged tree)

Order of the first-run steps (Matt, 2026-10-31, per-host decryption): 1 set the system proxy,
2 trust the CA, 3 add a host to Scope. PR 4 (system proxy, mac) has not merged, so this PR
ships rows 2 and 3 in that order and PR 4 inserts row 1 above them.

**Kit, `AitmproxyKit/CATrustFacts.swift` (new; the attribution spec's type, one home).**

```swift
public struct CATrustFacts: Hashable, Sendable {
    public var trusted: Bool
    public var scope: String?          // "user" | "system" | nil
    public var fingerprint: String?
    public var installing: Bool = false
    public var needsAdmin: Bool = false // Linux NeedsRoot / macOS HeadlessAuth came back from the last change
    public init?(status: CAStatus)     // nil unless status.trustReported (some store said yes|no)
    public var text: String            // D17.6: "CA trusted (user keychain)" | "CA trusted (System keychain)" |
                                       //        "HTTPS is not captured until the CA is trusted" | "trusting CA…" |
                                       //        "CA trust needs an administrator"
    public var state: LaneState        // ok | warning | working | warning
    public var remedy: String?         // D17.6 remedies; nil when trusted/installing
    public var actions: [ConnectionAction]  // [.openCAPanel] | [.trustCA, .openCAPanel] | [] | [.openCAPanel]
    public var step: GettingStartedStep     // kind .caTrusted; done == trusted && !installing
    public static let quicCaveat = "HTTPS apps that use QUIC are not captured until the CA is trusted; browsers fall back to TCP once it is."
    public static let notTrustedLine = "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"
    public static func unknownStep() -> GettingStartedStep  // "CA trust unknown — open the Certificate Authority panel", .openCAPanel
    public static func scopeArgs(platform: String) -> [String: JSONValue]  // ["scope": .string("user")] for macos|windows, [:] otherwise
}
```

`CAStatus` (`AitmproxyKit/Panels/CAStatus.swift`) gains `trustedScope: String?` (the first
store whose `trusted == "yes"`, user before system) and `trustReported: Bool` (any store says
`yes` or `no`). `ConnectionAction` gains `.trustCA` / `.openCAPanel` and `GettingStartedStep.Kind`
gains `.caTrusted` **if the orchestrator grants the additive exception on
`ConnectionSummary.swift`**; otherwise the same names live on a `CATrustAction` enum in
`CATrustFacts.swift` and the step is a `CATrustStep` struct, both to be folded in by
mac-attribution. `ConnectionSummary.make` is not touched either way; the Status view inserts
the CA step after `.busConnected` itself.

**App.** `Session.caStatus: CAStatus?`, `Session.caTrustInstalling`, `Session.caTrust:
CATrustFacts?` (facts with `installing`/`needsAdmin` applied). `Session+CATrust.swift` is the
only home of `"ca.install"`/`"ca.uninstall"`: `trustCA()`, `untrustCA()`, `caTrustControlLive`
(bus connected, `resolvedRole == "operator"`, not installing); the confirm re-call re-sends the
identical args plus `_confirm` (spec D4 of the bus); an error starting `ca.install cancelled` is
silent; `HeadlessAuth`/`NeedsRoot` text sets `needsAdmin`; every path ends in
`refreshCAStatus()`. `BusService.pollLoop` reads `ca.status` on the first tick and every 10th
tick (500 ms × 10) directly on the client (no activity-log entry), assigning `session.caStatus`
only when changed. `CAPanel` reads `session.caStatus`, calls `trustCA()`/`untrustCA()` after
its `NSAlert`, shows the facts' remedy only when the re-read says not trusted, and the QUIC
caveat as a footnote. `StatusPanel`: CA fact row under the Core card (text, state dot, remedy,
actions) and the `.caTrusted` step row after Bus; `run(.trustCA)` → `Task { await
session.trustCA() }`; `.openCAPanel` → `perform` → `show(.ca)`. `Shell/SetupSheet.swift` (new):
title "Set up aitmproxy on this Mac", rows "Trust the aitmproxy CA" (fact text, primary button
hidden when trusted, "trusting CA…" while in flight, the QUIC caveat under it) and "Add a host
to Scope" ("nothing is decrypted until a host is in Scope", button Open Scope…); no `NSAlert`
before `trustCA()`; buttons "Not Now" / "Done" (when both rows are done); shown once per store
(`Store.defaults` keys `systemProxy.sheetShown`, `systemProxy.promptSuppressed`, shared with
PR 4) when the embedded core is `.ready`, the bus is connected as operator and the CA facts are
non-nil and not trusted. Proxy menu: "Trust the aitmproxy CA" ⌃⌘T above "Certificate
Authority…", disabled unless `caTrustControlLive` and not trusted; `CommandMap` entry and the
`docs/BRIEF.md` command-map line (the Kit test pins them to each other). Settings ▸ Proxy:
the QUIC caveat as a footnote. Tripwire `tools/check-ca-trust-path.sh` per Task 40.
