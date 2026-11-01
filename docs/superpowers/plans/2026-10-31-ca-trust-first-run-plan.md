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

## Spec and plan corrections (decided by this session under the standing mandate; for the Architect to fold into §D17)

1. **D17.3 / Task 34 policy.** `verify-cert` runs with `-p basic`, not `-p ssl` (Task 32 result above); the `DETAIL` constant names the basic policy.
2. **Task 33 predicate.** `!frontend.is_trusted_control()` instead of `frontend == Frontend::Mcp` (the latter is forbidden by `crates/aitm-core/tests/trust_gate_scan.rs`); same decision for every `Frontend` variant.
3. **Task 33 files.** `frontend_label` (commands.rs) and the audit vocabulary (audit.rs `FRONTENDS`) gain `"operator"`, which SP-AC29's `frontend == "operator"` requires.
4. **D17.6 pill column.** `· CA needs admin` is a mac-fact-only row: `ca.status` carries no needs-admin reading, so the TUI and web (D17.11, D17.12, which derive the word from `ca.status` + the in-flight flag) render three words plus nothing; the mac app latches `needsAdmin` from the install reply. Their install error toast carries the core's NeedsRoot/HeadlessAuth text.
5. **D17.6 in-flight row.** One in-flight word, `· CA trusting…` / "trusting CA…", for install and uninstall alike (accepted; no fourth form).
6. **Task 35 files.** `crates/aitm-tui/tests/tester_shell.rs` was edited: its connect-contract assertion now pins `[Refresh, Call ca.status]`, which D17.11's connect-time request forces.
7. **D17.2 scope guard (core security Important).** A non-CLI frontend may not ask for `scope: "system"` on a platform that has a user scope (macOS, Windows): refused as `UnsupportedScope` before any executor run, so the operator token can never make the core spawn `sudo` against the System keychain (D17.1, D17.14). Linux is unchanged (its only scope is system; D17.13).
8. **D17.3 install on a present-but-untrusted certificate.** `install` no longer returns "already present" on presence alone: when present and `verify_trust` says No it deletes the untrusted copy and re-adds it with trust settings, so the Trust step can complete after a cancelled dialog whose rollback failed or a by-hand import.

9. **D17.3 tail.** A failed `verify-cert` puts the output tail (stdout first, where `Cert Verify Result:` is printed, then stderr) in `detail`, not the stderr tail alone.
10. **SP-AC31 literals.** `-l -L -p basic`; not trusted = `Cert Verify Result: CSSMERR_TP_NOT_TRUSTED`.
11. **Task 32 Result line** in the system-proxy plan points at this record's "Task 32 result".
12. **D17.8 / D17.9 / Task 42 order.** The first-run sheet and the Status checklist use Matt's order: 1 set the system proxy, 2 trust the CA, 3 add a host to Scope (nothing is decrypted until a host is in Scope); the operator docs already say so.
13. **D17.5 / D17.8 / D17.9 homes.** `CATrustFacts` and the two `CAStatus` fields ship in this session's PR D (`AitmproxyKit/CATrustFacts.swift`), not mac-attribution's; the sheet file is `Shell/SetupSheet.swift` (PR 4's `SystemProxySheet.swift` does not exist yet); the three enum cases in `ConnectionSummary.swift` land in PR D before mac-attribution's PR (orchestrator's ruling, 2026-11-01).
14. **Linux `sudo` from a bus client** keeps prompting on the core's own terminal (pre-existing, D17.13); `sudo -n` for non-CLI frontends is a follow-up, not in C1.

## Review log

| Date | PR | Reviewer | Finding | Severity | Disposition |
|---|---|---|---|---|---|
| 2026-11-01 | A core | quality | Cancelled branch drops stderr (same as security Minor) | Minor | fix task C1 |
| 2026-11-01 | A core | quality | `verify_failure_text` duplicates `failure_text`/`stderr_tail` | Minor | fix task C1: shared tail helpers |
| 2026-11-01 | A core | quality | two-pass kind/message with wildcard arm | Minor | fix task C1 |
| 2026-11-01 | A core | quality | kind word lives in commands.rs not on the type | Minor | fix task C1: `TrustErrorKind::label` |
| 2026-11-01 | A core | quality | test literals/helpers duplicated, `MACOS_DETAIL` means two things | Minor | fix task C1: `testing.rs` literals + `unspawnable` builder |
| 2026-11-01 | A core | quality | priming call and vacuous assertion in two tests | Minor | fix task C1 |
| 2026-11-01 | A core | quality | comments cite "Task 32" | Minor | fix task C1 |
| 2026-11-01 | A core | spec | audit.rs + tests/audit.rs undeclared in Task 33; record not committed at head | Important (disposition) | correction 3 committed in this record |
| 2026-11-01 | A core | spec | D17.3/SP-AC31/Task 34 say `-p ssl` and stderr tail | Important (spec text) | corrections 1, 9, 10, 11 |
| 2026-11-01 | A core | spec | Task 33 predicate text | Minor | correction 2 |
| 2026-11-01 | A core | spec | docs order/step differs from D17.8 and Task 42 | Minor | correction 12 (Matt's order) |
| 2026-11-01 | A core | spec | PR D design section contradicts D17.5/D17.8/D17.9 | Minor | correction 13 |
| 2026-11-01 | B TUI | quality | `ca_installing` never cleared on Connected/Disconnected: pill can read `· CA trusting…` forever after a bus drop mid-dialog | Important | fix task T1: clear on both arms + assertion |
| 2026-11-01 | B TUI | quality | `CONFIRM_TOOLS` used to mean "CA trust tool" | Minor | fix task T1: `CA_TRUST_TOOLS` |
| 2026-11-01 | B TUI | quality | `ca.status` ask copied four times | Minor | fix task T1: `ask_ca_status` helper |
| 2026-11-01 | B TUI | quality | seven-scenario test with a two-scenario name; `ca_status == None` branch untested | Minor | fix task T1 |
| 2026-11-01 | B TUI | spec | `tests/tester_shell.rs` edited outside the file list | Important (disposition) | recorded as correction 6; no code change |
| 2026-11-01 | B TUI | spec | `· CA needs admin` has no source in the TUI/web (D17.6 vs D17.11) | Important (spec) | correction 4: mac-fact-only row |
| 2026-11-01 | B TUI | spec | `· CA trusting…` also for uninstall | Minor | correction 5: accepted |
| 2026-11-01 | B TUI | spec | `ca.uninstall cancelled` not special-cased | Minor | consistent with the core; none |
| 2026-11-01 | A core | security | Operator-token client may request `scope: "system"` → core spawns `sudo` | Important | fix task C1: correction 7 guard + test, `sudo -n` for non-CLI |
| 2026-11-01 | A core | security | Cancelled path drops the tool's stderr from log and audit | Minor | fix task C1: warn the tail on the Cancelled branch |
| 2026-11-01 | A core | security | Present-but-untrusted certificate is a dead end for the Trust step | Minor | fix task C1: correction 8 |
| 2026-11-01 | C web | security | The palette never performs the bus confirm handshake (`needs_confirmation` envelope shown as `ok`), so `ca.install` from the web could never run | Minor (security) / Important (function) | fix task W1: generic handshake in `run`, server prompt, `_confirm` re-call, tests |
| 2026-11-01 | C web | security | `isCACancelled` keys on `ca.install cancelled` only; the core's uninstall path never emits `Cancelled` | Minor | fix task W1: match both verbs; core uninstall cancel classification is a follow-up |
| 2026-11-01 | C web | spec | No `· CA needs admin` pill word (D17.6 row 4); `ca.status` carries no needs-admin reading, D17.12 and SP-AC36 do not ask for it | Minor | accepted: spec gap D17.6 vs D17.11/D17.12; Architect addendum if Matt wants the word on TUI/web (the mac app latches it from the install error) |
| 2026-11-01 | C web | spec | No `ca.uninstall` palette test for the in-flight flag and re-read | Minor | fix task W1 |
| 2026-11-01 | C web | spec | `caPillWord(unknown, false) === null` covered only by composition | Minor | fix task W1 |
| 2026-11-01 | C web | quality | Hedged selector and `?.value ?? ''` let the Linux no-scope test pass vacuously | Minor | fix task W1 |
| 2026-11-01 | C web | quality | `refreshCA` swallows a failed post-install read-back; pill may stay stale silently | Minor | fix task W1: returns Bool, palette notices |
| 2026-11-01 | C web | quality | Fourth copy of the plain-object guard | Minor | fix task W1: shared `isRecord` in lib |
| 2026-11-01 | C web | quality | CA-tool knowledge split across three modules | Minor | fix task W1: `isCATrustTool` in caTrust.ts |

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
gains `.caTrusted` (the orchestrator granted this additive exception on
`ConnectionSummary.swift` on 2026-11-01: exactly the three cases and the two title lines,
nothing else; mac-attribution rebases onto it). `ConnectionSummary.make` is not touched; the
Status view inserts the CA step after `.busConnected` itself. PR D order: removal-mac PR →
this PR → mac-attribution → system-proxy PR 4.

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
