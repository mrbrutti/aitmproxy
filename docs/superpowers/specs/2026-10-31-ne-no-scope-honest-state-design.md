# NE capture: honest "on but scope is empty" state — design (hotfix)

**Status:** approved — self-approved 2026-10-31 by the orchestrator session (autonomous
mode; hotfix routed by the release orchestrator after Matt's first live NE activation).
**Milestone:** v0.5.3.1 (or folded into v0.5.4).
**Branch:** `fix/ne-no-scope-hint` off `origin/main` 6ba89d2 (includes PR #175).

## Intent

On the first real-Mac activation Matt approved the extension, Settings ▸ Capture read
"Capturing", and he saw no captured apps or flows. The whole chain was healthy; the
core's scope was empty. Two operator surfaces lied about that: the Capture status read
"Capturing", and the Apps page empty state blamed a missing extension. This hotfix makes
both surfaces say the one true thing and point at the one action (add a host to Scope).

## Root cause (evidence, 2026-10-31, Matt's Mac)

- `capture.enabled = 1`, `bus.activeKind = embedded`; embedded core running with
  `macos_capture: enabled: true`; `/private/tmp/aitmproxy-capture.rendezvous` +
  `control.sock`/`data.sock` present; `systemextensionsctl`: `com.mrbrutti.aitmproxy.ne
  (0.5.3) [activated enabled]`; app, sysext and core all `TeamIdentifier=995PCLM9KH`.
- Provider log: `handleNewFlow` called for every connection, **"provider rejected new
  flow"** for all of them (fail-open → direct). `scope.list` over the operator bus → `[]`.
- Hypothesis test: `scope.add example.com` → `curl http://example.com/` → provider log
  **"provider accepted new flow TCP com.apple.curl … example.com"**, the core dialled
  upstream (`app = aitm`), curl got 200, and `flow.table` gained two
  `authority: example.com` rows. Scope restored to `[]` afterwards.
- Design fact: the provider's `ScopeMatcher` matches nothing for an empty spec and has
  no wildcard-all token (a bare `*` matches nothing). Capture is inherently host-scoped.

## Design

- **`AitmproxyKit/CaptureAdvice`** (pure, tested): `make(capability:supported:scopeHostCount:)`
  → `unsupported | off | awaitingApproval | degraded(reason) | onEmptyScope | on(hosts:)`,
  with `headline`, `detail`, a one-line `banner`, `offersScope` (only `onEmptyScope`), `offersSettings`
  (only `off`). `.on` is worded "Capture is on", never "Capturing": `.approvedAttached` maps there
  too and its tunnel may still be connecting; the capability's own `title` is the one place that
  says "Capturing".
  Derives on/off from the published `CaptureCapability`, never from the `capture.enabled`
  key (keeps `check-capture-operator-only.sh`'s allow-list intact).
- **Settings ▸ Capture** (`SettingsView.swift`): when the advice is `onEmptyScope`, the Status
  row itself reads "On, nothing in scope" with a warning glyph (not "Capturing"), and a callout
  under it: "Capture is on, but the scope is empty …" with **Open Scope…** →
  `session.show(.scope)` (the same action as the Proxy ▸ Scope… menu item).
- **Apps page never hides captured flows** (`ShellView.swift`). The Apps page is the default
  landing page, and `session.clients` is fixture-only live (no source-app attribution on the
  wire), so today `clients.isEmpty` swaps the WHOLE flow table for a placeholder: Matt's 848
  captured flows were invisible until he clicked Domains (found live by the mac-review
  session). Now: with flows present, the table stays and a one-line `AppsAttributionBanner`
  (the `ScopeBanner` shape) states the advice with an **Open Scope…** / **Open Settings…**
  action; only with no flows at all does the advice-aware `AppsEmptyState` (a
  `ContentUnavailableView`) show. The "extension missing" wording appears only for
  `unsupported`. Neither view toggles capture (operator-only stays with the Settings toggle).
  Changing the default landing page is a product call left for v0.5.4.
- **Live scope count** (`Bus/BusService.swift`): `scopeHosts` was refreshed only at connect and
  after the app's own add/remove, so a host added from the CLI or another client would leave the
  advice claiming an empty scope; the poll loop now refreshes `scope.list` too.
- **Tripwire** (`apps/mac/tools/check-capture-toggle.sh`): pins the callout + Open Scope in
  SettingsView, the advice-driven Apps empty state in ShellView, and that ShellView gained no
  `capture.enabled` read, no `CaptureSwitch` call and no `extensionController` handle.
- **Snapshots**: `settings-capture-noscope-{light,dark}` (capability `.capturing`,
  `captureSupported = true`, `scopeHosts = []`) and `apps-noattribution-{light,dark}` (fixture
  rows with their `client` stripped and the `noscope` capture state: the banner over a full
  table). Every capture state starts from the fixture scope; only `noscope` empties it.

## Non-goals (follow-ups)

- **Source-app attribution on the wire.** The core keeps the captured flow's source app
  (`ingress.rs` `peer_identity`) but `flow.get`/`flow.table` never emit it and
  `FlowSummary` has no client field, so `session.clients` is fixture-only: the Apps page
  cannot group live NE flows even with a scope. Needs a protocol field + kit parsing — own
  spec, v0.5.4.
- A main-window capture control and the guided first-enable onboarding (v0.5.4).
- An observe-only "all apps" lane (the provider grammar has no wildcard) — v0.6 candidate.

## Acceptance criteria

1. **NS-AC1 [kit-unit]** `CaptureAdvice.make` maps every `CaptureCapability` × supported ×
   scope count as designed; `onEmptyScope` iff supported ∧ (approvedAttached|capturing) ∧
   scope empty; `offersScope` only for `onEmptyScope`; `offersSettings` only for `off`.
2. **NS-AC2 [structural]** Settings ▸ Capture shows the empty-scope callout with an
   **Open Scope…** button that calls `session.show(.scope)`; it is not shown when hosts are
   in scope.
3. **NS-AC3 [structural]** The Apps page's banner and empty state are driven by `CaptureAdvice`
   and offer Open Scope… / Open Settings… per the advice; the "extension missing" wording
   appears only for `unsupported`.
8. **NS-AC8 [structural + manual]** With flows present the Apps page keeps the flow table
   (banner above it); the full empty state shows only when `session.rows` is empty. On Matt's
   Mac the default page shows the captured flows without visiting Domains.
4. **NS-AC4 [structural]** `ShellView.swift` contains no `"capture.enabled"`, no
   `CaptureSwitch`, no `extensionController`; both capture tripwires exit 0.
5. **NS-AC5 [mac-snapshot]** The two no-scope scenes render in light + dark; grid-lint +
   check-layout PASS.
6. **NS-AC6 [gates]** `swift test` green (new tests included); `./build.sh` no errors; Rust
   gate unaffected (no Rust change).
7. **NS-AC7 [manual]** On Matt's Mac with capture on and an empty scope, both surfaces read
   the empty-scope state; after adding a host in Scope and browsing it in **Safari** (Firefox
   is proxied to :8080 and never reaches the NE), flows appear in the flow list.

## Review log

Stage-6 panel 2026-10-31 on `6ba89d2..9b0bdea`: Security PASS (3 Minor), Spec FAIL (1 Important,
3 Minor), Quality + Tester: see below. Dispositions by the orchestrator (autonomous mode).

| # | Reviewer | Sev | Finding | Disposition |
|---|---|---|---|---|
| 1 | Spec | Important | `noscope` leaves `scopeHosts = []` for the next states; dark `active` showed the callout | FIXED — `apply` resets to `Fixtures.scope` per state; pin added |
| 2 | Security | Minor | `.approvedAttached` read "Capturing" while its tunnel may be down | FIXED — `.on` worded "Capture is on"; test pins no advice starts with "Capturing" |
| 3 | Security | Minor | `scopeHosts` refreshed only at connect → stale count could make the advice lie | FIXED — poll loop refreshes `scope.list` |
| 4 | Security + Spec | Minor | Status row still read "Capturing" beside the empty-scope callout | FIXED — row reads "On, nothing in scope" with a warning glyph when `onEmptyScope` |
| 5 | Spec | Minor | `banner` not named in the spec; apps scene said "capture off" | FIXED — spec amended (this revision) |
| 6 | Spec | Minor | `Snapshot.swift:9` comment omitted `noscope` | FIXED |
| 7 | Quality | Important | Snapshot scope leak (same as #1) | FIXED (same) |
| 8 | Quality | Important | `apps-noattribution` shots showed no banner + stale CLIENT column | FIXED via row 19 (`FlowRow ==` ignored `client`); re-rendered shots verified |
| 9 | Quality | Important | Banner/detail copy promised app attribution that no flow carries on the wire yet | FIXED — copy says only what is true now; test pins no "attribute" wording |
| 10 | Quality | Minor | Open Settings… landed on the last tab, not Capture | FIXED — `settingsTab = .capture` first |
| 11 | Quality | Minor | `.link` buttons, no `lineLimit`, double hairline, a11y combine over the button | FIXED — `SmallButton`, `lineLimit(1)`, overlay rule dropped, combine on icon+text |
| 12 | Quality | Minor | `savedRows` overwritten if applied twice | FIXED — `Self.savedRows ?? session.rows` |
| 13 | Quality | Minor | Advice built 3×, Open Scope spelled 2 ways, booleans vs an action enum, `clients` computed twice, banner may stack with ScopeBanner | ACCEPTED (follow-up with the v0.5.4 onboarding: a `Session.captureAdvice`/`openScope()` + one `OneLineBanner`) |
| 14 | Quality | Minor | Test/pin polish (hoisted lists, per-view pins, NS-AC4 duplicates) | FIXED (per-view `body_of` pins, hoisted `everyAdvice`); NS-AC4 duplicates kept as defence in depth |
| 15 | Tester | Blocking | Three coder test pins contradicted copy that changed under review (`.on(1).detail` wording, `unsupported.banner` said "capture extension", `.on` banner said "not attributed") | FIXED — pins follow the copy; `.on` banner now reads "flows carry no source app yet" so no advice uses the word "attribute" |
| 16 | Tester | Minor | `.degraded("")` yields an empty detail and a banner ending in a dangling dash | ACCEPTED (follow-up with v0.5.4: fallback sentence, and guard `CaptureCapabilityEvent.failed` against an empty reason) |
| 17 | Tester | Minor | An unknown scope reads as empty: `scopeHosts` starts `[]` and `refreshScope` is `try?`, so before the first `scope.list` reply or with the bus down the callout can say "the scope is empty" | ACCEPTED (follow-up: `scopeHostCount: Int?` or a bus-connected gate; the poll-loop refresh keeps the window under one poll) |
| 18 | Tester | Minor | Apps-page routing (banner / empty state / table) is an inline predicate in `MainView`; a pure `AppsPageMode` would make NS-AC8 executable | ACCEPTED (follow-up with the `Session.captureAdvice` refactor, row 13) |
| 19 | Orchestrator (debugging row 8) | Important | `apps-noattribution` rendered no banner and a stale CLIENT column: the scene changed only `client` on each row, and `FlowRow ==` ignored `client`, so the new `rows` compared equal to the old — SwiftUI skipped the main view's update (confirmed with body prints: no re-evaluation between the scene and the reset) and `FlowTableView` skipped its reload | FIXED — `FlowRow ==` now includes `client` (Kit test pins it); row 8 closes once the re-rendered shots show the banner |
| 20 | Orchestrator | Minor | In the `settings-capture-{active,noscope}` snapshots the Capture L4 traffic toggle draws OFF and dimmed while the Status row says on; the binding reads `health.captureChoice ?? captureEnabled` and the scene sets `captureChoice = true`, so this is a fixture-render question (likely `.disabled(!usesEmbedded)` under the test store), not the live toggle, which the mac-review session saw ON against a real extension | ACCEPTED (follow-up with the v0.5.4 onboarding snapshots) |

Tester (stage 5) added `CaptureAdviceExhaustiveTests` (15 tests: the full capability × scope table, `isCaptureOn` oracle, exhaustive-switch witnesses so a new case fails to compile) and scoped tripwire pins; mutation runs killed 30/30 tripwire mutants and 17/17 kit mutants. Tripwire: 227 ok.
