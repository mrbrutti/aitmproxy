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
  with `headline`, `detail`, `offersScope` (only `onEmptyScope`), `offersSettings` (only `off`).
  Derives on/off from the published `CaptureCapability`, never from the `capture.enabled`
  key (keeps `check-capture-operator-only.sh`'s allow-list intact).
- **Settings ▸ Capture** (`SettingsView.swift`): when the advice is `onEmptyScope`, a callout
  under Status: "Capture is on, but the scope is empty …" with **Open Scope…** →
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
- **Tripwire** (`apps/mac/tools/check-capture-toggle.sh`): pins the callout + Open Scope in
  SettingsView, the advice-driven Apps empty state in ShellView, and that ShellView gained no
  `capture.enabled` read, no `CaptureSwitch` call and no `extensionController` handle.
- **Snapshots**: `settings-capture-noscope-{light,dark}` (capability `.capturing`,
  `captureSupported = true`, `scopeHosts = []`) and `apps-noattribution-{light,dark}` (fixture
  rows with their `client` stripped, capture off: the banner over a full table).

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

| # | Reviewer | Sev | Finding | Disposition |
|---|---|---|---|---|
