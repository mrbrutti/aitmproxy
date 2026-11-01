# Ship macOS L4 capture in the DMG and make it a user toggle — design

**Status:** approved — self-approved 2026-10-30 by the orchestrator session
(autonomous mode, memory `aitmproxy-autonomous-approve-merge-mode`; these are
design calls, not key account/identity decisions). Open-question dispositions:
**Q1 — dedicated "Capture" Settings tab: APPROVED** (right home for a
deny-by-default security feature; one-topic-per-tab rule). **Q2 — OFF stops the
tunnel but keeps the saved `NETransparentProxyManager` configuration: APPROVED**
(matches the task's "leave the sysex installed, keep Uninstall"; avoids
re-prompting). Builder note: `disable()` must also prevent the system from
auto-restarting the stopped tunnel (set `isEnabled = false` + save, or verify
live that `stopVPNTunnel()` alone suffices) — see TG-AC6's manual check. **Q3 —
add `CaptureCapability.inactive` + a `.disabled` event: APPROVED.** All eight
"Architect's calls" accepted as written.
**Milestone:** v0.5.2
**Research inputs:** `docs/research/10-macos-network-extension.md` (§3.5, §3.6
packaging/signing; §3.7 handoff);
`docs/superpowers/specs/2026-10-30-aitmproxy-macos-ne-live-feeder-design.md`
(the shipped feeder — its deny-by-default, operator-only, config-file-only
invariant and `macos_capture.enabled` gate; LF-AC1/LF-AC12);
`docs/superpowers/specs/2026-10-29-aitmproxy-macos-network-extension-design.md`
(D5 embed-in-app, D7 entitlements/signing, D8 activation + two prompts, D9
capability surfacing, NE-AC9/10/11/12/13/14/15);
`docs/superpowers/specs/2026-10-29-aitmproxy-distribution-packaging-design.md`
(the notarize/DMG pipeline, KEY #1 local signing).
**Code read (2026-10-30):** `scripts/notarize-dmg.sh`, `apps/mac/build.sh`,
`apps/mac/Aitmproxy.entitlements`, `apps/mac/Extension/Aitmproxy-Extension.entitlements`,
`apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift`,
`apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift`,
`apps/mac/Sources/Aitmproxy/Bus/EmbeddedCoreController.swift`,
`apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift`,
`apps/mac/Sources/AitmproxyKit/CaptureCapability.swift`,
`apps/mac/Sources/Aitmproxy/Shell/ShellView.swift`,
`apps/mac/Sources/Aitmproxy/SettingsView.swift`,
`crates/aitm/src/macos_capture/config.rs`, `crates/aitm/src/config_file.rs`,
`crates/aitm/src/wire.rs`, `crates/aitm/src/main.rs`.

## Intent

macOS L4 capture — the `NETransparentProxyProvider` system extension that hooks
every app's outbound flows and feeds the embedded core — is built and wired
(PR #144: the core feeder, rendezvous, peer-auth, ingress; the app's
`ExtensionController` activation lifecycle and `CaptureCapability`), but it does
not reach a user. Two gaps keep it dark. **Part 1:** `scripts/notarize-dmg.sh`
never signs the nested `.systemextension` and re-signs the app with no
entitlements, so the shipped v0.5.1 DMG strips the NE entitlements `build.sh`
added and ships an extension that cannot activate — the "no entitlements"
regression D7/NE-AC12 called out, now in the release path. **Part 2:** the app
auto-fires one activation at launch and offers only an "Uninstall" button; there
is no deny-by-default ON/OFF control, so a fresh install would prompt for
System Settings approval with no operator intent, and `macos_capture.enabled` is
reachable only by hand-editing a config file. This milestone signs the sysex
correctly into the notarized DMG and turns capture into an operator-controlled,
persisted, deny-by-default ON/OFF feature.

## Goals

- **Part 1.** When the app bundle embeds a `.systemextension`,
  `scripts/notarize-dmg.sh` deep-signs it inside-out with a Developer ID
  Application identity, hardened runtime, and the extension's own entitlements,
  then signs the app **with** its NE entitlements, verifies the whole bundle
  (`codesign --verify --deep --strict`, `spctl`, and `codesign -dv` on the nested
  sysex), and notarizes + staples the DMG. A non-NE build keeps today's
  behaviour exactly.
- **Part 2.** A single deny-by-default ON/OFF control for macOS L4 capture,
  **OFF on first run**, persisted in `UserDefaults` (domain
  `com.mrbrutti.aitmproxy`), idempotent to toggle.
- Turning **ON** activates the sysex (reusing `ExtensionController`'s existing
  `OSSystemExtensionManager` flow and its pending-approval/tunnel states), brings
  up the `NETransparentProxy` tunnel, and flips the embedded core's
  `macos_capture.enabled` so the feeder runs.
- Turning **OFF** stops the tunnel and clears the core gate while **leaving the
  sysex installed**; the separate Uninstall action remains the only full removal.
- The UI reflects the real state (off / awaiting-approval / active / failed) and
  never reads "active" until the tunnel is actually `.connected`.
- `macos_capture.enabled` becomes operator-controllable **from the app** and
  stays deny-by-default and operator-only: no bus, MCP, agent, `Session`, or
  command-palette path can flip capture on or trigger sysex activation.

## Non-goals

- **No change to the core feeder, rendezvous, peer-auth, ingress, or the
  `macos_capture` config schema** (all shipped in PR #144). Part 2 flips the
  existing gate by rewriting the app-authored per-launch `config.yaml` and
  restarting the core — the same route Settings ▸ Proxy already uses for the
  listen port and upstream-TLS toggle. If this route turns out not to work, the
  builder **stops and reports** rather than editing the core (see Constraints).
- **No new bus/MCP verb, `Session` action, or palette entry** for capture
  enable/disable, activation, or uninstall. The operator surfaces (a Settings
  control and its menu command) are the only paths.
- **No live core→bus capability handle.** The app derives capture state from its
  own `ExtensionController` + tunnel status + the toggle, exactly as the feeder
  spec deferred (its Open Q2). "Active" = the app's tunnel is `.connected`.
- No CI signing. The DMG is signed/notarized on Matt's Mac in the Terminal panel
  with his Developer ID + ASC key (packaging spec KEY #1). This spec does not
  move secrets into CI.
- No new entitlement files, bundle id, provisioning profiles, Xcode project, or
  `build.sh` signing change — those landed with the extension. Part 1 only brings
  `notarize-dmg.sh` up to parity with `build.sh`.
- No raw-packet L4 on macOS; capture stays flow-level (NE spec A2/D1), unchanged.

## Anti-goals

- **A fresh install that prompts for System Settings approval with no operator
  intent.** If opening the app on a clean Mac submits an activation request or
  shows either approval prompt before the operator turns capture ON, the
  deny-by-default control has failed.
- **Shipping an extension that cannot activate.** If the notarized DMG's app is
  signed without the NE entitlements, or the nested sysex is unsigned / signed
  without hardened runtime or its entitlements, the download is broken even
  though it notarizes — the exact v0.5.1 failure.
- **An agent-reachable on-switch.** If any `Frontend::Mcp` / bus / `Session` /
  palette path can flip `capture.enabled`, call `enable()`/`disable()`/activation,
  or start the tunnel, the operator gate is theatre. This must hold at the Swift
  layer (Part 2) and remain true at the core layer (the shipped LF-AC12).
- **A UI that claims "Capturing" when it is not.** Reading "active" before the
  tunnel is `.connected`, or leaving "Capturing" after an OFF, is a failure.
- **Turning OFF but still capturing.** If OFF leaves the core feeder running or
  the tunnel intercepting, it is a failure even if the indicator says off.
- **Silent `codesign` success.** A re-sign that fails but is masked (a
  `grep … || true` swallowing the exit status) must abort the release, as
  `build.sh`'s `cs()` already does.

## Constraints

- **Rust gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  must stay green. Part 1 is shell-only; Part 2 touches only the `aitm` app/kit
  Swift and adds no Rust, so the gate must still pass unchanged.
- **Mac app build/tests green:** `./build.sh` (no errors), `swift test
  --scratch-path ~/Library/Developer/Aitmproxy/test-build`, snapshots in light +
  dark, `tools/grid-lint.sh`, `swift tools/check-layout.swift`. Swift 6
  concurrency (`@MainActor` discipline as in `ExtensionController`).
- **Confirmed Part 2 mechanism (do not deviate without reporting).** The gate is
  **config-file-only** (operator authority): `crates/aitm/src/macos_capture/config.rs`
  defines `MacosCaptureConfig { enabled, activation }`; `config_file.rs` parses a
  top-level `macos_capture:` section (there is already a passing test
  `macos_capture_enable_round_trips` for `"macos_capture:\n  enabled: true\n"`);
  `main.rs:431` builds the feeder only on macOS when enabled. `EmbeddedCore.spawn()`
  (`EmbeddedCore.swift:142`) already reads `proxy.preferredPort` and
  `proxy.verifyUpstreamTLS` **fresh each spawn** from `UserDefaults`, and
  `EmbeddedCoreLaunch.Config.yaml()` already emits a conditional top-level key
  (`ssl_insecure`). Part 2 adds `capture.enabled` the same way. **No new runtime
  trigger is added to the core**, so the feeder's deny-by-default invariant is
  untouched. If the builder finds the gate is not config-file-only, or that a
  restart does not re-read it, **stop and report** instead of changing the core.
- **Deny-by-default; persisted OFF default; idempotent.** The control defaults
  OFF, persists across launches, and no-ops when toggled to its current value.
- **Operator-only, structurally.** Mirror `ExtensionController`'s type-comment
  discipline: the enable/disable and activation paths have exactly their operator
  call sites and nothing an agent can reach. The shipped core gate
  `allow_agent_sysex_install=false` stays.
- **Two System Settings prompts are an unavoidable human step** on first enable
  (NE spec D8): *Network Extensions → approve*, then *Add Proxy Configurations →
  Allow*. The app models them via the existing `pendingApproval`/reconcile states;
  the spec documents them as a manual step, not something automatable.
- **Sandbox:** `codesign`/`notarytool`/`stapler`/`spctl`, `./build.sh`,
  `swift test`/snapshots (GUI), port-binding and a live core all run in the
  Terminal panel on Matt's Mac. `bash -n`/shellcheck and pure `AitmproxyKit`
  unit tests run in the sandbox. Credentials (Developer ID, ASC key
  **G638JVUND7**, team **995PCLM9KH**) are Matt's, invoked by him; never
  automated into secrets.

## Design

Defaults the Architect chose are marked **(Architect's call)**.

### Part 1 — sign the sysex into the notarized DMG (`scripts/notarize-dmg.sh`)

Today the script (lines ~46–62) re-signs only `Contents/Resources/core/{obscura,aitm}`
then `codesign --force --sign "$dev_id" "$app"` with **no `--entitlements`**,
which (per the `codesign` man page, research §3.6) signs the app with no
entitlements at all and never signs the nested
`Contents/Library/SystemExtensions/com.mrbrutti.aitmproxy.ne.systemextension`.
`build.sh` (lines ~105–172) already does this correctly for a local NE build;
Part 1 brings the release script to the same recipe.

**Decision — detect the sysex and branch, mirroring `build.sh`.** After the
existing core re-sign and before building the DMG, detect
`"$app"/Contents/Library/SystemExtensions/`*`.systemextension` (there is exactly
one; the bundle id is `com.mrbrutti.aitmproxy.ne`). The two cases:

1. **NE build (a sysex is present).** Sign **inside-out** with `$dev_id` (the
   Developer ID Application identity the script already resolves), hardened
   runtime and secure timestamp (`--options runtime --timestamp`):
   1. any Mach-O / frameworks nested **inside** the sysex first (future-proofing:
      the current sysex is a single `Contents/MacOS/AitmproxyNE`, so there are
      none today, but sign depth-first if any appear) — **(Architect's call:**
      a depth-first pass so the recipe does not break when the sysex gains a
      framework);
   2. the `.systemextension` bundle itself, with
      `--entitlements apps/mac/Extension/Aitmproxy-Extension.entitlements`;
   3. `obscura` (with `EmbeddedObscura.entitlements`, as today) and `aitm`
      (as today);
   4. the **app bundle** with
      `--entitlements apps/mac/Aitmproxy.entitlements` (the NE host entitlements:
      the `networkextension` array with `app-proxy-provider-systemextension` and
      `system-extension.install`).
   The embedded `embedded.provisionprofile` files that authorise the restricted
   entitlements are already placed by `build.sh` (app at
   `Contents/embedded.provisionprofile`, sysex at
   `Contents/Library/SystemExtensions/<id>.systemextension/Contents/embedded.provisionprofile`);
   `notarize-dmg.sh` re-signs over them and does **not** re-copy them. It fails
   with a clear message if either profile is missing (a sysex with no embedded
   profile cannot carry the restricted entitlements).

2. **Non-NE build (no sysex present).** Unchanged: re-sign `obscura`, `aitm`,
   then `codesign --force --sign "$dev_id" "$app"` (no entitlements), as today.

**`cs()` abort-on-failure helper (Architect's call).** Port `build.sh`'s `cs()`
wrapper — run `codesign`, abort the script on a non-zero exit, hide only the
benign "replacing existing signature" chatter — so a failed restricted-entitlement
sign aborts the release instead of being masked by a pipeline's exit status
(memory `gate-exit-status-not-grep`). Reuse `build.sh`'s `runtime_opts` shape
(`--options runtime`, plus `--timestamp` for a real identity).

**Verify step (both cases, extended).** Keep `codesign --verify --deep --strict
--verbose=2 "$app"`. For an NE build, additionally, **before** building the DMG:

- `codesign -dv --verbose=4` on the nested `.systemextension` and assert it is
  signed by the Developer ID identity with the hardened runtime
  (`flags=…runtime`) — proves the nested sysex is correctly signed (task
  requirement; NE-AC13);
- `codesign -d --entitlements :- "$app"` and assert the output contains
  `app-proxy-provider-systemextension` and `com.apple.developer.system-extension.install`;
  `codesign -d --entitlements :-` on the sysex and assert the
  `-systemextension` NE value is present (NE-AC12);
- **fail the script** (non-zero) if any assertion fails, so a stripped-entitlement
  app can never reach `notarytool`;
- `spctl -a -t exec -vvv "$app"` as a Gatekeeper pre-check (advisory before
  notarization; authoritative after staple).

The DMG build, DMG signing, `notarytool submit --wait`, `stapler staple`, and the
final `stapler validate` + `spctl` on the DMG are unchanged — notarizing the
outer DMG covers the nested signed code (research §3.6, Quinn).

**App location.** An NE build installs to `/Applications` (`build.sh` forces it;
the Task-1 spike proved `~/Applications` is rejected). `notarize-dmg.sh` defaults
`APP=$HOME/Applications/Aitmproxy.app`; the runbook/header must note that an NE
release sets `APP=/Applications/Aitmproxy.app`. The script should detect a sysex
regardless of which location `APP` points at.

**Credentialed manual step.** This whole script runs in the Terminal panel on
Matt's Mac with his Developer ID Application identity and ASC key (ID
**G638JVUND7**, team **995PCLM9KH**). The spec and the script header state this as
a manual/credentialed step; no secret is added to the repo or CI.

**Files touched (Part 1):** `scripts/notarize-dmg.sh` only. (No change to
`scripts/make-dmg.sh` — `ditto` preserves signatures — or to `build.sh`, the
entitlement files, or the profiles.)

### Part 2 — operator ON/OFF toggle for L4 capture

Four pieces: the core gate flip (config + spawn), the capability model, the
activation controller, and the operator UI surface.

#### 2a. Core gate flip — config-file-only, via a restart

- **`apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift`** — add to
  `EmbeddedCoreLaunch.Config`:
  - a stored field `public var captureEnabled: Bool`;
  - an `init(…, captureEnabled: Bool = false)` parameter (default `false`,
    appended so existing call sites are unaffected);
  - in `yaml()`, append a top-level block **only when `captureEnabled` is true**,
    exactly analogous to the existing `ssl_insecure` append. The literal appended
    text is:

    ```
    macos_capture:
      enabled: true
    ```

    (a newline-terminated top-level `macos_capture:` key with `enabled: true`
    indented two spaces — a sibling of `listen`/`mcp`/`browser`). When
    `captureEnabled` is false, **no** `macos_capture` text is emitted, so the core
    parses its disabled default. This matches the core's already-passing
    `macos_capture_enable_round_trips` input byte-for-byte.
- **`apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift`** — in `spawn()`, read a
  new bool fresh each spawn beside the existing reads:
  `let captureEnabled = defaults.object(forKey: "capture.enabled") as? Bool ?? false`
  and pass `captureEnabled: captureEnabled` into the `Config(…)` it builds. Nothing
  else in the spawn changes; the fixed feeder socket dir
  (`feeder::DEFAULT_SOCKET_DIR`) and rendezvous are the core's, and the provider
  reconnects after a restart (fail-open).
- **Restart to apply.** Flipping the toggle bumps `session.restartCoreTick`, which
  `ShellView` already maps to `embeddedCore?.restart()` (stop + fresh spawn that
  re-reads `UserDefaults`). This is the Settings ▸ Proxy "Apply & Restart Core"
  route reused; no new core trigger. **(Architect's call:** reuse `restartCoreTick`
  rather than add a capture-specific restart path.)
- **No change** to `crates/aitm/*`. The gate stays config-file-authored; the app
  is its sole writer.

#### 2b. Capability model — `apps/mac/Sources/AitmproxyKit/CaptureCapability.swift`

The enum currently conflates "no extension in this build" and "extension present
but not activated" as `.extensionNotInstalled`, and has no honest "installed but
capture turned off" state (where capture is off yet full Uninstall should still
be offered). Add it.

- **Add `case inactive`** — "the extension is installed/approved, but capture is
  turned off." Property contract:
  - `title` → `"Off"`;
  - `isCaptureOn` → `false`;
  - `isInstalledOrInstalling` → `true`;
  - `canUninstall` → `true` (full removal still offered while off).
- **Add `case disabled`** to `CaptureCapabilityEvent` (the operator turned capture
  off). `applying(.disabled)` → `.inactive`, **authoritative** (resets even from
  `.capturing`, like `.uninstalled`).
- Unchanged: `.tunnelConnected` still only lifts `.approvedAttached → .capturing`
  (so "active" needs a real connected tunnel); `.uninstalled` still →
  `.extensionNotInstalled`; `.extensionNotInstalled` keeps meaning "no extension
  in this build, or fully uninstalled."
- Enabling from `.inactive` re-enters the normal path: `enable()` submits an
  activation request; an already-approved sysex returns `.completed` quickly
  (no prompt) → `.activated` → `.approvedAttached` → `.capturing`.

#### 2c. Activation controller — `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift`

- **`start()` becomes inert-detect + conditional-resume.** It still publishes the
  controller to `health.extensionController` and reports `.extensionNotInstalled`
  when the build embeds no extension (and in fixture/snapshot/self-test runs), but
  it **no longer submits an activation request unconditionally**. Instead:
  - if not embedded → `.extensionNotInstalled`, return (as today);
  - if embedded and the persisted `capture.enabled` is **true** → call `enable()`
    (resume activation at launch, as a pending approval resumes today);
  - if embedded and `capture.enabled` is **false** (first-run default) → submit
    **no** request and show **no** prompt; set the capability to the honest idle
    state (**(Architect's call:** `.extensionNotInstalled` when the saved
    `NETransparentProxyManager` configuration is absent, `.inactive` when it is
    present — i.e. best-effort detect a previously-approved-but-off extension via
    `NETransparentProxyManager.loadAllFromPreferences()`; if that is awkward,
    default to `.extensionNotInstalled` and let the first `enable()` reconcile).
- **`func enable()`** — the operator ON action. Guard embedded and not-already-
  pending; set `managingExtension = true`; publish self; `beginKeepingAlive()`;
  submit `OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier:
  CaptureExtension.identifier, queue: .main)` with `delegate = self` (the body
  currently inside `start()`). Idempotent.
- **`func disable() async`** — the operator OFF action, the new "stop without
  deactivating" method the task requires. It must **not** submit a deactivation
  request (the sysex stays installed). It:
  - cancels `reconcileTask` and awaits it (so a late reconcile cannot re-start the
    tunnel), removes the tunnel observer;
  - stops the tunnel (`connection.stopVPNTunnel()`);
  - **(Architect's call)** leaves the saved `NETransparentProxyManager`
    configuration **in place** (stop, do not `removeFromPreferences`), so a later
    re-enable does not re-trigger the "Add Proxy Configurations" prompt; the core
    gate being cleared already guarantees no capture (a feeder-less core makes the
    provider fail open), and stopping the tunnel means the provider is not
    intercepting. Full removal (config + sysex) stays the separate `uninstall()`;
  - `apply(.disabled)` → `.inactive`. Idempotent (guarded like `uninstall()`).
- **`uninstall()`** unchanged: cancels reconcile, removes the saved configuration,
  submits a deactivation request, ends at `.extensionNotInstalled`.

#### 2d. Operator UI surface

**Decision (Architect's call): a dedicated "Capture" Settings tab.** Add a
`SettingsTab.capture` case (title "Capture", an SF Symbol such as
`antenna.radiowaves.left.and.right`) rendered as one grouped `Form`, per the mac
CLAUDE.md "one tab per topic, one grouped Form per tab" rule. Move the existing
capture state + Uninstall out of the General tab's `CaptureSettings` into this
tab, and add the toggle there. Rationale: capture is a security-sensitive,
macOS-only operator feature that deserves its own prominent, deny-by-default
home, and the General tab stays about the flow list. (Alternative, lower churn:
keep it in General's `CaptureSettings` section. Flagged to confirm — Open Q1.)

The Capture tab shows:

- **A `Toggle` "Capture L4 traffic"** bound to `capture.enabled`
  (`@AppStorage("capture.enabled")`, default `false`, domain
  `com.mrbrutti.aitmproxy`). Its `set:` orchestrates (the `BusSettings`
  active-core picker is the existing precedent for a side-effecting binding):
  - **ON:** write the preference; call
    `session.coreHealth.extensionController?.enable()`; bump
    `session.restartCoreTick` so the core respawns with the gate on.
  - **OFF:** call `await session.coreHealth.extensionController?.disable()`; write
    the preference; bump `session.restartCoreTick` so the core respawns with the
    gate off. **(Architect's call:** on OFF, stop the tunnel before the restart so
    capture ceases immediately.)
  Both orderings are idempotent. A small `@MainActor` helper (e.g.
  `Session.setCaptureEnabled(_:)` or a method on the view) holds this glue; its
  exact home is left to the builder, provided it has exactly the operator call
  sites.
- **A state line** derived from `session.coreHealth.captureCapability`: Off /
  Awaiting approval / Capturing / Degraded(reason), using the existing `title`,
  `degradedReason`, and `isCaptureOn`, and the existing SF Symbol mapping. It must
  **not** read "Capturing" until `.capturing` (tunnel connected).
- **The Uninstall button** (unchanged behaviour), shown when `canUninstall`.
- **One line naming the two System Settings prompts** on first enable, so the
  human knows the approval step is expected.

**Visibility.** Show the control whenever this build/run supports capture —
**(Architect's call)** add `CoreHealthState.captureSupported: Bool`, set true at
launch when `CaptureExtension.isEmbedded(inApp:)` (and settable by a snapshot
seed so `Snapshot.swift` can render every state in a non-NE snapshot build). When
false (dev/fixture builds with no embedded sysex), the Capture controls are
hidden or shown disabled with "not available in this build" — builder's choice,
but a dev build must not show a live toggle that does nothing.

**Menu + shortcut (design rule "every action has a menu bar item and a keyboard
shortcut").** Add a menu command that toggles capture (label reflects state,
e.g. "Enable Capture" / "Disable Capture"), near the existing "Restart Core"
command in `App.swift`, with a keyboard shortcut that does not collide with the
existing ones (e.g. avoid ⌃⌘R). Exact menu placement and shortcut left to the
builder.

**Snapshots.** Extend `Snapshot.swift` to capture the Capture tab (or the Capture
section) in light and dark for the states off / awaiting-approval / active /
failed, seeding `captureCapability` + `captureSupported`. Grid-lint and layout
checks pass.

#### 2e. `ShellView` wiring

`ShellView`'s `.task` still constructs `ExtensionController(health:)` and calls
`start()` once (the existing single call site) — but `start()` is now the
conditional-resume above, so first-run (toggle OFF) submits no request and shows
no prompt. No other `ShellView` change.

## Acceptance criteria

Tags: **[kit-unit]** pure `AitmproxyKitTests` (sandbox-runnable);
**[rust]** a Rust test; **[mac-snapshot]** a snapshot + grid/layout check;
**[structural]** a source-level tripwire (sandbox-runnable, incl. `bash -n`);
**[manual]** a documented Terminal-panel / real-Mac step on Matt's machine.

### Part 1 — signing

1. **SH-AC1 — sysex detected and signed inside-out.** With an app bundle that
   contains `Contents/Library/SystemExtensions/*.systemextension`,
   `notarize-dmg.sh` signs any nested code first, then the `.systemextension`
   with `apps/mac/Extension/Aitmproxy-Extension.entitlements`, `--options
   runtime --timestamp`, and `$dev_id`, **before** signing the app. **[manual]**
   + **[structural]** (the branch exists, in this order, via the `cs()`
   abort-on-failure helper).
2. **SH-AC2 — app signed WITH NE entitlements (regression fixed).** For an NE
   build the app re-sign uses `--entitlements apps/mac/Aitmproxy.entitlements`
   (not entitlement-less); `codesign -d --entitlements :- "$app"` shows the NE
   array with `app-proxy-provider-systemextension` and
   `com.apple.developer.system-extension.install`. **[manual]** (NE-AC12).
3. **SH-AC3 — nested sysex proven correctly signed.** `codesign -dv --verbose=4`
   on the nested `.systemextension` shows the Developer ID identity and the
   hardened-runtime flag; `codesign --verify --deep --strict "$app"` and
   `spctl -a -t exec -vvv "$app"` pass. **[manual]** (NE-AC13).
4. **SH-AC4 — verify-or-fail before notarization.** If the sysex lacks its
   entitlements/hardened runtime or the app lacks the NE entitlements, the script
   exits non-zero **before** `notarytool submit`. **[manual]** + **[structural]**.
5. **SH-AC5 — notarize + staple with the nested sysex.** The DMG containing the
   signed nested sysex notarizes and staples; `stapler validate` and the DMG
   `spctl` pass. **[manual]** (NE-AC13).
6. **SH-AC6 — non-NE build unchanged.** With no sysex embedded, the script signs
   core + app (plain, no NE entitlements) and notarizes exactly as today; the NE
   branch is skipped. **[manual]** + **[structural]** (branch is conditional on
   sysex presence).
7. **SH-AC7 — credentialed manual step documented.** The script header / release
   runbook states it runs in the Terminal panel with Matt's Developer ID + ASC
   key **G638JVUND7** (team **995PCLM9KH**), with `APP=/Applications/Aitmproxy.app`
   for an NE release, and automates no secret. **[structural]** (doc/header).
8. **SH-AC8 — script stays valid.** `bash -n scripts/notarize-dmg.sh` and
   `shellcheck scripts/notarize-dmg.sh` pass. **[structural]**.

### Part 2 — toggle

9. **TG-AC1 — config emits the gate only when on.**
   `EmbeddedCoreLaunch.Config(…, captureEnabled: true).yaml()` contains the exact
   substring `"macos_capture:\n  enabled: true"`; with `captureEnabled: false`
   the output contains no `"macos_capture"`. **[kit-unit]**.
10. **TG-AC2 — default off, core-compatible.** `Config`'s `captureEnabled`
    defaults to `false`; the emitted-when-on YAML equals the core's
    already-passing `macos_capture_enable_round_trips` input, and an absent
    section parses to disabled (existing `macos_capture_defaults_disabled`).
    **[kit-unit]** + **[rust]** (existing).
11. **TG-AC3 — spawn reads the toggle fresh.** `EmbeddedCore.spawn()` reads
    `capture.enabled` from `UserDefaults` each spawn and threads it into `Config`;
    a changed value is picked up on the next restart. **[kit-unit]** (Config
    plumbing) + **[manual]** (live spawn shows the core running the feeder only
    when on).
12. **TG-AC4 — first-run OFF: no activation, no prompt.** On launch with
    `capture.enabled` absent/false, `ExtensionController.start()` submits no
    `OSSystemExtensionRequest` and no System Settings prompt appears.
    **[structural]** (start() does not call `submitRequest` when the toggle is
    off) + **[manual]** (clean install, no prompt).
13. **TG-AC5 — ON activates and flips the gate.** Toggling ON calls
    `enable()` (submits/resumes the activation request) **and** sets
    `capture.enabled = true` + restarts the core so the feeder runs.
    **[structural]** (the ON handler does both) + **[manual]** (prompt appears;
    after approval the tunnel comes up and flows capture).
14. **TG-AC6 — OFF stops the tunnel and clears the gate, sysex stays.** Toggling
    OFF calls `disable()` (stops the tunnel without a deactivation request; sysex
    remains installed) **and** sets `capture.enabled = false` + restarts; the
    separate Uninstall still performs full removal. **[kit-unit]** (capability
    `.disabled → .inactive`, `canUninstall == true`) + **[manual]** (capture
    stops; sysex still listed in System Settings; re-enable needs no re-approval).
15. **TG-AC7 — honest capability states.** The new `.inactive` case has
    `isCaptureOn == false`, `canUninstall == true`, `isInstalledOrInstalling ==
    true`, `title == "Off"`; `applying(.disabled)` returns `.inactive` even from
    `.capturing`; `.capturing` is reached only via `.tunnelConnected` from
    `.approvedAttached`. **[kit-unit]**.
16. **TG-AC8 — persisted OFF default, idempotent.** `capture.enabled` persists in
    `UserDefaults` (domain `com.mrbrutti.aitmproxy`), defaults false, survives
    relaunch; toggling to the current value is a no-op (no duplicate activation
    request, no redundant restart storm). **[kit-unit]** / **[manual]**.
17. **TG-AC9 — operator-only, no agent path.** A source tripwire proves no
    bus/MCP verb, `Session` action, or command-palette entry reaches the toggle,
    `enable()`, `disable()`, the activation request, or `capture.enabled`; these
    have exactly their operator surfaces (the Capture Settings control + its menu
    command), mirroring `ExtensionController`'s type comment. The core-side
    LF-AC12 structural test (no bus/MCP/`Session`/palette path reaches
    `CaptureSession::run`/`build_capture_session`) still passes — no core trigger
    added. **[structural]** + **[rust]** (existing LF-AC12).
18. **TG-AC10 — menu + shortcut.** The enable/disable action has a menu bar item
    and a non-colliding keyboard shortcut. **[structural]** + **[manual]** (menu
    audit).
19. **TG-AC11 — snapshots.** The Capture surface renders in light and dark for
    off / awaiting-approval / active / failed; `tools/grid-lint.sh` and
    `swift tools/check-layout.swift` print PASS. **[mac-snapshot]**.
20. **TG-AC12 — gates green.** `cargo fmt --check && cargo clippy --all-targets
    -- -D warnings && cargo test` passes (no Rust changed); `swift test` and
    `./build.sh` pass. **[rust]** + **[kit-unit]** + **[manual]** (build).

## Reconciliation with the feeder and NE specs

- **Feeder spec (LF-AC1/LF-AC12 — deny-by-default, operator-only, config-only).**
  Honoured verbatim. Part 2 adds **no** runtime trigger to the core; it rewrites
  the app-authored `config.yaml` and restarts, so `macos_capture.enabled` stays
  config-file-authored (operator authority). The emitted YAML is byte-identical
  to the feeder's already-tested parse input. The feeder's Open Q2 (live core→bus
  capability) stays deferred: the app's "active" is its own tunnel-connected
  signal, not a core-published handle.
- **NE spec D5/D7 (embed-in-app; entitlements/signing).** Part 1 completes the
  D7 release-script changes the milestone plan listed — "re-sign the sysex first
  … then the app with `--entitlements` … fail if the NE array lacks the suffix"
  — closing NE-AC12 and NE-AC13 in the *release* path (`build.sh` already does it
  for local builds).
- **NE spec D8/D9, NE-AC9/10/11/15.** Part 2 reuses the shipped activation
  lifecycle (`OSSystemExtensionRequest`, `pendingApproval`, the tunnel reconcile)
  and the `CaptureCapability` surface; it changes *when* activation fires (toggle-
  gated, not auto) and adds the OFF/`.inactive` state and the deny-by-default
  control (extending NE-AC11 operator-only and NE-AC15 indicator/uninstall). The
  two System Settings prompts (D8) stay a documented manual step. NE-AC14
  (version-bump reconcile) is unaffected — the reconcile still runs on activation.
- **Distribution/packaging spec (KEY #1).** Part 1 keeps signing local on Matt's
  Mac; no CI secret is introduced.
- **Known limitation (noted, not fixed here).** The app shows "Capturing" when
  its tunnel is connected; true end-to-end capture also needs the embedded core's
  feeder, which runs when the gate is on. Since the toggle flips both together,
  tunnel-up normally implies gate-on; if the core is degraded, the existing
  `CoreFailedBanner` already surfaces "not capturing." Closing this fully is the
  feeder spec's deferred live-capability follow-up.

## Left to the builder

- The exact home of the toggle-orchestration glue (`Session` method vs the
  view's binding `set:`), provided it has only operator call sites.
- Whether `start()` best-effort detects a previously-approved-but-off extension
  (via `NETransparentProxyManager.loadAllFromPreferences()`) to show `.inactive`
  rather than `.extensionNotInstalled` on an OFF launch, or defers that to the
  first `enable()`.
- The menu placement, label wording, and the (non-colliding) keyboard shortcut.
- The SF Symbol for the Capture tab and the `.inactive` state line copy.
- Whether `captureSupported` lives on `CoreHealthState` or is computed in the
  view, as long as snapshots can render every state and a dev build shows no live
  dead toggle.
- The order of the two side effects within ON / OFF (gate-flip+restart vs
  tunnel), provided both happen and the result is idempotent.
- Whether to track an "applied capture gate" snapshot (like `appliedPort`) for a
  disabled-until-diverged control; not required (the toggle restarts immediately).
- The Part 1 depth-first nested-sign loop shape and the exact `codesign -dv`
  assertion grep, as long as SH-AC1/3/4 hold and failures abort.

## Open questions

Each carries the Architect's recommendation; approve or correct.

1. **UI surface — a dedicated "Capture" Settings tab (recommended) vs keeping the
   control in the General tab's existing `CaptureSettings` section.** The task
   delegated this to the Architect; the call is a dedicated tab (prominence for a
   deny-by-default security feature, one-topic-per-tab rule). Confirm, or keep it
   in General for lower churn.
2. **OFF semantics — stop the tunnel but keep the saved proxy configuration
   (recommended) vs remove the configuration.** Keeping it avoids re-triggering
   the "Add Proxy Configurations" prompt on every re-enable; the cleared core
   gate already guarantees no capture. Removing it is "cleaner" but re-prompts.
   Confirm keep-and-stop.
3. **Add the `CaptureCapability.inactive` case (recommended) vs modelling "off"
   only in the view.** A real case lets "installed-but-off" offer Uninstall and
   read honestly across launches; the alternative risks showing "Approved"/
   "Capturing" or hiding Uninstall while off. Confirm the new case.

---

**Summary.** Two gaps keep the already-built macOS L4 capture extension from
reaching users. Part 1 fixes `scripts/notarize-dmg.sh` to deep-sign the nested
`.systemextension` inside-out (Developer ID + hardened runtime + its own
entitlements) and then sign the app **with** its NE entitlements — mirroring
`build.sh`'s `cs()` helper and sign order — verify (`codesign -dv`/`--verify
--deep --strict`/`spctl`/entitlement dumps, fail-closed), and notarize + staple;
a non-NE build is untouched. Part 2 makes capture a deny-by-default, persisted,
operator-only ON/OFF toggle in a new Capture Settings tab: ON activates the sysex
and flips `macos_capture.enabled` by rewriting the app-authored `config.yaml` and
restarting the core (the Settings ▸ Proxy route); OFF stops the tunnel and clears
the gate while leaving the sysex installed (a new `ExtensionController.disable()`
and a `CaptureCapability.inactive` state); first run is OFF, so no prompt fires
unbidden, and no bus/MCP/agent/`Session`/palette path can reach it. The confirmed
config-file-only mechanism needs no core change.

**Architect's calls (approve or correct):** (1) a dedicated "Capture" Settings
tab; (2) OFF stops the tunnel but keeps the saved proxy configuration; (3) add a
`CaptureCapability.inactive` case + a `.disabled` event; (4) reuse
`restartCoreTick` to apply the gate; (5) `notarize-dmg.sh` detects the sysex and
branches, reusing `build.sh`'s `cs()` abort-on-failure helper and sign order, and
signs any nested sysex code depth-first; (6) extend the verify step to assert the
nested-sysex signature + both entitlement sets and fail before notarization;
(7) add `CoreHealthState.captureSupported` to drive visibility + snapshots;
(8) `enable()`/`disable()` method names and the inert-detect `start()`.
