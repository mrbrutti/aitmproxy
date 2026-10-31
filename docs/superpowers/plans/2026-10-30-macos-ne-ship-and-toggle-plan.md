# Ship macOS L4 capture in the DMG and make it a user toggle — implementation plan

**Status:** approved — self-approved 2026-10-30 by the orchestrator session
(autonomous mode). Implementation runs in the existing session worktree on branch
`claude/quizzical-payne-463da0` (the orchestrator provisioned this worktree for one
PR to main); the nominal `feat/macos-ne-ship-and-toggle` name is superseded.
Environment adaptation: coder sub-agents (sandboxed Bash) edit + run sandbox-safe
checks (`bash -n`, `shellcheck`, grep tripwires, the Task-1 check script) and do NOT
build swift/cargo or `git commit`; the orchestrator runs the authoritative
`swift test` / `./build.sh` / Rust gate and commits per task in the Terminal panel.
**Spec:** `docs/superpowers/specs/2026-10-30-macos-ne-ship-and-toggle-design.md` (approved 2026-10-30)
**Branch / worktree:** `claude/quizzical-payne-463da0` (this session's worktree)
**Milestone:** v0.5.2

## Overview

Two parts. **Part 1** (Task 1) is shell-only — it brings `scripts/notarize-dmg.sh`
up to parity with `build.sh` so the release DMG signs the nested `.systemextension`
inside-out and signs the app **with** its NE entitlements. It touches no Swift and
no Rust and is **independent of every Part 2 task**. **Part 2** (Tasks 2–7) turns
the already-built capture extension into a deny-by-default operator ON/OFF toggle
by rewriting the app-authored `config.yaml` and restarting the core — **no change
to `crates/aitm/*`** (the gate is already consumed; the feeder, rendezvous,
peer-auth and `macos_capture` schema all shipped in PR #144).

Wave order (files are disjoint within a wave; see **Parallelization**):

- **Wave A (parallel):** Task 1 (Part 1 shell) ∥ Task 2 (Part 2a, `EmbeddedCoreLaunch`)
  ∥ Task 3 (Part 2b, `CaptureCapability`).
- **Wave B (parallel):** Task 4 (Part 2c, `ExtensionController`, depends on Task 3)
  ∥ Task 5 (Part 2d, `EmbeddedCore.spawn`, depends on Task 2).
- **Wave C (sequential):** Task 6 (Part 2e, Capture Settings tab + menu + snapshots,
  depends on Tasks 3, 4), then Task 7 (Part 2f, `ShellView` + operator-only tripwire,
  depends on Tasks 4, 6).
- **Then:** whole-branch Tester (every criterion) and the three-reviewer panel.

**Rust gate** stays green unchanged (Part 2 adds no Rust):
`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
**Mac gate:** `./build.sh`, `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`,
snapshots (light+dark), `tools/grid-lint.sh`, `swift tools/check-layout.swift`.

**Stop-and-report rule (from the spec Constraints):** if any task finds the gate is
not config-file-only, that a core restart does not re-read `macos_capture.enabled`,
or that satisfying it needs a change under `crates/aitm/*`, the Coder **stops and
reports** instead of editing the core.

**Verification environments** (per the sandbox memories): `kit-unit` (pure
`AitmproxyKitTests`), `structural` (`bash -n`, `shellcheck`, grep tripwires) run in
the **sandbox**. `./build.sh`, `swift test` (GUI target), `codesign`/`notarytool`/
`stapler`/`spctl`, and all live-core / clean-install steps run in the **Terminal
panel** on Matt's Mac. Every `[manual]` acceptance criterion is a human-run step
listed in **Manual verification (Terminal panel)** at the end.

---

## Tasks

### Task 1: sign the nested sysex into the notarized DMG — Part 1

- **Satisfies:** SH-AC1, SH-AC2, SH-AC3, SH-AC4, SH-AC5, SH-AC6, SH-AC7, SH-AC8
  (and release-path NE-AC12, NE-AC13).
- **Depends on:** none (shell-only; fully independent of Tasks 2–7).
- **Files:**
  - `scripts/notarize-dmg.sh` (modify).
  - `scripts/tests/check-notarize-dmg.sh` (create) — the sandbox-runnable structural
    tripwire for this task.
- **Change:** mirror `build.sh`'s recipe (lines ~105–172) in the release script.
  1. Add a `cs()` helper (ported from `build.sh`): runs `codesign "$@"`, prints
     output and `exit 1` on non-zero, otherwise filters only the benign
     `replacing existing signature` line. Build a `runtime_opts` array
     (`--options runtime` plus `--timestamp`, since the Developer ID is a real
     identity). Replace the bare `codesign --force …` calls on `obscura`/`aitm`/
     `$app` (lines ~59–61) with `cs …` so a failed sign aborts the release.
  2. After the core re-sign, detect the sysex:
     `sysex_bundle` = the single
     `"$app"/Contents/Library/SystemExtensions/*.systemextension` (bundle id
     `com.mrbrutti.aitmproxy.ne`). Detect it regardless of whether `APP` points at
     `/Applications` or `$HOME/Applications`.
  3. **NE branch** (`sysex_bundle` non-empty): fail with a clear message if the app
     profile (`$app/Contents/embedded.provisionprofile`) or the sysex profile
     (`$sysex_bundle/Contents/embedded.provisionprofile`) is missing (do **not**
     re-copy them — `build.sh` placed them). Then sign **inside-out** with `$dev_id`
     and `runtime_opts`: (a) a depth-first pass signing any nested Mach-O/frameworks
     under the sysex (none today — a single `Contents/MacOS/AitmproxyNE`; loop so it
     survives a future framework); (b) the `.systemextension` bundle with
     `--entitlements apps/mac/Extension/Aitmproxy-Extension.entitlements`; (c)
     `obscura` (with `apps/mac/EmbeddedObscura.entitlements`) and `aitm`; (d) the app
     with `--entitlements apps/mac/Aitmproxy.entitlements`. Sign the app **last**.
  4. **Non-NE branch** (no sysex): unchanged — `cs …` on `obscura`, `aitm`, then the
     app with no `--entitlements`.
  5. **Verify-or-fail, before `make-dmg.sh`** (NE branch): keep
     `codesign --verify --deep --strict --verbose=2 "$app"`; add
     `codesign -dv --verbose=4 "$sysex_bundle"` asserting the Developer ID identity
     and the hardened-runtime flag (`flags=…runtime`); `codesign -d --entitlements :- "$app"`
     asserting the output contains both `app-proxy-provider-systemextension` **and**
     `com.apple.developer.system-extension.install`; `codesign -d --entitlements :- "$sysex_bundle"`
     asserting the `-systemextension` NE value; `spctl -a -t exec -vvv "$app"`
     (advisory). Any failed assertion `exit 1` **before** `notarytool submit`.
  6. Header/doc: state this runs in the Terminal panel with Matt's Developer ID +
     ASC key **G638JVUND7** (team **995PCLM9KH**), that an NE release sets
     `APP=/Applications/Aitmproxy.app`, and that no secret is automated.
  The DMG build, DMG sign, `notarytool submit --wait`, `stapler staple`, and final
  `stapler validate` + `spctl` stay as they are.
- **Test:** `scripts/tests/check-notarize-dmg.sh` (new; `bash` + `grep` only) asserts,
  with `exit 0` expected:
  - `bash -n scripts/notarize-dmg.sh` exits 0;
  - `shellcheck scripts/notarize-dmg.sh` exits 0 (SH-AC8);
  - the script defines `cs()` and the app-sign path routes through `cs`
    (`grep -q 'cs("\{0,1\}' …` for the helper; no bare `codesign --force --sign "$dev_id" "$app"` masked by `|| true`);
  - the sysex-signing line references `apps/mac/Extension/Aitmproxy-Extension.entitlements`
    and appears **before** the app-sign line that references `apps/mac/Aitmproxy.entitlements`
    (ordering checked with `grep -n` line numbers; SH-AC1/SH-AC2);
  - the two entitlement-dump assertions and the `codesign -dv` sysex assertion appear
    **before** the `notarytool submit` line (SH-AC3/SH-AC4);
  - the NE work is guarded by a sysex-presence test, so the non-NE path is reachable
    (SH-AC6).
  TDD: write `check-notarize-dmg.sh` first; run it against today's `notarize-dmg.sh`
  and watch the sysex/entitlement/ordering assertions **fail**; edit `notarize-dmg.sh`;
  re-run and watch all assertions **pass**.
- **Done when:** `check-notarize-dmg.sh` exits 0 in the sandbox; and (manual, Terminal
  panel) a real NE-build notarization run passes SH-AC2/SH-AC3/SH-AC5 — see Manual
  verification. No Swift/Rust changed, so the Rust gate is unaffected.

---

### Task 2: config emits the capture gate only when on — Part 2a

- **Satisfies:** TG-AC1, TG-AC2, and the Config-plumbing half of TG-AC3.
- **Depends on:** none (independent of Task 1 and Task 3; disjoint files).
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift` (modify).
  - `apps/mac/Tests/AitmproxyKitTests/EmbeddedCoreLaunchTests.swift` (modify).
- **Change:** in `EmbeddedCoreLaunch.Config`:
  - add stored `public var captureEnabled: Bool`;
  - add `captureEnabled: Bool = false` to `init(…)` as the **last** parameter (after
    `sslInsecure`), so the existing call sites (`sampleConfig`, `config(sslInsecure:)`,
    the `bad` fixture, and `EmbeddedCore.spawn`) stay valid with the default;
  - in `yaml()`, after the existing `ssl_insecure` append, append — **only when
    `captureEnabled`** — the exact text `"\nmacos_capture:\n  enabled: true\n"`
    (a top-level `macos_capture:` sibling of `listen`/`mcp`/`browser`, `enabled: true`
    indented two spaces). Emit nothing when `captureEnabled` is false.
- **Test:** add to `EmbeddedCoreLaunchTests.swift`:
  - `@Test func capture_gate_emitted_only_when_enabled()`:
    `#expect(try config(captureEnabled: true).yaml().contains("macos_capture:\n  enabled: true"))`
    and `#expect(!(try config(captureEnabled: false).yaml()).contains("macos_capture"))`.
  - `@Test func capture_gate_defaults_off()`: a `Config` built without `captureEnabled:`
    has `captureEnabled == false` and its `yaml()` contains no `"macos_capture"`
    (TG-AC2 default-off). Add a local `config(captureEnabled:)` helper mirroring the
    existing `config(sslInsecure:)` helper.
  - `@Test func capture_gate_is_byte_identical_to_the_core_parse_input()`: the
    enabled `yaml()` contains the literal substring `"macos_capture:\n  enabled: true"`
    — byte-for-byte the input of the core's passing `config_file.rs`
    `macos_capture_enable_round_trips` test (`"macos_capture:\n  enabled: true\n"`).
  TDD: add the tests, run `swift test` filtered to `EmbeddedCoreLaunchTests`, watch
  them fail to compile/assert; implement; watch them pass.
- **Done when:** the three new kit-unit tests pass (sandbox), `swift test` is green,
  and the existing `EmbeddedCoreLaunchTests` still pass. The core's existing
  `macos_capture_enable_round_trips` / `macos_capture_defaults_disabled` remain green
  (TG-AC2 [rust], unchanged).

---

### Task 3: honest capability states — `.inactive` + `.disabled` event — Part 2b

- **Satisfies:** TG-AC7, and the kit-unit half of TG-AC6 (capability transition).
- **Depends on:** none (independent of Tasks 1 and 2; disjoint files).
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/CaptureCapability.swift` (modify).
  - `apps/mac/Tests/AitmproxyKitTests/CaptureCapabilityTests.swift` (modify).
  - `apps/mac/Sources/Aitmproxy/SettingsView.swift` (modify — **ONE line only**:
    the `.inactive` arm of the exhaustive `symbol(for:)` switch at ~line 249).
- **Plan amendment (orchestrator, 2026-10-30):** Task 3's coder correctly found that
  adding `case inactive` breaks the exhaustive `symbol(for:)` switch in
  `SettingsView.swift` (whole-package `swift test` would be red from end of Wave A
  through Wave B, and that file is otherwise Task 6's). Resolution (Option A): Task 3
  **also** adds the single arm `case .inactive: "pause.circle"` to that switch so the
  package stays compiling. `pause.circle` = flat monochrome, "installed but off"
  (Matt's icon rule). Task 6 then inherits this case (it no longer needs to add it;
  its heavier Capture-tab rework of `SettingsView.swift` runs sequentially in Wave C,
  so there is no concurrent-edit conflict). Also accepted: add `.inactive` to the
  existing `anUninstallLandsOnNotInstalledFromEveryState` test, and pin
  `.inactive.applying(.tunnelDisconnected) == .inactive` in
  `aDroppedTunnelFallsBackToApprovedButNeverHidesADegradation`.
- **Change:**
  - add `case inactive` to `CaptureCapability` with: `title` → `"Off"`;
    `isCaptureOn` → `false`; `isInstalledOrInstalling` → `true`; `canUninstall` →
    `true`. (The `canUninstall` and `title` switches are exhaustive, so the compiler
    forces `.inactive` into both.)
  - add `case disabled` to `CaptureCapabilityEvent`.
  - in `applying(_:)`, map `.disabled` → `.inactive` **authoritatively** (returns
    `.inactive` from every state, including `.capturing`, like `.uninstalled`).
  - leave `.tunnelConnected` lifting only `.approvedAttached → .capturing` (so
    `.inactive.applying(.tunnelConnected) == .inactive`); `.needsUserApproval`/
    `.activated` still re-enter the activation path from `.inactive`.
- **Test:** add to `CaptureCapabilityTests.swift`:
  - `@Test func theInactiveStateIsInstalledButOff()`:
    `#expect(CaptureCapability.inactive.title == "Off")`,
    `#expect(CaptureCapability.inactive.isCaptureOn == false)`,
    `#expect(CaptureCapability.inactive.isInstalledOrInstalling == true)`,
    `#expect(CaptureCapability.inactive.canUninstall == true)` (TG-AC7).
  - `@Test func disablingLandsOnInactiveFromEveryRunningState()`: for each of
    `.capturing, .approvedAttached, .pendingApproval, .degraded("boom"), .inactive`,
    `#expect(state.applying(.disabled) == .inactive)` (authoritative + idempotent)
    (TG-AC6 kit-unit).
  - `@Test func enablingFromInactiveReentersActivation()`:
    `#expect(CaptureCapability.inactive.applying(.needsUserApproval) == .pendingApproval)`
    and `#expect(CaptureCapability.inactive.applying(.activated) == .approvedAttached)`.
  - `@Test func inactiveIsNotLiftedToCapturingByALateTunnelEvent()`:
    `#expect(CaptureCapability.inactive.applying(.tunnelConnected) == .inactive)` and
    reaffirm `#expect(CaptureCapability.approvedAttached.applying(.tunnelConnected) == .capturing)`
    (TG-AC7 "capturing only via tunnelConnected from approvedAttached").
  - extend the existing exhaustive-ish tests (`everyStateHasAnOperatorFacingWord`,
    `theIndicatorSectionShowsOnlyWhenThereIsAnExtensionToReportOn`,
    `uninstallIsOfferedOnceApprovedAndAlsoToCleanUpADegradedInstall`,
    `theCaptureIndicatorIsOnOnlyWhileApprovedAndAttached`) to include `.inactive`.
  TDD: add tests, run `swift test` filtered to `CaptureCapabilityTests`, watch fail
  (missing case/compile); implement; watch pass.
- **Done when:** the new + updated kit-unit tests pass (sandbox), `swift test` green.

---

### Task 4: operator ON/OFF activation controller — Part 2c

- **Satisfies:** TG-AC4 (structural half), TG-AC5 (structural half), TG-AC6 (controller
  behaviour), and the controller side of TG-AC9.
- **Depends on:** Task 3 (uses `.disabled`/`.inactive`).
- **Files:**
  - `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift` (modify).
- **Change:**
  - **`start()` becomes inert-detect + conditional-resume.** Keep the fixture/
    snapshot/self-test guard and the `health.extensionController = self` publish.
    Then: if not embedded → `.extensionNotInstalled`, return (as today); if embedded
    and the persisted `capture.enabled` (`UserDefaults.standard.object(forKey: "capture.enabled") as? Bool ?? false`)
    is **true** → call `enable()`; if embedded and `capture.enabled` is **false** →
    submit **no** `OSSystemExtensionRequest` and set the idle state. **(Architect's
    call, per spec):** best-effort detect a previously-approved-but-off extension via
    `NETransparentProxyManager.loadAllFromPreferences()` and set `.inactive` when a
    configuration for `CaptureExtension.identifier` is present, else
    `.extensionNotInstalled`; if that proves awkward, default to
    `.extensionNotInstalled` and let the first `enable()` reconcile (spec "left to the
    builder").
  - **`func enable()`** — the operator ON action: guard embedded and not already
    pending/managing; set `managingExtension = true`; `health.extensionController = self`;
    `beginKeepingAlive()`; build and submit
    `OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: CaptureExtension.identifier, queue: .main)`
    with `delegate = self` (the body now in `start()`); idempotent (re-entry while a
    request is outstanding is a no-op).
  - **`func disable() async`** — the operator OFF action. Does **not** submit a
    deactivation request (sysex stays installed). Guard like `uninstall()` (managing,
    not already disabling). Cancel `reconcileTask` and `await` it; `removeTunnelObserver()`;
    then stop the tunnel. **(Architect's call, per spec Q2 APPROVED + builder note):**
    load this extension's saved `NETransparentProxyManager`, set `isEnabled = false`
    and `saveToPreferences()` (keeping the configuration, **not** `removeFromPreferences`)
    so the system does not auto-restart the stopped tunnel, then
    `connection.stopVPNTunnel()`. If `isEnabled = false` + save turns out to be
    unnecessary (live check TG-AC6), simplify to `stopVPNTunnel()` alone — decided by
    the manual check, not here. Finish with `apply(.disabled)` → `.inactive`.
    Idempotent.
  - **`uninstall()`** unchanged (full removal: cancel reconcile, remove configuration,
    deactivation request, end at `.extensionNotInstalled`).
  - The operator-only type comment stays and is extended to name `enable()`/`disable()`
    as operator-only methods with no bus/MCP/`Session`/palette caller.
- **Test:** structural tripwire (sandbox, `grep`), expected `exit 0`:
  - `func enable()` and `func disable() async` exist in `ExtensionController.swift`;
  - `start()` does **not** submit an activation request unconditionally — i.e. the
    single `submitRequest`/`activationRequest(...)` for activation lives inside
    `enable()`, and `start()` reads `capture.enabled` and branches to `enable()`
    (`grep -n 'capture.enabled' ExtensionController.swift` is non-empty; the
    `activationRequest(` call is textually inside `enable()`, not `start()`) (TG-AC4);
  - `disable()` contains `stopVPNTunnel()` and does **not** contain
    `deactivationRequest` (sysex not removed) (TG-AC6);
  - `disable()` ends with `apply(.disabled)`.
  TDD: write the grep assertions first (they fail — `func disable` absent); implement;
  re-run (pass). Then (Terminal) `./build.sh` compiles and `swift test` passes.
- **Done when:** the structural greps pass (sandbox), `./build.sh` compiles with no
  errors and no new warnings, `swift test` is green (Terminal). Live behaviour
  (prompt on ON, tunnel up, OFF stops capture, sysex remains, re-enable needs no
  re-approval) is proven in Manual verification (TG-AC5/TG-AC6 [manual]).

---

### Task 5: spawn threads `capture.enabled` from UserDefaults — Part 2d

- **Satisfies:** TG-AC3 (the spawn-read half).
- **Depends on:** Task 2 (`Config.captureEnabled`).
- **Files:**
  - `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift` (modify).
- **Change:** in `spawn()`, beside the existing `savedPort`/`sslInsecure` reads, add
  `let captureEnabled = defaults.object(forKey: "capture.enabled") as? Bool ?? false`
  (read fresh each spawn) and pass `captureEnabled: captureEnabled` into the
  `EmbeddedCoreLaunch.Config(…)` it builds (line ~177). Nothing else changes; the
  core respawns on `restartCoreTick` (already wired in `ShellView`) and re-reads the
  key.
- **Test:** structural tripwire (sandbox, `grep`), expected `exit 0`:
  - `grep -q 'forKey: "capture.enabled"' apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift`;
  - `grep -q 'captureEnabled: captureEnabled' apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift`.
  TDD: add the greps first (fail — key absent); implement; re-run (pass).
  The Config-plumbing value is already unit-covered by Task 2; the fresh-read-on-restart
  behaviour is proven live (TG-AC3 [manual]).
- **Done when:** the greps pass (sandbox), `./build.sh` compiles (Terminal). Live
  spawn shows the core running the feeder only when the toggle is on — Manual
  verification.

---

### Task 6: Capture Settings tab, menu command, visibility, snapshots — Part 2e

- **Satisfies:** TG-AC5 (UI ON handler), TG-AC6 (UI OFF handler), TG-AC8 (persisted
  OFF default + idempotent), TG-AC10 (menu + shortcut), TG-AC11 (snapshots), and the
  visibility/`captureSupported` design call.
- **Depends on:** Task 3 (`.inactive`/`title`/`symbol`), Task 4 (`enable()`/`disable()`).
- **Files:**
  - `apps/mac/Sources/Aitmproxy/SettingsView.swift` (modify).
  - `apps/mac/Sources/Aitmproxy/App.swift` (modify).
  - `apps/mac/Sources/Aitmproxy/Bus/CoreHealthState.swift` (modify).
  - `apps/mac/Sources/Aitmproxy/Snapshot.swift` (modify).
  - `apps/mac/Sources/Aitmproxy/SnapshotScenes.swift` (modify).
  - (optionally) `apps/mac/Sources/Aitmproxy/Session.swift` (modify) — only if the
    builder homes the ON/OFF glue in a `@MainActor Session.setCaptureEnabled(_:)`
    method rather than the toggle's `set:`. Declare it in the Coder's report if used.
- **Change:**
  - `CoreHealthState`: add `var captureSupported: Bool = false` (default false; set
    `true` at launch when `CaptureExtension.isEmbedded(inApp:)`, and settable by the
    snapshot seed). (Architect's call per spec — may instead be computed in the view;
    if so, note it and ensure snapshots can still render every state.)
  - `SettingsTab`: add `case capture` with `title "Capture"` and an SF Symbol such as
    `antenna.radiowaves.left.and.right`; add the `.capture` arm to the exhaustive
    `page(_:)` switch (compile tripwire) rendering a new `CaptureSettings`-style view.
  - Move the existing capture state + Uninstall out of `GeneralSettings`
    (`CaptureSettings()` call) into the new Capture tab view.
  - New Capture tab contents: a `Toggle("Capture L4 traffic", …)` bound to
    `@AppStorage("capture.enabled")` (default `false`, domain `com.mrbrutti.aitmproxy`)
    whose side-effecting `set:` (the `BusSettings` active-core picker is the precedent):
    **ON** → write the preference, `session.coreHealth.extensionController?.enable()`,
    `session.restartCoreTick += 1`; **OFF** →
    `await session.coreHealth.extensionController?.disable()`, write the preference,
    `session.restartCoreTick += 1` (stop the tunnel before the restart). Both orderings
    idempotent. Plus a state line derived from `session.coreHealth.captureCapability`
    (`title`, `degradedReason`, `isCaptureOn`, SF-Symbol mapping; must read "Capturing"
    only at `.capturing`), the Uninstall button when `canUninstall`, and one line
    naming the two System Settings prompts on first enable. Add `.inactive` to the
    view's exhaustive `symbol(for:)` switch (compile tripwire). Show the controls when
    `captureSupported` (or `capability.isInstalledOrInstalling`); when unsupported
    (dev/fixture), hide them or disable with "not available in this build" — never a
    live dead toggle.
  - `App.swift`: add a menu command near "Restart Core" in the `Proxy` `CommandMenu`
    that toggles capture (label reflects state, e.g. "Enable Capture"/"Disable
    Capture") with a **non-colliding** keyboard shortcut (avoid ⌃⌘R = Reconnect Bus,
    ⌃⌘⇧R = Restart Core, ⌘⇧R = Resume/Pause Capture, ⌥⌘R = Edit & Replay). It calls
    the same operator glue as the toggle. (Exact placement, label, shortcut left to
    the builder per spec.)
  - `Snapshot.swift` + `SnapshotScenes.swift`: after the existing Settings loop (or as
    a dedicated capture loop), seed `session.coreHealth.captureSupported = true` and
    cycle `session.coreHealth.captureCapability` through the four states and capture
    the Capture tab in light+dark:
    `.inactive` (off), `.pendingApproval` (awaiting-approval), `.capturing` (active),
    `.degraded("…")` (failed), e.g. `settings-capture-off-<mode>.png`,
    `settings-capture-awaiting-<mode>.png`, `settings-capture-active-<mode>.png`,
    `settings-capture-failed-<mode>.png`, each with its `-layout.json`.
- **Test:**
  - **[mac-snapshot] (Terminal):** `tools/snap.sh` (or `APP_SNAPSHOT_PAGES=settings tools/snap.sh`)
    writes the four Capture states in light+dark; `tools/grid-lint.sh` prints `PASS`
    and `swift tools/check-layout.swift /tmp/Aitmproxy-shots/*-layout.json` prints
    `PASS` (TG-AC11). Look at the PNGs: off/awaiting/active/failed each render, and
    the state line never says "Capturing" unless the seeded state is `.capturing`.
  - **[structural] (sandbox):** `grep -q 'case capture' apps/mac/Sources/Aitmproxy/SettingsView.swift`;
    the `Proxy` menu in `App.swift` contains a capture-toggle `Button` with a
    `keyboardShortcut` that is not one of the four listed collisions
    (TG-AC10); `@AppStorage("capture.enabled")` appears and defaults to `false`
    (TG-AC8); the ON path references `.enable()` + `restartCoreTick` and the OFF path
    references `.disable()` + `restartCoreTick` (TG-AC5/TG-AC6 UI halves).
  - **[manual] (Terminal):** persistence across relaunch and no-op-on-same-value
    (TG-AC8); menu audit (TG-AC10) — see Manual verification.
  TDD: snapshots are the red/green here — add the `.capture` case + seed states, run
  `swift test` (compile forces the exhaustive switches), then `tools/snap.sh` and
  inspect; the structural greps are added and demonstrated red (before) / green (after).
- **Done when:** `swift test` green (compile tripwires satisfied), the four Capture
  snapshots render in light+dark, grid-lint + check-layout print `PASS`, the structural
  greps pass. Live toggle behaviour and the menu audit are in Manual verification.

---

### Task 7: ShellView wiring + operator-only tripwire — Part 2f

- **Satisfies:** TG-AC4 (ShellView single call site), TG-AC9 (operator-only, no agent
  path), and consolidates the structural tripwires.
- **Depends on:** Task 4 (`start()` conditional-resume) and Task 6 (the Capture UI +
  menu are in the tripwire's allow-list). **Runs after Task 6** (its allow-list greps
  need Task 6's files present), so it is **not** parallel with Task 6.
- **Plan amendment (orchestrator, 2026-10-30):** the tripwire's allow-list below was
  written before the code existed; it must match reality. As actually built:
  `ExtensionController.swift` legitimately contains `"capture.enabled"` (read in
  `start()`) AND the `enable()`/`disable()` definitions + the `start()`→`enable()`
  self-call; Task 6 homed the ON/OFF glue in a `CaptureSwitch` enum inside
  `SettingsView.swift` (NOT `Session.swift`), and `App.swift` holds the menu label/
  command. So the legitimate locations are `EmbeddedCore.swift`,
  `ExtensionController.swift`, `SettingsView.swift`, and `App.swift`; there is no
  `Session*.swift` glue file. The coder MUST read the real files and build the
  allow-list from them; the invariant that matters is that NO agent-reachable surface
  (BusService / CommandMap / CommandPalette / Session+Palette / Session+Verbs /
  AgentPanel / Fixtures+Agent / Fixtures+Tools) references the toggle,
  `enable()`/`disable()`, the activation/deactivation requests, or `capture.enabled`.
- **Files:**
  - `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` (modify only if needed).
  - `apps/mac/tools/check-capture-operator-only.sh` (create) — the committed TG-AC9
    tripwire.
- **Change:**
  - `ShellView`: confirm the `.task` still constructs `ExtensionController(health:)`
    and calls `start()` exactly **once** (the existing single call site). With Task 4,
    `start()` is now the conditional-resume, so first-run OFF submits no request —
    **no code change is expected here**; if the build requires none, this file is
    verified unchanged (the task's production artifact is then the tripwire script).
  - `check-capture-operator-only.sh`: a `bash`+`grep` tripwire asserting the
    operator-only invariant (TG-AC9), `exit 0` on a clean tree, `exit 1` on a
    violation:
    1. `OSSystemExtensionRequest.activationRequest(` and the deactivation request
       appear **only** in `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift`;
    2. calls to `.enable()` / `.disable()` on the extension controller appear **only**
       in the Capture Settings view (`SettingsView.swift`) and `App.swift`
       (the menu), plus the definitions in `ExtensionController.swift`;
    3. the `"capture.enabled"` UserDefaults key appears **only** in
       `EmbeddedCore.swift`, `SettingsView.swift`, `App.swift`, and at most one
       `Session*.swift` glue file;
    4. none of the agent-reachable surfaces reference any of the above:
       `Bus/BusService.swift`, `AitmproxyKit/CommandMap.swift`,
       `Shell/CommandPalette.swift`, `Session+Palette.swift`, `Session+Verbs.swift`,
       `Panels/AgentPanel.swift`, `AitmproxyKit/Fixtures+Agent.swift`,
       `AitmproxyKit/Fixtures+Tools.swift`;
    5. `ShellView.swift` has exactly one `.start()` call on the `ExtensionController`.
    The script prints the offending file + line on failure (fail-closed, like the
    L4 `operator_surfaces.rs` tripwire).
- **Test:**
  - **[structural] (sandbox):** `bash -n apps/mac/tools/check-capture-operator-only.sh`
    exits 0; `shellcheck apps/mac/tools/check-capture-operator-only.sh` exits 0;
    `apps/mac/tools/check-capture-operator-only.sh` exits 0 on the branch tree.
    Demonstrate **red**: temporarily add a `UserDefaults.standard.set(true, forKey: "capture.enabled")`
    line to `Bus/BusService.swift`, run the script → `exit 1` naming BusService;
    remove it → `exit 0` (TG-AC9).
  - **[rust] (sandbox/Terminal):** the existing core-side `macos_capture_gate.rs`
    (`agent_cannot_trigger_sysex_install`) still passes — `cargo test` green,
    confirming no core trigger was added (TG-AC9 [rust]).
  TDD: write the tripwire, prove it catches a planted violation (red), remove the
  violation (green).
- **Done when:** the tripwire exits 0 on the branch, catches a planted violation,
  `bash -n`/`shellcheck` pass, `swift test` + `./build.sh` green (Terminal), and
  `cargo test` keeps `macos_capture_gate.rs` green.

---

## Parallelization

| Task | Part | Files (writer-exclusive) | Independent of | Depends on |
|---|---|---|---|---|
| 1 | 1 | `scripts/notarize-dmg.sh`, `scripts/tests/check-notarize-dmg.sh` | all of 2–7 | — |
| 2 | 2a | `AitmproxyKit/EmbeddedCoreLaunch.swift`, its test | 1, 3 | — |
| 3 | 2b | `AitmproxyKit/CaptureCapability.swift`, its test | 1, 2 | — |
| 4 | 2c | `Aitmproxy/Bus/ExtensionController.swift` | 5 | 3 |
| 5 | 2d | `Aitmproxy/Bus/EmbeddedCore.swift` | 4 | 2 |
| 6 | 2e | `SettingsView.swift`, `App.swift`, `CoreHealthState.swift`, `Snapshot.swift`, `SnapshotScenes.swift` (± `Session.swift`) | — | 3, 4 |
| 7 | 2f | `Shell/ShellView.swift`, `tools/check-capture-operator-only.sh` | — | 4, 6 |

- **Wave A (fan out 3 parallel coders):** Task 1 ∥ Task 2 ∥ Task 3 — disjoint files,
  no shared dependency.
- **Wave B (fan out 2 parallel coders):** Task 4 ∥ Task 5 — disjoint files; Task 4
  needs Wave-A Task 3, Task 5 needs Wave-A Task 2.
- **Wave C (sequential):** Task 6, then Task 7 — Task 7's allow-list greps need
  Task 6's Capture UI present. (Task 7's deny-list clause alone is independent of
  Task 6, but the full tripwire is authoritative only against the merged tree, which
  the whole-branch Tester re-runs.)
- **Then:** whole-branch Tester (every criterion), then the three-reviewer panel in
  parallel, then integration.

---

## Manual verification (Terminal panel, Matt's Mac)

Run after the branch's automated gate is green. These are the `[manual]` acceptance
criteria; the sandbox cannot sign, notarize, bind ports, or run a live core.

**Part 1 — signing/notarizing (SH-AC2/SH-AC3/SH-AC5, manual halves of SH-AC1/AC4/AC6):**

```
# Build an NE release into /Applications (needs the Developer ID identity + both NE profiles)
cd apps/mac && ./build.sh                 # embeds + signs the sysex; installs /Applications/Aitmproxy.app
# Sign + notarize + staple the DMG with the credentialed release script
APP=/Applications/Aitmproxy.app ASC_ISSUER_ID=<issuer> \
  bash scripts/notarize-dmg.sh           # uses Developer ID + ASC key G638JVUND7 (team 995PCLM9KH)
# Prove the nested sysex + app entitlements (SH-AC2/SH-AC3)
sysex=/Applications/Aitmproxy.app/Contents/Library/SystemExtensions/com.mrbrutti.aitmproxy.ne.systemextension
codesign -dv --verbose=4 "$sysex"                         # Developer ID identity + flags=…runtime
codesign -d --entitlements :- /Applications/Aitmproxy.app # app-proxy-provider-systemextension + system-extension.install
codesign -d --entitlements :- "$sysex"                    # the -systemextension NE value
codesign --verify --deep --strict --verbose=2 /Applications/Aitmproxy.app
spctl -a -t exec -vvv /Applications/Aitmproxy.app
xcrun stapler validate dist/Aitmproxy-*.dmg              # SH-AC5
```

**Part 2 — toggle behaviour (TG-AC3/AC4/AC5/AC6/AC8/AC10/AC12, manual halves):**

1. **Clean install, no prompt (TG-AC4):** on a Mac with no prior Aitmproxy sysex,
   open the notarized app. **Expect:** no "Network Extensions" / "Add Proxy
   Configurations" prompt, capture reads Off.
2. **ON activates + captures (TG-AC5, TG-AC3):** Settings ▸ Capture → turn **ON**.
   **Expect:** the two System Settings prompts appear; after approval the state line
   reaches "Capturing" (tunnel `.connected`); the embedded core log shows the feeder
   running; app flows capture L4 traffic.
3. **OFF stops + keeps the sysex (TG-AC6):** turn **OFF**. **Expect:** capture stops
   immediately (no interception); the state line reads Off/`.inactive`; the sysex is
   still listed in System Settings ▸ General ▸ Login Items & Extensions; re-enabling
   needs **no** re-approval.
4. **Uninstall still fully removes (TG-AC6):** with capture off, click Uninstall.
   **Expect:** the sysex and its proxy configuration are removed; state →
   Extension not installed.
5. **Persistence + idempotence (TG-AC8):** toggle ON, relaunch → still ON; toggle the
   same value twice → no duplicate activation request, no restart storm.
6. **Menu audit (TG-AC10):** the Proxy menu has the Enable/Disable Capture command
   with a working, non-colliding shortcut that drives the same behaviour as the toggle.
7. **Gates (TG-AC12):** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
   green; `./build.sh` no errors; `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`
   green.

---

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
