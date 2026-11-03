# Aitmproxy

A native macOS app in SwiftUI. It runs on this Mac only, with a local
SwiftData database and no server.

## Layout

- `Sources/Aitmproxy/` the app. `App.swift` has the window, menus, and the database location.
- `Sources/Aitmproxy/AitmApplication.swift` the `NSApplication` subclass named by `Info.plist.in`'s `NSPrincipalClass`; its `terminate(_:)` ends open sheets before `super` so Quit is never refused by an attached sheet.
- `Sources/AitmproxyKit/` rules and data logic with no SwiftUI. Tests in `Tests/AitmproxyKitTests/`.
- `Package.swift` a Swift package. There is no Xcode project.
- `build.sh` builds, signs, and installs `~/Applications/Aitmproxy.app`. Only `--ne` builds the Network Extension and installs to `/Applications`.
- `Icon/AppIcon.icon` the app icon, an Icon Composer file (JSON plus SVG layers). `build.sh` compiles it with `tools/make_icon.sh`; `tools/icon_review.sh` renders every look into one PNG.
- `docs/` the brief, the screen index, and the user stories, when they exist.

## Build and check

- Build and install: `./build.sh` (release) or `./build.sh --debug`, into `~/Applications`. Add `--open` to restart the app with the new build. The build shows warnings; fix them.
  - `--ne` is the only way to get the Network Extension build (Developer ID signing, sysex embedded, installed to `/Applications`). It is never inferred from the NE profiles being present, so a plain build cannot replace the released app in `/Applications`. `tools/ne-preflight.sh` picks the Developer ID identity that both profiles authorise (or checks `NE_SIGN_IDENTITY`); a sysex signed with a certificate its profile does not list fails activation with "code signature invalid".
  - A local `--ne` build can never activate capture: macOS refuses an unnotarized Developer ID system extension. build.sh prints that warning last and exits 1 unless `--allow-unnotarized` is passed, which the release recipe does because the build is the input to `scripts/notarize-dmg.sh` (`docs/RELEASE.md` step 3). The notarized DMG is the only path to a working extension.
  - Before installing, the script prints the bundle it is about to replace with its version and build. It refuses when the installed `CFBundleShortVersionString` differs from the version being built unless you pass `--replace` (`CFBundleVersion` is a per-build timestamp, so it is printed, not compared).
  - Iterate without installing anything: `DEV_TAG=<tag> CORE_DIR=<dir with aitm> tools/snap-dev.sh` builds to its own scratch dir, assembles a throwaway bundle `/tmp/Aitmproxy-dev-<tag>.app` with process name `Aitmproxy-<tag>`, and launches it LIVE against the copied core on an isolated `APP_STORE` (`/tmp/Aitmproxy-dev-state-<tag>`), printing the pid, the store path and the stop line (`kill <pid>; pkill -f <bundle>/Contents/Resources/core/` — a SIGTERM to the app does not run its AppKit teardown, so its embedded core and obscura child must be reaped by the bundle path; a follow-up gives the app a SIGTERM handler). `NO_LAUNCH=1` only builds.
- Unit tests: `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`.
- Live self-test (every proxy action over the real bus, `SelfTest+Live.swift`): start `aitm` with a config (`AITM_CONFIG=… ./target/release/aitm`) and an upstream (`python3 -m http.server 8099 --bind 127.0.0.1`), then `AITM_CONFIG=… tools/selftest-live.sh`. Run it after any change to `Bus/`. This is the **agent-driven** verification (the app's Session over the real MCP bus). `APP_LIVE_STRICT=1` makes `flow.kill` strict. `APP_BIN=<path to a snap-dev binary>` runs it against a dev bundle instead of `~/Applications`.
  - Also run after any change to `Bus/`: `tools/selftest-live-reconnect.sh` (`DEV_TAG=<tag> [CORE_DIR=<dir>]`) builds a snap-dev bundle with the embedded core, drives Proxy ▸ Reconnect Bus, Proxy ▸ Restart Core and a `kill -KILL` of the core through the real menu bar, and asserts over the bus that one menu-driven View ▸ Pause/Resume Proxy takes effect after each — the #192 reconnect-ownership check.
  - Connection settings (`bus.*`, `proxy.*`, `capture.enabled`) come from `Store.defaults`, never `UserDefaults.standard`. `SettingsDomain` (Kit) picks the store once per process: the real defaults in a normal launch; an isolated suite `com.mrbrutti.aitmproxy.harness`, wiped at startup, whenever `APP_STORE` or `APP_LIVE` is set; `APP_DEFAULTS_SUITE=<name>` names a suite that is kept between runs (pre-seed it to test a pasted operator token). So Settings ▸ Bus residue from an earlier session never reaches a self-test, and a self-test never writes the operator's settings. Under `APP_LIVE=1` the active core defaults to external, the core at `AITM_CONFIG`.
  - Never pass settings as `-key value` arguments: AppKit opens any bare word left over (for example `external` in `--selftest -bus.activeKind external`) as a document, SwiftUI then never opens the main window, and the self-test never starts. `SelfTest.armWatchdog` turns that into `SELFTEST FAIL` + exit 1 after 15 s, and a run that has not finished after 240 s likewise.
- Never test against the real database in `~/Library/Application Support/Aitmproxy/`.
- Then check the grid: `tools/grid-lint.sh` prints PASS.

**The gate** (in this order; a change is done when all five hold and the shots are attached to the PR):

1. `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build` (Terminal).
2. `tools/grid-lint.sh` and the three tripwires `tools/check-connection-words.sh`, `tools/check-capture-operator-only.sh`, `tools/check-capture-toggle.sh`, all exit 0.
3. Build the dev bundle with a real core: `DEV_TAG=<tag> CORE_DIR=<dir with aitm> tools/snap-dev.sh`. It launches the bundle LIVE on an isolated `APP_STORE` and prints the pid, the store path and the stop line (`kill <pid>; pkill -f <bundle>/Contents/Resources/core/` — a SIGTERM to the app does not run its AppKit teardown, so its embedded core and obscura child must be reaped by the bundle path; a follow-up gives the app a SIGTERM handler). `NO_LAUNCH=1` only builds.
4. Real traffic through it: `python3 -m http.server 8099 --bind 127.0.0.1` as upstream, `curl -x 127.0.0.1:<listen> http://127.0.0.1:8099/` (Safari for HTTPS once the CA is trusted), then read the real window: `swift tools/winshot.swift <pid printed by snap-dev.sh> /tmp/claude/<name>.png` (the pid, not `Aitmproxy-<tag>`: a tagged dev bundle keeps the display name `Aitmproxy`, and `winshot` matches an owner name).
5. `AITM_CONFIG=… tools/selftest-live.sh` (external core) and `tools/selftest-live-embedded.sh`.

No fixture, snapshot, gallery or sample-data run exists any more and none may be added.

**Removed 2026-10-31** with the fake-data modes (spec `docs/superpowers/specs/2026-10-31-remove-fake-data-ui-modes-design.md`), each with what replaces it:

- `tools/snap.sh`, `tools/verify.sh`, `tools/selftest.sh` (fixture snapshots, the fixture self-test, and the wrapper that ran them) → the gate above.
- `tools/cua-clickthrough.sh`, `tools/cua-l4.sh` (real input events on the fixture session) → removed, no replacement for the pixel-path row click-through. `tools/cua-ne-drive.sh` is a different tool: AX-driven Settings ▸ Capture, Scope add and Safari plus a `winshot` of the real window, on the INSTALLED app (a dev bundle embeds no extension).
- `tools/check-layout.swift` (read the `-layout.json` files only snapshot mode wrote) → `tools/grid-lint.sh` plus reading the real window.
- `APP_FIXTURES`, `APP_SNAPSHOT`, `APP_SNAPSHOT_PAGES`, `APP_KIT_GALLERY`, `APP_L4_EMBEDDED` (the switches that selected those modes) → a launch that still sets one prints `<VAR> was removed on 2026-10-31 with the fixture modes; see apps/mac/CLAUDE.md` and exits 1 before any window or core (`RemovedModes`, spec D3 item 8). The harness variables are `APP_STORE` and `APP_LIVE`.

## Design rules

- Use Apple's controls and system styles. Only the accent color is custom: `UI/Theme.swift` (`ThemeStore.defaultID`). People change it, and light or dark mode, in Settings > Appearance.
- Views use `.tint`, `Palette.accent`, `Palette.accentText` (accent-colored text), and `Palette.onAccent` (text on an accent fill). Never hard-code colors, radii, or durations in views.
- Compare accents: launch the dev bundle with `APP_ACCENT=<id>` in the environment (`APP_ACCENT=<id> DEV_TAG=<tag> CORE_DIR=<dir> tools/snap-dev.sh`).
- Spacing comes from `Space` in `UI/Grid.swift`, on a 4 pt grid. Mark custom pages and cards with `.gridArea` and `.gridProbe`.
- Windows open calm: `.noInitialFocus()` on every window and sheet (no focus ring or selected text on open), `.fitsContent()` on sheets and Settings tabs (no scroll bar with nothing to scroll). System scroll bars. Both in `UI/WindowBehavior.swift`.
- Settings: one tab per topic in `SettingsView.swift`, one grouped Form per tab. Add a case to `SettingsTab` for a new tab.
- Window chrome (title bar, toolbar, sidebar, menus, sheets) stays system. Buttons use system styles, like `.borderedProminent`.
- Colors: `.primary`, `.secondary`, `.tint`, and system colors. Never fixed grays or white for text.
- Every action has a menu bar item and a keyboard shortcut.
- `Label` for icon and text pairs. SF Symbols for icons.
- `ContentUnavailableView` for empty states.
- Liquid Glass belongs to floating controls only, never to content.

## Skills

The bama plugin has a skill for each step: `mac-design` (design rules),
`design-system` (accent and tokens), `layout-grid`, `ux-design`,
`swift-swiftui`, `os-integrations`, `performance`, `build-and-verify`,
`test-mac-app`, `app-icon`, `user-stories`, and `improve-loop`. Use them.

## Git

- Commit after each working change, with a message that says what the user can now do.
