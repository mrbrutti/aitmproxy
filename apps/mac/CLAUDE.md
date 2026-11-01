# Aitmproxy

A native macOS app in SwiftUI. It runs on this Mac only, with a local
SwiftData database and no server.

## Layout

- `Sources/Aitmproxy/` the app. `App.swift` has the window, menus, and the database location.
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
  - Iterate without installing anything: `DEV_TAG=<tag> tools/snap-dev.sh` builds to its own scratch dir and runs a throwaway bundle `/tmp/Aitmproxy-dev-<tag>.app` with process name `Aitmproxy-<tag>`.
- Unit tests: `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`.
- Self-test (the app's real functions on a /tmp store): `tools/selftest.sh`. Exit 0 when every check passes. Add a check for every story with logic in `SelfTest.swift`.
- Live self-test (every proxy action over the real bus, `SelfTest+Live.swift`): start `aitm` with a config (`AITM_CONFIG=… ./target/release/aitm`) and an upstream (`python3 -m http.server 8099 --bind 127.0.0.1`), then `AITM_CONFIG=… tools/selftest-live.sh`. Run it after any change to `Bus/`. This is the **agent-driven** verification (the app's Session over the real MCP bus). `APP_LIVE_STRICT=1` makes `flow.kill` strict. `APP_BIN=<path to a snap-dev binary>` runs it against a dev bundle instead of `~/Applications`.
  - Connection settings (`bus.*`, `proxy.*`, `capture.enabled`) come from `Store.defaults`, never `UserDefaults.standard`. `SettingsDomain` (Kit) picks the store once per process: the real defaults in a normal launch; an isolated suite `com.mrbrutti.aitmproxy.harness`, wiped at startup, whenever `APP_STORE`, `APP_LIVE`, `APP_SNAPSHOT` or `APP_FIXTURES` is set; `APP_DEFAULTS_SUITE=<name>` names a suite that is kept between runs (pre-seed it to test a pasted operator token). So Settings ▸ Bus residue from an earlier session never reaches a self-test, and a self-test never writes the operator's settings. Under `APP_LIVE=1` the active core defaults to external, the core at `AITM_CONFIG`.
  - Never pass settings as `-key value` arguments: AppKit opens any bare word left over (for example `external` in `--selftest -bus.activeKind external`) as a document, SwiftUI then never opens the main window, and the self-test never starts. `SelfTest.armWatchdog` turns that into `SELFTEST FAIL` + exit 1 after 15 s, and a run that has not finished after 240 s likewise.
- CUA click-through (`tools/cua-clickthrough.sh`, with `tools/cgclick.swift`): level-4 computer-use — REAL input events (not the bus) on the fixture session; proves the **human UI** path. Two layers: a **pixel path** that normalizes the window and CGEvent-clicks computed row pixels (no Accessibility tree — selection verified by a `screencapture`+`md5` inspector-region diff; proof shots in `/tmp/cua-row*.png`), and a **menu path** of real AX menu-bar clicks (Resume, Build PoC opens a sheet). Needs Accessibility + Screen-Recording permission for the terminal. Note: System Events can't address SwiftUI in-window elements by name (AX tree unnamed), which is why the pixel/coordinate path is used for row/tab/editor; the deterministic human-input coverage also lives in the in-app self-test (menu audit + key events).
- After every UI change, take snapshots with sample data and look at them: `tools/snap.sh`.
  It writes `/tmp/Aitmproxy-shots/<page>-light.png` and `-dark.png` for every sidebar page, and `settings-<tab>-light.png` and `-dark.png` for every Settings tab, then quits. `APP_SNAPSHOT_PAGES=all,settings tools/snap.sh` limits the pages.
  For a panel, sheet, or popover, add a capture to `Snapshot.swift` like the Settings loop.
- Parts gallery (every kit part in every state, `design/KIT.md`): `APP_KIT_GALLERY=1 APP_STORE=/tmp/x APP_SNAPSHOT=/tmp/Aitmproxy-gallery ~/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy` captures the parts gallery as `gallery-light.png` and `gallery-dark.png`.
- Snapshots, seed data, and the self-test refuse to run without `APP_STORE` in /tmp.
- Never test against the real database in `~/Library/Application Support/Aitmproxy/`.
- Then check the grid: `tools/grid-lint.sh` and `swift tools/check-layout.swift /tmp/Aitmproxy-shots/*-layout.json`. Both print PASS.
- A change is done when the build has no errors, the grid checks pass, and you looked at the light and dark snapshots.

## Design rules

- Use Apple's controls and system styles. Only the accent color is custom: `UI/Theme.swift` (`ThemeStore.defaultID`). People change it, and light or dark mode, in Settings > Appearance.
- Views use `.tint`, `Palette.accent`, `Palette.accentText` (accent-colored text), and `Palette.onAccent` (text on an accent fill). Never hard-code colors, radii, or durations in views.
- Compare accents: add `APP_ACCENT=<id>` to the snapshot command.
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
