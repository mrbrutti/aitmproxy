# 13 - Resolving a real app icon and display name from a Network Extension signing identifier

Researcher note, stage 1. Read 2026-10-31. Repo root for paths below is the
`apps-attribution-8ab619` worktree. Local checks ran on macOS 27.0 (build 26A428,
Xcode SDK on this Mac), not macOS 26; the app's floor is 26 (`Package.swift`,
`LSMinimumSystemVersion` 26.0). Apple docs are read from
`developer.apple.com/tutorials/data/documentation/...json` (the rendered pages are
JS-only). Labels: **(V)** verified by a command on this Mac, **(D)** Apple doc,
**(W)** third-party web source, **(U)** unverified / inference.

## 1. Question

How should the macOS app turn the `source_app` string (`NEFlowMetaData.sourceAppSigningIdentifier`)
into the process's real icon and display name, including XPC and helper processes and CLI
tools that have no app bundle?

## 2. Short answer

The identifier is usually the bundle id, so `NSWorkspace.urlForApplication(withBundleIdentifier:)`
plus `icon(forFile:)` and `Bundle.object(forInfoDictionaryKey:)` resolve ordinary apps and most
Electron/Chrome helpers (walk to the outermost `.app`). It returns nil for `com.apple.curl`,
`com.apple.WebKit.*` and ad-hoc ids, and a static `WebKit.Networking -> Safari` map is wrong:
that service serves Safari, Mail and others. Fallback is a terminal glyph. Everything is
thread-safe, off-main, unsandboxed. Exact owner of a shared helper needs a pid or audit token.

## 3. Findings

### Q1. `urlForApplication(withBundleIdentifier:)` and helper ids

Doc **(D)** (`.../nsworkspace/urlforapplication(withbundleidentifier:).json`): returns "the URL of
the app, or `nil` if no app has the bundle identifier"; "uses various heuristics in case multiple
apps have the same bundle ID"; "You can safely call this method from any thread".
`urlsForApplications(withBundleIdentifier:)` returns an empty array on no match, best match first **(D)**.

Measured on this Mac **(V)** (`swiftc` one-off, `NSWorkspace.shared`):

| Identifier | `urlForApplication` result |
|---|---|
| `com.apple.Safari` | `/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app` (cryptex path, not `/Applications/Safari.app`) |
| `com.google.Chrome`, `org.mozilla.firefox`, `net.whatsapp.WhatsApp`, `com.tinyspeck.slackmacgap` | `/Applications/<Name>.app` |
| `com.apple.WebKit.Networking`, `.GPU`, `.WebContent` | **nil** (a system-framework `.xpc` at `/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/`, not LS-registered as an app) |
| `com.apple.curl`, `com.apple.git-remote-http`, `com.apple.mDNSResponder` | **nil** (no bundle) |
| `com.google.Chrome.helper` | the nested `.../Google Chrome Framework.framework/.../Helpers/Google Chrome Helper.app` |
| `com.google.Chrome.helper.renderer`, `org.mozilla.plugincontainer`, `com.todesktop.230313mzl4w4u92.helper.Renderer` | **nil** (nested helper not registered) |
| `com.tinyspeck.slackmacgap.helper`, `com.anthropic.claudefordesktop.helper`, `org.whispersystems.signal-desktop.helper` | the nested helper app inside `Slack.app` / `Claude.app` / `Signal.app` |
| `com.microsoft.VSCode.helper` | two candidates (`Code Helper.app`, `Code Helper (Plugin).app`) |
| `com.raycast.macos` | nil: Raycast is not installed on this Mac, so the installed case is unverified **(U)** |

So LaunchServices has a partial route: when a helper bundle is registered, its URL sits inside
the owner, and the **outermost `.app` ancestor** is the owner. Registration is inconsistent
(Chrome's `.helper` resolves, `.helper.renderer` does not), so a resolver also needs a fallback.
A dotted-prefix strip (drop trailing components, stop before a two-component `com.vendor`)
recovered, **(V)**: `com.google.Chrome.helper.renderer` -> Chrome (via `.helper`);
`com.todesktop.230313mzl4w4u92.helper.Renderer` -> Cursor; `com.openai.codex.helper` -> `ChatGPT.app`
(via `com.openai.codex`); `com.apple.Safari.SandboxBroker` -> Safari. It stays nil for
`org.mozilla.plugincontainer`, `org.mozilla.firefox-gpu-helper`, `com.apple.WebKit.*`,
`com.apple.SafariPlatformSupport.Helper`, so those need an owner map.

Helper identifiers read from bundles on this Mac **(V)** (`defaults read .../Info CFBundleIdentifier`):

| App | Helper ids (all `LSUIElement=1` unless noted) |
|---|---|
| Chrome 156 | `com.google.Chrome.helper` (plain, GPU, Aperitif variants), `com.google.Chrome.helper.renderer`, `com.google.Chrome.framework.AlertNotificationService`, `com.google.GoogleUpdater` |
| Electron (Slack, Claude, Signal, VS Code) | `<appid>.helper` (shared by Helper, Renderer, GPU, Plugin) |
| Cursor (Electron) | `<appid>.helper`, `.helper.Renderer`, `.helper.GPU`, `.helper.Plugin` |
| Firefox | `org.mozilla.plugincontainer`, `org.mozilla.firefox-gpu-helper`, `org.mozilla.firefox-media-plugin-helper` (inside `Contents/MacOS/*.app`); the main `org.mozilla.firefox` |
| Safari | app `com.apple.Safari`; own XPC `com.apple.Safari.SandboxBroker`, `.ContentBlockerLoader`, ...; web stack is system `com.apple.WebKit.{Networking,GPU,WebContent}` |

Electron-builder default helper ids are `${appId}.helper`, `.helper.EH`, `.helper.NP`,
`.helper.Renderer`, `.helper.GPU`, `.helper.Plugin` **(W)** (electron.build `MacConfiguration`, via search).

**What the NE actually reports.** First-hand NE observations in the repo are the spike's
`sourceApp` values: `com.apple.curl`, `com.apple.Safari` (flow to `alive.github.com`),
`com.apple.git-remote-http`, `aitm-7728c895773169c7`, `com.openai.codex.helper`
(`docs/research/experiments/2026-10-29-macos-ne-spike.md` lines 55-64). No repo evidence shows
the NE reporting `com.apple.WebKit.Networking`; the sibling branch's `knownSourceApps` assumes
it **(U)**. What is verified: the `WebKit.Networking` process is **shared, one instance per host
app**. `NSRunningApplication` on this Mac lists `com.apple.WebKit.Networking` with
`localizedName` "Safari Networking" (pid 2391), "Mail Networking" (2484), "textunderstandingd
Networking" (4750) **(V)**; the same for `WebContent`/`GPU`. Apple DTS calls this the
"responsibility problem": "there's virtually no API surface for that infrastructure"; the only
route it names is an Endpoint Security client's `responsible_audit_token` (forum thread 739414,
Oct 2023 **(W)**). A firewall project reasons that `sourceAppAuditToken` is the "source application"
while `sourceProcessAuditToken` (macOS 13+, filter side only) is the socket creator (freesnitch #159,
Oct 2026 **(W)**, speculation, "not done yet"). `responsibility_get_pid_responsible_for_pid`
exists in libSystem on this Mac (`dlsym` non-nil **(V)**) but is private/undocumented **(U)**.
Consequence: a static `com.apple.WebKit.Networking -> Safari` map would mislabel Mail and every
other WebKit host if the NE ever reports that id. Without a pid or audit token the honest
label is "WebKit networking (shared)"; with a pid, `NSRunningApplication(processIdentifier:).localizedName`
names the host (the BandPeek project does exactly this, requiring the "<App> Networking" shape **(W)**,
github.com/churntechnologies/bandpeek PR 12).

### Q2. Signing identifier vs bundle identifier

Doc **(D)** (`.../neflowmetadata/sourceappsigningidentifier.json`): "For all apps that are signed in
the standard way using Xcode, this value is identical to the app's bundle identifier." Research 12
adds the header text: "almost always equivalent", "may be empty ... system process".

Measured `codesign -dv` **(V)**:

| Binary | Signing identifier |
|---|---|
| Safari, Chrome helper, Slack helper, Firefox, Ghostty, iTerm, zoom.us, Aitmproxy.app | equals the bundle id (`com.google.Chrome.helper`, `us.zoom.xos`, `com.mrbrutti.aitmproxy`, ...) |
| `/usr/bin/curl`, `ssh`, `zsh`, `mDNSResponder`, `trustd` | `com.apple.curl`, `com.apple.ssh`, `com.apple.zsh`, ... (Apple-signed, reverse-DNS, no bundle) |
| `/usr/bin/git`, `/usr/bin/python3` | **`com.apple.dt.xcode_select.tool-shim-public`** (the shim, same id for both tools) |
| Homebrew `node` (ad-hoc) | `node-5555494418ec1ba832083c9e9b4530af295cdd9b` |
| `cargo-nextest` (rustc linker-signed) | `cargo_nextest-15fbe60dbbdd586c` |
| freshly compiled test binary (ad-hoc, linker-signed) | `t` (no hex suffix) |
| bundled core `aitm` | `aitm` (Developer ID); an ad-hoc dev build of the core was seen as `aitm-7728c895773169c7` (spike) |

Differences to expect: ad-hoc and linker-signed binaries take the file name plus a hex suffix
(no dots, so the sibling's "last dotted component" rule would show the whole
`node-5555...` string **(V)**, since the rule only strips on `.`); the xcode-select shim hides which
tool ran; empty for some system processes (research 12). Unsigned Mach-O cannot run on Apple
Silicon, so "unsigned" in practice means ad-hoc **(U)**.

### Q3. `icon(forFile:)` vs `icon(forFileType:)` vs `NSRunningApplication.icon`

| API | Doc **(D)** | Measured **(V)** |
|---|---|---|
| `NSWorkspace.icon(forFile:)` | "initial size of 32 pixels by 32 pixels"; "safely call from any thread" | Returns a **new `NSImage` each call** (`===` false); `size` 32x32 pt; 32 `NSISIconImageRep`s: 16/32/64/128/256/512/1024 pt, each at 1x and 2x pixels (16 pt has 16 px and 32 px reps). Mutating `size` on one copy does not leak into the next call. Warm call 262 us; first call over 75 apps 0.49 ms each; 8 threads x 75 paths off main: all OK. Nonexistent path and `/usr/bin/curl` return a generic image, never nil |
| `icon(forFileType:)` | **Deprecated macOS 12**, use `icon(for: UTType)`; 32x32 initial size, any thread | Not needed; `icon(for: .unixExecutable)` gives the generic executable icon (returns a default icon on failure, macOS 11+) |
| `NSRunningApplication.icon` | `NSImage?`, no discussion; class is thread safe but time-varying props follow the main run loop | Same 32 pt/32-rep shape; **same instance on repeated reads** of one `NSRunningApplication`; nil when the app is not running or has no bundle (every property is optional **(D)**); `NSRunningApplication` is `NS_SWIFT_SENDABLE` in the SDK header |

Threading **(D)** (Apple Threading Programming Guide, archived 2014): `NSBundle`/`NSFileManager`
are thread-safe; `NSImage` is "generally not thread-safe ... use from only one thread at a time",
but "One thread can create an `NSImage` object, draw to the image buffer, and pass it off to the
main thread for drawing". `NSView` descendants are main-thread only. Code that returns an
`NSImage` from an `actor` to a `@MainActor` function typechecks clean under `-swift-version 6` on
this SDK **(V)** (`Package.swift` is tools 6.2).

Sizing: one image per request is cheap but not free (262 us warm), so cache per owner in the app
(a dictionary keyed by owner bundle path; icons seldom change). Because each call returns a fresh
instance, setting `size = 16x16` (or 32 for a 2x row) on the cached copy is safe. SwiftUI
`Image(nsImage:).resizable().frame(16)` and AppKit draw pick the 16 pt rep at 1x and the 32 px rep at 2x
from the rep list above (rep selection itself not visually inspected **(U)**). Do not rely on the
default 32 pt size for 16 pt cells.

### Q4. Display name

| Source | Safari | Chrome | Firefox | Teams | VS Code | zoom.us | WhatsApp |
|---|---|---|---|---|---|---|---|
| `Bundle.object(forInfoDictionaryKey: "CFBundleDisplayName")` (localized-aware) | Safari | Google Chrome | none | none | Code | **Zoom** | `U+200E` + WhatsApp |
| `infoDictionary["CFBundleName"]` (raw) | Safari | **Chrome** | Firefox | Microsoft Teams | Code | zoom.us | WhatsApp |
| `localizedInfoDictionary["CFBundleDisplayName"]` | Safari | none | none | none | none | Zoom | LRM WhatsApp |
| `FileManager.displayName(atPath:)` / `.localizedNameKey` | `Safari.app` | `Google Chrome.app` | `Firefox.app` | `Microsoft Teams.app` | **`Visual Studio Code.app`** | `Zoom.app` | `WhatsApp.app` |
| `NSRunningApplication.localizedName` (running only) | Safari | Google Chrome | Firefox | n/a | n/a | n/a | n/a |

All **(V)**. Docs **(D)**: `Bundle.object(forInfoDictionaryKey:)` "returns the localized value of a key
when one is available" and is "preferred over other access methods"; `CFBundleDisplayName` is "the
user-visible name ... if you want a product name that's longer than `CFBundleName`"; `CFBundleName`
"can contain up to 15 characters" and is the fallback "if `CFBundleDisplayName` isn't set";
`FileManager.displayName(atPath:)` "may also reflect ... the removal of filename extensions"
and returns the path unchanged on error. `NSRunningApplication.localizedName` is "dependent on the
current localization".

Traps: (a) `displayName(atPath:)` and `localizedNameKey` returned `Safari.app` on this Mac because
`AppleShowAllExtensions` = 1; the result follows a Finder setting, so strip a trailing `.app`
yourself and never use it first. (b) WhatsApp's name carries a leading U+200E (LRM); the sibling's
`withoutControlAndBidi` already strips it, and must run on this path too. (c) CFBundleName
can be a short form ("Chrome"). (d) Display names differ from file names (VS Code "Code" vs "Visual
Studio Code"); both are legitimate, choose one rule. (e) A Setapp-distributed app was not available
to test **(U)**; Setapp apps are ordinary bundles with their own `CFBundleIdentifier`, so the same path
applies (not verified).

### Q5. Fallback for identifiers with no bundle

- Proxyman: docs do not describe how Apps-list icons are chosen. The Network Extension page, post
  (2026-10-06) and "can't see traffic" page mention only "0 apps and 0 domains" and cURL captured
  "without the --proxy flag" **(W)** (proxyman.com/docs/advanced-features/network-extension). The changelog
  has "Add app details popover for client domains to show the codesign, bundle ID, and app path"
  (6.14.0, 2026-07-23) and "Fixed sidebar icon colors on macOS 27" (6.15.0) **(W)** (proxyman.com/changelog).
  "Generic glyph for CLI tools" is the brief's observation, not a documented fact **(U)**.
- Charles: shows the client process only as text in a request's Notes area (Client Process tool),
  no icon **(W)** (charlesproxy.com/documentation/tools/client-process/).
- Little Snitch 6.2.1 attributes helper processes to the parent app **(W)** (via research 12, secondary).

Glyph availability **(V)** (`CoreGlyphs.bundle/name_availability.plist` on this Mac): `terminal` (SF Symbols 2020,
macOS 11.0), `apple.terminal` (2023, macOS 14.0), `app.dashed` (macOS 12), `questionmark.app.dashed`
(macOS 12); all inside the macOS 26 floor. The repo already follows a flat monochrome icon rule (memory
`aitmproxy-ui-icon-editorial-rule`), which a template-rendered symbol satisfies; the existing `Monogram`
disc is the alternative. A monogram on an unknown id (`t`, `node-5555...`) tells the user nothing, while
a terminal glyph is wrong for a closed-source GUI whose id simply is not installed. By id alone the
app cannot tell a CLI from an uninstalled GUI; a hex suffix or a missing dot only suggests a CLI (heuristic **(U)**).

### Q6. Threading and sandbox

- App entitlements: `apps/mac/Aitmproxy.entitlements` has only the NE `app-proxy-provider-systemextension`,
  `system-extension.install`, `application-identifier`, `team-identifier`. **No `com.apple.security.app-sandbox`**;
  confirmed on the installed build with `codesign -d --entitlements` **(V)**. Non-NE dev builds carry none.
  `build.sh` signs with `--options runtime` (hardened runtime) only; `EmbeddedObscura.entitlements` is JIT for
  obscura. Hardened runtime does not restrict reading other bundles **(U)**, and Info.plist has no sandbox key.
- Reading `/Applications`, `/System/Applications`, the Preboot cryptex Safari path worked from an
  unsandboxed CLI **(V)**. The app is the same class of process. Apps in TCC-protected folders
  (`~/Downloads`, `~/Desktop`, `~/Documents`) could raise a consent prompt on a `Bundle(url:)` read **(U)**, untested.
- Off-main use: `urlForApplication`, `icon(forFile:)` are documented any-thread **(D)**; 8 background threads ran
  clean **(V)**; `Bundle`/`FileManager` documented thread-safe **(D)**. Only the `NSImage` object and views need care.
- Resolution must run in the app (it has the user's LaunchServices database). The sysex is root and sees every
  user's flows (research 12), and cannot call these APIs for the GUI user **(U)**; apps from another user's home
  would not resolve in the active user's LS database **(U)**.
- Sibling code to build on: `ClientInfo(sourceApp:)` keeps the raw id in `bundleID`, which is what the resolver
  needs; `ClientInfo` already has an unused `pid: Int32?`. `AppMark` (`SidebarView.swift:235`) uses only
  `NSRunningApplication.runningApplications(withBundleIdentifier:)`, so it shows an icon only for running
  apps with that exact id (Safari yes, curl and helpers no). `FlowCellView` Client cell
  (lines 97-102, `MonogramView` at 318) never looks up an icon at all.

## 4. Candidate directions (not decisions)

Recommended resolution order for the string-only wire (candidate A):

1. Reject empty; sanitize for display (existing strip). Memoize the whole result per id.
2. `urlForApplication(withBundleIdentifier: id)`; if found, owner = outermost `.app` ancestor of the URL.
3. Small owner map for ids LS cannot resolve and where the owner is known: `org.mozilla.plugincontainer`,
   `org.mozilla.firefox-gpu-helper`, `org.mozilla.firefox-media-plugin-helper` -> Firefox. Do **not** map
   `com.apple.WebKit.*` to Safari (shared, see Q1); label it "Safari and other WebKit apps" or "WebKit Networking".
4. Dotted-prefix strip to a registered app, minimum three components.
5. No bundle: name from the id (strip `-<hex>` ad-hoc suffix and the xcode-select shim id), glyph `terminal`.

Name from the owner bundle: `object(forInfoDictionaryKey: "CFBundleDisplayName")`, then `"CFBundleName"`,
then file name minus `.app`; sanitize. Icon: `icon(forFile: ownerPath)`, copy, set `size`, cache in a
resolver actor; the view reads the cached image synchronously and re-renders when the resolver publishes.

| Direction | For | Against |
|---|---|---|
| A. Bundle-id-only resolver (above), no wire change | Small, fully off-main, unit-testable with injected closures; covers Safari, Chrome, Electron, most named apps | Shared WebKit helper, xcode-select shim and `-hex` ids stay generic; the owner map goes stale |
| B. Carry the audit-token pid (and pidversion) in `FlowOpen`; resolve in app by `NSRunningApplication(processIdentifier:)`, `proc_pidpath_audittoken` | Names WebKit hosts ("Mail Networking") and shim tools; `ClientInfo.pid` already exists | Wire and extension change; pid is dead after the flow, so resolve at flow open; cross-user flows (research 12); the sysex runs as root |
| C. A plus B only when A returns shared/ambiguous | Keeps the common path cheap | Two paths to test |
| D. Monogram only (status quo), plus the real icon for running apps | No new risk | Does not meet the Proxyman-parity goal |

SF Symbol `terminal` is the candidate fallback (macOS 11); `apple.terminal` (macOS 14) is a more
Apple-flavoured alternative. A monogram stays valid for ids that look like an app but did not resolve.

## 5. Open questions

1. Does the NE report `com.apple.WebKit.Networking` for Safari/Mail traffic, or the host app id? The spike saw
   `com.apple.Safari`; the sibling assumes the former. Needs a live capture with Safari **and** Mail logging both
   `sourceAppSigningIdentifier` and the audit-token pid.
2. Is `sourceAppAuditToken` always present and does its pid match the socket owner or the responsible app?
   (research 12 marks this unverified; `sourceProcessAuditToken` is filter-only.)
3. Display-name policy: "Code" (bundle) or "Visual Studio Code" (file name)? Product call.
4. TCC prompts when reading bundles under `~/Downloads`/`~/Desktop`; needs a run on a signed build.
5. Icon cache invalidation (app update, icon change): key by path plus bundle mtime, or listen to
   `NSWorkspace` launch notifications? Untested.
6. Setapp/Raycast not installed here, so their ids and helper shapes are unverified.
7. What `localizedName` does a user see for an XPC helper whose own bundle is the only record (for example
   `com.apple.SafariPlatformSupport.Helper` shows "AutoFill (Safari)" per process)? Only reachable with a pid.

## 6. Sources

- developer.apple.com `.../documentation/appkit/nsworkspace/{urlforapplication(withbundleidentifier:), urlsforapplications(withbundleidentifier:), icon(forfile:), icon(forfiletype:), icon(for:), icon(forfiles:)}`, `appkit/nsrunningapplication` (+ `/icon`, `/localizedname`), `appkit/nsimage`, `foundation/filemanager/displayname(atpath:)`, `foundation/bundle/object(forinfodictionarykey:)`, `bundleresources/information-property-list/{cfbundledisplayname,cfbundlename}`, `networkextension/neflowmetadata/sourceappsigningidentifier` (all `/tutorials/data/...json`, 2026-10-31)
- Apple Threading Programming Guide, Thread Safety Summary (archive, 2014) https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/Multithreading/ThreadSafetySummary/ThreadSafetySummary.html
- Apple Developer Forums thread 739414 (DTS "responsibility problem") https://developer.apple.com/forums/thread/739414
- freesnitch issue 159 https://github.com/isaaclins/freesnitch/issues/159 ; BandPeek PR 12 https://github.com/churntechnologies/bandpeek/pull/12
- Proxyman: https://proxyman.com/docs/advanced-features/network-extension , https://proxyman.com/posts/2026-10-06-introducing-network-extension , https://proxyman.com/changelog
- Charles Client Process tool https://www.charlesproxy.com/documentation/tools/client-process/
- electron-builder helper ids https://www.electron.build/docs/api/electron-builder.interface.macconfiguration/ (search summary only)
- Repo: `apps/mac/Sources/Aitmproxy/Shell/SidebarView.swift`, `.../FlowTable/FlowCellView.swift`, `apps/mac/Aitmproxy.entitlements`, `apps/mac/build.sh`, `apps/mac/Package.swift`, `docs/research/experiments/2026-10-29-macos-ne-spike.md`, branch `fix/ne-source-app` `AitmproxyKit/Flow.swift`, branch `claude/heuristic-pare-835491` `docs/research/12-macos-observe-only-lane.md`
- Local checks (2026-10-31, throwaway `swiftc` programs in `$TMPDIR`, `codesign -dv`, `defaults read`, `CoreGlyphs` plist): all rows marked **(V)**
