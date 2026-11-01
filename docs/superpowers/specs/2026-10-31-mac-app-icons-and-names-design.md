# macOS app icons and display names for clients design

**Status:** approved — self-approved 2026-10-31 (Matt pre-approved this work in autonomous mode; see docs/research/MEMORY.md); amended 2026-11-01 (self-approved, autonomous mode): stage-6 fix pass on docs PR #242 (see Amendments)
**Research inputs:** `docs/research/21-macos-app-icon-resolution.md` (facts table, resolution order, open questions); `docs/research/experiments/2026-10-29-macos-ne-spike.md` (the `sourceApp` values the NE really reports); live observation 2026-10-31, apps-attribution session, provider log of the installed extension (see "What the extension sends" below); Matt's acceptance picture 2026-10-31, a Proxyman screenshot with its extension on (see "The acceptance picture"); sibling spec `docs/superpowers/specs/2026-10-31-ne-source-app-on-the-wire-design.md` (PR B, branch `fix/ne-source-app`, D5)
**Builds on:** PR B — `FlowSummary.sourceApp` and `FlowRow.client = ClientInfo(sourceApp:)` (`apps/mac/Sources/AitmproxyKit/FlowSummary.swift`, `Flow.swift`), merged as PR #195 `3fe92f66` and released in v0.5.9; PR #196 (`5eac2a50`) for `Shell/SidebarView.swift` and `Bus/BusService.swift`; the design is against `main 8e19c2e3`. **Ships second** from this branch, after the traffic-route plan's PR (plan gate 4)
**Prefix for criteria:** AI-AC

## Intent

Everywhere the macOS app names the client behind a flow it shows the app's real icon and its display name, the way Proxyman does: the sidebar's Apps group lists one expandable row per app, each opening to the domains that app talked to; the Client column of the flow table on every page (including the Apps page's drill-down) shows the same mark and name; the Overview "Clients" breakdown, the Inspector origin line, the palette subtitle and exports carry at least the name. Today the sidebar shows an icon only for an app that is running with that exact bundle id (`Shell/SidebarView.swift:230-234`), the table never shows one (`FlowTable/FlowCellView.swift:97-105`), Apps rows do not expand, and the name is the last dotted component of the signing identifier (PR B's Kit rule), which reads `Networking`, `helper`, or `node-5555…` for real traffic. One resolver, one cache, every surface; a generic process mark only for processes that resolve to no app bundle; the raw identifier always one hover away.

## What the extension sends (live observation 2026-10-31, apps-attribution session, provider log)

Measured on Matt's Mac from the installed extension's provider log, so the design rests on it rather than on the spike alone:

- Safari's own flows arrive as `app = com.apple.Safari` (a TCP flow to example.com:80 and the UDP/QUIC :443 flow), **not** `com.apple.WebKit.Networking`. The direct `urlForApplication(withBundleIdentifier:)` lookup therefore resolves Safari; PR B's `knownSourceApps["com.apple.WebKit.Networking"] = "Safari"` is not what Safari sends here and nothing in this design relies on it.
- Identifiers with no dot and no bundle are common, not an edge case: `a.out` (an ad-hoc binary), `codex`, plus Apple daemons `com.apple.usbmuxd`, `com.apple.identityservicesd`, `com.apple.AMPDeviceDiscoveryAgent`, and `com.apple.curl`. The no-bundle path (D2 step 7, D9) is a first-class path and gets the same test weight as the app path.

## The acceptance picture (Matt, 2026-10-31, Proxyman with its extension on)

What the finished sidebar and list must read like:

- Group **Apps** with a count (distinct apps). One row per app with the real icon and display name — "Proxyman", "claude", "Codex (Service)", "Claude Helper", "dataaccessd", "codex" — each **expandable** to the domains that app talked to ("api.anthropic.com"; "chatgpt.com", "chat.openai.com"; …), each domain sub-row with the generic host mark and its flow count. Selecting an app narrows to it; selecting a domain under an app narrows to app ∧ domain.
- Daemons and processes without a bundle ("dataaccessd") carry a generic process mark and their process name.
- Service helpers carry a "(Service)" suffix ("Codex (Service)").
- The separate **Domains** group stays flat with its count, unchanged.
- The Client column shows the same icon + name as the app's sidebar row; the identifier is in the tooltip.

Where this spec deviates from the picture it says so (D2 service rule: "Claude Helper" would read "Claude (Service)" here).

## Goals

- A flow from Safari shows Safari's icon and "Safari"; from Google Chrome's network helper (`com.google.Chrome.helper`) Chrome's icon and "Google Chrome (Service)"; from `curl` the process mark and "curl"; from `com.apple.dataaccessd` the process mark and "dataaccessd"; from a Homebrew ad-hoc `node-5555…` the process mark and "node".
- The Apps group shows the count of distinct apps; each app row shows its flow count and expands to its domains, each with a flow count; selecting a domain under an app narrows the list to that app's flows to that host.
- The same icon and name appear in the sidebar Apps rows, the pinned-app rows and the table's Client column; the same name appears in Overview, Inspector, palette and CSV.
- Hovering an Apps row or a Client cell shows the raw signing identifier.
- Grouping, pinning and narrowing are keyed by the identifier, never by the display name: two apps that happen to share a name stay two groups; one app is one group; the Apps group count equals the number of distinct identifiers. Proxied flows with no client stay out of Apps (unchanged).
- Nothing stalls: resolution runs off the main thread, the poll loop never waits for it, results are cached per owner app with a bound.
- Proven on the real installed app with real traffic, and by Kit tests over test-local literal data; nothing else.

## Non-goals

- Carrying a pid or audit token on the wire to name shared system helpers (research 21 direction B). `ClientInfo.pid` stays unused.
- Any change to the core, the NE provider, `flow.get`, or the Kit's wire decode (`FlowSummary.swift`) and `ClientInfo(sourceApp:)` rule (`Flow.swift`). Those files are not touched.
- Merging helper identifiers into their owner's group. Groups stay per identifier; a "(Service)" row sits beside its owner's row (D2, D5). See Open questions.
- Nesting under the Domains group (domain → apps); Domains stays flat.
- Keyboard navigation of the sidebar beyond what exists (KIT "focused / keyboard" TODO); the disclosure is a button, so Full Keyboard Access reaches it.
- Persisting expanded state across launches.
- Icons in the Overview bars, the Inspector origin line, the palette or HAR/CSV; an identifier column in CSV.
- Invalidating a cached icon when an app updates mid-session (research 21 OQ5); the cache lives for the process.
- Changes to the filter language (`client:` keeps matching the shown name).
- A migration of existing `pins.json` entries (see D7).
- Web UI and TUI.

## Anti-goals

- Wrong attribution: a Mail flow labelled "Safari" because a shared WebKit service was mapped statically. research 21 Q1 shows `com.apple.WebKit.Networking` is one process per host app; without a pid the honest label is the service's own name.
- A display name that splits or merges groups, pins or narrowing differently from the identifier.
- A primary label that hides the identifier with no way to see it.
- A main-thread stall or a slower poll loop (one `icon(forFile:)` is ~262 µs warm, ~0.5 ms cold; a dozen apps on the first poll would be a visible hitch on main).
- A flash of a wrong mark: the process mark shown for an app whose verdict is still pending.
- An expanded app whose domain counts do not add up to the app's count, or a domain sub-row that narrows to the host across all apps.
- Discs, capsules or glass behind an icon; hard-coded sizes or colours in views (`apps/mac/CLAUDE.md`, `design/KIT.md` "Flat minimal icons").
- Two ways to resolve: a view that looks up icons its own way (today's `NSRunningApplication` path in `AppMark`).

## Constraints

- **Sequencing and file claims.** PR B is on `main` (PR #195, `3fe92f66`; released in v0.5.9) and PR #196 is `5eac2a50`; the files this spec cites are read on `main 8e19c2e3`. Two PRs ship from this branch: the traffic-route plan's PR **first**, this one second — its Tasks 5/6 edit `Session.swift` and `Bus/BusService.swift` only after that plan's Tasks 2/2b, never concurrently (plan gate 4). `AitmproxyKit/Flow.swift` and `AitmproxyKit/FlowSummary.swift` are the NE session's files and are **not edited** by this change (D3 keeps Kit's rule as the no-bundle fallback and adds everything else in new files).
- **No new dependencies.** Foundation, AppKit, SwiftUI only. `AitmproxyKit` stays free of AppKit and SwiftUI (`apps/mac/CLAUDE.md` Layout).
- **Platform.** macOS 26 floor (`Package.swift` `.macOS(.v26)`), Swift tools 6.2 with strict concurrency. SF Symbol `terminal` (macOS 11) is inside the floor.
- **Threading.** `NSWorkspace.urlForApplication(withBundleIdentifier:)`, `icon(forFile:)`, `Bundle` and `FileManager` are documented any-thread (research 21 Q3/Q6). `NSImage` objects are created off-main and handed to the main actor once; views read only the main-actor cache. The poll loop (`Bus/BusService.swift:139-180`) performs no awaited work for identity: a cache read and, on a miss, a scheduled lookup.
- **Bounded cache.** Identities capped at 512 identifiers, icons at 128 owner bundles, plus a 4096-entry `seen` set of identifiers resolved once (stage-6 S-M1); oldest evicted first, an overwrite refreshes. An eviction never changes a name already applied to a row (rows carry their name); an evicted identifier is re-resolved only by a visible read, never by the poll loop.
- **Evidence rule (Matt, 2026-10-31, verbatim: "STOP USING THE FAKE DATA UI TESTS").** The mac app's fixture and sample-data modes are being deleted by a dedicated session (the fixture store flag and environment switches, the Kit fixture files, the snapshot and scene files, the fixture self-test and their shell wrappers). **That removal PR lands first; this branch rebases once onto its SHA before coding starts.** This spec references none of those modes, as evidence, as a gate, or as implementation; Kit unit tests construct their own `ClientInfo` / `FlowRow` values. Proof is exactly: (1) Kit unit tests of pure logic (Swift Testing, literal expected values, test-local data); (2) the three source tripwires `tools/check-capture-operator-only.sh`, `tools/check-capture-toggle.sh`, `tools/check-connection-words.sh`; (3) the real app — the installed notarized build with its embedded core and the extension on (the only build whose extension activates, `apps/mac/CLAUDE.md`) — with real traffic from Safari, `curl` and a third Mac app, screenshots of that, and the bus read (`flow.table` / `flow.get` over the operator token, never printed) proving what the UI shows. To make (1) reach as far as possible, the per-app host list, the pin mapping for groups and the cache's eviction policy are pure Kit types (D1, D4).
- **Design rules.** Sizes from `Tok.Size` (`icon` 16, `iconInline` 12), spacing from `Space` (4-pt grid: the three sidebar insets are 12, 28, 52), ink from `Tok.Ink`, glyphs from `Tok.Glyph` via `docs/design/tokens.json` → `swift tools/gen-tokens.swift` (never hand-edit `UI/Tokens.swift`). The builder still runs the source checks that survive the fixture removal (`tools/grid-lint.sh`, the three `tools/check-*.sh`) and looks at the real app in light and dark; only the tripwires and the real-app proof count as evidence (Evidence rule). "Keyboard actions never animate" (KIT Motion): the disclosure does not animate.
- **Entitlements.** The app is not sandboxed (research 21 Q6); reading other bundles' `Info.plist` and icons needs no entitlement. A TCC prompt for an app living under `~/Downloads`/`~/Desktop`/`~/Documents` is possible and untested; the live proof (AI-AC20) watches for it.

## Design

### D1. Two layers: pure rules in the Kit, AppKit resolution in the app

**(Architect's call)** The identifier rules that need no AppKit live in a new Kit file and are unit-tested; the LaunchServices/icon lookup lives in a new app-target file and is proven on the real app. One resolver instance serves every surface.

New Kit file `apps/mac/Sources/AitmproxyKit/AppIdentifier.swift`:

```swift
public enum AppIdentifier {
    /// The identifier, then its dotted prefixes down to three components, longest first.
    public static func candidates(for identifier: String) -> [String]
    /// `node-5555…` → `node`: an identifier with no `.` whose tail is `-` + 16 or more lowercase hex digits loses the tail.
    public static func trimmedAdHoc(_ identifier: String) -> String
    /// The name shown when no bundle resolves: `knownUnbundled`, else `trimmedAdHoc`, else `ClientInfo.displayName(forSourceApp:)`.
    public static func fallbackName(for identifier: String) -> String
    /// A bundle-supplied name made safe to show: Cc/Cf scalars removed, whitespace trimmed, a trailing `.app` dropped, at most 64 characters; nil when nothing printable is left.
    public static func sanitized(_ name: String) -> String?
    /// True when a bundle path is an XPC service, login item or helper: contains `/XPCServices/`, `.xpc/` (or ends in `.xpc`), `/Contents/Library/LoginItems/`, or `/Helpers/`.
    public static func isServicePath(_ path: String) -> Bool
    /// `name` + " (Service)"; the 64-character cap applies to `name` before the suffix.
    public static func serviceLabel(_ name: String) -> String
    /// Identifiers that are never an app of their own and have an honest name: shared WebKit services and the xcode-select shim.
    public static let knownUnbundled: [String: String]
    /// Helper identifiers LaunchServices cannot resolve whose owner is known.
    public static let ownerMap: [String: String]
    /// Caps on what LaunchServices is asked about (stage-6 S-I1): over either, `candidates` is `[]`.
    public static let maxIdentifierBytes: Int        // 256 UTF-8 bytes
    public static let maxIdentifierComponents: Int   // 8 dotted parts
    /// Most characters an identifier tooltip shows (stage-6 S-M3); the same figure by choice.
    public static let maxTooltipCharacters: Int      // 256
    /// The identifier for a tooltip: Cc/Cf removed, capped, no trimming (D10).
    public static func tooltipText(_ identifier: String) -> String
}

public extension ClientInfo {
    /// What groups, pins and narrowing key on: the identifier when there is one, else the name.
    var groupKey: String { bundleID ?? name }
    /// The same client with the resolved display name (and the monogram that follows it); identifier and pid unchanged. Returns self when the name is already that.
    func withResolvedName(_ name: String) -> ClientInfo
}

/// The sidebar's Apps tree, computed from rows (pure, so it is unit-tested with literal rows).
public enum ClientTree {
    /// One entry per distinct `groupKey`, most flows first, then by name: what `Session.clients` returns.
    public static func clients(in rows: [FlowRow]) -> [(ClientInfo, Int)]
    /// The authorities the app with `key` talked to, most flows first, then by host.
    public static func hosts(forClient key: String, in rows: [FlowRow]) -> [(String, Int)]
}

public extension Pins {
    /// `.host` and `.clientHost` pin the host; `.client` pins the key.
    mutating func pin(_ group: FlowGroup)
    mutating func unpin(_ group: FlowGroup)
    func contains(_ group: FlowGroup) -> Bool
}

/// Insertion-ordered dictionary that drops its oldest entry past `capacity` (the resolver's two caches).
public struct BoundedCache<Key: Hashable, Value> {
    public init(capacity: Int)
    public subscript(key: Key) -> Value? { get set }
    public var count: Int { get }
}
```

- `candidates`: an identifier over `maxIdentifierBytes` (256 UTF-8 bytes) or `maxIdentifierComponents` (8 dotted parts) → `[]`, never asked of LaunchServices (stage-6 security S-I1: the identifier is signer-chosen and unbounded off the wire — a 64 KiB all-dot id would otherwise cost ~2 GiB of prefix strings and 65k IPCs); otherwise split on `.`; fewer than three components → `[identifier]`; else the identifier followed by each prefix with ≥ 3 components, longest first. `com.google.Chrome.helper.renderer` → `["com.google.Chrome.helper.renderer", "com.google.Chrome.helper", "com.google.Chrome"]`; `com.apple.Safari.SandboxBroker` → `[…, "com.apple.Safari"]`; `com.apple.curl` → `["com.apple.curl"]`; `aitm` → `["aitm"]`; `.hidden` → `[".hidden"]`. Three components minimum stops the walk before a vendor prefix (`com.google`) that could match an unrelated registration.
- `tooltipText`: the identifier for a tooltip — Cc/Cf scalars removed (bidi overrides included, the one `withoutControlAndFormat` filter `sanitized` also uses), capped at `maxTooltipCharacters` (256) characters, no trimming and no `.app` rule (stage-6 security S-M3; D10). `com.evil.x\u{202E}irafaS.elppa.moc` → `com.evil.xirafaS.elppa.moc`.
- `trimmedAdHoc`: regex `^(.+)-([0-9a-f]{16,})$` on identifiers containing no `.`; else unchanged. `node-5555494418ec1ba832083c9e9b4530af295cdd9b` → `node`; `cargo_nextest-15fbe60dbbdd586c` → `cargo_nextest`; `aitm-7728c895773169c7` → `aitm`; `t` → `t`; `aitm` → `aitm`; `codex` → `codex`; `com.apple.curl` → unchanged (has a dot, and then rule 3 gives `curl`). `a.out` has a dot: `candidates` gives `["a.out"]` (two components), LaunchServices finds nothing, and rule 3 shows `out` — accepted (live observation: `a.out` is a throwaway compile; the tooltip shows `a.out`).
- `knownUnbundled` **(Architect's call)** = `com.apple.WebKit.Networking` → `WebKit Networking`, `com.apple.WebKit.GPU` → `WebKit GPU`, `com.apple.WebKit.WebContent` → `WebKit WebContent`, `com.apple.dt.xcode_select.tool-shim-public` → `developer tool`. The WebKit entries are a guard, not the Safari path: the extension reports Safari as `com.apple.Safari` (live observation 2026-10-31), so these ids are expected rarely if ever, and when one does arrive the resolver must never label a shared service as any one host (anti-goal 1) and need not ask LaunchServices for it; the shim entry because `tool-shim-public` names nothing (research 21 Q2). Daemons seen live (`com.apple.usbmuxd`, `com.apple.identityservicesd`, `com.apple.AMPDeviceDiscoveryAgent`, `com.apple.dataaccessd`) are **not** tabled: rule 3 already gives `usbmuxd`, `identityservicesd`, `AMPDeviceDiscoveryAgent`, `dataaccessd` with the process mark, which is honest and matches the picture. Lowercase `developer tool` follows the CLI casing rule 3 produces (`curl`, `python3`).
- `ownerMap` = `org.mozilla.plugincontainer`, `org.mozilla.firefox-gpu-helper`, `org.mozilla.firefox-media-plugin-helper` → `org.mozilla.firefox` (research 21 Q1: nested inside `Contents/MacOS`, not LS-registered, dotted strip cannot reach the owner). No `com.apple.WebKit.*` entry, ever.
- `sanitized`: filter Unicode general categories `.control` and `.format` (the same categories PR B's private `withoutControlAndBidi` uses; `Flow.swift` is not edited, so the six lines are repeated here and a Kit test pins both to the same output), trim whitespace and newlines, drop one trailing `.app`, keep the first 64 characters, nil if empty. `"\u{200E}WhatsApp"` → `WhatsApp` (research 21 Q4 trap b); `"Visual Studio Code.app"` → `Visual Studio Code`; `"\u{202E}"` → nil.
- `isServicePath`: `/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper.app` → true; `/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc` → true; `/Applications/Slack.app/Contents/Library/LoginItems/Slack Helper.app` → true; `/Applications/Example.app/Contents/XPCServices/Example Service.xpc/Contents/MacOS/Example Service` → true (the `.xpc/` clause; the fourth path AI-AC5 counts); `/Applications/Safari.app`, `/Applications/Google Chrome.app` → false.
- `withResolvedName` is `ClientInfo(name: name, bundleID: bundleID, pid: pid)` (the init recomputes the monogram), returning `self` when `name == self.name` so a settled row never changes value.
- `ClientTree.clients` replaces today's `Session.clients` body (`Session.swift:343` on `main 8e19c2e3`, which grouped by `ClientInfo` value) with the `groupKey` grouping above (I-2 ruling 2026-11-01, D4); `Session.clients` becomes a one-line call (Task 5). `ClientTree.hosts(forClient:in:)` counts `authority` over rows whose `client?.groupKey == key`.
- `Pins.pin/unpin/contains(_ group:)` carry the mapping `Session.pin/unpin/isPinned` do today (`Session.pin` :393, `unpin` :400, `isPinned` :408 on `main 8e19c2e3`) plus the new case; `Session` delegates.
- `BoundedCache` evicts the oldest key when a new key would exceed `capacity`; overwriting an existing key refreshes it to newest (a re-resolved identity is the last to go — architect ruling 2026-11-01 on the Task 2 stop-and-report: AI-AC12's literal values are the oracle; the earlier "does not change its age" sentence contradicted them).

New app file `apps/mac/Sources/Aitmproxy/UI/AppIdentity.swift`:

```swift
/// One identifier's verdict. `icon == nil` ⇔ `bundleURL == nil` ⇔ no app bundle (the process-mark case).
struct AppIdentity: Equatable {
    let identifier: String
    let name: String        // display name, with " (Service)" already appended when isService
    let icon: NSImage?      // a 16 × 16 pt copy, isTemplate false, shared per owner bundle
    let bundleURL: URL?     // the outermost .app (the owner)
    let isService: Bool     // D2 step 5
}

@MainActor @Observable
final class AppIdentityResolver {
    static let shared: AppIdentityResolver
    /// Bumped on every new verdict; SwiftUI views that read `identity(for:)` re-render through it.
    private(set) var version: Int
    /// The cached verdict, or nil while unknown; a miss schedules one off-main lookup per identifier.
    func identity(for identifier: String) -> AppIdentity?
    /// Registers a one-shot main-actor callback for an identifier still pending (AppKit cells).
    func onResolve(_ identifier: String, _ body: @escaping @MainActor (AppIdentity) -> Void)
    /// Blocking lookup on the calling thread; the background task calls it, nothing on the main actor does.
    func resolve(_ identifier: String) -> AppIdentity
    /// `client.withResolvedName(...)` from the cache; the client unchanged on a miss or when it has no identifier.
    /// A miss schedules a lookup only for an identifier never resolved in this process (`seen`); an evicted one
    /// is re-resolved by a visible `identity(for:)` read, so the poll loop never storms (stage-6 S-M1).
    func enriched(_ client: ClientInfo) -> ClientInfo
    // Storage: `BoundedCache<String, AppIdentity>(capacity: 512)` by identifier and
    // `BoundedCache<String, NSImage>(capacity: 128)` by owner bundle path; `BoundedCache<String, Bool>(capacity: 4096)` `seen`.
}
```

Exact concurrency shape (actor vs detached task vs serial queue) is the builder's, under these rules: one in-flight lookup per identifier; lookups run off the main actor; verdicts are stored and `version` bumped on the main actor; `identity(for:)` and `enriched(_:)` never block.

### D2. Resolution order and the service rule (per identifier, memoised)

research 21 §4 candidate A, written as the rule:

1. `knownUnbundled[id]` → verdict `(name: table value, icon: nil, bundleURL: nil, isService: false)`. Stop.
2. `lookup = ownerMap[id] ?? id`.
3. For each `AppIdentifier.candidates(for: lookup)`: `NSWorkspace.shared.urlForApplication(withBundleIdentifier:)`; the first non-nil URL is the **hit**, and the candidate that produced it is the **matched id**.
4. Owner = the outermost path component ending in `.app` on the hit (so `…/Google Chrome.app/Contents/Frameworks/…/Helpers/Google Chrome Helper.app` → `Google Chrome.app`); if none, the hit itself.
5. **Service rule (Architect's call, the coordinator's definition made exact).** `isService` is true when any of: (a) the hit is not the owner (resolved through the outermost-`.app` walk); (b) `AppIdentifier.isServicePath(hit.path)`; (c) `ownerMap` was used; (d) the matched id is not `id` itself (the identifier is not a registered bundle; only a prefix of it is). Otherwise false.
6. Name, first that `sanitized` accepts, read from the **owner**: `Bundle(url: owner).object(forInfoDictionaryKey: "CFBundleDisplayName") as? String`, then `"CFBundleName"`, then the owner's last path component; if none sanitises, `AppIdentifier.fallbackName(for: id)` (stage-6 SP-M3, Task 4 deviation (d)); then `serviceLabel` when `isService`. **(Architect's call)** `CFBundleDisplayName` first because Apple documents it as the user-visible name and it is what Safari/Chrome/Zoom/WhatsApp carry (research 21 Q4); the consequence is `Code` rather than `Visual Studio Code` and `Zoom` rather than `zoom.us`. `FileManager.displayName(atPath:)` is never used (follows the Finder's extension setting). The owner's name rather than the helper bundle's own (`Claude Helper`, `Code Helper (Plugin)`, `Google Chrome Helper (GPU)`) because the owner is what the user recognises and one vocabulary — owner name, optionally "(Service)" — holds across vendors; this is the one place the spec deviates from the picture ("Claude Helper" reads "Claude (Service)" here).
7. Icon = `NSWorkspace.shared.icon(forFile: owner.path)`, one copy per owner path with `size = NSSize(width: Tok.Size.icon, height: Tok.Size.icon)` and `isTemplate = false`, cached by owner path so every helper of an app shares one image.
8. No hit from step 3 → verdict `(name: AppIdentifier.fallbackName(for: id), icon: nil, bundleURL: nil, isService: false)`.

Literal examples (install-dependent names are what the owner's `Info.plist` says on that Mac; research 21 Q1/Q4 values given):

| Identifier | Hit | Owner | Name |
|---|---|---|---|
| `com.apple.Safari` | `Safari.app` | same | `Safari` |
| `com.google.Chrome` | `Google Chrome.app` | same | `Google Chrome` |
| `com.google.Chrome.helper` | nested `Google Chrome Helper.app` | `Google Chrome.app` | `Google Chrome (Service)` (5a, 5b) |
| `com.google.Chrome.helper.renderer` | via candidate `.helper` → nested helper | `Google Chrome.app` | `Google Chrome (Service)` (5a, 5b, 5d) |
| `com.apple.Safari.SandboxBroker` | via candidate `com.apple.Safari` → `Safari.app` | same | `Safari (Service)` (5d) |
| `com.openai.codex.helper` | via candidate `com.openai.codex` → that app's bundle (ChatGPT.app on the research Mac; Codex.app where the Codex desktop app owns the id) | same | `<owner> (Service)` — `Codex (Service)` on a Codex.app install, which is the picture's row (5d) |
| `com.tinyspeck.slackmacgap.helper` | nested helper inside `Slack.app` | `Slack.app` | `Slack (Service)` (5a) |
| `org.mozilla.plugincontainer` | via `ownerMap` → `Firefox.app` | same | `Firefox (Service)` (5c) |
| `com.apple.WebKit.Networking` | step 1 | — | `WebKit Networking`, process mark |
| `com.apple.dataaccessd`, `com.apple.usbmuxd`, `com.apple.curl` | none | — | `dataaccessd`, `usbmuxd`, `curl`, process mark |
| `codex`, `a.out`, `node-5555…` | none | — | `codex`, `out`, `node`, process mark |

Two different helper identifiers of one owner (`.helper`, `.helper.renderer`) are two groups both labelled `Google Chrome (Service)`; the tooltip tells them apart. A "(Service)" row sits beside its owner's row in the Apps list, ordered by count like every row; nothing is merged.

The whole verdict is cached by identifier; there is one lookup routine (`resolve`) and no second code path.

### D3. Where the name is applied: at row entry, by the poll loop **(Architect's call)**

Option (a) from the brief, chosen over view-level lookups:

- In `Bus/BusService.swift` the per-row transform that today is `scoped(_:)` (lines 164-168) gains one step: `row.client = row.client.map(AppIdentityResolver.shared.enriched)`. Both the polled rows (line 169) and the restored rows (line 172) pass through it, so an Undo-Clear row is named like any other. This is the only edit to `BusService.swift`.
- Consequence: `ClientInfo.name` is the display name (including "(Service)") on every live row, so every Kit consumer follows without edits — the `client:` filter (`FilterMatching.swift:374`), the Client sort (`FlowSort.swift:61`), the Overview tile (`Panels/Overview.swift:60`), the palette subtitle (`Session+Palette.swift:70`), the Inspector origin (`Inspector/InspectorView.swift:460`), CSV (`Transfer.swift:131`).
- On a cache miss the row keeps Kit's name for one poll (or, for an identifier evicted after being resolved once, until a visible mark re-reads it — stage-6 S-M1); the next poll's rows differ (`FlowRow ==` covers `client`, `Flow.swift:275`), so `session.rows` updates and every surface repaints. All rows of one identifier are enriched from the same cache in the same poll, so a group never straddles two names.
- Rows that never pass the poll loop (an imported session) keep the name they carry; views still fetch their mark by identifier from the same cache, so the icon arrives on first sight (D8).
- Why not (b): a name looked up only in views would leave filters, sort, Overview, palette, Inspector and CSV on the raw-derived name, and the sidebar filter would match text the user cannot see. Why not enrich in the Kit: the Kit cannot see LaunchServices.

The icon is **not** on `ClientInfo` (no AppKit in the Kit); views fetch it by `client.bundleID` from the same cache (D5, D6).

### D4. Groups, keys and the nested app ∧ domain group

`FlowGroup` (`AitmproxyKit/FlowQuery.swift:4-7`) gains a third case **(Architect's call: a case, not a two-part struct — every switch stays exhaustive and the host/client cases keep their meaning)**:

```swift
public enum FlowGroup: Hashable, Sendable {
    case host(String)                        // authority, any app
    case client(String)                      // group key, any host
    case clientHost(client: String, host: String)  // group key ∧ authority
}
```

`FlowQuery.Compiled.apply` (`FlowQuery.swift:55-59`): `.client(key)` → `$0.client?.groupKey == key`; `.clientHost(key, host)` → `$0.client?.groupKey == key && $0.authority == host`; `.host` unchanged.

`Session` (`Session.swift`):

```swift
/// Group keys of the Apps rows currently showing their domains. Session-only, never persisted.
var expandedApps: Set<String> = []
var clients: [(ClientInfo, Int)] { ClientTree.clients(in: rows) }
func hosts(forClient key: String) -> [(String, Int)] { ClientTree.hosts(forClient: key, in: rows) }
func toggleExpanded(_ key: String)
```

`show(_:group:)` (`Session.swift:388` on `main 8e19c2e3`): when `group` is `.client(key)` or `.clientHost(key, _)` it also inserts `key` into `expandedApps` **(Architect's call: selecting an app opens it; collapsing is explicit via the chevron; collapsing a selected app keeps the selection and the narrowing)**. `pin`/`unpin`/`isPinned` (`:393`/`:400`/`:408`) delegate to `Pins.pin/unpin/contains(_ group:)`: `.clientHost(_, host)` behaves as `.host(host)` — a domain under an app is a host pin. `unpin` clears `self.group` when it equals the unpinned group, as today.

| Thing | Today | After |
|---|---|---|
| `Session.clients` group (`Session.swift:343`) | `ClientInfo` hash (name + monogram + bundleID + pid) | **amended 2026-11-01 (Tester I-2 ruling):** grouped by `groupKey`, the group's `ClientInfo` being the first row's (the same first-row rule as `OverviewBreakdowns.clients`), so an imported row and a live row sharing one identifier under two names make ONE Apps row and the AI-AC20 invariant holds; the earlier "still the `ClientInfo` value" wording let two names split one identifier |
| Apps count (`SidebarView.swift:30`) | `session.clients.count` | unchanged: distinct apps |
| App row narrowing (`FlowGroup.client`) | the name | the **group key** `client.groupKey` (= `bundleID ?? name`) |
| Domain-under-app narrowing | — | `.clientHost(client: key, host: authority)`; count = that app's flows to that host; the counts under an app sum to the app's count |
| Pin key (`Pins.apps`, `FlowQuery.swift:60-62`) | the name | the group key; `apply` matches `apps.contains($0.client?.groupKey)`. Pinning a domain under an app pins the host (`Pins.hosts`) |
| Sidebar text filter (`SidebarView.swift:14-17,32`) | app name substring | app name, group key, **or any of the app's hosts**; while querying, a matching app shows expanded with only its matching hosts **(Architect's call)** |
| `client:` filter expression | name | name (display name now) — unchanged code |
| Client column sort | name | name — unchanged |
| Overview "Clients" count (`Overview.swift:60`) | distinct names | distinct group keys (equals `session.clients.count`) |
| Overview "Clients" bars (`OverviewBreakdowns.swift:61-65`, app view `:32-41`) | grouped by name, action `.client(name)` | grouped by group key; `ClientCount` gains `key`; label `name`, `.help(AppIdentifier.tooltipText(key))`, action `.client(key)` |
| Pinned-app sub-row title (`SidebarView.swift:51-54`) | the stored string | the display name of the current client whose `groupKey` equals the stored key, else the stored key as-is (an old or stale pin stays visible and unpinnable) |

A client with no identifier (an imported row) keys on its name, so nothing that exists today changes meaning.

### D5. Sidebar (`Shell/SidebarView.swift`)

Apps block (lines 30-38) becomes, per visible client (most flows first, as `session.clients` orders):

- **App row** (replaces `subItem(.client(name) …)` at line 35): anatomy `[chevron 12 in a 16 frame at inset 12] [gap 0] [ClientMark 16 at inset 28] [gap Space.sm] [title] [spacer] [count]`, height `Tok.Size.control`, selection fill `Tok.Ground.active` when `session.page == .apps && session.group == .client(key)`. The chevron is `Image(systemName: Tok.Glyph.chevron)` in `Tok.Ink.tertiary`, rotated 90° when `expandedApps.contains(key)`, inside its own `Button` so a click toggles expansion **without** changing selection or narrowing; a click anywhere else on the row calls `session.show(.apps, group: .client(key))` (which also expands). No animation on the rotation. Tooltip `.help(AppIdentifier.tooltipText(client.bundleID ?? client.name))` on the row; the chevron button's accessibility label is "Expand <name>" / "Collapse <name>"; the row's accessibility label is `"<name>, <count> flows[, pinned], expanded|collapsed"` and it carries `.accessibilityAction(named: "Expand")`/`"Collapse"` so VoiceOver can toggle without the pointer. Context menu: Pin/Unpin App (unchanged).
- **Domain sub-rows**, shown when `expandedApps.contains(key)` (or while querying, the matching hosts): one per `session.hosts(forClient: key)`, `subItem(.clientHost(client: key, host: host), title: host, count: n, page: .apps, leadingInset: 52, mark: { Monogram(text: "◎") })` with leading inset **52** (`Monogram` for hosts stays; the mark is the generic host mark), selected when `session.group == .clientHost(key, host)`; context menu "Pin Host"/"Unpin Host" (D4: a host pin); accessibility label `"<host>, <n> flows[, pinned]"`. `.help(host)`.
- Selecting a domain sub-row calls `session.show(.apps, group: .clientHost(client: key, host: host))`.
- `AppMark` (lines 215-235) is replaced by `ClientMark(client: ClientInfo)` in `UI/AppIdentity.swift` (SwiftUI). It reads `AppIdentityResolver.shared.identity(for: client.bundleID ?? client.name)`:
  - verdict with icon → `Image(nsImage:)` `.resizable()` in a `Tok.Size.icon` square, `.accessibilityLabel(client.name)`;
  - verdict without icon → `Image(systemName: Tok.Glyph.process)` at `Tok.Size.iconInline`, `Tok.Ink.secondary`, centred in a `Tok.Size.icon` square;
  - nil (pending) → an empty `Tok.Size.icon` square. Never the process mark while pending (anti-goal).
  - A client with no identifier (an imported row) is resolved by its name, which yields the process mark everywhere.
- Pinned apps (lines 51-54): keyed by the stored key; title/mark/count from `session.clients.first { $0.0.groupKey == key }`; `.help(AppIdentifier.tooltipText(key))`; not expandable (Pinned is a flat list; the app's domains live under Apps).
- Domains block (lines 39-46) and pinned hosts (48-50): unchanged, flat, `Monogram("◎")`.
- `subItem` (lines 154-186) grows a `leadingInset` parameter (default 28) and takes a `ClientMark`/`Monogram` view rather than `(monogram, bundleID)`; the `noun` for `.clientHost` is "Host".

### D6. Flow table Client cell (`FlowTable/FlowCellView.swift`)

- `MonogramView` (lines 13, 47-50, 97-105, 232-234, 317-332) is retired from the Client cell and deleted; in its place a second `NSImageView` `clientIcon` with the same constraints (leading `pad`, 16 × 16, label leading 6 after it), `imageScaling = .scaleProportionallyUpOrDown`.
- `configure` for `.client`:
  - identity with icon → `clientIcon.image = icon` (non-template), tint untouched;
  - identity without icon → `NSImage(systemSymbolName: Tok.Glyph.process, accessibilityDescription: client.name)`, `symbolConfiguration` point size `Tok.Size.iconInline`, `contentTintColor` = `meta.nsColor` (secondary; tertiary on an out-of-scope row like the rest of the cell);
  - pending → `clientIcon.image = nil`, view visible (keeps the label's x position), and `resolver.onResolve(identifier) { [weak self] in … }` which re-applies the icon only if the cell still shows that identifier (cells are reused);
  - `label.stringValue = client.name` in the UI face as today — the same text as the app's sidebar row, "(Service)" included.
- `toolTip` (line 216) gains `.client`: the identifier (`client.bundleID ?? client.name`).
- Selection: `backgroundStyle` is pinned to `.normal` (lines 69-72) and `FlowRowView.isEmphasized` is pinned `true`, so AppKit never flips the real icon to a template or whitens the glyph; the Client cell on a selected row looks identical to an unselected one (AI-AC17 covers it live). The real icon is not dimmed on out-of-scope rows (an image has no ink); the glyph follows the cell's ink.
- Accessibility (`describeDrawnViews`): `clientIcon` is an image element labelled with `client.name` when visible, as the monogram was (S-069).

### D7. Pins **(Architect's call: no migration)**

`Pins.apps` holds group keys from now on; `Pins.hosts` is untouched and also receives pins made from a domain under an app. An app pinned before this change was stored by name; after it, such an entry matches only a client whose key is its name. It still appears under Pinned with its stored text and can be unpinned from the context menu. PR B is released (v0.5.9), so an operator may have pinned an NE-attributed app by name since; such a pin keeps matching a name-keyed client, stays listed and unpinnable, and is re-made by key with one click — accepted, no migration.

### D8. First sight of an identifier **(Architect's call: no warm-up)**

- There is no pre-resolution of any kind. The first time an identifier is seen the row shows Kit's name with a blank mark; the verdict lands within milliseconds (research 21: ~0.5 ms cold) and the mark appears through the cell callback or the sidebar's observation (D5, D6); the display name follows at the next poll (D3). A launch does no identity work until traffic arrives.
- This is visible only on the real app with real traffic and is accepted as one blank-then-icon step per app per launch; the live proof (AI-AC20) confirms no hitch.

### D9. The generic process mark: SF Symbol `terminal` **(Architect's call)**

One mark for every identifier that resolves to no bundle: SF Symbol `terminal`, regular weight, `Tok.Ink.secondary`, 12 pt in the 16 pt frame, token role `glyph.process`.

Why it reads as "process", not "command line": macOS's own generic icon for a bundle-less executable — what Finder and `NSWorkspace.icon(for: .unixExecutable)` show for `curl`, `dataaccessd` and `a.out` alike — is, from memory, a terminal window labelled `exec` (unverified: research 21 Q3/Q5 verified only that the call returns a generic image and that the `terminal` symbol exists); `terminal` is that mark in SF Symbol form, so the user who has seen a daemon in Finder recognises it. It is flat and monochrome (KIT rule 1) and says what is true for every case the extension has produced so far (CLI tools, ad-hoc binaries, Apple daemons). Rejected: `gearshape.2` reads as settings/system preferences; `app.dashed` reads as "an app that is missing", wrong for a daemon that was never an app; the raster `.unixExecutable` icon itself would be faithful but is not token-governed and mixes a system-styled raster into a column the design rule keeps flat for everything but real app icons. It is wrong only for a GUI app not installed for this user and for the shared WebKit services, where the text label (`WebKit Networking`) carries the honesty and the tooltip shows the identifier.

Token: add `"process": { "mac": "terminal", "web": "terminal", "tui": "$" }` to the `icon.glyph` table in `docs/design/tokens.json` and regenerate `UI/Tokens.swift` (`Tok.Glyph.process`). The row is additive; any other generator that consumes the glyph table must still pass its gate.

### D10. Surfaces, counts and tooltips **(Architect's call)**

| Surface | Shows |
|---|---|
| Apps group header | title + count of distinct apps |
| App row | icon/mark + name + flow count; tooltip identifier; disclosure |
| Domain under an app | `◎` + host + count of that app's flows to that host; tooltip host |
| Domains group and its rows | unchanged: flat, counts |
| Pinned apps / hosts | icon/mark or `◎` + name + current count; tooltip identifier / host |
| Flow table Client column, every page incl. Apps drill-down | icon/mark + name (same text as the app row); tooltip identifier |
| Overview "Clients" bars | name; `.help` identifier |
| Overview "Clients" tile | count of group keys |
| Inspector origin line, palette subtitle | name |
| CSV `client` column | name |

Icons stay out of the text parts (BarRow, HeaderTable) for now: three more kit parts for little gain; can follow.

Every tooltip that shows an identifier shows `AppIdentifier.tooltipText(identifier)` (stage-6 S-M3), never the raw `bundleID`.

### D11. Kit documentation

`design/KIT.md`: the "Monogram" part becomes "Client mark (`ClientMark`, `FlowCellView.clientIcon`)": 16 × 16 real app icon when the identifier resolves to a bundle, else the `terminal` process mark 12 in the 16 frame in `Ink.secondary`, blank while pending; the Monogram disc remains for host rows. Its TODO ("The real app icon replaces it …") closes. "Sidebar row" gains the app row anatomy (chevron at 12, mark at 28, domain sub-rows at 52) and the three insets. Flow row column text: "Client 96 (icon + name, ui face)". The gallery is gone with the fixture modes; the kit page is the documentation.

### D12. Files

| File | Change |
|---|---|
| `apps/mac/Sources/AitmproxyKit/AppIdentifier.swift` | new (D1) |
| `apps/mac/Tests/AitmproxyKitTests/AppIdentifierTests.swift` | new |
| `apps/mac/Sources/AitmproxyKit/FlowQuery.swift` | `FlowGroup.clientHost`; `apply` keys on `groupKey` (D4) |
| `apps/mac/Sources/AitmproxyKit/ClientTree.swift` | new: `ClientTree`, `Pins` group mapping, `BoundedCache` (D1) |
| `apps/mac/Tests/AitmproxyKitTests/ClientTreeTests.swift` | new |
| `apps/mac/Sources/AitmproxyKit/Panels/Overview.swift`, `Panels/OverviewBreakdowns.swift` | count/group by key; `ClientCount.key` |
| `apps/mac/Sources/AitmproxyKit/Pins.swift` | doc comment: `apps` holds group keys |
| `apps/mac/Sources/Aitmproxy/UI/AppIdentity.swift` | new: resolver + `ClientMark` |
| `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` | one step in the per-row transform |
| `apps/mac/Sources/Aitmproxy/Shell/SidebarView.swift` | D5: app rows with disclosure, domain sub-rows, `ClientMark`, tooltips |
| `apps/mac/Sources/Aitmproxy/FlowTable/FlowCellView.swift` | D6 |
| `apps/mac/Sources/Aitmproxy/Session.swift` | `expandedApps`, `clients`/`hosts(forClient:)` via `ClientTree`, `toggleExpanded`, `show` expands, pin/unpin/isPinned via `Pins` |
| `apps/mac/Sources/Aitmproxy/Panels/OverviewBreakdowns.swift` | key action, help |
| `docs/design/tokens.json` → `apps/mac/Sources/Aitmproxy/UI/Tokens.swift` | `glyph.process` |
| `apps/mac/design/KIT.md` | D11 |
| **Not touched** | `AitmproxyKit/Flow.swift`, `AitmproxyKit/FlowSummary.swift`, anything in `crates/`; nothing under the deleted fixture/snapshot modes |

## Acceptance criteria

Evidence classes per the Constraints: **K** = Kit unit test (Swift Testing, literal values, rows built in the test), **T** = source tripwire, **L** = the real app with real traffic and the bus read. Nothing else counts.

Kit (`swift test`, `Tests/AitmproxyKitTests/AppIdentifierTests.swift` and `ClientTreeTests.swift` unless noted):

1. **AI-AC1 (K)** `AppIdentifier.candidates(for:)`: `com.google.Chrome.helper.renderer` → `["com.google.Chrome.helper.renderer", "com.google.Chrome.helper", "com.google.Chrome"]`; `com.apple.Safari.SandboxBroker` → `["com.apple.Safari.SandboxBroker", "com.apple.Safari"]`; `com.apple.curl` → `["com.apple.curl"]`; `aitm` → `["aitm"]`; `.hidden` → `[".hidden"]`; `""` → `[""]`; a 257-byte identifier → `[]`; `a.b.c.d.e.f.g.h.i` (nine components) → `[]`; `"" + 65536 × "."` → `[]` (stage-6 S-I1). `AppIdentifier.tooltipText`: `com.evil.x\u{202E}irafaS.elppa.moc` → `com.evil.xirafaS.elppa.moc`; `" com.x.app "` → `" com.x.app "` (no trimming, no `.app` rule); 300 × `k` → 256 characters; 300 × `🇺🇸` → 256 characters (a flag is one character, two scalars) (stage-6).
2. **AI-AC2 (K)** `AppIdentifier.trimmedAdHoc`: `node-5555494418ec1ba832083c9e9b4530af295cdd9b` → `node`; `cargo_nextest-15fbe60dbbdd586c` → `cargo_nextest`; `aitm-7728c895773169c7` → `aitm`; `t` → `t`; `aitm` → `aitm`; `node-abc` → `node-abc` (too short); `node-5555494418EC1BA8` → unchanged (uppercase is not the linker's form); `com.example.x-0123456789abcdef` → unchanged (has a dot).
3. **AI-AC3 (K)** `AppIdentifier.fallbackName(for:)`: `com.apple.curl` → `curl`; `com.apple.git-remote-http` → `git-remote-http`; `node-5555494418ec1ba832083c9e9b4530af295cdd9b` → `node`; `codex` → `codex`; `a.out` → `out`; `com.apple.dataaccessd` → `dataaccessd`; `com.apple.usbmuxd` → `usbmuxd`; `com.apple.AMPDeviceDiscoveryAgent` → `AMPDeviceDiscoveryAgent`; `com.apple.WebKit.Networking` → `WebKit Networking`; `com.apple.dt.xcode_select.tool-shim-public` → `developer tool`; `obscura` → `obscura`; `"\u{202E}com.evil.app"` → `app` (same as `ClientInfo.displayName(forSourceApp:)`).
4. **AI-AC4 (K)** `AppIdentifier.sanitized`: `"\u{200E}WhatsApp"` → `"WhatsApp"`; `"  Zoom\n"` → `"Zoom"`; `"Visual Studio Code.app"` → `"Visual Studio Code"`; `"\u{202E}"` → nil; `""` → nil; 100 × `"x"` → 64 × `"x"`; and for `"\u{200E}Wh\u{0007}atsApp"` the result equals `ClientInfo.displayName(forSourceApp:)` of the same text (both category filters agree).
5. **AI-AC5 (K)** `AppIdentifier.isServicePath` and `serviceLabel`: the four true and two false paths listed in D1; `serviceLabel("Google Chrome") == "Google Chrome (Service)"`; `serviceLabel(70 × "x")` is 64 × `"x"` + `" (Service)"`.
6. **AI-AC6 (K)** `ClientInfo.groupKey`: `ClientInfo(sourceApp: "com.apple.Safari").groupKey == "com.apple.Safari"`; `ClientInfo(name: "curl").groupKey == "curl"`. `withResolvedName`: `ClientInfo(sourceApp: "com.google.Chrome.helper").withResolvedName("Google Chrome (Service)")` has `name == "Google Chrome (Service)"`, `monogram == "G"`, `bundleID == "com.google.Chrome.helper"`, `pid == nil`; calling it with the current name returns an equal value.
7. **AI-AC7 (K)** Grouping stability, rows built in the test: A (`com.google.Chrome` → "Google Chrome", host `a.example`), B (`com.google.Chrome.helper` → "Google Chrome (Service)", `a.example`), C (`com.google.Chrome` → "Google Chrome", `a.example`), D (`com.google.Chrome.helper.renderer` → "Google Chrome (Service)", `b.example`), E (`client == nil`, `c.example`): `ClientTree.clients(in:)` has exactly three entries with keys `com.google.Chrome` (2), `com.google.Chrome.helper` (1), `com.google.Chrome.helper.renderer` (1) in that order, names `Google Chrome`, `Google Chrome (Service)`, `Google Chrome (Service)`; E is in none (a proxied flow with no client stays out of Apps).
8. **AI-AC8 (K)** `ClientTree.hosts(forClient:in:)` over rows built in the test — X (`com.apple.Safari`, `example.com`) ×3, X to `www.apple.com` ×1, Y (`com.apple.curl`, `example.com`) ×2: `hosts(forClient: "com.apple.Safari")` == `[("example.com", 3), ("www.apple.com", 1)]`, the counts summing to Safari's `clients` count (4); `hosts(forClient: "com.apple.curl")` == `[("example.com", 2)]`; `hosts(forClient: "nobody")` == `[]`.
9. **AI-AC9 (K)** `FlowQuery` (`FlowQueryTests.swift`) with the rows of AI-AC7: `.client("com.google.Chrome")` → A, C; `.client("Google Chrome")` → nothing; `.clientHost(client: "com.google.Chrome.helper", host: "a.example")` → B only; `.clientHost(client: "com.google.Chrome", host: "b.example")` → nothing; `.host("a.example")` → A, B, C (unchanged meaning); `Pins(apps: ["com.google.Chrome.helper"])` → B only; `Pins(hosts: ["c.example"])` → E only.
10. **AI-AC10 (K)** `Pins` group mapping: from empty, `pin(.client("com.apple.Safari"))` → `apps == ["com.apple.Safari"]`, `hosts == []`; `pin(.clientHost(client: "com.apple.Safari", host: "example.com"))` → `hosts == ["example.com"]`, `apps` unchanged; `contains(.host("example.com"))`, `contains(.clientHost(client: "anything", host: "example.com"))`, `contains(.client("com.apple.Safari"))` all true; `contains(.client("Safari"))` false; `unpin(.clientHost(client: "x", host: "example.com"))` empties `hosts`; pinning twice stores once.
11. **AI-AC11 (K)** Overview (`OverviewTests.swift`, `OverviewBreakdownsTests.swift`) with the rows of AI-AC7: `OverviewStats(rows:).clients == 3`; `OverviewBreakdowns(rows:).clients` has three entries, names `Google Chrome`, `Google Chrome (Service)`, `Google Chrome (Service)` with keys `com.google.Chrome` (2), `com.google.Chrome.helper` (1), `com.google.Chrome.helper.renderer` (1).
12. **AI-AC12 (K)** `BoundedCache<String, Int>(capacity: 3)`: after inserting `a, b, c, d` → `count == 3`, `["a"] == nil`, `["d"] == 4`; overwriting `b` then inserting `e` evicts `c` (not `b`); `capacity: 512` after 600 distinct keys → `count == 512` and the last 512 keys present.

Source tripwires:

13. **AI-AC13 (T)** `tools/check-capture-operator-only.sh`, `tools/check-capture-toggle.sh`, `tools/check-connection-words.sh` PASS on the branch (the sidebar and Session edits add no capture control and no connection-state word).

Real app, real traffic (**L**; the installed notarized `--ne` build at `/Applications/Aitmproxy.app` with its embedded core — version from the Status page — capture on, `example.com` and `www.apple.com` in scope; the operator token read from the app's config, never printed; screenshots in the PR):

14. **AI-AC14 (L) Apps tree.** Traffic: Safari loads `https://example.com/` and `https://www.apple.com/`; a shell runs `curl https://example.com/` twice; Google Chrome loads `https://example.com/` (Firefox or Slack if Chrome is absent — name the one used). The sidebar Apps header shows the count of distinct identifiers the bus reports (expected 3, or 4 when Chrome's main process and its network helper both appear). Rows, screenshot: "Safari" with Safari's icon; "curl" with the process mark; "Google Chrome" and/or "Google Chrome (Service)" with Chrome's icon (the helper row beside the owner row, never merged); every row with a count and a collapsed chevron.
15. **AI-AC15 (L) Nesting and narrowing.** Clicking the Safari row selects it, turns its chevron and lists `example.com` and `www.apple.com` with counts summing to Safari's count (screenshot); the list shows only rows whose Client cell reads "Safari". Clicking `www.apple.com` under Safari narrows the list to rows that are all Safari ∧ `www.apple.com` (screenshot), while the flat Domains group still lists `example.com` with Safari's **and** curl's **and** Chrome's flows combined. Clicking the chevron alone collapses Safari without changing the selection or the list.
16. **AI-AC16 (L) Bus read agrees.** For one flow under each Apps row, `flow.get` over the operator token returns a `source_app` equal to the identifier in that row's tooltip (`com.apple.Safari`, `com.apple.curl`, `com.google.Chrome` / `com.google.Chrome.helper`), and the number of distinct `source_app` values over `flow.table` equals the Apps header count; flows with `source_app: null` (if any proxied traffic is present) belong to no Apps row. Output pasted in the PR with the token redacted.
17. **AI-AC17 (L) Client column and tooltip.** On Flows and on the Apps drill-down the Client cell of each row shows the same mark and text as its sidebar app row; hovering a Client cell and a sidebar app row shows the identifier (screenshots of both tooltips). A selected row's Client cell looks the same as an unselected one.
18. **AI-AC18 (L) Service row.** If Chrome's helper appears, its row reads "Google Chrome (Service)" with Chrome's icon, beside the "Google Chrome" row if that one is present too, and its tooltip shows `com.google.Chrome.helper` (or `.helper.renderer`); a Safari XPC service (`com.apple.Safari.*`) seen in the same read satisfies this as "Safari (Service)". If no helper or service identifier appears during the run, the PR states "no helper observed" with the `flow.table` output attached; the rule itself is covered by AI-AC5 and the labelling by AI-AC6/AI-AC7.
19. **AI-AC19 (L) Pins.** Pin Safari from its row's context menu: the Pinned group shows "Safari" with its icon and count; pin `www.apple.com` from under Safari: it appears among the pinned hosts (not the pinned apps) with `◎`; `pins.json` under the app's store lists `"com.apple.Safari"` under `apps` and `"www.apple.com"` under `hosts` (file contents in the PR).
20. **AI-AC20 (L) Hygiene.** No TCC prompt appeared during the run; the app's Status page and the flow list kept updating while the first resolutions happened (no visible hitch); the Overview "Clients" tile equals the Apps header count and the "Clients" bars carry the same names.
21. **AI-AC21 (L) Unbundled processes.** Any daemon or ad-hoc tool that produced in-scope flows during the run (`com.apple.dataaccessd`, `a.out`, …) shows the process mark and its rule-3 name; if none did, run a freshly compiled `a.out` that fetches `https://example.com/` and show its row reading "out" with the process mark and tooltip `a.out`.

Review and gates:

22. **AI-AC22** Poll loop unchanged in shape: the diff of `Bus/BusService.swift` adds no `await` and no synchronous lookup to `pollLoop`, only the cache-read step in the per-row transform (the Security and Quality reviewers confirm from the diff).
23. **AI-AC23** `swift test --package-path apps/mac --scratch-path ~/Library/Developer/Aitmproxy/test-build-icons` green; `swift tools/gen-tokens.swift` leaves no diff after the token row is in; `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` green (no Rust change, run anyway per the workflow).
24. **AI-AC24** `design/KIT.md` describes the client mark, the app row anatomy with its three insets, and the Client column as icon + name; the `Monogram` TODO is gone.

## Left to the builder

- The resolver's concurrency shape (actor, serial queue or detached tasks) within D1's rules; the eviction bookkeeping (an insertion-order array is enough).
- Whether `ClientMark` and the resolver share one file or two under `UI/`.
- How `FlowCellView` stores the identifier it currently shows for the `onResolve` check.
- How `subItem` is refactored to take a mark view and a leading inset (one function with parameters or two small functions).
- The exact `.help` text when a pinned key has no current client (the key itself is the requirement).
- Test placement: new `AppIdentifierTests.swift` and `ClientTreeTests.swift` plus additions to `FlowQueryTests`, `OverviewTests`, `OverviewBreakdownsTests`.
- Which third Mac app the live proof uses when Chrome is absent, provided it is one research 21 verified to resolve (Firefox, Slack, Signal, VS Code, WhatsApp, Zoom); the PR names it.
- How the live-proof screenshots are taken (`screencapture`, `tools/winshot.swift`).

## Open questions

None blocking; the status line is as instructed. Three product forks were defaulted (and one security gap recorded) and Matt may overturn them after the fact without unblocking the plan (both are table or key changes, not architecture):

1. **Helper merging.** This spec keeps one group per identifier, so `com.google.Chrome` and `com.google.Chrome.helper` are two Apps rows, "Google Chrome" and "Google Chrome (Service)", side by side. The picture also shows helpers as separate rows ("Codex (Service)" beside "codex", "Claude Helper" beside "claude"), so nothing in it requires merging. Merging would change `Session.clients`' key to the owner bundle id and is a follow-up spec if wanted.
2. **Service naming.** Owner name + "(Service)" for every indirect resolution (D2 step 6) rather than the helper bundle's own name; the picture's "Claude Helper" reads "Claude (Service)" here. Switching to the helper's own `CFBundleDisplayName` is a one-step change in D2.
3. **Display-name source.** `CFBundleDisplayName` first (`Code`, `Zoom`, `Google Chrome`) rather than the bundle file name (`Visual Studio Code`, `zoom.us`); research 21 OQ3 calls it a product call.
4. **Unverified signer (stage-6 security S-M2, follow-up).** The identifier is the connecting process's code-signing identifier, which any local binary sets (`codesign -s - -i com.apple.Safari.sync`); the prefix walk then lends it Safari's icon and "Safari (Service)". The tooltip's raw identifier is the only tell. Closing it needs the extension to derive the signer's team identifier from the flow's audit token (`SecCodeCopySigningInformation`) and send it beside `source_app`, with the resolver inheriting icon/name only when the owner bundle's team matches — an extension + core + Kit change, its own spec. Until then prefix-only (5d) verdicts are rendered like any other; recorded here so the limitation is known.

## Summary

The Kit gains a pure `AppIdentifier` (candidate prefixes, ad-hoc trimming, a tiny honest table for shared WebKit services and the xcode-select shim, service-path detection, name sanitising), `ClientInfo.groupKey`/`withResolvedName`, and a third `FlowGroup` case `clientHost` for app ∧ domain narrowing; the app gains one main-actor `AppIdentityResolver` that resolves an identifier off-main through LaunchServices to the outermost `.app`, labels indirect resolutions "(Service)", caches a 16 pt icon per owner and a verdict per identifier, and a `ClientMark` view. The poll loop's per-row transform applies the resolved name so every Kit consumer sees it; the sidebar's Apps rows carry the mark, the name, a count and a disclosure that opens to the app's domains with counts; the table's Client column shows the same mark and text; groups, pins and narrowing key on the identifier (`bundleID ?? name`), the tooltip shows it, and the `terminal` process mark marks anything with no bundle. Proof is Kit tests over test-local data (`ClientTree`, `Pins`, `BoundedCache`, `FlowQuery`, `AppIdentifier`), the three tripwires, and the real installed app with Safari, curl and Chrome traffic read back over the bus; no fixture or snapshot mode is referenced, and the branch rebases onto the fixture-removal PR before coding. `Flow.swift` and `FlowSummary.swift` are not touched.

### Architect's calls

1. Groups, pins and narrowing key on the identifier (`groupKey = bundleID ?? name`); helpers are not merged into their owner (open question 1); a "(Service)" row sits beside the owner's row.
2. App ∧ domain narrowing is a third `FlowGroup` case `clientHost(client:host:)`; expanded state is `Session.expandedApps: Set<String>` (session-only); selecting an app expands it, the chevron toggles without selecting; a domain under an app pins as a host.
3. Name applied at row entry in the poll loop (option a), icon fetched by views from the same cache; Kit's `ClientInfo(sourceApp:)` rule stays as the no-bundle fallback; no edits to the NE session's files.
4. Pure rules in a new Kit file `AppIdentifier.swift`; resolver + `ClientMark` in a new app file `UI/AppIdentity.swift`; `knownUnbundled` and `ownerMap` live in the Kit.
5. Resolution order D2; `CFBundleDisplayName` → `CFBundleName` → folder name, read from the owner; never `displayName(atPath:)`.
6. Service rule: indirect resolution in any form (nested hit, service path, ownerMap, prefix match) → owner name + " (Service)"; `com.google.Chrome.helper.renderer` → "Google Chrome (Service)", `com.apple.Safari.SandboxBroker` → "Safari (Service)".
7. `com.apple.WebKit.*` labelled `WebKit Networking`/`GPU`/`WebContent`, never a host app (a guard: live, Safari sends `com.apple.Safari`); the xcode-select shim labelled `developer tool`; daemons and ad-hoc tools get rule-3 names, not table entries.
8. Generic process mark is SF Symbol `terminal` (token `glyph.process`), argued as the symbol form of macOS's own `exec` icon; one state for every unbundled identifier; `MonogramView` leaves the Client cell; `Monogram` stays for hosts and domain sub-rows.
9. Blank mark while a verdict is pending; the cell re-applies via a one-shot callback, SwiftUI via the resolver's `version`.
10. One lookup routine, no warm-up, no fixed table; evidence is Kit tests over test-local data, the tripwires and the real installed app only (Evidence rule) — `ClientTree`, the `Pins` group mapping and `BoundedCache` are pure so the tests reach them.
11. Cache bounds 512 identifiers / 128 owner icons, oldest evicted; no invalidation on app updates.
12. Sidebar text filter matches app name, identifier or any of the app's hosts; `client:` filter, sort, Overview, Inspector, palette and CSV use the display name only; icons only in the sidebar and the table.
13. No `pins.json` migration; a stored key with no current client stays listed and unpinnable.
14. Name cap 64 characters after sanitising, before the "(Service)" suffix.

## Amendments after approval

- 2026-11-01 (stage-6 panel on PR #268, the Kit half; self-approved, autonomous mode): security S-I1 → `candidates` caps (`maxIdentifierBytes` 256, `maxIdentifierComponents` 8, `[]` over the cap) with AI-AC1 literals; S-M3 → `AppIdentifier.tooltipText` used by every identifier tooltip (D10); S-M1 → the resolver's `seen` set: the poll loop never re-resolves an evicted identifier, only a visible read does; S-M2 → Open question 4 (signer verification follow-up). Quality Q-I1 → the Overview bars read `ClientTree.clients`. Spec SP-I1/M3/M4 wording fixes.
- 2026-11-01 (Kit-half Tester I-2; architect ruling, self-approved): D4's `Session.clients` row — groups are keyed by `groupKey` with the first row's `ClientInfo`, not by the `ClientInfo` value; `ClientTree.clients(in:)` amended to match, pinned by a `ClientTreeTests` case.
- 2026-11-01 (orchestrator ruling at the start of implementation; self-approved, autonomous mode): branch `feat/mac-app-icons-and-names` off `main 681dff57` (PR #265 merged); gate 2 = `c3a4fd37` (#249), gate 4 = `681dff57`. **Folded in** (PR #265 quality Q10 follow-up): D9's token row gains two siblings, `glyph.network` (`network` / `network` / `⇅`) and `glyph.apps` (`app.badge` / `layout-grid` / `▦`), and `Shell/RouteBanner.swift` reads its two glyph literals from `Tok.Glyph.network` / `Tok.Glyph.apps` — rendered symbols unchanged; plan Task 4. Tasks 5/6 additionally wait for system-proxy PR 4 (owner of the `BusService` poll loop).
- 2026-11-01 (stage-6 fix pass on docs PR #242, spec + quality panel; self-approved, autonomous mode): base `main 8e19c2e3`; PR B recorded as merged (PR #195 `3fe92f66`, v0.5.9) and D7's "PR B is not released" corrected; `Session.swift` citations by symbol (`Session.clients` :343, `show(_:group:)` :388, `pin` :393 / `unpin` :400 / `isPinned` :408); D5's `subItem` call matches the plan's `@ViewBuilder mark:` signature (`mark: { Monogram(text: "◎") }`); the `exec` icon remark labelled unverified; AI-AC23's scratch path = the plan's (`test-build-icons`); PR shape stated: two PRs from this branch, traffic-route first, this second (plan gate 4; Tasks 5/6 after the traffic-route plan's Tasks 2/2b on the shared `Session.swift` / `BusService.swift`).
