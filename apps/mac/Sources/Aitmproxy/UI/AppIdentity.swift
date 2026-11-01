import AitmproxyKit
import AppKit
import SwiftUI

/// One identifier's verdict (spec 2026-10-31-mac-app-icons-and-names, D1/D2).
/// `icon == nil` ⇔ `bundleURL == nil` ⇔ no app bundle (the process-mark case).
struct AppIdentity: Equatable {
    let identifier: String
    /// The display name, with " (Service)" already appended when `isService`.
    let name: String
    /// A `Tok.Size.icon` square copy, `isTemplate` false, shared per owner bundle.
    let icon: NSImage?
    /// The outermost `.app` (the owner).
    let bundleURL: URL?
    /// D2 step 5.
    let isService: Bool
}

/// The one LaunchServices + icon resolver every surface reads (spec D1 app half, D2, D8). The
/// pure identifier rules are `AppIdentifier` in the Kit; this class owns the AppKit half: one
/// lookup per identifier, run off the main actor, its verdict stored here on the main actor.
/// Nothing on the main actor ever blocks on a lookup, and there is no warm-up (D8): the first
/// sight of an identifier schedules it, the verdict lands through `version` (SwiftUI) or an
/// `onResolve` callback (AppKit cells), and the display name follows at the next poll (D3).
@MainActor @Observable
final class AppIdentityResolver {
    static let shared = AppIdentityResolver()

    /// Bumped on every new verdict; SwiftUI views that read `identity(for:)` re-render through it.
    private(set) var version = 0

    /// Verdicts by identifier.
    @ObservationIgnored private var verdicts = BoundedCache<String, AppIdentity>(capacity: 512)
    /// One icon per owner bundle path, so every helper of an app shares one image (D2 step 7).
    @ObservationIgnored private var icons = BoundedCache<String, NSImage>(capacity: 128)
    /// Identifiers with a lookup scheduled and not yet stored: one in-flight lookup per identifier.
    @ObservationIgnored private var inFlight: Set<String> = []
    /// Identifiers resolved at least once. The poll loop's `enriched` never re-schedules one of
    /// these after `verdicts` evicted it (stage-6 security S-M1: past 512 distinct identifiers the
    /// poll would otherwise re-resolve the evicted ones every tick, forever); only a visible
    /// `identity(for:)` read does, so re-resolution is bounded by what is on screen.
    @ObservationIgnored private var seen = BoundedCache<String, Bool>(capacity: 4096)
    /// `onResolve` callbacks waiting for a verdict, by identifier.
    @ObservationIgnored private var pending: [String: [@MainActor (AppIdentity) -> Void]] = [:]
    /// `Tok.Size.icon`, read once here: the token is main-actor isolated (the app target's default
    /// isolation) and the lookup runs off the main actor, so it travels as a `nonisolated let`.
    nonisolated private let iconSide: CGFloat

    /// One resolver serves every surface (D1): only `shared` may be built.
    private init() {
        iconSide = Tok.Size.icon
    }

    /// The cached verdict, or nil while unknown; a miss schedules one off-main lookup per
    /// identifier. Reads `version` first so SwiftUI observation registers. Never blocks.
    func identity(for identifier: String) -> AppIdentity? {
        _ = version
        if let verdict = verdicts[identifier] { return verdict }
        schedule(identifier)
        return nil
    }

    /// Registers a one-shot main-actor callback for an identifier still pending (AppKit cells);
    /// fires at once when the verdict is already cached. Never blocks.
    func onResolve(_ identifier: String, _ body: @escaping @MainActor (AppIdentity) -> Void) {
        if let verdict = verdicts[identifier] {
            body(verdict)
            return
        }
        pending[identifier, default: []].append(body)
        schedule(identifier)
    }

    /// `client.withResolvedName(...)` from the cache; the client unchanged on a miss (which
    /// schedules the lookup) or when it has no identifier. Never blocks: the poll loop calls it
    /// per row (D3).
    func enriched(_ client: ClientInfo) -> ClientInfo {
        guard let identifier = client.bundleID else { return client }
        if let verdict = verdicts[identifier] { return client.withResolvedName(verdict.name) }
        if seen[identifier] == nil { schedule(identifier) }
        return client
    }

    /// Blocking lookup on the calling thread — D2 steps 1–8 in order, the one routine and no
    /// second path. The background task calls it; nothing on the main actor does.
    nonisolated func resolve(_ identifier: String) -> AppIdentity {
        // 1. A shared service or shim with an honest name is never asked of LaunchServices.
        if let name = AppIdentifier.knownUnbundled[identifier] {
            return AppIdentity(identifier: identifier, name: name, icon: nil, bundleURL: nil, isService: false)
        }
        // 2. A helper LaunchServices cannot resolve is looked up as its owner.
        let lookup = AppIdentifier.ownerMap[identifier] ?? identifier
        let ownerMapUsed = lookup != identifier
        // 3. The first candidate LaunchServices knows is the hit; the candidate is the matched id.
        //    An oversize identifier has no candidates (Kit cap) and falls through to step 8 untouched.
        var hit: URL?
        var matched = lookup
        for candidate in AppIdentifier.candidates(for: lookup) {
            if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: candidate) {
                hit = url
                matched = candidate
                break
            }
        }
        // 8. No hit: the Kit's fallback name and the process mark.
        guard let hit else {
            return AppIdentity(
                identifier: identifier, name: AppIdentifier.fallbackName(for: identifier),
                icon: nil, bundleURL: nil, isService: false)
        }
        // 4. The owner is the outermost `.app` on the hit's path, else the hit itself.
        let owner = Self.owner(of: hit)
        // 5. The service rule: (a) the hit is not the owner, (b) a service path, (c) the owner map
        //    was used, (d) only a prefix of the identifier is registered.
        let isService = hit.standardizedFileURL.path != owner.standardizedFileURL.path
            || AppIdentifier.isServicePath(hit.path)
            || ownerMapUsed
            || matched != identifier
        // 6. The owner's name: CFBundleDisplayName, CFBundleName, then its last path component,
        //    the first `sanitized` accepts; then the service label. `FileManager.displayName`
        //    is never used (it follows the Finder's extension setting).
        var name = Self.bundleName(of: owner) ?? AppIdentifier.fallbackName(for: identifier)
        if isService { name = AppIdentifier.serviceLabel(name) }
        // 7. A `Tok.Size.icon` square copy of the owner's icon for this identifier, never a template;
        //    `store` swaps it for the owner's shared image so every helper of one app shows one picture.
        let icon = Self.icon(forOwner: owner, side: iconSide)
        return AppIdentity(identifier: identifier, name: name, icon: icon, bundleURL: owner, isService: isService)
    }

    /// D2 step 4: `…/Google Chrome.app/Contents/Frameworks/…/Helpers/Google Chrome Helper.app`
    /// → `…/Google Chrome.app`; a hit with no `.app` component is its own owner.
    nonisolated private static func owner(of hit: URL) -> URL {
        let components = hit.pathComponents
        guard let index = components.firstIndex(where: { $0.hasSuffix(".app") }), index < components.count - 1
        else { return hit }
        let path = NSString.path(withComponents: Array(components[...index]))
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    /// D2 step 6, before the service label.
    nonisolated private static func bundleName(of owner: URL) -> String? {
        let bundle = Bundle(url: owner)
        for key in ["CFBundleDisplayName", "CFBundleName"] {
            if let raw = bundle?.object(forInfoDictionaryKey: key) as? String,
               let name = AppIdentifier.sanitized(raw) {
                return name
            }
        }
        return AppIdentifier.sanitized(owner.lastPathComponent)
    }

    /// D2 step 7: one `Tok.Size.icon` square copy of the owner's icon, `isTemplate` false.
    nonisolated private static func icon(forOwner owner: URL, side: CGFloat) -> NSImage? {
        guard let copy = NSWorkspace.shared.icon(forFile: owner.path).copy() as? NSImage else { return nil }
        copy.size = NSSize(width: side, height: side)
        copy.isTemplate = false
        return copy
    }

    /// One lookup per identifier: marks it in flight and runs `resolve` off the main actor, then
    /// hops back to store the verdict.
    private func schedule(_ identifier: String) {
        guard inFlight.insert(identifier).inserted else { return }
        Task.detached(priority: .utility) { [weak self] in
            guard let self else { return }
            let verdict = self.resolve(identifier)
            await self.store(verdict)
        }
    }

    /// Stores a verdict on the main actor: the icon is shared per owner path (the first copy for
    /// an owner wins, so every helper of one app shows the same image), `version` is bumped, and
    /// the identifier's pending callbacks fire once and are dropped.
    private func store(_ verdict: AppIdentity) {
        inFlight.remove(verdict.identifier)
        var stored = verdict
        if let owner = verdict.bundleURL, let icon = verdict.icon {
            let path = owner.path
            if let shared = icons[path] {
                stored = AppIdentity(
                    identifier: verdict.identifier, name: verdict.name, icon: shared,
                    bundleURL: owner, isService: verdict.isService)
            } else {
                icons[path] = icon
            }
        }
        verdicts[verdict.identifier] = stored
        seen[verdict.identifier] = true
        version += 1
        let callbacks = pending.removeValue(forKey: verdict.identifier) ?? []
        for body in callbacks { body(stored) }
    }
}

/// The client mark in the sidebar's app rows and the Pinned list (spec D5): the owner's icon when
/// the identifier resolves to a bundle, the process mark (`Tok.Glyph.process`, D9) when it does
/// not, and an empty square while the verdict is pending — never the process mark while pending.
/// No disc, no background. A client with no identifier is resolved by its name, which yields the
/// process mark.
struct ClientMark: View {
    let client: ClientInfo

    var body: some View {
        if let identity = AppIdentityResolver.shared.identity(for: client.bundleID ?? client.name) {
            if let icon = identity.icon {
                Image(nsImage: icon)
                    .resizable()
                    .frame(width: Tok.Size.icon, height: Tok.Size.icon)
                    .accessibilityLabel(client.name)
            } else {
                Image(systemName: Tok.Glyph.process)
                    .font(.system(size: Tok.Size.iconInline))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .frame(width: Tok.Size.icon, height: Tok.Size.icon)
            }
        } else {
            Color.clear.frame(width: Tok.Size.icon, height: Tok.Size.icon)
        }
    }
}
