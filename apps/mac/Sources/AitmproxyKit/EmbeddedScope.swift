import Foundation

/// The **embedded** core's persisted operator scope only (`store/scope.json`, beside
/// `pins.json`): JSON `{"hosts": [...]}`, pretty-printed with sorted keys like `Pins`.
/// The app writes it after an operator Scope action (add/remove) and reads it at
/// every embedded spawn to emit the per-launch config's `scope:` block. It is never
/// written in fixture mode or for an external core, and the bus has no verb for it,
/// so no agent can read or widen it.
public struct EmbeddedScope: Codable, Hashable, Sendable {
    public var hosts: [String]

    public init(hosts: [String] = []) {
        self.hosts = hosts
    }

    /// `store/scope.json` — beside `pins.json`.
    public static func url(in store: URL) -> URL {
        store.appending(path: "scope.json")
    }

    /// Missing, unreadable, or undecodable → empty. Hosts pass through `sanitized`:
    /// load is the single validation point for what may reach the emitted config.
    public static func load(from url: URL) -> EmbeddedScope {
        guard let data = try? Data(contentsOf: url),
              let decoded = try? JSONDecoder().decode(EmbeddedScope.self, from: data) else {
            return EmbeddedScope()
        }
        return EmbeddedScope(hosts: sanitized(decoded.hosts))
    }

    /// Pretty + sortedKeys, creates the directory, writes atomically. Unlike `Pins`,
    /// atomic: a crash mid-write must not leave a truncated file that loads as empty
    /// and silently wipes the scope at the next launch.
    public func save(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(self).write(to: url, options: .atomic)
    }

    /// Trim `.whitespacesAndNewlines`, drop what `isPersistable` rejects, drop later
    /// duplicates (the first occurrence wins); order kept.
    public static func sanitized(_ hosts: [String]) -> [String] {
        var seen = Set<String>()
        var kept: [String] = []
        for raw in hosts {
            let host = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard isPersistable(host), seen.insert(host).inserted else { continue }
            kept.append(host)
        }
        return kept
    }

    /// `Scope.validate(host) == nil` AND no newline or control character. The second
    /// clause exists because `Scope.validate` accepts `"bad\nhost.test"`; without it a
    /// tampered file would make `Config.yaml()` throw on every spawn and wedge the
    /// embedded core in a restart loop.
    public static func isPersistable(_ host: String) -> Bool {
        Scope.validate(host) == nil
            && host.rangeOfCharacter(from: .newlines.union(.controlCharacters)) == nil
    }

    /// Whether `Session.init` seeds `scopeHosts` from the file before the bus connects:
    /// only for the embedded core, only when a bundled core is actually present, never
    /// in fixture mode. The app passes in the three facts; the Kit reads no defaults.
    public static func seedsAtLaunch(activeKind: ActiveCoreKind, bundledCorePresent: Bool, usesFixtures: Bool) -> Bool {
        !usesFixtures && activeKind == .embedded && bundledCorePresent
    }
}
