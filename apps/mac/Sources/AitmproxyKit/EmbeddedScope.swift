import Foundation

/// The **embedded** core's persisted operator scope only (`store/scope.json`, beside
/// `pins.json`): JSON `{"hosts": [...]}`, pretty-printed with sorted keys like `Pins`.
/// The app writes it after an operator Scope action (add/remove) and reads it at
/// every embedded spawn to emit the per-launch config's `scope:` block. It is never
/// written for an external core, and the bus has no verb for it, so no agent can read
/// or widen it.
///
/// Caps (spec D1 amendments): `load` reads only a regular file — not a directory, a
/// FIFO or a symlink — of at most `maxFileBytes` (1 MiB); anything else loads empty.
/// `sanitized` drops a host longer than `maxHostLength` (1 024) characters and keeps
/// at most `maxHosts` (10 000) entries, the first ones in order. The read runs on the
/// main actor at launch and inside the core actor at every spawn, and the core seeds
/// its guard with a linear-scan de-dup, so the file must stay small and bounded.
/// `save` applies the same caps on the way out — it writes `sanitized(hosts)` and refuses
/// a file over `maxFileBytes` — so the file only ever holds what `load` keeps and a Scope
/// action can never persist a list that loads empty at the next launch.
public struct EmbeddedScope: Codable, Hashable, Sendable {
    /// `save` refused to write; the Scope action that asked for it reports this as the reason.
    public enum SaveError: Error, Equatable, LocalizedError {
        /// The pretty-printed file would exceed `maxFileBytes`, which `load` reads as empty.
        case tooLarge(bytes: Int)

        public var errorDescription: String? {
            switch self {
            case .tooLarge(let bytes): "scope.json would be \(bytes) bytes; the limit is \(EmbeddedScope.maxFileBytes)"
            }
        }
    }

    /// The largest `scope.json` that `load` reads and `save` writes, in bytes.
    static let maxFileBytes: UInt64 = 1_048_576
    /// The most hosts `sanitized` keeps.
    static let maxHosts = 10_000
    /// The longest host, in characters, that `sanitized` keeps.
    static let maxHostLength = 1_024

    public var hosts: [String]

    public init(hosts: [String] = []) {
        self.hosts = hosts
    }

    /// `store/scope.json` — beside `pins.json`.
    public static func url(in store: URL) -> URL {
        store.appending(path: "scope.json")
    }

    /// Missing, unreadable, undecodable, not a regular file, or over `maxFileBytes` → empty.
    /// Hosts pass through `sanitized` here too: `load` validates on its own, whatever wrote
    /// the file, so a hand-edited `scope.json` cannot reach the emitted config.
    public static func load(from url: URL) -> EmbeddedScope {
        // Type and size are checked before the read: `Data(contentsOf:)` would block on a
        // FIFO and balloon on a huge file. `attributesOfItem` does not follow a symlink, so
        // a link at the path is not a regular file — the per-launch config's no-follow posture.
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              attributes[.type] as? FileAttributeType == .typeRegular,
              let size = (attributes[.size] as? NSNumber)?.uint64Value, size <= maxFileBytes,
              let data = try? Data(contentsOf: url),
              let decoded = try? JSONDecoder().decode(EmbeddedScope.self, from: data) else {
            return EmbeddedScope()
        }
        return EmbeddedScope(hosts: sanitized(decoded.hosts))
    }

    /// Pretty + sortedKeys, creates the directory, writes atomically. Unlike `Pins`,
    /// atomic: a crash mid-write must not leave a truncated file that loads as empty
    /// and silently wipes the scope at the next launch. Writes `sanitized(hosts)`, and
    /// throws `SaveError.tooLarge` — touching nothing on disk — rather than write a file
    /// `load` would read as empty.
    public func save(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(EmbeddedScope(hosts: Self.sanitized(hosts)))
        guard UInt64(data.count) <= Self.maxFileBytes else { throw SaveError.tooLarge(bytes: data.count) }
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
    }

    /// Trim `.whitespacesAndNewlines`, drop what `isPersistable` rejects and any host over
    /// `maxHostLength`, drop later duplicates (the first occurrence wins), and stop once
    /// `maxHosts` are kept; order kept. Dropped and duplicate entries do not use up the cap.
    public static func sanitized(_ hosts: [String]) -> [String] {
        var seen = Set<String>()
        var kept: [String] = []
        for raw in hosts {
            if kept.count >= maxHosts { break }
            let host = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard host.count <= maxHostLength, isPersistable(host), seen.insert(host).inserted else { continue }
            kept.append(host)
        }
        return kept
    }

    /// `Scope.validate(host) == nil`, no newline or control character, and every scalar
    /// one libyaml's reader accepts. The second clause exists because `Scope.validate`
    /// accepts `"bad\nhost.test"`; the third because the core's YAML reader (libyaml via
    /// serde_yaml) refuses U+FFFE/U+FFFF, which are neither Cc nor Cf. Either way a
    /// tampered file would make every spawn fail — `Config.yaml()` throwing, or the core
    /// refusing its own config — and wedge the embedded core in a restart loop.
    public static func isPersistable(_ host: String) -> Bool {
        Scope.validate(host) == nil
            && host.rangeOfCharacter(from: .newlines.union(.controlCharacters)) == nil
            && host.unicodeScalars.allSatisfy(isYAMLPrintable)
    }

    /// libyaml's reader allow-list (`yaml_parser_update_buffer`): `#x9 | [#x20-#x7E] | #x85 |
    /// [#xA0-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]`. The line breaks libyaml also
    /// allows (`#xA`, `#xD`) are left out: the newline clause rejects them regardless.
    private static func isYAMLPrintable(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x09, 0x20...0x7E, 0x85, 0xA0...0xD7FF, 0xE000...0xFFFD, 0x10000...0x10FFFF: true
        default: false
        }
    }

    /// Whether `Session.init` seeds `scopeHosts` from the file before the bus connects:
    /// only for the embedded core, only when a bundled core is actually present. The app
    /// passes in the two facts; the Kit reads no defaults.
    public static func seedsAtLaunch(activeKind: ActiveCoreKind, bundledCorePresent: Bool) -> Bool {
        activeKind == .embedded && bundledCorePresent
    }
}
