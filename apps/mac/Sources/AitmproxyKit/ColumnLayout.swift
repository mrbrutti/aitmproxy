import Foundation

/// The flow list's column order, widths and hidden set, kept in
/// `columns.json` under the app's state folder. Ids are the column ids; an
/// unknown id (an older or newer build) is ignored, a missing one falls
/// back to its default.
public struct ColumnLayout: Codable, Hashable, Sendable {
    public var order: [String]
    public var widths: [String: Double]
    public var hidden: Set<String>

    public init(order: [String] = [], widths: [String: Double] = [:], hidden: Set<String> = []) {
        self.order = order
        self.widths = widths
        self.hidden = hidden
    }

    /// nil when there is no file or it does not parse (then defaults apply).
    public static func load(from url: URL) -> ColumnLayout? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(ColumnLayout.self, from: data)
    }

    public func save(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(self).write(to: url)
    }

    /// The saved order restricted to `known` ids, with any id the file did
    /// not mention appended in `known`'s order.
    public func resolvedOrder(known: [String]) -> [String] {
        let knownSet = Set(known)
        var out = order.filter { knownSet.contains($0) }
        let seen = Set(out)
        out += known.filter { !seen.contains($0) }
        return out
    }

    public func width(for id: String, default defaultWidth: Double) -> Double {
        guard let w = widths[id], w > 0 else { return defaultWidth }
        return w
    }

    public func isHidden(_ id: String) -> Bool { hidden.contains(id) }
}
