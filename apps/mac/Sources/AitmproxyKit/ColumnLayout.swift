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

/// Which fixed-width columns to hide so a list fits its pane without a horizontal scroll bar.
/// The user's own hidden set stays apart from this one, so a header menu can tell them apart.
public enum ColumnFit {
    public struct Column: Hashable, Sendable {
        public var id: String
        public var width: Double
        /// Hidden by the user: already out of the sum, never auto-hidden.
        public var userHidden: Bool

        public init(id: String, width: Double, userHidden: Bool = false) {
            self.id = id
            self.width = width
            self.userHidden = userHidden
        }
    }

    /// Hides columns in `priority` order (first = first to go) until the visible fixed widths plus
    /// `flexibleMin` (the flexible column's minimum) fit `available`. Columns not in `priority`
    /// never hide. Returns the ids to hide; empty when everything fits.
    public static func autoHidden(available: Double, columns: [Column], flexibleMin: Double, priority: [String]) -> Set<String> {
        var hidden: Set<String> = []
        var needed = columns.filter { !$0.userHidden }.reduce(0) { $0 + $1.width } + flexibleMin
        for id in priority where needed > available {
            guard let column = columns.first(where: { $0.id == id && !$0.userHidden }) else { continue }
            hidden.insert(id)
            needed -= column.width
        }
        return hidden
    }
}
