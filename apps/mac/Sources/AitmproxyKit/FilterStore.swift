import Foundation

/// A named filter, kept as its text form so it copies between surfaces.
public struct SavedFilter: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var name: String
    public var expression: String

    public init(id: UUID = UUID(), name: String, expression: String) {
        self.id = id
        self.name = name
        self.expression = expression
    }
}

/// The saved-filter list as one JSON file (`filters.json` in the app's state
/// directory). A missing file is an empty list.
public struct SavedFilterStore: Sendable {
    public static let fileName = "filters.json"

    public let fileURL: URL

    public init(fileURL: URL) {
        self.fileURL = fileURL
    }

    public init(stateDirectory: URL) {
        self.init(fileURL: stateDirectory.appending(path: SavedFilterStore.fileName))
    }

    public func load() throws -> [SavedFilter] {
        guard FileManager.default.fileExists(atPath: fileURL.path(percentEncoded: false)) else { return [] }
        return try JSONDecoder().decode([SavedFilter].self, from: Data(contentsOf: fileURL))
    }

    public func save(_ filters: [SavedFilter]) throws {
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(filters).write(to: fileURL, options: [.atomic])
    }
}
