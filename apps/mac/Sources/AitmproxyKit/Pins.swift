import Foundation

/// Hosts and apps pinned to the sidebar's Working group (`pins.json`).
public struct Pins: Codable, Hashable, Sendable {
    public var hosts: [String]
    public var apps: [String]

    public init(hosts: [String] = [], apps: [String] = []) {
        self.hosts = hosts
        self.apps = apps
    }

    public static func load(from url: URL) -> Pins {
        guard let data = try? Data(contentsOf: url), let pins = try? JSONDecoder().decode(Pins.self, from: data) else {
            return Pins()
        }
        return pins
    }

    public func save(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(self).write(to: url)
    }

    /// Pinning twice stores once; order is the order of pinning.
    public mutating func pinHost(_ host: String) {
        if !hosts.contains(host) { hosts.append(host) }
    }

    public mutating func unpinHost(_ host: String) {
        hosts.removeAll { $0 == host }
    }

    public mutating func pinApp(_ app: String) {
        if !apps.contains(app) { apps.append(app) }
    }

    public mutating func unpinApp(_ app: String) {
        apps.removeAll { $0 == app }
    }

    public var isEmpty: Bool { hosts.isEmpty && apps.isEmpty }
}

/// The status bar's selection summary (foundation §3.1 "Multi-select + summary").
public struct SelectionSummary: Hashable, Sendable {
    public var count: Int
    /// Rows whose request and response sizes are both known.
    public var sized: Int
    public var totalBytes: Int64
    public var totalDuration: Duration

    public init(rows: [FlowRow]) {
        count = rows.count
        var sized = 0
        var bytes: Int64 = 0
        var duration: Duration = .zero
        for row in rows {
            if let req = row.requestBytes, let resp = row.responseBytes {
                sized += 1
                bytes += req + resp
            }
            if let d = row.duration { duration += d }
        }
        self.sized = sized
        totalBytes = bytes
        totalDuration = duration
    }

    /// `3 selected · 24.1 KB · 1.47 s`, or `3 selected · 2 sized · 18.0 KB · 1.47 s` when sizes are missing.
    public var text: String {
        var parts = ["\(count) selected"]
        if sized < count { parts.append("\(sized) sized") }
        if sized > 0 { parts.append(Format.bytes(totalBytes)) }
        if totalDuration > .zero { parts.append(Format.duration(totalDuration)) }
        return parts.joined(separator: " · ")
    }
}
