import Foundation

/// The sidebar's Apps tree, computed from rows (spec 2026-10-31-mac-app-icons-and-names, D1/D4).
/// Pure, so it is unit-tested with literal rows; `Session.clients` and `Session.hosts(forClient:)`
/// are one-line calls into it.
public enum ClientTree {
    /// One entry per distinct `ClientInfo` value (one identifier ⇒ one group, since `bundleID` is
    /// in the hash), most flows first, then by display name, then by `groupKey` so two
    /// "(Service)" rows of one owner order deterministically. Rows with no client are skipped.
    public static func clients(in rows: [FlowRow]) -> [(ClientInfo, Int)] {
        var counts: [ClientInfo: Int] = [:]
        for row in rows {
            if let client = row.client { counts[client, default: 0] += 1 }
        }
        return counts.sorted { lhs, rhs in
            if lhs.value != rhs.value { return lhs.value > rhs.value }
            if lhs.key.name != rhs.key.name { return lhs.key.name < rhs.key.name }
            return lhs.key.groupKey < rhs.key.groupKey
        }
    }

    /// The authorities the app with group key `key` talked to, most flows first, then by host.
    /// The counts sum to that app's entry in `clients(in:)`.
    public static func hosts(forClient key: String, in rows: [FlowRow]) -> [(String, Int)] {
        var counts: [String: Int] = [:]
        for row in rows where row.client?.groupKey == key {
            counts[row.authority, default: 0] += 1
        }
        return counts.sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }
    }
}

public extension Pins {
    /// `.host` and `.clientHost` pin the host (a domain under an app is a host pin, D4/D7);
    /// `.client` pins the group key.
    mutating func pin(_ group: FlowGroup) {
        switch group {
        case .host(let host), .clientHost(_, let host): pinHost(host)
        case .client(let key): pinApp(key)
        }
    }

    /// Mirrors `pin(_:)`.
    mutating func unpin(_ group: FlowGroup) {
        switch group {
        case .host(let host), .clientHost(_, let host): unpinHost(host)
        case .client(let key): unpinApp(key)
        }
    }

    /// Mirrors `pin(_:)`: `.clientHost(_, h)` is pinned exactly when `h` is in `hosts`.
    func contains(_ group: FlowGroup) -> Bool {
        switch group {
        case .host(let host), .clientHost(_, let host): hosts.contains(host)
        case .client(let key): apps.contains(key)
        }
    }
}

/// Insertion-ordered dictionary that drops its oldest entry past `capacity` (the resolver's two
/// caches). Overwriting an existing key refreshes it to newest (so a re-resolved identity is the
/// last to go); setting `nil` deletes the entry and its age slot (plan call 3).
public struct BoundedCache<Key: Hashable, Value> {
    private let capacity: Int
    private var storage: [Key: Value] = [:]
    /// Keys oldest first.
    private var order: [Key] = []

    public init(capacity: Int) {
        self.capacity = max(capacity, 0)
    }

    public var count: Int { storage.count }

    public subscript(key: Key) -> Value? {
        get { storage[key] }
        set {
            guard let newValue else {
                if storage.removeValue(forKey: key) != nil {
                    order.removeAll { $0 == key }
                }
                return
            }
            if storage.updateValue(newValue, forKey: key) == nil {
                order.append(key)
                while storage.count > capacity, let oldest = order.first {
                    order.removeFirst()
                    storage.removeValue(forKey: oldest)
                }
            } else {
                order.removeAll { $0 == key }
                order.append(key)
            }
        }
    }
}

extension BoundedCache: Sendable where Key: Sendable, Value: Sendable {}
