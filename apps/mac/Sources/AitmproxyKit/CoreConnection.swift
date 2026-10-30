import AitmBusClient
import Foundation

/// A stable, opaque identity for one core the UI talks to. Backed by a UUID so a
/// fresh id is unique per core; `rawValue` lets a persisted choice round-trip.
///
/// Every flow/row will carry a `CoreID` (Task 5) so a second connection is
/// additive rather than a migration; here it is just the identifier type.
public struct CoreID: Hashable, Sendable, Codable, CustomStringConvertible {
    public let rawValue: String

    /// A fresh, unique identity for a newly created connection.
    public init() { self.rawValue = UUID().uuidString }

    /// Reconstructs an identity from a persisted `rawValue`.
    public init(rawValue: String) { self.rawValue = rawValue }

    /// The well-known id for fixture / offline sample data: a single stable
    /// originating connection, so seeded flows (Task 5) share one `CoreID`
    /// without a live core. The live embedded connection gets a fresh id.
    public static let fixture = CoreID(rawValue: "fixture")

    public var description: String { rawValue }
}

/// One connection from a frontend to an `aitm` core: who it is, where its bus
/// is, and how healthy it is — the shared vocabulary every frontend uses.
///
/// Exactly one connection is active in this milestone, but the type and its
/// `ConnectionRegistry` are shaped so several at once — and a future `remote`
/// transport — slot in additively, not as a reshape.
public struct CoreConnection: Identifiable, Hashable, Sendable {
    /// How the core was obtained. A closed set; `remote` is reserved.
    public enum Kind: Hashable, Sendable {
        /// This UI launched and manages the core (the default).
        case embedded
        /// The operator supplied an already-running core (host/port/token).
        case external
        /// Reserved for a future cross-machine core over a secure transport.
        /// Named so that milestone adds its endpoint/auth fields rather than
        /// reshaping this type; it has no behaviour yet and cannot be active.
        case remote

        /// Whether a connection of this kind may become the active connection.
        /// `remote` is reserved and not yet selectable.
        public var canBeActive: Bool {
            switch self {
            case .embedded, .external: true
            case .remote: false
            }
        }
    }

    /// Lifecycle of the connection; the embedded-core manager (Task 6) maps its
    /// child process onto these.
    public enum Status: Hashable, Sendable {
        case starting
        case connecting
        case ready
        case degraded(reason: String)
        case stopped
    }

    /// Stable identity, assigned client-side per connection.
    public let id: CoreID
    /// How this core was obtained.
    public var kind: Kind
    /// Where the bus listens and the token its first line carries (loopback now).
    public var endpoint: BusEndpoint
    /// Current health.
    public var status: Status
    /// Operator-facing name, e.g. "Embedded core" or a `host:port`.
    public var label: String
    /// The proxy's actual bound `host:port` — may be an auto-chosen alternate when
    /// the preferred port was taken (AC9), which is what the toolbar must show. nil
    /// until the core reports ready.
    public var proxyAddress: String?

    public init(
        id: CoreID = CoreID(),
        kind: Kind,
        endpoint: BusEndpoint,
        status: Status,
        label: String,
        proxyAddress: String? = nil
    ) {
        self.id = id
        self.kind = kind
        self.endpoint = endpoint
        self.status = status
        self.label = label
        self.proxyAddress = proxyAddress
    }
}

/// The connections the app knows about, keyed by `CoreID`, with the single
/// active one tracked separately.
///
/// It can hold more than one entry today even though the UI exposes a single
/// active choice — the seam for multi-core and rule-based routing later. A pure
/// value type: a managing layer (Tasks 6–7) owns and observes an instance.
public struct ConnectionRegistry: Sendable {
    private var connections: [CoreID: CoreConnection] = [:]
    private var activeKey: CoreID?

    public init() {}

    /// Inserts a connection, replacing any existing entry with the same id.
    public mutating func insert(_ connection: CoreConnection) {
        connections[connection.id] = connection
    }

    /// Removes a connection; clears the active choice when it was the one removed.
    public mutating func remove(_ id: CoreID) {
        connections[id] = nil
        if activeKey == id { activeKey = nil }
    }

    /// How many connections are held.
    public var count: Int { connections.count }

    /// Every held connection, in no particular order.
    public var all: [CoreConnection] { Array(connections.values) }

    /// The held connection with this id, or `nil` when none is held.
    public func connection(for id: CoreID) -> CoreConnection? { connections[id] }

    /// The id of the active connection, or `nil` when none is chosen.
    public var activeID: CoreID? { activeKey }

    /// The active connection, or `nil` when none is chosen.
    public var active: CoreConnection? { activeKey.flatMap { connections[$0] } }

    /// Makes the identified connection active. Returns `false` — leaving the
    /// current choice untouched — when the id is unknown or its kind cannot be
    /// active (a reserved `remote`).
    @discardableResult
    public mutating func setActive(_ id: CoreID) -> Bool {
        guard let connection = connections[id], connection.kind.canBeActive else { return false }
        activeKey = id
        return true
    }
}
