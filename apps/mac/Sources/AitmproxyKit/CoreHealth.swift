import Foundation

/// The three states the embedded core's health dot shows (spec C4): the colour
/// bucket a `CoreConnection.Status` falls into. Coarser than the status on
/// purpose — the dot is a glance, the precise word and the degraded reason live
/// next to it.
public enum CoreHealth: Hashable, Sendable, CaseIterable {
    /// The core is up and the bus is connected (`.ready`). Green.
    case running
    /// Coming up or backing off between tries (`.starting` / `.connecting`). Amber.
    case restarting
    /// Gave up or was stopped (`.degraded` / `.stopped`). Red.
    case failed

    public init(_ status: CoreConnection.Status) {
        switch status {
        case .ready: self = .running
        case .starting, .connecting: self = .restarting
        case .degraded, .stopped: self = .failed
        }
    }

    /// The one status-bar word per core state, shared by the toolbar pill and the health
    /// dot so they never disagree. Lower case: it follows a dot or a "·" mid-sentence.
    /// `CoreConnection.Status.healthTitle` keeps the finer per-status word for the log.
    public var statusWord: String {
        switch self {
        case .running: "core running"
        case .restarting: "restarting…"
        case .failed: "core failed"
        }
    }
}

extension CoreConnection.Status {
    /// The health bucket this status falls into.
    public var health: CoreHealth { CoreHealth(self) }

    /// The precise operator-facing word for the dot. Finer than `health.title`:
    /// a first `.starting` reads "Starting", not "Restarting".
    public var healthTitle: String {
        switch self {
        case .starting: "Starting"
        case .connecting: "Connecting"
        case .ready: "Running"
        case .degraded: "Failed"
        case .stopped: "Stopped"
        }
    }

    /// The failure reason when `.degraded` (carries the stderr tail after a
    /// restart gives up — AC8), `nil` otherwise.
    public var degradedReason: String? {
        if case .degraded(let reason) = self { return reason }
        return nil
    }
}

extension CoreConnection {
    /// The health bucket of this connection's current status.
    public var health: CoreHealth { status.health }
}

/// One captured line of the embedded core's stdout/stderr. The `id` is
/// monotonic so SwiftUI never reuses an identity across a capacity trim or a
/// clear (a reused id would recycle a stale row).
public struct CoreLogLine: Identifiable, Hashable, Sendable {
    public let id: Int
    public let text: String

    public init(id: Int, text: String) {
        self.id = id
        self.text = text
    }
}

/// A bounded, in-order record of the embedded core's captured output for the
/// on-demand log panel (spec C4). Token-free by construction (Layer A removed
/// the token and the handshake spam from the stream before it is captured).
public struct CoreLogBuffer: Hashable, Sendable {
    public let capacity: Int
    public private(set) var lines: [CoreLogLine] = []
    /// The id the next appended line takes; never rewinds, even after a clear.
    private var nextID = 0

    public init(capacity: Int = 1000) {
        self.capacity = max(capacity, 1)
    }

    public var isEmpty: Bool { lines.isEmpty }

    public mutating func append(_ text: String) {
        lines.append(CoreLogLine(id: nextID, text: text))
        nextID += 1
        if lines.count > capacity { lines.removeFirst(lines.count - capacity) }
    }

    public mutating func removeAll() { lines.removeAll() }
}
