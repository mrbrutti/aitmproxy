import AitmBusClient
import Foundation

/// The Scope page's adds in flight (S-081). A host the operator typed is `sending`
/// until the core lists it. A send that failed because the bus was not there — the
/// embedded core restarting, a dropped connection, a timeout — is `queued` and
/// replayed on the next connect and on every poll while it stays queued (one attempt
/// per host in flight at a time), so an add typed during a restart, or while the core
/// was too busy to answer, lands instead of silently staying "pending". A send the core refused is `failed` with
/// the core's reason and waits for the operator's Retry or ✕. Nothing here is a
/// scope fact: `scope.list` (`Session.scopeHosts`) is, and `confirm` drops every
/// host it lists.
public struct ScopeAddQueue: Hashable, Sendable {
    public enum State: Hashable, Sendable {
        case sending
        /// The bus was not there; replayed when it is (`replayable`).
        case queued
        /// The core refused it; not replayed, Retry re-sends.
        case failed(String)
    }

    public struct Entry: Hashable, Sendable {
        public var host: String
        public var state: State
    }

    public private(set) var entries: [Entry] = []

    public init() {}

    public var isEmpty: Bool { entries.isEmpty }
    public var hosts: [String] { entries.map(\.host) }
    /// Hosts to send again once the bus is back.
    public var replayable: [String] {
        entries.compactMap { if case .queued = $0.state { $0.host } else { nil } }
    }

    public func state(of host: String) -> State? { entries.first { $0.host == host }?.state }

    /// The operator typed (or retried) `host`: it is being sent.
    public mutating func begin(_ host: String) {
        if let index = entries.firstIndex(where: { $0.host == host }) {
            entries[index].state = .sending
        } else {
            entries.append(Entry(host: host, state: .sending))
        }
    }

    /// The send failed. A bus that was not there means the add is only delayed
    /// (`queued`); anything the core said means it will not land as typed (`failed`).
    public mutating func fail(_ host: String, reason: String, retryable: Bool) {
        guard let index = entries.firstIndex(where: { $0.host == host }) else { return }
        entries[index].state = retryable ? .queued : .failed(reason)
    }

    public mutating func fail(_ host: String, error: BusError) {
        fail(host, reason: error.description, retryable: Self.isRetryable(error))
    }

    /// `scope.list` arrived: every host it lists is done here.
    public mutating func confirm(listed: [String]) {
        entries.removeAll { listed.contains($0.host) }
    }

    /// The operator gave up on `host` (✕ on a queued or failed row).
    public mutating func drop(_ host: String) {
        entries.removeAll { $0.host == host }
    }

    /// Whether a failure is the bus's absence (replay later) rather than the core's answer.
    public static func isRetryable(_ error: BusError) -> Bool {
        switch error {
        case .disconnected, .transport, .timeout: true
        case .unauthorized, .rpc, .tool, .malformed: false
        }
    }

    /// The row's state line, in the operator's words.
    public static func label(for state: State) -> String {
        switch state {
        case .sending: "sending…"
        case .queued: "queued — added when the core is back"
        case .failed(let reason): "not added — \(reason)"
        }
    }
}
