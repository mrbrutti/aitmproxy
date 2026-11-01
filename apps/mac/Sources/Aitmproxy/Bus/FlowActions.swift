import AitmBusClient
import AitmproxyKit
import Foundation

/// What the shell's buttons do: every call is a bus command (§4.5, §4.6), run by
/// `BusService` once `ShellView` has installed it on the session.
protocol FlowActions: AnyObject {
    func setIntercept(_ enabled: Bool, rules: [BreakpointRule]) async throws
    func resume(_ id: FlowID) async throws
    func kill(_ id: FlowID, mode: KillMode) async throws
    func mutate(_ id: FlowID, edits: RequestEdits) async throws
    func replay(_ id: FlowID) async throws -> FlowID?
    func send(_ request: RequestEdits) async throws -> FlowID?
    func addScope(_ host: String) async throws
    /// F12: `scope.remove {host}`.
    func removeScope(_ host: String) async throws
    /// F6: `flow.mark {id, marks}` / `flow.comment {id, text}`.
    func mark(_ id: FlowID, color: MarkColor?) async throws
    func comment(_ id: FlowID, text: String) async throws
    /// F7: `proxy.pause` / `proxy.resume` / `flow.clear`.
    func setCapturing(_ on: Bool) async throws
    func clear() async throws
}

/// Installed until `ShellView` hands the session a `BusService`: every action fails
/// with `BusError.disconnected` ("the bus connection closed"), which `Session+Verbs`
/// shows in the status bar. No stored state: nothing is mutated before the bus exists.
final class OfflineActions: FlowActions {
    func setIntercept(_ enabled: Bool, rules: [BreakpointRule]) async throws { throw BusError.disconnected }
    func resume(_ id: FlowID) async throws { throw BusError.disconnected }
    func kill(_ id: FlowID, mode: KillMode) async throws { throw BusError.disconnected }
    func mutate(_ id: FlowID, edits: RequestEdits) async throws { throw BusError.disconnected }
    func replay(_ id: FlowID) async throws -> FlowID? { throw BusError.disconnected }
    func send(_ request: RequestEdits) async throws -> FlowID? { throw BusError.disconnected }
    func addScope(_ host: String) async throws { throw BusError.disconnected }
    func removeScope(_ host: String) async throws { throw BusError.disconnected }
    func mark(_ id: FlowID, color: MarkColor?) async throws { throw BusError.disconnected }
    func comment(_ id: FlowID, text: String) async throws { throw BusError.disconnected }
    func setCapturing(_ on: Bool) async throws { throw BusError.disconnected }
    func clear() async throws { throw BusError.disconnected }
}
