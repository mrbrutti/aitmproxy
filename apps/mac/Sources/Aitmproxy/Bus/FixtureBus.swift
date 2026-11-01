import AitmBusClient
import AitmproxyKit
import Foundation

/// The fixture bus: the test adapter behind `Session.commandRunner`, where the live
/// adapter is `BusService.call`. Verbs the shell already models act on the session (arm,
/// resume, kill, replay, scope); the L4 and scan verbs answer with the fixtures' data and
/// refuse out-of-scope targets the way the core does; the rest echo. `Session.init`
/// installs it in fixture, snapshot and self-test runs, so the palette, the panels and the
/// self-test drive the same `runCommand` path they use on a real bus.
///
/// This is the bus's stand-in, so `tools/check-capture-operator-only.sh` lists it with
/// `BusService.swift` among the agent-reachable surfaces that must never mention the
/// capture glue.
final class FixtureBus {
    /// Weak, like the closure it replaced: a call after the session is gone reports
    /// `disconnected`, as a dropped bus would.
    private weak var session: Session?

    init(session: Session) { self.session = session }

    /// One fixture command, as `BusService.call` would run it live.
    func call(_ name: String, _ args: [String: JSONValue]) async throws -> JSONValue {
        guard let session else { throw BusError.disconnected }
        switch name {
        case "flow.intercept":
            session.interceptArmed = args["enabled"]?.boolValue ?? true
            return .bool(session.interceptArmed)
        case "flow.resume": if let id = args["id"]?.stringValue { session.resume(FlowID(id)) }; return .null
        case "flow.kill": if let id = args["id"]?.stringValue { session.kill(FlowID(id)) }; return .null
        case "flow.replay": if let id = args["id"]?.stringValue { session.replay(FlowID(id)) }; return .string("replayed")
        case "flow.list": return .array(session.rows.map { .string($0.id.raw) })
        case "scope.list": return .array(session.scopeHosts.map { .string($0) })
        case "scope.add": if let h = args["host"]?.stringValue { session.addScope(h) }; return .string(args["host"]?.stringValue ?? "")
        case "l4.flow.list": return .array(session.l4Details.keys.map { .string($0.raw) })
        case "l4.flow.get":
            guard let id = args["id"]?.stringValue, let flow = session.l4Details[FlowID(id)] else { throw BusError.tool(message: "no such L4 flow") }
            return Fixtures.l4FlowJSON(flow)
        case "l4.craft":
            return .object([
                "length": .number(Double(Fixtures.l4CraftBytes.count)),
                "bytes": .string(Fixtures.l4CraftBytes.base64EncodedString()),
                "summary": .object(["layers": .array([.string("IPv4"), .string("UDP")]),
                                    "length": .number(Double(Fixtures.l4CraftBytes.count))]),
            ])
        case "l4.inject", "l4.send_recv":
            // The guard refuses an out-of-scope target before any confirm token.
            let dst = args["dst"]?.stringValue ?? ""
            guard dst == "127.0.0.1" else {
                throw BusError.tool(message: "\(name) refused: OutOfL4Scope — \(dst) is not in the L4 scope "
                    + "(deny-by-default). Add it with l4.scope.add (operator-confirmed).")
            }
            if args["_confirm"] != nil { return .object(["status": .string("ok"), "sent": .number(1)]) }
            let count = args["count"]?.intValue ?? 1
            return .object([
                "status": .string("needs_confirmation"),
                "prompt": .string("Inject \(count)× IPv4/UDP (37 B) to \(dst):\(args["port"]?.intValue ?? 9) "
                    + "on \(args["interface"]?.stringValue ?? "lo0") — in scope \(Fixtures.l4Scope) · permit budget "
                    + "64 pps. Re-send with _confirm to put it on the wire."),
                "confirm_token": .string("l4-\(UUID().uuidString.prefix(8))"),
            ])
        case "scan.discover":
            // The scanner gates the seed before its first navigation: an out-of-scope target is refused, never crawled.
            let target = args["target"]?.stringValue ?? ""
            guard let authority = ScanForm.authority(of: target), Scope.contains(authority, in: session.scopeHosts) else {
                throw BusError.tool(message: "scan.discover refused: OutOfScope — \(target) is not in scope (deny-by-default).")
            }
            return Fixtures.scanDiscover
        case "l4.agent.status": return l4AgentGatesJSON(session)
        case "l4.agent.set":
            if let cap = args["capability"]?.stringValue, let allowed = args["allowed"]?.boolValue {
                session.setL4Gate(cap, allowed)
            }
            return l4AgentGatesJSON(session)
        case "l4.capture.start", "l4.capture.stop", "l4.scope.add", "l4.scope.list", "l4.interfaces", "l4.capture.status":
            return .string("ok (fixture)")
        default: return .string("ok (fixture)")
        }
    }

    /// The session's L4 agent gates as the `l4.agent.status` / `.set` JSON object.
    private func l4AgentGatesJSON(_ session: Session) -> JSONValue {
        let gates = session.l4AgentGates ?? L4AgentGates(capture: false, inject: false, intercept: false, widen: false)
        return .object([
            "capture": .bool(gates.capture), "inject": .bool(gates.inject),
            "intercept": .bool(gates.intercept), "widen": .bool(gates.widen),
        ])
    }
}
