import AitmBusClient
import AitmproxyKit
import Foundation
import Observation
import SwiftUI

/// What the bus calls each policy (foundation §4.8: `all | readonly | paused`).
extension AgentPolicy {
    var wire: String {
        switch self {
        case .all: "all"
        case .readOnly: "readonly"
        case .paused: "paused"
        }
    }

    init?(wire: String) {
        switch wire.lowercased().replacingOccurrences(of: "_", with: "").replacingOccurrences(of: "-", with: "") {
        case "all", "allowall": self = .all
        case "readonly": self = .readOnly
        case "paused": self = .paused
        default: return nil
        }
    }
}

/// The activity log and the agent policy (S-056, S-057). Entries arrive from
/// `notifications/aitm/agent` through `ingest`; until F2 lands the app records
/// its own commands through `record`, so the log is useful on day one.
@Observable
final class ActivityState {
    unowned let session: Session
    private(set) var ring = ActivityRing()
    var entries: [ActivityEntry] { ring.entries }
    /// `nil` shows every origin.
    var filter: ActivityEntry.Origin?
    /// Gated agent requests waiting for Approve once / Deny.
    var pending: [ActivityEntry] = []
    var connectedClients = 0
    /// The operator's choice while the bus cannot take it (before F1).
    var intendedPolicy: AgentPolicy?
    /// True between `agent.set` and the `agent.status` that confirms it.
    var confirming = false
    /// True once a bus notification has arrived: the log is the proxy's, not just this app's.
    private(set) var busFed = false

    init(session: Session) {
        self.session = session
        if Store.usesFixtures {
            for entry in Fixtures.activity { add(entry) }
            connectedClients = 1
            busFed = true
        }
    }

    /// The rows the panel shows, newest first, pending on top.
    var visible: [ActivityEntry] {
        let pendingRows = pending.filter { filter == nil || $0.origin == filter }
        let done = entries.reversed().filter { filter == nil || $0.origin == filter }
        return pendingRows + done
    }

    /// Live before F2: the panel lists this app's own commands only.
    var note: String? {
        !Store.usesFixtures && !busFed ? "This app's own commands only — every frontend's arrive with notifications/aitm/agent (F2)" : nil
    }

    func ingest(_ params: JSONValue) {
        guard let entry = ActivityEntry(notification: params) else { return }
        busFed = true
        add(entry)
    }

    func record(command: String, args: [String: JSONValue] = [:], result: ActivityEntry.Result) {
        add(ActivityEntry(origin: .operator, command: command, args: args, result: result))
    }

    private func add(_ entry: ActivityEntry) {
        if entry.result == .pending {
            pending.removeAll { $0.command == entry.command && $0.origin == entry.origin }
            pending.append(entry)
            return
        }
        // A completed agent command settles its pending request.
        if entry.origin == .agent { pending.removeAll { $0.command == entry.command && $0.origin == .agent } }
        ring.append(entry)
        if entry.origin == .agent, !Store.usesFixtures { session.agentActionsLastMinute = ring.actionsLastMinute() }
    }

    /// Runs the gated command with this app's (operator) identity, then logs the outcome.
    func approve(_ entry: ActivityEntry) {
        pending.removeAll { $0.id == entry.id }
        Task {
            do {
                _ = try await session.runCommand(entry.command, entry.args)
                record(command: entry.command, args: entry.args, result: .ok)
                session.lastError = nil
            } catch {
                let message = BusService.describe(error)
                record(command: entry.command, args: entry.args, result: .error(message))
                session.lastError = "\(entry.command): \(message)"
            }
        }
    }

    func deny(_ entry: ActivityEntry) {
        pending.removeAll { $0.id == entry.id }
        record(command: entry.command, args: entry.args, result: .error("denied by operator"))
    }

    private func hasTool(_ name: String) -> Bool { session.tools.contains { $0.name == name } }

    /// The synchronous entry for a control's binding: `setPolicy` in a task.
    func choose(_ policy: AgentPolicy) {
        Task { await setPolicy(policy) }
    }

    /// `agent.set {policy}` then `agent.status`; the toggle changes only when the bus confirms.
    func setPolicy(_ policy: AgentPolicy) async {
        if Store.usesFixtures {
            session.agentPolicy = policy
            record(command: "agent.set", args: ["policy": .string(policy.wire)], result: .ok)
            return
        }
        guard hasTool("agent.set") else {
            intendedPolicy = policy
            session.lastError = "agent.set needs F1"
            return
        }
        confirming = true
        defer { confirming = false }
        do {
            _ = try await session.runCommand("agent.set", ["policy": .string(policy.wire)])
            record(command: "agent.set", args: ["policy": .string(policy.wire)], result: .ok)
            let status = try await session.runCommand("agent.status", [:])
            if let status = AgentStatus(json: status) {
                apply(status)
            } else {
                session.agentPolicy = policy
            }
            intendedPolicy = nil
            session.lastError = nil
        } catch {
            let message = BusService.describe(error)
            record(command: "agent.set", args: ["policy": .string(policy.wire)], result: .error(message))
            session.lastError = "agent.set: \(message)"
        }
    }

    /// `agent.status` → policy, actions/min, connected clients.
    func refreshStatus() async {
        guard hasTool("agent.status"), let json = try? await session.runCommand("agent.status", [:]),
              let status = AgentStatus(json: json) else { return }
        apply(status)
    }

    private func apply(_ status: AgentStatus) {
        if let policy = AgentPolicy(wire: status.policy) { session.agentPolicy = policy }
        session.agentActionsLastMinute = status.actionsLastMinute
        connectedClients = status.connectedClients
    }
}

/// The Agent sidebar page: policy, connected clients, actions/min, then the
/// activity log inline (S-056).
struct AgentPanel: View {
    @Environment(Session.self) private var session
    @Bindable var state: ActivityState

    private var busOnline: Bool {
        if case .connected = session.bus { return true }
        return Store.usesFixtures
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: Space.md) {
                TrackedLabel("Agent")
                HStack(spacing: Space.md) {
                    FlatSegment(options: AgentPolicy.allCases.map { ($0, $0.title) },
                                selection: Binding(get: { session.agentPolicy }, set: { state.choose($0) }))
                        .disabled(!busOnline || state.confirming)
                        .help(busOnline ? "Agent policy" : "Agent policy needs the bus")
                        .accessibilityLabel("Agent policy")
                        .accessibilityValue("\(session.agentPolicy.title), \(session.agentActionsLastMinute) actions in the last minute")
                    if state.confirming {
                        Hint(text: "confirming…")
                    } else if let intended = state.intendedPolicy, intended != session.agentPolicy {
                        Hint(text: "agent.set needs F1 — intended: \(intended.title)")
                    } else if !busOnline {
                        Hint(text: "Agent policy needs the bus")
                    }
                }
                HStack(spacing: Space.section) {
                    stat("Connected clients", "\(state.connectedClients)")
                    stat("Actions / min", "\(session.agentActionsLastMinute)")
                    stat("Pending", "\(state.pending.count)")
                }
            }
            .padding(.horizontal, Space.margin)
            .padding(.vertical, Space.lg)
            .frame(maxWidth: .infinity, alignment: .leading)
            Rule()
            ActivityLogPanel(state: state, inline: true)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Tok.Ground.surface.color)
        .gridArea("agent")
        .task { await state.refreshStatus() }
    }

    private func stat(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            Text(value).font(Tok.Face.data(Tok.Typography.Size.lg, .medium)).foregroundStyle(Tok.Ink.primary.color)
        }
        .accessibilityElement(children: .combine)
    }
}
