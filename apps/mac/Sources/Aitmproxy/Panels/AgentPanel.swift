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
    }

    /// The rows the panel shows, newest first, pending on top.
    var visible: [ActivityEntry] {
        let pendingRows = pending.filter { filter == nil || $0.origin == filter }
        let done = entries.reversed().filter { filter == nil || $0.origin == filter }
        return pendingRows + done
    }

    /// Live before F2: the panel lists this app's own commands only.
    var note: String? {
        // F2: notifications/aitm/agent feeds every frontend's commands.
        !busFed ? "This app's own commands only — other frontends' commands arrive once the core publishes them" : nil
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
        if entry.origin == .agent { session.agentActionsLastMinute = ring.actionsLastMinute() }
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

    // MARK: L4 per-capability agent gates (AC11)

    /// The core advertises `l4.*` and reports per-capability gates.
    var l4Advertised: Bool { session.l4Enabled }
    /// The operator-only setter is present, so the toggles are live (else read-only).
    var l4SetterPresent: Bool { session.l4HasSetter }

    /// `l4.agent.status` → the four per-capability gate states.
    func refreshL4Gates() async {
        guard session.l4Enabled, hasTool("l4.agent.status"),
              let json = try? await session.runCommand("l4.agent.status", [:]),
              let gates = L4AgentGates(json: json) else { return }
        session.l4AgentGates = gates
    }

    /// Flip one L4 agent gate via the operator-only `l4.agent.set`, then re-read it.
    /// The agent can never flip its own — the setter refuses a `Frontend::Mcp` caller.
    func setL4Capability(_ capability: L4AgentGates.Capability, _ allowed: Bool) {
        let args: [String: JSONValue] = ["capability": .string(capability.rawValue), "allowed": .bool(allowed)]
        Task {
            guard hasTool("l4.agent.set") else {
                session.lastError = "l4.agent.set needs an operator-gated core setter"
                return
            }
            do {
                let json = try await session.runCommand("l4.agent.set", args)
                if let gates = L4AgentGates(json: json) { session.l4AgentGates = gates }
                record(command: "l4.agent.set", args: args, result: .ok)
                session.lastError = nil
            } catch {
                let message = BusService.describe(error)
                record(command: "l4.agent.set", args: args, result: .error(message))
                session.lastError = "l4.agent.set: \(message)"
            }
        }
    }

    /// The synchronous entry for a control's binding: `setPolicy` in a task.
    func choose(_ policy: AgentPolicy) {
        Task { await setPolicy(policy) }
    }

    /// `agent.set {policy}` then `agent.status`; the toggle changes only when the bus confirms.
    func setPolicy(_ policy: AgentPolicy) async {
        guard hasTool("agent.set") else {
            intendedPolicy = policy
            session.lastError = "The core cannot change the agent policy yet" // core F1
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
        return false
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: Space.md) {
                TrackedLabel("Agent")
                    .gridProbe("agent-title", area: "agent")
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
                        // F1: agent.set is not on this bus yet.
                        Hint(text: "The core cannot change the agent policy yet — intended: \(intended.title)")
                    } else if !busOnline {
                        Hint(text: "Agent policy needs the bus")
                    }
                }
                .gridProbe("agent-policy", area: "agent")
                HStack(spacing: Space.section) {
                    stat("Connected clients", "\(state.connectedClients)")
                    stat("Actions per minute", "\(session.agentActionsLastMinute)")
                    stat("Pending", "\(state.pending.count)")
                }
                .gridProbe("agent-stats", area: "agent")
                if state.l4Advertised {
                    L4CapabilitySection(state: state, gates: session.l4AgentGates)
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
        .task { await state.refreshL4Gates() }
    }

    private func stat(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            Text(value).font(Tok.Face.data(Tok.Typography.Size.lg, .medium)).foregroundStyle(Tok.Ink.primary.color)
        }
        .accessibilityElement(children: .combine)
    }

}

/// The Agent panel's L4 capability section (AC11): one toggle per gate
/// (Capture / Inject / Intercept / Widen) reflecting the `l4.allow_agent_*` gate
/// that governs the agent (MCP) L4 path. The operator sets each; where the core
/// exposes no `l4.agent.set`, the toggles are read-only with an honest note. An
/// agent can never flip its own.
struct L4CapabilitySection: View {
    @Bindable var state: ActivityState
    var gates: L4AgentGates?

    var body: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Rule().padding(.vertical, Space.xs)
            HStack(spacing: Space.sm) {
                Badge(text: "L4", pair: Tok.L4.badge)
                TrackedLabel("Agent L4 capabilities")
            }
            Text(state.l4SetterPresent
                ? "Turn the agent's access to each raw network capability on or off."
                : "Read-only here — change these in config.yaml and restart. The agent can never turn its own on.")
                .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                .fixedSize(horizontal: false, vertical: true)
                .help(state.l4SetterPresent
                    ? "Each switch reflects the l4.allow_agent_* gate that governs the agent (MCP) L4 path."
                    : "Set l4.allow_agent_* in config.yaml and restart; the operator-only setter refuses an agent (MCP) caller.")
            // A Grid so every switch lands on one trailing edge instead of starting
            // right after a ragged label.
            Grid(alignment: .leading, horizontalSpacing: Space.lg, verticalSpacing: Space.sm) {
                ForEach(L4AgentGates.Capability.allCases, id: \.self) { cap in
                    GridRow {
                        Text(cap.title).font(Tok.Face.ui(Tok.Typography.Size.base)).foregroundStyle(Tok.Ink.primary.color)
                        Toggle("", isOn: Binding(
                            get: { gates?.allowed(cap) ?? false },
                            set: { state.setL4Capability(cap, $0) }
                        ))
                        .labelsHidden()
                        .toggleStyle(.switch)
                        .controlSize(.small)
                        .tint(Tok.L4.base.color)
                        .disabled(!state.l4SetterPresent)
                        .accessibilityIdentifier("l4-gate-\(cap.rawValue)")
                        .accessibilityLabel(cap.title)
                    }
                }
            }
        }
        .padding(.top, Space.sm)
    }
}
