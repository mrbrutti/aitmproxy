import AitmBusClient
import Foundation

// The raw-L4 (transport-layer) operator model the macOS surface renders against.
// Visual/interaction design is ui-scripting-highlight-l4 Part 3 (§3.1 FlowKind,
// §3.2 per-surface L4); this is the native-Swift machinery that consumes the live
// `l4.*` bus (l4-operator-surfaces Part 3). The wire shapes are M5's
// `aitm-proto-l4` (flow.rs / commands/flow.rs / commands/craft.rs / agent.rs);
// this file parses them and never redesigns them.

// MARK: - Flow kinds (AC7: every kind renders; unknown → labelled placeholder)

/// A per-kind descriptor the flow list and inspector render against, so a surface
/// can never "only render HTTP": a known kind carries its badge; an unknown or
/// absent kind renders a *labelled* placeholder row, never an empty one.
public struct FlowKindDescriptor: Hashable, Sendable {
    /// The known kind, or nil when the core reports a kind this build does not model.
    public let kind: FlowKind?
    /// The raw kind string as the bus reported it.
    public let rawKind: String
    /// The badge label shown in the list (`HTTP` / `WS` / `L4`, or the raw name for
    /// an unknown kind so the placeholder is always labelled).
    public let badgeLabel: String
    /// True when the kind is unknown/absent and the row is a labelled placeholder.
    public let isPlaceholder: Bool

    /// Describe a kind string from `flow.list` / `l4.flow.list`. An empty or unknown
    /// string yields a placeholder whose label is still non-empty.
    public static func describe(_ raw: String) -> FlowKindDescriptor {
        switch FlowKind(rawValue: raw) {
        case .http: return FlowKindDescriptor(kind: .http, rawKind: raw, badgeLabel: "HTTP", isPlaceholder: false)
        case .websocket: return FlowKindDescriptor(kind: .websocket, rawKind: raw, badgeLabel: "WS", isPlaceholder: false)
        case .l4: return FlowKindDescriptor(kind: .l4, rawKind: raw, badgeLabel: "L4", isPlaceholder: false)
        case nil:
            let label = raw.trimmingCharacters(in: .whitespaces)
            return FlowKindDescriptor(
                kind: nil, rawKind: raw,
                badgeLabel: label.isEmpty ? "?" : label.uppercased(),
                isPlaceholder: true)
        }
    }
}

// MARK: - Protocol + session state

/// The transport/network protocol of an L4 flow, from the decoded `PacketSummary`
/// (`aitm-proto-l4::types::L4Proto`). Drives the TCP/UDP/ICMP sub-label.
public enum L4Proto: Hashable, Sendable {
    case tcp, udp, icmp, icmpV6, raw, other

    /// The one-word sub-label shown beside the L4 badge.
    public var subLabel: String {
        switch self {
        case .tcp: "TCP"
        case .udp: "UDP"
        case .icmp: "ICMP"
        case .icmpV6: "ICMPv6"
        case .raw: "RAW"
        case .other: "L4"
        }
    }

    /// Classify a flow from its packets' decoded layer names (innermost transport
    /// layer wins). An empty / all-link decode is `.raw`.
    public static func fromLayers(_ layers: [String]) -> L4Proto {
        for layer in layers.reversed() {
            switch layer.uppercased() {
            case "TCP": return .tcp
            case "UDP": return .udp
            case "ICMP": return .icmp
            case "ICMPV6": return .icmpV6
            default: continue
            }
        }
        return .raw
    }
}

/// Which L4 primitive produced a flow (`aitm-proto-l4::flow::L4FlowKind`): the
/// Status cell for an L4 row.
public enum L4SessionState: String, Sendable, Hashable {
    case capture, craft, sendRecv = "send_recv", intercept

    public var label: String {
        switch self {
        case .capture: "capture"
        case .craft: "craft"
        case .sendRecv: "send·recv"
        case .intercept: "intercept"
        }
    }
}

// MARK: - Packets + flow detail (l4.flow.get)

/// One packet in an L4 flow (`aitm-proto-l4::flow::L4Packet`, as `l4.flow.get`
/// serializes it): direction, byte length, the decoded layer names, and whether
/// aitmproxy authored and injected it. `l4.flow.get` carries no raw bytes, so the
/// hex pane renders from the craft `build()` preview, not from captured packets.
public struct L4Packet: Hashable, Sendable, Identifiable {
    public enum Direction: String, Sendable, Hashable { case inbound, outbound }

    public let index: Int
    public let dir: Direction
    public let length: Int
    public let injected: Bool
    /// Decoded layer names, outermost first (`Ethernet` → `IPv4`/`IPv6` → `TCP`/…).
    public let layers: [String]

    public var id: Int { index }

    /// The one-line decoded summary shown in the packet list.
    public var summary: String {
        let names = layers.isEmpty ? "raw" : layers.joined(separator: " · ")
        return "\(names) · \(length) B"
    }

    public init(index: Int, dir: Direction, length: Int, injected: Bool, layers: [String]) {
        self.index = index
        self.dir = dir
        self.length = length
        self.injected = injected
        self.layers = layers
    }

    init?(index: Int, json: JSONValue) {
        guard let dirRaw = json["dir"]?.stringValue, let dir = Direction(rawValue: dirRaw) else { return nil }
        self.index = index
        self.dir = dir
        self.length = json["length"]?.intValue ?? 0
        self.injected = json["injected"]?.boolValue ?? false
        self.layers = json["layers"]?.arrayValue?.compactMap { $0.stringValue } ?? []
    }
}

/// An L4 flow's detail (`l4.flow.get`): the bind, the session kind, the packet log
/// and the counts. Mirrors `WSDetail` for the WebSocket inspector.
public struct L4Flow: Hashable, Sendable {
    public let id: FlowID
    public let sessionState: L4SessionState
    public let interface: String
    public let filter: String?
    public let queue: Int?
    public let packetCount: Int
    public let injectedCount: Int
    public let packets: [L4Packet]

    /// The protocol sub-label, classified from the packets' layers.
    public var proto: L4Proto { L4Proto.fromLayers(packets.first?.layers ?? []) }

    public init(
        id: FlowID, sessionState: L4SessionState, interface: String, filter: String? = nil,
        queue: Int? = nil, packetCount: Int, injectedCount: Int, packets: [L4Packet]
    ) {
        self.id = id
        self.sessionState = sessionState
        self.interface = interface
        self.filter = filter
        self.queue = queue
        self.packetCount = packetCount
        self.injectedCount = injectedCount
        self.packets = packets
    }

    /// Decode an `l4.flow.get` result (`structuredContent`, or a bare object).
    public init?(json raw: JSONValue) {
        let json = raw["structuredContent"] ?? raw
        guard let id = json["id"]?.stringValue,
              let kindRaw = json["kind"]?.stringValue,
              let state = L4SessionState(rawValue: kindRaw) else { return nil }
        self.id = FlowID(id)
        self.sessionState = state
        self.interface = json["interface"]?.stringValue ?? ""
        self.filter = json["filter"]?.stringValue
        self.queue = json["queue"]?.intValue
        let packets = (json["packets"]?.arrayValue ?? []).enumerated()
            .compactMap { L4Packet(index: $0.offset, json: $0.element) }
        self.packets = packets
        self.packetCount = json["packet_count"]?.intValue ?? packets.count
        self.injectedCount = json["injected_count"]?.intValue ?? packets.filter(\.injected).count
    }

    /// The human-readable L4 target (`iface cidr:port ↕dir` shape; the bind is all
    /// `l4.flow.get` gives, so we show interface + filter).
    public var target: String {
        if let filter, !filter.isEmpty { return "\(interface) · \(filter)" }
        return interface.isEmpty ? "l4" : interface
    }

    /// Build the flow-list row for this L4 flow (kind `.l4`).
    public func row(seq: Int, inScope: Bool) -> FlowRow {
        FlowRow(
            id: id, seq: seq, kind: .l4, method: HTTPMethod("L4"), scheme: "l4",
            authority: target, path: "", status: nil,
            state: sessionState == .intercept ? .paused : .complete,
            origin: injectedCount > 0 ? .agent : .client,
            tls: .none, inScope: inScope,
            l4: L4RowInfo(
                proto: proto, sessionState: sessionState, target: target,
                packetCount: packetCount, injectedCount: injectedCount, inScope: inScope))
    }
}

/// The L4-specific fields a flow row carries (`FlowRow.l4`).
public struct L4RowInfo: Hashable, Sendable {
    public let proto: L4Proto
    public let sessionState: L4SessionState
    public let target: String
    public let packetCount: Int
    public let injectedCount: Int
    public let inScope: Bool

    public var subLabel: String { proto.subLabel }

    public init(
        proto: L4Proto, sessionState: L4SessionState, target: String,
        packetCount: Int, injectedCount: Int, inScope: Bool
    ) {
        self.proto = proto
        self.sessionState = sessionState
        self.target = target
        self.packetCount = packetCount
        self.injectedCount = injectedCount
        self.inScope = inScope
    }
}

// MARK: - Scope-as-authorization (AC9/AC10: dim + disable out-of-scope mutations)

/// A mutating L4 action the UI disables for an out-of-L4-scope session. Enforcement
/// is the core `L4Guard`; the UI's dimming/disabling is the courtesy that makes it
/// visible (and never a side channel to the wire).
public enum L4MutatingAction: String, CaseIterable, Sendable {
    case craft, inject, forward, drop
}

/// Whether the mutating L4 actions are enabled, from the session's scope. Out of
/// scope: every craft/inject/forward/drop action is disabled with the scope reason.
public struct L4ActionGate: Hashable, Sendable {
    public let inScope: Bool

    public init(inScope: Bool) { self.inScope = inScope }

    public func isEnabled(_ action: L4MutatingAction) -> Bool { inScope }
    public var injectEnabled: Bool { isEnabled(.inject) }

    /// The tooltip shown on a disabled action, or nil when enabled.
    public var disabledReason: String? {
        inScope ? nil
            : "Out of L4 scope — add an L4 scope entry (operator-confirmed) to authorize "
                + "capture, craft, inject and intercept on this target."
    }
}

// MARK: - Guarded inject + confirm-over-the-wire (AC10)

/// The operator confirm dialog's content, parsed from the M4 `needs_confirmation`
/// tool result (`aitm-mcp::server::needs_confirmation`): a wire summary (destination
/// + PacketSummary + count + scope + permit budget) and a single-use token the
/// operator re-issues the identical call with (`_confirm`).
public struct L4ConfirmRequest: Hashable, Sendable {
    public let prompt: String
    public let token: String

    public init(prompt: String, token: String) {
        self.prompt = prompt
        self.token = token
    }

    /// Parse a `needs_confirmation` result; nil for any other outcome (a plain
    /// success or an error is not a confirm dialog).
    public init?(json raw: JSONValue) {
        let json = raw["structuredContent"] ?? raw
        guard json["status"]?.stringValue == "needs_confirmation",
              let prompt = json["prompt"]?.stringValue,
              let token = json["confirm_token"]?.stringValue else { return nil }
        self.prompt = prompt
        self.token = token
    }
}

/// The outcome of issuing `l4.inject` without `_confirm`: a confirm handshake, a
/// guard refusal (surfaced verbatim), or a plain result.
public struct L4InjectOutcome: Sendable {
    public let confirm: L4ConfirmRequest?
    public let error: String?

    public init(confirm: L4ConfirmRequest?, error: String?) {
        self.confirm = confirm
        self.error = error
    }

    public var needsConfirmation: Bool { confirm != nil }
    /// A guard refusal (out-of-scope, rate, denylist, oversize, count) — never a dialog.
    public var isRefusal: Bool { confirm == nil && error != nil }
    public var refusalText: String? { isRefusal ? error : nil }
}

// MARK: - Availability from the core (L4PAR-AC26; spec §1, Decision 9)

/// Whether the core this app talks to can drive the L4 wire, read from the core's
/// own `l4.capture.status` / `l4.intercept.status` reply (spec §1) and never from a
/// guess about what kind of core it is. The surface always renders; degradation is
/// per wire verb, with the core's `reason` quoted. Until the first reply arrives the
/// value is `.pending`, and the UI shows `Reading L4 availability…`.
public enum L4Availability: Hashable, Sendable {
    /// No status reply has been read yet (first poll outstanding).
    case pending
    case available
    case degraded(reason: String)

    /// The marker the gated verbs put in front of their reason (`L4 unavailable: X`).
    /// A status error carrying it degrades with just `X`.
    public static let unavailableMarker = "L4 unavailable: "

    /// The one pending literal shared by the TUI, the web UI and this app.
    public static let pendingText = "Reading L4 availability…"

    /// Resolve availability from one status verb's reply.
    ///
    /// - An object with a bool `available`: `true` ⇒ `.available`; `false` ⇒
    ///   `.degraded(reason:)` with the object's `reason`, or `L4 unavailable` when
    ///   the core sent none. The object may be wrapped in `structuredContent`.
    /// - A bare array (an older core's payload-only reply) ⇒ `.available`.
    /// - No usable status and an `error` containing `L4 unavailable: X` (an older
    ///   core's gated verb) ⇒ `.degraded(reason: "X")`.
    /// - Neither ⇒ `.pending`.
    public static func resolve(status: JSONValue?, error: String?) -> L4Availability {
        if let raw = status {
            let json = raw["structuredContent"] ?? raw
            if let available = json["available"]?.boolValue {
                if available { return .available }
                let reason = json["reason"]?.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines)
                return .degraded(reason: reason.flatMap { $0.isEmpty ? nil : $0 } ?? "L4 unavailable")
            }
            if json.arrayValue != nil { return .available }
        }
        if let error, let range = error.range(of: unavailableMarker) {
            let reason = error[range.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
            return .degraded(reason: reason.isEmpty ? "L4 unavailable" : reason)
        }
        return .pending
    }

    /// The text a surface renders for this state: the pending literal while the
    /// first reply is outstanding, the core's reason when degraded, nil when
    /// available (nothing to say).
    public var displayText: String? {
        switch self {
        case .pending: Self.pendingText
        case .degraded(let reason): reason
        case .available: nil
        }
    }

    /// The surface always renders (capture/scope/craft work locally); degradation is
    /// per wire verb, not a blank screen.
    public var rendersSurface: Bool { true }
    /// Only a confirmed `.available` drives the wire; `.pending` does not.
    public var canDriveWire: Bool { self == .available }
    /// The core's reason when degraded; nil when available or pending.
    public var reason: String? {
        if case let .degraded(reason) = self { return reason }
        return nil
    }

    // Kept for Session.swift / L4Inspector.swift until M4a rewires them to
    // `resolve(status:error:)`; M4a deletes both members.
    public static let embeddedReason =
        "Raw L4 capture and injection need a privileged core. This app's embedded core runs as "
        + "you and cannot open raw sockets, /dev/bpf or NFQUEUE. A macOS Network/System Extension "
        + "(Phase 2) will provide the local capture path; until then, point the app at a privileged "
        + "core (Linux, elevated, or remote) over the bus to drive L4."

    // Kept for Session.swift until M4a; M4a deletes it.
    public static func resolve(embeddedCore: Bool, wireError: String?) -> L4Availability {
        if embeddedCore { return .degraded(reason: embeddedReason) }
        if let wireError, wireError.lowercased().contains("l4 unavailable") {
            return .degraded(reason: wireError)
        }
        return .available
    }
}

// MARK: - Parked packets and verdicts (L4PAR-AC28; spec §4, Decision 3)

/// One parked packet from `l4.intercept.list`: the parked id the verdict verbs
/// take, the flow it belongs to, its state, byte length, decoded layer names and
/// when the core parked it (`parked_at`, epoch milliseconds). The core lists
/// parked packets in arrival order, oldest first.
public struct L4ParkedPacket: Hashable, Sendable, Identifiable {
    public let id: String
    public let flow: FlowID
    public let state: String
    public let length: Int
    public let layers: [String]
    public let parkedAt: Date?

    public init(id: String, flow: FlowID, state: String, length: Int, layers: [String], parkedAt: Date?) {
        self.id = id
        self.flow = flow
        self.state = state
        self.length = length
        self.layers = layers
        self.parkedAt = parkedAt
    }

    /// Decode one list entry; nil without an `id` and a `flow` (nothing to act on).
    init?(json: JSONValue) {
        guard let id = json["id"]?.stringValue, let flow = json["flow"]?.stringValue else { return nil }
        self.id = id
        self.flow = FlowID(flow)
        self.state = json["state"]?.stringValue ?? ""
        self.length = json["length"]?.intValue ?? 0
        self.layers = json["layers"]?.arrayValue?.compactMap { $0.stringValue } ?? []
        self.parkedAt = json["parked_at"]?.doubleValue.map { Date(timeIntervalSince1970: $0 / 1000) }
    }

    /// Parse an `l4.intercept.list` reply (a bare array, or `{structuredContent: [...]}`)
    /// in the core's order. A reply that is not a list yields no packets.
    public static func list(_ raw: JSONValue) -> [L4ParkedPacket] {
        let json = raw["structuredContent"] ?? raw
        return (json.arrayValue ?? []).compactMap { L4ParkedPacket(json: $0) }
    }

    /// The first listed parked packet for `flow`, the oldest, which is the one the
    /// intercept bar acts on by default (Decision 3).
    public static func first(for flow: FlowID, in parked: [L4ParkedPacket]) -> L4ParkedPacket? {
        parked.first { $0.flow == flow }
    }
}

/// Arguments for the parked-packet verdict verbs (`l4.intercept.forward` / `.drop`
/// / `.mutate` / `.revert`): they act on a parked id, never on a flow id.
public enum L4Verdict {
    /// `{id: <parked id>}`; Mutate adds `spec` beside it.
    public static func args(parkedID: String) -> [String: JSONValue] {
        ["id": .string(parkedID)]
    }
}

// MARK: - Per-capability agent gates (AC11)

/// The four per-capability agent gate states read from `l4.agent.status`
/// (`aitm-proto-l4::commands::agent`): the toggles reflect the `l4.allow_agent_*`
/// gates that actually govern the agent (MCP) L4 path. An agent can never flip its
/// own — the `l4.agent.set` setter is operator-only — so these toggles are operator
/// -driven, and read-only when the setter is absent.
public struct L4AgentGates: Hashable, Sendable {
    /// One L4 capability the operator gates for the agent. Order matches the Agent
    /// panel's toggle column.
    public enum Capability: String, CaseIterable, Sendable {
        case capture, inject, intercept, widen

        public var title: String {
            switch self {
            case .capture: "Capture"
            case .inject: "Inject"
            case .intercept: "Intercept"
            case .widen: "Widen scope"
            }
        }
    }

    public var capture: Bool
    public var inject: Bool
    public var intercept: Bool
    public var widen: Bool

    public init(capture: Bool, inject: Bool, intercept: Bool, widen: Bool) {
        self.capture = capture
        self.inject = inject
        self.intercept = intercept
        self.widen = widen
    }

    /// Parse `l4.agent.status` / `.set` result. All four gates must be present; a
    /// malformed status does not fabricate gates.
    public init?(json raw: JSONValue) {
        let json = raw["structuredContent"] ?? raw
        guard let capture = json["capture"]?.boolValue,
              let inject = json["inject"]?.boolValue,
              let intercept = json["intercept"]?.boolValue,
              let widen = json["widen"]?.boolValue else { return nil }
        self.capture = capture
        self.inject = inject
        self.intercept = intercept
        self.widen = widen
    }

    public func allowed(_ capability: Capability) -> Bool {
        switch capability {
        case .capture: capture
        case .inject: inject
        case .intercept: intercept
        case .widen: widen
        }
    }

    /// Whether the operator may toggle the gates: only when the core exposes the
    /// operator-only `l4.agent.set` setter; otherwise the toggle is read-only with
    /// a "set in config and restart" note (honest gating).
    public static func togglable(setterPresent: Bool) -> Bool { setterPresent }
}

// MARK: - Craft editor (AC8: human-friendly YAML PacketSpec + build() preview)

/// A bounded parser for the human-friendly YAML `PacketSpec` the craft editor
/// authors (the project's human-friendly-scripting rule: readable, not agent-only).
/// It handles exactly the `PacketSpec` shape — a `layers:` list whose items are
/// single-key maps (`ipv4:` / `udp:` / `tcp:` / `icmp:` / `ether:` / `ipv6:` /
/// `raw:`) of scalar `key: value` fields — and produces the `{layers: […]}` object
/// `l4.craft` expects. The core validates the spec; this only shapes it.
public enum PacketSpecDraft {
    public static func parse(_ yaml: String) -> JSONValue? {
        var lines: [(indent: Int, text: String)] = []
        for raw in yaml.split(separator: "\n", omittingEmptySubsequences: false) {
            let stripped = stripComment(String(raw))
            if stripped.trimmingCharacters(in: .whitespaces).isEmpty { continue }
            let indent = stripped.prefix { $0 == " " }.count
            lines.append((indent, stripped.trimmingCharacters(in: .whitespaces)))
        }
        guard let first = lines.first, first.text == "layers:" || first.text.hasPrefix("layers:") else { return nil }

        var layers: [JSONValue] = []
        var current: (key: String, fields: [String: JSONValue])?
        func flush() {
            if let current { layers.append(.object([current.key: .object(current.fields)])) }
        }
        for line in lines.dropFirst() {
            if line.text.hasPrefix("- ") {
                // A new layer item: `- udp:` (optionally with a field on the same line).
                flush()
                current = nil
                let item = String(line.text.dropFirst(2))
                if let key = layerKey(item) {
                    current = (key, [:])
                } else { return nil }
            } else if var current0 = current, let (k, v) = scalar(line.text) {
                current0.fields[k] = v
                current = current0
            }
            // Lines that are neither a `- ` item nor a scalar under one are ignored.
        }
        flush()
        guard !layers.isEmpty else { return nil }
        return .object(["layers": .array(layers)])
    }

    /// `udp:` or `udp: {…}` → the layer key when it names a known layer.
    private static func layerKey(_ item: String) -> String? {
        guard let colon = item.firstIndex(of: ":") else { return nil }
        let key = String(item[..<colon]).trimmingCharacters(in: .whitespaces).lowercased()
        let known = ["ether", "ipv4", "ipv6", "tcp", "udp", "icmp", "raw"]
        return known.contains(key) ? key : nil
    }

    /// `src: 127.0.0.1` / `dport: 9` / `data: "hi"` → a key and a typed scalar.
    private static func scalar(_ text: String) -> (String, JSONValue)? {
        guard let colon = text.firstIndex(of: ":") else { return nil }
        let key = String(text[..<colon]).trimmingCharacters(in: .whitespaces)
        var value = String(text[text.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty, !value.isEmpty else { return nil }
        if value.hasPrefix("\"") && value.hasSuffix("\"") && value.count >= 2 {
            value = String(value.dropFirst().dropLast())
            return (key, .string(value))
        }
        if let i = Int(value) { return (key, .number(Double(i))) }
        if value == "true" || value == "false" { return (key, .bool(value == "true")) }
        return (key, .string(value))
    }

    private static func stripComment(_ line: String) -> String {
        // A `#` outside a quoted string begins a comment.
        var inQuote = false
        var out = ""
        for ch in line {
            if ch == "\"" { inQuote.toggle() }
            if ch == "#" && !inQuote { break }
            out.append(ch)
        }
        return out
    }
}

/// The `l4.craft` build result: the on-wire bytes (base64) and the decoded layer
/// names — rendered as the craft editor's hex preview + layer summary.
public struct L4CraftPreview: Hashable, Sendable {
    public let length: Int
    public let bytes: Data
    public let layers: [String]

    public init(length: Int, bytes: Data, layers: [String]) {
        self.length = length
        self.bytes = bytes
        self.layers = layers
    }

    public init?(json raw: JSONValue) {
        let json = raw["structuredContent"] ?? raw
        guard let b64 = json["bytes"]?.stringValue, let bytes = Data(base64Encoded: b64) else { return nil }
        self.bytes = bytes
        self.length = json["length"]?.intValue ?? bytes.count
        self.layers = json["summary"]?["layers"]?.arrayValue?.compactMap { $0.stringValue } ?? []
    }
}
