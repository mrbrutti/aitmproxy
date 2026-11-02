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
/// serializes it): direction, byte length, the decoded layer names, whether
/// aitmproxy authored and injected it, and the l4-parity §2 fields — the on-wire
/// bytes (present only for a caller the core trusts with them, §2.2), the capture
/// time, and the decoded protocol / addresses / ports. Every §2 field is optional
/// so an older core's reply (none of them) still parses.
public struct L4Packet: Hashable, Sendable, Identifiable {
    public enum Direction: String, Sendable, Hashable { case inbound, outbound }

    public let index: Int
    public let dir: Direction
    public let length: Int
    public let injected: Bool
    /// Decoded layer names, outermost first (`Ethernet` → `IPv4`/`IPv6` → `TCP`/…).
    public let layers: [String]
    /// The on-wire bytes (`bytes`, standard base64); nil when the core withheld them.
    public let bytes: Data?
    /// When the core recorded the packet (`timestamp`, epoch milliseconds).
    public let timestamp: Date?
    /// `TCP` / `UDP` / `ICMP` / `ICMPv6`, or nil when undecodable.
    public let proto: String?
    public let src: String?
    public let dst: String?
    public let srcPort: Int?
    public let dstPort: Int?

    public var id: Int { index }

    /// The one-line decoded summary shown in the packet list.
    public var summary: String {
        let names = layers.isEmpty ? "raw" : layers.joined(separator: " · ")
        return "\(names) · \(length) B"
    }

    public init(
        index: Int, dir: Direction, length: Int, injected: Bool, layers: [String],
        bytes: Data? = nil, timestamp: Date? = nil, proto: String? = nil,
        src: String? = nil, dst: String? = nil, srcPort: Int? = nil, dstPort: Int? = nil
    ) {
        self.index = index
        self.dir = dir
        self.length = length
        self.injected = injected
        self.layers = layers
        self.bytes = bytes
        self.timestamp = timestamp
        self.proto = proto
        self.src = src
        self.dst = dst
        self.srcPort = srcPort
        self.dstPort = dstPort
    }

    init?(index: Int, json: JSONValue) {
        guard let dirRaw = json["dir"]?.stringValue, let dir = Direction(rawValue: dirRaw) else { return nil }
        self.index = index
        self.dir = dir
        self.length = json["length"]?.intValue ?? 0
        self.injected = json["injected"]?.boolValue ?? false
        self.layers = json["layers"]?.arrayValue?.compactMap { $0.stringValue } ?? []
        self.bytes = json["bytes"]?.stringValue.flatMap { Data(base64Encoded: $0) }
        self.timestamp = L4Wire.date(epochMillis: json["timestamp"])
        self.proto = json["proto"]?.stringValue
        self.src = json["src"]?.stringValue
        self.dst = json["dst"]?.stringValue
        self.srcPort = json["src_port"]?.intValue
        self.dstPort = json["dst_port"]?.intValue
    }
}

/// An L4 flow's detail (`l4.flow.get`): the bind, the session kind, the packet log,
/// the counts, and the l4-parity §2 flow-level fields (`started_at` and the first
/// decodable packet's protocol / addresses / ports, so a list row shows its target
/// without reading packets). Mirrors `WSDetail` for the WebSocket inspector.
public struct L4Flow: Hashable, Sendable {
    public let id: FlowID
    public let sessionState: L4SessionState
    public let interface: String
    public let filter: String?
    public let queue: Int?
    public let packetCount: Int
    public let injectedCount: Int
    public let packets: [L4Packet]
    /// Flow creation (`started_at`, epoch milliseconds); nil from an older core.
    public let startedAt: Date?
    /// The flow-level `proto` string the core decoded (`TCP` / `UDP` / …), or nil.
    public let protoName: String?
    public let src: String?
    public let dst: String?
    public let srcPort: Int?
    public let dstPort: Int?

    /// The protocol sub-label: the core's flow-level `proto` when it sent one,
    /// otherwise classified from the first packet's layers.
    public var proto: L4Proto {
        if let protoName { return L4Proto.fromLayers([protoName]) }
        return L4Proto.fromLayers(packets.first?.layers ?? [])
    }

    public init(
        id: FlowID, sessionState: L4SessionState, interface: String, filter: String? = nil,
        queue: Int? = nil, packetCount: Int, injectedCount: Int, packets: [L4Packet],
        startedAt: Date? = nil, protoName: String? = nil, src: String? = nil, dst: String? = nil,
        srcPort: Int? = nil, dstPort: Int? = nil
    ) {
        self.id = id
        self.sessionState = sessionState
        self.interface = interface
        self.filter = filter
        self.queue = queue
        self.packetCount = packetCount
        self.injectedCount = injectedCount
        self.packets = packets
        self.startedAt = startedAt
        self.protoName = protoName
        self.src = src
        self.dst = dst
        self.srcPort = srcPort
        self.dstPort = dstPort
    }

    /// Decode an `l4.flow.get` result (`structuredContent`, or a bare object). The
    /// §2 keys are optional, so an older core's reply (without them) still parses.
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
        self.startedAt = L4Wire.date(epochMillis: json["started_at"])
        self.protoName = json["proto"]?.stringValue
        self.src = json["src"]?.stringValue
        self.dst = json["dst"]?.stringValue
        self.srcPort = json["src_port"]?.intValue
        self.dstPort = json["dst_port"]?.intValue
    }

    /// The human-readable L4 target: `<interface> → <dst>:<dstPort>` when the core
    /// sent the flow-level destination (§2), otherwise the bind's interface + filter.
    public var target: String {
        if let dst, !dst.isEmpty, let dstPort { return "\(interface) → \(dst):\(dstPort)" }
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

// MARK: - Wire capabilities and argument builders (L4PAR-AC25, AC39; spec §2, §3)

/// What the connected core's `tools/list` says the L4 wire supports, and the
/// argument builders that follow from it. Pure functions over `ToolDescriptor`s,
/// so a unit test pins each decision without a bus.
public enum L4Wire {
    /// True iff `l4.flow.get` declares a `limit` property: the core has the §2
    /// bounded window (`offset` / `limit`). Against an older core the UI omits both.
    public static func supportsWindow(_ tools: [ToolDescriptor]) -> Bool {
        guard let get = tools.first(where: { $0.name == "l4.flow.get" }) else { return false }
        return get.inputSchema["properties"]?["limit"] != nil
    }

    /// True iff `l4.scope.add` is listed with `confirmable: true` (spec §3, last
    /// rule): only then does a UI render its scope-add control. A core without the
    /// operator confirm path gets no form, not a form that can only fail.
    public static func supportsOperatorScopeAdd(_ tools: [ToolDescriptor]) -> Bool {
        tools.contains { $0.name == "l4.scope.add" && $0.confirmable }
    }

    /// The `l4.flow.get` arguments for one read. Without the window (older core):
    /// `{id}`. With it, list polling (`inspect: false`) asks `limit: 0` for the
    /// flow fields alone, and the inspector asks the first window of 256 packets.
    public static func flowGetArgs(id: FlowID, inspect: Bool, window: Bool) -> [String: JSONValue] {
        var args: [String: JSONValue] = ["id": .string(id.raw)]
        guard window else { return args }
        if inspect {
            args["offset"] = .number(0)
            args["limit"] = .number(256)
        } else {
            args["limit"] = .number(0)
        }
        return args
    }

    /// An integer epoch-milliseconds value → `Date`; nil for anything else.
    static func date(epochMillis value: JSONValue?) -> Date? {
        value?.doubleValue.map { Date(timeIntervalSince1970: $0 / 1000) }
    }
}

// MARK: - L4 scope entries and the operator add draft (L4PAR-AC30; spec §3)

/// One `l4.scope.list` entry as the core returns it: the match (cidr, ports,
/// interface, direction), the capability it authorizes, and its `source`
/// provenance (`config` from the operator's file, `runtime` added over the bus).
public struct L4ScopeItem: Hashable, Sendable, Identifiable {
    public let id: String
    public let cidr: String
    /// `lo-hi`, a single port, or `all`. An entry without `ports` matches every port.
    public let ports: String
    public let interface: String
    public let direction: String
    public let capability: String
    public let source: String

    public init(
        id: String, cidr: String, ports: String, interface: String, direction: String,
        capability: String, source: String
    ) {
        self.id = id
        self.cidr = cidr
        self.ports = ports
        self.interface = interface
        self.direction = direction
        self.capability = capability
        self.source = source
    }

    /// Decode one list entry; nil without an `id` (nothing to show or remove).
    init?(json: JSONValue) {
        guard let id = json["id"]?.stringValue else { return nil }
        self.id = id
        self.cidr = json["cidr"]?.stringValue ?? ""
        let ports = json["ports"]?.stringValue?.trimmingCharacters(in: .whitespaces) ?? ""
        self.ports = ports.isEmpty ? "all" : ports
        self.interface = json["interface"]?.stringValue ?? ""
        self.direction = json["direction"]?.stringValue ?? ""
        self.capability = json["capability"]?.stringValue ?? ""
        self.source = json["source"]?.stringValue ?? ""
    }

    /// Parse an `l4.scope.list` reply (a bare array, or `{structuredContent: [...]}`)
    /// in the core's order. A reply that is not a list yields no entries.
    public static func list(_ raw: JSONValue) -> [L4ScopeItem] {
        let json = raw["structuredContent"] ?? raw
        return (json.arrayValue ?? []).compactMap { L4ScopeItem(json: $0) }
    }

    /// Whether this entry covers a destination: the same interface, `dst` inside
    /// `cidr`, and `port` inside `ports` (or `ports` is all, or no port is known).
    /// The CIDR check is an IPv4 prefix match over the four octets; an IPv6 or
    /// unparsable `dst` matches only when the entry is literally `<dst>/32`.
    public func covers(interface: String, dst: String, port: Int?) -> Bool {
        guard interface == self.interface else { return false }
        guard Self.cidrContains(cidr, address: dst) else { return false }
        guard let port else { return true }
        return Self.portsContain(ports, port: port)
    }

    static func cidrContains(_ cidr: String, address: String) -> Bool {
        let parts = cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let network = String(parts.first ?? "")
        let prefix = parts.count == 2 ? Int(parts[1]) : 32
        guard let prefix, (0...32).contains(prefix) else { return false }
        guard let net = Self.ipv4(network), let addr = Self.ipv4(address) else {
            // Not IPv4 on one side: only an exact /32 literal of the address matches.
            return prefix == 32 && network == address
        }
        if prefix == 0 { return true }
        let mask: UInt32 = prefix == 32 ? .max : ~((1 << (32 - UInt32(prefix))) - 1)
        return (net & mask) == (addr & mask)
    }

    /// Four dotted decimal octets → a 32-bit value; nil for anything else.
    static func ipv4(_ text: String) -> UInt32? {
        let octets = text.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return nil }
        var value: UInt32 = 0
        for octet in octets {
            guard !octet.isEmpty, octet.allSatisfy(\.isNumber), let n = UInt32(octet), n <= 255 else { return nil }
            value = (value << 8) | n
        }
        return value
    }

    static func portsContain(_ ports: String, port: Int) -> Bool {
        let text = ports.trimmingCharacters(in: .whitespaces)
        if text.isEmpty || text.lowercased() == "all" { return true }
        let bounds = text.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        guard let lo = Int(bounds[0].trimmingCharacters(in: .whitespaces)) else { return false }
        if bounds.count == 1 { return port == lo }
        guard let hi = Int(bounds[1].trimmingCharacters(in: .whitespaces)) else { return false }
        return (min(lo, hi)...max(lo, hi)).contains(port)
    }
}

/// The operator's scope-add form, as the `l4.scope.add` arguments (AC5): exactly
/// `cidr`, `ports`, `interface`, `direction`, `capability`; `ports` is omitted when
/// empty (the core then says `all ports` in its prompt). The core validates every
/// value and confirms the add over the wire; this only shapes the call.
public struct L4ScopeDraft: Hashable, Sendable {
    public var cidr: String
    public var ports: String
    public var interface: String
    public var direction: String
    public var capability: String

    public init(cidr: String, ports: String, interface: String, direction: String, capability: String) {
        self.cidr = cidr
        self.ports = ports
        self.interface = interface
        self.direction = direction
        self.capability = capability
    }

    public var args: [String: JSONValue] {
        var args: [String: JSONValue] = [
            "cidr": .string(cidr),
            "interface": .string(interface),
            "direction": .string(direction),
            "capability": .string(capability),
        ]
        let ports = ports.trimmingCharacters(in: .whitespaces)
        if !ports.isEmpty { args["ports"] = .string(ports) }
        return args
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
/// single-key maps (`ipv4:` / `udp:` / `tcp:` / `icmp:` / `ether:` / `ipv6:`) of
/// scalar `key: value` fields, plus a `raw:` layer whose value is a scalar — a
/// quoted UTF-8 string or a `[n, n, …]` byte list — and produces the
/// `{layers: […]}` object `l4.craft` expects, with `raw` as a JSON integer list
/// (the core's `Layer::Raw(Vec<u8>)`). The core validates the spec; this only
/// shapes it.
public enum PacketSpecDraft {
    /// The craft editor's starting text (L4PAR-AC27): the spec `l4.craft` accepts,
    /// with the core's `PacketSpec` field names (`src_port` / `dst_port`, never
    /// `sport` / `dport`) and the payload as a `raw` scalar. The core builds it to
    /// 36 bytes (20 IPv4 + 8 UDP + 8 payload).
    public static let sample = """
    layers:
      - ipv4:
          src: 127.0.0.1
          dst: 127.0.0.1
      - udp:
          src_port: 40000
          dst_port: 9
      - raw: "hello-l4"
    """

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
        // A layer under construction: a map of scalar fields, or — for a scalar
        // `raw:` — the byte list itself.
        var current: (key: String, fields: [String: JSONValue], scalar: JSONValue?)?
        func flush() {
            guard let current else { return }
            layers.append(.object([current.key: current.scalar ?? .object(current.fields)]))
        }
        for line in lines.dropFirst() {
            if line.text.hasPrefix("- ") {
                // A new layer item: `- udp:` (fields follow, indented) or
                // `- raw: "payload"` / `- raw: [1, 2]` (the value on the same line).
                flush()
                current = nil
                let item = String(line.text.dropFirst(2))
                guard let (key, inline) = layerKey(item) else { return nil }
                if key == "raw", !inline.isEmpty {
                    guard let bytes = rawBytes(inline) else { return nil }
                    current = (key, [:], bytes)
                } else {
                    current = (key, [:], nil)
                }
            } else if var current0 = current, current0.scalar == nil, let (k, v) = scalar(line.text) {
                current0.fields[k] = v
                current = current0
            }
            // Lines that are neither a `- ` item nor a scalar under one are ignored.
        }
        flush()
        guard !layers.isEmpty else { return nil }
        return .object(["layers": .array(layers)])
    }

    /// `udp:` or `raw: "hi"` → the layer key when it names a known layer, and
    /// whatever follows the colon on the same line (trimmed; empty for `udp:`).
    private static func layerKey(_ item: String) -> (key: String, inline: String)? {
        guard let colon = item.firstIndex(of: ":") else { return nil }
        let key = String(item[..<colon]).trimmingCharacters(in: .whitespaces).lowercased()
        let known = ["ether", "ipv4", "ipv6", "tcp", "udp", "icmp", "raw"]
        guard known.contains(key) else { return nil }
        let inline = String(item[item.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        return (key, inline)
    }

    /// A `raw` payload scalar → its bytes as JSON integers: `"hello"` is the
    /// string's UTF-8; `[104, 105]` is taken as written, each member an integer in
    /// `0...255`. Anything else (an unquoted word, a float, an out-of-range
    /// member) is not a payload, and the draft fails rather than reaching the core.
    private static func rawBytes(_ text: String) -> JSONValue? {
        if text.hasPrefix("\"") && text.hasSuffix("\"") && text.count >= 2 {
            let payload = String(text.dropFirst().dropLast())
            return .array(payload.utf8.map { .number(Double($0)) })
        }
        if text.hasPrefix("[") && text.hasSuffix("]") && text.count >= 2 {
            var bytes: [JSONValue] = []
            for part in text.dropFirst().dropLast().split(separator: ",", omittingEmptySubsequences: true) {
                guard let n = Int(part.trimmingCharacters(in: .whitespaces)), (0...255).contains(n) else { return nil }
                bytes.append(.number(Double(n)))
            }
            return .array(bytes)
        }
        return nil
    }

    /// `src: 127.0.0.1` / `dst_port: 9` / `flags: "syn"` → a key and a typed scalar.
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
