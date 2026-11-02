import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

// The macOS L4 operator surface (ui-scripting-highlight-l4 Part 3 §3.1–3.2;
// l4-operator-surfaces Part 3, L4OPS-AC7–AC12/AC16/AC18). These exercise the
// pure-Kit seams the SwiftUI surface renders against, so the five named tests
// are deterministic without a live bus.

@Suite struct L4FlowKindTests {
    /// `every_kind_renders` (L4OPS-AC7): every known kind — http, websocket, l4 —
    /// describes to a non-placeholder badge, and an absent/unknown kind describes
    /// to a *labelled* placeholder, never an empty one.
    @Test func every_kind_renders() {
        for kind in FlowKind.allCases {
            let d = FlowKindDescriptor.describe(kind.rawValue)
            #expect(d.kind == kind)
            #expect(!d.isPlaceholder)
            #expect(!d.badgeLabel.isEmpty)
        }
        #expect(FlowKindDescriptor.describe("l4").badgeLabel == "L4")
        #expect(FlowKindDescriptor.describe("websocket").badgeLabel == "WS")

        // A kind the surface does not know (a newer core protocol) still renders:
        // a labelled placeholder row, never nothing.
        let unknown = FlowKindDescriptor.describe("quic")
        #expect(unknown.kind == nil)
        #expect(unknown.isPlaceholder)
        #expect(!unknown.badgeLabel.isEmpty)
        #expect(unknown.badgeLabel == "QUIC")

        // An absent kind (empty / missing) still renders a labelled placeholder.
        let absent = FlowKindDescriptor.describe("")
        #expect(absent.isPlaceholder)
        #expect(!absent.badgeLabel.isEmpty)
    }

    /// An `l4.flow.get` summary parses into a row carrying the L4 target, the
    /// session state, the TCP/UDP/ICMP sub-label and the packet / injected counts.
    @Test func l4FlowGetParsesIntoARow() throws {
        let json = JSONValue.object([
            "id": .string("a1b2"),
            "kind": .string("capture"),
            "interface": .string("lo0"),
            "filter": .string("udp port 9"),
            "queue": .null,
            "packet_count": .number(3),
            "injected_count": .number(1),
            "packets": .array([
                .object(["dir": .string("outbound"), "length": .number(42), "injected": .bool(true),
                         "layers": .array([.string("IPv4"), .string("UDP")])]),
                .object(["dir": .string("inbound"), "length": .number(40), "injected": .bool(false),
                         "layers": .array([.string("IPv4"), .string("UDP")])]),
            ]),
        ])
        let flow = try #require(L4Flow(json: json))
        #expect(flow.sessionState == .capture)
        #expect(flow.interface == "lo0")
        #expect(flow.packetCount == 3)
        #expect(flow.injectedCount == 1)
        #expect(flow.proto == .udp)
        #expect(flow.packets.count == 2)
        #expect(flow.packets[0].injected)
        #expect(flow.packets[0].layers == ["IPv4", "UDP"])

        let row = flow.row(seq: 7, inScope: true)
        #expect(row.kind == .l4)
        #expect(row.seq == 7)
        let info = try #require(row.l4)
        #expect(info.proto == .udp)
        #expect(info.subLabel == "UDP")
        #expect(info.packetCount == 3)
        #expect(info.injectedCount == 1)
        #expect(info.target.contains("lo0"))
    }
}

@Suite struct L4ScopeGateTests {
    /// `out_of_scope_inject_disabled` (L4OPS-AC9/AC10): the UI disables every
    /// mutating L4 action (craft/inject/forward/drop) for an out-of-L4-scope
    /// session and surfaces the scope reason; an in-scope session allows them.
    @Test func out_of_scope_inject_disabled() {
        let inScope = L4ActionGate(inScope: true)
        #expect(inScope.injectEnabled)
        #expect(inScope.disabledReason == nil)
        for action in L4MutatingAction.allCases {
            #expect(inScope.isEnabled(action))
        }

        let outOfScope = L4ActionGate(inScope: false)
        #expect(!outOfScope.injectEnabled)
        for action in L4MutatingAction.allCases {
            #expect(!outOfScope.isEnabled(action))
        }
        let reason = outOfScope.disabledReason
        #expect(reason != nil)
        #expect(reason?.lowercased().contains("scope") == true)
    }
}

@Suite struct L4ConfirmTests {
    /// `inject_shows_confirm` (L4OPS-AC10): a `needs_confirmation` tool result
    /// (the M4 confirm-over-the-wire handshake) parses into the operator confirm
    /// dialog's prompt + single-use token; the operator re-issues the identical
    /// call carrying `_confirm`. A guard refusal is surfaced verbatim, never as a
    /// confirm dialog.
    @Test func inject_shows_confirm() throws {
        let pending = JSONValue.object([
            "status": .string("needs_confirmation"),
            "prompt": .string("Inject 1× IPv4/UDP (42 B) to 127.0.0.1:9 on lo0 — in scope lo0 "
                + "127.0.0.1/32 · permit budget 9 left. Re-send with _confirm to proceed."),
            "confirm_token": .string("tok-7f1c"),
        ])
        let request = try #require(L4ConfirmRequest(json: pending))
        #expect(request.token == "tok-7f1c")
        #expect(request.prompt.contains("127.0.0.1:9"))
        #expect(request.prompt.contains("permit budget"))

        // A plain success (no confirmation needed) is not a confirm dialog.
        #expect(L4ConfirmRequest(json: .object(["status": .string("ok")])) == nil)
        #expect(L4ConfirmRequest(json: .string("done")) == nil)

        // A guard refusal is an error surfaced verbatim, not a dialog.
        let refusal = "l4.inject refused: OutOfL4Scope — 10.0.0.5:80 is not in the L4 scope."
        let outcome = L4InjectOutcome(confirm: L4ConfirmRequest(json: .string(refusal)), error: refusal)
        #expect(outcome.isRefusal)
        #expect(outcome.refusalText == refusal)
    }
}

@Suite struct L4AvailabilityTests {
    /// L4PAR-AC26 (Kit): availability comes from the core's `l4.capture.status` /
    /// `l4.intercept.status` reply (spec §1), never from a guess about the core.
    /// The AC3 object maps to `.degraded(reason)`; `{available: true}` and an
    /// older core's bare array map to `.available`; a tool error carrying
    /// `L4 unavailable: X` keeps only `X` (Decision 9); no reply at all is
    /// `.pending` with the shared literal `Reading L4 availability…`.
    @Test func testResolveReadsStatusObject() {
        let unavailable = JSONValue.object([
            "available": .bool(false),
            "code": .string("needs_privilege"),
            "reason": .string("X"),
            "captures": .array([]),
        ])
        #expect(L4Availability.resolve(status: unavailable, error: nil) == .degraded(reason: "X"))
        #expect(L4Availability.resolve(status: unavailable, error: nil).reason == "X")
        #expect(!L4Availability.resolve(status: unavailable, error: nil).canDriveWire)
        #expect(L4Availability.resolve(status: unavailable, error: nil).rendersSurface)

        // `available: false` with no reason still degrades, with a non-empty reason.
        #expect(L4Availability.resolve(status: .object(["available": .bool(false)]), error: nil)
            == .degraded(reason: "L4 unavailable"))

        // The status object may arrive wrapped in `structuredContent`.
        let wrapped = JSONValue.object(["structuredContent": unavailable])
        #expect(L4Availability.resolve(status: wrapped, error: nil) == .degraded(reason: "X"))

        let available = L4Availability.resolve(status: .object(["available": .bool(true)]), error: nil)
        #expect(available == .available)
        #expect(available.canDriveWire)
        #expect(available.reason == nil)

        // An older core answers the status verbs with the bare payload array.
        #expect(L4Availability.resolve(status: .array([]), error: nil) == .available)
        #expect(L4Availability.resolve(status: .array([.string("f1")]), error: nil) == .available)

        // An older core's gated error: keep only the text after the marker.
        #expect(L4Availability.resolve(status: nil, error: "l4.capture.status: L4 unavailable: X")
            == .degraded(reason: "X"))
        // The status reply wins over a stale error.
        #expect(L4Availability.resolve(status: .object(["available": .bool(true)]), error: "L4 unavailable: X")
            == .available)
        // An unrelated error is not an availability verdict.
        #expect(L4Availability.resolve(status: nil, error: "connection refused") == .pending)

        let pending = L4Availability.resolve(status: nil, error: nil)
        #expect(pending == .pending)
        #expect(pending.displayText == "Reading L4 availability…")
        #expect(!pending.canDriveWire)
        #expect(pending.rendersSurface)
        #expect(pending.reason == nil)
    }
}

@Suite struct L4ParkedPacketTests {
    /// L4PAR-AC28 (Kit): Forward / Drop / Mutate / Revert act on a parked packet
    /// by its parked id (spec §4), so the args builder carries exactly `{id}`.
    @Test func testVerdictArgsCarryParkedID() {
        #expect(L4Verdict.args(parkedID: "P1") == ["id": .string("P1")])
        #expect(L4Verdict.args(parkedID: "P1").count == 1)
    }

    /// `l4.intercept.list` lists parked packets oldest first (Decision 3); the
    /// bar acts on the first listed entry for the selected flow.
    @Test func testParkedListAndFirst() throws {
        let reply = JSONValue.object([
            "structuredContent": .array([
                .object([
                    "id": .string("P1"), "flow": .string("F"), "state": .string("parked"),
                    "length": .number(60), "layers": .array([.string("IPv4"), .string("TCP")]),
                    "parked_at": .number(1_761_955_200_000),
                ]),
                .object([
                    "id": .string("P2"), "flow": .string("G"), "state": .string("parked"),
                    "length": .number(42), "layers": .array([.string("IPv4"), .string("UDP")]),
                    "parked_at": .number(1_761_955_200_500),
                ]),
                .object([
                    "id": .string("P3"), "flow": .string("G"), "state": .string("parked"),
                    "length": .number(43), "layers": .array([.string("IPv4"), .string("UDP")]),
                    "parked_at": .number(1_761_955_201_000),
                ]),
            ]),
        ])
        let parked = L4ParkedPacket.list(reply)
        #expect(parked.map(\.id) == ["P1", "P2", "P3"])
        #expect(parked[0].flow == FlowID("F"))
        #expect(parked[0].state == "parked")
        #expect(parked[0].length == 60)
        #expect(parked[0].layers == ["IPv4", "TCP"])
        #expect(parked[0].parkedAt == Date(timeIntervalSince1970: 1_761_955_200))
        #expect(parked[1].parkedAt == Date(timeIntervalSince1970: 1_761_955_200.5))

        // The first listed entry for G is P2 (oldest), not P3.
        let g = try #require(L4ParkedPacket.first(for: FlowID("G"), in: parked))
        #expect(g.id == "P2")
        #expect(L4ParkedPacket.first(for: FlowID("F"), in: parked)?.id == "P1")
        #expect(L4ParkedPacket.first(for: FlowID("H"), in: parked) == nil)

        // A bare array (an older core) parses the same; an entry without an id or
        // flow is skipped, and a non-list reply is empty.
        let bare = JSONValue.array([
            .object(["id": .string("P9"), "flow": .string("F")]),
            .object(["flow": .string("F")]),
            .object(["id": .string("P10")]),
        ])
        let bareParsed = L4ParkedPacket.list(bare)
        #expect(bareParsed.map(\.id) == ["P9"])
        #expect(bareParsed[0].length == 0)
        #expect(bareParsed[0].layers == [])
        #expect(bareParsed[0].parkedAt == nil)
        #expect(L4ParkedPacket.list(.object(["available": .bool(false)])).isEmpty)
    }
}

@Suite struct L4AgentGateTests {
    /// `toggle_reflects_gate` (L4OPS-AC11): each per-capability toggle reflects the
    /// governing `l4.allow_agent_*` gate read from `l4.agent.status`; an agent can
    /// never flip its own (the setter is operator-only, so the toggle is operator
    /// -driven, and read-only when `l4.agent.set` is absent).
    @Test func toggle_reflects_gate() throws {
        let status = JSONValue.object([
            "capture": .bool(true),
            "inject": .bool(false),
            "intercept": .bool(false),
            "widen": .bool(true),
        ])
        let gates = try #require(L4AgentGates(json: status))
        #expect(gates.allowed(.capture))
        #expect(!gates.allowed(.inject))
        #expect(!gates.allowed(.intercept))
        #expect(gates.allowed(.widen))

        #expect(L4AgentGates.Capability.allCases.map(\.rawValue)
            == ["capture", "inject", "intercept", "widen"])

        // Setter present ⇒ the operator may toggle; absent ⇒ read-only with a note.
        #expect(L4AgentGates.togglable(setterPresent: true))
        #expect(!L4AgentGates.togglable(setterPresent: false))

        // A malformed status does not fabricate gates.
        #expect(L4AgentGates(json: .object(["capture": .bool(true)])) == nil)
    }
}

@Suite struct L4CraftTests {
    /// The craft editor authors a human-friendly YAML `PacketSpec`; it parses into
    /// the `{layers: […]}` object `l4.craft` builds (AC8). Human-authored, not
    /// agent-only (the project's human-friendly-scripting rule).
    @Test func packetSpecYAMLParses() throws {
        let yaml = """
        layers:
          - ipv4:
              src: 127.0.0.1
              dst: 127.0.0.1
          - udp:
              sport: 40000
              dport: 9
          - raw:
              data: "hello"
        """
        let value = try #require(PacketSpecDraft.parse(yaml))
        let layers = try #require(value["layers"]?.arrayValue)
        #expect(layers.count == 3)
        #expect(layers[0].objectValue?.keys.contains("ipv4") == true)
        #expect(layers[1]["udp"]?["dport"]?.intValue == 9)
        #expect(layers[2]["raw"]?["data"]?.stringValue == "hello")
        // Empty / malformed drafts fail cleanly rather than crafting nothing.
        #expect(PacketSpecDraft.parse("") == nil)
        #expect(PacketSpecDraft.parse("not: a packet") == nil)
    }

    /// The `l4.craft` result (bytes base64 + a layer summary) renders a hex preview
    /// and the decoded layer names.
    @Test func craftResultRendersHexAndLayers() throws {
        let result = JSONValue.object([
            "length": .number(4),
            "bytes": .string(Data([0xde, 0xad, 0xbe, 0xef]).base64EncodedString()),
            "summary": .object(["layers": .array([.string("IPv4"), .string("UDP")]), "length": .number(4)]),
        ])
        let preview = try #require(L4CraftPreview(json: result))
        #expect(preview.length == 4)
        #expect(preview.layers == ["IPv4", "UDP"])
        #expect(preview.bytes == Data([0xde, 0xad, 0xbe, 0xef]))
        #expect(!HexDump.lines(preview.bytes).isEmpty)
    }
}

@Suite struct L4Section2Tests {
    /// Spec §2: an `l4.flow.get` packet carries `bytes` (standard base64 →
    /// `Data`), `timestamp` (epoch ms → `Date`), `proto`, `src`/`dst` and
    /// `src_port`/`dst_port`; the old four fields stay.
    @Test func testPacketParsesSection2Fields() throws {
        let json = JSONValue.object([
            "id": .string("F1"),
            "kind": .string("capture"),
            "interface": .string("lo0"),
            "packets": .array([
                .object([
                    "dir": .string("inbound"), "length": .number(2), "injected": .bool(false),
                    "layers": .array([.string("IPv4"), .string("UDP")]),
                    "bytes": .string("3q0="),
                    "timestamp": .number(1_700_000_000_123),
                    "proto": .string("UDP"),
                    "src": .string("127.0.0.1"), "dst": .string("127.0.0.1"),
                    "src_port": .number(40000), "dst_port": .number(9053),
                ]),
            ]),
        ])
        let flow = try #require(L4Flow(json: json))
        let packet = try #require(flow.packets.first)
        #expect(packet.bytes == Data([0xde, 0xad]))
        let ts = try #require(packet.timestamp)
        #expect((ts.timeIntervalSince1970 * 1000).rounded() == 1_700_000_000_123)
        #expect(packet.proto == "UDP")
        #expect(packet.src == "127.0.0.1")
        #expect(packet.dst == "127.0.0.1")
        #expect(packet.srcPort == 40000)
        #expect(packet.dstPort == 9053)
        #expect(packet.length == 2)
        #expect(packet.dir == .inbound)
        #expect(packet.layers == ["IPv4", "UDP"])

        // The public init keeps working for callers that know only the old four fields.
        let old = L4Packet(index: 0, dir: .outbound, length: 1, injected: true, layers: ["IPv4"])
        #expect(old.bytes == nil)
        #expect(old.timestamp == nil)
        #expect(old.proto == nil)
        #expect(old.dstPort == nil)
    }

    /// The flow-level `dst`/`dst_port` make the target `lo0 → 127.0.0.1:9053`
    /// (a list row shows its target without reading packets); `started_at`
    /// (epoch ms) becomes `startedAt`.
    @Test func testFlowTargetUsesDestination() throws {
        let json = JSONValue.object([
            "id": .string("F1"),
            "kind": .string("capture"),
            "interface": .string("lo0"),
            "filter": .string("udp port 9053"),
            "started_at": .number(1_700_000_000_000),
            "proto": .string("UDP"),
            "src": .string("127.0.0.1"), "dst": .string("127.0.0.1"),
            "src_port": .number(40000), "dst_port": .number(9053),
            "packet_count": .number(0), "injected_count": .number(0),
            "packets": .array([]),
        ])
        let flow = try #require(L4Flow(json: json))
        #expect(flow.target == "lo0 → 127.0.0.1:9053")
        #expect(flow.startedAt == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(flow.src == "127.0.0.1")
        #expect(flow.dst == "127.0.0.1")
        #expect(flow.srcPort == 40000)
        #expect(flow.dstPort == 9053)
        #expect(flow.protoName == "UDP")
        #expect(flow.row(seq: 1, inScope: true).l4?.target == "lo0 → 127.0.0.1:9053")
    }

    /// An older core's reply (no §2 keys) still parses, with the old
    /// interface + filter target text.
    @Test func testOldFlowShapeStillParses() throws {
        let json = JSONValue.object([
            "id": .string("a1b2"),
            "kind": .string("capture"),
            "interface": .string("lo0"),
            "filter": .string("udp port 9"),
            "queue": .null,
            "packet_count": .number(1),
            "injected_count": .number(0),
            "packets": .array([
                .object(["dir": .string("inbound"), "length": .number(40), "injected": .bool(false),
                         "layers": .array([.string("IPv4"), .string("UDP")])]),
            ]),
        ])
        let flow = try #require(L4Flow(json: json))
        #expect(flow.target == "lo0 · udp port 9")
        #expect(flow.startedAt == nil)
        #expect(flow.dst == nil)
        #expect(flow.dstPort == nil)
        #expect(flow.protoName == nil)
        #expect(flow.packets.count == 1)
        #expect(flow.packets[0].bytes == nil)
        #expect(flow.packets[0].timestamp == nil)
        #expect(flow.packets[0].dstPort == nil)
    }

    /// Spec §2 bounded window: list polling asks `limit: 0`, the inspector a
    /// window of 256 from 0, and against an older core (no `limit` in the
    /// schema) only `id` is sent.
    @Test func testFlowGetArgs() {
        let id = FlowID("F1")
        #expect(L4Wire.flowGetArgs(id: id, inspect: false, window: false) == ["id": .string("F1")])
        #expect(L4Wire.flowGetArgs(id: id, inspect: true, window: false) == ["id": .string("F1")])
        #expect(L4Wire.flowGetArgs(id: id, inspect: false, window: true)
            == ["id": .string("F1"), "limit": .number(0)])
        #expect(L4Wire.flowGetArgs(id: id, inspect: true, window: true)
            == ["id": .string("F1"), "offset": .number(0), "limit": .number(256)])
    }

    /// `l4.scope.list` entries parse with their `source` provenance; the AC5
    /// draft builds exactly the five `l4.scope.add` keys; `covers` matches
    /// interface, CIDR and port range.
    @Test func testScopeItemsDraftAndCovers() throws {
        let reply = JSONValue.object([
            "structuredContent": .array([
                .object([
                    "capability": .string("capture"), "cidr": .string("127.0.0.1/32"),
                    "direction": .string("inbound"), "id": .string("S1"),
                    "inject_rate": .object(["per_second": .number(0)]),
                    "interface": .string("lo0"), "ports": .string("9000-9999"),
                    "source": .string("config"),
                ]),
                .object([
                    "capability": .string("inject"), "cidr": .string("10.0.0.0/8"),
                    "direction": .string("outbound"), "id": .string("S2"),
                    "interface": .string("en0"), "source": .string("runtime"),
                ]),
            ]),
        ])
        let items = L4ScopeItem.list(reply)
        #expect(items.map(\.id) == ["S1", "S2"])
        #expect(items[0].cidr == "127.0.0.1/32")
        #expect(items[0].ports == "9000-9999")
        #expect(items[0].interface == "lo0")
        #expect(items[0].direction == "inbound")
        #expect(items[0].capability == "capture")
        #expect(items[0].source == "config")
        #expect(items[1].source == "runtime")
        #expect(items[1].ports == "all")

        // A bare array (an older core) parses the same; a non-list is empty.
        #expect(L4ScopeItem.list(.array([.object(["id": .string("S9"), "cidr": .string("::1/128")])])).map(\.id)
            == ["S9"])
        #expect(L4ScopeItem.list(.object(["available": .bool(false)])).isEmpty)

        // The AC5 draft → exactly the AC5 keys.
        let draft = L4ScopeDraft(
            cidr: "127.0.0.1/32", ports: "9100-9199", interface: "lo0", direction: "inbound",
            capability: "capture")
        #expect(draft.args == [
            "cidr": .string("127.0.0.1/32"), "ports": .string("9100-9199"), "interface": .string("lo0"),
            "direction": .string("inbound"), "capability": .string("capture"),
        ])
        let noPorts = L4ScopeDraft(cidr: "127.0.0.1/32", ports: "", interface: "lo0", direction: "inbound",
                                   capability: "capture")
        #expect(noPorts.args == [
            "cidr": .string("127.0.0.1/32"), "interface": .string("lo0"),
            "direction": .string("inbound"), "capability": .string("capture"),
        ])

        // covers: interface, CIDR (IPv4 prefix) and port range.
        let item = items[0]
        #expect(item.covers(interface: "lo0", dst: "127.0.0.1", port: 9053))
        #expect(!item.covers(interface: "lo0", dst: "127.0.0.1", port: 8999))
        #expect(!item.covers(interface: "en0", dst: "127.0.0.1", port: 9053))
        #expect(!item.covers(interface: "lo0", dst: "10.0.0.1", port: 9053))
        #expect(item.covers(interface: "lo0", dst: "127.0.0.1", port: nil))
        // A /8 entry with all ports covers any host in it on any port.
        let wide = items[1]
        #expect(wide.covers(interface: "en0", dst: "10.1.2.3", port: 443))
        #expect(wide.covers(interface: "en0", dst: "10.255.255.255", port: nil))
        #expect(!wide.covers(interface: "en0", dst: "11.0.0.1", port: 443))
        // An IPv6 / unparsable destination matches only a /32-literal of itself.
        let v6 = L4ScopeItem(
            id: "S6", cidr: "::1/32", ports: "all", interface: "lo0", direction: "inbound",
            capability: "capture", source: "config")
        #expect(v6.covers(interface: "lo0", dst: "::1", port: 9053))
        #expect(!v6.covers(interface: "lo0", dst: "::2", port: 9053))
        #expect(!item.covers(interface: "lo0", dst: "::1", port: 9053))
        // A single-port range.
        let single = L4ScopeItem(
            id: "S7", cidr: "127.0.0.1/32", ports: "9053", interface: "lo0", direction: "inbound",
            capability: "capture", source: "runtime")
        #expect(single.covers(interface: "lo0", dst: "127.0.0.1", port: 9053))
        #expect(!single.covers(interface: "lo0", dst: "127.0.0.1", port: 9054))
    }

    /// AC39: the scope-add control renders only when `tools/list` shows
    /// `l4.scope.add` with `confirmable: true`.
    @Test func testSupportsOperatorScopeAdd() {
        let schema = JSONValue.object(["type": .string("object"), "properties": .object([:])])
        let confirmable = ToolDescriptor(
            name: "l4.scope.add", description: "", inputSchema: schema, confirmable: true)
        let plain = ToolDescriptor(name: "l4.scope.add", description: "", inputSchema: schema, confirmable: false)
        let other = ToolDescriptor(name: "l4.scope.list", description: "", inputSchema: schema, confirmable: true)
        #expect(L4Wire.supportsOperatorScopeAdd([other, confirmable]))
        #expect(!L4Wire.supportsOperatorScopeAdd([other, plain]))
        #expect(!L4Wire.supportsOperatorScopeAdd([other]))
        #expect(!L4Wire.supportsOperatorScopeAdd([]))
        // The default init parameter is false (an existing call site stays unchanged).
        #expect(!ToolDescriptor(name: "l4.scope.add", description: "", inputSchema: schema).confirmable)
    }

    /// Spec §2: a UI detects the bounded window from `limit` in the
    /// `l4.flow.get` inputSchema and omits it against an older core.
    @Test func testSupportsWindow() {
        let windowed = ToolDescriptor(
            name: "l4.flow.get", description: "",
            inputSchema: .object([
                "type": .string("object"),
                "properties": .object([
                    "id": .object(["type": .string("string")]),
                    "offset": .object(["type": .string("integer")]),
                    "limit": .object(["type": .string("integer")]),
                ]),
            ]))
        let old = ToolDescriptor(
            name: "l4.flow.get", description: "",
            inputSchema: .object([
                "type": .string("object"),
                "properties": .object(["id": .object(["type": .string("string")])]),
            ]))
        let list = ToolDescriptor(name: "l4.flow.list", description: "", inputSchema: .object([:]))
        #expect(L4Wire.supportsWindow([list, windowed]))
        #expect(!L4Wire.supportsWindow([list, old]))
        #expect(!L4Wire.supportsWindow([list]))
    }
}
