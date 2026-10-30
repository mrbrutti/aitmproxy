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

@Suite struct L4DegradationTests {
    /// `macos_embedded_core_degrades` (L4OPS-AC18): against the self-contained
    /// app's embedded user-level core the L4 surface renders but every wire verb
    /// is `L4Unavailable`, with a reason that names the Phase-2 Network/System
    /// Extension as the path; pointed at a privileged core over the bus it drives
    /// L4 fully.
    @Test func macos_embedded_core_degrades() {
        let embedded = L4Availability.resolve(embeddedCore: true, wireError: "L4 unavailable: no privilege")
        guard case let .degraded(reason) = embedded else {
            Issue.record("embedded core must degrade")
            return
        }
        #expect(reason.lowercased().contains("extension"))
        #expect(reason.lowercased().contains("privileged") || reason.lowercased().contains("privilege"))

        // The surface still renders (capture/scope/craft work locally) — degradation
        // is per wire verb, not a blank screen.
        #expect(embedded.rendersSurface)
        #expect(!embedded.canDriveWire)

        // Pointed at a privileged / remote core over the bus: full drive, no banner.
        let privileged = L4Availability.resolve(embeddedCore: false, wireError: nil)
        #expect(privileged == .available)
        #expect(privileged.canDriveWire)
        #expect(privileged.rendersSurface)
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
