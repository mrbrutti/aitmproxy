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

        // A guard refusal arrives as a thrown bus error, which the inspector surfaces
        // verbatim; its text is never a confirm dialog.
        let refusal = "l4.inject refused: OutOfL4Scope — 10.0.0.5:80 is not in the L4 scope."
        #expect(L4ConfirmRequest(json: .string(refusal)) == nil)
    }
}

@Suite struct L4PendingCallTests {
    /// `testConfirmedReissueKeepsEveryArgAndAddsOnlyTheToken` (L4PAR-AC33; spec
    /// §3 last rule, plan unit (d) amendment 2): a `needs_confirmation` prompt is
    /// bound to the exact call that produced it, and the confirmed re-issue is
    /// that call — same command, every original arg — plus `_confirm: token` and
    /// nothing else. Unit (b)'s TUI kept one shared "pending call" slot, so a
    /// confirm for `l4.intercept.drop` could be re-issued as `l4.inject`; here the
    /// binding is a value on the request, never a shared slot.
    @Test func testConfirmedReissueKeepsEveryArgAndAddsOnlyTheToken() throws {
        let drop = L4PendingCall(command: "l4.intercept.drop", args: ["id": .string("P1")])
        #expect(!drop.isConfirmed)

        // Parsing the core's reply with the call that caused it binds them.
        let request = L4ConfirmRequest(
            json: .object([
                "status": .string("needs_confirmation"),
                "prompt": .string("Drop parked packet P1"),
                "confirm_token": .string("tok"),
            ]),
            call: drop)
        let bound = try #require(request)
        #expect(bound.prompt == "Drop parked packet P1")
        #expect(bound.token == "tok")
        #expect(bound.call == drop)

        // The re-issue: identical command, identical args, plus exactly `_confirm`.
        let again = try #require(bound.call?.confirmed(with: bound))
        #expect(again.command == "l4.intercept.drop")
        #expect(again.args == ["id": .string("P1"), "_confirm": .string("tok")])
        #expect(again.args.count == 2)
        #expect(again.isConfirmed)
        #expect(!drop.isConfirmed)

        // Confirming an already-confirmed call replaces the token; it never
        // duplicates the key or grows the args.
        #expect(again.confirmed(with: bound).args == again.args)
        let other = L4ConfirmRequest(prompt: "again", token: "tok2")
        #expect(again.confirmed(with: other).args == ["id": .string("P1"), "_confirm": .string("tok2")])

        // Value semantics: the same prompt and token constructed with a different call
        // yields a request whose re-issue is *that* call; the drop request is untouched.
        let inject = L4PendingCall(
            command: "l4.inject",
            args: ["spec": .object([:]), "dst": .string("127.0.0.1")])
        let injectRequest = L4ConfirmRequest(prompt: bound.prompt, token: bound.token, call: inject)
        #expect(injectRequest.call == inject)
        #expect(injectRequest.token == "tok")
        #expect(injectRequest.prompt == "Drop parked packet P1")
        let injectAgain = try #require(injectRequest.call?.confirmed(with: injectRequest))
        #expect(injectAgain.command == "l4.inject")
        #expect(injectAgain.args == [
            "spec": .object([:]),
            "dst": .string("127.0.0.1"),
            "_confirm": .string("tok"),
        ])
        #expect(bound.call == drop)
        #expect(bound.call != inject)

        // An unbound parse (the pre-M2b shape) carries no call.
        let unbound = L4ConfirmRequest(json: .object([
            "status": .string("needs_confirmation"),
            "prompt": .string("Drop parked packet P1"),
            "confirm_token": .string("tok"),
        ]))
        #expect(unbound?.call == nil)
        #expect(L4ConfirmRequest(prompt: "p", token: "t").call == nil)

        // A non-confirm reply is still not a dialog, bound or not.
        #expect(L4ConfirmRequest(json: .object(["status": .string("ok")]), call: drop) == nil)
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
              src_port: 40000
              dst_port: 9
          - raw: "hello"
        """
        let value = try #require(PacketSpecDraft.parse(yaml))
        let layers = try #require(value["layers"]?.arrayValue)
        #expect(layers.count == 3)
        #expect(layers[0]["ipv4"]?["src"]?.stringValue == "127.0.0.1")
        #expect(layers[0]["ipv4"]?["dst"]?.stringValue == "127.0.0.1")
        // The map layers keep the core's field names (`PacketSpec`: src_port / dst_port).
        #expect(layers[1]["udp"]?["src_port"]?.intValue == 40000)
        #expect(layers[1]["udp"]?["dst_port"]?.intValue == 9)
        // A scalar `raw` is the payload's UTF-8 bytes, not a `{data: …}` map.
        #expect(layers[2]["raw"] == .array([104, 101, 108, 108, 111]))
        // Empty / malformed drafts fail cleanly rather than crafting nothing.
        #expect(PacketSpecDraft.parse("") == nil)
        #expect(PacketSpecDraft.parse("not: a packet") == nil)
    }

    /// L4PAR-AC27 (Kit half; plan M3a): the craft editor's starting text is a spec
    /// `l4.craft` accepts — `udp.src_port` / `udp.dst_port` (the core's `PacketSpec`
    /// names, not `sport` / `dport`) and `raw` as a byte list (the core's
    /// `Layer::Raw(Vec<u8>)`), never a `{data: "…"}` map. The core answers this
    /// sample with `length 36` (M9's live check over the bus).
    @Test func testSampleSpecIsWhatTheCoreAccepts() throws {
        let value = try #require(PacketSpecDraft.parse(PacketSpecDraft.sample))
        let expected: JSONValue = .object([
            "layers": .array([
                .object(["ipv4": .object(["src": .string("127.0.0.1"), "dst": .string("127.0.0.1")])]),
                .object(["udp": .object(["src_port": 40000, "dst_port": 9])]),
                .object(["raw": .array([104, 101, 108, 108, 111, 45, 108, 52])]),
            ]),
        ])
        #expect(value == expected)

        // What actually goes over the bus: the compact serialization. The byte list
        // is JSON integers (the core rejects floats), and none of the rejected keys
        // appear anywhere — not in the sample text either.
        let wire = value.serialized()
        #expect(wire.contains(#""raw":[104,101,108,108,111,45,108,52]"#))
        // `JSONValue.number` is a Double; a whole number must print as `104`, never
        // `104.0`. (`127.0.0.1` legitimately contains `.0`, so look only where a
        // number ends: before `,`, `]` or `}`.)
        for end in [",", "]", "}"] {
            #expect(!wire.contains(".0" + end), "a float reached the wire before \(end)")
        }
        for rejected in ["sport", "dport", "data"] {
            #expect(!wire.contains(rejected), "rejected key \(rejected) on the wire")
            #expect(!PacketSpecDraft.sample.contains(rejected), "rejected key \(rejected) in the sample")
        }
        #expect(wire == #"{"layers":[{"ipv4":{"dst":"127.0.0.1","src":"127.0.0.1"}},{"udp":{"dst_port":9,"src_port":40000}},{"raw":[104,101,108,108,111,45,108,52]}]}"#)

        // The block style is the human-friendly form (the scripting rule): the
        // sample is what the editor shows, not a one-line flow mapping.
        #expect(PacketSpecDraft.sample.hasPrefix("layers:\n  - ipv4:\n"))
        #expect(PacketSpecDraft.sample.contains("  - raw: \"hello-l4\"\n") || PacketSpecDraft.sample.hasSuffix("  - raw: \"hello-l4\""))

        // A `raw` layer may also be written as an explicit byte list.
        let list = try #require(PacketSpecDraft.parse("layers:\n  - raw: [1, 2, 255]"))
        #expect(list == .object(["layers": .array([.object(["raw": .array([1, 2, 255])])])]))
        #expect(list.serialized() == #"{"layers":[{"raw":[1,2,255]}]}"#)

        // A `#` inside the quoted payload is payload, not a comment.
        let hash = try #require(PacketSpecDraft.parse("layers:\n  - raw: \"a#b\" # trailing comment"))
        #expect(hash["layers"]?[0]?["raw"] == .array([97, 35, 98]))

        // Out-of-range or non-integer list members are not bytes: the draft fails
        // cleanly instead of crafting something the core would reject later.
        #expect(PacketSpecDraft.parse("layers:\n  - raw: [1, 256]") == nil)
        #expect(PacketSpecDraft.parse("layers:\n  - raw: [1.5]") == nil)
        #expect(PacketSpecDraft.parse("layers:\n  - raw: hello") == nil)
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
        // No port known (an ICMP-like flow): a port range cannot claim it, only `all` can (S1).
        #expect(!item.covers(interface: "lo0", dst: "127.0.0.1", port: nil))
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

// MARK: - L4 rows offer no HTTP verbs (L4PAR-AC29; spec §7(d))

@Suite struct L4RowVerbTests {
    /// The verbs an L4 row must never offer: everything that would send an HTTP
    /// verb (`flow.mark`, `flow.comment`, `flow.replay`, `poc.build`, the intercept
    /// and bulk verbs) with an L4 id. Pin host, Copy URL and Quick Look stay.
    static let gatedKeys: [FlowVerb] = [
        .mark(nil), .comment, .replay, .buildPoC, .resume, .edit, .kill, .delete, .editAndReplay,
        .resumeSelected, .killSelected,
    ]

    /// AC29 (Kit): the context-action model for an in-scope L4 row has no enabled
    /// mark, comment, replay or PoC; the host verbs are untouched; a concrete
    /// `.mark(.red)` item is gated through its table key; an HTTP row is unchanged.
    @Test func testL4RowOffersNoHTTPVerbs() {
        let flow = L4Flow(
            id: FlowID("l4-1"), sessionState: .capture, interface: "lo0", packetCount: 2, injectedCount: 0,
            packets: [])
        let row = flow.row(seq: 1, inScope: true)
        #expect(row.kind == .l4)

        let original = VerbTable.items(for: VerbContext(row: row))
        let gated = original.map { L4RowVerbs.gate($0, row: row) }
        #expect(gated.count == original.count)

        for key in Self.gatedKeys {
            let item = VerbTable.item(key, in: gated)
            #expect(!item.enabled, "\(key) must be disabled on an L4 row")
            #expect(item.disabledReason == "Not available for L4 flows", "\(key) carries the L4 reason")
        }
        // Before the gate the in-scope capture row had these on, so the gate is what turned them off.
        #expect(VerbTable.item(.mark(nil), in: original).enabled)
        #expect(VerbTable.item(.comment, in: original).enabled)
        #expect(VerbTable.item(.replay, in: original).enabled)
        #expect(VerbTable.item(.buildPoC, in: original).enabled)
        #expect(VerbTable.item(.delete, in: original).enabled)

        // The host verbs come back byte-for-byte as the table built them.
        for key in [FlowVerb.pinHost, .copyURL, .quickLook] {
            #expect(VerbTable.item(key, in: gated) == VerbTable.item(key, in: original), "\(key) unchanged")
        }
        #expect(VerbTable.item(.pinHost, in: gated).enabled)
        #expect(VerbTable.item(.copyURL, in: gated).enabled)
        #expect(VerbTable.item(.quickLook, in: gated).enabled)

        // A concrete colour mark is gated through its table key (`.mark(nil)`), not by equality.
        let red = VerbItem(verb: .mark(.red), title: "Mark", enabled: true, group: .annotate)
        let gatedRed = L4RowVerbs.gate(red, row: row)
        #expect(gatedRed.verb == .mark(.red))
        #expect(gatedRed.title == "Mark")
        #expect(!gatedRed.enabled)
        #expect(gatedRed.disabledReason == "Not available for L4 flows")

        // An HTTP row passes through untouched, item for item.
        let http = FlowRow(
            id: FlowID("h-1"), seq: 2, kind: .http, method: .post, scheme: "https",
            authority: "api.example.test", path: "/login", status: 200, state: .complete)
        let httpOriginal = VerbTable.items(for: VerbContext(row: http))
        let httpGated = httpOriginal.map { L4RowVerbs.gate($0, row: http) }
        #expect(httpGated == httpOriginal)
        #expect(VerbTable.item(.mark(nil), in: httpGated).enabled)
        #expect(VerbTable.item(.replay, in: httpGated).enabled)
        #expect(L4RowVerbs.gate(red, row: http) == red)
    }
}

// MARK: - Inert packet text (L4PAR-AC40; spec §2.3, Decision 10)

@Suite struct L4HexTests {
    /// The bytes AC40 names: an ANSI escape (`ESC [ A`), a newline, DEL, `~`, `A`.
    static let probe = Data([0x1b, 0x5b, 0x41, 0x0a, 0x7f, 0x7e, 0x41])

    /// AC40 (mac): the ASCII column maps every byte outside 0x20–0x7e to `.`, so
    /// the probe renders `.[A..~A`; no row carries any character below 0x20 (no
    /// line breaks inside a row, no raw escape); 17 bytes make two rows, the
    /// second at offset `00000010`; no bytes make no rows.
    @Test func testAsciiColumnIsInert() {
        #expect(L4Hex.asciiColumn(Self.probe) == ".[A..~A")

        let rows = L4Hex.rows(Self.probe)
        #expect(rows.count == 1)
        #expect(rows[0].hasPrefix("00000000"))
        #expect(rows[0].hasSuffix(".[A..~A"))
        #expect(rows[0] == "00000000  1b 5b 41 0a 7f 7e 41                             .[A..~A")
        for row in rows {
            for scalar in row.unicodeScalars {
                #expect(scalar.value >= 0x20, "row carries a control character: U+\(String(scalar.value, radix: 16))")
            }
        }

        let seventeen = L4Hex.rows(Data(repeating: 0x41, count: 17))
        #expect(seventeen.count == 2)
        #expect(seventeen[1].hasPrefix("00000010"))
        #expect(seventeen[0] == "00000000  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA")
        #expect(seventeen[1] == "00000010  41                                               A")

        #expect(L4Hex.rows(Data()) == [])
    }

    /// The confirm sheet is presented by item, so a request is identified by the
    /// single-use token the core minted for it (Kit-owned, not a retroactive
    /// conformance in the app).
    @Test func testConfirmRequestIdentityIsItsToken() {
        #expect(L4ConfirmRequest(prompt: "p", token: "t").id == "t")
    }
}

// MARK: - Tester additions (stage 5, plan 2026-10-31-l4-parity-fixes unit (d), whole branch)
//
// Every input below is built inline with literal expectations: no fixture, snapshot, self-test
// or seeded-store data (the plan's "Rule for every task"). These close the holes the task tests
// left open: the rig's real status shapes through `resolve`, malformed and oversized wire data
// into every parser the live poll feeds, the CIDR / port arithmetic at its edges, and the inert
// renderer over all 256 byte values.

@Suite struct L4TesterAvailabilityTests {
    /// The two status objects the unit (d) rig answered on 2026-11-01 (probe-1.txt), verbatim,
    /// map to `.degraded` with exactly the core's `reason`: this is the text the Scope page shows
    /// after `Capture and inject unavailable: ` / `In-path intercept unavailable: ` (AC26, AC28).
    @Test func testResolveReadsTheRigsStatusShapes() {
        let capture = JSONValue.object([
            "available": .bool(false),
            "captures": .array([]),
            "code": .string("needs_privilege"),
            "reason": .string(
                "no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)"),
        ])
        #expect(L4Availability.resolve(status: capture, error: nil)
            == .degraded(reason: "no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)"))

        let intercept = JSONValue.object([
            "available": .bool(false),
            "code": .string("unsupported_platform"),
            "reason": .string("in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)"),
            "sessions": .array([]),
        ])
        #expect(L4Availability.resolve(status: intercept, error: nil)
            == .degraded(reason: "in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)"))

        // The shape D0 will answer with: `available: true`, `code: available`, `reason: null`.
        let privileged = JSONValue.object([
            "available": .bool(true), "code": .string("available"), "reason": .null,
            "captures": .array([.string("f1")]),
        ])
        #expect(L4Availability.resolve(status: privileged, error: nil) == .available)
    }

    /// Malformed status replies never fabricate availability: anything without a bool
    /// `available` (and not a bare array) is `.pending`; a blank, null or non-string `reason`
    /// degrades with the fallback text; the marker with nothing after it degrades with the
    /// fallback too; a stale error never overrides a bare-array status.
    @Test func testResolveFailsClosedOnMalformedReplies() {
        #expect(L4Availability.resolve(status: .object([:]), error: nil) == .pending)
        #expect(L4Availability.resolve(status: .string("ok"), error: nil) == .pending)
        #expect(L4Availability.resolve(status: .number(1), error: nil) == .pending)
        #expect(L4Availability.resolve(status: .null, error: nil) == .pending)
        // `available` as a string is not a verdict.
        #expect(L4Availability.resolve(status: .object(["available": .string("false")]), error: nil) == .pending)
        #expect(L4Availability.resolve(status: .object(["available": .string("true")]), error: nil) == .pending)
        // A wrapper with no usable status inside.
        #expect(L4Availability.resolve(status: .object(["structuredContent": .object([:])]), error: nil) == .pending)

        #expect(L4Availability.resolve(status: .object(["available": .bool(false), "reason": .string("   ")]), error: nil)
            == .degraded(reason: "L4 unavailable"))
        #expect(L4Availability.resolve(status: .object(["available": .bool(false), "reason": .null]), error: nil)
            == .degraded(reason: "L4 unavailable"))
        #expect(L4Availability.resolve(status: .object(["available": .bool(false), "reason": .number(7)]), error: nil)
            == .degraded(reason: "L4 unavailable"))
        // Surrounding whitespace and newlines in the reason are trimmed, inner text is kept verbatim.
        #expect(L4Availability.resolve(status: .object(["available": .bool(false), "reason": .string("  a  b\n")]), error: nil)
            == .degraded(reason: "a  b"))

        #expect(L4Availability.resolve(status: nil, error: "L4 unavailable: ") == .degraded(reason: "L4 unavailable"))
        #expect(L4Availability.resolve(status: nil, error: "L4 unavailable:  X \n") == .degraded(reason: "X"))
        #expect(L4Availability.resolve(status: nil, error: "") == .pending)
        // The marker is matched exactly: a lowercase variant is not an availability verdict.
        #expect(L4Availability.resolve(status: nil, error: "l4 unavailable: X") == .pending)
        // A bare-array status (older core, payload only) beats a stale error.
        #expect(L4Availability.resolve(status: .array([]), error: "L4 unavailable: X") == .available)
        // A malformed status with a real error falls through to the error.
        #expect(L4Availability.resolve(status: .object([:]), error: "L4 unavailable: Y") == .degraded(reason: "Y"))

        // The display text of each state is exactly what the surfaces render.
        #expect(L4Availability.available.displayText == nil)
        #expect(L4Availability.degraded(reason: "R").displayText == "R")
        #expect(L4Availability.pending.displayText == "Reading L4 availability…")
        #expect(L4Availability.pendingText == "Reading L4 availability…")
        #expect(L4Availability.unavailableMarker == "L4 unavailable: ")
    }
}

@Suite struct L4TesterWireParsingTests {
    /// Malformed `l4.flow.get` replies fail closed: no `id` or `kind` ⇒ nil; an unknown kind ⇒
    /// nil (the session-state cell never shows a made-up state); a packet without a valid `dir`
    /// is skipped while its neighbours parse; invalid base64 ⇒ no bytes; a non-numeric
    /// `timestamp` / `started_at` ⇒ nil; non-array `packets` ⇒ none; counts fall back to what
    /// was parsed; the `structuredContent` wrapper is unwrapped.
    @Test func testFlowGetMalformedRepliesFailClosed() throws {
        #expect(L4Flow(json: .object(["kind": .string("capture")])) == nil)
        #expect(L4Flow(json: .object(["id": .string("F")])) == nil)
        #expect(L4Flow(json: .object(["id": .string("F"), "kind": .string("teleport")])) == nil)
        #expect(L4Flow(json: .string("F")) == nil)
        #expect(L4Flow(json: .array([])) == nil)
        #expect(L4Flow(json: .null) == nil)

        let wrapped = JSONValue.object([
            "structuredContent": .object([
                "id": .string("F"), "kind": .string("send_recv"),
                "packets": .array([
                    .object(["dir": .string("sideways"), "length": .number(1)]),
                    .object(["length": .number(2)]),
                    .object([
                        "dir": .string("inbound"), "length": .number(3), "injected": .bool(false),
                        "bytes": .string("!!not-base64!!"), "timestamp": .string("yesterday"),
                        "src_port": .string("40000"), "proto": .number(17),
                    ]),
                    .object(["dir": .string("outbound"), "injected": .bool(true), "bytes": .string("AAEC")]),
                ]),
                "started_at": .string("2026-11-01T17:03:00Z"),
            ]),
        ])
        let flow = try #require(L4Flow(json: wrapped))
        #expect(flow.id == FlowID("F"))
        #expect(flow.sessionState == .sendRecv)
        #expect(flow.interface == "")
        #expect(flow.packets.count == 2)
        #expect(flow.packets[0].index == 2)
        #expect(flow.packets[0].dir == .inbound)
        #expect(flow.packets[0].length == 3)
        #expect(flow.packets[0].bytes == nil)
        #expect(flow.packets[0].timestamp == nil)
        #expect(flow.packets[0].srcPort == nil)
        #expect(flow.packets[0].proto == nil)
        #expect(flow.packets[1].index == 3)
        #expect(flow.packets[1].length == 0)
        #expect(flow.packets[1].injected)
        #expect(flow.packets[1].bytes == Data([0x00, 0x01, 0x02]))
        // No counts on the wire ⇒ what was parsed: two packets, one injected.
        #expect(flow.packetCount == 2)
        #expect(flow.injectedCount == 1)
        #expect(flow.startedAt == nil)
        #expect(flow.proto == .raw)
        #expect(flow.target == "l4")

        let noPackets = try #require(L4Flow(json: .object([
            "id": .string("G"), "kind": .string("intercept"), "interface": .string("lo0"),
            "packets": .string("none"), "packet_count": .number(300), "queue": .number(5),
        ])))
        #expect(noPackets.packets.isEmpty)
        #expect(noPackets.packetCount == 300)
        #expect(noPackets.queue == 5)
        #expect(noPackets.row(seq: 1, inScope: false).state == .paused)
        #expect(noPackets.row(seq: 1, inScope: false).l4?.inScope == false)
    }

    /// An oversized reply (a 4096-packet window, the core's clamp) parses every packet with its
    /// index, and a flow-level destination without a port falls back to the filter text.
    @Test func testFlowGetWindowAtTheClamp() throws {
        var packets: [JSONValue] = []
        packets.reserveCapacity(4096)
        for i in 0..<4096 {
            packets.append(.object([
                "dir": .string(i % 2 == 0 ? "inbound" : "outbound"), "length": .number(Double(60 + i % 7)),
                "injected": .bool(i % 3 == 0), "layers": .array([.string("IPv4"), .string("TCP")]),
            ]))
        }
        let flow = try #require(L4Flow(json: .object([
            "id": .string("big"), "kind": .string("capture"), "interface": .string("lo0"),
            "filter": .string("tcp port 9199"), "dst": .string("127.0.0.1"),
            "packets": .array(packets), "packet_count": .number(300_000),
        ])))
        #expect(flow.packets.count == 4096)
        #expect(flow.packets.last?.index == 4095)
        #expect(flow.packets[4095].dir == .outbound)
        #expect(flow.packetCount == 300_000)
        #expect(flow.injectedCount == 1366)
        #expect(flow.proto == .tcp)
        // `dst` without `dst_port` is not a target: the filter text is shown instead.
        #expect(flow.target == "lo0 · tcp port 9199")
    }

    /// `l4.intercept.list` and `l4.scope.list` entries with the wrong types never crash the poll
    /// and never produce an actionable id out of nothing.
    @Test func testListParsersTolerateWrongTypes() {
        let parked = L4ParkedPacket.list(.array([
            .object(["id": .number(1), "flow": .string("F")]),
            .object(["id": .string("P1"), "flow": .number(2)]),
            .object(["id": .string("P2"), "flow": .string("F"), "length": .string("big"),
                     "layers": .string("IPv4"), "parked_at": .string("now"), "state": .number(0)]),
            .string("P3"),
            .null,
        ]))
        #expect(parked.map(\.id) == ["P2"])
        #expect(parked[0].length == 0)
        #expect(parked[0].layers == [])
        #expect(parked[0].parkedAt == nil)
        #expect(parked[0].state == "")
        #expect(L4ParkedPacket.list(.null).isEmpty)
        #expect(L4ParkedPacket.list(.string("[]")).isEmpty)
        #expect(L4ParkedPacket.list(.object(["structuredContent": .string("x")])).isEmpty)

        let scope = L4ScopeItem.list(.array([
            .object(["id": .number(1)]),
            .object(["id": .string("S1"), "ports": .string("   "), "cidr": .number(32)]),
            .object(["id": .string("S2"), "ports": .number(9000)]),
            .bool(true),
        ]))
        #expect(scope.map(\.id) == ["S1", "S2"])
        #expect(scope[0].ports == "all")
        #expect(scope[0].cidr == "")
        #expect(scope[1].ports == "all")
        // A blank cidr covers nothing, whatever the interface.
        #expect(!scope[0].covers(interface: "", dst: "127.0.0.1", port: nil))
        #expect(L4ScopeItem.list(.null).isEmpty)
    }

    /// A `needs_confirmation` reply without its token or prompt is not a confirm dialog (the UI
    /// would have nothing to re-issue); the status string is matched exactly.
    @Test func testConfirmRequestNeedsPromptAndToken() {
        let call = L4PendingCall(command: "l4.scope.add", args: ["cidr": .string("127.0.0.1/32")])
        #expect(L4ConfirmRequest(json: .object([
            "status": .string("needs_confirmation"), "prompt": .string("p"),
        ]), call: call) == nil)
        #expect(L4ConfirmRequest(json: .object([
            "status": .string("needs_confirmation"), "confirm_token": .string("t"),
        ]), call: call) == nil)
        #expect(L4ConfirmRequest(json: .object([
            "status": .string("NEEDS_CONFIRMATION"), "prompt": .string("p"), "confirm_token": .string("t"),
        ]), call: call) == nil)
        #expect(L4ConfirmRequest(json: .object([
            "status": .string("needs_confirmation"), "prompt": .string("p"), "confirm_token": .number(7),
        ]), call: call) == nil)
        #expect(L4ConfirmRequest(json: .null, call: call) == nil)

        // Confirming a call with no args yields exactly the token and nothing else.
        let bare = L4PendingCall(command: "l4.intercept.forward", args: [:])
        let request = L4ConfirmRequest(prompt: "Forward P1", token: "tok-1", call: bare)
        #expect(bare.confirmed(with: request).args == ["_confirm": .string("tok-1")])
        #expect(bare.confirmed(with: request).command == "l4.intercept.forward")
    }
}

@Suite struct L4TesterScopeCoverTests {
    private func item(_ cidr: String, ports: String, interface: String = "lo0") -> L4ScopeItem {
        L4ScopeItem(id: "T", cidr: cidr, ports: ports, interface: interface, direction: "inbound",
                    capability: "capture", source: "config")
    }

    /// The IPv4 prefix arithmetic at its edges: `/0` covers every IPv4 address, `/32` only the
    /// one, a missing prefix means `/32`, `/33` and non-numeric prefixes cover nothing, octets
    /// above 255 are not an address, and `/8` stops at the network boundary.
    @Test func testCidrEdges() {
        #expect(item("0.0.0.0/0", ports: "all").covers(interface: "lo0", dst: "203.0.113.9", port: 1))
        #expect(item("0.0.0.0/0", ports: "all").covers(interface: "lo0", dst: "255.255.255.255", port: 65535))
        #expect(!item("0.0.0.0/0", ports: "all").covers(interface: "lo0", dst: "::1", port: 1))
        #expect(item("127.0.0.1", ports: "all").covers(interface: "lo0", dst: "127.0.0.1", port: 9053))
        #expect(!item("127.0.0.1", ports: "all").covers(interface: "lo0", dst: "127.0.0.2", port: 9053))
        #expect(!item("127.0.0.1/33", ports: "all").covers(interface: "lo0", dst: "127.0.0.1", port: 9053))
        #expect(!item("127.0.0.1/-1", ports: "all").covers(interface: "lo0", dst: "127.0.0.1", port: 9053))
        #expect(!item("127.0.0.1/x", ports: "all").covers(interface: "lo0", dst: "127.0.0.1", port: 9053))
        #expect(!item("127.0.0.1/", ports: "all").covers(interface: "lo0", dst: "127.0.0.1", port: 9053))
        #expect(!item("", ports: "all").covers(interface: "lo0", dst: "127.0.0.1", port: 9053))
        #expect(!item("/32", ports: "all").covers(interface: "lo0", dst: "127.0.0.1", port: 9053))
        // 256 is not an octet: the network is not IPv4, so only the literal matches, and
        // "256.1.1.1" as a destination is not an IPv4 address either.
        #expect(!item("256.1.1.1/8", ports: "all").covers(interface: "lo0", dst: "256.1.1.2", port: 1))
        #expect(item("256.1.1.1/32", ports: "all").covers(interface: "lo0", dst: "256.1.1.1", port: 1))
        #expect(!item("127.0.0.1/32", ports: "all").covers(interface: "lo0", dst: "127.0.0.1.1", port: 1))
        #expect(!item("127.0.0.1/32", ports: "all").covers(interface: "lo0", dst: "127.0.0", port: 1))
        #expect(!item("127.0.0.1/32", ports: "all").covers(interface: "lo0", dst: "", port: 1))
        // /8 boundaries.
        let ten = item("10.0.0.0/8", ports: "all", interface: "en0")
        #expect(ten.covers(interface: "en0", dst: "10.0.0.0", port: 1))
        #expect(ten.covers(interface: "en0", dst: "10.255.255.255", port: 1))
        #expect(!ten.covers(interface: "en0", dst: "9.255.255.255", port: 1))
        #expect(!ten.covers(interface: "en0", dst: "11.0.0.0", port: 1))
        // /31 covers exactly two addresses.
        let pair = item("192.0.2.4/31", ports: "all")
        #expect(pair.covers(interface: "lo0", dst: "192.0.2.4", port: nil))
        #expect(pair.covers(interface: "lo0", dst: "192.0.2.5", port: nil))
        #expect(!pair.covers(interface: "lo0", dst: "192.0.2.6", port: nil))
        #expect(!pair.covers(interface: "lo0", dst: "192.0.2.3", port: nil))
        // The interface is compared exactly (case and whitespace included).
        #expect(!item("127.0.0.1/32", ports: "all").covers(interface: "LO0", dst: "127.0.0.1", port: nil))
        #expect(!item("127.0.0.1/32", ports: "all").covers(interface: "lo0 ", dst: "127.0.0.1", port: nil))
    }

    /// Port text at its edges: an inclusive range, a reversed range, a single port, `all` in any
    /// case, surrounding spaces, and garbage (which covers nothing).
    @Test func testPortsEdges() {
        let range = item("127.0.0.1/32", ports: "9000-9999")
        #expect(range.covers(interface: "lo0", dst: "127.0.0.1", port: 9000))
        #expect(range.covers(interface: "lo0", dst: "127.0.0.1", port: 9999))
        #expect(!range.covers(interface: "lo0", dst: "127.0.0.1", port: 10000))
        #expect(!range.covers(interface: "lo0", dst: "127.0.0.1", port: 0))
        #expect(!range.covers(interface: "lo0", dst: "127.0.0.1", port: -1))
        #expect(item("127.0.0.1/32", ports: "9999-9000").covers(interface: "lo0", dst: "127.0.0.1", port: 9500))
        #expect(item("127.0.0.1/32", ports: " 9000 - 9999 ").covers(interface: "lo0", dst: "127.0.0.1", port: 9500))
        #expect(item("127.0.0.1/32", ports: "ALL").covers(interface: "lo0", dst: "127.0.0.1", port: 1))
        #expect(item("127.0.0.1/32", ports: "").covers(interface: "lo0", dst: "127.0.0.1", port: 65535))
        #expect(!item("127.0.0.1/32", ports: "abc").covers(interface: "lo0", dst: "127.0.0.1", port: 1))
        #expect(!item("127.0.0.1/32", ports: "9000-").covers(interface: "lo0", dst: "127.0.0.1", port: 9000))
        #expect(!item("127.0.0.1/32", ports: "-9000").covers(interface: "lo0", dst: "127.0.0.1", port: 9000))
        #expect(!item("127.0.0.1/32", ports: "9000,9001").covers(interface: "lo0", dst: "127.0.0.1", port: 9000))
        // An unknown port (nil) is covered only by `all` (or blank, which lists as `all`): a range
        // or garbage ports cannot claim a flow whose port they cannot check (S1).
        #expect(!item("127.0.0.1/32", ports: "abc").covers(interface: "lo0", dst: "127.0.0.1", port: nil))
        #expect(!item("127.0.0.1/32", ports: "9000-9999").covers(interface: "lo0", dst: "127.0.0.1", port: nil))
        #expect(item("127.0.0.1/32", ports: "all").covers(interface: "lo0", dst: "127.0.0.1", port: nil))
        #expect(item("127.0.0.1/32", ports: "").covers(interface: "lo0", dst: "127.0.0.1", port: nil))
    }

    /// The draft trims the ports' surrounding spaces, and its key set is exactly the five AC5
    /// keys, or four when the ports are blank; `_confirm` is never part of a draft.
    @Test func testDraftArgsKeySet() {
        let draft = L4ScopeDraft(cidr: " 127.0.0.1/32", ports: "  9100-9199  ", interface: "lo0", direction: "inbound",
                                 capability: "inject")
        #expect(draft.args["ports"] == .string("9100-9199"))
        #expect(Set(draft.args.keys) == ["cidr", "ports", "interface", "direction", "capability"])
        let spaces = L4ScopeDraft(cidr: "127.0.0.1/32", ports: "   ", interface: "lo0", direction: "inbound",
                                  capability: "capture")
        #expect(Set(spaces.args.keys) == ["cidr", "interface", "direction", "capability"])
        #expect(spaces.args["_confirm"] == nil)
    }
}

// MARK: - Review-log fixes (stage 6, plan 2026-10-31-l4-parity-fixes unit (d))

@Suite struct L4ReviewFixCoverTests {
    private func item(_ cidr: String, ports: String, direction: String = "inbound") -> L4ScopeItem {
        L4ScopeItem(id: "R", cidr: cidr, ports: ports, interface: "lo0", direction: direction,
                    capability: "capture", source: "config")
    }

    /// S1: an ICMP-like flow (`lo0`, `127.0.0.1`, no port) is NOT covered by a `9000-9999` entry
    /// but IS by an `all` entry; a flow that carries a direction is covered only by an entry of
    /// the same direction, and a flow without one (today's `L4Flow`) ignores the entry's.
    @Test func testUnknownPortNeedsAllAndDirectionMustMatch() {
        #expect(!item("127.0.0.1/32", ports: "9000-9999").covers(interface: "lo0", dst: "127.0.0.1", port: nil))
        #expect(item("127.0.0.1/32", ports: "all").covers(interface: "lo0", dst: "127.0.0.1", port: nil))
        #expect(!item("127.0.0.1/32", ports: "9053").covers(interface: "lo0", dst: "127.0.0.1", port: nil))
        // A known port still goes through the range.
        #expect(item("127.0.0.1/32", ports: "9000-9999").covers(interface: "lo0", dst: "127.0.0.1", port: 9053))

        let inbound = item("127.0.0.1/32", ports: "all", direction: "inbound")
        #expect(inbound.covers(interface: "lo0", dst: "127.0.0.1", port: 9053, direction: "inbound"))
        #expect(!inbound.covers(interface: "lo0", dst: "127.0.0.1", port: 9053, direction: "outbound"))
        #expect(!inbound.covers(interface: "lo0", dst: "127.0.0.1", port: nil, direction: "outbound"))
        // No direction on the flow: the entry's direction is not consulted (the default argument).
        #expect(inbound.covers(interface: "lo0", dst: "127.0.0.1", port: 9053))
        #expect(inbound.covers(interface: "lo0", dst: "127.0.0.1", port: 9053, direction: nil))
        // The entry's direction is compared exactly.
        #expect(!inbound.covers(interface: "lo0", dst: "127.0.0.1", port: 9053, direction: "Inbound"))
        let outbound = item("10.0.0.0/8", ports: "all", direction: "outbound")
        #expect(outbound.covers(interface: "lo0", dst: "10.1.2.3", port: 443, direction: "outbound"))
        #expect(!outbound.covers(interface: "lo0", dst: "10.1.2.3", port: 443, direction: "inbound"))
    }
}

@Suite struct L4ReviewFixConfirmWordsTests {
    /// Q3: the one shared confirm sheet derives its title, action word and accessibility
    /// identifier from the bound call's command; an unknown or absent command gets the
    /// neutral words.
    @Test func testConfirmWordsFollowTheBoundCommand() {
        let inject = L4ConfirmWords.for(command: "l4.inject")
        #expect(inject.title == "Confirm injection")
        #expect(inject.action == "Inject")
        #expect(inject.identifier == "l4-confirm-inject")

        let forward = L4ConfirmWords.for(command: "l4.intercept.forward")
        #expect(forward.title == "Confirm forward")
        #expect(forward.action == "Forward")
        #expect(forward.identifier == "l4-confirm-forward")

        let drop = L4ConfirmWords.for(command: "l4.intercept.drop")
        #expect(drop.title == "Confirm drop")
        #expect(drop.action == "Drop")
        #expect(drop.identifier == "l4-confirm-drop")

        let scope = L4ConfirmWords.for(command: "l4.scope.add")
        #expect(scope.title == "Confirm L4 scope entry")
        #expect(scope.action == "Add")
        #expect(scope.identifier == "l4-scope-confirm")

        let unknown = L4ConfirmWords.for(command: "l4.intercept.mutate")
        #expect(unknown.title == "Confirm")
        #expect(unknown.action == "Confirm")
        #expect(unknown.identifier == "l4-confirm")
        let unbound = L4ConfirmWords.for(command: nil)
        #expect(unbound.title == "Confirm")
        #expect(unbound.action == "Confirm")
        #expect(unbound.identifier == "l4-confirm")
    }
}

@Suite struct L4ReviewFixEndpointsTests {
    /// Q7: `L4Packet.endpoints` is `src:srcPort → dst:dstPort` from whatever §2 fields the core
    /// sent — a side without a port is the bare host, a missing side is `?`, and a packet with
    /// neither address has no endpoints line at all.
    @Test func testEndpointsLine() {
        func packet(src: String? = nil, dst: String? = nil, srcPort: Int? = nil, dstPort: Int? = nil) -> L4Packet {
            L4Packet(index: 0, dir: .inbound, length: 1, injected: false, layers: [],
                     src: src, dst: dst, srcPort: srcPort, dstPort: dstPort)
        }
        #expect(packet(src: "127.0.0.1", dst: "127.0.0.1", srcPort: 40000, dstPort: 9053).endpoints
            == "127.0.0.1:40000 → 127.0.0.1:9053")
        #expect(packet(src: "10.0.0.5", dst: "10.0.0.9").endpoints == "10.0.0.5 → 10.0.0.9")
        #expect(packet(src: "10.0.0.5", dstPort: 53).endpoints == "10.0.0.5 → ?")
        #expect(packet(dst: "::1", dstPort: 53).endpoints == "? → ::1:53")
        #expect(packet(dst: "::1").endpoints == "? → ::1")
        #expect(packet(src: "", dst: "").endpoints == nil)
        #expect(packet(srcPort: 1, dstPort: 2).endpoints == nil)
        #expect(packet().endpoints == nil)
    }
}

@Suite struct L4TesterHexTests {
    /// AC40 over the whole byte space: every one of the 256 values renders to exactly one
    /// character in 0x20…0x7e; the 95 printable bytes render as themselves and the other 161 as
    /// `.`; no row of any width carries a line break, tab, escape or DEL.
    @Test func testEveryByteValueRendersInert() {
        let all = Data((0...255).map { UInt8($0) })
        let column = L4Hex.asciiColumn(all)
        #expect(column.unicodeScalars.count == 256)
        for scalar in column.unicodeScalars {
            #expect((0x20...0x7e).contains(scalar.value), "U+\(String(scalar.value, radix: 16)) reached the column")
        }
        let printable = Data((0x20...0x7e).map { UInt8($0) })
        #expect(L4Hex.asciiColumn(printable)
            == " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")
        #expect(L4Hex.asciiColumn(printable).count == 95)
        #expect(L4Hex.asciiColumn(Data((0x00...0x1f).map { UInt8($0) })) == String(repeating: ".", count: 32))
        #expect(L4Hex.asciiColumn(Data((0x7f...0xff).map { UInt8($0) })) == String(repeating: ".", count: 129))
        #expect(L4Hex.asciiColumn(Data()) == "")

        let rows = L4Hex.rows(all)
        #expect(rows.count == 16)
        #expect(rows[0] == "00000000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ................")
        #expect(rows[2] == "00000020  20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./")
        #expect(rows[7] == "00000070  70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f  pqrstuvwxyz{|}~.")
        #expect(rows[15] == "000000f0  f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff  ................")
        for row in rows {
            #expect(row.count == 8 + 2 + 47 + 2 + 16)
            for scalar in row.unicodeScalars { #expect(scalar.value >= 0x20 && scalar.value <= 0x7e) }
        }
    }

    /// Oversized and odd widths: a 4 MiB-window-sized dump stays linear and keeps its offsets,
    /// width 1 gives one byte per row, width 0 is clamped to 1, and the last short row is padded
    /// so the ASCII column lines up.
    @Test func testRowsAtOddWidthsAndSizes() {
        let big = Data(repeating: 0x0a, count: 65_536)
        let rows = L4Hex.rows(big)
        #expect(rows.count == 4096)
        #expect(rows[4095].hasPrefix("0000fff0  0a 0a"))
        #expect(rows[4095].hasSuffix("  ................"))
        #expect(!rows.contains { $0.contains("\n") })

        #expect(L4Hex.rows(Data([0x41, 0x1b]), width: 1) == ["00000000  41  A", "00000001  1b  ."])
        #expect(L4Hex.rows(Data([0x41, 0x1b]), width: 0) == ["00000000  41  A", "00000001  1b  ."])
        #expect(L4Hex.rows(Data([0x41, 0x1b]), width: -5) == ["00000000  41  A", "00000001  1b  ."])
        #expect(L4Hex.rows(Data([0x41, 0x42, 0x43]), width: 2) == ["00000000  41 42  AB", "00000002  43     C"])
        #expect(L4Hex.rows(Data(), width: 1) == [])
    }
}

@Suite struct L4TesterCraftDraftTests {
    /// Malformed drafts never reach the core: an unknown layer name, a `layers:` list with no
    /// items, an unterminated or unquoted payload, a negative or non-integer byte, a `raw` list
    /// with a nested list, and an empty payload (which is a legitimate zero-byte `raw`).
    @Test func testParseRejectsWhatTheCoreWouldReject() throws {
        #expect(PacketSpecDraft.parse("layers:") == nil)
        #expect(PacketSpecDraft.parse("layers:\n") == nil)
        #expect(PacketSpecDraft.parse("layers:\n  - quic:\n      version: 1") == nil)
        #expect(PacketSpecDraft.parse("layers:\n  - raw: \"open") == nil)
        #expect(PacketSpecDraft.parse("layers:\n  - raw: 'single'") == nil)
        #expect(PacketSpecDraft.parse("layers:\n  - raw: [-1]") == nil)
        #expect(PacketSpecDraft.parse("layers:\n  - raw: [1, [2]]") == nil)
        #expect(PacketSpecDraft.parse("layers:\n  - raw: [0x41]") == nil)
        #expect(PacketSpecDraft.parse("layers:\n  - raw: [1 2]") == nil)
        #expect(PacketSpecDraft.parse("# only a comment") == nil)

        #expect(PacketSpecDraft.parse("layers:\n  - raw: \"\"") == .object(["layers": .array([.object(["raw": .array([])])])]))
        #expect(PacketSpecDraft.parse("layers:\n  - raw: []") == .object(["layers": .array([.object(["raw": .array([])])])]))
        #expect(PacketSpecDraft.parse("layers:\n  - raw: [0, 255]") == .object(["layers": .array([.object(["raw": .array([0, 255])])])]))

        // A non-ASCII payload is its UTF-8 bytes, each an integer 0...255.
        let utf8 = try #require(PacketSpecDraft.parse("layers:\n  - raw: \"é\""))
        #expect(utf8["layers"]?[0]?["raw"] == .array([195, 169]))

        // Layer keys are case-insensitive, field keys are kept as written, a quoted scalar stays
        // a string, an integer becomes a number, and a bare word stays a string.
        let mixed = try #require(PacketSpecDraft.parse("""
        layers:
          - IPv4:
              src: 127.0.0.1
              ttl: 64
              flags: "df"
          - TCP:
              dst_port: 9199
              syn: true
        """))
        #expect(mixed == .object(["layers": .array([
            .object(["ipv4": .object(["src": .string("127.0.0.1"), "ttl": 64, "flags": .string("df")])]),
            .object(["tcp": .object(["dst_port": 9199, "syn": .bool(true)])]),
        ])]))
    }

    /// An oversized draft (10 000 raw layers, a 100 000-byte payload) parses in order without
    /// losing or reordering a layer.
    @Test func testParseStaysLinearOnOversizedDrafts() throws {
        var text = "layers:\n"
        for i in 0..<10_000 { text += "  - raw: [\(i % 256)]\n" }
        let value = try #require(PacketSpecDraft.parse(text))
        let layers = try #require(value["layers"]?.arrayValue)
        #expect(layers.count == 10_000)
        #expect(layers[0]["raw"] == .array([0]))
        #expect(layers[9_999]["raw"] == .array([.number(15)]))

        let payload = String(repeating: "A", count: 100_000)
        let big = try #require(PacketSpecDraft.parse("layers:\n  - raw: \"\(payload)\""))
        #expect(big["layers"]?[0]?["raw"]?.arrayValue?.count == 100_000)
        #expect(big["layers"]?[0]?["raw"]?[99_999] == .number(65))
    }

    /// A craft result without `bytes`, or with bytes that are not base64, is no preview (the
    /// inspector says `l4.craft returned no bytes.` instead of rendering an empty dump).
    @Test func testCraftPreviewNeedsBytes() {
        #expect(L4CraftPreview(json: .object(["length": .number(36)])) == nil)
        #expect(L4CraftPreview(json: .object(["bytes": .string("***")])) == nil)
        #expect(L4CraftPreview(json: .object(["bytes": .number(1)])) == nil)
        #expect(L4CraftPreview(json: .null) == nil)
        let empty = L4CraftPreview(json: .object(["bytes": .string("")]))
        #expect(empty?.bytes == Data())
        #expect(empty?.length == 0)
        #expect(empty?.layers == [])
    }
}

@Suite struct L4TesterWireCapabilityTests {
    /// AC39 at the descriptor level: `confirmable` on a *different* tool, or on a tool whose name
    /// merely starts with `l4.scope.add`, never enables the form; two descriptors for the add
    /// verb enable it as soon as one is confirmable (the core lists each name once, but the
    /// rule is "any confirmable l4.scope.add").
    @Test func testSupportsOperatorScopeAddMatchesTheExactName() {
        let schema = JSONValue.object(["type": .string("object"), "properties": .object([:])])
        let lookalike = ToolDescriptor(name: "l4.scope.add.v2", description: "", inputSchema: schema, confirmable: true)
        let caps = ToolDescriptor(name: "L4.scope.add", description: "", inputSchema: schema, confirmable: true)
        let inject = ToolDescriptor(name: "l4.inject", description: "", inputSchema: schema, confirmable: true)
        let add = ToolDescriptor(name: "l4.scope.add", description: "", inputSchema: schema, confirmable: true)
        let plainAdd = ToolDescriptor(name: "l4.scope.add", description: "", inputSchema: schema)
        #expect(!L4Wire.supportsOperatorScopeAdd([lookalike, caps, inject]))
        #expect(!L4Wire.supportsOperatorScopeAdd([plainAdd, inject]))
        #expect(L4Wire.supportsOperatorScopeAdd([plainAdd, add]))
        #expect(L4Wire.supportsOperatorScopeAdd([inject, lookalike, add]))
    }

    /// `supportsWindow` reads `properties.limit` and nothing else: a `limit` outside
    /// `properties`, a schema with no `properties`, or a `limit` on another verb is no window.
    @Test func testSupportsWindowReadsOnlyTheFlowGetProperties() {
        let noProps = ToolDescriptor(name: "l4.flow.get", description: "", inputSchema: .object(["type": .string("object")]))
        let topLevel = ToolDescriptor(name: "l4.flow.get", description: "",
                                      inputSchema: .object(["limit": .object(["type": .string("integer")])]))
        let onList = ToolDescriptor(name: "l4.flow.list", description: "",
                                    inputSchema: .object(["properties": .object(["limit": .object([:])])]))
        let nullLimit = ToolDescriptor(name: "l4.flow.get", description: "",
                                       inputSchema: .object(["properties": .object(["limit": .null])]))
        #expect(!L4Wire.supportsWindow([noProps]))
        #expect(!L4Wire.supportsWindow([topLevel]))
        #expect(!L4Wire.supportsWindow([onList]))
        #expect(!L4Wire.supportsWindow([]))
        // A `limit` property that is JSON null still counts as declared.
        #expect(L4Wire.supportsWindow([nullLimit]))

        // The args builders never carry a key the core did not declare: no `filter`, no
        // `_confirm`, no `inspect`.
        for inspect in [true, false] {
            for window in [true, false] {
                let args = L4Wire.flowGetArgs(id: FlowID("F"), inspect: inspect, window: window)
                #expect(Set(args.keys).isSubset(of: ["id", "offset", "limit"]))
                #expect(args["id"] == .string("F"))
            }
        }
    }
}

@Suite struct L4TesterRowVerbTests {
    /// AC29 on every L4 session kind and both scope states: capture, craft, send_recv and
    /// intercept rows, in and out of scope, all end with the same eleven HTTP verbs disabled and
    /// the three host verbs as the table built them. An out-of-scope L4 row keeps the table's
    /// scope reason on the host verbs (the gate never rewrites a reason it did not set).
    @Test func testEveryL4KindAndScopeStateIsGated() {
        for state in [L4SessionState.capture, .craft, .sendRecv, .intercept] {
            for inScope in [true, false] {
                let flow = L4Flow(id: FlowID("x"), sessionState: state, interface: "lo0", packetCount: 1,
                                  injectedCount: 0, packets: [])
                let row = flow.row(seq: 3, inScope: inScope)
                let original = VerbTable.items(for: VerbContext(row: row, selectedCount: 2, selectedPausedCount: 2))
                let gated = original.map { L4RowVerbs.gate($0, row: row) }
                #expect(gated.count == original.count)
                let disabled = gated.filter { !$0.enabled }.map(\.verb)
                let httpOnly: [FlowVerb] = [
                    .resume, .edit, .delete, .kill, .replay, .editAndReplay, .buildPoC, .resumeSelected, .killSelected,
                    .mark(nil), .comment,
                ]
                for verb in httpOnly {
                    let item = VerbTable.item(verb, in: gated)
                    #expect(!item.enabled, "\(state) inScope=\(inScope): \(verb) enabled")
                    #expect(item.disabledReason == "Not available for L4 flows", "\(state) inScope=\(inScope): \(verb) reason")
                }
                #expect(Set(disabled).isSuperset(of: Set(httpOnly)))
                for verb in [FlowVerb.pinHost, .copyURL, .quickLook] {
                    #expect(VerbTable.item(verb, in: gated) == VerbTable.item(verb, in: original))
                }
                if !inScope {
                    #expect(VerbTable.item(.pinHost, in: gated).disabledReason == VerbTable.outOfScopeReason(row.authority))
                }
            }
        }
        // The gate is idempotent: gating twice is the same as once.
        let flow = L4Flow(id: FlowID("y"), sessionState: .intercept, interface: "lo0", packetCount: 1, injectedCount: 0,
                          packets: [])
        let row = flow.row(seq: 1, inScope: true)
        let once = VerbTable.items(for: VerbContext(row: row)).map { L4RowVerbs.gate($0, row: row) }
        #expect(once.map { L4RowVerbs.gate($0, row: row) } == once)
        // A WebSocket row is not an L4 row: untouched.
        let ws = FlowRow(id: FlowID("w"), seq: 1, kind: .websocket, method: .get, scheme: "wss", authority: "ws.example.test",
                         path: "/", status: 101, state: .complete)
        let wsItems = VerbTable.items(for: VerbContext(row: ws))
        #expect(wsItems.map { L4RowVerbs.gate($0, row: ws) } == wsItems)
    }
}
