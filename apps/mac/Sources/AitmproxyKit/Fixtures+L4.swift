import AitmBusClient
import Foundation

// Raw-L4 fixture flows so the L4 operator surface (ui-scripting-highlight-l4
// Part 3) renders and snapshots without a live privileged core: an in-scope
// loopback UDP capture with one injected packet, and an out-of-L4-scope TCP
// session that the surface dims and disables (scope-as-authorization, AC9).
extension Fixtures {
    /// The fixed L4 scope the surface shows (loopback, operator-authorized).
    public static let l4Scope = "lo0 127.0.0.1/32 →"

    public static let l4Rows: [FlowRow] = l4Flows.enumerated().map { index, flow in
        flow.row(seq: 60 + index, inScope: flow.id == id(61) ? false : true)
    }

    /// The L4 flow details keyed by id, for the inspector.
    public static func l4Detail(for row: FlowRow) -> L4Flow? {
        l4Flows.first { $0.id == row.id }
    }

    static let l4Flows: [L4Flow] = [
        L4Flow(
            id: id(60), sessionState: .capture, interface: "lo0", filter: "udp port 9",
            packetCount: 4, injectedCount: 1,
            packets: [
                L4Packet(index: 0, dir: .outbound, length: 42, injected: false, layers: ["IPv4", "UDP"]),
                L4Packet(index: 1, dir: .inbound, length: 42, injected: false, layers: ["IPv4", "UDP"]),
                L4Packet(index: 2, dir: .outbound, length: 46, injected: true, layers: ["IPv4", "UDP"]),
                L4Packet(index: 3, dir: .inbound, length: 40, injected: false, layers: ["IPv4", "UDP"]),
            ]),
        L4Flow(
            id: id(61), sessionState: .capture, interface: "en0", filter: "tcp port 80",
            packetCount: 2, injectedCount: 0,
            packets: [
                L4Packet(index: 0, dir: .outbound, length: 60, injected: false, layers: ["IPv4", "TCP"]),
                L4Packet(index: 1, dir: .inbound, length: 52, injected: false, layers: ["IPv4", "TCP"]),
            ]),
        L4Flow(
            id: id(62), sessionState: .craft, interface: "lo0", filter: nil,
            packetCount: 1, injectedCount: 1,
            packets: [
                L4Packet(index: 0, dir: .outbound, length: 46, injected: true, layers: ["IPv4", "UDP"]),
            ]),
    ]

    /// Serialize an `L4Flow` back to the `l4.flow.get` JSON shape, so the fixture
    /// command runner answers `l4.flow.get` exactly as the live bus would.
    public static func l4FlowJSON(_ flow: L4Flow) -> JSONValue {
        let packets: [JSONValue] = flow.packets.map { p in
            .object([
                "dir": .string(p.dir.rawValue),
                "length": .number(Double(p.length)),
                "injected": .bool(p.injected),
                "layers": .array(p.layers.map { .string($0) }),
            ])
        }
        return .object([
            "id": .string(flow.id.raw),
            "kind": .string(flow.sessionState.rawValue),
            "interface": .string(flow.interface),
            "filter": flow.filter.map { .string($0) } ?? .null,
            "queue": flow.queue.map { .number(Double($0)) } ?? .null,
            "packet_count": .number(Double(flow.packetCount)),
            "injected_count": .number(Double(flow.injectedCount)),
            "packets": .array(packets),
        ])
    }

    /// A canned `l4.craft` / build-preview result for the craft editor on fixtures.
    public static let l4CraftBytes = Data([
        0x45, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x9c, 0x40, 0x00, 0x09,
        0x00, 0x1a, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2d, 0x6c, 0x34,
    ])
}
