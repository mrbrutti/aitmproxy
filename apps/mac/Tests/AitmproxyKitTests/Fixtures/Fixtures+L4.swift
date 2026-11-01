@testable import AitmproxyKit
import AitmBusClient
import Foundation

// Raw-L4 sample flows for the L4 unit tests (ui-scripting-highlight-l4 Part 3):
// an in-scope loopback UDP capture with one injected packet, and an
// out-of-L4-scope TCP session (scope-as-authorization, AC9).
extension Fixtures {
    static let l4Rows: [FlowRow] = l4Flows.enumerated().map { index, flow in
        flow.row(seq: 60 + index, inScope: flow.id == id(61) ? false : true)
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
}
