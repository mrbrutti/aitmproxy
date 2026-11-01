import Foundation
import Testing
@testable import AitmproxyKit

/// The sidebar's Apps tree over rows built here (spec 2026-10-31-mac-app-icons-and-names, D1/D4;
/// AI-AC7, AI-AC8, AI-AC10, AI-AC12): grouping keys on the identifier, hosts under an app sum
/// to its count, group pins map to hosts and keys, and the resolver's cache evicts its oldest.
@Suite struct ClientTreeTests {
    private func row(_ id: String, _ seq: Int, _ host: String, _ client: ClientInfo?) -> FlowRow {
        FlowRow(id: FlowID(id), seq: seq, method: .get, scheme: "https", authority: host, path: "/", client: client)
    }

    /// AI-AC7's rows: Chrome twice, its helper once, its renderer once, one row with no client.
    private var chromeRows: [FlowRow] {
        let chrome = ClientInfo(name: "Google Chrome", bundleID: "com.google.Chrome")
        return [
            row("A", 1, "a.example", chrome),
            row("B", 2, "a.example", ClientInfo(name: "Google Chrome (Service)", bundleID: "com.google.Chrome.helper")),
            row("C", 3, "a.example", chrome),
            row("D", 4, "b.example",
                ClientInfo(name: "Google Chrome (Service)", bundleID: "com.google.Chrome.helper.renderer")),
            row("E", 5, "c.example", nil),
        ]
    }

    @Test func clientsGroupByIdentifierNotName() {
        let clients = ClientTree.clients(in: chromeRows)
        #expect(clients.map(\.0.groupKey)
            == ["com.google.Chrome", "com.google.Chrome.helper", "com.google.Chrome.helper.renderer"])
        #expect(clients.map(\.1) == [2, 1, 1])
        #expect(clients.map(\.0.name) == ["Google Chrome", "Google Chrome (Service)", "Google Chrome (Service)"])
    }

    /// Tester finding I-2: two clients with one identifier but different names (a row renamed by
    /// the resolver after an earlier row settled) are one app, named by the first row.
    @Test func clientsWithOneIdentifierAndTwoNamesAreOneApp() {
        let rows = [
            row("K1", 1, "example.com", ClientInfo(name: "Chrome", bundleID: "com.google.Chrome")),
            row("K2", 2, "example.com", ClientInfo(name: "Google Chrome", bundleID: "com.google.Chrome")),
            row("K3", 3, "www.apple.com", ClientInfo(name: "Google Chrome", bundleID: "com.google.Chrome")),
        ]
        let clients = ClientTree.clients(in: rows)
        #expect(clients.count == 1)
        #expect(clients.map(\.0.groupKey) == ["com.google.Chrome"])
        #expect(clients.map(\.0.name) == ["Chrome"])
        #expect(clients.map(\.1) == [3])
        #expect(ClientTree.hosts(forClient: "com.google.Chrome", in: rows).map { "\($0.0):\($0.1)" }
            == ["example.com:2", "www.apple.com:1"])
    }

    @Test func hostsUnderAnAppSumToItsCount() {
        let safari = ClientInfo(name: "Safari", bundleID: "com.apple.Safari")
        let curl = ClientInfo(name: "curl", bundleID: "com.apple.curl")
        let rows = [
            row("X1", 1, "example.com", safari),
            row("X2", 2, "example.com", safari),
            row("X3", 3, "example.com", safari),
            row("X4", 4, "www.apple.com", safari),
            row("Y1", 5, "example.com", curl),
            row("Y2", 6, "example.com", curl),
        ]
        let safariHosts = ClientTree.hosts(forClient: "com.apple.Safari", in: rows)
        #expect(safariHosts.map { "\($0.0):\($0.1)" } == ["example.com:3", "www.apple.com:1"])
        let safariCount = ClientTree.clients(in: rows).first { $0.0.groupKey == "com.apple.Safari" }?.1
        #expect(safariCount == 4)
        #expect(safariHosts.map(\.1).reduce(0, +) == safariCount)
        #expect(ClientTree.hosts(forClient: "com.apple.curl", in: rows).map { "\($0.0):\($0.1)" } == ["example.com:2"])
        #expect(ClientTree.hosts(forClient: "nobody", in: rows).isEmpty)
    }

    @Test func pinsMapGroupsToHostsAndKeys() {
        var pins = Pins()
        pins.pin(.client("com.apple.Safari"))
        #expect(pins.apps == ["com.apple.Safari"])
        #expect(pins.hosts == [])
        pins.pin(.clientHost(client: "com.apple.Safari", host: "example.com"))
        #expect(pins.hosts == ["example.com"])
        #expect(pins.apps == ["com.apple.Safari"])
        #expect(pins.contains(.host("example.com")))
        #expect(pins.contains(.clientHost(client: "anything", host: "example.com")))
        #expect(pins.contains(.client("com.apple.Safari")))
        #expect(!pins.contains(.client("Safari")))
        pins.unpin(.clientHost(client: "x", host: "example.com"))
        #expect(pins.hosts == [])
        pins.pin(.client("com.apple.Safari"))
        #expect(pins.apps.count == 1)
    }

    @Test func boundedCacheEvictsOldestInserted() {
        var c = BoundedCache<String, Int>(capacity: 3)
        c["a"] = 1
        c["b"] = 2
        c["c"] = 3
        c["d"] = 4
        #expect(c.count == 3)
        #expect(c["a"] == nil)
        #expect(c["d"] == 4)
        // Overwriting refreshes "b" to newest, so "c" is now the oldest (ruling 2026-11-01).
        c["b"] = 20
        c["e"] = 5
        #expect(c["c"] == nil)
        #expect(c["b"] == 20)
        #expect(c["e"] == 5)

        var big = BoundedCache<String, Int>(capacity: 512)
        for n in 0..<600 { big["k\(n)"] = n }
        #expect(big.count == 512)
        #expect(big["k87"] == nil)
        #expect(big["k88"] == 88)
        #expect(big["k599"] == 599)
    }
}
