import Testing
@testable import AitmproxyKit

/// `FlowRow ==` decides when the table and SwiftUI redraw a row (both skip the update for
/// an equal value). A row whose client changes while everything else stays put must read
/// as changed: the sidebar's Apps groups and the Apps page derive from `client`.
struct FlowRowEqualityTests {
    private func row(client: ClientInfo?) -> FlowRow {
        FlowRow(id: FlowID("f-1"), seq: 1, method: .get, scheme: "https", authority: "example.com", path: "/", client: client)
    }

    @Test func aClientOnlyChangeMakesTheRowUnequal() {
        let attributed = row(client: ClientInfo(name: "Safari"))
        let unattributed = row(client: nil)
        #expect(attributed != unattributed)
        #expect(unattributed != attributed)
        // The array is what SwiftUI compares when `Session.rows` is assigned.
        #expect([attributed] != [unattributed])
    }

    @Test func theSameClientStillComparesEqual() {
        #expect(row(client: ClientInfo(name: "Safari")) == row(client: ClientInfo(name: "Safari")))
        #expect(row(client: nil) == row(client: nil))
    }

    @Test func hashingStaysOnIdentity() {
        // Hashable's contract only needs equal values to hash alike; keeping the hash on
        // (id, seq) means a client change never moves a row between hash buckets.
        var a = Hasher()
        row(client: ClientInfo(name: "Safari")).hash(into: &a)
        var b = Hasher()
        row(client: nil).hash(into: &b)
        #expect(a.finalize() == b.finalize())
    }
}
