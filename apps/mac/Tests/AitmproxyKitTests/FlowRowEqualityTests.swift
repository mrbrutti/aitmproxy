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

    /// Every field a live row changes after it first appears — a park ending, a status
    /// landing, sizes and duration arriving, an edit, a mark, a comment, a scope change —
    /// must make the row unequal, or the table keeps drawing the stale cell (S-079: a
    /// resumed row that kept reading `Paused`).
    @Test func everyLiveMutationMakesTheRowUnequal() {
        let parked = FlowRow(id: FlowID("f-2"), seq: 2, method: .get, scheme: "http", authority: "127.0.0.1:38599",
                             path: "/a", state: .paused, client: nil, requestBytes: 0)
        let mutations: [(String, (inout FlowRow) -> Void)] = [
            ("state paused → complete", { $0.state = .complete }),
            ("status 404 landing", { $0.status = 404 }),
            ("edited pencil", { $0.edited = true }),
            ("duration", { $0.duration = .milliseconds(3_840) }),
            ("response bytes", { $0.responseBytes = 460 }),
            ("request bytes", { $0.requestBytes = 12 }),
            ("comment", { $0.comment = "seen" }),
            ("mark", { $0.mark = .red }),
            ("scope", { $0.inScope.toggle() }),
            ("WebSocket frame counts", { $0.wsFrames = (sent: 3, received: 1) }),
            ("L4 packet count", { $0.l4 = L4RowInfo(proto: .tcp, sessionState: .capture, target: "10.0.0.1:443", packetCount: 7, injectedCount: 0, inScope: true) }),
            ("seq after a Clear", { $0.seq = 1 }),
        ]
        for (name, mutate) in mutations {
            var changed = parked
            mutate(&changed)
            #expect(changed != parked, "\(name) must change equality")
            #expect([changed] != [parked], "\(name) must change the array SwiftUI compares")
        }
        // The resumed row as the poll rebuilds it: state, status, duration, sizes and the pencil at once.
        var resumed = parked
        resumed.state = .complete
        resumed.status = 404
        resumed.duration = .milliseconds(3_840)
        resumed.responseBytes = 460
        resumed.edited = true
        #expect(resumed != parked)
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
