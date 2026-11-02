import Foundation
import Testing
@testable import AitmproxyKit

/// Stage-5 tester additions for the UI half (Tasks 5/6) of spec 2026-10-31-mac-app-icons-and-names.
/// Nothing the two tasks added lives in the Kit (`Session`, `SidebarView`, `FlowCellView` and the
/// `BusService` poll loop are the app target, proven by Task 8 and the diff review). These pin the Kit
/// invariants the UI half LEANS on — the places where a Kit change would leave every AC-literal test
/// green while the sidebar tree or the Client cell silently broke:
/// - D3 / Task 6: the poll loop's rename repaints only because `FlowRow ==` covers `client`; a row whose
///   client changed its name alone must read as changed, and one renamed to the same name must not;
/// - D4 / D5 / Task 5 deviation (c): narrowing, pins, the tree and the Overview key on `groupKey`, so the
///   D3 rename moves nothing — the Apps row keyed by `\.0.groupKey` survives and `.client(key)` keeps matching;
/// - D7 / plan call 5: a stale pinned key rebuilt as `ClientInfo(name: key, bundleID: key)` has that key as
///   its `groupKey` and as the identifier the sidebar hands `ClientMark` and `tooltipText`; a pre-D7
///   name-stored pin matches only a name-keyed client.
/// Every expected value is a test-local literal; rows are built by a private helper here.
@Suite struct AppIconsUITesterTests {
    private func row(_ id: String, _ seq: Int, _ host: String, _ client: ClientInfo?) -> FlowRow {
        FlowRow(id: FlowID(id), seq: seq, method: .get, scheme: "https", authority: host, path: "/", client: client)
    }

    // MARK: D3 — the poll loop's rename is a changed row, the same name is not

    /// `BusService.scoped` replaces `row.client` with the cache's name (one line, Task 6). The next poll's
    /// rows must compare unequal for `session.rows` to update and every surface to repaint; once the name
    /// has settled the rows must compare equal again, or every poll would repaint the whole table.
    @Test func renamedClientIsAChangedRowAndASettledOneIsNot() {
        let before = row("f", 1, "example.com", ClientInfo(name: "Chrome", bundleID: "com.google.Chrome"))
        var renamed = before
        renamed.client = before.client?.withResolvedName("Google Chrome")
        #expect(renamed != before)
        #expect(renamed.client?.groupKey == before.client?.groupKey)
        #expect(renamed.client?.name == "Google Chrome")

        var settled = before
        settled.client = before.client?.withResolvedName("Chrome")
        #expect(settled == before)

        // The service label travels in `name` like any other rename and keeps the helper's own key.
        var service = row("g", 2, "example.com", ClientInfo(name: "helper", bundleID: "com.google.Chrome.helper"))
        service.client = service.client?.withResolvedName("Google Chrome (Service)")
        #expect(service.client?.name == "Google Chrome (Service)")
        #expect(service.client?.groupKey == "com.google.Chrome.helper")
        #expect(service != before)
    }

    // MARK: D4 / D5 — the tree, the narrowing, the pins and the Overview survive the rename

    /// Three rows of one identifier under two names (the first poll's Kit name, then the resolved one):
    /// one Apps row keyed by the identifier whose domains sum to its count; `.client(key)` and
    /// `.clientHost(key, host)` match across both names; neither name is a group; a pin by key keeps all
    /// three; the Overview tile and bars agree with the Apps header (the AI-AC20 invariant, pinned here).
    @Test func narrowingPinsAndTreeKeyOnTheIdentifierAcrossARename() {
        let key = "com.google.Chrome"
        let rows = [
            row("A", 1, "a.example", ClientInfo(name: "Chrome", bundleID: key)),
            row("B", 2, "b.example", ClientInfo(name: "Google Chrome", bundleID: key)),
            row("C", 3, "a.example", ClientInfo(name: "Google Chrome", bundleID: key)),
        ]
        func ids(_ q: FlowQuery) -> [String] { q.apply(rows, details: [:]).map(\.id.raw) }

        #expect(ids(FlowQuery(group: .client(key))) == ["A", "B", "C"])
        #expect(ids(FlowQuery(group: .clientHost(client: key, host: "a.example"))) == ["A", "C"])
        #expect(ids(FlowQuery(group: .clientHost(client: key, host: "b.example"))) == ["B"])
        #expect(ids(FlowQuery(group: .client("Chrome"))) == [])
        #expect(ids(FlowQuery(group: .client("Google Chrome"))) == [])
        #expect(ids(FlowQuery(pins: Pins(apps: [key]))) == ["A", "B", "C"])

        let clients = ClientTree.clients(in: rows)
        #expect(clients.map(\.0.groupKey) == [key])
        #expect(clients.map(\.1) == [3])
        #expect(clients.map(\.0.name) == ["Chrome"])
        let hosts = ClientTree.hosts(forClient: key, in: rows)
        #expect(hosts.map { "\($0.0):\($0.1)" } == ["a.example:2", "b.example:1"])
        #expect(hosts.map(\.1).reduce(0, +) == clients[0].1)

        #expect(OverviewStats(rows: rows).clients == clients.count)
        #expect(OverviewBreakdowns(rows: rows).clients.map(\.key) == [key])
        #expect(OverviewBreakdowns(rows: rows).clients.map(\.count) == [3])
    }

    // MARK: D7 / plan call 5 — a stale pinned key and a pre-D7 name pin

    /// The sidebar rebuilds a pinned key with no current client as `ClientInfo(name: key, bundleID: key)`:
    /// its `groupKey` is the key, the identifier it hands `ClientMark` and `tooltipText` is the key, and the
    /// tooltip shows the key unchanged. A pin stored by name before D7 matches only a client keyed by its
    /// name (an imported row), never the identified one, and stays unpinnable through `.client(name)`.
    @Test func stalePinnedKeyAndPreD7NamePin() {
        let key = "com.example.Gone"
        let rebuilt = ClientInfo(name: key, bundleID: key)
        #expect(rebuilt.groupKey == key)
        #expect((rebuilt.bundleID ?? rebuilt.name) == key)
        #expect(AppIdentifier.tooltipText(key) == key)
        // The same for a client with no identifier at all: the sidebar and the cell resolve it by its name.
        let nameless = ClientInfo(name: "curl")
        #expect((nameless.bundleID ?? nameless.name) == "curl")
        #expect(AppIdentifier.tooltipText(nameless.bundleID ?? nameless.name) == "curl")

        let rows = [
            row("S", 1, "example.com", ClientInfo(name: "Safari", bundleID: "com.apple.Safari")),
            row("I", 2, "example.com", ClientInfo(name: "Safari")),
        ]
        func ids(_ q: FlowQuery) -> [String] { q.apply(rows, details: [:]).map(\.id.raw) }
        let namePin = Pins(apps: ["Safari"])
        #expect(ids(FlowQuery(pins: namePin)) == ["I"])
        #expect(namePin.contains(.client("Safari")))
        #expect(!namePin.contains(.client("com.apple.Safari")))
        var pins = namePin
        pins.unpin(.client("Safari"))
        #expect(pins.isEmpty)

        // The sidebar's `current` lookup: a stored key with no current client finds nothing (title falls
        // back to the key); the two Safaris are two Apps rows, the name-keyed one first (byte order on key).
        let clients = ClientTree.clients(in: rows)
        #expect(clients.first { $0.0.groupKey == key } == nil)
        #expect(clients.map(\.0.groupKey) == ["Safari", "com.apple.Safari"])
        #expect(clients.first { $0.0.groupKey == "com.apple.Safari" }?.0.name == "Safari")
    }
}
