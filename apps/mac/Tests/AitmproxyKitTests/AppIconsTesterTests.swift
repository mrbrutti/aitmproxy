import Foundation
import Testing
@testable import AitmproxyKit

/// Stage-5 tester additions for spec 2026-10-31-mac-app-icons-and-names (the Kit half: AI-AC1 … AI-AC12).
/// The Coder suites pin the spec's own literals; these pin the shapes those literals leave open —
/// the places where a rule could flip and every AC-literal test would still pass: the three-component
/// floor on a trailing-dot id, a 15- versus 16-hex ad-hoc tail, the greedy group of the ad-hoc regex,
/// `sanitized`'s order of operations, the byte-order tie-breaks, `BoundedCache` on `nil` and at
/// capacity 1 / 0, the "a domain under a pinned app is not itself pinned" corner, the Overview's
/// first-row-name rule. Every expected value is a test-local literal; rows are built by a private
/// helper here (the plan's private row-builder rule), never shared.
@Suite struct AppIconsTesterTests {
    private func row(_ id: String, _ seq: Int, _ host: String, _ client: ClientInfo?, inScope: Bool = true,
                     l4: L4RowInfo? = nil) -> FlowRow {
        FlowRow(id: FlowID(id), seq: seq, kind: l4 == nil ? .http : .l4, method: .get, scheme: "https",
                authority: host, path: "/", client: client, inScope: inScope, l4: l4)
    }

    // MARK: AI-AC1 — the three-component floor, seen from its edges

    /// A trailing dot is an empty fourth component, so the walk yields the three-component prefix
    /// and stops there (a floor of two would add `com.apple`). Two segments never walk. Case and a
    /// leading empty component are kept as sent; a six-component id walks three steps.
    @Test func candidatesEdgeShapes() {
        #expect(AppIdentifier.candidates(for: "com.apple.Safari.") == ["com.apple.Safari.", "com.apple.Safari"])
        #expect(AppIdentifier.candidates(for: "a.b") == ["a.b"])
        #expect(AppIdentifier.candidates(for: "COM.Apple.SAFARI.Broker") == ["COM.Apple.SAFARI.Broker", "COM.Apple.SAFARI"])
        #expect(AppIdentifier.candidates(for: "com..Chrome") == ["com..Chrome"])
        #expect(AppIdentifier.candidates(for: ".a.b.c") == [".a.b.c", ".a.b"])
        #expect(AppIdentifier.candidates(for: "a.b.c.d.e.f") == ["a.b.c.d.e.f", "a.b.c.d.e", "a.b.c.d", "a.b.c"])
        // The first candidate is always the identifier itself, verbatim.
        #expect(AppIdentifier.candidates(for: " x.y.z ").first == " x.y.z ")
    }

    // MARK: AI-AC2 — the 16-digit boundary and the regex's exact shape

    /// Fifteen hex digits are not a linker hash; sixteen are. The group before the dash is greedy, so a
    /// doubled tail loses only the last one; a dash with nothing before it, an underscore, a non-hex
    /// digit, a trailing newline or space all leave the identifier alone.
    @Test func trimmedAdHocBoundary() {
        #expect(AppIdentifier.trimmedAdHoc("node-123456789abcdef") == "node-123456789abcdef")
        #expect(AppIdentifier.trimmedAdHoc("node-0123456789abcdef") == "node")
        #expect(AppIdentifier.trimmedAdHoc("Node-0123456789abcdef") == "Node")
        #expect(AppIdentifier.trimmedAdHoc("a-b-0123456789abcdef") == "a-b")
        #expect(AppIdentifier.trimmedAdHoc("node-0123456789abcdef-0123456789abcdef") == "node-0123456789abcdef")
        #expect(AppIdentifier.trimmedAdHoc("-0123456789abcdef") == "-0123456789abcdef")
        #expect(AppIdentifier.trimmedAdHoc("node_0123456789abcdef") == "node_0123456789abcdef")
        #expect(AppIdentifier.trimmedAdHoc("node-0123456789abcdeg") == "node-0123456789abcdeg")
        #expect(AppIdentifier.trimmedAdHoc("node-0123456789abcdef\n") == "node-0123456789abcdef\n")
        #expect(AppIdentifier.trimmedAdHoc("node-0123456789abcdef ") == "node-0123456789abcdef ")
        #expect(AppIdentifier.trimmedAdHoc("") == "")
    }

    // MARK: AI-AC3 — the fallback never names a shared service after a host app

    /// `knownUnbundled` wins over PR B's `knownSourceApps` ("Safari"): the resolver's fallback for the
    /// WebKit networking service is the service's own name, never a host app (anti-goal 1). The owner map
    /// is the resolver's, not the fallback's: a Firefox helper with no bundle falls back to its last
    /// component. Lookups are exact and case-sensitive; an empty or all-format id is "unknown app".
    @Test func fallbackNameGuardsAndEdges() {
        #expect(AppIdentifier.fallbackName(for: "com.apple.WebKit.Networking") == "WebKit Networking")
        #expect(ClientInfo.displayName(forSourceApp: "com.apple.WebKit.Networking") == "Safari")
        #expect(AppIdentifier.fallbackName(for: "com.apple.WebKit.GPU") == "WebKit GPU")
        #expect(AppIdentifier.fallbackName(for: "com.apple.WebKit.WebContent") == "WebKit WebContent")
        #expect(AppIdentifier.fallbackName(for: "com.apple.WebKit.Networking.extra") == "extra")
        #expect(AppIdentifier.fallbackName(for: "com.apple.webkit.networking") == "networking")
        #expect(AppIdentifier.fallbackName(for: "org.mozilla.plugincontainer") == "plugincontainer")
        #expect(AppIdentifier.fallbackName(for: "trailing.") == "trailing.")
        #expect(AppIdentifier.fallbackName(for: "node-0123456789abcdef.x") == "x")
        #expect(AppIdentifier.fallbackName(for: "\u{202E}") == "unknown app")
        #expect(AppIdentifier.fallbackName(for: "") == "unknown app")
        #expect(ClientInfo.unnamedSourceApp == "unknown app")
    }

    /// D1 says "nothing else" for both tables: four unbundled ids, three Firefox helpers, no WebKit key
    /// in the owner map, every owner `org.mozilla.firefox`, and no id in both tables.
    @Test func tablesAreExactlyD1s() {
        #expect(AppIdentifier.knownUnbundled.count == 4)
        #expect(Set(AppIdentifier.knownUnbundled.keys) == [
            "com.apple.WebKit.Networking", "com.apple.WebKit.GPU", "com.apple.WebKit.WebContent",
            "com.apple.dt.xcode_select.tool-shim-public",
        ])
        #expect(AppIdentifier.ownerMap.count == 3)
        #expect(Set(AppIdentifier.ownerMap.keys) == [
            "org.mozilla.plugincontainer", "org.mozilla.firefox-gpu-helper", "org.mozilla.firefox-media-plugin-helper",
        ])
        #expect(Set(AppIdentifier.ownerMap.values) == ["org.mozilla.firefox"])
        #expect(AppIdentifier.ownerMap.keys.allSatisfy { !$0.hasPrefix("com.apple.WebKit") })
        #expect(Set(AppIdentifier.ownerMap.keys).isDisjoint(with: AppIdentifier.knownUnbundled.keys))
    }

    // MARK: AI-AC4 — sanitized's order: filter, trim, one `.app`, then the cap

    @Test func sanitizedOrderAndSuffixVariants() {
        #expect(AppIdentifier.sanitized(".app") == nil)
        #expect(AppIdentifier.sanitized(" .app ") == nil)
        #expect(AppIdentifier.sanitized("Foo.app.app") == "Foo.app")
        #expect(AppIdentifier.sanitized("Foo.APP") == "Foo.APP")
        #expect(AppIdentifier.sanitized("Foo.app\n") == "Foo")
        #expect(AppIdentifier.sanitized("Foo\u{0000}.app") == "Foo")
        #expect(AppIdentifier.sanitized("Zoom\u{200B}") == "Zoom")
        #expect(AppIdentifier.sanitized("A\tB") == "AB")
        #expect(AppIdentifier.sanitized("\u{00A0}Safari") == "Safari")
        #expect(AppIdentifier.sanitized("   ") == nil)
        #expect(AppIdentifier.sanitized("\u{1F600}") == "\u{1F600}")
        // The cap counts characters, not scalars, and applies after the `.app` drop.
        #expect(AppIdentifier.sanitized(String(repeating: "é", count: 100)) == String(repeating: "é", count: 64))
        #expect(AppIdentifier.sanitized(String(repeating: "x", count: 62) + ".app") == String(repeating: "x", count: 62))
        #expect(AppIdentifier.sanitized(String(repeating: "x", count: 70) + ".app") == String(repeating: "x", count: 64))
        // Exactly 64 is kept whole; 65 loses one.
        #expect(AppIdentifier.sanitized(String(repeating: "x", count: 64))?.count == 64)
        #expect(AppIdentifier.sanitized(String(repeating: "x", count: 65))?.count == 64)
    }

    // MARK: AI-AC5 — service paths: the four shapes, exactly

    /// `.xpc` as the last component, `/Helpers/` only as a whole component, case-sensitive, and the
    /// `/Contents/Library/LoginItems/` and `/XPCServices/` markers need a component after them.
    @Test func servicePathEdges() {
        #expect(AppIdentifier.isServicePath("/Applications/Foo.xpc"))
        #expect(AppIdentifier.isServicePath("/Applications/Foo.xpc/Contents/MacOS/Foo"))
        #expect(AppIdentifier.isServicePath("/Applications/Helpers/Foo.app"))
        #expect(!AppIdentifier.isServicePath("/Applications/My Helpers Inc.app"))
        #expect(!AppIdentifier.isServicePath("/Applications/XPCServices"))
        #expect(!AppIdentifier.isServicePath("/Applications/Foo.app/Contents/Library/LoginItems"))
        #expect(!AppIdentifier.isServicePath("/Applications/xpcservices/foo"))
        #expect(!AppIdentifier.isServicePath("/Applications/Foo.xpcx"))
        #expect(!AppIdentifier.isServicePath(""))
        #expect(!AppIdentifier.isServicePath("/"))

        #expect(AppIdentifier.serviceLabel("") == " (Service)")
        #expect(AppIdentifier.serviceLabel(String(repeating: "x", count: 64)) == String(repeating: "x", count: 64) + " (Service)")
        #expect(AppIdentifier.serviceLabel(String(repeating: "x", count: 65)) == String(repeating: "x", count: 64) + " (Service)")
    }

    // MARK: AI-AC6 — groupKey is `bundleID ?? name`, and renaming keeps pid but recomputes the monogram

    @Test func groupKeyAndRenameEdges() {
        // An empty identifier is still an identifier (the wire decoder maps "" to nil, so this is the Kit rule only).
        #expect(ClientInfo(name: "x", bundleID: "").groupKey == "")
        #expect(ClientInfo(name: "Safari", bundleID: "com.apple.Safari").groupKey == "com.apple.Safari")

        let renamed = ClientInfo(name: "a", bundleID: "b", pid: 42).withResolvedName("c")
        #expect(renamed.pid == 42)
        #expect(renamed.bundleID == "b")
        #expect(renamed.monogram == "c")
        #expect(renamed.groupKey == "b")

        // A custom monogram does not survive a rename: the monogram follows the new name.
        #expect(ClientInfo(name: "curl", monogram: "#", bundleID: "c").withResolvedName("Curl").monogram == "C")
        // Without an identifier the key follows the name — the resolver never renames such a client (D3).
        let noID = ClientInfo(name: "curl").withResolvedName("Curl")
        #expect(noID.bundleID == nil)
        #expect(noID.groupKey == "Curl")
        #expect(ClientInfo(name: "x", bundleID: "y").withResolvedName("").name == "")
        #expect(ClientInfo(name: "x", bundleID: "y").withResolvedName("").monogram == "")
        // Same name, different pid: still `self`, not a copy with the pid dropped.
        let pinned = ClientInfo(name: "Safari", bundleID: "com.apple.Safari", pid: 7)
        #expect(pinned.withResolvedName("Safari").pid == 7)
    }

    // MARK: AI-AC7 / AI-AC8 — tie-breaks are byte order, and hosts key on the group key

    /// Equal counts order by name in byte order (uppercase before lowercase), then by key; a case-folded
    /// sort would put `curl` before `Safari` and `alpha` before `Zed`.
    @Test func clientsTieOrderIsByteOrder() {
        let rows = [
            row("1", 1, "h", ClientInfo(name: "curl", bundleID: "com.apple.curl")),
            row("2", 2, "h", ClientInfo(name: "Safari", bundleID: "com.apple.Safari")),
            row("3", 3, "h", ClientInfo(name: "alpha", bundleID: "x.alpha.app")),
            row("4", 4, "h", ClientInfo(name: "Zed", bundleID: "dev.zed.Zed")),
        ]
        #expect(ClientTree.clients(in: rows).map(\.0.name) == ["Safari", "Zed", "alpha", "curl"])
        #expect(ClientTree.clients(in: rows).map(\.1) == [1, 1, 1, 1])
        #expect(ClientTree.clients(in: []).isEmpty)
        #expect(ClientTree.clients(in: [row("5", 5, "h", nil)]).isEmpty)
    }

    /// Count first, then host in byte order; a client with no identifier is found by its name and not
    /// by any identifier; an unknown key sees no hosts even when the rows are many.
    @Test func hostsUnderAnAppOrderAndNameKeyedClients() {
        let safari = ClientInfo(name: "Safari", bundleID: "com.apple.Safari")
        let curl = ClientInfo(name: "curl")
        let rows = [
            row("1", 1, "b.example", safari),
            row("2", 2, "a.example", safari),
            row("3", 3, "z.example", safari),
            row("4", 4, "z.example", safari),
            row("5", 5, "B.example", safari),
            row("6", 6, "example.com", curl),
        ]
        #expect(ClientTree.hosts(forClient: "com.apple.Safari", in: rows).map { "\($0.0):\($0.1)" }
            == ["z.example:2", "B.example:1", "a.example:1", "b.example:1"])
        #expect(ClientTree.hosts(forClient: "curl", in: rows).map { "\($0.0):\($0.1)" } == ["example.com:1"])
        #expect(ClientTree.hosts(forClient: "com.apple.curl", in: rows).isEmpty)
        #expect(ClientTree.hosts(forClient: "Safari", in: rows).isEmpty)
        #expect(ClientTree.hosts(forClient: "", in: rows).isEmpty)
    }

    // MARK: AI-AC9 — FlowQuery: pins by key, group ∧ pins, scope, identifier-less clients

    @Test func queryKeysAndCombinations() {
        let chrome = ClientInfo(name: "Google Chrome", bundleID: "com.google.Chrome")
        let helper = ClientInfo(name: "Google Chrome (Service)", bundleID: "com.google.Chrome.helper")
        let rows = [
            row("A", 1, "a.example", chrome),
            row("B", 2, "a.example", helper),
            row("C", 3, "a.example", chrome, inScope: false),
            row("D", 4, "b.example", ClientInfo(name: "curl")),
            row("E", 5, "c.example", nil),
        ]
        func ids(_ q: FlowQuery) -> [String] { q.apply(rows, details: [:]).map(\.id.raw) }

        // A pin by display name never matches an identified client; an empty pinned key never matches a client-less row.
        #expect(ids(FlowQuery(pins: Pins(apps: ["Google Chrome"]))) == [])
        #expect(ids(FlowQuery(pins: Pins(apps: [""]))) == [])
        // A client with no identifier is pinned by its name.
        #expect(ids(FlowQuery(pins: Pins(apps: ["curl"]))) == ["D"])
        // Group and pins both apply: the group narrows to Chrome ∧ a.example, the pinned host keeps both rows …
        #expect(ids(FlowQuery(group: .clientHost(client: "com.google.Chrome", host: "a.example"),
                              pins: Pins(hosts: ["a.example"]))) == ["A", "C"])
        // … and a pinned app that is not the group's app keeps none.
        #expect(ids(FlowQuery(group: .clientHost(client: "com.google.Chrome", host: "a.example"),
                              pins: Pins(apps: ["com.google.Chrome.helper"]))) == [])
        #expect(ids(FlowQuery(group: .host("a.example"), pins: Pins(apps: ["com.google.Chrome.helper"]))) == ["B"])
        // Scope applies before the group.
        #expect(ids(FlowQuery(inScopeOnly: true, group: .clientHost(client: "com.google.Chrome", host: "a.example"))) == ["A"])
        #expect(ids(FlowQuery(group: .clientHost(client: "curl", host: "b.example"))) == ["D"])
        #expect(ids(FlowQuery(group: .clientHost(client: "", host: "c.example"))) == [])

        #expect(FlowQuery(group: .clientHost(client: "k", host: "h")).isNarrowing)
        #expect(!FlowQuery().isNarrowing)
        #expect(FlowGroup.clientHost(client: "a", host: "b") != .clientHost(client: "b", host: "a"))
        #expect(FlowGroup.clientHost(client: "a", host: "b") != .host("b"))
        #expect(FlowGroup.clientHost(client: "a", host: "b") != .client("a"))
    }

    // MARK: AI-AC10 — a domain under an app is a host pin, and only a host pin

    @Test func domainUnderAPinnedAppIsNotItselfPinned() {
        var pins = Pins()
        pins.pin(.client("com.apple.Safari"))
        #expect(!pins.contains(.clientHost(client: "com.apple.Safari", host: "example.com")))
        #expect(!pins.contains(.host("example.com")))

        pins.pin(.clientHost(client: "com.apple.curl", host: "example.com"))
        #expect(pins.apps == ["com.apple.Safari"])
        #expect(pins.hosts == ["example.com"])
        #expect(!pins.contains(.client("com.apple.curl")))
        #expect(pins.contains(.clientHost(client: "com.apple.Safari", host: "example.com")))

        // `.host` and `.clientHost` share one host entry.
        pins.pin(.host("example.com"))
        #expect(pins.hosts == ["example.com"])
        pins.unpin(.host("example.com"))
        #expect(pins.hosts == [])
        #expect(!pins.contains(.clientHost(client: "com.apple.curl", host: "example.com")))

        pins.unpin(.client("com.apple.Safari"))
        #expect(pins.isEmpty)
        // Unpinning what is not pinned is a no-op.
        pins.unpin(.client("nobody"))
        pins.unpin(.clientHost(client: "nobody", host: "nowhere"))
        #expect(pins == Pins())
    }

    // MARK: AI-AC11 — Overview: the first row's name, the full order, L4 and identifier-less rows

    @Test func clientBarsNameFromFirstRowAndFullOrder() {
        let k = "com.google.Chrome"
        let early = row("1", 1, "h", ClientInfo(name: "Chrome", bundleID: k))
        let late = row("2", 2, "h", ClientInfo(name: "Google Chrome", bundleID: k))
        #expect(OverviewBreakdowns(rows: [early, late]).clients
            == [OverviewBreakdowns.ClientCount(key: k, name: "Chrome", count: 2)])
        #expect(OverviewBreakdowns(rows: [late, early]).clients
            == [OverviewBreakdowns.ClientCount(key: k, name: "Google Chrome", count: 2)])

        let rows = [
            row("1", 1, "h", ClientInfo(name: "Alpha", bundleID: "k2")),
            row("2", 2, "h", ClientInfo(name: "Beta", bundleID: "k0")),
            row("3", 3, "h", ClientInfo(name: "Zulu", bundleID: "k9")),
            row("4", 4, "h", ClientInfo(name: "Alpha", bundleID: "k1")),
            row("5", 5, "h", ClientInfo(name: "Zulu", bundleID: "k9")),
            row("6", 6, "h", nil),
        ]
        #expect(OverviewBreakdowns(rows: rows).clients == [
            OverviewBreakdowns.ClientCount(key: "k9", name: "Zulu", count: 2),
            OverviewBreakdowns.ClientCount(key: "k1", name: "Alpha", count: 1),
            OverviewBreakdowns.ClientCount(key: "k2", name: "Alpha", count: 1),
            OverviewBreakdowns.ClientCount(key: "k0", name: "Beta", count: 1),
        ])
        #expect(OverviewBreakdowns(rows: rows).clientMax == 2)
        // An identifier-less client keys on its name.
        #expect(OverviewBreakdowns(rows: [row("7", 7, "h", ClientInfo(name: "curl"))]).clients
            == [OverviewBreakdowns.ClientCount(key: "curl", name: "curl", count: 1)])
    }

    /// An L4 session is not an HTTP flow: its client adds no bar and does not change `clientMax`, while
    /// `OverviewStats.clients` counts distinct keys over every row.
    @Test func clientCountsAcrossL4AndIdentifierlessRows() {
        let l4 = L4RowInfo(proto: .udp, sessionState: .capture, target: "udp port 9", packetCount: 4, injectedCount: 0,
                           inScope: true)
        let rows = [
            row("1", 1, "example.com", ClientInfo(name: "Safari", bundleID: "com.apple.Safari")),
            row("2", 2, "lo0", ClientInfo(name: "nc", bundleID: "com.apple.nc"), l4: l4),
        ]
        #expect(OverviewBreakdowns(rows: rows).clients.map(\.key) == ["com.apple.Safari"])
        #expect(OverviewBreakdowns(rows: rows).l4Sessions.count == 1)

        // Same key through two spellings (an identifier-less client whose name IS the key) → one; same name, one with an identifier → two.
        let a = ClientInfo(name: "com.apple.Safari")
        let b = ClientInfo(name: "Safari", bundleID: "com.apple.Safari")
        let c = ClientInfo(name: "Safari")
        #expect(OverviewStats(rows: [row("1", 1, "h", a), row("2", 2, "h", b)]).clients == 1)
        #expect(OverviewStats(rows: [row("1", 1, "h", c), row("2", 2, "h", b)]).clients == 2)
        #expect(OverviewStats(rows: [row("1", 1, "h", nil), row("2", 2, "h", nil)]).clients == 0)
        #expect(OverviewStats(rows: []).clients == 0)
    }

    // MARK: AI-AC12 — BoundedCache on `nil`, overwrite, capacity 1 and 0

    /// `nil` deletes the entry and its age slot: a key deleted and re-inserted is the newest, not the
    /// oldest (a stale slot would evict it on the next insert).
    @Test func boundedCacheNilDeletesTheAgeSlot() {
        var c = BoundedCache<String, Int>(capacity: 3)
        c["a"] = 1
        c["b"] = 2
        c["c"] = 3
        c["a"] = nil
        #expect(c.count == 2)
        #expect(c["a"] == nil)
        c["a"] = 10
        c["d"] = 4
        #expect(c.count == 3)
        #expect(c["a"] == 10)
        #expect(c["b"] == nil)
        #expect(c["c"] == 3)
        #expect(c["d"] == 4)

        // Deleting then inserting two: the deleted key's slot is gone, so the eviction skips to the next oldest.
        var d = BoundedCache<String, Int>(capacity: 3)
        d["a"] = 1
        d["b"] = 2
        d["c"] = 3
        d["b"] = nil
        d["d"] = 4
        d["e"] = 5
        #expect(d["a"] == nil)
        #expect(d["c"] == 3 && d["d"] == 4 && d["e"] == 5)
        #expect(d.count == 3)

        // `nil` on an absent key changes nothing.
        var e = BoundedCache<String, Int>(capacity: 2)
        e["a"] = 1
        e["zz"] = nil
        #expect(e.count == 1 && e["a"] == 1)
    }

    /// Overwriting the oldest makes it the newest (the ruling of 2026-11-01) and keeps `count`.
    @Test func boundedCacheOverwriteRefreshesTheOldest() {
        var c = BoundedCache<String, Int>(capacity: 3)
        c["a"] = 1
        c["b"] = 2
        c["c"] = 3
        c["a"] = 10
        #expect(c.count == 3)
        c["d"] = 4
        #expect(c["a"] == 10)
        #expect(c["b"] == nil)
        #expect(c["c"] == 3 && c["d"] == 4)
        #expect(c.count == 3)
    }

    /// Capacity 1 holds exactly the newest key; capacity 0 (and below) holds nothing and never traps.
    @Test func boundedCacheCapacityOneAndZero() {
        var one = BoundedCache<String, Int>(capacity: 1)
        one["a"] = 1
        one["b"] = 2
        #expect(one.count == 1)
        #expect(one["a"] == nil)
        #expect(one["b"] == 2)
        one["b"] = 20
        #expect(one.count == 1 && one["b"] == 20)

        var zero = BoundedCache<String, Int>(capacity: 0)
        zero["a"] = 1
        #expect(zero.count == 0)
        #expect(zero["a"] == nil)

        var negative = BoundedCache<String, Int>(capacity: -5)
        negative["a"] = 1
        #expect(negative.count == 0)

        // The conditional conformance the resolver relies on (compile-time).
        // Compile-time check: the conditional `Sendable` conformance the resolver relies on (a runtime
        // `#expect` here could never fail — stage-6 Q-M4).
        let _: any Sendable = BoundedCache<String, Int>(capacity: 1)
    }

    // MARK: stage-6 security S-I1 / S-M3

    @Test func candidatesRefuseOversizeIdentifiers() {
        // 256 bytes with three components is still walked; one byte more is not asked of LaunchServices.
        let tail = String(repeating: "a", count: 256 - "com.x.".count)
        let atCap = "com.x." + tail
        #expect(atCap.utf8.count == 256)
        #expect(AppIdentifier.candidates(for: atCap) == [atCap])
        let overCap = atCap + "b"
        #expect(overCap.utf8.count == 257)
        #expect(AppIdentifier.candidates(for: overCap) == [])
        // Eight dotted components walk down to three; nine are refused outright.
        let eight = "a.b.c.d.e.f.g.h"
        #expect(AppIdentifier.candidates(for: eight).count == 6)
        #expect(AppIdentifier.candidates(for: eight).last == "a.b.c")
        #expect(AppIdentifier.candidates(for: eight + ".i") == [])
        // A 64 KiB all-dot identifier (the imported-session shape) yields no candidate at all.
        #expect(AppIdentifier.candidates(for: String(repeating: ".", count: 65536)) == [])
        // Multi-byte scalars count as bytes, not characters.
        let emoji = String(repeating: "\u{1F600}", count: 65)  // 65 × 4 = 260 bytes
        #expect(AppIdentifier.candidates(for: "a.b." + emoji) == [])
        #expect(AppIdentifier.maxIdentifierBytes == 256)
        #expect(AppIdentifier.maxIdentifierComponents == 8)
    }

    @Test func tooltipTextStripsFormatAndControlScalarsAndCaps() {
        #expect(AppIdentifier.tooltipText("com.apple.Safari") == "com.apple.Safari")
        // A right-to-left override cannot make the tail read as another vendor.
        #expect(AppIdentifier.tooltipText("com.evil.x\u{202E}irafaS.elppa.moc") == "com.evil.xirafaS.elppa.moc")
        #expect(AppIdentifier.tooltipText("a\u{0}b\u{7}c\u{200B}d") == "abcd")
        // No trimming and no `.app` rule: the tooltip is the identifier, not a display name.
        #expect(AppIdentifier.tooltipText(" com.x.app ") == " com.x.app ")
        #expect(AppIdentifier.tooltipText("").isEmpty)
        let long = String(repeating: "k", count: 300)
        #expect(AppIdentifier.tooltipText(long).count == 256)
    }
}
