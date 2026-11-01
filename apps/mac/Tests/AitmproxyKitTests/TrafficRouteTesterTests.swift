import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// Stage-5 tester additions for spec 2026-10-31-mac-traffic-route-advice-design (TR-AC3/4/5/18/21/22):
/// the cases the Coder's suites leave indistinguishable from a default (a `decrypt` that agrees with
/// the fallback, a core sentence equal to our copy), the D10 rows they skip (waiting / degraded /
/// `.other` state words, the external-core and no-extension rows), the D5 invariants over a grid of
/// inputs, and the malformed wire values a bus decoder must shrug off. Every value is a test-local
/// literal; `L = "127.0.0.1:8080"`.
@Suite struct TrafficRouteTesterTests {
    private let listen = "127.0.0.1:8080"
    private let coreSentence = "Nothing is decrypted until a host is in Scope."

    private func make(kind: ActiveCoreKind = .embedded, bus: BusState = .connected("127.0.0.1:60745"),
                      role: String? = "operator", roleWarning: Bool = false,
                      capability: CaptureCapability = .capturing, supported: Bool = true,
                      hosts: Int = 0, flows: Int = 0, systemProxy: SystemProxyState? = nil,
                      caTrust: CATrustFacts? = nil, tunnelled: Int = 0, decrypt: DecryptStatus? = nil) -> ConnectionSummary {
        ConnectionSummary.make(core: nil, activeKind: kind, bus: bus, role: role, roleWarning: roleWarning,
                               capability: capability, captureSupported: supported, scopeHostCount: hosts,
                               flowCount: flows, listenAddress: listen, systemProxy: systemProxy, caTrust: caTrust,
                               tunnelledFlowCount: tunnelled, decrypt: decrypt)
    }

    /// HTTP and HTTPS both at `host:port`.
    private func both(_ host: String, _ port: Int) -> SystemProxyState {
        let endpoint = SystemProxyState.Endpoint(host: host, port: port)
        return SystemProxyState(http: endpoint, https: endpoint)
    }

    /// PR D's not-trusted facts: every store answered, none said yes.
    private func notTrusted() throws -> CATrustFacts {
        try #require(CATrustFacts(status: CAStatus(fingerprint: "AB:CD", installed: false, trusted: false, platform: "macos",
                                                    trustedScope: nil, trustReported: true)))
    }

    // MARK: TR-AC3 — the bus-not-ok rule, made discriminating

    /// TR-AC3 "bus not `.ok`": a `decrypt` that DISAGREES with the scope list is ignored. The Coder's case
    /// fed the quoted sentence with an empty list, which equals the fallback, so it passed whether or not
    /// `decrypt` was read (D3/D6: a stale value after a disconnect changes nothing).
    @Test(arguments: [BusState.disconnected, .connecting("127.0.0.1:60745"), .failed("connection refused")])
    func decryptIsIgnoredWhileTheBusLaneIsNotOK(bus: BusState) {
        let saysDecrypting = DecryptStatus(scopeHosts: 2, decrypting: true, advice: nil)
        let closedByList = make(bus: bus, hosts: 0, decrypt: saysDecrypting).routes
        #expect(closedByList.scope.open == false)
        #expect(closedByList.scope.line == "Nothing is decrypted until a host is in Scope.")
        #expect(closedByList.advice == [])
        #expect(closedByList.banner == nil && closedByList.bannerAction == nil)

        let saysNothing = DecryptStatus(scopeHosts: 0, decrypting: false, advice: "Nothing is decrypted until a host is in Scope.")
        let openByList = make(bus: bus, hosts: 3, decrypt: saysNothing).routes
        #expect(openByList.scope.open == true)
        #expect(openByList.scope.line == "Scope: 3 hosts decrypted")
    }

    /// The same with the bus connected but not as the operator (lane `.warning`, not `.ok`).
    @Test func decryptIsIgnoredWhileConnectedAsTheWrongRole() {
        let r = make(role: "agent", roleWarning: true, hosts: 0,
                     decrypt: DecryptStatus(scopeHosts: 2, decrypting: true, advice: nil)).routes
        #expect(r.scope.open == false)
        #expect(r.scope.line == "Nothing is decrypted until a host is in Scope.")
        #expect(r.advice == [])
    }

    // MARK: D3 — the core's sentence is quoted, not matched

    /// D3: the Scope line is `decrypt.advice` VERBATIM, so a core wording change reaches the app without an
    /// edit. The Coder's quoted case used our own words, which cannot tell quoting from falling back.
    @Test func theCoreSentenceIsQuotedNotOurCopy() {
        let reworded = DecryptStatus(scopeHosts: 0, decrypting: false, advice: "Decrypting nothing yet; add a host to Scope.")
        let s = make(hosts: 0, flows: 0, systemProxy: .off, decrypt: reworded)
        #expect(s.routes.scope.line == "Decrypting nothing yet; add a host to Scope.")
        #expect(s.routes.scope.state == "Decrypting nothing yet; add a host to Scope.")
        #expect(s.routes.scope.open == false)
        #expect(s.routes.scope.actions == [.addScopeHost, .openScope])
        #expect(s.routes.advice.map(\.line) == [
            "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it",
            "Decrypting nothing yet; add a host to Scope.",
        ])
        #expect(s.steps.first { $0.kind == .scopeSet }?.detail == "Decrypting nothing yet; add a host to Scope.")
        #expect(!s.routes.advice.contains { $0.line == ConnectionSummary.nothingDecryptedAdvice })

        let tunnels = make(hosts: 0, flows: 2, systemProxy: .off, tunnelled: 2, decrypt: reworded).routes
        #expect(tunnels.banner == "Decrypting nothing yet; add a host to Scope.")
        #expect(tunnels.bannerAction == .addScopeHost)

        // The open form stays ours whatever the core's advice says (its advice is null in that state).
        let open = make(hosts: 0, decrypt: DecryptStatus(scopeHosts: 1, decrypting: true, advice: "stale words")).routes
        #expect(open.scope.line == "Scope: 1 host decrypted")
        #expect(open.scope.open == true)
    }

    // MARK: D10 rows the Coder's table skipped

    /// D10 "waiting / degraded state words likewise": the All Apps state words lead the composed banner and
    /// the lane's own action is the button; a reason with its own " — " never leaks into the banner.
    @Test func waitingAndDegradedAllAppsComposeTheBanner() {
        let waiting = make(capability: .pendingApproval, hosts: 0, flows: 3).routes
        #expect(waiting.banner == "All Apps waiting for approval · Nothing is decrypted until a host is in Scope.")
        #expect(waiting.bannerAction == .approveInSystemSettings)

        let degraded = make(capability: .degraded("x"), hosts: 2, flows: 3, systemProxy: .off).routes
        #expect(degraded.banner == "system proxy off · All Apps degraded")
        #expect(degraded.bannerAction == .openCaptureSettings)

        let wordy = make(capability: .degraded("code signature invalid — reinstall the signed app"), hosts: 2, flows: 3).routes
        #expect(wordy.allApps?.line == "All Apps degraded — code signature invalid — reinstall the signed app")
        #expect(wordy.allApps?.state == "All Apps degraded")
        #expect(wordy.banner == "All Apps degraded")
        #expect(wordy.bannerAction == .openCaptureSettings)
    }

    /// TR-AC13(b)'s composed line, pinned in the Kit: another proxy's state words lead, the remedy clause
    /// stays out, the button is All Apps' (the system-proxy entry has no action until PR4). TR-AC5: the
    /// `.other` and HTTP-only steps carry the route words and detail.
    @Test func anotherProxyLeadsTheComposedBanner() {
        let other = make(capability: .inactive, hosts: 2, flows: 3, systemProxy: both("127.0.0.1", 9090))
        #expect(other.routes.systemProxy?.state == "system proxy on · 127.0.0.1:9090, not this core")
        #expect(other.routes.banner == "system proxy on · 127.0.0.1:9090, not this core · All Apps off")
        #expect(other.routes.bannerAction == .openCaptureSettings)
        #expect(other.routes.banner?.contains(" — ") == false)
        #expect(other.steps[2].kind == .systemProxy)
        #expect(other.steps[2].detail == "every proxy-aware app, regardless of Scope")
        #expect(other.steps[2].action == nil)

        let empty = make(capability: .inactive, hosts: 0, flows: 3, systemProxy: both("127.0.0.1", 9090)).routes
        #expect(empty.banner
                == "system proxy on · 127.0.0.1:9090, not this core · All Apps off · Nothing is decrypted until a host is in Scope.")

        // An HTTPS-only system proxy at a foreign endpoint still names that endpoint, never "off".
        let httpsOnly = SystemProxyState(http: nil, https: SystemProxyState.Endpoint(host: "10.0.0.5", port: 3128))
        let foreign = make(hosts: 2, systemProxy: httpsOnly).routes
        #expect(foreign.systemProxy?.state == "system proxy on · 10.0.0.5:3128, not this core")
        #expect(foreign.systemProxy?.line.contains("off") == false)

        let httpOnly = make(hosts: 2, systemProxy: SystemProxyState(http: SystemProxyState.Endpoint(host: "127.0.0.1", port: 8080), https: nil))
        #expect(httpOnly.steps[2].title == "system proxy on · 127.0.0.1:8080 · HTTP only")
        #expect(httpOnly.steps[2].done == true)
    }

    /// D10 rows "off | unsupported or external core" and "thisCore | unsupported": with no All Apps route
    /// the Scope fact alone decides, and an open system proxy keeps the banner away while rows are readable.
    @Test func externalCoreAndNoExtensionRows() {
        let ext = make(kind: .external, hosts: 0, flows: 3, systemProxy: .off).routes
        #expect(ext.allApps == nil)
        #expect(ext.banner == "system proxy off · Nothing is decrypted until a host is in Scope.")
        #expect(ext.bannerAction == .addScopeHost)
        let extScopeSet = make(kind: .external, hosts: 2, flows: 3, systemProxy: .off).routes
        #expect(extScopeSet.banner == "system proxy off")
        #expect(extScopeSet.bannerAction == nil)
        let extUnknownTunnels = make(kind: .external, hosts: 0, flows: 3, tunnelled: 3).routes
        #expect(extUnknownTunnels.banner == "Nothing is decrypted until a host is in Scope.")
        #expect(extUnknownTunnels.bannerAction == .addScopeHost)
        #expect(make(kind: .external, hosts: 0, flows: 3).routes.banner == nil)

        let ours = make(supported: false, hosts: 0, flows: 3, systemProxy: both("127.0.0.1", 8080)).routes
        #expect(ours.banner == nil)
        #expect(ours.anyOpen == true)
        #expect(ours.advice.map(\.kind) == [.scope])
        #expect(make(supported: false, hosts: 0, flows: 3, systemProxy: both("127.0.0.1", 8080), tunnelled: 3).routes.banner
                == "Nothing is decrypted until a host is in Scope.")
        let allOpen = make(supported: false, hosts: 2, flows: 3, systemProxy: both("127.0.0.1", 8080)).routes
        #expect(allOpen.banner == nil)
        #expect(allOpen.advice == [])
    }

    /// D5 `allTunnels ⇔ flowCount > 0 ∧ tunnelledFlowCount == flowCount`: an inconsistent count (more
    /// tunnels than rows, a mid-poll race) is not "every row a tunnel"; zero rows never banner.
    @Test func allTunnelsNeedsEveryRowAndAtLeastOne() {
        let us = both("127.0.0.1", 8080)
        #expect(make(hosts: 0, flows: 3, systemProxy: us, tunnelled: 4).routes.banner == nil)
        #expect(make(hosts: 0, flows: 0, systemProxy: us, tunnelled: 0).routes.banner == nil)
        #expect(make(hosts: 0, flows: 1, systemProxy: us, tunnelled: 1).routes.banner == "Nothing is decrypted until a host is in Scope.")
    }

    // MARK: D5 invariants over a grid

    /// D5 over a grid of inputs: no words without an ok bus; a banner needs rows; the banner is the closed
    /// entries' states in `advice` order joined " · ", never remedy text, never a second line; the button is
    /// the first shown entry's first action, and there is none without a banner.
    @Test func bannerInvariantsHoldAcrossTheGrid() throws {
        let notTrusted = try notTrusted()
        let capabilities: [CaptureCapability] = [.capturing, .inactive, .pendingApproval, .degraded("x — y")]
        let proxies: [SystemProxyState?] = [nil, .off, both("127.0.0.1", 8080), both("127.0.0.1", 9090)]
        let buses: [BusState] = [.connected("127.0.0.1:60745"), .disconnected]
        let cas: [CATrustFacts?] = [nil, notTrusted]
        let rows: [(flows: Int, tunnelled: Int)] = [(0, 0), (3, 0), (3, 3), (3, 4)]
        var banners = 0
        for capability in capabilities {
            for proxy in proxies {
                for bus in buses {
                    for supported in [true, false] {
                        for hosts in [0, 2] {
                            for row in rows {
                                for ca in cas {
                                    let r = make(bus: bus, capability: capability, supported: supported, hosts: hosts, flows: row.flows,
                                                 systemProxy: proxy, caTrust: ca, tunnelled: row.tunnelled).routes
                                    let label = "\(capability) proxy=\(String(describing: proxy)) \(bus) supported=\(supported) "
                                        + "hosts=\(hosts) flows=\(row.flows)/\(row.tunnelled) ca=\(ca != nil)"
                                    #expect(r.advice.allSatisfy { !$0.open }, "advice lists closed facts only: \(label)")
                                    if case .connected = bus {} else {
                                        #expect(r.advice.isEmpty && r.banner == nil && r.bannerAction == nil, "no words without the bus: \(label)")
                                    }
                                    guard let banner = r.banner else {
                                        #expect(r.bannerAction == nil, "no button without a banner: \(label)")
                                        continue
                                    }
                                    banners += 1
                                    #expect(row.flows > 0, "a banner needs rows: \(label)")
                                    #expect(!banner.contains(" — ") && !banner.contains("\n"), "states only, one line: \(label)")
                                    let shown = r.advice.filter { banner.contains($0.state) }
                                    #expect(banner == shown.map(\.state).joined(separator: " · "), "closed states in advice order: \(label)")
                                    #expect(r.bannerAction == shown.first { !$0.actions.isEmpty }?.actions.first, "the first shown entry's button: \(label)")
                                    if row.tunnelled != row.flows, r.anyOpen {
                                        #expect(!shown.contains { $0.kind == .scope }, "a readable row keeps the Scope fact off the banner: \(label)")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        #expect(banners > 0)
    }

    // MARK: TR-AC21 / TR-AC22 — malformed wire values

    /// TR-AC21 edges: strict about `scope_hosts` (the key that makes it the decrypt object), lenient about the
    /// rest, so a wire oddity can never stop a poll.
    @Test func decryptStatusShrugsOffMalformedFields() {
        #expect(DecryptStatus(json: ["scope_hosts": "2", "decrypting": true]) == nil)
        #expect(DecryptStatus(json: ["scope_hosts": 1.5]) == nil)
        #expect(DecryptStatus(json: ["scope_hosts": true]) == nil)
        #expect(DecryptStatus(json: .array([1, 2])) == nil)
        #expect(DecryptStatus(json: ["scope_hosts": 2, "decrypting": "yes", "advice": 5])
                == DecryptStatus(scopeHosts: 2, decrypting: true, advice: nil))
        #expect(DecryptStatus(json: ["scope_hosts": 0, "decrypting": .null, "advice": .null])
                == DecryptStatus(scopeHosts: 0, decrypting: false, advice: nil))
    }

    /// TR-AC22 edges: the five #228 keys with the wrong JSON type read as absent — the row still lists and
    /// is not a tunnel it was never told about; the byte counts take the body-size cap.
    @Test func tunnelFieldsOfTheWrongTypeReadAsAbsent() throws {
        func summary(_ extra: [String: JSONValue]) throws -> FlowSummary {
            var obj: [String: JSONValue] = [
                "id": "f-1", "kind": "http", "intercept": "observed", "is_replay": false, "method": "CONNECT",
                "scheme": "https", "authority": "example.com", "path": "/", "status": 200,
            ]
            for (key, value) in extra { obj[key] = value }
            return try #require(FlowSummary(json: .object(obj)))
        }
        let wrongTypes: [JSONValue] = [1, true, ["mode": "passthrough"], .array(["passthrough"]), "", .null]
        for tunnel in wrongTypes {
            let s = try summary(["tunnel": tunnel])
            #expect(s.tunnel == nil, "\(tunnel)")
            #expect(s.row(seq: 1).isTunnel == false && s.row(seq: 1).tls == .decrypted, "\(tunnel)")
        }
        let odd = try summary(["tunnel": "passthrough", "tunnel_reason": 5, "bytes_up": "1234", "bytes_down": 1.5, "passive": "yes"])
        #expect(odd.tunnel == .passthrough)
        #expect(odd.tunnelReason == nil)
        #expect(odd.tunnelBytesUp == nil && odd.tunnelBytesDown == nil)
        #expect(odd.passive == false)
        #expect(try summary(["passive": 1]).passive == false)
        // The body-size cap (1 TiB): past it a count is a lie, at it a count.
        #expect(try summary(["bytes_up": 2_199_023_255_552]).tunnelBytesUp == nil)
        #expect(try summary(["bytes_up": 1_099_511_627_776]).tunnelBytesUp == 1_099_511_627_776)
    }

    /// TR-AC22 edges on `flow.detail`: no `meta`, a non-object `meta`, a non-object `meta.tunnel`, a non-string
    /// `mode`, out-of-range counts — none a crash, none a tunnel the core did not report.
    @Test func detailMetaOfTheWrongShapeReadsAsNoTunnel() throws {
        func detail(meta: JSONValue?) throws -> FlowDetail {
            var obj: [String: JSONValue] = [
                "id": "d-1", "kind": "http",
                "request": ["method": "GET", "scheme": "https", "authority": "example.com", "path": "/",
                            "version": "HTTP/1.1", "headers": .array([]), "body": .null],
                "response": .null, "client_conn": ["peer": "127.0.0.1:50000"], "server_conn": .null,
            ]
            if let meta { obj["meta"] = meta }
            return try #require(FlowDetail(detailJSON: .object(obj)))
        }
        let none = try detail(meta: nil)
        #expect(none.tunnel == nil && none.passive == false)
        let text = try detail(meta: "passive")
        #expect(text.tunnel == nil && text.passive == false)
        let flat = try detail(meta: ["tunnel": "passthrough", "passive": "true"])
        #expect(flat.tunnel == nil && flat.passive == false)
        let numericMode = try detail(meta: ["tunnel": ["mode": 2, "reason": "out_of_scope"]])
        #expect(numericMode.tunnel == nil)
        let counts = try detail(meta: ["tunnel": ["mode": "passthrough", "reason": "pinned", "bytes_up": -1, "bytes_down": 2_199_023_255_552]])
        #expect(counts.tunnel == TunnelInfo(mode: .passthrough, reason: .pinned, bytesUp: nil, bytesDown: nil))
    }

    /// `FlowRow ==` holds for two rows with the same five tunnel values: the five rows in
    /// `FlowRowEqualityTests` prove `!=`; this proves the comparison is not simply always false.
    @Test func equalTunnelRowsCompareEqual() {
        func row() -> FlowRow {
            FlowRow(id: FlowID("t-1"), seq: 1, method: .connect, scheme: "https", authority: "example.com", path: "/",
                    tls: .tunnelled, tunnel: .passthrough, tunnelReason: .outOfScope, tunnelBytesUp: 1, tunnelBytesDown: 2, passive: true)
        }
        #expect(row() == row())
        #expect([row()] == [row()])
        var other = row()
        other.tunnelReason = .pinned
        #expect(other != row())
    }
}
