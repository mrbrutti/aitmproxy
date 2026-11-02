import AitmBusClient
import Testing
@testable import AitmproxyKit

/// ST-AC1/ST-AC2: the one word table every connection indicator reads, and the
/// Getting-started steps, computed from published facts only.
@Suite struct ConnectionSummaryTests {
    private func core(_ status: CoreConnection.Status, proxy: String? = "127.0.0.1:8080") -> CoreConnection {
        CoreConnection(id: .fixture, kind: .embedded, endpoint: BusEndpoint(port: 0, token: ""), status: status,
                       label: "Embedded core", proxyAddress: proxy, appliedPort: 8080, appliedVerifyUpstreamTLS: true)
    }

    private func make(core: CoreConnection? = nil, kind: ActiveCoreKind = .embedded, bus: BusState = .disconnected,
                      role: String? = nil, roleWarning: Bool = false,
                      capability: CaptureCapability = .extensionNotInstalled, supported: Bool = true,
                      hosts: Int = 0, flows: Int = 0, coreCapture: CoreCaptureStatus? = nil,
                      systemProxy: SystemProxyState? = nil, caTrust: CATrustFacts? = nil, tunnelled: Int = 0,
                      decrypt: DecryptStatus? = nil) -> ConnectionSummary {
        ConnectionSummary.make(core: core, activeKind: kind, bus: bus, role: role, roleWarning: roleWarning,
                               capability: capability, captureSupported: supported, scopeHostCount: hosts,
                               flowCount: flows, listenAddress: "127.0.0.1:8080", coreCapture: coreCapture,
                               systemProxy: systemProxy, caTrust: caTrust, tunnelledFlowCount: tunnelled, decrypt: decrypt)
    }

    /// HTTP and HTTPS both at `host:port` (PR #246's `SystemProxyState(http:https:)`).
    private func both(_ host: String, _ port: Int) -> SystemProxyState {
        let endpoint = SystemProxyState.Endpoint(host: host, port: port)
        return SystemProxyState(http: endpoint, https: endpoint)
    }

    /// The core's own sentence, as `proxy.status.decrypt` carries it while Scope is empty (v0.5.9+).
    private let coreSentence = "Nothing is decrypted until a host is in Scope."
    private var quoted: DecryptStatus { DecryptStatus(scopeHosts: 0, decrypting: false, advice: coreSentence) }
    private let scopeDetail = "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel"
    private let systemProxyOffLine = "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it"
    private let allAppsOffLine = "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)"
    private let allAppsWaitingLine = "All Apps waiting for approval — approve the extension in System Settings"
    private let caNotTrustedDetail = "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"

    /// PR D's facts as `Session.caTrust` publishes them. `CATrustFacts` declares only `init?(status:)` (in its body,
    /// so Swift gives it no memberwise init); the value is built from a literal `CAStatus` and the two session
    /// flags set afterwards. TR-AC16's `notTrusted` = `caFacts()`: trusted false, scope nil, fingerprint "AB:CD",
    /// platform "macos", installing false, needsAdmin false; `trustedUser` = `caFacts(scope: "user")`.
    private func caFacts(scope: String? = nil, installing: Bool = false, needsAdmin: Bool = false) throws -> CATrustFacts {
        let status = CAStatus(fingerprint: "AB:CD", installed: scope != nil, trusted: scope != nil, platform: "macos",
                              trustedScope: scope, trustReported: true)
        var facts = try #require(CATrustFacts(status: status))
        facts.installing = installing
        facts.needsAdmin = needsAdmin
        return facts
    }

    /// D5 as ONE derivation: the banner is exactly the shown entries' `state`s joined " · " (nil when nothing is
    /// shown), the button is the first shown entry's first action, and the tooltip detail is their `detail`s
    /// joined " · " (nil when nothing is shown). A view reads `shown`; it never re-derives the set from the text.
    private func expectOneDerivation(_ r: TrafficRoutes, _ label: String = "", sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(r.banner == (r.shown.isEmpty ? nil : r.shown.map(\.state).joined(separator: " · ")), "\(label)", sourceLocation: sourceLocation)
        #expect(r.bannerAction == r.shown.first { !$0.actions.isEmpty }?.actions.first, "\(label)", sourceLocation: sourceLocation)
        #expect(r.bannerDetail == (r.shown.isEmpty ? nil : r.shown.map(\.detail).joined(separator: " · ")), "\(label)", sourceLocation: sourceLocation)
        #expect((r.banner == nil) == r.shown.isEmpty, "\(label)", sourceLocation: sourceLocation)
    }

    /// The Getting-started step of one kind; a test names the step it reads, never its position.
    private func step(_ summary: ConnectionSummary, _ kind: GettingStartedStep.Kind) -> GettingStartedStep? {
        summary.steps.first { $0.kind == kind }
    }

    // MARK: Core lane

    @Test func coreWords() {
        #expect(make(core: core(.ready)).core.word == "running")
        #expect(make(core: core(.ready)).core.state == .ok)
        #expect(make(core: core(.ready)).core.detail == "Embedded · proxy 127.0.0.1:8080")
        #expect(make(core: core(.starting)).core.word == "starting…")
        #expect(make(core: core(.connecting)).core.state == .working)
        let failed = make(core: core(.degraded(reason: "exited with status 1"))).core
        #expect(failed.state == .error && failed.word == "failed" && failed.detail == "exited with status 1")
        #expect(failed.remedy == "Restart the core" && failed.actions.first == .restartCore)
        #expect(make(core: core(.stopped)).core.word == "stopped")
        #expect(make(core: nil).core.word == "not running")
        #expect(make(core: nil).core.actions.first == .startCore)
    }

    @Test func externalCoreIsOffAndPointsAtBusSettings() {
        let lane = make(core: nil, kind: .external, bus: .connected("127.0.0.1:9090")).core
        #expect(lane.state == .off && lane.word == "external")
        #expect(lane.detail == "External · bus 127.0.0.1:9090")
        #expect(lane.actions == [.openBusSettings, .switchToEmbedded])
    }

    // MARK: Bus lane

    @Test func busWords() {
        let ok = make(bus: .connected("127.0.0.1:60745"), role: "operator").bus
        #expect(ok.state == .ok && ok.word == "connected" && ok.detail == "operator · 127.0.0.1:60745")
        let warn = make(bus: .connected("127.0.0.1:60745"), role: "agent", roleWarning: true).bus
        #expect(warn.state == .warning && warn.word == "connected as agent")
        #expect(warn.remedy == "Paste the operator token in Settings ▸ Bus, then reconnect")
        #expect(make(bus: .connecting("127.0.0.1:9090")).bus.word == "connecting…")
        let rejected = make(bus: .failed("the bus rejected the token")).bus
        #expect(rejected.state == .error && rejected.word == "bus failed")
        #expect(rejected.remedy == "Paste the operator token in Settings ▸ Bus, then reconnect")
        let offline = make(core: nil, bus: .disconnected).bus
        #expect(offline.state == .off && offline.word == "offline" && offline.actions == [.startCore])
        let offlineExternal = make(kind: .external, bus: .disconnected).bus
        #expect(offlineExternal.actions == [.reconnectBus, .openBusSettings])
    }

    // MARK: Capture lane

    @Test func captureWordsFollowTheAdvice() {
        #expect(make(capability: .capturing, supported: false).capture.word == "no extension")
        #expect(make(capability: .capturing, supported: false).capture.actions.isEmpty)
        let off = make(capability: .extensionNotInstalled).capture
        #expect(off.state == .off && off.word == "all apps off" && off.detail == "extension not installed")
        #expect(off.actions == [.turnCaptureOn, .openCaptureSettings])
        let inactive = make(capability: .inactive, hosts: 2).capture
        #expect(inactive.detail == "extension installed · 2 hosts in scope")
        #expect(inactive.actions.contains(.uninstallExtension))
        let waiting = make(capability: .pendingApproval).capture
        #expect(waiting.state == .working && waiting.word == "waiting for approval")
        #expect(waiting.actions.first == .approveInSystemSettings)
        let degraded = make(capability: .degraded("Extension activation failed: code signature invalid")).capture
        #expect(degraded.state == .error && degraded.word == "all apps degraded")
        #expect(degraded.remedy == "macOS refused this build's extension; install the signed Aitmproxy app")
        let empty = make(capability: .capturing, hosts: 0).capture
        #expect(empty.state == .warning && empty.word == "on, nothing in scope")
        #expect(empty.actions.first == .openScope)
        let on = make(capability: .capturing, hosts: 3).capture
        #expect(on.state == .ok && on.word == "all apps on · 3 hosts in scope")
        #expect(on.detail == "extension on · 3 hosts in scope")
        #expect(make(capability: .approvedAttached, hosts: 1).capture.word == "all apps on · 1 host in scope")
    }

    @Test func noCaptureWordSaysCapturingWithAnEmptyScope() {
        for capability in [CaptureCapability.approvedAttached, .capturing, .inactive, .pendingApproval, .extensionNotInstalled] {
            let lane = make(capability: capability, hosts: 0).capture
            #expect(!lane.word.localizedCaseInsensitiveContains("capturing"), "\(capability)")
        }
    }

    @Test func externalCoreCannotCapture() {
        let lane = make(kind: .external, capability: .capturing, hosts: 2).capture
        #expect(lane.state == .off && lane.word == "all apps off" && lane.actions == [.switchToEmbedded])
    }

    @Test func coreCaptureStatusSharpensTheOnLane() {
        let attached = make(capability: .capturing, hosts: 2,
                            coreCapture: CoreCaptureStatus(providerAttached: true, flowsHandedOff: 7)).capture
        #expect(attached.state == .ok && attached.detail == "attached · 2 hosts in scope · 7 flows handed off")
        let detached = make(capability: .capturing, hosts: 2,
                            coreCapture: CoreCaptureStatus(providerAttached: false, flowsHandedOff: 0)).capture
        #expect(detached.state == .warning && detached.word == "on, core not attached")
        #expect(detached.actions.first == .restartCore)
    }

    // MARK: Overall + steps

    @Test func overallIsTheWorstLane() {
        let healthy = make(core: core(.ready), bus: .connected("x"), role: "operator", capability: .capturing, hosts: 1, flows: 1)
        #expect(healthy.overall == .ok && healthy.allStepsDone)
        let scopeEmpty = make(core: core(.ready), bus: .connected("x"), role: "operator", capability: .capturing)
        #expect(scopeEmpty.overall == .warning && scopeEmpty.worst.kind == .capture)
        let coreFailed = make(core: core(.degraded(reason: "boom")), bus: .connected("x"), role: "operator", capability: .capturing, hosts: 1)
        #expect(coreFailed.overall == .error && coreFailed.worst.kind == .core)
    }

    @Test func gettingStartedStepsFollowTheFacts() {
        let fresh = make(core: core(.ready), bus: .connected("x"), role: "operator")
        #expect(fresh.steps.map(\.done) == [true, true, false, false, false])
        #expect(fresh.steps.map(\.title) == [
            "Core is running", "Bus connected",
            "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)",
            "Add a host to Scope (for now as example.com:443)", "Point a client at 127.0.0.1:8080, or open the browser",
        ])
        #expect(step(fresh, .extensionOn)?.action == .turnCaptureOn && step(fresh, .scopeSet)?.action == .openScope
                && step(fresh, .firstFlow)?.action == .openBrowser)
        let waiting = make(core: core(.ready), bus: .connected("x"), role: "operator", capability: .pendingApproval)
        #expect(step(waiting, .extensionOn)?.title == "All Apps waiting for approval — approve the extension in System Settings")
        let done = make(core: core(.ready), bus: .connected("x"), role: "operator", capability: .capturing, hosts: 2, flows: 14)
        #expect(done.steps.map(\.done) == [true, true, true, true, true])
        #expect(step(done, .scopeSet)?.title == "Scope: 2 hosts decrypted" && step(done, .firstFlow)?.title == "14 flows captured")
        let unsupported = make(core: core(.ready), bus: .connected("x"), role: "operator", supported: false, hosts: 1, flows: 1)
        #expect(step(unsupported, .extensionOn)?.title == "All Apps capture is not in this build" && step(unsupported, .extensionOn)?.action == nil)
        #expect(!unsupported.allStepsDone)
        let external = make(kind: .external, bus: .connected("x"), role: "operator")
        #expect(step(external, .coreRunning)?.done == true, "an external core counts as running once the bus is connected")
        let down = make(core: nil, bus: .disconnected)
        #expect(step(down, .coreRunning)?.title == "Start the core" && step(down, .coreRunning)?.action == .startCore)
        #expect(step(down, .busConnected)?.title == "Connect to the bus" && step(down, .busConnected)?.action == .startCore)
    }

    @Test func actionTitlesAreTitleCaseWithEllipsesWhereAViewOpens() {
        #expect(ConnectionAction.openScope.title == "Open Scope…")
        #expect(ConnectionAction.turnCaptureOn.title == "Capture All Apps")
        #expect(ConnectionAction.uninstallExtension.isDestructive)
        #expect(!ConnectionAction.restartCore.isDestructive)
    }

    @Test func remediesFallBackWhenTheReasonIsNotRecognised() {
        let refused = make(bus: .failed("connection refused")).bus
        #expect(refused.remedy == "Reconnect, or check the address in Settings ▸ Bus")
        let degraded = make(capability: .degraded("tunnel setup failed")).capture
        #expect(degraded.remedy == "Turn All Apps off and on again; if it stays degraded, uninstall and reinstall the extension")
    }

    @Test func laneStatesRankOffBelowWarningAndTheWorstTieBreaksToTheFirstLane() {
        #expect(LaneState.ok < LaneState.working && LaneState.working < LaneState.off
                && LaneState.off < LaneState.warning && LaneState.warning < LaneState.error)
        let bothOff = make(core: nil, kind: .embedded, bus: .connected("x"), role: "operator", capability: .extensionNotInstalled)
        #expect(bothOff.worst.kind == .core, "core and capture are both off; the first lane names the row")
    }

    @Test func compactTooltipAndSpokenComeFromTheLanes() {
        let s = make(core: core(.degraded(reason: "boom")), bus: .connected("127.0.0.1:1"), role: "operator", capability: .extensionNotInstalled)
        #expect(s.core.compact == "core: failed")
        #expect(s.capture.compact == "all apps off")
        #expect(s.tooltip == "Core: failed — boom\nBus: connected — operator · 127.0.0.1:1\nAll Apps: all apps off — extension not installed")
        #expect(s.spoken == "core: failed, bus: connected, all apps off")
    }

    // MARK: Traffic routes (spec 2026-10-31-mac-traffic-route-advice-design)

    /// TR-AC3: the Flows empty-state advice, the quoted core sentence, a stale list, and a bus that is not ok.
    @Test func routesAdviceAndBanner() {
        func routes(capability: CaptureCapability = .capturing, bus: BusState = .connected("127.0.0.1:60745"), hosts: Int = 0,
                    flows: Int = 0, tunnelled: Int = 0, systemProxy: SystemProxyState? = .off, decrypt: DecryptStatus? = nil) -> TrafficRoutes {
            make(bus: bus, role: "operator", capability: capability, hosts: hosts, flows: flows,
                 systemProxy: systemProxy, tunnelled: tunnelled, decrypt: decrypt).routes
        }
        let fresh = routes()
        #expect(fresh.advice.map(\.line) == [
            "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it",
            "Nothing is decrypted until a host is in Scope.",
        ])
        #expect(fresh.advice.map(\.kind) == [.systemProxy, .scope])
        #expect(fresh.allApps?.line == "All Apps on")
        #expect(fresh.allApps?.open == true)
        #expect(fresh.advice.map(\.detail) == [
            "every proxy-aware app, regardless of Scope",
            "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel",
        ])
        #expect(fresh.advice[0].actions == [])
        #expect(fresh.advice[1].actions == [.addScopeHost, .openScope])
        #expect(fresh.scope.state == "Nothing is decrypted until a host is in Scope.")
        #expect(fresh.banner == nil)
        #expect(fresh.bannerAction == nil)
        #expect(fresh.anyOpen == true)
        // Rows do not change the advice; the banner stays away while a route is open and rows are readable.
        let withRows = routes(flows: 6)
        #expect(withRows.advice.map(\.kind) == [.systemProxy, .scope])
        #expect(withRows.banner == nil)

        // The quoted core sentence (v0.5.9+): verbatim, period included.
        let core = quoted
        let quotedRoutes = routes(decrypt: core)
        #expect(quotedRoutes.scope.line == "Nothing is decrypted until a host is in Scope.")
        #expect(quotedRoutes.scope.state == "Nothing is decrypted until a host is in Scope.")
        #expect(quotedRoutes.scope.open == false)
        #expect(quotedRoutes.scope.actions == [.addScopeHost, .openScope])
        let allTunnels = routes(flows: 6, tunnelled: 6, decrypt: core)
        #expect(allTunnels.banner == "Nothing is decrypted until a host is in Scope.")
        #expect(allTunnels.bannerAction == .addScopeHost)
        let allOff = routes(capability: .inactive, flows: 6, decrypt: core)
        #expect(allOff.banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope.")
        #expect(allOff.bannerAction == .openCaptureSettings)

        // A stale scope list: the Scope fact follows `decrypt`, not `scopeHostCount`.
        let stale = routes(hosts: 0, decrypt: DecryptStatus(scopeHosts: 2, decrypting: true, advice: nil))
        #expect(stale.scope.open == true)
        #expect(stale.scope.line == "Scope: 2 hosts decrypted")
        #expect(!stale.advice.contains { $0.kind == .scope })
        #expect(routes(hosts: 0, flows: 6, tunnelled: 6, decrypt: DecryptStatus(scopeHosts: 2, decrypting: true, advice: nil)).banner == nil)

        // Bus not ok: `decrypt` is ignored, the Scope fact comes from `scopeHostCount`, and there is no advice.
        let offline = routes(bus: .disconnected, hosts: 0, decrypt: core)
        #expect(offline.scope.line == "Nothing is decrypted until a host is in Scope.")
        #expect(offline.advice == [])

        // An older core's null advice falls back to the same words.
        let fallback = DecryptStatus(scopeHosts: 0, decrypting: false, advice: nil)
        #expect(routes(decrypt: fallback).scope.line == "Nothing is decrypted until a host is in Scope.")
        #expect(routes(flows: 6, tunnelled: 6, decrypt: fallback).banner == "Nothing is decrypted until a host is in Scope.")
        #expect(routes(capability: .inactive, flows: 6, decrypt: fallback).banner
                == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope.")

        // Another proxy is the system proxy: the line names it and never reads "off".
        let other = routes(systemProxy: both("127.0.0.1", 9090))
        #expect(other.advice[0].line
                == "system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(other.advice.allSatisfy { !$0.line.contains("off") })
    }

    /// TR-AC4: one `make` per row of spec D10.
    @Test func predicateTable() {
        var produced: [TrafficRoutes] = []
        func row(kind: ActiveCoreKind = .embedded, bus: BusState = .connected("x"), role: String? = "operator", roleWarning: Bool = false,
                 _ capability: CaptureCapability, supported: Bool = true, systemProxy: SystemProxyState? = nil,
                 hosts: Int = 0, flows: Int = 0, tunnelled: Int = 0) -> TrafficRoutes {
            let routes = make(kind: kind, bus: bus, role: role, roleWarning: roleWarning, capability: capability, supported: supported,
                              hosts: hosts, flows: flows, systemProxy: systemProxy, tunnelled: tunnelled).routes
            produced.append(routes)
            return routes
        }
        let off = row(.inactive, systemProxy: .off)
        #expect(off.allApps?.line == "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)")
        #expect(off.allApps?.actions == [.openCaptureSettings])
        #expect(off.allApps?.open == false)
        let waiting = row(.pendingApproval)
        #expect(waiting.allApps?.line == "All Apps waiting for approval — approve the extension in System Settings")
        #expect(waiting.allApps?.actions == [.approveInSystemSettings])
        let degraded = row(.degraded("x"))
        #expect(degraded.allApps?.line == "All Apps degraded — x")
        #expect(degraded.allApps?.actions == [.openCaptureSettings])
        let one = row(.capturing, hosts: 1)
        #expect(one.allApps?.line == "All Apps on")
        #expect(one.allApps?.open == true)
        #expect(one.allApps?.actions == [])
        #expect(one.scope.line == "Scope: 1 host decrypted")
        #expect(one.scope.open == true)
        #expect(row(.capturing, hosts: 3).scope.line == "Scope: 3 hosts decrypted")

        let us = SystemProxyState.Endpoint(host: "127.0.0.1", port: 8080)
        let httpOnly = row(.capturing, systemProxy: SystemProxyState(http: us, https: nil))
        #expect(httpOnly.systemProxy?.line == "system proxy on · 127.0.0.1:8080 · HTTP only")
        #expect(httpOnly.systemProxy?.open == true)
        #expect(httpOnly.systemProxy?.actions == [])
        #expect(row(.capturing, systemProxy: SystemProxyState(http: nil, https: us)).systemProxy?.line
                == "system proxy on · 127.0.0.1:8080 · HTTPS only")
        #expect(row(.capturing, systemProxy: both("127.0.0.1", 8080)).systemProxy?.line == "system proxy on · 127.0.0.1:8080")

        let unknown = row(.capturing, systemProxy: nil, hosts: 0)
        #expect(unknown.systemProxy == nil)
        #expect(unknown.advice.map(\.line) == ["Nothing is decrypted until a host is in Scope."])

        // No extension in this build.
        let noExtScopeSet = row(.capturing, supported: false, systemProxy: .off, hosts: 2, flows: 3)
        #expect(noExtScopeSet.allApps == nil)
        #expect(noExtScopeSet.banner == "system proxy off")
        #expect(noExtScopeSet.bannerAction == nil)
        let noExtScopeEmpty = row(.capturing, supported: false, systemProxy: .off, hosts: 0, flows: 3)
        #expect(noExtScopeEmpty.banner == "system proxy off · Nothing is decrypted until a host is in Scope.")
        #expect(noExtScopeEmpty.bannerAction == .addScopeHost)
        #expect(row(.capturing, supported: false, systemProxy: nil, hosts: 0, flows: 3).banner == nil)
        #expect(row(.capturing, supported: false, systemProxy: nil, hosts: 0, flows: 3, tunnelled: 3).banner
                == "Nothing is decrypted until a host is in Scope.")
        #expect(row(.capturing, supported: false, systemProxy: .off, hosts: 0, flows: 0).advice.map(\.kind) == [.systemProxy, .scope])

        // System proxy unknown (every build until PR4), All Apps off: the banner never names the system proxy.
        let unknownOff = row(.inactive, systemProxy: nil, hosts: 0, flows: 3)
        #expect(unknownOff.banner == "All Apps off · Nothing is decrypted until a host is in Scope.")
        #expect(unknownOff.bannerAction == .openCaptureSettings)
        #expect(unknownOff.banner?.contains("system proxy") == false)
        #expect(!unknownOff.advice.contains { $0.line.contains("system proxy") })
        #expect(row(.inactive, systemProxy: nil, hosts: 2, flows: 3).banner == "All Apps off")

        // A route open: no banner while rows are readable.
        let openAllApps = row(.capturing, systemProxy: .off, hosts: 2, flows: 3)
        #expect(openAllApps.banner == nil)
        #expect(openAllApps.anyOpen == true)
        #expect(row(.capturing, systemProxy: both("127.0.0.1", 9090), hosts: 2, flows: 3).banner == nil)
        let openScopeEmpty = row(.capturing, systemProxy: both("127.0.0.1", 8080), hosts: 0, flows: 3)
        #expect(openScopeEmpty.banner == nil)
        #expect(openScopeEmpty.advice.map(\.kind) == [.scope])
        #expect(row(.capturing, systemProxy: both("127.0.0.1", 8080), hosts: 0, flows: 3, tunnelled: 3).banner
                == "Nothing is decrypted until a host is in Scope.")
        #expect(row(.capturing, systemProxy: both("127.0.0.1", 8080), hosts: 0, flows: 3, tunnelled: 2).banner == nil)

        // The bus lane must be ok: offline, or connected as the wrong role, yields no advice.
        let disconnected = row(bus: .disconnected, .capturing, systemProxy: .off, hosts: 0)
        #expect(disconnected.advice == [])
        #expect(disconnected.banner == nil)
        #expect(row(role: "agent", roleWarning: true, .capturing, systemProxy: .off).advice == [])

        // An external core runs no extension: no All Apps route.
        let external = row(kind: .external, .capturing, systemProxy: .off, hosts: 2)
        #expect(external.allApps == nil)
        #expect(external.advice.map(\.kind) == [.systemProxy])

        // Both routes closed.
        let bothClosedScopeSet = row(.inactive, systemProxy: .off, hosts: 2, flows: 3)
        #expect(bothClosedScopeSet.banner == "system proxy off · All Apps off")
        #expect(bothClosedScopeSet.bannerAction == .openCaptureSettings)
        #expect(row(.inactive, systemProxy: .off, hosts: 0, flows: 3).banner
                == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope.")

        // One derivation over every row above: banner, button and detail all read off `shown`.
        #expect(produced.contains { !$0.shown.isEmpty } && produced.contains { $0.shown.isEmpty })
        for (i, routes) in produced.enumerated() { expectOneDerivation(routes, "row \(i)") }
    }

    /// TR-AC5: the Getting-started steps carry the route words and details.
    @Test func stepsCarryTheRouteWords() {
        func steps(core: CoreConnection? = nil, _ capability: CaptureCapability = .capturing, systemProxy: SystemProxyState? = nil,
                   hosts: Int = 0, flows: Int = 0) -> ConnectionSummary {
            make(core: core, bus: .connected("x"), role: "operator", capability: capability, hosts: hosts, flows: flows, systemProxy: systemProxy)
        }
        #expect(!steps(systemProxy: nil).steps.map(\.kind).contains(.systemProxy))
        let off = steps(systemProxy: .off)
        #expect(off.steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .firstFlow])
        #expect(step(off, .systemProxy)?.done == false)
        #expect(step(off, .systemProxy)?.title == "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(step(off, .systemProxy)?.detail == "every proxy-aware app, regardless of Scope")
        #expect(step(off, .systemProxy)?.action == nil)
        let other = steps(systemProxy: both("127.0.0.1", 9090))
        #expect(step(other, .systemProxy)?.title
                == "system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(step(other, .systemProxy)?.done == false)
        let ours = steps(core: core(.ready), .capturing, systemProxy: both("127.0.0.1", 8080), hosts: 2, flows: 1)
        #expect(step(ours, .systemProxy)?.title == "system proxy on · 127.0.0.1:8080")
        #expect(step(ours, .systemProxy)?.done == true)
        #expect(step(ours, .systemProxy)?.action == nil)
        #expect(ours.allStepsDone == true)

        let scopeEmpty = steps(.capturing, hosts: 0)
        #expect(step(scopeEmpty, .extensionOn)?.title == "All Apps is on")
        #expect(step(scopeEmpty, .extensionOn)?.done == true)
        #expect(step(scopeEmpty, .extensionOn)?.detail == "in-scope hosts of every app")
        #expect(step(scopeEmpty, .scopeSet)?.title == "Add a host to Scope (for now as example.com:443)")
        #expect(step(scopeEmpty, .scopeSet)?.done == false)
        #expect(step(scopeEmpty, .scopeSet)?.action == .openScope)
        #expect(step(scopeEmpty, .scopeSet)?.detail == "Nothing is decrypted until a host is in Scope.")
        let inactive = steps(.inactive)
        #expect(step(inactive, .extensionOn)?.title
                == "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)")
        #expect(step(inactive, .extensionOn)?.action == .turnCaptureOn)
        let waiting = steps(.pendingApproval)
        #expect(step(waiting, .extensionOn)?.title == "All Apps waiting for approval — approve the extension in System Settings")
        #expect(step(waiting, .extensionOn)?.action == .approveInSystemSettings)
        let degraded = steps(.degraded("x"))
        #expect(step(degraded, .extensionOn)?.title == "All Apps degraded — x")
        #expect(step(degraded, .extensionOn)?.action == .openCaptureSettings)
        let scopeSet = steps(.capturing, hosts: 2)
        #expect(step(scopeSet, .scopeSet)?.title == "Scope: 2 hosts decrypted")
        #expect(step(scopeSet, .scopeSet)?.done == true)
        #expect(step(scopeSet, .scopeSet)?.action == nil)
        #expect(step(scopeSet, .scopeSet)?.detail
                == "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel")
        #expect(step(steps(.capturing, hosts: 1), .scopeSet)?.title == "Scope: 1 host decrypted")
        for kind in [GettingStartedStep.Kind.coreRunning, .busConnected, .firstFlow] {
            #expect(step(off, kind)?.detail == nil, "\(kind) carries no detail")
        }
    }

    /// TR-AC6: the Scope entry's remedy button, and the one action list (PR4's two system-proxy cases in
    /// place after it; no denied cases).
    @Test func addScopeHostAction() {
        #expect(ConnectionAction.addScopeHost.title == "Add Host…")
        #expect(ConnectionAction.addScopeHost.isDestructive == false)
        #expect(ConnectionAction.trustCA.title == "Trust the aitmproxy CA")
        #expect(ConnectionAction.allCases == [
            .startCore, .restartCore, .showCoreLog, .switchToEmbedded,
            .reconnectBus, .openBusSettings,
            .turnCaptureOn, .turnCaptureOff, .openScope, .approveInSystemSettings, .uninstallExtension, .openCaptureSettings,
            .openBrowser, .copyListenAddress,
            .addScopeHost,
            .setSystemProxy, .unsetSystemProxy,
            .trustCA, .openCAPanel,
        ])
    }

    /// TR-AC18: the banner is the shown facts' state words joined " · ", never a remedy clause; its one button.
    @Test func composedBanner() {
        func routes(_ capability: CaptureCapability, supported: Bool = true, systemProxy: SystemProxyState? = .off,
                    hosts: Int = 0, flows: Int = 0, tunnelled: Int = 0) -> TrafficRoutes {
            make(bus: .connected("x"), role: "operator", capability: capability, supported: supported,
                 hosts: hosts, flows: flows, systemProxy: systemProxy, tunnelled: tunnelled).routes
        }
        let off = routes(.capturing)
        #expect(off.systemProxy?.state == "system proxy off")
        #expect(off.systemProxy?.line.hasPrefix("system proxy off — set") == true)
        #expect(off.scope.state == "Nothing is decrypted until a host is in Scope.")
        #expect(off.scope.state == off.scope.line)
        #expect(routes(.capturing, hosts: 2).allApps?.line == "All Apps on")
        #expect(routes(.inactive).allApps?.state == "All Apps off")
        #expect(routes(.degraded("x")).allApps?.state == "All Apps degraded")

        let tunnels = routes(.capturing, hosts: 0, flows: 3, tunnelled: 3)
        #expect(tunnels.banner == "Nothing is decrypted until a host is in Scope.")
        #expect(tunnels.bannerAction == .addScopeHost)
        let freshWithPR4 = routes(.inactive, hosts: 0, flows: 3)
        #expect(freshWithPR4.banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope.")
        #expect(freshWithPR4.bannerAction == .openCaptureSettings)
        let freshUntilPR4 = routes(.inactive, systemProxy: nil, hosts: 0, flows: 3)
        #expect(freshUntilPR4.banner == "All Apps off · Nothing is decrypted until a host is in Scope.")
        #expect(freshUntilPR4.bannerAction == .openCaptureSettings)
        #expect(routes(.inactive, hosts: 2, flows: 3).banner == "system proxy off · All Apps off")
        let noExtension = routes(.capturing, supported: false, hosts: 2, flows: 3)
        #expect(noExtension.banner == "system proxy off")
        #expect(noExtension.bannerAction == nil)
        let none = routes(.capturing, hosts: 2, flows: 3)
        #expect(none.banner == nil)
        #expect(none.bannerAction == nil)
    }

    /// A route stores its state words and its remedy apart and composes `line` from them; nothing parses `line`.
    /// So a core sentence that itself contains " — " stays whole on the banner (D3 verbatim), and each builder's
    /// state is the exact head of its line.
    @Test func stateAndRemedyAreStoredNotParsed() {
        let dashed = DecryptStatus(scopeHosts: 0, decrypting: false, advice: "Nothing is decrypted — add a host to Scope.")
        let r = make(bus: .connected("x"), role: "operator", capability: .capturing, hosts: 0, flows: 3,
                     systemProxy: both("127.0.0.1", 8080), tunnelled: 3, decrypt: dashed).routes
        #expect(r.scope.state == "Nothing is decrypted — add a host to Scope.")
        #expect(r.scope.remedy == nil)
        #expect(r.scope.line == "Nothing is decrypted — add a host to Scope.")
        #expect(r.banner == "Nothing is decrypted — add a host to Scope.")
        #expect(r.bannerAction == .addScopeHost)

        let off = make(bus: .connected("x"), role: "operator", capability: .inactive, hosts: 2, systemProxy: .off).routes
        #expect(off.systemProxy?.state == "system proxy off")
        #expect(off.systemProxy?.remedy == "set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(off.systemProxy?.line == "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(off.allApps?.state == "All Apps off")
        #expect(off.allApps?.remedy == "turn it on to capture every app's traffic (macOS asks you to approve its extension)")
        #expect(off.allApps?.line == "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)")
        let other = make(bus: .connected("x"), role: "operator", capability: .pendingApproval, hosts: 2, systemProxy: both("127.0.0.1", 9090)).routes
        #expect(other.systemProxy?.state == "system proxy on · 127.0.0.1:9090, not this core")
        #expect(other.systemProxy?.remedy == "set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(other.allApps?.state == "All Apps waiting for approval")
        #expect(other.allApps?.remedy == "approve the extension in System Settings")
        let degraded = make(bus: .connected("x"), role: "operator", capability: .degraded("code signature invalid — reinstall"), hosts: 2).routes
        #expect(degraded.allApps?.state == "All Apps degraded")
        #expect(degraded.allApps?.remedy == "code signature invalid — reinstall")
        #expect(degraded.allApps?.line == "All Apps degraded — code signature invalid — reinstall")

        let on = make(bus: .connected("x"), role: "operator", capability: .capturing, hosts: 2, systemProxy: both("127.0.0.1", 8080)).routes
        #expect(on.systemProxy?.remedy == nil)
        #expect(on.systemProxy?.line == "system proxy on · 127.0.0.1:8080")
        #expect(on.allApps?.remedy == nil)
        #expect(on.allApps?.line == "All Apps on")
        #expect(on.scope.remedy == nil)
        #expect(on.scope.line == "Scope: 2 hosts decrypted")
        #expect(on.scope.state == "Scope: 2 hosts decrypted")
    }

    /// `scopeRoute` reads a blank `advice` as absent even when it arrives through the memberwise init (the decoder's
    /// rule is not the only door): the fallback sentence, never an empty Scope row or a blank banner.
    @Test func blankAdviceFromTheMemberwiseInitFallsBack() {
        for blank in ["", " ", "\n", "\t "] {
            let decrypt = DecryptStatus(scopeHosts: 0, decrypting: false, advice: blank)
            let r = make(bus: .connected("x"), role: "operator", capability: .capturing, hosts: 0, flows: 3,
                         systemProxy: both("127.0.0.1", 8080), tunnelled: 3, decrypt: decrypt).routes
            #expect(r.scope.line == "Nothing is decrypted until a host is in Scope.", "\(blank.debugDescription)")
            #expect(r.scope.open == false, "\(blank.debugDescription)")
            #expect(r.banner == "Nothing is decrypted until a host is in Scope.", "\(blank.debugDescription)")
            #expect(r.banner?.isEmpty == false, "\(blank.debugDescription)")
            #expect(r.advice.map(\.line) == ["Nothing is decrypted until a host is in Scope."], "\(blank.debugDescription)")
        }
        let plain = make(bus: .connected("x"), role: "operator", capability: .capturing, hosts: 0, flows: 0,
                         decrypt: DecryptStatus(scopeHosts: 0, decrypting: false, advice: "")).routes
        #expect(plain.scope.line == "Nothing is decrypted until a host is in Scope.")
    }

    /// The All Apps words reach the Status step from the one route table even when the route is not ours to
    /// show (an external core runs no extension: `routes.allApps == nil`), so step and route can never disagree.
    @Test func externalCoreStepsReuseTheAllAppsWords() {
        let ext = make(kind: .external, bus: .connected("x"), role: "operator", capability: .inactive, hosts: 2, systemProxy: .off)
        #expect(ext.routes.allApps == nil)
        #expect(step(ext, .extensionOn)?.title == "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)")
        #expect(step(ext, .extensionOn)?.done == false)
        #expect(step(ext, .extensionOn)?.action == .turnCaptureOn)
        #expect(step(ext, .extensionOn)?.detail == "in-scope hosts of every app")
        let extOn = make(kind: .external, bus: .connected("x"), role: "operator", capability: .capturing, hosts: 2)
        #expect(extOn.routes.allApps == nil)
        #expect(step(extOn, .extensionOn)?.title == "All Apps is on")
        #expect(step(extOn, .extensionOn)?.done == true)
        let extNoExt = make(kind: .external, bus: .connected("x"), role: "operator", supported: false, hosts: 2)
        #expect(step(extNoExt, .extensionOn)?.title == "All Apps capture is not in this build")
    }

    /// TR-AC18 with the system proxy known `.off`: the shown set leads with it, then All Apps, Scope and the CA,
    /// and `bannerDetail` is their four details in that order; without a CA fact, the first three.
    @Test func offLeadingShownSetAndItsDetail() throws {
        let notTrusted = try caFacts()
        let four = make(bus: .connected("x"), role: "operator", capability: .inactive, hosts: 0, flows: 3,
                        systemProxy: .off, caTrust: notTrusted).routes
        #expect(four.shown.map(\.kind) == [.systemProxy, .allApps, .scope, .caTrust])
        #expect(four.banner
                == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted")
        #expect(four.bannerAction == .openCaptureSettings)
        #expect(four.bannerDetail
                == "every proxy-aware app, regardless of Scope · in-scope hosts of every app · "
                + "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel · "
                + "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then")
        let three = make(bus: .connected("x"), role: "operator", capability: .inactive, hosts: 0, flows: 3, systemProxy: .off).routes
        #expect(three.shown.map(\.kind) == [.systemProxy, .allApps, .scope])
        #expect(three.banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope.")
        #expect(three.bannerDetail
                == "every proxy-aware app, regardless of Scope · in-scope hosts of every app · "
                + "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel")
        expectOneDerivation(four, "four")
        expectOneDerivation(three, "three")
    }

    // MARK: CA fact (spec D3/D4/D5; TR-AC16 and the CA cases of TR-AC18; every word is PR D's `CATrustFacts`)

    /// TR-AC16: the CA entry joins the advice last and the steps after Scope, worded by PR D's `text`/`actions`/`step`.
    @Test func caTrustJoinsAdviceAndSteps() throws {
        let notTrusted = try caFacts()
        #expect(notTrusted.trusted == false && notTrusted.scope == nil && notTrusted.fingerprint == "AB:CD")
        #expect(notTrusted.platform == "macos" && notTrusted.installing == false && notTrusted.needsAdmin == false)
        let s = make(bus: .connected("127.0.0.1:60745"), role: "operator", capability: .capturing, hosts: 0, flows: 0,
                     systemProxy: .off, caTrust: notTrusted)
        #expect(s.routes.caTrust?.kind == .caTrust)
        #expect(s.routes.caTrust?.open == false)
        #expect(s.routes.caTrust?.line == "HTTPS is not captured until the CA is trusted")
        #expect(s.routes.caTrust?.line == notTrusted.text)
        #expect(s.routes.caTrust?.detail == "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then")
        #expect(s.routes.caTrust?.actions == [.trustCA, .openCAPanel])
        #expect(s.routes.caTrust?.actions == notTrusted.actions)
        #expect(s.routes.advice.map(\.kind) == [.systemProxy, .scope, .caTrust])
        #expect(s.routes.advice.last?.line == "HTTPS is not captured until the CA is trusted")
        #expect(s.routes.anyOpen == true)
        #expect(s.steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .caTrusted, .firstFlow])
        #expect(step(s, .caTrusted)?.title == "Trust the aitmproxy CA")
        #expect(step(s, .caTrusted)?.done == false)
        #expect(step(s, .caTrusted)?.action == .trustCA)
        #expect(step(s, .caTrusted)?.detail == "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then")
        #expect(step(s, .caTrusted)?.title == notTrusted.step.title && step(s, .caTrusted)?.action == notTrusted.step.action)
        // No rows: the advice is the empty state's, the banner stays away.
        #expect(s.routes.banner == nil)
    }

    /// TR-AC16: the CA state joins the banner last whenever rows exist; alone it is the banner, with the Trust button.
    @Test func caTrustBanner() throws {
        let notTrusted = try caFacts()
        let trustedUser = try caFacts(scope: "user")
        func routes(_ capability: CaptureCapability = .capturing, systemProxy: SystemProxyState? = .off, hosts: Int = 0,
                    flows: Int, tunnelled: Int = 0, caTrust: CATrustFacts?) -> TrafficRoutes {
            make(bus: .connected("127.0.0.1:60745"), role: "operator", capability: capability, hosts: hosts, flows: flows,
                 systemProxy: systemProxy, caTrust: caTrust, tunnelled: tunnelled).routes
        }
        let readable = routes(flows: 6, caTrust: notTrusted)
        #expect(readable.banner == "HTTPS is not captured until the CA is trusted")
        #expect(readable.bannerAction == .trustCA)
        let tunnels = routes(flows: 6, tunnelled: 6, caTrust: notTrusted)
        #expect(tunnels.banner == "Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted")
        #expect(tunnels.bannerAction == .addScopeHost)
        let allOff = routes(.inactive, flows: 6, caTrust: notTrusted)
        #expect(allOff.banner
                == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted")
        #expect(allOff.bannerAction == .openCaptureSettings)
        let freshUntilPR4 = routes(.inactive, systemProxy: nil, flows: 6, caTrust: notTrusted)
        #expect(freshUntilPR4.banner
                == "All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted")
        #expect(freshUntilPR4.bannerAction == .openCaptureSettings)
        let caOnly = routes(systemProxy: both("127.0.0.1", 8080), hosts: 2, flows: 3, caTrust: notTrusted)
        #expect(caOnly.banner == "HTTPS is not captured until the CA is trusted")
        #expect(caOnly.bannerAction == .trustCA)
        #expect(caOnly.anyOpen == true)
        #expect(routes(systemProxy: both("127.0.0.1", 8080), hosts: 2, flows: 3, caTrust: trustedUser).banner == nil)
        let trustedTunnels = routes(systemProxy: .off, hosts: 0, flows: 3, tunnelled: 3, caTrust: trustedUser)
        #expect(trustedTunnels.banner == "Nothing is decrypted until a host is in Scope.")
        #expect(trustedTunnels.bannerAction == .addScopeHost)
    }

    /// TR-AC16: a trusted CA is an open entry — PR D's line, `HTTPS on both routes`, no stored action, a done step.
    @Test func caTrusted() throws {
        let trustedUser = try caFacts(scope: "user")
        #expect(trustedUser.trusted == true && trustedUser.scope == "user" && trustedUser.platform == "macos")
        let s = make(bus: .connected("x"), role: "operator", capability: .capturing, systemProxy: .off, caTrust: trustedUser)
        #expect(s.routes.caTrust?.line == "CA trusted (user keychain)")
        #expect(s.routes.caTrust?.open == true)
        #expect(s.routes.caTrust?.detail == "HTTPS on both routes")
        #expect(s.routes.caTrust?.actions == [])
        #expect(trustedUser.actions == [.openCAPanel], "PR D offers the panel on a trusted fact; an open entry stores no remedy")
        #expect(!s.routes.advice.contains { $0.kind == .caTrust })
        #expect(s.routes.advice.map(\.kind) == [.systemProxy, .scope])
        let step = try #require(s.steps.first { $0.kind == .caTrusted })
        #expect(step.title == "CA trusted (user keychain)")
        #expect(step.done == true)
        #expect(step.action == nil)
        #expect(step.detail == "HTTPS on both routes")
        let system = make(bus: .connected("x"), role: "operator", capability: .capturing, caTrust: try caFacts(scope: "system"))
        #expect(system.routes.caTrust?.line == "CA trusted (System keychain)")
        #expect(system.steps.first { $0.kind == .caTrusted }?.title == "CA trusted (System keychain)")
        let done = make(core: core(.ready), bus: .connected("x"), role: "operator", capability: .capturing, hosts: 2, flows: 1,
                        systemProxy: both("127.0.0.1", 8080), caTrust: trustedUser)
        #expect(done.allStepsDone == true)
        #expect(done.steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .caTrusted, .firstFlow])
    }

    /// TR-AC16: an unread or unknown CA (nil) says nothing — no entry, no step, no CA words in the advice or the banner.
    @Test func caUnknownSaysNothing() {
        let s = make(bus: .connected("x"), role: "operator", capability: .inactive, hosts: 0, flows: 3, systemProxy: .off, caTrust: nil)
        #expect(s.routes.caTrust == nil)
        #expect(!s.steps.contains { $0.kind == .caTrusted })
        #expect(s.steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .firstFlow])
        #expect(s.routes.advice.map(\.kind) == [.systemProxy, .allApps, .scope])
        #expect(s.routes.banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope.")
        for text in s.routes.advice.map(\.line) + [s.routes.banner ?? ""] {
            #expect(!text.contains("CA") && !text.contains("HTTPS"), "\(text)")
        }
        // The default: every existing call site passes no CA fact.
        #expect(make(bus: .connected("x"), role: "operator", capability: .capturing, flows: 3).routes.caTrust == nil)
    }

    /// TR-AC16: PR D's session flags — `installing` outranks everything (nothing to press), `needsAdmin` offers the panel.
    @Test func caSiblingStates() throws {
        let installing = make(bus: .connected("x"), role: "operator", capability: .capturing, systemProxy: .off,
                              caTrust: try caFacts(installing: true))
        #expect(installing.routes.caTrust?.line == "trusting CA…")
        #expect(installing.routes.caTrust?.open == false)
        #expect(installing.routes.caTrust?.actions == [])
        #expect(installing.routes.caTrust?.detail == caNotTrustedDetail)
        let installingStep = try #require(installing.steps.first { $0.kind == .caTrusted })
        #expect(installingStep.title == "trusting CA…")
        #expect(installingStep.done == false)
        #expect(installingStep.action == nil)
        // An uninstall in flight: a trusted store, `installing` set — PR D's `text` and `step.done` say in flight, not done.
        let untrusting = make(bus: .connected("x"), role: "operator", capability: .capturing, caTrust: try caFacts(scope: "user", installing: true))
        #expect(untrusting.routes.caTrust?.line == "trusting CA…")
        #expect(untrusting.routes.caTrust?.open == false)
        #expect(untrusting.steps.first { $0.kind == .caTrusted }?.done == false)

        let admin = make(bus: .connected("x"), role: "operator", capability: .capturing, systemProxy: .off,
                         caTrust: try caFacts(needsAdmin: true))
        #expect(admin.routes.caTrust?.line == "CA trust needs an administrator")
        #expect(admin.routes.caTrust?.open == false)
        #expect(admin.routes.caTrust?.actions == [.openCAPanel])
        #expect(admin.routes.caTrust?.detail == caNotTrustedDetail)
        let adminStep = try #require(admin.steps.first { $0.kind == .caTrusted })
        #expect(adminStep.title == "CA trust needs an administrator")
        #expect(adminStep.done == false)
        #expect(adminStep.action == .openCAPanel)

        let adminBanner = make(bus: .connected("x"), role: "operator", capability: .capturing, hosts: 2, flows: 3,
                               systemProxy: both("127.0.0.1", 8080), caTrust: try caFacts(needsAdmin: true)).routes
        #expect(adminBanner.banner == "CA trust needs an administrator")
        #expect(adminBanner.bannerAction == .openCAPanel)
        let installingBanner = make(bus: .connected("x"), role: "operator", capability: .capturing, hosts: 2, flows: 3,
                                    systemProxy: both("127.0.0.1", 8080), caTrust: try caFacts(installing: true)).routes
        #expect(installingBanner.banner == "trusting CA…")
        #expect(installingBanner.bannerAction == nil)
    }

    /// TR-AC18, CA cases: the CA state is its whole line; it joins the composed banner last; a single-fact banner is that state.
    @Test func composedBannerWithCA() throws {
        let notTrusted = try caFacts()
        func routes(_ capability: CaptureCapability, supported: Bool = true, systemProxy: SystemProxyState? = .off,
                    hosts: Int = 0, flows: Int = 0, tunnelled: Int = 0, caTrust: CATrustFacts? = nil) -> TrafficRoutes {
            make(bus: .connected("x"), role: "operator", capability: capability, supported: supported,
                 hosts: hosts, flows: flows, systemProxy: systemProxy, caTrust: caTrust, tunnelled: tunnelled).routes
        }
        let ca = routes(.capturing, caTrust: notTrusted).caTrust
        #expect(ca?.state == ca?.line)
        #expect(ca?.state == "HTTPS is not captured until the CA is trusted")
        let freshWithPR4 = routes(.inactive, hosts: 0, flows: 3, caTrust: notTrusted)
        #expect(freshWithPR4.banner
                == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted")
        #expect(freshWithPR4.bannerAction == .openCaptureSettings)
        let freshUntilPR4 = routes(.inactive, systemProxy: nil, hosts: 0, flows: 3, caTrust: notTrusted)
        #expect(freshUntilPR4.banner
                == "All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted")
        #expect(freshUntilPR4.bannerAction == .openCaptureSettings)
        let readable = routes(.capturing, hosts: 0, flows: 3, caTrust: notTrusted)
        #expect(readable.banner == "HTTPS is not captured until the CA is trusted")
        #expect(readable.bannerAction == .trustCA)
        let tunnels = routes(.capturing, hosts: 0, flows: 3, tunnelled: 3, caTrust: notTrusted)
        #expect(tunnels.banner == "Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted")
        #expect(tunnels.bannerAction == .addScopeHost)
        // Single-fact banners equal that fact's state, never a line with its remedy clause.
        let noExtension = routes(.capturing, supported: false, hosts: 2, flows: 3)
        #expect(noExtension.banner == noExtension.systemProxy?.state)
        #expect(noExtension.banner == "system proxy off")
        #expect(noExtension.bannerAction == nil)
        let caOnly = routes(.capturing, systemProxy: both("127.0.0.1", 8080), hosts: 2, flows: 3, caTrust: notTrusted)
        #expect(caOnly.banner == caOnly.caTrust?.state)
        #expect(caOnly.bannerAction == .trustCA)
        let none = routes(.capturing, systemProxy: both("127.0.0.1", 8080), hosts: 2, flows: 3, caTrust: try caFacts(scope: "user"))
        #expect(none.banner == nil)
        #expect(none.bannerAction == nil)
    }

    // MARK: Fix task (tester's whole-branch report)

    /// A core that serialises `advice: ""` while nothing is decrypted: the decoded status reads as absent, so the
    /// Scope line is the Kit's own sentence and the all-tunnels banner is that sentence — never an empty row or a
    /// blank banner with an Add Host… button.
    @Test func anEmptyCoreAdviceFallsBackToTheKitSentenceNeverAnEmptyLine() throws {
        let decoded = try #require(DecryptStatus(json: ["scope_hosts": 0, "decrypting": false, "advice": ""]))
        #expect(decoded == DecryptStatus(scopeHosts: 0, decrypting: false, advice: nil))
        func routes(flows: Int, tunnelled: Int, decrypt: DecryptStatus) -> TrafficRoutes {
            make(bus: .connected("127.0.0.1:60745"), role: "operator", capability: .capturing, hosts: 0, flows: flows,
                 systemProxy: both("127.0.0.1", 8080), tunnelled: tunnelled, decrypt: decrypt).routes
        }
        for status in [decoded, DecryptStatus(scopeHosts: 0, decrypting: false, advice: nil)] {
            let empty = routes(flows: 0, tunnelled: 0, decrypt: status)
            #expect(empty.scope.open == false)
            #expect(empty.scope.line == "Nothing is decrypted until a host is in Scope.")
            #expect(empty.scope.state == "Nothing is decrypted until a host is in Scope.")
            #expect(empty.advice.map(\.line) == ["Nothing is decrypted until a host is in Scope."])
            #expect(empty.banner == nil)
            let tunnels = routes(flows: 4, tunnelled: 4, decrypt: status)
            #expect(tunnels.banner == "Nothing is decrypted until a host is in Scope.")
            #expect(tunnels.banner?.isEmpty == false)
            #expect(tunnels.bannerAction == .addScopeHost)
            #expect(tunnels.shown.map(\.kind) == [.scope])
        }
    }

    /// The entries the banner names are the Kit's `shown` (D5's predicate, banner order), and the tooltip detail
    /// is their `detail`s joined " · ". The RouteBanner view reads these; nothing re-derives them from the text.
    @Test func shownEntriesAndBannerDetail() throws {
        let notTrusted = try caFacts()
        func routes(_ capability: CaptureCapability, systemProxy: SystemProxyState? = .off, hosts: Int = 0, flows: Int = 0,
                    tunnelled: Int = 0, caTrust: CATrustFacts? = nil) -> TrafficRoutes {
            make(bus: .connected("x"), role: "operator", capability: capability, hosts: hosts, flows: flows,
                 systemProxy: systemProxy, caTrust: caTrust, tunnelled: tunnelled).routes
        }
        // Fresh install (system proxy unknown until PR4): All Apps off · Scope · CA not trusted.
        let fresh = routes(.inactive, systemProxy: nil, hosts: 0, flows: 3, caTrust: notTrusted)
        #expect(fresh.shown.map(\.kind) == [.allApps, .scope, .caTrust])
        #expect(fresh.banner == "All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted")
        #expect(fresh.bannerDetail == "in-scope hosts of every app"
                + " · Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel"
                + " · HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then")
        #expect(fresh.bannerAction == .openCaptureSettings)
        expectOneDerivation(fresh, "fresh")
        // Every row a tunnel with both routes open: the Scope fact alone.
        let tunnels = routes(.capturing, systemProxy: both("127.0.0.1", 8080), hosts: 0, flows: 3, tunnelled: 3)
        #expect(tunnels.shown.map(\.kind) == [.scope])
        #expect(tunnels.bannerDetail
                == "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel")
        expectOneDerivation(tunnels, "tunnels")
        // Routes open, Scope set, CA not trusted: the CA fact alone.
        let caOnly = routes(.capturing, systemProxy: both("127.0.0.1", 8080), hosts: 2, flows: 3, caTrust: notTrusted)
        #expect(caOnly.shown.map(\.kind) == [.caTrust])
        #expect(caOnly.bannerDetail == "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then")
        #expect(caOnly.bannerAction == .trustCA)
        expectOneDerivation(caOnly, "caOnly")
        // No banner: nothing shown, no detail.
        let none = routes(.capturing, systemProxy: both("127.0.0.1", 8080), hosts: 2, flows: 3)
        #expect(none.banner == nil)
        #expect(none.shown == [])
        #expect(none.bannerDetail == nil)
        expectOneDerivation(none, "none")
        // No rows: the same closed facts are the empty state's advice, not shown.
        let noRows = routes(.inactive, systemProxy: nil, hosts: 0, flows: 0, caTrust: notTrusted)
        #expect(noRows.advice.map(\.kind) == [.allApps, .scope, .caTrust])
        #expect(noRows.shown == [])
        #expect(noRows.bannerDetail == nil)
        // The shown entries are the routes' own values, not copies with other words.
        #expect(fresh.shown == [fresh.allApps, fresh.scope, fresh.caTrust].compactMap { $0 })
    }

    // MARK: System proxy — the verb facts (spec 2026-10-31-system-proxy-automation-design §D12, §D13; plan Tasks 24 + 30)

    /// `make` with the verb facts beside the CFNetwork read: the core ready, the bus connected as operator.
    private func withFacts(_ facts: SystemProxyFacts?, systemProxy: SystemProxyState? = nil, capability: CaptureCapability = .capturing,
                           extensionSupported: Bool = true, hosts: Int = 2, flows: Int = 0,
                           listening: String = "127.0.0.1:8080") -> ConnectionSummary {
        ConnectionSummary.make(core: core(.ready, proxy: listening), activeKind: .embedded, bus: .connected("x"), role: "operator",
                               roleWarning: false, capability: capability, captureSupported: extensionSupported, scopeHostCount: hosts,
                               flowCount: flows, listenAddress: listening, systemProxy: systemProxy, systemProxyFacts: facts)
    }

    /// The verb facts for one word. `state` is what `SystemProxyFacts(compact:listenAddress:)` derives: both protocols at
    /// our address for `points_at_us`, both at the other endpoint for `other`, `.off` for `off`, nil for the rest.
    private func facts(_ word: SystemProxyFacts.Word, state: SystemProxyState? = nil, managed: Bool? = nil, setting: Bool = false,
                       supported: Bool = true, remedy: String? = nil) -> SystemProxyFacts {
        SystemProxyFacts(word: word, state: state, managedByUs: managed, setting: setting, supported: supported, detail: "", remedy: remedy)
    }

    private let otherRemedy = "Another app owns the system proxy. Set as System Proxy records its setting and restores it on quit."
    private let offRemedy = "Set as System Proxy so Safari and other proxy-aware apps use the core."
    private let todaysRemedy = "set 127.0.0.1:8080 as the system proxy, or point a client at it"
    private let adminSentence = "macOS asks for an administrator to change network settings on this Mac."

    /// SP-AC23, §D12's rows as the route table: words, remedy and actions per (state, managed_by_us, setting).
    @Test func systemProxyRouteWordTableWithTheVerbFacts() {
        let managed = withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: true)).routes.systemProxy
        #expect(managed?.open == true)
        #expect(managed?.state == "system proxy on · 127.0.0.1:8080")
        #expect(managed?.remedy == nil)
        #expect(managed?.line == "system proxy on · 127.0.0.1:8080")
        #expect(managed?.actions == [.unsetSystemProxy])

        let outside = withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: false)).routes.systemProxy
        #expect(outside?.open == true)
        #expect(outside?.state == "system proxy on · 127.0.0.1:8080 · set outside the app")
        #expect(outside?.line == "system proxy on · 127.0.0.1:8080 · set outside the app")
        #expect(outside?.actions == [])

        // Task 30's third shape: managed_by_us unknown (nil) — no suffix, no Restore button.
        let unknownManaged = withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: nil)).routes.systemProxy
        #expect(unknownManaged?.state == "system proxy on · 127.0.0.1:8080")
        #expect(unknownManaged?.actions == [])

        let other = withFacts(facts(.other, state: both("127.0.0.1", 9090), managed: false)).routes.systemProxy
        #expect(other?.open == false)
        #expect(other?.state == "system proxy on · 127.0.0.1:9090, not this core")
        #expect(other?.remedy == otherRemedy)
        #expect(other?.line == "system proxy on · 127.0.0.1:9090, not this core — Another app owns the system proxy."
                + " Set as System Proxy records its setting and restores it on quit.")
        #expect(other?.actions == [.setSystemProxy])

        let otherUnsupported = withFacts(facts(.other, state: both("10.0.0.5", 3128), managed: false, supported: false)).routes.systemProxy
        #expect(otherUnsupported?.state == "system proxy on · 10.0.0.5:3128, not this core")
        #expect(otherUnsupported?.remedy == todaysRemedy)
        #expect(otherUnsupported?.actions == [])

        let off = withFacts(facts(.off, state: .off, managed: false)).routes.systemProxy
        #expect(off?.open == false)
        #expect(off?.state == "system proxy off")
        #expect(off?.remedy == offRemedy)
        #expect(off?.line == "system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core.")
        #expect(off?.actions == [.setSystemProxy])

        let offUnsupported = withFacts(facts(.off, state: .off, managed: false, supported: false)).routes.systemProxy
        #expect(offUnsupported?.state == "system proxy off")
        #expect(offUnsupported?.remedy == todaysRemedy)
        #expect(offUnsupported?.line == "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(offUnsupported?.actions == [])

        let admin = withFacts(facts(.needsPrivilege, remedy: adminSentence)).routes.systemProxy
        #expect(admin?.open == false)
        #expect(admin?.state == "system proxy needs an administrator")
        #expect(admin?.remedy == adminSentence)
        #expect(admin?.line == "system proxy needs an administrator — macOS asks for an administrator to change network settings on this Mac.")
        #expect(admin?.actions == [])
        let adminNoRemedy = withFacts(facts(.needsPrivilege)).routes.systemProxy
        #expect(adminNoRemedy?.remedy == nil)
        #expect(adminNoRemedy?.line == "system proxy needs an administrator")
        #expect(adminNoRemedy?.actions == [])

        let setting = withFacts(facts(.off, state: .off, setting: true)).routes.systemProxy
        #expect(setting?.open == false)
        #expect(setting?.state == "setting system proxy…")
        #expect(setting?.remedy == nil)
        #expect(setting?.line == "setting system proxy…")
        #expect(setting?.actions == [])
        // `setting` outranks every word, a restore in flight and an administrator wait included.
        #expect(withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: true, setting: true)).routes.systemProxy?.line
                == "setting system proxy…")
        #expect(withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: true, setting: true)).routes.systemProxy?.open == false)
        #expect(withFacts(facts(.needsPrivilege, setting: true, remedy: adminSentence)).routes.systemProxy?.line == "setting system proxy…")
        #expect(withFacts(facts(.other, state: both("127.0.0.1", 9090), setting: true)).routes.systemProxy?.actions == [])

        // Never named: unsupported, unknown, and an `other` at our own endpoint (no state).
        #expect(withFacts(facts(.unsupported, supported: false)).routes.systemProxy == nil)
        #expect(!withFacts(facts(.unsupported, supported: false)).steps.map(\.kind).contains(.systemProxy))
        #expect(withFacts(facts(.unknown)).routes.systemProxy == nil)
        #expect(withFacts(facts(.other, state: nil, managed: false)).routes.systemProxy == nil)
        #expect(withFacts(facts(.pointsAtUs, state: nil, managed: true)).routes.systemProxy == nil)

        for route in [managed, outside, other, off, admin, setting] {
            #expect(route?.kind == .systemProxy)
            #expect(route?.detail == "every proxy-aware app, regardless of Scope")
        }
    }

    /// D1 (Task 30): the verb's answer wins over the CFNetwork read whenever the facts are present — even when it
    /// says nothing (unknown), the read does not fill in.
    @Test func theVerbFactsWinOverTheCFNetworkRead() {
        let off = withFacts(facts(.off, state: .off), systemProxy: both("127.0.0.1", 8080))
        #expect(off.routes.systemProxy?.state == "system proxy off")
        #expect(off.routes.systemProxy?.open == false)
        #expect(off.routes.systemProxy?.actions == [.setSystemProxy])
        #expect(step(off, .systemProxy)?.done == false)
        let atUs = withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: true), systemProxy: .off)
        #expect(atUs.routes.systemProxy?.state == "system proxy on · 127.0.0.1:8080")
        #expect(atUs.routes.systemProxy?.open == true)
        #expect(step(atUs, .systemProxy)?.done == true)
        let other = withFacts(facts(.other, state: both("127.0.0.1", 9090), managed: false), systemProxy: both("127.0.0.1", 8080))
        #expect(other.routes.systemProxy?.state == "system proxy on · 127.0.0.1:9090, not this core")
        #expect(withFacts(facts(.unknown), systemProxy: .off).routes.systemProxy == nil)
        #expect(withFacts(facts(.unsupported, supported: false), systemProxy: both("127.0.0.1", 8080)).routes.systemProxy == nil)
        // With no facts the read is the source, as before.
        #expect(withFacts(nil, systemProxy: both("127.0.0.1", 8080)).routes.systemProxy?.state == "system proxy on · 127.0.0.1:8080")
    }

    /// The `.systemProxy` Getting-started row carries the route's first action while closed, nothing when open.
    @Test func systemProxyStepCarriesTheRouteAction() {
        let off = withFacts(facts(.off, state: .off))
        #expect(step(off, .systemProxy)?.title == "system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core.")
        #expect(step(off, .systemProxy)?.done == false)
        #expect(step(off, .systemProxy)?.action == .setSystemProxy)
        #expect(step(off, .systemProxy)?.detail == "every proxy-aware app, regardless of Scope")
        let other = withFacts(facts(.other, state: both("127.0.0.1", 9090), managed: false))
        #expect(step(other, .systemProxy)?.title == "system proxy on · 127.0.0.1:9090, not this core — Another app owns the system proxy."
                + " Set as System Proxy records its setting and restores it on quit.")
        #expect(step(other, .systemProxy)?.action == .setSystemProxy)
        let managed = withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: true))
        #expect(step(managed, .systemProxy)?.title == "system proxy on · 127.0.0.1:8080")
        #expect(step(managed, .systemProxy)?.done == true)
        #expect(step(managed, .systemProxy)?.action == nil, "a done row offers no Restore button; the card does")
        let outside = withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: false))
        #expect(step(outside, .systemProxy)?.title == "system proxy on · 127.0.0.1:8080 · set outside the app")
        #expect(step(outside, .systemProxy)?.done == true)
        let admin = withFacts(facts(.needsPrivilege, remedy: adminSentence))
        #expect(step(admin, .systemProxy)?.title == "system proxy needs an administrator — macOS asks for an administrator to change network settings on this Mac.")
        #expect(step(admin, .systemProxy)?.done == false)
        #expect(step(admin, .systemProxy)?.action == nil)
        let setting = withFacts(facts(.off, state: .off, setting: true))
        #expect(step(setting, .systemProxy)?.title == "setting system proxy…")
        #expect(step(setting, .systemProxy)?.action == nil)
        let offUnsupported = withFacts(facts(.off, state: .off, supported: false))
        #expect(step(offUnsupported, .systemProxy)?.title == "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(step(offUnsupported, .systemProxy)?.action == nil)
        #expect(off.steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .firstFlow])
    }

    /// §D13 "Getting started": the `.firstFlow` row's undone title follows the system-proxy route.
    @Test func firstFlowStepFollowsTheSystemProxy() {
        let off = withFacts(facts(.off, state: .off), flows: 0)
        #expect(step(off, .firstFlow)?.title == "Set aitmproxy as the system proxy, or open the browser")
        #expect(step(off, .firstFlow)?.action == .setSystemProxy)
        #expect(step(off, .firstFlow)?.done == false)
        #expect(step(off, .firstFlow)?.detail == nil)
        let other = withFacts(facts(.other, state: both("127.0.0.1", 9090), managed: false), flows: 0)
        #expect(step(other, .firstFlow)?.title == "Set aitmproxy as the system proxy, or open the browser")
        #expect(step(other, .firstFlow)?.action == .setSystemProxy)

        let atUs = withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: true), flows: 0)
        #expect(step(atUs, .firstFlow)?.title == "System proxy points at 127.0.0.1:8080 — waiting for the first flow")
        #expect(step(atUs, .firstFlow)?.action == .openBrowser)
        #expect(step(atUs, .firstFlow)?.done == false)
        let outside = withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: false), flows: 0)
        #expect(step(outside, .firstFlow)?.title == "System proxy points at 127.0.0.1:8080 — waiting for the first flow")
        // The CFNetwork read alone, pointing at us, reads the same: the row follows the route, not the source.
        let readAtUs = withFacts(nil, systemProxy: both("127.0.0.1", 8080), flows: 0)
        #expect(step(readAtUs, .firstFlow)?.title == "System proxy points at 127.0.0.1:8080 — waiting for the first flow")
        #expect(step(readAtUs, .firstFlow)?.action == .openBrowser)

        for summary in [
            withFacts(facts(.unsupported, supported: false), flows: 0),
            withFacts(facts(.unknown), flows: 0),
            withFacts(facts(.off, state: .off, supported: false), flows: 0),
            withFacts(facts(.needsPrivilege, remedy: adminSentence), flows: 0),
            withFacts(facts(.off, state: .off, setting: true), flows: 0),
            withFacts(nil, flows: 0),
            withFacts(nil, systemProxy: .off, flows: 0),
        ] {
            #expect(step(summary, .firstFlow)?.title == "Point a client at 127.0.0.1:8080, or open the browser")
            #expect(step(summary, .firstFlow)?.action == .openBrowser)
        }
        // With rows the step is the count, whatever the route.
        let flows = withFacts(facts(.off, state: .off), flows: 3)
        #expect(step(flows, .firstFlow)?.title == "3 flows captured")
        #expect(step(flows, .firstFlow)?.done == true)
        #expect(step(flows, .firstFlow)?.action == nil)
    }

    /// D5's banner button through the filled actions: the system proxy leads, so Set as System Proxy is the button.
    @Test func bannerActionIsSetAsSystemProxyWhenTheProxyIsOff() {
        let off = withFacts(facts(.off, state: .off), capability: .inactive, hosts: 2, flows: 3).routes
        #expect(off.banner == "system proxy off · All Apps off")
        #expect(off.bannerAction == .setSystemProxy)
        #expect(off.advice.map(\.kind) == [.systemProxy, .allApps])
        expectOneDerivation(off, "off")
        let other = withFacts(facts(.other, state: both("127.0.0.1", 9090), managed: false), capability: .inactive, hosts: 2, flows: 3).routes
        #expect(other.banner == "system proxy on · 127.0.0.1:9090, not this core · All Apps off")
        #expect(other.bannerAction == .setSystemProxy)
        expectOneDerivation(other, "other")
        // No extension in this build: the system proxy alone, its button.
        let alone = withFacts(facts(.off, state: .off), extensionSupported: false, hosts: 2, flows: 3).routes
        #expect(alone.banner == "system proxy off")
        #expect(alone.bannerAction == .setSystemProxy)
        // Unsupported here: the system-proxy entry has no button, so All Apps' is the banner's.
        let unsupported = withFacts(facts(.off, state: .off, supported: false), capability: .inactive, hosts: 2, flows: 3).routes
        #expect(unsupported.banner == "system proxy off · All Apps off")
        #expect(unsupported.bannerAction == .openCaptureSettings)
        // A restore wait has no button either.
        #expect(withFacts(facts(.needsPrivilege, remedy: adminSentence), capability: .inactive, hosts: 2, flows: 3).routes.bannerAction
                == .openCaptureSettings)
        #expect(withFacts(facts(.needsPrivilege, remedy: adminSentence), capability: .inactive, hosts: 2, flows: 3).routes.banner
                == "system proxy needs an administrator · All Apps off")
        // No rows: no banner, but the empty state's first line carries the same button.
        let fresh = withFacts(facts(.off, state: .off), capability: .inactive, hosts: 2, flows: 0).routes
        #expect(fresh.banner == nil)
        #expect(fresh.bannerAction == nil)
        #expect(fresh.advice.first?.actions == [.setSystemProxy])
        // An open system proxy, managed: nothing shown, no button, whatever its own actions.
        let managed = withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: true), capability: .inactive, hosts: 2, flows: 3).routes
        #expect(managed.banner == nil)
        #expect(managed.bannerAction == nil)
        #expect(managed.systemProxy?.actions == [.unsetSystemProxy])
    }

    /// With no verb facts the CFNetwork read renders exactly as before this task: today's words, no actions.
    @Test func withoutFactsNothingChanges() {
        let off = withFacts(nil, systemProxy: .off, capability: .inactive, hosts: 2, flows: 3)
        #expect(off.routes.systemProxy?.open == false)
        #expect(off.routes.systemProxy?.state == "system proxy off")
        #expect(off.routes.systemProxy?.remedy == "set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(off.routes.systemProxy?.actions == [])
        #expect(off.routes.banner == "system proxy off · All Apps off")
        #expect(off.routes.bannerAction == .openCaptureSettings)
        #expect(step(off, .systemProxy)?.title == "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(step(off, .systemProxy)?.action == nil)
        let other = withFacts(nil, systemProxy: both("127.0.0.1", 9090))
        #expect(other.routes.systemProxy?.state == "system proxy on · 127.0.0.1:9090, not this core")
        #expect(other.routes.systemProxy?.remedy == "set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(other.routes.systemProxy?.actions == [])
        #expect(step(other, .systemProxy)?.action == nil)
        let ours = withFacts(nil, systemProxy: both("127.0.0.1", 8080))
        #expect(ours.routes.systemProxy?.open == true)
        #expect(ours.routes.systemProxy?.state == "system proxy on · 127.0.0.1:8080")
        #expect(ours.routes.systemProxy?.actions == [])
        let httpOnly = withFacts(nil, systemProxy: SystemProxyState(http: SystemProxyState.Endpoint(host: "127.0.0.1", port: 8080), https: nil))
        #expect(httpOnly.routes.systemProxy?.state == "system proxy on · 127.0.0.1:8080 · HTTP only")
        let none = withFacts(nil)
        #expect(none.routes.systemProxy == nil)
        #expect(none.steps.map(\.kind) == [.coreRunning, .busConnected, .extensionOn, .scopeSet, .firstFlow])
        #expect(step(none, .firstFlow)?.title == "Point a client at 127.0.0.1:8080, or open the browser")
    }

    /// §D12's button titles and the two sentences the Settings and sheet views print verbatim.
    @Test func systemProxyButtonTitlesAndCopy() {
        #expect(ConnectionAction.setSystemProxy.title == "Set as System Proxy")
        #expect(ConnectionAction.unsetSystemProxy.title == "Restore System Proxy")
        #expect(ConnectionAction.setSystemProxy.isDestructive == false)
        #expect(ConnectionAction.unsetSystemProxy.isDestructive == false)
        #expect(ConnectionSummary.systemProxyLaneSentence
                == "System proxy → every proxy-aware app, regardless of Scope. All Apps → in-scope hosts of every app.")
        #expect(ConnectionSummary.bypassFieldCopy
                == "Hosts that skip the system proxy. Add the hosts your own tools talk to (today's incident: a tool whose API calls were routed to another proxy).")
    }

    // MARK: System proxy — edges a bus client must survive (tester, stage 5)

    private let systemProxyDetail = "every proxy-aware app, regardless of Scope"
    private let plainPointer = "Point a client at 127.0.0.1:8080, or open the browser"

    /// (Matt, PR 4 re-base) The route model is not a lane: the three lanes, `overall`, `worst`, `tooltip` and
    /// `spoken` never take the system-proxy facts' state, whatever the word — the toolbar pill shows lanes only.
    @Test func theLanesAndOverallIgnoreTheSystemProxyFacts() {
        let none = withFacts(nil)
        #expect(none.overall == .ok)
        #expect(none.lanes.map(\.kind) == [.core, .bus, .capture])
        #expect(none.tooltip == "Core: running — Embedded · proxy 127.0.0.1:8080\nBus: connected — operator · x\n"
                + "All Apps: all apps on · 2 hosts in scope — extension on · 2 hosts in scope")
        let verbs = [
            facts(.other, state: both("127.0.0.1", 9090), managed: false),
            facts(.off, state: .off),
            facts(.needsPrivilege, remedy: adminSentence),
            facts(.off, state: .off, setting: true),
            facts(.unsupported, supported: false),
            facts(.unknown),
            facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: true),
            facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: false),
        ]
        for verb in verbs {
            let summary = withFacts(verb)
            #expect(summary.overall == .ok, "\(verb.word)")
            #expect(summary.lanes == none.lanes, "\(verb.word)")
            #expect(summary.worst == none.worst, "\(verb.word)")
            #expect(summary.tooltip == none.tooltip, "\(verb.word)")
            #expect(summary.spoken == none.spoken, "\(verb.word)")
        }
    }

    /// `setting` outranks every word, the two that carry no endpoint included: while a change is in flight the route
    /// is named "setting system proxy…" even on an `unsupported`/`unknown` wire (a contradictory but transient
    /// object), with nothing to press, and the first-flow row falls back to the plain pointer.
    @Test func settingIsNamedForEveryWordIncludingUnsupportedAndUnknown() {
        let words: [SystemProxyFacts.Word] = [.pointsAtUs, .other, .off, .unsupported, .needsPrivilege, .unknown]
        for word in words {
            let state: SystemProxyState? = word == .off ? .off : (word == .pointsAtUs ? both("127.0.0.1", 8080) : nil)
            let verb = facts(word, state: state, managed: word == .pointsAtUs, setting: true, supported: word != .unsupported,
                             remedy: word == .needsPrivilege ? adminSentence : nil)
            let summary = withFacts(verb)
            #expect(summary.routes.systemProxy == TrafficRoute(kind: .systemProxy, open: false, state: "setting system proxy…",
                                                               detail: systemProxyDetail, actions: []), "\(word)")
            #expect(step(summary, .systemProxy) == GettingStartedStep(kind: .systemProxy, title: "setting system proxy…", done: false,
                                                                      action: nil, detail: systemProxyDetail), "\(word)")
            #expect(step(summary, .firstFlow)?.title == plainPointer, "\(word)")
            #expect(step(summary, .firstFlow)?.action == .openBrowser, "\(word)")
            // Closed and shown: the empty state lists it first; with rows the banner names it, button-less.
            let rows = withFacts(verb, capability: .inactive, hosts: 2, flows: 3).routes
            #expect(rows.banner == "setting system proxy… · All Apps off", "\(word)")
            #expect(rows.bannerAction == .openCaptureSettings, "\(word)")
            #expect(rows.advice.first == summary.routes.systemProxy, "\(word)")
        }
    }

    /// A contradictory `managed_by_us: true` beside `off` or `other`: the word is the core's verdict, so the route
    /// is closed with Set as System Proxy — the flag is read only when the proxy points at us (Restore).
    @Test func managedByUsIsReadOnlyWhenTheProxyPointsAtUs() {
        #expect(withFacts(facts(.off, state: .off, managed: true)).routes.systemProxy
                == TrafficRoute(kind: .systemProxy, open: false, state: "system proxy off", remedy: offRemedy,
                                detail: systemProxyDetail, actions: [.setSystemProxy]))
        #expect(withFacts(facts(.other, state: both("127.0.0.1", 9090), managed: true)).routes.systemProxy
                == TrafficRoute(kind: .systemProxy, open: false, state: "system proxy on · 127.0.0.1:9090, not this core",
                                remedy: otherRemedy, detail: systemProxyDetail, actions: [.setSystemProxy]))
        #expect(withFacts(facts(.needsPrivilege, managed: true, remedy: adminSentence)).routes.systemProxy
                == TrafficRoute(kind: .systemProxy, open: false, state: "system proxy needs an administrator", remedy: adminSentence,
                                detail: systemProxyDetail, actions: []))
        #expect(step(withFacts(facts(.off, state: .off, managed: true)), .firstFlow)?.title
                == "Set aitmproxy as the system proxy, or open the browser")
    }

    /// From the wire to the words: the literal `proxy.status.system_proxy` objects the core serialises, parsed by
    /// `SystemProxyFacts(compact:listenAddress:)` and rendered by `make`, land on §D12's rows verbatim; the
    /// malformed shapes land on no route at all.
    @Test func theWireObjectReachesTheRouteVerbatim() throws {
        let listen = "127.0.0.1:8080"
        func parsed(_ object: JSONValue) throws -> SystemProxyFacts {
            try #require(SystemProxyFacts(compact: object, listenAddress: listen))
        }

        let other = try parsed(["state": "other", "host": "127.0.0.1", "port": 9090, "managed_by_us": false, "setting": false,
                                "supported": true, "detail": "HTTP and HTTPS → 127.0.0.1:9090"])
        #expect(withFacts(other).routes.systemProxy == TrafficRoute(
            kind: .systemProxy, open: false, state: "system proxy on · 127.0.0.1:9090, not this core", remedy: otherRemedy,
            detail: systemProxyDetail, actions: [.setSystemProxy]))

        let managed = try parsed(["state": "points_at_us", "host": nil, "port": nil, "managed_by_us": true, "setting": false,
                                  "supported": true, "detail": "HTTP and HTTPS → 127.0.0.1:8080 (this core)"])
        #expect(withFacts(managed).routes.systemProxy == TrafficRoute(
            kind: .systemProxy, open: true, state: "system proxy on · 127.0.0.1:8080", detail: systemProxyDetail,
            actions: [.unsetSystemProxy]))
        #expect(step(withFacts(managed), .firstFlow)?.title == "System proxy points at 127.0.0.1:8080 — waiting for the first flow")

        let outside = try parsed(["state": "points_at_us", "host": nil, "port": nil, "managed_by_us": false, "setting": false,
                                  "supported": true, "detail": "HTTP and HTTPS → 127.0.0.1:8080 (this core)"])
        #expect(withFacts(outside).routes.systemProxy == TrafficRoute(
            kind: .systemProxy, open: true, state: "system proxy on · 127.0.0.1:8080 · set outside the app",
            detail: systemProxyDetail, actions: []))

        let off = try parsed(["state": "off", "host": nil, "port": nil, "managed_by_us": false, "setting": false,
                              "supported": true, "detail": "HTTP and HTTPS off"])
        #expect(withFacts(off).routes.systemProxy == TrafficRoute(
            kind: .systemProxy, open: false, state: "system proxy off", remedy: offRemedy, detail: systemProxyDetail,
            actions: [.setSystemProxy]))

        // The compact object carries no `remedy`: the administrator row has the state words alone.
        let adminCompact = try parsed(["state": "needs_privilege", "host": nil, "port": nil, "managed_by_us": false,
                                       "setting": false, "supported": true, "detail": "networksetup needs an administrator"])
        #expect(withFacts(adminCompact).routes.systemProxy == TrafficRoute(
            kind: .systemProxy, open: false, state: "system proxy needs an administrator", detail: systemProxyDetail, actions: []))
        // The full object (a set reply, `proxy.system.status`) carries it.
        let adminFull = try parsed(["state": "needs_privilege", "host": nil, "port": nil, "managed_by_us": false, "setting": false,
                                    "supported": true, "detail": "networksetup needs an administrator", "mechanism": "networksetup",
                                    "guidance": nil, "remedy": .string(adminSentence)])
        #expect(withFacts(adminFull).routes.systemProxy?.line
                == "system proxy needs an administrator — macOS asks for an administrator to change network settings on this Mac.")

        // Never named: the unsupported full object, an unknown word, and the malformed shapes.
        let malformed = try [
            parsed(["state": "unsupported", "host": nil, "port": nil, "managed_by_us": false, "setting": false, "supported": false,
                    "detail": "no supported mechanism on this system", "mechanism": "none",
                    "guidance": "export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080", "remedy": nil]),
            parsed(["state": "banana", "supported": true]),
            parsed(["state": "other", "host": "localhost", "port": 8080, "supported": true]),   // our own address, spelled otherwise
            parsed(["state": "other", "host": "[::1]", "port": 8080, "supported": true]),
            parsed(["state": "other", "host": "10.0.0.5", "port": 99_999, "supported": true]), // huge port
            parsed(["state": "other", "host": "10.0.0.5", "port": -1, "supported": true]),     // negative port
            parsed(["state": "other", "host": "", "port": 3128, "supported": true]),           // empty host
            parsed(["state": "other", "supported": true]),                                     // no endpoint at all
        ]
        for verb in malformed {
            let summary = withFacts(verb)
            #expect(summary.routes.systemProxy == nil, "\(verb)")
            #expect(!summary.steps.map(\.kind).contains(.systemProxy), "\(verb)")
            #expect(step(summary, .firstFlow)?.title == plainPointer, "\(verb)")
            #expect(summary.routes.advice == [], "\(verb)")
            #expect(summary.routes.banner == nil, "\(verb)")
        }
        // `points_at_us` against a listen address the app cannot parse: facts, but no route (never "on").
        let unparsable = try #require(SystemProxyFacts(compact: ["state": "points_at_us", "managed_by_us": true, "supported": true],
                                                       listenAddress: "garbage"))
        let summary = withFacts(unparsable, listening: "garbage")
        #expect(summary.routes.systemProxy == nil)
        #expect(!summary.steps.map(\.kind).contains(.systemProxy))
        #expect(step(summary, .firstFlow)?.title == "Point a client at garbage, or open the browser")
    }

    /// IPv6 and wildcard spellings in the route words: a bare v6 literal is bracketed in the state line; a core on
    /// a wildcard listen that the services point at (as loopback) is named by its LISTEN spelling, `0.0.0.0:8080` —
    /// pinned as today's behaviour (the CFNetwork words of #265 do the same); see the stage-5 report.
    @Test func ipv6AndWildcardSpellingsInTheRouteWords() throws {
        #expect(withFacts(facts(.other, state: both("::1", 9090), managed: false)).routes.systemProxy?.state
                == "system proxy on · [::1]:9090, not this core")
        #expect(withFacts(facts(.other, state: both("[fe80::1]", 3128), managed: false)).routes.systemProxy?.state
                == "system proxy on · [fe80::1]:3128, not this core")
        // A v6 loopback core, pointed at via the v6 spelling: open, named by the listen spelling.
        let v6 = try #require(SystemProxyFacts(compact: ["state": "points_at_us", "managed_by_us": true, "supported": true],
                                               listenAddress: "[::1]:8080"))
        let v6Summary = withFacts(v6, listening: "[::1]:8080")
        #expect(v6Summary.routes.systemProxy?.state == "system proxy on · [::1]:8080")
        #expect(v6Summary.routes.systemProxy?.actions == [.unsetSystemProxy])
        #expect(step(v6Summary, .firstFlow)?.title == "System proxy points at [::1]:8080 — waiting for the first flow")
        // A wildcard listen: the parser puts the services at 127.0.0.1:8080, the words name 0.0.0.0:8080.
        let wildcard = try #require(SystemProxyFacts(compact: ["state": "points_at_us", "managed_by_us": true, "supported": true],
                                                     listenAddress: "0.0.0.0:8080"))
        #expect(wildcard.state == both("127.0.0.1", 8080))
        let wildcardSummary = withFacts(wildcard, listening: "0.0.0.0:8080")
        #expect(wildcardSummary.routes.systemProxy?.open == true)
        #expect(wildcardSummary.routes.systemProxy?.state == "system proxy on · 0.0.0.0:8080")
        #expect(step(wildcardSummary, .firstFlow)?.title == "System proxy points at 0.0.0.0:8080 — waiting for the first flow")
        // An `other` at 127.0.0.1:8080 while we listen on the wildcard is our own address: no route.
        let ownViaWildcard = try #require(SystemProxyFacts(compact: ["state": "other", "host": "127.0.0.1", "port": 8080, "supported": true],
                                                           listenAddress: "0.0.0.0:8080"))
        #expect(withFacts(ownViaWildcard, listening: "0.0.0.0:8080").routes.systemProxy == nil)
    }

    /// `allStepsDone`: an open system proxy counts as done; a closed one is the one undone row.
    @Test func allStepsDoneFollowsTheSystemProxyRow() {
        let managed = withFacts(facts(.pointsAtUs, state: both("127.0.0.1", 8080), managed: true), flows: 3)
        #expect(managed.steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .firstFlow])
        #expect(managed.allStepsDone)
        let off = withFacts(facts(.off, state: .off), flows: 3)
        #expect(!off.allStepsDone)
        #expect(off.steps.filter { !$0.done }.map(\.kind) == [.systemProxy])
        // The CFNetwork read alone, at us: done too (the route, not the source).
        #expect(withFacts(nil, systemProxy: both("127.0.0.1", 8080), flows: 3).allStepsDone)
    }
}
