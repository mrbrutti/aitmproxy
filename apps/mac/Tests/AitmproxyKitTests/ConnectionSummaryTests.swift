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
                      systemProxy: SystemProxyState? = nil, tunnelled: Int = 0, decrypt: DecryptStatus? = nil) -> ConnectionSummary {
        ConnectionSummary.make(core: core, activeKind: kind, bus: bus, role: role, roleWarning: roleWarning,
                               capability: capability, captureSupported: supported, scopeHostCount: hosts,
                               flowCount: flows, listenAddress: "127.0.0.1:8080", coreCapture: coreCapture,
                               systemProxy: systemProxy, tunnelledFlowCount: tunnelled, decrypt: decrypt)
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
        #expect(fresh.steps[2].action == .turnCaptureOn && fresh.steps[3].action == .openScope && fresh.steps[4].action == .openBrowser)
        let waiting = make(core: core(.ready), bus: .connected("x"), role: "operator", capability: .pendingApproval)
        #expect(waiting.steps[2].title == "All Apps waiting for approval — approve the extension in System Settings")
        let done = make(core: core(.ready), bus: .connected("x"), role: "operator", capability: .capturing, hosts: 2, flows: 14)
        #expect(done.steps.map(\.done) == [true, true, true, true, true])
        #expect(done.steps[3].title == "Scope: 2 hosts decrypted" && done.steps[4].title == "14 flows captured")
        let unsupported = make(core: core(.ready), bus: .connected("x"), role: "operator", supported: false, hosts: 1, flows: 1)
        #expect(unsupported.steps[2].title == "All Apps capture is not in this build" && unsupported.steps[2].action == nil)
        #expect(!unsupported.allStepsDone)
        let external = make(kind: .external, bus: .connected("x"), role: "operator")
        #expect(external.steps[0].done, "an external core counts as running once the bus is connected")
        let down = make(core: nil, bus: .disconnected)
        #expect(down.steps[0].title == "Start the core" && down.steps[0].action == .startCore)
        #expect(down.steps[1].title == "Connect to the bus" && down.steps[1].action == .startCore)
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
        func row(kind: ActiveCoreKind = .embedded, bus: BusState = .connected("x"), role: String? = "operator", roleWarning: Bool = false,
                 _ capability: CaptureCapability, supported: Bool = true, systemProxy: SystemProxyState? = nil,
                 hosts: Int = 0, flows: Int = 0, tunnelled: Int = 0) -> TrafficRoutes {
            make(kind: kind, bus: bus, role: role, roleWarning: roleWarning, capability: capability, supported: supported,
                 hosts: hosts, flows: flows, systemProxy: systemProxy, tunnelled: tunnelled).routes
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
        #expect(off.steps[2].done == false)
        #expect(off.steps[2].title == "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(off.steps[2].detail == "every proxy-aware app, regardless of Scope")
        #expect(off.steps[2].action == nil)
        let other = steps(systemProxy: both("127.0.0.1", 9090))
        #expect(other.steps[2].title
                == "system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it")
        #expect(other.steps[2].done == false)
        let ours = steps(core: core(.ready), .capturing, systemProxy: both("127.0.0.1", 8080), hosts: 2, flows: 1)
        #expect(ours.steps[2].title == "system proxy on · 127.0.0.1:8080")
        #expect(ours.steps[2].done == true)
        #expect(ours.steps[2].action == nil)
        #expect(ours.allStepsDone == true)

        func step(_ summary: ConnectionSummary, _ kind: GettingStartedStep.Kind) -> GettingStartedStep? {
            summary.steps.first { $0.kind == kind }
        }
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

    /// TR-AC6: the Scope entry's remedy button, and the one action list (no PR4 or denied cases).
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
}
