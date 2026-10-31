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
                      hosts: Int = 0, flows: Int = 0, coreCapture: CoreCaptureStatus? = nil) -> ConnectionSummary {
        ConnectionSummary.make(core: core, activeKind: kind, bus: bus, role: role, roleWarning: roleWarning,
                               capability: capability, captureSupported: supported, scopeHostCount: hosts,
                               flowCount: flows, listenAddress: "127.0.0.1:8080", coreCapture: coreCapture)
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
        #expect(off.state == .off && off.word == "capture off" && off.detail == "extension not installed")
        #expect(off.actions == [.turnCaptureOn, .openCaptureSettings])
        let inactive = make(capability: .inactive, hosts: 2).capture
        #expect(inactive.detail == "extension installed · 2 hosts in scope")
        #expect(inactive.actions.contains(.uninstallExtension))
        let waiting = make(capability: .pendingApproval).capture
        #expect(waiting.state == .working && waiting.word == "waiting for approval")
        #expect(waiting.actions.first == .approveInSystemSettings)
        let degraded = make(capability: .degraded("Extension activation failed: code signature invalid")).capture
        #expect(degraded.state == .error && degraded.word == "capture degraded")
        #expect(degraded.remedy == "macOS refused this build's extension; install the signed Aitmproxy app")
        let empty = make(capability: .capturing, hosts: 0).capture
        #expect(empty.state == .warning && empty.word == "on, nothing in scope")
        #expect(empty.actions.first == .openScope)
        let on = make(capability: .capturing, hosts: 3).capture
        #expect(on.state == .ok && on.word == "capture on · 3 hosts in scope")
        #expect(on.detail == "extension on · 3 hosts in scope")
        #expect(make(capability: .approvedAttached, hosts: 1).capture.word == "capture on · 1 host in scope")
    }

    @Test func noCaptureWordSaysCapturingWithAnEmptyScope() {
        for capability in [CaptureCapability.approvedAttached, .capturing, .inactive, .pendingApproval, .extensionNotInstalled] {
            let lane = make(capability: capability, hosts: 0).capture
            #expect(!lane.word.localizedCaseInsensitiveContains("capturing"), "\(capability)")
        }
    }

    @Test func externalCoreCannotCapture() {
        let lane = make(kind: .external, capability: .capturing, hosts: 2).capture
        #expect(lane.state == .off && lane.word == "capture off" && lane.actions == [.switchToEmbedded])
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
            "Core is running", "Bus connected", "Turn on the capture extension",
            "Add a host to Scope (for now as example.com:443)", "Point a client at 127.0.0.1:8080, or open the browser",
        ])
        #expect(fresh.steps[2].action == .turnCaptureOn && fresh.steps[3].action == .openScope && fresh.steps[4].action == .openBrowser)
        let waiting = make(core: core(.ready), bus: .connected("x"), role: "operator", capability: .pendingApproval)
        #expect(waiting.steps[2].title == "Approve the capture extension in System Settings")
        let done = make(core: core(.ready), bus: .connected("x"), role: "operator", capability: .capturing, hosts: 2, flows: 14)
        #expect(done.steps.map(\.done) == [true, true, true, true, true])
        #expect(done.steps[3].title == "Scope has 2 hosts" && done.steps[4].title == "14 flows captured")
        let unsupported = make(core: core(.ready), bus: .connected("x"), role: "operator", supported: false, hosts: 1, flows: 1)
        #expect(unsupported.steps[2].title == "Capture extension is not in this build" && unsupported.steps[2].action == nil)
        #expect(!unsupported.allStepsDone)
        let external = make(kind: .external, bus: .connected("x"), role: "operator")
        #expect(external.steps[0].done, "an external core counts as running once the bus is connected")
        let down = make(core: nil, bus: .disconnected)
        #expect(down.steps[0].title == "Start the core" && down.steps[0].action == .startCore)
        #expect(down.steps[1].title == "Connect to the bus" && down.steps[1].action == .startCore)
    }

    @Test func actionTitlesAreTitleCaseWithEllipsesWhereAViewOpens() {
        #expect(ConnectionAction.openScope.title == "Open Scope…")
        #expect(ConnectionAction.turnCaptureOn.title == "Turn On Capture")
        #expect(ConnectionAction.uninstallExtension.isDestructive)
        #expect(!ConnectionAction.restartCore.isDestructive)
    }

    @Test func remediesFallBackWhenTheReasonIsNotRecognised() {
        let refused = make(bus: .failed("connection refused")).bus
        #expect(refused.remedy == "Reconnect, or check the address in Settings ▸ Bus")
        let degraded = make(capability: .degraded("tunnel setup failed")).capture
        #expect(degraded.remedy == "Turn capture off and on again; if it stays degraded, uninstall and reinstall the extension")
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
        #expect(s.capture.compact == "capture off")
        #expect(s.tooltip == "Core: failed — boom\nBus: connected — operator · 127.0.0.1:1\nCapture: capture off — extension not installed")
        #expect(s.spoken == "core failed, bus connected, capture capture off")
    }
}
