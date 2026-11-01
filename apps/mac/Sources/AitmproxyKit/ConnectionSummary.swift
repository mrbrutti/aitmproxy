import Foundation

/// The app's link to the proxy's command bus: offline, dialling, connected (to an
/// address), or failed (with the reason). Published by the bus service; read by every
/// connection indicator through `ConnectionSummary`.
public enum BusState: Hashable, Sendable {
    case disconnected
    case connecting(String)
    case connected(String)
    case failed(String)
}

/// How well one lane of the connection is doing. Ordered worst-last so the toolbar pill
/// can show the worst lane.
public enum LaneState: Int, Comparable, Sendable {
    case ok, working, off, warning, error

    public static func < (a: LaneState, b: LaneState) -> Bool { a.rawValue < b.rawValue }
}

/// One thing a surface may offer to change a lane. The view maps each to the same call
/// its menu-bar item makes; the model only names it.
public enum ConnectionAction: Hashable, Sendable, CaseIterable {
    case startCore, restartCore, showCoreLog, switchToEmbedded
    case reconnectBus, openBusSettings
    case turnCaptureOn, turnCaptureOff, openScope, approveInSystemSettings, uninstallExtension, openCaptureSettings
    case openBrowser, copyListenAddress
    /// The Scope fact's remedy button: the Scope page with its add sheet open.
    case addScopeHost
    case trustCA, openCAPanel

    /// The button title (title case; an ellipsis where another view opens).
    public var title: String {
        switch self {
        case .startCore: "Start Core"
        case .restartCore: "Restart Core"
        case .showCoreLog: "Core Log…"
        case .switchToEmbedded: "Switch to Embedded…"
        case .reconnectBus: "Reconnect"
        case .openBusSettings: "Bus Settings…"
        case .turnCaptureOn: "Capture All Apps"
        case .turnCaptureOff: "Stop Capturing All Apps"
        case .openScope: "Open Scope…"
        case .approveInSystemSettings: "Open System Settings…"
        case .uninstallExtension: "Uninstall Extension…"
        case .openCaptureSettings: "All Apps Settings…"
        case .openBrowser: "Open Browser"
        case .copyListenAddress: "Copy Address"
        case .addScopeHost: "Add Host…"
        case .trustCA: "Trust the aitmproxy CA"
        case .openCAPanel: "Certificate Authority…"
        }
    }

    /// Actions that remove something; the view styles them as such and confirms.
    public var isDestructive: Bool { self == .uninstallExtension }
}

/// One of the three lanes the operator must understand: the core (the proxy process), the
/// bus (the app's link to it) and the capture extension (system-wide capture). Every word
/// a connection indicator shows comes from here, so the toolbar's connection cluster, the
/// Status page, the Core Log header and the Settings rows can never disagree.
public struct ConnectionLane: Hashable, Sendable {
    public enum Kind: String, Hashable, Sendable, CaseIterable {
        case core, bus, capture

        /// The lane's section label.
        public var title: String {
            switch self {
            case .core: "Core"
            case .bus: "Bus"
            case .capture: "All Apps"
            }
        }
    }

    public let kind: Kind
    public let state: LaneState
    /// The one lower-case word (or two) for the compact surfaces: "running", "connecting…",
    /// "capture on · 3 hosts". Follows a dot or a "·" mid-sentence, hence lower case.
    public let word: String
    /// The fact under it: "Embedded · proxy 127.0.0.1:8080", "operator · 127.0.0.1:60745",
    /// "extension approved · 3 hosts in scope".
    public let detail: String
    /// What fixes it when `state` is not `.ok`; `nil` when nothing is needed.
    public let remedy: String?
    /// What the surface may offer, primary first.
    public let actions: [ConnectionAction]

    /// The word with its lane named where the word alone would be ambiguous: "capture off" as is,
    /// "failed" → "core: failed". For one-line surfaces (the switch help, `spoken`).
    public var compact: String {
        word.localizedCaseInsensitiveContains(kind.title) ? word : "\(kind.title.lowercased()): \(word)"
    }

    public init(kind: Kind, state: LaneState, word: String, detail: String, remedy: String? = nil,
                actions: [ConnectionAction] = []) {
        self.kind = kind
        self.state = state
        self.word = word
        self.detail = detail
        self.remedy = remedy
        self.actions = actions
    }
}

/// One row of the Status page's Getting-started list: a fact that is either already true
/// or has one action that makes it true. Done rows stay — the list is live state, not a tour.
public struct GettingStartedStep: Hashable, Sendable {
    /// Source order is declaration history; the Getting-started list's order is `ConnectionSummary.make`'s
    /// (`coreRunning`, `busConnected`, `systemProxy`, `extensionOn`, `scopeSet`, `caTrusted`, `firstFlow`).
    public enum Kind: String, Hashable, Sendable, CaseIterable {
        case coreRunning, busConnected, caTrusted, systemProxy, extensionOn, scopeSet, firstFlow
    }

    public let kind: Kind
    public let title: String
    public let done: Bool
    public let action: ConnectionAction?
    /// The route's `detail` for the route and fact steps (the row's help); nil for the others.
    public let detail: String?

    public init(kind: Kind, title: String, done: Bool, action: ConnectionAction? = nil, detail: String? = nil) {
        self.kind = kind
        self.title = title
        self.done = done
        self.action = action
        self.detail = detail
    }
}

/// One way traffic reaches the core (the system proxy, All Apps) or one fact that gates what a
/// route carries (Scope → decryption, the CA → HTTPS), as one line with its actions. Both pages —
/// the Status steps and the Flows empty state / banner — print `line` verbatim (spec
/// 2026-10-31-mac-traffic-route-advice-design D2–D5).
public struct TrafficRoute: Hashable, Sendable {
    public enum Kind: String, Hashable, Sendable, CaseIterable { case systemProxy, allApps, scope, caTrust }

    public let kind: Kind
    public let open: Bool
    /// The one line, verbatim on both pages.
    public let line: String
    /// What this route carries (the lane principle), the same on every state of the route:
    /// systemProxy → "every proxy-aware app, regardless of Scope"; allApps → "in-scope hosts of every app".
    public let detail: String
    /// What opens the route, primary first; empty when open — and empty for the system-proxy entry
    /// until PR4 fills `.setSystemProxy`.
    public let actions: [ConnectionAction]

    /// The state words: `line` up to its first " — " ("system proxy off", "All Apps off"), or the whole
    /// line when it has none (the quoted Scope sentence, verbatim with its period; the CA line). The
    /// one-line banner is the shown entries' states joined with " · "; remedies are never text there.
    public var state: String {
        guard let clause = line.range(of: " — ") else { return line }
        return String(line[..<clause.lowerBound])
    }

    public init(kind: Kind, open: Bool, line: String, detail: String, actions: [ConnectionAction]) {
        self.kind = kind
        self.open = open
        self.line = line
        self.detail = detail
        self.actions = actions
    }
}

/// The two routes and the two facts, the Flows empty-state advice and the one banner line, all
/// derived once inside `ConnectionSummary.make` so Status and Flows can never disagree.
public struct TrafficRoutes: Hashable, Sendable {
    /// nil while the system proxy is unknown: before PR4 lands, before its first `proxy.status`
    /// answer, a session with no live bus, or a state the core cannot classify.
    public let systemProxy: TrafficRoute?
    /// nil when this build has no extension (`CaptureAdvice.unsupported`) or an external core is active.
    public let allApps: TrafficRoute?
    /// The Scope fact (not a route; under per-host decryption it gates decryption on both). Always
    /// present: closed iff `!open` — `!decrypt.decrypting` when `decrypt` is present and the bus lane
    /// is `.ok`, else `scopeHostCount == 0`.
    public let scope: TrafficRoute
    /// The CA fact (not a route; it gates HTTPS on both). nil while `ca.status` is unread or unknown.
    public let caTrust: TrafficRoute?
    /// The closed entries we know about — system proxy, All Apps, Scope, CA, in that order: the Flows
    /// empty-state lines. Empty unless the bus lane is `.ok`.
    public let advice: [TrafficRoute]
    /// The one-line banner text above the Flows table, or nil: the shown entries' `state`s joined " · ".
    public let banner: String?
    /// The banner's one button: the first shown entry that has an action, its `actions.first` (nil when
    /// none has one). Priority: system proxy (PR4's Set as System Proxy, once filled), All Apps, Scope, CA.
    public let bannerAction: ConnectionAction?

    /// Whether a known route is open; the two facts do not count.
    public var anyOpen: Bool { [systemProxy, allApps].compactMap { $0 }.contains(where: \.open) }

    public init(systemProxy: TrafficRoute?, allApps: TrafficRoute?, scope: TrafficRoute, caTrust: TrafficRoute?,
                advice: [TrafficRoute], banner: String?, bannerAction: ConnectionAction?) {
        self.systemProxy = systemProxy
        self.allApps = allApps
        self.scope = scope
        self.caTrust = caTrust
        self.advice = advice
        self.banner = banner
        self.bannerAction = bannerAction
    }
}

/// What the core itself reports about the capture extension, once the read-only
/// `capture.status` bus verb exists (proposed 2026-10-31). Optional input: when present it
/// sharpens the capture lane's detail; the app's own tunnel status stays the fallback.
public struct CoreCaptureStatus: Hashable, Sendable {
    public var providerAttached: Bool
    public var flowsHandedOff: Int

    public init(providerAttached: Bool, flowsHandedOff: Int) {
        self.providerAttached = providerAttached
        self.flowsHandedOff = flowsHandedOff
    }
}

/// The three lanes plus the Getting-started list, computed from published facts only
/// (`CoreConnection.Status`, `BusState`, `CaptureCapability`, the live scope count) and
/// never from a preference key — a lane cannot claim "on" because a switch was flipped.
public struct ConnectionSummary: Hashable, Sendable {
    public let core: ConnectionLane
    public let bus: ConnectionLane
    public let capture: ConnectionLane
    public let steps: [GettingStartedStep]
    /// The two routes, the two facts, the Flows empty-state advice and the one banner line; the
    /// route steps are built from it, so Status and Flows read one derivation.
    public let routes: TrafficRoutes
    /// The proxy address clients point at; the last step quotes it.
    public let listenAddress: String

    public var lanes: [ConnectionLane] { [core, bus, capture] }

    /// The worst lane state.
    public var overall: LaneState { lanes.map(\.state).max() ?? .ok }

    /// The worst lane, for the compact surfaces that show one word.
    public var worst: ConnectionLane { lanes.max { $0.state < $1.state } ?? core }

    public var allStepsDone: Bool { steps.allSatisfy(\.done) }

    /// The three lanes in one line, for tooltips: "Core: running — Embedded · proxy …\nBus: …".
    public var tooltip: String {
        lanes.map { "\($0.kind.title): \($0.word) — \($0.detail)" }.joined(separator: "\n")
    }

    /// The three lanes as one spoken sentence, for accessibility labels.
    public var spoken: String {
        lanes.map(\.compact).joined(separator: ", ")
    }

    /// The hint for a Scope entry while the provider still claims a bare host's DNS lookup:
    /// a port-qualified entry claims only the TCP flow. Removed with the provider fix.
    public static let scopeEntryHint = "example.com:443"

    /// The core's `NOTHING_DECRYPTED_ADVICE`, printed verbatim by every frontend (core spec D9): our
    /// own copy for a core that lacks `proxy.status.decrypt`, the same words.
    public static let nothingDecryptedAdvice = "Nothing is decrypted until a host is in Scope."

    // MARK: Make

    /// `systemProxy` is `Session.systemProxy` (nil = unknown, never rendered as "off");
    /// `tunnelledFlowCount` the rows whose `tls == .tunnelled`; `decrypt` the core's
    /// `proxy.status.decrypt` (nil from an older core).
    public static func make(
        core connection: CoreConnection?,
        activeKind: ActiveCoreKind,
        bus: BusState,
        role: String?,
        roleWarning: Bool,
        capability: CaptureCapability,
        captureSupported: Bool,
        scopeHostCount: Int,
        flowCount: Int,
        listenAddress: String,
        coreCapture: CoreCaptureStatus? = nil,
        systemProxy: SystemProxyState? = nil,
        tunnelledFlowCount: Int = 0,
        decrypt: DecryptStatus? = nil
    ) -> ConnectionSummary {
        let core = coreLane(connection, activeKind: activeKind, bus: bus)
        let busLane = self.busLane(bus, role: role, roleWarning: roleWarning, activeKind: activeKind, core: connection)
        let advice = CaptureAdvice.make(capability: capability, supported: captureSupported, scopeHostCount: scopeHostCount)
        let capture = captureLane(advice, capability: capability, activeKind: activeKind,
                                  scopeHostCount: scopeHostCount, coreCapture: coreCapture)
        let routes = self.routes(systemProxy: systemProxy, advice: advice, activeKind: activeKind, bus: busLane,
                                 scopeHostCount: scopeHostCount, flowCount: flowCount, tunnelledFlowCount: tunnelledFlowCount,
                                 decrypt: decrypt, listenAddress: listenAddress)
        let steps = self.steps(core: core, bus: busLane, activeKind: activeKind, advice: advice, routes: routes,
                               flowCount: flowCount, listenAddress: listenAddress)
        return ConnectionSummary(core: core, bus: busLane, capture: capture, steps: steps, routes: routes, listenAddress: listenAddress)
    }

    // MARK: Lanes

    private static func coreLane(_ connection: CoreConnection?, activeKind: ActiveCoreKind, bus: BusState) -> ConnectionLane {
        guard activeKind == .embedded else {
            // An external core is the operator's own process: the app only sees it through the bus.
            let detail: String
            switch bus {
            case .connected(let address), .connecting(let address): detail = "External · bus \(address)"
            case .disconnected, .failed: detail = "External · set the address in Settings ▸ Bus"
            }
            return ConnectionLane(kind: .core, state: .off, word: "external", detail: detail,
                                  remedy: "The app does not manage this core; start and stop it yourself",
                                  actions: [.openBusSettings, .switchToEmbedded])
        }
        guard let connection else {
            return ConnectionLane(kind: .core, state: .off, word: "not running", detail: "Embedded core",
                                  remedy: "Start the core", actions: [.startCore, .showCoreLog])
        }
        let address = connection.proxyAddress.map { "Embedded · proxy \($0)" } ?? "Embedded core"
        switch connection.status {
        case .ready:
            return ConnectionLane(kind: .core, state: .ok, word: "running", detail: address,
                                  actions: [.restartCore, .showCoreLog])
        case .starting, .connecting:
            return ConnectionLane(kind: .core, state: .working, word: "starting…", detail: address,
                                  actions: [.showCoreLog])
        case .degraded(let reason):
            return ConnectionLane(kind: .core, state: .error, word: "failed", detail: reason,
                                  remedy: "Restart the core", actions: [.restartCore, .showCoreLog])
        case .stopped:
            return ConnectionLane(kind: .core, state: .off, word: "stopped", detail: "Embedded core",
                                  remedy: "Start the core", actions: [.startCore, .showCoreLog])
        }
    }

    private static func busLane(_ bus: BusState, role: String?, roleWarning: Bool,
                                activeKind: ActiveCoreKind, core: CoreConnection?) -> ConnectionLane {
        switch bus {
        case .connected(let address):
            let who = role ?? "connected"
            if roleWarning {
                return ConnectionLane(kind: .bus, state: .warning, word: "connected as \(who)",
                                      detail: "\(who) · \(address)",
                                      remedy: "Paste the operator token in Settings ▸ Bus, then reconnect",
                                      actions: [.openBusSettings, .reconnectBus])
            }
            return ConnectionLane(kind: .bus, state: .ok, word: "connected", detail: "\(who) · \(address)",
                                  actions: [.reconnectBus])
        case .connecting(let address):
            return ConnectionLane(kind: .bus, state: .working, word: "connecting…", detail: address,
                                  actions: [.openBusSettings])
        case .failed(let why):
            return ConnectionLane(kind: .bus, state: .error, word: "bus failed", detail: why,
                                  remedy: why.localizedCaseInsensitiveContains("token")
                                      ? "Paste the operator token in Settings ▸ Bus, then reconnect"
                                      : "Reconnect, or check the address in Settings ▸ Bus",
                                  actions: [.reconnectBus, .openBusSettings])
        case .disconnected:
            let coreDown = activeKind == .embedded && (core == nil || core?.status == .stopped)
            return ConnectionLane(kind: .bus, state: .off, word: "offline",
                                  detail: activeKind == .embedded ? "Embedded core" : "External core",
                                  remedy: coreDown ? "Start the core" : "Reconnect",
                                  actions: coreDown ? [.startCore] : [.reconnectBus, .openBusSettings])
        }
    }

    private static func captureLane(_ advice: CaptureAdvice, capability: CaptureCapability, activeKind: ActiveCoreKind,
                                    scopeHostCount: Int, coreCapture: CoreCaptureStatus?) -> ConnectionLane {
        let hosts = Format.count(scopeHostCount, "host") + " in scope"
        // Capture is the embedded core's gate: with an external core the switch is not ours.
        if activeKind == .external, advice != .unsupported {
            return ConnectionLane(kind: .capture, state: .off, word: "all apps off",
                                  detail: "The external core does not run the extension",
                                  remedy: "Switch to the embedded core to capture other apps' traffic",
                                  actions: [.switchToEmbedded])
        }
        switch advice {
        case .unsupported:
            return ConnectionLane(kind: .capture, state: .off, word: "no extension",
                                  detail: "This build has no extension",
                                  remedy: "Install the signed Aitmproxy app; its extension is built in",
                                  actions: [])
        case .off:
            let installed = capability.isInstalledOrInstalling
            return ConnectionLane(kind: .capture, state: .off, word: "all apps off",
                                  detail: installed ? "extension installed · \(hosts)" : "extension not installed",
                                  remedy: installed ? "Turn on All Apps to see every Mac app's traffic"
                                                    : "Turn on All Apps; macOS asks you to approve its extension",
                                  actions: installed ? [.turnCaptureOn, .uninstallExtension, .openCaptureSettings]
                                                     : [.turnCaptureOn, .openCaptureSettings])
        case .awaitingApproval:
            return ConnectionLane(kind: .capture, state: .working, word: "waiting for approval",
                                  detail: "extension installed · approval pending",
                                  remedy: "Approve the extension in System Settings ▸ Network Extensions, then allow Add Proxy Configurations",
                                  actions: [.approveInSystemSettings, .turnCaptureOff])
        case .degraded(let reason):
            let unnotarized = reason.localizedCaseInsensitiveContains("signature")
            return ConnectionLane(kind: .capture, state: .error, word: "all apps degraded", detail: reason,
                                  remedy: unnotarized
                                      ? "macOS refused this build's extension; install the signed Aitmproxy app"
                                      : "Turn All Apps off and on again; if it stays degraded, uninstall and reinstall the extension",
                                  actions: [.turnCaptureOff, .uninstallExtension, .openCaptureSettings])
        case .onEmptyScope:
            return ConnectionLane(kind: .capture, state: .warning, word: "on, nothing in scope",
                                  detail: "extension on · 0 hosts in scope",
                                  remedy: "Add a host to Scope (for now as \(scopeEntryHint)); nothing is captured until then",
                                  actions: [.openScope, .turnCaptureOff, .uninstallExtension])
        case .on:
            var detail = "extension on · \(hosts)"
            if let coreCapture {
                detail = coreCapture.providerAttached
                    ? "attached · \(hosts) · \(coreCapture.flowsHandedOff) flows handed off"
                    : "extension on · \(hosts) · core not attached"
            }
            let attached = coreCapture?.providerAttached ?? true
            return ConnectionLane(kind: .capture, state: attached ? .ok : .warning,
                                  word: attached ? "all apps on · \(hosts)" : "on, core not attached",
                                  detail: detail,
                                  remedy: attached ? nil : "Restart the core so the extension can attach to it",
                                  actions: attached ? [.turnCaptureOff, .openScope, .uninstallExtension]
                                                    : [.restartCore, .turnCaptureOff])
        }
    }

    // MARK: Routes (spec 2026-10-31-mac-traffic-route-advice-design D3, D5)

    private static let systemProxyDetail = "every proxy-aware app, regardless of Scope"
    private static let allAppsDetail = "in-scope hosts of every app"
    private static let scopeDetail = "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel"

    private static func routes(systemProxy: SystemProxyState?, advice: CaptureAdvice, activeKind: ActiveCoreKind, bus: ConnectionLane,
                               scopeHostCount: Int, flowCount: Int, tunnelledFlowCount: Int, decrypt: DecryptStatus?,
                               listenAddress: String) -> TrafficRoutes {
        let busOK = bus.state == .ok
        let systemProxyRoute = systemProxy.map { systemProxyRoute($0, listenAddress: listenAddress) }
        // An external core runs no extension: the All Apps route is not ours to show.
        let allApps = activeKind == .external ? nil : allAppsRoute(advice)
        // The Scope fact is known only through the bus: a `decrypt` value is ignored unless the bus lane is ok
        // (the one `BusService` line has no disconnect reset), and the fallback is the live scope count.
        let scope = scopeRoute(busOK ? decrypt : nil, scopeHostCount: scopeHostCount)
        // Task 1b derives the CA fact from PR D's `CATrustFacts`; until then it is unknown.
        let caTrust: TrafficRoute? = nil

        // The Flows empty-state lines: every closed fact, in priority order, whatever the row count.
        let closedFacts = busOK ? [systemProxyRoute, allApps, scope, caTrust].compactMap { $0 }.filter { !$0.open } : []

        // D5: name only what is known closed; an unknown system proxy (nil) is never named.
        let knownOpenRoute = (systemProxyRoute?.open ?? false) || (allApps?.open ?? false)
        let closedRoutes = knownOpenRoute ? [] : [systemProxyRoute, allApps].compactMap { $0 }.filter { !$0.open }
        let allTunnels = flowCount > 0 && tunnelledFlowCount == flowCount
        var shown = closedRoutes
        if !scope.open, !closedRoutes.isEmpty || allTunnels { shown.append(scope) }
        if let caTrust, !caTrust.open { shown.append(caTrust) }
        let bannerShown = flowCount > 0 && busOK && !shown.isEmpty
        return TrafficRoutes(
            systemProxy: systemProxyRoute, allApps: allApps, scope: scope, caTrust: caTrust, advice: closedFacts,
            banner: bannerShown ? shown.map(\.state).joined(separator: " · ") : nil,
            bannerAction: bannerShown ? shown.first { !$0.actions.isEmpty }?.actions.first : nil)
    }

    /// D3's system-proxy table. The closed entries carry no action in this PR (PR4 fills `.setSystemProxy`).
    private static func systemProxyRoute(_ state: SystemProxyState, listenAddress: String) -> TrafficRoute {
        let remedy = "set \(listenAddress) as the system proxy, or point a client at it"
        switch state.route(to: listenAddress) {
        case .off:
            return TrafficRoute(kind: .systemProxy, open: false, line: "system proxy off — \(remedy)",
                                detail: systemProxyDetail, actions: [])
        case .other(let host, let port):
            let address = SystemProxyState.Endpoint(host: host, port: port).address
            return TrafficRoute(kind: .systemProxy, open: false, line: "system proxy on · \(address), not this core — \(remedy)",
                                detail: systemProxyDetail, actions: [])
        case .thisCore(let http, let https):
            var line = "system proxy on · \(listenAddress)"
            if http, !https { line += " · HTTP only" }
            if https, !http { line += " · HTTPS only" }
            return TrafficRoute(kind: .systemProxy, open: true, line: line, detail: systemProxyDetail, actions: [])
        }
    }

    /// D3's All Apps table: closed only when the extension is NOT on; with it on the route is open whatever
    /// the scope — the Scope fact owns the empty-scope clause, so the banner never says it twice. Nil when
    /// this build has no extension.
    private static func allAppsRoute(_ advice: CaptureAdvice) -> TrafficRoute? {
        switch advice {
        case .unsupported:
            return nil
        case .off:
            return TrafficRoute(kind: .allApps, open: false,
                                line: "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)",
                                detail: allAppsDetail, actions: [.openCaptureSettings])
        case .awaitingApproval:
            return TrafficRoute(kind: .allApps, open: false,
                                line: "All Apps waiting for approval — approve the extension in System Settings",
                                detail: allAppsDetail, actions: [.approveInSystemSettings])
        case .degraded(let reason):
            return TrafficRoute(kind: .allApps, open: false, line: "All Apps degraded — \(reason)",
                                detail: allAppsDetail, actions: [.openCaptureSettings])
        case .onEmptyScope, .on:
            return TrafficRoute(kind: .allApps, open: true, line: "All Apps on", detail: allAppsDetail, actions: [])
        }
    }

    /// D3's Scope fact. `decrypt` is the core's own account (already nil here when the bus lane is not ok):
    /// closed iff it says nothing is decrypted, else iff the scope count is 0; N comes from it when present.
    /// The closed line is the core's sentence verbatim, or our same-words fallback; the remedy is the
    /// button `Add Host…`, never appended text.
    private static func scopeRoute(_ decrypt: DecryptStatus?, scopeHostCount: Int) -> TrafficRoute {
        let open = decrypt.map(\.decrypting) ?? (scopeHostCount > 0)
        let hosts = decrypt?.scopeHosts ?? scopeHostCount
        if open {
            return TrafficRoute(kind: .scope, open: true, line: "Scope: \(Format.count(hosts, "host")) decrypted",
                                detail: scopeDetail, actions: [])
        }
        return TrafficRoute(kind: .scope, open: false, line: decrypt?.advice ?? nothingDecryptedAdvice,
                            detail: scopeDetail, actions: [.addScopeHost, .openScope])
    }

    // MARK: Steps (spec D4)

    private static func steps(core: ConnectionLane, bus: ConnectionLane, activeKind: ActiveCoreKind, advice: CaptureAdvice,
                              routes: TrafficRoutes, flowCount: Int, listenAddress: String) -> [GettingStartedStep] {
        // An external core is the operator's; it counts as running once the bus reaches it.
        let coreDone = core.state == .ok || (activeKind == .external && bus.state == .ok)
        let busDone = bus.state == .ok
        var steps = [
            GettingStartedStep(kind: .coreRunning,
                               title: coreDone ? "Core is running" : "Start the core",
                               done: coreDone, action: coreDone ? nil : core.actions.first),
            GettingStartedStep(kind: .busConnected,
                               title: busDone ? "Bus connected" : "Connect to the bus",
                               done: busDone, action: busDone ? nil : bus.actions.first),
        ]
        // Omitted while the system proxy is unknown: a step that cannot name its state would be a lie.
        if let systemProxy = routes.systemProxy {
            steps.append(GettingStartedStep(kind: .systemProxy, title: systemProxy.line, done: systemProxy.open,
                                            action: nil, detail: systemProxy.detail))
        }
        // The All Apps words come from the route table even when the route itself is not shown (external core).
        let allApps = routes.allApps ?? allAppsRoute(advice)
        let extensionAction: ConnectionAction?
        switch advice {
        case .on, .onEmptyScope, .unsupported: extensionAction = nil
        case .awaitingApproval: extensionAction = .approveInSystemSettings
        case .degraded: extensionAction = .openCaptureSettings
        case .off: extensionAction = .turnCaptureOn
        }
        if let allApps {
            steps.append(GettingStartedStep(kind: .extensionOn, title: allApps.open ? "All Apps is on" : allApps.line,
                                            done: allApps.open, action: extensionAction, detail: allApps.detail))
        } else {
            steps.append(GettingStartedStep(kind: .extensionOn, title: "All Apps capture is not in this build", done: false, action: nil))
        }
        let scope = routes.scope
        steps.append(GettingStartedStep(kind: .scopeSet,
                                        title: scope.open ? scope.line : "Add a host to Scope (for now as \(scopeEntryHint))",
                                        done: scope.open, action: scope.open ? nil : .openScope,
                                        detail: scope.open ? scope.detail : scope.line))
        steps.append(GettingStartedStep(kind: .firstFlow,
                                        title: flowCount > 0 ? "\(Format.count(flowCount, "flow")) captured"
                                                             : "Point a client at \(listenAddress), or open the browser",
                                        done: flowCount > 0, action: flowCount > 0 ? nil : .openBrowser))
        return steps
    }
}
