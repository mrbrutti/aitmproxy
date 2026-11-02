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
    /// The system-proxy route's buttons (spec 2026-10-31-system-proxy-automation-design §D12): make this core the
    /// system proxy (the core records the previous setting), restore that recorded setting.
    case setSystemProxy, unsetSystemProxy
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
        case .setSystemProxy: "Set as System Proxy"
        case .unsetSystemProxy: "Restore System Proxy"
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
/// route carries (Scope → decryption, the CA → HTTPS), as its state words, an optional remedy clause
/// and its actions. Both pages — the Status steps and the Flows empty state / banner — print `line`
/// verbatim (spec 2026-10-31-mac-traffic-route-advice-design D2–D5).
public struct TrafficRoute: Hashable, Sendable {
    public enum Kind: String, Hashable, Sendable, CaseIterable { case systemProxy, allApps, scope, caTrust }

    public let kind: Kind
    public let open: Bool
    /// The state words: "system proxy off", "All Apps waiting for approval", the quoted Scope sentence
    /// (verbatim with its period), the CA line. The one-line banner is the shown entries' states joined
    /// with " · "; remedies are never text there.
    public let state: String
    /// The remedy clause a closed route's line carries after " — "; nil for an open entry and for the two
    /// facts (the Scope fact's remedy is the Add Host… button, the CA fact's its Trust button).
    public let remedy: String?
    /// What this route carries (the lane principle), the same on every state of the route:
    /// systemProxy → "every proxy-aware app, regardless of Scope"; allApps → "in-scope hosts of every app".
    public let detail: String
    /// What opens the route, primary first; empty when closed with nothing to press (an administrator wait, a change
    /// in flight, a platform with no mechanism, the CFNetwork read without the verb's facts). Empty when open, with
    /// one exception: the system-proxy entry the app itself set carries `[.unsetSystemProxy]` (§D12's Restore
    /// button) — the banner never reads it, since an open entry is never shown.
    public let actions: [ConnectionAction]

    /// The one line, verbatim on both pages: the state, then " — " and the remedy when there is one. Composed
    /// from the two stored parts and never parsed back, so a core sentence that itself contains " — " stays whole.
    public var line: String { remedy.map { "\(state) — \($0)" } ?? state }

    public init(kind: Kind, open: Bool, state: String, remedy: String? = nil, detail: String, actions: [ConnectionAction]) {
        self.kind = kind
        self.open = open
        self.state = state
        self.remedy = remedy
        self.detail = detail
        self.actions = actions
    }
}

/// The two routes and the two facts, the Flows empty-state advice and the one banner line, all
/// derived once inside `ConnectionSummary.make` so Status and Flows can never disagree.
public struct TrafficRoutes: Hashable, Sendable {
    /// nil while the system proxy is unknown: before the first `proxy.status` answer with no CFNetwork read
    /// either, a session with no live bus, or a verb word that names no endpoint (`unsupported`, `unknown`,
    /// an `other` at our own address).
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
    /// The entries the one-line banner names (D5's predicate), in banner order; empty when there is no
    /// banner (no rows, bus not ok, nothing closed). The banner text, its button and its tooltip detail
    /// are all read off this list, so a view never re-derives the shown set from the banner's text.
    public let shown: [TrafficRoute]

    /// The one-line banner text above the Flows table, or nil: the shown entries' `state`s joined " · ".
    public var banner: String? { shown.isEmpty ? nil : shown.map(\.state).joined(separator: " · ") }
    /// The banner's one button: the first shown entry that has an action, its `actions.first` (nil when
    /// none has one). Priority: system proxy (Set as System Proxy), All Apps, Scope, CA.
    public var bannerAction: ConnectionAction? { shown.first { !$0.actions.isEmpty }?.actions.first }
    /// The banner's tooltip detail: the shown entries' `detail`s joined " · "; nil when nothing is shown.
    public var bannerDetail: String? { shown.isEmpty ? nil : shown.map(\.detail).joined(separator: " · ") }

    /// Whether a known route is open; the two facts do not count. The same list `ConnectionSummary.routes`
    /// derives the closed routes from, so the banner's gate and this flag can never disagree.
    public var anyOpen: Bool { Self.knownRoutes(systemProxy: systemProxy, allApps: allApps).contains(where: \.open) }

    /// The known routes, in banner order: a nil entry is unknown (never named), not closed.
    static func knownRoutes(systemProxy: TrafficRoute?, allApps: TrafficRoute?) -> [TrafficRoute] {
        [systemProxy, allApps].compactMap { $0 }
    }

    public init(systemProxy: TrafficRoute?, allApps: TrafficRoute?, scope: TrafficRoute, caTrust: TrafficRoute?,
                advice: [TrafficRoute], shown: [TrafficRoute]) {
        self.systemProxy = systemProxy
        self.allApps = allApps
        self.scope = scope
        self.caTrust = caTrust
        self.advice = advice
        self.shown = shown
    }
}

/// What the core itself reports about the capture extension, from the read-only
/// `capture.status` bus verb (PR #200). Optional input: when present it sharpens the capture
/// lane's detail; the app's own tunnel status stays the fallback (spec "Facts from the other
/// sessions folded in": the verb's reply overrides the detail line, never the lane's source).
public struct CoreCaptureStatus: Hashable, Sendable {
    public var providerAttached: Bool
    public var flowsHandedOff: Int
    /// The core's own reason when its capture path is not running — `capability_reason`, else the
    /// feeder's `reason` (a closed vocabulary: "macos_capture.enabled is false", "not a macOS build",
    /// "not started", "stopped", "cannot bind the capture sockets (<kind>)" …). Nil while attached.
    public var reason: String?

    public init(providerAttached: Bool, flowsHandedOff: Int, reason: String? = nil) {
        self.providerAttached = providerAttached
        self.flowsHandedOff = flowsHandedOff
        self.reason = reason
    }

    /// The fold of the verb's reply: `provider.state == attached`, TCP + UDP handoffs of the current
    /// attachment (saturating — two wire counts must never trap the app), and the core's reason when
    /// it has one, under the Kit's wire-text rule for advice (`DecryptStatus.displayAdvice`: blank is
    /// nil, one line, cut at 512). One mapping, so the lane never reads the raw reply.
    public init(_ status: CaptureStatus) {
        let feederReason: String? = switch status.feeder {
        case .off(let reason): reason
        case .bindFailed(let reason): reason
        case .listening, .unknown: nil
        }
        let (sum, overflow) = status.tcpHandedOff.addingReportingOverflow(status.udpHandedOff)
        self.init(providerAttached: status.providerAttached,
                  flowsHandedOff: overflow ? Int.max : sum,
                  reason: (status.capabilityReason ?? feederReason).flatMap(DecryptStatus.displayAdvice))
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

    /// §D12's lane sentence (spec 2026-10-31-system-proxy-automation-design), verbatim wherever both lanes appear:
    /// the Settings ▸ Proxy footnote, the first-run sheet, the Status page Core card tooltip.
    public static let systemProxyLaneSentence =
        "System proxy → every proxy-aware app, regardless of Scope. All Apps → in-scope hosts of every app."

    /// The Settings ▸ Proxy "Bypass hosts" field's help (§D5, §D13), verbatim.
    public static let bypassFieldCopy = "Hosts that skip the system proxy. Add the hosts your own tools talk to"
        + " (today's incident: a tool whose API calls were routed to another proxy)."

    // MARK: Make

    /// `systemProxy` is the endpoint half without the verb facts (reserved for a CFNetwork read; today always
    /// `systemProxyFacts?.state`; nil = unknown, never rendered as "off");
    /// `systemProxyFacts` the verb's `proxy.status.system_proxy` as `Session` parses it (nil = no verb on this
    /// bus) — when present it is the system-proxy route's one source and `systemProxy` is not read (spec
    /// 2026-10-31-system-proxy-automation-design D1); `caTrust` PR D's `Session.caTrust` (nil = `ca.status`
    /// unread or every store unknown, never rendered as trusted or not trusted); `tunnelledFlowCount` the rows
    /// whose `tls == .tunnelled`; `decrypt` the core's `proxy.status.decrypt` (nil from an older core).
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
        systemProxyFacts: SystemProxyFacts? = nil,
        caTrust: CATrustFacts? = nil,
        tunnelledFlowCount: Int = 0,
        decrypt: DecryptStatus? = nil
    ) -> ConnectionSummary {
        let core = coreLane(connection, activeKind: activeKind, bus: bus)
        let busLane = self.busLane(bus, role: role, roleWarning: roleWarning, activeKind: activeKind, core: connection)
        let advice = CaptureAdvice.make(capability: capability, supported: captureSupported, scopeHostCount: scopeHostCount)
        let capture = captureLane(advice, capability: capability, activeKind: activeKind,
                                  scopeHostCount: scopeHostCount, coreCapture: coreCapture)
        // The All Apps words come from the route table once. An external core runs no extension, so the route
        // is not ours to show (`routes.allApps` nil, D10) while the Status step still prints the same words.
        let allApps = allAppsRoute(advice)
        let routes = self.routes(systemProxy: systemProxy, systemProxyFacts: systemProxyFacts, caTrust: caTrust,
                                 allApps: activeKind == .external ? nil : allApps,
                                 bus: busLane, scopeHostCount: scopeHostCount, flowCount: flowCount,
                                 tunnelledFlowCount: tunnelledFlowCount, decrypt: decrypt, listenAddress: listenAddress)
        let steps = self.steps(core: core, bus: busLane, activeKind: activeKind, advice: advice, allApps: allApps, routes: routes,
                               caTrust: caTrust, flowCount: flowCount, listenAddress: listenAddress)
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
                if coreCapture.providerAttached {
                    detail = "attached · \(hosts) · \(coreCapture.flowsHandedOff) flows handed off"
                } else {
                    // The core's reason joins the detail when it has one ("macos_capture.enabled is
                    // false" while the app's switch still reads on), so the card says why, not just that.
                    let why = coreCapture.reason.map { " · \($0)" } ?? ""
                    detail = "extension on · \(hosts) · core not attached\(why)"
                }
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

    /// `allApps` is the route table's All Apps entry, or nil when it is not ours to show (no extension in this
    /// build, an external core).
    private static func routes(systemProxy: SystemProxyState?, systemProxyFacts: SystemProxyFacts?, caTrust: CATrustFacts?,
                               allApps: TrafficRoute?, bus: ConnectionLane, scopeHostCount: Int, flowCount: Int,
                               tunnelledFlowCount: Int, decrypt: DecryptStatus?, listenAddress: String) -> TrafficRoutes {
        let busOK = bus.state == .ok
        // D1: the verb's facts are the route's source whenever the bus offers them — even when they name nothing
        // (nil, never filled in from the read); the CFNetwork read is the source only without them.
        let systemProxyRoute: TrafficRoute? = if let systemProxyFacts {
            self.systemProxyRoute(systemProxyFacts, listenAddress: listenAddress)
        } else {
            systemProxy.map { self.systemProxyRoute($0, listenAddress: listenAddress) }
        }
        // The Scope fact is known only through the bus: a `decrypt` value is ignored unless the bus lane is ok
        // (the one `BusService` line has no disconnect reset), and the fallback is the live scope count.
        let scope = scopeRoute(busOK ? decrypt : nil, scopeHostCount: scopeHostCount)
        // The CA fact is PR D's `Session.caTrust`: nil while `ca.status` is unread or every store is unknown.
        let caTrust = caTrust.map(caTrustRoute)

        // The known routes, once (`TrafficRoutes.anyOpen` reads the same list): the closed ones, in order, are
        // the head of the empty-state advice and — unless another known route is open — of the banner.
        let known = TrafficRoutes.knownRoutes(systemProxy: systemProxyRoute, allApps: allApps)
        let closedRoutes = known.filter { !$0.open }
        // The Flows empty-state lines: every closed entry, routes then facts, whatever the row count.
        let closedFacts = busOK ? closedRoutes + [scope, caTrust].compactMap { $0 }.filter { !$0.open } : []

        // D5: name only what is known closed; an unknown system proxy (nil) is never named, and a closed route
        // is not named while another known route is open (rows are readable through it).
        let allTunnels = flowCount > 0 && tunnelledFlowCount == flowCount
        var shown = known.contains(where: \.open) ? [] : closedRoutes
        if !scope.open, !shown.isEmpty || allTunnels { shown.append(scope) }
        if let caTrust, !caTrust.open { shown.append(caTrust) }
        // A banner needs rows and a bus that is ok; `TrafficRoutes` joins the shown states, picks the button
        // and the tooltip detail from this one list.
        let bannerShown = flowCount > 0 && busOK && !shown.isEmpty
        return TrafficRoutes(systemProxy: systemProxyRoute, allApps: allApps, scope: scope, caTrust: caTrust,
                             advice: closedFacts, shown: bannerShown ? shown : [])
    }

    private static let systemProxyOtherRemedy =
        "Another app owns the system proxy. Set as System Proxy records its setting and restores it on quit."
    private static let systemProxyOffRemedy = "Set as System Proxy so Safari and other proxy-aware apps use the core."

    /// §D12's rows from the verb's facts (spec 2026-10-31-system-proxy-automation-design), in precedence order: a
    /// change in flight ("setting system proxy…", nothing to press) outranks every word; `needs_privilege` is closed
    /// with the core's own remedy sentence (nil when the compact object lacks it) and nothing to press; a word with
    /// no endpoint fact (`unsupported`, `unknown`, an `other` at our own address) is nil — unknown is never named.
    /// The endpoint words take the CFNetwork table's state words, then: at this core → open, " · set outside the
    /// app" appended when `managed_by_us` is false, `[.unsetSystemProxy]` only when it is true; elsewhere or off →
    /// closed, §D12's remedy and `[.setSystemProxy]` when `supported`, else the CFNetwork table's remedy and nothing
    /// to press.
    private static func systemProxyRoute(_ facts: SystemProxyFacts, listenAddress: String) -> TrafficRoute? {
        if facts.setting {
            return TrafficRoute(kind: .systemProxy, open: false, state: "setting system proxy…", detail: systemProxyDetail, actions: [])
        }
        if facts.word == .needsPrivilege {
            return TrafficRoute(kind: .systemProxy, open: false, state: "system proxy needs an administrator", remedy: facts.remedy,
                                detail: systemProxyDetail, actions: [])
        }
        guard let state = facts.state else { return nil }
        let words = systemProxyRoute(state, listenAddress: listenAddress)
        switch state.route(to: listenAddress) {
        case .thisCore:
            let outside = facts.managedByUs == false ? " · set outside the app" : ""
            return TrafficRoute(kind: .systemProxy, open: true, state: words.state + outside, detail: systemProxyDetail,
                                actions: facts.managedByUs == true ? [.unsetSystemProxy] : [])
        case .other:
            return TrafficRoute(kind: .systemProxy, open: false, state: words.state,
                                remedy: facts.supported ? systemProxyOtherRemedy : words.remedy,
                                detail: systemProxyDetail, actions: facts.supported ? [.setSystemProxy] : [])
        case .off:
            return TrafficRoute(kind: .systemProxy, open: false, state: words.state,
                                remedy: facts.supported ? systemProxyOffRemedy : words.remedy,
                                detail: systemProxyDetail, actions: facts.supported ? [.setSystemProxy] : [])
        }
    }

    /// D3's system-proxy table from the CFNetwork read alone: the state words and the generic remedy, no actions —
    /// without the verb's facts the app cannot tell whether it may set or restore anything.
    private static func systemProxyRoute(_ state: SystemProxyState, listenAddress: String) -> TrafficRoute {
        let remedy = "set \(listenAddress) as the system proxy, or point a client at it"
        switch state.route(to: listenAddress) {
        case .off:
            return TrafficRoute(kind: .systemProxy, open: false, state: "system proxy off", remedy: remedy,
                                detail: systemProxyDetail, actions: [])
        case .other(let host, let port):
            let address = SystemProxyState.Endpoint(host: host, port: port).address
            return TrafficRoute(kind: .systemProxy, open: false, state: "system proxy on · \(address), not this core",
                                remedy: remedy, detail: systemProxyDetail, actions: [])
        case .thisCore(let http, let https):
            var state = "system proxy on · \(listenAddress)"
            if http, !https { state += " · HTTP only" }
            if https, !http { state += " · HTTPS only" }
            return TrafficRoute(kind: .systemProxy, open: true, state: state, detail: systemProxyDetail, actions: [])
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
            return TrafficRoute(kind: .allApps, open: false, state: "All Apps off",
                                remedy: "turn it on to capture every app's traffic (macOS asks you to approve its extension)",
                                detail: allAppsDetail, actions: [.openCaptureSettings])
        case .awaitingApproval:
            return TrafficRoute(kind: .allApps, open: false, state: "All Apps waiting for approval",
                                remedy: "approve the extension in System Settings",
                                detail: allAppsDetail, actions: [.approveInSystemSettings])
        case .degraded(let reason):
            return TrafficRoute(kind: .allApps, open: false, state: "All Apps degraded", remedy: reason,
                                detail: allAppsDetail, actions: [.openCaptureSettings])
        case .onEmptyScope, .on:
            return TrafficRoute(kind: .allApps, open: true, state: "All Apps on", detail: allAppsDetail, actions: [])
        }
    }

    /// D3's Scope fact. `decrypt` is the core's own account (already nil here when the bus lane is not ok):
    /// closed iff it says nothing is decrypted, else iff the scope count is 0; N comes from it when present.
    /// The closed line is the core's sentence verbatim, or our same-words fallback; the remedy is the
    /// button `Add Host…`, never appended text. A blank sentence is no sentence whichever door it came
    /// through (the decoder drops one; the memberwise init does not), so the row and the banner are never empty.
    private static func scopeRoute(_ decrypt: DecryptStatus?, scopeHostCount: Int) -> TrafficRoute {
        let open = decrypt.map(\.decrypting) ?? (scopeHostCount > 0)
        let hosts = decrypt?.scopeHosts ?? scopeHostCount
        if open {
            return TrafficRoute(kind: .scope, open: true, state: "Scope: \(Format.count(hosts, "host")) decrypted",
                                detail: scopeDetail, actions: [])
        }
        let sentence = decrypt?.advice.flatMap { $0.allSatisfy(\.isWhitespace) ? nil : $0 }
        return TrafficRoute(kind: .scope, open: false, state: sentence ?? nothingDecryptedAdvice,
                            detail: scopeDetail, actions: [.addScopeHost, .openScope])
    }

    private static let caTrustedDetail = "HTTPS on both routes"

    /// D3's CA fact, worded by PR D's `CATrustFacts` helpers so every surface prints one vocabulary: `line` is
    /// its `text`; the closed detail its `notTrustedLine`; a closed entry's `actions` are its `actions`; an open
    /// entry stores none, like every other open entry (PR D's `[.openCAPanel]` on a trusted fact is the CA
    /// page's affordance, not a route remedy).
    /// Open iff trusted and no change is in flight: PR D's `installing` outranks `trusted` (D3's table row
    /// order, and its `step.done`), so an uninstall in flight reads "trusting CA…", not done.
    private static func caTrustRoute(_ facts: CATrustFacts) -> TrafficRoute {
        let open = facts.trusted && !facts.installing
        return TrafficRoute(kind: .caTrust, open: open, state: facts.text,
                            detail: open ? caTrustedDetail : CATrustFacts.notTrustedLine,
                            actions: open ? [] : facts.actions)
    }

    // MARK: Steps (spec D4)

    /// `allApps` is the route table's All Apps entry whether or not `routes` shows it (external core); its words
    /// and detail are the step's. `advice` picks the step's action, which differs from the route's button.
    private static func steps(core: ConnectionLane, bus: ConnectionLane, activeKind: ActiveCoreKind, advice: CaptureAdvice,
                              allApps: TrafficRoute?, routes: TrafficRoutes, caTrust: CATrustFacts?, flowCount: Int,
                              listenAddress: String) -> [GettingStartedStep] {
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
        // Omitted while the system proxy is unknown: a step that cannot name its state would be a lie. A closed row
        // offers the route's first button (Set as System Proxy when the verb says it may); a done row offers nothing.
        if let systemProxy = routes.systemProxy {
            steps.append(GettingStartedStep(kind: .systemProxy, title: systemProxy.line, done: systemProxy.open,
                                            action: systemProxy.open ? nil : systemProxy.actions.first, detail: systemProxy.detail))
        }
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
        // Omitted while the CA fact is unknown (D4): a step that cannot name its fix is noise. The title and action
        // are PR D's `step` — "Trust the aitmproxy CA" / `.trustCA` for the plain not-trusted fact, `.openCAPanel`
        // when an administrator is needed, PR D's `text` and nothing to press while a change is in flight.
        if let caTrust, let route = routes.caTrust {
            let step = caTrust.step
            steps.append(GettingStartedStep(kind: .caTrusted, title: step.title, done: route.open,
                                            action: route.open ? nil : step.action, detail: route.detail))
        }
        steps.append(firstFlowStep(flowCount: flowCount, systemProxy: routes.systemProxy, listenAddress: listenAddress))
        return steps
    }

    /// The last row (§D13 "Getting started"): the count once there are rows. Before that the system-proxy route picks
    /// the words — the Set button when the route is closed and offers it, "waiting for the first flow" when the route
    /// is open, else the plain pointer (no route, unsupported, an administrator wait, a change in flight).
    private static func firstFlowStep(flowCount: Int, systemProxy: TrafficRoute?, listenAddress: String) -> GettingStartedStep {
        if flowCount > 0 {
            return GettingStartedStep(kind: .firstFlow, title: "\(Format.count(flowCount, "flow")) captured", done: true)
        }
        if let systemProxy, !systemProxy.open, systemProxy.actions.contains(.setSystemProxy) {
            return GettingStartedStep(kind: .firstFlow, title: "Set aitmproxy as the system proxy, or open the browser",
                                      done: false, action: .setSystemProxy)
        }
        if let systemProxy, systemProxy.open {
            return GettingStartedStep(kind: .firstFlow, title: "System proxy points at \(listenAddress) — waiting for the first flow",
                                      done: false, action: .openBrowser)
        }
        return GettingStartedStep(kind: .firstFlow, title: "Point a client at \(listenAddress), or open the browser",
                                  done: false, action: .openBrowser)
    }
}
