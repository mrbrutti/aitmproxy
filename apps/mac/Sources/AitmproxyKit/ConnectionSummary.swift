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

/// How well one lane of the connection is doing. Ordered worst-last so the sidebar's
/// Status row and the toolbar pill can show the worst lane.
public enum LaneState: Int, Comparable, Sendable {
    case ok, working, off, warning, error

    public static func < (a: LaneState, b: LaneState) -> Bool { a.rawValue < b.rawValue }
}

/// One thing a surface may offer to change a lane. The view maps each to the same call
/// its menu-bar item makes; the model only names it.
public enum ConnectionAction: Hashable, Sendable {
    case startCore, restartCore, showCoreLog, switchToEmbedded
    case reconnectBus, openBusSettings
    case turnCaptureOn, turnCaptureOff, openScope, approveInSystemSettings, uninstallExtension, openCaptureSettings
    case openBrowser, copyListenAddress

    /// The button title (title case; an ellipsis where another view opens).
    public var title: String {
        switch self {
        case .startCore: "Start Core"
        case .restartCore: "Restart Core"
        case .showCoreLog: "Core Log…"
        case .switchToEmbedded: "Switch to Embedded…"
        case .reconnectBus: "Reconnect"
        case .openBusSettings: "Bus Settings…"
        case .turnCaptureOn: "Turn On Capture"
        case .turnCaptureOff: "Turn Off Capture"
        case .openScope: "Open Scope…"
        case .approveInSystemSettings: "Open System Settings…"
        case .uninstallExtension: "Uninstall Capture Extension…"
        case .openCaptureSettings: "Capture Settings…"
        case .openBrowser: "Open Browser"
        case .copyListenAddress: "Copy Address"
        }
    }

    /// Actions that remove something; the view styles them as such and confirms.
    public var isDestructive: Bool { self == .uninstallExtension }
}

/// One of the three lanes the operator must understand: the core (the proxy process), the
/// bus (the app's link to it) and the capture extension (system-wide capture). Every word
/// a connection indicator shows comes from here, so the toolbar pill, the status bar, the
/// sidebar row, the Status page and the Settings rows can never disagree.
public struct ConnectionLane: Hashable, Sendable {
    public enum Kind: String, Hashable, Sendable, CaseIterable {
        case core, bus, capture

        /// The lane's section label.
        public var title: String {
            switch self {
            case .core: "Core"
            case .bus: "Bus"
            case .capture: "Capture"
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
    /// "failed" → "core: failed". For the one-item surfaces (status bar).
    public var compact: String {
        word.hasPrefix(kind.title.lowercased()) ? word : "\(kind.title.lowercased()): \(word)"
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
    public enum Kind: String, Hashable, Sendable, CaseIterable {
        case coreRunning, busConnected, extensionOn, scopeSet, firstFlow
    }

    public let kind: Kind
    public let title: String
    public let done: Bool
    public let action: ConnectionAction?

    public init(kind: Kind, title: String, done: Bool, action: ConnectionAction? = nil) {
        self.kind = kind
        self.title = title
        self.done = done
        self.action = action
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
    /// The proxy address clients point at; the last step quotes it.
    public let listenAddress: String

    public var lanes: [ConnectionLane] { [core, bus, capture] }

    /// The worst lane state: what the sidebar's Status row glyph and the pill's dot show.
    public var overall: LaneState { lanes.map(\.state).max() ?? .ok }

    /// The worst lane, for the compact surfaces that show one word.
    public var worst: ConnectionLane { lanes.max { $0.state < $1.state } ?? core }

    public var allStepsDone: Bool { steps.allSatisfy(\.done) }

    /// The status bar's one connection word: "connected" while every lane is fine, else the
    /// worst lane's compact form ("capture off", "core: failed").
    public var overallWord: String { overall == .ok ? "connected" : worst.compact }

    /// The sidebar badge beside the brand: "ok", or the lane that needs attention ("Capture").
    public var badge: String { overall == .ok ? "ok" : worst.kind.title }

    /// The three lanes in one line, for tooltips: "Core: running — Embedded · proxy …\nBus: …".
    public var tooltip: String {
        lanes.map { "\($0.kind.title): \($0.word) — \($0.detail)" }.joined(separator: "\n")
    }

    /// The three lanes as one spoken sentence, for accessibility labels.
    public var spoken: String {
        "core \(core.word), bus \(bus.word), capture \(capture.word)"
    }

    /// The hint for a Scope entry while the provider still claims a bare host's DNS lookup:
    /// a port-qualified entry claims only the TCP flow. Removed with the provider fix.
    public static let scopeEntryHint = "example.com:443"

    // MARK: Make

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
        coreCapture: CoreCaptureStatus? = nil
    ) -> ConnectionSummary {
        let core = coreLane(connection, activeKind: activeKind, bus: bus)
        let busLane = self.busLane(bus, role: role, roleWarning: roleWarning, activeKind: activeKind, core: connection)
        let advice = CaptureAdvice.make(capability: capability, supported: captureSupported, scopeHostCount: scopeHostCount)
        let capture = captureLane(advice, capability: capability, activeKind: activeKind,
                                  scopeHostCount: scopeHostCount, coreCapture: coreCapture)
        let steps = self.steps(core: core, bus: busLane, activeKind: activeKind, advice: advice,
                               scopeHostCount: scopeHostCount, flowCount: flowCount, listenAddress: listenAddress)
        return ConnectionSummary(core: core, bus: busLane, capture: capture, steps: steps, listenAddress: listenAddress)
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
            return ConnectionLane(kind: .capture, state: .off, word: "capture off",
                                  detail: "The external core does not run the capture extension",
                                  remedy: "Switch to the embedded core to capture other apps' traffic",
                                  actions: [.switchToEmbedded])
        }
        switch advice {
        case .unsupported:
            return ConnectionLane(kind: .capture, state: .off, word: "no extension",
                                  detail: "This build has no capture extension",
                                  remedy: "Install the signed Aitmproxy app; its capture extension is built in",
                                  actions: [])
        case .off:
            let installed = capability.isInstalledOrInstalling
            return ConnectionLane(kind: .capture, state: .off, word: "capture off",
                                  detail: installed ? "extension installed · \(hosts)" : "extension not installed",
                                  remedy: installed ? "Turn on capture to see other apps' traffic"
                                                    : "Turn on capture; macOS asks you to approve the extension",
                                  actions: installed ? [.turnCaptureOn, .uninstallExtension, .openCaptureSettings]
                                                     : [.turnCaptureOn, .openCaptureSettings])
        case .awaitingApproval:
            return ConnectionLane(kind: .capture, state: .working, word: "waiting for approval",
                                  detail: "extension installed · approval pending",
                                  remedy: "Approve the extension in System Settings ▸ Network Extensions, then allow Add Proxy Configurations",
                                  actions: [.approveInSystemSettings, .turnCaptureOff])
        case .degraded(let reason):
            let unnotarized = reason.localizedCaseInsensitiveContains("signature")
            return ConnectionLane(kind: .capture, state: .error, word: "capture degraded", detail: reason,
                                  remedy: unnotarized
                                      ? "macOS refused this build's extension; install the signed Aitmproxy app"
                                      : "Turn capture off and on again; if it stays degraded, uninstall and reinstall the extension",
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
                                  word: attached ? "capture on · \(hosts)" : "on, core not attached",
                                  detail: detail,
                                  remedy: attached ? nil : "Restart the core so the extension can attach to it",
                                  actions: attached ? [.turnCaptureOff, .openScope, .uninstallExtension]
                                                    : [.restartCore, .turnCaptureOff])
        }
    }

    // MARK: Steps

    private static func steps(core: ConnectionLane, bus: ConnectionLane, activeKind: ActiveCoreKind, advice: CaptureAdvice,
                              scopeHostCount: Int, flowCount: Int, listenAddress: String) -> [GettingStartedStep] {
        // An external core is the operator's; it counts as running once the bus reaches it.
        let coreDone = core.state == .ok || (activeKind == .external && bus.state == .ok)
        let busDone = bus.state == .ok
        let extensionDone: Bool
        let extensionTitle: String
        let extensionAction: ConnectionAction?
        switch advice {
        case .on, .onEmptyScope:
            extensionDone = true; extensionTitle = "Capture extension is on"; extensionAction = nil
        case .unsupported:
            extensionDone = false; extensionTitle = "Capture extension is not in this build"; extensionAction = nil
        case .awaitingApproval:
            extensionDone = false; extensionTitle = "Approve the capture extension in System Settings"; extensionAction = .approveInSystemSettings
        case .degraded:
            extensionDone = false; extensionTitle = "Fix the capture extension"; extensionAction = .openCaptureSettings
        case .off:
            extensionDone = false; extensionTitle = "Turn on the capture extension"; extensionAction = .turnCaptureOn
        }
        let scopeDone = scopeHostCount > 0
        let hosts = Format.count(scopeHostCount, "host")
        return [
            GettingStartedStep(kind: .coreRunning,
                               title: coreDone ? "Core is running" : "Start the core",
                               done: coreDone, action: coreDone ? nil : core.actions.first),
            GettingStartedStep(kind: .busConnected,
                               title: busDone ? "Bus connected" : "Connect to the bus",
                               done: busDone, action: busDone ? nil : bus.actions.first),
            GettingStartedStep(kind: .extensionOn, title: extensionTitle, done: extensionDone, action: extensionAction),
            GettingStartedStep(kind: .scopeSet,
                               title: scopeDone ? "Scope has \(hosts)" : "Add a host to Scope (for now as \(scopeEntryHint))",
                               done: scopeDone, action: scopeDone ? nil : .openScope),
            GettingStartedStep(kind: .firstFlow,
                               title: flowCount > 0 ? "\(Format.count(flowCount, "flow")) captured"
                                                    : "Point a client at \(listenAddress), or open the browser",
                               done: flowCount > 0, action: flowCount > 0 ? nil : .openBrowser),
        ]
    }
}
