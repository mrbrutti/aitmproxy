import AitmproxyKit
import AppKit
import Foundation

/// The connection lanes (core, bus, capture) as one value, and the one place a
/// `ConnectionAction` turns into the same call its menu-bar item makes. Every connection
/// indicator — the Status page, the toolbar's connection cluster, the Core Log header, the
/// Settings rows — reads `connectionSummary`, so their words come from one table and never
/// disagree. The sidebar and the status bar carry no connection state at all (spec §4).
extension Session {
    /// Whether the embedded core is the active kind (embedded when nothing says otherwise): the
    /// one accessor for the toolbar, the summary and anyone else asking.
    var embeddedCoreActive: Bool { (connection?.activeKind ?? .embedded) == .embedded }

    var connectionSummary: ConnectionSummary {
        ConnectionSummary.make(
            core: coreHealth.connection,
            activeKind: connection?.activeKind ?? .embedded,
            bus: bus,
            role: resolvedRole,
            roleWarning: roleWarning,
            capability: coreHealth.captureCapability,
            captureSupported: coreHealth.captureSupported,
            scopeHostCount: scopeHosts.count,
            flowCount: rows.count,
            listenAddress: coreHealth.connection?.proxyAddress ?? listenAddress
        )
    }

    /// Runs a navigation or copy action from a lane card or a Getting-started row. The
    /// operator-only actions — the core restart, the capture switch, the extension uninstall and
    /// the Settings openers — are handled by the view (`StatusPanel`), which is one of the few
    /// surfaces the capture tripwire allows to reach them; `perform` returns `false` for those so
    /// the caller knows to take them.
    @discardableResult
    func perform(connection action: ConnectionAction) -> Bool {
        switch action {
        case .startCore, .restartCore:
            return false
        case .showCoreLog:
            coreLogVisible = true
        case .reconnectBus:
            reconnectBus()
        case .openScope:
            show(.scope)
        case .addScopeHost:
            show(.scope)
            scopeSheetVisible = true
        case .openCAPanel:
            show(.ca)
        case .trustCA:
            // Operator-only, like the capture switch: the view performs the trust action itself.
            return false
        case .openBrowser:
            show(.browser)
        case .copyListenAddress:
            Pasteboard.copy(coreHealth.connection?.proxyAddress ?? listenAddress)
        case .approveInSystemSettings:
            // General ▸ Login Items & Extensions, where macOS lists Network Extensions to approve.
            if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
                NSWorkspace.shared.open(url)
            }
        case .switchToEmbedded, .openBusSettings, .openCaptureSettings, .turnCaptureOn, .turnCaptureOff, .uninstallExtension:
            return false
        }
        return true
    }
}
