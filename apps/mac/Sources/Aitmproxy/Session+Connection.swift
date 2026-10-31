import AitmproxyKit
import AppKit
import Foundation

/// The connection lanes (core, bus, capture) as one value, and the one place a
/// `ConnectionAction` turns into the same call its menu-bar item makes. Every connection
/// indicator — the Status page, the toolbar pill, the status bar, the sidebar row — reads
/// `connectionSummary`, so their words come from one table and never disagree.
extension Session {
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

    /// Runs an action from a lane card or a Getting-started row. Settings-opening actions and
    /// the capture switch are handled by the view (`StatusPanel`): they need `openSettings` from
    /// the environment and `CaptureSwitch`'s operator-only steps; `perform` returns `false` for
    /// those so the caller knows to take them.
    @discardableResult
    func perform(connection action: ConnectionAction) -> Bool {
        switch action {
        case .startCore, .restartCore:
            restartCoreTick += 1
        case .stopCore:
            return false
        case .showCoreLog:
            coreLogVisible = true
        case .reconnectBus:
            reconnectBus()
        case .openScope:
            show(.scope)
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
