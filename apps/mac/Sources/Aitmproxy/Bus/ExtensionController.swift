import AitmproxyKit
import Foundation
import NetworkExtension
import SystemExtensions

/// Owns the macOS capture extension's activation lifecycle in the host app
/// (Task 13, spec D8/D9, NE-AC9/NE-AC10/NE-AC11) and pushes the resulting
/// `CaptureCapability` into `CoreHealthState`, where the status surfaces read it.
///
/// Lifecycle, driven by system callbacks and mapped by the pure
/// `CaptureCapability.applying(_:)` (tested in `AitmproxyKitTests`):
///
///     extensionNotInstalled
///       → pendingApproval   (requestNeedsUserApproval: the two System Settings prompts)
///       → approvedAttached  (didFinishWithResult .completed; the transparent-proxy
///                            manager is then saved, loaded and started)
///       → capturing         (the tunnel reaches `.connected`)
///     degraded(reason)      (activation failed, restart needed, or the tunnel failed)
///
/// **Inert unless the extension is embedded.** A development build has no
/// `Contents/Library/SystemExtensions/com.mrbrutti.aitmproxy.ne.systemextension`
/// (`build.sh` embeds it only for a Developer ID NE build, Task 14), so `start()`
/// reports `.extensionNotInstalled` and returns *without submitting any request*
/// and without any system prompt. It is likewise a no-op in fixture, snapshot and
/// self-test runs.
///
/// **Operator-only (NE-AC11).** Activating the extension is the *human operator's*
/// launch-time action. `start()` has exactly one call site, `ShellView`'s launch
/// task, i.e. the person opening the app. This type deliberately offers no bus or
/// MCP verb, no `Session` action and no command-palette entry, so an agent
/// (`Frontend::Mcp`) has nothing to call. Any future bus path to install or approve
/// the extension must pass the Rust deny-by-default gate `allow_agent_sysex_install`
/// (Task 7, off by default) before it may reach this controller. Do not add one here.
///
/// There is no headless path: approval stays pending until a human completes the
/// prompts, and the app is kept from automatic/sudden termination meanwhile. Closing
/// the last window still quits the app (`applicationShouldTerminateAfterLastWindowClosed`);
/// the pending approval then resumes the next time the app launches and re-submits.
/// Uninstall is Task 17, and version-bump reconciliation is Task 16; neither lives here.
@MainActor
final class ExtensionController: NSObject {
    private let health: CoreHealthState
    private let bundleURL: URL
    private var started = false
    /// The OS activity assertion held while an activation request is outstanding.
    private var pendingActivity: (any NSObjectProtocol)?
    private var tunnelObserver: (any NSObjectProtocol)?
    private var tunnelManager: NETransparentProxyManager?

    /// `bundleURL` is the app bundle to inspect for the embedded extension; the
    /// running app by default.
    init(health: CoreHealthState, bundleURL: URL = Bundle.main.bundleURL) {
        self.health = health
        self.bundleURL = bundleURL
        super.init()
    }

    /// Submits the activation request when, and only when, this is a real launch of
    /// a build that embeds the extension. Idempotent.
    func start() {
        guard !started else { return }
        started = true
        // Never fire in fixture, snapshot or self-test runs. `APP_LIVE=1` can make a
        // snapshot run non-fixture, so the snapshot env var is checked directly too.
        guard !Store.usesFixtures, !SelfTest.requested,
              ProcessInfo.processInfo.environment["APP_SNAPSHOT"] == nil
        else { return }
        // The dev app has no embedded extension: report that and stay inert.
        guard CaptureExtension.isEmbedded(inApp: bundleURL) else {
            health.captureCapability = .extensionNotInstalled
            return
        }
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: CaptureExtension.identifier, queue: .main)
        request.delegate = self
        beginKeepingAlive()
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: capability

    private func apply(_ event: CaptureCapabilityEvent) {
        health.captureCapability = health.captureCapability.applying(event)
    }

    // MARK: keep the app alive while approval is pending

    private func beginKeepingAlive() {
        guard pendingActivity == nil else { return }
        pendingActivity = ProcessInfo.processInfo.beginActivity(
            options: [.userInitiatedAllowingIdleSystemSleep, .automaticTerminationDisabled, .suddenTerminationDisabled],
            reason: "Waiting for the capture extension to be approved in System Settings")
    }

    private func endKeepingAlive() {
        if let pendingActivity { ProcessInfo.processInfo.endActivity(pendingActivity) }
        pendingActivity = nil
    }

    // MARK: transparent-proxy tunnel

    /// Saves, loads and starts the `NETransparentProxyManager` for the now-active
    /// extension. An existing configuration for this extension is reused, so a
    /// relaunch never piles up duplicate entries in System Settings.
    private func bringUpTunnel() async {
        do {
            let existing = try await NETransparentProxyManager.loadAllFromPreferences()
            let manager = existing.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == CaptureExtension.identifier
            } ?? NETransparentProxyManager()
            let configuration = NETunnelProviderProtocol()
            configuration.providerBundleIdentifier = CaptureExtension.identifier
            configuration.serverAddress = "localhost"
            manager.protocolConfiguration = configuration
            manager.localizedDescription = "Aitmproxy"
            manager.isEnabled = true
            try await manager.saveToPreferences()
            // A saved configuration must be re-loaded before it can be started.
            try await manager.loadFromPreferences()
            observeTunnel(manager)
            try manager.connection.startVPNTunnel()
            // Usually `.connecting` here, which is a no-op; this only catches a REUSED
            // manager already `.connected` before the observer was wired. The normal
            // `.connected` transition arrives through `observeTunnel`.
            applyTunnelStatus(manager.connection.status)
        } catch {
            apply(.failed("Could not start the capture tunnel: \(error.localizedDescription)"))
        }
    }

    private func observeTunnel(_ manager: NETransparentProxyManager) {
        if let tunnelObserver { NotificationCenter.default.removeObserver(tunnelObserver) }
        // Held here (main-actor state) so the observer reads it through `self` and
        // never captures the non-Sendable manager itself.
        tunnelManager = manager
        tunnelObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: manager.connection, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let status = self.tunnelManager?.connection.status else { return }
                self.applyTunnelStatus(status)
            }
        }
    }

    private func applyTunnelStatus(_ status: NEVPNStatus) {
        switch status {
        case .connected: apply(.tunnelConnected)
        case .disconnected, .invalid: apply(.tunnelDisconnected)
        case .connecting, .reasserting, .disconnecting: break
        @unknown default: break
        }
    }

    isolated deinit {
        if let tunnelObserver { NotificationCenter.default.removeObserver(tunnelObserver) }
        endKeepingAlive()
    }
}

// The system delivers these on the queue the request was created with (`.main`),
// so each one hops onto the main actor synchronously.
extension ExtensionController: OSSystemExtensionRequestDelegate {
    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension replacement: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        // Version-bump reconciliation is Task 16; replacing is correct until then.
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        MainActor.assumeIsolated { apply(.needsUserApproval) }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        MainActor.assumeIsolated {
            endKeepingAlive()
            switch result {
            case .completed:
                apply(.activated)
                Task { await bringUpTunnel() }
            case .willCompleteAfterReboot:
                apply(.willCompleteAfterReboot)
            @unknown default:
                apply(.failed("The capture extension returned an unexpected activation result."))
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: any Error) {
        let reason = "Extension activation failed: \(error.localizedDescription)"
        MainActor.assumeIsolated {
            endKeepingAlive()
            apply(.failed(reason))
        }
    }
}
