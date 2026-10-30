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
///                            manager is then reconciled, saved, loaded and started)
///       → capturing         (the tunnel reaches `.connected`)
///     degraded(reason)      (activation failed, restart needed, or the tunnel failed)
///     extensionNotInstalled (uninstall(): deactivated, configuration removed)
///
/// **Inert unless the extension is embedded.** A development build has no
/// `Contents/Library/SystemExtensions/com.mrbrutti.aitmproxy.ne.systemextension`
/// (`build.sh` embeds it only for a Developer ID NE build, Task 14), so `start()`
/// reports `.extensionNotInstalled` and returns *without submitting any request*
/// and without any system prompt. It is likewise a no-op in fixture, snapshot and
/// self-test runs.
///
/// **Operator-only (NE-AC11, NE-AC15).** Activating the extension is the *human
/// operator's* launch-time action. `start()` has exactly one call site, `ShellView`'s
/// launch task, i.e. the person opening the app. Uninstalling is likewise the
/// operator's: `uninstall()` has exactly one call site, the Uninstall button in
/// Settings. This type deliberately offers no bus or MCP verb, no `Session` action
/// and no command-palette entry, so an agent (`Frontend::Mcp`) has nothing to call.
/// Any future bus path to install, approve or remove the extension must pass the Rust
/// deny-by-default gate `allow_agent_sysex_install` (Task 7, off by default) before it
/// may reach this controller. Do not add one here. (`start()` publishes this controller
/// to `CoreHealthState.extensionController` so the Settings window, a separate scene, can
/// reach it to uninstall — still an operator-only call.)
///
/// There is no headless path: approval stays pending until a human completes the
/// prompts, and the app is kept from automatic/sudden termination meanwhile. Closing
/// the last window still quits the app (`applicationShouldTerminateAfterLastWindowClosed`);
/// the pending approval then resumes the next time the app launches and re-submits.
///
/// **Version bump and reconcile (Task 16, NE-AC14).** Every NE build stamps the
/// extension's `CFBundleVersion` with a timestamp (`build.sh` fills `__BUILD__`), so
/// the OS always sees a newer extension and asks `actionForReplacingExtension`, which
/// answers `.replace`. A replacement can leave the saved `NETransparentProxyManager`
/// configuration disabled (leash #58), so after every activation `bringUpTunnel`
/// reconciles it on the `TunnelReconcilePolicy` schedule: settle, re-enable and save,
/// start, confirm `.connected`, retry with backoff, else `.degraded`.
@MainActor
final class ExtensionController: NSObject {
    private let health: CoreHealthState
    private let bundleURL: URL
    private var started = false
    /// True once `start()` submitted the activation request, i.e. this controller is
    /// managing a real extension. Uninstalling is refused before that.
    private var managingExtension = false
    /// The OS activity assertion held while an activation or uninstall request is outstanding.
    private var pendingActivity: (any NSObjectProtocol)?
    private var tunnelObserver: (any NSObjectProtocol)?
    private var tunnelManager: NETransparentProxyManager?
    /// Set by `actionForReplacingExtension`; the next reconcile waits for the OS to settle.
    private var replacedExtension = false
    /// The running reconcile, so an uninstall can cancel it before it re-saves the configuration.
    private var reconcileTask: Task<Void, Never>?
    /// True from the start of `uninstall()` to its end; refuses a second concurrent uninstall.
    private var uninstalling = false
    /// Waiting for the deactivation request's result; non-nil only while one is outstanding,
    /// which is how the shared delegate tells its callbacks from the activation request's.
    private var deactivation: CheckedContinuation<DeactivationOutcome, Never>?

    private enum DeactivationOutcome {
        case removed
        case needsReboot
        case failed(String)
    }

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
        managingExtension = true
        health.extensionController = self
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

    private func beginKeepingAlive(
        reason: String = "Waiting for the capture extension to be approved in System Settings"
    ) {
        guard pendingActivity == nil else { return }
        pendingActivity = ProcessInfo.processInfo.beginActivity(
            options: [.userInitiatedAllowingIdleSystemSleep, .automaticTerminationDisabled, .suddenTerminationDisabled],
            reason: reason)
    }

    private func endKeepingAlive() {
        if let pendingActivity { ProcessInfo.processInfo.endActivity(pendingActivity) }
        pendingActivity = nil
    }

    // MARK: transparent-proxy tunnel

    private static func isOurs(_ manager: NETransparentProxyManager) -> Bool {
        (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
            == CaptureExtension.identifier
    }

    /// Whether a failed attempt can clear by itself, so retrying is worthwhile.
    /// `configurationDisabled` is the leash #58 symptom (the replacement left the saved
    /// configuration off), `configurationStale` and `configurationUnknown` mean "reload
    /// and try again", and `connectionFailed` is a provider that is not up yet. Anything
    /// else is permanent, notably `configurationReadWriteFailed`, which is what the
    /// operator refusing the "Add Proxy Configurations" prompt looks like: retrying would
    /// only show them the prompt again.
    private static func isTransient(_ error: any Error) -> Bool {
        guard let vpnError = error as? NEVPNError else { return false }
        switch vpnError.code {
        case .configurationDisabled, .configurationStale, .configurationUnknown, .connectionFailed: return true
        default: return false
        }
    }

    /// Reconciles the saved configuration for the now-active extension and confirms the
    /// tunnel connects (Task 16, NE-AC14), on the `TunnelReconcilePolicy.standard`
    /// schedule: wait for the OS to settle after a replacement, then up to
    /// `maxAttempts` of enable + save + start + connected-check, backing off between
    /// them. Gives up at once on a permanent failure, and reports `.degraded` when the
    /// attempts run out. Cancelled by `uninstall()`, which then owns the outcome.
    private func bringUpTunnel(afterReplacement: Bool) async {
        let policy = TunnelReconcilePolicy.standard
        var attempt = 1
        var failure = ""
        do {
            try await Task.sleep(for: policy.settleDelay(afterReplacement: afterReplacement))
            while true {
                let retryable: Bool
                do {
                    let manager = try await enableAndStartTunnel()
                    if try await waitUntilConnected(manager, policy: policy) { return }
                    failure = "the tunnel did not connect within \(policy.connectWindow.components.seconds) seconds"
                    retryable = true
                } catch let cancelled as CancellationError {
                    throw cancelled
                } catch {
                    failure = error.localizedDescription
                    retryable = Self.isTransient(error)
                }
                guard case .retry(let delay) = policy.decision(afterFailedAttempt: attempt, retryable: retryable) else {
                    break
                }
                try await Task.sleep(for: delay)
                attempt += 1
            }
        } catch {
            return  // cancelled by an uninstall: it reports the end state, not this loop
        }
        let tries = attempt > 1 ? " after \(attempt) attempts" : ""
        apply(.failed("Could not start the capture tunnel\(tries): \(failure)"))
    }

    /// One attempt: load the saved configuration (reusing an existing entry for this
    /// extension, so a relaunch never piles up duplicates in System Settings), make sure
    /// it is enabled, save it, reload it, and start the tunnel.
    private func enableAndStartTunnel() async throws -> NETransparentProxyManager {
        let existing = try await NETransparentProxyManager.loadAllFromPreferences()
        let manager = existing.first(where: Self.isOurs) ?? NETransparentProxyManager()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = CaptureExtension.identifier
        configuration.serverAddress = "localhost"
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "Aitmproxy"
        manager.isEnabled = true
        try await manager.saveToPreferences()
        // A saved configuration must be re-loaded before it can be started.
        try await manager.loadFromPreferences()
        // The OS can flip a just-replaced configuration back to disabled between the save
        // and the reload; treat that as the (retryable) failure it is.
        guard manager.isEnabled else { throw NEVPNError(.configurationDisabled) }
        observeTunnel(manager)
        switch manager.connection.status {
        case .connected, .connecting, .reasserting: break
        default: try manager.connection.startVPNTunnel()
        }
        return manager
    }

    /// The connected-check: samples the tunnel status until it reads `.connected` or the
    /// policy's window runs out. Throws only `CancellationError`.
    private func waitUntilConnected(_ manager: NETransparentProxyManager, policy: TunnelReconcilePolicy) async throws -> Bool {
        for _ in 0..<policy.pollCount {
            if manager.connection.status == .connected {
                applyTunnelStatus(.connected)
                return true
            }
            try await Task.sleep(for: policy.pollInterval)
        }
        guard manager.connection.status == .connected else { return false }
        applyTunnelStatus(.connected)
        return true
    }

    private func observeTunnel(_ manager: NETransparentProxyManager) {
        removeTunnelObserver()
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

    private func removeTunnelObserver() {
        if let tunnelObserver { NotificationCenter.default.removeObserver(tunnelObserver) }
        tunnelObserver = nil
    }

    private func applyTunnelStatus(_ status: NEVPNStatus) {
        switch status {
        case .connected: apply(.tunnelConnected)
        case .disconnected, .invalid: apply(.tunnelDisconnected)
        case .connecting, .reasserting, .disconnecting: break
        @unknown default: break
        }
    }

    // MARK: uninstall

    /// Uninstalls the capture extension (Task 17, NE-AC15): stops the reconcile, removes
    /// the saved `NETransparentProxyManager` configuration, then submits a deactivation
    /// request, and on completion reports `.extensionNotInstalled`. Returns when the
    /// whole flow has finished, so the Settings button can show it is working.
    ///
    /// Operator-only: the Settings Uninstall button is its one caller (see the type
    /// comment). A no-op unless this controller is managing a real extension that the
    /// capability says can be removed (`CaptureCapability.canUninstall`), and while an
    /// uninstall is already running.
    ///
    /// The configuration goes first: removing it stops the tunnel, and the deactivation
    /// is then not tearing down a provider that is mid-connection. The extension being
    /// already gone (`extensionNotFound`) counts as removed, so a leftover configuration
    /// from a failed earlier uninstall can be cleaned up by running this again.
    func uninstall() async {
        guard managingExtension, !uninstalling, health.captureCapability.canUninstall else { return }
        uninstalling = true
        beginKeepingAlive(reason: "Removing the capture extension")
        defer {
            endKeepingAlive()
            uninstalling = false
        }
        // Stop the reconcile and let it finish: a late save must not re-add the
        // configuration this is about to remove.
        reconcileTask?.cancel()
        await reconcileTask?.value
        reconcileTask = nil
        removeTunnelObserver()
        let configurationProblem = await removeSavedConfiguration()
        switch await deactivate() {
        case .removed:
            if let configurationProblem {
                apply(.failed("The capture extension was removed, but its proxy configuration could not be deleted: \(configurationProblem)"))
            } else {
                apply(.uninstalled)
            }
        case .needsReboot:
            apply(.failed("Restart your Mac to finish removing the capture extension."))
        case .failed(let reason):
            apply(.failed("Could not remove the capture extension: \(reason)"))
        }
    }

    /// Stops and removes this extension's saved configuration. The failure text, or `nil`
    /// when it is gone (including when there was none to remove).
    private func removeSavedConfiguration() async -> String? {
        do {
            for manager in try await NETransparentProxyManager.loadAllFromPreferences() where Self.isOurs(manager) {
                manager.connection.stopVPNTunnel()
                try await manager.removeFromPreferences()
            }
            tunnelManager = nil
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    /// Submits the deactivation request and waits for the shared delegate to report it.
    private func deactivate() async -> DeactivationOutcome {
        await withCheckedContinuation { continuation in
            deactivation = continuation
            let request = OSSystemExtensionRequest.deactivationRequest(
                forExtensionWithIdentifier: CaptureExtension.identifier, queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    /// Resolves the outstanding deactivation, if any. `true` when `outcome` was consumed
    /// by it, `false` when the callback belongs to the activation request.
    private func finishDeactivation(_ outcome: DeactivationOutcome) -> Bool {
        guard let deactivation else { return false }
        self.deactivation = nil
        deactivation.resume(returning: outcome)
        return true
    }

    isolated deinit {
        reconcileTask?.cancel()
        removeTunnelObserver()
        endKeepingAlive()
    }
}

// The system delivers these on the queue the request was created with (`.main`),
// so each one hops onto the main actor synchronously. They are shared by the
// activation request and the deactivation request; `deactivation` tells them apart.
extension ExtensionController: OSSystemExtensionRequestDelegate {
    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension replacement: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        // Every NE build carries a newer timestamped CFBundleVersion, so replacing is
        // always right. The saved configuration is reconciled once activation completes.
        MainActor.assumeIsolated { replacedExtension = true }
        return .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        MainActor.assumeIsolated {
            // A removal that needs the operator shows the system's own prompt; it must
            // not read as the extension awaiting (re)approval.
            guard deactivation == nil else { return }
            apply(.needsUserApproval)
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        MainActor.assumeIsolated {
            switch result {
            case .completed:
                if finishDeactivation(.removed) { return }
                endKeepingAlive()
                apply(.activated)
                let afterReplacement = replacedExtension
                replacedExtension = false
                reconcileTask?.cancel()
                reconcileTask = Task { await bringUpTunnel(afterReplacement: afterReplacement) }
            case .willCompleteAfterReboot:
                if finishDeactivation(.needsReboot) { return }
                endKeepingAlive()
                apply(.willCompleteAfterReboot)
            @unknown default:
                if finishDeactivation(.failed("The system returned an unexpected result.")) { return }
                endKeepingAlive()
                apply(.failed("The capture extension returned an unexpected activation result."))
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: any Error) {
        let alreadyGone = (error as? OSSystemExtensionError)?.code == .extensionNotFound
        let detail = error.localizedDescription
        MainActor.assumeIsolated {
            if finishDeactivation(alreadyGone ? .removed : .failed(detail)) { return }
            endKeepingAlive()
            apply(.failed("Extension activation failed: \(detail)"))
        }
    }
}
