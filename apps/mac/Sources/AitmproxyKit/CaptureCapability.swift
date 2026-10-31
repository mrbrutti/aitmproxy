import Foundation

/// What the host app knows about the macOS capture extension (Task 13, spec D9):
/// the operator-facing capture capability that sits beside core health. It walks
/// `extensionNotInstalled → pendingApproval → approvedAttached → capturing`, or
/// lands in `degraded(reason)` when something goes wrong, so the UI never has to
/// guess why capture is not live. `inactive` is the honest resting state once the
/// operator turns capture off: the extension stays installed, nothing is captured.
///
/// This is the *app's* view (system-extension activation plus the transparent-proxy
/// tunnel). It mirrors the Rust core's `CaptureCapability`, which the core derives
/// from its own control channel.
public enum CaptureCapability: Hashable, Sendable {
    /// No system extension is installed, or none is embedded in this build.
    case extensionNotInstalled
    /// Activation was requested; the operator has not finished the two System
    /// Settings prompts (Network Extensions approve + Add Proxy Configurations).
    case pendingApproval
    /// The extension is approved and active; the capture tunnel is not yet up.
    case approvedAttached
    /// The extension is approved and the capture tunnel is connected.
    case capturing
    /// Something went wrong; the reason is the text to show the operator.
    case degraded(String)
    /// The extension is installed (and approved), but the operator turned capture
    /// off: no tunnel, nothing captured, full uninstall still on offer.
    case inactive

    /// The operator-facing word for the capability.
    public var title: String {
        switch self {
        case .extensionNotInstalled: "Extension not installed"
        case .pendingApproval: "Awaiting approval"
        case .approvedAttached: "Approved"
        case .capturing: "Capturing"
        case .degraded: "Degraded"
        case .inactive: "Off"
        }
    }

    /// The failure reason when `.degraded`, `nil` otherwise.
    public var degradedReason: String? {
        if case .degraded(let reason) = self { return reason }
        return nil
    }
}

/// One thing the host app observed while activating the extension and bringing the
/// capture tunnel up. Fed to `CaptureCapability.applying(_:)`.
public enum CaptureCapabilityEvent: Hashable, Sendable {
    /// The system asked the operator to approve the extension.
    case needsUserApproval
    /// The system finished activating the extension (approved, or already was).
    case activated
    /// Activation will finish only after a restart.
    case willCompleteAfterReboot
    /// Activation or the tunnel setup failed; carries the operator-facing reason.
    case failed(String)
    /// The capture tunnel reached the connected state.
    case tunnelConnected
    /// The capture tunnel left the connected state.
    case tunnelDisconnected
    /// The operator uninstalled the extension: it is deactivated and its proxy
    /// configuration is gone (Task 17).
    case uninstalled
    /// The operator turned capture off: the tunnel is stopped, the extension stays
    /// installed.
    case disabled
}

extension CaptureCapability {
    /// The capability after `event`. Pure, so the framework-facing controller stays
    /// thin glue. Tunnel events are ADVISORY — a late one never overrides a pending
    /// approval or a degradation. Activation events (`needsUserApproval`, `activated`,
    /// `willCompleteAfterReboot`, `failed`), `uninstalled` and `disabled` are
    /// AUTHORITATIVE and intentionally reset even from `.capturing`: a genuine
    /// re-approval, re-activation, removal or switch-off really did change the
    /// extension's state, so the capability must follow it rather than cling to
    /// capturing.
    public func applying(_ event: CaptureCapabilityEvent) -> CaptureCapability {
        switch event {
        case .needsUserApproval:
            return .pendingApproval
        case .activated:
            return .approvedAttached
        case .willCompleteAfterReboot:
            return .degraded("Restart your Mac to finish enabling the capture extension.")
        case .failed(let reason):
            return .degraded(reason)
        case .tunnelConnected:
            return self == .approvedAttached ? .capturing : self
        case .tunnelDisconnected:
            return self == .capturing ? .approvedAttached : self
        case .uninstalled:
            return .extensionNotInstalled
        case .disabled:
            return .inactive
        }
    }

    /// Whether the operator-facing "capture is on" indicator reads on (Task 17,
    /// NE-AC15): the extension is approved and attached, whether or not the tunnel
    /// has finished connecting.
    public var isCaptureOn: Bool {
        self == .approvedAttached || self == .capturing
    }

    /// Whether there is an extension to report on at all. `false` for a build with no
    /// embedded extension, before the first activation and after an uninstall. It is one
    /// input to whether the capture controls are live: a capture-capable build shows them
    /// (the toggle, to turn capture on) even while this is `false`.
    public var isInstalledOrInstalling: Bool {
        self != .extensionNotInstalled
    }

    /// Whether an uninstall is offered. Once the extension is approved (including while
    /// capture is switched off), and also from `.degraded` so a failed install can be
    /// cleaned up; not while approval is still outstanding (nothing is installed yet) or
    /// when there is nothing to remove.
    public var canUninstall: Bool {
        switch self {
        case .approvedAttached, .capturing, .degraded, .inactive: true
        case .extensionNotInstalled, .pendingApproval: false
        }
    }
}

/// How the host app reconciles the saved `NETransparentProxyManager` configuration
/// after the extension is (re)activated (Task 16, NE-AC14). A version-bump replacement
/// can leave the saved configuration disabled (leash #58), so the app waits for the
/// system to settle, re-enables and saves the configuration, then checks the tunnel
/// really reaches `connected`, retrying with a bounded exponential backoff.
///
/// Pure data and arithmetic so the schedule is unit-tested; the framework calls live in
/// `ExtensionController`.
public struct TunnelReconcilePolicy: Equatable, Sendable {
    /// How long to wait after a replacement before touching the configuration: the OS
    /// is still swapping the extension and may disable the configuration afterwards.
    public var settleAfterReplacement: Duration
    /// Total attempts (enable, save, start, connected-check), including the first.
    public var maxAttempts: Int
    /// How long one attempt waits for the tunnel to reach `connected`.
    public var connectWindow: Duration
    /// How often the connected-check samples the tunnel status inside the window.
    public var pollInterval: Duration
    /// The wait after the first failed attempt; it doubles per failure.
    public var firstBackoff: Duration
    /// The ceiling for the doubling backoff.
    public var maxBackoff: Duration

    /// The shipped schedule. Worst case before reporting `.degraded` (replacement, four
    /// attempts each waiting out the window, backoffs 1 + 2 + 4 s) is about 33 seconds.
    public static let standard = TunnelReconcilePolicy(
        settleAfterReplacement: .seconds(2),
        maxAttempts: 4,
        connectWindow: .seconds(6),
        pollInterval: .milliseconds(500),
        firstBackoff: .seconds(1),
        maxBackoff: .seconds(8))

    /// What to do after an attempt failed.
    public enum Decision: Equatable, Sendable {
        case retry(after: Duration)
        case giveUp
    }

    /// The settle wait before the first attempt: only a replaced extension needs one.
    public func settleDelay(afterReplacement: Bool) -> Duration {
        afterReplacement ? settleAfterReplacement : .zero
    }

    /// The wait after failed attempt number `attempt` (1-based): `firstBackoff`
    /// doubling per failure, never above `maxBackoff`.
    public func backoff(afterAttempt attempt: Int) -> Duration {
        var delay = firstBackoff
        var remaining = attempt - 1
        while remaining > 0, delay < maxBackoff {
            delay = min(delay * 2, maxBackoff)
            remaining -= 1
        }
        return delay
    }

    /// How many status samples fit in one `connectWindow`.
    public var pollCount: Int {
        max(1, Int(connectWindow / pollInterval))
    }

    /// Retry only a failure that can clear by itself (`retryable`) and only while
    /// attempts remain. A permanent failure, such as the operator refusing the
    /// "Add Proxy Configurations" prompt, gives up at once rather than re-prompting.
    public func decision(afterFailedAttempt attempt: Int, retryable: Bool) -> Decision {
        guard retryable, attempt < maxAttempts else { return .giveUp }
        return .retry(after: backoff(afterAttempt: attempt))
    }
}

/// How the reconcile classifies a failed attempt (Task 16, NE-AC14). Pure, so the
/// retry policy is unit-tested without NetworkExtension; `ExtensionController` maps each
/// `NEVPNError.code` onto a case with a compiler-checked exhaustive switch, and the exact
/// code-to-case mapping is verified live at Task 18.
public enum TunnelFailure: Sendable {
    /// The leash #58 symptom: a replacement left the saved configuration disabled.
    case configurationDisabled
    /// The configuration is stale — reload and try again.
    case configurationStale
    /// The configuration state is unknown — reload and try again.
    case configurationUnknown
    /// The provider is not up yet.
    case connectionFailed
    /// Permanent, notably the operator refusing the "Add Proxy Configurations" prompt:
    /// retrying would only re-show it.
    case permanent

    /// Whether this failure can clear by itself, so retrying is worthwhile.
    public var isTransient: Bool {
        switch self {
        case .configurationDisabled, .configurationStale, .configurationUnknown, .connectionFailed: true
        case .permanent: false
        }
    }
}

/// Where the capture system extension lives in the app bundle, and whether this
/// build carries it. `build.sh` embeds it only for a Developer ID NE build (Task
/// 14); a development build has none, and the host app stays inert there.
public enum CaptureExtension {
    /// The extension's bundle identifier, also the `NETransparentProxyManager`
    /// provider bundle identifier and the `OSSystemExtensionRequest` identifier.
    public static let identifier = "com.mrbrutti.aitmproxy.ne"

    /// `<app>/Contents/Library/SystemExtensions/<identifier>.systemextension`, the
    /// only place macOS looks for an app's embedded system extensions.
    public static func embeddedBundleURL(inApp appURL: URL) -> URL {
        appURL
            .appending(path: "Contents", directoryHint: .isDirectory)
            .appending(path: "Library", directoryHint: .isDirectory)
            .appending(path: "SystemExtensions", directoryHint: .isDirectory)
            .appending(path: "\(identifier).systemextension", directoryHint: .isDirectory)
    }

    /// Whether `appURL` embeds the extension bundle (a directory, not a stray file).
    public static func isEmbedded(inApp appURL: URL, fileManager: FileManager = .default) -> Bool {
        var isDirectory: ObjCBool = false
        let exists = fileManager.fileExists(
            atPath: embeddedBundleURL(inApp: appURL).path, isDirectory: &isDirectory)
        return exists && isDirectory.boolValue
    }
}
