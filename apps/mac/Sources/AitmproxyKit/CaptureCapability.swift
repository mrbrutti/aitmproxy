import Foundation

/// What the host app knows about the macOS capture extension (Task 13, spec D9):
/// the operator-facing capture capability that sits beside core health. It walks
/// `extensionNotInstalled → pendingApproval → approvedAttached → capturing`, or
/// lands in `degraded(reason)` when something goes wrong, so the UI never has to
/// guess why capture is not live.
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

    /// The operator-facing word for the capability.
    public var title: String {
        switch self {
        case .extensionNotInstalled: "Extension not installed"
        case .pendingApproval: "Awaiting approval"
        case .approvedAttached: "Approved"
        case .capturing: "Capturing"
        case .degraded: "Degraded"
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
}

extension CaptureCapability {
    /// The capability after `event`. Pure, so the framework-facing controller stays
    /// thin glue. Tunnel events only mean something once the extension is approved:
    /// a late one never overrides a pending approval or a degradation.
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
