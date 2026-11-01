import Foundation

/// The one honest sentence about macOS capture for the operator surfaces (the
/// Settings ▸ Capture status and the Apps page empty state). Pure: computed from the
/// `CaptureCapability` the `ExtensionController` publishes, whether this build embeds
/// the extension, and how many hosts are in scope.
///
/// The trap it exists for: the capture extension is deny-by-default on scope (its
/// `ScopeMatcher` matches nothing for an empty spec), so capture that is ON with an
/// EMPTY scope captures nothing. That state must never read as a working
/// "Capturing" — it reads `onEmptyScope` and points the operator at Scope.
public enum CaptureAdvice: Equatable, Sendable {
    /// This build has no capture extension.
    case unsupported
    /// The extension is available but capture is off (or was never activated).
    case off
    /// Activation was submitted; the two System Settings approvals are outstanding.
    case awaitingApproval
    /// Something failed; carries the operator-facing reason.
    case degraded(String)
    /// Capture is on but the scope is empty: nothing is captured until a host is added.
    case onEmptyScope
    /// Capture is on with `hosts` hosts in scope; flows appear as they are contacted. Worded
    /// "on", not "Capturing": `.approvedAttached` reaches here too, and its tunnel may still be
    /// connecting — the capability's own `title` says which.
    case on(hosts: Int)

    /// `supported` is whether the running build embeds the extension
    /// (`CaptureExtension.isEmbedded`); `scopeHostCount` is the live `scope.list` size.
    public static func make(capability: CaptureCapability, supported: Bool, scopeHostCount: Int) -> CaptureAdvice {
        guard supported else { return .unsupported }
        switch capability {
        case .extensionNotInstalled, .inactive: return .off
        case .pendingApproval: return .awaitingApproval
        case .degraded(let reason): return .degraded(reason)
        case .approvedAttached, .capturing:
            return scopeHostCount <= 0 ? .onEmptyScope : .on(hosts: scopeHostCount)
        }
    }

    /// Whether the surface should offer the operator a way to the Scope page.
    public var offersScope: Bool { self == .onEmptyScope }

    /// Whether the surface should offer the operator a way to Settings ▸ Capture.
    public var offersSettings: Bool { self == .off }

    /// One line for a banner above a live flow table (the Apps page when flows carry no
    /// source app): the state, then the one thing that changes it.
    public var banner: String {
        switch self {
        case .unsupported:
            "Flows carry no source app yet, so this page cannot group them."
        case .off:
            "Capture is off — turn it on in Settings ▸ Capture to capture other apps' traffic."
        case .awaitingApproval:
            "Waiting for approval in System Settings — approve the extension to start capturing."
        case .degraded(let reason):
            "Capture is degraded — \(reason)"
        case .onEmptyScope:
            "Capture is on, but the scope is empty — add hosts to capture other apps' traffic."
        case .on(let hosts):
            "Capture is on, \(hosts == 1 ? "1 host" : "\(hosts) hosts") in scope — flows carry no source app yet, so this page cannot group them."
        }
    }

    /// The short headline for an empty state or status line.
    public var headline: String {
        switch self {
        case .unsupported: "No app attribution yet"
        case .off: "Capture is off"
        case .awaitingApproval: "Waiting for approval"
        case .degraded: "Capture is degraded"
        case .onEmptyScope: "Capture is on, but the scope is empty"
        case .on: "Capture is on"
        }
    }

    /// The explanatory sentence under the headline.
    public var detail: String {
        switch self {
        case .unsupported:
            "This build has no capture extension, and flows carry no source app yet, so there is nothing to group here."
        case .off:
            "Turn on Capture traffic from all apps in Settings ▸ All Apps."
        case .awaitingApproval:
            "Approve the extension in System Settings under Network Extensions, then allow Add Proxy Configurations."
        case .degraded(let reason):
            reason
        case .onEmptyScope:
            "Nothing is captured until you add a host to capture, such as example.com or *.example.com."
        case .on(let hosts):
            hosts == 1
                ? "1 host is in scope. Flows appear here as that host is contacted."
                : "\(hosts) hosts are in scope. Flows appear here as they are contacted."
        }
    }
}
