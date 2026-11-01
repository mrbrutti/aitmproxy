import AitmBusClient
import Foundation

/// The CA trust fact of the Core lane and its Getting-started step (spec
/// 2026-10-31-system-proxy-automation-design §D17.5, D17.6, D17.9), built from the
/// `ca.status` read-back and the app's in-flight / needs-admin flags, never from an
/// install reply. Every word a mac surface shows about CA trust comes from here.
public struct CATrustFacts: Hashable, Sendable {
    /// A store says `yes`.
    public var trusted: Bool
    /// `"user"` | `"system"`: the store that says `yes`; nil when none.
    public var scope: String?
    public var fingerprint: String?
    /// `ca.status.platform`; picks the needs-an-administrator remedy.
    public var platform: String
    /// A `ca.install` / `ca.uninstall` call is in flight (set by the session).
    public var installing = false
    /// Linux `NeedsRoot` or macOS `HeadlessAuth` came back from the last change.
    public var needsAdmin = false

    /// Nil unless some store answered `yes` or `no` (`CAStatus.trustReported`), so an older
    /// core or a failed evaluation never renders as "not trusted".
    public init?(status: CAStatus) {
        guard status.trustReported else { return nil }
        trusted = status.trustedScope != nil
        scope = status.trustedScope
        fingerprint = status.fingerprint.isEmpty ? nil : status.fingerprint
        platform = status.platform
    }

    /// D17.7, one sentence, verbatim wherever it appears.
    public static let quicCaveat = "HTTPS apps that use QUIC are not captured until the CA is trusted; browsers fall back to TCP once it is."
    /// The not-trusted remedy (mac-attribution's detail line).
    public static let notTrustedLine = "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"
    static let needsAdminLinuxLine = "Linux trust stores need root: run `aitm ca install` in a terminal where sudo can prompt"
    static let needsAdminMacLine = "macOS did not show its authentication dialog. Open the Certificate Authority panel, export the certificate and trust it in Keychain Access."

    /// The fact text (D17.6).
    public var text: String {
        if installing { return "trusting CA…" }
        if needsAdmin { return "CA trust needs an administrator" }
        if trusted { return scope == "system" ? "CA trusted (System keychain)" : "CA trusted (user keychain)" }
        return "HTTPS is not captured until the CA is trusted"
    }

    public var state: LaneState {
        if installing { return .working }
        if needsAdmin || !trusted { return .warning }
        return .ok
    }

    public var remedy: String? {
        if installing { return nil }
        if needsAdmin { return platform.hasPrefix("linux") ? Self.needsAdminLinuxLine : Self.needsAdminMacLine }
        return trusted ? nil : Self.notTrustedLine
    }

    /// What a surface may offer, primary first.
    public var actions: [ConnectionAction] {
        if installing { return [] }
        if needsAdmin || trusted { return [.openCAPanel] }
        return [.trustCA, .openCAPanel]
    }

    /// The Getting-started row (D17.9): done once a store says yes and nothing is in flight.
    public var step: GettingStartedStep {
        let done = trusted && !installing
        if done { return GettingStartedStep(kind: .caTrusted, title: text, done: true) }
        if installing { return GettingStartedStep(kind: .caTrusted, title: text, done: false) }
        if needsAdmin { return GettingStartedStep(kind: .caTrusted, title: text, done: false, action: .openCAPanel) }
        return GettingStartedStep(kind: .caTrusted, title: ConnectionAction.trustCA.title, done: false, action: .trustCA)
    }

    /// The row when the facts are nil: `ca.status` was read but every store is unknown.
    public static func unknownStep() -> GettingStartedStep {
        GettingStartedStep(kind: .caTrusted, title: "CA trust unknown — open the Certificate Authority panel",
                           done: false, action: .openCAPanel)
    }

    /// D17.1: the scope every frontend passes on `ca.install` / `ca.uninstall` — always the
    /// user store on macOS and Windows, nothing on Linux (its only scope is the system one).
    public static func scopeArgs(platform: String) -> [String: JSONValue] {
        platform == "macos" || platform == "windows" ? ["scope": .string("user")] : [:]
    }

    /// The core's D17.4 text for a dismissed macOS dialog: no toast, nothing to fix.
    public static func isCancelled(_ errorText: String) -> Bool {
        errorText.hasPrefix("ca.install cancelled")
    }

    /// The core's `HeadlessAuth` (macOS) or `NeedsRoot` (Linux) texts: the change needs an administrator.
    public static func signalsNeedsAdmin(_ errorText: String) -> Bool {
        errorText.contains("without a GUI session") || errorText.hasPrefix("needs root")
    }
}
