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
    /// Linux `NeedsRoot` or macOS `HeadlessAuth` came back from the last change. The
    /// read-back outranks it: a trusted store renders trusted whatever the latch says.
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
    /// The Agent log's answer to an agent's `ca.install` / `ca.uninstall` request: the operator trusts the CA from the app's own surfaces.
    public static let operatorOnlyNote = "not approved from the Agent log — the operator uses \(ConnectionAction.trustCA.title)"
    /// The spoken title of the CA fact's dot, "<title>: <word>", on the Status page and the first-run sheet.
    public static let laneTitle = "Certificate Authority"
    /// A trust change ran but the forced `ca.status` re-read did not land (D17.5: the reply is not the fact).
    public static let readBackFailedLine = "the CA may have changed but ca.status could not be read"
    /// The one call path refused: the bus is connected, but not as the operator.
    public static let notOperatorLine = "the bus is not the operator's"

    /// The fact text (D17.6).
    public var text: String {
        if installing { return "trusting CA…" }
        if trusted { return scope == "system" ? "CA trusted (System keychain)" : "CA trusted (user keychain)" }
        if needsAdmin { return "CA trust needs an administrator" }
        return "HTTPS is not captured until the CA is trusted"
    }

    public var state: LaneState {
        if installing { return .working }
        return trusted ? .ok : .warning
    }

    public var remedy: String? {
        if installing || trusted { return nil }
        if needsAdmin { return platform.hasPrefix("linux") ? Self.needsAdminLinuxLine : Self.needsAdminMacLine }
        return Self.notTrustedLine
    }

    /// What a surface may offer, primary first.
    public var actions: [ConnectionAction] {
        if installing { return [] }
        if trusted || needsAdmin { return [.openCAPanel] }
        return [.trustCA, .openCAPanel]
    }

    /// The Getting-started row (D17.9): done only when the fact is `ok`, with the first offered action otherwise.
    public var step: GettingStartedStep {
        let done = state == .ok
        let title = !done && !installing && !needsAdmin ? ConnectionAction.trustCA.title : text
        return GettingStartedStep(kind: .caTrusted, title: title, done: done, action: done ? nil : actions.first)
    }

    /// The row when the facts are nil: `ca.status` was read but every store is unknown.
    public static func unknownStep() -> GettingStartedStep {
        GettingStartedStep(kind: .caTrusted, title: "CA trust unknown — open the Certificate Authority panel",
                           done: false, action: .openCAPanel)
    }

    /// The row when `ca.status.exists == false` (D17.6 last row): nothing to trust yet, nothing to press.
    public static func notGeneratedStep() -> GettingStartedStep {
        GettingStartedStep(kind: .caTrusted, title: "CA not generated yet — the core creates it on first start", done: false)
    }

    /// D17.1: the scope every frontend passes on `ca.install` / `ca.uninstall` — always the
    /// user store on macOS and Windows, nothing on Linux (its only scope is the system one).
    public static func scopeArgs(platform: String) -> [String: JSONValue] {
        platform == "macos" || platform == "windows" ? ["scope": .string("user")] : [:]
    }

    /// The core's D17.4 text for a dismissed macOS dialog, for either verb (correction 15), wherever
    /// the bus wrapper put it: no toast, nothing to fix.
    public static func isCancelled(_ errorText: String) -> Bool {
        ["ca.install cancelled", "ca.uninstall cancelled"].contains { errorText.contains($0) }
    }

    /// The core's `HeadlessAuth` (macOS) or `NeedsRoot` (Linux) texts: the change needs an administrator.
    public static func signalsNeedsAdmin(_ errorText: String) -> Bool {
        errorText.contains("without a GUI session") || errorText.contains("needs root")
    }
}

/// The last trust change's failure, kept with the verb it came from so a read-back clears it only
/// when that verb's end state is what the store now says; the CA panel shows `line`.
public struct CATrustFailure: Hashable, Sendable {
    public var command: String
    public var message: String

    public init(command: String, message: String) {
        self.command = command
        self.message = message
    }

    public var line: String { "\(command): \(message)" }
}
