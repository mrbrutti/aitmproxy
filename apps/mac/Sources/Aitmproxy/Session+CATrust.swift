import AitmBusClient
import AitmproxyKit
import Foundation
import os.log

/// The one call path for CA trust in the mac app (spec 2026-10-31-system-proxy-automation-design
/// §D17.10): the only home of the `"ca.install"` and `"ca.uninstall"` literals, the D17.1 scope
/// (always the user store on macOS and Windows, never the System keychain), the bus confirm-token
/// re-call, the in-flight flag, a dismissed macOS dialog kept silent (D17.4), and the fact taken
/// from the forced `ca.status` re-read, never from the reply (D17.5). The CA panel, the first-run
/// sheet, the Status card and the Proxy menu all come here; `tools/check-ca-trust-path.sh` pins it.
extension Session {
    private static let caLog = Logger(subsystem: "com.mrbrutti.aitmproxy", category: "ca-trust")

    /// The CA fact of the Core lane and its Getting-started step; nil until `ca.status` has been
    /// read, the certificate exists and some store has said yes or no. The Kit ranks the read-back
    /// over the needs-admin latch (`CATrustFacts`, pinned by its tests).
    var caTrust: CATrustFacts? {
        guard let caStatus, caStatus.exists, var facts = CATrustFacts(status: caStatus) else { return nil }
        facts.installing = caTrustInstalling
        facts.needsAdmin = caTrustNeedsAdmin
        return facts
    }

    /// The Getting-started row for CA trust (D17.6, D17.9), shared by the Status page and the
    /// first-run sheet: nil until `ca.status` has been read; "not generated" when the core has no
    /// certificate yet; the facts' row; or the "unknown" row when every store is unknown.
    var caTrustStep: GettingStartedStep? {
        guard let caStatus else { return nil }
        if !caStatus.exists { return CATrustFacts.notGeneratedStep() }
        return caTrust?.step ?? CATrustFacts.unknownStep()
    }

    /// Trusting is a bus call that changes the OS store: live while the bus is connected AS the
    /// operator and no change is in flight.
    var caTrustControlLive: Bool {
        guard case .connected = bus, resolvedRole == "operator" else { return false }
        return !caTrustInstalling
    }

    /// The confirm-gated trust verbs, for the surfaces that must not offer them generically
    /// (the palette's Commands list, the Agent log's Approve).
    static func isCATrustVerb(_ name: String) -> Bool {
        name == "ca.install" || name == "ca.uninstall"
    }

    /// Install the CA into the user trust store (macOS asks for the login password itself).
    func trustCA() async { await changeCATrust("ca.install") }

    /// Remove the CA from the user trust store.
    func untrustCA() async { await changeCATrust("ca.uninstall") }

    /// `ca.status` read directly on the bus (no activity-log entry, like `proxy.status`),
    /// assigned only when it changed. A trusted store clears the needs-admin latch; the one place a
    /// read-back clears the last failure, when it says that failure's verb reached its end state
    /// (`CATrustFailure.resolved(by:)`). Returns whether the read-back landed: false for a core
    /// without the verb, no bus, or an unparseable reply, which leaves the status as is.
    @discardableResult
    func refreshCAStatus() async -> Bool {
        guard let commandRunner else { return false }
        let json: JSONValue
        do {
            json = try await commandRunner("ca.status", [:])
        } catch {
            Self.caLog.debug("ca.status not read: \(BusService.describe(error), privacy: .public)")
            return false
        }
        guard let status = CAStatus(json: json) else {
            Self.caLog.debug("ca.status reply did not decode")
            return false
        }
        if status != caStatus { caStatus = status }
        if status.trustedScope != nil { caTrustNeedsAdmin = false }
        if let failure = caTrustLastError, failure.resolved(by: status) { caTrustLastError = nil }
        return true
    }

    /// No bus, no fact: the read-back, the latch and the last failure all belong to a connection.
    func forgetCATrust() {
        caStatus = nil
        caTrustNeedsAdmin = false
        caTrustLastError = nil
    }

    private func changeCATrust(_ command: String) async {
        guard !caTrustInstalling, case .connected = bus else { return }
        guard caTrustControlLive else {
            fail(command, CATrustFacts.notOperatorLine)
            return
        }
        caTrustInstalling = true
        defer { caTrustInstalling = false }
        if caStatus == nil { await refreshCAStatus() }
        let args = CATrustFacts.scopeArgs(platform: caStatus?.platform ?? "")
        do {
            // Confirm-gated over the bus (spec D4): the first call mints a token and applies
            // nothing; the identical call re-sent with `_confirm` runs it.
            let reply = try await runCommand(command, args)
            if let token = reply["confirm_token"]?.stringValue {
                var confirmed = args
                confirmed["_confirm"] = .string(token)
                _ = try await runCommand(command, confirmed)
            }
            caTrustNeedsAdmin = false
            caTrustLastError = nil
        } catch {
            let message = BusService.describe(error)
            if CATrustFacts.isCancelled(message) {
                caTrustNeedsAdmin = false
                caTrustLastError = nil
            } else {
                caTrustNeedsAdmin = CATrustFacts.signalsNeedsAdmin(message)
                fail(command, message)
            }
        }
        // The fact is the store's (D17.5): the forced re-read clears a resolved failure itself.
        guard await refreshCAStatus() else {
            if caTrustLastError == nil { fail(command, CATrustFacts.readBackFailedLine) }
            return
        }
        if caTrustLastError == nil, caStatus?.trustReported == false { fail(command, CATrustFacts.storesUnknownLine) }
    }

    private func fail(_ command: String, _ message: String) {
        caTrustLastError = CATrustFailure(command: command, verb: .init(command: command), message: message)
        lastError = caTrustLastError?.line
    }

    // MARK: First-run sheet (spec D17.8)

    /// The sheet is due once per store: the embedded core is ready, the bus is the operator's, EITHER
    /// row is undone — the OS store has answered and says the CA is not trusted, or the system-proxy
    /// route is known, closed and `supported` (system-proxy spec D13 "First-run sheet", D17.8) — and
    /// neither `Store.defaults` key (shared by the two steps) says it was shown or suppressed.
    var setupSheetDue: Bool {
        guard embeddedCoreActive, coreHealth.connection?.status == .ready, caTrustControlLive else { return false }
        let caUndone = caTrust.map { !$0.trusted } ?? false
        // The system-proxy row is due when its route is KNOWN and closed (a word that names no endpoint
        // has no row to act on), the core has a mechanism, nothing is in flight, and D13's "Set system
        // proxy at launch" is off — with it on the core sets the proxy at launch itself.
        let systemProxyUndone = systemProxyFacts?.supported == true && systemProxy != nil && !systemProxyPointsAtUs
            && !(systemProxyFacts?.setting ?? false) && !Store.defaults.bool(forKey: SystemProxyPreferences.autoKey)
        guard caUndone || systemProxyUndone else { return false }
        let defaults = Store.defaults
        return !defaults.bool(forKey: SystemProxyPreferences.sheetShownKey)
            && !defaults.bool(forKey: SystemProxyPreferences.promptSuppressedKey)
    }

    func presentSetupSheetIfDue() {
        guard setupSheetDue else { return }
        Store.defaults.set(true, forKey: SystemProxyPreferences.sheetShownKey)
        setupSheetVisible = true
    }
}

private extension CATrustFailure.Verb {
    /// The verb literals' one home names them for the Kit.
    init(command: String) {
        switch command {
        case "ca.install": self = .install
        case "ca.uninstall": self = .uninstall
        default: self = .other
        }
    }
}
