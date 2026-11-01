import AitmBusClient
import AitmproxyKit
import Foundation

/// The one call path for CA trust in the mac app (spec 2026-10-31-system-proxy-automation-design
/// §D17.10): the only home of the `"ca.install"` and `"ca.uninstall"` literals, the D17.1 scope
/// (always the user store on macOS and Windows, never the System keychain), the bus confirm-token
/// re-call, the in-flight flag, a dismissed macOS dialog kept silent (D17.4), and the fact taken
/// from the forced `ca.status` re-read, never from the reply (D17.5). The CA panel, the first-run
/// sheet, the Status card and the Proxy menu all come here; `tools/check-ca-trust-path.sh` pins it.
extension Session {
    /// The CA fact of the Core lane and its Getting-started step; nil until `ca.status` has been
    /// read and some store has said yes or no.
    var caTrust: CATrustFacts? {
        guard let caStatus, var facts = CATrustFacts(status: caStatus) else { return nil }
        facts.installing = caTrustInstalling
        facts.needsAdmin = caTrustNeedsAdmin
        return facts
    }

    /// Trusting is a bus call that changes the OS store: live while the bus is connected AS the
    /// operator and no change is in flight.
    var caTrustControlLive: Bool {
        guard case .connected = bus, resolvedRole == "operator" else { return false }
        return !caTrustInstalling
    }

    /// Install the CA into the user trust store (macOS asks for the login password itself).
    func trustCA() async { await changeCATrust("ca.install") }

    /// Remove the CA from the user trust store.
    func untrustCA() async { await changeCATrust("ca.uninstall") }

    /// `ca.status` read directly on the bus (no activity-log entry, like `proxy.status`),
    /// assigned only when it changed. A core without the verb, or no bus, leaves it as is.
    func refreshCAStatus() async {
        guard let commandRunner, let json = try? await commandRunner("ca.status", [:]),
              let status = CAStatus(json: json) else { return }
        if status != caStatus { caStatus = status }
    }

    private func changeCATrust(_ command: String) async {
        guard !caTrustInstalling else { return }
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
                caTrustLastError = nil
            } else {
                caTrustNeedsAdmin = CATrustFacts.signalsNeedsAdmin(message)
                caTrustLastError = "\(command): \(message)"
                lastError = caTrustLastError
            }
        }
        await refreshCAStatus()
    }

    // MARK: First-run sheet (spec D17.8)

    /// The sheet is due once per store: the embedded core is ready, the bus is the operator's,
    /// the OS store has answered and says the CA is not trusted, and neither `Store.defaults`
    /// key (shared with the system-proxy step) says it was shown or suppressed.
    var setupSheetDue: Bool {
        guard !Store.usesFixtures, embeddedCoreActive, coreHealth.connection?.status == .ready,
              caTrustControlLive, let facts = caTrust, !facts.trusted else { return false }
        let defaults = Store.defaults
        return !defaults.bool(forKey: Self.setupSheetShownKey) && !defaults.bool(forKey: Self.setupSheetSuppressedKey)
    }

    static let setupSheetShownKey = "systemProxy.sheetShown"
    static let setupSheetSuppressedKey = "systemProxy.promptSuppressed"

    func presentSetupSheetIfDue() {
        guard setupSheetDue else { return }
        Store.defaults.set(true, forKey: Self.setupSheetShownKey)
        setupSheetVisible = true
    }
}
