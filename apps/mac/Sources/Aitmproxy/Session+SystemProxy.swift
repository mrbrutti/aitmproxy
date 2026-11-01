import AitmBusClient
import AitmproxyKit
import Foundation
import os.log

/// The one call path for the system proxy in the mac app (spec 2026-10-31-system-proxy-automation-design
/// §D13 "Calls out", §D6): the only home of the `"proxy.system.set"` and `"proxy.system.unset"` literals,
/// the in-flight flag the facts' `setting` does not cover (it is another client's change), the bypass list
/// read fresh from `Store.defaults`, and the reply — the core's fresh read of the services (D6) — taken as
/// the new facts. Settings ▸ Proxy, the first-run sheet, the Status card, the route banner and the Proxy
/// menu all come here; the facts themselves arrive through `BusService.refreshProxyStatus()` (D13 "Facts
/// in") and leave with the connection (`forgetSystemProxy`). Mirrors `Session+CATrust.swift`.
extension Session {
    private static let systemProxyLog = Logger(subsystem: "com.mrbrutti.aitmproxy", category: "system-proxy")

    /// Setting the system proxy is a bus call that changes the OS: live while the bus is connected AS the
    /// operator, the core has reported a mechanism (`supported`), and no change is in flight — neither
    /// ours (`systemProxySetting`) nor another client's (the facts' `setting`).
    var systemProxyControlLive: Bool {
        guard case .connected = bus, resolvedRole == "operator", let facts = systemProxyFacts, facts.supported else { return false }
        return !systemProxySetting && !facts.setting
    }

    /// The verb's word is `points_at_us`: the menu item reads "Restore System Proxy" and the Settings toggle
    /// is on. No facts (no verb, no bus) → false, never a guess from the CFNetwork read.
    var systemProxyPointsAtUs: Bool { systemProxyFacts?.word == .pointsAtUs }

    /// The two mutating verbs, for the surfaces that must not offer them generically (the palette's
    /// Commands list, the Agent log's Approve), like `isCATrustVerb`.
    static func isSystemProxyVerb(_ name: String) -> Bool {
        name == "proxy.system.set" || name == "proxy.system.unset"
    }

    /// Point every service at this core, with the Settings ▸ Proxy bypass list (D5).
    func setSystemProxy() async { await changeSystemProxy("proxy.system.set") }

    /// Put back what the core recorded before its set (D6 `proxy.system.unset`).
    func restoreSystemProxy() async { await changeSystemProxy("proxy.system.unset") }

    /// One full `proxy.system.status` read directly on the bus (no activity-log entry, like `ca.status`):
    /// the only object that carries `guidance` and `remedy`, so Settings ▸ Proxy asks for it on appear.
    /// Assigned only when it changed. Returns whether the read landed: false for no bus, a core without
    /// the verb, or an unparseable reply, which leaves the facts as they are.
    @discardableResult
    func refreshSystemProxyStatus() async -> Bool {
        guard let commandRunner else { return false }
        let json: JSONValue
        do {
            json = try await commandRunner("proxy.system.status", [:])
        } catch {
            Self.systemProxyLog.debug("proxy.system.status not read: \(BusService.describe(error), privacy: .public)")
            return false
        }
        guard let facts = SystemProxyFacts(compact: json, listenAddress: systemProxyListenAddress) else {
            Self.systemProxyLog.debug("proxy.system.status reply did not decode")
            return false
        }
        applySystemProxyFacts(facts)
        return true
    }

    /// No bus, no fact: the verb's word, the endpoint half and our own in-flight flag all belong to a connection.
    func forgetSystemProxy() {
        systemProxyFacts = nil
        systemProxy = nil
        systemProxySetting = false
    }

    /// The address the summary compares the services against: the live core's, else the configured one.
    private var systemProxyListenAddress: String { coreHealth.connection?.proxyAddress ?? listenAddress }

    /// Change-guarded like the poll's writes: an @Observable set notifies even when equal, and every
    /// route surface reads both.
    private func applySystemProxyFacts(_ facts: SystemProxyFacts) {
        if facts != systemProxyFacts { systemProxyFacts = facts }
        if facts.state != systemProxy { systemProxy = facts.state }
    }

    /// Why the control is not live, one line, in the order the Settings footnote lists the causes.
    private var systemProxyNotLiveReason: String {
        if systemProxySetting || systemProxyFacts?.setting == true { return "a system-proxy change is already in flight" }
        if let facts = systemProxyFacts, !facts.supported { return "the system proxy cannot be set on this platform" }
        guard case .connected = bus, resolvedRole == "operator" else { return CATrustFacts.notOperatorLine }
        return "the core has not reported the system proxy yet"
    }

    private func changeSystemProxy(_ command: String) async {
        guard !systemProxySetting, case .connected = bus else { return }
        guard systemProxyControlLive else {
            lastError = "\(command): \(systemProxyNotLiveReason)"
            return
        }
        systemProxySetting = true
        defer { systemProxySetting = false }
        var args: [String: JSONValue] = [:]
        if command == "proxy.system.set" {
            // The field as typed in Settings ▸ Proxy, parsed the way the spawn parses it; the key travels
            // only when there is something in it (the core's default applies otherwise, D5).
            let hosts = SystemProxyPreferences.bypassHosts(Store.defaults.string(forKey: SystemProxyPreferences.bypassKey) ?? "")
            if !hosts.isEmpty { args["bypass"] = .array(hosts.map(JSONValue.string)) }
        }
        let reply: JSONValue
        do {
            reply = try await runCommand(command, args)
        } catch {
            // Refusals verbatim (an in-flight change elsewhere, a tool that would not start, a rollback
            // that failed); never retried — the next poll says where the services stand.
            lastError = "\(command): \(BusService.describe(error))"
            return
        }
        // The reply IS the fresh status (D6: set/unset return the read they end with), so it is the fact.
        if let facts = SystemProxyFacts(compact: reply, listenAddress: systemProxyListenAddress) {
            applySystemProxyFacts(facts)
            lastError = nil
            return
        }
        // A reply without a readable status: the forced re-read is the fact; failing that, say so.
        guard await refreshSystemProxyStatus() else {
            lastError = "\(command): the reply carried no system-proxy status and the re-read failed"
            return
        }
        lastError = nil
    }
}
