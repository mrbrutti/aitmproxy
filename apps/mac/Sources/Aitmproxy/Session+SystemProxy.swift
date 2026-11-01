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

    /// Why the control is not live, in the order §D13's Settings footnote lists the causes; nil when
    /// `systemProxyControlLive`. One ladder for the footnote word and the refusal sentence.
    var systemProxyNotLiveCause: SystemProxyNotLive? {
        if systemProxySetting || systemProxyFacts?.setting == true { return .changeInFlight }
        if let facts = systemProxyFacts, !facts.supported { return .unsupported }
        guard case .connected = bus, resolvedRole == "operator" else { return .notOperator }
        return systemProxyFacts == nil ? .waitingForCore : nil
    }

    /// The address the services are compared against: the live core's, else the configured one. The
    /// summary, the facts parser and the status re-read all use this one.
    var effectiveListenAddress: String { coreHealth.connection?.proxyAddress ?? listenAddress }

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
        guard let facts = SystemProxyFacts(compact: json, listenAddress: effectiveListenAddress) else {
            Self.systemProxyLog.debug("proxy.system.status reply did not decode")
            return false
        }
        applySystemProxyFacts(facts)
        return true
    }

    /// No bus, no fact: the verb's word (and with it the endpoint half) and our own in-flight flag all
    /// belong to a connection.
    func forgetSystemProxy() {
        systemProxyFacts = nil
        systemProxySetting = false
    }

    /// The one write of the facts, change-guarded like the poll's writes (an @Observable set notifies
    /// even when equal): the poll, the status re-read and the set/unset replies all come here. A
    /// compact object keeps the last full read's `guidance`/`remedy` while the word is unchanged.
    func applySystemProxyFacts(_ facts: SystemProxyFacts) {
        let merged = facts.keepingFullFields(from: systemProxyFacts)
        if merged != systemProxyFacts { systemProxyFacts = merged }
    }

    private func changeSystemProxy(_ command: String) async {
        guard !systemProxySetting, case .connected = bus else { return }
        guard systemProxyControlLive else {
            lastError = "\(command): \((systemProxyNotLiveCause ?? .waitingForCore).sentence)"
            return
        }
        systemProxySetting = true
        defer { systemProxySetting = false }
        var args: [String: JSONValue] = [:]
        if command == "proxy.system.set" {
            // The field as typed in Settings ▸ Proxy, parsed the way the spawn parses it; the key travels
            // only when there is something in it (the core's default applies otherwise, D5).
            let hosts = SystemProxyPreferences.bypassHosts(SystemProxyPreferences.bypassField(Store.defaults))
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
        if let facts = SystemProxyFacts(compact: reply, listenAddress: effectiveListenAddress) {
            applySystemProxyFacts(facts)
            clearOwnError()
            return
        }
        // A reply without a readable status: the forced re-read is the fact; failing that, say so.
        guard await refreshSystemProxyStatus() else {
            lastError = "\(command): the reply carried no system-proxy status and the re-read failed"
            return
        }
        clearOwnError()
    }

    /// Success clears only this path's own line: `lastError` is the app's one shared error, and another
    /// surface's unread failure is not ours to blank (the CA path keeps its own `caTrustLastError`).
    private func clearOwnError() {
        if let line = lastError, line.hasPrefix("proxy.system.") { lastError = nil }
    }
}

/// Why the system-proxy control stands down (§D13 "disabled with the reason"), ordered as the Settings
/// footnote lists the causes. One home for the footnote word and the refusal sentence.
enum SystemProxyNotLive {
    case changeInFlight, unsupported, notOperator, waitingForCore

    /// The Settings footnote.
    var word: String {
        switch self {
        case .changeInFlight: "setting…"
        case .unsupported: "not available here"
        case .notOperator: "connect as operator"
        case .waitingForCore: "waiting for the core"
        }
    }

    /// The `lastError` sentence when a call is attempted anyway.
    var sentence: String {
        switch self {
        case .changeInFlight: "a system-proxy change is already in flight"
        case .unsupported: "the system proxy cannot be set on this platform"
        case .notOperator: CATrustFacts.notOperatorLine
        case .waitingForCore: "the core has not reported the system proxy yet"
        }
    }
}
