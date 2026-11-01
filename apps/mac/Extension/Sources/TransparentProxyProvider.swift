import Foundation
import Network
import NetworkExtension
import os.log

/// Transparent proxy provider (Band C Tasks 10 + 11, NE-AC5/6/7; rule set per spec
/// 2026-11-01-ne-tcp-only-catch-all-design).
///
/// **Rules.** The provider installs a TCP-only catch-all `NENetworkRule` by default and
/// one `.UDP` host rule per IP token the scope could claim a datagram through
/// (`ProviderRuleSet`). With no UDP target scoped the kernel diverts no UDP flow to the
/// provider at all, so `setsockopt(IP_DONTFRAG)` on the user's UDP sockets keeps working
/// and Chromium keeps HTTP/3 (research 24 §4). The rule set is a pure function of the
/// `ScopeMatcher` the core pushes: on every scope transition
/// (`FlowHandoff.onScopeChange`) the provider re-applies `setTunnelNetworkSettings`
/// IN PLACE through `RuleReconciler` on one serial queue -- no tunnel restart, nothing
/// applied while the wanted set equals the installed one, at most one apply in flight
/// plus one pending, `reasserting` set around a reconcile apply only, never around the
/// startup apply.
///
/// **Fails open.** Rules decide only what the kernel diverts; the per-flow decision is
/// unchanged and never waits on rule work: with no attached core control channel, no
/// pushed scope spec, no matching scope, or any handoff/peer-authentication failure, a
/// new flow returns `false` so it goes direct and the user's network is unaffected.
///
/// For an in-scope flow, with a core attached whose code signature was verified
/// over the control socket, the flow is handed to the core (`FlowHandoff`): its
/// per-flow data socket is peer-authenticated again before any byte moves, then
/// the flow is claimed (`true`) and its bytes are forwarded. See `FlowHandoff.swift`
/// for the wire contract and the security model.
///
/// `NEProviderClasses` in `Info.plist` maps `com.apple.networkextension.app-proxy`
/// to this class (resolved by its `@objc` name). The Task-1 spike proved this
/// provider activates once the containing app is Developer-ID-signed, notarized,
/// and installed to `/Applications`.
@objc(TransparentProxyProvider)
final class TransparentProxyProvider: NETransparentProxyProvider, NEAppProxyUDPFlowHandling {
    private let log = OSLog(subsystem: "com.mrbrutti.aitmproxy.ne", category: "provider")
    private let handoff = FlowHandoff()
    /// Every `RuleReconciler` call and every apply completion runs here, serially; the
    /// reconciler is touched nowhere else.
    private let rulesQueue = DispatchQueue(label: "com.mrbrutti.aitmproxy.ne.rules")
    private lazy var reconciler = RuleReconciler(
        apply: { [weak self] wanted, reassert, completion in
            self?.applyRules(wanted, reassert: reassert, completion: completion)
        },
        onEvent: { [weak self] event in self?.logRuleEvent(event) })

    override func startProxy(options: [String: Any]? = nil,
                             completionHandler: @escaping (Error?) -> Void) {
        os_log("startProxy", log: log, type: .default)
        // The rule reconcile hangs off the scope hook, installed BEFORE the core link
        // starts so every transition is seen (nil at serve start, the matcher per Scope
        // frame, nil on detach). Each hook call is one `rulesQueue.async`; nothing on
        // the control thread or the claim path waits on it.
        handoff.onScopeChange = { [weak self] scope in self?.reconcileRules(for: scope) }
        // Begin looking for the core. Until it attaches (and pushes a scope) every
        // flow fails open, so starting this before the network settings are applied
        // is safe.
        handoff.start()
        // Startup rule set: the TCP-only catch-all (every outbound TCP flow except
        // loopback; no UDP). UDP rules appear only after a Scope push holding
        // UDP-claimable IP tokens, re-applied in place by `reconcileRules`; a Scope
        // that arrives before this apply lands is coalesced and applied right after it.
        rulesQueue.async {
            self.reconciler.begin { error in
                if let error = error {
                    os_log("setTunnelNetworkSettings error %{public}@",
                           log: self.log, type: .error, String(describing: error))
                    self.handoff.stop()
                }
                completionHandler(error)
            }
        }
    }

    override func stopProxy(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        os_log("stopProxy %{public}d", log: log, type: .default, reason.rawValue)
        // Reconciler first: the detach that `handoff.stop()` triggers fires the hook,
        // whose reconcile is enqueued behind this block and dropped as stopped.
        rulesQueue.async {
            self.reconciler.stop()
            self.handoff.stop()
            completionHandler()
        }
    }

    // MARK: Rules (spec 2026-11-01-ne-tcp-only-catch-all-design, Design B, C, D)

    /// The scope hook's target: hop onto the serial queue and let the reconciler decide
    /// whether anything changes. Never on the claim path.
    private func reconcileRules(for scope: ScopeMatcher?) {
        rulesQueue.async { self.reconciler.reconcile(for: scope) }
    }

    /// The reconciler's `apply`: build the settings for `wanted` and re-apply them in
    /// place. `reasserting` is set iff `reassert` (a reconcile apply; the session is
    /// Connected then) and cleared by this apply's completion, which hops back onto
    /// `rulesQueue` before the reconciler sees the result. Called on `rulesQueue`.
    private func applyRules(_ wanted: ProviderRuleSet, reassert: Bool,
                            completion: @escaping (Error?) -> Void) {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = wanted.networkRules()
        if reassert { reasserting = true }
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            self.rulesQueue.async {
                if reassert { self.reasserting = false }
                completion(error)
            }
        }
    }

    /// Spec Design D: one `.default` line per completed change naming the count, the
    /// protocols and the scoped UDP targets (the operator's own configuration, not user
    /// traffic); one `.error` line per failed apply. Silent when nothing changes.
    private func logRuleEvent(_ event: RuleReconciler.Event) {
        switch event {
        case .applied(let set):
            os_log("provider rules applied: %{public}@", log: log, type: .default, set.summary)
        case .applyFailed(let wanted, let kept, let message):
            os_log("provider rules apply failed; keeping %{public}@ installed: %{public}@ (wanted %{public}@)",
                   log: log, type: .error, kept?.summary ?? "none", message, wanted.summary)
        }
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Fail open: no attached/authenticated core, no spec, no matching scope, or
        // any handoff failure -> `false`, the flow goes direct. Only an in-scope TCP
        // flow whose core and data socket both passed the code-signature check is
        // claimed. (UDP flows arrive via `handleNewUDPFlow` below, which carries the
        // initial remote endpoint; a UDP flow that reaches here has none, so it
        // cannot be scoped and fails open.)
        // Loop avoidance (NE-AC8): never capture flows our own binaries originate,
        // or the core's upstream dials / obscura's browsing would be fed back and loop.
        if SelfExclusion.isSelf(sourceAppAuditToken: flow.metaData.sourceAppAuditToken) { return false }
        guard let tcp = flow as? NEAppProxyTCPFlow else { return false }
        return handoff.handleTCP(tcp)
    }

    /// macOS 15+ delivers a UDP flow with its initial remote endpoint so it can be
    /// scoped and handed off exactly like a TCP flow. Same fail-open contract.
    func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow,
                          initialRemoteFlowEndpoint remoteEndpoint: Network.NWEndpoint) -> Bool {
        if SelfExclusion.isSelf(sourceAppAuditToken: flow.metaData.sourceAppAuditToken) { return false }
        return handoff.handleUDP(flow, initialRemote: remoteEndpoint)
    }
}
