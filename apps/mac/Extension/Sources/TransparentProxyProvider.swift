import Foundation
import Network
import NetworkExtension
import os.log

/// Transparent proxy provider (Band C Tasks 10 + 11, NE-AC5/6/7).
///
/// Installs one catch-all outbound rule (TCP + UDP) and **fails open**: with no
/// attached core control channel, no pushed scope spec, no matching scope, or any
/// handoff/peer-authentication failure, a new flow returns `false` so it goes
/// direct and the user's network is unaffected.
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

    override func startProxy(options: [String: Any]? = nil,
                             completionHandler: @escaping (Error?) -> Void) {
        os_log("startProxy", log: log, type: .default)
        // Begin looking for the core. Until it attaches (and pushes a scope) every
        // flow fails open, so starting this before the network settings are applied
        // is safe.
        handoff.start()
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // Catch-all included rule: any remote, outbound, protocol **any** so both
        // TCP byte-stream flows and UDP datagram flows reach the provider (spec D1,
        // NE-AC2). Provider *rules* cannot be hot-edited without a restart, so the
        // rule stays broad and the per-flow decision (handleNewFlow, once the handoff
        // lands) does the real scoping.
        // Use the non-deprecated macOS 15+ initializer (…NetworkEndpoint:, nw_endpoint_t)
        // rather than the deprecated NWHostEndpoint one; the distinct label selects it
        // for a nil catch-all.
        let rule = NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0,
                                 localNetworkEndpoint: nil, localPrefix: 0,
                                 protocol: .any, direction: .outbound)
        settings.includedNetworkRules = [rule]
        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                os_log("setTunnelNetworkSettings error %{public}@",
                       log: self.log, type: .error, String(describing: error))
                self.handoff.stop()
            }
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        os_log("stopProxy %{public}d", log: log, type: .default, reason.rawValue)
        handoff.stop()
        completionHandler()
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
