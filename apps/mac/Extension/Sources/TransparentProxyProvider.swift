import Foundation
import NetworkExtension
import os.log

/// Transparent proxy provider skeleton (Band C Task 10, NE-AC5).
///
/// Installs one catch-all outbound-TCP rule and **fails open**: with no attached
/// core control channel, no pushed scope spec, and no matching scope, every new
/// flow returns `false` so it goes direct and the user's network is unaffected.
/// The authenticated core handoff — connecting the per-flow data socket, pushing
/// the scope set, forwarding bytes — is Band C Task 11; until then this provider
/// is a pure pass-through, which is the correct fail-open behaviour when the core
/// is absent.
///
/// `NEProviderClasses` in `Info.plist` maps `com.apple.networkextension.app-proxy`
/// to this class (resolved by its `@objc` name). The Task-1 spike proved this
/// provider activates once the containing app is Developer-ID-signed, notarized,
/// and installed to `/Applications`.
@objc(TransparentProxyProvider)
final class TransparentProxyProvider: NETransparentProxyProvider {
    private let log = OSLog(subsystem: "com.mrbrutti.aitmproxy.ne", category: "provider")

    override func startProxy(options: [String: Any]? = nil,
                             completionHandler: @escaping (Error?) -> Void) {
        os_log("startProxy", log: log, type: .default)
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
            }
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        os_log("stopProxy %{public}d", log: log, type: .default, reason.rawValue)
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Fail open: no attached core / no spec / no matching scope -> go direct.
        // The core handoff that would return `true` for in-scope flows is Task 11.
        return false
    }
}
