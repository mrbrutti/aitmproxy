import Foundation
import Network
import NetworkExtension

// MARK: - Provider rule set (spec 2026-11-01-ne-tcp-only-catch-all-design, Design A, G, H, I)
//
// The `NENetworkRule`s the transparent proxy installs decide which traffic the kernel
// diverts to the provider at all. The shipped `.any` catch-all diverted every UDP flow
// too, and while it was installed `setsockopt(IP_DONTFRAG)` on every connected
// non-loopback UDP socket failed with ECONNRESET (research 24 §4), which costs Chromium
// HTTP/3 system-wide even though the provider declines every datagram. So the default
// rule set is TCP-only, and UDP enters the provider only for the targets it could
// actually claim a datagram through.
//
// ONE pure function builds every rule set (`wanted(for:)`); startup uses `tcpOnly`,
// which is `wanted(for: nil)`. Nothing here touches the claim path: `CoreLink.current()`
// and `ScopeMatcher.matches` still decide every flow, and detach stays instantly
// fail-open whatever rules the kernel holds.
//
// Rule shape (Design A, R2): always one `.TCP` outbound rule with nil remote and nil
// local (every TCP flow except loopback); then one `.UDP` outbound rule per
// UDP-claimable IP token of the scope (`ScopeMatcher.udpClaimableIPEntries`: `.ip`
// entries whose port is nil or not 53/5353/853), remote = that address with the token's
// port or `0` (= any port, allowed because the address is not a wildcard), prefix 32 for
// IPv4 and 128 for IPv6, nil local. Host and suffix tokens never yield a UDP rule; an
// `ip:53` / `ip:5353` / `ip:853` token yields none (it could never claim a datagram, and
// port "53" cannot even be named in an included rule). Under-inclusive is acceptable;
// over-inclusive never.
//
// Skipped silently (Design H): the wildcard addresses `0.0.0.0` and `::` (the header
// forbids them with port 0 and no real flow has that destination) and any address
// `Network.NWEndpoint.Host` does not parse as `.ipv4`/`.ipv6` (cannot happen for
// `IPText.canonical` output; kept as a guard).
//
// Canonical equality (Design G): `udpTargets` is sorted by address text then port with
// nil first, and de-duplicated, so two scopes with the same claimable IP set compare
// equal whatever the token order; the reconciler keys "nothing to apply" on that.
//
// Accepted consequence (Design I): a bare `ip` token yields a port-0 rule, which also
// diverts that IP's port-53 datagrams; the provider then declines them (claim rule D2)
// and such a socket suffers the IP_DONTFRAG defect. That is the operator's own target.

struct ProviderRuleSet: Equatable {
    /// One UDP-claimable IP token of the scope: a canonical IP text (`IPText.canonical`
    /// form, IPv6 unbracketed) and the token's port, nil for any port.
    struct UDPTarget: Equatable, Comparable {
        let address: String
        let port: UInt16?

        init(_ address: String, _ port: UInt16?) {
            self.address = address
            self.port = port
        }

        /// By address text, then port with nil (any) first.
        static func < (lhs: UDPTarget, rhs: UDPTarget) -> Bool {
            if lhs.address != rhs.address { return lhs.address < rhs.address }
            switch (lhs.port, rhs.port) {
            case (nil, nil): return false
            case (nil, _?): return true
            case (_?, nil): return false
            case (let l?, let r?): return l < r
            }
        }

        /// `a.b.c.d:port`, `[v6]:port`; `any` for a nil port. Used by `summary`.
        fileprivate var summaryText: String {
            let host = address.contains(":") ? "[\(address)]" : address
            return "\(host):\(port.map { String($0) } ?? "any")"
        }
    }

    /// Canonical: sorted (`UDPTarget.<`) and de-duplicated. Empty means TCP-only.
    let udpTargets: [UDPTarget]

    private init(udpTargets: [UDPTarget]) {
        self.udpTargets = udpTargets
    }

    /// The startup set and the set for any scope without a UDP-claimable IP token.
    static let tcpOnly = ProviderRuleSet(udpTargets: [])

    /// Wildcards the header forbids with port 0; no real flow has them as destination.
    private static let wildcardAddresses: Set<String> = ["0.0.0.0", "::"]

    /// The rule set wanted for `scope`: the TCP catch-all plus one UDP rule per
    /// claimable IP token, in canonical order. `nil` (no core attached) is TCP-only.
    static func wanted(for scope: ScopeMatcher?) -> ProviderRuleSet {
        var targets: [UDPTarget] = []
        for entry in scope?.udpClaimableIPEntries ?? [] {
            guard case .ip(let address) = entry.target else { continue }
            if wildcardAddresses.contains(address) { continue }
            guard hostAndPrefix(for: address) != nil else { continue }
            targets.append(UDPTarget(address, entry.port))
        }
        var canonical: [UDPTarget] = []
        for target in targets.sorted() where canonical.last != target {
            canonical.append(target)
        }
        return ProviderRuleSet(udpTargets: canonical)
    }

    /// The `NENetworkRule`s to install, TCP catch-all first, then one `.UDP` host rule
    /// per target in `udpTargets` order. Uses the non-deprecated macOS 15+ initializer
    /// (`…NetworkEndpoint:`, `Network.NWEndpoint`).
    func networkRules() -> [NENetworkRule] {
        var rules = [
            NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0,
                          localNetworkEndpoint: nil, localPrefix: 0,
                          protocol: .TCP, direction: .outbound),
        ]
        for target in udpTargets {
            guard let parsed = Self.hostAndPrefix(for: target.address) else { continue }
            // `Port(integerLiteral:)` is total over UInt16; `.any` is port 0 (= any
            // port, allowed because the address is not a wildcard).
            let port: Network.NWEndpoint.Port = target.port.map { Network.NWEndpoint.Port(integerLiteral: $0) } ?? .any
            rules.append(NENetworkRule(remoteNetworkEndpoint: .hostPort(host: parsed.host, port: port),
                                       remotePrefix: parsed.prefix,
                                       localNetworkEndpoint: nil, localPrefix: 0,
                                       protocol: .UDP, direction: .outbound))
        }
        return rules
    }

    /// For the "provider rules applied" log line (spec Design D): `1 rule (TCP
    /// catch-all)` or `N rules (TCP catch-all + UDP a:any, [b]:443, …)`. Scoped target
    /// addresses are the operator's own configuration, not user traffic.
    var summary: String {
        if udpTargets.isEmpty { return "1 rule (TCP catch-all)" }
        let targets = udpTargets.map(\.summaryText).joined(separator: ", ")
        return "\(1 + udpTargets.count) rules (TCP catch-all + UDP \(targets))"
    }

    /// The parsed host and the host-route prefix for a canonical IP text; nil when
    /// `Network.NWEndpoint.Host` does not read it as an IP address.
    private static func hostAndPrefix(for address: String) -> (host: Network.NWEndpoint.Host, prefix: Int)? {
        let host = Network.NWEndpoint.Host(address)
        switch host {
        case .ipv4: return (host, 32)
        case .ipv6: return (host, 128)
        case .name: return nil
        @unknown default: return nil
        }
    }
}

// MARK: - Self-checks (TR-AC1; run by apps/mac/tools/ne-selfcheck.sh)

#if DEBUG
extension HandoffSelfCheck {
    /// TR-AC1 of spec 2026-11-01-ne-tcp-only-catch-all-design: `ProviderRuleSet` is a pure
    /// function of the matcher, canonical under token order and duplicates, and the
    /// `NENetworkRule`s it builds read back with the literal protocol, direction, remote
    /// endpoint, prefix and nil local endpoint the spec names. No entitlement is needed
    /// to construct and read back an `NENetworkRule`.
    static func providerRules(_ r: Recorder) {
        typealias Target = ProviderRuleSet.UDPTarget
        let s6 = "198.51.100.7 203.0.113.9:4433 [2001:db8::3]:443 203.0.113.9:53 10.0.0.1:5353 example.com"
        let six = ScopeMatcher(spec: s6)
        r.check("providerRules: S6 spec parsed", six.entries.count == 6, "\(six.entries)")

        // -- TCP-only vectors (Design A, H) ------------------------------------
        let tcpOnlyVectors: [(String, ScopeMatcher?)] = [
            ("nil scope", nil),
            ("empty spec", ScopeMatcher(spec: "")),
            ("host and suffix tokens only", ScopeMatcher(spec: "example.com *.api.test:8443")),
            ("wildcard addresses", ScopeMatcher(spec: "0.0.0.0 [::]:4433")),
        ]
        for (label, scope) in tcpOnlyVectors {
            let w = ProviderRuleSet.wanted(for: scope)
            r.check("providerRules: \(label) -> tcpOnly", w == .tcpOnly, "\(w.udpTargets)")
            r.check("providerRules: \(label) -> no UDP targets", w.udpTargets.isEmpty, "\(w.udpTargets)")
        }
        // The wildcard vector must exercise the SKIP, not a parse failure: the matcher
        // does hold both IP entries; wanted(for:) is what drops them.
        r.check("providerRules: wildcard vector parses into two claimable IP entries",
              ScopeMatcher(spec: "0.0.0.0 [::]:4433").udpClaimableIPEntries.count == 2,
              "\(ScopeMatcher(spec: "0.0.0.0 [::]:4433").udpClaimableIPEntries)")
        r.check("providerRules: tcpOnly has no UDP targets", ProviderRuleSet.tcpOnly.udpTargets == [])

        // -- Canonical UDP targets (Design A, G) ---------------------------------
        let wantedSix = ProviderRuleSet.wanted(for: six)
        r.check("providerRules: S6 udpTargets sorted by address then port, :53/:5353 dropped",
              wantedSix.udpTargets == [
                  Target("198.51.100.7", nil),
                  Target("2001:db8::3", 443),
                  Target("203.0.113.9", 4433),
              ], "\(wantedSix.udpTargets)")
        r.check("providerRules: S6 is not tcpOnly", wantedSix != .tcpOnly)
        r.check("providerRules: UDPTarget orders nil port first within one address",
              Target("203.0.113.9", nil) < Target("203.0.113.9", 4433)
                  && !(Target("203.0.113.9", 4433) < Target("203.0.113.9", nil)))
        r.check("providerRules: UDPTarget orders by address text before port",
              Target("198.51.100.7", 443) < Target("2001:db8::3", nil))
        let samIPTwice = ProviderRuleSet.wanted(for: ScopeMatcher(spec: "203.0.113.9:4433 203.0.113.9"))
        r.check("providerRules: bare ip and ip:port of one address are two targets, bare first",
              samIPTwice.udpTargets == [Target("203.0.113.9", nil), Target("203.0.113.9", 4433)],
              "\(samIPTwice.udpTargets)")

        // -- Equality / idempotence (Design G) -----------------------------------
        for (label, scope) in tcpOnlyVectors + [("S6", six)] {
            r.check("providerRules: wanted(for:) idempotent for \(label)",
                  ProviderRuleSet.wanted(for: scope) == ProviderRuleSet.wanted(for: scope))
        }
        let a = ProviderRuleSet.wanted(for: ScopeMatcher(spec: "203.0.113.9:4433 198.51.100.7"))
        let b = ProviderRuleSet.wanted(for: ScopeMatcher(spec: "198.51.100.7 203.0.113.9:4433 198.51.100.7"))
        r.check("providerRules: token order and duplicates do not matter", a == b,
              "\(a.udpTargets) vs \(b.udpTargets)")
        r.check("providerRules: order/duplicate vector holds exactly two targets",
              a.udpTargets == [Target("198.51.100.7", nil), Target("203.0.113.9", 4433)], "\(a.udpTargets)")
        r.check("providerRules: a different port is a different set",
              ProviderRuleSet.wanted(for: ScopeMatcher(spec: "203.0.113.9:4433"))
                  != ProviderRuleSet.wanted(for: ScopeMatcher(spec: "203.0.113.9:4434")))
        r.check("providerRules: wanted(for: nil) == .tcpOnly", ProviderRuleSet.wanted(for: nil) == .tcpOnly)

        // -- networkRules() read-back (Design A) ---------------------------------
        // The remote endpoint is rendered as "<address>|<port>" from the read-back
        // `.hostPort(host:port:)`; "nil" for no remote. The literals are asserted.
        func remote(_ rule: NENetworkRule) -> String {
            guard let endpoint = rule.matchRemoteHostOrNetworkEndpoint else { return "nil" }
            guard case let .hostPort(host, port) = endpoint else { return "not hostPort: \(endpoint)" }
            switch host {
            case .ipv4(let address): return "\(address)|\(port.rawValue)"
            case .ipv6(let address): return "\(address)|\(port.rawValue)"
            case .name(let name, _): return "name \(name)|\(port.rawValue)"
            @unknown default: return "unknown host|\(port.rawValue)"
            }
        }
        func checkTCP(_ rule: NENetworkRule, _ label: String) {
            r.check("\(label) protocol .TCP", rule.matchProtocol == .TCP, "\(rule.matchProtocol.rawValue)")
            r.check("\(label) direction .outbound", rule.matchDirection == .outbound, "\(rule.matchDirection.rawValue)")
            r.check("\(label) nil remote", rule.matchRemoteHostOrNetworkEndpoint == nil, remote(rule))
            r.check("\(label) remote prefix 0", rule.matchRemotePrefix == 0, "\(rule.matchRemotePrefix)")
            r.check("\(label) nil local", rule.matchLocalNetworkEndpoint == nil,
                  "\(String(describing: rule.matchLocalNetworkEndpoint))")
        }
        func checkUDP(_ rule: NENetworkRule, _ label: String, host: String, port: UInt16, prefix: Int) {
            r.check("\(label) protocol .UDP", rule.matchProtocol == .UDP, "\(rule.matchProtocol.rawValue)")
            r.check("\(label) direction .outbound", rule.matchDirection == .outbound, "\(rule.matchDirection.rawValue)")
            r.check("\(label) remote \(host) port \(port)", remote(rule) == "\(host)|\(port)", remote(rule))
            r.check("\(label) remote prefix \(prefix)", rule.matchRemotePrefix == prefix, "\(rule.matchRemotePrefix)")
            r.check("\(label) nil local", rule.matchLocalNetworkEndpoint == nil,
                  "\(String(describing: rule.matchLocalNetworkEndpoint))")
        }

        let tcpRules = ProviderRuleSet.tcpOnly.networkRules()
        r.check("providerRules: tcpOnly.networkRules() count 1", tcpRules.count == 1, "\(tcpRules.count)")
        if let only = tcpRules.first { checkTCP(only, "providerRules: tcpOnly rule 0") }

        let sixRules = wantedSix.networkRules()
        r.check("providerRules: S6 networkRules() count 4", sixRules.count == 4, "\(sixRules.count)")
        if sixRules.count == 4 {
            checkTCP(sixRules[0], "providerRules: S6 rule 0")
            checkUDP(sixRules[1], "providerRules: S6 rule 1", host: "198.51.100.7", port: 0, prefix: 32)
            checkUDP(sixRules[2], "providerRules: S6 rule 2", host: "2001:db8::3", port: 443, prefix: 128)
            checkUDP(sixRules[3], "providerRules: S6 rule 3", host: "203.0.113.9", port: 4433, prefix: 32)
        }

        // -- summary (Design D) --------------------------------------------------
        r.check("providerRules: tcpOnly summary",
              ProviderRuleSet.tcpOnly.summary == "1 rule (TCP catch-all)", ProviderRuleSet.tcpOnly.summary)
        r.check("providerRules: S6 summary",
              wantedSix.summary == "4 rules (TCP catch-all + UDP 198.51.100.7:any, [2001:db8::3]:443, 203.0.113.9:4433)",
              wantedSix.summary)
    }
}
#endif
