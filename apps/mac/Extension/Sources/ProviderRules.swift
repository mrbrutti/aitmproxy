import Foundation
import Network
import NetworkExtension

// MARK: - Provider rule set (spec 2026-11-01-ne-tcp-only-catch-all-design, Design A, G, H, I)
//
// Why TCP-only by default: the shipped `.any` catch-all diverted every UDP flow too, and
// while it was installed `setsockopt(IP_DONTFRAG)` on every connected non-loopback UDP
// socket failed with ECONNRESET (research 24 §4), which costs Chromium HTTP/3
// system-wide even though the provider declines every datagram.
//
// Why one `.UDP` rule per UDP-claimable IP token (R2) and not one UDP catch-all (R1): it
// is exactly the matcher's UDP claim set, so the kernel diverts only what the provider
// can claim and the defect is confined to sockets aimed at the operator's own target.
// Under-inclusive is acceptable -- a skipped target is merely not captured, and the
// claim path (`CoreLink.current()`, `ScopeMatcher.matches`) still decides every flow;
// over-inclusive never. Accepted cost (Design I): a bare `ip` token's port-0 rule also
// diverts that IP's port-53 datagrams, which the provider then declines (claim rule D2).
//
// The rule shape, skip set, cap and canonical form are spec Design A/G/H and the doc
// comments on `ProviderRuleSet` below; `wanted(for:)` is the ONE function that builds
// every rule set, startup included (`tcpOnly == wanted(for: nil)`).

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

    /// Canonical: sorted (`UDPTarget.<`), de-duplicated, at most `maxUDPTargets` (the
    /// first ones in that order). Empty means TCP-only.
    let udpTargets: [UDPTarget]
    /// How many canonical targets the cap left out (0 when under it). Part of equality,
    /// so a scope that only changes beyond the cap still counts as a change.
    let dropped: Int

    private init(udpTargets: [UDPTarget], dropped: Int) {
        self.udpTargets = udpTargets
        self.dropped = dropped
    }

    /// The startup set and the set for any scope without a UDP-claimable IP token.
    static let tcpOnly = ProviderRuleSet(udpTargets: [], dropped: 0)

    /// Upper bound on UDP rules per set (spec Design A as amended): the framework
    /// documents no rule-count limit, so the bound is ours; under-inclusive beyond it.
    static let maxUDPTargets = 256

    /// Wildcards the header forbids with port 0; no real flow has them as destination.
    private static let wildcardAddresses: Set<String> = ["0.0.0.0", "::"]
    /// The IPv4 limited broadcast; `IPv4Address` has no property for it.
    private static let limitedBroadcast = "255.255.255.255"

    /// The rule set wanted for `scope`: the TCP catch-all plus one UDP rule per
    /// claimable IP token (`ScopeMatcher.udpClaimableIPEntries`: `.ip` entries whose
    /// port is nil or not 53/5353/853; host and suffix tokens never qualify), in
    /// canonical order, capped at `maxUDPTargets`. `nil` (no core attached) is TCP-only.
    /// Skipped silently (spec Design H as amended): wildcards,
    /// loopback, multicast, the limited broadcast, and any text `Network.NWEndpoint.Host`
    /// does not read as an IP (cannot happen for `IPText.canonical` output; a guard).
    static func wanted(for scope: ScopeMatcher?) -> ProviderRuleSet {
        var targets: [UDPTarget] = []
        for entry in scope?.udpClaimableIPEntries ?? [] {
            guard case .ip(let address) = entry.target else { continue }
            guard let parsed = hostAndPrefix(for: address), !isSkipped(parsed.host, text: address) else { continue }
            targets.append(UDPTarget(address, entry.port))
        }
        var canonical: [UDPTarget] = []
        for target in targets.sorted() where canonical.last != target {
            canonical.append(target)
        }
        let kept = Array(canonical.prefix(maxUDPTargets))
        return ProviderRuleSet(udpTargets: kept, dropped: canonical.count - kept.count)
    }

    /// The `NENetworkRule`s to install (spec Design A, R2): first the TCP catch-all --
    /// `.TCP`, `.outbound`, nil remote, prefix 0, nil local (every TCP flow except
    /// loopback) -- then one `.UDP` `.outbound` rule per target in `udpTargets` order,
    /// remote = the target's address with its port or `0` (any), prefix 32 for IPv4 and
    /// 128 for IPv6, nil local. Uses the non-deprecated macOS 15+ initializer
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
    /// catch-all)` or `N rules (TCP catch-all + UDP a:any, [b]:443, …)`; when the cap
    /// left K targets out, `N rules, K dropped (TCP catch-all + UDP …)`. The drop count
    /// sits at the HEAD, before up to 256 targets (~5-6 KiB): os_log truncates a long
    /// dynamic argument from its tail, and the drop is the one signal the cap exists
    /// for (fix R2-1). Scoped target addresses are the operator's own configuration,
    /// not user traffic.
    var summary: String {
        if udpTargets.isEmpty { return "1 rule (TCP catch-all)" }
        let targets = udpTargets.map(\.summaryText).joined(separator: ", ")
        let droppedText = dropped > 0 ? ", \(dropped) dropped" : ""
        return "\(1 + udpTargets.count) rules\(droppedText) (TCP catch-all + UDP \(targets))"
    }

    /// Addresses that yield no rule: the wildcards (the header forbids them with port 0
    /// and no real flow has that destination), loopback (the kernel never diverts it,
    /// NE header "except loopback"), multicast, and the IPv4 limited broadcast -- one
    /// rule the kernel rejects would block the whole set. Under-inclusive by design.
    private static func isSkipped(_ host: Network.NWEndpoint.Host, text address: String) -> Bool {
        if wildcardAddresses.contains(address) || address == limitedBroadcast { return true }
        switch host {
        case .ipv4(let v4):
            // `isLoopback` matches only 127.0.0.1 on the macOS 27 SDK (pinned by the
            // 127.200.1.2 vector); the whole 127/8 block is loopback, so test the octet.
            return v4.isLoopback || v4.rawValue.first == 127 || v4.isMulticast
        case .ipv6(let v6): return v6.isLoopback || v6.isMulticast
        case .name: return true
        @unknown default: return true
        }
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
    /// The remote endpoint of `rule` as `"<address>|<port>"` from the read-back
    /// `.hostPort(host:port:)`; `"nil"` for no remote. Shared by the rule groups so
    /// every literal pin reads the same rendering.
    private static func remoteText(_ rule: NENetworkRule) -> String {
        guard let endpoint = rule.matchRemoteHostOrNetworkEndpoint else { return "nil" }
        guard case let .hostPort(host, port) = endpoint else { return "not hostPort: \(endpoint)" }
        switch host {
        case .ipv4(let address): return "\(address)|\(port.rawValue)"
        case .ipv6(let address): return "\(address)|\(port.rawValue)"
        case .name(let name, _): return "name \(name)|\(port.rawValue)"
        @unknown default: return "unknown host|\(port.rawValue)"
        }
    }

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
        // `remoteText` renders the read-back remote endpoint as "<address>|<port>";
        // "nil" for no remote. The literals are asserted.
        func checkTCP(_ rule: NENetworkRule, _ label: String) {
            r.check("\(label) protocol .TCP", rule.matchProtocol == .TCP, "\(rule.matchProtocol.rawValue)")
            r.check("\(label) direction .outbound", rule.matchDirection == .outbound, "\(rule.matchDirection.rawValue)")
            r.check("\(label) nil remote", rule.matchRemoteHostOrNetworkEndpoint == nil, remoteText(rule))
            r.check("\(label) remote prefix 0", rule.matchRemotePrefix == 0, "\(rule.matchRemotePrefix)")
            r.check("\(label) nil local", rule.matchLocalNetworkEndpoint == nil,
                  "\(String(describing: rule.matchLocalNetworkEndpoint))")
        }
        func checkUDP(_ rule: NENetworkRule, _ label: String, host: String, port: UInt16, prefix: Int) {
            r.check("\(label) protocol .UDP", rule.matchProtocol == .UDP, "\(rule.matchProtocol.rawValue)")
            r.check("\(label) direction .outbound", rule.matchDirection == .outbound, "\(rule.matchDirection.rawValue)")
            r.check("\(label) remote \(host) port \(port)", remoteText(rule) == "\(host)|\(port)", remoteText(rule))
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

    /// Tester (stage 5) edge vectors for the pure rule set, as reached through
    /// `wanted(for:)`: a large shuffled token set with every token twice stays canonical
    /// under the cap; a 300-target set is capped at 256 in canonical order with the
    /// dropped count in the summary; an IPv4-mapped IPv6 token is unmapped by `IPText.canonical` and
    /// yields the SAME /32 IPv4 rule as the plain token; a spec made only of
    /// never-claimed ports, wildcards (any port -- spec H is unconditional) and malformed
    /// tokens is TCP-only; loopback, multicast and the limited broadcast are skipped like
    /// the wildcards (spec H as amended, fix F5), in their IPv4-mapped and long-form
    /// spellings too; the cap counts canonical targets only (duplicates and skipped tokens
    /// never inflate `dropped`, 257 drops exactly one); the summary's count prefix follows
    /// the rule count.
    static func providerRulesEdges(_ r: Recorder) {
        typealias Target = ProviderRuleSet.UDPTarget

        // -- Large, shuffled, duplicated input: under the cap, canonical order --------
        var distinct: [(address: String, port: UInt16?, token: String)] = []
        for i in 0..<64 {
            distinct.append(("10.1.\(i).9", UInt16(4000 + i), "10.1.\(i).9:\(4000 + i)"))
        }
        for i in 1...8 {
            distinct.append(("2001:db8::\(i)", nil, "[2001:db8::\(i)]"))
        }
        // A fixed permutation (7 is coprime to 72); every token twice; a host token and
        // an ip:53 token between each pair as noise that must yield nothing.
        var tokens: [String] = []
        for k in 0..<72 {
            let item = distinct[(k * 7) % 72]
            tokens.append(item.token)
            tokens.append("example.com")
            tokens.append(item.token)
            tokens.append("10.9.9.9:53")
        }
        let big = ScopeMatcher(spec: tokens.joined(separator: " "))
        r.check("providerRulesEdges: big spec parsed every token", big.entries.count == 72 * 4, "\(big.entries.count)")
        let wantedBig = ProviderRuleSet.wanted(for: big)
        r.check("providerRulesEdges: 72 distinct targets, none dropped, none duplicated",
              wantedBig.udpTargets.count == 72, "\(wantedBig.udpTargets.count)")
        // Literal canonical order, TEXT not numeric (fix F7: never computed with the
        // comparator under test): "10.1.10.9" sorts right after "10.1.1.9", "10.1.19.9"
        // is followed by "10.1.2.9", the last IPv4 text is "10.1.9.9", and every IPv6
        // text ("2001…") sorts after every IPv4 text ("10.…").
        r.check("providerRulesEdges: big targets 0-3 are 10.1.0.9:4000, 10.1.1.9:4001, 10.1.10.9:4010, 10.1.11.9:4011",
              Array(wantedBig.udpTargets.prefix(4)) == [Target("10.1.0.9", 4000), Target("10.1.1.9", 4001),
                                                        Target("10.1.10.9", 4010), Target("10.1.11.9", 4011)],
              "\(wantedBig.udpTargets.prefix(4))")
        r.check("providerRulesEdges: big targets 11-12 are 10.1.19.9:4019 then 10.1.2.9:4002",
              wantedBig.udpTargets.count == 72 && wantedBig.udpTargets[11] == Target("10.1.19.9", 4019)
                  && wantedBig.udpTargets[12] == Target("10.1.2.9", 4002),
              wantedBig.udpTargets.count == 72 ? "\(wantedBig.udpTargets[11...12])" : "\(wantedBig.udpTargets.count)")
        r.check("providerRulesEdges: big targets 63-64 are the last IPv4 10.1.9.9:4009 then the first IPv6 [2001:db8::1]:any",
              wantedBig.udpTargets.count == 72 && wantedBig.udpTargets[63] == Target("10.1.9.9", 4009)
                  && wantedBig.udpTargets[64] == Target("2001:db8::1", nil),
              wantedBig.udpTargets.count == 72 ? "\(wantedBig.udpTargets[63...64])" : "\(wantedBig.udpTargets.count)")
        r.check("providerRulesEdges: big target 71 is [2001:db8::8]:any",
              wantedBig.udpTargets.last == Target("2001:db8::8", nil), "\(String(describing: wantedBig.udpTargets.last))")
        let bigRules = wantedBig.networkRules()
        r.check("providerRulesEdges: big set builds 73 rules (under the 256 cap)", bigRules.count == 73, "\(bigRules.count)")
        if bigRules.count == 73 {
            r.check("providerRulesEdges: big rule 0 is the TCP catch-all",
                  bigRules[0].matchProtocol == .TCP && bigRules[0].matchRemoteHostOrNetworkEndpoint == nil
                      && bigRules[0].matchRemotePrefix == 0)
            r.check("providerRulesEdges: big rule 1 is the text-first address 10.1.0.9:4000 /32",
                  bigRules[1].matchProtocol == .UDP && remoteText(bigRules[1]) == "10.1.0.9|4000"
                      && bigRules[1].matchRemotePrefix == 32,
                  remoteText(bigRules[1]))
            r.check("providerRulesEdges: big rule 72 is the text-last address [2001:db8::8]:any /128",
                  bigRules[72].matchProtocol == .UDP && remoteText(bigRules[72]) == "2001:db8::8|0"
                      && bigRules[72].matchRemotePrefix == 128,
                  remoteText(bigRules[72]))
            r.check("providerRulesEdges: every big rule is outbound with nil local",
                  bigRules.allSatisfy { $0.matchDirection == .outbound && $0.matchLocalNetworkEndpoint == nil })
        }
        r.check("providerRulesEdges: big summary counts 73 rules and starts with the text-first target",
              wantedBig.summary.hasPrefix("73 rules (TCP catch-all + UDP 10.1.0.9:4000, "), wantedBig.summary)
        r.check("providerRulesEdges: big summary ends with the last IPv6 target bracketed",
              wantedBig.summary.hasSuffix(", [2001:db8::8]:any)"), wantedBig.summary)
        r.check("providerRulesEdges: big set equals its reversed, newline-separated token order",
              ProviderRuleSet.wanted(for: ScopeMatcher(spec: tokens.reversed().joined(separator: "\n"))) == wantedBig)

        // -- Over the cap (fix F4): 300 distinct targets keep the first 256 in canonical
        //    order and record the rest as dropped. Every "10.2.0.x" sorts before every
        //    "10.2.1.y" by text, so exactly the 256 "10.2.0.*" targets survive.
        var capTokens: [String] = []
        for i in 0..<300 {
            capTokens.append("10.2.\(i / 256).\(i % 256):\(5000 + i)")
        }
        let capped = ProviderRuleSet.wanted(for: ScopeMatcher(spec: capTokens.joined(separator: " ")))
        r.check("providerRulesEdges: cap vector parses 300 claimable entries",
              ScopeMatcher(spec: capTokens.joined(separator: " ")).udpClaimableIPEntries.count == 300)
        r.check("providerRulesEdges: 300 targets are capped at 256", capped.udpTargets.count == 256, "\(capped.udpTargets.count)")
        r.check("providerRulesEdges: maxUDPTargets is 256", ProviderRuleSet.maxUDPTargets == 256, "\(ProviderRuleSet.maxUDPTargets)")
        r.check("providerRulesEdges: 44 targets recorded as dropped", capped.dropped == 44, "\(capped.dropped)")
        r.check("providerRulesEdges: capped first target is 10.2.0.0:5000",
              capped.udpTargets.first == Target("10.2.0.0", 5000), "\(String(describing: capped.udpTargets.first))")
        r.check("providerRulesEdges: capped last target is the text-last 10.2.0.99:5099",
              capped.udpTargets.last == Target("10.2.0.99", 5099), "\(String(describing: capped.udpTargets.last))")
        r.check("providerRulesEdges: no 10.2.1.* target survives the cap",
              capped.udpTargets.allSatisfy { $0.address.hasPrefix("10.2.0.") }, "\(capped.udpTargets.suffix(3))")
        r.check("providerRulesEdges: capped set builds 257 rules", capped.networkRules().count == 257,
              "\(capped.networkRules().count)")
        r.check("providerRulesEdges: capped summary starts with 257 rules, 44 dropped, then the first target (fix R2-1: the count at the head)",
              capped.summary.hasPrefix("257 rules, 44 dropped (TCP catch-all + UDP 10.2.0.0:5000, "), capped.summary)
        r.check("providerRulesEdges: capped summary ends with the last target and nothing after it",
              capped.summary.hasSuffix(", 10.2.0.99:5099)") && !capped.summary.contains("(+"), capped.summary)
        r.check("providerRulesEdges: the cap is canonical (reversed token order gives the same set)",
              ProviderRuleSet.wanted(for: ScopeMatcher(spec: capTokens.reversed().joined(separator: "\n"))) == capped)
        let justKept = ProviderRuleSet.wanted(for: ScopeMatcher(spec: capTokens.prefix(256).joined(separator: " ")))
        r.check("providerRulesEdges: the kept 256 alone are the same targets", justKept.udpTargets == capped.udpTargets)
        r.check("providerRulesEdges: equality keys on the dropped count too (256 kept + 44 dropped != 256 kept + 0)",
              justKept != capped)
        r.check("providerRulesEdges: the kept 256 alone drop nothing", justKept.dropped == 0, "\(justKept.dropped)")
        r.check("providerRulesEdges: an uncapped summary has no dropped count anywhere",
              !justKept.summary.contains("dropped"), justKept.summary)
        r.check("providerRulesEdges: an uncapped 257-rule summary keeps the plain form (count, then the targets)",
              justKept.summary.hasPrefix("257 rules (TCP catch-all + UDP 10.2.0.0:5000, ")
                  && justKept.summary.hasSuffix(", 10.2.0.99:5099)"),
              justKept.summary)
        r.check("providerRulesEdges: the 72-target set and tcpOnly drop nothing",
              wantedBig.dropped == 0 && ProviderRuleSet.tcpOnly.dropped == 0, "\(wantedBig.dropped)")

        // -- IPv4-mapped IPv6 token: unmapped to the /32 IPv4 rule ------------------
        let mapped = ProviderRuleSet.wanted(for: ScopeMatcher(spec: "[::ffff:198.51.100.7]:443"))
        let plain = ProviderRuleSet.wanted(for: ScopeMatcher(spec: "198.51.100.7:443"))
        r.check("providerRulesEdges: IPv4-mapped IPv6 token equals the plain IPv4 token", mapped == plain,
              "\(mapped.udpTargets) vs \(plain.udpTargets)")
        r.check("providerRulesEdges: IPv4-mapped target carries the IPv4 text",
              mapped.udpTargets == [Target("198.51.100.7", 443)], "\(mapped.udpTargets)")
        let mappedRules = mapped.networkRules()
        r.check("providerRulesEdges: IPv4-mapped rule is .UDP to 198.51.100.7:443 /32",
              mappedRules.count == 2 && mappedRules[1].matchProtocol == .UDP
                  && remoteText(mappedRules[1]) == "198.51.100.7|443" && mappedRules[1].matchRemotePrefix == 32,
              mappedRules.count == 2 ? remoteText(mappedRules[1]) + " /\(mappedRules[1].matchRemotePrefix)" : "\(mappedRules.count) rules")

        // -- Only never-claimed, wildcard and malformed tokens: TCP-only -------------
        let junk = "[2001:db8::3 198.51.100.7:0 198.51.100.7:65536 10.0.0.1:53 10.0.0.2:5353 10.0.0.3:853 "
            + "0.0.0.0 [::]:443 0.0.0.0:8080 [::ffff:0.0.0.0] * *.example.com example.com:443 999.1.1.1 :443"
        let junkSet = ProviderRuleSet.wanted(for: ScopeMatcher(spec: junk))
        r.check("providerRulesEdges: never-claimed, wildcard and malformed tokens are TCP-only",
              junkSet == .tcpOnly, "\(junkSet.udpTargets)")
        r.check("providerRulesEdges: that set builds exactly one rule", junkSet.networkRules().count == 1,
              "\(junkSet.networkRules().count)")
        r.check("providerRulesEdges: that summary is the TCP-only line",
              junkSet.summary == "1 rule (TCP catch-all)", junkSet.summary)
        r.check("providerRulesEdges: a wildcard with a non-zero port is still skipped (spec H is unconditional)",
              ProviderRuleSet.wanted(for: ScopeMatcher(spec: "0.0.0.0:8080 [::]:443")) == .tcpOnly)
        r.check("providerRulesEdges: the matcher does hold those wildcard-with-port entries (the skip is in wanted)",
              ScopeMatcher(spec: "0.0.0.0:8080 [::]:443").udpClaimableIPEntries.count == 2)
        r.check("providerRulesEdges: a separators-only spec is TCP-only",
              ProviderRuleSet.wanted(for: ScopeMatcher(spec: " ,;\n\t")) == .tcpOnly)
        // Loopback, multicast and the IPv4 limited broadcast are skipped (spec H as
        // amended): the kernel never diverts loopback, and one rule it rejects would
        // block the whole set. The matcher does hold these entries; the skip is in wanted.
        let skippedTokens = ["127.0.0.1:9000", "[::1]:9000", "224.0.0.251", "224.0.0.251:9000",
                             "[ff02::fb]:5353", "[ff02::fb]:9000", "255.255.255.255:1900",
                             "127.0.0.1", "[::1]", "255.255.255.255", "127.200.1.2:443", "[ff05::1:3]:547"]
        for token in skippedTokens {
            let w = ProviderRuleSet.wanted(for: ScopeMatcher(spec: token))
            r.check("providerRulesEdges: \(token) -> tcpOnly", w == .tcpOnly, "\(w.udpTargets)")
        }
        r.check("providerRulesEdges: the matcher holds every skipped token but the :5353 one as claimable",
              ScopeMatcher(spec: skippedTokens.joined(separator: " ")).udpClaimableIPEntries.count == skippedTokens.count - 1,
              "\(ScopeMatcher(spec: skippedTokens.joined(separator: " ")).udpClaimableIPEntries.count)")
        let mixed = ProviderRuleSet.wanted(for: ScopeMatcher(spec: "127.0.0.1:9000 198.51.100.7:443 [::1] 224.0.0.251 255.255.255.255"))
        r.check("providerRulesEdges: a real target survives beside skipped loopback/multicast/broadcast tokens",
              mixed.udpTargets == [Target("198.51.100.7", 443)] && mixed.dropped == 0, "\(mixed.udpTargets)")
        r.check("providerRulesEdges: skipped tokens are not counted as dropped",
              ProviderRuleSet.wanted(for: ScopeMatcher(spec: "127.0.0.1:9000 [::1]:9000")).dropped == 0)

        // IPv4-mapped IPv6 and long-form spellings of the skipped addresses are
        // canonicalised by the matcher first (`IPText.canonical` unmaps `::ffff:a.b.c.d`)
        // and then skipped like the plain text; an IPv6 multicast of another scope too.
        let spelledSkipped = ["[::ffff:127.0.0.1]:443", "[::ffff:127.200.1.2]:443", "[::ffff:224.0.0.251]:9000",
                              "[::ffff:255.255.255.255]:1900", "[0:0:0:0:0:0:0:1]:9000",
                              "[0000:0000:0000:0000:0000:0000:0000:0001]", "[ff0e::1]:9000"]
        for token in spelledSkipped {
            let w = ProviderRuleSet.wanted(for: ScopeMatcher(spec: token))
            r.check("providerRulesEdges: \(token) -> tcpOnly", w == .tcpOnly, "\(w.udpTargets)")
        }
        r.check("providerRulesEdges: the matcher holds every re-spelled skipped token as claimable (the skip is in wanted)",
              ScopeMatcher(spec: spelledSkipped.joined(separator: " ")).udpClaimableIPEntries.count == spelledSkipped.count,
              "\(ScopeMatcher(spec: spelledSkipped.joined(separator: " ")).udpClaimableIPEntries.count)")
        r.check("providerRulesEdges: the mapped 127.200.1.2 is unmapped to the IPv4 text before the skip",
              ScopeMatcher(spec: "[::ffff:127.200.1.2]:443").udpClaimableIPEntries
                  == [ScopeMatcher.Entry(target: .ip("127.200.1.2"), port: 443)],
              "\(ScopeMatcher(spec: "[::ffff:127.200.1.2]:443").udpClaimableIPEntries)")

        // -- Cap edges (fix F4): the cap counts CANONICAL targets, so duplicates never
        //    inflate `dropped`, skipped tokens count toward neither the cap nor `dropped`,
        //    and exactly one over the cap drops exactly one (the text-last target).
        let capTwice = ProviderRuleSet.wanted(for: ScopeMatcher(spec: (capTokens + capTokens).joined(separator: " ")))
        r.check("providerRulesEdges: every cap token twice is the same capped set (duplicates do not inflate dropped)",
              capTwice == capped, "\(capTwice.udpTargets.count) kept, \(capTwice.dropped) dropped")
        let skippedNoise = ["127.0.0.1:9000", "[::1]:9000", "224.0.0.251", "255.255.255.255:1900", "0.0.0.0", "10.9.9.9:53", "example.com"]
        let capPlusSkipped = ProviderRuleSet.wanted(
            for: ScopeMatcher(spec: (Array(capTokens.prefix(256)) + skippedNoise).joined(separator: " ")))
        r.check("providerRulesEdges: skipped tokens beside exactly 256 targets count toward neither the cap nor dropped",
              capPlusSkipped == justKept && capPlusSkipped.dropped == 0 && capPlusSkipped.udpTargets.count == 256,
              "\(capPlusSkipped.udpTargets.count) kept, \(capPlusSkipped.dropped) dropped")
        let oneOver = ProviderRuleSet.wanted(for: ScopeMatcher(spec: capTokens.prefix(257).joined(separator: " ")))
        r.check("providerRulesEdges: 257 targets keep 256 and drop 1",
              oneOver.udpTargets.count == 256 && oneOver.dropped == 1, "\(oneOver.udpTargets.count) kept, \(oneOver.dropped) dropped")
        r.check("providerRulesEdges: the one dropped is the text-last 10.2.1.0 (the kept 256 are unchanged)",
              oneOver.udpTargets == justKept.udpTargets, "\(String(describing: oneOver.udpTargets.last))")
        r.check("providerRulesEdges: 257-target summary is 257 rules, 1 dropped (TCP catch-all + UDP … 10.2.0.99:5099)",
              oneOver.summary.hasPrefix("257 rules, 1 dropped (TCP catch-all + UDP 10.2.0.0:5000, ")
                  && oneOver.summary.hasSuffix(", 10.2.0.99:5099)") && !oneOver.summary.contains("(+"),
              oneOver.summary)
        r.check("providerRulesEdges: 257 and 300 targets with the same kept 256 are different sets (dropped 1 vs 44)",
              oneOver != capped && oneOver.udpTargets == capped.udpTargets)
    }
}
#endif
