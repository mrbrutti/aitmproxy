import Foundation
import Network
import NetworkExtension
import os.log

// EXPERIMENT experiment/macos-ne-observe-survey (research 12 §5 items 6, 7, 8; spec
// 2026-10-31-macos-ne-observe-only-lane-design.md Open question 6). THROWAWAY, never merged.
//
// Logging-only variant of the shipped provider. Claiming is UNCHANGED: the same
// `SelfExclusion.isSelf` check, the same `FlowHandoff.handleTCP/handleUDP`, the same
// fail-open `false`. The only addition: for every flow the provider DECLINES it appends
// one metadata-only `SURVEY` line (category `survey`) with the fields the observe-only
// lane would carry, plus the monotonic time spent in `isSelf`, in one
// `proc_pidpath_audittoken` call, and in the claim path. No payload bytes, no `open()`,
// no hostname text (only whether set and its length), no executable path text (only its
// length). A `SURVEY-RATE` line every 60 s carries counters kept in-process so a dropped
// log line cannot hide a burst.

@objc(TransparentProxyProvider)
final class TransparentProxyProvider: NETransparentProxyProvider, NEAppProxyUDPFlowHandling {
    private let log = OSLog(subsystem: "com.mrbrutti.aitmproxy.ne", category: "provider")
    private let survey = OSLog(subsystem: "com.mrbrutti.aitmproxy.ne", category: "survey")
    private let handoff = FlowHandoff()
    private let stats = SurveyStats()

    override func startProxy(options: [String: Any]? = nil,
                             completionHandler: @escaping (Error?) -> Void) {
        os_log("startProxy", log: log, type: .default)
        os_log("SURVEY-START variant=observe-survey pid=%{public}d", log: survey, type: .default, getpid())
        handoff.start()
        stats.start(log: survey)
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
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
        stats.stop(log: survey)
        handoff.stop()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let t0 = SurveyClock.now()
        let isSelf = SelfExclusion.isSelf(sourceAppAuditToken: flow.metaData.sourceAppAuditToken)
        let selfNs = SurveyClock.now() - t0
        let tcp = flow as? NEAppProxyTCPFlow
        if isSelf {
            record(flow, kind: tcp == nil ? "?" : "T", remote: tcp?.remoteFlowEndpoint,
                   why: "self", selfNs: selfNs, claimNs: 0, t0: t0)
            return false
        }
        guard let tcp else {
            record(flow, kind: "?", remote: nil, why: "nontcp", selfNs: selfNs, claimNs: 0, t0: t0)
            return false
        }
        let c0 = SurveyClock.now()
        let claimed = handoff.handleTCP(tcp)
        let claimNs = SurveyClock.now() - c0
        if !claimed {
            record(tcp, kind: "T", remote: tcp.remoteFlowEndpoint, why: "unclaimed",
                   selfNs: selfNs, claimNs: claimNs, t0: t0)
        }
        return claimed
    }

    func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow,
                          initialRemoteFlowEndpoint remoteEndpoint: Network.NWEndpoint) -> Bool {
        let t0 = SurveyClock.now()
        let isSelf = SelfExclusion.isSelf(sourceAppAuditToken: flow.metaData.sourceAppAuditToken)
        let selfNs = SurveyClock.now() - t0
        if isSelf {
            record(flow, kind: "U", remote: remoteEndpoint, why: "self", selfNs: selfNs, claimNs: 0, t0: t0)
            return false
        }
        let c0 = SurveyClock.now()
        let claimed = handoff.handleUDP(flow, initialRemote: remoteEndpoint)
        let claimNs = SurveyClock.now() - c0
        if !claimed {
            record(flow, kind: "U", remote: remoteEndpoint, why: "unclaimed",
                   selfNs: selfNs, claimNs: claimNs, t0: t0)
        }
        return claimed
    }

    // MARK: survey

    /// One metadata-only line per declined flow. Field meanings:
    ///   k        T (TCP) | U (UDP) | ? (neither class)
    ///   why      self | nontcp | unclaimed (declined by the unchanged claim path)
    ///   ep       ip:port, [ip6]:port, `name:<port>` (hostname-typed endpoint, name withheld),
    ///            service | url | unix | opaque | nil
    ///   hn       remoteHostname: -1 nil, else its UTF-8 length (text withheld)
    ///   sid      sourceAppSigningIdentifier non-empty (1) or empty (0)
    ///   tok      sourceAppAuditToken: 0 nil, 1 present (32 bytes), 2 present but wrong size
    ///   euid/pid from the audit token (libbsm's audit_token_to_euid/pid are val[1]/val[5])
    ///   ffid     filterFlowIdentifier non-nil (1) or nil (0)
    ///   if       networkInterface name or -
    ///   self_ns  monotonic ns spent in SelfExclusion.isSelf
    ///   pp_ns    monotonic ns spent in one proc_pidpath_audittoken call (0 when no token)
    ///   pp_len   bytes proc_pidpath_audittoken returned (0 = failed; path text withheld)
    ///   claim_ns monotonic ns spent in FlowHandoff.handleTCP/handleUDP (0 when not reached)
    ///   total_ns monotonic ns from entry to just before this log call
    private func record(_ flow: NEAppProxyFlow, kind: String, remote: Network.NWEndpoint?,
                        why: String, selfNs: UInt64, claimNs: UInt64, t0: UInt64) {
        let meta = flow.metaData
        var tok = 0
        var euid: UInt32 = 0
        var pid: UInt32 = 0
        var ppNs: UInt64 = 0
        var ppLen: Int32 = 0
        if let data = meta.sourceAppAuditToken {
            if data.count == MemoryLayout<audit_token_t>.size {
                tok = 1
                var token = audit_token_t()
                _ = withUnsafeMutableBytes(of: &token) { data.copyBytes(to: $0) }
                euid = token.val.1
                pid = token.val.5
                var buffer = [CChar](repeating: 0, count: 4096)
                let p0 = SurveyClock.now()
                ppLen = proc_pidpath_audittoken(&token, &buffer, UInt32(buffer.count))
                ppNs = SurveyClock.now() - p0
            } else {
                tok = 2
            }
        }
        let hn = flow.remoteHostname.map { $0.utf8.count } ?? -1
        let sid = meta.sourceAppSigningIdentifier.isEmpty ? 0 : 1
        let ffid = meta.filterFlowIdentifier == nil ? 0 : 1
        let iface = flow.networkInterface.map { String(cString: nw_interface_get_name($0)) } ?? "-"
        let ep = Self.describe(remote)
        let total = SurveyClock.now() - t0
        stats.count(kind: kind, why: why, selfNs: selfNs, ppNs: ppNs, totalNs: total)
        os_log("SURVEY k=%{public}@ why=%{public}@ ep=%{public}@ hn=%{public}ld sid=%{public}ld tok=%{public}ld euid=%{public}u pid=%{public}u ffid=%{public}ld if=%{public}@ self_ns=%{public}llu pp_ns=%{public}llu pp_len=%{public}d claim_ns=%{public}llu total_ns=%{public}llu",
               log: survey, type: .default,
               kind, why, ep, hn, sid, tok, euid, pid, ffid, iface, selfNs, ppNs, ppLen, claimNs, total)
    }

    private static func describe(_ endpoint: Network.NWEndpoint?) -> String {
        guard let endpoint else { return "nil" }
        switch endpoint {
        case .hostPort(let host, let port):
            switch host {
            case .ipv4(let address): return "\(address):\(port.rawValue)"
            case .ipv6(let address): return "[\(address)]:\(port.rawValue)"
            case .name: return "name:\(port.rawValue)"
            @unknown default: return "host?:\(port.rawValue)"
            }
        case .service: return "service"
        case .url: return "url"
        case .unix: return "unix"
        case .opaque: return "opaque"
        @unknown default: return "unknown"
        }
    }
}

enum SurveyClock {
    static func now() -> UInt64 { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) }
}

/// In-process counters so a burst is measured even if the log store throttles lines.
/// `SURVEY-RATE` every 60 s: totals since start, per-kind counts, the busiest single
/// second ever seen and in the last interval, and avg/max of the two timed calls.
final class SurveyStats: @unchecked Sendable {
    private let lock = NSLock()
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "com.mrbrutti.aitmproxy.ne.survey", qos: .utility)
    private let startedAt = SurveyClock.now()

    private var total = 0, tcp = 0, udp = 0, selfCount = 0
    private var intervalCount = 0
    private var currentSecond: UInt64 = 0, inSecond = 0
    private var maxPerSecond = 0, intervalMaxPerSecond = 0
    private var selfNsSum: UInt64 = 0, selfNsMax: UInt64 = 0
    private var ppNsSum: UInt64 = 0, ppNsMax: UInt64 = 0, ppCount = 0
    private var totalNsMax: UInt64 = 0

    func start(log: OSLog) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 60, repeating: 60, leeway: .seconds(1))
        timer.setEventHandler { [weak self] in self?.emit(log: log, final: false) }
        timer.resume()
        self.timer = timer
    }

    func stop(log: OSLog) {
        timer?.cancel()
        timer = nil
        emit(log: log, final: true)
    }

    func count(kind: String, why: String, selfNs: UInt64, ppNs: UInt64, totalNs: UInt64) {
        let second = SurveyClock.now() / 1_000_000_000
        lock.lock()
        total += 1
        intervalCount += 1
        if kind == "T" { tcp += 1 } else if kind == "U" { udp += 1 }
        if why == "self" { selfCount += 1 }
        if second == currentSecond {
            inSecond += 1
        } else {
            currentSecond = second
            inSecond = 1
        }
        maxPerSecond = max(maxPerSecond, inSecond)
        intervalMaxPerSecond = max(intervalMaxPerSecond, inSecond)
        selfNsSum += selfNs
        selfNsMax = max(selfNsMax, selfNs)
        if ppNs > 0 {
            ppNsSum += ppNs
            ppNsMax = max(ppNsMax, ppNs)
            ppCount += 1
        }
        totalNsMax = max(totalNsMax, totalNs)
        lock.unlock()
    }

    private func emit(log: OSLog, final: Bool) {
        lock.lock()
        let uptime = (SurveyClock.now() - startedAt) / 1_000_000_000
        let selfAvg = total > 0 ? selfNsSum / UInt64(total) : 0
        let ppAvg = ppCount > 0 ? ppNsSum / UInt64(ppCount) : 0
        let line = (uptime, total, tcp, udp, selfCount, intervalCount, maxPerSecond, intervalMaxPerSecond,
                    selfAvg, selfNsMax, ppAvg, ppNsMax, totalNsMax)
        intervalCount = 0
        intervalMaxPerSecond = 0
        lock.unlock()
        os_log("SURVEY-RATE final=%{public}d uptime_s=%{public}llu total=%{public}ld tcp=%{public}ld udp=%{public}ld self=%{public}ld last60s=%{public}ld max_1s=%{public}ld max_1s_last60s=%{public}ld self_ns_avg=%{public}llu self_ns_max=%{public}llu pp_ns_avg=%{public}llu pp_ns_max=%{public}llu total_ns_max=%{public}llu",
               log: log, type: .default, final ? 1 : 0,
               line.0, line.1, line.2, line.3, line.4, line.5, line.6, line.7,
               line.8, line.9, line.10, line.11, line.12)
    }
}
