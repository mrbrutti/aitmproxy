import Foundation

/// Per-phase timing for the Timing tab (foundation §3.3; F5 supplies the
/// phases). A missing phase is nil and prints as a dash; a real zero is `0 ms`.
public struct FlowTiming: Hashable, Sendable {
    public var dns: Duration?
    public var connect: Duration?
    public var tls: Duration?
    /// Request sent → first response byte.
    public var wait: Duration?
    public var download: Duration?

    public init(dns: Duration? = nil, connect: Duration? = nil, tls: Duration? = nil, wait: Duration? = nil,
                download: Duration? = nil) {
        self.dns = dns
        self.connect = connect
        self.tls = tls
        self.wait = wait
        self.download = download
    }

    public enum Phase: String, CaseIterable, Hashable, Sendable {
        case dns = "DNS", connect = "Connect", tls = "TLS", wait = "Wait", download = "Download"
    }

    public func duration(of phase: Phase) -> Duration? {
        switch phase {
        case .dns: dns
        case .connect: connect
        case .tls: tls
        case .wait: wait
        case .download: download
        }
    }

    /// The sum of the known phases.
    public var total: Duration {
        Phase.allCases.compactMap(duration(of:)).reduce(.zero, +)
    }
}

/// How much of a body the detail carries (foundation §2.7: large bodies
/// stream in pages; `truncated` shows a notice chip).
public struct BodyExtent: Hashable, Sendable {
    /// Bytes present in `HTTPMessage.body`.
    public var loaded: Int64
    /// Bytes the proxy holds in total.
    public var total: Int64

    public init(loaded: Int64, total: Int64) {
        self.loaded = loaded
        self.total = total
    }

    public var isTruncated: Bool { loaded < total }

    /// `truncated · 2.0 of 18.4 MB`
    public var chipText: String { "truncated · \(Format.bytes(loaded)) of \(Format.bytes(total))" }
}
