import Foundation

/// One client connection as the Connection Log lists it (S-064). Until
/// `flow.detail` (F5) reports connections, records are derived from the
/// captured flows: one per distinct client address and authority.
public struct ConnectionRecord: Identifiable, Hashable, Sendable {
    public enum Result: Hashable, Sendable {
        case ok
        case error(String)

        /// `ok`, or the error as written.
        public var text: String {
            switch self {
            case .ok: "ok"
            case .error(let message): message
            }
        }

        public var isError: Bool {
            if case .error = self { return true }
            return false
        }
    }

    /// Client address and authority, so one connection keeps its identity as flows arrive.
    public var id: String { "\(client) \(authority)" }
    /// When the first flow on the connection started.
    public var at: Date
    /// The client's `address:port`.
    public var client: String
    public var authority: String
    /// `TLS 1.3`; nil for plain HTTP and for tunnelled CONNECTs the proxy did not open.
    public var tls: String?
    public var alpn: String?
    public var sni: String?
    public var result: Result
    /// The flows carried on this connection, in capture order.
    public var flowIDs: [FlowID]

    public init(at: Date, client: String, authority: String, tls: String? = nil, alpn: String? = nil,
                sni: String? = nil, result: Result = .ok, flowIDs: [FlowID] = []) {
        self.at = at
        self.client = client
        self.authority = authority
        self.tls = tls
        self.alpn = alpn
        self.sni = sni
        self.result = result
        self.flowIDs = flowIDs
    }

    /// One record per distinct `(clientAddress, authority)`, in time order. A
    /// connection is an error when any of its flows failed or got a 5xx.
    public static func derive(rows: [FlowRow], details: [FlowID: FlowDetail]) -> [ConnectionRecord] {
        var records: [ConnectionRecord] = []
        var index: [String: Int] = [:]
        for row in rows {
            let connection = details[row.id]?.connection
            let client = connection?.clientAddress ?? Format.dash
            let tunnelled = row.tls == .tunnelled
            let key = "\(client) \(row.authority)"
            let at = row.startedAt ?? Date(timeIntervalSince1970: 0)
            if let i = index[key] {
                records[i].flowIDs.append(row.id)
                records[i].at = min(records[i].at, at)
                if records[i].result == .ok, let error = failure(of: row) { records[i].result = .error(error) }
                if records[i].tls == nil, !tunnelled { records[i].tls = connection?.tlsVersion }
                if records[i].alpn == nil, !tunnelled { records[i].alpn = connection?.alpn }
                if records[i].sni == nil { records[i].sni = connection?.sni }
            } else {
                index[key] = records.count
                records.append(ConnectionRecord(
                    at: at, client: client, authority: row.authority,
                    tls: tunnelled ? nil : connection?.tlsVersion,
                    alpn: tunnelled ? nil : connection?.alpn,
                    sni: connection?.sni,
                    result: failure(of: row).map(Result.error) ?? .ok,
                    flowIDs: [row.id]))
            }
        }
        return records.enumerated()
            .sorted { $0.element.at == $1.element.at ? $0.offset < $1.offset : $0.element.at < $1.element.at }
            .map(\.element)
    }

    /// `502 Bad Gateway` for a 5xx, `failed` for a transport failure, nil otherwise.
    static func failure(of row: FlowRow) -> String? {
        if row.state == .failed { return "failed" }
        guard let status = row.status, StatusClass(status) == .serverError else { return nil }
        let reason = StatusText.reason(status)
        return reason.isEmpty ? String(status) : "\(status) \(reason)"
    }
}
