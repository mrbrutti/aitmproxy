import Foundation

/// One HTTP message as the inspector shows it. Comes from F5 `flow.detail`
/// on the live bus.
public struct HTTPMessage: Hashable, Sendable {
    /// `POST /api/auth/login HTTP/2` or `HTTP/2 200 OK`.
    public var startLine: String
    /// Ordered, lowercase names as HTTP/2 sends them; duplicates kept.
    public var headers: [Header]
    public var body: Data?

    public struct Header: Hashable, Sendable {
        public var name: String
        public var value: String
        public init(_ name: String, _ value: String) {
            self.name = name
            self.value = value
        }
    }

    public init(startLine: String, headers: [Header], body: Data? = nil) {
        self.startLine = startLine
        self.headers = headers
        self.body = body
    }

    public func header(_ name: String) -> String? {
        headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    public var contentType: String? { header("content-type") }
    public var bodyText: String? { body.flatMap { String(data: $0, encoding: .utf8) } }
    public var bodyBytes: Int64 { Int64(body?.count ?? 0) }
}

/// Connection facts for the summary strip and the Connection tab.
public struct ConnectionInfo: Hashable, Sendable {
    public var httpVersion: String
    public var tlsVersion: String?
    public var alpn: String?
    public var sni: String?
    public var clientAddress: String?
    public var serverAddress: String?

    public init(httpVersion: String, tlsVersion: String? = nil, alpn: String? = nil, sni: String? = nil,
                clientAddress: String? = nil, serverAddress: String? = nil) {
        self.httpVersion = httpVersion
        self.tlsVersion = tlsVersion
        self.alpn = alpn
        self.sni = sni
        self.clientAddress = clientAddress
        self.serverAddress = serverAddress
    }
}

/// Everything the inspector needs for one flow.
public struct FlowDetail: Hashable, Sendable {
    public var id: FlowID
    /// The core connection this flow came from (Task 5), mirroring `FlowRow.coreID`.
    public var coreID: CoreID
    public var request: HTTPMessage
    public var response: HTTPMessage?
    public var connection: ConnectionInfo
    /// The request as it arrived, before any `flow.mutate` (the core's backup).
    public var originalRequest: HTTPMessage?
    /// Per-phase timing (F5); nil until the core reports it.
    public var timing: FlowTiming?
    /// Set when a body is paged or truncated (F5 `flow.detail {body: range}`).
    public var requestBodyExtent: BodyExtent?
    public var responseBodyExtent: BodyExtent?

    public init(id: FlowID, request: HTTPMessage, response: HTTPMessage? = nil,
                connection: ConnectionInfo, originalRequest: HTTPMessage? = nil, timing: FlowTiming? = nil,
                requestBodyExtent: BodyExtent? = nil, responseBodyExtent: BodyExtent? = nil,
                coreID: CoreID = .fixture) {
        self.id = id
        self.coreID = coreID
        self.request = request
        self.response = response
        self.connection = connection
        self.originalRequest = originalRequest
        self.timing = timing
        self.requestBodyExtent = requestBodyExtent
        self.responseBodyExtent = responseBodyExtent
    }
}
