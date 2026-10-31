import Foundation

/// The content-type chip bar (foundation §2.7; spec 2026-10-31 status page §4b): `All | HTTP
/// HTTPS WebSocket | TCP UDP L4 | h1 h2 | JSON Form XML JS CSS GraphQL Document Media Other`.
public enum ContentCategory: String, CaseIterable, Hashable, Sendable, Identifiable {
    case all
    case http, https, websocket
    /// Raw-L4 flows by transport; `l4` is every packet-level flow (ICMP, raw and other included).
    case tcp, udp, l4
    case h1, h2
    case json, form, xml, js, css, graphql, document, media, other

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .all: "All"
        case .http: "HTTP"
        case .https: "HTTPS"
        case .websocket: "WebSocket"
        case .tcp: "TCP"
        case .udp: "UDP"
        case .l4: "L4"
        case .h1: "h1"
        case .h2: "h2"
        case .json: "JSON"
        case .form: "Form"
        case .xml: "XML"
        case .js: "JS"
        case .css: "CSS"
        case .graphql: "GraphQL"
        case .document: "Document"
        case .media: "Media"
        case .other: "Other"
        }
    }

    /// The chip's hover help: what it keeps, starting with a verb.
    public var help: String {
        switch self {
        case .all: "Show every flow"
        case .http: "Keep plain HTTP flows"
        case .https: "Keep HTTPS flows"
        case .websocket: "Keep WebSocket connections"
        case .tcp: "Keep raw TCP sessions captured at L4"
        case .udp: "Keep raw UDP flows captured at L4"
        case .l4: "Keep every packet-level flow: TCP, UDP, ICMP and raw"
        case .h1: "Keep HTTP/1.x flows"
        case .h2: "Keep HTTP/2 flows"
        case .json: "Keep flows whose body is JSON"
        case .form: "Keep flows whose body is a form"
        case .xml: "Keep flows whose body is XML"
        case .js: "Keep JavaScript"
        case .css: "Keep style sheets"
        case .graphql: "Keep GraphQL flows"
        case .document: "Keep HTML, text and Markdown documents"
        case .media: "Keep images, video, audio and fonts"
        case .other: "Keep every other content type"
        }
    }

    /// The bar's groups, separated by a hairline: application protocols, then transport
    /// (raw L4), then HTTP versions, then content types.
    public static let groups: [[ContentCategory]] = [
        [.all],
        [.http, .https, .websocket],
        [.tcp, .udp, .l4],
        [.h1, .h2],
        [.json, .form, .xml, .js, .css, .graphql, .document, .media, .other],
    ]

    /// Classifies a response (or request) content type.
    public static func classify(contentType: String?) -> ContentCategory {
        guard let raw = contentType?.lowercased() else { return .other }
        let type = raw.split(separator: ";").first.map(String.init) ?? raw
        if type.contains("graphql") { return .graphql }
        if type.contains("json") { return .json }
        if type.contains("x-www-form-urlencoded") || type.contains("multipart/form-data") { return .form }
        if type.contains("xml") { return .xml }
        if type.contains("javascript") || type.contains("ecmascript") { return .js }
        if type.hasPrefix("text/css") { return .css }
        if type.hasPrefix("text/html") || type.hasPrefix("text/plain") || type.hasPrefix("text/markdown") { return .document }
        if type.hasPrefix("image/") || type.hasPrefix("video/") || type.hasPrefix("audio/") || type.hasPrefix("font/") { return .media }
        return .other
    }

    /// Whether a row passes this chip. Protocol chips look at scheme/kind/version, the L4 chips
    /// at the row's transport; type chips at the content type.
    public func matches(row: FlowRow, contentType: String?, httpVersion: String?) -> Bool {
        switch self {
        case .all: true
        case .http: row.scheme == "http"
        case .https: row.scheme == "https"
        case .websocket: row.kind == .websocket
        case .tcp: row.l4?.proto == .tcp
        case .udp: row.l4?.proto == .udp
        case .l4: row.kind == .l4
        case .h1: httpVersion?.hasPrefix("HTTP/1") ?? false
        case .h2: httpVersion?.hasPrefix("HTTP/2") ?? false
        default: Self.classify(contentType: contentType) == self
        }
    }
}
