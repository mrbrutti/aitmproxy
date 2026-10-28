import Foundation

/// The content-type chip bar (foundation §2.7): `All | HTTP HTTPS WebSocket |
/// h1 h2 | JSON Form XML JS CSS GraphQL Document Media Other`.
public enum ContentCategory: String, CaseIterable, Hashable, Sendable, Identifiable {
    case all
    case http, https, websocket
    case h1, h2
    case json, form, xml, js, css, graphql, document, media, other

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .all: "All"
        case .http: "HTTP"
        case .https: "HTTPS"
        case .websocket: "WebSocket"
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

    /// The bar's groups, separated by a hairline.
    public static let groups: [[ContentCategory]] = [
        [.all],
        [.http, .https, .websocket],
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

    /// Whether a row passes this chip. Protocol chips look at scheme/kind/version; type chips at the content type.
    public func matches(row: FlowRow, contentType: String?, httpVersion: String?) -> Bool {
        switch self {
        case .all: true
        case .http: row.scheme == "http"
        case .https: row.scheme == "https"
        case .websocket: row.kind == .websocket
        case .h1: httpVersion?.hasPrefix("HTTP/1") ?? false
        case .h2: httpVersion?.hasPrefix("HTTP/2") ?? false
        default: Self.classify(contentType: contentType) == self
        }
    }
}
