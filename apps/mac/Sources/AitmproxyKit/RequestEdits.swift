import AitmBusClient
import Foundation

/// The request fields `flow.mutate {edits}` and `request.send` accept
/// (`crates/aitm-plugins/src/mutate.rs::request_fields`). Headers replace
/// any existing header of the same name; a nil field is left alone.
public struct RequestEdits: Hashable, Sendable {
    public var method: String?
    public var scheme: String?
    public var authority: String?
    /// Path and query, as one string.
    public var path: String?
    public var headers: [String: String]?
    public var body: Data?

    public init(method: String? = nil, scheme: String? = nil, authority: String? = nil, path: String? = nil,
                headers: [String: String]? = nil, body: Data? = nil) {
        self.method = method
        self.scheme = scheme
        self.authority = authority
        self.path = path
        self.headers = headers
        self.body = body
    }

    public var isEmpty: Bool {
        method == nil && scheme == nil && authority == nil && path == nil && headers == nil && body == nil
    }

    /// The `edits` object / `request.send` arguments. A UTF-8 body crosses as
    /// a string (the command accepts either); other bytes as base64.
    public var arguments: [String: JSONValue] {
        var args: [String: JSONValue] = [:]
        if let method { args["method"] = .string(method) }
        if let scheme { args["scheme"] = .string(scheme) }
        if let authority { args["authority"] = .string(authority) }
        if let path { args["path"] = .string(path) }
        if let headers { args["headers"] = .object(headers.mapValues { .string($0) }) }
        if let body {
            if let text = String(data: body, encoding: .utf8) {
                args["body"] = .string(text)
            } else {
                args["body"] = .string(body.base64EncodedString())
            }
        }
        return args
    }

    /// The edits that turn `original` into `edited` (headers added or changed, body if different).
    public static func diff(from original: HTTPMessage, to edited: HTTPMessage) -> RequestEdits {
        var edits = RequestEdits()
        var changed: [String: String] = [:]
        for header in edited.headers where original.header(header.name) != header.value {
            changed[header.name] = header.value
        }
        if !changed.isEmpty { edits.headers = changed }
        if original.body != edited.body { edits.body = edited.body ?? Data() }
        if original.startLine != edited.startLine {
            let parts = edited.startLine.split(separator: " ").map(String.init)
            if parts.count >= 2 {
                edits.method = parts[0]
                edits.path = parts[1]
            }
        }
        return edits
    }
}
