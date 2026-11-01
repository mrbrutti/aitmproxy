import AitmBusClient
import Foundation

/// The fields `flow.mutate {edits}` and `request.send` accept
/// (`crates/aitm-plugins/src/mutate.rs::edit_fields`). Headers replace
/// any existing header of the same name; a nil field is left alone. `status`
/// is valid only for a flow parked at the response phase (S-041), where the
/// core applies the edits to the response instead of the request.
public struct RequestEdits: Hashable, Sendable {
    public var method: String?
    public var scheme: String?
    public var authority: String?
    /// Path and query, as one string.
    public var path: String?
    public var headers: [String: String]?
    public var body: Data?
    /// Response status code; only for a response parked at the response phase.
    public var status: Int?

    public init(method: String? = nil, scheme: String? = nil, authority: String? = nil, path: String? = nil,
                headers: [String: String]? = nil, body: Data? = nil, status: Int? = nil) {
        self.method = method
        self.scheme = scheme
        self.authority = authority
        self.path = path
        self.headers = headers
        self.body = body
        self.status = status
    }

    public var isEmpty: Bool {
        method == nil && scheme == nil && authority == nil && path == nil && headers == nil && body == nil && status == nil
    }

    /// The `edits` object / `request.send` arguments. A UTF-8 body crosses as
    /// a string (the command accepts either); other bytes as base64.
    public var arguments: [String: JSONValue] {
        var args: [String: JSONValue] = [:]
        if let method { args["method"] = .string(method) }
        if let scheme { args["scheme"] = .string(scheme) }
        if let authority { args["authority"] = .string(authority) }
        if let path { args["path"] = .string(path) }
        if let status { args["status"] = .number(Double(status)) }
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
        var edits = headersAndBody(from: original, to: edited)
        if original.startLine != edited.startLine {
            let parts = edited.startLine.split(separator: " ").map(String.init)
            if parts.count >= 2 {
                edits.method = parts[0]
                edits.path = parts[1]
            }
        }
        return edits
    }

    /// The edits that turn a parked response `original` into `edited` (S-041):
    /// headers and body as for a request, plus `status` when the code changed. A
    /// reason phrase alone is not an edit; the core writes its own.
    public static func diff(fromResponse original: HTTPMessage, to edited: HTTPMessage) -> RequestEdits {
        var edits = headersAndBody(from: original, to: edited)
        if let code = edited.statusCode, code != original.statusCode { edits.status = code }
        return edits
    }

    /// Headers and body edits. Headers are compared as the list of values per name,
    /// so a message with two `set-cookie` lines and an untouched header list yields
    /// no header edit. `flow.mutate {headers}` carries one value per name (the core
    /// removes every header of that name, then sets the one), so a changed name is
    /// encoded only when its edited list has exactly one value; a multi-value
    /// change is left out and reported by `unencodableHeaderNames`, never collapsed.
    private static func headersAndBody(from original: HTTPMessage, to edited: HTTPMessage) -> RequestEdits {
        var edits = RequestEdits()
        var changed: [String: String] = [:]
        let before = valuesByName(original)
        for (name, values) in valuesByName(edited) where before[name] != values && values.count == 1 {
            changed[name] = values[0]
        }
        if !changed.isEmpty { edits.headers = changed }
        if original.body != edited.body { edits.body = edited.body ?? Data() }
        return edits
    }

    /// Header values grouped by lowercased name, in message order.
    static func valuesByName(_ message: HTTPMessage) -> [String: [String]] {
        var byName: [String: [String]] = [:]
        for header in message.headers { byName[header.name.lowercased(), default: []].append(header.value) }
        return byName
    }

    /// Names whose edited values differ from the original and have more than one
    /// value — a change `flow.mutate {headers}` cannot carry (one value per name).
    /// `diff` leaves them out so the client never gets a collapsed header; the UI
    /// says so, as it does for a removal.
    public static func unencodableHeaderNames(from original: HTTPMessage, to edited: HTTPMessage) -> [String] {
        let before = valuesByName(original)
        return valuesByName(edited)
            .filter { name, values in before[name] != values && values.count > 1 }
            .keys.sorted()
    }

    /// Header names present in `original` but absent in `edited` — an attempted
    /// removal. `flow.mutate` only *replaces* headers (it has no removal form yet,
    /// see `crates/aitm-plugins/src/mutate.rs`), so `diff` cannot encode these and
    /// a removal would otherwise be a silent no-op. Surfaced so the UI can tell the
    /// operator a removal will not take effect until the core gains a removal form.
    public static func removedHeaderNames(from original: HTTPMessage, to edited: HTTPMessage) -> [String] {
        let kept = Set(edited.headers.map { $0.name.lowercased() })
        var names: [String] = []
        for header in original.headers where !kept.contains(header.name.lowercased()) {
            if !names.contains(where: { $0.caseInsensitiveCompare(header.name) == .orderedSame }) {
                names.append(header.name)
            }
        }
        return names
    }
}
