import Foundation

/// The raw-message form of a request the operator edits while it is paused
/// (S-037, S-038): start line, headers, a blank line, the body. Parsing is
/// forgiving about CRLF and trailing whitespace; errors name the line.
public enum RawHTTP {
    public struct ParseError: Error, Hashable, Sendable, CustomStringConvertible {
        public var line: Int
        public var message: String
        public init(line: Int, message: String) {
            self.line = line
            self.message = message
        }
        public var description: String { "line \(line): \(message)" }
    }

    /// LF-joined text for an editor (the wire form uses CRLF; see `CodeExport.rawHTTP`).
    public static func render(_ message: HTTPMessage) -> String {
        var lines = [message.startLine]
        lines += message.headers.map { "\($0.name): \($0.value)" }
        lines.append("")
        var text = lines.joined(separator: "\n")
        if let body = message.bodyText, !body.isEmpty { text += "\n" + body }
        return text
    }

    /// Parses editor text back into a message. A body that is not UTF-8
    /// cannot come through an editor, so bodies are always text here.
    public static func parse(_ text: String) throws(ParseError) -> HTTPMessage {
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
        let lines = normalized.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard let first = lines.first?.trimmingCharacters(in: .whitespaces), !first.isEmpty else {
            throw ParseError(line: 1, message: "the first line must be the request line, like POST /path HTTP/2")
        }
        let parts = first.split(separator: " ").map(String.init)
        guard parts.count >= 2 else {
            throw ParseError(line: 1, message: "the request line needs a method and a path")
        }
        guard parts[0].allSatisfy({ $0.isUppercase || $0.isNumber || $0 == "-" }) else {
            throw ParseError(line: 1, message: "\(parts[0]) is not an HTTP method")
        }
        var headers: [HTTPMessage.Header] = []
        var index = 1
        while index < lines.count {
            let line = lines[index]
            if line.trimmingCharacters(in: .whitespaces).isEmpty { break }
            guard let colon = line.firstIndex(of: ":"), colon != line.startIndex else {
                throw ParseError(line: index + 1, message: "expected `name: value`")
            }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces)
            guard !name.contains(" ") else {
                throw ParseError(line: index + 1, message: "a header name has no spaces")
            }
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers.append(.init(name.lowercased(), value))
            index += 1
        }
        var body: Data?
        if index < lines.count {
            let rest = lines[(index + 1)...].joined(separator: "\n")
            body = rest.isEmpty ? nil : Data(rest.utf8)
        }
        let startLine = parts.count >= 3 ? first : first + " HTTP/2"
        return HTTPMessage(startLine: startLine, headers: headers, body: body)
    }
}

extension RequestEdits {
    /// How many things the diff changes: each header, the body, the start line.
    public var changeCount: Int {
        (headers?.count ?? 0) + (body == nil ? 0 : 1) + (method == nil && path == nil ? 0 : 1)
    }
}
