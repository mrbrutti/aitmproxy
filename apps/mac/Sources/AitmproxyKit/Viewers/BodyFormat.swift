import Foundation

/// The Body tab's format picker (S-021): `Auto` resolves through
/// `BodyKind.detect`; every other case forces a viewer. The picker's words
/// are the `title`s, in `allCases` order.
public enum BodyFormat: String, CaseIterable, Identifiable, Hashable, Sendable {
    case auto, json, xml, html, js, css, form, multipart, markdown, text, hex

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .auto: "Auto"
        case .json: "JSON"
        case .xml: "XML"
        case .html: "HTML"
        case .js: "JS"
        case .css: "CSS"
        case .form: "Form"
        case .multipart: "Multipart"
        case .markdown: "Markdown"
        case .text: "Text"
        case .hex: "Hex"
        }
    }

    /// Formats shown as syntax-coloured text in the code viewer.
    public var isText: Bool {
        switch self {
        case .json, .xml, .html, .js, .css, .markdown, .text: true
        case .auto, .form, .multipart, .hex: false
        }
    }

    /// Markdown and HTML offer the "Rendered" toggle.
    public var isRenderable: Bool { self == .markdown || self == .html }

    /// JSON and XML get fold chevrons in the gutter.
    public var isFoldable: Bool { self == .json || self == .xml }

    /// The media type handed to `Syntax.runs(for:contentType:)` for colouring.
    public var syntaxContentType: String? {
        switch self {
        case .json: "application/json"
        case .xml: "application/xml"
        case .html: "text/html"
        case .js: "application/javascript"
        case .css: "text/css"
        case .markdown: "text/markdown"
        case .auto, .form, .multipart, .text, .hex: nil
        }
    }

    // MARK: Detection

    /// The concrete format for a message, from its content type first and its bytes otherwise.
    public static func detect(_ message: HTTPMessage) -> BodyFormat {
        let data = message.body ?? Data()
        let (type, _) = BodyKind.mediaType(message.contentType)
        if type.contains("markdown") { return .markdown }
        switch BodyKind.detect(contentType: message.contentType, data: data) {
        case .json: return .json
        case .xml: return .xml
        case .html: return .html
        case .javascript: return .js
        case .css: return .css
        case .form: return .form
        case .multipart: return .multipart
        case .text: return .text
        case .image, .protobuf, .messagepack, .binary: return .hex
        }
    }

    /// `auto` → the detected format; anything else stays as chosen.
    public func resolve(for message: HTTPMessage) -> BodyFormat {
        self == .auto ? BodyFormat.detect(message) : self
    }

    /// The multipart boundary when the message declares or shows one.
    public static func multipartBoundary(_ message: HTTPMessage) -> String? {
        if case .multipart(let boundary) = BodyKind.detect(contentType: message.contentType, data: message.body ?? Data()) {
            return boundary
        }
        return nil
    }

    // MARK: Text

    /// The text the code viewer shows for `format`: JSON reformatted with key
    /// order kept, XML indented, every other text format verbatim. Nil for
    /// `form`, `multipart` and `hex` (they have their own views), for an
    /// empty body, and for bytes that are not UTF-8 (the caller falls back to hex).
    public static func prettyText(_ message: HTTPMessage, as format: BodyFormat) -> String? {
        guard let data = message.body, !data.isEmpty else { return nil }
        let resolved = format.resolve(for: message)
        guard resolved.isText else { return nil }
        guard let raw = String(data: data, encoding: .utf8) else { return nil }
        switch resolved {
        case .json: return JSONTree.pretty(data) ?? raw
        case .xml: return XMLPretty.pretty(raw)
        default: return raw
        }
    }

    // MARK: Rendering safety

    /// HTML with everything that could load a remote resource or run code
    /// removed: `<script>` blocks, `<link>`, `<img>`, `<iframe>`, `<object>`,
    /// `<embed>`, `<video>`, `<audio>`, `<source>`, `<base>`, `<meta http-equiv>`,
    /// `on*=` handlers, `url(` inside style attributes and `<style>` blocks.
    /// The "Rendered" view feeds this to `NSAttributedString(html:)` so a
    /// response never phones home from the inspector (S-021).
    public static func sanitizedHTML(_ html: String) -> String {
        var text = html
        let blocks = ["script", "style", "iframe", "object", "video", "audio", "noscript", "template"]
        for tag in blocks {
            text = text.replacingOccurrences(
                of: "<\(tag)\\b[^>]*>[\\s\\S]*?</\(tag)\\s*>", with: "", options: [.regularExpression, .caseInsensitive])
        }
        let voids = ["script", "link", "img", "iframe", "embed", "source", "base", "meta", "object", "video", "audio", "track", "frame"]
        for tag in voids {
            text = text.replacingOccurrences(
                of: "<\(tag)\\b[^>]*/?>", with: "", options: [.regularExpression, .caseInsensitive])
            text = text.replacingOccurrences(of: "</\(tag)\\s*>", with: "", options: [.regularExpression, .caseInsensitive])
        }
        text = text.replacingOccurrences(
            of: "\\s+on[a-z]+\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)", with: "", options: [.regularExpression, .caseInsensitive])
        text = text.replacingOccurrences(of: "url\\s*\\(", with: "url-blocked(", options: [.regularExpression, .caseInsensitive])
        return text
    }
}

/// Line-by-line analysis for the code viewer, run off the main actor:
/// syntax runs as UTF-16 ranges, line starts for the gutter, and which
/// lines open a fold (`{` / `[` in JSON, an element in XML).
public enum CodeAnalysis {
    public struct Run: Hashable, Sendable {
        public var range: NSRange
        public var kind: SyntaxKind
        public init(range: NSRange, kind: SyntaxKind) {
            self.range = range
            self.kind = kind
        }
    }

    public struct Result: Hashable, Sendable {
        public var runs: [Run]
        public var lineStarts: [Int]
        public var foldableLines: Set<Int>
    }

    /// Whether a content type has a tokenizer here, so the editor only pays for
    /// live re-colouring when it will actually change the colours.
    public static func colours(contentType: String?) -> Bool {
        let type = contentType?.lowercased() ?? ""
        return ["json", "graphql", "xml", "html", "yaml", "yml", "rhai"].contains { type.contains($0) }
    }

    /// UTF-16 offset of every line's first character; `[0]` for an empty text.
    public static func lineStarts(_ text: String) -> [Int] {
        var starts = [0]
        var offset = 0
        for unit in text.utf16 {
            offset += 1
            if unit == 10 { starts.append(offset) }
        }
        return starts
    }

    @concurrent
    public static func analyse(text: String, contentType: String?) async -> Result {
        analyseNow(text: text, contentType: contentType)
    }

    /// The synchronous form, for small bodies and tests. Stops early when the task is cancelled.
    public static func analyseNow(text: String, contentType: String?) -> Result {
        let type = contentType?.lowercased() ?? ""
        let isJSON = type.contains("json") || type.contains("graphql")
        let isXML = type.contains("xml") || type.contains("html")
        let isYAML = type.contains("yaml") || type.contains("yml")
        let isRhai = type.contains("rhai")
        var runs: [Run] = []
        var starts: [Int] = []
        var foldable = Set<Int>()
        var offset = 0
        var lineIndex = 0
        // Rhai block comments and multiline strings carry across lines.
        var rhaiState = Syntax.RhaiState.code
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            if lineIndex % 2048 == 2047, Task.isCancelled { break }
            starts.append(offset)
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if isJSON, let last = trimmed.last, last == "{" || last == "[" {
                foldable.insert(lineIndex)
            } else if isXML, trimmed.hasPrefix("<"), !trimmed.hasPrefix("</"), !trimmed.hasPrefix("<?"),
                      !trimmed.hasPrefix("<!"), !trimmed.hasSuffix("/>"), !trimmed.contains("</") {
                foldable.insert(lineIndex)
            }
            // The token runs for this line, by language. Rhai threads its state.
            let lineRuns: [SyntaxRun]
            if isRhai {
                let tokenized = Syntax.rhai(line: String(line), continuing: rhaiState)
                lineRuns = tokenized.runs
                rhaiState = tokenized.next
            } else if isYAML {
                lineRuns = Syntax.yaml(line: String(line))
            } else if isJSON {
                lineRuns = Syntax.runs(for: String(line), contentType: contentType)
            } else {
                lineRuns = []
            }
            var cursor = offset
            for run in lineRuns {
                let length = run.text.utf16.count
                if run.kind != .plain { runs.append(Run(range: NSRange(location: cursor, length: length), kind: run.kind)) }
                cursor += length
            }
            offset += line.utf16.count + 1
            lineIndex += 1
        }
        return Result(runs: runs, lineStarts: starts.isEmpty ? [0] : starts, foldableLines: foldable)
    }
}

/// Find in body (S-029): case-insensitive plain search, or a regular
/// expression when asked. Empty matches are skipped; results are capped so a
/// one-character query on a 5 MB body stays responsive.
public enum BodySearch {
    public static let maxMatches = 20_000

    public struct InvalidPattern: Error, Equatable, Sendable {}

    public static func ranges(of query: String, in text: String, regex: Bool) throws -> [Range<String.Index>] {
        guard !query.isEmpty, !text.isEmpty else { return [] }
        var result: [Range<String.Index>] = []
        if regex {
            guard let expression = try? NSRegularExpression(pattern: query, options: [.caseInsensitive]) else {
                throw InvalidPattern()
            }
            let whole = NSRange(text.startIndex..., in: text)
            for match in expression.matches(in: text, range: whole) {
                guard match.range.length > 0, let range = Range(match.range, in: text) else { continue }
                result.append(range)
                if result.count >= maxMatches { break }
            }
        } else {
            var from = text.startIndex
            while from < text.endIndex,
                  let range = text.range(of: query, options: [.caseInsensitive], range: from..<text.endIndex) {
                result.append(range)
                if result.count >= maxMatches { break }
                from = range.upperBound
            }
        }
        return result
    }
}
