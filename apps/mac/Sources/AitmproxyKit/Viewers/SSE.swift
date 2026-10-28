import Foundation

/// One server-sent event as the SSE tab lists it (S-025). A comment line
/// (`: keep-alive`) is kept as its own dimmed row with `isComment` set.
public struct SSEEvent: Hashable, Sendable {
    /// The last event ID the client would hold when this event fires.
    public var id: String?
    /// The `event:` type; nil means `message`.
    public var event: String?
    /// Every `data:` line joined with `\n`; the comment text for a comment row.
    public var data: String
    public var retry: Int?
    public var isComment: Bool
    /// 0-based position in the stream; the row identity until F4 gives timestamps.
    public var order: Int

    public init(id: String? = nil, event: String? = nil, data: String, retry: Int? = nil, isComment: Bool = false,
                order: Int) {
        self.id = id
        self.event = event
        self.data = data
        self.retry = retry
        self.isComment = isComment
        self.order = order
    }
}

/// `text/event-stream` parsing per the WHATWG EventSource spec: CRLF, CR
/// or LF end a line; `field: value` with one optional space after the colon;
/// `data:` lines accumulate and join with `\n`; a blank line dispatches; an
/// event the stream ends in the middle of is dropped.
public enum SSE {
    public static func parse(_ text: String) -> [SSEEvent] {
        var events: [SSEEvent] = []
        var data: String?
        var eventType: String?
        var lastID: String?
        var retry: Int?

        func dispatch() {
            defer { data = nil; eventType = nil; retry = nil }
            guard var payload = data else { return }
            if payload.hasSuffix("\n") { payload.removeLast() }
            events.append(SSEEvent(id: lastID, event: eventType, data: payload, retry: retry, order: events.count))
        }

        for line in lines(of: text) {
            if line.isEmpty {
                dispatch()
                continue
            }
            if line.hasPrefix(":") {
                let comment = line.dropFirst()
                events.append(SSEEvent(id: lastID, data: String(comment.hasPrefix(" ") ? comment.dropFirst() : comment),
                                       isComment: true, order: events.count))
                continue
            }
            let field: Substring
            var value: Substring
            if let colon = line.firstIndex(of: ":") {
                field = line[..<colon]
                value = line[line.index(after: colon)...]
                if value.hasPrefix(" ") { value = value.dropFirst() }
            } else {
                field = line[...]
                value = ""
            }
            switch field {
            case "event":
                eventType = String(value)
            case "data":
                data = (data ?? "") + value + "\n"
            case "id":
                if !value.contains("\u{0}") { lastID = String(value) }
            case "retry":
                if let n = Int(value), value.allSatisfy(\.isNumber) { retry = n }
            default:
                continue
            }
        }
        return events
    }

    /// Complete lines (terminator removed). A final line with no terminator
    /// is not complete and is left out, as the spec's stream processing does.
    static func lines(of text: String) -> [Substring] {
        var lines: [Substring] = []
        var start = text.unicodeScalars.startIndex
        var pendingCR = false
        let scalars = text.unicodeScalars
        var index = scalars.startIndex
        if scalars.first == "\u{FEFF}" {
            index = scalars.index(after: index)
            start = index
        }
        while index < scalars.endIndex {
            let scalar = scalars[index]
            let next = scalars.index(after: index)
            if scalar == "\r" {
                lines.append(text[start..<index])
                start = next
                pendingCR = true
            } else if scalar == "\n" {
                if pendingCR {
                    start = next
                } else {
                    lines.append(text[start..<index])
                    start = next
                }
                pendingCR = false
            } else {
                pendingCR = false
            }
            index = next
        }
        return lines
    }

    /// OpenAI-style streams: the `choices[0].delta.content` strings of every
    /// JSON event concatenated, `[DONE]` skipped. Nil when no event has that shape.
    public static func mergedDeltas(_ events: [SSEEvent]) -> String? {
        var merged = ""
        var matched = false
        for event in events where !event.isComment {
            let payload = event.data.trimmingCharacters(in: .whitespacesAndNewlines)
            guard payload != "[DONE]", !payload.isEmpty, let root = try? JSONTree.parse(payload) else { continue }
            guard let choices = root.children.first(where: { $0.key == "choices" }),
                  let first = choices.children.first,
                  let delta = first.children.first(where: { $0.key == "delta" }),
                  case .object = delta.kind else { continue }
            matched = true
            if let content = delta.children.first(where: { $0.key == "content" }), content.kind == .string {
                merged += content.scalarText
            }
        }
        return matched ? merged : nil
    }
}
