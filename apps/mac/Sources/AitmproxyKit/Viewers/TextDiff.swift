import Foundation

public enum DiffKind: Hashable, Sendable {
    case equal, insert, delete
}

/// One line of a line-based diff with its 1-based line numbers on each side.
public struct DiffLine: Hashable, Sendable {
    public var kind: DiffKind
    public var text: String
    /// Line number in the old text; nil for an insert.
    public var oldLine: Int?
    /// Line number in the new text; nil for a delete.
    public var newLine: Int?

    public init(kind: DiffKind, text: String, oldLine: Int? = nil, newLine: Int? = nil) {
        self.kind = kind
        self.text = text
        self.oldLine = oldLine
        self.newLine = newLine
    }

    /// The unified-format prefix: ` `, `+` or `-`.
    public var marker: String {
        switch kind {
        case .equal: " "
        case .insert: "+"
        case .delete: "-"
        }
    }
}

/// A run of changed lines with their context, as unified format groups them.
public struct DiffHunk: Hashable, Sendable {
    public var oldStart: Int
    public var oldCount: Int
    public var newStart: Int
    public var newCount: Int
    public var lines: [DiffLine]

    public init(oldStart: Int, oldCount: Int, newStart: Int, newCount: Int, lines: [DiffLine]) {
        self.oldStart = oldStart
        self.oldCount = oldCount
        self.newStart = newStart
        self.newCount = newCount
        self.lines = lines
    }

    /// `@@ -1,4 +1,5 @@` (a count of 1 is omitted, as diff does).
    public var header: String {
        "@@ -\(Self.range(oldStart, oldCount)) +\(Self.range(newStart, newCount)) @@"
    }

    private static func range(_ start: Int, _ count: Int) -> String {
        count == 1 ? "\(start)" : "\(start),\(count)"
    }
}

/// One row of the two-column view.
public struct DiffPair: Hashable, Sendable {
    public enum Kind: Hashable, Sendable {
        case equal, insert, delete
        /// A deleted line paired with the inserted line that replaced it.
        case change
    }

    public var left: DiffLine?
    public var right: DiffLine?
    public var kind: Kind

    public init(left: DiffLine?, right: DiffLine?, kind: Kind) {
        self.left = left
        self.right = right
        self.kind = kind
    }
}

/// A line-based diff of two texts. Patience diff on unique lines with Myers
/// (O(ND)) inside the gaps; each side is capped at `maxBytesPerSide` and the
/// `truncated` flag says when the cap cut something off.
public struct TextDiff: Hashable, Sendable {
    /// 2 MB per side; the inspector's "large body" notice takes over above that.
    public static let maxBytesPerSide = 2 * 1024 * 1024
    /// Myers gives up on a single gap past this many edits and reports the gap as
    /// delete-all / insert-all. Keeps memory at O(D²) ≈ 32 MB worst case.
    static let maxEditDistance = 2000

    /// The whole edit script in order, equal lines included.
    public var lines: [DiffLine]
    public var truncated: Bool

    public init(lines: [DiffLine], truncated: Bool = false) {
        self.lines = lines
        self.truncated = truncated
    }

    public init(old: String, new: String) {
        let (oldText, oldCut) = Self.cap(old)
        let (newText, newCut) = Self.cap(new)
        let oldLines = Self.splitLines(oldText)
        let newLines = Self.splitLines(newText)
        lines = Self.diff(old: oldLines, new: newLines)
        truncated = oldCut || newCut
    }

    public var hasChanges: Bool { lines.contains { $0.kind != .equal } }
    public var insertions: Int { lines.filter { $0.kind == .insert }.count }
    public var deletions: Int { lines.filter { $0.kind == .delete }.count }

    // MARK: Output

    /// Changed lines grouped with `contextLines` equal lines around them.
    public func hunks(contextLines: Int = 3) -> [DiffHunk] {
        let context = max(0, contextLines)
        var ranges: [Range<Int>] = []
        var i = 0
        while i < lines.count {
            guard lines[i].kind != .equal else { i += 1; continue }
            var end = i + 1
            while end < lines.count, lines[end].kind != .equal { end += 1 }
            let lower = max(0, i - context)
            let upper = min(lines.count, end + context)
            if let last = ranges.last, lower <= last.upperBound {
                ranges[ranges.count - 1] = last.lowerBound..<max(last.upperBound, upper)
            } else {
                ranges.append(lower..<upper)
            }
            i = end
        }
        return ranges.map { range in
            let slice = Array(lines[range])
            let oldCount = slice.filter { $0.oldLine != nil }.count
            let newCount = slice.filter { $0.newLine != nil }.count
            let oldStart = oldCount > 0
                ? (slice.compactMap(\.oldLine).first ?? 1)
                : (lines[..<range.lowerBound].reversed().compactMap(\.oldLine).first ?? 0)
            let newStart = newCount > 0
                ? (slice.compactMap(\.newLine).first ?? 1)
                : (lines[..<range.lowerBound].reversed().compactMap(\.newLine).first ?? 0)
            return DiffHunk(oldStart: oldStart, oldCount: oldCount, newStart: newStart, newCount: newCount, lines: slice)
        }
    }

    /// Standard unified format, ending with a newline; empty when nothing changed.
    public func unified(oldName: String = "a", newName: String = "b", contextLines: Int = 3) -> String {
        let hunks = hunks(contextLines: contextLines)
        guard !hunks.isEmpty else { return "" }
        var out = "--- \(oldName)\n+++ \(newName)\n"
        for hunk in hunks {
            out += hunk.header
            out += "\n"
            for line in hunk.lines {
                out += line.marker
                out += line.text
                out += "\n"
            }
        }
        return out
    }

    /// Rows for the two-column view: equal lines on both sides, a delete paired
    /// with the insert that follows it in the same change run (`.change`), the
    /// rest one-sided.
    public func sideBySide() -> [DiffPair] {
        var pairs: [DiffPair] = []
        var i = 0
        while i < lines.count {
            let line = lines[i]
            if line.kind == .equal {
                pairs.append(DiffPair(left: line, right: line, kind: .equal))
                i += 1
                continue
            }
            var deletes: [DiffLine] = []
            var inserts: [DiffLine] = []
            while i < lines.count, lines[i].kind != .equal {
                if lines[i].kind == .delete { deletes.append(lines[i]) } else { inserts.append(lines[i]) }
                i += 1
            }
            for n in 0..<max(deletes.count, inserts.count) {
                let left = n < deletes.count ? deletes[n] : nil
                let right = n < inserts.count ? inserts[n] : nil
                let kind: DiffPair.Kind
                switch (left, right) {
                case (.some, .some): kind = .change
                case (.some, .none): kind = .delete
                default: kind = .insert
                }
                pairs.append(DiffPair(left: left, right: right, kind: kind))
            }
        }
        return pairs
    }

    // MARK: Input

    /// Cuts the text at the byte cap on a line boundary.
    static func cap(_ text: String) -> (String, Bool) {
        let utf8 = text.utf8
        guard utf8.count > maxBytesPerSide else { return (text, false) }
        var end = utf8.index(utf8.startIndex, offsetBy: maxBytesPerSide)
        if let newline = utf8[..<end].lastIndex(of: 0x0A) { end = newline }
        return (String(decoding: utf8[..<end], as: UTF8.self), true)
    }

    /// Lines without their LF or CRLF terminators; a trailing newline does not
    /// add an empty line. Splits on bytes because Swift treats `\r\n` as one Character.
    static func splitLines(_ text: String) -> [String] {
        guard !text.isEmpty else { return [] }
        var lines = text.utf8.split(separator: 0x0A, omittingEmptySubsequences: false).map { slice -> String in
            let bytes = slice.last == 0x0D ? slice.dropLast() : slice[...]
            return String(decoding: bytes, as: UTF8.self)
        }
        if lines.last == "" { lines.removeLast() }
        return lines
    }

    // MARK: Algorithm

    private enum Op {
        case equal(Int, Int)
        case delete(Int)
        case insert(Int)
    }

    static func diff(old: [String], new: [String]) -> [DiffLine] {
        // Intern lines so comparisons are integer compares.
        var ids: [String: Int] = [:]
        func intern(_ s: String) -> Int {
            if let id = ids[s] { return id }
            let id = ids.count
            ids[s] = id
            return id
        }
        let a = old.map(intern)
        let b = new.map(intern)
        var ops: [Op] = []
        ops.reserveCapacity(max(a.count, b.count))
        patience(a, 0, a.count, b, 0, b.count, into: &ops)
        return ops.map { op in
            switch op {
            case .equal(let i, let j): DiffLine(kind: .equal, text: old[i], oldLine: i + 1, newLine: j + 1)
            case .delete(let i): DiffLine(kind: .delete, text: old[i], oldLine: i + 1)
            case .insert(let j): DiffLine(kind: .insert, text: new[j], newLine: j + 1)
            }
        }
    }

    /// Patience: strip the common prefix and suffix, anchor on lines unique to
    /// both sides (longest increasing subsequence), recurse into the gaps.
    private static func patience(_ a: [Int], _ aLo: Int, _ aHi: Int, _ b: [Int], _ bLo: Int, _ bHi: Int,
                                 into ops: inout [Op]) {
        var aLo = aLo, aHi = aHi, bLo = bLo, bHi = bHi
        while aLo < aHi, bLo < bHi, a[aLo] == b[bLo] {
            ops.append(.equal(aLo, bLo))
            aLo += 1
            bLo += 1
        }
        var suffix = 0
        while aLo < aHi - suffix, bLo < bHi - suffix, a[aHi - suffix - 1] == b[bHi - suffix - 1] {
            suffix += 1
        }
        aHi -= suffix
        bHi -= suffix
        defer {
            for k in 0..<suffix { ops.append(.equal(aHi + k, bHi + k)) }
        }
        if aLo == aHi {
            for j in bLo..<bHi { ops.append(.insert(j)) }
            return
        }
        if bLo == bHi {
            for i in aLo..<aHi { ops.append(.delete(i)) }
            return
        }

        let anchors = uniqueAnchors(a, aLo, aHi, b, bLo, bHi)
        if anchors.isEmpty {
            myers(a, aLo, aHi, b, bLo, bHi, into: &ops)
            return
        }
        var prevA = aLo
        var prevB = bLo
        for (ai, bi) in anchors {
            patience(a, prevA, ai, b, prevB, bi, into: &ops)
            ops.append(.equal(ai, bi))
            prevA = ai + 1
            prevB = bi + 1
        }
        patience(a, prevA, aHi, b, prevB, bHi, into: &ops)
    }

    /// Lines occurring exactly once on each side, as (aIndex, bIndex) pairs in
    /// increasing order on both sides.
    private static func uniqueAnchors(_ a: [Int], _ aLo: Int, _ aHi: Int, _ b: [Int], _ bLo: Int, _ bHi: Int)
        -> [(Int, Int)] {
        var countA: [Int: Int] = [:]
        var countB: [Int: Int] = [:]
        var posB: [Int: Int] = [:]
        for i in aLo..<aHi { countA[a[i], default: 0] += 1 }
        for j in bLo..<bHi {
            countB[b[j], default: 0] += 1
            posB[b[j]] = j
        }
        var candidates: [(Int, Int)] = []
        for i in aLo..<aHi {
            let id = a[i]
            if countA[id] == 1, countB[id] == 1, let j = posB[id] {
                candidates.append((i, j))
            }
        }
        guard candidates.count > 1 else { return candidates }
        // Longest increasing subsequence on the b index (patience sorting).
        var tails: [Int] = []       // candidate index of the smallest tail per pile length
        var previous = [Int](repeating: -1, count: candidates.count)
        for (n, candidate) in candidates.enumerated() {
            var lo = 0
            var hi = tails.count
            while lo < hi {
                let mid = (lo + hi) / 2
                if candidates[tails[mid]].1 < candidate.1 { lo = mid + 1 } else { hi = mid }
            }
            if lo > 0 { previous[n] = tails[lo - 1] }
            if lo == tails.count { tails.append(n) } else { tails[lo] = n }
        }
        var result: [(Int, Int)] = []
        var cursor = tails.last ?? -1
        while cursor >= 0 {
            result.append(candidates[cursor])
            cursor = previous[cursor]
        }
        result.reverse()
        return result
    }

    /// Myers' greedy O(ND) diff with a full trace for backtracking (Coglan's
    /// formulation). Only the live part of each V is kept, so memory is O(D²).
    private static func myers(_ a: [Int], _ aLo: Int, _ aHi: Int, _ b: [Int], _ bLo: Int, _ bHi: Int,
                              into ops: inout [Op]) {
        let n = aHi - aLo
        let m = bHi - bLo
        let maxD = n + m
        let off = maxD + 1
        var v = [Int](repeating: 0, count: 2 * maxD + 3)
        var trace: [[Int]] = []   // trace[d] = v[-(d+1)...(d+1)] before round d
        var found: Int?
        search: for d in 0...maxD {
            if d > maxEditDistance { break }
            trace.append(Array(v[(off - d - 1)...(off + d + 1)]))
            var k = -d
            while k <= d {
                var x: Int
                if k == -d || (k != d && v[off + k - 1] < v[off + k + 1]) {
                    x = v[off + k + 1]
                } else {
                    x = v[off + k - 1] + 1
                }
                var y = x - k
                while x < n, y < m, a[aLo + x] == b[bLo + y] {
                    x += 1
                    y += 1
                }
                v[off + k] = x
                if x >= n, y >= m {
                    found = d
                    break search
                }
                k += 2
            }
        }
        guard let distance = found else {
            for i in aLo..<aHi { ops.append(.delete(i)) }
            for j in bLo..<bHi { ops.append(.insert(j)) }
            return
        }
        var reversed: [Op] = []
        var x = n
        var y = m
        for d in stride(from: distance, through: 0, by: -1) {
            let snapshot = trace[d]
            let base = d + 1   // snapshot index of k == 0
            let k = x - y
            let prevK: Int
            if k == -d || (k != d && snapshot[base + k - 1] < snapshot[base + k + 1]) {
                prevK = k + 1
            } else {
                prevK = k - 1
            }
            let prevX = snapshot[base + prevK]
            let prevY = prevX - prevK
            while x > prevX, y > prevY {
                x -= 1
                y -= 1
                reversed.append(.equal(aLo + x, bLo + y))
            }
            if d > 0 {
                if x == prevX {
                    reversed.append(.insert(bLo + prevY))
                } else {
                    reversed.append(.delete(aLo + prevX))
                }
            }
            x = prevX
            y = prevY
        }
        ops.append(contentsOf: reversed.reversed())
    }
}

// MARK: - Flow diff

/// One of the four compared parts of a flow.
public struct FlowDiffSection: Identifiable, Hashable, Sendable {
    public enum Part: String, Hashable, Sendable, CaseIterable {
        case requestHead, requestBody, responseHead, responseBody

        public var title: String {
            switch self {
            case .requestHead: "Request"
            case .requestBody: "Request body"
            case .responseHead: "Response"
            case .responseBody: "Response body"
            }
        }
    }

    public var id: Part { part }
    public var part: Part
    public var diff: TextDiff
    public var title: String { part.title }

    public init(part: Part, diff: TextDiff) {
        self.part = part
        self.diff = diff
    }
}

public struct FlowDiffResult: Hashable, Sendable {
    public var left: FlowID
    public var right: FlowID
    public var sections: [FlowDiffSection]

    public init(left: FlowID, right: FlowID, sections: [FlowDiffSection]) {
        self.left = left
        self.right = right
        self.sections = sections
    }

    public var hasChanges: Bool { sections.contains { $0.diff.hasChanges } }
    public var truncated: Bool { sections.contains { $0.diff.truncated } }

    /// Every changed section in unified format, one `---`/`+++` header per section — the exported patch.
    public func unified(contextLines: Int = 3) -> String {
        sections
            .filter { $0.diff.hasChanges }
            .map { section in
                section.diff.unified(oldName: "\(left)/\(section.part.rawValue)",
                                     newName: "\(right)/\(section.part.rawValue)",
                                     contextLines: contextLines)
            }
            .joined()
    }
}

public enum FlowDiff {
    /// Compares two flows as four sections: request line + headers, request body,
    /// response line + headers, response body. JSON bodies are pretty-printed on
    /// both sides first so formatting noise does not show up as changes.
    public static func compare(_ a: FlowDetail, _ b: FlowDetail) -> FlowDiffResult {
        let sections: [FlowDiffSection] = [
            FlowDiffSection(part: .requestHead, diff: TextDiff(old: headText(a.request), new: headText(b.request))),
            FlowDiffSection(part: .requestBody, diff: TextDiff(old: bodyText(a.request), new: bodyText(b.request))),
            FlowDiffSection(part: .responseHead, diff: TextDiff(old: a.response.map(headText) ?? "",
                                                                new: b.response.map(headText) ?? "")),
            FlowDiffSection(part: .responseBody, diff: TextDiff(old: a.response.map(bodyText) ?? "",
                                                                new: b.response.map(bodyText) ?? "")),
        ]
        return FlowDiffResult(left: a.id, right: b.id, sections: sections)
    }

    /// Start line and `name: value` headers, one per line.
    public static func headText(_ message: HTTPMessage) -> String {
        ([message.startLine] + message.headers.map { "\($0.name): \($0.value)" }).joined(separator: "\n")
    }

    /// The body as comparable text: pretty JSON when it parses, UTF-8 text when it decodes, a hex dump otherwise.
    public static func bodyText(_ message: HTTPMessage) -> String {
        guard let body = message.body, !body.isEmpty else { return "" }
        let type = message.contentType?.lowercased() ?? ""
        if type.contains("json") || looksLikeJSON(body), let pretty = JSONTree.pretty(body) {
            return pretty
        }
        if let text = String(data: body, encoding: .utf8) { return text }
        return HexDump.text(body)
    }

    private static func looksLikeJSON(_ data: Data) -> Bool {
        guard let first = data.first(where: { $0 != 0x20 && $0 != 0x09 && $0 != 0x0A && $0 != 0x0D }) else { return false }
        return first == UInt8(ascii: "{") || first == UInt8(ascii: "[")
    }
}
