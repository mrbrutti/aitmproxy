import Foundation

/// Fuzzy ranking for the command palette (foundation §2.7): subsequence
/// matching with bonuses for word starts and runs, so `fr` finds
/// `flow.replay` before `browser.refresh`. Name matches outrank description
/// matches; an empty query ranks everything equally.
public enum Fuzzy {
    public struct Match: Hashable, Sendable {
        /// Higher is better; 0 means no match.
        public var score: Int
        /// Character offsets of the matched query characters, for highlighting.
        public var positions: [Int]
    }

    /// nil when `query` is not a subsequence of `candidate` (case-insensitive).
    public static func match(_ query: String, in candidate: String) -> Match? {
        let q = Array(query.lowercased())
        let c = Array(candidate.lowercased())
        if q.isEmpty { return Match(score: 1, positions: []) }
        var positions: [Int] = []
        var score = 0
        var qi = 0
        var previous = -2
        for (ci, ch) in c.enumerated() where qi < q.count && ch == q[qi] {
            var gain = 1
            if ci == 0 || !(c[ci - 1].isLetter || c[ci - 1].isNumber) { gain += 8 } // word start
            if ci == previous + 1 { gain += 4 } // consecutive run
            if ci < c.count, candidate[candidate.index(candidate.startIndex, offsetBy: ci)].isUppercase { gain += 2 }
            score += gain
            positions.append(ci)
            previous = ci
            qi += 1
        }
        guard qi == q.count else { return nil }
        // Shorter candidates win ties; exact prefix wins outright.
        score += max(0, 20 - c.count / 4)
        if c.starts(with: q) { score += 30 }
        if c == q { score += 50 }
        return Match(score: score, positions: positions)
    }

    /// Ranks `name` first, then `description` at half weight.
    public static func score(_ query: String, name: String, description: String) -> Int {
        let n = match(query, in: name)?.score ?? 0
        let d = (match(query, in: description)?.score ?? 0) / 2
        return max(n, d)
    }
}
