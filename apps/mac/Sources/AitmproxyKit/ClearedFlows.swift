import Foundation

/// What Clear dropped, kept for one undo step (review D2, rule 43). The rows and their cached
/// details are the app's copy: the core has already dropped the flows.
public struct ClearedFlows: Sendable {
    public var rows: [FlowRow]
    public var details: [FlowID: FlowDetail]
    public var wsDetails: [FlowID: WSDetail]
    public var l4Details: [FlowID: L4Flow]
    public var selection: Set<FlowID>
    public var focused: FlowID?

    public init(rows: [FlowRow], details: [FlowID: FlowDetail] = [:], wsDetails: [FlowID: WSDetail] = [:],
                l4Details: [FlowID: L4Flow] = [:], selection: Set<FlowID> = [], focused: FlowID? = nil) {
        self.rows = rows
        self.details = details
        self.wsDetails = wsDetails
        self.l4Details = l4Details
        self.selection = selection
        self.focused = focused
    }

    public var count: Int { rows.count }

    /// The restored rows first, then the rows that arrived after the clear with their `seq`
    /// shifted past the restored maximum so `#` stays monotonic. A newer row that shares a
    /// restored id is dropped (the restored copy wins).
    public static func merge(restored: [FlowRow], newer: [FlowRow]) -> [FlowRow] {
        guard !restored.isEmpty else { return newer }
        let restoredIDs = Set(restored.map(\.id))
        let fresh = newer.filter { !restoredIDs.contains($0.id) }
        guard let firstSeq = fresh.map(\.seq).min() else { return restored }
        let base = restored.map(\.seq).max() ?? 0
        return restored + fresh.map { row in
            var row = row
            row.seq = base + 1 + (row.seq - firstSeq)
            return row
        }
    }
}

/// "Cleared n flows — Undo" in the status bar, for a few seconds after a Clear.
public struct ClearNotice: Equatable, Sendable {
    public var count: Int

    public init(count: Int) { self.count = count }

    public var text: String { "Cleared \(count) flow\(count == 1 ? "" : "s")" }
}
