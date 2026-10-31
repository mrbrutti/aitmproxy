import Foundation
import Testing
@testable import AitmproxyKit

/// Responsive flow columns: low-priority columns go first, the user's hidden set is untouched.
@Suite struct ColumnFitTests {
    typealias C = ColumnFit.Column
    // The flow list's fixed columns at their default widths (URL is the flexible one, min 200).
    static let columns = [
        C(id: "dot", width: 24), C(id: "seq", width: 52), C(id: "client", width: 96), C(id: "method", width: 72),
        C(id: "status", width: 84), C(id: "time", width: 124), C(id: "duration", width: 88), C(id: "request", width: 80),
        C(id: "response", width: 80), C(id: "ssl", width: 40), C(id: "edited", width: 64), C(id: "origin", width: 72),
        C(id: "mark", width: 20),
    ]
    static let priority = ["edited", "origin", "ssl", "response", "request", "duration", "client"]

    private func hidden(at available: Double, columns: [C] = Self.columns) -> Set<String> {
        ColumnFit.autoHidden(available: available, columns: columns, flexibleMin: 200, priority: Self.priority)
    }

    @Test func everythingFitsAtTheDefaultWindow() {
        // 896 fixed + 200 URL minimum = 1096 needed.
        #expect(hidden(at: 1199) == [])
        #expect(hidden(at: 1096) == [])
    }

    @Test func lowestPriorityGoesFirst() {
        #expect(hidden(at: 1095) == ["edited"])
        #expect(hidden(at: 1032) == ["edited"])
        #expect(hidden(at: 1031) == ["edited", "origin"])
        #expect(hidden(at: 900) == ["edited", "origin", "ssl", "response"])
    }

    @Test func splitPaneHidesClientToo() {
        // Each split pane at a 1440 window is about 598 pt: the six listed columns reach 672, so client goes.
        #expect(hidden(at: 598) == ["edited", "origin", "ssl", "response", "request", "duration", "client"])
    }

    @Test func userHiddenColumnsAreNotCountedOrTouched() {
        var columns = Self.columns
        columns[columns.firstIndex { $0.id == "edited" }!].userHidden = true
        // Without edited the sum is 1032; at 1032 nothing more needs to go, and edited is never returned.
        #expect(hidden(at: 1032, columns: columns) == [])
        #expect(hidden(at: 1031, columns: columns) == ["origin"])
    }

    @Test func columnsOutsidePriorityNeverHide() {
        #expect(hidden(at: 100) == Set(Self.priority))
    }
}
