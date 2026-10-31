import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct ColumnLayoutTests {
    @Test func unknownIdsAreIgnoredAndMissingOnesAppended() {
        let layout = ColumnLayout(order: ["url", "ghost", "seq"], widths: ["url": 320, "ghost": 50], hidden: ["ghost", "ssl"])
        #expect(layout.resolvedOrder(known: ["dot", "seq", "url", "ssl"]) == ["url", "seq", "dot", "ssl"])
        #expect(layout.width(for: "url", default: 100) == 320)
        #expect(layout.width(for: "seq", default: 52) == 52)
        #expect(layout.isHidden("ssl"))
        #expect(!layout.isHidden("url"))
    }

    @Test func roundTripsThroughAFile() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "columns-\(UUID().uuidString).json")
        let layout = ColumnLayout(order: ["seq", "url"], widths: ["url": 240.5], hidden: ["mark"])
        try layout.save(to: url)
        #expect(ColumnLayout.load(from: url) == layout)
        #expect(ColumnLayout.load(from: url.appendingPathExtension("missing")) == nil)
    }
}

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

    @Test func theSpecsOwnBoundaries() {
        // AC13: 1000 drops edited + origin; 800 drops through request; 500 drops every priority column.
        #expect(hidden(at: 1000) == ["edited", "origin"])
        #expect(hidden(at: 800) == ["edited", "origin", "ssl", "response", "request"])
        #expect(hidden(at: 500) == Set(Self.priority))
        // A user-hidden comment column (160) is out of the sum and never returned.
        let withComment = Self.columns + [C(id: "comment", width: 160, userHidden: true)]
        #expect(hidden(at: 1000, columns: withComment) == ["edited", "origin"])
        #expect(ColumnFit.autoHidden(available: 100, columns: Self.columns, flexibleMin: 200, priority: []) == [])
    }

    @Test func theFlexibleMinimumIsPartOfTheSum() {
        // 896 fixed + 220 (URL minimum plus 20 of spacing) = 1116: at 1115 the first column goes.
        let hidden = ColumnFit.autoHidden(available: 1115, columns: Self.columns, flexibleMin: 220, priority: Self.priority)
        #expect(hidden == ["edited"])
    }

    @Test func columnsOutsidePriorityNeverHide() {
        #expect(hidden(at: 100) == Set(Self.priority))
    }
}
