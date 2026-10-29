import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct PinsTests {
    @Test func pinningTwiceStoresOnce() {
        var pins = Pins()
        pins.pinHost("api.shop-staging.test")
        pins.pinHost("api.shop-staging.test")
        pins.pinApp("curl")
        #expect(pins.hosts == ["api.shop-staging.test"])
        #expect(pins.apps == ["curl"])
        pins.unpinHost("api.shop-staging.test")
        #expect(pins.hosts.isEmpty)
        #expect(!pins.isEmpty)
    }

    @Test func roundTripsThroughAFile() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "pins-\(UUID().uuidString).json")
        let pins = Pins(hosts: ["a.test", "b.test"], apps: ["Safari"])
        try pins.save(to: url)
        #expect(Pins.load(from: url) == pins)
        #expect(Pins.load(from: url.appendingPathExtension("missing")) == Pins())
    }
}

@Suite struct SelectionSummaryTests {
    @Test func sumsSizesAndDurations() {
        let rows = Array(Fixtures.rows[0..<3]) // 41, 42, 43: all sized
        let summary = SelectionSummary(rows: rows)
        #expect(summary.count == 3)
        #expect(summary.sized == 3)
        #expect(summary.totalBytes == 412 + 18_200 + 1_100 + 640 + 388 + 0)
        #expect(summary.text == "3 selected · 20.7 KB · 177 ms")
    }

    @Test func saysHowManyWereSizedWhenSomeAreMissing() {
        let rows = [Fixtures.rows[0], Fixtures.rows[9], Fixtures.rows[10]] // 41 sized; 50, 51 paused (no response size)
        let summary = SelectionSummary(rows: rows)
        #expect(summary.sized == 1)
        #expect(summary.text == "3 selected · 1 sized · 18.6 KB · 89 ms")
    }
}
