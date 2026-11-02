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
    /// A finished listing with both sizes known: 412 + 18 200 B in 89 ms.
    static let listing = Make.row(seq: 1, host: "api.shop-staging.test", path: "/api/products", status: 200,
                                  duration: .milliseconds(89), requestBytes: 412, responseBytes: 18_200)

    @Test func sumsSizesAndDurations() {
        // Three finished rows, every size known.
        let rows = [
            Self.listing,
            Make.row(seq: 2, method: .put, host: "api.shop-staging.test", path: "/api/cart/items/42", status: 200,
                     duration: .milliseconds(67), requestBytes: 1_100, responseBytes: 640),
            Make.row(seq: 3, host: "cdn.shop-staging.test", path: "/assets/app.js", status: 304,
                     duration: .milliseconds(21), requestBytes: 388, responseBytes: 0),
        ]
        let summary = SelectionSummary(rows: rows)
        #expect(summary.count == 3)
        #expect(summary.sized == 3)
        #expect(summary.totalBytes == 412 + 18_200 + 1_100 + 640 + 388 + 0)
        #expect(summary.text == "3 selected · 20.7 KB · 177 ms")
    }

    @Test func saysHowManyWereSizedWhenSomeAreMissing() {
        // One sized row and two parked requests with no response size yet.
        let rows = [
            Self.listing,
            Make.row(seq: 2, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login", state: .paused,
                     requestBytes: 186),
            Make.row(seq: 3, host: "api.shop-staging.test", path: "/api/me", state: .paused, requestBytes: 344),
        ]
        let summary = SelectionSummary(rows: rows)
        #expect(summary.sized == 1)
        #expect(summary.text == "3 selected · 1 sized · 18.6 KB · 89 ms")
    }
}
