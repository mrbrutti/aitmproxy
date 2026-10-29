import Foundation
import Testing
@testable import AitmproxyKit

/// S-065: HAR in and out, the other formats refused by name.
@Suite struct TransferTests {
    let rows = Fixtures.rows
    var flows: [(FlowRow, FlowDetail?)] { rows.map { ($0, Fixtures.detail(for: $0)) } }

    @Test func detectsByExtensionAndContent() {
        #expect(FlowTransfer.detect(name: "capture.har", data: Data()) == .har)
        #expect(FlowTransfer.detect(name: "flows.mitm", data: Data()) == .mitmproxy)
        #expect(FlowTransfer.detect(name: "x.proxymanlog", data: Data()) == .proxyman)
        #expect(FlowTransfer.detect(name: "x.chlz", data: Data()) == .charles)
        #expect(FlowTransfer.detect(name: "noext", data: Data("{\"log\": {}}".utf8)) == .har)
        #expect(FlowTransfer.detect(name: "notes.txt", data: Data("hello".utf8)) == nil)
    }

    @Test func refusesUnsupportedFilesWithTheDetectedType() {
        #expect(throws: ImportRefusal(name: "session.chlz", detected: .charles)) {
            try FlowTransfer.importFile(name: "session.chlz", data: Data(), firstSeq: 1)
        }
        let refusal = ImportRefusal(name: "session.chlz", detected: .charles)
        #expect(refusal.message.hasPrefix("Can't import session.chlz: Charles files are not supported"))
        #expect(ImportRefusal(name: "notes.txt", detected: nil).message == "Can't import notes.txt: not a HAR, mitmproxy, Proxyman or Charles file.")
    }

    @Test func harRoundTripsTheCapture() throws {
        let text = FlowTransfer.export(flows, as: .har)
        let imported = try FlowTransfer.importFile(name: "capture.har", data: Data(text.utf8), firstSeq: 100)
        #expect(imported.count == rows.count)
        #expect(imported.map(\.0.seq) == Array(100..<(100 + rows.count)))
        #expect(imported.allSatisfy { $0.0.origin == .imported })
        let login = try #require(imported.first { $0.0.path == "/api/auth/login" })
        let original = Fixtures.detail(for: rows.first { $0.seq == 50 }!)
        #expect(login.0.method == .post && login.0.authority == "auth.shop-staging.test" && login.0.scheme == "https")
        #expect(login.1.request.header("content-type") == original.request.header("content-type"))
        #expect(login.1.request.body == original.request.body)
        let products = try #require(imported.first { $0.0.path == "/api/products" })
        #expect(products.0.status == 200 && products.0.query == "category=electronics&limit=20" && products.0.state == .complete)
        #expect(products.1.response?.header("content-type")?.hasPrefix("application/json") == true)
        #expect(products.0.duration == rows.first { $0.seq == 41 }?.duration)
    }

    @Test func csvAndCurlBatchCoverEveryRow() {
        let csv = FlowTransfer.export(flows, as: .csv).split(separator: "\n")
        #expect(csv.first == "seq,method,url,status,client,time,duration_ms,request_bytes,response_bytes")
        #expect(csv.count == rows.count + 1)
        #expect(csv[1].hasPrefix("41,GET,https://api.shop-staging.test/api/products?category=electronics&limit=20,200,obscura,"))
        let sh = FlowTransfer.export(flows, as: .curl)
        #expect(sh.hasPrefix("#!/bin/sh\n# 14 requests exported from aitmproxy"))
        #expect(sh.components(separatedBy: "\ncurl ").count - 1 == rows.count)
    }

    @Test func filenameCarriesTheDate() {
        var parts = DateComponents()
        parts.year = 2026; parts.month = 10; parts.day = 28; parts.hour = 11; parts.minute = 25
        let date = Calendar.current.date(from: parts)!
        #expect(FlowTransfer.suggestedFilename(.har, date: date) == "aitmproxy-2026-10-28-1125.har")
        #expect(FlowTransfer.suggestedFilename(.curl, date: date).hasSuffix(".sh"))
    }
}
