import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// Task 5 (AC4): every flow/row/detail the UI holds carries the `CoreID` of the
/// connection it came from. With one connection today it is a constant, but the
/// field is threaded through both ingestion seams — the `flow.get` summary → row
/// and the `flow.detail` wire → detail — so a second connection is additive.
@Suite struct FlowCoreIDTests {
    private func summary() -> FlowSummary {
        FlowSummary(
            id: FlowID("22222222-2222-4222-8222-222222222222"), kind: .http,
            intercept: .observed, isReplay: false, method: "GET", scheme: "https",
            authority: "api.example.test", path: "/health", status: 200)
    }

    @Test func flows_carry_their_core_id() {
        let activeID = CoreID()
        let row = summary().row(seq: 1, coreID: activeID)
        #expect(row.coreID == activeID)
    }

    @Test func detail_from_the_wire_carries_its_core_id() throws {
        let activeID = CoreID()
        let detail = try #require(FlowDetail(detailJSON: FlowDetailWireTests.httpDetail, coreID: activeID))
        #expect(detail.coreID == activeID)
    }

    /// The ingestion seams default to the well-known fixture id, so sample and
    /// offline data all share one stable originating connection.
    @Test func ingestion_defaults_to_the_fixture_core_id() throws {
        #expect(summary().row(seq: 1).coreID == .fixture)
        let detail = try #require(FlowDetail(detailJSON: FlowDetailWireTests.httpDetail))
        #expect(detail.coreID == .fixture)
    }

    /// Every static fixture row and its detail carry the fixture id end-to-end.
    @Test func fixture_rows_and_details_all_carry_the_fixture_core_id() {
        for row in Fixtures.rows {
            #expect(row.coreID == .fixture)
            #expect(Fixtures.detail(for: row).coreID == .fixture)
        }
    }
}
