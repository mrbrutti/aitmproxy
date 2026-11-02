import Foundation
import Testing
@testable import AitmproxyKit

/// MS-R1 (spec 2026-10-31-scanner-v2-mac-scan-surface, Review log): the Scan page's poll publishes
/// its surface only on a real change. The app compares the model before assigning; these pin the
/// equalities that comparison relies on, on a populated model so a reset of any other field shows.
@Suite struct ScanIdleRedrawTests {
    private func populated() -> ScanSurfaceModel {
        var model = ScanSurfaceModel()
        model.tab = .jobs
        model.selectedProfile = "standard"
        model.checkQuery = "sqli"
        model.selectedJob = "scan-1a2b3c4d"
        model.statusLine = "Saved profile standard"
        model.launchNotices = ["scan-1a2b3c4d": ["lanes.skipped: l4"]]
        model.sitemapJob = "scan-1a2b3c4d"
        model.sitemapQuery = "/api"
        model.selectedIssue = "iss-1"
        model.issuesCursor = "c2"
        model.l4InjectScopeKnown = true
        model.launchInFlight = false
        return model
    }

    @Test func clearingNoFlagsLeavesAPopulatedModelEqual() {
        let model = populated()
        var cleared = model
        cleared.clearRefreshFlags()
        #expect(cleared == model)
        #expect(cleared.selectedJob == "scan-1a2b3c4d")
        #expect(cleared.statusLine == "Saved profile standard")
    }

    @Test func clearingARaisedFlagChangesTheModel() {
        var model = populated()
        model.listRefreshNeeded = true
        var cleared = model
        cleared.clearRefreshFlags()
        #expect(cleared != model)
        #expect(cleared.listRefreshNeeded == false)
        #expect(cleared.selectedJob == model.selectedJob)
    }

    @Test func aStaleJobLineChangesNothing() {
        let model = populated()
        var noted = model
        // Not a scan line at all: the Kit refuses it and the model must be byte-for-byte the same.
        let accepted = noted.noteJobEvent(["kind": "proxy", "job": "scan-1a2b3c4d", "seq": 1, "event": "progress"])
        #expect(accepted == false)
        #expect(noted == model)
    }

    /// The 2 s beats re-apply what the core already said; an identical result must leave the model
    /// equal, or the compare-before-assign republishes the page every beat (MS-R1, spec panel).
    @Test func reapplyingTheSameResultsLeavesTheModelEqual() throws {
        var model = ScanSurfaceModel()
        let list = try ScanListResult(json: ScanPack.load("scan.list.json"))
        let status = try ScanJobStatus(json: ScanPack.load("scan.status.json"))
        model.applyList(list)
        model.applyStatus(status)
        let settled = model
        model.applyList(list)
        #expect(model == settled)
        model.applyStatus(status)
        #expect(model == settled)
        model.clearRefreshFlags()
        #expect(model == settled)
    }
}
