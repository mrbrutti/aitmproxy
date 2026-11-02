import Foundation
import Testing
@testable import AitmproxyKit

/// MS-R1 (spec 2026-10-31-scanner-v2-mac-scan-surface, Review log): the Scan page's poll must
/// publish its surface only on a real change. The app compares the model before assigning, so
/// these pin the equalities that comparison relies on, and the dev-bundle run-dir isolation.
@Suite struct ScanIdleRedrawTests {
    @Test func clearingNoFlagsLeavesTheModelEqual() {
        let model = ScanSurfaceModel()
        var cleared = model
        cleared.clearRefreshFlags()
        #expect(cleared == model)
    }

    @Test func clearingARaisedFlagChangesTheModel() {
        var model = ScanSurfaceModel()
        model.listRefreshNeeded = true
        var cleared = model
        cleared.clearRefreshFlags()
        #expect(cleared != model)
        #expect(cleared.listRefreshNeeded == false)
    }


    @Test func devBundlesGetTheirOwnRunDirAndTheInstalledAppDoesNot() {
        #expect(EmbeddedCoreLaunch.isolatedRunDir(environment: [:]) == nil)
        #expect(EmbeddedCoreLaunch.isolatedRunDir(environment: ["APP_STORE": ""]) == nil)
        #expect(EmbeddedCoreLaunch.isolatedRunDir(environment: ["APP_STORE": "/tmp/Aitmproxy-dev-state-x"])?.path == "/tmp/Aitmproxy-dev-state-x/run/cores")
        #expect(EmbeddedCoreLaunch.runDirEnvironmentKey == "AITM_RUN_DIR")
    }
}
