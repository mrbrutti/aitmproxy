import Foundation
import Testing
@testable import AitmproxyKit

/// Task 13 (spec D9, NE-AC9/NE-AC10): the host app's capture-capability state
/// machine and the check that keeps activation inert in builds with no embedded
/// system extension. Both are pure, so the framework-facing `ExtensionController`
/// stays thin glue.
@Suite struct CaptureCapabilityTests {
    // MARK: state machine

    @Test func twoPromptApprovalWalksTheSpecStates() {
        var state = CaptureCapability.extensionNotInstalled
        state = state.applying(.needsUserApproval)
        #expect(state == .pendingApproval)
        state = state.applying(.activated)
        #expect(state == .approvedAttached)
        state = state.applying(.tunnelConnected)
        #expect(state == .capturing)
    }

    @Test func anAlreadyApprovedExtensionSkipsThePendingState() {
        // Re-submitting the request on a later launch finishes with no prompt.
        let state = CaptureCapability.extensionNotInstalled.applying(.activated)
        #expect(state == .approvedAttached)
    }

    @Test func activationFailureDegradesWithTheErrorText() {
        let state = CaptureCapability.pendingApproval
            .applying(.failed("Extension activation failed: App must be in /Applications folder"))
        #expect(state == .degraded("Extension activation failed: App must be in /Applications folder"))
    }

    @Test func rebootRequiredDegradesWithAnActionableReason() {
        let state = CaptureCapability.extensionNotInstalled.applying(.willCompleteAfterReboot)
        #expect(state == .degraded("Restart your Mac to finish enabling the capture extension."))
    }

    @Test func aLateTunnelEventNeverOverridesAnEarlierState() {
        // The tunnel only means something once the extension is approved.
        #expect(CaptureCapability.pendingApproval.applying(.tunnelConnected) == .pendingApproval)
        #expect(CaptureCapability.extensionNotInstalled.applying(.tunnelConnected) == .extensionNotInstalled)
        #expect(CaptureCapability.degraded("boom").applying(.tunnelConnected) == .degraded("boom"))
    }

    @Test func aDroppedTunnelFallsBackToApprovedButNeverHidesADegradation() {
        #expect(CaptureCapability.capturing.applying(.tunnelDisconnected) == .approvedAttached)
        #expect(CaptureCapability.approvedAttached.applying(.tunnelDisconnected) == .approvedAttached)
        #expect(CaptureCapability.degraded("boom").applying(.tunnelDisconnected) == .degraded("boom"))
        #expect(CaptureCapability.pendingApproval.applying(.tunnelDisconnected) == .pendingApproval)
    }

    @Test func aTunnelFailureAfterApprovalDegrades() {
        let state = CaptureCapability.approvedAttached
            .applying(.failed("Could not start the capture tunnel: permission denied"))
        #expect(state == .degraded("Could not start the capture tunnel: permission denied"))
    }

    @Test func approvalIsRequiredAgainWhenTheSystemAsksAgain() {
        // A replacement extension can ask for approval again while capturing.
        #expect(CaptureCapability.capturing.applying(.needsUserApproval) == .pendingApproval)
    }

    @Test func everyStateHasAnOperatorFacingWord() {
        #expect(CaptureCapability.extensionNotInstalled.title == "Extension not installed")
        #expect(CaptureCapability.pendingApproval.title == "Awaiting approval")
        #expect(CaptureCapability.approvedAttached.title == "Approved")
        #expect(CaptureCapability.capturing.title == "Capturing")
        #expect(CaptureCapability.degraded("x").title == "Degraded")
    }

    @Test func degradedReasonIsReadableOnlyWhenDegraded() {
        #expect(CaptureCapability.degraded("needs restart").degradedReason == "needs restart")
        #expect(CaptureCapability.capturing.degradedReason == nil)
        #expect(CaptureCapability.pendingApproval.degradedReason == nil)
    }

    // MARK: embedded-extension gate

    @Test func theExtensionLivesWhereBuildShPutsIt() {
        let app = URL(fileURLWithPath: "/Applications/Aitmproxy.app", isDirectory: true)
        #expect(CaptureExtension.identifier == "com.mrbrutti.aitmproxy.ne")
        #expect(CaptureExtension.embeddedBundleURL(inApp: app).path
            == "/Applications/Aitmproxy.app/Contents/Library/SystemExtensions/com.mrbrutti.aitmproxy.ne.systemextension")
    }

    @Test func aBundleWithoutTheExtensionIsNotEmbedded() throws {
        let app = try makeAppBundle(withExtension: false)
        defer { try? FileManager.default.removeItem(at: app) }
        #expect(CaptureExtension.isEmbedded(inApp: app) == false)
    }

    @Test func aBundleWithTheExtensionIsEmbedded() throws {
        let app = try makeAppBundle(withExtension: true)
        defer { try? FileManager.default.removeItem(at: app) }
        #expect(CaptureExtension.isEmbedded(inApp: app) == true)
    }

    @Test func aStrayFileAtTheExtensionPathIsNotAnEmbeddedBundle() throws {
        let app = try makeAppBundle(withExtension: false)
        defer { try? FileManager.default.removeItem(at: app) }
        let stray = CaptureExtension.embeddedBundleURL(inApp: app)
        try FileManager.default.createDirectory(at: stray.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("not a bundle".utf8).write(to: stray)
        #expect(CaptureExtension.isEmbedded(inApp: app) == false)
    }

    /// A throwaway `.app` directory, with or without the sysex directory inside.
    private func makeAppBundle(withExtension: Bool) throws -> URL {
        // Honour $TMPDIR the way SavedFilterStoreTests does, so the fixture also works
        // where the system temp directory is not writable.
        let tmp = ProcessInfo.processInfo.environment["TMPDIR"].map { URL(filePath: $0) }
            ?? FileManager.default.temporaryDirectory
        let app = tmp.appending(path: "capture-ext-\(UUID().uuidString).app", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
        if withExtension {
            try FileManager.default.createDirectory(
                at: CaptureExtension.embeddedBundleURL(inApp: app), withIntermediateDirectories: true)
        }
        return app
    }
}
