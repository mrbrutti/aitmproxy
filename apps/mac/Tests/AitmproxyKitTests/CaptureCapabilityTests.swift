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

    @Test func anAlreadyCapturingStateIsUnchangedByAnotherTunnelConnectedEvent() {
        // A repeated `.connected` observation while capturing is idempotent, not a reset.
        #expect(CaptureCapability.capturing.applying(.tunnelConnected) == .capturing)
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

    // MARK: uninstall + indicator (Task 17, NE-AC15)

    @Test func anUninstallLandsOnNotInstalledFromEveryState() {
        let everyState: [CaptureCapability] = [
            .extensionNotInstalled, .pendingApproval, .approvedAttached, .capturing,
            .degraded("Could not start the capture tunnel: boom"),
        ]
        for state in everyState {
            #expect(state.applying(.uninstalled) == .extensionNotInstalled)
        }
    }

    @Test func anUninstalledExtensionIsNotResurrectedByALateTunnelEvent() {
        // The tunnel observer can fire once more while the configuration is torn down.
        let state = CaptureCapability.capturing.applying(.uninstalled)
        #expect(state.applying(.tunnelConnected) == .extensionNotInstalled)
        #expect(state.applying(.tunnelDisconnected) == .extensionNotInstalled)
    }

    @Test func theCaptureIndicatorIsOnOnlyWhileApprovedAndAttached() {
        #expect(CaptureCapability.approvedAttached.isCaptureOn == true)
        #expect(CaptureCapability.capturing.isCaptureOn == true)
        #expect(CaptureCapability.extensionNotInstalled.isCaptureOn == false)
        #expect(CaptureCapability.pendingApproval.isCaptureOn == false)
        #expect(CaptureCapability.degraded("boom").isCaptureOn == false)
    }

    @Test func theIndicatorSectionShowsOnlyWhenThereIsAnExtensionToReportOn() {
        #expect(CaptureCapability.extensionNotInstalled.isInstalledOrInstalling == false)
        #expect(CaptureCapability.pendingApproval.isInstalledOrInstalling == true)
        #expect(CaptureCapability.approvedAttached.isInstalledOrInstalling == true)
        #expect(CaptureCapability.capturing.isInstalledOrInstalling == true)
        #expect(CaptureCapability.degraded("boom").isInstalledOrInstalling == true)
    }

    @Test func uninstallIsOfferedOnceApprovedAndAlsoToCleanUpADegradedInstall() {
        #expect(CaptureCapability.capturing.canUninstall == true)
        #expect(CaptureCapability.approvedAttached.canUninstall == true)
        #expect(CaptureCapability.degraded("activation failed").canUninstall == true)
        // Nothing to remove yet, and an outstanding approval request is not removable.
        #expect(CaptureCapability.extensionNotInstalled.canUninstall == false)
        #expect(CaptureCapability.pendingApproval.canUninstall == false)
    }

    // MARK: tunnel reconcile policy (Task 16, NE-AC14)

    @Test func aReplacedExtensionGetsASettleDelayAndAFreshInstallDoesNot() {
        let policy = TunnelReconcilePolicy.standard
        #expect(policy.settleDelay(afterReplacement: true) == .seconds(2))
        #expect(policy.settleDelay(afterReplacement: false) == .zero)
    }

    @Test func backoffDoublesFromOneSecondAndStopsAtTheCap() {
        let policy = TunnelReconcilePolicy.standard
        #expect(policy.backoff(afterAttempt: 1) == .seconds(1))
        #expect(policy.backoff(afterAttempt: 2) == .seconds(2))
        #expect(policy.backoff(afterAttempt: 3) == .seconds(4))
        #expect(policy.backoff(afterAttempt: 4) == .seconds(8))
        #expect(policy.backoff(afterAttempt: 5) == .seconds(8))
        #expect(policy.backoff(afterAttempt: 40) == .seconds(8))
    }

    @Test func aTransientFailureRetriesWithBackoffUntilTheAttemptsRunOut() {
        let policy = TunnelReconcilePolicy.standard
        #expect(policy.maxAttempts == 4)
        #expect(policy.decision(afterFailedAttempt: 1, retryable: true) == .retry(after: .seconds(1)))
        #expect(policy.decision(afterFailedAttempt: 2, retryable: true) == .retry(after: .seconds(2)))
        #expect(policy.decision(afterFailedAttempt: 3, retryable: true) == .retry(after: .seconds(4)))
        #expect(policy.decision(afterFailedAttempt: 4, retryable: true) == .giveUp)
        #expect(policy.decision(afterFailedAttempt: 9, retryable: true) == .giveUp)
    }

    @Test func aPermanentFailureNeverRetries() {
        // E.g. the operator refused the "Add Proxy Configurations" prompt: retrying would
        // just re-prompt them.
        #expect(TunnelReconcilePolicy.standard.decision(afterFailedAttempt: 1, retryable: false) == .giveUp)
    }

    @Test func theConnectedCheckPollsWithinItsWindow() {
        let policy = TunnelReconcilePolicy.standard
        #expect(policy.connectWindow == .seconds(6))
        #expect(policy.pollInterval == .milliseconds(500))
        #expect(policy.pollCount == 12)
    }

    @Test func theConnectedCheckAlwaysSamplesAtLeastOnce() {
        // A window shorter than one poll interval must still sample once, never zero times.
        let policy = TunnelReconcilePolicy(
            settleAfterReplacement: .seconds(2),
            maxAttempts: 4,
            connectWindow: .milliseconds(100),
            pollInterval: .seconds(1),
            firstBackoff: .seconds(1),
            maxBackoff: .seconds(8))
        #expect(policy.pollCount == 1)
    }

    @Test func transientReconcileFailuresRetryAndPermanentOnesDoNot() {
        // The retry policy ExtensionController maps each NEVPNError.code onto.
        #expect(TunnelFailure.configurationDisabled.isTransient)
        #expect(TunnelFailure.configurationStale.isTransient)
        #expect(TunnelFailure.configurationUnknown.isTransient)
        #expect(TunnelFailure.connectionFailed.isTransient)
        #expect(!TunnelFailure.permanent.isTransient)
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
