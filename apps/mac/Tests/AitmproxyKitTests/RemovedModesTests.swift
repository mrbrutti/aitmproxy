import Testing

@testable import AitmproxyKit

/// The fake-data switches removed on 2026-10-31 fail closed (spec D3 item 8): a stale
/// invocation that still sets one of them is refused at launch instead of silently running
/// the full live app on the operator's real defaults.
@Suite struct RemovedModesTests {
    @Test func aLaunchWithNoneOfTheRemovedVariablesIsNotRefused() {
        #expect(RemovedModes.refusal(environment: ["HOME": "/Users/x", "PATH": "/usr/bin"]) == nil)
    }

    @Test func aRemovedVariableIsRefusedWithTheExactLineWhateverItsValue() {
        #expect(RemovedModes.refusal(environment: ["APP_FIXTURES": "1"])
            == "APP_FIXTURES was removed on 2026-10-31 with the fixture modes; see apps/mac/CLAUDE.md")
        // Presence is the stale invocation: an empty value still refuses.
        #expect(RemovedModes.refusal(environment: ["APP_SNAPSHOT": ""])
            == "APP_SNAPSHOT was removed on 2026-10-31 with the fixture modes; see apps/mac/CLAUDE.md")
    }

    @Test func theListIsExactlyTheFiveSwitchesTheSpecNames() {
        #expect(RemovedModes.variables == ["APP_FIXTURES", "APP_SNAPSHOT", "APP_SNAPSHOT_PAGES", "APP_KIT_GALLERY", "APP_L4_EMBEDDED"])
    }

    @Test func theKeptHarnessVariableAloneIsNotRefused() {
        #expect(RemovedModes.refusal(environment: ["APP_STORE": "/tmp/claude/x"]) == nil)
    }
}
