import Foundation
import Testing

@testable import AitmproxyKit

/// `SystemProxyPreferences` names the `Store.defaults` keys Settings ▸ Proxy writes and
/// `EmbeddedCore.spawn()` reads (spec §D13 "Settings ▸ Proxy"), and turns the one-line
/// "Bypass hosts" field into the `[String]` the per-launch config and the live set carry.
@Suite struct SystemProxyPreferencesTests {
    // MARK: Keys

    /// The four keys are the literals the spec names; `Session+CATrust.swift` already spells
    /// the last two, so a typo here would silently split the preference in two.
    @Test func keysAreTheSpecLiterals() {
        #expect(SystemProxyPreferences.autoKey == "systemProxy.auto")
        #expect(SystemProxyPreferences.bypassKey == "systemProxy.bypass")
        #expect(SystemProxyPreferences.promptSuppressedKey == "systemProxy.promptSuppressed")
        #expect(SystemProxyPreferences.sheetShownKey == "systemProxy.sheetShown")
    }

    // MARK: bypassHosts

    /// Comma and/or whitespace separate hosts; order is kept.
    @Test func commaAndWhitespaceBothSeparate() {
        #expect(
            SystemProxyPreferences.bypassHosts("corp.test, api.example.com  foo.test")
                == ["corp.test", "api.example.com", "foo.test"])
    }

    @Test func emptyFieldIsNoHosts() {
        #expect(SystemProxyPreferences.bypassHosts("") == [])
    }

    @Test func separatorsAloneAreNoHosts() {
        #expect(SystemProxyPreferences.bypassHosts(" , ") == [])
        #expect(SystemProxyPreferences.bypassHosts(",,,") == [])
    }

    /// An exact duplicate is dropped; the first occurrence keeps its position.
    @Test func exactDuplicatesAreDropped() {
        #expect(
            SystemProxyPreferences.bypassHosts("a.test, b.test, a.test, c.test, b.test")
                == ["a.test", "b.test", "c.test"])
    }

    /// Only exact duplicates are dropped: case is left to the core.
    @Test func caseVariantsAreNotDuplicates() {
        #expect(SystemProxyPreferences.bypassHosts("A.test a.test") == ["A.test", "a.test"])
    }

    /// The field is single-line, but a pasted newline is whitespace, not part of a host.
    @Test func newlineIsWhitespace() {
        #expect(SystemProxyPreferences.bypassHosts("a.test\nb.test") == ["a.test", "b.test"])
    }

    @Test func surroundingWhitespaceIsTrimmed() {
        #expect(SystemProxyPreferences.bypassHosts("  corp.test ,\t*.local  ") == ["corp.test", "*.local"])
    }

    @Test func singleHostIsOneEntry() {
        #expect(SystemProxyPreferences.bypassHosts("corp.test") == ["corp.test"])
    }

    /// §D5: the field shows the recommended operator-tooling list until the operator writes the key.
    @Test func theBypassFieldDefaultsToTheRecommendedListUntilWritten() {
        let suite = "com.mrbrutti.aitmproxy.tests.sysproxy-prefs-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        #expect(SystemProxyPreferences.defaultBypassField
                == "*.anthropic.com, api.anthropic.com, claude.ai, *.claude.ai, github.com, *.githubusercontent.com")
        #expect(SystemProxyPreferences.bypassField(defaults) == SystemProxyPreferences.defaultBypassField)
        #expect(SystemProxyPreferences.bypassHosts(SystemProxyPreferences.bypassField(defaults))
                == ["*.anthropic.com", "api.anthropic.com", "claude.ai", "*.claude.ai", "github.com", "*.githubusercontent.com"])
        defaults.set("", forKey: SystemProxyPreferences.bypassKey)
        #expect(SystemProxyPreferences.bypassField(defaults) == "", "a cleared field stays cleared")
        defaults.set("corp.test", forKey: SystemProxyPreferences.bypassKey)
        #expect(SystemProxyPreferences.bypassField(defaults) == "corp.test")
    }
}
