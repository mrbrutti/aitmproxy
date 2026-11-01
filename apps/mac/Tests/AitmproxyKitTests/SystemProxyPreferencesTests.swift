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

    // MARK: Edges a bus client must survive (tester, stage 5)

    /// Tabs and CRLF are whitespace like any other; a pasted Windows line ending is not a host.
    @Test func tabsAndCRLFAreSeparators() {
        #expect(SystemProxyPreferences.bypassHosts("a.test\r\nb.test\tc.test") == ["a.test", "b.test", "c.test"])
        #expect(SystemProxyPreferences.bypassHosts("\r\n\t ,\r\n") == [])
    }

    /// The parser does not validate host SYNTAX (the two drops are control scalars and a leading dash, tested
    /// below): a quote, a backslash, a wildcard, an IDN label, a CIDR or a bracketed v6
    /// literal pass through untouched. The YAML escaper (`EmbeddedCoreLaunch.yamlDoubleQuoted`) owns the quoting
    /// and the core owns the matching rules.
    @Test func hostsPassThroughUnvalidated() {
        #expect(SystemProxyPreferences.bypassHosts("a\"b.test back\\slash.test *.local bücher.test 10.0.0.0/8 [::1]")
                == ["a\"b.test", "back\\slash.test", "*.local", "bücher.test", "10.0.0.0/8", "[::1]"])
    }

    /// An oversized field (10 000 hosts) parses whole, in order, without truncation.
    @Test func anOversizedFieldParsesWhole() {
        let field = (0..<10_000).map { "h\($0).test" }.joined(separator: ", ")
        let hosts = SystemProxyPreferences.bypassHosts(field)
        #expect(hosts.count == 10_000)
        #expect(hosts.first == "h0.test")
        #expect(hosts[4_999] == "h4999.test")
        #expect(hosts.last == "h9999.test")
    }

    /// A stored field that is only separators is kept as typed and is an empty host list for both the spawn
    /// (no `bypass:` key) and the live set (no `bypass` param).
    @Test func aStoredSeparatorOnlyFieldIsNoHosts() {
        let suite = "com.mrbrutti.aitmproxy.tests.sysproxy-prefs-edge-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(" , ,\n", forKey: SystemProxyPreferences.bypassKey)
        #expect(SystemProxyPreferences.bypassField(defaults) == " , ,\n")
        #expect(SystemProxyPreferences.bypassHosts(SystemProxyPreferences.bypassField(defaults)) == [])
    }

    /// Security panel (PR 4): a piece with a control scalar would make the per-launch config
    /// unparseable (the core fails to start until the field is edited); a leading `-` is an argv
    /// flag to `networksetup`. Both are dropped; everything else is the core's to judge.
    @Test func controlCharactersAndLeadingDashesAreDropped() {
        #expect(SystemProxyPreferences.bypassHosts("a.test, b\u{01}.test, -setwebproxystate, c.test") == ["a.test", "c.test"])
        #expect(SystemProxyPreferences.bypassHosts("del\u{7F}.test") == [])
        #expect(SystemProxyPreferences.bypassHosts("-") == [])
        #expect(SystemProxyPreferences.bypassHosts("a-b.test, *.corp.test") == ["a-b.test", "*.corp.test"], "an inner dash and a wildcard are fine")
    }
}
