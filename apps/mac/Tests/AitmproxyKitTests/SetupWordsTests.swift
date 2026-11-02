import Testing
@testable import AitmproxyKit

/// The sheet's own words have one Kit home (D17.8).
@Suite struct SetupWordsTests {
    @Test func setupWordsAreTheSheetsWords() {
        #expect(SetupWords.sheetTitle == "Set up aitmproxy on this Mac")
        #expect(SetupWords.scopeCaption == "Nothing is decrypted until a host is in Scope")
    }

    /// PR 4 Task 28 (spec §D13 "First-run sheet"): row 1's title (unconditional since F-mac: Matt's words), and the caption
    /// under its button — the sheet's Set button turns on the launch preference, and says so, verbatim.
    @Test func systemProxyRowWordsAreTheSpecLiterals() {
        #expect(SetupWords.systemProxyRowTitle == "Set aitmproxy as the system proxy")
        #expect(SetupWords.systemProxyAutoCaption == "Also turns on “Set system proxy at launch” in Settings ▸ Proxy")
        // The caption quotes the Settings toggle with typographic quotes (U+201C/U+201D) and names the pane with
        // the ▸ (U+25B8) every other Settings reference in the app uses — not ASCII look-alikes.
        #expect(SetupWords.systemProxyAutoCaption.unicodeScalars.contains("\u{201C}"))
        #expect(SetupWords.systemProxyAutoCaption.unicodeScalars.contains("\u{201D}"))
        #expect(SetupWords.systemProxyAutoCaption.unicodeScalars.contains("\u{25B8}"))
        #expect(!SetupWords.systemProxyAutoCaption.contains("\""))
        // Row 1's title is the Getting-started row's §D13 words minus its ", or open the browser" clause,
        // so the sheet and the Status list never say two different things.
        #expect("Set aitmproxy as the system proxy, or open the browser".hasPrefix(SetupWords.systemProxyRowTitle))
    }

    /// §D13 "First-run sheet": the checklist, verbatim and in order.
    @Test func theSystemProxyChecklistIsTheSpecsThreeLines() {
        #expect(SetupWords.systemProxyChecklist == [
            "Route every proxy-aware app through aitmproxy",
            "Remember and restore your previous proxy setting",
            "Revert automatically if the app quits or crashes",
        ])
    }
}
