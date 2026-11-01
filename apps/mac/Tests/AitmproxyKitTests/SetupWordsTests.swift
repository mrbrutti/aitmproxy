import Testing
@testable import AitmproxyKit

/// The sheet's own words have one Kit home (D17.8).
@Suite struct SetupWordsTests {
    @Test func setupWordsAreTheSheetsWords() {
        #expect(SetupWords.sheetTitle == "Set up aitmproxy on this Mac")
        #expect(SetupWords.scopeCaption == "Nothing is decrypted until a host is in Scope")
    }
}
