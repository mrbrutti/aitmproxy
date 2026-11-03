import Foundation
import Testing

/// Tripwire on the two quit routes and their helper (spec
/// `docs/superpowers/specs/2026-11-03-mac-quit-ends-open-sheets-design.md`, D6′): a source pin that
/// both callers still reach `Quit.endSheetsAndTerminate()` and that the principal-class detour stays
/// gone; the live proof (spec D7) is the behavioural evidence.
@Suite struct QuitRoutesTests {
    /// `apps/mac`: test file → `AitmproxyKitTests` → `Tests` → `apps/mac`.
    static let macRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    static func text(_ relativePath: String) throws -> String {
        try String(contentsOf: macRoot.appending(path: relativePath), encoding: .utf8)
    }

    static func count(of needle: String, in haystack: String) -> Int {
        haystack.components(separatedBy: needle).count - 1
    }

    @Test func theQuitHelperEndsSheetsAndThenCallsTerminate() throws {
        let helper = try Self.text("Sources/Aitmproxy/Quit.swift")
        #expect(helper.contains("static func endSheetsAndTerminate()"))
        #expect(helper.contains("NSApp.terminate(nil)"))
        #expect(!helper.contains("exit("))
    }

    @Test func bothQuitRoutesCallTheHelper() throws {
        let app = try Self.text("Sources/Aitmproxy/App.swift")
        #expect(app.contains("CommandGroup(replacing: .appTermination)"))
        #expect(app.contains("\"Quit Aitmproxy\""))
        #expect(app.contains(".keyboardShortcut(\"q\")"))
        #expect(app.contains("kAEQuitApplication"))
        #expect(app.contains("withReplyEvent"))
        #expect(Self.count(of: "Quit.endSheetsAndTerminate()", in: app) >= 2)
    }

    @Test func thePrincipalClassDetourIsGone() throws {
        let template = try Self.text("Info.plist.in")
        #expect(Self.count(of: "<key>NSPrincipalClass</key><string>NSApplication</string>", in: template) == 1)
        #expect(!template.contains("AitmApplication"))
        let script = try Self.text("tools/snap-dev.sh")
        #expect(!script.contains("NSPrincipalClass"))
        let detour = Self.macRoot.appending(path: "Sources/Aitmproxy/AitmApplication.swift").path
        #expect(!FileManager.default.fileExists(atPath: detour))
    }
}
