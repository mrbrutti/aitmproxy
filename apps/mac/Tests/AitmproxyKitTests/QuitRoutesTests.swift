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

    /// Character offset of the first `needle` (or the last, with `.backwards`), for ordering pins;
    /// throws when it is absent.
    static func offset(of needle: String, in haystack: String, options: String.CompareOptions = []) throws -> Int {
        let range = try #require(haystack.range(of: needle, options: options), "missing \(needle)")
        return haystack.distance(from: haystack.startIndex, to: range.lowerBound)
    }

    @Test func theQuitHelperEndsSheetsAndThenCallsTerminate() throws {
        let helper = try Self.text("Sources/Aitmproxy/Quit.swift")
        #expect(helper.contains("static func endSheetsAndTerminate()"))
        #expect(helper.contains("NSApp.terminate(nil)"))
        #expect(helper.contains("preventsApplicationTerminationWhenModal = false"))
        #expect(!helper.contains("exit("))
        // Spec D2 amendment and D3/D4: the flag is cleared before `terminate` is called (the doc
        // comment names `NSApp.terminate(nil)` too, so the call is the last occurrence), and the
        // helper never writes a reply, alerts or beeps on the way there.
        #expect(try Self.offset(of: "preventsApplicationTerminationWhenModal = false", in: helper)
            < Self.offset(of: "NSApp.terminate(nil)", in: helper, options: .backwards))
        #expect(!helper.contains("replyToApplicationShouldTerminate"))
        #expect(!helper.contains("NSAlert"))
        #expect(!helper.contains("NSSound.beep"))
    }

    @Test func bothQuitRoutesCallTheHelper() throws {
        let app = try Self.text("Sources/Aitmproxy/App.swift")
        #expect(app.contains("CommandGroup(replacing: .appTermination)"))
        #expect(app.contains("\"Quit Aitmproxy\""))
        #expect(app.contains(".keyboardShortcut(\"q\")"))
        #expect(app.contains("kAEQuitApplication"))
        #expect(app.contains("withReplyEvent"))
        #expect(Self.count(of: "Quit.endSheetsAndTerminate()", in: app) >= 2)
        // Spec Anti-goals: the callers reach `terminate` only through the helper.
        #expect(!app.contains("NSApp.terminate("))
        // Spec Constraints: the Apple event handler is registered inside `applicationDidFinishLaunching`
        // (after AppKit installed its own, before `setActivationPolicy`); registered earlier, AppKit's
        // later installation would replace it and the Apple event route would silently go back to a
        // refused quit. `applicationWillFinishLaunching` is named in a comment, so pin the `func`.
        let didFinish = try Self.offset(of: "func applicationDidFinishLaunching(", in: app)
        let registration = try Self.offset(of: "kAEQuitApplication", in: app)
        let activation = try Self.offset(of: "NSApp.setActivationPolicy(.regular)", in: app)
        #expect(didFinish < registration && registration < activation)
        #expect(!app.contains("func applicationWillFinishLaunching"))
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
