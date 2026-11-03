import Foundation
import Testing

/// Drift guard for the app's principal class (spec
/// `docs/superpowers/specs/2026-11-03-mac-quit-ends-open-sheets-design.md`, D6): the three
/// homes of the name are the Swift source, `Info.plist.in`, and this test; `tools/snap-dev.sh`
/// derives it from the template rather than spelling it. The fourth test renders the
/// release plist from the template the way `build.sh` does (AC9).
@Suite struct PrincipalClassTests {
    /// `apps/mac`: test file → `AitmproxyKitTests` → `Tests` → `apps/mac`.
    static let macRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    /// The single spelling of the class name in this file.
    static let principalClass = "AitmApplication"

    static func text(_ relativePath: String) throws -> String {
        try String(contentsOf: macRoot.appending(path: relativePath), encoding: .utf8)
    }

    static func count(of needle: String, in haystack: String) -> Int {
        haystack.components(separatedBy: needle).count - 1
    }

    @Test func theSourceDeclaresThePrincipalClassAsAnObjCNamedNSApplicationSubclass() throws {
        let source = try Self.text("Sources/Aitmproxy/\(Self.principalClass).swift")
        #expect(source.contains(
            "@objc(\(Self.principalClass)) final class \(Self.principalClass): NSApplication"))
    }

    @Test func theTemplateNamesThePrincipalClassOnceAndNoLongerStockNSApplication() throws {
        let template = try Self.text("Info.plist.in")
        let entry = "<key>NSPrincipalClass</key><string>\(Self.principalClass)</string>"
        #expect(Self.count(of: entry, in: template) == 1)
        #expect(!template.contains("<string>NSApplication</string>"))
    }

    @Test func theDevBundleScriptWritesThePrincipalClassWithoutSpellingIt() throws {
        let script = try Self.text("tools/snap-dev.sh")
        #expect(script.contains("plutil -replace NSPrincipalClass"))
        #expect(!script.contains(Self.principalClass))
    }

    /// AC9: the release plist is the template verbatim apart from the two tokens
    /// `build.sh` substitutes with `sed`, so this is proof of the installed bundle's value.
    @Test func aPlistRenderedFromTheTemplateByTheReleaseSedCarriesThePrincipalClass() throws {
        let rendered = try Self.text("Info.plist.in")
            .replacingOccurrences(of: "__BUILD__", with: "0")
            .replacingOccurrences(of: "__VERSION__", with: "0.0.0")
        #expect(rendered.contains("<key>NSPrincipalClass</key><string>\(Self.principalClass)</string>"))
        #expect(!rendered.contains("__BUILD__"))
        #expect(!rendered.contains("__VERSION__"))
    }
}
