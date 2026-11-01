import Foundation
import Testing
@testable import AitmproxyKit

/// The pure identifier rules of spec 2026-10-31-mac-app-icons-and-names D1 (AI-AC1 … AI-AC6).
/// Every expected value is a literal from the spec; no fixture, no shared data.
@Suite struct AppIdentifierTests {
    /// AI-AC1: the identifier, then every dotted prefix with at least three components, longest first.
    @Test func candidatesWalkDottedPrefixesDownToThree() {
        #expect(AppIdentifier.candidates(for: "com.google.Chrome.helper.renderer")
            == ["com.google.Chrome.helper.renderer", "com.google.Chrome.helper", "com.google.Chrome"])
        #expect(AppIdentifier.candidates(for: "com.apple.Safari.SandboxBroker")
            == ["com.apple.Safari.SandboxBroker", "com.apple.Safari"])
        #expect(AppIdentifier.candidates(for: "com.apple.curl") == ["com.apple.curl"])
        #expect(AppIdentifier.candidates(for: "aitm") == ["aitm"])
        #expect(AppIdentifier.candidates(for: ".hidden") == [".hidden"])
        #expect(AppIdentifier.candidates(for: "") == [""])
    }

    /// AI-AC2: a dotless identifier loses a `-` + 16-or-more lowercase-hex tail; everything else is unchanged.
    @Test func trimmedAdHocDropsALinkerHexTail() {
        #expect(AppIdentifier.trimmedAdHoc("node-5555494418ec1ba832083c9e9b4530af295cdd9b") == "node")
        #expect(AppIdentifier.trimmedAdHoc("cargo_nextest-15fbe60dbbdd586c") == "cargo_nextest")
        #expect(AppIdentifier.trimmedAdHoc("aitm-7728c895773169c7") == "aitm")
        #expect(AppIdentifier.trimmedAdHoc("t") == "t")
        #expect(AppIdentifier.trimmedAdHoc("aitm") == "aitm")
        // Too short to be a linker hash.
        #expect(AppIdentifier.trimmedAdHoc("node-abc") == "node-abc")
        // Uppercase is not the linker's form.
        #expect(AppIdentifier.trimmedAdHoc("node-5555494418EC1BA8") == "node-5555494418EC1BA8")
        // Has a dot: not an ad-hoc identifier.
        #expect(AppIdentifier.trimmedAdHoc("com.example.x-0123456789abcdef") == "com.example.x-0123456789abcdef")
    }

    /// AI-AC3: `knownUnbundled`, else `trimmedAdHoc`, else `ClientInfo.displayName(forSourceApp:)`.
    @Test func fallbackNameIsHonestForEveryUnbundledShape() {
        #expect(AppIdentifier.fallbackName(for: "com.apple.curl") == "curl")
        #expect(AppIdentifier.fallbackName(for: "com.apple.git-remote-http") == "git-remote-http")
        #expect(AppIdentifier.fallbackName(for: "node-5555494418ec1ba832083c9e9b4530af295cdd9b") == "node")
        #expect(AppIdentifier.fallbackName(for: "codex") == "codex")
        #expect(AppIdentifier.fallbackName(for: "a.out") == "out")
        #expect(AppIdentifier.fallbackName(for: "com.apple.dataaccessd") == "dataaccessd")
        #expect(AppIdentifier.fallbackName(for: "com.apple.usbmuxd") == "usbmuxd")
        #expect(AppIdentifier.fallbackName(for: "com.apple.AMPDeviceDiscoveryAgent") == "AMPDeviceDiscoveryAgent")
        #expect(AppIdentifier.fallbackName(for: "com.apple.WebKit.Networking") == "WebKit Networking")
        #expect(AppIdentifier.fallbackName(for: "com.apple.dt.xcode_select.tool-shim-public") == "developer tool")
        #expect(AppIdentifier.fallbackName(for: "obscura") == "obscura")
        // An RTL override in front of the identifier is stripped from what is shown.
        #expect(AppIdentifier.fallbackName(for: "\u{202E}com.evil.app") == "app")
        #expect(AppIdentifier.fallbackName(for: "\u{202E}com.evil.app")
            == ClientInfo.displayName(forSourceApp: "\u{202E}com.evil.app"))
    }

    /// AI-AC4: Cc/Cf scalars removed, whitespace trimmed, one trailing `.app` dropped, 64 characters at most, nil when empty.
    @Test func sanitizedStripsControlFormatWhitespaceAndDotApp() {
        #expect(AppIdentifier.sanitized("\u{200E}WhatsApp") == "WhatsApp")
        #expect(AppIdentifier.sanitized("  Zoom\n") == "Zoom")
        #expect(AppIdentifier.sanitized("Visual Studio Code.app") == "Visual Studio Code")
        #expect(AppIdentifier.sanitized("\u{202E}") == nil)
        #expect(AppIdentifier.sanitized("") == nil)
        #expect(AppIdentifier.sanitized(String(repeating: "x", count: 100)) == String(repeating: "x", count: 64))
        // The Kit's two category filters (this one and PR B's private `withoutControlAndBidi`) agree.
        let marked = "\u{200E}Wh\u{0007}atsApp"
        #expect(AppIdentifier.sanitized(marked) == "WhatsApp")
        #expect(AppIdentifier.sanitized(marked) == ClientInfo.displayName(forSourceApp: marked))
    }

    /// AI-AC5: the four service path shapes of D1, two plain app bundles, and the "(Service)" label with its 64-character cap.
    @Test func servicePathsAndLabel() {
        #expect(AppIdentifier.isServicePath(
            "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper.app"))
        #expect(AppIdentifier.isServicePath(
            "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc"))
        #expect(AppIdentifier.isServicePath("/Applications/Slack.app/Contents/Library/LoginItems/Slack Helper.app"))
        #expect(AppIdentifier.isServicePath("/Applications/Example.app/Contents/XPCServices/Example Service.xpc/Contents/MacOS/Example Service"))
        #expect(!AppIdentifier.isServicePath("/Applications/Safari.app"))
        #expect(!AppIdentifier.isServicePath("/Applications/Google Chrome.app"))

        #expect(AppIdentifier.serviceLabel("Google Chrome") == "Google Chrome (Service)")
        #expect(AppIdentifier.serviceLabel(String(repeating: "x", count: 70))
            == String(repeating: "x", count: 64) + " (Service)")
    }

    /// AI-AC6: groups key on the identifier when there is one, else the name; renaming keeps identifier and pid.
    @Test func groupKeyAndWithResolvedName() {
        #expect(ClientInfo(sourceApp: "com.apple.Safari").groupKey == "com.apple.Safari")
        #expect(ClientInfo(name: "curl").groupKey == "curl")

        let c = ClientInfo(sourceApp: "com.google.Chrome.helper").withResolvedName("Google Chrome (Service)")
        #expect(c.name == "Google Chrome (Service)")
        #expect(c.monogram == "G")
        #expect(c.bundleID == "com.google.Chrome.helper")
        #expect(c.pid == nil)
        // Already that name: an equal value, so a settled row never changes.
        #expect(c.withResolvedName("Google Chrome (Service)") == c)
    }

    // MARK: stage-6 security S-I1 / S-M3 (spec D1 caps and `tooltipText`, AI-AC1 literals)

    @Test func candidatesRefuseOversizeIdentifiers() {
        // 256 bytes with three components is still walked; one byte more is not asked of LaunchServices.
        let tail = String(repeating: "a", count: 256 - "com.x.".count)
        let atCap = "com.x." + tail
        #expect(atCap.utf8.count == 256)
        #expect(AppIdentifier.candidates(for: atCap) == [atCap])
        let overCap = atCap + "b"
        #expect(overCap.utf8.count == 257)
        #expect(AppIdentifier.candidates(for: overCap) == [])
        // Eight dotted components walk down to three; nine are refused outright.
        let eight = "a.b.c.d.e.f.g.h"
        #expect(AppIdentifier.candidates(for: eight).count == 6)
        #expect(AppIdentifier.candidates(for: eight).last == "a.b.c")
        #expect(AppIdentifier.candidates(for: eight + ".i") == [])
        // A 64 KiB all-dot identifier (the imported-session shape) yields no candidate at all.
        #expect(AppIdentifier.candidates(for: String(repeating: ".", count: 65536)) == [])
        // Multi-byte scalars count as bytes, not characters.
        let emoji = String(repeating: "\u{1F600}", count: 65)  // 65 × 4 = 260 bytes
        #expect(AppIdentifier.candidates(for: "a.b." + emoji) == [])
        #expect(AppIdentifier.maxIdentifierBytes == 256)
        #expect(AppIdentifier.maxIdentifierComponents == 8)
    }

    @Test func tooltipTextStripsFormatAndControlScalarsAndCaps() {
        #expect(AppIdentifier.tooltipText("com.apple.Safari") == "com.apple.Safari")
        // A right-to-left override cannot make the tail read as another vendor.
        #expect(AppIdentifier.tooltipText("com.evil.x\u{202E}irafaS.elppa.moc") == "com.evil.xirafaS.elppa.moc")
        #expect(AppIdentifier.tooltipText("a\u{0}b\u{7}c\u{200B}d") == "abcd")
        // No trimming and no `.app` rule: the tooltip is the identifier, not a display name.
        #expect(AppIdentifier.tooltipText(" com.x.app ") == " com.x.app ")
        #expect(AppIdentifier.tooltipText("").isEmpty)
        let long = String(repeating: "k", count: 300)
        #expect(AppIdentifier.tooltipText(long).count == 256)
        // The cap counts characters: a flag is one character of two scalars and is never split.
        let flags = String(repeating: "\u{1F1FA}\u{1F1F8}", count: 300)
        #expect(AppIdentifier.tooltipText(flags).count == 256)
        #expect(AppIdentifier.tooltipText(flags).unicodeScalars.count == 512)
    }
}
