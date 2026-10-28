import Foundation
import Testing
@testable import AitmproxyKit

/// S-069: the brief's command map, the Kit's `CommandMap` and (in the
/// self-test) the real menu bar are one list.
@Suite struct CommandMapTests {
    static let briefURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appending(path: "docs/BRIEF.md")

    @Test func shortcutsParseAndPrint() {
        #expect(Shortcut(display: "⇧⌘C") == Shortcut("c", command: true, shift: true))
        #expect(Shortcut(display: "`i`") == Shortcut("i"))
        #expect(Shortcut(display: "⌥⌘⏎") == Shortcut("\r", command: true, option: true))
        #expect(Shortcut(display: "⌘⌫") == Shortcut("\u{8}", command: true))
        #expect(Shortcut(display: "Space") == Shortcut(" "))
        #expect(Shortcut(display: "⌘\\") == Shortcut("\\", command: true))
        #expect(Shortcut(display: "⌃⌘S")?.display == "⌃⌘S")
        #expect(Shortcut(display: "radio") == nil)
        #expect(Shortcut(display: "⌘1…⌘9") == nil)
    }

    @Test func briefParses() throws {
        let brief = try String(contentsOf: Self.briefURL, encoding: .utf8)
        let verbs = CommandMap.briefVerbs(in: brief)
        #expect(verbs.contains(CommandMap.BriefVerb(menu: "File", title: "Compose Request…", shortcut: "⌘N (`n`)")))
        #expect(verbs.contains(CommandMap.BriefVerb(menu: "Flow", title: "Focus Inspector", shortcut: "⏎")))
        #expect(verbs.contains(CommandMap.BriefVerb(menu: "Proxy", title: "Certificate Authority…", shortcut: nil)))
        #expect(Set(verbs.map(\.menu)) == ["File", "Flow", "View", "Agent", "Proxy"])
    }

    @Test func mapMatchesTheBrief() throws {
        let brief = try String(contentsOf: Self.briefURL, encoding: .utf8)
        let verbs = CommandMap.briefVerbs(in: brief)
        let mapped = Set(CommandMap.all.map { CommandMap.BriefVerb(menu: $0.menu, title: $0.brief, shortcut: $0.briefShortcut) })
        let missing = verbs.filter { !mapped.contains($0) }
        let extra = mapped.subtracting(verbs)
        #expect(missing.isEmpty, "in the brief, not in CommandMap: \(missing)")
        #expect(extra.isEmpty, "in CommandMap, not in the brief: \(extra)")
    }

    @Test func everyVerbWithABriefShortcutHasAMenuShortcut() {
        for entry in CommandMap.all where entry.scope == .menu {
            let wanted = entry.briefShortcut.flatMap(Shortcut.init(display:))
            let hasRange = entry.briefShortcut?.contains("…") == true
            if wanted != nil || hasRange {
                #expect(entry.items.contains { $0.shortcut != nil }, "\(entry.brief) has no shortcut")
            }
            #expect(!entry.items.isEmpty && entry.items.allSatisfy { !$0.titles.isEmpty }, "\(entry.brief) has no items")
        }
        let deferred = CommandMap.all.filter { if case .deferred = $0.scope { return true } else { return false } }
        #expect(deferred.map(\.brief) == ["Import…", "Export Selection…", "Save Session", "Focus Inspector"])
    }

    @Test func rowsDescribeThemselvesForVoiceOver() {
        let login = Fixtures.rows.first { $0.seq == 50 }!
        #expect(login.accessibilityDescription == "POST, paused, auth.shop-staging.test/api/auth/login, edited")
        let health = Fixtures.rows.first { $0.seq == 54 }!
        #expect(health.accessibilityDescription == "HEAD, 200 OK, api.shop-staging.test/api/health, TLS failed")
        var marked = Fixtures.rows.first { $0.seq == 41 }!
        marked.mark = .red
        marked.comment = "look here"
        marked.inScope = false
        #expect(marked.accessibilityDescription.hasSuffix(", marked red, comment: look here, out of scope"))
    }
}
