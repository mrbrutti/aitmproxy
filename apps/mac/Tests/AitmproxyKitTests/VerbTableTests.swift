import Foundation
import Testing
@testable import AitmproxyKit

/// One verb table for row actions: titles, keys and enabled rules for every surface.
@Suite struct VerbTableTests {
    /// The four rows the table's rules turn on: parked, in flight, finished in scope, and out of scope.
    static let paused = Make.row(seq: 1, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login",
                                 state: .paused)
    static let pending = Make.row(seq: 2, host: "cdn.shop-staging.test", path: "/assets/hero.webp", state: .pending)
    static let finished = Make.row(seq: 3, host: "api.shop-staging.test", path: "/api/products", status: 200)
    static let outOfScope = Make.row(seq: 4, method: .post, host: "telemetry.vendor-analytics.example", path: "/v2/batch",
                                     status: 204, inScope: false)

    private func item(_ verb: FlowVerb, _ context: VerbContext?) -> VerbItem {
        VerbTable.item(verb, for: context)
    }

    @Test func pausedWithPendingEditsAppliesAndResumes() {
        let resume = item(.resume, VerbContext(row: Self.paused, pendingEdits: 2))
        #expect(resume.title == "Apply & Resume")
        #expect(resume.enabled)
        #expect(resume.shortcut == Shortcut("\r", command: true))
        #expect(item(.edit, VerbContext(row: Self.paused)).enabled)
        #expect(item(.kill, VerbContext(row: Self.paused)).enabled)
    }

    @Test func pausedWithoutEditsResumes() {
        let resume = item(.resume, VerbContext(row: Self.paused))
        #expect(resume.title == "Resume")
        #expect(resume.enabled)
        #expect(item(.delete, VerbContext(row: Self.paused)).title == "Kill")
    }

    @Test func finishedRowCannotResumeButDeletes() {
        let context = VerbContext(row: Self.finished)
        #expect(item(.resume, context).enabled == false)
        #expect(item(.resume, context).disabledReason == "Only a paused flow can be resumed")
        #expect(item(.edit, context).enabled == false)
        #expect(item(.edit, context).disabledReason == "Only a paused flow can be edited")
        #expect(item(.kill, context).enabled == false)
        let delete = item(.delete, context)
        #expect(delete.title == "Delete")
        #expect(delete.enabled)
        #expect(delete.key == "d")
        #expect(delete.shortcut == Shortcut("d"))
        #expect(item(.mark(nil), context).shortcut == nil)
        #expect(item(.quickLook, context).shortcut == nil)
        #expect(item(.comment, context).shortcut == Shortcut("l", command: true))
        #expect(item(.replay, context).enabled)
        #expect(item(.comment, context).title == "Comment…")
    }

    @Test func pendingRowKills() {
        #expect(item(.delete, VerbContext(row: Self.pending)).title == "Kill")
        #expect(item(.resume, VerbContext(row: Self.pending)).enabled == false)
    }

    @Test func outOfScopeDisablesEverythingWithTheReason() {
        let items = VerbTable.items(for: VerbContext(row: Self.outOfScope))
        #expect(items.allSatisfy { !$0.enabled })
        #expect(items.allSatisfy { $0.disabledReason == "Out of scope — add telemetry.vendor-analytics.example to scope to act" })
    }

    @Test func noRowDisablesEverythingWithDefaultTitles() {
        let items = VerbTable.items(for: nil)
        #expect(items.allSatisfy { !$0.enabled })
        #expect(items.allSatisfy { $0.disabledReason == nil })
        #expect(items.map(\.title).contains("Resume"))
        #expect(items.map(\.title).contains("Delete"))
        #expect(items.map(\.title).contains("Pin Host"))
    }

    @Test func multiSelectCountsTheSelection() {
        let three = VerbContext(row: Self.paused, selectedCount: 3, selectedPausedCount: 1)
        #expect(item(.resumeSelected, three).title == "Resume 3 Selected")
        #expect(item(.resumeSelected, three).enabled)
        #expect(item(.killSelected, three).title == "Kill 3 Selected")
        let nonePaused = VerbContext(row: Self.finished, selectedCount: 3, selectedPausedCount: 0)
        #expect(item(.resumeSelected, nonePaused).enabled == false)
        #expect(item(.resumeSelected, nonePaused).disabledReason == "No paused flows in the selection")
        let single = VerbContext(row: Self.paused, selectedCount: 1, selectedPausedCount: 1)
        #expect(item(.resumeSelected, single).title == "Resume Selected")
        #expect(item(.resumeSelected, single).enabled == false)
    }

    @Test func pinnedHostUnpins() {
        #expect(item(.pinHost, VerbContext(row: Self.finished, pinned: true)).title == "Unpin Host")
        #expect(item(.pinHost, VerbContext(row: Self.finished, pinned: false)).title == "Pin Host")
        #expect(item(.pinHost, VerbContext(row: Self.finished)).shortcut == Shortcut("p", shift: true))
    }

    @Test func keysMapToVerbs() {
        #expect(VerbTable.verb(forKey: "e") == .edit)
        #expect(VerbTable.verb(forKey: "d") == .delete)
        #expect(VerbTable.verb(forKey: "r") == .replay)
        #expect(VerbTable.verb(forKey: "p") == .buildPoC)
        #expect(VerbTable.verb(forKey: "m") == .mark(nil))
        #expect(VerbTable.verb(forKey: "c") == .comment)
        #expect(VerbTable.verb(forKey: " ") == .quickLook)
        #expect(VerbTable.verb(forKey: "x") == nil)
        #expect(VerbTable.verb(forKey: "i") == nil)
    }

    @Test func groupsAreOrderedAndTitlesComplete() {
        let items = VerbTable.items(for: nil)
        #expect(items.map(\.group.rawValue) == items.map(\.group.rawValue).sorted())
        #expect(VerbTable.order == items.map(\.verb))
        #expect(VerbTable.order.first == .resume)
        #expect(VerbTable.allTitles[.resume] == ["Resume", "Apply & Resume"])
        #expect(VerbTable.allTitles[.comment] == ["Comment…", "Edit Comment…"])
        #expect(Set(VerbTable.allTitles.keys) == Set(items.map(\.verb)))
    }

    @Test func everyMarkColourSharesTheMarkRow() {
        let outOfScope = VerbContext(row: Self.outOfScope)
        #expect(FlowVerb.mark(.red).tableKey == .mark(nil))
        #expect(VerbTable.item(.mark(.red), for: outOfScope).title == "Mark")
        #expect(VerbTable.item(.mark(.red), in: VerbTable.items(for: outOfScope)).title == "Mark")
        #expect(VerbTable.item(.mark(.red), for: outOfScope).enabled == false)
        #expect(VerbTable.item(.mark(.green), for: VerbContext(row: Self.finished)).enabled)
        #expect(VerbTable.titles(.mark(.blue)) == ["Mark"])
    }

    @Test func hintsPrintBareKeysAsLettersAndChordsAsGlyphs() {
        let context = VerbContext(row: Self.paused)
        #expect(VerbTable.item(.resume, for: context).hint == "⌘⏎")
        #expect(VerbTable.item(.edit, for: context).hint == "e")
        #expect(VerbTable.item(.kill, for: context).hint == "⌘\\")
        #expect(VerbTable.item(.editAndReplay, for: context).hint == "⇧R")
        #expect(VerbTable.item(.mark(nil), for: context).hint == "m")
        #expect(VerbTable.item(.copyURL, for: context).hint == nil)
        #expect(VerbTable.verb(forKey: "e") == .edit)
        #expect(VerbTable.verb(forKey: "i") == nil)
    }
}
