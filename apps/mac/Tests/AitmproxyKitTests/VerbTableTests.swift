import Foundation
import Testing
@testable import AitmproxyKit

/// One verb table for row actions: titles, keys and enabled rules for every surface.
@Suite struct VerbTableTests {
    static let paused = Fixtures.rows.first { $0.state == .paused }!
    static let pending = Fixtures.rows.first { $0.state == .pending }!
    static let finished = Fixtures.rows.first { $0.state == .complete && $0.inScope && $0.comment == nil }!
    static let outOfScope = Fixtures.rows.first { !$0.inScope }!

    private func item(_ verb: FlowVerb, _ context: VerbContext?) -> VerbItem {
        VerbTable.items(for: context).first { $0.verb == verb }!
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
        #expect(item(.edit, context).enabled == false)
        #expect(item(.kill, context).enabled == false)
        let delete = item(.delete, context)
        #expect(delete.title == "Delete")
        #expect(delete.enabled)
        #expect(delete.key == "d")
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
        let items = VerbTable.items(for: VerbContext(row: Self.paused))
        #expect(VerbTable.verb(forKey: "e", in: items) == .edit)
        #expect(VerbTable.verb(forKey: "d", in: items) == .delete)
        #expect(VerbTable.verb(forKey: "r", in: items) == .replay)
        #expect(VerbTable.verb(forKey: "p", in: items) == .buildPoC)
        #expect(VerbTable.verb(forKey: "m", in: items) == .mark(nil))
        #expect(VerbTable.verb(forKey: "c", in: items) == .comment)
        #expect(VerbTable.verb(forKey: " ", in: items) == .quickLook)
        #expect(VerbTable.verb(forKey: "x", in: items) == nil)
        #expect(VerbTable.verb(forKey: "i", in: items) == nil)
    }

    @Test func groupsAreOrderedAndTitlesComplete() {
        let items = VerbTable.items(for: nil)
        #expect(items.map(\.group.rawValue) == items.map(\.group.rawValue).sorted())
        #expect(VerbTable.allTitles[.resume] == ["Resume", "Apply & Resume"])
        #expect(VerbTable.allTitles[.comment] == ["Comment…", "Edit Comment…"])
        #expect(Set(VerbTable.allTitles.keys) == Set(items.map(\.verb)))
    }
}
