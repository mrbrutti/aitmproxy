import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

// MARK: - Jobs view: merged facts, re-read rule, selection, link facts (plan Task 1.2)

/// Jobs view spec D2, D3, D6 and D15 (plan Task 1.2): the merged facts the row
/// and the detail both read, the predicate that drives the status poll, the
/// list-driven selection, the cancel gate and the bus-link facts with the
/// banner strings. Pins AC3, AC4, AC7 (pure half), AC8 (unit half) and AC12
/// (unit half) with the spec's literals.
@Suite struct ScanJobsFactsTests {
    static func load(_ file: String) throws -> JSONValue { try ScanPack.load(file) }

    /// `scan.list.json`'s first row, re-stated with the given job, state and elapsed.
    static func summary(_ job: String = "scan-1a2b3c4d", state: ScanJobState, elapsedMs: Int) throws -> ScanJobSummary {
        var row = try #require(load("scan.list.json")["jobs"]?.arrayValue?.first)
        row = ScanPack.edited(row, path: ["job"], to: .string(job))
        row = ScanPack.edited(row, path: ["state"], to: .string(state.rawValue))
        row = ScanPack.edited(row, path: ["elapsed_ms"], to: .number(Double(elapsedMs)))
        return try ScanJobSummary(json: row)
    }

    /// `scan.status.json`, re-stated with the given job, state, elapsed and profile name.
    static func status(_ job: String = "scan-1a2b3c4d", state: ScanJobState, elapsedMs: Int,
                       profile: String = "standard") throws -> ScanJobStatus {
        var json = try load("scan.status.json")
        json = ScanPack.edited(json, path: ["job"], to: .string(job))
        json = ScanPack.edited(json, path: ["state"], to: .string(state.rawValue))
        json = ScanPack.edited(json, path: ["elapsed_ms"], to: .number(Double(elapsedMs)))
        json = ScanPack.edited(json, path: ["profile_name"], to: .string(profile))
        return try ScanJobStatus(json: json)
    }

    /// `scan.status.json` with the given state and elapsed, then the given edits
    /// (a key path and a value, applied in order).
    static func status(state: ScanJobState, elapsedMs: Int, edits: [([String], JSONValue)]) throws -> ScanJobStatus {
        var json = try load("scan.status.json")
        json = ScanPack.edited(json, path: ["state"], to: .string(state.rawValue))
        json = ScanPack.edited(json, path: ["elapsed_ms"], to: .number(Double(elapsedMs)))
        for (path, value) in edits { json = ScanPack.edited(json, path: path, to: value) }
        return try ScanJobStatus(json: json)
    }

    /// AC3: a job is read while no status is stored, and once more when the list
    /// calls it terminal while the stored status is still live; never otherwise.
    @Test func needsStatusReadFollowsTheListAndTheStoredState() throws {
        let running = try Self.summary(state: .running, elapsedMs: 42_000)
        let done = try Self.summary(state: .done, elapsedMs: 69_000)
        let cancelled = try Self.summary(state: .cancelled, elapsedMs: 115_000)
        let storedRunning = try Self.status(state: .running, elapsedMs: 42_000)
        let storedDone = try Self.status(state: .done, elapsedMs: 69_000)
        let storedCancelled = try Self.status(state: .cancelled, elapsedMs: 115_000)

        #expect(ScanSurfaceModel.needsStatusRead(summary: running, stored: nil) == true)
        #expect(ScanSurfaceModel.needsStatusRead(summary: done, stored: storedRunning) == true)
        #expect(ScanSurfaceModel.needsStatusRead(summary: running, stored: storedRunning) == false)
        #expect(ScanSurfaceModel.needsStatusRead(summary: done, stored: storedDone) == false)
        #expect(ScanSurfaceModel.needsStatusRead(summary: cancelled, stored: storedCancelled) == false)

        // Rule 1 (D2): the selected job is read every beat while its STORED status is
        // missing or live; a terminal stored status is final, whatever the list row says.
        #expect(ScanSurfaceModel.selectedNeedsStatusRead(stored: nil) == true)
        #expect(ScanSurfaceModel.selectedNeedsStatusRead(stored: storedRunning) == true)
        #expect(ScanSurfaceModel.selectedNeedsStatusRead(stored: storedDone) == false)
        #expect(ScanSurfaceModel.selectedNeedsStatusRead(stored: storedCancelled) == false)
        #expect(ScanSurfaceModel.selectedNeedsStatusRead(stored: try Self.status(state: .failed, elapsedMs: 12_000)) == false)
    }

    /// AC4 plus the plan's C1 tie: a terminal status wins, then a terminal list row,
    /// then the higher `elapsedMs`; the detail-only fields always come from the status.
    @Test func jobFactsPickTheNewerTruth() throws {
        // The list says done at 69 s while the stored status is still running at 65 s: the list wins.
        let listDone = ScanJobFacts.make(
            summary: try Self.summary(state: .done, elapsedMs: 69_000),
            status: try Self.status(state: .running, elapsedMs: 65_000, profile: "light-http"))
        #expect(listDone.job == "scan-1a2b3c4d")
        #expect(listDone.summary.state == .done)
        #expect(listDone.summary.elapsedMs == 69_000)
        #expect(listDone.status?.profileName == "light-http")
        #expect(listDone.status?.state == .running, "the status is kept as given")

        // Both live: the later elapsed wins.
        let later = ScanJobFacts.make(
            summary: try Self.summary(state: .running, elapsedMs: 65_000),
            status: try Self.status(state: .running, elapsedMs: 66_000))
        #expect(later.summary.elapsedMs == 66_000)
        let earlier = ScanJobFacts.make(
            summary: try Self.summary(state: .running, elapsedMs: 67_000),
            status: try Self.status(state: .running, elapsedMs: 66_000))
        #expect(earlier.summary.elapsedMs == 67_000)

        // A terminal status beats a later live list row.
        let terminalStatus = ScanJobFacts.make(
            summary: try Self.summary(state: .running, elapsedMs: 70_000),
            status: try Self.status(state: .cancelled, elapsedMs: 69_500))
        #expect(terminalStatus.summary.state == .cancelled)
        #expect(terminalStatus.summary.elapsedMs == 69_500)

        // The C1 tie: the list says cancelled, the stored status still says cancelling, same elapsed.
        let tie = ScanJobFacts.make(
            summary: try Self.summary(state: .cancelled, elapsedMs: 115_000),
            status: try Self.status(state: .cancelling, elapsedMs: 115_000))
        #expect(tie.summary.state == .cancelled)

        // No status yet: the list row alone, the detail-only fields absent.
        let bare = ScanJobFacts.make(summary: try Self.summary(state: .queued, elapsedMs: 0), status: nil)
        #expect(bare.summary.state == .queued)
        #expect(bare.status == nil)

        // `facts(for:)` is the one accessor: it merges the listed row with the stored status; nil when unlisted.
        var model = ScanSurfaceModel()
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 0)
        model.statuses["scan-1a2b3c4d"] = try Self.status(state: .running, elapsedMs: 43_000, profile: "standard")
        let facts = try #require(model.facts(for: "scan-1a2b3c4d"))
        #expect(facts.summary.elapsedMs == 43_000)
        #expect(facts.status?.profileName == "standard")
        let unread = try #require(model.facts(for: "scan-55667788"))
        #expect(unread.summary.state == .done)
        #expect(unread.status == nil)
        #expect(model.facts(for: "scan-elsewhere") == nil)
    }

    /// D2 (plan fix 1.5g): a facts value has one job id, its summary's. `job` is
    /// read off the summary, so the memberwise init takes only the two shapes.
    @Test func jobFactsReadTheJobOffTheSummary() throws {
        let summary = try Self.summary("scan-55667788", state: .done, elapsedMs: 69_000)
        let bare = ScanJobFacts(summary: summary, status: nil)
        #expect(bare.job == "scan-55667788")
        let status = try Self.status("scan-55667788", state: .done, elapsedMs: 69_000)
        let made = ScanJobFacts.make(summary: summary, status: status)
        #expect(made.job == "scan-55667788")
        #expect(made == ScanJobFacts(summary: status.summary, status: status))
    }

    /// AC8 (unit half) and D6's list facts: the list selects its newest job when
    /// nothing is selected, keeps a selection it still carries, and moves a
    /// selection the core dropped (unless this app started it) to the first row.
    @Test func applyListSelectsWhenNothingIsSelected() throws {
        var model = ScanSurfaceModel()
        #expect(model.selectedJob == nil)
        #expect(model.jobsLoadedAt == nil)
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 1_000)
        #expect(model.selectedJob == "scan-1a2b3c4d")
        #expect(model.jobsLoadedAt == 1_000)

        // An existing selection is never replaced by a newer job.
        var kept = ScanSurfaceModel()
        kept.selectedJob = "scan-55667788"
        kept.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 0)
        #expect(kept.selectedJob == "scan-55667788")

        // A selected job the list no longer carries, and this app is not waiting on, falls to the first row.
        var gone = ScanSurfaceModel()
        gone.selectedJob = "scan-gone"
        gone.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 0)
        #expect(gone.selectedJob == "scan-1a2b3c4d")

        // A job this app started stays selected while the list has yet to carry it.
        var local = ScanSurfaceModel()
        var start = try Self.load("scan.start.json")
        start = ScanPack.edited(start, path: ["job"], to: "scan-local")
        start = ScanPack.edited(start, path: ["status", "job"], to: "scan-local")
        local.applyStart(try ScanStartResult(json: start))
        local.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 0)
        #expect(local.selectedJob == "scan-local")

        // An empty list leaves nothing selected and does not invent a selection.
        var empty = ScanSurfaceModel()
        empty.applyList(try ScanListResult(json: ["jobs": []]), now: 0)
        #expect(empty.selectedJob == nil)

        // D6: a list failure stamps `readFailedAt` beside the error; the next list clears it.
        var failed = ScanSurfaceModel()
        failed.noteReadFailure(
            text: "Unable to list jobs: the bus did not reply in time", now: 5_000)
        #expect(failed.jobsError == "Unable to list jobs: the bus did not reply in time")
        #expect(failed.readFailedAt == 5_000)
        failed.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 7_000)
        #expect(failed.jobsError == nil)
        #expect(failed.readFailedAt == nil)
        #expect(failed.jobsLoadedAt == 7_000)
    }

    /// AC7 (pure half): a cancelling job is never Cancel Scan's target, by the
    /// merged state; a queued or running one is.
    @Test func cancelTargetSkipsACancellingJob() throws {
        var model = ScanSurfaceModel()
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 0)
        model.selectedJob = "scan-1a2b3c4d"
        #expect(model.cancelTarget == "scan-1a2b3c4d")
        #expect(model.mayCancel(job: "scan-1a2b3c4d") == true)
        #expect(model.mayCancel(job: "scan-55667788") == false, "a done job cannot be cancelled")
        #expect(model.mayCancel(job: "scan-elsewhere") == false, "an unlisted job cannot be cancelled")

        // The list row still says running; the stored status (the `scan.cancel` reply) says cancelling: merged wins.
        model.statuses["scan-1a2b3c4d"] = try Self.status(state: .cancelling, elapsedMs: 43_000)
        #expect(model.facts(for: "scan-1a2b3c4d")?.summary.state == .cancelling)
        #expect(model.cancelTarget == nil)
        #expect(model.mayCancel(job: "scan-1a2b3c4d") == false)

        // Through `applyStatus` the row itself turns cancelling; still no target.
        model.applyStatus(try Self.status(state: .cancelling, elapsedMs: 44_000))
        #expect(model.cancelTarget == nil)

        // A queued job is a target. With the selection on a done job there is no target
        // (D2 amendment: never a job the operator is not looking at); with no selection
        // the only live job is the target.
        model.applyStatus(try Self.status(state: .queued, elapsedMs: 0))
        model.selectedJob = "scan-55667788"
        #expect(model.cancelTarget == nil)
        model.selectedJob = nil
        #expect(model.cancelTarget == "scan-1a2b3c4d")

        // Two live jobs and no live selection: the choice would be a guess.
        var second = try Self.load("scan.list.json")
        var rows = try #require(second["jobs"]?.arrayValue)
        rows[1] = ScanPack.edited(rows[1], path: ["state"], to: "running")
        second = ScanPack.edited(second, path: ["jobs"], to: .array(rows))
        model.applyList(try ScanListResult(json: second), now: 0)
        model.selectedJob = nil
        #expect(model.cancelTarget == nil)
    }

    /// AC12 (unit half) and D15's banner table: the link kind from the bus state
    /// and the last list failure, the values' age, the verb gate and the words.
    @Test func jobsLinkKindsAndAge() {
        let reconnecting = ScanJobsLink.make(bus: .connecting("…"), readFailedAt: nil, jobsLoadedAt: 1_000, now: 43_000)
        #expect(reconnecting.kind == .reconnecting)
        #expect(reconnecting.valuesAgeMs == 42_000)
        #expect(reconnecting.verbsEnabled == false)
        #expect(reconnecting.bannerText == "Bus disconnected · showing values from 0:42 ago · reconnecting…")

        let unanswered = ScanJobsLink.make(bus: .connected("…"), readFailedAt: 5_000, jobsLoadedAt: 1_000, now: 43_000)
        #expect(unanswered.kind == .unanswered)
        #expect(unanswered.valuesAgeMs == 42_000)
        #expect(unanswered.verbsEnabled == false)
        #expect(unanswered.bannerText == "The core is not answering · showing values from 0:42 ago · retrying every 2 s")

        let live = ScanJobsLink.make(bus: .connected("…"), readFailedAt: nil, jobsLoadedAt: 1_000, now: 43_000)
        #expect(live.kind == .live)
        #expect(live.valuesAgeMs == 42_000)
        #expect(live.verbsEnabled == true)
        #expect(live.bannerText == nil)

        let disconnected = ScanJobsLink.make(bus: .disconnected, readFailedAt: nil, jobsLoadedAt: nil, now: 43_000)
        #expect(disconnected.kind == .disconnected)
        #expect(disconnected.valuesAgeMs == nil)
        #expect(disconnected.verbsEnabled == false)
        #expect(disconnected.bannerText == "Bus disconnected · Proxy ▸ Reconnect Bus (⌃⌘R) to retry",
                "the age clause is omitted before the first list")

        let disconnectedAged = ScanJobsLink.make(bus: .disconnected, readFailedAt: 5_000, jobsLoadedAt: 1_000, now: 43_000)
        #expect(disconnectedAged.kind == .disconnected, "a dead bus outranks a failed list")
        #expect(disconnectedAged.bannerText
                == "Bus disconnected · showing values from 0:42 ago · Proxy ▸ Reconnect Bus (⌃⌘R) to retry")

        let failed = ScanJobsLink.make(bus: .failed("…"), readFailedAt: nil, jobsLoadedAt: 1_000, now: 43_000)
        #expect(failed.kind == .disconnected)
        #expect(failed.verbsEnabled == false)

        let unansweredUnaged = ScanJobsLink.make(bus: .connected("…"), readFailedAt: 5_000, jobsLoadedAt: nil, now: 43_000)
        #expect(unansweredUnaged.bannerText == "The core is not answering · retrying every 2 s")

        // The list error's words (D6): the failed read's own wording is `jobsError`; the inline
        // text adds the last-good clause, and no age before the first list has landed.
        var model = ScanSurfaceModel()
        model.noteReadFailure(text: "Unable to list jobs: the bus did not reply in time", now: 43_000)
        #expect(model.jobsError == "Unable to list jobs: the bus did not reply in time")
        #expect(model.inlineJobsError(ageMs: 42_000)
                == "Unable to list jobs: the bus did not reply in time. Showing values from 0:42 ago; retrying every 2 s.")
        #expect(model.inlineJobsError(ageMs: nil)
                == "Unable to list jobs: the bus did not reply in time. Retrying every 2 s.")
    }

    /// AC9 and the parity pin P1–P14 (D4): `ScanEndText` spells the spec's table
    /// byte for byte, with grouped numbers and `ScanFormat.plural`'s singulars.
    @Test func endTextIsTheSpecsSentences() throws {
        // P4–P8 and AC9: the stopped-reason sentences; nil where the state sentence or the error says it.
        #expect(ScanEndText.stoppedReason(.errors, state: .done, probesBudget: 2000, error: nil)
                == "Stopped early: too many errors from the target.")
        #expect(ScanEndText.stoppedReason(.budget, state: .done, probesBudget: 2000, error: nil)
                == "Stopped early: the probe budget of 2,000 was spent. Raise it in the profile to go further.")
        #expect(ScanEndText.stoppedReason(.cancelled, state: .cancelled, probesBudget: 2000, error: nil) == nil)
        #expect(ScanEndText.stoppedReason(.failed, state: .failed, probesBudget: 2000, error: "boom") == nil)
        #expect(ScanEndText.stoppedReason(.other("paused"), state: .done, probesBudget: 2000, error: nil)
                == "Stopped early for a reason this app does not know.")
        // The rest of D4's table.
        #expect(ScanEndText.stoppedReason(.time, state: .done, probesBudget: 2000, error: nil)
                == "Stopped early: the time budget ran out.")
        #expect(ScanEndText.stoppedReason(.cancelled, state: .done, probesBudget: 2000, error: nil)
                == "Stopped early: the job was cancelled.", "a cancelled reason on a non-cancelled state is said")
        #expect(ScanEndText.stoppedReason(.sessionLost, state: .done, probesBudget: 2000, error: nil)
                == "Stopped early: the session was lost and the profile says stop when that happens.")
        #expect(ScanEndText.stoppedReason(.policy, state: .done, probesBudget: 2000, error: nil)
                == "Stopped early: the agent policy changed to paused or read-only.")
        #expect(ScanEndText.stoppedReason(.guardRefused, state: .done, probesBudget: 2000, error: nil)
                == "Stopped early: the L4 guard refused a target mid-run.")
        #expect(ScanEndText.stoppedReason(.failed, state: .failed, probesBudget: 2000, error: nil)
                == "Stopped early: an error ended the job.", "no error text to show, so the reason is said")
        #expect(ScanEndText.stoppedReason(.budget, state: .done, probesBudget: 500, error: nil)
                == "Stopped early: the probe budget of 500 was spent. Raise it in the profile to go further.")

        // P9 and the crawl raw line: the token as it came, for the data face only.
        #expect(ScanEndText.rawReasonLine(.errors) == "stopped_reason: errors")
        #expect(ScanEndText.rawReasonLine(.other("paused")) == "stopped_reason: paused")
        #expect(ScanEndText.rawCrawlErrorLine(.connectRefused) == "crawl.last_error: connect_refused")
        #expect(ScanEndText.rawCrawlErrorLine(.unknown("x")) == "crawl.last_error: x")

        // P10–P12: crawl trouble, singulars via `plural`, nil without errors.
        func crawl(pages: Int, errors: Int) throws -> ScanCrawlCounters {
            try ScanCrawlCounters(json: [
                "pages": .number(Double(pages)), "queued": 0, "depth": 0, "forms_submitted": 0,
                "errors": .number(Double(errors)),
            ])
        }
        #expect(ScanEndText.crawlTrouble(try crawl(pages: 1, errors: 1)) == "The crawl fetched 1 page and hit 1 error")
        #expect(ScanEndText.crawlTrouble(try crawl(pages: 46, errors: 2)) == "The crawl fetched 46 pages and hit 2 errors")
        #expect(ScanEndText.crawlTrouble(try crawl(pages: 37, errors: 0)) == nil)
        #expect(ScanEndText.crawlTrouble(try crawl(pages: 0, errors: 1)) == "The crawl fetched 0 pages and hit 1 error")

        // The Stopped section's crawl line: the trouble sentence joined with the last error's
        // words when the engine set one (it does only when no page was fetched); nil without errors.
        func crawlFailing(pages: Int, errors: Int, lastError: String) throws -> ScanCrawlCounters {
            try ScanCrawlCounters(json: [
                "pages": .number(Double(pages)), "errors": .number(Double(errors)), "last_error": .string(lastError),
            ])
        }
        #expect(ScanEndText.crawlTroubleLine(try crawl(pages: 1, errors: 1)) == "The crawl fetched 1 page and hit 1 error")
        #expect(ScanEndText.crawlTroubleLine(try crawlFailing(pages: 0, errors: 1, lastError: "connect_refused"))
                == "The crawl fetched 0 pages and hit 1 error — the target refused the connection")
        #expect(ScanEndText.crawlTroubleLine(try crawlFailing(pages: 0, errors: 3, lastError: "weird"))
                == "The crawl fetched 0 pages and hit 3 errors — the connection failed")
        #expect(ScanEndText.crawlTroubleLine(try crawl(pages: 37, errors: 0)) == nil)

        // One singular rule: `ScanFormat.plural`, grouped on request (the end-text sentences use it).
        #expect(ScanFormat.plural(1, "check") == "1 check")
        #expect(ScanFormat.plural(6468, "check") == "6468 checks")
        #expect(ScanFormat.plural(6468, "check", grouped: true) == "6,468 checks")
        #expect(ScanFormat.plural(1, "page", grouped: true) == "1 page")
        #expect(ScanFormat.plural(0, "error", grouped: true) == "0 errors")

        // P13, P14 and the rest of the `last_error` words.
        #expect(ScanEndText.crawlErrorWords(.connectRefused) == "the target refused the connection")
        #expect(ScanEndText.crawlErrorWords(.unknown("x")) == "the connection failed")
        #expect(ScanEndText.crawlErrorWords(.tls) == "TLS handshake failed")
        #expect(ScanEndText.crawlErrorWords(.timeout) == "the target did not answer in time")
        #expect(ScanEndText.crawlErrorWords(.h2NotNegotiated) == "the target does not speak HTTP/2")
        #expect(ScanEndText.crawlErrorWords(.transport) == "the connection failed")
        #expect(ScanEndText.crawlErrorWords(.other) == "the connection failed")

        // P1–P3: the end sentence from the merged facts; the list row carries other
        // counters, so the terminal status must be the truth the sentence reads.
        let done = ScanJobFacts.make(
            summary: try Self.summary(state: .done, elapsedMs: 69_000),
            status: try Self.status(state: .done, elapsedMs: 69_000, edits: [
                (["points", "found"], 1020), (["checks", "scheduled"], 6468), (["checks", "done"], 6468),
                (["checks", "running"], []), (["phase"], "done"),
            ]))
        #expect(ScanEndText.sentence(done) == "Done in 1:09 · 1,020 points · 6,468 checks.")

        let cancelled = ScanJobFacts.make(
            summary: try Self.summary(state: .cancelled, elapsedMs: 115_000),
            status: try Self.status(state: .cancelled, elapsedMs: 115_000, edits: [
                (["checks", "scheduled"], 6468), (["checks", "done"], 3236), (["stopped_reason"], "cancelled"),
            ]))
        #expect(ScanEndText.sentence(cancelled)
                == "Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays.")

        let failed = ScanJobFacts.make(
            summary: try Self.summary(state: .failed, elapsedMs: 12_000),
            status: try Self.status(state: .failed, elapsedMs: 12_000, edits: [
                (["stopped_reason"], "failed"), (["error"], "boom"),
            ]))
        #expect(ScanEndText.sentence(failed) == "Failed after 0:12.", "the error text is its own line, not the sentence")

        // Singulars in the sentence.
        let one = ScanJobFacts.make(
            summary: try Self.summary(state: .done, elapsedMs: 1_000),
            status: try Self.status(state: .done, elapsedMs: 1_000, edits: [
                (["points", "found"], 1), (["checks", "scheduled"], 1), (["checks", "done"], 1),
            ]))
        #expect(ScanEndText.sentence(one) == "Done in 0:01 · 1 point · 1 check.")

        // Nil while the job is live, and until the terminal status has landed (D2: the
        // checks are detail-only fields, nil until `scan.status` arrives).
        let running = ScanJobFacts.make(
            summary: try Self.summary(state: .running, elapsedMs: 42_000),
            status: try Self.status(state: .running, elapsedMs: 42_000, edits: []))
        #expect(ScanEndText.sentence(running) == nil)
        let cancelling = ScanJobFacts.make(
            summary: try Self.summary(state: .cancelling, elapsedMs: 42_000),
            status: try Self.status(state: .cancelling, elapsedMs: 42_000, edits: []))
        #expect(ScanEndText.sentence(cancelling) == nil)
        let queued = ScanJobFacts.make(summary: try Self.summary(state: .queued, elapsedMs: 0), status: nil)
        #expect(ScanEndText.sentence(queued) == nil)
        let unread = ScanJobFacts.make(summary: try Self.summary(state: .done, elapsedMs: 69_000), status: nil)
        #expect(ScanEndText.sentence(unread) == nil, "a done row whose status has not landed has no checks to say")

        // The grouped numbers every sentence uses: a comma every three digits, whatever the locale.
        #expect(ScanFormat.grouped(0) == "0")
        #expect(ScanFormat.grouped(999) == "999")
        #expect(ScanFormat.grouped(1000) == "1,000")
        #expect(ScanFormat.grouped(6468) == "6,468")
        #expect(ScanFormat.grouped(1_234_567) == "1,234,567")
    }

    /// Fix 1.5b and 1.5c: the `Cancelling…` title (D2, AC5) and the inline error's
    /// age clause (D6, AC12) both come from the Kit. `noteReadFailure(text:now:)` keeps
    /// the one failure record (the read's own wording and its stamp) so `inlineJobsError(ageMs:)`
    /// can add the last-good clause, while `jobsError` (its text) keeps its plain wording.
    /// Any failed Jobs read (list, status, cancel) marks the link (D6 amendment).
    @Test func cancellingTitleAndInlineListError() throws {
        #expect(ScanFormat.cancellingTitle == "Cancelling…")
        #expect(ScanFormat.cancelHelpText == "Stop this job; its issues stay (⌥⌘.)")

        var model = ScanSurfaceModel()
        model.noteReadFailure(
            text: "Unable to list jobs: the bus did not reply in time", now: 43_000)
        #expect(model.readFailure == ScanReadFailure(text: "Unable to list jobs: the bus did not reply in time", at: 43_000))
        #expect(model.readFailedAt == 43_000)
        #expect(model.jobsError == "Unable to list jobs: the bus did not reply in time")
        #expect(model.inlineJobsError(ageMs: 42_000)
                == "Unable to list jobs: the bus did not reply in time. Showing values from 0:42 ago; retrying every 2 s.")
        #expect(model.inlineJobsError(ageMs: nil)
                == "Unable to list jobs: the bus did not reply in time. Retrying every 2 s.")

        // The next list that lands clears the failure with the stamp and the error.
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 45_000)
        #expect(model.readFailure == nil)
        #expect(model.readFailedAt == nil)
        #expect(model.jobsError == nil)
        #expect(model.inlineJobsError(ageMs: 1_000) == nil)

        // A failed status read marks the link too (the poll reads the selected job's status
        // before the list, so against a frozen core it is the first to time out); the inline
        // error starts with that read's own wording and carries the age clause.
        model.noteReadFailure(
            text: "Unable to read job scan-1a2b3c4d: the bus did not reply in time", now: 43_000)
        #expect(model.jobsError == "Unable to read job scan-1a2b3c4d: the bus did not reply in time")
        #expect(model.readFailedAt == 43_000)
        #expect(ScanJobsLink.make(bus: .connected("…"), readFailedAt: 43_000, jobsLoadedAt: 1_000, now: 43_000).kind
                == .unanswered)
        #expect(model.inlineJobsError(ageMs: 42_000)
                == "Unable to read job scan-1a2b3c4d: the bus did not reply in time. Showing values from 0:42 ago; retrying every 2 s.")
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 45_000)
        #expect(model.readFailure == nil)
        #expect(model.inlineJobsError(ageMs: 0) == nil)

        // A failed cancel marks the link the same way, with its own wording.
        model.noteReadFailure(text: "Unable to cancel job scan-1a2b3c4d: nope", now: 43_000)
        #expect(model.readFailedAt == 43_000)
        #expect(model.inlineJobsError(ageMs: 42_000)
                == "Unable to cancel job scan-1a2b3c4d: nope. Showing values from 0:42 ago; retrying every 2 s.")
    }

    /// Tester (Jobs view plan 1.6): the edges of D2's precedence, the re-read rule,
    /// the cancel gate and D6's link that AC3, AC4, AC7 and AC12 do not name, each
    /// with the literal the Kit must produce.
    @Test func factsReReadCancelGateAndLinkAtTheEdges() throws {
        // D2 precedence: a terminal status wins even over a terminal list row that is later.
        let bothTerminal = ScanJobFacts.make(
            summary: try Self.summary(state: .done, elapsedMs: 70_000),
            status: try Self.status(state: .done, elapsedMs: 69_000))
        #expect(bothTerminal.summary.elapsedMs == 69_000, "a terminal status is final; the list row never overrides it")
        // A failed status beats a running list row that is far ahead in elapsed.
        let failedBehind = ScanJobFacts.make(
            summary: try Self.summary(state: .running, elapsedMs: 500_000),
            status: try Self.status(state: .failed, elapsedMs: 12_000))
        #expect(failedBehind.summary.state == .failed)
        #expect(failedBehind.summary.elapsedMs == 12_000)
        // Neither terminal, equal elapsed: the status (the tie goes to the status).
        let evenLive = ScanJobFacts.make(
            summary: try Self.summary(state: .running, elapsedMs: 42_000),
            status: try Self.status(state: .cancelling, elapsedMs: 42_000))
        #expect(evenLive.summary.state == .cancelling)
        // An unknown state is not terminal: the higher elapsed decides, the status is kept.
        let unknown = ScanJobFacts.make(
            summary: try Self.summary(state: .other("paused"), elapsedMs: 50_000),
            status: try Self.status(state: .running, elapsedMs: 49_000))
        #expect(unknown.summary.state == .other("paused"))
        #expect(unknown.status?.state == .running)
        // `job` is the merged summary's; the status is kept whole even when it names another job.
        let crossed = ScanJobFacts.make(
            summary: try Self.summary("scan-aaaa", state: .running, elapsedMs: 1_000),
            status: try Self.status("scan-bbbb", state: .running, elapsedMs: 2_000))
        #expect(crossed.job == "scan-bbbb")
        #expect(crossed.status?.job == "scan-bbbb")

        // The re-read rule with unknown states: an unknown stored state is not terminal,
        // so a terminal list row forces one more read; an unknown list row never does.
        let paused = try Self.summary(state: .other("paused"), elapsedMs: 50_000)
        let done = try Self.summary(state: .done, elapsedMs: 69_000)
        let storedPaused = try Self.status(state: .other("paused"), elapsedMs: 50_000)
        let storedRunning = try Self.status(state: .running, elapsedMs: 42_000)
        let storedFailed = try Self.status(state: .failed, elapsedMs: 12_000)
        #expect(ScanSurfaceModel.needsStatusRead(summary: paused, stored: nil) == true)
        #expect(ScanSurfaceModel.needsStatusRead(summary: done, stored: storedPaused) == true)
        #expect(ScanSurfaceModel.needsStatusRead(summary: paused, stored: storedRunning) == false)
        #expect(ScanSurfaceModel.needsStatusRead(summary: paused, stored: storedPaused) == false)
        // A terminal stored status is final whatever the list row says.
        #expect(ScanSurfaceModel.needsStatusRead(summary: done, stored: storedFailed) == false)
        #expect(ScanSurfaceModel.needsStatusRead(summary: paused, stored: storedFailed) == false)
        let running = try Self.summary(state: .running, elapsedMs: 42_000)
        #expect(ScanSurfaceModel.needsStatusRead(summary: running, stored: storedFailed) == false)

        // The cancel gate: an unknown merged state is never a target; a locally started job
        // the list has not carried yet is (its `scan.start` status is queued).
        var model = ScanSurfaceModel()
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 0)
        model.applyStatus(storedPaused)
        #expect(model.facts(for: "scan-1a2b3c4d")?.summary.state == .other("paused"))
        #expect(model.mayCancel(job: "scan-1a2b3c4d") == false)
        #expect(model.cancelTarget == nil)
        var started = ScanSurfaceModel()
        var start = try Self.load("scan.start.json")
        start = ScanPack.edited(start, path: ["job"], to: "scan-local")
        start = ScanPack.edited(start, path: ["status", "job"], to: "scan-local")
        started.applyStart(try ScanStartResult(json: start))
        let local = try #require(started.facts(for: "scan-local"))
        #expect(local.summary.state == .queued)
        #expect(local.status?.job == "scan-local")
        #expect(started.mayCancel(job: "scan-local") == true)
        #expect(started.cancelTarget == "scan-local")
        // D2 amendment: with the selection on a cancelling job, Cancel Scan has no target,
        // even though another job in the list is running; the fallback to the only queued
        // or running job applies only while nothing is selected, and never between two.
        var twoJobs = try Self.load("scan.list.json")
        var rows = try #require(twoJobs["jobs"]?.arrayValue)
        rows[1] = ScanPack.edited(rows[1], path: ["state"], to: "running")
        twoJobs = ScanPack.edited(twoJobs, path: ["jobs"], to: .array(rows))
        model.applyList(try ScanListResult(json: twoJobs), now: 0)
        model.applyStatus(try Self.status(state: .cancelling, elapsedMs: 43_000))
        model.selectedJob = "scan-1a2b3c4d"
        #expect(model.cancelTarget == nil)
        model.selectedJob = nil
        #expect(model.cancelTarget == "scan-55667788", "no selection, one running job: that job")
        model.applyStatus(try Self.status(state: .running, elapsedMs: 44_000))
        #expect(model.cancelTarget == nil, "no selection, two running jobs: a guess, so nothing")

        // D3: an empty list never invents a selection, and a selection the list dropped
        // falls to nothing when the list is empty too.
        var dropped = ScanSurfaceModel()
        dropped.selectedJob = "scan-gone"
        dropped.applyList(try ScanListResult(json: ["jobs": []]), now: 0)
        #expect(dropped.selectedJob == nil)

        // D6: a connecting bus outranks a failed list; a second failure moves the stamp and
        // keeps the age of the last good list; the age clause clamps at 0:00 when the
        // caller's clock is behind the stamp.
        let connectingFailed = ScanJobsLink.make(bus: .connecting("…"), readFailedAt: 5_000, jobsLoadedAt: 1_000, now: 43_000)
        #expect(connectingFailed.kind == .reconnecting)
        #expect(connectingFailed.verbsEnabled == false)
        var failing = ScanSurfaceModel()
        failing.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 1_000)
        failing.noteReadFailure(
            text: "Unable to list jobs: the bus did not reply in time", now: 31_000)
        failing.noteReadFailure(text: "Unable to list jobs: the core closed the bus", now: 33_000)
        #expect(failing.readFailedAt == 33_000)
        #expect(failing.jobsLoadedAt == 1_000)
        #expect(failing.jobs.count == 2, "the rows and their counters stay through a failure")
        #expect(failing.inlineJobsError(ageMs: 32_000)
                == "Unable to list jobs: the core closed the bus. Showing values from 0:32 ago; retrying every 2 s.")
        let behind = ScanJobsLink.make(bus: .connected("…"), readFailedAt: 2_000, jobsLoadedAt: 1_000, now: 700)
        #expect(behind.valuesAgeMs == 0, "two clocks may disagree for a beat; the age never reads negative")
        #expect(behind.bannerText == "The core is not answering · showing values from 0:00 ago · retrying every 2 s")
        let hourOld = ScanJobsLink.make(bus: .disconnected, readFailedAt: nil, jobsLoadedAt: 0, now: 3_600_000)
        #expect(hourOld.bannerText == "Bus disconnected · showing values from 1:00:00 ago · Proxy ▸ Reconnect Bus (⌃⌘R) to retry")
        // (D6 amendment of 2026-11-02: a failed status or cancel read marks the link too;
        // `cancellingTitleAndInlineListError` pins it.)
        failing.applyList(try ScanListResult(json: Self.load("scan.list.json")), now: 35_000)
        #expect(failing.inlineJobsError(ageMs: 0) == nil)
        #expect(failing.jobsLoadedAt == 35_000)
    }

    /// Tester (Jobs view plan 1.6): the end-text edges D4 and the plan's gap 8 imply but
    /// AC9 does not spell out, each with its literal.
    @Test func endTextAtTheEdges() throws {
        // Gap 8: a `failed` job with an empty-string error has no error text, so the reason is said.
        #expect(ScanEndText.stoppedReason(.failed, state: .failed, probesBudget: 2000, error: "")
                == "Stopped early: an error ended the job.")
        #expect(ScanEndText.stoppedReason(.failed, state: .done, probesBudget: 2000, error: "boom") == nil,
                "the error text is shown whatever the state")
        // `cancelled` is only swallowed by the cancelled state itself, not by cancelling.
        #expect(ScanEndText.stoppedReason(.cancelled, state: .cancelling, probesBudget: 2000, error: nil)
                == "Stopped early: the job was cancelled.")
        #expect(ScanEndText.stoppedReason(.cancelled, state: .failed, probesBudget: 2000, error: nil)
                == "Stopped early: the job was cancelled.")
        // The budget sentence groups every size of budget.
        #expect(ScanEndText.stoppedReason(.budget, state: .done, probesBudget: 0, error: nil)
                == "Stopped early: the probe budget of 0 was spent. Raise it in the profile to go further.")
        #expect(ScanEndText.stoppedReason(.budget, state: .done, probesBudget: 1_000_000, error: nil)
                == "Stopped early: the probe budget of 1,000,000 was spent. Raise it in the profile to go further.")
        // The unknown reason's raw line carries the token as it came, including an empty one.
        #expect(ScanEndText.stoppedReason(.other(""), state: .done, probesBudget: 2000, error: nil)
                == "Stopped early for a reason this app does not know.")
        #expect(ScanEndText.rawReasonLine(.other("")) == "stopped_reason: ")
        #expect(ScanEndText.rawReasonLine(.budget) == "stopped_reason: budget")
        #expect(ScanEndText.rawReasonLine(.sessionLost) == "stopped_reason: session_lost")
        #expect(ScanEndText.rawReasonLine(.guardRefused) == "stopped_reason: guard_refused")
        #expect(ScanEndText.rawCrawlErrorLine(.h2NotNegotiated) == "crawl.last_error: h2_not_negotiated")
        #expect(ScanEndText.crawlErrorWords(.unknown("")) == "the connection failed")

        // Crawl trouble with large counts groups both numbers.
        let big = try ScanCrawlCounters(json: ["pages": 12_345, "errors": 1_000])
        #expect(ScanEndText.crawlTrouble(big) == "The crawl fetched 12,345 pages and hit 1,000 errors")
        let onePageManyErrors = try ScanCrawlCounters(json: ["pages": 1, "errors": 2])
        #expect(ScanEndText.crawlTrouble(onePageManyErrors) == "The crawl fetched 1 page and hit 2 errors")

        // `sentence`: an unknown state is not terminal, so no sentence; a done row whose
        // stored status is still live (the one-beat gap D2 hides) has no sentence yet either:
        // the checks it would quote are the live read's, so it waits for the terminal status.
        let exploded = ScanJobFacts.make(
            summary: try Self.summary(state: .other("exploded"), elapsedMs: 9_000),
            status: try Self.status(state: .other("exploded"), elapsedMs: 9_000, edits: []))
        #expect(ScanEndText.sentence(exploded) == nil)
        let gap = ScanJobFacts.make(
            summary: try Self.summary(state: .done, elapsedMs: 69_000),
            status: try Self.status(state: .running, elapsedMs: 65_000, edits: []))
        #expect(gap.summary.state == .done)
        #expect(ScanEndText.sentence(gap) == nil)
        // Cancelled with nothing run yet, and an hour-long failure.
        let cancelledEarly = ScanJobFacts.make(
            summary: try Self.summary(state: .cancelled, elapsedMs: 500),
            status: try Self.status(state: .cancelled, elapsedMs: 500, edits: [
                (["checks", "scheduled"], 0), (["checks", "done"], 0),
            ]))
        #expect(ScanEndText.sentence(cancelledEarly) == "Cancelled after 0:00; 0 of 0 checks had run. What it found stays.")
        let failedLate = ScanJobFacts.make(
            summary: try Self.summary(state: .failed, elapsedMs: 3_600_000),
            status: try Self.status(state: .failed, elapsedMs: 3_600_000, edits: [(["error"], "boom")]))
        #expect(ScanEndText.sentence(failedLate) == "Failed after 1:00:00.")

        // `grouped` at the integer edges: no trap, a leading minus, every group of three.
        #expect(ScanFormat.grouped(-1_234) == "-1,234")
        #expect(ScanFormat.grouped(-1) == "-1")
        #expect(ScanFormat.grouped(100_000) == "100,000")
        #expect(ScanFormat.grouped(Int.max) == "9,223,372,036,854,775,807")
        #expect(ScanFormat.grouped(Int.min) == "-9,223,372,036,854,775,808")
    }

    /// Fix 1.5f (security minor): a failed read's text is a core-controlled string the
    /// inline error prints, so `noteReadFailure` bounds it like `ScanJobStatus.error`:
    /// control and format scalars dropped, then cut to 400 scalars.
    @Test func readFailureTextIsCleanedAndBounded() {
        let hostile = String(repeating: "a", count: 300) + "\u{202E}" + String(repeating: "b", count: 299)
            + "\n" + String(repeating: "c", count: 399)
        #expect(hostile.count == 1_000)
        var model = ScanSurfaceModel()
        model.noteReadFailure(text: hostile, now: 43_000)
        #expect(model.jobsError?.unicodeScalars.count == 400)
        #expect(model.jobsError == String(repeating: "a", count: 300) + String(repeating: "b", count: 100))
        #expect(model.readFailure == ScanReadFailure(
            text: String(repeating: "a", count: 300) + String(repeating: "b", count: 100), at: 43_000))
        #expect(model.inlineJobsError(ageMs: 1_000)?.hasPrefix(String(repeating: "a", count: 300)) == true)
        // A short, clean text is stored as given.
        model.noteReadFailure(text: "Unable to list jobs: nope", now: 44_000)
        #expect(model.jobsError == "Unable to list jobs: nope")
    }

    /// Fix 1.5f (quality important): the status-read ledger behind D2's rule 2. A key
    /// (job, list-row-terminal) is claimed once; the read's own outcome never changes
    /// it. Only the next list that lands settles the ledger: a job that still owes a
    /// read (the read failed, so nothing is stored; or the row turned terminal over a
    /// live stored status) is re-armed, a job whose read landed keeps its key, and a
    /// job the list dropped is pruned.
    @Test func statusReadLedgerReArmsOnlyWhenAListLands() throws {
        let runningA = try Self.summary("scan-a", state: .running, elapsedMs: 1_000)
        let doneA = try Self.summary("scan-a", state: .done, elapsedMs: 5_000)
        let doneB = try Self.summary("scan-b", state: .done, elapsedMs: 2_000)
        let storedRunningA = try Self.status("scan-a", state: .running, elapsedMs: 1_000)
        let storedDoneA = try Self.status("scan-a", state: .done, elapsedMs: 5_000)
        let storedDoneB = try Self.status("scan-b", state: .done, elapsedMs: 2_000)

        var ledger = ScanStatusReadLedger()
        #expect(ledger.count == 0)
        #expect(ledger.claim("scan-a", summaryIsTerminal: false) == true)
        #expect(ledger.claim("scan-a", summaryIsTerminal: false) == false)
        #expect(ledger.claim("scan-b", summaryIsTerminal: true) == true)
        #expect(ledger.claim("scan-c", summaryIsTerminal: false) == true)
        #expect(ledger.count == 3)
        #expect(ledger.keys == [
            ScanStatusReadLedger.Key(job: "scan-a", summaryIsTerminal: false),
            ScanStatusReadLedger.Key(job: "scan-b", summaryIsTerminal: true),
            ScanStatusReadLedger.Key(job: "scan-c", summaryIsTerminal: false),
        ])

        // A list lands. scan-a's read failed (nothing stored): re-armed. scan-b's terminal
        // read landed: kept. scan-c is no longer listed: pruned.
        ledger.settle(afterList: [runningA, doneB], stored: ["scan-b": storedDoneB])
        #expect(ledger.count == 1)
        #expect(ledger.keys == [ScanStatusReadLedger.Key(job: "scan-b", summaryIsTerminal: true)])
        #expect(ledger.claim("scan-a", summaryIsTerminal: false) == true)
        #expect(ledger.claim("scan-b", summaryIsTerminal: true) == false)
        #expect(ledger.claim("scan-c", summaryIsTerminal: false) == true)

        // scan-a's read lands (live): its key is kept through the next list.
        ledger.settle(afterList: [runningA, doneB], stored: ["scan-a": storedRunningA, "scan-b": storedDoneB])
        #expect(ledger.count == 2)
        #expect(ledger.claim("scan-a", summaryIsTerminal: false) == false)

        // The list calls scan-a done over its live stored status: it owes the second
        // read, so the live key goes and the terminal key is claimable.
        ledger.settle(afterList: [doneA, doneB], stored: ["scan-a": storedRunningA, "scan-b": storedDoneB])
        #expect(ledger.keys == [ScanStatusReadLedger.Key(job: "scan-b", summaryIsTerminal: true)])
        #expect(ledger.claim("scan-a", summaryIsTerminal: true) == true)
        #expect(ledger.claim("scan-a", summaryIsTerminal: true) == false)

        // The terminal read lands: both keys survive the next list; a terminal stored
        // status is final.
        ledger.settle(afterList: [doneA, doneB], stored: ["scan-a": storedDoneA, "scan-b": storedDoneB])
        #expect(ledger.count == 2)
        #expect(ledger.claim("scan-a", summaryIsTerminal: true) == false)
        #expect(ledger.claim("scan-b", summaryIsTerminal: true) == false)

        // An empty list prunes everything.
        ledger.settle(afterList: [], stored: [:])
        #expect(ledger.count == 0)
        #expect(ledger == ScanStatusReadLedger())
    }
}
