import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// The scanner v2 fixture pack, read from the repo path (spec D14). The pack is
/// the parsing contract for the Kit's wire types and nothing more: a green parse
/// says the shapes agree, never that a scanner found anything. Shared by every
/// `Scan*Tests` file.
enum ScanPack {
    /// `crates/aitm-scan-model/fixtures/`: five steps up from this file
    /// (`AitmproxyKitTests` → `Tests` → `mac` → `apps` → the repo root).
    static let directory: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appending(path: "crates/aitm-scan-model/fixtures")

    static var url: URL { directory }

    /// The `*.json` names in the pack, sorted.
    static var files: [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? [])
            .filter { $0.hasSuffix(".json") }
            .sorted()
    }

    /// One file's text, verbatim.
    static func text(_ name: String) throws -> String {
        try String(contentsOf: directory.appending(path: name), encoding: .utf8)
    }

    /// One file parsed as the bus would deliver it.
    static func load(_ name: String) throws -> JSONValue {
        try JSONValue.parse(Data(contentsOf: directory.appending(path: name)))
    }
}

/// MS-AC1 and the decode half of MS-AC6: every pack file decodes into its Kit
/// type with its literals pinned, unknown vocabulary lands in `.other`, and the
/// profile re-encodes to the file it came from.
@Suite struct ScanModelTests {
    static let contractFiles: Set<String> = [
        "scan.start.json", "scan.map.json", "scan.status.json", "scan.list.json", "scan.cancel.json",
        "scan.issues.json", "scan.issue.json", "scan.issue.update.json", "scan.sitemap.json",
        "scan.checks.json", "scan.profile.list.json", "scan.profile.get.json", "scan.profile.save.json",
        "scan.profile.delete.json", "scan.session.preview.json",
        "job.started.json", "job.phase.json", "job.progress.json", "job.issue.json",
        "job.finished.json", "job.cancelled.json", "job.failed.json",
    ]

    @Test func scanStartFixture() throws {
        let result = try ScanStartResult(json: ScanPack.load("scan.start.json"))
        #expect(result.job == "scan-1a2b3c4d")
        #expect(result.status.state == .queued)
        #expect(result.clamped == [ScanClamped(field: "budget.probes", requested: 50000, applied: 20000)])
        #expect(result.lanes.skipped[0].lane == .ws)
        #expect(result.dryRun == nil)
    }

    @Test func scanMapFixture() throws {
        let result = try ScanStartResult(json: ScanPack.load("scan.map.json"))
        #expect(result.status.state == .running)
        #expect(result.status.phase == .crawling)
        #expect(result.status.elapsedMs == 1500)
    }

    @Test func scanStatusFixture() throws {
        let status = try ScanJobStatus(json: ScanPack.load("scan.status.json"))
        #expect(status.state == .running)
        #expect(status.phase == .auditing)
        #expect(status.probes.sent == 418)
        #expect(status.probes.budget == 2000)
        #expect(status.issues.bySeverity.high == 1)
        #expect(status.checks.running == ["http.reflected-xss", "http.sqli-error"])
        let session = try #require(status.session)
        #expect(session.canary == .flow(method: "GET", path: "/account", expectedStatus: 200))
        #expect(status.lanes.skipped[0].reason == "lane not available on this build")
        #expect(status.startedBy.clientLabel == "web-ui")
        #expect(status.summary.probes.sent == 418)
    }

    @Test func scanListFixture() throws {
        let result = try ScanListResult(json: ScanPack.load("scan.list.json"))
        #expect(result.jobs.count == 2)
        #expect(result.jobs[0].job == "scan-1a2b3c4d")
        #expect(result.jobs[0].state == .running)
        #expect(result.jobs[1].state == .done)
        #expect(result.jobs[1].issues.total == 0)
    }

    @Test func scanCancelFixture() throws {
        let status = try ScanJobStatus(json: ScanPack.load("scan.cancel.json"))
        #expect(status.state == .cancelling)
        #expect(status.stoppedReason == .cancelled)
        #expect(status.phase == .auditing)
    }

    @Test func scanIssuesFixture() throws {
        let result = try ScanIssuesResult(json: ScanPack.load("scan.issues.json"))
        #expect(result.issues.count == 2)
        #expect(result.issues[0].severity == .high)
        #expect(result.issues[0].confidence == .certain)
        #expect(result.issues[0].pocRef == "poc-3b1c")
        #expect(result.issues[0].findingId == "finding-7a21")
        #expect(result.issues[1].id == "issue-4c3b2a19")
        #expect(result.issues[1].location.name == "next")
        #expect(result.nextCursor == nil)
        #expect(result.bySeverity.medium == 1)
    }

    @Test func scanIssueFixture() throws {
        let issue = try ScanIssue(json: ScanPack.load("scan.issue.json"))
        #expect(issue.evidence.payload == "<script>aitm-canary()</script>")
        #expect(issue.evidence.probeFlows.count == 2)
        #expect(issue.evidence.baselineFlow == "16fd2706-8baf-433b-82eb-8c7fada847da")
        #expect(issue.remediation == "Contextually encode output and set a strict CSP.")
        #expect(issue.note == nil)
        #expect(issue.evidence.timing == nil)
    }

    @Test func scanIssueUpdateFixture() throws {
        let issue = try ScanIssue(json: ScanPack.load("scan.issue.update.json"))
        #expect(issue.status == .falsePositive)
        #expect(issue.note == "intended behaviour")
        #expect(issue.id == "issue-9f8e7d6c")
    }

    @Test func scanSitemapFixture() throws {
        let result = try ScanSitemapResult(json: ScanPack.load("scan.sitemap.json"))
        #expect(result.nodes.count == 1)
        #expect(result.nodes[0].pathTemplate == "/account/{id}")
        #expect(result.nodes[0].auth == true)
        #expect(result.nodes[0].points == 2)
        #expect(result.nodes[0].origin == "http://127.0.0.1:8080")
        #expect(result.points.count == 2)
        #expect(result.points[0].kind == "json_value")
        #expect(result.points[0].path == "profile.address.city")
        #expect(result.points[0].example == "Lisbon")
        #expect(result.points[1].example == "<redacted>")
        #expect(result.points[1].traits == ["id"])
        #expect(result.points[1].frequency == 9)
        #expect(result.nextCursor == "node-2")
    }

    @Test func scanChecksFixture() throws {
        let result = try ScanChecksResult(json: ScanPack.load("scan.checks.json"))
        #expect(result.checks.count == 3)
        #expect(result.checks[0].id == "http.reflected-xss")
        #expect(result.checks[0].intensity == .medium)
        #expect(result.checks[0].origin == .native)
        #expect(result.checks[1].origin == .bundled(path: "scripts/bundled/active/sqli.rhai"))
        #expect(result.checks[1].cwe == 89)
        #expect(result.checks[1].needsBaseline == true)
        #expect(result.checks[2].origin == .custom(path: "~/.aitmproxy/scripts/marker.rhai"))
        #expect(result.checks[2].intensity == .passive)
        #expect(result.checks[2].severity == .low)
    }

    @Test func scanProfileListFixture() throws {
        let result = try ScanProfileListResult(json: ScanPack.load("scan.profile.list.json"))
        #expect(result.profiles.count == 7)
        #expect(result.profiles[3].name == "standard")
        #expect(result.profiles[3].builtin == true)
        #expect(result.profiles[3].lanes == [.http, .ws])
        #expect(result.profiles[5].name == "l4-stream-safe")
        #expect(result.profiles[5].lanes == [.l4Stream])
    }

    @Test func scanProfileGetFixture() throws {
        let profile = try ScanProfile(json: ScanPack.load("scan.profile.get.json"))
        #expect(profile.name == "standard")
        #expect(profile.lanes == [.http, .ws])
        #expect(profile.intensity == .medium)
        #expect(profile.accuracy == .normal)
        #expect(profile.budget.probes == 2000)
        #expect(profile.budget.timeS == 600)
        #expect(profile.session.mode == .observed)
        #expect(profile.session.onLost == .stop)
        #expect(profile.target.origins == [])
        #expect(profile.checks.include == [])
        #expect(profile.hasL4Lane == false)
        #expect(profile.crawl?["max_depth"]?.intValue == 3)
    }

    @Test func scanProfileSaveFixture() throws {
        let result = try ScanProfileSaveResult(json: ScanPack.load("scan.profile.save.json"))
        #expect(result.saved == "my-api")
        #expect(result.path.hasSuffix("scan/profiles/my-api.yaml"))
    }

    @Test func scanProfileDeleteFixture() throws {
        let result = try ScanProfileDeleteResult(json: ScanPack.load("scan.profile.delete.json"))
        #expect(result.deleted == true)
    }

    @Test func scanSessionPreviewFixture() throws {
        let session = try ScanSessionProfile(json: ScanPack.load("scan.session.preview.json"))
        #expect(session.origin == "http://127.0.0.1:8080")
        #expect(session.cookies == ["sid"])
        #expect(session.headers == ["authorization"])
        #expect(session.sourceFlow == "550e8400-e29b-41d4-a716-446655440000")
        #expect(session.canary == .flow(method: "GET", path: "/account", expectedStatus: 200))
    }

    @Test func jobStartedFixture() throws {
        let line = try ScanJobNotification(json: ScanPack.load("job.started.json"))
        #expect(line.event == .started)
        #expect(line.seq == 1)
        #expect(line.kind == "scan")
        #expect(line.status.phase == .crawling)
        #expect(line.issue == nil)
    }

    @Test func jobPhaseFixture() throws {
        let line = try ScanJobNotification(json: ScanPack.load("job.phase.json"))
        #expect(line.event == .phase)
        #expect(line.seq == 2)
        #expect(line.status.phase == .passive)
    }

    @Test func jobProgressFixture() throws {
        let line = try ScanJobNotification(json: ScanPack.load("job.progress.json"))
        #expect(line.event == .progress)
        #expect(line.seq == 3)
        #expect(line.tsMs == 1761900000003)
        #expect(line.status.probes.sent == 418)
    }

    @Test func jobIssueFixture() throws {
        let line = try ScanJobNotification(json: ScanPack.load("job.issue.json"))
        #expect(line.event == .issue)
        #expect(line.seq == 4)
        #expect(line.issue?.id == "issue-9f8e7d6c")
        #expect(line.issue?.severity == .high)
    }

    @Test func jobFinishedFixture() throws {
        let line = try ScanJobNotification(json: ScanPack.load("job.finished.json"))
        #expect(line.event == .finished)
        #expect(line.seq == 5)
        #expect(line.status.state == .done)
        #expect(line.event.isTerminal)
    }

    @Test func jobCancelledFixture() throws {
        let line = try ScanJobNotification(json: ScanPack.load("job.cancelled.json"))
        #expect(line.event == .cancelled)
        #expect(line.seq == 6)
        #expect(line.status.state == .cancelled)
    }

    @Test func jobFailedFixture() throws {
        let line = try ScanJobNotification(json: ScanPack.load("job.failed.json"))
        #expect(line.event == .failed)
        #expect(line.seq == 7)
        #expect(line.status.state == .failed)
        #expect(line.status.phase == .done)
    }

    @Test func thePackHasExactlyTheContractFiles() {
        let files = Set(ScanPack.files)
        let stray = files.subtracting(Self.contractFiles)
        let missing = Self.contractFiles.subtracting(files)
        #expect(files == Self.contractFiles, "stray: \(stray), missing: \(missing)")
        #expect(files.count == 22)
    }

    /// The pack README's rule, mirrored so the mac reader fails the same way the
    /// Rust test does: no file carries a secret-looking value.
    @Test func noPackFileCarriesASecretValue() throws {
        let needles = ["Bearer ", "sid=", "Set-Cookie", "\"Cookie\":", "\"Authorization\":"]
        for name in ScanPack.files {
            let text = try ScanPack.text(name)
            for needle in needles {
                #expect(!text.contains(needle), "\(name) carries a secret-looking value: \(needle)")
            }
        }
    }

    @Test func unknownEnumValuesDecodeToOther() throws {
        let paused = ScanJobState(rawValue: "paused")
        #expect(paused == .other("paused"))
        #expect(paused?.rawValue == "paused")
        #expect(paused?.word == "paused")
        #expect(paused?.isTerminal == false)

        var members = try #require(try ScanPack.load("scan.status.json").objectValue)
        members["state"] = "paused"
        let status = try ScanJobStatus(json: .object(members))
        #expect(status.state == .other("paused"))

        #expect(ScanLane(rawValue: "quic") == .other("quic"))
        #expect(try ScanCheckOrigin(json: ["kind": "remote"]) == .other(kind: "remote"))
    }

    @Test func aNonObjectIsRefused() {
        #expect(throws: BusError.self) { try ScanJobStatus(json: .string("ok")) }
    }

    @Test func aMissingRequiredKeyIsRefused() throws {
        var members = try #require(try ScanPack.load("scan.issue.json").objectValue)
        members.removeValue(forKey: "id")
        #expect(throws: BusError.self) { try ScanIssue(json: .object(members)) }
    }

    @Test func severityMapsToTheKitSeverity() {
        #expect(ScanSeverity.high.known == Severity.high)
        #expect(ScanSeverity.other("blocker").known == nil)
    }

    /// MS-AC6, decode half: `JSONValue` equality is the normalisation (key order
    /// and whitespace vanish, numbers compare as `Double`).
    @Test func profileReencodesEqualToTheFile() throws {
        let file = try ScanPack.load("scan.profile.get.json")
        #expect(try ScanProfile(json: file).json() == file)
    }
}

// MARK: - Tester additions (stage 5)

extension ScanPack {
    /// `json` with the value at `path` replaced; a path element that reads as an
    /// integer indexes an array. Builds the malformed and edited pack lines the
    /// negative tests need without touching the files.
    static func edited(_ json: JSONValue, path: [String], to value: JSONValue) -> JSONValue {
        guard let head = path.first else { return value }
        let rest = Array(path.dropFirst())
        if let index = Int(head), case .array(var items) = json, items.indices.contains(index) {
            items[index] = edited(items[index], path: rest, to: value)
            return .array(items)
        }
        if case .object(var members) = json {
            members[head] = edited(members[head] ?? .null, path: rest, to: value)
            return .object(members)
        }
        return json
    }

    /// `json` with the key at `path` removed (the last element names the key).
    static func removing(_ json: JSONValue, path: [String]) -> JSONValue {
        guard let head = path.first else { return json }
        let rest = Array(path.dropFirst())
        if let index = Int(head), case .array(var items) = json, items.indices.contains(index) {
            items[index] = removing(items[index], path: rest)
            return .array(items)
        }
        guard case .object(var members) = json else { return json }
        if rest.isEmpty {
            members.removeValue(forKey: head)
        } else if let child = members[head] {
            members[head] = removing(child, path: rest)
        }
        return .object(members)
    }
}

/// Tester — the wire reader's edges: a value of the wrong JSON type, `null`
/// where a key is required, empty collections, oversized pages, the tagged
/// objects' malformed shapes, and every vocabulary's wire spelling both ways.
/// A decoder that coerced or defaulted any of these would fail here.
extension ScanModelTests {
    @Test func aWrongJSONTypeIsRefusedNeverCoerced() throws {
        let status = try ScanPack.load("scan.status.json")
        #expect(throws: BusError.malformed("ScanProbeCounters.sent is not a whole number")) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["probes", "sent"], to: "418"))
        }
        #expect(throws: BusError.malformed("ScanJobStatus.state is not a string")) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["state"], to: 5))
        }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["probes", "sent"], to: 4.5)) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["probes"], to: .array([]))) }
        #expect(throws: BusError.self) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["targets"], to: "http://127.0.0.1:8080"))
        }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["session", "reused"], to: "yes")) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["probes", "by_lane"], to: ["http"])) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["checks", "running"], to: [1, 2])) }

        let line = try ScanPack.load("job.progress.json")
        #expect(throws: BusError.self) { try ScanJobNotification(json: ScanPack.edited(line, path: ["seq"], to: "3")) }
        #expect(throws: BusError.self) { try ScanJobNotification(json: ScanPack.edited(line, path: ["seq"], to: -1)) }
        #expect(throws: BusError.self) { try ScanJobNotification(json: ScanPack.edited(line, path: ["seq"], to: 3.5)) }
        #expect(throws: BusError.self) { try ScanJobNotification(json: ScanPack.edited(line, path: ["status"], to: "running")) }
        #expect(try ScanJobNotification(json: ScanPack.edited(line, path: ["seq"], to: 9_007_199_254_740_992)).seq == 9_007_199_254_740_992)

        let issues = try ScanPack.load("scan.issues.json")
        #expect(throws: BusError.self) { try ScanIssuesResult(json: ScanPack.edited(issues, path: ["issues"], to: .object([:]))) }
        #expect(throws: BusError.self) {
            try ScanIssuesResult(json: ScanPack.edited(issues, path: ["issues", "0", "target", "port"], to: "8080"))
        }
        #expect(throws: BusError.self) { try ScanIssuesResult(json: ScanPack.edited(issues, path: ["issues", "1", "severity"], to: 2)) }

        let profile = try ScanPack.load("scan.profile.get.json")
        #expect(throws: BusError.self) { try ScanProfile(json: ScanPack.edited(profile, path: ["lanes"], to: "http")) }
        #expect(throws: BusError.self) { try ScanProfile(json: ScanPack.edited(profile, path: ["budget", "probes"], to: "2000")) }
        #expect(throws: BusError.self) { try ScanProfile(json: ScanPack.edited(profile, path: ["target", "l4"], to: .object([:]))) }
        #expect(throws: BusError.self) { try ScanProfile(json: .array([])) }
        #expect(throws: BusError.self) { try ScanProfile(json: .null) }
    }

    /// S1: a whole number outside `0...2^53` is malformed at parse, so the tallies
    /// the Kit adds (`BySeverity.total`) and the stamps it subtracts
    /// (`ScanFormat.relative`) can never trap on a hostile core's value.
    @Test func wholeNumbersOutsideTheSafeRangeAreRefused() throws {
        let status = try ScanPack.load("scan.status.json")
        #expect(throws: BusError.self) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["issues", "by_severity", "critical"], to: 9_223_372_036_854_775_807))
        }
        // 2^62 reads as an exact `Int`; only the range rule refuses it, and the sum of two would trap.
        #expect(throws: BusError.malformed("BySeverity.critical is not a whole number in 0...9007199254740992")) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["issues", "by_severity", "critical"], to: 4_611_686_018_427_387_904))
        }
        #expect(throws: BusError.self) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["issues", "by_severity", "low"], to: 9_007_199_254_740_994))
        }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["probes", "sent"], to: -1)) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["started_at"], to: -1)) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["finished_at"], to: -1)) }
        #expect(throws: BusError.self) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["probes", "by_lane", "http"], to: -1))
        }
        // The top of the range is still a value; `null` and absence still read as the default.
        let top = try ScanJobStatus(json: ScanPack.edited(status, path: ["issues", "by_severity", "critical"], to: 9_007_199_254_740_992))
        #expect(top.issues.bySeverity.critical == 9_007_199_254_740_992)
        #expect(top.issues.bySeverity.total == 9_007_199_254_740_992 + 3)
        let nulled = try ScanJobStatus(json: ScanPack.edited(status, path: ["issues", "by_severity", "critical"], to: .null))
        #expect(nulled.issues.bySeverity.critical == 0)

        let issue = try ScanPack.load("scan.issue.json")
        #expect(throws: BusError.malformed("ScanIssue.first_seen is not a whole number in 0...9007199254740992")) {
            try ScanIssue(json: ScanPack.edited(issue, path: ["first_seen"], to: -1))
        }
        #expect(throws: BusError.self) { try ScanIssue(json: ScanPack.edited(issue, path: ["last_seen"], to: -1)) }
        #expect(throws: BusError.self) { try ScanIssue(json: ScanPack.edited(issue, path: ["occurrences"], to: -1)) }
        // `timing` is null in the pack; a timing object with a negative sample is refused through `ints`.
        let timing: JSONValue = ["requested_s": [1.0], "observed_ms": [-1], "baseline_ms": [0], "slope": 1.0, "r": 1.0]
        #expect(throws: BusError.malformed("ScanTiming.observed_ms is not an array of whole numbers in 0...9007199254740992")) {
            try ScanIssue(json: ScanPack.edited(issue, path: ["evidence", "timing"], to: timing))
        }
        #expect(throws: BusError.self) {
            try ScanIssue(json: ScanPack.edited(issue, path: ["last_seen"], to: 9_223_372_036_854_775_807))
        }
        let zero = try ScanIssue(json: ScanPack.edited(issue, path: ["first_seen"], to: 0))
        #expect(zero.firstSeen == 0)

        // The `seq` reader has its own rule (any UInt64 up to 2^53); it is not widened by this one.
        let line = try ScanPack.load("job.progress.json")
        #expect(throws: BusError.self) { try ScanJobNotification(json: ScanPack.edited(line, path: ["seq"], to: -1)) }
    }

    /// Q4: a detail is its summary plus the evidence and prose; the summary is
    /// parsed once and every list field reads and writes through it.
    @Test func anIssueComposesItsSummary() throws {
        let json = try ScanPack.load("scan.issue.json")
        let issue = try ScanIssue(json: json)
        let summary = try ScanIssueSummary(json: json)
        #expect(issue.summary == summary)
        #expect(issue.id == "issue-9f8e7d6c")
        #expect(issue.job == "scan-1a2b3c4d")
        #expect(issue.checkId == "http.reflected-xss")
        #expect(issue.klass == "reflected-xss")
        #expect(issue.name == summary.name)
        #expect(issue.severity == .high)
        #expect(issue.confidence == summary.confidence)
        #expect(issue.status == .open)
        #expect(issue.lane == .http)
        #expect(issue.target == summary.target)
        #expect(issue.location == summary.location)
        #expect(issue.firstSeen == 1_761_900_000_000)
        #expect(issue.lastSeen == 1_761_900_000_000)
        #expect(issue.occurrences == 1)
        #expect(issue.pocRef == summary.pocRef)
        #expect(issue.findingId == summary.findingId)

        var edited = issue
        edited.status = .confirmed
        edited.occurrences = 2
        edited.id = "issue-other"
        #expect(edited.summary.status == .confirmed)
        #expect(edited.summary.occurrences == 2)
        #expect(edited.summary.id == "issue-other")
        #expect(edited.evidence == issue.evidence)
        #expect(edited.description == issue.description)
        #expect(edited != issue)
        edited.summary = summary
        #expect(edited == issue)

        let rebuilt = ScanIssue(
            summary: summary, evidence: issue.evidence, description: issue.description, remediation: issue.remediation,
            note: issue.note)
        #expect(rebuilt == issue)
    }

    @Test func nullInARequiredFieldIsRefused() throws {
        let issue = try ScanPack.load("scan.issue.json")
        #expect(throws: BusError.malformed("ScanIssue needs `id`")) {
            try ScanIssue(json: ScanPack.edited(issue, path: ["id"], to: .null))
        }
        #expect(throws: BusError.self) { try ScanIssue(json: ScanPack.edited(issue, path: ["target"], to: .null)) }
        #expect(throws: BusError.self) { try ScanIssue(json: ScanPack.edited(issue, path: ["evidence"], to: .null)) }
        #expect(throws: BusError.self) { try ScanIssue(json: ScanPack.edited(issue, path: ["location", "path"], to: .null)) }
        #expect(throws: BusError.self) { try ScanIssue(json: ScanPack.edited(issue, path: ["description"], to: .null)) }
        #expect(throws: BusError.self) { try ScanIssue(json: ScanPack.edited(issue, path: ["first_seen"], to: .null)) }

        let status = try ScanPack.load("scan.status.json")
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["probes"], to: .null)) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["job"], to: .null)) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["lanes"], to: .null)) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["started_by"], to: .null)) }

        let line = try ScanPack.load("job.progress.json")
        #expect(throws: BusError.self) { try ScanJobNotification(json: ScanPack.edited(line, path: ["status"], to: .null)) }
        #expect(throws: BusError.self) { try ScanJobNotification(json: ScanPack.edited(line, path: ["seq"], to: .null)) }
        #expect(throws: BusError.self) { try ScanJobNotification(json: ScanPack.removing(line, path: ["event"])) }
        #expect(throws: BusError.self) { try ScanJobNotification(json: ScanPack.removing(line, path: ["kind"])) }

        let profile = try ScanPack.load("scan.profile.get.json")
        #expect(throws: BusError.self) { try ScanProfile(json: ScanPack.removing(profile, path: ["target"])) }
        #expect(throws: BusError.self) { try ScanProfile(json: ScanPack.edited(profile, path: ["budget", "probes"], to: .null)) }
        #expect(throws: BusError.self) { try ScanProfile(json: ScanPack.edited(profile, path: ["session"], to: .null)) }
        #expect(throws: BusError.self) { try ScanProfile(json: ScanPack.edited(profile, path: ["intensity"], to: .null)) }

        let sitemap = try ScanPack.load("scan.sitemap.json")
        #expect(throws: BusError.self) { try ScanSitemapResult(json: ScanPack.edited(sitemap, path: ["points", "0", "frequency"], to: .null)) }
        #expect(throws: BusError.self) { try ScanSitemapResult(json: ScanPack.edited(sitemap, path: ["nodes", "0", "path_template"], to: .null)) }
    }

    @Test func nullOrAbsentOptionalFieldsAreTolerated() throws {
        var json = try ScanPack.load("scan.status.json")
        json = ScanPack.edited(json, path: ["session"], to: .null)
        json = ScanPack.edited(json, path: ["probes", "by_lane"], to: .null)
        json = ScanPack.edited(json, path: ["checks", "running"], to: .null)
        json = ScanPack.edited(json, path: ["started_by", "client_label"], to: .null)
        json = ScanPack.removing(json, path: ["clamped"])
        json = ScanPack.removing(json, path: ["points", "skipped"])
        json = ScanPack.removing(json, path: ["issues", "by_severity"])
        json = ScanPack.removing(json, path: ["profile_name"])
        json = ScanPack.removing(json, path: ["targets"])
        let decoded = try ScanJobStatus(json: json)
        #expect(decoded.session == nil)
        #expect(decoded.probes.byLane == [:])
        #expect(decoded.probes.sent == 418)
        #expect(decoded.checks.running == [])
        #expect(decoded.startedBy.clientLabel == nil)
        #expect(decoded.startedBy.frontend == "operator")
        #expect(decoded.clamped == [])
        #expect(decoded.points.skipped == ScanPointCounters.Skipped(ignored: 0, frequent: 0, limit: 0))
        #expect(decoded.points.found == 120)
        #expect(decoded.issues.bySeverity == .zero)
        #expect(decoded.issues.total == 3)
        #expect(decoded.profileName == "")
        #expect(decoded.targets == [])
        #expect(decoded.finishedAt == nil)
        #expect(decoded.stoppedReason == nil)
        #expect(decoded.error == nil)
        #expect(decoded.l4 == nil)

        // A counter absent from a tally reads as 0, never as an error.
        let probes = try ScanProbeCounters(json: ["sent": 7])
        #expect(probes == ScanProbeCounters(sent: 7, budget: 0, errors: 0, timeouts: 0, rateWaits: 0, byLane: [:]))
        #expect(try BySeverity(json: [:]) == .zero)
        #expect(try ScanIssueCounters(json: [:]).total == 0)

        // A session with no canary key is `.none`; `null` likewise.
        #expect(try ScanSessionStatus(json: ["reused": true]).canary == ScanCanary.none)
        #expect(try ScanSessionStatus(json: ["canary": .null]).canary == ScanCanary.none)
        #expect(try ScanSessionStatus(json: [:]).reused == false)

        // A check's optional fields.
        var checks = try ScanPack.load("scan.checks.json")
        checks = ScanPack.removing(checks, path: ["checks", "0", "cwe"])
        checks = ScanPack.removing(checks, path: ["checks", "0", "remediation"])
        checks = ScanPack.edited(checks, path: ["checks", "0", "wants_traits"], to: ["id"])
        let meta = try ScanChecksResult(json: checks).checks[0]
        #expect(meta.cwe == nil)
        #expect(meta.remediation == nil)
        #expect(meta.wantsTraits == ["id"])

        // A start result without `dry_run` and an issue without `note` / `poc_ref`.
        #expect(try ScanStartResult(json: ScanPack.load("scan.map.json")).dryRun == nil)
        let map = ScanPack.edited(try ScanPack.load("scan.map.json"), path: ["dry_run"], to: true)
        #expect(try ScanStartResult(json: map).dryRun == true)
        var issue = try ScanPack.load("scan.issue.json")
        issue = ScanPack.removing(issue, path: ["note"])
        issue = ScanPack.edited(issue, path: ["poc_ref"], to: .null)
        issue = ScanPack.removing(issue, path: ["evidence", "probe_flows"])
        let decodedIssue = try ScanIssue(json: issue)
        #expect(decodedIssue.note == nil)
        #expect(decodedIssue.pocRef == nil)
        #expect(decodedIssue.evidence.probeFlows == [])
    }

    @Test func emptyCollectionsDecodeToEmpty() throws {
        #expect(try ScanListResult(json: ["jobs": []]).jobs.isEmpty)
        #expect(try ScanListResult(json: [:]).jobs.isEmpty)
        let issues = try ScanIssuesResult(json: ["issues": [], "next_cursor": .null, "by_severity": [:]])
        #expect(issues.issues.isEmpty)
        #expect(issues.nextCursor == nil)
        #expect(issues.bySeverity == .zero)
        #expect(try ScanChecksResult(json: ["checks": []]).checks.isEmpty)
        #expect(try ScanProfileListResult(json: ["profiles": []]).profiles.isEmpty)
        let sitemap = try ScanSitemapResult(json: ["nodes": [], "points": []])
        #expect(sitemap.nodes.isEmpty)
        #expect(sitemap.points.isEmpty)
        #expect(sitemap.nextCursor == nil)
        let lanes = try ScanLaneReport(json: ["requested": [], "run": [], "skipped": []])
        #expect(lanes.requested.isEmpty)
        #expect(lanes.skipped.isEmpty)
        let selection = try ScanCheckSelection(json: [:])
        #expect(selection.include.isEmpty)
        #expect(selection.exclude.isEmpty)
        let session = try ScanSessionProfile(json: ["origin": "http://127.0.0.1:8080", "cookies": [], "headers": [], "observed_at": 1])
        #expect(session.cookies.isEmpty)
        #expect(session.headers.isEmpty)
        #expect(session.sourceFlow == nil)
        #expect(session.canary == ScanCanary.none)
        let target = try ScanProfileTarget(json: ["origins": []])
        #expect(target.origins.isEmpty)
        #expect(target.l4 == JSONValue.array([]))
        #expect(target.l4Rows.isEmpty)
    }

    @Test func anOversizedPageDecodesWhole() throws {
        let template = try #require(try ScanPack.load("scan.issues.json")["issues"]?[0])
        let items: [JSONValue] = (0..<5000).map { ScanPack.edited(template, path: ["id"], to: .string("issue-\($0)")) }
        let result = try ScanIssuesResult(json: ["issues": .array(items)])
        #expect(result.issues.count == 5000)
        #expect(result.issues[4999].id == "issue-4999")
        #expect(Set(result.issues.map(\.id)).count == 5000)
        #expect(result.bySeverity == .zero)

        let big = String(repeating: "A", count: 1 << 20)
        let issue = ScanPack.edited(try ScanPack.load("scan.issue.json"), path: ["evidence", "payload"], to: .string(big))
        #expect(try ScanIssue(json: issue).evidence.payload?.count == 1 << 20)

        // A status's running list is the exception: the Jobs detail prints it, so the
        // decoder holds the engine's own cap of 8 against a hostile core (fix 1.5e;
        // `coreStringsAreBoundedAndCleaned`). The page-sized lists above stay whole.
        let manyLanes = ScanPack.edited(try ScanPack.load("scan.status.json"), path: ["checks", "running"],
                                        to: .array((0..<1000).map { JSONValue.string("check-\($0)") }))
        let running = try ScanJobStatus(json: manyLanes).checks.running
        #expect(running.count == 8)
        #expect(running == ["check-0", "check-1", "check-2", "check-3", "check-4", "check-5", "check-6", "check-7"])
    }

    @Test func taggedObjectsRefuseAMalformedShape() throws {
        #expect(throws: BusError.self) { try ScanCanary(json: ["kind": "flow"]) }
        #expect(throws: BusError.self) { try ScanCanary(json: ["kind": "flow", "method": "GET"]) }
        #expect(throws: BusError.self) { try ScanCanary(json: ["kind": "flow", "method": "GET", "path": "/", "expected_status": "200"]) }
        #expect(throws: BusError.self) { try ScanCanary(json: "none") }
        #expect(throws: BusError.self) { try ScanCanary(json: [:]) }
        // An unknown canary kind refuses the whole status today (see the Tester's report).
        #expect(throws: BusError.self) { try ScanCanary(json: ["kind": "heartbeat"]) }
        #expect(try ScanCanary(json: ["kind": "flow", "method": "HEAD", "path": "/"])
            == .flow(method: "HEAD", path: "/", expectedStatus: nil))
        #expect(try ScanCanary(json: ["kind": "none", "method": "GET"]) == ScanCanary.none)

        #expect(throws: BusError.self) { try ScanCheckOrigin(json: ["kind": "bundled"]) }
        #expect(throws: BusError.self) { try ScanCheckOrigin(json: ["kind": "custom", "path": .null]) }
        #expect(throws: BusError.self) { try ScanCheckOrigin(json: [:]) }
        #expect(throws: BusError.self) { try ScanCheckOrigin(json: "native") }
        #expect(try ScanCheckOrigin(json: ["kind": "native", "path": "ignored"]) == .native)
        #expect(ScanCheckOrigin.other(kind: "remote").word == "remote")
        #expect(ScanCheckOrigin.bundled(path: "x").word == "bundled")

        let evidence: JSONValue = [
            "sent_hex": "00ff", "seed_id": "seed-1", "rng_seed": 42, "mutation_chain": ["flip", "truncate"],
            "prior_messages": 2, "oracle": ["kind": "crash"], "liveness_before": true, "liveness_after": false,
            "reproduced": [2, 3], "scope_entry": "l4-1",
        ]
        let l4 = try ScanL4Evidence(json: evidence)
        #expect(l4.reproducedHits == 2)
        #expect(l4.reproducedTries == 3)
        #expect(l4.oracle["kind"] == "crash")
        #expect(l4.mutationChain == ["flip", "truncate"])
        #expect(throws: BusError.self) { try ScanL4Evidence(json: ScanPack.edited(evidence, path: ["reproduced"], to: [2])) }
        #expect(throws: BusError.self) { try ScanL4Evidence(json: ScanPack.edited(evidence, path: ["reproduced"], to: [2, 3, 4])) }
        #expect(throws: BusError.self) { try ScanL4Evidence(json: ScanPack.edited(evidence, path: ["reproduced"], to: ["2", "3"])) }
        #expect(throws: BusError.self) { try ScanL4Evidence(json: ScanPack.removing(evidence, path: ["liveness_after"])) }

        let timing: JSONValue = ["requested_s": [1, 2.5], "observed_ms": [1000, 2500], "baseline_ms": [10], "slope": 1.0, "r": 0.99]
        let decodedTiming = try ScanTiming(json: timing)
        #expect(decodedTiming.requestedS == [1, 2.5])
        #expect(decodedTiming.observedMs == [1000, 2500])
        #expect(throws: BusError.self) { try ScanTiming(json: ScanPack.edited(timing, path: ["observed_ms"], to: [1000.5])) }
        #expect(throws: BusError.self) { try ScanTiming(json: ScanPack.removing(timing, path: ["slope"])) }

        #expect(throws: BusError.self) { try ScanProfileTarget(json: ["origins": [], "l4": [:]]) }
        #expect(throws: BusError.self) { try ScanProfileTarget(json: ["origins": "http://x"]) }
        #expect(try ScanProfileTarget(json: ["origins": [], "l4": .null]).l4 == JSONValue.array([]))
    }

    @Test func everyVocabularySpellsTheWireBothWays() throws {
        // Multi-word cases are where a spelling drifts from the crate's snake_case.
        #expect(ScanStoppedReason.sessionLost.rawValue == "session_lost")
        #expect(ScanStoppedReason(rawValue: "guard_refused") == .guardRefused)
        #expect(ScanLane.l4Packet.rawValue == "l4_packet")
        #expect(ScanLane(rawValue: "l4_stream") == .l4Stream)
        #expect(ScanLane.l4Stream.word == "L4 stream")
        #expect(ScanLane.l4Packet.word == "L4 packet")
        #expect(ScanLane.ws.word == "WebSocket")
        #expect(ScanLane.http.word == "HTTP")
        #expect(ScanLane.l4Packet.isL4 && ScanLane.l4Stream.isL4)
        #expect(!ScanLane.http.isL4 && !ScanLane.ws.isL4 && !ScanLane.other("quic").isL4)
        #expect(ScanAccuracy.fewerFalseNegatives.rawValue == "fewer_false_negatives")
        #expect(ScanAccuracy(rawValue: "fewer_false_positives") == .fewerFalsePositives)
        #expect(ScanIssueStatus.falsePositive.rawValue == "false_positive")
        #expect(ScanIssueStatus.falsePositive.word == "False positive")
        #expect(ScanOnLost.continue.rawValue == "continue")
        #expect(ScanSessionMode.none.rawValue == "none")

        // Ranks order the way the filters and the tree rely on.
        #expect([ScanIntensity.passive, .light, .medium, .intrusive].map(\.rank) == [0, 1, 2, 3])
        #expect([ScanConfidence.tentative, .firm, .certain].map(\.rank) == [0, 1, 2])
        #expect([ScanSeverity.critical, .high, .medium, .low, .info].map(\.rank) == [0, 1, 2, 3, 4])
        #expect([ScanSeverity.critical, .high, .medium, .low, .info].map(\.word) == ["Critical", "High", "Medium", "Low", "Info"])

        // Terminal states and events.
        #expect([ScanJobState.queued, .running, .cancelling].allSatisfy { !$0.isTerminal })
        #expect([ScanJobState.done, .cancelled, .failed].allSatisfy { $0.isTerminal })
        #expect([ScanJobState.queued, .running, .cancelling, .done, .cancelled, .failed].map(\.word)
                == ["Queued", "Running", "Cancelling", "Done", "Cancelled", "Failed"])
        #expect([ScanPhase.queued, .crawling, .passive, .auditing, .reporting, .done].map(\.word)
                == ["Queued", "Crawling", "Passive", "Auditing", "Reporting", "Done"])
        #expect([ScanJobEvent.started, .phase, .progress, .issue].allSatisfy { !$0.isTerminal })
        #expect([ScanJobEvent.finished, .cancelled, .failed].allSatisfy { $0.isTerminal })

        // `init?(rawValue:)` never returns nil for any vocabulary; the raw text survives.
        #expect(ScanPhase(rawValue: "warming") == .other("warming"))
        #expect(ScanPhase(rawValue: "warming")?.word == "warming")
        #expect(ScanStoppedReason(rawValue: "meteor")?.rawValue == "meteor")
        #expect(ScanIntensity(rawValue: "nuclear")?.rank == 99)
        #expect(ScanSpeed(rawValue: "ludicrous") == .other("ludicrous"))
        #expect(ScanAccuracy(rawValue: "perfect") == .other("perfect"))
        #expect(ScanConfidence(rawValue: "guess")?.rank == 99)
        #expect(ScanIssueStatus(rawValue: "triaged")?.word == "triaged")
        #expect(ScanSeverity(rawValue: "blocker")?.rank == 99)
        #expect(ScanSeverity(rawValue: "blocker")?.word == "blocker")
        #expect(ScanSessionMode(rawValue: "replay") == .other("replay"))
        #expect(ScanOnLost(rawValue: "pause") == .other("pause"))
        #expect(ScanJobEvent(rawValue: "paused")?.isTerminal == false)
        #expect(ScanJobEvent(rawValue: "")?.rawValue == "")

        // Unknown words anywhere in a row decode, never throw.
        var issues = try ScanPack.load("scan.issues.json")
        issues = ScanPack.edited(issues, path: ["issues", "0", "severity"], to: "blocker")
        issues = ScanPack.edited(issues, path: ["issues", "0", "confidence"], to: "guess")
        issues = ScanPack.edited(issues, path: ["issues", "0", "lane"], to: "quic")
        issues = ScanPack.edited(issues, path: ["issues", "0", "status"], to: "triaged")
        let row = try ScanIssuesResult(json: issues).issues[0]
        #expect(row.severity == .other("blocker"))
        #expect(row.confidence == .other("guess"))
        #expect(row.lane == .other("quic"))
        #expect(row.status == .other("triaged"))
        #expect(row.severity.known == nil)

        var profile = try ScanPack.load("scan.profile.get.json")
        profile = ScanPack.edited(profile, path: ["intensity"], to: "nuclear")
        profile = ScanPack.edited(profile, path: ["lanes"], to: ["http", "quic"])
        profile = ScanPack.edited(profile, path: ["session", "on_lost"], to: "pause")
        let decoded = try ScanProfile(json: profile)
        #expect(decoded.intensity == .other("nuclear"))
        #expect(decoded.lanes == [.http, .other("quic")])
        #expect(decoded.hasL4Lane == false)
        #expect(decoded.isIntrusive == false)
        // and re-encode as they came, so a save never rewrites a newer core's words.
        #expect(decoded.json() == profile)

        var line = try ScanPack.load("job.progress.json")
        line = ScanPack.edited(line, path: ["event"], to: "paused")
        line = ScanPack.edited(line, path: ["status", "state"], to: "paused")
        let notification = try ScanJobNotification(json: line)
        #expect(notification.event == .other("paused"))
        #expect(notification.status.state == .other("paused"))
        #expect(notification.status.state.word == "paused")

        let cancel = ScanPack.edited(try ScanPack.load("scan.cancel.json"), path: ["stopped_reason"], to: "meteor")
        #expect(try ScanJobStatus(json: cancel).stoppedReason == .other("meteor"))
    }

    /// The thinner pack files, pinned past the Coder's one or two literals.
    @Test func theThinnerFilesPinTheirLiterals() throws {
        let save = try ScanProfileSaveResult(json: ScanPack.load("scan.profile.save.json"))
        #expect(save.saved == "my-api")
        #expect(save.path == "/Users/operator/.aitmproxy/findings/scan/profiles/my-api.yaml")
        #expect(throws: BusError.self) { try ScanProfileSaveResult(json: ["saved": "my-api"]) }

        #expect(try ScanProfileDeleteResult(json: ["deleted": false]).deleted == false)
        #expect(throws: BusError.self) { try ScanProfileDeleteResult(json: ["deleted": "true"]) }
        #expect(throws: BusError.self) { try ScanProfileDeleteResult(json: [:]) }

        let cancel = try ScanJobStatus(json: ScanPack.load("scan.cancel.json"))
        #expect(cancel.job == "scan-1a2b3c4d")
        #expect(cancel.profileName == "standard")
        #expect(cancel.targets == ["http://127.0.0.1:8080"])
        #expect(cancel.finishedAt == nil)
        #expect(cancel.elapsedMs == 42000)
        #expect(cancel.state.isTerminal == false)

        let map = try ScanStartResult(json: ScanPack.load("scan.map.json"))
        #expect(map.job == "scan-1a2b3c4d")
        #expect(map.status.profileName == "standard")
        #expect(map.clamped == [])
        #expect(map.lanes.run == [.http])

        let started = try ScanJobNotification(json: ScanPack.load("job.started.json"))
        #expect(started.job == "scan-1a2b3c4d")
        #expect(started.tsMs == 1_761_900_000_001)
        #expect(started.status.state == .running)
        #expect(started.status.elapsedMs == 42000)

        let phase = try ScanJobNotification(json: ScanPack.load("job.phase.json"))
        #expect(phase.kind == "scan")
        #expect(phase.status.state == .running)
        #expect(phase.tsMs == 1_761_900_000_002)

        let cancelled = try ScanJobNotification(json: ScanPack.load("job.cancelled.json"))
        #expect(cancelled.status.phase == .done)
        #expect(cancelled.tsMs == 1_761_900_000_006)
        #expect(cancelled.event.isTerminal)
        #expect(cancelled.issue == nil)

        let failed = try ScanJobNotification(json: ScanPack.load("job.failed.json"))
        #expect(failed.tsMs == 1_761_900_000_007)
        #expect(failed.event.isTerminal)
        #expect(failed.status.state.isTerminal)
        #expect(failed.status.probes.sent == 0)

        let updated = try ScanIssue(json: ScanPack.load("scan.issue.update.json"))
        #expect(updated.status.word == "False positive")
        #expect(updated.summary.status == .falsePositive)
        #expect(updated.summary.id == updated.id)

        // `summary` views carry the same numbers as their owners.
        let status = try ScanJobStatus(json: ScanPack.load("scan.status.json"))
        #expect(status.summary == ScanJobSummary(
            job: status.job, state: status.state, phase: status.phase, elapsedMs: status.elapsedMs,
            probes: status.probes, points: status.points, issues: status.issues))
        #expect(status.probes.byLane == ["http": 418])
        #expect(status.crawl.formsSubmitted == 4)
        #expect(status.points.skipped.frequent == 3)
        #expect(status.issues.byConfidence == ByConfidence(certain: 1, firm: 1, tentative: 1))
    }
}

/// Tester — stage 6 fix round, S1 at the edges a JSON double has: negative zero,
/// the first integer past 2^53 (which the wire cannot carry), a power-of-ten
/// double that is an exact `Int`, a fraction, and the sums and subtractions the
/// Kit runs on a top-of-range value. With the range rule reverted the 1e16 cases
/// below read as values and the five-tally sum is the trap S1 named.
extension ScanModelTests {
    @Test func wholeNumbersAtTheDoubleBoundary() throws {
        let status = try ScanPack.load("scan.status.json")
        let top = 9_007_199_254_740_992

        // `-0` is a JSON number; it is the whole number 0, in range.
        let negativeZero = try ScanJobStatus(json: ScanPack.edited(status, path: ["probes", "sent"], to: -0.0))
        #expect(negativeZero.probes.sent == 0)

        // 1e16 is integral and an exact `Int`, but past 2^53: the range rule, not the type rule, refuses it.
        #expect(throws: BusError.malformed("ScanProbeCounters.sent is not a whole number in 0...9007199254740992")) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["probes", "sent"], to: 1e16))
        }
        // A fraction is refused by the type rule, with its own words (no range suffix).
        #expect(throws: BusError.malformed("ScanProbeCounters.sent is not a whole number")) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["probes", "sent"], to: 0.5))
        }
        // 2^53 + 1 cannot be a JSON double: it arrives as 2^53 and reads as 2^53.
        let rounded = try ScanJobStatus(json: ScanPack.edited(status, path: ["probes", "sent"], to: 9_007_199_254_740_993))
        #expect(rounded.probes.sent == top)

        // Every tally at the top of the range: the sum the Kit takes still fits, and the
        // words that read it (the ledger's and the Issues cells' counts) spell every count
        // in full, grouped (fix 2.12b: `severityCountsInWords` is gone; these are its readers).
        var all = status
        for key in ["critical", "high", "medium", "low", "info"] {
            all = ScanPack.edited(all, path: ["issues", "by_severity", key], to: 9_007_199_254_740_992)
        }
        let full = try ScanJobStatus(json: all)
        #expect(full.issues.bySeverity.total == 45_035_996_273_704_960)
        #expect(ScanFormat.issuesTileHelp(by: full.issues.bySeverity)
                == "45,035,996,273,704,960 issues: 9,007,199,254,740,992 critical, 9,007,199,254,740,992 high, "
                    + "9,007,199,254,740,992 medium, 9,007,199,254,740,992 low, 9,007,199,254,740,992 info")
        #expect(ScanFormat.severityWordParts(by: full.issues.bySeverity).map(\.1)
                == ["9,007,199,254,740,992 critical", "9,007,199,254,740,992 high", "9,007,199,254,740,992 medium",
                    "9,007,199,254,740,992 low", "9,007,199,254,740,992 info"])

        // The formatters subtract and divide a top-of-range stamp without a trap.
        // Tester finding T-F2: `elapsed(ms:)` formats its 64-bit hour count with `%d`, so
        // every elapsed_ms from 7_730_941_132_800_000 to the S1 ceiling prints a negative
        // hour count (`-1792967504:59:00` here); `%ld` prints the value below.
        #expect(ScanFormat.elapsed(ms: top) == "2501999792:59:00")
        #expect(ScanFormat.elapsed(ms: 7_730_941_132_800_000) == "2147483648:00:00")
        #expect(ScanFormat.elapsed(ms: 7_730_941_132_800_000 - 3_600_000) == "2147483647:00:00")
        #expect(ScanFormat.relative(ms: top, now: 0) == "0 s ago")
        #expect(ScanFormat.relative(ms: 0, now: top) == "2501999792 h ago")
        let late = try ScanJobStatus(json: ScanPack.edited(status, path: ["elapsed_ms"], to: 9_007_199_254_740_992))
        #expect(late.elapsedMs == top)
        #expect(ScanFormat.elapsed(ms: late.summary.elapsedMs) == "2501999792:59:00")

        // The other whole-number readers of a status refuse the same way.
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["elapsed_ms"], to: -1)) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["elapsed_ms"], to: 1e16)) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["points", "found"], to: 1e16)) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["points", "skipped", "limit"], to: -1)) }
        #expect(throws: BusError.self) { try ScanJobStatus(json: ScanPack.edited(status, path: ["issues", "total"], to: -1)) }
        #expect(throws: BusError.self) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["issues", "by_confidence", "certain"], to: 1e16))
        }
        #expect(throws: BusError.malformed("ScanProbeCounters.by_lane is not an object of whole numbers in 0...9007199254740992")) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["probes", "by_lane", "http"], to: 1e16))
        }

        // A push line's `ts_ms` and its embedded status: the same rule.
        let line = try ScanPack.load("job.progress.json")
        #expect(throws: BusError.malformed("ScanJobNotification.ts_ms is not a whole number in 0...9007199254740992")) {
            try ScanJobNotification(json: ScanPack.edited(line, path: ["ts_ms"], to: 1e16))
        }
        #expect(throws: BusError.self) {
            try ScanJobNotification(json: ScanPack.edited(line, path: ["status", "probes", "sent"], to: -1))
        }
        let zeroStamp = try ScanJobNotification(json: ScanPack.edited(line, path: ["ts_ms"], to: -0.0))
        #expect(zeroStamp.tsMs == 0)

        // A list page and an issues page carry the rule into their rows and tallies.
        let list = try ScanPack.load("scan.list.json")
        #expect(throws: BusError.self) {
            try ScanListResult(json: ScanPack.edited(list, path: ["jobs", "0", "probes", "budget"], to: 1e16))
        }
        #expect(throws: BusError.self) {
            try ScanListResult(json: ScanPack.edited(list, path: ["jobs", "1", "issues", "by_severity", "info"], to: -1))
        }
        let issues = try ScanPack.load("scan.issues.json")
        #expect(throws: BusError.malformed("BySeverity.high is not a whole number in 0...9007199254740992")) {
            try ScanIssuesResult(json: ScanPack.edited(issues, path: ["by_severity", "high"], to: 1e16))
        }
        #expect(throws: BusError.self) {
            try ScanIssuesResult(json: ScanPack.edited(issues, path: ["issues", "0", "occurrences"], to: 1e16))
        }

        // An issue's stamps at the top of the range format without a trap.
        let issue = try ScanPack.load("scan.issue.json")
        let topIssue = try ScanIssue(json: ScanPack.edited(issue, path: ["first_seen"], to: 9_007_199_254_740_992))
        #expect(topIssue.firstSeen == top)
        #expect(topIssue.summary.firstSeen == top)
        #expect(ScanFormat.relative(ms: topIssue.firstSeen, now: 1_761_900_000_000) == "0 s ago")
        #expect(ScanFormat.relative(ms: 0, now: topIssue.firstSeen) == "2501999792 h ago")
    }

    /// AC1 and AC2 (Jobs view spec D1): the check-error, skipped-check and crawl-error
    /// fields decode with their literals, and an older core's status without them
    /// reads 0 / `[]` / nil.
    @Test func checkAndCrawlErrorFieldsDecodeWithDefaults() throws {
        let checks = try ScanCheckCounters(json: JSONValue.parse(Data("""
            {"scheduled":4,"done":3,"running":[],"errors":7,\
            "error_samples":[{"check":"http.xss","point":"p1","detail":"Connection refused (os error 61)"}],\
            "skipped":3,"skipped_samples":[{"check":"fake.point","point":"p2","detail":"the lane hosts nothing"}]}
            """.utf8)))
        #expect(checks.scheduled == 4)
        #expect(checks.done == 3)
        #expect(checks.errors == 7)
        #expect(checks.errorSamples.count == 1)
        #expect(checks.errorSamples[0] == ScanCheckErrorSample(check: "http.xss", point: "p1", detail: "Connection refused (os error 61)"))
        #expect(checks.skipped == 3)
        #expect(checks.skippedSamples.count == 1)
        #expect(checks.skippedSamples[0].check == "fake.point")
        #expect(checks.skippedSamples[0].point == "p2")
        #expect(checks.skippedSamples[0].detail == "the lane hosts nothing")

        // A sample with a key missing reads "" (the engine's `#[serde(default)]`).
        #expect(try ScanCheckErrorSample(json: ["check": "http.xss"]) == ScanCheckErrorSample(check: "http.xss", point: "", detail: ""))
        #expect(throws: BusError.self) { try ScanCheckErrorSample(json: ["check": 7]) }
        #expect(throws: BusError.self) { try ScanCheckCounters(json: ["error_samples": "nope"]) }

        let crawl = try ScanCrawlCounters(json: JSONValue.parse(Data("""
            {"pages":1,"queued":0,"depth":0,"forms_submitted":0,"errors":1,"forms_skipped":2,"last_error":"connect_refused"}
            """.utf8)))
        #expect(crawl.pages == 1)
        #expect(crawl.errors == 1)
        #expect(crawl.formsSkipped == 2)
        #expect(crawl.lastError == .connectRefused)

        let weird = try ScanCrawlCounters(json: ["pages": 0, "last_error": "weird"])
        #expect(weird.lastError == .unknown("weird"))
        #expect(weird.lastError?.rawValue == "weird")
        #expect(try ScanCrawlCounters(json: ["pages": 0, "last_error": .null]).lastError == nil)

        // The vocabulary spells the wire both ways; the engine's own `other` is a known case.
        let kinds: [ScanCrawlErrorKind] = [.h2NotNegotiated, .connectRefused, .tls, .timeout, .transport, .other]
        #expect(kinds.map(\.rawValue) == ["h2_not_negotiated", "connect_refused", "tls", "timeout", "transport", "other"])
        for kind in kinds {
            #expect(ScanCrawlErrorKind(rawValue: kind.rawValue) == kind)
        }
        #expect(ScanCrawlErrorKind(rawValue: "other") == .other)
        #expect(ScanCrawlErrorKind.other("x") == .unknown("x"))

        // The fixture pack's status carries none of the keys: zero, empty, nil.
        let status = try ScanJobStatus(json: ScanPack.load("scan.status.json"))
        #expect(status.checks.errors == 0)
        #expect(status.checks.errorSamples == [])
        #expect(status.checks.skipped == 0)
        #expect(status.checks.skippedSamples == [])
        #expect(status.crawl.errors == 0)
        #expect(status.crawl.formsSkipped == 0)
        #expect(status.crawl.lastError == nil)
    }

    /// Tester (Jobs view plan 1.6): the D1 decoders at the edges AC1 and AC2 do not
    /// name: a wrong type, a negative count or a non-object sample is refused; an
    /// empty object reads every default; a sample list longer than the engine's cap
    /// of 8 is cut to the first 8 (the Kit holds the engine's own cap against a
    /// hostile core, fix 1.5e); an empty `last_error` token is an unknown kind
    /// whose raw value is the empty string.
    @Test func checkAndCrawlErrorFieldsAtTheEdges() throws {
        // Wrong types and negative counts are malformed wire, not defaults.
        #expect(throws: BusError.self) { try ScanCheckCounters(json: ["errors": "seven"]) }
        #expect(throws: BusError.self) { try ScanCheckCounters(json: ["errors": -1]) }
        #expect(throws: BusError.self) { try ScanCheckCounters(json: ["skipped": 1.5]) }
        #expect(throws: BusError.self) { try ScanCheckCounters(json: ["skipped_samples": ["check": "x"]]) }
        #expect(throws: BusError.self) { try ScanCheckCounters(json: ["error_samples": [7]]) }
        #expect(throws: BusError.self) { try ScanCheckCounters(json: ["error_samples": [["detail": 3]]]) }
        #expect(throws: BusError.self) { try ScanCrawlCounters(json: ["errors": "one"]) }
        #expect(throws: BusError.self) { try ScanCrawlCounters(json: ["forms_skipped": -2]) }
        #expect(throws: BusError.self) { try ScanCrawlCounters(json: ["last_error": 7]) }
        #expect(throws: BusError.self) { try ScanCheckErrorSample(json: "not an object") }
        #expect(throws: BusError.self) { try ScanCheckErrorSample(json: .null) }

        // Empty objects read every default.
        let emptyChecks = try ScanCheckCounters(json: [:])
        #expect(emptyChecks.scheduled == 0)
        #expect(emptyChecks.done == 0)
        #expect(emptyChecks.running == [])
        #expect(emptyChecks.errors == 0)
        #expect(emptyChecks.errorSamples == [])
        #expect(emptyChecks.skipped == 0)
        #expect(emptyChecks.skippedSamples == [])
        let emptyCrawl = try ScanCrawlCounters(json: [:])
        #expect(emptyCrawl.pages == 0)
        #expect(emptyCrawl.errors == 0)
        #expect(emptyCrawl.formsSkipped == 0)
        #expect(emptyCrawl.lastError == nil)
        #expect(try ScanCheckErrorSample(json: [:]) == ScanCheckErrorSample(check: "", point: "", detail: ""))
        #expect(try ScanCheckCounters(json: ["error_samples": [], "skipped_samples": []]).errorSamples == [])

        // An explicit null reads as absent (the engine's `Option` fields), so the default.
        #expect(try ScanCheckCounters(json: ["errors": .null]).errors == 0)
        #expect(try ScanCheckCounters(json: ["error_samples": .null]).errorSamples == [])

        // A sample list past the engine's cap of 8 is cut to the first 8, in order.
        let many = JSONValue.array((0..<64).map { i in
            .object(["check": .string("c\(i)"), "point": .string("p\(i)"), "detail": .string("d\(i)")])
        })
        let capped = try ScanCheckCounters(json: ["errors": 64, "error_samples": many, "skipped_samples": many])
        #expect(capped.errorSamples.count == 8)
        #expect(capped.skippedSamples.count == 8)
        #expect(capped.errorSamples[7] == ScanCheckErrorSample(check: "c7", point: "p7", detail: "d7"))

        // A detail with the engine's scrubbed text and non-ASCII survives verbatim.
        let detail = "Connection refused (os error 61) — «scrubbed» \u{1F512}"
        #expect(try ScanCheckErrorSample(json: ["detail": .string(detail)]).detail == detail)

        // The empty token is an unknown kind, round-trips, and reads as a failed connection.
        let blank = try ScanCrawlCounters(json: ["last_error": ""])
        #expect(blank.lastError == .unknown(""))
        #expect(blank.lastError?.rawValue == "")
        #expect(ScanCrawlErrorKind(rawValue: "") == .unknown(""))
        #expect(ScanCrawlErrorKind(rawValue: "CONNECT_REFUSED") == .unknown("CONNECT_REFUSED"), "tokens are case-sensitive")
        // The wire token `other` always lands in the engine's own case, never the escape
        // hatch (equality on a `ScanVocabulary` is by raw value, so only the case match tells).
        var landsInOther = false
        if case .other = try #require(ScanCrawlErrorKind(rawValue: "other")) { landsInOther = true }
        #expect(landsInOther)
        var landsInUnknown = false
        if case .unknown("weird") = try #require(ScanCrawlErrorKind(rawValue: "weird")) { landsInUnknown = true }
        #expect(landsInUnknown)

        // The status's row summary carries none of the new fields: a status with errors
        // and a crawl error still summarises to the same seven counters as the list row.
        var json = try ScanPack.load("scan.status.json")
        json = ScanPack.edited(json, path: ["checks", "errors"], to: 7)
        json = ScanPack.edited(json, path: ["crawl", "errors"], to: 1)
        json = ScanPack.edited(json, path: ["crawl", "last_error"], to: "connect_refused")
        let status = try ScanJobStatus(json: json)
        #expect(status.checks.errors == 7)
        #expect(status.crawl.lastError == .connectRefused)
        let row = try ScanListResult(json: ScanPack.load("scan.list.json")).jobs[0]
        #expect(status.summary == row)
    }

    /// Security review, fix 1.5e: every core-controlled string the Jobs detail can
    /// print is bounded at decode, one choke point (`ScanWire.cleaned`): control,
    /// format and line/paragraph separator scalars are dropped, then the text is cut
    /// to its field's cap (profile name 64; error, sample fields, clamped field,
    /// skipped reason and running ids 400; targets 200; an unknown vocabulary token
    /// 64); the sample, running and target lists are cut to the engine's own 8.
    /// `ScanWire.boundedArray`'s contract (D1 amendment; plan fix 1.5g): items past
    /// `listMax` are neither type-checked nor kept, so a malformed ninth item is not
    /// refused, while a malformed item inside the cap is. The two string helpers are
    /// named by what they return: `optionalBoundedString` (nil when absent) and
    /// `boundedString` (required; absent is malformed).
    @Test func boundedArrayContractAndTheTwoBoundedStringHelpers() throws {
        let status = try ScanPack.load("scan.status.json")
        let eight: [JSONValue] = ["a", "b", "c", "d", "e", "f", "g", "h"]
        let decoded = try ScanJobStatus(json: ScanPack.edited(status, path: ["checks", "running"], to: .array(eight + [42])))
        #expect(decoded.checks.running == ["a", "b", "c", "d", "e", "f", "g", "h"])
        #expect(throws: BusError.self) {
            try ScanJobStatus(json: ScanPack.edited(status, path: ["checks", "running"], to: .array([42])))
        }

        let wire = try ScanWire(["present": .string("ab\u{0007}cdef")], as: "T")
        #expect(try wire.optionalBoundedString("present", max: 4) == "abcd")
        #expect(try wire.optionalBoundedString("absent", max: 4) == nil)
        let required: String = try wire.boundedString("present", max: 4)
        #expect(required == "abcd")
        #expect(throws: BusError.malformed("T needs `absent`")) {
            let _: String = try wire.boundedString("absent", max: 4)
        }
    }

    @Test func coreStringsAreBoundedAndCleaned() throws {
        // A 1,000-character detail with a bidi override and a newline in it: 400 clean characters.
        let hostile = String(repeating: "a", count: 300) + "\u{202E}" + String(repeating: "b", count: 300)
            + "\n" + String(repeating: "c", count: 400)
        #expect(hostile.count == 1_002)
        let sample = try ScanCheckErrorSample(json: ["check": .string(hostile), "point": .string(hostile), "detail": .string(hostile)])
        #expect(sample.detail.count == 400)
        #expect(sample.detail == String(repeating: "a", count: 300) + String(repeating: "b", count: 100))
        #expect(!sample.detail.contains("\u{202E}"))
        #expect(!sample.detail.contains("\n"))
        #expect(sample.check == sample.detail)
        #expect(sample.point == sample.detail)

        // Nine samples decode to the engine's 8; so do nine running ids and nine targets.
        let nine = JSONValue.array((0..<9).map { i in .object(["check": .string("c\(i)"), "detail": .string("d\(i)")]) })
        let checks = try ScanCheckCounters(json: [
            "error_samples": nine, "skipped_samples": nine,
            "running": .array((0..<9).map { .string("run-\($0)" + String(repeating: "x", count: 500)) }),
        ])
        #expect(checks.errorSamples.count == 8)
        #expect(checks.errorSamples.last == ScanCheckErrorSample(check: "c7", point: "", detail: "d7"))
        #expect(checks.skippedSamples.count == 8)
        #expect(checks.running.count == 8)
        #expect(checks.running[0].count == 400)
        #expect(checks.running[0].hasPrefix("run-0xxx"))

        // A 200-character `last_error` with a control character: `.unknown` of 64 clean characters.
        let token = String(repeating: "k", count: 100) + "\u{0007}" + String(repeating: "m", count: 99)
        #expect(token.count == 200)
        let crawl = try ScanCrawlCounters(json: ["last_error": .string(token)])
        #expect(crawl.lastError == .unknown(String(repeating: "k", count: 64)))
        #expect(crawl.lastError?.rawValue.count == 64)
        #expect(ScanCrawlErrorKind(rawValue: token)?.rawValue == String(repeating: "k", count: 64))
        // The other vocabularies clean their unknown token the same way (the row and header print them).
        #expect(ScanJobState(rawValue: "ex\u{0000}ploded\u{2028}" + String(repeating: "!", count: 80))?.rawValue
                == "exploded" + String(repeating: "!", count: 56))
        #expect(ScanPhase(rawValue: "\u{2029}" + String(repeating: "p", count: 65))?.rawValue == String(repeating: "p", count: 64))
        #expect(ScanStoppedReason(rawValue: String(repeating: "r", count: 65) + "\r")?.rawValue == String(repeating: "r", count: 64))
        // Known tokens are untouched.
        #expect(ScanJobState(rawValue: "running") == .running)
        #expect(ScanCrawlErrorKind(rawValue: "connect_refused") == .connectRefused)

        // The status's own strings: profile name 64, error 400, each target 200 and at most 8,
        // a clamped field 400, a skipped lane's reason 400.
        var json = try ScanPack.load("scan.status.json")
        json = ScanPack.edited(json, path: ["profile_name"], to: .string(String(repeating: "n", count: 70) + "\u{200B}"))
        json = ScanPack.edited(json, path: ["error"], to: .string(hostile))
        json = ScanPack.edited(json, path: ["targets"], to: .array((0..<9).map { _ in .string(String(repeating: "t", count: 250)) }))
        json = ScanPack.edited(json, path: ["clamped"], to: .array([
            .object(["field": .string(hostile), "requested": 2, "applied": 1]),
        ]))
        json = ScanPack.edited(json, path: ["lanes", "skipped"], to: .array([
            .object(["lane": .string("ws"), "reason": .string(hostile)]),
        ]))
        let status = try ScanJobStatus(json: json)
        #expect(status.profileName == String(repeating: "n", count: 64))
        #expect(status.error?.count == 400)
        #expect(status.error == sample.detail)
        #expect(status.targets.count == 8)
        #expect(status.targets.allSatisfy { $0 == String(repeating: "t", count: 200) })
        #expect(status.clamped == [ScanClamped(field: sample.detail, requested: 2, applied: 1)])
        #expect(status.lanes.skipped == [ScanSkippedLane(lane: .ws, reason: sample.detail)])

        // Short, clean strings pass through untouched; an empty string stays empty.
        #expect(try ScanCheckErrorSample(json: ["detail": "Connection refused (os error 61) — «scrubbed» \u{1F512}"]).detail
                == "Connection refused (os error 61) — «scrubbed» \u{1F512}")
        #expect(try ScanJobStatus(json: ScanPack.load("scan.status.json")).profileName == "standard")
        #expect(ScanWire.cleaned("", max: 64) == "")
        #expect(ScanWire.cleaned("tab\there", max: 64) == "tabhere")
    }

    /// Fix 1.5f (security minors): `cleaned` cuts on Unicode scalars, not Characters, so
    /// a thousand combining marks on one base letter cannot ride through a 400 cap as one
    /// grapheme; and a job id is bounded at decode like every other core string the
    /// views print (`ScanWire.tokenMax`), while a missing id is still refused.
    @Test func cleanedCutsOnScalarsAndJobIdsAreBounded() throws {
        let marks = "a" + String(repeating: "\u{0301}", count: 1_000)
        #expect(marks.count == 1)
        #expect(marks.unicodeScalars.count == 1_001)
        let cut = ScanWire.cleaned(marks, max: 400)
        #expect(cut.unicodeScalars.count == 400)
        #expect(cut.unicodeScalars.first == "a")
        #expect(cut.unicodeScalars.dropFirst().allSatisfy { $0 == "\u{0301}" })
        // A plain string still cuts to `max` characters.
        #expect(ScanWire.cleaned(String(repeating: "x", count: 500), max: 400).count == 400)

        // A 300-character job id decodes to 64 scalars on a list row and on a status.
        let longJob = String(repeating: "j", count: 300)
        var row = try #require(ScanPack.load("scan.list.json")["jobs"]?.arrayValue?.first)
        row = ScanPack.edited(row, path: ["job"], to: .string(longJob))
        #expect(try ScanJobSummary(json: row).job == String(repeating: "j", count: 64))
        let status = ScanPack.edited(try ScanPack.load("scan.status.json"), path: ["job"], to: .string("\n" + longJob))
        let decoded = try ScanJobStatus(json: status)
        #expect(decoded.job.unicodeScalars.count == 64)
        #expect(decoded.job == String(repeating: "j", count: 64))
        // A short id is untouched; a missing one is still malformed.
        #expect(try ScanJobStatus(json: ScanPack.load("scan.status.json")).job == "scan-1a2b3c4d")
        var members = try #require(try ScanPack.load("scan.status.json").objectValue)
        members.removeValue(forKey: "job")
        #expect(throws: BusError.self) { try ScanJobStatus(json: .object(members)) }
    }

    /// Fix 2.12a (PR 2 security minor): `lanes.skipped`, `clamped` (on a status and on a
    /// start result) and `probes.by_lane` are cut to the engine's cap of 8 at decode like
    /// every other list (`ScanWire.listMax`), so a hostile core cannot draw ten thousand
    /// notice rows or run the Notices de-dup over them. `by_lane` keeps its first eight
    /// keys in sorted order: the parser's object is a Swift dictionary, so wire order is
    /// not available. The Notices list still de-duplicates against the launch's notices.
    @Test func skippedClampedAndByLaneAreBoundedAtDecode() throws {
        let nineSkipped = JSONValue.array((0..<9).map { i in .object(["lane": "ws", "reason": .string("r\(i)")]) })
        let nineClamped = JSONValue.array((0..<9).map { i in
            .object(["field": .string("f\(i)"), "requested": 9, "applied": .number(Double(i))])
        })
        var nineLanes: [String: JSONValue] = [:]
        for i in 0..<9 { nineLanes["lane\(i)"] = .number(Double(i)) }

        var status = try ScanPack.load("scan.status.json")
        status = ScanPack.edited(status, path: ["lanes", "skipped"], to: nineSkipped)
        status = ScanPack.edited(status, path: ["clamped"], to: nineClamped)
        status = ScanPack.edited(status, path: ["probes", "by_lane"], to: .object(nineLanes))
        let decoded = try ScanJobStatus(json: status)
        #expect(decoded.lanes.skipped.count == 8)
        #expect(decoded.lanes.skipped.first == ScanSkippedLane(lane: .ws, reason: "r0"))
        #expect(decoded.lanes.skipped.last == ScanSkippedLane(lane: .ws, reason: "r7"))
        #expect(decoded.clamped.count == 8)
        #expect(decoded.clamped.last == ScanClamped(field: "f7", requested: 9, applied: 7))
        #expect(decoded.probes.byLane.count == 8)
        #expect(decoded.probes.byLane.keys.sorted() == (0..<8).map { "lane\($0)" })
        #expect(decoded.probes.byLane["lane7"] == 7)
        #expect(decoded.probes.byLane["lane8"] == nil)

        var start = try ScanPack.load("scan.start.json")
        start = ScanPack.edited(start, path: ["clamped"], to: nineClamped)
        start = ScanPack.edited(start, path: ["lanes", "skipped"], to: nineSkipped)
        let started = try ScanStartResult(json: start)
        #expect(started.clamped.count == 8)
        #expect(started.clamped.last == ScanClamped(field: "f7", requested: 9, applied: 7))
        #expect(started.lanes.skipped.count == 8)

        // Eight clamped and eight skipped lines, two of them already spelled out by the
        // launch: sixteen lines, the launch's first, nothing twice.
        let notices = ScanEndText.notices(decoded, launchNotices: ["Clamped f0 9 → 0", "Skipped ws: r3"])
        #expect(notices.count == 16)
        #expect(notices[0] == "Clamped f0 9 → 0")
        #expect(notices[1] == "Skipped ws: r3")
        #expect(notices[2] == "Clamped f1 9 → 1")
        #expect(notices[9] == "Skipped ws: r0")
        #expect(notices.last == "Skipped ws: r7")
        #expect(Set(notices).count == 16)
    }

    /// Fix 2.12c (PR 2 security minor, round 2): an unknown vocabulary token is cleaned
    /// and cut to `ScanWire.tokenMax` at the one choke point (`vocab`, `optionalVocab`,
    /// `vocabs`) and so are the keys `counts` keeps, so a `ScanLane.other` word or a
    /// `by_lane` key, which the Jobs view draws verbatim, can carry neither a bidi
    /// override nor a newline nor more than 64 scalars. Known tokens are short ASCII,
    /// so the cleaning is identity on them and `.http` still decodes to its case.
    @Test func unknownLaneTokensAreCleanedAtDecode() throws {
        // 300 scalars: a newline, a right-to-left override, then "ab" 149 times.
        let hostileKey = "\n\u{202E}" + String(repeating: "ab", count: 149)
        #expect(hostileKey.unicodeScalars.count == 300)
        var status = try ScanPack.load("scan.status.json")
        status = ScanPack.edited(status, path: ["probes", "by_lane"], to: .object([hostileKey: 3]))
        status = ScanPack.edited(status, path: ["lanes", "run"], to: .array(["http", "x\u{202E}y"]))
        status = ScanPack.edited(status, path: ["lanes", "requested"], to: .array(["a\nb"]))
        status = ScanPack.edited(
            status, path: ["lanes", "skipped"], to: .array([.object(["lane": "l4\u{200B}_stream", "reason": "r"])]))
        let decoded = try ScanJobStatus(json: status)

        let kept = String(repeating: "ab", count: 32)
        #expect(kept.unicodeScalars.count == 64)
        #expect(decoded.probes.byLane == [kept: 3])
        for key in decoded.probes.byLane.keys {
            #expect(!key.contains("\n"))
            #expect(!key.contains("\u{202E}"))
        }
        #expect(decoded.lanes.run == [.http, .other("xy")])
        #expect(decoded.lanes.requested == [.other("ab")])
        #expect(decoded.lanes.skipped == [ScanSkippedLane(lane: .other("l4_stream"), reason: "r")])

        // A single unknown token through `vocab`, and a long one cut to 64.
        var skipped = try ScanPack.load("scan.status.json")
        skipped = ScanPack.edited(
            skipped, path: ["lanes", "skipped"],
            to: .array([.object(["lane": .string(String(repeating: "q", count: 100)), "reason": "r"])]))
        let lane = try ScanJobStatus(json: skipped).lanes.skipped.first?.lane
        #expect(lane == .other(String(repeating: "q", count: 64)))
    }

    /// Fix 3.0a (mac PR 3 security minor, the round-3 `vocabs` follow-up): `lanes.run` and
    /// `lanes.requested` are cut to the engine's cap of 8 at decode like every other list
    /// the wells draw (`ScanWire.listMax`): the Crawl well's Lanes row is `lanes.run`
    /// joined, so without the cap a hostile core could put a hundred words in one row.
    /// Duplicates are dropped first (by raw wire value, first occurrence kept, order
    /// preserved), then the cap applies, so eight copies of one lane do not hide the rest.
    @Test func laneReportRunAndRequestedAreBoundedAtDecode() throws {
        let hundred = JSONValue.array((0..<100).map { .string("lane\($0)") })
        var status = try ScanPack.load("scan.status.json")
        status = ScanPack.edited(status, path: ["lanes", "run"], to: hundred)
        status = ScanPack.edited(status, path: ["lanes", "requested"], to: hundred)
        let decoded = try ScanJobStatus(json: status)
        #expect(ScanWire.listMax == 8)
        #expect(decoded.lanes.run.count == 8)
        #expect(decoded.lanes.run == (0..<8).map { ScanLane.other("lane\($0)") })
        #expect(decoded.lanes.requested.count == 8)
        #expect(decoded.lanes.requested.first == .other("lane0"))
        #expect(decoded.lanes.requested.last == .other("lane7"))

        // Duplicates collapse before the cap: first occurrence kept, wire order preserved.
        let twice = try ScanLaneReport(json: ["requested": ["ws", "http", "ws"], "run": ["http", "http", "ws"], "skipped": []])
        #expect(twice.run == [.http, .ws])
        #expect(twice.requested == [.ws, .http])

        // Eight copies of `http` then nine distinct lanes: the cap counts distinct tokens.
        let padded = JSONValue.array(
            (0..<8).map { _ in JSONValue.string("http") } + (0..<9).map { .string("l\($0)") })
        let report = try ScanLaneReport(json: ["requested": [], "run": padded, "skipped": []])
        #expect(report.run.count == 8)
        #expect(report.run == [.http] + (0..<7).map { ScanLane.other("l\($0)") })
        #expect(report.requested.isEmpty)
    }
}
