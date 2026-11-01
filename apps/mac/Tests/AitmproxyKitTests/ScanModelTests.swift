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
