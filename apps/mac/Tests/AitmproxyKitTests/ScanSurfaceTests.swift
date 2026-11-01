import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// The Scan surface's state model (scanner v2 T9, plan Task 3): the launch
/// gate (MS-AC2), the `_confirm` handshake (MS-AC3), push-as-trigger (MS-AC4),
/// grouping (MS-AC5), the profile edit round trip (MS-AC6) and every string the
/// views render. The pack files are the parsing contract, never evidence (D14).
@Suite struct ScanSurfaceTests {
    static let startTool = ToolDescriptor(name: "scan.start", description: "", inputSchema: ["type": "object"])
    static var toolsWithStart: [ToolDescriptor] { Fixtures.tools + [startTool] }

    static func load(_ file: String) throws -> JSONValue { try ScanPack.load(file) }

    static func standardProfile() throws -> ScanProfile { try ScanProfile(json: load("scan.profile.get.json")) }

    /// `json` with the value at `path` replaced; a path element that reads as an
    /// integer indexes an array. Builds the edited pack lines the tests need.
    static func set(_ json: JSONValue, path: [String], to value: JSONValue) -> JSONValue {
        guard let head = path.first else { return value }
        let rest = Array(path.dropFirst())
        if let index = Int(head), case .array(var items) = json, items.indices.contains(index) {
            items[index] = set(items[index], path: rest, to: value)
            return .array(items)
        }
        if case .object(var members) = json {
            members[head] = set(members[head] ?? .null, path: rest, to: value)
            return .object(members)
        }
        return json
    }

    // MARK: Mode

    @Test func modeFollowsTheToolList() {
        #expect(ScanSurface.mode(for: Self.toolsWithStart) == .surface)
        #expect(ScanSurface.isOffered(in: Self.toolsWithStart))
        #expect(!ScanSurface.legacyOffered(in: Self.toolsWithStart))
        #expect(ScanSurface.mode(for: Fixtures.tools) == .legacy)
        #expect(ScanSurface.legacyOffered(in: Fixtures.tools))
        #expect(!ScanSurface.isOffered(in: Fixtures.tools))
        #expect(ScanSurface.mode(for: []) == .unavailable)
        #expect(ScanSurface.has("l4.scope.list", in: Fixtures.tools))
        #expect(!ScanSurface.has("l4.scope.list", in: []))
    }

    // MARK: Launch gate (MS-AC2)

    @Test func anInScopeStandardProfileIsNotRefused() throws {
        var profile = try Self.standardProfile()
        profile.target.origins = ["http://api.shop-staging.test"]
        var model = ScanSurfaceModel()
        model.editedProfile = profile
        model.l4InjectScopeKnown = nil

        #expect(model.launchRefusal(scopeHosts: Fixtures.scope, tools: Self.toolsWithStart) == nil)
        let launch = model.launchArguments(map: false)
        #expect(launch.tool == "scan.start")
        #expect(launch.args["profile"]?["target"]?["origins"] == JSONValue.array(["http://api.shop-staging.test"]))
        #expect(launch.args["profile_name"] == nil)

        model.loadedProfile = profile
        #expect(!model.profileIsEdited)
        #expect(model.launchArguments(map: false).args == ["profile_name": "standard"])
        #expect(model.launchArguments(map: true).tool == "scan.map")
        #expect(model.launchArguments(map: true).args == ["profile_name": "standard"])
    }

    @Test func anOutOfScopeOriginIsRefused() throws {
        var profile = try Self.standardProfile()
        profile.target.origins = ["http://telemetry.vendor-analytics.example"]
        var model = ScanSurfaceModel()
        model.editedProfile = profile
        #expect(model.launchRefusal(scopeHosts: Fixtures.scope, tools: Self.toolsWithStart)
                == "Out of scope — add telemetry.vendor-analytics.example to scope to scan it")
    }

    @Test func anL4LaneWithoutAnInjectEntryIsRefusedWithTheHint() throws {
        var profile = try Self.standardProfile()
        profile.lanes = [.l4Stream]
        var model = ScanSurfaceModel()
        model.editedProfile = profile

        model.l4InjectScopeKnown = nil
        #expect(model.launchRefusal(scopeHosts: Fixtures.scope, tools: Self.toolsWithStart) == scanL4Hint)
        model.l4InjectScopeKnown = false
        #expect(model.launchRefusal(scopeHosts: Fixtures.scope, tools: Self.toolsWithStart) == scanL4Hint)

        profile.target.l4 = [["ip": "127.0.0.1", "port": 9000, "proto": "tcp", "grammar": nil]]
        model.editedProfile = profile
        model.l4InjectScopeKnown = true
        #expect(model.launchRefusal(scopeHosts: Fixtures.scope, tools: Self.toolsWithStart) == nil)
    }

    @Test func aBusWithoutScanStartIsRefused() throws {
        var profile = try Self.standardProfile()
        profile.target.origins = ["http://api.shop-staging.test"]
        var model = ScanSurfaceModel()
        model.editedProfile = profile
        #expect(model.launchRefusal(scopeHosts: Fixtures.scope, tools: Fixtures.tools) == "scan.start is not on this bus")
        #expect(model.launchRefusal(scopeHosts: Fixtures.scope, tools: []) == "scan.start is not on this bus")
    }

    @Test func emptyOriginsAreRefused() throws {
        var model = ScanSurfaceModel()
        #expect(model.launchRefusal(scopeHosts: Fixtures.scope, tools: Self.toolsWithStart) == "Choose a profile.")
        model.editedProfile = try Self.standardProfile()
        #expect(model.editedProfile?.target.origins == [])
        #expect(model.launchRefusal(scopeHosts: Fixtures.scope, tools: Self.toolsWithStart)
                == "Choose at least one in-scope origin.")
    }

    // MARK: Confirm handshake (MS-AC3)

    @Test func aNeedsConfirmationBecomesAConfirmWithTheSameArgumentsPlusTheToken() throws {
        let prompt = "This scan sends malformed traffic to 127.0.0.1:9000 and may disrupt the target. Continue?"
        let request = try #require(L4ConfirmRequest(json: [
            "status": "needs_confirmation", "prompt": .string(prompt), "confirm_token": "tok-1",
        ]))
        let args: [String: JSONValue] = ["profile_name": "l4-stream-safe"]
        var model = ScanSurfaceModel()
        model.launchInFlight = true
        model.applyConfirm(tool: "scan.start", args: args, request: request)

        let confirm = try #require(model.confirm)
        #expect(confirm.tool == "scan.start")
        #expect(confirm.request.prompt == prompt)
        #expect(confirm.arguments == args)
        #expect(confirm.confirmedArguments == args.merging(["_confirm": "tok-1"]) { _, last in last })
        #expect(confirm.confirmedArguments.count == args.count + 1)
        #expect(confirm.confirmedArguments["_confirm"] == "tok-1")
        #expect(!model.launchInFlight)
    }

    @Test func aStartResultInsertsTheJobFirstSelectsItAndOpensJobs() throws {
        let result = try ScanStartResult(json: Self.load("scan.start.json"))
        var model = ScanSurfaceModel()
        #expect(model.tab == .profiles)
        model.applyStart(result)

        #expect(model.jobs.count == 1)
        #expect(model.jobs[0].job == "scan-1a2b3c4d")
        #expect(model.jobs[0].state == .queued)
        #expect(model.selectedJob == "scan-1a2b3c4d")
        #expect(model.tab == .jobs)
        #expect(model.statuses["scan-1a2b3c4d"]?.profileName == "standard")
        #expect(model.launchNotices["scan-1a2b3c4d"]
                == ["Clamped budget.probes 50000 → 20000", "Skipped ws: lane not available on this build"])

        model.applyStart(result)
        #expect(model.jobs.count == 1)
    }

    // MARK: Push is a trigger (MS-AC4)

    @Test func aProgressLineIsATriggerNotAValue() throws {
        var model = ScanSurfaceModel()
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        model.applyStatus(try ScanJobStatus(json: Self.load("scan.status.json")))
        let before = model.jobs

        let line = Self.set(try Self.load("job.progress.json"), path: ["status", "probes", "sent"], to: 999)
        #expect(line["status"]?["probes"]?["sent"] == 999)
        let accepted1 = model.noteJobEvent(line)
        #expect(accepted1)

        #expect(model.refreshNeeded == ["scan-1a2b3c4d"])
        #expect(model.statuses["scan-1a2b3c4d"]?.probes.sent == 418)
        #expect(model.jobs == before)
        #expect(model.jobs[0].probes.sent == 418)
        #expect(!model.issuesRefreshNeeded)
        #expect(!model.listRefreshNeeded)

        model.clearRefreshFlags()
        #expect(model.refreshNeeded.isEmpty)
    }

    @Test func staleAndDuplicateSeqAreIgnored() throws {
        let progress = try Self.load("job.progress.json")
        var model = ScanSurfaceModel()
        let accepted2 = model.noteJobEvent(Self.set(progress, path: ["seq"], to: 3))
        #expect(accepted2)
        let accepted3 = model.noteJobEvent(Self.set(progress, path: ["seq"], to: 3))
        #expect(!accepted3)
        let accepted4 = model.noteJobEvent(Self.set(progress, path: ["seq"], to: 2))
        #expect(!accepted4)
        let accepted5 = model.noteJobEvent(Self.set(progress, path: ["seq"], to: 4))
        #expect(accepted5)
        #expect(model.lastSeq["scan-1a2b3c4d"] == 4)
    }

    @Test func issueAndTerminalEventsFlagIssuesAndTheList() throws {
        var model = ScanSurfaceModel()
        let accepted6 = model.noteJobEvent(try Self.load("job.issue.json"))
        #expect(accepted6)
        #expect(model.issuesRefreshNeeded)
        #expect(!model.listRefreshNeeded)
        #expect(model.refreshNeeded == ["scan-1a2b3c4d"])

        let accepted7 = model.noteJobEvent(try Self.load("job.finished.json"))
        #expect(accepted7)
        #expect(model.issuesRefreshNeeded && model.listRefreshNeeded)

        var fresh = ScanSurfaceModel()
        let accepted8 = fresh.noteJobEvent(try Self.load("job.started.json"))
        #expect(accepted8)
        #expect(fresh.listRefreshNeeded)
        #expect(!fresh.issuesRefreshNeeded)

        var other = ScanSurfaceModel()
        let accepted9 = other.noteJobEvent(Self.set(try Self.load("job.progress.json"), path: ["kind"], to: "backup"))
        #expect(!accepted9)
        #expect(other.refreshNeeded.isEmpty)
        #expect(other.lastSeq.isEmpty)
        #expect(!other.listRefreshNeeded && !other.issuesRefreshNeeded)
        let accepted10 = other.noteJobEvent(.string("not a line"))
        #expect(!accepted10)
    }

    // MARK: Grouping (MS-AC5)

    @Test func issuesGroupBySeverityInOrder() throws {
        var model = ScanSurfaceModel()
        model.applyIssues(try ScanIssuesResult(json: Self.load("scan.issues.json")), append: false)

        let sections = model.issuesGroupedBySeverity()
        #expect(sections.map(\.severity) == [.high, .medium])
        #expect(sections.map(\.issues.count) == [1, 1])
        #expect(sections.map(\.title) == ["HIGH 1", "MEDIUM 1"])

        model.filters.status = .falsePositive
        #expect(model.issuesGroupedBySeverity() == [])
        model.filters.status = nil
        model.filters.severityMin = .high
        #expect(model.issuesGroupedBySeverity().map(\.severity) == [.high])
        #expect(model.filters.arguments() == ["severity_min": "high"])
    }

    @Test func sitemapGroupsByOrigin() throws {
        var model = ScanSurfaceModel()
        model.applySitemap(try ScanSitemapResult(json: Self.load("scan.sitemap.json")), append: false)

        let groups = model.sitemapGroupedByOrigin()
        #expect(groups.count == 1)
        #expect(groups[0].origin == "http://127.0.0.1:8080")
        #expect(groups[0].nodes[0].pathTemplate == "/account/{id}")
        #expect(groups[0].nodes[0].points == 2)
        #expect(model.points(for: "node-1").count == 2)
        #expect(model.points(for: "node-2").isEmpty)

        model.sitemapQuery = "orders"
        #expect(model.sitemapGroupedByOrigin() == [])
        model.sitemapQuery = "ACCOUNT"
        #expect(model.sitemapGroupedByOrigin().count == 1)
    }

    @Test func severityBarSegmentsSkipZeros() throws {
        let counts = BySeverity(critical: 0, high: 1, medium: 1, low: 1, info: 0)
        let segments = ScanSurfaceModel.severityBarSegments(counts)
        #expect(segments.count == 3)
        #expect(segments.map(\.severity) == [.high, .medium, .low])
        #expect(segments.map(\.count) == [1, 1, 1])
        for segment in segments {
            #expect(abs(segment.fraction - 1.0 / 3.0) < 1e-9)
        }
        let none = BySeverity(critical: 0, high: 0, medium: 0, low: 0, info: 0)
        #expect(ScanSurfaceModel.severityBarSegments(none).isEmpty)
        #expect(ScanSurfaceModel().issuesBySeverity == none)
    }

    // MARK: Profile edits (MS-AC6)

    @Test func profileEditsSurviveTheRoundTrip() throws {
        let file = try Self.load("scan.profile.get.json")
        var profile = try ScanProfile(json: file)
        profile.checks.include = ["http.sqli-error"]

        let json = profile.json()
        #expect(json["checks"]?["include"] == JSONValue.array(["http.sqli-error"]))
        #expect(json["checks"]?["exclude"] == JSONValue.array([]))
        let keys = try #require(file.objectValue?.keys)
        for key in keys where key != "checks" {
            #expect(json[key] == file[key], "top-level key \(key) changed in the round trip")
        }
        #expect(Set(try #require(json.objectValue).keys) == Set(keys))
        #expect(try ScanProfile(json: json).checks.include == ["http.sqli-error"])
    }

    // MARK: Launch errors

    @Test func launchErrorsParseTheCodeToken() {
        let busy = ScanLaunchError(busMessage: "scan: busy: http://127.0.0.1:8080 already has a running job",
                                   origins: ["http://127.0.0.1:8080"])
        #expect(busy.code == "busy")
        #expect(busy.message == "http://127.0.0.1:8080 already has a running job")
        #expect(busy.display == "A scan on this origin is already running")

        let scope = ScanLaunchError(busMessage: "scan: out_of_scope: origin not in scope", origins: ["http://127.0.0.1:8080"])
        #expect(scope.code == "out_of_scope")
        #expect(scope.display == "Out of scope — add 127.0.0.1:8080 to scope to scan it")

        let offline = ScanLaunchError(busMessage: "bus offline", origins: [])
        #expect(offline.code == nil)
        #expect(offline.message == "bus offline")
        #expect(offline.display == "bus offline")

        let unknown = ScanLaunchError(busMessage: "scan: profile_not_found: no profile named x", origins: [])
        #expect(unknown.code == "profile_not_found")
        #expect(unknown.display == "no profile named x")

        var model = ScanSurfaceModel()
        model.launchInFlight = true
        model.applyLaunchError(busy)
        #expect(model.statusLine == "A scan on this origin is already running")
        #expect(model.confirm == nil)
        #expect(!model.launchInFlight)
    }

    // MARK: Check tree

    @Test func checkTreeGroupsAndKeepsOneSelection() throws {
        let checks = try ScanChecksResult(json: Self.load("scan.checks.json")).checks
        var selection = ScanCheckSelection(include: [], exclude: [])
        let tree = ScanCheckTree(checks: checks, selection: selection, intensity: .light, query: "")

        #expect(tree.groups.map(\.klass) == ["information-disclosure", "reflected-xss", "sqli-error"])
        #expect(tree.groups.allSatisfy { $0.lane == .http })
        #expect(tree.groups.flatMap(\.leaves).count == 3)
        let byID = Dictionary(uniqueKeysWithValues: tree.groups.flatMap(\.leaves).map { ($0.meta.id, $0) })
        #expect(byID["http.reflected-xss"]?.aboveIntensity == true)
        #expect(byID["http.sqli-error"]?.aboveIntensity == true)
        #expect(byID["http.custom-marker"]?.aboveIntensity == false)
        #expect(byID["http.sqli-error"]?.choice == .default)

        ScanCheckTree.set(.include, for: "http.sqli-error", in: &selection)
        #expect(selection.include == ["http.sqli-error"])
        #expect(selection.exclude == [])
        #expect(ScanCheckTree(checks: checks, selection: selection, intensity: .light, query: "")
            .groups.flatMap(\.leaves).first { $0.meta.id == "http.sqli-error" }?.choice == .include)

        ScanCheckTree.set(.exclude, for: "http.sqli-error", in: &selection)
        #expect(selection.include == [])
        #expect(selection.exclude == ["http.sqli-error"])

        ScanCheckTree.set(.default, for: "http.sqli-error", in: &selection)
        #expect(selection.include == [] && selection.exclude == [])

        ScanCheckTree.setAll(.exclude, ids: ["http.reflected-xss", "http.sqli-error"], in: &selection)
        #expect(selection.exclude == ["http.reflected-xss", "http.sqli-error"])
        ScanCheckTree.setAll(.default, ids: ["http.reflected-xss", "http.sqli-error"], in: &selection)
        #expect(selection.exclude == [])

        let filtered = ScanCheckTree(checks: checks, selection: selection, intensity: .light, query: "marker")
        #expect(filtered.groups.flatMap(\.leaves).map(\.meta.id) == ["http.custom-marker"])
        #expect(ScanCheckTree(checks: checks, selection: selection, intensity: .light, query: "SQLI")
            .groups.flatMap(\.leaves).map(\.meta.id) == ["http.sqli-error"])
    }

    // MARK: Counts and titles

    @Test func sidebarCountIsRunningJobsElseOpenIssues() throws {
        var model = ScanSurfaceModel()
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        #expect(model.runningJobs.map(\.job) == ["scan-1a2b3c4d"])
        #expect(model.sidebarCount == 1)

        let finished = Self.set(try Self.load("scan.list.json"), path: ["jobs", "0", "state"], to: "done")
        model.applyList(try ScanListResult(json: finished))
        #expect(model.runningJobs.isEmpty)
        #expect(model.sidebarCount == 0)
        model.applyIssues(try ScanIssuesResult(json: Self.load("scan.issues.json")), append: false)
        #expect(model.openIssueCount == 2)
        #expect(model.sidebarCount == 2)
    }

    @Test func tabTitlesCarryCounts() throws {
        var model = ScanSurfaceModel()
        #expect(model.tabTitle(.jobs) == "Jobs")
        #expect(model.tabTitle(.issues) == "Issues")
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        model.applyIssues(try ScanIssuesResult(json: Self.load("scan.issues.json")), append: false)
        #expect(model.tabTitle(.jobs) == "Jobs 2")
        #expect(model.tabTitle(.issues) == "Issues 2")
        #expect(model.tabTitle(.profiles) == "Profiles")
        #expect(model.tabTitle(.sitemap) == "Site map")
        #expect(ScanTab.allCases.map(\.description) == ["Profiles", "Jobs", "Site map", "Issues"])
    }

    // MARK: Words

    @Test func formatsAreTheSpecsWords() throws {
        let list = try ScanListResult(json: Self.load("scan.list.json"))
        let status = try ScanJobStatus(json: Self.load("scan.status.json"))
        let profileList = try ScanProfileListResult(json: Self.load("scan.profile.list.json"))
        let issues = try ScanIssuesResult(json: Self.load("scan.issues.json"))
        let sitemap = try ScanSitemapResult(json: Self.load("scan.sitemap.json"))
        let preview = try ScanSessionProfile(json: Self.load("scan.session.preview.json"))
        let issue = try ScanIssue(json: Self.load("scan.issue.json"))

        #expect(ScanFormat.elapsed(ms: 42000) == "0:42")
        #expect(ScanFormat.elapsed(ms: 3_723_000) == "1:02:03")
        #expect(ScanFormat.elapsed(ms: 0) == "0:00")
        #expect(ScanFormat.relative(ms: 1_761_900_000_000, now: 1_761_900_042_000) == "42 s ago")
        #expect(ScanFormat.relative(ms: 1_761_900_000_000, now: 1_761_900_000_000 + 125_000) == "2 min ago")
        #expect(ScanFormat.relative(ms: 1_761_900_000_000, now: 1_761_900_000_000 + 3 * 3_600_000 + 1) == "3 h ago")

        #expect(ScanFormat.probesText(status.probes) == "probes 418 / 2000")
        #expect(ScanFormat.pointsText(status.points) == "points 80 / 120 audited")
        #expect(ScanFormat.jobRowLine2(list.jobs[0]) == "probes 418 / 2000 · points 80 / 120 audited · 0:42")
        #expect(ScanFormat.jobRowLine1(list.jobs[0], status: status) == "Auditing · standard · 127.0.0.1:8080")
        #expect(ScanFormat.jobRowLine1(list.jobs[1], status: nil) == "Done · — · —")
        #expect(ScanFormat.jobAccessibilityLabel(list.jobs[0], status: status)
                == "Running, auditing, standard, 127.0.0.1:8080, 418 of 2000 probes, 80 of 120 points audited, "
                + "3 issues: 1 high, 1 medium, 1 low")
        #expect(ScanFormat.severityCountsInWords(list.jobs[0].issues.bySeverity) == "3 issues: 1 high, 1 medium, 1 low")
        #expect(ScanFormat.severityCountsInWords(list.jobs[1].issues.bySeverity) == "no issues")
        #expect(ScanFormat.severityCountsInWords(issues.bySeverity) == "2 issues: 1 high, 1 medium")

        #expect(ScanFormat.profileRowLine2(profileList.profiles[3]) == "http, ws · medium · normal")
        #expect(ScanFormat.profileRowLine2(profileList.profiles[5]) == "l4_stream · medium · normal")

        #expect(ScanFormat.issueRowLine2(issues.issues[0]) == "GET /search · query q · certain")
        #expect(ScanFormat.issueRowLine2(issues.issues[1]) == "GET /go · query next · firm")
        #expect(ScanFormat.issueWhere(issues.issues[0]) == "http://127.0.0.1:8080 · GET /search · query q")
        #expect(ScanFormat.issueMetaLine(issue, now: 1_761_900_000_000 + 125_000)
                == "first seen 2 min ago · last seen 2 min ago · 1 occurrence · http.reflected-xss · scan-1a2b3c4d")

        #expect(ScanFormat.pointAccessibilityLabel(sitemap.points[0])
                == "json_value city, path profile.address.city, traits json, example Lisbon, seen 3 times")
        #expect(ScanFormat.pointAccessibilityLabel(sitemap.points[1])
                == "cookie theme, traits id, example <redacted>, seen 9 times")
        #expect(ScanFormat.nodeAccessibilityLabel(sitemap.nodes[0]) == "GET /account/{id}, 2 points, audited, needs auth")

        #expect(ScanFormat.sessionPreviewText(preview, flowLabel: "GET /login", now: 1_761_900_000_000 + 125_000)
                == "Cookies: sid · Headers: authorization · from flow GET /login · observed 2 min ago")
        #expect(ScanFormat.sessionPreviewText(preview, flowLabel: nil, now: 1_761_900_000_000 + 125_000)
                == "Cookies: sid · Headers: authorization · from flow 550e8400 · observed 2 min ago")
        #expect(ScanFormat.canaryText(.none) == "Auth-lost detection off: no GET/HEAD flow seen")
        #expect(ScanFormat.canaryText(preview.canary) == "Canary: GET /account")
        #expect(ScanFormat.noSessionText == "No session seen yet for this origin.")
        #expect(ScanFormat.hostOf(origin: "http://127.0.0.1:8080") == "127.0.0.1:8080")
        #expect(ScanFormat.hostOf(origin: "https://api.shop-staging.test/") == "api.shop-staging.test")

        #expect(scanL4Hint == "The L4 lanes need an L4 scope entry with interface *, direction outbound, "
                + "the target CIDR and port range and the Inject capability.")
        #expect(scanIdleText == "Opening this page never scans. Start Scan sends probes to the origins above.")
    }

    // MARK: Keyboard selection

    @Test func moveSelectionWalksTheVisibleList() throws {
        var model = ScanSurfaceModel()
        model.applyIssues(try ScanIssuesResult(json: Self.load("scan.issues.json")), append: false)
        #expect(model.selectedIssue == nil)

        model.moveSelection(in: .issues, by: 1)
        #expect(model.selectedIssue == "issue-9f8e7d6c")
        model.moveSelection(in: .issues, by: 1)
        #expect(model.selectedIssue == "issue-4c3b2a19")
        model.moveSelection(in: .issues, by: 1)
        #expect(model.selectedIssue == "issue-4c3b2a19")
        model.moveSelection(in: .issues, by: -1)
        #expect(model.selectedIssue == "issue-9f8e7d6c")
        model.moveSelection(in: .issues, by: -1)
        #expect(model.selectedIssue == "issue-9f8e7d6c")

        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        model.moveSelection(in: .jobs, by: 1)
        #expect(model.selectedJob == "scan-1a2b3c4d")
        model.moveSelection(in: .jobs, by: 1)
        #expect(model.selectedJob == "scan-55667788")

        model.applyProfiles(try ScanProfileListResult(json: Self.load("scan.profile.list.json")))
        model.moveSelection(in: .profiles, by: 1)
        #expect(model.selectedProfile == "passive-only")

        model.applySitemap(try ScanSitemapResult(json: Self.load("scan.sitemap.json")), append: false)
        model.moveSelection(in: .sitemap, by: 1)
        #expect(model.selectedNode == "node-1")
    }
}
