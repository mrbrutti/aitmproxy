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
    /// The hosts the removed fixture scope carried; the gate tests still speak of them.
    static let scope = ["api.shop-staging.test", "auth.shop-staging.test", "cdn.shop-staging.test"]
    /// A legacy core's tool list: `scan.discover` without `scan.start`, with the L4 scope verbs.
    static let legacyTools: [ToolDescriptor] = ["flow.list", "flow.get", "scope.add", "scope.list", "scan.discover",
                                                 "l4.scope.add", "l4.scope.list", "poc.build", "poc.run"].map {
        ToolDescriptor(name: $0, description: "", inputSchema: ["type": "object"])
    }
    static var toolsWithStart: [ToolDescriptor] { legacyTools + [startTool] }

    static func load(_ file: String) throws -> JSONValue { try ScanPack.load(file) }

    static func standardProfile() throws -> ScanProfile { try ScanProfile(json: load("scan.profile.get.json")) }

    /// A model that has read `scan.list.json`, so it knows `scan-1a2b3c4d` and `scan-55667788`.
    static func listed() throws -> ScanSurfaceModel {
        var model = ScanSurfaceModel()
        model.applyList(try ScanListResult(json: load("scan.list.json")))
        return model
    }

    // MARK: Mode

    @Test func modeFollowsTheToolList() {
        #expect(ScanSurface.mode(for: Self.toolsWithStart) == .surface)
        #expect(ScanSurface.isOffered(in: Self.toolsWithStart))
        #expect(!ScanSurface.legacyOffered(in: Self.toolsWithStart))
        #expect(ScanSurface.mode(for: Self.legacyTools) == .legacy)
        #expect(ScanSurface.legacyOffered(in: Self.legacyTools))
        #expect(!ScanSurface.isOffered(in: Self.legacyTools))
        #expect(ScanSurface.mode(for: []) == .unavailable)
        #expect(ScanSurface.has("l4.scope.list", in: Self.legacyTools))
        #expect(!ScanSurface.has("l4.scope.list", in: []))
    }

    // MARK: Launch gate (MS-AC2)

    @Test func anInScopeStandardProfileIsNotRefused() throws {
        var profile = try Self.standardProfile()
        profile.target.origins = ["http://api.shop-staging.test"]
        var model = ScanSurfaceModel()
        model.editedProfile = profile
        model.l4InjectScopeKnown = nil

        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == nil)
        let launch = model.launchArguments(map: false)
        #expect(launch.tool == "scan.start")
        #expect(launch.args["profile"]?["target"]?["origins"] == JSONValue.array(["http://api.shop-staging.test"]))
        #expect(launch.args["profile_name"] == nil)

        // An unedited profile goes whole too: the core runs the object the gate checked, never a name it resolves.
        model.loadedProfile = profile
        #expect(!model.profileIsEdited)
        let unedited = model.launchArguments(map: false)
        #expect(unedited.args["profile_name"] == nil)
        #expect(unedited.args["profile"]?["name"] == "standard")
        #expect(unedited.args["profile"] == profile.json())
        #expect(model.launchArguments(map: true).tool == "scan.map")
        #expect(model.launchArguments(map: true).args == ["profile": profile.json()])
    }

    @Test func anOutOfScopeOriginIsRefused() throws {
        var profile = try Self.standardProfile()
        profile.target.origins = ["http://telemetry.vendor-analytics.example"]
        var model = ScanSurfaceModel()
        model.editedProfile = profile
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart)
                == "Out of scope — add telemetry.vendor-analytics.example to scope to scan it")
    }

    @Test func anL4LaneWithoutAnInjectEntryIsRefusedWithTheHint() throws {
        var profile = try Self.standardProfile()
        profile.lanes = [.l4Stream]
        var model = ScanSurfaceModel()
        model.editedProfile = profile

        model.l4InjectScopeKnown = nil
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == scanL4Hint)
        model.l4InjectScopeKnown = false
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == scanL4Hint)

        profile.target.l4 = [["ip": "127.0.0.1", "port": 9000, "proto": "tcp", "grammar": nil]]
        model.editedProfile = profile
        model.l4InjectScopeKnown = true
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == nil)
    }

    @Test func aBusWithoutScanStartIsRefused() throws {
        var profile = try Self.standardProfile()
        profile.target.origins = ["http://api.shop-staging.test"]
        var model = ScanSurfaceModel()
        model.editedProfile = profile
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.legacyTools) == "scan.start is not on this bus")
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: []) == "scan.start is not on this bus")
    }

    @Test func emptyOriginsAreRefused() throws {
        var model = ScanSurfaceModel()
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == "Choose a profile.")
        model.editedProfile = try Self.standardProfile()
        #expect(model.editedProfile?.target.origins == [])
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart)
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

        let line = ScanPack.edited(try Self.load("job.progress.json"), path: ["status", "probes", "sent"], to: 999)
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
        var model = try Self.listed()
        let accepted2 = model.noteJobEvent(ScanPack.edited(progress, path: ["seq"], to: 3))
        #expect(accepted2)
        let accepted3 = model.noteJobEvent(ScanPack.edited(progress, path: ["seq"], to: 3))
        #expect(!accepted3)
        let accepted4 = model.noteJobEvent(ScanPack.edited(progress, path: ["seq"], to: 2))
        #expect(!accepted4)
        let accepted5 = model.noteJobEvent(ScanPack.edited(progress, path: ["seq"], to: 4))
        #expect(accepted5)
        #expect(model.lastSeq["scan-1a2b3c4d"] == 4)
    }

    @Test func issueAndTerminalEventsFlagIssuesAndTheList() throws {
        var model = try Self.listed()
        let accepted6 = model.noteJobEvent(try Self.load("job.issue.json"))
        #expect(accepted6)
        #expect(model.issuesRefreshNeeded)
        #expect(!model.listRefreshNeeded)
        #expect(model.refreshNeeded == ["scan-1a2b3c4d"])

        let accepted7 = model.noteJobEvent(try Self.load("job.finished.json"))
        #expect(accepted7)
        #expect(model.issuesRefreshNeeded && model.listRefreshNeeded)

        var fresh = try Self.listed()
        let accepted8 = fresh.noteJobEvent(try Self.load("job.started.json"))
        #expect(accepted8)
        #expect(fresh.listRefreshNeeded)
        #expect(!fresh.issuesRefreshNeeded)

        var other = try Self.listed()
        let accepted9 = other.noteJobEvent(ScanPack.edited(try Self.load("job.progress.json"), path: ["kind"], to: "backup"))
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
        #expect(ScanSurfaceModel.severityBarSegments(.zero).isEmpty)
        #expect(ScanSurfaceModel().issuesBySeverity == .zero)
        #expect(BySeverity.zero == BySeverity(critical: 0, high: 0, medium: 0, low: 0, info: 0))
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

        let finished = ScanPack.edited(try Self.load("scan.list.json"), path: ["jobs", "0", "state"], to: "done")
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
        #expect(ScanFormat.profileAccessibilityLabel(profileList.profiles[3]) == "standard, builtin, http, ws · medium · normal")
        #expect(ScanFormat.issueAccessibilityLabel(issues.issues[0])
                == "High, Reflected cross-site scripting, GET /search · query q · certain, Open")
        #expect(ScanFormat.originAccessibilityLabel(origin: "http://127.0.0.1:8080", count: 3, collapsed: true)
                == "http://127.0.0.1:8080, 3 endpoints, collapsed")

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

// MARK: - Tester additions (stage 5)

/// Tester — the gate's remaining branches, the confirm handshake with a whole
/// profile, push lines for jobs never seen and `issue` lines without an issue,
/// every filter axis, a multi-lane check in the tree, profile edits beyond
/// `checks`, the `elapsed` / `relative` boundaries, and the mutations the
/// Coder's tests never exercised (`applyProfiles`, `applyList` with a pending
/// job, `applyIssues(append:)`, `applyIssue`, `applySitemap(append:)`).
extension ScanSurfaceTests {
    static let noL4Targets = "This profile has no L4 targets; add one to its target.l4 list."

    // MARK: Launch gate (MS-AC2)

    @Test func aPureL4ProfileWithNoL4TargetsIsRefused() throws {
        var profile = try Self.standardProfile()
        profile.lanes = [.l4Stream]
        var model = ScanSurfaceModel()
        model.editedProfile = profile
        model.l4InjectScopeKnown = true
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == Self.noL4Targets)

        // An L4 entry missing one of ip / port / proto is not a target.
        profile.target.l4 = [["ip": "127.0.0.1", "proto": "tcp"]]
        model.editedProfile = profile
        #expect(profile.target.l4Rows == [])
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == Self.noL4Targets)
        profile.target.l4 = [["ip": "127.0.0.1", "port": "9000", "proto": "tcp"]]
        model.editedProfile = profile
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == Self.noL4Targets)

        // A complete entry is; a malformed sibling is left out of the rows.
        profile.target.l4 = [["ip": "127.0.0.1", "port": 9000, "proto": "tcp", "grammar": .null], ["ip": "10.0.0.1"]]
        model.editedProfile = profile
        #expect(profile.target.l4Rows == ["127.0.0.1:9000/tcp"])
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == nil)
        #expect(model.launchRefusal(scopeHosts: [], tools: Self.toolsWithStart) == nil)

        // The hint wins over the missing-target message while no Inject entry is known.
        profile.target.l4 = []
        model.editedProfile = profile
        model.l4InjectScopeKnown = false
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == scanL4Hint)
        model.l4InjectScopeKnown = nil
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == scanL4Hint)

        // A mixed HTTP + L4 profile with nothing to aim at asks for an origin.
        profile.lanes = [.http, .l4Stream]
        model.editedProfile = profile
        model.l4InjectScopeKnown = true
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == "Choose at least one in-scope origin.")

        // An L4 target plus an out-of-scope origin is still refused on the origin.
        profile.target.l4 = [["ip": "127.0.0.1", "port": 9000, "proto": "tcp"]]
        profile.target.origins = ["http://telemetry.vendor-analytics.example"]
        model.editedProfile = profile
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart)
                == "Out of scope — add telemetry.vendor-analytics.example to scope to scan it")

        // The bus check comes before everything else, even with no profile.
        let bare = ScanSurfaceModel()
        #expect(bare.launchRefusal(scopeHosts: Self.scope, tools: []) == "scan.start is not on this bus")
        #expect(bare.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == "Choose a profile.")
    }

    @Test func theGateChecksEveryOriginAgainstScope() throws {
        var profile = try Self.standardProfile()
        var model = ScanSurfaceModel()

        // Mixed case, a port and a trailing slash still match the scope host.
        profile.target.origins = ["HTTP://API.shop-staging.test:8443/"]
        model.editedProfile = profile
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == nil)
        #expect(model.launchRefusal(scopeHosts: ["*.shop-staging.test"], tools: Self.toolsWithStart) == nil)
        #expect(model.launchRefusal(scopeHosts: ["api.shop-staging.test:8443"], tools: Self.toolsWithStart) == nil)
        // An empty scope covers nothing (deny by default); the refusal names the authority with its port.
        #expect(model.launchRefusal(scopeHosts: [], tools: Self.toolsWithStart)
                == "Out of scope — add api.shop-staging.test:8443 to scope to scan it")
        // A different port entry does not cover it.
        #expect(model.launchRefusal(scopeHosts: ["api.shop-staging.test:443"], tools: Self.toolsWithStart)
                == "Out of scope — add api.shop-staging.test:8443 to scope to scan it")

        // One bad origin among good ones names the bad one; nothing is sent for the good ones.
        profile.target.origins = ["http://api.shop-staging.test", "http://auth.shop-staging.test", "http://evil.example"]
        model.editedProfile = profile
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart)
                == "Out of scope — add evil.example to scope to scan it")

        // A subdomain is not covered by a plain host entry.
        profile.target.origins = ["http://dev.api.shop-staging.test"]
        model.editedProfile = profile
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart)
                == "Out of scope — add dev.api.shop-staging.test to scope to scan it")

        // Not an http(s) URL: never sent, the text shows the origin as typed.
        profile.target.origins = ["ftp://api.shop-staging.test"]
        model.editedProfile = profile
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart)
                == "Out of scope — add ftp://api.shop-staging.test to scope to scan it")
        profile.target.origins = ["api.shop-staging.test"]
        model.editedProfile = profile
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart)
                == "Out of scope — add api.shop-staging.test to scope to scan it")
    }

    @Test func launchArgumentsFollowTheEditState() throws {
        var model = ScanSurfaceModel()
        #expect(model.launchArguments(map: false).tool == "scan.start")
        #expect(model.launchArguments(map: false).args == [:])
        #expect(model.launchArguments(map: true).tool == "scan.map")

        var profile = try Self.standardProfile()
        profile.target.origins = ["http://api.shop-staging.test"]
        model.applyProfile(profile)
        #expect(!model.profileIsEdited)
        let unedited = model.launchArguments(map: false)
        #expect(unedited.args["profile_name"] == nil)
        #expect(unedited.args["profile"]?["name"] == "standard")
        #expect(unedited.args["profile"]?["budget"]?["probes"] == 2000)

        model.editedProfile?.budget.probes = 10
        #expect(model.profileIsEdited)
        let edited = model.launchArguments(map: true)
        #expect(edited.tool == "scan.map")
        #expect(edited.args["profile_name"] == nil)
        #expect(edited.args["profile"] == model.editedProfile?.json())
        #expect(edited.args["profile"]?["budget"]?["probes"] == 10)
        #expect(edited.args["profile"]?["name"] == "standard")

        // Renaming counts as an edit: the whole profile goes, under the new name.
        model.editedProfile = profile
        model.editedProfile?.name = "my-api"
        #expect(model.launchArguments(map: false).args["profile"]?["name"] == "my-api")

        // Reverting the edit sends the loaded profile whole, under its name; never `profile_name`.
        model.editedProfile = profile
        let reverted = model.launchArguments(map: false)
        #expect(reverted.args == ["profile": profile.json()])
        #expect(reverted.args["profile"]?["name"] == "standard")
        #expect(reverted.args["profile_name"] == nil)
    }

    // MARK: Confirm handshake (MS-AC3)

    @Test func aConfirmCarriesTheEditedProfileWholeAndAStartResultIsNeverAConfirm() throws {
        var profile = try Self.standardProfile()
        profile.lanes = [.l4Stream]
        profile.target.l4 = [["ip": "127.0.0.1", "port": 9000, "proto": "tcp"]]
        var model = ScanSurfaceModel()
        model.loadedProfile = try Self.standardProfile()
        model.editedProfile = profile
        model.l4InjectScopeKnown = true
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == nil)
        let launch = model.launchArguments(map: true)
        #expect(launch.tool == "scan.map")
        #expect(launch.args == ["profile": profile.json()])

        let token = "tok/with+chars=="
        let request = try #require(L4ConfirmRequest(json: [
            "structuredContent": ["status": "needs_confirmation", "prompt": "Really?", "confirm_token": .string(token)],
        ]))
        model.launchInFlight = true
        model.applyConfirm(tool: launch.tool, args: launch.args, request: request)
        let confirm = try #require(model.confirm)
        #expect(confirm.tool == "scan.map")
        #expect(confirm.request.prompt == "Really?")
        #expect(confirm.confirmedArguments == ["profile": profile.json(), "_confirm": .string(token)])
        #expect(confirm.arguments["_confirm"] == nil)
        #expect(!model.launchInFlight)
        #expect(model.jobs.isEmpty)
        #expect(model.tab == .profiles)

        // Cancel on the sheet: the app clears `confirm`; nothing else changed.
        model.confirm = nil
        var expected = ScanSurfaceModel()
        expected.loadedProfile = model.loadedProfile
        expected.editedProfile = profile
        expected.l4InjectScopeKnown = true
        #expect(model == expected)

        // A plain start result is never mistaken for a confirm request.
        let startResult = try Self.load("scan.start.json")
        #expect(L4ConfirmRequest(json: startResult) == nil)
        #expect(L4ConfirmRequest(json: ["status": "needs_confirmation", "prompt": "p"]) == nil)
        #expect(L4ConfirmRequest(json: ["status": "ok", "prompt": "p", "confirm_token": "t"]) == nil)

        // An error after the sheet clears it and lands in the status line.
        model.applyConfirm(tool: launch.tool, args: launch.args, request: request)
        model.applyLaunchError(ScanLaunchError(busMessage: "scan: guard_refused: refused by the L4 guard", origins: []))
        #expect(model.confirm == nil)
        #expect(model.statusLine == "refused by the L4 guard")

        // A start result after the sheet clears it and the status line.
        model.applyConfirm(tool: launch.tool, args: launch.args, request: request)
        model.applyStart(try ScanStartResult(json: Self.load("scan.start.json")))
        #expect(model.confirm == nil)
        #expect(model.statusLine == nil)
        #expect(model.tab == .jobs)
    }

    @Test func aSecondStartGoesInFrontAndAnUnclampedStartHasNoNotices() throws {
        var model = ScanSurfaceModel()
        model.applyStart(try ScanStartResult(json: Self.load("scan.start.json")))
        var second = try Self.load("scan.start.json")
        second = ScanPack.edited(second, path: ["job"], to: "scan-second")
        second = ScanPack.edited(second, path: ["status", "job"], to: "scan-second")
        second = ScanPack.edited(second, path: ["clamped"], to: [])
        second = ScanPack.edited(second, path: ["lanes", "skipped"], to: [])
        model.launchInFlight = true
        model.applyStart(try ScanStartResult(json: second))
        #expect(model.jobs.map(\.job) == ["scan-second", "scan-1a2b3c4d"])
        #expect(model.selectedJob == "scan-second")
        #expect(model.launchNotices["scan-second"] == [])
        #expect(model.launchNotices["scan-1a2b3c4d"]?.count == 2)
        #expect(!model.launchInFlight)
        #expect(model.runningJobs.count == 2)
        #expect(model.sidebarCount == 2)
        #expect(model.tabTitle(.jobs) == "Jobs 2")
    }

    // MARK: Push is a trigger (MS-AC4)

    @Test func pushLinesForUnknownJobsAndIssueLinesWithoutAnIssueStillTrigger() throws {
        var model = ScanSurfaceModel()
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        model.applyIssues(try ScanIssuesResult(json: Self.load("scan.issues.json")), append: false)
        let before = model

        // A job this model never saw (not listed, not started here, no status) only asks
        // for the list: no row, status, seq or per-job flag is kept for a stranger.
        let unknown = ScanPack.edited(try Self.load("job.progress.json"), path: ["job"], to: "scan-never-seen")
        let acceptedUnknown = model.noteJobEvent(unknown)
        #expect(acceptedUnknown)
        #expect(model.listRefreshNeeded)
        #expect(model.refreshNeeded.isEmpty)
        #expect(model.lastSeq["scan-never-seen"] == nil)
        #expect(model.lastSeq.isEmpty)
        #expect(model.jobs == before.jobs)
        #expect(model.statuses.isEmpty)
        #expect(!model.issuesRefreshNeeded)
        // Its lines never dedupe either: every one is the same request for the list.
        let acceptedUnknownAgain = model.noteJobEvent(unknown)
        #expect(acceptedUnknownAgain)
        #expect(model.lastSeq.isEmpty)
        model.clearRefreshFlags()

        // A known job's `seq` is tracked on its own.
        let acceptedKnown = model.noteJobEvent(try Self.load("job.progress.json"))
        #expect(acceptedKnown)
        #expect(model.refreshNeeded == ["scan-1a2b3c4d"])
        #expect(model.lastSeq == ["scan-1a2b3c4d": 3])
        #expect(!model.listRefreshNeeded)

        // An `issue` line without its `issue` object is still an issue trigger.
        let bare = ScanPack.removing(try Self.load("job.issue.json"), path: ["issue"])
        #expect(try ScanJobNotification(json: bare).issue == nil)
        let acceptedBare = model.noteJobEvent(bare)
        #expect(acceptedBare)
        #expect(model.issuesRefreshNeeded)
        #expect(!model.listRefreshNeeded)
        #expect(model.issues == before.issues)

        // A carried issue is never inserted into the list either: the next `scan.issues` is the truth.
        var carried = try Self.listed()
        let acceptedCarried = carried.noteJobEvent(try Self.load("job.issue.json"))
        #expect(acceptedCarried)
        #expect(carried.issues.isEmpty)
        #expect(carried.issueDetail == nil)
        #expect(carried.issuesBySeverity == .zero)

        // `cancelled` and `failed` are terminal: both flags.
        var cancelled = try Self.listed()
        let acceptedCancelled = cancelled.noteJobEvent(try Self.load("job.cancelled.json"))
        #expect(acceptedCancelled)
        #expect(cancelled.listRefreshNeeded && cancelled.issuesRefreshNeeded)
        var failed = try Self.listed()
        let acceptedFailed = failed.noteJobEvent(try Self.load("job.failed.json"))
        #expect(acceptedFailed)
        #expect(failed.listRefreshNeeded && failed.issuesRefreshNeeded)

        // `phase` and an unknown event flag the job alone.
        var phase = try Self.listed()
        let acceptedPhase = phase.noteJobEvent(try Self.load("job.phase.json"))
        #expect(acceptedPhase)
        #expect(phase.refreshNeeded == ["scan-1a2b3c4d"])
        #expect(!phase.listRefreshNeeded && !phase.issuesRefreshNeeded)
        let acceptedOther = phase.noteJobEvent(ScanPack.edited(try Self.load("job.phase.json"), path: ["event"], to: "paused"))
        #expect(!acceptedOther, "same seq as the phase line: ignored")
        let acceptedOtherNext = phase.noteJobEvent(
            ScanPack.edited(ScanPack.edited(try Self.load("job.phase.json"), path: ["event"], to: "paused"), path: ["seq"], to: 3))
        #expect(acceptedOtherNext)
        #expect(!phase.listRefreshNeeded && !phase.issuesRefreshNeeded)
        #expect(phase.lastSeq["scan-1a2b3c4d"] == 3)

        // A malformed line changes nothing at all.
        var untouched = try Self.listed()
        let snapshot = untouched
        let progress = try Self.load("job.progress.json")
        let brokenLines: [JSONValue] = [
            ScanPack.edited(progress, path: ["seq"], to: "3"),
            ScanPack.edited(progress, path: ["seq"], to: -1),
            ScanPack.removing(progress, path: ["status"]),
            ScanPack.removing(progress, path: ["job"]),
            ScanPack.edited(progress, path: ["kind"], to: "Scan"),
            .object([:]), .array([]), .null, .number(1),
        ]
        for broken in brokenLines {
            let accepted = untouched.noteJobEvent(broken)
            #expect(!accepted)
        }
        #expect(untouched == snapshot)

        // A terminal line after a stale one: the stale one is dropped, the terminal one lands.
        var ordered = try Self.listed()
        let acceptedFinished = ordered.noteJobEvent(try Self.load("job.finished.json"))
        #expect(acceptedFinished)
        ordered.clearRefreshFlags()
        let acceptedLate = ordered.noteJobEvent(try Self.load("job.progress.json"))
        #expect(!acceptedLate)
        #expect(ordered.refreshNeeded.isEmpty)
        #expect(!ordered.listRefreshNeeded && !ordered.issuesRefreshNeeded)
        #expect(ordered.lastSeq["scan-1a2b3c4d"] == 5)

        // A job this app started, or one with a status read, is known before the list carries it.
        var local = ScanSurfaceModel()
        local.applyStart(try ScanStartResult(json: Self.load("scan.start.json")))
        let acceptedLocal = local.noteJobEvent(try Self.load("job.progress.json"))
        #expect(acceptedLocal)
        #expect(local.lastSeq["scan-1a2b3c4d"] == 3)
        #expect(local.refreshNeeded == ["scan-1a2b3c4d"])
        var withStatus = ScanSurfaceModel()
        withStatus.applyStatus(try ScanJobStatus(json: Self.load("scan.status.json")))
        let acceptedStatus = withStatus.noteJobEvent(try Self.load("job.progress.json"))
        #expect(acceptedStatus)
        #expect(withStatus.lastSeq["scan-1a2b3c4d"] == 3)
        #expect(!withStatus.listRefreshNeeded)
    }

    /// S6: `scan.list` prunes every per-job side table to the jobs it lists plus
    /// the ones this app started and is still waiting on.
    @Test func applyListPrunesThePerJobTablesToListedAndLocallyStarted() throws {
        var model = try Self.listed()
        model.applyStatus(try ScanJobStatus(json: Self.load("scan.status.json")))
        let elsewhere = ScanPack.edited(try Self.load("scan.status.json"), path: ["job"], to: "scan-elsewhere")
        model.applyStatus(try ScanJobStatus(json: elsewhere))
        let acceptedKnown = model.noteJobEvent(try Self.load("job.progress.json"))
        #expect(acceptedKnown)
        let acceptedElsewhere = model.noteJobEvent(
            ScanPack.edited(try Self.load("job.progress.json"), path: ["job"], to: "scan-elsewhere"))
        #expect(acceptedElsewhere, "a job with a status read is known")
        var start = try Self.load("scan.start.json")
        start = ScanPack.edited(start, path: ["job"], to: "scan-local")
        start = ScanPack.edited(start, path: ["status", "job"], to: "scan-local")
        model.applyStart(try ScanStartResult(json: start))
        #expect(Set(model.statuses.keys) == ["scan-1a2b3c4d", "scan-elsewhere", "scan-local"])
        #expect(Set(model.lastSeq.keys) == ["scan-1a2b3c4d", "scan-elsewhere"])
        #expect(model.refreshNeeded == ["scan-1a2b3c4d", "scan-elsewhere"])
        #expect(Set(model.launchNotices.keys) == ["scan-local"])

        // The list carries scan-1a2b3c4d and scan-55667788 but not scan-elsewhere; scan-local waits.
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        #expect(model.jobs.map(\.job) == ["scan-local", "scan-1a2b3c4d", "scan-55667788"])
        #expect(Set(model.statuses.keys) == ["scan-1a2b3c4d", "scan-local"])
        #expect(Set(model.lastSeq.keys) == ["scan-1a2b3c4d"])
        #expect(model.refreshNeeded == ["scan-1a2b3c4d"])
        #expect(Set(model.launchNotices.keys) == ["scan-local"])
        #expect(model.locallyStarted == ["scan-local"])

        // An empty list keeps only what this app started.
        model.applyList(try ScanListResult(json: ["jobs": []]))
        #expect(model.jobs.map(\.job) == ["scan-local"])
        #expect(Set(model.statuses.keys) == ["scan-local"])
        #expect(model.lastSeq.isEmpty)
        #expect(model.refreshNeeded.isEmpty)
        #expect(Set(model.launchNotices.keys) == ["scan-local"])

        // Once the list carries scan-local too, and then drops it, nothing is left behind.
        var listed = try Self.load("scan.list.json")
        var jobs = try #require(listed["jobs"]?.arrayValue)
        jobs.append(ScanPack.edited(jobs[1], path: ["job"], to: "scan-local"))
        listed = ScanPack.edited(listed, path: ["jobs"], to: .array(jobs))
        model.applyList(try ScanListResult(json: listed))
        #expect(model.locallyStarted.isEmpty)
        #expect(Set(model.statuses.keys) == ["scan-local"])
        model.applyList(try ScanListResult(json: ["jobs": []]))
        #expect(model.jobs.isEmpty)
        #expect(model.statuses.isEmpty)
        #expect(model.launchNotices.isEmpty)
    }

    // MARK: Grouping (MS-AC5)

    @Test func issueFiltersMatchOnEveryAxis() throws {
        let issues = try ScanIssuesResult(json: Self.load("scan.issues.json")).issues
        let xss = issues[0].id
        let redirect = issues[1].id
        func visible(_ filters: ScanIssueFilters) -> [String] { issues.filter(filters.matches).map(\.id) }

        #expect(visible(ScanIssueFilters()) == [xss, redirect])
        #expect(visible(ScanIssueFilters(job: "scan-1a2b3c4d")) == [xss, redirect])
        #expect(visible(ScanIssueFilters(job: "scan-other")) == [])
        #expect(visible(ScanIssueFilters(severityMin: .info)) == [xss, redirect])
        #expect(visible(ScanIssueFilters(severityMin: .medium)) == [xss, redirect])
        #expect(visible(ScanIssueFilters(severityMin: .high)) == [xss])
        #expect(visible(ScanIssueFilters(severityMin: .critical)) == [])
        #expect(visible(ScanIssueFilters(confidenceMin: .tentative)) == [xss, redirect])
        #expect(visible(ScanIssueFilters(confidenceMin: .firm)) == [xss, redirect])
        #expect(visible(ScanIssueFilters(confidenceMin: .certain)) == [xss])
        #expect(visible(ScanIssueFilters(lane: .http)) == [xss, redirect])
        #expect(visible(ScanIssueFilters(lane: .ws)) == [])
        #expect(visible(ScanIssueFilters(klass: "open-redirect")) == [redirect])
        #expect(visible(ScanIssueFilters(klass: "reflected-xss")) == [xss])
        #expect(visible(ScanIssueFilters(klass: "sqli-error")) == [])
        #expect(visible(ScanIssueFilters(status: .open)) == [xss, redirect])
        #expect(visible(ScanIssueFilters(status: .confirmed)) == [])
        #expect(visible(ScanIssueFilters(status: .falsePositive)) == [])

        // Axes AND together.
        #expect(visible(ScanIssueFilters(severityMin: .medium, confidenceMin: .certain)) == [xss])
        #expect(visible(ScanIssueFilters(severityMin: .high, klass: "open-redirect")) == [])
        #expect(visible(ScanIssueFilters(job: "scan-1a2b3c4d", lane: .http, status: .open)) == [xss, redirect])

        // `arguments()` carries exactly the set axes under the verb's parameter names.
        let all = ScanIssueFilters(job: "scan-1a2b3c4d", severityMin: .high, confidenceMin: .firm, lane: .ws,
                                   klass: "sqli-error", status: .falsePositive)
        #expect(all.arguments() == [
            "job": "scan-1a2b3c4d", "severity_min": "high", "confidence_min": "firm", "lane": "ws",
            "class": "sqli-error", "status": "false_positive",
        ])
        #expect(ScanIssueFilters().arguments() == [:])
        #expect(ScanIssueFilters(lane: .l4Stream).arguments() == ["lane": "l4_stream"])

        // The model applies the same predicate to what it shows and what it counts.
        var model = ScanSurfaceModel()
        model.applyIssues(try ScanIssuesResult(json: Self.load("scan.issues.json")), append: false)
        model.filters = ScanIssueFilters(confidenceMin: .certain)
        #expect(model.issuesGroupedBySeverity().flatMap(\.issues).map(\.id) == [xss])
        #expect(model.tabTitle(.issues) == "Issues 2", "the tab counts the loaded page, not the filtered view")
        model.moveSelection(in: .issues, by: 1)
        #expect(model.selectedIssue == xss)
        model.moveSelection(in: .issues, by: 1)
        #expect(model.selectedIssue == xss, "the hidden row is not reachable from the keyboard")
    }

    @Test func issuesGroupInSeverityOrderWithUnknownsLast() throws {
        var file = try Self.load("scan.issues.json")
        var items = try #require(file["issues"]?.arrayValue)
        items.append(ScanPack.edited(ScanPack.edited(items[0], path: ["id"], to: "issue-info"), path: ["severity"], to: "info"))
        items.append(ScanPack.edited(ScanPack.edited(items[0], path: ["id"], to: "issue-blocker"), path: ["severity"], to: "blocker"))
        items.append(ScanPack.edited(ScanPack.edited(items[1], path: ["id"], to: "issue-critical"), path: ["severity"], to: "critical"))
        items.append(ScanPack.edited(ScanPack.edited(items[1], path: ["id"], to: "issue-high-2"), path: ["severity"], to: "high"))
        file = ScanPack.edited(file, path: ["issues"], to: .array(items))
        var model = ScanSurfaceModel()
        model.applyIssues(try ScanIssuesResult(json: file), append: false)

        let sections = model.issuesGroupedBySeverity()
        #expect(sections.map(\.severity) == [.critical, .high, .medium, .info, .other("blocker")])
        #expect(sections.map(\.title) == ["CRITICAL 1", "HIGH 2", "MEDIUM 1", "INFO 1", "BLOCKER 1"])
        #expect(sections[1].issues.map(\.id) == ["issue-9f8e7d6c", "issue-high-2"])

        // Keyboard selection walks the sections in that order; from nil, up lands on the last row.
        model.moveSelection(in: .issues, by: -1)
        #expect(model.selectedIssue == "issue-blocker")
        model.moveSelection(in: .issues, by: -1)
        #expect(model.selectedIssue == "issue-info")
        model.moveSelection(in: .issues, by: -10)
        #expect(model.selectedIssue == "issue-critical")

        // An empty tab never moves a selection.
        var empty = ScanSurfaceModel()
        empty.moveSelection(in: .jobs, by: 1)
        empty.moveSelection(in: .profiles, by: -1)
        empty.moveSelection(in: .sitemap, by: 1)
        empty.moveSelection(in: .issues, by: 1)
        #expect(empty == ScanSurfaceModel())
    }

    @Test func severityBarSegmentsShareTheTotal() {
        let counts = BySeverity(critical: 1, high: 0, medium: 0, low: 0, info: 3)
        let segments = ScanSurfaceModel.severityBarSegments(counts)
        #expect(segments.map(\.severity) == [.critical, .info])
        #expect(segments.map(\.count) == [1, 3])
        #expect(abs(segments[0].fraction - 0.25) < 1e-9)
        #expect(abs(segments[1].fraction - 0.75) < 1e-9)
        #expect(abs(segments.map(\.fraction).reduce(0, +) - 1) < 1e-9)
        #expect(counts.total == 4)
        #expect(counts.count(.other("blocker")) == 0)
    }

    @Test func checkTreeListsAMultiLaneCheckUnderEachLane() throws {
        let file = ScanPack.edited(try Self.load("scan.checks.json"), path: ["checks", "0", "lanes"], to: ["ws", "http"])
        let checks = try ScanChecksResult(json: file).checks
        #expect(checks[0].lanes == [.ws, .http])
        var selection = ScanCheckSelection(include: [], exclude: [])
        let tree = ScanCheckTree(checks: checks, selection: selection, intensity: .medium, query: "")
        #expect(tree.groups.map { "\($0.lane.rawValue)/\($0.klass)" }
                == ["http/information-disclosure", "http/reflected-xss", "http/sqli-error", "ws/reflected-xss"])
        #expect(tree.groups.flatMap(\.leaves).count == 4)
        #expect(tree.groups.flatMap(\.leaves).allSatisfy { !$0.aboveIntensity }, "a medium profile runs medium checks")

        // One selection covers every lane's copy of the check, and never duplicates the id.
        ScanCheckTree.set(.exclude, for: "http.reflected-xss", in: &selection)
        ScanCheckTree.set(.exclude, for: "http.reflected-xss", in: &selection)
        #expect(selection.exclude == ["http.reflected-xss"])
        let copies = ScanCheckTree(checks: checks, selection: selection, intensity: .medium, query: "")
            .groups.flatMap(\.leaves).filter { $0.meta.id == "http.reflected-xss" }
        #expect(copies.count == 2)
        #expect(copies.allSatisfy { $0.choice == .exclude })
        ScanCheckTree.set(.include, for: "http.reflected-xss", in: &selection)
        #expect(selection.include == ["http.reflected-xss"])
        #expect(selection.exclude == [])

        // An unknown lane sorts after the known four; a check with no lane is in no group.
        var exotic = ScanPack.edited(file, path: ["checks", "1", "lanes"], to: ["quic"])
        exotic = ScanPack.edited(exotic, path: ["checks", "2", "lanes"], to: [])
        let exoticChecks = try ScanChecksResult(json: exotic).checks
        let exoticTree = ScanCheckTree(checks: exoticChecks, selection: ScanCheckSelection(include: [], exclude: []),
                                       intensity: .intrusive, query: "")
        #expect(exoticTree.groups.map(\.lane) == [.http, .ws, .other("quic")])
        #expect(exoticTree.groups.flatMap(\.leaves).map(\.meta.id) == ["http.reflected-xss", "http.reflected-xss", "http.sqli-error"])

        // The four known lanes order HTTP, WebSocket, L4 packet, L4 stream regardless of arrival.
        var lanes = ScanPack.edited(file, path: ["checks", "0", "lanes"], to: ["l4_stream", "l4_packet", "ws", "http"])
        lanes = ScanPack.edited(lanes, path: ["checks", "1", "lanes"], to: [])
        lanes = ScanPack.edited(lanes, path: ["checks", "2", "lanes"], to: [])
        let laneTree = ScanCheckTree(checks: try ScanChecksResult(json: lanes).checks,
                                     selection: ScanCheckSelection(include: [], exclude: []), intensity: .light, query: "")
        #expect(laneTree.groups.map(\.lane) == [.http, .ws, .l4Packet, .l4Stream])
        #expect(laneTree.groups.allSatisfy { $0.leaves.count == 1 && $0.leaves[0].aboveIntensity })

        // The query trims whitespace and matches id, name and class, case-insensitively.
        #expect(ScanCheckTree(checks: checks, selection: selection, intensity: .light, query: "  Marker ")
            .groups.flatMap(\.leaves).map(\.meta.id) == ["http.custom-marker"])
        #expect(ScanCheckTree(checks: checks, selection: selection, intensity: .light, query: "information")
            .groups.flatMap(\.leaves).map(\.meta.id) == ["http.custom-marker"])
        #expect(ScanCheckTree(checks: checks, selection: selection, intensity: .light, query: "Error-based")
            .groups.flatMap(\.leaves).map(\.meta.id) == ["http.sqli-error"])
        #expect(ScanCheckTree(checks: checks, selection: selection, intensity: .light, query: "nothing-here").groups.isEmpty)
        #expect(ScanCheckTree(checks: checks, selection: selection, intensity: .light, query: "   ").groups.count == 4)
        #expect(ScanCheckTree(checks: [], selection: selection, intensity: .light, query: "").groups.isEmpty)

        // `aboveIntensity` follows the rank: a passive profile greys everything but passive checks.
        let passive = ScanCheckTree(checks: checks, selection: selection, intensity: .passive, query: "")
        let above = Dictionary(passive.groups.flatMap(\.leaves).map { ($0.meta.id, $0.aboveIntensity) }, uniquingKeysWith: { first, _ in first })
        #expect(above["http.custom-marker"] == false)
        #expect(above["http.sqli-error"] == true)
        #expect(above["http.reflected-xss"] == true)

        // `setAll` with an empty list is a no-op; `setAll(.default)` clears both lists.
        ScanCheckTree.setAll(.include, ids: [], in: &selection)
        #expect(selection.include == ["http.reflected-xss"])
        ScanCheckTree.setAll(.default, ids: ["http.reflected-xss", "never-listed"], in: &selection)
        #expect(selection == ScanCheckSelection(include: [], exclude: []))
    }

    // MARK: Profile edits (MS-AC6)

    @Test func profileEditsToBudgetSessionAndLanesSurviveTheRoundTrip() throws {
        let file = try Self.load("scan.profile.get.json")
        var profile = try ScanProfile(json: file)
        profile.name = "my-api"
        profile.lanes = [.http]
        profile.intensity = .light
        profile.speed = .thorough
        profile.accuracy = .fewerFalsePositives
        profile.budget.probes = 5000
        profile.budget.timeS = 60
        profile.session.mode = ScanSessionMode.none
        profile.session.fromFlow = "550e8400-e29b-41d4-a716-446655440000"
        profile.session.onLost = .continue
        profile.target.origins = ["http://api.shop-staging.test"]
        profile.checks.exclude = ["http.reflected-xss"]

        let json = profile.json()
        #expect(json["name"] == "my-api")
        #expect(json["lanes"] == JSONValue.array(["http"]))
        #expect(json["intensity"] == "light")
        #expect(json["speed"] == "thorough")
        #expect(json["accuracy"] == "fewer_false_positives")
        #expect(json["budget"]?["probes"] == 5000)
        #expect(json["budget"]?["time_s"] == 60)
        #expect(json["budget"]?["max_issues"] == 1024, "untouched siblings keep the file's values")
        #expect(json["budget"]?["check_timeout_s"] == 60)
        #expect(json["budget"]?["per_host_errors"] == file["budget"]?["per_host_errors"])
        #expect(json["session"] == JSONValue.object([
            "mode": "none", "from_flow": "550e8400-e29b-41d4-a716-446655440000", "on_lost": "continue",
        ]))
        #expect(json["target"]?["origins"] == JSONValue.array(["http://api.shop-staging.test"]))
        #expect(json["target"]?["l4"] == JSONValue.array([]))
        #expect(json["checks"] == JSONValue.object(["include": .array([]), "exclude": .array(["http.reflected-xss"])]))
        for key in ["crawl", "audit", "http", "ws", "l4"] {
            #expect(json[key] == file[key], "pass-through section \(key) changed")
        }
        #expect(Set(try #require(json.objectValue).keys) == Set(try #require(file.objectValue).keys))

        let decoded = try ScanProfile(json: json)
        #expect(decoded == profile)
        #expect(decoded.budget.probes == 5000)
        #expect(decoded.session.onLost == .continue)
        #expect(decoded.session.fromFlow == "550e8400-e29b-41d4-a716-446655440000")
        #expect(decoded.lanes == [.http])
        #expect(decoded.name == "my-api")
        #expect(decoded.json() == json)

        // Clearing `from_flow` re-encodes as `null`, as the crate serialises it.
        profile.session.fromFlow = nil
        #expect(profile.json()["session"]?["from_flow"] == JSONValue.null)
        #expect(try ScanProfile(json: profile.json()).session.fromFlow == nil)
    }

    @Test func unknownProfileKeysPassThroughASave() throws {
        var file = try Self.load("scan.profile.get.json")
        file = ScanPack.edited(file, path: ["future_section"], to: ["knob": 1])
        file = ScanPack.edited(file, path: ["crawl", "new_crawl_knob"], to: true)
        file = ScanPack.edited(file, path: ["budget", "per_host_errors", "window_s"], to: 30)
        file = ScanPack.edited(file, path: ["l4"], to: .null)
        var profile = try ScanProfile(json: file)
        #expect(profile.extra["future_section"] == JSONValue.object(["knob": 1]))
        #expect(profile.extra.count == 1)
        #expect(profile.l4 == JSONValue.null)
        profile.checks.include = ["http.sqli-error"]
        profile.budget.probes = 1

        let json = profile.json()
        #expect(json["future_section"] == JSONValue.object(["knob": 1]))
        #expect(json["crawl"]?["new_crawl_knob"] == true)
        #expect(json["budget"]?["per_host_errors"]?["window_s"] == 30)
        #expect(json["budget"]?["probes"] == 1)
        #expect(json["checks"]?["include"] == JSONValue.array(["http.sqli-error"]))
        #expect(json["l4"] == JSONValue.null)
        #expect(try ScanProfile(json: json) == profile)

        // A profile that omits the pass-through sections omits them on the way back too.
        var thin = file
        for key in ["crawl", "audit", "http", "ws", "l4", "future_section"] { thin = ScanPack.removing(thin, path: [key]) }
        let thinProfile = try ScanProfile(json: thin)
        #expect(thinProfile.crawl == nil)
        #expect(thinProfile.extra.isEmpty)
        #expect(Set(try #require(thinProfile.json().objectValue).keys) == ScanProfile.editedKeys)
    }

    // MARK: Words

    @Test func elapsedAndRelativeBoundaries() {
        #expect(ScanFormat.elapsed(ms: 999) == "0:00")
        #expect(ScanFormat.elapsed(ms: 1_000) == "0:01")
        #expect(ScanFormat.elapsed(ms: 59_999) == "0:59")
        #expect(ScanFormat.elapsed(ms: 60_000) == "1:00")
        #expect(ScanFormat.elapsed(ms: 3_599_999) == "59:59")
        #expect(ScanFormat.elapsed(ms: 3_600_000) == "1:00:00")
        #expect(ScanFormat.elapsed(ms: 36_005_000) == "10:00:05")
        #expect(ScanFormat.elapsed(ms: -5_000) == "0:00")

        let t = 1_761_900_000_000
        #expect(ScanFormat.relative(ms: t, now: t) == "0 s ago")
        #expect(ScanFormat.relative(ms: t, now: t + 999) == "0 s ago")
        #expect(ScanFormat.relative(ms: t, now: t + 59_999) == "59 s ago")
        #expect(ScanFormat.relative(ms: t, now: t + 60_000) == "1 min ago")
        #expect(ScanFormat.relative(ms: t, now: t + 3_599_999) == "59 min ago")
        #expect(ScanFormat.relative(ms: t, now: t + 3_600_000) == "1 h ago")
        #expect(ScanFormat.relative(ms: t, now: t + 90_000_000) == "25 h ago")
        #expect(ScanFormat.relative(ms: t + 10_000, now: t) == "0 s ago", "a core clock ahead of ours never reads negative")
    }

    @Test func wordsAtTheEdgesOfTheRows() throws {
        let list = try ScanListResult(json: Self.load("scan.list.json"))

        // MS-AC1: an unknown state renders as it came, in the row and for VoiceOver.
        let paused = try ScanListResult(json: ScanPack.edited(Self.load("scan.list.json"), path: ["jobs", "0", "state"], to: "paused")).jobs[0]
        #expect(ScanFormat.jobRowLine1(paused, status: nil) == "paused · — · —")
        #expect(ScanFormat.jobAccessibilityLabel(paused, status: nil)
                == "paused, auditing, 418 of 2000 probes, 80 of 120 points audited, 3 issues: 1 high, 1 medium, 1 low")

        // A queued or cancelling job shows its state word, not its phase; only a running job shows the phase.
        let queued = try ScanStartResult(json: Self.load("scan.start.json")).status
        #expect(ScanFormat.jobRowLine1(queued.summary, status: queued) == "Queued · standard · 127.0.0.1:8080")
        let cancelling = try ScanJobStatus(json: Self.load("scan.cancel.json"))
        #expect(ScanFormat.jobRowLine1(cancelling.summary, status: cancelling) == "Cancelling · standard · 127.0.0.1:8080")
        let crawling = try ScanStartResult(json: Self.load("scan.map.json")).status
        #expect(ScanFormat.jobRowLine1(crawling.summary, status: crawling) == "Crawling · standard · 127.0.0.1:8080")
        #expect(ScanFormat.jobRowLine2(crawling.summary) == "probes 0 / 0 · points 0 / 0 audited · 0:01")

        // A finished job with no status read yet.
        #expect(ScanFormat.jobAccessibilityLabel(list.jobs[1], status: nil)
                == "Done, done, 0 of 0 probes, 0 of 0 points audited, no issues")
        #expect(ScanFormat.severityCountsInWords(BySeverity(critical: 1, high: 0, medium: 0, low: 0, info: 0)) == "1 issue: 1 critical")
        #expect(ScanFormat.severityCountsInWords(BySeverity(critical: 2, high: 0, medium: 0, low: 0, info: 3)) == "5 issues: 2 critical, 3 info")

        // Two targets join with a comma; a target with a path or scheme in capitals is reduced to its authority.
        let two = ScanPack.edited(try Self.load("scan.status.json"), path: ["targets"], to: ["http://127.0.0.1:8080", "HTTPS://api.shop-staging.test/"])
        let status = try ScanJobStatus(json: two)
        #expect(ScanFormat.jobRowLine1(status.summary, status: status) == "Auditing · standard · 127.0.0.1:8080, api.shop-staging.test")
        let noTargets = try ScanJobStatus(json: ScanPack.edited(try Self.load("scan.status.json"), path: ["targets"], to: []))
        #expect(ScanFormat.jobRowLine1(noTargets.summary, status: noTargets) == "Auditing · standard · —")

        // An issue row without a method (a WS or L4 lane) shows the path alone.
        var issue = try ScanIssuesResult(json: Self.load("scan.issues.json")).issues[0]
        issue.location.method = nil
        #expect(ScanFormat.issueRowLine2(issue) == "/search · query q · certain")
        #expect(ScanFormat.issueWhere(issue) == "http://127.0.0.1:8080 · /search · query q")

        // Plurals.
        var detail = try ScanIssue(json: Self.load("scan.issue.json"))
        detail.occurrences = 2
        let meta = ScanFormat.issueMetaLine(detail, now: detail.lastSeen)
        #expect(meta == "first seen 0 s ago · last seen 0 s ago · 2 occurrences · http.reflected-xss · scan-1a2b3c4d")
        var point = try ScanSitemapResult(json: Self.load("scan.sitemap.json")).points[0]
        point.frequency = 1
        point.traits = []
        point.example = nil
        point.path = nil
        #expect(ScanFormat.pointAccessibilityLabel(point) == "json_value city, seen 1 time")
        point.example = ""
        point.path = ""
        #expect(ScanFormat.pointAccessibilityLabel(point) == "json_value city, seen 1 time")
        var node = try ScanSitemapResult(json: Self.load("scan.sitemap.json")).nodes[0]
        node.points = 1
        node.audited = false
        node.auth = false
        #expect(ScanFormat.nodeAccessibilityLabel(node) == "GET /account/{id}, 1 point")
        node.points = 0
        node.auth = true
        #expect(ScanFormat.nodeAccessibilityLabel(node) == "GET /account/{id}, 0 points, needs auth")

        // A session preview with nothing to reuse and no source flow; names only, never a value.
        var preview = try ScanSessionProfile(json: Self.load("scan.session.preview.json"))
        preview.cookies = []
        preview.headers = []
        preview.sourceFlow = nil
        #expect(ScanFormat.sessionPreviewText(preview, flowLabel: nil, now: preview.observedAt)
                == "Cookies: none · Headers: none · observed 0 s ago")
        preview.cookies = ["sid", "csrf"]
        #expect(ScanFormat.sessionPreviewText(preview, flowLabel: nil, now: preview.observedAt)
                == "Cookies: sid, csrf · Headers: none · observed 0 s ago")
        #expect(ScanFormat.canaryText(.flow(method: "HEAD", path: "/me", expectedStatus: nil)) == "Canary: HEAD /me")

        // `hostOf` keeps a port, lower-cases, drops path and credentials; a non-URL comes back as typed.
        #expect(ScanFormat.hostOf(origin: "HTTPS://User:pw@API.Shop-Staging.test:8443/x?y#z") == "api.shop-staging.test:8443")
        #expect(ScanFormat.hostOf(origin: "127.0.0.1:9000") == "127.0.0.1:9000")
        #expect(ScanFormat.hostOf(origin: "ftp://files.example") == "ftp://files.example")
        #expect(ScanFormat.hostOf(origin: "http://") == "http://")
        #expect(ScanFormat.hostOf(origin: "") == "")

        // A profile row with an unknown lane shows the wire word.
        var entry = try ScanProfileListResult(json: Self.load("scan.profile.list.json")).profiles[0]
        entry.lanes = [.http, .other("quic")]
        #expect(ScanFormat.profileRowLine2(entry) == "http, quic · passive · normal")
        entry.lanes = []
        #expect(ScanFormat.profileRowLine2(entry) == "no lanes · passive · normal")

        // Launch notices for a clamp and a skipped lane are one line each, in that order.
        var model = ScanSurfaceModel()
        var start = try Self.load("scan.start.json")
        start = ScanPack.edited(start, path: ["clamped"], to: [
            ["field": "budget.probes", "requested": 50000, "applied": 20000],
            ["field": "budget.time_s", "requested": 7200, "applied": 3600],
        ])
        start = ScanPack.edited(start, path: ["lanes", "skipped"], to: [
            ["lane": "ws", "reason": "lane not available on this build"],
            ["lane": "l4_stream", "reason": "no L4 scope entry"],
        ])
        model.applyStart(try ScanStartResult(json: start))
        #expect(model.launchNotices["scan-1a2b3c4d"] == [
            "Clamped budget.probes 50000 → 20000", "Clamped budget.time_s 7200 → 3600",
            "Skipped ws: lane not available on this build", "Skipped l4_stream: no L4 scope entry",
        ])
    }

    @Test func launchErrorParsingEdges() {
        #expect(ScanLaunchError(busMessage: "scan: : no code", origins: []).code == nil)
        #expect(ScanLaunchError(busMessage: "scan: : no code", origins: []).display == "scan: : no code")
        #expect(ScanLaunchError(busMessage: "scan: not a code: x", origins: []).code == nil)
        #expect(ScanLaunchError(busMessage: "scan: not a code: x", origins: []).display == "scan: not a code: x")
        #expect(ScanLaunchError(busMessage: "scan: busy", origins: []).code == nil)
        #expect(ScanLaunchError(busMessage: "scan: busy", origins: []).display == "scan: busy")
        #expect(ScanLaunchError(busMessage: "scan:busy: x", origins: []).code == nil)
        #expect(ScanLaunchError(busMessage: "", origins: []).display == "")

        let busy = ScanLaunchError(busMessage: "scan: busy: ", origins: [])
        #expect(busy.code == "busy")
        #expect(busy.message == "")
        #expect(busy.display == "A scan on this origin is already running")

        // `out_of_scope` with no origin to name falls back to the engine's text.
        let scope = ScanLaunchError(busMessage: "scan: out_of_scope: origin not in scope", origins: [])
        #expect(scope.display == "origin not in scope")
        // With origins, the first names the authority, lower-cased and without the path.
        let named = ScanLaunchError(busMessage: "scan: out_of_scope: origin not in scope",
                                    origins: ["HTTPS://Api.Shop-Staging.test/x", "http://second.example"])
        #expect(named.display == "Out of scope — add api.shop-staging.test to scope to scan it")

        // Nested colons stay in the message.
        let nested = ScanLaunchError(busMessage: "scan: profile_not_found: no profile named a:b: c", origins: [])
        #expect(nested.code == "profile_not_found")
        #expect(nested.message == "no profile named a:b: c")
        #expect(nested.display == "no profile named a:b: c")

        // The memberwise init and the parsing init agree.
        #expect(ScanLaunchError(code: "busy", message: "x", origins: ["http://a"])
                == ScanLaunchError(busMessage: "scan: busy: x", origins: ["http://a"]))
    }

    // MARK: Mutations

    /// Plan Task 3: `applyList` keeps "a locally inserted job that the list lacks
    /// yet". A job the core itself listed and then stopped listing (a core restart,
    /// a capped list) is not that job: the list is the truth for it.
    @Test func aJobTheCoreStopsListingIsDropped() throws {
        var started = ScanSurfaceModel()
        started.applyStart(try ScanStartResult(json: Self.load("scan.start.json")))
        started.applyList(try ScanListResult(json: ["jobs": []]))
        #expect(started.jobs.map(\.job) == ["scan-1a2b3c4d"], "a job this app started stays until the list carries it")

        var listed = ScanSurfaceModel()
        listed.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        #expect(listed.jobs.count == 2)
        listed.applyList(try ScanListResult(json: ["jobs": []]))
        #expect(listed.jobs.isEmpty, "scan.list is the truth for a job it carried before")
    }

    @Test func mutationsKeepTheListsConsistent() throws {
        var model = ScanSurfaceModel()

        // applyProfiles: builtins as listed, then custom profiles alphabetically; the error clears.
        var list = try Self.load("scan.profile.list.json")
        let zeta: JSONValue = ["name": "zeta", "builtin": false, "summary": ["lanes": ["http"], "intensity": "light", "speed": "fast"]]
        let alpha = ScanPack.edited(zeta, path: ["name"], to: "alpha")
        var profiles = try #require(list["profiles"]?.arrayValue)
        profiles.insert(zeta, at: 0)
        profiles.append(alpha)
        list = ScanPack.edited(list, path: ["profiles"], to: .array(profiles))
        model.profilesError = "old"
        model.applyProfiles(try ScanProfileListResult(json: list))
        #expect(model.profiles.map(\.name)
                == ["passive-only", "map-only", "light-http", "standard", "thorough", "l4-stream-safe", "l4-full", "alpha", "zeta"])
        #expect(model.profilesError == nil)
        model.applyProfiles(try ScanProfileListResult(json: ["profiles": []]))
        #expect(model.profiles.isEmpty)

        // applyProfile: loaded and edited start equal; the selection follows.
        let profile = try Self.standardProfile()
        model.applyProfile(profile)
        #expect(model.loadedProfile == profile)
        #expect(model.editedProfile == profile)
        #expect(model.selectedProfile == "standard")
        #expect(!model.profileIsEdited)
        model.editedProfile?.budget.probes = 1
        #expect(model.profileIsEdited)
        model.applyChecks(try ScanChecksResult(json: Self.load("scan.checks.json")))
        #expect(model.checks.count == 3)

        // applyList keeps a job this app started that the list lacks yet, in front; the error clears.
        var start = try Self.load("scan.start.json")
        start = ScanPack.edited(start, path: ["job"], to: "scan-local")
        start = ScanPack.edited(start, path: ["status", "job"], to: "scan-local")
        model.applyStart(try ScanStartResult(json: start))
        model.jobsError = "old"
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        #expect(model.jobs.map(\.job) == ["scan-local", "scan-1a2b3c4d", "scan-55667788"])
        #expect(model.jobsError == nil)
        #expect(model.selectedJob == "scan-local")

        // Once the list carries it, the list's order and values win.
        var listed = try Self.load("scan.list.json")
        var jobs = try #require(listed["jobs"]?.arrayValue)
        jobs.append(ScanPack.edited(jobs[1], path: ["job"], to: "scan-local"))
        listed = ScanPack.edited(listed, path: ["jobs"], to: .array(jobs))
        model.applyList(try ScanListResult(json: listed))
        #expect(model.jobs.map(\.job) == ["scan-1a2b3c4d", "scan-55667788", "scan-local"])
        #expect(model.jobs[2].state == .done)
        #expect(model.statuses["scan-local"]?.state == .queued, "the start's status stays until scan.status replaces it")

        // applyStatus replaces the matching row and only that row; a stranger is stored without a row.
        var statusModel = ScanSurfaceModel()
        statusModel.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        let status = try ScanJobStatus(json: ScanPack.edited(Self.load("scan.status.json"), path: ["probes", "sent"], to: 777))
        statusModel.applyStatus(status)
        #expect(statusModel.jobs[0].probes.sent == 777)
        #expect(statusModel.jobs[1].probes.sent == 0)
        #expect(statusModel.statuses["scan-1a2b3c4d"]?.probes.sent == 777)
        let stranger = try ScanJobStatus(json: ScanPack.edited(Self.load("scan.status.json"), path: ["job"], to: "scan-elsewhere"))
        statusModel.applyStatus(stranger)
        #expect(statusModel.jobs.count == 2)
        #expect(statusModel.statuses["scan-elsewhere"] != nil)

        // applyIssues: replace, then append without repeating rows; cursor and tally follow the page.
        let page = try ScanIssuesResult(json: Self.load("scan.issues.json"))
        model.issuesError = "old"
        model.applyIssues(page, append: false)
        #expect(model.issuesError == nil)
        model.applyIssues(page, append: true)
        #expect(model.issues.count == 2)
        var more = try Self.load("scan.issues.json")
        more = ScanPack.edited(more, path: ["issues", "0", "id"], to: "issue-new")
        more = ScanPack.edited(more, path: ["next_cursor"], to: "issue-new")
        more = ScanPack.edited(more, path: ["by_severity", "high"], to: 2)
        model.applyIssues(try ScanIssuesResult(json: more), append: true)
        #expect(model.issues.map(\.id) == ["issue-9f8e7d6c", "issue-4c3b2a19", "issue-new"])
        #expect(model.issuesCursor == "issue-new")
        #expect(model.issuesBySeverity.high == 2)
        #expect(model.tabTitle(.issues) == "Issues 3")
        model.applyIssues(try ScanIssuesResult(json: ["issues": []]), append: false)
        #expect(model.issues.isEmpty)
        #expect(model.issuesCursor == nil)
        #expect(model.issuesBySeverity == .zero)
        #expect(model.issuesGroupedBySeverity().isEmpty)
        #expect(model.tabTitle(.issues) == "Issues")

        // applyIssue: the detail is kept and the list row takes the new status; the open count follows.
        model.applyIssues(page, append: false)
        #expect(model.openIssueCount == 2)
        let updated = try ScanIssue(json: Self.load("scan.issue.update.json"))
        model.applyIssue(updated)
        #expect(model.issueDetail?.id == "issue-9f8e7d6c")
        #expect(model.issueDetail?.note == "intended behaviour")
        #expect(model.issues[0].status == .falsePositive)
        #expect(model.issues[1].status == .open)
        #expect(model.openIssueCount == 1)
        model.filters.status = .falsePositive
        #expect(model.issuesGroupedBySeverity().flatMap(\.issues).map(\.id) == ["issue-9f8e7d6c"])
        model.filters = ScanIssueFilters()
        // A detail for an issue not in the list is kept without inventing a row.
        var elsewhere = updated
        elsewhere.id = "issue-elsewhere"
        model.applyIssue(elsewhere)
        #expect(model.issueDetail?.id == "issue-elsewhere")
        #expect(model.issues.count == 2)

        // select(issue:) keeps the detail for the same id and drops it for another.
        model.applyIssue(updated)
        model.select(issue: "issue-9f8e7d6c")
        #expect(model.issueDetail != nil)
        model.select(issue: "issue-4c3b2a19")
        #expect(model.issueDetail == nil)
        #expect(model.selectedIssue == "issue-4c3b2a19")
        model.select(issue: nil)
        #expect(model.selectedIssue == nil)

        // applySitemap: append onto nothing is a plain load; a later page merges without repeating ids.
        let sitemap = try ScanSitemapResult(json: Self.load("scan.sitemap.json"))
        model.applySitemap(sitemap, append: true)
        #expect(model.sitemap == sitemap)
        var next = try Self.load("scan.sitemap.json")
        next = ScanPack.edited(next, path: ["nodes", "0", "id"], to: "node-2")
        next = ScanPack.edited(next, path: ["nodes", "0", "host"], to: "api.shop-staging.test")
        next = ScanPack.edited(next, path: ["nodes", "0", "path_template"], to: "/orders")
        next = ScanPack.edited(next, path: ["points", "0", "id"], to: "point-json-2")
        next = ScanPack.edited(next, path: ["points", "0", "site_node"], to: "node-2")
        next = ScanPack.edited(next, path: ["next_cursor"], to: .null)
        model.applySitemap(try ScanSitemapResult(json: next), append: true)
        #expect(model.sitemap?.nodes.map(\.id) == ["node-1", "node-2"])
        #expect(model.sitemap?.points.map(\.id) == ["point-json-1", "point-cookie-1", "point-json-2"])
        #expect(model.sitemap?.nextCursor == nil)
        let groups = model.sitemapGroupedByOrigin()
        #expect(groups.map(\.origin) == ["http://127.0.0.1:8080", "http://api.shop-staging.test:8080"])
        #expect(groups[1].nodes.map(\.pathTemplate) == ["/orders"])
        #expect(model.points(for: "node-2").map(\.id) == ["point-json-2"])
        #expect(model.points(for: "node-1").map(\.id) == ["point-json-1", "point-cookie-1"])
        model.sitemapQuery = "shop-staging"
        #expect(model.sitemapGroupedByOrigin().map(\.origin) == ["http://api.shop-staging.test:8080"])
        model.sitemapQuery = "  ORDERS "
        #expect(model.sitemapGroupedByOrigin().flatMap(\.nodes).map(\.id) == ["node-2"])
        model.moveSelection(in: .sitemap, by: 1)
        #expect(model.selectedNode == "node-2", "the keyboard walks the filtered tree")
        model.sitemapQuery = ""
        model.moveSelection(in: .sitemap, by: -1)
        #expect(model.selectedNode == "node-1")
        // A fresh page (not appended) replaces the tree.
        model.applySitemap(sitemap, append: false)
        #expect(model.sitemap == sitemap)
        #expect(model.sitemapGroupedByOrigin().count == 1)
    }

    /// Task 3's rule: every string a Scan view renders has one home in the Kit.
    /// These were view-local copies in the five view files; now the views read them here.
    @Test func viewStringsHaveOneHome() {
        #expect(scanEditedBuiltinText == "Edited builtin — Start Scan uses these values; Duplicate… to keep them.")
        #expect(scanIntrusiveHint == "Intrusive checks may disrupt the target; the engine asks before starting.")
        #expect(scanAboveIntensityHelp == "Above this profile's intensity; raise Intensity to run it.")
        let clamped = ScanClamped(field: "budget.probes", requested: 50000, applied: 20000)
        #expect(ScanFormat.clampedText(clamped) == "Clamped budget.probes 50000 → 20000")
        let skipped = ScanSkippedLane(lane: .ws, reason: "lane not available on this build")
        #expect(ScanFormat.skippedLaneText(skipped) == "Skipped ws: lane not available on this build")
        #expect(ScanFormat.outOfScopeText(origin: "http://a.test:8443/x") == "Out of scope — add a.test:8443 to scope to scan it")
        #expect(ScanLaunchError(code: "out_of_scope", message: "x", origins: ["http://a.test:8443/x"]).display
            == ScanFormat.outOfScopeText(origin: "http://a.test:8443/x"))
        #expect(ScanConfidence.tentative.word == "Tentative")
        #expect(ScanConfidence.firm.word == "Firm")
        #expect(ScanConfidence.certain.word == "Certain")
        #expect(ScanConfidence.other("sure-ish").word == "sure-ish")
        #expect(ScanCheckTree.Choice.default.word == "Default")
        #expect(ScanCheckTree.Choice.include.word == "Include")
        #expect(ScanCheckTree.Choice.exclude.word == "Exclude")
        #expect(ScanFormat.number(0.8571) == "0.857")
        #expect(ScanFormat.number(2) == "2")
        #expect(ScanFormat.number(12345.5) == "12345.5", "no grouping separator")
        #expect(ScanFormat.yesNo(true) == "yes")
        #expect(ScanFormat.yesNo(false) == "no")
        #expect(ScanFormat.plural(1, "endpoint") == "1 endpoint")
        #expect(ScanFormat.plural(3, "endpoint") == "3 endpoints")

        // Q10: the empty states and placeholders the four tabs render.
        #expect(scanNoEndpointsMatchText == "No endpoints match.")
        #expect(scanSelectEndpointText == "Select an endpoint.")
        #expect(scanNoPointsOnEndpointText == "None on this endpoint.")
        #expect(scanNoFlowsOnEndpointText == "None recorded for this endpoint.")
        #expect(scanNoEvidenceText == "No evidence recorded for this issue.")
        #expect(scanSelectIssueText == "Select an issue to read its evidence.")
        #expect(scanSelectJobText == "Select a job.")
        #expect(scanNoJobsText == "No jobs yet — pick a profile and Start Scan.")
        #expect(scanNoIssuesText == "No issues — start a scan, or widen the filters.")
        #expect(scanNoSitemapText == "No site map yet — a running job fills this as it crawls.")
        #expect(scanProfileNameRuleText == "Use lowercase letters, digits, - _ . (start with a letter or digit)")
        #expect(ScanFormat.findingText("f-3b1c") == "Finding f-3b1c")
        #expect(scanNoProfilesText == "No profiles — the core lists none.")
        #expect(scanNothingToDeleteText(name: "my-api") == "Nothing to delete: my-api is not on the core")
        #expect(scanUnableText("save profile", "bus closed") == "Unable to save profile: bus closed")
    }

    // MARK: Stage 6 fixes

    /// P1: a launch error is kept whole (code, origins) beside its display line, and
    /// cleared by a start, a confirm request, or picking another profile.
    @Test func aLaunchErrorIsKeptWholeUntilTheNextLaunchStep() throws {
        var model = ScanSurfaceModel()
        #expect(model.launchError == nil)
        model.launchInFlight = true
        model.applyLaunchError(ScanLaunchError(busMessage: "scan: lane_unavailable: ws not built", origins: []))
        #expect(model.launchError?.code == "lane_unavailable")
        #expect(model.launchError?.message == "ws not built")
        #expect(model.statusLine == "ws not built")
        #expect(!model.launchInFlight)

        model.select(profile: "thorough")
        #expect(model.launchError == nil, "picking another profile clears it")
        #expect(model.statusLine == nil, "and its line with it")

        model.applyLaunchError(ScanLaunchError(busMessage: "scan: out_of_scope: no", origins: ["http://a.test:8443/x"]))
        #expect(model.launchError?.code == "out_of_scope")
        #expect(model.launchError?.origins == ["http://a.test:8443/x"])
        #expect(model.statusLine == ScanFormat.outOfScopeText(origin: "http://a.test:8443/x"))
        model.applyStart(try ScanStartResult(json: Self.load("scan.start.json")))
        #expect(model.launchError == nil, "a start clears it")
        #expect(model.statusLine == nil)

        model.applyLaunchError(ScanLaunchError(busMessage: "plain words", origins: []))
        #expect(model.launchError?.code == nil)
        #expect(model.statusLine == "plain words")
        let request = try #require(L4ConfirmRequest(json: [
            "structuredContent": ["status": "needs_confirmation", "prompt": "Really?", "confirm_token": "t"],
        ]))
        model.applyConfirm(tool: "scan.start", args: [:], request: request)
        #expect(model.launchError == nil, "a confirm request clears it")
    }

    /// S5: a profile name is a store key on the core; only a plain token may go there.
    @Test func profileNamesAreValidatedBeforeTheyReachTheCore() {
        #expect(ScanSurface.isValidProfileName("my-api"))
        #expect(ScanSurface.isValidProfileName("my.api_2"))
        #expect(!ScanSurface.isValidProfileName("My.API_2"), "the engine takes lowercase only")
        #expect(ScanSurface.isValidProfileName("standard"))
        #expect(ScanSurface.isValidProfileName("a"))
        #expect(ScanSurface.isValidProfileName(String(repeating: "a", count: 64)))
        #expect(!ScanSurface.isValidProfileName("../x"))
        #expect(!ScanSurface.isValidProfileName(".hidden"))
        #expect(!ScanSurface.isValidProfileName("-flag"))
        #expect(!ScanSurface.isValidProfileName("a b"))
        #expect(!ScanSurface.isValidProfileName(""))
        #expect(!ScanSurface.isValidProfileName(String(repeating: "a", count: 65)))
        #expect(!ScanSurface.isValidProfileName("standard/.."))
        #expect(!ScanSurface.isValidProfileName("a\\b"))
        #expect(!ScanSurface.isValidProfileName("a\u{0}b"))
        #expect(!ScanSurface.isValidProfileName("a\tb"))
        #expect(!ScanSurface.isValidProfileName("a\nb"))
        #expect(!ScanSurface.isValidProfileName("café"))
        #expect(!ScanSurface.isValidProfileName("a:b"))
    }

    /// Q1: the Issues detail resolves `poc_ref` to a listed PoC path in the Kit, not the view.
    /// The engine's live `poc_ref` is the PoC file's absolute path (seen on 2026-11-01); it
    /// resolves by equality, and a different file in the same folder does not.
    @Test func anAbsolutePocRefResolvesByEquality() {
        let a = "/tmp/f/scan/pocs/aitm-poc-reflected-cross-site-scripting-43248-1-1793548843269530000/reflected-cross-site-scripting.poc.yaml"
        let b = "/tmp/f/scan/pocs/aitm-poc-open-redirect-99/open-redirect.poc.yaml"
        #expect(ScanFindingLink.match(pocRef: a, in: [b, a]) == 1)
        #expect(ScanFindingLink.match(pocRef: a, in: [b]) == nil)
        #expect(ScanFindingLink.match(pocRef: "/tmp/other/reflected-cross-site-scripting.poc.yaml", in: [a]) == nil)
    }

    @Test func pocRefResolvesToAListedPath() {
        let paths = ["/x/pocs/poc-3b1c.poc.yaml", "/x/pocs/other.poc.yaml"]
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c", in: paths) == 0)
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c.poc.yaml", in: paths) == 0)
        #expect(ScanFindingLink.match(pocRef: "other", in: paths) == 1)
        #expect(ScanFindingLink.match(pocRef: "pocs/other.poc.yaml", in: paths) == 1, "a suffix after a slash matches")
        #expect(ScanFindingLink.match(pocRef: "nope", in: paths) == nil)
        #expect(ScanFindingLink.match(pocRef: "", in: paths) == nil)
        #expect(ScanFindingLink.match(pocRef: nil, in: paths) == nil)
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c", in: []) == nil)
        #expect(ScanFindingLink.match(pocRef: "3b1c", in: paths) == nil, "a bare substring is not a match")
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c", in: ["poc-3b1c", "/x/poc-3b1c"]) == 0)
        #expect(ScanFindingLink.match(pocRef: "x/poc-3b1c", in: ["/x/poc-3b1c"]) == 0)
    }

    /// Q9: the row words VoiceOver reads for an issue, a profile, a check and an origin (D13).
    @Test func accessibilityLabelsForTheOtherRows() throws {
        let issues = try ScanIssuesResult(json: Self.load("scan.issues.json"))
        #expect(ScanFormat.issueAccessibilityLabel(issues.issues[0])
                == "High, Reflected cross-site scripting, GET /search · query q · certain, Open")
        var fp = issues.issues[1]
        fp.status = .falsePositive
        #expect(ScanFormat.issueAccessibilityLabel(fp) == "Medium, Open redirect, GET /go · query next · firm, False positive")
        fp.severity = .other("blocker")
        fp.status = .other("wontfix")
        #expect(ScanFormat.issueAccessibilityLabel(fp) == "blocker, Open redirect, GET /go · query next · firm, wontfix")

        let profiles = try ScanProfileListResult(json: Self.load("scan.profile.list.json")).profiles
        #expect(ScanFormat.profileAccessibilityLabel(profiles[0]) == "passive-only, builtin, http · passive · normal")
        #expect(ScanFormat.profileAccessibilityLabel(profiles[3]) == "standard, builtin, http, ws · medium · normal")
        var custom = profiles[3]
        custom.name = "my-api"
        custom.builtin = false
        #expect(ScanFormat.profileAccessibilityLabel(custom) == "my-api, http, ws · medium · normal")

        let checks = try ScanChecksResult(json: Self.load("scan.checks.json")).checks
        let profile = try Self.standardProfile()
        let tree = ScanCheckTree(checks: checks, selection: profile.checks, intensity: .light, query: "")
        let leaves = tree.groups.flatMap(\.leaves)
        let sqli = try #require(leaves.first { $0.meta.id == "http.sqli-error" })
        #expect(sqli.aboveIntensity)
        // The row's visible words (name, class, intensity, cost, origin); the choice menu reads its own.
        #expect(ScanFormat.checkAccessibilityLabel(sqli)
                == "Error-based SQL injection, sqli-error, medium, light, bundled, above this profile's intensity")
        var included = sqli
        included.choice = .include
        included.aboveIntensity = false
        #expect(ScanFormat.checkAccessibilityLabel(included)
                == "Error-based SQL injection, sqli-error, medium, light, bundled")
        let xss = try #require(leaves.first { $0.meta.id == "http.reflected-xss" })
        #expect(ScanFormat.checkAccessibilityLabel(xss)
                == "reflected-xss check, reflected-xss, medium, light, native, above this profile's intensity")

        #expect(ScanFormat.originAccessibilityLabel(origin: "http://127.0.0.1:8080", count: 3, collapsed: true)
                == "http://127.0.0.1:8080, 3 endpoints, collapsed")
        #expect(ScanFormat.originAccessibilityLabel(origin: "http://127.0.0.1:8080", count: 1, collapsed: false)
                == "http://127.0.0.1:8080, 1 endpoint, expanded")
    }

    /// Q12: a status with an empty profile name reads as not told yet, in the row and for VoiceOver.
    @Test func anEmptyProfileNameReadsAsAbsent() throws {
        let list = try ScanListResult(json: Self.load("scan.list.json"))
        let nameless = try ScanJobStatus(json: ScanPack.edited(Self.load("scan.status.json"), path: ["profile_name"], to: ""))
        #expect(nameless.profileName == "")
        #expect(ScanFormat.jobRowLine1(list.jobs[0], status: nameless) == "Auditing · — · 127.0.0.1:8080")
        #expect(ScanFormat.jobAccessibilityLabel(list.jobs[0], status: nameless)
                == "Running, auditing, 127.0.0.1:8080, 418 of 2000 probes, 80 of 120 points audited, "
                + "3 issues: 1 high, 1 medium, 1 low")
        let absent = try ScanJobStatus(json: ScanPack.removing(Self.load("scan.status.json"), path: ["profile_name"]))
        #expect(ScanFormat.jobRowLine1(list.jobs[0], status: absent) == "Auditing · — · 127.0.0.1:8080")
        let bare = try ScanJobStatus(json: ScanPack.edited(
            ScanPack.edited(Self.load("scan.status.json"), path: ["profile_name"], to: ""), path: ["targets"], to: []))
        #expect(ScanFormat.jobRowLine1(list.jobs[0], status: bare) == "Auditing · — · —")
        #expect(ScanFormat.jobAccessibilityLabel(list.jobs[0], status: bare)
                == "Running, auditing, 418 of 2000 probes, 80 of 120 points audited, 3 issues: 1 high, 1 medium, 1 low")
    }

    /// P4: the Site map tab picks the newest job once, the first time there is one;
    /// after that the operator's choice (a job or All jobs) stands.
    @Test func theSitemapJobIsSeededOnce() throws {
        var model = ScanSurfaceModel()
        model.seedSitemapJobIfNeeded()
        #expect(model.sitemapJob == nil, "nothing to seed from")
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        model.seedSitemapJobIfNeeded()
        #expect(model.sitemapJob == "scan-1a2b3c4d")
        model.seedSitemapJobIfNeeded()
        #expect(model.sitemapJob == "scan-1a2b3c4d")

        // All jobs, chosen by the operator, is not re-seeded.
        model.sitemapJob = nil
        model.seedSitemapJobIfNeeded()
        #expect(model.sitemapJob == nil)

        // A chosen job is never overridden.
        var chosen = ScanSurfaceModel()
        chosen.sitemapJob = "scan-55667788"
        chosen.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        chosen.seedSitemapJobIfNeeded()
        #expect(chosen.sitemapJob == "scan-55667788")

        // A job this app started seeds it too.
        var started = ScanSurfaceModel()
        started.applyStart(try ScanStartResult(json: Self.load("scan.start.json")))
        started.seedSitemapJobIfNeeded()
        #expect(started.sitemapJob == "scan-1a2b3c4d")
    }
}

// MARK: - Tester — stage 6 fix round edges

/// Tester — the edges of the panel round 1 fixes (Review log S4, S5, S6, P1, P4,
/// Q1, Q9). Each test pins a literal the fix decides; with that fix reverted the
/// test fails (a `profile_name` key, an accepted `../x`, a stranger's `seq`
/// kept, a launch error wiped by a list read, a re-seeded Site map job, a PoC
/// matched by prefix).
extension ScanSurfaceTests {
    /// S5: the name rule at its boundaries — the 64th scalar is the last allowed,
    /// a leading `.` / `-` is refused but a trailing one is not, and nothing
    /// outside ASCII (accented or full-width letters, combining marks, zero-width
    /// or NUL scalars) passes however many scalars it has.
    @Test func profileNameRuleAtItsBoundaries() {
        let sixtyThree = String(repeating: "a", count: 63)
        #expect(ScanSurface.isValidProfileName(sixtyThree + "z"))
        #expect(!ScanSurface.isValidProfileName(sixtyThree + "Z"), "uppercase is refused")
        #expect(ScanSurface.isValidProfileName(sixtyThree + "."))
        #expect(ScanSurface.isValidProfileName(sixtyThree + "-"))
        #expect(ScanSurface.isValidProfileName(sixtyThree + "_"))
        #expect(!ScanSurface.isValidProfileName(sixtyThree + "ab"), "65 scalars")
        #expect(!ScanSurface.isValidProfileName(sixtyThree + "é"), "64 scalars, one outside ASCII")
        #expect(!ScanSurface.isValidProfileName(sixtyThree + " "))

        // A trailing `.` or `-` is allowed; a leading one is not, nor is a dot-only name.
        #expect(ScanSurface.isValidProfileName("api."))
        #expect(ScanSurface.isValidProfileName("api.."))
        #expect(ScanSurface.isValidProfileName("api-"))
        #expect(!ScanSurface.isValidProfileName("_api"), "a name starts with a letter or digit")
        #expect(ScanSurface.isValidProfileName("0"))
        #expect(ScanSurface.isValidProfileName("9-lives"))
        #expect(ScanSurface.isValidProfileName("a..b"), "two dots inside a name are not a path segment")
        #expect(!ScanSurface.isValidProfileName("."))
        #expect(!ScanSurface.isValidProfileName(".."))
        #expect(!ScanSurface.isValidProfileName("..."))
        #expect(!ScanSurface.isValidProfileName("-"))
        #expect(!ScanSurface.isValidProfileName("--help"))
        #expect(!ScanSurface.isValidProfileName("./api"))
        #expect(!ScanSurface.isValidProfileName("..\\api"))

        // Letters outside ASCII, in any form.
        #expect(!ScanSurface.isValidProfileName("Ünïcode"))
        #expect(!ScanSurface.isValidProfileName("naïve"))
        #expect(!ScanSurface.isValidProfileName("e\u{301}"), "a combining acute on a plain e")
        #expect(!ScanSurface.isValidProfileName("\u{FF41}pi"), "a full-width a")
        #expect(!ScanSurface.isValidProfileName("a\u{200B}pi"), "a zero-width space")
        #expect(!ScanSurface.isValidProfileName("api\u{0}"))
        #expect(!ScanSurface.isValidProfileName("\u{0}"))
        #expect(!ScanSurface.isValidProfileName("api🔒"))
        #expect(!ScanSurface.isValidProfileName("ａｐｉ"))
        #expect(!ScanSurface.isValidProfileName("ᴀpi"), "a small-capital a")
        #expect(!ScanSurface.isValidProfileName("ap\u{2024}"), "a one-dot leader is not a `.`")
        #expect(!ScanSurface.isValidProfileName("ap\u{2010}i"), "a Unicode hyphen is not a `-`")

        // Whitespace anywhere: the view trims, the Kit never does.
        #expect(!ScanSurface.isValidProfileName(" api"))
        #expect(!ScanSurface.isValidProfileName("api "))
        #expect(!ScanSurface.isValidProfileName("\u{A0}api"), "a no-break space")
        #expect(!ScanSurface.isValidProfileName("api\r"))
        #expect(!ScanSurface.isValidProfileName("\n"))

        // Separators and shell / URL punctuation.
        let punctuated = [
            "a/b", "/api", "api/", "a\\b", "a:b", "a;b", "a|b", "a&b", "a$b", "a*b", "a?b", "a#b", "a%b", "a@b",
            "a=b", "a+b", "a,b", "a'b", "a\"b", "a`b", "a~b", "a!b", "a(b)", "a[b]", "a{b}", "a<b>", "a^b",
        ]
        for bad in punctuated {
            #expect(!ScanSurface.isValidProfileName(bad), "\(bad)")
        }
        // The names the core ships all pass.
        for good in ["passive-only", "map-only", "light-http", "standard", "thorough", "l4-stream-safe", "l4-full"] {
            #expect(ScanSurface.isValidProfileName(good), "\(good)")
        }
    }

    /// Q1: a ref matches a whole file name, never a prefix, a suffix or a
    /// substring of one; a directory in the ref must land on a `/` boundary; the
    /// first listed match wins; a ref of whitespace matches nothing.
    @Test func pocRefMatchesWholeFileNamesOnly() throws {
        let paths = [
            "/x/pocs/poc-3b1c-extra.poc.yaml", "/x/pocs/poc-3b1c2.poc.yaml", "/x/pocs/poc-3b1c.poc.yaml",
            "/x/pocs/poc-3b1c.poc.yaml.bak",
        ]
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c", in: paths) == 2, "a ref that is a prefix of two other names picks its own")
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c.poc.yaml", in: paths) == 2)
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c2", in: paths) == 1)
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c-extra", in: paths) == 0)
        #expect(ScanFindingLink.match(pocRef: "3b1c.poc.yaml", in: paths) == nil, "a suffix of a file name is not a match")
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c.poc", in: paths) == nil, "a prefix of a file name is not a match")
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c.poc.yaml.bak", in: paths) == 3)
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c", in: ["/x/pocs/poc-3b1c.yaml"]) == nil, "another extension")
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c", in: ["/x/pocs/POC-3B1C.poc.yaml"]) == nil, "case matters")
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c", in: ["/x/pocs/poc-3b1c/"]) == nil, "a directory named like the ref")
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c/", in: paths) == nil)

        // A directory in the ref must sit on a `/` boundary and names the file exactly.
        #expect(ScanFindingLink.match(pocRef: "pocs/poc-3b1c", in: ["/x/mypocs/poc-3b1c", "/x/pocs/poc-3b1c"]) == 1)
        #expect(ScanFindingLink.match(pocRef: "pocs/poc-3b1c", in: ["/x/pocs/poc-3b1c.poc.yaml"]) == nil,
                "a directory ref does not take the extension")
        #expect(ScanFindingLink.match(pocRef: "x/pocs/poc-3b1c.poc.yaml", in: paths) == 2)

        // The first listed match wins when two directories hold the same file name.
        #expect(ScanFindingLink.match(pocRef: "p", in: ["/a/p.poc.yaml", "/b/p.poc.yaml"]) == 0)
        #expect(ScanFindingLink.match(pocRef: "p", in: ["/a/q.poc.yaml", "/b/p.poc.yaml", "/c/p"]) == 1)

        // Whitespace is not empty, and matches nothing; an empty path entry matches nothing.
        #expect(ScanFindingLink.match(pocRef: " ", in: paths) == nil)
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c", in: ["", "poc-3b1c.poc.yaml"]) == 1)
        #expect(ScanFindingLink.match(pocRef: "poc-3b1c", in: [""]) == nil)

        // The pack's own issues resolve against a findings list: the one with a PoC, the one without.
        let issues = try ScanIssuesResult(json: Self.load("scan.issues.json")).issues
        #expect(issues[0].pocRef == "poc-3b1c")
        #expect(ScanFindingLink.match(pocRef: issues[0].pocRef, in: ["/x/other.poc.yaml", "/x/poc-3b1c.poc.yaml"]) == 1)
        #expect(issues[1].pocRef == nil)
        #expect(ScanFindingLink.match(pocRef: issues[1].pocRef, in: ["/x/poc-3b1c.poc.yaml"]) == nil, "an issue without a PoC")
    }

    /// S6: after a prune, a line for the pruned stranger is again a list request
    /// only; a kept job's `seq` survives the prune so its replays stay ignored; a
    /// job this app started and the list omits keeps its status, notices and `seq`;
    /// a stranger's issue or terminal line raises no issues flag; an empty model
    /// treats every line as a list request and keeps nothing.
    @Test func prunedJobsForgetTheirSeqAndLocalJobsKeepTheirs() throws {
        var model = try Self.listed()
        model.applyStatus(try ScanJobStatus(json: Self.load("scan.status.json")))
        let strangerStatus = try ScanJobStatus(json: ScanPack.edited(Self.load("scan.status.json"), path: ["job"], to: "scan-elsewhere"))
        model.applyStatus(strangerStatus)
        let progress = try Self.load("job.progress.json")
        let strangerLine = ScanPack.edited(
            ScanPack.edited(progress, path: ["job"], to: "scan-elsewhere"), path: ["status", "job"], to: "scan-elsewhere")
        let acceptedStranger = model.noteJobEvent(strangerLine)
        #expect(acceptedStranger, "a stranger with a status read is known")
        #expect(model.lastSeq["scan-elsewhere"] == 3)
        let acceptedKnown = model.noteJobEvent(progress)
        #expect(acceptedKnown)
        model.clearRefreshFlags()

        // The list omits the stranger: its tables go, the listed job's stay.
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        #expect(model.statuses["scan-elsewhere"] == nil)
        #expect(model.lastSeq["scan-elsewhere"] == nil)
        #expect(model.statuses["scan-1a2b3c4d"]?.probes.sent == 418)
        #expect(model.lastSeq["scan-1a2b3c4d"] == 3)

        // The stranger's next line, a higher seq even, is a list request only: no seq, no flag.
        let laterStranger = ScanPack.edited(strangerLine, path: ["seq"], to: 9)
        let acceptedLater = model.noteJobEvent(laterStranger)
        #expect(acceptedLater)
        #expect(model.listRefreshNeeded)
        #expect(model.refreshNeeded.isEmpty)
        #expect(model.lastSeq["scan-elsewhere"] == nil)
        #expect(Set(model.lastSeq.keys) == ["scan-1a2b3c4d"])
        model.clearRefreshFlags()

        // The kept job's seq survived the prune: a replay of seq 3 is still ignored; seq 4 lands.
        let replay = model.noteJobEvent(progress)
        #expect(!replay)
        #expect(model.refreshNeeded.isEmpty)
        let next = model.noteJobEvent(ScanPack.edited(progress, path: ["seq"], to: 4))
        #expect(next)
        #expect(model.lastSeq["scan-1a2b3c4d"] == 4)
        model.clearRefreshFlags()

        // A job this app started that the list omits: status, notices and seq all stay.
        var start = try Self.load("scan.start.json")
        start = ScanPack.edited(start, path: ["job"], to: "scan-local")
        start = ScanPack.edited(start, path: ["status", "job"], to: "scan-local")
        model.applyStart(try ScanStartResult(json: start))
        let localLine = ScanPack.edited(
            ScanPack.edited(progress, path: ["job"], to: "scan-local"), path: ["status", "job"], to: "scan-local")
        let acceptedLocal = model.noteJobEvent(localLine)
        #expect(acceptedLocal)
        #expect(model.lastSeq["scan-local"] == 3)
        model.clearRefreshFlags()
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        #expect(model.jobs.map(\.job) == ["scan-local", "scan-1a2b3c4d", "scan-55667788"])
        #expect(model.statuses["scan-local"]?.state == .queued)
        #expect(model.launchNotices["scan-local"]
                == ["Clamped budget.probes 50000 → 20000", "Skipped ws: lane not available on this build"])
        #expect(model.lastSeq["scan-local"] == 3)
        let localReplay = model.noteJobEvent(localLine)
        #expect(!localReplay, "its seq survived the prune")
        #expect(model.refreshNeeded.isEmpty)
        #expect(!model.listRefreshNeeded)

        // The same list twice changes nothing.
        var twice = model
        twice.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        #expect(twice == model)

        // A stranger's issue or terminal line is a list request only: the issues flag is not raised for it.
        var fresh = try Self.listed()
        let strangerIssue = ScanPack.edited(try Self.load("job.issue.json"), path: ["job"], to: "scan-elsewhere")
        let acceptedIssue = fresh.noteJobEvent(strangerIssue)
        #expect(acceptedIssue)
        #expect(fresh.listRefreshNeeded)
        #expect(!fresh.issuesRefreshNeeded)
        #expect(fresh.lastSeq.isEmpty)
        #expect(fresh.refreshNeeded.isEmpty)
        let strangerDone = ScanPack.edited(try Self.load("job.finished.json"), path: ["job"], to: "scan-elsewhere")
        let acceptedDone = fresh.noteJobEvent(strangerDone)
        #expect(acceptedDone)
        #expect(!fresh.issuesRefreshNeeded)
        #expect(fresh.issues.isEmpty)

        // An empty model knows no job: every line is a list request, the tables stay empty.
        var empty = ScanSurfaceModel()
        let files = [
            "job.started.json", "job.phase.json", "job.progress.json", "job.issue.json", "job.finished.json",
            "job.cancelled.json", "job.failed.json",
        ]
        for file in files {
            let accepted = empty.noteJobEvent(try Self.load(file))
            #expect(accepted, "\(file)")
        }
        #expect(empty.lastSeq.isEmpty)
        #expect(empty.refreshNeeded.isEmpty)
        #expect(empty.statuses.isEmpty)
        #expect(empty.jobs.isEmpty)
        #expect(empty.listRefreshNeeded)
        #expect(!empty.issuesRefreshNeeded)
    }

    /// P1: the kept launch error survives every read that is not a launch step
    /// (lists, statuses, issues, profiles, checks, site map, selections, pushes,
    /// tab changes, an edit) and goes only with a start, a confirm request or a
    /// profile pick — the same profile or none included.
    @Test func aLaunchErrorSurvivesEveryNonLaunchRead() throws {
        var model = try Self.listed()
        model.select(profile: "standard")
        let error = ScanLaunchError(busMessage: "scan: lane_unavailable: ws not built", origins: [])
        model.applyLaunchError(error)
        #expect(model.launchError == error)

        model.applyIssues(try ScanIssuesResult(json: Self.load("scan.issues.json")), append: false)
        model.applyIssue(try ScanIssue(json: Self.load("scan.issue.json")))
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        model.applyStatus(try ScanJobStatus(json: Self.load("scan.status.json")))
        model.applyProfiles(try ScanProfileListResult(json: Self.load("scan.profile.list.json")))
        model.applyProfile(try Self.standardProfile())
        model.applyChecks(try ScanChecksResult(json: Self.load("scan.checks.json")))
        model.applySitemap(try ScanSitemapResult(json: Self.load("scan.sitemap.json")), append: false)
        model.select(job: "scan-1a2b3c4d")
        model.select(issue: "issue-9f8e7d6c")
        model.select(node: "node-1")
        let pushed = model.noteJobEvent(try Self.load("job.progress.json"))
        #expect(pushed)
        model.clearRefreshFlags()
        model.tab = .issues
        model.moveSelection(in: .jobs, by: 1)
        model.editedProfile?.budget.probes = 10
        model.seedSitemapJobIfNeeded()
        #expect(model.launchError == error)
        #expect(model.launchError?.code == "lane_unavailable")
        #expect(model.statusLine == "ws not built")

        // Re-picking the same profile clears it; so does picking none.
        model.select(profile: "standard")
        #expect(model.launchError == nil)
        #expect(model.statusLine == nil)
        model.applyLaunchError(error)
        #expect(model.launchError == error)
        model.select(profile: nil)
        #expect(model.launchError == nil)
        #expect(model.statusLine == nil)

        // A confirm request clears it; an error while the sheet is up closes the sheet and is kept whole.
        model.applyLaunchError(error)
        let request = try #require(L4ConfirmRequest(json: [
            "structuredContent": ["status": "needs_confirmation", "prompt": "Really?", "confirm_token": "t"],
        ]))
        model.applyConfirm(tool: "scan.start", args: ["profile": "x"], request: request)
        #expect(model.launchError == nil)
        #expect(model.confirm != nil)
        let busy = ScanLaunchError(busMessage: "scan: busy: already", origins: [])
        model.applyLaunchError(busy)
        #expect(model.confirm == nil)
        #expect(model.launchError == busy)
        #expect(model.launchError?.message == "already")
        #expect(model.statusLine == "A scan on this origin is already running")
        #expect(!model.launchInFlight)
    }

    /// P4: the seed happens once. An operator's "All jobs" after it survives a new
    /// job and a new list; a chosen job survives the list changing; "All jobs"
    /// chosen before the first job is overtaken by the first seed (the model
    /// cannot tell it from never having chosen), which is the documented rule.
    @Test func theSitemapSeedNeverOverridesALaterChoice() throws {
        var model = try Self.listed()
        model.seedSitemapJobIfNeeded()
        #expect(model.sitemapJob == "scan-1a2b3c4d")

        // The operator picks All jobs; a new job lands in front; the view seeds again on every list change.
        model.sitemapJob = nil
        var start = try Self.load("scan.start.json")
        start = ScanPack.edited(start, path: ["job"], to: "scan-new")
        start = ScanPack.edited(start, path: ["status", "job"], to: "scan-new")
        model.applyStart(try ScanStartResult(json: start))
        #expect(model.jobs.first?.job == "scan-new")
        model.seedSitemapJobIfNeeded()
        #expect(model.sitemapJob == nil, "All jobs stands after the first seed")
        model.applyList(try ScanListResult(json: ["jobs": []]))
        model.seedSitemapJobIfNeeded()
        #expect(model.sitemapJob == nil)
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        model.seedSitemapJobIfNeeded()
        #expect(model.sitemapJob == nil)

        // A chosen job survives the list dropping and re-adding jobs.
        model.sitemapJob = "scan-55667788"
        model.applyList(try ScanListResult(json: ["jobs": []]))
        model.seedSitemapJobIfNeeded()
        #expect(model.sitemapJob == "scan-55667788")
        model.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        model.seedSitemapJobIfNeeded()
        #expect(model.sitemapJob == "scan-55667788")

        // Before the first seed, All jobs is indistinguishable from no choice: the first job seeds.
        var early = ScanSurfaceModel()
        early.sitemapJob = nil
        early.seedSitemapJobIfNeeded()
        #expect(early.sitemapJob == nil)
        early.applyList(try ScanListResult(json: Self.load("scan.list.json")))
        early.seedSitemapJobIfNeeded()
        #expect(early.sitemapJob == "scan-1a2b3c4d")

        // The seed takes the list's first row, whatever its state.
        var doneFirst = ScanSurfaceModel()
        let list = try Self.load("scan.list.json")
        let rows = try #require(list["jobs"]?.arrayValue)
        let reversed = ScanPack.edited(list, path: ["jobs"], to: .array(Array(rows.reversed())))
        doneFirst.applyList(try ScanListResult(json: reversed))
        doneFirst.seedSitemapJobIfNeeded()
        #expect(doneFirst.sitemapJob == "scan-55667788")
    }

    /// S4: with no profile the launch has nothing to send and the gate refuses; the
    /// confirmed retry carries the very `profile` object plus the token, and
    /// still no `profile_name`.
    @Test func launchArgumentsCarryTheProfileThroughTheConfirmRetry() throws {
        var model = ScanSurfaceModel()
        #expect(model.launchArguments(map: false).args.isEmpty)
        #expect(model.launchArguments(map: true).args.isEmpty)
        #expect(model.launchArguments(map: false).tool == "scan.start")
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == "Choose a profile.")

        var profile = try Self.standardProfile()
        profile.target.origins = ["http://api.shop-staging.test"]
        model.applyProfile(profile)
        #expect(model.launchRefusal(scopeHosts: Self.scope, tools: Self.toolsWithStart) == nil)
        let launch = model.launchArguments(map: false)
        #expect(launch.args.keys.sorted() == ["profile"])
        let request = try #require(L4ConfirmRequest(json: [
            "structuredContent": ["status": "needs_confirmation", "prompt": "Really?", "confirm_token": "tok-1"],
        ]))
        model.applyConfirm(tool: launch.tool, args: launch.args, request: request)
        let confirm = try #require(model.confirm)
        #expect(confirm.tool == "scan.start")
        #expect(confirm.arguments == launch.args)
        let confirmed = confirm.confirmedArguments
        #expect(confirmed.keys.sorted() == ["_confirm", "profile"])
        #expect(confirmed["profile"] == profile.json())
        #expect(confirmed["_confirm"] == "tok-1")
        #expect(confirmed["profile_name"] == nil)
        // The profile sent is the object the gate checked: the edited origins, not the core's copy.
        #expect(confirmed["profile"]?["target"]?["origins"] == JSONValue.array(["http://api.shop-staging.test"]))
        #expect(confirmed["profile"]?["name"] == "standard")

        // A map launch of the same profile sends the same object to `scan.map`.
        let map = model.launchArguments(map: true)
        #expect(map.tool == "scan.map")
        #expect(map.args == launch.args)
    }

    /// Q9 / Q10: a custom profile the operator saved with every lane unticked
    /// (the editor allows it; only the launch gate refuses it) lists with no lane
    /// word. Its row line and its VoiceOver label must not open on a separator.
    /// Tester finding T-F1: `profileRowLine2` joins an empty lane list as `""`,
    /// so the line reads ` · medium · normal` and the label `no-lanes,  · medium · normal`.
    @Test func aProfileWithNoLanesReadsCleanly() throws {
        let entry = try ScanProfileListEntry(json: [
            "name": "no-lanes", "builtin": false,
            "summary": ["lanes": [], "intensity": "medium", "speed": "normal"],
        ])
        #expect(entry.lanes.isEmpty)
        let line = ScanFormat.profileRowLine2(entry)
        #expect(!line.hasPrefix(" · "), "row line 2 opens on a separator: \(line.debugDescription)")
        #expect(line == "no lanes · medium · normal")
        let label = ScanFormat.profileAccessibilityLabel(entry)
        #expect(!label.contains(",  · "), "VoiceOver label carries an empty lane slot: \(label.debugDescription)")
        #expect(label == "no-lanes, no lanes · medium · normal")
    }
}

// MARK: - Stage 6 fix round 2

extension ScanSurfaceTests {
    /// QR2-1: the footer has one status line. A line the app writes (`Saved x`, the
    /// delete line, a refusal) replaces a kept launch error rather than hiding
    /// behind it; a profile pick clears both; `nil` takes both down.
    @Test func aStatusLineReplacesTheLaunchError() throws {
        var model = try Self.listed()
        model.select(profile: "standard")
        let error = ScanLaunchError(busMessage: "scan: lane_unavailable: ws not built", origins: [])
        model.applyLaunchError(error)
        #expect(model.launchError == error)
        #expect(model.statusLine == "ws not built")

        model.setStatusLine("Saved x")
        #expect(model.launchError == nil, "a new status line retires the launch error")
        #expect(model.statusLine == "Saved x")

        model.applyLaunchError(error)
        #expect(model.statusLine == "ws not built")
        model.select(profile: "thorough")
        #expect(model.launchError == nil)
        #expect(model.statusLine == nil)

        model.applyLaunchError(error)
        model.setStatusLine(nil)
        #expect(model.launchError == nil)
        #expect(model.statusLine == nil)

        // The error after a line: the error is the line again, whole.
        model.setStatusLine(scanNothingToDeleteText(name: "my-api"))
        model.applyLaunchError(error)
        #expect(model.launchError?.code == "lane_unavailable")
        #expect(model.statusLine == "ws not built")
    }

    /// SR2: a duplicate's name collides with a listed one case-insensitively, so a
    /// case-folding store cannot be made to overwrite a builtin or a saved profile.
    @Test func profileNameCollisionIsCaseInsensitive() throws {
        #expect(ScanSurface.profileNameCollides("My-API", with: ["my-api"]))
        #expect(ScanSurface.profileNameCollides("my-api", with: ["My-API"]))
        #expect(ScanSurface.profileNameCollides("STANDARD", with: ["passive-only", "standard"]))
        #expect(ScanSurface.profileNameCollides("standard", with: ["standard"]))
        #expect(!ScanSurface.profileNameCollides("my-api", with: ["standard", "thorough"]))
        #expect(!ScanSurface.profileNameCollides("my-api2", with: ["my-api"]), "a longer name is not the same name")
        #expect(!ScanSurface.profileNameCollides("my-ap", with: ["my-api"]), "nor a shorter one")
        #expect(!ScanSurface.profileNameCollides("my-api", with: []))
        #expect(!ScanSurface.profileNameCollides("", with: ["my-api"]))
        let listed = try ScanProfileListResult(json: Self.load("scan.profile.list.json")).profiles.map(\.name)
        #expect(ScanSurface.profileNameCollides("Standard", with: listed))
        #expect(!ScanSurface.profileNameCollides("standard-2", with: listed))
    }
}
