import AitmBusClient
import Foundation

// The Scan surface's state (scanner v2 T9, spec D4–D9, D12, D13, D15): the
// launch gate, the `_confirm` handshake, push-as-trigger, grouping and every
// string the views render. Pure value types, no SwiftUI, no async; the app's
// `ScanPanelState` holds a `ScanSurfaceModel` and drives it. The wire types it
// stores are `ScanModel.swift`'s.

/// The L4 lanes' launch hint (parent spec; D12), verbatim.
public let scanL4Hint = "The L4 lanes need an L4 scope entry with interface *, direction outbound, "
    + "the target CIDR and port range and the Inject capability."

/// The Profiles footer's idle status line (D4).
public let scanIdleText = "Opening this page never scans. Start Scan sends probes to the origins above."

// MARK: - Offering

/// Which Scan page the bus can back: the four-surface model needs `scan.start`;
/// the legacy one-shot form needs `scan.discover`. Both are feature-detected from
/// `tools/list`, never assumed.
public enum ScanSurface {
    public static let startTool = "scan.start"

    public enum Mode: Equatable, Sendable { case surface, legacy, unavailable }

    public static func has(_ tool: String, in tools: [ToolDescriptor]) -> Bool {
        tools.contains { $0.name == tool }
    }

    /// The surface is offered when the bus lists `scan.start`.
    public static func isOffered(in tools: [ToolDescriptor]) -> Bool { has(startTool, in: tools) }

    /// The legacy form is offered when the bus lists `scan.discover` and not `scan.start`.
    public static func legacyOffered(in tools: [ToolDescriptor]) -> Bool {
        has(ScanForm.toolName, in: tools) && !isOffered(in: tools)
    }

    public static func mode(for tools: [ToolDescriptor]) -> Mode {
        if isOffered(in: tools) { return .surface }
        if legacyOffered(in: tools) { return .legacy }
        return .unavailable
    }
}

/// The four tabs under the page header (D2).
public enum ScanTab: String, CaseIterable, Hashable, Sendable, CustomStringConvertible {
    case profiles, jobs, sitemap, issues

    public var description: String {
        switch self {
        case .profiles: "Profiles"
        case .jobs: "Jobs"
        case .sitemap: "Site map"
        case .issues: "Issues"
        }
    }
}

// MARK: - Issues filters and groups

/// The Issues tab's filters (D7): the `scan.issues` parameters, and the same
/// predicate applied locally so a loaded page filters without a round trip.
public struct ScanIssueFilters: Hashable, Sendable {
    public var job: String?
    public var severityMin: ScanSeverity?
    public var confidenceMin: ScanConfidence?
    public var lane: ScanLane?
    public var klass: String?
    public var status: ScanIssueStatus?

    public init(job: String? = nil, severityMin: ScanSeverity? = nil, confidenceMin: ScanConfidence? = nil,
                lane: ScanLane? = nil, klass: String? = nil, status: ScanIssueStatus? = nil) {
        self.job = job
        self.severityMin = severityMin
        self.confidenceMin = confidenceMin
        self.lane = lane
        self.klass = klass
        self.status = status
    }

    /// Only the set filters, under the verb's parameter names.
    public func arguments() -> [String: JSONValue] {
        var args: [String: JSONValue] = [:]
        if let job { args["job"] = .string(job) }
        if let severityMin { args["severity_min"] = .string(severityMin.rawValue) }
        if let confidenceMin { args["confidence_min"] = .string(confidenceMin.rawValue) }
        if let lane { args["lane"] = .string(lane.rawValue) }
        if let klass { args["class"] = .string(klass) }
        if let status { args["status"] = .string(status.rawValue) }
        return args
    }

    /// Severity is ranked critical first, so "at least high" is `rank <= high.rank`;
    /// confidence is ranked tentative first, so "at least firm" is `rank >= firm.rank`.
    public func matches(_ issue: ScanIssueSummary) -> Bool {
        if let job, issue.job != job { return false }
        if let severityMin, issue.severity.rank > severityMin.rank { return false }
        if let confidenceMin, issue.confidence.rank < confidenceMin.rank { return false }
        if let lane, issue.lane != lane { return false }
        if let klass, issue.klass != klass { return false }
        if let status, issue.status != status { return false }
        return true
    }
}

/// One severity section of the Issues list (D7); the header is `"HIGH 1"`.
public struct ScanIssueSection: Hashable, Sendable {
    public var severity: ScanSeverity
    public var issues: [ScanIssueSummary]

    public init(severity: ScanSeverity, issues: [ScanIssueSummary]) {
        self.severity = severity
        self.issues = issues
    }

    public var title: String { "\(severity.word.uppercased()) \(issues.count)" }
}

/// One `scheme://host:port` disclosure group of the Site map tree (D6).
public struct ScanOriginGroup: Hashable, Sendable {
    public var origin: String
    public var nodes: [ScanSiteNode]

    public init(origin: String, nodes: [ScanSiteNode]) {
        self.origin = origin
        self.nodes = nodes
    }
}

/// One slice of the stacked severity bar (D5): its share of the total.
public struct ScanSeveritySegment: Hashable, Sendable {
    public var severity: ScanSeverity
    public var count: Int
    public var fraction: Double

    public init(severity: ScanSeverity, count: Int, fraction: Double) {
        self.severity = severity
        self.count = count
        self.fraction = fraction
    }
}

// MARK: - Launch handshake (D9)

/// A `needs_confirmation` answer to `scan.start` / `scan.map`: the sheet shows
/// `request.prompt` verbatim and Start Scan re-sends the identical arguments plus
/// `_confirm: token`. `L4ConfirmRequest(json:)` is the parser.
public struct ScanConfirm: Hashable, Sendable {
    public var tool: String
    public var arguments: [String: JSONValue]
    public var request: L4ConfirmRequest

    public init(tool: String, arguments: [String: JSONValue], request: L4ConfirmRequest) {
        self.tool = tool
        self.arguments = arguments
        self.request = request
    }

    /// The original arguments plus the token; nothing else changes.
    public var confirmedArguments: [String: JSONValue] {
        var args = arguments
        args["_confirm"] = .string(request.token)
        return args
    }
}

/// A thrown launch error, read as `scan: <code>: <message>` when the engine
/// shaped it so. `busy` and `out_of_scope` get the app's own words (D12).
public struct ScanLaunchError: Hashable, Sendable {
    public var code: String?
    public var message: String
    /// The origins the refused launch named; `out_of_scope` reads its authority from the first.
    public var origins: [String]

    public init(code: String?, message: String, origins: [String] = []) {
        self.code = code
        self.message = message
        self.origins = origins
    }

    public init(busMessage: String, origins: [String]) {
        self.origins = origins
        let prefix = "scan: "
        if busMessage.hasPrefix(prefix) {
            let rest = busMessage.dropFirst(prefix.count)
            if let separator = rest.range(of: ": ") {
                let code = rest[..<separator.lowerBound]
                if !code.isEmpty, !code.contains(" ") {
                    self.code = String(code)
                    self.message = String(rest[separator.upperBound...])
                    return
                }
            }
        }
        self.code = nil
        self.message = busMessage
    }

    /// What the status line shows.
    public var display: String {
        switch code {
        case "busy":
            return "A scan on this origin is already running"
        case "out_of_scope":
            guard let first = origins.first else { return message }
            return "Out of scope — add \(ScanFormat.hostOf(origin: first)) to scope to scan it"
        default:
            return message
        }
    }
}

// MARK: - Check tree (D4)

/// The Checks disclosure tree: `scan.checks` grouped by lane then class, with the
/// profile's tri-state per leaf. `checks.include` / `checks.exclude` are the only
/// state; `default` means in neither list.
public struct ScanCheckTree: Hashable, Sendable {
    public enum Choice: String, Hashable, Sendable, CaseIterable {
        case `default`, include, exclude
    }

    public struct Leaf: Hashable, Sendable {
        public var meta: ScanCheckMeta
        public var choice: Choice
        /// Above the profile's intensity: rendered tertiary, never run.
        public var aboveIntensity: Bool

        public init(meta: ScanCheckMeta, choice: Choice, aboveIntensity: Bool) {
            self.meta = meta
            self.choice = choice
            self.aboveIntensity = aboveIntensity
        }
    }

    public struct Group: Hashable, Sendable {
        public var lane: ScanLane
        public var klass: String
        public var leaves: [Leaf]

        public init(lane: ScanLane, klass: String, leaves: [Leaf]) {
            self.lane = lane
            self.klass = klass
            self.leaves = leaves
        }
    }

    public var groups: [Group]

    /// `query` matches id, name or class, case-insensitively; blank keeps every check.
    public init(checks: [ScanCheckMeta], selection: ScanCheckSelection, intensity: ScanIntensity, query: String) {
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        var byGroup: [GroupKey: [Leaf]] = [:]
        for meta in checks {
            if !needle.isEmpty,
               !(meta.id.lowercased().contains(needle) || meta.name.lowercased().contains(needle)
                   || meta.klass.lowercased().contains(needle)) { continue }
            let choice: Choice = selection.include.contains(meta.id) ? .include
                : selection.exclude.contains(meta.id) ? .exclude : .default
            let leaf = Leaf(meta: meta, choice: choice, aboveIntensity: meta.intensity.rank > intensity.rank)
            for lane in meta.lanes {
                byGroup[GroupKey(lane: lane, klass: meta.klass), default: []].append(leaf)
            }
        }
        groups = byGroup.keys.sorted().map { Group(lane: $0.lane, klass: $0.klass, leaves: byGroup[$0] ?? []) }
    }

    private struct GroupKey: Hashable, Comparable {
        var lane: ScanLane
        var klass: String

        static func < (lhs: GroupKey, rhs: GroupKey) -> Bool {
            let (l, r) = (laneOrder(lhs.lane), laneOrder(rhs.lane))
            if l != r { return l < r }
            if lhs.lane.rawValue != rhs.lane.rawValue { return lhs.lane.rawValue < rhs.lane.rawValue }
            return lhs.klass < rhs.klass
        }

        /// HTTP, WebSocket, L4 packet, L4 stream, then anything newer.
        private static func laneOrder(_ lane: ScanLane) -> Int {
            switch lane {
            case .http: 0
            case .ws: 1
            case .l4Packet: 2
            case .l4Stream: 3
            default: 4
            }
        }
    }

    /// Moves `id` into the chosen list and out of the other; `default` clears it from both.
    public static func set(_ choice: Choice, for id: String, in selection: inout ScanCheckSelection) {
        selection.include.removeAll { $0 == id }
        selection.exclude.removeAll { $0 == id }
        switch choice {
        case .include: selection.include.append(id)
        case .exclude: selection.exclude.append(id)
        case .default: break
        }
    }

    public static func setAll(_ choice: Choice, ids: [String], in selection: inout ScanCheckSelection) {
        for id in ids { set(choice, for: id, in: &selection) }
    }
}

// MARK: - The model (D8)

/// Everything the Scan page shows and the app drives: the tab, the lists and
/// selections of the four tabs, the filters, the pending launch, the confirm
/// request and the push flags. A push line is a trigger (`noteJobEvent` sets a
/// flag); every counter the surfaces show is a `scan.status` / `scan.list` value.
public struct ScanSurfaceModel: Equatable, Sendable {
    public var tab: ScanTab = .profiles

    // Profiles
    public var profiles: [ScanProfileListEntry] = []
    public var selectedProfile: String?
    /// The profile as `scan.profile.get` returned it.
    public var loadedProfile: ScanProfile?
    /// The profile as the editor holds it; a launch sends it whole once it differs from `loadedProfile`.
    public var editedProfile: ScanProfile?
    public var checks: [ScanCheckMeta] = []
    public var checkQuery = ""
    public var sessionPreview: ScanSessionProfile?
    /// Whether an L4 scope entry with Inject is known; nil when `l4.scope.list` is
    /// not listed or not yet read, in which case the L4 lanes are unavailable.
    public var l4InjectScopeKnown: Bool?
    public var profilesError: String?

    // Jobs
    public var jobs: [ScanJobSummary] = []
    public var statuses: [String: ScanJobStatus] = [:]
    public var selectedJob: String?
    /// Per job: the `clamped` and `lanes.skipped` notices of its `scan.start` result.
    public var launchNotices: [String: [String]] = [:]
    public var jobsError: String?

    // Site map
    public var sitemapJob: String?
    public var sitemap: ScanSitemapResult?
    public var selectedNode: String?
    public var sitemapQuery = ""

    // Issues
    public var filters = ScanIssueFilters()
    public var issues: [ScanIssueSummary] = []
    public var issuesCursor: String?
    /// The `by_severity` tally of the last `scan.issues` page.
    public var issuesBySeverity = BySeverity(critical: 0, high: 0, medium: 0, low: 0, info: 0)
    public var selectedIssue: String?
    public var issueDetail: ScanIssue?
    public var issuesError: String?

    // Launch
    public var launchInFlight = false
    public var confirm: ScanConfirm?
    /// The footer's status line: a refusal, the last launch error, or nil for `scanIdleText`.
    public var statusLine: String?

    // Push
    public var lastSeq: [String: UInt64] = [:]
    public var refreshNeeded: Set<String> = []
    public var listRefreshNeeded = false
    public var issuesRefreshNeeded = false

    public init() {}

    // MARK: Queries

    public var profileIsEdited: Bool { editedProfile != nil && editedProfile != loadedProfile }

    public var runningJobs: [ScanJobSummary] {
        jobs.filter { [.queued, .running, .cancelling].contains($0.state) }
    }

    public var openIssueCount: Int { issues.filter { $0.status == .open }.count }

    /// Running jobs when any (queue style), else open issues. Computed for the
    /// follow-on PR; the sidebar does not read it yet.
    public var sidebarCount: Int {
        let running = runningJobs.count
        return running > 0 ? running : openIssueCount
    }

    /// `"Jobs 2"`, `"Issues 7"`; no count when zero, never for Profiles / Site map.
    public func tabTitle(_ tab: ScanTab) -> String {
        let count: Int = switch tab {
        case .jobs: jobs.count
        case .issues: issues.count
        case .profiles, .sitemap: 0
        }
        return count > 0 ? "\(tab.description) \(count)" : tab.description
    }

    /// The one gate every launch passes: nil when the edited profile may be sent,
    /// else why not. Deny-by-default: an empty scope covers nothing, an L4 lane
    /// with no known Inject entry is unavailable.
    public func launchRefusal(scopeHosts: [String], tools: [ToolDescriptor]) -> String? {
        guard ScanSurface.isOffered(in: tools) else { return "scan.start is not on this bus" }
        guard let profile = editedProfile else { return "Choose a profile." }
        if profile.hasL4Lane, l4InjectScopeKnown != true { return scanL4Hint }
        let origins = profile.target.origins
        if origins.isEmpty, profile.target.l4Rows.isEmpty {
            // A profile with nothing to aim at never reaches the bus: an HTTP/WS profile
            // wants an origin; a pure-L4 one wants an L4 target in its `target.l4` list.
            return profile.lanes.contains(where: { !$0.isL4 })
                ? "Choose at least one in-scope origin."
                : "This profile has no L4 targets; add one to its target.l4 list."
        }
        for origin in origins {
            guard let authority = ScanForm.authority(of: origin), Scope.contains(authority, in: scopeHosts) else {
                return "Out of scope — add \(ScanFormat.hostOf(origin: origin)) to scope to scan it"
            }
        }
        return nil
    }

    /// What a launch sends: `scan.map` when `map`; the name alone for an unedited
    /// profile, the whole edited profile otherwise. The caller sends nothing while
    /// `launchRefusal` is non-nil.
    public func launchArguments(map: Bool) -> (tool: String, args: [String: JSONValue]) {
        let tool = map ? "scan.map" : ScanSurface.startTool
        guard let profile = editedProfile else { return (tool, [:]) }
        if profileIsEdited { return (tool, ["profile": profile.json()]) }
        return (tool, ["profile_name": .string(profile.name)])
    }

    /// The Issues list: `filters` applied, one section per severity in severity
    /// order, empty sections omitted.
    public func issuesGroupedBySeverity() -> [ScanIssueSection] {
        let visible = issues.filter(filters.matches)
        var order: [ScanSeverity] = []
        var grouped: [ScanSeverity: [ScanIssueSummary]] = [:]
        for issue in visible {
            if grouped[issue.severity] == nil { order.append(issue.severity) }
            grouped[issue.severity, default: []].append(issue)
        }
        return order
            .sorted { ($0.rank, $0.rawValue) < ($1.rank, $1.rawValue) }
            .map { ScanIssueSection(severity: $0, issues: grouped[$0] ?? []) }
    }

    /// The Site map tree: nodes by origin (origins sorted), filtered by `sitemapQuery` on host and path.
    public func sitemapGroupedByOrigin() -> [ScanOriginGroup] {
        let needle = sitemapQuery.trimmingCharacters(in: .whitespaces).lowercased()
        let nodes = (sitemap?.nodes ?? []).filter { node in
            needle.isEmpty || node.host.lowercased().contains(needle) || node.pathTemplate.lowercased().contains(needle)
        }
        var grouped: [String: [ScanSiteNode]] = [:]
        for node in nodes { grouped[node.origin, default: []].append(node) }
        return grouped.keys.sorted().map { ScanOriginGroup(origin: $0, nodes: grouped[$0] ?? []) }
    }

    /// The insertion points of one node.
    public func points(for node: String) -> [ScanInsertionPoint] {
        (sitemap?.points ?? []).filter { $0.siteNode == node }
    }

    /// The stacked bar's slices: zero counts omitted, `fraction` = count / total.
    public static func severityBarSegments(_ counts: BySeverity) -> [ScanSeveritySegment] {
        let total = counts.total
        guard total > 0 else { return [] }
        let order: [ScanSeverity] = [.critical, .high, .medium, .low, .info]
        return order.compactMap { severity in
            let count = counts.count(severity)
            guard count > 0 else { return nil }
            return ScanSeveritySegment(severity: severity, count: count, fraction: Double(count) / Double(total))
        }
    }

    // MARK: Mutations: profiles

    /// Builtins first (as listed), then custom profiles alphabetically (D4).
    public mutating func applyProfiles(_ result: ScanProfileListResult) {
        let builtins = result.profiles.filter(\.builtin)
        let custom = result.profiles.filter { !$0.builtin }.sorted { $0.name < $1.name }
        profiles = builtins + custom
        profilesError = nil
    }

    /// A `scan.profile.get` result: loaded and edited start equal; the profile is selected.
    public mutating func applyProfile(_ profile: ScanProfile) {
        loadedProfile = profile
        editedProfile = profile
        selectedProfile = profile.name
    }

    public mutating func applyChecks(_ result: ScanChecksResult) {
        checks = result.checks
    }

    // MARK: Mutations: jobs

    /// `scan.list`, newest first as delivered. A job this app started that the
    /// list does not carry yet stays in front of it.
    public mutating func applyList(_ result: ScanListResult) {
        let listed = Set(result.jobs.map(\.job))
        let pending = jobs.filter { !listed.contains($0.job) }
        jobs = pending + result.jobs
        jobsError = nil
    }

    /// `scan.status`: stored, and the matching list row takes its summary.
    public mutating func applyStatus(_ status: ScanJobStatus) {
        statuses[status.job] = status
        if let index = jobs.firstIndex(where: { $0.job == status.job }) {
            jobs[index] = status.summary
        }
    }

    /// A `scan.start` / `scan.map` result: the job goes first, is selected, and the
    /// Jobs tab opens; `clamped` and `lanes.skipped` become its notices.
    public mutating func applyStart(_ result: ScanStartResult) {
        statuses[result.job] = result.status
        if let index = jobs.firstIndex(where: { $0.job == result.job }) {
            jobs[index] = result.status.summary
        } else {
            jobs.insert(result.status.summary, at: 0)
        }
        launchNotices[result.job] = result.clamped.map { "Clamped \($0.field) \($0.requested) → \($0.applied)" }
            + result.lanes.skipped.map { "Skipped \($0.lane.rawValue): \($0.reason)" }
        selectedJob = result.job
        tab = .jobs
        confirm = nil
        statusLine = nil
        launchInFlight = false
    }

    /// A `needs_confirmation` answer: the sheet opens; nothing is sent until Start Scan.
    public mutating func applyConfirm(tool: String, args: [String: JSONValue], request: L4ConfirmRequest) {
        confirm = ScanConfirm(tool: tool, arguments: args, request: request)
        launchInFlight = false
    }

    public mutating func applyLaunchError(_ error: ScanLaunchError) {
        statusLine = error.display
        confirm = nil
        launchInFlight = false
    }

    // MARK: Mutations: issues and site map

    /// A `scan.issues` page; `append` for Load More (rows already listed are not repeated).
    public mutating func applyIssues(_ result: ScanIssuesResult, append: Bool) {
        if append {
            let known = Set(issues.map(\.id))
            issues += result.issues.filter { !known.contains($0.id) }
        } else {
            issues = result.issues
        }
        issuesCursor = result.nextCursor
        issuesBySeverity = result.bySeverity
        issuesError = nil
    }

    /// A `scan.issue` / `scan.issue.update` result: the detail, and the list row takes its summary.
    public mutating func applyIssue(_ issue: ScanIssue) {
        issueDetail = issue
        if let index = issues.firstIndex(where: { $0.id == issue.id }) {
            issues[index] = issue.summary
        }
    }

    /// A `scan.sitemap` page; `append` for Load More.
    public mutating func applySitemap(_ result: ScanSitemapResult, append: Bool) {
        guard append, let current = sitemap else {
            sitemap = result
            return
        }
        let knownNodes = Set(current.nodes.map(\.id))
        let knownPoints = Set(current.points.map(\.id))
        var merged = current
        merged.nodes += result.nodes.filter { !knownNodes.contains($0.id) }
        merged.points += result.points.filter { !knownPoints.contains($0.id) }
        merged.nextCursor = result.nextCursor
        sitemap = merged
    }

    // MARK: Push (D8)

    /// A `notifications/aitm/job` line. A trigger only: records `seq`, flags the
    /// job (and the list / issues as the event warrants) and returns true; false
    /// and no change for a non-scan kind, an unreadable line, or a `seq` at or
    /// below the last seen. Never touches `statuses`, `jobs` or `issues`.
    @discardableResult
    public mutating func noteJobEvent(_ params: JSONValue) -> Bool {
        guard let line = try? ScanJobNotification(json: params), line.kind == "scan" else { return false }
        if let last = lastSeq[line.job], line.seq <= last { return false }
        lastSeq[line.job] = line.seq
        refreshNeeded.insert(line.job)
        if line.event == .started || line.event.isTerminal { listRefreshNeeded = true }
        if line.event == .issue || line.event.isTerminal { issuesRefreshNeeded = true }
        return true
    }

    public mutating func clearRefreshFlags() {
        refreshNeeded = []
        listRefreshNeeded = false
        issuesRefreshNeeded = false
    }

    // MARK: Selection

    public mutating func select(job: String?) { selectedJob = job }

    public mutating func select(issue: String?) {
        selectedIssue = issue
        if issueDetail?.id != issue { issueDetail = nil }
    }

    public mutating func select(node: String?) { selectedNode = node }

    public mutating func select(profile: String?) { selectedProfile = profile }

    /// ↑↓ over the visible list of a tab, clamped at both ends; from no selection
    /// a step down lands on the first row and a step up on the last.
    public mutating func moveSelection(in tab: ScanTab, by delta: Int) {
        let ids: [String] = switch tab {
        case .profiles: profiles.map(\.name)
        case .jobs: jobs.map(\.job)
        case .sitemap: sitemapGroupedByOrigin().flatMap(\.nodes).map(\.id)
        case .issues: issuesGroupedBySeverity().flatMap(\.issues).map(\.id)
        }
        guard !ids.isEmpty else { return }
        let current: String? = switch tab {
        case .profiles: selectedProfile
        case .jobs: selectedJob
        case .sitemap: selectedNode
        case .issues: selectedIssue
        }
        let target: Int = if let current, let index = ids.firstIndex(of: current) {
            min(max(index + delta, 0), ids.count - 1)
        } else {
            delta >= 0 ? 0 : ids.count - 1
        }
        switch tab {
        case .profiles: select(profile: ids[target])
        case .jobs: select(job: ids[target])
        case .sitemap: select(node: ids[target])
        case .issues: select(issue: ids[target])
        }
    }
}

// MARK: - Words (D12, D13)

/// Every string the Scan views render, so a view carries no logic.
public enum ScanFormat {
    public static let noSessionText = "No session seen yet for this origin."

    /// `m:ss`, or `h:mm:ss` from an hour on.
    public static func elapsed(ms: Int) -> String {
        let total = max(0, ms) / 1000
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        let seconds = total % 60
        if hours > 0 { return String(format: "%d:%02d:%02d", hours, minutes, seconds) }
        return String(format: "%d:%02d", minutes, seconds)
    }

    /// `42 s ago` / `2 min ago` / `3 h ago`, from two epoch-millisecond stamps.
    public static func relative(ms: Int, now: Int) -> String {
        let seconds = max(0, now - ms) / 1000
        if seconds < 60 { return "\(seconds) s ago" }
        if seconds < 3600 { return "\(seconds / 60) min ago" }
        return "\(seconds / 3600) h ago"
    }

    public static func probesText(_ probes: ScanProbeCounters) -> String {
        "probes \(probes.sent) / \(probes.budget)"
    }

    public static func pointsText(_ points: ScanPointCounters) -> String {
        "points \(points.audited) / \(points.found) audited"
    }

    /// `host[:port]` of an origin, lower-cased; the origin itself when it is not an http(s) URL.
    public static func hostOf(origin: String) -> String {
        ScanForm.authority(of: origin) ?? origin
    }

    /// The state word, or the phase word while running.
    static func stateWord(_ summary: ScanJobSummary) -> String {
        summary.state == .running ? summary.phase.word : summary.state.word
    }

    static func hosts(_ status: ScanJobStatus?) -> String? {
        guard let targets = status?.targets, !targets.isEmpty else { return nil }
        return targets.map(hostOf(origin:)).joined(separator: ", ")
    }

    /// `Auditing · standard · 127.0.0.1:8080`; `—` for what `scan.status` has not told us yet.
    public static func jobRowLine1(_ summary: ScanJobSummary, status: ScanJobStatus?) -> String {
        [stateWord(summary), status?.profileName ?? "—", hosts(status) ?? "—"].joined(separator: " · ")
    }

    /// `probes 418 / 2000 · points 80 / 120 audited · 0:42`.
    public static func jobRowLine2(_ summary: ScanJobSummary) -> String {
        [probesText(summary.probes), pointsText(summary.points), elapsed(ms: summary.elapsedMs)].joined(separator: " · ")
    }

    /// The row's words for VoiceOver (D13); the severity bar hides behind it.
    public static func jobAccessibilityLabel(_ summary: ScanJobSummary, status: ScanJobStatus?) -> String {
        var parts = [summary.state.word, summary.phase.rawValue]
        if let name = status?.profileName { parts.append(name) }
        if let hosts = hosts(status) { parts.append(hosts) }
        parts.append("\(summary.probes.sent) of \(summary.probes.budget) probes")
        parts.append("\(summary.points.audited) of \(summary.points.found) points audited")
        parts.append(severityCountsInWords(summary.issues.bySeverity))
        return parts.joined(separator: ", ")
    }

    /// `3 issues: 1 high, 1 medium, 1 low` / `no issues`.
    public static func severityCountsInWords(_ counts: BySeverity) -> String {
        let total = counts.total
        guard total > 0 else { return "no issues" }
        let order: [ScanSeverity] = [.critical, .high, .medium, .low, .info]
        let parts = order.compactMap { severity -> String? in
            let count = counts.count(severity)
            return count > 0 ? "\(count) \(severity.rawValue)" : nil
        }
        return "\(plural(total, "issue")): \(parts.joined(separator: ", "))"
    }

    /// `http, ws · medium · normal`.
    public static func profileRowLine2(_ entry: ScanProfileListEntry) -> String {
        [entry.lanes.map(\.rawValue).joined(separator: ", "), entry.intensity.rawValue, entry.speed.rawValue]
            .joined(separator: " · ")
    }

    /// `GET /search` (the path alone when the lane has no method).
    static func requestLine(_ location: ScanIssueLocation) -> String {
        [location.method, location.path].compactMap { $0 }.joined(separator: " ")
    }

    /// `GET /search · query q · certain`.
    public static func issueRowLine2(_ issue: ScanIssueSummary) -> String {
        [requestLine(issue.location), "\(issue.location.kind) \(issue.location.name)", issue.confidence.rawValue]
            .joined(separator: " · ")
    }

    /// `http://127.0.0.1:8080 · GET /search · query q`.
    public static func issueWhere(_ issue: ScanIssueSummary) -> String {
        [issue.target.origin, requestLine(issue.location), "\(issue.location.kind) \(issue.location.name)"]
            .joined(separator: " · ")
    }

    /// `first seen 2 min ago · last seen 2 min ago · 1 occurrence · http.reflected-xss · scan-1a2b3c4d`.
    public static func issueMetaLine(_ issue: ScanIssue, now: Int) -> String {
        ["first seen \(relative(ms: issue.firstSeen, now: now))", "last seen \(relative(ms: issue.lastSeen, now: now))",
         plural(issue.occurrences, "occurrence"), issue.checkId, issue.job].joined(separator: " · ")
    }

    /// `json_value city, path profile.address.city, traits json, example Lisbon, seen 3 times`.
    public static func pointAccessibilityLabel(_ point: ScanInsertionPoint) -> String {
        var parts = ["\(point.kind) \(point.name)"]
        if let path = point.path, !path.isEmpty { parts.append("path \(path)") }
        if !point.traits.isEmpty { parts.append("traits \(point.traits.joined(separator: ", "))") }
        if let example = point.example, !example.isEmpty { parts.append("example \(example)") }
        parts.append("seen \(plural(point.frequency, "time"))")
        return parts.joined(separator: ", ")
    }

    /// `GET /account/{id}, 2 points, audited, needs auth`.
    public static func nodeAccessibilityLabel(_ node: ScanSiteNode) -> String {
        var parts = ["\(node.method) \(node.pathTemplate)", plural(node.points, "point")]
        if node.audited { parts.append("audited") }
        if node.auth { parts.append("needs auth") }
        return parts.joined(separator: ", ")
    }

    /// `Cookies: sid · Headers: authorization · from flow GET /login · observed 2 min ago`.
    /// Names only, never values. `flowLabel` nil falls back to the flow id's first 8 characters.
    public static func sessionPreviewText(_ preview: ScanSessionProfile, flowLabel: String?, now: Int) -> String {
        var parts = [
            "Cookies: \(preview.cookies.isEmpty ? "none" : preview.cookies.joined(separator: ", "))",
            "Headers: \(preview.headers.isEmpty ? "none" : preview.headers.joined(separator: ", "))",
        ]
        if let label = flowLabel ?? preview.sourceFlow.map({ String($0.prefix(8)) }) { parts.append("from flow \(label)") }
        parts.append("observed \(relative(ms: preview.observedAt, now: now))")
        return parts.joined(separator: " · ")
    }

    /// `Canary: GET /account` / `Auth-lost detection off: no GET/HEAD flow seen`.
    public static func canaryText(_ canary: ScanCanary) -> String {
        switch canary {
        case .flow(let method, let path, _): "Canary: \(method) \(path)"
        case .none: "Auth-lost detection off: no GET/HEAD flow seen"
        }
    }

    static func plural(_ n: Int, _ noun: String) -> String { "\(n) \(noun)\(n == 1 ? "" : "s")" }
}
