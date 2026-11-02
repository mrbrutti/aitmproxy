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

/// D4: a builtin's edits are launch overrides, never saved.
public let scanEditedBuiltinText = "Edited builtin — Start Scan uses these values; Duplicate… to keep them."

/// D4: shown under the dials while Intensity is Intrusive.
public let scanIntrusiveHint = "Intrusive checks may disrupt the target; the engine asks before starting."

/// D4: the help on a check the profile's intensity will not run.
public let scanAboveIntensityHelp = "Above this profile's intensity; raise Intensity to run it."

// The empty states and placeholders of the four tabs (D4–D7), one home each.

/// Profiles: the core's `scan.profile.list` came back empty.
public let scanNoProfilesText = "No profiles — the core lists none."

/// Jobs: nothing started yet.
public let scanNoJobsText = "No jobs yet — pick a profile and Start Scan."

/// Jobs: no row selected.
public let scanSelectJobText = "Select a job."

/// Site map: no job has crawled yet (D11, one sentence, the empty state's title).
public let scanNoSitemapText = "No site map yet — a running job fills this as it crawls."

/// Site map: the filter leaves no endpoint.
public let scanNoEndpointsMatchText = "No endpoints match."

/// Site map: no endpoint selected.
public let scanSelectEndpointText = "Select an endpoint."

/// Site map: the selected endpoint has no insertion points.
public let scanNoPointsOnEndpointText = "None on this endpoint."

/// Site map: the selected endpoint has no recorded flows.
public let scanNoFlowsOnEndpointText = "None recorded for this endpoint."

/// Issues: nothing to list.
public let scanNoIssuesText = "No issues — start a scan, or widen the filters."

/// Issues: no row selected.
public let scanSelectIssueText = "Select an issue to read its evidence."

/// Issues: the detail carries no evidence.
public let scanNoEvidenceText = "No evidence recorded for this issue."

/// `Nothing to delete: my-api is not on the core`: Delete on a profile the core does not list.
public func scanNothingToDeleteText(name: String) -> String { "Nothing to delete: \(name) is not on the core" }

/// `Unable to save profile: <reason>`: a bus error behind one of the page's actions.
public func scanUnableText(_ what: String, _ reason: String) -> String { "Unable to \(what): \(reason)" }

/// The Duplicate… popover's hint under a name `ScanSurface.isValidProfileName` refuses.
public let scanProfileNameRuleText = "Use lowercase letters, digits, - _ . (start with a letter or digit)"

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

    /// Whether `name` may go to `scan.profile.save` / `.delete` as a profile name
    /// (the core stores a profile under its name): 1...64 ASCII letters, digits,
    /// `-`, `_` or `.`, not starting with `.` or `-`. So no path separator, no
    /// whitespace, no NUL, no `..` segment can reach the core's store.
    public static func isValidProfileName(_ name: String) -> Bool {
        // The engine's rule for a saved profile (`^[a-z0-9][a-z0-9._-]{0,63}$`): lowercase
        // only, so collisions are case-insensitive by construction; validated here before
        // the name ever reaches `scan.profile.save`, and again by the core before any path.
        let scalars = Array(name.unicodeScalars)
        guard (1...64).contains(scalars.count) else { return false }
        func lowerOrDigit(_ scalar: Unicode.Scalar) -> Bool {
            switch scalar {
            case "a"..."z", "0"..."9": true
            default: false
            }
        }
        guard lowerOrDigit(scalars[0]) else { return false }
        return scalars.dropFirst().allSatisfy { scalar in
            switch scalar {
            case "-", "_", ".": true
            default: lowerOrDigit(scalar)
            }
        }
    }

    /// Whether `name` is already one of `names`, compared case-insensitively: the
    /// core's store may fold case, so `My-API` must not be offered as a new name
    /// beside a saved `my-api` (nor beside a builtin).
    public static func profileNameCollides(_ name: String, with names: [String]) -> Bool {
        names.contains { $0.caseInsensitiveCompare(name) == .orderedSame }
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

// MARK: - PoC link (D6)

/// Resolves an issue's `poc_ref` to one of the PoC files the app lists, so the
/// Issues detail can open the finding's PoC without guessing a path.
public enum ScanFindingLink {
    /// The index of the first path in `pocPaths` whose file name is `pocRef`,
    /// `pocRef + ".poc.yaml"`, or that ends in `/` + `pocRef`; nil for a nil or
    /// empty ref, or no match.
    public static func match(pocRef: String?, in pocPaths: [String]) -> Int? {
        guard let ref = pocRef, !ref.isEmpty else { return nil }
        let withExtension = ref + ".poc.yaml"
        return pocPaths.firstIndex { path in
            let file = path.split(separator: "/", omittingEmptySubsequences: false).last.map(String.init) ?? path
            // The engine's `poc_ref` is the PoC file's own path (seen live: an absolute
            // `<findings.dir>/scan/pocs/<slug>/<name>.poc.yaml`), so equality comes first;
            // a bare name or a `dir/name` tail still resolves for a relative reference.
            return path == ref || file == ref || file == withExtension || path.hasSuffix("/" + ref)
        }
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
            return ScanFormat.outOfScopeText(origin: first)
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

        /// The tri-state's words (D4): Default · Include · Exclude.
        public var word: String {
            switch self {
            case .default: "Default"
            case .include: "Include"
            case .exclude: "Exclude"
            }
        }
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

// MARK: - Job facts and the bus link (Jobs view spec D2, D6, D15)

/// One truth per job: the counters both wire shapes carry, merged from the
/// `scan.list` row and the stored `scan.status`, plus the detail-only fields
/// the status alone carries. The row and the detail both read this value, so
/// they can never disagree (Jobs view spec D2).
public struct ScanJobFacts: Equatable, Sendable {
    public var job: String
    /// The shared counters (state, phase, elapsed, probes, points, issues), from
    /// whichever of the two shapes is the newer truth.
    public var summary: ScanJobSummary
    /// The detail-only fields (profile, targets, started by, crawl, checks, lanes,
    /// stopped reason, error); nil until the first `scan.status` lands.
    public var status: ScanJobStatus?

    public init(job: String, summary: ScanJobSummary, status: ScanJobStatus?) {
        self.job = job
        self.summary = summary
        self.status = status
    }

    /// The shared counters come from, in order: a terminal status (final, every
    /// field present); else a terminal list row (the list turned terminal while
    /// the stored status is still live, the C1 and C2 bug); else whichever of the
    /// two has the higher `elapsedMs` (the status on a tie). `status` is kept as
    /// given either way.
    public static func make(summary: ScanJobSummary, status: ScanJobStatus?) -> ScanJobFacts {
        guard let status else { return ScanJobFacts(job: summary.job, summary: summary, status: nil) }
        let merged: ScanJobSummary = if status.state.isTerminal {
            status.summary
        } else if summary.state.isTerminal {
            summary
        } else if status.elapsedMs >= summary.elapsedMs {
            status.summary
        } else {
            summary
        }
        return ScanJobFacts(job: summary.job, summary: merged, status: status)
    }
}

/// How the Jobs view is linked to the core right now: from the bus state and
/// the last `scan.list` outcome (Jobs view spec D6). The verbs (Cancel Scan,
/// the hover Cancel, the context-menu Cancel) are enabled only while `.live`;
/// `bannerText` is D15's inline banner, nil while live.
public struct ScanJobsLink: Equatable, Sendable {
    public enum Kind: Equatable, Sendable { case live, reconnecting, disconnected, unanswered }

    public var kind: Kind
    /// `now - jobsLoadedAt`; nil before the first list arrived.
    public var valuesAgeMs: Int?
    public var bannerText: String?
    public var verbsEnabled: Bool

    public init(kind: Kind, valuesAgeMs: Int?, bannerText: String?, verbsEnabled: Bool) {
        self.kind = kind
        self.valuesAgeMs = valuesAgeMs
        self.bannerText = bannerText
        self.verbsEnabled = verbsEnabled
    }

    /// A connecting bus is `.reconnecting`; a disconnected or failed one
    /// `.disconnected`; a connected bus whose last `scan.list` failed is
    /// `.unanswered`; else `.live`.
    public static func make(bus: BusState, listFailedAt: Int?, jobsLoadedAt: Int?, now: Int) -> ScanJobsLink {
        let kind: Kind = switch bus {
        case .connecting: .reconnecting
        case .disconnected, .failed: .disconnected
        case .connected: listFailedAt != nil ? .unanswered : .live
        }
        let age = jobsLoadedAt.map { now - $0 }
        return ScanJobsLink(
            kind: kind, valuesAgeMs: age, bannerText: bannerText(kind: kind, ageMs: age), verbsEnabled: kind == .live)
    }

    /// D15's table; the age clause is omitted while no list has arrived.
    static func bannerText(kind: Kind, ageMs: Int?) -> String? {
        guard kind != .live else { return nil }
        let age = ageMs.map { "showing values from \(ScanFormat.elapsed(ms: $0)) ago" }
        let parts: [String?] = switch kind {
        case .live: []
        case .reconnecting: ["Bus disconnected", age, "reconnecting…"]
        case .disconnected: ["Bus disconnected", age, "Proxy ▸ Reconnect Bus (⌃⌘R) to retry"]
        case .unanswered: ["The core is not answering", age, "retrying every 2 s"]
        }
        return parts.compactMap { $0 }.joined(separator: " · ")
    }
}

// MARK: - End-state sentences (Jobs view spec D4)

/// The words for a job that has stopped: one sentence for the state, one for
/// the stopped reason, one for a crawl that hit errors, and the raw tokens for
/// the data-face lines. Identical on the web and TUI surfaces (the parity pin);
/// numbers are grouped (`6,468`), singulars go through `ScanFormat.plural`.
public enum ScanEndText {
    /// The one sentence for a terminal job; nil while the job is live, and
    /// until its `scan.status` has landed (the checks it quotes are detail-only
    /// fields, nil until then, spec D2).
    public static func sentence(_ facts: ScanJobFacts) -> String? {
        let summary = facts.summary
        guard summary.state.isTerminal, let status = facts.status else { return nil }
        let elapsed = ScanFormat.elapsed(ms: summary.elapsedMs)
        switch summary.state {
        case .done:
            return "Done in \(elapsed) · \(count(summary.points.found, "point")) · "
                + "\(count(status.checks.scheduled, "check"))."
        case .cancelled:
            return "Cancelled after \(elapsed); \(ScanFormat.grouped(status.checks.done)) of "
                + "\(count(status.checks.scheduled, "check")) had run. What it found stays."
        case .failed:
            return "Failed after \(elapsed)."
        default:
            return nil
        }
    }

    /// The stopped-reason sentence; nil for a reason the state sentence already
    /// says (`cancelled` on a cancelled job) or the error text already shows
    /// (`failed` with an error).
    public static func stoppedReason(_ reason: ScanStoppedReason, state: ScanJobState, probesBudget: Int, error: String?)
        -> String?
    {
        switch reason {
        case .budget:
            "Stopped early: the probe budget of \(ScanFormat.grouped(probesBudget)) was spent. "
                + "Raise it in the profile to go further."
        case .time: "Stopped early: the time budget ran out."
        case .cancelled: state == .cancelled ? nil : "Stopped early: the job was cancelled."
        case .sessionLost: "Stopped early: the session was lost and the profile says stop when that happens."
        case .errors: "Stopped early: too many errors from the target."
        case .policy: "Stopped early: the agent policy changed to paused or read-only."
        case .guardRefused: "Stopped early: the L4 guard refused a target mid-run."
        case .failed: error?.isEmpty == false ? nil : "Stopped early: an error ended the job."
        case .other: "Stopped early for a reason this app does not know."
        }
    }

    /// `The crawl fetched 1 page and hit 1 error`; nil when the crawl hit none.
    public static func crawlTrouble(_ crawl: ScanCrawlCounters) -> String? {
        guard crawl.errors > 0 else { return nil }
        return "The crawl fetched \(count(crawl.pages, "page")) and hit \(count(crawl.errors, "error"))"
    }

    /// The words for a `crawl.last_error` token; `transport`, `other` and an
    /// unknown token all read as a failed connection.
    public static func crawlErrorWords(_ kind: ScanCrawlErrorKind) -> String {
        switch kind {
        case .connectRefused: "the target refused the connection"
        case .tls: "TLS handshake failed"
        case .timeout: "the target did not answer in time"
        case .h2NotNegotiated: "the target does not speak HTTP/2"
        case .transport, .other, .unknown: "the connection failed"
        }
    }

    /// `stopped_reason: errors`: the raw token, for the data-face line only.
    public static func rawReasonLine(_ reason: ScanStoppedReason) -> String {
        "stopped_reason: \(reason.rawValue)"
    }

    /// `crawl.last_error: connect_refused`: the raw token, for the data-face line only.
    public static func rawCrawlErrorLine(_ kind: ScanCrawlErrorKind) -> String {
        "crawl.last_error: \(kind.rawValue)"
    }

    /// `1 check` / `6,468 checks`: `ScanFormat.plural`'s singular rule over a grouped number.
    private static func count(_ n: Int, _ noun: String) -> String {
        "\(ScanFormat.grouped(n)) \(noun)\(n == 1 ? "" : "s")"
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
    /// When the last `scan.list` landed (epoch ms, the caller's clock); nil before the first (Jobs view D6).
    public var jobsLoadedAt: Int?
    /// When the last `scan.list` failed (epoch ms); cleared by the next list that lands. A failed
    /// cancel or status read sets `jobsError` but not this (Jobs view D6).
    public var listFailedAt: Int?

    // Site map
    public var sitemapJob: String?
    public var sitemap: ScanSitemapResult?
    public var selectedNode: String?
    public var sitemapQuery = ""
    /// Whether the Site map tab has had its job picked for it once (P4).
    private var sitemapSeeded = false

    // Issues
    public var filters = ScanIssueFilters()
    public var issues: [ScanIssueSummary] = []
    public var issuesCursor: String?
    /// The `by_severity` tally of the last `scan.issues` page.
    public var issuesBySeverity: BySeverity = .zero
    public var selectedIssue: String?
    public var issueDetail: ScanIssue?
    public var issuesError: String?

    // Launch
    public var launchInFlight = false
    public var confirm: ScanConfirm?
    /// The footer's status line: a refusal, the last launch error, or nil for `scanIdleText`.
    public var statusLine: String?
    /// The last launch error whole (its code and origins), for the footer's detail;
    /// cleared by a start, a confirm request or picking another profile.
    public var launchError: ScanLaunchError?

    // Push
    public var lastSeq: [String: UInt64] = [:]
    /// Jobs this app started that `scan.list` has not carried yet (kept ahead of the list).
    public var locallyStarted: Set<String> = []
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

    /// The one accessor the Jobs views read: the listed row merged with the stored
    /// status (Jobs view D2); nil when the job is not listed.
    public func facts(for job: String) -> ScanJobFacts? {
        guard let summary = jobs.first(where: { $0.job == job }) else { return nil }
        return ScanJobFacts.make(summary: summary, status: statuses[job])
    }

    /// Whether the poll should read `scan.status` for a listed job (Jobs view D2):
    /// while nothing is stored, and once more when the list calls it terminal
    /// while the stored status is still live. A terminal stored status is final.
    public static func needsStatusRead(summary: ScanJobSummary, stored: ScanJobStatus?) -> Bool {
        guard let stored else { return true }
        return summary.state.isTerminal && !stored.state.isTerminal
    }

    /// Whether Cancel may be offered for `job`: its merged state is queued or
    /// running. A cancelling or terminal job is never a target (Jobs view D2).
    public func mayCancel(job: String) -> Bool {
        guard let state = facts(for: job)?.summary.state else { return false }
        return state == .queued || state == .running
    }

    /// The job Cancel Scan would stop: the selected one while its merged state is
    /// queued or running, else the only such job in the list. Nil when the choice
    /// would be a guess, and never a cancelling job (Jobs view D2).
    public var cancelTarget: String? {
        if let job = selectedJob, mayCancel(job: job) { return job }
        let live = jobs.filter { mayCancel(job: $0.job) }
        return live.count == 1 ? live[0].job : nil
    }

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
            return profile.lanes.contains(where: { !$0.isL4 }) || profile.lanes.isEmpty
                ? "Choose at least one in-scope origin."
                : "This profile has no L4 targets; add one to its target.l4 list."
        }
        // A blank row is not a host to add to scope; it is a missing origin.
        if origins.contains(where: { $0.trimmingCharacters(in: .whitespaces).isEmpty }) {
            return "Choose at least one in-scope origin."
        }
        for origin in origins {
            guard let authority = ScanForm.authority(of: origin), Scope.contains(authority, in: scopeHosts) else {
                return ScanFormat.outOfScopeText(origin: origin)
            }
        }
        return nil
    }

    /// What a launch sends: `scan.map` when `map`, `scan.start` otherwise, and
    /// always the whole `editedProfile` — the exact object `launchRefusal` checked,
    /// never a name the core would resolve to something else. The caller sends
    /// nothing while `launchRefusal` is non-nil.
    public func launchArguments(map: Bool) -> (tool: String, args: [String: JSONValue]) {
        let tool = map ? "scan.map" : ScanSurface.startTool
        guard let profile = editedProfile else { return (tool, [:]) }
        return (tool, ["profile": profile.json()])
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
    /// list does not carry yet stays in front of it. `now` (epoch ms, the caller's
    /// clock) stamps `jobsLoadedAt` and clears `listFailedAt` (Jobs view D6). The
    /// selection follows the list (Jobs view D3): nothing selected → the newest
    /// job; a selection the core dropped and this app is not waiting on → the
    /// first row; an existing selection is never replaced by a newer job.
    public mutating func applyList(_ result: ScanListResult, now: Int) {
        let listed = Set(result.jobs.map(\.job))
        // Only a job this app started and the core has not listed yet stays ahead of the
        // list; a job the core itself stopped listing (restart, history cap) goes with it.
        let pending = jobs.filter { !listed.contains($0.job) && locallyStarted.contains($0.job) }
        locallyStarted.subtract(listed)
        jobs = pending + result.jobs
        jobsError = nil
        // The per-job side tables follow the list: a job the core no longer lists
        // (and this app is not waiting on) takes its seq, status, notices and flag with it.
        let kept = listed.union(locallyStarted)
        lastSeq = lastSeq.filter { kept.contains($0.key) }
        statuses = statuses.filter { kept.contains($0.key) }
        launchNotices = launchNotices.filter { kept.contains($0.key) }
        refreshNeeded = refreshNeeded.intersection(kept)
        jobsLoadedAt = now
        listFailedAt = nil
        if let selected = selectedJob {
            if !jobs.contains(where: { $0.job == selected }), !locallyStarted.contains(selected) {
                selectedJob = jobs.first?.job
            }
        } else if let first = jobs.first {
            selectedJob = first.job
        }
    }

    /// A `scan.list` that failed: the inline error and the failure stamp (Jobs view
    /// D6); the rows and their counters stay. The caller passes the same clock as `applyList`.
    public mutating func noteListFailure(_ text: String, now: Int) {
        jobsError = text
        listFailedAt = now
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
        locallyStarted.insert(result.job)
        if let index = jobs.firstIndex(where: { $0.job == result.job }) {
            jobs[index] = result.status.summary
        } else {
            jobs.insert(result.status.summary, at: 0)
        }
        launchNotices[result.job] = result.clamped.map(ScanFormat.clampedText)
            + result.lanes.skipped.map(ScanFormat.skippedLaneText)
        selectedJob = result.job
        tab = .jobs
        confirm = nil
        statusLine = nil
        launchError = nil
        launchInFlight = false
    }

    /// A `needs_confirmation` answer: the sheet opens; nothing is sent until Start Scan.
    public mutating func applyConfirm(tool: String, args: [String: JSONValue], request: L4ConfirmRequest) {
        confirm = ScanConfirm(tool: tool, arguments: args, request: request)
        launchError = nil
        launchInFlight = false
    }

    /// A launch the bus refused: the error is kept whole and its display becomes the status line.
    public mutating func applyLaunchError(_ error: ScanLaunchError) {
        launchError = error
        statusLine = error.display
        confirm = nil
        launchInFlight = false
    }

    /// The footer has one line. A line the app writes (`Saved <name>`, the delete
    /// line, a refusal) replaces a kept launch error; `nil` takes both down.
    public mutating func setStatusLine(_ line: String?) {
        statusLine = line
        launchError = nil
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

    /// Whether `job` is one this model tracks: listed, started here, or with a status read.
    func knowsJob(_ job: String) -> Bool {
        locallyStarted.contains(job) || statuses[job] != nil || jobs.contains { $0.job == job }
    }

    /// A `notifications/aitm/job` line. A trigger only: records `seq`, flags the
    /// job (and the list / issues as the event warrants) and returns true; false
    /// and no change for a non-scan kind, an unreadable line, or a `seq` at or
    /// below the last seen. A line for a job this model does not know (not listed,
    /// not started here, no status) only asks for the list: no `seq` or flag is
    /// kept for it, so a stranger's lines cannot grow the tables. Never touches
    /// `statuses`, `jobs` or `issues`.
    @discardableResult
    public mutating func noteJobEvent(_ params: JSONValue) -> Bool {
        guard let line = try? ScanJobNotification(json: params), line.kind == "scan" else { return false }
        guard knowsJob(line.job) else {
            listRefreshNeeded = true
            return true
        }
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

    /// Picking a profile (the same one or none included) starts afresh: the launch
    /// error and the status line go together.
    public mutating func select(profile: String?) {
        selectedProfile = profile
        launchError = nil
        statusLine = nil
    }

    /// The Site map tab's first opening picks the newest job once `jobs` has one;
    /// after that the operator's choice (a job or All jobs) stands.
    public mutating func seedSitemapJobIfNeeded() {
        guard !sitemapSeeded, sitemapJob == nil, let first = jobs.first else { return }
        sitemapJob = first.job
        sitemapSeeded = true
    }

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
        // `%ld`: every component is a 64-bit `Int`; `%d` would read the hour count as 32 bits.
        if hours > 0 { return String(format: "%ld:%02ld:%02ld", hours, minutes, seconds) }
        return String(format: "%ld:%02ld", minutes, seconds)
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

    /// `Out of scope — add a.test:8443 to scope to scan it` (D12): the launch gate,
    /// the `out_of_scope` error and the origin row all say this.
    public static func outOfScopeText(origin: String) -> String {
        "Out of scope — add \(hostOf(origin: origin)) to scope to scan it"
    }

    /// `Unable to list jobs: <core text>. Showing values from 0:42 ago; retrying every 2 s.`
    /// (Jobs view D6): the inline list error with the last-good clause; without an age
    /// (no list has landed yet) `Unable to list jobs: <core text>. Retrying every 2 s.`
    public static func listErrorText(core: String, ageMs: Int?) -> String {
        guard let ageMs else { return "Unable to list jobs: \(core). Retrying every 2 s." }
        return "Unable to list jobs: \(core). Showing values from \(elapsed(ms: ageMs)) ago; retrying every 2 s."
    }

    /// `Clamped budget.probes 50000 → 20000`: a `scan.start` / `scan.status` clamp notice.
    public static func clampedText(_ clamped: ScanClamped) -> String {
        "Clamped \(clamped.field) \(clamped.requested) → \(clamped.applied)"
    }

    /// `Skipped ws: lane not available on this build`: a `lanes.skipped` notice.
    public static func skippedLaneText(_ skipped: ScanSkippedLane) -> String {
        "Skipped \(skipped.lane.rawValue): \(skipped.reason)"
    }

    /// A timing-evidence double: up to three fraction digits, no grouping, `.` as the
    /// decimal mark whatever the locale (`0.857`, `2`).
    public static func number(_ value: Double) -> String {
        value.formatted(
            .number.precision(.fractionLength(0...3)).grouping(.never).locale(Locale(identifier: "en_US_POSIX")))
    }

    /// A count with a `,` every three digits (`6,468`, `1,234,567`) whatever the
    /// locale: the Jobs view's numbers (Jobs view spec D4, D11). Spelled by hand
    /// because `en_US_POSIX` formats without grouping.
    public static func grouped(_ n: Int) -> String {
        let digits = String(n.magnitude)
        var groups: [Substring] = []
        var end = digits.endIndex
        while end > digits.startIndex {
            let start = digits.index(end, offsetBy: -3, limitedBy: digits.startIndex) ?? digits.startIndex
            groups.insert(digits[start..<end], at: 0)
            end = start
        }
        return (n < 0 ? "-" : "") + groups.joined(separator: ",")
    }

    /// `yes` / `no`, for the session and L4 evidence flags.
    public static func yesNo(_ value: Bool) -> String { value ? "yes" : "no" }

    /// The state word, or the phase word while running.
    static func stateWord(_ summary: ScanJobSummary) -> String {
        summary.state == .running ? summary.phase.word : summary.state.word
    }

    static func hosts(_ status: ScanJobStatus?) -> String? {
        guard let targets = status?.targets, !targets.isEmpty else { return nil }
        return targets.map(hostOf(origin:)).joined(separator: ", ")
    }

    /// The status's profile name; nil when there is no status or it carries none (`""`).
    private static func profileName(_ status: ScanJobStatus?) -> String? {
        guard let name = status?.profileName, !name.isEmpty else { return nil }
        return name
    }

    /// `Auditing · standard · 127.0.0.1:8080`; `—` for what `scan.status` has not told us yet.
    public static func jobRowLine1(_ summary: ScanJobSummary, status: ScanJobStatus?) -> String {
        [stateWord(summary), profileName(status) ?? "—", hosts(status) ?? "—"].joined(separator: " · ")
    }

    /// `probes 418 / 2000 · points 80 / 120 audited · 0:42`.
    public static func jobRowLine2(_ summary: ScanJobSummary) -> String {
        [probesText(summary.probes), pointsText(summary.points), elapsed(ms: summary.elapsedMs)].joined(separator: " · ")
    }

    /// The row's words for VoiceOver (D13); the severity bar hides behind it.
    public static func jobAccessibilityLabel(_ summary: ScanJobSummary, status: ScanJobStatus?) -> String {
        var parts = [summary.state.word, summary.phase.rawValue]
        if let name = profileName(status) { parts.append(name) }
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

    /// `http, ws · medium · normal`; `no lanes · medium · normal` for a saved profile with every lane unticked.
    public static func profileRowLine2(_ entry: ScanProfileListEntry) -> String {
        let lanes = entry.lanes.isEmpty ? "no lanes" : entry.lanes.map(\.rawValue).joined(separator: ", ")
        return [lanes, entry.intensity.rawValue, entry.speed.rawValue].joined(separator: " · ")
    }

    /// `standard, builtin, http, ws · medium · normal` (D13); `builtin` only when it is one.
    public static func profileAccessibilityLabel(_ entry: ScanProfileListEntry) -> String {
        var parts = [entry.name]
        if entry.builtin { parts.append("builtin") }
        parts.append(profileRowLine2(entry))
        return parts.joined(separator: ", ")
    }

    /// The check row's visible words (D13): `Error-based SQL injection, sqli-error,
    /// medium, light, bundled`, plus `above this profile's intensity` when the profile
    /// will not run it. The choice menu beside the row reads its own word.
    public static func checkAccessibilityLabel(_ leaf: ScanCheckTree.Leaf) -> String {
        var parts = [
            leaf.meta.name, leaf.meta.klass, leaf.meta.intensity.rawValue, leaf.meta.cost, leaf.meta.origin.word,
        ]
        if leaf.aboveIntensity { parts.append("above this profile's intensity") }
        return parts.joined(separator: ", ")
    }

    /// `Finding f-3b1c`: the Issues detail's `finding_id`, as text (D6).
    public static func findingText(_ id: String) -> String { "Finding \(id)" }

    /// `http://127.0.0.1:8080, 3 endpoints, collapsed` (D13): a Site map origin row.
    public static func originAccessibilityLabel(origin: String, count: Int, collapsed: Bool) -> String {
        [origin, plural(count, "endpoint"), collapsed ? "collapsed" : "expanded"].joined(separator: ", ")
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

    /// `High, Reflected cross-site scripting, GET /search · query q · certain, Open` (D13).
    public static func issueAccessibilityLabel(_ issue: ScanIssueSummary) -> String {
        [issue.severity.word, issue.name, issueRowLine2(issue), issue.status.word].joined(separator: ", ")
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

    /// `1 endpoint` / `3 endpoints`.
    public static func plural(_ n: Int, _ noun: String) -> String { "\(n) \(noun)\(n == 1 ? "" : "s")" }
}
