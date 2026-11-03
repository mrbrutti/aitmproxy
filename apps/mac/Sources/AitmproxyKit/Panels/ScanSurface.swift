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

    /// What the sheet says it is about to start (Jobs view D13): `Profile standard ·
    /// 127.0.0.1:8117`, read from the arguments in either shape: Start Scan's inline
    /// `profile` (its `name` and `target.origins`) or Scan Again's `profile_name` plus
    /// the `overrides.target.origins` override. A name the arguments lack reads `—`;
    /// the host clause is left off when there are no origins.
    public var summaryLine: String {
        let name: String?
        let origins: [JSONValue]
        if let profile = arguments["profile"] {
            name = profile["name"]?.stringValue
            origins = profile["target"]?["origins"]?.arrayValue ?? []
        } else {
            name = arguments["profile_name"]?.stringValue
            origins = arguments["overrides"]?["target"]?["origins"]?.arrayValue ?? []
        }
        let profile = (name?.isEmpty == false ? name : nil) ?? ScanFormat.missingValue
        let hosts = ScanFormat.hostsJoined(origins: origins.compactMap(\.stringValue))
        return hosts.map { "Profile \(profile) · \($0)" } ?? "Profile \(profile)"
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
/// they can never disagree (Jobs view spec D2). `job` is the merged summary's id:
/// inside `ScanSurfaceModel` the listed row and its stored status always name the
/// same job (`facts(for:)` reads `statuses[job]`, stored under `status.job`).
public struct ScanJobFacts: Equatable, Sendable {
    /// The job id, the merged summary's.
    public var job: String { summary.job }
    /// The shared counters (state, phase, elapsed, probes, points, issues), from
    /// whichever of the two shapes is the newer truth.
    public var summary: ScanJobSummary
    /// The detail-only fields (profile, targets, started by, crawl, checks, lanes,
    /// stopped reason, error); nil until the first `scan.status` lands.
    public var status: ScanJobStatus?

    public init(summary: ScanJobSummary, status: ScanJobStatus?) {
        self.summary = summary
        self.status = status
    }

    /// The shared counters come from, in order: a terminal status (final, every
    /// field present); else a terminal list row (the list turned terminal while
    /// the stored status is still live, the C1 and C2 bug); else whichever of the
    /// two has the higher `elapsedMs` (the status on a tie). `status` is kept as
    /// given either way.
    public static func make(summary: ScanJobSummary, status: ScanJobStatus?) -> ScanJobFacts {
        guard let status else { return ScanJobFacts(summary: summary, status: nil) }
        let merged: ScanJobSummary = if status.state.isTerminal {
            status.summary
        } else if summary.state.isTerminal {
            summary
        } else if status.elapsedMs >= summary.elapsedMs {
            status.summary
        } else {
            summary
        }
        return ScanJobFacts(summary: merged, status: status)
    }
}

/// The `scan.status` reads the poll has made under rule 2 of the re-read rule
/// (Jobs view D2; `ScanSurfaceModel.needsStatusRead`): `scan.list` carries no profile
/// name or targets, so every listed job is read once while nothing is stored, and
/// once more after the list calls it terminal while the stored status is still live.
/// A key is the job and whether its list row was terminal when the read was claimed,
/// so the second read is distinct from the first.
///
/// A claim is never undone by the read's own outcome: a failed read against a core
/// that is not answering would otherwise retry at 1 Hz and flip the link every
/// second. Only `settle(afterList:stored:)`, called when a list lands (the proof the
/// core answers), prunes the jobs the list dropped and re-arms every job that still
/// owes a read under `needsStatusRead`, so a failed read is retried after that list.
public struct ScanStatusReadLedger: Equatable, Sendable {
    /// One claimed read: the job and whether its list row was terminal at the claim.
    public struct Key: Hashable, Sendable {
        public var job: String
        public var summaryIsTerminal: Bool
    }

    private(set) var keys: Set<Key> = []

    public init() {}

    var count: Int { keys.count }

    /// Claims the read for `job` under its row's terminality: true when the key was
    /// absent (the caller makes the read), false when it was already claimed.
    public mutating func claim(_ job: String, summaryIsTerminal: Bool) -> Bool {
        keys.insert(Key(job: job, summaryIsTerminal: summaryIsTerminal)).inserted
    }

    /// A list landed: keeps a key only while its job is listed and
    /// `ScanSurfaceModel.needsStatusRead` says the job owes nothing more, so an
    /// unlisted job is pruned and a job whose read failed (nothing stored) or whose
    /// row turned terminal over a live stored status is re-armed.
    public mutating func settle(afterList jobs: [ScanJobSummary], stored: [String: ScanJobStatus]) {
        let listed = Dictionary(jobs.map { ($0.job, $0) }, uniquingKeysWith: { first, _ in first })
        keys = keys.filter { key in
            guard let summary = listed[key.job] else { return false }
            return !ScanSurfaceModel.needsStatusRead(summary: summary, stored: stored[key.job])
        }
    }
}

/// A failed Jobs read (`scan.list`, `scan.status` or `scan.cancel`): the read's
/// own wording (`Unable to list jobs: <core>` / `Unable to read job <id>: <core>` /
/// `Unable to cancel job <id>: <core>`) and when it failed (epoch ms, the caller's
/// clock; Jobs view D6 amendment). The one record of a failed read: `jobsError` and
/// `readFailedAt` read it, `ScanSurfaceModel.inlineJobsError(ageMs:)` adds the
/// last-good clause, and the next list that lands clears it.
public struct ScanReadFailure: Equatable, Sendable {
    public var text: String
    public var at: Int

    public init(text: String, at: Int) {
        self.text = text
        self.at = at
    }
}

/// How the Jobs view is linked to the core right now: from the bus state and
/// the last Jobs read's outcome (Jobs view spec D6). The verbs (Cancel Scan,
/// the hover Cancel, the context-menu Cancel) are enabled only while `.live`;
/// `bannerText` is D15's inline banner, nil while live.
public struct ScanJobsLink: Equatable, Sendable {
    public enum Kind: Equatable, Sendable { case live, reconnecting, disconnected, unanswered }

    public var kind: Kind
    /// `now - jobsLoadedAt`, never below 0 (the stamp and `now` may come from two
    /// clocks a beat apart); nil before the first list arrived.
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
    /// `.disconnected`; a connected bus whose last Jobs read (list, status or
    /// cancel) failed is `.unanswered` (D6 amendment); else `.live`.
    public static func make(bus: BusState, readFailedAt: Int?, jobsLoadedAt: Int?, now: Int) -> ScanJobsLink {
        let kind: Kind = switch bus {
        case .connecting: .reconnecting
        case .disconnected, .failed: .disconnected
        case .connected: readFailedAt != nil ? .unanswered : .live
        }
        let age = jobsLoadedAt.map { max(0, now - $0) }
        return ScanJobsLink(
            kind: kind, valuesAgeMs: age, bannerText: bannerText(kind: kind, ageMs: age),
            verbsEnabled: verbsEnabled(bus: bus, readFailedAt: readFailedAt))
    }

    /// The verb gate alone, without a clock: true only for the `.live` kind (a connected
    /// bus whose last Jobs read landed). The rows, the context menu and the header's verb
    /// slot read this, not `make(...).verbsEnabled`, so the 1 Hz age clock re-evaluates
    /// only the inline error (plan fix 1.5h).
    public static func verbsEnabled(bus: BusState, readFailedAt: Int?) -> Bool {
        if case .connected = bus { return readFailedAt == nil }
        return false
    }

    /// D15's table; the age clause is omitted while no list has arrived.
    static func bannerText(kind: Kind, ageMs: Int?) -> String? {
        let age = ageMs.map { "showing values from \(ScanFormat.elapsed(ms: $0)) ago" }
        let parts: [String?]
        switch kind {
        case .live: return nil
        case .reconnecting: parts = ["Bus disconnected", age, "reconnecting…"]
        case .disconnected: parts = ["Bus disconnected", age, "Proxy ▸ Reconnect Bus (⌃⌘R) to retry"]
        case .unanswered: parts = ["The core is not answering", age, "retrying every 2 s"]
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
    /// The one sentence for a terminal job; nil while the job is live, and until a
    /// terminal `scan.status` has landed: the checks it quotes are detail-only fields,
    /// and a stored status still live during the one-beat gap (spec D2) would quote the
    /// live read's numbers, so the sentence waits for the final ones.
    public static func sentence(_ facts: ScanJobFacts) -> String? {
        guard let status = facts.status, status.state.isTerminal else { return nil }
        let summary = facts.summary
        let elapsed = ScanFormat.elapsed(ms: summary.elapsedMs)
        switch summary.state {
        case .done:
            return "Done in \(elapsed) · \(ScanFormat.plural(summary.points.found, "point", grouped: true)) · "
                + "\(ScanFormat.plural(status.checks.scheduled, "check", grouped: true))."
        case .cancelled:
            return "Cancelled after \(elapsed); \(ScanFormat.grouped(status.checks.done)) of "
                + "\(ScanFormat.plural(status.checks.scheduled, "check", grouped: true)) had run. What it found stays."
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
        return "The crawl fetched \(ScanFormat.plural(crawl.pages, "page", grouped: true)) and hit "
            + ScanFormat.plural(crawl.errors, "error", grouped: true)
    }

    /// The Stopped section's crawl line: `crawlTrouble`, joined by an em dash with the
    /// last error's words when the engine set `crawl.last_error` (it does only when no
    /// page was fetched): `The crawl fetched 0 pages and hit 1 error — the target refused
    /// the connection`. Nil when the crawl hit no errors.
    public static func crawlTroubleLine(_ crawl: ScanCrawlCounters) -> String? {
        guard let trouble = crawlTrouble(crawl) else { return nil }
        guard let kind = crawl.lastError else { return trouble }
        return trouble + " — " + crawlErrorWords(kind)
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
}

// MARK: - The derived progress model (Jobs view D8, D9)

/// The pace a running audit is keeping: two bus counters (`checks.done`,
/// `checks.scheduled`) over the job's elapsed time, nothing more (Jobs view D8
/// amendment). The elapsed time includes the crawl, so the estimate is conservative.
public struct ScanPace: Equatable, Sendable {
    /// `ceil((scheduled - done) / checksPerSecond)`.
    public var secondsToGo: Int
    /// `done / (elapsedMs / 1000)`.
    public var checksPerSecond: Double

    public init(secondsToGo: Int, checksPerSecond: Double) {
        self.secondsToGo = secondsToGo
        self.checksPerSecond = checksPerSecond
    }
}

/// What the Jobs row's ring, the card's lane and the KPI strip show for one job,
/// derived from the merged facts by one total rule (Jobs view D8 and its
/// amendment; parity pins P15–P22). The engine sends counters, never a
/// percentage; every value here says so in its help.
public struct ScanJobProgress: Equatable, Sendable {
    public enum Ring: Equatable, Sendable {
        /// A state this build does not know: nothing to draw.
        case none
        /// Progress exists but cannot be measured (queued, passive, nothing scheduled yet).
        case indeterminate
        /// The fraction, 0…1.
        case determinate(Double)
        /// A terminal job: the final fraction, dimmed; nil when the counters give none.
        case finished(Double?)
    }

    public var ring: Ring
    /// The determinate value, 0…1; nil otherwise (including a finished ring).
    public var fraction: Double?
    /// `50 %` (a non-breaking space), floored so a running job never reads `100 %`
    /// before `done == scheduled`; nil when `fraction` is nil.
    public var percentText: String?
    /// The card's progress line; `""` for a terminal job (the card shows the end sentence, D9).
    public var phaseLine: String
    /// `Now: xss-reflected` / `Now: xss-reflected and 3 more`; nil when `checks.running`
    /// is empty. The parity spelling the web and the TUI share.
    public var nowLine: String?
    /// `3,236 of 6,468 checks (derived from the engine's counters)`, the crawl's `46 of
    /// 58 pages (derived …)`, or `Progress is not known yet`.
    public var helpText: String
    /// `3,232 checks to go`; while running in auditing or reporting with something
    /// scheduled and left; nil otherwise and when terminal.
    public var checksToGoText: String?
    /// `now · xss-reflected and 3 more`: the lane's spelling of `nowLine`; nil with it.
    public var nowTag: String?
    /// `at this pace, about 1:04 to go`; only while running in auditing with a derivable pace.
    public var estimateText: String?
    /// `Derived from the counters: 3,236 checks done in 1:04, about 51 checks per
    /// second, 3,232 to go.`; nil with `estimateText`.
    public var estimateHelp: String?

    static let waitingLine = "Waiting for the engine to start this job."
    static let passiveLine = "Passive checks over captured traffic"
    static let schedulingLine = "Scheduling checks"
    static let reportingLine = "Writing results"
    static let unknownHelp = "Progress is not known yet"
    static let derivedSuffix = " (derived from the engine's counters)"

    public init(_ facts: ScanJobFacts) {
        let summary = facts.summary
        let status = facts.status
        let checks = status?.checks
        let crawl = status?.crawl
        let running = checks?.running ?? []

        nowLine = Self.nowLine(running)
        nowTag = running.first.map { "now · " + Self.nowIds(running, first: $0) }

        let checksFraction: Double? = checks.flatMap { Self.fraction(of: $0.done, over: $0.scheduled) }
        let pagesFraction: Double? = crawl.flatMap { Self.fraction(of: $0.pages, over: $0.pages + $0.queued) }
        let checksHelp: String? = checks.flatMap { checks in
            checksFraction == nil ? nil : Self.checksLine(checks)
        }
        let pagesHelp: String? = crawl.flatMap { crawl in
            pagesFraction == nil
                ? nil
                : ScanFormat.grouped(crawl.pages) + " of "
                    + ScanFormat.plural(crawl.pages + crawl.queued, "page", grouped: true)
        }

        var ring: Ring = .indeterminate
        var line = ""
        var help: String? = nil
        var toGo: String? = nil
        var pace: ScanPace? = nil

        switch summary.state {
        case .queued:
            line = Self.waitingLine
        case .running, .cancelling:
            guard let checks, let crawl else {
                line = summary.phase.word
                break
            }
            switch summary.phase {
            case .crawling:
                if let pagesFraction { ring = .determinate(pagesFraction) }
                line = ScanFormat.plural(crawl.pages, "page", grouped: true) + ", "
                    + ScanFormat.grouped(crawl.queued) + " queued"
                help = pagesHelp
            case .passive:
                line = Self.passiveLine
            case .auditing:
                if let checksFraction {
                    ring = .determinate(checksFraction)
                    line = Self.checksLine(checks)
                } else {
                    line = Self.schedulingLine
                }
                help = checksHelp
                if summary.state == .running {
                    toGo = ScanFormat.checksToGo(done: checks.done, scheduled: checks.scheduled)
                    pace = ScanFormat.paceEstimate(
                        done: checks.done, scheduled: checks.scheduled, elapsedMs: summary.elapsedMs)
                }
            case .reporting:
                ring = .determinate(1)
                line = Self.reportingLine
                help = checksHelp
                if summary.state == .running {
                    toGo = ScanFormat.checksToGo(done: checks.done, scheduled: checks.scheduled)
                }
            case .queued, .done, .other:
                line = summary.phase.word
            }
        case .done, .cancelled, .failed:
            ring = .finished(checksFraction ?? pagesFraction)
            help = checksFraction != nil ? checksHelp : pagesHelp
        case .other:
            ring = .none
            line = summary.state.word
        }

        self.ring = ring
        phaseLine = line
        if case .determinate(let value) = ring {
            fraction = value
            percentText = "\(Int((value * 100).rounded(.down)))\u{00A0}%"
        } else {
            fraction = nil
            percentText = nil
        }
        helpText = help.map { $0 + Self.derivedSuffix } ?? Self.unknownHelp
        checksToGoText = toGo
        if let pace, let checks {
            estimateText = ScanFormat.estimateText(pace)
            estimateHelp = ScanFormat.estimateHelp(
                done: checks.done, elapsedMs: summary.elapsedMs, pace: pace, toGo: checks.scheduled - checks.done)
        } else {
            estimateText = nil
            estimateHelp = nil
        }
    }

    /// `3,236 of 6,468 checks`.
    private static func checksLine(_ checks: ScanCheckCounters) -> String {
        ScanFormat.grouped(checks.done) + " of " + ScanFormat.plural(checks.scheduled, "check", grouped: true)
    }

    /// `done / total` when `total > 0`, clamped at 1 so a core reporting `done` past
    /// `scheduled` never overshoots the ring, the lane or `percentText` (D8 types the
    /// fraction 0…1); nil otherwise. The phase line still quotes the counters as sent.
    private static func fraction(of done: Int, over total: Int) -> Double? {
        guard total > 0 else { return nil }
        return min(1, Double(done) / Double(total))
    }

    private static func nowLine(_ running: [String]) -> String? {
        guard let first = running.first else { return nil }
        return "Now: " + nowIds(running, first: first)
    }

    /// `xss-reflected` / `xss-reflected and 3 more`.
    private static func nowIds(_ running: [String], first: String) -> String {
        running.count > 1 ? "\(first) and \(running.count - 1) more" : first
    }
}

extension ScanFormat {
    /// `checks.done` over the elapsed time (Jobs view D8 amendment); nil when no rate can
    /// be derived: `elapsedMs <= 0`, `done <= 0` (rate 0), `scheduled <= 0` or
    /// `done >= scheduled`, and nil when the seconds to go would not fit under the
    /// decoder's 2^53 ms ceiling (`ScanWire.wholeNumberRange`): the arithmetic stays in
    /// `Double` until the value is known to fit, and gives up the estimate rather than
    /// trap on `Int(Double)` or on `secondsToGo * 1000` (fix 2.12a). The bound is
    /// checked on the raw quotient, so the rounded-up second is at most 2^53 + 1000 ms,
    /// inside `Int` and inside what `elapsed(ms:)` prints. The caller limits it to a
    /// running audit.
    public static func paceEstimate(done: Int, scheduled: Int, elapsedMs: Int) -> ScanPace? {
        guard elapsedMs > 0, done > 0, scheduled > 0, done < scheduled else { return nil }
        let checksPerSecond = Double(done) / (Double(elapsedMs) / 1000)
        let seconds = Double(scheduled - done) / checksPerSecond
        guard seconds <= Double(ScanWire.wholeNumberRange.upperBound) / 1000 else { return nil }
        return ScanPace(secondsToGo: Int(seconds.rounded(.up)), checksPerSecond: checksPerSecond)
    }

    /// `3,232 checks to go` / `1 check to go`; nil when nothing is scheduled or nothing is left.
    public static func checksToGo(done: Int, scheduled: Int) -> String? {
        guard scheduled > 0, done < scheduled else { return nil }
        return plural(scheduled - done, "check", grouped: true) + " to go"
    }

    /// `at this pace, about 1:04 to go`.
    public static func estimateText(_ pace: ScanPace) -> String {
        "at this pace, about \(elapsed(ms: pace.secondsToGo * 1000)) to go"
    }

    /// `Derived from the counters: 3,236 checks done in 1:04, about 51 checks per second,
    /// 3,232 to go.`; the rate is rounded (`about 1 check per second`), or `fewer than 1
    /// check per second` when it rounds to 0.
    public static func estimateHelp(done: Int, elapsedMs: Int, pace: ScanPace, toGo: Int) -> String {
        let rate = Int(pace.checksPerSecond.rounded())
        let rateWords =
            rate == 0 ? "fewer than 1 check per second" : "about \(plural(rate, "check", grouped: true)) per second"
        return "Derived from the counters: \(plural(done, "check", grouped: true)) done in \(elapsed(ms: elapsedMs)), "
            + "\(rateWords), \(grouped(toGo)) to go."
    }
}

/// One line of the job card's attention block (Jobs view D9): the count sentence
/// and the engine's samples behind its disclosure, empty for a line with none.
public struct ScanAttentionLine: Equatable, Sendable {
    /// `7 checks could not run`.
    public var text: String
    /// The disclosure's rows; empty for none.
    public var samples: [ScanCheckErrorSample]

    public init(text: String, samples: [ScanCheckErrorSample]) {
        self.text = text
        self.samples = samples
    }
}

extension ScanEndText {
    /// The attention lines, in this order and only when non-zero: `<n> checks could
    /// not run` with `errorSamples`, `<n> checks were skipped` with `skippedSamples`,
    /// the crawl trouble line (`crawlTroubleLine`) with no samples. Empty until a
    /// status has landed; rendered in every state.
    public static func attention(_ facts: ScanJobFacts) -> [ScanAttentionLine] {
        guard let status = facts.status else { return [] }
        var lines: [ScanAttentionLine] = []
        let checks = status.checks
        if checks.errors > 0 {
            lines.append(ScanAttentionLine(
                text: ScanFormat.plural(checks.errors, "check", grouped: true) + " could not run",
                samples: checks.errorSamples))
        }
        if checks.skipped > 0 {
            let verb = checks.skipped == 1 ? "was" : "were"
            lines.append(ScanAttentionLine(
                text: ScanFormat.plural(checks.skipped, "check", grouped: true) + " \(verb) skipped",
                samples: checks.skippedSamples))
        }
        if let trouble = crawlTroubleLine(status.crawl) {
            lines.append(ScanAttentionLine(text: trouble, samples: []))
        }
        return lines
    }

    /// The **Notices** list: the launch's notices (`clamped` and `lanes.skipped` from
    /// the `scan.start` result, `ScanSurfaceModel.launchNotices`) first, then the
    /// status's `clamped` rows and skipped lanes the notices did not already spell out.
    public static func notices(_ status: ScanJobStatus, launchNotices: [String]) -> [String] {
        var lines = launchNotices
        for line in status.clamped.map(ScanFormat.clampedText) + status.lanes.skipped.map(ScanFormat.skippedLaneText)
        where !lines.contains(line) {
            lines.append(line)
        }
        return lines
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
    /// The last failed Jobs read (`scan.list`, `scan.status` or `scan.cancel`): its own
    /// wording and when it failed; the one stored failure fact. Set by `noteReadFailure`,
    /// cleared by the next list that lands, the proof the core answers (Jobs view D6
    /// amendment). Any failed Jobs read marks the link: the poll reads the selected job's
    /// status before the list, so against a frozen core the status read times out first.
    public var readFailure: ScanReadFailure?
    /// The inline error's plain wording (`Unable to list jobs: <core>`); nil while no Jobs
    /// read has failed since the last list landed. Reads `readFailure`.
    public var jobsError: String? { readFailure?.text }
    /// When the last Jobs read failed (epoch ms), for `ScanJobsLink.make`; nil while none has
    /// since the last list landed. Reads `readFailure`.
    public var readFailedAt: Int? { readFailure?.at }

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
    /// A Scan Again the bus refused (Jobs view D13), shown under the card's title row as
    /// `Unable to scan again: <display>`; cleared by the next successful start, by
    /// selecting another job, or by Escape. The Profiles footer never shows it.
    public var scanAgainError: ScanLaunchError?

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

    /// Rule 1 of the re-read rule (Jobs view D2): the selected job is read every beat
    /// while its STORED status is missing or still live, whatever the list row says
    /// (the list turns terminal first; the stored status must follow it there or the
    /// detail freezes at its last live read). A terminal stored status is final.
    public static func selectedNeedsStatusRead(stored: ScanJobStatus?) -> Bool {
        stored.map { !$0.state.isTerminal } ?? true
    }

    /// Whether Cancel may be offered for `job`: its merged state is queued or
    /// running. A cancelling or terminal job is never a target (Jobs view D2).
    public func mayCancel(job: String) -> Bool {
        guard let state = facts(for: job)?.summary.state else { return false }
        return state == .queued || state == .running
    }

    /// The job Cancel Scan would stop: the selected one while its merged state is
    /// queued or running; nil while a job is selected but is cancelling, terminal
    /// or unknown (never a job the operator is not looking at, Jobs view D2
    /// amendment). Only with nothing selected, the only queued or running job in
    /// the list; nil when the choice would be a guess.
    public var cancelTarget: String? {
        if let job = selectedJob { return mayCancel(job: job) ? job : nil }
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

    // MARK: Scan Again (Jobs view D13)

    /// nil when Scan Again may be sent for `job`; else why not. The gate is Start Scan's,
    /// in Start Scan's order: the tool, then the job (missing or not finished), then an L4
    /// lane with no known Inject entry, then the first target host not in scope.
    public func scanAgainRefusal(for job: String, scopeHosts: [String], tools: [ToolDescriptor]) -> String? {
        guard ScanSurface.isOffered(in: tools) else { return "scan.start is not on this bus" }
        guard let status = statuses[job], status.state.isTerminal else { return "Select a finished job." }
        if status.lanes.requested.contains(where: \.isL4), l4InjectScopeKnown != true { return scanL4Hint }
        for origin in status.targets {
            guard let authority = ScanForm.authority(of: origin), Scope.contains(authority, in: scopeHosts) else {
                return ScanFormat.outOfScopeText(origin: origin)
            }
        }
        return nil
    }

    /// What Scan Again sends: `scan.start { profile_name, overrides: { target: { origins } } }`
    /// from the job's status, so the engine resolves the named profile and runs it against
    /// the same origins. nil when the status is missing or the job is not finished; the
    /// caller sends nothing while `scanAgainRefusal` is non-nil.
    public func scanAgainArguments(for job: String) -> (tool: String, args: [String: JSONValue])? {
        guard let status = statuses[job], status.state.isTerminal else { return nil }
        let origins = JSONValue.array(status.targets.map(JSONValue.string))
        return (ScanSurface.startTool, [
            "profile_name": .string(status.profileName),
            "overrides": .object(["target": .object(["origins": origins])]),
        ])
    }

    /// The Scan Again verb's help: `Start a new job with profile standard against
    /// 127.0.0.1:8117` (every host, joined with `, `). Without a profile name the generic
    /// help stands; without targets the `against` clause is left off.
    public static func scanAgainHelp(_ status: ScanJobStatus) -> String {
        guard !status.profileName.isEmpty else { return ScanFormat.scanAgainHelpGeneric }
        let base = "Start a new job with profile \(status.profileName)"
        return ScanFormat.hostsJoined(origins: status.targets).map { "\(base) against \($0)" } ?? base
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
    /// list does not carry yet stays in front of it. Clears `readFailure` (Jobs view
    /// D6). The selection follows the list (Jobs view D3): nothing selected → the newest
    /// job; a selection the core dropped and this app is not waiting on → the
    /// first row; an existing selection is never replaced by a newer job.
    ///
    /// Every write compares first (plan fix 1.5h): the poll re-applies the same list
    /// every 2 s, and a value that did not change is not assigned, so an identical list
    /// leaves the model equal (MS-R1, #308). The freshness stamp `jobsLoadedAt` therefore
    /// lives on `ScanPanelState`, outside the published model: it moves on every beat.
    public mutating func applyList(_ result: ScanListResult) {
        let listed = Set(result.jobs.map(\.job))
        // Only a job this app started and the core has not listed yet stays ahead of the
        // list; a job the core itself stopped listing (restart, history cap) goes with it.
        let pending = jobs.filter { !listed.contains($0.job) && locallyStarted.contains($0.job) }
        if !locallyStarted.isDisjoint(with: listed) { locallyStarted.subtract(listed) }
        let newJobs = pending + result.jobs
        if jobs != newJobs { jobs = newJobs }
        // The per-job side tables follow the list: a job the core no longer lists
        // (and this app is not waiting on) takes its seq, status, notices and flag with it.
        let kept = listed.union(locallyStarted)
        let keptSeq = lastSeq.filter { kept.contains($0.key) }
        if lastSeq != keptSeq { lastSeq = keptSeq }
        let keptStatuses = statuses.filter { kept.contains($0.key) }
        if statuses != keptStatuses { statuses = keptStatuses }
        let keptNotices = launchNotices.filter { kept.contains($0.key) }
        if launchNotices != keptNotices { launchNotices = keptNotices }
        let keptRefresh = refreshNeeded.intersection(kept)
        if refreshNeeded != keptRefresh { refreshNeeded = keptRefresh }
        if readFailure != nil { readFailure = nil }
        if let selected = selectedJob {
            if !jobs.contains(where: { $0.job == selected }), !locallyStarted.contains(selected) {
                let first = jobs.first?.job
                if selectedJob != first { selectedJob = first }
            }
        } else if let first = jobs.first {
            selectedJob = first.job
        }
    }

    /// A Jobs read (`scan.list`, `scan.status`, `scan.cancel`) that failed: `text` is the
    /// read's own wording (`Unable to list jobs: <core>` and the like), `now` the caller's
    /// clock, the same one `ScanPanelState` stamps `jobsLoadedAt` with. Records the one failure fact (Jobs view
    /// D6 amendment): `jobsError`, `readFailedAt` and `inlineJobsError(ageMs:)` all read it,
    /// and only the next list that lands clears it. The rows and their counters stay.
    /// The text carries the core's words, so it is bounded like `ScanJobStatus.error`:
    /// control and format scalars dropped, then cut to `ScanWire.detailMax` scalars.
    /// A failure repeating the stored text keeps the stored `at` and writes nothing, so
    /// a core that keeps failing does not republish the surface every beat (plan fix 1.5h).
    public mutating func noteReadFailure(text: String, now: Int) {
        let cleaned = ScanWire.cleaned(text, max: ScanWire.detailMax)
        if readFailure?.text != cleaned {
            readFailure = ScanReadFailure(text: cleaned, at: now)
        }
    }

    /// The text of the inline error above the rows: while a Jobs read has failed and no
    /// list has landed since, that read's own wording with the last-good clause, e.g.
    /// `Unable to read job scan-…: <core>. Showing values from 0:42 ago; retrying every 2 s.`
    /// (`ScanFormat.ageClause`, with `ScanJobsLink.valuesAgeMs` as the age; the list beat
    /// is what brings the values back, Jobs view D6); nil otherwise.
    public func inlineJobsError(ageMs: Int?) -> String? {
        readFailure.map { $0.text + ScanFormat.ageClause(ageMs) }
    }

    /// `scan.status`: stored, and the matching list row takes its summary; neither is
    /// written when it already holds the value (plan fix 1.5h).
    public mutating func applyStatus(_ status: ScanJobStatus) {
        if statuses[status.job] != status { statuses[status.job] = status }
        if let index = jobs.firstIndex(where: { $0.job == status.job }), jobs[index] != status.summary {
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
        scanAgainError = nil
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

    /// A Scan Again the bus refused (Jobs view D13): kept whole for the card's inline
    /// line; the Profiles footer's `statusLine` and `launchError` are not touched.
    public mutating func applyScanAgainError(_ error: ScanLaunchError) {
        scanAgainError = error
        confirm = nil
        launchInFlight = false
    }

    /// Escape on the card takes the inline Scan Again error down.
    public mutating func clearScanAgainError() {
        scanAgainError = nil
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

    public mutating func select(job: String?) {
        if selectedJob != job {
            selectedJob = job
            scanAgainError = nil
        }
    }

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
    /// The header button's title while the merged state is cancelling: disabled, and
    /// the only button whose title is not a verb (Jobs view D2).
    public static let cancellingTitle = "Cancelling…"
    /// The help on Cancel Scan and the row's hover Cancel (Jobs view D7 keeps PR 1's words).
    public static let cancelHelpText = "Stop this job; its issues stay (⌥⌘.)"

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

    /// The last-good clause a failed Jobs read's inline error ends with (Jobs view D6):
    /// `. Showing values from 0:42 ago; retrying every 2 s.` with an age; without one (no
    /// list has landed yet) `. Retrying every 2 s.`
    static func ageClause(_ ageMs: Int?) -> String {
        guard let ageMs else { return ". Retrying every 2 s." }
        return ". Showing values from \(elapsed(ms: ageMs)) ago; retrying every 2 s."
    }

    /// `Clamped budget.probes 50000 → 20000`: a `scan.start` / `scan.status` clamp notice.
    public static func clampedText(_ clamped: ScanClamped) -> String {
        "Clamped \(clamped.field) \(clamped.requested) → \(clamped.applied)"
    }

    /// `Skipped ws: lane not available on this build`: a `lanes.skipped` notice.
    public static func skippedLaneText(_ skipped: ScanSkippedLane) -> String {
        "Skipped \(skipped.lane.rawValue): \(skipped.reason)"
    }

    /// `WebSocket: lane not available on this build`: the Crawl well's `Lane skipped`
    /// row (Jobs view D11), the lane's word before the engine's reason.
    public static func skippedLaneWords(_ skipped: ScanSkippedLane) -> String {
        "\(skipped.lane.word): \(skipped.reason)"
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

    /// The hosts of the status's targets, `host[:port]` each; empty until a status lands.
    static func hostList(_ facts: ScanJobFacts) -> [String] {
        facts.status?.targets.map(hostOf(origin:)) ?? []
    }

    /// The hosts joined with `, `; nil when none are known.
    static func hosts(_ facts: ScanJobFacts) -> String? {
        hostsJoined(origins: facts.status?.targets ?? [])
    }

    /// `host[:port]` of every origin, joined with `, `; nil when there are none.
    static func hostsJoined(origins: [String]) -> String? {
        let hosts = origins.map(hostOf(origin:))
        return hosts.isEmpty ? nil : hosts.joined(separator: ", ")
    }

    /// The status's profile name; nil when there is no status or it carries none (`""`).
    static func profileName(_ facts: ScanJobFacts) -> String? {
        guard let name = facts.status?.profileName, !name.isEmpty else { return nil }
        return name
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

    /// `ok` when a canary flow guards the session, `off` when there is none: the
    /// Crawl well's Session cell (`reused · lost · canary · browser partial`, Jobs view D11).
    public static func canaryWord(_ canary: ScanCanary) -> String {
        switch canary {
        case .flow: "ok"
        case .none: "off"
        }
    }

    /// `1 endpoint` / `3 endpoints`; with `grouped`, `6,468 checks` (the end-state
    /// sentences, Jobs view D4). The one singular rule.
    public static func plural(_ n: Int, _ noun: String, grouped: Bool = false) -> String {
        "\(grouped ? Self.grouped(n) : String(n)) \(noun)\(n == 1 ? "" : "s")"
    }
}

// MARK: - The Jobs table's and the card's words (Jobs view D10, D11, D14, D17)

/// The job card's tone (Jobs view D11): one Kit value the app maps to its token
/// pair once (`ScanToneColors`). Queued and running share the progress pair,
/// cancelled is neutral (Architect's call).
public enum ScanJobTone: Equatable, Sendable { case progress, pending, success, danger, neutral }

/// The finding line under the card's heading (Jobs view D11). `parts` carry the
/// roles the view inks differently; joined, they are `text`. `reason` is the
/// stopped-reason sentence a terminal job shows above the line, nil when none.
public struct ScanFindingLine: Equatable, Sendable {
    public enum Role: Equatable, Sendable { case plain, figure, checkId, agent }

    public struct Part: Equatable, Sendable {
        public var text: String
        public var role: Role

        public init(text: String, role: Role) {
            self.text = text
            self.role = role
        }
    }

    /// The stopped-reason sentence, terminal only; nil when there is none to say.
    public var reason: String?
    /// The line's pieces in order; joined, they are `text`.
    public var parts: [Part]
    /// The line as one string (the AX value, the tests' pin).
    public var text: String
    /// Whether an MCP or agent frontend started the job (the `an agent` part is inked).
    public var agentOriginated: Bool

    public init(reason: String?, parts: [Part], text: String, agentOriginated: Bool) {
        self.reason = reason
        self.parts = parts
        self.text = text
        self.agentOriginated = agentOriginated
    }
}

/// One group of the card's issue ledger (Jobs view D11): the marks drawn, capped at
/// `ScanFormat.ledgerMarkCap`, and the count word that carries the true count.
public struct ScanLedgerGroup: Equatable, Sendable {
    public var severity: ScanSeverity
    public var count: Int
    public var marks: Int
    /// `4 low`.
    public var word: String

    public init(severity: ScanSeverity, count: Int, marks: Int, word: String) {
        self.severity = severity
        self.count = count
        self.marks = marks
        self.word = word
    }
}

extension ScanFormat {
    // MARK: Fixed words (D10, D11, D17)

    /// The table's header labels, sentence case, in column order.
    public static let tableHeaders = ["State", "Profile", "Target", "Progress", "Probes", "Points", "Issues", "Elapsed"]
    /// The KPI strip's labels, in cell order.
    public static let kpiLabels = ["Progress", "Checks", "Probes", "Points audited", "Issues"]
    public static let gaugeLabel = "probe budget"
    public static let laneCrawlLabel = "crawl"
    public static let laneAuditLabel = "audit"
    /// What a cell shows for a value the bus has not said.
    public static let missingValue = "—"
    public static let agentDotHelp = "started by an agent"
    public static let wellCrawlTitle = "Crawl and points"
    public static let wellCrawlSubtitle = "what the job found to test"
    public static let wellIssuesTitle = "Issues"
    public static let wellIssuesSubtitle = "by severity and confidence"
    /// The most marks one ledger group draws; the word carries the true count.
    public static let ledgerMarkCap = 12
    /// The help strings of the UX section, verbatim. `Stop` here is the one allowed
    /// use of the verb in a Jobs string (AC32).
    public static let cancelScanHelp = "Stop this job; the issues and site map it found stay (⌥⌘.)"
    public static let scanAgainHelpGeneric = "Start a new job with this job's profile and target"
    public static let showIssuesHelp = "Open the Issues tab filtered to this job"
    public static let showSiteMapHelp = "Open the Site map tab for this job"
    /// D13's refusal line under the card's title row: this prefix, then
    /// `ScanLaunchError.display` (AC26: `Unable to scan again: A scan on this origin is
    /// already running`).
    public static let scanAgainErrorPrefix = "Unable to scan again: "
    /// The most characters of a `started_by.client_label` the finding line shows.
    static let startedByLabelMax = 40

    /// The keys of the card's two wells (Jobs view D11), one constant each.
    public enum WellKey {
        public static let pagesFetched = "Pages fetched"
        public static let pagesWaiting = "Pages waiting"
        public static let depth = "Depth"
        public static let formsSubmitted = "Forms submitted"
        public static let formsNotSubmitted = "Forms not submitted"
        public static let crawlErrors = "Crawl errors"
        public static let pointsFound = "Points found"
        public static let waitingForAudit = "Waiting for audit"
        public static let audited = "Audited"
        public static let lanes = "Lanes"
        /// One row per `lanes.skipped` entry, valued by `skippedLaneWords`.
        public static let laneSkipped = "Lane skipped"
        public static let probesByLane = "Probes by lane"
        public static let session = "Session"
        /// The L4 lanes' own counters, one row each; shown only when the status carries `l4`.
        public static let l4Cases = "L4 cases"
        public static let l4Crashes = "L4 crashes"
        public static let l4LivenessFailures = "L4 liveness failures"
        public static let l4RetiredElements = "L4 retired elements"
        public static let criticalHighMedium = "Critical · High · Medium"
        public static let low = "Low"
        public static let info = "Info"
        public static let certainFirmTentative = "Certain · Firm · Tentative"
        public static let probeErrors = "Probe errors · timeouts · rate waits"
        public static let checks = "Checks scheduled · done · errors · skipped"

        /// Every key, in the wells' order.
        public static let all = [
            pagesFetched, pagesWaiting, depth, formsSubmitted, formsNotSubmitted, crawlErrors, pointsFound,
            waitingForAudit, audited, lanes, laneSkipped, probesByLane, session, l4Cases, l4Crashes,
            l4LivenessFailures, l4RetiredElements, criticalHighMedium, low, info, certainFirmTentative,
            probeErrors, checks,
        ]
    }

    // MARK: The row's cells (D10)

    /// The phase word while running, else the state word: `Auditing` / `Cancelling` /
    /// `Done` (P23). The chip and the State cell both read it.
    public static func stateWord(_ facts: ScanJobFacts) -> String {
        let summary = facts.summary
        return summary.state == .running ? summary.phase.word : summary.state.word
    }

    /// `standard`; `—` until the status lands or when it carries no name.
    public static func profileText(_ facts: ScanJobFacts) -> String {
        profileName(facts) ?? missingValue
    }

    /// `127.0.0.1:8117` / `a.test, b.test`; `—` until the status lands.
    public static func hostsText(_ facts: ScanJobFacts) -> String {
        hosts(facts) ?? missingValue
    }

    /// The Progress cell: `50 % · 3,236 of 6,468` while auditing with something
    /// scheduled; the pages line while crawling; `Passive checks`; `Scheduling checks`;
    /// `Writing results`; `—` while queued or before the status lands; the checks
    /// `3,236 of 6,468` when terminal (`0 of 0` is the bus truth, shown as such).
    public static func rowProgressText(_ facts: ScanJobFacts, _ progress: ScanJobProgress) -> String {
        guard let status = facts.status else { return missingValue }
        let checks = status.checks
        switch facts.summary.state {
        case .queued, .other:
            return missingValue
        case .running, .cancelling:
            switch facts.summary.phase {
            case .crawling:
                return progress.phaseLine
            case .passive:
                return "Passive checks"
            case .auditing:
                guard checks.scheduled > 0, let percent = progress.percentText else { return ScanJobProgress.schedulingLine }
                return "\(percent) · \(grouped(checks.done)) of \(grouped(checks.scheduled))"
            case .reporting:
                return ScanJobProgress.reportingLine
            case .queued, .done, .other:
                return progress.phaseLine
            }
        case .done, .cancelled, .failed:
            return "\(grouped(checks.done)) of \(grouped(checks.scheduled))"
        }
    }

    /// `4 low` / `1 high, 3 low`; `no issues yet` for a live job with none, `no issues` otherwise.
    public static func severityWords(by: BySeverity, running: Bool) -> String {
        let parts = severityWordParts(by: by)
        guard !parts.isEmpty else { return running ? "no issues yet" : "no issues" }
        return parts.map(\.1).joined(separator: ", ")
    }

    /// `[(.high, "1 high"), (.low, "3 low")]`, critical → info, zero counts omitted;
    /// the view inks each in its severity's colour.
    public static func severityWordParts(by: BySeverity) -> [(ScanSeverity, String)] {
        severityCounts(by).map { ($0, "\(grouped($1)) \($0.rawValue)") }
    }

    /// The non-zero tallies, critical → info.
    static func severityCounts(_ by: BySeverity) -> [(ScanSeverity, Int)] {
        [ScanSeverity.critical, .high, .medium, .low, .info].compactMap { severity in
            let count = by.count(severity)
            return count > 0 ? (severity, count) : nil
        }
    }

    /// `4 jobs · 1 running` / `1 job` / `3 jobs`: the table container's accessibility label.
    public static func jobsCaption(total: Int, running: Int) -> String {
        let jobs = plural(total, "job", grouped: true)
        return running > 0 ? "\(jobs) · \(grouped(running)) running" : jobs
    }

    // MARK: The card's heading and finding line (D11)

    /// The hosts: `127.0.0.1:8117` / `a.test, b.test` / `a.test and 2 more`; `—` until known.
    public static func jobHeading(_ facts: ScanJobFacts) -> String {
        let hosts = hostList(facts)
        guard let first = hosts.first else { return missingValue }
        return hosts.count >= 3 ? "\(first) and \(hosts.count - 1) more" : hosts.joined(separator: ", ")
    }

    /// The full host list for the heading's help when three or more are cut to `and n more`.
    public static func jobHeadingHelp(_ facts: ScanJobFacts) -> String? {
        let hosts = hostList(facts)
        return hosts.count >= 3 ? hosts.joined(separator: ", ") : nil
    }

    /// Whether an MCP or agent frontend started the job.
    public static func agentOriginated(_ by: ScanStartedBy) -> Bool {
        by.frontend == "mcp" || by.frontend == "agent"
    }

    /// Who started the job: `this app` (the mac app's own client label), `the CLI`,
    /// `an agent`, an operator client's label (control and format scalars stripped,
    /// cut to 40 characters), else `the operator`.
    public static func startedByWords(_ by: ScanStartedBy) -> String {
        let label = by.clientLabel.map { ScanWire.cleaned($0, max: startedByLabelMax) } ?? ""
        if label == "aitm-mac" { return "this app" }
        if by.frontend == "cli" { return "the CLI" }
        if agentOriginated(by) { return "an agent" }
        if by.frontend == "operator", !label.isEmpty { return label }
        return "the operator"
    }

    /// `HH:mm`, 24-hour, of an epoch-millisecond stamp in the given zone.
    public static func clock(ms: Int, timeZone: TimeZone) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let parts = calendar.dateComponents([.hour, .minute], from: Date(timeIntervalSince1970: Double(ms) / 1000))
        return String(format: "%02ld:%02ld", parts.hour ?? 0, parts.minute ?? 0)
    }

    /// `no issues so far` / `4 low issues so far` / `1 high issue so far` / `5 issues so far: 1 high, 4 low`.
    public static func issuesSoFar(by: BySeverity) -> String {
        issuesSoFarParts(by).map(\.text).joined()
    }

    static func issuesSoFarParts(_ by: BySeverity) -> [ScanFindingLine.Part] {
        let counts = severityCounts(by)
        guard !counts.isEmpty else { return [plain("no issues so far")] }
        if counts.count == 1, let (severity, count) = counts.first {
            return [figure(count), plain(" \(severity.rawValue) issue\(count == 1 ? "" : "s") so far")]
        }
        var parts = [figure(by.total), plain(" issues so far: ")]
        for (index, (severity, count)) in counts.enumerated() {
            if index > 0 { parts.append(plain(", ")) }
            parts.append(figure(count))
            parts.append(plain(" \(severity.rawValue)"))
        }
        return parts
    }

    /// `xss-reflected running now` / `xss-reflected and 3 more checks running now`; nil when nothing runs.
    public static func nowClause(running: [String]) -> String? {
        nowClauseParts(running)?.map(\.text).joined()
    }

    static func nowClauseParts(_ running: [String]) -> [ScanFindingLine.Part]? {
        guard let first = running.first else { return nil }
        let more = running.count - 1
        guard more > 0 else { return [checkId(first), plain(" running now")] }
        return [checkId(first), plain(" and \(more) more check\(more == 1 ? "" : "s") running now")]
    }

    private static func plain(_ text: String) -> ScanFindingLine.Part { .init(text: text, role: .plain) }
    private static func figure(_ n: Int) -> ScanFindingLine.Part { .init(text: grouped(n), role: .figure) }
    private static func checkId(_ id: String) -> ScanFindingLine.Part { .init(text: id, role: .checkId) }

    /// The finding line (Jobs view D11). Live: `<issues so far> · <now clause> ·
    /// <profile> · started <h:mm> by <who>`; terminal: `<profile> · started <h:mm> by
    /// <who> · finished <h:mm>` with the stopped-reason sentence as `reason`. The
    /// clauses the status carries wait for it: before it lands a live line is the
    /// issues clause alone and a terminal line is empty. A status without
    /// `started_at` reads `started by <who>`.
    public static func findingLine(_ facts: ScanJobFacts, timeZone: TimeZone) -> ScanFindingLine {
        let summary = facts.summary
        let terminal = summary.state.isTerminal
        var clauses: [[ScanFindingLine.Part]] = []
        var agent = false
        var reason: String?
        if !terminal { clauses.append(issuesSoFarParts(summary.issues.bySeverity)) }
        if let status = facts.status {
            if !terminal, let now = nowClauseParts(status.checks.running) { clauses.append(now) }
            clauses.append([plain(profileText(facts))])
            agent = agentOriginated(status.startedBy)
            let when = status.startedAt > 0 ? " \(clock(ms: status.startedAt, timeZone: timeZone))" : ""
            clauses.append([
                plain("started\(when) by "), .init(text: startedByWords(status.startedBy), role: agent ? .agent : .plain),
            ])
            if terminal {
                if let finishedAt = status.finishedAt, finishedAt > 0 {
                    clauses.append([plain("finished \(clock(ms: finishedAt, timeZone: timeZone))")])
                }
                if let stopped = status.stoppedReason {
                    reason = ScanEndText.stoppedReason(
                        stopped, state: summary.state, probesBudget: summary.probes.budget, error: status.error)
                }
            }
        }
        var parts: [ScanFindingLine.Part] = []
        for (index, clause) in clauses.enumerated() {
            if index > 0 { parts.append(plain(" · ")) }
            parts += clause
        }
        return ScanFindingLine(
            reason: reason, parts: parts, text: parts.map(\.text).joined(), agentOriginated: agent)
    }

    // MARK: Tone, ledger, gauge, lane and KPI words (D11)

    /// Queued and running → `.progress`; cancelling → `.pending`; done → `.success`;
    /// failed → `.danger`; cancelled and an unknown state → `.neutral`.
    public static func tone(_ facts: ScanJobFacts) -> ScanJobTone {
        switch facts.summary.state {
        case .queued, .running: .progress
        case .cancelling: .pending
        case .done: .success
        case .failed: .danger
        case .cancelled, .other: .neutral
        }
    }

    /// One group per non-zero severity, critical → info, `marks = min(count, 12)`, `word = "4 low"`.
    public static func ledgerGroups(by: BySeverity) -> [ScanLedgerGroup] {
        severityCounts(by).map { severity, count in
            ScanLedgerGroup(
                severity: severity, count: count, marks: min(count, ledgerMarkCap), word: "\(grouped(count)) \(severity.rawValue)")
        }
    }

    /// The gauge turns amber past 80 % of a known budget.
    public static func budgetWarning(sent: Int, budget: Int) -> Bool {
        budget > 0 && Double(sent) > 0.8 * Double(budget)
    }

    /// `287 of 2,000`; `287 probes` when the budget is unknown (`0`).
    public static func probeBudgetText(sent: Int, budget: Int) -> String {
        budget > 0 ? "\(grouped(sent)) of \(grouped(budget))" : plural(sent, "probe", grouped: true)
    }

    /// `287 of 2,000 probes sent (the probe budget, not progress)`; `287 probes sent (…)` without a budget.
    public static func probesTileHelp(sent: Int, budget: Int) -> String {
        let count = budget > 0 ? "\(grouped(sent)) of \(grouped(budget)) probes" : plural(sent, "probe", grouped: true)
        return "\(count) sent (the probe budget, not progress)"
    }

    /// `4 issues: 1 high, 3 low` / `no issues`: the ledger's and the Issues KPI cell's help.
    public static func issuesTileHelp(by: BySeverity) -> String {
        let parts = severityWordParts(by: by)
        guard !parts.isEmpty else { return "no issues" }
        return "\(plural(by.total, "issue", grouped: true)): \(parts.map(\.1).joined(separator: ", "))"
    }

    /// `of 6,468`: the unit after a KPI or cell numeral.
    public static func ofText(_ n: Int) -> String { "of \(grouped(n))" }

    /// `3,236 checks done`: the audit segment's lower label.
    public static func laneChecksDone(_ done: Int) -> String { plural(done, "check", grouped: true) + " done" }

    /// `46 pages` / `1 page`: the crawl segment's lower label.
    public static func lanePages(_ pages: Int) -> String { plural(pages, "page", grouped: true) }

    /// `started 11:32`: the scale row's first entry.
    public static func scaleStarted(_ clock: String) -> String { "started \(clock)" }

    /// `elapsed 1:04`: the scale row's second entry.
    public static func scaleElapsed(ms: Int) -> String { "elapsed \(elapsed(ms: ms))" }

    /// The Crawl well's skipped-points rows, one per reason, zeros included:
    /// `722 skipped as repetitive`, `6 skipped by rule`, `0 skipped at the per-request cap`.
    public static func pointSkipWords(_ skipped: ScanPointCounters.Skipped) -> [String] {
        [
            "\(grouped(skipped.frequent)) skipped as repetitive",
            "\(grouped(skipped.ignored)) skipped by rule",
            "\(grouped(skipped.limit)) skipped at the per-request cap",
        ]
    }

    // MARK: Accessibility (D14)

    /// `1 minute 4 seconds` / `42 seconds` / `1 hour 2 minutes 3 seconds`; zero
    /// components are left out, `0 seconds` for nothing.
    public static func elapsedWords(ms: Int) -> String {
        let total = max(0, ms) / 1000
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        let seconds = total % 60
        var parts: [String] = []
        if hours > 0 { parts.append(plural(hours, "hour")) }
        if minutes > 0 { parts.append(plural(minutes, "minute")) }
        if seconds > 0 || parts.isEmpty { parts.append(plural(seconds, "second")) }
        return parts.joined(separator: " ")
    }

    /// `50 percent` for a determinate progress (the lane's accessibility value); nil otherwise.
    public static func progressAccessibilityValue(_ progress: ScanJobProgress) -> String? {
        progress.percentText.map { $0.replacingOccurrences(of: "\u{00A0}%", with: " percent") }
    }

    /// The row as one sentence: `Auditing, standard, 127.0.0.1:8117, 50 percent, 3,236
    /// of 6,468 checks, 4 issues: 4 low, 1 minute 4 seconds.` The percent and the
    /// progress line only when the progress is determinate; the profile and hosts only
    /// once the status has said them.
    public static func jobAccessibilityLabel(_ facts: ScanJobFacts) -> String {
        let summary = facts.summary
        let progress = ScanJobProgress(facts)
        var parts = [stateWord(facts)]
        if let name = profileName(facts) { parts.append(name) }
        if let hosts = hosts(facts) { parts.append(hosts) }
        if let percent = progressAccessibilityValue(progress) {
            parts.append(percent)
            parts.append(progress.phaseLine)
        }
        let by = summary.issues.bySeverity
        parts.append(by.total > 0 ? issuesTileHelp(by: by) : severityWords(by: by, running: !summary.state.isTerminal))
        parts.append(elapsedWords(ms: summary.elapsedMs))
        return parts.joined(separator: ", ") + "."
    }

    /// The one VoiceOver announcement when the selected job ends: `Scan of
    /// 127.0.0.1:8117 done: 4 issues.` / `… cancelled: no issues.` / `… failed.`
    /// The job id names the scan while no host is known.
    public static func endAnnouncement(_ facts: ScanJobFacts) -> String {
        let subject = hostList(facts).isEmpty ? "Scan \(facts.job)" : "Scan of \(jobHeading(facts))"
        let by = facts.summary.issues.bySeverity
        let issues = by.total > 0 ? plural(by.total, "issue", grouped: true) : "no issues"
        switch facts.summary.state {
        case .done: return "\(subject) done: \(issues)."
        case .cancelled: return "\(subject) cancelled: \(issues)."
        case .failed: return "\(subject) failed."
        default: return "\(subject) \(facts.summary.state.rawValue)."
        }
    }
}
