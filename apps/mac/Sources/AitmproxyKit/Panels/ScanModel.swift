import AitmBusClient
import Foundation

// The scanner v2 wire types (scanner-v2 mac surface, spec D15): every `scan.*`
// verb result and the `notifications/aitm/job` push line, decoded as the bus
// delivers them. The shapes are `crates/aitm-scan-model` (serde `snake_case`);
// this file reads them and never redesigns them. Each type decodes with
// `init(json:)`, throwing `BusError.malformed` for a non-object or a missing
// required key; an optional field tolerates absence and `null`, a counter
// absent from a tally reads as 0 (the crate's `#[serde(default)]`), and an
// unknown vocabulary string lands in `.other` so a newer core never breaks a
// row. No SwiftUI, so tests run without the app.

// Vocabularies

/// A closed wire vocabulary with an escape hatch: the known cases, plus
/// `other(String)` carrying any string this build does not know. `init?(rawValue:)`
/// never returns nil, and `rawValue` gives back the wire spelling either way.
/// Equality and hashing go through `rawValue` (the standard library's
/// `RawRepresentable` witnesses), so each enum spells both as plain switches.
public protocol ScanVocabulary: RawRepresentable, Hashable, Sendable where RawValue == String {
    /// The case an unknown string lands in.
    static func other(_ raw: String) -> Self
}

/// `JobState`: where a job is in its life.
public enum ScanJobState: ScanVocabulary {
    case queued, running, cancelling, done, cancelled, failed
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "queued": self = .queued
        case "running": self = .running
        case "cancelling": self = .cancelling
        case "done": self = .done
        case "cancelled": self = .cancelled
        case "failed": self = .failed
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .queued: "queued"
        case .running: "running"
        case .cancelling: "cancelling"
        case .done: "done"
        case .cancelled: "cancelled"
        case .failed: "failed"
        case .other(let raw): raw
        }
    }

    /// Done, cancelled or failed: nothing more will happen to the job.
    public var isTerminal: Bool {
        switch self {
        case .done, .cancelled, .failed: true
        default: false
        }
    }

    /// The status word the Jobs row shows (spec D12); an unknown state shows as it came.
    public var word: String {
        switch self {
        case .queued: "Queued"
        case .running: "Running"
        case .cancelling: "Cancelling"
        case .done: "Done"
        case .cancelled: "Cancelled"
        case .failed: "Failed"
        case .other(let raw): raw
        }
    }
}

/// `Phase`: which stage a running job is in.
public enum ScanPhase: ScanVocabulary {
    case queued, crawling, passive, auditing, reporting, done
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "queued": self = .queued
        case "crawling": self = .crawling
        case "passive": self = .passive
        case "auditing": self = .auditing
        case "reporting": self = .reporting
        case "done": self = .done
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .queued: "queued"
        case .crawling: "crawling"
        case .passive: "passive"
        case .auditing: "auditing"
        case .reporting: "reporting"
        case .done: "done"
        case .other(let raw): raw
        }
    }

    public var word: String {
        switch self {
        case .queued: "Queued"
        case .crawling: "Crawling"
        case .passive: "Passive"
        case .auditing: "Auditing"
        case .reporting: "Reporting"
        case .done: "Done"
        case .other(let raw): raw
        }
    }
}

/// `StoppedReason`: why a job ended before its work ran out.
public enum ScanStoppedReason: ScanVocabulary {
    case budget, time, cancelled, sessionLost, errors, policy, guardRefused, failed
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "budget": self = .budget
        case "time": self = .time
        case "cancelled": self = .cancelled
        case "session_lost": self = .sessionLost
        case "errors": self = .errors
        case "policy": self = .policy
        case "guard_refused": self = .guardRefused
        case "failed": self = .failed
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .budget: "budget"
        case .time: "time"
        case .cancelled: "cancelled"
        case .sessionLost: "session_lost"
        case .errors: "errors"
        case .policy: "policy"
        case .guardRefused: "guard_refused"
        case .failed: "failed"
        case .other(let raw): raw
        }
    }
}

/// `LaneKind`: which protocol lane a point, check, probe or issue belongs to.
public enum ScanLane: ScanVocabulary {
    case http, ws, l4Packet, l4Stream
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "http": self = .http
        case "ws": self = .ws
        case "l4_packet": self = .l4Packet
        case "l4_stream": self = .l4Stream
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .http: "http"
        case .ws: "ws"
        case .l4Packet: "l4_packet"
        case .l4Stream: "l4_stream"
        case .other(let raw): raw
        }
    }

    public var word: String {
        switch self {
        case .http: "HTTP"
        case .ws: "WebSocket"
        case .l4Packet: "L4 packet"
        case .l4Stream: "L4 stream"
        case .other(let raw): raw
        }
    }

    /// The two lanes that need an L4 scope entry before they may run.
    public var isL4: Bool {
        switch self {
        case .l4Packet, .l4Stream: true
        default: false
        }
    }
}

/// `Intensity`: how invasive a check or profile may be, least first.
public enum ScanIntensity: ScanVocabulary {
    case passive, light, medium, intrusive
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "passive": self = .passive
        case "light": self = .light
        case "medium": self = .medium
        case "intrusive": self = .intrusive
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .passive: "passive"
        case .light: "light"
        case .medium: "medium"
        case .intrusive: "intrusive"
        case .other(let raw): raw
        }
    }

    /// 0 (passive) to 3 (intrusive); an unknown intensity sorts last.
    public var rank: Int {
        switch self {
        case .passive: 0
        case .light: 1
        case .medium: 2
        case .intrusive: 3
        case .other: 99
        }
    }
}

/// `Speed`: the time-versus-coverage dial.
public enum ScanSpeed: ScanVocabulary {
    case fast, normal, thorough
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "fast": self = .fast
        case "normal": self = .normal
        case "thorough": self = .thorough
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .fast: "fast"
        case .normal: "normal"
        case .thorough: "thorough"
        case .other(let raw): raw
        }
    }
}

/// `Accuracy`: which way the scheduler leans on an uncertain verdict.
public enum ScanAccuracy: ScanVocabulary {
    case fewerFalseNegatives, normal, fewerFalsePositives
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "fewer_false_negatives": self = .fewerFalseNegatives
        case "normal": self = .normal
        case "fewer_false_positives": self = .fewerFalsePositives
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .fewerFalseNegatives: "fewer_false_negatives"
        case .normal: "normal"
        case .fewerFalsePositives: "fewer_false_positives"
        case .other(let raw): raw
        }
    }
}

/// `Confidence`: how sure a verdict is, least first.
public enum ScanConfidence: ScanVocabulary {
    case tentative, firm, certain
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "tentative": self = .tentative
        case "firm": self = .firm
        case "certain": self = .certain
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .tentative: "tentative"
        case .firm: "firm"
        case .certain: "certain"
        case .other(let raw): raw
        }
    }

    /// 0 (tentative) to 2 (certain); an unknown confidence sorts last.
    public var rank: Int {
        switch self {
        case .tentative: 0
        case .firm: 1
        case .certain: 2
        case .other: 99
        }
    }

    public var word: String {
        switch self {
        case .tentative: "Tentative"
        case .firm: "Firm"
        case .certain: "Certain"
        case .other(let raw): raw
        }
    }
}

/// `IssueStatus`: an issue's triage state.
public enum ScanIssueStatus: ScanVocabulary {
    case open, confirmed, falsePositive
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "open": self = .open
        case "confirmed": self = .confirmed
        case "false_positive": self = .falsePositive
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .open: "open"
        case .confirmed: "confirmed"
        case .falsePositive: "false_positive"
        case .other(let raw): raw
        }
    }

    public var word: String {
        switch self {
        case .open: "Open"
        case .confirmed: "Confirmed"
        case .falsePositive: "False positive"
        case .other(let raw): raw
        }
    }
}

/// `aitm_poc::Severity` as the scanner spells it, with the Kit's `Severity`
/// one step away so the app reuses its severity colours.
public enum ScanSeverity: ScanVocabulary {
    case critical, high, medium, low, info
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "critical": self = .critical
        case "high": self = .high
        case "medium": self = .medium
        case "low": self = .low
        case "info": self = .info
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .critical: "critical"
        case .high: "high"
        case .medium: "medium"
        case .low: "low"
        case .info: "info"
        case .other(let raw): raw
        }
    }

    /// 0 (critical) to 4 (info); an unknown severity sorts last.
    public var rank: Int {
        switch self {
        case .critical: 0
        case .high: 1
        case .medium: 2
        case .low: 3
        case .info: 4
        case .other: 99
        }
    }

    /// The Kit's `Severity` for a known level; nil for one this build does not know.
    public var known: Severity? {
        switch self {
        case .critical: Severity.critical
        case .high: Severity.high
        case .medium: Severity.medium
        case .low: Severity.low
        case .info: Severity.info
        case .other: nil
        }
    }

    public var word: String {
        switch self {
        case .critical: "Critical"
        case .high: "High"
        case .medium: "Medium"
        case .low: "Low"
        case .info: "Info"
        case .other(let raw): raw
        }
    }
}

/// `SessionMode`: whether a job reuses the operator's observed session.
public enum ScanSessionMode: ScanVocabulary {
    case observed, none
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "observed": self = .observed
        case "none": self = .none
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .observed: "observed"
        case .none: "none"
        case .other(let raw): raw
        }
    }
}

/// `OnLost`: what a job does when its session canary fails.
public enum ScanOnLost: ScanVocabulary {
    case stop, `continue`
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "stop": self = .stop
        case "continue": self = .continue
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .stop: "stop"
        case .continue: "continue"
        case .other(let raw): raw
        }
    }
}

/// `JobEvent`: what a push line reports.
public enum ScanJobEvent: ScanVocabulary {
    case started, phase, progress, issue, finished, cancelled, failed
    case other(String)

    public init?(rawValue: String) {
        switch rawValue {
        case "started": self = .started
        case "phase": self = .phase
        case "progress": self = .progress
        case "issue": self = .issue
        case "finished": self = .finished
        case "cancelled": self = .cancelled
        case "failed": self = .failed
        default: self = .other(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .started: "started"
        case .phase: "phase"
        case .progress: "progress"
        case .issue: "issue"
        case .finished: "finished"
        case .cancelled: "cancelled"
        case .failed: "failed"
        case .other(let raw): raw
        }
    }

    /// Finished, cancelled or failed: the job's last line.
    public var isTerminal: Bool {
        switch self {
        case .finished, .cancelled, .failed: true
        default: false
        }
    }
}

/// `CheckOrigin`: where a check came from, a `{kind, path?}` object on the wire.
public enum ScanCheckOrigin: Hashable, Sendable {
    case native
    case bundled(path: String)
    case custom(path: String)
    case other(kind: String)

    public var word: String {
        switch self {
        case .native: "native"
        case .bundled: "bundled"
        case .custom: "custom"
        case .other(let kind): kind
        }
    }

    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanCheckOrigin")
        let kind = try wire.string("kind")
        switch kind {
        case "native": self = .native
        case "bundled": self = .bundled(path: try wire.string("path"))
        case "custom": self = .custom(path: try wire.string("path"))
        default: self = .other(kind: kind)
        }
    }
}

/// `Canary`: how a job checks its session is still alive. `none`, or one flow
/// (`GET /account` expecting 200) replayed between probes.
public enum ScanCanary: Hashable, Sendable {
    case none
    case flow(method: String, path: String, expectedStatus: Int?)

    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanCanary")
        let kind = try wire.string("kind")
        switch kind {
        case "none":
            self = .none
        case "flow":
            self = .flow(
                method: try wire.string("method"), path: try wire.string("path"),
                expectedStatus: try wire.optionalInt("expected_status"))
        default:
            throw BusError.malformed("ScanCanary has an unknown kind `\(kind)`")
        }
    }
}

// Reading the wire

/// The object a wire type is read from, with the type's name for error text.
/// `null` reads as absent everywhere, so an optional field tolerates both; a
/// value of the wrong JSON type is malformed, never coerced.
struct ScanWire {
    let type: String
    let members: [String: JSONValue]

    init(_ json: JSONValue, as type: String) throws {
        guard case .object(let members) = json else {
            throw BusError.malformed("\(type) is not an object")
        }
        self.type = type
        self.members = members
    }

    /// The value under `key`; nil when absent or `null`.
    subscript(key: String) -> JSONValue? {
        guard let value = members[key], !value.isNull else { return nil }
        return value
    }

    /// The value under `key` verbatim (`null` included); `.null` when absent.
    func value(_ key: String) -> JSONValue { members[key] ?? .null }

    private func missing(_ key: String) -> BusError { .malformed("\(type) needs `\(key)`") }
    private func wrong(_ key: String, _ expected: String) -> BusError {
        .malformed("\(type).\(key) is not \(expected)")
    }

    func string(_ key: String) throws -> String {
        guard let value = self[key] else { throw missing(key) }
        guard let text = value.stringValue else { throw wrong(key, "a string") }
        return text
    }

    func optionalString(_ key: String) throws -> String? {
        guard let value = self[key] else { return nil }
        guard let text = value.stringValue else { throw wrong(key, "a string") }
        return text
    }

    /// The largest whole number a wire field may carry: 2^53, the last integer a
    /// JSON double represents exactly. Every count, port and epoch-millisecond
    /// stamp the scanner sends is non-negative and far below it, so a value
    /// outside `0...2^53` is malformed, never stored: the tallies are added
    /// (`BySeverity.total`) and the stamps subtracted (`ScanFormat.relative`),
    /// and a full-range `Int` would trap there.
    static let wholeNumberRange: ClosedRange<Int> = 0...9_007_199_254_740_992

    /// `value` as a whole number in `wholeNumberRange`, or the malformed error for `key`.
    private func whole(_ value: JSONValue, _ key: String, _ expected: String = "a whole number") throws -> Int {
        guard let number = value.intValue else { throw wrong(key, expected) }
        guard Self.wholeNumberRange.contains(number) else {
            throw wrong(key, "\(expected) in 0...9007199254740992")
        }
        return number
    }

    func int(_ key: String) throws -> Int {
        guard let value = self[key] else { throw missing(key) }
        return try whole(value, key)
    }

    /// A counter: absent reads as `fallback` (the crate's `#[serde(default)]`).
    func int(_ key: String, default fallback: Int) throws -> Int {
        try optionalInt(key) ?? fallback
    }

    func optionalInt(_ key: String) throws -> Int? {
        guard let value = self[key] else { return nil }
        return try whole(value, key)
    }

    func uint64(_ key: String) throws -> UInt64 {
        guard let value = self[key] else { throw missing(key) }
        guard let number = value.doubleValue, let whole = UInt64(exactly: number) else {
            throw wrong(key, "a whole number")
        }
        return whole
    }

    func double(_ key: String) throws -> Double {
        guard let value = self[key] else { throw missing(key) }
        guard let number = value.doubleValue else { throw wrong(key, "a number") }
        return number
    }

    func bool(_ key: String) throws -> Bool {
        guard let value = self[key] else { throw missing(key) }
        guard let flag = value.boolValue else { throw wrong(key, "a boolean") }
        return flag
    }

    func bool(_ key: String, default fallback: Bool) throws -> Bool {
        try optionalBool(key) ?? fallback
    }

    func optionalBool(_ key: String) throws -> Bool? {
        guard let value = self[key] else { return nil }
        guard let flag = value.boolValue else { throw wrong(key, "a boolean") }
        return flag
    }

    /// An array field; absent reads as empty.
    func array(_ key: String) throws -> [JSONValue] {
        try optionalArray(key) ?? []
    }

    func optionalArray(_ key: String) throws -> [JSONValue]? {
        guard let value = self[key] else { return nil }
        guard let items = value.arrayValue else { throw wrong(key, "an array") }
        return items
    }

    func strings(_ key: String) throws -> [String] {
        try optionalStrings(key) ?? []
    }

    func optionalStrings(_ key: String) throws -> [String]? {
        try optionalArray(key)?.map { item in
            guard let text = item.stringValue else { throw wrong(key, "an array of strings") }
            return text
        }
    }

    func ints(_ key: String) throws -> [Int] {
        try array(key).map { try whole($0, key, "an array of whole numbers") }
    }

    func doubles(_ key: String) throws -> [Double] {
        try array(key).map { item in
            guard let number = item.doubleValue else { throw wrong(key, "an array of numbers") }
            return number
        }
    }

    /// A required nested object, handed on to its own `init(json:)`.
    func object(_ key: String) throws -> JSONValue {
        guard let value = try optionalObject(key) else { throw missing(key) }
        return value
    }

    func optionalObject(_ key: String) throws -> JSONValue? {
        guard let value = self[key] else { return nil }
        guard case .object = value else { throw wrong(key, "an object") }
        return value
    }

    /// An object of whole numbers (`by_lane`); absent reads as empty.
    func counts(_ key: String) throws -> [String: Int] {
        guard let value = try optionalObject(key)?.objectValue else { return [:] }
        return try value.mapValues { try whole($0, key, "an object of whole numbers") }
    }

    func vocab<V: ScanVocabulary>(_ key: String) throws -> V {
        let raw = try string(key)
        return V(rawValue: raw) ?? V.other(raw)
    }

    func optionalVocab<V: ScanVocabulary>(_ key: String) throws -> V? {
        guard let raw = try optionalString(key) else { return nil }
        return V(rawValue: raw) ?? V.other(raw)
    }

    func vocabs<V: ScanVocabulary>(_ key: String) throws -> [V] {
        try strings(key).map { V(rawValue: $0) ?? V.other($0) }
    }

    /// A canary; absent or `null` is `.none`.
    func canary(_ key: String) throws -> ScanCanary {
        guard let value = self[key] else { return .none }
        return try ScanCanary(json: value)
    }
}

// Counters and parts

/// `ProbeCounters`: probes sent against the budget.
public struct ScanProbeCounters: Hashable, Sendable {
    public var sent: Int
    public var budget: Int
    public var errors: Int
    public var timeouts: Int
    public var rateWaits: Int
    /// Probes per lane, keyed by the lane's wire name.
    public var byLane: [String: Int]
}

extension ScanProbeCounters {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanProbeCounters")
        sent = try wire.int("sent", default: 0)
        budget = try wire.int("budget", default: 0)
        errors = try wire.int("errors", default: 0)
        timeouts = try wire.int("timeouts", default: 0)
        rateWaits = try wire.int("rate_waits", default: 0)
        byLane = try wire.counts("by_lane")
    }
}

/// `CrawlCounters`: how far the crawl got.
public struct ScanCrawlCounters: Hashable, Sendable {
    public var pages: Int
    public var queued: Int
    public var depth: Int
    public var formsSubmitted: Int
}

extension ScanCrawlCounters {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanCrawlCounters")
        pages = try wire.int("pages", default: 0)
        queued = try wire.int("queued", default: 0)
        depth = try wire.int("depth", default: 0)
        formsSubmitted = try wire.int("forms_submitted", default: 0)
    }
}

/// `PointCounters`: insertion points found, waiting and audited.
public struct ScanPointCounters: Hashable, Sendable {
    /// `SkippedPoints`: why points were left out.
    public struct Skipped: Hashable, Sendable {
        public var ignored: Int
        public var frequent: Int
        public var limit: Int
    }

    public var found: Int
    public var queued: Int
    public var audited: Int
    public var skipped: Skipped
}

extension ScanPointCounters.Skipped {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanPointCounters.Skipped")
        ignored = try wire.int("ignored", default: 0)
        frequent = try wire.int("frequent", default: 0)
        limit = try wire.int("limit", default: 0)
    }
}

extension ScanPointCounters {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanPointCounters")
        found = try wire.int("found", default: 0)
        queued = try wire.int("queued", default: 0)
        audited = try wire.int("audited", default: 0)
        skipped = try wire.optionalObject("skipped").map { try Skipped(json: $0) }
            ?? Skipped(ignored: 0, frequent: 0, limit: 0)
    }
}

/// `CheckCounters`: checks scheduled, done and running right now.
public struct ScanCheckCounters: Hashable, Sendable {
    public var scheduled: Int
    public var done: Int
    /// The ids of the checks in flight (the engine caps this at 8).
    public var running: [String]
}

extension ScanCheckCounters {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanCheckCounters")
        scheduled = try wire.int("scheduled", default: 0)
        done = try wire.int("done", default: 0)
        running = try wire.strings("running")
    }
}

/// `BySeverity`: an issue tally per severity.
public struct BySeverity: Hashable, Sendable {
    public var critical: Int
    public var high: Int
    public var medium: Int
    public var low: Int
    public var info: Int

    public var total: Int { critical + high + medium + low + info }

    /// The tally for one severity; 0 for one this build does not know.
    public func count(_ severity: ScanSeverity) -> Int {
        switch severity {
        case .critical: critical
        case .high: high
        case .medium: medium
        case .low: low
        case .info: info
        case .other: 0
        }
    }

    public static let zero = BySeverity(critical: 0, high: 0, medium: 0, low: 0, info: 0)
}

extension BySeverity {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "BySeverity")
        critical = try wire.int("critical", default: 0)
        high = try wire.int("high", default: 0)
        medium = try wire.int("medium", default: 0)
        low = try wire.int("low", default: 0)
        info = try wire.int("info", default: 0)
    }
}

/// `ByConfidence`: an issue tally per confidence.
public struct ByConfidence: Hashable, Sendable {
    public var certain: Int
    public var firm: Int
    public var tentative: Int

    public static let zero = ByConfidence(certain: 0, firm: 0, tentative: 0)
}

extension ByConfidence {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ByConfidence")
        certain = try wire.int("certain", default: 0)
        firm = try wire.int("firm", default: 0)
        tentative = try wire.int("tentative", default: 0)
    }
}

/// `IssueCounters`: the issues a job has raised so far.
public struct ScanIssueCounters: Hashable, Sendable {
    public var total: Int
    public var bySeverity: BySeverity
    public var byConfidence: ByConfidence
}

extension ScanIssueCounters {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanIssueCounters")
        total = try wire.int("total", default: 0)
        bySeverity = try wire.optionalObject("by_severity").map { try BySeverity(json: $0) } ?? .zero
        byConfidence = try wire.optionalObject("by_confidence").map { try ByConfidence(json: $0) } ?? .zero
    }
}

/// `L4Counters`: the L4 lanes' own counters, present only when one ran.
public struct ScanL4Counters: Hashable, Sendable {
    public var cases: Int
    public var crashes: Int
    public var livenessFailures: Int
    public var retiredElements: Int
}

extension ScanL4Counters {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanL4Counters")
        cases = try wire.int("cases", default: 0)
        crashes = try wire.int("crashes", default: 0)
        livenessFailures = try wire.int("liveness_failures", default: 0)
        retiredElements = try wire.int("retired_elements", default: 0)
    }
}

/// `SessionStatus`: whether the job reused the operator's session and still has it.
public struct ScanSessionStatus: Hashable, Sendable {
    public var reused: Bool
    public var lost: Bool
    public var canary: ScanCanary
    /// The browser ran without the session (it could not take the cookies).
    public var browserPartial: Bool
}

extension ScanSessionStatus {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanSessionStatus")
        reused = try wire.bool("reused", default: false)
        lost = try wire.bool("lost", default: false)
        canary = try wire.canary("canary")
        browserPartial = try wire.bool("browser_partial", default: false)
    }
}

/// `SkippedLane`: a requested lane that did not run, and why.
public struct ScanSkippedLane: Hashable, Sendable {
    public var lane: ScanLane
    public var reason: String
}

extension ScanSkippedLane {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanSkippedLane")
        lane = try wire.vocab("lane")
        reason = try wire.string("reason")
    }
}

/// `LaneReport`: the lanes asked for, the lanes that run, and the rest.
public struct ScanLaneReport: Hashable, Sendable {
    public var requested: [ScanLane]
    public var run: [ScanLane]
    public var skipped: [ScanSkippedLane]
}

extension ScanLaneReport {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanLaneReport")
        requested = try wire.vocabs("requested")
        run = try wire.vocabs("run")
        skipped = try wire.array("skipped").map { try ScanSkippedLane(json: $0) }
    }
}

/// `Clamped`: a profile value the engine lowered to a configured ceiling.
/// Not an error; the job detail shows it as a one-line notice.
public struct ScanClamped: Hashable, Sendable {
    /// The profile path, e.g. `budget.probes`.
    public var field: String
    public var requested: Int
    public var applied: Int

    public init(field: String, requested: Int, applied: Int) {
        self.field = field
        self.requested = requested
        self.applied = applied
    }
}

extension ScanClamped {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanClamped")
        self.init(
            field: try wire.string("field"), requested: try wire.int("requested"), applied: try wire.int("applied"))
    }
}

/// `StartedBy`: which frontend launched the job.
public struct ScanStartedBy: Hashable, Sendable {
    /// `operator` or `agent`.
    public var frontend: String
    public var clientLabel: String?
}

extension ScanStartedBy {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanStartedBy")
        frontend = try wire.optionalString("frontend") ?? ""
        clientLabel = try wire.optionalString("client_label")
    }
}

// Jobs

/// `JobSummary`: the Jobs row and the push line's counters. Every number here
/// is a `scan.list` or `scan.status` value; the app never computes one.
public struct ScanJobSummary: Hashable, Sendable {
    public var job: String
    public var state: ScanJobState
    public var phase: ScanPhase
    public var elapsedMs: Int
    public var probes: ScanProbeCounters
    public var points: ScanPointCounters
    public var issues: ScanIssueCounters
}

extension ScanJobSummary {
    public init(json: JSONValue) throws {
        try self.init(wire: ScanWire(json, as: "ScanJobSummary"))
    }

    init(wire: ScanWire) throws {
        job = try wire.string("job")
        state = try wire.vocab("state")
        phase = try wire.vocab("phase")
        elapsedMs = try wire.int("elapsed_ms", default: 0)
        probes = try ScanProbeCounters(json: wire.object("probes"))
        points = try ScanPointCounters(json: wire.object("points"))
        issues = try ScanIssueCounters(json: wire.object("issues"))
    }
}

/// `JobStatus`: everything `scan.status` and `scan.cancel` say about one job (spec D5).
public struct ScanJobStatus: Hashable, Sendable {
    public var job: String
    public var state: ScanJobState
    public var phase: ScanPhase
    public var profileName: String
    public var targets: [String]
    public var startedBy: ScanStartedBy
    /// Epoch milliseconds.
    public var startedAt: Int
    public var finishedAt: Int?
    public var elapsedMs: Int
    public var stoppedReason: ScanStoppedReason?
    public var probes: ScanProbeCounters
    public var crawl: ScanCrawlCounters
    public var points: ScanPointCounters
    public var checks: ScanCheckCounters
    public var issues: ScanIssueCounters
    public var l4: ScanL4Counters?
    public var session: ScanSessionStatus?
    public var lanes: ScanLaneReport
    public var clamped: [ScanClamped]
    /// The failure text when `state` is `failed`.
    public var error: String?

    /// The row's view of this status.
    public var summary: ScanJobSummary {
        ScanJobSummary(
            job: job, state: state, phase: phase, elapsedMs: elapsedMs, probes: probes, points: points, issues: issues)
    }
}

extension ScanJobStatus {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanJobStatus")
        job = try wire.string("job")
        state = try wire.vocab("state")
        phase = try wire.vocab("phase")
        profileName = try wire.optionalString("profile_name") ?? ""
        targets = try wire.strings("targets")
        startedBy = try ScanStartedBy(json: wire.object("started_by"))
        startedAt = try wire.int("started_at", default: 0)
        finishedAt = try wire.optionalInt("finished_at")
        elapsedMs = try wire.int("elapsed_ms", default: 0)
        stoppedReason = try wire.optionalVocab("stopped_reason")
        probes = try ScanProbeCounters(json: wire.object("probes"))
        crawl = try ScanCrawlCounters(json: wire.object("crawl"))
        points = try ScanPointCounters(json: wire.object("points"))
        checks = try ScanCheckCounters(json: wire.object("checks"))
        issues = try ScanIssueCounters(json: wire.object("issues"))
        l4 = try wire.optionalObject("l4").map { try ScanL4Counters(json: $0) }
        session = try wire.optionalObject("session").map { try ScanSessionStatus(json: $0) }
        lanes = try ScanLaneReport(json: wire.object("lanes"))
        clamped = try wire.array("clamped").map { try ScanClamped(json: $0) }
        error = try wire.optionalString("error")
    }
}

/// `StartResult`: what `scan.start` and `scan.map` return the moment the job is accepted.
public struct ScanStartResult: Hashable, Sendable {
    public var job: String
    public var status: ScanJobStatus
    public var clamped: [ScanClamped]
    public var lanes: ScanLaneReport
    /// Present only for a profile with an L4 lane: it plans its cases without sending them.
    public var dryRun: Bool?
}

extension ScanStartResult {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanStartResult")
        job = try wire.string("job")
        status = try ScanJobStatus(json: wire.object("status"))
        clamped = try wire.array("clamped").map { try ScanClamped(json: $0) }
        lanes = try ScanLaneReport(json: wire.object("lanes"))
        dryRun = try wire.optionalBool("dry_run")
    }
}

/// `ListResult`: `scan.list`, newest job first.
public struct ScanListResult: Hashable, Sendable {
    public var jobs: [ScanJobSummary]
}

extension ScanListResult {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanListResult")
        jobs = try wire.array("jobs").map { try ScanJobSummary(json: $0) }
    }
}

// Issues

/// `IssueTarget`: the origin an issue was found on.
public struct ScanTarget: Hashable, Sendable {
    public var scheme: String
    public var host: String
    public var port: Int

    /// `http://127.0.0.1:8080`.
    public var origin: String { "\(scheme)://\(host):\(port)" }
}

extension ScanTarget {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanTarget")
        scheme = try wire.string("scheme")
        host = try wire.string("host")
        port = try wire.int("port")
    }
}

/// `L4Location`: where an L4 issue sits.
public struct ScanL4Location: Hashable, Sendable {
    public var ip: String
    public var port: Int
    /// `tcp` or `udp`.
    public var proto: String
    public var grammar: String?
    public var fieldPath: String?
    public var mutation: String?
}

extension ScanL4Location {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanL4Location")
        ip = try wire.string("ip")
        port = try wire.int("port")
        proto = try wire.string("proto")
        grammar = try wire.optionalString("grammar")
        fieldPath = try wire.optionalString("field_path")
        mutation = try wire.optionalString("mutation")
    }
}

/// `IssueLocation`: where inside the request an issue sits (spec D6).
public struct ScanIssueLocation: Hashable, Sendable {
    public var method: String?
    public var path: String
    public var pathTemplate: String
    /// The insertion kind's wire name (`query`, `json_value`, ...).
    public var kind: String
    public var name: String
    public var fieldPath: String?
    public var wsPath: String?
    public var l4: ScanL4Location?
}

extension ScanIssueLocation {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanIssueLocation")
        method = try wire.optionalString("method")
        path = try wire.string("path")
        pathTemplate = try wire.string("path_template")
        kind = try wire.string("kind")
        name = try wire.string("name")
        fieldPath = try wire.optionalString("field_path")
        wsPath = try wire.optionalString("ws_path")
        l4 = try wire.optionalObject("l4").map { try ScanL4Location(json: $0) }
    }
}

/// `Timing`: the delays a timing check asked for against what it measured.
public struct ScanTiming: Hashable, Sendable {
    public var requestedS: [Double]
    public var observedMs: [Int]
    public var baselineMs: [Int]
    public var slope: Double
    public var r: Double
}

extension ScanTiming {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanTiming")
        requestedS = try wire.doubles("requested_s")
        observedMs = try wire.ints("observed_ms")
        baselineMs = try wire.ints("baseline_ms")
        slope = try wire.double("slope")
        r = try wire.double("r")
    }
}

/// `Diff`: response lengths behind a boolean verdict.
public struct ScanDiff: Hashable, Sendable {
    public var baselineLen: Int
    public var trueLen: Int
    public var falseLen: Int
}

extension ScanDiff {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanDiff")
        baselineLen = try wire.int("baseline_len")
        trueLen = try wire.int("true_len")
        falseLen = try wire.int("false_len")
    }
}

/// `L4Evidence`: what an L4 lane sent and saw. `reproduced` is the crate's
/// `(hits, tries)` pair, a two-element array on the wire.
public struct ScanL4Evidence: Hashable, Sendable {
    public var sentHex: String
    public var seedId: String
    public var rngSeed: Int
    public var mutationChain: [String]
    public var priorMessages: Int
    /// The `L4Oracle` object verbatim (`{kind, ...}`); the detail shows its `kind`.
    public var oracle: JSONValue
    public var livenessBefore: Bool
    public var livenessAfter: Bool
    public var reproducedHits: Int
    public var reproducedTries: Int
    public var scopeEntry: String
}

extension ScanL4Evidence {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanL4Evidence")
        sentHex = try wire.string("sent_hex")
        seedId = try wire.string("seed_id")
        rngSeed = try wire.int("rng_seed")
        mutationChain = try wire.strings("mutation_chain")
        priorMessages = try wire.int("prior_messages")
        oracle = wire.value("oracle")
        livenessBefore = try wire.bool("liveness_before")
        livenessAfter = try wire.bool("liveness_after")
        let reproduced = try wire.ints("reproduced")
        guard reproduced.count == 2 else {
            throw BusError.malformed("ScanL4Evidence.reproduced is not a [hits, tries] pair")
        }
        reproducedHits = reproduced[0]
        reproducedTries = reproduced[1]
        scopeEntry = try wire.string("scope_entry")
    }
}

/// `Evidence`: what supports an issue. Every field is optional; a passive
/// finding may carry only `matched`.
public struct ScanEvidence: Hashable, Sendable {
    public var payload: String?
    public var matched: String?
    /// The flows the probes ran in; each opens in the inspector.
    public var probeFlows: [String]
    public var baselineFlow: String?
    public var timing: ScanTiming?
    public var diff: ScanDiff?
    public var l4: ScanL4Evidence?
}

extension ScanEvidence {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanEvidence")
        payload = try wire.optionalString("payload")
        matched = try wire.optionalString("matched")
        probeFlows = try wire.strings("probe_flows")
        baselineFlow = try wire.optionalString("baseline_flow")
        timing = try wire.optionalObject("timing").map { try ScanTiming(json: $0) }
        diff = try wire.optionalObject("diff").map { try ScanDiff(json: $0) }
        l4 = try wire.optionalObject("l4").map { try ScanL4Evidence(json: $0) }
    }
}

/// `IssueSummary`: an issue without its evidence and prose, as `scan.issues`
/// and the `issue` push line carry it (spec D6).
public struct ScanIssueSummary: Hashable, Sendable {
    public var id: String
    public var job: String
    public var checkId: String
    /// The weakness class (`reflected-xss`, `sqli-error`, ...); `class` on the wire.
    public var klass: String
    public var name: String
    public var severity: ScanSeverity
    public var confidence: ScanConfidence
    public var status: ScanIssueStatus
    public var lane: ScanLane
    public var target: ScanTarget
    public var location: ScanIssueLocation
    /// Epoch milliseconds.
    public var firstSeen: Int
    public var lastSeen: Int
    public var occurrences: Int
    public var pocRef: String?
    public var findingId: String?
}

extension ScanIssueSummary {
    public init(json: JSONValue) throws {
        try self.init(wire: ScanWire(json, as: "ScanIssueSummary"))
    }

    init(wire: ScanWire) throws {
        id = try wire.string("id")
        job = try wire.string("job")
        checkId = try wire.string("check_id")
        klass = try wire.string("class")
        name = try wire.string("name")
        severity = try wire.vocab("severity")
        confidence = try wire.vocab("confidence")
        status = try wire.vocab("status")
        lane = try wire.vocab("lane")
        target = try ScanTarget(json: wire.object("target"))
        location = try ScanIssueLocation(json: wire.object("location"))
        firstSeen = try wire.int("first_seen")
        lastSeen = try wire.int("last_seen")
        occurrences = try wire.int("occurrences")
        pocRef = try wire.optionalString("poc_ref")
        findingId = try wire.optionalString("finding_id")
    }
}

/// `Issue`: the full finding `scan.issue` and `scan.issue.update` return (spec D6).
/// The list's fields live in `summary`, parsed once; the evidence and prose are
/// what the detail adds. Every summary field is also reachable directly
/// (`issue.severity`, `issue.occurrences = 2`) through dynamic member lookup, so
/// a view reads a detail and a row the same way.
@dynamicMemberLookup
public struct ScanIssue: Hashable, Sendable {
    /// The list's view of this issue: every field `scan.issues` carries.
    public var summary: ScanIssueSummary
    public var evidence: ScanEvidence
    public var description: String
    public var remediation: String?
    /// The operator's triage note, set through `scan.issue.update`.
    public var note: String?

    public init(
        summary: ScanIssueSummary, evidence: ScanEvidence, description: String, remediation: String?, note: String?
    ) {
        self.summary = summary
        self.evidence = evidence
        self.description = description
        self.remediation = remediation
        self.note = note
    }

    /// The summary's fields, read and written in place (`issue.id`, `issue.status = .confirmed`).
    public subscript<T>(dynamicMember keyPath: WritableKeyPath<ScanIssueSummary, T>) -> T {
        get { summary[keyPath: keyPath] }
        set { summary[keyPath: keyPath] = newValue }
    }
}

extension ScanIssue {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanIssue")
        summary = try ScanIssueSummary(wire: wire)
        evidence = try ScanEvidence(json: wire.object("evidence"))
        description = try wire.string("description")
        remediation = try wire.optionalString("remediation")
        note = try wire.optionalString("note")
    }
}

/// `IssuesResult`: one page of `scan.issues` and the tally over the whole filtered set.
public struct ScanIssuesResult: Hashable, Sendable {
    public var issues: [ScanIssueSummary]
    /// Pass back for the next page; nil on the last.
    public var nextCursor: String?
    public var bySeverity: BySeverity
}

extension ScanIssuesResult {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanIssuesResult")
        issues = try wire.array("issues").map { try ScanIssueSummary(json: $0) }
        nextCursor = try wire.optionalString("next_cursor")
        bySeverity = try wire.optionalObject("by_severity").map { try BySeverity(json: $0) } ?? .zero
    }
}

// Site map

/// `ParamRef`: a parameter a site node was seen with.
public struct ScanParamRef: Hashable, Sendable {
    public var kind: String
    public var name: String
}

extension ScanParamRef {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanParamRef")
        kind = try wire.string("kind")
        name = try wire.string("name")
    }
}

/// `SiteNode`: one method + templated path the crawl reached.
public struct ScanSiteNode: Hashable, Sendable {
    public var id: String
    public var method: String
    public var scheme: String
    public var host: String
    public var port: Int
    /// The path with volatile segments templated (`/account/{id}`).
    public var pathTemplate: String
    public var flows: [String]
    public var params: [ScanParamRef]
    /// The node was seen with session material.
    public var auth: Bool
    /// How many insertion points sit on it.
    public var points: Int
    public var audited: Bool

    /// `http://127.0.0.1:8080`.
    public var origin: String { "\(scheme)://\(host):\(port)" }
}

extension ScanSiteNode {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanSiteNode")
        id = try wire.string("id")
        method = try wire.string("method")
        scheme = try wire.string("scheme")
        host = try wire.string("host")
        port = try wire.int("port")
        pathTemplate = try wire.string("path_template")
        flows = try wire.strings("flows")
        params = try wire.array("params").map { try ScanParamRef(json: $0) }
        auth = try wire.bool("auth", default: false)
        points = try wire.int("points", default: 0)
        audited = try wire.bool("audited", default: false)
    }
}

/// `InsertionPoint`: one place a probe can go. `example` arrives already
/// redacted (`<redacted>` for a cookie or secret-named value) and is shown verbatim.
public struct ScanInsertionPoint: Hashable, Sendable {
    public var id: String
    /// The lane's wire name.
    public var lane: String
    /// The insertion kind's wire name.
    public var kind: String
    public var name: String
    /// The field path inside a structured body.
    public var path: String?
    public var example: String?
    public var flow: String?
    public var siteNode: String?
    public var traits: [String]
    /// How many requests carried this point.
    public var frequency: Int
    public var method: String?
    public var url: String?
}

extension ScanInsertionPoint {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanInsertionPoint")
        id = try wire.string("id")
        lane = try wire.string("lane")
        kind = try wire.string("kind")
        name = try wire.string("name")
        path = try wire.optionalString("path")
        example = try wire.optionalString("example")
        flow = try wire.optionalString("flow")
        siteNode = try wire.optionalString("site_node")
        traits = try wire.strings("traits")
        frequency = try wire.int("frequency")
        method = try wire.optionalString("method")
        url = try wire.optionalString("url")
    }
}

/// `SitemapResult`: one page of `scan.sitemap`.
public struct ScanSitemapResult: Hashable, Sendable {
    public var nodes: [ScanSiteNode]
    public var points: [ScanInsertionPoint]
    public var nextCursor: String?
}

extension ScanSitemapResult {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanSitemapResult")
        nodes = try wire.array("nodes").map { try ScanSiteNode(json: $0) }
        points = try wire.array("points").map { try ScanInsertionPoint(json: $0) }
        nextCursor = try wire.optionalString("next_cursor")
    }
}

// Checks

/// `CheckMeta`: one entry of the unified check catalogue (spec D4), native and script alike.
public struct ScanCheckMeta: Hashable, Sendable {
    public var id: String
    public var name: String
    /// The weakness class; `class` on the wire.
    public var klass: String
    public var lanes: [ScanLane]
    /// The insertion kinds the check applies to, by wire name.
    public var kinds: [String]
    public var intensity: ScanIntensity
    /// `light`, `medium` or `heavy`.
    public var cost: String
    public var technique: String
    public var severity: ScanSeverity
    public var confidenceMax: ScanConfidence
    public var needsBaseline: Bool
    public var wantsTraits: [String]?
    public var targetsSession: Bool
    public var cwe: Int?
    public var description: String
    public var remediation: String?
    public var origin: ScanCheckOrigin
}

extension ScanCheckMeta {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanCheckMeta")
        id = try wire.string("id")
        name = try wire.string("name")
        klass = try wire.string("class")
        lanes = try wire.vocabs("lanes")
        kinds = try wire.strings("kinds")
        intensity = try wire.vocab("intensity")
        cost = try wire.string("cost")
        technique = try wire.string("technique")
        severity = try wire.vocab("severity")
        confidenceMax = try wire.vocab("confidence_max")
        needsBaseline = try wire.bool("needs_baseline", default: false)
        wantsTraits = try wire.optionalStrings("wants_traits")
        targetsSession = try wire.bool("targets_session", default: false)
        cwe = try wire.optionalInt("cwe")
        description = try wire.string("description")
        remediation = try wire.optionalString("remediation")
        origin = try ScanCheckOrigin(json: wire.object("origin"))
    }
}

/// `ChecksResult`: `scan.checks`.
public struct ScanChecksResult: Hashable, Sendable {
    public var checks: [ScanCheckMeta]
}

extension ScanChecksResult {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanChecksResult")
        checks = try wire.array("checks").map { try ScanCheckMeta(json: $0) }
    }
}

// Profiles

/// `CheckSelection`: the check ids a profile adds and removes.
public struct ScanCheckSelection: Hashable, Sendable {
    public var include: [String]
    public var exclude: [String]

    public func json() -> JSONValue {
        .object(["include": .array(include.map(JSONValue.string)), "exclude": .array(exclude.map(JSONValue.string))])
    }
}

extension ScanCheckSelection {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanCheckSelection")
        include = try wire.strings("include")
        exclude = try wire.strings("exclude")
    }
}

/// `Budget`: the profile's spend limits. `per_host_errors` is kept verbatim;
/// the editor does not touch it.
public struct ScanBudget: Hashable, Sendable {
    public var probes: Int
    public var timeS: Int
    public var maxIssues: Int
    public var checkTimeoutS: Int
    public var perHostErrors: JSONValue

    public func json() -> JSONValue {
        .object([
            "probes": .number(Double(probes)),
            "time_s": .number(Double(timeS)),
            "max_issues": .number(Double(maxIssues)),
            "check_timeout_s": .number(Double(checkTimeoutS)),
            "per_host_errors": perHostErrors,
        ])
    }
}

extension ScanBudget {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanBudget")
        probes = try wire.int("probes")
        timeS = try wire.int("time_s")
        maxIssues = try wire.int("max_issues")
        checkTimeoutS = try wire.int("check_timeout_s")
        perHostErrors = try wire.optionalObject("per_host_errors") ?? .object([:])
    }
}

/// `SessionOptions`: whether and how a job reuses the operator's session.
public struct ScanSessionOptions: Hashable, Sendable {
    public var mode: ScanSessionMode
    public var fromFlow: String?
    public var onLost: ScanOnLost

    /// Re-encodes as the crate serialises it: an absent `from_flow` is `null`, not omitted.
    public func json() -> JSONValue {
        .object([
            "mode": .string(mode.rawValue),
            "from_flow": fromFlow.map(JSONValue.string) ?? .null,
            "on_lost": .string(onLost.rawValue),
        ])
    }
}

extension ScanSessionOptions {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanSessionOptions")
        mode = try wire.vocab("mode")
        fromFlow = try wire.optionalString("from_flow")
        onLost = try wire.vocab("on_lost")
    }
}

/// `ProfileTarget`: the origins to scan and the L4 targets. The L4 list is
/// kept verbatim (`[{ip, port, proto, grammar?}]`); the editor shows it read-only.
public struct ScanProfileTarget: Hashable, Sendable {
    public var origins: [String]
    public var l4: JSONValue

    /// `ip:port/proto` per L4 entry, for the read-only rows; an entry missing one of the three is left out.
    public var l4Rows: [String] {
        (l4.arrayValue ?? []).compactMap { entry in
            guard let ip = entry["ip"]?.stringValue, let port = entry["port"]?.intValue,
                  let proto = entry["proto"]?.stringValue else { return nil }
            return "\(ip):\(port)/\(proto)"
        }
    }

    public func json() -> JSONValue {
        .object(["origins": .array(origins.map(JSONValue.string)), "l4": l4])
    }
}

extension ScanProfileTarget {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanProfileTarget")
        origins = try wire.strings("origins")
        l4 = try wire.optionalArray("l4").map(JSONValue.array) ?? .array([])
    }
}

/// `ScanProfile`: the one knob an operator turns (spec D2). The editor edits
/// `name`, `target`, `lanes`, the three dials, `checks`, `budget` and `session`;
/// the five sections it never edits (`crawl`, `audit`, `http`, `ws`, `l4`) and any
/// key this build does not know pass through `json()` verbatim, so a save never
/// drops what a newer core added.
public struct ScanProfile: Hashable, Sendable {
    public var name: String
    public var target: ScanProfileTarget
    public var lanes: [ScanLane]
    public var intensity: ScanIntensity
    public var speed: ScanSpeed
    public var accuracy: ScanAccuracy
    public var checks: ScanCheckSelection
    public var budget: ScanBudget
    public var session: ScanSessionOptions
    public var crawl: JSONValue?
    public var audit: JSONValue?
    public var http: JSONValue?
    public var ws: JSONValue?
    public var l4: JSONValue?
    /// Top-level keys this build does not know, kept for `json()`.
    public var extra: [String: JSONValue]

    static let editedKeys: Set<String> = [
        "name", "target", "lanes", "intensity", "speed", "accuracy", "checks", "budget", "session",
    ]
    static let passThroughKeys: Set<String> = ["crawl", "audit", "http", "ws", "l4"]

    /// An L4 lane is in the profile, so the launch needs an L4 scope entry.
    public var hasL4Lane: Bool { lanes.contains { $0.isL4 } }
    public var isIntrusive: Bool { intensity == .intrusive }

    /// The whole profile as `scan.profile.save` takes it.
    public func json() -> JSONValue {
        var members = extra
        members["name"] = .string(name)
        members["target"] = target.json()
        members["lanes"] = .array(lanes.map { .string($0.rawValue) })
        members["intensity"] = .string(intensity.rawValue)
        members["speed"] = .string(speed.rawValue)
        members["accuracy"] = .string(accuracy.rawValue)
        members["checks"] = checks.json()
        members["budget"] = budget.json()
        members["session"] = session.json()
        members["crawl"] = crawl
        members["audit"] = audit
        members["http"] = http
        members["ws"] = ws
        members["l4"] = l4
        return .object(members)
    }
}

extension ScanProfile {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanProfile")
        name = try wire.optionalString("name") ?? ""
        target = try ScanProfileTarget(json: wire.object("target"))
        lanes = try wire.vocabs("lanes")
        intensity = try wire.vocab("intensity")
        speed = try wire.vocab("speed")
        accuracy = try wire.vocab("accuracy")
        checks = try ScanCheckSelection(json: wire.object("checks"))
        budget = try ScanBudget(json: wire.object("budget"))
        session = try ScanSessionOptions(json: wire.object("session"))
        crawl = wire.members["crawl"]
        audit = wire.members["audit"]
        http = wire.members["http"]
        ws = wire.members["ws"]
        l4 = wire.members["l4"]
        extra = wire.members.filter { !Self.editedKeys.contains($0.key) && !Self.passThroughKeys.contains($0.key) }
    }
}

/// `ProfileListEntry`: one `scan.profile.list` row, with its `summary` dials flattened.
public struct ScanProfileListEntry: Hashable, Sendable {
    public var name: String
    /// Ships with aitmproxy; cannot be saved over or deleted.
    public var builtin: Bool
    public var lanes: [ScanLane]
    public var intensity: ScanIntensity
    public var speed: ScanSpeed
}

extension ScanProfileListEntry {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanProfileListEntry")
        name = try wire.string("name")
        builtin = try wire.bool("builtin")
        let summary = try ScanWire(wire.object("summary"), as: "ScanProfileListEntry.summary")
        lanes = try summary.vocabs("lanes")
        intensity = try summary.vocab("intensity")
        speed = try summary.vocab("speed")
    }
}

/// `ProfileListResult`: `scan.profile.list`, built-ins first.
public struct ScanProfileListResult: Hashable, Sendable {
    public var profiles: [ScanProfileListEntry]
}

extension ScanProfileListResult {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanProfileListResult")
        profiles = try wire.array("profiles").map { try ScanProfileListEntry(json: $0) }
    }
}

/// `ProfileSaveResult`: `scan.profile.save`.
public struct ScanProfileSaveResult: Hashable, Sendable {
    public var saved: String
    /// `<findings.dir>/scan/profiles/<name>.yaml`.
    public var path: String
}

extension ScanProfileSaveResult {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanProfileSaveResult")
        saved = try wire.string("saved")
        path = try wire.string("path")
    }
}

/// `ProfileDeleteResult`: `scan.profile.delete`; `false` means there was nothing to delete.
public struct ScanProfileDeleteResult: Hashable, Sendable {
    public var deleted: Bool
}

extension ScanProfileDeleteResult {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanProfileDeleteResult")
        deleted = try wire.bool("deleted")
    }
}

// Session and push

/// `SessionProfile`: `scan.session.preview`. Names only: the cookie and header
/// names the job would reuse, never a value (spec D7).
public struct ScanSessionProfile: Hashable, Sendable {
    public var origin: String
    public var cookies: [String]
    public var headers: [String]
    public var sourceFlow: String?
    /// Epoch milliseconds.
    public var observedAt: Int
    public var canary: ScanCanary
}

extension ScanSessionProfile {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanSessionProfile")
        origin = try wire.string("origin")
        cookies = try wire.strings("cookies")
        headers = try wire.strings("headers")
        sourceFlow = try wire.optionalString("source_flow")
        observedAt = try wire.int("observed_at")
        canary = try wire.canary("canary")
    }
}

/// `JobNotification`: the params of one `notifications/aitm/job` line. A push
/// is a trigger, not the truth: the model refreshes from `scan.status` when a
/// line arrives and never updates a counter from `status` here.
public struct ScanJobNotification: Hashable, Sendable {
    public static let method = "notifications/aitm/job"

    public var job: String
    /// `scan` for a scanner job; the line is generic over job kinds.
    public var kind: String
    public var event: ScanJobEvent
    /// Starts at 1 and rises within a job; a gap is a coalesced line.
    public var seq: UInt64
    /// Epoch milliseconds.
    public var tsMs: Int
    public var status: ScanJobSummary
    /// Carried on an `issue` line only.
    public var issue: ScanIssueSummary?
}

extension ScanJobNotification {
    public init(json: JSONValue) throws {
        let wire = try ScanWire(json, as: "ScanJobNotification")
        job = try wire.string("job")
        kind = try wire.string("kind")
        event = try wire.vocab("event")
        seq = try wire.uint64("seq")
        tsMs = try wire.int("ts_ms")
        status = try ScanJobSummary(json: wire.object("status"))
        issue = try wire.optionalObject("issue").map { try ScanIssueSummary(json: $0) }
    }
}
