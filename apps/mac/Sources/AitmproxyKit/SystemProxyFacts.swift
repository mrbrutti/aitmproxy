import AitmBusClient
import Foundation

/// The core's verdict on the system proxy (spec 2026-10-31-system-proxy-automation-design §D6,
/// §D12, §D13): the compact `proxy.status.system_proxy` object the app polls, or the full
/// `proxy.system.status` result (the same keys plus `guidance` and `remedy`). `SystemProxyState`
/// is the endpoint half; this type adds the verb's word and the flags that decide the buttons —
/// whether the app set the proxy (`managedByUs`), whether a change is in flight (`setting`),
/// whether this platform has a mechanism at all (`supported`). `ConnectionSummary.make` reads it
/// as the system-proxy route's source whenever it is present (D1: the verb's answer wins over the
/// `CFNetworkCopySystemProxySettings` read).
///
/// Pure data, `Hashable` and `Sendable`, no SwiftUI. The polling and the two mutating calls live
/// in `Session`; this type never shells out and never calls a verb.
public struct SystemProxyFacts: Hashable, Sendable {
    /// §D6's `state` word.
    public enum Word: String, Hashable, Sendable, CaseIterable {
        case pointsAtUs = "points_at_us"
        case other
        case off
        case unsupported
        case needsPrivilege = "needs_privilege"
        case unknown
    }

    public var word: Word
    /// The endpoints, via `SystemProxyState(compact:listenAddress:)`: nil for the three words that
    /// name no endpoint (`unsupported`, `needsPrivilege`, `unknown`), for an `other` at our own
    /// address (§D6's partial case, which two equal endpoints cannot express) and for an `other`
    /// without a usable host and port.
    public var state: SystemProxyState?
    /// §D6 `managed_by_us`: the app's own set is what the services still read back. Nil when the
    /// object lacks the key (or it is not a boolean); the text then drops the "· set outside the
    /// app" suffix and no Restore button is offered.
    public var managedByUs: Bool?
    /// §D6 `setting`: a set or unset is in flight. Absent → false.
    public var setting: Bool
    /// §D6 `supported` (`mechanism != none`). Absent on the wire → **false**: the core always sends
    /// the key, so a missing one is not a yes, and no surface may offer Set as System Proxy on the
    /// strength of a gap. The memberwise init defaults it to true, because a value a surface builds
    /// by hand is a complete fact.
    public var supported: Bool
    /// §D6 `detail`, the core's one-line account. Absent → "".
    public var detail: String
    /// §D6 `remedy`: the privilege sentence when `needs_privilege` (the full object only; the
    /// compact one carries no such key). Blank or absent → nil.
    public var remedy: String?
    /// §D6 `guidance`: the env-var line when `unsupported` (the full object only). Blank or absent → nil.
    public var guidance: String?

    public init(word: Word, state: SystemProxyState? = nil, managedByUs: Bool? = nil, setting: Bool = false,
                supported: Bool = true, detail: String = "", remedy: String? = nil, guidance: String? = nil) {
        self.word = word
        self.state = state
        self.managedByUs = managedByUs
        self.setting = setting
        self.supported = supported
        self.detail = detail
        self.remedy = remedy
        self.guidance = guidance
    }

    /// From the compact `proxy.status.system_proxy` object or the full `proxy.system.status`
    /// result. Nil unless `compact` is an object with a string `state`; a state word this build
    /// does not know is `.unknown` (never off, never ours). Values of the wrong type read as
    /// absent; each property documents its absent value.
    public init?(compact: JSONValue, listenAddress: String) {
        guard let members = compact.objectValue, let stateWord = members["state"]?.stringValue else { return nil }
        self.init(
            word: Word(rawValue: stateWord) ?? .unknown,
            state: SystemProxyState(compact: compact, listenAddress: listenAddress),
            managedByUs: members["managed_by_us"]?.boolValue,
            setting: members["setting"]?.boolValue ?? false,
            supported: members["supported"]?.boolValue ?? false,
            detail: members["detail"]?.stringValue ?? "",
            remedy: SystemProxyFacts.sentence(members["remedy"]),
            guidance: SystemProxyFacts.sentence(members["guidance"]))
    }

    /// A string with something in it, trimmed; nil for null, a non-string, or blank.
    private static func sentence(_ value: JSONValue?) -> String? {
        guard let text = value?.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty else { return nil }
        return text
    }
}
