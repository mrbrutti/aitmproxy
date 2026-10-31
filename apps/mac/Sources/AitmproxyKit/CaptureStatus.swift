import AitmBusClient
import Foundation

/// What the read-only `capture.status` bus verb returns (spec
/// 2026-10-31-capture-status-verb-design, D7): the core-side feeder's own account of
/// the macOS capture path. Whether the core's config on-switch is on, whether the
/// feeder's sockets are bound, whether a provider is attached (and signed by which
/// team), the scope it was last pushed, and how many flows it has handed to ingress.
/// Times on the wire are Unix epoch milliseconds; `null` means none.
///
/// This is the *core's* view. It is deliberately not the app's own capture capability
/// enum, which the host app derives from the system-extension and tunnel state; the UI
/// layer folds the two. Decoding this type changes nothing anywhere.
public struct CaptureStatus: Hashable, Sendable {
    /// `feeder.state` on the wire. A state this build does not know decodes as
    /// `.unknown`, never as a decode failure, so a newer core still reports.
    public enum Feeder: Hashable, Sendable {
        /// The feeder is not running. `reason` is one of the core's four pinned strings
        /// (the config on-switch is off, not a macOS build, not started, stopped), or nil
        /// when the core sent none.
        case off(reason: String?)
        /// The capture sockets are bound and the rendezvous is published.
        case listening
        /// The bind failed; terminal for this run. `reason` is the core's text.
        case bindFailed(reason: String)
        /// A newer core's state.
        case unknown(state: String)
    }

    /// The core's derived capability, as the wire string names it. Deliberately not the
    /// app's own capability enum: the UI layer folds the two.
    public enum CoreCapability: Hashable, Sendable {
        case feederOff, awaitingProvider, approvedAttached, capturing, degraded
        /// A wire name this build does not know (a newer core); `wire` gives it back verbatim.
        case unknown(String)

        /// The five wire names the verb emits; anything else is `.unknown(wire)`.
        public init(wire: String) {
            switch wire {
            case "feeder_off": self = .feederOff
            case "awaiting_provider": self = .awaitingProvider
            case "approved_attached": self = .approvedAttached
            case "capturing": self = .capturing
            case "degraded": self = .degraded
            default: self = .unknown(wire)
            }
        }

        /// The inverse of `init(wire:)`; `.unknown(s)` is `s`.
        public var wire: String {
            switch self {
            case .feederOff: "feeder_off"
            case .awaitingProvider: "awaiting_provider"
            case .approvedAttached: "approved_attached"
            case .capturing: "capturing"
            case .degraded: "degraded"
            case .unknown(let wire): wire
            }
        }
    }

    /// Whether the core's config on-switch for the capture path is on.
    public var enabled: Bool
    public var feeder: Feeder
    /// `provider.state == "attached"`: a code-signature-verified provider holds the control channel.
    public var providerAttached: Bool
    public var attachedAt: Date?
    /// The Apple team id the provider's code signature was verified against (the
    /// requirement's pinned OU); not read from the peer's signing information. Nil when
    /// detached or when the verifier pins no team.
    public var teamID: String?
    /// The scope tokens last pushed to the provider; `scopeTokens.count` is the count.
    public var scopeTokens: [String]
    public var tcpHandedOff: Int
    public var udpHandedOff: Int
    public var lastHandoffAt: Date?
    public var capability: CoreCapability
    public var capabilityReason: String?

    public init(enabled: Bool, feeder: Feeder, providerAttached: Bool = false, attachedAt: Date? = nil, teamID: String? = nil,
                scopeTokens: [String] = [], tcpHandedOff: Int = 0, udpHandedOff: Int = 0, lastHandoffAt: Date? = nil,
                capability: CoreCapability, capabilityReason: String? = nil) {
        self.enabled = enabled
        self.feeder = feeder
        self.providerAttached = providerAttached
        self.attachedAt = attachedAt
        self.teamID = teamID
        self.scopeTokens = scopeTokens
        self.tcpHandedOff = tcpHandedOff
        self.udpHandedOff = udpHandedOff
        self.lastHandoffAt = lastHandoffAt
        self.capability = capability
        self.capabilityReason = capabilityReason
    }

    /// Nil unless `json` is a `capture.status` object: it must carry `enabled` (Bool),
    /// `feeder.state` (String) and `capability` (String). `scope_entries` is not decoded.
    public init?(json: JSONValue) {
        guard let enabled = json["enabled"]?.boolValue,
              let feederState = json["feeder"]?["state"]?.stringValue,
              let capability = json["capability"]?.stringValue else { return nil }
        let feederReason = json["feeder"]?["reason"]?.stringValue
        let feeder: Feeder
        switch feederState {
        case "off": feeder = .off(reason: feederReason)
        case "listening": feeder = .listening
        case "bind_failed": feeder = .bindFailed(reason: feederReason ?? "")
        default: feeder = .unknown(state: feederState)
        }
        let provider = json["provider"]
        let handoffs = json["flows_handed_off"]
        self.init(
            enabled: enabled,
            feeder: feeder,
            providerAttached: provider?["state"]?.stringValue == "attached",
            attachedAt: Self.date(provider?["attached_at"]),
            teamID: provider?["team_id"]?.stringValue,
            scopeTokens: json["scope_tokens"]?.arrayValue?.compactMap(\.stringValue) ?? [],
            tcpHandedOff: Self.count(handoffs?["tcp"]),
            udpHandedOff: Self.count(handoffs?["udp"]),
            lastHandoffAt: Self.date(json["last_handoff_at"]),
            capability: CoreCapability(wire: capability),
            capabilityReason: json["capability_reason"]?.stringValue)
    }

    /// Epoch milliseconds as a `Date`. Nil for `null`, a negative or a non-integral
    /// number: a time is a count of milliseconds, and anything else from the wire is
    /// not one (as `FlowSummary.size` rejects absurd sizes).
    private static func date(_ value: JSONValue?) -> Date? {
        guard let ms = value?.intValue, ms >= 0 else { return nil }
        return Date(timeIntervalSince1970: Double(ms) / 1000)
    }

    /// A handoff count: never below zero; a missing or non-integral value reads as 0.
    private static func count(_ value: JSONValue?) -> Int {
        max(0, value?.intValue ?? 0)
    }
}
