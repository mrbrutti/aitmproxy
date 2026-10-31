import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// `CaptureStatus` decodes the read-only `capture.status` bus verb (spec
/// 2026-10-31-capture-status-verb-design, D7/D10): the core-side feeder's own
/// account of the macOS capture path. One fixture per D7 example, exactly as the
/// core serialises it (keys sorted, epoch-millisecond times, `null` for "none").
@Suite struct CaptureStatusTests {
    /// The default build on any platform: the core's on-switch is off.
    static let disabledJSON = """
    {
      "capability": "feeder_off",
      "capability_reason": "macos_capture.enabled is false",
      "enabled": false,
      "feeder": { "reason": "macos_capture.enabled is false", "state": "off" },
      "flows_handed_off": { "tcp": 0, "udp": 0 },
      "last_handoff_at": null,
      "provider": { "attached_at": null, "state": "detached", "team_id": null },
      "scope_entries": 0,
      "scope_tokens": []
    }
    """

    /// macOS, enabled, the socket directory unusable.
    static let bindFailedJSON = """
    {
      "capability": "degraded",
      "capability_reason": "cannot bind the capture sockets (not a directory)",
      "enabled": true,
      "feeder": { "reason": "cannot bind the capture sockets (not a directory)", "state": "bind_failed" },
      "flows_handed_off": { "tcp": 0, "udp": 0 },
      "last_handoff_at": null,
      "provider": { "attached_at": null, "state": "detached", "team_id": null },
      "scope_entries": 0,
      "scope_tokens": []
    }
    """

    /// macOS, enabled, listening; no provider has attached.
    static let listeningJSON = """
    {
      "capability": "awaiting_provider",
      "capability_reason": null,
      "enabled": true,
      "feeder": { "reason": null, "state": "listening" },
      "flows_handed_off": { "tcp": 0, "udp": 0 },
      "last_handoff_at": null,
      "provider": { "attached_at": null, "state": "detached", "team_id": null },
      "scope_entries": 0,
      "scope_tokens": []
    }
    """

    /// Attached and capturing: L7 scope `example.com`, `*.example.com`; one L4 entry.
    static let capturingJSON = """
    {
      "capability": "capturing",
      "capability_reason": null,
      "enabled": true,
      "feeder": { "reason": null, "state": "listening" },
      "flows_handed_off": { "tcp": 12, "udp": 3 },
      "last_handoff_at": 1761907305123,
      "provider": { "attached_at": 1761907200000, "state": "attached", "team_id": "995PCLM9KH" },
      "scope_entries": 3,
      "scope_tokens": ["example.com", "*.example.com", "198.51.100.7"]
    }
    """

    /// The same attachment, nothing handed off and an empty scope: the incident
    /// state ("Capturing" with nothing captured), now reported honestly.
    static let approvedAttachedEmptyScopeJSON = """
    {
      "capability": "approved_attached",
      "capability_reason": null,
      "enabled": true,
      "feeder": { "reason": null, "state": "listening" },
      "flows_handed_off": { "tcp": 0, "udp": 0 },
      "last_handoff_at": null,
      "provider": { "attached_at": 1761907200000, "state": "attached", "team_id": "995PCLM9KH" },
      "scope_entries": 0,
      "scope_tokens": []
    }
    """

    /// The closed vocabulary of `feeder.reason` when `feeder.state == "off"` (D7).
    static let offReasons = ["macos_capture.enabled is false", "not a macOS build", "not started", "stopped"]

    /// The five capability names the verb emits (D5); the app never sees the other two.
    static let capabilityWireNames = ["feeder_off", "awaiting_provider", "approved_attached", "capturing", "degraded"]

    static func decode(_ text: String) throws -> CaptureStatus {
        let status = try #require(CaptureStatus(json: JSONValue.parse(text)))
        return status
    }

    // MARK: The four D7 examples

    @Test func decodesTheDisabledShape() throws {
        let status = try Self.decode(Self.disabledJSON)
        #expect(status.enabled == false)
        #expect(status.feeder == .off(reason: "macos_capture.enabled is false"))
        #expect(status.providerAttached == false)
        #expect(status.attachedAt == nil)
        #expect(status.teamID == nil)
        #expect(status.scopeTokens == [])
        #expect(status.tcpHandedOff == 0)
        #expect(status.udpHandedOff == 0)
        #expect(status.lastHandoffAt == nil)
        #expect(status.capability == .feederOff)
        #expect(status.capabilityReason == "macos_capture.enabled is false")
    }

    @Test func decodesTheBindFailedShape() throws {
        let status = try Self.decode(Self.bindFailedJSON)
        #expect(status.enabled == true)
        #expect(status.feeder == .bindFailed(reason: "cannot bind the capture sockets (not a directory)"))
        #expect(status.providerAttached == false)
        #expect(status.capability == .degraded)
        #expect(status.capabilityReason == "cannot bind the capture sockets (not a directory)")
    }

    @Test func decodesTheListeningShape() throws {
        let status = try Self.decode(Self.listeningJSON)
        #expect(status.enabled == true)
        #expect(status.feeder == .listening)
        #expect(status.capability == .awaitingProvider)
        #expect(status.capabilityReason == nil)
        #expect(status.providerAttached == false)
        #expect(status.attachedAt == nil)
        #expect(status.teamID == nil)
    }

    @Test func decodesTheCapturingShape() throws {
        let status = try Self.decode(Self.capturingJSON)
        #expect(status.enabled == true)
        #expect(status.feeder == .listening)
        #expect(status.providerAttached == true)
        #expect(status.attachedAt == Date(timeIntervalSince1970: 1_761_907_200))
        #expect(status.lastHandoffAt == Date(timeIntervalSince1970: 1_761_907_305.123))
        #expect(status.teamID == "995PCLM9KH")
        #expect(status.scopeTokens == ["example.com", "*.example.com", "198.51.100.7"])
        #expect(status.tcpHandedOff == 12)
        #expect(status.udpHandedOff == 3)
        #expect(status.capability == .capturing)
        #expect(status.capabilityReason == nil)
    }

    @Test func approvedAttachedWithEmptyScopeIsHonest() throws {
        let status = try Self.decode(Self.approvedAttachedEmptyScopeJSON)
        #expect(status.capability == .approvedAttached)
        #expect(status.scopeTokens.isEmpty)
        #expect(status.lastHandoffAt == nil)
        #expect(status.providerAttached == true)
        #expect(status.attachedAt == Date(timeIntervalSince1970: 1_761_907_200))
        #expect(status.tcpHandedOff == 0)
        #expect(status.udpHandedOff == 0)
    }

    // MARK: Required keys

    @Test func rejectsAnObjectWithoutTheRequiredKeys() {
        #expect(CaptureStatus(json: .object([:])) == nil)
        #expect(CaptureStatus(json: ["enabled": true]) == nil)
        // All three of `enabled`, `feeder.state` and `capability` must be present.
        #expect(CaptureStatus(json: ["enabled": true, "feeder": ["state": "listening"]]) == nil)
        #expect(CaptureStatus(json: ["enabled": true, "capability": "awaiting_provider"]) == nil)
        #expect(CaptureStatus(json: ["enabled": true, "feeder": ["reason": nil], "capability": "feeder_off"]) == nil)
        #expect(CaptureStatus(json: ["feeder": ["state": "listening"], "capability": "awaiting_provider"]) == nil)
        // Not even an object.
        #expect(CaptureStatus(json: .null) == nil)
        #expect(CaptureStatus(json: "capturing") == nil)
        // The minimum that decodes.
        #expect(CaptureStatus(json: ["enabled": true, "feeder": ["state": "listening"], "capability": "awaiting_provider"]) != nil)
    }

    // MARK: A newer core

    @Test func unknownCapabilityDecodesAsUnknown() throws {
        let json: JSONValue = ["enabled": true, "feeder": ["state": "listening"], "capability": "something_new"]
        let status = try #require(CaptureStatus(json: json))
        #expect(status.capability == .unknown("something_new"))
        #expect(status.capability.wire == "something_new")
        #expect(CaptureStatus.CoreCapability(wire: "something_new") == .unknown("something_new"))
    }

    @Test func unknownFeederStateDecodesAsUnknown() throws {
        let json: JSONValue = ["enabled": true, "feeder": ["state": "weird", "reason": nil], "capability": "awaiting_provider"]
        let status = try #require(CaptureStatus(json: json))
        #expect(status.feeder == .unknown(state: "weird"))
        // The capability still reads: a strange feeder state is never a decode failure.
        #expect(status.capability == .awaitingProvider)
    }

    // MARK: Off reasons

    @Test func offReasonsDecodeVerbatim() throws {
        for reason in Self.offReasons {
            let json: JSONValue = [
                "enabled": .bool(reason != "macos_capture.enabled is false"),
                "feeder": ["state": "off", "reason": .string(reason)],
                "capability": "feeder_off",
                "capability_reason": .string(reason),
            ]
            let status = try #require(CaptureStatus(json: json), "\(reason)")
            #expect(status.feeder == .off(reason: reason), "\(reason)")
            #expect(status.capability == .feederOff, "\(reason)")
            #expect(status.capabilityReason == reason, "\(reason)")
        }
        // `off` with no reason at all still decodes; the reason is simply nil.
        let bare: JSONValue = ["enabled": true, "feeder": ["state": "off"], "capability": "feeder_off"]
        let bareStatus = try #require(CaptureStatus(json: bare))
        #expect(bareStatus.feeder == .off(reason: nil))
        // `bind_failed` without a reason reads as an empty reason, not nil.
        let bind: JSONValue = ["enabled": true, "feeder": ["state": "bind_failed"], "capability": "degraded"]
        let bindStatus = try #require(CaptureStatus(json: bind))
        #expect(bindStatus.feeder == .bindFailed(reason: ""))
    }

    // MARK: Hostile numbers

    @Test func absurdTimesAndCountsAreClamped() throws {
        let negativeTime: JSONValue = [
            "enabled": true, "feeder": ["state": "listening"], "capability": "approved_attached",
            "provider": ["state": "attached", "attached_at": -5, "team_id": "995PCLM9KH"],
            "last_handoff_at": -1,
        ]
        let a = try #require(CaptureStatus(json: negativeTime))
        #expect(a.attachedAt == nil)
        #expect(a.lastHandoffAt == nil)
        #expect(a.providerAttached == true)

        let fractionalTime: JSONValue = [
            "enabled": true, "feeder": ["state": "listening"], "capability": "approved_attached",
            "provider": ["state": "attached", "attached_at": 1.5],
        ]
        let b = try #require(CaptureStatus(json: fractionalTime))
        #expect(b.attachedAt == nil)

        let zeroTime: JSONValue = [
            "enabled": true, "feeder": ["state": "listening"], "capability": "approved_attached",
            "provider": ["state": "attached", "attached_at": 0],
        ]
        let z = try #require(CaptureStatus(json: zeroTime))
        #expect(z.attachedAt == Date(timeIntervalSince1970: 0))

        let negativeCounts: JSONValue = [
            "enabled": true, "feeder": ["state": "listening"], "capability": "capturing",
            "flows_handed_off": ["tcp": -1, "udp": -2],
        ]
        let c = try #require(CaptureStatus(json: negativeCounts))
        #expect(c.tcpHandedOff == 0)
        #expect(c.udpHandedOff == 0)

        let fractionalCounts: JSONValue = [
            "enabled": true, "feeder": ["state": "listening"], "capability": "capturing",
            "flows_handed_off": ["tcp": 2.5, "udp": "3"],
        ]
        let f = try #require(CaptureStatus(json: fractionalCounts))
        #expect(f.tcpHandedOff == 0)
        #expect(f.udpHandedOff == 0)
    }

    // MARK: The wire names

    @Test func capabilityWireRoundTrips() {
        for name in Self.capabilityWireNames {
            #expect(CaptureStatus.CoreCapability(wire: name).wire == name, "\(name)")
        }
        #expect(CaptureStatus.CoreCapability(wire: "feeder_off") == .feederOff)
        #expect(CaptureStatus.CoreCapability(wire: "awaiting_provider") == .awaitingProvider)
        #expect(CaptureStatus.CoreCapability(wire: "approved_attached") == .approvedAttached)
        #expect(CaptureStatus.CoreCapability(wire: "capturing") == .capturing)
        #expect(CaptureStatus.CoreCapability(wire: "degraded") == .degraded)
        #expect(CaptureStatus.CoreCapability.feederOff.wire == "feeder_off")
        #expect(CaptureStatus.CoreCapability.awaitingProvider.wire == "awaiting_provider")
        #expect(CaptureStatus.CoreCapability.approvedAttached.wire == "approved_attached")
        #expect(CaptureStatus.CoreCapability.capturing.wire == "capturing")
        #expect(CaptureStatus.CoreCapability.degraded.wire == "degraded")
        // Case and spelling matter: the Rust side pins the lower-case snake names.
        #expect(CaptureStatus.CoreCapability(wire: "Capturing") == .unknown("Capturing"))
        #expect(CaptureStatus.CoreCapability(wire: "") == .unknown(""))
    }

    // MARK: Memberwise init

    @Test func theMemberwiseInitDefaultsToADetachedIdleProvider() {
        let status = CaptureStatus(enabled: true, feeder: .listening, capability: .awaitingProvider)
        #expect(status.providerAttached == false)
        #expect(status.attachedAt == nil)
        #expect(status.teamID == nil)
        #expect(status.scopeTokens == [])
        #expect(status.tcpHandedOff == 0)
        #expect(status.udpHandedOff == 0)
        #expect(status.lastHandoffAt == nil)
        #expect(status.capabilityReason == nil)
    }
}
