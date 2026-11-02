import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// TR-AC22 (plan Task 1c): the per-host decryption fields of PR #228 on a `flow.get` /
/// `flow.table` row (`crates/aitm-plugins/src/capture.rs` `tunnel_fields`): `tunnel`,
/// `tunnel_reason`, `bytes_up`, `bytes_down`, `passive`. Every value is a literal the core
/// emits (`crates/aitm-core/src/flow.rs` `TunnelMode::label` / `TunnelReason::label`).
/// The suite is named apart from `KitTests.swift`'s `FlowSummaryTests`, which covers the
/// older summary fields.
@Suite struct FlowSummaryTunnelTests {
    /// A literal `flow.get` object for a `CONNECT example.com:443` row. `extra` adds or
    /// overrides keys; the base carries no tunnel key, as an older core would send.
    static func connect(scheme: String = "https", _ extra: [String: JSONValue] = [:]) -> JSONValue {
        var obj: [String: JSONValue] = [
            "id": "7a3f0c1e-0000-4000-8000-00000000c0de", "kind": "http", "intercept": "observed",
            "is_replay": false, "method": "CONNECT", "scheme": .string(scheme), "authority": "example.com",
            "path": "/", "status": 200, "request_bytes": .null, "response_bytes": .null,
        ]
        for (key, value) in extra { obj[key] = value }
        return .object(obj)
    }

    @Test func passthroughReadsAsTunnelled() throws {
        let summary = try #require(FlowSummary(json: Self.connect(["tunnel": "passthrough"])))
        #expect(summary.tunnel == .passthrough)
        let row = summary.row(seq: 1)
        #expect(row.tunnel == .passthrough)
        #expect(row.tls == .tunnelled)
        #expect(row.isTunnel == true)
    }

    @Test func failedReadsAsPinnedOrFailed() throws {
        let summary = try #require(FlowSummary(json: Self.connect(["tunnel": "failed", "status": .null])))
        #expect(summary.tunnel == .failed)
        let row = summary.row(seq: 1)
        #expect(row.tunnel == .failed)
        #expect(row.tls == .pinnedOrFailed)
        #expect(row.isTunnel == true)
    }

    @Test func decryptedReadsAsDecrypted() throws {
        let summary = try #require(FlowSummary(json: Self.connect(["tunnel": "decrypted"])))
        #expect(summary.tunnel == .decrypted)
        let row = summary.row(seq: 1)
        #expect(row.tunnel == .decrypted)
        #expect(row.tls == .decrypted)
        #expect(row.isTunnel == true)
    }

    /// A row that is not a tunnel (`tunnel: null`) and a row from a core older than #228
    /// (no key) both fall back to the scheme rule: `https` / `wss` → decrypted, else none.
    @Test func nullOrAbsentTunnelUsesTheSchemeRule() throws {
        let null = try #require(FlowSummary(json: Self.connect(["tunnel": .null])))
        #expect(null.tunnel == nil)
        #expect(null.row(seq: 1).isTunnel == false)
        #expect(null.row(seq: 1).tls == .decrypted)

        let absent = try #require(FlowSummary(json: Self.connect()))
        #expect(absent.tunnel == nil)
        #expect(absent.row(seq: 1).tunnel == nil)
        #expect(absent.row(seq: 1).isTunnel == false)
        #expect(absent.row(seq: 1).tls == .decrypted)

        let plain = try #require(FlowSummary(json: Self.connect(scheme: "http")))
        #expect(plain.row(seq: 1).tls == TLSState.none)

        let wss = try #require(FlowSummary(json: Self.connect(scheme: "wss")))
        #expect(wss.row(seq: 1).tls == .decrypted)
    }

    @Test func theWireWinsOverTheScheme() throws {
        let row = try #require(FlowSummary(json: Self.connect(scheme: "http", ["tunnel": "passthrough"]))).row(seq: 1)
        #expect(row.tls == .tunnelled)
        #expect(row.isTunnel == true)
    }

    /// A mode this build does not know (a newer core) is no tunnel, never a crash.
    @Test func unknownTunnelModeReadsAsNil() throws {
        let summary = try #require(FlowSummary(json: Self.connect(["tunnel": "something_new"])))
        #expect(summary.tunnel == nil)
        #expect(summary.row(seq: 1).isTunnel == false)
        #expect(summary.row(seq: 1).tls == .decrypted)
    }

    @Test(arguments: [
        ("out_of_scope", TunnelReason.outOfScope),
        ("pinned", TunnelReason.pinned),
        ("client_rejected_certificate", TunnelReason.clientRejectedCertificate),
        ("client_closed", TunnelReason.clientClosed),
        ("client_tls_error", TunnelReason.clientTLSError),
        ("upstream_unreachable", TunnelReason.upstreamUnreachable),
        ("upstream_tls_failed", TunnelReason.upstreamTLSFailed),
        ("protocol_error", TunnelReason.protocolError),
    ])
    func eachOfTheEightReasonsDecodes(label: String, reason: TunnelReason) throws {
        let mode: JSONValue = reason == .outOfScope || reason == .pinned ? "passthrough" : "failed"
        let summary = try #require(FlowSummary(json: Self.connect(["tunnel": mode, "tunnel_reason": .string(label)])))
        #expect(summary.tunnelReason == reason)
        #expect(summary.row(seq: 1).tunnelReason == reason)
        #expect(TunnelReason(rawValue: label) == reason)
        #expect(reason.rawValue == label)
    }

    @Test func unknownNullOrAbsentReasonIsNil() throws {
        let unknown = try #require(FlowSummary(json: Self.connect(["tunnel": "failed", "tunnel_reason": "something_new"])))
        #expect(unknown.tunnelReason == nil)
        #expect(unknown.row(seq: 1).tunnelReason == nil)
        // The mode still decodes: an unknown reason does not lose the row's outcome.
        #expect(unknown.tunnel == .failed)

        let null = try #require(FlowSummary(json: Self.connect(["tunnel": "decrypted", "tunnel_reason": .null])))
        #expect(null.tunnelReason == nil)

        let absent = try #require(FlowSummary(json: Self.connect()))
        #expect(absent.tunnelReason == nil)
        #expect(absent.row(seq: 1).tunnelReason == nil)
        #expect(TunnelReason(rawValue: "something_new") == nil)
    }

    @Test func byteCountsReachSummaryAndRow() throws {
        let closed = try #require(FlowSummary(json: Self.connect([
            "tunnel": "passthrough", "tunnel_reason": "out_of_scope", "bytes_up": 1_234, "bytes_down": 56,
        ])))
        #expect(closed.tunnelBytesUp == 1_234)
        #expect(closed.tunnelBytesDown == 56)
        let row = closed.row(seq: 1)
        #expect(row.tunnelBytesUp == 1_234)
        #expect(row.tunnelBytesDown == 56)
        // The tunnel's counts are not the request/response body sizes.
        #expect(row.requestBytes == nil)
        #expect(row.responseBytes == nil)

        // Still open: the core sends null until a passthrough tunnel closes.
        let open = try #require(FlowSummary(json: Self.connect(["tunnel": "passthrough", "bytes_up": .null, "bytes_down": .null])))
        #expect(open.tunnelBytesUp == nil)
        #expect(open.tunnelBytesDown == nil)
        #expect(open.row(seq: 1).tunnelBytesUp == nil)
        #expect(open.row(seq: 1).tunnelBytesDown == nil)

        let absent = try #require(FlowSummary(json: Self.connect()))
        #expect(absent.tunnelBytesUp == nil)
        #expect(absent.tunnelBytesDown == nil)

        // The same guards as the body sizes: a negative count is not a count.
        let negative = try #require(FlowSummary(json: Self.connect(["tunnel": "passthrough", "bytes_up": -1, "bytes_down": -9_000_000_000])))
        #expect(negative.tunnelBytesUp == nil)
        #expect(negative.tunnelBytesDown == nil)
    }

    @Test func passiveReadsTrueOnlyWhenTheWireSaysSo() throws {
        let passive = try #require(FlowSummary(json: Self.connect(scheme: "http", ["passive": true])))
        #expect(passive.passive == true)
        #expect(passive.row(seq: 1).passive == true)

        let active = try #require(FlowSummary(json: Self.connect(["passive": false])))
        #expect(active.passive == false)
        #expect(active.row(seq: 1).passive == false)

        let absent = try #require(FlowSummary(json: Self.connect()))
        #expect(absent.passive == false)
        #expect(absent.row(seq: 1).passive == false)

        let null = try #require(FlowSummary(json: Self.connect(["passive": .null])))
        #expect(null.passive == false)
    }

    /// `inScope` keeps the scope-list rule: none of the five fields moves it.
    @Test func inScopeIsUnchangedByTheTunnelFields() throws {
        let plain = try #require(FlowSummary(json: Self.connect())).row(seq: 1)
        let outOfScope = try #require(FlowSummary(json: Self.connect([
            "tunnel": "passthrough", "tunnel_reason": "out_of_scope", "bytes_up": 1, "bytes_down": 2, "passive": true,
        ]))).row(seq: 1)
        #expect(outOfScope.inScope == plain.inScope)
        #expect(outOfScope.inScope == true)
    }

    /// The memberwise initialisers keep every older call site compiling: the five fields
    /// default to nil / nil / nil / nil / false.
    @Test func memberwiseDefaultsAreNoTunnel() {
        let summary = FlowSummary(id: FlowID("s"), kind: .http, intercept: .observed, isReplay: false)
        #expect(summary.tunnel == nil && summary.tunnelReason == nil)
        #expect(summary.tunnelBytesUp == nil && summary.tunnelBytesDown == nil)
        #expect(summary.passive == false)
        let row = FlowRow(id: FlowID("r"), seq: 1, method: .get, scheme: "https", authority: "example.com", path: "/")
        #expect(row.tunnel == nil && row.tunnelReason == nil)
        #expect(row.tunnelBytesUp == nil && row.tunnelBytesDown == nil)
        #expect(row.passive == false)
        #expect(row.isTunnel == false)
    }
}
