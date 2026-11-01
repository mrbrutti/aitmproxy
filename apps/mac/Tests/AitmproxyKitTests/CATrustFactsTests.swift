import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// SP-AC33 (spec 2026-10-31-system-proxy-automation-design §D17.5, D17.6, D17.9) in
/// `CATrustFacts`'s own home: the mac CA fact and its Getting-started step, decoded from
/// literal `ca.status` JSON as the core serialises it, never from an install reply.
@Suite struct CATrustFactsTests {
    static let fingerprint = "9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15:A3:BF:4F:1B:2B:0B:82:2C:D1:5D:6C:15:B0:F0:0A:08"

    /// macOS, the certificate in the login keychain and trusted there (D17.3 read-back said yes).
    static let trustedUserJSON = """
    {
      "exists": true,
      "dir": "/Users/op/Library/Application Support/aitmproxy/ca",
      "path": "/Users/op/Library/Application Support/aitmproxy/ca/ca.crt",
      "fingerprint_sha256": "9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15:A3:BF:4F:1B:2B:0B:82:2C:D1:5D:6C:15:B0:F0:0A:08",
      "fingerprint_sha1": "A9:4A:8F:E5:CC:B1:9B:A6:1C:4C:08:73:D3:91:E9:87:98:2F:BB:D3",
      "platform": "macos",
      "stores": {
        "user": { "installed": "present", "trusted": "yes", "location": "/Users/op/Library/Keychains/login.keychain-db" },
        "system": { "installed": "absent", "trusted": "no", "location": "/Library/Keychains/System.keychain" }
      },
      "detail": ["certificate verification successful"]
    }
    """

    /// macOS, nothing in either keychain: the v0.5.5 state on Matt's Mac.
    static let notTrustedJSON = """
    {
      "exists": true,
      "dir": "/Users/op/Library/Application Support/aitmproxy/ca",
      "path": "/Users/op/Library/Application Support/aitmproxy/ca/ca.crt",
      "fingerprint_sha256": "9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15:A3:BF:4F:1B:2B:0B:82:2C:D1:5D:6C:15:B0:F0:0A:08",
      "fingerprint_sha1": "A9:4A:8F:E5:CC:B1:9B:A6:1C:4C:08:73:D3:91:E9:87:98:2F:BB:D3",
      "platform": "macos",
      "stores": {
        "user": { "installed": "absent", "trusted": "no", "location": "/Users/op/Library/Keychains/login.keychain-db" },
        "system": { "installed": "absent", "trusted": "no", "location": "/Library/Keychains/System.keychain" }
      },
      "detail": []
    }
    """

    /// An older core (or a failed evaluation tool): every store says unknown.
    static let allUnknownJSON = """
    {
      "exists": true,
      "dir": "/Users/op/Library/Application Support/aitmproxy/ca",
      "path": "/Users/op/Library/Application Support/aitmproxy/ca/ca.crt",
      "fingerprint_sha256": "9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15:A3:BF:4F:1B:2B:0B:82:2C:D1:5D:6C:15:B0:F0:0A:08",
      "fingerprint_sha1": "A9:4A:8F:E5:CC:B1:9B:A6:1C:4C:08:73:D3:91:E9:87:98:2F:BB:D3",
      "platform": "macos",
      "stores": {
        "user": { "installed": "present", "trusted": "unknown", "location": "/Users/op/Library/Keychains/login.keychain-db" },
        "system": { "installed": "unknown", "trusted": "unknown", "location": "/Library/Keychains/System.keychain" }
      },
      "detail": ["security verify-cert: exit 2"]
    }
    """

    /// Trusted by hand in the System keychain only (never the app's path, D17.14).
    static let trustedSystemJSON = """
    {
      "exists": true,
      "dir": "/Users/op/Library/Application Support/aitmproxy/ca",
      "path": "/Users/op/Library/Application Support/aitmproxy/ca/ca.crt",
      "fingerprint_sha256": "9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15:A3:BF:4F:1B:2B:0B:82:2C:D1:5D:6C:15:B0:F0:0A:08",
      "fingerprint_sha1": "A9:4A:8F:E5:CC:B1:9B:A6:1C:4C:08:73:D3:91:E9:87:98:2F:BB:D3",
      "platform": "macos",
      "stores": {
        "user": { "installed": "absent", "trusted": "no", "location": "/Users/op/Library/Keychains/login.keychain-db" },
        "system": { "installed": "present", "trusted": "yes", "location": "/Library/Keychains/System.keychain" }
      },
      "detail": []
    }
    """

    /// Linux has one scope; the anchor is absent.
    static let linuxNotTrustedJSON = """
    {
      "exists": true,
      "dir": "/home/op/.local/share/aitmproxy/ca",
      "path": "/home/op/.local/share/aitmproxy/ca/ca.crt",
      "fingerprint_sha256": "9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15:A3:BF:4F:1B:2B:0B:82:2C:D1:5D:6C:15:B0:F0:0A:08",
      "fingerprint_sha1": "A9:4A:8F:E5:CC:B1:9B:A6:1C:4C:08:73:D3:91:E9:87:98:2F:BB:D3",
      "platform": "linux-debian",
      "stores": {
        "system": { "installed": "absent", "trusted": "no", "location": "/usr/local/share/ca-certificates/aitmproxy.crt" }
      },
      "detail": []
    }
    """

    private func status(_ json: String) throws -> CAStatus {
        let value = try JSONValue.parse(json)
        return try #require(CAStatus(json: value))
    }

    private func facts(_ json: String) throws -> CATrustFacts {
        try #require(CATrustFacts(status: try status(json)))
    }

    // MARK: CAStatus decodes the per-store trust (D17.5)

    @Test func statusReportsTrustAndScopeUserBeforeSystem() throws {
        let trusted = try status(Self.trustedUserJSON)
        #expect(trusted.trustReported)
        #expect(trusted.trustedScope == "user")
        let system = try status(Self.trustedSystemJSON)
        #expect(system.trustedScope == "system")
        let none = try status(Self.notTrustedJSON)
        #expect(none.trustReported)
        #expect(none.trustedScope == nil)
        let unknown = try status(Self.allUnknownJSON)
        #expect(unknown.trustReported == false)
        #expect(unknown.trustedScope == nil)
    }

    // MARK: The fact row (D17.6)

    @Test func trustedInTheUserKeychain() throws {
        let f = try facts(Self.trustedUserJSON)
        #expect(f.trusted)
        #expect(f.scope == "user")
        #expect(f.fingerprint == Self.fingerprint)
        #expect(f.text == "CA trusted (user keychain)")
        #expect(f.state == .ok)
        #expect(f.remedy == nil)
        #expect(f.actions == [.openCAPanel])
        #expect(f.step.kind == .caTrusted)
        #expect(f.step.done)
        #expect(f.step.title == "CA trusted (user keychain)")
        #expect(f.step.action == nil)
    }

    @Test func notTrustedOffersTheTrustStep() throws {
        let f = try facts(Self.notTrustedJSON)
        #expect(!f.trusted)
        #expect(f.scope == nil)
        #expect(f.text == "HTTPS is not captured until the CA is trusted")
        #expect(f.remedy == "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then")
        #expect(f.remedy == CATrustFacts.notTrustedLine)
        #expect(f.state == .warning)
        #expect(f.actions == [.trustCA, .openCAPanel])
        #expect(!f.step.done)
        #expect(f.step.title == "Trust the aitmproxy CA")
        #expect(f.step.action == .trustCA)
    }

    @Test func everyStoreUnknownIsNoFact() throws {
        let unknown = try status(Self.allUnknownJSON)
        #expect(CATrustFacts(status: unknown) == nil)
        #expect(unknown.trustReported == false)
        let step = CATrustFacts.unknownStep()
        #expect(step.kind == .caTrusted)
        #expect(!step.done)
        #expect(step.title == "CA trust unknown — open the Certificate Authority panel")
        #expect(step.action == .openCAPanel)
    }

    @Test func installingIsWorkingWithNoActions() throws {
        var f = try facts(Self.notTrustedJSON)
        f.installing = true
        #expect(f.text == "trusting CA…")
        #expect(f.state == .working)
        #expect(f.remedy == nil)
        #expect(f.actions == [])
        #expect(!f.step.done)
        #expect(f.step.title == "trusting CA…")
        #expect(f.step.action == nil)
        // A trusted store with a change in flight is not "done" until the re-read says so.
        var t = try facts(Self.trustedUserJSON)
        t.installing = true
        #expect(!t.step.done)
    }

    @Test func needsAnAdministratorOpensThePanel() throws {
        var mac = try facts(Self.notTrustedJSON)
        mac.needsAdmin = true
        #expect(mac.text == "CA trust needs an administrator")
        #expect(mac.state == .warning)
        #expect(mac.actions == [.openCAPanel])
        #expect(mac.remedy == "macOS did not show its authentication dialog. Open the Certificate Authority panel, export the certificate and trust it in Keychain Access.")
        #expect(mac.step.title == "CA trust needs an administrator")
        #expect(mac.step.action == .openCAPanel)
        #expect(!mac.step.done)
        var linux = try facts(Self.linuxNotTrustedJSON)
        linux.needsAdmin = true
        #expect(linux.text == "CA trust needs an administrator")
        #expect(linux.remedy == "Linux trust stores need root: run `aitm ca install` in a terminal where sudo can prompt")
    }

    @Test func trustedInTheSystemKeychainSaysSo() throws {
        let f = try facts(Self.trustedSystemJSON)
        #expect(f.trusted)
        #expect(f.scope == "system")
        #expect(f.text == "CA trusted (System keychain)")
        #expect(f.step.title == "CA trusted (System keychain)")
        #expect(f.actions == [.openCAPanel])
    }

    // MARK: D17.1 scope, D17.7 caveat, action titles

    @Test func scopeIsUserOnMacAndWindowsAndAbsentElsewhere() {
        #expect(CATrustFacts.scopeArgs(platform: "macos") == ["scope": .string("user")])
        #expect(CATrustFacts.scopeArgs(platform: "windows") == ["scope": .string("user")])
        #expect(CATrustFacts.scopeArgs(platform: "linux-debian") == [:])
        #expect(CATrustFacts.scopeArgs(platform: "linux") == [:])
        #expect(CATrustFacts.scopeArgs(platform: "unknown") == [:])
    }

    @Test func quicCaveatIsTheOneSentence() {
        #expect(CATrustFacts.quicCaveat == "HTTPS apps that use QUIC are not captured until the CA is trusted; browsers fall back to TCP once it is.")
    }

    @Test func actionTitles() {
        #expect(ConnectionAction.trustCA.title == "Trust the aitmproxy CA")
        #expect(ConnectionAction.openCAPanel.title == "Certificate Authority…")
        #expect(!ConnectionAction.trustCA.isDestructive)
        #expect(!ConnectionAction.openCAPanel.isDestructive)
    }

    /// The core's error texts the app keys on (D17.4 cancelled → silent; D17.6 needs an administrator).
    @Test func errorTextsAreClassified() {
        #expect(CATrustFacts.isCancelled("ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted"))
        #expect(!CATrustFacts.isCancelled("ca.install: security add-trusted-cert exited 1"))
        #expect(CATrustFacts.signalsNeedsAdmin("macOS refused to change trust settings without a GUI session; run aitm ca install from a terminal in a logged-in desktop session (security: exit 1)"))
        #expect(CATrustFacts.signalsNeedsAdmin("needs root: run aitm ca install from a shell where sudo can prompt, or start the proxy as root (tee: exit 1)"))
        #expect(!CATrustFacts.signalsNeedsAdmin("ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted"))
        #expect(!CATrustFacts.signalsNeedsAdmin("the bus connection closed"))
    }
}
