@testable import AitmproxyKit
import AitmBusClient
import Foundation

/// PoC findings, their YAML and a config document: inputs for the Findings and
/// Configuration unit tests (S-050–S-053, S-059).
extension Fixtures {
    /// Three findings: a failed High XSS reflecting into `/api/search`
    /// (capture = flow 48), a passed Medium IDOR on `/api/orders`, and an Info
    /// run the agent kicked off. Newest first.
    static let findings: [Finding] = [
        Finding(
            id: UUID(uuidString: "F1000000-0000-4000-8000-000000000001")!,
            title: "Reflected XSS in search",
            severity: .high, target: "https://api.shop-staging.test", passed: false, ranAt: at(15.2),
            origin: .human, pocPath: "/tmp/aitm/pocs/reflected-xss-in-search.poc.yaml",
            yaml: pocYAML(name: "Reflected XSS in search", param: "q", severity: "high"),
            captureID: id(48), screenshotPath: "/tmp/aitm/pocs/reflected-xss-in-search.png", screenshot: tinyPNG,
            assertions: [
                Assertion(text: "status == 200", matched: true),
                Assertion(text: "word: <img src=x onerror=alert(1)>", matched: false),
            ]),
        Finding(
            id: UUID(uuidString: "F1000000-0000-4000-8000-000000000002")!,
            title: "IDOR on orders listing",
            severity: .medium, target: "https://api.shop-staging.test", passed: true, ranAt: at(9.4),
            origin: .human, pocPath: "/tmp/aitm/pocs/idor-on-orders-listing.poc.yaml",
            yaml: pocYAML(name: "IDOR on orders listing", param: "page", severity: "medium"),
            captureID: id(45), screenshotPath: "/tmp/aitm/pocs/idor-on-orders-listing.png", screenshot: tinyPNG,
            assertions: [
                Assertion(text: "status == 200", matched: true),
                Assertion(text: "word: \"total\"", matched: true),
            ]),
        Finding(
            id: UUID(uuidString: "F1000000-0000-4000-8000-000000000003")!,
            title: "Verbose error on cart patch",
            severity: .info, target: "https://api.shop-staging.test", passed: true, ranAt: at(2.1),
            origin: .agent, pocPath: "/tmp/aitm/pocs/verbose-error-on-cart-patch.poc.yaml",
            yaml: pocYAML(name: "Verbose error on cart patch", param: "quantity", severity: "info"),
            captureID: id(53), screenshotPath: nil, screenshot: nil,
            assertions: [Assertion(text: "status == 422", matched: true)]),
    ]

    /// A nuclei-style PoC document the way `aitm-poc` serializes one
    /// (`crates/aitm-poc`): `id`, `info`, `variables`, one `http` step, `success`.
    static func pocYAML(name: String, param: String, severity: String = "medium") -> String {
        """
        id: \(slug(name))
        info:
          name: \(name)
          severity: \(severity)
          description: Reproduces the finding by replaying the parameterized request.
          author: operator
        variables:
          - name: target
            description: Base URL of the target
          - name: param
            default: \(param)
            description: The parameter to vary
        steps:
          - http:
              method: GET
              url: "{{target}}/api/search?{{param}}=payload"
              headers:
                accept: application/json
        success:
          type: status
          status: 200
        """
    }

    private static func slug(_ name: String) -> String {
        var out = ""
        var dash = false
        for c in name {
            if c.isASCII, c.isLetter || c.isNumber { out.append(Character(c.lowercased())); dash = false }
            else if !out.isEmpty, !dash { out.append("-"); dash = true }
        }
        while out.hasSuffix("-") { out.removeLast() }
        return out.isEmpty ? "reproduced-finding" : out
    }

    /// The proxy's effective config.yaml, with the keys the panel highlights
    /// (listen, the loopback_tcp bus port) and the agent-install gate set false.
    static let configYAML = """
    # aitmproxy configuration
    listen: 127.0.0.1:8080
    upstream:
      ssl_insecure: false
    scope:
      - api.shop-staging.test
      - auth.shop-staging.test
      - "*.shop-staging.test"
    mcp:
      transport:
        loopback_tcp:
          host: 127.0.0.1
          port: 9090
          token: file:~/Library/Application Support/aitmproxy/bus.token
    browser:
      engine: obscura
    ca:
      allow_agent_install: false
    """
}
