import Testing

@testable import AitmBusClient

@Suite struct ServerInfoTests {
    /// The `initialize` result's top-level `role` becomes `ServerInfo.role` (spec Decision C).
    @Test func readsOperatorRole() throws {
        let result: JSONValue = [
            "protocolVersion": "2025-06-18",
            "serverInfo": ["name": "aitmproxy", "version": "0.1"],
            "role": "operator",
        ]
        let info = try ServerInfo(initializeResult: result)
        #expect(info.role == "operator")
        #expect(info.name == "aitmproxy")
    }

    /// A server that echoes no `role` leaves it `nil` — "role unknown", not an error (AC10).
    @Test func missingRoleIsNil() throws {
        let result: JSONValue = [
            "protocolVersion": "2025-06-18",
            "serverInfo": ["name": "aitmproxy", "version": "0.1"],
        ]
        let info = try ServerInfo(initializeResult: result)
        #expect(info.role == nil)
    }

    /// Expecting operator but resolving agent — or not confirming a role at all —
    /// is a mismatch; a matching pair and "no expectation" are not (AC8).
    @Test func mismatchLogic() {
        #expect(roleMismatch(expected: .operator, resolved: "agent"))
        #expect(roleMismatch(expected: .operator, resolved: nil))
        #expect(!roleMismatch(expected: .operator, resolved: "operator"))
        #expect(!roleMismatch(expected: .agent, resolved: "agent"))
        #expect(!roleMismatch(expected: nil, resolved: "agent"))
    }
}
