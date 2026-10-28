import Foundation
import Testing

@testable import AitmBusClient

/// Fails instead of hanging when the bus never answers.
private func withTimeout<T: Sendable>(
    _ limit: Duration = .seconds(5), _ body: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(for: limit)
            throw BusError.timeout
        }
        guard let first = try await group.next() else { throw BusError.timeout }
        group.cancelAll()
        return first
    }
}

private func makeClient(_ endpoint: BusEndpoint, timeout: Duration = .seconds(5)) -> BusClient {
    BusClient(endpoint: endpoint, clientName: "aitm-mac-tests", clientVersion: "0.1", timeout: timeout)
}

@Suite(.serialized) struct BusClientTests {
    @Test func handshakeListAndCall() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        let client = makeClient(endpoint)
        let states = await client.states()

        let info = try await withTimeout { try await client.connect() }
        #expect(info == ServerInfo(name: "fake-aitmproxy", version: "0.0.1", protocolVersion: "2025-06-18"))
        #expect(await client.state == .ready(info))

        try await withTimeout { try await client.ping() }

        let tools = try await withTimeout { try await client.listTools() }
        #expect(tools.map(\.name) == ["fake.echo", "fake.fail", "fake.hang"])
        let echo = try #require(tools.first)
        #expect(echo.description == "Echo typed arguments back.")
        let types = Dictionary(uniqueKeysWithValues: echo.parameters.map { ($0.name, $0.type) })
        #expect(
            types == [
                "id": .flowId, "limit": .int, "ratio": .float, "verbose": .bool, "raw": .bytes,
                "tags": .array, "edits": .object, "vars": .map, "blob": .any,
            ])
        #expect(echo.parameters.filter(\.required).map(\.name) == ["id"])
        #expect(echo.parameters.first { $0.name == "id" }?.description == "a flow id")
        #expect(echo.inputSchema["additionalProperties"] == false)

        let arguments: [String: JSONValue] = ["id": "7f3c", "limit": 5, "tags": ["a", "b"]]
        let result = try await withTimeout { try await client.call("fake.echo", arguments) }
        #expect(result == .object(arguments))
        #expect(try await withTimeout { try await client.call("fake.text") } == ["plain": true])

        let methods = await server.receivedMethods
        #expect(methods.prefix(3) == ["initialize", "notifications/initialized", "ping"])

        await client.disconnect()
        #expect(await client.state == .closed)
        var seen: [BusClient.State] = []
        for await state in states {
            seen.append(state)
            if state == .closed { break }
        }
        #expect(seen == [.idle, .connecting, .authenticating, .ready(info), .closed])
    }

    @Test func wrongTokenIsUnauthorized() async throws {
        let server = FakeBusServer(token: "right")
        var endpoint = try await server.start()
        defer { Task { await server.stop() } }
        endpoint.token = "wrong"
        let client = makeClient(endpoint)
        await #expect(throws: BusError.unauthorized) {
            try await withTimeout { try await client.connect() }
        }
        #expect(await client.state == .failed(.unauthorized))
    }

    @Test func toolFailureIsToolError() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        let client = makeClient(endpoint)
        _ = try await withTimeout { try await client.connect() }
        await #expect(throws: BusError.tool(message: "boom: the tool refused")) {
            try await withTimeout { try await client.call("fake.fail") }
        }
        // The connection survives a tool error.
        try await withTimeout { try await client.ping() }
    }

    @Test func unknownToolIsRpcError() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        let client = makeClient(endpoint)
        _ = try await withTimeout { try await client.connect() }
        await #expect(throws: BusError.rpc(code: -32602, message: "unknown tool `nope`")) {
            try await withTimeout { try await client.call("nope") }
        }
    }

    @Test func serverClosingMidCallDisconnects() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        let client = makeClient(endpoint)
        _ = try await withTimeout { try await client.connect() }
        await #expect(throws: BusError.disconnected) {
            try await withTimeout { try await client.call("fake.drop") }
        }
        #expect(await client.state == .failed(.disconnected))
        await #expect(throws: BusError.disconnected) { try await client.ping() }
        // And it can connect again.
        _ = try await withTimeout { try await client.connect() }
        try await withTimeout { try await client.ping() }
    }

    @Test func slowServerTimesOut() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        let client = makeClient(endpoint, timeout: .milliseconds(200))
        _ = try await withTimeout { try await client.connect() }
        await #expect(throws: BusError.timeout) {
            try await withTimeout { try await client.call("fake.hang") }
        }
        try await withTimeout { try await client.ping() }
    }

    @Test func notificationsAreDelivered() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        let client = makeClient(endpoint)
        _ = try await withTimeout { try await client.connect() }
        await server.pushNotification("notifications/aitm/flow", params: ["event": "created", "id": "abc"])
        let received = try await withTimeout {
            for await notification in client.notifications { return notification }
            throw BusError.disconnected
        }
        #expect(received == JSONRPCNotification(method: "notifications/aitm/flow", params: ["event": "created", "id": "abc"]))
        try await withTimeout { try await client.ping() }
    }

    @Test func refusedConnectionIsTransportError() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        await server.stop()
        let client = makeClient(endpoint)
        do {
            _ = try await withTimeout { try await client.connect() }
            Issue.record("connect succeeded against a closed port")
        } catch let error as BusError {
            guard case .transport = error else { Issue.record("expected .transport, got \(error)"); return }
        }
        guard case .failed(.transport) = await client.state else {
            Issue.record("state should be .failed(.transport), got \(await client.state)")
            return
        }
    }
}
