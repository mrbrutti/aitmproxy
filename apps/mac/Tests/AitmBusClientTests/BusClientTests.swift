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
        #expect(tools.map(\.name) == ["fake.echo", "fake.fail", "fake.hang", "l4.inject"])
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

    // MARK: Confirm-over-the-wire (spec 2026-10-31-l4-parity-fixes §3)
    //
    // The core strips `_confirm` before schema enforcement, so no tool's
    // `inputSchema` declares it. A client that prunes arguments to the schema
    // sends the confirmed re-issue bare and gets a second `needs_confirmation`
    // (the TUI did exactly that, found live). These pins run the real
    // `BusClient` over a loopback `NWConnection` and read what the server got.

    /// The arguments the inspector sends for a guarded inject, built here.
    private static let bareInjectArgs: [String: JSONValue] = [
        "spec": ["layers": [["udp": ["dst_port": 9]], ["payload": ["hex": "00"]]]],
        "dst": .string("127.0.0.1"),
        "interface": .string("lo0"),
    ]

    /// What `aitm-mcp::server::needs_confirmation` answers the bare call with.
    private static let needsConfirmationResult: JSONValue = [
        "content": [["type": "text", "text": "Inject 1× UDP 127.0.0.1:9 on lo0"]],
        "structuredContent": [
            "status": "needs_confirmation",
            "prompt": "Inject 1× UDP 127.0.0.1:9 on lo0",
            "confirm_token": "tok-7f1c",
        ],
        "isError": false,
    ]

    private static let injectedResult: JSONValue = [
        "content": [["type": "text", "text": "{\"injected\":1}"]],
        "structuredContent": ["injected": 1],
        "isError": false,
    ]

    @Test func confirmKeyReachesTheWireVerbatim() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        await server.script("l4.inject", [Self.injectedResult])
        let client = makeClient(endpoint)
        _ = try await withTimeout { try await client.connect() }

        // The pin is only meaningful against a declared schema that does not list `_confirm`
        // and forbids extra keys: that is what a schema-pruning client would prune to.
        let tools = try await withTimeout { try await client.listTools() }
        let inject = try #require(tools.first { $0.name == "l4.inject" })
        #expect(inject.inputSchema["properties"]?["_confirm"] == nil)
        #expect(inject.inputSchema["additionalProperties"] == false)
        #expect(inject.parameters.map(\.name) == ["count", "dst", "interface", "spec"])

        let confirmed = Self.bareInjectArgs.merging(["_confirm": .string("tok-7f1c")]) { _, new in new }
        _ = try await withTimeout { try await client.call("l4.inject", confirmed) }

        // The whole arguments object, so a pruner that drops any key fails here.
        let calls = await server.receivedCalls
        #expect(
            calls == [
                RecordedCall(
                    name: "l4.inject",
                    arguments: [
                        "spec": ["layers": [["udp": ["dst_port": 9]], ["payload": ["hex": "00"]]]],
                        "dst": "127.0.0.1",
                        "interface": "lo0",
                        "_confirm": "tok-7f1c",
                    ])
            ])
        #expect(calls.first?.arguments["_confirm"] == "tok-7f1c")
    }

    @Test func needsConfirmationResultIsReturnedNotThrown() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        await server.script("l4.inject", [Self.needsConfirmationResult])
        let client = makeClient(endpoint)
        _ = try await withTimeout { try await client.connect() }

        // Not a thrown `.tool` error: `isError` is false, so the UI parses
        // `L4ConfirmRequest` (status, prompt, confirm_token) from the result.
        let result = try await withTimeout { try await client.call("l4.inject", Self.bareInjectArgs) }
        #expect(
            result == [
                "status": "needs_confirmation",
                "prompt": "Inject 1× UDP 127.0.0.1:9 on lo0",
                "confirm_token": "tok-7f1c",
            ])
        #expect(result["status"]?.stringValue == "needs_confirmation")
        #expect(result["prompt"]?.stringValue == "Inject 1× UDP 127.0.0.1:9 on lo0")
        #expect(result["confirm_token"]?.stringValue == "tok-7f1c")
        // The connection survives the handshake reply.
        try await withTimeout { try await client.ping() }
    }

    @Test func confirmedReissueIsASecondCallWithTheSameNameAndArgsPlusToken() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        await server.script("l4.inject", [Self.needsConfirmationResult, Self.injectedResult])
        let client = makeClient(endpoint)
        _ = try await withTimeout { try await client.connect() }

        // 1. Bare call: the core asks for confirmation and hands out a token.
        let first = try await withTimeout { try await client.call("l4.inject", Self.bareInjectArgs) }
        let token = try #require(first["confirm_token"]?.stringValue)
        #expect(token == "tok-7f1c")

        // 2. The identical call plus `_confirm` runs it.
        let confirmed = Self.bareInjectArgs.merging(["_confirm": .string(token)]) { _, new in new }
        let second = try await withTimeout { try await client.call("l4.inject", confirmed) }
        #expect(second == ["injected": 1])

        var expectedConfirmed = Self.bareInjectArgs
        expectedConfirmed["_confirm"] = "tok-7f1c"
        let calls = await server.receivedCalls
        #expect(
            calls == [
                RecordedCall(name: "l4.inject", arguments: .object(Self.bareInjectArgs)),
                RecordedCall(name: "l4.inject", arguments: .object(expectedConfirmed)),
            ])

        // The second call's arguments minus `_confirm` are exactly the first's.
        var secondMinusToken = try #require(calls.last?.arguments.objectValue)
        #expect(secondMinusToken.removeValue(forKey: "_confirm") == "tok-7f1c")
        #expect(secondMinusToken == calls.first?.arguments.objectValue)
        #expect(secondMinusToken == Self.bareInjectArgs)
    }
    // MARK: Tester additions (stage 5, plan 2026-10-31-l4-parity-fixes unit (d))

    /// AC39's wire half: `confirmable` is decoded from the `tools/list` entry through the real
    /// client — `true` on `l4.inject`, `false` on every tool that does not declare it — and
    /// `ToolDescriptor(json:)` treats a non-bool or missing flag as `false`, never `true`.
    @Test func toolsListDecodesConfirmable() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        let client = makeClient(endpoint)
        _ = try await withTimeout { try await client.connect() }
        let tools = try await withTimeout { try await client.listTools() }
        #expect(tools.map { ($0.name, $0.confirmable) }.map { "\($0.0)=\($0.1)" }
            == ["fake.echo=false", "fake.fail=false", "fake.hang=false", "l4.inject=true"])

        let schema: JSONValue = ["type": "object", "properties": [:], "additionalProperties": false]
        #expect(try ToolDescriptor(json: ["name": "t", "inputSchema": schema, "confirmable": true]).confirmable)
        #expect(!(try ToolDescriptor(json: ["name": "t", "inputSchema": schema, "confirmable": false]).confirmable))
        #expect(!(try ToolDescriptor(json: ["name": "t", "inputSchema": schema]).confirmable))
        #expect(!(try ToolDescriptor(json: ["name": "t", "inputSchema": schema, "confirmable": "true"]).confirmable))
        #expect(!(try ToolDescriptor(json: ["name": "t", "inputSchema": schema, "confirmable": 1]).confirmable))
        #expect(!(try ToolDescriptor(json: ["name": "t", "inputSchema": schema, "confirmable": nil]).confirmable))
        // A tool without a name is malformed, confirmable or not.
        #expect(throws: BusError.malformed("tool without a name")) {
            try ToolDescriptor(json: ["confirmable": true])
        }
    }

    /// A `needs_confirmation` result that the core flags `isError: true` (a future shape, or a
    /// proxy that rewrites it) is a thrown tool error, not a silent dialog: the UI never shows a
    /// confirm prompt for a reply the core called a failure.
    @Test func needsConfirmationWithIsErrorIsAToolError() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        var members = try #require(Self.needsConfirmationResult.objectValue)
        members["isError"] = true
        await server.script("l4.inject", [.object(members)])
        let client = makeClient(endpoint)
        _ = try await withTimeout { try await client.connect() }
        await #expect(throws: BusError.tool(message: "Inject 1× UDP 127.0.0.1:9 on lo0")) {
            try await withTimeout { try await client.call("l4.inject", Self.bareInjectArgs) }
        }
        // The bare call still reached the wire with exactly its arguments.
        let calls = await server.receivedCalls
        #expect(calls == [RecordedCall(name: "l4.inject", arguments: .object(Self.bareInjectArgs))])
        try await withTimeout { try await client.ping() }
    }

    /// A `needs_confirmation` reply whose `structuredContent` is malformed (no `confirm_token`)
    /// is still returned as a result for the UI's parser to reject — the client never invents a
    /// token — and a second `needs_confirmation` to a confirmed re-issue (the pruning failure
    /// mode seen live on the TUI) is visible as such to the caller.
    @Test func malformedAndRepeatedConfirmationsAreReturnedAsResults() async throws {
        let server = FakeBusServer()
        let endpoint = try await server.start()
        defer { Task { await server.stop() } }
        let tokenless: JSONValue = [
            "content": [["type": "text", "text": "needs confirmation"]],
            "structuredContent": ["status": "needs_confirmation", "prompt": "Inject?"],
            "isError": false,
        ]
        await server.script("l4.inject", [tokenless, Self.needsConfirmationResult])
        let client = makeClient(endpoint)
        _ = try await withTimeout { try await client.connect() }

        let first = try await withTimeout { try await client.call("l4.inject", Self.bareInjectArgs) }
        #expect(first == ["status": "needs_confirmation", "prompt": "Inject?"])
        #expect(first["confirm_token"] == nil)

        let confirmed = Self.bareInjectArgs.merging(["_confirm": .string("stale")]) { _, new in new }
        let second = try await withTimeout { try await client.call("l4.inject", confirmed) }
        #expect(second["status"]?.stringValue == "needs_confirmation")
        #expect(second["confirm_token"]?.stringValue == "tok-7f1c")
        let calls = await server.receivedCalls
        #expect(calls.count == 2)
        #expect(calls[1].arguments["_confirm"] == "stale")
        #expect(calls[1].arguments.objectValue?.count == 4)
    }
}
