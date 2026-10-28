import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// F5: decoding a `flow.detail` result (shape from crates/aitm-plugins/src/detail.rs).
@Suite struct FlowDetailWireTests {
    /// base64 of a known body, as the bus sends it (Value::Bytes → base64 string).
    static func b64(_ s: String) -> JSONValue { .string(Data(s.utf8).base64EncodedString()) }

    static var httpDetail: JSONValue {
        [
            "id": "11111111-1111-4111-8111-111111111111",
            "kind": "http",
            "request": [
                "method": "POST", "scheme": "https", "authority": "api.example.test",
                "path": "/api/login", "version": "HTTP/1.1",
                "headers": [["content-type", "application/json"], ["x-debug", "1"]],
                "body": b64("{\"user\":\"ops\"}"), "body_size": 14, "body_truncated": false,
            ],
            "response": [
                "status": 200, "version": "HTTP/1.1",
                "headers": [["content-type", "application/json"], ["set-cookie", "s=abc; HttpOnly"]],
                "body": b64("{\"ok\":true}"), "body_size": 11, "body_truncated": false,
            ],
            "client_conn": ["peer": "127.0.0.1:52100", "sni": "api.example.test", "alpn": "http/1.1", "tls": true, "established": "2026-10-28T00:00:00Z", "process": .null],
            "server_conn": ["peer": "93.184.216.34:443", "sni": "api.example.test", "alpn": "http/1.1", "tls": true, "established": "2026-10-28T00:00:00Z"],
            "meta": ["marks": .array([]), "comment": .null, "is_replay": false, "created": "2026-10-28T00:00:00Z", "duration_ms": 58, "truncated": false, "edited": false, "origin": .null],
            "intercept": "observed",
            "edited": false,
        ]
    }

    @Test func decodesHTTPRequestAndResponse() throws {
        let d = try #require(FlowDetail(detailJSON: Self.httpDetail))
        #expect(d.id.raw == "11111111-1111-4111-8111-111111111111")
        #expect(d.request.startLine == "POST /api/login HTTP/1.1")
        #expect(d.request.header("content-type") == "application/json")
        #expect(d.request.header("x-debug") == "1")
        #expect(d.request.bodyText == "{\"user\":\"ops\"}")
        let resp = try #require(d.response)
        #expect(resp.startLine == "HTTP/1.1 200 OK")
        #expect(resp.header("set-cookie") == "s=abc; HttpOnly")
        #expect(resp.bodyText == "{\"ok\":true}")
        #expect(d.connection.sni == "api.example.test")
        #expect(d.connection.alpn == "http/1.1")
        #expect(d.connection.clientAddress == "127.0.0.1:52100")
        #expect(d.connection.serverAddress == "93.184.216.34:443")
    }

    @Test func handlesNullResponseAndBody() throws {
        var obj = Self.httpDetail.objectValue!
        obj["response"] = .null
        obj["request"] = ["method": "GET", "path": "/ping", "version": "HTTP/1.1", "headers": .array([]), "body": .null]
        let d = try #require(FlowDetail(detailJSON: .object(obj)))
        #expect(d.response == nil)
        #expect(d.request.startLine == "GET /ping HTTP/1.1")
        #expect(d.request.body == nil)
        #expect(d.request.headers.isEmpty)
    }

    @Test func websocketReturnsNilForFlowDetailButFramesDecode() {
        let ws: JSONValue = [
            "id": "22222222-2222-4222-8222-222222222222", "kind": "websocket",
            "handshake": "33333333-3333-4333-8333-333333333333",
            "messages": [
                ["dir": "client_to_server", "opcode": "text", "length": 5, "injected": false, "timestamp": "2026-10-28T00:00:01Z", "data": Self.b64("hello")],
                ["dir": "server_to_client", "opcode": "text", "length": 2, "injected": true, "timestamp": "2026-10-28T00:00:02Z", "data": Self.b64("hi")],
            ],
        ]
        #expect(FlowDetail(detailJSON: ws) == nil) // HTTP-only; WS frames via WSFrameDetail
        let frames = WSFrameDetail.frames(in: ws)
        #expect(frames.count == 2)
        #expect(frames[0].direction == .clientToServer && frames[0].data.flatMap { String(data: $0, encoding: .utf8) } == "hello")
        #expect(frames[1].injected && frames[1].opcode == "text")
    }

    @Test func wsDetailDecodesHandshakeFramesAndConnection() throws {
        let ws: JSONValue = [
            "id": "22222222-2222-4222-8222-222222222222", "kind": "websocket",
            "handshake": "33333333-3333-4333-8333-333333333333",
            "client_conn": ["alpn": "http/1.1", "sni": "api.test", "peer": "127.0.0.1:51000"],
            "server_conn": ["peer": "10.0.0.1:443"],
            "messages": [
                ["dir": "client_to_server", "opcode": "text", "length": 5, "injected": false, "data": Self.b64("hello")],
                ["dir": "server_to_client", "opcode": "binary", "length": 3, "injected": false, "data": Self.b64("\u{01}\u{02}\u{03}")],
            ],
        ]
        let d = try #require(WSDetail(detailJSON: ws))
        #expect(d.handshakeFlowID == "33333333-3333-4333-8333-333333333333")
        #expect(d.frames.count == 2)
        #expect(d.sentCount == 1 && d.receivedCount == 1)
        #expect(d.connection.clientAddress == "127.0.0.1:51000" && d.connection.serverAddress == "10.0.0.1:443")
        // An HTTP result is not a WSDetail.
        #expect(WSDetail(detailJSON: ["id": "x", "kind": "http", "request": ["method": "GET", "path": "/"]]) == nil)
    }

    @Test func wsFramePreviewAndBodyKind() {
        let jsonFrame = WSFrameDetail(direction: .serverToClient, opcode: "text", length: 13,
                                      data: Data(#"{"type":"ok"}"#.utf8))
        #expect(jsonFrame.preview == #"{"type":"ok"}"#)
        #expect(jsonFrame.bodyKind == .json)

        let binary = WSFrameDetail(direction: .clientToServer, opcode: "binary", length: 3,
                                   data: Data([0xFF, 0xFE, 0xFD]))
        #expect(binary.preview == "3 bytes")
        #expect(binary.bodyKind == .binary)

        let ping = WSFrameDetail(direction: .clientToServer, opcode: "ping", length: 0)
        #expect(ping.preview == "Ping")
    }
}
