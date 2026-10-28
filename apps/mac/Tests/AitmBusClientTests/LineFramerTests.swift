import Foundation
import Testing

@testable import AitmBusClient

@Suite struct LineFramerTests {
    @Test func splitsPartialAndMultipleLines() throws {
        var framer = LineFramer()
        #expect(try framer.append(Data("{\"a\":".utf8)).isEmpty)
        let first = try framer.append(Data("1}\n{\"b\":2}\r\n\n{\"c\"".utf8))
        #expect(first.map { String(decoding: $0, as: UTF8.self) } == ["{\"a\":1}", "{\"b\":2}"])
        let second = try framer.append(Data(":3}\n".utf8))
        #expect(second.map { String(decoding: $0, as: UTF8.self) } == ["{\"c\":3}"])
        #expect(try framer.append(Data()).isEmpty)
    }

    @Test func rejectsOversizedLine() throws {
        var framer = LineFramer()
        let chunk = Data(repeating: UInt8(ascii: "x"), count: 4 * 1024 * 1024)
        for _ in 0..<4 { _ = try framer.append(chunk) }  // exactly 16 MiB, still allowed
        #expect(throws: BusError.malformed("line exceeds \(LineFramer.maxLineBytes) bytes")) {
            try framer.append(Data([UInt8(ascii: "y")]))
        }
    }

    @Test func parsesMessages() throws {
        let response = try JSONRPCMessage.parse(Data(#"{"jsonrpc":"2.0","id":7,"result":{"ok":true}}"#.utf8))
        #expect(response == .response(JSONRPCResponse(id: 7, result: ["ok": true], error: nil)))
        let refusal = try JSONRPCMessage.parse(
            Data(#"{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"unauthorized"}}"#.utf8))
        guard case .response(let body) = refusal else { Issue.record("not a response"); return }
        #expect(body.id.isNull)
        #expect(body.error == JSONRPCErrorBody(code: -32001, message: "unauthorized", data: nil))
        let notification = try JSONRPCMessage.parse(Data(#"{"jsonrpc":"2.0","method":"notifications/aitm/flow","params":{"event":"created"}}"#.utf8))
        #expect(notification == .notification(JSONRPCNotification(method: "notifications/aitm/flow", params: ["event": "created"])))
        #expect(throws: BusError.self) { try JSONRPCMessage.parse(Data("[1]".utf8)) }
        #expect(throws: BusError.self) { try JSONRPCMessage.parse(Data("{\"jsonrpc\":\"2.0\"}".utf8)) }
    }

    @Test func encodesRequestLines() {
        let line = String(decoding: JSONRPCRequest(id: 3, method: "ping", params: [:]).encodedLine(), as: UTF8.self)
        #expect(line == "{\"id\":3,\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"params\":{}}\n")
        let note = String(decoding: JSONRPCNotification(method: "notifications/initialized").encodedLine(), as: UTF8.self)
        #expect(note == "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n")
    }
}
