import Foundation
import Testing

@testable import AitmBusClient

@Suite struct JSONValueTests {
    @Test func integersSerializeWithoutFraction() throws {
        #expect(JSONValue.number(1).serialized() == "1")
        #expect(JSONValue.number(-42).serialized() == "-42")
        #expect(JSONValue.number(1.5).serialized() == "1.5")
        #expect(JSONValue.number(1e19).serialized() == "1e+19")
        let parsed = try JSONValue.parse("[1, 2.5, -3, 1e2]")
        #expect(parsed == [1, 2.5, -3, 100])
        #expect(parsed[0]?.intValue == 1)
        #expect(parsed[1]?.intValue == nil)
        #expect(parsed[1]?.doubleValue == 2.5)
    }

    @Test func roundTripsNestingWithSortedKeys() throws {
        let value: JSONValue = [
            "z": [1, [true, nil], ["k": "v"]],
            "a": "quote\" back\\ nl\n tab\t é",
            "m": 3.25,
        ]
        let text = value.serialized()
        #expect(text == #"{"a":"quote\" back\\ nl\n tab\t é","m":3.25,"z":[1,[true,null],{"k":"v"}]}"#)
        #expect(try JSONValue.parse(text) == value)
        let pretty = value.serialized(prettyPrinted: true)
        #expect(pretty.hasPrefix("{\n  \"a\": "))
        #expect(try JSONValue.parse(pretty) == value)
    }

    @Test func bridgesBoolsAndNumbersDistinctly() throws {
        #expect(JSONValue(any: true) == .bool(true))
        #expect(JSONValue(any: 1) == .number(1))
        #expect(JSONValue(any: NSNumber(value: true)) == .bool(true))
        #expect(JSONValue(any: NSNumber(value: 0)) == .number(0))
        #expect(try JSONValue.parse("{\"b\":false,\"n\":0}") == ["b": false, "n": 0])
        #expect(JSONValue.number(7).anyValue as? Int == 7)
        #expect(JSONValue.number(7.5).anyValue as? Double == 7.5)
        #expect(JSONValue.bool(false).anyValue as? Bool == false)
        #expect(JSONValue.null.anyValue is NSNull)
    }

    @Test func codableRoundTrip() throws {
        struct Envelope: Codable, Equatable {
            var body: JSONValue
        }
        let envelope = Envelope(body: ["n": 1, "f": 0.5, "s": "x", "l": [nil, true], "o": [:]])
        let data = try JSONEncoder().encode(envelope)
        #expect(String(decoding: data, as: UTF8.self).contains("\"n\":1"))
        #expect(try JSONDecoder().decode(Envelope.self, from: data) == envelope)
    }

    @Test func accessors() {
        let value: JSONValue = ["list": [10, "s"], "flag": true]
        #expect(value["list"]?[0]?.intValue == 10)
        #expect(value["list"]?[1]?.stringValue == "s")
        #expect(value["list"]?[2] == nil)
        #expect(value["flag"]?.boolValue == true)
        #expect(value["missing"] == nil)
        #expect(value.objectValue?.count == 2)
        #expect(value["list"]?.arrayValue?.count == 2)
        #expect(JSONValue.null.isNull)
        #expect(JSONValue.string("1").intValue == nil)
    }

    @Test func rejectsInvalidText() {
        #expect(throws: BusError.self) { try JSONValue.parse("{not json") }
    }
}
