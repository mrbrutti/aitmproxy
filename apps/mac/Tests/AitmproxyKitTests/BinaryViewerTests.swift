import Foundation
import Testing
@testable import AitmproxyKit

/// The binary bodies `BinaryViewerTests` decodes: one protobuf message, one MessagePack map
/// touching every family, and a 4×4 image as PNG and as JPEG.
private enum BinaryViewerInputs {
    /// A message with a varint, a string, a nested message, a float and a zigzag-encoded sint:
    /// `1: 150 · 2: "testing" · 3: {1: 1, 2: "ok"} · 4: 1.0f · 5: -1 (sint32)`.
    static let protobuf = Data([
        0x08, 0x96, 0x01,
        0x12, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67,
        0x1A, 0x06, 0x08, 0x01, 0x12, 0x02, 0x6F, 0x6B,
        0x25, 0x00, 0x00, 0x80, 0x3F,
        0x28, 0x01,
    ])

    /// A 12-entry map touching every MessagePack family: nil, bool, negative
    /// fixint, uint8, int16, float32, float64, str, bin, array, map, fixext1.
    static let msgpack = Data([
        0x8C,
        0xA3, 0x6E, 0x69, 0x6C, 0xC0,                                     // "nil": nil
        0xA4, 0x62, 0x6F, 0x6F, 0x6C, 0xC3,                               // "bool": true
        0xA3, 0x69, 0x6E, 0x74, 0xFF,                                     // "int": -1
        0xA5, 0x75, 0x69, 0x6E, 0x74, 0x38, 0xCC, 0xC8,                   // "uint8": 200
        0xA5, 0x69, 0x6E, 0x74, 0x31, 0x36, 0xD1, 0xFE, 0xD4,             // "int16": -300
        0xA5, 0x66, 0x6C, 0x6F, 0x61, 0x74, 0xCA, 0x3F, 0xC0, 0x00, 0x00, // "float": 1.5
        0xA6, 0x64, 0x6F, 0x75, 0x62, 0x6C, 0x65,                         // "double": 2.5
        0xCB, 0x40, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA3, 0x73, 0x74, 0x72, 0xA2, 0x68, 0x69,                         // "str": "hi"
        0xA3, 0x62, 0x69, 0x6E, 0xC4, 0x03, 0x01, 0x02, 0x03,             // "bin": 01 02 03
        0xA5, 0x61, 0x72, 0x72, 0x61, 0x79, 0x92, 0x01, 0x02,             // "array": [1, 2]
        0xA3, 0x6D, 0x61, 0x70, 0x81, 0xA1, 0x61, 0x01,                   // "map": {"a": 1}
        0xA3, 0x65, 0x78, 0x74, 0xD4, 0x01, 0x2A,                         // "ext": fixext1 type 1, 0x2a
    ])

    /// A valid 4×4 RGBA PNG with an sRGB chunk (97 bytes).
    static let png = Data(base64Encoded:
        "iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAAXNSR0IArs4c6QAAABtJREFUeNpjUE1+/f8/EEPpBgYkDohuYCCo"
        + "AgDXYSv1p0H72AAAAABJRU5ErkJggg==")!

    /// The same 4×4 image as a baseline JPEG (850 bytes, JFIF + Exif).
    static let jpeg = Data(base64Encoded:
        "/9j/4AAQSkZJRgABAQAASABIAAD/4QBMRXhpZgAATU0AKgAAAAgAAYdpAAQAAAABAAAAGgAAAAAAA6ABAAMAAAABAAEAAKACAAQA"
        + "AAABAAAABKADAAQAAAABAAAABAAAAAD/7QA4UGhvdG9zaG9wIDMuMAA4QklNBAQAAAAAAAA4QklNBCUAAAAAABDUHYzZjwCyBOmA"
        + "CZjs+EJ+/8AAEQgABAAEAwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//EALUQAAIBAwMCBAMFBQQE"
        + "AAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldY"
        + "WVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk"
        + "5ebn6Onq8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCAkKC//EALURAAIBAgQEAwQHBQQEAAECdwABAgMR"
        + "BAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM1LwFWJy0QoWJDThJfEXGBkaJicoKSo1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdo"
        + "aWpzdHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uLj5OXm5+jp6vLz"
        + "9PX29/j5+v/bAEMAAgICAgICAwICAwQDAwMEBQQEBAQFBwUFBQUFBwgHBwcHBwcICAgICAgICAoKCgoKCgsLCwsLDQ0NDQ0NDQ0N"
        + "Df/bAEMBAgICAwMDBgMDBg0JBwkNDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDf/dAAQA"
        + "Af/aAAwDAQACEQMRAD8A+k/hXey6P4dube3G5TqV2v33i4t3+zLxC0a/chU9ML91Nsaoi+lf8JJe/wB3/wAj3P8A8erynwD/AMgS"
        + "4/7Cmp/+lctdrX9eYr+PP1f5n00/iZ//2Q==")!
}

/// S-024 raw protobuf and MessagePack decoding, S-023 image dimensions.
@Suite struct BinaryViewerTests {
    // MARK: - Protobuf

    @Test func decodesVarintStringAndNestedMessage() throws {
        let fields = try ProtobufRaw.decode(BinaryViewerInputs.protobuf)
        #expect(fields.map(\.number) == [1, 2, 3, 4, 5])
        #expect(fields.map(\.wireType) == [.varint, .lengthDelimited, .lengthDelimited, .fixed32, .varint])
        #expect(fields[0].valueText == "150 (zigzag 75)")
        #expect(fields[0].nested == nil)
        #expect(fields[1].valueText == "\"testing\"")
        #expect(fields[1].nested == nil, "the string does not walk as a message")
        #expect(fields[3].valueText == "0x3f800000 (float 1.0)")
        #expect(fields[4].valueText == "1 (zigzag -1)")

        let nested = try #require(fields[2].nested)
        #expect(nested.map(\.number) == [1, 2])
        #expect(nested[0].valueText == "1 (zigzag -1)")
        #expect(nested[1].valueText == "\"ok\"")
        #expect(fields[2].valueText == "6 bytes · 08 01 12 02 6f 6b", "control bytes keep it from reading as text")
    }

    @Test func zigzagAndSignedReadings() {
        #expect(ProtobufRaw.varintText(0) == "0")
        #expect(ProtobufRaw.varintText(1) == "1 (zigzag -1)")
        #expect(ProtobufRaw.varintText(2) == "2 (zigzag 1)")
        #expect(ProtobufRaw.varintText(4_294_967_294) == "4294967294 (zigzag 2147483647)")
        #expect(ProtobufRaw.varintText(4_294_967_295) == "4294967295 (zigzag -2147483648)")
        #expect(ProtobufRaw.varintText(UInt64.max) == "18446744073709551615 (signed -1)")
        #expect(ProtobufRaw.fixed64Text(0x3FF0_0000_0000_0000) == "0x3ff0000000000000 (double 1.0)")
        #expect(ProtobufRaw.fixed32Text(0xC000_0000) == "0xc0000000 (float -2.0)")
    }

    @Test func lengthDelimitedBytesAndFixedWidths() throws {
        // 1: bytes ff fe (not text, not a message: tag ff… runs out) · 2: fixed64 1.0 · 3: 20 bytes
        var data = Data([0x0A, 0x02, 0xFF, 0xFE, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F, 0x1A, 0x14])
        data.append(Data(repeating: 0x80, count: 20))
        let fields = try ProtobufRaw.decode(data)
        #expect(fields.count == 3)
        #expect(fields[0].valueText == "2 bytes · ff fe")
        #expect(fields[0].nested == nil)
        #expect(fields[1].wireType == .fixed64)
        #expect(fields[1].valueText == "0x3ff0000000000000 (double 1.0)")
        #expect(fields[2].valueText == "20 bytes · 80 80 80 80 80 80 80 80 80 80 80 80 80 80 80 80 …")
        #expect(WireType.lengthDelimited.description == "length-delimited")
        #expect(try ProtobufRaw.decode(Data()).isEmpty)
    }

    @Test func groupsNestLikeMessages() throws {
        // 1: group { 2: 7 } · 3: 1
        let fields = try ProtobufRaw.decode(Data([0x0B, 0x10, 0x07, 0x0C, 0x18, 0x01]))
        #expect(fields.map(\.wireType) == [.startGroup, .varint])
        #expect(fields[0].valueText == "1 field")
        #expect(fields[0].nested?.map(\.number) == [2])
    }

    @Test func protobufErrorsCarryOffsets() {
        func offset(_ bytes: [UInt8]) -> Int? {
            do {
                _ = try ProtobufRaw.decode(Data(bytes))
                return nil
            } catch {
                return error.offset
            }
        }
        #expect(offset([0x08]) == 1, "varint value missing")
        #expect(offset([0x08, 0x96]) == 1, "varint runs past the end")
        #expect(offset([0x12, 0x05, 0x61]) == 1, "length past the end")
        #expect(offset([0x0D, 0x00, 0x00]) == 1, "fixed32 needs 4 bytes")
        #expect(offset([0x0E]) == 0, "wire type 6 is reserved")
        #expect(offset([0x00, 0x01]) == 0, "field number 0")
        #expect(offset([0x08, 0x01, 0x0C]) == 2, "end group without a start")
        #expect(offset([0x0B, 0x10, 0x07]) == 3, "group never closed")
        #expect(offset(Array(repeating: 0xFF, count: 11)) == 0, "varint longer than 10 bytes")
        #expect(ProtobufRawError(offset: 3, message: "x").description == "x at byte 3")
        #expect(offset(Array(BinaryViewerInputs.protobuf)) == nil)
        #expect(BodyKind.detect(contentType: nil, data: BinaryViewerInputs.protobuf) == .protobuf)
    }

    // MARK: - MessagePack

    @Test func decodesEveryFamilyIntoTheTree() throws {
        let root = try MessagePack.decode(BinaryViewerInputs.msgpack)
        #expect(root.kind == .object(count: 12))
        #expect(root.children.map(\.key) == ["nil", "bool", "int", "uint8", "int16", "float", "double", "str", "bin",
                                              "array", "map", "ext"])
        let byKey = Dictionary(uniqueKeysWithValues: root.children.map { ($0.key ?? "", $0) })
        #expect(byKey["nil"]?.kind == .null)
        #expect(byKey["bool"]?.scalarText == "true")
        #expect(byKey["int"]?.scalarText == "-1")
        #expect(byKey["uint8"]?.scalarText == "200")
        #expect(byKey["int16"]?.scalarText == "-300")
        #expect(byKey["float"]?.scalarText == "1.5")
        #expect(byKey["double"]?.scalarText == "2.5")
        #expect(byKey["double"]?.kind == .number)
        #expect(byKey["str"]?.scalarText == "hi")
        #expect(byKey["str"]?.kind == .string)
        #expect(byKey["bin"]?.scalarText == "AQID")
        #expect(byKey["array"]?.children.map(\.scalarText) == ["1", "2"])
        #expect(byKey["array"]?.children.map(\.path) == ["$.array[0]", "$.array[1]"])
        #expect(byKey["map"]?.children.first?.path == "$.map.a")
        #expect(byKey["ext"]?.children.map(\.key) == ["ext", "data"])
        #expect(byKey["ext"]?.children.map(\.scalarText) == ["1", "Kg=="])
        #expect(JSONTree.copyText(for: try #require(byKey["map"])) == "{\n  \"a\": 1\n}")
        #expect(BodyKind.detect(contentType: nil, data: BinaryViewerInputs.msgpack) == .messagepack)
    }

    @Test func wideIntegersAndLongContainers() throws {
        var bytes: [UInt8] = [0x95]
        bytes += [0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]        // uint64 max
        bytes += [0xD3, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]        // int64 min
        bytes += [0xD2, 0xFF, 0xFF, 0xFF, 0xFE]                                 // int32 -2
        bytes += [0xDC, 0x00, 0x01, 0xD9, 0x02, 0x6F, 0x6B]                     // array16 ["ok"] with str8
        bytes += [0xDE, 0x00, 0x01, 0x01, 0xC5, 0x00, 0x01, 0xAA]               // map16 {1: bin16 aa}
        let root = try MessagePack.decode(Data(bytes))
        #expect(root.children.map(\.scalarText).prefix(3) == ["18446744073709551615", "-9223372036854775808", "-2"])
        #expect(root.children[3].kind == .array(count: 1))
        #expect(root.children[3].children[0].scalarText == "ok")
        #expect(root.children[4].children[0].key == "1")
        #expect(root.children[4].children[0].path == "$[4][\"1\"]")
        #expect(root.children[4].children[0].scalarText == "qg==")
    }

    @Test func messagePackErrorsCarryOffsets() {
        func offset(_ bytes: [UInt8]) -> Int? {
            do {
                _ = try MessagePack.decode(Data(bytes))
                return nil
            } catch {
                return error.offset
            }
        }
        #expect(offset([]) == 0)
        #expect(offset([0x82, 0xA1, 0x61]) == 3, "map value missing")
        #expect(offset([0xA5, 0x61, 0x62]) == 1, "str needs 5 bytes")
        #expect(offset([0xCB, 0x40, 0x04]) == 1, "float64 needs 8 bytes")
        #expect(offset([0xDC, 0x00]) == 1, "array16 length truncated")
        #expect(offset([0xC1]) == 0, "reserved")
        #expect(offset([0x01, 0x02]) == 1, "trailing content")
        #expect(offset([0x81, 0x90, 0x01]) == 1, "container as a map key")
        #expect(MessagePackError(offset: 3, message: "x").description == "x at byte 3")
    }

    // MARK: - Images

    @Test func tinyImagesDecodeWithDimensions() {
        #expect(BodyKind.imageInfo(BinaryViewerInputs.png) == .image(format: .png, width: 4, height: 4))
        #expect(BodyKind.imageInfo(BinaryViewerInputs.jpeg) == .image(format: .jpeg, width: 4, height: 4))
    }
}
