@testable import AitmproxyKit
import Foundation

/// Binary bodies for the image / hex / protobuf / MessagePack viewer tests
/// (stories S-023, S-024) and the flow details that carry them.
extension Fixtures {
    /// A valid 4×4 RGBA PNG with an sRGB chunk (97 bytes).
    static let tinyPNG = Data(base64Encoded:
        "iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAAXNSR0IArs4c6QAAABtJREFUeNpjUE1+/f8/EEPpBgYkDohuYCCo"
        + "AgDXYSv1p0H72AAAAABJRU5ErkJggg==")!

    /// The same 4×4 image as a baseline JPEG (850 bytes, JFIF + Exif).
    static let tinyJPEG = Data(base64Encoded:
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

    /// A message with a varint, a string, a nested message, a float and a zigzag-encoded sint:
    /// `1: 150 · 2: "testing" · 3: {1: 1, 2: "ok"} · 4: 1.0f · 5: -1 (sint32)`.
    static let protobufSample = Data([
        0x08, 0x96, 0x01,
        0x12, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67,
        0x1A, 0x06, 0x08, 0x01, 0x12, 0x02, 0x6F, 0x6B,
        0x25, 0x00, 0x00, 0x80, 0x3F,
        0x28, 0x01,
    ])

    /// A 12-entry map touching every MessagePack family: nil, bool, negative
    /// fixint, uint8, int16, float32, float64, str, bin, array, map, fixext1.
    static let msgpackSample = Data([
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

    /// Flow 60: `GET /assets/logo.png` → the 4×4 PNG.
    static let imageDetail = binaryDetail(
        n: 60, method: "GET", path: "/assets/logo.png", host: "cdn.shop-staging.test",
        contentType: "image/png", body: tinyPNG)

    /// Flow 61: `POST /grpc/cart.CartService/Get` → a protobuf response.
    static let protobufDetail = binaryDetail(
        n: 61, method: "POST", path: "/grpc/cart.CartService/Get", host: "api.shop-staging.test",
        contentType: "application/x-protobuf", body: protobufSample, requestBody: Data([0x08, 0x2A]))

    /// Flow 62: `GET /api/cart.msgpack` → a MessagePack response.
    static let msgpackDetail = binaryDetail(
        n: 62, method: "GET", path: "/api/cart.msgpack", host: "api.shop-staging.test",
        contentType: "application/msgpack", body: msgpackSample)

    private static func binaryDetail(n: Int, method: String, path: String, host: String,
                                     contentType: String, body: Data, requestBody: Data? = nil) -> FlowDetail {
        var requestHeaders: [HTTPMessage.Header] = [
            .init("host", host),
            .init("accept", "*/*"),
            .init("user-agent", userAgent(obscura)),
        ]
        if requestBody != nil { requestHeaders.append(.init("content-type", contentType)) }
        return FlowDetail(
            id: id(n),
            request: HTTPMessage(startLine: "\(method) \(path) HTTP/2", headers: requestHeaders, body: requestBody),
            response: HTTPMessage(
                startLine: "HTTP/2 200 OK",
                headers: [
                    .init("content-type", contentType),
                    .init("content-length", String(body.count)),
                    .init("server", "envoy"),
                ],
                body: body),
            connection: ConnectionInfo(httpVersion: "HTTP/2", tlsVersion: "TLS 1.3", alpn: "h2", sni: host,
                                       clientAddress: "127.0.0.1:\(52_000 + n)", serverAddress: "10.0.4.12:443"))
    }
}
