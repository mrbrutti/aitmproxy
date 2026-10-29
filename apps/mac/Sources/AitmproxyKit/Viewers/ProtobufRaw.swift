import Foundation

/// The six protobuf wire types (the low three bits of a tag).
public enum WireType: Int, Hashable, Sendable, CustomStringConvertible {
    case varint = 0
    case fixed64 = 1
    case lengthDelimited = 2
    case startGroup = 3
    case endGroup = 4
    case fixed32 = 5

    /// The column text in the raw-decode table.
    public var description: String {
        switch self {
        case .varint: "varint"
        case .fixed64: "fixed64"
        case .lengthDelimited: "length-delimited"
        case .startGroup: "group"
        case .endGroup: "end group"
        case .fixed32: "fixed32"
        }
    }
}

/// One field of a schema-less protobuf decode (foundation §2.7 "protobuf
/// (raw decode)"): the field number, its wire type, the value in every
/// reading the bytes allow, and the fields of a nested message when the
/// payload walks as one.
public struct ProtoField: Hashable, Sendable {
    public var number: Int
    public var wireType: WireType
    /// Varints as unsigned decimal plus the zigzag reading in parentheses;
    /// fixed widths as hex plus the float / double; length-delimited as the
    /// UTF-8 text when printable, else `N bytes` and a hex preview.
    public var valueText: String
    /// The payload decoded as a message, kept only when the whole payload decodes.
    public var nested: [ProtoField]?

    public init(number: Int, wireType: WireType, valueText: String, nested: [ProtoField]? = nil) {
        self.number = number
        self.wireType = wireType
        self.valueText = valueText
        self.nested = nested
    }
}

/// Bytes that do not walk as protobuf: where (byte offset) and why.
public struct ProtobufRawError: Error, Hashable, Sendable, CustomStringConvertible {
    public var offset: Int
    public var message: String

    public init(offset: Int, message: String) {
        self.offset = offset
        self.message = message
    }

    public var description: String { "\(message) at byte \(offset)" }
}

public enum ProtobufRaw {
    /// Nested messages deeper than this are left as bytes.
    static let maxDepth = 32
    /// Bytes of a length-delimited payload shown in the hex preview.
    static let previewBytes = 16

    /// Walks `data` as one message. Throws when a tag, varint or length runs
    /// past the end, on wire types 6 and 7, field number 0, or an unmatched group.
    public static func decode(_ data: Data) throws(ProtobufRawError) -> [ProtoField] {
        var decoder = Decoder(bytes: Array(data), depth: 0)
        return try decoder.fields(closingGroup: nil)
    }

    // MARK: Value text

    /// `150 (zigzag 75)`; a value past `Int64.max` is almost always a negative
    /// int32 / int64 and shows that reading instead.
    static func varintText(_ value: UInt64) -> String {
        if value > UInt64(Int64.max) {
            return "\(value) (signed \(Int64(bitPattern: value)))"
        }
        if value == 0 { return "0" }
        let zigzag = Int64(value >> 1) ^ -Int64(value & 1)
        return "\(value) (zigzag \(zigzag))"
    }

    static func fixed32Text(_ bits: UInt32) -> String {
        String(format: "0x%08x", bits) + " (float \(Float(bitPattern: bits)))"
    }

    static func fixed64Text(_ bits: UInt64) -> String {
        String(format: "0x%016llx", bits) + " (double \(Double(bitPattern: bits)))"
    }

    /// The quoted UTF-8 text when every scalar is printable (tabs and newlines
    /// allowed), else `N bytes · 0a 02 ff …`.
    static func bytesText(_ payload: ArraySlice<UInt8>) -> String {
        if let text = printableText(payload) { return JSONTree.quote(text) }
        let count = payload.count
        let preview = payload.prefix(previewBytes).map(HexDump.hexByte).joined(separator: " ")
        let tail = count > previewBytes ? " …" : ""
        return count == 1 ? "1 byte · \(preview)" : "\(count) bytes · \(preview)\(tail)"
    }

    static func printableText(_ payload: ArraySlice<UInt8>) -> String? {
        guard !payload.isEmpty, let text = String(bytes: payload, encoding: .utf8) else { return nil }
        for scalar in text.unicodeScalars {
            if scalar.value < 0x20, scalar != "\n", scalar != "\r", scalar != "\t" { return nil }
            if scalar.value == 0x7F { return nil }
        }
        return text
    }

    // MARK: Decoder

    private struct Decoder {
        let bytes: [UInt8]
        var pos = 0
        let depth: Int

        init(bytes: [UInt8], depth: Int) {
            self.bytes = bytes
            self.depth = depth
        }

        /// Fields until the end of the bytes, or until the end-group tag of `closingGroup`.
        mutating func fields(closingGroup: Int?) throws(ProtobufRawError) -> [ProtoField] {
            var result: [ProtoField] = []
            while pos < bytes.count {
                let tagStart = pos
                let tag = try varint()
                let number = tag >> 3
                guard number >= 1, number <= 536_870_911 else {
                    throw ProtobufRawError(offset: tagStart, message: "Field number \(number) out of range")
                }
                guard let wireType = WireType(rawValue: Int(tag & 0x7)) else {
                    throw ProtobufRawError(offset: tagStart, message: "Wire type \(tag & 0x7) is reserved")
                }
                let field = Int(number)
                switch wireType {
                case .varint:
                    let value = try varint()
                    result.append(ProtoField(number: field, wireType: .varint, valueText: varintText(value)))
                case .fixed64:
                    let bits = try fixed(8)
                    result.append(ProtoField(number: field, wireType: .fixed64, valueText: fixed64Text(bits)))
                case .fixed32:
                    let bits = try fixed(4)
                    result.append(ProtoField(number: field, wireType: .fixed32, valueText: fixed32Text(UInt32(bits))))
                case .lengthDelimited:
                    let lengthStart = pos
                    let length = try varint()
                    guard length <= UInt64(bytes.count - pos) else {
                        throw ProtobufRawError(offset: lengthStart, message: "Length \(length) runs past the end")
                    }
                    let payload = bytes[pos..<(pos + Int(length))]
                    pos += Int(length)
                    result.append(ProtoField(number: field, wireType: .lengthDelimited,
                                             valueText: bytesText(payload), nested: nestedMessage(payload)))
                case .startGroup:
                    let inner = try fields(closingGroup: field)
                    let count = inner.count
                    result.append(ProtoField(number: field, wireType: .startGroup,
                                             valueText: count == 1 ? "1 field" : "\(count) fields", nested: inner))
                case .endGroup:
                    guard closingGroup == field else {
                        throw ProtobufRawError(offset: tagStart, message: "End of group \(field) without a start")
                    }
                    return result
                }
            }
            if let closingGroup {
                throw ProtobufRawError(offset: pos, message: "Group \(closingGroup) is not closed")
            }
            return result
        }

        /// The payload as a message when it is non-empty and walks completely; nil otherwise.
        func nestedMessage(_ payload: ArraySlice<UInt8>) -> [ProtoField]? {
            guard !payload.isEmpty, depth < ProtobufRaw.maxDepth else { return nil }
            var inner = Decoder(bytes: Array(payload), depth: depth + 1)
            guard let fields = try? inner.fields(closingGroup: nil), !fields.isEmpty else { return nil }
            return fields
        }

        mutating func varint() throws(ProtobufRawError) -> UInt64 {
            let start = pos
            var value: UInt64 = 0
            var shift: UInt64 = 0
            var count = 0
            while pos < bytes.count {
                let byte = bytes[pos]
                pos += 1
                count += 1
                if shift < 64 { value |= UInt64(byte & 0x7F) << shift }
                if byte & 0x80 == 0 { return value }
                guard count < 10 else { throw ProtobufRawError(offset: start, message: "Varint longer than 10 bytes") }
                shift += 7
            }
            throw ProtobufRawError(offset: start, message: "Varint runs past the end")
        }

        /// `width` little-endian bytes as an unsigned integer.
        mutating func fixed(_ width: Int) throws(ProtobufRawError) -> UInt64 {
            guard pos + width <= bytes.count else {
                throw ProtobufRawError(offset: pos, message: "Need \(width) bytes, \(bytes.count - pos) left")
            }
            var value: UInt64 = 0
            for i in 0..<width {
                value |= UInt64(bytes[pos + i]) << (UInt64(i) * 8)
            }
            pos += width
            return value
        }
    }
}
