import Foundation

/// Bytes that do not decode as MessagePack: where (byte offset) and why.
public struct MessagePackError: Error, Hashable, Sendable, CustomStringConvertible {
    public var offset: Int
    public var message: String

    public init(offset: Int, message: String) {
        self.offset = offset
        self.message = message
    }

    public var description: String { "\(message) at byte \(offset)" }
}

/// MessagePack → `JSONNode`, so a MessagePack body renders in the JSON tree
/// (foundation §2.7). Maps keep their order; `bin` becomes a base64 string;
/// `ext` becomes `{"ext": type, "data": base64}`; non-string map keys become
/// their text.
public enum MessagePack {
    static let maxDepth = 128

    /// Decodes exactly one value; trailing bytes are an error.
    public static func decode(_ data: Data) throws(MessagePackError) -> JSONNode {
        var decoder = Decoder(bytes: Array(data))
        guard !decoder.bytes.isEmpty else { throw MessagePackError(offset: 0, message: "Empty document") }
        let root = try decoder.value(key: nil, path: "$", depth: 0)
        if decoder.pos < decoder.bytes.count {
            throw MessagePackError(offset: decoder.pos, message: "Unexpected trailing content")
        }
        return root
    }

    private struct Decoder {
        let bytes: [UInt8]
        var pos = 0

        init(bytes: [UInt8]) {
            self.bytes = bytes
        }

        mutating func value(key: String?, path: String, depth: Int) throws(MessagePackError) -> JSONNode {
            guard depth < MessagePack.maxDepth else { throw MessagePackError(offset: pos, message: "Nested too deeply") }
            guard pos < bytes.count else { throw MessagePackError(offset: pos, message: "Unexpected end of input") }
            let start = pos
            let t = bytes[pos]
            pos += 1
            switch t {
            case 0x00...0x7F: return scalar(key, path, .number, "\(t)")
            case 0xE0...0xFF: return scalar(key, path, .number, "\(Int8(bitPattern: t))")
            case 0xC0: return scalar(key, path, .null, "null")
            case 0xC2: return scalar(key, path, .bool, "false")
            case 0xC3: return scalar(key, path, .bool, "true")
            case 0xC1: throw MessagePackError(offset: start, message: "Reserved type 0xc1")
            case 0x80...0x8F: return try map(count: Int(t & 0x0F), key: key, path: path, depth: depth)
            case 0xDE: return try map(count: Int(try unsigned(2)), key: key, path: path, depth: depth)
            case 0xDF: return try map(count: Int(try unsigned(4)), key: key, path: path, depth: depth)
            case 0x90...0x9F: return try array(count: Int(t & 0x0F), key: key, path: path, depth: depth)
            case 0xDC: return try array(count: Int(try unsigned(2)), key: key, path: path, depth: depth)
            case 0xDD: return try array(count: Int(try unsigned(4)), key: key, path: path, depth: depth)
            case 0xA0...0xBF: return try string(length: Int(t & 0x1F), key: key, path: path)
            case 0xD9: return try string(length: Int(try unsigned(1)), key: key, path: path)
            case 0xDA: return try string(length: Int(try unsigned(2)), key: key, path: path)
            case 0xDB: return try string(length: Int(try unsigned(4)), key: key, path: path)
            case 0xC4: return try binary(length: Int(try unsigned(1)), key: key, path: path)
            case 0xC5: return try binary(length: Int(try unsigned(2)), key: key, path: path)
            case 0xC6: return try binary(length: Int(try unsigned(4)), key: key, path: path)
            case 0xCA: return scalar(key, path, .number, floatText(Float(bitPattern: UInt32(try unsigned(4)))))
            case 0xCB: return scalar(key, path, .number, floatText(Double(bitPattern: try unsigned(8))))
            case 0xCC: return scalar(key, path, .number, "\(try unsigned(1))")
            case 0xCD: return scalar(key, path, .number, "\(try unsigned(2))")
            case 0xCE: return scalar(key, path, .number, "\(try unsigned(4))")
            case 0xCF: return scalar(key, path, .number, "\(try unsigned(8))")
            case 0xD0: return scalar(key, path, .number, "\(Int8(bitPattern: UInt8(try unsigned(1))))")
            case 0xD1: return scalar(key, path, .number, "\(Int16(bitPattern: UInt16(try unsigned(2))))")
            case 0xD2: return scalar(key, path, .number, "\(Int32(bitPattern: UInt32(try unsigned(4))))")
            case 0xD3: return scalar(key, path, .number, "\(Int64(bitPattern: try unsigned(8)))")
            case 0xD4: return try ext(length: 1, key: key, path: path)
            case 0xD5: return try ext(length: 2, key: key, path: path)
            case 0xD6: return try ext(length: 4, key: key, path: path)
            case 0xD7: return try ext(length: 8, key: key, path: path)
            case 0xD8: return try ext(length: 16, key: key, path: path)
            case 0xC7: return try ext(length: Int(try unsigned(1)), key: key, path: path)
            case 0xC8: return try ext(length: Int(try unsigned(2)), key: key, path: path)
            case 0xC9: return try ext(length: Int(try unsigned(4)), key: key, path: path)
            default: throw MessagePackError(offset: start, message: "Unknown type byte")
            }
        }

        private func scalar(_ key: String?, _ path: String, _ kind: JSONKind, _ text: String) -> JSONNode {
            JSONNode(key: key, path: path, kind: kind, scalarText: text)
        }

        /// `1.5`, `2.0`; NaN and the infinities as JSON cannot spell them, so the tree still shows them.
        private func floatText<F: BinaryFloatingPoint & CustomStringConvertible>(_ value: F) -> String {
            value.description
        }

        private mutating func map(count: Int, key: String?, path: String, depth: Int) throws(MessagePackError) -> JSONNode {
            var children: [JSONNode] = []
            children.reserveCapacity(min(count, 4096))
            for _ in 0..<count {
                let keyStart = pos
                let keyNode = try value(key: nil, path: path, depth: depth + 1)
                guard !keyNode.kind.isContainer else {
                    throw MessagePackError(offset: keyStart, message: "Map key is a container")
                }
                let name = keyNode.scalarText
                children.append(try value(key: name, path: JSONTree.childPath(parent: path, key: name), depth: depth + 1))
            }
            return JSONNode(key: key, path: path, kind: .object(count: count), children: children)
        }

        private mutating func array(count: Int, key: String?, path: String, depth: Int) throws(MessagePackError) -> JSONNode {
            var children: [JSONNode] = []
            children.reserveCapacity(min(count, 4096))
            for index in 0..<count {
                children.append(try value(key: "[\(index)]", path: "\(path)[\(index)]", depth: depth + 1))
            }
            return JSONNode(key: key, path: path, kind: .array(count: count), children: children)
        }

        private mutating func string(length: Int, key: String?, path: String) throws(MessagePackError) -> JSONNode {
            let slice = try take(length)
            return scalar(key, path, .string, String(decoding: slice, as: UTF8.self))
        }

        private mutating func binary(length: Int, key: String?, path: String) throws(MessagePackError) -> JSONNode {
            let slice = try take(length)
            return scalar(key, path, .string, Data(slice).base64EncodedString())
        }

        private mutating func ext(length: Int, key: String?, path: String) throws(MessagePackError) -> JSONNode {
            let type = Int8(bitPattern: UInt8(try unsigned(1)))
            let slice = try take(length)
            let children = [
                JSONNode(key: "ext", path: "\(path).ext", kind: .number, scalarText: "\(type)"),
                JSONNode(key: "data", path: "\(path).data", kind: .string, scalarText: Data(slice).base64EncodedString()),
            ]
            return JSONNode(key: key, path: path, kind: .object(count: 2), children: children)
        }

        /// `width` big-endian bytes.
        private mutating func unsigned(_ width: Int) throws(MessagePackError) -> UInt64 {
            let slice = try take(width)
            var value: UInt64 = 0
            for byte in slice { value = value << 8 | UInt64(byte) }
            return value
        }

        private mutating func take(_ count: Int) throws(MessagePackError) -> ArraySlice<UInt8> {
            guard count >= 0, pos + count <= bytes.count else {
                throw MessagePackError(offset: pos, message: "Need \(count) bytes, \(bytes.count - pos) left")
            }
            defer { pos += count }
            return bytes[pos..<(pos + count)]
        }
    }
}
