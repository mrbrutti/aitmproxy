import Foundation

/// A JSON document as a plain Swift value.
///
/// Numbers are stored as `Double`; integral values serialize without a
/// fractional part (`1`, never `1.0`) so ids and counts round-trip exactly
/// through the bus. Object keys serialize sorted, so output is deterministic.
public enum JSONValue: Hashable, Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])
}

// MARK: - Accessors

extension JSONValue {
    /// The member named `key` when this is an object, else `nil`.
    public subscript(key: String) -> JSONValue? {
        if case .object(let members) = self { return members[key] }
        return nil
    }

    /// The element at `index` when this is an array and `index` is in bounds.
    public subscript(index: Int) -> JSONValue? {
        if case .array(let items) = self, items.indices.contains(index) { return items[index] }
        return nil
    }

    public var isNull: Bool { if case .null = self { return true } else { return false } }

    public var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    public var doubleValue: Double? {
        if case .number(let value) = self { return value }
        return nil
    }

    /// The number as an `Int` when it is integral and in range, else `nil`.
    public var intValue: Int? {
        if case .number(let value) = self { return Int(exactly: value) }
        return nil
    }

    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    public var arrayValue: [JSONValue]? {
        if case .array(let items) = self { return items }
        return nil
    }

    public var objectValue: [String: JSONValue]? {
        if case .object(let members) = self { return members }
        return nil
    }
}

// MARK: - Literals

extension JSONValue: ExpressibleByNilLiteral, ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral,
    ExpressibleByFloatLiteral, ExpressibleByStringLiteral, ExpressibleByArrayLiteral,
    ExpressibleByDictionaryLiteral
{
    public init(nilLiteral: ()) { self = .null }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(integerLiteral value: Int) { self = .number(Double(value)) }
    public init(floatLiteral value: Double) { self = .number(value) }
    public init(stringLiteral value: String) { self = .string(value) }
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { _, last in last }))
    }
}

// MARK: - Foundation bridging

extension JSONValue {
    /// Builds a value from what `JSONSerialization` produces (`NSNull`,
    /// `NSNumber`, `String`, `[Any]`, `[String: Any]`) or from Swift
    /// scalars. Returns `nil` for anything that is not JSON.
    public init?(any: Any) {
        switch any {
        case let value as JSONValue:
            self = value
        case is NSNull:
            self = .null
        case let number as NSNumber:
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                self = .bool(number.boolValue)
            } else {
                self = .number(number.doubleValue)
            }
        case let text as String:
            self = .string(text)
        case let items as [Any]:
            var out: [JSONValue] = []
            out.reserveCapacity(items.count)
            for item in items {
                guard let value = JSONValue(any: item) else { return nil }
                out.append(value)
            }
            self = .array(out)
        case let members as [String: Any]:
            var out: [String: JSONValue] = [:]
            out.reserveCapacity(members.count)
            for (key, item) in members {
                guard let value = JSONValue(any: item) else { return nil }
                out[key] = value
            }
            self = .object(out)
        default:
            return nil
        }
    }

    /// The Foundation form: `NSNull`, `Bool`, `Int`/`Double`, `String`, `[Any]`, `[String: Any]`.
    public var anyValue: Any {
        switch self {
        case .null: return NSNull()
        case .bool(let value): return value
        case .number(let value): return Int(exactly: value).map { $0 as Any } ?? value
        case .string(let value): return value
        case .array(let items): return items.map(\.anyValue)
        case .object(let members): return members.mapValues(\.anyValue)
        }
    }

    /// Parses one JSON text (any top-level value).
    public static func parse(_ data: Data) throws(BusError) -> JSONValue {
        let raw: Any
        do {
            raw = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        } catch {
            throw BusError.malformed("invalid JSON: \(error.localizedDescription)")
        }
        guard let value = JSONValue(any: raw) else { throw BusError.malformed("unsupported JSON value") }
        return value
    }

    /// Parses one JSON text (any top-level value).
    public static func parse(_ text: String) throws(BusError) -> JSONValue {
        try parse(Data(text.utf8))
    }
}

// MARK: - Serialization

extension JSONValue {
    /// Compact (or two-space indented) JSON text with sorted object keys.
    public func serialized(prettyPrinted: Bool = false) -> String {
        var out = ""
        write(into: &out, indent: prettyPrinted ? 0 : nil)
        return out
    }

    private func write(into out: inout String, indent: Int?) {
        switch self {
        case .null:
            out += "null"
        case .bool(let value):
            out += value ? "true" : "false"
        case .number(let value):
            out += Self.format(value)
        case .string(let value):
            Self.writeEscaped(value, into: &out)
        case .array(let items):
            guard !items.isEmpty else { out += "[]"; return }
            out += "["
            for (i, item) in items.enumerated() {
                if i > 0 { out += "," }
                Self.newline(into: &out, indent: indent.map { $0 + 1 })
                item.write(into: &out, indent: indent.map { $0 + 1 })
            }
            Self.newline(into: &out, indent: indent)
            out += "]"
        case .object(let members):
            guard !members.isEmpty else { out += "{}"; return }
            out += "{"
            for (i, key) in members.keys.sorted().enumerated() {
                if i > 0 { out += "," }
                Self.newline(into: &out, indent: indent.map { $0 + 1 })
                Self.writeEscaped(key, into: &out)
                out += indent == nil ? ":" : ": "
                members[key]?.write(into: &out, indent: indent.map { $0 + 1 })
            }
            Self.newline(into: &out, indent: indent)
            out += "}"
        }
    }

    private static func newline(into out: inout String, indent: Int?) {
        guard let indent else { return }
        out += "\n" + String(repeating: "  ", count: indent)
    }

    private static func format(_ value: Double) -> String {
        if let integer = Int64(exactly: value) { return String(integer) }
        return value.isFinite ? "\(value)" : "null"
    }

    private static func writeEscaped(_ text: String, into out: inout String) {
        out += "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case ..<" ": out += String(format: "\\u%04x", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        out += "\""
    }
}

// MARK: - Codable

extension JSONValue: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "not a JSON value")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .number(let value):
            if let integer = Int64(exactly: value) { try container.encode(integer) } else { try container.encode(value) }
        case .string(let value): try container.encode(value)
        case .array(let items): try container.encode(items)
        case .object(let members): try container.encode(members)
        }
    }
}
