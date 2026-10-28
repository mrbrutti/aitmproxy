/// What `initialize` told us about the server.
public struct ServerInfo: Hashable, Sendable {
    public let name: String
    public let version: String
    public let protocolVersion: String

    public init(name: String, version: String, protocolVersion: String) {
        self.name = name
        self.version = version
        self.protocolVersion = protocolVersion
    }

    init(initializeResult result: JSONValue) throws(BusError) {
        guard let server = result["serverInfo"], let name = server["name"]?.stringValue else {
            throw BusError.malformed("initialize result has no serverInfo.name")
        }
        self.init(
            name: name,
            version: server["version"]?.stringValue ?? "",
            protocolVersion: result["protocolVersion"]?.stringValue ?? "")
    }
}

/// The core's `TypeDesc`, recovered from the JSON Schema `tools/list` emits
/// (see `crates/aitm-mcp/src/schema.rs`).
public enum ParamType: String, Hashable, Sendable, CaseIterable {
    case bool, int, float, string, bytes, flowId, array, object, map, any

    /// Classifies one property schema.
    public init(schema: JSONValue) {
        switch schema["type"]?.stringValue {
        case "boolean": self = .bool
        case "integer": self = .int
        case "number": self = .float
        case "string":
            if schema["format"]?.stringValue == "uuid" {
                self = .flowId
            } else if schema["contentEncoding"]?.stringValue == "base64" {
                self = .bytes
            } else {
                self = .string
            }
        case "array": self = .array
        case "object":
            // A `Map` carries an item schema in `additionalProperties`; an
            // `Object` declares its properties and sets it to `false`.
            if case .object = schema["additionalProperties"] ?? .null { self = .map } else { self = .object }
        default: self = .any
        }
    }
}

/// One parameter of a tool: enough to build a form field.
public struct ParamDescriptor: Hashable, Sendable {
    public let name: String
    public let type: ParamType
    public let required: Bool
    /// `ParamDef.description`, the field's help text (may be empty).
    public let description: String
    /// The property's own JSON Schema, for nested arrays/objects.
    public let schema: JSONValue

    public init(name: String, type: ParamType, required: Bool, description: String, schema: JSONValue = .object([:])) {
        self.name = name
        self.type = type
        self.required = required
        self.description = description
        self.schema = schema
    }

    /// Every property of an object schema, sorted by name.
    public static func parameters(from schema: JSONValue) -> [ParamDescriptor] {
        guard let properties = schema["properties"]?.objectValue else { return [] }
        let required = Set(schema["required"]?.arrayValue?.compactMap(\.stringValue) ?? [])
        return properties.keys.sorted().map { name in
            let property = properties[name] ?? .null
            return ParamDescriptor(
                name: name,
                type: ParamType(schema: property),
                required: required.contains(name),
                description: property["description"]?.stringValue ?? "",
                schema: property)
        }
    }
}

/// One entry of `tools/list`: a registered command.
public struct ToolDescriptor: Hashable, Sendable {
    public let name: String
    public let description: String
    /// The raw JSON Schema (`type: object`, `properties`, `required`, `additionalProperties: false`).
    public let inputSchema: JSONValue
    /// `inputSchema.properties`, classified.
    public let parameters: [ParamDescriptor]

    public init(name: String, description: String, inputSchema: JSONValue) {
        self.name = name
        self.description = description
        self.inputSchema = inputSchema
        self.parameters = ParamDescriptor.parameters(from: inputSchema)
    }

    init(json: JSONValue) throws(BusError) {
        guard let name = json["name"]?.stringValue else { throw BusError.malformed("tool without a name") }
        self.init(
            name: name,
            description: json["description"]?.stringValue ?? "",
            inputSchema: json["inputSchema"] ?? .object([:]))
    }
}
