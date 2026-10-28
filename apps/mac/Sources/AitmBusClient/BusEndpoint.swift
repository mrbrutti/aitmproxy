import Foundation

/// Where the bus listens and the token its first line must carry.
public struct BusEndpoint: Hashable, Sendable {
    public var host: String
    public var port: UInt16
    public var token: String

    public init(host: String = "127.0.0.1", port: UInt16, token: String) {
        self.host = host
        self.port = port
        self.token = token
    }

    /// `<config_dir>/aitmproxy/config.yaml`, the path `aitm` reads by default
    /// (`~/Library/Application Support/aitmproxy/config.yaml` on macOS,
    /// `~/.aitm/config.yaml` when no config directory is known).
    public static var defaultConfigURL: URL {
        if let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            return support.appending(path: "aitmproxy/config.yaml")
        }
        return FileManager.default.homeDirectoryForCurrentUser.appending(path: ".aitm/config.yaml")
    }

    /// Reads `mcp.transport.loopback_tcp.{port, token}` from aitmproxy's
    /// `config.yaml`, in block form or inline-map form. Returns `nil` when the
    /// file does not exist or configures another transport; throws
    /// `.malformed` when the block is present but unusable.
    public static func fromConfigFile(_ url: URL = defaultConfigURL) throws -> BusEndpoint? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let text = try String(contentsOf: url, encoding: .utf8)
        let scalars = YAMLScalars.scan(text)
        let base = "mcp.transport.loopback_tcp."
        guard let portText = scalars[base + "port"] else { return nil }
        guard let port = UInt16(portText) else {
            throw BusError.malformed("\(url.path): loopback_tcp.port `\(portText)` is not a port")
        }
        guard let token = scalars[base + "token"], !token.isEmpty else {
            throw BusError.malformed("\(url.path): loopback_tcp.token is missing or empty")
        }
        return BusEndpoint(port: port, token: token)
    }

    /// Parses `--bus host:port` with `--token <t>` or `--token-file <path>`
    /// (also `--flag=value`). Returns `nil` when `--bus` is absent.
    public static func fromArguments(_ args: [String]) throws -> BusEndpoint? {
        var options: [String: String] = [:]
        var index = 0
        while index < args.count {
            let arg = args[index]
            if let equals = arg.firstIndex(of: "="), arg.hasPrefix("--") {
                options[String(arg[..<equals])] = String(arg[arg.index(after: equals)...])
            } else if arg.hasPrefix("--"), index + 1 < args.count {
                options[arg] = args[index + 1]
                index += 1
            }
            index += 1
        }
        guard let bus = options["--bus"] else { return nil }
        guard let colon = bus.lastIndex(of: ":"), let port = UInt16(bus[bus.index(after: colon)...]) else {
            throw BusError.malformed("--bus expects host:port, got `\(bus)`")
        }
        let host = colon == bus.startIndex ? "127.0.0.1" : String(bus[..<colon])
        let token: String
        if let literal = options["--token"] {
            token = literal
        } else if let path = options["--token-file"] {
            token = try String(contentsOfFile: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            throw BusError.malformed("--bus needs --token or --token-file")
        }
        guard !token.isEmpty else { throw BusError.malformed("the bus token is empty") }
        return BusEndpoint(host: host, port: port, token: token)
    }
}

/// Just enough YAML to find scalar leaves by dotted path: indentation-based
/// block mappings plus `{k: v, k2: {…}}` flow mappings. Lists are skipped.
enum YAMLScalars {
    static func scan(_ text: String) -> [String: String] {
        var out: [String: String] = [:]
        var stack: [(indent: Int, key: String)] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = stripComment(String(rawLine))
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, trimmed != "---", !trimmed.hasPrefix("-") else { continue }
            guard let (key, value) = splitKey(trimmed) else { continue }
            let indent = line.prefix(while: { $0 == " " }).count
            while let top = stack.last, top.indent >= indent { stack.removeLast() }
            let path = (stack.map(\.key) + [key]).joined(separator: ".")
            if value.isEmpty {
                stack.append((indent, key))
            } else if value.hasPrefix("{") {
                flowMap(value, prefix: path, into: &out)
            } else {
                out[path] = unquote(value)
            }
        }
        return out
    }

    /// `key: value` → (key, value); the separator is the first `:` followed by a space or the end.
    private static func splitKey(_ line: String) -> (String, String)? {
        var cursor = line.startIndex
        while let colon = line[cursor...].firstIndex(of: ":") {
            let after = line.index(after: colon)
            if after == line.endIndex || line[after] == " " {
                return (unquote(String(line[..<colon])), line[after...].trimmingCharacters(in: .whitespaces))
            }
            cursor = after
        }
        return nil
    }

    private static func flowMap(_ text: String, prefix: String, into out: inout [String: String]) {
        var body = text.trimmingCharacters(in: .whitespaces)
        guard body.hasPrefix("{"), body.hasSuffix("}") else { return }
        body = String(body.dropFirst().dropLast())
        for entry in splitTopLevel(body) {
            guard let (key, value) = splitKey(entry.trimmingCharacters(in: .whitespaces)) else { continue }
            let path = prefix + "." + key
            if value.hasPrefix("{") { flowMap(value, prefix: path, into: &out) } else { out[path] = unquote(value) }
        }
    }

    /// Splits on commas outside quotes, braces and brackets.
    private static func splitTopLevel(_ text: String) -> [String] {
        var parts: [String] = []
        var current = ""
        var depth = 0
        var quote: Character?
        for ch in text {
            if let open = quote {
                if ch == open { quote = nil }
            } else if ch == "\"" || ch == "'" {
                quote = ch
            } else if ch == "{" || ch == "[" {
                depth += 1
            } else if ch == "}" || ch == "]" {
                depth -= 1
            } else if ch == ",", depth == 0 {
                parts.append(current)
                current = ""
                continue
            }
            current.append(ch)
        }
        if !current.trimmingCharacters(in: .whitespaces).isEmpty { parts.append(current) }
        return parts
    }

    /// Drops a `#` comment that starts the line or follows whitespace, outside quotes.
    private static func stripComment(_ line: String) -> String {
        var quote: Character?
        var previous: Character = " "
        for index in line.indices {
            let ch = line[index]
            if let open = quote {
                if ch == open { quote = nil }
            } else if ch == "\"" || ch == "'" {
                quote = ch
            } else if ch == "#", previous == " " || previous == "\t" || index == line.startIndex {
                return String(line[..<index])
            }
            previous = ch
        }
        return line
    }

    private static func unquote(_ text: String) -> String {
        let value = text.trimmingCharacters(in: .whitespaces)
        guard value.count >= 2, let first = value.first, first == "\"" || first == "'", value.last == first else {
            return value
        }
        return String(value.dropFirst().dropLast())
    }
}
