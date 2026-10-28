import Foundation

/// "Copy as cURL" and friends (foundation §3.3), plus the reverse: pasting a
/// curl command into Compose. Everything is generated from the detail the
/// inspector already has; nothing touches the bus.
public enum CodeExport {
    /// Headers no client should copy: hop-by-hop (RFC 9110 §7.6.1), the body
    /// length (the client recomputes it) and HTTP/2 pseudo-headers.
    static let excludedHeaders: Set<String> = [
        "connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade",
        "proxy-authenticate", "proxy-authorization", "content-length",
    ]

    /// The method, URL, headers and body a generator needs, derived from the
    /// detail's start line (which carries any edits) and the row's scheme/authority.
    public struct Request: Hashable, Sendable {
        public var method: String
        public var url: String
        public var headers: [HTTPMessage.Header]
        public var body: Data?

        public init(_ detail: FlowDetail, row: FlowRow) {
            let parts = detail.request.startLine.split(separator: " ", maxSplits: 2).map(String.init)
            method = parts.first.map { $0.uppercased() } ?? row.method.label
            let target = parts.count > 1 ? parts[1] : (row.query.map { "\(row.path)?\($0)" } ?? row.path)
            if target.contains("://") {
                url = target
            } else if target.hasPrefix("/") || target.isEmpty {
                url = "\(row.scheme)://\(row.authority)\(target.isEmpty ? "/" : target)"
            } else {
                url = "\(row.scheme)://\(row.authority)/\(target)"
            }
            headers = detail.request.headers.filter { header in
                !header.name.hasPrefix(":") && !CodeExport.excludedHeaders.contains(header.name.lowercased())
            }
            body = detail.request.body
        }

        public init(method: String, url: String, headers: [HTTPMessage.Header], body: Data?) {
            self.method = method
            self.url = url
            self.headers = headers
            self.body = body
        }

        public var bodyText: String? { body.flatMap { String(data: $0, encoding: .utf8) } }
        public func header(_ name: String) -> String? {
            headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
        }
    }

    // MARK: curl

    /// A multi-line `curl` command: `-X` unless the method is a plain GET, one
    /// `-H` per header, `--data-raw` for a UTF-8 body (`--data-binary` with a
    /// base64 round-trip otherwise), `--compressed` when the request accepted
    /// an encoding. Never adds `-k`.
    public static func curl(_ detail: FlowDetail, row: FlowRow) -> String {
        curl(Request(detail, row: row))
    }

    public static func curl(_ request: Request) -> String {
        var parts: [String] = []
        var first = "curl"
        if !(request.method == "GET" && request.body == nil) {
            first += " -X \(request.method)"
        }
        first += " \(shellQuote(request.url))"
        parts.append(first)
        for header in request.headers {
            parts.append("-H \(shellQuote("\(header.name): \(header.value)"))")
        }
        if request.header("accept-encoding") != nil {
            parts.append("--compressed")
        }
        if let body = request.body {
            if let text = String(data: body, encoding: .utf8) {
                parts.append("--data-raw \(shellQuote(text))")
            } else {
                parts.append("--data-binary \"$(printf %s \(shellQuote(body.base64EncodedString())) | base64 -d)\"")
            }
        }
        return parts.joined(separator: " \\\n  ")
    }

    /// POSIX single-quoting: wraps in `'…'`, writing a literal `'` as `'\''`.
    public static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    // MARK: httpie

    /// `http METHOD URL 'name:value' … --raw 'body'`.
    public static func httpie(_ detail: FlowDetail, row: FlowRow) -> String {
        httpie(Request(detail, row: row))
    }

    public static func httpie(_ request: Request) -> String {
        var parts = ["http \(request.method) \(shellQuote(request.url))"]
        for header in request.headers {
            parts.append(shellQuote("\(header.name):\(header.value)"))
        }
        if let body = request.body {
            if let text = String(data: body, encoding: .utf8) {
                parts.append("--raw \(shellQuote(text))")
            } else {
                parts.append("--raw \"$(printf %s \(shellQuote(body.base64EncodedString())) | base64 -d)\"")
            }
        }
        return parts.joined(separator: " \\\n  ")
    }

    // MARK: python-requests

    public static func pythonRequests(_ detail: FlowDetail, row: FlowRow) -> String {
        pythonRequests(Request(detail, row: row))
    }

    public static func pythonRequests(_ request: Request) -> String {
        var out = "import requests\n\n"
        out += "url = \(pythonString(request.url))\n"
        if request.headers.isEmpty {
            out += "headers = {}\n"
        } else {
            out += "headers = {\n"
            for header in request.headers {
                out += "    \(pythonString(header.name)): \(pythonString(header.value)),\n"
            }
            out += "}\n"
        }
        var arguments = "url, headers=headers"
        if let body = request.body {
            if let text = String(data: body, encoding: .utf8) {
                out += "data = \(pythonString(text))\n"
            } else {
                out += "data = bytes.fromhex(\"\(body.map { HexDump.hexByte($0) }.joined())\")\n"
            }
            arguments += ", data=data"
        }
        out += "\n"
        let convenience: Set<String> = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        if convenience.contains(request.method) {
            out += "response = requests.\(request.method.lowercased())(\(arguments))\n"
        } else {
            out += "response = requests.request(\(pythonString(request.method)), \(arguments))\n"
        }
        out += "print(response.status_code)\nprint(response.text)\n"
        return out
    }

    /// A double-quoted Python string literal; also valid JavaScript.
    static func pythonString(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 || scalar.value == 0x7F {
                    out += String(format: "\\x%02x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
        return out
    }

    // MARK: fetch

    public static func fetch(_ detail: FlowDetail, row: FlowRow) -> String {
        fetch(Request(detail, row: row))
    }

    public static func fetch(_ request: Request) -> String {
        var out = "await fetch(\(pythonString(request.url)), {\n"
        out += "  method: \(pythonString(request.method)),\n"
        if request.headers.isEmpty {
            out += "  headers: {},\n"
        } else {
            out += "  headers: {\n"
            for header in request.headers {
                out += "    \(pythonString(header.name)): \(pythonString(header.value)),\n"
            }
            out += "  },\n"
        }
        if let body = request.body {
            if let text = String(data: body, encoding: .utf8) {
                out += "  body: \(pythonString(text)),\n"
            } else {
                out += "  body: Uint8Array.from(atob(\"\(body.base64EncodedString())\"), (c) => c.charCodeAt(0)),\n"
            }
        }
        out += "});\n"
        return out
    }

    // MARK: Raw

    /// The message as it would cross the wire: start line, headers, blank line,
    /// body (lossily decoded when it is not UTF-8). CRLF line ends.
    public static func rawHTTP(_ message: HTTPMessage) -> String {
        var out = message.startLine + "\r\n"
        for header in message.headers {
            out += "\(header.name): \(header.value)\r\n"
        }
        out += "\r\n"
        if let body = message.body {
            out += String(decoding: body, as: UTF8.self)
        }
        return out
    }

    // MARK: Import

    /// Parses a pasted curl command into request edits: method, scheme,
    /// authority, path (with query), headers (lowercase names, later wins) and
    /// body. Understands `-X`, `-H`, the `-d` family, `--json`, `-u`, `-A`,
    /// `-b`, `-e`, `--url`, `-G`, `-I`, `-F` (as a multipart marker only),
    /// `--long=value`, attached short values (`-XPOST`), single/double/`$'…'`
    /// quoting and backslash-newline continuations. Nil without a `curl` word or a URL.
    public static func parseCurl(_ command: String) -> RequestEdits? {
        let tokens = shellTokens(command)
        guard let start = tokens.firstIndex(where: { $0 == "curl" || $0.hasSuffix("/curl") }) else { return nil }

        var method: String?
        var url: String?
        var headers: [(String, String)] = []
        var dataParts: [String] = []
        var jsonBody: String?
        var dataToQuery = false
        var multipart = false
        var head = false
        var optionsEnded = false

        /// Options that take a value we have no use for.
        let skipWithValue: Set<String> = [
            "-o", "--output", "-x", "--proxy", "--connect-timeout", "-m", "--max-time", "--cacert", "--cert",
            "--key", "--retry", "-w", "--write-out", "--max-redirs", "--limit-rate", "-c", "--cookie-jar",
            "-K", "--config", "-T", "--upload-file", "--resolve", "--interface", "--dns-servers", "-y", "-Y",
            "--speed-time", "--speed-limit", "--ciphers", "--tlsv1.2", "--proto", "--range", "-r", "-z",
            "--time-cond", "--unix-socket", "--abstract-unix-socket", "--retry-delay", "--retry-max-time",
            "--stderr", "--trace", "--trace-ascii", "--dump-header", "-D", "--output-dir", "--variable",
        ]

        var i = start + 1
        func takeValue() -> String? {
            guard i + 1 < tokens.count else { return nil }
            i += 1
            return tokens[i]
        }

        while i < tokens.count {
            let token = tokens[i]
            defer { i += 1 }
            if optionsEnded || !token.hasPrefix("-") || token == "-" {
                if url == nil { url = token }
                continue
            }
            if token == "--" {
                optionsEnded = true
                continue
            }
            var name = token
            var attached: String?
            if token.hasPrefix("--") {
                if let eq = token.firstIndex(of: "=") {
                    name = String(token[..<eq])
                    attached = String(token[token.index(after: eq)...])
                }
            } else if token.count > 2, Self.shortWithValue.contains(String(token.prefix(2))) {
                name = String(token.prefix(2))
                attached = String(token.dropFirst(2))
            }
            func value() -> String? { attached ?? takeValue() }

            switch name {
            case "-X", "--request":
                if let v = value() { method = v.uppercased() }
            case "-H", "--header":
                if let v = value() {
                    if let colon = v.firstIndex(of: ":") {
                        let hname = v[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
                        let hvalue = v[v.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                        if !hname.isEmpty { headers.append((hname, hvalue)) }
                    } else if v.hasSuffix(";") {
                        headers.append((String(v.dropLast()).trimmingCharacters(in: .whitespaces).lowercased(), ""))
                    }
                }
            case "-d", "--data", "--data-raw", "--data-binary", "--data-ascii":
                if let v = value() { dataParts.append(v) }
            case "--data-urlencode", "--data-urlencoded":
                if let v = value() { dataParts.append(urlEncodeDataOption(v)) }
            case "--json":
                if let v = value() { jsonBody = (jsonBody ?? "") + v }
            case "-u", "--user":
                if let v = value() {
                    headers.append(("authorization", "Basic " + Data(v.utf8).base64EncodedString()))
                }
            case "-A", "--user-agent":
                if let v = value() { headers.append(("user-agent", v)) }
            case "-b", "--cookie":
                if let v = value() { headers.append(("cookie", v)) }
            case "-e", "--referer":
                if let v = value() { headers.append(("referer", v)) }
            case "--url":
                if let v = value() { url = v }
            case "-F", "--form", "--form-string":
                _ = value()
                multipart = true
            case "-G", "--get":
                dataToQuery = true
            case "-I", "--head":
                head = true
            default:
                if attached == nil, skipWithValue.contains(name) { _ = takeValue() }
                // Everything else (-k, -s, -L, --compressed, …) is a flag with no bearing on the request.
            }
        }

        guard let rawURL = url else { return nil }
        let components = splitURL(rawURL)

        var merged: [String: String] = [:]
        for (name, value) in headers { merged[name] = value }

        var path = components.path
        var body: Data?
        if let jsonBody {
            body = Data(jsonBody.utf8)
            if merged["content-type"] == nil { merged["content-type"] = "application/json" }
            if merged["accept"] == nil { merged["accept"] = "application/json" }
        } else if !dataParts.isEmpty {
            let joined = dataParts.joined(separator: "&")
            if dataToQuery {
                path += path.contains("?") ? "&\(joined)" : "?\(joined)"
            } else {
                body = Data(joined.utf8)
                if merged["content-type"] == nil { merged["content-type"] = "application/x-www-form-urlencoded" }
            }
        }
        if multipart, merged["content-type"] == nil { merged["content-type"] = "multipart/form-data" }

        let resolvedMethod: String
        if let method {
            resolvedMethod = method
        } else if head {
            resolvedMethod = "HEAD"
        } else if body != nil || multipart {
            resolvedMethod = "POST"
        } else {
            resolvedMethod = "GET"
        }

        return RequestEdits(method: resolvedMethod, scheme: components.scheme, authority: components.authority,
                            path: path, headers: merged.isEmpty ? nil : merged, body: body)
    }

    private static let shortWithValue: Set<String> = ["-X", "-H", "-d", "-u", "-A", "-b", "-e", "-F", "-o", "-x",
                                                      "-m", "-w", "-c", "-K", "-T", "-y", "-Y", "-r", "-z", "-D"]

    /// `--data-urlencode name=value` encodes the value; `=value` and `content` encode everything after `=`/all.
    private static func urlEncodeDataOption(_ v: String) -> String {
        if let eq = v.firstIndex(of: "=") {
            let name = String(v[..<eq])
            let value = String(v[v.index(after: eq)...])
            return name.isEmpty ? formEncode(value) : "\(name)=\(formEncode(value))"
        }
        return formEncode(v)
    }

    static func formEncode(_ s: String) -> String {
        var out = ""
        for b in s.utf8 {
            switch b {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "_"), UInt8(ascii: "."),
                 UInt8(ascii: "~"):
                out.append(Character(UnicodeScalar(b)))
            default:
                out += "%" + HexDump.hexByte(b).uppercased()
            }
        }
        return out
    }

    struct URLParts {
        var scheme: String
        var authority: String
        var path: String
    }

    /// Splits a URL without `URLComponents`, which rejects the odd characters
    /// curl happily sends. No scheme means `http`, as curl assumes.
    static func splitURL(_ raw: String) -> URLParts {
        var rest = Substring(raw)
        var scheme = "http"
        if let range = rest.range(of: "://") {
            scheme = rest[..<range.lowerBound].lowercased()
            rest = rest[range.upperBound...]
        }
        if let hash = rest.firstIndex(of: "#") { rest = rest[..<hash] }
        let authorityEnd = rest.firstIndex { $0 == "/" || $0 == "?" } ?? rest.endIndex
        let authority = String(rest[..<authorityEnd])
        var path = String(rest[authorityEnd...])
        if path.isEmpty || path.hasPrefix("?") { path = "/" + path }
        return URLParts(scheme: scheme, authority: authority, path: path)
    }

    /// Splits a shell command line into words: whitespace separates, `'…'` is
    /// literal, `"…"` honours `\"` `\\` `\$` `` \` `` and `\`-newline, `$'…'`
    /// honours C escapes, a bare `\` escapes the next character and `\`-newline
    /// continues the line. `#` comments are not handled.
    public static func shellTokens(_ command: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var inWord = false
        let chars = Array(command.unicodeScalars)
        var i = 0

        func flush() {
            if inWord { tokens.append(current) }
            current = ""
            inWord = false
        }

        while i < chars.count {
            let c = chars[i]
            switch c {
            case " ", "\t", "\n", "\r":
                flush()
                i += 1
            case "\\":
                inWord = true
                if i + 1 < chars.count {
                    let next = chars[i + 1]
                    if next == "\n" {
                        i += 2
                        if i < chars.count, chars[i] == "\r" { i += 1 }
                    } else if next == "\r", i + 2 < chars.count, chars[i + 2] == "\n" {
                        i += 3
                    } else {
                        current.unicodeScalars.append(next)
                        i += 2
                    }
                } else {
                    i += 1
                }
            case "'":
                inWord = true
                i += 1
                while i < chars.count, chars[i] != "'" {
                    current.unicodeScalars.append(chars[i])
                    i += 1
                }
                i += 1
            case "\"":
                inWord = true
                i += 1
                while i < chars.count, chars[i] != "\"" {
                    if chars[i] == "\\", i + 1 < chars.count {
                        let next = chars[i + 1]
                        switch next {
                        case "\"", "\\", "$", "`":
                            current.unicodeScalars.append(next)
                            i += 2
                        case "\n":
                            i += 2
                        default:
                            current.unicodeScalars.append("\\")
                            current.unicodeScalars.append(next)
                            i += 2
                        }
                    } else {
                        current.unicodeScalars.append(chars[i])
                        i += 1
                    }
                }
                i += 1
            case "$" where i + 1 < chars.count && chars[i + 1] == "'":
                inWord = true
                i += 2
                while i < chars.count, chars[i] != "'" {
                    if chars[i] == "\\", i + 1 < chars.count {
                        let (scalar, consumed) = ansiEscape(chars, at: i + 1)
                        if let scalar { current.unicodeScalars.append(scalar) }
                        i += 1 + consumed
                    } else {
                        current.unicodeScalars.append(chars[i])
                        i += 1
                    }
                }
                i += 1
            default:
                inWord = true
                current.unicodeScalars.append(c)
                i += 1
            }
        }
        flush()
        return tokens
    }

    /// Decodes the escape after a backslash inside `$'…'`; returns the scalar and how many scalars it used.
    private static func ansiEscape(_ chars: [Unicode.Scalar], at index: Int) -> (Unicode.Scalar?, Int) {
        let c = chars[index]
        switch c {
        case "n": return ("\n", 1)
        case "t": return ("\t", 1)
        case "r": return ("\r", 1)
        case "a": return ("\u{07}", 1)
        case "b": return ("\u{08}", 1)
        case "e", "E": return ("\u{1B}", 1)
        case "f": return ("\u{0C}", 1)
        case "v": return ("\u{0B}", 1)
        case "\\": return ("\\", 1)
        case "'": return ("'", 1)
        case "\"": return ("\"", 1)
        case "x":
            let (value, digits) = hexDigits(chars, from: index + 1, max: 2)
            guard digits > 0 else { return ("x", 1) }
            return (Unicode.Scalar(value), 1 + digits)
        case "u":
            let (value, digits) = hexDigits(chars, from: index + 1, max: 4)
            guard digits > 0 else { return ("u", 1) }
            return (Unicode.Scalar(value), 1 + digits)
        case "U":
            let (value, digits) = hexDigits(chars, from: index + 1, max: 8)
            guard digits > 0 else { return ("U", 1) }
            return (Unicode.Scalar(value), 1 + digits)
        case "0"..."7":
            var value: UInt32 = 0
            var n = 0
            while n < 3, index + n < chars.count, ("0"..."7").contains(chars[index + n]) {
                value = value * 8 + (chars[index + n].value - 48)
                n += 1
            }
            return (Unicode.Scalar(value), n)
        default:
            return (c, 1)
        }
    }

    private static func hexDigits(_ chars: [Unicode.Scalar], from start: Int, max count: Int) -> (UInt32, Int) {
        var value: UInt32 = 0
        var n = 0
        while n < count, start + n < chars.count, let digit = hexValue(chars[start + n]) {
            value = value * 16 + digit
            n += 1
        }
        return (value, n)
    }

    private static func hexValue(_ c: Unicode.Scalar) -> UInt32? {
        switch c {
        case "0"..."9": return c.value - 48
        case "a"..."f": return c.value - 97 + 10
        case "A"..."F": return c.value - 65 + 10
        default: return nil
        }
    }
}
