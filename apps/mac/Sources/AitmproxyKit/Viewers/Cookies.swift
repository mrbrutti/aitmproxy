import Foundation

/// One cookie as the Cookies / Set-Cookie tabs show it (S-019). A request
/// `Cookie:` pair carries only a name and value; a response `Set-Cookie:`
/// adds its attributes.
public struct Cookie: Hashable, Sendable {
    public var name: String
    public var value: String
    public var domain: String?
    public var path: String?
    public var expires: Date?
    public var maxAge: Int?
    public var secure: Bool
    public var httpOnly: Bool
    /// `Lax`, `Strict` or `None` as written (case kept).
    public var sameSite: String?

    public init(name: String, value: String, domain: String? = nil, path: String? = nil, expires: Date? = nil,
                maxAge: Int? = nil, secure: Bool = false, httpOnly: Bool = false, sameSite: String? = nil) {
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.expires = expires
        self.maxAge = maxAge
        self.secure = secure
        self.httpOnly = httpOnly
        self.sameSite = sameSite
    }

    /// `HttpOnly · Secure · SameSite=Lax` — the Flags column; empty when the cookie has none.
    public var flagsText: String {
        var flags: [String] = []
        if httpOnly { flags.append("HttpOnly") }
        if secure { flags.append("Secure") }
        if let sameSite { flags.append("SameSite=\(sameSite)") }
        return flags.joined(separator: " · ")
    }

    // MARK: Request `Cookie:`

    /// `a=1; b="quoted; still"; c` → three cookies, in order. Quoted values
    /// keep their `;`, lose their quotes. A pair without `=` is a nameless
    /// cookie whose value is the whole token (RFC 6265bis §5.6, as browsers do).
    /// Duplicate names are kept in order.
    public static func parseCookieHeader(_ value: String) -> [Cookie] {
        splitSegments(value).compactMap { segment in
            let (name, raw) = splitPair(segment)
            guard !name.isEmpty || !raw.isEmpty else { return nil }
            return Cookie(name: name, value: unquote(raw))
        }
    }

    // MARK: Response `Set-Cookie:`

    /// `session=abc; Path=/; Expires=…; Max-Age=3600; HttpOnly; Secure; SameSite=Lax`.
    /// Attribute names are case-insensitive; unknown attributes are ignored;
    /// a header with neither a name nor a value is nil.
    public static func parseSetCookie(_ value: String) -> Cookie? {
        let segments = splitSegments(value, dropEmpty: false)
        guard let first = segments.first else { return nil }
        let (name, raw) = splitPair(first)
        guard !name.isEmpty || !raw.isEmpty else { return nil }
        var cookie = Cookie(name: name, value: unquote(raw))
        for attribute in segments.dropFirst() where !attribute.isEmpty {
            // A flag attribute (`Secure`) is its own name; `splitPair` would read it as a value.
            let (key, attributeValue) = attribute.contains("=") ? splitPair(attribute) : (attribute, "")
            switch key.lowercased() {
            case "domain":
                cookie.domain = attributeValue.isEmpty ? nil : attributeValue
            case "path":
                cookie.path = attributeValue.isEmpty ? nil : attributeValue
            case "expires":
                cookie.expires = parseHTTPDate(attributeValue)
            case "max-age":
                cookie.maxAge = Int(attributeValue.trimmingCharacters(in: .whitespaces))
            case "secure":
                cookie.secure = true
            case "httponly":
                cookie.httpOnly = true
            case "samesite":
                cookie.sameSite = attributeValue.isEmpty ? nil : attributeValue
            default:
                continue
            }
        }
        return cookie
    }

    /// Every cookie a message carries: request messages (`METHOD /path …`)
    /// read each `cookie` header, response messages (`HTTP/…`) each `set-cookie`.
    public static func cookies(in message: HTTPMessage) -> [Cookie] {
        let isResponse = message.startLine.hasPrefix("HTTP/")
        let wanted = isResponse ? "set-cookie" : "cookie"
        return message.headers
            .filter { $0.name.caseInsensitiveCompare(wanted) == .orderedSame }
            .flatMap { header -> [Cookie] in
                isResponse ? parseSetCookie(header.value).map { [$0] } ?? [] : parseCookieHeader(header.value)
            }
    }

    // MARK: Pieces

    /// Splits on `;` outside double quotes and trims each piece; drops empty
    /// pieces unless the caller needs the first one's position (`Set-Cookie`).
    static func splitSegments(_ text: String, dropEmpty: Bool = true) -> [String] {
        var segments: [String] = []
        var current = ""
        var inQuotes = false
        for scalar in text.unicodeScalars {
            if scalar == "\"" { inQuotes.toggle() }
            if scalar == ";", !inQuotes {
                segments.append(current)
                current = ""
            } else {
                current.unicodeScalars.append(scalar)
            }
        }
        segments.append(current)
        let trimmed = segments.map { $0.trimmingCharacters(in: .whitespaces) }
        return dropEmpty ? trimmed.filter { !$0.isEmpty } : trimmed
    }

    /// `name=value` → (name, value); no `=` → ("", token).
    static func splitPair(_ segment: String) -> (String, String) {
        guard let eq = segment.firstIndex(of: "=") else { return ("", segment) }
        let name = segment[..<eq].trimmingCharacters(in: .whitespaces)
        let value = segment[segment.index(after: eq)...].trimmingCharacters(in: .whitespaces)
        return (name, value)
    }

    static func unquote(_ value: String) -> String {
        guard value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") else { return value }
        return String(value.dropFirst().dropLast())
    }

    // MARK: Dates

    private static let months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]

    /// The tolerant cookie-date algorithm of RFC 6265 §5.1.1: finds a time,
    /// a day, a month and a year wherever they sit, so RFC 1123
    /// (`Sun, 06 Nov 1994 08:49:37 GMT`), RFC 850 (`Sunday, 06-Nov-94 08:49:37 GMT`)
    /// and asctime (`Sun Nov  6 08:49:37 1994`) all parse. UTC; nil when a part is missing.
    public static func parseHTTPDate(_ text: String) -> Date? {
        var hour: Int?, minute: Int?, second: Int?
        var day: Int?, month: Int?, year: Int?
        let delimiters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ":")).inverted
        for token in text.components(separatedBy: delimiters) where !token.isEmpty {
            if hour == nil, token.contains(":") {
                let parts = token.split(separator: ":").map { Int($0) }
                if parts.count == 3, let h = parts[0], let m = parts[1], let s = parts[2] {
                    hour = h; minute = m; second = s
                    continue
                }
            }
            if day == nil, token.count <= 2, let n = Int(token) {
                day = n
                continue
            }
            if month == nil, token.count >= 3, let index = months.firstIndex(of: String(token.prefix(3)).lowercased()) {
                month = index + 1
                continue
            }
            if year == nil, token.count == 2 || token.count == 4, let n = Int(token) {
                year = token.count == 2 ? (n >= 70 ? 1900 + n : 2000 + n) : n
                continue
            }
        }
        guard let hour, let minute, let second, let day, let month, let year,
              (1...31).contains(day), year >= 1601, hour <= 23, minute <= 59, second <= 59 else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? .current
        return calendar.date(from: DateComponents(year: year, month: month, day: day,
                                                  hour: hour, minute: minute, second: second))
    }
}
