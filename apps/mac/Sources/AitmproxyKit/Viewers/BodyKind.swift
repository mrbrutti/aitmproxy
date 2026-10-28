import Foundation

public enum ImageFormat: String, Hashable, Sendable {
    case png, jpeg, gif, webp, svg

    public var label: String {
        switch self {
        case .png: "PNG"
        case .jpeg: "JPEG"
        case .gif: "GIF"
        case .webp: "WebP"
        case .svg: "SVG"
        }
    }
}

/// One part of a `multipart/*` body.
public struct MultipartPart: Hashable, Sendable {
    public var headers: [HTTPMessage.Header]
    public var body: Data

    public init(headers: [HTTPMessage.Header], body: Data) {
        self.headers = headers
        self.body = body
    }

    public func header(_ name: String) -> String? {
        headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    public var contentType: String? { header("content-type") }
    /// `name` from Content-Disposition.
    public var name: String? { dispositionParameter("name") }
    /// `filename` from Content-Disposition.
    public var filename: String? { dispositionParameter("filename") }

    private func dispositionParameter(_ key: String) -> String? {
        guard let disposition = header("content-disposition") else { return nil }
        return BodyKind.parameters(of: disposition)[key]
    }
}

/// Which viewer a body gets (foundation §2.7 body viewers). Decided from the
/// content type when it says something useful, from the bytes otherwise.
public enum BodyKind: Hashable, Sendable {
    case json
    case xml
    case html
    case javascript
    case css
    /// `application/x-www-form-urlencoded`.
    case form
    case multipart(boundary: String)
    /// Dimensions when the header bytes give them (PNG IHDR, JPEG SOF, GIF, WebP VP8/VP8L/VP8X, SVG attributes).
    case image(format: ImageFormat, width: Int?, height: Int?)
    case text
    /// Declared, or the bytes walk as valid protobuf wire format.
    case protobuf
    /// Declared, or the bytes decode as one MessagePack map/array.
    case messagepack
    case binary

    // MARK: Detection

    public static func detect(contentType: String?, data: Data) -> BodyKind {
        let (type, params) = mediaType(contentType)
        if !type.isEmpty, type != "application/octet-stream" {
            if let declared = kind(forDeclaredType: type, params: params, data: data) { return declared }
        }
        return sniff(data)
    }

    /// `(lowercased media type, lowercased-key parameters)`.
    static func mediaType(_ contentType: String?) -> (String, [String: String]) {
        guard let raw = contentType?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else { return ("", [:]) }
        let semicolon = raw.firstIndex(of: ";") ?? raw.endIndex
        let type = raw[..<semicolon].trimmingCharacters(in: .whitespaces).lowercased()
        let params = semicolon < raw.endIndex ? parameters(of: String(raw[raw.index(after: semicolon)...])) : [:]
        return (type, params)
    }

    /// `a=b; c="d e"` → `[a: b, c: d e]`. Keys lowercased, quotes stripped.
    static func parameters(of text: String) -> [String: String] {
        var result: [String: String] = [:]
        for piece in text.split(separator: ";") {
            guard let eq = piece.firstIndex(of: "=") else { continue }
            let key = piece[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            var value = piece[piece.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") {
                value = String(value.dropFirst().dropLast()).replacingOccurrences(of: "\\\"", with: "\"")
            }
            if !key.isEmpty { result[key] = value }
        }
        return result
    }

    private static func kind(forDeclaredType type: String, params: [String: String], data: Data) -> BodyKind? {
        if type.hasPrefix("multipart/") {
            if let boundary = params["boundary"] ?? sniffBoundary(data) { return .multipart(boundary: boundary) }
            return .text
        }
        if type == "image/svg+xml" || type == "image/svg" {
            let size = svgSize(data)
            return .image(format: .svg, width: size?.0, height: size?.1)
        }
        if type.hasPrefix("image/") {
            if let info = imageInfo(data) { return info }
            switch type {
            case "image/png": return .image(format: .png, width: nil, height: nil)
            case "image/jpeg", "image/jpg", "image/pjpeg": return .image(format: .jpeg, width: nil, height: nil)
            case "image/gif": return .image(format: .gif, width: nil, height: nil)
            case "image/webp": return .image(format: .webp, width: nil, height: nil)
            default: return .binary
            }
        }
        if type.contains("json") { return .json }
        if type.contains("javascript") || type.contains("ecmascript") { return .javascript }
        if type == "text/css" { return .css }
        if type == "text/html" || type == "application/xhtml+xml" { return .html }
        if type.contains("xml") { return .xml }
        if type == "application/x-www-form-urlencoded" { return .form }
        if type.contains("protobuf") { return .protobuf }
        if type.contains("msgpack") || type.contains("messagepack") { return .messagepack }
        if type.hasPrefix("text/") { return .text }
        if type.hasPrefix("application/x-") || type.hasPrefix("application/vnd.") || type.hasPrefix("font/")
            || type.hasPrefix("audio/") || type.hasPrefix("video/") || type == "application/pdf"
            || type == "application/zip" || type == "application/gzip" || type == "application/wasm" {
            return .binary
        }
        return nil
    }

    /// Decides from the bytes alone: image magic, then text shapes, then binary encodings.
    public static func sniff(_ data: Data) -> BodyKind {
        if data.isEmpty { return .text }
        if let image = imageInfo(data) { return image }
        if let text = String(data: data, encoding: .utf8) {
            let trimmed = text.drop { $0.isWhitespace || $0 == "\u{FEFF}" }
            if trimmed.hasPrefix("{") || trimmed.hasPrefix("["), (try? JSONTree.parse(data)) != nil { return .json }
            let lower = trimmed.prefix(512).lowercased()
            if lower.hasPrefix("<!doctype html") || lower.hasPrefix("<html") { return .html }
            if lower.hasPrefix("<svg") || (lower.hasPrefix("<?xml") && lower.contains("<svg")) {
                let size = svgSize(data)
                return .image(format: .svg, width: size?.0, height: size?.1)
            }
            if lower.hasPrefix("<?xml") || (lower.hasPrefix("<") && lower.contains(">") && !lower.hasPrefix("<!")) {
                return .xml
            }
            if let boundary = sniffBoundary(data), text.contains("content-disposition") || text.contains("Content-Disposition") {
                return .multipart(boundary: boundary)
            }
            if looksLikeForm(trimmed) { return .form }
            return .text
        }
        if isMessagePack(data) { return .messagepack }
        if isProtobuf(data) { return .protobuf }
        return .binary
    }

    private static func looksLikeForm(_ text: Substring) -> Bool {
        guard !text.contains("\n"), text.contains("=") else { return false }
        return text.split(separator: "&").allSatisfy { pair in
            pair.contains("=") && !pair.contains(" ")
        }
    }

    /// The boundary of a body whose first line is `--boundary`.
    static func sniffBoundary(_ data: Data) -> String? {
        guard data.count > 2, data[data.startIndex] == 0x2D, data[data.startIndex + 1] == 0x2D else { return nil }
        let firstLine = data.prefix(200).prefix { $0 != 0x0D && $0 != 0x0A }
        let boundary = String(decoding: firstLine.dropFirst(2), as: UTF8.self)
        return boundary.isEmpty ? nil : boundary
    }

    // MARK: Images

    /// Format and dimensions from the header bytes, nil when the bytes are not a known raster image.
    public static func imageInfo(_ data: Data) -> BodyKind? {
        let b = Array(data.prefix(64))
        guard b.count >= 4 else { return nil }
        if b.count >= 8, b[0] == 0x89, b[1] == 0x50, b[2] == 0x4E, b[3] == 0x47, b[4] == 0x0D, b[5] == 0x0A, b[6] == 0x1A, b[7] == 0x1A {
            // IHDR is always the first chunk: length(4) "IHDR"(4) width(4) height(4).
            if b.count >= 24, b[12] == 0x49, b[13] == 0x48, b[14] == 0x44, b[15] == 0x52 {
                return .image(format: .png, width: Int(be32(b, 16)), height: Int(be32(b, 20)))
            }
            return .image(format: .png, width: nil, height: nil)
        }
        if b[0] == 0xFF, b[1] == 0xD8, b[2] == 0xFF {
            let size = jpegSize(data)
            return .image(format: .jpeg, width: size?.0, height: size?.1)
        }
        if b.count >= 10, b[0] == 0x47, b[1] == 0x49, b[2] == 0x46, b[3] == 0x38, b[4] == 0x37 || b[4] == 0x39, b[5] == 0x61 {
            return .image(format: .gif, width: Int(b[6]) | Int(b[7]) << 8, height: Int(b[8]) | Int(b[9]) << 8)
        }
        if b.count >= 16, b[0] == 0x52, b[1] == 0x49, b[2] == 0x46, b[3] == 0x46, b[8] == 0x57, b[9] == 0x45, b[10] == 0x42, b[11] == 0x50 {
            let size = webpSize(b)
            return .image(format: .webp, width: size?.0, height: size?.1)
        }
        return nil
    }

    private static func be32(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3])
    }

    private static func be16(_ b: [UInt8], _ i: Int) -> Int {
        Int(b[i]) << 8 | Int(b[i + 1])
    }

    private static func le24(_ b: [UInt8], _ i: Int) -> Int {
        Int(b[i]) | Int(b[i + 1]) << 8 | Int(b[i + 2]) << 16
    }

    /// Walks the JPEG segments to the first SOFn marker.
    private static func jpegSize(_ data: Data) -> (Int, Int)? {
        let b = Array(data.prefix(65_536))
        var i = 2
        while i + 3 < b.count {
            guard b[i] == 0xFF else { i += 1; continue }
            let marker = b[i + 1]
            if marker == 0xFF { i += 1; continue }                   // fill byte
            if marker == 0xD8 || marker == 0x01 || (0xD0...0xD7).contains(marker) { // standalone
                i += 2
                continue
            }
            let length = be16(b, i + 2)
            let isSOF = (0xC0...0xCF).contains(marker) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC
            if isSOF {
                guard i + 8 < b.count else { return nil }
                return (be16(b, i + 7), be16(b, i + 5))
            }
            if marker == 0xDA { return nil }                          // start of scan: no SOF before it
            guard length >= 2 else { return nil }
            i += 2 + length
        }
        return nil
    }

    /// VP8 (lossy), VP8L (lossless) and VP8X (extended) headers.
    private static func webpSize(_ b: [UInt8]) -> (Int, Int)? {
        guard b.count >= 30 else { return nil }
        let fourcc = String(decoding: b[12..<16], as: UTF8.self)
        switch fourcc {
        case "VP8 ":
            // Payload at 20: frame tag(3), start code 9d 01 2a(3), width(2), height(2); top 2 bits are scaling.
            guard b[23] == 0x9D, b[24] == 0x01, b[25] == 0x2A else { return nil }
            let w = (Int(b[26]) | Int(b[27]) << 8) & 0x3FFF
            let h = (Int(b[28]) | Int(b[29]) << 8) & 0x3FFF
            return (w, h)
        case "VP8L":
            guard b[20] == 0x2F else { return nil }
            let bits = UInt32(b[21]) | UInt32(b[22]) << 8 | UInt32(b[23]) << 16 | UInt32(b[24]) << 24
            return (Int(bits & 0x3FFF) + 1, Int((bits >> 14) & 0x3FFF) + 1)
        case "VP8X":
            // Payload at 20: flags(1), reserved(3), canvas width-1 (24 bit LE), height-1 (24 bit LE).
            return (le24(b, 24) + 1, le24(b, 27) + 1)
        default:
            return nil
        }
    }

    /// `width="…"`/`height="…"` on the `<svg` tag, when they are plain numbers (optionally `px`).
    private static func svgSize(_ data: Data) -> (Int, Int)? {
        let text = String(decoding: data.prefix(4096), as: UTF8.self)
        guard let open = text.range(of: "<svg", options: .caseInsensitive) else { return nil }
        let tagEnd = text[open.upperBound...].firstIndex(of: ">") ?? text.endIndex
        let tag = text[open.upperBound..<tagEnd]
        guard let w = svgAttribute("width", in: tag), let h = svgAttribute("height", in: tag) else { return nil }
        return (w, h)
    }

    private static func svgAttribute(_ name: String, in tag: Substring) -> Int? {
        guard let range = tag.range(of: " \(name)=", options: .caseInsensitive) else { return nil }
        var rest = tag[range.upperBound...]
        guard let quote = rest.first, quote == "\"" || quote == "'" else { return nil }
        rest = rest.dropFirst()
        guard let close = rest.firstIndex(of: quote) else { return nil }
        var value = rest[..<close].trimmingCharacters(in: .whitespaces)
        if value.hasSuffix("px") { value = String(value.dropLast(2)) }
        if let n = Int(value) { return n }
        if let d = Double(value) { return Int(d.rounded()) }
        return nil
    }

    // MARK: Binary guesses

    /// A MessagePack document whose root is a map or array and whose encoding ends exactly at the end.
    static func isMessagePack(_ data: Data) -> Bool {
        let b = Array(data)
        guard let first = b.first else { return false }
        let rootIsContainer = (0x80...0x9F).contains(first) || (0xDC...0xDF).contains(first)
        guard rootIsContainer else { return false }
        var pos = 0
        guard skipMessagePack(b, &pos, depth: 0) else { return false }
        return pos == b.count
    }

    private static func skipMessagePack(_ b: [UInt8], _ pos: inout Int, depth: Int) -> Bool {
        guard depth < 64, pos < b.count else { return false }
        let t = b[pos]
        pos += 1
        func take(_ n: Int) -> Bool {
            guard pos + n <= b.count else { return false }
            pos += n
            return true
        }
        func length(_ bytes: Int) -> Int? {
            guard pos + bytes <= b.count else { return nil }
            var n = 0
            for k in 0..<bytes { n = n << 8 | Int(b[pos + k]) }
            pos += bytes
            return n
        }
        func elements(_ count: Int) -> Bool {
            guard count <= 1_000_000 else { return false }
            for _ in 0..<count {
                guard skipMessagePack(b, &pos, depth: depth + 1) else { return false }
            }
            return true
        }
        switch t {
        case 0x00...0x7F, 0xE0...0xFF, 0xC0, 0xC2, 0xC3: return true
        case 0x80...0x8F: return elements(Int(t & 0x0F) * 2)
        case 0x90...0x9F: return elements(Int(t & 0x0F))
        case 0xA0...0xBF: return take(Int(t & 0x1F))
        case 0xC1: return false
        case 0xC4, 0xD9: return length(1).map(take) ?? false
        case 0xC5, 0xDA: return length(2).map(take) ?? false
        case 0xC6, 0xDB: return length(4).map(take) ?? false
        case 0xC7: return length(1).map { take($0 + 1) } ?? false
        case 0xC8: return length(2).map { take($0 + 1) } ?? false
        case 0xC9: return length(4).map { take($0 + 1) } ?? false
        case 0xCA: return take(4)
        case 0xCB: return take(8)
        case 0xCC, 0xD0: return take(1)
        case 0xCD, 0xD1: return take(2)
        case 0xCE, 0xD2: return take(4)
        case 0xCF, 0xD3: return take(8)
        case 0xD4: return take(2)
        case 0xD5: return take(3)
        case 0xD6: return take(5)
        case 0xD7: return take(9)
        case 0xD8: return take(17)
        case 0xDC: return length(2).map(elements) ?? false
        case 0xDD: return length(4).map(elements) ?? false
        case 0xDE: return length(2).map { elements($0 * 2) } ?? false
        case 0xDF: return length(4).map { elements($0 * 2) } ?? false
        default: return false
        }
    }

    /// Protobuf wire format: a sequence of `(field << 3 | type)` varint tags with
    /// well-formed payloads that ends exactly at the end of the data.
    static func isProtobuf(_ data: Data) -> Bool {
        let b = Array(data)
        guard !b.isEmpty else { return false }
        var pos = 0
        var fields = 0
        func varint() -> UInt64? {
            var value: UInt64 = 0
            var shift: UInt64 = 0
            while pos < b.count, shift < 64 {
                let byte = b[pos]
                pos += 1
                value |= UInt64(byte & 0x7F) << shift
                if byte & 0x80 == 0 { return value }
                shift += 7
            }
            return nil
        }
        while pos < b.count {
            guard let tag = varint() else { return false }
            let field = tag >> 3
            guard field >= 1, field <= 536_870_911 else { return false }
            switch tag & 0x7 {
            case 0: guard varint() != nil else { return false }
            case 1: guard pos + 8 <= b.count else { return false }; pos += 8
            case 5: guard pos + 4 <= b.count else { return false }; pos += 4
            case 2:
                guard let length = varint(), length <= UInt64(b.count - pos) else { return false }
                pos += Int(length)
            default: return false
            }
            fields += 1
        }
        return fields > 0
    }

    // MARK: Form and multipart

    /// `a=1&b=hello+world&c=%20x` → `[(a, 1), (b, hello world), (c,  x)]`. A pair
    /// without `=` decodes to an empty value. Invalid percent escapes pass through.
    public static func formDecode(_ data: Data) -> [(String, String)] {
        let text = String(decoding: data, as: UTF8.self)
        return text.split(separator: "&", omittingEmptySubsequences: true).map { pair in
            if let eq = pair.firstIndex(of: "=") {
                return (formDecodeComponent(pair[..<eq]), formDecodeComponent(pair[pair.index(after: eq)...]))
            }
            return (formDecodeComponent(pair), "")
        }
    }

    static func formDecodeComponent(_ s: Substring) -> String {
        let bytes = Array(s.utf8)
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count)
        var i = 0
        while i < bytes.count {
            let c = bytes[i]
            if c == UInt8(ascii: "+") {
                out.append(0x20)
                i += 1
            } else if c == UInt8(ascii: "%"), let hi = hexNibble(bytes[safe: i + 1]), let lo = hexNibble(bytes[safe: i + 2]) {
                out.append(hi << 4 | lo)
                i += 3
            } else {
                out.append(c)
                i += 1
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    private static func hexNibble(_ b: UInt8?) -> UInt8? {
        guard let b else { return nil }
        switch b {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return b - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return b - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return b - UInt8(ascii: "A") + 10
        default: return nil
        }
    }

    /// Splits a multipart body on `--boundary`. Each part's headers end at the
    /// first blank line; the body runs to the line before the next delimiter.
    /// Accepts CRLF or LF line ends; the preamble and the epilogue are dropped.
    public static func multipartParts(_ data: Data, boundary: String) -> [MultipartPart] {
        let bytes = Array(data)
        let delimiter = Array("--\(boundary)".utf8)
        guard !boundary.isEmpty, !bytes.isEmpty else { return [] }

        var starts: [Int] = []
        var search = 0
        while let hit = find(delimiter, in: bytes, from: search) {
            starts.append(hit)
            search = hit + delimiter.count
        }
        guard starts.count >= 2 else { return [] }

        var parts: [MultipartPart] = []
        for n in 0..<(starts.count - 1) {
            var begin = starts[n] + delimiter.count
            // The closing delimiter has `--` after the boundary; stop there.
            if begin + 1 < bytes.count, bytes[begin] == 0x2D, bytes[begin + 1] == 0x2D { break }
            // Skip the rest of the delimiter line.
            while begin < bytes.count, bytes[begin] != 0x0A { begin += 1 }
            begin += 1
            var end = starts[n + 1]
            if end > begin, bytes[end - 1] == 0x0A { end -= 1 }
            if end > begin, bytes[end - 1] == 0x0D { end -= 1 }
            guard begin <= end else { continue }
            let section = Array(bytes[begin..<end])
            parts.append(part(from: section))
        }
        return parts
    }

    private static func part(from section: [UInt8]) -> MultipartPart {
        var headers: [HTTPMessage.Header] = []
        var pos = 0
        var bodyStart = section.count
        while pos < section.count {
            var lineEnd = pos
            while lineEnd < section.count, section[lineEnd] != 0x0A { lineEnd += 1 }
            var contentEnd = lineEnd
            if contentEnd > pos, section[contentEnd - 1] == 0x0D { contentEnd -= 1 }
            if contentEnd == pos {
                bodyStart = min(section.count, lineEnd + 1)
                break
            }
            let line = String(decoding: section[pos..<contentEnd], as: UTF8.self)
            if let colon = line.firstIndex(of: ":") {
                let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
                let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                headers.append(.init(name, value))
            } else {
                // Not a header line: the part has no headers and this is body.
                bodyStart = pos
                break
            }
            pos = lineEnd + 1
        }
        return MultipartPart(headers: headers, body: Data(section[bodyStart...]))
    }

    private static func find(_ needle: [UInt8], in haystack: [UInt8], from: Int) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count else { return nil }
        var i = from
        let last = haystack.count - needle.count
        while i <= last {
            if haystack[i] == needle[0] {
                var match = true
                for k in 1..<needle.count where haystack[i + k] != needle[k] {
                    match = false
                    break
                }
                if match { return i }
            }
            i += 1
        }
        return nil
    }
}

private extension Array where Element == UInt8 {
    subscript(safe index: Int) -> UInt8? {
        index >= 0 && index < count ? self[index] : nil
    }
}
