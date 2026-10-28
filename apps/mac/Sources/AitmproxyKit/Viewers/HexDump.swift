import Foundation

/// One row of the hex viewer: `offset · bytes · ASCII` (foundation §2.7).
public struct HexLine: Identifiable, Hashable, Sendable {
    public var id: Int { offset }
    /// Byte offset of the first byte on the line.
    public var offset: Int
    /// Eight lowercase hex digits: `00000010`.
    public var offsetText: String
    /// Two-digit lowercase hex per byte, one space between bytes, two between
    /// the two halves of the line. Always the full line width: a short last
    /// line is padded with spaces so the ASCII column stays aligned.
    public var hexText: String
    /// Printable ASCII (0x20–0x7E) as is, anything else as `.`.
    public var asciiText: String

    public init(offset: Int, offsetText: String, hexText: String, asciiText: String) {
        self.offset = offset
        self.offsetText = offsetText
        self.hexText = hexText
        self.asciiText = asciiText
    }
}

public enum HexDump {
    /// Every line of the dump. For large bodies use `lines(_:range:)` with the visible rows only.
    public static func lines(_ data: Data, bytesPerLine: Int = 16) -> [HexLine] {
        lines(data, range: 0..<lineCount(data.count, bytesPerLine: bytesPerLine), bytesPerLine: bytesPerLine)
    }

    /// How many lines a body of `byteCount` bytes dumps to (0 for an empty body).
    public static func lineCount(_ byteCount: Int, bytesPerLine: Int = 16) -> Int {
        let width = max(1, bytesPerLine)
        return (byteCount + width - 1) / width
    }

    /// The lines with indices in `range` (line indices, not byte offsets), so
    /// a list can ask for the rows on screen. Out-of-range indices are clamped.
    public static func lines(_ data: Data, range: Range<Int>, bytesPerLine: Int = 16) -> [HexLine] {
        let width = max(1, bytesPerLine)
        let total = lineCount(data.count, bytesPerLine: width)
        let lower = min(max(0, range.lowerBound), total)
        let upper = min(max(lower, range.upperBound), total)
        guard lower < upper else { return [] }
        var result: [HexLine] = []
        result.reserveCapacity(upper - lower)
        let base = data.startIndex
        for lineIndex in lower..<upper {
            let offset = lineIndex * width
            let end = min(offset + width, data.count)
            let slice = Array(data[(base + offset)..<(base + end)])
            result.append(line(offset: offset, bytes: slice, bytesPerLine: width))
        }
        return result
    }

    /// Formats one line from the bytes at `offset`.
    public static func line(offset: Int, bytes: [UInt8], bytesPerLine: Int = 16) -> HexLine {
        let width = max(1, bytesPerLine)
        let half = width / 2
        var hex = ""
        hex.reserveCapacity(width * 3 + 1)
        var ascii = ""
        ascii.reserveCapacity(width)
        for i in 0..<width {
            if i > 0 {
                hex += (half > 0 && i == half) ? "  " : " "
            }
            if i < bytes.count {
                let b = bytes[i]
                hex += hexByte(b)
                ascii.append((0x20...0x7E).contains(b) ? Character(UnicodeScalar(b)) : ".")
            } else {
                hex += "  "
            }
        }
        return HexLine(offset: offset, offsetText: offsetText(offset), hexText: hex, asciiText: ascii)
    }

    /// `00000010`.
    public static func offsetText(_ offset: Int) -> String {
        String(format: "%08x", offset)
    }

    private static let digits: [Character] = Array("0123456789abcdef")

    static func hexByte(_ b: UInt8) -> String {
        var s = ""
        s.append(digits[Int(b >> 4)])
        s.append(digits[Int(b & 0x0F)])
        return s
    }

    /// `offset  hex  ascii` for every line, newline-separated — the text form
    /// used for copying and for diffing binary bodies.
    public static func text(_ data: Data, bytesPerLine: Int = 16) -> String {
        lines(data, bytesPerLine: bytesPerLine)
            .map { "\($0.offsetText)  \($0.hexText)  \($0.asciiText)" }
            .joined(separator: "\n")
    }
}
