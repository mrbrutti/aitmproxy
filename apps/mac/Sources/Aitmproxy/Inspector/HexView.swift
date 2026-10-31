import AitmproxyKit
import SwiftUI

/// `offset · bytes · ASCII`, 16 bytes per line in a wide pane and 8 in a
/// narrow one (S-024). A lazy stack of `HexDump.lineCount` rows, each
/// formatted on demand from the bytes it covers, so a 20 MB body never
/// materialises all its lines.
struct HexView: View {
    var data: Data
    var bodySize: CGFloat = Tok.Typography.Size.md

    /// 16 bytes per line fit (with the ASCII column) from 640 pt; below that, 8.
    static func bytesPerLine(forWidth width: CGFloat) -> Int { width >= 640 ? 16 : 8 }

    var body: some View {
        // The content is at least the viewport's size, so a short dump sits
        // top-leading and never floats in the middle of the pane (as CodeView).
        GeometryReader { viewport in
            let bytesPerLine = Self.bytesPerLine(forWidth: viewport.size.width)
            let lineCount = HexDump.lineCount(data.count, bytesPerLine: bytesPerLine)
            ScrollView([.vertical, .horizontal]) {
                LazyVStack(alignment: .leading, spacing: 0) {
                    if data.isEmpty {
                        Hint(text: "No body")
                    }
                    ForEach(0..<lineCount, id: \.self) { index in
                        HexRow(line: HexDump.lines(data, range: index..<(index + 1), bytesPerLine: bytesPerLine).first,
                               bodySize: bodySize)
                    }
                }
                .padding(Space.md)
                .frame(minWidth: viewport.size.width, minHeight: viewport.size.height, alignment: .topLeading)
            }
            .textSelection(.enabled)
            .accessibilityLabel("Hex dump, \(lineCount) lines")
        }
    }
}

/// One line: offset in the line-number colour, bytes in primary, ASCII in secondary.
private struct HexRow: View {
    var line: HexLine?
    var bodySize: CGFloat

    var body: some View {
        if let line {
            Text(attributed(line))
                .font(Tok.Face.data(bodySize))
                .lineLimit(1)
                .frame(height: 20, alignment: .leading) // grid: ok code line height 13 * 1.55
                .textSelection(.enabled)
        }
    }

    private func attributed(_ line: HexLine) -> AttributedString {
        var text = AttributedString()
        var offset = AttributedString(line.offsetText + "  ")
        offset.foregroundColor = Tok.Syntax.lineNumber.color
        var bytes = AttributedString(line.hexText + "  ")
        bytes.foregroundColor = Tok.Ink.primary.color
        var ascii = AttributedString(line.asciiText)
        ascii.foregroundColor = Tok.Ink.secondary.color
        text.append(offset)
        text.append(bytes)
        text.append(ascii)
        return text
    }
}
