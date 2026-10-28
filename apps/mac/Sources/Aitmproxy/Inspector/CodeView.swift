import AitmproxyKit
import SwiftUI

/// One line of a body viewer: syntax runs, plus the edited / current flags.
struct CodeLine: Hashable, Identifiable {
    var id = UUID()
    var runs: [SyntaxRun]
    var edited = false
    var current = false
}

/// A line-numbered, syntax-coloured mono viewer: 13px on 20px lines,
/// a 44px gutter. Pure SwiftUI for now; the NSTextView editor for paused
/// requests and multi-megabyte bodies comes with the body-viewer work.
struct CodeView: View {
    var lines: [CodeLine]
    var header: String?
    var footer: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let header {
                Hint(text: header)
                    .padding(.leading, Space.md)
                    .padding(.top, Space.xs)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ScrollView([.vertical, .horizontal]) {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(lines.enumerated()), id: \.element.id) { index, line in
                    HStack(spacing: 0) {
                        Text("\(index + 1)")
                            .font(Tok.Face.data(Tok.Typography.Size.xs))
                            .foregroundStyle((line.current ? Tok.Ink.secondary : Tok.Syntax.lineNumber).color)
                            .frame(width: 44, alignment: .trailing) // grid: ok gutter width from the foundation
                            .padding(.trailing, Tok.Metric.gapMeta)
                        runs(line.runs)
                            .font(Tok.Face.data(Tok.Typography.Size.md))
                            .lineLimit(1)
                        Spacer(minLength: Space.lg)
                    }
                    .frame(minHeight: 20) // grid: ok code line height 13 * 1.55
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(line.current ? Tok.Syntax.currentLine.color : .clear)
                    .overlay(alignment: .leading) {
                        if line.edited { Rectangle().fill(Tok.Intercept.base.color).frame(width: 2) }
                    }
                }
                if let footer {
                    Hint(text: footer).padding(.leading, 58) // grid: ok gutter + padding
                }
            }
            .padding(.vertical, Space.sm)
            .frame(maxWidth: .infinity, alignment: .leading)
            }
            .textSelection(.enabled)
        }
    }

    private func runs(_ runs: [SyntaxRun]) -> Text {
        var text = AttributedString()
        for run in runs {
            var piece = AttributedString(run.text)
            piece.foregroundColor = run.kind.color.color
            text.append(piece)
        }
        return Text(text)
    }
}

struct Hint: View {
    var text: String
    var body: some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.tertiary.color)
            .padding(.vertical, Space.xs)
            .padding(.trailing, Space.md)
    }
}

/// Two-column key : value table (mono lowercase names in `syntax.key`).
struct HeaderTable: View {
    var headers: [HTTPMessage.Header]

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                if headers.isEmpty {
                    Hint(text: "None").padding(.leading, Space.md)
                }
                ForEach(Array(headers.enumerated()), id: \.offset) { _, header in
                    HStack(alignment: .firstTextBaseline, spacing: Space.md) {
                        Text(header.name)
                            .foregroundStyle(Tok.Syntax.key.color)
                            .frame(width: 180, alignment: .leading)
                        Text(header.value)
                            .foregroundStyle(Tok.Ink.primary.color)
                            .textSelection(.enabled)
                        Spacer(minLength: 0)
                    }
                    .font(Tok.Face.data(Tok.Typography.Size.md))
                    .padding(.horizontal, Space.md)
                    .frame(minHeight: Tok.Size.Row.dense)
                    .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
                }
            }
        }
    }
}
