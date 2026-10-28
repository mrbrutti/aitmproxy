import AitmBusClient
import AitmproxyKit
import SwiftUI

/// Configuration (S-059): the effective proxy config as a read-only code view,
/// overridden keys carrying an `env` chip in the gutter, the listen and bus
/// addresses highlighted, and a Reload.
///
/// A custom line view rather than the plain `CodeTextView`: an NSTextView
/// cannot carry the per-line `env` chips or the listen/bus highlight the story
/// requires, and it lets the YAML colour through `Syntax.yaml` (the shared
/// `CodeAnalysis` tokenizer has no YAML path and is out of this task's files).
struct ConfigPanel: View {
    @Environment(Session.self) private var session
    @State private var document: ConfigDocument?
    @State private var note: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Rule()
            if let document {
                if let note {
                    Hint(text: note).padding(.horizontal, Space.md).padding(.top, Space.xs)
                }
                // Anchored to the viewport: a two-axis ScrollView otherwise centres short content.
                GeometryReader { viewport in
                    ScrollView([.vertical, .horizontal]) {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(document.lines) { line in ConfigLine(line: line) }
                        }
                        .padding(.vertical, Space.sm)
                        .textSelection(.enabled)
                        .frame(minWidth: viewport.size.width, minHeight: viewport.size.height, alignment: .topLeading)
                    }
                }
            } else {
                LoadingLines()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Tok.Ground.surface.color)
        .gridArea("config")
        .onAppear { if document == nil { load() } }
    }

    private var header: some View {
        HStack(spacing: Space.md) {
            Text("Configuration").font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
            Spacer()
            FlatButton("Reload", symbol: "arrow.clockwise") { load() }
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.inspectorHeader)
    }

    private func load() {
        if Store.usesFixtures {
            document = ConfigDocument(yaml: Fixtures.configYAML, path: "config.yaml", envOverrides: [])
            note = nil
            return
        }
        if session.tools.contains(where: { $0.name == "config.get" }) {
            Task {
                if let yaml = try? await session.runCommand("config.get", [:]).stringValue {
                    document = ConfigDocument(yaml: yaml, path: "proxy", envOverrides: [])
                    note = nil
                } else {
                    readFromFile()
                }
            }
        } else {
            readFromFile()
        }
    }

    /// Before F7: the config.yaml the app reads itself, with a note (S-059 state).
    private func readFromFile() {
        let url = BusService.configURL
        let yaml = (try? String(contentsOf: url, encoding: .utf8)) ?? "# no config.yaml at \(url.path)"
        document = ConfigDocument(yaml: yaml, path: url.path, envOverrides: [])
        note = "from \(url.path); the proxy's effective config needs config.get (F7)"
    }
}

/// One rendered config line: a gutter holding an `env` chip, then the
/// YAML-coloured text, with a wash on the listen / bus lines.
private struct ConfigLine: View {
    var line: ConfigDocument.Line

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 0) {
            Group {
                if line.isEnv {
                    Text("env").font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                        .foregroundStyle(Tok.Ink.secondary.color)
                        .padding(.horizontal, Tok.Metric.gapTight).frame(height: Tok.Metric.countChip)
                        .background(Tok.Ground.raised.color, in: Capsule())
                }
            }
            .frame(width: 44, alignment: .trailing) // grid: ok gutter width from the foundation
            .padding(.trailing, Tok.Metric.gapMeta)
            text
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .lineLimit(1)
            Spacer(minLength: Space.lg)
        }
        .frame(minHeight: 20) // grid: ok code line height 13 * 1.55
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(line.highlight ? Tok.Accent.tint.color : .clear)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(line.text + (line.isEnv ? ", overridden by an environment variable" : ""))
    }

    private var text: Text {
        var attributed = AttributedString()
        for run in Syntax.yaml(line: line.text) {
            var piece = AttributedString(run.text)
            piece.foregroundColor = run.kind.color.color
            attributed.append(piece)
        }
        return Text(attributed)
    }
}
