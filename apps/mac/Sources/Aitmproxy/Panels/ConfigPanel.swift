import AitmBusClient
import AitmproxyKit
import AppKit
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
    @State private var reloadedAt: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .gridProbe("config-head", area: "config", edge: nil)
            Rule()
            if let document {
                provenance(document)
                    .gridProbe("config-prov", area: "config", edge: nil)
                Rule(color: Tok.Line.rule)
                if let note {
                    Hint(text: note).padding(.horizontal, Space.md).padding(.top, Space.xs)
                }
                // Anchored to the viewport: a two-axis ScrollView otherwise centres short content.
                GeometryReader { viewport in
                    // The env gutter is only held open when some line carries an override.
                    let hasEnv = document.lines.contains(where: \.isEnv)
                    ScrollView([.vertical, .horizontal]) {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(document.lines) { line in ConfigLine(line: line, showsGutter: hasEnv) }
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
        .gridArea("config", inset: 0)
        .onAppear { if document == nil { load() } }
    }

    private var header: some View {
        HStack(spacing: Space.md) {
            Text("Configuration").font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
            Spacer()
            FlatButton("Reload", symbol: "arrow.clockwise") { load() }
        }
        .padding(.horizontal, Space.margin)
        .frame(height: Tok.Size.inspectorHeader)
    }

    /// Where the shown config came from and when it was last read, with a jump to
    /// the file in Finder when it is a real path on disk (S-059 provenance).
    private func provenance(_ document: ConfigDocument) -> some View {
        HStack(spacing: Space.sm) {
            Text(provenanceText(document))
                .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                .lineLimit(1).truncationMode(.middle).help(document.path)
            if document.path.hasPrefix("/") {
                FlatButton("Reveal in Finder", symbol: "folder") { reveal(document.path) }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Space.md).padding(.vertical, Space.xs)
    }

    private func provenanceText(_ document: ConfigDocument) -> String {
        var parts = ["Loaded from \(document.path)"]
        if let reloadedAt {
            parts.append("reloaded \(reloadedAt.formatted(date: .omitted, time: .shortened))")
        }
        return parts.joined(separator: " · ")
    }

    private func reveal(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    private func load() {
        reloadedAt = Date()
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
        // F7: config.get serves the proxy's effective configuration.
        note = "Read from \(url.path) — the proxy's effective configuration arrives when the core can report it"
    }
}

/// One rendered config line: a gutter holding an `env` chip, then the
/// YAML-coloured text, with a wash on the listen / bus lines.
private struct ConfigLine: View {
    var line: ConfigDocument.Line
    /// False when no line in the document has an env override: the gutter collapses.
    var showsGutter = true

    var body: some View {
        HStack(alignment: .center, spacing: 0) {
            // A reserved gutter: EmptyView ignores .frame, so the chip rides in an
            // overlay over a clear box that holds the 44 pt column open while any
            // line needs it.
            if showsGutter {
                Color.clear
                    .frame(width: 44, height: Tok.Metric.countChip) // grid: ok gutter width from the foundation
                    .overlay(alignment: .trailing) { if line.isEnv { envChip } }
                    .padding(.trailing, Tok.Metric.gapMeta)
            }
            text
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .lineLimit(1)
            Spacer(minLength: Space.lg)
            if let tag = highlightTag {
                Text(tag)
                    .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                    .foregroundStyle(Tok.Accent.deep.color)
                    .padding(.horizontal, Tok.Metric.gapTight).frame(height: Tok.Metric.countChip)
                    .background(Tok.Ground.surface.color, in: Capsule())
                    .padding(.trailing, Space.md)
                    .help(tag == "listen" ? "The address aitmproxy listens on" : "The address the MCP bus listens on")
            }
        }
        .padding(.leading, Space.md)
        .frame(minHeight: 20) // grid: ok code line height 13 * 1.55
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(line.highlight ? Tok.Accent.tint.color : .clear)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(line.text + (line.isEnv ? ", overridden by an environment variable" : "")
            + (highlightTag.map { ", the \($0) address" } ?? ""))
    }

    private var envChip: some View {
        Text("env").font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
            .foregroundStyle(Tok.Ink.secondary.color)
            .padding(.horizontal, Tok.Metric.gapTight).frame(height: Tok.Metric.countChip)
            .background(Tok.Ground.raised.color, in: Capsule())
    }

    /// The word for the listen / bus highlight wash, so the tint carries meaning
    /// without colour alone.
    private var highlightTag: String? {
        guard line.highlight else { return nil }
        if line.key == "listen" { return "listen" }
        if line.key.contains("loopback_tcp") { return "bus" }
        return nil
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
