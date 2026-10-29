import AitmproxyKit
import SwiftUI
import UniformTypeIdentifiers

/// Shared between `DiffView` and the tab bar's `DiffControls`.
@Observable
final class DiffViewState {
    var unified = false
    var collapsed: Set<FlowDiffSection.Part> = []
}

/// Two flows compared (S-026): four collapsible sections, side by side or
/// unified; inserted lines on `diffAdd`, deleted on `diffRemove`, each with
/// its `+` / `-` marker so colour is never the only signal.
struct DiffView: View {
    var result: FlowDiffResult
    var bodySize: CGFloat = Tok.Typography.Size.md
    var state: DiffViewState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(result.sections) { section in
                    sectionHeader(section)
                    if section.diff.hasChanges, !state.collapsed.contains(section.part) {
                        if state.unified {
                            UnifiedDiff(diff: section.diff, bodySize: bodySize)
                        } else {
                            SideBySideDiff(pairs: section.diff.sideBySide(), bodySize: bodySize)
                        }
                    }
                }
            }
            .padding(.vertical, Space.sm)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// `› REQUEST BODY  +3 −1`, or `REQUEST BODY  No changes` with no chevron.
    private func sectionHeader(_ section: FlowDiffSection) -> some View {
        let changed = section.diff.hasChanges
        let open = changed && !state.collapsed.contains(section.part)
        return Button {
            guard changed else { return }
            if open { state.collapsed.insert(section.part) } else { state.collapsed.remove(section.part) }
        } label: {
            HStack(spacing: Space.sm) {
                Image(systemName: Tok.Glyph.chevron)
                    .font(.system(size: Tok.Size.iconInline))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .rotationEffect(.degrees(open ? 90 : 0))
                    .opacity(changed ? 1 : 0)
                    .frame(width: Space.md)
                Text(section.title.uppercased())
                    .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                    .tracking(0.5)
                    .foregroundStyle(Tok.Ink.tertiary.color)
                if changed {
                    Text("+\(section.diff.insertions) −\(section.diff.deletions)")
                        .font(Tok.Face.data(Tok.Typography.Size.xs))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                } else {
                    Text("No changes")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, Space.md)
            .frame(height: Tok.Size.columnHeader)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!changed)
        .accessibilityLabel(section.title)
        .accessibilityValue(changed ? (open ? "expanded" : "collapsed") : "no changes")
    }
}

/// Two columns of `DiffPair`s: old on the left, new on the right.
private struct SideBySideDiff: View {
    var pairs: [DiffPair]
    var bodySize: CGFloat

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(pairs.enumerated()), id: \.offset) { _, pair in
                HStack(spacing: 0) {
                    DiffCell(line: pair.left, side: .old, bodySize: bodySize)
                    VRule(color: Tok.Line.rule)
                    DiffCell(line: pair.right, side: .new, bodySize: bodySize)
                }
            }
        }
    }
}

/// `TextDiff.hunks` as one column: a hunk header, then every line with both numbers.
private struct UnifiedDiff: View {
    var diff: TextDiff
    var bodySize: CGFloat

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(diff.hunks().enumerated()), id: \.offset) { _, hunk in
                Text(hunk.header)
                    .font(Tok.Face.data(bodySize))
                    .foregroundStyle(Tok.Syntax.punct.color)
                    .padding(.leading, Space.md)
                    .frame(minHeight: 20, alignment: .leading) // grid: ok code line height 13 * 1.55
                    .frame(maxWidth: .infinity, alignment: .leading)
                ForEach(Array(hunk.lines.enumerated()), id: \.offset) { _, line in
                    DiffCell(line: line, side: .both, bodySize: bodySize)
                }
            }
        }
    }
}

/// One line: number(s) in the gutter colour, the marker, the text; tinted when changed.
private struct DiffCell: View {
    enum Side { case old, new, both }

    var line: DiffLine?
    var side: Side
    var bodySize: CGFloat

    var body: some View {
        HStack(spacing: 0) {
            Text(numbers)
                .foregroundStyle(Tok.Syntax.lineNumber.color)
                .frame(width: side == .both ? 72 : 40, alignment: .trailing) // grid: ok gutter, as CodeView
                .padding(.trailing, Space.sm)
            Text(line?.marker ?? " ")
                .frame(width: Space.md, alignment: .leading)
            Text(line?.text ?? "")
                .lineLimit(1)
                .truncationMode(.tail)
                .textSelection(.enabled)
            Spacer(minLength: Space.sm)
        }
        .font(Tok.Face.data(bodySize))
        .foregroundStyle(pair?.fg.color ?? Tok.Ink.primary.color)
        .frame(minHeight: 20) // grid: ok code line height 13 * 1.55
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(pair?.bg.color ?? .clear)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(line.map { "\(accessibleKind($0)) \($0.text)" } ?? "")
    }

    private var numbers: String {
        guard let line else { return "" }
        switch side {
        case .old: return line.oldLine.map(String.init) ?? ""
        case .new: return line.newLine.map(String.init) ?? ""
        case .both:
            let old = line.oldLine.map(String.init) ?? ""
            let new = line.newLine.map(String.init) ?? ""
            return "\(old) \(new)"
        }
    }

    private var pair: ColorPair? {
        switch line?.kind {
        case .insert: Tok.Syntax.diffAdd
        case .delete: Tok.Syntax.diffRemove
        case .equal, .none: nil
        }
    }

    private func accessibleKind(_ line: DiffLine) -> String {
        switch line.kind {
        case .insert: "added"
        case .delete: "removed"
        case .equal: ""
        }
    }
}

/// The Diff tab's trailing controls: Side by side | Unified, Export Patch…, the truncated chip.
struct DiffControls: View {
    var result: FlowDiffResult
    var state: DiffViewState

    var body: some View {
        HStack(spacing: Space.sm) {
            if result.truncated {
                Text("truncated")
                    .font(Tok.Face.ui(Tok.Typography.Size.xs))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .padding(.horizontal, Tok.Metric.gapTight)
                    .frame(minHeight: Tok.Metric.countChip)
                    .background(Tok.Ground.raised.color, in: Capsule())
                    .help("Each side is compared up to \(Format.bytes(Int64(TextDiff.maxBytesPerSide)))")
                    .accessibilityLabel("truncated")
            }
            HStack(spacing: 2) {
                mode("Side by side", unified: false)
                mode("Unified", unified: true)
            }
            Button("Export Patch…") { exportPatch() }
                .buttonStyle(.plain)
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(result.hasChanges ? Tok.Ink.secondary.color : Tok.Ink.tertiary.color)
                .disabled(!result.hasChanges)
                .help("Save the unified diff as a .patch file")
        }
    }

    private func mode(_ title: String, unified: Bool) -> some View {
        let on = state.unified == unified
        return Button { state.unified = unified } label: {
            Text(title)
                .font(Tok.Face.ui(Tok.Typography.Size.sm, on ? .medium : .regular))
                .foregroundStyle(on ? Tok.Ink.primary.color : Tok.Ink.tertiary.color)
                .padding(.horizontal, Space.sm)
                .frame(height: Tok.Metric.chip)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(on ? .isSelected : [])
    }

    private func exportPatch() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "patch") ?? .plainText]
        panel.nameFieldStringValue = "\(result.left.raw.prefix(8))-\(result.right.raw.prefix(8)).patch"
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? Data(result.unified().utf8).write(to: url, options: .atomic)
    }
}

/// One row selected: the words from S-026's UX block.
struct DiffEmpty: View {
    var body: some View {
        Text("Select a second flow with ⌘-click to compare")
            .font(Tok.Face.ui(Tok.Typography.Size.md))
            .foregroundStyle(Tok.Ink.tertiary.color)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
