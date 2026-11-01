import AitmproxyKit
import AppKit
import SwiftUI

/// The detail pane of the Findings page (S-051): the editable YAML with Save,
/// the screenshot, the per-assertion table, and the Open Capture · Run Again… ·
/// Export… actions.
struct FindingDetail: View {
    @Bindable var state: PocPanelState
    @State private var showRunAgain = false

    var body: some View {
        if let finding = state.selectedFinding {
            VStack(spacing: 0) {
                header(finding)
                    .gridProbe("finding-head", area: "finding-detail", edge: nil)
                Rule()
                content(finding)
                    .gridProbe("finding-content", area: "finding-detail", edge: nil)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .gridArea("finding-detail", inset: 0)
        } else {
            ContentUnavailableView {
                Label("No finding selected", systemImage: Tok.Glyph.poc)
            } description: {
                Text("Pick a run on the left, or build a PoC from any flow (press p).")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func header(_ finding: Finding) -> some View {
        HStack(spacing: Space.md) {
            Text(finding.title).font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
            Badge(text: finding.severity.title, pair: finding.severity.pair, uppercase: false)
            if let verdict = runVerdict(finding) {
                Text(verdict).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                    .lineLimit(1).truncationMode(.tail)
            }
            Spacer(minLength: Space.sm)
            FlatButton("Open Capture") { state.openCapture() }
                .disabled(finding.captureID == nil)
            FlatButton("Run Again…") { showRunAgain = true }
                .popover(isPresented: $showRunAgain, arrowEdge: .bottom) {
                    RunAgainPopover(state: state, finding: finding, isPresented: $showRunAgain)
                }
            FlatButton("Export…") { state.exportViaPanel() }
        }
        .padding(.horizontal, Space.margin)
        .frame(height: Tok.Size.inspectorHeader)
    }

    /// "Last run 11:05 · 1 of 2 assertions matched" — nil for a built-but-never-run PoC.
    private func runVerdict(_ finding: Finding) -> String? {
        guard finding.hasRun else { return nil }
        let matched = finding.assertions.filter(\.matched).count
        let total = finding.assertions.count
        let time = finding.ranAt.formatted(date: .omitted, time: .shortened)
        return "Last run \(time) · \(matched) of \(total) assertion\(total == 1 ? "" : "s") matched"
    }

    /// A real, decodable capture — not an empty or tiny placeholder.
    private func hasScreenshot(_ finding: Finding) -> Bool {
        guard let data = finding.screenshot, let decoded = DecodedImage(data: data, contentType: "image/png") else { return false }
        return decoded.width >= 16 && decoded.height >= 16
    }

    @ViewBuilder private func content(_ finding: Finding) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.lg) {
                section("YAML") {
                    HStack(spacing: Space.sm) {
                        if state.isDirty {
                            Text("Unsaved").font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                                .foregroundStyle(Tok.Intercept.deep.color)
                                .padding(.horizontal, Tok.Metric.gapTight).frame(height: Tok.Metric.countChip)
                                .background(Tok.Intercept.tint.color, in: Capsule())
                        }
                        PrimaryButton("Save", hint: "⌘S") { state.save() }.disabled(!state.isDirty)
                    }
                }
                CodeTextView(text: state.yamlDraft, contentType: "text/yaml", editable: true,
                             completion: { LanguageCompletion.pocYAML(source: $0, caret: $1) },
                             onTextChange: { state.yamlDraft = $0 })
                    // Taller when the screenshot well below collapses to a one-line hint.
                    .frame(height: hasScreenshot(finding) ? 260 : 360) // grid: ok fixed editor height on a scrolling page
                    .clipShape(RoundedRectangle(cornerRadius: Tok.Radius.control))
                    .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.border.color))

                section("Screenshot") { EmptyView() }
                screenshot(finding)

                section("Assertions") { EmptyView() }
                assertions(finding)
            }
            .padding(Space.md)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder private func screenshot(_ finding: Finding) -> some View {
        if let data = finding.screenshot,
           let decoded = DecodedImage(data: data, contentType: "image/png"),
           decoded.width >= 16, decoded.height >= 16 {
            // Size the well to the image (capped) so a small capture is not a giant empty box.
            ImageBodyView(data: data, contentType: "image/png")
                .frame(height: min(220, CGFloat(decoded.height) + 56))
                .frame(maxWidth: .infinity)
                .background(Tok.Ground.surface.color)
                .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.border.color))
                .clipShape(RoundedRectangle(cornerRadius: Tok.Radius.control))
        } else {
            // One line rather than a 120 pt empty well, so the YAML editor keeps the room.
            Hint(text: finding.hasRun ? "No screenshot captured for this run." : "Run the PoC to capture a screenshot.")
        }
    }

    private var assertionsHead: some View {
        HStack(spacing: Space.md) {
            Text("ASSERTION").frame(maxWidth: .infinity, alignment: .leading)
            Text("RESULT").frame(width: 80, alignment: .leading)
        }
        .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.5)
        .foregroundStyle(Tok.Ink.tertiary.color)
        .lineLimit(1)
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.columnHeader)
        .overlay(alignment: .bottom) { Rule() }
        .accessibilityHidden(true)
    }

    @ViewBuilder private func assertions(_ finding: Finding) -> some View {
        if finding.assertions.isEmpty {
            Hint(text: finding.hasRun ? "No assertions evaluated" : "Not run yet — Run Again… evaluates the success assertions")
        } else {
            VStack(spacing: 0) {
                // Built locally (not the shared ColumnHeads) so RESULT sits over the
                // ✓/✗ column: the label column fills, RESULT is a fixed 80 pt leading
                // frame that lines up with each row's icon frame.
                assertionsHead
                ForEach(Array(finding.assertions.enumerated()), id: \.offset) { _, assertion in
                    HStack(spacing: Space.md) {
                        Text(assertion.text).font(Tok.Face.data(Tok.Typography.Size.md))
                            .foregroundStyle(Tok.Ink.primary.color).textSelection(.enabled)
                        Spacer(minLength: Space.sm)
                        Image(systemName: assertion.matched ? "checkmark.circle" : "xmark.circle")
                            .font(.system(size: Tok.Size.iconInline, weight: .medium))
                            .foregroundStyle((assertion.matched ? Tok.Status.success : Tok.Status.serverError).color)
                            .frame(width: 80, alignment: .leading)
                    }
                    .padding(.horizontal, Space.md)
                    .frame(minHeight: Tok.Size.Row.dense)
                    .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel("\(assertion.text), \(assertion.matched ? "matched" : "not matched")")
                }
            }
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.border.color))
        }
    }

    private func section<Trailing: View>(_ title: String, @ViewBuilder trailing: () -> Trailing) -> some View {
        HStack {
            Text(title.uppercased()).font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
                .foregroundStyle(Tok.Ink.tertiary.color)
            Spacer()
            trailing()
        }
    }

}
