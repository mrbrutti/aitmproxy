import AitmproxyKit
import AppKit
import SwiftUI

/// The detail pane of the Findings page (S-051): the editable YAML with Save,
/// the screenshot, the per-assertion table, and the Open capture · Run again ·
/// Export actions.
struct FindingDetail: View {
    @Bindable var state: PocPanelState
    @State private var showRunAgain = false

    var body: some View {
        if let finding = state.selectedFinding {
            VStack(spacing: 0) {
                header(finding)
                Rule()
                content(finding)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            VStack(spacing: Space.sm) {
                Text("No finding selected").font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                Text("Pick a run on the left, or build a PoC from any flow with p.")
                    .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func header(_ finding: Finding) -> some View {
        HStack(spacing: Space.md) {
            Text(finding.title).font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
            Badge(text: finding.severity.title, pair: finding.severity.pair, uppercase: false)
            Spacer(minLength: Space.sm)
            FlatButton("Open capture") { state.openCapture() }
                .disabled(finding.captureID == nil)
            FlatButton("Run again") { showRunAgain = true }
                .popover(isPresented: $showRunAgain, arrowEdge: .bottom) {
                    RunAgainPopover(state: state, finding: finding, isPresented: $showRunAgain)
                }
            FlatButton("Export") { export() }
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.inspectorHeader)
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
                             onTextChange: { state.yamlDraft = $0 })
                    .frame(height: 260) // grid: ok fixed editor height on a scrolling page
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
        if let data = finding.screenshot {
            ImageBodyView(data: data, contentType: "image/png")
                .frame(height: 220) // grid: ok fixed screenshot viewport
                .background(Tok.Ground.surface.color)
                .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.border.color))
        } else {
            Text("No screenshot")
                .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
                .frame(maxWidth: .infinity).frame(height: 220) // grid: ok placeholder at the image's size
                .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
        }
    }

    @ViewBuilder private func assertions(_ finding: Finding) -> some View {
        if finding.assertions.isEmpty {
            Hint(text: finding.hasRun ? "No assertions evaluated" : "Not run yet — Run again to evaluate the success assertions")
        } else {
            VStack(spacing: 0) {
                ColumnHeads(columns: [(title: "Assertion", width: nil), (title: "Result", width: 80)])
                ForEach(Array(finding.assertions.enumerated()), id: \.offset) { _, assertion in
                    HStack(spacing: Space.md) {
                        Text(assertion.text).font(Tok.Face.data(Tok.Typography.Size.md))
                            .foregroundStyle(Tok.Ink.primary.color).textSelection(.enabled)
                        Spacer(minLength: Space.sm)
                        Image(systemName: assertion.matched ? "checkmark" : "xmark")
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

    private func export() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Export"
        panel.message = "Choose a folder for the YAML, screenshot and HAR"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        state.exportBundle(to: url)
    }
}
