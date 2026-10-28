import AitmproxyKit
import SwiftUI

/// Run again (S-052): a small popover built from `poc.run`'s schema — Target
/// prefilled, Vars as key : value rows — that drops a new finding into the list.
struct RunAgainPopover: View {
    var state: PocPanelState
    var finding: Finding
    @Binding var isPresented: Bool

    @State private var form: PocRunForm
    @FocusState private var targetFocused: Bool

    init(state: PocPanelState, finding: Finding, isPresented: Binding<Bool>) {
        self.state = state
        self.finding = finding
        _isPresented = isPresented
        _form = State(initialValue: PocRunForm(tool: state.session.tools.first { $0.name == "poc.run" }, finding: finding))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            Text("Run again").font(Tok.Face.ui(Tok.Typography.Size.md, .semibold)).foregroundStyle(Tok.Ink.primary.color)
            field("Target") {
                TextField("https://host", text: $form.target).textFieldStyle(.plain)
                    .font(Tok.Face.data(Tok.Typography.Size.md)).focused($targetFocused)
                    .padding(.horizontal, Space.sm).frame(height: Tok.Size.control)
                    .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                    .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
            }
            if form.hasVars {
                Text("VARS").font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6).foregroundStyle(Tok.Ink.tertiary.color)
                ForEach($form.vars) { $row in
                    HStack(spacing: Space.sm) {
                        varField("name", text: $row.key)
                        Text(":").foregroundStyle(Tok.Ink.tertiary.color)
                        varField("value", text: $row.value)
                        Button { form.vars.removeAll { $0.id == row.id } } label: {
                            Image(systemName: "minus.circle").font(.system(size: 13)).foregroundStyle(Tok.Ink.tertiary.color)
                        }
                        .buttonStyle(.plain)
                    }
                }
                FlatButton("Add Var", symbol: "plus") { form.vars.append(PocRunForm.Var()) }
            }
            HStack {
                Spacer()
                PrimaryButton(state.running ? "Running…" : "Run", hint: "⏎") { run() }
                    .disabled(state.running || form.target.isEmpty)
                    .keyboardShortcut(.return, modifiers: [])
            }
        }
        .padding(Space.lg)
        .frame(width: 360)
        .onAppear { targetFocused = true }
    }

    private func field<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            content()
        }
    }

    private func varField(_ placeholder: String, text: Binding<String>) -> some View {
        TextField(placeholder, text: text).textFieldStyle(.plain)
            .font(Tok.Face.data(Tok.Typography.Size.md))
            .padding(.horizontal, Space.sm).frame(height: Tok.Size.control)
            .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
    }

    private func run() {
        let target = form.target
        let vars = Dictionary(form.vars.filter { !$0.key.trimmingCharacters(in: .whitespaces).isEmpty }
            .map { ($0.key.trimmingCharacters(in: .whitespaces), $0.value) }, uniquingKeysWith: { _, last in last })
        Task {
            await state.run(finding, target: target, vars: vars)
            isPresented = false
        }
    }
}

/// Build PoC from a flow (S-053): Name, a Parameter picker from the request's
/// query / headers / JSON body keys, and `Build ⌘⏎`.
struct BuildPoCSheet: View {
    @Environment(Session.self) private var session
    @Environment(\.dismiss) private var dismiss
    var flowID: FlowID

    @State private var name = ""
    @State private var param = ""
    @FocusState private var nameFocused: Bool

    private var row: FlowRow? { session.rows.first { $0.id == flowID } }
    private var candidates: [String] {
        guard let row else { return [] }
        return PocParameters.candidates(for: session.details[flowID] ?? Fixtures.detail(for: row), row: row)
    }
    private var inScope: Bool { row?.inScope ?? false }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.lg) {
            Text("Build PoC").font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold)).foregroundStyle(Tok.Ink.primary.color)
            if let row {
                Text("\(row.method.label) \(row.url)").font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color).lineLimit(1).truncationMode(.middle)
            }
            field("Name") {
                TextField("reproduced finding", text: $name).textFieldStyle(.roundedBorder)
                    .font(Tok.Face.ui(Tok.Typography.Size.base)).focused($nameFocused)
            }
            field("Parameter") {
                FlatMenu(title: param.isEmpty ? "none" : param, width: 220) {
                    Button("none") { param = "" }
                    ForEach(candidates, id: \.self) { candidate in Button(candidate) { param = candidate } }
                }
            }
            HStack(spacing: Space.md) {
                if !inScope {
                    Text("Out of scope — add \(row?.authority ?? "host") to scope to act")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Intercept.deep.color)
                }
                Spacer()
                FlatButton("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                PrimaryButton(session.poc.running ? "Building…" : "Build", hint: "⌘⏎") { build() }
                    .disabled(!inScope || session.poc.running)
                    .keyboardShortcut(.return, modifiers: .command)
                    .help(inScope ? "Build a PoC from this flow (⌘⏎)" : "Out of scope — add \(row?.authority ?? "host") to scope to act")
            }
        }
        .padding(Space.xl)
        .frame(width: 440)
        .background(Tok.Ground.surface.color)
        .onAppear {
            if name.isEmpty { name = Self.defaultName(for: row) }
            if param.isEmpty { param = candidates.first ?? "" }
            nameFocused = true
        }
    }

    private func field<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            content()
        }
    }

    private func build() {
        let name = name.trimmingCharacters(in: .whitespaces)
        let param = param
        dismiss()
        Task { await session.poc.build(flowID: flowID, name: name.isEmpty ? "reproduced finding" : name, param: param.isEmpty ? nil : param) }
    }

    /// Prefilled from the request path's last segment (foundation §2.7).
    static func defaultName(for row: FlowRow?) -> String {
        guard let segment = row?.path.split(separator: "/").last.map(String.init), !segment.isEmpty else { return "reproduced finding" }
        return segment.replacingOccurrences(of: "-", with: " ").replacingOccurrences(of: "_", with: " ")
    }
}
