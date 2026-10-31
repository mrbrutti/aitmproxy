import AitmproxyKit
import SwiftUI

/// Breakpoint Rules (S-040; foundation §2.7 "Rules…" after Proxyman's form):
/// the rules table on the left, the form on the right, one primary `Save ⌘⏎`.
struct RulesSheet: View {
    @Environment(Session.self) private var session
    @Environment(\.dismiss) private var dismiss
    @State private var draft = BreakpointRules()
    @State private var selected: UUID?
    @State private var testResult: String?

    private var current: Binding<BreakpointRule>? {
        guard let selected, let index = draft.rules.firstIndex(where: { $0.id == selected }) else { return nil }
        return $draft.rules[index]
    }

    private var canSave: Bool { draft.rules.allSatisfy { $0.validationError == nil } }

    var body: some View {
        VStack(spacing: 0) {
            Text("Edit Breakpoint Rules")
                .font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold))
                .foregroundStyle(Tok.Ink.primary.color)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, Space.lg).padding(.top, Space.xl).padding(.bottom, Space.md)
            Rule()
            HStack(spacing: 0) {
                table
                VRule()
                form
            }
            Rule()
            HStack(spacing: Space.md) {
                Text(draft.rules.isEmpty ? "No rules — every request pauses while intercept is armed." : draft.armedNotice)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                Spacer()
                FlatButton("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                PrimaryButton("Save", hint: "⌘⏎") { save() }
                    .disabled(!canSave)
                    .keyboardShortcut(.return, modifiers: .command)
            }
            .padding(Space.lg)
        }
        // Two scroll views (the table and the grouped form) share this sheet, so
        // `fitsContent` has no single content height to follow: a fixed height.
        .frame(width: 640, height: 440)
        .background(Tok.Ground.surface.color)
        .onAppear {
            draft = session.breakpointRules
            selected = draft.rules.first?.id
        }
    }

    private var table: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("RULES").font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
                .foregroundStyle(Tok.Ink.tertiary.color)
                .padding(.horizontal, Space.lg).padding(.top, Space.md).padding(.bottom, Space.sm)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(draft.rules) { rule in
                        Button { selected = rule.id; testResult = nil } label: {
                            HStack(spacing: Space.sm) {
                                Toggle("", isOn: Binding(
                                    get: { rule.enabled },
                                    set: { on in if let i = draft.rules.firstIndex(where: { $0.id == rule.id }) { draft.rules[i].enabled = on } }))
                                    .toggleStyle(.checkbox).labelsHidden()
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(rule.name.isEmpty ? "Untitled rule" : rule.name)
                                        .font(Tok.Face.ui(Tok.Typography.Size.md, rule.id == selected ? .medium : .regular))
                                        .foregroundStyle(Tok.Ink.primary.color)
                                    Text(rule.url.isEmpty ? "—" : rule.url).font(Tok.Face.data(Tok.Typography.Size.xs))
                                        .foregroundStyle(rule.validationError == nil ? Tok.Ink.tertiary.color : Tok.Intercept.deep.color)
                                        .lineLimit(1)
                                }
                                Spacer()
                                if let flag = rule.flag {
                                    RoundedRectangle(cornerRadius: 2).fill(Color(nsColor: flag.color)).frame(width: 6, height: 16) // grid: ok mark swatch 6×16 (foundation §2.7)
                                }
                            }
                            .padding(.horizontal, Space.lg)
                            .frame(height: Tok.Size.Row.comfortable)
                            .background(rule.id == selected ? Tok.Ground.active.color : .clear)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            Rule()
            HStack(spacing: Space.sm) {
                FlatButton("Add Rule", symbol: "plus") {
                    let rule = BreakpointRule(name: "", url: "*")
                    draft.rules.append(rule)
                    selected = rule.id
                }
                FlatButton("Remove", symbol: "minus") {
                    draft.rules.removeAll { $0.id == selected }
                    selected = draft.rules.first?.id
                }
                .disabled(selected == nil)
            }
            .padding(Space.sm)
        }
        .frame(width: 240)
        .background(Tok.Ground.page.color)
    }

    @ViewBuilder private var form: some View {
        if let rule = current {
            Form {
                TextField("Name", text: rule.name, prompt: Text("Login requests"))
                HStack {
                    TextField("URL", text: rule.url, prompt: Text(rule.wrappedValue.matching == .wildcard ? "*/api/auth/*" : "^https://.*/login$"))
                        .font(Tok.Face.data(Tok.Typography.Size.md))
                    Picker("", selection: rule.matching) {
                        ForEach(BreakpointRule.Matching.allCases, id: \.self) { Text($0.title).tag($0) }
                    }
                    .labelsHidden().frame(width: 112)
                }
                Picker("Method", selection: rule.method) {
                    Text("Any").tag("")
                    ForEach(ComposeDraft.methods, id: \.self) { Text($0).tag($0) }
                }
                LabeledContent("Run on") {
                    HStack(spacing: Space.lg) {
                        Toggle("Request", isOn: rule.onRequest)
                        Toggle("Response", isOn: rule.onResponse)
                    }
                    .toggleStyle(.checkbox)
                }
                Picker("Flag", selection: rule.flag) {
                    Text("None").tag(MarkColor?.none)
                    ForEach(MarkColor.allCases, id: \.self) { Text($0.title).tag(MarkColor?.some($0)) }
                }
                LabeledContent("Test your rule") {
                    HStack(spacing: Space.sm) {
                        Button("Test Against List") {
                            let n = draft.matchCount(of: rule.wrappedValue, in: session.rows)
                            testResult = "\(n) of \(session.rows.count) flows match"
                        }
                        if let testResult { Text(testResult).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color) }
                    }
                }
                if let error = rule.wrappedValue.validationError {
                    Text(error).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Intercept.deep.color)
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
        } else {
            VStack(spacing: Space.sm) {
                Text("No rule selected").font(Tok.Face.ui(Tok.Typography.Size.base, .medium)).foregroundStyle(Tok.Ink.primary.color)
                Text("Add a rule to pause only matching requests.").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func save() {
        session.setBreakpointRules(draft)
        dismiss()
    }
}
