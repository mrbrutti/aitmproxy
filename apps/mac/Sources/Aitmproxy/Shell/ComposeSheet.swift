import AitmproxyKit
import SwiftUI

/// Compose (foundation §2.7 "Compose / repeat"; S-042–S-044): history on the
/// left; method, URL, Headers · Query · Body tabs, templates, Import cURL by
/// pasting; one primary `Send ⌘⏎`. Out-of-scope hosts cannot be sent.
struct ComposeSheet: View {
    @Environment(Session.self) private var session
    @Environment(\.dismiss) private var dismiss
    @State private var tab: Tab = .headers
    @State private var importedFromCurl = false
    @State private var unknownFlags: [String] = []
    @State private var sending = false
    @FocusState private var urlFocused: Bool

    enum Tab: String, CaseIterable { case headers = "Headers", query = "Query", body = "Body" }

    private var error: String? { session.composeDraft.validationError(scope: session.scopeHosts) }

    var body: some View {
        @Bindable var session = session
        HStack(spacing: 0) {
            history
            VRule()
            VStack(alignment: .leading, spacing: Space.md) {
                HStack(spacing: Space.md) {
                    Text("Compose Request").font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold))
                    if importedFromCurl {
                        Text("Imported from cURL")
                            .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                            .foregroundStyle(Tok.Ink.primary.color)
                            .padding(.horizontal, Tok.Metric.gapTight)
                            .frame(height: Tok.Metric.countChip)
                            .background(Tok.Ground.raised.color, in: Capsule())
                    }
                    Spacer()
                    templates
                }
                HStack(spacing: Space.sm) {
                    FlatMenu(title: session.composeDraft.method, width: 96) {
                        ForEach(ComposeDraft.methods, id: \.self) { m in Button(m) { session.composeDraft.method = m } }
                    }
                    TextField("https://host/path?query", text: $session.composeDraft.url)
                        .textFieldStyle(.plain)
                        .font(Tok.Face.data(Tok.Typography.Size.md))
                        .padding(.horizontal, Space.sm)
                        .frame(height: Tok.Size.controlLg)
                        .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                        .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
                        .focused($urlFocused)
                        .onChange(of: session.composeDraft.url) { importCurlIfPasted(session.composeDraft.url) }
                }
                FlatSegment(options: Tab.allCases.map { ($0, $0.rawValue) }, selection: $tab)
                Group {
                    switch tab {
                    case .headers:
                        editor($session.composeDraft.headersText, placeholder: "name: value, one per line")
                            .onChange(of: session.composeDraft.headersText) { importCurlIfPasted(session.composeDraft.headersText) }
                    case .query:
                        if session.composeDraft.queryItems.isEmpty {
                            Hint(text: "No query — add ?name=value to the URL").frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                        } else {
                            HeaderTable(headers: session.composeDraft.queryItems.map { .init($0.0, $0.1) })
                        }
                    case .body:
                        VStack(alignment: .leading, spacing: Space.sm) {
                            FlatSegment(options: ComposeDraft.BodyKind.allCases.map { ($0, $0.title) }, selection: $session.composeDraft.bodyKind)
                            editor($session.composeDraft.body, placeholder: "Body")
                                .onChange(of: session.composeDraft.body) { importCurlIfPasted(session.composeDraft.body) }
                        }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                if !unknownFlags.isEmpty {
                    Text("Ignored cURL flags: \(unknownFlags.joined(separator: " "))")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                }
                HStack(spacing: Space.md) {
                    if let error {
                        Text(error).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Intercept.deep.color)
                    }
                    Spacer()
                    FlatButton("Cancel") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    PrimaryButton(sending ? "Sending…" : "Send", hint: "⌘⏎") { send() }
                        .disabled(error != nil || sending)
                        .keyboardShortcut(.return, modifiers: .command)
                        .help(error ?? "Send through the proxy (⌘⏎)")
                }
            }
            .padding(Space.xl)
        }
        .frame(width: 880, height: 560)
        .background(Tok.Ground.surface.color)
        .onAppear { urlFocused = session.composeDraft.url.isEmpty || session.composeDraft.url.hasSuffix("://") }
    }

    private var templates: some View {
        @Bindable var session = session
        return FlatMenu(title: "Template", width: 120) {
            ForEach(ComposeDraft.Template.allCases, id: \.self) { template in
                Button(template.rawValue) {
                    session.composeDraft = template.draft
                    importedFromCurl = false
                    unknownFlags = []
                }
                .disabled(!template.isAvailable)
            }
            Divider()
            Button("Import cURL from Clipboard") {
                if let text = NSPasteboard.general.string(forType: .string) { importCurlIfPasted(text, force: true) }
            }
        }
    }

    private var history: some View {
        @Bindable var session = session
        return VStack(alignment: .leading, spacing: 0) {
            Text("HISTORY").font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
                .foregroundStyle(Tok.Ink.tertiary.color)
                .padding(.horizontal, Space.lg).padding(.top, Space.xl).padding(.bottom, Space.sm)
            if session.composeHistory.entries.isEmpty {
                Text("Nothing sent yet").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                    .padding(.horizontal, Space.lg)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(session.composeHistory.entries.enumerated()), id: \.offset) { _, entry in
                        Button {
                            session.composeDraft = entry
                            importedFromCurl = false
                        } label: {
                            HStack(spacing: Space.sm) {
                                Badge(text: entry.method, pair: HTTPMethod(entry.method).badge)
                                Text(entry.url).font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.primary.color)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                            .padding(.horizontal, Space.lg)
                            .frame(height: Tok.Size.Row.default)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help(entry.sentAt.map { "Sent \(Format.time($0))" } ?? "")
                    }
                }
            }
        }
        .frame(width: 260)
        .background(Tok.Ground.page.color)
    }

    private func editor(_ text: Binding<String>, placeholder: String) -> some View {
        TextEditor(text: text)
            .font(Tok.Face.data(Tok.Typography.Size.md))
            .scrollContentBackground(.hidden)
            .padding(Space.sm)
            .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
            .overlay(alignment: .topLeading) {
                if text.wrappedValue.isEmpty {
                    Text(placeholder).font(Tok.Face.data(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
                        .padding(Space.md).allowsHitTesting(false)
                }
            }
    }

    /// Paste a `curl …` command into any field and the whole draft fills from it (S-043).
    private func importCurlIfPasted(_ text: String, force: Bool = false) {
        guard force || text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("curl ") else { return }
        guard let imported = ComposeDraft.from(curl: text) else { return }
        session.composeDraft = imported.draft
        unknownFlags = imported.unknownFlags
        importedFromCurl = true
    }

    private func send() {
        sending = true
        session.sendCompose { ok in
            sending = false
            if ok { dismiss() }
        }
    }
}
