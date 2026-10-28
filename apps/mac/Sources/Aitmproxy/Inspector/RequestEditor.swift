import AitmproxyKit
import SwiftUI

/// The paused request as editable raw bytes (S-038): an `NSTextView` with
/// the syntax colours; edited lines take the amber edge; the footer counts
/// the pending edits and offers Revert.
struct RawRequestEditor: View {
    @Environment(Session.self) private var session
    var row: FlowRow
    var detail: FlowDetail
    @State private var text = ""
    @State private var parseError: RawHTTP.ParseError?

    private var draft: HTTPMessage { session.editDrafts[row.id] ?? detail.request }

    var body: some View {
        VStack(spacing: 0) {
            CodeTextView(text: text, contentType: "message/http", bodySize: session.density.bodySize, editable: true) { new in
                text = new
                do {
                    let message = try RawHTTP.parse(new)
                    parseError = nil
                    session.updateDraft(row.id, message)
                } catch {
                    parseError = error as? RawHTTP.ParseError ?? RawHTTP.ParseError(line: 1, message: error.localizedDescription)
                }
            }
            Rule(color: Tok.Line.rule)
            HStack(spacing: Space.md) {
                if let parseError {
                    Text("Could not parse the request: \(parseError.description)")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Intercept.deep.color)
                } else {
                    let n = session.pendingEditCount(row.id)
                    Text(n == 0 ? "No edits · Resume forwards the request as it arrived"
                         : "\(n) edit\(n == 1 ? "" : "s") pending · Apply & Resume sends flow.mutate then flow.resume")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                }
                Spacer()
                if session.editDrafts[row.id] != nil {
                    FlatButton("Revert to Original") {
                        session.revertDraft(row.id)
                        text = RawHTTP.render(detail.originalRequest ?? detail.request)
                        parseError = nil
                    }
                }
            }
            .padding(.horizontal, Space.md)
            .frame(height: Tok.Size.control)
        }
        .onAppear { text = RawHTTP.render(draft) }
        .onChange(of: row.id) { text = RawHTTP.render(draft); parseError = nil }
        // The Headers table (or a revert) changed the draft: re-render unless the text already says the same.
        .onChange(of: session.editDrafts[row.id]) {
            if (try? RawHTTP.parse(text)) != draft { text = RawHTTP.render(draft); parseError = nil }
        }
    }
}

/// Headers of a paused request as an editable table (S-037): name and value
/// fields per row, ✕ removes, `Add Header` appends.
struct EditableHeaderTable: View {
    @Environment(Session.self) private var session
    var row: FlowRow
    var detail: FlowDetail

    private var draft: HTTPMessage { session.editDrafts[row.id] ?? detail.request }
    private var originalNames: Set<String> { Set((detail.originalRequest ?? detail.request).headers.map(\.name)) }

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                ForEach(Array(draft.headers.enumerated()), id: \.offset) { index, header in
                    HStack(spacing: Space.md) {
                        TextField("name", text: binding(index, \.name))
                            .textFieldStyle(.plain)
                            .font(Tok.Face.data(Tok.Typography.Size.md))
                            .foregroundStyle(Tok.Syntax.key.color)
                            .frame(width: 180)
                        TextField("value", text: binding(index, \.value))
                            .textFieldStyle(.plain)
                            .font(Tok.Face.data(Tok.Typography.Size.md))
                            .foregroundStyle(Tok.Ink.primary.color)
                        Button {
                            var m = draft
                            m.headers.remove(at: index)
                            session.updateDraft(row.id, m)
                        } label: {
                            Image(systemName: "minus.circle").font(.system(size: 13)).foregroundStyle(Tok.Ink.tertiary.color)
                                .frame(width: Tok.Size.control, height: Tok.Size.control).contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help("Remove this header")
                    }
                    .padding(.horizontal, Space.md)
                    .frame(minHeight: Tok.Size.Row.dense)
                    .overlay(alignment: .leading) {
                        if !originalNames.contains(header.name) || isChanged(header) {
                            Rectangle().fill(Tok.Intercept.base.color).frame(width: 2)
                        }
                    }
                    .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
                }
                HStack {
                    FlatButton("Add Header", symbol: "plus") {
                        var m = draft
                        m.headers.append(.init("x-", ""))
                        session.updateDraft(row.id, m)
                    }
                    Spacer()
                }
                .padding(.horizontal, Space.sm)
            }
        }
    }

    private func isChanged(_ header: HTTPMessage.Header) -> Bool {
        (detail.originalRequest ?? detail.request).header(header.name) != header.value
    }

    private func binding(_ index: Int, _ key: WritableKeyPath<HTTPMessage.Header, String>) -> Binding<String> {
        Binding(
            get: { draft.headers.indices.contains(index) ? draft.headers[index][keyPath: key] : "" },
            set: { new in
                var m = draft
                guard m.headers.indices.contains(index) else { return }
                m.headers[index][keyPath: key] = key == \.name ? new.lowercased() : new
                session.updateDraft(row.id, m)
            })
    }
}
