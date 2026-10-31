import AitmproxyKit
import SwiftUI

/// The paused message as editable raw bytes (S-038): an `NSTextView` with
/// the syntax colours; edited lines take the amber edge; the footer counts
/// the pending edits and offers Revert. `phase` picks the message: the request,
/// or the response of a flow parked at the response head (S-041).
struct RawRequestEditor: View {
    @Environment(Session.self) private var session
    var row: FlowRow
    var detail: FlowDetail
    var phase: InterceptPhase = .request
    @State private var text = ""
    @State private var parseError: RawHTTP.ParseError?

    /// The message as the proxy holds it now, and the copy Revert goes back to.
    private var target: HTTPMessage { phase == .response ? detail.response ?? detail.request : detail.request }
    private var original: HTTPMessage { phase == .response ? target : detail.originalRequest ?? detail.request }
    private var draft: HTTPMessage { session.currentDraft(row.id) ?? target }
    private var noun: String { phase.rawValue }

    var body: some View {
        // The editor is clipped to its frame and the footer is a bottom safe-area
        // inset, so in a short inspector the lines scroll under the footer instead
        // of the footer painting over them.
        CodeTextView(text: text, contentType: "message/http", bodySize: session.density.bodySize, editable: true,
                     onTextChange: { new in
            text = new
            do {
                let message = try RawHTTP.parse(new)
                parseError = nil
                session.updateDraft(row.id, message)
            } catch {
                parseError = error as? RawHTTP.ParseError ?? RawHTTP.ParseError(line: 1, message: error.localizedDescription)
            }
        })
        .frame(minHeight: 60)
        .clipped()
        .safeAreaInset(edge: .bottom, spacing: 0) { footer }
        .onAppear { text = RawHTTP.render(draft) }
        .onChange(of: row.id) { text = RawHTTP.render(draft); parseError = nil }
        // The Headers table (or a revert) changed the draft: re-render unless the text already says the same.
        .onChange(of: session.editDrafts[row.id]) {
            if (try? RawHTTP.parse(text)) != draft { text = RawHTTP.render(draft); parseError = nil }
        }
    }

    private var footer: some View {
        VStack(spacing: 0) {
            Rule(color: Tok.Line.rule)
            HStack(spacing: Space.md) {
                if let parseError {
                    Text("Could not parse the \(noun): \(parseError.description)")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Intercept.deep.color)
                } else if !session.removedHeaders(row.id).isEmpty {
                    // A deleted header can't be applied yet (flow.mutate has no removal
                    // form); say so plainly rather than let the operator think it was removed.
                    let removed = session.removedHeaders(row.id)
                    Text("Header removal needs a core follow-up — \(removed.joined(separator: ", ")) will still be sent")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Intercept.deep.color)
                        .lineLimit(1).truncationMode(.middle)
                        .accessibilityIdentifier("removal-warning")
                        .accessibilityValue(removed.joined(separator: ","))
                } else {
                    let n = session.pendingEditCount(row.id)
                    Text(n == 0 ? "No edits yet — Resume forwards the \(noun) unchanged."
                         : "\(n) edit\(n == 1 ? "" : "s") pending — Apply & Resume sends your changes, then continues.")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                        // Deterministic read-back of the pending-edit count (CUA / a11y).
                        .accessibilityIdentifier("edit-status")
                        .accessibilityValue("\(n)")
                }
                Spacer()
                if session.currentDraft(row.id) != nil {
                    FlatButton("Revert to Original") {
                        session.revertDraft(row.id)
                        text = RawHTTP.render(original)
                        parseError = nil
                    }
                }
            }
            .padding(.horizontal, Space.md)
            .frame(height: Tok.Size.control)
        }
        .background(Tok.Ground.surface.color)
    }
}

/// Headers of a paused message as an editable table (S-037): name and value
/// fields per row, ✕ removes, `Add Header` appends. `phase` picks the request
/// or, for a flow parked at the response head, the response (S-041).
struct EditableHeaderTable: View {
    @Environment(Session.self) private var session
    var row: FlowRow
    var detail: FlowDetail
    var phase: InterceptPhase = .request

    private var target: HTTPMessage { phase == .response ? detail.response ?? detail.request : detail.request }
    private var original: HTTPMessage { phase == .response ? target : detail.originalRequest ?? detail.request }
    private var draft: HTTPMessage { session.currentDraft(row.id) ?? target }
    private var originalNames: Set<String> { Set(original.headers.map(\.name)) }

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
                        // Header removal has no flow.mutate form yet (core follow-up),
                        // so the ✕ is disabled rather than silently dropping the action.
                        Button {} label: {
                            Image(systemName: "minus.circle").font(.system(size: 13)).foregroundStyle(Tok.Ink.tertiary.color)
                                .frame(width: Tok.Size.control, height: Tok.Size.control).contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .disabled(true)
                        .help("Removing a header needs a core follow-up (flow.mutate has no removal form yet); you can edit a value or add a header")
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
        original.header(header.name) != header.value
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
