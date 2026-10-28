import AitmproxyKit
import SwiftUI

/// Shared between `SSEView` and the tab bar's `SSEControls`.
@Observable
final class SSEViewState {
    /// Show the OpenAI-style deltas concatenated instead of the event rows.
    var merged = false
}

/// A `text/event-stream` body as an event list (S-025): Time · ID · Event ·
/// Data, newest at the bottom, JSON data pretty-printed, comment rows
/// dimmed. New rows append without moving the operator's scroll unless they
/// were already at the bottom, in which case the list follows.
struct SSEView: View {
    var message: HTTPMessage
    var bodySize: CGFloat = Tok.Typography.Size.md
    var state: SSEViewState

    @State private var atBottom = true

    private static let columns: [(title: String, width: CGFloat?)] = [
        ("Time", 48), ("ID", 72), ("Event", 96), ("Data", nil),
    ]

    private var events: [SSEEvent] { SSE.parse(message.bodyText ?? "") }

    var body: some View {
        let events = events
        if events.isEmpty {
            Hint(text: "Waiting for events…")
                .padding(.leading, Space.md)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else if state.merged {
            merged(events)
        } else {
            list(events)
        }
    }

    private func merged(_ events: [SSEEvent]) -> some View {
        Group {
            if let text = SSE.mergedDeltas(events) {
                CodeView(lines: text.split(separator: "\n", omittingEmptySubsequences: false).map {
                    CodeLine(runs: [SyntaxRun(.plain, String($0))])
                }, footer: nil)
            } else {
                Hint(text: "No deltas to merge — the events are not OpenAI-style chunks")
                    .padding(.leading, Space.md)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
        }
    }

    private func list(_ events: [SSEEvent]) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 0, pinnedViews: .sectionHeaders) {
                    Section {
                        ForEach(events, id: \.order) { event in
                            EventRow(event: event, bodySize: bodySize).id(event.order)
                        }
                    } header: {
                        ColumnHeads(columns: Self.columns).background(Tok.Ground.surface.color)
                    }
                }
            }
            .onScrollGeometryChange(for: Bool.self) { geometry in
                geometry.contentOffset.y + geometry.containerSize.height >= geometry.contentSize.height - Space.xl
            } action: { _, isAtBottom in
                atBottom = isAtBottom
            }
            .onChange(of: events.count) { _, _ in
                guard atBottom, let last = events.last else { return }
                proxy.scrollTo(last.order, anchor: .bottom)
            }
        }
    }
}

/// One event: the order index where the time will go (F4), id, type, data.
private struct EventRow: View {
    var event: SSEEvent
    var bodySize: CGFloat

    var body: some View {
        let ink = event.isComment ? Tok.Ink.tertiary : Tok.Ink.primary
        HStack(alignment: .firstTextBaseline, spacing: Space.md) {
            Text("\(event.order + 1)")
                .foregroundStyle(Tok.Syntax.lineNumber.color)
                .frame(width: 48, alignment: .trailing)
            Text(event.id ?? Format.dash)
                .foregroundStyle(event.id == nil ? Tok.Ink.tertiary.color : ink.color)
                .lineLimit(1)
                .frame(width: 72, alignment: .leading)
            Text(event.isComment ? "comment" : event.event ?? "message")
                .foregroundStyle(event.isComment || event.event == nil ? Tok.Ink.tertiary.color : Tok.Syntax.key.color)
                .lineLimit(1)
                .frame(width: 96, alignment: .leading)
            Text(dataText)
                .foregroundStyle(ink.color)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .font(Tok.Face.data(bodySize))
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.xs)
        .frame(minHeight: Tok.Size.Row.dense)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(event.isComment ? "comment" : "event \(event.event ?? "message")")
        .accessibilityValue("data \(event.data)")
    }

    private var dataText: String {
        guard !event.isComment, let pretty = JSONTree.pretty(Data(event.data.utf8)) else { return event.data }
        return pretty
    }
}

/// The tab bar's trailing control for the SSE tab: a flat "Merged" toggle.
struct SSEControls: View {
    var state: SSEViewState

    var body: some View {
        Button {
            state.merged.toggle()
        } label: {
            Text("Merged")
                .font(Tok.Face.ui(Tok.Typography.Size.sm, state.merged ? .medium : .regular))
                .foregroundStyle(state.merged ? Tok.Ink.primary.color : Tok.Ink.secondary.color)
                .padding(.horizontal, Space.sm)
                .frame(height: Tok.Metric.chip)
                .background(state.merged ? Tok.Ground.active.color : .clear,
                            in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Concatenate the OpenAI-style deltas into one text")
        .accessibilityAddTraits(state.merged ? .isSelected : [])
    }
}
