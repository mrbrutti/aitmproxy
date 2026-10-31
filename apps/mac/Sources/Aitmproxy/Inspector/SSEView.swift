import AitmproxyKit
import SwiftUI

/// Shared between `SSEView` and the tab bar's `SSEControls`.
@Observable
final class SSEViewState {
    /// Show the OpenAI-style deltas concatenated instead of the event rows.
    var merged = false
}

/// A `text/event-stream` body as a master-detail (S-025), mirroring the WebSocket
/// inspector: the top pane lists the events on one line each (# · ID · Event ·
/// preview), newest at the bottom; selecting one shows its payload in the lower
/// BodyHost (pretty JSON, text, hex), so a JSON event never inflates its row. New
/// rows append without moving the operator's scroll unless they were at the bottom.
struct SSEView: View {
    var message: HTTPMessage
    var bodySize: CGFloat = Tok.Typography.Size.md
    var state: SSEViewState

    @State private var selected = 0
    @State private var bodyState = BodyViewState()

    private var events: [SSEEvent] { SSE.parse(message.bodyText ?? "") }

    var body: some View {
        let events = events
        if events.isEmpty {
            ContentUnavailableView {
                Label("No Events", systemImage: "dot.radiowaves.left.and.right")
            } description: {
                Text("This event stream has no events yet.")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if state.merged {
            merged(events)
        } else {
            SplitPane(axis: .horizontal, firstMinimum: 120, secondMinimum: 120, initialSecondFraction: 0.4,
                      autosaveName: "inspector.sse") {
                list(events).themed()
            } second: {
                detail(events).themed()
            }
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
                        ForEach(Array(events.enumerated()), id: \.element.order) { index, event in
                            EventRow(event: event, bodySize: bodySize, isSelected: index == selected)
                                .contentShape(Rectangle())
                                .onTapGesture { selected = index }
                                .id(event.order)
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

    @ViewBuilder private func detail(_ events: [SSEEvent]) -> some View {
        let index = min(max(selected, 0), events.count - 1)
        let event = events[index]
        if event.data.isEmpty {
            Hint(text: event.isComment ? "Comment — no data" : "No data")
                .padding(.leading, Space.md)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            BodyHost(message: event.message, extent: nil, bodySize: bodySize, sseState: SSEViewState(), state: bodyState)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .onChange(of: index) { bodyState.format = .auto; bodyState.findShown = false }
        }
    }

    @State private var atBottom = true

    private static let columns: [(title: String, width: CGFloat?)] = [
        ("#", 48), ("ID", 72), ("Event", 96), ("Data", nil),
    ]
}

/// One event on a single line: #, id, type, a one-line data preview.
private struct EventRow: View {
    var event: SSEEvent
    var bodySize: CGFloat
    var isSelected: Bool

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
            Text(preview)
                .foregroundStyle(ink.color)
                .lineLimit(1)
                .truncationMode(.tail)
            Spacer(minLength: 0)
        }
        .font(Tok.Face.data(bodySize))
        .padding(.horizontal, Space.md)
        .frame(minHeight: Tok.Size.Row.dense)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(isSelected ? Tok.Ground.raised.color : .clear)
        .overlay(alignment: .leading) { if isSelected { Rectangle().fill(Palette.accent).frame(width: 2) } }
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(event.isComment ? "comment" : "event \(event.event ?? "message")")
        .accessibilityValue("data \(event.data)")
    }

    /// The data on one line: newlines collapsed so a multi-line JSON chunk is a readable preview.
    private var preview: String {
        event.data.split(whereSeparator: \.isNewline).joined(separator: " ")
    }
}

extension SSEEvent {
    /// The event payload as a synthetic HTTP message, so the body viewers render it
    /// (pretty JSON, text, hex) without new viewer code — JSON when it parses.
    var message: HTTPMessage {
        let isJSON = !isComment && JSONTree.pretty(Data(data.utf8)) != nil
        return HTTPMessage(startLine: "",
                           headers: isJSON ? [HTTPMessage.Header("content-type", "application/json")] : [],
                           body: Data(data.utf8))
    }
}

/// The tab bar's trailing control for the SSE tab: an Events / Merged segment.
struct SSEControls: View {
    @Bindable var state: SSEViewState

    var body: some View {
        FlatSegment(options: [(false, "Events"), (true, "Merged")], selection: $state.merged)
            .help("Switch between the event list and the concatenated OpenAI-style deltas")
            .accessibilityLabel("Event view")
    }
}
