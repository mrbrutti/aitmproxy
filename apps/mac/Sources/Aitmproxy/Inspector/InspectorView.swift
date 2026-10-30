import AitmproxyKit
import SwiftUI

/// The inspector (foundation §2.7): a 40px summary strip over Request |
/// Response panes, each with a title, plain tabs and a body viewer.
struct InspectorView: View {
    @Environment(Session.self) private var session

    var body: some View {
        // GeometryReader has no intrinsic size: a wide tab bar or a tall viewer
        // can never grow the window; the split view decides the inspector's size.
        GeometryReader { _ in
            VStack(spacing: 0) {
                if let row = session.focusedRow {
                    SummaryStrip(row: row, detail: session.focusedDetail)
                    Rule()
                    if row.kind == .websocket {
                        // A WebSocket is a message stream, not a request/response pair (S-045).
                        // `.id(row.id)` gives each flow a fresh frame selection and filter.
                        WebSocketInspector(row: row, detail: session.focusedWSDetail)
                            .id(row.id).environment(session).themed()
                    } else if row.kind == .l4 {
                        // A raw-L4 flow is a packet log + craft/inject, not request/response.
                        L4Inspector(row: row, detail: session.focusedL4Detail)
                            .id(row.id).environment(session).themed()
                    } else {
                        // A real split: the operator drags the divider; the position is remembered.
                        SplitPane(axis: .vertical, firstMinimum: 240, secondMinimum: 240, initialSecondFraction: 0.5,
                                  autosaveName: "inspector.panes") {
                            RequestPane(row: row, detail: session.focusedDetail).environment(session).themed()
                        } second: {
                            ResponsePane(row: row, detail: session.focusedDetail).environment(session).themed()
                        }
                    }
                } else {
                    EmptyInspector()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(Tok.Ground.surface.color)
    }
}

struct EmptyInspector: View {
    var body: some View {
        VStack(spacing: Space.sm) {
            Text("Nothing selected").font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
            Text("Select a flow to inspect it, or press ↑ ↓.").font(Tok.Face.ui(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.tertiary.color)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// `[POST] [200 OK] https://host/path  ⧉   HTTP/2 · TLS 1.3 · h2 · req 186 B · client …`
struct SummaryStrip: View {
    var row: FlowRow
    var detail: FlowDetail?

    var body: some View {
        HStack(spacing: Tok.Metric.padInner) {
            Badge(text: row.method.label, pair: row.method.badge)
            statusPill
            HStack(spacing: 0) {
                Text(row.site).foregroundStyle(Tok.Ink.primary.color)
                Text(row.path).foregroundStyle(Tok.Ink.link.color)
                if let query = row.query { Text("?\(query)").foregroundStyle(Tok.Ink.tertiary.color) }
            }
            .font(Tok.Face.data(Tok.Typography.Size.md))
            .lineLimit(1)
            .truncationMode(.middle)
            // Deterministic read-back of which flow the inspector is showing (CUA / a11y).
            .accessibilityElement(children: .ignore)
            .accessibilityIdentifier("inspector-url")
            .accessibilityValue(row.url)
            if let detail {
                ExportMenu(detail: detail, row: row)
            } else {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(row.url, forType: .string)
                } label: {
                    Image(systemName: Tok.Glyph.copy).font(.system(size: 12)).foregroundStyle(Tok.Ink.secondary.color)
                        .frame(width: Space.xxl, height: Space.xxl)
                }
                .buttonStyle(.plain)
                .help("Copy URL")
            }
            Spacer(minLength: Space.sm)
            HStack(spacing: Tok.Metric.gapMeta) {
                if let c = detail?.connection {
                    Text([c.httpVersion, c.tlsVersion, c.alpn].compactMap { $0 }.joined(separator: " · "))
                }
                meta("req", Format.bytes(row.requestBytes))
                if row.responseBytes != nil { meta("resp", Format.bytes(row.responseBytes)) }
                if let d = row.duration { meta("", Format.duration(d)) }
                if let client = detail?.connection.clientAddress { meta("client", client) }
                Text(row.inScope ? "in scope" : "out of scope")
                    .foregroundStyle(row.inScope ? Tok.Ink.secondary.color : Tok.Intercept.deep.color)
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.secondary.color)
            .lineLimit(1)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.inspectorHeader)
    }

    private func meta(_ label: String, _ value: String) -> some View {
        HStack(spacing: 4) {
            if !label.isEmpty { Text(label) }
            Text(value).fontWeight(.medium).foregroundStyle(Tok.Ink.primary.color)
                .font(Tok.Face.data(Tok.Typography.Size.sm, .medium))
        }
    }

    @ViewBuilder private var statusPill: some View {
        switch row.state {
        case .paused:
            Badge(text: "Paused · request", pair: ColorPair(fg: Tok.Intercept.deep, bg: Tok.Intercept.tint), uppercase: false)
        case .killed:
            Badge(text: "Killed", pair: ColorPair(fg: Tok.Status.killed, bg: Tok.Ground.raised), uppercase: false)
        case .pending:
            Badge(text: "Pending", pair: ColorPair(fg: Tok.Status.pending, bg: Tok.Intercept.tint), uppercase: false)
        case .failed:
            Badge(text: "Error", pair: Tok.Method.delete, uppercase: false)
        case .complete:
            if let status = row.status, let cls = StatusClass(status) {
                Badge(text: "\(status) \(StatusText.reason(status))".trimmingCharacters(in: .whitespaces), pair: cls.pill)
            }
        }
    }
}

/// A tinted pill: 18px, radius 4, 11/600 mono.
struct Badge: View {
    var text: String
    var pair: ColorPair
    var uppercase = true

    var body: some View {
        Text(uppercase ? text.uppercased() : text)
            .font(Tok.Face.data(Tok.Typography.Size.xs, .semibold))
            .foregroundStyle(pair.fg.color)
            .padding(.horizontal, Tok.Metric.gapTight)
            .frame(height: Tok.Size.badge)
            .background(pair.bg.color, in: RoundedRectangle(cornerRadius: Tok.Radius.badge))
            .lineLimit(1)
            .fixedSize()
    }
}

/// Pane title 16/600 + plain tabs; the active tab in the accent with a 2px underline on the shared rule.
struct PaneTabs<Tab: Hashable & CustomStringConvertible, Trailing: View>: View {
    var title: String
    var tabs: [Tab]
    @Binding var selected: Tab
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(spacing: Space.sm) {
            // The tabs scroll when the pane is narrow; they never wrap and never widen the window.
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    Text(title).font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold)).foregroundStyle(Tok.Ink.primary.color)
                        .padding(.trailing, Tok.Metric.padInner)
                        .fixedSize()
                    ForEach(tabs, id: \.self) { tab in
                        let on = tab == selected
                        Button { selected = tab } label: {
                            Text(tab.description)
                                .font(Tok.Face.ui(Tok.Typography.Size.md, on ? .medium : .regular))
                                .foregroundStyle(on ? Palette.accentText : Tok.Ink.secondary.color)
                                .lineLimit(1)
                                .fixedSize()
                                .padding(.horizontal, Tok.Metric.gapTight)
                                .frame(height: Tok.Size.tabBar)
                                .overlay(alignment: .bottom) {
                                    if on { Rectangle().fill(Palette.accent).frame(height: 2).padding(.horizontal, Tok.Metric.gapTight) }
                                }
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                    Button {} label: {
                        Text("+").font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
                            .padding(.horizontal, Tok.Metric.gapTight).frame(height: Tok.Size.tabBar)
                    }
                    .buttonStyle(.plain)
                    .help("Add viewer")
                }
            }
            .frame(height: Tok.Size.tabBar)
            Spacer(minLength: 0)
            trailing
                .layoutPriority(1)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.tabBar)
        .frame(minWidth: 0)
        .overlay(alignment: .bottom) { Rule() }
    }
}

enum RequestTab: String, CaseIterable, CustomStringConvertible {
    case headers = "Headers", cookies = "Cookies", query = "Query", body = "Body", raw = "Raw", summary = "Summary",
         timing = "Timing", connection = "Connection"
    var description: String { rawValue }
}

enum ResponseTab: String, CaseIterable, CustomStringConvertible {
    case headers = "Headers", setCookie = "Set-Cookie", body = "Body", raw = "Raw", json = "JSON", diff = "Diff"
    var description: String { rawValue }
}

/// Lines for the Raw and text Body viewers, built in one place.
enum BodyLines {
    static func body(_ message: HTTPMessage) -> [CodeLine] {
        guard let text = pretty(message), !text.isEmpty else { return [] }
        return text.split(separator: "\n", omittingEmptySubsequences: false).map {
            CodeLine(runs: Syntax.runs(for: String($0), contentType: message.contentType))
        }
    }

    /// JSON pretty-printed with key order kept; everything else as UTF-8.
    static func pretty(_ message: HTTPMessage) -> String? {
        guard let data = message.body else { return nil }
        if (message.contentType ?? "").lowercased().contains("json"), let pretty = JSONTree.pretty(data) { return pretty }
        return message.bodyText
    }

    static func raw(_ message: HTTPMessage, original: HTTPMessage? = nil) -> [CodeLine] {
        var lines: [CodeLine] = [CodeLine(runs: Syntax.startLine(message.startLine))]
        let originalNames = Set(original?.headers.map(\.name) ?? [])
        for header in message.headers {
            let edited = original != nil && !originalNames.contains(header.name)
            lines.append(CodeLine(runs: Syntax.header(line: "\(header.name): \(header.value)"), edited: edited, current: edited))
        }
        lines.append(CodeLine(runs: []))
        lines += body(message)
        return lines
    }
}

/// The Body tab's state: format, rendered toggle, find, paging — one per pane.
@Observable
final class BodyViewState {
    var format: BodyFormat = .auto
    var rendered = false
    var find = FindState()
    var findShown = false
}

/// Picks the viewer a body needs (foundation §2.7 "Body viewers"): images,
/// protobuf and MessagePack have their own; event streams list events;
/// everything else is the pretty viewer with its format picker.
struct BodyHost: View {
    var message: HTTPMessage
    var extent: BodyExtent?
    var bodySize: CGFloat
    var sseState: SSEViewState
    @Bindable var state: BodyViewState
    var onLoadMore: (() async throws -> Void)?

    var body: some View {
        if let data = message.body, !data.isEmpty {
            switch (state.format, BodyKind.detect(contentType: message.contentType, data: data)) {
            case (.auto, .image): ImageBodyView(data: data, contentType: message.contentType)
            case (.auto, .protobuf): ProtobufBodyView(data: data, bodySize: bodySize)
            case (.auto, .messagepack): MessagePackBodyView(data: data, bodySize: bodySize)
            default:
                if state.format == .auto, (message.contentType ?? "").lowercased().hasPrefix("text/event-stream") {
                    SSEView(message: message, bodySize: bodySize, state: sseState)
                } else {
                    PrettyBodyView(message: message, format: $state.format, extent: extent, bodySize: bodySize,
                                   find: state.findShown ? state.find : nil, rendered: $state.rendered, onLoadMore: onLoadMore)
                }
            }
        } else {
            Hint(text: "No body").padding(.leading, Space.md).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }

    /// What the tab bar's trailing slot shows for this body.
    @ViewBuilder static func controls(message: HTTPMessage, extent: BodyExtent?, state: BodyViewState, sseState: SSEViewState) -> some View {
        @Bindable var state = state
        if let data = message.body, !data.isEmpty {
            let kind = BodyKind.detect(contentType: message.contentType, data: data)
            let detected = BodyFormat.detect(message)
            HStack(spacing: Space.xs) {
                if state.findShown { FindBar(state: state.find, isPresented: $state.findShown) }
                if let extent, extent.isTruncated { TruncatedChip(extent: extent) }
                if case .image = kind, state.format == .auto {
                    ImageControls(data: data, contentType: message.contentType)
                } else if state.format == .auto, (message.contentType ?? "").lowercased().hasPrefix("text/event-stream") {
                    SSEControls(state: sseState)
                } else {
                    if state.format.resolve(for: message).isRenderable { RenderedToggle(isOn: $state.rendered) }
                    FormatPicker(selection: $state.format, detected: detected)
                    Button { state.findShown.toggle() } label: {
                        Image(systemName: Tok.Glyph.search).font(.system(size: 12))
                            .foregroundStyle(state.findShown ? Tok.Ink.primary.color : Tok.Ink.secondary.color)
                            .frame(width: Space.xxl, height: Space.xxl).contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help("Find in body (⌥⌘F)")
                }
            }
        }
    }
}

struct MultipartList: View {
    var parts: [MultipartPart]
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.md) {
                ForEach(Array(parts.enumerated()), id: \.offset) { index, part in
                    VStack(alignment: .leading, spacing: Space.xs) {
                        Text("Part \(index + 1)\(part.name.map { " · \($0)" } ?? "")\(part.filename.map { " · \($0)" } ?? "")")
                            .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium)).foregroundStyle(Tok.Ink.secondary.color)
                        HeaderTable(headers: part.headers)
                        if let text = String(data: part.body, encoding: .utf8) {
                            Text(text).font(Tok.Face.data(Tok.Typography.Size.md)).textSelection(.enabled)
                        } else {
                            Text(Format.bytes(Int64(part.body.count))).font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                        }
                    }
                }
            }
            .padding(Space.md)
        }
    }
}

struct RequestPane: View {
    @Environment(Session.self) private var session
    var row: FlowRow
    var detail: FlowDetail?
    @State private var sseState = SSEViewState()
    @State private var bodyState = BodyViewState()
    private var tab: RequestTab { session.requestTab }
    private var bodySize: CGFloat { session.density.bodySize }

    var body: some View {
        @Bindable var session = session
        VStack(spacing: 0) {
            PaneTabs(title: "Request", tabs: RequestTab.allCases, selected: $session.requestTab) {
                if tab == .body, let detail {
                    BodyHost.controls(message: detail.request, extent: detail.requestBodyExtent, state: bodyState, sseState: sseState)
                } else if row.state == .paused {
                    let n = session.pendingEditCount(row.id)
                    Text(n > 0 ? "\(n) pending" : "editing").font(Tok.Face.ui(Tok.Typography.Size.sm))
                        .foregroundStyle(n > 0 ? Tok.Intercept.deep.color : Tok.Ink.tertiary.color)
                }
            }
            if let detail {
                switch tab {
                case .raw:
                    if row.state == .paused {
                        RawRequestEditor(row: row, detail: detail)
                    } else {
                        CodeView(lines: BodyLines.raw(detail.request, original: detail.originalRequest), footer: nil)
                    }
                case .headers:
                    if row.state == .paused {
                        EditableHeaderTable(row: row, detail: detail)
                    } else {
                        HeaderTable(headers: detail.request.headers)
                    }
                case .cookies: CookieTable(cookies: Cookie.cookies(in: detail.request), bodySize: bodySize)
                case .query: QueryTable(query: row.query)
                case .body: BodyHost(message: detail.request, extent: detail.requestBodyExtent, bodySize: bodySize, sseState: sseState, state: bodyState)
                case .summary:
                    HeaderTable(headers: [
                        .init("method", row.method.label), .init("url", row.url),
                        .init("request size", Format.bytes(row.requestBytes)),
                        .init("started", Format.time(row.startedAt)),
                        .init("origin", row.origin == .agent ? "agent" : row.client?.name ?? "client"),
                        .init("comment", row.comment ?? Format.dash),
                    ])
                case .timing: TimingView(timing: detail.timing, total: row.duration)
                case .connection: ConnectionTable(connection: detail.connection, tls: row.tls)
                }
            } else {
                LoadingLines()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onChange(of: session.findRequestTick) { if tab == .body { bodyState.findShown = true } }
        .onChange(of: row.id) { bodyState.format = .auto; bodyState.findShown = false }
    }
}

struct ResponsePane: View {
    @Environment(Session.self) private var session
    var row: FlowRow
    var detail: FlowDetail?
    @State private var sseState = SSEViewState()
    @State private var diffState = DiffViewState()
    @State private var bodyState = BodyViewState()
    @State private var tree: (FlowID, JSONTreeState?)?
    private var tab: ResponseTab { session.responseTab }
    private var bodySize: CGFloat { session.density.bodySize }

    /// The two selected flows, in capture order, when exactly two are selected.
    private var diffPair: (FlowDetail, FlowDetail)? {
        let chosen = session.rows.filter { session.selection.contains($0.id) }
        guard chosen.count == 2, let a = session.details[chosen[0].id], let b = session.details[chosen[1].id] else { return nil }
        return (a, b)
    }

    private var treeState: JSONTreeState? {
        if let tree, tree.0 == row.id { return tree.1 }
        return nil
    }

    var body: some View {
        @Bindable var session = session
        VStack(spacing: 0) {
            PaneTabs(title: "Response", tabs: ResponseTab.allCases, selected: $session.responseTab) {
                trailing
            }
            if let response = detail?.response {
                switch tab {
                case .headers: HeaderTable(headers: response.headers)
                case .setCookie: CookieTable(cookies: Cookie.cookies(in: response), bodySize: bodySize)
                case .body:
                    BodyHost(message: response, extent: detail?.responseBodyExtent, bodySize: bodySize, sseState: sseState,
                             state: bodyState, onLoadMore: { try await session.loadMoreBody(for: row.id) })
                case .raw: CodeView(lines: BodyLines.raw(response), footer: nil)
                case .json:
                    if let state = treeState {
                        JSONTreeView(state: state, bodySize: bodySize)
                    } else {
                        Hint(text: "Not JSON — see Body").padding(.leading, Space.md)
                            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    }
                case .diff: diff
                }
            } else if tab == .diff {
                diff
            } else if row.state == .paused, let previous = previousResponse {
                CodeView(lines: BodyLines.body(previous),
                         header: "No response yet — the request is paused. Showing the last response to this endpoint (flow 38, 11:04:12) for reference.",
                         footer: nil)
            } else if row.state == .pending || detail == nil {
                LoadingLines()
            } else {
                Text(row.state == .killed ? "Killed — no response" : "No response")
                    .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.secondary.color)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onChange(of: row.id, initial: true) { rebuildTree(); bodyState.format = .auto; bodyState.findShown = false }
        .onChange(of: detail?.response?.body) { rebuildTree() }
        .onChange(of: session.findRequestTick) { if tab == .body { bodyState.findShown = true } }
    }

    @ViewBuilder private var diff: some View {
        if let pair = diffPair {
            let result = FlowDiff.compare(pair.0, pair.1)
            DiffView(result: result, bodySize: bodySize, state: diffState)
        } else {
            DiffEmpty()
        }
    }

    @ViewBuilder private var trailing: some View {
        switch tab {
        case .json:
            if let state = treeState { JSONTreeControls(state: state) }
        case .diff:
            if let pair = diffPair { DiffControls(result: FlowDiff.compare(pair.0, pair.1), state: diffState) }
        case .body:
            if let response = detail?.response {
                BodyHost.controls(message: response, extent: detail?.responseBodyExtent, state: bodyState, sseState: sseState)
            } else if row.state == .paused {
                FormatLabel(title: "JSON")
            }
        default:
            EmptyView()
        }
    }

    private func rebuildTree() {
        guard let data = detail?.response?.body, let root = try? JSONTree.parse(data) else {
            tree = (row.id, nil)
            return
        }
        tree = (row.id, JSONTreeState(root: root))
    }

    /// Fixture-only reference while the live detail (F5) cannot look up the previous flow.
    /// Guarded by `Store.usesFixtures` so a live flow that happens to hit the fixture
    /// hostname never shows a canned "previous response".
    private var previousResponse: HTTPMessage? {
        guard Store.usesFixtures else { return nil }
        return row.authority == "auth.shop-staging.test" && row.path == "/api/auth/login" ? Fixtures.previousLoginResponse : nil
    }
}

/// The `JSON ▾` format label in the tab bar's trailing slot (the picker arrives with the pretty body viewer).
struct FormatLabel: View {
    var title: String
    var body: some View {
        HStack(spacing: 4) {
            Text("\(title) ▾")
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.primary.color)
                .padding(.horizontal, Space.sm)
                .frame(height: Space.xxl)
                .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
            Image(systemName: Tok.Glyph.search).font(.system(size: 12)).foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: Space.xxl, height: Space.xxl)
        }
    }
}

/// Grey bars at real size, no shimmer (foundation §2.8 "Loading").
struct LoadingLines: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach([0.6, 0.4, 0.5, 0.3], id: \.self) { width in
                RoundedRectangle(cornerRadius: Tok.Radius.badge).fill(Tok.Ground.raised.color).frame(height: Space.md)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .scaleEffect(x: width, anchor: .leading)
            }
            Spacer()
        }
        .padding(Space.md)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

struct DiffPlaceholder: View {
    var body: some View { DiffEmpty() }
}
