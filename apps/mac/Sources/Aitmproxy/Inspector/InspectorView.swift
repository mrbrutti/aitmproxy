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
                        .gridProbe("inspector.strip", area: "inspector", edge: nil)
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
            .gridArea("inspector", inset: 0)
        }
        .background(Tok.Ground.surface.color)
    }
}

struct EmptyInspector: View {
    var body: some View {
        ContentUnavailableView {
            Label("No Flow Selected", systemImage: "square.dashed")
        } description: {
            Text("Select a flow in the list to inspect it, or press ↑ ↓.")
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
            // One concatenated Text so a single middle-truncation applies to the whole
            // URL, instead of three Texts each ellipsing on their own.
            url
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
                .accessibilityLabel("Copy URL")
            }
            Spacer(minLength: Space.sm)
            // The meta keeps its full size; the URL truncates instead of the numbers.
            HStack(spacing: Tok.Metric.gapMeta) {
                if let c = detail?.connection {
                    Text([c.httpVersion, c.tlsVersion, c.alpn].compactMap { $0 }.joined(separator: " · "))
                }
                // A WebSocket / raw-L4 flow has no request/response byte split, so those
                // columns would read "req –"; show the stream's size cues only.
                if !isStream {
                    meta("req", Format.bytes(row.requestBytes))
                    if row.responseBytes != nil { meta("resp", Format.bytes(row.responseBytes)) }
                }
                if let d = row.duration { meta("", Format.duration(d)) }
                if let client = detail?.connection.clientAddress { meta("client", client) }
                Text(row.inScope ? "in scope" : "out of scope")
                    .foregroundStyle(row.inScope ? Tok.Ink.secondary.color : Tok.Intercept.deep.color)
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.secondary.color)
            .lineLimit(1)
            .fixedSize()
            .layoutPriority(1)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.inspectorHeader)
    }

    /// A WebSocket or raw-L4 flow: a message stream, not a request/response pair.
    private var isStream: Bool { row.kind == .websocket || row.kind == .l4 }

    /// `site` + `path` + `?query` as one Text, so middle-truncation treats it as a whole.
    private var url: Text {
        var text = Text(row.site).foregroundStyle(Tok.Ink.primary.color)
            + Text(row.path).foregroundStyle(Tok.Ink.link.color)
        if let query = row.query {
            text = text + Text("?\(query)").foregroundStyle(Tok.Ink.tertiary.color)
        }
        return text
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
    /// The tab row's natural width and the width it was given; when the row is
    /// wider than its frame the overflow menu appears so no tab is unreachable.
    @State private var tabsContentWidth: CGFloat = 0
    @State private var tabsFrameWidth: CGFloat = 0

    private var tabsOverflow: Bool { tabsContentWidth > tabsFrameWidth + 1 }

    var body: some View {
        HStack(spacing: Space.sm) {
            // The title sits outside the tab scroller at its full size, so it can
            // never be scrolled away or clipped by a narrow pane.
            Text(title).font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold)).foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
                .fixedSize()
                .layoutPriority(1)
                .padding(.trailing, 2)
            // The tabs scroll when the pane is narrow; they never wrap and never widen
            // the window. The selected tab is scrolled into view from the leading edge,
            // so a late tab (JSON, Diff) can never be pushed off-screen by the trailing controls.
            ScrollViewReader { proxy in
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 2) {
                        ForEach(tabs, id: \.self) { tab in
                            tabButton(tab).id(tab)
                        }
                    }
                    .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { tabsContentWidth = $0 }
                }
                .frame(minWidth: 72, minHeight: Tok.Size.tabBar, maxHeight: Tok.Size.tabBar)
                .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { tabsFrameWidth = $0 }
                .onAppear { proxy.scrollTo(selected, anchor: .leading) }
                .onChange(of: selected) { _, tab in proxy.scrollTo(tab, anchor: .leading) }
            }
            if tabsOverflow {
                overflowMenu
            }
            Spacer(minLength: Space.sm)
            trailing
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.tabBar)
        .frame(minWidth: 0)
        .overlay(alignment: .bottom) { Rule() }
    }

    /// A flat chevron listing every tab, shown only when the tab row is wider than
    /// its frame; the selected tab carries a checkmark.
    private var overflowMenu: some View {
        Menu {
            ForEach(tabs, id: \.self) { tab in
                Button {
                    selected = tab
                } label: {
                    if tab == selected {
                        Label(tab.description, systemImage: "checkmark")
                    } else {
                        Text(tab.description)
                    }
                }
            }
        } label: {
            Image(systemName: "chevron.down")
                .symbolRenderingMode(.monochrome)
                .font(.system(size: Tok.Size.iconInline, weight: .medium))
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: Tok.Size.control, height: Tok.Size.control)
                .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("More tabs")
        .accessibilityLabel("More tabs")
    }

    private func tabButton(_ tab: Tab) -> some View {
        let on = tab == selected
        return Button { selected = tab } label: {
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
        // The blank header/body separator only when there is a body to separate;
        // a bodiless message would otherwise end in a phantom empty line.
        let bodyLines = body(message)
        if !bodyLines.isEmpty {
            lines.append(CodeLine(runs: []))
            lines += bodyLines
        }
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
    var imageZoom: ImageZoom = .fit
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
            case (.auto, .image): ImageBodyView(data: data, contentType: message.contentType, zoom: state.imageZoom)
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
                if let extent, extent.isTruncated { TruncatedChip(extent: extent) }
                if case .image = kind, state.format == .auto {
                    ImageControls(data: data, contentType: message.contentType, zoom: $state.imageZoom)
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
        @Bindable var bodyState = bodyState
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
            if tab == .body, bodyState.findShown {
                FindRow(state: bodyState.find, isPresented: $bodyState.findShown)
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
                case .cookies: CookieTable(cookies: Cookie.cookies(in: detail.request), bodySize: bodySize, isRequest: true)
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
        .onChange(of: row.id) { bodyState.format = .auto; bodyState.findShown = false; bodyState.imageZoom = .fit }
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

    /// `#45 → #46` for the two compared flows, in capture order.
    private var compareLabel: String? {
        let chosen = session.rows.filter { session.selection.contains($0.id) }
        guard chosen.count == 2 else { return nil }
        return "#\(chosen[0].seq) → #\(chosen[1].seq)"
    }

    private var treeState: JSONTreeState? {
        if let tree, tree.0 == row.id { return tree.1 }
        return nil
    }

    var body: some View {
        @Bindable var session = session
        @Bindable var bodyState = bodyState
        VStack(spacing: 0) {
            PaneTabs(title: "Response", tabs: ResponseTab.allCases, selected: $session.responseTab) {
                trailing
            }
            if tab == .body, bodyState.findShown {
                FindRow(state: bodyState.find, isPresented: $bodyState.findShown)
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
                // The previous response is a reference, not this flow's content: the
                // badge says so beside the caption, and the trailing slot stays empty.
                VStack(alignment: .leading, spacing: 0) {
                    HStack(alignment: .firstTextBaseline, spacing: Space.sm) {
                        Badge(text: "Reference", pair: ColorPair(fg: Tok.Ink.secondary, bg: Tok.Ground.raised), uppercase: false)
                        Hint(text: "No response yet — the request is paused. Showing the last response to this endpoint for reference.")
                    }
                    .padding(.leading, Space.md)
                    .padding(.top, Space.xs)
                    CodeView(lines: BodyLines.body(previous), header: nil, footer: nil)
                }
            } else if row.state == .pending || detail == nil {
                LoadingLines()
            } else {
                ContentUnavailableView {
                    Label("No Response", systemImage: row.state == .killed ? "xmark.circle" : "tray")
                } description: {
                    Text(row.state == .killed ? "This flow was killed before a response arrived."
                         : "No response was received for this flow.")
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onChange(of: row.id, initial: true) { rebuildTree(); bodyState.format = .auto; bodyState.findShown = false; bodyState.imageZoom = .fit }
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
            if let pair = diffPair { DiffControls(result: FlowDiff.compare(pair.0, pair.1), state: diffState, compareLabel: compareLabel) }
        case .body:
            // While the request is paused there is no response to format or search,
            // so the slot shows nothing rather than dead controls.
            if let response = detail?.response {
                BodyHost.controls(message: response, extent: detail?.responseBodyExtent, state: bodyState, sseState: sseState)
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
