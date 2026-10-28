import AitmproxyKit
import SwiftUI

/// The inspector (foundation §2.7): a 40px summary strip over Request |
/// Response panes, each with a title, plain tabs and a body viewer.
struct InspectorView: View {
    @Environment(Session.self) private var session

    var body: some View {
        VStack(spacing: 0) {
            if let row = session.focusedRow {
                SummaryStrip(row: row, detail: session.focusedDetail)
                Rule()
                HStack(spacing: 0) {
                    RequestPane(row: row, detail: session.focusedDetail)
                    VRule()
                    ResponsePane(row: row, detail: session.focusedDetail)
                }
            } else {
                EmptyInspector()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
    }
}

struct EmptyInspector: View {
    var body: some View {
        VStack(spacing: Space.sm) {
            Text("No flow selected").font(Tok.Face.ui(Tok.Typography.Size.base)).foregroundStyle(Tok.Ink.secondary.color)
            Text("Select a flow to inspect it, or press ↑↓.").font(Tok.Face.ui(Tok.Typography.Size.sm))
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
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(row.url, forType: .string)
            } label: {
                Image(systemName: Tok.Glyph.copy).font(.system(size: 12)).foregroundStyle(Tok.Ink.secondary.color)
                    .frame(width: Space.xxl, height: Space.xxl)
            }
            .buttonStyle(.plain)
            .help("Copy URL")
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
        HStack(spacing: 2) {
            Text(title).font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold)).foregroundStyle(Tok.Ink.primary.color)
                .padding(.trailing, Tok.Metric.padInner)
            ForEach(tabs, id: \.self) { tab in
                let on = tab == selected
                Button { selected = tab } label: {
                    Text(tab.description)
                        .font(Tok.Face.ui(Tok.Typography.Size.md, on ? .medium : .regular))
                        .foregroundStyle(on ? Palette.accentText : Tok.Ink.secondary.color)
                        .padding(.horizontal, Space.sm)
                        .frame(height: Tok.Size.tabBar)
                        .overlay(alignment: .bottom) {
                            if on { Rectangle().fill(Palette.accent).frame(height: 2).padding(.horizontal, Space.sm) }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
            Button {} label: {
                Text("+").font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
                    .padding(.horizontal, Space.sm).frame(height: Tok.Size.tabBar)
            }
            .buttonStyle(.plain)
            .help("Add viewer")
            Spacer(minLength: Space.xs)
            trailing
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.tabBar)
        .overlay(alignment: .bottom) { Rule() }
    }
}

enum RequestTab: String, CaseIterable, CustomStringConvertible {
    case headers = "Headers", query = "Query", body = "Body", raw = "Raw", summary = "Summary", connection = "Connection"
    var description: String { rawValue }
}

enum ResponseTab: String, CaseIterable, CustomStringConvertible {
    case headers = "Headers", body = "Body", raw = "Raw", json = "JSON", diff = "Diff"
    var description: String { rawValue }
}

struct RequestPane: View {
    var row: FlowRow
    var detail: FlowDetail?
    @State private var tab: RequestTab = .raw

    var body: some View {
        VStack(spacing: 0) {
            PaneTabs(title: "Request", tabs: RequestTab.allCases, selected: $tab) {
                if row.state == .paused {
                    Text("editing").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                }
            }
            if let detail {
                switch tab {
                case .raw:
                    CodeView(lines: rawLines(detail), footer: row.state == .paused && row.edited
                             ? "1 edit pending · Apply & Resume sends flow.mutate then flow.resume · Revert to original" : nil)
                case .headers:
                    HeaderTable(headers: detail.request.headers)
                case .query:
                    HeaderTable(headers: queryPairs)
                case .body:
                    CodeView(lines: bodyLines(detail.request), footer: nil)
                case .summary:
                    HeaderTable(headers: [
                        .init("method", row.method.label), .init("url", row.url),
                        .init("request size", Format.bytes(row.requestBytes)),
                        .init("started", Format.time(row.startedAt)),
                        .init("origin", row.origin == .agent ? "agent" : row.client?.name ?? "client"),
                    ])
                case .connection:
                    HeaderTable(headers: [
                        .init("protocol", detail.connection.httpVersion),
                        .init("tls", detail.connection.tlsVersion ?? "none"),
                        .init("alpn", detail.connection.alpn ?? Format.dash),
                        .init("sni", detail.connection.sni ?? Format.dash),
                        .init("client", detail.connection.clientAddress ?? Format.dash),
                        .init("server", detail.connection.serverAddress ?? Format.dash),
                    ])
                }
            } else {
                LoadingLines()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var queryPairs: [HTTPMessage.Header] {
        (row.query ?? "").split(separator: "&").map { pair in
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            return .init(parts.first ?? "", parts.count > 1 ? parts[1].removingPercentEncoding ?? parts[1] : "")
        }
    }

    private func rawLines(_ detail: FlowDetail) -> [CodeLine] {
        var lines: [CodeLine] = [CodeLine(runs: Syntax.startLine(detail.request.startLine))]
        let originalNames = Set(detail.originalRequest?.headers.map(\.name) ?? [])
        for header in detail.request.headers {
            let edited = detail.originalRequest != nil && !originalNames.contains(header.name)
            lines.append(CodeLine(runs: Syntax.header(line: "\(header.name): \(header.value)"), edited: edited, current: edited))
        }
        lines.append(CodeLine(runs: []))
        lines += bodyLines(detail.request)
        return lines
    }

    private func bodyLines(_ message: HTTPMessage) -> [CodeLine] {
        guard let text = message.bodyText, !text.isEmpty else { return [] }
        return text.split(separator: "\n", omittingEmptySubsequences: false).map {
            CodeLine(runs: Syntax.runs(for: String($0), contentType: message.contentType))
        }
    }
}

struct ResponsePane: View {
    var row: FlowRow
    var detail: FlowDetail?
    @State private var tab: ResponseTab = .body

    var body: some View {
        VStack(spacing: 0) {
            PaneTabs(title: "Response", tabs: ResponseTab.allCases, selected: $tab) {
                HStack(spacing: 4) {
                    Text("\(format) ▾")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.primary.color)
                        .padding(.horizontal, Space.sm)
                        .frame(height: Space.xxl)
                        .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
                    Image(systemName: Tok.Glyph.search).font(.system(size: 12)).foregroundStyle(Tok.Ink.secondary.color)
                        .frame(width: Space.xxl, height: Space.xxl)
                }
            }
            if let response = detail?.response {
                switch tab {
                case .headers: HeaderTable(headers: response.headers)
                case .body, .json: CodeView(lines: bodyLines(response), footer: nil)
                case .raw:
                    CodeView(lines: [CodeLine(runs: Syntax.startLine(response.startLine))]
                             + response.headers.map { CodeLine(runs: Syntax.header(line: "\($0.name): \($0.value)")) }
                             + [CodeLine(runs: [])] + bodyLines(response), footer: nil)
                case .diff: DiffPlaceholder()
                }
            } else if row.state == .paused, let previous = previousResponse {
                CodeView(
                    lines: bodyLines(previous),
                    header: "No response yet — the request is paused. Showing the last response to this endpoint (flow 38, 11:04:12) for reference.",
                    footer: nil)
            } else if row.state == .pending {
                LoadingLines()
            } else {
                VStack(spacing: Space.sm) {
                    Text(row.state == .killed ? "Killed — no response" : "No response")
                        .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.secondary.color)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var format: String {
        ContentCategory.classify(contentType: detail?.response?.contentType ?? previousResponse?.contentType).title
    }

    /// Fixture-only reference while the live detail (F5) cannot look up the previous flow.
    private var previousResponse: HTTPMessage? {
        row.authority == "auth.shop-staging.test" && row.path == "/api/auth/login" ? Fixtures.previousLoginResponse : nil
    }

    private func bodyLines(_ message: HTTPMessage) -> [CodeLine] {
        guard let text = message.bodyText, !text.isEmpty else { return [] }
        return text.split(separator: "\n", omittingEmptySubsequences: false).map {
            CodeLine(runs: Syntax.runs(for: String($0), contentType: message.contentType))
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
    var body: some View {
        VStack(spacing: Space.sm) {
            Text("Diff two flows").font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.secondary.color)
            Text("Select a second flow with ⌘-click, then Diff.").font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.tertiary.color)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
