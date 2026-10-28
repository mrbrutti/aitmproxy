import AitmproxyKit
import SwiftUI
import UniformTypeIdentifiers

/// What the copy menu puts on the pasteboard (S-028). The Flow ▸ Copy As ▸
/// menu uses the same cases through `ExportMenu.copy`.
enum ExportKind: CaseIterable {
    case url, curl, httpie, python, fetch

    var title: String {
        switch self {
        case .url: "Copy URL"
        case .curl: "Copy as cURL"
        case .httpie: "Copy as httpie"
        case .python: "Copy as Python (requests)"
        case .fetch: "Copy as fetch"
        }
    }

    func text(_ detail: FlowDetail, row: FlowRow) -> String {
        switch self {
        case .url: row.url
        case .curl: CodeExport.curl(detail, row: row)
        case .httpie: CodeExport.httpie(detail, row: row)
        case .python: CodeExport.pythonRequests(detail, row: row)
        case .fetch: CodeExport.fetch(detail, row: row)
        }
    }
}

/// The summary strip's copy button as a flat menu: Copy URL, the four code
/// exports, Export Body…. The glyph alone is the label; no border, no chrome.
struct ExportMenu: View {
    var detail: FlowDetail
    var row: FlowRow

    var body: some View {
        Menu {
            Button(ExportKind.url.title) { Self.copy(.url, detail: detail, row: row) }
            Divider()
            Button(ExportKind.curl.title) { Self.copy(.curl, detail: detail, row: row) }
                .keyboardShortcut("c", modifiers: [.shift, .command])
                .help(bodyIsBinary ? "The body is not UTF-8 — cURL pipes it through base64" : "")
            Button(ExportKind.httpie.title) { Self.copy(.httpie, detail: detail, row: row) }
            Button(ExportKind.python.title) { Self.copy(.python, detail: detail, row: row) }
            Button(ExportKind.fetch.title) { Self.copy(.fetch, detail: detail, row: row) }
            Divider()
            Button("Export Body…") { Self.exportBody(detail, row: row) }
                .disabled(exportable == nil)
        } label: {
            Image(systemName: Tok.Glyph.copy)
                .font(.system(size: Tok.Size.iconInline))
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: Space.xxl, height: Space.xxl)
                .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Copy as…")
        .accessibilityLabel("Copy as")
    }

    private var bodyIsBinary: Bool {
        guard let body = detail.request.body, !body.isEmpty else { return false }
        return String(data: body, encoding: .utf8) == nil
    }

    /// The body Export Body… writes: the response's when there is one, else the request's.
    private var exportable: HTTPMessage? { Self.exportable(detail) }

    static func exportable(_ detail: FlowDetail) -> HTTPMessage? {
        if let response = detail.response, let body = response.body, !body.isEmpty { return response }
        if let body = detail.request.body, !body.isEmpty { return detail.request }
        return nil
    }

    // MARK: Actions

    /// Puts the export on the general pasteboard as plain text.
    static func copy(_ kind: ExportKind, detail: FlowDetail, row: FlowRow) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(kind.text(detail, row: row), forType: .string)
    }

    /// A save panel prefilled from the path's last segment and the content type's extension.
    static func exportBody(_ detail: FlowDetail, row: FlowRow) {
        guard let message = exportable(detail), let body = message.body else { return }
        let panel = NSSavePanel()
        let name = filename(path: row.path, contentType: message.contentType)
        panel.nameFieldStringValue = name
        panel.allowedContentTypes = [UTType(filenameExtension: (name as NSString).pathExtension) ?? .data]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? body.write(to: url, options: .atomic)
    }

    /// `/api/products` + `application/json` → `products.json`; `/` → `body.bin`.
    static func filename(path: String, contentType: String?) -> String {
        let segment = path.split(separator: "/").last.map(String.init) ?? ""
        let base = segment.isEmpty ? "body" : (segment as NSString).deletingPathExtension
        let stem = base.isEmpty ? "body" : base
        if let ext = extensionFor(contentType) { return "\(stem).\(ext)" }
        let existing = (segment as NSString).pathExtension
        return existing.isEmpty ? "\(stem).bin" : segment
    }

    private static let extensions: [(type: String, ext: String)] = [
        ("application/json", "json"), ("image/png", "png"), ("text/html", "html"), ("image/jpeg", "jpg"),
        ("image/gif", "gif"), ("image/webp", "webp"), ("image/svg+xml", "svg"), ("application/pdf", "pdf"),
        ("text/plain", "txt"), ("text/css", "css"), ("application/javascript", "js"), ("text/javascript", "js"),
        ("application/xml", "xml"), ("text/xml", "xml"), ("text/event-stream", "txt"),
    ]

    static func extensionFor(_ contentType: String?) -> String? {
        guard let contentType else { return nil }
        let mime = contentType.split(separator: ";").first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            ?? ""
        return extensions.first { $0.type == mime }?.ext
    }
}
