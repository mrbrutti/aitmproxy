import AitmproxyKit
import AppKit
import SwiftUI

/// The Body tab (S-021 / S-027 / S-029): the body in its detected or
/// chosen format. Text formats go through `CodeTextView`; form and
/// multipart get tables; Markdown and HTML can render (scripts and remote
/// loads stripped, no WebKit); binary goes to `HexView`. Pretty-printing of
/// bodies over 256 KB runs off the main actor behind loading bars.
struct PrettyBodyView: View {
    var message: HTTPMessage
    @Binding var format: BodyFormat
    var extent: BodyExtent?
    var bodySize: CGFloat
    var find: FindState?
    var rendered: Binding<Bool>?
    var onLoadMore: (() async throws -> Void)?

    @State private var text: String?
    @State private var textKey: Int?
    @State private var localRendered = false
    @State private var paging = PagingState(lastGood: .now)

    init(message: HTTPMessage, format: Binding<BodyFormat>, extent: BodyExtent? = nil,
         bodySize: CGFloat = Tok.Typography.Size.md, find: FindState? = nil, rendered: Binding<Bool>? = nil,
         onLoadMore: (() async throws -> Void)? = nil) {
        self.message = message
        _format = format
        self.extent = extent
        self.bodySize = bodySize
        self.find = find
        self.rendered = rendered
        self.onLoadMore = onLoadMore
    }

    private var resolved: BodyFormat { format.resolve(for: message) }
    private var isRendered: Bool { rendered?.wrappedValue ?? localRendered }
    /// Identifies the text to show without hashing a multi-megabyte body on
    /// every evaluation: head, headers, length and the body's first and last 4 KB.
    private var key: Int {
        var hasher = Hasher()
        hasher.combine(message.startLine)
        hasher.combine(message.headers)
        hasher.combine(message.bodyBytes)
        if let body = message.body {
            hasher.combine(body.prefix(4096))
            hasher.combine(body.suffix(4096))
        }
        hasher.combine(resolved)
        return hasher.finalize()
    }

    var body: some View {
        VStack(spacing: 0) {
            content.frame(maxWidth: .infinity, maxHeight: .infinity)
            if let extent, extent.isTruncated {
                LoadMoreFooter(state: paging, extent: extent, onLoadMore: onLoadMore)
            }
        }
        .task(id: key) { await loadText() }
        .onChange(of: text, initial: true) { _, shown in find?.search(in: shown ?? "") }
        .onChange(of: message.bodyBytes) { _, _ in paging.lastGood = .now }
    }

    @ViewBuilder private var content: some View {
        if message.body?.isEmpty ?? true {
            Text("No body")
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.tertiary.color)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            switch resolved {
            case .form:
                HeaderTable(headers: BodyKind.formDecode(message.body ?? Data()).map { HTTPMessage.Header($0.0, $0.1) })
            case .multipart:
                MultipartView(message: message, bodySize: bodySize)
            case .hex:
                HexView(data: message.body ?? Data())
            default:
                textContent
            }
        }
    }

    @ViewBuilder private var textContent: some View {
        if textKey != key {
            LoadingLines()
        } else if let text {
            if resolved.isRenderable, isRendered {
                RenderedView(text: text, format: resolved)
            } else {
                CodeTextView(text: text, contentType: resolved.syntaxContentType, bodySize: bodySize,
                             highlights: find?.matches ?? [], currentHighlight: find?.current)
            }
        } else {
            VStack(spacing: 0) {
                Hint(text: "Not UTF-8 — showing hex").padding(.leading, Space.md)
                HexView(data: message.body ?? Data())
            }
        }
    }

    private func loadText() async {
        let message = message
        let format = resolved
        let key = key
        guard format.isText else {
            text = nil
            textKey = key
            return
        }
        if (message.body?.count ?? 0) < 256_000 {
            text = BodyFormat.prettyText(message, as: format)
        } else {
            text = await Task.detached(priority: .userInitiated) { BodyFormat.prettyText(message, as: format) }.value
        }
        guard !Task.isCancelled else { return }
        textKey = key
    }
}

/// The `JSON ▾` popup for the tab bar's trailing slot: 24 pt, outlined,
/// the detected format's name while on Auto.
struct FormatPicker: View {
    @Binding var selection: BodyFormat
    var detected: BodyFormat

    var body: some View {
        Menu {
            Picker("Format", selection: $selection) {
                ForEach(BodyFormat.allCases) { format in
                    Text(format.title).tag(format)
                }
            }
            .pickerStyle(.inline)
        } label: {
            Text("\((selection == .auto ? detected : selection).title) ▾")
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.primary.color)
                .padding(.horizontal, Space.sm)
                .frame(height: Space.xxl)
                .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
                .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Body format")
        .accessibilityLabel("Body format")
        .accessibilityValue(selection == .auto ? "Auto, \(detected.title)" : selection.title)
    }
}

/// "Rendered" for Markdown and HTML bodies: outlined, `Ground.active` when on.
struct RenderedToggle: View {
    @Binding var isOn: Bool

    var body: some View {
        Button { isOn.toggle() } label: {
            Text("Rendered")
                .font(Tok.Face.ui(Tok.Typography.Size.sm, isOn ? .medium : .regular))
                .foregroundStyle((isOn ? Tok.Ink.primary : Tok.Ink.secondary).color)
                .padding(.horizontal, Space.sm)
                .frame(height: Space.xxl)
                .background(isOn ? Tok.Ground.active.color : .clear, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Render the body instead of showing its source")
        .accessibilityAddTraits(isOn ? .isSelected : [])
    }
}

/// Markdown through `AttributedString(markdown:)`, HTML through
/// `NSAttributedString(html:)` after `BodyFormat.sanitizedHTML`. Nothing
/// loads from the network and no script runs; over 1 MB shows a notice.
struct RenderedView: View {
    var text: String
    var format: BodyFormat
    static let maxBytes = 1_000_000

    var body: some View {
        ScrollView {
            if text.utf8.count > Self.maxBytes {
                Hint(text: "Too large to render — showing source is faster").padding(.leading, Space.md)
            } else {
                Text(rendered)
                    .font(Tok.Face.ui(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Space.md)
            }
        }
    }

    private var rendered: AttributedString {
        switch format {
        case .markdown:
            let options = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
            return (try? AttributedString(markdown: text, options: options)) ?? AttributedString(text)
        default:
            let data = Data(BodyFormat.sanitizedHTML(text).utf8)
            guard let html = NSMutableAttributedString(
                html: data, options: [.documentType: NSAttributedString.DocumentType.html, .characterEncoding: String.Encoding.utf8.rawValue],
                documentAttributes: nil) else { return AttributedString(text) }
            // The converter bakes in black text and web fonts; the view sets ink and face.
            let whole = NSRange(location: 0, length: html.length)
            html.removeAttribute(.foregroundColor, range: whole)
            html.removeAttribute(.backgroundColor, range: whole)
            html.enumerateAttribute(.font, in: whole) { value, range, _ in
                guard let font = value as? NSFont else { return }
                let bold = font.fontDescriptor.symbolicTraits.contains(.bold)
                let size = min(max(font.pointSize, Tok.Typography.Size.sm), Tok.Typography.Size.xl)
                html.addAttribute(.font, value: Tok.Face.nsUI(size, bold ? .semibold : .regular), range: range)
            }
            return AttributedString(html)
        }
    }
}

/// Multipart parts (S-021): each part's name, its headers as key : value
/// rows, then its body as text or, for binary, its size.
struct MultipartView: View {
    var message: HTTPMessage
    var bodySize: CGFloat

    private var parts: [MultipartPart] {
        guard let boundary = BodyFormat.multipartBoundary(message) else { return [] }
        return BodyKind.multipartParts(message.body ?? Data(), boundary: boundary)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                let parts = parts
                if parts.isEmpty {
                    Hint(text: "No parts — the boundary did not match").padding(.leading, Space.md)
                }
                ForEach(Array(parts.enumerated()), id: \.offset) { index, part in
                    Text(title(for: part, index: index))
                        .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                        .tracking(0.6)
                        .textCase(.uppercase)
                        .foregroundStyle(Tok.Ink.tertiary.color)
                        .padding(.horizontal, Space.md)
                        .padding(.top, index == 0 ? Space.md : Space.xl)
                        .padding(.bottom, Space.sm)
                    ForEach(Array(part.headers.enumerated()), id: \.offset) { _, header in
                        HStack(alignment: .firstTextBaseline, spacing: Space.md) {
                            Text(header.name).foregroundStyle(Tok.Syntax.key.color).frame(width: 180, alignment: .leading)
                            Text(header.value).foregroundStyle(Tok.Ink.primary.color).textSelection(.enabled)
                            Spacer(minLength: 0)
                        }
                        .font(Tok.Face.data(Tok.Typography.Size.md))
                        .padding(.horizontal, Space.md)
                        .frame(minHeight: Tok.Size.Row.dense)
                        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
                    }
                    partBody(part)
                }
            }
            .padding(.bottom, Space.md)
        }
    }

    private func title(for part: MultipartPart, index: Int) -> String {
        var words = ["Part \(index + 1)"]
        if let name = part.name { words.append(name) }
        if let filename = part.filename { words.append(filename) }
        return words.joined(separator: " · ")
    }

    @ViewBuilder private func partBody(_ part: MultipartPart) -> some View {
        if part.body.isEmpty {
            Hint(text: "Empty").padding(.leading, Space.md)
        } else if let text = String(data: part.body, encoding: .utf8) {
            Text(text)
                .font(Tok.Face.data(bodySize))
                .foregroundStyle(Tok.Ink.primary.color)
                .textSelection(.enabled)
                .lineSpacing(bodySize * (Tok.Typography.LineHeight.code - 1))
                .padding(.horizontal, Space.md)
                .padding(.vertical, Space.sm)
                .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            Hint(text: "\(Format.bytes(Int64(part.body.count))) · binary").padding(.leading, Space.md)
        }
    }
}
