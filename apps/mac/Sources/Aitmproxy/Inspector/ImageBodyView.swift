import AitmproxyKit
import ImageIO
import SwiftUI
import UniformTypeIdentifiers

/// What the image viewer knows about a body: the decoded picture and its caption parts (S-023).
struct DecodedImage {
    var image: NSImage
    var width: Int
    var height: Int
    /// `PNG`, `JPEG`, `SVG`, …; from the magic bytes, else the content type.
    var typeLabel: String
    /// `sRGB`, `Display P3`, …; nil when the decoder reports none (SVG).
    var colorSpace: String?
    var byteCount: Int
    /// File extension for Open in Preview / Export….
    var fileExtension: String

    /// `1200×800 · PNG · 184 KB · sRGB`.
    var caption: String {
        ["\(width)×\(height)", typeLabel, Format.bytes(Int64(byteCount)), colorSpace].compactMap { $0 }.joined(separator: " · ")
    }

    /// Nil when the bytes are not a picture AppKit can draw.
    init?(data: Data, contentType: String?) {
        guard !data.isEmpty, let image = NSImage(data: data), image.isValid else { return nil }
        self.image = image
        byteCount = data.count
        let info = BodyKind.imageInfo(data)
        var format: ImageFormat?
        var size: (Int?, Int?) = (nil, nil)
        if case .image(let f, let w, let h)? = info {
            format = f
            size = (w, h)
        } else if case .image(let f, let w, let h) = BodyKind.detect(contentType: contentType, data: data) {
            format = f
            size = (w, h)
        }
        let cg = Self.firstFrame(data)
        width = size.0 ?? cg.map(\.width) ?? Int(image.size.width.rounded())
        height = size.1 ?? cg.map(\.height) ?? Int(image.size.height.rounded())
        colorSpace = cg?.colorSpace.flatMap(Self.colorSpaceName)
        let subtype = Self.subtype(of: contentType)
        typeLabel = (format?.label ?? subtype ?? "image").uppercased()
        fileExtension = format.map(Self.fileExtension) ?? subtype ?? "img"
        guard width > 0, height > 0 else { return nil }
    }

    /// `image/svg+xml; charset=utf-8` → `svg+xml`; nil without a slash.
    private static func subtype(of contentType: String?) -> String? {
        guard let contentType else { return nil }
        let type = contentType.split(separator: ";").first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
        guard let slash = type.firstIndex(of: "/") else { return nil }
        let subtype = type[type.index(after: slash)...].lowercased()
        return subtype.isEmpty ? nil : subtype
    }

    private static func firstFrame(_ data: Data) -> CGImage? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        return CGImageSourceCreateImageAtIndex(source, 0, nil)
    }

    /// `kCGColorSpaceSRGB` → `sRGB`; unknown names lose the prefix.
    private static func colorSpaceName(_ space: CGColorSpace) -> String? {
        guard let raw = space.name as String? else { return nil }
        switch raw {
        case String(CGColorSpace.sRGB): return "sRGB"
        case String(CGColorSpace.displayP3): return "Display P3"
        case String(CGColorSpace.adobeRGB1998): return "Adobe RGB"
        case String(CGColorSpace.linearSRGB): return "Linear sRGB"
        case String(CGColorSpace.genericGrayGamma2_2): return "Gray"
        case String(CGColorSpace.extendedSRGB): return "Extended sRGB"
        default: return raw.replacingOccurrences(of: "kCGColorSpace", with: "")
        }
    }

    private static func fileExtension(_ format: ImageFormat) -> String {
        switch format {
        case .png: "png"
        case .jpeg: "jpg"
        case .gif: "gif"
        case .webp: "webp"
        case .svg: "svg"
        }
    }
}

/// The picture at 1× (fit to the pane when larger, never upscaled) on an 8 pt
/// checkerboard, the caption beneath; hex under a notice when it cannot be read.
struct ImageBodyView: View {
    var data: Data
    var contentType: String?

    var body: some View {
        if let decoded = DecodedImage(data: data, contentType: contentType) {
            picture(decoded)
        } else {
            VStack(alignment: .leading, spacing: 0) {
                Hint(text: "Not a readable image")
                    .padding(.leading, Space.md)
                    .padding(.top, Space.xs)
                HexView(data: data)
            }
        }
    }

    private func picture(_ decoded: DecodedImage) -> some View {
        GeometryReader { proxy in
            let room = CGSize(width: max(1, proxy.size.width - Space.md * 2),
                              height: max(1, proxy.size.height - Space.md * 2 - Space.sm - Space.xl))
            let natural = CGSize(width: CGFloat(decoded.width), height: CGFloat(decoded.height))
            let scale = min(1, room.width / natural.width, room.height / natural.height)
            let drawn = CGSize(width: (natural.width * scale).rounded(.down), height: (natural.height * scale).rounded(.down))
            VStack(spacing: Space.sm) {
                Image(nsImage: decoded.image)
                    .resizable()
                    .interpolation(scale < 1 ? .high : .none)
                    .frame(width: drawn.width, height: drawn.height)
                    .background { Checkerboard() }
                    .accessibilityLabel(decoded.caption)
                Text(decoded.caption)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .textSelection(.enabled)
                    .frame(height: Space.xl)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(Space.md)
        }
    }
}

/// 8 pt squares in `raised` over `surface`, the way image editors show transparency.
private struct Checkerboard: View {
    var body: some View {
        Canvas { context, size in
            context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(Tok.Ground.surface.color))
            var squares = Path()
            let step: CGFloat = 8 // grid: ok drawn checkerboard geometry
            var y: CGFloat = 0
            var oddRow = false
            while y < size.height {
                var x: CGFloat = oddRow ? step : 0
                while x < size.width {
                    squares.addRect(CGRect(x: x, y: y, width: step, height: step))
                    x += step * 2
                }
                y += step
                oddRow.toggle()
            }
            context.fill(squares, with: .color(Tok.Ground.raised.color))
        }
        .clipped()
        .accessibilityHidden(true)
    }
}

/// The tab bar's trailing slot for an image body: "Open in Preview" and "Export…".
struct ImageControls: View {
    var data: Data
    var contentType: String?

    private var fileExtension: String {
        DecodedImage(data: data, contentType: contentType)?.fileExtension ?? "bin"
    }

    var body: some View {
        HStack(spacing: Space.xs) {
            FlatTextButton("Open in Preview", action: openInPreview)
                .help("Write the image to a temporary file and open it")
            FlatTextButton("Export…", action: export)
                .help("Save the image bytes as a file")
        }
    }

    private func openInPreview() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("aitmproxy-\(UUID().uuidString)")
            .appendingPathExtension(fileExtension)
        do {
            try data.write(to: url, options: .atomic)
            NSWorkspace.shared.open(url)
        } catch {
            NSSound.beep()
        }
    }

    private func export() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "image.\(fileExtension)"
        if let type = UTType(filenameExtension: fileExtension) { panel.allowedContentTypes = [type] }
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? data.write(to: url, options: .atomic)
    }
}

/// A flat text button for a tab bar's trailing slot: 12 ui secondary, 24 tall, no fill.
private struct FlatTextButton: View {
    var title: String
    var action: () -> Void

    init(_ title: String, action: @escaping () -> Void) {
        self.title = title
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .padding(.horizontal, Space.sm)
                .frame(height: Space.xxl)
                .contentShape(Rectangle())
        }
        .buttonStyle(PressStyle())
    }
}
