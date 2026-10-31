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

/// How the image viewer sizes the picture: Fit the pane, or a fixed zoom.
enum ImageZoom: Hashable, CaseIterable {
    case fit, actual, large
    var label: String {
        switch self {
        case .fit: "Fit"
        case .actual: "100%"
        case .large: "400%"
        }
    }
}

/// The picture on an 8 pt checkerboard with the caption beneath; the zoom control
/// in the tab bar picks Fit / 100% / 400%, and Fit upscales a tiny image so it is
/// not a single dot. Hex under a notice when the bytes cannot be read.
struct ImageBodyView: View {
    var data: Data
    var contentType: String?
    var zoom: ImageZoom = .fit

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
            let scale = scaleFactor(for: natural, in: room)
            let drawn = CGSize(width: (natural.width * scale).rounded(.down), height: (natural.height * scale).rounded(.down))
            VStack(spacing: Space.sm) {
                Group {
                    if zoom == .fit {
                        image(decoded, drawn: drawn, scale: scale)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    } else {
                        // 100% / 400% can overflow the pane, so they scroll.
                        ScrollView([.vertical, .horizontal]) {
                            image(decoded, drawn: drawn, scale: scale)
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }
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

    private func image(_ decoded: DecodedImage, drawn: CGSize, scale: CGFloat) -> some View {
        Image(nsImage: decoded.image)
            .resizable()
            .interpolation(scale < 1 ? .high : .none)
            .frame(width: drawn.width, height: drawn.height)
            .background { Checkerboard() }
    }

    /// Fit scales down to the pane but upscales a tiny image (nearest-neighbour)
    /// so it is at least 64 pt on its longer side; 100% and 400% are literal.
    private func scaleFactor(for natural: CGSize, in room: CGSize) -> CGFloat {
        switch zoom {
        case .actual: return 1
        case .large: return 4
        case .fit:
            let fit = min(1, room.width / natural.width, room.height / natural.height)
            let longer = max(natural.width, natural.height)
            if longer * fit < 64 { return min(64, max(room.width, room.height)) / longer }
            return fit
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

/// The tab bar's trailing slot for an image body: the Fit / 100% / 400% zoom
/// segment and an overflow menu with Open in Preview and Export….
struct ImageControls: View {
    var data: Data
    var contentType: String?
    @Binding var zoom: ImageZoom

    private var fileExtension: String {
        DecodedImage(data: data, contentType: contentType)?.fileExtension ?? "bin"
    }

    var body: some View {
        HStack(spacing: Space.sm) {
            FlatSegment(options: ImageZoom.allCases.map { ($0, $0.label) }, selection: $zoom)
            Menu {
                Button("Open in Preview") { openInPreview() }
                Button("Export…") { export() }
            } label: {
                Image(systemName: "ellipsis")
                    .font(.system(size: Tok.Size.iconInline))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .frame(width: Space.xxl, height: Space.xxl)
                    .contentShape(Rectangle())
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("Open or export the image")
            .accessibilityLabel("Image actions")
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
