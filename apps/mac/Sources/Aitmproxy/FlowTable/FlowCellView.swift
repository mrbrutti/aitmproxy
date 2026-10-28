import AitmproxyKit
import AppKit

/// One cell. A label for text columns; a small drawn view for the dot, the
/// method/status badges, the padlock, the origin tag and the mark swatch.
final class FlowCellView: NSTableCellView {
    let column: FlowColumn
    private let label = NSTextField(labelWithString: "")
    private let badge = BadgeView()
    private let dot = DotView()
    private let icon = NSImageView()
    private let swatch = NSView()
    private let monogram = MonogramView()

    init(column: FlowColumn) {
        self.column = column
        super.init(frame: .zero)
        label.translatesAutoresizingMaskIntoConstraints = false
        label.lineBreakMode = .byTruncatingTail
        label.cell?.truncatesLastVisibleLine = true
        label.usesSingleLineMode = true
        label.font = Tok.Face.nsData(Tok.Typography.Size.md)
        label.alignment = column.numeric ? .right : .left
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        for view in [label, badge, dot, icon, swatch, monogram] as [NSView] {
            view.translatesAutoresizingMaskIntoConstraints = false
            addSubview(view)
            view.isHidden = true
        }
        let pad: CGFloat = 8
        NSLayoutConstraint.activate([
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
            label.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -pad),
            badge.centerYAnchor.constraint(equalTo: centerYAnchor),
            badge.leadingAnchor.constraint(equalTo: leadingAnchor, constant: pad),
            badge.heightAnchor.constraint(equalToConstant: Tok.Size.badge),
            dot.centerYAnchor.constraint(equalTo: centerYAnchor),
            dot.centerXAnchor.constraint(equalTo: centerXAnchor),
            dot.widthAnchor.constraint(equalToConstant: Tok.Size.statusDot),
            dot.heightAnchor.constraint(equalToConstant: Tok.Size.statusDot),
            icon.centerYAnchor.constraint(equalTo: centerYAnchor),
            icon.centerXAnchor.constraint(equalTo: centerXAnchor),
            swatch.centerYAnchor.constraint(equalTo: centerYAnchor),
            swatch.centerXAnchor.constraint(equalTo: centerXAnchor),
            swatch.widthAnchor.constraint(equalToConstant: 6),
            swatch.heightAnchor.constraint(equalToConstant: 16),
            monogram.centerYAnchor.constraint(equalTo: centerYAnchor),
            monogram.leadingAnchor.constraint(equalTo: leadingAnchor, constant: pad),
            monogram.widthAnchor.constraint(equalToConstant: 16),
            monogram.heightAnchor.constraint(equalToConstant: 16),
        ])
        if column == .client {
            label.leadingAnchor.constraint(equalTo: monogram.trailingAnchor, constant: 6).isActive = true
        } else {
            label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: pad).isActive = true
        }
        swatch.wantsLayer = true
        swatch.layer?.cornerRadius = 2
        icon.symbolConfiguration = .init(pointSize: 12, weight: .regular)
        icon.contentTintColor = Tok.Ink.secondary.nsColor
        textField = label
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    /// Selection is a quiet tint, so cells keep their own colours: no
    /// emphasized white text or template icons on the selected row.
    override var backgroundStyle: NSView.BackgroundStyle {
        get { .normal }
        set {}
    }

    func configure(_ row: FlowRow) {
        for view in [label, badge, dot, icon, swatch, monogram] as [NSView] { view.isHidden = true }
        let dim = !row.inScope
        let ink = dim ? Tok.Ink.tertiary : Tok.Ink.primary
        let meta = dim ? Tok.Ink.tertiary : Tok.Ink.secondary
        label.font = Tok.Face.nsData(Tok.Typography.Size.md)
        label.attributedStringValue = NSAttributedString()
        label.textColor = meta.nsColor
        switch column {
        case .dot:
            dot.color = row.dotColor.nsColor
            dot.isHidden = false
        case .seq:
            label.stringValue = row.isReplay ? "\(row.seq) ↻" : "\(row.seq)"
            label.isHidden = false
        case .url:
            label.attributedStringValue = urlText(row, dim: dim)
            label.isHidden = false
        case .client:
            if let client = row.client {
                monogram.text = client.monogram
                monogram.isHidden = false
                label.font = Tok.Face.nsUI(Tok.Typography.Size.md)
                label.stringValue = client.name
            } else {
                label.stringValue = Format.dash
            }
            label.isHidden = false
        case .method:
            badge.text = row.method.label
            badge.pair = row.method.badge
            badge.uppercase = true
            badge.isHidden = false
        case .status:
            switch row.state {
            case .paused:
                badge.text = "Paused"
                badge.pair = ColorPair(fg: Tok.Intercept.deep, bg: Tok.Intercept.tint)
                badge.uppercase = false
                badge.isHidden = false
            case .killed:
                label.stringValue = "killed"
                label.textColor = row.statusColor.nsColor
                label.isHidden = false
            case .pending:
                label.stringValue = Format.dash
                label.textColor = row.statusColor.nsColor
                label.isHidden = false
            case .failed:
                label.stringValue = "error"
                label.textColor = row.statusColor.nsColor
                label.isHidden = false
            case .complete:
                label.stringValue = row.status.map(String.init) ?? Format.dash
                label.font = Tok.Face.nsData(Tok.Typography.Size.md, .medium)
                label.textColor = (dim ? Tok.Ink.tertiary : row.statusColor).nsColor
                label.isHidden = false
            }
        case .time:
            label.stringValue = Format.time(row.startedAt)
            label.isHidden = false
        case .duration:
            label.stringValue = row.state == .pending ? "…" : Format.duration(row.duration)
            label.isHidden = false
        case .request:
            label.stringValue = row.kind == .websocket ? row.wsFrames.map { "\($0.sent) ↑" } ?? Format.dash
                : Format.bytes(row.requestBytes)
            label.isHidden = false
        case .response:
            label.stringValue = row.kind == .websocket ? row.wsFrames.map { "\($0.received) ↓" } ?? Format.dash
                : Format.bytes(row.responseBytes)
            label.isHidden = false
        case .ssl:
            let (symbol, tint): (String?, NSColor) = switch row.tls {
            case .none: (nil, .clear)
            case .decrypted: (Tok.Glyph.lockOpen, meta.nsColor)
            case .tunnelled: (Tok.Glyph.lock, meta.nsColor)
            case .pinnedOrFailed: ("exclamationmark.triangle", Tok.Status.clientError.nsColor)
            }
            if let symbol {
                icon.image = NSImage(systemSymbolName: symbol, accessibilityDescription: row.tls.help)
                icon.contentTintColor = tint
                icon.isHidden = false
            }
        case .edited:
            if row.edited {
                icon.image = NSImage(systemSymbolName: Tok.Glyph.compose, accessibilityDescription: "Edited while paused")
                icon.contentTintColor = meta.nsColor
                icon.isHidden = false
            }
        case .origin:
            if row.origin == .agent {
                badge.text = "agent"
                badge.pair = ColorPair(fg: Tok.Agent.deep, bg: Tok.Agent.tint)
                badge.uppercase = false
                badge.font = Tok.Face.nsUI(Tok.Typography.Size.xs)
                badge.isHidden = false
            }
        case .mark:
            if let mark = row.mark {
                swatch.layer?.backgroundColor = mark.color.cgColor
                swatch.isHidden = false
            }
        }
        toolTip = column == .url ? row.url : column == .ssl ? row.tls.help : nil
        _ = ink
    }

    /// Host in ink, path in the link colour, query dimmed; killed rows struck through.
    private func urlText(_ row: FlowRow, dim: Bool) -> NSAttributedString {
        let font = Tok.Face.nsData(Tok.Typography.Size.md)
        let killed = row.state == .killed
        let host = dim || killed ? Tok.Ink.tertiary : Tok.Ink.primary
        let path = dim || killed ? Tok.Ink.tertiary : Tok.Ink.link
        let text = NSMutableAttributedString()
        text.append(NSAttributedString(string: row.site, attributes: [.font: font, .foregroundColor: host.nsColor]))
        text.append(NSAttributedString(string: row.path, attributes: [.font: font, .foregroundColor: path.nsColor]))
        if let query = row.query {
            text.append(NSAttributedString(string: "?\(query)", attributes: [.font: font, .foregroundColor: Tok.Ink.tertiary.nsColor]))
        }
        if killed {
            text.addAttribute(.strikethroughStyle, value: NSUnderlineStyle.single.rawValue,
                              range: NSRange(location: 0, length: text.length))
        }
        return text
    }
}

extension TLSState {
    var help: String {
        switch self {
        case .none: "Plain HTTP"
        case .decrypted: "Decrypted (MITM)"
        case .tunnelled: "Tunnelled — not decrypted"
        case .pinnedOrFailed: "Upstream cert pinned or handshake failed — tunnelled"
        }
    }
}

/// An 8px status dot.
final class DotView: NSView {
    var color: NSColor = .clear { didSet { needsDisplay = true } }
    override func draw(_ dirtyRect: NSRect) {
        color.setFill()
        NSBezierPath(ovalIn: bounds).fill()
    }
}

/// A method/status badge: tint background, deep text, 18px, radius 4, 11/600 mono.
final class BadgeView: NSView {
    var text = "" { didSet { invalidateIntrinsicContentSize(); needsDisplay = true } }
    var pair = Tok.Method.head { didSet { needsDisplay = true } }
    var uppercase = true
    var font: NSFont = Tok.Face.nsData(Tok.Typography.Size.xs, .semibold) {
        didSet { invalidateIntrinsicContentSize(); needsDisplay = true }
    }

    private var attributed: NSAttributedString {
        NSAttributedString(string: uppercase ? text.uppercased() : text,
                           attributes: [.font: font, .foregroundColor: pair.fg.nsColor])
    }

    override var intrinsicContentSize: NSSize {
        NSSize(width: ceil(attributed.size().width) + 12, height: Tok.Size.badge)
    }

    override func draw(_ dirtyRect: NSRect) {
        pair.bg.nsColor.setFill()
        NSBezierPath(roundedRect: bounds, xRadius: Tok.Radius.badge, yRadius: Tok.Radius.badge).fill()
        let size = attributed.size()
        attributed.draw(at: NSPoint(x: (bounds.width - size.width) / 2, y: (bounds.height - size.height) / 2))
    }
}

/// The 16px monogram disc for the Client column.
final class MonogramView: NSView {
    var text = "" { didSet { needsDisplay = true } }
    override func draw(_ dirtyRect: NSRect) {
        let path = NSBezierPath(roundedRect: bounds.insetBy(dx: 0.5, dy: 0.5), xRadius: Tok.Radius.badge, yRadius: Tok.Radius.badge)
        Tok.Ground.raised.nsColor.setFill()
        path.fill()
        Tok.Line.control.nsColor.setStroke()
        path.stroke()
        let attributed = NSAttributedString(string: text, attributes: [
            .font: Tok.Face.nsUI(Tok.Typography.Size.xs, .medium), .foregroundColor: Tok.Ink.secondary.nsColor,
        ])
        let size = attributed.size()
        attributed.draw(at: NSPoint(x: (bounds.width - size.width) / 2, y: (bounds.height - size.height) / 2))
    }
}
