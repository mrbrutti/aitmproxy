import AitmproxyKit
import AppKit

/// One cell. A label for text columns; a small drawn view for the dot, the
/// method/status badges, the padlock, the origin tag and the mark swatch; the
/// client's icon or process mark (icons spec D6) ahead of its name.
final class FlowCellView: NSTableCellView {
    let column: FlowColumn
    private let label = NSTextField(labelWithString: "")
    private let badge = BadgeView()
    private let dot = DotView()
    private let icon = NSImageView()
    private let swatch = NSView()
    /// The Client column's mark: the owner's icon, the process glyph, or empty while
    /// the identity is pending (never the glyph while pending). Internal so a harness can read it.
    let clientIcon = NSImageView()
    /// The identifier this cell last showed: a pending verdict is applied only while it still matches
    /// (cells are reused).
    private var shownIdentifier: String?
    /// The identifier this cell has a pending `onResolve` callback for (stage-6 security on #272):
    /// a cell reconfigured every tick while a lookup is in flight registers once, not once per tick.
    private var awaitingIdentifier: String?
    /// The tint the pending mark should take when the verdict lands (the latest configure wins).
    private var pendingTint: NSColor?

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
        for view in [label, badge, dot, icon, swatch, clientIcon] as [NSView] {
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
            clientIcon.centerYAnchor.constraint(equalTo: centerYAnchor),
            clientIcon.leadingAnchor.constraint(equalTo: leadingAnchor, constant: pad),
            clientIcon.widthAnchor.constraint(equalToConstant: Tok.Size.icon),
            clientIcon.heightAnchor.constraint(equalToConstant: Tok.Size.icon),
        ])
        if column == .client {
            label.leadingAnchor.constraint(equalTo: clientIcon.trailingAnchor, constant: Tok.Metric.gapTight).isActive = true
        } else {
            label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: pad).isActive = true
        }
        swatch.wantsLayer = true
        swatch.layer?.cornerRadius = 2
        icon.symbolConfiguration = .init(pointSize: 12, weight: .regular)
        icon.contentTintColor = Tok.Ink.secondary.nsColor
        clientIcon.imageScaling = .scaleProportionallyUpOrDown
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

    func configure(_ row: FlowRow, density: Density = .dense) {
        for view in [label, badge, dot, icon, swatch, clientIcon] as [NSView] { view.isHidden = true }
        shownIdentifier = nil
        let dim = !row.inScope
        let ink = dim ? Tok.Ink.tertiary : Tok.Ink.primary
        let meta = dim ? Tok.Ink.tertiary : Tok.Ink.secondary
        let body = density.bodySize
        label.font = Tok.Face.nsData(body)
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
            if let l4 = row.l4 {
                label.attributedStringValue = l4Text(l4, dim: dim, size: body)
            } else {
                label.attributedStringValue = urlText(row, dim: dim, size: body)
            }
            label.isHidden = false
        case .client:
            if let client = row.client {
                // Icon + name (icons spec D6): the same text as the sidebar's app row, "(Service)" included.
                let identifier = client.bundleID ?? client.name
                shownIdentifier = identifier
                clientIcon.isHidden = false
                label.font = Tok.Face.nsUI(body)
                label.stringValue = client.name
                if let identity = AppIdentityResolver.shared.identity(for: identifier) {
                    awaitingIdentifier = nil
                    pendingTint = nil
                    applyClientMark(identity, name: client.name, tint: meta.nsColor)
                } else {
                    // Pending: an empty mark keeps the label's x; the verdict lands through the callback
                    // only if this reused cell still shows the same identifier.
                    clientIcon.image = nil
                    pendingTint = meta.nsColor
                    if awaitingIdentifier != identifier {
                        awaitingIdentifier = identifier
                        AppIdentityResolver.shared.onResolve(identifier) { [weak self] identity in
                            guard let self else { return }
                            if self.awaitingIdentifier == identifier { self.awaitingIdentifier = nil }
                            guard self.shownIdentifier == identifier else { return }
                            // The label already carries the latest configure's name; the tint likewise.
                            self.applyClientMark(identity, name: self.label.stringValue, tint: self.pendingTint ?? meta.nsColor)
                            self.clientIcon.setAccessibilityElement(self.clientIcon.image != nil)
                        }
                    }
                }
            } else {
                awaitingIdentifier = nil
                pendingTint = nil
                label.stringValue = Format.dash
            }
            label.isHidden = false
        case .method:
            // L4 wears the slate/indigo kind badge; HTTP/WS wear the method badge.
            if row.kind == .l4 {
                badge.text = "L4"
                badge.pair = Tok.L4.badge
            } else {
                badge.text = row.method.label
                badge.pair = row.method.badge
            }
            badge.uppercase = true
            badge.isHidden = false
        case .status:
            if let l4 = row.l4 {
                // The L4 Status cell shows the session state (capture / craft / intercept).
                label.stringValue = l4.sessionState.label
                label.textColor = (l4.sessionState == .intercept ? Tok.Intercept.deep : meta).nsColor
                label.isHidden = false
                break
            }
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
                label.font = Tok.Face.nsData(body, .medium)
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
            if let l4 = row.l4 {
                label.stringValue = "\(l4.packetCount) pkt"
            } else {
                label.stringValue = row.kind == .websocket ? row.wsFrames.map { "\($0.sent) ↑" } ?? Format.dash
                    : Format.bytes(row.requestBytes)
            }
            label.isHidden = false
        case .response:
            if let l4 = row.l4 {
                label.stringValue = l4.injectedCount > 0 ? "\(l4.injectedCount) inj" : Format.dash
            } else {
                label.stringValue = row.kind == .websocket ? row.wsFrames.map { "\($0.received) ↓" } ?? Format.dash
                    : Format.bytes(row.responseBytes)
            }
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
            } else if row.origin == .imported {
                // From a file (S-065): a neutral tag, no hue — nothing happened on the wire.
                badge.text = "imported"
                badge.pair = ColorPair(fg: Tok.Ink.secondary, bg: Tok.Ground.raised)
                badge.uppercase = false
                badge.font = Tok.Face.nsUI(Tok.Typography.Size.xs)
                badge.isHidden = false
            }
        case .comment:
            label.font = Tok.Face.nsUI(body)
            label.stringValue = row.comment ?? ""
            label.textColor = ink.nsColor
            label.isHidden = false
        case .mark:
            if let mark = row.mark {
                swatch.layer?.backgroundColor = mark.color.cgColor
                swatch.isHidden = false
            }
        }
        toolTip = switch column {
        case .url: row.url
        case .ssl: row.tls.help
        case .comment: row.comment
        // The identifier, never the raw `bundleID` (icons spec D10, stage-6 S-M3): it is wire text.
        case .client: row.client.map { AppIdentifier.tooltipText($0.bundleID ?? $0.name) }
        default: nil
        }
        describeDrawnViews(row)
    }

    /// The Client mark for a verdict (icons spec D6): the owner's icon untouched (no tint, no
    /// template), else the process glyph in the cell's ink — secondary, tertiary out of scope.
    private func applyClientMark(_ identity: AppIdentity, name: String, tint: NSColor) {
        if let icon = identity.icon {
            clientIcon.image = icon
        } else {
            clientIcon.image = NSImage(systemSymbolName: Tok.Glyph.process, accessibilityDescription: name)
            clientIcon.symbolConfiguration = .init(pointSize: Tok.Size.iconInline, weight: .regular)
            clientIcon.contentTintColor = tint
        }
    }

    /// The drawn views (badge, dot, swatch, client mark) carry labels in the
    /// screen's words, so VoiceOver reads a cell the same as a sighted user (S-069).
    private func describeDrawnViews(_ row: FlowRow) {
        badge.setAccessibilityElement(!badge.isHidden)
        badge.setAccessibilityRole(.staticText)
        badge.setAccessibilityLabel(badge.text)
        dot.setAccessibilityElement(!dot.isHidden)
        dot.setAccessibilityRole(.image)
        dot.setAccessibilityLabel("\(row.state)")
        swatch.setAccessibilityElement(!swatch.isHidden)
        swatch.setAccessibilityRole(.image)
        swatch.setAccessibilityLabel(row.mark.map { "marked \($0.rawValue)" })
        clientIcon.setAccessibilityElement(!clientIcon.isHidden && clientIcon.image != nil)
        clientIcon.setAccessibilityRole(.image)
        clientIcon.setAccessibilityLabel(row.client?.name)
        icon.setAccessibilityLabel(icon.image?.accessibilityDescription)
    }

    /// The L4 row's target: a `[TCP]` sub-label in the slate/indigo hue, then the
    /// bound target (`iface · filter`). Out-of-scope rows dim.
    private func l4Text(_ info: L4RowInfo, dim: Bool, size: CGFloat) -> NSAttributedString {
        let font = Tok.Face.nsData(size)
        let sub = dim ? Tok.Ink.tertiary : Tok.L4.deep
        let target = dim ? Tok.Ink.tertiary : Tok.Ink.primary
        let text = NSMutableAttributedString()
        text.append(NSAttributedString(string: info.subLabel + "  ",
                                       attributes: [.font: Tok.Face.nsData(size, .medium), .foregroundColor: sub.nsColor]))
        text.append(NSAttributedString(string: info.target, attributes: [.font: font, .foregroundColor: target.nsColor]))
        return text
    }

    /// Host in ink, path in the link colour, query dimmed; killed rows struck through.
    private func urlText(_ row: FlowRow, dim: Bool, size: CGFloat) -> NSAttributedString {
        let font = Tok.Face.nsData(size)
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
