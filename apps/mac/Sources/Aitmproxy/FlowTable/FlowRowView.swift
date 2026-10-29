import AppKit

/// One row: `surface` ground, a 1px `rule` separator, the `active` tint when
/// selected (never the accent), and a 2px left edge for paused/agent flows.
final class FlowRowView: NSTableRowView {
    var leftEdge: NSColor? {
        didSet { if leftEdge != oldValue { needsDisplay = true } }
    }

    /// The pointer is over this row. Hover never moves the selection (foundation §2.8).
    private(set) var hovered = false {
        didSet { if hovered != oldValue { needsDisplay = true } }
    }

    override var isEmphasized: Bool {
        get { true }
        set {}
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        for area in trackingAreas { removeTrackingArea(area) }
        addTrackingArea(NSTrackingArea(rect: bounds, options: [.mouseEnteredAndExited, .activeInKeyWindow, .inVisibleRect],
                                       owner: self, userInfo: nil))
    }

    override func mouseEntered(with event: NSEvent) { hovered = true }
    override func mouseExited(with event: NSEvent) { hovered = false }

    override func prepareForReuse() {
        super.prepareForReuse()
        hovered = false
    }

    override func drawBackground(in dirtyRect: NSRect) {
        (hovered ? Tok.Ground.hover : Tok.Ground.surface).nsColor.setFill()
        bounds.fill()
        drawDecorations()
    }

    override func drawSelection(in dirtyRect: NSRect) {
        Tok.Ground.active.nsColor.setFill()
        bounds.fill()
        drawDecorations()
    }

    private func drawDecorations() {
        Tok.Line.rule.nsColor.setFill()
        NSRect(x: 0, y: bounds.maxY - 1, width: bounds.width, height: 1).fill()
        if let leftEdge {
            leftEdge.setFill()
            NSRect(x: 0, y: 0, width: 2, height: bounds.height).fill()
        }
    }
}

/// The header strip: `surface` with a 1px `border` under it, 28px tall.
final class FlowHeaderView: NSTableHeaderView {
    override func draw(_ dirtyRect: NSRect) {
        Tok.Ground.surface.nsColor.setFill()
        bounds.fill()
        super.draw(dirtyRect)
        Tok.Line.border.nsColor.setFill()
        NSRect(x: 0, y: bounds.maxY - 1, width: bounds.width, height: 1).fill()
    }
}

/// Column titles: 12pt UI face, `text.secondary`, no bevel.
final class FlowHeaderCell: NSTableHeaderCell {
    override func draw(withFrame cellFrame: NSRect, in controlView: NSView) {
        Tok.Ground.surface.nsColor.setFill()
        cellFrame.fill()
        drawInterior(withFrame: cellFrame, in: controlView)
    }

    override func drawInterior(withFrame cellFrame: NSRect, in controlView: NSView) {
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = alignment
        paragraph.lineBreakMode = .byTruncatingTail
        let attributes: [NSAttributedString.Key: Any] = [
            .font: Tok.Face.nsUI(Tok.Typography.Size.xs, .medium),
            .foregroundColor: Tok.Ink.tertiary.nsColor,
            .kern: 0.5,
            .paragraphStyle: paragraph,
        ]
        let text = NSAttributedString(string: stringValue.uppercased(), attributes: attributes)
        let height = text.size().height
        let rect = NSRect(x: cellFrame.minX + 8, y: cellFrame.midY - height / 2,
                          width: cellFrame.width - 16, height: height)
        text.draw(in: rect)
    }

    /// A small ↑ / ↓ in the tertiary tier instead of the system chevron (S-009).
    override func drawSortIndicator(withFrame cellFrame: NSRect, in controlView: NSView, ascending: Bool, priority: Int) {
        let glyph = NSAttributedString(string: ascending ? "↑" : "↓", attributes: [
            .font: Tok.Face.nsUI(Tok.Typography.Size.xs, .medium), .foregroundColor: Tok.Ink.tertiary.nsColor,
        ])
        let size = glyph.size()
        let x = alignment == .right ? cellFrame.minX + 2 : cellFrame.maxX - size.width - 4
        glyph.draw(at: NSPoint(x: x, y: cellFrame.midY - size.height / 2))
    }
}
