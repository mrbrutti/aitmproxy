import AitmproxyKit
import AppKit
import SwiftUI

/// A read-only (or plainly editable) code viewer over `NSTextView`, for
/// bodies too large for the SwiftUI `CodeView`: 13 mono on 20 pt lines, a
/// 44 pt line-number ruler, syntax runs applied off the main actor, find
/// highlights on `Syntax.match` with the current one outlined in the accent.
struct CodeTextView: NSViewRepresentable {
    var text: String
    var contentType: String?
    var bodySize: CGFloat = Tok.Typography.Size.md
    var editable = false
    var highlights: [Range<String.Index>] = []
    var currentHighlight: Int?
    var onTextChange: ((String) -> Void)?

    init(text: String, contentType: String?, bodySize: CGFloat = Tok.Typography.Size.md, editable: Bool = false,
         highlights: [Range<String.Index>] = [], currentHighlight: Int? = nil, onTextChange: ((String) -> Void)? = nil) {
        self.text = text
        self.contentType = contentType
        self.bodySize = bodySize
        self.editable = editable
        self.highlights = highlights
        self.currentHighlight = currentHighlight
        self.onTextChange = onTextChange
    }

    /// Fold chevrons draw on `{` / `[` / element lines; clicking them is off
    /// until folding is proven safe against find ranges and line numbers.
    /// TODO (story S-021): fold by swapping the range for a `…` attachment and
    /// keeping the original text in a side table; remap highlights and line starts.
    static let foldingEnabled = false

    func makeCoordinator() -> Coordinator { Coordinator() }

    static func dismantleNSView(_ scrollView: NSScrollView, coordinator: Coordinator) {
        coordinator.detach()
    }

    func makeNSView(context: Context) -> NSScrollView {
        let storage = NSTextStorage()
        let layout = MatchLayoutManager(accent: NSColor(Palette.accent))
        layout.allowsNonContiguousLayout = true
        storage.addLayoutManager(layout)
        let container = NSTextContainer(containerSize: CGSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude))
        container.widthTracksTextView = false
        container.lineFragmentPadding = Tok.Metric.gapMeta
        layout.addTextContainer(container)

        let textView = NSTextView(frame: .zero, textContainer: container)
        textView.isEditable = editable
        // Stable identifier for the editable Raw request editor (CUA / accessibility).
        if editable { textView.setAccessibilityIdentifier("raw-request-editor") }
        textView.isSelectable = true
        textView.isRichText = false
        textView.usesFontPanel = false
        textView.usesFindBar = false
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.isAutomaticTextReplacementEnabled = false
        textView.isAutomaticSpellingCorrectionEnabled = false
        textView.isContinuousSpellCheckingEnabled = false
        textView.allowsUndo = true
        textView.focusRingType = .none
        textView.drawsBackground = true
        textView.backgroundColor = Tok.Ground.surface.nsColor
        textView.insertionPointColor = Tok.Ink.primary.nsColor
        textView.isHorizontallyResizable = true
        textView.isVerticallyResizable = true
        textView.maxSize = CGSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.autoresizingMask = [.width]
        textView.textContainerInset = CGSize(width: 0, height: Space.sm)
        textView.delegate = context.coordinator

        let scrollView = NSScrollView()
        scrollView.documentView = textView
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.drawsBackground = true
        scrollView.backgroundColor = Tok.Ground.surface.nsColor
        scrollView.borderType = .noBorder
        scrollView.focusRingType = .none
        let ruler = LineNumberRuler(scrollView: scrollView)
        ruler.coordinator = context.coordinator
        scrollView.verticalRulerView = ruler
        scrollView.hasVerticalRuler = true
        scrollView.rulersVisible = true

        context.coordinator.attach(textView: textView, ruler: ruler, scrollView: scrollView)
        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        let c = context.coordinator
        c.onTextChange = onTextChange
        guard let textView = c.textView else { return }
        textView.isEditable = editable
        if c.text != text || c.contentType != contentType || c.bodySize != bodySize {
            c.load(text: text, contentType: contentType, bodySize: bodySize)
        }
        c.apply(highlights: highlights, current: currentHighlight)
    }

    // MARK: Coordinator

    final class Coordinator: NSObject, NSTextViewDelegate {
        weak var textView: NSTextView?
        weak var ruler: LineNumberRuler?
        var onTextChange: ((String) -> Void)?
        private(set) var text = ""
        private(set) var contentType: String?
        private(set) var bodySize: CGFloat = 0
        /// UTF-16 offset of every line's first character; `[0]` for an empty text.
        private(set) var lineStarts: [Int] = [0]
        /// Zero-based lines that open a `{`, `[` or element.
        private(set) var foldableLines: Set<Int> = []
        private var generation = 0
        private var work: Task<Void, Never>?
        private var appliedHighlights: [Range<String.Index>] = []
        private var appliedCurrent: Int?
        private var observer: NSObjectProtocol?
        private var colours: [SyntaxKind: NSColor] = [:]

        func attach(textView: NSTextView, ruler: LineNumberRuler, scrollView: NSScrollView) {
            self.textView = textView
            self.ruler = ruler
            scrollView.contentView.postsBoundsChangedNotifications = true
            observer = NotificationCenter.default.addObserver(
                forName: NSView.boundsDidChangeNotification, object: scrollView.contentView, queue: .main
            ) { [weak ruler] _ in
                MainActor.assumeIsolated { ruler?.needsDisplay = true }
            }
        }

        /// Called from `dismantleNSView`: a deinit cannot touch main-actor state.
        func detach() {
            if let observer { NotificationCenter.default.removeObserver(observer) }
            observer = nil
            work?.cancel()
        }

        var baseAttributes: [NSAttributedString.Key: Any] {
            let style = NSMutableParagraphStyle()
            style.lineHeightMultiple = Tok.Typography.LineHeight.code
            return [
                .font: Tok.Face.nsData(bodySize),
                .foregroundColor: Tok.Ink.primary.nsColor,
                .paragraphStyle: style,
            ]
        }

        /// Shows `text` plainly at once, then colours it when the runs arrive.
        func load(text: String, contentType: String?, bodySize: CGFloat) {
            self.text = text
            self.contentType = contentType
            self.bodySize = bodySize
            generation += 1
            let gen = generation
            work?.cancel()
            guard let textView, let storage = textView.textStorage else { return }
            let attributes = baseAttributes
            storage.setAttributedString(NSAttributedString(string: text, attributes: attributes))
            textView.typingAttributes = attributes
            appliedHighlights = []
            appliedCurrent = nil
            foldableLines = []
            // Small bodies get their line numbers synchronously so nothing flashes in.
            lineStarts = text.utf16.count < 256_000 ? CodeAnalysis.lineStarts(text) : [0]
            ruler?.needsDisplay = true
            work = Task { [weak self] in
                let analysis = await CodeAnalysis.analyse(text: text, contentType: contentType)
                guard !Task.isCancelled, let self, self.generation == gen else { return }
                self.lineStarts = analysis.lineStarts
                self.foldableLines = analysis.foldableLines
                self.ruler?.needsDisplay = true
                await self.applyRuns(analysis.runs, generation: gen)
            }
        }

        /// Applies foreground colours in slices between run-loop turns, so a
        /// million-run body never holds the main thread for a whole frame.
        private func applyRuns(_ runs: [CodeAnalysis.Run], generation gen: Int) async {
            guard let storage = textView?.textStorage else { return }
            let length = storage.length
            var index = 0
            while index < runs.count {
                guard generation == gen, !Task.isCancelled else { return }
                let end = min(index + 6000, runs.count)
                storage.beginEditing()
                for run in runs[index..<end] where NSMaxRange(run.range) <= length {
                    storage.addAttribute(.foregroundColor, value: colour(run.kind), range: run.range)
                }
                storage.endEditing()
                index = end
                await Task.yield()
            }
        }

        private func colour(_ kind: SyntaxKind) -> NSColor {
            if let cached = colours[kind] { return cached }
            let colour = kind.color.nsColor
            colours[kind] = colour
            return colour
        }

        /// Match backgrounds as temporary attributes (no text-storage edit), the current one outlined by the layout manager.
        func apply(highlights: [Range<String.Index>], current: Int?) {
            guard highlights != appliedHighlights || current != appliedCurrent else { return }
            guard let textView, let layout = textView.layoutManager, let storage = textView.textStorage else { return }
            appliedHighlights = highlights
            appliedCurrent = current
            let whole = NSRange(location: 0, length: storage.length)
            layout.removeTemporaryAttribute(.backgroundColor, forCharacterRange: whole)
            let match = Tok.Syntax.match.nsColor
            for range in highlights {
                let nsRange = NSRange(range, in: text)
                guard NSMaxRange(nsRange) <= storage.length else { continue }
                layout.addTemporaryAttribute(.backgroundColor, value: match, forCharacterRange: nsRange)
            }
            let matchLayout = layout as? MatchLayoutManager
            if let current, highlights.indices.contains(current) {
                let nsRange = NSRange(highlights[current], in: text)
                guard NSMaxRange(nsRange) <= storage.length else { return }
                matchLayout?.setCurrentMatch(nsRange)
                textView.scrollRangeToVisible(nsRange)
            } else {
                matchLayout?.setCurrentMatch(nil)
            }
        }

        /// Zero-based line holding the UTF-16 offset.
        func line(at offset: Int) -> Int {
            var low = 0
            var high = lineStarts.count - 1
            while low < high {
                let mid = (low + high + 1) / 2
                if lineStarts[mid] <= offset { low = mid } else { high = mid - 1 }
            }
            return low
        }

        var currentLine: Int? {
            guard let textView, textView.window?.firstResponder === textView else { return nil }
            return line(at: textView.selectedRange().location)
        }

        // NSTextViewDelegate

        func textDidChange(_ notification: Notification) {
            guard let textView else { return }
            text = textView.string
            lineStarts = CodeAnalysis.lineStarts(text)
            ruler?.needsDisplay = true
            onTextChange?(text)
        }

        func textViewDidChangeSelection(_ notification: Notification) {
            ruler?.needsDisplay = true
        }
    }
}

/// Draws the 2 px accent outline around the current find match. Not
/// main-actor isolated because `NSLayoutManager` is not; AppKit calls it on main.
nonisolated final class MatchLayoutManager: NSLayoutManager {
    private let accent: NSColor
    /// The current find match, in characters. Set through `setCurrentMatch` so both the old and the new rect redraw.
    private(set) var currentMatch: NSRange?

    init(accent: NSColor) {
        self.accent = accent
        super.init()
    }

    required init?(coder: NSCoder) {
        accent = .controlAccentColor
        super.init(coder: coder)
    }

    func setCurrentMatch(_ range: NSRange?) {
        if let old = currentMatch { invalidateDisplay(forCharacterRange: old) }
        currentMatch = range
        if let range { invalidateDisplay(forCharacterRange: range) }
    }

    override func drawBackground(forGlyphRange glyphsToShow: NSRange, at origin: NSPoint) {
        super.drawBackground(forGlyphRange: glyphsToShow, at: origin)
        guard let match = currentMatch, let container = textContainers.first else { return }
        let glyphs = glyphRange(forCharacterRange: match, actualCharacterRange: nil)
        guard NSIntersectionRange(glyphs, glyphsToShow).length > 0 else { return }
        enumerateEnclosingRects(forGlyphRange: glyphs, withinSelectedGlyphRange: NSRange(location: NSNotFound, length: 0),
                                in: container) { rect, _ in
            let path = NSBezierPath(rect: rect.offsetBy(dx: origin.x, dy: origin.y).insetBy(dx: 1, dy: 1))
            path.lineWidth = 2
            self.accent.setStroke()
            path.stroke()
        }
    }
}

/// The 44 pt gutter: numbers 11 mono right-aligned in `Syntax.lineNumber`,
/// the current line's in `Ink.secondary`, a flat chevron on foldable lines.
final class LineNumberRuler: NSRulerView {
    weak var coordinator: CodeTextView.Coordinator?
    static let width: CGFloat = 44 // grid: ok gutter width from the foundation

    init(scrollView: NSScrollView) {
        super.init(scrollView: scrollView, orientation: .verticalRuler)
        ruleThickness = Self.width
        clientView = scrollView.documentView
    }

    required init(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    override var isFlipped: Bool { true }
    override var requiredThickness: CGFloat { Self.width }

    override func drawHashMarksAndLabels(in rect: NSRect) {
        Tok.Ground.surface.nsColor.setFill()
        bounds.fill()
        guard let coordinator, let textView = clientView as? NSTextView,
              let layout = textView.layoutManager, let container = textView.textContainer else { return }
        let starts = coordinator.lineStarts
        let visible = textView.visibleRect
        let glyphs = layout.glyphRange(forBoundingRect: visible, in: container)
        let characters = layout.characterRange(forGlyphRange: glyphs, actualGlyphRange: nil)
        let current = coordinator.currentLine
        let font = Tok.Face.nsData(Tok.Typography.Size.xs)
        let numberColour = Tok.Syntax.lineNumber.nsColor
        let currentColour = Tok.Ink.secondary.nsColor
        let chevron = NSImage(systemSymbolName: "chevron.down", accessibilityDescription: "Fold")?
            .withSymbolConfiguration(.init(pointSize: Tok.Size.iconInline, weight: .regular).applying(.init(paletteColors: [numberColour])))
        let length = (textView.string as NSString).length
        var line = coordinator.line(at: characters.location)
        while line < starts.count, starts[line] <= NSMaxRange(characters) {
            let start = starts[line]
            let fragment: NSRect
            if start >= length {
                fragment = layout.extraLineFragmentRect
                if fragment.isEmpty { break }
            } else {
                fragment = layout.lineFragmentRect(forGlyphAt: layout.glyphIndexForCharacter(at: start), effectiveRange: nil)
            }
            let top = convert(NSPoint(x: 0, y: fragment.minY + textView.textContainerInset.height), from: textView).y
            let lineRect = NSRect(x: 0, y: top, width: Self.width, height: fragment.height)
            let label = NSAttributedString(string: String(line + 1), attributes: [
                .font: font, .foregroundColor: line == current ? currentColour : numberColour,
            ])
            let size = label.size()
            label.draw(at: NSPoint(x: Self.width - Tok.Metric.gapTight - size.width, y: lineRect.midY - size.height / 2))
            if let chevron, coordinator.foldableLines.contains(line) {
                let side = Tok.Size.iconInline
                chevron.draw(in: NSRect(x: Space.xs, y: lineRect.midY - side / 2, width: side, height: side))
            }
            line += 1
        }
    }
}
