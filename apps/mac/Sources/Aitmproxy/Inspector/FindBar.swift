import AitmproxyKit
import SwiftUI

/// Find in body (S-029): the query, its matches in the text the viewer
/// shows, and the current match. Case-insensitive; `isRegex` switches to a
/// regular expression, and an invalid one yields no matches and `isInvalid`.
@Observable
final class FindState {
    var query = "" { didSet { if query != oldValue { run() } } }
    var isRegex = false { didSet { if isRegex != oldValue { run() } } }
    private(set) var matches: [Range<String.Index>] = []
    private(set) var current: Int?
    private(set) var isInvalid = false
    /// The text the matches index into (the viewer's displayed text).
    private(set) var text = ""

    init(query: String = "", isRegex: Bool = false) {
        self.query = query
        self.isRegex = isRegex
    }

    /// Re-runs the query over `text`; keeps the current index when it still exists.
    func search(in text: String) {
        self.text = text
        run()
    }

    func next() {
        guard !matches.isEmpty else { return }
        current = ((current ?? -1) + 1) % matches.count
    }

    func previous() {
        guard !matches.isEmpty else { return }
        current = ((current ?? 0) - 1 + matches.count) % matches.count
    }

    /// Drops the matches but keeps the query, so reopening the bar restores it.
    func clear() {
        matches = []
        current = nil
        isInvalid = false
    }

    /// `3 of 12`, `0 of 0`.
    var counterText: String { "\(matches.isEmpty ? 0 : (current ?? 0) + 1) of \(matches.count)" }

    private func run() {
        do {
            matches = try BodySearch.ranges(of: query, in: text, regex: isRegex)
            isInvalid = false
        } catch {
            matches = []
            isInvalid = true
        }
        if matches.isEmpty {
            current = nil
        } else if let current, current < matches.count {
            self.current = current
        } else {
            current = 0
        }
    }
}

/// The 28 pt find field for the tab bar's trailing slot: "Find in body",
/// `n of m`, a flat `(.*)` regex toggle. ⏎ / ⇧⏎ step, Esc dismisses. The
/// lead binds ⌥⌘F to `isPresented`.
struct FindBar: View {
    @Bindable var state: FindState
    @Binding var isPresented: Bool
    @FocusState private var focused: Bool

    init(state: FindState, isPresented: Binding<Bool>) {
        self.state = state
        _isPresented = isPresented
    }

    var body: some View {
        HStack(spacing: Tok.Metric.gapTight) {
            Image(systemName: Tok.Glyph.search)
                .font(.system(size: Tok.Size.iconInline))
                .foregroundStyle(Tok.Ink.secondary.color)
            TextField("Find in body", text: $state.query)
                .textFieldStyle(.plain)
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.primary.color)
                .focused($focused)
                .onKeyPress(.return, phases: .down) { press in
                    if press.modifiers.contains(.shift) { state.previous() } else { state.next() }
                    return .handled
                }
                .onKeyPress(.escape) {
                    dismiss()
                    return .handled
                }
                .accessibilityLabel("Find in body")
            Text(state.counterText)
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle((state.matches.isEmpty ? Tok.Ink.tertiary : Tok.Ink.secondary).color)
                .lineLimit(1)
                .fixedSize()
                .accessibilityLabel("Matches")
                .accessibilityValue(state.matches.isEmpty ? "No matches" : "Match \(state.counterText)")
            Button {
                state.isRegex.toggle()
            } label: {
                Text("(.*)")
                    .font(Tok.Face.data(Tok.Typography.Size.xs, state.isRegex ? .medium : .regular))
                    .foregroundStyle((state.isRegex ? Tok.Ink.primary : Tok.Ink.tertiary).color)
                    .frame(width: Space.xxl, height: Space.xxl)
                    .background(state.isRegex ? Tok.Ground.active.color : .clear, in: RoundedRectangle(cornerRadius: Tok.Radius.badge))
            }
            .buttonStyle(.plain)
            .help("Regular expression")
            .accessibilityLabel("Regular expression")
            .accessibilityAddTraits(state.isRegex ? .isSelected : [])
        }
        .padding(.leading, Space.sm)
        .padding(.trailing, 2)
        .frame(width: 240, height: Tok.Size.control) // grid: ok the 28 pt find field (S-029), 240 wide
        .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
        .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control)
            .strokeBorder((state.isInvalid ? Tok.Intercept.deep : Tok.Line.control).color))
        .onAppear { focused = true }
        .onChange(of: isPresented) { _, shown in
            if shown { focused = true }
        }
        .onExitCommand { dismiss() }
    }

    private func dismiss() {
        state.clear()
        isPresented = false
    }
}
