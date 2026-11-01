import AitmproxyKit
import SwiftUI

/// How a `LaneState` looks, once, for every connection indicator (the toolbar's connection
/// cluster, the Status page, the Core Log header). Hue only on state; the word always travels with it.
extension LaneState {
    var color: DynamicColor {
        switch self {
        case .ok: Tok.Status.success
        case .working: Tok.Intercept.base
        case .off: Tok.Ink.tertiary
        case .warning: Tok.State.warning.fg
        case .error: Tok.Status.serverError
        }
    }
}

/// A status dot and its word: the compact form of one lane, or of one fact that carries a
/// `LaneState` (the CA trust row and the first-run sheet).
struct LaneDot: View {
    var state: LaneState
    var word: String
    /// The spoken form, "<Lane>: <word>".
    var label: String
    var value: String?
    /// Show the lane only when it needs attention (the pill stays calm when all is well).
    var quietWhenOK = false

    init(lane: ConnectionLane, quietWhenOK: Bool = false) {
        state = lane.state
        word = lane.word
        label = "\(lane.kind.title): \(lane.word)"
        value = lane.detail
        self.quietWhenOK = quietWhenOK
    }

    init(state: LaneState, word: String, label: String) {
        self.state = state
        self.word = word
        self.label = label
    }

    var body: some View {
        if !(quietWhenOK && state == .ok) {
            if let value {
                dot.accessibilityValue(value)
            } else {
                dot
            }
        }
    }

    private var dot: some View {
        HStack(spacing: Tok.Metric.gapTight) {
            Circle().fill(state.color.color).frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
            Text(word)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
    }
}

/// The remedy line under a fact: small, wrapping, secondary unless the surface says otherwise.
struct RemedyText: View {
    var text: String
    var color: DynamicColor

    init(_ text: String, color: DynamicColor = Tok.Ink.secondary) {
        self.text = text
        self.color = color
    }

    var body: some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(color.color)
            .fixedSize(horizontal: false, vertical: true)
    }
}
