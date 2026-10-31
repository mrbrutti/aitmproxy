import AitmproxyKit
import SwiftUI

/// How a `LaneState` looks, once, for every connection indicator (sidebar row, toolbar
/// pill, status bar, Status page). Hue only on state; the word always travels with it.
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

    /// The glyph for places that cannot draw a dot (the sidebar chip).
    var symbol: String {
        switch self {
        case .ok: "checkmark.circle.fill"
        case .working: "hourglass"
        case .off: "circle"
        case .warning: "exclamationmark.circle.fill"
        case .error: "xmark.circle.fill"
        }
    }
}

/// A status dot and its word, the compact form of one lane.
struct LaneDot: View {
    var lane: ConnectionLane
    /// Show the word only when something needs attention (the pill stays calm when all is well).
    var quietWhenOK = false

    var body: some View {
        HStack(spacing: Tok.Metric.gapTight) {
            Circle().fill(lane.state.color.color).frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
            if !(quietWhenOK && lane.state == .ok) {
                Text(lane.word)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(lane.kind.title): \(lane.word)")
        .accessibilityValue(lane.detail)
    }
}
