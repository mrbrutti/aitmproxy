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

/// A status dot and its word, the compact form of one lane.
struct LaneDot: View {
    var lane: ConnectionLane
    /// Show the lane only when it needs attention (the pill stays calm when all is well).
    var quietWhenOK = false

    var body: some View {
        if !(quietWhenOK && lane.state == .ok) {
            HStack(spacing: Tok.Metric.gapTight) {
                Circle().fill(lane.state.color.color).frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
                Text(lane.word)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("\(lane.kind.title): \(lane.word)")
            .accessibilityValue(lane.detail)
        }
    }
}
