import AitmproxyKit
import SwiftUI

/// The embedded core's always-visible health dot (Task 8, spec C4): a coloured
/// dot and a word — running / restarting / failed — mapped from the core
/// connection's status. It carries the quietly-surfaced facts too: the proxy
/// port the core actually bound (an auto-chosen alternate when the default was
/// taken, C3) and, when a restart gives up, the `.degraded` reason with the
/// captured stderr tail. Clicking it opens the on-demand core-log panel.
///
/// It lives in the status bar beside the bus dot; the bus dot reports the
/// client↔bus link, this one reports the child core process the app manages.
struct CoreHealthDot: View {
    var connection: CoreConnection
    /// Opens the core-log panel (the same action as Proxy ▸ Core Log).
    var openLog: () -> Void

    private var health: CoreHealth { connection.health }

    var body: some View {
        Button(action: openLog) {
            HStack(spacing: Tok.Metric.gapTight) {
                Circle()
                    .fill(health.dotColor.color)
                    .frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
                Text(health.statusWord)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(helpText)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Embedded core: \(health.statusWord)")
        .accessibilityValue(connection.status.degradedReason ?? connection.label)
        .accessibilityHint("Opens the core log")
    }

    /// The state word, then the label (which carries the bound proxy port once
    /// ready), then the failure reason and stderr tail when degraded.
    private var helpText: String {
        var lines = [health.statusWord.capitalized, connection.label]
        if let reason = connection.status.degradedReason { lines.append(reason) }
        return lines.joined(separator: "\n")
    }
}

extension CoreHealth {
    /// The one status-bar word per core state, shared by the toolbar pill and
    /// the health dot so they never disagree (B10). Lower case: it follows a
    /// dot or a "·" mid-sentence.
    var statusWord: String {
        switch self {
        case .running: "core running"
        case .restarting: "restarting…"
        case .failed: "core failed"
        }
    }
}
