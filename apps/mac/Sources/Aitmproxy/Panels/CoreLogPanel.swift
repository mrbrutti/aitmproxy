import AitmproxyKit
import SwiftUI

/// The on-demand core-log panel (Task 8, spec C4): a right-side panel, 360 wide
/// behind a rule, that shows the embedded core's captured stdout/stderr when the
/// operator opens it (Proxy ▸ Core Log, ⌃⌘L). Not an always-on tail — it is
/// opened on demand. The stream is token-free and free of handshake spam by
/// construction (Layer A), which is what makes it safe to show.
struct CoreLogPanel: View {
    @Environment(Session.self) private var session

    static let panelWidth: CGFloat = 360

    private var state: CoreHealthState { session.coreHealth }

    var body: some View {
        VStack(spacing: 0) {
            header
            Rule()
            if let reason = state.connection?.status.degradedReason {
                degraded(reason)
                Rule(color: Tok.Line.rule)
            }
            let lines = state.log.lines
            if lines.isEmpty {
                Text(emptyText)
                    .font(Tok.Face.ui(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, Space.md)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(lines) { line in
                                Text(line.text)
                                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                                    .foregroundStyle(Tok.Ink.secondary.color)
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(.vertical, Space.xs)
                                    // Shares the PageHeader's leading edge.
                                    .padding(.horizontal, Space.margin)
                                    .id(line.id)
                            }
                        }
                        .padding(.vertical, Space.xs)
                    }
                    .onChange(of: lines.last?.id) {
                        if let last = lines.last?.id { proxy.scrollTo(last, anchor: .bottom) }
                    }
                    .onAppear {
                        if let last = lines.last?.id { proxy.scrollTo(last, anchor: .bottom) }
                    }
                }
            }
        }
        .frame(width: Self.panelWidth)
        .frame(maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .overlay(alignment: .leading) { VRule() }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Core log")
    }

    private var header: some View {
        PageHeader("Core Log") {
            if let connection = state.connection {
                HStack(spacing: Tok.Metric.gapTight) {
                    Circle().fill(connection.health.dotColor.color)
                        .frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
                    Text(connection.status.healthTitle)
                        .font(Tok.Face.data(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.secondary.color)
                }
            }
        }
    }

    private func degraded(_ reason: String) -> some View {
        Text(reason)
            .font(Tok.Face.data(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Status.serverError.color)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Space.margin)
            .padding(.vertical, Space.sm)
    }

    private var emptyText: String {
        state.connection == nil
            ? "No embedded core — the app is connected to an external core."
            : "No core output yet."
    }
}
