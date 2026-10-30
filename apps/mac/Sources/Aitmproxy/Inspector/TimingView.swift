import AitmproxyKit
import SwiftUI

/// The Timing tab (S-020): one bar per phase, proportional to the longest,
/// in the tertiary tier with the duration printed beside it; the total under
/// them. A missing phase prints a dash and no bar; a real zero prints `0 ms`.
/// No timing (the live bus does not carry phase timings yet, F5): a follow-up
/// notice, not perpetual loading bars.
struct TimingView: View {
    var timing: FlowTiming?
    /// The row's Duration column, when known; printed beside the sum if they differ.
    var total: Duration?

    var body: some View {
        if let timing {
            VStack(alignment: .leading, spacing: Space.sm) {
                ForEach(FlowTiming.Phase.allCases, id: \.self) { phase in
                    PhaseRow(phase: phase, duration: timing.duration(of: phase), longest: longest(timing))
                }
                Text(totalText(timing))
                    .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .padding(.top, Space.xs)
                Spacer()
            }
            .padding(Space.md)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            // flow.detail never carries timing on the live bus yet, so a nil
            // here means the core has not landed F5 — say so (like the web
            // TimingTab and the TUI) rather than spinning loading bars forever.
            VStack(spacing: Space.xs) {
                Text("Timing needs core follow-up F5")
                    .font(Tok.Face.ui(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                if let total {
                    Text("total \(Format.duration(total))")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                }
            }
            .padding(Space.md)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func longest(_ timing: FlowTiming) -> Duration {
        FlowTiming.Phase.allCases.compactMap(timing.duration(of:)).max() ?? .zero
    }

    /// `total 412 ms`, or `total 412 ms · row 415 ms` when the row's Duration disagrees.
    private func totalText(_ timing: FlowTiming) -> String {
        let sum = timing.total
        if let total, total != sum {
            return "total \(Format.duration(sum)) · row \(Format.duration(total))"
        }
        return "total \(Format.duration(sum))"
    }
}

/// `Wait  ▬▬▬▬▬▬▬  289 ms`
private struct PhaseRow: View {
    var phase: FlowTiming.Phase
    var duration: Duration?
    var longest: Duration

    var body: some View {
        HStack(spacing: Space.md) {
            Text(phase.rawValue)
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: 72, alignment: .leading)
            GeometryReader { geo in
                RoundedRectangle(cornerRadius: Tok.Radius.badge)
                    .fill(Self.color(for: phase))
                    .frame(width: barWidth(in: geo.size.width), height: Space.sm)
            }
            .frame(height: Space.sm)
            Text(Format.duration(duration))
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(duration == nil ? Tok.Ink.tertiary.color : Tok.Ink.primary.color)
                .frame(width: 64, alignment: .trailing)
        }
        .frame(height: Space.xl)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(phase.rawValue)
        .accessibilityValue(duration.map(Format.duration) ?? "not reported")
    }

    /// Each phase a distinct hue, waterfall-style (dns · connect · tls · wait · download).
    private static let phaseColors: [Color] = [
        Tok.Mark.purple.color, Tok.Mark.blue.color, Tok.Mark.green.color, Tok.Mark.orange.color, Tok.Mark.teal.color,
    ]

    private static func color(for phase: FlowTiming.Phase) -> Color {
        let index = FlowTiming.Phase.allCases.firstIndex(of: phase) ?? 0
        return phaseColors[index % phaseColors.count]
    }

    private func barWidth(in available: CGFloat) -> CGFloat {
        guard let duration, duration > .zero, longest > .zero else { return 0 }
        let fraction = seconds(duration) / seconds(longest)
        return max(2, available * fraction)
    }

    private func seconds(_ d: Duration) -> Double {
        Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
    }
}

/// The Connection tab (S-020): protocol · tls · alpn · sni · client · server
/// in the header-table style, the tls row carrying the padlock and its meaning.
struct ConnectionTable: View {
    var connection: ConnectionInfo
    var tls: TLSState

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                row("protocol") { value(connection.httpVersion) }
                row("tls") {
                    if let glyph {
                        Image(systemName: glyph.name)
                            .font(.system(size: Tok.Size.iconInline))
                            .foregroundStyle(glyph.color.color)
                            .accessibilityHidden(true)
                    }
                    value(connection.tlsVersion ?? "none")
                    Text(tls.help)
                        .foregroundStyle(Tok.Ink.tertiary.color)
                        .lineLimit(1)
                }
                row("alpn") { value(connection.alpn) }
                row("sni") { value(connection.sni) }
                row("client") { value(connection.clientAddress) }
                row("server") { value(connection.serverAddress) }
            }
        }
    }

    private var glyph: (name: String, color: DynamicColor)? {
        switch tls {
        case .none: nil
        case .decrypted: (Tok.Glyph.lockOpen, Tok.Ink.secondary)
        case .tunnelled: (Tok.Glyph.lock, Tok.Ink.secondary)
        case .pinnedOrFailed: ("exclamationmark.triangle", Tok.Status.clientError)
        }
    }

    private func row<Content: View>(_ name: String, @ViewBuilder content: () -> Content) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Space.md) {
            Text(name)
                .foregroundStyle(Tok.Syntax.key.color)
                .frame(width: 180, alignment: .leading)
            HStack(spacing: Space.sm) { content() }
            Spacer(minLength: 0)
        }
        .font(Tok.Face.data(Tok.Typography.Size.md))
        .padding(.horizontal, Space.md)
        .frame(minHeight: Tok.Size.Row.dense)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .help(name == "tls" ? tls.help : "")
        .accessibilityElement(children: .combine)
    }

    private func value(_ text: String?) -> some View {
        Text(text ?? Format.dash)
            .foregroundStyle(text == nil ? Tok.Ink.tertiary.color : Tok.Ink.primary.color)
            .textSelection(.enabled)
    }
}
