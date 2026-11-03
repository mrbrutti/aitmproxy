import AitmproxyKit
import SwiftUI

// The Jobs tab's shared pieces (Jobs view spec D10–D12): the row's ring and
// dots, the card's chip, the one tone → token mapping, the two motion modifiers
// and the raised-card chrome. `ScanPanel+Jobs.swift` (the table) and
// `ScanJobCard.swift` (the card) both draw from here; `ScanJobWells.swift` uses
// the chrome. Every colour, radius and duration is a `Tok.*` or `ScanMotion`
// token; the comp's geometric constants are `CardMetrics` (ScanJobCard.swift).
// No view here owns a timer: the ring follows the facts and the breathing is a
// system-driven repeating animation (AC32).

// MARK: - Tone colours

/// The one place a `ScanJobTone` becomes colours (D11): the card's edge and the
/// row's state dot take the pair's foreground; the chip takes both.
enum ScanToneColors {
    static func edge(_ tone: ScanJobTone) -> Color { pair(tone).fg.color }
    static func chipForeground(_ tone: ScanJobTone) -> Color { pair(tone).fg.color }
    static func chipBackground(_ tone: ScanJobTone) -> Color { pair(tone).bg.color }

    /// A severity's ink (the ledger marks, the count words, the Issues cells); a
    /// level this build does not know falls back to the info ink so a newer core
    /// never leaves a gap.
    static func severity(_ severity: ScanSeverity) -> Color {
        (severity.known?.pair ?? Tok.Severity.info).fg.color
    }

    private static func pair(_ tone: ScanJobTone) -> (fg: DynamicColor, bg: DynamicColor) {
        switch tone {
        case .progress: (Tok.Accent.base, Tok.Accent.tint)
        case .pending: (Tok.Intercept.base, Tok.Intercept.tint)
        case .success: (Tok.State.success.fg, Tok.State.success.bg)
        case .danger: (Tok.State.danger.fg, Tok.State.danger.bg)
        case .neutral: (Tok.State.neutral.fg, Tok.State.neutral.bg)
        }
    }
}

// MARK: - Ring and dots

/// The row's 18 pt progress slot (D10): a determinate ring trimmed to the fraction
/// in `Tok.Accent.base` over a `Tok.Line.control` track, starting at twelve
/// o'clock and easing to each new value; the system's small spinner while
/// indeterminate; an empty slot for a finished or unknown ring (the row shows a
/// `ScanStateDot` then). Hidden from VoiceOver: the row's label reads the percent.
struct ScanProgressRing: View {
    var ring: ScanJobProgress.Ring
    var reduceMotion: Bool

    var body: some View {
        Group {
            switch ring {
            case .determinate(let fraction):
                ZStack {
                    Circle().stroke(Tok.Line.control.color, lineWidth: CardMetrics.ringStroke)
                    Circle()
                        .trim(from: 0, to: fraction)
                        .stroke(Tok.Accent.base.color, style: StrokeStyle(lineWidth: CardMetrics.ringStroke, lineCap: .round))
                        .rotationEffect(.degrees(CardMetrics.ringStart))
                }
                // Half the stroke sits outside a shape's frame; inset so the ring is not clipped.
                .padding(CardMetrics.ringStroke / 2)
                .animation(reduceMotion ? nil : ScanMotion.ease(ScanMotion.progress), value: fraction)
            case .indeterminate:
                ProgressView().controlSize(.small)
            case .none, .finished:
                Color.clear
            }
        }
        .frame(width: Tok.Size.badge, height: Tok.Size.badge)
        .accessibilityHidden(true)
    }
}

/// A 6 pt dot in the tone's colour (D10): the row's State cell for a cancelling or
/// terminal job. It breathes only while `breathing` (the cancelling dot) and
/// Reduce Motion is off (D12).
struct ScanStateDot: View {
    var tone: ScanJobTone
    var breathing: Bool
    var reduceMotion: Bool

    var body: some View {
        let dot = Circle()
            .fill(ScanToneColors.edge(tone))
            .frame(width: CardMetrics.dot, height: CardMetrics.dot)
        Group {
            if breathing, !reduceMotion {
                dot.modifier(Breathing())
            } else {
                dot
            }
        }
        .accessibilityHidden(true)
    }
}

/// The agent-originated mark (D10): a 6 pt `Tok.Agent.base` dot in a 3 pt
/// `Tok.Agent.tint` halo, with the Kit's help text as its tooltip.
struct ScanAgentDot: View {
    var body: some View {
        Circle()
            .fill(Tok.Agent.base.color)
            .frame(width: CardMetrics.dot, height: CardMetrics.dot)
            .padding(CardMetrics.dotHalo)
            .background(Circle().fill(Tok.Agent.tint.color))
            .help(ScanFormat.agentDotHelp)
            .accessibilityHidden(true)
    }
}

// MARK: - Chip

/// The card's state chip (D11): a 22 pt pill in the tone pair with a static 6 pt
/// dot before the word. The word crossfades and the pair recolours over
/// `ScanMotion.state` (D12); both are opacity and colour, so Reduce Motion keeps them.
struct ScanStateChip: View {
    var word: String
    var tone: ScanJobTone

    var body: some View {
        HStack(spacing: Tok.Metric.gapTight) {
            Circle()
                .fill(ScanToneColors.chipForeground(tone))
                .frame(width: CardMetrics.dot, height: CardMetrics.dot)
            Text(word)
                .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
                .contentTransition(.opacity)
                .animation(ScanMotion.ease(ScanMotion.state), value: word)
        }
        .foregroundStyle(ScanToneColors.chipForeground(tone))
        .padding(.horizontal, CardMetrics.chipPadding)
        .frame(height: Tok.Metric.chip)
        .background(ScanToneColors.chipBackground(tone), in: RoundedRectangle(cornerRadius: Tok.Radius.pill))
        .animation(ScanMotion.ease(ScanMotion.state), value: tone)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Motion

/// The breathing (D12): opacity 1 → `CardMetrics.breathFloor` and back on the pulse
/// curve, forever, started once on appear by a system-driven repeating animation.
/// Applied to exactly two dots: the lane's now dot while the job is live and not
/// cancelling, and the cancelling dot. Callers skip it under Reduce Motion.
struct Breathing: ViewModifier {
    @State private var on = true

    func body(content: Content) -> some View {
        content
            .opacity(on ? 1 : CardMetrics.breathFloor)
            .onAppear { withAnimation(ScanMotion.breathe()) { on = false } }
    }
}

/// The one named entrance (D12): when `generation` changes the block takes a new
/// identity and rises `CardMetrics.entranceRise` while fading in, `index` stagger
/// steps after the first block. Under Reduce Motion it only fades. `generation` is
/// `ScanPanelState.entranceGeneration`, which never moves for a keyboard selection
/// or a status beat, so this never fires for either.
struct CardEntrance: ViewModifier {
    var index: Int
    var generation: Int
    var reduceMotion: Bool

    func body(content: Content) -> some View {
        content
            .id(generation)
            .transition(reduceMotion ? .opacity : .opacity.combined(with: .offset(y: CardMetrics.entranceRise))) // grid: ok D12 entrance travel, a transition, not a layout nudge
            .animation(ScanMotion.ease(ScanMotion.entrance).delay(Double(index) * ScanMotion.stagger), value: generation)
    }
}

// MARK: - Card chrome

/// The raised-card chrome the job card and the wells share (D11): `Tok.Ground.card`,
/// a 1 pt `Tok.Line.border`, `Tok.Radius.floating`, and the token shadow the caller
/// names (`Tok.Shadow.float` for the card, `Tok.Shadow.rest` for a well) in the
/// mode's opacity. Content is clipped to the radius, so an edge overlay applied
/// before this modifier follows the corners.
struct ScanCardChrome: ViewModifier {
    var shadow: FloatingShadow
    @Environment(\.colorScheme) private var colorScheme

    func body(content: Content) -> some View {
        content
            .background(Tok.Ground.card.color, in: RoundedRectangle(cornerRadius: Tok.Radius.floating))
            .clipShape(RoundedRectangle(cornerRadius: Tok.Radius.floating))
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.floating).strokeBorder(Tok.Line.border.color))
            .shadow(
                color: .black.opacity(colorScheme == .dark ? shadow.darkOpacity : shadow.lightOpacity),
                radius: shadow.radius, y: shadow.y)
    }
}

extension View {
    /// The raised-card chrome with the given token shadow (D11).
    func scanCardChrome(shadow: FloatingShadow) -> some View {
        modifier(ScanCardChrome(shadow: shadow))
    }

    /// One block of the card's staggered entrance (D12).
    func cardEntrance(index: Int, generation: Int, reduceMotion: Bool) -> some View {
        modifier(CardEntrance(index: index, generation: generation, reduceMotion: reduceMotion))
    }
}
