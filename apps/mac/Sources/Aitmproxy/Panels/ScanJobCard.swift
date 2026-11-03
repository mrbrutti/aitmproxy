import AitmproxyKit
import SwiftUI

// MARK: - Comp constants

/// The locked comp's geometric constants that are not tokens (Jobs view spec D11;
/// `docs/design/mockup/scan-jobs/committed.html`), each named after the CSS rule
/// it comes from. Everything else the Jobs views draw is a `Tok.*` or `ScanMotion`
/// token (AC22). Internal rather than private because `ScanProgressViews.swift`
/// draws the ring, the dots, the chip and the entrance from the same numbers;
/// nonisolated because they are constants and the table's `Layout` (nonisolated by
/// its protocol) builds its columns from them once.
nonisolated enum CardMetrics {
    /// `.card::before { width: 3px }` — the card's tone edge; also the selected row's edge (D10).
    static let edge: CGFloat = 3
    /// `.now { width: 2px }` — the lane's now mark.
    static let nowMark: CGFloat = 2
    /// `.now { top: -10px; bottom: -10px }` — how far the mark overshoots the track.
    static let nowOvershoot: CGFloat = 10
    /// `.now::after { width: 10px; height: 10px }` — the breathing dot on the mark.
    static let nowDot: CGFloat = 10
    /// `.now { box-shadow: 0 0 0 3px rgba(230,230,232,.12) }` — the mark's halo width …
    static let haloWidth: CGFloat = 3
    /// … and the halo's opacity from the same rule.
    static let haloOpacity: Double = 0.12
    /// `.chip i`, `.who`, `.pend`, `.ok { width: 6px; height: 6px }` — the state, chip and agent dots.
    static let dot: CGFloat = 6
    /// `.who { box-shadow: 0 0 0 3px var(--agent-tint) }` — the agent dot's halo.
    static let dotHalo: CGFloat = 3
    /// `.gauge { height: 3px }` — the probe budget gauge.
    static let gauge: CGFloat = 3
    /// `.group i { width: 8px }` — one ledger mark's width …
    static let markWidth: CGFloat = 8
    /// `.group i { height: 16px }` — … its height …
    static let markHeight: CGFloat = 16
    /// `.group i { border-radius: 2px }` — … and its corner.
    static let markRadius: CGFloat = 2
    /// `.group { gap: 3px }` — between two marks of one ledger group.
    static let markGap: CGFloat = 3
    /// `<circle stroke-width="2.5">` in `.ring` — the row's progress ring.
    static let ringStroke: CGFloat = 2.5
    /// `.ring .arc { transform: rotate(-90 9 9) }` — the arc starts at twelve o'clock.
    static let ringStart: Double = -90
    /// `.seg.crawl` — the crawl cap is as wide as its labels, about 80 pt (D11 §2: the
    /// bus carries no crawl duration, so the cap is layout, not a proportion).
    static let crawlCapWidth: CGFloat = 80
    /// `.seg .lbl { white-space: nowrap }`, `.rest` — no comp rule sizes this: the room a
    /// segment or the empty part must offer before its labels show (D11 §2, builder's
    /// call); about the width of `46 pages, 12 queued` in the data face at UI sm.
    static let laneLabelRoom: CGFloat = 140
    /// `.seg .lbl { top: 10px }`, `.seg .sub { bottom: 10px }`, `.rest { top: 10px }` — the
    /// lane labels' vertical inset (the 12 pt horizontal inset is `Space.md`).
    static let laneLabelInset: CGFloat = 10
    /// `.seg .sub { opacity: .75 }` — a segment's lower label.
    static let laneSubOpacity: Double = 0.75
    /// `.track { box-shadow: inset 0 1px 0 rgba(255,255,255,.03) }` — the track's 1 pt top highlight.
    static let trackHighlightOpacity: Double = 0.03
    /// `.scale { margin-top: 40px }` — the scale row sits 40 pt under the track; the now
    /// tag (`.nowtag { top: 76px }`, 12 pt = `Space.md` under the 64 pt track) lives in that gap.
    static let scaleGap: CGFloat = 40
    /// `.ledger { margin-top: 14px }`, `.budget { margin-top: 14px }` — the ledger under the
    /// scale row and the gauge under the ledger.
    static let ledgerGap: CGFloat = 14
    /// `.kpis div { padding: 14px 16px }` — a KPI cell's vertical padding (16 is `Space.lg`).
    static let kpiPaddingVertical: CGFloat = 14
    /// `td { height: 46px }` on the 4 pt grid — the row pitch (D10).
    static let rowPitch: CGFloat = 44
    /// `th { height: 32px }` — the table header.
    static let headerHeight: CGFloat = 32
    /// `th:last-child, td:last-child { width: 84px }` — the trailing action column.
    static let actionColumn: CGFloat = 84
    /// `table { width: 100% }`, `td { white-space: nowrap }` — the comp's auto table sizes
    /// its other eight columns by content; D10 fixes them in points. The three flexible
    /// columns (State, Target, Progress) take D10's minimums as shares of the leftover
    /// (`ScanJobsColumns`); the rest are fixed. State: min 148 pt …
    static let tableStateShare: CGFloat = 148
    /// … Profile: 120 pt …
    static let tableProfileWidth: CGFloat = 120
    /// … Target: min 220 pt (data face) …
    static let tableTargetShare: CGFloat = 220
    /// … Progress: min 220 pt (data face) …
    static let tableProgressShare: CGFloat = 220
    /// … Probes: 120 pt, right-aligned …
    static let tableProbesWidth: CGFloat = 120
    /// … Points: 120 pt, right-aligned …
    static let tablePointsWidth: CGFloat = 120
    /// … Issues: 124 pt, right-aligned …
    static let tableIssuesWidth: CGFloat = 124
    /// … and Elapsed: 80 pt, right-aligned.
    static let tableElapsedWidth: CGFloat = 80
    /// `.enter { transform: translateY(8px) }` — the entrance's rise.
    static let entranceRise: CGFloat = 8
    /// `@keyframes breathe { to { opacity: .4 } }` — the breathing floor.
    static let breathFloor: Double = 0.4
    /// `.chip { padding: 0 9px }` — the chip's horizontal padding (its 22 pt height is `Tok.Metric.chip`).
    static let chipPadding: CGFloat = 9
    /// `.nowtag { transform: translateY(2px) }` under `.enter`, `@keyframes rise { from {
    /// translateY(3px) scaleY(.6) } }` — the end swap's and a ledger mark's travel and
    /// the mark's starting scale (D12).
    static let swapTravel: CGFloat = 2
    static let markTravel: CGFloat = 3
    static let markScale: CGFloat = 0.6
}

// MARK: - Inked text

/// One `Text` from several, joined by interpolation (`+` on `Text` is deprecated on
/// macOS 26), and the two inkings the card repeats: a number run in the data face and
/// one named token (a check id) in the data face.
private enum ScanInked {
    static func joined(_ parts: [Text]) -> Text {
        parts.reduce(Text(verbatim: "")) { Text("\($0)\($1)") }
    }

    /// `text` with the one `token` it contains set in the data face and `tokenInk`
    /// (the now tag's check id); `text` unchanged when the token is absent.
    static func token(_ text: String, token: String?, size: CGFloat, ink: Color, tokenInk: Color) -> Text {
        guard let token, !token.isEmpty, let range = text.range(of: token) else {
            return Text(verbatim: text).font(Tok.Face.ui(size)).foregroundStyle(ink)
        }
        return joined([
            Text(verbatim: String(text[..<range.lowerBound])).font(Tok.Face.ui(size)).foregroundStyle(ink),
            Text(verbatim: token).font(Tok.Face.data(size)).foregroundStyle(tokenInk),
            Text(verbatim: String(text[range.upperBound...])).font(Tok.Face.ui(size)).foregroundStyle(ink),
        ])
    }

    /// `text` with every run of digits and their separators (`11:32`, `1:04`, `3,236`) in
    /// the data face, the words in the UI face, all in `ink` (the scale row).
    static func digits(_ text: String, size: CGFloat, ink: Color) -> Text {
        var parts: [Text] = []
        var run = ""
        var runIsDigits = false
        func flush() {
            guard !run.isEmpty else { return }
            parts.append(Text(verbatim: run).font(runIsDigits ? Tok.Face.data(size) : Tok.Face.ui(size)))
            run = ""
        }
        for character in text {
            let digit = character.isNumber || (runIsDigits && (character == ":" || character == "," || character == "."))
            if digit != runIsDigits {
                flush()
                runIsDigits = digit
            }
            run.append(character)
        }
        flush()
        return joined(parts).foregroundStyle(ink)
    }
}

// MARK: - Card

/// The selected job's card (Jobs view D11): the inspect-and-act surface at the top
/// of the Jobs column, on the raised chrome with a 3 pt edge in the job's tone. The
/// title row with the verbs, the scan lane with the ledger and the gauge, the KPI
/// strip and the attention block, each carrying its part of the one entrance (D12).
/// The card reads the merged facts (D2) and the derived progress (D8) and computes no
/// number of its own; its verb slot reads `state.verbsEnabled`, never the 1 Hz `link`
/// (plan gap 34d), so a clock tick re-evaluates nothing here.
struct ScanJobCard: View {
    var state: ScanPanelState
    var facts: ScanJobFacts
    var progress: ScanJobProgress
    var reduceMotion: Bool
    /// The tab's entrance generation (D12): the card's blocks enter when it changes.
    var generation: Int
    /// The card's first enabled verb takes focus when the tab sets this (D14).
    var inspectorFocused: FocusState<Bool>.Binding
    /// Escape from the verbs: the tab returns focus to the table (D14).
    var onEscape: () -> Void

    private var tone: ScanJobTone { ScanFormat.tone(facts) }
    private var by: BySeverity { facts.summary.issues.bySeverity }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.lg) {
            ScanJobTitleRow(
                state: state, facts: facts, reduceMotion: reduceMotion, inspectorFocused: inspectorFocused,
                onEscape: onEscape
            )
            .cardEntrance(index: 0, generation: generation, reduceMotion: reduceMotion)
            VStack(alignment: .leading, spacing: CardMetrics.ledgerGap) {
                ScanJobLane(progress: progress, facts: facts, reduceMotion: reduceMotion, verbsEnabled: state.verbsEnabled)
                ScanIssueLedger(
                    groups: ScanFormat.ledgerGroups(by: by), running: !facts.summary.state.isTerminal,
                    reduceMotion: reduceMotion, accessibilityLabel: ScanFormat.issuesTileHelp(by: by))
                ScanProbeGauge(
                    sent: facts.summary.probes.sent, budget: facts.summary.probes.budget, reduceMotion: reduceMotion)
            }
            .cardEntrance(index: 1, generation: generation, reduceMotion: reduceMotion)
            ScanKPIStrip(facts: facts, progress: progress, reduceMotion: reduceMotion)
                .padding(.top, Space.xs)
                .cardEntrance(index: 2, generation: generation, reduceMotion: reduceMotion)
            ScanAttentionBlock(facts: facts, launchNotices: state.surface.launchNotices[facts.job] ?? [])
        }
        .padding(.vertical, Space.xl)
        .padding(.horizontal, Space.xxl)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .leading) {
            // The tone edge, recoloured over `ScanMotion.state` on a state change (D12);
            // the chrome's clip rounds its ends to the card's corners.
            Rectangle()
                .fill(ScanToneColors.edge(tone))
                .frame(width: CardMetrics.edge)
                .animation(ScanMotion.ease(ScanMotion.state), value: tone)
        }
        .scanCardChrome(shadow: Tok.Shadow.float)
        .gridProbe("scan-job-card", area: "scan")
    }
}

// MARK: - Title row

/// The card's title row (D11 §1): the state chip, the host heading, the finding line
/// with its parts inked by role, and the verbs at the trailing edge: Show Site Map,
/// Show Issues, then the one primary, Cancel Scan while the job is live (titled by the
/// cancelling word and disabled while a cancel is on the wire or the core calls the job
/// cancelling, D2) or Scan Again once it has ended (D13). The slot is disabled while
/// `state.verbsEnabled` is false (D6, D15); Escape returns focus to the table and clears
/// the Scan Again refusal; the refusal's text sits under the row (D13).
struct ScanJobTitleRow: View {
    var state: ScanPanelState
    var facts: ScanJobFacts
    var reduceMotion: Bool
    var inspectorFocused: FocusState<Bool>.Binding
    var onEscape: () -> Void

    private var line: ScanFindingLine { ScanFormat.findingLine(facts, timeZone: .current) }
    private var terminal: Bool { facts.summary.state.isTerminal }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            HStack(alignment: .top, spacing: Space.md) {
                VStack(alignment: .leading, spacing: Space.xs) {
                    HStack(spacing: Space.md) {
                        // The chip's dot breathes while cancelling; the chip skips it under Reduce Motion (D12).
                        ScanStateChip(
                            word: ScanFormat.stateWord(facts), tone: ScanFormat.tone(facts),
                            breathing: facts.summary.state == .cancelling, reduceMotion: reduceMotion)
                        Text(ScanFormat.jobHeading(facts))
                            .font(Tok.Face.data(Tok.Typography.Size.xxl, .semibold))
                            .foregroundStyle(Tok.Ink.primary.color)
                            .lineLimit(1)
                            .help(ScanFormat.jobHeadingHelp(facts) ?? "")
                            .accessibilityAddTraits(.isHeader)
                    }
                    if let reason = line.reason {
                        Text(verbatim: reason)
                            .font(Tok.Face.ui(Tok.Typography.Size.base))
                            .foregroundStyle(Tok.Ink.secondary.color)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if !line.parts.isEmpty {
                        ScanInked.joined(line.parts.map(partText))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: Space.sm)
                verbs
            }
            if let error = state.surface.scanAgainError {
                // D13's `Unable to scan again: <display>` in the error ink (AC26).
                Text(verbatim: ScanFormat.scanAgainErrorPrefix + error.display)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Status.serverError.color)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// One finding-line part in its role's ink (D11 §1): plain words in the secondary
    /// ink, counts and check ids in the primary ink (ids in the data face), `an agent`
    /// in the agent ink.
    private func partText(_ part: ScanFindingLine.Part) -> Text {
        let size = Tok.Typography.Size.base
        return switch part.role {
        case .plain: Text(verbatim: part.text).font(Tok.Face.ui(size)).foregroundStyle(Tok.Ink.secondary.color)
        case .figure: Text(verbatim: part.text).font(Tok.Face.ui(size)).foregroundStyle(Tok.Ink.primary.color)
        case .checkId: Text(verbatim: part.text).font(Tok.Face.data(size)).foregroundStyle(Tok.Ink.primary.color)
        case .agent: Text(verbatim: part.text).font(Tok.Face.ui(size)).foregroundStyle(Tok.Agent.base.color)
        }
    }

    /// The verb slot. The primary swaps between Cancel Scan and Scan Again inside a
    /// `ZStack` under `ScanMotion.endSwap` when the merged state turns terminal (D12);
    /// the whole slot follows the clock-free verb gate (plan gap 34d).
    private var verbs: some View {
        HStack(spacing: Space.sm) {
            FlatButton("Show Site Map") { state.showSitemap(job: facts.job) }
                .focused(inspectorFocused)
                .help(ScanFormat.showSiteMapHelp)
                .accessibilityHint(ScanFormat.showSiteMapHelp)
            FlatButton("Show Issues") { state.showIssues(job: facts.job) }
                .help(ScanFormat.showIssuesHelp)
                .accessibilityHint(ScanFormat.showIssuesHelp)
            ZStack {
                if terminal {
                    scanAgainButton.transition(.swapTransition(reduceMotion: reduceMotion))
                } else {
                    primaryLiveVerb.transition(.swapTransition(reduceMotion: reduceMotion))
                }
            }
            .animation(ScanMotion.ease(ScanMotion.endSwap), value: terminal)
        }
        .frame(height: Tok.Size.controlLg)
        .disabled(!state.verbsEnabled)
        .onExitCommand {
            onEscape()
            state.surface.clearScanAgainError()
        }
    }

    /// Cancel Scan while the merged state is queued or running; the cancelling word,
    /// disabled, while a cancel is on the wire or the core calls the job cancelling (D2).
    @ViewBuilder
    private var primaryLiveVerb: some View {
        switch facts.summary.state {
        case .queued, .running:
            if state.cancelInFlight(facts.job) {
                cancellingButton
            } else {
                PrimaryButton("Cancel Scan") { Task { await state.cancel(job: facts.job) } }
                    .keyboardShortcut(".", modifiers: [.command, .option])
                    .help(ScanFormat.cancelScanHelp)
                    .accessibilityHint(ScanFormat.cancelScanHelp)
            }
        case .cancelling:
            cancellingButton
        default:
            EmptyView()
        }
    }

    private var cancellingButton: some View {
        PrimaryButton(ScanFormat.cancellingTitle) {}
            .disabled(true)
    }

    /// Scan Again for a finished job (D13): enabled by the state's one predicate
    /// (`scanAgainEnabled(for:)`: the Kit's gate, the verb gate, no launch on the wire, no
    /// confirm sheet up; the same guard `scanAgain(job:)` sends under); its help is the
    /// refusal when there is one, else the Kit's sentence naming the profile and the target.
    private var scanAgainButton: some View {
        let refusal = state.scanAgainRefusal(for: facts.job)
        let help = refusal ?? facts.status.map(ScanSurfaceModel.scanAgainHelp) ?? ScanFormat.scanAgainHelpGeneric
        return PrimaryButton("Scan Again") { Task { await state.scanAgain(job: facts.job) } }
            .disabled(!state.scanAgainEnabled(for: facts.job))
            .help(help)
            .accessibilityHint(help)
    }
}

// MARK: - Lane

/// The scan lane (D11 §2; the spec names it `ScanLane`, which is the Kit's lane enum, so
/// the view is `ScanJobLane`): the 64 pt raised track with the crawl cap, the audit fill
/// at the checks fraction, the right label, the now mark with its breathing dot and the
/// now tag under it, then the scale row. Every width is a fraction of the measured
/// track; the fill, the mark and the tag ease under `ScanMotion.progress` and the now
/// tag gives way to the end sentence under `ScanMotion.endSwap` (D12). One
/// accessibility element labelled `Progress` with the percent or the phase line (D14).
/// `verbsEnabled` is the state's clock-free verb gate (gap 34d): while the bus is away
/// the values are stale, so the now dot stops breathing but stays (D15).
struct ScanJobLane: View {
    var progress: ScanJobProgress
    var facts: ScanJobFacts
    var reduceMotion: Bool
    var verbsEnabled: Bool

    /// The now tag's measured width, for clamping it inside the track.
    @State private var tagWidth = CGFloat.zero

    private var summary: ScanJobSummary { facts.summary }
    private var status: ScanJobStatus? { facts.status }
    private var terminal: Bool { summary.state.isTerminal }
    /// Running or cancelling: the mark is shown (it fades under `endSwap` otherwise).
    private var marked: Bool { summary.state == .running || summary.state == .cancelling }
    /// The dot breathes only while running, with the bus live and Reduce Motion off (D12, D15).
    private var breathing: Bool { summary.state == .running && !reduceMotion && verbsEnabled }

    /// What the track draws, decided once from the merged state and phase (D11 §2).
    private enum Track: Equatable {
        /// Passive, queued, a running job without its status, an unknown state, or a
        /// finished job with no fraction: the line centred in the empty track.
        case text(String)
        /// Crawling (or finished with pages but nothing scheduled): one crawl segment.
        case crawl(fraction: Double)
        /// Auditing, reporting or finished with checks scheduled: the cap, then the fill;
        /// `scheduled == false` is auditing before anything is scheduled.
        case audit(fraction: Double, scheduled: Bool)
    }

    private var track: Track {
        switch summary.state {
        case .running, .cancelling:
            guard status != nil else { return .text(progress.phaseLine) }
            switch summary.phase {
            case .crawling:
                return progress.fraction.map { .crawl(fraction: $0) } ?? .text(progress.phaseLine)
            case .auditing:
                return .audit(fraction: progress.fraction ?? 0, scheduled: progress.fraction != nil)
            case .reporting:
                return .audit(fraction: 1, scheduled: true)
            case .passive, .queued, .done, .other:
                return .text(progress.phaseLine)
            }
        case .done, .cancelled, .failed:
            guard case .finished(let final) = progress.ring, let final else { return .text("") }
            if let checks = status?.checks, checks.scheduled > 0 { return .audit(fraction: final, scheduled: true) }
            return .crawl(fraction: final)
        case .queued, .other:
            return .text(progress.phaseLine)
        }
    }

    /// The value the eases follow: the fill's or the crawl segment's fraction.
    private var fillFraction: Double {
        switch track {
        case .text: 0
        case .crawl(let fraction): fraction
        case .audit(let fraction, _): fraction
        }
    }

    /// The now tag while live: the Kit's `now · <id>` form, or the phase line while
    /// reporting (`Writing results`, D11 §2); nil when terminal (the end sentence stands).
    private var tagText: String? {
        guard !terminal else { return nil }
        if summary.state == .running || summary.state == .cancelling, summary.phase == .reporting {
            return progress.phaseLine
        }
        return progress.nowTag
    }

    private var startedClock: String? {
        guard let status, status.startedAt > 0 else { return nil }
        return ScanFormat.clock(ms: status.startedAt, timeZone: .current)
    }

    /// The track's widths for one measured width.
    private struct Geometry {
        var cap: CGFloat
        var fill: CGFloat
        var crawl: CGFloat
        var rest: CGFloat
        var markX: CGFloat
        var markPresent: Bool
    }

    private func geometry(width: CGFloat) -> Geometry {
        switch track {
        case .text:
            return Geometry(cap: 0, fill: 0, crawl: 0, rest: width, markX: 0, markPresent: false)
        case .crawl(let fraction):
            let crawl = max(0, min(width, width * fraction))
            return Geometry(cap: 0, fill: 0, crawl: crawl, rest: width - crawl, markX: crawl, markPresent: false)
        case .audit(let fraction, let scheduled):
            let cap = min(CardMetrics.crawlCapWidth, width)
            let fill = scheduled ? max(0, min(width - cap, (width - cap) * fraction)) : 0
            return Geometry(
                cap: cap, fill: fill, crawl: 0, rest: width - cap - fill, markX: cap + fill, markPresent: scheduled)
        }
    }

    private var progressAnimation: Animation? { reduceMotion ? nil : ScanMotion.ease(ScanMotion.progress) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            GeometryReader { geo in
                let width = geo.size.width
                let g = geometry(width: width)
                VStack(alignment: .leading, spacing: 0) {
                    trackView(g)
                        .frame(height: Tok.Size.Row.card)
                    tagZone(g, width: width)
                        .frame(height: CardMetrics.scaleGap)
                }
            }
            .frame(height: Tok.Size.Row.card + CardMetrics.scaleGap)
            scaleRow
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(ScanFormat.kpiLabels[0])
        .accessibilityValue(ScanFormat.progressAccessibilityValue(progress) ?? progress.phaseLine)
        .help(progress.helpText)
    }

    // MARK: The track

    private func trackView(_ g: Geometry) -> some View {
        ZStack(alignment: .leading) {
            RoundedRectangle(cornerRadius: Tok.Radius.panel)
                .fill(Tok.Ground.raised.color)
            HStack(spacing: 0) {
                switch track {
                case .text(let line):
                    centred(line)
                case .crawl:
                    crawlSegment(width: g.crawl, lower: progress.phaseLine)
                    Spacer(minLength: 0)
                case .audit(_, let scheduled):
                    crawlSegment(width: g.cap, lower: ScanFormat.lanePages(status?.crawl.pages ?? 0))
                    if scheduled {
                        auditFill(width: g.fill)
                        Spacer(minLength: 0)
                    } else {
                        centred(progress.phaseLine)
                    }
                }
            }
            .animation(progressAnimation, value: fillFraction)
        }
        .overlay(alignment: .top) {
            Rectangle()
                .fill(Tok.Ink.primary.color.opacity(CardMetrics.trackHighlightOpacity))
                .frame(height: 1)
        }
        .clipShape(RoundedRectangle(cornerRadius: Tok.Radius.panel))
        .overlay(alignment: .topTrailing) {
            if let toGo = progress.checksToGoText, g.rest >= CardMetrics.laneLabelRoom {
                Text(verbatim: toGo)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .monospacedDigit()
                    .counterTick(value: toGo, reduceMotion: reduceMotion)
                    .padding(.top, CardMetrics.laneLabelInset)
                    .padding(.trailing, Space.md)
            }
        }
        .overlay(alignment: .leading) {
            if g.markPresent {
                nowMark
                    .padding(.leading, max(0, g.markX - CardMetrics.nowDot / 2))
                    .opacity(marked ? 1 : 0)
                    .animation(progressAnimation, value: fillFraction)
                    .animation(ScanMotion.ease(ScanMotion.endSwap), value: marked)
            }
        }
    }

    /// The phase line centred in the empty track (passive, queued, scheduling, no status).
    private func centred(_ line: String) -> some View {
        Text(verbatim: line)
            .font(Tok.Face.ui(Tok.Typography.Size.md))
            .foregroundStyle(Tok.Ink.secondary.color)
            .lineLimit(1)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// The crawl cap (or the crawling job's one segment) in `Tok.Accent.deep` with
    /// `crawl` over its pages label.
    private func crawlSegment(width: CGFloat, lower: String) -> some View {
        Rectangle()
            .fill(Tok.Accent.deep.color)
            .frame(width: width)
            .overlay(alignment: .leading) {
                segmentLabels(upper: ScanFormat.laneCrawlLabel, lower: lower, fits: width >= CardMetrics.crawlCapWidth)
            }
            .clipped()
    }

    /// The audit fill in `Tok.Accent.base` with `audit` over its checks-done label.
    private func auditFill(width: CGFloat) -> some View {
        Rectangle()
            .fill(Tok.Accent.base.color)
            .frame(width: width)
            .overlay(alignment: .leading) {
                segmentLabels(
                    upper: ScanFormat.laneAuditLabel, lower: ScanFormat.laneChecksDone(status?.checks.done ?? 0),
                    fits: width >= CardMetrics.laneLabelRoom)
            }
            .clipped()
    }

    /// A segment's two labels, 10 pt from the top and bottom and 12 pt from the left in
    /// the on-accent ink; hidden (and always clipped to the segment) when the segment is
    /// narrower than they need: `laneLabelRoom` for the fill and the crawling segment, the
    /// cap's own width for the cap, which is sized for its labels.
    private func segmentLabels(upper: String, lower: String, fits: Bool) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(verbatim: upper)
                .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
            Spacer(minLength: 0)
            Text(verbatim: lower)
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .opacity(CardMetrics.laneSubOpacity)
                .monospacedDigit()
                .counterTick(value: lower, reduceMotion: reduceMotion)
        }
        .lineLimit(1)
        .fixedSize()
        .foregroundStyle(Tok.Ink.onAccent.color)
        .padding(.vertical, CardMetrics.laneLabelInset)
        .padding(.leading, Space.md)
        .opacity(fits ? 1 : 0)
    }

    /// The now mark: a 2 pt line of the primary ink overshooting the track by 10 pt each
    /// way inside a 3 pt halo at 12 %, with the 10 pt dot centred on its top end; the dot
    /// breathes while the job is running, the bus is live and Reduce Motion is off (D12, D15).
    private var nowMark: some View {
        let height = Tok.Size.Row.card + 2 * CardMetrics.nowOvershoot
        let dot = Circle()
            .fill(Tok.Ink.primary.color)
            .frame(width: CardMetrics.nowDot, height: CardMetrics.nowDot)
        return ZStack(alignment: .top) {
            Rectangle()
                .fill(Tok.Ink.primary.color)
                .frame(width: CardMetrics.nowMark, height: height)
                .background(
                    RoundedRectangle(cornerRadius: CardMetrics.haloWidth)
                        .fill(Tok.Ink.primary.color.opacity(CardMetrics.haloOpacity))
                        .padding(-CardMetrics.haloWidth)
                )
                .padding(.vertical, CardMetrics.nowDot / 2)
            if breathing {
                dot.modifier(Breathing())
            } else {
                dot
            }
        }
        .frame(width: CardMetrics.nowDot, height: Tok.Size.Row.card)
        .accessibilityHidden(true)
    }

    // MARK: The tag zone

    /// Under the track: the now tag centred beneath the mark and clamped inside the
    /// track, or the end sentence left-aligned once the job has ended (empty for the beat
    /// before its terminal status lands); the two swap under `ScanMotion.endSwap`.
    private func tagZone(_ g: Geometry, width: CGFloat) -> some View {
        ZStack(alignment: .topLeading) {
            if terminal {
                if let sentence = ScanEndText.sentence(facts) {
                    Text(verbatim: sentence)
                        .font(Tok.Face.ui(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Ink.primary.color)
                        .lineLimit(1)
                        .transition(.swapTransition(reduceMotion: reduceMotion))
                }
            } else if let tag = tagText {
                ScanInked.token(
                    tag, token: status?.checks.running.first, size: Tok.Typography.Size.sm,
                    ink: Tok.Ink.secondary.color, tokenInk: Tok.Ink.primary.color
                )
                .lineLimit(1)
                .fixedSize()
                .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { tagWidth = $0 }
                .padding(.leading, min(max(0, g.markX - tagWidth / 2), max(0, width - tagWidth)))
                .animation(progressAnimation, value: fillFraction)
                .transition(.swapTransition(reduceMotion: reduceMotion))
            }
        }
        .padding(.top, Space.md)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .animation(ScanMotion.ease(ScanMotion.endSwap), value: terminal)
    }

    // MARK: The scale row

    /// `started 11:32` · `elapsed 1:04` · `at this pace, about 1:04 to go` in the tertiary
    /// ink, numbers in the data face; the started entry waits for the status, the
    /// estimate's slot is empty when the Kit derives none.
    private var scaleRow: some View {
        let size = Tok.Typography.Size.sm
        let ink = Tok.Ink.tertiary.color
        let elapsed = ScanFormat.scaleElapsed(ms: summary.elapsedMs)
        return HStack(spacing: Space.lg) {
            if let startedClock {
                ScanInked.digits(ScanFormat.scaleStarted(startedClock), size: size, ink: ink)
            }
            Spacer(minLength: 0)
            ScanInked.digits(elapsed, size: size, ink: ink)
                .monospacedDigit()
                .counterTick(value: elapsed, reduceMotion: reduceMotion)
            Spacer(minLength: 0)
            if let estimate = progress.estimateText {
                ScanInked.digits(estimate, size: size, ink: ink)
                    .monospacedDigit()
                    .counterTick(value: estimate, reduceMotion: reduceMotion)
                    .help(progress.estimateHelp ?? "")
            }
        }
        .lineLimit(1)
    }
}

// MARK: - Ledger

/// The issue ledger (D11 §3): one group per non-zero severity, critical → info, its
/// marks (capped by the Kit at 12) in the severity ink and the count word after them;
/// `no issues yet` / `no issues` when empty; a fixed minimum height so nothing shifts.
/// New marks rise in under `ScanMotion.entrance` (D12). One accessibility element
/// carrying the Kit's `4 issues: 4 low` (D14).
struct ScanIssueLedger: View {
    var groups: [ScanLedgerGroup]
    var running: Bool
    var reduceMotion: Bool
    var accessibilityLabel: String

    private var arrival: AnyTransition {
        reduceMotion
            ? .opacity
            : .opacity.combined(with: .offset(y: CardMetrics.markTravel)) // grid: ok D12 ledger mark arrival, a transition, not a layout nudge
                .combined(with: .scale(scale: CardMetrics.markScale, anchor: .bottom))
    }

    var body: some View {
        HStack(spacing: Space.lg) {
            if groups.isEmpty {
                Text(verbatim: ScanFormat.severityWords(by: .zero, running: running))
                    .foregroundStyle(Tok.Ink.tertiary.color)
            } else {
                ForEach(groups, id: \.severity) { group in
                    let ink = ScanToneColors.severity(group.severity)
                    HStack(spacing: CardMetrics.markGap) {
                        ForEach(0..<group.marks, id: \.self) { _ in
                            RoundedRectangle(cornerRadius: CardMetrics.markRadius)
                                .fill(ink)
                                .frame(width: CardMetrics.markWidth, height: CardMetrics.markHeight)
                                .transition(arrival)
                        }
                        Text(verbatim: group.word)
                            .foregroundStyle(ink)
                            .monospacedDigit()
                            .counterTick(value: group.word, reduceMotion: reduceMotion)
                            .padding(.leading, Tok.Metric.gapTight - CardMetrics.markGap)
                    }
                }
            }
        }
        .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
        .frame(minHeight: Space.xl, alignment: .leading)
        .animation(ScanMotion.ease(ScanMotion.entrance), value: groups)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityLabel)
    }
}

// MARK: - Gauge

/// The probe budget gauge (D11 §4): the label, a 3 pt raised track with the fill at
/// `sent / budget` in the tertiary ink, amber once the Kit's warning holds (colour
/// under `ScanMotion.state`, width under `ScanMotion.progress`), and the Kit's text;
/// the track is hidden when the budget is unknown. One accessibility element reading
/// the Kit's `Probe budget, 287 of 2,000` (D11 §4, D14).
struct ScanProbeGauge: View {
    var sent: Int
    var budget: Int
    var reduceMotion: Bool

    private var fraction: Double { budget > 0 ? min(1, max(0, Double(sent) / Double(budget))) : 0 }
    private var warning: Bool { ScanFormat.budgetWarning(sent: sent, budget: budget) }
    private var text: String { ScanFormat.probeBudgetText(sent: sent, budget: budget) }

    var body: some View {
        HStack(spacing: Space.md) {
            Text(verbatim: ScanFormat.gaugeLabel)
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
            if budget > 0 {
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        Capsule().fill(Tok.Ground.raised.color)
                        Capsule()
                            .fill(warning ? Tok.Intercept.base.color : Tok.Ink.tertiary.color)
                            .frame(width: geo.size.width * fraction)
                            .animation(reduceMotion ? nil : ScanMotion.ease(ScanMotion.progress), value: fraction)
                            .animation(ScanMotion.ease(ScanMotion.state), value: warning)
                    }
                }
                .frame(height: CardMetrics.gauge)
                .frame(maxWidth: .infinity)
            }
            Text(verbatim: text)
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .monospacedDigit()
                .counterTick(value: text, reduceMotion: reduceMotion)
        }
        .foregroundStyle(Tok.Ink.secondary.color)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(ScanFormat.gaugeAccessibilityLabel(sent: sent, budget: budget))
        .help(ScanFormat.probesTileHelp(sent: sent, budget: budget))
    }
}

// MARK: - KPI strip

/// The KPI strip (D11 §5): five cells in one bordered container on `Tok.Ground.surface`,
/// split by 1 pt rules. Progress leads in the accent; Checks, Probes and Points audited
/// carry their `of …` unit; Issues carries the severity words in their inks. Numerals
/// tick under `ScanMotion.counter` (D12); each cell is one accessibility element (D14).
struct ScanKPIStrip: View {
    var facts: ScanJobFacts
    var progress: ScanJobProgress
    var reduceMotion: Bool

    private var summary: ScanJobSummary { facts.summary }
    private var checks: ScanCheckCounters? { facts.status?.checks }
    private var by: BySeverity { summary.issues.bySeverity }

    var body: some View {
        HStack(spacing: 0) {
            ScanKPICell(
                label: ScanFormat.kpiLabels[0], value: progress.percentText ?? ScanFormat.missingValue, unit: nil,
                lead: true, help: progress.helpText, reduceMotion: reduceMotion)
            VRule(color: Tok.Line.border)
            ScanKPICell(
                label: ScanFormat.kpiLabels[1],
                value: checks.map { ScanFormat.grouped($0.done) } ?? ScanFormat.missingValue,
                unit: checks.map { ScanFormat.ofText($0.scheduled) }, lead: false, help: nil, reduceMotion: reduceMotion)
            VRule(color: Tok.Line.border)
            ScanKPICell(
                label: ScanFormat.kpiLabels[2], value: ScanFormat.grouped(summary.probes.sent),
                unit: ScanFormat.ofText(summary.probes.budget), lead: false,
                help: ScanFormat.probesTileHelp(sent: summary.probes.sent, budget: summary.probes.budget),
                reduceMotion: reduceMotion)
            VRule(color: Tok.Line.border)
            ScanKPICell(
                label: ScanFormat.kpiLabels[3], value: ScanFormat.grouped(summary.points.audited),
                unit: ScanFormat.ofText(summary.points.found), lead: false, help: nil, reduceMotion: reduceMotion)
            VRule(color: Tok.Line.border)
            ScanKPICell(
                label: ScanFormat.kpiLabels[4], value: ScanFormat.grouped(by.total), unit: nil, lead: false,
                severity: ScanFormat.severityWordParts(by: by),
                emptyWords: ScanFormat.severityWords(by: by, running: !summary.state.isTerminal),
                help: ScanFormat.issuesTileHelp(by: by), reduceMotion: reduceMotion)
        }
        .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.panel))
        .clipShape(RoundedRectangle(cornerRadius: Tok.Radius.panel))
        .overlay(RoundedRectangle(cornerRadius: Tok.Radius.panel).strokeBorder(Tok.Line.border.color))
    }
}

/// One KPI cell: the label over the numeral, the unit or the severity words beside it;
/// hover fills it with `Tok.Ground.hover`; read as one element, label then value.
struct ScanKPICell: View {
    var label: String
    var value: String
    var unit: String?
    var lead: Bool
    /// The Issues cell's words, each in its severity ink; empty for the other cells.
    var severity: [(ScanSeverity, String)] = []
    /// The Issues cell's `no issues yet` / `no issues` when `severity` is empty.
    var emptyWords: String?
    var help: String?
    var reduceMotion: Bool

    @State private var hovered = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(verbatim: label)
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.secondary.color)
            HStack(alignment: .firstTextBaseline, spacing: Space.sm) {
                Text(verbatim: value)
                    .font(Tok.Face.data(Tok.Typography.Size.display))
                    .foregroundStyle(lead ? Tok.Accent.base.color : Tok.Ink.primary.color)
                    .monospacedDigit()
                    .counterTick(value: value, reduceMotion: reduceMotion)
                if let unit {
                    Text(verbatim: unit)
                        .font(Tok.Face.ui(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Ink.secondary.color)
                        .monospacedDigit()
                        .counterTick(value: unit, reduceMotion: reduceMotion)
                }
                if !severity.isEmpty {
                    severityText
                        .lineLimit(1)
                } else if let emptyWords {
                    Text(verbatim: emptyWords)
                        .font(Tok.Face.ui(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                }
            }
        }
        .lineLimit(1)
        .padding(.horizontal, Space.lg)
        .padding(.vertical, CardMetrics.kpiPaddingVertical)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(hovered ? Tok.Ground.hover.color : .clear)
        .animation(ScanMotion.ease(ScanMotion.hoverReveal), value: hovered)
        .onHover { hovered = $0 }
        .accessibilityElement(children: .combine)
        .help(help ?? "")
    }

    /// `1 high, 2 low`, each word in its severity ink, the commas in the secondary ink.
    private var severityText: Text {
        var parts: [Text] = []
        for (index, (level, word)) in severity.enumerated() {
            if index > 0 {
                parts.append(
                    Text(verbatim: ", ").font(Tok.Face.ui(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Ink.secondary.color))
            }
            parts.append(
                Text(verbatim: word).font(Tok.Face.ui(Tok.Typography.Size.md))
                    .foregroundStyle(ScanToneColors.severity(level)))
        }
        return ScanInked.joined(parts)
    }
}

// MARK: - Attention block

/// The attention block (D9, D11 §6): what needs the operator's eye, only when there is
/// something. The Kit's lines, each with samples behind a system `DisclosureGroup`
/// (`check` and `detail` in the data face, selectable) or as plain text when it has
/// none; the Failed error verbatim; the raw-token lines; the Notices under their title.
struct ScanAttentionBlock: View {
    var facts: ScanJobFacts
    var launchNotices: [String]

    private var status: ScanJobStatus? { facts.status }
    private var lines: [ScanAttentionLine] { ScanEndText.attention(facts) }
    private var notices: [String] { status.map { ScanEndText.notices($0, launchNotices: launchNotices) } ?? [] }
    private var rawLines: [String] {
        var raw: [String] = []
        if let reason = status?.stoppedReason { raw.append(ScanEndText.rawReasonLine(reason)) }
        if let kind = status?.crawl.lastError { raw.append(ScanEndText.rawCrawlErrorLine(kind)) }
        return raw
    }

    private var isEmpty: Bool { lines.isEmpty && status?.error == nil && rawLines.isEmpty && notices.isEmpty }

    var body: some View {
        if !isEmpty {
            VStack(alignment: .leading, spacing: Space.sm) {
                ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                    if line.samples.isEmpty {
                        lineLabel(line.text)
                    } else {
                        DisclosureGroup {
                            VStack(alignment: .leading, spacing: Space.xs) {
                                ForEach(Array(line.samples.enumerated()), id: \.offset) { _, sample in
                                    HStack(alignment: .firstTextBaseline, spacing: Space.md) {
                                        Text(verbatim: sample.check)
                                        Text(verbatim: sample.detail)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                                    .foregroundStyle(Tok.Ink.secondary.color)
                                    .textSelection(.enabled)
                                }
                            }
                            .padding(.top, Space.xs)
                        } label: {
                            lineLabel(line.text)
                        }
                    }
                }
                if let error = status?.error {
                    Text(verbatim: error)
                        .font(Tok.Face.data(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Status.serverError.color)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(rawLines, id: \.self) { raw in
                    Text(verbatim: raw)
                        .font(Tok.Face.data(Tok.Typography.Size.xs))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                        .textSelection(.enabled)
                }
                if !notices.isEmpty {
                    ScanSectionTitle("Notices")
                        .padding(.top, Space.xs)
                    ForEach(Array(notices.enumerated()), id: \.offset) { _, notice in
                        Text(verbatim: notice)
                            .font(Tok.Face.ui(Tok.Typography.Size.sm))
                            .foregroundStyle(Tok.Ink.secondary.color)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(.top, Space.xs)
        }
    }

    private func lineLabel(_ text: String) -> some View {
        Text(verbatim: text)
            .font(Tok.Face.ui(Tok.Typography.Size.md))
            .foregroundStyle(Tok.Ink.primary.color)
            .fixedSize(horizontal: false, vertical: true)
    }
}
