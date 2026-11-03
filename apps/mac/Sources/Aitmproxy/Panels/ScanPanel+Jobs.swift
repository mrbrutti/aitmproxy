import AitmproxyKit
import SwiftUI

/// The Scan page's Jobs tab (Jobs view spec, UX *Surface*; D10, D11, D15): one
/// scrolling column, top to bottom: the bus banner when the link is away, the
/// selected job's card, the jobs table, the two wells. Every number on this tab is
/// a value the bus returned or the Kit derived from one; the views add no number of
/// their own beyond a count, a first line or a fill fraction of those values (gap 39
/// moves the rest into the Kit). Reduce Motion is read here once and passed down (D12).
///
/// The body reads nothing that rides the state's 1 Hz clock: `state.link` is read
/// only inside `ScanJobsBanner` and `ScanJobsReadError`, so a clock tick re-renders
/// those two lines and not the card or the rows (plan gap 34, fix 1.5h).
struct ScanJobsTab: View {
    var state: ScanPanelState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @FocusState private var listFocused: Bool
    /// The card's first enabled verb takes focus when true (D14): Return or → in
    /// the table sets it; Escape from the card clears it.
    @FocusState private var inspectorFocused: Bool
    /// The row under the pointer, so only it shows its hover Cancel button.
    @State private var hoveredJob: String?

    /// The table joins the one entrance only on the tab's first selected job (D12):
    /// on a row click the operator is pointing at the table, which must not move. So
    /// its generation follows the state's while `firstEntrance` and then holds, which
    /// keeps the table's identity (focus, hover) across every later selection.
    private var tableGeneration: Int { state.firstEntrance ? state.entranceGeneration : 1 }

    /// The selected job's merged facts (D2), read once for the card and the wells.
    private var selectedFacts: ScanJobFacts? {
        state.surface.selectedJob.flatMap { state.surface.facts(for: $0) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.xl) {
                if !state.verbsEnabled {
                    // The bus is away (D15): nothing failed, so the banner reads in
                    // secondary ink on raised, not the error ink.
                    ScanJobsBanner(state: state)
                }
                if state.surface.readFailure != nil {
                    // The inline read error (D6): the values it could not refresh stay,
                    // and a failed list says how old its values are.
                    ScanJobsReadError(state: state)
                }
                if state.surface.jobs.isEmpty {
                    ContentUnavailableView {
                        Label(scanNoJobsText, systemImage: Tok.Glyph.search)
                    } actions: {
                        FlatButton("Open Profiles") { state.surface.tab = .profiles }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, Space.section)
                } else {
                    if let facts = selectedFacts {
                        ScanJobCard(
                            state: state,
                            facts: facts,
                            progress: ScanJobProgress(facts),
                            reduceMotion: reduceMotion,
                            generation: state.entranceGeneration,
                            inspectorFocused: $inspectorFocused,
                            onEscape: { listFocused = true }
                        )
                    }
                    table
                        .cardEntrance(index: 2, generation: tableGeneration, reduceMotion: reduceMotion)
                    if let facts = selectedFacts {
                        // 28 pt below the table (D11 Wells): the column's `Space.xl` plus `Space.sm`.
                        ScanJobWells(facts: facts)
                            .padding(.top, Space.sm)
                            .cardEntrance(index: 3, generation: state.entranceGeneration, reduceMotion: reduceMotion)
                    }
                }
            }
            .padding(.horizontal, Space.xxl)
            .padding(.top, Space.xl)
            .padding(.bottom, Space.section)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
    }

    // MARK: Table

    /// The listed jobs as merged facts (D2), newest first as `scan.list` orders them:
    /// each listed row with its stored status, through the Kit's one merge rule.
    private var rows: [ScanJobFacts] {
        let statuses = state.surface.statuses
        return state.surface.jobs.map { ScanJobFacts.make(summary: $0, status: statuses[$0.job]) }
    }

    /// The jobs table (D10): the header, then one row per job on the same column
    /// layout, split by rules. Every row reads the Kit's merged facts (D2): the list
    /// row and the stored status, reconciled once, so the row and the card never
    /// disagree. Arrow keys walk the selection once the table has focus (D14), with no
    /// animation and no entrance (D12); Return or → hands focus to the card's verbs.
    /// The accessibility container is declared before `.focusable()`: on macOS a
    /// focusable view with no element of its own lends its frame to the last element
    /// directly inside it, which here was the bottom row (fix 2.12d). With the
    /// container inside, that element is the table's own group, whose frame is right.
    private var table: some View {
        let rows = rows
        return VStack(spacing: 0) {
            ScanJobsHeader()
            ForEach(rows, id: \.job) { facts in
                Rule(color: Tok.Line.rule)
                ScanJobRow(
                    facts: facts,
                    progress: ScanJobProgress(facts),
                    selected: facts.job == state.surface.selectedJob,
                    hovered: facts.job == hoveredJob,
                    cancelable: mayCancel(facts.job),
                    reduceMotion: reduceMotion,
                    select: { select(facts.job) },
                    cancel: { cancel(facts.job) }
                )
                .onHover { inside in
                    if inside {
                        hoveredJob = facts.job
                    } else if hoveredJob == facts.job {
                        hoveredJob = nil
                    }
                }
                .contextMenu { rowMenu(facts) }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(
            ScanFormat.jobsCaption(total: rows.count, running: rows.filter { $0.summary.state == .running }.count))
        .focusable()
        .focused($listFocused)
        .focusEffectDisabled()
        .onMoveCommand { direction in
            // Keyboard selection never animates (D12): the state runs it under a
            // no-animation transaction and leaves the entrance generation alone.
            switch direction {
            case .up: state.moveSelection(by: -1)
            case .down: state.moveSelection(by: 1)
            case .right: inspectorFocused = true
            default: break
            }
        }
        .onKeyPress(.return) {
            inspectorFocused = true
            return .handled
        }
        .gridProbe("scan-jobs-table", area: "scan")
    }

    /// The row's verbs (D10): Cancel Scan while the job can still be stopped and the
    /// link is live, Scan Again for a finished job (enabled by the state's one predicate,
    /// the same the card's primary and `scanAgain(job:)` read), the two tab jumps, and
    /// the id for a terminal or a bug report.
    @ViewBuilder private func rowMenu(_ facts: ScanJobFacts) -> some View {
        let job = facts.job
        if mayCancel(job) {
            Button("Cancel Scan") { cancel(job) }
        }
        if facts.summary.state.isTerminal {
            Button("Scan Again") { Task { await state.scanAgain(job: job) } }
                .disabled(!state.scanAgainEnabled(for: job))
        }
        Button("Show Issues") { state.showIssues(job: job) }
        Button("Show Site Map") { state.showSitemap(job: job) }
        Divider()
        Button("Copy Job ID") { Pasteboard.copy(job) }
    }

    /// Whether a row may offer Cancel: the Kit's predicate on the merged state
    /// (queued or running; never cancelling or terminal, Jobs view D2) and the
    /// link's verb gate (Jobs view D6).
    private func mayCancel(_ job: String) -> Bool {
        state.surface.mayCancel(job: job) && state.verbsEnabled
    }

    /// A pointer selection: the state bumps the entrance generation when the job
    /// changes (D12), and the table keeps the keyboard.
    private func select(_ job: String) {
        state.select(job, cause: .pointer)
        listFocused = true
    }

    private func cancel(_ job: String) {
        Task { await state.cancel(job: job) }
    }
}

// MARK: - Banner and read error

/// The bus-away banner (D15): the Kit's sentence in `Tok.Ink.secondary` on
/// `Tok.Ground.raised`, `ScanInlineError`'s shape without the error ink. Its own
/// view because `link` rides the state's 1 Hz clock (the age clause): the tick
/// re-renders this line alone.
private struct ScanJobsBanner: View {
    var state: ScanPanelState

    var body: some View {
        if let text = state.link.bannerText {
            Text(text)
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .lineLimit(2)
                .textSelection(.enabled)
                .padding(.horizontal, Space.md)
                .padding(.vertical, Space.sm)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.panel))
        }
    }
}

/// The inline read error (D6), with the age of the values a failed list left on
/// screen. Its own view for the same reason as the banner: the age moves with the
/// clock, and only this line should move with it.
private struct ScanJobsReadError: View {
    var state: ScanPanelState

    var body: some View {
        if let text = state.surface.inlineJobsError(ageMs: state.link.valuesAgeMs) {
            ScanInlineError(text: text, inset: 0)
        }
    }
}

// MARK: - Columns

/// The one column layout the header and every row share (D10), so cells align:
/// fixed widths for Profile, the four numeric columns and the action column; the
/// three flexible columns (State, Target, Progress) share what is left in the
/// proportion of D10's minimums (148 : 220 : 220). The sum of D10's minimums
/// (1,236 pt) is wider than the comp's 1,152 pt content column at 1,440 pt, so
/// below that sum the flexible columns shrink in proportion rather than overflow
/// the column (the comp's auto table does the same; its last column is the one
/// fixed width). Nonisolated because `Layout`'s requirements are.
nonisolated struct ScanJobsColumns: Layout {
    /// One column's width rule and alignment.
    struct Column: Equatable, Sendable {
        /// A fixed width; nil for a flexible column.
        var fixed: CGFloat?
        /// A flexible column's share of the leftover (its D10 minimum); 0 when fixed.
        var share: CGFloat
        /// Right-aligned (the numeric columns and the action column).
        var trailing: Bool
    }

    var columns: [Column]

    /// D10's nine columns in order: State, Profile, Target, Progress, Probes, Points,
    /// Issues, Elapsed, the action column; every width is a `CardMetrics.table*`
    /// constant (one home for the comp's numbers). Built once: its inputs are constants.
    static let standard: ScanJobsColumns = {
        ScanJobsColumns(columns: [
            Column(fixed: nil, share: CardMetrics.tableStateShare, trailing: false),
            Column(fixed: CardMetrics.tableProfileWidth, share: 0, trailing: false),
            Column(fixed: nil, share: CardMetrics.tableTargetShare, trailing: false),
            Column(fixed: nil, share: CardMetrics.tableProgressShare, trailing: false),
            Column(fixed: CardMetrics.tableProbesWidth, share: 0, trailing: true),
            Column(fixed: CardMetrics.tablePointsWidth, share: 0, trailing: true),
            Column(fixed: CardMetrics.tableIssuesWidth, share: 0, trailing: true),
            Column(fixed: CardMetrics.tableElapsedWidth, share: 0, trailing: true),
            Column(fixed: CardMetrics.actionColumn, share: 0, trailing: true),
        ])
    }()

    /// Whether column `index` is right-aligned.
    func trailing(_ index: Int) -> Bool {
        columns.indices.contains(index) && columns[index].trailing
    }

    /// The width every column takes when `total` is on offer.
    func widths(total: CGFloat) -> [CGFloat] {
        let fixed = columns.compactMap(\.fixed).reduce(0, +)
        let shares = columns.map(\.share).reduce(0, +)
        let flexible = max(0, total - fixed)
        return columns.map { column in
            if let width = column.fixed { return width }
            return shares > 0 ? flexible * column.share / shares : 0
        }
    }

    /// With no width proposed, D10's minimums.
    private var minimumWidth: CGFloat {
        columns.map { $0.fixed ?? $0.share }.reduce(0, +)
    }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? minimumWidth
        let height = zip(subviews, widths(total: width))
            .map { subview, width in subview.sizeThatFits(ProposedViewSize(width: width, height: proposal.height)).height }
            .max() ?? 0
        return CGSize(width: width, height: max(height, proposal.height ?? 0))
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        for (subview, width) in zip(subviews, widths(total: bounds.width)) {
            subview.place(
                at: CGPoint(x: x, y: bounds.midY), anchor: .leading,
                proposal: ProposedViewSize(width: width, height: bounds.height))
            x += width
        }
    }
}

/// One cell of the table: padded `Space.sm` each side and pinned to its column's
/// edge, so the content never leaks into the next column.
private struct ScanJobsCell<Content: View>: View {
    var column: Int
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(.horizontal, Space.sm)
            .frame(maxWidth: .infinity, alignment: ScanJobsColumns.standard.trailing(column) ? .trailing : .leading)
    }
}

// MARK: - Header

/// The table's header (D10): `CardMetrics.headerHeight` tall, the Kit's eight labels
/// in UI sm `Tok.Ink.tertiary` with the numeric ones right-aligned, an empty action
/// column, no fill and no rule under it. Hidden from VoiceOver: every row's label is
/// a whole sentence, so the headers would only be read as eight stray words.
private struct ScanJobsHeader: View {
    var body: some View {
        ScanJobsColumns.standard {
            ForEach(Array(ScanFormat.tableHeaders.enumerated()), id: \.offset) { index, title in
                ScanJobsCell(column: index) {
                    Text(title)
                        .font(Tok.Face.ui(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                        .lineLimit(1)
                }
            }
            ScanJobsCell(column: ScanFormat.tableHeaders.count) { Color.clear }
        }
        .frame(height: CardMetrics.headerHeight)
        .accessibilityHidden(true)
    }
}

// MARK: - Row

/// One job (D10): the State cell (the ring or the tone dot in the 18 pt slot, the
/// agent dot, the state word, a stopped-reason or error sub-line for a finished job),
/// Profile, Target, Progress, Probes, Points, Issues, Elapsed, and the hover Cancel in
/// the fixed action column. Every value is the merged facts' (D2) or the Kit's word
/// for them. The row is one accessibility element with the button trait, the
/// selected trait while selected, a `Select` action and the identifier
/// `scan-job-<id>` (D5, D14).
private struct ScanJobRow: View {
    var facts: ScanJobFacts
    var progress: ScanJobProgress
    var selected: Bool
    var hovered: Bool
    /// Whether the hover Cancel shows: the merged state is queued or running and
    /// the link is live (D2, D6).
    var cancelable: Bool
    var reduceMotion: Bool
    var select: () -> Void
    var cancel: () -> Void

    private var summary: ScanJobSummary { facts.summary }
    /// Queued or running: the slot holds the ring; a dot otherwise (D10).
    private var showsRing: Bool { summary.state == .queued || summary.state == .running }
    private var showCancel: Bool { hovered && cancelable }

    var body: some View {
        ScanJobsColumns.standard {
            ScanJobsCell(column: 0) { stateCell }
            ScanJobsCell(column: 1) {
                Text(ScanFormat.profileText(facts))
                    .font(Tok.Face.ui(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            ScanJobsCell(column: 2) {
                Text(ScanFormat.hostsText(facts))
                    .font(Tok.Face.data(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(ScanFormat.hostsText(facts))
            }
            ScanJobsCell(column: 3) {
                let text = ScanFormat.rowProgressText(facts, progress)
                Text(text)
                    .font(Tok.Face.data(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .counterTick(value: text, reduceMotion: reduceMotion)
            }
            ScanJobsCell(column: 4) { probesCell }
            ScanJobsCell(column: 5) {
                let text = "\(ScanFormat.grouped(summary.points.audited)) \(ScanFormat.ofText(summary.points.found))"
                Text(text)
                    .font(Tok.Face.data(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .counterTick(value: text, reduceMotion: reduceMotion)
            }
            ScanJobsCell(column: 6) { issuesCell }
            ScanJobsCell(column: 7) {
                let text = ScanFormat.elapsed(ms: summary.elapsedMs)
                Text(text)
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .counterTick(value: text, reduceMotion: reduceMotion)
            }
            ScanJobsCell(column: 8) {
                // Always laid out, so a hover never moves anything (D10); it fades in
                // over `ScanMotion.hoverReveal` (D12) and is inert while hidden.
                FlatButton("Cancel", action: cancel)
                    .help(ScanFormat.cancelScanHelp)
                    .opacity(showCancel ? 1 : 0)
                    .animation(ScanMotion.ease(ScanMotion.hoverReveal), value: showCancel)
                    .disabled(!showCancel)
            }
        }
        .frame(minHeight: CardMetrics.rowPitch)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(selected ? Tok.Ground.active.color : hovered ? Tok.Ground.hover.color : .clear)
        .overlay(alignment: .leading) {
            // The selection edge (D10): 3 pt of accent at the leading edge.
            Rectangle()
                .fill(Tok.Accent.base.color)
                .frame(width: CardMetrics.edge)
                .opacity(selected ? 1 : 0)
        }
        .contentShape(Rectangle())
        .onTapGesture { select() }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(ScanFormat.jobAccessibilityLabel(facts))
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .accessibilityAction { select() }
        .accessibilityAction(named: "Select") { select() }
        .accessibilityIdentifier("scan-job-\(facts.job)")
    }

    /// The State cell (D10): the 18 pt slot holds the progress ring while the job is
    /// queued or running and the tone dot otherwise (breathing only while
    /// cancelling, D12); the agent dot when an agent started the job; the state or
    /// phase word, crossfading on a change; and, for a finished job, the Kit's
    /// `rowSubLine` (the stopped-reason sentence, D4, or the error's first line; D21).
    private var stateCell: some View {
        let word = ScanFormat.stateWord(facts)
        return VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: Space.sm) {
                Group {
                    if showsRing {
                        ScanProgressRing(ring: progress.ring, reduceMotion: reduceMotion)
                    } else {
                        ScanStateDot(
                            tone: ScanFormat.tone(facts), breathing: summary.state == .cancelling, reduceMotion: reduceMotion)
                    }
                }
                .frame(width: Tok.Size.badge, height: Tok.Size.badge)
                if let by = facts.status?.startedBy, ScanFormat.agentOriginated(by) {
                    ScanAgentDot()
                }
                Text(word)
                    .font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .contentTransition(.opacity)
                    .animation(ScanMotion.ease(ScanMotion.state), value: word)
            }
            if let subLine = ScanEndText.rowSubLine(facts) {
                Text(subLine)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(subLine)
            }
        }
    }

    /// Probes: the count in primary ink, the unit (`of 2,000`) muted (D10).
    private var probesCell: some View {
        let sent = ScanFormat.grouped(summary.probes.sent)
        let unit = ScanFormat.ofText(summary.probes.budget)
        return Text("\(Text(sent).foregroundStyle(Tok.Ink.primary.color)) \(Text(unit).foregroundStyle(Tok.Ink.secondary.color))")
            .font(Tok.Face.data(Tok.Typography.Size.md))
            .lineLimit(1)
            .counterTick(value: sent + unit, reduceMotion: reduceMotion)
    }

    /// Issues: the Kit's severity words through the one builder, each in its severity
    /// ink, comma-separated in secondary, in the data face (D10, D21); the Kit's `no
    /// issues yet` / `no issues` in tertiary when there are none.
    private var issuesCell: some View {
        let parts = ScanFormat.severityWordParts(by: summary.issues.bySeverity)
        return Group {
            if parts.isEmpty {
                Text(ScanFormat.severityWords(by: summary.issues.bySeverity, running: !summary.state.isTerminal))
                    .font(Tok.Face.ui(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.tertiary.color)
            } else {
                ScanSeverityWordsText.text(parts, font: Tok.Face.data(Tok.Typography.Size.md))
                    .counterTick(value: parts.map(\.word).joined(), reduceMotion: reduceMotion)
            }
        }
        .lineLimit(1)
    }
}
