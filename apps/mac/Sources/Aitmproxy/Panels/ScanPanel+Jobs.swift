import AitmproxyKit
import SwiftUI

/// The Scan page's Jobs tab (scanner v2 T9, spec D5): the job rows from
/// `scan.list` on the left, the selected job's `scan.status` detail on the right.
/// Every number on this tab is a value the bus returned; the view computes none.
/// Hue appears only in the severity bar, the one datum that carries it.
struct ScanJobsTab: View {
    @Bindable var state: ScanPanelState
    @FocusState private var listFocused: Bool
    /// The row under the pointer, so only it shows its hover Cancel button.
    @State private var hoveredJob: String?

    var body: some View {
        HStack(spacing: 0) {
            list
                .frame(width: 360)
                .gridProbe("scan-jobs-list", area: "scan", edge: nil)
            VRule()
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
    }

    // MARK: List

    @ViewBuilder private var list: some View {
        VStack(spacing: 0) {
            if let error = state.surface.inlineJobsError(ageMs: state.link.valuesAgeMs) {
                // The inline error above the rows (D11): the list it could not refresh stays,
                // and a failed list says how old its values are (Jobs view D6).
                ScanInlineError(text: error)
                Rule(color: Tok.Line.rule)
            }
            if state.surface.jobs.isEmpty {
                ContentUnavailableView {
                    Label(scanNoJobsText, systemImage: Tok.Glyph.search)
                } actions: {
                    FlatButton("Open Profiles") { state.surface.tab = .profiles }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                rows
            }
        }
        .background(Tok.Ground.surface.color)
    }

    private var rows: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                // Every row reads the Kit's merged facts (Jobs view D2): the list row and
                // the stored status, reconciled once, so the row and the detail never disagree.
                ForEach(state.surface.jobs, id: \.job) { summary in
                    if let facts = state.surface.facts(for: summary.job) {
                        ScanJobRow(
                            facts: facts,
                            selected: facts.job == state.surface.selectedJob,
                            hovered: facts.job == hoveredJob,
                            cancelable: mayCancel(facts.job),
                            select: { select(facts.job) },
                            cancel: { cancel(facts.job) }
                        )
                        .contentShape(Rectangle())
                        .onTapGesture { select(facts.job) }
                        .onHover { inside in
                            if inside {
                                hoveredJob = facts.job
                            } else if hoveredJob == facts.job {
                                hoveredJob = nil
                            }
                        }
                        .contextMenu { rowMenu(facts.job) }
                    }
                }
            }
        }
        // Arrow keys walk the selection once the list has focus (D13), as Findings does.
        .focusable()
        .focused($listFocused)
        .focusEffectDisabled()
        .onMoveCommand { direction in
            switch direction {
            case .up: state.surface.moveSelection(in: .jobs, by: -1)
            case .down: state.surface.moveSelection(in: .jobs, by: 1)
            default: break
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Jobs")
    }

    /// The row's verbs (D5): Cancel Scan while the job can still be stopped and the
    /// link is live, the two tab jumps, and the id for a terminal or a bug report.
    @ViewBuilder private func rowMenu(_ job: String) -> some View {
        if mayCancel(job) {
            Button("Cancel Scan") { cancel(job) }
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
        state.surface.mayCancel(job: job) && state.link.verbsEnabled
    }

    private func select(_ job: String) {
        state.surface.select(job: job)
        listFocused = true
    }

    private func cancel(_ job: String) {
        Task { await state.cancel(job: job) }
    }

    // MARK: Detail

    @ViewBuilder private var detail: some View {
        if let job = state.surface.selectedJob, let facts = state.surface.facts(for: job) {
            ScanJobDetail(state: state, facts: facts)
        } else {
            Text(scanSelectJobText)
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.tertiary.color)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

// MARK: - Row

/// One job (D5): `<State or phase> · <profile> · <hosts>` over the probe / point /
/// elapsed line, then the severity bar. The counters are the merged facts' (Jobs
/// view D2); the profile name and hosts come from `scan.status`, so a job whose
/// status has not been read yet shows `—` for them. The row is one accessibility
/// element with the button trait, the selected trait while selected, a `Select`
/// action and the identifier `scan-job-<id>` (Jobs view D5).
private struct ScanJobRow: View {
    var facts: ScanJobFacts
    var selected: Bool
    var hovered: Bool
    /// Whether the hover Cancel shows: the merged state is queued or running and
    /// the link is live (Jobs view D2, D6).
    var cancelable: Bool
    var select: () -> Void
    var cancel: () -> Void

    private var summary: ScanJobSummary { facts.summary }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                Text(ScanFormat.jobRowLine1(summary, status: facts.status))
                    .font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: Space.xs)
                if hovered, cancelable {
                    FlatButton("Cancel", action: cancel)
                        .help("Stop this job; its issues stay (⌥⌘.)")
                }
            }
            // The line keeps the button's height whether or not it shows, so a
            // hover never moves the rows below.
            .frame(height: Tok.Size.control)
            Text(ScanFormat.jobRowLine2(summary))
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .lineLimit(1)
            ScanSeverityBar(by: summary.issues.bySeverity, height: 6) // grid: ok spec D5 fixes the row bar at 6 pt
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(selected ? Tok.Ground.active.color : .clear)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(ScanFormat.jobAccessibilityLabel(summary, status: facts.status))
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .accessibilityAction { select() }
        .accessibilityAction(named: "Select") { select() }
        .accessibilityIdentifier("scan-job-\(facts.job)")
    }
}

// MARK: - Severity bar

/// A stacked bar of an issue tally (D5): one `Rectangle` per non-zero severity,
/// width proportional to its share, in that severity's `Tok.Severity` ink; the
/// total as a number at the end; a 1 pt rule when there is nothing to show. It
/// hides from VoiceOver because the row label already reads the counts in words
/// (D13: severity never by colour alone).
struct ScanSeverityBar: View {
    var by: BySeverity
    var height: CGFloat

    private var segments: [ScanSeveritySegment] { ScanSurfaceModel.severityBarSegments(by) }

    var body: some View {
        HStack(spacing: Space.sm) {
            Group {
                if segments.isEmpty {
                    Rule(color: Tok.Line.border)
                } else {
                    GeometryReader { geo in
                        // The 1 pt seams between segments come out of the width first,
                        // so the shares still sum to the bar and never overflow it.
                        let usable = max(0, geo.size.width - CGFloat(segments.count - 1))
                        HStack(spacing: 1) {
                            ForEach(segments, id: \.severity) { segment in
                                Rectangle()
                                    .fill(Self.ink(segment.severity))
                                    .frame(width: max(1, usable * segment.fraction))
                            }
                        }
                    }
                }
            }
            .frame(height: height)
            .frame(maxWidth: .infinity)
            Text("\(by.total)")
                .font(Tok.Face.data(Tok.Typography.Size.sm, .medium))
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: 32, alignment: .trailing)
        }
        .accessibilityHidden(true)
    }

    /// The kit pair's foreground for a known severity; a level this build does not
    /// know falls back to the info ink so a newer core never leaves a gap.
    static func ink(_ severity: ScanSeverity) -> Color {
        (severity.known?.pair ?? Tok.Severity.info).fg.color
    }
}

// MARK: - Detail

/// The selected job's `scan.status` (D5), read through the merged facts (Jobs
/// view D2): the counters the row already has (probes, points, issues, state,
/// phase, elapsed) are the facts' summary, the newer of the list row and the
/// stored status, so no number is ever blank and the detail never lags the row;
/// the rest reads `—` until the status arrives, and keeps its last value through
/// every later refresh (D11).
private struct ScanJobDetail: View {
    @Bindable var state: ScanPanelState
    var facts: ScanJobFacts

    private var summary: ScanJobSummary { facts.summary }
    private var status: ScanJobStatus? { facts.status }
    private var jobState: ScanJobState { summary.state }
    private var phase: ScanPhase { summary.phase }
    private var elapsedMs: Int { summary.elapsedMs }
    private var probes: ScanProbeCounters { summary.probes }
    private var points: ScanPointCounters { summary.points }
    private var issues: ScanIssueCounters { summary.issues }

    /// The Stopped section shows for a stopped reason, an error, or a crawl that
    /// hit errors (Jobs view D4).
    private var hasStoppedFacts: Bool {
        guard let status else { return false }
        return status.stoppedReason != nil || status.error != nil || status.crawl.errors > 0
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Rule()
            ScrollView {
                VStack(alignment: .leading, spacing: Space.xl) {
                    probesSection
                    crawlSection
                    pointsSection
                    checksSection
                    issuesSection
                    if let lanes = status?.lanes { lanesSection(lanes) }
                    if !clampedLines.isEmpty { clampedSection }
                    if let session = status?.session { sessionSection(session) }
                    if let l4 = status?.l4 { l4Section(l4) }
                    if hasStoppedFacts { stoppedSection }
                }
                .padding(Space.md)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
    }

    // MARK: Header

    private var header: some View {
        HStack(spacing: Space.md) {
            Text([jobState.word, phase.word, ScanFormat.elapsed(ms: elapsedMs)].joined(separator: " · "))
                .font(Tok.Face.ui(Tok.Typography.Size.xl, .medium))
                .foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
            Spacer(minLength: Space.sm)
            // Cancel Scan while the merged state is queued or running; disabled and
            // titled by the cancelling word while the cancel is in flight (Jobs view
            // D2); the whole verb is off while the link is not live (Jobs view D6).
            switch jobState {
            case .queued, .running:
                PrimaryButton("Cancel Scan") { Task { await state.cancel(job: facts.job) } }
                    .keyboardShortcut(".", modifiers: [.command, .option])
                    .help("Stop this job; its issues stay (⌥⌘.)")
                    .disabled(!state.link.verbsEnabled)
            case .cancelling:
                PrimaryButton(ScanFormat.cancellingTitle) {}
                    .disabled(true)
            default:
                EmptyView()
            }
            FlatButton("Show Issues") { state.showIssues(job: facts.job) }
            FlatButton("Show Site Map") { state.showSitemap(job: facts.job) }
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.inspectorHeader)
    }

    // MARK: Sections

    private var probesSection: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            ScanSectionTitle("Probes")
            Text("\(probes.sent) / \(probes.budget)")
                .font(Tok.Face.data(Tok.Typography.Size.xl, .medium))
                .foregroundStyle(Tok.Ink.primary.color)
            ScanJobProgressRule(done: probes.sent, total: probes.budget)
            HStack(alignment: .top, spacing: Space.xl) {
                ScanStat("Errors", "\(probes.errors)")
                ScanStat("Timeouts", "\(probes.timeouts)")
                ScanStat("Rate waits", "\(probes.rateWaits)")
            }
            if !probes.byLane.isEmpty {
                ScanStat("By lane", probes.byLane.keys.sorted().map { "\($0) \(probes.byLane[$0] ?? 0)" }
                    .joined(separator: " · "))
            }
        }
    }

    private var crawlSection: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            ScanSectionTitle("Crawl")
            HStack(alignment: .top, spacing: Space.xl) {
                ScanStat("Pages", status.map { "\($0.crawl.pages)" })
                ScanStat("Queued", status.map { "\($0.crawl.queued)" })
                ScanStat("Depth", status.map { "\($0.crawl.depth)" })
                ScanStat("Forms", status.map { "\($0.crawl.formsSubmitted)" })
            }
        }
    }

    private var pointsSection: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            ScanSectionTitle("Points")
            HStack(alignment: .top, spacing: Space.xl) {
                ScanStat("Found", "\(points.found)")
                ScanStat("Queued", "\(points.queued)")
                ScanStat("Audited", "\(points.audited)")
            }
            HStack(alignment: .top, spacing: Space.xl) {
                ScanStat("Skipped ignored", "\(points.skipped.ignored)")
                ScanStat("Skipped frequent", "\(points.skipped.frequent)")
                ScanStat("Skipped limit", "\(points.skipped.limit)")
            }
        }
    }

    private var checksSection: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            ScanSectionTitle("Checks")
            HStack(alignment: .top, spacing: Space.xl) {
                ScanStat("Scheduled", status.map { "\($0.checks.scheduled)" })
                ScanStat("Done", status.map { "\($0.checks.done)" })
            }
            if let running = status?.checks.running, !running.isEmpty {
                VStack(alignment: .leading, spacing: Space.xs) {
                    caption("Running")
                    // The engine caps this at 8 ids (D11), so a plain list is enough.
                    ForEach(running, id: \.self) { id in
                        Text(id)
                            .font(Tok.Face.data(Tok.Typography.Size.sm))
                            .foregroundStyle(Tok.Ink.primary.color)
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    private var issuesSection: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            ScanSectionTitle("Issues")
            ScanSeverityBar(by: issues.bySeverity, height: 12)
            // The counts in words beside the bar, so severity is never colour alone.
            HStack(alignment: .top, spacing: Space.xl) {
                ScanStat(ScanSeverity.critical.word, "\(issues.bySeverity.critical)")
                ScanStat(ScanSeverity.high.word, "\(issues.bySeverity.high)")
                ScanStat(ScanSeverity.medium.word, "\(issues.bySeverity.medium)")
                ScanStat(ScanSeverity.low.word, "\(issues.bySeverity.low)")
                ScanStat(ScanSeverity.info.word, "\(issues.bySeverity.info)")
            }
            HStack(alignment: .top, spacing: Space.xl) {
                ScanStat("Certain", "\(issues.byConfidence.certain)")
                ScanStat("Firm", "\(issues.byConfidence.firm)")
                ScanStat("Tentative", "\(issues.byConfidence.tentative)")
            }
        }
    }

    private func lanesSection(_ lanes: ScanLaneReport) -> some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            ScanSectionTitle("Lanes")
            HStack(alignment: .top, spacing: Space.xl) {
                ScanStat("Requested", laneWords(lanes.requested))
                ScanStat("Run", laneWords(lanes.run))
            }
            if !lanes.skipped.isEmpty {
                VStack(alignment: .leading, spacing: Space.xs) {
                    caption("Skipped")
                    ForEach(Array(lanes.skipped.enumerated()), id: \.offset) { _, skipped in
                        Text("\(skipped.lane.word): \(skipped.reason)")
                            .font(Tok.Face.ui(Tok.Typography.Size.sm))
                            .foregroundStyle(Tok.Ink.secondary.color)
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    /// The launch's notices (`clamped` and `lanes.skipped` from the `scan.start`
    /// result) first, then any `clamped` row of the status the notices did not
    /// already spell out.
    private var clampedLines: [String] {
        let notices = state.surface.launchNotices[facts.job] ?? []
        let fromStatus = (status?.clamped ?? []).map(ScanFormat.clampedText)
        return notices + fromStatus.filter { !notices.contains($0) }
    }

    private var clampedSection: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            ScanSectionTitle("Clamped")
            ForEach(Array(clampedLines.enumerated()), id: \.offset) { _, line in
                Text(line)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .textSelection(.enabled)
            }
        }
    }

    private func sessionSection(_ session: ScanSessionStatus) -> some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            ScanSectionTitle("Session")
            HStack(alignment: .top, spacing: Space.xl) {
                ScanStat("Reused", ScanFormat.yesNo(session.reused))
                ScanStat("Lost", ScanFormat.yesNo(session.lost))
                ScanStat("Browser partial", ScanFormat.yesNo(session.browserPartial))
            }
            Text(ScanFormat.canaryText(session.canary))
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .textSelection(.enabled)
        }
    }

    private func l4Section(_ l4: ScanL4Counters) -> some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            ScanSectionTitle("L4")
            HStack(alignment: .top, spacing: Space.xl) {
                ScanStat("Cases", "\(l4.cases)")
                ScanStat("Crashes", "\(l4.crashes)")
                ScanStat("Liveness failures", "\(l4.livenessFailures)")
                ScanStat("Retired elements", "\(l4.retiredElements)")
            }
        }
    }

    /// Why the job stopped, in words (Jobs view D4): the stopped-reason sentence,
    /// the crawl-trouble sentence with the last error's words, the engine's error
    /// text verbatim, and last the raw tokens in the data face, the one place
    /// they appear.
    @ViewBuilder private var stoppedSection: some View {
        if let status {
            VStack(alignment: .leading, spacing: Space.sm) {
                ScanSectionTitle("Stopped")
                if let reason = status.stoppedReason,
                   let sentence = ScanEndText.stoppedReason(
                       reason, state: jobState, probesBudget: probes.budget, error: status.error)
                {
                    stoppedSentence(sentence)
                }
                if let trouble = ScanEndText.crawlTrouble(status.crawl) {
                    if let kind = status.crawl.lastError {
                        stoppedSentence(trouble + " — " + ScanEndText.crawlErrorWords(kind))
                    } else {
                        stoppedSentence(trouble)
                    }
                }
                if let error = status.error {
                    Text(error)
                        .font(Tok.Face.data(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Status.serverError.color)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let reason = status.stoppedReason {
                    rawLine(ScanEndText.rawReasonLine(reason))
                }
                if let kind = status.crawl.lastError {
                    rawLine(ScanEndText.rawCrawlErrorLine(kind))
                }
            }
        }
    }

    /// A Stopped-section sentence: UI face, md, secondary ink.
    private func stoppedSentence(_ text: String) -> some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.md))
            .foregroundStyle(Tok.Ink.secondary.color)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// A raw-token line (`stopped_reason: errors`): data face, xs, tertiary ink.
    private func rawLine(_ text: String) -> some View {
        Text(text)
            .font(Tok.Face.data(Tok.Typography.Size.xs))
            .foregroundStyle(Tok.Ink.tertiary.color)
            .textSelection(.enabled)
    }

    // MARK: Pieces

    /// A sub-caption inside a section, one step down from the title.
    private func caption(_ title: String) -> some View {
        Text(title).font(Tok.Face.ui(Tok.Typography.Size.xs))
            .foregroundStyle(Tok.Ink.tertiary.color)
    }

    private func laneWords(_ lanes: [ScanLane]) -> String? {
        lanes.isEmpty ? nil : lanes.map(\.word).joined(separator: ", ")
    }
}

// MARK: - Progress rule

/// A thin progress rule in ink on `raised` (D5): no hue, 4 pt high, the fill's
/// share is `done / total`, clamped to the track; an unknown total shows the
/// empty track.
private struct ScanJobProgressRule: View {
    var done: Int
    var total: Int

    private var fraction: Double {
        guard total > 0 else { return 0 }
        return min(1, max(0, Double(done) / Double(total)))
    }

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Rectangle().fill(Tok.Ground.raised.color)
                Rectangle().fill(Tok.Ink.primary.color)
                    .frame(width: geo.size.width * fraction)
            }
        }
        .frame(height: 4)
        .frame(maxWidth: .infinity)
        .accessibilityHidden(true)
    }
}
