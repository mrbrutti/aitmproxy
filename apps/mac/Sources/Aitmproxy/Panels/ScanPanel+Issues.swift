import AitmproxyKit
import SwiftUI

// The Scan page's Issues tab (scanner v2 T9, spec D7, D11, D12, D13): a filter
// bar whose menus are the `scan.issues` parameters, the issues grouped by
// severity on the left, and the selected issue's evidence on the right. Every
// string a row or the detail renders comes from `ScanFormat` or the wire value
// itself; the only hue is on the severity pills and the section headers, which
// are the datum. The poll loop in `ScanPanelState` re-reads the page whenever
// `surface.filters` changes and loads the selected issue's detail by itself, so
// this file only mutates the model and calls the intents.

/// The Issues tab: filters, the grouped list (360 pt) and the detail pane.
struct ScanIssuesTab: View {
    @Bindable var state: ScanPanelState
    @FocusState private var listFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            ScanIssueFilterBar(state: state)
            Rule()
            if let error = state.surface.issuesError {
                ScanIssueErrorLine(text: error)
                Rule()
            }
            HStack(spacing: 0) {
                list
                    .frame(width: 360)
                    .gridProbe("scan-issues-list", area: "scan-issues", edge: nil)
                VRule()
                detail
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .gridProbe("scan-issues-detail", area: "scan-issues", edge: nil)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .gridArea("scan-issues", inset: 0)
    }

    // MARK: List

    @ViewBuilder private var list: some View {
        let sections = state.surface.issuesGroupedBySeverity()
        if sections.isEmpty {
            ContentUnavailableView {
                Label("No issues", systemImage: Tok.Glyph.search)
            } description: {
                Text("Start a scan, or widen the filters.")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
                    ForEach(sections, id: \.severity) { section in
                        Section {
                            ForEach(section.issues, id: \.id) { issue in
                                ScanIssueRow(issue: issue, selected: issue.id == state.surface.selectedIssue)
                                    .contentShape(Rectangle())
                                    .onTapGesture {
                                        state.surface.select(issue: issue.id)
                                        listFocused = true
                                    }
                            }
                        } header: {
                            ScanIssueSectionHeader(section: section)
                        }
                    }
                    if state.surface.issuesCursor != nil {
                        FlatButton("Load More") { Task { await state.refreshIssues(append: true) } }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, Space.sm)
                    }
                }
            }
            // Arrow keys walk the selection once the list has focus (the Findings list pattern).
            .focusable()
            .focused($listFocused)
            .focusEffectDisabled()
            .onMoveCommand { direction in
                switch direction {
                case .up: state.surface.moveSelection(in: .issues, by: -1)
                case .down: state.surface.moveSelection(in: .issues, by: 1)
                default: break
                }
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Issues")
        }
    }

    // MARK: Detail

    @ViewBuilder private var detail: some View {
        if let issue = state.surface.issueDetail {
            // Keyed on the id so the status and note fields start fresh per issue.
            ScanIssueDetail(state: state, issue: issue)
                .id(issue.id)
        } else {
            ContentUnavailableView {
                Label("No issue selected", systemImage: Tok.Glyph.search)
            } description: {
                Text("Select an issue to read its evidence.")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

// MARK: - Filter bar

/// The six `scan.issues` parameters as `FlatMenu`s bound to `surface.filters`.
/// A change here is a new read, made by the poll loop; nothing is sieved locally.
private struct ScanIssueFilterBar: View {
    var state: ScanPanelState

    private var filters: ScanIssueFilters { state.surface.filters }

    /// Info first, as the menu reads "at least …".
    private static let severities: [ScanSeverity] = [.info, .low, .medium, .high, .critical]
    private static let confidences: [ScanConfidence] = [.tentative, .firm, .certain]
    private static let lanes: [ScanLane] = [.http, .ws, .l4Packet, .l4Stream]
    private static let statuses: [ScanIssueStatus] = [.open, .confirmed, .falsePositive]

    /// The distinct classes of the loaded issues, sorted; the one filtered on
    /// stays listed even when the page no longer carries it, so it can be unset.
    private var classes: [String] {
        var set = Set(state.surface.issues.map(\.klass))
        if let klass = filters.klass { set.insert(klass) }
        return set.sorted()
    }

    var body: some View {
        HStack(spacing: Space.sm) {
            FlatMenu(title: "Job: \(filters.job ?? "All")", width: 160) {
                Button("All") { state.surface.filters.job = nil }
                ForEach(state.surface.jobs, id: \.job) { job in
                    Button(job.job) { state.surface.filters.job = job.job }
                }
            }
            .help("Filter the issues by job")
            FlatMenu(title: "Severity ≥ \(filters.severityMin?.word ?? "Any")", width: 144) {
                Button("Any") { state.surface.filters.severityMin = nil }
                ForEach(Self.severities, id: \.self) { severity in
                    Button(severity.word) { state.surface.filters.severityMin = severity }
                }
            }
            .help("Show issues of at least this severity")
            FlatMenu(title: "Confidence ≥ \(filters.confidenceMin.map(\.word) ?? "Any")", width: 160) {
                Button("Any") { state.surface.filters.confidenceMin = nil }
                ForEach(Self.confidences, id: \.self) { confidence in
                    Button(confidence.word) { state.surface.filters.confidenceMin = confidence }
                }
            }
            .help("Show issues of at least this confidence")
            FlatMenu(title: "Lane: \(filters.lane?.word ?? "Any")", width: 136) {
                Button("Any") { state.surface.filters.lane = nil }
                ForEach(Self.lanes, id: \.self) { lane in
                    Button(lane.word) { state.surface.filters.lane = lane }
                }
            }
            .help("Filter the issues by lane")
            FlatMenu(title: "Class: \(filters.klass ?? "Any")", width: 160) {
                Button("Any") { state.surface.filters.klass = nil }
                ForEach(classes, id: \.self) { klass in
                    Button(klass) { state.surface.filters.klass = klass }
                }
            }
            .help("Filter the issues by check class")
            FlatMenu(title: "Status: \(filters.status?.word ?? "All")", width: 152) {
                Button("All") { state.surface.filters.status = nil }
                ForEach(Self.statuses, id: \.self) { status in
                    Button(status.word) { state.surface.filters.status = status }
                }
            }
            .help("Filter the issues by triage status")
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.filterBar)
    }
}

/// A failed read or update, inline under the filter bar; the list it could not
/// refresh stays as it was (D11).
private struct ScanIssueErrorLine: View {
    var text: String

    var body: some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Status.serverError.color)
            .lineLimit(2)
            .textSelection(.enabled)
            .padding(.horizontal, Space.md)
            .padding(.vertical, Space.xs)
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityLabel("Error: \(text)")
    }
}

// MARK: - List parts

/// "HIGH 1": tracked xs caps in the severity's colour — the one header with hue.
private struct ScanIssueSectionHeader: View {
    var section: ScanIssueSection

    var body: some View {
        Text(section.title)
            .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
            .foregroundStyle(section.severity.known?.pair.fg.color ?? Tok.Ink.tertiary.color)
            .lineLimit(1)
            .padding(.horizontal, Space.md)
            .frame(maxWidth: .infinity, minHeight: Tok.Size.columnHeader, alignment: .leading)
            .background(Tok.Ground.surface.color)
            .overlay(alignment: .bottom) { Rule() }
            .accessibilityAddTraits(.isHeader)
    }
}

/// One issue: the severity pill, the name, the request line, and the triage glyphs.
struct ScanIssueRow: View {
    var issue: ScanIssueSummary
    var selected: Bool

    private var line2: String { ScanFormat.issueRowLine2(issue) }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                Badge(text: issue.severity.word, pair: issue.severity.known?.pair ?? Tok.Severity.info)
                Text(issue.name).font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                    .foregroundStyle(Tok.Ink.primary.color).lineLimit(1)
                Spacer(minLength: Space.xs)
                glyphs
            }
            Text(line2).font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color).lineLimit(1).truncationMode(.middle)
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(selected ? Tok.Ground.active.color : .clear)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(issue.severity.word), \(issue.name), \(line2), \(issue.status.word)")
    }

    @ViewBuilder private var glyphs: some View {
        HStack(spacing: Space.xs) {
            switch issue.status {
            case .confirmed:
                glyph("checkmark.seal").help("Confirmed")
            case .falsePositive:
                glyph("xmark.seal").help("False positive")
            case .open, .other:
                EmptyView()
            }
            if issue.findingId != nil {
                glyph(Tok.Glyph.poc).help("Has a finding")
            }
        }
    }

    private func glyph(_ name: String) -> some View {
        Image(systemName: name)
            .font(.system(size: Tok.Size.iconInline, weight: .medium))
            .foregroundStyle(Tok.Ink.tertiary.color)
    }
}

// MARK: - Detail

/// The selected issue's evidence (`scan.issue {id}`), with the status segment,
/// the note field and the links out. Status and note mirror the detail into
/// local state so a refused update snaps the control back (D11).
struct ScanIssueDetail: View {
    var state: ScanPanelState
    var issue: ScanIssue
    @State private var status: ScanIssueStatus
    @State private var note: String

    init(state: ScanPanelState, issue: ScanIssue) {
        self.state = state
        self.issue = issue
        _status = State(initialValue: issue.status)
        _note = State(initialValue: issue.note ?? "")
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Rule()
            content
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onChange(of: status) { _, new in
            guard new != issue.status else { return }
            Task { await state.updateIssueStatus(issue.id, new) }
        }
        .onChange(of: issue.status) { _, new in status = new }
        .onChange(of: issue.note) { _, new in note = new ?? "" }
    }

    /// Milliseconds since the epoch, for `ScanFormat.issueMetaLine`.
    private static var nowMs: Int { Int(Date().timeIntervalSince1970 * 1000) }

    // MARK: Header

    private var header: some View {
        HStack(spacing: Space.md) {
            Text(issue.name).font(Tok.Face.ui(Tok.Typography.Size.xl, .medium))
                .foregroundStyle(Tok.Ink.primary.color).lineLimit(1)
            Badge(text: issue.severity.word, pair: issue.severity.known?.pair ?? Tok.Severity.info)
            Badge(text: issue.confidence.word, pair: Tok.State.neutral)
            Badge(text: issue.lane.word, pair: Tok.State.neutral)
            Spacer(minLength: Space.sm)
            Picker("Status", selection: $status) {
                Text(ScanIssueStatus.open.word).tag(ScanIssueStatus.open)
                Text(ScanIssueStatus.confirmed.word).tag(ScanIssueStatus.confirmed)
                Text(ScanIssueStatus.falsePositive.word).tag(ScanIssueStatus.falsePositive)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help("Set the issue's triage status")
            .accessibilityLabel("Status")
        }
        .padding(.horizontal, Space.margin)
        .frame(height: Tok.Size.inspectorHeader)
    }

    // MARK: Content

    private var content: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.lg) {
                sectionTitle("Where")
                whereBlock

                sectionTitle("Description")
                paragraph(issue.description)

                if let remediation = issue.remediation, !remediation.isEmpty {
                    sectionTitle("Remediation")
                    paragraph(remediation)
                }

                sectionTitle("Evidence")
                evidence

                sectionTitle("Probe flows")
                flowRows(issue.evidence.probeFlows)

                sectionTitle("Baseline flow")
                flowRows(issue.evidence.baselineFlow.map { [$0] } ?? [])

                if issue.pocRef != nil || issue.findingId != nil {
                    sectionTitle("Links")
                    links
                }

                sectionTitle("Note")
                noteField

                Text(ScanFormat.issueMetaLine(issue, now: Self.nowMs))
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .textSelection(.enabled)
            }
            .padding(Space.md)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder private var whereBlock: some View {
        let location = issue.location
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(ScanFormat.issueWhere(issue.summary))
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.primary.color)
                .textSelection(.enabled)
            if location.pathTemplate != location.path {
                Text(location.pathTemplate)
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .textSelection(.enabled)
            }
            if let fieldPath = location.fieldPath, !fieldPath.isEmpty {
                keyValue("field path", fieldPath)
            }
            if let wsPath = location.wsPath, !wsPath.isEmpty {
                keyValue("ws path", wsPath)
            }
            if let l4 = location.l4 {
                keyValue("l4", "\(l4.proto) \(l4.ip):\(l4.port)")
                if let grammar = l4.grammar, !grammar.isEmpty { keyValue("grammar", grammar) }
                if let fieldPath = l4.fieldPath, !fieldPath.isEmpty { keyValue("l4 field path", fieldPath) }
                if let mutation = l4.mutation, !mutation.isEmpty { keyValue("mutation", mutation) }
            }
        }
    }

    @ViewBuilder private var evidence: some View {
        let ev = issue.evidence
        if ev.payload == nil, ev.matched == nil, ev.timing == nil, ev.diff == nil, ev.l4 == nil {
            Hint(text: "No evidence recorded for this issue.")
        } else {
            VStack(alignment: .leading, spacing: Space.md) {
                if let payload = ev.payload {
                    subTitle("Payload")
                    dataBox(payload)
                }
                if let matched = ev.matched {
                    subTitle("Matched")
                    dataBox(matched)
                }
                if let timing = ev.timing {
                    subTitle("Timing")
                    timingBlock(timing)
                }
                if let diff = ev.diff {
                    subTitle("Diff")
                    Text("baseline \(diff.baselineLen) · true \(diff.trueLen) · false \(diff.falseLen)")
                        .font(Tok.Face.data(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.primary.color)
                        .textSelection(.enabled)
                }
                if let l4 = ev.l4 {
                    subTitle("L4")
                    l4Block(l4)
                }
            }
        }
    }

    private func timingBlock(_ timing: ScanTiming) -> some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Text("slope \(ScanFormat.number(timing.slope)) · r \(ScanFormat.number(timing.r))")
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.primary.color)
                .textSelection(.enabled)
            let rows = max(timing.requestedS.count, timing.observedMs.count, timing.baselineMs.count)
            Grid(alignment: .leading, horizontalSpacing: Space.lg, verticalSpacing: Space.xs) {
                GridRow {
                    columnHead("requested_s")
                    columnHead("observed_ms")
                    columnHead("baseline_ms")
                }
                ForEach(0..<rows, id: \.self) { index in
                    GridRow {
                        cell(timing.requestedS.indices.contains(index) ? ScanFormat.number(timing.requestedS[index]) : "—")
                        cell(timing.observedMs.indices.contains(index) ? String(timing.observedMs[index]) : "—")
                        cell(timing.baselineMs.indices.contains(index) ? String(timing.baselineMs[index]) : "—")
                    }
                }
            }
        }
    }

    private func l4Block(_ l4: ScanL4Evidence) -> some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            subTitle("Sent (hex)")
            dataBox(l4.sentHex)
            VStack(alignment: .leading, spacing: Space.xs) {
                keyValue("seed id", l4.seedId)
                keyValue("rng seed", String(l4.rngSeed))
                if !l4.mutationChain.isEmpty { keyValue("mutation chain", l4.mutationChain.joined(separator: " → ")) }
                keyValue("prior messages", String(l4.priorMessages))
                keyValue("liveness before", ScanFormat.yesNo(l4.livenessBefore))
                keyValue("liveness after", ScanFormat.yesNo(l4.livenessAfter))
                keyValue("reproduced", "\(l4.reproducedHits) / \(l4.reproducedTries)")
                keyValue("scope entry", l4.scopeEntry)
                if !l4.oracle.isNull { keyValue("oracle", l4.oracle.serialized()) }
            }
        }
    }

    @ViewBuilder private func flowRows(_ ids: [String]) -> some View {
        if ids.isEmpty {
            Hint(text: "None")
        } else {
            VStack(spacing: 0) {
                ForEach(ids, id: \.self) { id in
                    ScanEndpointRow(url: state.flowLabel(id) ?? id, linked: true, openable: state.isListed(id)) {
                        state.openFlow(id)
                    }
                }
            }
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.border.color))
        }
    }

    private var links: some View {
        HStack(spacing: Space.sm) {
            if let ref = issue.pocRef {
                FlatButton("Open PoC") { state.openPoC(ref: ref, findingId: issue.findingId) }
                    .help("Open the PoC in Findings")
            }
            if let findingId = issue.findingId {
                FlatButton("Open Finding") { state.openPoC(ref: issue.pocRef, findingId: findingId) }
                    .help("Open the finding in Findings")
            }
        }
    }

    private var noteField: some View {
        HStack(spacing: Space.sm) {
            TextField("Add a note", text: $note)
                .textFieldStyle(.plain)
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .padding(.horizontal, Space.sm)
                .frame(height: Tok.Size.control)
                .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
                .onSubmit { Task { await state.saveNote(issue.id, note: note) } }
                .accessibilityLabel("Note")
            FlatButton("Save Note") { Task { await state.saveNote(issue.id, note: note) } }
                .disabled(note == (issue.note ?? ""))
                .help("Save the note with the issue's current status")
        }
    }

    // MARK: Parts

    private func sectionTitle(_ title: String) -> some View {
        Text(title.uppercased()).font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
            .foregroundStyle(Tok.Ink.tertiary.color)
            .accessibilityAddTraits(.isHeader)
    }

    private func subTitle(_ title: String) -> some View {
        Text(title).font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
            .foregroundStyle(Tok.Ink.secondary.color)
    }

    private func columnHead(_ title: String) -> some View {
        Text(title).font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.5)
            .foregroundStyle(Tok.Ink.tertiary.color)
            .lineLimit(1)
    }

    private func cell(_ text: String) -> some View {
        Text(text).font(Tok.Face.data(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.primary.color)
            .textSelection(.enabled)
    }

    private func paragraph(_ text: String) -> some View {
        Text(text).font(Tok.Face.ui(Tok.Typography.Size.md))
            .foregroundStyle(Tok.Ink.primary.color)
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func keyValue(_ key: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Space.sm) {
            Text(key).font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                .foregroundStyle(Tok.Ink.tertiary.color)
                .frame(width: 112, alignment: .leading)
            Text(value).font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.primary.color)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(key), \(value)")
    }

    /// A selectable data-face block on `raised`: the payload exactly as sent, the match exactly as seen.
    private func dataBox(_ text: String) -> some View {
        Text(text)
            .font(Tok.Face.data(Tok.Typography.Size.md))
            .foregroundStyle(Tok.Ink.primary.color)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
            .padding(Space.sm)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
    }
}
