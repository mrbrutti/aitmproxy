import AitmproxyKit
import AppKit
import SwiftUI

/// The Status page (spec 2026-10-31 macOS status page §2): the first thing a fresh
/// session shows. Three lane cards — Core, Bus, Capture — each a state dot + word, the
/// one fact under it, the remedy when something needs doing, and its actions; then the
/// Getting-started checklist and the last five flows. Every word comes from
/// `Session.connectionSummary`, so this page, the toolbar's connection cluster, the Core
/// Log header and the Settings rows can never disagree. Hue only on the state dot; hairline rules, no cards-with-shadows.
struct StatusPanel: View {
    @Environment(Session.self) private var session
    @Environment(\.openSettings) private var openSettings
    @State private var width: CGFloat = 0
    @State private var confirmingUninstall = false

    /// Below this the three lane cards stack.
    private static let sideBySideMin: CGFloat = 900
    private static let recentCount = 5

    private var sideBySide: Bool { width >= Self.sideBySideMin }

    /// Side by side, each card takes a third of the content width rounded down to the 4 pt
    /// grid, so every card's leading edge lands on the grid whatever the window width.
    private var cardWidth: CGFloat? {
        guard sideBySide else { return nil }
        let content = width - Space.margin * 2 - Space.xl * 2
        return max(Space.xs, floor(content / 3 / Space.xs) * Space.xs)
    }

    var body: some View {
        let summary = session.connectionSummary
        VStack(spacing: 0) {
            PageHeader("Status") {
                FlatButton("Open Browser", symbol: Tok.Glyph.browser) { run(.openBrowser) }
                    .help("Open the built-in browser, already pointed at the proxy")
                FlatButton("Copy Address", symbol: Tok.Glyph.copy) { run(.copyListenAddress) }
                    .help("Copy \(summary.listenAddress)")
            }
            // The header band spans the full width (inset 0) while the sections sit at the page
            // margin, so it is not part of the sections' leading-edge chain.
            .gridProbe("status.title", area: "status", edge: nil)
            Rule()
            ScrollView {
                VStack(alignment: .leading, spacing: Space.section) {
                    lanes(summary)
                    // Hairlines sit in a 4 pt box so the gaps between sections stay on the grid.
                    Rule(color: Tok.Line.rule).frame(height: Space.xs)
                    gettingStarted(summary)
                        .gridProbe("status.steps", area: "status")
                    Rule(color: Tok.Line.rule).frame(height: Space.xs)
                    recent(summary)
                        .gridProbe("status.recent", area: "status")
                }
                .padding(Space.margin)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        // The page never reports a minimum width to the shell split (see OverviewPanel).
        .frame(minWidth: 0, maxWidth: .infinity)
        .background(Tok.Ground.surface.color)
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width = $0 }
        .gridArea("status", inset: 0)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Status")
        .confirmationDialog(
            "Uninstall the capture extension?", isPresented: $confirmingUninstall, titleVisibility: .visible
        ) {
            Button("Uninstall", role: .destructive) {
                Task { await CaptureSwitch.uninstall(session: session) }
            }
        } message: {
            Text("Capture stops, and the extension and its proxy configuration are removed. Turning capture on again installs the extension again and asks for approval again.")
        }
    }

    // MARK: Lanes

    private func lanes(_ summary: ConnectionSummary) -> some View {
        let layout = sideBySide
            ? AnyLayout(HStackLayout(alignment: .top, spacing: Space.xl))
            : AnyLayout(VStackLayout(alignment: .leading, spacing: Space.xl))
        let busy = session.coreHealth.captureBusy
        return layout {
            ForEach(summary.lanes, id: \.kind) { lane in
                LaneCard(lane: lane, captureBusy: busy, run: run)
                    .frame(width: cardWidth, alignment: .leading)
                    .gridProbe("status.\(lane.kind.rawValue)", area: "status", edge: nil)
            }
            // No trailing Spacer: it would add one more HStack spacing (20 pt) and push the
            // row past the viewport, which centres the whole page on a half point.
        }
    }

    // MARK: Getting started

    private func gettingStarted(_ summary: ConnectionSummary) -> some View {
        VStack(alignment: .leading, spacing: Space.md) {
            TrackedLabel("Getting started").accessibilityAddTraits(.isHeader)
            if summary.allStepsDone {
                Text("Everything is connected — \(Format.count(session.rows.count, "flow")) captured")
                    .font(Tok.Face.ui(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .frame(height: Tok.Size.Row.default)
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(summary.steps, id: \.kind) { step in
                        StepRow(step: step, run: run)
                        if step.kind != summary.steps.last?.kind {
                            Rule(color: Tok.Line.rule)
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Getting started")
    }

    // MARK: Recent

    private func recent(_ summary: ConnectionSummary) -> some View {
        let rows = recentRows
        return VStack(alignment: .leading, spacing: Space.md) {
            TrackedLabel("Recent").accessibilityAddTraits(.isHeader)
            if rows.isEmpty {
                Text("No flows yet — point a client at \(summary.listenAddress)")
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .frame(height: Tok.Size.Row.default)
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(rows) { row in
                        RecentFlowRow(row: row) {
                            session.select(row.id)
                            session.show(.domains)
                        }
                        if row.id != rows.last?.id {
                            Rule(color: Tok.Line.rule)
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Recent flows")
    }

    /// The last five flows by `seq`, newest first. One pass over the rows: the list can
    /// hold thousands and this page re-renders on every arrival.
    private var recentRows: [FlowRow] {
        var top: [FlowRow] = []
        top.reserveCapacity(Self.recentCount + 1)
        for row in session.rows {
            if top.count < Self.recentCount {
                top.append(row)
                top.sort { $0.seq > $1.seq }
            } else if let last = top.last, row.seq > last.seq {
                top[top.count - 1] = row
                top.sort { $0.seq > $1.seq }
            }
        }
        return top
    }

    // MARK: Actions

    /// Every card and step action goes through `Session.perform(connection:)` — the same
    /// entry its menu-bar item uses. The ones that need this view (Settings, the operator-only
    /// capture switch, the uninstall confirmation) come back `false` and are taken here.
    private func run(_ action: ConnectionAction) {
        if session.perform(connection: action) { return }
        switch action {
        case .startCore, .restartCore:
            // The same bump as Proxy ▸ Restart Core: ShellView restarts the embedded core, which
            // re-reads the capture choice — an operator action, so it lives in this view, not Session.
            session.restartCoreTick += 1
        case .switchToEmbedded, .openBusSettings:
            session.settingsTab = .bus
            openSettings()
        case .openCaptureSettings:
            session.settingsTab = .capture
            openSettings()
        case .turnCaptureOn:
            Task { await CaptureSwitch.set(true, session: session) }
        case .turnCaptureOff:
            Task { await CaptureSwitch.set(false, session: session) }
        case .uninstallExtension:
            confirmingUninstall = true
        case .showCoreLog, .reconnectBus, .openScope, .openBrowser, .copyListenAddress, .approveInSystemSettings:
            break // handled by Session.perform(connection:) above
        }
    }
}

// MARK: - Lane card

/// One lane: tracked section label, dot + word (16/600), the fact in mono, the remedy,
/// then the actions — the first always a button, the Settings/uninstall ones behind `⋯`.
private struct LaneCard: View {
    var lane: ConnectionLane
    var captureBusy: Bool
    var run: (ConnectionAction) -> Void

    /// Actions that live in the trailing menu rather than inline (never the primary one).
    private static func isMenuItem(_ action: ConnectionAction) -> Bool {
        action == .uninstallExtension || action == .openCaptureSettings || action == .openBusSettings
    }

    /// Actions `CaptureSwitch` serializes: they stand down while one runs.
    private static func isCaptureAction(_ action: ConnectionAction) -> Bool {
        action == .turnCaptureOn || action == .turnCaptureOff || action == .uninstallExtension
    }

    private var primary: ConnectionAction? { lane.actions.first }
    private var inline: [ConnectionAction] { Array(lane.actions.dropFirst()).filter { !Self.isMenuItem($0) } }
    private var menu: [ConnectionAction] { Array(lane.actions.dropFirst()).filter { Self.isMenuItem($0) } }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            TrackedLabel(lane.kind.title).accessibilityAddTraits(.isHeader)
            LaneDot(lane: lane)
                .font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold))
                .foregroundStyle(Tok.Ink.primary.color)
            Text(lane.detail)
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
                .help(lane.detail)
            if let remedy = lane.remedy {
                Text(remedy)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !lane.actions.isEmpty {
                actions
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(lane.kind.title): \(lane.word)")
    }

    private var actions: some View {
        HStack(spacing: Space.xs) {
            if let primary {
                FlatButton(primary.title) { run(primary) }
                    .disabled(captureBusy && Self.isCaptureAction(primary))
            }
            ForEach(inline, id: \.self) { action in
                FlatButton(action.title) { run(action) }
                    .disabled(captureBusy && Self.isCaptureAction(action))
            }
            if !menu.isEmpty {
                Menu {
                    ForEach(menu, id: \.self) { action in
                        Button(action.title, role: action.isDestructive ? .destructive : nil) { run(action) }
                            .disabled(captureBusy && Self.isCaptureAction(action))
                    }
                } label: {
                    Image(systemName: "ellipsis")
                        .font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                        .foregroundStyle(Tok.Ink.secondary.color)
                        .frame(width: Tok.Size.control, height: Tok.Size.control)
                        .contentShape(Rectangle())
                }
                .menuStyle(.button)
                .buttonStyle(.plain)
                .menuIndicator(.hidden)
                .help("More \(lane.kind.title) actions")
                .accessibilityLabel("More \(lane.kind.title) actions")
            }
        }
    }
}

// MARK: - Getting-started row

/// `✓` (done: success + secondary word) or `○` (to do: primary word + its one action).
private struct StepRow: View {
    var step: GettingStartedStep
    var run: (ConnectionAction) -> Void

    var body: some View {
        HStack(spacing: Space.md) {
            Image(systemName: step.done ? "checkmark.circle.fill" : "circle")
                .font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                .foregroundStyle(step.done ? Tok.Status.success.color : Tok.Ink.tertiary.color)
                .frame(width: Tok.Size.icon)
                .accessibilityHidden(true)
            Text(step.title)
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .foregroundStyle(step.done ? Tok.Ink.secondary.color : Tok.Ink.primary.color)
                .lineLimit(1)
                .truncationMode(.tail)
            Spacer(minLength: Space.sm)
            if !step.done, let action = step.action {
                FlatButton(action.title) { run(action) }
            }
        }
        .frame(height: Tok.Size.Row.default)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(step.done ? "Done" : "To do"): \(step.title)")
    }
}

// MARK: - Recent flow row

/// One compact flow row: the method badge, the URL middle-truncated, the status (or the
/// state word) in its colour, a chevron on hover. The Overview breakdowns' list row,
/// kept private here on purpose: the two pages may drift apart.
private struct RecentFlowRow: View {
    var row: FlowRow
    var action: () -> Void
    @State private var hovered = false

    private static let trailingWidth: CGFloat = 80

    var body: some View {
        Button(action: action) {
            HStack(spacing: Space.sm) {
                Badge(text: row.method.label, pair: row.method.badge)
                Text(row.url)
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text(Self.statusText(row))
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Self.statusColor(row).color)
                    .lineLimit(1)
                    .frame(width: Self.trailingWidth, alignment: .trailing)
                Image(systemName: Tok.Glyph.chevron)
                    .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .opacity(hovered ? 1 : 0)
                    .accessibilityHidden(true)
            }
            .padding(.horizontal, Space.xs)
            .frame(height: Tok.Size.Row.default)
            .background(hovered ? Tok.Ground.hover.color : .clear,
                        in: RoundedRectangle(cornerRadius: Tok.Radius.badge))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
        .help(row.url)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(row.method.label), \(row.url), \(Self.statusText(row))")
        .accessibilityHint("Opens the flow")
    }

    private static func statusText(_ row: FlowRow) -> String {
        if let status = row.status { return String(status) }
        return row.state.label
    }

    private static func statusColor(_ row: FlowRow) -> DynamicColor {
        if let status = row.status, let cls = StatusClass(status) { return cls.color }
        return row.state == .failed ? Tok.Status.serverError : Tok.Ink.secondary
    }
}
