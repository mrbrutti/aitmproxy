import AitmproxyKit
import SwiftUI

/// The Scan page's Site map tab (scanner v2 T9, spec D6): a job filter and a
/// search field on top, the node tree grouped by `scheme://host:port` on the
/// left, and the selected endpoint's insertion points and flows on the right.
/// Every node and point is a `scan.sitemap` value; the page's poll loop reads
/// the page when the job filter changes, Load More appends the next one.
struct ScanSitemapTab: View {
    @Bindable var state: ScanPanelState
    /// Origins whose nodes are folded away; everything opens expanded.
    @State private var collapsed: Set<String> = []
    @FocusState private var treeFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            bar
                .gridProbe("scan-sitemap-bar", area: "scan", edge: nil)
            Rule()
            if let error = state.sitemapError {
                ScanSitemapErrorLine(text: error)
                Rule(color: Tok.Line.rule)
            }
            if hasNodes {
                HStack(spacing: 0) {
                    tree
                        .frame(width: 360)
                        .gridProbe("scan-sitemap-tree", area: "scan", edge: nil)
                    VRule()
                    ScanSitemapDetail(state: state)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else {
                empty
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
    }

    // MARK: Bar

    private var hasNodes: Bool { !(state.surface.sitemap?.nodes.isEmpty ?? true) }

    private var groups: [ScanOriginGroup] { state.surface.sitemapGroupedByOrigin() }

    /// The job filter's choices, newest first: by the `scan.status` start time where
    /// this app has read one, else in the list's order behind those.
    private var jobChoices: [String] {
        let statuses = state.surface.statuses
        return state.surface.jobs.enumerated()
            .sorted { lhs, rhs in
                let left = statuses[lhs.element.job]?.startedAt ?? Int.min
                let right = statuses[rhs.element.job]?.startedAt ?? Int.min
                return left != right ? left > right : lhs.offset < rhs.offset
            }
            .map { $0.element.job }
    }

    private var jobTitle: String { state.surface.sitemapJob ?? "All jobs" }

    private var bar: some View {
        HStack(spacing: Space.sm) {
            FlatMenu(title: jobTitle, width: 200) {
                Button("All jobs") { state.surface.sitemapJob = nil }
                if !jobChoices.isEmpty { Divider() }
                ForEach(jobChoices, id: \.self) { job in
                    Button(job) { state.surface.sitemapJob = job }
                }
            }
            .help("Show the site map of one job, or of all jobs")
            TextField("Search host or path", text: $state.surface.sitemapQuery)
                .textFieldStyle(.plain)
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .padding(.horizontal, Space.sm)
                .frame(maxWidth: 320)
                .frame(height: Tok.Size.control)
                .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
                .accessibilityLabel("Search the site map")
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.filterBar)
    }

    // MARK: Tree

    @ViewBuilder private var tree: some View {
        if groups.isEmpty {
            // Nodes exist but the query matches none of them.
            Text("No endpoints match.")
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.tertiary.color)
                .padding(.horizontal, Space.md)
                .padding(.vertical, Space.sm)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(groups, id: \.origin) { group in
                        ScanSitemapOriginRow(
                            origin: group.origin, count: group.nodes.count,
                            collapsed: collapsed.contains(group.origin)
                        ) { toggle(group.origin) }
                        if !collapsed.contains(group.origin) {
                            ForEach(group.nodes, id: \.id) { node in
                                ScanNodeRow(node: node, selected: node.id == state.surface.selectedNode)
                                    .contentShape(Rectangle())
                                    .onTapGesture {
                                        state.surface.select(node: node.id)
                                        treeFocused = true
                                    }
                            }
                        }
                    }
                    if state.surface.sitemap?.nextCursor != nil {
                        FlatButton("Load More") {
                            Task { await state.refreshSitemap(append: true) }
                        }
                        .help("Read the next page of the site map")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, Space.sm)
                    }
                }
            }
            // Arrow keys walk the selection once the tree has focus (D13, the Findings list pattern).
            .focusable()
            .focused($treeFocused)
            .focusEffectDisabled()
            .onMoveCommand { direction in
                switch direction {
                case .up: move(by: -1)
                case .down: move(by: 1)
                default: break
                }
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Site map")
        }
    }

    private func toggle(_ origin: String) {
        if collapsed.contains(origin) { collapsed.remove(origin) } else { collapsed.insert(origin) }
    }

    /// Moves over the visible node order; a node inside a folded origin unfolds it,
    /// so the keyboard never lands on a row that is not on screen.
    private func move(by delta: Int) {
        state.surface.moveSelection(in: .sitemap, by: delta)
        guard let id = state.surface.selectedNode,
              let node = state.surface.sitemap?.nodes.first(where: { $0.id == id }) else { return }
        collapsed.remove(node.origin)
    }

    // MARK: Empty

    private var empty: some View {
        ContentUnavailableView {
            Label("No site map yet", systemImage: Tok.Glyph.search)
        } description: {
            Text("No site map yet — a running job fills this as it crawls.")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Rows

/// One `scheme://host:port` disclosure row: a chevron that folds the origin's
/// nodes, the origin itself, and the node count in tertiary.
private struct ScanSitemapOriginRow: View {
    var origin: String
    var count: Int
    var collapsed: Bool
    var toggle: () -> Void

    var body: some View {
        HStack(spacing: Space.sm) {
            Button(action: toggle) {
                Image(systemName: Tok.Glyph.chevron)
                    .font(.system(size: Tok.Size.iconInline, weight: .medium))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .rotationEffect(.degrees(collapsed ? 0 : 90))
                    .frame(width: Space.lg, height: Tok.Size.Row.dense)
                    .contentShape(Rectangle())
            }
            .buttonStyle(PressStyle())
            .help("Collapse or expand this origin")
            Text(origin)
                .font(Tok.Face.data(Tok.Typography.Size.md, .medium))
                .foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: Space.xs)
            Text("\(count)")
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.tertiary.color)
                .monospacedDigit()
        }
        .padding(.leading, Space.sm)
        .padding(.trailing, Space.md)
        .frame(maxWidth: .infinity, minHeight: Tok.Size.Row.dense, alignment: .leading)
        .contentShape(Rectangle())
        .onTapGesture(perform: toggle)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(origin), \(scanSitemapPlural(count, "endpoint")), \(collapsed ? "collapsed" : "expanded")")
        .accessibilityAddTraits(.isButton)
        .accessibilityAction(named: "Collapse or expand", toggle)
    }
}

/// One endpoint of the tree: method pill, path template, the points count, and
/// the audited / needs-a-session glyphs. Selection is the `active` ground.
struct ScanNodeRow: View {
    var node: ScanSiteNode
    var selected: Bool

    var body: some View {
        HStack(spacing: Space.sm) {
            Badge(text: node.method, pair: HTTPMethod(node.method).badge)
            Text(node.pathTemplate)
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: Space.xs)
            if node.auth {
                Image(systemName: Tok.Glyph.lock)
                    .font(.system(size: Tok.Size.iconInline, weight: .medium))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .help("Needs a session")
            }
            if node.audited {
                Image(systemName: "checkmark")
                    .font(.system(size: Tok.Size.iconInline, weight: .medium))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .help("Audited")
            }
            Text("\(node.points)")
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .monospacedDigit()
        }
        .padding(.leading, Space.xxl)
        .padding(.trailing, Space.md)
        .frame(maxWidth: .infinity, minHeight: Tok.Size.Row.dense, alignment: .leading)
        .background(selected ? Tok.Ground.active.color : .clear)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(ScanFormat.nodeAccessibilityLabel(node))
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// One insertion point of the selected endpoint: kind (grey — a kind is not a
/// severity), name, the JSON path when there is one, traits in tertiary, the
/// example exactly as the core returned it (`<redacted>` reads as is), and how
/// often the crawl saw it.
struct ScanInsertionPointRow: View {
    var point: ScanInsertionPoint

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                Badge(text: point.kind, pair: Tok.Severity.info, uppercase: false)
                Text(point.name)
                    .font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                if let path = point.path, !path.isEmpty {
                    Text(path)
                        .font(Tok.Face.data(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.secondary.color)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer(minLength: Space.xs)
                Text("×\(point.frequency)")
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .monospacedDigit()
            }
            if !point.traits.isEmpty {
                HStack(spacing: Space.sm) {
                    ForEach(Array(point.traits.enumerated()), id: \.offset) { _, trait in
                        Text(trait)
                            .font(Tok.Face.ui(Tok.Typography.Size.sm))
                            .foregroundStyle(Tok.Ink.tertiary.color)
                    }
                }
            }
            if let example = point.example, !example.isEmpty {
                Text(example)
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(Space.sm)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
            }
        }
        .padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(ScanFormat.pointAccessibilityLabel(point))
    }
}

// MARK: - Detail

/// The selected endpoint: its URL, its insertion points, and the flows the
/// crawl reached it in (each opens in the inspector while it is still listed).
private struct ScanSitemapDetail: View {
    @Bindable var state: ScanPanelState

    private var node: ScanSiteNode? {
        guard let id = state.surface.selectedNode else { return nil }
        return state.surface.sitemap?.nodes.first { $0.id == id }
    }

    var body: some View {
        if let node {
            let points = state.surface.points(for: node.id)
            ScrollView {
                VStack(alignment: .leading, spacing: Space.lg) {
                    HStack(spacing: Space.sm) {
                        Badge(text: node.method, pair: HTTPMethod(node.method).badge)
                        Text(node.origin + node.pathTemplate)
                            .font(Tok.Face.data(Tok.Typography.Size.md))
                            .foregroundStyle(Tok.Ink.primary.color)
                            .textSelection(.enabled)
                            .lineLimit(2)
                            .truncationMode(.middle)
                    }
                    .frame(minHeight: Tok.Size.Row.dense)

                    section("Insertion points", count: points.count)
                    if points.isEmpty {
                        Hint(text: "None on this endpoint.")
                    } else {
                        VStack(spacing: 0) {
                            ForEach(points, id: \.id) { point in
                                ScanInsertionPointRow(point: point)
                            }
                        }
                    }

                    section("Flows", count: node.flows.count)
                    if node.flows.isEmpty {
                        Hint(text: "None recorded for this endpoint.")
                    } else {
                        VStack(spacing: 0) {
                            ForEach(Array(node.flows.enumerated()), id: \.offset) { _, id in
                                ScanEndpointRow(url: state.flowLabel(id) ?? id, linked: true, openable: state.isListed(id)) {
                                    state.openFlow(id)
                                }
                            }
                        }
                    }
                }
                .padding(Space.md)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            Text("Select an endpoint.")
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.tertiary.color)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func section(_ title: String, count: Int) -> some View {
        HStack(spacing: Space.sm) {
            Text(title.uppercased())
                .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                .tracking(0.6)
                .foregroundStyle(Tok.Ink.tertiary.color)
            Text("\(count)")
                .font(Tok.Face.ui(Tok.Typography.Size.xs))
                .foregroundStyle(Tok.Ink.tertiary.color)
                .monospacedDigit()
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }
}

/// The `sitemapError` line under the bar (D11: inline).
private struct ScanSitemapErrorLine: View {
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
    }
}

/// `1 endpoint` / `3 endpoints` — the Kit's `ScanFormat.plural` is not public.
private func scanSitemapPlural(_ n: Int, _ noun: String) -> String {
    "\(n) \(noun)\(n == 1 ? "" : "s")"
}
