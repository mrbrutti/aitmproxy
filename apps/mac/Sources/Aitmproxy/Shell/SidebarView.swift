import AitmproxyKit
import SwiftUI

/// Traffic: Flows, Apps, Domains, Pinned, Connections, Overview · Testing: Scope, Scan,
/// Findings, Browser · Automation: Scripts, Agent (spec §3). Flat `surface`, 28px rows,
/// counts only on queues. Apps and Domains expand to one sub-item per
/// client / host; a sub-item narrows the list (S-013); ⇧P pins one (S-014). An Apps row is a
/// tree node (icons spec D5): its chevron opens the app's domains, each a `.clientHost` narrowing.
struct SidebarView: View {
    @Environment(Session.self) private var session
    @FocusState private var filterFocused: Bool

    /// The three leading insets of the Apps tree (spec D5 / D11), on the `Space` scale: the chevron
    /// at 12, the mark (and every flat sub-item) at 28, a domain under an app at 52.
    private enum Inset {
        static let chevron = Space.md
        static let mark = Space.md + Space.lg
        static let domain = mark + Space.xxl
    }

    /// Case-insensitive substring over host / client name (S-034).
    private func matches(_ text: String) -> Bool {
        let q = session.sidebarQuery.trimmingCharacters(in: .whitespaces)
        return q.isEmpty || text.localizedCaseInsensitiveContains(q)
    }

    /// The app rule (spec D4, architect's call 12): an Apps row is visible when the query matches
    /// its name, its group key, or any of the hosts under it.
    private func matches(_ client: ClientInfo) -> Bool {
        matches(client.name) || matches(client.groupKey) || session.hosts(forClient: client.groupKey).contains { matches($0.0) }
    }

    private var querying: Bool { !session.sidebarQuery.trimmingCharacters(in: .whitespaces).isEmpty }

    var body: some View {
        VStack(spacing: 0) {
            brand
            Rule()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    // Groups by the operator's jobs (spec §3): the main work window first.
                    group("Traffic")
                    item(.flows, count: session.rows.count)
                    item(.apps, count: session.clients.count)
                    if session.page == .apps || querying {
                        let visible = session.clients.filter { matches($0.0) }
                        if querying, visible.isEmpty { hint("No match") }
                        ForEach(visible, id: \.0.groupKey) { client, count in
                            appRow(client, count: count)
                            ForEach(domains(under: client.groupKey), id: \.0) { host, count in
                                subItem(.clientHost(client: client.groupKey, host: host), title: host, count: count, page: .apps,
                                        leadingInset: Inset.domain, help: host) { Monogram(text: "◎") }
                            }
                        }
                    }
                    item(.domains, count: session.hosts.count)
                    if session.page == .domains || querying {
                        let visible = session.hosts.filter { matches($0.0) }
                        if querying, visible.isEmpty { hint("No match") }
                        ForEach(visible, id: \.0) { host, count in
                            subItem(.host(host), title: host, count: count, page: .domains) { Monogram(text: "◎") }
                        }
                    }
                    item(.pinned, count: session.pins.hosts.count + session.pins.apps.count)
                    ForEach(session.pins.hosts.filter(matches), id: \.self) { host in
                        subItem(.host(host), title: host, count: session.hosts.first { $0.0 == host }?.1, page: .pinned) {
                            Monogram(text: "◎")
                        }
                    }
                    // Pinned apps are keyed by the stored group key (D7, no migration): a key with no current
                    // client keeps its key as title and resolves through the one cache (plan call 5).
                    ForEach(session.pins.apps.filter { key in
                        matches(key) || (session.clients.first { $0.0.groupKey == key }.map { matches($0.0.name) } ?? false)
                    }, id: \.self) { key in
                        let current = session.clients.first { $0.0.groupKey == key }
                        subItem(.client(key), title: current?.0.name ?? key, count: current?.1, page: .pinned,
                                help: AppIdentifier.tooltipText(key)) {
                            ClientMark(client: current?.0 ?? ClientInfo(name: key, bundleID: key))
                        }
                    }
                    if session.page == .pinned, session.pins.isEmpty {
                        hint("Nothing pinned — press ⇧P on a row.")
                    }
                    item(.connections)
                    item(.overview)

                    group("Testing")
                    item(.scope, count: session.scopeHosts.count, queue: true)
                    // Offered only when the core lists scan.discover; the count is the injection points found.
                    if session.scanEnabled { item(.scan, count: session.scan.points.count, queue: true) }
                    item(.findings, count: session.findingsCount, queue: true)
                    item(.browser, text: session.browserTabs == 1 ? "1 tab" : "\(session.browserTabs) tabs")

                    group("Automation")
                    item(.scripts, text: "\(session.activeScripts) active")
                    item(.agent, text: "\(session.agentActionsLastMinute)/min", agent: true)
                }
                .padding(.horizontal, Space.sm)
            }
            filterField
        }
        .frame(maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .dimsWhenInactive()
    }

    /// `›•‹ aitmproxy` — the product mark and wordmark, nothing else. Connection state has one
    /// home, the toolbar's connection cluster (spec §4, revision 2); this row says nothing about it.
    private var brand: some View {
        HStack(spacing: Space.sm) {
            ProductMark().frame(width: 16, height: 16)
            Text("aitmproxy").font(Tok.Face.ui(Tok.Typography.Size.md, .medium)).foregroundStyle(Tok.Ink.primary.color)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Space.lg)
        .frame(height: Tok.Size.toolbar)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("aitmproxy")
    }

    /// Editorial section labels: small, tracked capitals in the tertiary tier.
    private func group(_ title: String) -> some View {
        Text(title.uppercased())
            .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
            .tracking(0.6)
            .foregroundStyle(Tok.Ink.tertiary.color)
            .padding(.horizontal, Space.sm)
            .padding(.top, Space.xl)
            .padding(.bottom, Space.sm)
    }

    private func hint(_ text: String) -> some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.tertiary.color)
            .padding(.leading, 28)
            .padding(.vertical, Space.xs)
    }

    private func item(_ page: SidebarPage, count: Int? = nil, text: String? = nil, queue: Bool = false,
                      agent: Bool = false) -> some View {
        let selected = session.page == page && session.group == nil
        return Button {
            session.show(page)
        } label: {
            HStack(spacing: Space.sm) {
                Image(systemName: page.symbol)
                    .font(.system(size: 12, weight: .regular))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .frame(width: 16)
                Text(page.title)
                    .font(Tok.Face.ui(Tok.Typography.Size.md, selected ? .medium : .regular))
                    .foregroundStyle(Tok.Ink.primary.color)
                Spacer(minLength: Space.xs)
                if let text {
                    countChip(text, queue: queue, agent: agent)
                } else if let count, count > 0 || !queue {
                    countChip("\(count)", queue: queue, agent: agent)
                }
            }
            .padding(.horizontal, Space.sm)
            .frame(height: Tok.Size.control)
            .background(selected ? Tok.Ground.active.color : .clear, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private func countChip(_ text: String, queue: Bool, agent: Bool) -> some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(agent ? Tok.Agent.deep.color : queue ? Tok.Ink.primary.color : Tok.Ink.secondary.color)
            .padding(.horizontal, queue || agent ? Tok.Metric.gapTight : 0)
            .frame(minWidth: queue || agent ? Tok.Metric.countChip : 0, minHeight: Tok.Metric.countChip)
            .background(agent ? Tok.Agent.tint.color : queue ? Tok.Ground.raised.color : .clear, in: Capsule())
    }

    /// The domain sub-rows an Apps row shows (spec D5, plan call 4): all of them while the app is
    /// expanded; while querying, the hosts matching the query — or all of them when the app matched
    /// only by name or key.
    private func domains(under key: String) -> [(String, Int)] {
        let hosts = session.hosts(forClient: key)
        if querying {
            let matching = hosts.filter { matches($0.0) }
            return matching.isEmpty ? hosts : matching
        }
        return session.expandedApps.contains(key) ? hosts : []
    }

    /// One Apps row (spec D5): a chevron `Button` that only opens or closes the app's domains, then
    /// the row itself (`ClientMark`, name, count) which selects the app and narrows the list. The
    /// tooltip is the identifier (D10); the context menu pins the app by its group key.
    private func appRow(_ client: ClientInfo, count: Int) -> some View {
        let key = client.groupKey
        let group = FlowGroup.client(key)
        let selected = session.page == .apps && session.group == group
        let pinned = session.isPinned(group)
        let expanded = session.expandedApps.contains(key)
        return HStack(spacing: 0) {
            Button {
                session.toggleExpanded(key)
            } label: {
                Image(systemName: Tok.Glyph.chevron)
                    .font(.system(size: Tok.Size.iconInline))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .rotationEffect(.degrees(expanded ? 90 : 0))
                    .frame(width: Tok.Size.icon, height: Tok.Size.icon)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(expanded ? "Collapse \(client.name)" : "Expand \(client.name)")
            Button {
                session.show(.apps, group: group)
            } label: {
                HStack(spacing: Space.sm) {
                    ClientMark(client: client)
                    Text(client.name)
                        .font(Tok.Face.ui(Tok.Typography.Size.md, selected ? .medium : .regular))
                        .foregroundStyle(Tok.Ink.primary.color)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer(minLength: Space.xs)
                    Text("\(count)").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                }
                .padding(.trailing, Space.sm)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(AppIdentifier.tooltipText(client.bundleID ?? client.name))
            .contextMenu {
                Button(pinned ? "Unpin App" : "Pin App") { pinned ? session.unpin(group) : session.pin(group) }
            }
            .accessibilityLabel("\(client.name), \(count) flows\(pinned ? ", pinned" : ""), \(expanded ? "expanded" : "collapsed")")
            .accessibilityAction(named: expanded ? "Collapse" : "Expand") { session.toggleExpanded(key) }
            .accessibilityAddTraits(selected ? .isSelected : [])
        }
        .padding(.leading, Inset.chevron)
        .frame(height: Tok.Size.control)
        .background(selected ? Tok.Ground.active.color : .clear, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
    }

    /// One flat sub-item under a group: a host under Domains or Pinned, a domain under an app
    /// (`.clientHost`, inset `Inset.domain`), or a pinned app. Selecting it narrows the list; the
    /// context menu pins it — a host for `.host` and `.clientHost` (a domain under an app is a host
    /// pin, D4/D7), an app for `.client`.
    private func subItem<Mark: View>(_ group: FlowGroup, title: String, count: Int?, page: SidebarPage,
                                     leadingInset: CGFloat = Inset.mark, help: String? = nil,
                                     @ViewBuilder mark: () -> Mark) -> some View {
        let selected = session.page == page && session.group == group
        let pinned = session.isPinned(group)
        let noun: String = switch group {
        case .host, .clientHost: "Host"
        case .client: "App"
        }
        return Button {
            session.show(page, group: group)
        } label: {
            HStack(spacing: Space.sm) {
                mark()
                Text(title)
                    .font(Tok.Face.ui(Tok.Typography.Size.md, selected ? .medium : .regular))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: Space.xs)
                if let count {
                    Text("\(count)").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                }
            }
            .padding(.leading, leadingInset)
            .padding(.trailing, Space.sm)
            .frame(height: Tok.Size.control)
            .background(selected ? Tok.Ground.active.color : .clear, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(help ?? "")
        .contextMenu {
            Button(pinned ? "Unpin \(noun)" : "Pin \(noun)") { pinned ? session.unpin(group) : session.pin(group) }
        }
        .accessibilityLabel("\(title), \(count ?? 0) flows\(pinned ? ", pinned" : "")")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var filterField: some View {
        @Bindable var session = session
        return HStack(spacing: Space.sm) {
            Image(systemName: Tok.Glyph.search).font(.system(size: 12)).foregroundStyle(Tok.Ink.tertiary.color)
            TextField("Filter", text: $session.sidebarQuery)
                .textFieldStyle(.plain)
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .focused($filterFocused)
                .onExitCommand { session.sidebarQuery = ""; filterFocused = false }
            if querying {
                Button { session.sidebarQuery = "" } label: {
                    Image(systemName: "xmark.circle.fill").font(.system(size: 12)).foregroundStyle(Tok.Ink.tertiary.color)
                }
                .buttonStyle(.plain)
            } else {
                Text("⌘⇧F").font(Tok.Face.ui(Tok.Typography.Size.xs)).foregroundStyle(Tok.Ink.tertiary.color)
            }
        }
        .padding(.horizontal, Tok.Metric.padInner)
        .frame(height: Tok.Size.control)
        .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
        .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(filterFocused ? Palette.accent : .clear, lineWidth: 2))
        .padding(Space.sm)
        .onChange(of: session.sidebarFilterFocusTick) { filterFocused = true }
    }
}

/// The generic host mark (`◎`) for Domains rows, pinned hosts and the domains under an app. Apps
/// carry `ClientMark` (UI/AppIdentity.swift) instead.
struct Monogram: View {
    var text: String
    var body: some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
            .foregroundStyle(Tok.Ink.secondary.color)
            .frame(width: 16, height: 16)
            .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.badge))
    }
}

/// Two chevrons facing a dot — `›•‹`, the thing in the middle.
struct ProductMark: View {
    var body: some View {
        Canvas { context, size in
            let s = size.width / 16
            var path = Path()
            path.move(to: CGPoint(x: 2 * s, y: 3 * s))
            path.addLine(to: CGPoint(x: 6 * s, y: 8 * s))
            path.addLine(to: CGPoint(x: 2 * s, y: 13 * s))
            path.move(to: CGPoint(x: 14 * s, y: 3 * s))
            path.addLine(to: CGPoint(x: 10 * s, y: 8 * s))
            path.addLine(to: CGPoint(x: 14 * s, y: 13 * s))
            context.stroke(path, with: .color(Palette.accent),
                           style: StrokeStyle(lineWidth: 1.6 * s, lineCap: .round, lineJoin: .round)) // grid: ok glyph geometry
            context.fill(Path(ellipseIn: CGRect(x: 6.3 * s, y: 6.3 * s, width: 3.4 * s, height: 3.4 * s)), // grid: ok glyph geometry
                         with: .color(Palette.accent))
        }
        .accessibilityHidden(true)
    }
}
