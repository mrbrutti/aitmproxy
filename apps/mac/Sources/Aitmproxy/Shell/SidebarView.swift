import AitmproxyKit
import AppKit
import SwiftUI

/// Working: Pinned, Saved · All: Apps, Domains · aitmproxy: Scope, Scan,
/// Findings, Browser, Scripts, Agent (foundation §2.6). Flat `surface`, 28px rows,
/// counts only on queues. Apps and Domains expand to one sub-item per
/// client / host; a sub-item narrows the list (S-013); ⇧P pins one (S-014).
struct SidebarView: View {
    @Environment(Session.self) private var session
    @FocusState private var filterFocused: Bool

    /// Case-insensitive substring over host / client name (S-034).
    private func matches(_ text: String) -> Bool {
        let q = session.sidebarQuery.trimmingCharacters(in: .whitespaces)
        return q.isEmpty || text.localizedCaseInsensitiveContains(q)
    }

    private var querying: Bool { !session.sidebarQuery.trimmingCharacters(in: .whitespaces).isEmpty }

    var body: some View {
        VStack(spacing: 0) {
            brand
            Rule()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    group("Working")
                    item(.pinned, count: session.pins.hosts.count + session.pins.apps.count)
                    ForEach(session.pins.hosts.filter(matches), id: \.self) { host in
                        subItem(.host(host), title: host, monogram: "◎", count: session.hosts.first { $0.0 == host }?.1, page: .pinned)
                    }
                    ForEach(session.pins.apps.filter(matches), id: \.self) { app in
                        subItem(.client(app), title: app, monogram: String(app.prefix(1)),
                                count: session.clients.first { $0.0.name == app }?.1, page: .pinned)
                    }
                    if session.page == .pinned, session.pins.isEmpty {
                        hint("Nothing pinned — press ⇧P on a row.")
                    }
                    item(.saved, count: session.savedSessions)

                    group("All")
                    item(.overview)
                    item(.connections)
                    item(.apps, count: session.clients.count)
                    if session.page == .apps || querying {
                        let visible = session.clients.filter { matches($0.0.name) }
                        if querying, visible.isEmpty { hint("No match") }
                        ForEach(visible, id: \.0) { client, count in
                            subItem(.client(client.name), title: client.name, monogram: client.monogram, count: count,
                                    page: .apps, bundleID: client.bundleID)
                        }
                    }
                    item(.domains, count: session.hosts.count)
                    if session.page == .domains || querying {
                        let visible = session.hosts.filter { matches($0.0) }
                        if querying, visible.isEmpty { hint("No match") }
                        ForEach(visible, id: \.0) { host, count in
                            subItem(.host(host), title: host, monogram: "◎", count: count, page: .domains)
                        }
                    }

                    group("aitmproxy")
                    item(.scope, count: session.scopeHosts.count, queue: true)
                    // Offered only when the core lists scan.discover; the count is the injection points found.
                    if session.scanEnabled { item(.scan, count: session.scan.points.count, queue: true) }
                    item(.findings, count: session.findingsCount, queue: true)
                    item(.browser, text: session.browserTabs == 1 ? "1 tab" : "\(session.browserTabs) tabs")
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

    /// `›•‹ aitmproxy  0.1` — the product mark in the accent, the wordmark in the UI face.
    private var brand: some View {
        HStack(spacing: Space.sm) {
            ProductMark().frame(width: 16, height: 16)
            Text("aitmproxy").font(Tok.Face.ui(Tok.Typography.Size.md, .medium)).foregroundStyle(Tok.Ink.primary.color)
            Spacer()
            Text(session.version).font(Tok.Face.data(Tok.Typography.Size.xs)).foregroundStyle(Tok.Ink.tertiary.color)
        }
        .padding(.horizontal, Space.lg)
        .frame(height: Tok.Size.toolbar)
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

    /// One client or host under its group. Selecting it narrows the list; the context menu pins it.
    private func subItem(_ group: FlowGroup, title: String, monogram: String, count: Int?, page: SidebarPage,
                         bundleID: String? = nil) -> some View {
        let selected = session.page == page && session.group == group
        let pinned = session.isPinned(group)
        let noun: String = { if case .host = group { return "Host" } else { return "App" } }()
        return Button {
            session.show(page, group: group)
        } label: {
            HStack(spacing: Space.sm) {
                AppMark(monogram: monogram, bundleID: bundleID)
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
            .padding(.leading, 28)
            .padding(.trailing, Space.sm)
            .frame(height: Tok.Size.control)
            .background(selected ? Tok.Ground.active.color : .clear, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
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

/// The real app icon when the client resolves to a running application, else a monogram on `raised`.
struct AppMark: View {
    var monogram: String
    var bundleID: String?

    var body: some View {
        if let icon = Self.icon(for: bundleID) {
            Image(nsImage: icon)
                .resizable()
                .frame(width: 16, height: 16)
        } else {
            Monogram(text: monogram)
        }
    }

    static func icon(for bundleID: String?) -> NSImage? {
        guard let bundleID else { return nil }
        guard let app = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).first else { return nil }
        return app.icon
    }
}

/// A 16px app disc for clients with no icon.
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
