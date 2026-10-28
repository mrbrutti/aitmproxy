import AitmproxyKit
import SwiftUI

/// Working: Pinned, Saved · All: Apps, Domains · aitmproxy: Scope, Findings,
/// Browser, Scripts, Agent (foundation §2.6). Flat `surface`, 28px rows,
/// counts only on queues.
struct SidebarView: View {
    @Environment(Session.self) private var session

    var body: some View {
        VStack(spacing: 0) {
            brand
            Rule()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    group("Working")
                    item(.pinned, count: session.pinnedHosts.count)
                    ForEach(session.pinnedHosts, id: \.self) { host in
                        subItem(host, monogram: "◎", count: nil)
                    }
                    item(.saved, count: session.savedSessions)

                    group("All")
                    item(.apps, count: session.clients.count)
                    if session.page == .apps {
                        ForEach(session.clients, id: \.0) { client, count in
                            subItem(client.name, monogram: client.monogram, count: count)
                        }
                    }
                    item(.domains, count: session.hosts.count)

                    group("aitmproxy")
                    item(.scope, count: session.scopeHosts.count, queue: true)
                    item(.findings, count: session.findingsCount, queue: true)
                    item(.browser, text: session.browserTabs == 1 ? "1 tab" : "\(session.browserTabs) tabs")
                    item(.scripts, text: "\(session.activeScripts) active")
                    item(.agent, text: "\(session.agentActionsLastMinute)/min", agent: true)
                }
                .padding(.horizontal, Space.sm)
                .padding(.top, Space.sm)
            }
            filterField
        }
        .frame(maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .overlay(alignment: .trailing) { VRule() }
    }

    /// `›•‹ aitmproxy  0.1` — the product mark in the accent, the wordmark in the UI face.
    private var brand: some View {
        HStack(spacing: Space.sm) {
            ProductMark().frame(width: 16, height: 16)
            Text("aitmproxy").font(Tok.Face.ui(Tok.Typography.Size.md, .medium)).foregroundStyle(Tok.Ink.primary.color)
            Spacer()
            Text(session.version).font(Tok.Face.data(Tok.Typography.Size.xs)).foregroundStyle(Tok.Ink.tertiary.color)
        }
        .padding(.horizontal, Tok.Metric.gapMeta)
        .frame(height: Tok.Size.filterBar)
    }

    private func group(_ title: String) -> some View {
        Text(title)
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.secondary.color)
            .padding(.horizontal, Space.sm)
            .padding(.top, Space.md)
            .padding(.bottom, Space.xs)
    }

    private func item(_ page: SidebarPage, count: Int? = nil, text: String? = nil, queue: Bool = false,
                      agent: Bool = false) -> some View {
        let selected = session.page == page
        return Button {
            session.page = page
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
                } else if let count {
                    countChip("\(count)", queue: queue, agent: agent)
                }
            }
            .padding(.horizontal, Space.sm)
            .frame(height: Tok.Size.control)
            .background(selected ? Tok.Ground.active.color : .clear, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func countChip(_ text: String, queue: Bool, agent: Bool) -> some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(agent ? Tok.Agent.deep.color : queue ? Tok.Ink.primary.color : Tok.Ink.secondary.color)
            .padding(.horizontal, queue || agent ? Tok.Metric.gapTight : 0)
            .frame(minWidth: queue || agent ? Tok.Metric.countChip : 0, minHeight: Tok.Metric.countChip)
            .background(agent ? Tok.Agent.tint.color : queue ? Tok.Ground.raised.color : .clear, in: Capsule())
    }

    private func subItem(_ title: String, monogram: String, count: Int?) -> some View {
        HStack(spacing: Space.sm) {
            Monogram(text: monogram)
            Text(title)
                .font(Tok.Face.ui(Tok.Typography.Size.md))
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
    }

    private var filterField: some View {
        HStack(spacing: Space.sm) {
            Image(systemName: Tok.Glyph.search).font(.system(size: 12)).foregroundStyle(Tok.Ink.tertiary.color)
            Text("Filter").font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
            Spacer()
            Text("⌘⇧F").font(Tok.Face.ui(Tok.Typography.Size.xs)).foregroundStyle(Tok.Ink.tertiary.color)
        }
        .padding(.horizontal, Tok.Metric.padInner)
        .frame(height: Tok.Size.control)
        .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
        .padding(Space.sm)
    }
}

/// A 16px app disc: the real app icon when the client resolves to one, else a monogram on `raised`.
struct Monogram: View {
    var text: String
    var body: some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
            .foregroundStyle(Tok.Ink.secondary.color)
            .frame(width: 16, height: 16)
            .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.badge))
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.badge).strokeBorder(Tok.Line.control.color))
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
