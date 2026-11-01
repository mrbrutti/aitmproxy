import AitmproxyKit
import SwiftUI

/// The one banner line above every flow list (Flows, Pinned, Domains, Apps) while flows exist and a
/// known route is closed, every row is a tunnel with an empty Scope, or the CA is not trusted (spec
/// 2026-10-31-mac-traffic-route-advice-design D5/D8). The text is `TrafficRoutes.banner` — the shown
/// facts' state words only — and the one button is `bannerAction`; both come from `Session.trafficRoutes`,
/// the only thing this file reads, so no route word is spelled here and the caller draws the `Rule`.
struct RouteBanner: View {
    @Environment(Session.self) private var session
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        let routes = session.trafficRoutes
        let banner = routes.banner ?? ""
        HStack(spacing: Space.sm) {
            HStack(spacing: Space.sm) {
                Image(systemName: "network").font(.system(size: Tok.Size.iconInline))
                Text(banner)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: Space.sm)
            if let action = routes.bannerAction {
                SmallButton(action.title) { RouteActions.run(action, session: session, openSettings: openSettings) }
                    .accessibilityIdentifier("route-banner-action")
            }
        }
        .font(Tok.Face.ui(Tok.Typography.Size.sm))
        .foregroundStyle(Tok.Ink.tertiary.color)
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.Row.dense)
        .frame(maxWidth: .infinity, alignment: .leading)
        .help(Self.help(banner: banner, shown: Self.shownEntries(routes)))
        .accessibilityIdentifier("route-banner")
    }

    /// The tooltip: the full banner (the line truncates), then the shown entries' details joined " · ".
    static func help(banner: String, shown: [TrafficRoute]) -> String {
        let details = shown.map(\.detail).joined(separator: " · ")
        return details.isEmpty ? banner : "\(banner)\n\(details)"
    }

    /// The entries the banner names, in its order. The Kit joins the shown entries' `state`s with " · " in
    /// `advice` order (spec D5), so walking `advice` and consuming each state that heads the remaining text
    /// recovers that list without a second derivation of the banner predicate.
    static func shownEntries(_ routes: TrafficRoutes) -> [TrafficRoute] {
        guard let banner = routes.banner else { return [] }
        var rest = Substring(banner)
        var shown: [TrafficRoute] = []
        for entry in routes.advice where rest.hasPrefix(entry.state) {
            shown.append(entry)
            rest = rest.dropFirst(entry.state.count)
            if rest.hasPrefix(Self.separator) { rest = rest.dropFirst(Self.separator.count) }
        }
        return shown
    }

    private static let separator = " · "
}

/// Runs a route action from the Flows surfaces the way the Status page runs its steps: through
/// `Session.perform(connection:)`, and when that returns `false` for `.openCaptureSettings` (the All Apps
/// button) the view opens Settings ▸ Capture itself, exactly as `AppsAttributionBanner` did. Every other
/// action a route carries is one `perform` takes.
enum RouteActions {
    static func run(_ action: ConnectionAction, session: Session, openSettings: OpenSettingsAction) {
        // The trust action is the view's to run (PR D: `perform` returns false for it on purpose); same
        // confirm-gated path as the Status page's row. The model drops the button once trusted or installing.
        if action == .trustCA { Task { await session.trustCA() }; return }
        if session.perform(connection: action) { return }
        if action == .openCaptureSettings {
            session.settingsTab = .capture
            openSettings()
        }
    }
}

/// One closed route or fact in the Flows empty state (spec D4): its glyph, the line verbatim, every action
/// as a `SmallButton`, and the detail beneath in a smaller tertiary line.
struct RouteAdviceRow: View {
    var route: TrafficRoute
    var run: (ConnectionAction) -> Void

    static func glyph(_ kind: TrafficRoute.Kind) -> String {
        switch kind {
        case .systemProxy: "network"
        case .allApps: "app.badge"
        case .scope: Tok.Glyph.scope
        case .caTrust: Tok.Glyph.lock
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                Image(systemName: Self.glyph(route.kind))
                    .font(.system(size: Tok.Size.iconInline))
                    .frame(width: Tok.Size.icon)
                    .accessibilityHidden(true)
                Text(route.line)
                    .font(Tok.Face.ui(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .allowsHitTesting(false)
                ForEach(route.actions, id: \.self) { action in
                    SmallButton(action.title) { run(action) }
                }
            }
            Text(route.detail)
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.tertiary.color)
                .padding(.leading, Tok.Size.icon + Space.sm)
                .allowsHitTesting(false)
        }
        .multilineTextAlignment(.leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(route.line)
        .accessibilityIdentifier("route-advice-\(route.kind.rawValue)")
    }
}
