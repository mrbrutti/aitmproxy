import AitmproxyKit
import SwiftUI

/// The one banner line above every flow list (Flows, Pinned, Domains, Apps) while flows exist and a
/// known route is closed, every row is a tunnel with an empty Scope, or the CA is not trusted (spec
/// 2026-10-31-mac-traffic-route-advice-design D5/D8). The text is `TrafficRoutes.banner` — the shown
/// facts' state words only — the one button is `bannerAction`, and the tooltip's second line is
/// `bannerDetail`; all three come from `routes`, the `Session.trafficRoutes` value `MainView.flows` reads
/// once and hands down, so no route word is spelled here, nothing re-derives the shown set, and the caller
/// draws the `Rule`. Nothing renders when `banner` is nil. The session is read only to run the button.
struct RouteBanner: View {
    var routes: TrafficRoutes
    @Environment(Session.self) private var session
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        if let banner = routes.banner {
            HStack(spacing: Space.sm) {
                Label {
                    Text(banner)
                        .lineLimit(1)
                        .truncationMode(.tail)
                } icon: {
                    Image(systemName: Tok.Glyph.network).font(.system(size: Tok.Size.iconInline))
                }
                .labelStyle(RouteLabelStyle())
                Spacer(minLength: Space.sm)
                if let action = routes.bannerAction {
                    SmallButton(action.title) { RouteActions.run(action, session: session, openSettings: openSettings) }
                        // Trusting is a bus call the operator makes: the button stands down while the bus is not the
                        // operator's (`Session.trustCA()` refuses it then), as the Status page's row does.
                        .disabled(action == .trustCA && !session.caTrustControlLive)
                        .accessibilityIdentifier("route-banner-action")
                }
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.tertiary.color)
            .padding(.horizontal, Space.md)
            .frame(height: Tok.Size.Row.dense)
            .frame(maxWidth: .infinity, alignment: .leading)
            .help(Self.help(banner: banner, detail: routes.bannerDetail))
            .accessibilityIdentifier("route-banner")
        }
    }

    /// The tooltip: the full banner (the line truncates), then the Kit's `bannerDetail` — the shown entries'
    /// details joined " · " — on a second line when there is one.
    static func help(banner: String, detail: String?) -> String {
        guard let detail else { return banner }
        return "\(banner)\n\(detail)"
    }
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

/// Icon then text on the grid (`Space.sm` apart), the icon in a fixed slot when `iconWidth` is set so the
/// detail line beneath a `RouteAdviceRow` aligns under its text.
struct RouteLabelStyle: LabelStyle {
    var iconWidth: CGFloat? = nil

    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: Space.sm) {
            configuration.icon.frame(width: iconWidth)
            configuration.title
        }
    }
}

/// One closed route or fact in the Flows empty state (spec D4): its glyph, the line verbatim, every action
/// as a `SmallButton`, and the detail beneath in a smaller tertiary line. A pure function of its inputs:
/// `controlLive` is `Session.caTrustControlLive` (the Trust button stands down without it) and `run` is the
/// caller's `RouteActions.run`.
struct RouteAdviceRow: View {
    var route: TrafficRoute
    var controlLive: Bool
    var run: (ConnectionAction) -> Void

    static func glyph(_ kind: TrafficRoute.Kind) -> String {
        switch kind {
        case .systemProxy: Tok.Glyph.network
        case .allApps: Tok.Glyph.apps
        case .scope: Tok.Glyph.scope
        case .caTrust: Tok.Glyph.lock
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                Label {
                    Text(route.line)
                        .font(Tok.Face.ui(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Ink.secondary.color)
                        .allowsHitTesting(false)
                } icon: {
                    Image(systemName: Self.glyph(route.kind))
                        .font(.system(size: Tok.Size.iconInline))
                        .accessibilityHidden(true)
                }
                .labelStyle(RouteLabelStyle(iconWidth: Tok.Size.icon))
                ForEach(route.actions, id: \.self) { action in
                    SmallButton(action.title) { run(action) }
                        .disabled(action == .trustCA && !controlLive)
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
