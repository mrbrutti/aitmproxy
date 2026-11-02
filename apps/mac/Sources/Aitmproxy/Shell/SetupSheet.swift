import AitmproxyKit
import SwiftUI

/// The first-run sheet (spec 2026-10-31-system-proxy-automation-design §D13 and §D17.8, order per
/// Matt's per-host-decryption decision): the ordered steps that make this Mac's traffic show
/// up. Step 1 sets aitmproxy as the system proxy through `Session.setSystemProxy()` and turns on
/// "Set system proxy at launch" with it. Step 2 trusts the CA through `Session.trustCA()` with no
/// alert of its own — the row says what it does and macOS shows its own password dialog. Step 3
/// points at Scope: nothing is decrypted until a host is in it. Every system-proxy word is the
/// route's (`TrafficRoute.line`/`.detail`), every CA word comes from `CATrustFacts`, the sheet's
/// own from `SetupWords`; the buttons carry `ConnectionAction` titles.
struct SetupSheet: View {
    @Environment(Session.self) private var session
    @Environment(\.dismiss) private var dismiss
    /// "Don't ask again" (§D13), the sheet's own key.
    @AppStorage(SystemProxyPreferences.promptSuppressedKey, store: Store.defaults) private var promptSuppressed = false

    /// The Scope step of the Getting-started list: one title, one done state, shared with the Status page.
    private var scopeStep: GettingStartedStep? { session.connectionSummary.steps.first { $0.kind == .scopeSet } }
    private var scopeDone: Bool { scopeStep?.done ?? false }
    private var caDone: Bool { session.caTrust?.step.done ?? false }
    /// The system-proxy route and its Getting-started step: nil while the system proxy is unknown.
    private var systemProxyRoute: TrafficRoute? { session.connectionSummary.routes.systemProxy }
    private var systemProxyDone: Bool { systemProxyRoute?.open == true }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(SetupWords.sheetTitle)
                .font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold))
                .foregroundStyle(Tok.Ink.primary.color)
                .padding(.horizontal, Space.lg).padding(.top, Space.xl).padding(.bottom, Space.md)
            VStack(alignment: .leading, spacing: Space.lg) {
                systemProxyRow
                Rule(color: Tok.Line.rule)
                caRow
                if let scopeStep {
                    Rule(color: Tok.Line.rule)
                    scopeRow(scopeStep)
                }
            }
            .padding(.horizontal, Space.lg).padding(.bottom, Space.lg)
            Rule()
            HStack {
                Toggle("Don't ask again", isOn: $promptSuppressed)
                    .toggleStyle(.checkbox)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color)
                Spacer()
                FlatButton(systemProxyDone && caDone && scopeDone ? "Done" : "Not Now") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
        }
        .frame(width: 560)
        .background(Tok.Ground.surface.color)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(SetupWords.sheetTitle)
    }

    /// Step 1 (§D13, Matt's words as the title): the route's line as the fact (nothing while the route is
    /// unknown), the §D13 checklist, the primary button while the route offers it (hidden once open; the
    /// Kit drops it while a change is in flight, when an administrator is needed and when the platform
    /// has no mechanism), the launch-preference caption, the lane sentence.
    private var systemProxyRow: some View {
        let route = systemProxyRoute
        return SetupRow(number: 1, title: SetupWords.systemProxyRowTitle, done: systemProxyDone) {
            if let route, !route.open {
                Text(route.line)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color)
                VStack(alignment: .leading, spacing: Space.xs) {
                    ForEach(SetupWords.systemProxyChecklist, id: \.self) { item in
                        Label(item, systemImage: "checkmark")
                            .labelStyle(.titleAndIcon)
                    }
                }
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                if route.actions.contains(.setSystemProxy) {
                    PrimaryButton(ConnectionAction.setSystemProxy.title) {
                        Task {
                            await session.setSystemProxy()
                            // Also at every launch (§D13, Architect's call) — once the set has actually
                            // landed, so a refused set does not leave the preference on.
                            if session.systemProxyPointsAtUs {
                                Store.defaults.set(true, forKey: SystemProxyPreferences.autoKey)
                            }
                        }
                    }
                    .disabled(!session.systemProxyControlLive)
                    Text(SetupWords.systemProxyAutoCaption)
                        .font(Tok.Face.ui(Tok.Typography.Size.xs))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                }
                Hint(text: ConnectionSummary.systemProxyLaneSentence)
            }
        }
    }

    /// Step 2: the fact's word (or the step's, while there is no fact), the needs-an-administrator
    /// remedy when that is the fact, the primary button (hidden once trusted, absent while the
    /// core has no certificate yet), the QUIC caveat.
    private var caRow: some View {
        let facts = session.caTrust
        let generated = session.caStatus?.exists != false
        return SetupRow(number: 2, title: ConnectionAction.trustCA.title, done: caDone) {
            Group {
                if let facts {
                    LaneDot(state: facts.state, word: facts.text, title: CATrustFacts.laneTitle)
                } else {
                    Text((session.caTrustStep ?? CATrustFacts.unknownStep()).title)
                }
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.secondary.color)
            if let facts, facts.needsAdmin, let remedy = facts.remedy {
                RemedyText(remedy)
            }
            if !caDone, generated {
                PrimaryButton(ConnectionAction.trustCA.title) { Task { await session.trustCA() } }
                    .disabled(!session.caTrustControlLive)
            }
            Hint(text: CATrustFacts.quicCaveat)
        }
    }

    /// Step 3: Scope, the Getting-started step's own title and state, the same page Proxy ▸ Scope… opens.
    private func scopeRow(_ step: GettingStartedStep) -> some View {
        SetupRow(number: 3, title: step.title, done: step.done) {
            if !step.done {
                Text(SetupWords.scopeCaption)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color)
                FlatButton(ConnectionAction.openScope.title) {
                    dismiss()
                    session.perform(connection: .openScope)
                }
            }
        }
    }
}

/// One numbered step: `✓` or the number, the title, then the row's own lines.
private struct SetupRow<Content: View>: View {
    var number: Int
    var title: String
    var done: Bool
    @ViewBuilder var content: () -> Content

    var body: some View {
        HStack(alignment: .top, spacing: Space.md) {
            Group {
                if done {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Tok.Status.success.color)
                } else {
                    Text(String(number)).foregroundStyle(Tok.Ink.tertiary.color)
                }
            }
            .font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
            .frame(width: Tok.Size.icon)
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Space.sm) {
                Text(title)
                    .font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                    .foregroundStyle(done ? Tok.Ink.secondary.color : Tok.Ink.primary.color)
                content()
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(done ? "Done" : "Step \(number)"): \(title)")
    }
}
