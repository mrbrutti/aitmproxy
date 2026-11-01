import AitmproxyKit
import SwiftUI

/// The first-run sheet (spec 2026-10-31-system-proxy-automation-design §D17.8, order per
/// Matt's per-host-decryption decision): the ordered steps that make this Mac's traffic show
/// up. Step 1 trusts the CA through `Session.trustCA()` with no alert of its own — the row
/// says what it does and macOS shows its own password dialog. Step 2 points at Scope: nothing
/// is decrypted until a host is in it. The system-proxy row (PR 4) goes above step 1. Every
/// CA word comes from `CATrustFacts`, the sheet's own from `SetupWords`; the buttons carry
/// `ConnectionAction` titles.
struct SetupSheet: View {
    @Environment(Session.self) private var session
    @Environment(\.dismiss) private var dismiss

    /// The Scope step of the Getting-started list: one title, one done state, shared with the Status page.
    private var scopeStep: GettingStartedStep? { session.connectionSummary.steps.first { $0.kind == .scopeSet } }
    private var scopeDone: Bool { scopeStep?.done ?? false }
    private var caDone: Bool { session.caTrust?.step.done ?? false }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(SetupWords.sheetTitle)
                .font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold))
                .foregroundStyle(Tok.Ink.primary.color)
                .padding(.horizontal, Space.lg).padding(.top, Space.xl).padding(.bottom, Space.md)
            VStack(alignment: .leading, spacing: Space.lg) {
                caRow
                if let scopeStep {
                    Rule(color: Tok.Line.rule)
                    scopeRow(scopeStep)
                }
            }
            .padding(.horizontal, Space.lg).padding(.bottom, Space.lg)
            Rule()
            HStack {
                Spacer()
                FlatButton(caDone && scopeDone ? "Done" : "Not Now") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
        }
        .frame(width: 560)
        .background(Tok.Ground.surface.color)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(SetupWords.sheetTitle)
    }

    /// Step 1: the fact's word (or the step's, while there is no fact), the needs-an-administrator
    /// remedy when that is the fact, the primary button (hidden once trusted, absent while the
    /// core has no certificate yet), the QUIC caveat.
    private var caRow: some View {
        let facts = session.caTrust
        let generated = session.caStatus?.exists != false
        return SetupRow(number: 1, title: ConnectionAction.trustCA.title, done: caDone) {
            Group {
                if let facts {
                    LaneDot(state: facts.state, word: facts.text, label: "Certificate Authority: \(facts.text)")
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

    /// Step 2: Scope, the Getting-started step's own title and state, the same page Proxy ▸ Scope… opens.
    private func scopeRow(_ step: GettingStartedStep) -> some View {
        SetupRow(number: 2, title: step.title, done: step.done) {
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
