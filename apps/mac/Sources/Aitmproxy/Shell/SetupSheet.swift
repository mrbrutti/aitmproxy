import AitmproxyKit
import SwiftUI

/// The first-run sheet (spec 2026-10-31-system-proxy-automation-design §D17.8, order per
/// Matt's per-host-decryption decision): the ordered steps that make this Mac's traffic show
/// up. Step 1 trusts the CA through `Session.trustCA()` with no alert of its own — the row
/// says what it does and macOS shows its own password dialog. Step 2 points at Scope: nothing
/// is decrypted until a host is in it. The system-proxy row (PR 4) goes above step 1. Every
/// CA word comes from `CATrustFacts`; the buttons carry `ConnectionAction` titles.
struct SetupSheet: View {
    @Environment(Session.self) private var session
    @Environment(\.dismiss) private var dismiss

    private var scopeDone: Bool { !session.scopeHosts.isEmpty }
    private var caDone: Bool { session.caTrust?.trusted == true && !session.caTrustInstalling }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Set up aitmproxy on this Mac")
                .font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold))
                .foregroundStyle(Tok.Ink.primary.color)
                .padding(.horizontal, Space.lg).padding(.top, Space.xl).padding(.bottom, Space.md)
            VStack(alignment: .leading, spacing: Space.lg) {
                caRow
                Rule(color: Tok.Line.rule)
                scopeRow
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
        .accessibilityLabel("Set up aitmproxy on this Mac")
    }

    /// Step 1: the fact's word, the primary button (hidden once trusted), the QUIC caveat.
    private var caRow: some View {
        let facts = session.caTrust
        return SetupRow(number: 1, title: ConnectionAction.trustCA.title, done: caDone) {
            HStack(spacing: Space.sm) {
                if let facts {
                    Circle().fill(facts.state.color.color).frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
                        .accessibilityHidden(true)
                    Text(facts.text)
                } else {
                    Text(CATrustFacts.unknownStep().title)
                }
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.secondary.color)
            if let remedy = facts?.remedy {
                Text(remedy)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !caDone {
                PrimaryButton(ConnectionAction.trustCA.title) { Task { await session.trustCA() } }
                    .disabled(!session.caTrustControlLive)
            }
            Hint(text: CATrustFacts.quicCaveat)
        }
    }

    /// Step 2: Scope, the same page Proxy ▸ Scope… opens.
    private var scopeRow: some View {
        SetupRow(number: 2, title: "Add a host to Scope", done: scopeDone) {
            Text(scopeDone ? "\(Format.count(session.scopeHosts.count, "host")) in scope"
                           : "Nothing is decrypted until a host is in Scope")
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
            if !scopeDone {
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
