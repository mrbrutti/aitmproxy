import AitmproxyKit
import SwiftUI

/// Scope as a sheet (S-047; Proxy ▸ Scope… ⇧⌘O): the same panel for when
/// the list is on another page. 640 wide (the fixed columns + host need it,
/// else the leading edge clips), content-sized, one `Done`.
struct ScopeSheet: View {
    @Environment(Session.self) private var session
    @Environment(\.dismiss) private var dismiss
    /// Bumped once the calm-open hook has cleared the first responder; the panel focuses its field on it.
    @State private var focusRequest = 0

    init() {}

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: Space.md) {
                Text("Edit Scope").font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold)).foregroundStyle(Tok.Ink.primary.color)
                Text(summary).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                Spacer()
            }
            .padding(.horizontal, Space.lg).padding(.top, Space.xl).padding(.bottom, Space.md)
            ScopePanel(showsLabel: false, focusRequest: focusRequest)
            Rule()
            HStack {
                Spacer()
                FlatButton("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
        }
        .frame(width: 640)
        .background(Tok.Ground.surface.color)
        // Open calm, then focus the one field this sheet is for — the same exception the Compose
        // sheet makes (rule 51; release acceptance MAC-5). The hook's follow runs right after the
        // clear, in the same run-loop turn, so an `onAppear` focus cannot be undone by it.
        .noInitialFocus { focusRequest += 1 }
    }

    /// `3 hosts · 13 flows in scope`, or nothing while empty (the panel says so);
    /// ` · 3 L4 entries` follows when the core advertises L4 and lists any.
    private var summary: String {
        let hosts = session.scopeHosts.count
        let l4 = session.l4Enabled ? session.l4Scope.count : 0
        let l4Text = l4 > 0 ? "\(l4) L4 entr\(l4 == 1 ? "y" : "ies")" : ""
        guard hosts > 0 else { return l4Text }
        let flows = session.rows.filter(\.inScope).count
        let base = "\(hosts) host\(hosts == 1 ? "" : "s") · \(flows) flow\(flows == 1 ? "" : "s") in scope"
        return l4Text.isEmpty ? base : "\(base) · \(l4Text)"
    }
}
