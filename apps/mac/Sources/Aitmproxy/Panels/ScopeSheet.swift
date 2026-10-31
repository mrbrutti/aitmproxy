import AitmproxyKit
import SwiftUI

/// Scope as a sheet (S-047; Proxy ▸ Scope… ⇧⌘O): the same panel for when
/// the list is on another page. 640 wide (the fixed columns + host need it,
/// else the leading edge clips), content-sized, one `Done`.
struct ScopeSheet: View {
    @Environment(Session.self) private var session
    @Environment(\.dismiss) private var dismiss

    init() {}

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: Space.md) {
                Text("Edit Scope").font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold)).foregroundStyle(Tok.Ink.primary.color)
                Text(summary).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                Spacer()
            }
            .padding(.horizontal, Space.lg).padding(.top, Space.xl).padding(.bottom, Space.md)
            ScopePanel(showsLabel: false)
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
    }

    /// `3 hosts · 13 flows in scope`, or nothing while empty (the panel says so).
    private var summary: String {
        let hosts = session.scopeHosts.count
        guard hosts > 0 else { return "" }
        let flows = session.rows.filter(\.inScope).count
        return "\(hosts) host\(hosts == 1 ? "" : "s") · \(flows) flow\(flows == 1 ? "" : "s") in scope"
    }
}
