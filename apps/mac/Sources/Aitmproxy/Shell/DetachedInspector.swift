import SwiftUI

/// The inspector alone, for the detached layout (S-061). While this window is
/// open the main window shows the list full height; closing it returns the
/// inspector to where it was.
struct DetachedInspector: View {
    @Environment(Session.self) private var session

    var body: some View {
        VStack(spacing: 0) {
            if session.interceptArmed { InterceptBar() }
            InspectorView()
        }
        .background(Tok.Ground.surface.color)
        // The window names its content (rule 19): the focused flow, else the pane's name.
        .navigationTitle(session.focusedRow.map { "\($0.method.label) \($0.path.isEmpty ? $0.authority : $0.path)" } ?? "Inspector")
        .navigationSubtitle(session.focusedRow.map { $0.path.isEmpty ? "" : $0.site } ?? "")
        .onAppear { if session.layout != .detached { session.layout = .detached } }
        .onDisappear { if session.layout == .detached { session.layout = session.attachedLayout } }
    }
}
