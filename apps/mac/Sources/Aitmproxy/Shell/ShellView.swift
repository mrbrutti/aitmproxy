import AitmproxyKit
import SwiftUI

/// The primary screen (foundation §2.6): sidebar | toolbar / chip bar / flow
/// list / intercept bar / inspector, with the status bar across the bottom.
struct ShellView: View {
    @Environment(Session.self) private var session
    @Environment(\.openSettings) private var openSettings
    @State private var sidebarVisible = true
    @State private var bus: BusService?

    var body: some View {
        VStack(spacing: 0) {
            HSplitView {
                if sidebarVisible {
                    SidebarView()
                        .frame(minWidth: Tok.Size.sidebarMin, idealWidth: Tok.Size.sidebar, maxWidth: Tok.Size.sidebarMax)
                }
                MainView()
                    .frame(minWidth: 720, maxWidth: .infinity)
            }
            StatusBar()
        }
        .background(Tok.Ground.surface.color)
        .toolbar { ShellToolbar(sidebarVisible: $sidebarVisible) }
        .task {
            if Store.usesFixtures {
                session.loadFixtures()
            } else {
                let service = BusService(session: session)
                session.actions = service
                service.start()
                bus = service
            }
            SelfTest.runIfRequested(session: session)
            Snapshot.runIfRequested(session: session, openSettings: openSettings)
        }
    }
}

/// Everything right of the sidebar.
struct MainView: View {
    @Environment(Session.self) private var session

    var body: some View {
        @Bindable var session = session
        VStack(spacing: 0) {
            ChipBar(selected: $session.chip)
            if session.layout == .vertical {
                HSplitView {
                    flows.frame(minWidth: 480)
                    inspector.frame(minWidth: 480)
                }
            } else {
                VSplitView {
                    flows.frame(minHeight: 160)
                    inspector.frame(minHeight: 200)
                }
            }
        }
    }

    private var flows: some View {
        @Bindable var session = session
        return FlowTableView(rows: session.visibleRows, selection: $session.selection) { id in
            session.focused = id
        }
        .overlay {
            if session.visibleRows.isEmpty {
                EmptyFlows(filtered: !session.rows.isEmpty, listen: session.listenAddress)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .layoutPriority(1)
    }

    private var inspector: some View {
        VStack(spacing: 0) {
            if session.interceptArmed {
                InterceptBar()
            }
            InspectorView()
        }
    }
}

/// "No flows yet — point a client at 127.0.0.1:8080 or open the browser." (foundation §2.8)
struct EmptyFlows: View {
    var filtered: Bool
    var listen: String

    var body: some View {
        VStack(spacing: Space.sm) {
            Text(filtered ? "No flows match" : "No flows yet")
                .font(Tok.Face.ui(Tok.Typography.Size.base)).foregroundStyle(Tok.Ink.secondary.color)
            Text(filtered ? "Clear the chip or the filter to see the capture."
                 : "Point a client at \(listen) or open the browser.")
                .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
        }
        .padding(.top, Tok.Size.columnHeader)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .allowsHitTesting(false)
    }
}

/// Hairline helpers in the foundation's line colours.
struct Rule: View {
    var color: DynamicColor = Tok.Line.border
    var body: some View {
        Rectangle().fill(color.color).frame(height: 1)
    }
}

struct VRule: View {
    var color: DynamicColor = Tok.Line.border
    var body: some View {
        Rectangle().fill(color.color).frame(width: 1)
    }
}
