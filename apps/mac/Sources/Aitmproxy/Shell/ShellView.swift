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
        Group {
            // APP_KIT_GALLERY=1 shows the parts gallery (DesignKit/KitGallery.swift) in place of the shell.
            if KitGallery.enabled {
                KitGallery()
            } else {
                VStack(spacing: 0) {
                    // Hosting controllers do not inherit this view's environment: pass it on.
                    ShellSplitView(sidebarVisible: $sidebarVisible,
                                   sidebar: SidebarView().environment(session).themed(),
                                   main: MainView().environment(session).themed())
                    StatusBar()
                }
            }
        }
        .background(Tok.Ground.surface.color)
        .overlay(alignment: .top) {
            if session.paletteVisible {
                ZStack(alignment: .top) {
                    Color.black.opacity(0.001).ignoresSafeArea().onTapGesture { session.paletteVisible = false }
                    CommandPalette()
                        .padding(.top, Space.section * 2)
                        .transition(session.paletteOpenedByKeyboard ? .identity
                                    : .scale(scale: 0.97, anchor: .top).combined(with: .opacity))
                }
                .animation(session.paletteOpenedByKeyboard ? nil : Tok.Motion.easeOut(Tok.Motion.popover), value: session.paletteVisible)
            }
        }
        .sheet(isPresented: Binding(get: { session.composeVisible }, set: { session.composeVisible = $0 })) {
            ComposeSheet().environment(session).themed()
        }
        .sheet(isPresented: Binding(get: { session.rulesVisible }, set: { session.rulesVisible = $0 })) {
            RulesSheet().environment(session).themed()
        }
        .sheet(isPresented: Binding(get: { session.scopeSheetVisible }, set: { session.scopeSheetVisible = $0 })) {
            ScopeSheet().environment(session).themed()
        }
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
            ChipBar(selected: $session.chip, filterActive: session.filterBarVisible) { session.filterBarVisible.toggle() }
            if session.filterBarVisible {
                FilterBar()
            }
            // A real NSSplitView: draggable, remembered; the inspector takes 45% until the operator moves it.
            if session.layout == .vertical {
                SplitPane(axis: .vertical, firstMinimum: 420, secondMinimum: 420, initialSecondFraction: 0.5,
                          autosaveName: "main.vertical") { flows } second: { inspector }
            } else {
                SplitPane(axis: .horizontal, firstMinimum: 160, secondMinimum: 200, initialSecondFraction: 0.45,
                          autosaveName: "main.horizontal") { flows } second: { inspector }
            }
        }
    }

    private var flows: some View {
        VStack(spacing: 0) {
            if session.page == .scope {
                ScopePanel()
                Rule()
            } else if !Store.usesFixtures, session.scopeHosts.isEmpty, case .connected = session.bus {
                ScopeBanner()
                Rule()
            }
            flowTable
        }
        .environment(session)
        .themed()
    }

    private var flowTable: some View {
        @Bindable var session = session
        return FlowTableView(rows: session.visibleRows, selection: $session.selection, sort: $session.sort,
                             density: session.density, layoutURL: session.columnsURL,
                             isPinned: { session.isPinned(.host($0)) },
                             onComment: { id, text in session.comment(id, text) },
                             onFocus: { id in session.focused = id },
                             onAction: { action, id in session.perform(action, on: id) },
                             onToggleIntercept: { session.arm(!session.interceptArmed) },
                             onCompose: { session.openCompose() })
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
        .environment(session)
        .themed()
    }
}

/// "No flows yet — point a client at 127.0.0.1:8080 or open the browser." (foundation §2.8)
struct EmptyFlows: View {
    var filtered: Bool
    var listen: String

    var body: some View {
        VStack(spacing: Space.sm) {
            Text(filtered ? "No flows match" : "No flows yet")
                .font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
            Text(filtered ? "Clear the chip or the filter to see the capture."
                 : "Point a client at \(listen) or open the browser.")
                .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
        }
        .multilineTextAlignment(.center)
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
