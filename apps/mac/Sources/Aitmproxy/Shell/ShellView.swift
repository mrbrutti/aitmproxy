import AitmproxyKit
import SwiftUI

/// The primary screen (foundation §2.6): sidebar | toolbar / chip bar / flow
/// list / intercept bar / inspector, with the status bar across the bottom.
struct ShellView: View {
    @Environment(Session.self) private var session
    @Environment(\.openSettings) private var openSettings
    @Environment(\.openWindow) private var openWindow
    @State private var bus: BusService?
    @State private var embeddedCore: EmbeddedCoreController?
    @State private var captureExtension: ExtensionController?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        @Bindable var session = session
        Group {
            // APP_KIT_GALLERY=1 shows the parts gallery (DesignKit/KitGallery.swift) in place of the shell.
            if KitGallery.enabled {
                KitGallery()
            } else {
                VStack(spacing: 0) {
                    // Hosting controllers do not inherit this view's environment: pass it on.
                    ShellSplitView(sidebarVisible: $session.sidebarVisible,
                                   sidebar: SidebarView().environment(session).themed(),
                                   main: MainView().environment(session).themed())
                    StatusBar()
                }
            }
        }
        .background(Tok.Ground.surface.color)
        // Drop a HAR (or, after F10, a mitmproxy/Proxyman/Charles file) anywhere on the window (S-065).
        .onDrop(of: [.fileURL], isTargeted: $session.dropTargeted) { providers in
            // Stays on the main actor: the item provider's async load is awaited here.
            Task { @MainActor in
                for provider in providers {
                    let data: Data? = await withCheckedContinuation { done in
                        _ = provider.loadDataRepresentation(for: .fileURL) { data, _ in done.resume(returning: data) }
                    }
                    guard let data, let url = URL(dataRepresentation: data, relativeTo: nil) else { continue }
                    if !session.importFile(url) { break }
                }
            }
            return !providers.isEmpty
        }
        .overlay {
            if session.dropTargeted { DropOverlay() }
        }
        .overlay(alignment: .top) {
            if session.paletteVisible {
                ZStack(alignment: .top) {
                    Color.black.opacity(0.001).ignoresSafeArea().onTapGesture { session.paletteVisible = false }
                    // Keyboard opens land in the same frame; the mouse gets the popover motion,
                    // a fade only under Reduce Motion (S-069).
                    CommandPalette()
                        .padding(.top, Space.section * 2)
                        .transition(session.paletteOpenedByKeyboard ? .identity
                                    : reduceMotion ? .opacity
                                    : .scale(scale: 0.97, anchor: .top).combined(with: .opacity))
                }
                .animation(session.paletteOpenedByKeyboard ? nil : Tok.Motion.easeOut(Tok.Motion.popover), value: session.paletteVisible)
            }
        }
        .sheet(isPresented: Binding(get: { session.composeVisible }, set: { session.composeVisible = $0 })) {
            ComposeSheet().environment(session).themed()
        }
        .sheet(isPresented: Binding(get: { session.rulesVisible }, set: { session.rulesVisible = $0 })) {
            RulesSheet().environment(session).themed().noInitialFocus()
        }
        .sheet(isPresented: Binding(get: { session.scopeSheetVisible }, set: { session.scopeSheetVisible = $0 })) {
            ScopeSheet().environment(session).themed().noInitialFocus()
        }
        .toolbar { ShellToolbar(sidebarVisible: $session.sidebarVisible) }
        .onChange(of: session.detachRequestTick) { openWindow(id: "inspector") }
        .onChange(of: session.reconnectTick) { bus?.start() }
        .onChange(of: session.restartCoreTick) { embeddedCore?.restart() }
        .task {
            session.attachActivityHooks()
            if session.layout == .detached { openWindow(id: "inspector") }
            if Store.usesFixtures {
                session.loadFixtures()
            } else {
                let service = BusService(session: session)
                session.actions = service
                // The active connection is a switchable, persisted choice (Task 7,
                // AC10): embedded by default, external when the operator picks it in
                // Settings ▸ Bus. The driver turns that choice into start/stop of the
                // bundled core (when present — Task 9) and the matching bus endpoint;
                // `activate()` applies the restored choice on launch. The health
                // surface (Task 8) drives the status dot + core-log panel.
                let controller = EmbeddedCoreController(coreID: session.activeCoreID, bus: service, health: session.coreHealth)
                let driver = LiveConnectionDriver(embedded: controller, bus: service)
                let model = ActiveConnectionModel(driver: driver, persistence: UserDefaultsActiveKindPersistence())
                model.activate()
                session.connection = model
                embeddedCore = controller
                bus = service
                // Operator-launch activation of the macOS capture extension (Task 13,
                // NE-AC11): the only call site, so no bus/MCP/agent path can trigger it.
                // Inert unless this build embeds the extension.
                if captureExtension == nil {
                    let capture = ExtensionController(health: session.coreHealth)
                    capture.start()
                    captureExtension = capture
                }
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
        HStack(spacing: 0) {
            content
            if session.activityLogVisible {
                VRule()
                ActivityLogPanel(state: session.activity).frame(width: ActivityLogPanel.panelWidth)
            }
            if session.coreLogVisible {
                CoreLogPanel().environment(session).themed()
            }
        }
        .sheet(item: Binding(get: { session.buildPoCFlowID.map(BuildPoCTarget.init) }, set: { session.buildPoCFlowID = $0?.id })) { target in
            BuildPoCSheet(flowID: target.id).environment(session).themed().noInitialFocus()
        }
    }

    /// The page's own panel, or the flow list with the inspector.
    @ViewBuilder private var content: some View {
        switch session.page ?? .apps {
        case .overview: OverviewPanel()
        case .scan: ScanPanel(state: session.scan)
        case .findings: FindingsPanel(state: session.poc)
        case .browser: BrowserPanel(state: session.browser)
        case .scripts: ScriptsPanel()
        case .agent: AgentPanel(state: session.activity)
        case .ca: CAPanel()
        case .config: ConfigPanel()
        default: listAndInspector
        }
    }

    private var listAndInspector: some View {
        @Bindable var session = session
        return VStack(spacing: 0) {
            if !session.splitView {
                ChipBar(selected: $session.chip, filterActive: session.filterBarVisible) { session.filterBarVisible.toggle() }
            }
            if session.filterBarVisible {
                FilterBar()
            }
            // A real NSSplitView: draggable, remembered; the inspector takes 45% until the operator moves it.
            if session.layout == .detached {
                flows
                if session.interceptArmed { InterceptBar() }
            } else if session.layout == .vertical {
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
            // A failed embedded core captures nothing; surface it everywhere, not just
            // in the status-bar dot, with the reason and the two recovery actions.
            if session.coreHealth.health == .failed {
                CoreFailedBanner()
                Rule()
            }
            if session.page == .scope {
                ScopePanel()
                Rule()
            } else if session.page == .connections {
                ConnectionDashboard().frame(height: 260)
                Rule()
            } else if !Store.usesFixtures, session.scopeHosts.isEmpty, case .connected = session.bus {
                ScopeBanner()
                Rule()
            }
            if session.page == .apps, session.clients.isEmpty, !session.rows.isEmpty {
                // Captured flows exist but carry no source app, so this page cannot group them.
                // Keep the table (captured flows are never hidden) and say why in one line.
                AppsAttributionBanner()
                Rule()
            }
            if session.splitView {
                // Two lists, own chips and selection, one capture; the focused pane carries a 2 px accent edge.
                HStack(spacing: 0) {
                    listPane(0)
                    VRule()
                    listPane(1)
                }
            } else if session.page == .connections {
                // Viz-first Connection page: the waterfall replaces the flow table; the
                // inspector opens on select. The dashboard band sits above (see above).
                ConnectionWaterfall()
            } else if session.page == .apps, session.clients.isEmpty, session.rows.isEmpty {
                // No flows at all. Say the one true thing about capture (off, awaiting
                // approval, on with an EMPTY scope, no extension) rather than a bare "0".
                // With flows present the table stays and AppsAttributionBanner speaks above it.
                AppsEmptyState()
            } else {
                flowTable
            }
        }
        .environment(session)
        .themed()
    }

    private func listPane(_ pane: Int) -> some View {
        @Bindable var session = session
        return VStack(spacing: 0) {
            if pane == 0 {
                ChipBar(selected: $session.chip, filterActive: session.filterBarVisible) { session.filterBarVisible.toggle() }
            } else {
                ChipBar(selected: $session.secondQuery.chip)
            }
            if pane == 0 {
                flowTable
            } else {
                FlowTableView(rows: session.secondVisibleRows, selection: $session.secondSelection, sort: $session.secondQuery.sort,
                              density: session.density, layoutURL: nil, quickLookTick: session.quickLookTick,
                              isPinned: { session.isPinned(.host($0)) },
                              onComment: { id, text in session.comment(id, text) },
                              onFocus: { id in session.focus(pane: 1, on: id) },
                              onAction: { action, id in session.perform(action, on: id) },
                              onToggleIntercept: { session.arm(!session.interceptArmed) },
                              onCompose: { session.openCompose() })
            }
        }
        .overlay(alignment: .top) {
            Rectangle().fill(session.focusedPane == pane ? Palette.accent : .clear).frame(height: 2)
        }
        .frame(maxWidth: .infinity)
    }

    private var flowTable: some View {
        @Bindable var session = session
        return FlowTableView(rows: session.visibleRows, selection: $session.selection, sort: $session.sort,
                             density: session.density, layoutURL: session.columnsURL, quickLookTick: session.quickLookTick,
                             isPinned: { session.isPinned(.host($0)) },
                             onComment: { id, text in session.comment(id, text) },
                             onFocus: { id in session.focus(pane: 0, on: id) },
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

/// Shown above the flow area when the embedded core has failed (Wave 11): a dead
/// core captures nothing, so the status-bar dot alone is too quiet — say it plainly
/// with the failure reason and the two recovery actions.
private struct CoreFailedBanner: View {
    @Environment(Session.self) private var session

    var body: some View {
        HStack(spacing: Space.sm) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(Tok.Severity.high.fg.color)
            VStack(alignment: .leading, spacing: 0) {
                Text("Embedded core failed — not capturing")
                    .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
                    .foregroundStyle(Tok.Ink.primary.color)
                if let reason = session.coreHealth.connection?.status.degradedReason {
                    Text(reason)
                        .font(Tok.Face.ui(Tok.Typography.Size.xs))
                        .foregroundStyle(Tok.Ink.secondary.color)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: Space.sm)
            SmallButton("Show Log") { session.coreLogVisible = true }
            SmallButton("Restart Core") { session.restartCoreTick += 1 }
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Tok.Severity.high.bg.color)
        .accessibilityElement(children: .combine)
    }
}

/// `sheet(item:)` wants an Identifiable; a flow id is one.
struct BuildPoCTarget: Identifiable {
    let id: FlowID
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

/// One line above the flow table on the Apps page when flows exist but carry no source
/// app (so nothing can be grouped): the honest capture state from `CaptureAdvice` and the
/// one action that changes it. The table stays; captured flows are never hidden behind it.
struct AppsAttributionBanner: View {
    @Environment(Session.self) private var session
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        let health = session.coreHealth
        let advice = CaptureAdvice.make(
            capability: health.captureCapability, supported: health.captureSupported,
            scopeHostCount: session.scopeHosts.count)
        HStack(spacing: Space.sm) {
            HStack(spacing: Space.sm) {
                Image(systemName: "app.badge").font(.system(size: Tok.Size.iconInline))
                Text(advice.banner)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: Space.sm)
            if advice.offersScope {
                SmallButton("Open Scope…") { session.show(.scope) }
            } else if advice.offersSettings {
                SmallButton("Open Settings…") {
                    session.settingsTab = .capture
                    openSettings()
                }
            }
        }
        .font(Tok.Face.ui(Tok.Typography.Size.sm))
        .foregroundStyle(Tok.Ink.tertiary.color)
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.Row.dense)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// The Apps page when there is nothing to group by. It says the one true thing about
/// capture (`CaptureAdvice`) instead of always blaming a missing extension: with the
/// extension on but the scope EMPTY, nothing is captured until a host is added, so the
/// state offers Scope; off offers Settings. It never toggles capture itself (that stays
/// operator-only, in the Settings toggle).
struct AppsEmptyState: View {
    @Environment(Session.self) private var session
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        let health = session.coreHealth
        let advice = CaptureAdvice.make(
            capability: health.captureCapability, supported: health.captureSupported,
            scopeHostCount: session.scopeHosts.count)
        ContentUnavailableView {
            Label(advice.headline, systemImage: "app.badge")
        } description: {
            Text(advice.detail)
        } actions: {
            if advice.offersScope {
                Button("Open Scope…") { session.show(.scope) }
            } else if advice.offersSettings {
                Button("Open Settings…") {
                    session.settingsTab = .capture
                    openSettings()
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
    }
}

/// The "Drop to import" face over the whole window while a file is dragged
/// in (S-065): the surface at nine tenths, one line of type, no illustration.
struct DropOverlay: View {
    var body: some View {
        ZStack {
            Tok.Ground.surface.color.opacity(0.92)
            VStack(spacing: Space.sm) {
                Image(systemName: "arrow.down.doc")
                    .font(.system(size: Tok.Typography.Size.xl * 2, weight: .light))
                    .foregroundStyle(Tok.Ink.secondary.color)
                Text("Drop to import")
                    .font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                Text("HAR files are read here; mitmproxy, Proxyman and Charles files need the proxy (F10).")
                    .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
            }
            .multilineTextAlignment(.center)
            .padding(Space.section)
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.panel).strokeBorder(Tok.Line.control.color, style: StrokeStyle(lineWidth: 1, dash: [6, 6])))
            .padding(Space.section)
        }
        .ignoresSafeArea()
        .allowsHitTesting(false)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Drop to import")
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
