import AitmproxyKit
import AppKit
import SwiftUI

// Aitmproxy — the native macOS operator app for the aitmproxy command bus.
//   Aitmproxy                       the app (connects to the bus from Settings or config.yaml)
//   APP_FIXTURES=1 Aitmproxy        show the fixture session instead of a live bus
//   APP_STORE=<dir> Aitmproxy       keep local state (pins, saved filters) elsewhere (tests)
//   APP_SNAPSHOT=<dir> Aitmproxy    save a PNG of every sidebar page and Settings tab in light and dark, then quit
//   Aitmproxy --selftest            run the self-test and quit with 0 or 1 (tools/selftest.sh)
//   APP_ACCENT=<id> Aitmproxy       run with another accent from Theme.all (UI/Theme.swift)
//   APP_GRID=1 Aitmproxy            draw the 8 pt grid and the layout probes over the window

@main
struct AitmproxyApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var session = Session()

    var body: some Scene {
        Window("aitmproxy", id: "main") {
            ShellView()
                .environment(session)
                .themed()
                .overlay { if GridOverlay.enabled { GridOverlay() } }
                .frame(minWidth: 1100, minHeight: 640)
                .toolbar(removing: .title)
                // Open calm: no sidebar-filter focus ring stealing attention on launch.
                .noInitialFocus()
        }
        .defaultSize(width: 1440, height: 900)
        .windowToolbarStyle(.unified)
        .commands {
            FlowCommands(session: session)
        }

        // S-061: the inspector in its own window; closing it returns to the previous layout.
        Window("Inspector", id: "inspector") {
            DetachedInspector()
                .environment(session)
                .themed()
                .frame(minWidth: 720, minHeight: 360)
                .noInitialFocus()
        }
        .defaultSize(width: 1100, height: 620)
        .windowToolbarStyle(.unifiedCompact)

        Settings {
            SettingsView()
                .environment(session)
                .themed()
        }
        .windowResizability(.contentSize)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Started from a terminal, the process is not a foreground app yet.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    /// The self-test's result becomes the exit code, after a normal quit.
    func applicationWillTerminate(_ notification: Notification) {
        if SelfTest.requested { exit(SelfTest.exitCode) }
    }
}

/// Where surface-local state lives (pins, saved filters, compose history):
/// ~/Library/Application Support/Aitmproxy/. Flows never persist here; they live in the proxy.
enum Store {
    /// True when APP_STORE points somewhere else (tests, snapshots).
    static var isOverridden: Bool {
        !(ProcessInfo.processInfo.environment["APP_STORE"] ?? "").isEmpty
    }

    static var url: URL {
        if let path = ProcessInfo.processInfo.environment["APP_STORE"], !path.isEmpty {
            return URL(fileURLWithPath: path, isDirectory: true)
        }
        let dir = URL.applicationSupportDirectory.appending(path: "Aitmproxy", directoryHint: .isDirectory)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Fixture mode: APP_FIXTURES=1, or any snapshot/self-test run — unless
    /// APP_LIVE=1 asks a snapshot to capture the live bus instead.
    static var usesFixtures: Bool {
        let env = ProcessInfo.processInfo.environment
        if env["APP_LIVE"] == "1" { return false }
        return env["APP_FIXTURES"] == "1" || env["APP_SNAPSHOT"] != nil || SelfTest.requested
    }
}

/// Menu bar items for every flow action, with the shortcuts the foundation
/// prints on buttons (§2.7). The targets resolve when the item fires.
struct FlowCommands: Commands {
    let session: Session
    /// The persisted capture choice (Settings ▸ Capture), read here for the Enable/Disable label.
    @AppStorage("capture.enabled") private var captureEnabled = false

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("Compose Request…") { session.openCompose() }
                .keyboardShortcut("n")
            Divider()
            Button("Import…") { session.chooseImport() }
                .keyboardShortcut("o")
            Menu("Export Selection…") {
                Button("HAR…") { session.exportSelection(as: .har) }
                    .keyboardShortcut("e")
                Button("CSV…") { session.exportSelection(as: .csv) }
                Button("cURL Batch…") { session.exportSelection(as: .curl) }
            }
            .disabled(session.rows.isEmpty)
            Divider()
            Button("Clear Session") { session.clearSession(confirm: ClearConfirmation.ask) }
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(session.rows.isEmpty)
        }
        CommandMenu("Flow") {
            Button(session.interceptArmed ? "Disarm Intercept" : "Arm Intercept") {
                session.arm(!session.interceptArmed)
            }
            .keyboardShortcut("i", modifiers: [])
            Button(session.interceptTarget.map { session.pendingEditCount($0.id) > 0 } == true ? "Apply & Resume" : "Resume") {
                if let target = session.interceptTarget { session.applyAndResume(target.id) }
            }
            .keyboardShortcut(.return, modifiers: .command)
            .disabled(session.interceptTarget == nil)
            Button("Resume All") { session.resumeAll() }
                .keyboardShortcut(.return, modifiers: [.command, .option])
                .disabled(session.paused.isEmpty)
            Button("Edit Paused Request") { if let id = session.focused { session.perform(.edit, on: id) } }
                .keyboardShortcut("e", modifiers: [])
                .disabled(session.focusedRow?.state != .paused)
            // ⌘Z stays Undo inside the request editor; the item reverts the whole draft.
            Button("Revert to Original") { if let id = session.focused { session.revertDraft(id) } }
                .disabled(session.focused.map { session.pendingEditCount($0) > 0 } != true)
            Button("Kill") { if let target = session.interceptTarget { session.perform(.kill, on: target.id) } }
                .keyboardShortcut("\\", modifiers: .command)
                .disabled(session.interceptTarget == nil)
            Divider()
            Button("Replay") { if let id = session.focused { session.perform(.replay, on: id) } }
                .keyboardShortcut("r", modifiers: [])
                .disabled(session.focused == nil)
            Button("Edit & Replay…") { if let id = session.focused { session.editAndReplay(id) } }
                .keyboardShortcut("r", modifiers: .shift)
                .disabled(session.focused == nil)
            Divider()
            Button("Resume Selected") { session.resumeSelected() }
                .disabled(session.selectedRows.allSatisfy { $0.state != .paused })
            Button("Kill Selected") { session.killSelected() }
                .disabled(session.selectedRows.allSatisfy { $0.state != .paused })
            Button(session.focusedRow.map { $0.state == .paused || $0.state == .pending } == true ? "Kill" : "Delete") {
                if let id = session.focused { session.deleteOrKill(id) }
            }
            .keyboardShortcut("d", modifiers: [])
            .disabled(session.focused == nil)
            Button("Build PoC from Flow…") { if let id = session.focused { session.perform(.buildPoC, on: id) } }
                .keyboardShortcut("p", modifiers: [])
                .disabled(session.focused == nil)
            Divider()
            Menu("Mark") {
                ForEach(MarkColor.allCases, id: \.self) { color in
                    Button(color.title) { if let id = session.focused { session.perform(.mark(color), on: id) } }
                }
                Divider()
                Button("Clear Mark") { if let id = session.focused { session.perform(.mark(nil), on: id) } }
            }
            .disabled(session.focused == nil)
            Button("Comment…") { if let id = session.focused { session.perform(.comment, on: id) } }
                .keyboardShortcut("l", modifiers: .command)
                .disabled(session.focused == nil)
            Button(session.focusedRow.map { session.isPinned(.host($0.authority)) } == true ? "Unpin Host" : "Pin Host") {
                if let id = session.focused { session.perform(.pinHost, on: id) }
            }
            .keyboardShortcut("p", modifiers: .shift)
            .disabled(session.focused == nil)
            Button("Add Host to Scope…") { session.addFocusedHostToScope() }
                .keyboardShortcut("s", modifiers: .shift)
                .disabled(session.focused == nil)
            Divider()
            Menu("Copy as") {
                Button("Copy as cURL") { session.copyFocused(as: .curl) }
                    .keyboardShortcut("c", modifiers: [.shift, .command])
                Button("Copy as httpie") { session.copyFocused(as: .httpie) }
                Button("Copy as Python (requests)") { session.copyFocused(as: .python) }
                Button("Copy as fetch") { session.copyFocused(as: .fetch) }
            }
            .disabled(session.focusedDetail == nil)
            Button("Diff Selected") { session.diffSelected() }
                .keyboardShortcut("d", modifiers: .command)
                .disabled(!session.canDiffSelected)
            // Space on the focused list; a menu shortcut would take Space from every field.
            Button("Quick Look Body") { if let id = session.focused { session.perform(.quickLook, on: id) } }
                .disabled(session.focused == nil)
        }
        CommandMenu("Proxy") {
            Button("Breakpoint Rules…") { session.rulesVisible = true }
                .keyboardShortcut("b", modifiers: [.command, .shift])
            Button("Scope…") { if session.page == .scope { session.scopeSheetVisible = true } else { session.show(.scope) } }
                .keyboardShortcut("o", modifiers: [.command, .shift])
            Button("Scan") { session.show(.scan) }
                .keyboardShortcut("s", modifiers: [.command, .option])
                .disabled(!session.scanEnabled)
            Divider()
            Button("Browser") { session.show(.browser) }
                .keyboardShortcut("w", modifiers: [.command, .shift])
            Button("New Browser Tab") { session.show(.browser); session.browser.newTab() }
                .keyboardShortcut("t", modifiers: .command)
            Divider()
            Button("Overview") { session.show(.overview) }
            Button("Connection Log") { session.show(.connections) }
            Button("Certificate Authority…") { session.show(.ca) }
            Button("Configuration…") { session.show(.config) }
            Button(session.coreLogVisible ? "Hide Core Log" : "Core Log…") { session.coreLogVisible.toggle() }
                .keyboardShortcut("l", modifiers: [.command, .control])
            Divider()
            Button("Reconnect Bus") { session.reconnectBus() }
                .keyboardShortcut("r", modifiers: [.command, .control])
            Button("Restart Core") { session.restartCoreTick += 1 }
                .keyboardShortcut("r", modifiers: [.command, .control, .shift])
                .disabled(session.coreHealth.connection == nil)
            Divider()
            // The same steps as Settings ▸ Capture's toggle (CaptureSwitch). ⌃⌘C: none of
            // the reconnect/restart/pause/replay chords on R, and no other C chord but ⇧⌘C.
            Button((session.coreHealth.captureChoice ?? captureEnabled) ? "Disable Capture" : "Enable Capture") {
                let on = !(session.coreHealth.captureChoice ?? captureEnabled)
                Task { await CaptureSwitch.set(on, session: session) }
            }
            .keyboardShortcut("c", modifiers: [.command, .control])
            .disabled(!session.coreHealth.captureControlsAvailable || session.coreHealth.captureBusy)
        }
        CommandMenu("Agent") {
            Picker("Policy", selection: Binding(get: { session.agentPolicy }, set: { session.activity.choose($0) })) {
                ForEach(AgentPolicy.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .pickerStyle(.inline)
            Divider()
            Button(session.activityLogVisible ? "Hide Activity Log" : "Activity Log…") { session.activityLogVisible.toggle() }
                .keyboardShortcut("l", modifiers: [.command, .shift])
            Button("Approve Pending Request") { session.approvePendingRequest() }
                .keyboardShortcut(.return, modifiers: .option)
                .disabled(session.activity.pending.isEmpty)
        }
        CommandMenu("View") {
            Button(session.filterBarVisible ? "Hide Filter Bar" : "Show Filter Bar") { session.filterBarVisible.toggle() }
                .keyboardShortcut("f", modifiers: .command)
            Button("Sidebar Filter") { session.sidebarFilterFocusTick += 1 }
                .keyboardShortcut("f", modifiers: [.command, .shift])
            Button("Command Palette") {
                session.paletteOpenedByKeyboard = true
                session.paletteVisible.toggle()
            }
            .keyboardShortcut("k", modifiers: .command)
            Button("Find in Body") { session.findRequestTick += 1 }
                .keyboardShortcut("f", modifiers: [.command, .option])
                .disabled(session.focused == nil)
            Button("Toggle Sidebar") { session.sidebarVisible.toggle() }
                .keyboardShortcut("s", modifiers: [.command, .control])
            Divider()
            // ⌘1…⌘9: the first nine chips, in chip-bar order (foundation §2.7).
            Menu("Chip") {
                ForEach(Array(ContentCategory.groups.flatMap { $0 }.prefix(9).enumerated()), id: \.offset) { index, chip in
                    Toggle(chip.title, isOn: Binding(get: { session.chip == chip }, set: { _ in session.chip = chip }))
                        .keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: .command)
                }
            }
            Picker("Sort By", selection: Binding(get: { session.sort.key }, set: { session.sort = FlowSort(key: $0, ascending: true) })) {
                ForEach(FlowSort.Key.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            Divider()
            // One item per layout, so each carries its ⌥⌘1…3 (a Picker's options cannot).
            ForEach(Array(InspectorLayout.allCases.enumerated()), id: \.offset) { index, layout in
                Toggle(layout.title, isOn: Binding(get: { session.layout == layout }, set: { _ in session.layout = layout }))
                    .keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: [.command, .option])
            }
            Toggle("Split View", isOn: Binding(get: { session.splitView }, set: { session.splitView = $0 }))
                .keyboardShortcut("4", modifiers: [.command, .option])
            Divider()
            Picker("Density", selection: Binding(get: { session.density }, set: { session.density = $0 })) {
                ForEach(Density.allCases) { Text($0.title).tag($0) }
            }
            Toggle("Auto-select", isOn: Binding(get: { session.autoSelect }, set: { session.autoSelect = $0 }))
                .keyboardShortcut("a", modifiers: [.command, .shift])
            Button(session.capturing ? "Pause Capture" : "Resume Capture") { session.setCapturing(!session.capturing) }
                .keyboardShortcut("r", modifiers: [.command, .shift])
        }
    }
}
