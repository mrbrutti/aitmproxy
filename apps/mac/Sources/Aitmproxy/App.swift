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
    /// The active core kind (Settings ▸ Bus), read exactly as `ProxySettings` reads it: capture
    /// belongs to the embedded core, so the Enable/Disable Capture command stands down unless
    /// that is the active one.
    @AppStorage(UserDefaultsActiveKindPersistence.key) private var activeKindRaw = ActiveCoreKind.embedded.rawValue

    private var usesEmbedded: Bool { (ActiveCoreKind(rawValue: activeKindRaw) ?? .embedded) == .embedded }

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
            // Row verbs read the verb table (titles, shortcuts, enabled); the rest are session intents.
            Button(session.interceptArmed ? "Disarm Intercept" : "Arm Intercept") {
                session.arm(!session.interceptArmed)
            }
            .keyboardShortcut("i", modifiers: [])
            VerbButton(session: session, verb: .resume, target: session.interceptTarget?.id)
            Button("Resume All") { session.resumeAll() }
                .keyboardShortcut(.return, modifiers: [.command, .option])
                .disabled(session.paused.isEmpty)
            VerbButton(session: session, verb: .edit, target: session.focused)
            // ⌘Z stays Undo inside the request editor; the item reverts the whole draft.
            Button("Revert to Original") { if let id = session.focused { session.revertDraft(id) } }
                .disabled(session.focused.map { session.pendingEditCount($0) > 0 } != true)
            VerbButton(session: session, verb: .kill, target: session.interceptTarget?.id)
            Divider()
            VerbButton(session: session, verb: .replay, target: session.focused)
            VerbButton(session: session, verb: .editAndReplay, target: session.focused)
            Divider()
            VerbButton(session: session, verb: .resumeSelected, target: session.focused)
            VerbButton(session: session, verb: .killSelected, target: session.focused)
            VerbButton(session: session, verb: .delete, target: session.focused)
            VerbButton(session: session, verb: .buildPoC, target: session.focused)
            Divider()
            Menu(session.verbItem(.mark(nil), for: session.focused).title) {
                ForEach(MarkColor.allCases, id: \.self) { color in
                    Button(color.title) { if let id = session.focused { session.perform(.mark(color), on: id) } }
                }
                Divider()
                Button("Clear Mark") { if let id = session.focused { session.perform(.mark(nil), on: id) } }
            }
            .disabled(!session.verbItem(.mark(nil), for: session.focused).enabled)
            VerbButton(session: session, verb: .comment, target: session.focused)
            VerbButton(session: session, verb: .pinHost, target: session.focused)
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
            VerbButton(session: session, verb: .quickLook, target: session.focused)
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
            .disabled(!session.coreHealth.captureControlsAvailable || session.coreHealth.captureBusy || !usesEmbedded)
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

/// One Flow-menu item for a row verb: title, key equivalent and enabled state from `VerbTable`,
/// so the menu bar can never drift from the row menu or the intercept bar.
private struct VerbButton: View {
    let session: Session
    let verb: FlowVerb
    let target: FlowID?

    var body: some View {
        let item = session.verbItem(verb, for: target)
        Button(item.title) { if let target { session.perform(verb, on: target) } }
            .keyboardShortcut(item.shortcut.map(KeyboardShortcut.init))
            .disabled(!item.enabled)
    }
}

extension KeyboardShortcut {
    /// The Kit's `Shortcut` as SwiftUI binds it.
    init(_ shortcut: Shortcut) {
        let key: KeyEquivalent = switch shortcut.key {
        case "\r": .return
        case "\u{8}": .delete
        case " ": .space
        case "\u{1b}": .escape
        default: KeyEquivalent(Character(shortcut.key))
        }
        var modifiers: EventModifiers = []
        if shortcut.command { modifiers.insert(.command) }
        if shortcut.shift { modifiers.insert(.shift) }
        if shortcut.option { modifiers.insert(.option) }
        if shortcut.control { modifiers.insert(.control) }
        self.init(key, modifiers: modifiers)
    }
}
