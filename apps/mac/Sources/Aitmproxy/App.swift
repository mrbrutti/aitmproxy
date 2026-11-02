import AitmproxyKit
import AppKit
import SwiftUI

// Aitmproxy — the native macOS operator app for the aitmproxy command bus.
//   Aitmproxy                       the app (connects to the bus from Settings or config.yaml)
//   APP_STORE=<dir> Aitmproxy       keep local state (pins, saved filters) elsewhere (tests)
//   APP_LIVE=1 Aitmproxy --selftest run the live self-test against a running aitm and quit with 0 or 1 (tools/selftest-live.sh)
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
        // Fail closed first (spec D3 items 8 and 5), before the process even becomes a
        // foreground app and before any window, BusService, connection model or
        // ExtensionController exists: a removed fake-data switch, or a `--selftest`
        // without its harness, must never run the live stack on the operator's real
        // defaults. `exit` flushes the one printed line.
        if let why = RemovedModes.refusal(environment: ProcessInfo.processInfo.environment) {
            print(why)
            exit(1)
        }
        if SelfTest.requested, let why = SelfTest.refusal() {
            print(why)
            exit(1)
        }
        // Started from a terminal, the process is not a foreground app yet.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
        SelfTest.armWatchdog()
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
    /// True when APP_STORE points somewhere else (tests, the dev bundle).
    static var isOverridden: Bool {
        !(ProcessInfo.processInfo.environment["APP_STORE"] ?? "").isEmpty
    }

    /// The store for the connection settings (`bus.*`, `proxy.*`, `capture.enabled`):
    /// the operator's real defaults in a normal launch, an isolated suite in a
    /// harness run (`APP_STORE` / `APP_LIVE`; `SettingsDomain`), so stale Settings ▸ Bus
    /// residue never steers a test and a test never overwrites it. `UserDefaults` is
    /// thread-safe but not marked `Sendable`, hence `unsafe`; the embedded core reads
    /// it off the main actor.
    nonisolated(unsafe) static let defaults: UserDefaults = {
        let env = ProcessInfo.processInfo.environment
        return SettingsDomain.select(environment: env).makeDefaults(registering: SettingsDomain.registration(environment: env))
    }()

    static var url: URL {
        if let path = ProcessInfo.processInfo.environment["APP_STORE"], !path.isEmpty {
            return URL(fileURLWithPath: path, isDirectory: true)
        }
        let dir = URL.applicationSupportDirectory.appending(path: "Aitmproxy", directoryHint: .isDirectory)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
}

/// Menu bar items for every flow action, with the shortcuts the foundation
/// prints on buttons (§2.7). The targets resolve when the item fires.
struct FlowCommands: Commands {
    let session: Session
    /// The persisted capture choice (Settings ▸ Capture), read here for the Enable/Disable label.
    @AppStorage("capture.enabled", store: Store.defaults) private var captureEnabled = false
    /// The active core kind (Settings ▸ Bus), read exactly as `ProxySettings` reads it: capture
    /// belongs to the embedded core, so the Turn On/Off Capture command stands down unless
    /// that is the active one.
    @AppStorage(UserDefaultsActiveKindPersistence.key, store: Store.defaults) private var activeKindRaw = ActiveCoreKind.embedded.rawValue

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
            // Resume and Kill act on the intercept bar's target, every other verb on the focused row.
            let focused = session.focused
            let target = session.interceptTarget?.id
            let focusedItems = session.verbItems(for: focused)
            let targetItems = session.verbItems(for: target)
            let verb: (FlowVerb, FlowID?, [VerbItem]) -> VerbButton = { v, id, items in
                VerbButton(item: VerbTable.item(v, in: items)) { if let id { session.perform(v, on: id) } }
            }
            Button(session.interceptArmed ? "Disarm Intercept" : "Arm Intercept") {
                session.arm(!session.interceptArmed)
            }
            .keyboardShortcut("i", modifiers: [])
            verb(.resume, target, targetItems)
            Button("Resume All") { session.resumeAll() }
                .keyboardShortcut(.return, modifiers: [.command, .option])
                .disabled(session.paused.isEmpty)
            verb(.edit, focused, focusedItems)
            // ⌘Z stays Undo inside the request editor; the item reverts the whole draft.
            Button("Revert to Original") { if let id = session.focused { session.revertDraft(id) } }
                .disabled(session.focused.map { session.pendingEditCount($0) > 0 } != true)
            verb(.kill, target, targetItems)
            Divider()
            verb(.replay, focused, focusedItems)
            verb(.editAndReplay, focused, focusedItems)
            Divider()
            verb(.resumeSelected, focused, focusedItems)
            verb(.killSelected, focused, focusedItems)
            verb(.delete, focused, focusedItems)
            verb(.buildPoC, focused, focusedItems)
            Divider()
            let mark = VerbTable.item(.mark(nil), in: focusedItems)
            Menu(mark.title) {
                ForEach(MarkColor.allCases, id: \.self) { color in
                    Button(color.title) { if let focused { session.perform(.mark(color), on: focused) } }
                }
                Divider()
                Button("Clear Mark") { if let focused { session.perform(.mark(nil), on: focused) } }
            }
            .disabled(!mark.enabled)
            verb(.comment, focused, focusedItems)
            verb(.pinHost, focused, focusedItems)
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
            verb(.quickLook, focused, focusedItems)
        }
        CommandMenu("Proxy") {
            Button("Status") { session.show(.status) }
                .keyboardShortcut("0", modifiers: .command)
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
            // The first-run step from the menu (spec D17.10): the same `trustCA()` as the sheet, the
            // Status card and the CA panel. ⌃⌘T is free (⌘T is New Browser Tab). Disabled while the
            // bus is not the operator's, while a change is in flight, and once a store says trusted.
            Button(ConnectionAction.trustCA.title) { Task { await session.trustCA() } }
                .keyboardShortcut("t", modifiers: [.command, .control])
                .disabled(!session.caTrustControlLive || session.caTrust?.trusted == true)
            // The system-proxy step from the menu (spec D13 "Menu"): one item whose title follows the fact
            // (CommandMap's toggle pair), the same `setSystemProxy()` / `restoreSystemProxy()` as the sheet,
            // the Status page and the Flows banner. ⌥⌘P is free. Disabled while the bus is not the
            // operator's or a change is in flight.
            Button(session.systemProxyPointsAtUs ? ConnectionAction.unsetSystemProxy.title : ConnectionAction.setSystemProxy.title) {
                Task { await (session.systemProxyPointsAtUs ? session.restoreSystemProxy() : session.setSystemProxy()) }
            }
            .keyboardShortcut("p", modifiers: [.command, .option])
            .disabled(!session.systemProxyControlLive)
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
            // The same steps as Settings ▸ All Apps' toggle (CaptureSwitch). ⌃⌘A: none of
            // the reconnect/restart/pause/replay chords on R, and no other C chord but ⇧⌘C.
            Button((session.coreHealth.captureChoice ?? captureEnabled) ? "Stop Capturing All Apps" : "Capture All Apps") {
                let on = !(session.coreHealth.captureChoice ?? captureEnabled)
                Task { await CaptureSwitch.set(on, session: session) }
            }
            .keyboardShortcut("a", modifiers: [.command, .control])
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
                ForEach(Array(ContentCategory.shortcutChips.enumerated()), id: \.offset) { index, chip in
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
            Button(session.capturing ? "Pause Proxy" : "Resume Proxy") { session.setCapturing(!session.capturing) }
                .keyboardShortcut("r", modifiers: [.command, .shift])
        }
    }
}

/// One Flow-menu item for a row verb: title, key equivalent and enabled state from `VerbTable`,
/// so the menu bar can never drift from the row menu or the intercept bar.
private struct VerbButton: View {
    let item: VerbItem
    let action: () -> Void

    var body: some View {
        Button(item.title, action: action)
            .keyboardShortcut(item.shortcut.flatMap(KeyboardShortcut.init))
            .disabled(!item.enabled)
    }
}

extension KeyboardShortcut {
    /// The Kit's `Shortcut` as SwiftUI binds it; nil for a key that is not one character.
    init?(_ shortcut: Shortcut) {
        guard shortcut.key.count == 1, let character = shortcut.key.first else { return nil }
        let key: KeyEquivalent = switch character {
        case "\r": .return
        case "\u{8}": .delete
        case " ": .space
        case "\u{1b}": .escape
        default: KeyEquivalent(character)
        }
        var modifiers: EventModifiers = []
        if shortcut.command { modifiers.insert(.command) }
        if shortcut.shift { modifiers.insert(.shift) }
        if shortcut.option { modifiers.insert(.option) }
        if shortcut.control { modifiers.insert(.control) }
        self.init(key, modifiers: modifiers)
    }
}
