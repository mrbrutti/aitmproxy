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
        }
        .defaultSize(width: 1440, height: 900)
        .windowToolbarStyle(.unified)
        .commands {
            FlowCommands(session: session)
        }

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

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("Compose Request…") {}
                .keyboardShortcut("n")
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
            Button("Resume") {
                if let target = session.interceptTarget {
                    target.edited ? session.applyAndResume(target.id) : session.resume(target.id)
                }
            }
            .keyboardShortcut(.return, modifiers: .command)
            .disabled(session.interceptTarget == nil)
            Button("Kill") { if let target = session.interceptTarget { session.perform(.kill, on: target.id) } }
                .keyboardShortcut("\\", modifiers: .command)
                .disabled(session.interceptTarget == nil)
            Divider()
            Button("Replay") { if let id = session.focused { session.perform(.replay, on: id) } }
                .keyboardShortcut("r", modifiers: [])
                .disabled(session.focused == nil)
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
            Divider()
            Picker("Sort By", selection: Binding(get: { session.sort.key }, set: { session.sort = FlowSort(key: $0, ascending: true) })) {
                ForEach(FlowSort.Key.allCases, id: \.self) { Text($0.title).tag($0) }
            }
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
