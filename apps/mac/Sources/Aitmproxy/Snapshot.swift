import AppKit
import IOKit.pwr_mgt
import SwiftUI

/// Screenshot mode for agents.
///   APP_STORE=/tmp/x APP_SNAPSHOT=/tmp/shots ~/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy
/// writes <page>-light.png and <page>-dark.png for every sidebar page, and
/// settings-<tab>-light.png and settings-<tab>-dark.png for every Settings tab, then quits.
/// Settings ▸ Capture also writes settings-capture-<off|awaiting|active|failed>-<mode>.png.
/// Each PNG gets a <page>-<mode>-layout.json with the grid probes (tools/check-layout.swift).
/// APP_SNAPSHOT_PAGES=apps,scope limits the pages. Add "settings" to include Settings.
/// Add APP_ACCENT=<id> to see the pages in another accent. Snapshots always show the fixture session.
enum Snapshot {
    static func runIfRequested(session: Session, openSettings: OpenSettingsAction) {
        let env = ProcessInfo.processInfo.environment
        guard let dir = env["APP_SNAPSHOT"], !dir.isEmpty else { return }
        // Snapshots never touch the real local state.
        guard Store.isOverridden else {
            print("SNAPSHOT refused: set APP_STORE to a folder in /tmp")
            NSApp.terminate(nil)
            return
        }
        let only = env["APP_SNAPSHOT_PAGES"].map { Set($0.split(separator: ",").map(String.init)) }
        Task {
            // A sleeping display gives screencapture nothing. Declaring user
            // activity wakes it; the assertion keeps it on until the run quits.
            var activity: IOPMAssertionID = 0
            IOPMAssertionDeclareUserActivity("Snapshots" as CFString, kIOPMUserActiveLocal, &activity)
            var awake: IOPMAssertionID = 0
            IOPMAssertionCreateWithName(kIOPMAssertionTypePreventUserIdleDisplaySleep as CFString,
                                        IOPMAssertionLevel(kIOPMAssertionLevelOn), "Snapshots" as CFString, &awake)
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            // Deterministic frames before the first layout settles: pages at 1440×900, the gallery at the whole screen.
            if let window = NSApp.windows.first(where: { $0.canBecomeMain && !$0.isSheet }) {
                window.isRestorable = false
                let frame = NSRect(x: window.frame.minX, y: window.frame.maxY - 900, width: 1440, height: 900)
                window.setFrame(frame, display: true)
                window.center()
            }
            try? await Task.sleep(for: .seconds(1.5))
            if env["APP_KIT_GALLERY"] == "1" {
                // The parts gallery is one tall page: give it the whole screen, then one shot per mode.
                if let window = NSApp.windows.first(where: { $0.canBecomeMain && !$0.isSheet }),
                   let screen = window.screen ?? NSScreen.main {
                    window.setFrame(screen.visibleFrame, display: true)
                }
                for mode in ["light", "dark"] {
                    NSApp.appearance = NSAppearance(named: mode == "light" ? .aqua : .darkAqua)
                    try? await Task.sleep(for: .seconds(0.8))
                    capture(to: "\(dir)/gallery-\(mode).png")
                }
                print("SNAPSHOT done \(dir)")
                NSApp.terminate(nil)
                return
            }
            for mode in ["light", "dark"] {
                NSApp.appearance = NSAppearance(named: mode == "light" ? .aqua : .darkAqua)
                // Scenes mutate the session (imports, sends, selections); start each appearance
                // pass from the same fixture state so a light/dark pair differs only in appearance.
                if Store.usesFixtures { session.loadFixtures() }
                for page in SidebarPage.allCases where only?.contains(page.rawValue) ?? true {
                    session.page = page
                    try? await Task.sleep(for: .seconds(0.8))
                    capture(to: "\(dir)/\(page.rawValue)-\(mode).png")
                }
                // Panels, bars and selections (docs/STORIES.md `Screens:`), each applied then reset.
                for scene in SnapshotScene.allCases where only?.contains(scene.rawValue) ?? true {
                    scene.apply(to: session)
                    try? await Task.sleep(for: .seconds(0.8))
                    capture(to: "\(dir)/\(scene.rawValue)-\(mode).png")
                    if scene == .detached, let inspector = Snapshot.inspectorWindow() {
                        inspector.setContentSize(NSSize(width: 1100, height: 620))
                        try? await Task.sleep(for: .seconds(0.4))
                        capture(to: "\(dir)/\(scene.rawValue)-window-\(mode).png", window: inspector)
                    }
                    SnapshotScene.reset(session)
                    try? await Task.sleep(for: .seconds(0.2))
                }
            }
            if only == nil || only?.contains("settings") == true {
                // A ready embedded core so Settings ▸ Proxy shows its real resting state:
                // Apply & Restart disabled (nothing changed) and no divergent bound address.
                session.coreHealth.connection = SnapshotScene.core(
                    .ready, label: "Embedded core · proxy 127.0.0.1:8080", proxyAddress: "127.0.0.1:8080")
                let main = NSApp.windows.first { $0.canBecomeMain && !$0.isSheet }
                openSettings()
                try? await Task.sleep(for: .seconds(1))
                for mode in ["light", "dark"] {
                    NSApp.appearance = NSAppearance(named: mode == "light" ? .aqua : .darkAqua)
                    for tab in SettingsTab.allCases {
                        session.settingsTab = tab
                        try? await Task.sleep(for: .seconds(0.8))
                        let settings = NSApp.windows.first { $0.isVisible && $0 !== main && !$0.isSheet }
                        capture(to: "\(dir)/settings-\(tab.rawValue)-\(mode).png", window: settings)
                    }
                }
                // The Capture tab above shows a build without the extension (the note). Here it is
                // in each state the operator can meet: off, awaiting approval, capturing, failed.
                session.settingsTab = .capture
                for mode in ["light", "dark"] {
                    NSApp.appearance = NSAppearance(named: mode == "light" ? .aqua : .darkAqua)
                    for state in CaptureSnapshotState.allCases {
                        state.apply(to: session)
                        try? await Task.sleep(for: .seconds(0.8))
                        let settings = NSApp.windows.first { $0.isVisible && $0 !== main && !$0.isSheet }
                        capture(to: "\(dir)/settings-capture-\(state.rawValue)-\(mode).png", window: settings)
                    }
                }
                CaptureSnapshotState.reset(session)
            }
            print("SNAPSHOT done \(dir)")
            // An open sheet refuses terminate, and the run would wait forever.
            for window in NSApp.windows { if let sheet = window.attachedSheet { window.endSheet(sheet) } }
            NSApp.terminate(nil)
        }
    }

    /// The detached inspector window, found by its scene id: its title names the focused
    /// flow (rule 19), so a title match would miss it.
    static func inspectorWindow() -> NSWindow? {
        NSApp.windows.first { window in
            (window.identifier?.rawValue.hasPrefix("inspector") ?? false) || window.title == "Inspector"
        }
    }

    /// Captures the real window with screencapture, so glass, sidebars, and
    /// materials look exactly as on screen. That needs Screen Recording
    /// permission for the app that started this one. Without it, falls back
    /// to drawing the view hierarchy, which leaves glass blank.
    private static func capture(to path: String, window: NSWindow? = nil) {
        if NSApp.isHidden { NSApp.unhideWithoutActivation() }
        guard let window = window ?? NSApp.windows.first(where: { $0.canBecomeMain && !$0.isSheet }) else {
            print("SNAPSHOT no window")
            return
        }
        NSApp.activate()
        window.makeKeyAndOrderFront(nil)
        // A scene that opened a sheet wants the sheet, not the target behind it.
        let target = window.attachedSheet ?? window
        let size = target.contentView?.bounds.size ?? .zero
        GridProbes.shared.write(to: path.replacingOccurrences(of: ".png", with: "-layout.json"), window: size)
        try? FileManager.default.removeItem(atPath: path)
        for _ in 1...3 {
            let shot = Process()
            shot.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            shot.arguments = ["-x", "-o", "-l", String(target.windowNumber), path]
            try? shot.run()
            shot.waitUntilExit()
            if FileManager.default.fileExists(atPath: path) {
                print("SNAPSHOT \(path)")
                return
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        guard let view = target.contentView?.superview ?? target.contentView,
              let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        if let data = rep.representation(using: .png, properties: [:]) {
            try? data.write(to: URL(fileURLWithPath: path))
            print("SNAPSHOT \(path) (fallback: no Screen Recording permission, glass is blank)")
        }
    }
}
