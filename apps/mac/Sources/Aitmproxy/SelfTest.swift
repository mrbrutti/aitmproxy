import AitmproxyKit
import AppKit
import Synchronization

/// The self-test entry point and its scaffolding (the watchdog, `settle`, `check`,
/// `finish`, the S-069 menu audit). The only run is the live one (`SelfTest+Live.swift`):
/// with `APP_LIVE=1` and a running `aitm` it drives the real session over the real bus,
/// prints PASS or FAIL per check, and quits with exit code 0 or 1.
///   AITM_CONFIG=… APP_STORE=/tmp/x APP_LIVE=1 Aitmproxy --selftest   (tools/selftest-live.sh)
/// Without `APP_LIVE=1` the run is refused: the fixture self-test was removed on 2026-10-31.
@MainActor
enum SelfTest {
    static var requested: Bool { CommandLine.arguments.contains("--selftest") }
    /// Read by AppDelegate.applicationWillTerminate.
    static var exitCode: Int32 = 0
    static var failures = 0
    static var count = 0

    /// The window scene's `.task` starts the self-test. AppKit opens a bare
    /// command-line word (one that is neither `--selftest` nor part of a
    /// `-key value` pair) as a document, and SwiftUI then never opens the main
    /// window, so that `.task` never fires and the process would idle forever
    /// (seen 2026-10-31 with `--selftest -bus.activeKind external`). The watchdog
    /// turns that, and a check that never settles, into a failed run: FAIL and
    /// exit 1 when the self-test has not started by `startDeadline` or finished by
    /// `runDeadline`. It runs off the main actor so a busy main thread cannot stall it.
    nonisolated static let startDeadline: Duration = .seconds(15)
    nonisolated static let runDeadline: Duration = .seconds(240)
    nonisolated private static let started = Mutex(false)
    nonisolated private static let finished = Mutex(false)

    static func armWatchdog() {
        guard requested else { return }
        Task.detached {
            try? await Task.sleep(for: startDeadline)
            guard started.withLock({ $0 }) else {
                print("SELFTEST FAIL: not started within \(startDeadline): the main window never appeared. A bare command-line word is opened as a document; pass settings through APP_DEFAULTS_SUITE, not -key value arguments.")
                exit(1)
            }
            try? await Task.sleep(for: runDeadline - startDeadline)
            guard finished.withLock({ $0 }) else {
                print("SELFTEST FAIL: not finished within \(runDeadline)")
                exit(1)
            }
        }
    }

    /// Why a `--selftest` run must not proceed, or nil: no `APP_STORE` (it would run on
    /// the operator's real store), or no `APP_LIVE=1` (the fixture self-test is gone).
    /// `AppDelegate.applicationDidFinishLaunching` prints it and exits before the live
    /// stack is built (spec D3 item 5); `runIfRequested` re-checks it as a second line
    /// of defence.
    static func refusal() -> String? {
        guard Store.isOverridden else { return "SELFTEST refused: set APP_STORE to a folder in /tmp" }
        guard live else { return "SELFTEST refused: the fixture self-test was removed on 2026-10-31; run tools/selftest-live.sh (APP_LIVE=1)" }
        return nil
    }

    static func runIfRequested(session: Session) {
        guard requested else { return }
        started.withLock { $0 = true }
        setvbuf(stdout, nil, _IOLBF, 0)
        if let why = refusal() {
            print(why)
            finish(code: 1)
            return
        }
        runLive(session: session)
    }

    // MARK: S-069

    private struct MenuEntry {
        var title: String
        var shortcut: Shortcut?
    }

    /// Every item of every menu, submenus included, with its key equivalent as a `Shortcut`.
    private static func allMenuItems() -> [MenuEntry] {
        var out: [MenuEntry] = []
        func walk(_ menu: NSMenu) {
            menu.update()
            for item in menu.items {
                var key = item.keyEquivalent
                var shift = item.keyEquivalentModifierMask.contains(.shift)
                if key.count == 1, key != key.lowercased() { shift = true; key = key.lowercased() }
                let mask = item.keyEquivalentModifierMask
                let shortcut = key.isEmpty ? nil
                    : Shortcut(key, command: mask.contains(.command), shift: shift, option: mask.contains(.option), control: mask.contains(.control))
                out.append(MenuEntry(title: item.title, shortcut: shortcut))
                if let submenu = item.submenu { walk(submenu) }
            }
        }
        if let main = NSApp.mainMenu { walk(main) }
        return out
    }

    static func checkMenuCoverage() {
        let items = allMenuItems()
        for entry in CommandMap.all {
            if case .deferred(let why) = entry.scope {
                print("SKIP menu \(entry.brief): \(why)")
                continue
            }
            var missing: [String] = []
            for item in entry.items {
                let wantsKey = entry.scope == .menu ? item.shortcut : nil
                let found = items.contains { menu in item.titles.contains(menu.title) && (wantsKey == nil || menu.shortcut == wantsKey) }
                if !found { missing.append(item.titles[0] + (wantsKey.map { " \($0.display)" } ?? "")) }
            }
            check("\(entry.menu) menu has \(entry.brief)", missing.isEmpty, "missing \(missing)")
        }
    }

    /// Types `r` into the sidebar filter: the field gets the letter, nothing replays.
    static func checkTypingIsNotAVerb(_ session: Session) async {
        NSApp.activate()
        guard let window = NSApp.windows.first(where: { $0.isVisible && !($0 is NSPanel) }) else {
            return check("a main window exists for the typing check", false)
        }
        window.makeKeyAndOrderFront(nil)
        session.sidebarFilterFocusTick += 1
        await settle { window.firstResponder is NSTextView }
        guard window.firstResponder is NSTextView else {
            return check("the sidebar filter takes focus", false, "first responder \(String(describing: window.firstResponder))")
        }
        let before = session.rows.count
        let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                     windowNumber: window.windowNumber, context: nil, characters: "r", charactersIgnoringModifiers: "r",
                                     isARepeat: false, keyCode: 15)
        if let event { window.sendEvent(event) }
        await settle(timeout: .seconds(1)) { session.sidebarQuery == "r" }
        check("typing r in the sidebar filter types, never replays", session.sidebarQuery == "r" && session.rows.count == before,
              "query '\(session.sidebarQuery)' rows \(session.rows.count) were \(before)")
        session.sidebarQuery = ""
        window.makeFirstResponder(nil)
    }

    /// Waits for an async action to land instead of sleeping a fixed time (bus
    /// replies hop through Tasks; under load a fixed sleep races them).
    static func settle(timeout: Duration = .seconds(5), until done: () -> Bool) async {
        let deadline = ContinuousClock.now + timeout
        while !done(), ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(25))
        }
    }

    static func check(_ name: String, _ ok: Bool, _ detail: String = "") {
        count += 1
        if !ok { failures += 1 }
        print(ok ? "PASS \(name)" : "FAIL \(name)\(detail.isEmpty ? "" : ": \(detail)")")
    }

    /// Quits through NSApp.terminate, never exit(), and closes sheets first.
    static func finish(code: Int32) {
        finished.withLock { $0 = true }
        exitCode = code
        for window in NSApp.windows { if let sheet = window.attachedSheet { window.endSheet(sheet) } }
        NSApp.terminate(nil)
    }
}
