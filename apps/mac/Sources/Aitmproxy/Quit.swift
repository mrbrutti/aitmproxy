import AppKit

/// The one quit path for the app. Spec:
/// `docs/superpowers/specs/2026-11-03-mac-quit-ends-open-sheets-design.md`.
///
/// AppKit refuses every quit while a sheet is attached to any window, logging
/// `App termination blocked by modal sheet` and aborting before `applicationShouldTerminate`
/// is ever asked, so menu Quit, ⌘Q and the quit Apple event all fail with a beep. The check
/// consults `preventsApplicationTerminationWhenModal` on each attached sheet window, so the
/// helper clears that flag on every attached sheet, ends the sheets innermost first so nothing
/// is left on screen during the exit, and hands the quit to `NSApp.terminate(nil)`, which runs
/// the ordinary orderly-exit path: the delegate's default `NSTerminateNow`,
/// `willTerminateNotification`, the embedded core's SIGTERM, and the core's system-proxy
/// restore. A quit never asks about a sheet's contents (spec D4); the Rules draft it discards is
/// recorded there as accepted.
///
/// This is a helper with two callers (the replaced Quit command and the quit Apple event
/// handler in `App.swift`) and not an `NSApplication` subclass because SwiftUI's `@main`
/// installs its own `NSApplication` subclass and ignores `NSPrincipalClass`.
enum Quit {
    /// Takes one snapshot of the attached sheets (windows with a `sheetParent`), sorted so the
    /// innermost sheet of each chain comes first, and visits each exactly once: clears
    /// `preventsApplicationTerminationWhenModal` so AppKit's modal-sheet check cannot refuse the
    /// quit (spec D2 amendment), then ends the sheet through its parent. Then always calls
    /// `NSApp.terminate(nil)`. A detach that lags behind `endSheet(_:)` is harmless because the
    /// cleared flag already lets `terminate` through. Never asks, alerts or beeps, and never
    /// inspects what a sheet shows.
    static func endSheetsAndTerminate() {
        let sheets = NSApp.windows.filter { $0.sheetParent != nil }.sorted { depth($0) > depth($1) }
        for sheet in sheets {
            sheet.preventsApplicationTerminationWhenModal = false
            sheet.sheetParent?.endSheet(sheet)
        }
        NSApp.terminate(nil)
    }

    /// How many sheet parents sit above a window: 0 for a plain window, 1 for a sheet, 2 for a
    /// sheet on a sheet.
    private static func depth(_ window: NSWindow) -> Int {
        var depth = 0
        var parent = window.sheetParent
        while let next = parent {
            depth += 1
            parent = next.sheetParent
        }
        return depth
    }
}
