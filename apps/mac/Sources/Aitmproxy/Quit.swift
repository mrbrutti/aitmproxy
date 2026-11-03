import AppKit

/// The one quit path for the app. Spec:
/// `docs/superpowers/specs/2026-11-03-mac-quit-ends-open-sheets-design.md`.
///
/// AppKit refuses every quit while a sheet is attached to any window, logging
/// `App termination blocked by modal sheet` and aborting before `applicationShouldTerminate`
/// is ever asked, so menu Quit, ⌘Q and the quit Apple event all fail with a beep. Every sheet
/// in this app is work-free, so the helper ends the attached sheets first and then hands the
/// quit to `NSApp.terminate(nil)`, which runs the ordinary orderly-exit path: the delegate's
/// default `NSTerminateNow`, `willTerminateNotification`, the embedded core's SIGTERM, and the
/// core's system-proxy restore.
///
/// This is a helper with two callers (the replaced Quit command and the quit Apple event
/// handler in `App.swift`) and not an `NSApplication` subclass because SwiftUI's `@main`
/// installs its own `NSApplication` subclass and ignores `NSPrincipalClass`.
enum Quit {
    /// Ends every attached sheet on every window, innermost first, then always calls
    /// `NSApp.terminate(nil)`. The walk runs before `terminate` because AppKit's modal-sheet
    /// check runs before the delegate is asked. It is bounded by the window count at entry so
    /// it finishes even if `endSheet(_:)` fails to detach a sheet; AppKit then refuses exactly
    /// as before. Never asks, alerts or beeps, and never inspects what a sheet shows.
    ///
    /// AppKit's modal-sheet check consults `preventsApplicationTerminationWhenModal` on each
    /// attached sheet window, so clearing that flag first is the guarantee that `terminate` goes
    /// through whatever the detach timing of `endSheet(_:)` (spec D2 amendment). The end-sheets
    /// loop stays so nothing is left on screen while the app exits.
    static func endSheetsAndTerminate() {
        for sheet in NSApp.windows where sheet.sheetParent != nil {
            sheet.preventsApplicationTerminationWhenModal = false
        }
        var remaining = NSApp.windows.count
        while remaining > 0,
            let innermost = NSApp.windows.first(where: { $0.sheetParent != nil && $0.attachedSheet == nil }),
            let parent = innermost.sheetParent
        {
            parent.endSheet(innermost)
            remaining -= 1
        }
        NSApp.terminate(nil)
    }
}
