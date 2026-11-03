import AppKit

/// The app's principal class, named by `NSPrincipalClass` in `Info.plist.in` (and carried into
/// dev bundles by `tools/snap-dev.sh`). Spec:
/// `docs/superpowers/specs/2026-11-03-mac-quit-ends-open-sheets-design.md`.
///
/// AppKit refuses every quit while a sheet is attached to any window, logging
/// `App termination blocked by modal sheet` and aborting before `applicationShouldTerminate`
/// is ever asked, so menu Quit, ⌘Q and the quit Apple event all fail with a beep. Every sheet
/// in this app is work-free, so `terminate(_:)` ends the attached sheets first (innermost
/// first, on every window) and then hands the quit to `super`, which runs the ordinary
/// orderly-exit path: the delegate's default `NSTerminateNow`, `willTerminateNotification`,
/// the embedded core's SIGTERM, and the core's system-proxy restore.
@objc(AitmApplication) final class AitmApplication: NSApplication {
    /// Ends every attached sheet, innermost first, then always calls `super.terminate(_:)`.
    /// The walk runs before `super` because AppKit's modal-sheet check runs before the
    /// delegate is asked. It is bounded by the window count at entry so it finishes even if
    /// `endSheet(_:)` fails to detach a sheet; `super` then refuses exactly as before.
    override func terminate(_ sender: Any?) {
        var remaining = windows.count
        while remaining > 0,
            let innermost = windows.first(where: { $0.sheetParent != nil && $0.attachedSheet == nil }),
            let parent = innermost.sheetParent
        {
            parent.endSheet(innermost)
            remaining -= 1
        }
        super.terminate(sender)
    }
}
