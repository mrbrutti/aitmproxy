// ax_focus.swift — give keyboard focus to one UI element of the INSTALLED Aitmproxy app's main window
// (or its sheets) by accessibility identifier, through the AXUIElement API: AXFocused := true.
//
// Why: System Events' `click at {x, y}` does not land on a window that sits at negative screen
// coordinates (a main window on an upper display), and a point read a moment earlier can be stale;
// the element itself is unambiguous. This is the harness's ONE write to the app's UI state besides
// typing: it raises window 1, activates the app (the same frontmost step menu.sh/click.sh take) and
// sets AXFocused on the element — no value, no other action.
//
// Build (ax_focus.sh does this on first use):  swiftc -O -o <cache>/ax_focus ax_focus.swift
// Usage:  ax_focus <identifier>   — prints "focused <identifier>" on success.
// Exit codes: 2 bad args, 3 app not running / ambiguous, 4 no Accessibility permission,
//             5 no window, 6 element not found, 7 focus refused by the app.
import AppKit
import ApplicationServices
import Foundation

func attr(_ el: AXUIElement, _ name: String) -> CFTypeRef? {
    var value: CFTypeRef?
    return AXUIElementCopyAttributeValue(el, name as CFString, &value) == .success ? value : nil
}

func children(_ el: AXUIElement) -> [AXUIElement] {
    (attr(el, kAXChildrenAttribute as String) as? [AXUIElement]) ?? []
}

var visited = Set<AXUIElement>()
func find(_ el: AXUIElement, _ ident: String, _ depth: Int = 0) -> AXUIElement? {
    if visited.contains(el) || depth > 60 { return nil }
    visited.insert(el)
    if let v = attr(el, kAXIdentifierAttribute as String) as? String, v == ident { return el }
    for c in children(el) { if let hit = find(c, ident, depth + 1) { return hit } }
    return nil
}

func fail(_ code: Int32, _ msg: String) -> Never {
    FileHandle.standardError.write("refused: \(msg)\n".data(using: .utf8)!)
    exit(code)
}

let args = CommandLine.arguments
guard args.count == 2, !args[1].isEmpty else { fail(2, "usage: ax_focus <identifier>") }
let ident = args[1]
let apps = NSWorkspace.shared.runningApplications.filter { $0.bundleURL?.path == "/Applications/Aitmproxy.app" }
guard apps.count == 1 else { fail(3, "expected exactly one installed Aitmproxy process, found \(apps.count)") }
let pid = apps[0].processIdentifier
guard AXIsProcessTrusted() else { fail(4, "this terminal lacks Accessibility permission (System Settings ▸ Privacy & Security ▸ Accessibility)") }

let app = AXUIElementCreateApplication(pid)
AXUIElementSetMessagingTimeout(app, 2)
guard let windows = attr(app, kAXWindowsAttribute as String) as? [AXUIElement], let window = windows.first else { fail(5, "the app has no window") }
// Sheets hang off the window; `find` walks them as children, so one search covers page and sheet.
guard let target = find(window, ident) else { fail(6, "no element with identifier \(ident) in window 1 (or its sheets)") }
// Bring the window forward so the focus is a real keyboard focus, then set AXFocused.
_ = AXUIElementPerformAction(window, kAXRaiseAction as CFString)
NSRunningApplication(processIdentifier: pid)?.activate(options: [])
usleep(200_000)
let err = AXUIElementSetAttributeValue(target, kAXFocusedAttribute as CFString, kCFBooleanTrue)
usleep(200_000)
let focused = (attr(target, kAXFocusedAttribute as String) as? Bool) ?? false
if err == .success && focused {
    print("focused \(ident)")
} else {
    fail(7, "the app did not accept keyboard focus for \(ident) (set err \(err.rawValue), read-back \(focused))")
}
