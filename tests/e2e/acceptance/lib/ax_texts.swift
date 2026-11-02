// ax_texts.swift — fast accessibility text dump of the INSTALLED Aitmproxy app's main window.
//
// Same rows as the AppleScript body of ax_texts.sh (role, title, value, description; text fields
// add identifier, "x,y", "w,h"), but through the AXUIElement C API: one in-process call per
// attribute instead of one Apple Event per attribute through osascript. On an idle 0.5.15 the
// AppleScript walk took 49.7 s for 142 rows (the ~30 s harness budget is the AppleScript floor,
// not the app); this walk finishes in well under a second.
//
// Read-only: no click, no keystroke, no focus change. Needs Accessibility permission for the
// terminal that runs it, the same as osascript did.
//
// Build (ax_texts.sh does this on first use):  swiftc -O -o <cache>/ax_texts ax_texts.swift
// Usage:  ax_texts [pid]   — pid defaults to the single installed Aitmproxy process.
import AppKit
import ApplicationServices
import Foundation

let wanted: Set<String> = ["AXStaticText", "AXButton", "AXCheckBox", "AXTextField", "AXPopUpButton"]

func attr(_ el: AXUIElement, _ name: String) -> CFTypeRef? {
    var value: CFTypeRef?
    let err = AXUIElementCopyAttributeValue(el, name as CFString, &value)
    return err == .success ? value : nil
}

func text(_ el: AXUIElement, _ name: String) -> String {
    guard let v = attr(el, name) else { return "" }
    if let s = v as? String { return s }
    if let n = v as? NSNumber { return n.stringValue }
    if let a = v as? NSAttributedString { return a.string }
    return ""
}

func point(_ el: AXUIElement, _ name: String) -> (Int, Int)? {
    guard let v = attr(el, name), CFGetTypeID(v) == AXValueGetTypeID() else { return nil }
    let ax = v as! AXValue
    if AXValueGetType(ax) == .cgPoint {
        var p = CGPoint.zero
        if AXValueGetValue(ax, .cgPoint, &p) { return (Int(p.x.rounded()), Int(p.y.rounded())) }
    } else if AXValueGetType(ax) == .cgSize {
        var s = CGSize.zero
        if AXValueGetValue(ax, .cgSize, &s) { return (Int(s.width.rounded()), Int(s.height.rounded())) }
    }
    return nil
}

func children(_ el: AXUIElement) -> [AXUIElement] {
    guard let v = attr(el, kAXChildrenAttribute as String) else { return [] }
    return (v as? [AXUIElement]) ?? []
}

// Depth-first walk in the same order `entire contents` yields (parent before children).
var visited = Set<AXUIElement>()
var truncated = false
func walk(_ el: AXUIElement, _ out: inout [String], _ seen: inout Int) {
    if visited.contains(el) { return } // a cyclic tree never repeats a row
    visited.insert(el)
    seen += 1
    if seen > 20_000 { truncated = true; return } // size cap, reported on stderr below
    let role = text(el, kAXRoleAttribute as String)
    if wanted.contains(role) {
        // Same columns as the AppleScript walk: an unset title/value prints "missing value" and an
        // unset description falls back to the role description ("button", "text field", …). Known
        // difference, recorded in the acceptance spec's Review log: where the app sets a button's
        // AXDescription the C API returns it while System Events rendered "button".
        var title = text(el, kAXTitleAttribute as String)
        var value = text(el, kAXValueAttribute as String)
        var desc = text(el, kAXDescriptionAttribute as String)
        if title.isEmpty { title = "missing value" }
        if value.isEmpty { value = "missing value" }
        if desc.isEmpty { desc = text(el, kAXRoleDescriptionAttribute as String) }
        if desc.isEmpty { desc = "missing value" }
        var row = [role, title, value, desc].joined(separator: "\t")
        if role == "AXTextField" {
            let ident = text(el, kAXIdentifierAttribute as String)
            let p = point(el, kAXPositionAttribute as String) ?? (0, 0)
            let s = point(el, kAXSizeAttribute as String) ?? (0, 0)
            row += "\t\(ident)\t\(p.0),\(p.1)\t\(s.0),\(s.1)"
        }
        // The row format is positional: separators must not appear inside a cell.
        let flat = row.replacingOccurrences(of: "\r\n", with: " ").replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
        let cols = flat.split(separator: "\t", omittingEmptySubsequences: false)
        out.append(cols.map { $0.replacingOccurrences(of: "\t", with: " ") }.joined(separator: "\t"))
    }
    for c in children(el) { walk(c, &out, &seen) }
}

func installedPid() -> pid_t? {
    let apps = NSWorkspace.shared.runningApplications.filter {
        $0.bundleURL?.path == "/Applications/Aitmproxy.app"
    }
    guard apps.count == 1 else {
        FileHandle.standardError.write("refused: expected exactly one installed Aitmproxy process, found \(apps.count)\n".data(using: .utf8)!)
        return nil
    }
    return apps[0].processIdentifier
}

let args = CommandLine.arguments
let pid: pid_t
if args.count > 1 {
    guard let p = Int32(args[1]) else {
        FileHandle.standardError.write("refused: pid argument is not a number: \(args[1])\n".data(using: .utf8)!)
        exit(2)
    }
    pid = p
} else if let p = installedPid() {
    pid = p
} else {
    exit(3)
}

guard AXIsProcessTrusted() else {
    FileHandle.standardError.write("refused: this terminal lacks Accessibility permission (System Settings ▸ Privacy & Security ▸ Accessibility)\n".data(using: .utf8)!)
    exit(4)
}

let app = AXUIElementCreateApplication(pid)
// A hung main thread must fail fast (the cell's budget is 30 s), not block per attribute for seconds.
AXUIElementSetMessagingTimeout(app, 2)
guard let windows = attr(app, kAXWindowsAttribute as String) as? [AXUIElement], let window = windows.first else {
    FileHandle.standardError.write("refused: the app has no window\n".data(using: .utf8)!)
    exit(5)
}
var rows: [String] = []
var seen = 0
walk(window, &rows, &seen)
if truncated { FileHandle.standardError.write("ax_texts: truncated after \(seen) elements\n".data(using: .utf8)!) }
print(rows.joined(separator: "\n"))
