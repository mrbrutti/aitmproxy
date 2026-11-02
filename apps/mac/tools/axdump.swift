import ApplicationServices
import Cocoa

// Dump one app window's accessibility tree as TSV, natively (computer-use reads for the live
// checks; an AppleScript `entire contents` walk of the same window takes minutes).
//   swift axdump.swift <pid> [--sheet] [--roles AXStaticText,AXButton,...]
// The window: the first AXWindow of the app that is main, else the AXWindow with the largest
// area — never a help tag (tooltip) or a sheet. `--sheet` dumps that window's sheets instead (a
// confirm dialog). The choice is logged on stderr as `window: <title> <x y w h>`.
// One line per element, tab-separated:
//   ROLE  TITLE  VALUE  DESC  PLACEHOLDER  ENABLED  X  Y  W  H  IDENTIFIER
// Empty for a missing attribute. Text cells are cleaned at the Unicode-scalar level: whitespace
// and line breaks become one space, other control characters (< U+0020, U+007F, U+0080–U+009F,
// U+2028, U+2029) are dropped, then the cell is cut at 200 scalars. X Y W H are global screen
// points (kAXPosition/kAXSize), the space cgclick.swift posts in. IDENTIFIER is SwiftUI's
// accessibilityIdentifier (AXIdentifier). Depth-first in document order through
// kAXChildrenAttribute, capped at 20 000 elements; the root is the first line. Every element
// costs one AX round trip (AXUIElementCopyMultipleAttributeValues for all attributes and the
// children at once; messaging timeout 2 s). `--roles` filters the output lines only; the
// traversal stays complete. Exit 1 with a message when accessibility is denied
// (AXIsProcessTrusted false) or the app has no window / no sheet.
let args = Array(CommandLine.arguments.dropFirst())
func die(_ message: String, _ code: Int32) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}
func note(_ message: String) { FileHandle.standardError.write(Data((message + "\n").utf8)) }
guard let first = args.first, let pid = Int32(first) else {
    die("usage: axdump.swift <pid> [--sheet] [--roles AXRole,AXRole,...]", 2)
}
var sheetMode = false
var roleFilter: Set<String>? = nil
var i = 1
while i < args.count {
    switch args[i] {
    case "--sheet": sheetMode = true
    case "--roles":
        i += 1
        guard i < args.count else { die("--roles needs a comma-separated list of AX roles", 2) }
        roleFilter = Set(args[i].split(separator: ",").map { String($0) }.filter { !$0.isEmpty })
    default: die("unknown argument \(args[i]) (usage: axdump.swift <pid> [--sheet] [--roles ...])", 2)
    }
    i += 1
}
let maxElements = 20_000

guard AXIsProcessTrusted() else {
    die("accessibility denied: AXIsProcessTrusted false (grant the terminal running swift in System Settings ▸ Privacy & Security ▸ Accessibility)", 1)
}
let app = AXUIElementCreateApplication(pid)
AXUIElementSetMessagingTimeout(app, 2)

// MARK: attribute reads

func attribute(_ element: AXUIElement, _ name: String) -> AnyObject? {
    var ref: CFTypeRef?
    guard AXUIElementCopyAttributeValue(element, name as CFString, &ref) == .success else { return nil }
    return ref
}
/// All of `names` in one round trip; a missing attribute comes back as nil.
func attributes(_ element: AXUIElement, _ names: [String]) -> [AnyObject?] {
    var values: CFArray?
    let err = AXUIElementCopyMultipleAttributeValues(element, names as CFArray, AXCopyMultipleAttributeOptions(rawValue: 0), &values)
    guard err == .success, let list = values as? [AnyObject], list.count == names.count else {
        return Array(repeating: nil, count: names.count)
    }
    return list.map { value in
        // With no options, an attribute the element lacks is an AXValue of the error type.
        if CFGetTypeID(value) == AXValueGetTypeID(), AXValueGetType(value as! AXValue) == .axError { return nil }
        return value
    }
}
func elements(_ value: AnyObject?) -> [AXUIElement] {
    guard let array = value as? [AnyObject] else { return [] }
    return array.compactMap { CFGetTypeID($0) == AXUIElementGetTypeID() ? ($0 as! AXUIElement) : nil }
}
func point(_ value: AnyObject?) -> CGPoint? {
    guard let value, CFGetTypeID(value) == AXValueGetTypeID() else { return nil }
    var p = CGPoint.zero
    return AXValueGetValue(value as! AXValue, .cgPoint, &p) ? p : nil
}
func size(_ value: AnyObject?) -> CGSize? {
    guard let value, CFGetTypeID(value) == AXValueGetTypeID() else { return nil }
    var s = CGSize.zero
    return AXValueGetValue(value as! AXValue, .cgSize, &s) ? s : nil
}
func isTrue(_ value: AnyObject?) -> Bool {
    guard let value else { return false }
    if CFGetTypeID(value) == CFBooleanGetTypeID() { return CFBooleanGetValue((value as! CFBoolean)) }
    return (value as? NSNumber)?.boolValue ?? false
}
/// One clean TSV cell: control characters out, line breaks to spaces, 200 scalars at most.
func clean(_ raw: String) -> String {
    var scalars = String.UnicodeScalarView()
    for scalar in raw.unicodeScalars {
        let v = scalar.value
        if scalar.properties.isWhitespace || v == 0x2028 || v == 0x2029 {
            scalars.append(" ")
        } else if v < 0x20 || v == 0x7f || (0x80...0x9f).contains(v) {
            continue
        } else {
            scalars.append(scalar)
        }
        if scalars.count >= 200 { break }
    }
    return String(scalars)
}
/// Any attribute as one clean text cell.
func text(_ value: AnyObject?) -> String {
    guard let value else { return "" }
    let s: String
    if CFGetTypeID(value) == CFBooleanGetTypeID() {
        s = CFBooleanGetValue((value as! CFBoolean)) ? "true" : "false"
    } else if let str = value as? String {
        s = str
    } else if let attributed = value as? NSAttributedString {
        s = attributed.string
    } else if let number = value as? NSNumber {
        s = number.stringValue
    } else if let url = value as? URL {
        s = url.absoluteString
    } else if let p = point(value) {
        s = "\(Int(p.x)) \(Int(p.y))"
    } else if let z = size(value) {
        s = "\(Int(z.width)) \(Int(z.height))"
    } else if CFGetTypeID(value) == AXUIElementGetTypeID() {
        s = "<element>"
    } else if let array = value as? [AnyObject] {
        s = "<\(array.count) items>"
    } else {
        s = String(describing: value)
    }
    return clean(s)
}
func number(_ value: Double) -> String { String(Int(value.rounded())) }
func frame(_ element: AXUIElement) -> CGRect? {
    let read = attributes(element, [kAXPositionAttribute as String, kAXSizeAttribute as String])
    guard let p = point(read[0]), let z = size(read[1]) else { return nil }
    return CGRect(origin: p, size: z)
}

// MARK: the window

let windows = elements(attribute(app, kAXWindowsAttribute as String))
guard !windows.isEmpty else { die("no window for pid \(pid) (not running, no window yet, or not an AX client)", 1) }
var chosen: AXUIElement? = nil
var chosenFrame = CGRect.zero
var chosenTitle = ""
var largest: (AXUIElement, CGRect, String)? = nil
for window in windows {
    let read = attributes(window, [kAXRoleAttribute as String, kAXMainAttribute as String, kAXTitleAttribute as String])
    guard text(read[0]) == "AXWindow" else { continue }  // never a help tag, popover or sheet
    let rect = frame(window) ?? .zero
    let title = text(read[2])
    if isTrue(read[1]) { chosen = window; chosenFrame = rect; chosenTitle = title; break }
    if largest == nil || rect.width * rect.height > largest!.1.width * largest!.1.height { largest = (window, rect, title) }
}
if chosen == nil, let largest { chosen = largest.0; chosenFrame = largest.1; chosenTitle = largest.2 }
guard let window = chosen else { die("no AXWindow among the \(windows.count) windows of pid \(pid) (only help tags or sheets)", 1) }
note("window: \(chosenTitle.isEmpty ? "(untitled)" : chosenTitle) \(number(chosenFrame.minX)) \(number(chosenFrame.minY)) \(number(chosenFrame.width)) \(number(chosenFrame.height))")

let roots: [AXUIElement]
if sheetMode {
    roots = elements(attribute(window, "AXSheets"))  // no kAXSheetsAttribute constant; the name is AXSheets
    guard !roots.isEmpty else { die("no sheet on the window of pid \(pid)", 1) }
} else {
    roots = [window]
}

// MARK: the walk — one round trip per element

let names: [String] = [
    kAXRoleAttribute as String, kAXTitleAttribute as String, kAXValueAttribute as String,
    kAXDescriptionAttribute as String, kAXPlaceholderValueAttribute as String, kAXEnabledAttribute as String,
    kAXPositionAttribute as String, kAXSizeAttribute as String, kAXIdentifierAttribute as String,
    kAXChildrenAttribute as String,
]
var out = ""
out.reserveCapacity(1 << 17)
var count = 0
var stack: [AXUIElement] = roots.reversed()
while let element = stack.popLast(), count < maxElements {
    count += 1
    let read = attributes(element, names)
    let role = text(read[0])
    let p: CGPoint? = point(read[6])
    let z: CGSize? = size(read[7])
    if roleFilter == nil || roleFilter!.contains(role) {
        var cells: [String] = [role, text(read[1]), text(read[2]), text(read[3]), text(read[4]), text(read[5])]
        cells.append(p.map { number($0.x) } ?? "")
        cells.append(p.map { number($0.y) } ?? "")
        cells.append(z.map { number($0.width) } ?? "")
        cells.append(z.map { number($0.height) } ?? "")
        cells.append(text(read[8]))
        out += cells.joined(separator: "\t")
        out += "\n"
    }
    // Depth-first in document order: push children reversed so the first child pops first.
    for child in elements(read[9]).reversed() { stack.append(child) }
}
FileHandle.standardOutput.write(Data(out.utf8))
if count >= maxElements { note("axdump: stopped at the \(maxElements)-element cap") }
exit(0)
