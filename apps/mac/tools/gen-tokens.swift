#!/usr/bin/env swift
// Generates Sources/Aitmproxy/UI/Tokens.swift from docs/design/tokens.json,
// the single source of truth shared with the web and terminal UIs.
//   swift tools/gen-tokens.swift            (from apps/mac)
//   swift tools/gen-tokens.swift <tokens.json> <Tokens.swift>
// Colours become `DynamicColor` (light + dark, SwiftUI and AppKit), method /
// severity / diff colours become `ColorPair` (fg + bg), dimensions CGFloat,
// durations seconds, curves Animation helpers and CAMediaTimingFunctions, icon roles SF Symbol names.
import Foundation

let here = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
let packageRoot = here.deletingLastPathComponent()
let inputPath = CommandLine.arguments.count > 1 ? CommandLine.arguments[1]
    : packageRoot.appending(path: "../../docs/design/tokens.json").standardized.path
let outputPath = CommandLine.arguments.count > 2 ? CommandLine.arguments[2]
    : packageRoot.appending(path: "Sources/Aitmproxy/UI/Tokens.swift").path

guard let data = FileManager.default.contents(atPath: inputPath),
      let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
    FileHandle.standardError.write("cannot read \(inputPath)\n".data(using: .utf8)!)
    exit(1)
}

var out = ""
func line(_ s: String = "", _ depth: Int = 0) { out += String(repeating: "    ", count: depth) + s + "\n" }

/// JSON keys are camelCase already; a numeric key gets a letter prefix.
func ident(_ key: String) -> String {
    if let first = key.first, first.isNumber { return "s\(key)" }
    let reserved = ["default", "repeat", "in", "as", "is", "func", "var", "let", "class", "enum", "struct"]
    return reserved.contains(key) ? "`\(key)`" : key
}
func typeName(_ key: String) -> String {
    // `text` would shadow SwiftUI.Text at every call site; the tier is called Ink.
    let renamed = ["text": "Ink"]
    let k = renamed[key] ?? key
    return k.prefix(1).uppercased() + k.dropFirst()
}
func hex(_ s: String) -> String { "0x" + s.trimmingCharacters(in: CharacterSet(charactersIn: "#")).uppercased() }
func points(_ s: String) -> String { s.replacingOccurrences(of: "px", with: "") }
func seconds(_ s: String) -> String {
    let ms = Double(s.replacingOccurrences(of: "ms", with: "")) ?? 0
    return String(format: "%.3f", ms / 1000)
}
func weight(_ n: Int) -> String {
    switch n {
    case ..<450: ".regular"
    case ..<550: ".medium"
    case ..<650: ".semibold"
    default: ".bold"
    }
}

/// One colour token: "#RRGGBB" pair, or a {fg,bg} pair per mode.
func emitColor(_ name: String, _ value: Any, _ description: String?, _ depth: Int) {
    if let d = description, !d.isEmpty { line("/// \(d)", depth) }
    guard let modes = value as? [String: Any],
          let light = modes["light"], let dark = modes["dark"] else { return }
    if let l = light as? String, let d = dark as? String {
        // Optional Increase-Contrast overrides (nil falls back to light/dark).
        let hcl = (modes["highContrastLight"] as? String).map { ", highContrastLight: \(hex($0))" } ?? ""
        let hcd = (modes["highContrastDark"] as? String).map { ", highContrastDark: \(hex($0))" } ?? ""
        line("static let \(ident(name)) = DynamicColor(light: \(hex(l)), dark: \(hex(d))\(hcl)\(hcd))", depth)
    } else if let l = light as? [String: String], let d = dark as? [String: String],
              let lf = l["fg"], let lb = l["bg"], let df = d["fg"], let db = d["bg"] {
        line("static let \(ident(name)) = ColorPair(", depth)
        line("fg: DynamicColor(light: \(hex(lf)), dark: \(hex(df))),", depth + 1)
        line("bg: DynamicColor(light: \(hex(lb)), dark: \(hex(db))))", depth + 1)
    }
}

/// Walks a token group. A node with `$type` is a leaf; anything else nests.
func emitGroup(_ name: String, _ node: [String: Any], _ depth: Int) {
    if let d = node["$description"] as? String { line("/// \(d.split(separator: ".").first.map(String.init) ?? d).", depth) }
    line("enum \(typeName(name)) {", depth)
    for key in node.keys.sorted() where !key.hasPrefix("$") {
        guard let child = node[key] as? [String: Any] else { continue }
        if let type = child["$type"] as? String {
            emitLeaf(key, type, child, depth + 1)
        } else if name == "glyph" {
            // icon.glyph.<role>: {mac, web, tui}; macOS reads the SF Symbol.
            if let mac = child["mac"] as? String {
                line("static let \(ident(key)) = \"\(mac)\"", depth + 1)
            }
        } else {
            emitGroup(key, child, depth + 1)
        }
    }
    line("}", depth)
}

func emitLeaf(_ key: String, _ type: String, _ node: [String: Any], _ depth: Int) {
    let description = node["$description"] as? String
    let value = node["$value"]
    func doc() { if let d = description, !d.isEmpty { line("/// \(d)", depth) } }
    switch type {
    case "color":
        emitColor(key, value as Any, description, depth)
    case "dimension":
        doc()
        if let v = value as? String { line("static let \(ident(key)): CGFloat = \(points(v))", depth) }
        for extra in ["min", "max", "inline", "toolbar"] {
            if let v = node[extra] as? String {
                line("static let \(ident(key))\(typeName(extra)): CGFloat = \(points(v))", depth)
            }
        }
    case "fontWeight":
        doc()
        if let v = value as? Int { line("static let \(ident(key)): Font.Weight = \(weight(v))", depth) }
    case "number":
        doc()
        if let v = value as? Double { line("static let \(ident(key)): CGFloat = \(v)", depth) }
    case "duration":
        doc()
        if let v = value as? String { line("static let \(ident(key)): Double = \(seconds(v))", depth) }
    case "cubicBezier":
        doc()
        if let v = value as? [Double], v.count == 4 {
            line("static func \(ident(key))(_ duration: Double) -> Animation {", depth)
            line("Animation.timingCurve(\(v[0]), \(v[1]), \(v[2]), \(v[3]), duration: duration)", depth + 1)
            line("}", depth)
            // The same curve for Core Animation. A computed property rather than a stored static:
            // CAMediaTimingFunction is not Sendable, so this does not lean on the app target's
            // MainActor default isolation to be concurrency-safe.
            line("static var \(ident(key))Timing: CAMediaTimingFunction {", depth)
            line("CAMediaTimingFunction(controlPoints: \(v[0]), \(v[1]), \(v[2]), \(v[3]))", depth + 1)
            line("}", depth)
        }
    case "string":
        doc()
        if let v = value as? String { line("static let \(ident(key)) = \"\(v)\"", depth) }
    case "shadow":
        doc()
        // "0 8px 24px rgba(...)": the first layer's offset and blur; opacity per mode.
        if let modes = value as? [String: String], let light = modes["light"], let dark = modes["dark"] {
            func parse(_ s: String) -> (y: String, blur: String, alpha: String) {
                let parts = s.split(separator: ",")[0].split(separator: " ")
                let alpha = s.split(separator: ",").dropFirst(3).first.map { $0.trimmingCharacters(in: CharacterSet(charactersIn: ") ")) } ?? "0.1"
                return (points(String(parts[1])), points(String(parts[2])), alpha)
            }
            let l = parse(light), d = parse(dark)
            line("static let \(ident(key)) = FloatingShadow(y: \(l.y), radius: \(l.blur) / 2, lightOpacity: \(l.alpha), darkOpacity: \(d.alpha))", depth)
        }
    case "fontFamily":
        break // SF Pro / SF Mono come from Font.system(design:).
    default:
        break
    }
}

line("// Generated from docs/design/tokens.json by tools/gen-tokens.swift. Do not edit.")
line("// Version \(root["$version"] as? String ?? "?"). The names mirror the JSON; see")
line("// docs/design/operator-ui-foundation.md §2 for which token goes where.")
line("import AppKit")
line("import SwiftUI")
line()
line("/// A colour with a light and a dark value, for SwiftUI views and AppKit cells alike.")
line("struct DynamicColor: Hashable, Sendable {")
line("let light: UInt32", 1)
line("let dark: UInt32", 1)
line("/// Increase-Contrast overrides; nil falls back to light/dark.", 1)
line("var highContrastLight: UInt32? = nil", 1)
line("var highContrastDark: UInt32? = nil", 1)
line("var nsColor: NSColor { NSColor.dynamic(light: light, dark: dark, highContrastLight: highContrastLight, highContrastDark: highContrastDark) }", 1)
line("var color: Color { Color(nsColor: nsColor) }", 1)
line("}")
line()
line("/// Badge colours: deep text on a tint background.")
line("struct ColorPair: Hashable, Sendable {")
line("let fg: DynamicColor", 1)
line("let bg: DynamicColor", 1)
line("}")
line()
line("/// A floating shadow (menus, popovers, the palette, sheets). Resting panels get none.")
line("struct FloatingShadow: Hashable, Sendable {")
line("let y: CGFloat", 1)
line("let radius: CGFloat", 1)
line("let lightOpacity: Double", 1)
line("let darkOpacity: Double", 1)
line("}")
line()
line("enum Tok {")
let order = ["color", "typography", "space", "size", "radius", "shadow", "motion", "icon"]
for key in order {
    guard let node = root[key] as? [String: Any] else { continue }
    if key == "color" {
        // The colour groups sit directly under Tok (Tok.Ground.page, Tok.Method.get).
        for sub in node.keys.sorted() where !sub.hasPrefix("$") {
            if let child = node[sub] as? [String: Any] { emitGroup(sub, child, 1) }
        }
    } else if key == "icon" {
        if let glyph = node["glyph"] as? [String: Any] {
            line("/// SF Symbol per icon role (`icon.glyph.*.mac`).", 1)
            emitGroup("glyph", glyph, 1)
        }
    } else {
        emitGroup(key, node, 1)
    }
}
line("}")

do {
    try out.write(toFile: outputPath, atomically: false, encoding: .utf8)
    print("wrote \(outputPath)")
} catch {
    FileHandle.standardError.write("cannot write \(outputPath): \(error)\n".data(using: .utf8)!)
    exit(1)
}
