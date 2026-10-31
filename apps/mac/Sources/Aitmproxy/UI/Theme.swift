import AppKit
import Observation
import SwiftUI

/// The accent (foundation §2.10a): follows the Mac's accent colour; while
/// that is Multicolor, the brand blue from tokens.json (`color.accent`).
/// Light and dark mode follow the Mac. The data hues (method, status,
/// intercept, agent, syntax) are fixed tokens and never follow the accent.
///   APP_ACCENT=brand Aitmproxy     force the brand blue, to compare
struct Theme: Identifiable, Hashable {
    struct Shades: Hashable {
        let light: UInt32
        let base: UInt32
        let deep: UInt32
    }

    let id: String
    let name: String
    /// nil follows the accent color in System Settings.
    let shades: Shades?
    var darkText = false

    /// For `.tint`. nil keeps the system accent.
    var tint: Color? { shades.map { Color(hex: $0.base) } }
    /// The flat accent color.
    var accent: Color { tint ?? .accentColor }
    /// Accent-colored text on a plain or tinted background: deep in light mode, light in dark mode.
    var accentText: Color { shades.map { Color(light: $0.deep, dark: $0.light) } ?? .accentColor }
    /// Text and symbols on an accent fill.
    var onAccent: Color { darkText ? Color(hex: 0x16161C) : .white }

    static let brand = Theme(
        id: "brand", name: "aitmproxy blue",
        shades: .init(light: Tok.Accent.base.dark, base: Tok.Accent.base.light, deep: Tok.Accent.deep.light))

    static let all: [Theme] = [
        Theme(id: "system", name: "System", shades: nil),
        brand,
    ]
}

/// The chosen accent, saved in UserDefaults.
@Observable
final class ThemeStore {
    static let shared = ThemeStore()

    /// Keep "system": the app follows the accent people chose for their Mac (HIG).
    static let defaultID = "system"

    /// The brand shows only while the Mac's accent is Multicolor, as in Apple's own apps.
    static let brand: Theme? = Theme.brand

    var themeID: String {
        didSet { if !Store.isOverridden { UserDefaults.standard.set(themeID, forKey: "appearance.accent") } }
    }

    /// True while the Mac's accent is Multicolor.
    private(set) var macIsMulticolor = ThemeStore.readMulticolor()

    var theme: Theme {
        let chosen = Theme.all.first { $0.id == themeID } ?? Theme.all[0]
        if chosen.id == "system", macIsMulticolor, let brand = Self.brand {
            return Theme(id: "system", name: "System", shades: brand.shades, darkText: brand.darkText)
        }
        return chosen
    }

    private init() {
        // APP_ACCENT picks the accent for a run; otherwise the operator's choice, except in a
        // snapshot, self-test or fixture run (`Store.isOverridden`), which shows the default
        // so a harness never inherits the operator's accent.
        themeID = ProcessInfo.processInfo.environment["APP_ACCENT"]
            ?? (Store.isOverridden ? Self.defaultID : UserDefaults.standard.string(forKey: "appearance.accent") ?? Self.defaultID)
        NotificationCenter.default.addObserver(forName: NSColor.systemColorsDidChangeNotification,
                                               object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.macIsMulticolor = ThemeStore.readMulticolor() }
        }
    }

    /// The Mac stores no accent number while the accent is Multicolor.
    private static func readMulticolor() -> Bool {
        UserDefaults.standard.object(forKey: "AppleAccentColor") == nil
    }
}

/// Accent tokens for views. Never hard-code an accent hex in a view.
enum Palette {
    static var accent: Color { ThemeStore.shared.theme.accent }
    static var accentText: Color { ThemeStore.shared.theme.accentText }
    static var onAccent: Color { ThemeStore.shared.theme.onAccent }
}

extension View {
    /// Applies the chosen accent to everything below. Put it on every scene's root.
    func themed() -> some View {
        modifier(Themed())
    }
}

private struct Themed: ViewModifier {
    private var store = ThemeStore.shared

    func body(content: Content) -> some View {
        content.tint(store.theme.tint)
    }
}

extension Color {
    init(hex: UInt32) {
        self.init(nsColor: NSColor(hex: hex))
    }

    /// A color with a light and a dark value: Color(light: 0x0064D2, dark: 0x7CC0FF).
    init(light: UInt32, dark: UInt32, highContrastLight: UInt32? = nil, highContrastDark: UInt32? = nil) {
        self.init(nsColor: NSColor.dynamic(light: light, dark: dark, highContrastLight: highContrastLight,
                                           highContrastDark: highContrastDark))
    }
}

extension NSColor {
    convenience init(hex: UInt32) {
        self.init(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
                  green: CGFloat((hex >> 8) & 0xFF) / 255,
                  blue: CGFloat(hex & 0xFF) / 255,
                  alpha: 1)
    }

    /// A dynamic colour that resolves per appearance, for AppKit views and `Color(nsColor:)`.
    /// The Increase-Contrast values default to the normal ones.
    static func dynamic(light: UInt32, dark: UInt32, highContrastLight: UInt32? = nil,
                        highContrastDark: UInt32? = nil) -> NSColor {
        NSColor(name: nil) { appearance in
            switch appearance.bestMatch(from: [.aqua, .darkAqua, .accessibilityHighContrastAqua,
                                               .accessibilityHighContrastDarkAqua]) {
            case .darkAqua: NSColor(hex: dark)
            case .accessibilityHighContrastAqua: NSColor(hex: highContrastLight ?? light)
            case .accessibilityHighContrastDarkAqua: NSColor(hex: highContrastDark ?? dark)
            default: NSColor(hex: light)
            }
        }
    }
}
