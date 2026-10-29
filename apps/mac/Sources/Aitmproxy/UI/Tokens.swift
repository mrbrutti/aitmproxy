// Generated from docs/design/tokens.json by tools/gen-tokens.swift. Do not edit.
// Version 0.1.0. The names mirror the JSON; see
// docs/design/operator-ui-foundation.md §2 for which token goes where.
import AppKit
import SwiftUI

/// A colour with a light and a dark value, for SwiftUI views and AppKit cells alike.
struct DynamicColor: Hashable, Sendable {
    let light: UInt32
    let dark: UInt32
    var nsColor: NSColor { NSColor.dynamic(light: light, dark: dark) }
    var color: Color { Color(nsColor: nsColor) }
}

/// Badge colours: deep text on a tint background.
struct ColorPair: Hashable, Sendable {
    let fg: DynamicColor
    let bg: DynamicColor
}

/// A floating shadow (menus, popovers, the palette, sheets). Resting panels get none.
struct FloatingShadow: Hashable, Sendable {
    let y: CGFloat
    let radius: CGFloat
    let lightOpacity: Double
    let darkOpacity: Double
}

enum Tok {
    enum Accent {
        /// THE accent: active tab underline, focus ring, selection tint source, primary links, the product mark. Taken from Proxyman WebUI's active-tab blue. Budget: about 3% of pixels.
        static let base = DynamicColor(light: 0x2563EB, dark: 0x60A5FA)
        /// Accent text on light surfaces / pressed state.
        static let deep = DynamicColor(light: 0x1D4ED8, dark: 0x3B82F6)
        /// Accent wash: selected row, GET badge background.
        static let tint = DynamicColor(light: 0xDBEAFE, dark: 0x1E2A44)
    }
    /// The AI agent's presence over MCP.
    enum Agent {
        static let base = DynamicColor(light: 0x0D9488, dark: 0x2DD4BF)
        static let deep = DynamicColor(light: 0x0F766E, dark: 0x5EEAD4)
        static let tint = DynamicColor(light: 0xCCFBF1, dark: 0x113A36)
    }
    enum Ground {
        /// Selected row in a list that drives a detail pane; selected sidebar item. A quiet accent tint, never the full accent.
        static let active = DynamicColor(light: 0xE8EEFB, dark: 0x2B3344)
        /// Row/item hover. Never moves a selection.
        static let hover = DynamicColor(light: 0xF3F4F6, dark: 0x232325)
        /// Near-black primary button fill (light) / inverted white (dark).
        static let inverse = DynamicColor(light: 0x1D1F20, dark: 0xF5F5F7)
        /// Window/page background behind panels (WebUI off-white; native near-black).
        static let page = DynamicColor(light: 0xF7F8FA, dark: 0x161618)
        /// Chips, inset wells, the status bar, sidebar group headers.
        static let raised = DynamicColor(light: 0xF3F4F6, dark: 0x262628)
        /// Panels, the flow table, inspector panes.
        static let surface = DynamicColor(light: 0xFFFFFF, dark: 0x1E1E20)
    }
    /// The breakpoint/intercept state.
    enum Intercept {
        static let base = DynamicColor(light: 0xD97706, dark: 0xF5A524)
        static let deep = DynamicColor(light: 0xB45309, dark: 0xFBBF24)
        static let onBase = DynamicColor(light: 0x1F1300, dark: 0x1F1300)
        static let tint = DynamicColor(light: 0xFEF3C7, dark: 0x3A2E12)
    }
    enum Line {
        /// Panel edges, pane splitters, the rule under tab bars.
        static let border = DynamicColor(light: 0xE5E7EB, dark: 0x2E2E31)
        /// Input, select and outlined-button borders; one step darker than border.
        static let control = DynamicColor(light: 0xD1D5DB, dark: 0x45454A)
        /// 2px focus ring = accent.
        static let focus = DynamicColor(light: 0x2563EB, dark: 0x60A5FA)
        /// Row separators in tables and key-value lists; one step lighter than border.
        static let rule = DynamicColor(light: 0xF0F1F3, dark: 0x252527)
    }
    /// The 11 flow mark colours (Proxyman's set = the macOS system colours, light/dark).
    enum Mark {
        static let blue = DynamicColor(light: 0x007AFF, dark: 0x0A84FF)
        static let cyan = DynamicColor(light: 0x32ADE6, dark: 0x64D2FF)
        static let green = DynamicColor(light: 0x34C759, dark: 0x30D158)
        static let indigo = DynamicColor(light: 0x5856D6, dark: 0x5E5CE6)
        static let mint = DynamicColor(light: 0x00C7BE, dark: 0x63E6E2)
        static let orange = DynamicColor(light: 0xFF9500, dark: 0xFF9F0A)
        static let pink = DynamicColor(light: 0xFF2D55, dark: 0xFF375F)
        static let purple = DynamicColor(light: 0xAF52DE, dark: 0xBF5AF2)
        static let red = DynamicColor(light: 0xFF3B30, dark: 0xFF453A)
        static let teal = DynamicColor(light: 0x30B0C7, dark: 0x40C8E0)
        static let yellow = DynamicColor(light: 0xFFCC00, dark: 0xFFD60A)
    }
    /// HTTP method badge colors, Proxyman-WebUI convention.
    enum Method {
        static let connect = ColorPair(
            fg: DynamicColor(light: 0x4B5563, dark: 0xB4B4B8),
            bg: DynamicColor(light: 0xF3F4F6, dark: 0x2A2A2D))
        static let delete = ColorPair(
            fg: DynamicColor(light: 0xB91C1C, dark: 0xFCA5A5),
            bg: DynamicColor(light: 0xFEE2E2, dark: 0x3B1C1C))
        static let get = ColorPair(
            fg: DynamicColor(light: 0x1D4ED8, dark: 0x93C5FD),
            bg: DynamicColor(light: 0xDBEAFE, dark: 0x1E2A44))
        static let head = ColorPair(
            fg: DynamicColor(light: 0x4B5563, dark: 0xB4B4B8),
            bg: DynamicColor(light: 0xF3F4F6, dark: 0x2A2A2D))
        static let options = ColorPair(
            fg: DynamicColor(light: 0x4B5563, dark: 0xB4B4B8),
            bg: DynamicColor(light: 0xF3F4F6, dark: 0x2A2A2D))
        static let patch = ColorPair(
            fg: DynamicColor(light: 0xC2410C, dark: 0xFDBA74),
            bg: DynamicColor(light: 0xFFEDD5, dark: 0x3B2516))
        static let post = ColorPair(
            fg: DynamicColor(light: 0x15803D, dark: 0x86EFAC),
            bg: DynamicColor(light: 0xDCFCE7, dark: 0x14322A))
        static let put = ColorPair(
            fg: DynamicColor(light: 0xB45309, dark: 0xFCD34D),
            bg: DynamicColor(light: 0xFEF3C7, dark: 0x3A2E12))
        /// WebSocket flows (and 101 Switching Protocols).
        static let ws = ColorPair(
            fg: DynamicColor(light: 0x6D28D9, dark: 0xC4B5FD),
            bg: DynamicColor(light: 0xEDE9FE, dark: 0x2E2550))
    }
    /// PoC finding severity (aitm-poc Severity enum).
    enum Severity {
        static let critical = ColorPair(
            fg: DynamicColor(light: 0x7F1D1D, dark: 0xFCA5A5),
            bg: DynamicColor(light: 0xFEE2E2, dark: 0x4C1D1D))
        static let high = ColorPair(
            fg: DynamicColor(light: 0xB91C1C, dark: 0xF87171),
            bg: DynamicColor(light: 0xFEE2E2, dark: 0x3B1C1C))
        static let info = ColorPair(
            fg: DynamicColor(light: 0x4B5563, dark: 0xB4B4B8),
            bg: DynamicColor(light: 0xF3F4F6, dark: 0x2A2A2D))
        static let low = ColorPair(
            fg: DynamicColor(light: 0x1D4ED8, dark: 0x93C5FD),
            bg: DynamicColor(light: 0xDBEAFE, dark: 0x1E2A44))
        static let medium = ColorPair(
            fg: DynamicColor(light: 0xB45309, dark: 0xFCD34D),
            bg: DynamicColor(light: 0xFEF3C7, dark: 0x3A2E12))
    }
    /// HTTP status classes.
    enum Status {
        /// 4xx
        static let clientError = DynamicColor(light: 0xB45309, dark: 0xFCD34D)
        /// 1xx
        static let informational = DynamicColor(light: 0x6D28D9, dark: 0xC4B5FD)
        /// Killed/aborted flow: grey + strikethrough on the URL.
        static let killed = DynamicColor(light: 0x616A78, dark: 0x8E8E93)
        /// In flight / no response yet (Proxyman 'Active') as TEXT. Same hue family as intercept on purpose: both mean 'not finished'. The pending status DOT uses intercept.base (a graphic: 3:1 is enough).
        static let pending = DynamicColor(light: 0xB45309, dark: 0xF5A524)
        /// 3xx
        static let redirect = DynamicColor(light: 0x0369A1, dark: 0x7DD3FC)
        /// 5xx and transport errors
        static let serverError = DynamicColor(light: 0xB91C1C, dark: 0xF87171)
        /// 2xx
        static let success = DynamicColor(light: 0x15803D, dark: 0x4ADE80)
    }
    /// Body viewer syntax colors (JSON/XML/HTML/JS/headers), Proxyman-native-derived.
    enum Syntax {
        /// true/false/null literals.
        static let boolean = DynamicColor(light: 0x6D28D9, dark: 0xC4B5FD)
        /// Outer object/array brackets.
        static let bracket = DynamicColor(light: 0xA16207, dark: 0xE5C07B)
        /// Line and block comments; additive for code editing.
        static let comment = DynamicColor(light: 0x6E7A82, dark: 0x7D8590)
        static let currentLine = DynamicColor(light: 0xF3F4F6, dark: 0x232325)
        static let diffAdd = ColorPair(
            fg: DynamicColor(light: 0x15803D, dark: 0x86EFAC),
            bg: DynamicColor(light: 0xDCFCE7, dark: 0x14322A))
        static let diffRemove = ColorPair(
            fg: DynamicColor(light: 0xB91C1C, dark: 0xFCA5A5),
            bg: DynamicColor(light: 0xFEE2E2, dark: 0x3B1C1C))
        /// JSON keys, header names, XML attribute names.
        static let key = DynamicColor(light: 0x9D174D, dark: 0xE58BC9)
        /// Rhai control keywords (fn/let/if/…); additive for code editing.
        static let keyword = DynamicColor(light: 0x1D4ED8, dark: 0x8AB4F8)
        static let lineNumber = DynamicColor(light: 0x9CA3AF, dark: 0x5C5C62)
        /// Find-in-body highlight.
        static let match = DynamicColor(light: 0xFDE68A, dark: 0x6B5312)
        static let number = DynamicColor(light: 0x15803D, dark: 0x7FD88F)
        /// Braces, colons, commas.
        static let punct = DynamicColor(light: 0x6B7280, dark: 0x8E8E93)
        /// String values.
        static let string = DynamicColor(light: 0xB45309, dark: 0xE8B86D)
    }
    enum Ink {
        /// URL path segment and links: the accent's deep shade in light so it holds 4.5:1 on the selected-row tint; the WebUI draws the path in a blue-violet, we keep one hue.
        static let link = DynamicColor(light: 0x1D4ED8, dark: 0x7DB2F8)
        /// Text on an accent fill.
        static let onAccent = DynamicColor(light: 0xFFFFFF, dark: 0x0B1220)
        /// Text on the primary (inverse) button.
        static let onInverse = DynamicColor(light: 0xFFFFFF, dark: 0x111111)
        /// Identity text: URL host, header names, values, titles.
        static let primary = DynamicColor(light: 0x111827, dark: 0xE6E6E8)
        /// Column headers, labels, timestamps, durations.
        static let secondary = DynamicColor(light: 0x4B5563, dark: 0xB4B4B8)
        /// Placeholders, meta, disabled labels. Floor of the readable tiers (4.7:1 on raised, 5.3:1 on surface in light).
        static let tertiary = DynamicColor(light: 0x616A78, dark: 0x8E8E93)
    }
    /// Two faces, each with one job.
    enum Typography {
        enum Family {
        }
        enum Features {
            /// On every number in a column, a timer, or a byte count.
            static let tabularNums = "tnum"
        }
        enum LineHeight {
            /// Body viewers: 13px → 20px lines.
            static let code: CGFloat = 1.55
            static let text: CGFloat = 1.45
            /// Badges, single-line cells.
            static let tight: CGFloat = 1.25
        }
        /// Six sizes.
        enum Size {
            /// Body in comfortable views, sidebar labels, form controls.
            static let base: CGFloat = 14
            /// Pane titles (Request / Response), dialog titles.
            static let lg: CGFloat = 16
            /// Body in dense views: flow rows, header tables, code.
            static let md: CGFloat = 13
            /// Column headers, labels, timestamps, status bar.
            static let sm: CGFloat = 12
            /// The one screen title (h1), PoC finding title.
            static let xl: CGFloat = 20
            /// Badges, pills, meta chips, line numbers. Floor.
            static let xs: CGFloat = 11
        }
        enum Weight {
            /// Active tab, selected sidebar item, badge text.
            static let medium: Font.Weight = .medium
            static let regular: Font.Weight = .regular
            /// Pane titles, h1, the status code.
            static let semibold: Font.Weight = .semibold
        }
    }
    /// 4px base.
    enum Space {
        static let s1: CGFloat = 4
        static let s2: CGFloat = 8
        static let s3: CGFloat = 12
        static let s4: CGFloat = 16
        static let s5: CGFloat = 20
        static let s6: CGFloat = 24
        static let s8: CGFloat = 32
    }
    /// Fixed dimensions of the shell.
    enum Size {
        /// Method/status pill height.
        static let badge: CGFloat = 18
        static let columnHeader: CGFloat = 28
        /// Button/input height in toolbars and bars.
        static let control: CGFloat = 28
        /// In dialogs and forms.
        static let controlLg: CGFloat = 32
        /// The content-type chip row.
        static let filterBar: CGFloat = 36
        static let icon: CGFloat = 16
        static let iconInline: CGFloat = 12
        static let iconToolbar: CGFloat = 18
        /// The GET · 200 OK · URL summary line.
        static let inspectorHeader: CGFloat = 40
        static let interceptBar: CGFloat = 40
        enum Row {
            /// Two-line WebUI-style rows (method+status / URL) for narrow layouts and the web viewer.
            static let card: CGFloat = 64
            static let comfortable: CGFloat = 40
            static let `default`: CGFloat = 32
            /// Default for the flow list (Proxyman native ≈30).
            static let dense: CGFloat = 28
        }
        static let sidebar: CGFloat = 240
        static let sidebarMin: CGFloat = 200
        static let sidebarMax: CGFloat = 320
        static let splitterHit: CGFloat = 6
        static let statusBar: CGFloat = 28
        static let statusDot: CGFloat = 8
        static let tabBar: CGFloat = 36
        static let toolbar: CGFloat = 44
    }
    /// Tight family (Proxyman): badges 4, controls 6, panels 8, floating 10.
    enum Radius {
        static let badge: CGFloat = 4
        static let control: CGFloat = 6
        /// Menus, popovers, the command palette.
        static let floating: CGFloat = 10
        static let panel: CGFloat = 8
        /// Only the toolbar's 'Listening on host:port' status pill and chip filters.
        static let pill: CGFloat = 999
    }
    /// Shadows only on what floats.
    enum Shadow {
        static let floating = FloatingShadow(y: 8, radius: 24 / 2, lightOpacity: 0.12, darkOpacity: 0.5)
    }
    /// Feedback only; nothing on screen performs an entrance.
    enum Motion {
        static func easeInOut(_ duration: Double) -> Animation {
            Animation.timingCurve(0.77, 0.0, 0.175, 1.0, duration: duration)
        }
        static func easeOut(_ duration: Double) -> Animation {
            Animation.timingCurve(0.23, 1.0, 0.32, 1.0, duration: duration)
        }
        static let hover: Double = 0.100
        /// The armed-intercept bar's dot pulses opacity 1→0.5; stops under reduced motion.
        static let interceptPulse: Double = 1.200
        /// Menus, popovers; scale from 0.97 at the trigger's origin.
        static let popover: Double = 0.160
        /// Button :active scale(0.97).
        static let press: Double = 0.120
        /// New flows append with no animation: the list can gain 50 rows/s.
        static let rowArrive: Double = 0.000
        /// Compose/PoC sheets, the browser drawer.
        static let sheet: Double = 0.220
    }
    /// SF Symbol per icon role (`icon.glyph.*.mac`).
    enum Glyph {
        static let agent = "cpu"
        static let browser = "globe"
        static let chevron = "chevron.right"
        static let clear = "trash"
        static let comment = "text.bubble"
        static let compose = "square.and.pencil"
        static let copy = "doc.on.doc"
        static let filter = "line.3.horizontal.decrease"
        static let intercept = "hand.raised"
        static let kill = "xmark.circle"
        static let lock = "lock"
        static let lockOpen = "lock.open"
        static let mark = "flag"
        static let palette = "command"
        static let pause = "pause.fill"
        static let pin = "pin"
        static let poc = "flag.checkered"
        static let record = "record.circle"
        static let replay = "arrow.counterclockwise"
        static let resume = "arrow.right.circle"
        static let scope = "scope"
        static let search = "magnifyingglass"
        static let sidebar = "sidebar.left"
        static let split = "rectangle.split.2x1"
        static let websocket = "arrow.left.arrow.right"
    }
}
