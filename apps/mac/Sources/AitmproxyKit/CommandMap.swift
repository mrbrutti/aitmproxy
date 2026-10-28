import Foundation

/// A keyboard shortcut as the brief prints it (`⇧⌘C`, `i`, `⌥⌘⏎`, `Space`).
public struct Shortcut: Hashable, Sendable {
    /// The key equivalent as AppKit stores it: a lowercase character, `"\r"`,
    /// `"\u{8}"` (delete), `" "` or `"\u{1b}"`.
    public var key: String
    public var command = false
    public var shift = false
    public var option = false
    public var control = false

    public init(_ key: String, command: Bool = false, shift: Bool = false, option: Bool = false, control: Bool = false) {
        self.key = key
        self.command = command
        self.shift = shift
        self.option = option
        self.control = control
    }

    /// `⌥⌘⏎` → return with option and command; `` `i` `` → the bare key; nil for words like `radio`.
    public init?(display: String) {
        var rest = Substring(display.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "`", with: ""))
        var mods = (command: false, shift: false, option: false, control: false)
        loop: while let first = rest.first {
            switch first {
            case "⌘": mods.command = true
            case "⇧": mods.shift = true
            case "⌥": mods.option = true
            case "⌃": mods.control = true
            default: break loop
            }
            rest.removeFirst()
        }
        let key: String
        switch rest {
        case "⏎", "Return": key = "\r"
        case "⌫", "Delete": key = "\u{8}"
        case "Space": key = " "
        case "⎋", "Escape": key = "\u{1b}"
        case "\\": key = "\\"
        default:
            guard rest.count == 1, let c = rest.first, c.isLetter || c.isNumber || c.isPunctuation || c.isSymbol else { return nil }
            key = String(c).lowercased()
        }
        self.init(key, command: mods.command, shift: mods.shift, option: mods.option, control: mods.control)
    }

    public var display: String {
        var s = ""
        if control { s += "⌃" }
        if option { s += "⌥" }
        if shift { s += "⇧" }
        if command { s += "⌘" }
        switch key {
        case "\r": s += "⏎"
        case "\u{8}": s += "⌫"
        case " ": s += "Space"
        case "\u{1b}": s += "⎋"
        default: s += key.uppercased()
        }
        return s
    }
}

/// One verb of the brief's command map and the menu items that satisfy it.
public struct CommandMapEntry: Sendable {
    public enum Scope: Sendable, Equatable {
        /// A menu item carries the shortcut.
        case menu
        /// The shortcut is handled where it applies (an editor, the focused list);
        /// the menu item exists, without a key equivalent.
        case inContext(String)
        /// Not built yet; the story that brings it.
        case deferred(String)
    }

    /// A concrete item: any of `titles` (toggle variants) with `shortcut`.
    public struct Item: Sendable {
        public var titles: [String]
        public var shortcut: Shortcut?
        public init(_ titles: [String], _ shortcut: Shortcut? = nil) {
            self.titles = titles
            self.shortcut = shortcut
        }
        public init(_ title: String, _ shortcut: String) {
            self.titles = [title]
            self.shortcut = Shortcut(display: shortcut)
        }
    }

    public var menu: String
    /// The verb exactly as `docs/BRIEF.md` writes it.
    public var brief: String
    /// The shortcut text exactly as the brief writes it (`⌘N`, `` `i` ``, `radio`).
    public var briefShortcut: String?
    public var items: [Item]
    public var scope: Scope
    /// The single key that acts on the focused list row (S-010).
    public var listKey: String?

    public init(_ menu: String, _ brief: String, _ briefShortcut: String?, items: [Item], scope: Scope = .menu, listKey: String? = nil) {
        self.menu = menu
        self.brief = brief
        self.briefShortcut = briefShortcut
        self.items = items
        self.scope = scope
        self.listKey = listKey
    }
}

/// The brief's command map (`docs/BRIEF.md`, "Command map") as data, so a test
/// can hold the brief and the menu bar to the same list (S-069).
public enum CommandMap {
    public static let all: [CommandMapEntry] = {
        typealias E = CommandMapEntry
        typealias I = CommandMapEntry.Item
        func one(_ title: String, _ shortcut: String?) -> [I] { [I([title], shortcut.flatMap(Shortcut.init(display:)))] }
        func toggle(_ titles: [String], _ shortcut: String?) -> [I] { [I(titles, shortcut.flatMap(Shortcut.init(display:)))] }
        let chips = ["All", "HTTP", "HTTPS", "WebSocket", "h1", "h2", "JSON", "Form", "XML"]
        return [
            E("File", "Compose Request…", "⌘N (`n`)", items: one("Compose Request…", "⌘N"), listKey: "n"),
            E("File", "Import…", "⌘O", items: one("Import…", "⌘O"), scope: .deferred("S-065")),
            E("File", "Export Selection…", "⌘E", items: one("Export Selection…", "⌘E"), scope: .deferred("S-065")),
            E("File", "Save Session", "⌘S", items: one("Save Session", "⌘S"), scope: .deferred("S-066")),
            E("File", "Clear Session", "⌘⌫", items: one("Clear Session", "⌘⌫")),

            E("Flow", "Arm/Disarm Intercept", "`i`", items: toggle(["Arm Intercept", "Disarm Intercept"], "i"), listKey: "i"),
            E("Flow", "Resume / Apply & Resume", "⌘⏎", items: toggle(["Resume", "Apply & Resume"], "⌘⏎")),
            E("Flow", "Resume All", "⌥⌘⏎", items: one("Resume All", "⌥⌘⏎")),
            E("Flow", "Kill…", "⌘\\", items: toggle(["Kill", "Kill…"], "⌘\\")),
            E("Flow", "Edit Paused Request", "`e`", items: one("Edit Paused Request", "e"), listKey: "e"),
            E("Flow", "Revert to Original", "⌘Z (in editor)", items: one("Revert to Original", nil),
              scope: .inContext("⌘Z is Undo in the request editor")),
            E("Flow", "Replay", "`r`", items: one("Replay", "r"), listKey: "r"),
            E("Flow", "Edit & Replay", "⇧R", items: one("Edit & Replay…", "⇧R")),
            E("Flow", "Kill/Delete", "`d`", items: toggle(["Kill", "Delete"], "d"), listKey: "d"),
            E("Flow", "Mark", "`m`", items: one("Mark", nil), scope: .inContext("m opens the mark menu on the row"), listKey: "m"),
            E("Flow", "Comment…", "⌘L (`c`)", items: toggle(["Comment…", "Edit Comment…"], "⌘L"), listKey: "c"),
            E("Flow", "Pin Host", "⇧P", items: toggle(["Pin Host", "Unpin Host"], "⇧P")),
            E("Flow", "Build PoC from Flow…", "`p`", items: one("Build PoC from Flow…", "p"), listKey: "p"),
            E("Flow", "Add Host to Scope…", "⇧S", items: one("Add Host to Scope…", "⇧S")),
            E("Flow", "Copy as cURL / httpie / Python / fetch", "⇧⌘C",
              items: [I("Copy as cURL", "⇧⌘C"), I(["Copy as httpie"]), I(["Copy as Python (requests)"]), I(["Copy as fetch"])]),
            E("Flow", "Diff Selected", "⌘D", items: one("Diff Selected", "⌘D")),
            E("Flow", "Quick Look Body", "Space", items: one("Quick Look Body", nil),
              scope: .inContext("Space on the focused list"), listKey: " "),
            E("Flow", "Focus Inspector", "⏎", items: one("Focus Inspector", nil),
              scope: .deferred("the inspector has no single focus target yet"), listKey: "\r"),

            E("View", "Filter Bar", "⌘F", items: toggle(["Show Filter Bar", "Hide Filter Bar"], "⌘F")),
            E("View", "Sidebar Filter", "⇧⌘F", items: one("Sidebar Filter", "⇧⌘F")),
            E("View", "Command Palette", "⌘K", items: one("Command Palette", "⌘K")),
            E("View", "Find in Body", "⌥⌘F", items: one("Find in Body", "⌥⌘F")),
            E("View", "Chips", "⌘1…⌘9", items: chips.enumerated().map { I($0.element, "⌘\($0.offset + 1)") }),
            E("View", "Inspector Below / Right / Detached / Split View", "⌘⌥1…4",
              items: [I("Inspector Below", "⌥⌘1"), I("Inspector Right", "⌥⌘2"), I("Inspector Detached", "⌥⌘3"), I("Split View", "⌥⌘4")]),
            E("View", "Toggle Sidebar", "⌃⌘S", items: one("Toggle Sidebar", "⌃⌘S")),
            E("View", "Pause/Resume Capture", "⇧⌘R", items: toggle(["Pause Capture", "Resume Capture"], "⇧⌘R")),
            E("View", "Auto-select", "⇧⌘A", items: one("Auto-select", "⇧⌘A")),
            E("View", "Density", "Dense/Default/Comfortable", items: [I(["Dense"]), I(["Default"]), I(["Comfortable"])]),

            E("Agent", "Allow All Tools / Read-only / Paused", "radio", items: [I(["Allow all tools"]), I(["Read-only"]), I(["Paused"])]),
            E("Agent", "Activity Log…", "⇧⌘L", items: toggle(["Activity Log…", "Hide Activity Log"], "⇧⌘L")),
            E("Agent", "Approve Pending Request", "⌥⏎", items: one("Approve Pending Request", "⌥⏎")),

            E("Proxy", "Scope…", "⇧⌘O", items: one("Scope…", "⇧⌘O")),
            E("Proxy", "Breakpoint Rules…", "⇧⌘B", items: one("Breakpoint Rules…", "⇧⌘B")),
            E("Proxy", "Certificate Authority…", nil, items: one("Certificate Authority…", nil)),
            E("Proxy", "Configuration…", nil, items: one("Configuration…", nil)),
            E("Proxy", "Browser", "⇧⌘W", items: one("Browser", "⇧⌘W")),
        ]
    }()

    /// A verb as the brief lists it.
    public struct BriefVerb: Hashable, Sendable {
        public var menu: String
        public var title: String
        public var shortcut: String?
    }

    /// Reads the brief's `**Command map.**` bullet: one line per menu,
    /// `Menu ▸ verb — shortcut · verb — shortcut …`.
    public static func briefVerbs(in markdown: String) -> [BriefVerb] {
        var verbs: [BriefVerb] = []
        var inMap = false
        for raw in markdown.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("- **Command map.**") { inMap = true; continue }
            guard inMap else { continue }
            if line.isEmpty || line.hasPrefix("- ") { break }
            guard let arrow = line.range(of: " ▸ ") else { continue }
            let menu = String(line[..<arrow.lowerBound])
            for part in line[arrow.upperBound...].components(separatedBy: " · ") {
                var title = part.trimmingCharacters(in: .whitespaces)
                var shortcut: String?
                if let dash = title.range(of: " — ") {
                    shortcut = String(title[dash.upperBound...]).trimmingCharacters(in: .whitespaces)
                    title = String(title[..<dash.lowerBound])
                }
                if title.hasSuffix(".") { title.removeLast() }
                if let shortcut, shortcut.hasSuffix(".") { verbs.append(BriefVerb(menu: menu, title: title, shortcut: String(shortcut.dropLast()))); continue }
                verbs.append(BriefVerb(menu: menu, title: title, shortcut: shortcut))
            }
        }
        return verbs
    }
}
