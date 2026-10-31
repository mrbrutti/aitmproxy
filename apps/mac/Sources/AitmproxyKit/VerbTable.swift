import Foundation

/// What a flow row can do, from the keyboard (S-010), the row's context menu, the Flow menu or
/// the intercept bar. One table (`VerbTable`) owns every title, key and enabled rule, so the
/// surfaces never disagree (architecture card "one verb table for row actions").
public enum FlowVerb: Hashable, Sendable {
    case resume, edit, kill, delete, replay, editAndReplay, buildPoC
    case resumeSelected, killSelected
    case mark(MarkColor?), comment, pinHost, copyURL, quickLook

    /// The table row a verb belongs to: every mark colour shares the one `Mark` row.
    public var tableKey: FlowVerb {
        if case .mark = self { .mark(nil) } else { self }
    }
}

/// The menu sections, in order; the row menu puts a separator between groups.
public enum VerbGroup: Int, Hashable, Sendable, CaseIterable {
    case intercept, replay, selection, annotate, host
}

/// Everything the table needs to know about the row a verb would act on.
public struct VerbContext: Sendable {
    public var row: FlowRow
    /// Draft edits not yet applied to the paused request (`Session.pendingEditCount`).
    public var pendingEdits: Int
    /// Whether the row's host is pinned in the sidebar.
    public var pinned: Bool
    /// How many rows are selected in the list the row belongs to.
    public var selectedCount: Int
    /// How many of those are paused (the bulk verbs act on them alone).
    public var selectedPausedCount: Int

    public init(row: FlowRow, pendingEdits: Int = 0, pinned: Bool = false, selectedCount: Int = 1,
                selectedPausedCount: Int = 0) {
        self.row = row
        self.pendingEdits = pendingEdits
        self.pinned = pinned
        self.selectedCount = selectedCount
        self.selectedPausedCount = selectedPausedCount
    }
}

/// One row verb as a surface shows it.
public struct VerbItem: Hashable, Sendable {
    public var verb: FlowVerb
    public var title: String
    /// The bare list key that fires it while the flow list is first responder (`"e"`, `" "`).
    public var key: String?
    /// The menu-bar key equivalent (`⌘⏎`, `⇧R`, or the bare letter itself). Nil for a verb whose
    /// key only works on the focused list (`m` opens the mark menu, Space is Quick Look).
    public var shortcut: Shortcut?
    public var enabled: Bool
    public var group: VerbGroup
    /// Why the verb is off, when a surface can show it.
    public var disabledReason: String?

    public init(verb: FlowVerb, title: String, key: String? = nil, shortcut: Shortcut? = nil, enabled: Bool = true,
                group: VerbGroup, disabledReason: String? = nil) {
        self.verb = verb
        self.title = title
        self.key = key
        self.shortcut = shortcut
        self.enabled = enabled
        self.group = group
        self.disabledReason = disabledReason
    }

    /// The shortcut as a button prints it (foundation §2.7): a bare key as the letter (`e`), a
    /// chord as its glyphs (`⌘⏎`).
    public var hint: String? {
        guard let shortcut else { return key }
        let bare = !shortcut.command && !shortcut.shift && !shortcut.option && !shortcut.control
        return bare ? shortcut.key : shortcut.display
    }
}

public enum VerbTable {
    /// The verbs in menu order. `nil` is "no row": default titles, every verb disabled.
    public static func items(for context: VerbContext?) -> [VerbItem] {
        let row = context?.row
        let state = row?.state
        let paused = state == .paused
        let inFlight = paused || state == .pending
        let inScope = row?.inScope ?? false
        let scopeReason = row.flatMap { $0.inScope ? nil : outOfScopeReason($0.authority) }
        let selectedCount = context?.selectedCount ?? 1
        let bulkOn = selectedCount > 1 && (context?.selectedPausedCount ?? 0) > 0
        let bulkCount = selectedCount > 1 ? " \(selectedCount)" : ""
        let needsPaused = "Only a paused flow can be "
        let noPausedSelected = "No paused flows in the selection"

        // `off` explains a verb the row's state turns off; the scope reason wins when both apply.
        func item(_ verb: FlowVerb, _ title: String, key: String? = nil, shortcut: String? = nil, on: Bool = true,
                  off: String? = nil, group: VerbGroup) -> VerbItem {
            let enabled = inScope && on
            let why = row == nil ? nil : (scopeReason ?? (on ? nil : off))
            return VerbItem(verb: verb, title: title, key: key, shortcut: shortcut.flatMap(Shortcut.init(display:)),
                            enabled: enabled, group: group, disabledReason: enabled ? nil : why)
        }

        return [
            item(.resume, (context?.pendingEdits ?? 0) > 0 ? "Apply & Resume" : "Resume", shortcut: "⌘⏎", on: paused,
                 off: needsPaused + "resumed", group: .intercept),
            item(.edit, "Edit Paused Request", key: "e", shortcut: "e", on: paused, off: needsPaused + "edited", group: .intercept),
            item(.delete, inFlight ? "Kill" : "Delete", key: "d", shortcut: "d", group: .intercept),
            item(.kill, "Kill", shortcut: "⌘\\", on: paused, off: needsPaused + "killed", group: .intercept),
            item(.replay, "Replay", key: "r", shortcut: "r", group: .replay),
            item(.editAndReplay, "Edit & Replay…", shortcut: "⇧R", group: .replay),
            item(.buildPoC, "Build PoC from Flow…", key: "p", shortcut: "p", group: .replay),
            item(.resumeSelected, "Resume\(bulkCount) Selected", on: bulkOn, off: noPausedSelected, group: .selection),
            item(.killSelected, "Kill\(bulkCount) Selected", on: bulkOn, off: noPausedSelected, group: .selection),
            item(.mark(nil), "Mark", key: "m", group: .annotate),
            item(.comment, row?.comment == nil ? "Comment…" : "Edit Comment…", key: "c", shortcut: "⌘L", group: .annotate),
            item(.pinHost, (context?.pinned ?? false) ? "Unpin Host" : "Pin Host", shortcut: "⇧P", group: .host),
            item(.copyURL, "Copy URL", group: .host),
            item(.quickLook, "Quick Look Body", key: " ", group: .host),
        ]
    }

    /// One verb's row for a context (`nil` context: the default, disabled row).
    public static func item(_ verb: FlowVerb, for context: VerbContext?) -> VerbItem {
        item(verb, in: items(for: context))
    }

    /// One verb's row out of a table already built. Every `FlowVerb` has a row (`.mark(color)`
    /// shares `Mark`'s), so this cannot miss.
    public static func item(_ verb: FlowVerb, in items: [VerbItem]) -> VerbItem {
        let key = verb.tableKey
        guard let item = items.first(where: { $0.verb == key }) else {
            preconditionFailure("VerbTable has no row for \(verb)")
        }
        return item
    }

    /// The verb a bare key fires on the focused list; keys are the same for every row.
    public static func verb(forKey key: String) -> FlowVerb? { keyMap[key] }

    private static let keyMap: [String: FlowVerb] = Dictionary(uniqueKeysWithValues: items(for: nil).compactMap { item in
        item.key.map { ($0, item.verb) }
    })

    /// The verbs in the order every surface lists them.
    public static let order: [FlowVerb] = items(for: nil).map(\.verb)

    /// Every title a verb can show, for `CommandMap` and the menu audit.
    public static func titles(_ verb: FlowVerb) -> [String] {
        switch verb.tableKey {
        case .resume: ["Resume", "Apply & Resume"]
        case .edit: ["Edit Paused Request"]
        case .kill: ["Kill"]
        case .delete: ["Kill", "Delete"]
        case .replay: ["Replay"]
        case .editAndReplay: ["Edit & Replay…"]
        case .buildPoC: ["Build PoC from Flow…"]
        case .resumeSelected: ["Resume Selected"]
        case .killSelected: ["Kill Selected"]
        case .mark: ["Mark"]
        case .comment: ["Comment…", "Edit Comment…"]
        case .pinHost: ["Pin Host", "Unpin Host"]
        case .copyURL: ["Copy URL"]
        case .quickLook: ["Quick Look Body"]
        }
    }

    public static let allTitles: [FlowVerb: [String]] = Dictionary(uniqueKeysWithValues: order.map { ($0, titles($0)) })

    public static func outOfScopeReason(_ authority: String) -> String {
        "Out of scope — add \(authority) to scope to act"
    }
}
