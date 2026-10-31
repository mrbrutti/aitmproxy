import Foundation

/// What a flow row can do, from the keyboard (S-010), the row's context menu, the Flow menu or
/// the intercept bar. One table (`VerbTable`) owns every title, key and enabled rule, so the
/// surfaces never disagree (architecture card "one verb table for row actions").
public enum FlowVerb: Hashable, Sendable {
    case resume, edit, kill, delete, replay, editAndReplay, buildPoC
    case resumeSelected, killSelected
    case mark(MarkColor?), comment, pinHost, copyURL, quickLook
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
    /// Whether the row is the intercept bar's target (the focused paused row, else the oldest).
    public var isInterceptTarget: Bool

    public init(row: FlowRow, pendingEdits: Int = 0, pinned: Bool = false, selectedCount: Int = 1,
                selectedPausedCount: Int = 0, isInterceptTarget: Bool = false) {
        self.row = row
        self.pendingEdits = pendingEdits
        self.pinned = pinned
        self.selectedCount = selectedCount
        self.selectedPausedCount = selectedPausedCount
        self.isInterceptTarget = isInterceptTarget
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
}

public enum VerbTable {
    /// The verbs in menu order. `nil` is "no row": default titles, every verb disabled.
    public static func items(for context: VerbContext?) -> [VerbItem] {
        guard let context else {
            return items(for: nil as FlowRow?, pendingEdits: 0, pinned: false, selectedCount: 1, selectedPausedCount: 0)
        }
        return items(for: context.row, pendingEdits: context.pendingEdits, pinned: context.pinned,
                     selectedCount: context.selectedCount, selectedPausedCount: context.selectedPausedCount)
    }

    /// The verb a bare key fires, if any of `items` claims it (enabled or not: the caller reports).
    public static func verb(forKey key: String, in items: [VerbItem]) -> FlowVerb? {
        items.first { $0.key == key }?.verb
    }

    /// Every title a verb can show, for `CommandMap` and the menu audit.
    public static func titles(_ verb: FlowVerb) -> [String] {
        switch verb {
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

    public static var allTitles: [FlowVerb: [String]] {
        Dictionary(uniqueKeysWithValues: order.map { ($0, titles($0)) })
    }

    /// The verbs in the order every surface lists them.
    public static let order: [FlowVerb] = [
        .resume, .edit, .delete, .kill,
        .replay, .editAndReplay, .buildPoC,
        .resumeSelected, .killSelected,
        .mark(nil), .comment,
        .pinHost, .copyURL, .quickLook,
    ]

    public static func outOfScopeReason(_ authority: String) -> String {
        "Out of scope — add \(authority) to scope to act"
    }

    private static func items(for row: FlowRow?, pendingEdits: Int, pinned: Bool, selectedCount: Int,
                              selectedPausedCount: Int) -> [VerbItem] {
        let state = row?.state
        let paused = state == .paused
        let inFlight = paused || state == .pending
        let inScope = row?.inScope ?? false
        let reason = row.map { $0.inScope ? nil : outOfScopeReason($0.authority) } ?? nil
        let bulkOn = selectedCount > 1 && selectedPausedCount > 0
        let bulkCount = selectedCount > 1 ? " \(selectedCount)" : ""

        // `off` explains a verb the row's state turns off; the scope reason wins when both apply.
        func item(_ verb: FlowVerb, _ title: String, key: String? = nil, shortcut: String? = nil, on: Bool = true,
                  off: String? = nil, group: VerbGroup) -> VerbItem {
            let enabled = row != nil && inScope && on
            let why = row == nil ? nil : (reason ?? (on ? nil : off))
            return VerbItem(verb: verb, title: title, key: key, shortcut: shortcut.flatMap(Shortcut.init(display:)),
                            enabled: enabled, group: group, disabledReason: enabled ? nil : why)
        }
        let needsPaused = "Only a paused flow can be "
        let noPausedSelected = "No paused flows in the selection"

        return [
            item(.resume, pendingEdits > 0 ? "Apply & Resume" : "Resume", shortcut: "⌘⏎", on: paused,
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
            item(.pinHost, pinned ? "Unpin Host" : "Pin Host", shortcut: "⇧P", group: .host),
            item(.copyURL, "Copy URL", group: .host),
            item(.quickLook, "Quick Look Body", key: " ", group: .host),
        ]
    }
}
