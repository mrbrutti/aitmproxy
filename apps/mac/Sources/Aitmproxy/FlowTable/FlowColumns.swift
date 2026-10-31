import AitmproxyKit
import AppKit

/// The columns, in default order (foundation §2.7 "Flow list").
enum FlowColumn: String, CaseIterable {
    case dot, seq, url, client, method, status, time, duration, request, response, ssl, edited, origin, comment, mark

    var identifier: NSUserInterfaceItemIdentifier { NSUserInterfaceItemIdentifier(rawValue) }

    var title: String {
        switch self {
        case .dot, .mark: ""
        case .seq: "#"
        case .url: "URL"
        case .client: "Client"
        case .method: "Method"
        case .status: "Status"
        case .time: "Time"
        case .duration: "Duration"
        case .request: "Request"
        case .response: "Response"
        case .ssl: "SSL"
        case .edited: "Edited"
        case .origin: "Origin"
        case .comment: "Comment"
        }
    }

    /// The header context menu's label (the two glyph-only columns need words).
    var menuTitle: String {
        switch self {
        case .dot: "Status Dot"
        case .mark: "Mark"
        default: title
        }
    }

    var width: CGFloat {
        switch self {
        case .dot: 24
        case .seq: 52
        case .url: 300
        case .client: 96
        case .method: 72
        case .status: 84
        case .time: 124
        case .duration: 88
        case .request: 80
        case .response: 80
        case .ssl: 40
        case .edited: 64
        case .origin: 72
        case .comment: 160
        case .mark: 20
        }
    }

    /// Comment starts hidden: the default set fits a 1440pt window.
    var defaultHidden: Bool { self == .comment }

    var minWidth: CGFloat { self == .url ? 200 : width }

    var numeric: Bool {
        switch self {
        case .seq, .duration, .request, .response: true
        default: false
        }
    }

    /// The columns that give way, first to last, when the pane is narrower than the visible
    /// columns' minimum sum (about 1096 pt with every column shown); they come back with room.
    /// `#`, URL and Method never hide; Status and Time stay because a row without them says nothing.
    static let autoHidePriority: [FlowColumn] = [.edited, .origin, .ssl, .response, .request, .duration, .client]

    /// `#`, URL and Method cannot be hidden.
    var alwaysVisible: Bool {
        switch self {
        case .seq, .url, .method: true
        default: false
        }
    }

    var sortKey: FlowSort.Key? {
        switch self {
        case .dot, .comment: nil
        default: FlowSort.Key(rawValue: rawValue)
        }
    }
}

/// Row pitch and body size move together (foundation §2.4 "Density").
enum Density: String, CaseIterable, Identifiable {
    case dense, `default`, comfortable

    var id: String { rawValue }

    var title: String {
        switch self {
        case .dense: "Dense"
        case .default: "Default"
        case .comfortable: "Comfortable"
        }
    }

    var rowHeight: CGFloat {
        switch self {
        case .dense: Tok.Size.Row.dense
        case .default: Tok.Size.Row.default
        case .comfortable: Tok.Size.Row.comfortable
        }
    }

    /// Body text in rows, header tables and code.
    var bodySize: CGFloat {
        switch self {
        case .dense, .default: Tok.Typography.Size.md
        case .comfortable: Tok.Typography.Size.base
        }
    }
}
