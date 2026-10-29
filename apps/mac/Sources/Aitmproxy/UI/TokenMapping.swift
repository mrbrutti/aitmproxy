import AitmproxyKit
import AppKit
import SwiftUI

/// Which token each domain value wears (foundation §2.2). Views and cells
/// read these, never a hex.
extension HTTPMethod {
    var badge: ColorPair {
        switch self {
        case .get: Tok.Method.get
        case .post: Tok.Method.post
        case .put: Tok.Method.put
        case .patch: Tok.Method.patch
        case .delete: Tok.Method.delete
        case .head: Tok.Method.head
        case .options: Tok.Method.options
        case .connect: Tok.Method.connect
        case .ws: Tok.Method.ws
        case .other: Tok.Method.head
        }
    }
}

extension StatusClass {
    var color: DynamicColor {
        switch self {
        case .informational: Tok.Status.informational
        case .success: Tok.Status.success
        case .redirect: Tok.Status.redirect
        case .clientError: Tok.Status.clientError
        case .serverError: Tok.Status.serverError
        }
    }

    /// The summary strip's status pill borrows the method tints of the same hue.
    var pill: ColorPair {
        switch self {
        case .informational: Tok.Method.ws
        case .success: Tok.Method.post
        case .redirect: Tok.Method.get
        case .clientError: Tok.Method.put
        case .serverError: Tok.Method.delete
        }
    }
}

extension FlowRow {
    /// The leading dot (a graphic: the pending dot uses `intercept.base`).
    var dotColor: DynamicColor {
        switch state {
        case .paused, .pending: Tok.Intercept.base
        case .killed: Tok.Status.killed
        case .failed: Tok.Status.serverError
        case .complete: status.flatMap(StatusClass.init)?.color ?? Tok.Status.success
        }
    }

    /// The Status column's text colour.
    var statusColor: DynamicColor {
        switch state {
        case .pending: Tok.Status.pending
        case .killed: Tok.Status.killed
        case .failed: Tok.Status.serverError
        case .paused: Tok.Intercept.deep
        case .complete: status.flatMap(StatusClass.init)?.color ?? Tok.Ink.secondary
        }
    }

    /// The 2px left edge: amber while paused, teal for agent-originated flows.
    var leftEdge: DynamicColor? {
        if state == .paused { return Tok.Intercept.base }
        if origin == .agent { return Tok.Agent.base }
        return nil
    }
}

extension CoreHealth {
    /// The embedded-core health dot's colour. One place both the status-bar dot
    /// (`CoreHealthDot`) and the core-log panel (`CoreLogPanel`) read, so the two
    /// surfaces never drift (Q1).
    var dotColor: DynamicColor {
        switch self {
        case .running: Tok.Status.success
        case .restarting: Tok.Intercept.base
        case .failed: Tok.Status.serverError
        }
    }
}

extension MarkColor {
    var color: NSColor {
        switch self {
        case .red: .systemRed
        case .orange: .systemOrange
        case .yellow: .systemYellow
        case .green: .systemGreen
        case .mint: .systemMint
        case .teal: .systemTeal
        case .cyan: .systemCyan
        case .blue: .systemBlue
        case .indigo: .systemIndigo
        case .purple: .systemPurple
        case .pink: .systemPink
        }
    }
}

extension SyntaxKind {
    var color: DynamicColor {
        switch self {
        case .plain: Tok.Ink.primary
        case .key: Tok.Syntax.key
        case .string: Tok.Syntax.string
        case .number: Tok.Syntax.number
        case .boolean: Tok.Syntax.boolean
        case .punct: Tok.Syntax.punct
        case .bracket: Tok.Syntax.bracket
        case .method: Tok.Method.post.fg
        case .version: Tok.Syntax.string
        case .keyword: Tok.Syntax.keyword
        case .comment: Tok.Syntax.comment
        }
    }
}

/// The two faces (foundation §2.3): the system text face for chrome, SF Mono for data.
extension Tok {
    enum Face {
        static func ui(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
            .system(size: size, weight: weight)
        }

        static func data(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
            .system(size: size, weight: weight, design: .monospaced)
        }

        static func nsUI(_ size: CGFloat, _ weight: NSFont.Weight = .regular) -> NSFont {
            .systemFont(ofSize: size, weight: weight)
        }

        static func nsData(_ size: CGFloat, _ weight: NSFont.Weight = .regular) -> NSFont {
            .monospacedSystemFont(ofSize: size, weight: weight)
        }
    }
}

/// The dense-chrome metrics the mockup fixes between the 4 pt steps
/// (foundation §2.4: chips 22, bar buttons 26, 6/10/14 px gaps).
extension Tok {
    enum Metric {
        /// Chip-bar chips and the inspector's format button.
        static let chip: CGFloat = 22
        /// Buttons inside the intercept bar.
        static let barButton: CGFloat = 26
        /// The status bar's small buttons.
        static let smallButton: CGFloat = 20
        /// Count chips in the sidebar and the Agent toggle.
        static let countChip: CGFloat = 18
        /// The Agent toggle's switch.
        static let switchWidth: CGFloat = 26
        static let switchHeight: CGFloat = 16
        static let switchKnob: CGFloat = 12
        /// Inner padding of pills and buttons.
        static let padInner: CGFloat = 10
        /// The gap between a label and its shortcut hint, or two tight items.
        static let gapTight: CGFloat = 6
        /// The gap between summary-strip and status-bar items.
        static let gapMeta: CGFloat = 14
        /// Height of the hairline separators between chip groups.
        static let chipSeparator: CGFloat = 14
    }
}
