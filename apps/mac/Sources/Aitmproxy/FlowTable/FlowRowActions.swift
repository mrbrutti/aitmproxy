import AitmproxyKit
import AppKit
import Quartz
import SwiftUI

/// An `NSTableView` that turns mitmproxy's single-key verbs into row actions.
/// Keys arrive here only while the table is first responder, so a text
/// field never loses a letter to a verb. The letters come from `VerbTable`.
final class FlowKeyTable: NSTableView {
    var onVerb: ((FlowVerb) -> Void)?
    var onToggleIntercept: (() -> Void)?
    var onCompose: (() -> Void)?
    var onEnter: (() -> Void)?
    /// The list's undo manager (Clear's step), so Edit ▸ Undo and ⌘Z reach it while the list is
    /// first responder; a text field in front keeps its own.
    var undoManagerProvider: (() -> UndoManager?)?

    override var undoManager: UndoManager? { undoManagerProvider?() ?? super.undoManager }

    override func keyDown(with event: NSEvent) {
        guard event.modifierFlags.intersection([.command, .option, .control]).isEmpty,
              let key = event.charactersIgnoringModifiers else { return super.keyDown(with: event) }
        switch key {
        case "i": onToggleIntercept?()
        case "n": onCompose?()
        case "\r": onEnter?()
        default:
            guard let verb = VerbTable.verb(forKey: key) else { return super.keyDown(with: event) }
            // Space toggles Quick Look, as in Finder.
            if verb == .quickLook, QLPreviewPanel.sharedPreviewPanelExists(), QLPreviewPanel.shared().isVisible {
                QLPreviewPanel.shared().orderOut(nil)
            } else {
                onVerb?(verb)
            }
        }
    }

    // MARK: Quick Look controller

    // AppKit declares these nonisolated; it calls them on the main thread.
    nonisolated override func acceptsPreviewPanelControl(_ panel: QLPreviewPanel!) -> Bool { true }

    nonisolated override func beginPreviewPanelControl(_ panel: QLPreviewPanel!) {
        MainActor.assumeIsolated {
            panel.dataSource = BodyQuickLook.shared
            panel.delegate = BodyQuickLook.shared
        }
    }

    nonisolated override func endPreviewPanelControl(_ panel: QLPreviewPanel!) {
        MainActor.assumeIsolated {
            panel.dataSource = nil
            panel.delegate = nil
        }
    }
}

/// The comment popover (S-017): one field, Return saves, Escape cancels.
struct CommentPopover: View {
    var initial: String
    var onSave: (String) -> Void
    @State private var text = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Text("Comment").font(Tok.Face.ui(Tok.Typography.Size.md, .semibold))
            TextField("Why this flow matters", text: $text)
                .textFieldStyle(.roundedBorder)
                .frame(width: 320)
                .onSubmit { save() }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") { save() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(Space.lg)
        .onAppear { text = initial }
    }

    private func save() {
        onSave(text)
        dismiss()
    }
}

extension MarkColor {
    var title: String { rawValue.prefix(1).uppercased() + rawValue.dropFirst() }
}

/// "Clear 2 paused flows too?" — asked only when flows are paused (S-018).
enum ClearConfirmation {
    static func ask(pausedCount: Int) -> Bool {
        let alert = NSAlert()
        alert.messageText = pausedCount == 1 ? "Clear 1 paused flow too?" : "Clear \(pausedCount) paused flows too?"
        alert.informativeText = "Clearing drops every flow, including the ones waiting for Resume. Their clients see a reset."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Clear")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }
}
