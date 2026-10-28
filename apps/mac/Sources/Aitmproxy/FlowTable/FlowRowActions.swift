import AitmproxyKit
import AppKit
import SwiftUI

/// What a row can do, from the keyboard (S-010), the context menu or the Flow menu.
enum FlowRowAction: Hashable {
    case resume, kill, delete, replay, editAndReplay, edit, mark(MarkColor?), comment, buildPoC, pinHost, copyURL, quickLook,
         resumeSelected, killSelected
}

/// An `NSTableView` that turns mitmproxy's single-key verbs into row actions.
/// Keys arrive here only while the table is first responder, so a text
/// field never loses a letter to a verb.
final class FlowKeyTable: NSTableView {
    var onVerb: ((FlowRowAction) -> Void)?
    var onToggleIntercept: (() -> Void)?
    var onCompose: (() -> Void)?
    var onEnter: (() -> Void)?

    override func keyDown(with event: NSEvent) {
        guard event.modifierFlags.intersection([.command, .option, .control]).isEmpty,
              let key = event.charactersIgnoringModifiers else { return super.keyDown(with: event) }
        switch key {
        case "i": onToggleIntercept?()
        case "e": onVerb?(.edit)
        case "r": onVerb?(.replay)
        case "n": onCompose?()
        case "d": onVerb?(.delete)
        case "m": onVerb?(.mark(nil))
        case "c": onVerb?(.comment)
        case "p": onVerb?(.buildPoC)
        case " ": onVerb?(.quickLook)
        case "\r": onEnter?()
        default: super.keyDown(with: event)
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
