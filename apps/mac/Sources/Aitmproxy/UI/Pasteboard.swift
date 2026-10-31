import AppKit

/// The one place the app writes to the general pasteboard. `sensitive` marks text that came
/// out of captured traffic (URLs with tokens, command arguments carrying headers or bodies):
/// the concealed type tells Universal Clipboard and clipboard managers to leave it alone.
enum Pasteboard {
    static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")

    static func copy(_ text: String, sensitive: Bool = false) {
        let board = NSPasteboard.general
        board.clearContents()
        if sensitive {
            board.declareTypes([.string, concealed], owner: nil)
            board.setString("", forType: concealed)
        }
        board.setString(text, forType: .string)
    }
}
