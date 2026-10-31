import SwiftUI

/// The Saved page (Working ▸ Saved) until the core can save and reopen a capture
/// (S-066, core F10): an honest empty state instead of the flow list again.
struct SavedPanel: View {
    var body: some View {
        ContentUnavailableView {
            Label("No Saved Sessions", systemImage: "tray.full")
        } description: {
            Text("Saving a capture to disk and reopening it later needs the core's session.save. Export Selection… (⌘E) writes the selected flows as HAR, CSV or a cURL batch today.")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
    }
}
