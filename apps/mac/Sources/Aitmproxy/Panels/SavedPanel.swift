import SwiftUI

/// The Saved page (Working ▸ Saved) until the core can save and reopen a capture
/// (S-066, core F10): an honest empty state instead of the flow list again.
struct SavedPanel: View {
    var body: some View {
        ContentUnavailableView {
            Label("No Saved Sessions", systemImage: "tray.full")
        } description: {
            // Saving and reopening a capture waits on the core (S-066, F10).
            Text("Saving a capture to disk and reopening it later is not available yet. Export Selection… (⌘E) writes the selected flows as HAR, CSV or a cURL batch.")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
    }
}
