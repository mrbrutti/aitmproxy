import AitmproxyKit
import SwiftUI

/// The one operator confirm dialog for every confirmable L4 verb (spec §3 last rule:
/// inject, the parked-packet verdicts and the scope add all go through the same
/// confirm-over-the-wire handshake). It shows the core's own prompt — selectable in
/// full, because it is multi-line text an alert would clip — with Cancel and one
/// action button whose title, label and accessibility identifier follow the call the
/// request is bound to (`L4ConfirmWords`, Kit). A sheet, presented by item: the
/// single-use token identifies the request.
struct L4ConfirmSheet: View {
    var request: L4ConfirmRequest
    var onConfirm: () -> Void
    var onCancel: () -> Void

    /// The sheet's width. No `Tok.Size` token fits (the shell's sizes are control and row
    /// heights and the sidebar's widths); on the 4 pt grid, wide enough for the core's
    /// one-line inject summary without wrapping.
    private static let width: CGFloat = 480

    private var words: (title: String, action: String, identifier: String) {
        L4ConfirmWords.for(command: request.call?.command)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            HStack(spacing: Space.sm) {
                Image(systemName: "exclamationmark.shield").foregroundStyle(Tok.L4.base.color)
                Text(words.title).font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold)).foregroundStyle(Tok.Ink.primary.color)
            }
            Text(request.prompt)
                .font(Tok.Face.data(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.secondary.color)
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                    .accessibilityIdentifier("\(words.identifier)-cancel")
                Button(words.action) { onConfirm() }.buttonStyle(.borderedProminent)
                    .accessibilityIdentifier(words.identifier)
            }
        }
        .padding(Space.lg)
        .frame(width: Self.width)
        .noInitialFocus()
    }
}
