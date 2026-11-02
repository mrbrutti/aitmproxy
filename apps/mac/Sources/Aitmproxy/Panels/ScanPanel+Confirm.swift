import AitmproxyKit
import SwiftUI

extension View {
    /// The Scan page's modals (scanner v2 T9): the Start Scan confirm sheet of the
    /// D9 launch handshake and the Delete Profile dialog.
    ///
    /// D2's rule is one modal at a time: the confirm sheet never stacks on the
    /// delete dialog, so the sheet's item is nil while a profile is being deleted.
    /// The pending confirm itself is kept in `surface.confirm` the whole time — the
    /// sheet comes back when the dialog closes, and no token is thrown away.
    func scanModals(_ state: ScanPanelState) -> some View {
        let confirming = Binding<ScanConfirmItem?>(
            get: {
                guard state.deleteCandidate == nil, let confirm = state.surface.confirm else { return nil }
                return ScanConfirmItem(confirm: confirm)
            },
            set: { item in
                // A dismissal (⎋, click-away) cancels the launch: nothing more is
                // sent. The delete dialog hiding the sheet is not a dismissal.
                guard item == nil, state.deleteCandidate == nil else { return }
                state.dismissConfirm()
            }
        )
        let deleting = Binding<Bool>(
            get: { state.deleteCandidate != nil },
            set: { presented in if !presented { state.deleteCandidate = nil } }
        )
        return sheet(item: confirming) { _ in ScanConfirmSheet(state: state) }
            .confirmationDialog(
                Text("Delete Profile “\(state.deleteCandidate ?? "")”?"),
                isPresented: deleting,
                titleVisibility: .visible,
                presenting: state.deleteCandidate
            ) { name in
                Button("Delete", role: .destructive) { Task { await state.deleteProfile(name) } }
                Button("Cancel", role: .cancel) {}
            } message: { _ in
                Text("This removes the saved profile file. Jobs that used it keep their results.")
            }
    }
}

/// `sheet(item:)` wants an Identifiable; `ScanConfirm` is Hashable, and the
/// confirm token is its identity — a second `needs_confirmation` answer carries a
/// new token, so the sheet re-presents with the new prompt.
private struct ScanConfirmItem: Identifiable {
    var confirm: ScanConfirm
    var id: String { confirm.request.token }
}

/// D9 step 1: the engine asked for confirmation. The prompt is the engine's words
/// verbatim — this app never paraphrases what the scan is about to do. Cancel
/// sends nothing further; Start Scan re-sends the identical arguments plus the
/// token (`ScanConfirm.confirmedArguments`).
private struct ScanConfirmSheet: View {
    var state: ScanPanelState

    var body: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            HStack(spacing: Space.sm) {
                Image(systemName: "exclamationmark.triangle")
                    .font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .accessibilityHidden(true)
                Text("Start Scan?")
                    .font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .accessibilityAddTraits(.isHeader)
            }
            Text(state.surface.confirm?.request.prompt ?? "")
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.secondary.color)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: Space.md) {
                Spacer()
                // Once the confirmed call is on the wire there is nothing left to
                // cancel: the engine has the token, and the answer settles the sheet.
                FlatButton("Cancel") { state.dismissConfirm() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(state.surface.launchInFlight)
                if state.surface.launchInFlight {
                    // D11: the confirmed call is in flight; the button is gone, so
                    // the same launch cannot be sent twice.
                    ProgressView().controlSize(.small)
                } else {
                    PrimaryButton("Start Scan") { Task { await state.confirmLaunch() } }
                        .keyboardShortcut(.defaultAction)
                        .accessibilityIdentifier("scan-confirm-start")
                }
            }
        }
        .padding(Space.lg)
        .frame(width: 480)
        .background(Tok.Ground.surface.color)
        .noInitialFocus()
        .fitsContent()
    }
}
