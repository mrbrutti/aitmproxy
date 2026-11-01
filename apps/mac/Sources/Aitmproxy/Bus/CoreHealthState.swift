import AitmproxyKit
import Foundation
import Observation

/// What the UI shows about the embedded core (Task 8, spec C4): its current
/// `CoreConnection` (for the always-visible health dot) and the captured
/// stdout/stderr (for the on-demand log panel). The `EmbeddedCoreController`
/// pushes both here as the core's lifecycle unfolds; the status bar and the log
/// panel read them, so neither view has to reach into the controller.
///
/// `connection` is `nil` when no embedded core is running (an external core, or
/// a development build with nothing bundled) — then the dot simply does not show,
/// and the bus dot already reports the external connection's health.
@MainActor @Observable
final class CoreHealthState {
    /// The live embedded connection, or `nil` when none is running.
    var connection: CoreConnection?
    /// The captured core output, oldest first, bounded.
    var log = CoreLogBuffer()
    /// Whether the macOS capture extension is installed, approved and capturing
    /// (Task 13, spec D9). The `ExtensionController` pushes it here; the Task 17
    /// indicator and any capture-dependent UI read it. A build with no embedded
    /// extension stays at `.extensionNotInstalled`.
    var captureCapability: CaptureCapability = .extensionNotInstalled

    /// Whether this launch can run L4 capture at all: a real run (not a self-test) of a
    /// build that embeds the capture extension. Without it the Settings ▸ All Apps
    /// controls and Proxy ▸ Capture All Apps stay unavailable, so a development build
    /// never shows a live control that does nothing. Decided once at launch, mirroring
    /// the guard in `ExtensionController.start()`.
    var captureSupported: Bool = CoreHealthState.launchSupportsCapture()

    /// Whether the capture controls are live: capture is supported, or an extension is
    /// already installed (or installing) and so has a state to show and an uninstall to offer.
    var captureControlsAvailable: Bool { captureSupported || captureCapability.isInstalledOrInstalling }

    /// True while an operator capture action (turn on, turn off, uninstall) is running.
    /// The Capture toggle, its menu command and the Uninstall button all stand down
    /// meanwhile, so the actions never overlap: a fast off-then-on is held until the off
    /// has finished, not dropped by the controller's own re-entry guards.
    var captureBusy = false

    /// The toggle position to show instead of the persisted capture choice: what the
    /// operator just asked for while an action runs, so the switch follows the click at
    /// once. `nil` otherwise, when the persisted choice is shown.
    var captureChoice: Bool?

    /// The controller managing the capture extension, published here by
    /// `ExtensionController.start()` so the Settings window — a separate scene that
    /// cannot see `ShellView`'s `@State` — can reach it to uninstall (Task 17).
    /// `nil` until a real launch of a build that embeds the extension begins managing
    /// it, so it stays `nil` in development and self-test runs. Weak, because
    /// `ShellView` owns the controller's lifetime and the controller holds a strong
    /// reference to this state; not observed, as it is an imperative handle, not UI state.
    @ObservationIgnored weak var extensionController: ExtensionController?

    /// The current health bucket, or `nil` when no embedded core is running.
    var health: CoreHealth? { connection?.health }

    /// Appends one captured line (token-free by construction — Layer A).
    func record(_ line: String) { log.append(line) }

    /// A real launch (the same guard `ExtensionController.start()` applies: not a self-test
    /// run) of an app bundle that embeds the capture extension.
    private static func launchSupportsCapture() -> Bool {
        guard !SelfTest.requested else { return false }
        return CaptureExtension.isEmbedded(inApp: Bundle.main.bundleURL)
    }
}
