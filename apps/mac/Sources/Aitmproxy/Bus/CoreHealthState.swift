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

    /// The controller managing the capture extension, published here by
    /// `ExtensionController.start()` so the Settings window — a separate scene that
    /// cannot see `ShellView`'s `@State` — can reach it to uninstall (Task 17).
    /// `nil` until a real launch of a build that embeds the extension begins managing
    /// it, so it stays `nil` in development, fixture and snapshot runs. Weak, because
    /// `ShellView` owns the controller's lifetime and the controller holds a strong
    /// reference to this state; not observed, as it is an imperative handle, not UI state.
    @ObservationIgnored weak var extensionController: ExtensionController?

    /// The current health bucket, or `nil` when no embedded core is running.
    var health: CoreHealth? { connection?.health }

    /// Appends one captured line (token-free by construction — Layer A).
    func record(_ line: String) { log.append(line) }
}
