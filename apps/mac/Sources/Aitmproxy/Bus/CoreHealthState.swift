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

    /// The current health bucket, or `nil` when no embedded core is running.
    var health: CoreHealth? { connection?.health }

    /// Appends one captured line (token-free by construction — Layer A).
    func record(_ line: String) { log.append(line) }
}
