import AitmproxyKit
import Foundation

/// The live backing for `ActiveConnectionModel` (Task 7): it turns an
/// embedded/external choice into real start/stop of the embedded core and the
/// matching bus endpoint.
///
/// - **Embedded.** When the core is bundled, (re)start the controller and have the
///   bus wait for its endpoint (never latching onto some other running core). On a
///   development or not-yet-bundled build there is no controller, so "embedded"
///   degrades to the external `config.yaml` path — which is exactly what the live
///   self-test and `aitm`-on-PATH operators rely on until Task 9 bundles the core.
/// - **External.** Stop the embedded core (if any) and point the bus at the
///   operator's `config.yaml` / Settings endpoint.
@MainActor
final class LiveConnectionDriver: ActiveConnectionDriver {
    private let embedded: EmbeddedCoreController?
    private unowned let bus: BusService

    init(embedded: EmbeddedCoreController?, bus: BusService) {
        self.embedded = embedded
        self.bus = bus
    }

    var isEmbeddedRunning: Bool { embedded?.isRunning ?? false }

    func activateEmbedded() {
        guard let embedded else {
            // No bundled core: fall back to the external core so the app still
            // connects (dev builds, the live self-test, CLI operators).
            bus.useExternalEndpoint()
            return
        }
        bus.awaitEmbeddedEndpoint()
        embedded.start()
    }

    func activateExternal() {
        embedded?.stop()
        bus.useExternalEndpoint()
    }
}
