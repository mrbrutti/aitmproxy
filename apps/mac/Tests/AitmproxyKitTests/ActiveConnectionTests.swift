import Foundation
import Testing
@testable import AitmproxyKit

@MainActor
@Suite struct ActiveConnectionTests {
    /// A stand-in for the live embedded-core controller + bus (Task 6): it only
    /// records whether the embedded core is running and which kind was last
    /// activated, so the switchable-active-connection state machine can be driven
    /// and asserted without spawning a real `aitm` child.
    private final class FakeDriver: ActiveConnectionDriver {
        var isEmbeddedRunning = false
        private(set) var activations: [ActiveCoreKind] = []

        func activateEmbedded() {
            isEmbeddedRunning = true
            activations.append(.embedded)
        }

        func activateExternal() {
            isEmbeddedRunning = false
            activations.append(.external)
        }
    }

    /// In-memory persistence so the choice round-trips across a simulated relaunch
    /// without touching the real `UserDefaults`.
    private final class MemoryPersistence: ActiveKindPersistence {
        var stored: ActiveCoreKind?
        func load() -> ActiveCoreKind? { stored }
        func save(_ kind: ActiveCoreKind) { stored = kind }
    }

    @Test func active_connection_switches_both_ways_without_disabling_embedded() {
        let driver = FakeDriver()
        let persistence = MemoryPersistence()
        let model = ActiveConnectionModel(driver: driver, persistence: persistence)

        // Default is embedded (O1). Applying the choice starts the embedded core
        // and makes it the active connection; construction alone has no effect.
        #expect(model.activeKind == .embedded)
        #expect(!driver.isEmbeddedRunning)
        model.activate()
        #expect(driver.isEmbeddedRunning)

        // Select external: external becomes active and the embedded core is not
        // running. The choice is persisted.
        model.select(.external)
        #expect(model.activeKind == .external)
        #expect(!driver.isEmbeddedRunning)
        #expect(persistence.stored == .external)

        // Select embedded again: the embedded core (re)starts and is active once
        // more — choosing external earlier did not permanently disable it.
        model.select(.embedded)
        #expect(model.activeKind == .embedded)
        #expect(driver.isEmbeddedRunning)
        #expect(persistence.stored == .embedded)

        // End on external so the relaunch below restores a non-default choice.
        model.select(.external)
        #expect(!driver.isEmbeddedRunning)
        #expect(persistence.stored == .external)

        // The persisted choice round-trips across a relaunch: a fresh model over
        // the same persistence restores external and, on activate, leaves the
        // embedded core stopped.
        let relaunchedDriver = FakeDriver()
        let relaunched = ActiveConnectionModel(driver: relaunchedDriver, persistence: persistence)
        #expect(relaunched.activeKind == .external)
        relaunched.activate()
        #expect(!relaunchedDriver.isEmbeddedRunning)

        // Both directions were exercised against the driver.
        #expect(driver.activations == [.embedded, .external, .embedded, .external])
    }

    @Test func missing_persisted_choice_defaults_to_embedded() {
        let persistence = MemoryPersistence()
        #expect(persistence.load() == nil)
        let model = ActiveConnectionModel(driver: FakeDriver(), persistence: persistence)
        #expect(model.activeKind == .embedded)
    }
}
