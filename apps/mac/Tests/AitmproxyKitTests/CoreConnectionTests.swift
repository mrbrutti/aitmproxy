import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct CoreConnectionTests {
    private func endpoint(port: UInt16) -> BusEndpoint {
        BusEndpoint(port: port, token: "tok-\(port)")
    }

    @Test func connection_registry_holds_many_exposes_one_active() {
        let embedded = CoreConnection(
            kind: .embedded,
            endpoint: endpoint(port: 9001),
            status: .ready,
            label: "Embedded core"
        )
        let external = CoreConnection(
            kind: .external,
            endpoint: endpoint(port: 9002),
            status: .connecting,
            label: "127.0.0.1:9002"
        )

        var registry = ConnectionRegistry()
        registry.insert(embedded)
        registry.insert(external)

        // Holds more than one entry (the multi-core / routing seam).
        #expect(registry.count == 2)
        #expect(Set(registry.all.map(\.id)) == [embedded.id, external.id])
        #expect(registry.connection(for: embedded.id) == embedded)

        // Exposes exactly one active connection, the chosen one.
        let activatedExternal = registry.setActive(external.id)
        #expect(activatedExternal)
        #expect(registry.activeID == external.id)
        #expect(registry.active == external)

        // The choice is switchable between held entries.
        let activatedEmbedded = registry.setActive(embedded.id)
        #expect(activatedEmbedded)
        #expect(registry.activeID == embedded.id)
        #expect(registry.active == embedded)
    }

    @Test func remote_constructs_but_is_not_selectable_as_active() {
        let remote = CoreConnection(
            kind: .remote,
            endpoint: endpoint(port: 9003),
            status: .stopped,
            label: "reserved"
        )
        // Reserved case constructs and is a real member of the closed set.
        #expect(remote.kind == .remote)
        #expect(!CoreConnection.Kind.remote.canBeActive)
        #expect(CoreConnection.Kind.embedded.canBeActive)
        #expect(CoreConnection.Kind.external.canBeActive)

        var registry = ConnectionRegistry()
        registry.insert(remote)
        #expect(registry.count == 1)
        // ...but it cannot be made the active connection yet.
        let activated = registry.setActive(remote.id)
        #expect(!activated)
        #expect(registry.activeID == nil)
        #expect(registry.active == nil)
    }

    @Test func setting_active_to_an_unknown_id_is_rejected() {
        var registry = ConnectionRegistry()
        let activated = registry.setActive(CoreID())
        #expect(!activated)
        #expect(registry.activeID == nil)
    }

    @Test func removing_the_active_connection_clears_the_active_choice() {
        let embedded = CoreConnection(
            kind: .embedded,
            endpoint: endpoint(port: 9004),
            status: .ready,
            label: "Embedded core"
        )
        var registry = ConnectionRegistry()
        registry.insert(embedded)
        let activated = registry.setActive(embedded.id)
        #expect(activated)
        #expect(registry.activeID == embedded.id)

        registry.remove(embedded.id)
        #expect(registry.count == 0)
        #expect(registry.activeID == nil)
        #expect(registry.active == nil)
    }

    @Test func core_ids_are_distinct_and_round_trip_through_their_raw_value() {
        #expect(CoreID() != CoreID())
        let id = CoreID()
        #expect(CoreID(rawValue: id.rawValue) == id)
    }

    @Test func degraded_status_carries_its_reason() {
        #expect(CoreConnection.Status.degraded(reason: "exit 1: boom")
            == .degraded(reason: "exit 1: boom"))
        #expect(CoreConnection.Status.degraded(reason: "exit 1: boom")
            != .degraded(reason: "other"))
    }
}
