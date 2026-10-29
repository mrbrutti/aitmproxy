import AitmBusClient
import AitmproxyKit
import AppKit
import Foundation
import Observation

/// The main-actor owner of the embedded `aitm` core (Task 6): it starts the
/// `EmbeddedCore` actor, maps its lifecycle onto a `CoreConnection` the UI can
/// watch (health dot in Task 8), hands the resolved bus endpoint to the live
/// `BusService`, and guarantees teardown on app quit so no child is orphaned.
///
/// It registers the connection in its own `ConnectionRegistry` and makes it the
/// active one — the embedded default. The switchable, persisted external/embedded
/// choice and the Settings surface are Task 7; here the app simply runs its own
/// core when nothing external is configured.
@MainActor @Observable
final class EmbeddedCoreController {
    /// The live embedded connection, kept current as the core's status changes.
    private(set) var connection: CoreConnection
    /// The registry seam (Task 4): holds the embedded connection and tracks the
    /// single active one; shaped to hold more than one later.
    private(set) var registry = ConnectionRegistry()
    /// Whether the embedded core is currently supervised (Task 7): read by the
    /// active-connection driver to decide a switch and surface it in Settings.
    private(set) var isRunning = false

    private let core: EmbeddedCore
    private unowned let bus: BusService
    @ObservationIgnored private var pump: Task<Void, Never>?
    @ObservationIgnored private var terminateObserver: (any NSObjectProtocol)?

    /// Builds a controller for the bundled core, or `nil` when no core is
    /// bundled (development / non-`.app` builds) so the caller keeps the external
    /// path. `coreID` ties the connection to the id flows are stamped with
    /// (Task 5), so embedded flows carry this connection's identity.
    init?(coreID: CoreID, bus: BusService) {
        guard let binaries = EmbeddedCore.discoverBundled() else { return nil }
        self.bus = bus
        self.core = EmbeddedCore(binaries: binaries)
        self.connection = CoreConnection(
            id: coreID,
            kind: .embedded,
            endpoint: BusEndpoint(port: 0, token: ""),
            status: .starting,
            label: "Embedded core"
        )
        registry.insert(connection)
        // Not active until `start()` brings the core up (Task 7): a controller may
        // be built but left dormant while an external core is the active choice.
    }

    /// Spawns and supervises the core, pumping its events onto the main actor,
    /// and arms the quit teardown. Idempotent: calling it while already running
    /// does nothing, so switching back to embedded (Task 7) re-starts only a
    /// stopped core.
    func start() {
        guard !isRunning else { return }
        isRunning = true
        update { $0.status = .starting }
        registry.setActive(connection.id)
        pump = Task { [weak self, core] in
            for await event in core.events {
                self?.handle(event)
            }
        }
        Task { [core] in await core.start() }
        armTerminateObserver()
    }

    /// Stops the embedded core and makes it inactive (Task 7): used when the
    /// operator switches to an external core. The core can be started again later
    /// — external never permanently disables embedded.
    func stop() {
        guard isRunning else { return }
        isRunning = false
        pump?.cancel()
        pump = nil
        update { $0.status = .stopped }
        Task { [core] in await core.stop() }
    }

    /// Arm the quit teardown once, for the controller's lifetime, so an
    /// embedded→external→embedded cycle never stacks observers.
    private func armTerminateObserver() {
        guard terminateObserver == nil else { return }
        terminateObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.terminateSynchronously() }
        }
    }

    private func handle(_ event: EmbeddedCore.Event) {
        switch event {
        case .status(let status):
            update { $0.status = status }
        case .ready(let runtime):
            update {
                $0.endpoint = runtime.endpoint
                $0.status = .ready
                $0.label = "Embedded core · proxy 127.0.0.1:\(runtime.proxyPort)"
            }
            // Point the live bus client at the core we just brought up.
            bus.useEmbeddedEndpoint(runtime.endpoint)
        case .log:
            // Captured core output feeds the on-demand log panel (Task 8); the
            // health dot reads `connection.status`. Nothing to do here yet.
            break
        }
    }

    private func update(_ mutate: (inout CoreConnection) -> Void) {
        var next = connection
        mutate(&next)
        connection = next
        registry.insert(next)
    }

    /// Blocks briefly during quit to SIGTERM→reap the child so none is orphaned
    /// (AC7). `applicationWillTerminate` is synchronous, so the async stop runs
    /// on a detached task we wait on with a bounded timeout.
    private func terminateSynchronously() {
        if let terminateObserver {
            NotificationCenter.default.removeObserver(terminateObserver)
            self.terminateObserver = nil
        }
        pump?.cancel()
        let done = DispatchSemaphore(value: 0)
        Task.detached { [core] in
            await core.stop()
            done.signal()
        }
        _ = done.wait(timeout: .now() + 5)
    }

    isolated deinit {
        pump?.cancel()
        if let terminateObserver { NotificationCenter.default.removeObserver(terminateObserver) }
    }
}
