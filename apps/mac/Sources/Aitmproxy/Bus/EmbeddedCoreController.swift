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
    /// The shared surface the health dot and core-log panel read (Task 8); the
    /// controller mirrors status changes and captured output onto it.
    private unowned let health: CoreHealthState
    @ObservationIgnored private var pump: Task<Void, Never>?
    @ObservationIgnored private var terminateObserver: (any NSObjectProtocol)?

    /// Builds a controller for the bundled core, or `nil` when no core is
    /// bundled (development / non-`.app` builds) so the caller keeps the external
    /// path. `coreID` ties the connection to the id flows are stamped with
    /// (Task 5), so embedded flows carry this connection's identity.
    init?(coreID: CoreID, bus: BusService, health: CoreHealthState) {
        guard let binaries = EmbeddedCore.discoverBundled() else { return nil }
        self.bus = bus
        self.health = health
        self.core = EmbeddedCore(binaries: binaries, scopeURL: EmbeddedScope.url(in: Store.url))
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
        // Give the health surface (Task 8) the connection reference so the dot
        // reflects the core's real status from the first frame.
        health.connection = connection
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

    /// Restart the embedded core in place so Settings ▸ Proxy edits (listen port,
    /// upstream-TLS verification) take effect: stop the child and spawn a fresh one,
    /// which re-reads those settings. The event pump keeps running, so status flows
    /// stopped → starting → ready. Starts a stopped core instead of nothing.
    func restart() {
        guard isRunning else { start(); return }
        update { $0.status = .starting }
        Task { [core] in
            await core.stop()
            await core.start()
        }
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
            // Snapshot the Settings ▸ Proxy values this core was started with, so the
            // Proxy tab can disable Apply & Restart until an edit actually diverges.
            // Read the same keys and defaults EmbeddedCore reads at spawn.
            let defaults = Store.defaults
            // 8080 matches Settings ▸ Proxy's @AppStorage default and EmbeddedCore's default port.
            let appliedPort = defaults.object(forKey: "proxy.preferredPort") as? Int ?? 8080
            let appliedVerifyTLS = defaults.object(forKey: "proxy.verifyUpstreamTLS") as? Bool ?? true
            // The two system-proxy keys, with the defaults EmbeddedCore.spawn() uses; the bypass
            // field is kept as typed so the dirty-check compares what the operator sees.
            let appliedSystemProxyAuto = defaults.object(forKey: SystemProxyPreferences.autoKey) as? Bool ?? false
            let appliedSystemProxyBypass = SystemProxyPreferences.bypassField(defaults)
            update {
                $0.endpoint = runtime.endpoint
                $0.status = .ready
                let proxy = "127.0.0.1:\(runtime.proxyPort)"
                $0.proxyAddress = proxy
                $0.label = "Embedded core · proxy \(proxy)"
                $0.appliedPort = appliedPort
                $0.appliedVerifyUpstreamTLS = appliedVerifyTLS
                $0.appliedSystemProxyAuto = appliedSystemProxyAuto
                $0.appliedSystemProxyBypass = appliedSystemProxyBypass
            }
            // Point the live bus client at the core we just brought up.
            bus.useEmbeddedEndpoint(runtime.endpoint)
        case .log(let line):
            // Captured core output feeds the on-demand log panel (Task 8); the
            // health dot reads `connection.status`.
            health.record(line)
        }
    }

    private func update(_ mutate: (inout CoreConnection) -> Void) {
        var next = connection
        mutate(&next)
        connection = next
        registry.insert(next)
        // Keep the status-bar health dot current (Task 8).
        health.connection = next
    }

    /// Blocks briefly during quit to SIGTERM→reap the child so none is orphaned
    /// (AC7). `applicationWillTerminate` is synchronous, so the async stop runs
    /// on a detached task we wait on with a bounded timeout. The wait must exceed
    /// the child's full `SIGTERM`→grace→`SIGKILL` teardown so a force-kill always
    /// lands before the app exits even if the core ignores `SIGTERM`; hence the
    /// grace plus a 2 s margin.
    private static let quitWaitSeconds = EmbeddedCoreLaunch.childStopGraceSeconds + 2
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
        _ = done.wait(timeout: .now() + .seconds(Self.quitWaitSeconds))
    }

    isolated deinit {
        pump?.cancel()
        if let terminateObserver { NotificationCenter.default.removeObserver(terminateObserver) }
    }
}
