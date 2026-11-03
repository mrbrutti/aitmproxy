import AitmBusClient
import AitmproxyKit
import Foundation

/// A managed child `aitm` core: the macOS app's own embedded proxy, spawned and
/// supervised exactly as `tui`/`web` own their in-process cores — just as a
/// child process (spec C2). One actor owns one child's whole lifecycle:
///
/// - **Launch.** Fresh CSPRNG bus token, an auto-picked free proxy port, the
///   operator's persisted scope (`scope.json`, read fresh every spawn), a `0600`
///   per-launch config in the app container, then spawn the bundled `aitm` with
///   a loopback bus on an ephemeral port.
/// - **Rendezvous.** The child publishes its bound bus `host:port` (token-free)
///   to a file after bind (Task 3); the actor watches it, pairs the address with
///   the token it already holds, and emits `.ready`.
/// - **Stop.** `SIGTERM`, a grace budget, then `SIGKILL`; reap; delete the temp
///   and rendezvous files. Idempotent and crash-legible: no orphan survives.
/// - **Restart.** An unexpected child exit triggers a bounded exponential-backoff
///   restart (fresh token + port each time); past the cap it reports `.degraded`
///   with the captured stderr tail rather than looping forever.
///
/// Events flow out over `events`; a main-actor controller maps them onto a
/// `CoreConnection` and feeds the bus client. The full spawn is exercised by the
/// live self-test (Task 9); the pure helpers it leans on are unit-tested
/// (`EmbeddedCoreLaunch`).
actor EmbeddedCore {
    /// The bundled binaries this core runs.
    struct Binaries: Sendable {
        var core: URL
        var obscura: URL
    }

    /// What the app needs once the core is up: where to connect, and the ports
    /// it actually bound (the proxy port may be an auto-chosen alternate — AC9).
    struct Runtime: Sendable {
        var endpoint: BusEndpoint
        var proxyPort: UInt16
        var browserProxyPort: UInt16
    }

    /// Lifecycle signals, consumed by the controller and mapped to
    /// `CoreConnection.Status`.
    enum Event: Sendable {
        case status(CoreConnection.Status)
        case ready(Runtime)
        /// One captured stdout/stderr line (token-free by construction — Layer A).
        case log(String)
    }

    // MARK: Tunables

    private let defaultProxyPort: UInt16
    private let defaultBrowserProxyPort: UInt16
    /// `SIGTERM` → wait this long → `SIGKILL`. Must exceed the embedded core's own
    /// obscura teardown budget (`EmbeddedCoreLaunch.obscuraStopTimeoutSeconds` + the
    /// core's 1 s reap margin) so a clean `SIGTERM` always suffices and `SIGKILL`
    /// never lands mid-teardown and orphans obscura (AC7).
    private let stopGrace: Duration = .seconds(EmbeddedCoreLaunch.childStopGraceSeconds)
    /// How long to wait for the rendezvous file after a spawn before giving up on it.
    private let rendezvousTimeout: Duration = .seconds(15)
    /// Restart backoff: `base * factor^(n-1)`, capped, up to `maxRestarts` tries.
    private let backoffBase: Duration = .milliseconds(500)
    private let backoffCap: Duration = .seconds(10)
    private let maxRestarts = 5
    /// How many trailing captured lines to keep in the rolling buffer.
    private let tailLines = 40
    /// How many of those trailing lines to surface in a `.degraded` reason when a
    /// restart gives up — a short, legible tail, not the whole buffer.
    private let degradedTailLines = 8

    // MARK: State

    private let binaries: Binaries
    /// Where the operator's persisted embedded scope lives (`EmbeddedScope.url(in: Store.url)`),
    /// injected by the controller: `Store` is main-actor isolated, and reading it here would
    /// put a suspension point between `spawn()`'s `stopping` guard and `process.run()`.
    private let scopeURL: URL
    /// Immutable and `Sendable`, so a consumer reads it without hopping onto the actor.
    nonisolated let events: AsyncStream<Event>
    private let emit: AsyncStream<Event>.Continuation

    private var child: Child?
    /// Bumped per spawn so a stale termination handler from an old child is ignored.
    private var generation = 0
    private var restarts = 0
    private var stopping = false
    private var started = false
    private var logTail: [String] = []

    /// One running child and the files it owns.
    private final class Child: @unchecked Sendable {
        let process: Process
        let configURL: URL
        let endpointURL: URL
        let workDir: URL
        var reapedNormally = false
        init(process: Process, configURL: URL, endpointURL: URL, workDir: URL) {
            self.process = process
            self.configURL = configURL
            self.endpointURL = endpointURL
            self.workDir = workDir
        }
    }

    init(binaries: Binaries, scopeURL: URL, defaultProxyPort: UInt16 = 8080, defaultBrowserProxyPort: UInt16 = 8083) {
        self.binaries = binaries
        self.scopeURL = scopeURL
        self.defaultProxyPort = defaultProxyPort
        self.defaultBrowserProxyPort = defaultBrowserProxyPort
        (events, emit) = AsyncStream.makeStream(bufferingPolicy: .bufferingNewest(256))
    }

    /// Looks for the core bundled into the running `.app` under
    /// `Contents/Resources/core/{aitm,obscura}` (Task 9 puts them there). Returns
    /// `nil` in development or any build without the bundle, so the app falls
    /// back to an external core and the embedded path stays dormant and testable.
    static func discoverBundled() -> Binaries? {
        guard let resources = Bundle.main.resourceURL else { return nil }
        let dir = resources.appending(path: "core", directoryHint: .isDirectory)
        let core = dir.appending(path: "aitm")
        let obscura = dir.appending(path: "obscura")
        guard FileManager.default.isExecutableFile(atPath: core.path) else { return nil }
        return Binaries(core: core, obscura: obscura)
    }

    // MARK: Lifecycle

    /// Starts the core and keeps it running (restarting on crash) until `stop()`.
    func start() async {
        guard !started else { return }
        started = true
        stopping = false
        restarts = 0
        await spawn()
    }

    /// Stops the core for good: terminate the child, reap it, delete its files.
    /// Idempotent — safe to call from quit and from an error path.
    func stop() async {
        stopping = true
        started = false
        await teardownChild()
        emit.yield(.status(.stopped))
    }

    // MARK: Spawn

    private func spawn() async {
        guard !stopping else { return }
        emit.yield(.status(.starting))

        // Two distinct per-launch tokens: the agent token the loopback transport
        // requires (left for an agent that may attach), and the operator token the
        // app itself connects with so it is classified `Frontend::Operator` — a
        // present human that may widen scope from the Scope panel. Both are 256-bit
        // CSPRNG draws, so they never collide in practice.
        let token = EmbeddedCoreLaunch.freshToken()
        let operatorToken = EmbeddedCoreLaunch.freshToken()
        // Operator-editable (Settings ▸ Proxy), read fresh each spawn so Apply &
        // Restart Core picks them up: the preferred listen port and whether to verify
        // upstream TLS. Unset values fall back to the secure defaults.
        let defaults = Store.defaults
        let savedPort = defaults.integer(forKey: "proxy.preferredPort")
        let preferredPort = (savedPort > 0 && savedPort <= 65535) ? UInt16(savedPort) : defaultProxyPort
        let sslInsecure = !(defaults.object(forKey: "proxy.verifyUpstreamTLS") as? Bool ?? true)
        // Settings ▸ Capture toggle: off unless the operator turned it on. Read fresh
        // here too so Apply & Restart Core flips the core's `macos_capture` gate. A build
        // that does not embed the capture extension (a development build sharing this
        // defaults domain with a signed one) never opens the gate, whatever the key says.
        let captureEnabled = (defaults.object(forKey: "capture.enabled") as? Bool ?? false) && CaptureExtension.isEmbedded(inApp: Bundle.main.bundleURL)
        // Settings ▸ Proxy's system-proxy choices (spec §D13): "Set system proxy at launch"
        // and the "Bypass hosts" field, read fresh here too so Apply & Restart Core applies
        // them; they ride the per-launch config as the top-level `system_proxy:` block.
        let systemProxyAuto = defaults.object(forKey: SystemProxyPreferences.autoKey) as? Bool ?? false
        let systemProxyBypass = SystemProxyPreferences.bypassHosts(SystemProxyPreferences.bypassField(defaults))
        // The operator's persisted scope rides the per-launch config, read fresh every spawn
        // so relaunch, crash-restart and Apply & Restart Core all keep it; nothing is pushed
        // over the bus (D3). `load` already dropped anything unsafe to emit.
        let scopeHosts = EmbeddedScope.load(from: scopeURL).hosts
        guard let proxyPort = EmbeddedCoreLaunch.pickProxyPort(preferred: preferredPort),
              let browserProxyPort = EmbeddedCoreLaunch.pickProxyPort(preferred: defaultBrowserProxyPort)
        else {
            await failPermanently("could not find a free proxy port")
            return
        }

        let workDir: URL
        let configURL: URL
        let endpointURL: URL
        do {
            workDir = try makeWorkDir()
            configURL = workDir.appending(path: "config.yaml")
            endpointURL = workDir.appending(path: "bus.endpoint")
            // A stale rendezvous from a killed prior run must not be read as this
            // core's address: start from a clean slate (Rust truncates on write).
            try? FileManager.default.removeItem(at: endpointURL)
            let config = EmbeddedCoreLaunch.Config(
                obscuraBinary: binaries.obscura,
                proxyPort: proxyPort,
                browserProxyPort: browserProxyPort,
                token: token,
                operatorToken: operatorToken,
                endpointFile: endpointURL,
                sslInsecure: sslInsecure,
                captureEnabled: captureEnabled,
                scopeHosts: scopeHosts,
                systemProxyAuto: systemProxyAuto,
                systemProxyBypass: systemProxyBypass,
                // A harness run (dev bundle `APP_STORE`, live self-test `APP_LIVE=1`) keeps
                // its durable audit under its own directory, never the operator's real
                // `audit.jsonl`; a normal launch passes nil and the config is unchanged.
                auditLogFile: EmbeddedCoreLaunch.harnessAuditLogFile(
                    environment: ProcessInfo.processInfo.environment, workDir: workDir)
            )
            try EmbeddedCoreLaunch.writeConfig(config.yaml(), to: configURL)  // yaml() escapes/validates spliced paths
        } catch {
            await retryOrFail("writing the core config failed: \(error.localizedDescription)")
            return
        }

        generation += 1
        let thisGeneration = generation
        let process = Process()
        process.executableURL = binaries.core
        process.arguments = ["--config", configURL.path]
        // The curated default log level (Task 3) applies when RUST_LOG is unset.
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "RUST_LOG")
        environment["AITM_OBSCURA_BIN"] = binaries.obscura.path
        // A dev bundle, harness or live self-test (an overridden store) publishes its core pointer
        // under its own store, never in the operator's run dir: otherwise the CLI's one-shots see
        // "two running cores" beside the installed app (seen on the 0.5.14 acceptance run). The
        // installed app keeps the core's default dir, which is where the CLI looks. An explicit
        // AITM_RUN_DIR in the launch environment wins over the store's (the core's own rule: a
        // non-empty AITM_RUN_DIR is the operator's choice).
        if (environment[EmbeddedCoreLaunch.runDirEnvironmentKey] ?? "").isEmpty,
           let runDir = EmbeddedCoreLaunch.isolatedRunDir(environment: environment) {
            environment[EmbeddedCoreLaunch.runDirEnvironmentKey] = runDir.path
        }
        process.environment = environment

        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err
        captureOutput(out, err)

        process.terminationHandler = { [weak self] proc in
            guard let self else { return }
            Task { await self.childExited(generation: thisGeneration, status: proc.terminationStatus) }
        }

        do {
            try process.run()
        } catch {
            await retryOrFail("spawning the core failed: \(error.localizedDescription)")
            return
        }

        child = Child(process: process, configURL: configURL, endpointURL: endpointURL, workDir: workDir)
        emit.yield(.status(.connecting))
        // Dial the embedded bus with the OPERATOR token: the app is a present human,
        // so it connects as `Frontend::Operator` and its Scope panel may widen scope.
        await awaitRendezvous(generation: thisGeneration, token: operatorToken,
                              proxyPort: proxyPort, browserProxyPort: browserProxyPort,
                              endpointURL: endpointURL)
    }

    /// Polls the rendezvous file until the core publishes its bound bus address,
    /// then emits `.ready`. If the child dies first, `childExited` drives the
    /// restart; this just stops watching.
    private func awaitRendezvous(
        generation: Int, token: String, proxyPort: UInt16, browserProxyPort: UInt16, endpointURL: URL
    ) async {
        let deadline = ContinuousClock.now.advanced(by: rendezvousTimeout)
        while generation == self.generation, !stopping, child?.process.isRunning == true {
            if let contents = try? String(contentsOf: endpointURL, encoding: .utf8),
               let endpoint = EmbeddedCoreLaunch.parseEndpoint(fromFileContents: contents, token: token) {
                restarts = 0
                emit.yield(.ready(Runtime(endpoint: endpoint, proxyPort: proxyPort, browserProxyPort: browserProxyPort)))
                emit.yield(.status(.ready))
                return
            }
            if ContinuousClock.now >= deadline {
                // Bound but never published: treat as a failed start.
                await teardownChild()
                await retryOrFail("the core did not publish its bus address within \(rendezvousTimeout)")
                return
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
    }

    // MARK: Exit handling

    private func childExited(generation: Int, status: Int32) async {
        guard generation == self.generation else { return }  // a superseded child
        guard !stopping, !(child?.reapedNormally ?? false) else { return }  // an orderly stop
        child = nil
        await retryOrFail("the core exited unexpectedly (status \(status))")
    }

    /// Backoff-and-respawn, or give up past the cap. The retry/backoff/cap
    /// decision is the pure, unit-tested `EmbeddedCoreLaunch.restartDecision`.
    private func retryOrFail(_ reason: String) async {
        guard !stopping else { return }
        emit.yield(.log(reason))
        restarts += 1
        switch EmbeddedCoreLaunch.restartDecision(
            restarts: restarts, maxRestarts: maxRestarts, base: backoffBase, cap: backoffCap
        ) {
        case .giveUp:
            await failPermanently(reason)
        case .retry(let backoff):
            emit.yield(.status(.degraded(reason: "restarting (\(restarts)/\(maxRestarts)): \(reason)")))
            try? await Task.sleep(for: backoff)
            await spawn()
        }
    }

    private func failPermanently(_ reason: String) async {
        started = false
        let detail = EmbeddedCoreLaunch.giveUpDetail(reason: reason, logTail: logTail, tailLines: degradedTailLines)
        emit.yield(.status(.degraded(reason: detail)))
    }

    // MARK: Teardown

    private func teardownChild() async {
        guard let child else { return }
        self.child = nil
        child.reapedNormally = true
        // Invalidate this child's pending termination handler so an intentional
        // teardown (stop, or a failed-start timeout) is never read as a crash and
        // does not trigger a second restart.
        generation += 1
        let process = child.process
        if process.isRunning {
            kill(process.processIdentifier, SIGTERM)
            let deadline = ContinuousClock.now.advanced(by: stopGrace)
            while process.isRunning, ContinuousClock.now < deadline {
                try? await Task.sleep(for: .milliseconds(50))
            }
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
                process.waitUntilExit()
            }
        }
        try? FileManager.default.removeItem(at: child.workDir)
    }

    // MARK: Output capture

    private func captureOutput(_ out: Pipe, _ err: Pipe) {
        for pipe in [out, err] {
            pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else {
                    if data.isEmpty { handle.readabilityHandler = nil }
                    return
                }
                Task { await self?.absorb(text) }
            }
        }
    }

    private func absorb(_ text: String) {
        for line in text.split(whereSeparator: \.isNewline) where !line.isEmpty {
            let entry = String(line)
            logTail.append(entry)
            if logTail.count > tailLines { logTail.removeFirst(logTail.count - tailLines) }
            emit.yield(.log(entry))
        }
    }

    // MARK: Files

    /// A fresh per-launch directory under the app's temp area for this core's
    /// config and rendezvous file.
    private func makeWorkDir() throws -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appending(path: "aitm-embedded-core", directoryHint: .isDirectory)
            .appending(path: UUID().uuidString, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        return dir
    }
}
