import AitmBusClient
import AitmproxyKit
import SwiftUI

/// The Settings window (Command-Comma). One tab per topic; each a grouped
/// Form sized to its content.
struct SettingsView: View {
    @Environment(Session.self) private var session

    var body: some View {
        @Bindable var session = session
        TabView(selection: $session.settingsTab) {
            ForEach(SettingsTab.allCases) { tab in
                page(tab)
                    .tabItem { Label(tab.title, systemImage: tab.symbol) }
                    .tag(tab)
            }
        }
        .noInitialFocus()
    }

    @ViewBuilder
    private func page(_ tab: SettingsTab) -> some View {
        Form {
            switch tab {
            case .general: GeneralSettings()
            case .bus: BusSettings()
            case .proxy: ProxySettings()
            case .capture: CaptureSettings()
            case .appearance: AppearanceSettings()
            }
        }
        .formStyle(.grouped)
        .fitsContent()
        .frame(width: 520)
    }
}

/// The Settings tabs. Snapshot mode walks through every case.
enum SettingsTab: String, CaseIterable, Identifiable {
    case general, bus, proxy
    /// L4 capture: the operator's on/off, its state, and the extension's uninstall.
    case capture
    case appearance

    var id: String { rawValue }

    var title: String {
        switch self {
        case .general: "General"
        case .bus: "Bus"
        case .proxy: "Proxy"
        case .capture: "Capture"
        case .appearance: "Appearance"
        }
    }

    var symbol: String {
        switch self {
        case .general: "gearshape"
        case .bus: "network"
        case .proxy: "lock.shield"
        case .capture: "antenna.radiowaves.left.and.right"
        case .appearance: "paintpalette"
        }
    }
}

struct GeneralSettings: View {
    @Environment(Session.self) private var session

    var body: some View {
        @Bindable var session = session
        Section("Flow list") {
            Picker("Row density", selection: $session.density) {
                ForEach(Density.allCases) { density in
                    Text("\(density.title) (\(Int(density.rowHeight)) pt)").tag(density)
                }
            }
            Toggle("Auto-select new flows", isOn: $session.autoSelect)
        }
    }
}

/// How the app reaches the proxy's command bus (foundation §4.2): a switchable,
/// persistent choice between the bundled embedded core and an external one
/// (Task 7, AC10).
struct BusSettings: View {
    @Environment(Session.self) private var session
    @AppStorage(UserDefaultsActiveKindPersistence.key, store: Store.defaults) private var activeKindRaw = ActiveCoreKind.embedded.rawValue
    @AppStorage(BusEndpointSettings.Key.host, store: Store.defaults) private var host = "127.0.0.1"
    @AppStorage(BusEndpointSettings.Key.port, store: Store.defaults) private var port = 9090
    @AppStorage(BusEndpointSettings.Key.tokenFile, store: Store.defaults) private var tokenFile = ""
    @AppStorage(BusEndpointSettings.Key.fromConfig, store: Store.defaults) private var fromConfig = true
    /// The operator token, pasted by a human. Empty ⇒ connect as agent with the
    /// config token (spec Decision E). A `SecureField` keeps it off the screen;
    /// it is never printed or logged.
    @AppStorage(BusEndpointSettings.Key.operatorToken, store: Store.defaults) private var operatorToken = ""
    /// What role the operator expects the connection to resolve to. Client-side
    /// only — it never travels to the server, it only drives the warning.
    @AppStorage(BusEndpointSettings.Key.expectedRole, store: Store.defaults) private var expectedRole = ExpectedRole.agent.rawValue

    private var activeKind: ActiveCoreKind { ActiveCoreKind(rawValue: activeKindRaw) ?? .embedded }
    private var usesExternal: Bool { activeKind == .external }

    var body: some View {
        Section("Core") {
            Picker("Active core", selection: Binding(
                get: { activeKind },
                set: { kind in
                    activeKindRaw = kind.rawValue
                    // Drive the live start/stop + make-active transition. The model
                    // persists the choice too; it is nil only in fixture/snapshot runs.
                    session.connection?.select(kind)
                }
            )) {
                ForEach(ActiveCoreKind.allCases) { Text($0.title).tag($0) }
            }
            Text(usesExternal
                 ? "Connects to a core you run yourself; the embedded core stops."
                 : "The app runs its own bundled core. Choose External to use your own.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        Section("External connection") {
            Toggle("Read address and token from aitmproxy's config.yaml", isOn: $fromConfig)
            TextField("Host", text: $host).disabled(fromConfig)
            TextField("Port", value: $port, format: .number.grouping(.never)).disabled(fromConfig)
            TextField("Token file", text: $tokenFile, prompt: Text("~/Library/Application Support/aitmproxy/mcp.token"))
                .disabled(fromConfig)
            Text("Used when the active core is External.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .disabled(!usesExternal)
        Section("Role") {
            SecureField("Operator token", text: $operatorToken, prompt: Text("Paste to connect as operator"))
            Picker("Expected role", selection: $expectedRole) {
                ForEach(ExpectedRole.allCases) { role in
                    Text(role.title).tag(role.rawValue)
                }
            }
            Text("Paste an operator token and reconnect (⌃⌘R) to connect as operator.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }
}

/// Settings ▸ Proxy: the embedded core's editable config — the proxy listen port and
/// upstream TLS verification. Changes persist to UserDefaults and apply when the bundled
/// core restarts (EmbeddedCore re-reads them each spawn). An external core is governed by
/// its own config.yaml, so the controls are read-only then.
struct ProxySettings: View {
    @Environment(Session.self) private var session
    @AppStorage(UserDefaultsActiveKindPersistence.key, store: Store.defaults) private var activeKindRaw = ActiveCoreKind.embedded.rawValue
    @AppStorage("proxy.preferredPort", store: Store.defaults) private var port = 8080
    @AppStorage("proxy.verifyUpstreamTLS", store: Store.defaults) private var verifyTLS = true

    private var usesEmbedded: Bool { (ActiveCoreKind(rawValue: activeKindRaw) ?? .embedded) == .embedded }

    /// Apply & Restart is live only for the embedded core and only once an edit
    /// diverges from what the running core was started with. With no applied
    /// snapshot yet (no core up, or a fixture) it stays live so a first Apply can
    /// start the core.
    private var canApply: Bool {
        guard usesEmbedded else { return false }
        guard let connection = session.coreHealth.connection,
              let appliedPort = connection.appliedPort,
              let appliedVerifyTLS = connection.appliedVerifyUpstreamTLS else { return true }
        return port != appliedPort || verifyTLS != appliedVerifyTLS
    }

    var body: some View {
        @Bindable var session = session
        Section("Embedded proxy") {
            TextField("Listen port", value: $port, format: .number.grouping(.never))
            if usesEmbedded, let bound = session.coreHealth.connection?.proxyAddress,
               Self.port(from: bound) != port {
                LabeledContent("Bound address", value: bound)
            }
            Toggle("Verify upstream TLS", isOn: $verifyTLS)
            if !verifyTLS {
                Text("Disabling TLS verification lets the proxy trust any upstream certificate. Use it only to reach a server with a self-signed or mismatched cert — never on an untrusted network.")
                    .font(.callout)
                    .foregroundStyle(Tok.Status.serverError.color)
            }
        }
        .disabled(!usesEmbedded)
        Section {
            Button("Apply and Restart Core") { session.restartCoreTick += 1 }
                .disabled(!canApply)
            Text(usesEmbedded
                 ? "The bundled core restarts to apply these — the proxy and bus briefly drop and rebind. If the chosen port is taken, the core picks a free one, shown above as the bound address."
                 : "The active core is external; its port and TLS come from the config.yaml it was launched with. Switch to the embedded core in Bus to manage them here.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    /// The port in a `host:port` bound address, for comparing against the preferred port.
    private static func port(from address: String) -> Int? {
        Int(address.split(separator: ":").last ?? "")
    }
}

/// Settings ▸ Capture: the operator's switch for L4 capture on this Mac, what the capture
/// extension is doing, and its uninstall (Task 17, NE-AC15). Capture is off until the
/// operator turns it on here or with Proxy ▸ Enable Capture. Reads the capability the
/// `ExtensionController` pushes into `CoreHealthState`. With no extension in this build
/// (a development build, fixture and snapshot runs) the controls give way to a note: a
/// toggle that does nothing is never shown.
///
/// Turning capture on or off, and uninstalling, are the operator's controls and nothing
/// else: there is no bus, MCP or `Session` verb for them (the controller documents why).
/// `CaptureSwitch` holds the steps, shared with the menu command.
///
/// Like Settings ▸ Proxy, the toggle is live only while the embedded core is the active
/// one: capture is the embedded core's `macos_capture` gate, and turning it on restarts
/// that core, which an external choice must not do. With an external core active the toggle
/// is disabled and a note says where to change it.
struct CaptureSettings: View {
    @Environment(Session.self) private var session
    @AppStorage(UserDefaultsActiveKindPersistence.key, store: Store.defaults) private var activeKindRaw = ActiveCoreKind.embedded.rawValue
    /// The persisted choice, `false` until the operator turns capture on. Read here only:
    /// `CaptureSwitch` writes it, at the point in its steps where it must be written.
    @AppStorage("capture.enabled", store: Store.defaults) private var captureEnabled = false
    @State private var confirming = false
    @State private var removing = false

    private var usesEmbedded: Bool { (ActiveCoreKind(rawValue: activeKindRaw) ?? .embedded) == .embedded }

    var body: some View {
        let health = session.coreHealth
        let capability = health.captureCapability
        Section("Network extension") {
            if health.captureControlsAvailable {
                Toggle("Capture L4 traffic", isOn: Binding(
                    get: { health.captureChoice ?? captureEnabled },
                    set: { on in Task { await CaptureSwitch.set(on, session: session) } }
                ))
                .disabled(health.captureBusy || !usesEmbedded)
                if !usesEmbedded {
                    Text("The active core is external, so capture is not controlled from here. Switch to the embedded core in Bus to turn it on or off.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Text("The first time you turn this on, macOS asks twice in System Settings: approve the extension under Network Extensions, then allow Add Proxy Configurations.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                LabeledContent("Status") {
                    if health.captureBusy {
                        Label {
                            Text("Working…")
                        } icon: {
                            ProgressView().controlSize(.small)
                        }
                    } else {
                        Label {
                            Text(capability.title)
                        } icon: {
                            Image(systemName: symbol(for: capability))
                                .foregroundStyle(capability.isCaptureOn ? Palette.accent : Color.secondary)
                        }
                    }
                }
                if let reason = capability.degradedReason {
                    Text(reason)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                if capability.canUninstall {
                    Button(removing ? "Removing…" : "Uninstall Capture Extension…", role: .destructive) {
                        confirming = true
                    }
                    .disabled(removing || health.captureBusy)
                    .confirmationDialog(
                        "Uninstall the capture extension?", isPresented: $confirming, titleVisibility: .visible
                    ) {
                        Button("Uninstall", role: .destructive, action: uninstall)
                    } message: {
                        Text("Capture stops, and the extension and its proxy configuration are removed. Turning capture on again installs the extension again and asks for approval again.")
                    }
                }
            } else {
                LabeledContent("Capture L4 traffic", value: "Not available in this build")
                Text("L4 capture needs the signed Aitmproxy app with its capture extension. This build does not include it.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func symbol(for capability: CaptureCapability) -> String {
        switch capability {
        case .extensionNotInstalled: "circle.slash"
        case .pendingApproval: "hourglass"
        case .approvedAttached: "checkmark.circle"
        case .capturing: "record.circle.fill"
        case .degraded: "exclamationmark.triangle"
        case .inactive: "pause.circle"
        }
    }

    private func uninstall() {
        removing = true
        Task {
            await CaptureSwitch.uninstall(session: session)
            removing = false
        }
    }
}

/// The operator's capture on, off and uninstall, in one place so Settings ▸ Capture and
/// Proxy ▸ Enable/Disable Capture run identical steps. Operator-only: those two callers
/// are all there is. No bus verb, `Session` action or palette entry reaches `enable()`,
/// `disable()`, `uninstall()` or the persisted `capture.enabled` choice (see
/// `ExtensionController`).
///
/// Actions are serialized on `CoreHealthState.captureBusy`: one that arrives while another
/// runs is dropped (the controls are disabled meanwhile), and asking for the state already
/// in force does nothing, so there is no second activation request and no needless core
/// restart. Each action ends by bumping `restartCoreTick`, which `ShellView` maps to an
/// embedded-core restart, so the respawned core re-reads `capture.enabled` and opens or
/// closes its capture gate. Only while the embedded core is the active one: with an external
/// core active the toggle does nothing and an uninstall bumps no restart, because that
/// restart would start the embedded core the operator switched away from.
enum CaptureSwitch {
    /// Whether the embedded core is the active kind: the choice Settings ▸ Bus persists,
    /// read the way `ActiveConnectionModel` and `ProxySettings.usesEmbedded` read it
    /// (embedded when unset). The toggle and the menu command, which cannot see the views'
    /// `@AppStorage`, gate on this.
    static var embeddedCoreActive: Bool {
        (UserDefaultsActiveKindPersistence(defaults: Store.defaults).load() ?? .embedded) == .embedded
    }

    /// ON: persist the choice, activate the extension, then respawn the core so its capture
    /// gate opens. OFF: persist the choice first, so a crash part-way fails toward off, then
    /// stop the tunnel, then respawn the core so the gate closes. Returns when the steps are
    /// done. Does nothing without an extension controller (no embedded extension in this
    /// run), or unless the embedded core is the active kind. The same-value check reads the
    /// key as `spawn()` and `start()` do, so a stored value that is not a Bool reads as off
    /// and cannot lock turning capture on out.
    static func set(_ on: Bool, session: Session) async {
        let health = session.coreHealth
        guard !health.captureBusy, health.extensionController != nil, embeddedCoreActive,
              on != (Store.defaults.object(forKey: "capture.enabled") as? Bool ?? false)
        else { return }
        health.captureBusy = true
        health.captureChoice = on
        defer {
            health.captureChoice = nil
            health.captureBusy = false
        }
        if on {
            Store.defaults.set(true, forKey: "capture.enabled")
            health.extensionController?.enable()
            session.restartCoreTick += 1
        } else {
            Store.defaults.set(false, forKey: "capture.enabled")
            await health.extensionController?.disable()
            session.restartCoreTick += 1
        }
    }

    /// Removes the extension and its proxy configuration. A finished uninstall also switches
    /// the persisted choice off and respawns the core, so the toggle, the menu command and
    /// the next launch agree that nothing is installed; left on, the choice would install
    /// the extension again at the next launch and ask for approval. The respawn happens only
    /// while the embedded core is the active one; the choice is cleared either way.
    static func uninstall(session: Session) async {
        let health = session.coreHealth
        guard !health.captureBusy else { return }
        health.captureBusy = true
        defer { health.captureBusy = false }
        await health.extensionController?.uninstall()
        guard health.captureCapability == .extensionNotInstalled,
              Store.defaults.object(forKey: "capture.enabled") as? Bool ?? false
        else { return }
        Store.defaults.set(false, forKey: "capture.enabled")
        if embeddedCoreActive { session.restartCoreTick += 1 }
    }
}
