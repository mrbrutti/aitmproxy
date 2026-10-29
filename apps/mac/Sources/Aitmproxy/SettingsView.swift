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
    case general, bus, appearance

    var id: String { rawValue }

    var title: String {
        switch self {
        case .general: "General"
        case .bus: "Bus"
        case .appearance: "Appearance"
        }
    }

    var symbol: String {
        switch self {
        case .general: "gearshape"
        case .bus: "network"
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
    @AppStorage(UserDefaultsActiveKindPersistence.key) private var activeKindRaw = ActiveCoreKind.embedded.rawValue
    @AppStorage("bus.host") private var host = "127.0.0.1"
    @AppStorage("bus.port") private var port = 9090
    @AppStorage("bus.tokenFile") private var tokenFile = ""
    @AppStorage("bus.fromConfig") private var fromConfig = true
    /// The operator token, pasted by a human. Empty ⇒ connect as agent with the
    /// config token (spec Decision E). A `SecureField` keeps it off the screen;
    /// it is never printed or logged.
    @AppStorage("bus.operatorToken") private var operatorToken = ""
    /// What role the operator expects the connection to resolve to. Client-side
    /// only — it never travels to the server, it only drives the warning.
    @AppStorage("bus.expectedRole") private var expectedRole = ExpectedRole.agent.rawValue

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
                 ? "Connect to an aitm core you run yourself. Enter its address below, or launch the app with `--bus host:port` and `--token`/`--token-file`. The embedded core stops while External is active and starts again when you switch back."
                 : "Embedded is the default: the app bundles its own aitm core and manages it, starting it on launch and stopping it on quit. Nothing to install separately. Choose External to point the app at a core you run yourself.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        Section("External connection") {
            Toggle("Read address and token from aitmproxy's config.yaml", isOn: $fromConfig)
            TextField("Host", text: $host).disabled(fromConfig)
            TextField("Port", value: $port, format: .number).disabled(fromConfig)
            TextField("Token file", text: $tokenFile, prompt: Text("~/Library/Application Support/aitmproxy/mcp.token"))
                .disabled(fromConfig)
        }
        .disabled(!usesExternal)
        Section("Role") {
            SecureField("Operator token", text: $operatorToken, prompt: Text("Paste to connect as operator"))
            Picker("Expected role", selection: $expectedRole) {
                ForEach(ExpectedRole.allCases) { role in
                    Text(role.title).tag(role.rawValue)
                }
            }
        }
        Section {
            Text("""
                With no operator token the app connects as an agent using the token in config.yaml, \
                and is gated exactly as an agent. Paste the operator token to connect as operator; \
                reconnect (Proxy ▸ Reconnect Bus, ⌃⌘R) to apply it. The role the bus assigns is \
                shown in the status bar, with a warning when it differs from the expected role.
                """)
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }
}
