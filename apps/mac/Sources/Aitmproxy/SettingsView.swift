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

/// How the app reaches the proxy's command bus (foundation §4.2).
struct BusSettings: View {
    @AppStorage("bus.host") private var host = "127.0.0.1"
    @AppStorage("bus.port") private var port = 9090
    @AppStorage("bus.tokenFile") private var tokenFile = ""
    @AppStorage("bus.fromConfig") private var fromConfig = true

    var body: some View {
        Section("Connection") {
            Toggle("Read address and token from aitmproxy's config.yaml", isOn: $fromConfig)
            TextField("Host", text: $host).disabled(fromConfig)
            TextField("Port", value: $port, format: .number).disabled(fromConfig)
            TextField("Token file", text: $tokenFile, prompt: Text("~/Library/Application Support/aitmproxy/mcp.token"))
                .disabled(fromConfig)
        }
        Section {
            Text("The app connects as an operator (clientInfo `aitm-mac`) over loopback TCP and never acts as the agent.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }
}
