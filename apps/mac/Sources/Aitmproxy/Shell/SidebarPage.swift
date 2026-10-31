import AitmproxyKit

/// Where the operator can be: the sidebar's pages, the inspector's placement and the agent
/// policy the toolbar and the Agent page switch. Model enums with titles and symbols; the
/// state that picks among them lives on `Session`.
/// The sidebar's entries (foundation §2.6). Snapshot mode walks every case.
enum SidebarPage: String, CaseIterable, Identifiable {
    case status, flows, pinned, saved, apps, domains, overview, connections, scope, scan, findings, browser, scripts, agent, ca, config

    var id: String { rawValue }

    var title: String {
        switch self {
        case .status: "Status"
        case .flows: "Flows"
        case .pinned: "Pinned"
        case .saved: "Saved"
        case .apps: "Apps"
        case .domains: "Domains"
        case .overview: "Overview"
        case .connections: "Connection Log"
        case .scope: "Scope"
        case .scan: "Scan"
        case .findings: "Findings"
        case .browser: "Browser"
        case .scripts: "Scripts"
        case .agent: "Agent"
        case .ca: "Certificate Authority"
        case .config: "Configuration"
        }
    }

    var symbol: String {
        switch self {
        case .status: "waveform.path.ecg"
        case .flows: "list.bullet"
        case .pinned: Tok.Glyph.pin
        case .saved: "tray.full"
        case .apps: "app.badge"
        case .domains: Tok.Glyph.browser
        case .overview: "chart.bar"
        case .connections: "point.3.connected.trianglepath.dotted"
        case .scope: Tok.Glyph.scope
        case .scan: Tok.Glyph.search
        case .findings: Tok.Glyph.poc
        case .browser: Tok.Glyph.browser
        case .scripts: "chevron.left.forwardslash.chevron.right"
        case .agent: Tok.Glyph.agent
        case .ca: Tok.Glyph.lock
        case .config: "doc.text"
        }
    }

    /// Pages that show the flow list (the rest open their own panel).
    var showsFlows: Bool {
        switch self {
        case .flows, .pinned, .saved, .apps, .domains, .scope, .connections: true
        case .status, .overview, .scan, .findings, .browser, .scripts, .agent, .ca, .config: false
        }
    }

    /// CA and Configuration open from the Proxy menu and the palette; Status from the toolbar
    /// pill, ⌘0 and the palette; Saved waits for the core to save (S-066). None are list rows.
    var isInSidebar: Bool {
        switch self {
        case .ca, .config, .status, .saved: false
        default: true
        }
    }
}

/// Where the inspector sits (Proxyman's layouts): below, right, or in its own window.
enum InspectorLayout: String, CaseIterable {
    case horizontal, vertical, detached

    var title: String {
        switch self {
        case .horizontal: "Inspector Below"
        case .vertical: "Inspector Right"
        case .detached: "Inspector Detached"
        }
    }

    var symbol: String {
        switch self {
        case .horizontal: "rectangle.split.1x2"
        case .vertical: Tok.Glyph.split
        case .detached: "macwindow.on.rectangle"
        }
    }
}

/// The agent policy (foundation §4.8, F1).
enum AgentPolicy: String, CaseIterable {
    case all, readOnly, paused

    var title: String {
        switch self {
        case .all: "Allow all tools"
        case .readOnly: "Read-only"
        case .paused: "Paused"
        }
    }
}
