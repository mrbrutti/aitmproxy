import AitmBusClient
import AitmproxyKit
import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Certificate Authority (S-058): the CA's status, export PEM/DER, install or
/// uninstall after the proxy's own confirmation, the read-only agent-gate flag,
/// and setup guides for iOS, Android, browsers and terminals. The status is the
/// session's `ca.status` read-back (spec D17.5); Install…/Uninstall… route through
/// `Session.trustCA()` / `untrustCA()`, the app's one CA call path (D17.10).
struct CAPanel: View {
    @Environment(Session.self) private var session
    @State private var agentMayInstall = false
    @State private var busy = false
    /// Export errors; trust errors come from the session (`caTrustLastError`).
    @State private var actionError: String?

    /// The session's read-back; "No certificate" only for a connected core that has no `ca.status`
    /// verb at all, and the loading lines until the first read lands otherwise.
    private var status: CAStatus? {
        if let live = session.caStatus { return live }
        guard case .connected = session.bus, !session.tools.contains(where: { $0.name == "ca.status" }) else { return nil }
        return CAStatus(fingerprint: "", installed: false, trusted: false, exists: false)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.lg) {
                Text("Certificate Authority").font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                    .gridProbe("ca-title", area: "ca")
                if let status {
                    statusLine(status)
                        .gridProbe("ca-status", area: "ca")
                    buttons(status)
                    agentInstall
                    Rule()
                    guides
                } else {
                    LoadingLines().frame(height: 120) // grid: ok loading placeholder
                }
            }
            .padding(Space.xl)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Tok.Ground.surface.color)
        .gridArea("ca", inset: 0)
        .onAppear(perform: load)
    }

    private func statusLine(_ status: CAStatus) -> some View {
        VStack(alignment: .leading, spacing: Space.md) {
            HStack(spacing: Space.md) {
                Badge(text: status.statusText, pair: Self.statusPair(status), uppercase: false)
                if let expires = status.expires {
                    Text("expires \(expires.formatted(.dateTime.year().month(.abbreviated).day()))")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                }
            }
            if !status.fingerprint.isEmpty { fingerprint(status.fingerprint) }
            keyValue("Subject", status.subject)
            if let path = status.path { pathRow(path) }
            // The remedy is the read-back's word (D17.6), shown only while the OS store says not trusted.
            if let facts = session.caTrust, !facts.trusted, let remedy = facts.remedy {
                RemedyText(remedy, color: Tok.State.warning.fg)
            }
            if let failure = session.caTrustLastError { errorLabel(failure.line) }
            if let actionError { errorLabel(actionError) }
            Hint(text: CATrustFacts.quicCaveat)
        }
    }

    private func errorLabel(_ text: String) -> some View {
        Label(text, systemImage: "exclamationmark.triangle.fill")
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Status.serverError.color)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// Green when installed and trusted, amber when installed but not trusted, grey
    /// when present but not installed, red when the CA is missing.
    private static func statusPair(_ s: CAStatus) -> ColorPair {
        if s.installed, s.trusted { return Tok.State.success }
        if s.installed { return Tok.State.warning }
        if s.exists { return Tok.State.neutral }
        return Tok.State.danger
    }

    /// SHA-256 grouped into byte pairs, wrapping across lines, with a copy button.
    private func fingerprint(_ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Space.md) {
            Text("SHA-256").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: 72, alignment: .leading)
            Text(Self.grouped(value))
                .font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.primary.color)
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(value, forType: .string)
            } label: {
                Image(systemName: Tok.Glyph.copy).font(.system(size: Tok.Size.iconInline))
                    .foregroundStyle(Tok.Ink.secondary.color)
            }
            .buttonStyle(.plain).help("Copy fingerprint")
            Spacer(minLength: 0)
        }
    }

    /// Hex digits in space-separated pairs; falls back to the raw value if it has none.
    private static func grouped(_ s: String) -> String {
        let hex = s.filter(\.isHexDigit)
        var out = ""
        for (i, c) in hex.enumerated() {
            if i > 0, i.isMultiple(of: 2) { out.append(" ") }
            out.append(c)
        }
        return out.isEmpty ? s : out
    }

    private func keyValue(_ key: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Space.md) {
            Text(key).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: 72, alignment: .leading)
            Text(value).font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.primary.color)
                .textSelection(.enabled).lineLimit(1).truncationMode(.middle)
        }
    }

    /// The certificate path, with a jump to it in Finder.
    private func pathRow(_ path: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Space.md) {
            Text("Path").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: 72, alignment: .leading)
            Text(path).font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.primary.color)
                .textSelection(.enabled).lineLimit(1).truncationMode(.middle)
            FlatButton("Reveal in Finder", symbol: "folder") { reveal(path) }
            Spacer(minLength: 0)
        }
    }

    private func reveal(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    /// Whether the agent may install the CA — a read-only flag owned by config.yaml,
    /// shown as a labelled value with a pointer to where it is set.
    private var agentInstall: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            LabeledContent {
                Text(agentMayInstall ? "Yes" : "No")
                    .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            } label: {
                Text("Agent may install")
                    .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.primary.color)
            }
            .frame(maxWidth: 360, alignment: .leading)
            Hint(text: "Set by ca.allow_agent_install in config.yaml. Even when on, the agent's install still passes the proxy's confirmation.")
            FlatButton("Open Config", symbol: "doc.text") { session.show(.config) }
        }
    }

    private func buttons(_ status: CAStatus) -> some View {
        HStack(spacing: Space.sm) {
            FlatButton("Export PEM…") { export(format: "pem") }.disabled(busy || !status.exists)
            FlatButton("Export DER…") { export(format: "der") }.disabled(busy || !status.exists)
            Spacer()
            // Live only while the bus is the operator's and no change is in flight, like the sheet's button.
            if status.installed {
                FlatButton("Uninstall…") { change(install: false, status: status) }.disabled(busy || !session.caTrustControlLive)
            } else {
                PrimaryButton("Install…") { change(install: true, status: status) }
                    .disabled(busy || !session.caTrustControlLive || !status.exists)
            }
        }
    }

    private var guides: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            Text("SETUP").font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6).foregroundStyle(Tok.Ink.tertiary.color)
            ForEach(CAStatus.guides, id: \.title) { guide in
                VStack(alignment: .leading, spacing: Space.xs) {
                    Text(guide.title).font(Tok.Face.ui(Tok.Typography.Size.md, .semibold)).foregroundStyle(Tok.Ink.primary.color)
                    Text(guide.body).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: Actions

    private func load() {
        agentMayInstall = configFlag()
        Task {
            await session.refreshCAStatus()
            if session.caStatus?.allowAgentInstall == true { agentMayInstall = true }
        }
    }

    /// `ca.allow_agent_install` from the proxy's own config.yaml.
    private func configFlag() -> Bool {
        guard let yaml = try? String(contentsOf: BusService.configURL, encoding: .utf8) else { return false }
        return ConfigDocument(yaml: yaml, path: BusService.configURL.path, envOverrides: []).allowAgentInstall
    }

    private func export(format: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "aitmproxy-ca.\(format == "der" ? "der" : "pem")"
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                actionError = nil
                _ = try await session.runCommand("ca.export", ["format": .string(format), "path": .string(url.path)])
            } catch {
                let message = "ca.export: \(BusService.describe(error))"
                actionError = message
                session.lastError = message
            }
        }
    }

    /// The panel's own confirmation (the ellipsis promises one), then the session's one call
    /// path: scope, confirm token, in-flight flag, the forced `ca.status` re-read. The word
    /// after it is the read-back's, never the reply's.
    private func change(install: Bool, status: CAStatus) {
        let alert = NSAlert()
        alert.messageText = install ? "Install the aitmproxy root CA?" : "Remove the aitmproxy root CA?"
        alert.informativeText = status.confirmPrompt(install: install)
        alert.addButton(withTitle: install ? "Install" : "Remove")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        busy = true
        Task {
            defer { busy = false }
            actionError = nil
            if install {
                await session.trustCA()
            } else {
                await session.untrustCA()
            }
        }
    }
}
