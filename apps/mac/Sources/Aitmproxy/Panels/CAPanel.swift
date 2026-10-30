import AitmBusClient
import AitmproxyKit
import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Certificate Authority (S-058): the CA's status, export PEM/DER, install or
/// uninstall after the proxy's own confirmation, the read-only agent-gate flag,
/// and setup guides for iOS, Android, browsers and terminals.
struct CAPanel: View {
    @Environment(Session.self) private var session
    @State private var status: CAStatus?
    @State private var agentMayInstall = false
    @State private var busy = false
    @State private var actionError: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.lg) {
                Text("Certificate Authority").font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                if let status {
                    statusLine(status)
                    buttons(status)
                    Text("Agent may install: \(agentMayInstall ? "yes" : "no")")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
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
        .gridArea("ca")
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
            if let path = status.path { keyValue("Path", path) }
            if let actionError {
                Label(actionError, systemImage: "exclamationmark.triangle.fill")
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Status.serverError.color)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// Green when installed and trusted, amber when installed but not trusted, grey
    /// when present but not installed, red when the CA is missing.
    private static func statusPair(_ s: CAStatus) -> ColorPair {
        if s.installed, s.trusted { return Tok.Method.post }
        if s.installed { return Tok.Method.put }
        if s.exists { return Tok.Method.connect }
        return Tok.Method.delete
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

    private func buttons(_ status: CAStatus) -> some View {
        HStack(spacing: Space.sm) {
            FlatButton("Export PEM") { export(format: "pem") }.disabled(busy || !status.exists)
            FlatButton("Export DER") { export(format: "der") }.disabled(busy || !status.exists)
            Spacer()
            if status.installed {
                FlatButton("Uninstall…") { change(install: false, status: status) }.disabled(busy)
            } else {
                PrimaryButton("Install…") { change(install: true, status: status) }.disabled(busy || !status.exists)
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
        if Store.usesFixtures {
            status = Fixtures.caStatus
            agentMayInstall = Fixtures.caStatus.allowAgentInstall
            return
        }
        agentMayInstall = configFlag()
        Task {
            if let json = try? await session.runCommand("ca.status", [:]), let parsed = CAStatus(json: json) {
                status = parsed
                if parsed.allowAgentInstall { agentMayInstall = true }
            } else {
                status = CAStatus(fingerprint: "", installed: false, trusted: false, exists: false)
            }
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
            let command = install ? "ca.install" : "ca.uninstall"
            do {
                // ca.install / ca.uninstall are confirm-gated over the bus: the first call
                // returns a confirm token and applies nothing; it must be re-sent with
                // `_confirm` to actually run (the alert above is the human confirmation).
                // Missing this re-call was the silent no-op — the first response looked like
                // success while the keychain was never touched.
                let result = try await session.runCommand(command, [:])
                if let token = result["confirm_token"]?.stringValue {
                    _ = try await session.runCommand(command, ["_confirm": .string(token)])
                }
                if let json = try? await session.runCommand("ca.status", [:]), let parsed = CAStatus(json: json) {
                    self.status = parsed
                }
                // The install can finish without login-keychain trust landing (the macOS
                // trust dialog may not surface in this process); say so, don't look installed.
                if install, let current = self.status, !(current.installed && current.trusted) {
                    actionError = "Install finished but the CA is not trusted in the login keychain yet. Export the PEM and trust it in Keychain Access, or follow the setup guide below."
                }
            } catch {
                let message = "\(command): \(BusService.describe(error))"
                actionError = message
                session.lastError = message
            }
        }
    }
}
