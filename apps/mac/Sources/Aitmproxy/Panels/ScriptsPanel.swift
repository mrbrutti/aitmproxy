import AitmBusClient
import AitmproxyKit
import SwiftUI

/// The Scripts page (S-060): one row per Rhai script — name, rule summary,
/// phases, status dot + text, a flat switch. `script.list/enable/disable`
/// are F8; until then the fixture list stands in, with a note.
struct ScriptsPanel: View {
    @Environment(Session.self) private var session
    @State private var scripts: [ScriptInfo] = []
    @State private var note: String?

    private static let phaseChip = ColorPair(fg: Tok.Ink.secondary, bg: Tok.Ground.raised)

    private var hasBusList: Bool { session.tools.contains { $0.name == "script.list" } }
    private var hasBusToggle: Bool { session.tools.contains { $0.name == "script.enable" } }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: Space.md) {
                TrackedLabel("Scripts")
                Spacer(minLength: Space.sm)
                Text("\(scripts.filter(\.isActive).count) active")
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color)
            }
            .padding(.horizontal, Space.margin)
            .frame(height: Tok.Size.filterBar)
            Rule()
            if let note {
                Hint(text: note).padding(.leading, Space.margin).frame(maxWidth: .infinity, alignment: .leading)
                Rule(color: Tok.Line.rule)
            }
            if scripts.isEmpty {
                VStack(spacing: Space.sm) {
                    Text("No scripts loaded.").font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                    Text("Drop a .rhai file into the proxy's scripts folder; it lists here.")
                        .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(scripts) { script in row(script) }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .gridArea("scripts")
        .task { await load() }
        .onChange(of: session.tools) { Task { await load() } }
    }

    private func row(_ script: ScriptInfo) -> some View {
        HStack(alignment: .center, spacing: Space.md) {
            Circle().fill(dotColor(script).color).frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
            VStack(alignment: .leading, spacing: Space.xs) {
                HStack(spacing: Space.sm) {
                    Text(script.name).font(Tok.Face.ui(Tok.Typography.Size.md, .medium)).foregroundStyle(Tok.Ink.primary.color)
                    ForEach(script.phases, id: \.self) { phase in
                        Badge(text: phase, pair: Self.phaseChip, uppercase: false)
                    }
                }
                Text(script.ruleSummary)
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: Space.sm)
            Text(script.statusText)
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(script.error == nil ? Tok.Ink.secondary.color : Tok.Status.serverError.color)
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(maxWidth: 320, alignment: .trailing)
                .help(script.statusText)
            Toggle(script.name, isOn: Binding(get: { script.enabled }, set: { setEnabled(script, $0) }))
                .toggleStyle(.switch)
                .controlSize(.small)
                .labelsHidden()
                .accessibilityLabel(script.name)
        }
        .padding(.horizontal, Space.margin)
        .padding(.vertical, Space.sm)
        .frame(minHeight: Tok.Size.Row.comfortable)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
    }

    private func dotColor(_ script: ScriptInfo) -> DynamicColor {
        if script.error != nil { return Tok.Status.serverError }
        return script.enabled ? Tok.Status.success : Tok.Ink.tertiary
    }

    private func load() async {
        if hasBusList {
            do {
                let items = try await session.runCommand("script.list", [:]).arrayValue ?? []
                scripts = items.compactMap { ScriptInfo(json: $0) }
                note = nil
            } catch {
                session.lastError = "script.list: \(BusService.describe(error))"
            }
        } else if Store.usesFixtures {
            scripts = Fixtures.scripts
            note = "Fixture list — the live list needs script.list (F8)"
        } else {
            scripts = []
            note = "Scripts need script.list on the bus (F8)"
        }
        syncCount()
    }

    /// Flip locally at once; the bus confirms or the row reverts with a status-bar note.
    private func setEnabled(_ script: ScriptInfo, _ on: Bool) {
        guard let index = scripts.firstIndex(where: { $0.id == script.id }) else { return }
        let previous = scripts[index].enabled
        scripts[index].enabled = on
        syncCount()
        if Store.usesFixtures, !hasBusToggle { return }
        guard hasBusToggle else {
            scripts[index].enabled = previous
            syncCount()
            session.lastError = "script.enable needs F8"
            return
        }
        Task {
            do {
                _ = try await session.runCommand(on ? "script.enable" : "script.disable", ["id": .string(script.id)])
                session.lastError = nil
            } catch {
                if let i = scripts.firstIndex(where: { $0.id == script.id }) { scripts[i].enabled = previous }
                syncCount()
                session.lastError = "\(on ? "script.enable" : "script.disable"): \(BusService.describe(error))"
            }
        }
    }

    private func syncCount() { session.activeScripts = scripts.filter(\.isActive).count }
}
