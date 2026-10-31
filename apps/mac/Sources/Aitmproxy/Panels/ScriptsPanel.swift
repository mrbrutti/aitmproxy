import AitmBusClient
import AitmproxyKit
import AppKit
import SwiftUI

/// The Scripts page (S-060): a master list of Rhai scripts on the left (name,
/// rule, phases, status word, enable switch) and a detail pane on the right that
/// shows the selected script's status, its *full* error (the list shows only a
/// one-line summary), its rule and phases. Live source and console land when the
/// core serves `script.get` / `script.log` (F8).
struct ScriptsPanel: View {
    @Environment(Session.self) private var session
    @State private var scripts: [ScriptInfo] = []
    @State private var selected: String?
    @State private var note: String?

    private static let phaseChip = ColorPair(fg: Tok.Ink.secondary, bg: Tok.Ground.raised)

    private var hasBusList: Bool { session.tools.contains { $0.name == "script.list" } }
    private var hasBusToggle: Bool { session.tools.contains { $0.name == "script.enable" } }
    private var selectedScript: ScriptInfo? { scripts.first { $0.id == selected } }

    var body: some View {
        VStack(spacing: 0) {
            header
            Rule()
            if let note {
                Hint(text: note).padding(.leading, Space.margin).frame(maxWidth: .infinity, alignment: .leading)
                Rule(color: Tok.Line.rule)
            }
            if scripts.isEmpty {
                empty
            } else {
                HStack(spacing: 0) {
                    list.frame(width: 360)
                    VRule()
                    ScriptDetail(script: selectedScript).frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .gridArea("scripts", inset: 0)
        .task { await load() }
        .onChange(of: session.tools) { Task { await load() } }
    }

    private var header: some View {
        PageHeader("Scripts") {
            Text("\(scripts.filter(\.isActive).count) active")
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
        }
        .gridProbe("scripts.title", area: "scripts")
    }

    private var empty: some View {
        VStack(spacing: Space.sm) {
            Text("No scripts loaded.").font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
            Text("Drop a .rhai file into the proxy's scripts folder; it lists here.")
                .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var list: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(scripts) { script in row(script) }
            }
        }
    }

    private func row(_ script: ScriptInfo) -> some View {
        Button { selected = script.id } label: {
            HStack(alignment: .center, spacing: Space.md) {
                VStack(alignment: .leading, spacing: Space.xs) {
                    HStack(spacing: Space.sm) {
                        Text(script.name).font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                            .foregroundStyle(Tok.Ink.primary.color).lineLimit(1)
                            .help(script.name)
                        ForEach(script.phases, id: \.self) { phase in
                            Badge(text: phase, pair: Self.phaseChip, uppercase: false)
                        }
                    }
                    Text(script.ruleSummary)
                        .font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                        .lineLimit(1).truncationMode(.middle)
                }
                Spacer(minLength: Space.sm)
                // The same word + symbol the detail header uses, so status is never
                // colour alone; hue only on the error.
                Label(script.statusWord, systemImage: script.statusSymbol)
                    .labelStyle(.titleAndIcon)
                    .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                    .foregroundStyle((script.error != nil ? Tok.Status.serverError : Tok.Ink.secondary).color)
                    .fixedSize()
                    .help(script.statusText)
                Toggle(script.name, isOn: Binding(get: { script.enabled }, set: { setEnabled(script, $0) }))
                    .toggleStyle(.switch).controlSize(.small).labelsHidden()
                    .accessibilityLabel(script.name)
            }
            .padding(.horizontal, Space.md)
            .padding(.vertical, Space.sm)
            .frame(minHeight: Tok.Size.Row.comfortable)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(script.id == selected ? Tok.Ground.active.color : .clear)
            .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .contextMenu {
            Button(script.enabled ? "Disable" : "Enable") { setEnabled(script, !script.enabled) }
            Button("Copy Rule") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(script.ruleSummary, forType: .string)
            }
        }
        .accessibilityAddTraits(script.id == selected ? .isSelected : [])
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
            note = "Sample scripts — the live list arrives when the core lists its scripts" // F8 script.list
        } else {
            scripts = []
            note = "The core does not list scripts yet" // F8 script.list
        }
        // Lead with a failing script so its fault is visible, else the first script.
        if selected == nil || !scripts.contains(where: { $0.id == selected }) {
            selected = scripts.first(where: { $0.error != nil })?.id ?? scripts.first?.id
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

/// The selected script in full: status, its complete error (not the list's one-line
/// summary), rule and phases, and placeholders for the source and live console that
/// arrive with the F8 `script.get` / `script.log` bus verbs.
private struct ScriptDetail: View {
    var script: ScriptInfo?

    var body: some View {
        if let script {
            ScrollView {
                VStack(alignment: .leading, spacing: Space.lg) {
                    header(script)
                    if let error = script.error, !error.isEmpty {
                        section("Error")
                        Text(error)
                            .font(Tok.Face.data(Tok.Typography.Size.md))
                            .foregroundStyle(Tok.State.danger.fg.color)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(Space.md)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Tok.State.danger.bg.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                    }
                    section("Rule")
                    Text(script.ruleSummary)
                        .font(Tok.Face.data(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.primary.color)
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    if !script.phases.isEmpty {
                        section("Phases")
                        HStack(spacing: Space.sm) {
                            ForEach(script.phases, id: \.self) { phase in
                                Badge(text: phase, pair: ColorPair(fg: Tok.Ink.secondary, bg: Tok.Ground.raised), uppercase: false)
                            }
                        }
                    }
                    section("Source")
                    Hint(text: "The script's source appears here once the core can serve it.") // F8 script.get
                    section("Console")
                    Hint(text: "Live script output appears here once the core can stream it.") // F8 script.log
                }
                .padding(Space.md)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            VStack(spacing: Space.sm) {
                Text("No script selected").font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                Text("Pick a script on the left to see its status, rule and any error in full.")
                    .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func header(_ script: ScriptInfo) -> some View {
        HStack(spacing: Space.md) {
            Text(script.name).font(Tok.Face.ui(Tok.Typography.Size.xl, .medium))
                .foregroundStyle(Tok.Ink.primary.color).lineLimit(1)
            Spacer(minLength: Space.sm)
            // One status, consistent with the sidebar's "N active": an erroring script
            // reads "Error", never "Enabled", and the icon carries the colour.
            Label(script.statusWord, systemImage: script.statusSymbol)
                .labelStyle(.titleAndIcon)
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(statusColor(script).color)
                .help(script.statusText)
        }
    }

    private func statusColor(_ s: ScriptInfo) -> DynamicColor {
        s.error != nil ? Tok.Status.serverError : s.enabled ? Tok.Status.success : Tok.Ink.tertiary
    }

    private func section(_ title: String) -> some View {
        Text(title.uppercased()).font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
            .foregroundStyle(Tok.Ink.tertiary.color)
    }
}

/// One status vocabulary for the list row and the detail header: an erroring
/// script reads "Error", never "Active".
private extension ScriptInfo {
    var statusWord: String {
        error != nil ? "Error" : enabled ? "Active" : "Disabled"
    }

    var statusSymbol: String {
        error != nil ? "exclamationmark.triangle.fill" : enabled ? "checkmark.circle.fill" : "circle"
    }
}
