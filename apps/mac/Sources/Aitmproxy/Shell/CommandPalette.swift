import AitmBusClient
import AitmproxyKit
import SwiftUI

/// ⌘K (foundation §2.7 "Command palette"; S-035, S-036): fuzzy search over
/// every bus command (from `tools/list`), flows by URL, setup actions and
/// local actions. Floating card, radius 10, `floating` shadow; keyboard
/// open/close never animates.
struct CommandPalette: View {
    @Environment(Session.self) private var session
    @Environment(\.colorScheme) private var colorScheme
    @State private var query = ""
    @State private var highlighted = 0
    @State private var form: PaletteForm?
    @State private var result: String?
    @FocusState private var fieldFocused: Bool

    private var items: [PaletteItem] { session.paletteItems(for: query) }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: Space.sm) {
                Image(systemName: Tok.Glyph.palette).font(.system(size: 14)).foregroundStyle(Tok.Ink.tertiary.color)
                TextField("Type a command, a URL or a setting…", text: $query)
                    .textFieldStyle(.plain)
                    .font(Tok.Face.ui(Tok.Typography.Size.base))
                    .focused($fieldFocused)
                    .onSubmit { activate() }
                    .onChange(of: query) { highlighted = 0 }
                if let result {
                    Text(result).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color).lineLimit(1)
                }
            }
            .padding(.horizontal, Space.lg)
            .frame(height: Tok.Size.toolbar)
            Rule()
            if let form {
                PaletteFormView(form: form, onRun: { args in run(form.tool, args) }, onCancel: { self.form = nil })
            } else {
                list
            }
        }
        .frame(width: 600)
        .frame(maxHeight: 440)
        .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.floating))
        .overlay(RoundedRectangle(cornerRadius: Tok.Radius.floating).strokeBorder(Tok.Line.border.color))
        .shadow(color: .black.opacity(colorScheme == .dark ? Tok.Shadow.floating.darkOpacity : Tok.Shadow.floating.lightOpacity),
                radius: Tok.Shadow.floating.radius, y: Tok.Shadow.floating.y)
        .onAppear {
            fieldFocused = true
            // A scene can hand the palette an opening query (palette-flows snapshot); consumed once.
            if let seed = session.paletteSeedQuery { query = seed; session.paletteSeedQuery = nil }
        }
        .onExitCommand { if form != nil { form = nil } else { session.paletteVisible = false } }
        .onKeyPress(.downArrow) { highlighted = min(highlighted + 1, max(items.count - 1, 0)); return .handled }
        .onKeyPress(.upArrow) { highlighted = max(highlighted - 1, 0); return .handled }
        .accessibilityLabel("Command palette")
    }

    private var list: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    let grouped = Dictionary(grouping: items.enumerated().map { ($0.offset, $0.element) }, by: { $0.1.section })
                    ForEach(PaletteSection.allCases, id: \.self) { section in
                        if let rows = grouped[section], !rows.isEmpty {
                            Text(section.title.uppercased())
                                .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
                                .foregroundStyle(Tok.Ink.tertiary.color)
                                .padding(.horizontal, Space.lg).padding(.top, Space.md).padding(.bottom, Space.xs)
                            ForEach(rows, id: \.0) { index, item in
                                PaletteRow(item: item, highlighted: index == highlighted)
                                    .id(index)
                                    .onTapGesture { highlighted = index; activate() }
                            }
                        }
                    }
                    if items.isEmpty {
                        Text(session.tools.isEmpty && !Store.usesFixtures ? "Bus offline — connect in Settings ▸ Bus" : "No match")
                            .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
                            .padding(Space.lg)
                    }
                }
                .padding(.bottom, Space.sm)
            }
            .onChange(of: highlighted) { proxy.scrollTo(highlighted) }
        }
    }

    private func activate() {
        guard items.indices.contains(highlighted) else { return }
        let item = items[highlighted]
        session.rememberPaletteUse(item)
        switch item.kind {
        case .command(let tool):
            if tool.parameters.isEmpty {
                run(tool, [:])
            } else {
                form = PaletteForm(tool: tool, session: session)
            }
        case .flow(let id):
            session.select(id)
            session.paletteVisible = false
        case .local(let action):
            action()
            session.paletteVisible = false
        case .savedFilter(let saved):
            session.applySavedFilter(saved)
            session.filterBarVisible = true
            session.paletteVisible = false
        }
    }

    private func run(_ tool: ToolDescriptor, _ args: [String: JSONValue]) {
        form = nil
        result = "Running \(tool.name)…"
        Task {
            do {
                let value = try await session.runCommand(tool.name, args)
                result = "\(tool.name): \(value.serialized().prefix(80))"
                try? await Task.sleep(for: .seconds(2))
                session.paletteVisible = false
            } catch {
                result = "\(tool.name) failed: \(BusService.describe(error))"
            }
        }
    }
}

struct PaletteRow: View {
    var item: PaletteItem
    var highlighted: Bool
    @State private var hovered = false

    var body: some View {
        HStack(spacing: Space.md) {
            if let method = item.method { Badge(text: method.label, pair: method.badge) }
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title).font(Tok.Face.ui(Tok.Typography.Size.md, .medium)).foregroundStyle(Tok.Ink.primary.color).lineLimit(1)
                if !item.subtitle.isEmpty {
                    Text(item.subtitle).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color).lineLimit(1)
                }
            }
            Spacer()
            if let shortcut = item.shortcut {
                Text(shortcut).font(Tok.Face.ui(Tok.Typography.Size.xs)).foregroundStyle(Tok.Ink.tertiary.color)
            }
        }
        .padding(.horizontal, Space.lg)
        .frame(height: Tok.Size.toolbar)
        // Keyboard highlight wins; the pointer only tints an unhighlighted row (D3).
        .background(highlighted ? Tok.Ground.active.color : (hovered ? Tok.Ground.hover.color : .clear))
        .contentShape(Rectangle())
        .onHover { hovered = $0 }
    }
}

/// A command's parameters as a form built from `tools/list` (S-035).
@Observable
final class PaletteForm {
    let tool: ToolDescriptor
    var values: [String: String] = [:]
    var booleans: [String: Bool] = [:]
    let flows: [FlowRow]

    init(tool: ToolDescriptor, session: Session) {
        self.tool = tool
        flows = session.rows
        for p in tool.parameters where p.type == .flowId {
            values[p.name] = session.focused?.raw ?? ""
        }
    }

    var missing: [String] {
        tool.parameters.filter { $0.required && $0.type != .bool && (values[$0.name] ?? "").isEmpty }.map(\.name)
    }

    /// Typed arguments; empty optional fields are omitted.
    func arguments() throws -> [String: JSONValue] {
        var args: [String: JSONValue] = [:]
        for p in tool.parameters {
            switch p.type {
            case .bool:
                if let b = booleans[p.name] { args[p.name] = .bool(b) }
            case .int:
                if let text = values[p.name], !text.isEmpty {
                    guard let n = Int(text) else { throw BusError.malformed("\(p.name) must be an integer") }
                    args[p.name] = .number(Double(n))
                }
            case .float:
                if let text = values[p.name], !text.isEmpty {
                    guard let n = Double(text) else { throw BusError.malformed("\(p.name) must be a number") }
                    args[p.name] = .number(n)
                }
            case .string, .flowId, .bytes:
                if let text = values[p.name], !text.isEmpty { args[p.name] = .string(text) }
            case .array, .object, .map, .any:
                if let text = values[p.name], !text.isEmpty {
                    args[p.name] = try JSONValue.parse(text)
                }
            }
        }
        return args
    }
}

struct PaletteFormView: View {
    @Bindable var form: PaletteForm
    var onRun: ([String: JSONValue]) -> Void
    var onCancel: () -> Void
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            Text(form.tool.description).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            ForEach(form.tool.parameters, id: \.name) { param in
                HStack(alignment: .firstTextBaseline, spacing: Space.md) {
                    Text(param.name + (param.required ? " *" : ""))
                        .font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                        .frame(width: 120, alignment: .trailing)
                    field(param)
                }
            }
            if let error { Text(error).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Status.serverError.color) }
            HStack {
                Spacer()
                FlatButton("Cancel") { onCancel() }
                PrimaryButton("Run", hint: "⏎") { run() }
                    .disabled(!form.missing.isEmpty)
            }
        }
        .padding(Space.lg)
        .onSubmit { run() }
    }

    @ViewBuilder private func field(_ param: ParamDescriptor) -> some View {
        switch param.type {
        case .bool:
            Toggle(isOn: Binding(get: { form.booleans[param.name] ?? false }, set: { form.booleans[param.name] = $0 })) { EmptyView() }
                .toggleStyle(.switch).labelsHidden()
        case .flowId:
            Picker("", selection: Binding(get: { form.values[param.name] ?? "" }, set: { form.values[param.name] = $0 })) {
                Text("Choose a flow…").tag("")
                ForEach(form.flows) { row in Text("\(row.seq) · \(row.method.label) \(row.url)").tag(row.id.raw) }
            }
            .labelsHidden()
        case .bytes:
            TextField("base64 or text", text: Binding(get: { form.values[param.name] ?? "" }, set: { form.values[param.name] = $0 }))
                .textFieldStyle(.roundedBorder).font(Tok.Face.data(Tok.Typography.Size.md))
        case .array, .object, .map, .any:
            TextField("JSON", text: Binding(get: { form.values[param.name] ?? "" }, set: { form.values[param.name] = $0 }), axis: .vertical)
                .textFieldStyle(.roundedBorder).font(Tok.Face.data(Tok.Typography.Size.md)).lineLimit(1...4)
        default:
            TextField(param.description, text: Binding(get: { form.values[param.name] ?? "" }, set: { form.values[param.name] = $0 }))
                .textFieldStyle(.roundedBorder)
        }
    }

    private func run() {
        do {
            onRun(try form.arguments())
        } catch {
            self.error = BusService.describe(error)
        }
    }
}

// MARK: - Items

enum PaletteSection: CaseIterable {
    case recent, commands, flows, setup, filters, local

    var title: String {
        switch self {
        case .recent: "Recent"
        case .commands: "Commands"
        case .flows: "Flows"
        case .setup: "Setup"
        case .filters: "Saved Filters"
        case .local: "App"
        }
    }
}

struct PaletteItem: Identifiable {
    enum Kind {
        case command(ToolDescriptor)
        case flow(FlowID)
        case local(() -> Void)
        case savedFilter(SavedFilter)
    }

    var id: String
    var section: PaletteSection
    var title: String
    var subtitle: String
    var shortcut: String?
    var method: HTTPMethod?
    var kind: Kind
}
