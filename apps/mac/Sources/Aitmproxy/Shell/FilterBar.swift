import AitmproxyKit
import SwiftUI

/// The stacked filter bar (foundation §2.7 "Filter bar & search"; S-031–S-033):
/// rows of Field · Operator · Value under All / Any, an Advanced mode that
/// shows the same filter as a mitmproxy expression, and saved filters.
struct FilterBar: View {
    @Environment(Session.self) private var session
    @FocusState private var focusedRow: Int?
    @State private var showingSaved = false

    var body: some View {
        @Bindable var session = session
        VStack(alignment: .leading, spacing: Space.sm) {
            header
            if session.filterAdvanced {
                advanced
            } else {
                ForEach(session.filterStack.rows.indices, id: \.self) { index in
                    filterRow(index)
                }
                HStack(spacing: Space.md) {
                    FlatButton("Add Row", symbol: "plus") {
                        session.filterStack.rows.append(FilterRow(.url, .contains))
                        focusedRow = session.filterStack.rows.count - 1
                    }
                    if !session.filterStack.isEmpty {
                        Text(session.filterStack.text)
                            .font(Tok.Face.data(Tok.Typography.Size.sm))
                            .foregroundStyle(Tok.Ink.tertiary.color)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                    }
                }
            }
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Tok.Ground.page.color)
        .overlay(alignment: .bottom) { Rule() }
        .onAppear { if session.filterStack.rows.isEmpty { session.filterStack.rows = [FilterRow(.url, .contains)] }; focusedRow = 0 }
        .onExitCommand { session.filterBarVisible = false }
    }

    private var header: some View {
        @Bindable var session = session
        return HStack(spacing: Space.md) {
            Text("Match").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            FlatSegment(options: FilterStack.Combinator.allCases.map { ($0, $0.title) }, selection: $session.filterStack.combinator)
                .disabled(session.filterAdvanced && session.filterStackFromText == nil)
            Spacer()
            // "Rows" alone is disabled while the Advanced text has no row form, so
            // switching back can never silently drop a nested filter (B5).
            FlatSegment(options: [(false, "Rows"), (true, "Advanced")], selection: Binding(
                get: { session.filterAdvanced }, set: { session.setFilterAdvanced($0) }),
                disabledOptions: rowsHaveNoForm ? [false] : [])
            if session.filterAdvanced, session.filterStackFromText == nil, !session.filterText.isEmpty, session.filterError == nil {
                Text("Nested filter — edit as text").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
            }
            Button { showingSaved.toggle() } label: {
                Image(systemName: "bookmark").font(.system(size: 13)).foregroundStyle(Tok.Ink.secondary.color)
                    .frame(width: Tok.Size.control, height: Tok.Size.control).contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Show saved filters")
            .popover(isPresented: $showingSaved, arrowEdge: .bottom) { SavedFiltersPopover() }
            FlatButton("Reset") { session.clearFilter() }
                .help("Reset the filter rows")
            Button { session.filterBarVisible = false } label: {
                Image(systemName: "xmark").font(.system(size: 11, weight: .medium)).foregroundStyle(Tok.Ink.secondary.color)
                    .frame(width: Tok.Size.control, height: Tok.Size.control).contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Close the filter bar (⌘F)")
        }
    }

    /// True while Advanced is on with a non-empty text that has no rows form
    /// (nested, or still invalid): "Rows" would lose it.
    private var rowsHaveNoForm: Bool {
        session.filterAdvanced && !session.filterText.isEmpty && session.filterStackFromText == nil
    }

    private func filterRow(_ index: Int) -> some View {
        @Bindable var session = session
        let row = session.filterStack.rows[index]
        let error = row.validationError
        return VStack(alignment: .leading, spacing: Space.xs) {
            filterRowControls(index, row: row, error: error)
            // The border alone is not a report: say what is wrong under the row (B5).
            if let error {
                Text(error)
                    .font(Tok.Face.ui(Tok.Typography.Size.xs))
                    .foregroundStyle(Tok.Intercept.deep.color)
                    .lineLimit(1)
                    .padding(.leading, Space.sm)
            }
        }
    }

    private func filterRowControls(_ index: Int, row: FilterRow, error: String?) -> some View {
        @Bindable var session = session
        return HStack(spacing: Space.sm) {
            FlatMenu(title: row.field.title, width: 148) {
                ForEach(FilterField.allCases, id: \.self) { field in
                    Button(field.title) {
                        session.filterStack.rows[index].field = field
                        if !field.operators.contains(session.filterStack.rows[index].op) {
                            session.filterStack.rows[index].op = field.operators.first ?? .contains
                        }
                    }
                }
            }
            FlatMenu(title: row.op.title, width: 124) {
                ForEach(row.field.operators, id: \.self) { op in
                    Button(op.title) { session.filterStack.rows[index].op = op }
                }
            }
            TextField(placeholder(for: row.op), text: $session.filterStack.rows[index].value)
                .textFieldStyle(.plain)
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .padding(.horizontal, Space.sm)
                .frame(height: Tok.Size.control)
                .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control)
                    .strokeBorder(error == nil ? Tok.Line.control.color : Tok.Intercept.deep.color))
                .focused($focusedRow, equals: index)
                .help(error ?? "")
                .frame(maxWidth: 360)
            FlatToggle("not", isOn: $session.filterStack.rows[index].negated)
            Button {
                session.filterStack.rows.remove(at: index)
                if session.filterStack.rows.isEmpty { session.filterStack.rows = [FilterRow(.url, .contains)] }
            } label: {
                Image(systemName: "minus.circle").font(.system(size: 13)).foregroundStyle(Tok.Ink.tertiary.color)
                    .frame(width: Tok.Size.control, height: Tok.Size.control).contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Remove this row")
            Spacer(minLength: 0)
        }
    }

    private var advanced: some View {
        @Bindable var session = session
        return VStack(alignment: .leading, spacing: Space.xs) {
            TextField("~u login & ~m POST", text: $session.filterText)
                .textFieldStyle(.plain)
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .padding(.horizontal, Space.sm)
                .frame(height: Tok.Size.control)
                .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control)
                    .strokeBorder(session.filterError == nil ? Tok.Line.control.color : Tok.Intercept.deep.color))
                .focused($focusedRow, equals: -1)
                .onAppear { focusedRow = -1 }
            if let error = session.filterError {
                HStack(spacing: 0) {
                    Text(String(repeating: " ", count: max(0, error.offset)))
                        .font(Tok.Face.data(Tok.Typography.Size.md))
                    Text("^").font(Tok.Face.data(Tok.Typography.Size.md)).foregroundStyle(Tok.Intercept.deep.color)
                    Text("  \(error.message)").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Intercept.deep.color)
                }
                .padding(.leading, Space.sm)
            }
        }
    }

    private func placeholder(for op: FilterOperator) -> String {
        switch op {
        case .contains: "contains…"
        case .equals: "equals…"
        case .wildcard: "*.example.test"
        case .regex: "regex…"
        case .jsonPath: "$.path or $.path=value"
        case .fullText: "any text…"
        case .greaterThan: "greater than…"
        case .lessThan: "less than…"
        }
    }
}

/// Saved filters (S-033): list with name and expression, Save Filter…, Manage.
struct SavedFiltersPopover: View {
    @Environment(Session.self) private var session
    @State private var name = ""
    @State private var managing = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Text("Saved Filters").font(Tok.Face.ui(Tok.Typography.Size.md, .semibold))
            if session.savedFilters.isEmpty {
                Text("No saved filters").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
            }
            ForEach(session.savedFilters) { saved in
                HStack(spacing: Space.sm) {
                    Button { session.applySavedFilter(saved) } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(saved.name).font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.primary.color)
                            Text(saved.expression).font(Tok.Face.data(Tok.Typography.Size.xs)).foregroundStyle(Tok.Ink.tertiary.color)
                                .lineLimit(1)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    if managing {
                        Button { session.deleteSavedFilter(saved) } label: {
                            Image(systemName: "minus.circle").foregroundStyle(Tok.Ink.tertiary.color)
                        }
                        .buttonStyle(.plain)
                        .help("Delete this saved filter")
                        .accessibilityLabel("Delete saved filter")
                    }
                }
            }
            Rule()
            HStack(spacing: Space.sm) {
                TextField("Name", text: $name)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { save() }
                Button(session.savedFilters.contains { $0.name == name } ? "Replace" : "Save") { save() }
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || session.currentFilterExpressionText.isEmpty)
            }
            FlatToggle(managing ? "Done" : "Edit", isOn: $managing)
        }
        .padding(Space.lg)
        .frame(width: 360)
    }

    private func save() {
        session.saveFilter(named: name.trimmingCharacters(in: .whitespaces))
        name = ""
    }
}

// MARK: - Flat controls (foundation: no chrome, hue only on data)

/// A text button in the secondary tier; no border, no fill.
struct FlatButton: View {
    var title: String
    var symbol: String?
    var action: () -> Void

    init(_ title: String, symbol: String? = nil, action: @escaping () -> Void) {
        self.title = title
        self.symbol = symbol
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: Space.xs) {
                if let symbol { Image(systemName: symbol).font(.system(size: 11, weight: .medium)) }
                Text(title)
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
            .foregroundStyle(Tok.Ink.secondary.color)
            .padding(.horizontal, Space.sm)
            .frame(height: Tok.Size.control)
            .contentShape(Rectangle())
        }
        .buttonStyle(PressStyle())
    }
}

/// Two or three words; the active one in ink on `raised`, the others secondary.
/// Rounded-rect, not a capsule, so it reads as a control and not a chip (C5).
/// Disabled (whole segment via `.disabled`, or one option via
/// `disabledOptions`) drops to tertiary ink with no fill (B5).
struct FlatSegment<Value: Hashable>: View {
    var options: [(Value, String)]
    @Binding var selection: Value
    /// Options that cannot be chosen right now; the rest stay live.
    var disabledOptions: Set<Value> = []
    @Environment(\.isEnabled) private var isEnabled

    var body: some View {
        HStack(spacing: 2) {
            ForEach(options, id: \.0) { value, title in
                let on = value == selection
                let live = isEnabled && !disabledOptions.contains(value)
                Button { selection = value } label: {
                    Text(title)
                        .font(Tok.Face.ui(Tok.Typography.Size.sm, on ? .medium : .regular))
                        .foregroundStyle(ink(on: on, live: live))
                        .padding(.horizontal, Space.sm)
                        .frame(height: Tok.Metric.chip)
                        .background(on && live ? Tok.Ground.raised.color : .clear,
                                    in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                        .contentShape(RoundedRectangle(cornerRadius: Tok.Radius.control))
                }
                .buttonStyle(.plain)
                .disabled(!live)
                .accessibilityAddTraits(on ? .isSelected : [])
            }
        }
    }

    private func ink(on: Bool, live: Bool) -> Color {
        if !live { return Tok.Ink.tertiary.color }
        return on ? Tok.Ink.primary.color : Tok.Ink.secondary.color
    }
}

/// A popup-style menu drawn flat: title + chevron on a control-border outline.
struct FlatMenu<Content: View>: View {
    var title: String
    var width: CGFloat
    @ViewBuilder var content: Content

    var body: some View {
        Menu {
            content
        } label: {
            HStack(spacing: Space.xs) {
                Text(title).lineLimit(1)
                Spacer(minLength: 0)
                Image(systemName: "chevron.down").font(.system(size: 9, weight: .medium))
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.primary.color)
            .padding(.horizontal, Space.sm)
            .frame(width: width, height: Tok.Size.control)
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
            .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
    }
}

/// A word that is on (ink on `raised`) or off (tertiary).
struct FlatToggle: View {
    var title: String
    @Binding var isOn: Bool

    init(_ title: String, isOn: Binding<Bool>) {
        self.title = title
        _isOn = isOn
    }

    var body: some View {
        Button { isOn.toggle() } label: {
            Text(title)
                .font(Tok.Face.ui(Tok.Typography.Size.sm, isOn ? .medium : .regular))
                .foregroundStyle(isOn ? Tok.Ink.primary.color : Tok.Ink.tertiary.color)
                .padding(.horizontal, Space.sm)
                .frame(height: Tok.Metric.chip)
                .background(isOn ? Tok.Ground.raised.color : .clear, in: Capsule())
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(isOn ? .isSelected : [])
    }
}
