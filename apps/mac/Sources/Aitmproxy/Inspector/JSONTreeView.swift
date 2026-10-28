import AitmproxyKit
import SwiftUI

/// Expansion, filter, sort and "show more" for one JSON document (S-022).
/// The view owns one; the lead can also drive it from the tab bar.
@Observable final class JSONTreeState {
    /// Arrays longer than this show their first page and a "Show more" row.
    static let pageSize = 1_000

    let root: JSONNode
    var expanded: Set<String>
    var filter = "" {
        didSet { matches = filter.isEmpty ? nil : root.filter(filter) }
    }
    var sortKeys = false {
        didSet { if sortKeys, sortedRoot == nil { sortedRoot = root.sortedKeys() } }
    }
    /// Paths of the nodes matching the filter plus their ancestors; nil with no filter.
    private(set) var matches: Set<String>?
    private var sortedRoot: JSONNode?
    /// How many items a long array shows (path → count); absent means one page.
    private var pages: [String: Int] = [:]

    /// Depth 0 and 1 open, as the story's "tree expanded one level".
    init(root: JSONNode) {
        self.root = root
        var open: Set<String> = []
        if root.kind.isContainer { open.insert(root.path) }
        for child in root.children where child.kind.isContainer { open.insert(child.path) }
        expanded = open
    }

    var displayRoot: JSONNode { sortKeys ? (sortedRoot ?? root) : root }
    /// A filter is typed but nothing matches: the tree stays and a hint says so.
    var noMatch: Bool { matches?.isEmpty == true }

    enum Row: Identifiable, Hashable {
        case node(JSONTreeRow)
        case showMore(path: String, shown: Int, total: Int)

        var id: String {
            switch self {
            case .node(let row): row.id
            case .showMore(let path, _, _): "\(path) more"
            }
        }
    }

    /// The visible outline. Matches are forced open so a filtered hit is always reachable.
    var rows: [Row] {
        let open = (noMatch ? nil : matches).map { expanded.union($0) } ?? expanded
        let keep = noMatch ? nil : matches
        var rows: [Row] = []
        append(displayRoot, depth: 0, open: open, keep: keep, into: &rows)
        return rows
    }

    private func append(_ node: JSONNode, depth: Int, open: Set<String>, keep: Set<String>?, into rows: inout [Row]) {
        if let keep, !keep.contains(node.path) { return }
        let isOpen = node.kind.isContainer && open.contains(node.path)
        rows.append(.node(JSONTreeRow(depth: depth, node: node, isExpanded: isOpen)))
        guard isOpen else { return }
        let limit = pages[node.path] ?? Self.pageSize
        let isArray = if case .array = node.kind { true } else { false }
        let shown = isArray ? min(limit, node.children.count) : node.children.count
        for child in node.children.prefix(shown) {
            append(child, depth: depth + 1, open: open, keep: keep, into: &rows)
        }
        if shown < node.children.count {
            rows.append(.showMore(path: node.path, shown: shown, total: node.children.count))
        }
    }

    // MARK: Actions

    func toggle(_ node: JSONNode, subtree: Bool) {
        let isOpen = expanded.contains(node.path)
        if subtree {
            isOpen ? collapse(node) : expand(node)
        } else if isOpen {
            expanded.remove(node.path)
        } else {
            expanded.insert(node.path)
        }
    }

    func expand(_ node: JSONNode) { expanded.formUnion(node.allPaths) }
    func collapse(_ node: JSONNode) { expanded.subtract(node.allPaths) }
    func expandAll() { expanded = root.allPaths }
    func collapseAll() { expanded = [] }
    func showMore(_ path: String) { pages[path, default: Self.pageSize] += Self.pageSize }

    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

/// The JSON tree: an outline of `JSONTreeState.rows`, 28 pt rows, 16 pt per depth.
struct JSONTreeView: View {
    @State private var state: JSONTreeState
    var bodySize: CGFloat

    init(root: JSONNode, bodySize: CGFloat = Tok.Typography.Size.md) {
        _state = State(initialValue: JSONTreeState(root: root))
        self.bodySize = bodySize
    }

    init(state: JSONTreeState, bodySize: CGFloat = Tok.Typography.Size.md) {
        _state = State(initialValue: state)
        self.bodySize = bodySize
    }

    var body: some View {
        // Vertical only: a LazyVStack inside a two-axis ScrollView lays out at zero width.
        ScrollView(.vertical) {
            LazyVStack(alignment: .leading, spacing: 0) {
                if state.noMatch {
                    Hint(text: "No match")
                }
                ForEach(state.rows) { row in
                    switch row {
                    case .node(let treeRow):
                        JSONTreeRowView(row: treeRow, state: state, bodySize: bodySize)
                    case .showMore(let path, let shown, let total):
                        Button { state.showMore(path) } label: {
                            Text("Show more · \(shown) of \(total)")
                                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                                .foregroundStyle(Tok.Ink.link.color)
                                .frame(height: Tok.Size.Row.dense)
                                .padding(.leading, Space.lg)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .padding(.vertical, Space.sm)
            .padding(.horizontal, Space.md)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// `▸ key: value` with the chevron flat and grey; ⌥-click toggles the whole subtree.
private struct JSONTreeRowView: View {
    var row: JSONTreeRow
    var state: JSONTreeState
    var bodySize: CGFloat

    private var node: JSONNode { row.node }

    var body: some View {
        HStack(spacing: 0) {
            Color.clear.frame(width: Space.lg * CGFloat(row.depth), height: 1)
            disclosure
            Text(text)
                .font(Tok.Face.data(bodySize))
                .lineLimit(1)
                .textSelection(.enabled)
            Spacer(minLength: Space.lg)
        }
        .frame(height: Tok.Size.Row.dense)
        .contentShape(Rectangle())
        .contextMenu {
            Button("Copy Value") { JSONTreeState.copy(JSONTree.copyText(for: node)) }
            Button("Copy Path") { JSONTreeState.copy(node.path) }
            Divider()
            Button("Expand All") { state.expandAll() }
            Button("Collapse All") { state.collapseAll() }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(node.path)
        .accessibilityValue(node.kind.isContainer ? (row.isExpanded ? "expanded" : "collapsed") : node.summary)
    }

    @ViewBuilder private var disclosure: some View {
        if node.kind.isContainer {
            Button {
                state.toggle(node, subtree: NSEvent.modifierFlags.contains(.option))
            } label: {
                Image(systemName: row.isExpanded ? "chevron.down" : Tok.Glyph.chevron)
                    .font(.system(size: Tok.Size.iconInline))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .frame(width: Space.lg, height: Tok.Size.Row.dense)
            }
            .buttonStyle(.plain)
            .help(row.isExpanded ? "Collapse (⌥ for the whole subtree)" : "Expand (⌥ for the whole subtree)")
        } else {
            Color.clear.frame(width: Space.lg, height: 1)
        }
    }

    /// Key in `syntax.key`, `:` in punct, the value in its syntax colour or the
    /// `{3 keys}` / `[2 items]` summary in tertiary when collapsed.
    private var text: AttributedString {
        var text = AttributedString()
        if let key = node.key {
            var k = AttributedString(key)
            k.foregroundColor = Tok.Syntax.key.color
            var colon = AttributedString(": ")
            colon.foregroundColor = Tok.Syntax.punct.color
            text.append(k)
            text.append(colon)
        }
        var value: AttributedString
        switch node.kind {
        case .object where row.isExpanded, .array where row.isExpanded:
            value = AttributedString(node.kind.isObject ? "{" : "[")
            value.foregroundColor = Tok.Syntax.bracket.color
        case .object, .array:
            value = AttributedString(node.kind.isObject ? "{\(node.summary)}" : "[\(node.summary)]")
            value.foregroundColor = Tok.Ink.tertiary.color
        case .string:
            value = AttributedString(JSONTree.quote(node.scalarText))
            value.foregroundColor = node.syntaxKind.color.color
        case .number, .bool, .null:
            value = AttributedString(node.scalarText)
            value.foregroundColor = node.syntaxKind.color.color
        }
        text.append(value)
        return text
    }
}

private extension JSONKind {
    var isObject: Bool { if case .object = self { true } else { false } }
}

/// The tab bar's trailing slot for the JSON tab: a filter field and the "Sort Keys" toggle.
struct JSONTreeControls: View {
    @Bindable var state: JSONTreeState

    var body: some View {
        HStack(spacing: Space.sm) {
            TextField("Filter keys and values", text: $state.filter)
                .textFieldStyle(.plain)
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.primary.color)
                .padding(.horizontal, Space.sm)
                .frame(width: Space.section * 5, height: Tok.Size.control)
                .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                .accessibilityLabel("Filter keys and values")
            SmallButton("Sort Keys", on: state.sortKeys) { state.sortKeys.toggle() }
                .help("Sort object keys alphabetically")
        }
    }
}
