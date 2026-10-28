import AitmproxyKit
import SwiftUI

/// `Field · Wire type · Value` for a raw protobuf decode (S-024). Nested
/// messages indent 16 pt per level behind a flat chevron, like the JSON tree.
struct ProtobufView: View {
    var fields: [ProtoField]
    var bodySize: CGFloat = Tok.Typography.Size.md
    /// Index paths (`0.2.1`) of the open nested messages; top-level nesting starts open.
    @State private var expanded: Set<String>

    init(fields: [ProtoField], bodySize: CGFloat = Tok.Typography.Size.md) {
        self.fields = fields
        self.bodySize = bodySize
        _expanded = State(initialValue: Set(fields.indices.filter { fields[$0].nested != nil }.map { "\($0)" }))
    }

    private static let fieldColumn: CGFloat = Space.section * 2
    private static let typeColumn: CGFloat = Space.section * 4

    private struct Row: Identifiable {
        var id: String
        var depth: Int
        var field: ProtoField
        var isExpanded: Bool
    }

    private var rows: [Row] {
        var rows: [Row] = []
        append(fields, prefix: "", depth: 0, into: &rows)
        return rows
    }

    private func append(_ fields: [ProtoField], prefix: String, depth: Int, into rows: inout [Row]) {
        for (index, field) in fields.enumerated() {
            let id = prefix.isEmpty ? "\(index)" : "\(prefix).\(index)"
            let open = field.nested != nil && expanded.contains(id)
            rows.append(Row(id: id, depth: depth, field: field, isExpanded: open))
            if open, let nested = field.nested {
                append(nested, prefix: id, depth: depth + 1, into: &rows)
            }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            ScrollView([.vertical, .horizontal]) {
                LazyVStack(alignment: .leading, spacing: 0) {
                    if fields.isEmpty {
                        Hint(text: "No fields").padding(.leading, Space.md)
                    }
                    ForEach(rows) { row in
                        line(row)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .textSelection(.enabled)
        }
    }

    /// Section-role column titles (11/500, uppercase, tracked) on a 28 pt header.
    private var header: some View {
        HStack(spacing: Space.md) {
            Text("Field").frame(width: Self.fieldColumn, alignment: .leading)
            Text("Wire type").frame(width: Self.typeColumn, alignment: .leading)
            Text("Value")
            Spacer(minLength: 0)
        }
        .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
        .kerning(0.5)
        .textCase(.uppercase)
        .foregroundStyle(Tok.Ink.tertiary.color)
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.columnHeader)
        .overlay(alignment: .bottom) { Rule() }
    }

    private func line(_ row: Row) -> some View {
        HStack(spacing: Space.md) {
            HStack(spacing: 0) {
                Color.clear.frame(width: Space.lg * CGFloat(row.depth), height: 1)
                disclosure(row)
                Text("\(row.field.number)")
                    .foregroundStyle(Tok.Syntax.key.color)
            }
            .frame(width: Self.fieldColumn, alignment: .leading)
            Text(row.field.wireType.description)
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: Self.typeColumn, alignment: .leading)
            Text(row.field.valueText)
                .foregroundStyle(row.field.nested != nil ? Tok.Ink.tertiary.color : Tok.Ink.primary.color)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
        .font(Tok.Face.data(bodySize))
        .lineLimit(1)
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.Row.dense)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .combine)
        .accessibilityValue(row.field.nested == nil ? "" : (row.isExpanded ? "expanded" : "collapsed"))
    }

    @ViewBuilder private func disclosure(_ row: Row) -> some View {
        if row.field.nested != nil {
            Button {
                if expanded.contains(row.id) { expanded.remove(row.id) } else { expanded.insert(row.id) }
            } label: {
                Image(systemName: row.isExpanded ? "chevron.down" : Tok.Glyph.chevron)
                    .font(.system(size: Tok.Size.iconInline))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .frame(width: Space.lg, height: Tok.Size.Row.dense)
            }
            .buttonStyle(.plain)
            .help(row.isExpanded ? "Collapse message" : "Expand message")
        } else {
            Color.clear.frame(width: Space.lg, height: 1)
        }
    }
}

/// Body picker ▸ Protobuf: the field table, or hex under a notice when the bytes do not walk.
struct ProtobufBodyView: View {
    var data: Data
    var bodySize: CGFloat = Tok.Typography.Size.md

    var body: some View {
        switch Result(catching: { () throws(ProtobufRawError) in try ProtobufRaw.decode(data) }) {
        case .success(let fields):
            ProtobufView(fields: fields, bodySize: bodySize)
        case .failure(let error):
            VStack(alignment: .leading, spacing: 0) {
                Hint(text: "Not protobuf — showing hex · \(error.description)")
                    .padding(.leading, Space.md)
                    .padding(.top, Space.xs)
                HexView(data: data, bodySize: bodySize)
            }
        }
    }
}

/// Body picker ▸ MessagePack: the JSON tree, or hex under a notice when the bytes do not decode.
struct MessagePackBodyView: View {
    var data: Data
    var bodySize: CGFloat = Tok.Typography.Size.md

    var body: some View {
        switch Result(catching: { () throws(MessagePackError) in try MessagePack.decode(data) }) {
        case .success(let root):
            JSONTreeView(root: root, bodySize: bodySize)
        case .failure(let error):
            VStack(alignment: .leading, spacing: 0) {
                Hint(text: "Not MessagePack — showing hex · \(error.description)")
                    .padding(.leading, Space.md)
                    .padding(.top, Space.xs)
                HexView(data: data, bodySize: bodySize)
            }
        }
    }
}
