import AitmproxyKit
import SwiftUI

/// The Connection Log page (S-064): `time · client · host · TLS · ALPN · SNI ·
/// result` at 28 pt in mono, time order, the header kept in view. Selecting a
/// row narrows the flow list to that connection's flows. Until `flow.detail`
/// (F5) reports connections the rows are derived from the captured flows.
struct ConnectionLogPanel: View {
    @Environment(Session.self) private var session
    @State private var selected: String?

    static let note = "Derived from captured flows until flow.detail (F5) reports connections"

    private static let columns: [(title: String, width: CGFloat?)] = [
        ("Time", 96), ("Client", 128), ("Host", 200), ("TLS", 56), ("ALPN", 40), ("SNI", 200), ("Result", nil),
    ]

    private var records: [ConnectionRecord] {
        ConnectionRecord.derive(rows: session.rows, details: session.details)
    }

    var body: some View {
        let records = records
        VStack(spacing: 0) {
            header(records.count)
            Rule()
            ColumnHeads(columns: Self.columns)
            if records.isEmpty {
                Text("No connections yet.")
                    .font(Tok.Face.ui(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(records) { record in
                            ConnectionRow(record: record, selected: record.id == selected) { choose(record) }
                        }
                    }
                }
            }
            Rule(color: Tok.Line.rule)
            Hint(text: Self.note)
                .padding(.leading, Space.md)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .gridArea("connection-log", inset: 0)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Connection Log")
    }

    private func header(_ count: Int) -> some View {
        HStack(spacing: Space.md) {
            TrackedLabel("Connection Log").accessibilityAddTraits(.isHeader)
            Spacer(minLength: Space.sm)
            Text(count == 1 ? "1 connection" : "\(count) connections")
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.tertiary.color)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.filterBar)
    }

    /// The flow list beneath narrows to the connection's flows; the inspector shows the first.
    private func choose(_ record: ConnectionRecord) {
        selected = record.id
        session.selection = Set(record.flowIDs)
        session.focused = record.flowIDs.first
    }
}

/// One connection at 28 pt: mono cells, a dash where the fact is missing,
/// an error result in `status.serverError`.
private struct ConnectionRow: View {
    var record: ConnectionRecord
    var selected: Bool
    var action: () -> Void
    @State private var hovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: Space.md) {
                cell(Format.time(record.at), width: 96, color: Tok.Ink.secondary)
                cell(record.client, width: 128, color: Tok.Ink.secondary)
                cell(record.authority, width: 200, color: Tok.Ink.primary)
                cell(record.tls, width: 56)
                cell(record.alpn, width: 40)
                cell(record.sni, width: 200)
                Text(record.result.text)
                    .font(Tok.Face.data(Tok.Typography.Size.md, record.result.isError ? .medium : .regular))
                    .foregroundStyle(record.result.isError ? Tok.Status.serverError.color : Tok.Ink.secondary.color)
                    .lineLimit(1)
                    .help(record.result.text)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, Space.md)
            .frame(height: Tok.Size.Row.dense)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(selected ? Tok.Ground.active.color : hovered ? Tok.Ground.hover.color : .clear)
            .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(Format.time(record.at)), \(record.client), \(record.authority), \(record.result.text)")
        .accessibilityValue(selected ? "selected" : "")
        .accessibilityHint("Shows its flows")
    }

    /// A fixed-width mono cell; nil reads as a tertiary dash.
    private func cell(_ text: String?, width: CGFloat, color: DynamicColor = Tok.Ink.secondary) -> some View {
        Text(text ?? Format.dash)
            .font(Tok.Face.data(Tok.Typography.Size.md))
            .foregroundStyle(text == nil ? Tok.Ink.tertiary.color : color.color)
            .lineLimit(1)
            .truncationMode(.middle)
            .frame(width: width, alignment: .leading)
            .help(text ?? "")
    }
}
