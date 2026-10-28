import AitmproxyKit
import SwiftUI

/// Cookies / Set-Cookie as a table (S-019): Name · Value · Domain · Path ·
/// Expires · Flags. Names in `syntax.key`, values in ink; a long value
/// truncates with the whole of it in a tooltip. Empty: "No cookies".
struct CookieTable: View {
    var cookies: [Cookie]
    var bodySize: CGFloat = Tok.Typography.Size.md

    private static let columns: [(title: String, width: CGFloat?)] = [
        ("Name", 120), ("Value", 200), ("Domain", 160), ("Path", 72), ("Expires", 168), ("Flags", nil),
    ]

    var body: some View {
        if cookies.isEmpty {
            Hint(text: "No cookies")
                .padding(.leading, Space.md)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            ScrollView([.vertical, .horizontal]) {
                VStack(spacing: 0) {
                    ColumnHeads(columns: Self.columns)
                    ForEach(Array(cookies.enumerated()), id: \.offset) { _, cookie in
                        row(cookie)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func row(_ cookie: Cookie) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Space.md) {
            cell(cookie.name, width: 120).foregroundStyle(Tok.Syntax.key.color)
            cell(cookie.value, width: 200)
            cell(cookie.domain ?? Format.dash, width: 160, dim: cookie.domain == nil)
            cell(cookie.path ?? Format.dash, width: 72, dim: cookie.path == nil)
            cell(expires(cookie), width: 168, dim: cookie.expires == nil && cookie.maxAge == nil)
            cell(cookie.flagsText.isEmpty ? Format.dash : cookie.flagsText, width: nil, dim: cookie.flagsText.isEmpty)
            Spacer(minLength: 0)
        }
        .font(Tok.Face.data(bodySize))
        .padding(.horizontal, Space.md)
        .frame(minHeight: Tok.Size.Row.dense)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(cookie.name), \(cookie.value)")
        .accessibilityValue([cookie.domain, cookie.path, cookie.flagsText].compactMap { $0 }.joined(separator: ", "))
    }

    private func cell(_ text: String, width: CGFloat?, dim: Bool = false) -> some View {
        Text(text)
            .foregroundStyle(dim ? Tok.Ink.tertiary.color : Tok.Ink.primary.color)
            .lineLimit(1)
            .truncationMode(.tail)
            .frame(width: width, alignment: .leading)
            .frame(minWidth: width == nil ? 120 : nil, alignment: .leading)
            .help(text)
            .textSelection(.enabled)
    }

    /// The Expires column: the date when given, else the Max-Age as seconds, else a dash.
    private func expires(_ cookie: Cookie) -> String {
        if let date = cookie.expires {
            return date.formatted(.dateTime.year().month(.abbreviated).day().hour().minute())
        }
        if let maxAge = cookie.maxAge { return "max-age \(maxAge) s" }
        return Format.dash
    }
}

/// A column-head row in the flow list's header style: 11/500 tracked
/// capitals in the tertiary tier, 28 tall, a 1 px border under.
struct ColumnHeads: View {
    var columns: [(title: String, width: CGFloat?)]

    var body: some View {
        HStack(spacing: Space.md) {
            ForEach(Array(columns.enumerated()), id: \.offset) { _, column in
                Text(column.title.uppercased())
                    .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                    .tracking(0.5)
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .lineLimit(1)
                    .frame(width: column.width, alignment: .leading)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.columnHeader)
        .overlay(alignment: .bottom) { Rule() }
        .accessibilityHidden(true)
    }
}

/// The request's query string as decoded `name : value` rows (S-019).
struct QueryTable: View {
    var query: String?

    var body: some View {
        HeaderTable(headers: Self.pairs(query))
    }

    /// `a=1&b=%20c&flag` → `a: 1`, `b:  c`, `flag:` (percent-decoded; `+` kept as written).
    static func pairs(_ query: String?) -> [HTTPMessage.Header] {
        guard let query, !query.isEmpty else { return [] }
        return query.split(separator: "&", omittingEmptySubsequences: true).map { pair in
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            let name = parts.first ?? ""
            let value = parts.count > 1 ? parts[1] : ""
            return .init(name.removingPercentEncoding ?? name, value.removingPercentEncoding ?? value)
        }
    }
}
