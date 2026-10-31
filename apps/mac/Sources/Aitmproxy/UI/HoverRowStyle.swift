import SwiftUI

/// The Overview's clickable rows (`BarRow`, `HostRow`, `FlowListRow`): the dense row height,
/// the badge-radius hover fill and a full-width hit area, with the hover state kept here so
/// no row tracks it. A label that reacts to hover reads `\.rowHovered`.
struct HoverRowStyle: ButtonStyle {
    @State private var hovered = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .environment(\.rowHovered, hovered)
            .padding(.horizontal, Space.xs)
            .frame(height: Tok.Size.Row.dense)
            .background(hovered ? Tok.Ground.hover.color : .clear, in: RoundedRectangle(cornerRadius: Tok.Radius.badge))
            .contentShape(Rectangle())
            .opacity(configuration.isPressed ? 0.7 : 1)
            .onHover { hovered = $0 }
    }
}

extension EnvironmentValues {
    /// True while the pointer is over the `HoverRowStyle` button the view sits in.
    @Entry var rowHovered = false
}

/// The trailing chevron of a hover row: visible only while the row is hovered.
struct HoverChevron: View {
    @Environment(\.rowHovered) private var hovered

    var body: some View {
        Image(systemName: Tok.Glyph.chevron)
            .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
            .foregroundStyle(Tok.Ink.tertiary.color)
            .opacity(hovered ? 1 : 0)
            .accessibilityHidden(true)
    }
}
