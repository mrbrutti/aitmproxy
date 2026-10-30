import SwiftUI

/// Settings > Appearance: the accent color. Light and dark mode follow the Mac.
struct AppearanceSettings: View {
    @Bindable private var store = ThemeStore.shared

    var body: some View {
        Section {
            AccentPreview()
                .padding(.vertical, Space.xs)
            LabeledContent("Accent color") {
                VStack(alignment: .trailing, spacing: Space.xs) {
                    HStack(spacing: Space.sm) {
                        ForEach(Theme.all) { theme in
                            AccentSwatch(theme: theme, selected: store.themeID == theme.id) {
                                store.themeID = theme.id
                            }
                        }
                    }
                    Text(store.theme.name)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

/// A small sample of aitmproxy's OWN surfaces in the chosen accent — a sidebar
/// with a selected page, two flow rows (method + status badges, accent path link),
/// and the primary button + Agent toggle. The accent lifts chrome and selection;
/// the method/status hues are fixed data colours and stay put. Redraws on pick.
private struct AccentPreview: View {
    private let shape = RoundedRectangle(cornerRadius: 12, style: .continuous)

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            content
        }
        .frame(height: 152)
        .background(.background, in: shape)
        .clipShape(shape)
        .overlay(shape.strokeBorder(.separator, lineWidth: 1))
        .allowsHitTesting(false)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Preview of the accent colour on aitmproxy's own components")
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.xs) {
                ProductMark().frame(width: 12, height: 12)
                Text("aitmproxy").font(.caption.weight(.medium)).foregroundStyle(.primary)
            }
            .padding(.leading, Space.xs)
            .padding(.bottom, Space.sm)
            sidebarRow("Overview", symbol: "chart.bar", selected: false)
            sidebarRow("Connection Log", symbol: "point.3.connected.trianglepath.dotted", selected: true)
            sidebarRow("Scan", symbol: "magnifyingglass", selected: false)
            Spacer(minLength: 0)
        }
        .padding(Space.sm)
        .frame(width: 148)
        .background(.background.secondary)
    }

    private func sidebarRow(_ title: String, symbol: String, selected: Bool) -> some View {
        Label(title, systemImage: symbol)
            .font(.caption)
            .foregroundStyle(selected ? Palette.accentText : .primary)
            .lineLimit(1)
            .padding(.horizontal, Space.sm)
            .frame(maxWidth: .infinity, minHeight: 24, alignment: .leading)
            .background(selected ? Palette.accent.opacity(0.15) : .clear,
                        in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            flowRow(method: "GET", pair: Tok.Method.get, host: "api.shop-staging.test",
                    path: "/api/products", status: "200", statusColor: Tok.Status.success)
            flowRow(method: "POST", pair: Tok.Method.post, host: "auth.shop-staging.test",
                    path: "/api/auth/login", status: "paused", statusColor: Tok.Intercept.deep)
            Spacer(minLength: 0)
            // Drawn, not real controls: the preview is a picture, and real controls
            // turn gray when the window is not in front.
            HStack {
                Text("Resume")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(Palette.onAccent)
                    .padding(.horizontal, Space.md)
                    .frame(height: 24)
                    .background(Palette.accent, in: Capsule())
                Spacer()
                Text("Agent").font(.caption).foregroundStyle(.secondary)
                Capsule()
                    .fill(Palette.accent)
                    .frame(width: 28, height: 16)
                    .overlay(alignment: .trailing) {
                        Circle().fill(.white).padding(2).shadow(color: .black.opacity(0.2), radius: 1, y: 1)
                    }
            }
        }
        .padding(Space.md)
    }

    private func flowRow(method: String, pair: ColorPair, host: String, path: String,
                         status: String, statusColor: DynamicColor) -> some View {
        HStack(spacing: Space.sm) {
            Badge(text: method, pair: pair)
            (Text(host).foregroundStyle(Tok.Ink.primary.color)
                + Text(path).foregroundStyle(Palette.accentText))
                .font(Tok.Face.data(Tok.Typography.Size.xs))
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: Space.xs)
            Text(status)
                .font(Tok.Face.data(Tok.Typography.Size.xs, .medium))
                .foregroundStyle(statusColor.color)
        }
    }
}

/// One color dot, like the accent row in System Settings.
private struct AccentSwatch: View {
    let theme: Theme
    let selected: Bool
    let choose: () -> Void

    var body: some View {
        Button(action: choose) {
            Circle()
                .fill(fill)
                .frame(width: 16, height: 16)
                .overlay {
                    if selected {
                        Circle().fill(theme.onAccent).frame(width: 6, height: 6) // grid: ok
                    }
                }
                .overlay(Circle().strokeBorder(.primary.opacity(0.15), lineWidth: 1))
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .help(theme.name)
        .accessibilityLabel(theme.name)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var fill: AnyShapeStyle {
        if let tint = theme.tint {
            AnyShapeStyle(tint)
        } else {
            AnyShapeStyle(AngularGradient(colors: [.red, .orange, .yellow, .green, .blue, .purple, .pink, .red],
                                          center: .center))
        }
    }
}
