import AitmproxyKit
import AppKit
import SwiftUI

/// The Browser view (S-054, S-055): a tabs row, a flat toolbar, the page as a
/// live image that relays clicks and keys, and console / DOM drawers beneath.
struct BrowserPanel: View {
    @Environment(Session.self) private var session
    @Bindable var state: BrowserState
    @FocusState private var urlFocused: Bool
    @FocusState private var pageFocused: Bool

    private static let drawerHeight: CGFloat = 160

    var body: some View {
        VStack(spacing: 0) {
            tabsRow
            Rule()
            toolbar
            Rule()
            if !state.available {
                // The bus is down: the toolbar is disabled, so say what is wrong
                // rather than invite a ⌘T that cannot work.
                ContentUnavailableView {
                    Label("Browser needs the bus", systemImage: "bolt.horizontal.circle")
                } description: {
                    Text("Connect to a running core to open pages and drive the browser.")
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if state.tabs.isEmpty {
                ContentUnavailableView {
                    Label("No tabs open", systemImage: "macwindow")
                } description: {
                    Text("Open a page with ⌘T to start browsing.")
                } actions: {
                    Button("New Tab") { state.newTab() }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                page
            }
            if state.consoleVisible { Rule(); ConsoleDrawer(state: state).frame(height: Self.drawerHeight) }
            if state.domVisible { Rule(); DOMDrawer(lines: state.domOutline).frame(height: Self.drawerHeight) }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .gridArea("browser", inset: Space.md)
        .onAppear { state.startLive() }
        .onDisappear { state.stopLive() }
        .onChange(of: state.urlFocusTick) { urlFocused = true }
        .onChange(of: state.available) { if state.available { state.startLive() } else { state.stopLive() } }
    }

    // MARK: Tabs

    private var tabsRow: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: Space.xs) {
                ForEach(state.tabs) { tab in
                    let on = tab.id == state.currentID
                    HStack(spacing: Tok.Metric.gapTight) {
                        Button { state.select(tab.id) } label: {
                            Text(tab.title.isEmpty ? tab.url : tab.title)
                                .font(Tok.Face.ui(Tok.Typography.Size.md, on ? .medium : .regular))
                                .foregroundStyle(on ? Tok.Ink.primary.color : Tok.Ink.secondary.color)
                                .lineLimit(1)
                                .frame(maxWidth: 200)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(on ? .isSelected : [])
                        glyphButton("xmark", size: Tok.Size.iconInline, help: "Close tab") { state.close(tab.id) }
                    }
                    .padding(.leading, Space.sm)
                    .frame(height: Tok.Size.tabBar)
                    .overlay(alignment: .bottom) {
                        if on { Rectangle().fill(Tok.Ink.primary.color).frame(height: 2).padding(.horizontal, Space.sm) }
                    }
                }
                glyphButton("plus", size: Tok.Size.iconInline, help: "New tab (⌘T)") { state.newTab() }
            }
            .padding(.horizontal, Space.sm)
        }
        .frame(height: Tok.Size.tabBar)
    }

    // MARK: Toolbar

    private var toolbar: some View {
        HStack(spacing: Space.sm) {
            glyphButton("chevron.left", help: "Back") { Task { await state.back() } }
            glyphButton("chevron.right", help: "Forward") { Task { await state.forward() } }
            glyphButton("arrow.clockwise", help: "Reload") { Task { await state.reload() } }
            TextField("https://", text: $state.urlText)
                .textFieldStyle(.plain)
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .padding(.horizontal, Space.sm)
                .frame(height: Tok.Size.control)
                .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control)
                    .strokeBorder(urlFocused ? Palette.accent : Tok.Line.control.color, lineWidth: urlFocused ? 2 : 1))
                .focused($urlFocused)
                .onSubmit { Task { await state.navigate(state.urlText) } }
                .accessibilityLabel("URL")
            glyphButton("camera", help: "Save screenshot") { state.saveScreenshot() }
            drawerToggle("Console", symbol: "terminal", on: state.consoleVisible,
                         help: "Show the JavaScript console") { state.consoleVisible.toggle() }
            drawerToggle("Outline", symbol: "list.bullet.indent", on: state.domVisible,
                         help: "Show the page's DOM outline") {
                state.domVisible.toggle()
                if state.domVisible { Task { await state.dom() } }
            }
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.toolbar)
        .disabled(!state.available)
        .help(state.available ? "" : "Browser needs the bus")
    }

    private func glyphButton(_ symbol: String, size: CGFloat = Tok.Size.icon, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: size, weight: .regular))
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: Tok.Size.control, height: Tok.Size.control)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityLabel(help)
    }

    /// A labelled, flat drawer toggle (Console / Outline) that carries an
    /// on-state while its drawer is open, so the toolbar shows what is showing.
    private func drawerToggle(_ title: String, symbol: String, on: Bool, help: String,
                              action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: Space.xs) {
                Image(systemName: symbol).font(.system(size: Tok.Typography.Size.xs, weight: .medium))
                Text(title)
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
            .foregroundStyle(on ? Tok.Ink.primary.color : Tok.Ink.secondary.color)
            .padding(.horizontal, Space.sm)
            .frame(height: Tok.Size.control)
            .background(on ? Tok.Ground.raised.color : .clear,
                        in: RoundedRectangle(cornerRadius: Tok.Radius.control))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityLabel(help)
        .accessibilityAddTraits(on ? .isSelected : [])
    }

    // MARK: Page

    private var page: some View {
        GeometryReader { proxy in
            let frame = state.current?.lastFrame.flatMap(PageFrame.init)
            // Mat the page inside the well so the aspect-fit gutters read as a deliberate
            // frame, not a broken/empty pane: a consistent inset, then a bordered, rounded page.
            let matted = CGSize(width: max(proxy.size.width - Space.md * 2, 0),
                                height: max(proxy.size.height - Space.md * 2, 0))
            ZStack(alignment: .topTrailing) {
                // A raised matte reads in light mode (the page/surface hairline alone did not).
                Tok.Ground.raised.color
                if let frame {
                    let fit = frame.fit(in: matted)
                    Image(nsImage: frame.image)
                        .resizable()
                        .interpolation(frame.pixelSize.width < 64 ? .none : .medium)
                        .frame(width: fit.size.width, height: fit.size.height)
                        .clipShape(RoundedRectangle(cornerRadius: Tok.Radius.panel))
                        .overlay(RoundedRectangle(cornerRadius: Tok.Radius.panel)
                            .strokeBorder(Tok.Line.border.color, lineWidth: 1))
                        .contentShape(Rectangle())
                        .onTapGesture { location in
                            pageFocused = true
                            let point = CGPoint(x: location.x / fit.scale, y: location.y / fit.scale)
                            Task { await state.click(at: point, imageSize: frame.pixelSize) }
                        }
                        .accessibilityLabel(state.current.map { "\($0.title) — \($0.url)" } ?? "Page")
                        .accessibilityAddTraits(.isImage)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    // No frames yet: a placeholder at the default window aspect, framed like a
                    // real page so the first frame lands without a visual jump.
                    let fit = PageFrame.placeholder(in: matted)
                    RoundedRectangle(cornerRadius: Tok.Radius.panel)
                        .fill(Tok.Ground.surface.color)
                        .overlay(RoundedRectangle(cornerRadius: Tok.Radius.panel)
                            .strokeBorder(Tok.Line.border.color, lineWidth: 1))
                        .frame(width: fit.size.width, height: fit.size.height)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                Text(state.liveChipText)
                    .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .padding(.horizontal, Space.sm)
                    .frame(height: Tok.Metric.chip)
                    .background(Tok.Ground.raised.color, in: Capsule())
                    .padding(Space.sm)
                    .accessibilityLabel(state.liveChipText)
            }
            .gridProbe("browser.page", area: "browser")
            .padding(Space.md)
        }
        .focusable()
        .focused($pageFocused)
        .focusEffectDisabled()
        .onKeyPress(phases: .down) { press in
            guard press.key != .escape, press.modifiers.isDisjoint(with: [.command, .control]) else { return .ignored }
            let text = press.key == .return ? "\n" : press.characters
            Task { await state.type(text) }
            return .handled
        }
    }
}

/// A decoded frame and its pixel size, with the aspect-fit rectangle inside a viewport.
struct PageFrame {
    let image: NSImage
    let pixelSize: CGSize

    struct Fit {
        var size: CGSize
        var scale: CGFloat
    }

    init?(data: Data) {
        guard let image = NSImage(data: data) else { return nil }
        self.image = image
        if let rep = NSBitmapImageRep(data: data), rep.pixelsWide > 0 {
            pixelSize = CGSize(width: rep.pixelsWide, height: rep.pixelsHigh)
        } else {
            pixelSize = image.size
        }
    }

    func fit(in viewport: CGSize) -> Fit { Self.fit(pixelSize, in: viewport) }

    /// The default window's 1440 × 900 proportions until the first frame says otherwise.
    static func placeholder(in viewport: CGSize) -> Fit { fit(CGSize(width: 1440, height: 900), in: viewport) }

    private static func fit(_ size: CGSize, in viewport: CGSize) -> Fit {
        guard size.width > 0, size.height > 0, viewport.width > 0, viewport.height > 0 else {
            return Fit(size: .zero, scale: 1)
        }
        let scale = min(viewport.width / size.width, viewport.height / size.height)
        return Fit(size: CGSize(width: size.width * scale, height: size.height * scale), scale: scale)
    }
}

/// `Eval…`: the lines so far and an input; ⏎ runs `browser.eval`.
struct ConsoleDrawer: View {
    @Bindable var state: BrowserState
    @State private var input = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { reader in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        if state.consoleLines.isEmpty { Hint(text: "Type an expression below; its value prints here.") }
                        ForEach(Array(state.consoleLines.enumerated()), id: \.offset) { index, line in
                            Text(line)
                                .font(Tok.Face.data(Tok.Typography.Size.sm))
                                .foregroundStyle(line.hasPrefix("›") ? Tok.Ink.secondary.color : Tok.Ink.primary.color)
                                .textSelection(.enabled)
                                .frame(minHeight: Space.xl)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(index)
                        }
                    }
                    .padding(.horizontal, Space.md)
                    .padding(.vertical, Space.xs)
                }
                .onChange(of: state.consoleLines.count) { if let last = state.consoleLines.indices.last { reader.scrollTo(last) } }
            }
            Rule(color: Tok.Line.rule)
            HStack(spacing: Space.sm) {
                Text("›").font(Tok.Face.data(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
                TextField("document.title", text: $input)
                    .textFieldStyle(.plain)
                    .font(Tok.Face.data(Tok.Typography.Size.md))
                    .focused($focused)
                    .onSubmit {
                        let expr = input
                        input = ""
                        Task { await state.eval(expr) }
                    }
                    .accessibilityLabel("Eval expression")
            }
            .padding(.horizontal, Space.md)
            .frame(height: Tok.Size.control)
        }
        .onAppear { focused = true }
    }
}

/// `DOM`: the outline as indented mono lines.
struct DOMDrawer: View {
    var lines: [String]

    var body: some View {
        ScrollView([.vertical, .horizontal]) {
            VStack(alignment: .leading, spacing: 0) {
                if lines.isEmpty { Hint(text: "No DOM yet — click DOM to fetch it.") }
                ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                    Text(line)
                        .font(Tok.Face.data(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.primary.color)
                        .lineLimit(1)
                        .frame(minHeight: Space.xl)
                }
            }
            .padding(.horizontal, Space.md)
            .padding(.vertical, Space.xs)
            .textSelection(.enabled)
        }
    }
}
