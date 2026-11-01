import AitmproxyKit
import SwiftUI

/// Toolbar parts, the flat icon set, and chips (KIT.md "Toolbar", "Chip").
struct GalleryToolbarParts: View {
    var fx: GalleryFixtures

    /// The bar icons by role, from `Tok.Glyph`.
    private static let glyphs = [
        Tok.Glyph.sidebar, Tok.Glyph.record, Tok.Glyph.pause, Tok.Glyph.compose, Tok.Glyph.clear,
        Tok.Glyph.intercept, Tok.Glyph.resume, Tok.Glyph.kill, Tok.Glyph.replay, Tok.Glyph.agent,
        Tok.Glyph.palette, Tok.Glyph.split, Tok.Glyph.copy, Tok.Glyph.lockOpen, Tok.Glyph.lock, Tok.Glyph.mark,
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xxl) {
            KitSection("Connection cluster", caption: "The pill (core dot + address) and the Proxy and Capture switches: the one home of connection state. Green dot listening · grey proxy paused · amber intercept armed. Raised capsule, 28 tall.") {
                VStack(alignment: .leading, spacing: Space.sm) {
                    ConnectionCluster().environment(fx.listening)
                    ConnectionCluster().environment(fx.captureOff)
                    ConnectionCluster().environment(fx.paused)
                }
            }
            KitSection("Agent toggle · layout switch",
                       caption: "Teal switch and count while the agent may act, grey when paused. Two flat glyphs: the active layout in ink, the other tertiary.") {
                HStack(spacing: Space.lg) {
                    AgentToggle().environment(fx.paused)
                    AgentToggle().environment(fx.agentPaused)
                    LayoutPicker().environment(fx.paused)
                    LayoutPicker().environment(fx.vertical)
                }
            }
            KitSection("Flat icons",
                       caption: "SF Symbols, regular weight, text.secondary: 16 in bars, 12 inline. No capsule, bevel or glass. The window toolbar above is the live set; its hover is the system's.") {
                VStack(alignment: .leading, spacing: Space.sm) {
                    glyphRow(size: Tok.Size.icon)
                    glyphRow(size: Tok.Size.iconInline)
                }
            }
            KitSection("Chip", caption: "Off: secondary text, no fill. On: raised capsule, medium weight. A 14 px hairline between groups.") {
                HStack(spacing: 2) {
                    Chip(title: "All", on: false) {}
                    Rectangle().fill(Tok.Line.border.color).frame(width: 1, height: Tok.Metric.chipSeparator)
                        .padding(.horizontal, Tok.Metric.gapTight)
                    Chip(title: "HTTPS", on: false) {}
                    Chip(title: "JSON", on: true) {}
                    Chip(title: "Form", on: false) {}
                }
            }
        }
    }

    private func glyphRow(size: CGFloat) -> some View {
        HStack(spacing: Space.md) {
            ForEach(Self.glyphs, id: \.self) { symbol in
                Image(systemName: symbol)
                    .font(Tok.Face.ui(size))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .frame(width: size, height: size)
            }
        }
    }
}

/// Method badges and the status vocabulary (KIT.md "Method badge", "Status").
struct GalleryBadgeParts: View {
    private static let methods: [HTTPMethod] = [.get, .post, .put, .patch, .delete, .head, .options, .connect, .ws]
    private static let codes = [200, 304, 422, 502]
    private static let pillCodes = [200, 304, 502]

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xxl) {
            KitSection("Method badge", caption: "Deep text on tint, 18 tall, radius 4, 11/600 mono, uppercase.") {
                VStack(alignment: .leading, spacing: Space.sm) {
                    HStack(spacing: Space.sm) {
                        ForEach(Self.methods.prefix(5), id: \.self) { Badge(text: $0.label, pair: $0.badge) }
                    }
                    HStack(spacing: Space.sm) {
                        ForEach(Self.methods.dropFirst(5), id: \.self) { Badge(text: $0.label, pair: $0.badge) }
                    }
                }
            }
            KitSection("Status",
                       caption: "In the list: the code as 13/500 mono text in its class colour; — pending, killed, error. In the summary strip: a pill in the matching method tint; Paused, Pending, Killed, Error and the agent tag are pills too.") {
                VStack(alignment: .leading, spacing: Space.sm) {
                    HStack(spacing: Space.md) {
                        ForEach(Self.codes, id: \.self) { code in
                            Text("\(code)").foregroundStyle((StatusClass(code)?.color ?? Tok.Ink.secondary).color)
                        }
                        Text(Format.dash).foregroundStyle(Tok.Status.pending.color)
                        Text("killed").foregroundStyle(Tok.Status.killed.color)
                        Text("error").foregroundStyle(Tok.Status.serverError.color)
                    }
                    .font(Tok.Face.data(Tok.Typography.Size.md, .medium))
                    HStack(spacing: Space.sm) {
                        ForEach(Self.pillCodes, id: \.self) { code in
                            if let cls = StatusClass(code) {
                                Badge(text: "\(code) \(StatusText.reason(code))", pair: cls.pill)
                            }
                        }
                    }
                    HStack(spacing: Space.sm) {
                        Badge(text: "Paused · request", pair: ColorPair(fg: Tok.Intercept.deep, bg: Tok.Intercept.tint), uppercase: false)
                        Badge(text: "Pending", pair: ColorPair(fg: Tok.Status.pending, bg: Tok.Intercept.tint), uppercase: false)
                        Badge(text: "Killed", pair: ColorPair(fg: Tok.Status.killed, bg: Tok.Ground.raised), uppercase: false)
                    }
                    HStack(spacing: Space.sm) {
                        Badge(text: "Error", pair: Tok.Method.delete, uppercase: false)
                        Badge(text: "agent", pair: ColorPair(fg: Tok.Agent.deep, bg: Tok.Agent.tint), uppercase: false)
                    }
                }
            }
            KitSection("Status bar small button", caption: "20 tall, control outline, 11 pt. On: active fill, primary text.") {
                HStack(spacing: Space.sm) {
                    SmallButton("Clear") {}
                    SmallButton("Filter") {}
                    SmallButton("Auto-select", on: true) {}
                }
                .padding(.horizontal, Space.md)
                .frame(height: Tok.Size.statusBar)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Tok.Ground.raised.color)
            }
        }
    }
}

/// The bar buttons on their real grounds, and the empty states (KIT.md
/// "Primary button", "Ghost button", "Empty state").
struct GalleryButtonParts: View {
    var body: some View {
        VStack(alignment: .leading, spacing: Space.xxl) {
            KitSection("Primary · ghost button",
                       caption: "On the paused bar: inverse primary with its shortcut, translucent ghosts, a chevron on the one with a menu. On the armed notice: ghosts in intercept.deep. Pressed scales to 0.97 for 120 ms; not captured.") {
                VStack(spacing: 2) {
                    bar(Tok.Intercept.base) {
                        PrimaryButton("Resume", hint: "⌘⏎") {}
                        GhostButton("Resume All") {}
                    }
                    bar(Tok.Intercept.base) {
                        GhostButton("Kill", hint: "⌘\\", menu: true) {}
                        GhostButton("Disarm", hint: "i") {}
                    }
                    bar(Tok.Intercept.tint) {
                        GhostButton("Rules…", onColor: Tok.Intercept.deep) {}
                        GhostButton("Disarm", hint: "i", onColor: Tok.Intercept.deep) {}
                    }
                }
            }
            KitSection("Empty state", caption: "Keeps the frame and says the trade's words; 20/500 title, 13 tertiary line, no illustration.") {
                VStack(spacing: Space.sm) {
                    EmptyFlows(filtered: false, listen: "127.0.0.1:8080").frame(height: GalleryFixtures.emptyHeight)
                    EmptyFlows(filtered: true, listen: "127.0.0.1:8080").frame(height: GalleryFixtures.emptyHeight)
                    EmptyInspector().frame(height: GalleryFixtures.emptyHeight)
                }
            }
        }
    }

    private func bar<C: View>(_ ground: DynamicColor, @ViewBuilder content: () -> C) -> some View {
        HStack(spacing: Tok.Metric.gapTight, content: content)
            .padding(.horizontal, Space.md)
            .frame(height: Tok.Size.interceptBar)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(ground.color)
    }
}

/// The body viewer, the header table and the loading bars (KIT.md "Code
/// view line", "Header table row", "Loading bars").
struct GalleryViewerParts: View {
    private static let lines: [CodeLine] = [
        CodeLine(runs: Syntax.startLine("POST /api/auth/login HTTP/2")),
        CodeLine(runs: Syntax.header(line: "host: auth.shop-staging.test")),
        CodeLine(runs: Syntax.header(line: "x-forwarded-for: 127.0.0.1"), edited: true, current: true),
        CodeLine(runs: []),
        CodeLine(runs: Syntax.runs(for: "{ \"remember\": true, \"count\": 2 }", contentType: "application/json")),
    ]
    private static let headers: [HTTPMessage.Header] = [
        .init("content-type", "application/json"),
        .init("cache-control", "no-store"),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xxl) {
            KitSection("Code view line",
                       caption: "Normal · current (currentLine fill, secondary number) · edited (2 px intercept edge) · a hint footer. 13 on 20, 44 gutter, syntax tokens on the runs.") {
                CodeView(lines: Self.lines, footer: "1 edit pending · Revert to original")
                    .frame(height: Tok.Size.Row.dense * 5)
                    .border(Tok.Line.border.color)
            }
            KitSection("Header table row", caption: "Name in syntax.key mono, value in primary, rule separators, 28 tall.") {
                HeaderTable(headers: Self.headers)
                    .frame(height: Tok.Size.Row.dense * 2)
                    .border(Tok.Line.border.color)
            }
            KitSection("Loading bars", caption: "Final layout, grey bars at real size, no shimmer, no layout shift when data lands.") {
                LoadingLines().frame(height: Space.section * 3)
            }
        }
    }
}
