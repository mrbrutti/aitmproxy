import AitmproxyKit
import AppKit
import SwiftUI

/// Every part of the kit in every state it can take, on one page
/// (design/KIT.md). Shown instead of the shell when APP_KIT_GALLERY=1;
/// snapshot mode then writes gallery-light.png and gallery-dark.png (it
/// flips NSApp.appearance, so the parts render in both modes untouched).
/// Every part here is the real view; a state a snapshot cannot force
/// (hover, pressed) is named in a caption, never faked with shapes.
/// Layout: the sidebar column beside the wide parts, then four columns of
/// small parts. About 1100 pt tall: snapshot mode grows the window to the
/// screen; a smaller screen scrolls.
struct KitGallery: View {
    static let enabled = ProcessInfo.processInfo.environment["APP_KIT_GALLERY"] == "1"

    @State private var fx = GalleryFixtures()
    @State private var selection: Set<FlowID> = [GalleryFixtures.flowRows[0].id]
    @State private var requestTab: RequestTab = .raw
    @State private var responseTab: ResponseTab = .body

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.xxl) {
                HStack(alignment: .top, spacing: Space.xxl) {
                    sidebarColumn.frame(width: Tok.Size.sidebar)
                    VStack(alignment: .leading, spacing: Space.xxl) {
                        flowRows
                        interceptBars
                        inspectorHead
                    }
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                }
                HStack(alignment: .top, spacing: Space.xxl) {
                    GalleryToolbarParts(fx: fx).frame(maxWidth: .infinity, alignment: .topLeading)
                    GalleryBadgeParts().frame(maxWidth: .infinity, alignment: .topLeading)
                    GalleryButtonParts().frame(maxWidth: .infinity, alignment: .topLeading)
                    GalleryViewerParts().frame(maxWidth: .infinity, alignment: .topLeading)
                }
            }
            .padding(Space.xxl)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Tok.Ground.surface.color)
    }

    private var sidebarColumn: some View {
        VStack(alignment: .leading, spacing: Space.xxl) {
            KitSection("Sidebar row · group label · count chip",
                       caption: "Scope selected: active fill, medium label; queue counts on raised, the agent count on teal tint; one pinned host as a sub-row. Hover fill: TODO (story S-…).") {
                SidebarView().environment(fx.sidebar)
                    .frame(height: GalleryFixtures.sidebarHeight)
                    .border(Tok.Line.border.color)
            }
            KitSection("Product mark · monogram", caption: "The mark in the accent; monograms on raised, radius 4.") {
                HStack(spacing: Space.sm) {
                    ProductMark().frame(width: Tok.Size.icon, height: Tok.Size.icon)
                    ForEach(["o", "S", "$", "P"], id: \.self) { Monogram(text: $0) }
                }
            }
        }
    }

    private var flowRows: some View {
        KitSection("Flow row",
                   caption: "41 selected (active fill, never the accent) · 42 normal, marked cyan · 44 out of scope (tertiary) · 46 replay ↻, agent edge and tag · 49 killed (struck) · 50 paused (amber edge, Paused badge, edited pencil) · 52 pending (amber dot, — status). Hover fill is not captured.") {
            // In memory only (layoutURL nil): the gallery never writes a columns.json.
            FlowTableView(rows: GalleryFixtures.flowRows, selection: $selection, sort: .constant(.captureOrder),
                          density: .dense, layoutURL: nil, onFocus: { _ in })
                .frame(height: Tok.Size.columnHeader + Tok.Size.Row.dense * CGFloat(GalleryFixtures.flowRows.count))
                .border(Tok.Line.border.color)
        }
    }

    private var interceptBars: some View {
        KitSection("Intercept bar",
                   caption: "Armed, nothing paused: tint fill, deep text. Paused: base fill, on-colour text, the dot pulses 1200 ms (still under Reduce Motion), Apply & Resume because the target is edited.") {
            VStack(spacing: Space.sm) {
                InterceptBar().environment(fx.armed)
                InterceptBar().environment(fx.paused)
            }
        }
    }

    private var inspectorHead: some View {
        KitSection("Summary strip · pane tabs",
                   caption: "200 OK and Paused strips; Request tabs with Raw active and the editing hint; Response tabs with the search glyph. The active tab is the accent with a 2 px underline on the shared rule.") {
            VStack(spacing: 0) {
                SummaryStrip(row: GalleryFixtures.row(41), detail: Fixtures.detail(for: GalleryFixtures.row(41)))
                Rule(color: Tok.Line.rule)
                SummaryStrip(row: GalleryFixtures.row(50), detail: Fixtures.pausedLogin)
                Rule()
                HStack(spacing: 0) {
                    PaneTabs(title: "Request", tabs: RequestTab.allCases, selected: $requestTab) {
                        Text("editing").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                    }
                    VRule()
                    PaneTabs(title: "Response", tabs: ResponseTab.allCases, selected: $responseTab) {
                        Image(systemName: Tok.Glyph.search).font(Tok.Face.ui(Tok.Size.iconInline))
                            .foregroundStyle(Tok.Ink.secondary.color)
                    }
                }
            }
            .border(Tok.Line.border.color)
        }
    }
}

/// An editorial section: a tracked small-caps label like the sidebar's group
/// labels, the part, and an optional caption in the tertiary tier.
struct KitSection<Content: View>: View {
    var title: String
    var caption: String?
    var content: Content

    init(_ title: String, caption: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.caption = caption
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Text(title.uppercased())
                .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                .tracking(0.6)
                .foregroundStyle(Tok.Ink.tertiary.color)
            content
            if let caption {
                Text(caption)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Sessions tuned to each state the shell's parts can take, built once per
/// gallery. Each starts from `loadFixtures()`: armed, two paused, the edited
/// login focused.
struct GalleryFixtures {
    /// The mockup's state as is.
    let paused = GalleryFixtures.make()
    /// Armed with nothing waiting.
    let armed = GalleryFixtures.make { s in s.rows.removeAll { $0.state == .paused } }
    /// Disarmed and listening.
    let listening = GalleryFixtures.make { s in s.interceptArmed = false }
    /// Capture paused.
    let captureOff = GalleryFixtures.make { s in
        s.interceptArmed = false
        s.capturing = false
    }
    /// The agent paused by the operator, nothing counted.
    let agentPaused = GalleryFixtures.make { s in
        s.agentPolicy = .paused
        s.agentActionsLastMinute = 0
    }
    /// Inspector on the right.
    let vertical = GalleryFixtures.make { s in s.layout = .vertical }
    /// Scope selected; one pinned host so a monogram sub-row shows.
    let sidebar = GalleryFixtures.make { s in
        s.page = .scope
        s.pins = Pins(hosts: ["api.shop-staging.test"])
    }

    /// Brand 44 + three group labels + ten rows + the filter field.
    static let sidebarHeight = Tok.Size.Row.dense * 18
    static let emptyHeight = Tok.Size.Row.dense * 3

    /// One fixture row per state, in capture order.
    static let flowRows: [FlowRow] = [41, 42, 44, 46, 49, 50, 52].map { GalleryFixtures.row($0) }

    static func row(_ seq: Int) -> FlowRow {
        Fixtures.rows.first { $0.seq == seq } ?? Fixtures.rows[0]
    }

    private static func make(_ tune: (Session) -> Void = { _ in }) -> Session {
        let session = Session()
        session.loadFixtures()
        tune(session)
        return session
    }
}
