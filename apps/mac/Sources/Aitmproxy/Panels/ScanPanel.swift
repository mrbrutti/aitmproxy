import AitmBusClient
import AitmproxyKit
import Observation
import SwiftUI

/// The Scan page's state (scanner-integration Stage 1): the launch form, the last
/// `scan.discover` result, and the intents. Held by the session as `session.scan`,
/// like `poc`. The data and the launch gate are the Kit's `ScanState` / `ScanForm`.
///
/// Viewing the page never scans: only `launch()` reaches the bus, and it passes the
/// scope gate (deny-by-default) first.
@Observable
final class ScanPanelState {
    @ObservationIgnored unowned let session: Session

    var form = ScanForm(tool: nil, scopeHosts: [])
    var model = ScanState()

    init(session: Session) { self.session = session }

    var running: Bool { model.running }
    var endpoints: [String] { model.endpoints }
    var points: [InjectionPoint] { model.points }
    var error: String? { model.error }

    /// The bus lists `scan.discover`; without it the page degrades instead of breaking.
    var offered: Bool { session.scanEnabled }
    /// Why the current target cannot be scanned; nil when it can.
    var refusal: String? { form.scopeError(scopeHosts: session.scopeHosts) }
    var canLaunch: Bool { offered && !model.running && refusal == nil }

    /// The in-scope hosts a scan can start from (never a `*.wildcard`).
    var scopeChoices: [String] { ScanForm.concreteHosts(in: session.scopeHosts) }

    /// Re-reads the tool schema and scope into the form; a typed target is kept.
    func syncForm() {
        form.sync(tool: session.tools.first { $0.name == ScanForm.toolName }, scopeHosts: session.scopeHosts)
    }

    /// Fixture sessions open with a finished crawl, the way Findings opens with runs.
    func loadFixture() {
        syncForm()
        guard let result = try? ScanResult(json: Fixtures.scanDiscover) else { return }
        model.begin(target: form.normalizedTarget)
        model.finish(result)
    }

    // MARK: Intents

    /// The in-flight crawl, held so Cancel can stop waiting on it.
    @ObservationIgnored private var scanTask: Task<Void, Never>?

    /// Start a crawl and keep its task so the running state can be cancelled.
    func start() { scanTask = Task { await launch() } }

    /// Stop waiting on the crawl and clear the running state. The bus call cannot be
    /// recalled, so a late result is dropped (the `Task.isCancelled` guard in `launch`).
    func cancelScan() {
        scanTask?.cancel()
        scanTask = nil
        model.running = false
    }

    /// `scan.discover {target, max_depth?, max_pages?}` → the endpoints and injection points it found.
    func launch() async {
        guard let args = model.beginLaunch(form: form, scopeHosts: session.scopeHosts, tools: session.tools) else { return }
        let value: JSONValue
        do {
            value = try await session.runCommand(ScanForm.toolName, args)
        } catch {
            if Task.isCancelled { return }
            model.fail(BusService.describe(error))
            return
        }
        guard !Task.isCancelled else { return }
        do {
            model.finish(try ScanResult(json: value))
        } catch {
            model.fail("scan.discover returned a result this app cannot read")
        }
    }

    func select(_ index: Int) { model.selected = index }

    /// The flow an injection point was seen in is still in the flow list.
    func canOpen(_ point: InjectionPoint) -> Bool { isListed(point.flowID) }

    /// Open the point's flow in the inspector: select it and show the flow list. A flow
    /// that is no longer listed is refused, not selected.
    func open(_ point: InjectionPoint) { openFlow(point.flowID) }

    /// The flow the crawl fetched this endpoint in, or nil when the result links none
    /// (the row is then plain).
    func flowID(forEndpoint url: String) -> FlowID? { model.flowID(forEndpoint: url) }

    /// The result links this endpoint to a flow.
    func isLinked(endpoint url: String) -> Bool { flowID(forEndpoint: url) != nil }

    /// The endpoint is linked and its flow is still in the flow list.
    func canOpen(endpoint url: String) -> Bool { flowID(forEndpoint: url).map(isListed) ?? false }

    /// Open the endpoint's flow like an injection point's. An unlinked endpoint does
    /// nothing; a linked flow that is no longer listed is refused, not selected.
    func open(endpoint url: String) {
        guard let flow = flowID(forEndpoint: url) else { return }
        openFlow(flow)
    }

    private func isListed(_ flow: FlowID) -> Bool { session.rows.contains { $0.id == flow } }

    private func openFlow(_ flow: FlowID) {
        guard isListed(flow) else {
            session.lastError = "flow \(flow.raw) is not in the flow list (cleared, or not captured here)"
            return
        }
        session.select(flow)
        session.show(.apps)
    }
}

/// The Scan page: a launch bar on top (target bound to the scope, depth and page
/// budget from the tool schema), then a master list of endpoints and injection
/// points on the left and the selected injection point on the right.
struct ScanPanel: View {
    @Bindable var state: ScanPanelState

    var body: some View {
        VStack(spacing: 0) {
            if state.offered {
                launchBar
                    .gridProbe("scan-launch", area: "scan", edge: nil)
                Rule()
                HStack(spacing: 0) {
                    lists
                        .frame(width: 320)
                        .gridProbe("scan-lists", area: "scan", edge: nil)
                    VRule()
                    ScanPointDetail(state: state)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else {
                unavailable
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .gridArea("scan", inset: 0)
        // Opening the page seeds the form; it never starts a crawl.
        .onAppear { state.syncForm() }
        .onChange(of: state.session.tools) { state.syncForm() }
        .onChange(of: state.session.scopeHosts) { state.syncForm() }
    }

    // MARK: Launch

    private var launchBar: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            HStack(alignment: .bottom, spacing: Space.md) {
                field("Target") {
                    TextField("http://host/", text: $state.form.target)
                        .scanFieldChrome()
                        .onSubmit { if state.canLaunch { launch() } }
                }
                field("In scope") {
                    FlatMenu(title: "Choose host", width: 160) {
                        if state.scopeChoices.isEmpty {
                            Button("No concrete host in scope") {}.disabled(true)
                        }
                        ForEach(state.scopeChoices, id: \.self) { host in
                            Button(host) { state.form.target = ScanForm.seedURL(for: host) }
                        }
                    }
                }
                .frame(width: 160)
                if state.form.hasMaxDepth {
                    field("Depth") { TextField("auto", text: $state.form.maxDepth).scanFieldChrome() }
                        .frame(width: 64)
                }
                if state.form.hasMaxPages {
                    field("Pages") { TextField("auto", text: $state.form.maxPages).scanFieldChrome() }
                        .frame(width: 64)
                }
                PrimaryButton(state.running ? "Scanning…" : "Scan", hint: "⌘⏎") { launch() }
                    .disabled(!state.canLaunch)
                    .keyboardShortcut(.return, modifiers: .command)
                    .help(state.refusal ?? "Crawl the target and list its endpoints and injection points (⌘⏎)")
            }
            status
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
    }

    /// One line: what is in flight, what went wrong, why the target cannot launch, or what the last crawl found.
    private var status: some View {
        HStack(spacing: Space.sm) {
            if state.running {
                ProgressView().controlSize(.small)
                Text("Crawling \(state.model.target ?? "")…").foregroundStyle(Tok.Ink.secondary.color)
                FlatButton("Cancel") { state.cancelScan() }
            } else if let error = state.error {
                Text(error).foregroundStyle(Tok.Status.serverError.color)
            } else if let refusal = state.refusal {
                Text(refusal).foregroundStyle(Tok.Intercept.deep.color)
                if let host = state.form.authority {
                    FlatButton("Add Host to Scope…") {
                        state.session.scopeSheetHost = host
                        state.session.scopeSheetVisible = true
                    }
                }
            } else if state.model.hasResult {
                Text(state.model.summary).foregroundStyle(Tok.Ink.secondary.color)
                if let reason = state.model.stoppedReason {
                    Text("stopped: \(reason)").foregroundStyle(Tok.Intercept.deep.color)
                }
            } else {
                Text("Idle — opening this page never scans. Scan crawls the target above.").foregroundStyle(Tok.Ink.tertiary.color)
            }
            Spacer(minLength: 0)
        }
        .font(Tok.Face.ui(Tok.Typography.Size.sm))
        .lineLimit(1)
        .frame(minHeight: Tok.Size.control)
    }

    private func launch() { state.start() }

    private func field<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            content()
        }
    }

    // MARK: Results

    /// Endpoints is a supporting list: cap it to its rows (up to a few) so a short
    /// crawl leaves no dead band, and let the injection-points list take the rest.
    private static let maxEndpointRows = 8

    private var endpointListHeight: CGFloat {
        CGFloat(min(max(state.endpoints.count, 2), Self.maxEndpointRows)) * Tok.Size.Row.dense
    }

    private var lists: some View {
        VStack(spacing: 0) {
            sectionHead("Endpoints", count: state.endpoints.count)
            endpointList
                .frame(height: endpointListHeight)
            Rule()
            sectionHead("Injection points", count: state.points.count)
            pointList
                .frame(maxHeight: .infinity)
        }
    }

    private func sectionHead(_ title: String, count: Int) -> some View {
        HStack {
            Text(title.uppercased()).font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.5)
                .foregroundStyle(Tok.Ink.tertiary.color)
            Spacer(minLength: Space.sm)
            Text("\(count)").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.columnHeader)
        .overlay(alignment: .bottom) { Rule() }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }

    @ViewBuilder private var endpointList: some View {
        if state.endpoints.isEmpty {
            placeholder(state.model.hasResult ? "No endpoints reached" : "None yet — Scan crawls an in-scope target")
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    // An endpoint the result links to a flow opens it, like an injection point; the rest stay plain.
                    ForEach(Array(state.endpoints.enumerated()), id: \.offset) { _, url in
                        ScanEndpointRow(url: url, linked: state.isLinked(endpoint: url), openable: state.canOpen(endpoint: url)) {
                            state.open(endpoint: url)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder private var pointList: some View {
        if state.points.isEmpty {
            placeholder(state.model.hasResult ? "No injection points found" : "None yet")
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(Array(state.points.enumerated()), id: \.offset) { index, point in
                        ScanPointRow(point: point, selected: index == state.model.selected)
                            .contentShape(Rectangle())
                            .onTapGesture(count: 2) {
                                state.select(index)
                                state.open(point)
                            }
                            .onTapGesture { state.select(index) }
                    }
                }
            }
        }
    }

    private func placeholder(_ text: String) -> some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.md))
            .foregroundStyle(Tok.Ink.tertiary.color)
            .padding(.horizontal, Space.md)
            .padding(.vertical, Space.sm)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    /// The core does not list `scan.discover` (no scanner plugin): degraded, never broken.
    private var unavailable: some View {
        ContentUnavailableView {
            Label("Scan is unavailable", systemImage: Tok.Glyph.search)
        } description: {
            Text("scan.discover is not on this bus (it needs the scanner plugin).")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// One reached endpoint, its URL exactly as the scanner returned it. When the result
/// links the endpoint to the flow it was fetched in (`linked`), the row opens that flow:
/// double-click, the trailing chevron, or Open Flow in the context menu. An unlinked row
/// stays a plain, selectable URL.
struct ScanEndpointRow: View {
    var url: String
    /// The result carries a flow id for this endpoint.
    var linked: Bool
    /// That flow is still in the flow list, so opening it can succeed.
    var openable: Bool
    var open: () -> Void

    var body: some View {
        HStack(spacing: Space.sm) {
            if linked {
                // Double-click opens the flow, so the text is not selectable here; Copy URL stays in the menu.
                label
                Button(action: open) {
                    Image(systemName: Tok.Glyph.chevron)
                        .font(.system(size: Tok.Size.iconInline))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                        .frame(width: Space.lg, height: Tok.Size.Row.dense)
                        .contentShape(Rectangle())
                }
                .buttonStyle(PressStyle())
                .disabled(!openable)
                .help(openable ? "Open Flow" : "This flow is no longer in the flow list (cleared, or not captured here).")
            } else {
                label.textSelection(.enabled)
            }
        }
        .padding(.leading, Space.md)
        .padding(.trailing, linked ? Space.sm : Space.md)
        .frame(maxWidth: .infinity, minHeight: Tok.Size.Row.dense, alignment: .leading)
        .contentShape(Rectangle())
        .opensOnDoubleClick(linked, open)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .contextMenu {
            if linked {
                Button("Open Flow", action: open).disabled(!openable)
            }
            Button("Copy URL") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(url, forType: .string)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(url)
        .accessibilityAddTraits(linked ? .isButton : [])
        .accessibilityActions {
            if linked { Button("Open Flow", action: open) }
        }
    }

    private var label: some View {
        Text(url)
            .font(Tok.Face.data(Tok.Typography.Size.md))
            .foregroundStyle(Tok.Ink.primary.color)
            .lineLimit(1)
            .truncationMode(.middle)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// One injection point: name and location, then the example exactly as the scanner returned it.
struct ScanPointRow: View {
    var point: InjectionPoint
    var selected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                Text(point.name).font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                    .foregroundStyle(Tok.Ink.primary.color).lineLimit(1)
                Spacer(minLength: Space.xs)
                // The neutral grey pill pair: a location is not a severity.
                Badge(text: point.location, pair: Tok.Severity.info, uppercase: false)
            }
            Text(point.example.isEmpty ? "—" : point.example)
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .lineLimit(1)
                .truncationMode(.tail)
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(selected ? Tok.Ground.active.color : .clear)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(point.name), \(point.location), \(point.example.isEmpty ? "no example" : point.example)")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// The selected injection point: where it lives, its example verbatim, and the flow it opens.
struct ScanPointDetail: View {
    @Bindable var state: ScanPanelState

    var body: some View {
        if let point = state.model.selectedPoint {
            VStack(spacing: 0) {
                header(point)
                Rule()
                ScrollView {
                    VStack(alignment: .leading, spacing: Space.lg) {
                        section("Example")
                        Text(point.example.isEmpty ? "(empty)" : point.example)
                            .font(Tok.Face.data(Tok.Typography.Size.md))
                            .foregroundStyle(point.example.isEmpty ? Tok.Ink.tertiary.color : Tok.Ink.primary.color)
                            .textSelection(.enabled)
                            .padding(Space.sm)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                        Hint(text: "Shown as the scanner returned it; secrets are redacted at the source.")

                        section("Flow")
                        flowReference(point)
                        if !state.canOpen(point) {
                            Hint(text: "This flow is no longer in the flow list (cleared, or not captured here).")
                        }
                    }
                    .padding(Space.md)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else if state.model.hasResult {
            scanSummary
        } else {
            ContentUnavailableView {
                Label("No scan yet", systemImage: Tok.Glyph.search)
            } description: {
                Text("Scan an in-scope target above to crawl its endpoints and injection points.")
            } actions: {
                PrimaryButton(state.running ? "Scanning…" : "Scan") { state.start() }
                    .disabled(!state.canLaunch)
                    .help(state.refusal ?? "Crawl the target above (⌘⏎)")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    /// With a result but nothing selected, the detail pane shows the crawl's coverage
    /// instead of sitting empty: counts and the injection points broken down by type.
    private var scanSummary: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.lg) {
                section("Coverage")
                HStack(alignment: .top, spacing: Space.section) {
                    stat("Endpoints", "\(state.endpoints.count)")
                    stat("Injection points", "\(state.points.count)")
                }
                if !state.points.isEmpty {
                    section("Injection points by type")
                    typeBreakdown
                }
                if let reason = state.model.stoppedReason {
                    Hint(text: "Crawl stopped: \(reason)")
                }
                Hint(text: "Pick an injection point on the left to see its example and open its flow.")
            }
            .padding(Space.md)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// Injection points grouped by `location` (query / body_param / cookie / …), each a
    /// colored proportion bar — the audit's injection-type distribution.
    private var typeBreakdown: some View {
        let groups: [(location: String, count: Int)] = Dictionary(grouping: state.points, by: \.location)
            .map { (location: $0.key, count: $0.value.count) }
            .sorted { $0.count == $1.count ? $0.location < $1.location : $0.count > $1.count }
        let total = max(1, state.points.count)
        // Kept narrow so each count sits by its bar's end, not 500 pt away.
        return VStack(alignment: .leading, spacing: Space.sm) {
            ForEach(Array(groups.enumerated()), id: \.offset) { item in
                let group = item.element
                HStack(spacing: Space.md) {
                    Text(group.location)
                        .font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                        .frame(width: 120, alignment: .leading).lineLimit(1).truncationMode(.tail)
                    GeometryReader { geo in
                        RoundedRectangle(cornerRadius: Tok.Radius.badge)
                            .fill(Self.typeColor(item.offset))
                            .frame(width: max(2, geo.size.width * Double(group.count) / Double(total)))
                    }
                    .frame(height: 8)
                    Text("\(group.count)")
                        .font(Tok.Face.data(Tok.Typography.Size.sm, .medium)).foregroundStyle(Tok.Ink.primary.color)
                        .frame(width: 32, alignment: .trailing)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(group.location), \(group.count)")
            }
        }
        .frame(maxWidth: 320, alignment: .leading)
    }

    private static let typeColors: [Color] = ChartPalette.categorical

    private static func typeColor(_ index: Int) -> Color { typeColors[index % typeColors.count] }

    private func stat(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label.uppercased()).font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
                .foregroundStyle(Tok.Ink.tertiary.color)
            Text(value).font(Tok.Face.data(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1).minimumScaleFactor(0.7)
        }
    }

    /// The injection point's flow as a method badge + URL (when still listed), not a raw UUID.
    @ViewBuilder private func flowReference(_ point: InjectionPoint) -> some View {
        if let row = state.session.rows.first(where: { $0.id == point.flowID }) {
            HStack(spacing: Space.sm) {
                Badge(text: row.method.label, pair: row.method.badge)
                Text("\(row.authority)\(row.path)")
                    .font(Tok.Face.data(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
            }
        } else {
            Text(point.flow)
                .font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                .textSelection(.enabled)
        }
    }

    private func header(_ point: InjectionPoint) -> some View {
        HStack(spacing: Space.md) {
            Text(point.name).font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
            Badge(text: point.location, pair: Tok.Severity.info, uppercase: false)
            Spacer(minLength: Space.sm)
            FlatButton("Open Flow") { state.open(point) }
                .disabled(!state.canOpen(point))
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.inspectorHeader)
    }

    private func section(_ title: String) -> some View {
        Text(title.uppercased()).font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
            .foregroundStyle(Tok.Ink.tertiary.color)
    }
}

private extension View {
    /// Runs `action` on a double-click when `enabled`. Left off otherwise so an unlinked
    /// row's selectable text keeps its own double-click.
    @ViewBuilder func opensOnDoubleClick(_ enabled: Bool, _ action: @escaping () -> Void) -> some View {
        if enabled { onTapGesture(count: 2, perform: action) } else { self }
    }

    /// The launch bar's text field: plain, on `surface`, a control-border outline.
    func scanFieldChrome() -> some View {
        textFieldStyle(.plain)
            .font(Tok.Face.data(Tok.Typography.Size.md))
            .padding(.horizontal, Space.sm)
            .frame(height: Tok.Size.control)
            .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
    }
}
