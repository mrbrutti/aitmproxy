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

    /// `scan.discover {target, max_depth?, max_pages?}` → the endpoints and injection points it found.
    func launch() async {
        guard let args = model.beginLaunch(form: form, scopeHosts: session.scopeHosts, tools: session.tools) else { return }
        let value: JSONValue
        do {
            value = try await session.runCommand(ScanForm.toolName, args)
        } catch {
            model.fail(BusService.describe(error))
            return
        }
        do {
            model.finish(try ScanResult(json: value))
        } catch {
            model.fail("scan.discover returned a result this app cannot read")
        }
    }

    func select(_ index: Int) { model.selected = index }

    /// The flow an injection point was seen in is still in the flow list.
    func canOpen(_ point: InjectionPoint) -> Bool { session.rows.contains { $0.id == point.flowID } }

    /// Open the point's flow in the inspector: select it and show the flow list. A flow
    /// that is no longer listed is refused, not selected.
    func open(_ point: InjectionPoint) {
        guard canOpen(point) else {
            session.lastError = "flow \(point.flow) is not in the flow list (cleared, or not captured here)"
            return
        }
        session.select(point.flowID)
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
                Rule()
                HStack(spacing: 0) {
                    lists
                        .frame(width: 320)
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
        .gridArea("scan")
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
                Text("Crawling \(state.model.target ?? "")…").foregroundStyle(Tok.Ink.secondary.color)
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

    private func launch() { Task { await state.launch() } }

    private func field<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            content()
        }
    }

    // MARK: Results

    private var lists: some View {
        VStack(spacing: 0) {
            sectionHead("Endpoints", count: state.endpoints.count)
            endpointList
                .frame(maxHeight: .infinity)
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
                    // Plain rows: the result carries no flow id per endpoint, so an endpoint cannot open its flow.
                    // Stage-1 parity gap — needs a backend flow-id-per-endpoint; injection points below do open theirs.
                    ForEach(Array(state.endpoints.enumerated()), id: \.offset) { _, url in
                        ScanEndpointRow(url: url)
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
        VStack(spacing: Space.sm) {
            Text("Scan is unavailable").font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
            Text("scan.discover is not on this bus (needs the scanner plugin).")
                .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// One reached endpoint: a plain URL row (see the parity-gap note in `ScanPanel`).
struct ScanEndpointRow: View {
    var url: String

    var body: some View {
        Text(url)
            .font(Tok.Face.data(Tok.Typography.Size.md))
            .foregroundStyle(Tok.Ink.primary.color)
            .lineLimit(1)
            .truncationMode(.middle)
            .textSelection(.enabled)
            .padding(.horizontal, Space.md)
            .frame(maxWidth: .infinity, minHeight: Tok.Size.Row.dense, alignment: .leading)
            .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
            .accessibilityLabel(url)
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
                        Text(point.flow)
                            .font(Tok.Face.data(Tok.Typography.Size.md))
                            .foregroundStyle(Tok.Ink.secondary.color)
                            .textSelection(.enabled)
                        if !state.canOpen(point) {
                            Hint(text: "This flow is no longer in the flow list (cleared, or not captured here).")
                        }
                    }
                    .padding(Space.md)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            VStack(spacing: Space.sm) {
                Text("No injection point selected").font(Tok.Face.ui(Tok.Typography.Size.xl, .medium))
                    .foregroundStyle(Tok.Ink.primary.color)
                Text("Pick one on the left to see its example and open its flow.")
                    .font(Tok.Face.ui(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func header(_ point: InjectionPoint) -> some View {
        HStack(spacing: Space.md) {
            Text(point.name).font(Tok.Face.ui(Tok.Typography.Size.xl, .medium)).foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
            Badge(text: point.location, pair: Tok.Severity.info, uppercase: false)
            Spacer(minLength: Space.sm)
            FlatButton("Open flow") { state.open(point) }
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
