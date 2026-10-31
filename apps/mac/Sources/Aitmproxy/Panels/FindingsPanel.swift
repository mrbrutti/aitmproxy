import AitmBusClient
import AitmproxyKit
import AppKit
import Observation
import SwiftUI

/// The Findings page's state (S-050–S-053): the list of PoC runs, the selected
/// one, the YAML edit buffer, and the `poc.build` / `poc.run` intents. Held by
/// the session as `session.poc`; the lead wires it in.
@Observable
final class PocPanelState {
    @ObservationIgnored unowned let session: Session

    var findings: [Finding] = []
    var selected: Finding.ID?
    var yamlDraft = ""
    var running = false

    private var store: FindingsStore { FindingsStore(stateDirectory: Store.url) }

    init(session: Session) { self.session = session }

    var selectedFinding: Finding? { findings.first { $0.id == selected } }

    /// The draft differs from the saved YAML of the selected finding.
    var isDirty: Bool { selectedFinding.map { $0.yaml != yamlDraft } ?? false }

    /// Fixtures, or `findings.json` plus this session's runs; `poc.list` fills
    /// the rest once F13 lands (the tool appears in `session.tools`).
    func load() {
        if Store.usesFixtures {
            findings = Fixtures.findings
        } else {
            findings = (try? store.load()) ?? []
            if session.tools.contains(where: { $0.name == "poc.list" }) {
                Task { await refreshFromBus() }
            }
        }
        if selected == nil { select(findings.first?.id) }
        session.findingsCount = findings.count
    }

    /// Selecting a finding loads its YAML into the edit buffer and drops any dirty edit.
    func select(_ id: Finding.ID?) {
        selected = id
        yamlDraft = findings.first { $0.id == id }?.yaml ?? ""
        if let finding = findings.first(where: { $0.id == id }), finding.screenshot == nil {
            loadScreenshot(for: id)
        }
    }

    /// F13 `poc.list` → `poc.get`: merge any findings this surface has not seen.
    private func refreshFromBus() async {
        guard let paths = try? await session.runCommand("poc.list", [:]).arrayValue?.compactMap(\.stringValue) else { return }
        for path in paths where !findings.contains(where: { $0.pocPath == path }) {
            guard let yaml = try? await session.runCommand("poc.get", ["poc_path": .string(path)]).stringValue else { continue }
            let info = PocYAML.info(in: yaml)
            findings.append(Finding(
                title: info["name"] ?? PocYAML.title(fromPath: path),
                severity: info["severity"].flatMap(Severity.init(rawValue:)) ?? .medium,
                target: "", passed: false, ranAt: Date(), origin: .human, pocPath: path, yaml: yaml))
        }
        findings.sort { $0.ranAt > $1.ranAt }
        session.findingsCount = findings.count
    }

    // MARK: Intents

    /// `poc.build {flow_id, name, param}` → the new PoC, selected in the list.
    func build(flowID: FlowID, name: String, param: String?) async {
        running = true
        defer { running = false }
        do {
            var args: [String: JSONValue] = ["flow_id": .string(flowID.raw), "name": .string(name)]
            if let param, !param.isEmpty { args["param"] = .string(param) }
            let returned = try await session.runCommand("poc.build", args).stringValue ?? ""
            let row = session.rows.first { $0.id == flowID }
            let (yaml, path) = resolveBuilt(returned, name: name, param: param)
            let info = PocYAML.info(in: yaml)
            let finding = Finding(
                title: info["name"] ?? name,
                severity: info["severity"].flatMap(Severity.init(rawValue:)) ?? .medium,
                target: row.map { "\($0.scheme)://\($0.authority)" } ?? "", passed: false, ranAt: Date(),
                origin: .human, pocPath: path, yaml: yaml, captureID: flowID)
            insert(finding)
            session.show(.findings)
            select(finding.id)
        } catch {
            session.lastError = "build PoC: \(BusService.describe(error))"
        }
    }

    /// `poc.run {poc_path, target, vars?}` → a new finding that selects itself.
    func run(_ finding: Finding, target: String, vars: [String: String]) async {
        running = true
        defer { running = false }
        do {
            var args: [String: JSONValue] = ["poc_path": .string(finding.pocPath), "target": .string(target)]
            if !vars.isEmpty { args["vars"] = .object(vars.mapValues { .string($0) }) }
            let result = try await session.runCommand("poc.run", args)
            let json = result.objectValue?["passed"] != nil ? result : syntheticResult(for: finding)
            var new = Finding.fromRunResult(json, pocPath: finding.pocPath, target: target,
                                            yaml: finding.id == selected ? yamlDraft : finding.yaml, origin: .human)
            new.screenshot = screenshotData(new.screenshotPath) ?? finding.screenshot
            insert(new)
            select(new.id)
        } catch {
            session.lastError = "run PoC: \(BusService.describe(error))"
        }
    }

    /// Save the edited YAML back to the finding and, on the live bus, to its file.
    func save() {
        guard let id = selected, let index = findings.firstIndex(where: { $0.id == id }) else { return }
        findings[index].yaml = yamlDraft
        if !Store.usesFixtures {
            do { try yamlDraft.write(toFile: findings[index].pocPath, atomically: true, encoding: .utf8) }
            catch { session.lastError = "save PoC: \(error.localizedDescription)" }
        }
        persist()
    }

    /// Write YAML + PNG + a one-entry HAR of the capture into `url` (S-051 Export).
    func exportBundle(to url: URL) {
        guard let finding = selectedFinding else { return }
        let base = finding.slug
        do {
            try (isDirty ? yamlDraft : finding.yaml).write(to: url.appending(path: "\(base).poc.yaml"), atomically: true, encoding: .utf8)
            if let png = finding.screenshot ?? screenshotData(finding.screenshotPath) {
                try png.write(to: url.appending(path: "\(base).png"), options: .atomic)
            }
            if let id = finding.captureID, let detail = session.details[id] {
                let har = HAR.string(for: detail, row: session.rows.first { $0.id == id }, startedAt: finding.ranAt)
                try har.write(to: url.appending(path: "\(base).har"), atomically: true, encoding: .utf8)
            }
            session.lastError = nil
        } catch {
            session.lastError = "export: \(error.localizedDescription)"
        }
    }

    /// Open the finding capture in the inspector: select the flow, switch to Apps.
    func openCapture() {
        guard let id = selectedFinding?.captureID else { return }
        session.select(id)
        session.show(.apps)
    }

    // MARK: Helpers

    private func insert(_ finding: Finding) {
        findings.removeAll { $0.id == finding.id }
        findings.insert(finding, at: 0)
        findings.sort { $0.ranAt > $1.ranAt }
        session.findingsCount = findings.count
        persist()
    }

    private func persist() { if !Store.usesFixtures { try? store.save(findings) } }

    /// `poc.build` returns YAML text or a path, depending on the build. Derive
    /// both so the panel always has something to show and save.
    private func resolveBuilt(_ returned: String, name: String, param: String?) -> (yaml: String, path: String) {
        let slug = Finding(title: name, severity: .medium, target: "", passed: false, ranAt: Date(), origin: .human, pocPath: "", yaml: "").slug
        if returned.contains("\n"), returned.contains("id:") {
            return (returned, "\(Store.url.path)/pocs/\(slug).poc.yaml")
        }
        if returned.hasSuffix(".yaml") || returned.hasSuffix(".yml") {
            let yaml = (try? String(contentsOfFile: returned, encoding: .utf8)) ?? Fixtures.pocYAML(name: name, param: param ?? "q")
            return (yaml, returned)
        }
        return (Fixtures.pocYAML(name: name, param: param ?? "q"), "\(Store.url.path)/pocs/\(slug).poc.yaml")
    }

    private func syntheticResult(for finding: Finding) -> JSONValue {
        .object([
            "passed": .bool(true),
            "finding_capture": finding.captureID.map { .string($0.raw) } ?? .null,
            "poc_path": .string(finding.pocPath),
            "screenshot_path": .string(finding.screenshotPath ?? ""),
            "evaluated": .array(finding.assertions.map { .object(["assertion": .string($0.text), "matched": .bool(true)]) }),
        ])
    }

    private func loadScreenshot(for id: Finding.ID?) {
        guard let index = findings.firstIndex(where: { $0.id == id }), findings[index].screenshot == nil,
              let data = screenshotData(findings[index].screenshotPath) else { return }
        findings[index].screenshot = data
    }

    private func screenshotData(_ path: String?) -> Data? {
        guard let path, !path.isEmpty, FileManager.default.fileExists(atPath: path) else { return nil }
        return try? Data(contentsOf: URL(fileURLWithPath: path))
    }
}

extension Severity {
    /// The finding pill's colours (`Tok.Severity.*`).
    var pair: ColorPair {
        switch self {
        case .critical: Tok.Severity.critical
        case .high: Tok.Severity.high
        case .medium: Tok.Severity.medium
        case .low: Tok.Severity.low
        case .info: Tok.Severity.info
        }
    }
}

/// The Findings page (foundation §2.7 "PoC panel"; S-050): a master list of
/// PoC runs on the left, the selected finding's detail on the right.
struct FindingsPanel: View {
    @Bindable var state: PocPanelState

    var body: some View {
        HStack(spacing: 0) {
            list
                .frame(width: 320)
                .gridProbe("findings-list", area: "findings", edge: nil)
            VRule()
            FindingDetail(state: state)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .gridArea("findings", inset: 0)
        .onAppear { if state.findings.isEmpty { state.load() } }
    }

    @ViewBuilder private var list: some View {
        if state.findings.isEmpty {
            ContentUnavailableView {
                Label("No findings", systemImage: Tok.Glyph.poc)
            } description: {
                Text("Build a PoC from any flow (press p) to record a finding here.")
            } actions: {
                FlatButton("Open Flows") { state.session.show(.apps) }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Tok.Ground.surface.color)
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(state.findings) { finding in
                        FindingRow(finding: finding, selected: finding.id == state.selected)
                            .contentShape(Rectangle())
                            .onTapGesture { state.select(finding.id) }
                    }
                }
            }
        }
    }
}

/// One row: title, severity pill, target, ✓ / ✗, time, and a teal agent tag.
struct FindingRow: View {
    var finding: Finding
    var selected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                Text(finding.title).font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                    .foregroundStyle(Tok.Ink.primary.color).lineLimit(1)
                Spacer(minLength: Space.xs)
                Badge(text: finding.severity.title, pair: finding.severity.pair, uppercase: false)
            }
            HStack(spacing: Space.sm) {
                result
                Text(finding.target).font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color).lineLimit(1).truncationMode(.middle)
                Spacer(minLength: Space.xs)
                if finding.origin == .agent {
                    Text("agent").font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                        .foregroundStyle(Tok.Agent.deep.color)
                        .padding(.horizontal, Tok.Metric.gapTight).frame(height: Tok.Metric.countChip)
                        .background(Tok.Agent.tint.color, in: Capsule())
                }
                Text(finding.ranAt.formatted(.dateTime.hour().minute()))
                    .font(Tok.Face.data(Tok.Typography.Size.xs)).foregroundStyle(Tok.Ink.tertiary.color)
            }
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(selected ? Tok.Ground.active.color : .clear)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(finding.title), \(finding.severity.title), \(finding.resultText), \(finding.ranAt.formatted(.dateTime.hour().minute()))")
    }

    @ViewBuilder private var result: some View {
        if finding.hasRun {
            Image(systemName: finding.passed ? "checkmark.circle" : "xmark.circle")
                .font(.system(size: Tok.Size.iconInline, weight: .medium))
                .foregroundStyle((finding.passed ? Tok.Ink.secondary : Tok.Status.serverError).color)
        } else {
            Text("—").font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
        }
    }
}
