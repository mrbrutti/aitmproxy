import AitmproxyKit
import SwiftUI

/// The Scan page's Profiles tab (scanner v2 T9, spec D4, D11, D12, D13): the
/// profile list on the left, the editor on the right, and the sticky footer that
/// launches. Every string the tab renders is `ScanFormat`'s or the plan's; every
/// edit lands in `state.surface.editedProfile`, which the launch gate and
/// `launchArguments` read. Opening this tab never scans (D4).
struct ScanProfilesTab: View {
    @Bindable var state: ScanPanelState
    @FocusState private var listFocused: Bool
    @FocusState private var startFocused: Bool

    /// The editor's bottom anchor, which `launchFocusTick` scrolls to.
    private static let footerAnchor = "scan-profile-footer"

    var body: some View {
        HStack(spacing: 0) {
            list
                .frame(width: 320)
                .gridProbe("scan-profiles-list", area: "scan", edge: nil)
            VRule()
            editor
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
    }

    // MARK: List (D4 left, D11 Profiles list)

    @ViewBuilder private var list: some View {
        if state.surface.profiles.isEmpty {
            if let error = state.surface.profilesError {
                ContentUnavailableView {
                    Label(error, systemImage: "exclamationmark.triangle")
                } actions: {
                    FlatButton("Retry") { Task { await state.refreshProfiles() } }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ContentUnavailableView {
                    Label(scanNoProfilesText, systemImage: Tok.Glyph.search)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        } else {
            VStack(spacing: 0) {
                if let error = state.surface.profilesError {
                    // A failed refresh keeps the cached rows and says so under the header (D11).
                    ScanInlineError(text: error)
                        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
                }
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(state.surface.profiles, id: \.name) { entry in
                            ScanProfileRow(entry: entry, selected: entry.name == state.surface.selectedProfile)
                                .contentShape(Rectangle())
                                .onTapGesture {
                                    select(entry.name)
                                    listFocused = true
                                }
                        }
                    }
                }
                // Arrow keys walk the selection once the list has focus (the Findings pattern).
                .focusable()
                .focused($listFocused)
                .focusEffectDisabled()
                .onMoveCommand { direction in
                    switch direction {
                    case .up: move(by: -1)
                    case .down: move(by: 1)
                    default: break
                    }
                }
                .accessibilityElement(children: .contain)
                .accessibilityLabel("Profiles")
            }
        }
    }

    /// A tap selects the row and loads it only when the editor does not already
    /// hold it, so tapping the row being edited never throws the edits away. A
    /// row whose load failed (nothing loaded under that name) gets its retry here.
    private func select(_ name: String) {
        state.surface.select(profile: name)
        loadIfListed(name)
    }

    /// ↑↓ move the selection and load the row they land on, by the same rule as a tap.
    private func move(by delta: Int) {
        state.surface.moveSelection(in: .profiles, by: delta)
        loadIfListed(state.surface.selectedProfile)
    }

    /// The one place a selection becomes an editor load: only a name the list
    /// carries (a duplicate's fresh name is not asked of the core) and only when
    /// the editor does not already hold that profile.
    private func loadIfListed(_ name: String?) {
        guard let name, state.surface.profiles.contains(where: { $0.name == name }),
              state.surface.loadedProfile?.name != name else { return }
        Task { await state.loadProfile(name) }
    }

    // MARK: Editor (D4 right)

    private var editor: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: Space.xl) {
                        if let edited = state.surface.editedProfile {
                            ScanProfileEditor(state: state, edited: edited)
                        }
                        Color.clear.frame(height: 1).id(Self.footerAnchor)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, Space.margin)
                    .padding(.vertical, Space.lg)
                }
                .onChange(of: state.launchFocusTick) {
                    proxy.scrollTo(Self.footerAnchor, anchor: .bottom)
                    startFocused = true
                }
            }
            Rule()
            footer
                .gridProbe("scan-profiles-footer", area: "scan", edge: nil)
        }
    }

    // MARK: Footer (D4, sticky)

    private var footer: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            HStack(spacing: Space.sm) {
                PrimaryButton("Start Scan", hint: "⌘⏎") { state.startScan(map: false) }
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(launchDisabled)
                    .help(state.launchRefusal ?? "Start a scan with this profile (⌘⏎)")
                    .focused($startFocused)
                FlatButton("Map Only") { state.startScan(map: true) }
                    .disabled(launchDisabled)
                    .help(state.launchRefusal ?? "Crawl the origins and fill the site map without probing")
                if state.surface.launchInFlight {
                    ProgressView().controlSize(.small)
                }
                Spacer(minLength: Space.sm)
                if let edited = state.surface.editedProfile {
                    profileButtons(for: edited)
                }
            }
            statusLine
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
    }

    // A pending confirm sheet owns the launch: Cmd-Return behind it must not start a second job.
    private var launchDisabled: Bool { state.launchRefusal != nil || state.surface.launchInFlight || state.surface.confirm != nil }

    /// Save Profile / Delete Profile… for a custom profile; Duplicate… for a builtin,
    /// whose edits are launch overrides only (D4).
    @ViewBuilder private func profileButtons(for edited: ScanProfile) -> some View {
        if isBuiltin(edited.name) {
            FlatButton("Duplicate…") { state.duplicateName = "" }
                .help("Copy this builtin under a new name so it can be saved")
                .popover(isPresented: duplicatePresented, arrowEdge: .top) {
                    ScanProfileDuplicatePopover(state: state)
                }
        } else {
            FlatButton("Save Profile") { Task { await state.saveProfile() } }
                .keyboardShortcut("s", modifiers: .command)
                .help("Save this profile on the core (⌘S)")
            if isListedCustom(edited.name) {
                FlatButton("Delete Profile…") { state.deleteCandidate = edited.name }
                    .help("Remove this saved profile; its jobs keep their results")
            }
        }
    }

    /// The one line under the buttons (D4): the refusal first, then the model's
    /// status line (a launch error's words with its code beside them, or "Saved
    /// <name>"), then the edited-builtin note, else the idle text.
    @ViewBuilder private var statusLine: some View {
        Group {
            if let refusal = state.launchRefusal {
                Text(refusal).foregroundStyle(Tok.Intercept.deep.color)
            } else if let line = state.surface.statusLine {
                HStack(spacing: Space.sm) {
                    Text(line).foregroundStyle(Tok.Ink.secondary.color)
                    if let error = state.surface.launchError, error.display == line, let code = error.code {
                        // The engine's error code beside its words, for a bug report.
                        Text(code)
                            .font(Tok.Face.data(Tok.Typography.Size.sm))
                            .foregroundStyle(Tok.Ink.tertiary.color)
                            .textSelection(.enabled)
                    }
                }
            } else if editedBuiltin {
                Text(scanEditedBuiltinText).foregroundStyle(Tok.Ink.secondary.color)
            } else {
                Text(scanIdleText).foregroundStyle(Tok.Ink.tertiary.color)
            }
        }
        .font(Tok.Face.ui(Tok.Typography.Size.sm))
        .lineLimit(2)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var editedBuiltin: Bool {
        guard let edited = state.surface.editedProfile else { return false }
        return state.surface.profileIsEdited && isBuiltin(edited.name)
    }

    /// Builtin by the list's word, never by name shape; a name the list does not
    /// carry (a fresh duplicate) is custom.
    private func isBuiltin(_ name: String) -> Bool {
        state.surface.profiles.first { $0.name == name }?.builtin ?? false
    }

    /// A custom profile the core has on file, so Delete Profile… has something to remove.
    private func isListedCustom(_ name: String) -> Bool {
        state.surface.profiles.contains { $0.name == name && !$0.builtin }
    }

    private var duplicatePresented: Binding<Bool> {
        Binding(
            get: { state.duplicateName != nil },
            set: { if !$0 { state.duplicateName = nil } }
        )
    }
}

// MARK: - Rows

/// One profile row (D4): name, BUILTIN when builtin, then `lanes · intensity · speed`.
struct ScanProfileRow: View {
    var entry: ScanProfileListEntry
    var selected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                Text(entry.name)
                    .font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: Space.xs)
                if entry.builtin {
                    Badge(text: "BUILTIN", pair: Tok.Severity.info)
                }
            }
            Text(ScanFormat.profileRowLine2(entry))
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .lineLimit(1)
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(selected ? Tok.Ground.active.color : .clear)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        // Long names middle-truncate; the tooltip carries the whole name (D11).
        .help(entry.name)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(ScanFormat.profileAccessibilityLabel(entry))
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

// MARK: - Editor

/// The sections of the editor (D4): Target, Lanes, Intensity / Speed / Accuracy,
/// Checks, Budget, Session. `edited` is the profile as the parent read it this
/// render; every binding writes through to `state.surface.editedProfile` and
/// no-ops once that is nil, so a profile deleted mid-edit cannot be resurrected
/// by a stale control.
private struct ScanProfileEditor: View {
    @Bindable var state: ScanPanelState
    let edited: ScanProfile

    /// HTTP, WebSocket, L4 packet, L4 stream — the four toggles, in this order.
    private static let lanes: [ScanLane] = [.http, .ws, .l4Packet, .l4Stream]

    var body: some View {
        target
        lanesSection
        dials
        checks
        budget
        sessionSection
    }

    // MARK: Target

    private var target: some View {
        block("Target") {
            ForEach(Array(edited.target.origins.enumerated()), id: \.offset) { index, origin in
                ScanProfileOriginRow(
                    origin: origin,
                    refusal: outOfScope(origin),
                    remove: { removeOrigin(at: index) },
                    addToScope: { state.openScopeSheet(for: ScanFormat.hostOf(origin: origin)) })
            }
            FlatMenu(title: "Add in-scope host", width: 200) {
                let hosts = ScanForm.concreteHosts(in: state.session.scopeHosts)
                if hosts.isEmpty {
                    Button("No concrete host in scope") {}.disabled(true)
                }
                ForEach(hosts, id: \.self) { host in
                    Button("http://\(host)") { addOrigin("http://\(host)") }
                    Button("https://\(host)") { addOrigin("https://\(host)") }
                }
            }
            .help("Add a scope host as an origin, over http or https")
            if !edited.target.l4Rows.isEmpty {
                // L4 targets are read-only here (D4): editing them is the TUI's / config's.
                ForEach(edited.target.l4Rows, id: \.self) { row in
                    Text(row)
                        .font(Tok.Face.data(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Ink.secondary.color)
                        .textSelection(.enabled)
                }
            }
        }
    }

    /// Why this origin cannot be scanned, nil when it can. The words are the Kit's
    /// `ScanFormat.outOfScopeText`, so the row and the launch gate say the same thing.
    private func outOfScope(_ origin: String) -> String? {
        if let authority = ScanForm.authority(of: origin), Scope.contains(authority, in: state.session.scopeHosts) {
            return nil
        }
        return ScanFormat.outOfScopeText(origin: origin)
    }

    private func addOrigin(_ origin: String) {
        guard var profile = state.surface.editedProfile, !profile.target.origins.contains(origin) else { return }
        profile.target.origins.append(origin)
        state.surface.editedProfile = profile
    }

    private func removeOrigin(at index: Int) {
        guard var profile = state.surface.editedProfile, profile.target.origins.indices.contains(index) else { return }
        profile.target.origins.remove(at: index)
        state.surface.editedProfile = profile
    }

    // MARK: Lanes

    private var lanesSection: some View {
        block("Lanes") {
            HStack(spacing: Space.sm) {
                ForEach(Self.lanes, id: \.self) { lane in
                    FlatToggle(lane.word, isOn: laneBinding(lane))
                        .help("Run the \(lane.word) lane")
                }
            }
        }
    }

    /// On when the lane is in `lanes`. Setting rebuilds the list in the toggles'
    /// order, keeping any lane this build does not know at the end.
    private func laneBinding(_ lane: ScanLane) -> Binding<Bool> {
        Binding(
            get: { (state.surface.editedProfile ?? edited).lanes.contains(lane) },
            set: { on in
                guard var profile = state.surface.editedProfile else { return }
                var chosen = Set(profile.lanes)
                if on { chosen.insert(lane) } else { chosen.remove(lane) }
                let unknown = profile.lanes.filter { !Self.lanes.contains($0) && chosen.contains($0) }
                profile.lanes = Self.lanes.filter(chosen.contains) + unknown
                state.surface.editedProfile = profile
            })
    }

    // MARK: Intensity / Speed / Accuracy

    private var dials: some View {
        block("Intensity / Speed / Accuracy") {
            HStack(alignment: .top, spacing: Space.lg) {
                field("Intensity") {
                    Picker("Intensity", selection: bind(\.intensity)) {
                        Text("Passive").tag(ScanIntensity.passive)
                        Text("Light").tag(ScanIntensity.light)
                        Text("Medium").tag(ScanIntensity.medium)
                        Text("Intrusive").tag(ScanIntensity.intrusive)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .fixedSize()
                }
                field("Speed") {
                    Picker("Speed", selection: bind(\.speed)) {
                        Text("Fast").tag(ScanSpeed.fast)
                        Text("Normal").tag(ScanSpeed.normal)
                        Text("Thorough").tag(ScanSpeed.thorough)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .fixedSize()
                }
            }
            field("Accuracy") {
                Picker("Accuracy", selection: bind(\.accuracy)) {
                    Text("Fewer false negatives").tag(ScanAccuracy.fewerFalseNegatives)
                    Text("Normal").tag(ScanAccuracy.normal)
                    Text("Fewer false positives").tag(ScanAccuracy.fewerFalsePositives)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
            }
            if edited.isIntrusive {
                Hint(text: scanIntrusiveHint)
            }
        }
    }

    // MARK: Checks

    private var checks: some View {
        block("Checks") {
            if let error = state.checksError {
                // The catalogue already loaded stays; the failed re-read says so here (D11).
                // The block carries its own inset, so the line takes none.
                ScanInlineError(text: error, inset: 0)
            }
            TextField("Search checks", text: $state.surface.checkQuery)
                .scanFieldChrome()
                .frame(width: 240)
                .help("Filter the checks by id, name or class")
            // Built once per distinct (catalogue, selection, intensity, query), not per body pass
            // (MS-R1): the state caches it, so an unrelated tick never rebuilds ~160 rows.
            let tree = state.checkTree(selection: edited.checks, intensity: edited.intensity)
            // A flat indented list, not a disclosure tree: every row keeps its
            // height, so the list never jumps under the pointer (plan Task 5).
            VStack(spacing: 0) {
                ForEach(tree.groups, id: \.rowID) { group in
                    ScanProfileCheckGroupHeader(group: group) { choice in setAll(choice, in: group) }
                    ForEach(group.leaves, id: \.meta.id) { leaf in
                        ScanProfileCheckRow(leaf: leaf) { choice in set(choice, for: leaf.meta.id) }
                    }
                }
            }
        }
    }

    private func set(_ choice: ScanCheckTree.Choice, for id: String) {
        guard var profile = state.surface.editedProfile else { return }
        ScanCheckTree.set(choice, for: id, in: &profile.checks)
        state.surface.editedProfile = profile
    }

    private func setAll(_ choice: ScanCheckTree.Choice, in group: ScanCheckTree.Group) {
        guard var profile = state.surface.editedProfile else { return }
        ScanCheckTree.setAll(choice, ids: group.leaves.map(\.meta.id), in: &profile.checks)
        state.surface.editedProfile = profile
    }

    // MARK: Budget

    private var budget: some View {
        block("Budget") {
            HStack(alignment: .top, spacing: Space.md) {
                field("Probes") {
                    TextField("Probes", value: bind(\.budget.probes), format: .number.grouping(.never))
                        .scanFieldChrome()
                }
                .frame(width: 96)
                field("Time (s)") {
                    TextField("Time (s)", value: bind(\.budget.timeS), format: .number.grouping(.never))
                        .scanFieldChrome()
                }
                .frame(width: 96)
                field("Max issues") {
                    TextField("Max issues", value: bind(\.budget.maxIssues), format: .number.grouping(.never))
                        .scanFieldChrome()
                }
                .frame(width: 96)
                field("Check timeout (s)") {
                    TextField("Check timeout (s)", value: bind(\.budget.checkTimeoutS), format: .number.grouping(.never))
                        .scanFieldChrome()
                }
                .frame(width: 120)
            }
        }
    }

    // MARK: Session

    private var sessionSection: some View {
        block("Session") {
            field("Mode") {
                Picker("Session", selection: bind(\.session.mode)) {
                    Text("Observed").tag(ScanSessionMode.observed)
                    Text("None").tag(ScanSessionMode.none)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
            }
            if edited.session.mode == .observed {
                // Names only, never values (the Kit's rule); the preview is the core's
                // `scan.session.preview` for the first origin.
                if let preview = state.surface.sessionPreview {
                    // "observed 5 s ago" ticks on its own 1 Hz timeline (MS-R1: the model no longer
                    // republishes every 250 ms, so a clock read in `body` would freeze).
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        Text(ScanFormat.sessionPreviewText(
                            preview, flowLabel: preview.sourceFlow.flatMap(state.flowLabel), now: Self.ms(context.date)))
                            .font(Tok.Face.data(Tok.Typography.Size.sm))
                            .foregroundStyle(Tok.Ink.secondary.color)
                            .textSelection(.enabled)
                    }
                    Text(ScanFormat.canaryText(preview.canary))
                        .font(Tok.Face.data(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.secondary.color)
                } else {
                    Text(ScanFormat.noSessionText)
                        .font(Tok.Face.ui(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                }
            }
            field("On lost") {
                Picker("On lost", selection: bind(\.session.onLost)) {
                    Text("Stop").tag(ScanOnLost.stop)
                    Text("Continue").tag(ScanOnLost.continue)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
            }
        }
        // The preview is per mode and per first origin: either change re-reads it.
        .onChange(of: edited.session.mode) { Task { await state.refreshSessionPreview() } }
        .onChange(of: edited.target.origins.first) { Task { await state.refreshSessionPreview() } }
    }

    private static func ms(_ date: Date) -> Int { Int(date.timeIntervalSince1970 * 1000) }

    // MARK: Helpers

    /// A binding into the edited profile. Reads the live value (the snapshot when
    /// the editor has been emptied); writes only while a profile is loaded.
    private func bind<Value>(_ keyPath: WritableKeyPath<ScanProfile, Value>) -> Binding<Value> {
        Binding(
            get: { state.surface.editedProfile?[keyPath: keyPath] ?? edited[keyPath: keyPath] },
            set: { state.surface.editedProfile?[keyPath: keyPath] = $0 })
    }

    /// A section: the shared `ScanSectionTitle`, then its rows.
    private func block<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            ScanSectionTitle(title)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func field<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            content()
        }
    }
}

/// One origin (D4): the URL, Remove, and under an out-of-scope one the refusal
/// and Add Host to Scope…, which opens the existing scope sheet.
private struct ScanProfileOriginRow: View {
    var origin: String
    var refusal: String?
    var remove: () -> Void
    var addToScope: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                Text(origin)
                    .font(Tok.Face.data(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Spacer(minLength: Space.sm)
                FlatButton("Remove", action: remove)
                    .help("Remove this origin from the profile")
            }
            if let refusal {
                HStack(spacing: Space.sm) {
                    Text(refusal)
                        .font(Tok.Face.ui(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Intercept.deep.color)
                        .lineLimit(2)
                    FlatButton("Add Host to Scope…", action: addToScope)
                        .help("Open the scope sheet with this host filled in")
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(refusal.map { "\(origin), \($0)" } ?? origin)
    }
}

/// A `lane · class` group header with Include all / Exclude all / Reset (D4).
private struct ScanProfileCheckGroupHeader: View {
    var group: ScanCheckTree.Group
    var setAll: (ScanCheckTree.Choice) -> Void

    var body: some View {
        HStack(spacing: Space.sm) {
            Text("\(group.lane.word) · \(group.klass)")
                .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
                .foregroundStyle(Tok.Ink.secondary.color)
                .lineLimit(1)
            Text("\(group.leaves.count)")
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.tertiary.color)
            Spacer(minLength: Space.sm)
            FlatMenu(title: "Set all", width: 96) {
                Button("Include all") { setAll(.include) }
                Button("Exclude all") { setAll(.exclude) }
                Button("Reset") { setAll(.default) }
            }
            .help("Include, exclude or reset every check in this group")
            .accessibilityLabel("Set all checks in \(group.lane.word) \(group.klass)")
        }
        .frame(height: Tok.Size.columnHeader)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .contain)
        .accessibilityAddTraits(.isHeader)
    }
}

/// One check (D4): name, class, intensity badge, cost and origin, and the
/// Default / Include / Exclude menu. Above the profile's intensity it reads
/// tertiary and says why on hover.
private struct ScanProfileCheckRow: View {
    var leaf: ScanCheckTree.Leaf
    var set: (ScanCheckTree.Choice) -> Void

    private var meta: ScanCheckMeta { leaf.meta }

    var body: some View {
        HStack(alignment: .center, spacing: Space.sm) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: Space.sm) {
                    Text(meta.name)
                        .font(Tok.Face.ui(Tok.Typography.Size.md))
                        .foregroundStyle(leaf.aboveIntensity ? Tok.Ink.tertiary.color : Tok.Ink.primary.color)
                        .lineLimit(1)
                    Text(meta.klass)
                        .font(Tok.Face.ui(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                        .lineLimit(1)
                    Badge(text: meta.intensity.rawValue, pair: Tok.State.neutral)
                }
                Text("\(meta.cost) · \(meta.origin.word)")
                    .font(Tok.Face.ui(Tok.Typography.Size.xs))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .lineLimit(1)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(ScanFormat.checkAccessibilityLabel(leaf))
            Spacer(minLength: Space.sm)
            FlatMenu(title: leaf.choice.word, width: 96) {
                ForEach(ScanCheckTree.Choice.allCases, id: \.self) { choice in
                    Button(choice.word) { set(choice) }
                }
            }
            .accessibilityLabel("\(meta.name): \(leaf.choice.word)")
        }
        .padding(.leading, Space.lg)
        .padding(.vertical, Space.xs)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .help(leaf.aboveIntensity ? scanAboveIntensityHelp : meta.description)
    }
}

/// The Duplicate… popover (D4): a name and the Duplicate button, which hands the
/// edited values to `duplicateProfile(as:)` as an unsaved custom profile.
private struct ScanProfileDuplicatePopover: View {
    @Bindable var state: ScanPanelState

    var body: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Text("Name")
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
            TextField("Name", text: name)
                .scanFieldChrome()
                .frame(width: 240)
                .onSubmit { if valid { duplicate() } }
            if !trimmedName.isEmpty, !ScanSurface.isValidProfileName(trimmedName) {
                Hint(text: scanProfileNameRuleText)
            }
            HStack(spacing: Space.sm) {
                Spacer(minLength: 0)
                FlatButton("Cancel") { state.duplicateName = nil }
                    .keyboardShortcut(.cancelAction)
                PrimaryButton("Duplicate", action: duplicate)
                    .disabled(!valid)
                    .help("Make a copy under this name")
            }
        }
        .padding(Space.md)
        .background(Tok.Ground.surface.color)
    }

    private var name: Binding<String> {
        Binding(get: { state.duplicateName ?? "" }, set: { state.duplicateName = $0 })
    }

    private var trimmedName: String { (state.duplicateName ?? "").trimmingCharacters(in: .whitespaces) }

    /// A name the core would accept as a file name (`ScanSurface.isValidProfileName`)
    /// that the list does not already carry in any case (the core would refuse to
    /// overwrite a builtin, a saved custom one is not a duplicate's to replace, and
    /// a case-folding store must not be reached through `My-API` beside `my-api`).
    private var valid: Bool {
        let trimmed = trimmedName
        return ScanSurface.isValidProfileName(trimmed)
            && !ScanSurface.profileNameCollides(trimmed, with: state.surface.profiles.map(\.name))
    }

    private func duplicate() {
        state.duplicateProfile(as: state.duplicateName ?? "")
    }
}

private extension ScanCheckTree.Group {
    /// A stable `ForEach` id: a check in two lanes sits in two groups, so the
    /// group's identity is lane and class together.
    var rowID: String { "\(lane.rawValue)/\(klass)" }
}
