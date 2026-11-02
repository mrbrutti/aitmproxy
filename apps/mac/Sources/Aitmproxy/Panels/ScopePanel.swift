import AitmproxyKit
import AppKit
import SwiftUI

/// The Scope page's top section (S-047, S-048; foundation §2.7 "Scope panel"):
/// a tracked `SCOPE` label, the add field with `Add ⌘⏎`, and the entries
/// table — Host · Limit · Back-off · Flows — with ✕ and Delete to remove.
/// Content-sized; the lead places it above the in-scope flow list.
struct ScopePanel: View {
    @Environment(Session.self) private var session
    /// Off in the sheet, which carries its own title.
    var showsLabel = true

    @State private var draft = ""
    @State private var selected: String?
    @State private var hovered: String?
    /// Hosts sent with `scope.add` that the bus has not listed yet (kept in tertiary).
    @State private var pending: [String] = []
    @State private var width: CGFloat = 0
    @FocusState private var fieldFocused: Bool
    @FocusState private var tableFocused: Bool

    init(showsLabel: Bool = true) { self.showsLabel = showsLabel }

    /// Fixed columns after Host; Host takes what is left, at least `hostMin`.
    private static let limitWidth: CGFloat = 160
    private static let backoffWidth: CGFloat = 88
    private static let flowsWidth: CGFloat = 44
    private static let hostMin: CGFloat = 176
    private static let maxVisibleRows = 4

    private var hostWidth: CGFloat {
        // The row's real trailing consumption beyond Host: the three fixed columns,
        // the ✕ button, the five inter-cell gaps, and the row's own side padding —
        // seven Space.md gaps in all. Undercounting this overflowed the sheet and
        // clipped the leading edge ("HOST" → "OST").
        let fixed = Self.limitWidth + Self.backoffWidth + Self.flowsWidth + Tok.Size.control + Space.md * 7
        return max(Self.hostMin, width - fixed)
    }

    private var entries: [ScopeEntry] {
        let listed = ScopeEntry.entries(hosts: session.scopeHosts)
        return listed + pending.filter { !session.scopeHosts.contains($0) }.map { ScopeEntry(host: $0) }
    }

    private var trimmed: String { draft.trimmingCharacters(in: .whitespaces) }
    private var validation: String? { trimmed.isEmpty ? nil : ScopeEntry.validate(trimmed, existing: session.scopeHosts + pending) }
    private var canAdd: Bool { !trimmed.isEmpty && validation == nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if showsLabel {
                Text("SCOPE").font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .gridProbe("scope-title", area: "scope-panel")
                    .padding(.horizontal, Space.lg).padding(.top, Space.lg).padding(.bottom, Space.sm)
                    .accessibilityAddTraits(.isHeader)
            }
            addRow
            if entries.isEmpty {
                ContentUnavailableView {
                    Label("No hosts in scope", systemImage: Tok.Glyph.scope)
                } description: {
                    Text("Add a host above to authorise testing. Everything stays read-only until then.")
                }
                .frame(maxWidth: .infinity)
                .padding(.bottom, Space.lg)
            } else {
                table
            }
            if session.l4Enabled {
                l4Section
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .gridArea("scope-panel", inset: 0)
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width = $0 }
        .onAppear {
            // Flow ▸ Add Host to Scope… (⇧S) opens with the focused row's host typed in.
            if let host = session.scopeSheetHost {
                draft = host
                session.scopeSheetHost = nil
                fieldFocused = true
            } else if entries.isEmpty {
                fieldFocused = true
            }
        }
        .onChange(of: session.scopeHosts) { pending.removeAll { session.scopeHosts.contains($0) } }
    }

    // MARK: Add

    private var addRow: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                // Port-qualified for now: a bare host also claims the app's DNS lookup (see
                // ConnectionSummary.scopeEntryHint); the hint goes when the provider fix lands.
                TextField("host:443 or host:80 (for now), host:port or *.wildcard:port", text: $draft)
                    .textFieldStyle(.plain)
                    .font(Tok.Face.data(Tok.Typography.Size.md))
                    .padding(.horizontal, Space.sm)
                    .frame(height: Tok.Size.control)
                    .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                    .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control)
                        .strokeBorder(validation == nil ? Tok.Line.control.color : Tok.Intercept.deep.color))
                    .focused($fieldFocused)
                    .onSubmit(add)
                    .accessibilityLabel("Host to add to scope")
                PrimaryButton("Add", hint: "⌘⏎", action: add)
                    .disabled(!canAdd)
                    .keyboardShortcut(.return, modifiers: .command)
                    .help(validation ?? "Add the host to scope (⌘⏎)")
            }
            if let validation {
                Text(validation).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Intercept.deep.color)
            }
        }
        .gridProbe("scope-add", area: "scope-panel")
        .padding(.horizontal, Space.lg).padding(.bottom, Space.md)
    }

    private func add() {
        guard canAdd else { return }
        let host = trimmed
        pending.append(host)
        session.addScope(host)
        draft = ""
        fieldFocused = true
    }

    // MARK: Table

    private var table: some View {
        VStack(spacing: 0) {
            tableHeader
                .gridProbe("scope-table", area: "scope-panel", edge: nil)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(entries) { entry in row(entry) }
                }
            }
            .frame(height: CGFloat(min(entries.count, Self.maxVisibleRows)) * Tok.Size.Row.dense)
            .focusable()
            .focused($tableFocused)
            .focusEffectDisabled()
            .onDeleteCommand { if let selected { remove(selected) } }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Scope entries")
        }
    }

    /// Local header so the Flows column can trailing-align with its numbers; the
    /// first three columns match the row's leading cells one-for-one.
    private var tableHeader: some View {
        HStack(spacing: Space.md) {
            headCell("Host", width: hostWidth)
            headCell("Limit", width: Self.limitWidth)
            headCell("Back-off", width: Self.backoffWidth)
            headCell("Flows", width: Self.flowsWidth, alignment: .trailing)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.columnHeader)
        .overlay(alignment: .bottom) { Rule() }
        .accessibilityHidden(true)
    }

    private func headCell(_ title: String, width: CGFloat, alignment: Alignment = .leading) -> some View {
        Text(title.uppercased())
            .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
            .foregroundStyle(Tok.Ink.tertiary.color).lineLimit(1)
            .frame(width: width, alignment: alignment)
    }

    private func row(_ entry: ScopeEntry) -> some View {
        let isPending = !session.scopeHosts.contains(entry.host)
        let isSelected = selected == entry.host
        let ink = isPending ? Tok.Ink.tertiary.color : Tok.Ink.primary.color
        return Button {
            selected = entry.host
            tableFocused = true
        } label: {
            HStack(spacing: Space.md) {
                cell(entry.host, width: hostWidth).foregroundStyle(ink).truncationMode(.middle)
                cell(entry.limit?.limitText ?? Format.dash, width: Self.limitWidth)
                    .foregroundStyle(entry.limit == nil ? Tok.Ink.tertiary.color : Tok.Ink.secondary.color)
                cell(entry.limit?.backoffText ?? Format.dash, width: Self.backoffWidth)
                    .foregroundStyle(entry.limit == nil ? Tok.Ink.tertiary.color : Tok.Ink.secondary.color)
                cell(String(entry.flowCount(in: session.rows)), width: Self.flowsWidth, alignment: .trailing)
                    .foregroundStyle(ink).monospacedDigit()
                Spacer(minLength: 0)
                Button { remove(entry.host) } label: {
                    Image(systemName: "xmark")
                        .font(.system(size: Tok.Size.iconInline))
                        .foregroundStyle(hovered == entry.host || isSelected ? Tok.Ink.secondary.color : Tok.Ink.tertiary.color)
                        .frame(width: Tok.Size.control, height: Tok.Size.control)
                        .contentShape(Rectangle())
                }
                .buttonStyle(PressStyle())
                .help("Remove from Scope")
                .accessibilityLabel("Remove \(entry.host) from Scope")
            }
            .font(Tok.Face.data(Tok.Typography.Size.sm))
            .padding(.horizontal, Space.md)
            .frame(height: Tok.Size.Row.dense)
            .background(isSelected ? Tok.Ground.active.color : hovered == entry.host ? Tok.Ground.hover.color : .clear)
            .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 ? entry.host : (hovered == entry.host ? nil : hovered) }
        .contextMenu {
            Button("Remove from Scope") { remove(entry.host) }
            Button("Copy Host") {
                Pasteboard.copy(entry.host)
            }
            // Show Flows narrows the Domains page to this host; a wildcard or a host
            // with no captured flows has no group to show, so the item stays out.
            if session.hosts.contains(where: { $0.0 == entry.host }) {
                Divider()
                Button("Show Flows") { session.show(.domains, group: .host(entry.host)) }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(entry.host)
        .accessibilityValue(isPending ? "pending" : entry.limit?.readout ?? "no limit")
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    private func cell(_ text: String, width: CGFloat, alignment: Alignment = .leading) -> some View {
        Text(text).lineLimit(1).truncationMode(.tail).frame(width: width, alignment: alignment).help(text)
    }

    // MARK: Remove

    private func remove(_ host: String) {
        if pending.contains(host), !session.scopeHosts.contains(host) {
            pending.removeAll { $0 == host }
        } else {
            session.removeScope(host) { ScopeRemoveConfirmation.ask(host: host, pausedCount: $0) }
        }
        if selected == host { selected = nil }
    }

    // MARK: L4 scope (L4PAR-AC26, AC28, AC30; plan unit (d) Decision 6)
    //
    // The row-less L4 home: the core's own capture/inject and in-path intercept
    // availability (spec §1), its `l4.scope.list` entries, and — only while
    // `tools/list` shows `l4.scope.add` confirmable (spec §3 last rule) — the
    // operator's add form with the confirm-over-the-wire handshake. No remove
    // action and no Craft button live here.

    @State private var l4Cidr = ""
    @State private var l4Ports = ""
    @State private var l4Interface = "lo0"
    @State private var l4Direction = "inbound"
    @State private var l4Capability = "capture"
    /// A guard refusal or bus error from the last add, shown inline under the form.
    @State private var l4AddError: String?
    /// The core's `needs_confirmation` prompt, bound to the call that caused it.
    @State private var l4Confirm: L4ConfirmRequest?
    /// An add (or its confirmed re-issue) is in flight; the button waits.
    @State private var l4Adding = false

    private static let l4CidrWidth: CGFloat = 160
    private static let l4PortsWidth: CGFloat = 96
    private static let l4InterfaceWidth: CGFloat = 56
    private static let l4DirectionWidth: CGFloat = 72
    private static let l4CapabilityWidth: CGFloat = 80
    private static let l4Directions = ["inbound", "outbound"]
    private static let l4Capabilities = ["capture", "inject", "intercept"]

    private var l4Section: some View {
        VStack(alignment: .leading, spacing: 0) {
            Rule()
            Text("L4 SCOPE").font(Tok.Face.ui(Tok.Typography.Size.xs, .medium)).tracking(0.6)
                .foregroundStyle(Tok.Ink.tertiary.color)
                .gridProbe("scope-l4-title", area: "scope-l4")
                .padding(.horizontal, Space.lg).padding(.top, Space.lg).padding(.bottom, Space.sm)
                .accessibilityAddTraits(.isHeader)
            l4AvailabilityLine(Self.l4LineText("Capture and inject", session.l4CaptureAvailability),
                               availability: session.l4CaptureAvailability, id: "l4-scope-capture-line")
            l4AvailabilityLine(Self.l4LineText("In-path intercept", session.l4InterceptAvailability),
                               availability: session.l4InterceptAvailability, id: "l4-scope-intercept-line")
            if session.l4Scope.isEmpty {
                Hint(text: "No L4 scope entries")
                    .gridProbe("scope-l4-empty", area: "scope-l4")
                    .padding(.horizontal, Space.lg).padding(.top, Space.sm)
                    .accessibilityIdentifier("l4-scope-empty")
            } else {
                l4Table
            }
            if session.l4CanAddScope {
                if l4IsOperator {
                    l4AddForm
                } else {
                    // `tools/list` says confirmable to an agent too, but only the operator's
                    // add is ever accepted (spec §3): an agent gets a policy refusal, so the
                    // form would be a control that can only fail (AC33; plan amendment 7).
                    Hint(text: "Adding L4 scope needs the operator token (Settings ▸ Bus)")
                        .gridProbe("scope-l4-operator-only", area: "scope-l4")
                        .padding(.horizontal, Space.lg).padding(.top, Space.sm)
                        .accessibilityIdentifier("l4-scope-add-operator-only")
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.bottom, Space.lg)
        .gridArea("scope-l4", inset: 0)
        .sheet(item: $l4Confirm) { request in
            // The shared L4 confirm sheet (Inspector/L4ConfirmSheet.swift): its words follow the
            // bound `l4.scope.add` call — "Confirm L4 scope entry" / Add / `l4-scope-confirm`.
            L4ConfirmSheet(request: request, onConfirm: { confirmL4Scope(request) }, onCancel: { l4Confirm = nil })
        }
    }

    /// `<what> available`, `<what> unavailable: <reason>`, or the shared pending
    /// literal while the first status reply is outstanding (spec §1).
    static func l4LineText(_ what: String, _ availability: L4Availability) -> String {
        switch availability {
        case .available: "\(what) available"
        case .degraded(let reason): "\(what) unavailable: \(reason)"
        case .pending: availability.displayText ?? L4Availability.pendingText
        }
    }

    /// One documented-limited line, no buttons: the core's own reason, quoted.
    private func l4AvailabilityLine(_ text: String, availability: L4Availability, id: String) -> some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(availability == .pending ? Tok.Ink.tertiary.color : Tok.Ink.secondary.color)
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
            .padding(.horizontal, Space.lg).padding(.bottom, Space.xs)
            .frame(maxWidth: .infinity, alignment: .leading)
            .help(text)
            .accessibilityIdentifier(id)
    }

    private var l4Table: some View {
        VStack(spacing: 0) {
            HStack(spacing: Space.md) {
                headCell("CIDR", width: Self.l4CidrWidth)
                headCell("Ports", width: Self.l4PortsWidth)
                headCell("If", width: Self.l4InterfaceWidth)
                headCell("Direction", width: Self.l4DirectionWidth)
                headCell("Capability", width: Self.l4CapabilityWidth)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, Space.md)
            .frame(height: Tok.Size.columnHeader)
            .overlay(alignment: .bottom) { Rule() }
            .accessibilityHidden(true)
            .gridProbe("scope-l4-table", area: "scope-l4", edge: nil)
            ForEach(session.l4Scope) { item in l4Row(item) }
        }
        .padding(.top, Space.xs)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("L4 scope entries")
    }

    private func l4Row(_ item: L4ScopeItem) -> some View {
        HStack(spacing: Space.md) {
            cell(item.cidr, width: Self.l4CidrWidth).foregroundStyle(Tok.Ink.primary.color)
            cell(item.ports, width: Self.l4PortsWidth).foregroundStyle(Tok.Ink.secondary.color)
            cell(item.interface, width: Self.l4InterfaceWidth).foregroundStyle(Tok.Ink.secondary.color)
            cell(item.direction, width: Self.l4DirectionWidth).foregroundStyle(Tok.Ink.secondary.color)
            cell(item.capability, width: Self.l4CapabilityWidth).foregroundStyle(Tok.Ink.secondary.color)
            Spacer(minLength: 0)
            Badge(text: item.source, pair: item.source == "config" ? Tok.State.neutral : Tok.L4.badge)
                .help(item.source == "config" ? "Declared in the l4.scope config block" : "Added at runtime over the bus")
        }
        .font(Tok.Face.data(Tok.Typography.Size.sm))
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.Row.dense)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(item.cidr) \(item.ports) \(item.interface) \(item.direction) \(item.capability)")
        .accessibilityValue(item.source)
        .accessibilityIdentifier("l4-scope-row-\(item.id)")
    }

    // MARK: L4 add (spec §3; rendered only while `l4CanAddScope` and the session is the operator)

    /// The connection is the operator's: `Session.isOperator`, read from the `resolvedRole` the
    /// server echoed at `initialize`; nil (unconfirmed) is not the operator.
    private var l4IsOperator: Bool { session.isOperator }

    private var l4CidrTrimmed: String { l4Cidr.trimmingCharacters(in: .whitespaces) }
    private var l4InterfaceTrimmed: String { l4Interface.trimmingCharacters(in: .whitespaces) }
    private var canAddL4: Bool { !l4Adding && !l4CidrTrimmed.isEmpty && !l4InterfaceTrimmed.isEmpty }

    private var l4AddForm: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            HStack(spacing: Space.sm) {
                l4Field("cidr", text: $l4Cidr, width: Self.l4CidrWidth, label: "CIDR to add to L4 scope")
                l4Field("all", text: $l4Ports, width: Self.l4PortsWidth, label: "Ports (empty for all)")
                l4Field("lo0", text: $l4Interface, width: Self.l4InterfaceWidth, label: "Interface")
            }
            HStack(spacing: Space.md) {
                FlatSegment(options: Self.l4Directions.map { ($0, $0) }, selection: $l4Direction)
                    .accessibilityLabel("Direction")
                FlatSegment(options: Self.l4Capabilities.map { ($0, $0) }, selection: $l4Capability)
                    .accessibilityLabel("Capability")
                Spacer(minLength: 0)
                PrimaryButton("Add", action: addL4Scope)
                    .disabled(!canAddL4)
                    .help(l4Adding ? "Waiting for the core" : "Add the entry to L4 scope — the core confirms it over the wire first")
                    .accessibilityIdentifier("l4-scope-add")
            }
            if let l4AddError {
                Text(l4AddError)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Status.serverError.color)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("l4-scope-add-error")
            }
        }
        .gridProbe("scope-l4-add", area: "scope-l4")
        .padding(.horizontal, Space.lg).padding(.top, Space.md)
    }

    private func l4Field(_ placeholder: String, text: Binding<String>, width: CGFloat, label: String) -> some View {
        TextField(placeholder, text: text)
            .textFieldStyle(.plain)
            .font(Tok.Face.data(Tok.Typography.Size.md))
            .padding(.horizontal, Space.sm)
            .frame(width: width, height: Tok.Size.control)
            .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
            .onSubmit(addL4Scope)
            .accessibilityLabel(label)
    }

    /// Issue `l4.scope.add` once, unconfirmed. A `needs_confirmation` reply opens the
    /// prompt bound to this exact call; a plain result refreshes the list; a guard
    /// refusal or error lands inline, never in a dialog.
    private func addL4Scope() {
        // The role gate at the send site, not only on the form (AC33; plan amendment 7): a
        // future menu item or shortcut that reaches here without the operator role is refused
        // inline with the same reason the inspector's verbs use, and nothing is sent.
        guard l4IsOperator else { l4AddError = Session.operatorOnlyReason; return }
        guard canAddL4 else { return }
        let draft = L4ScopeDraft(cidr: l4CidrTrimmed, ports: l4Ports, interface: l4InterfaceTrimmed,
                                 direction: l4Direction, capability: l4Capability)
        let call = L4PendingCall(command: "l4.scope.add", args: draft.args)
        l4AddError = nil
        l4Adding = true
        Task {
            defer { l4Adding = false }
            do {
                let result = try await session.runCommand(call.command, call.args)
                if let request = L4ConfirmRequest(json: result, call: call) {
                    l4Confirm = request
                } else {
                    await refreshL4ScopeAfterAdd()
                }
            } catch {
                l4AddError = BusService.describe(error)
            }
        }
    }

    /// Re-issue the identical call the prompt was bound to, plus `_confirm` and
    /// nothing else (`L4PendingCall.confirmed(with:)`).
    private func confirmL4Scope(_ request: L4ConfirmRequest) {
        l4Confirm = nil
        guard let call = request.call?.confirmed(with: request) else {
            l4AddError = "The confirmation was not bound to a call; add the entry again."
            return
        }
        l4Adding = true
        Task {
            defer { l4Adding = false }
            do {
                _ = try await session.runCommand(call.command, call.args)
                await refreshL4ScopeAfterAdd()
            } catch {
                l4AddError = BusService.describe(error)
            }
        }
    }

    /// Re-read `l4.scope.list` so the new entry shows at once, and clear the form.
    ///
    /// The read goes through `session.runCommand` like the add itself (the Scope page has no
    /// `FlowActions` verb for L4 scope, and this fix may not widen that protocol), so the
    /// write into `session.l4Scope` has no run-ownership guard of its own: it is taken only
    /// while the bus still reports connected after the await, which is as close as a view can
    /// get to `BusService`'s owner check. A reconnect that lands inside the round trip loses
    /// nothing — `BusService.pollLoop` clears the L4 facts on disconnect and its slow tick
    /// re-reads `l4.scope.list` (about every 5 s), so the list converges on the core's either
    /// way. The form is the view's own and is cleared on every successful read.
    private func refreshL4ScopeAfterAdd() async {
        do {
            let list = try await session.runCommand("l4.scope.list", [:])
            let items = L4ScopeItem.list(list)
            if case .connected = session.bus, session.l4Scope != items { session.l4Scope = items }
            l4Cidr = ""
            l4Ports = ""
            l4Interface = "lo0"
        } catch {
            l4AddError = BusService.describe(error)
        }
    }
}

/// "Remove host from scope? N paused flows will become read-only." — asked
/// only when a paused flow is on the host (S-048).
enum ScopeRemoveConfirmation {
    static func ask(host: String, pausedCount: Int) -> Bool {
        let alert = NSAlert()
        alert.messageText = "Remove \(host) from scope?"
        alert.informativeText = pausedCount == 1 ? "1 paused flow will become read-only." : "\(pausedCount) paused flows will become read-only."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Remove")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }
}

/// One tertiary line over the list while the live bus has no scope (S-049).
struct ScopeBanner: View {
    var body: some View {
        HStack(spacing: Space.sm) {
            Image(systemName: Tok.Glyph.scope).font(.system(size: Tok.Size.iconInline))
            Text("No scope set — every host is read-only until you add one")
        }
        .font(Tok.Face.ui(Tok.Typography.Size.sm))
        .foregroundStyle(Tok.Ink.tertiary.color)
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.Row.dense)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .combine)
    }
}
