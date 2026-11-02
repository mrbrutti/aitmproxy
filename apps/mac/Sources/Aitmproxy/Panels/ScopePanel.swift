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

    /// The core's list, then the adds in flight (S-081): sending, queued for the core's
    /// return, or failed with the core's reason — each says so on its row.
    private var entries: [ScopeEntry] {
        let listed = ScopeEntry.entries(hosts: session.scopeHosts)
        return listed + session.scopeAdds.hosts.filter { !session.scopeHosts.contains($0) }.map { ScopeEntry(host: $0) }
    }

    private var trimmed: String { draft.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var validation: String? { trimmed.isEmpty ? nil : ScopeEntry.validate(trimmed, existing: session.scopeHosts + session.scopeAdds.hosts) }
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
        let addState = session.scopeAdds.state(of: entry.host)
        let isPending = addState != nil
        let isSelected = selected == entry.host
        let ink = isPending ? Tok.Ink.tertiary.color : Tok.Ink.primary.color
        // An add in flight carries its state where the limit columns would be (S-081).
        let stateLine = addState.map(ScopeAddQueue.label(for:))
        let failed: Bool = if case .failed = addState { true } else { false }
        // ✕ while the send is in flight would forget the row but not the send: the host would come
        // back as a listed entry within a poll. It is enabled again as soon as the core has answered.
        let sending = addState == .sending
        return Button {
            selected = entry.host
            tableFocused = true
        } label: {
            HStack(spacing: Space.md) {
                cell(entry.host, width: hostWidth).foregroundStyle(ink).truncationMode(.middle)
                if let stateLine {
                    // State and Retry share the Limit + Back-off columns' width exactly, so a
                    // failed row keeps Host and ✕ where every other row has them (a Retry added
                    // beside a full-width cell overflowed the row and clipped the host's leading edge).
                    HStack(spacing: Space.sm) {
                        Text(stateLine).lineLimit(1).truncationMode(.tail).help(stateLine)
                            .foregroundStyle(failed ? Tok.Intercept.deep.color : Tok.Ink.tertiary.color)
                            .accessibilityIdentifier("scope-add-state")
                        if failed {
                            FlatButton("Retry") { session.retryScopeAdd(entry.host) }
                                .accessibilityLabel("Retry adding \(entry.host) to Scope")
                        }
                    }
                    .frame(width: Self.limitWidth + Self.backoffWidth + Space.md, alignment: .leading)
                } else {
                    cell(entry.limit?.limitText ?? Format.dash, width: Self.limitWidth)
                        .foregroundStyle(entry.limit == nil ? Tok.Ink.tertiary.color : Tok.Ink.secondary.color)
                    cell(entry.limit?.backoffText ?? Format.dash, width: Self.backoffWidth)
                        .foregroundStyle(entry.limit == nil ? Tok.Ink.tertiary.color : Tok.Ink.secondary.color)
                }
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
                .disabled(sending)
                .help(sending ? "Sending to the core…" : "Remove from Scope")
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
        .accessibilityValue(stateLine ?? entry.limit?.readout ?? "no limit")
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    private func cell(_ text: String, width: CGFloat, alignment: Alignment = .leading) -> some View {
        Text(text).lineLimit(1).truncationMode(.tail).frame(width: width, alignment: alignment).help(text)
    }

    // MARK: Remove

    private func remove(_ host: String) {
        if session.scopeAdds.state(of: host) != nil, !session.scopeHosts.contains(host) {
            session.dropScopeAdd(host)
        } else {
            session.removeScope(host) { ScopeRemoveConfirmation.ask(host: host, pausedCount: $0) }
        }
        if selected == host { selected = nil }
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
