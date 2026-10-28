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
    private static let limitWidth: CGFloat = 220
    private static let backoffWidth: CGFloat = 88
    private static let flowsWidth: CGFloat = 44
    private static let hostMin: CGFloat = 176
    private static let maxVisibleRows = 4

    private var hostWidth: CGFloat {
        let fixed = Self.limitWidth + Self.backoffWidth + Self.flowsWidth + Tok.Size.control + Space.md * 6
        return max(Self.hostMin, width - fixed)
    }

    private var entries: [ScopeEntry] {
        let limits = Store.usesFixtures ? Fixtures.scopeLimits : [:]
        let listed = ScopeEntry.entries(hosts: session.scopeHosts, limits: limits)
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
                    .padding(.horizontal, Space.lg).padding(.top, Space.lg).padding(.bottom, Space.sm)
                    .accessibilityAddTraits(.isHeader)
            }
            addRow
            if entries.isEmpty {
                Text("No hosts in scope — add one to authorise testing; everything stays read-only until then.")
                    .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                    .padding(.horizontal, Space.lg).padding(.bottom, Space.lg)
            } else {
                table
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width = $0 }
        .onAppear { if entries.isEmpty { fieldFocused = true } }
        .onChange(of: session.scopeHosts) { pending.removeAll { session.scopeHosts.contains($0) } }
    }

    // MARK: Add

    private var addRow: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                TextField("host, host:port or *.wildcard", text: $draft)
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
            ColumnHeads(columns: [("Host", hostWidth), ("Limit", Self.limitWidth), ("Back-off", Self.backoffWidth), ("Flows", Self.flowsWidth)])
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
                cell(String(entry.flowCount(in: session.rows)), width: Self.flowsWidth)
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
        .accessibilityElement(children: .combine)
        .accessibilityLabel(entry.host)
        .accessibilityValue(isPending ? "pending" : entry.limit?.readout ?? "no limit")
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    private func cell(_ text: String, width: CGFloat) -> some View {
        Text(text).lineLimit(1).truncationMode(.tail).frame(width: width, alignment: .leading).help(text)
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
