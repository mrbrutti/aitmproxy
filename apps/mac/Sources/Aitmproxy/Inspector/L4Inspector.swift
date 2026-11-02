import AitmBusClient
import AitmproxyKit
import SwiftUI

/// The inspector for a raw-L4 flow (ui-scripting-highlight-l4 Part 3 §3.2;
/// l4-operator-surfaces Part 3; l4-parity spec §2, §4). A packet list (top) over a
/// detail pane (bottom) that toggles between the selected packet's layer tree +
/// hex and the craft editor (human-friendly YAML `PacketSpec` → `build()` hex
/// preview → guarded inject with the operator confirm-over-the-wire dialog).
/// Scope-as-authorization dims and disables every mutating action out of L4 scope
/// (AC9/AC10); every wire verb degrades with the core's own reason (AC18, L4PAR §1).
///
/// The list polls `l4.flow.get` with `limit: 0` (flow fields only); this view
/// fetches one bounded window of packets per selected flow (spec §2, "only the
/// inspector fetches a window") and renders their bytes through `L4Hex` (§2.3).
struct L4Inspector: View {
    @Environment(Session.self) private var session
    var row: FlowRow
    var detail: L4Flow?

    @State private var selected = 0
    @State private var tab: L4Tab = .packet
    @State private var craftYAML = PacketSpecDraft.sample
    @State private var preview: L4CraftPreview?
    @State private var buildError: String?
    @State private var confirm: L4ConfirmRequest?
    @State private var injectResult: String?
    /// The inspect window for the selected flow (`l4.flow.get` with `inspect: true`).
    @State private var window: L4Flow?
    /// Why the last window read failed (`BusService.describe`), shown where the packets
    /// would be; cleared by the next successful read.
    @State private var windowError: String?

    private var gate: L4ActionGate { L4ActionGate(inScope: row.inScope) }
    /// Inject, Forward and Drop are the operator's (spec §3): an agent-role session would only
    /// get a policy refusal, so the buttons are disabled with `Session.operatorOnlyReason` and
    /// `issue` refuses at the send site — the same gate as the Scope page's add form.
    private var isOperator: Bool { session.isOperator }
    /// The oldest parked packet of this flow, the one the intercept bar acts on (spec §4).
    private var parkedPacket: L4ParkedPacket? { L4ParkedPacket.first(for: row.id, in: session.l4Parked) }

    var body: some View {
        VStack(spacing: 0) {
            if session.l4CaptureAvailability != .available {
                L4DegradedBanner(availability: session.l4CaptureAvailability)
                Rule()
            }
            L4InterceptBar(availability: session.l4InterceptAvailability, parked: parkedPacket, gate: gate,
                           isOperator: isOperator, operatorOnlyReason: Session.operatorOnlyReason,
                           onForward: { verdict("l4.intercept.forward") },
                           onDrop: { verdict("l4.intercept.drop") })
            if let detail {
                SplitPane(axis: .vertical, firstMinimum: 140, secondMinimum: 280, initialSecondFraction: 0.5,
                          autosaveName: "inspector.l4") {
                    L4PacketList(detail: detail, packets: packets(detail), selected: $selected).environment(session).themed()
                } second: {
                    detailPane(detail).environment(session).themed()
                }
            } else {
                LoadingLines()
            }
        }
        .opacity(row.inScope ? 1 : 0.55)
        .overlay(alignment: .topTrailing) {
            if !row.inScope {
                Text("out of L4 scope")
                    .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
                    .foregroundStyle(Tok.Intercept.deep.color)
                    .padding(.horizontal, Tok.Metric.gapTight).frame(height: Tok.Size.badge)
                    .background(Tok.Intercept.tint.color, in: RoundedRectangle(cornerRadius: Tok.Radius.badge))
                    .padding(Space.sm)
                    .help(gate.disabledReason ?? "")
            }
        }
        .sheet(item: $confirm) { request in
            L4ConfirmSheet(request: request, onConfirm: { confirmed(request) }, onCancel: { confirm = nil })
        }
        .task(id: detail.map(WindowKey.init)) {
            guard let id = detail?.id else { window = nil; windowError = nil; return }
            await fetchWindow(id)
        }
    }

    /// What the window follows: the flow, and the two list-poll fields that change when
    /// the core recorded more packets or the session moved on. A new key re-reads the
    /// window; `fetchWindow` keeps the old one while the id matches, so the list never
    /// blanks between the reads.
    private struct WindowKey: Hashable {
        let id: FlowID
        let packetCount: Int
        let sessionState: L4SessionState

        init(_ flow: L4Flow) {
            id = flow.id
            packetCount = flow.packetCount
            sessionState = flow.sessionState
        }
    }

    /// The packets to show: the inspect window when it has arrived, else whatever
    /// the poll carried (an older core without the window sends every packet).
    private func packets(_ detail: L4Flow) -> [L4Packet] {
        if let window, window.id == detail.id { return window.packets }
        return detail.packets
    }

    @ViewBuilder private func detailPane(_ detail: L4Flow) -> some View {
        VStack(spacing: 0) {
            PaneTabs(title: tab == .packet ? "Layers" : "Craft", tabs: L4Tab.allCases, selected: $tab) {
                EmptyView()
            }
            switch tab {
            case .packet:
                let shown = packets(detail)
                if shown.isEmpty {
                    Hint(text: windowError.map { "Packets unavailable: \($0)" } ?? "No packets").padding(.leading, Space.md)
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                        .accessibilityIdentifier(windowError == nil ? "l4-no-packets" : "l4-window-error")
                } else {
                    L4PacketDetail(packet: shown[min(selected, shown.count - 1)])
                }
            case .craft:
                craftEditor
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: Craft editor (AC8) + guarded inject (AC10)

    private var craftEditor: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Text("PacketSpec (YAML): the layers of one packet to build and, in scope, inject.")
                .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                .padding(.horizontal, Space.md).padding(.top, Space.sm)
            TextEditor(text: $craftYAML)
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .scrollContentBackground(.hidden)
                .background(Tok.Ground.page.color)
                .frame(minHeight: 120)
                .padding(.horizontal, Space.xs)
                .accessibilityIdentifier("l4-craft-editor")
            HStack(spacing: Space.sm) {
                Button("Build") { build() }
                    .disabled(!gate.isEnabled(.craft))
                    .help(gate.disabledReason ?? "Parse the YAML and preview the on-wire bytes")
                Button("Inject…") { beginInject() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!isOperator || !gate.injectEnabled || preview == nil || !session.l4CaptureAvailability.canDriveWire)
                    .help(injectHelp)
                Spacer()
                if let preview {
                    Text("\(preview.length) B · \(preview.layers.joined(separator: " · "))")
                        .font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.L4.deep.color)
                }
            }
            .padding(.horizontal, Space.md)
            if let buildError {
                Text(buildError).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Status.serverError.color)
                    .padding(.horizontal, Space.md).textSelection(.enabled)
            }
            if let injectResult {
                Text(injectResult).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                    .padding(.horizontal, Space.md).textSelection(.enabled)
            }
            if let preview {
                Rule()
                Text("build() preview").font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
                    .foregroundStyle(Tok.Ink.secondary.color).padding(.horizontal, Space.md)
                HexView(data: preview.bytes).frame(maxHeight: .infinity)
            } else {
                Spacer()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    /// Inject's tooltip: the operator-only reason, else the scope reason, else the core's
    /// availability text (its reason when degraded, the pending literal before the first
    /// status reply), else what is left to do.
    private var injectHelp: String {
        if !isOperator { return Session.operatorOnlyReason }
        if !gate.injectEnabled { return gate.disabledReason ?? "" }
        if let text = session.l4CaptureAvailability.displayText { return text }
        if preview == nil { return "Build the packet first" }
        return "Inject through l4.inject — the guard confirms over the wire before anything hits the wire"
    }

    private func build() {
        buildError = nil
        injectResult = nil
        guard let spec = PacketSpecDraft.parse(craftYAML) else {
            preview = nil
            buildError = "Could not parse the PacketSpec — expected a `layers:` list of layer maps (ipv4 / udp / tcp / icmp / raw)."
            return
        }
        Task {
            do {
                let result = try await session.runCommand("l4.craft", ["spec": spec])
                preview = L4CraftPreview(json: result)
                if preview == nil { buildError = "l4.craft returned no bytes." }
            } catch {
                preview = nil
                buildError = BusService.describe(error)
            }
        }
    }

    private func beginInject() {
        guard let spec = PacketSpecDraft.parse(craftYAML) else { buildError = "Build the packet first."; return }
        let args: [String: JSONValue] = [
            "spec": spec, "dst": .string("127.0.0.1"), "interface": .string("lo0"), "port": .number(9), "count": .number(1),
        ]
        issue(L4PendingCall(command: "l4.inject", args: args), plainResult: "Injected.")
    }

    /// Forward / Drop the flow's oldest parked packet (spec §4, AC28): the verdict
    /// verbs take the parked id from `l4.intercept.list`, never the flow id, and
    /// go through the same confirm-over-the-wire handshake as inject.
    private func verdict(_ command: String) {
        guard let parked = parkedPacket else { return }
        issue(L4PendingCall(command: command, args: L4Verdict.args(parkedID: parked.id)), plainResult: "\(command) done.")
    }

    // MARK: Confirm-over-the-wire (spec §3 last rule; plan unit (d) amendment 2)

    /// Issue one confirmable call. A `needs_confirmation` reply becomes a prompt
    /// bound to exactly this call; a plain result reports `plainResult`; a guard
    /// refusal is surfaced verbatim, never as a confirm dialog. The role gate is
    /// enforced here, at the send site, not only on the buttons: a future menu item
    /// or shortcut that reaches `issue` without the operator role is refused the
    /// same way (AC33), nothing is sent.
    private func issue(_ call: L4PendingCall, plainResult: String) {
        guard isOperator else { injectResult = Session.operatorOnlyReason; return }
        injectResult = nil
        Task {
            do {
                let result = try await session.runCommand(call.command, call.args)
                if let request = L4ConfirmRequest(json: result, call: call) {
                    confirm = request
                } else {
                    injectResult = plainResult
                }
            } catch {
                injectResult = BusService.describe(error)
            }
        }
    }

    /// The operator confirmed: re-issue the call the prompt is bound to, with
    /// `_confirm` added and nothing else changed. No other state carries the command or args.
    private func confirmed(_ request: L4ConfirmRequest) {
        confirm = nil
        guard let call = request.call?.confirmed(with: request) else {
            injectResult = "The confirmation was not bound to a call; nothing was sent."
            return
        }
        Task {
            do {
                _ = try await session.runCommand(call.command, call.args)
                injectResult = "\(call.command) confirmed."
            } catch {
                injectResult = BusService.describe(error)
            }
        }
    }

    // MARK: The inspect window (spec §2: only the inspector fetches packets)

    /// One `l4.flow.get` window for the selected flow: the first 256 packets with
    /// their bytes when this core has the bounded window, every packet otherwise.
    /// Re-run for every `WindowKey` change; the previous window stays up while the id
    /// matches, and a failed read keeps it too and records why, so a transient bus
    /// error never blanks the packets the operator is reading.
    private func fetchWindow(_ id: FlowID) async {
        if window?.id != id { window = nil; windowError = nil }
        let args = L4Wire.flowGetArgs(id: id, inspect: true, window: L4Wire.supportsWindow(session.tools))
        do {
            let result = try await session.runCommand("l4.flow.get", args)
            guard !Task.isCancelled else { return }
            if let flow = L4Flow(json: result) {
                window = flow
                windowError = nil
            } else {
                windowError = "l4.flow.get returned no flow"
            }
        } catch {
            guard !Task.isCancelled else { return }
            windowError = BusService.describe(error)
        }
    }
}

enum L4Tab: String, CaseIterable, CustomStringConvertible {
    case packet = "Layers", craft = "Craft"
    var description: String { rawValue }
}

// MARK: - Packet list (mirrors the WebSocket frame list)

private struct L4PacketList: View {
    var detail: L4Flow
    var packets: [L4Packet]
    @Binding var selected: Int

    var body: some View {
        VStack(spacing: 0) {
            header
            Rule()
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(packets) { packet in
                        L4PacketRow(packet: packet, isSelected: packet.index == selected)
                            .contentShape(Rectangle())
                            .onTapGesture { selected = packet.index }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var header: some View {
        HStack(spacing: Tok.Metric.gapMeta) {
            Text("Packets").font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold)).foregroundStyle(Tok.Ink.primary.color)
            Badge(text: detail.proto.subLabel, pair: Tok.L4.badge, uppercase: false)
            Text(detail.sessionState.label).font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
            Spacer(minLength: 0)
            Text("\(detail.packetCount) pkt · \(detail.injectedCount) injected · \(detail.target)")
                .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color).lineLimit(1)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.tabBar)
    }
}

private struct L4PacketRow: View {
    var packet: L4Packet
    var isSelected: Bool

    private var outbound: Bool { packet.dir == .outbound }

    var body: some View {
        let endpoints = packet.endpoints
        HStack(spacing: Space.md) {
            Image(systemName: outbound ? "arrow.up" : "arrow.down")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(outbound ? Tok.L4.deep.color : Tok.Ink.link.color)
                .frame(width: Space.lg)
                .help(outbound ? "Outbound" : "Inbound")
            if let timestamp = packet.timestamp {
                Text(Format.time(timestamp))
                    .font(Tok.Face.data(Tok.Typography.Size.sm)).monospacedDigit()
                    .foregroundStyle(Tok.Ink.secondary.color)
            }
            if packet.injected {
                Badge(text: "injected", pair: ColorPair(fg: Tok.L4.deep, bg: Tok.L4.tint), uppercase: false)
            }
            if let endpoints {
                Text(endpoints)
                    .font(Tok.Face.data(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1).truncationMode(.middle)
            }
            Text(packet.summary)
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .foregroundStyle(endpoints == nil ? Tok.Ink.primary.color : Tok.Ink.secondary.color)
                .lineLimit(1).truncationMode(.tail)
            Spacer(minLength: Space.sm)
            Text(Format.bytes(Int64(packet.length)))
                .font(Tok.Face.data(Tok.Typography.Size.sm)).monospacedDigit()
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: 64, alignment: .trailing)
        }
        .padding(.horizontal, Space.md)
        .frame(minHeight: Tok.Size.Row.dense)
        .background(isSelected ? Tok.Ground.raised.color : .clear)
        .overlay(alignment: .leading) { if isSelected { Rectangle().fill(Tok.L4.base.color).frame(width: 2) } }
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier("l4-packet-\(packet.index)")
        .accessibilityLabel("\(outbound ? "outbound" : "inbound") packet, \(packet.length) bytes, \(packet.summary)")
    }
}

// MARK: - Packet detail (layer tree + hex)

private struct L4PacketDetail: View {
    var packet: L4Packet

    var body: some View {
        ScrollView([.vertical, .horizontal]) {
            VStack(alignment: .leading, spacing: Space.md) {
                Text("Layer tree").font(Tok.Face.ui(Tok.Typography.Size.sm, .medium)).foregroundStyle(Tok.Ink.secondary.color)
                if packet.layers.isEmpty {
                    Hint(text: "raw — no decodable layers (shown as-is, never corrected)")
                } else {
                    ForEach(Array(packet.layers.enumerated()), id: \.offset) { depth, layer in
                        HStack(spacing: Space.xs) {
                            Text(String(repeating: "  ", count: depth) + (depth == 0 ? "" : "└ "))
                                .font(Tok.Face.data(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.tertiary.color)
                            Text(layer).font(Tok.Face.data(Tok.Typography.Size.md, .medium)).foregroundStyle(Tok.L4.deep.color)
                        }
                    }
                }
                Text(metaLine)
                    .font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                Divider()
                Text("Bytes (hex)").font(Tok.Face.ui(Tok.Typography.Size.sm, .medium)).foregroundStyle(Tok.Ink.secondary.color)
                if let bytes = packet.bytes {
                    // Every row is one `Text`; `L4Hex` has already replaced every byte
                    // outside 0x20–0x7e with `.`, so nothing a packet carried can act on
                    // the screen (spec §2.3). These are one packet's rows — a jumbo frame is
                    // a few thousand — so they are built once, here, and laid out lazily.
                    let rows = L4Hex.rows(bytes)
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(rows.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(Tok.Face.data(Tok.Typography.Size.md)).monospaced()
                                .foregroundStyle(Tok.Ink.primary.color)
                                .lineLimit(1)
                        }
                    }
                    .textSelection(.enabled)
                } else {
                    Text("no bytes from this core")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                }
            }
            .padding(Space.md)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
    }

    /// Time · `src:port → dst:port` · direction · length · injected, from what the core sent.
    private var metaLine: String {
        var parts: [String] = []
        if let timestamp = packet.timestamp { parts.append(Format.time(timestamp)) }
        if let endpoints = packet.endpoints { parts.append(endpoints) }
        if let proto = packet.proto, !proto.isEmpty { parts.append(proto) }
        parts.append("Direction: \(packet.dir.rawValue)")
        parts.append("\(packet.length) B")
        if packet.injected { parts.append("injected") }
        return parts.joined(separator: " · ")
    }
}

// MARK: - Honest degradation banner (AC18) + documented-limited intercept (AC12, L4PAR-AC28)

/// The in-path intercept bar (spec §4). Degraded ⇒ one documented-limited line
/// with the core's own reason and no buttons; pending ⇒ the pending literal; available
/// with a parked packet for this flow ⇒ `Packet parked · <id>` with Forward / Drop,
/// which send the parked id (never the flow id) through the confirm handshake;
/// available with nothing parked ⇒ nothing. Never a control that silently fails: an
/// agent-role session sees Forward / Drop disabled with the operator-only reason.
struct L4InterceptBar: View {
    var availability: L4Availability
    var parked: L4ParkedPacket?
    var gate: L4ActionGate
    var isOperator: Bool
    /// What a verdict says when `isOperator` is false (`Session.operatorOnlyReason`).
    var operatorOnlyReason: String
    var onForward: () -> Void
    var onDrop: () -> Void

    /// The reason a verdict is disabled, or nil when it is offered.
    private func disabledReason(_ action: L4MutatingAction) -> String? {
        if !isOperator { return operatorOnlyReason }
        return gate.isEnabled(action) ? nil : gate.disabledReason
    }

    var body: some View {
        switch availability {
        case .degraded(let reason):
            limited(text: "In-path intercept unavailable: \(reason)", value: reason)
        case .pending:
            limited(text: L4Availability.pendingText, value: L4Availability.pendingText)
        case .available:
            if let parked {
                HStack(spacing: Space.sm) {
                    Text("Packet parked · \(parked.id.prefix(8))")
                        .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium)).foregroundStyle(Tok.Intercept.onBase.color)
                        .lineLimit(1)
                    Spacer(minLength: 0)
                    GhostButton("Forward") { onForward() }
                        .disabled(disabledReason(.forward) != nil)
                        .help(disabledReason(.forward) ?? "Forward the parked packet — the core confirms over the wire first")
                    GhostButton("Drop") { onDrop() }
                        .disabled(disabledReason(.drop) != nil)
                        .help(disabledReason(.drop) ?? "Drop the parked packet — the core confirms over the wire first")
                }
                .padding(.horizontal, Space.md)
                .frame(height: Tok.Size.interceptBar).frame(maxWidth: .infinity)
                .background(Tok.Intercept.base.color)
                .accessibilityIdentifier("l4-intercept-bar")
                .accessibilityValue(parked.id)
            } else {
                EmptyView()
            }
        }
    }

    private func limited(text: String, value: String) -> some View {
        HStack(spacing: Space.sm) {
            Image(systemName: "hand.raised.slash").font(.system(size: 12)).foregroundStyle(Tok.Ink.tertiary.color)
            Text(text)
                .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                .lineLimit(1).truncationMode(.tail)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Space.md).padding(.vertical, Space.xs)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Tok.Ground.raised.color)
        .help(value)
        .accessibilityIdentifier("l4-intercept-limited")
        .accessibilityValue(value)
    }
}

/// The capture/inject degradation banner: the core's own reason (spec §1) when
/// degraded, the shared pending literal before the first status reply, nothing when
/// available.
struct L4DegradedBanner: View {
    var availability: L4Availability

    var body: some View {
        switch availability {
        case .degraded(let reason):
            line(text: "Capture and inject unavailable: \(reason)", value: reason, glyph: "exclamationmark.triangle")
        case .pending:
            line(text: L4Availability.pendingText, value: L4Availability.pendingText, glyph: "clock")
        case .available:
            EmptyView()
        }
    }

    private func line(text: String, value: String, glyph: String) -> some View {
        HStack(spacing: Space.sm) {
            Image(systemName: glyph).foregroundStyle(Tok.Intercept.deep.color)
            Text(text)
                .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1).truncationMode(.tail)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Tok.Intercept.tint.color)
        .help(value)
        .accessibilityIdentifier("l4-degraded-banner")
        .accessibilityValue(value)
    }
}
