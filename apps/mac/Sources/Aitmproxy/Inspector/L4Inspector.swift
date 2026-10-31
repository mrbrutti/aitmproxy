import AitmBusClient
import AitmproxyKit
import SwiftUI

/// The inspector for a raw-L4 flow (ui-scripting-highlight-l4 Part 3 §3.2;
/// l4-operator-surfaces Part 3). A packet list (top) over a detail pane (bottom)
/// that toggles between the selected packet's layer tree + hex and the craft
/// editor (human-friendly YAML `PacketSpec` → `build()` hex preview → guarded
/// inject with the operator confirm-over-the-wire dialog). Scope-as-authorization
/// dims and disables every mutating action out of L4 scope (AC9/AC10); the macOS
/// embedded core degrades every wire verb honestly (AC18).
struct L4Inspector: View {
    @Environment(Session.self) private var session
    var row: FlowRow
    var detail: L4Flow?

    @State private var selected = 0
    @State private var tab: L4Tab = .packet
    @State private var craftYAML = L4Inspector.sampleSpec
    @State private var preview: L4CraftPreview?
    @State private var buildError: String?
    @State private var confirm: L4ConfirmRequest?
    @State private var pendingInject: [String: JSONValue]?
    @State private var pendingCommand = "l4.inject"
    @State private var injectResult: String?

    private var gate: L4ActionGate { L4ActionGate(inScope: row.inScope) }

    var body: some View {
        VStack(spacing: 0) {
            if let reason = session.l4Availability.reason {
                L4DegradedBanner(reason: reason)
                Rule()
            }
            L4InterceptBar(present: session.l4HasIntercept, session: detail?.sessionState == .intercept,
                           gate: gate, onForward: { interceptVerb("l4.intercept.forward") },
                           onDrop: { interceptVerb("l4.intercept.drop") })
            if let detail {
                SplitPane(axis: .vertical, firstMinimum: 140, secondMinimum: 280, initialSecondFraction: 0.5,
                          autosaveName: "inspector.l4") {
                    L4PacketList(detail: detail, selected: $selected).environment(session).themed()
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
            L4ConfirmSheet(request: request, onConfirm: { confirmInject(request) }, onCancel: { confirm = nil })
        }
    }

    @ViewBuilder private func detailPane(_ detail: L4Flow) -> some View {
        VStack(spacing: 0) {
            PaneTabs(title: tab == .packet ? "Layers" : "Craft", tabs: L4Tab.allCases, selected: $tab) {
                EmptyView()
            }
            switch tab {
            case .packet:
                if detail.packets.isEmpty {
                    Hint(text: "No packets").padding(.leading, Space.md)
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                } else {
                    L4PacketDetail(packet: detail.packets[min(selected, detail.packets.count - 1)])
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
            Text("PacketSpec (YAML) — human-authored; the Rhai l4.craft(#{…}) path lights up when the seam lands.")
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
                    .disabled(!gate.injectEnabled || preview == nil || !session.l4Availability.canDriveWire)
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

    private var injectHelp: String {
        if !gate.injectEnabled { return gate.disabledReason ?? "" }
        if !session.l4Availability.canDriveWire { return session.l4Availability.reason ?? "" }
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
        injectResult = nil
        let args: [String: JSONValue] = [
            "spec": spec, "dst": .string("127.0.0.1"), "interface": .string("lo0"), "port": .number(9), "count": .number(1),
        ]
        pendingInject = args
        pendingCommand = "l4.inject"
        Task {
            do {
                let result = try await session.runCommand("l4.inject", args)
                if let request = L4ConfirmRequest(json: result) {
                    confirm = request
                } else {
                    // A plain result (no confirmation needed) — report it.
                    injectResult = "Injected."
                    session.l4LastWireError = nil
                }
            } catch {
                // A guard refusal is surfaced verbatim, never as a confirm dialog.
                let message = BusService.describe(error)
                injectResult = message
                if message.lowercased().contains("l4 unavailable") { session.l4LastWireError = message }
            }
        }
    }

    private func confirmInject(_ request: L4ConfirmRequest) {
        guard var args = pendingInject else { confirm = nil; return }
        args["_confirm"] = .string(request.token)
        let command = pendingCommand
        confirm = nil
        Task {
            do {
                _ = try await session.runCommand(command, args)
                injectResult = "\(command) confirmed."
                session.l4LastWireError = nil
            } catch {
                injectResult = BusService.describe(error)
            }
        }
    }

    /// Forward / Drop a parked packet through the in-path intercept verbs, reusing
    /// the same confirm-over-the-wire handshake as inject (AC12).
    private func interceptVerb(_ command: String) {
        guard let id = detail?.id else { return }
        let args: [String: JSONValue] = ["id": .string(id.raw)]
        pendingInject = args
        pendingCommand = command
        injectResult = nil
        Task {
            do {
                let result = try await session.runCommand(command, args)
                if let request = L4ConfirmRequest(json: result) {
                    confirm = request
                } else {
                    injectResult = "\(command) done."
                }
            } catch {
                injectResult = BusService.describe(error)
            }
        }
    }

    /// A minimal, human-friendly loopback UDP spec the operator edits.
    static let sampleSpec = """
    layers:
      - ipv4:
          src: 127.0.0.1
          dst: 127.0.0.1
      - udp:
          sport: 40000
          dport: 9
      - raw:
          data: "hello-l4"
    """
}

enum L4Tab: String, CaseIterable, CustomStringConvertible {
    case packet = "Layers", craft = "Craft"
    var description: String { rawValue }
}

// MARK: - Packet list (mirrors the WebSocket frame list)

private struct L4PacketList: View {
    var detail: L4Flow
    @Binding var selected: Int

    var body: some View {
        VStack(spacing: 0) {
            header
            Rule()
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(detail.packets) { packet in
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
        HStack(spacing: Space.md) {
            Image(systemName: outbound ? "arrow.up" : "arrow.down")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(outbound ? Tok.L4.deep.color : Tok.Ink.link.color)
                .frame(width: Space.lg)
                .help(outbound ? "Outbound" : "Inbound")
            if packet.injected {
                Badge(text: "injected", pair: ColorPair(fg: Tok.L4.deep, bg: Tok.L4.tint), uppercase: false)
            }
            Text(packet.summary)
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.primary.color)
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
        ScrollView {
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
                Text("Direction: \(packet.dir.rawValue) · \(packet.length) B\(packet.injected ? " · injected" : "")")
                    .font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
                Divider()
                Text("Bytes (hex)").font(Tok.Face.ui(Tok.Typography.Size.sm, .medium)).foregroundStyle(Tok.Ink.secondary.color)
                // l4.flow.get is a summary — it carries layers + length, not the raw
                // bytes (bounded M5 store). The craft editor's build() preview shows
                // crafted bytes in hex; captured bytes are not transported.
                Hint(text: "The captured bytes aren't kept here. Use Craft → Build to see crafted bytes in hex.")
            }
            .padding(Space.md)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
    }
}

// MARK: - Confirm dialog (confirm-over-the-wire, AC10)

private struct L4ConfirmSheet: View {
    var request: L4ConfirmRequest
    var onConfirm: () -> Void
    var onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            HStack(spacing: Space.sm) {
                Image(systemName: "exclamationmark.shield").foregroundStyle(Tok.L4.base.color)
                Text("Confirm injection").font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold)).foregroundStyle(Tok.Ink.primary.color)
            }
            Text(request.prompt)
                .font(Tok.Face.data(Tok.Typography.Size.md)).foregroundStyle(Tok.Ink.secondary.color)
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                Button("Inject") { onConfirm() }.buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("l4-confirm-inject")
            }
        }
        .padding(Space.lg)
        .frame(width: 480)
    }
}

// MARK: - Honest degradation banner (AC18) + documented-limited intercept (AC12)

/// The in-path intercept bar (AC12). Where `l4.intercept.*` is present and the
/// flow is an interception session, it parks a packet with Forward / Mutate / Drop
/// (Forward/Drop reuse the confirm-over-the-wire handshake). Where absent
/// (macOS / unprivileged / non-Linux), it renders documented-limited — never a
/// control that silently fails.
struct L4InterceptBar: View {
    var present: Bool
    var session: Bool
    var gate: L4ActionGate
    var onForward: () -> Void
    var onDrop: () -> Void

    var body: some View {
        if !present {
            HStack(spacing: Space.sm) {
                Image(systemName: "hand.raised.slash").font(.system(size: 12)).foregroundStyle(Tok.Ink.tertiary.color)
                Text("Forwarding and dropping packets in-path isn't available here — capture, craft and guarded inject still work.")
                    .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
                    .lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, Space.md).padding(.vertical, Space.xs)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Tok.Ground.raised.color)
            .help("In-path intercept (Forward / Mutate / Drop) needs a Linux core with the l4.intercept.* verbs (NFQUEUE / CAP_NET_ADMIN).")
            .accessibilityIdentifier("l4-intercept-limited")
        } else if session {
            HStack(spacing: Space.sm) {
                Text("Packet parked").font(Tok.Face.ui(Tok.Typography.Size.sm, .medium)).foregroundStyle(Tok.Intercept.onBase.color)
                Spacer(minLength: 0)
                GhostButton("Forward") { onForward() }.disabled(!gate.isEnabled(.forward))
                GhostButton("Drop") { onDrop() }.disabled(!gate.isEnabled(.drop))
            }
            .padding(.horizontal, Space.md)
            .frame(height: Tok.Size.interceptBar).frame(maxWidth: .infinity)
            .background(Tok.Intercept.base.color)
            .accessibilityIdentifier("l4-intercept-bar")
        }
    }
}

struct L4DegradedBanner: View {
    var reason: String

    var body: some View {
        HStack(spacing: Space.sm) {
            Image(systemName: "exclamationmark.triangle").foregroundStyle(Tok.Intercept.deep.color)
            Text("Sending and injecting packets isn't available here.")
                .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1).truncationMode(.tail)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Tok.Intercept.tint.color)
        .help(reason)
        .accessibilityIdentifier("l4-degraded-banner")
        .accessibilityValue(reason)
    }
}

extension L4ConfirmRequest: Identifiable {
    public var id: String { token }
}
