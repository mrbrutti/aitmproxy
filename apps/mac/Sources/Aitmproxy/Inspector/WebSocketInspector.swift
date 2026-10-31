import AitmproxyKit
import SwiftUI

/// The inspector for a WebSocket flow (S-045). A WebSocket has no request /
/// response split; it has an ordered message stream. The top pane lists the
/// frames (direction, opcode, length, time, preview); selecting one shows its
/// decoded payload below, reusing the body viewers (JSON, text, hex, …).
struct WebSocketInspector: View {
    @Environment(Session.self) private var session
    var row: FlowRow
    var detail: WSDetail?

    @State private var selected = 0
    @State private var direction: WSDirectionFilter = .both
    @State private var bodyState = BodyViewState()
    @State private var sseState = SSEViewState()

    private func frames(_ detail: WSDetail) -> [WSFrameDetail] {
        detail.frames.filter { direction.keeps($0) }
    }

    var body: some View {
        if let detail {
            if detail.frames.isEmpty {
                ContentUnavailableView {
                    Label("No Frames", systemImage: "dot.radiowaves.left.and.right")
                } description: {
                    Text("This WebSocket has exchanged no frames yet.")
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                // Same autosave name and fraction as the HTTP Request | Response split, so
                // the divider doesn't jump when the operator moves between HTTP and WS flows.
                SplitPane(axis: .vertical, firstMinimum: 160, secondMinimum: 160, initialSecondFraction: 0.5,
                          autosaveName: "inspector.panes") {
                    WSFramesList(detail: detail, frames: frames(detail), direction: $direction, selected: $selected)
                        .environment(session).themed()
                } second: {
                    frameBody(frames(detail)).environment(session).themed()
                }
            }
        } else {
            LoadingLines()
        }
    }

    @ViewBuilder private func frameBody(_ frames: [WSFrameDetail]) -> some View {
        if frames.isEmpty {
            Hint(text: "No frames in this direction")
                .padding(.leading, Space.md)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
        @Bindable var bodyState = bodyState
        let index = min(selected, frames.count - 1)
        let frame = frames[index]
        VStack(spacing: 0) {
            PaneTabs(title: "Frame \(index + 1)", tabs: [WSBodyTab.body], selected: .constant(.body)) {
                if let data = frame.data, !data.isEmpty {
                    BodyHost.controls(message: frame.message, extent: nil, state: bodyState, sseState: sseState)
                }
            }
            if bodyState.findShown {
                FindRow(state: bodyState.find, isPresented: $bodyState.findShown)
            }
            BodyHost(message: frame.message, extent: nil, bodySize: session.density.bodySize,
                     sseState: sseState, state: bodyState)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onChange(of: index) { bodyState.format = .auto; bodyState.findShown = false; bodyState.imageZoom = .fit }
        }
    }
}

private enum WSBodyTab: Hashable, CustomStringConvertible {
    case body
    var description: String { "Body" }
}

/// The frames table: a direction filter over one tappable row per message.
private struct WSFramesList: View {
    @Environment(Session.self) private var session
    var detail: WSDetail
    var frames: [WSFrameDetail]
    @Binding var direction: WSDirectionFilter
    @Binding var selected: Int

    var body: some View {
        VStack(spacing: 0) {
            header
            Rule()
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(Array(frames.enumerated()), id: \.offset) { index, frame in
                        WSFrameRow(frame: frame, index: index, isSelected: index == selected)
                            .contentShape(Rectangle())
                            .onTapGesture { selected = index }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onChange(of: direction) { selected = 0 }
    }

    private var header: some View {
        HStack(spacing: Tok.Metric.gapMeta) {
            Text("Messages").font(Tok.Face.ui(Tok.Typography.Size.lg, .semibold)).foregroundStyle(Tok.Ink.primary.color)
            Picker("Direction", selection: $direction) {
                ForEach(WSDirectionFilter.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .accessibilityIdentifier("ws-direction-filter")
            Spacer(minLength: 0)
            Text([detail.connection.httpVersion, detail.connection.tlsVersion, detail.connection.alpn]
                .compactMap { $0 }.joined(separator: " · "))
                .font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color).lineLimit(1)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.tabBar)
    }
}

private struct WSFrameRow: View {
    var frame: WSFrameDetail
    var index: Int
    var isSelected: Bool

    private var outbound: Bool { frame.direction == .clientToServer }

    var body: some View {
        HStack(spacing: Space.md) {
            Image(systemName: outbound ? "arrow.up" : "arrow.down")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(outbound ? Tok.Intercept.deep.color : Tok.Ink.link.color)
                .frame(width: Space.lg)
                .help(outbound ? "Client to server" : "Server to client")
            Badge(text: frame.opcode, pair: opcodePair, uppercase: false)
            if frame.injected {
                Badge(text: "injected", pair: ColorPair(fg: Tok.Intercept.deep, bg: Tok.Intercept.tint), uppercase: false)
            }
            Text(frame.preview)
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .foregroundStyle(frame.opcode == "text" ? Tok.Ink.primary.color : Tok.Ink.tertiary.color)
                .lineLimit(1).truncationMode(.tail)
            Spacer(minLength: Space.sm)
            Text(Format.bytes(Int64(frame.length)))
                .font(Tok.Face.data(Tok.Typography.Size.sm)).monospacedDigit()
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: 64, alignment: .trailing)
            Text(frame.timestamp.flatMap { Format.clock(rfc3339: $0) } ?? Format.dash)
                .font(Tok.Face.data(Tok.Typography.Size.sm)).monospacedDigit()
                .foregroundStyle(Tok.Ink.tertiary.color)
                .frame(width: 92, alignment: .trailing)
        }
        .padding(.horizontal, Space.md)
        .frame(minHeight: Tok.Size.Row.dense)
        .background(isSelected ? Tok.Ground.raised.color : .clear)
        .overlay(alignment: .leading) {
            if isSelected { Rectangle().fill(Palette.accent).frame(width: 2) }
        }
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier("ws-frame-\(index)")
        .accessibilityLabel("\(outbound ? "sent" : "received") \(frame.opcode) frame, \(frame.length) bytes")
        .accessibilityValue(frame.preview)
    }

    private var opcodePair: ColorPair {
        switch frame.opcode {
        case "text": ColorPair(fg: Tok.Ink.secondary, bg: Tok.Ground.raised)
        case "binary": ColorPair(fg: Tok.Syntax.number, bg: Tok.Ground.raised)
        default: ColorPair(fg: Tok.Ink.tertiary, bg: Tok.Ground.raised)
        }
    }
}

extension WSFrameDetail {
    /// The frame payload as a synthetic HTTP message, so the body viewers can
    /// render it (JSON tree, text, hex) with no new viewer code.
    var message: HTTPMessage {
        HTTPMessage(startLine: "",
                    headers: contentTypeHint.map { [HTTPMessage.Header("content-type", $0)] } ?? [],
                    body: data)
    }
}
