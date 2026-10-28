import AitmproxyKit
import SwiftUI

/// The one saturated element (foundation §2.7). Hidden when disarmed; a
/// tinted notice when armed with nothing paused; the amber fill with the
/// oldest paused flow and its actions when flows are waiting.
struct InterceptBar: View {
    @Environment(Session.self) private var session
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var pulse = false

    private var target: FlowRow? { session.interceptTarget }

    var body: some View {
        if session.paused.isEmpty {
            armedNotice
        } else {
            pausedBar
        }
    }

    private var armedNotice: some View {
        HStack(spacing: Tok.Metric.padInner) {
            Image(systemName: Tok.Glyph.intercept).font(.system(size: 13))
            Text(session.breakpointRules.armedNotice)
            Spacer()
            GhostButton("Rules…", onColor: Tok.Intercept.deep) { session.rulesVisible = true }
            GhostButton("Disarm", hint: "i", onColor: Tok.Intercept.deep) { session.arm(false) }
        }
        .font(Tok.Face.ui(Tok.Typography.Size.md))
        .foregroundStyle(Tok.Intercept.deep.color)
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.interceptBar)
        .frame(maxWidth: .infinity)
        .background(Tok.Intercept.tint.color)
        .overlay(alignment: .top) { Rule() }
        .overlay(alignment: .bottom) { Rule() }
    }

    private var pausedBar: some View {
        HStack(spacing: Tok.Metric.padInner) {
            Circle()
                .fill(Tok.Intercept.onBase.color)
                .frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
                .opacity(pulse && !reduceMotion ? 0.45 : 1)
                .onAppear {
                    guard !reduceMotion else { return }
                    withAnimation(.easeInOut(duration: Tok.Motion.interceptPulse / 2).repeatForever()) { pulse = true }
                }
            Text("\(session.paused.count) paused").fontWeight(.semibold)
            if let target {
                Text(targetText(target))
                    .font(Tok.Face.data(Tok.Typography.Size.md))
                    .opacity(0.9)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: Space.sm)
            HStack(spacing: Tok.Metric.gapTight) {
                PrimaryButton(target.map { session.pendingEditCount($0.id) > 0 } == true ? "Apply & Resume" : "Resume", hint: "⌘⏎") {
                    if let target { session.applyAndResume(target.id) }
                }
                if let target, row(target).state == .paused {
                    GhostButton("Edit", hint: "e") { session.editPaused(target.id) }
                }
                GhostButton("Resume all") { session.resumeAll() }
                Menu {
                    ForEach(KillMode.allCases, id: \.self) { mode in
                        Button {
                            session.killMode = mode
                            if let target { session.kill(target.id) }
                        } label: {
                            if mode == session.killMode { Label(mode.title, systemImage: "checkmark") } else { Text(mode.title) }
                        }
                    }
                } label: {
                    GhostButton("Kill", hint: "⌘\\", menu: true) { if let target { session.kill(target.id) } }
                } primaryAction: {
                    if let target { session.kill(target.id) }
                }
                .menuStyle(.button)
                .buttonStyle(.plain)
                .menuIndicator(.hidden)
                .help("Kill \(session.killMode.title.lowercased()) (⌘\\); click the chevron for other modes")
                GhostButton("Rules…") { session.rulesVisible = true }
                GhostButton("Disarm", hint: "i") { session.arm(false) }
            }
        }
        .font(Tok.Face.ui(Tok.Typography.Size.md))
        .foregroundStyle(Tok.Intercept.onBase.color)
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.interceptBar)
        .frame(maxWidth: .infinity)
        .background(Tok.Intercept.base.color)
        .overlay(alignment: .top) { Rule() }
        .overlay(alignment: .bottom) { Rule() }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Intercept: \(session.paused.count) paused")
    }

    private func row(_ r: FlowRow) -> FlowRow { r }

    private func targetText(_ row: FlowRow) -> String {
        var s = "\(row.method.label) \(row.url)"
        let pending = session.pendingEditCount(row.id)
        if pending > 0 {
            s += " · \(pending) edit\(pending == 1 ? "" : "s") pending"
        } else if row.edited, let detail = session.details[row.id], let original = detail.originalRequest {
            let n = max(abs(detail.request.headers.count - original.headers.count), 1)
            s += " · edited (\(n) header\(n == 1 ? "" : "s"))"
        }
        return s
    }
}

/// The inverse-fill primary button, with its shortcut printed on it.
struct PrimaryButton: View {
    var title: String
    var hint: String?
    var action: () -> Void

    init(_ title: String, hint: String? = nil, action: @escaping () -> Void) {
        self.title = title
        self.hint = hint
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: Tok.Metric.gapTight) {
                Text(title)
                if let hint { Text(hint).opacity(0.85) }
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
            .foregroundStyle(Tok.Ink.onInverse.color)
            .padding(.horizontal, Tok.Metric.padInner)
            .frame(height: Tok.Metric.barButton)
            .background(Tok.Ground.inverse.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
        }
        .buttonStyle(PressStyle())
    }
}

/// A translucent button on the intercept bar.
struct GhostButton: View {
    var title: String
    var hint: String?
    var menu = false
    var onColor: DynamicColor = Tok.Intercept.onBase
    var action: () -> Void

    init(_ title: String, hint: String? = nil, menu: Bool = false, onColor: DynamicColor = Tok.Intercept.onBase,
         action: @escaping () -> Void) {
        self.title = title
        self.hint = hint
        self.menu = menu
        self.onColor = onColor
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: Tok.Metric.gapTight) {
                Text(title)
                if let hint { Text(hint).opacity(0.85) }
                if menu { Image(systemName: "chevron.down").font(.system(size: 9, weight: .medium)) }
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
            .foregroundStyle(onColor.color)
            .padding(.horizontal, Tok.Metric.padInner)
            .frame(height: Tok.Metric.barButton)
            .background(Color.black.opacity(0.12), in: RoundedRectangle(cornerRadius: Tok.Radius.control))
        }
        .buttonStyle(PressStyle())
    }
}

/// Press: 120ms scale(0.97) (motion.press).
struct PressStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .animation(Tok.Motion.easeOut(Tok.Motion.press), value: configuration.isPressed)
    }
}
