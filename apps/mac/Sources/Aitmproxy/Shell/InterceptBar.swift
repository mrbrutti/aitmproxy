import AitmproxyKit
import SwiftUI

/// The one saturated element (foundation §2.7). Hidden when disarmed; a
/// tinted notice when armed with nothing paused; the amber fill with the
/// oldest paused flow and its actions when flows are waiting.
struct InterceptBar: View {
    @Environment(Session.self) private var session
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var target: FlowRow? { session.interceptTarget }

    /// A failed embedded core cannot resume, kill or edit anything: the paused
    /// bar keeps Disarm and Rules… live and dims the rest (B4).
    private var coreFailed: Bool { session.coreHealth.health == .failed }

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
            PulseDot(color: Tok.Intercept.onBase, reduceMotion: reduceMotion)
                .frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
                .accessibilityHidden(true)
            Text("\(session.paused.count) paused").fontWeight(.semibold)
            if coreFailed {
                Text("· core failed — restart the core to resume")
                    .opacity(0.9)
                    .lineLimit(1)
            } else if let target {
                Text(targetText(target))
                    .font(Tok.Face.data(Tok.Typography.Size.md))
                    .opacity(0.9)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: Space.sm)
            // Collapse the secondary actions into an overflow menu when the bar is
            // narrow (e.g. a side panel opened), so buttons never truncate to ellipses.
            ViewThatFits(in: .horizontal) {
                actions(compact: false)
                actions(compact: true)
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

    /// The paused-bar actions. `compact` keeps only Resume and folds the rest into
    /// an overflow menu; `ViewThatFits` picks it when the full row would not fit.
    @ViewBuilder private func actions(compact: Bool) -> some View {
        // The verb table titles Resume vs Apply & Resume and says whether Edit applies (one predicate
        // with the Flow menu and the row menu, B3).
        let resume = session.verbItem(.resume, for: target?.id)
        let edit = session.verbItem(.edit, for: target?.id)
        let kill = session.verbItem(.kill, for: target?.id)
        HStack(spacing: Tok.Metric.gapTight) {
            PrimaryButton(resume.title, hint: resume.hint) { if let target { session.applyAndResume(target.id) } }
                .accessibilityIdentifier("resume-button")
                .disabled(coreFailed)
            if compact {
                Menu {
                    if let target, edit.enabled {
                        Button(edit.title) { session.perform(.edit, on: target.id) }.disabled(coreFailed)
                    }
                    Button("Resume All") { session.resumeAll() }.disabled(coreFailed)
                    Menu(kill.title) {
                        ForEach(KillMode.allCases, id: \.self) { mode in
                            Button(mode.title) { session.killMode = mode; if let target { session.kill(target.id) } }
                        }
                    }
                    .disabled(coreFailed)
                    Button("Breakpoint Rules…") { session.rulesVisible = true }
                    Button("Disarm Intercept") { session.arm(false) }
                } label: {
                    GhostButton("More", menu: true) {}
                }
                .menuStyle(.button)
                .buttonStyle(.plain)
                .menuIndicator(.hidden)
                .fixedSize()
            } else {
                if let target, edit.enabled {
                    GhostButton("Edit", hint: edit.hint) { session.perform(.edit, on: target.id) }
                        .accessibilityIdentifier("edit-button")
                        .disabled(coreFailed)
                }
                GhostButton("Resume All") { session.resumeAll() }
                    .disabled(coreFailed)
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
                    GhostButton(kill.title, hint: kill.hint, menu: true) { if let target { session.kill(target.id) } }
                } primaryAction: {
                    if let target { session.kill(target.id) }
                }
                .menuStyle(.button)
                .buttonStyle(.plain)
                .menuIndicator(.hidden)
                .disabled(coreFailed)
                .help("Kill \(session.killMode.title.lowercased()) (⌘\\); click the chevron for other modes")
                GhostButton("Rules…") { session.rulesVisible = true }
                GhostButton("Disarm", hint: "i") { session.arm(false) }
            }
        }
    }

    /// "edited"/"pending" comes from `pendingEditCount` alone, the same predicate
    /// the Resume title and the editor footer use, so the three never disagree (B3).
    private func targetText(_ row: FlowRow) -> String {
        var s = "\(row.method.label) \(row.url)"
        let pending = session.pendingEditCount(row.id)
        if pending > 0 {
            s += " · \(pending) edit\(pending == 1 ? "" : "s") pending"
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

/// The paused bar's 8 pt dot. Its pulse (opacity 1 → 0.45 and back over `motion.interceptPulse`,
/// curve `motion.pulse`) is a Core Animation animation on the dot's own layer, so the render server
/// breathes it and the main thread does nothing per frame: the SwiftUI `repeatForever` it replaces
/// cost 17–23 % of a core for as long as any flow was paused. Reduce Motion removes the animation
/// and holds opacity 1; when the setting turns off again the animation is added back. Both run from
/// `updateNSView`, so a live toggle in System Settings is right in either direction (S-069).
struct PulseDot: NSViewRepresentable {
    var color: DynamicColor
    var reduceMotion: Bool

    func makeNSView(context: Context) -> DotView {
        let view = DotView()
        view.wantsLayer = true
        view.layer?.cornerRadius = Tok.Size.statusDot / 2
        return view
    }

    func updateNSView(_ view: DotView, context: Context) {
        view.fill = color.nsColor
        view.setPulsing(!reduceMotion)
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: DotView, context: Context) -> CGSize? {
        CGSize(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
    }

    final class DotView: NSView {
        static let pulseKey = "pulse"
        var fill: NSColor = .clear { didSet { needsDisplay = true } }
        private(set) var pulsing = false

        override var wantsUpdateLayer: Bool { true }
        override func updateLayer() { layer?.backgroundColor = fill.cgColor }
        override func viewDidChangeEffectiveAppearance() {
            super.viewDidChangeEffectiveAppearance()
            needsDisplay = true
        }

        func setPulsing(_ on: Bool) {
            pulsing = on
            guard let layer else { return }
            if on {
                guard layer.animation(forKey: Self.pulseKey) == nil else { return }
                let pulse = CABasicAnimation(keyPath: "opacity")
                pulse.fromValue = 1.0
                pulse.toValue = 0.45
                pulse.duration = Tok.Motion.interceptPulse / 2
                pulse.autoreverses = true
                pulse.repeatCount = .infinity
                pulse.timingFunction = Tok.Motion.pulseTiming
                layer.add(pulse, forKey: Self.pulseKey)
            } else {
                layer.removeAnimation(forKey: Self.pulseKey)
                layer.opacity = 1
            }
        }

        /// A layer that left and re-entered a window may have dropped its animations; put it back.
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if pulsing, window != nil { setPulsing(true) }
        }
    }
}

/// Press: 120ms scale(0.97) (motion.press); a plain opacity dip under Reduce Motion (S-069).
struct PressStyle: ButtonStyle {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed && !reduceMotion ? 0.97 : 1)
            // Disabled buttons must read as disabled: these custom buttons carry no
            // system chrome, so without this a `.disabled` Add/Save looks clickable.
            .opacity(!isEnabled ? 0.4 : (configuration.isPressed && reduceMotion ? 0.7 : 1))
            .animation(reduceMotion ? nil : Tok.Motion.easeOut(Tok.Motion.press), value: configuration.isPressed)
    }
}
