import AppKit
import SwiftUI

extension View {
    /// Opens the window with nothing focused: no focus ring and no text
    /// cursor until the person clicks or presses Tab. Use it on every window
    /// and sheet, except one whose only job is typing (a search or quick-add
    /// panel focuses its field on purpose).
    func noInitialFocus(then follow: (() -> Void)? = nil) -> some View {
        background(WindowHook(follow: follow))
    }

    /// Dims custom chrome when its window is not the active one, matching the
    /// system's own controls (rule 62). Desaturates rather than fading, so opaque
    /// chrome backgrounds stay opaque and only the colour (accent, status, agent
    /// tints) greys out; the active state is unchanged. Chrome only — never content.
    func dimsWhenInactive() -> some View {
        modifier(DimsWhenInactive())
    }

    /// Sizes a Form, List, or ScrollView to its content, up to `max` points.
    /// A Settings page or sheet then grows to fit, and scrolls only when its
    /// content is taller than `max`.
    func fitsContent(max: CGFloat = 640) -> some View {
        modifier(FitsContent(max: max))
    }
}

private struct DimsWhenInactive: ViewModifier {
    @Environment(\.controlActiveState) private var activeState

    func body(content: Content) -> some View {
        content.saturation(activeState == .inactive ? 0 : 1)
    }
}

private struct FitsContent: ViewModifier {
    var max: CGFloat
    @State private var height: CGFloat?

    func body(content: Content) -> some View {
        content
            // Only the content's own height: the insets change as the window
            // resizes, which would start a resize loop.
            .onScrollGeometryChange(for: CGFloat.self) { geometry in
                geometry.contentSize.height.rounded(.up)
            } action: { _, new in
                if abs(new - (height ?? 0)) >= 1 { height = new }
            }
            .frame(height: height.map { min($0, max) })
            .scrollBounceBehavior(.basedOnSize)
    }
}

/// A zero-size view that reaches the NSWindow it sits in.
private struct WindowHook: NSViewRepresentable {
    /// Runs right after the first responder is cleared, in the same run-loop turn, so a
    /// window whose one job is typing can focus its field without racing the clear.
    var follow: (() -> Void)?

    func makeNSView(context: Context) -> Probe {
        let probe = Probe()
        probe.follow = follow
        return probe
    }

    func updateNSView(_ probe: Probe, context: Context) {
        probe.follow = follow
    }

    final class Probe: NSView {
        var follow: (() -> Void)?
        private var reopened = false

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let window else { return }
            NotificationCenter.default.removeObserver(self)
            clear(window)
            // A closed window keeps its views. Clear again when it opens next time.
            NotificationCenter.default.addObserver(self, selector: #selector(willClose),
                                                   name: NSWindow.willCloseNotification, object: window)
            NotificationCenter.default.addObserver(self, selector: #selector(didBecomeKey),
                                                   name: NSWindow.didBecomeKeyNotification, object: window)
        }

        @objc private func willClose(_ note: Notification) {
            reopened = true
        }

        @objc private func didBecomeKey(_ note: Notification) {
            guard reopened, let window else { return }
            reopened = false
            clear(window)
        }

        /// AppKit picks a first control right after the window shows. Clear it after that.
        private func clear(_ window: NSWindow) {
            DispatchQueue.main.async { [weak self] in
                window.makeFirstResponder(nil)
                self?.follow?()
            }
        }
    }
}
