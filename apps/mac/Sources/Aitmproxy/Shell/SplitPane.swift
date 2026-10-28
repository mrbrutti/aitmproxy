import AppKit
import SwiftUI

/// Two SwiftUI views on an `NSSplitView` with a draggable, persisted
/// divider (foundation §2.10a "persisted widths"): the flow list over the
/// inspector, and the Request | Response panes.
struct SplitPane<First: View, Second: View>: NSViewControllerRepresentable {
    /// `.vertical` puts the panes side by side (a vertical divider); `.horizontal` stacks them.
    var axis: Axis
    var firstMinimum: CGFloat
    var secondMinimum: CGFloat
    /// The second pane's share when nothing is remembered yet.
    var initialSecondFraction: CGFloat
    var autosaveName: String
    let first: First
    let second: Second

    init(axis: Axis, firstMinimum: CGFloat = 160, secondMinimum: CGFloat = 160, initialSecondFraction: CGFloat = 0.5,
         autosaveName: String, @ViewBuilder first: () -> First, @ViewBuilder second: () -> Second) {
        self.axis = axis
        self.firstMinimum = firstMinimum
        self.secondMinimum = secondMinimum
        self.initialSecondFraction = initialSecondFraction
        self.autosaveName = autosaveName
        self.first = first()
        self.second = second()
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSViewController(context: Context) -> NSSplitViewController {
        let controller = NSSplitViewController()
        controller.splitView = FlatSplitView()
        controller.splitView.isVertical = axis == .vertical
        controller.splitView.dividerStyle = .thin
        // sizingOptions = []: the content takes the split item's frame instead of its ideal size.
        let firstHost = NSHostingController(rootView: Filled(content: first))
        firstHost.sizingOptions = []
        let secondHost = NSHostingController(rootView: Filled(content: second))
        secondHost.sizingOptions = []
        let a = NSSplitViewItem(viewController: firstHost)
        a.minimumThickness = firstMinimum
        a.holdingPriority = NSLayoutConstraint.Priority(rawValue: 250)
        let b = NSSplitViewItem(viewController: secondHost)
        b.minimumThickness = secondMinimum
        b.holdingPriority = NSLayoutConstraint.Priority(rawValue: 251)
        controller.addSplitViewItem(a)
        controller.addSplitViewItem(b)
        controller.splitView.autosaveName = Store.isOverridden ? nil : autosaveName
        context.coordinator.controller = controller
        context.coordinator.fraction = initialSecondFraction
        return controller
    }

    func updateNSViewController(_ controller: NSSplitViewController, context: Context) {
        (controller.splitViewItems[0].viewController as? NSHostingController<Filled<First>>)?.rootView = Filled(content: first)
        (controller.splitViewItems[1].viewController as? NSHostingController<Filled<Second>>)?.rootView = Filled(content: second)
        context.coordinator.placeOnce()
    }

    /// Fills the hosting view from its top-leading corner.
    struct Filled<Content: View>: View {
        let content: Content
        var body: some View {
            content.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }

    final class Coordinator {
        weak var controller: NSSplitViewController?
        var fraction: CGFloat = 0.5
        private var placed = false

        /// Without a remembered position, the divider sits at the initial fraction once the view has a size.
        func placeOnce() {
            guard !placed, let controller else { return }
            let remembered = controller.splitView.autosaveName.map {
                UserDefaults.standard.object(forKey: "NSSplitView Subview Frames \($0)") != nil
            } ?? false
            guard !remembered else { placed = true; return }
            let split = controller.splitView
            let length = split.isVertical ? split.bounds.width : split.bounds.height
            guard length > 0 else { return }
            placed = true
            DispatchQueue.main.async { [fraction] in
                let total = split.isVertical ? split.bounds.width : split.bounds.height
                split.setPosition((total * (1 - fraction)).rounded(), ofDividerAt: 0)
            }
        }
    }
}
