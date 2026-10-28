import AppKit
import SwiftUI

/// The sidebar | main split as an `NSSplitViewController` (foundation §2.10a):
/// the sidebar opens at 240, holds its width while the window resizes, stays
/// within 200–320, remembers its width, and collapses with the toolbar toggle.
struct ShellSplitView<Sidebar: View, Main: View>: NSViewControllerRepresentable {
    @Binding var sidebarVisible: Bool
    let sidebar: Sidebar
    let main: Main

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSViewController(context: Context) -> NSSplitViewController {
        let controller = NSSplitViewController()
        controller.splitView = FlatSplitView()
        controller.splitView.isVertical = true
        controller.splitView.dividerStyle = .thin

        let side = NSSplitViewItem(viewController: NSHostingController(rootView: sidebar))
        side.minimumThickness = Tok.Size.sidebarMin
        side.maximumThickness = Tok.Size.sidebarMax
        side.canCollapse = true
        // Higher than the main pane's, so the sidebar keeps its width and the main pane stretches.
        side.holdingPriority = NSLayoutConstraint.Priority(rawValue: 260)
        let content = NSSplitViewItem(viewController: NSHostingController(rootView: main))
        content.minimumThickness = 720
        content.holdingPriority = NSLayoutConstraint.Priority(rawValue: 250)
        controller.addSplitViewItem(side)
        controller.addSplitViewItem(content)
        controller.splitView.autosaveName = Store.isOverridden ? nil : "shell.split"
        context.coordinator.controller = controller
        return controller
    }

    func updateNSViewController(_ controller: NSSplitViewController, context: Context) {
        (controller.splitViewItems[0].viewController as? NSHostingController<Sidebar>)?.rootView = sidebar
        (controller.splitViewItems[1].viewController as? NSHostingController<Main>)?.rootView = main
        let item = controller.splitViewItems[0]
        if item.isCollapsed == sidebarVisible {
            item.animator().isCollapsed = !sidebarVisible
        }
        context.coordinator.openAtIdealWidthOnce()
    }

    final class Coordinator {
        weak var controller: NSSplitViewController?
        private var placed = false

        /// Without a remembered width the divider sits at 240 (`size.sidebar`).
        func openAtIdealWidthOnce() {
            guard !placed, let controller else { return }
            placed = true
            let remembered = controller.splitView.autosaveName.map {
                UserDefaults.standard.object(forKey: "NSSplitView Subview Frames \($0)") != nil
            } ?? false
            guard !remembered else { return }
            DispatchQueue.main.async {
                controller.splitView.setPosition(Tok.Size.sidebar, ofDividerAt: 0)
            }
        }
    }
}

/// A split view whose divider is the foundation's `line.border`.
final class FlatSplitView: NSSplitView {
    override var dividerColor: NSColor { Tok.Line.border.nsColor }
    override var dividerThickness: CGFloat { 1 }
}
