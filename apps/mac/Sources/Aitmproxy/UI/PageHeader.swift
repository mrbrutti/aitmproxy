import SwiftUI

/// The dashboard-tier page header: a small-caps tracked title on the left and an
/// optional trailing control, on one band. One component so these headers share a
/// left margin (`Space.margin`), band height (`Tok.Size.filterBar`) and title style
/// instead of each panel re-deriving them (Wave 15). Document/entity pages (CA,
/// Config, Finding detail) keep their own prominent 20pt title by design.
struct PageHeader<Trailing: View>: View {
    private let title: String
    @ViewBuilder private let trailing: () -> Trailing

    init(_ title: String, @ViewBuilder trailing: @escaping () -> Trailing = { EmptyView() }) {
        self.title = title
        self.trailing = trailing
    }

    var body: some View {
        HStack(spacing: Space.md) {
            TrackedLabel(title).accessibilityAddTraits(.isHeader)
            Spacer(minLength: Space.sm)
            trailing()
        }
        .padding(.horizontal, Space.margin)
        .frame(height: Tok.Size.filterBar)
    }
}
