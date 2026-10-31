import AitmproxyKit
import SwiftUI

/// The content-type quick filter (foundation §2.7). One chip active (raised
/// fill, 500 weight); the rest plain secondary. `⌘1…9` select.
struct ChipBar: View {
    @Binding var selected: ContentCategory
    var filterActive = false
    var onFilters: () -> Void = {}

    var body: some View {
        HStack(spacing: 2) {
            // Chips never truncate; the row scrolls when the pane is narrow (split view).
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    ForEach(Array(ContentCategory.groups.enumerated()), id: \.offset) { index, group in
                        if index > 0 {
                            Rectangle().fill(Tok.Line.border.color).frame(width: 1, height: Tok.Metric.chipSeparator).padding(.horizontal, Tok.Metric.gapTight)
                        }
                        ForEach(group) { chip in
                            Chip(title: chip.title, on: selected == chip, help: chip.help) { selected = chip }
                                .fixedSize()
                        }
                    }
                }
            }
            Spacer(minLength: Space.sm)
            Button(action: onFilters) {
                HStack(spacing: 2) {
                    Text("Filters")
                    Image(systemName: filterActive ? "chevron.up" : "chevron.down").font(.system(size: 9, weight: .medium))
                }
                .font(Tok.Face.ui(Tok.Typography.Size.sm, filterActive ? .medium : .regular))
                .foregroundStyle(filterActive ? Tok.Ink.primary.color : Tok.Ink.tertiary.color)
                .padding(.horizontal, Space.sm)
                .frame(height: Tok.Metric.chip)
            }
            .buttonStyle(.plain)
            .help(filterActive ? "Hide the filter bar (⌘F)" : "Show the filter bar (⌘F)")
        }
        .padding(.horizontal, Tok.Metric.padInner)
        .frame(height: Tok.Size.filterBar)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .bottom) { Rule() }
        .dimsWhenInactive()
    }
}

struct Chip: View {
    var title: String
    var on: Bool
    /// What the chip keeps (`ContentCategory.help`); empty shows no tooltip.
    var help = ""
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(Tok.Face.ui(Tok.Typography.Size.sm, on ? .medium : .regular))
                .foregroundStyle(on ? Tok.Ink.primary.color : Tok.Ink.secondary.color)
                .padding(.horizontal, Space.sm)
                .frame(height: Tok.Metric.chip)
                .background(on ? Tok.Ground.raised.color : .clear, in: Capsule())
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityAddTraits(on ? .isSelected : [])
    }
}
