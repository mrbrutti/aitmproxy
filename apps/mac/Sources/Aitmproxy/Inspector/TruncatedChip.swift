import AitmproxyKit
import SwiftUI

/// `truncated · 2.0 of 18.4 MB`: a raised chip for the tab bar's trailing
/// slot while a body is paged (S-027). A status, not a control.
struct TruncatedChip: View {
    var extent: BodyExtent

    var body: some View {
        Text(extent.chipText)
            .font(Tok.Face.ui(Tok.Typography.Size.xs))
            .foregroundStyle(Tok.Ink.secondary.color)
            .lineLimit(1)
            .padding(.horizontal, Tok.Metric.gapTight)
            .frame(height: Tok.Metric.countChip)
            .background(Tok.Ground.raised.color, in: Capsule())
            .fixedSize()
            .accessibilityLabel("Body truncated")
            .accessibilityValue("\(Format.bytes(extent.loaded)) of \(Format.bytes(extent.total)) loaded")
    }
}

/// Where paging stands: idle, fetching the next range, or failed with the
/// time of the last range that landed (foundation §2.8 "last good").
@Observable
final class PagingState {
    enum Phase: Equatable { case idle, loading, failed }

    var phase: Phase = .idle
    /// When the body last grew (or first appeared).
    var lastGood: Date?
    var errorText: String?

    init(lastGood: Date? = nil) {
        self.lastGood = lastGood
    }

    /// Runs one fetch; marks the result. A second call while loading is ignored.
    func load(_ fetch: () async throws -> Void) async {
        guard phase != .loading else { return }
        phase = .loading
        errorText = nil
        do {
            try await fetch()
            lastGood = .now
            phase = .idle
        } catch {
            errorText = error.localizedDescription
            phase = .failed
        }
    }
}

/// The strip under a paged body: "Load more", a plain "Loading…", or
/// "Unable to load the next 2 MB · Retry" with the last good time.
struct LoadMoreFooter: View {
    var state: PagingState
    var extent: BodyExtent
    var onLoadMore: (() async throws -> Void)?

    init(state: PagingState, extent: BodyExtent, onLoadMore: (() async throws -> Void)?) {
        self.state = state
        self.extent = extent
        self.onLoadMore = onLoadMore
    }

    /// The next range is as big as the first page, or whatever is left.
    private var nextBytes: Int64 { min(max(extent.loaded, 1), extent.total - extent.loaded) }

    var body: some View {
        HStack(spacing: Tok.Metric.padInner) {
            switch state.phase {
            case .idle:
                SmallButton("Load more") { fetch() }
                    .disabled(onLoadMore == nil)
                    .accessibilityHint("Fetches the next \(Format.bytes(nextBytes)) of the body")
                Text("\(Format.bytes(extent.loaded)) of \(Format.bytes(extent.total)) loaded")
                    .foregroundStyle(Tok.Ink.tertiary.color)
            case .loading:
                Text("Loading…").foregroundStyle(Tok.Ink.tertiary.color)
            case .failed:
                Text("Unable to load the next \(Format.bytes(nextBytes))")
                    .foregroundStyle(Tok.Ink.secondary.color)
                SmallButton("Retry") { fetch() }
                if let lastGood = state.lastGood {
                    Text("last good \(Format.time(lastGood))").foregroundStyle(Tok.Ink.tertiary.color)
                }
            }
            Spacer(minLength: 0)
        }
        .font(Tok.Face.ui(Tok.Typography.Size.sm))
        .lineLimit(1)
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.control)
        .overlay(alignment: .top) { Rule(color: Tok.Line.rule) }
        .background(Tok.Ground.surface.color)
    }

    private func fetch() {
        guard let onLoadMore else { return }
        Task { await state.load(onLoadMore) }
    }
}
