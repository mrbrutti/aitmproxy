import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// The poll loop's re-fetch decisions: never-seen, parked, headless, stale and
/// still-streaming flows are asked about again; finished ones are not; the wait on a
/// streaming body is bounded; an older core's size-less flows are never re-fetched
/// for their sizes.
@Suite struct FlowRefetchPolicyTests {
    private let id = FlowID("11111111-1111-4111-8111-111111111111")
    private let other = FlowID("22222222-2222-4222-8222-222222222222")

    private func http(status: Int? = 200, intercept: InterceptLabel = .observed, request: Int64? = 0,
                      response: Int64? = 1_024, reportsSizes: Bool = true) -> FlowSummary {
        FlowSummary(
            id: id, kind: .http, intercept: intercept, isReplay: false, method: "GET", scheme: "https",
            authority: "h", path: "/", status: status, requestBytes: request, responseBytes: response,
            reportsBodySizes: reportsSizes)
    }

    @Test func neverSeenIsFetched() {
        var policy = FlowRefetchPolicy()
        #expect(policy.shouldFetch(id, cached: nil) == true)
    }

    @Test func finishedFlowIsLeftAlone() {
        var policy = FlowRefetchPolicy()
        #expect(policy.shouldFetch(id, cached: http()) == false)
        #expect(policy.shouldFetch(id, cached: http()) == false)
    }

    @Test func parkedAndHeadlessFlowsAreFetchedEveryPoll() {
        var policy = FlowRefetchPolicy()
        for _ in 0..<3 {
            #expect(policy.shouldFetch(id, cached: http(intercept: .intercepted)) == true)
            #expect(policy.shouldFetch(id, cached: http(status: nil, response: nil)) == true)
        }
    }

    @Test func streamingBodyIsFetchedUntilTheLimitThenLeftAlone() {
        var policy = FlowRefetchPolicy(bodySizePollLimit: 3)
        let streaming = http(response: nil)
        #expect(streaming.awaitsBodySize)
        #expect(policy.shouldFetch(id, cached: streaming) == true)
        policy.didFetch(id, summary: streaming)
        #expect(policy.shouldFetch(id, cached: streaming) == true)
        policy.didFetch(id, summary: streaming)
        #expect(policy.shouldFetch(id, cached: streaming) == true)
        policy.didFetch(id, summary: streaming)
        // Fourth poll: the upstream probably abandoned it; stop asking.
        #expect(policy.shouldFetch(id, cached: streaming) == false)
        #expect(policy.shouldFetch(id, cached: streaming) == false)
        // Another flow's wait is its own.
        #expect(policy.shouldFetch(other, cached: nil) == true)
    }

    @Test func landedSizeEndsTheWaitAndClearsTheCount() {
        var policy = FlowRefetchPolicy(bodySizePollLimit: 2)
        let streaming = http(response: nil)
        #expect(policy.shouldFetch(id, cached: streaming) == true)
        policy.didFetch(id, summary: http(response: 4_096))
        #expect(policy.shouldFetch(id, cached: http(response: 4_096)) == false)
        // Were it to stream again (a replay reusing the id), the budget is whole.
        #expect(policy.shouldFetch(id, cached: streaming) == true)
        #expect(policy.shouldFetch(id, cached: streaming) == true)
        #expect(policy.shouldFetch(id, cached: streaming) == false)
    }

    @Test func olderCoreWithoutSizesIsNeverRefetchedForThem() {
        var policy = FlowRefetchPolicy()
        let legacy = http(request: nil, response: nil, reportsSizes: false)
        #expect(!legacy.awaitsBodySize)
        #expect(policy.shouldFetch(id, cached: legacy) == false)
    }

    @Test func staleFlowIsFetchedOnceThenSettles() {
        var policy = FlowRefetchPolicy()
        let done = http()
        #expect(policy.shouldFetch(id, cached: done) == false)
        policy.markStale(id)
        #expect(policy.shouldFetch(id, cached: done) == true)
        policy.didFetch(id, summary: done)
        #expect(policy.shouldFetch(id, cached: done) == false)
    }

    @Test func retainDropsFlowsTheCoreNoLongerLists() {
        var policy = FlowRefetchPolicy(bodySizePollLimit: 1)
        policy.markStale(id)
        let streaming = http(response: nil)
        #expect(policy.shouldFetch(other, cached: streaming) == true)  // spends other's one poll
        policy.retain([])
        // The stale mark is gone, and other's budget is fresh again.
        #expect(policy.shouldFetch(id, cached: http()) == false)
        #expect(policy.shouldFetch(other, cached: streaming) == true)
    }

    @Test func resetForgetsEverything() {
        var policy = FlowRefetchPolicy(bodySizePollLimit: 1)
        policy.markStale(id)
        _ = policy.shouldFetch(other, cached: http(response: nil))
        policy.reset()
        #expect(policy.shouldFetch(id, cached: http()) == false)
        #expect(policy.shouldFetch(other, cached: http(response: nil)) == true)
    }
}
