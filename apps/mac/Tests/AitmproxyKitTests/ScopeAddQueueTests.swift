import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// S-081: an add typed while the core is away is queued and replayed; one the core
/// refused is failed and waits for Retry; a listed host leaves the queue.
@Suite struct ScopeAddQueueTests {
    @Test func aBusThatIsNotThereQueuesTheAddForReplay() {
        var queue = ScopeAddQueue()
        queue.begin("api.shop-staging.test")
        #expect(queue.state(of: "api.shop-staging.test") == .sending)
        queue.fail("api.shop-staging.test", error: .disconnected)
        #expect(queue.state(of: "api.shop-staging.test") == .queued("the bus connection closed"))
        #expect(queue.replayable == ["api.shop-staging.test"])
        #expect(ScopeAddQueue.label(for: queue.state(of: "api.shop-staging.test")!) == "queued — added when the core is back")
    }

    @Test func aCoreRefusalFailsTheAddAndIsNotReplayed() {
        var queue = ScopeAddQueue()
        queue.begin("bad host")
        queue.fail("bad host", error: .tool(message: "scope entry must be a host, host:port or *.wildcard"))
        #expect(queue.state(of: "bad host") == .failed("scope entry must be a host, host:port or *.wildcard"))
        #expect(queue.replayable.isEmpty)
        #expect(ScopeAddQueue.label(for: queue.state(of: "bad host")!) == "not added — scope entry must be a host, host:port or *.wildcard")
        // Retry sends it again.
        queue.begin("bad host")
        #expect(queue.state(of: "bad host") == .sending)
        #expect(queue.hosts == ["bad host"])
    }

    @Test func onlyTheBusAbsenceIsRetryable() {
        #expect(ScopeAddQueue.isRetryable(.disconnected))
        #expect(ScopeAddQueue.isRetryable(.transport("connection refused")))
        #expect(ScopeAddQueue.isRetryable(.timeout))
        #expect(!ScopeAddQueue.isRetryable(.tool(message: "no")))
        #expect(!ScopeAddQueue.isRetryable(.rpc(code: -32602, message: "bad args")))
        #expect(!ScopeAddQueue.isRetryable(.unauthorized))
        #expect(!ScopeAddQueue.isRetryable(.malformed("x")))
    }

    @Test func aListedHostLeavesTheQueueAndTheRestStay() {
        var queue = ScopeAddQueue()
        queue.begin("a.test")
        queue.begin("b.test")
        queue.fail("b.test", error: .disconnected)
        queue.confirm(listed: ["a.test", "other.test"])
        #expect(queue.hosts == ["b.test"])
        queue.drop("b.test")
        #expect(queue.isEmpty)
    }
}
