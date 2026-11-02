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
        #expect(queue.state(of: "api.shop-staging.test") == .queued)
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
        // An RPC-level refusal is the core's answer too: failed with its message, not replayed.
        queue.fail("bad host", error: .rpc(code: -32602, message: "bad args"))
        #expect(queue.state(of: "bad host") == .failed(BusError.rpc(code: -32602, message: "bad args").description))
        #expect(queue.replayable.isEmpty)
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

    @Test func replayBeginsAQueuedHostAgainWithoutDuplicatingIt() {
        var queue = ScopeAddQueue()
        queue.begin("later.test")
        queue.fail("later.test", error: .disconnected)
        #expect(queue.replayable == ["later.test"])
        queue.begin("later.test")
        #expect(queue.state(of: "later.test") == .sending)
        #expect(queue.hosts == ["later.test"])
        #expect(queue.replayable.isEmpty)
    }

    @Test func unknownHostsAreNoOpsAndANonBusErrorFails() {
        var queue = ScopeAddQueue()
        queue.begin("one.test")
        queue.drop("nope.test")
        queue.fail("nope.test", error: .disconnected)
        #expect(queue.hosts == ["one.test"])
        // ✕ on a sending row, then the send fails: nothing comes back.
        queue.drop("one.test")
        queue.fail("one.test", error: .tool(message: "late"))
        #expect(queue.isEmpty)
        // An error that is not the bus's (decoding, a thrown String) is a refusal, not a replay.
        queue.begin("odd.test")
        queue.fail("odd.test", reason: "unexpected reply", retryable: false)
        #expect(queue.state(of: "odd.test") == .failed("unexpected reply"))
        #expect(queue.replayable.isEmpty)
    }
}
