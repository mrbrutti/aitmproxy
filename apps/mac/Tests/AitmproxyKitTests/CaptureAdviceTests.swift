import Testing

@testable import AitmproxyKit

/// `CaptureAdvice` is the honest capture sentence for the operator surfaces; the
/// case it exists for is capture ON with an EMPTY scope, which captures nothing.
struct CaptureAdviceTests {
    private let everyCapability: [CaptureCapability] = [
        .extensionNotInstalled, .pendingApproval, .approvedAttached, .capturing, .degraded("boom"), .inactive,
    ]

    @Test func aBuildWithoutTheExtensionIsUnsupportedWhateverTheState() {
        for capability in everyCapability {
            for hosts in [0, 1, 3] {
                #expect(CaptureAdvice.make(capability: capability, supported: false, scopeHostCount: hosts) == .unsupported)
            }
        }
    }

    @Test func captureOnWithAnEmptyScopeIsTheTrapNotCapturing() {
        #expect(CaptureAdvice.make(capability: .capturing, supported: true, scopeHostCount: 0) == .onEmptyScope)
        #expect(CaptureAdvice.make(capability: .approvedAttached, supported: true, scopeHostCount: 0) == .onEmptyScope)
        #expect(CaptureAdvice.onEmptyScope.offersScope)
        #expect(CaptureAdvice.onEmptyScope.headline == "Capture is on, but the scope is empty")
    }

    @Test func captureOnWithHostsInScopeIsCapturing() {
        #expect(CaptureAdvice.make(capability: .capturing, supported: true, scopeHostCount: 1) == .on(hosts: 1))
        #expect(CaptureAdvice.make(capability: .approvedAttached, supported: true, scopeHostCount: 4) == .on(hosts: 4))
        #expect(CaptureAdvice.on(hosts: 1).detail == "1 host is in scope. Flows appear here as it is contacted.")
        #expect(CaptureAdvice.on(hosts: 4).detail.hasPrefix("4 hosts are in scope."))
        #expect(!CaptureAdvice.on(hosts: 4).offersScope)
    }

    @Test func offStatesPointAtSettings() {
        for capability in [CaptureCapability.extensionNotInstalled, .inactive] {
            let advice = CaptureAdvice.make(capability: capability, supported: true, scopeHostCount: 2)
            #expect(advice == .off)
            #expect(advice.offersSettings)
            #expect(!advice.offersScope)
        }
    }

    @Test func pendingAndDegradedCarryTheirOwnWords() {
        #expect(CaptureAdvice.make(capability: .pendingApproval, supported: true, scopeHostCount: 0) == .awaitingApproval)
        let degraded = CaptureAdvice.make(capability: .degraded("tunnel failed"), supported: true, scopeHostCount: 5)
        #expect(degraded == .degraded("tunnel failed"))
        #expect(degraded.detail == "tunnel failed")
    }

    @Test func theBannerNamesTheStateAndTheOneActionOnOneLine() {
        #expect(CaptureAdvice.onEmptyScope.banner.contains("scope is empty"))
        #expect(CaptureAdvice.on(hosts: 1).banner.hasPrefix("Capturing 1 host "))
        #expect(CaptureAdvice.on(hosts: 3).banner.hasPrefix("Capturing 3 hosts "))
        #expect(CaptureAdvice.unsupported.banner.contains("capture extension"))
        #expect(CaptureAdvice.degraded("tunnel failed").banner.hasSuffix("tunnel failed"))
        let all: [CaptureAdvice] = [.unsupported, .off, .awaitingApproval, .degraded("x"), .onEmptyScope, .on(hosts: 2)]
        for advice in all {
            #expect(!advice.banner.isEmpty)
            #expect(!advice.banner.contains("\n"))
        }
    }

    @Test func everyAdviceHasAHeadlineAndADetail() {
        let all: [CaptureAdvice] = [.unsupported, .off, .awaitingApproval, .degraded("x"), .onEmptyScope, .on(hosts: 2)]
        for advice in all {
            #expect(!advice.headline.isEmpty)
            #expect(!advice.detail.isEmpty)
        }
        // Only the empty-scope trap offers Scope; only off offers Settings.
        #expect(all.filter(\.offersScope) == [.onEmptyScope])
        #expect(all.filter(\.offersSettings) == [.off])
    }
}
