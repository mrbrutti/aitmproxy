import Testing

@testable import AitmproxyKit

/// `CaptureAdvice` is the honest capture sentence for the operator surfaces; the
/// case it exists for is capture ON with an EMPTY scope, which captures nothing.
struct CaptureAdviceTests {
    private let everyCapability: [CaptureCapability] = [
        .extensionNotInstalled, .pendingApproval, .approvedAttached, .capturing, .degraded("boom"), .inactive,
    ]
    private let everyAdvice: [CaptureAdvice] = [.unsupported, .off, .awaitingApproval, .degraded("x"), .onEmptyScope, .on(hosts: 2)]

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

    @Test func onlyAConnectedTunnelMayReadCapturingAnywhere() {
        // `.approvedAttached` also maps to `.on`, and its tunnel may still be connecting, so the
        // advice says "on"; the capability's own title is the one place that says "Capturing".
        for advice in [CaptureAdvice.on(hosts: 1), .on(hosts: 3), .onEmptyScope, .off, .awaitingApproval, .unsupported, .degraded("x")] {
            #expect(!advice.headline.hasPrefix("Capturing"))
            #expect(!advice.banner.hasPrefix("Capturing"))
        }
    }

    @Test func captureOnWithHostsInScopeIsCapturing() {
        #expect(CaptureAdvice.make(capability: .capturing, supported: true, scopeHostCount: 1) == .on(hosts: 1))
        #expect(CaptureAdvice.make(capability: .approvedAttached, supported: true, scopeHostCount: 4) == .on(hosts: 4))
        #expect(CaptureAdvice.on(hosts: 1).detail == "1 host is in scope. Flows appear here as that host is contacted.")
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
        #expect(CaptureAdvice.awaitingApproval.detail.contains("System Settings"))
        #expect(CaptureAdvice.awaitingApproval.banner.contains("approve the extension"))
        let degraded = CaptureAdvice.make(capability: .degraded("tunnel failed"), supported: true, scopeHostCount: 5)
        #expect(degraded == .degraded("tunnel failed"))
        #expect(degraded.detail == "tunnel failed")
    }

    @Test func offAndEmptyScopeAtZeroHostsAreNotTheTrap() {
        for capability in [CaptureCapability.extensionNotInstalled, .inactive] {
            #expect(CaptureAdvice.make(capability: capability, supported: true, scopeHostCount: 0) == .off)
        }
        #expect(CaptureAdvice.make(capability: .degraded("d"), supported: true, scopeHostCount: 0) == .degraded("d"))
        #expect(CaptureAdvice.make(capability: .capturing, supported: true, scopeHostCount: -1) == .onEmptyScope)
    }

    @Test func theBannerNamesTheStateAndTheOneActionOnOneLine() {
        #expect(CaptureAdvice.onEmptyScope.banner.contains("scope is empty"))
        #expect(CaptureAdvice.on(hosts: 1).banner.hasPrefix("Capture is on, 1 host in scope"))
        #expect(CaptureAdvice.on(hosts: 3).banner.hasPrefix("Capture is on, 3 hosts in scope"))
        #expect(CaptureAdvice.unsupported.banner.contains("no source app"))
        #expect(CaptureAdvice.degraded("tunnel failed").banner.hasSuffix("tunnel failed"))
        for advice in everyAdvice {
            #expect(!advice.banner.isEmpty)
            #expect(!advice.banner.contains("\n"))
        }
        // Nothing may promise app attribution: no flow carries its source app on the wire yet.
        for advice in everyAdvice {
            #expect(!advice.banner.lowercased().contains("attribute"))
            #expect(!advice.detail.lowercased().contains("attribute"))
        }
    }

    @Test func everyAdviceHasAHeadlineAndADetail() {
        let all = everyAdvice
        for advice in all {
            #expect(!advice.headline.isEmpty)
            #expect(!advice.detail.isEmpty)
        }
        // Only the empty-scope trap offers Scope; only off offers Settings.
        #expect(all.filter(\.offersScope) == [.onEmptyScope])
        #expect(all.filter(\.offersSettings) == [.off])
    }
}

// MARK: - Tester (stage 5): exhaustive table and copy contract
//
// The Coder's tests above prove the headline cases. These close the gaps a default-returning or
// partly-wrong `make` would slip through: every `CaptureCapability` case with an empty and a
// non-empty scope as spelled-out literals (not re-derived from the implementation), a property
// cross-check against the independent `CaptureCapability.isCaptureOn`, distinct copy per state,
// the trap never reading as working capture, and the "extension missing" wording confined to
// `.unsupported` (NS-AC1, NS-AC3).

/// One witness per `CaptureCapability` case, built by a switch with no `default`: adding a case to
/// `CaptureCapability` stops this file compiling until a witness exists, and the coverage test then
/// fails until the table below covers it.
private enum CapabilityKind: CaseIterable {
    case extensionNotInstalled, pendingApproval, approvedAttached, capturing, degraded, inactive

    init(_ capability: CaptureCapability) {
        switch capability {
        case .extensionNotInstalled: self = .extensionNotInstalled
        case .pendingApproval: self = .pendingApproval
        case .approvedAttached: self = .approvedAttached
        case .capturing: self = .capturing
        case .degraded: self = .degraded
        case .inactive: self = .inactive
        }
    }
}

/// The same guard for `CaptureAdvice`: a new advice case must join `everyAdvice` below.
private enum AdviceKind: CaseIterable {
    case unsupported, off, awaitingApproval, degraded, onEmptyScope, on

    init(_ advice: CaptureAdvice) {
        switch advice {
        case .unsupported: self = .unsupported
        case .off: self = .off
        case .awaitingApproval: self = .awaitingApproval
        case .degraded: self = .degraded
        case .onEmptyScope: self = .onEmptyScope
        case .on: self = .on
        }
    }
}

struct CaptureAdviceExhaustiveTests {
    private let everyCapability: [CaptureCapability] = [
        .extensionNotInstalled, .pendingApproval, .approvedAttached, .capturing, .degraded("boom"), .inactive,
    ]

    private let everyAdvice: [CaptureAdvice] = [
        .unsupported, .off, .awaitingApproval, .degraded("x"), .onEmptyScope, .on(hosts: 2),
    ]

    /// A build that embeds the extension: every capability x {0, 1, 7} hosts, as literals.
    private let supportedTable: [(capability: CaptureCapability, hosts: Int, expected: CaptureAdvice)] = [
        (.extensionNotInstalled, 0, .off), (.extensionNotInstalled, 1, .off), (.extensionNotInstalled, 7, .off),
        (.pendingApproval, 0, .awaitingApproval), (.pendingApproval, 1, .awaitingApproval),
        (.pendingApproval, 7, .awaitingApproval),
        (.approvedAttached, 0, .onEmptyScope), (.approvedAttached, 1, .on(hosts: 1)),
        (.approvedAttached, 7, .on(hosts: 7)),
        (.capturing, 0, .onEmptyScope), (.capturing, 1, .on(hosts: 1)), (.capturing, 7, .on(hosts: 7)),
        (.degraded("boom"), 0, .degraded("boom")), (.degraded("boom"), 1, .degraded("boom")),
        (.degraded("boom"), 7, .degraded("boom")),
        (.inactive, 0, .off), (.inactive, 1, .off), (.inactive, 7, .off),
    ]

    // MARK: NS-AC1 coverage of the mapping

    @Test func theTableAndTheListsCoverEveryCapabilityAndEveryAdviceCase() {
        #expect(Set(everyCapability.map { CapabilityKind($0) }) == Set(CapabilityKind.allCases))
        #expect(Set(everyAdvice.map { AdviceKind($0) }) == Set(AdviceKind.allCases))
        var seenEmpty = Set<CapabilityKind>()
        var seenNonEmpty = Set<CapabilityKind>()
        for row in supportedTable {
            if row.hosts == 0 {
                seenEmpty.insert(CapabilityKind(row.capability))
            } else {
                seenNonEmpty.insert(CapabilityKind(row.capability))
            }
        }
        #expect(seenEmpty == Set(CapabilityKind.allCases), "every capability needs a row with an empty scope")
        #expect(seenNonEmpty == Set(CapabilityKind.allCases), "every capability needs a row with hosts in scope")
    }

    @Test func everyCapabilityAndScopeSizeMapsToTheDesignedAdviceForASupportedBuild() {
        for row in supportedTable {
            let advice = CaptureAdvice.make(capability: row.capability, supported: true, scopeHostCount: row.hosts)
            #expect(advice == row.expected, "\(row.capability) with \(row.hosts) host(s)")
        }
    }

    @Test func aBuildWithoutTheExtensionIsUnsupportedForEveryRowOfTheTable() {
        for row in supportedTable {
            let advice = CaptureAdvice.make(capability: row.capability, supported: false, scopeHostCount: row.hosts)
            #expect(advice == .unsupported, "\(row.capability) with \(row.hosts) host(s)")
        }
    }

    @Test func onEmptyScopeIffSupportedAndCaptureOnAndNoHostsAcrossTheWholeInputSpace() {
        // The oracle is `CaptureCapability.isCaptureOn`, which `CaptureAdvice` does not call.
        for supported in [true, false] {
            for capability in everyCapability {
                for hosts in [-1, 0, 1, 2, 100] {
                    let advice = CaptureAdvice.make(capability: capability, supported: supported, scopeHostCount: hosts)
                    let captureOn = supported && capability.isCaptureOn
                    let trap = captureOn && hosts <= 0
                    let label = "\(capability) supported=\(supported) hosts=\(hosts)"
                    #expect((advice == .onEmptyScope) == trap, "\(label)")
                    #expect(advice.offersScope == trap, "\(label)")
                    let offStates = capability == .extensionNotInstalled || capability == .inactive
                    #expect(advice.offersSettings == (supported && offStates), "\(label)")
                    if case .on(let counted) = advice {
                        #expect(captureOn && hosts > 0 && counted == hosts, "\(label)")
                    } else {
                        #expect(!(captureOn && hosts > 0), "\(label)")
                    }
                }
            }
        }
    }

    @Test func aNegativeScopeCountIsEmptyNotHosts() {
        #expect(CaptureAdvice.make(capability: .capturing, supported: true, scopeHostCount: -1) == .onEmptyScope)
        #expect(CaptureAdvice.make(capability: .approvedAttached, supported: true, scopeHostCount: Int.min) == .onEmptyScope)
    }

    @Test func aHugeScopeCountStillFormatsOnOneLine() {
        let advice = CaptureAdvice.make(capability: .capturing, supported: true, scopeHostCount: Int.max)
        #expect(advice == .on(hosts: Int.max))
        #expect(advice.banner.hasPrefix("Capture is on, \(Int.max) hosts in scope "))
        #expect(!advice.banner.contains("\n"))
    }

    @Test func adviceValuesCompareByTheirPayload() {
        #expect(CaptureAdvice.on(hosts: 1) != CaptureAdvice.on(hosts: 2))
        #expect(CaptureAdvice.degraded("a") != CaptureAdvice.degraded("b"))
        #expect(CaptureAdvice.degraded("a").banner != CaptureAdvice.degraded("b").banner)
        #expect(CaptureAdvice.degraded("a").detail != CaptureAdvice.degraded("b").detail)
    }

    // MARK: the copy

    @Test func noTwoAdvicesShareAHeadlineABannerOrADetail() {
        #expect(Set(everyAdvice.map(\.headline)).count == everyAdvice.count)
        #expect(Set(everyAdvice.map(\.banner)).count == everyAdvice.count)
        #expect(Set(everyAdvice.map(\.detail)).count == everyAdvice.count)
    }

    @Test func theSixHeadlinesAreExactlyAsDesigned() {
        #expect(CaptureAdvice.unsupported.headline == "No app attribution yet")
        #expect(CaptureAdvice.off.headline == "Capture is off")
        #expect(CaptureAdvice.awaitingApproval.headline == "Waiting for approval")
        #expect(CaptureAdvice.degraded("x").headline == "Capture is degraded")
        #expect(CaptureAdvice.onEmptyScope.headline == "Capture is on, but the scope is empty")
        #expect(CaptureAdvice.on(hosts: 3).headline == "Capture is on")
    }

    @Test func everyBannerIsOneNonEmptyLineForEveryAdvice() {
        // The Apps banner is a fixed-height one-line row: a newline or an empty banner breaks it.
        for advice in everyAdvice + [CaptureAdvice.on(hosts: 1), .on(hosts: 50)] {
            #expect(!advice.banner.isEmpty, "\(advice)")
            #expect(!advice.banner.contains("\n"), "\(advice)")
            #expect(!advice.banner.hasSuffix(" "), "\(advice)")
        }
    }

    @Test func theEmptyScopeTrapNeverReadsAsWorkingCapture() {
        let trap = CaptureAdvice.onEmptyScope
        let working = CaptureAdvice.on(hosts: 1)
        #expect(trap.headline != working.headline)
        #expect(trap.banner != working.banner)
        #expect(trap.detail != working.detail)
        // The published capability title is the word the old Settings status showed for this state.
        #expect(trap.headline != CaptureCapability.capturing.title)
        #expect(trap.headline.hasPrefix("Capture is on"))
        #expect(trap.headline.contains("scope is empty"))
        for text in [trap.headline, trap.banner, trap.detail] {
            #expect(!text.lowercased().contains("capturing"), "\(text)")
        }
        // The two lines an operator reads first name the cause: the scope.
        for text in [trap.headline, trap.banner] {
            #expect(text.lowercased().contains("scope"), "\(text)")
        }
        for text in [working.headline, working.banner, working.detail] {
            #expect(!text.lowercased().contains("empty"), "\(text)")
            // `.approvedAttached` reaches `.on` with its tunnel possibly still connecting, so no word of it may say "Capturing".
            #expect(!text.contains("Capturing"), "\(text)")
        }

    }

    @Test func theSettingsCalloutReadsAsOneCleanParagraph() {
        // Settings renders "\(headline). \(detail)": no headline may carry its own full stop or newline.
        for advice in everyAdvice {
            #expect(!advice.headline.hasSuffix("."), "\(advice.headline)")
            #expect(!advice.headline.contains("\n"), "\(advice.headline)")
        }
        let trap = CaptureAdvice.onEmptyScope
        let callout = "\(trap.headline). \(trap.detail)"
        #expect(callout.hasPrefix("Capture is on, but the scope is empty. "))
        #expect(callout.hasSuffix("."))
        #expect(!callout.contains(".."))
        #expect(!callout.contains("\n"))

    }

    @Test func theExtensionMissingWordingBelongsToUnsupportedOnly() {
        #expect(CaptureAdvice.unsupported.headline == "No app attribution yet")
        #expect(CaptureAdvice.unsupported.detail.contains("no capture extension"))
        let others: [CaptureAdvice] = [.off, .awaitingApproval, .onEmptyScope, .on(hosts: 1), .on(hosts: 5)]
        for advice in others {
            for text in [advice.headline, advice.banner, advice.detail] {
                let lower = text.lowercased()
                #expect(!lower.contains("no capture extension"), "\(text)")
                #expect(!lower.contains("no app attribution"), "\(text)")
                #expect(!lower.contains("not installed"), "\(text)")
                #expect(!lower.contains("missing"), "\(text)")
                #expect(!lower.contains("needs the"), "\(text)")
            }
        }

    }

    @Test func theCopyNamesTheDestinationOfTheActionTheSurfaceOffers() {
        for advice in everyAdvice {
            if advice.offersScope {
                #expect(advice.headline.lowercased().contains("scope"), "\(advice.headline)")
                #expect(advice.banner.lowercased().contains("scope"), "\(advice.banner)")
            }
            if advice.offersSettings {
                #expect(advice.banner.contains("Settings"), "\(advice.banner)")
                #expect(advice.detail.contains("Settings"), "\(advice.detail)")
            }
        }

    }

    @Test func hostCountIsPluralisedInTheBannerAndTheDetail() {
        #expect(CaptureAdvice.on(hosts: 1).banner.hasPrefix("Capture is on, 1 host in scope \u{2014}"))
        #expect(CaptureAdvice.on(hosts: 2).banner.hasPrefix("Capture is on, 2 hosts in scope \u{2014}"))
        #expect(!CaptureAdvice.on(hosts: 1).banner.contains("1 hosts"))
        #expect(CaptureAdvice.on(hosts: 2).detail.hasPrefix("2 hosts are in scope."))
    }
}
