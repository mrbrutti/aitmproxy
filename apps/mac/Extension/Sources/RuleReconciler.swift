import Foundation

// MARK: - Rule reconciler (spec 2026-11-01-ne-tcp-only-catch-all-design, Design B, C)
//
// The bookkeeping behind the provider's in-place `setTunnelNetworkSettings` re-apply:
// which `ProviderRuleSet` is installed, which one is wanted, whether an apply is in
// flight. It coalesces: at most one apply in flight plus one pending set, so a burst of
// Scope pushes applies at most the LAST distinct set, and nothing is applied while the
// wanted set equals the installed one (a core restart with no UDP target scoped applies
// nothing; with one scoped, exactly two applications: TCP-only, then TCP + UDP).
//
// The `apply` is injected so the self-check drives every transition with a fake; the
// provider's `apply` is the only place `NETransparentProxyNetworkSettings` is built.
// Nothing here is on the claim path: `CoreLink.current()` decides every flow, and
// detach is fail-open before any rule work begins (NE-AC5).
//
// Failure semantics (spec B): an error leaves `installed` as it was -- the kernel keeps
// the previous rules as far as we know -- and is reported once. The set that failed is
// NOT retried by itself (no timer, no loop); the next scope change tries again. A newer
// set that arrived during the failed flight is applied right away, like after a success.

/// Coalescing apply state. NOT thread-safe by itself: the owner calls every method, and
/// delivers every apply completion, on one serial queue (the provider's `rulesQueue`).
final class RuleReconciler {
    enum Event: Equatable {
        /// The apply completed without error; this set is now `installed`.
        case applied(ProviderRuleSet)
        /// The apply completed with an error; `kept` (the previous `installed`, nil when
        /// nothing had been installed yet) stays.
        case applyFailed(wanted: ProviderRuleSet, kept: ProviderRuleSet?, message: String)
    }

    /// Install `wanted`, with `reasserting` set around the call iff asked, and deliver the
    /// result ON THE OWNER'S QUEUE exactly once.
    typealias Apply = (_ wanted: ProviderRuleSet, _ reasserting: Bool,
                       _ completion: @escaping (Error?) -> Void) -> Void

    private let apply: Apply
    private let onEvent: (Event) -> Void

    /// The last set whose apply completed without error; nil before the startup apply
    /// lands and after `stop()`.
    private(set) var installed: ProviderRuleSet?
    private var pending: ProviderRuleSet = .tcpOnly
    private var inFlight = false
    /// Idle until `begin`; set again by `stop()`.
    private var stopped = true
    /// Bumped by `stop()`. An apply completion whose generation no longer matches belongs
    /// to a tunnel that is gone and is ignored entirely.
    private var generation: UInt64 = 0
    /// `begin` callers waiting for the next apply's result.
    private var startupCompletions: [(Error?) -> Void] = []

    init(apply: @escaping Apply, onEvent: @escaping (Event) -> Void) {
        self.apply = apply
        self.onEvent = onEvent
    }

    /// Startup (spec Design C): the wanted set is `.tcpOnly`, applied WITHOUT
    /// `reasserting` (the session is not Connected yet). `completion` receives that
    /// apply's result. A second `begin` without a `stop()` in between (Tahoe FB21464147,
    /// `startProxy` called twice) is answered by the apply in flight, or re-applies.
    func begin(completion: @escaping (Error?) -> Void) {
        stopped = false
        pending = .tcpOnly
        startupCompletions.append(completion)
        if inFlight { return }
        startApply(reasserting: false)
    }

    /// A scope transition (the `CoreLink.onScopeChange` hook). The wanted set becomes
    /// `ProviderRuleSet.wanted(for:)`; it is applied with `reasserting` iff it differs
    /// from the installed one and nothing is in flight, else it waits as the pending set.
    func reconcile(for scope: ScopeMatcher?) {
        pending = ProviderRuleSet.wanted(for: scope)
        applyIfNeeded(reasserting: true)
    }

    /// `stopProxy`: forget everything. A late `reconcile` (the hook the detach fires)
    /// applies nothing; an in-flight completion becomes stale and is ignored; a later
    /// `begin` starts over.
    func stop() {
        stopped = true
        installed = nil
        pending = .tcpOnly
        inFlight = false
        generation &+= 1
        startupCompletions.removeAll()
    }

    private func applyIfNeeded(reasserting: Bool) {
        guard !stopped, !inFlight, pending != installed else { return }
        startApply(reasserting: reasserting)
    }

    private func startApply(reasserting: Bool) {
        inFlight = true
        let wanted = pending
        let gen = generation
        apply(wanted, reasserting) { [weak self] error in
            guard let self, gen == self.generation, !self.stopped else { return }
            self.inFlight = false
            if let error {
                self.onEvent(.applyFailed(wanted: wanted, kept: self.installed,
                                          message: String(describing: error)))
            } else {
                self.installed = wanted
                self.onEvent(.applied(wanted))
            }
            let waiting = self.startupCompletions
            self.startupCompletions.removeAll()
            waiting.forEach { $0(error) }
            // Coalescing: the LAST pending set is applied now if it still differs from the
            // installed one. After a failure only a set that arrived DURING the flight is
            // tried; the set that just failed waits for the next scope change.
            if error == nil || self.pending != wanted {
                self.applyIfNeeded(reasserting: true)
            }
        }
    }
}

// MARK: - Self-checks (spec 2026-11-01-ne-tcp-only-catch-all-design, Design B, C; run by apps/mac/tools/ne-selfcheck.sh)

#if DEBUG
extension HandoffSelfCheck {
    /// The fake `apply` both reconciler groups drive: records `(wanted, reasserting)` per
    /// apply in `applied`, parks each completion in `completions` so the check delivers
    /// every result by hand, and collects each `onEvent` in `events`. It holds no
    /// reference to the reconciler it feeds, so there is no cycle.
    private final class FakeApply {
        private let r: Recorder
        private(set) var applied: [(ProviderRuleSet, Bool)] = []
        private(set) var completions: [(Error?) -> Void] = []
        private(set) var events: [RuleReconciler.Event] = []

        init(_ r: Recorder) { self.r = r }

        func makeReconciler() -> RuleReconciler {
            RuleReconciler(
                apply: { wanted, reasserting, completion in
                    self.applied.append((wanted, reasserting))
                    self.completions.append(completion)
                },
                onEvent: { self.events.append($0) })
        }

        /// `(summary, reasserting); …` for every apply so far (diagnostics).
        func trail() -> String {
            applied.map { "(\($0.0.summary), \($0.1))" }.joined(separator: "; ")
        }

        /// True iff `applied` has exactly `i + 1` entries and the last is `(set, reasserting)`.
        func lastApply(_ i: Int, _ set: ProviderRuleSet, _ reasserting: Bool) -> Bool {
            applied.count == i + 1 && applied[i] == (set, reasserting)
        }

        /// Deliver the `i`th parked completion with `error`. A completion that was never
        /// parked is a failure under `label`, never a silent skip.
        func complete(_ i: Int, _ error: Error?, _ label: String) {
            guard i < completions.count else {
                r.fail("FAIL \(label): completion \(i) was never parked (have \(completions.count))")
                return
            }
            completions[i](error)
        }
    }

    /// Design B/C of spec 2026-11-01-ne-tcp-only-catch-all-design, pinned against a fake
    /// `apply` that records `(wanted, reasserting)` and parks each completion so the check
    /// drives every transition by hand: startup applies `.tcpOnly` without `reasserting`;
    /// "no change" applies nothing; a change during a flight is coalesced to the LAST
    /// pending set and applied right after with `reasserting`; an apply error keeps
    /// `installed` and is retried only on the next scope change, never by itself;
    /// `stop()` resets the state, drops late reconciles and makes an in-flight completion
    /// stale; `begin` after `stop()` starts over (Tahoe double-`startProxy` tolerance).
    static func ruleReconciler(_ r: Recorder) {
        let fake = FakeApply(r)
        let reconciler = fake.makeReconciler()
        var startupResults: [Error?] = []

        let m1 = ScopeMatcher(spec: "example.com 198.51.100.7")
        let m2 = ScopeMatcher(spec: "198.51.100.7 203.0.113.9:4433")
        let w1 = ProviderRuleSet.wanted(for: m1)
        let w2 = ProviderRuleSet.wanted(for: m2)
        r.check("ruleReconciler: w1 has the one bare-IP target",
              w1.udpTargets == [ProviderRuleSet.UDPTarget("198.51.100.7", nil)], "\(w1.udpTargets)")
        r.check("ruleReconciler: w1 and w2 differ", w1 != w2)
        r.check("ruleReconciler: nothing installed before begin", reconciler.installed == nil)

        // 1. begin: one apply of .tcpOnly without reasserting; nothing installed yet; the
        //    startup completion waits for the apply's result.
        reconciler.begin { startupResults.append($0) }
        r.check("ruleReconciler: 1 begin applies once", fake.applied.count == 1, "\(fake.applied.count)")
        r.check("ruleReconciler: 1 begin applies (.tcpOnly, reasserting false)",
              fake.lastApply(0, .tcpOnly, false), fake.trail())
        r.check("ruleReconciler: 1 installed still nil during the startup apply", reconciler.installed == nil)
        r.check("ruleReconciler: 1 startup completion not called yet", startupResults.isEmpty, "\(startupResults.count)")

        // 2. The startup apply succeeds.
        fake.complete(0, nil, "ruleReconciler: 2")
        r.check("ruleReconciler: 2 installed == .tcpOnly", reconciler.installed == .tcpOnly,
              "\(String(describing: reconciler.installed?.summary))")
        r.check("ruleReconciler: 2 startup completion called once with nil",
              startupResults.count == 1 && startupResults[0] == nil,
              "\(startupResults.map { String(describing: $0) })")
        r.check("ruleReconciler: 2 events == [.applied(.tcpOnly)]", fake.events == [.applied(.tcpOnly)], "\(fake.events)")

        // 3. No change: nothing applied.
        reconciler.reconcile(for: nil)
        r.check("ruleReconciler: 3 reconcile(nil) with tcpOnly installed applies nothing",
              fake.applied.count == 1, "\(fake.applied.count)")

        // 4. A change: one apply with reasserting.
        reconciler.reconcile(for: m1)
        r.check("ruleReconciler: 4 reconcile(m1) applies", fake.applied.count == 2, "\(fake.applied.count)")
        r.check("ruleReconciler: 4 applied[1] == (w1, true)", fake.lastApply(1, w1, true), fake.trail())

        // 5. Changes during the flight are coalesced: nothing new is applied yet.
        reconciler.reconcile(for: m2)
        reconciler.reconcile(for: nil)
        r.check("ruleReconciler: 5 reconciles in flight apply nothing", fake.applied.count == 2, "\(fake.applied.count)")
        r.check("ruleReconciler: 5 installed unchanged in flight", reconciler.installed == .tcpOnly)

        // 6. The flight lands: installed = w1, then ONLY the last pending set (tcpOnly) is
        //    applied; m2 was coalesced away.
        fake.complete(1, nil, "ruleReconciler: 6")
        r.check("ruleReconciler: 6 installed == w1", reconciler.installed == w1,
              "\(String(describing: reconciler.installed?.summary))")
        r.check("ruleReconciler: 6 the last pending set is applied next", fake.applied.count == 3, "\(fake.applied.count)")
        r.check("ruleReconciler: 6 applied[2] == (.tcpOnly, true), m2 coalesced away",
              fake.lastApply(2, .tcpOnly, true), fake.trail())
        r.check("ruleReconciler: 6 events so far", fake.events == [.applied(.tcpOnly), .applied(w1)], "\(fake.events)")

        // 7. That lands too: installed = tcpOnly and nothing further.
        fake.complete(2, nil, "ruleReconciler: 7")
        r.check("ruleReconciler: 7 installed == .tcpOnly", reconciler.installed == .tcpOnly)
        r.check("ruleReconciler: 7 nothing more applied", fake.applied.count == 3, "\(fake.applied.count)")

        // 8. An apply error keeps `installed`, reports kept + wanted + the error text, and
        //    does NOT retry by itself (spec B: "never retries on a timer; the next scope
        //    change triggers the next attempt").
        reconciler.reconcile(for: m1)
        r.check("ruleReconciler: 8 reconcile(m1) applies", fake.applied.count == 4, "\(fake.applied.count)")
        fake.complete(3, NSError(domain: "test", code: 1), "ruleReconciler: 8")
        r.check("ruleReconciler: 8 installed kept at .tcpOnly after the error", reconciler.installed == .tcpOnly,
              "\(String(describing: reconciler.installed?.summary))")
        if case .applyFailed(let wanted, let kept, let message)? = fake.events.last {
            r.check("ruleReconciler: 8 applyFailed.wanted == w1", wanted == w1, wanted.summary)
            r.check("ruleReconciler: 8 applyFailed.kept == .tcpOnly", kept == .tcpOnly, "\(String(describing: kept?.summary))")
            r.check("ruleReconciler: 8 applyFailed.message names the error", message.contains("test"), message)
        } else {
            r.fail("FAIL ruleReconciler: 8 events.last is not .applyFailed: \(String(describing: fake.events.last))")
        }
        r.check("ruleReconciler: 8 a failed apply is not retried by itself", fake.applied.count == 4, "\(fake.applied.count)")

        // 9. The next scope change retries.
        reconciler.reconcile(for: m1)
        r.check("ruleReconciler: 9 the next change retries", fake.applied.count == 5, "\(fake.applied.count)")
        r.check("ruleReconciler: 9 applied[4] == (w1, true)", fake.lastApply(4, w1, true), fake.trail())
        fake.complete(4, nil, "ruleReconciler: 9")
        r.check("ruleReconciler: 9 installed == w1 after the retry", reconciler.installed == w1)

        // 10. stop: installed reset; a late reconcile (the detach hook) is dropped.
        reconciler.stop()
        r.check("ruleReconciler: 10 stop resets installed", reconciler.installed == nil,
              "\(String(describing: reconciler.installed?.summary))")
        reconciler.reconcile(for: nil)
        r.check("ruleReconciler: 10 reconcile after stop applies nothing", fake.applied.count == 5, "\(fake.applied.count)")

        // 11. begin again (Tahoe double-startProxy tolerance): a fresh startup apply.
        var secondStart: [Error?] = []
        reconciler.begin { secondStart.append($0) }
        r.check("ruleReconciler: 11 begin after stop applies again", fake.applied.count == 6, "\(fake.applied.count)")
        r.check("ruleReconciler: 11 applied[5] == (.tcpOnly, false)", fake.lastApply(5, .tcpOnly, false), fake.trail())

        // 12. An in-flight completion made stale by stop() is ignored even after a new
        //    begin: it must neither install, nor report, nor answer the new startup.
        reconciler.stop()
        var thirdStart: [Error?] = []
        reconciler.begin { thirdStart.append($0) }
        r.check("ruleReconciler: 12 begin after a stop mid-flight applies anew", fake.applied.count == 7, "\(fake.applied.count)")
        let eventsBeforeStale = fake.events.count
        fake.complete(5, nil, "ruleReconciler: 12 stale")   // the stale one from step 11
        r.check("ruleReconciler: 12 stale completion installs nothing", reconciler.installed == nil,
              "\(String(describing: reconciler.installed?.summary))")
        r.check("ruleReconciler: 12 stale completion reports nothing", fake.events.count == eventsBeforeStale,
              "\(fake.events.count) vs \(eventsBeforeStale)")
        r.check("ruleReconciler: 12 stale completion does not answer the new startup", thirdStart.isEmpty,
              "\(thirdStart.count)")
        r.check("ruleReconciler: 12 the abandoned startup completion is dropped, not answered", secondStart.isEmpty,
              "\(secondStart.count)")
        fake.complete(6, nil, "ruleReconciler: 12 live")
        r.check("ruleReconciler: 12 the live completion installs .tcpOnly", reconciler.installed == .tcpOnly)
        r.check("ruleReconciler: 12 the live completion answers the new startup with nil",
              thirdStart.count == 1 && thirdStart[0] == nil, "\(thirdStart.map { String(describing: $0) })")
        r.check("ruleReconciler: 12 the live completion reports .applied(.tcpOnly)",
              fake.events.last == .applied(.tcpOnly), "\(String(describing: fake.events.last))")

        // 13. A NEWER pending set that arrived during a flight that then FAILS is applied
        //    right after (spec B: the completion re-runs the check against pendingWanted);
        //    only the set that just failed is left for the next scope change.
        reconciler.reconcile(for: m2)
        r.check("ruleReconciler: 13 reconcile(m2) applies", fake.applied.count == 8, "\(fake.applied.count)")
        reconciler.reconcile(for: m1)
        r.check("ruleReconciler: 13 reconcile(m1) in flight applies nothing yet", fake.applied.count == 8, "\(fake.applied.count)")
        fake.complete(7, NSError(domain: "test", code: 2), "ruleReconciler: 13")
        r.check("ruleReconciler: 13 installed kept at .tcpOnly after the failed w2",
              reconciler.installed == .tcpOnly, "\(String(describing: reconciler.installed?.summary))")
        r.check("ruleReconciler: 13 the newer pending set (w1) is applied after the failure",
              fake.lastApply(8, w1, true), fake.trail())
        fake.complete(8, nil, "ruleReconciler: 13")
        r.check("ruleReconciler: 13 installed == w1", reconciler.installed == w1)
        r.check("ruleReconciler: 13 nothing further applied", fake.applied.count == 9, "\(fake.applied.count)")
    }

    /// Tester (stage 5) vectors around `begin` and `stop()` (spec Design B, C), on a
    /// fresh reconciler with the same fake `apply`:
    ///  A. a `reconcile` BEFORE `begin` applies nothing (`stopped` starts true) and
    ///     installs nothing; `begin` then installs TCP-only first, without `reasserting`,
    ///     and -- per the plan's `begin` contract (`pending = .tcpOnly`) -- the pre-begin
    ///     set is NOT re-applied after startup (observed; the next Scope push installs it);
    ///  B. a `reconcile` DURING the startup flight is coalesced and applied right after it
    ///     with `reasserting` (spec C: "a Scope that arrives before the startup apply
    ///     completes is coalesced as pendingWanted and applied right after");
    ///  C. a second `begin` without `stop()` (Tahoe FB21464147) while a UDP set is
    ///     installed re-applies TCP-only without `reasserting`; the UDP rules return on
    ///     the next scope change (observed; recorded in the Tester report);
    ///  D. after `stop()`: a hook carrying a UDP set is dropped (plan step 10 covers nil
    ///     only), a late completion of a pre-stop apply -- success or error -- neither
    ///     installs nor reports nor answers a startup, and nothing further is applied;
    ///  E. a `begin` after all that starts over cleanly.
    static func ruleReconcilerStartupAndStop(_ r: Recorder) {
        let fake = FakeApply(r)
        let reconciler = fake.makeReconciler()
        let m1 = ScopeMatcher(spec: "example.com 198.51.100.7")
        let w1 = ProviderRuleSet.wanted(for: m1)
        let tcpOnly = ProviderRuleSet.tcpOnly
        let g = "ruleReconciler/startup-stop"

        // A. Before begin nothing moves, whatever the set; begin then installs TCP-only.
        reconciler.reconcile(for: nil)
        reconciler.reconcile(for: m1)
        r.check("\(g): A reconcile before begin applies nothing", fake.applied.isEmpty, fake.trail())
        r.check("\(g): A nothing installed before begin", reconciler.installed == nil)
        r.check("\(g): A no event before begin", fake.events.isEmpty, "\(fake.events)")
        var startupA: [Error?] = []
        reconciler.begin { startupA.append($0) }
        r.check("\(g): A begin applies (.tcpOnly, false) first", fake.lastApply(0, tcpOnly, false), fake.trail())
        fake.complete(0, nil, "\(g): A")
        r.check("\(g): A installed == .tcpOnly", reconciler.installed == tcpOnly)
        r.check("\(g): A startup answered once with nil",
              startupA.count == 1 && startupA[0] == nil, "\(startupA.map { String(describing: $0) })")
        r.check("\(g): A the pre-begin set is not re-applied after startup (begin resets pending to .tcpOnly)",
              fake.applied.count == 1, fake.trail())
        reconciler.reconcile(for: m1)
        r.check("\(g): A the next Scope push installs it", fake.lastApply(1, w1, true), fake.trail())
        fake.complete(1, nil, "\(g): A")
        r.check("\(g): A installed == w1", reconciler.installed == w1)

        // B. A Scope during the startup flight is coalesced and applied right after it.
        reconciler.stop()
        var startupB: [Error?] = []
        reconciler.begin { startupB.append($0) }
        r.check("\(g): B begin applies (.tcpOnly, false)", fake.lastApply(2, tcpOnly, false), fake.trail())
        reconciler.reconcile(for: nil)   // serve start
        reconciler.reconcile(for: m1)    // the Scope frame
        r.check("\(g): B reconciles during the startup flight apply nothing yet", fake.applied.count == 3, fake.trail())
        r.check("\(g): B nothing installed during the startup flight", reconciler.installed == nil)
        fake.complete(2, nil, "\(g): B")
        r.check("\(g): B startup answered once with nil",
              startupB.count == 1 && startupB[0] == nil, "\(startupB.map { String(describing: $0) })")
        r.check("\(g): B the coalesced Scope set is applied right after startup with reasserting",
              fake.lastApply(3, w1, true), fake.trail())
        r.check("\(g): B installed == .tcpOnly until that lands", reconciler.installed == tcpOnly)
        fake.complete(3, nil, "\(g): B")
        r.check("\(g): B installed == w1", reconciler.installed == w1)
        r.check("\(g): B events end [.applied(.tcpOnly), .applied(w1)]",
              Array(fake.events.suffix(2)) == [.applied(tcpOnly), .applied(w1)], "\(fake.events.suffix(2))")

        // C. A second begin WITHOUT stop while w1 is installed (observed behaviour).
        var startupC: [Error?] = []
        reconciler.begin { startupC.append($0) }
        r.check("\(g): C a second begin without stop re-applies (.tcpOnly, false)",
              fake.lastApply(4, tcpOnly, false), fake.trail())
        fake.complete(4, nil, "\(g): C")
        r.check("\(g): C installed == .tcpOnly (the UDP rule is gone until the next scope change)",
              reconciler.installed == tcpOnly, "\(String(describing: reconciler.installed?.summary))")
        r.check("\(g): C the second startup answered once with nil",
              startupC.count == 1 && startupC[0] == nil, "\(startupC.map { String(describing: $0) })")
        reconciler.reconcile(for: m1)
        r.check("\(g): C the next scope change restores w1", fake.lastApply(5, w1, true), fake.trail())
        fake.complete(5, nil, "\(g): C")
        r.check("\(g): C installed == w1", reconciler.installed == w1)

        // D1. stop() with a SUCCEEDING apply in flight: the late completion is inert, and
        //     a hook carrying a UDP set after stop is dropped.
        reconciler.reconcile(for: nil)
        r.check("\(g): D1 reconcile(nil) applies (.tcpOnly, true)", fake.lastApply(6, tcpOnly, true), fake.trail())
        reconciler.stop()
        r.check("\(g): D1 stop resets installed", reconciler.installed == nil)
        let eventsBeforeD1 = fake.events.count
        fake.complete(6, nil, "\(g): D1")
        r.check("\(g): D1 late success completion installs nothing", reconciler.installed == nil,
              "\(String(describing: reconciler.installed?.summary))")
        r.check("\(g): D1 late success completion reports nothing", fake.events.count == eventsBeforeD1,
              "\(fake.events.count) vs \(eventsBeforeD1)")
        r.check("\(g): D1 late success completion applies nothing further", fake.applied.count == 7, fake.trail())
        reconciler.reconcile(for: m1)
        r.check("\(g): D1 a hook carrying a UDP set after stop applies nothing", fake.applied.count == 7, fake.trail())
        r.check("\(g): D1 still nothing installed", reconciler.installed == nil)

        // D2. stop() with a FAILING apply in flight: no .applyFailed, no startup answer.
        var startupD: [Error?] = []
        reconciler.begin { startupD.append($0) }
        r.check("\(g): D2 begin after stop applies (.tcpOnly, false)", fake.lastApply(7, tcpOnly, false), fake.trail())
        reconciler.stop()
        let eventsBeforeD2 = fake.events.count
        fake.complete(7, NSError(domain: "test", code: 3), "\(g): D2")
        r.check("\(g): D2 late error completion reports nothing", fake.events.count == eventsBeforeD2,
              "\(fake.events.count) vs \(eventsBeforeD2)")
        r.check("\(g): D2 late error completion does not answer the abandoned startup",
              startupD.isEmpty, "\(startupD.count)")
        r.check("\(g): D2 nothing installed", reconciler.installed == nil)
        r.check("\(g): D2 nothing further applied", fake.applied.count == 8, fake.trail())

        // E. A begin after all that starts over cleanly.
        var startupE: [Error?] = []
        reconciler.begin { startupE.append($0) }
        r.check("\(g): E begin applies (.tcpOnly, false)", fake.lastApply(8, tcpOnly, false), fake.trail())
        fake.complete(8, nil, "\(g): E")
        r.check("\(g): E installed == .tcpOnly", reconciler.installed == tcpOnly)
        r.check("\(g): E startup answered once with nil",
              startupE.count == 1 && startupE[0] == nil, "\(startupE.map { String(describing: $0) })")
        r.check("\(g): E last event is .applied(.tcpOnly)", fake.events.last == .applied(tcpOnly),
              "\(String(describing: fake.events.last))")
        r.check("\(g): E every apply parked exactly one completion",
              fake.completions.count == fake.applied.count, "\(fake.completions.count) vs \(fake.applied.count)")
    }
}
#endif
