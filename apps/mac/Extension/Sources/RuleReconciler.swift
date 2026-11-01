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
    /// Design B/C of spec 2026-11-01-ne-tcp-only-catch-all-design, pinned against a fake
    /// `apply` that records `(wanted, reasserting)` and parks each completion so the check
    /// drives every transition by hand: startup applies `.tcpOnly` without `reasserting`;
    /// "no change" applies nothing; a change during a flight is coalesced to the LAST
    /// pending set and applied right after with `reasserting`; an apply error keeps
    /// `installed` and is retried only on the next scope change, never by itself;
    /// `stop()` resets the state, drops late reconciles and makes an in-flight completion
    /// stale; `begin` after `stop()` starts over (Tahoe double-`startProxy` tolerance).
    static func ruleReconciler(_ r: Recorder) {
        var applied: [(ProviderRuleSet, Bool)] = []
        var completions: [(Error?) -> Void] = []
        var events: [RuleReconciler.Event] = []
        var startupResults: [Error?] = []
        let reconciler = RuleReconciler(
            apply: { wanted, reasserting, completion in
                applied.append((wanted, reasserting))
                completions.append(completion)
            },
            onEvent: { events.append($0) })

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
        r.check("ruleReconciler: 1 begin applies once", applied.count == 1, "\(applied.count)")
        r.check("ruleReconciler: 1 begin applies (.tcpOnly, reasserting false)",
              applied.count == 1 && applied[0] == (ProviderRuleSet.tcpOnly, false),
              applied.map { "(\($0.0.summary), \($0.1))" }.joined(separator: "; "))
        r.check("ruleReconciler: 1 installed still nil during the startup apply", reconciler.installed == nil)
        r.check("ruleReconciler: 1 startup completion not called yet", startupResults.isEmpty, "\(startupResults.count)")

        // 2. The startup apply succeeds.
        if completions.count == 1 { completions[0](nil) }
        r.check("ruleReconciler: 2 installed == .tcpOnly", reconciler.installed == .tcpOnly,
              "\(String(describing: reconciler.installed?.summary))")
        r.check("ruleReconciler: 2 startup completion called once with nil",
              startupResults.count == 1 && startupResults[0] == nil,
              "\(startupResults.map { String(describing: $0) })")
        r.check("ruleReconciler: 2 events == [.applied(.tcpOnly)]", events == [.applied(.tcpOnly)], "\(events)")

        // 3. No change: nothing applied.
        reconciler.reconcile(for: nil)
        r.check("ruleReconciler: 3 reconcile(nil) with tcpOnly installed applies nothing",
              applied.count == 1, "\(applied.count)")

        // 4. A change: one apply with reasserting.
        reconciler.reconcile(for: m1)
        r.check("ruleReconciler: 4 reconcile(m1) applies", applied.count == 2, "\(applied.count)")
        r.check("ruleReconciler: 4 applied[1] == (w1, true)",
              applied.count == 2 && applied[1] == (w1, true),
              applied.count == 2 ? "(\(applied[1].0.summary), \(applied[1].1))" : "\(applied.count)")

        // 5. Changes during the flight are coalesced: nothing new is applied yet.
        reconciler.reconcile(for: m2)
        reconciler.reconcile(for: nil)
        r.check("ruleReconciler: 5 reconciles in flight apply nothing", applied.count == 2, "\(applied.count)")
        r.check("ruleReconciler: 5 installed unchanged in flight", reconciler.installed == .tcpOnly)

        // 6. The flight lands: installed = w1, then ONLY the last pending set (tcpOnly) is
        //    applied; m2 was coalesced away.
        if completions.count == 2 { completions[1](nil) }
        r.check("ruleReconciler: 6 installed == w1", reconciler.installed == w1,
              "\(String(describing: reconciler.installed?.summary))")
        r.check("ruleReconciler: 6 the last pending set is applied next", applied.count == 3, "\(applied.count)")
        r.check("ruleReconciler: 6 applied[2] == (.tcpOnly, true), m2 coalesced away",
              applied.count == 3 && applied[2] == (ProviderRuleSet.tcpOnly, true),
              applied.count == 3 ? "(\(applied[2].0.summary), \(applied[2].1))" : "\(applied.count)")
        r.check("ruleReconciler: 6 events so far", events == [.applied(.tcpOnly), .applied(w1)], "\(events)")

        // 7. That lands too: installed = tcpOnly and nothing further.
        if completions.count == 3 { completions[2](nil) }
        r.check("ruleReconciler: 7 installed == .tcpOnly", reconciler.installed == .tcpOnly)
        r.check("ruleReconciler: 7 nothing more applied", applied.count == 3, "\(applied.count)")

        // 8. An apply error keeps `installed`, reports kept + wanted + the error text, and
        //    does NOT retry by itself (spec B: "never retries on a timer; the next scope
        //    change triggers the next attempt").
        reconciler.reconcile(for: m1)
        r.check("ruleReconciler: 8 reconcile(m1) applies", applied.count == 4, "\(applied.count)")
        if completions.count == 4 { completions[3](NSError(domain: "test", code: 1)) }
        r.check("ruleReconciler: 8 installed kept at .tcpOnly after the error", reconciler.installed == .tcpOnly,
              "\(String(describing: reconciler.installed?.summary))")
        if case .applyFailed(let wanted, let kept, let message)? = events.last {
            r.check("ruleReconciler: 8 applyFailed.wanted == w1", wanted == w1, wanted.summary)
            r.check("ruleReconciler: 8 applyFailed.kept == .tcpOnly", kept == .tcpOnly, "\(String(describing: kept?.summary))")
            r.check("ruleReconciler: 8 applyFailed.message names the error", message.contains("test"), message)
        } else {
            r.fail("FAIL ruleReconciler: 8 events.last is not .applyFailed: \(String(describing: events.last))")
        }
        r.check("ruleReconciler: 8 a failed apply is not retried by itself", applied.count == 4, "\(applied.count)")

        // 9. The next scope change retries.
        reconciler.reconcile(for: m1)
        r.check("ruleReconciler: 9 the next change retries", applied.count == 5, "\(applied.count)")
        r.check("ruleReconciler: 9 applied[4] == (w1, true)",
              applied.count == 5 && applied[4] == (w1, true),
              applied.count == 5 ? "(\(applied[4].0.summary), \(applied[4].1))" : "\(applied.count)")
        if completions.count == 5 { completions[4](nil) }
        r.check("ruleReconciler: 9 installed == w1 after the retry", reconciler.installed == w1)

        // 10. stop: installed reset; a late reconcile (the detach hook) is dropped.
        reconciler.stop()
        r.check("ruleReconciler: 10 stop resets installed", reconciler.installed == nil,
              "\(String(describing: reconciler.installed?.summary))")
        reconciler.reconcile(for: nil)
        r.check("ruleReconciler: 10 reconcile after stop applies nothing", applied.count == 5, "\(applied.count)")

        // 11. begin again (Tahoe double-startProxy tolerance): a fresh startup apply.
        var secondStart: [Error?] = []
        reconciler.begin { secondStart.append($0) }
        r.check("ruleReconciler: 11 begin after stop applies again", applied.count == 6, "\(applied.count)")
        r.check("ruleReconciler: 11 applied[5] == (.tcpOnly, false)",
              applied.count == 6 && applied[5] == (ProviderRuleSet.tcpOnly, false),
              applied.count == 6 ? "(\(applied[5].0.summary), \(applied[5].1))" : "\(applied.count)")

        // 12. An in-flight completion made stale by stop() is ignored even after a new
        //    begin: it must neither install, nor report, nor answer the new startup.
        reconciler.stop()
        var thirdStart: [Error?] = []
        reconciler.begin { thirdStart.append($0) }
        r.check("ruleReconciler: 12 begin after a stop mid-flight applies anew", applied.count == 7, "\(applied.count)")
        let eventsBeforeStale = events.count
        if completions.count == 7 { completions[5](nil) }   // the stale one from step 11
        r.check("ruleReconciler: 12 stale completion installs nothing", reconciler.installed == nil,
              "\(String(describing: reconciler.installed?.summary))")
        r.check("ruleReconciler: 12 stale completion reports nothing", events.count == eventsBeforeStale,
              "\(events.count) vs \(eventsBeforeStale)")
        r.check("ruleReconciler: 12 stale completion does not answer the new startup", thirdStart.isEmpty,
              "\(thirdStart.count)")
        r.check("ruleReconciler: 12 the abandoned startup completion is dropped, not answered", secondStart.isEmpty,
              "\(secondStart.count)")
        if completions.count == 7 { completions[6](nil) }
        r.check("ruleReconciler: 12 the live completion installs .tcpOnly", reconciler.installed == .tcpOnly)
        r.check("ruleReconciler: 12 the live completion answers the new startup with nil",
              thirdStart.count == 1 && thirdStart[0] == nil, "\(thirdStart.map { String(describing: $0) })")
        r.check("ruleReconciler: 12 the live completion reports .applied(.tcpOnly)",
              events.last == .applied(.tcpOnly), "\(String(describing: events.last))")

        // 13. A NEWER pending set that arrived during a flight that then FAILS is applied
        //    right after (spec B: the completion re-runs the check against pendingWanted);
        //    only the set that just failed is left for the next scope change.
        reconciler.reconcile(for: m2)
        r.check("ruleReconciler: 13 reconcile(m2) applies", applied.count == 8, "\(applied.count)")
        reconciler.reconcile(for: m1)
        r.check("ruleReconciler: 13 reconcile(m1) in flight applies nothing yet", applied.count == 8, "\(applied.count)")
        if completions.count == 8 { completions[7](NSError(domain: "test", code: 2)) }
        r.check("ruleReconciler: 13 installed kept at .tcpOnly after the failed w2",
              reconciler.installed == .tcpOnly, "\(String(describing: reconciler.installed?.summary))")
        r.check("ruleReconciler: 13 the newer pending set (w1) is applied after the failure",
              applied.count == 9 && applied[8] == (w1, true),
              applied.count == 9 ? "(\(applied[8].0.summary), \(applied[8].1))" : "\(applied.count)")
        if completions.count == 9 { completions[8](nil) }
        r.check("ruleReconciler: 13 installed == w1", reconciler.installed == w1)
        r.check("ruleReconciler: 13 nothing further applied", applied.count == 9, "\(applied.count)")
    }
}
#endif
