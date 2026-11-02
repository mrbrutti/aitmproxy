//! The verb table (spec D6) and the call budgets (spec D8).
//!
//! **The rule.** A verb is local only when its whole effect is on this
//! machine's disk or OS and it reads nothing from a core: the CA files and
//! trust store, the findings and PoC directories, a report rendered from the
//! findings directory, a static script compile, undoing the OS proxy setting.
//! Everything that reads or writes a store, guard, client, browser, script
//! host, policy, capture feeder or the core's own configuration is live, as is
//! every script verb and every verb the local registry does not know.
//!
//! `tests/oneshot_verbs.rs` walks the whole built-in registry against this
//! table, so a verb added without a placement decision fails there.

use std::time::Duration;

/// Where a one-shot runs a verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// On this machine, through today's in-process `Cli::dispatch`.
    Local,
    /// On the running core, over the loopback operator bus.
    Live,
}

/// The thirteen local verbs (spec D6). Every other verb is live.
pub const LOCAL_VERBS: &[&str] = &[
    "ca.status",
    "ca.export",
    "ca.install",
    "ca.uninstall",
    "findings.list",
    "findings.get",
    "findings.remove",
    "poc.list",
    "poc.get",
    "poc.artifact",
    "scan.report",
    "script.validate",
    "proxy.system.unset",
];

/// Native verbs on the long lane ([`LONG_CALL_BUDGET`]): each drives traffic,
/// a browser or the wire and may legitimately run for minutes.
pub const LONG_RUNNING_VERBS: &[&str] = &[
    "poc.run",
    "scan.discover",
    "scan.passive",
    "request.send",
    "flow.replay",
    "browser.navigate",
    "browser.click",
    "browser.type",
    "browser.eval",
    "browser.screenshot",
    "browser.get_dom",
    "l4.send_recv",
    "l4.inject",
];

/// Bundled Rhai `ScriptCommand`s on the long lane. They register from
/// `scripts/bundled/l4/*.rhai` when the catalogue loads, never from the
/// native registry (research F13), so the walking test asserts they are
/// absent there.
pub const LONG_RUNNING_SCRIPT_VERBS: &[&str] = &["l4.recon", "l4.tcp_probe", "l4.udp_probe"];

/// Verb-name prefixes whose every verb is on the long lane: the `check.*`
/// checks (natives since the scanner v2 rewrite, bundled Rhai scripts before)
/// and the `l4.intercept.*` natives.
pub const LONG_RUNNING_PREFIXES: &[&str] = &["check.", "l4.intercept."];

/// The budget for `connect` plus `initialize` (and `tools/list` for a verb
/// the local registry lacks), spec D8 step 6.
pub const HANDSHAKE_BUDGET: Duration = Duration::from_secs(2);

/// The call budget for every verb not on the long lane.
pub const CALL_BUDGET: Duration = Duration::from_secs(30);

/// The call budget for the long lane (10 min).
pub const LONG_CALL_BUDGET: Duration = Duration::from_secs(600);

/// The one-shot's own flag names (spec D7). No registered command may declare
/// a param with one of these names; the walking test pins that.
pub const ONE_SHOT_FLAG_NAMES: &[&str] = &["bus", "token-file"];

/// Where the one-shot runs `dotted`: [`Placement::Local`] only for a name in
/// [`LOCAL_VERBS`]; every other name, including unknown and script verbs, is
/// [`Placement::Live`].
pub fn placement(dotted: &str) -> Placement {
    if LOCAL_VERBS.contains(&dotted) {
        Placement::Local
    } else {
        Placement::Live
    }
}

/// The call budget for `dotted`: [`LONG_CALL_BUDGET`] when it is in
/// [`LONG_RUNNING_VERBS`] or [`LONG_RUNNING_SCRIPT_VERBS`], starts with a
/// [`LONG_RUNNING_PREFIXES`] entry, or the local registry does not know it
/// (`!known_locally`, so the core decides what it is); else [`CALL_BUDGET`].
pub fn budget(dotted: &str, known_locally: bool) -> Duration {
    let long = !known_locally
        || LONG_RUNNING_VERBS.contains(&dotted)
        || LONG_RUNNING_SCRIPT_VERBS.contains(&dotted)
        || LONG_RUNNING_PREFIXES.iter().any(|p| dotted.starts_with(p));
    if long {
        LONG_CALL_BUDGET
    } else {
        CALL_BUDGET
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_is_live_unless_listed() {
        assert_eq!(placement("scope.add"), Placement::Live);
        assert_eq!(placement("ca.status"), Placement::Local);
        assert_eq!(placement("check.xss"), Placement::Live);
        assert_eq!(placement("nonsense.verb"), Placement::Live);
    }

    #[test]
    fn budget_picks_the_long_lane() {
        assert_eq!(budget("scope.add", true), Duration::from_secs(30));
        assert_eq!(budget("poc.run", true), Duration::from_secs(600));
        assert_eq!(budget("check.xss", true), Duration::from_secs(600));
        assert_eq!(budget("l4.recon", true), Duration::from_secs(600));
        assert_eq!(budget("custom.verb", false), Duration::from_secs(600));
    }

    // ---- tester additions (stage 5, R14 pass 1) ----

    /// Tester — the long lane by prefix and by local knowledge: every
    /// `check.*` and `l4.intercept.*` name is long; a bundled script verb is
    /// long by name; a dotted name the table does not list is long only when
    /// the local registry does not know it (`known_locally == false`); the
    /// prefix is `check.` with its dot, so `checker.x` is on the short lane.
    #[test]
    fn tester_budget_prefixes_and_locally_known_unknowns() {
        assert_eq!(budget("check.anything", true), LONG_CALL_BUDGET);
        assert_eq!(budget("check.anything.deep", true), LONG_CALL_BUDGET);
        assert_eq!(budget("l4.intercept.start", true), LONG_CALL_BUDGET);
        assert_eq!(budget("l4.intercept.status", true), LONG_CALL_BUDGET);
        assert_eq!(budget("l4.tcp_probe", true), LONG_CALL_BUDGET);
        assert_eq!(budget("l4.udp_probe", true), LONG_CALL_BUDGET);
        assert_eq!(budget("l4.interfaces", true), CALL_BUDGET);
        assert_eq!(budget("l4.capture.start", true), CALL_BUDGET);
        assert_eq!(budget("custom.verb", true), CALL_BUDGET);
        assert_eq!(budget("checker.x", true), CALL_BUDGET);
        assert_eq!(budget("check", true), CALL_BUDGET);
        assert_eq!(budget("scope.add", false), LONG_CALL_BUDGET);
        assert_eq!(budget("", true), CALL_BUDGET);
        assert_eq!(HANDSHAKE_BUDGET, Duration::from_secs(2));
        assert_eq!(CALL_BUDGET, Duration::from_secs(30));
        assert_eq!(LONG_CALL_BUDGET, Duration::from_secs(600));
    }

    /// Tester — `placement` is an exact-name lookup: a prefix, a parent
    /// group, a different case, a trailing dot and the empty name are all
    /// live (the safe side of the rule).
    #[test]
    fn tester_placement_is_an_exact_match_only() {
        assert_eq!(placement("proxy.system.unset"), Placement::Local);
        assert_eq!(placement("proxy.system"), Placement::Live);
        assert_eq!(placement("proxy.system.unset.now"), Placement::Live);
        assert_eq!(placement("ca"), Placement::Live);
        assert_eq!(placement("ca.status."), Placement::Live);
        assert_eq!(placement("Ca.Status"), Placement::Live);
        assert_eq!(placement(" ca.status"), Placement::Live);
        assert_eq!(placement(""), Placement::Live);
        assert_eq!(LOCAL_VERBS.len(), 13);
        assert_eq!(ONE_SHOT_FLAG_NAMES, &["bus", "token-file"]);
    }
}
