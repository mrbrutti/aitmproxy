//! The point/check scheduler and its priority rule (spec D5). Task 10 of the
//! T1b plan fills it.
//!
//! [`plan`] turns one job's insertion points, site nodes and selected checks
//! into two ordered work lists: the passive phase, which sends nothing, and the
//! active phase, which does. Spec D4 fixes the rules it applies — lane, kind,
//! intensity, the profile's `audit.kinds` and `audit.ignore`, the `session`
//! trait, `wants_traits`, the frequent-point rule and `CheckMeta::scope` — and
//! research 17 §3.2 fixes the order: priority is `0.8 x exposure + 0.2 x
//! interest`, light checks run before medium ones across all points, and the
//! passive phase runs before the active one.
//!
//! Nothing here sends, charges or decides policy: the scheduler reads metadata
//! and returns a plan. The budget, the scope guard and the agent gate are the
//! worker's, and they apply whatever this plan says.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use aitm_scan_model::{
    Accuracy, Check, CheckCost, CheckMeta, CheckScope, IgnoreRule, InsertionKind, InsertionPoint,
    PointTrait, ScanProfile, SiteNode, SkippedPoints, Speed, Technique,
};

/// One check to run against one insertion point.
pub struct ScheduleItem {
    /// Index into the `points` slice [`plan`] was given.
    pub point: usize,
    /// The check to run.
    pub check: Arc<dyn Check>,
    /// Burp's audit-item priority, `0.8 x exposure + 0.2 x interest`.
    pub priority: f32,
}

impl std::fmt::Debug for ScheduleItem {
    /// Prints the check's id, never the check itself.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduleItem")
            .field("point", &self.point)
            .field("check", &self.check.meta().id)
            .field("priority", &self.priority)
            .finish()
    }
}

/// Everything a job's audit phase will do, in the order it will do it.
#[derive(Debug, Default)]
pub struct SchedulePlan {
    /// The passive phase: checks that read captured traffic and send nothing.
    pub passive: Vec<ScheduleItem>,
    /// The active phase: everything that sends.
    pub active: Vec<ScheduleItem>,
    /// Why points were left out, for `JobStatus.points.skipped` (spec D5).
    pub skipped: SkippedPoints,
    /// The `(kind, name)` pairs treated as frequent, so the worker can revert
    /// one to a full audit when a check hits on it (spec D4).
    pub frequent: HashSet<(InsertionKind, String)>,
}

/// How interesting a request is to attack: method, content type, authentication
/// (research 17 §3.2). Clamped to `1.0`.
pub fn interest(method: Option<&str>, content_type: Option<&str>, authenticated: bool) -> f32 {
    let writes = method.is_some_and(|m| {
        matches!(
            m.to_ascii_uppercase().as_str(),
            "POST" | "PUT" | "PATCH" | "DELETE"
        )
    });
    let mut score: f32 = if writes { 0.6 } else { 0.3 };

    if let Some(kind) = content_type {
        let kind = kind.to_ascii_lowercase();
        if kind.contains("html") || kind.contains("json") || kind.contains("xml") {
            score += 0.3;
        }
    }
    if authenticated {
        score += 0.1;
    }
    score.min(1.0)
}

/// How much attack surface a node adds, as its share of the busiest node's
/// insertion points (research 17 §3.2). Zero when nothing was found.
pub fn exposure(new_points: u32, max_new_points: u32) -> f32 {
    if max_new_points == 0 {
        return 0.0;
    }
    (new_points as f32 / max_new_points as f32).clamp(0.0, 1.0)
}

/// Burp's audit-item priority: weighted 80/20 towards exposure over interest.
pub fn priority(exposure: f32, interest: f32) -> f32 {
    0.8 * exposure + 0.2 * interest
}

/// How many payloads one check may spend per point, by `Speed` and technique
/// (spec D2: boolean pairs 2/4/8, timing repeats 2/3/5, everything else
/// 8/25/unbounded).
pub fn payload_cap(speed: Speed, technique: Technique) -> u32 {
    match technique {
        Technique::Boolean => match speed {
            Speed::Fast => 2,
            Speed::Normal => 4,
            Speed::Thorough => 8,
        },
        Technique::Timing => match speed {
            Speed::Fast => 2,
            Speed::Normal => 3,
            Speed::Thorough => 5,
        },
        _ => match speed {
            Speed::Fast => 8,
            Speed::Normal => 25,
            Speed::Thorough => u32::MAX,
        },
    }
}

/// How many times a blind technique repeats before it concludes (spec D2).
pub fn repeats(accuracy: Accuracy) -> u32 {
    match accuracy {
        Accuracy::FewerFalseNegatives => 1,
        Accuracy::Normal => 2,
        Accuracy::FewerFalsePositives => 3,
    }
}

/// Build one job's schedule (spec D4 "Scheduling").
///
/// `points` and `nodes` are what discovery found; `checks` is the catalogue
/// already narrowed by the profile's include/exclude selection; `profile` is
/// the resolved, clamped profile. The returned [`SchedulePlan`] names points by
/// their index in `points`.
pub fn plan(
    points: &[InsertionPoint],
    nodes: &[SiteNode],
    checks: &[Arc<dyn Check>],
    profile: &ScanProfile,
) -> SchedulePlan {
    let by_id: HashMap<&str, &SiteNode> = nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let busiest = nodes.iter().map(|n| n.points).max().unwrap_or(0);
    let thorough = profile.speed == Speed::Thorough;

    let mut out = SchedulePlan::default();
    // One slot per (check id, scope key) for node- and origin-scoped checks:
    // the first admissible point claims it and the rest are not scheduled.
    let mut claimed: HashSet<(String, String)> = HashSet::new();

    for (index, point) in points.iter().enumerate() {
        if !profile.audit.kinds.contains(&point.kind) {
            continue;
        }
        if profile.audit.ignore.iter().any(|rule| ignores(rule, point)) {
            out.skipped.ignored += 1;
            continue;
        }

        let node = point
            .site_node
            .as_deref()
            .and_then(|id| by_id.get(id).copied());
        let is_session = point.traits.contains(&PointTrait::Session);
        let frequent = point.frequency > profile.audit.frequent_point_threshold;
        if frequent {
            out.frequent.insert((point.kind, point.name.clone()));
        }

        // A site node carries no content type (the model's `SiteNode` has no
        // such field), so interest reads it as unknown, per spec D4.
        let score = priority(
            exposure(node.map(|n| n.points).unwrap_or(0), busiest),
            interest(point.method.as_deref(), None, node.is_some_and(|n| n.auth)),
        );

        let mut session_blocked = false;
        for check in checks {
            let meta = check.meta();

            if !meta.lanes.contains(&point.lane)
                || !meta.kinds.contains(&point.kind)
                || meta.intensity > profile.intensity
            {
                continue;
            }
            if is_session && !meta.targets_session {
                session_blocked = true;
                continue;
            }
            if !thorough {
                if let Some(wanted) = &meta.wants_traits {
                    if !wanted.iter().any(|t| point.traits.contains(t)) {
                        continue;
                    }
                }
            }
            if frequent && meta.cost != CheckCost::Light {
                out.skipped.frequent += 1;
                continue;
            }
            if let Some(key) = scope_key(meta, point, node) {
                if !claimed.insert((meta.id.clone(), key)) {
                    continue;
                }
            }

            let item = ScheduleItem {
                point: index,
                check: Arc::clone(check),
                priority: score,
            };
            if meta.technique == Technique::Passive {
                out.passive.push(item);
            } else {
                out.active.push(item);
            }
        }

        if session_blocked {
            out.skipped.ignored += 1;
        }
    }

    // The passive phase is point-ordered; the active phase runs every light
    // check before any medium one, highest priority first within a cost.
    out.passive.sort_by_key(|item| item.point);
    out.active.sort_by(|a, b| {
        cost_rank(&a.check).cmp(&cost_rank(&b.check)).then_with(|| {
            b.priority
                .partial_cmp(&a.priority)
                .unwrap_or(Ordering::Equal)
                .then(a.point.cmp(&b.point))
        })
    });
    out
}

/// Whether an `audit.ignore` rule takes this point out of the audit: every key
/// the rule sets must match (spec D2). A rule that sets no key matches nothing
/// — the profile validator refuses such a rule rather than auditing nothing.
fn ignores(rule: &IgnoreRule, point: &InsertionPoint) -> bool {
    if !rule.is_valid() {
        return false;
    }
    if rule.kind.is_some_and(|kind| kind != point.kind) {
        return false;
    }
    if rule
        .point_trait
        .is_some_and(|wanted| !point.traits.contains(&wanted))
    {
        return false;
    }
    if let Some(pattern) = &rule.name_regex {
        if !regex_matches(pattern, &point.name) {
            return false;
        }
    }
    true
}

/// Whether `pattern` matches `text`.
///
/// The regex engine is the PoC matcher's, which this crate already depends on:
/// an `Assertion::Regex` over a body-only context. A pattern that does not
/// compile matches nothing, so a malformed `name_regex` cannot take the whole
/// audit out.
fn regex_matches(pattern: &str, text: &str) -> bool {
    aitm_poc::evaluate(
        &aitm_poc::Assertion::regex(pattern),
        &aitm_poc::MatchContext::new(0, text),
    )
}

/// The slot a node- or origin-scoped check occupies, or `None` for a
/// per-point check, which never shares a slot (spec D4, coordinator decision 4).
fn scope_key(meta: &CheckMeta, point: &InsertionPoint, node: Option<&SiteNode>) -> Option<String> {
    match meta.scope {
        CheckScope::Point => None,
        // A point with no site node is its own node: the check still runs once
        // for it rather than being folded into an unrelated node's slot.
        CheckScope::Node => Some(
            point
                .site_node
                .clone()
                .unwrap_or_else(|| format!("point:{}", point.id)),
        ),
        CheckScope::Origin => Some(origin_key(point, node)),
    }
}

/// The origin a point belongs to, `scheme://host:port`.
///
/// Taken from the point's site node, else parsed from the point's URL, else the
/// point's own id — an unattributable point is its own origin rather than being
/// merged into another one's single run.
fn origin_key(point: &InsertionPoint, node: Option<&SiteNode>) -> String {
    if let Some(node) = node {
        return format!("{}://{}:{}", node.scheme, node.host, node.port);
    }
    if let Some(parsed) = point.url.as_deref().and_then(|u| url::Url::parse(u).ok()) {
        if let Some(host) = parsed.host_str() {
            let port = parsed.port_or_known_default().unwrap_or(0);
            return format!("{}://{}:{}", parsed.scheme(), host, port);
        }
    }
    format!("point:{}", point.id)
}

/// Light before medium before heavy.
fn cost_rank(check: &Arc<dyn Check>) -> u8 {
    match check.meta().cost {
        CheckCost::Light => 0,
        CheckCost::Medium => 1,
        CheckCost::Heavy => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use aitm_scan_model::testing::{null_meta, NullCheck};
    use aitm_scan_model::{
        Accuracy, Check, CheckCost, CheckMeta, CheckScope, InsertionKind, InsertionPoint, LaneKind,
        PointTrait, ScanProfile, SiteNode, Speed, Technique,
    };

    /// A check carrying the model's null meta for `id`, with `edit` applied.
    /// The null meta is `http` / `query` / `passive` intensity / `light` cost,
    /// and technique `observe`, so it schedules into the **active** list.
    fn check(id: &str, edit: impl FnOnce(&mut CheckMeta)) -> Arc<dyn Check> {
        let mut meta = null_meta(id);
        edit(&mut meta);
        Arc::new(NullCheck::new(meta))
    }

    /// An HTTP `GET` query point named `name`, id `id`, on the default origin.
    fn point(id: &str, name: &str) -> InsertionPoint {
        InsertionPoint {
            id: id.to_string(),
            lane: LaneKind::Http,
            kind: InsertionKind::Query,
            name: name.to_string(),
            path: None,
            example: None,
            flow: None,
            site_node: None,
            traits: Vec::new(),
            frequency: 1,
            method: Some("GET".to_string()),
            url: Some("http://127.0.0.1:8080/s".to_string()),
        }
    }

    /// A site node on `host` carrying `points` insertion points.
    fn node(id: &str, host: &str, points: u32) -> SiteNode {
        SiteNode {
            id: id.to_string(),
            method: "GET".to_string(),
            scheme: "http".to_string(),
            host: host.to_string(),
            port: 8080,
            path_template: "/s".to_string(),
            flows: Vec::new(),
            params: Vec::new(),
            auth: false,
            points,
            audited: false,
        }
    }

    /// The check ids of a schedule list, in order.
    fn ids(items: &[ScheduleItem]) -> Vec<String> {
        items.iter().map(|i| i.check.meta().id.clone()).collect()
    }

    /// The `(check id, point index)` pairs of a schedule list, in order.
    fn pairs(items: &[ScheduleItem]) -> Vec<(String, usize)> {
        items
            .iter()
            .map(|i| (i.check.meta().id.clone(), i.point))
            .collect()
    }

    /// How many items a given check id got.
    fn count_for(items: &[ScheduleItem], id: &str) -> usize {
        items.iter().filter(|i| i.check.meta().id == id).count()
    }

    /// Research 17 §3.2: priority is weighted 80/20 in favour of exposure over
    /// interest, and interest is method plus content type plus authentication.
    #[test]
    fn priority_formula_matches_research_17() {
        assert!((priority(1.0, 0.5) - 0.9).abs() < 1e-6);
        assert!((priority(0.0, 1.0) - 0.2).abs() < 1e-6);

        assert_eq!(interest(Some("POST"), Some("application/json"), true), 1.0);
        assert_eq!(interest(Some("GET"), None, false), 0.3);
        assert!((interest(Some("PUT"), None, false) - 0.6).abs() < 1e-6);
        assert!((interest(Some("get"), Some("text/html"), false) - 0.6).abs() < 1e-6);
        assert!((interest(None, None, true) - 0.4).abs() < 1e-6);

        assert!((exposure(2, 4) - 0.5).abs() < 1e-6);
        assert_eq!(exposure(3, 0), 0.0, "no nodes means no exposure");
        assert_eq!(exposure(9, 3), 1.0, "exposure never exceeds one");
    }

    /// Spec D4 "Scheduling": lane, kind and intensity all gate an item.
    #[test]
    fn plan_filters_by_lane_kind_and_intensity() {
        let checks = vec![
            check("http-query-light", |m| {
                m.intensity = aitm_scan_model::Intensity::Light;
            }),
            check("ws-text-light", |m| {
                m.lanes = vec![LaneKind::Ws];
                m.kinds = vec![InsertionKind::WsText];
                m.intensity = aitm_scan_model::Intensity::Light;
            }),
            check("http-query-intrusive", |m| {
                m.intensity = aitm_scan_model::Intensity::Intrusive;
            }),
        ];
        let points = vec![point("p0", "q")];

        let out = plan(&points, &[], &checks, &ScanProfile::default());

        assert_eq!(ids(&out.active), vec!["http-query-light".to_string()]);
        assert!(out.passive.is_empty());

        let mut no_query = ScanProfile::default();
        no_query.audit.kinds = vec![InsertionKind::Header];
        assert!(
            plan(&points, &[], &checks, &no_query).active.is_empty(),
            "a kind the profile does not audit schedules nothing"
        );
    }

    /// Spec D4: within the active phase, `light` checks run before `medium`
    /// across all points, not point by point.
    #[test]
    fn light_before_medium_across_points() {
        let checks = vec![
            check("L", |m| m.cost = CheckCost::Light),
            check("M", |m| m.cost = CheckCost::Medium),
        ];
        let points = vec![point("p0", "q"), point("p1", "r")];

        let out = plan(&points, &[], &checks, &ScanProfile::default());

        assert_eq!(
            pairs(&out.active),
            vec![
                ("L".to_string(), 0),
                ("L".to_string(), 1),
                ("M".to_string(), 0),
                ("M".to_string(), 1),
            ]
        );
    }

    /// Spec D4: a `(kind, name)` seen on more nodes than the threshold gets
    /// light checks only, and the pair is recorded so a hit can revert it.
    #[test]
    fn frequent_point_gets_light_only() {
        let checks = vec![
            check("L", |m| m.cost = CheckCost::Light),
            check("M", |m| m.cost = CheckCost::Medium),
        ];
        let mut frequent = point("p0", "q");
        frequent.frequency = 9;

        let out = plan(&[frequent], &[], &checks, &ScanProfile::default());

        assert_eq!(ids(&out.active), vec!["L".to_string()]);
        assert_eq!(out.skipped.frequent, 1);
        assert!(out
            .frequent
            .contains(&(InsertionKind::Query, "q".to_string())));
        assert_eq!(out.skipped.ignored, 0);
    }

    /// Spec D4 ("skip checks unlikely to be effective"): `wants_traits` must
    /// intersect the point's traits, except at `speed: thorough`.
    #[test]
    fn wants_traits_respected_unless_thorough() {
        let checks = vec![check("open-redirect", |m| {
            m.wants_traits = Some(vec![PointTrait::Url]);
        })];
        let plain = vec![point("p0", "next")];

        let normal = ScanProfile::default();
        assert!(
            plan(&plain, &[], &checks, &normal).active.is_empty(),
            "a trait-less point is not worth an open-redirect probe"
        );

        let thorough = ScanProfile {
            speed: Speed::Thorough,
            ..ScanProfile::default()
        };
        assert_eq!(
            ids(&plan(&plain, &[], &checks, &thorough).active),
            vec!["open-redirect".to_string()],
            "thorough schedules it anyway"
        );

        let mut url_point = point("p0", "next");
        url_point.traits = vec![PointTrait::Url];
        assert_eq!(
            ids(&plan(&[url_point], &[], &checks, &normal).active),
            vec!["open-redirect".to_string()],
            "a url-trait point is exactly what it wants"
        );
    }

    /// Spec D2: a `session`-trait point is never mutated — by the default
    /// `audit.ignore` rule and by the `targets_session` gate behind it.
    #[test]
    fn session_trait_is_ignored_by_default() {
        let checks = vec![check("probe", |_| {})];
        let mut session_point = point("p0", "SESSIONID");
        session_point.traits = vec![PointTrait::Session];
        let points = vec![session_point];

        let out = plan(&points, &[], &checks, &ScanProfile::default());
        assert!(out.active.is_empty() && out.passive.is_empty());
        assert_eq!(out.skipped.ignored, 1, "counted once for the point");

        let mut open = ScanProfile::default();
        open.audit.ignore = Vec::new();
        let still_skipped = plan(&points, &[], &checks, &open);
        assert!(
            still_skipped.active.is_empty(),
            "removing the rule is not enough: the check must target sessions"
        );
        assert_eq!(still_skipped.skipped.ignored, 1);

        let targeting = vec![check("probe", |m| m.targets_session = true)];
        let scheduled = plan(&points, &[], &targeting, &open);
        assert_eq!(ids(&scheduled.active), vec!["probe".to_string()]);
        assert_eq!(scheduled.skipped.ignored, 0);
    }

    /// Spec D4: the passive phase is its own list; everything else is active.
    #[test]
    fn passive_items_come_first_and_separately() {
        let checks = vec![
            check("observer", |m| m.technique = Technique::Passive),
            check("prober", |m| m.technique = Technique::Reflected),
        ];

        let out = plan(&[point("p0", "q")], &[], &checks, &ScanProfile::default());

        assert_eq!(ids(&out.passive), vec!["observer".to_string()]);
        assert_eq!(ids(&out.active), vec!["prober".to_string()]);
    }

    /// Coordinator decision 4 (spec D4): a `node`-scoped check runs once per
    /// site node and an `origin`-scoped one once per origin, whatever the
    /// number of points.
    #[test]
    fn origin_and_node_scoped_checks_run_once() {
        let checks = vec![
            check("per-point", |m| m.scope = CheckScope::Point),
            check("per-node", |m| m.scope = CheckScope::Node),
            check("per-origin", |m| m.scope = CheckScope::Origin),
        ];
        let nodes = vec![node("n1", "a.test", 2), node("n2", "a.test", 1)];
        let points: Vec<InsertionPoint> = ["n1", "n1", "n2"]
            .iter()
            .enumerate()
            .map(|(i, node_id)| InsertionPoint {
                site_node: Some(node_id.to_string()),
                ..point(&format!("p{i}"), "q")
            })
            .collect();

        let out = plan(&points, &nodes, &checks, &ScanProfile::default());

        assert_eq!(count_for(&out.active, "per-point"), 3);
        assert_eq!(count_for(&out.active, "per-node"), 2);
        assert_eq!(count_for(&out.active, "per-origin"), 1);

        let two_origins = vec![node("n1", "a.test", 2), node("n2", "b.test", 1)];
        let out = plan(&points, &two_origins, &checks, &ScanProfile::default());
        assert_eq!(count_for(&out.active, "per-origin"), 2);
        assert_eq!(count_for(&out.active, "per-node"), 2);
    }

    /// Spec D4: exposure comes from the node's point count, interest from the
    /// point's method and the node's authentication.
    #[test]
    fn priority_uses_node_exposure_and_point_interest() {
        let checks = vec![check("probe", |_| {})];
        let mut busy = node("n1", "a.test", 4);
        busy.auth = true;
        let quiet = node("n2", "a.test", 1);

        let points = vec![
            InsertionPoint {
                site_node: Some("n1".to_string()),
                method: Some("POST".to_string()),
                ..point("p0", "q")
            },
            InsertionPoint {
                site_node: Some("n2".to_string()),
                ..point("p1", "r")
            },
        ];

        let out = plan(&points, &[busy, quiet], &checks, &ScanProfile::default());

        // p0: exposure 4/4 = 1.0, interest 0.6 (POST) + 0.1 (auth) = 0.7.
        assert!((out.active[0].priority - 0.94).abs() < 1e-6);
        // p1: exposure 1/4 = 0.25, interest 0.3 (GET).
        assert!((out.active[1].priority - 0.26).abs() < 1e-6);
        assert_eq!(
            pairs(&out.active),
            vec![("probe".to_string(), 0), ("probe".to_string(), 1)],
            "equal cost, so the higher priority goes first"
        );
    }

    /// Spec D2: `Speed` maps to payload caps and `Accuracy` to blind repeats.
    #[test]
    fn caps_and_repeats() {
        assert_eq!(payload_cap(Speed::Fast, Technique::Boolean), 2);
        assert_eq!(payload_cap(Speed::Normal, Technique::Boolean), 4);
        assert_eq!(payload_cap(Speed::Thorough, Technique::Boolean), 8);

        assert_eq!(payload_cap(Speed::Fast, Technique::Timing), 2);
        assert_eq!(payload_cap(Speed::Normal, Technique::Timing), 3);
        assert_eq!(payload_cap(Speed::Thorough, Technique::Timing), 5);

        assert_eq!(payload_cap(Speed::Fast, Technique::Reflected), 8);
        assert_eq!(payload_cap(Speed::Normal, Technique::Reflected), 25);
        assert_eq!(payload_cap(Speed::Thorough, Technique::Reflected), u32::MAX);

        assert_eq!(repeats(Accuracy::FewerFalseNegatives), 1);
        assert_eq!(repeats(Accuracy::Normal), 2);
        assert_eq!(repeats(Accuracy::FewerFalsePositives), 3);
    }

    /// Spec D2 `audit.ignore`: a rule matches when every key it sets matches,
    /// and a matched point is counted once in `skipped.ignored`.
    #[test]
    fn ignore_rules_match_on_every_present_key() {
        use aitm_scan_model::IgnoreRule;

        let checks = vec![check("a", |_| {}), check("b", |_| {})];
        let points = vec![point("p0", "csrf_token"), point("p1", "q")];

        let mut profile = ScanProfile::default();
        profile.audit.ignore = vec![IgnoreRule {
            kind: Some(InsertionKind::Query),
            name_regex: Some("^csrf_".to_string()),
            point_trait: None,
        }];

        let out = plan(&points, &[], &checks, &profile);

        assert_eq!(pairs(&out.active).len(), 2, "only p1 is audited");
        assert!(out.active.iter().all(|i| i.point == 1));
        assert_eq!(out.skipped.ignored, 1, "one point, not one item");

        profile.audit.ignore = vec![IgnoreRule {
            kind: Some(InsertionKind::Header),
            name_regex: Some("^csrf_".to_string()),
            point_trait: None,
        }];
        assert_eq!(
            plan(&points, &[], &checks, &profile).skipped.ignored,
            0,
            "a rule whose kind does not match leaves the point alone"
        );
    }
}
