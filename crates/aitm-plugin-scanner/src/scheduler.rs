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
//! passive phase runs before the active one. Amendment 38 adds one rule on top:
//! an origin-scoped HTTP check is scheduled once per *origin* — the profile's
//! targets plus every origin a discovered point belongs to — against a
//! synthetic point in [`SchedulePlan::origin_points`], so a target where
//! discovery found nothing still gets its origin checks.
//!
//! Nothing here sends, charges or decides policy: the scheduler reads metadata
//! and returns a plan. The budget, the scope guard and the agent gate are the
//! worker's, and they apply whatever this plan says.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use aitm_scan_model::{
    Accuracy, Check, CheckCost, CheckMeta, CheckScope, IgnoreRule, InsertionKind, InsertionPoint,
    LaneKind, PointTrait, ScanProfile, SiteNode, SkippedPoints, Speed, Technique,
};

/// One check to run against one insertion point.
pub struct ScheduleItem {
    /// Index into the `points` slice [`plan`] was given, or, when it is
    /// `>= points.len()`, into [`SchedulePlan::origin_points`] at
    /// `point - points.len()` (amendment 38). Resolve it with
    /// [`SchedulePlan::point_at`] rather than indexing either slice.
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
    /// One synthetic point per origin in the job's origin set, addressed by
    /// `ScheduleItem::point - points.len()` (amendment 38). An origin-scoped
    /// HTTP check runs against these, not against a discovered point, so a
    /// target with no insertion points at all still gets its origin checks.
    pub origin_points: Vec<InsertionPoint>,
}

impl SchedulePlan {
    /// The insertion point a [`ScheduleItem::point`] index names: a discovered
    /// point when `index < points.len()`, else the origin item at
    /// `index - points.len()`. `None` when the index addresses neither.
    ///
    /// `points` must be the same slice [`plan`] was given.
    pub fn point_at<'a>(
        &'a self,
        points: &'a [InsertionPoint],
        index: usize,
    ) -> Option<&'a InsertionPoint> {
        match points.get(index) {
            Some(point) => Some(point),
            None => self.origin_points.get(index - points.len()),
        }
    }
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
        // `skipped.frequent` counts points, like `skipped.ignored`, so a point
        // losing three heavy checks to the frequent rule is one skipped point.
        let mut frequent_dropped = false;
        for check in checks {
            let meta = check.meta();

            // Amendment 38: an origin-scoped HTTP check is driven by the origin
            // set below, never by a point, so it claims no slot here.
            if origin_driven(meta) {
                continue;
            }
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
                frequent_dropped = true;
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

        if frequent_dropped {
            out.skipped.frequent += 1;
        }
        if session_blocked {
            out.skipped.ignored += 1;
        }
    }

    // Amendment 38 (spec D4/D8): one item per origin for every origin-scoped
    // HTTP check, whether or not a point was discovered there. An origin is not
    // a point, so only `intensity` gates these.
    for (offset, (key, on_origin)) in origin_set(profile, points, nodes, &by_id)
        .into_iter()
        .enumerate()
    {
        let score = priority(
            exposure(
                on_origin.iter().map(|n| n.points).max().unwrap_or(0),
                busiest,
            ),
            interest(Some("GET"), None, on_origin.iter().any(|n| n.auth)),
        );
        out.origin_points.push(origin_point(&key, &on_origin));

        for check in checks {
            let meta = check.meta();
            if !origin_driven(meta) || meta.intensity > profile.intensity {
                continue;
            }
            let item = ScheduleItem {
                point: points.len() + offset,
                check: Arc::clone(check),
                priority: score,
            };
            if meta.technique == Technique::Passive {
                out.passive.push(item);
            } else {
                out.active.push(item);
            }
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
///
/// An origin-scoped **HTTP** check never reaches this: amendment 38 drives it
/// from the origin set instead, so the point loop skips it before asking for a
/// slot. The `CheckScope::Origin` arm below serves the other lanes.
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
        return node_origin_key(node);
    }
    if let Some(key) = point
        .url
        .as_deref()
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|parsed| url_origin_key(&parsed))
    {
        return key;
    }
    format!("point:{}", point.id)
}

/// Whether a check is driven by the origin set rather than by points:
/// `scope: origin` on the HTTP lane (amendment 38). An origin-scoped check of
/// another lane keeps the point-derived rule, where the first admissible point
/// of each origin claims the check's single slot.
fn origin_driven(meta: &CheckMeta) -> bool {
    meta.scope == CheckScope::Origin && meta.lanes.contains(&LaneKind::Http)
}

/// A site node's origin, `scheme://host:port`.
fn node_origin_key(node: &SiteNode) -> String {
    format!("{}://{}:{}", node.scheme, node.host, node.port)
}

/// A URL's origin, `scheme://host:port`, with the scheme's default port filled
/// in; `None` for a URL without a host. The one spelling of the key the origin
/// set dedupes on, so a node, a point URL and a profile target agree.
fn url_origin_key(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    let port = url.port_or_known_default().unwrap_or(0);
    Some(format!("{}://{}:{}", url.scheme(), host, port))
}

/// A profile target origin's key, `scheme://host:port` with the default port
/// filled in. Unlike [`crate::util::normalize_origin`] (which keeps only an
/// explicit port), this is the origin set's key form. A target that does not
/// parse as a URL is used verbatim, so it is never silently dropped.
fn target_origin_key(origin: &str) -> String {
    url::Url::parse(origin)
        .ok()
        .and_then(|parsed| url_origin_key(&parsed))
        .unwrap_or_else(|| origin.to_string())
}

/// The origins an origin-scoped HTTP check runs against, each with the site
/// nodes found on it: the profile's target origins in profile order, then every
/// origin a point that survives the `audit.kinds` and `audit.ignore` gates
/// belongs to. First-seen order, so the set is deterministic.
fn origin_set<'a>(
    profile: &ScanProfile,
    points: &[InsertionPoint],
    nodes: &'a [SiteNode],
    by_id: &HashMap<&str, &'a SiteNode>,
) -> Vec<(String, Vec<&'a SiteNode>)> {
    let mut keys: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for origin in &profile.target.origins {
        let key = target_origin_key(origin);
        if seen.insert(key.clone()) {
            keys.push(key);
        }
    }
    for point in points {
        if !profile.audit.kinds.contains(&point.kind) {
            continue;
        }
        if profile.audit.ignore.iter().any(|rule| ignores(rule, point)) {
            continue;
        }
        let node = point
            .site_node
            .as_deref()
            .and_then(|id| by_id.get(id).copied());
        let key = origin_key(point, node);
        if seen.insert(key.clone()) {
            keys.push(key);
        }
    }

    keys.into_iter()
        .map(|key| {
            let on_origin = nodes.iter().filter(|n| node_origin_key(n) == key).collect();
            (key, on_origin)
        })
        .collect()
}

/// The synthetic point that stands for one origin (amendment 38).
///
/// It is `GET <origin>/`: the interim lane builds a probe host over it, and
/// nothing injects into it. The kind is cosmetic — origin items bypass every
/// point gate — so nothing may branch on it.
fn origin_point(key: &str, nodes: &[&SiteNode]) -> InsertionPoint {
    InsertionPoint {
        id: format!("origin:{key}"),
        lane: LaneKind::Http,
        kind: InsertionKind::PathSegment,
        name: "/".to_string(),
        path: Some("/".to_string()),
        example: None,
        flow: None,
        site_node: nodes
            .iter()
            .find(|n| n.path_template == "/")
            .map(|n| n.id.clone()),
        traits: Vec::new(),
        frequency: 1,
        method: Some("GET".to_string()),
        url: Some(format!("{key}/")),
    }
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

    /// Wave-2/3 quality fix: `skipped.frequent` counts *points*, like
    /// `skipped.ignored`, not the items dropped from them — one frequent point
    /// losing three medium checks is one skipped point, not three.
    #[test]
    fn frequent_is_counted_once_per_point() {
        let checks = vec![
            check("M1", |m| m.cost = CheckCost::Medium),
            check("M2", |m| m.cost = CheckCost::Medium),
            check("M3", |m| m.cost = CheckCost::Medium),
        ];
        let mut frequent = point("p0", "q");
        frequent.frequency = 9;

        let out = plan(&[frequent], &[], &checks, &ScanProfile::default());

        assert!(out.active.is_empty(), "{:?}", ids(&out.active));
        assert_eq!(out.skipped.frequent, 1, "one point, however many items");
        assert!(out
            .frequent
            .contains(&(InsertionKind::Query, "q".to_string())));
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

    /// A packet-lane point as `aitm-scan-l4-packet`'s discovery mints one:
    /// `l4` lane, `l4_field` kind, no method, an `udp://` url and its target's
    /// site node (`l4:<ip>:<port>/<proto>`).
    fn l4_point(id: &str, name: &str, node: Option<&str>) -> InsertionPoint {
        InsertionPoint {
            id: id.to_string(),
            lane: LaneKind::L4Packet,
            kind: InsertionKind::L4Field,
            name: name.to_string(),
            site_node: node.map(ToString::to_string),
            method: None,
            url: Some("udp://127.0.0.1:9".to_string()),
            ..point(id, name)
        }
    }

    /// A packet-lane site node as that discovery emits one.
    fn l4_node(id: &str, port: u16, points: u32) -> SiteNode {
        SiteNode {
            scheme: "udp".to_string(),
            host: "127.0.0.1".to_string(),
            port,
            path_template: "/".to_string(),
            method: String::new(),
            ..node(id, "127.0.0.1", points)
        }
    }

    /// A packet-lane check: `l4` lane, `l4_field` kind, intrusive, heavy,
    /// point-scoped — the meta `aitm_scan_l4_packet::checks` declares.
    fn l4_check(id: &str) -> Arc<dyn Check> {
        check(id, |meta| {
            meta.lanes = vec![LaneKind::L4Packet];
            meta.kinds = vec![InsertionKind::L4Field];
            meta.intensity = aitm_scan_model::Intensity::Intrusive;
            meta.cost = CheckCost::Heavy;
            meta.scope = CheckScope::Point;
        })
    }

    /// Tester (stage 5), task 4b: the packet lane's site nodes are what give
    /// its points any exposure at all. `plan` looks a point's node up by
    /// `site_node` and scores `exposure(node.points, busiest)`, so before
    /// discovery emitted nodes every L4 point scored exposure 0 and the whole
    /// lane sorted below every HTTP point — on top of the issue placement
    /// (`location.l4` null) the missing node cost. With the nodes in place a
    /// 14-field target outranks a 2-field one, and a point whose node is
    /// missing from the node list still schedules, at exposure 0.
    ///
    /// Mutation: return `Discovery { nodes: Vec::new(), .. }` from the lane's
    /// `discover_all` (the state before commit ef950434) and all three
    /// priorities collapse to 0.06.
    #[test]
    fn l4_points_take_their_exposure_from_their_targets_site_node() {
        let checks = vec![l4_check("l4-crash")];
        let busy = l4_node("l4:127.0.0.1:9/udp", 9, 14);
        let quiet = l4_node("l4:127.0.0.1:80/tcp", 80, 2);
        let points = vec![
            l4_point("l4:127.0.0.1:9/udp/raw", "raw", Some("l4:127.0.0.1:9/udp")),
            l4_point(
                "l4:127.0.0.1:80/tcp/raw",
                "raw",
                Some("l4:127.0.0.1:80/tcp"),
            ),
            l4_point("l4:127.0.0.1:7/udp/raw", "raw", None),
        ];
        let profile = ScanProfile {
            intensity: aitm_scan_model::Intensity::Intrusive,
            ..ScanProfile::default()
        };

        let out = plan(&points, &[busy, quiet], &checks, &profile);

        assert_eq!(out.active.len(), 3, "every L4 point is scheduled");
        // interest is 0.2 * 0.3 = 0.06 for all three (no method, no auth), so
        // the spread is exposure alone.
        assert!(
            (out.active[0].priority - (0.8 + 0.06)).abs() < 1e-6,
            "the 14-field target is at full exposure: {}",
            out.active[0].priority
        );
        assert!(
            (out.active[1].priority - (0.8 * (2.0 / 14.0) + 0.06)).abs() < 1e-6,
            "the 2-field target is at 2/14: {}",
            out.active[1].priority
        );
        assert!(
            (out.active[2].priority - 0.06).abs() < 1e-6,
            "a point with no node in the list scores exposure 0: {}",
            out.active[2].priority
        );
        assert_eq!(
            pairs(&out.active),
            vec![
                ("l4-crash".to_string(), 0),
                ("l4-crash".to_string(), 1),
                ("l4-crash".to_string(), 2),
            ],
            "equal cost, so exposure orders them"
        );
        assert!(
            out.passive.is_empty(),
            "the packet lane has no passive check"
        );
    }

    /// Tester (stage 5), task 4b (rig run with zero cases): both packet-lane
    /// checks are `Intrusive`, and `plan` drops every check whose intensity is
    /// **above the profile's**. The default profile is `Medium`, so a job that
    /// does not ask for `intrusive` schedules nothing on an L4 point, finishes
    /// `done` and sends not one frame — which is exactly what the first
    /// real-bus T5 cells did until they set the intensity (commit 9d086234).
    /// Pinned here so the engine-side half of that trap has a test.
    ///
    /// Mutation: change `meta.intensity > profile.intensity` to `>=` and the
    /// intrusive half schedules nothing; drop the comparison and the medium
    /// half schedules the check.
    #[test]
    fn an_intrusive_l4_check_needs_an_intrusive_profile() {
        let checks = vec![l4_check("l4-crash")];
        let node = l4_node("l4:127.0.0.1:9/udp", 9, 14);
        let points = vec![l4_point(
            "l4:127.0.0.1:9/udp/raw",
            "raw",
            Some("l4:127.0.0.1:9/udp"),
        )];

        let medium = ScanProfile::default();
        assert_eq!(medium.intensity, aitm_scan_model::Intensity::Medium);
        let out = plan(&points, std::slice::from_ref(&node), &checks, &medium);
        assert!(
            out.active.is_empty() && out.passive.is_empty(),
            "a medium job runs no intrusive packet-lane check: {:?}",
            pairs(&out.active)
        );

        let intrusive = ScanProfile {
            intensity: aitm_scan_model::Intensity::Intrusive,
            ..ScanProfile::default()
        };
        let out = plan(&points, std::slice::from_ref(&node), &checks, &intrusive);
        assert_eq!(ids(&out.active), vec!["l4-crash".to_string()]);
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

    // ---- tester additions ---------------------------------------------------

    /// Coordinator decision 4, the edges: a point with no site node is its own
    /// node, an origin is read from the URL when the node is missing, and a
    /// point with neither is its own origin — so an unattributable point is
    /// never folded into another's single run.
    #[test]
    fn scope_keys_without_nodes_fall_back_to_url_then_point() {
        let checks = vec![
            check("per-node", |m| m.scope = CheckScope::Node),
            check("per-origin", |m| m.scope = CheckScope::Origin),
        ];
        // Two node-less points on one origin (by URL), one on another origin,
        // one with no URL at all.
        let mut p0 = point("p0", "a");
        p0.url = Some("http://a.test:8080/x".to_string());
        let mut p1 = point("p1", "b");
        p1.url = Some("http://a.test:8080/y".to_string());
        let mut p2 = point("p2", "c");
        p2.url = Some("https://b.test/".to_string());
        let mut p3 = point("p3", "d");
        p3.url = None;
        let points = vec![p0, p1, p2, p3];

        let out = plan(&points, &[], &checks, &ScanProfile::default());

        assert_eq!(
            count_for(&out.active, "per-node"),
            4,
            "a node-less point is its own node"
        );
        assert_eq!(
            count_for(&out.active, "per-origin"),
            3,
            "a.test:8080 once (from the URL), b.test once, the url-less point once"
        );
        // Amendment 38: the origin items are addressed past the end of the
        // four points, one per origin, in first-seen order.
        assert_eq!(
            indices_for(&out.active, "per-origin"),
            vec![4, 5, 6],
            "an origin item is not a point item"
        );
        assert_eq!(
            out.origin_points
                .iter()
                .map(|p| p.id.clone())
                .collect::<Vec<_>>(),
            vec![
                "origin:http://a.test:8080".to_string(),
                "origin:https://b.test:443".to_string(),
                "origin:point:p3".to_string(),
            ],
            "the origin comes from the URL, and a url-less point is its own origin"
        );
    }

    /// Spec D2 `audit.ignore`: a `name_regex` that does not compile matches
    /// nothing, so a typo cannot take the whole audit out; a `point_trait`
    /// key matches only a point carrying that trait.
    #[test]
    fn a_malformed_ignore_regex_matches_nothing_and_traits_match_exactly() {
        let checks = vec![check("a", |_| {})];
        let mut url_point = point("p0", "next");
        url_point.traits = vec![PointTrait::Url];
        let points = vec![url_point, point("p1", "q")];

        let mut profile = ScanProfile::default();
        profile.audit.ignore = vec![IgnoreRule {
            kind: None,
            name_regex: Some("(".to_string()),
            point_trait: None,
        }];
        let out = plan(&points, &[], &checks, &profile);
        assert_eq!(out.active.len(), 2, "a broken regex ignores nothing");
        assert_eq!(out.skipped.ignored, 0);

        profile.audit.ignore = vec![IgnoreRule {
            kind: None,
            name_regex: None,
            point_trait: Some(PointTrait::Url),
        }];
        let out = plan(&points, &[], &checks, &profile);
        assert_eq!(
            pairs(&out.active),
            vec![("a".to_string(), 1)],
            "only the url-trait point is ignored"
        );
        assert_eq!(out.skipped.ignored, 1);

        // No points, no nodes: an empty plan, not a panic on the empty maximum.
        let empty = plan(&[], &[], &checks, &profile);
        assert!(empty.active.is_empty() && empty.passive.is_empty());
        assert_eq!(empty.skipped.ignored, 0);
        assert_eq!(empty.skipped.frequent, 0);
        assert!(empty.frequent.is_empty());
    }

    // ---- amendment 38: origin items -----------------------------------------

    /// A profile whose `target.origins` names `origins`, defaults otherwise.
    fn profile_with_origins(origins: &[&str]) -> ScanProfile {
        let mut profile = ScanProfile::default();
        profile.target.origins = origins.iter().map(|o| o.to_string()).collect();
        profile
    }

    /// The `point` indices a given check id was scheduled against, in order.
    fn indices_for(items: &[ScheduleItem], id: &str) -> Vec<usize> {
        items
            .iter()
            .filter(|i| i.check.meta().id == id)
            .map(|i| i.point)
            .collect()
    }

    /// Amendment 38 (spec D4/D8): an origin-scoped HTTP check is scheduled once
    /// per target origin whether or not any insertion point was discovered
    /// there — a parameterless site still gets its origin checks.
    #[test]
    fn origin_scoped_checks_run_once_per_target_origin_without_points() {
        let checks = vec![
            check("origin.check", |m| m.scope = CheckScope::Origin),
            check("point.check", |m| m.scope = CheckScope::Point),
        ];
        let profile = profile_with_origins(&["http://a.test:8080"]);

        let out = plan(&[], &[], &checks, &profile);

        assert_eq!(ids(&out.active), vec!["origin.check".to_string()]);
        assert_eq!(out.active[0].point, 0);
        assert_eq!(out.origin_points.len(), 1);
        let item = out.point_at(&[], 0).expect("the origin item resolves");
        assert_eq!(item.url.as_deref(), Some("http://a.test:8080/"));
        assert_eq!(item.id, "origin:http://a.test:8080");
    }

    /// Amendment 38: the origin set is the profile's targets plus every origin
    /// a discovered point belongs to, and each gets exactly one item, addressed
    /// past the end of `points`.
    #[test]
    fn origin_scoped_checks_run_once_per_origin_with_points_on_two_origins() {
        let checks = vec![
            check("origin.check", |m| m.scope = CheckScope::Origin),
            check("point.check", |m| m.scope = CheckScope::Point),
        ];
        let nodes = vec![node("n1", "a.test", 2), node("n2", "b.test", 1)];
        let points: Vec<InsertionPoint> = ["n1", "n1", "n2"]
            .iter()
            .enumerate()
            .map(|(i, node_id)| InsertionPoint {
                site_node: Some(node_id.to_string()),
                ..point(&format!("p{i}"), "q")
            })
            .collect();
        let profile = profile_with_origins(&["http://a.test:8080"]);

        let out = plan(&points, &nodes, &checks, &profile);

        assert_eq!(count_for(&out.active, "origin.check"), 2, "one per origin");
        assert_eq!(count_for(&out.active, "point.check"), 3, "one per point");
        assert_eq!(
            indices_for(&out.active, "origin.check"),
            vec![3, 4],
            "origin items are addressed past the end of the points slice"
        );
        assert_eq!(out.origin_points.len(), 2);
        assert_eq!(
            out.point_at(&points, 3).map(|p| p.id.clone()),
            Some("origin:http://a.test:8080".to_string())
        );
        assert_eq!(
            out.point_at(&points, 4).map(|p| p.id.clone()),
            Some("origin:http://b.test:8080".to_string())
        );
        assert_eq!(
            out.point_at(&points, 0).map(|p| p.id.clone()),
            Some("p0".to_string()),
            "an index inside the slice still resolves to a real point"
        );
        assert!(out.point_at(&points, 5).is_none(), "nothing past the end");
    }

    /// Amendment 38: an origin is not a point, so the kind, trait and session
    /// gates do not apply to its items — but `intensity` still does.
    #[test]
    fn origin_items_ignore_point_gates_but_respect_intensity() {
        let profile = profile_with_origins(&["http://a.test:8080"]);

        let loud = vec![check("origin.loud", |m| {
            m.scope = CheckScope::Origin;
            m.intensity = aitm_scan_model::Intensity::Intrusive;
        })];
        let out = plan(&[], &[], &loud, &profile);
        assert!(
            out.active.is_empty() && out.passive.is_empty(),
            "an over-intense check schedules nothing: {:?}",
            ids(&out.active)
        );
        assert_eq!(out.origin_points.len(), 1, "the origin is still known");

        let gated = vec![
            check("origin.cookie", |m| {
                m.scope = CheckScope::Origin;
                m.kinds = vec![InsertionKind::Cookie];
            }),
            check("origin.wants-url", |m| {
                m.scope = CheckScope::Origin;
                m.wants_traits = Some(vec![PointTrait::Url]);
            }),
        ];
        let out = plan(&[], &[], &gated, &profile);
        assert_eq!(
            ids(&out.active),
            vec!["origin.cookie".to_string(), "origin.wants-url".to_string()],
            "neither the kinds gate nor wants_traits applies to an origin"
        );
    }

    /// Amendment 38 and call C2: only the **HTTP** lane's origin-scoped checks
    /// moved to the origin set. An origin-scoped check of another lane keeps
    /// the point-derived rule — the first admissible point of each origin
    /// claims its single slot — so its item still addresses a real point.
    #[test]
    fn an_origin_scoped_check_of_another_lane_keeps_the_point_rule() {
        let checks = vec![
            check("ws.origin", |m| {
                m.scope = CheckScope::Origin;
                m.lanes = vec![LaneKind::Ws];
                m.kinds = vec![InsertionKind::WsText];
            }),
            check("http.origin", |m| m.scope = CheckScope::Origin),
        ];
        let ws_points: Vec<InsertionPoint> = (0..2)
            .map(|i| InsertionPoint {
                lane: LaneKind::Ws,
                kind: InsertionKind::WsText,
                ..point(&format!("w{i}"), "frame")
            })
            .collect();
        let profile = profile_with_origins(&["http://a.test:8080"]);

        let out = plan(&ws_points, &[], &checks, &profile);

        assert_eq!(
            indices_for(&out.active, "ws.origin"),
            vec![0],
            "a WebSocket origin check runs on a point, not on an origin item"
        );
        assert_eq!(
            indices_for(&out.active, "http.origin"),
            vec![2, 3],
            "the HTTP origin check runs once per origin, past the points"
        );
        assert_eq!(
            out.origin_points
                .iter()
                .map(|p| p.id.clone())
                .collect::<Vec<_>>(),
            vec![
                "origin:http://a.test:8080".to_string(),
                "origin:http://127.0.0.1:8080".to_string(),
            ],
            "the target origin first, then the origin the points belong to"
        );
    }

    /// Amendment 38: the origin set is normalized before it is deduplicated,
    /// so a target written without its default port and the same origin
    /// reached through a discovered point are one origin, not two — and an
    /// origin that is not a URL is still kept, verbatim, rather than dropped.
    #[test]
    fn the_origin_set_normalizes_default_ports_and_dedupes() {
        let checks = vec![check("origin.check", |m| m.scope = CheckScope::Origin)];
        let mut on_a = point("p0", "q");
        on_a.url = Some("http://a.test/path?q=1".to_string());
        let points = vec![on_a];
        let profile =
            profile_with_origins(&["http://a.test", "http://a.test:80/deep", "not a url", ""]);

        let out = plan(&points, &[], &checks, &profile);

        assert_eq!(
            out.origin_points
                .iter()
                .map(|p| p.id.clone())
                .collect::<Vec<_>>(),
            vec![
                "origin:http://a.test:80".to_string(),
                "origin:not a url".to_string(),
                "origin:".to_string(),
            ],
            "the default port is filled in, so the three spellings of a.test are one origin; \
             a malformed or empty origin is kept verbatim for the lane to refuse, not dropped \
             and not a panic"
        );
        assert_eq!(count_for(&out.active, "origin.check"), 3);
        assert_eq!(
            out.point_at(&points, 1).and_then(|p| p.url.clone()),
            Some("http://a.test:80/".to_string())
        );
    }

    /// Amendment 38: an origin item is scheduled by technique like any other —
    /// a passive origin-scoped check belongs to the passive phase, which runs
    /// over captured flows, not to the active one.
    #[test]
    fn a_passive_origin_scoped_check_runs_in_the_passive_phase() {
        let checks = vec![
            check("origin.passive", |m| {
                m.scope = CheckScope::Origin;
                m.technique = Technique::Passive;
            }),
            check("origin.active", |m| m.scope = CheckScope::Origin),
        ];
        let profile = profile_with_origins(&["http://a.test:8080"]);

        let out = plan(&[], &[], &checks, &profile);

        assert_eq!(ids(&out.passive), vec!["origin.passive".to_string()]);
        assert_eq!(ids(&out.active), vec!["origin.active".to_string()]);
        assert_eq!(out.passive[0].point, 0, "both address the one origin item");
        assert_eq!(out.active[0].point, 0);
    }

    /// The frequent-point rule is a strict `>` on the threshold, and a frequent
    /// point still gets every light check — including passive ones, which run
    /// in their own phase.
    #[test]
    fn frequent_threshold_is_strict_and_light_passives_survive() {
        let checks = vec![
            check("light-active", |m| m.cost = CheckCost::Light),
            check("heavy-active", |m| m.cost = CheckCost::Heavy),
            check("light-passive", |m| {
                m.cost = CheckCost::Light;
                m.technique = Technique::Passive;
            }),
        ];
        let threshold = ScanProfile::default().audit.frequent_point_threshold;

        let mut at = point("p0", "q");
        at.frequency = threshold;
        let out = plan(&[at], &[], &checks, &ScanProfile::default());
        assert_eq!(
            out.skipped.frequent, 0,
            "exactly the threshold is not frequent"
        );
        assert!(out.frequent.is_empty());
        assert_eq!(count_for(&out.active, "heavy-active"), 1);

        let mut over = point("p0", "q");
        over.frequency = threshold + 1;
        let out = plan(&[over], &[], &checks, &ScanProfile::default());
        assert_eq!(out.skipped.frequent, 1, "one heavy item dropped");
        assert_eq!(ids(&out.active), vec!["light-active".to_string()]);
        assert_eq!(ids(&out.passive), vec!["light-passive".to_string()]);
        assert!(out
            .frequent
            .contains(&(InsertionKind::Query, "q".to_string())));
    }
}
