//! The one check catalogue: native checks and Rhai checks (spec D4). Task 10
//! of the T1b plan fills it.
//!
//! Everything a job can run lives in one [`Catalogue`]: the checks each lane
//! ships through `Lane::checks()`, the `native_checks` slot the binary fills
//! (`aitm-scan-checks-http`), and the Rhai checks the scripting tier registered
//! in the model's `CheckRegistry`. `scan.checks` renders it, the scheduler
//! reasons over it, and the engine registers one manual `check.<id>` command
//! per entry.
//!
//! **Source precedence is explicit** (wave-1 security review): native sources
//! first — the lanes in the order the binary collected them, then the
//! `native_checks` slot — then bundled scripts, then the operator's custom
//! scripts. One id belongs to the first source that claims it, so which source
//! wins never depends on the order scripts happened to load in, and a script
//! cannot take over a native check's id by being loaded late. A later claim is
//! refused and recorded in [`Catalogue::conflicts`], naming both sources, so a
//! squatted id is reported at load time rather than silently dropped.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use aitm_scan_model::{
    scan_error, Check, CheckMeta, CheckOrigin, CheckRegistry, CheckSelection, Lane, LaneKind,
    ScanErrorCode,
};

/// Every check one job can run, deduped by id and sorted by id.
pub struct Catalogue {
    /// The entries, sorted by `meta().id`.
    entries: Vec<Arc<dyn Check>>,
    /// The ids a later source claimed and was refused.
    conflicts: Vec<CheckConflict>,
}

/// A check id two sources claimed: the first source kept it, the second was
/// refused (spec D4, wave-1 security review).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckConflict {
    /// The contested check id.
    pub id: String,
    /// The source that owns the id in the assembled catalogue.
    pub kept: String,
    /// The source whose check was left out.
    pub refused: String,
}

impl fmt::Display for CheckConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "check `{}` from `{}` was refused: `{}` already owns that id",
            self.id, self.refused, self.kept
        )
    }
}

/// One entry of a profile's `checks.include` / `checks.exclude` list.
///
/// `lane:<token>` is a lane selector; anything else is an id or a class, which
/// only the catalogue can tell apart, so [`Selector::parse`] reads a bare token
/// as an [`Selector::Id`] and the catalogue promotes it to [`Selector::Class`]
/// when no id matches (spec D3 `unknown_check`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// One check, by id.
    Id(String),
    /// Every check of one vulnerability class.
    Class(String),
    /// Every check of one lane.
    Lane(LaneKind),
}

impl Selector {
    /// Read one selector entry. Never fails: an entry that names nothing the
    /// catalogue knows is refused by [`Catalogue::validate_selection`], which
    /// can then quote the operator's text back verbatim.
    pub fn parse(s: &str) -> Selector {
        if let Some(token) = s.strip_prefix("lane:") {
            if let Some(lane) = lane_from_token(token) {
                return Selector::Lane(lane);
            }
        }
        Selector::Id(s.to_string())
    }
}

/// Assemble the catalogue from the lanes, the native slot and the script
/// registry, in that precedence order (spec D4).
///
/// Entries come out sorted by id. A source claiming an id an earlier source
/// already holds keeps nothing: its check is left out and the clash is
/// recorded in [`Catalogue::conflicts`].
pub fn assemble(
    lanes: &[Arc<dyn Lane>],
    native: &[Arc<dyn Check>],
    scripts: &CheckRegistry,
) -> Catalogue {
    let mut ordered: Vec<(String, Arc<dyn Check>)> = Vec::new();

    for lane in lanes {
        let source = format!("lane:{}", lane_token(lane.lane()));
        for check in lane.checks() {
            ordered.push((source.clone(), check));
        }
    }
    for check in native {
        ordered.push(("native".to_string(), Arc::clone(check)));
    }

    // The registry snapshot is id-sorted; a stable sort by source rank keeps
    // that order inside each rank, so assembly is deterministic.
    let mut from_scripts = scripts.snapshot();
    from_scripts.sort_by_key(|check| origin_rank(&check.meta().origin));
    for check in from_scripts {
        let source = source_label(&check.meta().origin);
        ordered.push((source, check));
    }

    let mut owner: HashMap<String, String> = HashMap::new();
    let mut entries: Vec<Arc<dyn Check>> = Vec::new();
    let mut conflicts: Vec<CheckConflict> = Vec::new();

    for (source, check) in ordered {
        let id = check.meta().id.clone();
        if let Some(kept) = owner.get(&id) {
            conflicts.push(CheckConflict {
                id,
                kept: kept.clone(),
                refused: source,
            });
            continue;
        }
        owner.insert(id, source);
        entries.push(check);
    }

    entries.sort_by(|a, b| a.meta().id.cmp(&b.meta().id));
    Catalogue { entries, conflicts }
}

impl Catalogue {
    /// Every entry's metadata, in catalogue (id) order — what `scan.checks`
    /// returns unfiltered.
    pub fn metas(&self) -> Vec<CheckMeta> {
        self.entries.iter().map(|c| c.meta().clone()).collect()
    }

    /// The check with this id, if the catalogue holds one.
    pub fn get(&self, id: &str) -> Option<Arc<dyn Check>> {
        self.entries
            .binary_search_by(|c| c.meta().id.as_str().cmp(id))
            .ok()
            .map(|at| Arc::clone(&self.entries[at]))
    }

    /// Every entry, in catalogue order.
    pub fn all(&self) -> &[Arc<dyn Check>] {
        &self.entries
    }

    /// The ids more than one source claimed, with both source names. Empty for
    /// a clean assembly; never empty silently — the engine reports these when
    /// it loads the catalogue.
    pub fn conflicts(&self) -> &[CheckConflict] {
        &self.conflicts
    }

    /// `scan.checks`' filters: lane, class and origin token (`native`,
    /// `bundled`, `custom`). An absent filter matches everything; an origin
    /// token the vocabulary does not know matches nothing.
    pub fn filter(
        &self,
        lane: Option<LaneKind>,
        class: Option<&str>,
        origin: Option<&str>,
    ) -> Vec<CheckMeta> {
        self.entries
            .iter()
            .map(|c| c.meta())
            .filter(|meta| lane.is_none_or(|l| meta.lanes.contains(&l)))
            .filter(|meta| class.is_none_or(|c| meta.class == c))
            .filter(|meta| origin.is_none_or(|o| origin_token(&meta.origin) == o))
            .cloned()
            .collect()
    }

    /// Refuse a selection naming anything this catalogue does not hold.
    ///
    /// Every include and exclude entry must be a known id, a known class or a
    /// valid `lane:` token; the first entry that is none of those fails with
    /// `scan: unknown_check: <entry>` (spec D3).
    pub fn validate_selection(&self, sel: &CheckSelection) -> anyhow::Result<()> {
        for entry in sel.include.iter().chain(sel.exclude.iter()) {
            if self.resolve(entry).is_none() {
                return Err(scan_error(ScanErrorCode::UnknownCheck, entry));
            }
        }
        Ok(())
    }

    /// The checks a profile's selection admits: an empty `include` means every
    /// entry, and `exclude` is applied afterwards (spec D2).
    ///
    /// An entry that resolves to nothing selects nothing; `scan.start` refuses
    /// such a selection through [`Catalogue::validate_selection`] first.
    pub fn selected(&self, sel: &CheckSelection) -> Vec<Arc<dyn Check>> {
        let include: Vec<Selector> = sel.include.iter().filter_map(|e| self.resolve(e)).collect();
        let exclude: Vec<Selector> = sel.exclude.iter().filter_map(|e| self.resolve(e)).collect();

        self.entries
            .iter()
            .filter(|check| {
                let meta = check.meta();
                let included = sel.include.is_empty() || include.iter().any(|s| selects(meta, s));
                included && !exclude.iter().any(|s| selects(meta, s))
            })
            .map(Arc::clone)
            .collect()
    }

    /// Decide a bare selector entry against this catalogue: a known id stays an
    /// id, a known class becomes a class, a valid `lane:` token is a lane, and
    /// anything else is unknown.
    fn resolve(&self, entry: &str) -> Option<Selector> {
        match Selector::parse(entry) {
            Selector::Lane(lane) => Some(Selector::Lane(lane)),
            Selector::Class(class) => Some(Selector::Class(class)),
            Selector::Id(token) => {
                if self.entries.iter().any(|c| c.meta().id == token) {
                    Some(Selector::Id(token))
                } else if self.entries.iter().any(|c| c.meta().class == token) {
                    Some(Selector::Class(token))
                } else {
                    None
                }
            }
        }
    }
}

impl fmt::Debug for Catalogue {
    /// Prints the ids and the conflicts, never the checks themselves.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids: Vec<&str> = self.entries.iter().map(|c| c.meta().id.as_str()).collect();
        f.debug_struct("Catalogue")
            .field("checks", &ids)
            .field("conflicts", &self.conflicts)
            .finish()
    }
}

/// Whether `meta` is picked by `selector`.
fn selects(meta: &CheckMeta, selector: &Selector) -> bool {
    match selector {
        Selector::Id(id) => &meta.id == id,
        Selector::Class(class) => &meta.class == class,
        Selector::Lane(lane) => meta.lanes.contains(lane),
    }
}

/// The `scan.checks` origin token for an origin: `native`, `bundled`, `custom`.
fn origin_token(origin: &CheckOrigin) -> &'static str {
    match origin {
        CheckOrigin::Native => "native",
        CheckOrigin::Bundled { .. } => "bundled",
        CheckOrigin::Custom { .. } => "custom",
    }
}

/// Precedence of a script entry: bundled before custom, and a script claiming
/// the `native` origin last of all — it is not a native check, and must never
/// outrank one.
fn origin_rank(origin: &CheckOrigin) -> u8 {
    match origin {
        CheckOrigin::Bundled { .. } => 0,
        CheckOrigin::Custom { .. } => 1,
        CheckOrigin::Native => 2,
    }
}

/// The source name a conflict report names: `native`, `bundled:<path>` or
/// `custom:<path>`.
fn source_label(origin: &CheckOrigin) -> String {
    match origin {
        CheckOrigin::Native => "native".to_string(),
        CheckOrigin::Bundled { path } => format!("bundled:{path}"),
        CheckOrigin::Custom { path } => format!("custom:{path}"),
    }
}

/// A lane's wire token (`http`, `ws`, `l4_packet`, `l4_stream`), taken from the
/// model's serde representation so selectors and the wire never diverge.
fn lane_token(lane: LaneKind) -> String {
    serde_json::to_value(lane)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{lane:?}").to_lowercase())
}

/// The lane a `lane:<token>` selector names, or `None` for an unknown token.
fn lane_from_token(token: &str) -> Option<LaneKind> {
    serde_json::from_value(serde_json::Value::String(token.to_string())).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use aitm_scan_model::testing::{null_meta, NullCheck};
    use aitm_scan_model::{
        Check, CheckMeta, CheckOrigin, CheckRegistry, CheckSelection, Discovery, InsertionPoint,
        JobCtx, Lane, LaneKind, ProbeHost, ProfileTarget,
    };
    use futures::future::BoxFuture;

    /// A check carrying the model's null meta for `id`, with `edit` applied.
    fn check(id: &str, edit: impl FnOnce(&mut CheckMeta)) -> Arc<dyn Check> {
        let mut meta = null_meta(id);
        edit(&mut meta);
        Arc::new(NullCheck::new(meta))
    }

    /// A bundled-origin script check.
    fn bundled(id: &str, path: &str) -> Arc<dyn Check> {
        check(id, |m| {
            m.origin = CheckOrigin::Bundled {
                path: path.to_string(),
            }
        })
    }

    /// A custom-origin (operator-written) script check.
    fn custom(id: &str, path: &str) -> Arc<dyn Check> {
        check(id, |m| {
            m.origin = CheckOrigin::Custom {
                path: path.to_string(),
            }
        })
    }

    /// A lane that discovers nothing and ships exactly the checks it holds.
    struct StubLane(Vec<Arc<dyn Check>>);

    impl Lane for StubLane {
        fn lane(&self) -> LaneKind {
            LaneKind::Http
        }
        fn discover<'a>(
            &'a self,
            _target: &'a ProfileTarget,
            _job: &'a dyn JobCtx,
        ) -> BoxFuture<'a, anyhow::Result<Discovery>> {
            Box::pin(async { Ok(Discovery::default()) })
        }
        fn probe_host_for(
            &self,
            _point: &InsertionPoint,
            _job: Arc<dyn JobCtx>,
        ) -> anyhow::Result<Box<dyn ProbeHost>> {
            Err(anyhow::anyhow!("the stub lane hosts no probes"))
        }
        fn checks(&self) -> Vec<Arc<dyn Check>> {
            self.0.clone()
        }
    }

    /// The catalogue's ids, in catalogue order.
    fn ids(catalogue: &Catalogue) -> Vec<String> {
        catalogue.metas().into_iter().map(|m| m.id).collect()
    }

    /// Coordinator (wave-1 security review): source precedence is explicit, so a
    /// squatted id never depends on load order. A custom script claiming an id a
    /// native check owns loses, and the clash is reported rather than dropped.
    #[test]
    fn catalogue_keeps_the_native_entry_and_reports_a_squatted_id() {
        let native = vec![check("x", |m| {
            m.description = "the native check".to_string()
        })];
        let scripts = CheckRegistry::new();
        scripts
            .add("scripts/mine/x.rhai", {
                let mut meta = null_meta("x");
                meta.description = "the squatting script".to_string();
                meta.origin = CheckOrigin::Custom {
                    path: "scripts/mine/x.rhai".to_string(),
                };
                Arc::new(NullCheck::new(meta))
            })
            .expect("the registry is empty");

        let catalogue = assemble(&[], &native, &scripts);

        assert_eq!(ids(&catalogue), vec!["x".to_string()]);
        assert_eq!(catalogue.metas()[0].description, "the native check");
        assert_eq!(
            catalogue.conflicts(),
            [CheckConflict {
                id: "x".to_string(),
                kept: "native".to_string(),
                refused: "custom:scripts/mine/x.rhai".to_string(),
            }]
        );
    }

    /// Spec D4: one catalogue out of the lanes' `checks()`, the `native_checks`
    /// slot and the Rhai registry, in that order, sorted by id.
    #[test]
    fn assemble_reads_lanes_then_native_then_scripts_sorted_by_id() {
        let lane: Arc<dyn Lane> = Arc::new(StubLane(vec![check("d-lane", |_| {})]));
        let native = vec![check("c-native", |_| {})];
        let scripts = CheckRegistry::new();
        scripts
            .add("bundled", bundled("a-bundled", "scripts/bundled/a.rhai"))
            .expect("new id");
        scripts
            .add("custom", custom("b-custom", "/home/op/b.rhai"))
            .expect("new id");

        let catalogue = assemble(&[lane], &native, &scripts);

        assert_eq!(
            ids(&catalogue),
            vec![
                "a-bundled".to_string(),
                "b-custom".to_string(),
                "c-native".to_string(),
                "d-lane".to_string(),
            ]
        );
        assert!(catalogue.conflicts().is_empty());
        assert_eq!(catalogue.all().len(), 4);
        assert_eq!(
            catalogue.get("d-lane").expect("the lane's check").meta().id,
            "d-lane"
        );
        assert!(catalogue.get("nope").is_none());
    }

    /// A bundled script beats a custom one for the same id, and a lane check
    /// beats both: precedence is native, then bundled, then custom.
    #[test]
    fn later_sources_never_take_an_id_from_an_earlier_one() {
        let lane: Arc<dyn Lane> = Arc::new(StubLane(vec![check("shared", |m| {
            m.description = "the lane's".to_string()
        })]));
        let scripts = CheckRegistry::new();
        scripts
            .add("custom", {
                let mut meta = null_meta("only-bundled-vs-custom");
                meta.description = "the custom one".to_string();
                meta.origin = CheckOrigin::Custom {
                    path: "/home/op/c.rhai".to_string(),
                };
                Arc::new(NullCheck::new(meta))
            })
            .expect("new id");
        scripts
            .add("bundled", {
                let mut meta = null_meta("shared");
                meta.description = "the bundled one".to_string();
                meta.origin = CheckOrigin::Bundled {
                    path: "scripts/bundled/s.rhai".to_string(),
                };
                Arc::new(NullCheck::new(meta))
            })
            .expect("new id");

        let catalogue = assemble(&[lane], &[], &scripts);

        assert_eq!(
            catalogue.get("shared").expect("kept").meta().description,
            "the lane's"
        );
        assert_eq!(
            catalogue.conflicts(),
            [CheckConflict {
                id: "shared".to_string(),
                kept: "lane:http".to_string(),
                refused: "bundled:scripts/bundled/s.rhai".to_string(),
            }]
        );
    }

    /// Spec D3 `scan.checks`: filter by lane, class and origin token.
    #[test]
    fn filter_narrows_by_lane_class_and_origin() {
        let native = vec![
            check("xss", |m| {
                m.class = "xss".to_string();
                m.lanes = vec![LaneKind::Http];
            }),
            check("ws-smuggle", |m| {
                m.class = "smuggling".to_string();
                m.lanes = vec![LaneKind::Ws];
            }),
        ];
        let scripts = CheckRegistry::new();
        scripts
            .add("bundled", bundled("sqli", "scripts/bundled/sqli.rhai"))
            .expect("new id");
        let catalogue = assemble(&[], &native, &scripts);

        let got = |lane, class, origin| -> Vec<String> {
            catalogue
                .filter(lane, class, origin)
                .into_iter()
                .map(|m| m.id)
                .collect()
        };

        assert_eq!(got(None, None, None).len(), 3);
        assert_eq!(
            got(Some(LaneKind::Http), None, None),
            vec!["sqli".to_string(), "xss".to_string()]
        );
        assert_eq!(
            got(None, Some("smuggling"), None),
            vec!["ws-smuggle".to_string()]
        );
        assert_eq!(got(None, None, Some("bundled")), vec!["sqli".to_string()]);
        assert_eq!(
            got(None, None, Some("native")),
            vec!["ws-smuggle".to_string(), "xss".to_string()]
        );
        assert!(got(None, None, Some("custom")).is_empty());
        assert!(got(Some(LaneKind::Ws), Some("xss"), None).is_empty());
    }

    /// Spec D3: every include/exclude entry names a known id, a known class or a
    /// valid `lane:` token; anything else is `scan: unknown_check: <entry>`.
    #[test]
    fn selectors_validate_against_the_catalogue() {
        let native = vec![
            check("reflected-xss", |m| m.class = "xss".to_string()),
            check("header-audit", |_| {}),
        ];
        let catalogue = assemble(&[], &native, &CheckRegistry::new());

        catalogue
            .validate_selection(&CheckSelection {
                include: vec![
                    "lane:http".to_string(),
                    "reflected-xss".to_string(),
                    "none".to_string(),
                ],
                exclude: Vec::new(),
            })
            .expect("a lane token, an id and a class all resolve");

        let err = catalogue
            .validate_selection(&CheckSelection {
                include: vec!["nope".to_string()],
                exclude: Vec::new(),
            })
            .expect_err("`nope` is neither an id, a class nor a lane");
        assert_eq!(err.to_string(), "scan: unknown_check: nope");

        let err = catalogue
            .validate_selection(&CheckSelection {
                include: Vec::new(),
                exclude: vec!["lane:carrier-pigeon".to_string()],
            })
            .expect_err("an unknown lane token is refused too");
        assert_eq!(err.to_string(), "scan: unknown_check: lane:carrier-pigeon");

        assert_eq!(Selector::parse("lane:ws"), Selector::Lane(LaneKind::Ws));
        assert_eq!(
            Selector::parse("lane:l4_stream"),
            Selector::Lane(LaneKind::L4Stream)
        );
        assert_eq!(
            Selector::parse("reflected-xss"),
            Selector::Id("reflected-xss".to_string())
        );
    }

    /// Spec D2 `checks: { include, exclude }`: an empty include means all, and
    /// excludes are applied after includes.
    #[test]
    fn selected_applies_include_then_exclude() {
        let native = vec![
            check("reflected-xss", |m| {
                m.class = "xss".to_string();
                m.lanes = vec![LaneKind::Http];
            }),
            check("stored-xss", |m| {
                m.class = "xss".to_string();
                m.lanes = vec![LaneKind::Http];
            }),
            check("ws-frame", |m| {
                m.class = "ws".to_string();
                m.lanes = vec![LaneKind::Ws];
            }),
        ];
        let catalogue = assemble(&[], &native, &CheckRegistry::new());

        let selected = |include: &[&str], exclude: &[&str]| -> Vec<String> {
            catalogue
                .selected(&CheckSelection {
                    include: include.iter().map(|s| s.to_string()).collect(),
                    exclude: exclude.iter().map(|s| s.to_string()).collect(),
                })
                .into_iter()
                .map(|c| c.meta().id.clone())
                .collect()
        };

        assert_eq!(
            selected(&[], &[]),
            vec![
                "reflected-xss".to_string(),
                "stored-xss".to_string(),
                "ws-frame".to_string()
            ],
            "an empty include is every check"
        );
        assert_eq!(
            selected(&["xss"], &[]),
            vec!["reflected-xss".to_string(), "stored-xss".to_string()],
            "a class selector takes the whole class"
        );
        assert_eq!(
            selected(&["lane:http"], &["stored-xss"]),
            vec!["reflected-xss".to_string()],
            "excludes are applied after includes"
        );
        assert!(
            selected(&[], &["lane:http", "ws-frame"]).is_empty(),
            "excluding everything selects nothing"
        );
    }
}
