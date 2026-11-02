//! Every `scan.*` verb of spec D3: one [`Command`] per row of the verb table.
//!
//! A verb here does three things and no more: it reads its typed arguments,
//! hands them to the engine module that owns the work ([`crate::profiles`],
//! [`crate::jobs`], [`crate::issues`], [`crate::session`]), and serialises the
//! model's result type onto the bus through [`util::json_to_value`]. No result
//! shaping lives in this file — the wire shapes are `aitm-scan-model`'s, which
//! is what every UI's contract fixture pins.
//!
//! Three rules are contract rather than taste:
//!
//! * **Every refusal is `scan: <code>: <message>`** built with
//!   [`aitm_scan_model::scan_error`], so a frontend matches on the code token
//!   and never on prose.
//! * **`scan.start` owes an agent the `refused_agent` code** (call B6). Under
//!   `agent.policy: auto` the MCP layer defers `scan.start` to the command, so
//!   the refusal must come from the engine, before a job id is minted, the
//!   registry is touched or anything is sent. [`crate::jobs::start`] takes
//!   that gate at its steps (5)/(6), which is both early enough for call B6
//!   and late enough for spec D3's order (`lane_unavailable` →
//!   `out_of_scope` → `refused_l4` → `refused_agent`); no verb here takes it
//!   a second time.
//! * **`scan.start` is `Sensitive` whatever the profile does** (spec D4, "tier
//!   laundering guard"): the job's gate is taken once, at start, and the
//!   catalogue then runs script checks without a per-call policy decision.

use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Registry, Sensitivity, TypeDesc, Value,
};
use aitm_poc::Severity;
use aitm_scan_model::{
    scan_error, ChecksResult, Confidence, IssueStatus, LaneKind, ListResult, ProfileListResult,
    ScanErrorCode, ScanProfile, SessionProfile, SitemapResult,
};
use serde::de::DeserializeOwned;

use crate::issues::{IssueFilter, MAX_ISSUE_PAGE};
use crate::jobs::{self, Caller, Engine};
use crate::profiles::{self, StartArgs};
use crate::{session, util};

/// `scan.issues`' page size when the caller names none (spec D3).
const DEFAULT_ISSUE_PAGE: usize = 100;

/// `scan.sitemap`'s page size when the caller names none, and its ceiling
/// (spec D3).
const DEFAULT_SITEMAP_PAGE: usize = 1024;
const MAX_SITEMAP_PAGE: usize = 4096;

/// The `_confirm` question an L4 or intrusive job must be answered before it
/// runs (spec D3).
fn confirm_sentence(targets: &str) -> String {
    format!("This scan sends malformed traffic to {targets} and may disrupt the target. Continue?")
}

/// Register every verb of spec D3's table on `reg`.
///
/// Fifteen commands: the three shipped ones (`scan.discover`, `scan.passive`,
/// `scan.report`) stay with [`crate::commands`].
pub fn register(engine: &Arc<Engine>, reg: &mut Registry) {
    reg.add_command(Arc::new(ScanStart {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanMap {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanStatus {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanList {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanCancel {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanIssues {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanIssue {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanIssueUpdate {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanSitemap {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanChecks {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanProfileList {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanProfileGet {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanProfileSave {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanProfileDelete {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanSessionPreview {
        engine: Arc::clone(engine),
    }));
}

// --- shared argument and result plumbing ------------------------------------

/// Who is calling, as the engine's gates classify callers (shared facts,
/// "Caller classes"): `Frontend::Mcp` is the agent, the CLI and an
/// operator-token connection are the human control surfaces.
pub(crate) fn caller_of(host: &CommandHost<'_>) -> Caller {
    Caller {
        frontend: host.frontend(),
        client_label: host.client_label().map(str::to_string),
    }
}

/// Serialise a model result type onto the bus.
///
/// Every verb's result goes through here, so no verb can hand-build a shape
/// that drifts from the one `aitm-scan-model` pins.
pub(crate) fn result_of<T: serde::Serialize>(value: &T) -> anyhow::Result<Value> {
    let json = serde_json::to_value(value)
        .map_err(|e| anyhow::anyhow!("the scanner result cannot be serialized: {e}"))?;
    Ok(util::json_to_value(json))
}

/// The bus [`Value`] as JSON, for the two params that carry a whole model type
/// (`scan.start`'s `profile`/`overrides`, `scan.profile.save`'s `profile`).
///
/// The mirror of [`util::json_to_value`]. `Bytes` has no JSON form and becomes
/// an array of byte values rather than silently vanishing.
pub(crate) fn value_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Int(i) => serde_json::Value::from(*i),
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::Str(s) => serde_json::Value::String(s.clone()),
        Value::Bytes(b) => {
            serde_json::Value::Array(b.iter().map(|b| serde_json::Value::from(*b)).collect())
        }
        Value::Array(items) => serde_json::Value::Array(items.iter().map(value_to_json).collect()),
        Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), value_to_json(v)))
                .collect(),
        ),
    }
}

/// An optional string argument. A present key of another type is a refusal, not
/// a silent `None`.
fn opt_str(args: &Params, name: &str) -> anyhow::Result<Option<String>> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => Ok(Some(args.get_str(name)?.to_string())),
    }
}

/// An optional non-negative integer argument, as a `usize`.
fn opt_usize(args: &Params, name: &str) -> anyhow::Result<Option<usize>> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => {
            let raw = args.get_int(name)?;
            let value = usize::try_from(raw)
                .map_err(|_| anyhow::anyhow!("`{name}` must be a non-negative whole number"))?;
            Ok(Some(value))
        }
    }
}

/// An optional unsigned 64-bit argument (`since`, an epoch-millisecond stamp).
fn opt_u64(args: &Params, name: &str) -> anyhow::Result<Option<u64>> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => {
            let raw = args.get_int(name)?;
            let value = u64::try_from(raw)
                .map_err(|_| anyhow::anyhow!("`{name}` must be a non-negative whole number"))?;
            Ok(Some(value))
        }
    }
}

/// An optional boolean argument.
fn opt_bool(args: &Params, name: &str) -> anyhow::Result<Option<bool>> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => Ok(Some(args.get_bool(name)?)),
    }
}

/// An optional vocabulary token, parsed by the model's own serde so a verb and
/// the wire can never disagree about what `severity_min: "high"` means.
///
/// `allowed` is listed in the refusal, because a caller that mistyped a token
/// needs the vocabulary, not a serde message.
fn opt_token<T: DeserializeOwned>(
    args: &Params,
    name: &str,
    allowed: &str,
) -> anyhow::Result<Option<T>> {
    let Some(text) = opt_str(args, name)? else {
        return Ok(None);
    };
    serde_json::from_value::<T>(serde_json::Value::String(text.clone()))
        .map(Some)
        .map_err(|_| {
            scan_error(
                ScanErrorCode::InvalidProfile,
                format!("`{name}` must be one of {allowed}; got `{text}`"),
            )
        })
}

/// The vocabulary lists the token refusals quote.
const SEVERITY_TOKENS: &str = "`info`, `low`, `medium`, `high`, `critical`";
const CONFIDENCE_TOKENS: &str = "`tentative`, `firm`, `certain`";
const STATUS_TOKENS: &str = "`open`, `confirmed`, `false_positive`";
const LANE_TOKENS: &str = "`http`, `ws`, `l4_stream`, `l4_packet`";
const ORIGIN_TOKENS: &str = "`native`, `bundled`, `custom`";

/// `scan.start`/`scan.map`'s four profile params (spec D3).
fn start_args(args: &Params) -> anyhow::Result<StartArgs> {
    let profile = match args.get("profile") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            serde_json::from_value::<ScanProfile>(value_to_json(value)).map_err(|e| {
                scan_error(ScanErrorCode::InvalidProfile, format!("`profile`: {e}"))
            })?,
        ),
    };
    Ok(StartArgs {
        profile,
        profile_name: opt_str(args, "profile_name")?,
        target: opt_str(args, "target")?,
        overrides: match args.get("overrides") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value_to_json(value)),
        },
    })
}

/// The four profile params, as every start-shaped verb declares them.
fn start_params() -> Vec<ParamDef> {
    vec![
        ParamDef {
            name: "profile".into(),
            // Free-form: the MCP param validator refuses any key a closed
            // `Object` does not declare, which would reject every
            // `ScanProfile` field. `ScanProfile`'s `deny_unknown_fields` is
            // the real validator, and it answers a typo with
            // `scan: invalid_profile:`.
            ty: TypeDesc::Map(Box::new(TypeDesc::Any)),
            required: false,
            description: "A complete `ScanProfile`, inline; an unknown key is refused rather \
                          than ignored."
                .into(),
        },
        ParamDef {
            name: "profile_name".into(),
            ty: TypeDesc::Str,
            required: false,
            description: "The name of a built-in, configured or saved profile.".into(),
        },
        ParamDef {
            name: "target".into(),
            ty: TypeDesc::Str,
            required: false,
            description: "Shorthand: one origin (`https://app.example`), scanned with the \
                          profile named by `scanner.default_profile`."
                .into(),
        },
        ParamDef {
            name: "overrides".into(),
            ty: TypeDesc::Map(Box::new(TypeDesc::Any)),
            required: false,
            description: "A partial profile merged over the selected one; an unknown key is \
                          refused rather than ignored."
                .into(),
        },
    ]
}

/// The one `{ job }` param three verbs share.
fn job_param() -> ParamDef {
    ParamDef {
        name: "job".into(),
        ty: TypeDesc::Str,
        required: true,
        description: "The job id `scan.start` returned (`scan-<8 hex>`).".into(),
    }
}

/// `scan: not_found: job <id>`.
fn no_such_job(job: &str) -> anyhow::Error {
    scan_error(ScanErrorCode::NotFound, format!("job {job}"))
}

/// Resolve a profile for a start-shaped call, and name the targets it would hit.
fn resolve(engine: &Engine, args: &Params) -> anyhow::Result<ScanProfile> {
    engine.profiles.resolve(&engine.cfg, start_args(args)?)
}

/// The human-readable target list in the `_confirm` prompt.
fn targets_of(profile: &ScanProfile) -> String {
    let mut targets: Vec<String> = profile.target.origins.clone();
    targets.extend(
        profile
            .target
            .l4
            .iter()
            .map(|t| format!("{}:{}", t.ip, t.port)),
    );
    if targets.is_empty() {
        "the profile's targets".to_string()
    } else {
        targets.join(", ")
    }
}

// --- scan.start / scan.map --------------------------------------------------

/// `scan.start` — accept a scan job and return at once (spec D3, D5).
pub struct ScanStart {
    engine: Arc<Engine>,
}

impl Command for ScanStart {
    fn name(&self) -> &str {
        "scan.start"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Spec D4, "Tier laundering guard": the job's gate is taken once, here,
        // and the catalogue then runs every check — script checks included —
        // without a per-call policy decision. That is why a profile which would
        // only read is still started by a `Sensitive` verb.
        Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Start a scan job against an authorized, in-scope target and return \
                          immediately with the accepted job. Exactly one of `profile`, \
                          `profile_name` and `target` selects the profile; `overrides` is \
                          merged over it. Poll `scan.status` and `scan.issues` for progress \
                          (a `notifications/aitm/job` line is a refresh trigger, not the \
                          truth). A figure above a configured ceiling is clamped, not \
                          refused, and reported in `clamped`; a requested lane this build \
                          does not have is skipped and reported in `lanes.skipped`. Refusals \
                          are `scan: <code>: <message>` with one of `lane_unavailable`, \
                          `unknown_check`, `out_of_scope`, `refused_l4`, `refused_agent`, \
                          `invalid_profile`, `busy`."
                .into(),
            params: start_params(),
            result: TypeDesc::Object(Vec::new()),
        }
    }

    /// Spec D3: an L4 lane or `intensity: intrusive` needs the operator's yes.
    /// A profile that does not resolve asks nothing — `invoke` will say why.
    fn confirm_prompt(&self, args: &Params) -> Option<String> {
        let profile = resolve(&self.engine, args).ok()?;
        let l4 = profile
            .lanes
            .iter()
            .any(|lane| matches!(lane, LaneKind::L4Packet | LaneKind::L4Stream));
        (l4 || profile.intensity == aitm_scan_model::Intensity::Intrusive)
            .then(|| confirm_sentence(&targets_of(&profile)))
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let caller = caller_of(host);
        let profile = resolve(&self.engine, &args)?;
        // Call B6 is honoured inside `jobs::start`, which takes the same
        // `agent_gate` at its steps (5)/(6) — after lane availability and
        // scope, and before a job id is minted, the registry is touched or
        // anything is sent. So under `agent.policy: auto` an agent still gets
        // `refused_agent` from this verb with no job and no traffic, and a
        // caller that is wrong in two ways still learns spec D3's first
        // reason. Gating here as well put `refused_agent` ahead of
        // `lane_unavailable` and `out_of_scope` (whole-branch spec finding).
        let result = jobs::start(&self.engine, profile, caller, false)?;
        result_of(&result)
    }

    fn summarize(&self, _args: &Params, result: &Value) -> Option<String> {
        match result {
            Value::Object(map) => match map.get("job") {
                Some(Value::Str(job)) => Some(format!("started {job}")),
                _ => None,
            },
            _ => None,
        }
    }
}

/// `scan.map` — the job-model successor of `scan.discover`: crawl, passive
/// checks and insertion points, no probe (spec D3).
pub struct ScanMap {
    engine: Arc<Engine>,
}

impl Command for ScanMap {
    fn name(&self) -> &str {
        "scan.map"
    }

    fn sensitivity(&self) -> Sensitivity {
        // It crawls and reads; it sends no probe. Same tier as the shipped
        // `scan.discover` it replaces.
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Map one authorized, in-scope target: crawl it, run the passive \
                          checks and enumerate its insertion points. Takes the same \
                          parameters as `scan.start`, but the engine forces `lanes: [http]` \
                          and `intensity: passive`, so no probe is ever sent. The map crawl \
                          submits same-origin forms with inert values and the observed \
                          session, skips logout-looking and destructive-looking forms \
                          (counted in `crawl.forms_skipped`), and can be turned off with \
                          `crawl.submit_forms: false`. Returns the accepted job \
                          immediately; read the result with `scan.sitemap` and \
                          `scan.issues`."
                .into(),
            params: start_params(),
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let caller = caller_of(host);
        let profile = resolve(&self.engine, &args)?;
        let result = jobs::start(&self.engine, profile, caller, true)?;
        result_of(&result)
    }
}

// --- scan.status / scan.list / scan.cancel ----------------------------------

/// `scan.status` — one job's full counters (spec D3, D5).
pub struct ScanStatus {
    engine: Arc<Engine>,
}

impl Command for ScanStatus {
    fn name(&self) -> &str {
        "scan.status"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "The full `JobStatus` of one scan job: state, phase, elapsed, probe \
                          and point counters, issues by severity, lanes, clamps and the \
                          stopped reason. Poll this; the push line is only a trigger. \
                          `scan: not_found:` if the job is unknown or has aged out of the \
                          retained history."
                .into(),
            params: vec![job_param()],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let job = args.get_str("job")?;
        let status = self
            .engine
            .registry
            .status(job)
            .ok_or_else(|| no_such_job(job))?;
        result_of(&status)
    }
}

/// `scan.list` — the retained jobs, newest first (spec D3).
pub struct ScanList {
    engine: Arc<Engine>,
}

impl Command for ScanList {
    fn name(&self) -> &str {
        "scan.list"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Scan jobs, newest first: the live ones plus the finished history \
                          `scanner.history` retains (reloaded from disk at startup when \
                          `findings.dir` is set). `active_only` keeps the jobs that have not \
                          reached a terminal state."
                .into(),
            params: vec![
                ParamDef {
                    name: "active_only".into(),
                    ty: TypeDesc::Bool,
                    required: false,
                    description: "Only jobs that are still running. Default false.".into(),
                },
                ParamDef {
                    name: "limit".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "How many jobs to return. Defaults to `scanner.history`.".into(),
                },
            ],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let active_only = opt_bool(&args, "active_only")?.unwrap_or(false);
        let limit = opt_usize(&args, "limit")?.unwrap_or(self.engine.cfg.history as usize);
        let jobs = self.engine.registry.list(active_only, limit);
        result_of(&ListResult { jobs })
    }
}

/// `scan.cancel` — stop a job; idempotent (spec D3, D5).
pub struct ScanCancel {
    engine: Arc<Engine>,
}

impl Command for ScanCancel {
    fn name(&self) -> &str {
        "scan.cancel"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Ask a scan job to stop. Returns its status, `cancelling` while the \
                          worker unwinds and `cancelled` once it has. Idempotent: cancelling \
                          a job that already finished changes nothing and is not an error. \
                          The issues the job raised are kept."
                .into(),
            params: vec![job_param()],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let job = args.get_str("job")?;
        let status = self
            .engine
            .registry
            .cancel(job)
            .ok_or_else(|| no_such_job(job))?;
        result_of(&status)
    }
}

// --- scan.issues / scan.issue / scan.issue.update ---------------------------

/// `scan.issues` — one filtered, paged slice of the issue store (spec D3, D6).
pub struct ScanIssues {
    engine: Arc<Engine>,
}

impl Command for ScanIssues {
    fn name(&self) -> &str {
        "scan.issues"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Issues from the scan issue store, ordered by severity (descending), \
                          then first seen, then id. Every parameter narrows; `by_severity` \
                          tallies the whole filtered set, not the page. Page with \
                          `next_cursor`: pass it back as `cursor`."
                .into(),
            params: vec![
                ParamDef {
                    name: "job".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Only issues this job found.".into(),
                },
                ParamDef {
                    name: "target".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Only issues on this origin (`scheme://host[:port]`, or a \
                                  bare host)."
                        .into(),
                },
                ParamDef {
                    name: "severity_min".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "At least this severe: info | low | medium | high | critical."
                        .into(),
                },
                ParamDef {
                    name: "confidence_min".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "At least this confident: tentative | firm | certain.".into(),
                },
                ParamDef {
                    name: "class".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Only this issue class (`reflected-xss`, `sqli`, ...).".into(),
                },
                ParamDef {
                    name: "lane".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Only this lane: http | ws | l4_stream | l4_packet.".into(),
                },
                ParamDef {
                    name: "status".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Only this triage state: open | confirmed | false_positive."
                        .into(),
                },
                ParamDef {
                    name: "since".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Only issues last seen at or after this epoch-millisecond \
                                  timestamp."
                        .into(),
                },
                ParamDef {
                    name: "limit".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Page size, default 100, capped at 1024.".into(),
                },
                ParamDef {
                    name: "cursor".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "The `next_cursor` of the previous page.".into(),
                },
            ],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let filter = IssueFilter {
            job: opt_str(&args, "job")?,
            target: opt_str(&args, "target")?,
            severity_min: opt_token::<Severity>(&args, "severity_min", SEVERITY_TOKENS)?,
            confidence_min: opt_token::<Confidence>(&args, "confidence_min", CONFIDENCE_TOKENS)?,
            class: opt_str(&args, "class")?,
            lane: opt_token::<LaneKind>(&args, "lane", LANE_TOKENS)?,
            status: opt_token::<IssueStatus>(&args, "status", STATUS_TOKENS)?,
            since_ms: opt_u64(&args, "since")?,
        };
        let limit = opt_usize(&args, "limit")?
            .unwrap_or(DEFAULT_ISSUE_PAGE)
            .min(MAX_ISSUE_PAGE);
        let cursor = opt_str(&args, "cursor")?;
        let page = self
            .engine
            .issues
            .query(&filter, limit, cursor.as_deref())?;
        result_of(&page)
    }
}

/// `scan.issue` — one issue with its full evidence (spec D3, D6).
pub struct ScanIssue {
    engine: Arc<Engine>,
}

impl Command for ScanIssue {
    fn name(&self) -> &str {
        "scan.issue"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "One issue in full: description, remediation, evidence (payload, \
                          match, timing, diff), the probe flows that proved it, the PoC \
                          reference and the linked finding. `scan: not_found:` if the id is \
                          unknown."
                .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The issue id (`issue-<8 hex>`).".into(),
            }],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_str("id")?;
        let issue = self
            .engine
            .issues
            .get(id)
            .ok_or_else(|| scan_error(ScanErrorCode::NotFound, format!("issue {id}")))?;
        result_of(&issue)
    }
}

/// `scan.issue.update` — triage an issue; persisted (spec D3, D6).
pub struct ScanIssueUpdate {
    engine: Arc<Engine>,
}

impl Command for ScanIssueUpdate {
    fn name(&self) -> &str {
        "scan.issue.update"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Set an issue's triage state and, optionally, a note. The change is \
                          written through to `<findings.dir>/scan/issues/<id>.json` when a \
                          findings directory is configured, so triage survives a restart. \
                          Omitting `note` leaves the previous note alone."
                .into(),
            params: vec![
                ParamDef {
                    name: "id".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The issue id (`issue-<8 hex>`).".into(),
                },
                ParamDef {
                    name: "status".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "open | confirmed | false_positive.".into(),
                },
                ParamDef {
                    name: "note".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "A triage note for the operator's own record.".into(),
                },
            ],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_str("id")?.to_string();
        // Required, so the "missing" and "mistyped" cases are told apart: an
        // absent `status` is a schema error, a bad token an `invalid_profile`.
        args.get_str("status")?;
        let status = opt_token::<IssueStatus>(&args, "status", STATUS_TOKENS)?
            .ok_or_else(|| anyhow::anyhow!("`status` is required"))?;
        let note = opt_str(&args, "note")?;
        let issue = self.engine.issues.update_status(&id, status, note)?;
        result_of(&issue)
    }
}

// --- scan.sitemap -----------------------------------------------------------

/// `scan.sitemap` — a job's site nodes and insertion points (spec D3, D8.1).
pub struct ScanSitemap {
    engine: Arc<Engine>,
}

impl Command for ScanSitemap {
    fn name(&self) -> &str {
        "scan.sitemap"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "The site map one job discovered: its nodes (method and path \
                          template per origin) and the insertion points on them. Name the \
                          job, name a `target` origin and get its newest job, or give \
                          neither and get the newest job of all; `job` names the job \
                          the map came from. `nodes` is \
                          always complete; `points` is paged — at most `limit` (default \
                          1024, capped 4096), then pass `next_cursor` back as `cursor`."
                .into(),
            params: vec![
                ParamDef {
                    name: "job".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "The job whose site map to read.".into(),
                },
                ParamDef {
                    name: "target".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "An origin; the newest job that ran against it is used.".into(),
                },
                ParamDef {
                    name: "cursor".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "The `next_cursor` of the previous page.".into(),
                },
                ParamDef {
                    name: "limit".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Insertion points per page, default 1024, capped 4096.".into(),
                },
            ],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let job =
            match (opt_str(&args, "job")?, opt_str(&args, "target")?) {
                (Some(job), _) => job,
                // Neither given (both are optional in spec D3): the newest job.
                (None, None) => self.engine.registry.newest().ok_or_else(|| {
                    scan_error(ScanErrorCode::NotFound, "no scan job has run yet")
                })?,
                (None, Some(target)) => {
                    let origin = profiles::normalize_origin(&target)
                        .map_err(|e| scan_error(ScanErrorCode::InvalidProfile, e))?;
                    self.engine
                        .registry
                        .newest_for_target(&origin)
                        .ok_or_else(|| {
                            scan_error(
                                ScanErrorCode::NotFound,
                                format!("no scan job has run against {origin}"),
                            )
                        })?
                }
            };
        let discovery = self
            .engine
            .registry
            .entry_handles(&job)
            .ok_or_else(|| no_such_job(&job))?
            .discovery;

        let limit = opt_usize(&args, "limit")?
            .unwrap_or(DEFAULT_SITEMAP_PAGE)
            .clamp(1, MAX_SITEMAP_PAGE);
        let offset = match opt_str(&args, "cursor")? {
            None => 0usize,
            Some(cursor) => cursor
                .parse::<usize>()
                .map_err(|_| scan_error(ScanErrorCode::NotFound, "cursor"))?,
        };

        let guarded = discovery.read().unwrap_or_else(|e| e.into_inner());
        let points: Vec<_> = guarded
            .points
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        let next = offset.saturating_add(points.len());
        let next_cursor = (next < guarded.points.len()).then(|| next.to_string());
        let result = SitemapResult {
            job: Some(job.clone()),
            nodes: guarded.nodes.clone(),
            points,
            next_cursor,
        };
        drop(guarded);
        result_of(&result)
    }
}

// --- scan.checks ------------------------------------------------------------

/// `scan.checks` — the unified catalogue as loaded (spec D3, D4).
pub struct ScanChecks {
    engine: Arc<Engine>,
}

impl Command for ScanChecks {
    fn name(&self) -> &str {
        "scan.checks"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "The check catalogue as this build loaded it: the lanes' native \
                          checks, the native HTTP checks and every Rhai check a script \
                          declared with `reg.add_check`, each with its full metadata (class, \
                          lanes, kinds, intensity, cost, technique, severity, confidence \
                          ceiling, CWE, description, remediation, origin). Every entry also \
                          has a manual `check.<id>` command. Filters narrow by lane, class \
                          and origin."
                .into(),
            params: vec![
                ParamDef {
                    name: "lane".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Only checks this lane runs: http | ws | l4_stream | \
                                  l4_packet."
                        .into(),
                },
                ParamDef {
                    name: "class".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Only checks of this issue class.".into(),
                },
                ParamDef {
                    name: "origin".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Where the check came from: native | bundled | custom.".into(),
                },
            ],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let lane = opt_token::<LaneKind>(&args, "lane", LANE_TOKENS)?;
        let class = opt_str(&args, "class")?;
        let origin = opt_str(&args, "origin")?;
        if let Some(origin) = &origin {
            if !matches!(origin.as_str(), "native" | "bundled" | "custom") {
                return Err(scan_error(
                    ScanErrorCode::InvalidProfile,
                    format!("`origin` must be one of {ORIGIN_TOKENS}; got `{origin}`"),
                ));
            }
        }
        let checks = self
            .engine
            .catalogue()
            .filter(lane, class.as_deref(), origin.as_deref());
        let lanes = self.engine.lane_entries();
        result_of(&ChecksResult { checks, lanes })
    }
}

// --- the profile verbs ------------------------------------------------------

/// `scan.profile.list` (spec D3).
pub struct ScanProfileList {
    engine: Arc<Engine>,
}

impl Command for ScanProfileList {
    fn name(&self) -> &str {
        "scan.profile.list"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Every scan profile this build can resolve: the seven built-ins, \
                          the `scanner.profiles:` config section and the ones saved under \
                          `<findings.dir>/scan/profiles/`. A saved profile shadows a \
                          configured one, which shadows a built-in."
                .into(),
            params: Vec::new(),
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        result_of(&ProfileListResult {
            profiles: self.engine.profiles.list(),
        })
    }
}

/// `scan.profile.get` (spec D3).
pub struct ScanProfileGet {
    engine: Arc<Engine>,
}

impl Command for ScanProfileGet {
    fn name(&self) -> &str {
        "scan.profile.get"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "One profile in full, as `scan.start { profile }` would take it. \
                          `scan: not_found:` for an unknown name."
                .into(),
            params: vec![ParamDef {
                name: "name".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The profile name.".into(),
            }],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let profile = self.engine.profiles.get(args.get_str("name")?)?;
        result_of(&profile)
    }
}

/// `scan.profile.save` (spec D3, D11).
pub struct ScanProfileSave {
    engine: Arc<Engine>,
}

impl Command for ScanProfileSave {
    fn name(&self) -> &str {
        "scan.profile.save"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Save a profile as human-readable YAML under \
                          `<findings.dir>/scan/profiles/<name>.yaml`. The profile needs a \
                          `name` that is not a built-in's and is a safe file name \
                          (lowercase letters, digits, `.`, `_`, `-`), and must validate. \
                          Refused with `scan: invalid_profile:` otherwise, or when no \
                          findings directory is configured."
                .into(),
            params: vec![ParamDef {
                name: "profile".into(),
                // Free-form for the same reason as `scan.start`'s `profile`:
                // the schema must not police a `ScanProfile`'s keys.
                ty: TypeDesc::Map(Box::new(TypeDesc::Any)),
                required: true,
                description: "The complete `ScanProfile` to save.".into(),
            }],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let raw = args
            .get("profile")
            .ok_or_else(|| anyhow::anyhow!("`profile` is required"))?;
        let profile: ScanProfile = serde_json::from_value(value_to_json(raw))
            .map_err(|e| scan_error(ScanErrorCode::InvalidProfile, format!("`profile`: {e}")))?;
        let saved = self.engine.profiles.save(&profile)?;
        result_of(&saved)
    }
}

/// `scan.profile.delete` (spec D3).
pub struct ScanProfileDelete {
    engine: Arc<Engine>,
}

impl Command for ScanProfileDelete {
    fn name(&self) -> &str {
        "scan.profile.delete"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Remove a saved profile. Idempotent: deleting one that is not there \
                          reports `deleted: false`. A built-in's name is refused."
                .into(),
            params: vec![ParamDef {
                name: "name".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The saved profile's name.".into(),
            }],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let deleted = self.engine.profiles.delete(args.get_str("name")?)?;
        result_of(&deleted)
    }
}

// --- scan.session.preview ---------------------------------------------------

/// `scan.session.preview` — the observed session, names only (spec D3, D7).
pub struct ScanSessionPreview {
    engine: Arc<Engine>,
}

impl Command for ScanSessionPreview {
    fn name(&self) -> &str {
        "scan.session.preview"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "What `session.mode: observed` would reuse for this origin: the \
                          names of the session cookies and secret headers on the newest \
                          captured in-scope flow that carries them, the flow they came from \
                          and the GET/HEAD canary that would detect the session being lost. \
                          Names only — no verb, push line, issue, PoC or log ever carries a \
                          session value. An origin with nothing observed returns an empty \
                          profile with `canary: none`, which is also how auth-lost detection \
                          reports being off."
                .into(),
            params: vec![ParamDef {
                name: "target".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The origin (`https://app.example`).".into(),
            }],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let services = self.engine.late.get()?;
        let origin = profiles::normalize_origin(args.get_str("target")?)
            .map_err(|e| scan_error(ScanErrorCode::InvalidProfile, e))?;
        let profile = session::pick_observed(services.store.as_ref(), &origin, None)
            .map(|observed| observed.profile)
            .unwrap_or_else(|| SessionProfile {
                origin: origin.clone(),
                cookies: Vec::new(),
                headers: Vec::new(),
                source_flow: None,
                observed_at: 0,
                canary: aitm_scan_model::Canary::None,
            });
        result_of(&profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use aitm_core::{
        AgentPolicy, Body, Command, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore,
        Frontend, HeaderMap, HttpFlow, HttpRequest, HttpVersion, InterceptState, JobBus,
        MemFlowStore, Registry, ScopeEntry, ScopeRateGuard, Sensitivity, StdGuard,
    };
    use aitm_scan_model::{Check, ScanErrorCode, ScanRefusal};

    use crate::config::ScannerConfig;
    use crate::jobs::test_support::{FakeCheck, FakeRun, StubClient};
    use crate::jobs::{Engine, ScanServices};
    use crate::plugin::ScannerPlugin;

    /// A directory under `$TMPDIR` removed when the harness drops. `test_support`
    /// has one, but its constructor is private to that module.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("aitm-scanner-verbs-{}", FlowId::new()));
            std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
            Self(dir)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A registry loaded with a real [`ScannerPlugin`], its [`crate::jobs::ScanLate`]
    /// bound to in-memory services. The plugin carries **no** lane crate, so the
    /// interim HTTP lane is what `lanes_for_run` picks (call B2); the catalogue
    /// holds the engine's three shipped passive checks (spec amendment 24) and
    /// the two legacy actives in the native slot; a `FakeCheck` rides in beside
    /// them through the native-check slot the binary fills.
    struct Harness {
        reg: Registry,
        engine: Arc<Engine>,
        store: Arc<MemFlowStore>,
        guard: Arc<StdGuard>,
        client: Arc<StubClient>,
        policy: Arc<Mutex<AgentPolicy>>,
        _scratch: Option<ScratchDir>,
    }

    impl Harness {
        fn new() -> Self {
            Self::build(ScannerConfig::default(), Vec::new(), None)
        }

        /// A harness whose catalogue also holds `check`.
        fn with_check(check: Arc<dyn Check>) -> Self {
            Self::build(ScannerConfig::default(), vec![check], None)
        }

        /// A harness with a scratch `findings.dir`, so profiles and issues persist.
        fn with_findings_dir() -> Self {
            let scratch = ScratchDir::new();
            let cfg = ScannerConfig {
                findings_dir: Some(scratch.0.clone()),
                ..ScannerConfig::default()
            };
            Self::build(cfg, Vec::new(), Some(scratch))
        }

        fn build(
            cfg: ScannerConfig,
            natives: Vec<Arc<dyn Check>>,
            scratch: Option<ScratchDir>,
        ) -> Self {
            // The native slot always carries the lane's two legacy active checks,
            // standing in for the T3 natives the binary puts there (PR 2a), so
            // the catalogue these tests pin still holds `xss-reflected` and
            // `open-redirect` beside the lane's three passive checks.
            let mut slot = crate::interim_lane::legacy_active_checks();
            slot.extend(natives);
            let plugin = ScannerPlugin::new(cfg.clone()).with_native_checks(slot);
            let late = plugin.late();
            let cell = plugin.engine_cell();

            let mut reg = Registry::new();
            reg.add_plugin(Box::new(plugin));
            let engine = cell.get().expect("`load` built the engine").clone();

            let guard = Arc::new(StdGuard::default());
            for host in ["scan.test", "other.test"] {
                guard.add_scope(ScopeEntry { host: host.into() });
            }
            let store = Arc::new(MemFlowStore::new());
            let client = StubClient::new();
            let policy = Arc::new(Mutex::new(AgentPolicy::Ask));
            let read = Arc::clone(&policy);
            assert!(late.bind(ScanServices {
                store: Arc::clone(&store) as Arc<dyn aitm_core::FlowStore>,
                client: Arc::clone(&client) as Arc<dyn aitm_core::ProxyClient>,
                guard: Arc::clone(&guard) as Arc<dyn aitm_core::ScopeRateGuard>,
                browser: None,
                egress: None,
                l4: None,
                jobs: Arc::new(JobBus::default()),
                agent_policy: Arc::new(move || *read.lock().expect("policy lock")),
                rt: tokio::runtime::Handle::current(),
                config: Arc::new(aitm_core::Config {
                    findings: aitm_core::FindingsConfig {
                        dir: cfg.findings_dir.clone(),
                    },
                    ..aitm_core::Config::default()
                }),
            }));

            Self {
                reg,
                engine,
                store,
                guard,
                client,
                policy,
                _scratch: scratch,
            }
        }

        fn set_policy(&self, policy: AgentPolicy) {
            *self.policy.lock().expect("policy lock") = policy;
        }

        fn cmd(&self, name: &str) -> Arc<dyn Command> {
            Arc::clone(
                self.reg
                    .command(name)
                    .unwrap_or_else(|| panic!("`{name}` is registered")),
            )
        }

        /// Invoke `name` as an operator (CLI).
        fn call(&self, name: &str, args: &[(&str, Value)]) -> anyhow::Result<Value> {
            self.call_as(name, Frontend::Cli, args)
        }

        fn call_as(
            &self,
            name: &str,
            frontend: Frontend,
            args: &[(&str, Value)],
        ) -> anyhow::Result<Value> {
            let cmd = self.cmd(name);
            let host = CommandHost::new(&*self.store, &*self.client, &*self.guard, None)
                .with_frontend(frontend);
            cmd.invoke(params(args), &host)
        }

        fn ok(&self, name: &str, args: &[(&str, Value)]) -> Value {
            self.call(name, args)
                .unwrap_or_else(|e| panic!("`{name}` succeeds: {e}"))
        }

        /// Wait for `job` to be terminal via the registry's terminal signal
        /// (`test_support::wait_terminal`); no clock.
        async fn wait_terminal(&self, job: &str) {
            crate::jobs::test_support::wait_terminal(&self.engine.registry, job).await;
        }

        /// A captured, in-scope flow the interim lane can map.
        fn capture(&self, path: &str, headers: HeaderMap, body: &str) -> FlowId {
            self.store.insert(Flow::Http(HttpFlow {
                id: FlowId::new(),
                request: HttpRequest {
                    method: "GET".into(),
                    scheme: "http".into(),
                    authority: "scan.test".into(),
                    path: path.into(),
                    version: HttpVersion::Http11,
                    headers,
                    body: Body::Empty,
                    timestamp: SystemTime::now(),
                },
                response: Some(aitm_core::HttpResponse {
                    status: 200,
                    version: HttpVersion::Http11,
                    headers: HeaderMap::new(),
                    trailers: HeaderMap::new(),
                    body: Body::Bytes(body.as_bytes().to_vec()),
                    timestamp: SystemTime::now(),
                    peer: None,
                }),
                client_conn: ConnInfo {
                    peer: "127.0.0.1:0".parse().expect("loopback"),
                    sni: None,
                    alpn: None,
                    tls: false,
                    established: SystemTime::now(),
                },
                server_conn: None,
                metadata: FlowMeta::default(),
                intercept: InterceptState::Observed,
            }))
        }
    }

    fn params(args: &[(&str, Value)]) -> Params {
        Params::new(
            args.iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        )
    }

    fn s(v: &str) -> Value {
        Value::Str(v.to_string())
    }

    /// The typed code behind a verb refusal.
    fn code(err: &anyhow::Error) -> ScanErrorCode {
        err.downcast_ref::<ScanRefusal>()
            .unwrap_or_else(|| panic!("`{err}` is not a typed scan refusal"))
            .code
    }

    fn obj<'a>(value: &'a Value, key: &str) -> &'a Value {
        match value {
            Value::Object(map) => map
                .get(key)
                .unwrap_or_else(|| panic!("the result has a `{key}` key")),
            other => panic!("expected an object, got {other:?}"),
        }
    }

    fn as_str(value: &Value) -> &str {
        match value {
            Value::Str(s) => s,
            other => panic!("expected a string, got {other:?}"),
        }
    }

    fn as_array(value: &Value) -> &[Value] {
        match value {
            Value::Array(items) => items,
            other => panic!("expected an array, got {other:?}"),
        }
    }

    /// Every string anywhere in a value, keys included.
    fn strings(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Str(text) => out.push(text.clone()),
            Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
            Value::Object(map) => map.iter().for_each(|(k, v)| {
                out.push(k.clone());
                strings(v, out);
            }),
            _ => {}
        }
    }

    /// Spec D3: the verb table is the contract. The registry holds exactly the
    /// eighteen `scan.*` names (fifteen new, three shipped) and one uniform
    /// `check.<id>` per catalogue entry — here the engine's three shipped passive
    /// checks plus the two legacy actives in the harness's native slot (call B8).
    #[tokio::test(flavor = "multi_thread")]
    async fn registry_exposes_every_d3_verb_and_the_manual_checks() {
        let h = Harness::new();

        let mut scan: Vec<&str> = h
            .reg
            .commands()
            .map(|c| c.name())
            .filter(|n| n.starts_with("scan."))
            .collect();
        scan.sort_unstable();
        assert_eq!(
            scan,
            vec![
                "scan.cancel",
                "scan.checks",
                "scan.discover",
                "scan.issue",
                "scan.issue.update",
                "scan.issues",
                "scan.list",
                "scan.map",
                "scan.passive",
                "scan.profile.delete",
                "scan.profile.get",
                "scan.profile.list",
                "scan.profile.save",
                "scan.report",
                "scan.session.preview",
                "scan.sitemap",
                "scan.start",
                "scan.status",
            ]
        );

        let mut checks: Vec<&str> = h
            .reg
            .commands()
            .map(|c| c.name())
            .filter(|n| n.starts_with("check."))
            .collect();
        checks.sort_unstable();
        assert_eq!(
            checks,
            vec![
                "check.cookie-flag",
                "check.open-redirect",
                "check.reflection",
                "check.security-header",
                "check.xss-reflected",
            ]
        );
    }

    /// Spec D3's tier column: `scan.start` is `Sensitive` (D4's tier-laundering
    /// guard), `scan.map` only `Write`, `scan.status` `Read`.
    #[tokio::test(flavor = "multi_thread")]
    async fn start_is_sensitive_map_is_write_status_is_read() {
        let h = Harness::new();
        assert_eq!(h.cmd("scan.start").sensitivity(), Sensitivity::Sensitive);
        assert_eq!(h.cmd("scan.map").sensitivity(), Sensitivity::Write);
        assert_eq!(h.cmd("scan.status").sensitivity(), Sensitivity::Read);
    }

    /// Spec D3: the `_confirm` prompt appears for an L4 lane or `intrusive`, and
    /// for nothing else.
    #[tokio::test(flavor = "multi_thread")]
    async fn confirm_prompt_only_for_l4_or_intrusive() {
        let h = Harness::new();
        let start = h.cmd("scan.start");

        assert_eq!(
            start.confirm_prompt(&params(&[("target", s("http://scan.test"))])),
            None,
            "`standard` over one origin asks nothing"
        );

        let l4 = params(&[
            ("profile_name", s("l4-full")),
            (
                "overrides",
                Value::Object(BTreeMap::from([(
                    "target".to_string(),
                    Value::Object(BTreeMap::from([(
                        "l4".to_string(),
                        Value::Array(vec![Value::Object(BTreeMap::from([
                            ("ip".to_string(), s("127.0.0.1")),
                            ("port".to_string(), Value::Int(9999)),
                            ("proto".to_string(), s("tcp")),
                        ]))]),
                    )])),
                )])),
            ),
        ]);
        let prompt = start.confirm_prompt(&l4).expect("an l4 profile prompts");
        assert!(
            prompt.contains("may disrupt the target"),
            "prompt was {prompt:?}"
        );

        let intrusive = params(&[
            ("target", s("http://scan.test")),
            (
                "overrides",
                Value::Object(BTreeMap::from([("intensity".to_string(), s("intrusive"))])),
            ),
        ]);
        assert!(start
            .confirm_prompt(&intrusive)
            .expect("an intrusive profile prompts")
            .contains("may disrupt the target"));
    }

    /// AC T1-1: `scan.start` returns the accepted job at once; the work happens
    /// in the background. Proven without a clock: the job runs a check that
    /// does not end until the job is cancelled (or the engine's
    /// `check_timeout_s`, 60 s by default, cuts it), so the verb answering with
    /// the job's terminal signal still unset shows it did not wait for the
    /// work; a `scan.start` that did wait would come back late with the signal
    /// already `true` — a failure, not a hang. The old `elapsed() < 2 s` bound
    /// tripped on a loaded CI runner (#290, 2026-11-02; coordinator's
    /// amendment 71b).
    #[tokio::test(flavor = "multi_thread")]
    async fn start_returns_a_start_result_immediately() {
        let h = Harness::with_check(FakeCheck::blocking("fake.blocker"));
        h.capture("/search?q=1", HeaderMap::new(), "ok");

        let result = h.ok("scan.start", &[("target", s("http://scan.test"))]);

        let job = as_str(obj(&result, "job")).to_string();
        assert_eq!(
            h.engine
                .registry
                .terminal_signal(&job)
                .map(|signal| *signal.borrow()),
            Some(false),
            "the verb answered while its job was still running"
        );
        assert_eq!(job.len(), 13, "`{job}` is `scan-<8 hex>`");
        assert!(job.starts_with("scan-"));
        assert!(job[5..].chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(as_str(obj(obj(&result, "status"), "state")), "queued");

        // `standard` asks for http + ws; this build has only the interim HTTP lane.
        let skipped = as_array(obj(obj(&result, "lanes"), "skipped"));
        assert_eq!(skipped.len(), 1);
        assert_eq!(as_str(obj(&skipped[0], "lane")), "ws");
        assert_eq!(as_array(obj(obj(&result, "lanes"), "run")).len(), 1);

        h.ok("scan.cancel", &[("job", s(&job))]);
        h.wait_terminal(&job).await;
    }

    /// AC T1-4 / call B6: under `agent.policy: auto` the command itself refuses
    /// an agent with the `refused_agent` code, before it touches the registry.
    #[tokio::test(flavor = "multi_thread")]
    async fn agent_under_auto_is_refused_agent_without_touching_the_registry() {
        let h = Harness::new();
        h.set_policy(AgentPolicy::Auto);

        let err = h
            .call_as(
                "scan.start",
                Frontend::Mcp,
                &[("target", s("http://scan.test"))],
            )
            .expect_err("an agent under `auto` is refused");
        assert_eq!(code(&err), ScanErrorCode::RefusedAgent);
        assert!(
            err.to_string().starts_with("scan: refused_agent: "),
            "text was {err}"
        );
        assert_eq!(h.engine.registry.list(false, 16).len(), 0);
        assert_eq!(h.client.calls(), 0);
    }

    /// The other two agent gates, through the verb: `all` without
    /// `allow_agent_active`, then with it.
    #[tokio::test(flavor = "multi_thread")]
    async fn agent_needs_all_and_allow_agent_active() {
        let h = Harness::new();
        h.set_policy(AgentPolicy::All);
        let err = h
            .call_as(
                "scan.start",
                Frontend::Mcp,
                &[("target", s("http://scan.test"))],
            )
            .expect_err("`allow_agent_active` is off");
        assert_eq!(code(&err), ScanErrorCode::RefusedAgent);

        let on = Harness::build(
            ScannerConfig {
                allow_agent_active: true,
                ..ScannerConfig::default()
            },
            Vec::new(),
            None,
        );
        on.set_policy(AgentPolicy::All);
        let result = on
            .call_as(
                "scan.start",
                Frontend::Mcp,
                &[("target", s("http://scan.test"))],
            )
            .expect("an agent with the flag and policy `all` may scan");
        on.wait_terminal(as_str(obj(&result, "job"))).await;
    }

    /// Spec D3: an unknown job is `not_found`, from `scan.status` and
    /// `scan.cancel` alike.
    #[tokio::test(flavor = "multi_thread")]
    async fn status_not_found() {
        let h = Harness::new();
        for verb in ["scan.status", "scan.cancel"] {
            let err = h
                .call(verb, &[("job", s("scan-00000000"))])
                .expect_err("an unknown job is refused");
            assert_eq!(code(&err), ScanErrorCode::NotFound, "{verb}");
            assert!(err.to_string().starts_with("scan: not_found: "));
        }
    }

    /// Spec D3: `scan.list` is newest first and honours `active_only`.
    #[tokio::test(flavor = "multi_thread")]
    async fn list_reports_the_finished_job() {
        let h = Harness::new();
        let result = h.ok("scan.map", &[("target", s("http://scan.test"))]);
        let job = as_str(obj(&result, "job")).to_string();
        h.wait_terminal(&job).await;

        let listed = h.ok("scan.list", &[]);
        let jobs = as_array(obj(&listed, "jobs"));
        assert_eq!(jobs.len(), 1);
        assert_eq!(as_str(obj(&jobs[0], "job")), job);

        let active = h.ok("scan.list", &[("active_only", Value::Bool(true))]);
        assert_eq!(as_array(obj(&active, "jobs")).len(), 0);
    }

    /// Spec D3/D6: triage round-trips through `scan.issue.update`, `scan.issue`
    /// and the `status` filter of `scan.issues`.
    #[tokio::test(flavor = "multi_thread")]
    async fn issue_update_round_trips() {
        let h = Harness::with_check(FakeCheck::new("fake.vuln", "demo", FakeRun::vulnerable()));
        h.capture("/search?q=1", HeaderMap::new(), "ok");

        let started = h.ok("scan.start", &[("target", s("http://scan.test"))]);
        let job = as_str(obj(&started, "job")).to_string();
        h.wait_terminal(&job).await;

        let issues = h.ok("scan.issues", &[("job", s(&job))]);
        let listed = as_array(obj(&issues, "issues"));
        assert!(!listed.is_empty(), "the vulnerable verdict raised an issue");
        let id = as_str(obj(&listed[0], "id")).to_string();

        let updated = h.ok(
            "scan.issue.update",
            &[
                ("id", s(&id)),
                ("status", s("false_positive")),
                ("note", s("intended")),
            ],
        );
        assert_eq!(as_str(obj(&updated, "status")), "false_positive");
        assert_eq!(as_str(obj(&updated, "note")), "intended");

        let fetched = h.ok("scan.issue", &[("id", s(&id))]);
        assert_eq!(as_str(obj(&fetched, "status")), "false_positive");

        let filtered = h.ok("scan.issues", &[("status", s("false_positive"))]);
        assert_eq!(as_array(obj(&filtered, "issues")).len(), 1);

        let err = h
            .call(
                "scan.issue.update",
                &[("id", s(&id)), ("status", s("nope"))],
            )
            .expect_err("an unknown status token is refused");
        assert_eq!(code(&err), ScanErrorCode::InvalidProfile);

        let missing = h
            .call("scan.issue", &[("id", s("issue-00000000"))])
            .expect_err("an unknown issue is refused");
        assert_eq!(code(&missing), ScanErrorCode::NotFound);
    }

    /// Amendment 27c (T7 live run 3): a second job on the same core and target
    /// re-finds the issue the first job recorded; D6 merges it, and the per-job
    /// view still lists it for the re-finder — `scan.issues { job: <second> }`
    /// returns it with `jobs` of length 2 and `job` naming the first finder.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_job_lists_the_issue_it_refound() {
        let h = Harness::with_check(FakeCheck::new("fake.vuln", "demo", FakeRun::vulnerable()));
        h.capture("/search?q=1", HeaderMap::new(), "ok");

        let first = h.ok("scan.start", &[("target", s("http://scan.test"))]);
        let first_job = as_str(obj(&first, "job")).to_string();
        h.wait_terminal(&first_job).await;
        let second = h.ok("scan.start", &[("target", s("http://scan.test"))]);
        let second_job = as_str(obj(&second, "job")).to_string();
        assert_ne!(first_job, second_job);
        h.wait_terminal(&second_job).await;

        let mine = h.ok("scan.issues", &[("job", s(&second_job))]);
        let listed = as_array(obj(&mine, "issues"));
        assert!(
            !listed.is_empty(),
            "the second job lists the issue it re-found"
        );
        let issue = &listed[0];
        assert_eq!(
            as_str(obj(issue, "job")),
            first_job,
            "`job` names the first finder"
        );
        let jobs: Vec<&str> = as_array(obj(issue, "jobs")).iter().map(as_str).collect();
        assert_eq!(jobs, vec![first_job.as_str(), second_job.as_str()]);
        assert_eq!(
            as_array(obj(
                &h.ok("scan.issues", &[("job", s(&first_job))]),
                "issues"
            ))
            .len(),
            listed.len(),
            "the first finder still lists the same issues"
        );
        let status = h.ok("scan.status", &[("job", s(&second_job))]);
        let total = obj(obj(&status, "issues"), "total");
        assert!(
            matches!(total, Value::Int(n) if *n >= 1),
            "the second job's issues tally counts the re-found issue: {total:?}"
        );
    }

    /// Spec D3 / call B12: `scan.sitemap` pages its points by a decimal cursor
    /// and returns the node list whole every time.
    #[tokio::test(flavor = "multi_thread")]
    async fn sitemap_pages_points() {
        let h = Harness::new();
        h.capture("/search?q=1", HeaderMap::new(), "ok");
        h.capture("/other?r=2", HeaderMap::new(), "ok");

        let started = h.ok("scan.map", &[("target", s("http://scan.test"))]);
        let job = as_str(obj(&started, "job")).to_string();
        h.wait_terminal(&job).await;

        let first = h.ok(
            "scan.sitemap",
            &[("job", s(&job)), ("limit", Value::Int(1))],
        );
        assert_eq!(as_array(obj(&first, "points")).len(), 1);
        assert_eq!(as_str(obj(&first, "next_cursor")), "1");
        assert_eq!(as_array(obj(&first, "nodes")).len(), 2);

        let second = h.ok(
            "scan.sitemap",
            &[
                ("job", s(&job)),
                ("limit", Value::Int(1)),
                ("cursor", s("1")),
            ],
        );
        assert_eq!(as_array(obj(&second, "points")).len(), 1);
        assert_eq!(obj(&second, "next_cursor"), &Value::Null);
        assert_eq!(as_array(obj(&second, "nodes")).len(), 2);

        // `target` resolves to the newest job for that origin.
        let by_target = h.ok("scan.sitemap", &[("target", s("http://scan.test"))]);
        assert_eq!(as_array(obj(&by_target, "points")).len(), 2);

        // Neither `job` nor `target` (spec amendment 27): the newest job of
        // all. A second job against an origin with no captures has no node,
        // which tells it from the first.
        let bare = h.ok("scan.sitemap", &[]);
        assert_eq!(
            as_array(obj(&bare, "nodes")).len(),
            2,
            "one job: it is the newest"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
        let second = h.ok("scan.map", &[("target", s("http://other.test"))]);
        let second = as_str(obj(&second, "job")).to_string();
        h.wait_terminal(&second).await;
        let bare = h.ok("scan.sitemap", &[]);
        assert_eq!(
            as_array(obj(&bare, "nodes")).len(),
            0,
            "the newest job's nodes"
        );
        assert_eq!(as_array(obj(&bare, "points")).len(), 0);
        assert_eq!(
            h.engine.registry.newest().as_deref(),
            Some(second.as_str()),
            "the registry names the same job"
        );
        let by_target = h.ok("scan.sitemap", &[("target", s("http://scan.test"))]);
        assert_eq!(
            as_array(obj(&by_target, "nodes")).len(),
            2,
            "`target` still picks the first job"
        );
    }

    /// `scan.sitemap {}` before any job has run is `not_found`, in words.
    #[tokio::test(flavor = "multi_thread")]
    async fn sitemap_without_job_or_target_on_a_fresh_engine_is_not_found() {
        let h = Harness::new();
        let err = h.call("scan.sitemap", &[]).expect_err("no job has run");
        assert_eq!(code(&err), ScanErrorCode::NotFound);
        assert_eq!(err.to_string(), "scan: not_found: no scan job has run yet");
    }

    /// Spec D3/D4: `scan.checks` is the unified catalogue, filtered by lane,
    /// class and origin.
    #[tokio::test(flavor = "multi_thread")]
    async fn checks_lists_the_catalogue_with_filters() {
        let h = Harness::with_check(FakeCheck::new("fake.vuln", "demo", FakeRun::clean()));

        let all = h.ok("scan.checks", &[]);
        let ids: Vec<&str> = as_array(obj(&all, "checks"))
            .iter()
            .map(|c| as_str(obj(c, "id")))
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            vec![
                "cookie-flag",
                "fake.vuln",
                "open-redirect",
                "reflection",
                "security-header",
                "xss-reflected",
            ]
        );

        let native = h.ok("scan.checks", &[("origin", s("native"))]);
        assert_eq!(as_array(obj(&native, "checks")).len(), 6);

        let ws = h.ok("scan.checks", &[("lane", s("ws"))]);
        assert_eq!(as_array(obj(&ws, "checks")).len(), 0);

        // The lanes the engine would run, with their source: with no lane crate
        // the `http` lane is the interim one, and a filter does not hide it.
        let lanes = as_array(obj(&ws, "lanes"));
        assert_eq!(lanes.len(), 1);
        assert_eq!(as_str(obj(&lanes[0], "lane")), "http");
        assert_eq!(as_str(obj(&lanes[0], "source")), "interim");

        let demo = h.ok("scan.checks", &[("class", s("demo"))]);
        assert_eq!(as_array(obj(&demo, "checks")).len(), 1);
    }

    /// Spec D3: the four profile verbs over the engine's `Profiles`.
    #[tokio::test(flavor = "multi_thread")]
    async fn profile_verbs_round_trip() {
        let h = Harness::with_findings_dir();

        let listed = h.ok("scan.profile.list", &[]);
        assert_eq!(as_array(obj(&listed, "profiles")).len(), 7);

        let profile = Value::Object(BTreeMap::from([
            ("name".to_string(), s("mine")),
            (
                "target".to_string(),
                Value::Object(BTreeMap::from([(
                    "origins".to_string(),
                    Value::Array(vec![s("http://scan.test")]),
                )])),
            ),
        ]));
        let saved = h.ok("scan.profile.save", &[("profile", profile)]);
        assert_eq!(as_str(obj(&saved, "saved")), "mine");
        assert!(as_str(obj(&saved, "path")).ends_with("mine.yaml"));

        let got = h.ok("scan.profile.get", &[("name", s("mine"))]);
        assert_eq!(as_str(obj(&got, "name")), "mine");
        assert_eq!(
            as_array(obj(obj(&got, "target"), "origins")),
            &[s("http://scan.test")]
        );

        assert_eq!(
            as_array(obj(&h.ok("scan.profile.list", &[]), "profiles")).len(),
            8
        );

        let deleted = h.ok("scan.profile.delete", &[("name", s("mine"))]);
        assert_eq!(obj(&deleted, "deleted"), &Value::Bool(true));

        let builtin = Value::Object(BTreeMap::from([("name".to_string(), s("standard"))]));
        let err = h
            .call("scan.profile.save", &[("profile", builtin)])
            .expect_err("a built-in cannot be saved over");
        assert_eq!(code(&err), ScanErrorCode::InvalidProfile);

        let unknown = h
            .call("scan.profile.get", &[("name", s("nope"))])
            .expect_err("an unknown profile is refused");
        assert_eq!(code(&unknown), ScanErrorCode::NotFound);
    }

    /// Spec D7 / AC T2-6: `scan.session.preview` carries names, never a value.
    #[tokio::test(flavor = "multi_thread")]
    async fn session_preview_names_only() {
        let h = Harness::new();
        let mut headers = HeaderMap::new();
        headers.set("Cookie", "sid=abc");
        h.capture("/dashboard", headers, "ok");

        let preview = h.ok("scan.session.preview", &[("target", s("http://scan.test"))]);
        assert_eq!(as_array(obj(&preview, "cookies")), &[s("sid")]);
        let mut found = Vec::new();
        strings(&preview, &mut found);
        assert!(
            !found.iter().any(|text| text.contains("abc")),
            "a session value reached the wire: {found:?}"
        );

        let empty = Harness::new();
        let none = empty.ok("scan.session.preview", &[("target", s("http://scan.test"))]);
        assert_eq!(as_str(obj(obj(&none, "canary"), "kind")), "none");
        assert_eq!(as_array(obj(&none, "cookies")).len(), 0);
    }

    /// D4's tier-laundering guard: `scan.start` is `Sensitive` even for a
    /// profile that would only read.
    #[tokio::test(flavor = "multi_thread")]
    async fn scan_start_is_in_the_registry_as_sensitive_even_for_passive_only() {
        let h = Harness::new();
        let result = h.ok(
            "scan.start",
            &[
                ("profile_name", s("passive-only")),
                (
                    "overrides",
                    Value::Object(BTreeMap::from([(
                        "target".to_string(),
                        Value::Object(BTreeMap::from([(
                            "origins".to_string(),
                            Value::Array(vec![s("http://scan.test")]),
                        )])),
                    )])),
                ),
            ],
        );
        assert_eq!(
            as_str(obj(obj(&result, "status"), "profile_name")),
            "passive-only"
        );
        assert_eq!(h.cmd("scan.start").sensitivity(), Sensitivity::Sensitive);
        h.wait_terminal(as_str(obj(&result, "job"))).await;
    }

    /// Spec D3: exactly one of `profile`, `profile_name`, `target`.
    #[tokio::test(flavor = "multi_thread")]
    async fn start_needs_exactly_one_selector() {
        let h = Harness::new();
        let err = h
            .call(
                "scan.start",
                &[
                    ("target", s("http://scan.test")),
                    ("profile_name", s("standard")),
                ],
            )
            .expect_err("two selectors are refused");
        assert_eq!(code(&err), ScanErrorCode::InvalidProfile);

        let none = h
            .call("scan.start", &[])
            .expect_err("no selector is refused");
        assert_eq!(code(&none), ScanErrorCode::InvalidProfile);
    }

    /// The rule the MCP param validator applies to a param value
    /// (`aitm_mcp::json::object_from_json`): a closed [`TypeDesc::Object`]
    /// refuses every key it does not declare, while a `Map`/`Any` admits any
    /// key and leaves the checking to the command. Mirrored here because
    /// `aitm-mcp` is not a dependency of this crate. The live-run refusal this
    /// reproduces was ``param `profile`: unknown param `name` for `object` ``.
    fn keys_the_mcp_validator_refuses(ty: &TypeDesc, json: &serde_json::Value) -> Vec<String> {
        let Some(fields) = json.as_object() else {
            panic!("the value under test is a JSON object");
        };
        match ty {
            TypeDesc::Map(_) | TypeDesc::Any => Vec::new(),
            TypeDesc::Object(defs) => fields
                .keys()
                .filter(|key| !defs.iter().any(|def| &def.name == *key))
                .cloned()
                .collect(),
            _ => fields.keys().cloned().collect(),
        }
    }

    /// The declared type of one of `cmd`'s params.
    fn param_ty(cmd: &dyn Command, name: &str) -> TypeDesc {
        cmd.schema()
            .params
            .into_iter()
            .find(|def| def.name == name)
            .unwrap_or_else(|| panic!("`{}` declares a `{name}` param", cmd.name()))
            .ty
    }

    /// A profile that exercises the whole `ScanProfile` tree, including the
    /// three keys the live run was refused on (`name`, `target`, `accuracy`).
    fn full_profile(name: &str) -> serde_json::Value {
        let profile = ScanProfile {
            name: name.to_string(),
            target: aitm_scan_model::ProfileTarget {
                origins: vec!["http://scan.test".to_string()],
                l4: Vec::new(),
            },
            accuracy: aitm_scan_model::Accuracy::FewerFalsePositives,
            ..ScanProfile::default()
        };
        let json = serde_json::to_value(&profile).expect("a `ScanProfile` serialises");
        let keys: Vec<&str> = json
            .as_object()
            .expect("a profile is a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![
                "name",
                "target",
                "lanes",
                "intensity",
                "speed",
                "accuracy",
                "checks",
                "crawl",
                "audit",
                "session",
                "budget",
                "http",
                "ws",
                "l4",
            ],
            "the profile under test must carry every `ScanProfile` field"
        );
        json
    }

    /// Spec D3: `scan.start`'s `profile` is "a complete `ScanProfile`, inline"
    /// and `overrides` "a partial profile", so the MCP param validator must not
    /// police their keys — `ScanProfile`'s `deny_unknown_fields` is the real
    /// validator, and a typo is still `invalid_profile`. A real `tests/e2e`
    /// run was refused at the schema with ``param `profile`: unknown param
    /// `name` for `object` `` because both start-shaped verbs declared the
    /// param as a closed, empty object.
    #[tokio::test(flavor = "multi_thread")]
    async fn scan_start_accepts_a_full_profile_object() {
        let h = Harness::new();
        let json = full_profile("inline-full");
        let none: Vec<String> = Vec::new();

        for verb in ["scan.start", "scan.map"] {
            let cmd = h.cmd(verb);
            for param in ["profile", "overrides"] {
                assert_eq!(
                    keys_the_mcp_validator_refuses(&param_ty(&*cmd, param), &json),
                    none,
                    "`{verb}` refuses `ScanProfile` keys in `{param}` at the schema"
                );
            }
        }

        // The whole profile really drives a job: the engine, not the schema,
        // is what accepts it.
        let result = h.ok(
            "scan.start",
            &[("profile", util::json_to_value(json.clone()))],
        );
        assert_eq!(
            as_str(obj(obj(&result, "status"), "profile_name")),
            "inline-full"
        );
        h.wait_terminal(as_str(obj(&result, "job"))).await;

        // …and a typo is refused by that engine, with the typed code.
        let mut typo = json;
        let fields = typo.as_object_mut().expect("the profile is an object");
        let accuracy = fields.remove("accuracy").expect("`accuracy` is a field");
        fields.insert("accuracyy".to_string(), accuracy);
        let err = h
            .call("scan.start", &[("profile", util::json_to_value(typo))])
            .expect_err("a mistyped profile key is refused");
        assert_eq!(code(&err), ScanErrorCode::InvalidProfile);
    }

    /// Spec D3/D11: `scan.profile.save`'s `profile` is a whole `ScanProfile`
    /// too, and was closed the same way.
    #[tokio::test(flavor = "multi_thread")]
    async fn scan_profile_save_accepts_a_full_profile_object() {
        let h = Harness::with_findings_dir();
        let json = full_profile("mine-full");
        let cmd = h.cmd("scan.profile.save");
        assert_eq!(
            keys_the_mcp_validator_refuses(&param_ty(&*cmd, "profile"), &json),
            Vec::<String>::new(),
            "`scan.profile.save` refuses `ScanProfile` keys at the schema"
        );

        let saved = h.ok(
            "scan.profile.save",
            &[("profile", util::json_to_value(json.clone()))],
        );
        assert_eq!(as_str(obj(&saved, "saved")), "mine-full");
        let got = h.ok("scan.profile.get", &[("name", s("mine-full"))]);
        assert_eq!(as_str(obj(&got, "accuracy")), "fewer_false_positives");

        let mut typo = json;
        typo.as_object_mut()
            .expect("the profile is an object")
            .insert("budgett".to_string(), serde_json::Value::Null);
        let err = h
            .call(
                "scan.profile.save",
                &[("profile", util::json_to_value(typo))],
            )
            .expect_err("a mistyped profile key is refused");
        assert_eq!(code(&err), ScanErrorCode::InvalidProfile);
    }

    /// Spec D3: an out-of-scope origin is `out_of_scope`, and `scan.cancel` is
    /// idempotent on a job that already finished.
    #[tokio::test(flavor = "multi_thread")]
    async fn out_of_scope_and_idempotent_cancel() {
        let h = Harness::new();
        let err = h
            .call("scan.start", &[("target", s("http://nope.test"))])
            .expect_err("an unscoped origin is refused");
        assert_eq!(code(&err), ScanErrorCode::OutOfScope);

        let started = h.ok("scan.map", &[("target", s("http://scan.test"))]);
        let job = as_str(obj(&started, "job")).to_string();
        h.wait_terminal(&job).await;
        let first = h.ok("scan.cancel", &[("job", s(&job))]);
        let second = h.ok("scan.cancel", &[("job", s(&job))]);
        assert_eq!(obj(&first, "state"), obj(&second, "state"));
    }

    /// `scan.map` forces the passive, HTTP-only shape whatever the profile asks
    /// for (spec D3), so a `thorough` profile's `ws` lane is never requested.
    #[tokio::test(flavor = "multi_thread")]
    async fn map_forces_http_and_passive() {
        let h = Harness::new();
        let result = h.ok(
            "scan.map",
            &[
                ("profile_name", s("thorough")),
                (
                    "overrides",
                    Value::Object(BTreeMap::from([(
                        "target".to_string(),
                        Value::Object(BTreeMap::from([(
                            "origins".to_string(),
                            Value::Array(vec![s("http://scan.test")]),
                        )])),
                    )])),
                ),
            ],
        );
        let lanes = obj(&result, "lanes");
        assert_eq!(as_array(obj(lanes, "requested")), &[s("http")]);
        assert_eq!(as_array(obj(lanes, "run")), &[s("http")]);
        assert_eq!(as_array(obj(lanes, "skipped")).len(), 0);
        h.wait_terminal(as_str(obj(&result, "job"))).await;
    }

    /// A whole-`ScanProfile` JSON over `origins`, running `lanes`.
    fn profile_json(origins: &[&str], lanes: &[&str]) -> serde_json::Value {
        let mut json = full_profile("order");
        let fields = json.as_object_mut().expect("the profile is an object");
        fields.insert(
            "target".to_string(),
            serde_json::json!({ "origins": origins, "l4": [] }),
        );
        fields.insert("lanes".to_string(), serde_json::json!(lanes));
        json
    }

    /// Spec D3's refusal order, reached through the verb rather than through
    /// `jobs::start`: `lane_unavailable` → `out_of_scope` → `refused_l4` →
    /// `refused_agent`. An agent that is wrong in two ways learns the same
    /// reason an operator would, and learns `refused_agent` last.
    ///
    /// Whole-branch spec finding: `ScanStart::invoke` called `jobs::agent_gate`
    /// **before** `jobs::start`, so every one of these answered
    /// `refused_agent`. `jobs::start` already takes the same gate at its steps
    /// (5)/(6) — after lanes and scope and before a job is minted or anything
    /// is sent — so the pre-call only reordered the codes.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_agents_scan_start_is_refused_in_d3_order() {
        let h = Harness::new();
        h.set_policy(AgentPolicy::Auto);

        // (3) No lane this build has: `lane_unavailable`, before the agent gate.
        let err = h
            .call_as(
                "scan.start",
                Frontend::Mcp,
                &[(
                    "profile",
                    util::json_to_value(profile_json(&["http://scan.test"], &["ws"])),
                )],
            )
            .expect_err("no requested lane is available");
        assert_eq!(code(&err), ScanErrorCode::LaneUnavailable);
        assert!(
            err.to_string().starts_with("scan: lane_unavailable:"),
            "{err}"
        );

        // (4) Scope, still before the agent gate.
        let err = h
            .call_as(
                "scan.start",
                Frontend::Mcp,
                &[(
                    "profile",
                    util::json_to_value(profile_json(&["http://nope.test"], &["http"])),
                )],
            )
            .expect_err("the origin is not in scope");
        assert_eq!(code(&err), ScanErrorCode::OutOfScope);
        assert!(err.to_string().starts_with("scan: out_of_scope:"), "{err}");

        // (6) Only a caller that passes both reaches the agent gate.
        let err = h
            .call_as(
                "scan.start",
                Frontend::Mcp,
                &[(
                    "profile",
                    util::json_to_value(profile_json(&["http://scan.test"], &["http"])),
                )],
            )
            .expect_err("an agent under `auto` is refused");
        assert_eq!(code(&err), ScanErrorCode::RefusedAgent);
        assert!(err.to_string().starts_with("scan: refused_agent:"), "{err}");

        // None of the three minted a job or sent anything.
        assert_eq!(h.engine.registry.list(true, 16).len(), 0);
        assert_eq!(h.client.calls(), 0);
    }

    /// AC T1-4, through the verbs: under `agent.policy: auto` an agent's
    /// `scan.start` is `refused_agent`, and its `scan.map` succeeds — a map
    /// job sends no probe, so only `scan.start` is deferred to its own gate
    /// (call B6; orchestrator ruling 2026-11-01).
    #[tokio::test(flavor = "multi_thread")]
    async fn agent_under_auto_is_refused_agent_map_is_not() {
        let h = Harness::new();
        h.set_policy(AgentPolicy::Auto);

        let err = h
            .call_as(
                "scan.start",
                Frontend::Mcp,
                &[("target", s("http://scan.test"))],
            )
            .expect_err("an agent's `scan.start` under `auto` is refused");
        assert_eq!(code(&err), ScanErrorCode::RefusedAgent);
        assert_eq!(h.engine.registry.list(false, 16).len(), 0);

        let result = h
            .call_as(
                "scan.map",
                Frontend::Mcp,
                &[("target", s("http://scan.test"))],
            )
            .expect("an agent's `scan.map` under `auto` is admitted");
        let job = as_str(obj(&result, "job")).to_string();
        assert!(job.starts_with("scan-"), "job was {job}");
        assert_eq!(h.engine.registry.list(false, 16).len(), 1);
        h.wait_terminal(&job).await;
        let status = h.engine.registry.status(&job).expect("the map job exists");
        assert_eq!(status.started_by.frontend, "mcp");
    }
}
