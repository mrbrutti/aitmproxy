//! The `findings.*` commands and the [`FindingsPlugin`] that registers them.
//!
//! `findings.list` (Read) and `findings.get` (Read) read the store; `findings.record`
//! (Write) persists a finding; `findings.remove` (Sensitive) deletes one. All read the
//! configured `findings.dir` from the host; with no directory configured the reads are
//! empty and the writes error (persistence is opt-in). `findings.remove` is
//! operator/CLI-only: it refuses the agent role itself (the D2 policy gate that also
//! blocks it under `Paused`/`ReadOnly` lives in `call_tool`, a separate task).
//!
//! The command param set matches spec D8a — `{title, class, severity, target, poc_ref,
//! flows?, notes?}` are honoured — and adds optional reproduction/artifact params
//! (`passed`, `control_passed`, `run_at`, `finding_capture`, `poc_path`,
//! `screenshot_path`) so a `findings.record` after a `poc.run` can carry the outcome the
//! grader scores; a human may omit them.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Command, CommandHost, FlowId, Frontend, ParamDef, ParamSchema, Params, Registry, Sensitivity,
    TypeDesc, Value,
};
use aitm_poc::Severity;

use crate::record::{
    origin_str, parse_time, FindingArtifacts, FindingFilter, FindingRecord, FindingSummary,
    Reproduction,
};
use crate::store::{DiskFindingStore, FindingStore};

const NIL_FLOW_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Registers the four `findings.*` commands.
pub struct FindingsPlugin;

impl Default for FindingsPlugin {
    fn default() -> Self {
        Self
    }
}

impl FindingsPlugin {
    pub fn new() -> Self {
        Self
    }

    /// Register the commands into `reg` (also callable without a plugin).
    pub fn register(reg: &mut Registry) {
        reg.add_command(Arc::new(FindingsList));
        reg.add_command(Arc::new(FindingsGet));
        reg.add_command(Arc::new(FindingsRecord));
        reg.add_command(Arc::new(FindingsRemove));
    }
}

impl aitm_core::Plugin for FindingsPlugin {
    fn name(&self) -> &str {
        "findings"
    }

    fn load(&mut self, reg: &mut Registry) {
        FindingsPlugin::register(reg);
    }
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn parse_severity(s: &str) -> anyhow::Result<Severity> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        other => {
            anyhow::bail!("unknown severity `{other}` (expected info|low|medium|high|critical)")
        }
    })
}

fn opt_str<'a>(args: &'a Params, name: &str) -> Option<&'a str> {
    match args.get(name) {
        Some(Value::Str(s)) => Some(s),
        _ => None,
    }
}

fn opt_bool(args: &Params, name: &str) -> Option<bool> {
    match args.get(name) {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// The store for this invocation, or `None` when no `findings.dir` is configured.
fn store_for(host: &CommandHost) -> Option<DiskFindingStore> {
    host.config()
        .and_then(|c| c.findings.dir.clone())
        .map(DiskFindingStore::new)
}

fn flows_from(args: &Params) -> anyhow::Result<Vec<FlowId>> {
    match args.get("flows") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                Value::Str(s) => s
                    .parse::<FlowId>()
                    .map_err(|e| anyhow::anyhow!("invalid flow id `{s}`: {e}")),
                other => anyhow::bail!("flows entries must be flow-id strings, got {other:?}"),
            })
            .collect(),
        Some(other) => anyhow::bail!("`flows` must be an array of flow-id strings, got {other:?}"),
    }
}

fn flow_value(ids: &[FlowId]) -> Value {
    Value::Array(ids.iter().map(|f| Value::Str(f.to_string())).collect())
}

fn record_to_value(r: &FindingRecord) -> Value {
    let mut o = BTreeMap::new();
    o.insert("id".into(), Value::Str(r.id.clone()));
    o.insert("title".into(), Value::Str(r.title.clone()));
    o.insert("class".into(), Value::Str(r.class.clone()));
    o.insert(
        "severity".into(),
        Value::Str(severity_str(r.severity).into()),
    );
    o.insert("target".into(), Value::Str(r.target.clone()));
    o.insert(
        "discovered_at".into(),
        Value::Str(crate::record::fmt_time(r.discovered_at)),
    );
    o.insert("origin".into(), Value::Str(origin_str(r.origin).into()));
    o.insert(
        "client_label".into(),
        r.client_label.clone().map_or(Value::Null, Value::Str),
    );
    o.insert("poc_ref".into(), Value::Str(r.poc_ref.clone()));
    let mut repro = BTreeMap::new();
    repro.insert("passed".into(), Value::Bool(r.reproduction.passed));
    repro.insert(
        "control_passed".into(),
        r.reproduction
            .control_passed
            .map_or(Value::Null, Value::Bool),
    );
    repro.insert(
        "run_at".into(),
        Value::Str(crate::record::fmt_time(r.reproduction.run_at)),
    );
    o.insert("reproduction".into(), Value::Object(repro));
    let mut art = BTreeMap::new();
    art.insert(
        "finding_capture".into(),
        Value::Str(r.artifacts.finding_capture.to_string()),
    );
    art.insert("poc_path".into(), Value::Str(r.artifacts.poc_path.clone()));
    art.insert(
        "screenshot_path".into(),
        Value::Str(r.artifacts.screenshot_path.clone()),
    );
    o.insert("artifacts".into(), Value::Object(art));
    o.insert("flows".into(), flow_value(&r.flows));
    o.insert(
        "notes".into(),
        r.notes.clone().map_or(Value::Null, Value::Str),
    );
    Value::Object(o)
}

fn summary_to_value(s: &FindingSummary) -> Value {
    let mut o = BTreeMap::new();
    o.insert("id".into(), Value::Str(s.id.clone()));
    o.insert("title".into(), Value::Str(s.title.clone()));
    o.insert("class".into(), Value::Str(s.class.clone()));
    o.insert(
        "severity".into(),
        Value::Str(severity_str(s.severity).into()),
    );
    o.insert("target".into(), Value::Str(s.target.clone()));
    o.insert(
        "discovered_at".into(),
        Value::Str(crate::record::fmt_time(s.discovered_at)),
    );
    o.insert("origin".into(), Value::Str(origin_str(s.origin).into()));
    o.insert("poc_ref".into(), Value::Str(s.poc_ref.clone()));
    o.insert("passed".into(), Value::Bool(s.passed));
    o.insert(
        "control_passed".into(),
        s.control_passed.map_or(Value::Null, Value::Bool),
    );
    Value::Object(o)
}

fn filter_from(args: &Params) -> anyhow::Result<FindingFilter> {
    let Some(Value::Object(f)) = args.get("filter") else {
        return Ok(FindingFilter::default());
    };
    let str_field = |k: &str| match f.get(k) {
        Some(Value::Str(s)) => Some(s.clone()),
        _ => None,
    };
    let severity = match f.get("severity") {
        Some(Value::Str(s)) => Some(parse_severity(s)?),
        _ => None,
    };
    let since = match f.get("since") {
        Some(Value::Str(s)) => {
            Some(parse_time(s).map_err(|e| anyhow::anyhow!("bad `since`: {e}"))?)
        }
        _ => None,
    };
    Ok(FindingFilter {
        target: str_field("target"),
        class: str_field("class"),
        severity,
        since,
    })
}

/// `findings.list` → the summaries of stored findings matching an optional filter.
struct FindingsList;

impl Command for FindingsList {
    fn name(&self) -> &str {
        "findings.list"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List recorded findings (id, title, class, severity, target, when, \
                          reproduction), filterable by target/class/severity/since. Empty when \
                          no findings directory is configured."
                .into(),
            params: vec![ParamDef {
                name: "filter".into(),
                ty: TypeDesc::Object(vec![
                    ParamDef {
                        name: "target".into(),
                        ty: TypeDesc::Str,
                        required: false,
                        description: "Only findings against this target.".into(),
                    },
                    ParamDef {
                        name: "class".into(),
                        ty: TypeDesc::Str,
                        required: false,
                        description: "Only findings of this vulnerability class.".into(),
                    },
                    ParamDef {
                        name: "severity".into(),
                        ty: TypeDesc::Str,
                        required: false,
                        description: "Only findings of this severity.".into(),
                    },
                    ParamDef {
                        name: "since".into(),
                        ty: TypeDesc::Str,
                        required: false,
                        description: "Only findings discovered at/after this RFC 3339 time.".into(),
                    },
                ]),
                required: false,
                description: "Optional filter; an unset field matches everything.".into(),
            }],
            result: TypeDesc::Array(Box::new(TypeDesc::Object(Vec::new()))),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let Some(store) = store_for(host) else {
            return Ok(Value::Array(Vec::new()));
        };
        let filter = filter_from(&args)?;
        let out = store.list(&filter).iter().map(summary_to_value).collect();
        Ok(Value::Array(out))
    }
}

/// `findings.get` → the full record for an id.
struct FindingsGet;

impl Command for FindingsGet {
    fn name(&self) -> &str {
        "findings.get"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Read one recorded finding by id (full record incl. reproduction, \
                          artifacts, flows, notes)."
                .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The finding id.".into(),
            }],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_str("id")?;
        let store = store_for(host)
            .ok_or_else(|| anyhow::anyhow!("findings.get: no findings directory is configured"))?;
        let record = store
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("findings.get: no finding `{id}`"))?;
        Ok(record_to_value(&record))
    }
}

/// `findings.record` → persist a finding; returns `{id}`.
struct FindingsRecord;

impl Command for FindingsRecord {
    fn name(&self) -> &str {
        "findings.record"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Record a finding (after a passing poc.run): writes a human-readable \
                          YAML record and a runs.jsonl line, returns its id."
                .into(),
            params: vec![
                ParamDef {
                    name: "title".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "Human title of the finding.".into(),
                },
                ParamDef {
                    name: "class".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "Vulnerability class (matches a planted-vuln class).".into(),
                },
                ParamDef {
                    name: "severity".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "info|low|medium|high|critical.".into(),
                },
                ParamDef {
                    name: "target".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The vulnerable endpoint/target.".into(),
                },
                ParamDef {
                    name: "poc_ref".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "Reference to the PoC that reproduces it.".into(),
                },
                ParamDef {
                    name: "flows".into(),
                    ty: TypeDesc::Array(Box::new(TypeDesc::FlowId)),
                    required: false,
                    description: "Flow ids backing the finding.".into(),
                },
                ParamDef {
                    name: "notes".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Free-text notes (secrets are redacted).".into(),
                },
                ParamDef {
                    name: "passed".into(),
                    ty: TypeDesc::Bool,
                    required: false,
                    description: "poc.run passed on the vulnerable path (default true).".into(),
                },
                ParamDef {
                    name: "control_passed".into(),
                    ty: TypeDesc::Bool,
                    required: false,
                    description: "poc.run result on the patched control (false = reproduced)."
                        .into(),
                },
                ParamDef {
                    name: "run_at".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "RFC 3339 time of the reproduction run (default now).".into(),
                },
                ParamDef {
                    name: "finding_capture".into(),
                    ty: TypeDesc::FlowId,
                    required: false,
                    description: "The capture flow id for the finding.".into(),
                },
                ParamDef {
                    name: "poc_path".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Path to the PoC artifact (default = poc_ref).".into(),
                },
                ParamDef {
                    name: "screenshot_path".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Path to the screenshot artifact.".into(),
                },
            ],
            result: TypeDesc::Object(vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The assigned finding id.".into(),
            }]),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let store = store_for(host).ok_or_else(|| {
            anyhow::anyhow!("findings.record: no findings directory is configured")
        })?;

        let severity = parse_severity(args.get_str("severity")?)?;
        let flows = flows_from(&args)?;
        let poc_ref = args.get_str("poc_ref")?.to_string();

        let finding_capture = match opt_str(&args, "finding_capture") {
            Some(s) => s
                .parse::<FlowId>()
                .map_err(|e| anyhow::anyhow!("invalid finding_capture `{s}`: {e}"))?,
            None => flows
                .first()
                .copied()
                .unwrap_or_else(|| NIL_FLOW_ID.parse().expect("nil flow id parses")),
        };
        let run_at = match opt_str(&args, "run_at") {
            Some(s) => parse_time(s).map_err(|e| anyhow::anyhow!("bad `run_at`: {e}"))?,
            None => SystemTime::now(),
        };

        let record = FindingRecord {
            id: String::new(),
            title: args.get_str("title")?.to_string(),
            class: args.get_str("class")?.to_string(),
            severity,
            target: args.get_str("target")?.to_string(),
            discovered_at: SystemTime::now(),
            origin: host.frontend(),
            client_label: host.client_label().map(str::to_string),
            poc_ref: poc_ref.clone(),
            reproduction: Reproduction {
                passed: opt_bool(&args, "passed").unwrap_or(true),
                control_passed: opt_bool(&args, "control_passed"),
                run_at,
            },
            artifacts: FindingArtifacts {
                finding_capture,
                poc_path: opt_str(&args, "poc_path").unwrap_or(&poc_ref).to_string(),
                screenshot_path: opt_str(&args, "screenshot_path").unwrap_or("").to_string(),
            },
            flows,
            notes: opt_str(&args, "notes").map(str::to_string),
        };

        let id = store.record(record)?;
        let mut o = BTreeMap::new();
        o.insert("id".into(), Value::Str(id));
        Ok(Value::Object(o))
    }
}

/// `findings.remove` → delete a finding's record (operator/CLI only).
struct FindingsRemove;

impl Command for FindingsRemove {
    fn name(&self) -> &str {
        "findings.remove"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Delete a recorded finding's YAML (the runs.jsonl history is kept). \
                          Operator/CLI only."
                .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The finding id to remove.".into(),
            }],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        // Operator/CLI-only: refuse the agent role here, independent of the D2
        // policy gate in `call_tool` (which also blocks it under Paused/ReadOnly).
        if host.frontend() == Frontend::Mcp {
            anyhow::bail!("findings.remove is operator/CLI-only");
        }
        let id = args.get_str("id")?;
        let store = store_for(host).ok_or_else(|| {
            anyhow::anyhow!("findings.remove: no findings directory is configured")
        })?;
        store.remove(id)?;
        Ok(Value::Object(BTreeMap::new()))
    }
}
