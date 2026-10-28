//! F10: native sessions + `aitm` flow export/import — all **passive**.
//!
//! `SessionIoPlugin` registers four commands over the flow store:
//!
//! - `session.save {path}` / `session.load {path}` — persist and restore the whole
//!   store as a native `aitm-session/1` JSON document (full fidelity: every field,
//!   both bodies, WS messages; `InterceptState` collapses to `Observed`).
//! - `flow.export {ids?, format?, path?}` / `flow.import {path?, bytes?, format?}` —
//!   move selected flows across tools.
//!
//! **Passivity (Review focus #4).** Import and load only touch the store via its
//! `insert`/`clear` methods; they never call the proxy client,
//! so they make **zero** upstream requests and do not pass `ScopeRateGuard` —
//! exactly as passive capture is ungated. Replaying an imported flow is a later,
//! explicit `flow.replay`, never a side effect of import.
//!
//! **Formats.** Only the native `aitm` format is wired here. The `format` param is
//! already the extension point: HAR 1.2 export/import and mitmproxy `.flows`
//! import land in Task 9 by adding arms to [`require_native`]/the dispatch.

pub mod native;

use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, Flow, FlowId, ParamDef, ParamSchema, Params, Plugin, Registry, TypeDesc,
    Value,
};
use anyhow::Context;

use native::{from_doc, to_doc, SessionDoc, SCHEMA};

/// The one serialization format this task wires. HAR / mitmproxy arrive in Task 9.
const FORMAT_AITM: &str = "aitm";

/// Registers `session.save`, `session.load`, `flow.export`, `flow.import`.
/// Observes no events — serialization is a pure view over the store.
pub struct SessionIoPlugin;

impl Plugin for SessionIoPlugin {
    fn name(&self) -> &str {
        "sessionio"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(SessionSave));
        reg.add_command(Arc::new(SessionLoad));
        reg.add_command(Arc::new(FlowExport));
        reg.add_command(Arc::new(FlowImport));
    }
}

/// The requested format, defaulting to the native `aitm` format when omitted.
fn format_param(args: &Params) -> anyhow::Result<String> {
    match args.get("format") {
        None | Some(Value::Null) => Ok(FORMAT_AITM.to_string()),
        Some(Value::Str(s)) => Ok(s.clone()),
        Some(other) => anyhow::bail!("param `format` must be a string, got {other:?}"),
    }
}

/// Accept only the native `aitm` format for now. HAR 1.2 and mitmproxy `.flows`
/// are added here in Task 9; until then they are a clear, catchable refusal.
fn require_native(format: &str) -> anyhow::Result<()> {
    match format {
        FORMAT_AITM => Ok(()),
        "har" | "mitmproxy" => {
            anyhow::bail!("format `{format}` is not supported yet (added in Task 9); use `aitm`")
        }
        other => anyhow::bail!("unknown format `{other}`; use `aitm`"),
    }
}

/// Parse the optional `ids` array into flow ids. `None`/absent means "all flows".
fn ids_param(args: &Params) -> anyhow::Result<Option<Vec<FlowId>>> {
    match args.get("ids") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            let mut ids = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Str(s) => ids.push(
                        s.parse::<FlowId>()
                            .map_err(|e| anyhow::anyhow!("invalid flow id {s:?}: {e}"))?,
                    ),
                    other => anyhow::bail!("each id must be a string, got {other:?}"),
                }
            }
            Ok(Some(ids))
        }
        Some(other) => anyhow::bail!("param `ids` must be an array of flow ids, got {other:?}"),
    }
}

/// Snapshot the selected flows (or the whole visible store when `ids` is `None`).
/// A named id that is not in the store is a clear error, not a silent gap.
fn collect_flows(host: &CommandHost, ids: Option<Vec<FlowId>>) -> anyhow::Result<Vec<Flow>> {
    let store = host.store();
    match ids {
        Some(ids) => ids
            .into_iter()
            .map(|id| {
                store
                    .get(id)
                    .ok_or_else(|| anyhow::anyhow!("no flow with id {id}"))
            })
            .collect(),
        None => Ok(store
            .list()
            .into_iter()
            .filter_map(|id| store.get(id))
            .collect()),
    }
}

/// Parse native-format JSON bytes into a `SessionDoc`, rejecting a foreign or
/// future schema tag up front.
fn parse_native(bytes: &[u8]) -> anyhow::Result<SessionDoc> {
    let doc: SessionDoc =
        serde_json::from_slice(bytes).context("parsing native aitm session document")?;
    if doc.schema != SCHEMA {
        anyhow::bail!(
            "unexpected session schema {:?} (this build reads {SCHEMA:?})",
            doc.schema
        );
    }
    Ok(doc)
}

/// Serialize the selected flows to pretty native JSON bytes.
fn encode_native(flows: &[Flow]) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec_pretty(&to_doc(flows)).context("serializing native aitm session document")
}

fn path_param() -> ParamDef {
    ParamDef {
        name: "path".into(),
        ty: TypeDesc::Str,
        required: true,
        description: "Filesystem path to write/read the native session JSON.".into(),
    }
}

/// `session.save {path}` → write the whole store to `path` as native JSON.
struct SessionSave;

impl Command for SessionSave {
    fn name(&self) -> &str {
        "session.save"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Persist the whole flow store to a native `aitm-session/1` JSON file."
                .into(),
            params: vec![path_param()],
            result: TypeDesc::Object(vec![
                ParamDef {
                    name: "flows".into(),
                    ty: TypeDesc::Int,
                    required: true,
                    description: "Number of flows written.".into(),
                },
                ParamDef {
                    name: "path".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The path written.".into(),
                },
            ]),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let path = args.get_str("path")?.to_string();
        let flows = collect_flows(host, None)?;
        let bytes = encode_native(&flows)?;
        std::fs::write(&path, &bytes).with_context(|| format!("writing session to {path}"))?;
        Ok(object([
            ("flows", Value::Int(flows.len() as i64)),
            ("path", Value::Str(path)),
        ]))
    }
}

/// `session.load {path}` → replace the store with the flows in `path`.
struct SessionLoad;

impl Command for SessionLoad {
    fn name(&self) -> &str {
        "session.load"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Replace the flow store with a native `aitm-session/1` JSON file. \
                          Passive: no upstream requests."
                .into(),
            params: vec![path_param()],
            result: TypeDesc::Object(vec![ParamDef {
                name: "flows".into(),
                ty: TypeDesc::Int,
                required: true,
                description: "Number of flows loaded.".into(),
            }]),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let path = args.get_str("path")?;
        let bytes = std::fs::read(path).with_context(|| format!("reading session from {path}"))?;
        let doc = parse_native(&bytes)?;
        let flows = from_doc(&doc);
        let store = host.store();
        // Replace the capture: drop the terminal flows already there, then insert
        // the loaded ones full-fidelity (no `imported` stamp — this is a restore).
        store.clear();
        let mut loaded = 0usize;
        for flow in flows {
            store.insert(flow);
            loaded += 1;
        }
        Ok(object([("flows", Value::Int(loaded as i64))]))
    }
}

/// `flow.export {ids?, format?, path?}` → serialize selected flows (or all).
struct FlowExport;

impl Command for FlowExport {
    fn name(&self) -> &str {
        "flow.export"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Export selected flows (or the whole store) to native `aitm` JSON. \
                          Returns bytes, or writes to `path` when given."
                .into(),
            params: vec![
                ParamDef {
                    name: "ids".into(),
                    ty: TypeDesc::Array(Box::new(TypeDesc::FlowId)),
                    required: false,
                    description: "Flows to export; omit to export the whole store.".into(),
                },
                ParamDef {
                    name: "format".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Serialization format; `aitm` (default).".into(),
                },
                ParamDef {
                    name: "path".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Write here instead of returning bytes.".into(),
                },
            ],
            result: TypeDesc::Object(vec![
                ParamDef {
                    name: "bytes".into(),
                    ty: TypeDesc::Bytes,
                    required: false,
                    description: "The document, when no `path` was given.".into(),
                },
                ParamDef {
                    name: "path".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "The path written, when `path` was given.".into(),
                },
                ParamDef {
                    name: "flows".into(),
                    ty: TypeDesc::Int,
                    required: true,
                    description: "Number of flows exported.".into(),
                },
            ]),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        require_native(&format_param(&args)?)?;
        let ids = ids_param(&args)?;
        let flows = collect_flows(host, ids)?;
        let bytes = encode_native(&flows)?;
        let count = Value::Int(flows.len() as i64);
        match args.get("path") {
            Some(Value::Str(path)) => {
                std::fs::write(path, &bytes)
                    .with_context(|| format!("writing export to {path}"))?;
                Ok(object([
                    ("path", Value::Str(path.clone())),
                    ("flows", count),
                ]))
            }
            Some(Value::Null) | None => {
                Ok(object([("bytes", Value::Bytes(bytes)), ("flows", count)]))
            }
            Some(other) => anyhow::bail!("param `path` must be a string, got {other:?}"),
        }
    }
}

/// `flow.import {path?, bytes?, format?}` → insert flows from a document. Passive.
struct FlowImport;

impl Command for FlowImport {
    fn name(&self) -> &str {
        "flow.import"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Import flows from a native `aitm` document (by `path` or `bytes`) into \
                          the store, marked `imported`. Passive: no upstream requests, never \
                          replays."
                .into(),
            params: vec![
                ParamDef {
                    name: "path".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Read the document from this path.".into(),
                },
                ParamDef {
                    name: "bytes".into(),
                    ty: TypeDesc::Bytes,
                    required: false,
                    description: "The document bytes (alternative to `path`).".into(),
                },
                ParamDef {
                    name: "format".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Serialization format; `aitm` (default).".into(),
                },
            ],
            result: TypeDesc::Object(vec![ParamDef {
                name: "ids".into(),
                ty: TypeDesc::Array(Box::new(TypeDesc::FlowId)),
                required: true,
                description: "Ids of the imported flows.".into(),
            }]),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        require_native(&format_param(&args)?)?;
        let bytes = match (args.get("bytes"), args.get("path")) {
            (Some(Value::Bytes(b)), _) => b.clone(),
            (_, Some(Value::Str(path))) => {
                std::fs::read(path).with_context(|| format!("reading import from {path}"))?
            }
            _ => anyhow::bail!("flow.import needs `bytes` or `path`"),
        };
        let doc = parse_native(&bytes)?;
        let store = host.store();
        let mut ids = Vec::new();
        for mut flow in from_doc(&doc) {
            // Imported flows are tagged `imported` and are explicitly not replays;
            // nothing egresses — they only populate the store.
            let meta = flow.metadata_mut();
            meta.is_replay = false;
            if !meta.marks.iter().any(|m| m == "imported") {
                meta.marks.push("imported".to_string());
            }
            ids.push(Value::Str(store.insert(flow).to_string()));
        }
        Ok(object([("ids", Value::Array(ids))]))
    }
}

/// Build an object `Value` from `(name, value)` pairs.
fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}
