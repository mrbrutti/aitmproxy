//! PoC library and artifact commands (F13): `poc.list`, `poc.get`, `poc.artifact`.
//!
//! `poc.list` and `poc.get` read the PoC library under the configured `poc.dir`
//! (the directory `poc.run` loads from); `poc.artifact` serves a run artifact (the
//! YAML copy or screenshot `poc.run` wrote) as bytes, confined to the configured
//! `poc.out_dir`. All reads go through the shared [`crate::loader`], which resists
//! symlink/traversal tricks and returns one non-revealing error.
//!
//! A persistent per-run *findings record* (pass/fail over time) is not kept by the
//! core yet; these commands expose the files on disk, which is what the PoC panel
//! needs to list, open and export.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use aitm_core::{Command, CommandHost, ParamDef, ParamSchema, Params, Registry, TypeDesc, Value};

use crate::loader::{self, MAX_POC_BYTES};
use crate::model::{Poc, Severity};

/// An artifact (screenshot PNG, YAML copy) is capped near the bus's own payload
/// limit so a single read cannot be made to buffer an unbounded file.
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

/// `poc.run` only ever writes these artifact kinds; restricting `poc.artifact` to
/// them means a mis-pointed `out_dir` (e.g. one that contains the CA key) cannot
/// be used to read a `.pem`/`.key` through the bus.
const ARTIFACT_EXTENSIONS: [&str; 3] = ["png", "yaml", "yml"];

/// Cap how many directory entries `poc.list` scans, so a huge library directory
/// cannot stall the command.
const MAX_LIST_ENTRIES: usize = 10_000;

/// Register `poc.list`, `poc.get`, and `poc.artifact`.
pub fn register(registry: &mut Registry) {
    registry.add_command(Arc::new(PocList));
    registry.add_command(Arc::new(PocGet));
    registry.add_command(Arc::new(PocArtifact));
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

/// A one-line summary object for a PoC on disk.
fn summary(path: &Path, poc: &Poc) -> Value {
    let mut obj = BTreeMap::new();
    obj.insert("poc_path".into(), Value::Str(path.display().to_string()));
    obj.insert("id".into(), Value::Str(poc.id.clone()));
    obj.insert("title".into(), Value::Str(poc.info.name.clone()));
    obj.insert(
        "severity".into(),
        Value::Str(severity_str(poc.info.severity).into()),
    );
    Value::Object(obj)
}

/// Load one PoC under `dir`, returning `None` (and logging) when it does not parse.
fn load_summary(path: &Path, dir: &Path) -> Option<Value> {
    match loader::read_confined(path, dir, MAX_POC_BYTES)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|t| loader::parse_poc(&t).ok())
    {
        Some(poc) => Some(summary(path, &poc)),
        None => {
            tracing::warn!(path = %path.display(), "poc.list: skipping unreadable or invalid PoC file");
            None
        }
    }
}

/// `poc.list` → the PoCs in the configured library directory.
struct PocList;

impl Command for PocList {
    fn name(&self) -> &str {
        "poc.list"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the PoCs in the configured PoC directory (id, title, severity, \
                          path). Empty when no PoC directory is configured."
                .into(),
            params: vec![],
            result: TypeDesc::Array(Box::new(TypeDesc::Object(Vec::new()))),
        }
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let Some(dir) = host.config().and_then(|c| c.poc.dir.clone()) else {
            return Ok(Value::Array(Vec::new()));
        };
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            // A missing/unreadable library is an empty list, not an error, and does
            // not disclose the path's state.
            Err(_) => return Ok(Value::Array(Vec::new())),
        };
        let mut out = Vec::new();
        for entry in entries.flatten().take(MAX_LIST_ENTRIES) {
            let path = entry.path();
            let is_yaml = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yaml" || e == "yml");
            if !is_yaml || !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            if let Some(item) = load_summary(&path, &dir) {
                out.push(item);
            }
        }
        // Stable order so the panel does not reshuffle between polls.
        out.sort_by(|a, b| path_of(a).cmp(path_of(b)));
        Ok(Value::Array(out))
    }
}

fn path_of(v: &Value) -> &str {
    match v {
        Value::Object(o) => match o.get("poc_path") {
            Some(Value::Str(s)) => s,
            _ => "",
        },
        _ => "",
    }
}

/// `poc.get` → the parsed PoC at `poc_path`, confined to the PoC directory.
struct PocGet;

impl Command for PocGet {
    fn name(&self) -> &str {
        "poc.get"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Read one PoC by path (confined to the PoC directory): id, title, \
                          severity, description, and the YAML source."
                .into(),
            params: vec![ParamDef {
                name: "poc_path".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "Path to the PoC YAML file.".into(),
            }],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let poc_path = args.get_str("poc_path")?;
        let dir = host
            .config()
            .and_then(|c| c.poc.dir.clone())
            .ok_or_else(|| anyhow::anyhow!("poc.get: no PoC directory is configured"))?;
        let bytes = loader::read_confined(Path::new(poc_path), &dir, MAX_POC_BYTES)
            .map_err(|e| anyhow::anyhow!("poc.get: {e}"))?;
        let text = String::from_utf8(bytes).map_err(|_| {
            anyhow::anyhow!("poc.get: not found or outside the configured PoC directory")
        })?;
        let poc = loader::parse_poc(&text).map_err(|e| anyhow::anyhow!("poc.get: {e}"))?;

        let mut obj = BTreeMap::new();
        obj.insert("poc_path".into(), Value::Str(poc_path.to_string()));
        obj.insert("id".into(), Value::Str(poc.id.clone()));
        obj.insert("title".into(), Value::Str(poc.info.name.clone()));
        obj.insert(
            "severity".into(),
            Value::Str(severity_str(poc.info.severity).into()),
        );
        obj.insert(
            "description".into(),
            poc.info.description.clone().map_or(Value::Null, Value::Str),
        );
        obj.insert("yaml".into(), Value::Str(text));
        Ok(Value::Object(obj))
    }
}

/// `poc.artifact` → the bytes of a run artifact, confined to the PoC out-dir.
struct PocArtifact;

impl Command for PocArtifact {
    fn name(&self) -> &str {
        "poc.artifact"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Read a PoC run artifact (YAML copy or screenshot) as bytes, confined to \
                          the configured PoC output directory."
                .into(),
            params: vec![ParamDef {
                name: "path".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "Path to the artifact, under the PoC output directory.".into(),
            }],
            result: TypeDesc::Bytes,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let path_arg = args.get_str("path")?;
        // Only serve the artifact kinds poc.run writes; never a .pem/.key, even if
        // out_dir were mis-configured to contain key material.
        let ext_ok = Path::new(path_arg)
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| ARTIFACT_EXTENSIONS.contains(&e));
        if !ext_ok {
            anyhow::bail!(
                "poc.artifact: only {} artifacts are served",
                ARTIFACT_EXTENSIONS.join(", ")
            );
        }
        let root = host
            .config()
            .and_then(|c| c.poc.out_dir.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "poc.artifact: no PoC output directory is configured (set poc.out_dir)"
                )
            })?;
        let bytes = loader::read_confined(Path::new(path_arg), &root, MAX_ARTIFACT_BYTES)
            .map_err(|e| anyhow::anyhow!("poc.artifact: {e}"))?;
        Ok(Value::Bytes(bytes))
    }
}
