//! PoC library and artifact commands (F13): `poc.list`, `poc.get`, `poc.artifact`.
//!
//! `poc.list` and `poc.get` read the PoC library under the configured `poc.dir`
//! (the directory `poc.run` loads from); `poc.artifact` serves a run artifact (the
//! YAML copy or screenshot `poc.run` wrote) as bytes, confined to the configured
//! `poc.out_dir`. All three refuse paths that escape their confinement root and
//! never follow a symlink at the final component, so a remote/web surface can read
//! findings without a filesystem path escape.
//!
//! A persistent per-run *findings history* (pass/fail over time) is not kept by
//! the core yet; these commands expose the files on disk, which is what the PoC
//! panel needs to list, open and export.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use aitm_core::{Command, CommandHost, ParamDef, ParamSchema, Params, Registry, TypeDesc, Value};

use crate::model::{Poc, Severity};

/// Cap a single PoC document at 1 MiB (as `poc.run` does) and an artifact at
/// 50 MiB (a screenshot PNG), so a surface cannot be made to buffer an unbounded
/// file through the bus.
const MAX_POC_BYTES: u64 = 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 50 * 1024 * 1024;

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
    obj.insert("name".into(), Value::Str(poc.info.name.clone()));
    obj.insert(
        "severity".into(),
        Value::Str(severity_str(poc.info.severity).into()),
    );
    Value::Object(obj)
}

/// `poc.list` → the PoCs in the configured library directory.
struct PocList;

impl Command for PocList {
    fn name(&self) -> &str {
        "poc.list"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the PoCs in the configured PoC directory (id, name, severity, \
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
        let mut out = Vec::new();
        let entries = std::fs::read_dir(&dir).map_err(|e| {
            anyhow::anyhow!("poc.list: cannot read PoC dir `{}`: {e}", dir.display())
        })?;
        for entry in entries.flatten() {
            let path = entry.path();
            let is_yaml = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yaml" || e == "yml");
            if !is_yaml || !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            // Skip a file that does not parse rather than failing the whole list.
            if let Ok(poc) = load_poc(&path, &dir) {
                out.push(summary(&path, &poc));
            }
        }
        // Stable order so the panel does not reshuffle between polls.
        out.sort_by(|a, b| id_of(a).cmp(id_of(b)));
        Ok(Value::Array(out))
    }
}

fn id_of(v: &Value) -> &str {
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
            description: "Read one PoC by path (confined to the PoC directory): id, name, \
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
        let path = Path::new(poc_path);
        let text = read_confined_text(path, &dir, MAX_POC_BYTES)
            .map_err(|e| anyhow::anyhow!("poc.get: {e}"))?;
        let poc = parse_poc(&text).map_err(|e| anyhow::anyhow!("poc.get: `{poc_path}`: {e}"))?;

        let mut obj = BTreeMap::new();
        obj.insert("poc_path".into(), Value::Str(poc_path.to_string()));
        obj.insert("id".into(), Value::Str(poc.id.clone()));
        obj.insert("name".into(), Value::Str(poc.info.name.clone()));
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
        let root = host
            .config()
            .and_then(|c| c.poc.out_dir.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "poc.artifact: no PoC output directory is configured (set poc.out_dir)"
                )
            })?;
        let bytes = read_confined_bytes(Path::new(path_arg), &root, MAX_ARTIFACT_BYTES)
            .map_err(|e| anyhow::anyhow!("poc.artifact: {e}"))?;
        Ok(Value::Bytes(bytes))
    }
}

// ---------------------------------------------------------------------------
// Safe, confined loading
// ---------------------------------------------------------------------------

fn parse_poc(text: &str) -> anyhow::Result<Poc> {
    let raw: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|_| anyhow::anyhow!("not valid YAML"))?;
    crate::schema::validate(&raw).map_err(|e| anyhow::anyhow!("failed validation: {e}"))?;
    serde_yaml::from_value(raw).map_err(|_| anyhow::anyhow!("not a valid PoC document"))
}

fn load_poc(path: &Path, root: &Path) -> anyhow::Result<Poc> {
    let text = read_confined_text(path, root, MAX_POC_BYTES)?;
    parse_poc(&text)
}

/// Resolve `path`, require it under `root` (canonicalized, so `..`/symlinks are
/// followed), open without following a final symlink, cap the size, read bytes.
fn read_confined_bytes(path: &Path, root: &Path, max: u64) -> anyhow::Result<Vec<u8>> {
    let canon_root = root
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("dir `{}` is not accessible: {e}", root.display()))?;
    let canon_path = path
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot resolve `{}`: {e}", path.display()))?;
    if !canon_path.starts_with(&canon_root) {
        anyhow::bail!("`{}` is outside `{}`", path.display(), canon_root.display());
    }
    let mut file = open_nofollow(&canon_path)
        .map_err(|e| anyhow::anyhow!("cannot open `{}`: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| anyhow::anyhow!("cannot stat `{}`: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        anyhow::bail!("`{}` is not a regular file", path.display());
    }
    if meta.len() > max {
        anyhow::bail!("`{}` exceeds the {max}-byte cap", path.display());
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    std::io::Read::read_to_end(&mut file, &mut buf)
        .map_err(|e| anyhow::anyhow!("cannot read `{}`: {e}", path.display()))?;
    Ok(buf)
}

fn read_confined_text(path: &Path, root: &Path, max: u64) -> anyhow::Result<String> {
    let bytes = read_confined_bytes(path, root, max)?;
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("`{}` is not UTF-8", path.display()))
}

/// Open read-only without following a symlink at the final component.
#[cfg(unix)]
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to open a symlink",
        ));
    }
    std::fs::File::open(path)
}
