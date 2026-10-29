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
//! **Formats.** `flow.export`/`flow.import` carry a `format` param ([`Format`]).
//! Native `aitm` (full fidelity) and HAR 1.2 (lossy interchange) both export and
//! import; mitmproxy `.flows` is import-only. `session.save`/`session.load`
//! remain native-only — they persist and restore the whole store verbatim.

pub mod har;
pub mod mitmproxy;
pub mod native;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, Flow, FlowId, Frontend, ParamDef, ParamSchema, Params, Plugin, Registry,
    TypeDesc, Value,
};
use anyhow::Context;

use native::{from_doc, to_doc, SessionDoc, SCHEMA};

/// Default cap on a single session/flow document read from a host path. A file
/// larger than this is refused before it is read, so a hostile document cannot
/// force an unbounded allocation. Generous (1 GiB) so real sessions load; the
/// operator can lower it via [`SessionIoPlugin::with_max_doc_bytes`].
const DEFAULT_MAX_DOC_BYTES: u64 = 1024 * 1024 * 1024;

/// A serialization format for `flow.export`/`flow.import`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// Native `aitm` session JSON: full fidelity, round-trips every field.
    Aitm,
    /// HAR 1.2: a lossy, portable interchange.
    Har,
    /// mitmproxy `.flows`: import only.
    Mitmproxy,
}

/// The file-I/O policy every session/flow command shares: the agent gate, the
/// optional confinement root, and the read-size cap. Cloned into each command at
/// `load`.
#[derive(Clone)]
struct FileIo {
    /// Whether an agent (MCP) frontend may hand these commands a host path.
    /// Off by default; see [`aitm_core::SessionIoConfig::allow_agent_file_io`].
    allow_agent_file_io: bool,
    /// When set, every path argument must resolve under this directory (traversal
    /// and absolute escapes are refused). `None` (the default) imposes no
    /// confinement — the human CLI keeps full path access, as before.
    session_root: Option<PathBuf>,
    /// Cap on a document read from a host path; a larger file is refused before it
    /// is read (DoS guard).
    max_doc_bytes: u64,
}

/// Registers `session.save`, `session.load`, `flow.export`, `flow.import`.
/// Observes no events — serialization is a pure view over the store.
pub struct SessionIoPlugin {
    io: FileIo,
}

impl SessionIoPlugin {
    /// Build the plugin with the agent file-I/O gate. `allow_agent_file_io` (off at
    /// the call site by default) lets an agent frontend read/write a host path.
    /// Confinement is off and the read cap is [`DEFAULT_MAX_DOC_BYTES`]; use
    /// [`Self::with_session_root`] / [`Self::with_max_doc_bytes`] to tighten them.
    pub fn new(allow_agent_file_io: bool) -> Self {
        Self {
            io: FileIo {
                allow_agent_file_io,
                session_root: None,
                max_doc_bytes: DEFAULT_MAX_DOC_BYTES,
            },
        }
    }

    /// Confine every path argument under `root` (traversal/absolute escapes are
    /// refused). `None` keeps the default of no confinement.
    pub fn with_session_root(mut self, root: Option<PathBuf>) -> Self {
        self.io.session_root = root;
        self
    }

    /// Set the maximum size of a document read from a host path.
    pub fn with_max_doc_bytes(mut self, max: u64) -> Self {
        self.io.max_doc_bytes = max;
        self
    }
}

impl Default for SessionIoPlugin {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Plugin for SessionIoPlugin {
    fn name(&self) -> &str {
        "sessionio"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(SessionSave {
            io: self.io.clone(),
        }));
        reg.add_command(Arc::new(SessionLoad {
            io: self.io.clone(),
        }));
        reg.add_command(Arc::new(FlowExport {
            io: self.io.clone(),
        }));
        reg.add_command(Arc::new(FlowImport {
            io: self.io.clone(),
        }));
    }
}

/// Refuse a host-path file operation from an agent frontend unless the gate is
/// open. `session.save`/`session.load`/`flow.export`/`flow.import` can read or
/// overwrite an arbitrary host file, so they mirror `scope.add`'s agent gate; the
/// human CLI (`Frontend::Cli`) always keeps full path access.
fn check_file_io_gate(host: &CommandHost, allow_agent_file_io: bool) -> anyhow::Result<()> {
    if host.frontend() != Frontend::Cli && !allow_agent_file_io {
        anyhow::bail!(
            "file I/O refused: reading or writing a host path from an agent frontend is \
             disabled. Set session_io.allow_agent_file_io = true in the aitmproxy config to \
             allow it, run the command from the human CLI, or pass `bytes` instead of `path`."
        );
    }
    Ok(())
}

/// Confine `path` under the configured session root. With no root (the default)
/// the path is returned unchanged — the human CLI keeps full access. With a root,
/// the path must resolve under it (the canonicalize + `starts_with` pattern Map
/// Local uses), extended to confine a not-yet-existing write target by its parent
/// directory. A traversal (`..`) or absolute path that escapes the root is refused.
fn confine_path(io: &FileIo, path: &str) -> anyhow::Result<PathBuf> {
    let Some(root) = io.session_root.as_deref() else {
        return Ok(PathBuf::from(path));
    };
    let root = root.canonicalize().map_err(|err| {
        anyhow::anyhow!("session root {} is not accessible: {err}", root.display())
    })?;
    // `join` with an absolute `path` replaces `root`; the prefix check below then
    // rejects it, so an absolute escaping path is refused too.
    let candidate = root.join(path);
    let resolved = match candidate.canonicalize() {
        // An existing file (reads, or an overwrite): resolve it directly.
        Ok(resolved) => resolved,
        // A not-yet-existing write target: confine its parent directory, then
        // re-attach the final component (the parent must exist to write into).
        Err(_) => {
            let parent = candidate
                .parent()
                .ok_or_else(|| anyhow::anyhow!("path {path:?} has no parent directory"))?;
            let file = candidate
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("path {path:?} has no file name"))?;
            parent
                .canonicalize()
                .map_err(|err| {
                    anyhow::anyhow!("path {path:?} parent directory is not accessible: {err}")
                })?
                .join(file)
        }
    };
    if !resolved.starts_with(&root) {
        anyhow::bail!("path {path:?} escapes the session root {}", root.display());
    }
    Ok(resolved)
}

/// Read a document from a confined path, refusing a file over the configured cap
/// before reading it (stat, then read) so a hostile document cannot force an
/// unbounded allocation.
fn read_capped(io: &FileIo, path: &Path) -> anyhow::Result<Vec<u8>> {
    let len = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    if len > io.max_doc_bytes {
        anyhow::bail!(
            "document {} is {len} bytes, over the {}-byte limit",
            path.display(),
            io.max_doc_bytes
        );
    }
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

/// The requested format, defaulting to native `aitm` when omitted.
fn format_param(args: &Params) -> anyhow::Result<Format> {
    let name = match args.get("format") {
        None | Some(Value::Null) => return Ok(Format::Aitm),
        Some(Value::Str(s)) => s.as_str(),
        Some(other) => anyhow::bail!("param `format` must be a string, got {other:?}"),
    };
    match name {
        "aitm" => Ok(Format::Aitm),
        "har" => Ok(Format::Har),
        "mitmproxy" => Ok(Format::Mitmproxy),
        other => anyhow::bail!("unknown format `{other}`; use `aitm`, `har`, or `mitmproxy`"),
    }
}

/// Serialize flows in the requested format. mitmproxy `.flows` is import-only, so
/// exporting it is a clear, catchable refusal.
fn encode(format: Format, flows: &[Flow]) -> anyhow::Result<Vec<u8>> {
    match format {
        Format::Aitm => encode_native(flows),
        Format::Har => serde_json::to_vec_pretty(&har::flows_to_har(flows))
            .context("serializing HAR 1.2 document"),
        Format::Mitmproxy => {
            anyhow::bail!("format `mitmproxy` is import-only; export as `har` or `aitm`")
        }
    }
}

/// Parse flows from the requested format. Every path is passive: it only builds
/// `Flow`s in memory and never egresses.
fn decode(format: Format, bytes: &[u8]) -> anyhow::Result<Vec<Flow>> {
    match format {
        Format::Aitm => Ok(from_doc(&parse_native(bytes)?)),
        Format::Har => {
            let doc: har::Har =
                serde_json::from_slice(bytes).context("parsing HAR 1.2 document")?;
            har::har_to_flows(&doc)
        }
        Format::Mitmproxy => mitmproxy::mitmproxy_to_flows(bytes),
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
struct SessionSave {
    io: FileIo,
}

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
        // Always writes a host path, so the agent gate always applies.
        check_file_io_gate(host, self.io.allow_agent_file_io)?;
        let path = args.get_str("path")?.to_string();
        let target = confine_path(&self.io, &path)?;
        let flows = collect_flows(host, None)?;
        let bytes = encode_native(&flows)?;
        std::fs::write(&target, &bytes)
            .with_context(|| format!("writing session to {}", target.display()))?;
        Ok(object([
            ("flows", Value::Int(flows.len() as i64)),
            ("path", Value::Str(path)),
        ]))
    }
}

/// `session.load {path}` → replace the store with the flows in `path`.
struct SessionLoad {
    io: FileIo,
}

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
        // Always reads a host path, so the agent gate always applies.
        check_file_io_gate(host, self.io.allow_agent_file_io)?;
        let path = args.get_str("path")?;
        let target = confine_path(&self.io, path)?;
        let bytes = read_capped(&self.io, &target)?;
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
struct FlowExport {
    io: FileIo,
}

impl Command for FlowExport {
    fn name(&self) -> &str {
        "flow.export"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Export selected flows (or the whole store) as `aitm` native JSON or \
                          HAR 1.2. Returns bytes, or writes to `path` when given."
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
                    description: "Serialization format; `aitm` (default) or `har`.".into(),
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
        let format = format_param(&args)?;
        let ids = ids_param(&args)?;
        let flows = collect_flows(host, ids)?;
        let bytes = encode(format, &flows)?;
        let count = Value::Int(flows.len() as i64);
        match args.get("path") {
            Some(Value::Str(path)) => {
                // Writing a host path: gate an agent. Exporting without a `path`
                // (returns bytes) stays allowed for any frontend — it is passive.
                check_file_io_gate(host, self.io.allow_agent_file_io)?;
                let target = confine_path(&self.io, path)?;
                std::fs::write(&target, &bytes)
                    .with_context(|| format!("writing export to {}", target.display()))?;
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
struct FlowImport {
    io: FileIo,
}

impl Command for FlowImport {
    fn name(&self) -> &str {
        "flow.import"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Import flows (by `path` or `bytes`) into the store, marked `imported`. \
                          Formats: `aitm`, `har`, or mitmproxy `.flows`. Passive: no upstream \
                          requests, never replays."
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
                    description: "Serialization format; `aitm` (default), `har`, or `mitmproxy`."
                        .into(),
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
        let format = format_param(&args)?;
        let bytes = match (args.get("bytes"), args.get("path")) {
            (Some(Value::Bytes(b)), _) => b.clone(),
            (_, Some(Value::Str(path))) => {
                // Reading a host path: gate an agent. Importing from `bytes`
                // (checked first above) stays allowed for any frontend — passive.
                check_file_io_gate(host, self.io.allow_agent_file_io)?;
                let target = confine_path(&self.io, path)?;
                read_capped(&self.io, &target)?
            }
            _ => anyhow::bail!("flow.import needs `bytes` or `path`"),
        };
        let flows = decode(format, &bytes)?;
        let store = host.store();
        let mut ids = Vec::new();
        for mut flow in flows {
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
