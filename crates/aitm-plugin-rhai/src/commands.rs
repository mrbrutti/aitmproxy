//! The tier's own operator-facing commands (spec §3, §8): `script.validate`,
//! `script.reload`, `script.findings`, and `script.list`, registered by
//! [`ScriptCommands`] — one more `Plugin` whose `load` adds native `Command`s,
//! so MCP `tools/list` and the CLI (`aitm script validate --path x.rhai`) pick
//! them up with no special casing.
//!
//! - **`script.validate { path | source }`** compiles a file, or script text
//!   given inline, on the shared engine without registering anything and
//!   answers with the script's declared metadata and a best-effort static
//!   `registers { commands, options }` scan, or the positioned compile error
//!   in the pinned format. Exactly one of `path`/`source`. Only a `.rhai` path
//!   is read, so the command is not a general file probe for an agent
//!   frontend; `source` is bounded by the sandbox `max_string_size`.
//! - **`script.reload { name }`** recompiles a loaded script from its file and
//!   swaps its hooks live through the [`ScriptHandle`] it shares with the
//!   plugin; a recompile that fails leaves the previous good AST in service.
//!   Commands and options the script's `load(reg)` registered are not
//!   re-run — those still need a restart (the registry is sealed once built).
//! - **`script.findings { limit? }`** reads the in-memory [`FindingSink`] back:
//!   every finding a script emitted with `finding(...)` this run, as an object
//!   (newest last), and how many the bounded sink dropped. Distinct from the
//!   persistent `findings.*` store (`aitm-findings`): this lists only the
//!   current process's script-emitted findings and persists nothing.
//! - **`script.list {}`** enumerates the loaded scripts in chain order:
//!   `{ name, path, api, hooks, enabled, last_error }`, read from the live
//!   handles and the shared [`ErrorSink`], so it reports current state, not
//!   the config file. Read-tier, so an agent may call it.
//! - **`script.enable { name }` / `script.disable { name }`** flip a loaded
//!   script's live `enabled` flag (a disabled script's hooks are skipped; its
//!   registered commands remain) and answer `{ name, enabled }`. Idempotent;
//!   an unknown name gets `script.reload`'s error. `Sensitive`.
//! - **`script.save { name, source, enable? }`** writes `<scripts_dir>/<name>.rhai`
//!   (see [`Save`] for the confinement and the overwrite-live / new-name split)
//!   and answers `{ name, path, api, hooks, registers, restart_required }`.
//!   `Sensitive`.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Command, CommandHost, Frontend, ParamDef, ParamSchema, Params, Plugin, Registry, Sensitivity,
    TypeDesc, Value,
};

use crate::config::ScriptMeta;
use crate::host_core::{severity_name, Finding, FindingSink};
use crate::loader::{Registers, RhaiLoader, Validated};
use crate::plugin::{ErrorSink, ScriptHandle};

/// Registers the three commands. Built by `wire::build` over the same loader
/// and sink the plugins use; the host registers it among the command
/// providers, after the script plugins.
pub struct ScriptCommands {
    loader: Arc<RhaiLoader>,
    scripts: Vec<Arc<ScriptHandle>>,
    findings: Arc<dyn FindingSink>,
    errors: Arc<ErrorSink>,
}

impl ScriptCommands {
    pub fn new(
        loader: Arc<RhaiLoader>,
        scripts: Vec<Arc<ScriptHandle>>,
        findings: Arc<dyn FindingSink>,
        errors: Arc<ErrorSink>,
    ) -> Self {
        Self {
            loader,
            scripts,
            findings,
            errors,
        }
    }
}

impl Plugin for ScriptCommands {
    fn name(&self) -> &str {
        "scripts"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(Validate {
            loader: Arc::clone(&self.loader),
        }));
        reg.add_command(Arc::new(Reload {
            loader: Arc::clone(&self.loader),
            scripts: self.scripts.clone(),
            errors: Arc::clone(&self.errors),
        }));
        reg.add_command(Arc::new(ScriptFindings {
            findings: Arc::clone(&self.findings),
        }));
        reg.add_command(Arc::new(List {
            scripts: self.scripts.clone(),
            errors: Arc::clone(&self.errors),
        }));
        reg.add_command(Arc::new(Toggle {
            scripts: self.scripts.clone(),
            enable: true,
        }));
        reg.add_command(Arc::new(Toggle {
            scripts: self.scripts.clone(),
            enable: false,
        }));
        reg.add_command(Arc::new(Save {
            loader: Arc::clone(&self.loader),
            scripts: self.scripts.clone(),
            errors: Arc::clone(&self.errors),
        }));
    }
}

struct Validate {
    loader: Arc<RhaiLoader>,
}

struct Reload {
    loader: Arc<RhaiLoader>,
    scripts: Vec<Arc<ScriptHandle>>,
    errors: Arc<ErrorSink>,
}

struct List {
    scripts: Vec<Arc<ScriptHandle>>,
    errors: Arc<ErrorSink>,
}

/// `script.enable` (`enable: true`) / `script.disable` (`enable: false`): one
/// type, two registered commands, so the lookup and the answer shape cannot
/// drift apart.
struct Toggle {
    scripts: Vec<Arc<ScriptHandle>>,
    enable: bool,
}

struct ScriptFindings {
    findings: Arc<dyn FindingSink>,
}

/// `script.save`: the only command here that writes to disk, so every write is
/// confined to the operator-configured `scripts_dir` and nothing is touched
/// until the request has passed, in order: the `name` rule, the `scripts_dir`
/// opt-in, the size cap, and a compile of the source.
///
/// The plugin chain is sealed once built, so a brand-new script's hooks cannot
/// join the running chain: that save persists the file (the config scan loads
/// it next start) and answers `restart_required: true`. Saving over a script
/// that is already loaded swaps its AST through the shared handle, exactly as
/// `script.reload` does, so the new hooks run live.
struct Save {
    loader: Arc<RhaiLoader>,
    scripts: Vec<Arc<ScriptHandle>>,
    errors: Arc<ErrorSink>,
}

/// The one extension a script file may have; `script.validate` reads nothing
/// else.
const SCRIPT_EXT: &str = "rhai";

impl Command for Validate {
    fn name(&self) -> &str {
        "script.validate"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Compile a .rhai script without loading it; reports its name, API, \
                          hooks and the commands/options its load(reg) registers (a static \
                          scan; empty when the names are not literals), or the positioned \
                          compile error. Give exactly one of `path` (a file) or `source` (the \
                          script text, compiled in the sandbox with nothing written)."
                .to_string(),
            params: vec![
                param(
                    "path",
                    TypeDesc::Str,
                    false,
                    "path to the .rhai file to check; exactly one of `path` or `source`",
                ),
                param(
                    "source",
                    TypeDesc::Str,
                    false,
                    "the script text to check, at most the sandbox max_string_size bytes; \
                     exactly one of `path` or `source`",
                ),
            ],
            result: TypeDesc::Any,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        match (
            optional_text(&args, "path")?,
            optional_text(&args, "source")?,
        ) {
            (Some(_), Some(_)) => {
                anyhow::bail!("script.validate takes exactly one of `path` or `source`, got both")
            }
            (None, None) => anyhow::bail!(
                "script.validate takes exactly one of `path` or `source`, got neither"
            ),
            (Some(path), None) => {
                let path = Path::new(&path);
                if path.extension().and_then(|e| e.to_str()) != Some(SCRIPT_EXT) {
                    anyhow::bail!(
                        "script.validate reads only .rhai files, got {}",
                        path.display()
                    );
                }
                confine_validate(host, path)?;
                let validated = self
                    .loader
                    .validate_with_registers(path)
                    .map_err(|err| anyhow::anyhow!("{err}"))?;
                Ok(validate_value(&validated, true))
            }
            (None, Some(source)) => {
                // No file to confine; the only bound is the sandbox's string cap.
                let limit = self.loader.max_string_size();
                if source.len() > limit {
                    anyhow::bail!(
                        "`source` is {} bytes, over the sandbox max_string_size ({limit})",
                        source.len()
                    );
                }
                let validated = self
                    .loader
                    .validate_source(&source)
                    .map_err(|err| anyhow::anyhow!("{err}"))?;
                Ok(validate_value(&validated, false))
            }
        }
    }
}

/// Keep `script.validate` from being a file-existence / content-disclosure
/// oracle. The human CLI (`Frontend::Cli`) may compile any `.rhai` path; an
/// agent frontend may reach only a file inside the configured scripts/PoC
/// directory (`poc.dir`). Both "outside the directory" and "does not resolve"
/// return the one generic refusal, so the command never confirms the presence
/// of a file it would not read.
fn confine_validate(host: &CommandHost, path: &Path) -> anyhow::Result<()> {
    if host.frontend() == Frontend::Cli {
        return Ok(());
    }
    let within = host
        .poc_dir()
        .and_then(|root| root.canonicalize().ok())
        .zip(path.canonicalize().ok())
        .is_some_and(|(root, target)| target.starts_with(root));
    if !within {
        anyhow::bail!(
            "script.validate from an agent frontend may read only a .rhai file inside the \
             configured scripts/PoC directory (poc.dir); run it from the human CLI for an \
             arbitrary path"
        );
    }
    Ok(())
}

impl Command for Reload {
    fn name(&self) -> &str {
        "script.reload"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Recompile a loaded script from its file and swap its hooks live; a \
                          failed recompile keeps the previous version. Commands and options it \
                          registered at load are unchanged until restart."
                .to_string(),
            params: vec![param(
                "name",
                TypeDesc::Str,
                true,
                "the script's NAME (or file stem) as loaded",
            )],
            result: TypeDesc::Any,
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let name = text(&args, "name")?;
        let handle = find_script(&self.scripts, &name)?;
        let (ast, meta) = self
            .loader
            .compile(handle.path())
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        handle.swap(ast);
        self.errors.clear(&name);
        tracing::info!(
            target: "aitm_plugin_rhai::loader",
            script = %name,
            path = %handle.path().display(),
            hooks = ?meta.hooks,
            "script reloaded"
        );
        Ok(meta_value(&meta))
    }
}

impl Command for Toggle {
    fn name(&self) -> &str {
        if self.enable {
            "script.enable"
        } else {
            "script.disable"
        }
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: if self.enable {
                "Turn a loaded script's hooks back on live. Idempotent. Answers { name, \
                 enabled }."
            } else {
                "Turn a loaded script's hooks off live without unloading it; commands and \
                 options it registered stay (the registry is sealed). Idempotent. Answers \
                 { name, enabled }."
            }
            .to_string(),
            params: vec![param(
                "name",
                TypeDesc::Str,
                true,
                "the script's NAME (or file stem) as loaded",
            )],
            result: TypeDesc::Any,
        }
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let name = text(&args, "name")?;
        let handle = find_script(&self.scripts, &name)?;
        handle.set_enabled(self.enable);
        Ok(Value::Object(BTreeMap::from([
            ("name".to_string(), Value::Str(handle.name().to_string())),
            ("enabled".to_string(), Value::Bool(handle.is_enabled())),
        ])))
    }
}

/// Whether `name` is exactly one `[A-Za-z0-9_-]+` path segment. A character
/// check, not a filesystem question: no separator, dot, NUL or non-ASCII byte
/// survives it, so `<scripts_dir>/<name>.rhai` cannot name anything outside
/// `scripts_dir`.
fn is_script_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Distinguishes the temp files of concurrent saves in one process.
static SAVE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Write `source` as `<dir>/<name>.rhai` and return that path. `name` must
/// already have passed [`is_script_name`].
///
/// Defence in depth behind the name rule: the directory is created if absent,
/// the target's canonical parent must be the canonical `dir`, and a target that
/// already exists must itself resolve inside `dir` (a symlink out is refused,
/// never followed). The bytes go to a hidden `.tmp` sibling first and are
/// renamed over the target, so a failed save leaves no half-written `.rhai`
/// for the startup scan to load, and `rename` replaces a link rather than
/// writing through it.
fn write_script(dir: &Path, name: &str, source: &str) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("cannot create scripts directory {}: {e}", dir.display()))?;
    let canonical_dir = dir
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot resolve scripts directory {}: {e}", dir.display()))?;
    let target = dir.join(format!("{name}.{SCRIPT_EXT}"));

    let parent_ok = target
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .is_some_and(|p| p == canonical_dir);
    let target_ok = match fs::symlink_metadata(&target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
        Ok(_) => target
            .canonicalize()
            .ok()
            .and_then(|t| t.parent().map(Path::to_path_buf))
            .is_some_and(|p| p == canonical_dir),
    };
    if !parent_ok || !target_ok {
        anyhow::bail!(
            "refusing to write {}: it does not resolve inside the scripts directory",
            target.display()
        );
    }

    let tmp = dir.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        SAVE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| f.write_all(source.as_bytes()).and_then(|()| f.sync_all()))
        .and_then(|()| fs::rename(&tmp, &target));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        anyhow::bail!("cannot write {}: {e}", target.display());
    }
    Ok(target)
}

impl Command for Save {
    fn name(&self) -> &str {
        "script.save"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Write a script to <scripts_dir>/<name>.rhai after checking it \
                          compiles (a non-compiling source writes nothing). Saving over a \
                          loaded script swaps its hooks live; a new name is persisted for the \
                          next start (restart_required: true, the plugin chain is sealed). A \
                          script that registers commands/options also needs a restart. Answers \
                          { name, path, api, hooks, registers, restart_required }. Needs \
                          rhai.scripts_dir."
                .to_string(),
            params: vec![
                param(
                    "name",
                    TypeDesc::Str,
                    true,
                    "the script's file stem: letters, digits, `_` and `-` only",
                ),
                param(
                    "source",
                    TypeDesc::Str,
                    true,
                    "the script text, at most the sandbox max_string_size bytes",
                ),
                param(
                    "enable",
                    TypeDesc::Bool,
                    false,
                    "keep a loaded script enabled (default true) or disable it after the \
                     swap; no live effect for a new name",
                ),
            ],
            result: TypeDesc::Any,
        }
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        // Every refusal below happens before the disk is touched.
        let name = optional_text(&args, "name")?.unwrap_or_default();
        if !is_script_name(&name) {
            anyhow::bail!(
                "`name` must be a single path segment matching [A-Za-z0-9_-]+ (no \
                 separators, dots or spaces), got {name:?}"
            );
        }
        let source = text(&args, "source")?;
        let enable = match args.get("enable") {
            None | Some(Value::Null) => true,
            Some(Value::Bool(b)) => *b,
            Some(_) => anyhow::bail!("`enable` must be a boolean"),
        };
        let Some(dir) = self.loader.scripts_dir() else {
            anyhow::bail!("no scripts directory configured; set rhai.scripts_dir");
        };
        let limit = self.loader.max_string_size();
        if source.len() > limit {
            anyhow::bail!(
                "`source` is {} bytes, over the sandbox max_string_size ({limit})",
                source.len()
            );
        }
        // Compile-before-write: a source that does not compile writes no file.
        let validated = self
            .loader
            .validate_source(&source)
            .map_err(|err| anyhow::anyhow!("{err}"))?;

        let path = write_script(dir, &name, &source)?;

        let registers = &validated.registers;
        let registers_present = !registers.commands.is_empty() || !registers.options.is_empty();
        let restart_required = match self.scripts.iter().find(|s| s.name() == name) {
            Some(handle) => {
                // Overwrite: `script.reload` semantics over the file just written.
                let (ast, _) = self
                    .loader
                    .compile(&path)
                    .map_err(|err| anyhow::anyhow!("{err}"))?;
                handle.swap(ast);
                handle.set_enabled(enable);
                self.errors.clear(&name);
                tracing::info!(
                    target: "aitm_plugin_rhai::loader",
                    script = %name,
                    path = %path.display(),
                    "script saved over a loaded script and swapped live"
                );
                registers_present
            }
            None => {
                tracing::info!(
                    target: "aitm_plugin_rhai::loader",
                    script = %name,
                    path = %path.display(),
                    "script saved; its hooks join on the next start"
                );
                true
            }
        };

        let meta = &validated.meta;
        Ok(Value::Object(BTreeMap::from([
            ("name".to_string(), Value::Str(name)),
            ("path".to_string(), Value::Str(path.display().to_string())),
            ("api".to_string(), Value::Str(meta.api.clone())),
            (
                "hooks".to_string(),
                Value::Array(meta.hooks.iter().cloned().map(Value::Str).collect()),
            ),
            ("registers".to_string(), registers_value(registers)),
            (
                "restart_required".to_string(),
                Value::Bool(restart_required),
            ),
        ])))
    }
}

impl Command for ScriptFindings {
    fn name(&self) -> &str {
        "script.findings"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Findings scripts emitted with finding(...) this run (in-memory, not \
                          persisted): each as an object, oldest first, plus how many the bounded \
                          sink dropped. For the persistent store use findings.list/get/record."
                .to_string(),
            params: vec![param(
                "limit",
                TypeDesc::Int,
                false,
                "return only the newest N findings",
            )],
            result: TypeDesc::Any,
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let mut findings = self.findings.list();
        if let Some(Value::Int(limit)) = args.get("limit") {
            let keep = usize::try_from(*limit).unwrap_or(0);
            let skip = findings.len().saturating_sub(keep);
            findings.drain(..skip);
        }
        Ok(Value::Object(BTreeMap::from([
            (
                "findings".to_string(),
                Value::Array(findings.iter().map(finding_value).collect()),
            ),
            (
                "dropped".to_string(),
                Value::Int(i64::try_from(self.findings.dropped()).unwrap_or(i64::MAX)),
            ),
        ])))
    }
}

impl Command for List {
    fn name(&self) -> &str {
        "script.list"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the loaded scripts in chain order: name, path, API, hooks, \
                          whether enabled, and the most recent hook error (null if none)."
                .to_string(),
            params: Vec::new(),
            result: TypeDesc::Any,
        }
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Array(
            self.scripts
                .iter()
                .map(|s| {
                    let meta = s.meta();
                    Value::Object(BTreeMap::from([
                        ("name".to_string(), Value::Str(s.name().to_string())),
                        (
                            "path".to_string(),
                            Value::Str(s.path().display().to_string()),
                        ),
                        ("api".to_string(), Value::Str(meta.api.clone())),
                        (
                            "hooks".to_string(),
                            Value::Array(meta.hooks.iter().cloned().map(Value::Str).collect()),
                        ),
                        ("enabled".to_string(), Value::Bool(s.is_enabled())),
                        (
                            "last_error".to_string(),
                            self.errors
                                .last_error(s.name())
                                .map(Value::Str)
                                .unwrap_or(Value::Null),
                        ),
                    ]))
                })
                .collect(),
        ))
    }
}

/// The loaded script called `name`, or the one error every by-name script
/// command shares: it names the miss and lists what is loaded.
fn find_script<'a>(
    scripts: &'a [Arc<ScriptHandle>],
    name: &str,
) -> anyhow::Result<&'a Arc<ScriptHandle>> {
    scripts.iter().find(|s| s.name() == name).ok_or_else(|| {
        let loaded: Vec<&str> = scripts.iter().map(|s| s.name()).collect();
        anyhow::anyhow!(
            "no loaded script is named `{name}`; loaded: {}",
            if loaded.is_empty() {
                "(none)".to_string()
            } else {
                loaded.join(", ")
            }
        )
    })
}

/// A script's metadata as the frontends render it.
fn meta_value(meta: &ScriptMeta) -> Value {
    Value::Object(BTreeMap::from([
        ("name".to_string(), Value::Str(meta.name.clone())),
        ("api".to_string(), Value::Str(meta.api.clone())),
        (
            "path".to_string(),
            Value::Str(meta.path.display().to_string()),
        ),
        (
            "hooks".to_string(),
            Value::Array(meta.hooks.iter().cloned().map(Value::Str).collect()),
        ),
    ]))
}

/// What `script.validate` answers: the script's metadata (with `path` only
/// when it came from a file) plus the `registers` scan. `script.reload` and
/// `script.list` use [`meta_value`] alone and never carry `registers`.
fn validate_value(validated: &Validated, with_path: bool) -> Value {
    let meta = &validated.meta;
    let mut fields = BTreeMap::from([
        ("name".to_string(), Value::Str(meta.name.clone())),
        ("api".to_string(), Value::Str(meta.api.clone())),
        (
            "hooks".to_string(),
            Value::Array(meta.hooks.iter().cloned().map(Value::Str).collect()),
        ),
    ]);
    if with_path {
        fields.insert(
            "path".to_string(),
            Value::Str(meta.path.display().to_string()),
        );
    }
    fields.insert(
        "registers".to_string(),
        registers_value(&validated.registers),
    );
    Value::Object(fields)
}

/// The `{ commands, options }` object `registers` is reported as.
fn registers_value(registers: &Registers) -> Value {
    let names = |list: &[String]| Value::Array(list.iter().cloned().map(Value::Str).collect());
    Value::Object(BTreeMap::from([
        ("commands".to_string(), names(&registers.commands)),
        ("options".to_string(), names(&registers.options)),
    ]))
}

/// One finding as the frontends render it: `at` is Unix milliseconds.
fn finding_value(f: &Finding) -> Value {
    let at =
        f.at.duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0);
    let opt = |s: &Option<String>| s.clone().map(Value::Str).unwrap_or(Value::Null);
    Value::Object(BTreeMap::from([
        ("name".to_string(), Value::Str(f.name.clone())),
        (
            "severity".to_string(),
            Value::Str(severity_name(f.severity).to_string()),
        ),
        (
            "flow_id".to_string(),
            f.flow
                .map(|id| Value::Str(id.to_string()))
                .unwrap_or(Value::Null),
        ),
        ("detail".to_string(), opt(&f.detail)),
        (
            "tags".to_string(),
            Value::Array(f.tags.iter().cloned().map(Value::Str).collect()),
        ),
        ("source".to_string(), Value::Str(f.source.clone())),
        ("at".to_string(), Value::Int(at)),
    ]))
}

fn param(name: &str, ty: TypeDesc, required: bool, description: &str) -> ParamDef {
    ParamDef {
        name: name.to_string(),
        ty,
        required,
        description: description.to_string(),
    }
}

/// An optional string argument: absent or null is `None`; anything but a
/// string is an error.
fn optional_text(args: &Params, key: &str) -> anyhow::Result<Option<String>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Str(s)) => Ok(Some(s.clone())),
        Some(_) => anyhow::bail!("`{key}` must be a string"),
    }
}

/// A required string argument.
fn text(args: &Params, key: &str) -> anyhow::Result<String> {
    match args.get(key) {
        Some(Value::Str(s)) if !s.is_empty() => Ok(s.clone()),
        _ => anyhow::bail!("`{key}` is required and must be a string"),
    }
}
