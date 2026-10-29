//! The tier's own operator-facing commands (spec §3, §8): `script.validate`,
//! `script.reload`, `script.findings`, and `script.list`, registered by [`ScriptCommands`] —
//! one more `Plugin` whose `load` adds native `Command`s, so MCP `tools/list`
//! and the CLI (`aitm script validate --path x.rhai`) pick them up with no
//! special casing.
//!
//! - **`script.validate { path }`** compiles the file on the shared engine
//!   without registering anything and answers with the script's declared
//!   metadata, or the positioned compile error in the pinned format. Only a
//!   `.rhai` path is read, so the command is not a general file probe for an
//!   agent frontend.
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

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Command, CommandHost, Frontend, ParamDef, ParamSchema, Params, Plugin, Registry, Sensitivity,
    TypeDesc, Value,
};

use crate::config::ScriptMeta;
use crate::host_core::{severity_name, Finding, FindingSink};
use crate::loader::RhaiLoader;
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

struct ScriptFindings {
    findings: Arc<dyn FindingSink>,
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
            description: "Compile a .rhai script without loading it; reports its name, API and \
                          hooks, or the positioned compile error."
                .to_string(),
            params: vec![param(
                "path",
                TypeDesc::Str,
                true,
                "path to the .rhai file to check",
            )],
            result: TypeDesc::Any,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let path = text(&args, "path")?;
        let path = Path::new(&path);
        if path.extension().and_then(|e| e.to_str()) != Some(SCRIPT_EXT) {
            anyhow::bail!(
                "script.validate reads only .rhai files, got {}",
                path.display()
            );
        }
        confine_validate(host, path)?;
        let meta = self
            .loader
            .validate(path)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(meta_value(&meta))
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
        let handle = self
            .scripts
            .iter()
            .find(|s| s.name() == name)
            .ok_or_else(|| {
                let loaded: Vec<&str> = self.scripts.iter().map(|s| s.name()).collect();
                anyhow::anyhow!(
                    "no loaded script is named `{name}`; loaded: {}",
                    if loaded.is_empty() {
                        "(none)".to_string()
                    } else {
                        loaded.join(", ")
                    }
                )
            })?;
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

/// A required string argument.
fn text(args: &Params, key: &str) -> anyhow::Result<String> {
    match args.get(key) {
        Some(Value::Str(s)) if !s.is_empty() => Ok(s.clone()),
        _ => anyhow::bail!("`{key}` is required and must be a string"),
    }
}
