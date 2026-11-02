//! argv → command. The leading non-flag tokens are the subcommand path
//! (`flow get` → `flow.get`; an already-dotted `flow.get` also works); every
//! following `--name value` / `--name=value` is a `ParamDef` of that command,
//! parsed by its `TypeDesc`. Scalars come from the text, arrays and objects from
//! JSON text, bytes from the argument's UTF-8, booleans from a bare flag or a
//! `true`/`false` literal. One flag is the CLI's own: a bare `--yes` is removed
//! before parsing and answers the command's confirmation prompt, if it has one.
//!
//! **Typed usage errors (plan C35).** Every usage error `dispatch` returns is an
//! [`aitm_term::error::ErrorReport`] of kind `Usage` wrapped in `anyhow::Error`
//! (`report.downcast_ref::<ErrorReport>()` takes it back out): `what` is the
//! headline, `why` holds the `did you mean:` line when there is one and then
//! the relevant `Usage:` line, and `command` is the help pointer — [`TOP_HELP`]
//! (`aitm --help`) for an unknown group or a malformed command line,
//! [`group_help`] (`aitm <group>`) for an unknown verb or a bare group, and
//! [`verb_help`] (`aitm <group> <verb> --help`) for a flag error. Dotted wire
//! names never appear in that prose: every command is printed through
//! [`spaced`] (`scope add`, not `scope.add`; spec T6, AC-W2-4).
//!
//! The dispatcher only resolves argv; the help pages themselves are built by
//! the `aitm` binary over [`Cli::locate`], which returns the located command
//! or the group it names without running anything.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use aitm_core::{
    BrowserDriver, Command, CommandHost, EgressConfinement, FlowId, FlowStore, Frontend, ParamDef,
    Params, ProxyClient, Registry, ScopeRateGuard, SsrfPolicy, TypeDesc, Value,
};
use aitm_term::error::ErrorReport;
use anyhow::Context as _;
use serde_json::Value as JsonValue;

use crate::confirm::{Confirmer, TtyConfirmer};
use crate::suggest::{did_you_mean, suggest};

/// The reserved flag: not a `ParamDef`, accepted by every command, skips the
/// confirmation prompt.
const YES_FLAG: &str = "--yes";

/// The one-shot usage form: the first line of [`Cli::usage`] and the cause
/// line of a malformed command line (spec D15, plan C39).
pub const USAGE_FORM: &str = "Usage: aitm <group> <verb> [--flag <value>]...";

/// The help pointer for an unknown group or a malformed command line.
pub const TOP_HELP: &str = "aitm --help";

/// A dotted wire name as prose: `tls.passthrough.add` → `tls passthrough add`
/// (spec T6: dotted names never appear in an error string).
pub fn spaced(dotted: &str) -> String {
    dotted.replace('.', " ")
}

/// The help pointer for a group: `aitm <group>`.
pub fn group_help(group: &str) -> String {
    format!("aitm {group}")
}

/// The help pointer for a verb: `aitm <group> <verb> --help`.
pub fn verb_help(dotted: &str) -> String {
    format!("aitm {} --help", spaced(dotted))
}

/// The placeholder a usage form shows for a flag's value: `<true|false>` for a
/// `Bool`, else the flag's own name in angle brackets (plan C42).
pub fn placeholder(def: &ParamDef) -> String {
    match def.ty {
        TypeDesc::Bool => "<true|false>".to_string(),
        _ => format!("<{}>", def.name),
    }
}

/// `aitm <spaced name>` followed by ` --name <placeholder>` for each required
/// flag and ` [--name <placeholder>]` for each optional one, in schema order.
pub fn usage_form(cmd: &dyn Command) -> String {
    let mut out = format!("aitm {}", spaced(cmd.name()));
    for def in &cmd.schema().params {
        let flag = format!("--{} {}", def.name, placeholder(def));
        if def.required {
            let _ = write!(out, " {flag}");
        } else {
            let _ = write!(out, " [{flag}]");
        }
    }
    out
}

/// `Usage: ` + [`usage_form`]: the last cause line of every flag error.
pub fn usage_line(cmd: &dyn Command) -> String {
    format!("Usage: {}", usage_form(cmd))
}

/// `Usage: aitm <group> <verb> [--flag <value>]...`: the cause line of a bare
/// group that reaches the dispatcher (plan C38).
pub fn group_usage_line(group: &str) -> String {
    format!("Usage: aitm {group} <verb> [--flag <value>]...")
}

/// What a command line names once the subcommand path is resolved.
pub enum Located<'a> {
    /// A bare group (`aitm scope`): its name and its commands in registration
    /// order. The binary renders the group page; `dispatch` makes it a usage
    /// error.
    Group {
        name: String,
        commands: Vec<&'a Arc<dyn Command>>,
    },
    /// A registered command and every argv token after its path, flags and
    /// stray tokens alike.
    Command {
        cmd: &'a Arc<dyn Command>,
        rest: &'a [String],
    },
}

/// Commands print as their names (`dyn Command` has no `Debug` of its own).
impl std::fmt::Debug for Located<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Located::Group { name, commands } => f
                .debug_struct("Group")
                .field("name", name)
                .field(
                    "commands",
                    &commands.iter().map(|c| c.name()).collect::<Vec<_>>(),
                )
                .finish(),
            Located::Command { cmd, rest } => f
                .debug_struct("Command")
                .field("cmd", &cmd.name())
                .field("rest", rest)
                .finish(),
        }
    }
}

/// The core services a `CommandHost` borrows for each dispatch.
struct Services {
    store: Arc<dyn FlowStore>,
    client: Arc<dyn ProxyClient>,
    guard: Arc<dyn ScopeRateGuard>,
    browser: Option<Arc<dyn BrowserDriver>>,
}

/// The CLI frontend: a registry handle plus the services commands run against.
pub struct Cli {
    registry: Arc<Registry>,
    services: Option<Services>,
    ssrf: SsrfPolicy,
    poc_dir: Option<std::path::PathBuf>,
    config: Option<Arc<aitm_core::Config>>,
    finding_recorder: Option<Arc<dyn aitm_core::FindingRecorder>>,
    /// The proxy's live browser-egress posture, handed to every host so
    /// `browser.confine` toggles the connector's real posture. `None` = the
    /// toggle is unavailable on this frontend (the command then errors).
    egress: Option<Arc<EgressConfinement>>,
    confirmer: Arc<dyn Confirmer>,
}

impl Cli {
    /// A CLI over `registry`. Attach services with [`Cli::with_services`] before
    /// dispatching. Confirmation prompts go to the terminal on stdin until
    /// [`Cli::with_confirmer`] says otherwise.
    pub fn new(registry: Arc<Registry>) -> Self {
        Self {
            registry,
            services: None,
            ssrf: SsrfPolicy::default(),
            poc_dir: None,
            config: None,
            finding_recorder: None,
            egress: None,
            confirmer: Arc::new(TtyConfirmer::from_stdin()),
        }
    }

    /// Attach the proxy's live browser-egress posture (`Proxy::egress()`), so a
    /// CLI `browser.confine` flips the connector's real posture. Without it the
    /// command errors rather than toggling a detached copy.
    pub fn with_egress(mut self, egress: Arc<EgressConfinement>) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Attach the proxy configuration so `config.get`/`proxy.status` can read it.
    pub fn with_config(mut self, config: Arc<aitm_core::Config>) -> Self {
        self.config = Some(config);
        self
    }

    /// Wire the finding recorder so a CLI `poc.run` persists a finding (T7);
    /// gated on `findings.dir`.
    pub fn with_finding_recorder(mut self, recorder: Arc<dyn aitm_core::FindingRecorder>) -> Self {
        self.finding_recorder = Some(recorder);
        self
    }

    /// Put confirmation prompts to `confirmer` instead of the terminal.
    pub fn with_confirmer(mut self, confirmer: Arc<dyn Confirmer>) -> Self {
        self.confirmer = confirmer;
        self
    }

    /// Use the configured SSRF policy for command-side pre-flights, so the PoC
    /// runner's browser navigation matches the connector.
    pub fn with_ssrf_policy(mut self, policy: SsrfPolicy) -> Self {
        self.ssrf = policy;
        self
    }

    /// Confine `poc.run` to PoC files under `dir` (opt-in; `None` = unconfined).
    pub fn with_poc_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.poc_dir = dir;
        self
    }

    /// The services every `Command::invoke` receives through its `CommandHost`.
    pub fn with_services(
        mut self,
        store: Arc<dyn FlowStore>,
        client: Arc<dyn ProxyClient>,
        guard: Arc<dyn ScopeRateGuard>,
        browser: Option<Arc<dyn BrowserDriver>>,
    ) -> Self {
        self.services = Some(Services {
            store,
            client,
            guard,
            browser,
        });
        self
    }

    /// `aitm flow replay --id <uuid>` -> command "flow.replay" + Params{ id }.
    /// Subcommand path maps 1:1 to Command::name(); flags map to ParamDef by name.
    /// A command with a `confirm_prompt` is put to the confirmer first unless
    /// `--yes` was given; a "no" leaves it un-invoked. A bare group is the
    /// usage error `missing verb after `<group>`` (plan C38); every usage error
    /// is an [`ErrorReport`] inside the `anyhow::Error` (plan C35).
    pub fn dispatch(&self, argv: &[String]) -> anyhow::Result<Value> {
        let (cmd, rest) = match self.locate(argv).map_err(anyhow::Error::new)? {
            Located::Group { name, .. } => {
                return Err(anyhow::Error::new(
                    ErrorReport::usage(format!("missing verb after `{name}`"))
                        .with_why(vec![group_usage_line(&name)])
                        .with_command(group_help(&name)),
                ));
            }
            Located::Command { cmd, rest } => (cmd, rest),
        };
        let yes = rest.iter().any(|t| t == YES_FLAG);
        let flags: Vec<String> = rest.iter().filter(|t| *t != YES_FLAG).cloned().collect();
        let args = parse_flags(&flags, cmd.as_ref()).map_err(anyhow::Error::new)?;
        let services = self.services.as_ref().ok_or_else(|| {
            anyhow::anyhow!("no core services attached; call Cli::with_services first")
        })?;
        let host = CommandHost::new(
            services.store.as_ref(),
            services.client.as_ref(),
            services.guard.as_ref(),
            services.browser.as_deref(),
        )
        .with_ssrf(self.ssrf.clone())
        .with_poc_dir(self.poc_dir.clone())
        .with_frontend(Frontend::Cli);
        let host = match &self.config {
            Some(cfg) => host.with_config(cfg.clone()),
            None => host,
        };
        let host = match &self.finding_recorder {
            Some(rec) => host.with_finding_recorder(rec.as_ref()),
            None => host,
        };
        let host = match &self.egress {
            Some(egress) => host.with_egress(egress.clone()),
            None => host,
        };
        if !yes {
            if let Some(prompt) = cmd.confirm_prompt(&args) {
                let confirmed = self
                    .confirmer
                    .confirm(&prompt)
                    .with_context(|| spaced(cmd.name()))?;
                if !confirmed {
                    anyhow::bail!("aborted: {} not run", spaced(cmd.name()));
                }
            }
        }
        cmd.invoke(args, &host)
    }

    /// Usage text: the [`USAGE_FORM`] line, the `--yes` note, then every
    /// registered command in argv form with its flags.
    pub fn usage(&self) -> String {
        let mut out = format!(
            "{USAGE_FORM}\n\
             (a value that itself starts with `--` must be given as --flag=value;\n\
             --yes answers a command's confirmation prompt without asking)\n\
             \ncommands:\n"
        );
        for cmd in self.registry.commands() {
            let schema = cmd.schema();
            let mut line = spaced(cmd.name());
            for p in &schema.params {
                let flag = format!("--{} <{}>", p.name, type_hint(&p.ty));
                if p.required {
                    let _ = write!(line, " {flag}");
                } else {
                    let _ = write!(line, " [{flag}]");
                }
            }
            let _ = writeln!(out, "  {line}");
            if !schema.description.is_empty() {
                let _ = writeln!(out, "      {}", schema.description);
            }
        }
        out
    }

    /// Resolve argv to the command it names, or the group it names, without
    /// running anything. The leading non-flag tokens are the path; the longest
    /// prefix of the path whose dotted join is a registered command wins, and
    /// everything after it is `rest` (`scope add extra --host x` → `scope.add`
    /// with `rest = ["extra", "--host", "x"]`). A single token that is the first
    /// segment of some command is its [`Located::Group`]. Anything else is a
    /// usage error with a `did you mean:` line when a name is close (plan C37)
    /// and the help pointer for where the operator was.
    // The error type is the plan C35 contract (`report_for` downcasts it); it
    // is built once per failed invocation, so its size is not on a hot path.
    #[allow(clippy::result_large_err)]
    pub fn locate<'a>(&'a self, argv: &'a [String]) -> Result<Located<'a>, ErrorReport> {
        let Some(first) = argv.first() else {
            return Err(ErrorReport::usage("expected a command")
                .with_why(vec![USAGE_FORM.to_string()])
                .with_command(TOP_HELP));
        };
        let path_len = argv.iter().take_while(|a| !is_flag(a)).count();
        if path_len == 0 {
            return Err(ErrorReport::usage(format!(
                "expected a command before flags, got `{first}`"
            ))
            .with_why(vec![USAGE_FORM.to_string()])
            .with_command(TOP_HELP));
        }
        let path = &argv[..path_len];
        for prefix_len in (1..=path_len).rev() {
            let name = path[..prefix_len].join(".");
            if let Some(cmd) = self.registry.command(&name) {
                return Ok(Located::Command {
                    cmd,
                    rest: &argv[prefix_len..],
                });
            }
        }
        let group = path[0].as_str();
        let verbs = self.group_commands(group);
        if verbs.is_empty() {
            let groups: Vec<&str> = self.groups();
            let mut why = Vec::new();
            why.extend(did_you_mean(&suggest(group, groups)));
            return Err(ErrorReport::usage(format!("unknown command `{group}`"))
                .with_why(why)
                .with_command(TOP_HELP));
        }
        if path_len == 1 {
            return Ok(Located::Group {
                name: group.to_string(),
                commands: verbs,
            });
        }
        // Inside a known group: suggest its verbs, written as spaced full names.
        let group_prefix = format!("{group}.");
        let verb_names: Vec<&str> = verbs
            .iter()
            .filter_map(|c| c.name().strip_prefix(group_prefix.as_str()))
            .collect();
        let full_names: Vec<String> = suggest(&path[1], verb_names)
            .into_iter()
            .map(|verb| format!("{group} {}", spaced(verb)))
            .collect();
        let full_names: Vec<&str> = full_names.iter().map(String::as_str).collect();
        let mut why = Vec::new();
        why.extend(did_you_mean(&full_names));
        Err(
            ErrorReport::usage(format!("unknown command `{}`", path.join(" ")))
                .with_why(why)
                .with_command(group_help(group)),
        )
    }

    /// The commands whose name starts with `<group>.`, in registration order.
    fn group_commands(&self, group: &str) -> Vec<&Arc<dyn Command>> {
        let prefix = format!("{group}.");
        self.registry
            .commands()
            .filter(|c| c.name().starts_with(prefix.as_str()))
            .collect()
    }

    /// The distinct first segments of every registered command, in
    /// registration order.
    fn groups(&self) -> Vec<&str> {
        let mut groups: Vec<&str> = Vec::new();
        for cmd in self.registry.commands() {
            let group = cmd.name().split('.').next().unwrap_or_default();
            if !groups.contains(&group) {
                groups.push(group);
            }
        }
        groups
    }
}

fn is_flag(tok: &str) -> bool {
    tok.len() > 2 && tok.starts_with("--")
}

/// Flags → typed `Params` for `cmd`: every flag a declared param, each given at
/// most once, every required param present. Every error names the spaced
/// command, ends its causes with the command's `Usage:` line and points at
/// the verb's help (plan C35, C37).
// Same contract as `Cli::locate`: one `ErrorReport` per failed invocation.
#[allow(clippy::result_large_err)]
fn parse_flags(tokens: &[String], cmd: &dyn Command) -> Result<Params, ErrorReport> {
    let schema = cmd.schema();
    let name = spaced(cmd.name());
    let usage_error = |what: String, mut why: Vec<String>| {
        why.push(usage_line(cmd));
        ErrorReport::usage(what)
            .with_why(why)
            .with_command(verb_help(cmd.name()))
    };
    let mut map = BTreeMap::new();
    let mut toks = tokens.iter().peekable();
    while let Some(tok) = toks.next() {
        let Some(flag) = tok.strip_prefix("--").filter(|f| !f.is_empty()) else {
            return Err(usage_error(
                format!("unexpected argument `{tok}` for `{name}`"),
                Vec::new(),
            ));
        };
        let (flag_name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (flag, None),
        };
        let Some(def) = schema.params.iter().find(|d| d.name == flag_name) else {
            let declared = schema.params.iter().map(|d| d.name.as_str());
            let close: Vec<String> = suggest(flag_name, declared)
                .into_iter()
                .map(|s| format!("--{s}"))
                .collect();
            let close: Vec<&str> = close.iter().map(String::as_str).collect();
            let mut why = Vec::new();
            why.extend(did_you_mean(&close));
            return Err(usage_error(
                format!("unknown flag --{flag_name} for `{name}`"),
                why,
            ));
        };
        if map.contains_key(flag_name) {
            return Err(usage_error(
                format!("flag --{flag_name} given more than once"),
                Vec::new(),
            ));
        }
        let raw = match inline {
            Some(v) => Some(v),
            // A bare boolean flag means true; a following `true`/`false` literal
            // is its value. Every other type needs the next token.
            None if matches!(def.ty, TypeDesc::Bool) => toks
                .next_if(|t| matches!(t.as_str(), "true" | "false"))
                .cloned(),
            None => Some(toks.next_if(|t| !is_flag(t)).cloned().ok_or_else(|| {
                usage_error(format!("flag --{flag_name} needs a value"), Vec::new())
            })?),
        };
        let value = match raw {
            None => Value::Bool(true),
            Some(raw) => parse_value(&raw, &def.ty)
                .map_err(|e| usage_error(format!("flag --{flag_name}: {e}"), Vec::new()))?,
        };
        map.insert(def.name.clone(), value);
    }
    if let Some(def) = schema
        .params
        .iter()
        .find(|d| d.required && !map.contains_key(&d.name))
    {
        return Err(usage_error(
            format!("missing required flag --{} for `{name}`", def.name),
            Vec::new(),
        ));
    }
    Ok(Params::new(map))
}

/// One flag's text as the `Value` its `TypeDesc` describes.
fn parse_value(raw: &str, ty: &TypeDesc) -> anyhow::Result<Value> {
    match ty {
        TypeDesc::Bool => match raw {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => anyhow::bail!("expected true or false, got `{raw}`"),
        },
        TypeDesc::Int => raw
            .parse::<i64>()
            .map(Value::Int)
            .map_err(|_| anyhow::anyhow!("expected an integer, got `{raw}`")),
        TypeDesc::Float => raw
            .parse::<f64>()
            .map(Value::Float)
            .map_err(|_| anyhow::anyhow!("expected a number, got `{raw}`")),
        TypeDesc::Str => Ok(Value::Str(raw.to_string())),
        TypeDesc::Bytes => Ok(Value::Bytes(raw.as_bytes().to_vec())),
        TypeDesc::FlowId => {
            raw.parse::<FlowId>()
                .map_err(|e| anyhow::anyhow!("not a valid flow id: {e}"))?;
            Ok(Value::Str(raw.to_string()))
        }
        TypeDesc::Array(_) | TypeDesc::Object(_) | TypeDesc::Map(_) => {
            let json: JsonValue = serde_json::from_str(raw)
                .map_err(|e| anyhow::anyhow!("expected JSON for this flag ({e})"))?;
            json_to_value(&json, ty)
        }
        // Anything goes: JSON if it parses, otherwise the text itself.
        TypeDesc::Any => Ok(serde_json::from_str::<JsonValue>(raw)
            .map(|j| any_from_json(&j))
            .unwrap_or_else(|_| Value::Str(raw.to_string()))),
    }
}

/// A parsed JSON flag value as the `Value` `ty` describes. Bytes inside JSON
/// are a string's UTF-8, like a bytes flag.
fn json_to_value(j: &JsonValue, ty: &TypeDesc) -> anyhow::Result<Value> {
    match ty {
        TypeDesc::Bool => j
            .as_bool()
            .map(Value::Bool)
            .ok_or_else(|| anyhow::anyhow!("expected a boolean, got {j}")),
        TypeDesc::Int => j
            .as_i64()
            .map(Value::Int)
            .ok_or_else(|| anyhow::anyhow!("expected an integer, got {j}")),
        TypeDesc::Float => j
            .as_f64()
            .map(Value::Float)
            .ok_or_else(|| anyhow::anyhow!("expected a number, got {j}")),
        TypeDesc::Str => j
            .as_str()
            .map(|s| Value::Str(s.to_string()))
            .ok_or_else(|| anyhow::anyhow!("expected a string, got {j}")),
        TypeDesc::Bytes => j
            .as_str()
            .map(|s| Value::Bytes(s.as_bytes().to_vec()))
            .ok_or_else(|| anyhow::anyhow!("expected a string, got {j}")),
        TypeDesc::FlowId => {
            let s = j
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("expected a flow id string, got {j}"))?;
            s.parse::<FlowId>()
                .map_err(|e| anyhow::anyhow!("not a valid flow id: {e}"))?;
            Ok(Value::Str(s.to_string()))
        }
        TypeDesc::Array(item) => j
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("expected an array, got {j}"))?
            .iter()
            .enumerate()
            .map(|(i, v)| json_to_value(v, item).map_err(|e| anyhow::anyhow!("[{i}]: {e}")))
            .collect::<anyhow::Result<Vec<_>>>()
            .map(Value::Array),
        TypeDesc::Object(defs) => {
            let fields = j
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("expected an object, got {j}"))?;
            let mut out = BTreeMap::new();
            for def in defs {
                match fields.get(&def.name) {
                    Some(v) => {
                        let value = json_to_value(v, &def.ty)
                            .map_err(|e| anyhow::anyhow!("`{}`: {e}", def.name))?;
                        out.insert(def.name.clone(), value);
                    }
                    None if def.required => anyhow::bail!("missing required `{}`", def.name),
                    None => {}
                }
            }
            if let Some(unknown) = fields.keys().find(|k| !defs.iter().any(|d| &d.name == *k)) {
                anyhow::bail!("unknown field `{unknown}`");
            }
            Ok(Value::Object(out))
        }
        TypeDesc::Map(item) => {
            let fields = j
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("expected an object, got {j}"))?;
            let mut out = BTreeMap::new();
            for (k, v) in fields {
                let value = json_to_value(v, item).map_err(|e| anyhow::anyhow!("`{k}`: {e}"))?;
                out.insert(k.clone(), value);
            }
            Ok(Value::Object(out))
        }
        TypeDesc::Any => Ok(any_from_json(j)),
    }
}

fn any_from_json(j: &JsonValue) -> Value {
    match j {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(b) => Value::Bool(*b),
        JsonValue::Number(n) => n
            .as_i64()
            .map(Value::Int)
            .unwrap_or_else(|| Value::Float(n.as_f64().unwrap_or(f64::NAN))),
        JsonValue::String(s) => Value::Str(s.clone()),
        JsonValue::Array(items) => Value::Array(items.iter().map(any_from_json).collect()),
        JsonValue::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), any_from_json(v)))
                .collect(),
        ),
    }
}

/// The placeholder shown for a flag's value in usage text (also the words
/// `aitm::describe::fingerprint` pins the schema-only registry with, plan C28).
pub fn type_hint(ty: &TypeDesc) -> &'static str {
    match ty {
        TypeDesc::Bool => "true|false",
        TypeDesc::Int => "int",
        TypeDesc::Float => "number",
        TypeDesc::Str => "string",
        TypeDesc::Bytes => "text",
        TypeDesc::FlowId => "flow-id",
        TypeDesc::Array(_) => "json-array",
        TypeDesc::Object(_) | TypeDesc::Map(_) => "json-object",
        TypeDesc::Any => "value",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `EgressConfinement` is already in scope via `use super::*` (the module imports
    // it for the `Cli.egress` field), so it is not re-imported here.
    use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, ParamSchema, Sensitivity, StdGuard};
    use aitm_term::error::FixCommand;
    use futures::future::BoxFuture;

    /// A `ProxyClient` the probe never reaches.
    struct NoClient;

    impl ProxyClient for NoClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("egress.probe does not use the proxy client") })
        }
    }

    /// `egress.probe`: reports exactly what `browser.confine` reads off the
    /// host (`host.egress()`), so the wiring is testable here without the
    /// browser crate.
    struct EgressProbe;

    impl Command for EgressProbe {
        fn name(&self) -> &str {
            "egress.probe"
        }
        fn sensitivity(&self) -> Sensitivity {
            Sensitivity::Read
        }
        fn schema(&self) -> ParamSchema {
            ParamSchema {
                description: "Report the host's browser-egress posture.".into(),
                params: vec![],
                result: TypeDesc::Str,
            }
        }
        fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
            Ok(Value::Str(match host.egress() {
                None => "absent".into(),
                Some(e) if e.confined() => "confined".into(),
                Some(_) => "free".into(),
            }))
        }
    }

    /// A schema-only fake: its dotted name, its flags and, when set, the
    /// question it asks before running. `invoke` returns `Value::Null`.
    struct Fake {
        name: &'static str,
        params: Vec<ParamDef>,
        prompt: Option<&'static str>,
    }

    impl Command for Fake {
        fn name(&self) -> &str {
            self.name
        }
        fn sensitivity(&self) -> Sensitivity {
            Sensitivity::Read
        }
        fn schema(&self) -> ParamSchema {
            ParamSchema {
                description: format!("Fake {}.", self.name),
                params: self.params.clone(),
                result: TypeDesc::Any,
            }
        }
        fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
            Ok(Value::Null)
        }
        fn confirm_prompt(&self, _args: &Params) -> Option<String> {
            self.prompt.map(str::to_string)
        }
    }

    fn param(name: &str, ty: TypeDesc, required: bool) -> ParamDef {
        ParamDef {
            name: name.into(),
            ty,
            required,
            description: String::new(),
        }
    }

    fn fake(
        name: &'static str,
        params: Vec<ParamDef>,
        prompt: Option<&'static str>,
    ) -> Arc<dyn Command> {
        Arc::new(Fake {
            name,
            params,
            prompt,
        })
    }

    /// Answers every confirmation the same way.
    struct Answer(bool);

    impl Confirmer for Answer {
        fn confirm(&self, _prompt: &str) -> anyhow::Result<bool> {
            Ok(self.0)
        }
    }

    /// The fake registry of plan task 5, in this registration order:
    /// `egress.probe`, `flow.get --id <flow-id> [--body <string>]`, `flow.list`,
    /// `scope.add --host <string>`, `scope.list`, `browser.confine --on <bool>`,
    /// `ca.install` (asks `Install it?`), `tls.passthrough.add --host <string>`.
    /// Confirmations are answered yes unless a test says otherwise.
    fn cli() -> Cli {
        let mut reg = Registry::new();
        reg.add_command(Arc::new(EgressProbe));
        reg.add_command(fake(
            "flow.get",
            vec![
                param("id", TypeDesc::FlowId, true),
                param("body", TypeDesc::Str, false),
            ],
            None,
        ));
        reg.add_command(fake("flow.list", vec![], None));
        reg.add_command(fake(
            "scope.add",
            vec![param("host", TypeDesc::Str, true)],
            None,
        ));
        reg.add_command(fake("scope.list", vec![], None));
        reg.add_command(fake(
            "browser.confine",
            vec![param("on", TypeDesc::Bool, true)],
            None,
        ));
        reg.add_command(fake("ca.install", vec![], Some("Install it?")));
        reg.add_command(fake(
            "tls.passthrough.add",
            vec![param("host", TypeDesc::Str, true)],
            None,
        ));
        Cli::new(Arc::new(reg))
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(NoClient),
                Arc::new(StdGuard::default()),
                None,
            )
            .with_confirmer(Arc::new(Answer(true)))
    }

    fn probe(cli: &Cli) -> Value {
        cli.dispatch(&["egress".to_string(), "probe".to_string()])
            .expect("egress.probe dispatches")
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// The typed usage error a dispatch returned (plan C35).
    fn report(result: anyhow::Result<Value>) -> ErrorReport {
        match result {
            Ok(v) => panic!("expected an error, got {v:?}"),
            Err(e) => e
                .downcast::<ErrorReport>()
                .unwrap_or_else(|e| panic!("not an ErrorReport: {e:#}")),
        }
    }

    fn fix(cmd: &str) -> Option<FixCommand> {
        Some(FixCommand(cmd.into()))
    }

    /// Task 4b / AC9: the host a `Cli` assembles carries the live posture it
    /// was wired with — the same handle, so a later flip is visible through it.
    #[test]
    fn cli_host_carries_the_wired_egress_posture() {
        let posture = Arc::new(EgressConfinement::new(false));
        let cli = cli().with_egress(posture.clone());
        assert_eq!(probe(&cli), Value::Str("free".into()));

        posture.set_base(true);
        assert_eq!(
            probe(&cli),
            Value::Str("confined".into()),
            "the host reads the live handle, not a snapshot"
        );
    }

    /// Without `with_egress` the host carries no posture (fail-closed: a
    /// `browser.confine` on such a host errors rather than toggling nothing).
    #[test]
    fn cli_host_without_wiring_carries_no_posture() {
        assert_eq!(probe(&cli()), Value::Str("absent".into()));
    }

    // ---- wave 2, task 5: `locate`, typed usage errors, spaced names, help
    // pointers (plan C35, C37, C38, C39, C42; spec AC-W2-3/4/5, T6) ----

    const FLOW_GET_USAGE: &str = "Usage: aitm flow get --id <id> [--body <body>]";
    const SCOPE_ADD_USAGE: &str = "Usage: aitm scope add --host <host>";

    /// AC-W2-3, M-W2-4: the first unknown token is the headline, the
    /// suggestions come from the group names, the pointer is the top page.
    #[test]
    fn locate_names_the_unknown_group_and_suggests() {
        let cli = cli();
        let argv = argv(&["scpe", "add", "--host", "x"]);
        let r = cli.locate(&argv).expect_err("an unknown group is an error");
        assert_eq!(r.what, "unknown command `scpe`");
        assert_eq!(r.why, vec!["did you mean: scope".to_string()]);
        assert_eq!(r.command, fix("aitm --help"));
        assert_eq!(r.exit_code(), 2);
    }

    /// C37: inside a known group the suggestions are the group's verbs as
    /// spaced full names and the pointer is the group page.
    #[test]
    fn locate_names_the_unknown_verb_inside_a_known_group() {
        let cli = cli();
        let argv = argv(&["scope", "ad"]);
        let r = cli.locate(&argv).expect_err("an unknown verb is an error");
        assert_eq!(r.what, "unknown command `scope ad`");
        assert_eq!(r.why, vec!["did you mean: scope add".to_string()]);
        assert_eq!(r.command, fix("aitm scope"));
        assert_eq!(r.exit_code(), 2);
    }

    /// A bare group is `Located::Group` with its verbs in registration order.
    #[test]
    fn locate_returns_the_group_for_a_bare_group() {
        let cli = cli();
        let argv = argv(&["scope"]);
        match cli.locate(&argv) {
            Ok(Located::Group { name, commands }) => {
                assert_eq!(name, "scope");
                let names: Vec<&str> = commands.iter().map(|c| c.name()).collect();
                assert_eq!(names, vec!["scope.add", "scope.list"]);
            }
            other => panic!("expected the scope group, got {other:?}"),
        }
    }

    /// The longest registered prefix of the path wins; everything after it
    /// (flags and stray tokens alike) is `rest`.
    #[test]
    fn locate_resolves_the_longest_command_prefix() {
        let cli = cli();
        let nested = argv(&["tls", "passthrough", "add", "--host", "h"]);
        match cli.locate(&nested) {
            Ok(Located::Command { cmd, rest }) => {
                assert_eq!(cmd.name(), "tls.passthrough.add");
                assert_eq!(rest, argv(&["--host", "h"]).as_slice());
            }
            other => panic!("expected tls.passthrough.add, got {other:?}"),
        }
        let trailing = argv(&["scope", "add", "extra"]);
        match cli.locate(&trailing) {
            Ok(Located::Command { cmd, rest }) => {
                assert_eq!(cmd.name(), "scope.add");
                assert_eq!(rest, argv(&["extra"]).as_slice());
            }
            other => panic!("expected scope.add, got {other:?}"),
        }
        // An already-dotted token still resolves (one token, dotted join unchanged).
        let dotted = argv(&["flow.get", "--id", "x"]);
        match cli.locate(&dotted) {
            Ok(Located::Command { cmd, rest }) => {
                assert_eq!(cmd.name(), "flow.get");
                assert_eq!(rest, argv(&["--id", "x"]).as_slice());
            }
            other => panic!("expected flow.get, got {other:?}"),
        }
    }

    /// AC-W2-5 (`aitm --bad`): a leading flag, and an empty argv, carry the
    /// `Usage:` form as their one cause line and point at the top page.
    #[test]
    fn locate_rejects_a_leading_flag_with_the_usage_form() {
        let cli = cli();
        let bad = argv(&["--bad"]);
        let r = cli.locate(&bad).expect_err("a leading flag is an error");
        assert_eq!(r.what, "expected a command before flags, got `--bad`");
        assert_eq!(
            r.why,
            vec!["Usage: aitm <group> <verb> [--flag <value>]...".to_string()]
        );
        assert_eq!(r.command, fix("aitm --help"));
        assert_eq!(r.exit_code(), 2);

        let r = cli.locate(&[]).expect_err("an empty argv is an error");
        assert_eq!(r.what, "expected a command");
        assert_eq!(r.why, vec![USAGE_FORM.to_string()]);
        assert_eq!(r.command, fix(TOP_HELP));
        assert_eq!(r.exit_code(), 2);
    }

    /// C38: a trailing token after a known command is an unexpected argument
    /// for that (spaced) command, never an unknown command.
    #[test]
    fn dispatch_trailing_token_is_an_unexpected_argument() {
        let r = report(cli().dispatch(&argv(&["scope", "add", "extra"])));
        assert_eq!(r.what, "unexpected argument `extra` for `scope add`");
        assert_eq!(r.why, vec![SCOPE_ADD_USAGE.to_string()]);
        assert_eq!(r.command, fix("aitm scope add --help"));
        assert_eq!(r.exit_code(), 2);
    }

    /// Every flag error names the spaced command, ends its causes with the
    /// verb's `Usage:` line and points at the verb's help.
    #[test]
    fn dispatch_flag_errors_carry_the_usage_line_and_the_verb_help() {
        let cli = cli();

        let r = report(cli.dispatch(&argv(&["flow", "get", "--bogus", "1"])));
        assert_eq!(r.what, "unknown flag --bogus for `flow get`");
        assert_eq!(r.why, vec![FLOW_GET_USAGE.to_string()]);
        assert_eq!(r.command, fix("aitm flow get --help"));
        assert_eq!(r.exit_code(), 2);

        let r = report(cli.dispatch(&argv(&["flow", "get", "--di", "x"])));
        assert_eq!(r.what, "unknown flag --di for `flow get`");
        assert_eq!(
            r.why,
            vec!["did you mean: --id".to_string(), FLOW_GET_USAGE.to_string()]
        );
        assert_eq!(r.command, fix("aitm flow get --help"));

        let r = report(cli.dispatch(&argv(&["scope", "add"])));
        assert_eq!(r.what, "missing required flag --host for `scope add`");
        assert_eq!(r.why, vec![SCOPE_ADD_USAGE.to_string()]);
        assert_eq!(r.command, fix("aitm scope add --help"));

        let r = report(cli.dispatch(&argv(&["flow", "get", "--id"])));
        assert_eq!(r.what, "flag --id needs a value");
        assert_eq!(r.why, vec![FLOW_GET_USAGE.to_string()]);
        assert_eq!(r.command, fix("aitm flow get --help"));

        let r = report(cli.dispatch(&argv(&["flow", "get", "--id", "not-a-uuid"])));
        assert!(
            r.what.starts_with("flag --id: not a valid flow id"),
            "{}",
            r.what
        );
        assert_eq!(r.why, vec![FLOW_GET_USAGE.to_string()]);
        assert_eq!(r.command, fix("aitm flow get --help"));

        // The plan writes this case as `--id x --id y`; `x` is not a flow id and
        // fails as a value before the second `--id` is seen, so two real ids
        // carry the duplicate.
        let (x, y) = (FlowId::new().to_string(), FlowId::new().to_string());
        let r = report(cli.dispatch(&argv(&["flow", "get", "--id", &x, "--id", &y])));
        assert_eq!(r.what, "flag --id given more than once");
        assert_eq!(r.why, vec![FLOW_GET_USAGE.to_string()]);
        assert_eq!(r.command, fix("aitm flow get --help"));
    }

    /// C38: a bare group that reaches the dispatcher (`aitm scope --yes`)
    /// points at the group page with the group's `Usage:` line.
    #[test]
    fn dispatch_bare_group_points_at_the_group_page() {
        let r = report(cli().dispatch(&argv(&["scope", "--yes"])));
        assert_eq!(r.what, "missing verb after `scope`");
        assert_eq!(
            r.why,
            vec!["Usage: aitm scope <verb> [--flag <value>]...".to_string()]
        );
        assert_eq!(r.command, fix("aitm scope"));
        assert_eq!(r.exit_code(), 2);
    }

    /// Rule 14 / T6: a declined confirmation names the spaced command; a
    /// granted one runs it.
    #[test]
    fn dispatch_declined_confirmation_names_the_spaced_command() {
        let declined = cli().with_confirmer(Arc::new(Answer(false)));
        let e = declined
            .dispatch(&argv(&["ca", "install"]))
            .expect_err("a no leaves the command un-invoked");
        assert_eq!(format!("{e:#}"), "aborted: ca install not run");

        assert_eq!(
            cli()
                .dispatch(&argv(&["ca", "install"]))
                .expect("a yes runs it"),
            Value::Null
        );
    }

    /// `[a-z_]+\.[a-z_]+`: a `.` with a name character on both sides.
    fn has_dotted_token(text: &str) -> bool {
        let is_name = |c: char| c.is_ascii_lowercase() || c == '_';
        let chars: Vec<char> = text.chars().collect();
        chars
            .windows(3)
            .any(|w| w[1] == '.' && is_name(w[0]) && is_name(w[2]))
    }

    /// AC-W2-4: every dispatcher error path, and the aborted text, prints no
    /// dotted command name in `what`, any `why`, `fix` or `command`.
    #[test]
    fn no_dispatcher_error_carries_a_dotted_command_name() {
        assert!(has_dotted_token("unknown flag --x for `scope.add`"));
        assert!(has_dotted_token("aborted: tls.passthrough.add not run"));
        assert!(!has_dotted_token(
            "Usage: aitm <group> <verb> [--flag <value>]..."
        ));
        assert!(!has_dotted_token("flag --id: not a valid flow id. x"));

        let granted = cli();
        let (x, y) = (FlowId::new().to_string(), FlowId::new().to_string());
        let cases: Vec<Vec<&str>> = vec![
            vec![],
            vec!["--bad"],
            vec!["scpe", "add", "--host", "x"],
            vec!["scope", "ad"],
            vec!["tls", "passthrough"],
            vec!["tls", "passthrough", "ad"],
            vec!["scope", "--yes"],
            vec!["scope", "add", "extra"],
            vec!["tls", "passthrough", "add", "extra"],
            vec!["flow", "get", "--bogus", "1"],
            vec!["flow", "get", "--di", "x"],
            vec!["scope", "add"],
            vec!["tls", "passthrough", "add"],
            vec!["flow", "get", "--id"],
            vec!["flow", "get", "--id", "not-a-uuid"],
            vec!["flow", "get", "--id", &x, "--id", &y],
            vec!["browser", "confine", "--on", "maybe"],
            vec!["tls", "passthrough", "add", "--host", "h", "--host", "h"],
        ];
        let mut texts: Vec<String> = Vec::new();
        for case in &cases {
            let r = report(granted.dispatch(&argv(case)));
            texts.push(r.what.clone());
            texts.extend(r.why.iter().cloned());
            texts.extend(r.fix.iter().cloned());
            texts.extend(r.command.iter().map(|FixCommand(c)| c.clone()));
        }
        let declined = cli().with_confirmer(Arc::new(Answer(false)));
        let aborted = declined
            .dispatch(&argv(&["ca", "install"]))
            .expect_err("declined");
        texts.push(format!("{aborted:#}"));
        assert!(
            texts.len() > cases.len() * 2,
            "every case carries a why and a command"
        );
        for text in &texts {
            assert!(!has_dotted_token(text), "dotted command name in {text:?}");
        }
    }

    /// C39: `usage()` keeps its rows and the one `--yes` sentence; its first
    /// line is the `Usage:` form.
    #[test]
    fn usage_first_line_is_the_usage_form() {
        let usage = cli().usage();
        assert_eq!(
            usage.lines().next(),
            Some("Usage: aitm <group> <verb> [--flag <value>]...")
        );
        assert_eq!(usage.matches("--yes").count(), 1, "{usage}");
        assert!(
            usage.contains("\n  scope add --host <string>\n"),
            "the rows keep their type hints:\n{usage}"
        );
        assert!(
            usage.contains("\n  flow get --id <flow-id> [--body <string>]\n"),
            "{usage}"
        );
    }

    /// C42: `<name>` placeholders, `<true|false>` for a bool, optionals in
    /// brackets, schema order; and the spaced-name helpers.
    #[test]
    fn usage_form_uses_name_placeholders_and_brackets_optionals() {
        let cli = cli();
        let flow_get = cli.registry.command("flow.get").expect("registered");
        assert_eq!(
            usage_form(flow_get.as_ref()),
            "aitm flow get --id <id> [--body <body>]"
        );
        assert_eq!(usage_line(flow_get.as_ref()), FLOW_GET_USAGE);
        let confine = cli.registry.command("browser.confine").expect("registered");
        assert_eq!(
            usage_form(confine.as_ref()),
            "aitm browser confine --on <true|false>"
        );
        let flow_list = cli.registry.command("flow.list").expect("registered");
        assert_eq!(usage_form(flow_list.as_ref()), "aitm flow list");

        assert_eq!(spaced("tls.passthrough.add"), "tls passthrough add");
        assert_eq!(spaced("flow"), "flow");
        assert_eq!(verb_help("scope.add"), "aitm scope add --help");
        assert_eq!(group_help("scope"), "aitm scope");
        assert_eq!(
            group_usage_line("scope"),
            "Usage: aitm scope <verb> [--flag <value>]..."
        );
        assert_eq!(
            placeholder(&param("on", TypeDesc::Bool, true)),
            "<true|false>"
        );
        assert_eq!(placeholder(&param("host", TypeDesc::Str, true)), "<host>");
        assert_eq!(placeholder(&param("id", TypeDesc::FlowId, false)), "<id>");
        assert_eq!(USAGE_FORM, "Usage: aitm <group> <verb> [--flag <value>]...");
        assert_eq!(TOP_HELP, "aitm --help");
    }

    /// C35: every usage error is an `ErrorReport` inside the `anyhow::Error`,
    /// so `report_for` can take it back out.
    #[test]
    fn errors_downcast_to_error_report() {
        let e = cli()
            .dispatch(&argv(&["scpe"]))
            .expect_err("an unknown command is an error");
        let r = e.downcast_ref::<ErrorReport>();
        assert!(r.is_some(), "{e:#}");
        assert_eq!(r.map(|r| r.exit_code()), Some(2));
        assert_eq!(r.map(|r| r.what.as_str()), Some("unknown command `scpe`"));
    }

    // ---- tester, wave-2 pass 1 (AC-W2-3/4; plan C37/C38) ----

    /// A registry with underscored verbs, a three-segment group and a
    /// one-verb group; confirmations are declined.
    fn cli_wide() -> Cli {
        let mut reg = Registry::new();
        reg.add_command(fake(
            "tls.passthrough.add",
            vec![param("host", TypeDesc::Str, true)],
            None,
        ));
        reg.add_command(fake("tls.passthrough.list", vec![], None));
        reg.add_command(fake("browser.get_dom", vec![], None));
        reg.add_command(fake(
            "l4.tcp_probe",
            vec![param("args", TypeDesc::Any, false)],
            None,
        ));
        reg.add_command(fake(
            "l4.udp_probe",
            vec![param("args", TypeDesc::Any, false)],
            None,
        ));
        reg.add_command(fake(
            "check.open_redirect",
            vec![param("max_pages", TypeDesc::Int, false)],
            None,
        ));
        reg.add_command(fake("ca.install", vec![], Some("Install it?")));
        Cli::new(Arc::new(reg))
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(NoClient),
                Arc::new(StdGuard::default()),
                None,
            )
            .with_confirmer(Arc::new(Answer(false)))
    }

    /// C37 over three-segment and underscored names: the hint for an unknown
    /// verb comes from the token after the group (so a two-segment prefix of a
    /// three-segment group lists every verb under it), written as spaced full
    /// names; a dash for an underscore is one edit; an underscored flag keeps
    /// its underscore in the hint.
    #[test]
    fn locate_suggests_three_segment_and_underscored_verbs_spaced() {
        let cli = cli_wide();
        let both = "did you mean: tls passthrough add, tls passthrough list".to_string();
        let r = cli
            .locate(&argv(&["tls", "passthrough", "ad"]))
            .expect_err("unknown verb");
        assert_eq!(r.what, "unknown command `tls passthrough ad`");
        assert_eq!(r.why, vec![both.clone()]);
        assert_eq!(r.command, fix("aitm tls"));
        assert_eq!(r.exit_code(), 2);
        let r = cli
            .locate(&argv(&["tls", "passthrough"]))
            .expect_err("not a command");
        assert_eq!(r.what, "unknown command `tls passthrough`");
        assert_eq!(r.why, vec![both]);
        assert_eq!(r.command, fix("aitm tls"));
        let r = cli
            .locate(&argv(&["browser", "get-dom"]))
            .expect_err("dash for underscore");
        assert_eq!(r.what, "unknown command `browser get-dom`");
        assert_eq!(r.why, vec!["did you mean: browser get_dom".to_string()]);
        assert_eq!(r.command, fix("aitm browser"));
        let r = cli
            .locate(&argv(&["l4", "tcp-probe"]))
            .expect_err("dash for underscore");
        assert_eq!(
            r.why,
            vec!["did you mean: l4 tcp_probe".to_string()],
            "udp_probe is two edits away and not offered"
        );
        let r = cli
            .locate(&argv(&["check", "openredirect", "--args", "{}"]))
            .expect_err("missing underscore");
        assert_eq!(r.what, "unknown command `check openredirect`");
        assert_eq!(r.why, vec!["did you mean: check open_redirect".to_string()]);
        assert_eq!(r.command, fix("aitm check"));
        let r = report(cli.dispatch(&argv(&["check", "open_redirect", "--max-pages", "3"])));
        assert_eq!(r.what, "unknown flag --max-pages for `check open_redirect`");
        assert_eq!(
            r.why,
            vec![
                "did you mean: --max_pages".to_string(),
                "Usage: aitm check open_redirect [--max_pages <max_pages>]".to_string(),
            ]
        );
        assert_eq!(r.command, fix("aitm check open_redirect --help"));
        for text in [&r.what, &r.why[0], &r.why[1]] {
            assert!(!has_dotted_token(text), "{text:?}");
        }
    }

    /// `--yes` is a verb flag: before the command it is a leading flag, inside
    /// the path it ends the path (a bare group), after the verb it skips the
    /// prompt. A one-verb group locates and suggests like any other.
    #[test]
    fn locate_yes_placement_and_a_one_verb_group() {
        let cli = cli_wide();
        let r = cli
            .locate(&argv(&["--yes", "ca", "install"]))
            .expect_err("leading flag");
        assert_eq!(r.what, "expected a command before flags, got `--yes`");
        assert_eq!(r.why, vec![USAGE_FORM.to_string()]);
        assert_eq!(r.command, fix(TOP_HELP));
        let r = report(cli.dispatch(&argv(&["ca", "--yes", "install"])));
        assert_eq!(r.what, "missing verb after `ca`");
        assert_eq!(
            r.why,
            vec!["Usage: aitm ca <verb> [--flag <value>]...".to_string()]
        );
        assert_eq!(r.command, fix("aitm ca"));
        assert_eq!(
            cli.dispatch(&argv(&["ca", "install", "--yes"]))
                .expect("--yes skips the declining confirmer"),
            Value::Null
        );
        let e = cli
            .dispatch(&argv(&["ca", "install"]))
            .expect_err("declined");
        assert_eq!(format!("{e:#}"), "aborted: ca install not run");
        match cli.locate(&argv(&["ca"])) {
            Ok(Located::Group { name, commands }) => {
                assert_eq!(name, "ca");
                let names: Vec<&str> = commands.iter().map(|c| c.name()).collect();
                assert_eq!(names, vec!["ca.install"]);
            }
            other => panic!("expected the ca group, got {other:?}"),
        }
        let r = cli
            .locate(&argv(&["ca", "instal"]))
            .expect_err("unknown verb");
        assert_eq!(r.what, "unknown command `ca instal`");
        assert_eq!(r.why, vec!["did you mean: ca install".to_string()]);
        assert_eq!(r.command, fix("aitm ca"));
    }

    /// Dotted tokens are a compatibility affordance (the module doc): a
    /// dotted name resolves as one token, and a dotted head with a spaced
    /// tail joins to the registered name. A dotted typo is echoed as the
    /// operator typed it — the operator's own token, not a wire name we
    /// composed (AC-W2-4 is about the names we print) — with no hint, since
    /// the whole token is matched against the groups.
    #[test]
    fn locate_dotted_tokens_resolve_and_a_dotted_typo_is_echoed_without_a_hint() {
        let cli = cli_wide();
        let dotted = argv(&["tls.passthrough.add", "--host", "h"]);
        match cli.locate(&dotted) {
            Ok(Located::Command { cmd, rest }) => {
                assert_eq!(cmd.name(), "tls.passthrough.add");
                assert_eq!(rest, argv(&["--host", "h"]).as_slice());
            }
            other => panic!("expected tls.passthrough.add, got {other:?}"),
        }
        let mixed = argv(&["tls.passthrough", "list"]);
        match cli.locate(&mixed) {
            Ok(Located::Command { cmd, rest }) => {
                assert_eq!(cmd.name(), "tls.passthrough.list");
                assert!(rest.is_empty(), "{rest:?}");
            }
            other => panic!("expected tls.passthrough.list, got {other:?}"),
        }
        let r = cli
            .locate(&argv(&["browser.getdom"]))
            .expect_err("a dotted typo");
        assert_eq!(r.what, "unknown command `browser.getdom`");
        assert_eq!(r.why, Vec::<String>::new());
        assert_eq!(r.command, fix(TOP_HELP));
    }

    /// Flag-value edges: an empty inline value is a value; `--` alone and
    /// `---x` are not flags of the command (the latter is one edit from
    /// `--host`); a bare bool followed by a stray word reports the word; a
    /// 64 KiB value is accepted whole; an empty path token is echoed.
    #[test]
    fn dispatch_flag_value_edges() {
        let cli = cli();
        assert_eq!(
            cli.dispatch(&argv(&["scope", "add", "--host="]))
                .expect("an empty inline value is a value"),
            Value::Null
        );
        let r = report(cli.dispatch(&argv(&["scope", "add", "--"])));
        assert_eq!(r.what, "unexpected argument `--` for `scope add`");
        assert_eq!(r.why, vec![SCOPE_ADD_USAGE.to_string()]);
        let r = report(cli.dispatch(&argv(&["scope", "add", "---host", "h"])));
        assert_eq!(r.what, "unknown flag ---host for `scope add`");
        assert_eq!(
            r.why,
            vec![
                "did you mean: --host".to_string(),
                SCOPE_ADD_USAGE.to_string()
            ]
        );
        let r = report(cli.dispatch(&argv(&["browser", "confine", "--on", "maybe"])));
        assert_eq!(r.what, "unexpected argument `maybe` for `browser confine`");
        assert_eq!(
            r.why,
            vec!["Usage: aitm browser confine --on <true|false>".to_string()]
        );
        assert_eq!(r.command, fix("aitm browser confine --help"));
        let r = report(cli.dispatch(&argv(&["browser", "confine", "--on=maybe"])));
        assert_eq!(r.what, "flag --on: expected true or false, got `maybe`");
        let big = "h".repeat(64 * 1024);
        assert_eq!(
            cli.dispatch(&argv(&["scope", "add", "--host", &big]))
                .expect("a 64 KiB value"),
            Value::Null
        );
        // An empty token is echoed; the only group within two edits of the
        // empty string is the two-letter `ca`.
        let r = cli.locate(&argv(&[""])).expect_err("an empty token");
        assert_eq!(r.what, "unknown command ``");
        assert_eq!(r.why, vec!["did you mean: ca".to_string()]);
        assert_eq!(r.command, fix(TOP_HELP));
    }
}
