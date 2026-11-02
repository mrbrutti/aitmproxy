//! argv → command. The leading non-flag tokens are the subcommand path
//! (`flow get` → `flow.get`; an already-dotted `flow.get` also works); every
//! following `--name value` / `--name=value` is a `ParamDef` of that command,
//! parsed by its `TypeDesc`. Scalars come from the text, arrays and objects from
//! JSON text, bytes from the argument's UTF-8, booleans from a bare flag or a
//! `true`/`false` literal. One flag is the CLI's own: a bare `--yes` is removed
//! before parsing and answers the command's confirmation prompt, if it has one.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use aitm_core::{
    BrowserDriver, Command, CommandHost, EgressConfinement, FlowId, FlowStore, Frontend,
    ParamSchema, Params, ProxyClient, Registry, ScopeRateGuard, SsrfPolicy, TypeDesc, Value,
};
use anyhow::Context as _;
use serde_json::Value as JsonValue;

use crate::confirm::{Confirmer, TtyConfirmer};

/// The reserved flag: not a `ParamDef`, accepted by every command, skips the
/// confirmation prompt.
const YES_FLAG: &str = "--yes";

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
    /// `--yes` was given; a "no" leaves it un-invoked.
    pub fn dispatch(&self, argv: &[String]) -> anyhow::Result<Value> {
        let (cmd, flags) = self.resolve(argv)?;
        let yes = flags.iter().any(|t| t == YES_FLAG);
        let flags: Vec<String> = flags.iter().filter(|t| *t != YES_FLAG).cloned().collect();
        let args = parse_flags(&flags, &cmd.schema(), cmd.name())?;
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
                    .with_context(|| cmd.name().to_string())?;
                if !confirmed {
                    anyhow::bail!("aborted: {} not run", cmd.name());
                }
            }
        }
        cmd.invoke(args, &host)
    }

    /// Usage text: every registered command in argv form with its flags.
    pub fn usage(&self) -> String {
        let mut out = String::from(
            "usage: aitm <command> [--flag value]...\n\
             (a value that itself starts with `--` must be given as --flag=value;\n\
             --yes answers a command's confirmation prompt without asking)\n\
             \ncommands:\n",
        );
        for cmd in self.registry.commands() {
            let schema = cmd.schema();
            let mut line = cmd.name().replace('.', " ");
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

    /// Split argv into the command it names and the flag tokens that follow.
    fn resolve<'a>(&self, argv: &'a [String]) -> anyhow::Result<(&Arc<dyn Command>, &'a [String])> {
        if argv.is_empty() {
            anyhow::bail!("{}", self.usage());
        }
        let path_len = argv.iter().take_while(|a| !is_flag(a)).count();
        if path_len == 0 {
            anyhow::bail!(
                "expected a command before flags, got `{}`\n{}",
                argv[0],
                self.usage()
            );
        }
        let name = argv[..path_len].join(".");
        let cmd = self.registry.command(&name).ok_or_else(|| {
            anyhow::anyhow!("unknown command `{name}`; run with no arguments to list commands")
        })?;
        Ok((cmd, &argv[path_len..]))
    }
}

fn is_flag(tok: &str) -> bool {
    tok.len() > 2 && tok.starts_with("--")
}

/// Flags → typed `Params` for `cmd`: every flag a declared param, each given at
/// most once, every required param present.
pub fn parse_flags(tokens: &[String], schema: &ParamSchema, cmd: &str) -> anyhow::Result<Params> {
    let mut map = BTreeMap::new();
    let mut toks = tokens.iter().peekable();
    while let Some(tok) = toks.next() {
        let Some(flag) = tok.strip_prefix("--").filter(|f| !f.is_empty()) else {
            anyhow::bail!("unexpected argument `{tok}` for `{cmd}`; flags are `--name value`");
        };
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (flag, None),
        };
        let def = schema
            .params
            .iter()
            .find(|d| d.name == name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown flag --{name} for `{cmd}`; accepted: {}",
                    accepted_flags(schema)
                )
            })?;
        if map.contains_key(name) {
            anyhow::bail!("flag --{name} given more than once");
        }
        let raw = match inline {
            Some(v) => Some(v),
            // A bare boolean flag means true; a following `true`/`false` literal
            // is its value. Every other type needs the next token.
            None if matches!(def.ty, TypeDesc::Bool) => toks
                .next_if(|t| matches!(t.as_str(), "true" | "false"))
                .cloned(),
            None => Some(
                toks.next_if(|t| !is_flag(t))
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("flag --{name} needs a value"))?,
            ),
        };
        let value = match raw {
            None => Value::Bool(true),
            Some(raw) => {
                parse_value(&raw, &def.ty).map_err(|e| anyhow::anyhow!("flag --{name}: {e}"))?
            }
        };
        map.insert(def.name.clone(), value);
    }
    if let Some(def) = schema
        .params
        .iter()
        .find(|d| d.required && !map.contains_key(&d.name))
    {
        anyhow::bail!("missing required flag --{} for `{cmd}`", def.name);
    }
    Ok(Params::new(map))
}

fn accepted_flags(schema: &ParamSchema) -> String {
    if schema.params.is_empty() {
        return "(none)".into();
    }
    schema
        .params
        .iter()
        .map(|p| format!("--{}", p.name))
        .collect::<Vec<_>>()
        .join(", ")
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

/// The placeholder shown for a flag's value in usage text.
fn type_hint(ty: &TypeDesc) -> &'static str {
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
    use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, Sensitivity, StdGuard};
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

    fn cli() -> Cli {
        let mut reg = Registry::new();
        reg.add_command(Arc::new(EgressProbe));
        Cli::new(Arc::new(reg)).with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(NoClient),
            Arc::new(StdGuard::default()),
            None,
        )
    }

    fn probe(cli: &Cli) -> Value {
        cli.dispatch(&["egress".to_string(), "probe".to_string()])
            .expect("egress.probe dispatches")
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
}
