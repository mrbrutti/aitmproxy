//! `poc.build` (data-flow 5): turn a captured flow + the agent's choices into a
//! parameterized `Poc`.
//!
//! The PoC is a reproduction, not a transcript: concrete values from the flow are
//! replaced with `{{var}}` placeholders per the chosen `PocSpec.variables` (the
//! base URL → `{{target}}`, the reflected query key → `{{param}}`, the injected
//! value → `{{payload}}`, and any other variable's default literal →
//! `{{name}}`), the single HTTP step is emitted, and the chosen `success`
//! assertion is attached. A `poc.build` command wraps the builder for the bus.

use std::sync::Arc;

use aitm_core::{
    Body, Command, CommandHost, Flow, HeaderMap, HttpFlow, HttpRequest, ParamDef, ParamSchema,
    Params, Registry, TypeDesc, Value,
};

use crate::model::{Assertion, HttpStep, Poc, PocInfo, Severity, Step, Variable};

/// Turn a captured flow into a parameterized `Poc`.
pub trait PocBuilder: Send + Sync {
    fn build(&self, flow: &HttpFlow, spec: PocSpec) -> anyhow::Result<Poc>;
}

/// The agent's choices for a build: metadata, the variables to parameterize by,
/// and the `success` assertion that defines "triggered".
#[derive(Debug, Clone)]
pub struct PocSpec {
    pub info: PocInfo,
    pub variables: Vec<Variable>,
    pub success: Assertion,
}

/// The default builder.
#[derive(Debug, Clone, Default)]
pub struct StdPocBuilder;

impl PocBuilder for StdPocBuilder {
    fn build(&self, flow: &HttpFlow, spec: PocSpec) -> anyhow::Result<Poc> {
        let req = &flow.request;
        let url = parameterize_url(req, &spec.variables);
        let (headers, secret_vars) = request_headers(&req.headers);

        let step = HttpStep {
            method: req.method.clone(),
            url,
            headers,
            body: body_text(&req.body),
            extract: Vec::new(),
        };

        // Credential headers are never baked into a shareable PoC: they become
        // required `{{var}}` placeholders the runner must be given at run time.
        let mut variables = spec.variables;
        for var in secret_vars {
            if !variables.iter().any(|v| v.name == var.name) {
                variables.push(var);
            }
        }

        Ok(Poc {
            id: slug(&spec.info.name),
            info: spec.info,
            variables,
            steps: vec![Step::Http(step)],
            success: spec.success,
        })
    }
}

/// Request headers whose value is a credential: replaced with a placeholder in a
/// built PoC so the secret is never written to disk.
const SECRET_HEADERS: [&str; 4] = [
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
];

/// Replace the flow's concrete URL pieces with `{{var}}` placeholders.
fn parameterize_url(req: &HttpRequest, variables: &[Variable]) -> String {
    let mut url = format!("{}://{}{}", req.scheme, req.authority, req.path);

    // Base URL → {{target}}.
    if variables.iter().any(|v| v.name == "target") {
        let prefix = format!("{}://{}", req.scheme, req.authority);
        url = url.replacen(&prefix, "{{target}}", 1);
    }

    // Reflected query key → {{param}} (only where it is a query key).
    if let Some(key) = default_str(variables, "param") {
        url = url
            .replace(&format!("?{key}="), "?{{param}}=")
            .replace(&format!("&{key}="), "&{{param}}=");
    }

    // Every other variable's concrete default literal → {{name}}.
    for var in variables {
        if var.name == "target" || var.name == "param" {
            continue;
        }
        if let Some(default) = var.default.as_ref().and_then(value_str) {
            if !default.is_empty() {
                url = url.replace(default, &format!("{{{{{}}}}}", var.name));
            }
        }
    }

    url
}

/// Carry request headers into the PoC, dropping `Host` (implied by `{{target}}`)
/// and redacting credential headers to `{{var}}` placeholders. Returns the
/// headers and the required variables the redacted ones introduce.
fn request_headers(headers: &HeaderMap) -> (Vec<(String, String)>, Vec<Variable>) {
    let mut out = Vec::new();
    let mut vars = Vec::new();
    for (name, value) in headers.iter() {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        if SECRET_HEADERS.iter().any(|s| name.eq_ignore_ascii_case(s)) {
            let var = secret_var_name(name);
            out.push((name.to_string(), format!("{{{{{var}}}}}")));
            if !vars.iter().any(|v: &Variable| v.name == var) {
                vars.push(Variable {
                    name: var,
                    default: None,
                    description: format!(
                        "Credential for the `{name}` header (not stored in the PoC)"
                    ),
                    required: true,
                });
            }
        } else {
            out.push((name.to_string(), value.to_string()));
        }
    }
    (out, vars)
}

/// A variable name for a redacted credential header (`X-API-Key` → `x_api_key`).
fn secret_var_name(header: &str) -> String {
    header.to_ascii_lowercase().replace('-', "_")
}

fn body_text(body: &Body) -> Option<String> {
    match body {
        Body::Bytes(bytes) if !bytes.is_empty() => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        _ => None,
    }
}

fn default_str<'a>(variables: &'a [Variable], name: &str) -> Option<&'a str> {
    variables
        .iter()
        .find(|v| v.name == name)
        .and_then(|v| v.default.as_ref())
        .and_then(value_str)
}

fn value_str(v: &Value) -> Option<&str> {
    match v {
        Value::Str(s) => Some(s),
        _ => None,
    }
}

/// A filesystem/identifier-safe slug derived from the PoC title.
fn slug(name: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_end_matches('-').to_string();
    if trimmed.is_empty() {
        "reproduced-finding".to_string()
    } else {
        trimmed
    }
}

// ---------------------------------------------------------------------------
// poc.build command
// ---------------------------------------------------------------------------

/// The `poc.build` command: build a parameterized PoC from a stored flow and
/// return it as YAML. Variables/success are seeded with reproduction defaults
/// (a `{{target}}`/`{{param}}` parameterization and a status assertion) that the
/// agent refines; the full assertion authoring lands with `poc.run`.
pub struct PocBuildCommand;

impl Command for PocBuildCommand {
    fn name(&self) -> &str {
        "poc.build"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Build a parameterized reproducible PoC (YAML) from a captured flow."
                .to_string(),
            params: vec![
                ParamDef {
                    name: "flow_id".to_string(),
                    ty: TypeDesc::FlowId,
                    required: true,
                    description: "The captured flow to reproduce.".to_string(),
                },
                ParamDef {
                    name: "name".to_string(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Human title for the finding.".to_string(),
                },
                ParamDef {
                    name: "param".to_string(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "The reflected query parameter to parameterize.".to_string(),
                },
            ],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let flow_id = args.get_flow_id("flow_id")?;
        let flow = match host.store().get(flow_id) {
            Some(Flow::Http(http)) => http,
            Some(Flow::WebSocket(_)) => {
                anyhow::bail!("poc.build: flow {flow_id} is a WebSocket flow, not HTTP")
            }
            None => anyhow::bail!("poc.build: no flow with id {flow_id}"),
        };

        let name = args
            .get_str("name")
            .map(str::to_string)
            .unwrap_or_else(|_| "reproduced finding".to_string());
        let param = args.get_str("param").unwrap_or("q").to_string();

        let spec = PocSpec {
            info: PocInfo {
                name,
                severity: Severity::Medium,
                references: Vec::new(),
                tags: Vec::new(),
                cwe: None,
            },
            variables: vec![
                Variable {
                    name: "target".to_string(),
                    default: None,
                    description: "Base URL of the target".to_string(),
                    required: true,
                },
                Variable {
                    name: "param".to_string(),
                    default: Some(Value::Str(param)),
                    description: "Reflected query parameter".to_string(),
                    required: false,
                },
            ],
            success: Assertion::Status(flow.response.as_ref().map(|r| r.status).unwrap_or(200)),
        };

        let poc = StdPocBuilder.build(&flow, spec)?;
        let yaml = serde_yaml::to_string(&poc)?;
        Ok(Value::Str(yaml))
    }
}

/// Register `poc.build` on a registry (called from binary assembly, Task 28).
pub fn register(registry: &mut Registry) {
    registry.add_command(Arc::new(PocBuildCommand));
}
