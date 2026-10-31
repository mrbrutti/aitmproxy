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
        // Credentials in the query string (?access_token=, ?api_key=) and request
        // body (password=, {"token":"…"}) are masked so no secret is baked into a
        // shareable PoC. Redaction is by secret-named KEY (not value shape), so an
        // opaque or special-character credential is masked; a `{{…}}` placeholder is
        // exempt, so the declared injection point (param/payload) survives and the
        // PoC still reproduces; a JSON body is scrubbed structurally so redaction
        // never corrupts it (an unparseable or opaque body falls back to the shared
        // free-text scrubber, never emitted verbatim); and a credential embedded in a
        // non-secret value (`next=…?jwt=…`, a `Referer`) is caught per value. Every
        // "is this key a secret" decision here is `aitm_core::redact::is_secret_key`,
        // the one shared vocabulary (which includes sid/jwt/csrf/session/PHPSESSID).
        let url = scrub_url_credentials(&parameterize_url(req, &spec.variables));
        let (headers, secret_vars) = request_headers(&req.headers);

        let step = HttpStep {
            method: req.method.clone(),
            url,
            headers,
            body: body_text(&req.body).map(|b| scrub_body_credentials(&b)),
            extract: Vec::new(),
            extra: serde_yaml::Mapping::new(),
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

/// Request headers whose value is always a credential: replaced with a placeholder
/// in a built PoC so the secret is never written to disk. Beyond this fixed list,
/// any header whose name reads as credential-bearing (`is_secret_poc_key`, e.g.
/// `X-Auth-Token`, `X-Session-Token`) is redacted the same way.
const SECRET_HEADERS: [&str; 4] = [
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
];

/// Whether a request header carries a credential and must not be baked into a PoC.
fn is_secret_header(name: &str) -> bool {
    SECRET_HEADERS.iter().any(|s| name.eq_ignore_ascii_case(s)) || is_secret_poc_key(name)
}

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
        if is_secret_header(name) {
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
            // A non-secret header is kept, but its value is content-scrubbed so a
            // credential embedded in it (e.g. a session id in `Referer: …?sid=…`)
            // does not ride into the PoC.
            out.push((name.to_string(), scrub_embedded_credentials(value)));
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

/// Whether a query / body / header KEY names a credential. The vocabulary lives in
/// `aitm-core` ([`aitm_core::redact::is_secret_key`]) and is not copied here, so a
/// directly-captured flow (`poc.build` runs on any stored flow, not only scanner
/// output) is judged by the same vocabulary as the audit ring and the findings store.
fn is_secret_poc_key(key: &str) -> bool {
    aitm_core::redact::is_secret_key(key)
}

/// Redact a value at a secret-named key: everything under it is secret, so force every
/// scalar leaf to `[redacted]`, descending through nested objects/arrays, so a real
/// secret cannot escape via a non-secret sub-key (`{"token":{"v":"sk-…"}}`,
/// `{"api_keys":["sk-…"]}`). A `{{…}}` placeholder is kept (the declared payload). Note:
/// a value that is itself literally `{{…}}` in the captured flow is kept by shape, not
/// provenance -- a documented, narrow residual (a real credential is essentially never
/// fully brace-wrapped).
fn force_redact_subtree(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => map.values_mut().for_each(force_redact_subtree),
        serde_json::Value::Array(items) => items.iter_mut().for_each(force_redact_subtree),
        serde_json::Value::String(s) if is_placeholder(s) => {}
        _ => *v = serde_json::Value::String("[redacted]".to_string()),
    }
}

/// Whether `value` is a `{{var}}` placeholder the builder parameterized (the
/// declared injection point / a required credential variable). A placeholder is
/// never redacted: it carries no secret, and preserving it is how an injected
/// payload survives into the reproduction (the caller declares it via the `param` /
/// `payload` variables rather than the scrubber guessing payload-vs-credential by
/// shape, which would leak special-character credentials).
fn is_placeholder(value: &str) -> bool {
    let v = value.trim();
    v.len() >= 4 && v.starts_with("{{") && v.ends_with("}}")
}

/// Mask credentials in a built-PoC query string. Redaction is BY KEY, not by value
/// shape: at a secret-named key (`is_secret_poc_key`) the value is
/// redacted unless it is a `{{…}}` placeholder — so an opaque or special-character
/// credential (`password=P@ss/w0rd!`) is masked, while the declared injection point
/// survives. At any other key the value is content-scrubbed with the shared
/// free-text scrubber, which masks a credential embedded in a URL-valued parameter
/// (`next=…?access_token=…`) while leaving an injection payload intact.
fn scrub_url_credentials(url: &str) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };
    let scrubbed = query
        .split('&')
        .map(scrub_kv_segment)
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{scrubbed}")
}

/// If `pair` is a `key=value` at a secret-named key, its redacted form -- a `{{…}}`
/// placeholder kept (the declared injection point), any other value masked. None when
/// the key is not secret, so each caller chooses how to treat a non-secret value. This
/// is the one redaction rule the query scrub and the embedded-URL scrub must apply
/// identically.
fn redact_secret_pair(pair: &str) -> Option<String> {
    match pair.split_once('=') {
        Some((k, v)) if is_secret_poc_key(k) => Some(if is_placeholder(v) {
            pair.to_string()
        } else {
            format!("{k}=[redacted]")
        }),
        _ => None,
    }
}

/// One `key=value` (or bare) query / form-body segment: a secret-named value is
/// redacted; any other value may itself embed a URL with a credential, so it goes to
/// [`scrub_embedded_credentials`].
fn scrub_kv_segment(pair: &str) -> String {
    if let Some(redacted) = redact_secret_pair(pair) {
        return redacted;
    }
    match pair.split_once('=') {
        Some((k, v)) => format!("{k}={}", scrub_embedded_credentials(v)),
        None => pair.to_string(),
    }
}

/// Content-scrub a NON-secret value that may still embed a credential. A URL carried in
/// a `next=` / `Referer` value has its own `?query`. The per-part scrub here is kept for
/// placeholder handling, not for vocabulary: the shared `scrub_text` would mask a `{{…}}`
/// placeholder sitting at a secret key (the declared injection point), so each embedded
/// query param is scrubbed individually (one level, no recursion -- bounded against a
/// crafted deeply-nested URL): a secret-named param is redacted ([`redact_secret_pair`]),
/// a `{{…}}` placeholder is kept, and any other value (plus the base, plus a value with
/// no embedded query) is content-scrubbed for an embedded `Bearer …` / `access_token=…`.
/// Scrubbing per part -- never over the reassembled string -- is what keeps a kept
/// placeholder from being eaten by the free-text pass.
fn scrub_embedded_credentials(value: &str) -> String {
    let Some((base, query)) = value.split_once('?') else {
        return aitm_core::redact::scrub_text(value);
    };
    let scrubbed = query
        .split('&')
        .map(|pair| {
            if let Some(redacted) = redact_secret_pair(pair) {
                return redacted;
            }
            match pair.split_once('=') {
                Some((_, v)) if is_placeholder(v) => pair.to_string(),
                Some((k, v)) => format!("{k}={}", aitm_core::redact::scrub_text(v)),
                None => aitm_core::redact::scrub_text(pair),
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{}?{scrubbed}", aitm_core::redact::scrub_text(base))
}

/// Mask credentials in a request body without corrupting it. A JSON body is parsed
/// and scrubbed structurally (see [`scrub_json_credentials`]) so the document stays
/// valid; a form body gets the same key=value rule as the query; anything else — a
/// JSON-shaped body that failed to parse (truncated capture, trailing comma,
/// comments) or an opaque body — falls back to the shared free-text `scrub_text`, so
/// a credential is never emitted verbatim. That fallback cannot hit the #123 "scrub
/// corrupts valid JSON" bug: a body that parsed as JSON already returned above, so
/// `scrub_text` only ever runs here on a non-JSON string.
fn scrub_body_credentials(body: &str) -> String {
    if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(body) {
        scrub_json_credentials(&mut json);
        // Always re-serialize the scrubbed Value rather than returning the raw bytes:
        // the parse canonicalizes the document, dropping a duplicate-key shadow, so a
        // credential hidden in `{"k":"<secret>","k":"ok"}` (the parse keeps only the
        // last `k`) cannot ride through on the original bytes.
        if let Ok(rendered) = serde_json::to_string(&json) {
            return rendered;
        }
    }
    let looks_json = body.trim_start().starts_with(['{', '[']);
    if body.contains('=') && !looks_json {
        return body
            .split('&')
            .map(scrub_kv_segment)
            .collect::<Vec<_>>()
            .join("&");
    }
    aitm_core::redact::scrub_text(body)
}

/// Structure-aware JSON scrub. At a secret-named key the whole value is redacted (see
/// [`force_redact_subtree`]); at any other key a string value is content-scrubbed
/// (see [`scrub_embedded_credentials`], masking an embedded `Bearer …` / `key=…` /
/// `?jwt=…`) and a container is recursed. Because the scrubber only ever sees an
/// individual string *value*, never the serialized document, it cannot eat a `"`/`}`
/// delimiter and corrupt the JSON (the #123 failure); re-serialization keeps it valid.
fn scrub_json_credentials(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if is_secret_poc_key(key) {
                    force_redact_subtree(val);
                } else {
                    scrub_json_credentials(val);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(scrub_json_credentials),
        serde_json::Value::String(s) => *s = scrub_embedded_credentials(s),
        _ => {}
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
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
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
                description: None,
                author: None,
                metadata: None,
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
