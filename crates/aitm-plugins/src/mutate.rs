//! The mutate plugin: `flow.mutate` edits a stored flow's request in place
//! (AC5 command path), and `request.send` crafts a request and sends it through
//! the proxy's guarded client (AC16 gating half).
//!
//! Both work over `Value` objects on the command bus. `flow.mutate` applies an
//! `edits` object to the backed-up flow via `FlowStore::update`; `request.send`
//! builds an `HttpRequest` from a crafted object, passes the scope/rate guard,
//! then captures the result.

use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, Command, CommandHost, Flow, HeaderMap, HttpRequest, HttpResponse, HttpVersion,
    InterceptState, ParamDef, ParamSchema, Params, Plugin, Registry, TypeDesc, Value,
};

use crate::block_on;

/// Registers `flow.mutate` and `request.send`. Observes no events.
pub struct MutatePlugin;

impl MutatePlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MutatePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for MutatePlugin {
    fn name(&self) -> &str {
        "mutate"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(FlowMutate));
        reg.add_command(Arc::new(RequestSend));
    }
}

/// The edit fields `flow.mutate` and `request.send` understand.
fn request_fields(all_required_authority: bool) -> Vec<ParamDef> {
    let field = |name: &str, ty: TypeDesc, required: bool, description: &str| ParamDef {
        name: name.into(),
        ty,
        required,
        description: description.into(),
    };
    vec![
        field("method", TypeDesc::Str, false, "HTTP method."),
        field("scheme", TypeDesc::Str, false, "`http` or `https`."),
        field(
            "authority",
            TypeDesc::Str,
            all_required_authority,
            "Target host[:port].",
        ),
        field("path", TypeDesc::Str, false, "Request path and query."),
        field(
            "headers",
            TypeDesc::Map(Box::new(TypeDesc::Str)),
            false,
            "Header name→value; each replaces any existing header of that name.",
        ),
        field(
            "body",
            TypeDesc::Any,
            false,
            "Request body as a string or bytes.",
        ),
    ]
}

/// Apply an `edits` object to a request, rejecting unknown keys. Header edits
/// replace (remove-then-set) so a mutation does not accumulate duplicates.
fn apply_edits(
    req: &mut HttpRequest,
    edits: &std::collections::BTreeMap<String, Value>,
) -> anyhow::Result<()> {
    for (key, val) in edits {
        match key.as_str() {
            "method" => req.method = as_str(key, val)?.to_string(),
            "scheme" => req.scheme = as_str(key, val)?.to_string(),
            "authority" => req.authority = as_str(key, val)?.to_string(),
            "path" => req.path = as_str(key, val)?.to_string(),
            "body" => req.body = as_body(key, val)?,
            "headers" => apply_header_edits(&mut req.headers, val)?,
            "status" => anyhow::bail!(
                "edit `status` is only valid for a response parked at the response phase"
            ),
            other => anyhow::bail!("unknown edit key `{other}`"),
        }
    }
    Ok(())
}

/// Apply an `edits` object to a parked response: `status`, `headers`, `body`. The
/// request-only keys (`method`, `scheme`, `authority`, `path`) are rejected — they
/// have no meaning for a response.
fn apply_response_edits(
    resp: &mut HttpResponse,
    edits: &std::collections::BTreeMap<String, Value>,
) -> anyhow::Result<()> {
    for (key, val) in edits {
        match key.as_str() {
            "status" => resp.status = as_status(key, val)?,
            "body" => resp.body = as_body(key, val)?,
            "headers" => apply_header_edits(&mut resp.headers, val)?,
            other => anyhow::bail!(
                "edit key `{other}` is not valid for a response (response edits: status, headers, body)"
            ),
        }
    }
    Ok(())
}

/// Replace each named header (remove-then-set), validating before mutating so a
/// CRLF-injected value is refused and leaves the map unchanged.
fn apply_header_edits(headers: &mut HeaderMap, val: &Value) -> anyhow::Result<()> {
    let Value::Object(edits) = val else {
        anyhow::bail!("edit `headers` must be an object, got {val:?}");
    };
    for (name, hval) in edits {
        let value = as_str(name, hval)?;
        headers.remove(name);
        headers
            .try_set(name, value)
            .map_err(|e| anyhow::anyhow!("edit `headers`: {e}"))?;
    }
    Ok(())
}

/// An HTTP status code edit: an integer in the valid status range.
fn as_status(key: &str, val: &Value) -> anyhow::Result<u16> {
    let n = match val {
        Value::Int(n) => *n,
        other => anyhow::bail!("`{key}` must be an integer, got {other:?}"),
    };
    let code =
        u16::try_from(n).map_err(|_| anyhow::anyhow!("`{key}` {n} is not a valid HTTP status"))?;
    if (100..=599).contains(&code) {
        Ok(code)
    } else {
        anyhow::bail!("`{key}` {code} is outside the HTTP status range 100-599")
    }
}

fn as_str<'a>(key: &str, val: &'a Value) -> anyhow::Result<&'a str> {
    match val {
        Value::Str(s) => Ok(s),
        other => anyhow::bail!("`{key}` must be a string, got {other:?}"),
    }
}

fn as_body(key: &str, val: &Value) -> anyhow::Result<Body> {
    match val {
        Value::Str(s) => Ok(Body::Bytes(s.clone().into_bytes())),
        Value::Bytes(b) => Ok(Body::Bytes(b.clone())),
        Value::Null => Ok(Body::Empty),
        other => anyhow::bail!("`{key}` must be a string or bytes, got {other:?}"),
    }
}

/// `flow.mutate {id, edits}` → edits a captured request in place.
struct FlowMutate;

impl Command for FlowMutate {
    fn name(&self) -> &str {
        "flow.mutate"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Edit a captured HTTP flow in place. Edits apply to the request \
                          (method, path, headers, body); when the flow is parked at the response \
                          phase they apply to the response and `status` is valid."
                .into(),
            params: vec![
                ParamDef {
                    name: "id".into(),
                    ty: TypeDesc::FlowId,
                    required: true,
                    description: "The flow to edit.".into(),
                },
                ParamDef {
                    name: "edits".into(),
                    ty: TypeDesc::Object(edit_fields()),
                    required: true,
                    description: "The fields to change.".into(),
                },
            ],
            result: TypeDesc::FlowId,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_flow_id("id")?;
        let edits = args.get_object("edits")?.clone();
        let Some(Flow::Http(snapshot)) = host.store().get(id) else {
            match host.store().get(id) {
                None => anyhow::bail!("no flow with id {id}"),
                Some(_) => anyhow::bail!("flow {id} is not an HTTP flow"),
            }
        };

        // A flow parked at the response phase (`Intercepted` and carrying a
        // response) is edited on its response, where `status` is valid; every
        // other flow is edited on its request, where `status` is rejected.
        let edit_response = matches!(snapshot.intercept, InterceptState::Intercepted { .. })
            && snapshot.response.is_some();

        // Validate against the snapshot before touching the store, so a bad edit
        // (an unknown key, a bad status, a CRLF header) leaves the flow unchanged.
        if edit_response {
            let mut resp = snapshot.response.clone().expect("response present");
            apply_response_edits(&mut resp, &edits)?;
        } else {
            let mut req = snapshot.request.clone();
            apply_edits(&mut req, &edits)?;
        }

        let mut result: anyhow::Result<()> = Ok(());
        host.store().update(id, &mut |flow: &mut Flow| {
            if let Flow::Http(f) = flow {
                result = if edit_response {
                    match f.response.as_mut() {
                        Some(resp) => apply_response_edits(resp, &edits),
                        None => Err(anyhow::anyhow!(
                            "flow {id} lost its response before the edit"
                        )),
                    }
                } else {
                    apply_edits(&mut f.request, &edits)
                };
                // Record that the flow was edited, so the inspector's "Edited"
                // flag (flow.detail.edited) reflects a real mutation.
                if result.is_ok() {
                    f.metadata.edited = true;
                }
            }
        });
        result?;
        Ok(Value::Str(id.to_string()))
    }
}

/// The edit fields `flow.mutate` understands: the request fields plus `status`
/// (valid only for a response parked at the response phase).
fn edit_fields() -> Vec<ParamDef> {
    let mut fields = request_fields(false);
    fields.push(ParamDef {
        name: "status".into(),
        ty: TypeDesc::Int,
        required: false,
        description: "Response status code; only valid for a flow parked at the response phase."
            .into(),
    });
    fields
}

/// `request.send {…}` → craft a request, guard it, send it, capture it.
struct RequestSend;

impl Command for RequestSend {
    fn name(&self) -> &str {
        "request.send"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Craft an HTTP request and send it through the proxy's guarded client; \
                          returns the captured flow's id."
                .into(),
            params: request_fields(true),
            result: TypeDesc::FlowId,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let authority = args.get_str("authority")?.to_string();
        let mut req = HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority,
            path: "/".into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        };
        // Reuse the edit applier for the remaining crafted fields.
        let edits: std::collections::BTreeMap<String, Value> = args
            .iter()
            .filter(|(k, _)| *k != "authority")
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        apply_edits(&mut req, &edits)?;

        // The `ProxyClient` is the single scope/rate chokepoint and guards the
        // authority before sending; the command does not re-check.
        let sent = block_on(host.client().send(req))?;
        Ok(Value::Str(sent.id.to_string()))
    }
}
