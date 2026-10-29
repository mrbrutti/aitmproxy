//! The action half of a Map rule and the bus (de)serialization for a whole
//! `map.add` argument: `kind`, `condition`, and `action`.
//!
//! The condition is the shared [`aitm_rules::MatchCondition`] (so Map reuses F3's
//! matcher); only the *action* is Map-specific. Map Local serves a confined local
//! file as the response; Map Remote rewrites the target host before upstream
//! (the serve-side of Remote lands in Task 13 — the type is defined here so that
//! task extends it rather than re-shaping the stored entry).

use aitm_core::Value;
use aitm_rules::{bus, MatchCondition, Phase};

/// What a matching Map rule does.
#[derive(Debug, Clone)]
pub enum MapAction {
    /// Serve a local file as the response (a mock). `path` is confined to the
    /// plugin's map root (checked at `map.add`); `status` defaults to 200 and the
    /// content-type is inferred from the extension unless `headers` overrides it.
    Local {
        path: String,
        status: Option<u16>,
        headers: Vec<(String, String)>,
    },
    /// Rewrite the request's target before it goes upstream (a redirect). The
    /// serve-side (scope-guarded rewrite) is Task 13; the shape is fixed here.
    Remote { to: RemoteTarget },
}

/// Where Map Remote sends a matching request.
#[derive(Debug, Clone)]
pub enum RemoteTarget {
    /// A full replacement URL.
    Url(String),
    /// A host (and optional scheme) swap, keeping the original path.
    Host {
        authority: String,
        scheme: Option<String>,
    },
}

/// Which arm of [`MapAction`] a `map.add` call carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    Local,
    Remote,
}

impl MapKind {
    /// The wire string (`map.add {kind}` / `map.list` output).
    pub fn as_str(self) -> &'static str {
        match self {
            MapKind::Local => "local",
            MapKind::Remote => "remote",
        }
    }

    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "local" => Ok(MapKind::Local),
            "remote" => Ok(MapKind::Remote),
            other => anyhow::bail!("map kind must be \"local\" or \"remote\", got {other:?}"),
        }
    }
}

/// The parsed `condition` + `action` of one `map.add`, before the condition is
/// compiled.
pub struct ParsedMap {
    pub kind: MapKind,
    pub condition: MatchCondition,
    pub action: MapAction,
}

/// A required string field of an object value.
fn obj_str<'a>(
    obj: &'a std::collections::BTreeMap<String, Value>,
    key: &str,
) -> anyhow::Result<&'a str> {
    match obj.get(key) {
        Some(Value::Str(s)) => Ok(s),
        Some(other) => anyhow::bail!("`{key}` must be a string, got {other:?}"),
        None => anyhow::bail!("missing required field `{key}`"),
    }
}

/// Pull the `{kind, condition, action}` out of a `map.add` argument map and parse
/// each into the typed model. The condition is parsed but **not** compiled here
/// (the plugin compiles it so a bad regex surfaces as the command's error).
pub fn parse_map(
    kind: &str,
    condition: &std::collections::BTreeMap<String, Value>,
    action: &std::collections::BTreeMap<String, Value>,
) -> anyhow::Result<ParsedMap> {
    let kind = MapKind::parse(kind)?;
    let condition = parse_condition(condition)?;
    let action = match kind {
        MapKind::Local => parse_local(action)?,
        MapKind::Remote => parse_remote(action)?,
    };
    Ok(ParsedMap {
        kind,
        condition,
        action,
    })
}

/// Parse the shared [`MatchCondition`] via the shared [`aitm_rules::bus`] serde.
/// `phase` defaults to `Request` (a Map rule fires on the request), so a Map Local
/// condition need only carry a `url`/`host`.
fn parse_condition(
    obj: &std::collections::BTreeMap<String, Value>,
) -> anyhow::Result<MatchCondition> {
    bus::parse_condition(obj, Phase::Request)
}

fn parse_local(obj: &std::collections::BTreeMap<String, Value>) -> anyhow::Result<MapAction> {
    let path = obj_str(obj, "path")?.to_string();
    let status = match obj.get("status") {
        None | Some(Value::Null) => None,
        Some(Value::Int(i)) => Some(u16::try_from(*i).map_err(|_| {
            anyhow::anyhow!("`action.status` must be a valid HTTP status (0..=65535), got {i}")
        })?),
        Some(other) => anyhow::bail!("`action.status` must be an integer, got {other:?}"),
    };
    let headers = match obj.get("headers") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(o)) => parse_headers(o)?,
        Some(other) => anyhow::bail!("`action.headers` must be an object, got {other:?}"),
    };
    Ok(MapAction::Local {
        path,
        status,
        headers,
    })
}

fn parse_headers(
    obj: &std::collections::BTreeMap<String, Value>,
) -> anyhow::Result<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(obj.len());
    for (name, value) in obj {
        match value {
            Value::Str(v) => out.push((name.clone(), v.clone())),
            other => anyhow::bail!("header `{name}` must be a string, got {other:?}"),
        }
    }
    Ok(out)
}

fn parse_remote(obj: &std::collections::BTreeMap<String, Value>) -> anyhow::Result<MapAction> {
    let to = match obj.get("to") {
        Some(Value::Object(o)) => parse_remote_target(o)?,
        Some(other) => anyhow::bail!("`action.to` must be an object, got {other:?}"),
        None => anyhow::bail!("missing required field `action.to`"),
    };
    Ok(MapAction::Remote { to })
}

fn parse_remote_target(
    obj: &std::collections::BTreeMap<String, Value>,
) -> anyhow::Result<RemoteTarget> {
    if let Ok(url) = obj_str(obj, "url") {
        Ok(RemoteTarget::Url(url.to_string()))
    } else if let Ok(authority) = obj_str(obj, "authority") {
        let scheme = match obj.get("scheme") {
            None | Some(Value::Null) => None,
            Some(Value::Str(s)) => Some(s.clone()),
            Some(other) => anyhow::bail!("`action.to.scheme` must be a string, got {other:?}"),
        };
        Ok(RemoteTarget::Host {
            authority: authority.to_string(),
            scheme,
        })
    } else {
        anyhow::bail!("`action.to` needs a `url` or `authority` field")
    }
}

/// Render a [`MatchCondition`] back to a bus value for `map.list` via the shared
/// [`aitm_rules::bus`] echo, so Map's tokens match every other rule surface.
pub fn condition_to_value(cond: &MatchCondition) -> Value {
    bus::condition_to_value(cond)
}

/// Render a [`MapAction`] back to a bus value for `map.list`.
pub fn action_to_value(action: &MapAction) -> Value {
    let mut obj = std::collections::BTreeMap::new();
    match action {
        MapAction::Local {
            path,
            status,
            headers,
        } => {
            obj.insert("path".to_string(), Value::Str(path.clone()));
            if let Some(status) = status {
                obj.insert("status".to_string(), Value::Int(i64::from(*status)));
            }
            if !headers.is_empty() {
                let map = headers
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::Str(v.clone())))
                    .collect();
                obj.insert("headers".to_string(), Value::Object(map));
            }
        }
        MapAction::Remote { to } => {
            let to = match to {
                RemoteTarget::Url(url) => Value::Object(
                    [("url".to_string(), Value::Str(url.clone()))]
                        .into_iter()
                        .collect(),
                ),
                RemoteTarget::Host { authority, scheme } => {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert("authority".to_string(), Value::Str(authority.clone()));
                    if let Some(scheme) = scheme {
                        m.insert("scheme".to_string(), Value::Str(scheme.clone()));
                    }
                    Value::Object(m)
                }
            };
            obj.insert("to".to_string(), to);
        }
    }
    Value::Object(obj)
}

/// Guess a response content-type from a file-name extension. Falls back to
/// `application/octet-stream` for an unknown or missing extension.
pub fn content_type_for(path: &std::path::Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "xml" => "application/xml",
        "txt" | "text" => "text/plain; charset=utf-8",
        "csv" => "text/csv",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}
