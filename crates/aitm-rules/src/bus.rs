//! Bus (de)serialization for the shared rule model.
//!
//! F3 intercept, F9 WS-frame control and Map Local/Remote all turn a command-bus
//! [`Value`] into a [`Rule`]/[`MatchCondition`] and echo it back. That parse+echo —
//! and the phase/ws_dir/url/host token tables — used to be hand-rolled in each of
//! the three plugins and had drifted apart (most visibly `Phase::WsFrame`, which
//! one plugin emitted as `"wsframe"` and the others as `"ws_frame"`). This module
//! is the one place those live, so every surface emits and accepts the same tokens
//! (spec §0: one shared rule-match model, down to the wire).
//!
//! Tokens are case-insensitive on input; the canonical output token for
//! `Phase::WsFrame` is **`ws_frame`** (the legacy `wsframe` / `frame` spellings are
//! still accepted on input).

use std::collections::BTreeMap;

use aitm_core::{Value, WsDir};

use crate::{HostMatch, MatchCondition, Phase, Rule, UrlMatch};

/// The canonical wire token for a [`Phase`]. `Phase::WsFrame` is `"ws_frame"`.
pub fn phase_token(phase: Phase) -> &'static str {
    match phase {
        Phase::Request => "request",
        Phase::Response => "response",
        Phase::WsFrame => "ws_frame",
        Phase::Any => "any",
    }
}

/// Parse a phase token (case-insensitive). The canonical `ws_frame` plus the legacy
/// `wsframe`/`frame` spellings all map to [`Phase::WsFrame`].
pub fn parse_phase(s: &str) -> anyhow::Result<Phase> {
    match s.to_ascii_lowercase().as_str() {
        "request" => Ok(Phase::Request),
        "response" => Ok(Phase::Response),
        "ws_frame" | "wsframe" | "frame" => Ok(Phase::WsFrame),
        "any" => Ok(Phase::Any),
        other => anyhow::bail!("unknown rule phase {other:?} (request|response|ws_frame|any)"),
    }
}

/// The canonical wire token for a [`WsDir`].
pub fn ws_dir_token(dir: WsDir) -> &'static str {
    match dir {
        WsDir::ClientToServer => "c2s",
        WsDir::ServerToClient => "s2c",
    }
}

/// Parse a ws_dir token (case-insensitive), accepting the short and long spellings.
pub fn parse_ws_dir(s: &str) -> anyhow::Result<WsDir> {
    match s.to_ascii_lowercase().as_str() {
        "c2s" | "client_to_server" | "clienttoserver" => Ok(WsDir::ClientToServer),
        "s2c" | "server_to_client" | "servertoclient" => Ok(WsDir::ServerToClient),
        other => anyhow::bail!("unknown ws_dir {other:?} (c2s|s2c)"),
    }
}

/// Parse a `url` clause: a bare string is a wildcard; an object selects
/// `{wildcard}` or `{regex}`.
pub fn parse_url_match(value: &Value) -> anyhow::Result<UrlMatch> {
    match value {
        Value::Str(s) => Ok(UrlMatch::Wildcard(s.clone())),
        Value::Object(o) => {
            if let Some(s) = str_field(o, "wildcard")? {
                Ok(UrlMatch::Wildcard(s))
            } else if let Some(s) = str_field(o, "regex")? {
                Ok(UrlMatch::Regex(s))
            } else {
                anyhow::bail!("rule field `url` object must be {{wildcard:str}} or {{regex:str}}")
            }
        }
        other => anyhow::bail!("rule field `url` must be a string or object, got {other:?}"),
    }
}

/// Echo a [`UrlMatch`] back to the bus as `{wildcard|regex: str}`.
pub fn url_match_to_value(url: &UrlMatch) -> Value {
    let (key, pat) = match url {
        UrlMatch::Wildcard(s) => ("wildcard", s),
        UrlMatch::Regex(s) => ("regex", s),
    };
    single(key, pat)
}

/// Parse a `host` clause: a bare string is an exact authority; an object selects
/// `{exact}` or `{wildcard}`.
pub fn parse_host_match(value: &Value) -> anyhow::Result<HostMatch> {
    match value {
        Value::Str(s) => Ok(HostMatch::Exact(s.clone())),
        Value::Object(o) => {
            if let Some(s) = str_field(o, "exact")? {
                Ok(HostMatch::Exact(s))
            } else if let Some(s) = str_field(o, "wildcard")? {
                Ok(HostMatch::Wildcard(s))
            } else {
                anyhow::bail!("rule field `host` object must be {{exact:str}} or {{wildcard:str}}")
            }
        }
        other => anyhow::bail!("rule field `host` must be a string or object, got {other:?}"),
    }
}

/// Echo a [`HostMatch`] back to the bus as `{exact|wildcard: str}`.
pub fn host_match_to_value(host: &HostMatch) -> Value {
    let (key, pat) = match host {
        HostMatch::Exact(s) => ("exact", s),
        HostMatch::Wildcard(s) => ("wildcard", s),
    };
    single(key, pat)
}

/// Parse a [`MatchCondition`] from an object's `url`/`method`/`host`/`phase`/`ws_dir`
/// fields. An absent `phase` defaults to `default_phase` (request for intercept/map,
/// ws_frame for WS control).
pub fn parse_condition(
    obj: &BTreeMap<String, Value>,
    default_phase: Phase,
) -> anyhow::Result<MatchCondition> {
    let url = match obj.get("url") {
        None | Some(Value::Null) => None,
        Some(v) => Some(parse_url_match(v)?),
    };
    let method = str_field(obj, "method")?;
    let host = match obj.get("host") {
        None | Some(Value::Null) => None,
        Some(v) => Some(parse_host_match(v)?),
    };
    let phase = match obj.get("phase") {
        None | Some(Value::Null) => default_phase,
        Some(Value::Str(s)) => parse_phase(s)?,
        Some(other) => anyhow::bail!("rule field `phase` must be a string, got {other:?}"),
    };
    let ws_dir = match obj.get("ws_dir") {
        None | Some(Value::Null) => None,
        Some(Value::Str(s)) => Some(parse_ws_dir(s)?),
        Some(other) => anyhow::bail!("rule field `ws_dir` must be a string, got {other:?}"),
    };
    Ok(MatchCondition {
        url,
        method,
        host,
        phase,
        ws_dir,
    })
}

/// Echo a [`MatchCondition`] back to the bus: `url?`/`method?`/`host?`/`phase`
/// (always), plus `ws_dir?` when present.
pub fn condition_to_value(cond: &MatchCondition) -> Value {
    let mut obj = BTreeMap::new();
    if let Some(url) = &cond.url {
        obj.insert("url".to_string(), url_match_to_value(url));
    }
    if let Some(method) = &cond.method {
        obj.insert("method".to_string(), Value::Str(method.clone()));
    }
    if let Some(host) = &cond.host {
        obj.insert("host".to_string(), host_match_to_value(host));
    }
    obj.insert(
        "phase".to_string(),
        Value::Str(phase_token(cond.phase).to_string()),
    );
    if let Some(dir) = cond.ws_dir {
        obj.insert(
            "ws_dir".to_string(),
            Value::Str(ws_dir_token(dir).to_string()),
        );
    }
    Value::Object(obj)
}

/// Parse a whole [`Rule`] object: `id` (defaults to `default_id`), `name?`,
/// `enabled` (defaults true), and the [`MatchCondition`] fields.
pub fn parse_rule(
    obj: &BTreeMap<String, Value>,
    default_id: &str,
    default_phase: Phase,
) -> anyhow::Result<Rule> {
    let id = str_field(obj, "id")?.unwrap_or_else(|| default_id.to_string());
    let name = str_field(obj, "name")?;
    let enabled = match obj.get("enabled") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(other) => anyhow::bail!("rule field `enabled` must be a boolean, got {other:?}"),
    };
    let condition = parse_condition(obj, default_phase)?;
    Ok(Rule {
        id,
        name,
        enabled,
        condition,
    })
}

/// Echo a whole [`Rule`] back to the bus: `id`, `name?`, `enabled`, `phase`, and the
/// present condition clauses (`url?`/`method?`/`host?`/`ws_dir?`).
pub fn rule_to_value(rule: &Rule) -> Value {
    let mut obj = BTreeMap::new();
    obj.insert("id".to_string(), Value::Str(rule.id.clone()));
    if let Some(name) = &rule.name {
        obj.insert("name".to_string(), Value::Str(name.clone()));
    }
    obj.insert("enabled".to_string(), Value::Bool(rule.enabled));
    let cond = &rule.condition;
    obj.insert(
        "phase".to_string(),
        Value::Str(phase_token(cond.phase).to_string()),
    );
    if let Some(url) = &cond.url {
        obj.insert("url".to_string(), url_match_to_value(url));
    }
    if let Some(method) = &cond.method {
        obj.insert("method".to_string(), Value::Str(method.clone()));
    }
    if let Some(host) = &cond.host {
        obj.insert("host".to_string(), host_match_to_value(host));
    }
    if let Some(dir) = cond.ws_dir {
        obj.insert(
            "ws_dir".to_string(),
            Value::Str(ws_dir_token(dir).to_string()),
        );
    }
    Value::Object(obj)
}

/// A one-key `{key: str}` object value.
fn single(key: &str, value: &str) -> Value {
    Value::Object(
        [(key.to_string(), Value::Str(value.to_string()))]
            .into_iter()
            .collect(),
    )
}

/// An optional string field: `None` if absent/null, `Err` if present but not a
/// string.
fn str_field(obj: &BTreeMap<String, Value>, key: &str) -> anyhow::Result<Option<String>> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Str(s)) => Ok(Some(s.clone())),
        Some(other) => anyhow::bail!("rule field `{key}` must be a string, got {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsframe_token_is_canonical_and_aliases_parse() {
        assert_eq!(phase_token(Phase::WsFrame), "ws_frame");
        assert_eq!(parse_phase("ws_frame").unwrap(), Phase::WsFrame);
        assert_eq!(parse_phase("wsframe").unwrap(), Phase::WsFrame);
        assert_eq!(parse_phase("FRAME").unwrap(), Phase::WsFrame);
    }

    #[test]
    fn condition_round_trips_through_the_bus() {
        let obj: BTreeMap<String, Value> = [
            ("url".to_string(), Value::Str("*/admin".into())),
            ("host".to_string(), Value::Str("api.test".into())),
            ("method".to_string(), Value::Str("POST".into())),
            ("phase".to_string(), Value::Str("ws_frame".into())),
            ("ws_dir".to_string(), Value::Str("c2s".into())),
        ]
        .into_iter()
        .collect();
        let cond = parse_condition(&obj, Phase::Request).unwrap();
        assert_eq!(cond.phase, Phase::WsFrame);
        let Value::Object(echoed) = condition_to_value(&cond) else {
            panic!("object");
        };
        assert_eq!(echoed.get("phase"), Some(&Value::Str("ws_frame".into())));
        assert_eq!(echoed.get("ws_dir"), Some(&Value::Str("c2s".into())));
    }
}
