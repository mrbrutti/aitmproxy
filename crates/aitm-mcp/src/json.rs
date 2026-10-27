//! `Value` ⇄ JSON. Outbound conversion is structural; inbound conversion is
//! guided by the command's `TypeDesc` so `tools/call` arguments arrive as the
//! typed `Value`s the command's `Params` getters expect (bytes decode from
//! base64, flow ids are validated, integers stay integers).

use std::collections::BTreeMap;

use aitm_core::{FlowId, ParamDef, ParamSchema, Params, TypeDesc, Value};
use serde_json::{Map, Number, Value as JsonValue};

use crate::base64;

/// A `Value` as JSON. `Bytes` become a base64 string; a non-finite `Float`
/// becomes `null` (JSON has no NaN/∞).
pub fn to_json(v: &Value) -> JsonValue {
    match v {
        Value::Null => JsonValue::Null,
        Value::Bool(b) => JsonValue::Bool(*b),
        Value::Int(i) => JsonValue::Number((*i).into()),
        Value::Float(f) => Number::from_f64(*f).map_or(JsonValue::Null, JsonValue::Number),
        Value::Str(s) => JsonValue::String(s.clone()),
        Value::Bytes(b) => JsonValue::String(base64::encode(b)),
        Value::Array(items) => JsonValue::Array(items.iter().map(to_json).collect()),
        Value::Object(fields) => JsonValue::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), to_json(v)))
                .collect(),
        ),
    }
}

/// A JSON value as the `Value` that `ty` describes. `Any` converts structurally
/// (integral numbers → `Int`, others → `Float`).
pub fn from_json(j: &JsonValue, ty: &TypeDesc) -> anyhow::Result<Value> {
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
        TypeDesc::Bytes => {
            let s = j
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("expected a base64 string, got {j}"))?;
            base64::decode(s)
                .map(Value::Bytes)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        TypeDesc::FlowId => {
            let s = j
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("expected a flow id string, got {j}"))?;
            s.parse::<FlowId>()
                .map_err(|e| anyhow::anyhow!("not a valid flow id: {e}"))?;
            Ok(Value::Str(s.to_string()))
        }
        TypeDesc::Array(item) => {
            let items = j
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("expected an array, got {j}"))?;
            items
                .iter()
                .enumerate()
                .map(|(i, v)| from_json(v, item).map_err(|e| anyhow::anyhow!("[{i}]: {e}")))
                .collect::<anyhow::Result<Vec<_>>>()
                .map(Value::Array)
        }
        TypeDesc::Object(defs) => {
            let fields = j
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("expected an object, got {j}"))?;
            object_from_json(fields, defs, "object").map(Value::Object)
        }
        TypeDesc::Any => Ok(any_from_json(j)),
    }
}

/// Typed arguments for `cmd` from a `tools/call` `arguments` object: every
/// required param present, every param of its declared type, nothing undeclared.
pub fn params_from_json(
    args: &Map<String, JsonValue>,
    schema: &ParamSchema,
    cmd: &str,
) -> anyhow::Result<Params> {
    object_from_json(args, &schema.params, cmd).map(Params::new)
}

fn object_from_json(
    fields: &Map<String, JsonValue>,
    defs: &[ParamDef],
    ctx: &str,
) -> anyhow::Result<BTreeMap<String, Value>> {
    let mut out = BTreeMap::new();
    for def in defs {
        match fields.get(&def.name) {
            Some(v) => {
                let value = from_json(v, &def.ty)
                    .map_err(|e| anyhow::anyhow!("param `{}`: {e}", def.name))?;
                out.insert(def.name.clone(), value);
            }
            None if def.required => {
                anyhow::bail!("missing required param `{}` for `{ctx}`", def.name)
            }
            None => {}
        }
    }
    if let Some(unknown) = fields.keys().find(|k| !defs.iter().any(|d| &d.name == *k)) {
        anyhow::bail!("unknown param `{unknown}` for `{ctx}`");
    }
    Ok(out)
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
