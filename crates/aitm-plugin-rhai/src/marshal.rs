//! `aitm_core::Value` ⇄ `rhai::Dynamic` marshalling, recursive (plan Task 3).
//!
//! Shared by script commands (`Params` in, result out), the host functions
//! (`finding(...)`, `option(...)`), and PoC `vars`. The mapping:
//!
//! | `Value`  | `Dynamic`                     |
//! |----------|-------------------------------|
//! | `Null`   | `()`                          |
//! | `Bool`   | `bool`                        |
//! | `Int`    | `INT` (`i64`)                 |
//! | `Float`  | `FLOAT` (`f64`)               |
//! | `Str`    | `ImmutableString`             |
//! | `Bytes`  | `Blob`                        |
//! | `Array`  | `Array`, element-wise         |
//! | `Object` | `Map`, entry-wise (keys kept) |
//!
//! A Rhai value outside that table (a `char`, a timestamp, a custom type, a
//! function pointer, …) has no `Value` counterpart and converts to
//! [`ScriptError::Runtime`] naming the Rhai type.

use std::collections::BTreeMap;

use aitm_core::Value;
use rhai::Dynamic;

use crate::error::ScriptError;

/// Convert a bus `Value` into the Rhai value a script sees. Total: every
/// `Value` has a Rhai shape.
pub fn value_to_dynamic(v: &Value) -> Dynamic {
    match v {
        Value::Null => Dynamic::UNIT,
        Value::Bool(b) => Dynamic::from_bool(*b),
        Value::Int(i) => Dynamic::from_int(*i),
        Value::Float(f) => Dynamic::from_float(*f),
        Value::Str(s) => Dynamic::from(s.clone()),
        Value::Bytes(b) => Dynamic::from_blob(b.clone()),
        Value::Array(items) => Dynamic::from_array(items.iter().map(value_to_dynamic).collect()),
        Value::Object(fields) => Dynamic::from_map(
            fields
                .iter()
                .map(|(k, v)| (k.as_str().into(), value_to_dynamic(v)))
                .collect(),
        ),
    }
}

/// Convert a Rhai value back into a bus `Value`. Fails with
/// [`ScriptError::Runtime`] for a Rhai type that has no `Value` counterpart;
/// the error names the offending type (nested conversions report the inner
/// type).
pub fn dynamic_to_value(d: &Dynamic) -> Result<Value, ScriptError> {
    // A closure-captured (shared) value is unwrapped to a plain one so the
    // typed accessors below see through it.
    let d = d.flatten_clone();
    if d.is_unit() {
        return Ok(Value::Null);
    }
    if let Ok(b) = d.as_bool() {
        return Ok(Value::Bool(b));
    }
    if let Ok(i) = d.as_int() {
        return Ok(Value::Int(i));
    }
    if let Ok(f) = d.as_float() {
        return Ok(Value::Float(f));
    }
    if let Ok(s) = d.as_immutable_string_ref() {
        return Ok(Value::Str(s.to_string()));
    }
    if let Ok(blob) = d.as_blob_ref() {
        return Ok(Value::Bytes(blob.clone()));
    }
    if let Ok(items) = d.as_array_ref() {
        return items
            .iter()
            .map(dynamic_to_value)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    if let Ok(map) = d.as_map_ref() {
        return map
            .iter()
            .map(|(k, v)| Ok((k.to_string(), dynamic_to_value(v)?)))
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(Value::Object);
    }
    Err(unmapped(d.type_name()))
}

/// The error for a Rhai type with no `Value` counterpart. The script/hook/line
/// context is not known at this layer; the caller that owns it fills it in.
fn unmapped(type_name: &str) -> ScriptError {
    ScriptError::Runtime {
        script: String::new(),
        hook: String::new(),
        line: 0,
        message: format!("cannot convert a Rhai `{type_name}` into a value"),
    }
}
