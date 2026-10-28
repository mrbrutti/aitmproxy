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

/// How deep an array/map a script hands the host may nest. Every layer of the
/// conversion (and of Rhai's own clone and drop) is one stack frame, and no
/// Rhai limit bounds nesting — `max_array_size` counts elements, so a
/// thousand singleton arrays inside one another are a thousand elements.
/// Thirty-two levels is more than any JSON a script would build and far
/// short of what overflows a 2 MiB worker stack.
pub const MAX_DEPTH: usize = 32;

/// Convert a Rhai value back into a bus `Value`. Fails with
/// [`ScriptError::Runtime`] for a Rhai type that has no `Value` counterpart
/// (the error names the offending type; nested conversions report the inner
/// type) or for a value nested deeper than [`MAX_DEPTH`].
pub fn dynamic_to_value(d: &Dynamic) -> Result<Value, ScriptError> {
    convert(d, 0)
}

fn convert(d: &Dynamic, depth: usize) -> Result<Value, ScriptError> {
    if depth > MAX_DEPTH {
        return Err(runtime(format!(
            "value nested deeper than {MAX_DEPTH} levels cannot be passed to the host"
        )));
    }
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
            .map(|item| convert(item, depth + 1))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    if let Ok(map) = d.as_map_ref() {
        return map
            .iter()
            .map(|(k, v)| Ok((k.to_string(), convert(v, depth + 1)?)))
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(Value::Object);
    }
    Err(runtime(format!(
        "cannot convert a Rhai `{}` into a value",
        d.type_name()
    )))
}

/// A conversion failure. The script/hook/line context is not known at this
/// layer; the caller that owns it fills it in.
fn runtime(message: String) -> ScriptError {
    ScriptError::Runtime {
        script: String::new(),
        hook: String::new(),
        line: 0,
        message,
    }
}
