//! Task 3 — `aitm_core::Value` ⇄ `rhai::Dynamic` marshalling, recursive.

use std::collections::BTreeMap;

use aitm_core::Value;
use aitm_plugin_rhai::marshal::{dynamic_to_value, value_to_dynamic};

#[test]
fn scalars_round_trip() {
    for v in [
        Value::Null,
        Value::Bool(true),
        Value::Int(7),
        Value::Float(1.5),
        Value::Str("x".into()),
    ] {
        let back = dynamic_to_value(&value_to_dynamic(&v)).expect("scalar converts back");
        assert_eq!(back, v);
    }
}

#[test]
fn bytes_map_to_blob() {
    let d = value_to_dynamic(&Value::Bytes(vec![1, 2, 3]));
    assert!(d.is_blob(), "expected a Rhai blob, got {}", d.type_name());
    assert_eq!(
        dynamic_to_value(&d).expect("blob converts back"),
        Value::Bytes(vec![1, 2, 3])
    );
}

#[test]
fn nested_object_round_trips() {
    let mut obj = BTreeMap::new();
    obj.insert("a".to_string(), Value::Int(1));
    obj.insert("b".to_string(), Value::Array(vec![Value::Str("y".into())]));
    let v = Value::Object(obj);
    let d = value_to_dynamic(&v);
    assert!(d.is_map(), "expected a Rhai map, got {}", d.type_name());
    assert_eq!(dynamic_to_value(&d).expect("map converts back"), v);
}

#[test]
fn unmapped_rhai_type_is_runtime_error() {
    // A `char` has no `Value` counterpart.
    let d = rhai::Dynamic::from_char('c');
    match dynamic_to_value(&d) {
        Err(aitm_plugin_rhai::error::ScriptError::Runtime { message, .. }) => {
            assert!(
                message.contains("char"),
                "message names the type: {message}"
            );
        }
        other => panic!("expected ScriptError::Runtime, got {other:?}"),
    }
}
