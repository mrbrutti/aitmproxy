//! Transport-neutral values and the typed argument bag commands receive.
//!
//! `Value` is what crosses the command bus — MCP and CLI alike. `Params` is a
//! name→value map with typed getters that fail with a clear error on a missing or
//! mistyped argument, so command bodies can use `?` instead of hand-rolling checks.

use std::collections::BTreeMap;

use crate::flow::FlowId;

/// A transport-neutral value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

/// A named argument bag handed to a command.
#[derive(Debug, Clone, Default)]
pub struct Params(BTreeMap<String, Value>);

impl Params {
    /// Build a bag from a name→value map.
    pub fn new(map: BTreeMap<String, Value>) -> Self {
        Self(map)
    }

    /// The raw value for `name`, if present.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.get(name)
    }

    /// Whether the bag is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of arguments.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over `(name, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// A required string argument.
    pub fn get_str(&self, name: &str) -> anyhow::Result<&str> {
        match self.0.get(name) {
            Some(Value::Str(s)) => Ok(s),
            Some(other) => anyhow::bail!("param `{name}` must be a string, got {other:?}"),
            None => anyhow::bail!("missing required param `{name}`"),
        }
    }

    /// A required integer argument.
    pub fn get_int(&self, name: &str) -> anyhow::Result<i64> {
        match self.0.get(name) {
            Some(Value::Int(i)) => Ok(*i),
            Some(other) => anyhow::bail!("param `{name}` must be an integer, got {other:?}"),
            None => anyhow::bail!("missing required param `{name}`"),
        }
    }

    /// A required boolean argument.
    pub fn get_bool(&self, name: &str) -> anyhow::Result<bool> {
        match self.0.get(name) {
            Some(Value::Bool(b)) => Ok(*b),
            Some(other) => anyhow::bail!("param `{name}` must be a boolean, got {other:?}"),
            None => anyhow::bail!("missing required param `{name}`"),
        }
    }

    /// A required flow-id argument (carried as a string on the bus).
    pub fn get_flow_id(&self, name: &str) -> anyhow::Result<FlowId> {
        let s = self.get_str(name)?;
        s.parse::<FlowId>()
            .map_err(|e| anyhow::anyhow!("param `{name}` is not a valid flow id: {e}"))
    }

    /// A required object argument.
    pub fn get_object(&self, name: &str) -> anyhow::Result<&BTreeMap<String, Value>> {
        match self.0.get(name) {
            Some(Value::Object(o)) => Ok(o),
            Some(other) => anyhow::bail!("param `{name}` must be an object, got {other:?}"),
            None => anyhow::bail!("missing required param `{name}`"),
        }
    }
}
