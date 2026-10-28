//! `l4.craft` — build a [`PacketSpec`] into on-wire bytes + a structural summary.
//!
//! Sensitivity: **pure**. Crafting is sans-IO: no privilege, no guard, no wire
//! (building bytes is not sending them). The guard gates the wire in the inject /
//! send-recv commands (M5 Task 10), not here. `l4.craft` lets an operator or agent
//! author and inspect a packet — including a deliberately-malformed one — before
//! deciding to inject it.

use std::collections::BTreeMap;

use aitm_core::{Command, CommandHost, ParamDef, ParamSchema, Params, TypeDesc, Value};

use crate::craft::PacketSpec;

/// `l4.craft {spec}` → `{ length, bytes, summary }` for a layered packet spec.
pub struct Craft;

impl Command for Craft {
    fn name(&self) -> &str {
        "l4.craft"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Build a layered PacketSpec into on-wire bytes and a structural summary. \
                          Pure: no privilege, no wire. `Some` header fields ship verbatim (a \
                          forced-bad checksum/length is preserved); omitted fields auto-complete."
                .into(),
            params: vec![ParamDef {
                name: "spec".into(),
                ty: TypeDesc::Any,
                required: true,
                description: "A PacketSpec: `{ layers: [ {ipv4|ipv6|tcp|udp|icmp|ether: {..}} | \
                              {raw: [bytes]} , .. ] }`, outermost layer first."
                    .into(),
            }],
            result: TypeDesc::Object(craft_result_fields()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let spec = parse_spec(super::require(&args, "spec")?)?;
        // Pure build: `Some` fields verbatim (malformed survives), `None` auto-
        // completed. No guard, no wire — crafting is not sending.
        let bytes = spec
            .build()
            .map_err(|e| anyhow::anyhow!("craft failed: {e}"))?;
        let summary = PacketSpec::summarize(&bytes);

        let mut obj = BTreeMap::new();
        obj.insert("length".to_string(), Value::Int(bytes.len() as i64));
        obj.insert("summary".to_string(), summary_to_value(&summary));
        obj.insert("bytes".to_string(), Value::Bytes(bytes));
        Ok(Value::Object(obj))
    }
}

/// The fields `l4.craft` returns.
fn craft_result_fields() -> Vec<ParamDef> {
    vec![
        ParamDef {
            name: "length".into(),
            ty: TypeDesc::Int,
            required: true,
            description: "The built frame's length in bytes.".into(),
        },
        ParamDef {
            name: "bytes".into(),
            ty: TypeDesc::Bytes,
            required: true,
            description: "The built on-wire bytes.".into(),
        },
        ParamDef {
            name: "summary".into(),
            ty: TypeDesc::Object(vec![
                ParamDef {
                    name: "layers".into(),
                    ty: TypeDesc::Array(Box::new(TypeDesc::Str)),
                    required: true,
                    description: "Decoded layer names, outermost first.".into(),
                },
                ParamDef {
                    name: "length".into(),
                    ty: TypeDesc::Int,
                    required: true,
                    description: "The summarized buffer length.".into(),
                },
            ]),
            required: true,
            description: "A structural decode of the built bytes.".into(),
        },
    ]
}

/// A [`PacketSummary`](crate::craft::PacketSummary) as a transport-neutral object.
fn summary_to_value(summary: &crate::craft::PacketSummary) -> Value {
    let mut obj = BTreeMap::new();
    obj.insert(
        "layers".to_string(),
        Value::Array(summary.layers.iter().cloned().map(Value::Str).collect()),
    );
    obj.insert("length".to_string(), Value::Int(summary.length as i64));
    Value::Object(obj)
}

/// Deserialize a transport-neutral [`Value`] craft spec into a [`PacketSpec`].
fn parse_spec(spec: &Value) -> anyhow::Result<PacketSpec> {
    let json = super::value_to_json(spec);
    serde_json::from_value(json).map_err(|e| anyhow::anyhow!("invalid PacketSpec: {e}"))
}
