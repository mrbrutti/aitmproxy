//! MCP tool derivation: a command's transport-neutral `ParamSchema` becomes an
//! MCP tool whose `inputSchema` is JSON Schema.

use aitm_core::{Command, ParamDef, TypeDesc};
use serde_json::{json, Map, Value as JsonValue};

/// Maps the transport-neutral `ParamSchema` onto an MCP tool with JSON Schema input.
pub trait McpSchemaDerive {
    fn to_mcp_tool(&self, cmd: &dyn Command) -> McpTool;
}

/// One MCP tool, as `tools/list` reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct McpTool {
    /// `== Command::name()`.
    pub name: String,
    pub description: String,
    /// JSON Schema derived from `ParamSchema.params`.
    pub input_schema: JsonValue,
}

impl McpTool {
    /// The MCP wire form (`inputSchema` is camelCase on the wire).
    pub fn to_json(&self) -> JsonValue {
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        })
    }
}

/// The M1 derivation: one JSON Schema property per `ParamDef`, required params
/// listed, undeclared properties rejected.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdSchemaDerive;

impl McpSchemaDerive for StdSchemaDerive {
    fn to_mcp_tool(&self, cmd: &dyn Command) -> McpTool {
        let schema = cmd.schema();
        McpTool {
            name: cmd.name().to_string(),
            description: schema.description,
            input_schema: object_schema(&schema.params),
        }
    }
}

/// JSON Schema for one `TypeDesc`.
pub fn type_schema(ty: &TypeDesc) -> JsonValue {
    match ty {
        TypeDesc::Bool => json!({"type": "boolean"}),
        TypeDesc::Int => json!({"type": "integer"}),
        TypeDesc::Float => json!({"type": "number"}),
        TypeDesc::Str => json!({"type": "string"}),
        TypeDesc::Bytes => json!({"type": "string", "contentEncoding": "base64"}),
        TypeDesc::FlowId => json!({"type": "string", "format": "uuid"}),
        TypeDesc::Array(item) => json!({"type": "array", "items": type_schema(item)}),
        TypeDesc::Object(defs) => object_schema(defs),
        TypeDesc::Map(item) => json!({
            "type": "object",
            "additionalProperties": type_schema(item),
        }),
        TypeDesc::Any => json!({}),
    }
}

fn object_schema(defs: &[ParamDef]) -> JsonValue {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for def in defs {
        let mut prop = type_schema(&def.ty);
        if !def.description.is_empty() {
            if let Some(obj) = prop.as_object_mut() {
                obj.insert(
                    "description".into(),
                    JsonValue::String(def.description.clone()),
                );
            }
        }
        properties.insert(def.name.clone(), prop);
        if def.required {
            required.push(JsonValue::String(def.name.clone()));
        }
    }
    let mut schema = Map::new();
    schema.insert("type".into(), json!("object"));
    schema.insert("properties".into(), JsonValue::Object(properties));
    if !required.is_empty() {
        schema.insert("required".into(), JsonValue::Array(required));
    }
    schema.insert("additionalProperties".into(), json!(false));
    JsonValue::Object(schema)
}
