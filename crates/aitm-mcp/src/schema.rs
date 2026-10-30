//! MCP tool derivation: a command's transport-neutral `ParamSchema` becomes an
//! MCP tool whose `inputSchema` is JSON Schema.

use aitm_core::{Command, ParamDef, Params, TypeDesc};
use serde_json::{json, Map, Value as JsonValue};

/// Maps the transport-neutral `ParamSchema` onto an MCP tool with JSON Schema input.
pub trait McpSchemaDerive {
    fn to_mcp_tool(&self, cmd: &dyn Command) -> McpTool;
}

/// One MCP tool, as `tools/list` reports it.
///
/// `PartialEq` is intentionally not derived: `ui` ([`crate::widgets::WidgetMeta`])
/// and `result` ([`TypeDesc`]) are not `PartialEq`, and both are defined in other
/// files this workstream does not edit. Nothing compares `McpTool` values (tool
/// equality is asserted on the `to_json` wire form instead).
#[derive(Debug, Clone)]
pub struct McpTool {
    /// `== Command::name()`.
    pub name: String,
    pub description: String,
    /// JSON Schema derived from `ParamSchema.params`.
    pub input_schema: JsonValue,
    /// Whether this command may require an operator confirmation (its
    /// `confirm_prompt` can return `Some`), so a surface knows which commands may
    /// take the confirm-over-the-wire handshake (spec D4) without calling them.
    pub confirmable: bool,
    /// The MCP Apps widget overlay for this tool, or `None` for a non-widget tool
    /// (Design A placement 1 / Design D). When `Some`, `to_json` appends
    /// `annotations`, `outputSchema`, and `_meta`; when `None`, `to_json` is
    /// byte-identical to the pre-overlay wire form (AC6).
    pub ui: Option<crate::widgets::WidgetMeta>,
    /// The command result type, used to build `outputSchema` when `ui` is `Some`.
    pub result: TypeDesc,
}

impl McpTool {
    /// The MCP wire form (`inputSchema` is camelCase on the wire).
    ///
    /// When `ui` is `Some`, appends the widget overlay (`annotations`,
    /// `outputSchema`, `_meta`); when `ui` is `None`, the output is byte-identical
    /// to the pre-overlay form (AC6).
    pub fn to_json(&self) -> JsonValue {
        let mut tool = json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "confirmable": self.confirmable,
        });
        let Some(ui) = &self.ui else {
            return tool;
        };
        if let Some(obj) = tool.as_object_mut() {
            // Annotations: all three hints are required for a tool that returns
            // `structuredContent` (research 08 §3.2).
            obj.insert(
                "annotations".into(),
                json!({
                    "readOnlyHint": ui.read_only,
                    "destructiveHint": ui.destructive,
                    "openWorldHint": ui.open_world,
                }),
            );
            // `outputSchema` for the structured result.
            obj.insert("outputSchema".into(), type_schema(&self.result));
            // Tool-descriptor `_meta` (research 08 §3.2 exact key strings).
            let mut meta = Map::new();
            match ui.resource_uri {
                Some(uri) => {
                    // Render tool: standard `ui.resourceUri` plus the `openai/*`
                    // alias (equal), and the two ≤64-char invocation strings.
                    meta.insert("ui".into(), json!({"resourceUri": uri}));
                    meta.insert("openai/outputTemplate".into(), json!(uri));
                    meta.insert("openai/toolInvocation/invoking".into(), json!(ui.invoking));
                    meta.insert("openai/toolInvocation/invoked".into(), json!(ui.invoked));
                }
                None => {
                    // Data-only, widget-accessible tool: no render template.
                    if ui.widget_accessible {
                        meta.insert("ui".into(), json!({"visibility": ["model", "app"]}));
                        meta.insert("openai/widgetAccessible".into(), json!(true));
                    }
                }
            }
            obj.insert("_meta".into(), JsonValue::Object(meta));
        }
        tool
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
            // Static for the surface: a command is confirmable iff it can return a
            // `confirm_prompt` (probed with no arguments; `confirm_prompt` is
            // read-only by contract). Drives the operator handshake (spec D4).
            confirmable: cmd.confirm_prompt(&Params::default()).is_some(),
            // Widget overlay keyed on the tool name (W3, amendment): `None` for a
            // non-widget tool, keeping its `to_json` byte-identical (AC6).
            ui: crate::widgets::widget_meta_for(cmd.name()),
            result: schema.result,
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
