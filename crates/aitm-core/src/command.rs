//! The command trait and its typed schema. Every deterministic capability is a
//! `Command` a plugin registers; all frontends (MCP, CLI, …) invoke the same
//! commands, and the MCP tool schema is derived from `ParamSchema`/`TypeDesc`.

use crate::ctx::CommandHost;
use crate::value::{Params, Value};

/// A transport-neutral type descriptor; MCP derives JSON Schema from it.
#[derive(Debug, Clone)]
pub enum TypeDesc {
    Bool,
    Int,
    Float,
    Str,
    Bytes,
    FlowId,
    Array(Box<TypeDesc>),
    Object(Vec<ParamDef>),
    Any,
}

/// One declared parameter.
#[derive(Debug, Clone)]
pub struct ParamDef {
    pub name: String,
    pub ty: TypeDesc,
    pub required: bool,
    pub description: String,
}

/// A command's typed parameter + result schema.
#[derive(Debug, Clone)]
pub struct ParamSchema {
    pub description: String,
    pub params: Vec<ParamDef>,
    pub result: TypeDesc,
}

/// A deterministic capability callable from any frontend.
pub trait Command: Send + Sync {
    /// The dotted command name, e.g. `"flow.list"`.
    fn name(&self) -> &str;
    /// The typed schema (drives the MCP tool schema).
    fn schema(&self) -> ParamSchema;
    /// Run the command with typed arguments against the core services in `host`.
    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value>;
}
