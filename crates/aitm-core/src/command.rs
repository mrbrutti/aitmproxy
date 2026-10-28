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
    /// A fixed set of named fields.
    Object(Vec<ParamDef>),
    /// A free-form string-keyed map whose values all share one type
    /// (`headers: Map(Str)`, `vars: Map(Any)`).
    Map(Box<TypeDesc>),
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
    /// A question a human frontend must put to the operator before `invoke`,
    /// for these arguments. `None` (the default) means no confirmation is
    /// needed; a frontend without a human never asks and relies on the
    /// command's own gate.
    fn confirm_prompt(&self, _args: &Params) -> Option<String> {
        None
    }
}
