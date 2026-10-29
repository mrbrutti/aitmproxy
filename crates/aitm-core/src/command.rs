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

/// How much authority running a command grants, used by the agent policy gate
/// (F1/D2). The default (unclassified) is [`Sensitivity::Sensitive`] so a new
/// command never silently runs autonomously — deny-by-default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Observation only; changes no state (`flow.list`, `ca.status`, …).
    Read,
    /// A routine, scope/rate/SSRF-bounded testing verb (`flow.replay`,
    /// `request.send`, `poc.run`, `browser.navigate`, …).
    Write,
    /// Trust, authorization, or irreversible-beyond-scope (`ca.install`,
    /// `scope.add`, …); the fail-closed default for an unclassified command.
    Sensitive,
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
    /// The authority tier the agent policy gate enforces (D2). The default is
    /// fail-closed [`Sensitivity::Sensitive`]: an unclassified command never
    /// runs autonomously.
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }
    /// Whether running the command changes state. Derived: every tier except
    /// [`Sensitivity::Read`] mutates.
    fn mutates(&self) -> bool {
        self.sensitivity() != Sensitivity::Read
    }
    /// An optional one-line, human-readable summary of an outcome for these
    /// arguments and this result (e.g. `"replayed #52 → 200 OK"`). `None` (the
    /// default) lets a surface fall back to the typed render.
    fn summarize(&self, _args: &Params, _result: &Value) -> Option<String> {
        None
    }
}
