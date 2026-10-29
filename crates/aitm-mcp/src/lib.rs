//! `aitm-mcp` — MCP frontend over the one command bus.
//!
//! Every command in the [`aitm_core::Registry`] is exposed as an MCP tool whose
//! JSON Schema is derived from its [`aitm_core::ParamSchema`] ([`schema`]).
//! [`McpServer`] speaks JSON-RPC 2.0 one message at a time ([`McpServer::handle`])
//! so the same core serves every transport ([`transport`]): newline-delimited JSON
//! over stdio, or over a loopback-only TCP socket that requires a token.

mod base64;
pub mod json;
pub mod render;
pub mod schema;
pub mod server;
pub mod transport;

pub use aitm_core::McpTransport;
pub use schema::{McpSchemaDerive, McpTool, StdSchemaDerive};
pub use server::{
    ConnCtx, McpServer, NotificationSink, DEFAULT_BROADCAST_CAPACITY, DEFAULT_PUSH_CAPACITY,
};
