//! How the CLI prints a command's result (spec §D9).
//!
//! A string is the operator's text (a PEM, a message) and gets a trailing
//! newline; bytes (a DER certificate, a screenshot) go out raw so they can be
//! redirected to a file; anything else is the same JSON the MCP frontend
//! returns, pretty-printed.

use aitm_core::Value;
use aitm_mcp::json::to_json;

/// The bytes to write to stdout for `v`.
pub fn render_cli_value(v: &Value) -> Vec<u8> {
    match v {
        Value::Str(s) => format!("{s}\n").into_bytes(),
        Value::Bytes(b) => b.clone(),
        // `{:#}` on a `serde_json::Value` is its pretty-printed form.
        other => format!("{:#}\n", to_json(other)).into_bytes(),
    }
}
