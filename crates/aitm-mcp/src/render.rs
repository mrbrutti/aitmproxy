//! Readable `tools/call` result rendering (spec D3b).
//!
//! The `structuredContent` of a result stays the exact machine value, byte for
//! byte; only the human-facing `content` text is produced here: a one-line
//! `summarize` (when the command provides one) followed by the value as
//! pretty-printed, stable-key-ordered JSON — never a jammed single line — so a
//! dumb viewer and the agent transcript both read cleanly.

use serde_json::Value as JsonValue;

/// The `content[0].text` for a successful result: `summary` (when present) on its
/// own first line, then `value` as indented, stable-key JSON.
///
/// Key order is stable because `serde_json::Value` orders object keys (the
/// workspace builds `serde_json` without `preserve_order`, so maps are sorted).
pub fn render_content(summary: Option<&str>, value: &JsonValue) -> String {
    let pretty = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    match summary {
        Some(s) => format!("{s}\n{pretty}"),
        None => pretty,
    }
}
