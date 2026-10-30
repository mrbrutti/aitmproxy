//! MCP Apps widget registry (Design A/B, workstream W2).
//!
//! The server serves one `ui://aitm/<widget>` HTML template per family over
//! `resources/list` / `resources/read` (see [`crate::server`]), and overlays the
//! widget `_meta`/annotations/`outputSchema` onto the mapped tools' `tools/list`
//! entries via [`widget_meta_for`] (consumed by `schema.rs`, workstream W3).
//!
//! The HTML is compiled in with `include_str!`; W2 ships minimal placeholders and
//! W5 replaces each with the rich, palette-correct document. This module is the
//! single seam the two workstreams share.

use serde_json::{json, Value as JsonValue};

/// The MCP Apps resource mime type (research 08 §3.3; SDK `RESOURCE_MIME_TYPE`).
pub const RESOURCE_MIME: &str = "text/html;profile=mcp-app";

/// Placeholder widget origin (Design H). Replaced with the real per-plugin
/// domain at ChatGPT submission time; documented as a submission step.
pub const WIDGET_DOMAIN: &str = "aitmproxy.widget";

/// A compile-time widget template served over `resources/*`.
pub struct Widget {
    /// The `ui://aitm/<widget>` resource URI (cache key; 08 §3.3).
    pub uri: &'static str,
    /// Machine name (resource `name`).
    pub name: &'static str,
    /// Human title (resource `title`).
    pub title: &'static str,
    /// One-line description.
    pub description: &'static str,
    /// Whether the host should draw a border around the widget.
    pub prefers_border: bool,
    /// The complete HTML5 document (inlined CSS+JS; CSP-clean).
    pub html: &'static str,
}

/// The seven widget families (Design C). Order is stable and is the order
/// `resources/list` returns.
pub fn widgets() -> &'static [Widget] {
    &WIDGETS
}

static WIDGETS: [Widget; 7] = [
    Widget {
        uri: "ui://aitm/flows",
        name: "flows",
        title: "Flows",
        description: "Captured flows as a sortable table.",
        prefers_border: true,
        html: include_str!("../widgets/flows.html"),
    },
    Widget {
        uri: "ui://aitm/flow-detail",
        name: "flow-detail",
        title: "Flow detail",
        description: "One flow's request and response.",
        prefers_border: true,
        html: include_str!("../widgets/flow-detail.html"),
    },
    Widget {
        uri: "ui://aitm/findings",
        name: "findings",
        title: "Findings",
        description: "Recorded findings by severity.",
        prefers_border: true,
        html: include_str!("../widgets/findings.html"),
    },
    Widget {
        uri: "ui://aitm/finding-detail",
        name: "finding-detail",
        title: "Finding detail",
        description: "One finding's evidence and detail.",
        prefers_border: true,
        html: include_str!("../widgets/finding-detail.html"),
    },
    Widget {
        uri: "ui://aitm/scope",
        name: "scope",
        title: "Scope",
        description: "In-scope hosts and TLS passthrough.",
        prefers_border: true,
        html: include_str!("../widgets/scope.html"),
    },
    Widget {
        uri: "ui://aitm/poc-result",
        name: "poc-result",
        title: "PoC result",
        description: "A proof-of-concept run's result.",
        prefers_border: true,
        html: include_str!("../widgets/poc-result.html"),
    },
    Widget {
        uri: "ui://aitm/proxy-status",
        name: "proxy-status",
        title: "Proxy status",
        description: "Proxy, intercept, agent, and L4 status.",
        prefers_border: true,
        html: include_str!("../widgets/proxy-status.html"),
    },
];

/// The resource `_meta` for a widget (Design A placement 2): both the standard
/// `ui.*` keys and the legacy `openai/*` aliases. CSP domain arrays are empty
/// (widgets are fully self-contained; Constraints: CSP).
pub fn resource_meta(w: &Widget) -> JsonValue {
    json!({
        "ui": {
            "csp": {"connectDomains": [], "resourceDomains": []},
            "domain": WIDGET_DOMAIN,
            "prefersBorder": w.prefers_border,
        },
        "openai/widgetCSP": {"connect_domains": [], "resource_domains": []},
        "openai/widgetDomain": WIDGET_DOMAIN,
        "openai/widgetPrefersBorder": w.prefers_border,
        "openai/ui": {"availableDisplayModes": ["inline"]},
    })
}

/// The tool-descriptor widget overlay (Design A placement 1 / Design D).
///
/// Defined here so `schema.rs` (W3) can `use` it. `resource_uri` is `None` for a
/// data-only widget-accessible tool (`tls.passthrough.list`), which gets
/// `ui.visibility` + legacy `openai/widgetAccessible` but no `resourceUri`.
#[derive(Clone, Copy, Debug)]
pub struct WidgetMeta {
    /// The mapped `ui://aitm/<widget>` URI, or `None` for a data-only tool.
    pub resource_uri: Option<&'static str>,
    /// `openai/toolInvocation/invoking` status text (≤ 64 chars).
    pub invoking: &'static str,
    /// `openai/toolInvocation/invoked` status text (≤ 64 chars).
    pub invoked: &'static str,
    /// `annotations.readOnlyHint`.
    pub read_only: bool,
    /// `annotations.destructiveHint`.
    pub destructive: bool,
    /// `annotations.openWorldHint`.
    pub open_world: bool,
    /// Whether the widget may call this tool (`ui.visibility`/`openai/widgetAccessible`).
    pub widget_accessible: bool,
}

/// Map a tool name to its widget overlay, or `None` for a non-widget tool
/// (Design C/D). The eight widget tools map to their `ui://aitm/<widget>` URI;
/// `tls.passthrough.list` is widget-accessible with no render template.
pub fn widget_meta_for(tool_name: &str) -> Option<WidgetMeta> {
    let render = |uri, invoking, invoked, read_only, open_world| WidgetMeta {
        resource_uri: Some(uri),
        invoking,
        invoked,
        read_only,
        destructive: false,
        open_world,
        widget_accessible: false,
    };
    match tool_name {
        "flow.table" => Some(render(
            "ui://aitm/flows",
            "Fetching flows",
            "Flows ready",
            true,
            false,
        )),
        "flow.detail" => Some(render(
            "ui://aitm/flow-detail",
            "Loading flow",
            "Flow loaded",
            true,
            false,
        )),
        "findings.list" => Some(render(
            "ui://aitm/findings",
            "Loading findings",
            "Findings ready",
            true,
            false,
        )),
        "findings.get" => Some(render(
            "ui://aitm/finding-detail",
            "Loading finding",
            "Finding loaded",
            true,
            false,
        )),
        "scope.list" => Some(render(
            "ui://aitm/scope",
            "Loading scope",
            "Scope ready",
            true,
            false,
        )),
        "poc.get" => Some(render(
            "ui://aitm/poc-result",
            "Loading PoC result",
            "PoC result ready",
            true,
            false,
        )),
        // The one non-read-only widget tool: it runs a PoC against a target.
        "poc.run" => Some(render(
            "ui://aitm/poc-result",
            "Running PoC",
            "PoC complete",
            false,
            true,
        )),
        "proxy.status" => Some(render(
            "ui://aitm/proxy-status",
            "Reading status",
            "Status ready",
            true,
            false,
        )),
        // Data-only, widget-accessible: the scope widget calls it; no template.
        "tls.passthrough.list" => Some(WidgetMeta {
            resource_uri: None,
            invoking: "",
            invoked: "",
            read_only: true,
            destructive: false,
            open_world: false,
            widget_accessible: true,
        }),
        _ => None,
    }
}
