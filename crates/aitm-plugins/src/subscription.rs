//! The subscription plugin: the chain tap behind F4 server push.
//!
//! Rather than tapping `aitm-core`'s event bus from outside, a tiny first-party
//! plugin sits in the chain and forwards every lifecycle [`Event`] to a
//! `tokio::sync::broadcast`. The MCP server holds the receiver and a dispatcher
//! task that renders each event as a `notifications/aitm/flow` line and pushes it
//! to every matching subscription — so "everything is a plugin" stays true and
//! the core event model is untouched (spec D3.3).
//!
//! The plugin also registers the `flow.subscribe`/`flow.unsubscribe` commands so
//! they appear in `tools/list` with a typed schema. Their *effect* is connection
//! scoped (they need the connection's push sink and the server's subscription
//! registry), so the MCP server handles them directly in `call_tool`; the command
//! bodies here exist only for schema/discovery and error if invoked off a
//! streaming connection (e.g. the CLI), where a subscription has nowhere to go.

use aitm_core::{
    Command, CommandHost, Event, FlowCtx, ParamDef, ParamSchema, Params, Plugin, Registry,
    Sensitivity, TypeDesc, Value, Verdict,
};
use anyhow::bail;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Forwards lifecycle events from the chain to a broadcast the MCP server drains.
pub struct SubscriptionPlugin {
    tx: broadcast::Sender<Event>,
}

impl SubscriptionPlugin {
    /// Build the plugin over the broadcast sender shared with the MCP server
    /// (`McpServer::with_push`).
    pub fn new(tx: broadcast::Sender<Event>) -> Self {
        Self { tx }
    }
}

impl Plugin for SubscriptionPlugin {
    fn name(&self) -> &str {
        "subscription"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(FlowSubscribe));
        reg.add_command(Arc::new(FlowUnsubscribe));
    }

    fn on_event(&mut self, ev: &Event, _ctx: &mut FlowCtx<'_>) -> Verdict {
        // A lagging/absent receiver must never block the proxy data path: a
        // broadcast `send` is non-blocking and its error (no live receiver, or a
        // slow one that will see `Lagged`) is intentionally ignored here.
        let _ = self.tx.send(ev.clone());
        Verdict::Continue
    }
}

fn param(name: &str, ty: TypeDesc, required: bool, description: &str) -> ParamDef {
    ParamDef {
        name: name.to_string(),
        ty,
        required,
        description: description.to_string(),
    }
}

/// `flow.subscribe {filter?, since?} -> {sub_id}` (Read). Handled by the MCP
/// server per-connection; this body is the schema and a clear off-stream error.
struct FlowSubscribe;

impl Command for FlowSubscribe {
    fn name(&self) -> &str {
        "flow.subscribe"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Subscribe to live flow notifications on this connection. Returns a \
                          sub_id; matching flows then arrive as notifications/aitm/flow lines with \
                          no further request. Read-only."
                .to_string(),
            params: vec![
                param(
                    "filter",
                    TypeDesc::Object(vec![
                        param(
                            "host",
                            TypeDesc::Str,
                            false,
                            "Match this host (host[:port]).",
                        ),
                        param("method", TypeDesc::Str, false, "Match this HTTP method."),
                    ]),
                    false,
                    "Only notify about flows matching these constraints (default: all).",
                ),
                param(
                    "since",
                    TypeDesc::FlowId,
                    false,
                    "Replay matching flows captured after this flow id before the live stream.",
                ),
            ],
            result: TypeDesc::Object(vec![param(
                "sub_id",
                TypeDesc::Int,
                true,
                "The subscription id, for flow.unsubscribe.",
            )]),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        bail!(
            "flow.subscribe is only meaningful over a streaming MCP connection (it has no push \
             channel to deliver notifications on when run this way)."
        )
    }
}

/// `flow.unsubscribe {sub_id} -> {}` (Read). Handled by the MCP server
/// per-connection; this body is the schema and a clear off-stream error.
struct FlowUnsubscribe;

impl Command for FlowUnsubscribe {
    fn name(&self) -> &str {
        "flow.unsubscribe"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Cancel a flow subscription on this connection. Read-only.".to_string(),
            params: vec![param(
                "sub_id",
                TypeDesc::Int,
                true,
                "The sub_id returned by flow.subscribe.",
            )],
            result: TypeDesc::Object(vec![]),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        bail!("flow.unsubscribe is only meaningful over a streaming MCP connection.")
    }
}
