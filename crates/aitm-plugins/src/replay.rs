//! The replay plugin: `flow.replay {id}` reissues a captured HTTP request through
//! the proxy's own client.
//!
//! The request passes the scope/rate guard before anything is sent, so an
//! out-of-scope host is refused with the guard's error (AC16); the client marks
//! the resulting flow `is_replay` and captures it (AC6).

use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, Flow, ParamDef, ParamSchema, Params, Plugin, Registry, TypeDesc, Value,
};

use crate::block_on;

/// Registers `flow.replay`. Observes no events.
pub struct ReplayPlugin;

impl ReplayPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ReplayPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for ReplayPlugin {
    fn name(&self) -> &str {
        "replay"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(FlowReplay));
    }
}

/// `flow.replay {id}` → the id of the fresh, captured replay flow.
struct FlowReplay;

impl Command for FlowReplay {
    fn name(&self) -> &str {
        "flow.replay"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description:
                "Reissue a captured HTTP request through the proxy client; returns the new flow's id."
                    .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::FlowId,
                required: true,
                description: "The captured HTTP flow to replay.".into(),
            }],
            result: TypeDesc::FlowId,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_flow_id("id")?;
        let flow = host
            .store()
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("no flow with id {id}"))?;
        let Flow::Http(http) = flow else {
            anyhow::bail!("flow {id} is a WebSocket flow; only HTTP flows can be replayed");
        };
        let request = http.request;
        // Held across the send: dropping the permit releases the concurrency slot.
        let _permit = host.guard().check_active(&request.authority)?;
        let replayed = block_on(host.client().send(request))?;
        Ok(Value::Str(replayed.id.to_string()))
    }
}
