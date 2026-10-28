//! The intercept plugin: an arm-able mode that parks every request as a pausable
//! future (data-flow 2), plus the commands that release a parked flow.
//!
//! `flow.intercept` arms or disarms the mode. While armed, `on_event(Request)`
//! backs the flow up and parks it; the chain then awaits the `ResumeHandle` this
//! plugin keeps per flow. `flow.resume` fires that handle so the parked future
//! wakes and forwards the (possibly mutated) request; `flow.kill` marks the flow
//! killed and wakes the future so the client sees the connection dropped.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use aitm_core::{
    Command, CommandHost, Event, Flow, FlowCtx, FlowId, InterceptState, ParamDef, ParamSchema,
    Params, Plugin, Registry, ResumeHandle, TypeDesc, Value, Verdict,
};

/// State the plugin (which parks flows on events) shares with its commands
/// (which release them).
#[derive(Default)]
struct Shared {
    armed: AtomicBool,
    parked: Mutex<HashMap<FlowId, ResumeHandle>>,
}

/// Registers `flow.intercept`, `flow.resume`, `flow.kill`; parks requests while
/// armed.
pub struct InterceptPlugin {
    shared: Arc<Shared>,
}

impl InterceptPlugin {
    pub fn new() -> Self {
        Self {
            shared: Arc::default(),
        }
    }
}

impl Default for InterceptPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for InterceptPlugin {
    fn name(&self) -> &str {
        "intercept"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(FlowIntercept {
            shared: self.shared.clone(),
        }));
        reg.add_command(Arc::new(FlowResume {
            shared: self.shared.clone(),
        }));
        reg.add_command(Arc::new(FlowKill {
            shared: self.shared.clone(),
        }));
    }

    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if let Event::Request(id) = ev {
            if self.shared.armed.load(Ordering::SeqCst) {
                ctx.backup();
                let handle = ctx.intercept();
                if let Ok(mut parked) = self.shared.parked.lock() {
                    parked.insert(*id, handle);
                }
            }
        }
        Verdict::Continue
    }
}

fn id_param(description: &str) -> ParamDef {
    ParamDef {
        name: "id".into(),
        ty: TypeDesc::FlowId,
        required: true,
        description: description.into(),
    }
}

/// `flow.intercept {enabled?}` → arm (default) or disarm; returns the armed state.
struct FlowIntercept {
    shared: Arc<Shared>,
}

impl Command for FlowIntercept {
    fn name(&self) -> &str {
        "flow.intercept"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Arm (default) or disarm interception: while armed, every request is \
                          parked until flow.resume or flow.kill releases it."
                .into(),
            params: vec![ParamDef {
                name: "enabled".into(),
                ty: TypeDesc::Bool,
                required: false,
                description: "true to arm (default), false to disarm.".into(),
            }],
            result: TypeDesc::Bool,
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let enabled = match args.get("enabled") {
            None => true,
            Some(_) => args.get_bool("enabled")?,
        };
        self.shared.armed.store(enabled, Ordering::SeqCst);
        Ok(Value::Bool(enabled))
    }
}

/// `flow.resume {id}` → fire the parked flow's handle; it forwards.
struct FlowResume {
    shared: Arc<Shared>,
}

impl Command for FlowResume {
    fn name(&self) -> &str {
        "flow.resume"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description:
                "Release an intercepted flow so its (possibly mutated) request is forwarded.".into(),
            params: vec![id_param("The intercepted flow to resume.")],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        release(&self.shared, host, args.get_flow_id("id")?, Release::Resume)
    }
}

/// `flow.kill {id}` → drop the parked flow; the client sees a closed connection.
struct FlowKill {
    shared: Arc<Shared>,
}

impl Command for FlowKill {
    fn name(&self) -> &str {
        "flow.kill"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Drop an intercepted flow; the client sees a reset/closed connection."
                .into(),
            params: vec![id_param("The intercepted flow to kill.")],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        release(&self.shared, host, args.get_flow_id("id")?, Release::Kill)
    }
}

enum Release {
    Resume,
    Kill,
}

/// Release a parked flow: record its new state in the store, then wake the
/// parked future. The handle is the one this plugin parked, or — for a flow
/// another plugin parked — the one its stored `Intercepted` state carries.
fn release(shared: &Shared, host: &CommandHost, id: FlowId, how: Release) -> anyhow::Result<Value> {
    let parked = shared
        .parked
        .lock()
        .map_err(|_| anyhow::anyhow!("intercept state poisoned"))?
        .remove(&id);
    let handle = match parked {
        Some(handle) => handle,
        None => stored_handle(host, id)?,
    };
    let (state, label) = match how {
        Release::Resume => (InterceptState::Resumed, "resumed"),
        Release::Kill => (InterceptState::Killed, "killed"),
    };
    host.store().update(id, &mut |flow: &mut Flow| {
        set_intercept(flow, state.clone())
    });
    handle.fire();
    Ok(Value::Str(label.into()))
}

/// The resume handle a stored flow's `Intercepted` state carries.
fn stored_handle(host: &CommandHost, id: FlowId) -> anyhow::Result<ResumeHandle> {
    let flow = host
        .store()
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("no flow with id {id}"))?;
    let state = match &flow {
        Flow::Http(f) => &f.intercept,
        Flow::WebSocket(f) => &f.intercept,
    };
    match state {
        InterceptState::Intercepted { resume, .. } => Ok(resume.clone()),
        _ => anyhow::bail!("flow {id} is not intercepted"),
    }
}

fn set_intercept(flow: &mut Flow, state: InterceptState) {
    match flow {
        Flow::Http(f) => f.intercept = state,
        Flow::WebSocket(f) => f.intercept = state,
    }
}
