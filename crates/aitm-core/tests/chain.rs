//! Task 8 (AC4 / AC-P1): the ordered, halting plugin chain and the pausable
//! interception future.

use aitm_core::{
    Body, Chain, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpVersion, InterceptState, MemFlowStore, Plugin, Registry, Verdict,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

fn http_flow() -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: "/".into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: ConnInfo {
            peer: addr,
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

fn label(ev: &Event) -> &'static str {
    match ev {
        Event::Request(_) => "Request",
        Event::Response(_) => "Response",
        Event::WsMessage { .. } => "WsMessage",
        _ => "other",
    }
}

/// Records `(plugin_name, event_label)` for each event it sees, and optionally
/// halts on a chosen event label.
struct RecPlugin {
    name: String,
    log: Arc<Mutex<Vec<(String, String)>>>,
    halt_on: Option<&'static str>,
}

impl Plugin for RecPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn on_event(&mut self, ev: &Event, _ctx: &mut FlowCtx<'_>) -> Verdict {
        let lbl = label(ev);
        self.log
            .lock()
            .unwrap()
            .push((self.name.clone(), lbl.to_string()));
        if self.halt_on == Some(lbl) {
            Verdict::Halt
        } else {
            Verdict::Continue
        }
    }
}

#[tokio::test]
async fn ordered_events_and_halt() {
    let log = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(RecPlugin {
        name: "A".into(),
        log: log.clone(),
        halt_on: Some("Request"), // A halts the Request event
    }));
    reg.add_plugin(Box::new(RecPlugin {
        name: "B".into(),
        log: log.clone(),
        halt_on: None,
    }));

    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let id = store.insert(http_flow());
    let chain = Chain::new(Arc::new(reg), store.clone());

    chain.dispatch(Event::Request(id)).await;
    chain.dispatch(Event::Response(id)).await;
    chain
        .dispatch(Event::WsMessage { flow: id, index: 0 })
        .await;

    let log = log.lock().unwrap();
    let names_for = |lbl: &str| -> Vec<String> {
        log.iter()
            .filter(|(_, l)| l == lbl)
            .map(|(n, _)| n.clone())
            .collect()
    };

    // A halted Request, so B never saw it.
    assert_eq!(names_for("Request"), vec!["A".to_string()]);
    // Response and WsMessage reach both, in registration order A then B.
    assert_eq!(
        names_for("Response"),
        vec!["A".to_string(), "B".to_string()]
    );
    assert_eq!(
        names_for("WsMessage"),
        vec!["A".to_string(), "B".to_string()]
    );
}

/// Intercepts the request: backs the flow up and parks it.
struct Interceptor;

impl Plugin for Interceptor {
    fn name(&self) -> &str {
        "interceptor"
    }
    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if matches!(ev, Event::Request(_)) {
            ctx.backup();
            ctx.intercept();
        }
        Verdict::Continue
    }
}

#[tokio::test]
async fn intercept_resume_forwards() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(Interceptor));
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let id = store.insert(http_flow());
    let chain = Arc::new(Chain::new(Arc::new(reg), store.clone()));

    // Dispatch parks on the resume receiver, so run it concurrently.
    let chain2 = chain.clone();
    let task = tokio::spawn(async move { chain2.dispatch(Event::Request(id)).await });

    // Wait until the flow is parked (Intercepted), then grab its resume handle.
    let resume = loop {
        if let Some(Flow::Http(f)) = store.get(id) {
            if let InterceptState::Intercepted { resume, .. } = &f.intercept {
                break resume.clone();
            }
        }
        tokio::task::yield_now().await;
    };

    assert!(
        matches!(store.get(id), Some(Flow::Http(f)) if matches!(f.intercept, InterceptState::Intercepted { .. })),
        "flow should be parked as Intercepted"
    );

    // A command fires the resume handle.
    resume.fire();
    task.await.expect("dispatch completes");

    assert!(
        matches!(store.get(id), Some(Flow::Http(f)) if matches!(f.intercept, InterceptState::Resumed)),
        "flow should be Resumed after firing the handle"
    );
}

/// An intercepted flow that is never resumed is killed after the timeout, so it
/// cannot pin the flow (or its backup) forever.
#[tokio::test]
async fn abandoned_intercept_is_killed_after_timeout() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(Interceptor));
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let id = store.insert(http_flow());
    let chain = Chain::new(Arc::new(reg), store.clone())
        .with_intercept_timeout(std::time::Duration::from_millis(50));

    // Dispatch parks, then (no resume ever fires) the timeout kills the flow.
    chain.dispatch(Event::Request(id)).await;

    assert!(
        matches!(store.get(id), Some(Flow::Http(f)) if matches!(f.intercept, InterceptState::Killed)),
        "an abandoned intercept must be killed after the timeout"
    );
}
