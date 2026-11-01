//! Task 8 (AC4 / AC-P1): the ordered, halting plugin chain and the pausable
//! interception future.

use aitm_core::{
    Body, Chain, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpVersion, InterceptState, MemFlowStore, Plugin, Registry, TunnelInfo,
    TunnelReason, Verdict,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

fn http_flow() -> Flow {
    http_flow_with(FlowMeta::default())
}

/// An ordinary `GET http://ex.test/` flow carrying the given metadata.
fn http_flow_with(metadata: FlowMeta) -> Flow {
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
        metadata,
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
/// halts on a chosen event label. `observes_passive` is what it answers to
/// `Plugin::observes_passive_flows`.
struct RecPlugin {
    name: String,
    log: Arc<Mutex<Vec<(String, String)>>>,
    halt_on: Option<&'static str>,
    observes_passive: bool,
}

impl Plugin for RecPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn observes_passive_flows(&self) -> bool {
        self.observes_passive
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
        observes_passive: false,
    }));
    reg.add_plugin(Box::new(RecPlugin {
        name: "B".into(),
        log: log.clone(),
        halt_on: None,
        observes_passive: false,
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

/// On `Request`, writes a mark to the *live* store copy (standing in for a
/// concurrent `flow.mark` command) and a different mark to its own working copy.
struct ConcurrentMarker {
    store: Arc<dyn FlowStore>,
}

impl Plugin for ConcurrentMarker {
    fn name(&self) -> &str {
        "concurrent-marker"
    }
    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if matches!(ev, Event::Request(_)) {
            let id = ctx.flow().id();
            // A concurrent operator annotation lands on the stored flow while this
            // dispatch still holds its own copy.
            self.store.update(id, &mut |f: &mut Flow| {
                f.metadata_mut().marks.push("concurrent".into());
            });
            // The plugin's own edit, applied to its working copy.
            ctx.flow_mut().metadata_mut().marks.push("plugin".into());
        }
        Verdict::Continue
    }
}

/// A concurrent `flow.mark` that lands while the chain is dispatching must not be
/// clobbered by the plugins' write-back.
///
/// Regression: dispatch cloned the flow out, ran plugins on the clone, then
/// blind-inserted it over the store — discarding any mark/comment a command set
/// in between.
#[tokio::test]
async fn concurrent_mark_survives_plugin_writeback() {
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let id = store.insert(http_flow());
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(ConcurrentMarker {
        store: store.clone(),
    }));
    let chain = Chain::new(Arc::new(reg), store.clone());

    chain.dispatch(Event::Request(id)).await;

    let marks = match store.get(id) {
        Some(Flow::Http(f)) => f.metadata.marks,
        other => panic!("expected http flow, got {other:?}"),
    };
    assert!(
        marks.iter().any(|m| m == "plugin"),
        "the plugin's own mark must be persisted, got {marks:?}"
    );
    assert!(
        marks.iter().any(|m| m == "concurrent"),
        "a concurrent mark must survive the plugin write-back, got {marks:?}"
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

/// A killed parked flow must stay `Killed` after the chain's pausable future
/// wakes, so the HTTP module drops the connection instead of forwarding it.
///
/// Regression: the chain used to clobber the kill back to `Resumed` on wake, so
/// a killed, intercept-armed request was forwarded upstream and the client
/// received the upstream response instead of a closed connection — the
/// `flow.kill` safety control did nothing.
#[tokio::test]
async fn intercept_kill_is_dropped_not_forwarded() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(Interceptor));
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let id = store.insert(http_flow());
    let chain = Arc::new(Chain::new(Arc::new(reg), store.clone()));

    // Dispatch parks on the resume receiver, so run it concurrently.
    let chain2 = chain.clone();
    let task = tokio::spawn(async move { chain2.dispatch(Event::Request(id)).await });

    // Wait until the flow is parked, then grab its resume handle.
    let resume = loop {
        if let Some(Flow::Http(f)) = store.get(id) {
            if let InterceptState::Intercepted { resume, .. } = &f.intercept {
                break resume.clone();
            }
        }
        tokio::task::yield_now().await;
    };

    // Reproduce exactly what the intercept plugin's `release(.., Kill)` does:
    // record `Killed` in the store, then wake the parked future.
    store.update(id, &mut |f: &mut Flow| {
        if let Flow::Http(h) = f {
            h.intercept = InterceptState::Killed;
        }
    });
    resume.fire();

    let verdict = task.await.expect("dispatch completes");

    // The kill survives the wake: the flow is still `Killed` (so the HTTP module
    // drops the connection rather than forwarding), and the chain halts.
    assert!(
        matches!(store.get(id), Some(Flow::Http(f)) if matches!(f.intercept, InterceptState::Killed)),
        "a killed flow must stay Killed after the wake, not be forwarded as Resumed"
    );
    assert_eq!(
        verdict,
        Verdict::Halt,
        "a killed flow halts the chain instead of continuing to forward"
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

/// Spec D4 / AC10: a passive flow (`passive = true`, or a tunnel row via
/// `tunnel.is_some()`) is dispatched only to plugins that opt in through
/// `observes_passive_flows()`; a flow with neither still reaches every plugin, in
/// registration order.
#[tokio::test]
async fn passive_flow_reaches_only_observers() {
    /// Dispatch `Request` on a flow carrying `metadata` through an "actor" (does
    /// not observe passive flows) and an "observer" (does). Returns both logs and
    /// the verdict.
    async fn run(metadata: FlowMeta) -> (Vec<(String, String)>, Vec<(String, String)>, Verdict) {
        let actor_log = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let observer_log = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(RecPlugin {
            name: "actor".into(),
            log: actor_log.clone(),
            halt_on: None,
            observes_passive: false,
        }));
        reg.add_plugin(Box::new(RecPlugin {
            name: "observer".into(),
            log: observer_log.clone(),
            halt_on: None,
            observes_passive: true,
        }));
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let id = store.insert(http_flow_with(metadata));
        let chain = Chain::new(Arc::new(reg), store);

        let verdict = chain.dispatch(Event::Request(id)).await;
        let actor = actor_log.lock().unwrap().clone();
        let observer = observer_log.lock().unwrap().clone();
        (actor, observer, verdict)
    }

    let seen = |name: &str| vec![(name.to_string(), "Request".to_string())];

    // `passive = true`: only the observer runs.
    let (actor, observer, verdict) = run(FlowMeta {
        passive: true,
        ..FlowMeta::default()
    })
    .await;
    assert_eq!(
        observer,
        seen("observer"),
        "the observer must see the passive flow's event"
    );
    assert!(
        actor.is_empty(),
        "a plugin that does not observe passive flows must not run on one, got {actor:?}"
    );
    assert_eq!(verdict, Verdict::Continue);

    // A tunnel row (`passive = false`, `tunnel.is_some()`) is passive too.
    let (actor, observer, verdict) = run(FlowMeta {
        passive: false,
        tunnel: Some(TunnelInfo::passthrough(TunnelReason::OutOfScope)),
        ..FlowMeta::default()
    })
    .await;
    assert_eq!(
        observer,
        seen("observer"),
        "the observer must see the tunnel row's event"
    );
    assert!(
        actor.is_empty(),
        "a plugin that does not observe passive flows must not run on a tunnel row, got {actor:?}"
    );
    assert_eq!(verdict, Verdict::Continue);

    // Neither: every plugin runs, as before.
    let (actor, observer, verdict) = run(FlowMeta::default()).await;
    assert_eq!(
        actor,
        seen("actor"),
        "an ordinary flow still reaches the actor"
    );
    assert_eq!(
        observer,
        seen("observer"),
        "an ordinary flow still reaches the observer"
    );
    assert_eq!(verdict, Verdict::Continue);
}

/// Spec D4 / AC10: a passive flow is never parked. The intercepting plugin does
/// not observe passive flows, so it is skipped: `dispatch` returns at once with
/// `Continue` (no 300 s intercept wait) and the stored flow stays `Observed`.
#[tokio::test]
async fn passive_flow_is_never_parked() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(Interceptor));
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let id = store.insert(http_flow_with(FlowMeta {
        passive: true,
        ..FlowMeta::default()
    }));
    let chain = Chain::new(Arc::new(reg), store.clone());

    let verdict = tokio::time::timeout(
        Duration::from_millis(100),
        chain.dispatch(Event::Request(id)),
    )
    .await
    .expect("a passive dispatch must return without parking");

    assert_eq!(verdict, Verdict::Continue);
    assert!(
        matches!(store.get(id), Some(Flow::Http(f)) if matches!(f.intercept, InterceptState::Observed)),
        "a passive flow must stay Observed; the intercept plugin never ran on it"
    );
}

/// Opts in to passive flows and (wrongly) tries to park every request. No
/// first-party plugin does this; it exercises the chain's defensive half of the
/// rule.
struct ObservingInterceptor;

impl Plugin for ObservingInterceptor {
    fn name(&self) -> &str {
        "observing-interceptor"
    }
    fn observes_passive_flows(&self) -> bool {
        true
    }
    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if matches!(ev, Event::Request(_)) {
            ctx.intercept();
        }
        Verdict::Continue
    }
}

/// Spec D4 / AC10, defensive half: even a plugin that observes passive flows
/// cannot park one. The chain drops the parked receiver and returns at once.
#[tokio::test]
async fn opted_in_plugin_cannot_park_a_passive_flow() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(ObservingInterceptor));
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let id = store.insert(http_flow_with(FlowMeta {
        tunnel: Some(TunnelInfo::passthrough(TunnelReason::OutOfScope)),
        ..FlowMeta::default()
    }));
    let chain = Chain::new(Arc::new(reg), store);

    let verdict = tokio::time::timeout(
        Duration::from_millis(100),
        chain.dispatch(Event::Request(id)),
    )
    .await
    .expect("a passive dispatch must return even if an observer tried to park it");

    assert_eq!(verdict, Verdict::Continue);
}
