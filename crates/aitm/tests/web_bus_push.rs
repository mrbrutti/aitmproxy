//! `aitm web` `/bus` push: `flow.subscribe` over the bridge, and the
//! `notifications/aitm/{flow,state,agent}` lines that follow it on the same
//! socket (spec `2026-10-30-web-bus-push-design.md`, AC1-AC6).
//!
//! The contract these tests pin:
//!
//! - a bridge connection that subscribes receives flow pushes whose `params.id`
//!   is the stored flow's id (AC1), including through the real broadcast
//!   dispatcher `main.rs` relies on (AC1/AC9);
//! - replies keep arriving, in line order within a frame, while pushes flow, and
//!   a parked command does not hold pushes back (AC2);
//! - pushes keep flowing while the read side is paused at the in-flight cap (D3);
//! - a connection's subscriptions end with it: on a Close (AC3), on a refusal
//!   before the close handshake (D4), and when a frame still running at
//!   disconnect subscribes afterwards (AC4);
//! - `flow.unsubscribe` in a later frame stops the pushes, since one `ConnCtx`
//!   lives for the whole connection;
//! - a subscriber that stops reading is bounded: it lags, is told so, and still
//!   gets the newest event when it resumes (AC5);
//! - an agent-role connection never receives operator-only notifications (AC6).
//!
//! Hermetic: loopback only; the in-process test commands (`test.block`,
//! `test.tick`, `test.sensitive`) are registered through the scripting wiring's
//! command-provider slot; `flow.subscribe`, `flow.list` and `agent.approve` are
//! the real ones. The `McpServer` is shared with the test so it can push events
//! and probe the agent policy gate directly.

// The `/bus` harness shared with `web_bus_concurrency` and `web_bus_roles`.
#[path = "support/web_bus.rs"]
#[allow(dead_code)] // this suite uses a subset of the shared harness
mod web_bus;

use aitm::web::bridge::MAX_IN_FLIGHT;
use aitm_core::{AgentPolicy, Event};
use futures::SinkExt as _;
use serde_json::json;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use web_bus::{
    assert_refused_without_operator, call_line, call_line_with, drain_for, http_flow, next_frame,
    open_agent, open_operator, probe_ask_gate, push_flow, recv_until, recv_until_collecting,
    recv_within, send_text, start, stream_ends_within, subscribe, wait_until, ServerOptions,
    TestCommands, APPROVAL_TIMEOUT, FAST, PARKED_TIMED_OUT, QUIET, SETTLE, TIMEOUT,
};

/// AC1: a bridge connection that subscribes gets `{sub_id}`, and a flow push for
/// a stored flow arrives on that socket with the flow's id.
#[tokio::test]
async fn subscribe_over_bus_then_a_flow_push_arrives() {
    let commands = TestCommands::new();
    let server = start("subscribe", &commands, ServerOptions::default()).await;
    let mut ws = open_agent(&server).await;

    let sub_id = subscribe(&mut ws).await;
    assert_eq!(sub_id, 1, "the first subscription on a fresh server");

    let id = push_flow(&server, "/pushed");
    let note = recv_until(&mut ws, "a notifications/aitm/flow frame", |v| {
        v["method"] == "notifications/aitm/flow"
    })
    .await;
    assert_eq!(note["params"]["id"], id.to_string(), "{note}");
    assert_eq!(note["params"]["event"], "created", "{note}");
    assert_eq!(
        note["params"]["summary"]["authority"], "example.com:443",
        "{note}"
    );
    assert_eq!(note["params"]["summary"]["path"], "/pushed", "{note}");
}

/// AC1/AC9 at the wiring level: a server built `.with_push(tx)` whose
/// `spawn_push_dispatcher()` was called delivers a broadcast `Event` to a bridge
/// subscriber. This is the contract `main.rs` relies on for the web server.
#[tokio::test]
async fn pushes_flow_through_the_real_broadcast_dispatcher() {
    let commands = TestCommands::new();
    let server = start(
        "dispatcher",
        &commands,
        ServerOptions {
            dispatcher: true,
            ..ServerOptions::default()
        },
    )
    .await;
    let mut ws = open_agent(&server).await;
    subscribe(&mut ws).await;

    let id = server
        .store
        .insert(http_flow("example.com:443", "/broadcast"));
    server
        .push_tx
        .send(Event::Response(id))
        .unwrap_or_else(|_| panic!("the dispatcher must hold a receiver on the broadcast"));

    let note = recv_until(
        &mut ws,
        "the dispatched notifications/aitm/flow frame",
        |v| v["method"] == "notifications/aitm/flow",
    )
    .await;
    assert_eq!(note["params"]["id"], id.to_string(), "{note}");
    assert_eq!(note["params"]["event"], "response", "{note}");
    assert_eq!(note["params"]["summary"]["path"], "/broadcast", "{note}");
}

/// AC2: pushes arrive while a frame's command is parked (they do not wait behind
/// it), and the frame's replies still come back in line order, none lost, while
/// more pushes flow; every push below the sink capacity arrives, once, in order.
#[tokio::test]
async fn replies_stay_in_order_while_pushes_flow() {
    const TICKS: u64 = 40;
    const PARKED_PUSHES: usize = 5;
    const LIVE_PUSHES: usize = 200;
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("interleave", &commands, ServerOptions::default()).await;
    let mut ws = open_agent(&server).await;
    subscribe(&mut ws).await;

    // One frame: a parked line first, then the ticks, then flow.list. Its replies
    // are held until the whole frame is done, so until the release only pushes
    // can reach the socket.
    let first_id = 10;
    let last_id = first_id + TICKS + 1;
    let frame = std::iter::once(call_line(first_id, "test.block"))
        .chain((1..=TICKS).map(|i| call_line(first_id + i, "test.tick")))
        .chain(std::iter::once(call_line(last_id, "flow.list")))
        .collect::<Vec<_>>()
        .join("\n");
    send_text(&mut ws, frame).await;
    wait_until("test.block to start", || commands.parking.entered() == 1).await;

    let parked_ids: Vec<String> = (0..PARKED_PUSHES)
        .map(|i| push_flow(&server, &format!("/parked/{i}")).to_string())
        .collect();
    for expected in &parked_ids {
        let frame = recv_within(
            &mut ws,
            FAST,
            "a push while the frame's test.block is still parked",
        )
        .await;
        assert_eq!(
            frame["method"], "notifications/aitm/flow",
            "while the frame is parked only a push can arrive: {frame}"
        );
        assert_eq!(
            frame["params"]["id"], *expected,
            "pushes arrive in push order: {frame}"
        );
    }

    // Release the frame and keep pushing from a task while its replies come back.
    release.release();
    let pusher = {
        let mcp = server.mcp.clone();
        let store = server.store.clone();
        tokio::spawn(async move {
            let mut ids = Vec::with_capacity(LIVE_PUSHES);
            for i in 0..LIVE_PUSHES {
                let id = store.insert(http_flow("example.com:443", &format!("/live/{i}")));
                mcp.push_flow_event(&Event::RequestHeaders(id));
                ids.push(id.to_string());
                if i % 8 == 7 {
                    tokio::task::yield_now().await;
                }
            }
            ids
        })
    };

    let want_replies = usize::try_from(TICKS).expect("small") + 2;
    let mut replies: Vec<u64> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let deadline = Instant::now() + TIMEOUT;
    while replies.len() < want_replies || notes.len() < LIVE_PUSHES {
        let frame = match tokio::time::timeout_at(deadline, next_frame(&mut ws)).await {
            Ok(Some(frame)) => frame,
            Ok(None) => panic!(
                "the stream ended with {replies:?} replies and {} pushes",
                notes.len()
            ),
            Err(_) => panic!(
                "timed out with {} of {want_replies} replies and {} of {LIVE_PUSHES} pushes",
                replies.len(),
                notes.len()
            ),
        };
        if let Some(id) = frame["id"].as_u64() {
            assert_eq!(frame["result"]["isError"], false, "{frame}");
            replies.push(id);
        } else if frame["method"] == "notifications/aitm/flow" {
            notes.push(
                frame["params"]["id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            );
        } else if frame["method"] == "notifications/aitm/agent" {
            // Every finished tool call is audited and fanned to all subscribers, so
            // this frame's own commands show up on the stream; nothing else may.
            let command = frame["params"]["command"].as_str().unwrap_or_default();
            assert!(
                matches!(command, "test.block" | "test.tick" | "flow.list"),
                "an agent-stream line that is not this frame's own audit: {frame}"
            );
        } else {
            panic!("unexpected frame: {frame}");
        }
    }
    assert_eq!(
        replies,
        (first_id..=last_id).collect::<Vec<_>>(),
        "the frame's replies arrive in line order, each exactly once"
    );
    assert_eq!(commands.ticks(), usize::try_from(TICKS).expect("small"));
    let live_ids = pusher.await.expect("the pusher task");
    assert_eq!(
        notes, live_ids,
        "every push below the sink capacity arrives once, in push order"
    );
}

/// AC3: when the client closes, its subscriptions go with it. With the operator
/// subscribed, an `Ask`-policy Sensitive agent call parks (the control); once that
/// operator has closed, the same call is refused at once for want of an operator.
#[tokio::test]
async fn disconnect_drops_the_subscription() {
    let commands = TestCommands::new();
    let server = start(
        "disconnect",
        &commands,
        ServerOptions {
            policy: AgentPolicy::Ask,
            ..ServerOptions::default()
        },
    )
    .await;
    let mut operator = open_operator(&server).await;
    subscribe(&mut operator).await;

    // Control: with the operator subscribed the probe parks. It is still pending
    // after a short wait, and is refused only when the approval timeout expires.
    let mut parked = Box::pin(probe_ask_gate(&server.mcp));
    assert!(
        tokio::time::timeout(SETTLE, &mut parked).await.is_err(),
        "the control probe must park while the operator is subscribed, but it returned at once"
    );
    let probe = parked.await;
    assert!(
        probe.text.contains(PARKED_TIMED_OUT),
        "the control probe must have parked and timed out, got: {}",
        probe.text
    );
    assert!(
        probe.elapsed >= APPROVAL_TIMEOUT / 2,
        "a parked probe waits out the approval timeout; took {:?}",
        probe.elapsed
    );
    let request = recv_until(&mut operator, "the approval request", |v| {
        v["method"] == "notifications/aitm/agent"
    })
    .await;
    assert_eq!(
        request["params"]["event"], "approval_requested",
        "{request}"
    );
    assert_eq!(request["params"]["command"], "test.sensitive", "{request}");

    // The operator closes; the stream ends; its subscription is gone.
    operator.close(None).await.expect("client close");
    assert!(
        stream_ends_within(&mut operator, FAST).await,
        "the server must end the stream after the client's Close"
    );
    tokio::time::sleep(SETTLE).await;
    let probe = probe_ask_gate(&server.mcp).await;
    assert_refused_without_operator(&probe);
    assert_eq!(commands.sensitive_runs(), 0, "no probe ever ran");
}

/// AC4 (the late-subscribe race): a frame `[test.block, flow.subscribe,
/// test.tick]` is still running when its operator connection drops. One probe
/// proves the teardown ran before the frame is released; after the release the
/// tick proves the late `flow.subscribe` has returned, and a second probe shows
/// it registered nothing (the `Ask`-policy call is refused at once, not parked).
#[tokio::test]
async fn a_frame_still_running_at_disconnect_cannot_resubscribe() {
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start(
        "late-subscribe",
        &commands,
        ServerOptions {
            policy: AgentPolicy::Ask,
            ..ServerOptions::default()
        },
    )
    .await;
    let mut operator = open_operator(&server).await;
    // Subscriptions work on this bridge, so a missing one below means teardown.
    subscribe(&mut operator).await;

    // One frame: the parked line, the late subscribe, then a tick. Lines in a
    // frame run in order, so the tick is proof that the subscribe has returned.
    send_text(
        &mut operator,
        format!(
            "{}\n{}\n{}",
            call_line(10, "test.block"),
            call_line(11, "flow.subscribe"),
            call_line(12, "test.tick")
        ),
    )
    .await;
    wait_until("test.block to start", || commands.parking.entered() == 1).await;

    // The client vanishes while the frame is parked. One frame is in flight,
    // below the cap, so the bridge is reading and sees the drop at once.
    drop(operator);
    tokio::time::sleep(SETTLE).await;
    // The teardown has already run: the subscription made above is gone. So the
    // `flow.subscribe` released below really runs after it, against the closed
    // sink, rather than before a slow teardown that would then sweep it.
    assert_refused_without_operator(&probe_ask_gate(&server.mcp).await);

    // The detached frame finishes: test.block returns, flow.subscribe runs
    // against the torn-down connection, and the tick after it shows the
    // subscribe has certainly run before the probe below.
    release.release();
    wait_until("the detached frame to run its test.tick", || {
        commands.ticks() == 1
    })
    .await;

    assert_refused_without_operator(&probe_ask_gate(&server.mcp).await);
    assert_eq!(commands.sensitive_runs(), 0, "no probe ever ran");
}

/// AC5: a subscriber that stops reading while far more than `push_capacity` large
/// events are pushed is not sent them all. When it resumes it receives fewer
/// lines than were pushed, a `notifications/aitm/state {lagged:true}` marker,
/// and the newest event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_reading_subscriber_is_bounded_and_lags() {
    const CAPACITY: usize = 16;
    const PUSHES: usize = 5000;
    let commands = TestCommands::new();
    let server = start(
        "lag",
        &commands,
        ServerOptions {
            push_capacity: Some(CAPACITY),
            ..ServerOptions::default()
        },
    )
    .await;
    let mut ws = open_agent(&server).await;
    subscribe(&mut ws).await;

    // Each notification carries this ~4 KiB path, so the burst is some 20 MiB:
    // more than the loopback socket buffers absorb while the client is not
    // reading, so the bridge's send really does block and the sink overflows.
    let big_path = format!("/{}", "x".repeat(4096));
    let big = server.store.insert(http_flow("example.com:443", &big_path));
    for i in 0..PUSHES {
        server.mcp.push_flow_event(&Event::RequestHeaders(big));
        if i % 64 == 63 {
            tokio::task::yield_now().await;
        }
    }
    let final_id = push_flow(&server, "/final");

    // Resume reading until the final event arrives, counting what came.
    let deadline = Instant::now() + TIMEOUT;
    let mut flows = 0usize;
    let mut lagged = false;
    loop {
        let frame = match tokio::time::timeout_at(deadline, next_frame(&mut ws)).await {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                panic!("the stream ended after {flows} flow frames, before the final event")
            }
            Err(_) => {
                panic!("the final event did not arrive; {flows} flow frames, lagged seen: {lagged}")
            }
        };
        match frame["method"].as_str() {
            Some("notifications/aitm/flow") => {
                flows += 1;
                if frame["params"]["id"] == final_id.to_string() {
                    assert_eq!(frame["params"]["summary"]["path"], "/final", "{frame}");
                    break;
                }
            }
            Some("notifications/aitm/state") if frame["params"]["lagged"] == true => {
                lagged = true;
            }
            _ => panic!("unexpected frame during the burst: {frame}"),
        }
    }
    assert!(
        flows <= PUSHES,
        "a subscriber that was not reading must not be sent every event: {flows} of {} arrived",
        PUSHES + 1
    );
    assert!(
        lagged,
        "a lagged state marker must tell the subscriber it missed events ({flows} of {} arrived)",
        PUSHES + 1
    );
}

/// AC6: with an operator and an agent connection both subscribed, a parked
/// `Ask`-policy call produces `approval_requested` on the operator connection
/// only; the agent connection keeps receiving flow pushes but never that line;
/// `agent.approve {allow:false}` from the operator refuses the parked call.
#[tokio::test]
async fn agent_role_never_gets_operator_only_pushes() {
    let commands = TestCommands::new();
    let server = start(
        "roles",
        &commands,
        ServerOptions {
            policy: AgentPolicy::Ask,
            // Long enough for the operator to read the request and answer it.
            approval_timeout: FAST,
            ..ServerOptions::default()
        },
    )
    .await;
    let mut operator = open_operator(&server).await;
    let mut agent = open_agent(&server).await;
    subscribe(&mut operator).await;
    subscribe(&mut agent).await;

    // The agent asks for a Sensitive command; under Ask it parks for the operator.
    send_text(&mut agent, call_line(5, "test.sensitive")).await;
    let request = recv_until(
        &mut operator,
        "the approval request on the operator connection",
        |v| v["method"] == "notifications/aitm/agent",
    )
    .await;
    assert_eq!(
        request["params"]["event"], "approval_requested",
        "{request}"
    );
    assert_eq!(request["params"]["command"], "test.sensitive", "{request}");
    let request_id = request["params"]["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the approval request carries a request_id: {request}"))
        .to_owned();

    // A flow push reaches the agent connection; the approval request never does,
    // and the parked call has no reply yet. The approval request was fanned out
    // before this push (the operator has already read it) and a sink delivers in
    // order, so anything that leaked to the agent connection arrives before its
    // flow push: no quiet wait is needed.
    let id = push_flow(&server, "/both");
    let on_operator = recv_until(
        &mut operator,
        "the flow push on the operator connection",
        |v| v["method"] == "notifications/aitm/flow",
    )
    .await;
    assert_eq!(on_operator["params"]["id"], id.to_string(), "{on_operator}");
    let (on_agent, before_it) =
        recv_until_collecting(&mut agent, "the flow push on the agent connection", |v| {
            v["method"] == "notifications/aitm/flow"
        })
        .await;
    assert_eq!(on_agent["params"]["id"], id.to_string(), "{on_agent}");
    assert!(
        before_it
            .iter()
            .all(|f| f["params"]["event"] != "approval_requested"),
        "the agent connection must never receive the operator-only approval request: {before_it:?}"
    );
    assert!(
        before_it.iter().all(|f| f["id"] != 5),
        "the Sensitive call must still be parked while the operator has not answered: {before_it:?}"
    );

    // The operator denies; the parked call is refused and never ran.
    send_text(
        &mut operator,
        call_line_with(
            6,
            "agent.approve",
            json!({ "request_id": request_id, "allow": false }),
        ),
    )
    .await;
    let approved = recv_until(&mut operator, "the agent.approve reply", |v| v["id"] == 6).await;
    assert_eq!(
        approved["result"]["isError"], false,
        "agent.approve from the operator connection resolves the request: {approved}"
    );
    let done = recv_until(&mut agent, "the parked call's reply", |v| v["id"] == 5).await;
    assert_eq!(
        done["result"]["isError"], true,
        "a denied agent call is refused: {done}"
    );
    let text = done["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("denied"),
        "the refusal names the denial: {text}"
    );
    assert_eq!(commands.sensitive_runs(), 0, "a denied command never ran");
}

/// Spec D3, added by the tester: the drain arm is not gated on the in-flight cap.
/// With `MAX_IN_FLIGHT` frames parked the bridge has stopped reading, yet a push
/// still reaches the subscriber; the parked frames are answered once released.
#[tokio::test]
async fn pushes_flow_while_the_read_branch_is_paused_at_the_cap() {
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("at-cap", &commands, ServerOptions::default()).await;
    let mut ws = open_agent(&server).await;
    subscribe(&mut ws).await;

    // One frame per parked command, exactly the cap: the read branch is now off.
    let cap = u64::try_from(MAX_IN_FLIGHT).expect("small");
    let first_id = 100;
    for id in first_id..first_id + cap {
        send_text(&mut ws, call_line(id, "test.block")).await;
    }
    wait_until("every in-flight frame to park in test.block", || {
        commands.parking.entered() == MAX_IN_FLIGHT
    })
    .await;

    let id = push_flow(&server, "/at-cap");
    let note = recv_within(&mut ws, FAST, "a push while the bridge is at the cap").await;
    assert_eq!(
        note["method"], "notifications/aitm/flow",
        "while every frame is parked only a push can arrive: {note}"
    );
    assert_eq!(note["params"]["id"], id.to_string(), "{note}");

    release.release();
    let mut replies = Vec::new();
    while replies.len() < MAX_IN_FLIGHT {
        let reply = recv_until(&mut ws, "a released test.block reply", |v| v["id"].is_u64()).await;
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        replies.push(reply["id"].as_u64().unwrap_or_default());
    }
    replies.sort_unstable();
    assert_eq!(
        replies,
        (first_id..first_id + cap).collect::<Vec<_>>(),
        "every parked frame is answered exactly once"
    );
}

/// Spec Intent ("exactly as over loopback TCP"), added by the tester: the
/// connection's one `ConnCtx` spans frames, so a `flow.unsubscribe` sent in a later
/// frame removes the subscription an earlier frame made, and pushes stop.
#[tokio::test]
async fn unsubscribe_in_a_later_frame_stops_pushes() {
    let commands = TestCommands::new();
    let server = start("unsubscribe", &commands, ServerOptions::default()).await;
    let mut ws = open_agent(&server).await;
    let sub_id = subscribe(&mut ws).await;

    // Control: while subscribed, a push arrives.
    let before = push_flow(&server, "/before");
    let note = recv_until(&mut ws, "the push before unsubscribing", |v| {
        v["method"] == "notifications/aitm/flow"
    })
    .await;
    assert_eq!(note["params"]["id"], before.to_string(), "{note}");

    send_text(
        &mut ws,
        call_line_with(2, "flow.unsubscribe", json!({ "sub_id": sub_id })),
    )
    .await;
    let reply = recv_until(&mut ws, "the flow.unsubscribe reply", |v| v["id"] == 2).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");

    push_flow(&server, "/after");
    let after = drain_for(&mut ws, QUIET).await;
    assert!(
        after
            .iter()
            .all(|f| f["method"] != "notifications/aitm/flow"),
        "no flow push reaches a connection that unsubscribed: {after:?}"
    );
}

/// Spec D4's refusal exit path, added by the tester: a post-auth refusal drops the
/// connection's subscriptions before its close handshake (`refuse` drops the guard
/// first), so a peer that never answers our Close is not counted as a subscribed
/// operator for the drain budget. The client reads the server's Close and then
/// stops reading, so its answer is never flushed and the server is still inside
/// the handshake when the probe runs; the probe must be refused at once anyway.
#[tokio::test]
async fn a_refused_connection_is_unsubscribed_before_the_close_handshake() {
    let commands = TestCommands::new();
    let server = start(
        "refused",
        &commands,
        ServerOptions {
            policy: AgentPolicy::Ask,
            ..ServerOptions::default()
        },
    )
    .await;
    let mut operator = open_operator(&server).await;
    subscribe(&mut operator).await;

    // A binary frame after auth is refused (`Unsupported`).
    operator
        .send(Message::binary(vec![0u8; 4]))
        .await
        .expect("send");
    assert!(
        stream_ends_within(&mut operator, FAST).await,
        "the server must refuse a binary frame by closing"
    );
    let probe = probe_ask_gate(&server.mcp).await;
    assert_refused_without_operator(&probe);
    assert_eq!(commands.sensitive_runs(), 0, "no probe ever ran");
}
