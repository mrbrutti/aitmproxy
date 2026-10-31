//! `aitm web` `/bus` write deadline (spec `2026-10-30-bus-hardening-design.md`,
//! D3/D4, AC9-AC13 and AC23): a peer that stops reading while the bridge writes is
//! disconnected within the server's write deadline, and a peer that is slow but
//! still reading is not.
//!
//! The contract these tests pin:
//!
//! - an operator that subscribes and then never reads, while 16 MiB of flow
//!   pushes are sent, is disconnected: its subscription is gone (an `Ask`-policy
//!   probe is refused at once for want of an operator) and its stream ends (AC9);
//! - the same for an operator that sends one frame of 16 `test.blob` lines and
//!   never reads, which is the reply send site rather than the push one (AC10);
//! - the same for an agent-token connection (AC11);
//! - control: with the default 30 s deadline the same stopped operator is still
//!   subscribed 3 s later, so the bound in AC9 is the configured deadline and not
//!   something else cutting the connection (AC12);
//! - a reader that sleeps 10 ms between frames against a 1 s deadline is not
//!   disconnected (AC13);
//! - before authentication, a peer that pings without reading and then sends a bad
//!   token is dropped when the refusal's own 5 s bound expires, and is never sent
//!   the refusal or a Close frame, even once it resumes reading (AC23). That one
//!   exercises the refusal's call site in `relay`, which the in-memory tests in
//!   `bridge.rs` do not reach.
//!
//! A "stopped" client is one that never polls its socket after setup. To make the
//! kernel buffers small, its socket gets a 4096-byte `SO_RCVBUF` before it
//! connects and the server's listener gets a 4096-byte `SO_SNDBUF` before it
//! listens (D4); both are belt and braces, since even loopback autotuning holds
//! well under the 16 MiB these tests push. Assertions never read byte counts from
//! the kernel. Disconnect is seen through the registry (the `Ask` probe) and
//! through the socket (the stream ends once the test resumes reading). Timing
//! comes from margins, not tuning: the registry must flip within 1 s + 5 s of a
//! 1 s deadline, the control is checked at 3 s against 30 s, the slow reader
//! pauses 10 ms per frame against 1 s, and the unauthenticated pinger is given
//! its 5 s refusal bound plus 2 s before it reads again.
//!
//! Hermetic: loopback only; `test.blob` and `test.sensitive` are in-process
//! commands from the shared harness.

// The `/bus` harness shared with the other `web_bus_*` suites.
#[path = "support/web_bus.rs"]
#[allow(dead_code)] // this suite uses a subset of the shared harness
mod web_bus;

use std::time::Duration;

use aitm_core::{AgentPolicy, Event};
use futures::SinkExt as _;
use tokio::net::TcpSocket;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tokio_tungstenite::{client_async, MaybeTlsStream};
use web_bus::{
    assert_refused_without_operator, authenticate, call_line, drain_until_end, http_flow,
    next_frame, probe_ask_gate, push_flow, recv_until, send_text, start, stream_ends_within,
    subscribe, Probe, Server, ServerOptions, TestCommands, Ws, AGENT_TOKEN, APPROVAL_TIMEOUT, FAST,
    NO_OPERATOR, OPERATOR_TOKEN, PARKED_TIMED_OUT, SETTLE, TIMEOUT,
};

/// The write deadline every test but the control gives the server.
const TEST_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
/// Flow events a stopped peer is sent: with [`PATH_BYTES`] each, 16 MiB, which is
/// exactly the default sink capacity (4096 lines), so the bridge really attempts
/// every byte and nothing is dropped on the way.
const PUSHES: usize = 4096;
/// The length of the path each pushed flow carries, so each push line is a bit
/// over 4 KiB.
const PATH_BYTES: usize = 4096;
/// `SO_RCVBUF` of the stopped client, set before it connects.
const CLIENT_RECV_BUFFER: u32 = 4096;
/// `SO_SNDBUF` of the server's listener, set before it listens.
const SERVER_SEND_BUFFER: u32 = 4096;
/// How many `test.blob` lines the reply-site frame carries: 16 replies of a little
/// over 2 MiB each (the 1 MiB blob is in `structuredContent` and in the rendered
/// `content` text, neither truncated), well over 16 MiB and under the bridge's
/// 256-line frame cap.
const BLOB_LINES: u64 = 16;
/// How long the control waits after the pump before it looks at the registry.
const CONTROL_WAIT: Duration = Duration::from_secs(3);
/// How long the bridge gives the refusal of a bad token (its `CLOSE_DRAIN_TIMEOUT`,
/// private to `src/web/bridge.rs`). Keep it equal to that. If the bridge's bound
/// ever grows past this plus [`REFUSAL_MARGIN`] the AC23 test goes red, not green.
const REFUSAL_DEADLINE: Duration = Duration::from_secs(5);
/// How much longer than [`REFUSAL_DEADLINE`] the unauthenticated pinger waits
/// before it reads again, so the server has certainly given up.
const REFUSAL_MARGIN: Duration = Duration::from_secs(2);
/// The payload of each Ping: 125 bytes, the most a control frame may carry.
const PING_PAYLOAD_BYTES: usize = 125;
/// The size of the Pong the server answers a Ping with: a 2-byte header (server
/// frames are unmasked, and 125 fits the short length form) plus the echoed payload.
const PONG_FRAME_BYTES: usize = 2 + PING_PAYLOAD_BYTES;
/// How much Pong data the flood makes the server queue: 20 MiB, the same order of
/// margin as the 16 MiB of the other tests. The kernel path of a 4096-byte
/// `SO_SNDBUF` and `SO_RCVBUF` holds a tiny fraction of it, and even a kernel that
/// ignored both and autotuned would hold well under it on loopback.
const PONG_VOLUME: usize = 20 << 20;
/// How many Pings that is (165,130).
const PINGS: usize = PONG_VOLUME / PONG_FRAME_BYTES;
/// How long sending the Pings and the bad-token frame may take. It must stay well
/// inside the bridge's 10 s `HANDSHAKE_TIMEOUT`, which runs from the upgrade: a
/// token that arrives later is met by the authentication timeout, a different
/// bounded path, and the test would then prove nothing about the refusal.
const FLOOD_BOUND: Duration = Duration::from_secs(6);
/// A token that is neither of the bridge's (they are `d` and `e` repeated).
const BAD_TOKEN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A server the tests below stop a client against: the `Ask` policy (so the probe
/// can tell a connected operator from none), a 1 s write deadline and a 4 KiB send
/// buffer on the listener.
fn stopped_options() -> ServerOptions {
    ServerOptions {
        policy: AgentPolicy::Ask,
        write_timeout: Some(TEST_WRITE_TIMEOUT),
        send_buffer: Some(SERVER_SEND_BUFFER),
        ..ServerOptions::default()
    }
}

/// Connect to the bus and complete the websocket upgrade, but do not authenticate,
/// over a client socket whose receive buffer is [`CLIENT_RECV_BUFFER`] bytes, set
/// before `connect` (bus-hardening spec D4), so a test that then stops reading
/// fills the kernel buffers after a few KiB. The socket is upgraded with
/// `client_async`, which yields the same [`Ws`] the shared helpers take.
async fn connect_stopped(server: &Server) -> Ws {
    let socket = TcpSocket::new_v4().expect("client socket");
    socket
        .set_recv_buffer_size(CLIENT_RECV_BUFFER)
        .expect("client receive buffer size");
    let stream = tokio::time::timeout(TIMEOUT, socket.connect(server.addr))
        .await
        .expect("connect within the timeout")
        .expect("connect");
    let request = format!("ws://{}/bus", server.addr)
        .into_client_request()
        .expect("client request");
    let (ws, _) = tokio::time::timeout(
        TIMEOUT,
        client_async(request, MaybeTlsStream::Plain(stream)),
    )
    .await
    .expect("handshake within the timeout")
    .expect("handshake");
    ws
}

/// Open the bus as `token` like `web_bus::open_bus`, but over the small-buffer
/// socket of [`connect_stopped`].
async fn open_stopped(server: &Server, token: &str, role: &str) -> Ws {
    authenticate(connect_stopped(server).await, token, role).await
}

/// Push `count` flow events of a `PATH_BYTES` path straight into the server's
/// fan-out, yielding now and then so the bridge task drains while the burst runs.
async fn pump(server: &Server, count: usize) {
    let big_path = format!("/{}", "x".repeat(PATH_BYTES));
    let big = server.store.insert(http_flow("example.com:443", &big_path));
    for i in 0..count {
        server.mcp.push_flow_event(&Event::RequestHeaders(big));
        if i % 64 == 63 {
            tokio::task::yield_now().await;
        }
    }
}

/// Probe the `Ask` gate until it is refused for want of an operator, which is when
/// the bridge has dropped the operator's subscription. While one is still
/// subscribed a probe parks for the approval timeout and is refused with the parked
/// reason, so each round costs at most that. Panics, with the last reason, when
/// `bound` passes first.
async fn wait_until_no_operator(server: &Server, bound: Duration) -> Probe {
    let deadline = Instant::now() + bound;
    loop {
        let probe = probe_ask_gate(&server.mcp).await;
        if probe.text.contains(NO_OPERATOR) {
            return probe;
        }
        assert!(
            Instant::now() < deadline,
            "an operator that stopped reading was still subscribed after {bound:?}; \
             the last probe was refused with: {}",
            probe.text
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Bus-hardening AC9 (the push send site): an operator that subscribes and then
/// never reads while 16 MiB of flow pushes are sent is disconnected by the write
/// deadline. The probe flips to "no operator" within the deadline plus 5 s of the
/// pump, then the client's stream ends once it resumes reading.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_operator_is_disconnected_by_the_write_deadline() {
    let commands = TestCommands::new();
    let server = start("stopped-operator", &commands, stopped_options()).await;
    let mut ws = open_stopped(&server, OPERATOR_TOKEN, "operator").await;
    subscribe(&mut ws).await;

    // From here the client never polls its socket until the checks below.
    pump(&server, PUSHES).await;

    let probe = wait_until_no_operator(&server, TEST_WRITE_TIMEOUT + FAST).await;
    assert_refused_without_operator(&probe);
    assert!(
        stream_ends_within(&mut ws, FAST).await,
        "the server must have dropped the stopped operator's connection, so its stream ends"
    );
    assert_eq!(commands.sensitive_runs(), 0, "no probe ever ran");
}

/// Bus-hardening AC10 (the reply send site): an operator that subscribes, sends
/// one frame of [`BLOB_LINES`] `test.blob` lines and never reads is disconnected
/// the same way. No push is involved; the replies, each over 2 MiB, are what the
/// bridge cannot get onto the socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_reader_of_large_replies_is_disconnected_by_the_write_deadline() {
    let commands = TestCommands::new();
    let server = start("stopped-replies", &commands, stopped_options()).await;
    let mut ws = open_stopped(&server, OPERATOR_TOKEN, "operator").await;
    subscribe(&mut ws).await;

    let frame: String = (0..BLOB_LINES)
        .map(|i| format!("{}\n", call_line(100 + i, "test.blob")))
        .collect();
    send_text(&mut ws, frame).await;
    // From here the client never polls its socket until the checks below.

    let probe = wait_until_no_operator(&server, TEST_WRITE_TIMEOUT + FAST).await;
    assert_refused_without_operator(&probe);
    assert!(
        stream_ends_within(&mut ws, FAST).await,
        "the server must have dropped the connection of an operator that stopped \
         reading its replies, so its stream ends"
    );
    assert_eq!(commands.sensitive_runs(), 0, "no probe ever ran");
}

/// Bus-hardening AC11: an agent-token connection that subscribes and never reads
/// has its stream end within the same bound. An agent does not pin
/// `any_role(Operator)`, so the socket is the observation: the test waits out the
/// deadline plus a second without reading, so the server has certainly given up,
/// then resumes reading.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_agent_is_disconnected_by_the_write_deadline() {
    let commands = TestCommands::new();
    let server = start("stopped-agent", &commands, stopped_options()).await;
    let mut ws = open_stopped(&server, AGENT_TOKEN, "agent").await;
    subscribe(&mut ws).await;

    pump(&server, PUSHES).await;
    tokio::time::sleep(TEST_WRITE_TIMEOUT + Duration::from_secs(1)).await;

    assert!(
        stream_ends_within(&mut ws, TEST_WRITE_TIMEOUT + FAST).await,
        "the server must have dropped the stopped agent's connection, so its stream \
         ends once the client resumes reading"
    );
}

/// Bus-hardening AC12, the control: the same stopped operator on a server with the
/// default 30 s deadline is still subscribed 3 s after the pump, so the 1 s bound
/// in AC9 is the configured deadline. The `Ask` probe parks (it is still pending
/// after `SETTLE`) and is refused with the parked reason, not the no-operator one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_operator_is_still_connected_before_the_default_deadline() {
    let commands = TestCommands::new();
    let server = start(
        "stopped-control",
        &commands,
        ServerOptions {
            write_timeout: None,
            ..stopped_options()
        },
    )
    .await;
    let mut ws = open_stopped(&server, OPERATOR_TOKEN, "operator").await;
    subscribe(&mut ws).await;

    pump(&server, PUSHES).await;
    tokio::time::sleep(CONTROL_WAIT).await;

    let mut parked = Box::pin(probe_ask_gate(&server.mcp));
    assert!(
        tokio::time::timeout(SETTLE, &mut parked).await.is_err(),
        "the probe must park while the stopped operator is still subscribed, but it returned at once"
    );
    let probe = parked.await;
    assert!(
        probe.text.contains(PARKED_TIMED_OUT),
        "the probe must have parked and timed out, not been refused for want of an operator, got: {}",
        probe.text
    );
    assert!(
        probe.elapsed >= APPROVAL_TIMEOUT / 2,
        "a parked probe waits out the approval timeout; took {:?}",
        probe.elapsed
    );
    assert_eq!(commands.sensitive_runs(), 0, "no probe ever ran");
    drop(ws);
}

/// Bus-hardening AC13: a reader that sleeps 10 ms between frames, against a 1 s
/// deadline and a 16-line sink, is not disconnected. Pushes outrun it, so the sink
/// laps and the reader is told it lagged, but every send finds room within the
/// deadline: the final distinctive event arrives and a later `flow.list` call is
/// answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_but_live_reader_is_not_disconnected() {
    const CAPACITY: usize = 16;
    const BURST: usize = 1024;
    const PAUSE: Duration = Duration::from_millis(10);
    const LIST_ID: u64 = 7;
    let commands = TestCommands::new();
    let server = start(
        "slow-reader",
        &commands,
        ServerOptions {
            push_capacity: Some(CAPACITY),
            ..stopped_options()
        },
    )
    .await;
    let mut ws = open_stopped(&server, AGENT_TOKEN, "agent").await;
    subscribe(&mut ws).await;

    pump(&server, BURST).await;
    let final_id = push_flow(&server, "/final");

    let deadline = Instant::now() + TIMEOUT;
    let mut frames = 0usize;
    loop {
        let frame = match tokio::time::timeout_at(deadline, next_frame(&mut ws)).await {
            Ok(Some(frame)) => frame,
            Ok(None) => panic!(
                "the stream ended after {frames} frames, before the final event: \
                 a reader that is slow but live must not be disconnected"
            ),
            Err(_) => panic!("the final event did not arrive within {TIMEOUT:?}; {frames} frames"),
        };
        frames += 1;
        if frame["method"] == "notifications/aitm/flow"
            && frame["params"]["id"] == final_id.to_string()
        {
            assert_eq!(frame["params"]["summary"]["path"], "/final", "{frame}");
            break;
        }
        tokio::time::sleep(PAUSE).await;
    }

    send_text(&mut ws, call_line(LIST_ID, "flow.list")).await;
    let reply = recv_until(&mut ws, "the flow.list reply", |v| v["id"] == LIST_ID).await;
    assert_eq!(
        reply["result"]["isError"], false,
        "the connection must still answer calls after the slow read: {reply}"
    );
}

/// Bus-hardening AC23, the pre-auth refusal's call site: an unauthenticated peer
/// that floods 125-byte Pings without ever reading, then sends a bad token, is
/// dropped when the refusal's own bound ([`REFUSAL_DEADLINE`], 5 s) expires. It is
/// never sent the refusal or a Close frame, even if it reads again afterwards.
///
/// tungstenite answers every Ping with a Pong, queues the Pongs without limit once
/// the socket is full, and keeps reading while it cannot write. So [`PINGS`] Pings
/// from a client with a 4096-byte receive buffer, against a listener with a
/// 4096-byte send buffer, leave about 20 MiB of Pongs queued in the server and the
/// kernel path full, while the bad-token frame behind them is still read. The
/// refusal send then has nowhere to go: bounded, it fails at 5 s and the bridge
/// drops the connection; unbounded (`ws.send(UNAUTHORIZED_REPLY)`, as the call site
/// was before this change) it parks until the client drains and then delivers.
///
/// The assertion is on content, not on the stream ending: once the path drains the
/// stream ends either way, a dropped connection after its buffered Pongs and a
/// refused one after the refusal and a Close. So after [`REFUSAL_DEADLINE`] plus
/// [`REFUSAL_MARGIN`] the client reads again and requires that the stream ends and
/// that no text frame mentions `unauthorized` and no Close frame arrived. A path
/// that was not actually full would deliver the refusal and fail this too, so a
/// kernel with larger buffers than assumed makes the test red rather than
/// vacuously green.
///
/// The server keeps the default 30 s write deadline, not the 1 s of the other
/// tests, so that only the 5 s refusal bound can drop the peer inside the wait: a
/// refusal sent under the post-authentication deadline would fail here.
///
/// Takes about 7 s plus the flood, which is a second or two (the in-memory
/// equivalent measured half a second in a debug build).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unauthenticated_pinging_peer_is_dropped_at_the_refusal_deadline() {
    let commands = TestCommands::new();
    let server = start(
        "preauth-pinging",
        &commands,
        ServerOptions {
            write_timeout: None,
            ..stopped_options()
        },
    )
    .await;
    let mut ws = connect_stopped(&server).await;

    let payload = Bytes::from(vec![b'p'; PING_PAYLOAD_BYTES]);
    tokio::time::timeout(FLOOD_BOUND, async {
        for _ in 0..PINGS {
            ws.feed(Message::Ping(payload.clone()))
                .await
                .expect("send a ping");
        }
        ws.flush().await.expect("flush the pings");
        send_text(&mut ws, format!(r#"{{"token":"{BAD_TOKEN}"}}"#)).await;
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "sending {PINGS} pings and the bad token took more than {FLOOD_BOUND:?}; the \
             bridge's 10 s authentication window may have expired, so this run could not \
             tell the refusal's bound from the authentication timeout"
        )
    });
    // From here the client never polls its socket until the checks below.

    tokio::time::sleep(REFUSAL_DEADLINE + REFUSAL_MARGIN).await;

    let drained = drain_until_end(&mut ws, TIMEOUT).await;
    let refusals: Vec<&String> = drained
        .replies
        .iter()
        .filter(|reply| reply.contains("unauthorized"))
        .collect();
    assert!(
        refusals.is_empty() && !drained.saw_close,
        "the bridge gave up on the pinging peer at the refusal deadline, so once the peer \
         reads again it must be sent neither the refusal nor a Close; got refusals \
         {refusals:?}, close frame seen: {} (code {:?})",
        drained.saw_close,
        drained.close_code
    );
    assert!(
        drained.ended,
        "the stream of a peer dropped at the refusal deadline must end once it reads \
         again, but it was still open after {TIMEOUT:?}"
    );
}
