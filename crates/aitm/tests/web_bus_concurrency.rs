//! `aitm web` `/bus` concurrency: a long-running command on one connection must
//! not freeze the rest of that connection. The web UI polls `flow.list` every
//! 500 ms on the same socket as a `scan.discover` that can run for minutes.
//!
//! The contract these tests pin:
//!
//! - frames run **concurrently** — a slow `tools/call` does not delay the reply to a
//!   fast request sent after it on the same socket, including a request that shares
//!   the token's frame;
//! - lines batched in **one** frame run and answer in order (a frame is the unit of
//!   work), and a frame may carry at most 256 lines: a longer one closes the
//!   connection with `Size` before any of its lines runs;
//! - at most `MAX_IN_FLIGHT` frames are in flight per connection; further frames
//!   wait unread (TCP backpressure) and none is lost;
//! - a command that panics ends its own connection only; below the in-flight cap a
//!   client Close is seen while a command is still parked (at the cap the bridge is
//!   not reading, and notices only once a frame finishes), and the parked command
//!   then runs to completion.
//!
//! Hermetic: the commands under test are in-process test commands (`test.block`,
//! `test.sleep`, `test.tick`, `test.panic`) registered through the scripting wiring's
//! command-provider slot; `flow.list` is the real one. No browser, no network
//! beyond loopback.

// The `/bus` harness shared with the other `web_bus_*` suites.
#[path = "support/web_bus.rs"]
#[allow(dead_code)] // this suite uses a subset of the shared harness
mod web_bus;

use aitm::web::bridge::MAX_IN_FLIGHT;
use serde_json::{json, Value as JsonValue};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use web_bus::{
    call_line, drain_until_end, recv_json, send_text, wait_until, ws_connect, Server,
    ServerOptions, TestCommands, Ws, AGENT_TOKEN, FAST, SETTLE,
};

/// The most request lines one frame may carry: the contract figure, the same as
/// `MAX_BATCH_LEN` in the MCP HTTP transport, pinned here as a literal.
const MAX_LINES_PER_FRAME: u64 = 256;

/// A served `aitm web` over the real wired registry plus the test commands, set up
/// for this suite: no operator token, only `test.block`, `test.sleep`, `test.tick`
/// and `test.panic`, and the `McpServer`'s own default gate rather than the wired
/// one the push suite uses.
async fn start(tag: &str, commands: &TestCommands) -> Server {
    web_bus::start(
        tag,
        &commands.without_extras(),
        ServerOptions {
            operator_token: None,
            wired_gate: false,
            ..ServerOptions::default()
        },
    )
    .await
}

/// The token line, as its own frame (the way the web client authenticates).
fn token_line() -> String {
    json!({ "token": AGENT_TOKEN }).to_string()
}

/// One frame of `count` `tools/call` lines for `name` (ids `1..=count`), led by
/// `lead` when given — e.g. the token line, to share the token's frame.
fn call_frame(lead: Option<String>, count: u64, name: &str) -> String {
    lead.into_iter()
        .chain((1..=count).map(|id| call_line(id, name)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Open the bus: connect, send the token, and `initialize`. The `initialize` reply
/// must be the first frame the server sends; the shared `web_bus::open_bus` skips
/// ahead to it and checks the role echo instead, which is a different check.
async fn open_bus(server: &Server) -> Ws {
    let mut ws = ws_connect(server).await;
    send_text(&mut ws, token_line()).await;
    send_text(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "aitm-web", "version": "0"}}})
        .to_string(),
    )
    .await;
    let init = recv_json(&mut ws).await;
    assert_eq!(init["id"], 0, "initialize reply: {init}");
    ws
}

#[tokio::test]
async fn slow_command_does_not_block_the_connection() {
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("slow", &commands).await;
    let mut ws = open_bus(&server).await;

    // id 1 parks inside `test.block`; wait until it really is running there, so
    // id 2 is sent while id 1 is provably still in flight.
    send_text(&mut ws, call_line(1, "test.block")).await;
    wait_until("test.block to start", || commands.parking.entered() == 1).await;
    send_text(&mut ws, call_line(2, "flow.list")).await;

    // The fast request is answered while the slow one is still blocked.
    let fast = tokio::time::timeout(FAST, recv_json(&mut ws))
        .await
        .expect("the flow.list reply must arrive while test.block is still parked");
    assert_eq!(fast["id"], 2, "the first reply is flow.list's: {fast}");
    assert_eq!(fast["result"]["isError"], false, "{fast}");
    assert_eq!(fast["result"]["structuredContent"], json!([]), "{fast}");

    // Release the slow command; its reply then arrives.
    release.release();
    let slow = recv_json(&mut ws).await;
    assert_eq!(slow["id"], 1, "the second reply is test.block's: {slow}");
    assert_eq!(slow["result"]["isError"], false, "{slow}");
    assert_eq!(slow["result"]["structuredContent"], json!("released"));
}

#[tokio::test]
async fn a_request_sharing_the_token_frame_does_not_block_later_frames() {
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("token-frame", &commands).await;
    let mut ws = ws_connect(&server).await;

    // The token line and a request that parks share the first frame; the request
    // is the first frame in flight.
    send_text(
        &mut ws,
        format!("{}\n{}", token_line(), call_line(1, "test.block")),
    )
    .await;
    wait_until("test.block to start", || commands.parking.entered() == 1).await;
    send_text(&mut ws, call_line(2, "flow.list")).await;

    let fast = tokio::time::timeout(FAST, recv_json(&mut ws))
        .await
        .expect("the flow.list reply must arrive while test.block is still parked");
    assert_eq!(fast["id"], 2, "the first reply is flow.list's: {fast}");
    assert_eq!(fast["result"]["structuredContent"], json!([]), "{fast}");

    release.release();
    let slow = recv_json(&mut ws).await;
    assert_eq!(slow["id"], 1, "the second reply is test.block's: {slow}");
    assert_eq!(slow["result"]["structuredContent"], json!("released"));
}

#[tokio::test]
async fn lines_in_one_frame_still_answer_in_order() {
    let commands = TestCommands::new();
    let server = start("order", &commands).await;
    let mut ws = open_bus(&server).await;

    // One frame, a slow line first and a fast line second: the replies must come
    // back slow-then-fast even though the fast line is quicker. A single frame is
    // the unit of work, so its lines run one after another.
    let batch = format!(
        "{}\n{}\n",
        call_line(10, "test.sleep"),
        call_line(11, "flow.list")
    );
    send_text(&mut ws, batch).await;
    // A later frame runs concurrently with the batch, so its reply may arrive
    // before or after the batch's replies.
    send_text(&mut ws, call_line(12, "flow.list")).await;

    let mut replies = Vec::new();
    for _ in 0..3 {
        let reply = recv_json(&mut ws).await;
        let id = reply["id"].as_u64().expect("numeric id");
        replies.push((id, reply["result"]["structuredContent"].clone()));
    }
    let position = |id: u64| {
        replies
            .iter()
            .position(|(i, _)| *i == id)
            .unwrap_or_else(|| panic!("id {id} was never answered, got {replies:?}"))
    };
    assert!(
        position(10) < position(11),
        "the batch's replies must stay in order, got {replies:?}"
    );
    replies.sort_by_key(|(id, _)| *id);
    assert_eq!(
        replies,
        vec![(10, json!("slept")), (11, json!([])), (12, json!([]))],
        "every request answered once, with its own result"
    );
}

#[tokio::test]
async fn at_most_the_cap_run_at_once_and_no_frame_is_lost() {
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("cap", &commands).await;
    let mut ws = open_bus(&server).await;

    // Well over the cap, every frame parked, sent back-to-back without reading.
    const FRAMES: u64 = MAX_IN_FLIGHT as u64 * 2 + 8;
    for id in 1..=FRAMES {
        send_text(&mut ws, call_line(id, "test.block")).await;
    }

    // The cap fills, and then — with more frames queued — does not overflow.
    wait_until("the in-flight cap to fill", || {
        commands.parking.entered() >= MAX_IN_FLIGHT
    })
    .await;
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        commands.parking.entered(),
        MAX_IN_FLIGHT,
        "exactly the cap may run at once while every command is parked"
    );

    // Releasing them lets the queued frames through; each is answered once.
    release.release();
    let mut ids = Vec::new();
    for _ in 0..FRAMES {
        let reply = recv_json(&mut ws).await;
        assert_eq!(reply["result"]["structuredContent"], json!("released"));
        ids.push(reply["id"].as_u64().expect("numeric id"));
    }
    ids.sort_unstable();
    assert_eq!(
        ids,
        (1..=FRAMES).collect::<Vec<_>>(),
        "every frame answered exactly once"
    );
}

#[tokio::test]
async fn a_frame_of_exactly_the_line_cap_is_answered_in_full() {
    let commands = TestCommands::new();
    let server = start("lines-at-cap", &commands).await;
    let mut ws = open_bus(&server).await;

    let frame = call_frame(None, MAX_LINES_PER_FRAME, "flow.list");
    send_text(&mut ws, frame).await;
    expect_answered_in_order(&mut ws, MAX_LINES_PER_FRAME).await;
}

/// Read `count` replies and check each is `flow.list`'s empty result, one text
/// frame per line, in the order the lines (ids `1..=count`) were sent.
async fn expect_answered_in_order(ws: &mut Ws, count: u64) {
    for id in 1..=count {
        let reply = recv_json(ws).await;
        assert_eq!(reply["id"], id, "replies stay in line order: {reply}");
        assert_eq!(reply["result"]["structuredContent"], json!([]), "{reply}");
    }
}

#[tokio::test]
async fn a_token_frame_of_exactly_the_line_cap_is_answered_in_full() {
    let commands = TestCommands::new();
    let server = start("token-lines-at-cap", &commands).await;
    let mut ws = ws_connect(&server).await;

    // The token line shares the frame with a full cap's worth of requests; the
    // token line itself is not a request and does not count against the cap.
    let frame = call_frame(Some(token_line()), MAX_LINES_PER_FRAME, "flow.list");
    send_text(&mut ws, frame).await;
    expect_answered_in_order(&mut ws, MAX_LINES_PER_FRAME).await;
}

#[tokio::test]
async fn a_token_frame_over_the_line_cap_closes_the_connection_and_runs_nothing() {
    let commands = TestCommands::new();
    let server = start("token-lines-over-cap", &commands).await;
    let mut ws = ws_connect(&server).await;

    let frame = call_frame(Some(token_line()), MAX_LINES_PER_FRAME + 1, "test.tick");
    send_text(&mut ws, frame).await;

    let drained = drain_until_end(&mut ws, FAST).await;
    assert!(
        drained.ended,
        "an oversized token frame must close the connection; it answered {} lines instead",
        drained.replies.len()
    );
    assert!(
        drained.replies.is_empty(),
        "no line of an oversized token frame may be answered, got {:?}",
        drained.replies
    );
    assert_eq!(
        drained.close_code,
        Some(CloseCode::Size),
        "the Close frame says why"
    );
    assert_eq!(commands.ticks(), 0, "no line of an oversized frame may run");
}

#[tokio::test]
async fn a_bad_token_is_refused_before_the_line_cap_is_considered() {
    let commands = TestCommands::new();
    let server = start("bad-token-over-cap", &commands).await;
    let mut ws = ws_connect(&server).await;

    // A wrong token leading an oversized frame must get the ordinary unauthorized
    // refusal (`Policy`), not `Size`: authentication comes before the cap.
    let bad_token = json!({ "token": "nope" }).to_string();
    let frame = call_frame(Some(bad_token), MAX_LINES_PER_FRAME + 1, "test.tick");
    send_text(&mut ws, frame).await;

    let drained = drain_until_end(&mut ws, FAST).await;
    assert!(drained.ended, "a refused connection must be closed");
    assert_eq!(
        drained.replies.len(),
        1,
        "exactly the unauthorized reply, got {:?}",
        drained.replies
    );
    let refusal: JsonValue = serde_json::from_str(&drained.replies[0]).expect("reply is JSON");
    assert_eq!(refusal["error"]["code"], -32001, "{refusal}");
    assert!(refusal["id"].is_null(), "{refusal}");
    assert_eq!(
        drained.close_code,
        Some(CloseCode::Policy),
        "refused as unauthorized, not as too large"
    );
    assert_eq!(commands.ticks(), 0, "no line may run for a refused token");
}

#[tokio::test]
async fn a_frame_over_the_line_cap_closes_the_connection_and_runs_nothing() {
    let commands = TestCommands::new();
    let server = start("lines-over-cap", &commands).await;
    let mut ws = open_bus(&server).await;

    let frame = call_frame(None, MAX_LINES_PER_FRAME + 1, "test.tick");
    send_text(&mut ws, frame).await;

    // The server has read the whole frame, so it refuses with a `Size` Close frame
    // before dropping the connection; not one of the frame's lines is answered or run.
    let drained = drain_until_end(&mut ws, FAST).await;
    assert!(
        drained.ended,
        "an oversized frame must close the connection; it answered {} lines instead",
        drained.replies.len()
    );
    assert!(
        drained.replies.is_empty(),
        "no line of an oversized frame may be answered, got {:?}",
        drained.replies
    );
    assert_eq!(
        drained.close_code,
        Some(CloseCode::Size),
        "the Close frame says why"
    );
    assert_eq!(commands.ticks(), 0, "no line of an oversized frame may run");
}

#[tokio::test]
async fn a_panicking_command_ends_only_its_own_connection() {
    let commands = TestCommands::new();
    let server = start("panic", &commands).await;
    let mut ws = open_bus(&server).await;

    send_text(&mut ws, call_line(1, "test.panic")).await;
    let drained = drain_until_end(&mut ws, FAST).await;
    assert!(drained.ended, "a panicking command must end its connection");
    assert!(
        drained.replies.is_empty(),
        "a panicked line has no reply, got {:?}",
        drained.replies
    );

    // The server and its other connections are untouched.
    let mut other = open_bus(&server).await;
    send_text(&mut other, call_line(2, "flow.list")).await;
    let reply = recv_json(&mut other).await;
    assert_eq!(reply["id"], 2, "{reply}");
    assert_eq!(reply["result"]["structuredContent"], json!([]), "{reply}");
}

#[tokio::test]
async fn a_client_close_is_seen_while_a_command_is_parked() {
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("close", &commands).await;
    let mut ws = open_bus(&server).await;

    send_text(&mut ws, call_line(1, "test.block")).await;
    wait_until("test.block to start", || commands.parking.entered() == 1).await;

    // The client closes while the command is still parked. One frame is in flight,
    // below the cap, so the bridge is still reading: it notices at once rather than
    // after the command, and the stream ends.
    ws.close(None).await.expect("client close");
    let drained = drain_until_end(&mut ws, FAST).await;
    assert!(
        drained.ended,
        "the close must be observed while test.block is still parked"
    );
    assert!(
        drained.replies.is_empty(),
        "no reply may arrive after the close, got {:?}",
        drained.replies
    );

    // The parked command cannot be cancelled: once released it runs to completion
    // on its own, and its reply is dropped with the connection.
    assert_eq!(commands.parking.completed(), 0);
    release.release();
    wait_until("the detached test.block to run to completion", || {
        commands.parking.completed() == 1
    })
    .await;
}
