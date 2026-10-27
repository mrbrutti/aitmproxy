//! AC2: a WebSocket upgraded through the proxy is captured as a `WsFlow` linked
//! to its 101 `HttpFlow`, with both directions' frames in order. Plus unit
//! checks on the sans-IO frame coder's masking rules.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    Config, Flow, FlowStore, HttpFlow, Proxy, ScopeConfig, ScopeEntry, WsDir, WsFlow, WsMessage,
    WsOpcode,
};
use aitm_proto_http::HttpModule;
use aitm_proto_ws::{Side, WsFrameMachine, WsModule, WsSansIoEvent, WsStateMachine};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

// --- sans-IO frame coder -----------------------------------------------------

/// A masked single-frame text message as a client would send it.
fn masked_text_frame(payload: &[u8], key: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0x81, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&key);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    frame
}

#[test]
fn masked_client_text_frame_is_decoded() {
    let mut m = WsFrameMachine::new();
    let frame = masked_text_frame(b"hi", [1, 2, 3, 4]);
    let events = m.on_bytes(Side::Client, &frame).unwrap();
    assert_eq!(
        events,
        vec![WsSansIoEvent::Open, WsSansIoEvent::Message { index: 0 }]
    );
    let msg = m.message(0).expect("message 0 recorded");
    assert_eq!(msg.dir, WsDir::ClientToServer);
    assert_eq!(msg.opcode, WsOpcode::Text);
    assert_eq!(msg.data, b"hi".to_vec());
    assert!(!msg.injected);
}

#[test]
fn frame_split_across_reads_is_decoded_once_complete() {
    let mut m = WsFrameMachine::new();
    let frame = masked_text_frame(b"split", [9, 9, 9, 9]);
    let first = m.on_bytes(Side::Client, &frame[..3]).unwrap();
    assert_eq!(
        first,
        vec![WsSansIoEvent::Open],
        "partial frame yields no message"
    );
    let rest = m.on_bytes(Side::Client, &frame[3..]).unwrap();
    assert_eq!(rest, vec![WsSansIoEvent::Message { index: 0 }]);
    assert_eq!(m.message(0).unwrap().data, b"split".to_vec());
}

fn text(dir: WsDir, data: &[u8]) -> WsMessage {
    WsMessage {
        dir,
        opcode: WsOpcode::Text,
        data: data.to_vec(),
        timestamp: SystemTime::now(),
        injected: false,
    }
}

#[test]
fn send_frame_to_client_is_unmasked() {
    let mut m = WsFrameMachine::new();
    assert_eq!(m.poll_outbound(Side::Client), None);
    m.send_frame(Side::Client, text(WsDir::ServerToClient, b"ok"));
    assert_eq!(
        m.poll_outbound(Side::Client),
        Some(vec![0x81, 0x02, b'o', b'k'])
    );
    assert_eq!(m.poll_outbound(Side::Client), None, "queue drains once");
}

#[test]
fn send_frame_to_server_is_masked() {
    let mut m = WsFrameMachine::new();
    m.send_frame(Side::Server, text(WsDir::ClientToServer, b"ok"));
    let frame = m.poll_outbound(Side::Server).expect("frame queued");
    assert_eq!(frame.len(), 2 + 4 + 2);
    assert_eq!(frame[0], 0x81);
    assert_eq!(
        frame[1],
        0x80 | 2,
        "frames towards the server carry the mask bit"
    );
    let key = [frame[2], frame[3], frame[4], frame[5]];
    let unmasked: Vec<u8> = frame[6..]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % 4])
        .collect();
    assert_eq!(unmasked, b"ok".to_vec());
}

#[test]
fn close_frame_emits_close() {
    let mut m = WsFrameMachine::new();
    // Unmasked close from the server with status 1000.
    let events = m.on_bytes(Side::Server, &[0x88, 0x02, 0x03, 0xE8]).unwrap();
    assert_eq!(
        events,
        vec![
            WsSansIoEvent::Open,
            WsSansIoEvent::Message { index: 0 },
            WsSansIoEvent::Close
        ]
    );
    assert_eq!(m.message(0).unwrap().opcode, WsOpcode::Close);
}

// --- AC2 through a real proxy ------------------------------------------------

fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("pick a free port")
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut chunk).await.expect("read head");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// A WebSocket server echoing every text/binary message.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_text() || msg.is_binary() {
                        if ws.send(msg).await.is_err() {
                            break;
                        }
                    } else if msg.is_close() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A `Proxy` with the HTTP module (hands off upgrades) and the WS module.
async fn run_proxy() -> (SocketAddr, Arc<dyn FlowStore>) {
    let config = Config {
        scope: ScopeConfig {
            entries: vec![ScopeEntry {
                host: "127.0.0.1".to_string(),
            }],
        },
        ..Config::default()
    };
    let proxy = Proxy::builder()
        .with_config(config)
        .register_module(Arc::new(HttpModule::new().with_insecure(true)))
        .register_module(Arc::new(WsModule::new()))
        .build()
        .expect("build proxy");
    let store = proxy.store();
    let addr = free_port();
    tokio::spawn(async move {
        let _ = proxy.run(addr).await;
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "proxy never started listening");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, store)
}

/// The captured `WsFlow` once it holds `want` messages, plus its handshake flow.
async fn wait_for_ws_flow(store: &dyn FlowStore, want: usize) -> (WsFlow, HttpFlow) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let ws = store.list().into_iter().find_map(|id| match store.get(id) {
            Some(Flow::WebSocket(f)) if f.messages.len() >= want => Some(f),
            _ => None,
        });
        if let Some(ws) = ws {
            let handshake = match store.get(ws.handshake) {
                Some(Flow::Http(h)) => h,
                other => panic!("handshake {} is not an HttpFlow: {other:?}", ws.handshake),
            };
            return (ws, handshake);
        }
        assert!(
            Instant::now() < deadline,
            "no WsFlow with {want} messages captured; store has {:?}",
            store.list().len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_frames_captured_in_order() {
    let echo = spawn_echo().await;
    let (proxy, store) = run_proxy().await;

    // A CONNECT tunnel to the echo server, then the WebSocket handshake inside it.
    let mut tcp = TcpStream::connect(proxy).await.expect("connect proxy");
    tcp.write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes())
        .await
        .expect("send CONNECT");
    let reply = read_head(&mut tcp).await;
    assert!(
        reply.starts_with("HTTP/1.1 200"),
        "CONNECT reply: {reply:?}"
    );
    let (mut ws, response) = tokio_tungstenite::client_async(format!("ws://{echo}/chat"), tcp)
        .await
        .expect("WebSocket handshake through the proxy");
    assert_eq!(response.status().as_u16(), 101);

    ws.send(Message::text("ping-aitm"))
        .await
        .expect("send text");
    let echoed = ws.next().await.expect("echo reply").expect("echo frame");
    assert_eq!(echoed.to_text().expect("text frame"), "ping-aitm");

    let (flow, handshake) = wait_for_ws_flow(store.as_ref(), 2).await;
    assert_eq!(
        flow.handshake, handshake.id,
        "WsFlow must link to its 101 HttpFlow"
    );
    assert_eq!(handshake.request.path, "/chat");
    assert_eq!(
        handshake.response.as_ref().map(|r| r.status),
        Some(101),
        "the handshake flow carries the 101"
    );
    let shape: Vec<(WsDir, WsOpcode)> = flow.messages.iter().map(|m| (m.dir, m.opcode)).collect();
    assert_eq!(
        shape,
        vec![
            (WsDir::ClientToServer, WsOpcode::Text),
            (WsDir::ServerToClient, WsOpcode::Text),
        ]
    );
    assert_eq!(flow.messages[0].data, b"ping-aitm".to_vec());
    assert_eq!(flow.messages[1].data, b"ping-aitm".to_vec());

    ws.close(None).await.ok();
}
