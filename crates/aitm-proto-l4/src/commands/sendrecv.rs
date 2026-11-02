//! `l4.send_recv` — scapy `sr`/`sr1`: inject a stimulus and return the correlated
//! reply (M5 Task 10).
//!
//! Sensitivity: **guarded (`Inject` + `Capture`)**. This is the primitive the L4
//! fuzzing / memory-safety loop drives: craft a stimulus, send it, read the typed
//! [`SendRecvOutcome`](crate::sendrecv::SendRecvOutcome) — a `NoResponse` where the
//! target was answering is the candidate crash the agent confirms.
//!
//! The gating lives in [`crate::sendrecv::send_recv`], which mints an `Inject`
//! permit (scope + denylist + rate) and a `Capture` permit before any I/O and routes
//! the stimulus through the single [`send_on_wire`](crate::wire::send_on_wire) choke
//! point. This command adds the core guard as **defense in depth**
//! ([`CommandHost::guard().check_active`]) so the destination is also an in-scope
//! engagement host, then delegates.
//!
//! [`CommandHost::guard().check_active`]: aitm_core::ScopeRateGuard::check_active

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};

use crate::backend::CaptureInjectBackend;
use crate::craft::PacketSpec;
use crate::flow::L4FlowStore;
use crate::guard::L4Guard;
use crate::sendrecv::{send_recv, ReplyMatch, SendRecvOutcome, SendRecvSpec};
use crate::types::{L4Action, L4Capability, L4Direction, L4Target};

/// Default await before reporting silence when `timeout_ms` is omitted.
const DEFAULT_TIMEOUT_MS: i64 = 1000;

/// `l4.send_recv {spec, dst, interface, port?, timeout_ms?, expect?}` → inject a
/// stimulus and return the correlated [`SendRecvOutcome`] plus the linked flow id.
pub struct SendRecv {
    guard: Arc<L4Guard>,
    store: Arc<dyn L4FlowStore>,
    backend: Arc<dyn CaptureInjectBackend>,
}

impl SendRecv {
    /// A command over the shared guard, flow store, and wire backend.
    pub fn new(
        guard: Arc<L4Guard>,
        store: Arc<dyn L4FlowStore>,
        backend: Arc<dyn CaptureInjectBackend>,
    ) -> Self {
        Self {
            guard,
            store,
            backend,
        }
    }
}

impl Command for SendRecv {
    fn name(&self) -> &str {
        "l4.send_recv"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Writes a stimulus packet to the wire (and captures the reply).
        Sensitivity::Sensitive
    }

    /// The operator confirm-over-the-wire prompt (spec §2.4) for the stimulus that
    /// will hit the wire. `None` (no token minted) when the guard would refuse the
    /// `Inject` of the stimulus — `invoke` then surfaces the typed refusal. Only the
    /// operator role is offered this handshake.
    fn confirm_prompt(&self, args: &Params) -> Option<String> {
        let spec = super::parse_packet_spec(super::require(args, "spec").ok()?).ok()?;
        let dst: IpAddr = args.get_str("dst").ok()?.parse().ok()?;
        let interface = args.get_str("interface").ok()?.to_string();
        let dst_port = match args.get("port") {
            Some(_) => Some(u16::try_from(args.get_int("port").ok()?).ok()?),
            None => None,
        };
        let bytes = spec.build().ok()?;
        let target = L4Target {
            interface: interface.clone(),
            direction: L4Direction::Outbound,
            dst: Some(dst),
            dst_port,
            proto: spec.transport_proto(),
        };
        let permit = self.guard.check(L4Action::Inject, &target).ok()?;
        let summary = PacketSpec::summarize(&bytes);
        let entry = super::covering_scope_entry(
            &self.guard,
            &interface,
            L4Direction::Outbound,
            L4Capability::Inject,
            Some(dst),
            dst_port,
        );
        Some(super::wire_confirm_summary(
            "l4.send_recv",
            dst,
            dst_port,
            &interface,
            L4Direction::Outbound,
            &summary.layers,
            summary.length,
            1,
            permit.remaining(),
            entry.as_ref(),
        ))
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Scapy sr/sr1: inject a crafted stimulus and return the correlated reply \
                          (Response / Other / NoResponse) linked to the stimulus in an L4 flow. \
                          Guarded (Inject+Capture); never hangs (bounded by `timeout_ms`)."
                .into(),
            params: vec![
                ParamDef {
                    name: "spec".into(),
                    ty: TypeDesc::Any,
                    required: true,
                    description: "The stimulus PacketSpec (see `l4.craft`).".into(),
                },
                ParamDef {
                    name: "dst".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description:
                        "The destination IP (also the host a FiveTuple reply must come from)."
                            .into(),
                },
                ParamDef {
                    name: "interface".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The interface to inject on and capture the reply from.".into(),
                },
                ParamDef {
                    name: "port".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "The destination port (for TCP/UDP), matched in correlation."
                        .into(),
                },
                ParamDef {
                    name: "timeout_ms".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description:
                        "How long to await the reply before reporting silence (default 1000)."
                            .into(),
                },
                ParamDef {
                    name: "expect".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description:
                        "Reply correlation: `five_tuple` (default), `from_host`, or `any`.".into(),
                },
            ],
            result: TypeDesc::Object(vec![
                ParamDef {
                    name: "flow_id".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The id of the recorded SendRecv flow (stimulus + reply).".into(),
                },
                ParamDef {
                    name: "outcome".into(),
                    ty: TypeDesc::Object(vec![
                        ParamDef {
                            name: "kind".into(),
                            ty: TypeDesc::Str,
                            required: true,
                            description: "`response`, `responses`, `other`, or `no_response`."
                                .into(),
                        },
                        ParamDef {
                            name: "waited_ms".into(),
                            ty: TypeDesc::Int,
                            required: false,
                            description: "For `no_response`: how long the await lasted.".into(),
                        },
                    ]),
                    required: true,
                    description: "The typed send-and-receive outcome.".into(),
                },
            ]),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let packet = super::parse_packet_spec(super::require(&args, "spec")?)?;
        let dst: IpAddr = args
            .get_str("dst")?
            .parse()
            .map_err(|e| anyhow::anyhow!("param `dst` is not an IP address: {e}"))?;
        let interface = args.get_str("interface")?.to_string();
        let dst_port = match args.get("port") {
            Some(_) => Some(
                u16::try_from(args.get_int("port")?)
                    .map_err(|_| anyhow::anyhow!("`port` must be in 0..=65535"))?,
            ),
            None => None,
        };
        let timeout_ms = match args.get("timeout_ms") {
            Some(_) => args.get_int("timeout_ms")?,
            None => DEFAULT_TIMEOUT_MS,
        };
        let timeout = Duration::from_millis(
            u64::try_from(timeout_ms)
                .map_err(|_| anyhow::anyhow!("`timeout_ms` must be non-negative"))?,
        );
        let expect = parse_expect(&args, dst)?;

        // Defense in depth: the proxy-wide scope/rate/concurrency guard on the
        // destination host. The L4 guard (Inject + Capture) is applied inside
        // `send_recv` before any I/O, so an unauthorized call never reaches the wire.
        let _active = host
            .guard()
            .check_active(&dst.to_string())
            .map_err(anyhow::Error::new)?;

        let spec = SendRecvSpec {
            packet,
            dst,
            dst_port,
            interface,
            timeout,
            expect,
        };
        let (flow_id, outcome) =
            send_recv(&self.guard, self.backend.clone(), self.store.clone(), spec)
                .map_err(anyhow::Error::new)?;

        let mut obj = BTreeMap::new();
        obj.insert(
            "flow_id".to_string(),
            Value::Str(super::flow_id_to_string(flow_id)),
        );
        obj.insert("outcome".to_string(), outcome_to_value(&outcome));
        Ok(Value::Object(obj))
    }
}

/// Resolve the `expect` param into a [`ReplyMatch`]. Defaults to `FiveTuple`;
/// `from_host` correlates purely on the stimulus destination host.
fn parse_expect(args: &Params, dst: IpAddr) -> anyhow::Result<ReplyMatch> {
    match args.get("expect") {
        None => Ok(ReplyMatch::FiveTuple),
        Some(Value::Str(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "five_tuple" | "fivetuple" | "" => Ok(ReplyMatch::FiveTuple),
            "from_host" | "fromhost" => Ok(ReplyMatch::FromHost(dst)),
            "any" => Ok(ReplyMatch::Any),
            other => anyhow::bail!(
                "unknown `expect` `{other}` (want `five_tuple`, `from_host`, or `any`)"
            ),
        },
        Some(other) => anyhow::bail!("param `expect` must be a string, got {other:?}"),
    }
}

/// A [`SendRecvOutcome`] as a transport-neutral object: a `kind` discriminant plus
/// the matched packet (or, for silence, how long the await lasted).
fn outcome_to_value(outcome: &SendRecvOutcome) -> Value {
    let mut obj = BTreeMap::new();
    match outcome {
        SendRecvOutcome::Response(pkt) => {
            obj.insert("kind".to_string(), Value::Str("response".into()));
            obj.insert("packet".to_string(), packet_to_value(pkt));
        }
        SendRecvOutcome::Responses(pkts) => {
            obj.insert("kind".to_string(), Value::Str("responses".into()));
            obj.insert(
                "packets".to_string(),
                Value::Array(pkts.iter().map(packet_to_value).collect()),
            );
        }
        SendRecvOutcome::Other(pkt) => {
            obj.insert("kind".to_string(), Value::Str("other".into()));
            obj.insert("packet".to_string(), packet_to_value(pkt));
        }
        SendRecvOutcome::NoResponse { waited } => {
            obj.insert("kind".to_string(), Value::Str("no_response".into()));
            obj.insert(
                "waited_ms".to_string(),
                Value::Int(i64::try_from(waited.as_millis()).unwrap_or(i64::MAX)),
            );
        }
    }
    Value::Object(obj)
}

/// A reply [`L4Packet`](crate::flow::L4Packet) as a compact object (direction,
/// length, injected flag, decoded layer names).
fn packet_to_value(pkt: &crate::flow::L4Packet) -> Value {
    use crate::types::L4Direction;
    let dir = match pkt.dir {
        L4Direction::Inbound => "inbound",
        L4Direction::Outbound => "outbound",
    };
    let mut o = BTreeMap::new();
    o.insert("dir".to_string(), Value::Str(dir.to_string()));
    o.insert("length".to_string(), Value::Int(pkt.bytes.len() as i64));
    o.insert("injected".to_string(), Value::Bool(pkt.injected));
    o.insert(
        "layers".to_string(),
        Value::Array(pkt.decoded.layers.iter().cloned().map(Value::Str).collect()),
    );
    Value::Object(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::Mutex;

    use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, ProxyClient, ScopeRateGuard, StdGuard};
    use futures::future::BoxFuture;

    use crate::backend::{CaptureSource, L4Error};
    use crate::config::L4Config;
    use crate::craft::{Ipv4Spec, Layer, PacketSpec, UdpSpec};
    use crate::flow::{InMemoryL4FlowStore, L4FlowKind};
    use crate::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, PortRange, RateCap,
    };

    struct StubClient;
    impl ProxyClient for StubClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    fn core_guard_scoped() -> StdGuard {
        let g = StdGuard::default();
        g.add_scope(aitm_core::ScopeEntry {
            host: "127.0.0.1".into(),
        });
        g
    }

    /// A backend that records injected frames and replays scripted reply frames into
    /// the awaiting capture, then idles like a real read timeout.
    struct MockBackend {
        replies: Mutex<Option<Vec<Vec<u8>>>>,
        injected: Mutex<Vec<Vec<u8>>>,
    }

    impl MockBackend {
        fn with_replies(replies: Vec<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(Some(replies)),
                injected: Mutex::new(Vec::new()),
            })
        }

        fn injected(&self) -> Vec<Vec<u8>> {
            self.injected.lock().unwrap().clone()
        }
    }

    impl CaptureInjectBackend for MockBackend {
        fn open_capture(
            &self,
            _iface: &str,
            _filter: Option<&str>,
            _read_timeout: Duration,
        ) -> Result<Box<dyn CaptureSource>, L4Error> {
            let replies = self.replies.lock().unwrap().take().unwrap_or_default();
            Ok(Box::new(ReplySource {
                frames: replies.into_iter().collect(),
            }))
        }

        fn inject(&self, _iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
            self.injected.lock().unwrap().push(bytes.to_vec());
            Ok(())
        }
    }

    struct ReplySource {
        frames: VecDeque<Vec<u8>>,
    }
    impl CaptureSource for ReplySource {
        fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
            match self.frames.pop_front() {
                Some(frame) => Ok(Some(frame)),
                None => {
                    std::thread::sleep(Duration::from_millis(2));
                    Ok(None)
                }
            }
        }
    }

    fn l4_guard() -> Arc<L4Guard> {
        let g = L4Guard::new(&L4Config::default());
        for (dir, cap) in [
            (L4Direction::Outbound, L4Capability::Inject),
            (L4Direction::Inbound, L4Capability::Capture),
        ] {
            g.add_scope(L4ScopeEntry {
                id: L4ScopeId::new(),
                cidr: IpCidr {
                    addr: "127.0.0.1".parse().unwrap(),
                    prefix: 32,
                },
                ports: PortRange { lo: 0, hi: 65535 },
                interface: "mock0".to_string(),
                direction: dir,
                capability: cap,
                inject_rate: RateCap {
                    pps: 100,
                    burst: 100,
                },
                source: crate::types::L4ScopeSource::Config,
            })
            .unwrap();
        }
        Arc::new(g)
    }

    fn udp_reply(src: &str, src_port: u16, payload: &[u8]) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(src.parse().unwrap()),
                    dst: Some("127.0.0.1".parse().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(src_port),
                    dst_port: Some(40000),
                    ..UdpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
        .build()
        .expect("reply builds")
    }

    fn spec_value(dst: &str, dst_port: i64) -> Value {
        let ipv4 = {
            let mut m = BTreeMap::new();
            m.insert("dst".to_string(), Value::Str(dst.into()));
            let mut l = BTreeMap::new();
            l.insert("ipv4".to_string(), Value::Object(m));
            Value::Object(l)
        };
        let udp = {
            let mut m = BTreeMap::new();
            m.insert("dst_port".to_string(), Value::Int(dst_port));
            // The port `udp_reply` answers to. Port 0 is a real port since amendment
            // 66 (a stimulus sent from 0 is answered to 0), so the fixture names the
            // source port the reply is addressed to instead of leaning on the old
            // "0 means unset" relaxation.
            m.insert("src_port".to_string(), Value::Int(40000));
            let mut l = BTreeMap::new();
            l.insert("udp".to_string(), Value::Object(m));
            Value::Object(l)
        };
        let mut spec = BTreeMap::new();
        spec.insert("layers".to_string(), Value::Array(vec![ipv4, udp]));
        Value::Object(spec)
    }

    fn params(timeout_ms: i64) -> Params {
        let mut m = BTreeMap::new();
        m.insert("spec".to_string(), spec_value("127.0.0.1", 9));
        m.insert("dst".to_string(), Value::Str("127.0.0.1".into()));
        m.insert("interface".to_string(), Value::Str("mock0".into()));
        m.insert("port".to_string(), Value::Int(9));
        m.insert("timeout_ms".to_string(), Value::Int(timeout_ms));
        Params::new(m)
    }

    /// Hermetic: a correlated UDP reply yields an `outcome.kind == "response"` and a
    /// SendRecv flow linking the injected stimulus and the observed reply.
    #[test]
    fn send_recv_cmd_response() {
        let guard = l4_guard();
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let backend = MockBackend::with_replies(vec![udp_reply("127.0.0.1", 9, b"echo")]);
        let cmd = SendRecv::new(guard, store.clone(), backend.clone());

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = core_guard_scoped();
        let host = CommandHost::new(&mem, &client, &core, None);

        let result = cmd
            .invoke(params(1000), &host)
            .expect("authorized send_recv");
        let Value::Object(obj) = result else {
            panic!("l4.send_recv returns an object");
        };
        let Some(Value::Object(outcome)) = obj.get("outcome") else {
            panic!("l4.send_recv returns an outcome object");
        };
        assert_eq!(outcome.get("kind"), Some(&Value::Str("response".into())));

        assert_eq!(backend.injected().len(), 1, "the stimulus reached the wire");

        let Some(Value::Str(flow_id)) = obj.get("flow_id") else {
            panic!("l4.send_recv returns a flow id");
        };
        let id = super::super::flow_id_from_str(flow_id).unwrap();
        let flow = store.get(id).expect("send_recv flow recorded");
        assert_eq!(flow.kind, L4FlowKind::SendRecv);
        assert_eq!(flow.packets.len(), 2, "stimulus + reply linked");
        assert!(flow.packets[0].injected);
        assert!(!flow.packets[1].injected);
    }

    /// Hermetic (AC11): no responder ⇒ `outcome.kind == "no_response"` with a
    /// `waited_ms >= timeout`, and the command returns rather than hanging.
    #[test]
    fn send_recv_cmd_no_response() {
        let guard = l4_guard();
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let backend = MockBackend::with_replies(vec![]);
        let cmd = SendRecv::new(guard, store.clone(), backend.clone());

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = core_guard_scoped();
        let host = CommandHost::new(&mem, &client, &core, None);

        let result = cmd.invoke(params(80), &host).expect("authorized send_recv");
        let Value::Object(obj) = result else {
            panic!("object");
        };
        let Some(Value::Object(outcome)) = obj.get("outcome") else {
            panic!("outcome object");
        };
        assert_eq!(outcome.get("kind"), Some(&Value::Str("no_response".into())));
        let Some(Value::Int(waited)) = outcome.get("waited_ms") else {
            panic!("no_response carries waited_ms");
        };
        assert!(*waited >= 80, "waited {waited}ms < timeout 80ms");
        assert_eq!(
            backend.injected().len(),
            1,
            "silence still sent the stimulus"
        );
    }

    /// Pinned (plan Task 10 / AC10): the real-pcap command round-trip on a scoped
    /// loopback against a UDP echo responder. Privilege-gated — `#[ignore]`d and run
    /// only with `AITM_L4_TESTS=1`; without raw privilege it skips on `L4Unavailable`.
    /// Linux-only (the craft layer emits an Ethernet frame; see `sendrecv::send_recv_response`).
    #[test]
    #[ignore = "requires raw-inject/capture privilege; run with AITM_L4_TESTS=1 and -- --ignored"]
    fn send_recv_cmd() {
        if std::env::var("AITM_L4_TESTS").ok().as_deref() != Some("1") || cfg!(target_os = "macos")
        {
            return;
        }
        use crate::backend::pcap::PcapBackend;
        use std::net::UdpSocket;

        let echo = UdpSocket::bind("127.0.0.1:0").expect("bind echo");
        let echo_port = echo.local_addr().unwrap().port();
        let responder = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });

        // Scope loopback for inject (outbound) + capture (inbound) on `lo`.
        let guard = Arc::new(L4Guard::new(&L4Config::default()));
        for (dir, cap) in [
            (L4Direction::Outbound, L4Capability::Inject),
            (L4Direction::Inbound, L4Capability::Capture),
        ] {
            guard
                .add_scope(L4ScopeEntry {
                    id: L4ScopeId::new(),
                    cidr: IpCidr {
                        addr: "127.0.0.0".parse().unwrap(),
                        prefix: 8,
                    },
                    ports: PortRange { lo: 0, hi: 65535 },
                    interface: "lo".to_string(),
                    direction: dir,
                    capability: cap,
                    inject_rate: RateCap {
                        pps: 100,
                        burst: 100,
                    },
                    source: crate::types::L4ScopeSource::Config,
                })
                .unwrap();
        }
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let backend: Arc<dyn CaptureInjectBackend> = Arc::new(PcapBackend::new());
        let cmd = SendRecv::new(guard, store, backend);

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = core_guard_scoped();
        let host = CommandHost::new(&mem, &client, &core, None);

        // An Ethernet/IPv4/UDP stimulus from 127.0.0.1:40000 to the echo port.
        let ether = {
            let mut l = BTreeMap::new();
            l.insert("ether".to_string(), Value::Object(BTreeMap::new()));
            Value::Object(l)
        };
        let ipv4 = {
            let mut m = BTreeMap::new();
            m.insert("src".to_string(), Value::Str("127.0.0.1".into()));
            m.insert("dst".to_string(), Value::Str("127.0.0.1".into()));
            let mut l = BTreeMap::new();
            l.insert("ipv4".to_string(), Value::Object(m));
            Value::Object(l)
        };
        let udp = {
            let mut m = BTreeMap::new();
            m.insert("src_port".to_string(), Value::Int(40000));
            m.insert("dst_port".to_string(), Value::Int(i64::from(echo_port)));
            let mut l = BTreeMap::new();
            l.insert("udp".to_string(), Value::Object(m));
            Value::Object(l)
        };
        let raw = {
            let mut l = BTreeMap::new();
            l.insert(
                "raw".to_string(),
                Value::Array(b"probe".iter().map(|b| Value::Int(i64::from(*b))).collect()),
            );
            Value::Object(l)
        };
        let mut spec = BTreeMap::new();
        spec.insert(
            "layers".to_string(),
            Value::Array(vec![ether, ipv4, udp, raw]),
        );

        let mut m = BTreeMap::new();
        m.insert("spec".to_string(), Value::Object(spec));
        m.insert("dst".to_string(), Value::Str("127.0.0.1".into()));
        m.insert("interface".to_string(), Value::Str("lo".into()));
        m.insert("port".to_string(), Value::Int(i64::from(echo_port)));
        m.insert("timeout_ms".to_string(), Value::Int(2000));

        let result = match cmd.invoke(Params::new(m), &host) {
            Ok(v) => v,
            Err(e) => {
                if e.downcast_ref::<L4Error>()
                    .is_some_and(|e| matches!(e, L4Error::Unavailable(_)))
                {
                    return; // no privilege here: fail-closed contract, skip.
                }
                panic!("unexpected send_recv error: {e:?}");
            }
        };
        let _ = responder.join();

        let Value::Object(obj) = result else {
            panic!("object");
        };
        let Some(Value::Object(outcome)) = obj.get("outcome") else {
            panic!("outcome");
        };
        assert_eq!(outcome.get("kind"), Some(&Value::Str("response".into())));
    }
}
