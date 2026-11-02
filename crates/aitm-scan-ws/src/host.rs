//! The `WsProbeHost`: one insertion point, re-driven as a real conversation.
//!
//! A check holds nothing but a `&dyn ProbeHost`, so everything the spec's
//! "Probe semantics" (D8.3) asks for happens here: dial the captured handshake
//! (with the point's override when the point *is* a handshake header), replay
//! the client->server frames that preceded the chosen one, send the mutated
//! frame, collect the server's answer for `reply_window_ms`, close, and hand
//! back a [`ProbeResponse`] whose `ws_frames` are the oracle.
//!
//! Three rules from the spec are load-bearing and easy to lose:
//!
//! - **Budget.** One unit per dial and one per frame sent, charged *before* the
//!   socket or the frame goes out (D8.3; the dialer takes no `JobCtx`, so the
//!   charging is this module's job). A refused charge is an error, not a
//!   quieter probe.
//! - **Record policy.** Under `issues_only` a conversation never reaches the
//!   store; it is held in memory ([`crate::types::HELD_PROBES`] probes, newest
//!   kept, plus the baseline) so the engine can re-record exactly the flows
//!   that evidenced an issue (D5).
//! - **A drop is data.** A non-101 upgrade is `Ok` with that status, and a
//!   transport drop during collection ends the conversation without an error:
//!   the frames (no `Close`) and an early `elapsed_ms` are how a check reads it
//!   (plan call 18).
//!
//! Nothing here puts a header value or a frame payload in an error, a log line
//! or a `Debug` output; the replayed `Cookie` lives only in the held flows,
//! which are store data.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use aitm_core::{Flow, HttpFlow, WsDir, WsFlow, WsMessage, WsOpcode};
use aitm_scan_model::{
    FlowRef, Frame, FrameKind, InsertionPoint, JobCtx, Payload, PayloadMode, ProbeHost,
    ProbeResponse, RawProbe, RecordProbes, ScanProfile, MAX_MATCH_BODY,
};
use anyhow::{anyhow, bail};
use futures::future::BoxFuture;
use tokio::sync::Mutex as AsyncMutex;

use crate::dialer::{CollectEnd, CollectOutcome, DialLimits, DialOutcome, WsConn, WsDialer};
use crate::mutate;
use crate::types::{authority_with_port, HandshakeOverrides, Locator, PointSpec, HELD_PROBES};

/// The marker that turns a payload into "pad this frame", not "send this text".
///
/// A check sees neither the captured frame nor its canonical length (it holds
/// only a `&dyn ProbeHost`), so `ws-oversize-frame` asks for the pad with this
/// sentinel and the host computes the size (plan call 21). The leading NUL
/// keeps it from colliding with any payload a real check would send, and the
/// sentinel itself never goes on the wire.
pub const PAD_SENTINEL: &str = "\u{0}aitm-pad:";

/// The payload `ws-oversize-frame` sends to ask for a padded frame.
///
/// [`WsProbeHost::probe`] replaces it with as many `A`s as it takes to make the
/// frame exactly `min(2 x largest captured client frame, max_frame_bytes)`
/// bytes.
#[must_use]
pub fn pad_payload() -> Payload {
    Payload {
        value: PAD_SENTINEL.to_string(),
        mode: PayloadMode::Suffix,
        bytes: None,
    }
}

/// How long one wait for a replayed prerequisite's answer lasts before the next
/// read, so the drain ends on the first answer instead of on the whole window.
const DRAIN_POLL: Duration = Duration::from_millis(25);

/// Which held slot a conversation belongs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeldSlot {
    /// The one cached baseline conversation.
    Baseline,
    /// A probe conversation, newest kept.
    Probe,
}

/// Head-room the read limit of an oversize dial keeps above the padded frame.
///
/// A server that echoes the padded frame answers with more bytes than it
/// received (a prefix, a JSON envelope, a close reason), and the margin has to
/// cover that wrapper with room to spare.
const PAD_READ_HEADROOM: usize = 4096;

/// What one conversation sends: the handshake differences, the frame, the
/// protocol limits to dial with.
struct Attempt {
    overrides: HandshakeOverrides,
    frame: Option<Frame>,
    limits: DialLimits,
}

/// The read limit an oversize probe dials with for a pad of `target` bytes.
///
/// The pad target stays the profile's (`min(2 x largest client frame,
/// max_frame_bytes)`), but tungstenite applies `max_frame_bytes` to *incoming*
/// frames as well, so dialling an oversize probe at the profile cap would make
/// our own reader refuse the echo of the frame we just sent: no reply, no
/// Close, an early `elapsed_ms` — exactly the shape `ws-oversize-frame` reads
/// as "the server dropped the connection". The limit is lifted clear of the
/// padded frame so that a drop can only have come from the server.
fn pad_limits(target: usize) -> DialLimits {
    DialLimits {
        max_frame_bytes: target
            .saturating_mul(2)
            .max(target.saturating_add(PAD_READ_HEADROOM)),
        ..DialLimits::default()
    }
}

/// The conversations kept in memory for `held_flows()`.
#[derive(Default)]
struct Held {
    baseline: Option<(HttpFlow, WsFlow)>,
    probes: VecDeque<(HttpFlow, WsFlow)>,
}

/// One discovered WebSocket insertion point, re-drivable as a conversation.
///
/// Built by the lane per point (`probe_host_for`) over the lane's shared
/// [`WsDialer`], so every probe host of a job competes for the same four
/// connections (plan call 23).
pub struct WsProbeHost {
    point: InsertionPoint,
    spec: PointSpec,
    handshake: HttpFlow,
    ws: WsFlow,
    dialer: Arc<WsDialer>,
    job: Arc<dyn JobCtx>,
    baseline: AsyncMutex<Option<ProbeResponse>>,
    held: Mutex<Held>,
}

impl WsProbeHost {
    /// A probe host for `point`, re-driving `ws` through `dialer`.
    ///
    /// # Errors
    ///
    /// When `spec.frame_index` does not name a client->server frame of `ws`, or
    /// when the locator addresses something inside a frame and the spec carries
    /// no frame index — either way the point could not be re-driven, and a
    /// silent no-op probe would read to a check as a clean target.
    pub fn new(
        point: InsertionPoint,
        spec: PointSpec,
        handshake: HttpFlow,
        ws: WsFlow,
        dialer: Arc<WsDialer>,
        job: Arc<dyn JobCtx>,
    ) -> anyhow::Result<Self> {
        match spec.frame_index {
            Some(index) => {
                let message = ws.messages.get(index).ok_or_else(|| {
                    anyhow!("frame {index} is past the end of the captured conversation")
                })?;
                if message.dir != WsDir::ClientToServer {
                    bail!("frame {index} is not a client->server frame; only those are re-sent");
                }
            }
            None => {
                if !matches!(spec.locator, Locator::HandshakeHeader(_)) {
                    bail!("a point inside a frame needs the index of the frame it was found in");
                }
            }
        }
        Ok(Self {
            point,
            spec,
            handshake,
            ws,
            dialer,
            job,
            baseline: AsyncMutex::new(None),
            held: Mutex::new(Held::default()),
        })
    }

    /// The point this host probes.
    #[must_use]
    pub fn point(&self) -> &InsertionPoint {
        &self.point
    }

    /// The captured handshake's authority, with the scheme's default port.
    fn authority(&self) -> String {
        authority_with_port(
            &self.handshake.request.scheme,
            &self.handshake.request.authority,
        )
    }

    /// The captured client->server frame the payload is placed in.
    fn chosen_frame(&self) -> Option<Frame> {
        let index = self.spec.frame_index?;
        self.ws.messages.get(index).map(frame_of)
    }

    /// The client->server frames captured before the chosen one, in order.
    fn preceding_frames(&self) -> Vec<Frame> {
        let Some(index) = self.spec.frame_index else {
            return Vec::new();
        };
        self.ws
            .messages
            .iter()
            .take(index)
            .filter(|message| message.dir == WsDir::ClientToServer)
            .map(frame_of)
            .collect()
    }

    /// The whole of one `probe(payload)`: what to override, what to send, and
    /// the protocol limits to dial with.
    ///
    /// A handshake-header point moves the payload into the upgrade request (an
    /// empty value strips the header) and replays its chosen frame unchanged;
    /// every other point mutates the chosen frame at its locator.
    fn plan_probe(&self, payload: &Payload) -> anyhow::Result<Attempt> {
        match &self.spec.locator {
            Locator::HandshakeHeader(name) => {
                let overrides = if payload.value.is_empty() {
                    HandshakeOverrides::strip(name)
                } else {
                    HandshakeOverrides::set(name, &payload.value)
                };
                Ok(Attempt {
                    overrides,
                    frame: self.chosen_frame(),
                    limits: self.dial_limits(),
                })
            }
            locator => {
                let original = self
                    .chosen_frame()
                    .ok_or_else(|| anyhow!("the captured conversation has no frame to mutate"))?;
                let (bytes, limits) = if is_pad(payload) {
                    let target = self.pad_target(&original.payload);
                    (self.padded(&original.payload, target)?, pad_limits(target))
                } else {
                    (
                        mutate::place(&original.payload, locator, payload)?,
                        self.dial_limits(),
                    )
                };
                Ok(Attempt {
                    overrides: HandshakeOverrides::default(),
                    frame: Some(Frame {
                        kind: original.kind,
                        payload: bytes,
                    }),
                    limits,
                })
            }
        }
    }

    /// The protocol limits an ordinary probe dials with: the job profile's cap.
    fn dial_limits(&self) -> DialLimits {
        DialLimits {
            max_frame_bytes: self.job.profile().ws.max_frame_bytes as usize,
            ..DialLimits::default()
        }
    }

    /// The exact byte length an oversize probe pads the chosen frame to:
    /// `min(2 x largest captured client frame, profile.ws.max_frame_bytes)`.
    fn pad_target(&self, original: &[u8]) -> usize {
        let largest = self
            .ws
            .messages
            .iter()
            .filter(|message| message.dir == WsDir::ClientToServer)
            .map(|message| message.data.len())
            .max()
            .unwrap_or(original.len());
        let cap = self.job.profile().ws.max_frame_bytes as usize;
        largest.saturating_mul(2).min(cap)
    }

    /// `original` padded at the point's locator to exactly `target` bytes.
    ///
    /// The arithmetic goes through the same [`mutate::place`] the probe uses,
    /// via [`mutate::canonical_len`], so the frame that leaves is exactly that
    /// many bytes even when re-serialising the JSON changes its length. A
    /// target no larger than the canonical frame sends it unchanged.
    fn padded(&self, original: &[u8], target: usize) -> anyhow::Result<Vec<u8>> {
        let canonical = mutate::canonical_len(original, &self.spec.locator)?;
        let Some(pad) = target.checked_sub(canonical).filter(|pad| *pad > 0) else {
            return Ok(original.to_vec());
        };
        mutate::place(
            original,
            &self.spec.locator,
            &Payload {
                value: "A".repeat(pad),
                mode: PayloadMode::Suffix,
                bytes: None,
            },
        )
    }

    /// The handshake overrides a [`RawProbe`] asks for.
    ///
    /// `headers` are differences from the capture — an empty value strips the
    /// header — and `url`, when given, may only name the captured authority:
    /// a check does not get to retarget the scanner. `method` and `body` are
    /// not used: a WebSocket upgrade is always a bodyless `GET`.
    fn raw_overrides(&self, req: &RawProbe) -> anyhow::Result<HandshakeOverrides> {
        if !req.url.is_empty() {
            let (scheme, authority) = split_url(&req.url)
                .ok_or_else(|| anyhow!("a raw probe url must be absolute, with an authority"))?;
            if !authority_with_port(scheme, authority).eq_ignore_ascii_case(&self.authority()) {
                bail!("a raw probe cannot dial an authority the capture did not");
            }
        }
        let mut overrides = HandshakeOverrides::default();
        for (name, value) in &req.headers {
            if value.is_empty() {
                overrides.strip.push(name.clone());
            } else {
                overrides.set.push((name.clone(), value.clone()));
            }
        }
        Ok(overrides)
    }

    /// Dial, replay, send, collect, close — one probe's whole conversation.
    async fn conversation(
        &self,
        attempt: Attempt,
        slot: HeldSlot,
    ) -> anyhow::Result<ProbeResponse> {
        if self.job.cancelled() {
            bail!("the job was cancelled");
        }
        let deadline = self.job.deadline();
        if Instant::now() >= deadline {
            bail!("the job deadline passed before the probe was sent");
        }
        if !self.job.charge(1) {
            bail!("the job budget is exhausted");
        }

        let Attempt {
            overrides,
            frame,
            limits,
        } = attempt;
        let window = Duration::from_millis(u64::from(self.job.profile().ws.reply_window_ms));
        let guard = self.job.guard();
        let started = Instant::now();
        let mut conn = match self
            .dialer
            .dial(&self.handshake, &overrides, &*guard, deadline, limits)
            .await?
        {
            DialOutcome::Upgraded(conn) => conn,
            DialOutcome::Refused { status, headers } => {
                return Ok(ProbeResponse {
                    status: Some(status),
                    headers,
                    body: Vec::new(),
                    elapsed_ms: millis_since(started),
                    flow: None,
                    ws_frames: Some(Vec::new()),
                    l4: None,
                })
            }
        };

        let is_cancelled = || self.job.cancelled();
        // `Sync` as well as `Fn`: the collected future crosses threads, and a
        // bare `&dyn Fn` is not `Sync`, which would make every probe future
        // non-`Send` and so unusable as the trait's `BoxFuture`.
        let cancelled: &(dyn Fn() -> bool + Sync) = &is_cancelled;
        let mut frames: Vec<Frame> = Vec::new();
        let mut over = false;
        for prerequisite in self.preceding_frames() {
            if !self.job.charge(1) {
                bail!("the job budget is exhausted");
            }
            if conn.send(prerequisite).await.is_err() {
                over = true;
                break;
            }
            let drained = drain_reply(&mut conn, window, deadline, cancelled).await;
            if drained.ended != CollectEnd::Window {
                // The conversation ended while catching up on the prerequisites
                // (a Close, a drop, the deadline, a cancel, or the collection
                // ceiling — `Limit` is data like `Transport`); what arrived is
                // the observation, and nothing more can be sent.
                frames.extend(drained.frames);
                over = true;
                break;
            }
        }
        if !over {
            let sent = match frame {
                Some(frame) => {
                    if !self.job.charge(1) {
                        bail!("the job budget is exhausted");
                    }
                    // A payload above the dial's frame cap is refused here
                    // without reaching the wire (tester finding F2); like any
                    // failed send, the conversation ends as data.
                    conn.send(frame).await.is_ok()
                }
                None => true,
            };
            if sent {
                frames.extend(conn.collect(window, deadline, cancelled).await.frames);
            }
        }
        frames.extend(conn.close().await);

        let elapsed_ms = millis_since(started);
        let status = conn.status();
        let headers = conn.response_headers().to_vec();
        // How many frames the dial's collection ceilings dropped (S5) — the
        // count only, never a payload, so an evidence flow that ends mid
        // exchange is explained rather than silently short.
        let unrecorded = conn.unrecorded();
        if unrecorded > 0 {
            tracing::debug!(unrecorded, "replay conversation truncated");
        }
        let body = text_body(&frames);
        let (handshake, conversation) =
            conn.into_flows(vec![format!("scan:{}", self.job.job_id())]);
        let flow = match self.job.profile().http.record_probes {
            RecordProbes::All => {
                let store = self.job.store();
                store.insert(Flow::Http(handshake.clone()));
                store.insert(Flow::WebSocket(conversation.clone()));
                Some(FlowRef(conversation.id))
            }
            RecordProbes::IssuesOnly => None,
        };
        self.hold(slot, handshake, conversation);

        Ok(ProbeResponse {
            status: Some(status),
            headers,
            body,
            elapsed_ms,
            flow,
            ws_frames: Some(frames),
            l4: None,
        })
    }

    /// Keep one conversation in memory for `held_flows()`.
    fn hold(&self, slot: HeldSlot, handshake: HttpFlow, conversation: WsFlow) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        match slot {
            HeldSlot::Baseline => held.baseline = Some((handshake, conversation)),
            HeldSlot::Probe => {
                held.probes.push_front((handshake, conversation));
                while held.probes.len() > HELD_PROBES {
                    held.probes.pop_back();
                }
            }
        }
    }
}

impl ProbeHost for WsProbeHost {
    /// The captured conversation replayed unchanged, dialled once and reused.
    fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            // The lock is held across the dial on purpose: two checks racing for
            // the baseline of one point must cost one dial, not two.
            let mut cached = self.baseline.lock().await;
            if let Some(response) = cached.as_ref() {
                return Ok(response.clone());
            }
            let response = self
                .conversation(
                    Attempt {
                        overrides: HandshakeOverrides::default(),
                        frame: self.chosen_frame(),
                        limits: self.dial_limits(),
                    },
                    HeldSlot::Baseline,
                )
                .await?;
            *cached = Some(response.clone());
            Ok(response)
        })
    }

    fn probe<'a>(&'a self, payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            let attempt = self.plan_probe(payload)?;
            self.conversation(attempt, HeldSlot::Probe).await
        })
    }

    fn probe_raw(&self, req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            let attempt = Attempt {
                overrides: self.raw_overrides(&req)?,
                frame: self.chosen_frame(),
                limits: self.dial_limits(),
            };
            self.conversation(attempt, HeldSlot::Probe).await
        })
    }

    fn marker(&self) -> String {
        self.job.marker()
    }

    fn budget_left(&self) -> u32 {
        self.job.budget_left()
    }

    fn deadline(&self) -> Instant {
        self.job.deadline()
    }

    fn profile(&self) -> &ScanProfile {
        self.job.profile()
    }

    fn cancelled(&self) -> bool {
        self.job.cancelled()
    }

    /// The job's budgeted client, lent for a bridge send (amendment 72b).
    fn client(&self) -> Option<Arc<dyn aitm_core::ProxyClient>> {
        Some(self.job.client())
    }

    /// `None`: a ws point is re-driven from a captured conversation, not from
    /// one captured HTTP flow (the handshake is in `held_flows`).
    fn captured(&self) -> Option<aitm_core::HttpFlow> {
        None
    }

    /// Debited against the one job budget, like every dial and frame.
    fn charge(&self, units: u32) -> bool {
        self.job.charge(units)
    }

    /// The baseline conversation first, then the probes newest first.
    fn held_flows(&self) -> Vec<Flow> {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let mut flows = Vec::with_capacity((held.probes.len() + 1) * 2);
        for (handshake, conversation) in held.baseline.iter().chain(held.probes.iter()) {
            flows.push(Flow::Http(handshake.clone()));
            flows.push(Flow::WebSocket(conversation.clone()));
        }
        flows
    }
}

/// Whether `payload` is the oversize check's pad request rather than data.
fn is_pad(payload: &Payload) -> bool {
    payload.mode == PayloadMode::Suffix && payload.value.starts_with(PAD_SENTINEL)
}

/// One captured message as a frame to send.
fn frame_of(message: &WsMessage) -> Frame {
    Frame {
        kind: kind_of(message.opcode),
        payload: message.data.clone(),
    }
}

/// The model frame kind a captured opcode replays as.
fn kind_of(opcode: WsOpcode) -> FrameKind {
    match opcode {
        WsOpcode::Text => FrameKind::Text,
        WsOpcode::Binary => FrameKind::Binary,
        WsOpcode::Ping => FrameKind::Ping,
        WsOpcode::Pong => FrameKind::Pong,
        WsOpcode::Close => FrameKind::Close,
    }
}

/// Milliseconds since `started`, saturating rather than wrapping.
fn millis_since(started: Instant) -> u32 {
    u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX)
}

/// The Text payloads of `frames`, concatenated and bounded at
/// [`MAX_MATCH_BODY`].
///
/// This is what a signature or reflection check matches on; the untruncated
/// frames stay in `ws_frames` for an oracle that needs them.
fn text_body(frames: &[Frame]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    for frame in frames.iter().filter(|frame| frame.kind == FrameKind::Text) {
        let room = MAX_MATCH_BODY.saturating_sub(body.len());
        if room == 0 {
            break;
        }
        body.extend(frame.payload.iter().take(room));
    }
    body
}

/// The scheme and authority of an absolute URL.
fn split_url(url: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if scheme.is_empty() || authority.is_empty() {
        return None;
    }
    Some((scheme, authority))
}

/// Read and discard the server's answer to one replayed prerequisite frame.
///
/// The oracle is what the *mutated* frame produced, so the answers to the
/// frames replayed ahead of it must not land in `ws_frames`. The wait ends on
/// the first answer and is bounded by the same reply window, so a server that
/// says nothing to a prerequisite costs one window and no more. A window that
/// ends any other way (a Close, a drop, the deadline, a cancel) is returned to
/// the caller: the conversation is over and its frames are the observation.
async fn drain_reply(
    conn: &mut WsConn,
    window: Duration,
    deadline: Instant,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> CollectOutcome {
    let until = Instant::now() + window;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return CollectOutcome {
                frames: Vec::new(),
                ended: CollectEnd::Window,
            };
        }
        let outcome = conn
            .collect(left.min(DRAIN_POLL), deadline, cancelled)
            .await;
        if !outcome.frames.is_empty() || outcome.ended != CollectEnd::Window {
            return outcome;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aitm_core::{Flow, FlowQuery, WsDir};
    use aitm_scan_model::{
        FlowRef, FrameKind, JobCtx, Payload, PayloadMode, ProbeHost, ProbeResponse, RawProbe,
        RecordProbes, MAX_MATCH_BODY,
    };
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::handshake::server::ErrorResponse;
    use tokio_tungstenite::tungstenite::http::StatusCode;
    use tokio_tungstenite::tungstenite::Message;

    use super::{pad_payload, WsProbeHost, PAD_SENTINEL};
    use crate::dialer::{WsDialer, DEFAULT_MAX_COLLECT_FRAMES};
    use crate::testing::{
        captured_conversation, echo_handler, handshake_header, host_for, ws_server,
        DuplexTransport, HandshakeDecision, ServerConn, TestJob,
    };
    use crate::transport::WsTransport;

    /// The fixture's first client frame, as it was captured.
    const HELLO: &[u8] = br#"{"type":"hello"}"#;

    /// The fixture's second client frame, the one the `msg` point lives in.
    const CHOSEN: &[u8] = br#"{"msg":"hi","user":"bob"}"#;

    /// A text payload in `mode`.
    fn text(value: &str, mode: PayloadMode) -> Payload {
        Payload {
            value: value.to_string(),
            mode,
            bytes: None,
        }
    }

    /// The frame kinds of a response, in order.
    fn kinds(response: &ProbeResponse) -> Vec<FrameKind> {
        response
            .ws_frames
            .as_ref()
            .expect("the ws lane always sets ws_frames")
            .iter()
            .map(|frame| frame.kind)
            .collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_replays_preceding_frames_then_the_mutated_one() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);

        let response = host
            .probe(&text("X", PayloadMode::Replace))
            .await
            .expect("the probe conversation succeeds");

        assert_eq!(
            log.received(),
            vec![HELLO.to_vec(), br#"{"msg":"X","user":"bob"}"#.to_vec()],
            "the frame before the chosen one is replayed unchanged, then the mutated one"
        );
        assert_eq!(response.status, Some(101));
        assert_eq!(response.body, br#"echo:{"msg":"X","user":"bob"}"#.to_vec());
        let frames = kinds(&response);
        assert_eq!(
            frames
                .iter()
                .filter(|kind| **kind == FrameKind::Text)
                .count(),
            1,
            "only the mutated frame's reply is the oracle's: {frames:?}"
        );
        assert_eq!(frames.last(), Some(&FrameKind::Close), "{frames:?}");
        assert!(
            response.elapsed_ms >= 300,
            "the probe waits out the 300 ms reply window, took {} ms",
            response.elapsed_ms
        );
        assert_eq!(response.flow, None, "issues_only holds the flow in memory");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn budget_is_charged_per_dial_and_frame() {
        let (transport, _log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);

        host.probe(&text("X", PayloadMode::Replace))
            .await
            .expect("the probe conversation succeeds");

        assert_eq!(
            job.charged(),
            3,
            "one unit for the dial, one for the replayed frame, one for the mutated frame"
        );
    }

    /// Amendment 72b: `client`, `charge` and `captured` are required, and the
    /// ws host answers them from its job.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_ws_host_lends_the_job_client_and_debits_its_budget() {
        let (transport, _log) = ws_server(None, echo_handler);
        let job = TestJob::new(10);
        let host = host_for("msg", &job, transport);

        let lent = host.client().expect("the ws host lends the job's client");
        assert!(
            Arc::ptr_eq(&lent, &job.client()),
            "the host lends the job's own budgeted client, not a second one"
        );
        assert!(host.charge(2), "two units out of ten are affordable");
        assert_eq!(job.charged(), 2, "the charge reaches the job's budget");
        assert_eq!(job.budget_left(), 8);
        assert!(
            host.captured().is_none(),
            "a ws point came from no captured HTTP flow"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn budget_exhausted_is_err_before_connect() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(0);
        let host = host_for("msg", &job, transport);

        let err = host
            .probe(&text("X", PayloadMode::Replace))
            .await
            .expect_err("a probe with no budget must not be sent");

        assert!(
            err.to_string().contains("budget"),
            "the error must name the budget: {err}"
        );
        assert_eq!(log.connections(), 0, "no socket is opened without budget");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_is_err_before_connect() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);
        job.cancel();

        let err = host
            .probe(&text("X", PayloadMode::Replace))
            .await
            .expect_err("a cancelled job must not dial");

        assert!(
            err.to_string().contains("cancelled"),
            "the error must say it was cancelled: {err}"
        );
        assert_eq!(log.connections(), 0, "no socket is opened after cancel");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn baseline_is_dialled_once() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);

        let first = host.baseline().await.expect("the baseline conversation");
        let second = host.baseline().await.expect("the cached baseline");

        assert_eq!(
            log.connections(),
            1,
            "the baseline is dialled once and reused"
        );
        assert_eq!(first.body, br#"echo:{"msg":"hi","user":"bob"}"#.to_vec());
        assert_eq!(second.body, br#"echo:{"msg":"hi","user":"bob"}"#.to_vec());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handshake_header_point_sets_or_strips() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("origin", &job, transport);

        host.probe(&text("https://attacker.invalid", PayloadMode::Replace))
            .await
            .expect("the foreign-origin probe");
        host.probe(&text("", PayloadMode::Replace))
            .await
            .expect("the stripped-origin probe");

        assert_eq!(
            handshake_header(&log, 0, "origin").as_deref(),
            Some("https://attacker.invalid"),
            "a non-empty payload replaces the header"
        );
        assert_eq!(
            handshake_header(&log, 1, "origin"),
            None,
            "an empty payload strips the header"
        );
        assert_eq!(
            log.received(),
            vec![HELLO.to_vec(), HELLO.to_vec()],
            "a handshake point replays its chosen frame unchanged, once per probe"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_raw_headers_are_overrides() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);

        host.probe_raw(RawProbe {
            method: "GET".to_string(),
            url: String::new(),
            headers: vec![
                ("Cookie".to_string(), String::new()),
                ("X-Test".to_string(), "1".to_string()),
            ],
            body: Vec::new(),
        })
        .await
        .expect("a raw probe at the captured authority");

        assert_eq!(
            handshake_header(&log, 0, "cookie"),
            None,
            "an empty value strips the header"
        );
        assert_eq!(
            handshake_header(&log, 0, "x-test").as_deref(),
            Some("1"),
            "a value sets the header"
        );

        let foreign = host
            .probe_raw(RawProbe {
                method: "GET".to_string(),
                url: "ws://other.test/ws".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await;
        assert!(
            foreign.is_err(),
            "a raw probe may not retarget the authority"
        );
        assert_eq!(log.connections(), 1, "the foreign probe never dialled");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refused_upgrade_is_ok_with_status() {
        // The `Err` half is tungstenite's own `ErrorResponse`; the
        // `HandshakeDecision` contract fixes it, so it cannot be boxed away.
        #[allow(clippy::result_large_err)]
        let decide: HandshakeDecision = Arc::new(|_request| {
            let mut response = ErrorResponse::new(Some("unauthorized".to_string()));
            *response.status_mut() = StatusCode::UNAUTHORIZED;
            Err(response)
        });
        let (transport, _log) = ws_server(Some(decide), echo_handler);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);

        let response = host
            .probe(&text("X", PayloadMode::Replace))
            .await
            .expect("a refused upgrade is data, not an error");

        assert_eq!(response.status, Some(401));
        assert_eq!(
            response.ws_frames.as_ref().map(Vec::len),
            Some(0),
            "a refused upgrade carries no frames"
        );
        assert!(response.body.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn issues_only_keeps_flows_in_memory_not_store() {
        let (transport, _log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);

        host.baseline().await.expect("the baseline");
        host.probe(&text("a", PayloadMode::Replace))
            .await
            .expect("the first probe");
        host.probe(&text("b", PayloadMode::Replace))
            .await
            .expect("the second probe");

        assert_eq!(
            job.store().query(&FlowQuery::default()).len(),
            0,
            "issues_only never inserts a probe conversation"
        );
        let held = host.held_flows();
        assert_eq!(held.len(), 6, "three conversations, two flows each");
        for flow in &held {
            assert!(flow.metadata().is_replay, "every held flow is a replay");
            assert_eq!(flow.metadata().marks, vec!["scan:job-1".to_string()]);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn record_all_inserts_each_conversation() {
        let (transport, _log) = ws_server(None, echo_handler);
        let job = TestJob::with(100, |profile| {
            profile.http.record_probes = RecordProbes::All;
        });
        let host = host_for("msg", &job, transport);

        let response = host
            .probe(&text("X", PayloadMode::Replace))
            .await
            .expect("the probe conversation");

        let store = job.store();
        let ids = store.query(&FlowQuery::default());
        assert_eq!(ids.len(), 2, "the handshake and the conversation");
        let flows: Vec<Flow> = ids
            .iter()
            .filter_map(|id| store.get(*id))
            .collect::<Vec<_>>();
        let ws_id = flows
            .iter()
            .find_map(|flow| match flow {
                Flow::WebSocket(ws) => Some(ws.id),
                Flow::Http(_) => None,
            })
            .expect("one WebSocket flow was recorded");
        assert!(
            flows.iter().any(|flow| matches!(flow, Flow::Http(_))),
            "one HTTP handshake flow was recorded"
        );
        assert_eq!(response.flow, Some(FlowRef(ws_id)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn held_ring_is_bounded() {
        let (transport, _log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);

        for nth in 1..=20 {
            host.probe(&text(&format!("p{nth}"), PayloadMode::Replace))
                .await
                .unwrap_or_else(|err| panic!("probe {nth} failed: {err}"));
        }

        let held = host.held_flows();
        assert_eq!(held.len(), 32, "sixteen conversations, two flows each");
        let newest = held
            .get(1)
            .and_then(|flow| match flow {
                Flow::WebSocket(ws) => Some(ws.clone()),
                Flow::Http(_) => None,
            })
            .expect("the newest held conversation is first");
        assert!(
            newest.messages.iter().any(|message| {
                message.dir == WsDir::ClientToServer
                    && message.data == br#"{"msg":"p20","user":"bob"}"#.to_vec()
            }),
            "the ring keeps the newest probe, not the oldest"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn body_is_bounded() {
        let (transport, _log) = ws_server(None, |conn: ServerConn| async move {
            let mut ws = conn.ws().await;
            while let Some(Ok(message)) = ws.next().await {
                match message {
                    Message::Text(received) => {
                        conn.record(received.as_bytes().to_vec());
                        if ws
                            .send(Message::text("a".repeat(2 * 1024 * 1024)))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        });
        let job = TestJob::with(100, |profile| {
            profile.ws.max_frame_bytes = 4 << 20;
        });
        let host = host_for("msg", &job, transport);

        let response = host
            .probe(&text("X", PayloadMode::Replace))
            .await
            .expect("the probe conversation");

        assert_eq!(
            response.body.len(),
            MAX_MATCH_BODY,
            "the body a check matches on is bounded"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pad_sentinel_pads_to_twice_largest_frame() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);

        let response = host.probe(&pad_payload()).await.expect("the padded probe");

        let sent = log.received();
        assert_eq!(sent.first().map(Vec::len), Some(HELLO.len()));
        assert_eq!(
            sent.get(1).map(Vec::len),
            Some(2 * CHOSEN.len()),
            "the padded frame is exactly twice the largest captured client frame"
        );

        assert!(
            !String::from_utf8_lossy(&response.body).contains("aitm-pad"),
            "the sentinel never leaves the process"
        );
        for flow in host.held_flows() {
            if let Flow::WebSocket(ws) = flow {
                for message in &ws.messages {
                    assert!(
                        !String::from_utf8_lossy(&message.data).contains("aitm-pad"),
                        "the sentinel never reaches a held flow"
                    );
                }
            }
        }
        assert!(
            PAD_SENTINEL.starts_with('\u{0}'),
            "the sentinel cannot collide with a real payload"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pad_is_capped_by_the_profile_frame_limit() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::with(100, |profile| {
            profile.ws.max_frame_bytes = 40;
        });
        let host = host_for("msg", &job, transport);

        host.probe(&pad_payload()).await.expect("the padded probe");

        assert_eq!(
            log.received().get(1).map(Vec::len),
            Some(40),
            "the pad is capped by the profile's max_frame_bytes"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pad_probe_raises_the_dial_limit_so_an_echo_is_readable() {
        // The pad fills the profile's frame cap exactly, so a server that
        // echoes it answers with *more* than the cap. If the dial used the
        // profile cap as its read limit, our own reader would error and the
        // conversation would end `Transport` with no Close — which is exactly
        // the shape `ws-oversize-frame` reads as "the server dropped us". The
        // drop has to come from the server, never from us.
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::with(100, |profile| {
            profile.ws.max_frame_bytes = 40;
        });
        let host = host_for("msg", &job, transport);

        let response = host.probe(&pad_payload()).await.expect("the padded probe");

        assert_eq!(
            log.received().get(1).map(Vec::len),
            Some(40),
            "the pad target still comes from the profile cap"
        );
        let frames = response
            .ws_frames
            .as_ref()
            .expect("the ws lane always sets ws_frames");
        let texts: Vec<usize> = frames
            .iter()
            .filter(|frame| frame.kind == FrameKind::Text)
            .map(|frame| frame.payload.len())
            .collect();
        assert_eq!(
            texts,
            vec!["echo:".len() + 40],
            "the echo of the padded frame must be readable: {frames:?}"
        );
        assert_eq!(
            frames.last().map(|frame| frame.kind),
            Some(FrameKind::Close),
            "the window ended on the peer's Close, not on a read error: {frames:?}"
        );
    }

    // --- Specs and frames that do not fit (tester, stage 5) --------------
    //
    // `WsProbeHost::new`'s three refusals and the three ways a frame can fail
    // to leave. The documented reason for all of them is the same: a probe
    // that silently sends nothing reads to a check as a clean target, so each
    // one must be an `Err` the check turns into `Inconclusive`, or a response
    // that carries no reply.

    use aitm_core::{WsMessage, WsOpcode};

    use crate::types::{Locator, PointSpec};

    /// The message of a `WsProbeHost::new` that was expected to refuse.
    ///
    /// `WsProbeHost` deliberately has no `Debug` (nothing about a probe host
    /// may be printed), so `expect_err` cannot be used on its constructor.
    fn build_error(built: anyhow::Result<WsProbeHost>, why: &str) -> String {
        match built {
            Ok(_) => panic!("{why}"),
            Err(err) => err.to_string(),
        }
    }

    /// A host over the fixture built straight from `spec`, bypassing discovery.
    fn host_with_spec(
        spec_of: impl FnOnce(&aitm_core::HttpFlow, &aitm_core::WsFlow) -> PointSpec,
        edit_ws: impl FnOnce(&mut aitm_core::WsFlow),
        job: &Arc<TestJob>,
        transport: Arc<DuplexTransport>,
    ) -> anyhow::Result<WsProbeHost> {
        let (handshake, mut ws) = captured_conversation();
        edit_ws(&mut ws);
        let spec = spec_of(&handshake, &ws);
        let point = crate::testing::point(
            aitm_scan_model::InsertionKind::WsJsonValue,
            "msg",
            Some("msg"),
            spec.clone(),
        );
        WsProbeHost::new(
            point,
            spec,
            handshake,
            ws,
            Arc::new(WsDialer::new(transport as Arc<dyn WsTransport>)),
            Arc::clone(job) as Arc<dyn JobCtx>,
        )
    }

    #[test]
    fn a_spec_naming_a_server_frame_is_rejected() {
        let (transport, _log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);

        // Message 2 of the fixture is the server's reply.
        let built = host_with_spec(
            |handshake, ws| PointSpec {
                ws_flow: ws.id,
                handshake: handshake.id,
                frame_index: Some(2),
                locator: Locator::JsonPath("echo".to_string()),
            },
            |_| {},
            &job,
            transport,
        );

        assert_eq!(
            build_error(built, "only client->server frames can be re-sent"),
            "frame 2 is not a client->server frame; only those are re-sent"
        );
    }

    #[test]
    fn a_spec_past_the_end_of_the_conversation_is_rejected() {
        let (transport, _log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);

        let built = host_with_spec(
            |handshake, ws| PointSpec {
                ws_flow: ws.id,
                handshake: handshake.id,
                frame_index: Some(99),
                locator: Locator::JsonPath("msg".to_string()),
            },
            |_| {},
            &job,
            transport,
        );

        assert_eq!(
            build_error(built, "a frame index must address a captured frame"),
            "frame 99 is past the end of the captured conversation"
        );
    }

    #[test]
    fn a_frame_locator_without_an_index_is_rejected() {
        let (transport, _log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);

        let built = host_with_spec(
            |handshake, ws| PointSpec {
                ws_flow: ws.id,
                handshake: handshake.id,
                frame_index: None,
                locator: Locator::JsonPath("msg".to_string()),
            },
            |_| {},
            &job,
            transport,
        );

        assert_eq!(
            build_error(built, "a point inside a frame needs its frame"),
            "a point inside a frame needs the index of the frame it was found in"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_json_path_that_is_not_in_the_frame_errs_before_any_dial() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_with_spec(
            |handshake, ws| PointSpec {
                ws_flow: ws.id,
                handshake: handshake.id,
                frame_index: Some(1),
                locator: Locator::JsonPath("gone".to_string()),
            },
            |_| {},
            &job,
            transport,
        )
        .expect("the spec itself is well formed; only the path is wrong");

        let err = host
            .probe(&text("X", PayloadMode::Replace))
            .await
            .expect_err("a payload that cannot be placed is never sent");

        assert!(
            err.to_string().contains("gone"),
            "the error must name the path it could not find: {err}"
        );
        assert_eq!(log.connections(), 0, "nothing is dialled for a dead point");
        assert_eq!(job.charged(), 0, "nothing is charged for a dead point");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_capture_with_no_client_frame_still_dials_the_handshake() {
        // The empty-conversation case: a capture whose only message came from
        // the server. The handshake point has no frame to replay, so the probe
        // is a bare upgrade — and must still be a `ProbeResponse`, not an error.
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_with_spec(
            |handshake, ws| PointSpec {
                ws_flow: ws.id,
                handshake: handshake.id,
                frame_index: None,
                locator: Locator::HandshakeHeader("origin".to_string()),
            },
            |ws| {
                ws.messages
                    .retain(|message| message.dir == WsDir::ServerToClient)
            },
            &job,
            transport,
        )
        .expect("a handshake point needs no frame");

        let response = host
            .probe(&text("https://attacker.invalid", PayloadMode::Replace))
            .await
            .expect("a handshake-only probe is a conversation like any other");

        assert_eq!(response.status, Some(101));
        assert!(response.body.is_empty(), "{:?}", response.body);
        assert_eq!(log.received(), Vec::<Vec<u8>>::new(), "no frame was sent");
        assert_eq!(log.connections(), 1);
        assert_eq!(job.charged(), 1, "one unit for the dial and no frames");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_profile_frame_cap_bounds_writes_too() {
        // Tester finding F2: `DialLimits.max_frame_bytes` becomes tungstenite's
        // read limit *and* the dialer's own write limit. A probe payload above
        // the profile cap is refused before it reaches the wire; the
        // conversation ends there as data (status 101, no reply), the way any
        // failed send does, rather than as an error.
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::with(100, |profile| {
            profile.ws.max_frame_bytes = 64;
        });
        let host = host_with_spec(
            |handshake, ws| PointSpec {
                ws_flow: ws.id,
                handshake: handshake.id,
                frame_index: Some(0),
                locator: Locator::WholeText,
            },
            |ws| {
                ws.messages.truncate(1);
            },
            &job,
            transport,
        )
        .expect("the spec addresses the one client frame");

        let response = host
            .probe(&text(&"B".repeat(4096), PayloadMode::Replace))
            .await
            .expect("a frame the write limit refuses is data, not an error");

        assert_eq!(
            log.received().iter().map(Vec::len).collect::<Vec<_>>(),
            Vec::<usize>::new(),
            "the 4096-byte frame never reaches the wire at a 64-byte cap"
        );
        assert_eq!(response.status, Some(101));
        assert_eq!(response.body, Vec::<u8>::new());
        assert_eq!(
            response.ws_frames.as_ref().map(|frames| frames
                .iter()
                .filter(|frame| frame.kind == FrameKind::Text)
                .count()),
            Some(0),
            "no text frame was exchanged: {:?}",
            response.ws_frames
        );
        assert_eq!(job.charged(), 2, "the dial and the frame");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_flood_of_replies_is_bounded_as_data() {
        // Security finding S5 at the host: a server answering one frame with
        // a thousand frames yields an `Ok` probe response, status 101, whose
        // frames are bounded by the dial's collection ceiling — once for the
        // reply window and once for the close window (`WsConn::close` waits
        // for the peer's Close through the same bounded collection), so 512
        // of the thousand, and never the Close that was queued behind them.
        // The recorded replay conversation is capped at the ceiling itself.
        let (transport, _log) = ws_server(None, |conn: ServerConn| async move {
            let mut ws = conn.ws().await;
            while let Some(Ok(message)) = ws.next().await {
                match message {
                    Message::Text(_) => {
                        for _ in 0..1000 {
                            if ws.send(Message::text("r")).await.is_err() {
                                return;
                            }
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        });
        let job = TestJob::with(100, |profile| {
            profile.ws.reply_window_ms = 5_000;
        });
        let host = host_for("msg", &job, transport);

        let response = host
            .probe(&text("X", PayloadMode::Replace))
            .await
            .expect("a flooded reply is data");

        assert_eq!(response.status, Some(101));
        let frames = response
            .ws_frames
            .as_ref()
            .expect("the ws lane always sets ws_frames");
        assert_eq!(
            frames
                .iter()
                .filter(|frame| frame.kind == FrameKind::Text)
                .count(),
            2 * DEFAULT_MAX_COLLECT_FRAMES,
            "one ceiling for the reply window, one for the close window"
        );
        assert_eq!(frames.len(), 2 * DEFAULT_MAX_COLLECT_FRAMES);
        let recorded = host
            .held_flows()
            .into_iter()
            .find_map(|flow| match flow {
                Flow::WebSocket(ws) => Some(ws),
                Flow::Http(_) => None,
            })
            .expect("the probe conversation is held");
        assert_eq!(
            recorded.messages.len(),
            DEFAULT_MAX_COLLECT_FRAMES,
            "the replay flow stops recording at the ceiling"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_expired_job_does_not_dial() {
        let (transport, _log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        job.expire();
        let host = host_for("msg", &job, transport.clone());

        let err = host
            .probe(&text("X", PayloadMode::Replace))
            .await
            .expect_err("a job past its deadline sends nothing");

        assert!(err.to_string().contains("deadline"), "{err}");
        assert!(transport.connects().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_non_utf8_text_prerequisite_ends_the_conversation_as_data() {
        // A captured Text frame whose bytes are not UTF-8 cannot be replayed
        // (RFC 6455 section 5.6). The conversation stops there and returns what
        // arrived, so a check reads "no reply", never a crash.
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_with_spec(
            |handshake, ws| PointSpec {
                ws_flow: ws.id,
                handshake: handshake.id,
                frame_index: Some(1),
                locator: Locator::JsonPath("msg".to_string()),
            },
            |ws| {
                ws.messages[0] = WsMessage {
                    dir: WsDir::ClientToServer,
                    opcode: WsOpcode::Text,
                    data: vec![0xff, 0xfe, 0xfd],
                    timestamp: ws.messages[0].timestamp,
                    injected: false,
                };
            },
            &job,
            transport,
        )
        .expect("the spec is well formed; the captured bytes are not");

        let response = host
            .probe(&text("X", PayloadMode::Replace))
            .await
            .expect("an unsendable prerequisite is data, not an error");

        assert_eq!(response.status, Some(101));
        assert_eq!(
            log.received(),
            Vec::<Vec<u8>>::new(),
            "the bad prerequisite stops the replay before the mutated frame"
        );
        assert_eq!(
            response.ws_frames.as_ref().map(|frames| frames
                .iter()
                .filter(|frame| frame.kind == FrameKind::Text)
                .count()),
            Some(0),
            "nothing was echoed: {:?}",
            response.ws_frames
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_cancel_during_the_reply_window_returns_what_arrived() {
        // Cancellation mid-collect, not before the dial: the probe must come
        // back well inside the window with the frames it already had.
        let (transport, _log) = ws_server(None, echo_handler);
        let job = TestJob::with(100, |profile| {
            profile.ws.reply_window_ms = 10_000;
        });
        let host = host_for("msg", &job, transport);
        let cancel_job = Arc::clone(&job);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            cancel_job.cancel();
        });

        let started = std::time::Instant::now();
        let response = host
            .probe(&text("X", PayloadMode::Replace))
            .await
            .expect("a cancel after the dial returns what arrived");
        let took = started.elapsed();

        assert!(
            took < std::time::Duration::from_secs(5),
            "a cancelled collect must not wait out a 10 s window, took {took:?}"
        );
        assert_eq!(response.status, Some(101));
        assert_eq!(
            response.body,
            br#"echo:{"msg":"X","user":"bob"}"#.to_vec(),
            "the frames already collected are kept"
        );
    }
}
