//! Insertion points, site nodes and probe I/O types (spec D2, D8.1). Task 5 of the T1a plan owns this file.
//!
//! Two kinds of type live here. [`InsertionPoint`], [`SiteNode`] and [`ParamRef`]
//! are **wire** types: `scan.sitemap` returns them and every frontend renders
//! them, so their serde shape is contract. [`Payload`], [`RawProbe`],
//! [`ProbeResponse`], [`Frame`] and [`L4Reply`] are **in-process** types passed
//! between a lane's `ProbeHost` and a `Check` (plan call A8); they carry raw
//! bodies and unredacted headers, so they deliberately have no serde derives and
//! cannot be serialised onto the bus by accident. Their `Debug` impls are
//! hand-written to print header *names* with `<redacted>` values and bodies as
//! byte lengths (as `SessionMaterial` does), so a `{:?}` in a log line cannot
//! leak a cookie, a token or a response body either.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::check::L4Oracle;
use crate::ids::{FlowRef, NodeId};
use crate::vocab::{InsertionKind, LaneKind, PayloadMode, PointTrait};

/// The largest response body a check matches against: 1 MiB (spec D8.1).
///
/// A lane bounds `ProbeResponse::body` at this before handing it to a check, so
/// a hostile target cannot make matching unbounded work.
pub const MAX_MATCH_BODY: usize = 1 << 20;

/// One place in a request where a payload can be inserted (spec D2).
///
/// A point is lane-scoped: the lane that discovered it is the only one that can
/// mutate it, and `kind` is always one the lane produces.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InsertionPoint {
    /// Stable identifier within a job.
    pub id: String,
    /// The lane that discovered the point and knows how to mutate it.
    pub lane: LaneKind,
    /// Where in the request the point sits.
    pub kind: InsertionKind,
    /// The parameter, header, cookie or field name.
    pub name: String,
    /// For `json_value`, `xml_*` and `l4_field`: the dotted/bracket field path.
    #[serde(default)]
    pub path: Option<String>,
    /// The observed value, already redacted by the lane (`aitm_core::redact`).
    #[serde(default)]
    pub example: Option<String>,
    /// The captured flow the point was derived from.
    #[serde(default)]
    pub flow: Option<FlowRef>,
    /// The site-map node the point belongs to.
    #[serde(default)]
    pub site_node: Option<NodeId>,
    /// What the observed value looks like; the scheduler aims checks with it.
    #[serde(default)]
    pub traits: Vec<PointTrait>,
    /// How many site nodes carry the same `(kind, name)` pair.
    pub frequency: u32,
    /// The request method, for the D4 Rhai point map (plan call A6).
    #[serde(default)]
    pub method: Option<String>,
    /// The request URL, for the D4 Rhai point map (plan call A6).
    #[serde(default)]
    pub url: Option<String>,
}

/// A `(kind, name)` pair a site node carries (spec D8.1 `params`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ParamRef {
    /// Where in the request the parameter sits.
    pub kind: InsertionKind,
    /// The parameter name.
    pub name: String,
}

/// One node of the site map: a method and path template on an origin.
///
/// This is the union of D3's `scan.sitemap` node and D8.1's `SiteNode` (plan call
/// A7); `params`, `auth`, `points` and `audited` are absent from an early crawl
/// result and default rather than failing the parse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SiteNode {
    /// Stable identifier within a job.
    pub id: NodeId,
    /// The request method.
    pub method: String,
    /// `http` or `https`.
    pub scheme: String,
    /// The origin host.
    pub host: String,
    /// The origin port.
    pub port: u16,
    /// The path with variable segments collapsed (`/account/{id}`).
    pub path_template: String,
    /// The captured flows that mapped to this node.
    #[serde(default)]
    pub flows: Vec<FlowRef>,
    /// The parameters observed on this node.
    #[serde(default)]
    pub params: Vec<ParamRef>,
    /// Whether the node was reached with session material applied.
    #[serde(default)]
    pub auth: bool,
    /// How many insertion points the node yielded.
    #[serde(default)]
    pub points: u32,
    /// Whether the audit phase has finished with this node.
    #[serde(default)]
    pub audited: bool,
}

/// `Debug` helper: header names with every value replaced by `<redacted>`.
fn redact_headers(pairs: &[(String, String)]) -> Vec<String> {
    pairs
        .iter()
        .map(|(name, _)| format!("{name}=<redacted>"))
        .collect()
}

/// `Debug` helper: a body or payload shown only as its length.
fn byte_len(bytes: &[u8]) -> String {
    format!("<{} bytes>", bytes.len())
}

/// A payload a check asks its `ProbeHost` to insert. In-process only (call A8).
///
/// `Debug` prints `value` and `bytes` as byte lengths, never their contents.
#[derive(Clone)]
pub struct Payload {
    /// The textual payload.
    pub value: String,
    /// How it combines with the point's existing value.
    pub mode: PayloadMode,
    /// Raw bytes, when the payload is not valid text (binary WS frames, L4).
    pub bytes: Option<Vec<u8>>,
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Payload")
            .field("value", &byte_len(self.value.as_bytes()))
            .field("mode", &self.mode)
            .field("bytes", &self.bytes.as_deref().map(byte_len))
            .finish()
    }
}

/// A fully specified request a check builds itself. In-process only (call A8).
///
/// `Debug` prints header names with `<redacted>` values and the body as a length.
#[derive(Clone)]
pub struct RawProbe {
    /// The request method.
    pub method: String,
    /// The absolute request URL.
    pub url: String,
    /// Request headers, in order; duplicates allowed.
    pub headers: Vec<(String, String)>,
    /// The request body.
    pub body: Vec<u8>,
}

impl fmt::Debug for RawProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawProbe")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &redact_headers(&self.headers))
            .field("body", &byte_len(&self.body))
            .finish()
    }
}

/// What a probe got back. In-process only (call A8).
///
/// `body` is bounded at [`MAX_MATCH_BODY`] by the lane before a check sees it.
/// `Debug` prints header names with `<redacted>` values and the body as a length.
#[derive(Clone)]
pub struct ProbeResponse {
    /// The HTTP status, absent for lanes that have none.
    pub status: Option<u16>,
    /// Response headers, in order.
    pub headers: Vec<(String, String)>,
    /// The response body, bounded at [`MAX_MATCH_BODY`].
    pub body: Vec<u8>,
    /// Wall-clock time the probe took.
    pub elapsed_ms: u32,
    /// The flow the probe produced, when the lane held one.
    pub flow: Option<FlowRef>,
    /// Frames observed in the reply window, for the WebSocket lane.
    pub ws_frames: Option<Vec<Frame>>,
    /// The layer 4 reply, for the L4 lanes.
    pub l4: Option<L4Reply>,
}

impl fmt::Debug for ProbeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeResponse")
            .field("status", &self.status)
            .field("headers", &redact_headers(&self.headers))
            .field("body", &byte_len(&self.body))
            .field("elapsed_ms", &self.elapsed_ms)
            .field("flow", &self.flow)
            .field("ws_frames", &self.ws_frames)
            .field("l4", &self.l4)
            .finish()
    }
}

/// One WebSocket frame. In-process only (call A8).
///
/// `Debug` prints the payload as a length, never its contents.
#[derive(Clone)]
pub struct Frame {
    /// The frame's opcode class.
    pub kind: FrameKind,
    /// The frame payload.
    pub payload: Vec<u8>,
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("kind", &self.kind)
            .field("payload", &byte_len(&self.payload))
            .finish()
    }
}

/// The WebSocket opcode classes a lane surfaces. In-process only (call A8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameKind {
    /// A text frame.
    Text,
    /// A binary frame.
    Binary,
    /// A ping control frame.
    Ping,
    /// A pong control frame.
    Pong,
    /// A close control frame.
    Close,
}

/// What an L4 case got back, with the oracle's reading of it. In-process (A8).
#[derive(Debug, Clone)]
pub struct L4Reply {
    /// The bytes received, empty on silence.
    pub bytes: Vec<u8>,
    /// How the oracle classified the reaction.
    pub oracle: L4Oracle,
    /// Wall-clock time from send to reply or timeout.
    pub elapsed_ms: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insertion_point_round_trips() {
        let point = InsertionPoint {
            id: "p-1".into(),
            lane: LaneKind::Http,
            kind: InsertionKind::JsonValue,
            name: "city".into(),
            path: Some("profile.address.city".into()),
            example: Some("Lisbon".into()),
            flow: None,
            site_node: Some("n1".into()),
            traits: vec![PointTrait::Json],
            frequency: 3,
            method: Some("POST".into()),
            url: Some("http://127.0.0.1:8080/account".into()),
        };

        let json = serde_json::to_string(&point).expect("serializes");
        assert!(json.contains(r#""kind":"json_value""#), "{json}");

        let back: InsertionPoint = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, point);
        assert_eq!(back.path.as_deref(), Some("profile.address.city"));
        assert_eq!(back.traits, vec![PointTrait::Json]);
        assert_eq!(back.frequency, 3);
    }

    #[test]
    fn site_node_tolerates_missing_optional_keys() {
        let node: SiteNode = serde_json::from_str(
            r#"{"id":"n1","method":"GET","scheme":"http","host":"127.0.0.1","port":8080,"path_template":"/account/{id}","flows":[]}"#,
        )
        .expect("deserializes");

        assert_eq!(node.id, "n1");
        assert_eq!(node.method, "GET");
        assert_eq!(node.port, 8080);
        assert_eq!(node.path_template, "/account/{id}");
        assert!(node.params.is_empty());
        assert!(!node.auth);
        assert_eq!(node.points, 0);
        assert!(!node.audited);
    }

    /// Panel S3 — the in-process probe types carry unredacted headers and raw
    /// bodies; their `Debug` must print header *names* with `<redacted>` values
    /// and bodies as byte lengths, so a `{:?}` in a log line cannot leak a
    /// cookie or a `set-cookie` value (mirrors `SessionMaterial`).
    #[test]
    fn probe_types_debug_redacts_header_values_and_bodies() {
        let probe = RawProbe {
            method: "GET".into(),
            url: "http://127.0.0.1:8080/account".into(),
            headers: vec![("cookie".into(), "sid=s3cr3t".into())],
            body: b"body-s3cr3t".to_vec(),
        };
        let shown = format!("{probe:?}");
        assert!(shown.contains("cookie"), "header name kept: {shown}");
        assert!(shown.contains("<redacted>"), "value redacted: {shown}");
        assert!(!shown.contains("s3cr3t"), "value leaked: {shown}");
        assert!(shown.contains("11 bytes"), "body as a length: {shown}");

        let response = ProbeResponse {
            status: Some(200),
            headers: vec![("set-cookie".into(), "sid=s3cr3t; HttpOnly".into())],
            body: b"<html>s3cr3t</html>".to_vec(),
            elapsed_ms: 12,
            flow: None,
            ws_frames: Some(vec![Frame {
                kind: FrameKind::Text,
                payload: b"s3cr3t".to_vec(),
            }]),
            l4: None,
        };
        let shown = format!("{response:?}");
        assert!(shown.contains("set-cookie"), "header name kept: {shown}");
        assert!(shown.contains("<redacted>"), "value redacted: {shown}");
        assert!(!shown.contains("s3cr3t"), "value leaked: {shown}");
        assert!(shown.contains("19 bytes"), "body as a length: {shown}");
        assert!(
            shown.contains("6 bytes"),
            "frame payload as a length: {shown}"
        );
        assert!(shown.contains("Text"), "frame kind kept: {shown}");

        let payload = Payload {
            value: "' OR 's3cr3t'='s3cr3t".into(),
            mode: PayloadMode::Replace,
            bytes: Some(vec![0xde, 0xad]),
        };
        let shown = format!("{payload:?}");
        assert!(!shown.contains("s3cr3t"), "payload text leaked: {shown}");
        assert!(shown.contains("21 bytes"), "value as a length: {shown}");
        assert!(shown.contains("2 bytes"), "bytes as a length: {shown}");
        assert!(shown.contains("Replace"), "mode kept: {shown}");
    }

    /// Panel Q5 — `FrameKind` is a plain opcode class: copyable, comparable and
    /// hashable like every other vocabulary enum.
    #[test]
    fn frame_kind_is_copy_eq_hash() {
        let kind = FrameKind::Binary;
        let copy = kind;
        assert_eq!(kind, copy);
        assert_ne!(FrameKind::Ping, FrameKind::Pong);
        let set: std::collections::HashSet<FrameKind> =
            [FrameKind::Text, FrameKind::Text, FrameKind::Close]
                .into_iter()
                .collect();
        assert_eq!(set.len(), 2);
    }
}
