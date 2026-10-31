//! Task 2: core flow-model types (`HeaderMap`, `Body`, `HttpFlow`, …).

use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpVersion,
    InterceptState, StreamBody,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn headermap_case_insensitive() {
    let mut h = HeaderMap::new();
    h.set("Content-Type", "text/html");
    assert_eq!(h.get("content-type"), Some("text/html"));
}

#[test]
fn headermap_preserves_duplicate_order() {
    let mut h = HeaderMap::new();
    h.set("Set-Cookie", "a=1");
    h.set("Set-Cookie", "b=2");
    let cookies: Vec<&str> = h
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v)
        .collect();
    assert_eq!(cookies, ["a=1", "b=2"]);
}

#[test]
fn httpflow_construct() {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let request = HttpRequest {
        method: "GET".into(),
        scheme: "https".into(),
        authority: "ex.test".into(),
        path: "/a".into(),
        version: HttpVersion::Http11,
        headers: HeaderMap::new(),
        body: Body::Empty,
        timestamp: SystemTime::now(),
    };
    let flow = HttpFlow {
        id: FlowId::new(),
        request,
        response: None,
        client_conn: ConnInfo {
            peer: addr,
            sni: None,
            alpn: None,
            tls: true,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    };

    assert_eq!(flow.request.method, "GET");
    assert!(flow.response.is_none());
    assert!(matches!(flow.intercept, InterceptState::Observed));

    let wrapped = Flow::Http(flow);
    assert!(matches!(wrapped, Flow::Http(_)));
}

/// `Body::buffered_len` is the size `flow.get` and the flow pushes report: the
/// buffered byte count, `Some(0)` for no body, and `None` while the body is still
/// streaming from the wire and its size is not known yet.
#[test]
fn body_buffered_len_is_the_buffered_size_and_none_while_streaming() {
    assert_eq!(Body::Empty.buffered_len(), Some(0));
    assert_eq!(Body::Bytes(vec![0; 2048]).buffered_len(), Some(2048));
    assert_eq!(Body::Streamed(StreamBody).buffered_len(), None);
}

/// `FlowMeta::started_at_ms` is `created` as whole milliseconds since the Unix
/// epoch (the fraction of a millisecond dropped); a clock before the epoch is
/// `None`, never a negative number.
#[test]
fn flow_meta_started_at_ms_is_created_in_whole_epoch_millis_or_none() {
    let timed = FlowMeta {
        created: UNIX_EPOCH + Duration::from_millis(1_761_908_698_120),
        ..FlowMeta::default()
    };
    assert_eq!(timed.started_at_ms(), Some(1_761_908_698_120));

    let fractional = FlowMeta {
        created: UNIX_EPOCH + Duration::from_micros(1_761_908_698_120_900),
        ..FlowMeta::default()
    };
    assert_eq!(
        fractional.started_at_ms(),
        Some(1_761_908_698_120),
        "whole milliseconds: the 900 µs fraction is dropped, not rounded up"
    );

    let before_epoch = FlowMeta {
        created: UNIX_EPOCH - Duration::from_secs(1),
        ..FlowMeta::default()
    };
    assert_eq!(before_epoch.started_at_ms(), None);
}

/// `FlowMeta::duration_ms` is `duration` in whole milliseconds, saturated at
/// `i64::MAX` rather than wrapped or truncated; `None` while the flow is in
/// flight or its end is unknown.
#[test]
fn flow_meta_duration_ms_is_whole_millis_saturated_or_none() {
    let timed = FlowMeta {
        duration: Some(Duration::from_millis(412)),
        ..FlowMeta::default()
    };
    assert_eq!(timed.duration_ms(), Some(412));

    let in_flight = FlowMeta {
        duration: None,
        ..FlowMeta::default()
    };
    assert_eq!(in_flight.duration_ms(), None);

    let absurd = FlowMeta {
        duration: Some(Duration::MAX),
        ..FlowMeta::default()
    };
    assert_eq!(absurd.duration_ms(), Some(i64::MAX));
}

/// Tester addition (spec D7: `started_at_ms` is `created` since `UNIX_EPOCH` in
/// whole ms, "saturated to `i64::MAX`"). Oversized input: a clock so far in the
/// future that its millisecond count exceeds `i64` is `Some(i64::MAX)`, never a
/// wrapped or truncated number. `duration_ms` has its own saturation test; this
/// pins the rule for `started_at` so the two cannot drift apart.
#[test]
fn flow_meta_started_at_ms_saturates_a_far_future_clock() {
    // ~1.1 billion years. Unix-like `SystemTime` (i64 seconds) represents it; a
    // platform whose clock type cannot has no way to reach the path, so there
    // is nothing to check there.
    let Some(far_future) = UNIX_EPOCH.checked_add(Duration::from_secs(1 << 55)) else {
        return;
    };
    assert!(
        Duration::from_secs(1 << 55).as_millis() > i64::MAX as u128,
        "fixture must overflow i64 milliseconds to exercise saturation"
    );
    let meta = FlowMeta {
        created: far_future,
        ..FlowMeta::default()
    };
    assert_eq!(meta.started_at_ms(), Some(i64::MAX));
}
