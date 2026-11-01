//! Task 2: core flow-model types (`HeaderMap`, `Body`, `HttpFlow`, …).

use aitm_core::{
    saturating_i64, Body, ConnInfo, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest,
    HttpVersion, InterceptState, StreamBody, TunnelInfo, TunnelMode, TunnelReason,
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

/// Spec D7: a tunnel row's `tunnel` and `tunnel_reason` values are these literal
/// snake_case codes on every surface (`flow.table`, `flow.get`, push, `flow.detail`),
/// so a frontend matches them byte for byte. One assertion per variant.
#[test]
fn tunnel_labels_are_the_wire_codes() {
    assert_eq!(TunnelMode::Decrypted.label(), "decrypted");
    assert_eq!(TunnelMode::Passthrough.label(), "passthrough");
    assert_eq!(TunnelMode::Failed.label(), "failed");

    // passthrough reasons
    assert_eq!(TunnelReason::OutOfScope.label(), "out_of_scope");
    assert_eq!(TunnelReason::Pinned.label(), "pinned");
    // failed reasons (the six codes of spec D5)
    assert_eq!(
        TunnelReason::ClientRejectedCertificate.label(),
        "client_rejected_certificate"
    );
    assert_eq!(TunnelReason::ClientClosed.label(), "client_closed");
    assert_eq!(TunnelReason::ClientTlsError.label(), "client_tls_error");
    assert_eq!(
        TunnelReason::UpstreamUnreachable.label(),
        "upstream_unreachable"
    );
    assert_eq!(
        TunnelReason::UpstreamTlsFailed.label(),
        "upstream_tls_failed"
    );
    assert_eq!(TunnelReason::ProtocolError.label(), "protocol_error");
}

/// An ordinary flow is neither passive nor a tunnel row: both the plain default
/// and the attribution constructor every protocol module uses start with
/// `passive == false` and `tunnel == None`.
#[test]
fn flow_meta_defaults_are_not_passive_and_not_a_tunnel() {
    let meta = FlowMeta::default();
    assert!(!meta.passive);
    assert_eq!(meta.tunnel, None);

    let attributed =
        FlowMeta::with_attribution(Some("com.apple.Safari".into()), Some("macos-ne".into()));
    assert!(!attributed.passive);
    assert_eq!(attributed.tunnel, None);
    assert_eq!(attributed.source_app.as_deref(), Some("com.apple.Safari"));
}

/// The three constructors build exactly the shapes of spec D5: a decrypted tunnel
/// has no reason; passthrough and failed carry theirs; no constructor sets byte
/// counts (a passthrough tunnel gets them on close).
#[test]
fn tunnel_info_constructors_set_mode_and_reason_and_no_bytes() {
    assert_eq!(
        TunnelInfo::decrypted(),
        TunnelInfo {
            mode: TunnelMode::Decrypted,
            reason: None,
            bytes_up: None,
            bytes_down: None,
        }
    );
    assert_eq!(
        TunnelInfo::passthrough(TunnelReason::OutOfScope),
        TunnelInfo {
            mode: TunnelMode::Passthrough,
            reason: Some(TunnelReason::OutOfScope),
            bytes_up: None,
            bytes_down: None,
        }
    );
    assert_eq!(
        TunnelInfo::failed(TunnelReason::UpstreamUnreachable),
        TunnelInfo {
            mode: TunnelMode::Failed,
            reason: Some(TunnelReason::UpstreamUnreachable),
            bytes_up: None,
            bytes_down: None,
        }
    );
}

/// Spec D5's terminal rule in one place (panel Q6): a tunnel row is closed iff
/// it *is* a tunnel row and its `duration` is set — whatever the mode, and
/// regardless of the `200` an established tunnel carries. An ordinary flow is
/// never a "closed tunnel", however finished.
#[test]
fn tunnel_is_closed_iff_a_tunnel_row_has_its_duration() {
    for info in [
        TunnelInfo::decrypted(),
        TunnelInfo::passthrough(TunnelReason::Pinned),
        TunnelInfo::failed(TunnelReason::ClientClosed),
    ] {
        let open = FlowMeta {
            tunnel: Some(info.clone()),
            duration: None,
            ..FlowMeta::default()
        };
        assert!(
            !open.tunnel_is_closed(),
            "{info:?} with no duration is open"
        );
        let closed = FlowMeta {
            tunnel: Some(info.clone()),
            duration: Some(Duration::from_millis(1)),
            ..FlowMeta::default()
        };
        assert!(
            closed.tunnel_is_closed(),
            "{info:?} with a duration is closed"
        );
    }
    let finished_request = FlowMeta {
        tunnel: None,
        duration: Some(Duration::from_millis(1)),
        ..FlowMeta::default()
    };
    assert!(
        !finished_request.tunnel_is_closed(),
        "a finished ordinary request is not a tunnel row at all"
    );
    assert!(!FlowMeta::default().tunnel_is_closed());
}

/// Panel Q3: `TunnelMode::ALL` is the one list of variants — sessionio reverses
/// the wire labels through it — so every label round-trips through `from_label`,
/// a code this build does not know is `None`, and the list is exactly the variant
/// set. The exhaustive `match` is the witness: a new variant fails to compile
/// until it is added to the pattern, whose arm count then fails this test until
/// `ALL` grows to hold it.
#[test]
fn tunnel_mode_all_round_trips_through_from_label() {
    let variant_count = match TunnelMode::Decrypted {
        // Add a new variant here AND to `TunnelMode::ALL`, then bump the count.
        TunnelMode::Decrypted | TunnelMode::Passthrough | TunnelMode::Failed => 3,
    };
    assert_eq!(TunnelMode::ALL.len(), variant_count);
    assert_eq!(
        TunnelMode::ALL,
        [
            TunnelMode::Decrypted,
            TunnelMode::Passthrough,
            TunnelMode::Failed
        ],
        "every variant once, in wire-code order"
    );
    for mode in TunnelMode::ALL {
        assert_eq!(TunnelMode::from_label(mode.label()), Some(mode), "{mode:?}");
    }
    assert_eq!(
        TunnelMode::from_label("passthrough"),
        Some(TunnelMode::Passthrough)
    );
    assert_eq!(
        TunnelMode::from_label("Passthrough"),
        None,
        "labels are exact, not case-folded"
    );
    assert_eq!(TunnelMode::from_label("pending"), None);
    assert_eq!(TunnelMode::from_label(""), None);
}

/// Panel Q3, the reason side: eight variants, eight labels, one list.
#[test]
fn tunnel_reason_all_round_trips_through_from_label() {
    let variant_count = match TunnelReason::OutOfScope {
        // Add a new variant here AND to `TunnelReason::ALL`, then bump the count.
        TunnelReason::OutOfScope
        | TunnelReason::Pinned
        | TunnelReason::ClientRejectedCertificate
        | TunnelReason::ClientClosed
        | TunnelReason::ClientTlsError
        | TunnelReason::UpstreamUnreachable
        | TunnelReason::UpstreamTlsFailed
        | TunnelReason::ProtocolError => 8,
    };
    assert_eq!(TunnelReason::ALL.len(), variant_count);
    assert_eq!(
        TunnelReason::ALL,
        [
            TunnelReason::OutOfScope,
            TunnelReason::Pinned,
            TunnelReason::ClientRejectedCertificate,
            TunnelReason::ClientClosed,
            TunnelReason::ClientTlsError,
            TunnelReason::UpstreamUnreachable,
            TunnelReason::UpstreamTlsFailed,
            TunnelReason::ProtocolError,
        ],
        "every variant once, in wire-code order"
    );
    for reason in TunnelReason::ALL {
        assert_eq!(
            TunnelReason::from_label(reason.label()),
            Some(reason),
            "{reason:?}"
        );
    }
    assert_eq!(
        TunnelReason::from_label("client_rejected_certificate"),
        Some(TunnelReason::ClientRejectedCertificate)
    );
    assert_eq!(TunnelReason::from_label("client-closed"), None);
    assert_eq!(TunnelReason::from_label("OUT_OF_SCOPE"), None);
    assert_eq!(TunnelReason::from_label("unknown"), None);
}

/// Panel Q4: the one byte-count-to-bus-integer rule. A count that fits is itself;
/// anything past `i64::MAX` saturates there, never wraps negative.
#[test]
fn saturating_i64_clamps_at_i64_max() {
    assert_eq!(saturating_i64(0), 0);
    assert_eq!(saturating_i64(4_096), 4_096);
    assert_eq!(saturating_i64(i64::MAX as u64), i64::MAX);
    assert_eq!(saturating_i64(i64::MAX as u64 + 1), i64::MAX);
    assert_eq!(saturating_i64(u64::MAX), i64::MAX);
}
