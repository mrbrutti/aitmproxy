//! Panel-fix coverage: MemFlowStore ephemeral/clear/count and StdGuard scope
//! removal + normalization.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow, HttpRequest,
    HttpResponse, HttpVersion, InterceptState, MemFlowStore, ResumeHandle, ScopeEntry,
    ScopeRateGuard, StdGuard,
};

fn conn() -> ConnInfo {
    ConnInfo {
        peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

fn http(intercept: InterceptState, with_response: bool) -> Flow {
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
        response: with_response.then(|| HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }),
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept,
    })
}

#[test]
fn paused_insert_is_resident_but_hidden_then_retired() {
    let store = MemFlowStore::new();
    store.set_capturing(false);
    let id = store.insert(http(InterceptState::Observed, true));

    // Resident (pipeline can reach it) but hidden from list/query/count.
    assert!(store.get(id).is_some());
    assert!(store.list().is_empty());
    assert_eq!(store.count(), 0);

    assert!(store.retire_ephemeral(id));
    assert!(store.get(id).is_none());
    // A second retire is a no-op.
    assert!(!store.retire_ephemeral(id));
}

#[test]
fn capturing_flows_are_visible_and_not_ephemeral() {
    let store = MemFlowStore::new();
    assert!(store.is_capturing());
    let id = store.insert(http(InterceptState::Observed, true));
    assert!(store.list().contains(&id));
    assert_eq!(store.count(), 1);
    assert!(
        !store.retire_ephemeral(id),
        "a captured flow is never ephemeral"
    );
    assert!(store.get(id).is_some());
}

#[test]
fn clear_removes_terminal_keeps_in_flight_and_parked() {
    let store = MemFlowStore::new();
    store.insert(http(InterceptState::Observed, true)); // terminal: has response
    store.insert(http(InterceptState::Killed, false)); // terminal: killed
    let in_flight = store.insert(http(InterceptState::Observed, false)); // no response
    let (h, _rx) = ResumeHandle::new();
    let parked = store.insert(http(
        InterceptState::Intercepted {
            backup: Box::new(http(InterceptState::Observed, false)),
            resume: h,
        },
        false,
    ));

    let outcome = store.clear();
    assert_eq!(outcome.cleared, 2);
    assert_eq!(outcome.skipped_in_flight, 2);
    assert!(store.get(in_flight).is_some());
    assert!(store.get(parked).is_some());
    assert_eq!(store.count(), 2);
}

#[test]
fn intercepted_count_tracks_parked() {
    let store = MemFlowStore::new();
    store.insert(http(InterceptState::Observed, true));
    assert_eq!(store.intercepted_count(), 0);
    let (h, _rx) = ResumeHandle::new();
    store.insert(http(
        InterceptState::Intercepted {
            backup: Box::new(http(InterceptState::Observed, false)),
            resume: h,
        },
        false,
    ));
    assert_eq!(store.intercepted_count(), 1);
}

#[test]
fn scope_add_normalizes_and_dedups_remove_matches() {
    let guard = StdGuard::default();
    guard.add_scope(ScopeEntry {
        host: "  Example.COM  ".into(),
    });
    // Normalized (trimmed + lowercased) on the way in.
    assert_eq!(
        guard.list_scope(),
        vec![ScopeEntry {
            host: "example.com".into()
        }]
    );
    // Re-adding the same host (any spelling) does not duplicate.
    guard.add_scope(ScopeEntry {
        host: "EXAMPLE.com".into(),
    });
    assert_eq!(guard.list_scope().len(), 1);

    // Remove matches regardless of case/whitespace; a second remove is false.
    assert!(guard.remove_scope("example.com "));
    assert!(guard.list_scope().is_empty());
    assert!(!guard.remove_scope("example.com"));
}

#[test]
fn intercept_state_labels() {
    assert_eq!(InterceptState::Observed.label(), "observed");
    assert_eq!(InterceptState::Resumed.label(), "resumed");
    assert_eq!(InterceptState::Killed.label(), "killed");
    let (h, _rx) = ResumeHandle::new();
    let parked = InterceptState::Intercepted {
        backup: Box::new(http(InterceptState::Observed, false)),
        resume: h,
    };
    assert_eq!(parked.label(), "intercepted");
}
