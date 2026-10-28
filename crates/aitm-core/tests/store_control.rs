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

fn http_with_id(id: FlowId, intercept: InterceptState, with_response: bool) -> Flow {
    match http(intercept, with_response) {
        Flow::Http(mut f) => {
            f.id = id;
            Flow::Http(f)
        }
        other => other,
    }
}

#[test]
fn parked_hidden_flow_is_visible_so_it_can_be_resumed() {
    // A flow captured while paused that then parks (intercept) must be visible so
    // an operator can find and resume it (otherwise it hangs to the timeout).
    let store = MemFlowStore::new();
    store.set_capturing(false);
    let id = store.insert(http(InterceptState::Observed, false));
    assert!(store.list().is_empty(), "hidden until it parks");

    let (h, _rx) = ResumeHandle::new();
    store.insert(http_with_id(
        id,
        InterceptState::Intercepted {
            backup: Box::new(http(InterceptState::Observed, false)),
            resume: h,
        },
        false,
    ));
    assert!(
        store.list().contains(&id),
        "a parked hidden flow is shown so it can be resumed"
    );
    assert_eq!(store.intercepted_count(), 1);
}

#[test]
fn paused_insert_is_resident_but_hidden() {
    let store = MemFlowStore::new();
    store.set_capturing(false);
    let id = store.insert(http(InterceptState::Observed, true));

    // Resident (pipeline can reach it by id) but hidden from list/query/count.
    assert!(store.get(id).is_some());
    assert!(store.list().is_empty());
    assert_eq!(store.count(), 0);
    assert!(store.resident_bytes() > 0, "the hidden flow is still held");
}

#[test]
fn reinsert_of_visible_flow_while_paused_stays_visible_and_keeps_marks() {
    // A flow first seen while capturing is visible; the chain re-inserts it on
    // later events, and pausing mid-flight must NOT hide it or drop its marks.
    let store = MemFlowStore::new();
    let id = store.insert(http(InterceptState::Observed, false));
    store.update(id, &mut |f| f.metadata_mut().marks = vec!["red".into()]);
    assert!(store.list().contains(&id));

    store.set_capturing(false);
    // Re-insert the SAME flow as it now stands (as the chain does on each event,
    // carrying the current state including the mark).
    let current = store.get(id).expect("resident");
    store.insert(current);
    assert!(
        store.list().contains(&id),
        "an already-visible in-flight flow stays visible when capture pauses"
    );
    assert_eq!(store.count(), 1);
    assert_eq!(
        store.get(id).unwrap().metadata().marks,
        vec!["red".to_string()],
        "the mark survives the re-insert"
    );
}

#[test]
fn hidden_flows_age_out_via_eviction_without_stale_ids() {
    // With a tiny capacity, hidden flows are bounded by the normal FIFO eviction
    // rather than any retire step, and the hidden set never keeps a stale id.
    let store = MemFlowStore::with_capacity(2);
    store.set_capturing(false);
    let ids: Vec<_> = (0..5)
        .map(|_| store.insert(http(InterceptState::Observed, true)))
        .collect();

    assert!(store.list().is_empty(), "hidden flows are never listed");
    assert!(
        store.get(ids[0]).is_none(),
        "the oldest hidden flow is evicted"
    );
    // The hidden set holds exactly the hidden flows still resident — no stale ids.
    let resident = ids.iter().filter(|id| store.get(**id).is_some()).count();
    assert_eq!(store.hidden_len(), resident);
    assert!(resident <= 2, "eviction keeps the map near capacity");
}

#[test]
fn clear_prunes_the_hidden_set() {
    let store = MemFlowStore::new();
    store.set_capturing(false);
    for _ in 0..3 {
        store.insert(http(InterceptState::Observed, true)); // terminal: has response
    }
    assert_eq!(store.hidden_len(), 3);
    let outcome = store.clear();
    assert_eq!(outcome.cleared, 3, "clear removes hidden terminal flows");
    assert_eq!(store.hidden_len(), 0, "clear prunes their hidden ids");
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
