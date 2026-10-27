//! Task 3: events, verdicts, and the error taxonomy.

use aitm_core::{Event, FlowId, GuardError};

#[test]
fn guard_error_display() {
    let msg = GuardError::OutOfScope("x".into()).to_string();
    assert!(msg.contains('x'), "message should mention the host: {msg}");
    assert!(msg.contains("scope"), "message should mention scope: {msg}");
}

#[test]
fn event_variant() {
    let ev = Event::WsMessage {
        flow: FlowId::new(),
        index: 3,
    };
    match ev {
        Event::WsMessage { index, .. } => assert_eq!(index, 3usize),
        _ => panic!("expected WsMessage"),
    }
}
