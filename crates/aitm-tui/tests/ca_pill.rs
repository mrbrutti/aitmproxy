//! D17.11 / SP-AC35, SP-AC38: the toolbar pill's CA-trust word. The word is
//! appended directly after the listening text until the sys-proxy word (PR 2)
//! lands between them (§D12 order).

mod common;

use aitm_tui::action::{BusEvent, BusRequest};
use aitm_tui::app::App;
use aitm_tui::caps::TermCaps;
use common::*;
use serde_json::json;

fn ca_status(trusted: &str) -> serde_json::Value {
    json!({"exists": true, "platform": "macos", "fingerprint_sha256": "AB:CD",
        "stores": {"user": {"installed": "present", "trusted": trusted, "location": "login"}}})
}

fn toolbar(app: &App) -> String {
    text_of(app, 200, 50)
        .lines()
        .next()
        .map(str::to_string)
        .unwrap_or_default()
}

#[test]
fn pill_shows_the_ca_word() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let reqs = connect(&mut app, CORE_TOOLS, Some("127.0.0.1:8080"));
    assert_eq!(
        reqs.iter()
            .filter(|r| matches!(r, BusRequest::Call { name, .. } if name == "ca.status"))
            .count(),
        1,
        "{reqs:?}"
    );
    let before = toolbar(&app);
    assert!(before.contains("listening 127.0.0.1:8080"), "{before}");
    assert!(
        !before.contains("· CA"),
        "no word before the status lands: {before}"
    );

    let _ = app.on_bus(BusEvent::CallOk {
        name: "ca.status".into(),
        value: ca_status("no"),
    });
    let t = toolbar(&app);
    assert!(t.contains("listening 127.0.0.1:8080 · CA untrusted"), "{t}");

    let _ = app.on_bus(BusEvent::CallOk {
        name: "ca.status".into(),
        value: ca_status("yes"),
    });
    let t = toolbar(&app);
    assert!(t.contains("listening 127.0.0.1:8080 · CA trusted"), "{t}");
    assert!(!t.contains("untrusted"), "{t}");

    app.ca_installing = true;
    let t = toolbar(&app);
    assert!(t.contains("listening 127.0.0.1:8080 · CA trusting…"), "{t}");
    app.ca_installing = false;

    let _ = app.on_bus(BusEvent::CallOk {
        name: "ca.status".into(),
        value: ca_status("unknown"),
    });
    let t = toolbar(&app);
    assert!(!t.contains("· CA"), "every store unknown: no word: {t}");
}

#[test]
fn pill_drops_the_trusting_word_when_the_bus_drops() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = connect(&mut app, CORE_TOOLS, Some("127.0.0.1:8080"));
    let _ = app.on_bus(BusEvent::CallOk {
        name: "ca.status".into(),
        value: ca_status("no"),
    });
    app.ca_installing = true;
    let t = toolbar(&app);
    assert!(t.contains("· CA trusting…"), "{t}");

    let _ = app.on_bus(BusEvent::Disconnected("connection reset".into()));
    let _ = connect(&mut app, CORE_TOOLS, Some("127.0.0.1:8080"));
    let _ = app.on_bus(BusEvent::CallOk {
        name: "ca.status".into(),
        value: ca_status("no"),
    });
    let t = toolbar(&app);
    assert!(t.contains("listening 127.0.0.1:8080 · CA untrusted"), "{t}");
    assert!(!t.contains("trusting"), "{t}");
}
