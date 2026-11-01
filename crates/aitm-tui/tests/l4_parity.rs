//! L4 parity (spec `2026-10-31-l4-parity-fixes-design.md`, unit (b)): pure-logic
//! tests of the TUI's L4 models and reducer. Every input is built in the test in
//! the core's wire shape (`l4.capture.status` → `{available, code, reason,
//! captures}`, `l4.intercept.list` → `[{id, flow, state, dir, length, layers,
//! parked_at}]`, `l4.flow.get` packets with the §2 fields); the app is built with
//! `App::new` and driven through `on_bus` / `update` / `run_command`. No fixture,
//! snapshot or seeded store is used anywhere in this file.

use aitm_tui::action::{BusEvent, BusRequest, ToolInfo};
use aitm_tui::app::App;
use aitm_tui::caps::TermCaps;
use aitm_tui::l4::{
    ascii_column, flow_get_args, hex_dump, inspect_args, status_ids, supports_operator_scope_add,
    supports_window, L4Availability, L4Flow, L4Parked, L4State,
};
use serde_json::{json, Value};

/// The 25 `l4.*` names the rig's `tools/list` offers: the 22 core verbs plus the
/// three bundled Rhai probes.
const L4_TOOL_NAMES: [&str; 25] = [
    "l4.agent.set",
    "l4.agent.status",
    "l4.capture.start",
    "l4.capture.status",
    "l4.capture.stop",
    "l4.craft",
    "l4.flow.get",
    "l4.flow.list",
    "l4.inject",
    "l4.intercept.drop",
    "l4.intercept.forward",
    "l4.intercept.list",
    "l4.intercept.mutate",
    "l4.intercept.revert",
    "l4.intercept.start",
    "l4.intercept.status",
    "l4.intercept.stop",
    "l4.interfaces",
    "l4.scope.add",
    "l4.scope.list",
    "l4.scope.remove",
    "l4.send_recv",
    "l4.recon",
    "l4.tcp_probe",
    "l4.udp_probe",
];

/// The rig's `l4.*` tool entries. `l4.flow.get` declares the §2 `offset` /
/// `limit` window; `l4.scope.add` is `confirmable` only when asked (spec §3: a
/// core with unit (a') reports `confirmable: true`).
fn l4_tools(confirmable_scope_add: bool) -> Vec<ToolInfo> {
    L4_TOOL_NAMES
        .iter()
        .map(|name| {
            let input_schema = match *name {
                "l4.flow.get" => json!({
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "offset": {"type": "integer"},
                        "limit": {"type": "integer"}
                    },
                    "required": ["id"]
                }),
                "l4.scope.add" => json!({
                    "type": "object",
                    "properties": {
                        "cidr": {"type": "string"},
                        "ports": {"type": "string"},
                        "interface": {"type": "string"},
                        "direction": {"type": "string"},
                        "capability": {"type": "string"}
                    },
                    "required": ["cidr"]
                }),
                _ => json!({"type": "object", "properties": {}}),
            };
            ToolInfo {
                name: (*name).to_string(),
                description: format!("{name} (rig)"),
                input_schema,
                confirmable: confirmable_scope_add && *name == "l4.scope.add",
            }
        })
        .collect()
}

/// Connect `app` to a bus offering `tools`, as the handshake does.
fn connected(app: &mut App, tools: Vec<ToolInfo>) -> Vec<BusRequest> {
    app.on_bus(BusEvent::Connected {
        server: "aitmproxy rig".into(),
        tools,
        role: Some("operator".into()),
    })
}

/// An `l4.flow.get` object for an in-path interception session `id` holding one
/// parked inbound TCP packet (the pre-§2 shape: no timestamps or addresses).
fn intercept_flow(id: &str) -> Value {
    json!({
        "id": id,
        "kind": "intercept",
        "interface": "lo",
        "queue": 0,
        "packet_count": 1,
        "injected_count": 0,
        "packets": [
            {"dir": "inbound", "length": 60, "injected": false, "layers": ["IPv4", "TCP"]}
        ]
    })
}

fn app() -> App {
    App::new(TermCaps::from_env(|_| None), "127.0.0.1:27431")
}

// ------------------------------------------------------------------ models

/// Spec §1: the status object `{available, code, reason, …}` is copied
/// field-for-field.
#[test]
fn models_availability_from_the_status_object() {
    let v = json!({"available": false, "code": "needs_privilege", "reason": "X", "captures": []});
    assert_eq!(
        L4Availability::from_reply(&v),
        L4Availability {
            available: false,
            code: Some("needs_privilege".into()),
            reason: Some("X".into()),
        }
    );
    let ok = json!({"available": true, "code": "available", "reason": null, "sessions": []});
    assert_eq!(
        L4Availability::from_reply(&ok),
        L4Availability {
            available: true,
            code: Some("available".into()),
            reason: None,
        }
    );
}

/// Spec §1 compatibility: an older core answers the status verbs with a bare
/// array, which means available.
#[test]
fn models_availability_from_a_bare_array_is_available() {
    let available = L4Availability {
        available: true,
        code: None,
        reason: None,
    };
    assert_eq!(L4Availability::from_reply(&json!([])), available);
    assert_eq!(L4Availability::from_reply(&json!(["C1"])), available);
    // Anything else is honestly unavailable with a reason, never a panic.
    let odd = L4Availability::from_reply(&json!("nope"));
    assert!(!odd.available);
    assert_eq!(odd.reason.as_deref(), Some("unrecognised l4 status reply"));
}

/// Spec §1 compatibility: an older core's tool error carries `L4 unavailable: `
/// and the reason is exactly the text after that marker.
#[test]
fn models_availability_from_an_l4_unavailable_error() {
    assert_eq!(
        L4Availability::from_error("l4.capture.status: L4 unavailable: X"),
        Some(L4Availability {
            available: false,
            code: None,
            reason: Some("X".into()),
        })
    );
    assert_eq!(L4Availability::from_error("connection reset"), None);
}

/// Plan decision 9: one pending literal shared by TUI, web and macOS.
#[test]
fn models_availability_pending_has_the_shared_literal() {
    let p = L4Availability::pending();
    assert!(!p.available);
    assert_eq!(p.code, None);
    assert_eq!(p.reason, Some("Reading L4 availability…".into()));
    // Before the first reply, the state holds exactly that.
    let st = L4State::default();
    assert_eq!(st.capture, L4Availability::pending());
    assert_eq!(st.intercept, L4Availability::pending());
    assert!(st.captures.is_empty());
    assert!(st.parked.is_empty());
}

/// The running capture ids come from the new `captures` key or, on an older
/// core, the bare array.
#[test]
fn models_status_ids_reads_both_shapes() {
    assert_eq!(
        status_ids(&json!({"captures": ["C1"]}), "captures"),
        vec!["C1".to_string()]
    );
    assert_eq!(
        status_ids(&json!(["C1"]), "captures"),
        vec!["C1".to_string()]
    );
    assert_eq!(
        status_ids(&json!({"captures": []}), "captures"),
        Vec::<String>::new()
    );
    assert_eq!(
        status_ids(&json!({"available": false}), "captures"),
        Vec::<String>::new()
    );
}

/// Spec §4: `l4.intercept.list` entries parse with their parked id and
/// `parked_at`.
#[test]
fn models_parked_list_parses_the_core_entries() {
    let v = json!([{
        "id": "P1", "flow": "F", "state": "parked", "dir": "inbound",
        "length": 60, "layers": ["IPv4", "TCP"], "parked_at": 1700000000000i64
    }]);
    let parked = L4Parked::list_from_json(&v);
    assert_eq!(parked.len(), 1);
    assert_eq!(
        parked[0],
        L4Parked {
            id: "P1".into(),
            flow: "F".into(),
            state: "parked".into(),
            length: 60,
            layers: vec!["IPv4".into(), "TCP".into()],
            parked_at: Some(1_700_000_000_000),
        }
    );
    // An older core without `parked_at` still lists.
    let old = L4Parked::list_from_json(&json!([{"id": "P9", "flow": "F", "state": "parked"}]));
    assert_eq!(old[0].id, "P9");
    assert_eq!(old[0].parked_at, None);
    // Not an array: nothing parked, no panic.
    assert!(L4Parked::list_from_json(&json!({"error": "x"})).is_empty());
}

/// Plan decision 3: the UI acts on the first listed entry for the flow; the
/// core lists oldest first.
#[test]
fn models_parked_for_is_the_first_listed_for_the_flow() {
    let st = L4State {
        parked: L4Parked::list_from_json(&json!([
            {"id": "P2", "flow": "F", "state": "parked", "parked_at": 1700000000000i64},
            {"id": "P1", "flow": "F", "state": "parked", "parked_at": 1700000000001i64},
            {"id": "P3", "flow": "G", "state": "parked", "parked_at": 1700000000002i64}
        ])),
        ..L4State::default()
    };
    assert_eq!(st.parked_for("F").map(|p| p.id.as_str()), Some("P2"));
    assert_eq!(st.parked_for("G").map(|p| p.id.as_str()), Some("P3"));
    assert_eq!(st.parked_for("Z"), None);
}

/// Spec §2: list polling uses `limit: 0` on a core that declares the window
/// and omits it against an older one; the inspector fetches one window.
#[test]
fn models_flow_get_and_inspect_args() {
    assert_eq!(flow_get_args("F", true), json!({"id": "F", "limit": 0}));
    assert_eq!(flow_get_args("F", false), json!({"id": "F"}));
    assert_eq!(
        inspect_args("F"),
        json!({"id": "F", "offset": 0, "limit": 256})
    );
}

/// Spec §2: the window is detected from `l4.flow.get`'s inputSchema.
#[test]
fn models_supports_window_reads_the_input_schema() {
    assert!(supports_window(&l4_tools(false)));
    let old: Vec<ToolInfo> = l4_tools(false)
        .into_iter()
        .map(|mut t| {
            if t.name == "l4.flow.get" {
                t.input_schema =
                    json!({"type": "object", "properties": {"id": {"type": "string"}}});
            }
            t
        })
        .collect();
    assert!(!supports_window(&old));
    assert!(!supports_window(&[]));
}

/// An `l4.flow.get` object without the §2 fields (an older core) still parses,
/// with every new field absent.
#[test]
fn models_flow_without_section_2_fields_still_parses() {
    let f = L4Flow::from_json(&intercept_flow("F")).expect("parses");
    assert_eq!(f.id, "F");
    assert!(f.is_intercept());
    assert_eq!(f.started_at, None);
    assert_eq!(f.src, None);
    assert_eq!(f.dst, None);
    assert_eq!(f.src_port, None);
    assert_eq!(f.dst_port, None);
    let p = &f.packets[0];
    assert_eq!(p.length, 60);
    assert_eq!(p.timestamp, None);
    assert_eq!(p.proto, None);
    assert_eq!(p.src, None);
    assert_eq!(p.dst, None);
    assert_eq!(p.src_port, None);
    assert_eq!(p.dst_port, None);
    assert_eq!(p.bytes, None);
    // The transport sub-label still comes from the layers.
    assert_eq!(f.proto(), Some("TCP"));
}

/// Spec §2: the packet and flow fields, with `bytes` decoded from base64.
#[test]
fn models_flow_with_section_2_fields() {
    let v = json!({
        "id": "C1", "kind": "capture", "interface": "lo0",
        "started_at": 1700000000000i64,
        "proto": "UDP", "src": "127.0.0.1", "dst": "127.0.0.1",
        "src_port": 40000, "dst_port": 9053,
        "packet_count": 1, "injected_count": 0, "offset": 0,
        "truncated": false, "next_offset": null,
        "packets": [{
            "dir": "outbound", "length": 36, "injected": false,
            "layers": ["IPv4", "UDP", "Raw"],
            "bytes": "aGVsbG8tbDQ=",
            "timestamp": 1700000000123i64,
            "proto": "UDP", "src": "127.0.0.1", "dst": "127.0.0.1",
            "src_port": 40000, "dst_port": 9053
        }]
    });
    let f = L4Flow::from_json(&v).expect("parses");
    assert_eq!(f.started_at, Some(1_700_000_000_000));
    assert_eq!(f.src.as_deref(), Some("127.0.0.1"));
    assert_eq!(f.dst.as_deref(), Some("127.0.0.1"));
    assert_eq!(f.src_port, Some(40000));
    assert_eq!(f.dst_port, Some(9053));
    assert_eq!(f.proto(), Some("UDP"));
    let p = &f.packets[0];
    assert_eq!(p.bytes.as_deref(), Some(&b"hello-l4"[..]));
    assert_eq!(p.timestamp, Some(1_700_000_000_123));
    assert_eq!(p.proto.as_deref(), Some("UDP"));
    assert_eq!(p.src.as_deref(), Some("127.0.0.1"));
    assert_eq!(p.dst.as_deref(), Some("127.0.0.1"));
    assert_eq!(p.src_port, Some(40000));
    assert_eq!(p.dst_port, Some(9053));
    // A packet the caller may not see (§2.2) has no `bytes` key: None, not empty.
    let hidden = json!({"dir": "inbound", "length": 60, "injected": false, "layers": []});
    let f2 = L4Flow::from_json(&json!({"id": "x", "packets": [hidden]})).expect("parses");
    assert_eq!(f2.packets[0].bytes, None);
}

/// AC39: the scope-add control exists only when `tools/list` shows
/// `l4.scope.add` with `confirmable: true`.
#[test]
fn models_supports_operator_scope_add_needs_confirmable() {
    assert!(supports_operator_scope_add(&l4_tools(true)));
    assert!(!supports_operator_scope_add(&l4_tools(false)));
    assert!(!supports_operator_scope_add(&[]));
    // `confirmable` absent from the wire entry decodes as false.
    let absent = ToolInfo::from_json(&json!({"name": "l4.scope.add"})).expect("decodes");
    assert!(!absent.confirmable);
    assert!(!supports_operator_scope_add(&[absent]));
    let present = ToolInfo::from_json(&json!({"name": "l4.scope.add", "confirmable": true}))
        .expect("decodes");
    assert!(present.confirmable);
    assert!(supports_operator_scope_add(&[present]));
}

/// AC40: packet text is inert — bytes outside 0x20–0x7e render as `.`.
#[test]
fn models_ascii_column_is_inert() {
    assert_eq!(
        ascii_column(&[0x1b, 0x5b, 0x41, 0x0a, 0x7f, 0x7e, 0x41]),
        ".[A..~A"
    );
    assert_eq!(ascii_column(b"hello-l4"), "hello-l4");
    assert_eq!(ascii_column(&[]), "");
}

/// AC40: no hex-dump row of every byte value contains a character below
/// `' '`; rows are 16 bytes each with their offset.
#[test]
fn models_hex_dump_rows_carry_no_control_characters() {
    let all: Vec<u8> = (0..=255u8).collect();
    let rows = hex_dump(&all);
    assert_eq!(rows.len(), 16);
    for row in &rows {
        assert!(
            row.chars().all(|c| c >= ' '),
            "control character in hex row {row:?}"
        );
    }
    assert!(rows[0].starts_with("00000000"));
    assert!(rows[1].starts_with("00000010"));
    assert!(rows[0].contains("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"));
    assert!(rows[0].ends_with("................"));
    assert!(rows[4].ends_with("@ABCDEFGHIJKLMNO"));
    assert!(hex_dump(&[]).is_empty());
    // A short tail row keeps its offset and ascii.
    let short = hex_dump(b"hello-l4");
    assert_eq!(short.len(), 1);
    assert!(short[0].starts_with("00000000"));
    assert!(short[0].ends_with("hello-l4"));
}

/// The reducer folds the two new bus events into `App::l4` without emitting a
/// request or a toast.
#[test]
fn models_bus_events_fold_into_l4_state() {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    assert_eq!(app.l4.capture, L4Availability::pending());
    assert_eq!(app.l4.intercept, L4Availability::pending());

    let capture = L4Availability::from_reply(
        &json!({"available": false, "code": "needs_privilege", "reason": "X", "captures": []}),
    );
    let intercept = L4Availability::from_reply(&json!({
        "available": false, "code": "unsupported_platform", "reason": "Y", "sessions": []
    }));
    let out = app.on_bus(BusEvent::L4Availability {
        capture: capture.clone(),
        intercept: intercept.clone(),
        captures: vec!["C1".into()],
    });
    assert_eq!(out, Vec::<BusRequest>::new());
    assert_eq!(app.l4.capture, capture);
    assert_eq!(app.l4.intercept, intercept);
    assert_eq!(app.l4.captures, vec!["C1".to_string()]);
    assert!(
        app.current_toast().is_none(),
        "an availability change never toasts"
    );

    let _ = app.on_bus(BusEvent::L4Flows(vec![intercept_flow("F")]));
    let out = app.on_bus(BusEvent::L4Parked(vec![json!({
        "id": "P1", "flow": "F", "state": "parked", "dir": "inbound",
        "length": 60, "layers": ["IPv4", "TCP"], "parked_at": 1700000000000i64
    })]));
    assert_eq!(out, Vec::<BusRequest>::new());
    assert_eq!(app.l4.parked_for("F").map(|p| p.id.as_str()), Some("P1"));
    assert_eq!(app.l4.parked[0].parked_at, Some(1_700_000_000_000));
}
