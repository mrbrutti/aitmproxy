//! L4 parity (spec `2026-10-31-l4-parity-fixes-design.md`, unit (b)): pure-logic
//! tests of the TUI's L4 models and reducer. Every input is built in the test in
//! the core's wire shape (`l4.capture.status` → `{available, code, reason,
//! captures}`, `l4.intercept.list` → `[{id, flow, state, dir, length, layers,
//! parked_at}]`, `l4.flow.get` packets with the §2 fields); the app is built with
//! `App::new` and driven through `on_bus` / `update` / `run_command`; the two
//! render checks draw that same state into a `Buffer` and read the text back.
//! No fixture, snapshot or seeded store is used anywhere in this file.

use aitm_tui::action::{Action, BusEvent, BusRequest, ToolInfo};
use aitm_tui::app::{App, Chip, Mode, SidebarItem};
use aitm_tui::caps::TermCaps;
use aitm_tui::keys;
use aitm_tui::l4::{
    ascii_column, clock_ms, flow_get_args, fold_status, hex_dump, inspect_args, packet_fields,
    slow_l4_reads, status_ids, supports_operator_scope_add, supports_window, L4Availability,
    L4Confirm, L4Flow, L4Pane, L4Parked, L4State,
};
use aitm_tui::model::FlowRow;
use aitm_tui::theme::Theme;
use aitm_tui::ui::complete::l4_command_candidates;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
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

// ----------------------------------------------------------------- polling

/// Spec §1: the slow pass re-reads both status verbs every time; spec §4: it
/// asks for `l4.intercept.list` only when intercept is available, and the
/// statuses come first so one pass's status read governs its list read.
#[test]
fn polling_slow_reads_status_always_and_parked_only_when_available() {
    let unavailable = slow_l4_reads(|_| true, false);
    assert!(unavailable.contains(&"l4.capture.status"));
    assert!(unavailable.contains(&"l4.intercept.status"));
    assert!(!unavailable.contains(&"l4.intercept.list"));

    let available = slow_l4_reads(|_| true, true);
    assert!(available.contains(&"l4.intercept.list"));
    assert_eq!(
        available,
        vec![
            "l4.scope.list",
            "l4.agent.status",
            "l4.capture.status",
            "l4.intercept.status",
            "l4.intercept.list",
        ]
    );
}

/// Only verbs the bus offers are read: a core without the intercept verbs is
/// never asked for them, and a bus without `l4.*` reads nothing.
#[test]
fn polling_slow_reads_only_offered_verbs() {
    let no_intercept = |t: &str| !t.starts_with("l4.intercept.");
    assert_eq!(
        slow_l4_reads(no_intercept, true),
        vec!["l4.scope.list", "l4.agent.status", "l4.capture.status"]
    );
    assert_eq!(slow_l4_reads(|_| false, true), Vec::<&str>::new());
    assert_eq!(slow_l4_reads(|_| false, false), Vec::<&str>::new());
}

/// Spec §1: a status reply folds through `from_reply` + `status_ids`; a tool
/// error carrying `L4 unavailable: ` through `from_error`; any other tool error
/// is honestly unavailable with its text as the reason. No ids on an error.
#[test]
fn polling_status_outcome_folds_replies_and_tool_errors() {
    let ac3 = json!({"available": false, "code": "needs_privilege", "reason": "X", "captures": []});
    assert_eq!(
        fold_status(Ok(&ac3), "captures"),
        (
            L4Availability {
                available: false,
                code: Some("needs_privilege".into()),
                reason: Some("X".into()),
            },
            Vec::new()
        )
    );
    let running =
        json!({"available": true, "code": "available", "reason": null, "captures": ["C1", "C2"]});
    assert_eq!(
        fold_status(Ok(&running), "captures"),
        (
            L4Availability {
                available: true,
                code: Some("available".into()),
                reason: None,
            },
            vec!["C1".to_string(), "C2".to_string()]
        )
    );
    // An older core's bare array: available, and the ids are the array.
    assert_eq!(
        fold_status(Ok(&json!(["C1"])), "captures"),
        (
            L4Availability {
                available: true,
                code: None,
                reason: None,
            },
            vec!["C1".to_string()]
        )
    );
    // An older core's gated error: the reason is exactly the text after the marker.
    assert_eq!(
        fold_status(Err("l4.capture.status: L4 unavailable: X"), "captures"),
        (
            L4Availability {
                available: false,
                code: None,
                reason: Some("X".into()),
            },
            Vec::new()
        )
    );
    // Any other tool error: unavailable, the error text as the reason.
    assert_eq!(
        fold_status(Err("internal error (-32603)"), "sessions"),
        (
            L4Availability {
                available: false,
                code: None,
                reason: Some("internal error (-32603)".into()),
            },
            Vec::new()
        )
    );
}

/// Spec §1 end to end in the reducer: pending until the first reply, then the
/// AC3 / AC4 objects land as the app's availability with no toast and no
/// request; a later flip to available (D0 at runtime) replaces them.
#[test]
fn polling_availability_replies_land_in_app_state() {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    assert_eq!(app.l4.capture, L4Availability::pending());
    assert_eq!(app.l4.intercept, L4Availability::pending());
    assert_eq!(
        app.l4.capture.reason.as_deref(),
        Some("Reading L4 availability…")
    );

    let ac3 =
        json!({"available": false, "code": "needs_privilege", "reason": "R_CAP", "captures": []});
    let ac4 = json!({
        "available": false, "code": "unsupported_platform", "reason": "R_INT", "sessions": []
    });
    let (capture, captures) = fold_status(Ok(&ac3), "captures");
    let (intercept, _) = fold_status(Ok(&ac4), "sessions");
    let out = app.on_bus(BusEvent::L4Availability {
        capture,
        intercept,
        captures,
    });
    assert_eq!(out, Vec::<BusRequest>::new());
    assert_eq!(app.l4.capture.code, Some("needs_privilege".into()));
    assert!(!app.l4.capture.available);
    assert_eq!(app.l4.capture.reason.as_deref(), Some("R_CAP"));
    assert_eq!(app.l4.intercept.code, Some("unsupported_platform".into()));
    assert_eq!(app.l4.intercept.reason.as_deref(), Some("R_INT"));
    assert!(app.l4.captures.is_empty());
    assert!(
        app.current_toast().is_none(),
        "an availability change never toasts"
    );

    // Availability is never cached: the next slow pass's reply wins.
    let lit = json!({"available": true, "code": "available", "reason": null, "captures": ["C1"]});
    let (capture, captures) = fold_status(Ok(&lit), "captures");
    let out = app.on_bus(BusEvent::L4Availability {
        capture,
        intercept: app.l4.intercept.clone(),
        captures,
    });
    assert_eq!(out, Vec::<BusRequest>::new());
    assert!(app.l4.capture.available);
    assert_eq!(app.l4.capture.code, Some("available".into()));
    assert_eq!(app.l4.captures, vec!["C1".to_string()]);
    assert!(
        app.current_toast().is_none(),
        "an availability change never toasts"
    );
}

// -------------------------------------------------------- capture_commands

/// Land a capture availability in the app (the slow poll's reply), with
/// `captures` running.
fn set_capture(app: &mut App, capture: L4Availability, captures: &[&str]) {
    let intercept = app.l4.intercept.clone();
    let out = app.on_bus(BusEvent::L4Availability {
        capture,
        intercept,
        captures: captures.iter().map(|s| (*s).to_string()).collect(),
    });
    assert_eq!(out, Vec::<BusRequest>::new());
}

fn available() -> L4Availability {
    L4Availability::from_reply(
        &json!({"available": true, "code": "available", "reason": null, "captures": []}),
    )
}

fn unavailable(reason: &str) -> L4Availability {
    L4Availability::from_reply(
        &json!({"available": false, "code": "needs_privilege", "reason": reason, "captures": []}),
    )
}

fn toast_text(app: &App) -> String {
    app.current_toast()
        .map(|t| t.text.clone())
        .unwrap_or_default()
}

/// The text of a buffer, one trimmed line per row.
fn buffer_text(buf: &Buffer) -> Vec<String> {
    let w = usize::from(buf.area.width);
    buf.content()
        .chunks(w)
        .map(|row| {
            row.iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect()
}

fn press(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

/// `:l4` opens the panel and sends nothing; so do `L` and the sidebar item.
#[test]
fn capture_commands_l4_opens_the_panel_with_no_request() {
    {
        let mut app = app();
        let _ = connected(&mut app, l4_tools(false));
        assert_eq!(app.run_command("l4"), Vec::<BusRequest>::new());
        assert_eq!(app.mode, Mode::L4);
        assert!(app.current_toast().is_none());
    }
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    assert_eq!(
        keys::map(press('L'), Mode::Flows),
        Some(Action::OpenL4),
        "L in the flow list opens the L4 panel"
    );
    assert_eq!(app.update(Action::OpenL4), Vec::<BusRequest>::new());
    assert_eq!(app.mode, Mode::L4);
    assert_eq!(app.sidebar, SidebarItem::L4);
    // The panel is a read-only panel: Esc / q back, `:` palette, `?` help.
    assert_eq!(
        keys::map(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), Mode::L4),
        Some(Action::Back)
    );
    assert_eq!(keys::map(press('q'), Mode::L4), Some(Action::Back));
    assert_eq!(keys::map(press(':'), Mode::L4), Some(Action::PaletteOpen));
    assert_eq!(keys::map(press('?'), Mode::L4), Some(Action::Help));
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Flows);
}

/// AC15: with capture unavailable (reason `X`), `:l4 capture lo0` refuses
/// locally with that reason and puts nothing on the bus. The same before the
/// first status reply (pending is not available).
#[test]
fn capture_commands_refuse_locally_while_capture_is_unavailable() {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    // Pending: nothing has answered yet.
    assert_eq!(app.l4.capture, L4Availability::pending());
    assert_eq!(app.run_command("l4 capture lo0"), Vec::<BusRequest>::new());
    assert!(
        toast_text(&app).contains("Reading L4 availability…"),
        "toast: {:?}",
        toast_text(&app)
    );

    set_capture(&mut app, unavailable("X"), &[]);
    assert_eq!(app.run_command("l4 capture lo0"), Vec::<BusRequest>::new());
    let t = toast_text(&app);
    assert!(t.contains('X'), "toast carries the core's reason: {t:?}");
    assert!(
        t.starts_with("capture unavailable: "),
        "toast is the plan's literal: {t:?}"
    );
    assert_eq!(
        app.run_command("l4 capture lo0 outbound"),
        Vec::<BusRequest>::new()
    );
}

/// With capture available, `:l4 capture <iface> [dir]` is exactly one
/// `l4.capture.start {interface, direction}`; the direction defaults to
/// `inbound` and any other word is refused locally.
#[test]
fn capture_commands_start_sends_interface_and_direction() {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    set_capture(&mut app, available(), &[]);
    assert_eq!(
        app.run_command("l4 capture lo0"),
        vec![BusRequest::Call {
            name: "l4.capture.start".into(),
            args: json!({"interface": "lo0", "direction": "inbound"}),
        }]
    );
    assert_eq!(
        app.run_command("l4 capture lo0 outbound"),
        vec![BusRequest::Call {
            name: "l4.capture.start".into(),
            args: json!({"interface": "lo0", "direction": "outbound"}),
        }]
    );
    assert_eq!(
        app.run_command("l4 capture lo0 inbound"),
        vec![BusRequest::Call {
            name: "l4.capture.start".into(),
            args: json!({"interface": "lo0", "direction": "inbound"}),
        }]
    );
    assert_eq!(
        app.run_command("l4 capture lo0 sideways"),
        Vec::<BusRequest>::new()
    );
    assert_eq!(toast_text(&app), "direction must be inbound or outbound");
    // No interface: a usage toast, no request.
    assert_eq!(app.run_command("l4 capture"), Vec::<BusRequest>::new());
    assert!(toast_text(&app).contains("usage"), "{:?}", toast_text(&app));
    // The args never carry a `filter` key (the core derives BPF from scope).
    for line in ["l4 capture lo0", "l4 capture en0 outbound"] {
        for req in app.run_command(line) {
            if let BusRequest::Call { args, .. } = req {
                assert_eq!(args.as_object().map(|o| o.len()), Some(2));
                assert!(args.get("filter").is_none());
            }
        }
    }
}

/// `:l4 stop` stops every running capture, one `l4.capture.stop {id}` each,
/// in the core's order; `:l4 stop <id>` stops that one; nothing running is
/// a toast.
#[test]
fn capture_commands_stop_one_or_every_running_capture() {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    set_capture(&mut app, available(), &["C1", "C2"]);
    assert_eq!(
        app.run_command("l4 stop"),
        vec![
            BusRequest::Call {
                name: "l4.capture.stop".into(),
                args: json!({"id": "C1"}),
            },
            BusRequest::Call {
                name: "l4.capture.stop".into(),
                args: json!({"id": "C2"}),
            },
        ]
    );
    assert_eq!(
        app.run_command("l4 stop C1"),
        vec![BusRequest::Call {
            name: "l4.capture.stop".into(),
            args: json!({"id": "C1"}),
        }]
    );
    set_capture(&mut app, available(), &[]);
    assert_eq!(app.run_command("l4 stop"), Vec::<BusRequest>::new());
    assert_eq!(toast_text(&app), "no running capture");
    // An unknown sub-command is a usage toast, never a request.
    assert_eq!(app.run_command("l4 frobnicate"), Vec::<BusRequest>::new());
    assert!(toast_text(&app).contains("usage"), "{:?}", toast_text(&app));
}

/// Without the capture verbs on the bus nothing is sent, whatever the status
/// says (an older core cannot be asked for a verb it lacks).
#[test]
fn capture_commands_need_the_verbs_on_the_bus() {
    let mut app = app();
    let tools: Vec<ToolInfo> = l4_tools(false)
        .into_iter()
        .filter(|t| !t.name.starts_with("l4.capture.st"))
        .collect();
    let _ = connected(&mut app, tools);
    set_capture(&mut app, available(), &["C1"]);
    assert_eq!(app.run_command("l4 capture lo0"), Vec::<BusRequest>::new());
    assert!(toast_text(&app).contains("l4.capture.start"));
    assert_eq!(app.run_command("l4 stop"), Vec::<BusRequest>::new());
    assert!(toast_text(&app).contains("l4.capture.stop"));
}

/// Completion for the `:l4` line: `capture` / `stop`, then the known
/// interface names (live state only: scope entries and L4 flows), then
/// `inbound` / `outbound`; `stop` offers "all" and each running id.
#[test]
fn capture_commands_completion_offers_subcommands_interfaces_and_directions() {
    let labels = |line: &str, ifaces: &[&str], caps: &[&str]| -> Vec<String> {
        let ifaces: Vec<String> = ifaces.iter().map(|s| (*s).to_string()).collect();
        let caps: Vec<String> = caps.iter().map(|s| (*s).to_string()).collect();
        l4_command_candidates(line, &ifaces, &caps)
            .into_iter()
            .map(|c| c.label)
            .collect()
    };
    assert_eq!(
        labels("l4 ", &["lo0"], &["C1"]),
        vec!["l4 capture".to_string(), "l4 stop".to_string()]
    );
    assert_eq!(
        labels("l4 ca", &["lo0"], &[]),
        vec!["l4 capture".to_string()]
    );
    assert_eq!(labels("l4 st", &["lo0"], &[]), vec!["l4 stop".to_string()]);
    assert_eq!(
        labels("l4 capture ", &["lo0", "en0"], &[]),
        vec!["l4 capture lo0".to_string(), "l4 capture en0".to_string()]
    );
    assert_eq!(
        labels("l4 capture e", &["lo0", "en0"], &[]),
        vec!["l4 capture en0".to_string()]
    );
    assert_eq!(
        labels("l4 capture lo0 ", &["lo0"], &[]),
        vec![
            "l4 capture lo0 inbound".to_string(),
            "l4 capture lo0 outbound".to_string()
        ]
    );
    assert_eq!(
        labels("l4 capture lo0 out", &["lo0"], &[]),
        vec!["l4 capture lo0 outbound".to_string()]
    );
    assert_eq!(
        labels("l4 stop ", &[], &["C1", "C2"]),
        vec![
            "l4 stop".to_string(),
            "l4 stop C1".to_string(),
            "l4 stop C2".to_string()
        ]
    );
    assert_eq!(
        labels("l4 stop C2", &[], &["C1", "C2"]),
        vec!["l4 stop C2".to_string()]
    );
    // Nothing past a complete line, and nothing for other commands.
    assert_eq!(
        labels("l4 capture lo0 inbound x", &["lo0"], &[]),
        Vec::<String>::new()
    );
    assert_eq!(labels("scope add", &["lo0"], &["C1"]), Vec::<String>::new());
    assert_eq!(labels("l4", &["lo0"], &["C1"]), Vec::<String>::new());
    // Every candidate carries a hint.
    for c in l4_command_candidates("l4 ", &["lo0".to_string()], &[]) {
        assert!(!c.detail.is_empty(), "{c:?}");
    }
}

/// The palette shows those completions for an `:l4 …` line, with the
/// interface names taken from live state (scope entries ∪ L4 flows) and
/// nothing else; Enter runs the highlighted completion.
#[test]
fn capture_commands_palette_completes_from_live_state() {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    set_capture(&mut app, available(), &["C1"]);
    let _ = app.on_bus(BusEvent::L4Scope(vec![json!({
        "interface": "lo0", "capability": "capture", "cidr": "127.0.0.1/32",
        "ports": "9000-9999", "direction": "inbound"
    })]));
    let _ = app.on_bus(BusEvent::L4Flows(vec![json!({
        "id": "C1", "kind": "capture", "interface": "en0", "packet_count": 0,
        "injected_count": 0, "packets": []
    })]));
    assert_eq!(
        app.l4_interfaces(),
        vec!["en0".to_string(), "lo0".to_string()]
    );
    app.prompt = "l4 capture ".into();
    let labels: Vec<String> = app.palette_items().into_iter().map(|i| i.label).collect();
    assert_eq!(
        labels,
        vec![":l4 capture en0".to_string(), ":l4 capture lo0".to_string()]
    );
    // Enter on the highlighted completion runs that line.
    let _ = app.update(Action::PaletteOpen);
    app.prompt = "l4 capture lo0 ".into();
    app.palette_cursor = 1; // outbound
    let out = app.update(Action::Submit);
    assert_eq!(
        out,
        vec![BusRequest::Call {
            name: "l4.capture.start".into(),
            args: json!({"interface": "lo0", "direction": "outbound"}),
        }]
    );
}

/// The sidebar's L4 item exists only when the bus offers `l4.capture.status`:
/// `]` never lands on it otherwise, and landing on it opens the panel.
#[test]
fn capture_commands_sidebar_item_only_with_the_status_verb() {
    {
        let mut app = app();
        let _ = connected(&mut app, Vec::new());
        for _ in 0..(SidebarItem::ALL.len() * 2) {
            let _ = app.update(Action::SidebarNext);
            assert_ne!(
                app.sidebar,
                SidebarItem::L4,
                "hidden without l4.capture.status"
            );
            assert_ne!(app.mode, Mode::L4);
        }
    }
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    let mut seen = false;
    for _ in 0..SidebarItem::ALL.len() {
        let _ = app.update(Action::SidebarNext);
        if app.sidebar == SidebarItem::L4 {
            seen = true;
            assert_eq!(app.mode, Mode::L4);
        }
    }
    assert!(
        seen,
        "the L4 item is reachable when the bus offers the verb"
    );
    assert_eq!(SidebarItem::L4.label(), "L4");
}

/// The panel renders live state only: the availability lines, the running
/// capture ids and the two command hints. Before the first reply it shows the
/// shared pending literal.
#[test]
fn capture_commands_panel_renders_availability_captures_and_hints() {
    let theme = Theme::new(true);
    let area = Rect::new(0, 0, 100, 14);
    let render = |app: &App| -> String {
        let mut buf = Buffer::empty(area);
        aitm_tui::ui::l4::panel(app, &theme, area, &mut buf);
        buffer_text(&buf).join("\n")
    };

    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    let text = render(&app);
    assert!(text.contains("Reading L4 availability…"), "{text}");
    assert!(!text.contains("capture unavailable"), "{text}");

    set_capture(&mut app, unavailable("X"), &[]);
    let intercept = L4Availability::from_reply(&json!({
        "available": false, "code": "unsupported_platform", "reason": "Y", "sessions": []
    }));
    let _ = app.on_bus(BusEvent::L4Availability {
        capture: unavailable("X"),
        intercept,
        captures: vec![],
    });
    let text = render(&app);
    assert!(text.contains("capture unavailable — X"), "{text}");
    assert!(text.contains("intercept unavailable — Y"), "{text}");
    assert!(
        text.contains(":l4 capture <iface> [inbound|outbound]"),
        "{text}"
    );
    assert!(text.contains(":l4 stop [<id>]"), "{text}");
    assert!(!text.contains("Reading L4 availability…"), "{text}");
    assert!(text.contains("no running capture"), "{text}");

    set_capture(&mut app, available(), &["C1", "C2"]);
    let text = render(&app);
    assert!(text.contains("capture: available"), "{text}");
    assert!(text.contains("C1"), "{text}");
    assert!(text.contains("C2"), "{text}");
    assert!(!text.contains("no running capture"), "{text}");
    // No control character ever reaches the terminal from this panel.
    assert!(text.chars().all(|c| c >= ' ' || c == '\n'), "{text:?}");
}

/// Help lists the panel key and the two `:l4` commands.
#[test]
fn capture_commands_help_lists_the_panel_key_and_commands() {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    app.mode = Mode::Help;
    let area = Rect::new(0, 0, 160, 50);
    let mut buf = Buffer::empty(area);
    aitm_tui::ui::render(&app, &Theme::new(true), area, &mut buf);
    let text = buffer_text(&buf).join("\n");
    assert!(
        text.contains(":l4 capture <iface> [inbound|outbound]"),
        "{text}"
    );
    assert!(text.contains(":l4 stop [<id>]"), "{text}");
    assert!(text.contains("L4 panel"), "{text}");
}

// --------------------------------------------------------------- parked_id

/// A base64 of `bytes` as the core sends it (standard, padded).
fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// An `l4.flow.get` object for intercept session `id` whose one parked packet
/// carries the §2 fields and `bytes` (a UDP datagram 127.0.0.1:40000 →
/// 127.0.0.1:9053 with payload `payload`).
fn section_2_flow(id: &str, payload: &[u8]) -> Value {
    json!({
        "id": id,
        "kind": "intercept",
        "interface": "lo",
        "queue": 0,
        "packet_count": 1,
        "injected_count": 0,
        "started_at": 1_700_000_000_000i64,
        "proto": "UDP", "src": "127.0.0.1", "dst": "127.0.0.1",
        "src_port": 40000, "dst_port": 9053,
        "offset": 0, "truncated": false, "next_offset": null,
        "packets": [{
            "dir": "inbound", "length": payload.len(), "injected": false,
            "layers": ["IPv4", "UDP", "Raw"],
            "timestamp": 1_700_000_000_000i64,
            "proto": "UDP", "src": "127.0.0.1", "dst": "127.0.0.1",
            "src_port": 40000, "dst_port": 9053,
            "bytes": b64(payload)
        }]
    })
}

/// An intercept-capable session: the rig's verbs, intercept available, an L4
/// scope entry covering `lo` for intercept, flow `F` landed by the poll and
/// parked packet `P1` listed for it, with `F` selected.
fn intercept_ready(parked: Vec<Value>) -> App {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    let _ = app.on_bus(BusEvent::L4Availability {
        capture: unavailable("X"),
        intercept: L4Availability::from_reply(
            &json!({"available": true, "code": "available", "reason": null, "sessions": ["F"]}),
        ),
        captures: vec![],
    });
    let _ = app.on_bus(BusEvent::L4Scope(vec![json!({
        "interface": "lo", "capability": "intercept", "cidr": "127.0.0.1/32",
        "ports": "9000-9999", "direction": "inbound"
    })]));
    let _ = app.on_bus(BusEvent::L4Flows(vec![intercept_flow("F")]));
    let _ = app.on_bus(BusEvent::L4Parked(parked));
    app.selected = Some("F".into());
    assert!(app.selected_l4().is_some(), "flow F must be selected");
    app
}

fn parked_p1() -> Value {
    json!({
        "id": "P1", "flow": "F", "state": "parked", "dir": "inbound",
        "length": 60, "layers": ["IPv4", "TCP"], "parked_at": 1_700_000_000_000i64
    })
}

fn render_inspector(app: &App) -> String {
    let theme = Theme::new(true);
    let area = Rect::new(0, 0, 120, 30);
    let mut buf = Buffer::empty(area);
    aitm_tui::ui::l4::inspector(app, &theme, area, &mut buf);
    buffer_text(&buf).join("\n")
}

/// AC10: Forward and Drop send the parked packet's id from `l4.intercept.list`,
/// never the flow id.
#[test]
fn parked_id_forward_and_drop_send_the_parked_id_never_the_flow_id() {
    let mut app = intercept_ready(vec![parked_p1()]);
    let out = app.update(Action::Resume);
    assert_eq!(
        out,
        vec![BusRequest::Call {
            name: "l4.intercept.forward".into(),
            args: json!({"id": "P1"}),
        }]
    );
    let out2 = app.update(Action::Kill);
    assert_eq!(
        out2,
        vec![BusRequest::Call {
            name: "l4.intercept.drop".into(),
            args: json!({"id": "P1"}),
        }]
    );
    for req in out.iter().chain(out2.iter()) {
        let BusRequest::Call { args, .. } = req else {
            panic!("{req:?}");
        };
        assert_ne!(*args, json!({"id": "F"}));
        assert!(!args.to_string().contains("\"F\""), "{args}");
    }
}

/// The oldest listed parked packet for the flow is the one acted on; another
/// flow's parked packet is never picked.
#[test]
fn parked_id_acts_on_the_first_listed_for_the_flow() {
    let mut app = intercept_ready(vec![
        json!({"id": "P9", "flow": "OTHER", "state": "parked", "length": 1, "layers": []}),
        json!({"id": "P2", "flow": "F", "state": "parked", "length": 1, "layers": []}),
        json!({"id": "P3", "flow": "F", "state": "parked", "length": 1, "layers": []}),
    ]);
    assert_eq!(
        app.update(Action::Resume),
        vec![BusRequest::Call {
            name: "l4.intercept.forward".into(),
            args: json!({"id": "P2"}),
        }]
    );
}

/// No parked entry for the flow: nothing on the bus, an honest toast.
#[test]
fn parked_id_without_a_parked_entry_sends_nothing() {
    let mut app = intercept_ready(vec![]);
    assert_eq!(app.update(Action::Resume), Vec::<BusRequest>::new());
    assert!(
        toast_text(&app).contains("no parked packet"),
        "{}",
        toast_text(&app)
    );
    assert_eq!(app.update(Action::Kill), Vec::<BusRequest>::new());
}

/// AC11: intercept unavailable (reason `Y`) → Forward / Drop / Mutate put no
/// `l4.intercept.*` call on the bus, the toast carries the core's reason, and
/// the intercept pane is one documented-limited line with `Y` and no hints.
#[test]
fn parked_id_unavailable_intercept_refuses_locally_with_the_reason() {
    let mut app = intercept_ready(vec![parked_p1()]);
    let _ = app.on_bus(BusEvent::L4Availability {
        capture: unavailable("X"),
        intercept: L4Availability::from_reply(&json!({
            "available": false, "code": "unsupported_platform", "reason": "Y", "sessions": []
        })),
        captures: vec![],
    });
    assert_eq!(app.update(Action::Resume), Vec::<BusRequest>::new());
    assert!(toast_text(&app).contains('Y'), "{}", toast_text(&app));
    assert_eq!(app.update(Action::Kill), Vec::<BusRequest>::new());
    assert!(toast_text(&app).contains('Y'), "{}", toast_text(&app));
    // Mutate (`e`) opens the craft pane; it never calls `l4.intercept.*`.
    let out = app.update(Action::Edit);
    assert!(
        !out.iter().any(
            |r| matches!(r, BusRequest::Call { name, .. } if name.starts_with("l4.intercept."))
        ),
        "{out:?}"
    );
    assert_eq!(out, Vec::<BusRequest>::new());

    app.l4.pane = L4Pane::Intercept;
    let text = render_inspector(&app);
    assert!(text.contains("intercept unavailable"), "{text}");
    assert!(text.contains('Y'), "{text}");
    assert!(!text.contains("Forward"), "{text}");
    assert!(!text.contains("Drop"), "{text}");
    assert!(!text.contains("Mutate"), "{text}");
    assert!(!text.contains("Phase 2"), "{text}");
}

/// With intercept available and `P1` parked, the pane shows the parked id and
/// the Forward / Mutate / Drop hints.
#[test]
fn parked_id_available_pane_shows_the_parked_packet_and_hints() {
    let mut app = intercept_ready(vec![parked_p1()]);
    app.l4.pane = L4Pane::Intercept;
    let text = render_inspector(&app);
    assert!(text.contains("P1"), "{text}");
    assert!(text.contains("Forward"), "{text}");
    assert!(text.contains("Drop"), "{text}");
    assert!(text.contains("60B") || text.contains("60 B"), "{text}");
}

/// Selecting an L4 row asks for its packet window with `inspect_args` on a core
/// that declares the window; the reply lands in `app.l4.flows` silently, and
/// the next `limit: 0` poll does not wipe the packets it brought.
#[test]
fn parked_id_selecting_an_l4_row_fetches_the_packet_window() {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    let _ = app.on_bus(BusEvent::L4Flows(vec![intercept_flow("F")]));
    app.selected = None;
    let out = app.update(Action::Down);
    assert_eq!(app.selected.as_deref(), Some("F"));
    assert_eq!(
        out,
        vec![BusRequest::Call {
            name: "l4.flow.get".into(),
            args: inspect_args("F"),
        }]
    );

    let out = app.on_bus(BusEvent::CallOk {
        name: "l4.flow.get".into(),
        value: section_2_flow("F", b"hello-l4"),
    });
    assert_eq!(out, Vec::<BusRequest>::new());
    assert!(
        app.current_toast().is_none(),
        "the window reply never toasts"
    );
    let f = app.selected_l4().expect("F");
    assert_eq!(f.packets.len(), 1);
    assert_eq!(f.packets[0].bytes.as_deref(), Some(&b"hello-l4"[..]));

    // The poll's `limit: 0` reply carries flow fields only.
    let mut polled = section_2_flow("F", b"hello-l4");
    polled["packets"] = json!([]);
    let out = app.on_bus(BusEvent::L4Flows(vec![polled.clone()]));
    assert_eq!(out, Vec::<BusRequest>::new());
    assert_eq!(app.selected_l4().map(|f| f.packets.len()), Some(1));

    // More packets arrived: the selected flow's window is asked for again.
    polled["packet_count"] = json!(2);
    let out = app.on_bus(BusEvent::L4Flows(vec![polled]));
    assert_eq!(
        out,
        vec![BusRequest::Call {
            name: "l4.flow.get".into(),
            args: inspect_args("F"),
        }]
    );

    // An older core without the window: the row's poll reply is all there is.
    let mut old = self::app();
    let tools: Vec<ToolInfo> = l4_tools(false)
        .into_iter()
        .map(|mut t| {
            if t.name == "l4.flow.get" {
                t.input_schema =
                    json!({"type": "object", "properties": {"id": {"type": "string"}}});
            }
            t
        })
        .collect();
    let _ = connected(&mut old, tools);
    let _ = old.on_bus(BusEvent::L4Flows(vec![intercept_flow("F")]));
    old.selected = None;
    assert_eq!(old.update(Action::Down), Vec::<BusRequest>::new());
}

/// Pure: epoch ms → a UTC clock, and the §2 field list of a packet.
#[test]
fn parked_id_clock_and_packet_fields() {
    assert_eq!(clock_ms(1_700_000_000_000), "22:13:20.000");
    assert_eq!(clock_ms(0), "00:00:00.000");
    assert_eq!(clock_ms(1_700_000_000_123), "22:13:20.123");

    let flow = L4Flow::from_json(&section_2_flow("F", b"hello-l4")).expect("flow");
    let fields = packet_fields(&flow.packets[0]);
    assert_eq!(
        fields,
        vec![
            ("time", "22:13:20.000".to_string()),
            ("proto", "UDP".to_string()),
            ("endpoints", "127.0.0.1:40000 → 127.0.0.1:9053".to_string()),
            ("length", "8 B".to_string()),
            ("injected", "no".to_string()),
        ]
    );

    let bare = L4Flow::from_json(&intercept_flow("F")).expect("flow");
    let fields = packet_fields(&bare.packets[0]);
    assert_eq!(fields[0], ("time", "—".to_string()));
    assert_eq!(fields[1], ("proto", "TCP".to_string()));
    assert_eq!(fields[2], ("endpoints", "—".to_string()));
}

/// AC40 (render): the packet pane shows the §2 fields and a `hex_dump` row of
/// the packet's bytes.
#[test]
fn parked_id_packet_pane_shows_section_2_fields_and_hex() {
    let mut app = intercept_ready(vec![parked_p1()]);
    let _ = app.on_bus(BusEvent::CallOk {
        name: "l4.flow.get".into(),
        value: section_2_flow("F", b"hello-l4"),
    });
    app.l4.pane = L4Pane::Packets;
    let text = render_inspector(&app);
    assert!(text.contains("22:13:20.000"), "{text}");
    assert!(text.contains("UDP"), "{text}");
    assert!(text.contains("127.0.0.1:40000 → 127.0.0.1:9053"), "{text}");
    assert!(text.contains("8 B"), "{text}");
    assert!(text.contains("injected"), "{text}");
    assert!(text.contains("00000000  68 65 6c 6c 6f 2d 6c 34"), "{text}");
    assert!(text.contains("hello-l4"), "{text}");
    assert!(!text.contains("no bytes from this core"), "{text}");
}

/// A packet without `bytes` (withheld under §2.2, or an older core) says so.
#[test]
fn parked_id_packet_pane_is_honest_without_bytes() {
    let mut app = intercept_ready(vec![parked_p1()]);
    let mut v = section_2_flow("F", b"hello-l4");
    v["packets"][0]
        .as_object_mut()
        .expect("packet")
        .remove("bytes");
    let _ = app.on_bus(BusEvent::CallOk {
        name: "l4.flow.get".into(),
        value: v,
    });
    app.l4.pane = L4Pane::Packets;
    let text = render_inspector(&app);
    assert!(text.contains("no bytes from this core"), "{text}");
    assert!(!text.contains("00000000  "), "{text}");
}

/// AC40: a packet of every byte 0..=255, with control characters in the
/// core's strings too, renders with no character below `' '`.
#[test]
fn parked_id_packet_pane_render_is_inert() {
    let mut app = intercept_ready(vec![parked_p1()]);
    let all: Vec<u8> = (0..=255u8).collect();
    let mut v = section_2_flow("F", &all);
    v["packets"][0]["proto"] = json!("U\u{1b}[31mDP");
    v["packets"][0]["src"] = json!("127.0.0.1\u{7}");
    v["packets"][0]["layers"] = json!(["IPv4", "UDP\u{1b}[0m", "Raw"]);
    let _ = app.on_bus(BusEvent::CallOk {
        name: "l4.flow.get".into(),
        value: v,
    });
    let theme = Theme::new(true);
    // Tall enough to draw every one of the 16 hex rows.
    let area = Rect::new(0, 0, 120, 60);
    let mut buf = Buffer::empty(area);
    app.l4.pane = L4Pane::Packets;
    aitm_tui::ui::l4::inspector(&app, &theme, area, &mut buf);
    let text = buffer_text(&buf).join("\n");
    assert!(text.contains("00000020  20 21 22 23"), "{text}");
    assert!(
        text.chars().all(|c| c >= ' ' || c == '\n'),
        "control character reached the terminal: {text:?}"
    );
    // The same for the intercept pane, whose parked entry comes from the core.
    let _ = app.on_bus(BusEvent::L4Parked(vec![json!({
        "id": "P1\u{1b}[2J", "flow": "F", "state": "parked", "length": 60,
        "layers": ["IPv4", "TCP\u{8}"]
    })]));
    app.l4.pane = L4Pane::Intercept;
    let text = render_inspector(&app);
    assert!(
        text.chars().all(|c| c >= ' ' || c == '\n'),
        "control character reached the terminal: {text:?}"
    );
}

// ------------------------------------------------------------------ mutate

/// The spec the test types into the craft editor: JSON is valid YAML, so the
/// editor's parser yields exactly this value for `l4.intercept.mutate.spec`.
const EDITOR_SPEC: &str = r#"{"layers":[{"ipv4":{"src":"127.0.0.1","dst":"127.0.0.1"}},{"udp":{"src_port":40000,"dst_port":9053}},{"raw":[104,105]}]}"#;

fn editor_spec() -> Value {
    serde_json::from_str(EDITOR_SPEC).expect("literal spec is JSON")
}

/// An intercept-ready app with `P1` parked and `EDITOR_SPEC` in the craft pane.
fn craft_ready(parked: Vec<Value>) -> App {
    let mut app = intercept_ready(parked);
    app.l4.craft.lines = vec![EDITOR_SPEC.to_string()];
    app.l4.pane = L4Pane::Craft;
    app
}

/// AC12: "apply to parked packet" emits exactly `l4.intercept.mutate {id: <parked
/// id>, spec: <the editor's spec>}` — the parked id from `l4.intercept.list`,
/// never the flow id, and the spec parsed from the editor's text.
#[test]
fn mutate_apply_sends_the_parked_id_and_the_editor_spec() {
    let mut app = craft_ready(vec![parked_p1()]);
    let out = app.update(Action::L4MutateParked);
    assert_eq!(
        out,
        vec![BusRequest::Call {
            name: "l4.intercept.mutate".into(),
            args: json!({"id": "P1", "spec": editor_spec()}),
        }]
    );
    let BusRequest::Call { args, .. } = &out[0] else {
        panic!("{out:?}");
    };
    assert_eq!(args["id"], json!("P1"));
    assert_eq!(args["spec"]["layers"][1]["udp"]["dst_port"], json!(9053));
    assert!(!args.to_string().contains("\"F\""), "{args}");
    assert!(app.l4.craft.error.is_none());
}

/// AC12: revert emits exactly `l4.intercept.revert {id: <parked id>}`.
#[test]
fn mutate_revert_sends_the_parked_id() {
    let mut app = craft_ready(vec![parked_p1()]);
    assert_eq!(
        app.update(Action::L4RevertParked),
        vec![BusRequest::Call {
            name: "l4.intercept.revert".into(),
            args: json!({"id": "P1"}),
        }]
    );
}

/// Both act on the first listed parked packet for the flow (decision 3), never
/// another flow's.
#[test]
fn mutate_and_revert_act_on_the_first_listed_for_the_flow() {
    let mut app = craft_ready(vec![
        json!({"id": "P9", "flow": "OTHER", "state": "parked", "length": 1, "layers": []}),
        json!({"id": "P2", "flow": "F", "state": "parked", "length": 1, "layers": []}),
        json!({"id": "P3", "flow": "F", "state": "parked", "length": 1, "layers": []}),
    ]);
    let out = app.update(Action::L4MutateParked);
    assert_eq!(out.len(), 1, "{out:?}");
    let BusRequest::Call { name, args } = &out[0] else {
        panic!("{out:?}");
    };
    assert_eq!(name, "l4.intercept.mutate");
    assert_eq!(args["id"], json!("P2"));
    assert_eq!(
        app.update(Action::L4RevertParked),
        vec![BusRequest::Call {
            name: "l4.intercept.revert".into(),
            args: json!({"id": "P2"}),
        }]
    );
}

/// The B4 refusal: intercept unavailable (reason `Y`) → neither verb reaches the
/// bus and the toast carries the core's reason.
#[test]
fn mutate_unavailable_intercept_refuses_both_with_the_reason() {
    let mut app = craft_ready(vec![parked_p1()]);
    let _ = app.on_bus(BusEvent::L4Availability {
        capture: unavailable("X"),
        intercept: L4Availability::from_reply(&json!({
            "available": false, "code": "unsupported_platform", "reason": "Y", "sessions": []
        })),
        captures: vec![],
    });
    assert_eq!(app.update(Action::L4MutateParked), Vec::<BusRequest>::new());
    assert!(toast_text(&app).contains('Y'), "{}", toast_text(&app));
    assert_eq!(app.update(Action::L4RevertParked), Vec::<BusRequest>::new());
    assert!(toast_text(&app).contains('Y'), "{}", toast_text(&app));
}

/// The B4 refusal: no parked packet for the flow → nothing on the bus, an
/// honest toast.
#[test]
fn mutate_without_a_parked_packet_refuses_both() {
    let mut app = craft_ready(vec![]);
    assert_eq!(app.update(Action::L4MutateParked), Vec::<BusRequest>::new());
    assert!(
        toast_text(&app).contains("no parked packet"),
        "{}",
        toast_text(&app)
    );
    assert_eq!(app.update(Action::L4RevertParked), Vec::<BusRequest>::new());
    assert!(
        toast_text(&app).contains("no parked packet"),
        "{}",
        toast_text(&app)
    );
}

/// A spec the editor cannot parse never reaches the bus: the error lands in
/// the craft pane.
#[test]
fn mutate_with_unparsable_yaml_sends_nothing() {
    let mut app = craft_ready(vec![parked_p1()]);
    app.l4.craft.lines = vec!["layers: [".to_string()];
    assert_eq!(app.update(Action::L4MutateParked), Vec::<BusRequest>::new());
    assert!(app.l4.craft.error.is_some(), "{:?}", app.l4.craft.error);
}

/// On an HTTP row the two actions are no-ops (the key map is per mode, the
/// reducer routes by flow kind).
#[test]
fn mutate_and_revert_are_noops_off_an_l4_flow() {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    assert_eq!(app.update(Action::L4MutateParked), Vec::<BusRequest>::new());
    assert_eq!(app.update(Action::L4RevertParked), Vec::<BusRequest>::new());
    assert_eq!(toast_text(&app), "");
}

/// The inspector keys for the two verbs.
#[test]
fn mutate_keys_are_bound_in_the_inspector() {
    assert_eq!(
        keys::map(press('m'), Mode::Inspector),
        Some(Action::L4MutateParked)
    );
    assert_eq!(
        keys::map(press('u'), Mode::Inspector),
        Some(Action::L4RevertParked)
    );
}

/// The craft pane names the two keys and the parked id only when they can act
/// (intercept available, a parked packet listed); otherwise it offers nothing
/// that can only fail (AC33).
#[test]
fn mutate_craft_pane_lists_the_keys_only_when_they_can_act() {
    let app = craft_ready(vec![parked_p1()]);
    let text = render_inspector(&app);
    assert!(text.contains("m apply to parked P1"), "{text}");
    assert!(text.contains("u revert"), "{text}");

    let none = craft_ready(vec![]);
    let text = render_inspector(&none);
    assert!(!text.contains("apply to parked"), "{text}");
    assert!(!text.contains("u revert"), "{text}");

    let mut off = craft_ready(vec![parked_p1()]);
    let _ = off.on_bus(BusEvent::L4Availability {
        capture: unavailable("X"),
        intercept: L4Availability::from_reply(&json!({
            "available": false, "code": "unsupported_platform", "reason": "Y", "sessions": []
        })),
        captures: vec![],
    });
    let text = render_inspector(&off);
    assert!(!text.contains("apply to parked"), "{text}");
    assert!(!text.contains("u revert"), "{text}");
}

// ------------------------------------------------------------ scope_add_l4

/// The operator L4 scope add (spec §3 / AC13, AC39). With a core whose
/// `tools/list` marks `l4.scope.add` `confirmable: true`, the palette line
/// sends exactly the five strings the core's `ScopeAdd` reads.
#[test]
fn scope_add_l4_sends_the_five_strings_when_confirmable() {
    let mut on = app();
    let _ = connected(&mut on, l4_tools(true));
    let reqs = on.run_command("scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture");
    assert_eq!(
        reqs,
        vec![BusRequest::Call {
            name: "l4.scope.add".into(),
            args: json!({
                "cidr": "127.0.0.1/32",
                "ports": "9100-9199",
                "interface": "lo0",
                "direction": "inbound",
                "capability": "capture"
            }),
        }]
    );
    assert!(on.current_toast().is_none(), "{:?}", toast_text(&on));
}

/// The core answers the first call with the confirm handshake
/// (`{"status":"needs_confirmation","prompt","confirm_token"}`, the shape
/// `aitm-mcp`'s `needs_confirmation()` builds). The TUI opens the existing
/// confirm overlay with the core's prompt, and `y` re-issues the identical args
/// plus `_confirm`.
#[test]
fn scope_add_l4_confirm_handshake_reissues_with_the_token() {
    let mut on = app();
    let _ = connected(&mut on, l4_tools(true));
    let _ = on.run_command("scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture");
    let reqs = on.on_bus(BusEvent::CallOk {
        name: "l4.scope.add".into(),
        value: json!({"status": "needs_confirmation", "prompt": "P", "confirm_token": "tok-1"}),
    });
    assert_eq!(on.mode, Mode::L4Confirm);
    let confirm = on.l4.confirm.as_ref().expect("confirm overlay state");
    assert_eq!(confirm.prompt, "P");
    assert_eq!(confirm.call, "l4.scope.add");
    assert!(
        !reqs.iter().any(|r| matches!(r, BusRequest::Call { .. })),
        "the handshake reply itself sends nothing: {reqs:?}"
    );

    assert_eq!(
        keys::map(press('y'), Mode::L4Confirm),
        Some(Action::L4Confirm(true))
    );
    let reqs = on.update(Action::L4Confirm(true));
    assert_eq!(
        reqs,
        vec![BusRequest::Call {
            name: "l4.scope.add".into(),
            args: json!({
                "cidr": "127.0.0.1/32",
                "ports": "9100-9199",
                "interface": "lo0",
                "direction": "inbound",
                "capability": "capture",
                "_confirm": "tok-1"
            }),
        }]
    );
    assert_eq!(
        on.mode,
        Mode::Scope,
        "back to the scope panel after confirming"
    );

    // The confirmed call's success re-reads the L4 scope so the new entry
    // shows without waiting for the slow poll.
    let reqs = on.on_bus(BusEvent::CallOk {
        name: "l4.scope.add".into(),
        value: json!("S4"),
    });
    assert!(
        reqs.contains(&BusRequest::Call {
            name: "l4.scope.list".into(),
            args: json!({}),
        }),
        "{reqs:?}"
    );
    assert_eq!(on.mode, Mode::Scope);
}

/// Wrong arity or a wrong word is a usage toast and no request.
#[test]
fn scope_add_l4_refuses_bad_arity_and_words_locally() {
    let mut on = app();
    let _ = connected(&mut on, l4_tools(true));
    assert_eq!(on.run_command("scope add l4 127.0.0.1/32"), vec![]);
    assert!(toast_text(&on).contains("usage"), "{:?}", toast_text(&on));
    assert_eq!(
        on.run_command("scope add l4 127.0.0.1/32 9100-9199 lo0 sideways capture"),
        vec![]
    );
    assert!(toast_text(&on).contains("usage"), "{:?}", toast_text(&on));
    assert_eq!(
        on.run_command("scope add l4 127.0.0.1/32 9100-9199 lo0 inbound sniff"),
        vec![]
    );
    assert!(toast_text(&on).contains("usage"), "{:?}", toast_text(&on));
}

/// Against a core without unit (a') (`confirmable` false) the full command is
/// refused locally with the plan's toast and nothing reaches the bus (AC13,
/// AC33).
#[test]
fn scope_add_l4_is_refused_locally_when_not_confirmable() {
    let mut on = app();
    let _ = connected(&mut on, l4_tools(false));
    let reqs = on.run_command("scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture");
    assert_eq!(reqs, vec![]);
    assert_eq!(
        toast_text(&on),
        "this core cannot confirm an operator L4 scope add"
    );
    assert_eq!(on.mode, Mode::Flows, "no confirm overlay opened");

    // No tools at all: the same refusal.
    let mut bare = app();
    assert_eq!(
        bare.run_command("scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture"),
        vec![]
    );
}

/// HTTP `:scope add <host>` is unchanged by the L4 form.
#[test]
fn scope_add_host_is_unchanged() {
    let mut on = app();
    let _ = connected(&mut on, l4_tools(true));
    assert_eq!(
        on.run_command("scope add api.test"),
        vec![BusRequest::ScopeAdd("api.test".into())]
    );
    let mut off = app();
    let _ = connected(&mut off, l4_tools(false));
    assert_eq!(
        off.run_command("scope add api.test"),
        vec![BusRequest::ScopeAdd("api.test".into())]
    );
}

/// `l4.scope.list` entries carry `id` and `source` (unit (a) A5) into the
/// app's state.
#[test]
fn scope_add_l4_entries_keep_id_and_source() {
    let mut on = app();
    let _ = connected(&mut on, l4_tools(true));
    let _ = on.on_bus(BusEvent::L4Scope(vec![
        json!({
            "id": "S1", "interface": "lo0", "capability": "capture",
            "cidr": "127.0.0.1/32", "ports": "9000-9999", "direction": "inbound",
            "source": "config"
        }),
        json!({
            "id": "S4", "interface": "lo0", "capability": "inject",
            "cidr": "127.0.0.1/32", "ports": "9100-9199", "direction": "inbound",
            "source": "runtime"
        }),
    ]));
    assert_eq!(on.l4.scope.len(), 2);
    assert_eq!(on.l4.scope[0].id, "S1");
    assert_eq!(on.l4.scope[0].source, "config");
    assert_eq!(on.l4.scope[1].id, "S4");
    assert_eq!(on.l4.scope[1].source, "runtime");
    // An entry from a core before A5 still parses, with an empty id and an
    // empty source (shown as-is, never invented).
    let _ = on.on_bus(BusEvent::L4Scope(vec![json!({
        "interface": "en0", "capability": "capture", "cidr": "10.0.0.0/8",
        "ports": "0-65535", "direction": "outbound"
    })]));
    assert_eq!(on.l4.scope.len(), 1);
    assert_eq!(on.l4.scope[0].id, "");
    assert_eq!(on.l4.scope[0].source, "");
}

/// The scope panel (`S`) renders an "L4 scope" section listing every entry with
/// its interface, cidr, ports, direction, capability and source; the add hint
/// shows only when the core can confirm it.
#[test]
fn scope_add_l4_panel_lists_entries_with_source() {
    let theme = Theme::new(true);
    let area = Rect::new(0, 0, 120, 24);
    let render = |app: &App| -> String {
        let mut buf = Buffer::empty(area);
        aitm_tui::ui::overlays::scope(app, &theme, area, &mut buf);
        buffer_text(&buf).join("\n")
    };

    let mut on = app();
    let _ = connected(&mut on, l4_tools(true));
    let _ = on.on_bus(BusEvent::L4Scope(vec![
        json!({
            "id": "S1", "interface": "lo0", "capability": "capture",
            "cidr": "127.0.0.1/32", "ports": "9000-9999", "direction": "inbound",
            "source": "config"
        }),
        json!({
            "id": "S4", "interface": "lo0", "capability": "inject",
            "cidr": "127.0.0.1/32", "ports": "9100-9199", "direction": "inbound",
            "source": "runtime"
        }),
    ]));
    let text = render(&on);
    assert!(text.contains("L4 scope"), "{text}");
    let config_row = text
        .lines()
        .find(|l| l.contains("9000-9999"))
        .unwrap_or_else(|| panic!("config entry row: {text}"));
    for word in [
        "lo0",
        "127.0.0.1/32",
        "9000-9999",
        "inbound",
        "capture",
        "config",
    ] {
        assert!(config_row.contains(word), "{word:?} in {config_row:?}");
    }
    let runtime_row = text
        .lines()
        .find(|l| l.contains("9100-9199"))
        .unwrap_or_else(|| panic!("runtime entry row: {text}"));
    for word in [
        "lo0",
        "127.0.0.1/32",
        "9100-9199",
        "inbound",
        "inject",
        "runtime",
    ] {
        assert!(runtime_row.contains(word), "{word:?} in {runtime_row:?}");
    }
    assert!(
        text.contains(
            ":scope add l4 <cidr> <ports> <iface> <inbound|outbound> <capture|inject|intercept>"
        ),
        "{text}"
    );

    // Without (a') the section lists the entries but offers no add form.
    let mut off = app();
    let _ = connected(&mut off, l4_tools(false));
    let _ = off.on_bus(BusEvent::L4Scope(vec![json!({
        "id": "S1", "interface": "lo0", "capability": "capture",
        "cidr": "127.0.0.1/32", "ports": "9000-9999", "direction": "inbound",
        "source": "config"
    })]));
    let text = render(&off);
    assert!(text.contains("L4 scope"), "{text}");
    assert!(text.contains("9000-9999"), "{text}");
    assert!(!text.contains("scope add l4"), "{text}");

    // No L4 scope at all: the section says so rather than vanishing.
    let mut empty = app();
    let _ = connected(&mut empty, l4_tools(true));
    let text = render(&empty);
    assert!(text.contains("L4 scope"), "{text}");
    assert!(text.contains("no L4 scope"), "{text}");
}

/// Palette completion offers `scope add l4` (and the direction / capability
/// words) only against a confirmable core; the HTTP `scope add` stays.
#[test]
fn scope_add_l4_completion_is_gated_on_confirmable() {
    let labels = |app: &mut App, line: &str| -> Vec<String> {
        app.prompt = line.to_string();
        app.palette_items().into_iter().map(|i| i.label).collect()
    };
    let mut on = app();
    let _ = connected(&mut on, l4_tools(true));
    let _ = on.on_bus(BusEvent::L4Scope(vec![json!({
        "id": "S1", "interface": "lo0", "capability": "capture",
        "cidr": "127.0.0.1/32", "ports": "9000-9999", "direction": "inbound",
        "source": "config"
    })]));
    let l = labels(&mut on, "scope add ");
    assert!(l.contains(&":scope add l4".to_string()), "{l:?}");
    let l = labels(&mut on, "scope add l4 127.0.0.1/32 9100-9199 ");
    assert!(
        l.contains(&":scope add l4 127.0.0.1/32 9100-9199 lo0".to_string()),
        "{l:?}"
    );
    let l = labels(&mut on, "scope add l4 127.0.0.1/32 9100-9199 lo0 ");
    assert!(
        l.contains(&":scope add l4 127.0.0.1/32 9100-9199 lo0 inbound".to_string()),
        "{l:?}"
    );
    let l = labels(&mut on, "scope add l4 127.0.0.1/32 9100-9199 lo0 inbound ");
    assert!(
        l.contains(&":scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture".to_string()),
        "{l:?}"
    );

    let mut off = app();
    let _ = connected(&mut off, l4_tools(false));
    let l = labels(&mut off, "scope add ");
    assert!(!l.iter().any(|s| s.contains("scope add l4")), "{l:?}");
}

// ----------------------------------------------------------- chips_filters

/// An HTTP summary in the core's wire shape, for the chip / atom checks.
fn http_summary(id: &str) -> Value {
    json!({
        "id": id, "kind": "http", "method": "GET", "scheme": "http",
        "authority": "127.0.0.1:9099", "path": "/", "status": 200,
        "is_replay": false, "intercept": "observed"
    })
}

/// The two rows every chip / atom check uses: an L4 row built by
/// `FlowRow::from_l4` from a TCP intercept flow, and an HTTP row from a summary.
fn l4_and_http_rows() -> (FlowRow, FlowRow) {
    let flow = L4Flow::from_json(&intercept_flow("F")).expect("l4 flow");
    let l4 = FlowRow::from_l4(&flow, 1);
    assert_eq!(l4.l4.as_ref().and_then(|l| l.proto.as_deref()), Some("TCP"));
    let http = FlowRow::from_summary(&http_summary("H1"), 2).expect("http row");
    (l4, http)
}

fn filter_ctx() -> aitm_tui::filter::Ctx<'static> {
    aitm_tui::filter::Ctx {
        detail: None,
        in_scope: true,
    }
}

/// AC14: `~l4` matches the L4 row only; `~tcp` matches it and `~udp` does
/// not; `~icmp` parses; none of the three protocol atoms match an HTTP row.
#[test]
fn chips_filters_l4_atoms_match_the_l4_row_only() {
    let (l4, http) = l4_and_http_rows();
    let ctx = filter_ctx();
    let parse = |s: &str| aitm_tui::filter::parse(s).expect(s).expect(s);
    let e = parse("~l4");
    assert!(e.matches(&l4, &ctx), "~l4 matches the L4 row");
    assert!(!e.matches(&http, &ctx), "~l4 hides the HTTP row");
    let tcp = parse("~tcp");
    assert!(tcp.matches(&l4, &ctx), "~tcp matches a TCP L4 row");
    assert!(!tcp.matches(&http, &ctx));
    let udp = parse("~udp");
    assert!(!udp.matches(&l4, &ctx), "~udp does not match a TCP L4 row");
    assert!(!udp.matches(&http, &ctx));
    let icmp = parse("~icmp");
    assert!(!icmp.matches(&l4, &ctx));
    assert!(!icmp.matches(&http, &ctx));
    // `!~l4` is the HTTP side of the same split.
    let not_l4 = parse("!~l4");
    assert!(not_l4.matches(&http, &ctx));
    assert!(!not_l4.matches(&l4, &ctx));
}

/// AC14, in the app: with a real-shaped HTTP row and an L4 row listed,
/// `/~l4` leaves only the L4 row visible and the `L4` chip does the same.
#[test]
fn chips_filters_l4_filter_hides_every_http_row_in_the_app() {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    let _ = app.on_bus(BusEvent::Flows(vec![
        http_summary("H1"),
        http_summary("H2"),
    ]));
    let _ = app.on_bus(BusEvent::L4Flows(vec![intercept_flow("F")]));
    assert_eq!(
        app.visible().len(),
        3,
        "two HTTP rows and one L4 row listed"
    );
    let _ = app.run_command("filter ~l4");
    assert!(app.filter.is_some(), "~l4 parses");
    let ids: Vec<&str> = app
        .visible()
        .into_iter()
        .map(|i| app.flows[i].id.as_str())
        .collect();
    assert_eq!(ids, vec!["F"], "~l4 hides every HTTP row");
    let _ = app.run_command("filter");
    app.chip = Chip::L4;
    let ids: Vec<&str> = app
        .visible()
        .into_iter()
        .map(|i| app.flows[i].id.as_str())
        .collect();
    assert_eq!(ids, vec!["F"], "the L4 chip hides every HTTP row");
    app.chip = Chip::Udp;
    assert!(
        app.visible().is_empty(),
        "a TCP flow is not under the UDP chip"
    );
    app.chip = Chip::Tcp;
    let ids: Vec<&str> = app
        .visible()
        .into_iter()
        .map(|i| app.flows[i].id.as_str())
        .collect();
    assert_eq!(ids, vec!["F"]);
}

/// The chip bar order (web / macOS parity: `TCP UDP L4` as their own group
/// after `WebSocket`), the three labels, and what each new chip matches.
#[test]
fn chips_filters_chip_order_labels_and_matches() {
    assert_eq!(Chip::ALL.len(), 18);
    assert_eq!(Chip::ALL[3], Chip::WebSocket);
    let labels: Vec<&str> = Chip::ALL[4..7].iter().map(|c| c.label()).collect();
    assert_eq!(labels, vec!["TCP", "UDP", "L4"]);
    assert_eq!(Chip::ALL[7], Chip::H1);
    assert_eq!(Chip::ALL[0].label(), "All");
    assert_eq!(Chip::ALL[17].label(), "Other");
    let (l4, http) = l4_and_http_rows();
    assert!(!Chip::L4.matches(&http, None));
    assert!(Chip::L4.matches(&l4, None));
    assert!(Chip::Tcp.matches(&l4, None));
    assert!(!Chip::Udp.matches(&l4, None));
    assert!(!Chip::Tcp.matches(&http, None));
    assert!(!Chip::Udp.matches(&http, None));
    // The HTTP chips do not claim the L4 row.
    assert!(!Chip::Http.matches(&l4, None));
    assert!(!Chip::WebSocket.matches(&l4, None));
    // `Other` is still "has a content type no content chip claims": an L4 row
    // has no content type, so it is not `Other` either.
    assert!(!Chip::Other.matches(&l4, None));
}

/// The chip bar renders the three labels; help and the filter prompt's hint
/// list `~l4 ~tcp ~udp ~icmp`; help names the craft-pane keys B4/B5 added.
#[test]
fn chips_filters_help_bar_and_filter_hint_list_the_atoms() {
    let theme = Theme::new(true);
    let mut app = app();
    let _ = connected(&mut app, l4_tools(false));
    let area = Rect::new(0, 0, 160, 50);
    // The chip bar.
    let mut buf = Buffer::empty(area);
    aitm_tui::ui::render(&app, &theme, area, &mut buf);
    let text = buffer_text(&buf).join("\n");
    assert!(text.contains("WebSocket"), "{text}");
    assert!(text.contains("TCP"), "{text}");
    assert!(text.contains("UDP"), "{text}");
    assert!(text.contains(" L4"), "{text}");
    // Help.
    app.mode = Mode::Help;
    let mut buf = Buffer::empty(area);
    aitm_tui::ui::render(&app, &theme, area, &mut buf);
    let text = buffer_text(&buf).join("\n");
    assert!(text.contains("~l4 ~tcp ~udp ~icmp"), "{text}");
    assert!(text.contains("b / s / m / u"), "{text}");
    assert!(
        text.contains("apply to parked packet") && text.contains("revert"),
        "{text}"
    );
    assert!(
        text.contains("Any key closes this help."),
        "the last help line is not clipped: {text}"
    );
    // The filter prompt's hint.
    app.mode = Mode::Flows;
    assert_eq!(keys::map(press('/'), Mode::Flows), Some(Action::FilterOpen));
    let _ = app.update(Action::FilterOpen);
    let mut buf = Buffer::empty(area);
    aitm_tui::ui::render(&app, &theme, area, &mut buf);
    let text = buffer_text(&buf).join("\n");
    assert!(text.contains("~l4 ~tcp ~udp ~icmp"), "{text}");
}

fn render_confirm(call: &str, args: Value, prompt: &str) -> String {
    let mut app = app();
    let _ = connected(&mut app, l4_tools(true));
    app.l4.confirm = Some(L4Confirm {
        call: call.to_string(),
        args,
        prompt: prompt.to_string(),
        token: "tok-1".to_string(),
    });
    app.mode = Mode::L4Confirm;
    let theme = Theme::new(true);
    let area = Rect::new(0, 0, 120, 30);
    let mut buf = Buffer::empty(area);
    aitm_tui::ui::l4::confirm(&app, &theme, area, &mut buf);
    buffer_text(&buf).join("\n")
}

/// The confirm overlay's "reaches the wire only through l4.inject" footer is
/// true of an inject and false of a scope add: an `l4.scope.add` confirm shows
/// the core's prompt and no `l4.inject` text; an `l4.inject` confirm shows it.
#[test]
fn chips_filters_confirm_footer_only_for_inject() {
    let scope = render_confirm(
        "l4.scope.add",
        json!({"cidr": "127.0.0.1/32", "ports": "9100-9199", "interface": "lo0",
               "direction": "inbound", "capability": "capture"}),
        "Add L4 scope 127.0.0.1/32 ports 9100-9199 on lo0 inbound capture",
    );
    assert!(scope.contains("l4.scope.add"), "{scope}");
    assert!(scope.contains("Add L4 scope 127.0.0.1/32"), "{scope}");
    assert!(!scope.contains("l4.inject"), "{scope}");
    assert!(scope.contains("y confirm"), "{scope}");

    let inject = render_confirm(
        "l4.inject",
        json!({"flow": "F", "spec": {"layers": []}}),
        "Inject 1 packet to 127.0.0.1:9 via lo0",
    );
    assert!(
        inject.contains("This reaches the wire only through l4.inject; the guard enforces scope."),
        "{inject}"
    );
    assert!(inject.contains("y confirm"), "{inject}");
}
