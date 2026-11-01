//! Helpers shared by the `macos_capture` unit tests and the `wire.rs` tests that
//! read the `capture.status` handle: the spec D7 literals, the CS-AC12 matrix,
//! and the small `Value` builders every one of them uses. Compiled only under
//! `cfg(test)`; an integration test cannot reach it and keeps its own `at`.

use std::time::{SystemTime, UNIX_EPOCH};

use aitm_core::Value;

pub(crate) use super::status::object as obj;
use super::status::{CaptureStatusSnapshot, FeederState, OffReason, ProviderState};

/// Now, as Unix-epoch milliseconds — the same clock the handle stamps with.
pub(crate) fn now_ms() -> u64 {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock is after 1970");
    u64::try_from(since_epoch.as_millis()).expect("millisecond count fits in u64")
}

/// A `Value::Str`.
pub(crate) fn s(v: &str) -> Value {
    Value::Str(v.to_string())
}

/// `value[key]`: the member of an object (`Value` has no `Index` impl); panics
/// on a missing key or a non-object so a test reads like the literal it checks.
pub(crate) fn at<'a>(value: &'a Value, key: &str) -> &'a Value {
    match value {
        Value::Object(map) => map
            .get(key)
            .unwrap_or_else(|| panic!("no key {key:?} in {value:?}")),
        other => panic!("{key:?} indexed into a non-object: {other:?}"),
    }
}

/// Spec D7, "Disabled": what `capture.status` reports when the feature is off.
pub(crate) fn disabled_literal() -> Value {
    obj([
        ("capability", s("feeder_off")),
        ("capability_reason", s("macos_capture.enabled is false")),
        ("enabled", Value::Bool(false)),
        (
            "feeder",
            obj([
                ("reason", s("macos_capture.enabled is false")),
                ("state", s("off")),
            ]),
        ),
        (
            "flows_handed_off",
            obj([("tcp", Value::Int(0)), ("udp", Value::Int(0))]),
        ),
        ("last_handoff_at", Value::Null),
        (
            "provider",
            obj([
                ("attached_at", Value::Null),
                ("state", s("detached")),
                ("team_id", Value::Null),
            ]),
        ),
        ("scope_entries", Value::Int(0)),
        ("scope_tokens", Value::Array(vec![])),
    ])
}

/// Spec D7, "Listening, no provider yet".
pub(crate) fn listening_literal() -> Value {
    obj([
        ("capability", s("awaiting_provider")),
        ("capability_reason", Value::Null),
        ("enabled", Value::Bool(true)),
        (
            "feeder",
            obj([("reason", Value::Null), ("state", s("listening"))]),
        ),
        (
            "flows_handed_off",
            obj([("tcp", Value::Int(0)), ("udp", Value::Int(0))]),
        ),
        ("last_handoff_at", Value::Null),
        (
            "provider",
            obj([
                ("attached_at", Value::Null),
                ("state", s("detached")),
                ("team_id", Value::Null),
            ]),
        ),
        ("scope_entries", Value::Int(0)),
        ("scope_tokens", Value::Array(vec![])),
    ])
}

/// Spec D7, "Bind failed".
pub(crate) fn bind_failed_literal() -> Value {
    obj([
        ("capability", s("degraded")),
        (
            "capability_reason",
            s("cannot bind the capture sockets (not a directory)"),
        ),
        ("enabled", Value::Bool(true)),
        (
            "feeder",
            obj([
                (
                    "reason",
                    s("cannot bind the capture sockets (not a directory)"),
                ),
                ("state", s("bind_failed")),
            ]),
        ),
        (
            "flows_handed_off",
            obj([("tcp", Value::Int(0)), ("udp", Value::Int(0))]),
        ),
        ("last_handoff_at", Value::Null),
        (
            "provider",
            obj([
                ("attached_at", Value::Null),
                ("state", s("detached")),
                ("team_id", Value::Null),
            ]),
        ),
        ("scope_entries", Value::Int(0)),
        ("scope_tokens", Value::Array(vec![])),
    ])
}

/// Spec D7, "Attached and capturing".
pub(crate) fn capturing_literal() -> Value {
    obj([
        ("capability", s("capturing")),
        ("capability_reason", Value::Null),
        ("enabled", Value::Bool(true)),
        (
            "feeder",
            obj([("reason", Value::Null), ("state", s("listening"))]),
        ),
        (
            "flows_handed_off",
            obj([("tcp", Value::Int(12)), ("udp", Value::Int(3))]),
        ),
        ("last_handoff_at", Value::Int(1_761_907_305_123)),
        (
            "provider",
            obj([
                ("attached_at", Value::Int(1_761_907_200_000)),
                ("state", s("attached")),
                ("team_id", s("995PCLM9KH")),
            ]),
        ),
        ("scope_entries", Value::Int(3)),
        (
            "scope_tokens",
            Value::Array(vec![
                s("example.com"),
                s("*.example.com"),
                s("198.51.100.7"),
            ]),
        ),
    ])
}

/// Every `FeederState` (the four `Off` reasons, `Listening`, `BindFailed`) ×
/// `ProviderState` {`Detached`, `Attached`} × handoffs {(0,0), (1,0), (0,1)}:
/// 36 snapshots, the CS-AC12 matrix.
pub(crate) fn matrix() -> Vec<CaptureStatusSnapshot> {
    let feeders = [
        FeederState::Off(OffReason::Disabled),
        FeederState::Off(OffReason::NotMacos),
        FeederState::Off(OffReason::NotStarted),
        FeederState::Off(OffReason::Stopped),
        FeederState::Listening,
        FeederState::BindFailed("cannot bind the capture sockets (not a directory)".into()),
    ];
    let providers = [
        ProviderState::Detached,
        ProviderState::Attached {
            attached_at_ms: 1_761_907_200_000,
            team_id: Some("995PCLM9KH".into()),
        },
    ];
    let handoffs = [(0u64, 0u64), (1, 0), (0, 1)];
    let mut rows = Vec::new();
    for feeder in &feeders {
        for provider in &providers {
            for (tcp, udp) in handoffs {
                let attached = matches!(provider, ProviderState::Attached { .. });
                rows.push(CaptureStatusSnapshot {
                    enabled: true,
                    feeder: feeder.clone(),
                    provider: provider.clone(),
                    scope_tokens: if attached {
                        vec!["example.com".into()]
                    } else {
                        Vec::new()
                    },
                    tcp_handed_off: tcp,
                    udp_handed_off: udp,
                    last_handoff_at_ms: if tcp + udp > 0 {
                        Some(1_761_907_305_123)
                    } else {
                        None
                    },
                });
            }
        }
    }
    rows
}
